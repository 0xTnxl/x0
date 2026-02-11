//! EVM Artifact Fetching
//!
//! Fetches block headers, transactions, receipts, and Merkle proofs
//! from an EVM-compatible RPC node (Base/Ethereum).

use alloy_primitives::{B256, U256};
use alloy_provider::{Provider, ProviderBuilder};
use alloy_rpc_types::{Block, TransactionReceipt};
use alloy_consensus::TxType;
use anyhow::{anyhow, bail, Context, Result};
use tiny_keccak::{Hasher, Keccak};
use x0_sp1_common::EVMProofWitness;

/// Fetch all EVM artifacts needed for proof generation
///
/// This function:
/// 1. Fetches the transaction by hash
/// 2. Fetches the full block (with transactions)
/// 3. Fetches the transaction receipt
/// 4. Constructs Merkle-Patricia Trie proofs for tx and receipt
/// 5. Returns an EVMProofWitness ready for the SP1 guest
pub async fn fetch_evm_artifacts(rpc_url: &str, tx_hash_hex: &str) -> Result<EVMProofWitness> {
    let tx_hash: B256 = tx_hash_hex
        .parse()
        .context("Invalid transaction hash format")?;

    let provider = ProviderBuilder::new()
        .on_http(rpc_url.parse().context("Invalid RPC URL")?);

    // Fetch transaction
    tracing::debug!("Fetching transaction {}", tx_hash_hex);
    let tx = provider
        .get_transaction_by_hash(tx_hash)
        .await
        .context("Failed to fetch transaction")?
        .ok_or_else(|| anyhow!("Transaction not found: {}", tx_hash_hex))?;

    let block_number = tx
        .block_number
        .ok_or_else(|| anyhow!("Transaction is pending (no block number)"))?;

    let tx_index = tx
        .transaction_index
        .ok_or_else(|| anyhow!("Transaction has no index"))?;

    // Fetch full block
    tracing::debug!("Fetching block {}", block_number);
    let block: Block = provider
        .get_block_by_number(block_number.into(), true)
        .await
        .context("Failed to fetch block")?
        .ok_or_else(|| anyhow!("Block not found: {}", block_number))?;

    let block_hash = block.header.hash;

    // Fetch receipt
    tracing::debug!("Fetching receipt for {}", tx_hash_hex);
    let receipt: TransactionReceipt = provider
        .get_transaction_receipt(tx_hash)
        .await
        .context("Failed to fetch receipt")?
        .ok_or_else(|| anyhow!("Receipt not found: {}", tx_hash_hex))?;

    // Verify receipt status
    if !receipt.status() {
        bail!(
            "Transaction failed (receipt.status=0). Cannot prove a failed transaction."
        );
    }

    // Fetch Merkle proofs via eth_getProof or construct them
    // For transaction and receipt tries, we use the debug/proof APIs
    // or construct proofs locally from the full block data
    tracing::debug!("Constructing Merkle-Patricia Trie proofs");

    let (block_header_rlp, tx_rlp, receipt_rlp, tx_proof_nodes, receipt_proof_nodes) =
        construct_proofs(&provider, rpc_url, &block, tx_index as u32, &receipt)
            .await
            .context("Failed to construct MPT proofs")?;

    // Extract from/to from transaction
    let from = address_to_bytes20(tx.from);
    let to = address_to_bytes20(
        tx.to
            .unwrap_or_default(),
    );
    let value = tx.value.to::<u64>();

    // Verify block header hash
    let computed_hash = keccak256(&block_header_rlp);
    let expected_hash: [u8; 32] = block_hash.0;
    if computed_hash != expected_hash {
        bail!(
            "Block header hash mismatch: computed={} expected={}",
            hex::encode(computed_hash),
            hex::encode(expected_hash),
        );
    }

    Ok(EVMProofWitness {
        block_header_rlp,
        block_hash: block_hash.0,
        block_number,
        transaction_rlp: tx_rlp,
        transaction_index: tx_index as u32,
        receipt_rlp,
        tx_proof_nodes,
        receipt_proof_nodes,
        from,
        to,
        value,
    })
}

/// Construct Merkle-Patricia Trie proofs for the transaction and receipt
///
/// Uses `eth_getProof`-style approach or builds proofs from full block data.
/// For Base/OP-stack chains, we fetch all transactions/receipts and build
/// the trie locally.
async fn construct_proofs<P: Provider<T>, T: alloy_transport::Transport + Clone>(
    provider: &P,
    rpc_url: &str,
    block: &Block,
    tx_index: u32,
    receipt: &TransactionReceipt,
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<Vec<u8>>, Vec<Vec<u8>>)> {
    // Get RLP-encoded block header
    let block_header_rlp = rlp_encode_block_header(block)?;

    // Get all transactions in the block for trie construction
    let txs = match &block.transactions {
        alloy_rpc_types::BlockTransactions::Full(txs) => txs.clone(),
        _ => bail!("Block must be fetched with full transactions"),
    };

    // Build transaction trie and get proof
    // Use manual RLP encoding for standard types (0, 1, 2),
    // fall back to fetching raw bytes via RPC for unsupported types
    // (e.g., OP Stack deposit txs type 0x7E which have non-standard fields)
    let mut tx_rlps: Vec<Vec<u8>> = Vec::with_capacity(txs.len());
    for tx in &txs {
        let encoded = match rlp_encode_transaction(tx) {
            Ok(rlp) if !rlp.is_empty() => rlp,
            Ok(_) | Err(_) => {
                tracing::debug!(
                    "Fetching raw bytes for tx {} (type {:?})",
                    tx.hash,
                    tx.transaction_type
                );
                fetch_raw_tx(rpc_url, tx.hash)
                    .await
                    .with_context(|| format!(
                        "Failed to fetch raw bytes for tx {}",
                        tx.hash
                    ))?
            }
        };
        tx_rlps.push(encoded);
    }

    let tx_proof_nodes = build_mpt_proof(&tx_rlps, tx_index as usize)?;
    let target_tx_rlp = tx_rlps
        .get(tx_index as usize)
        .ok_or_else(|| anyhow!("Transaction index {} out of range", tx_index))?
        .clone();

    // Build receipt trie and get proof
    // Fetch all receipts for the block
    let block_receipts = provider
        .get_block_receipts(block.header.number.into())
        .await
        .context("Failed to fetch block receipts")?
        .ok_or_else(|| anyhow!("Block receipts not found"))?;

    let receipt_rlps: Vec<Vec<u8>> = block_receipts
        .iter()
        .map(|r| rlp_encode_receipt(r))
        .collect::<Result<Vec<_>>>()?;

    let receipt_proof_nodes = build_mpt_proof(&receipt_rlps, tx_index as usize)?;
    let target_receipt_rlp = receipt_rlps
        .get(tx_index as usize)
        .ok_or_else(|| anyhow!("Receipt index {} out of range", tx_index))?
        .clone();

    // Sanity check: verify fetched receipt matches the one we already have
    if block_receipts.get(tx_index as usize).map(|r| r.transaction_hash) 
        != Some(receipt.transaction_hash) 
    {
        bail!(
            "Receipt mismatch: fetched tx_hash differs from provided receipt"
        );
    }

    Ok((
        block_header_rlp,
        target_tx_rlp,
        target_receipt_rlp,
        tx_proof_nodes,
        receipt_proof_nodes,
    ))
}

// ============================================================================
// RLP Encoding Helpers
// ============================================================================

/// RLP-encode a block header
fn rlp_encode_block_header(block: &Block) -> Result<Vec<u8>> {
    let mut items: Vec<Vec<u8>> = Vec::new();

    // Standard block header fields in order
    items.push(encode_bytes32(block.header.parent_hash.0));
    items.push(encode_bytes32(block.header.uncles_hash.0));
    items.push(encode_bytes20(block.header.miner.0 .0));
    items.push(encode_bytes32(block.header.state_root.0));
    items.push(encode_bytes32(block.header.transactions_root.0));
    items.push(encode_bytes32(block.header.receipts_root.0));
    items.push(encode_bytes(&block.header.logs_bloom.0 .0));
    items.push(encode_u256(block.header.difficulty));
    items.push(encode_u64(block.header.number));
    items.push(encode_u128(block.header.gas_limit));
    items.push(encode_u128(block.header.gas_used));
    items.push(encode_u64(block.header.timestamp));
    items.push(encode_bytes(&block.header.extra_data));
    items.push(encode_bytes32(block.header.mix_hash.unwrap_or_default().0));
    items.push(encode_bytes(&block.header.nonce.unwrap_or_default().0));

    // Post-London fields
    if let Some(base_fee) = block.header.base_fee_per_gas {
        items.push(encode_u128(base_fee));
    }

    // Post-Shanghai
    if let Some(withdrawals_root) = block.header.withdrawals_root {
        items.push(encode_bytes32(withdrawals_root.0));
    }

    // Post-Cancun
    if let Some(blob_gas_used) = block.header.blob_gas_used {
        items.push(encode_u128(blob_gas_used));
    }
    if let Some(excess_blob_gas) = block.header.excess_blob_gas {
        items.push(encode_u128(excess_blob_gas));
    }
    if let Some(parent_beacon_root) = block.header.parent_beacon_block_root {
        items.push(encode_bytes32(parent_beacon_root.0));
    }

    Ok(rlp_encode_list(&items))
}

/// RLP-encode a transaction for MPT trie construction
///
/// Handles the three standard EVM transaction types:
/// - Type 0 (Legacy): RLP([nonce, gasPrice, gasLimit, to, value, data, v, r, s])
/// - Type 1 (EIP-2930): 0x01 || RLP([chainId, nonce, gasPrice, gasLimit, to, value, data, accessList, yParity, r, s])
/// - Type 2 (EIP-1559): 0x02 || RLP([chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, to, value, data, accessList, yParity, r, s])
///
/// For non-standard types (e.g., OP Stack deposit txs type 0x7E), this returns
/// an error and the caller should fall back to fetching raw bytes via RPC.
fn rlp_encode_transaction(tx: &alloy_rpc_types::Transaction) -> Result<Vec<u8>> {
    let tx_type = tx.transaction_type.unwrap_or(0);

    match tx_type {
        0 => rlp_encode_legacy_tx(tx),
        1 => rlp_encode_eip2930_tx(tx),
        2 => rlp_encode_eip1559_tx(tx),
        other => bail!(
            "Unsupported transaction type 0x{:02x} — use raw RPC fallback",
            other
        ),
    }
}

/// RLP-encode a legacy (type 0) transaction
fn rlp_encode_legacy_tx(tx: &alloy_rpc_types::Transaction) -> Result<Vec<u8>> {
    let sig = tx
        .signature
        .as_ref()
        .context("Legacy transaction missing signature")?;

    let mut items: Vec<Vec<u8>> = Vec::with_capacity(9);
    items.push(encode_u64(tx.nonce));
    items.push(encode_u128(tx.gas_price.unwrap_or(0)));
    items.push(encode_u128(tx.gas));

    // to: empty for contract creation, 20-byte address for regular tx
    if let Some(to) = tx.to {
        items.push(encode_bytes20(to.0 .0));
    } else {
        items.push(vec![0x80]); // RLP empty string
    }

    items.push(encode_u256(tx.value));
    items.push(encode_bytes(&tx.input));

    // Legacy signature uses v directly (includes chain_id for EIP-155)
    items.push(encode_u256(sig.v));
    items.push(encode_u256(sig.r));
    items.push(encode_u256(sig.s));

    Ok(rlp_encode_list(&items))
}

/// RLP-encode an EIP-2930 (type 1) transaction
fn rlp_encode_eip2930_tx(tx: &alloy_rpc_types::Transaction) -> Result<Vec<u8>> {
    let sig = tx
        .signature
        .as_ref()
        .context("EIP-2930 transaction missing signature")?;

    let mut items: Vec<Vec<u8>> = Vec::with_capacity(11);
    items.push(encode_u64(tx.chain_id.unwrap_or(1)));
    items.push(encode_u64(tx.nonce));
    items.push(encode_u128(tx.gas_price.unwrap_or(0)));
    items.push(encode_u128(tx.gas));

    if let Some(to) = tx.to {
        items.push(encode_bytes20(to.0 .0));
    } else {
        items.push(vec![0x80]);
    }

    items.push(encode_u256(tx.value));
    items.push(encode_bytes(&tx.input));
    items.push(rlp_encode_access_list(&tx.access_list));

    // Typed tx signature uses y_parity (0 or 1)
    items.push(encode_u8(signature_y_parity(sig)));
    items.push(encode_u256(sig.r));
    items.push(encode_u256(sig.s));

    let payload = rlp_encode_list(&items);

    // EIP-2718: type_byte || RLP(fields)
    let mut result = Vec::with_capacity(1 + payload.len());
    result.push(0x01);
    result.extend_from_slice(&payload);
    Ok(result)
}

/// RLP-encode an EIP-1559 (type 2) transaction
fn rlp_encode_eip1559_tx(tx: &alloy_rpc_types::Transaction) -> Result<Vec<u8>> {
    let sig = tx
        .signature
        .as_ref()
        .context("EIP-1559 transaction missing signature")?;

    let mut items: Vec<Vec<u8>> = Vec::with_capacity(12);
    items.push(encode_u64(tx.chain_id.unwrap_or(1)));
    items.push(encode_u64(tx.nonce));
    items.push(encode_u128(tx.max_priority_fee_per_gas.unwrap_or(0)));
    items.push(encode_u128(tx.max_fee_per_gas.unwrap_or(0)));
    items.push(encode_u128(tx.gas));

    if let Some(to) = tx.to {
        items.push(encode_bytes20(to.0 .0));
    } else {
        items.push(vec![0x80]);
    }

    items.push(encode_u256(tx.value));
    items.push(encode_bytes(&tx.input));
    items.push(rlp_encode_access_list(&tx.access_list));

    // Typed tx signature uses y_parity (0 or 1)
    items.push(encode_u8(signature_y_parity(sig)));
    items.push(encode_u256(sig.r));
    items.push(encode_u256(sig.s));

    let payload = rlp_encode_list(&items);

    // EIP-2718: type_byte || RLP(fields)
    let mut result = Vec::with_capacity(1 + payload.len());
    result.push(0x02);
    result.extend_from_slice(&payload);
    Ok(result)
}

/// Extract y-parity from an RPC Signature for typed (non-legacy) transactions.
///
/// For EIP-2930/1559/4844, the signature uses a single y-parity bit (0 or 1)
/// instead of the legacy v value.
fn signature_y_parity(sig: &alloy_rpc_types::Signature) -> u8 {
    // Prefer the explicit y_parity field if present
    if let Some(ref parity) = sig.y_parity {
        if parity.0 {
            1
        } else {
            0
        }
    } else {
        // Derive from v: 0 or 27 = even (0), 1 or 28 = odd (1)
        let v = sig.v.to::<u64>();
        match v {
            0 | 27 => 0,
            1 | 28 => 1,
            // EIP-155: v = chain_id * 2 + 35 (even) or chain_id * 2 + 36 (odd)
            _ => ((v + 1) % 2) as u8,
        }
    }
}

/// RLP-encode an EIP-2930 access list
fn rlp_encode_access_list(
    access_list: &Option<alloy_rpc_types::AccessList>,
) -> Vec<u8> {
    match access_list {
        None => rlp_encode_list(&[]), // empty list
        Some(al) => {
            let items: Vec<Vec<u8>> = al
                .0
                .iter()
                .map(|item| {
                    let mut entry: Vec<Vec<u8>> = Vec::with_capacity(2);
                    entry.push(encode_bytes20(item.address.0 .0));

                    let keys: Vec<Vec<u8>> = item
                        .storage_keys
                        .iter()
                        .map(|k| encode_bytes32(k.0))
                        .collect();
                    entry.push(rlp_encode_list(&keys));

                    rlp_encode_list(&entry)
                })
                .collect();
            rlp_encode_list(&items)
        }
    }
}

/// Fetch raw transaction bytes via JSON-RPC `eth_getRawTransactionByHash`.
///
/// This is used as a fallback for transaction types that can't be manually
/// RLP-encoded from the parsed Transaction struct (e.g., OP Stack deposit
/// transactions which have non-standard fields like sourceHash).
async fn fetch_raw_tx(rpc_url: &str, tx_hash: B256) -> Result<Vec<u8>> {
    let client = reqwest::Client::new();
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "eth_getRawTransactionByHash",
        "params": [format!("0x{}", hex::encode(tx_hash.0))],
        "id": 1
    });

    let resp = client
        .post(rpc_url)
        .json(&body)
        .send()
        .await
        .context("RPC request failed")?;

    let result: serde_json::Value = resp
        .json()
        .await
        .context("Failed to parse RPC response")?;

    let hex_str = result["result"]
        .as_str()
        .context("eth_getRawTransactionByHash returned null")?;

    let raw = hex::decode(hex_str.strip_prefix("0x").unwrap_or(hex_str))
        .context("Invalid hex in raw transaction")?;

    if raw.is_empty() {
        bail!("eth_getRawTransactionByHash returned empty bytes");
    }

    Ok(raw)
}

/// RLP-encode a transaction receipt
fn rlp_encode_receipt(receipt: &TransactionReceipt) -> Result<Vec<u8>> {
    // Similar to transactions, we need the raw encoding.
    // Receipts are: [status, cumulativeGasUsed, logsBloom, logs]
    //
    // For typed receipts (EIP-2718), prefix with type byte.

    let mut items: Vec<Vec<u8>> = Vec::new();

    // Status
    let status_byte = if receipt.status() { 1u8 } else { 0u8 };
    items.push(encode_u8(status_byte));

    // Cumulative gas used (accessed via inner)
    items.push(encode_u128(receipt.inner.cumulative_gas_used()));

    // Logs bloom (accessed via inner)
    items.push(encode_bytes(receipt.inner.logs_bloom().as_slice()));

    // Logs
    let log_items: Vec<Vec<u8>> = receipt
        .inner
        .logs()
        .iter()
        .map(|log| {
            let mut log_fields: Vec<Vec<u8>> = Vec::new();
            log_fields.push(encode_bytes20(log.address().0 .0));

            // Topics as list
            let topic_items: Vec<Vec<u8>> = log
                .topics()
                .iter()
                .map(|t| encode_bytes32(t.0))
                .collect();
            log_fields.push(rlp_encode_list(&topic_items));

            // Data
            log_fields.push(encode_bytes(log.data().data.as_ref()));

            rlp_encode_list(&log_fields)
        })
        .collect();
    items.push(rlp_encode_list(&log_items));

    let receipt_rlp = rlp_encode_list(&items);

    // For EIP-2718 typed receipts, prepend the type byte
    let tx_type = receipt.transaction_type();
    if tx_type != TxType::Legacy {
        let mut typed = vec![tx_type as u8];
        typed.extend_from_slice(&receipt_rlp);
        Ok(typed)
    } else {
        Ok(receipt_rlp)
    }
}

// ============================================================================
// RLP Primitives
// ============================================================================

fn encode_u8(v: u8) -> Vec<u8> {
    if v == 0 {
        vec![0x80] // RLP empty string for 0
    } else if v < 0x80 {
        vec![v]
    } else {
        vec![0x81, v]
    }
}

fn encode_u64(v: u64) -> Vec<u8> {
    if v == 0 {
        return vec![0x80];
    }
    let bytes = v.to_be_bytes();
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(7);
    let significant = &bytes[start..];
    if significant.len() == 1 && significant[0] < 0x80 {
        significant.to_vec()
    } else {
        let mut encoded = vec![0x80 + significant.len() as u8];
        encoded.extend_from_slice(significant);
        encoded
    }
}

fn encode_u128(v: u128) -> Vec<u8> {
    if v == 0 {
        return vec![0x80];
    }
    let bytes = v.to_be_bytes();
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(15);
    let significant = &bytes[start..];
    if significant.len() == 1 && significant[0] < 0x80 {
        significant.to_vec()
    } else {
        let mut encoded = vec![0x80 + significant.len() as u8];
        encoded.extend_from_slice(significant);
        encoded
    }
}

fn encode_u256(v: U256) -> Vec<u8> {
    if v.is_zero() {
        return vec![0x80];
    }
    let bytes: [u8; 32] = v.to_be_bytes();
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(31);
    let significant = &bytes[start..];
    encode_bytes(significant)
}

fn encode_bytes(data: &[u8]) -> Vec<u8> {
    if data.len() == 1 && data[0] < 0x80 {
        data.to_vec()
    } else if data.len() <= 55 {
        let mut encoded = vec![0x80 + data.len() as u8];
        encoded.extend_from_slice(data);
        encoded
    } else {
        let len_bytes = encode_length_bytes(data.len());
        let mut encoded = vec![0xb7 + len_bytes.len() as u8];
        encoded.extend_from_slice(&len_bytes);
        encoded.extend_from_slice(data);
        encoded
    }
}

fn encode_bytes20(data: [u8; 20]) -> Vec<u8> {
    encode_bytes(&data)
}

fn encode_bytes32(data: [u8; 32]) -> Vec<u8> {
    encode_bytes(&data)
}

fn rlp_encode_list(items: &[Vec<u8>]) -> Vec<u8> {
    let payload: Vec<u8> = items.iter().flat_map(|i| i.iter().copied()).collect();
    if payload.len() <= 55 {
        let mut encoded = vec![0xc0 + payload.len() as u8];
        encoded.extend_from_slice(&payload);
        encoded
    } else {
        let len_bytes = encode_length_bytes(payload.len());
        let mut encoded = vec![0xf7 + len_bytes.len() as u8];
        encoded.extend_from_slice(&len_bytes);
        encoded.extend_from_slice(&payload);
        encoded
    }
}

fn encode_length_bytes(len: usize) -> Vec<u8> {
    let bytes = len.to_be_bytes();
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len() - 1);
    bytes[start..].to_vec()
}

// ============================================================================
// Merkle-Patricia Trie Construction
// ============================================================================

/// Build an MPT proof for a given index in a list of RLP-encoded items.
///
/// This constructs the full trie and extracts the proof path for the
/// given key (index).
///
/// Returns the list of trie nodes from root to leaf.
fn build_mpt_proof(items: &[Vec<u8>], index: usize) -> Result<Vec<Vec<u8>>> {
    if index >= items.len() {
        bail!("Index {} out of range (have {} items)", index, items.len());
    }

    // For a simple implementation, we build the trie in memory
    // and extract the proof path.
    //
    // The key for each item is the RLP encoding of its index.
    // The value is the RLP-encoded item itself.

    let mut trie = SimpleMPT::new();

    for (i, item) in items.iter().enumerate() {
        let key = rlp_encode_u32_key(i as u32);
        trie.insert(&key, item.clone());
    }

    let target_key = rlp_encode_u32_key(index as u32);
    trie.get_proof(&target_key)
}

/// RLP-encode a u32 for use as an MPT key
fn rlp_encode_u32_key(value: u32) -> Vec<u8> {
    if value == 0 {
        vec![0x80]
    } else {
        let bytes = value.to_be_bytes();
        let start = bytes.iter().position(|&b| b != 0).unwrap_or(3);
        let significant = &bytes[start..];
        if significant.len() == 1 && significant[0] < 0x80 {
            significant.to_vec()
        } else {
            let mut encoded = vec![0x80 + significant.len() as u8];
            encoded.extend_from_slice(significant);
            encoded
        }
    }
}

// ============================================================================
// Simple In-Memory MPT Implementation
// ============================================================================

/// A simple in-memory Merkle-Patricia Trie for proof construction
///
/// This is a minimal implementation sufficient for building proofs
/// for transaction/receipt tries. It supports insert and proof
/// extraction but is not optimized for large tries.
struct SimpleMPT {
    root: MPTNode,
}

#[derive(Clone, Debug)]
enum MPTNode {
    Empty,
    Leaf {
        /// Partial key (nibbles)
        key: Vec<u8>,
        /// Value
        value: Vec<u8>,
    },
    Extension {
        /// Shared prefix (nibbles)
        prefix: Vec<u8>,
        /// Child node
        child: Box<MPTNode>,
    },
    Branch {
        /// 16 children (one per nibble)
        children: [Option<Box<MPTNode>>; 16],
        /// Optional value at this node
        value: Option<Vec<u8>>,
    },
}

impl SimpleMPT {
    fn new() -> Self {
        Self {
            root: MPTNode::Empty,
        }
    }

    fn insert(&mut self, key: &[u8], value: Vec<u8>) {
        let nibbles = bytes_to_nibbles(key);
        self.root = Self::insert_node(self.root.clone(), &nibbles, value);
    }

    fn insert_node(node: MPTNode, key: &[u8], value: Vec<u8>) -> MPTNode {
        match node {
            MPTNode::Empty => MPTNode::Leaf {
                key: key.to_vec(),
                value,
            },

            MPTNode::Leaf {
                key: existing_key,
                value: existing_value,
            } => {
                // Find common prefix
                let common_len = existing_key
                    .iter()
                    .zip(key.iter())
                    .take_while(|(a, b)| a == b)
                    .count();

                if common_len == existing_key.len() && common_len == key.len() {
                    // Same key: update value
                    return MPTNode::Leaf {
                        key: existing_key,
                        value,
                    };
                }

                // Create branch node
                let mut children: [Option<Box<MPTNode>>; 16] = Default::default();
                let mut branch_value = None;

                // Insert existing leaf into branch
                if common_len < existing_key.len() {
                    let nibble = existing_key[common_len] as usize;
                    let remaining = existing_key[common_len + 1..].to_vec();
                    if remaining.is_empty() {
                        children[nibble] = Some(Box::new(MPTNode::Leaf {
                            key: Vec::new(),
                            value: existing_value,
                        }));
                    } else {
                        children[nibble] = Some(Box::new(MPTNode::Leaf {
                            key: remaining,
                            value: existing_value,
                        }));
                    }
                } else {
                    branch_value = Some(existing_value);
                }

                // Insert new leaf into branch
                if common_len < key.len() {
                    let nibble = key[common_len] as usize;
                    let remaining = key[common_len + 1..].to_vec();
                    if remaining.is_empty() {
                        children[nibble] = Some(Box::new(MPTNode::Leaf {
                            key: Vec::new(),
                            value,
                        }));
                    } else {
                        children[nibble] = Some(Box::new(MPTNode::Leaf {
                            key: remaining,
                            value,
                        }));
                    }
                } else {
                    branch_value = Some(value);
                }

                let branch = MPTNode::Branch {
                    children,
                    value: branch_value,
                };

                if common_len > 0 {
                    MPTNode::Extension {
                        prefix: existing_key[..common_len].to_vec(),
                        child: Box::new(branch),
                    }
                } else {
                    branch
                }
            }

            MPTNode::Extension {
                prefix,
                child,
            } => {
                let common_len = prefix
                    .iter()
                    .zip(key.iter())
                    .take_while(|(a, b)| a == b)
                    .count();

                if common_len == prefix.len() {
                    // Key extends beyond the prefix
                    let child = Self::insert_node(*child, &key[common_len..], value);
                    MPTNode::Extension {
                        prefix,
                        child: Box::new(child),
                    }
                } else {
                    // Need to split the extension
                    let mut children: [Option<Box<MPTNode>>; 16] = Default::default();
                    let mut branch_value = None;

                    // Original extension's remaining path
                    if common_len + 1 < prefix.len() {
                        let nibble = prefix[common_len] as usize;
                        children[nibble] = Some(Box::new(MPTNode::Extension {
                            prefix: prefix[common_len + 1..].to_vec(),
                            child,
                        }));
                    } else {
                        let nibble = prefix[common_len] as usize;
                        children[nibble] = Some(child);
                    }

                    // New key
                    if common_len < key.len() {
                        let nibble = key[common_len] as usize;
                        let remaining = key[common_len + 1..].to_vec();
                        if remaining.is_empty() {
                            children[nibble] = Some(Box::new(MPTNode::Leaf {
                                key: Vec::new(),
                                value,
                            }));
                        } else {
                            children[nibble] = Some(Box::new(MPTNode::Leaf {
                                key: remaining,
                                value,
                            }));
                        }
                    } else {
                        branch_value = Some(value);
                    }

                    let branch = MPTNode::Branch {
                        children,
                        value: branch_value,
                    };

                    if common_len > 0 {
                        MPTNode::Extension {
                            prefix: prefix[..common_len].to_vec(),
                            child: Box::new(branch),
                        }
                    } else {
                        branch
                    }
                }
            }

            MPTNode::Branch {
                mut children,
                value: branch_value,
            } => {
                if key.is_empty() {
                    MPTNode::Branch {
                        children,
                        value: Some(value),
                    }
                } else {
                    let nibble = key[0] as usize;
                    let child = children[nibble]
                        .take()
                        .map(|c| *c)
                        .unwrap_or(MPTNode::Empty);
                    children[nibble] =
                        Some(Box::new(Self::insert_node(child, &key[1..], value)));
                    MPTNode::Branch {
                        children,
                        value: branch_value,
                    }
                }
            }
        }
    }

    fn get_proof(&self, key: &[u8]) -> Result<Vec<Vec<u8>>> {
        let nibbles = bytes_to_nibbles(key);
        let mut proof = Vec::new();
        Self::collect_proof(&self.root, &nibbles, &mut proof)?;
        Ok(proof)
    }

    fn collect_proof(
        node: &MPTNode,
        remaining_key: &[u8],
        proof: &mut Vec<Vec<u8>>,
    ) -> Result<()> {
        match node {
            MPTNode::Empty => bail!("Key not found in trie"),

            MPTNode::Leaf { key, value } => {
                let rlp = rlp_encode_leaf_node(key, value);
                proof.push(rlp);
                Ok(())
            }

            MPTNode::Extension { prefix, child } => {
                let child_rlp = Self::rlp_encode_node(child);
                let child_ref = if child_rlp.len() >= 32 {
                    keccak256(&child_rlp).to_vec()
                } else {
                    child_rlp
                };
                let rlp = rlp_encode_extension_node(prefix, &child_ref);
                proof.push(rlp);

                if remaining_key.len() >= prefix.len()
                    && &remaining_key[..prefix.len()] == prefix.as_slice()
                {
                    Self::collect_proof(child, &remaining_key[prefix.len()..], proof)?;
                } else {
                    bail!("Key prefix mismatch in extension node");
                }
                Ok(())
            }

            MPTNode::Branch {
                children,
                value,
            } => {
                let rlp = Self::rlp_encode_branch(children, value);
                proof.push(rlp);

                if remaining_key.is_empty() {
                    // Value is at this branch
                    Ok(())
                } else {
                    let nibble = remaining_key[0] as usize;
                    if let Some(child) = &children[nibble] {
                        Self::collect_proof(child, &remaining_key[1..], proof)?;
                    } else {
                        bail!("Key not found: no child at nibble {}", nibble);
                    }
                    Ok(())
                }
            }
        }
    }

    fn rlp_encode_node(node: &MPTNode) -> Vec<u8> {
        match node {
            MPTNode::Empty => vec![0x80],
            MPTNode::Leaf { key, value } => rlp_encode_leaf_node(key, value),
            MPTNode::Extension { prefix, child } => {
                let child_rlp = Self::rlp_encode_node(child);
                let child_ref = if child_rlp.len() >= 32 {
                    keccak256(&child_rlp).to_vec()
                } else {
                    child_rlp
                };
                rlp_encode_extension_node(prefix, &child_ref)
            }
            MPTNode::Branch { children, value } => {
                Self::rlp_encode_branch(children, value)
            }
        }
    }

    fn rlp_encode_branch(
        children: &[Option<Box<MPTNode>>; 16],
        value: &Option<Vec<u8>>,
    ) -> Vec<u8> {
        let mut items: Vec<Vec<u8>> = Vec::with_capacity(17);
        for child in children.iter() {
            if let Some(child) = child {
                let child_rlp = Self::rlp_encode_node(child);
                if child_rlp.len() >= 32 {
                    items.push(encode_bytes(&keccak256(&child_rlp)));
                } else {
                    items.push(child_rlp);
                }
            } else {
                items.push(vec![0x80]); // Empty string
            }
        }
        // Value slot
        if let Some(v) = value {
            items.push(encode_bytes(v));
        } else {
            items.push(vec![0x80]);
        }
        rlp_encode_list(&items)
    }
}

/// Encode a leaf node: [compact(key, is_leaf=true), value]
fn rlp_encode_leaf_node(key_nibbles: &[u8], value: &[u8]) -> Vec<u8> {
    let compact = nibbles_to_compact(key_nibbles, true);
    let items = vec![encode_bytes(&compact), encode_bytes(value)];
    rlp_encode_list(&items)
}

/// Encode an extension node: [compact(prefix, is_leaf=false), child_ref]
fn rlp_encode_extension_node(prefix_nibbles: &[u8], child_ref: &[u8]) -> Vec<u8> {
    let compact = nibbles_to_compact(prefix_nibbles, false);
    let items = vec![encode_bytes(&compact), encode_bytes(child_ref)];
    rlp_encode_list(&items)
}

/// Convert nibbles to compact (hex prefix) encoding
fn nibbles_to_compact(nibbles: &[u8], is_leaf: bool) -> Vec<u8> {
    let odd = nibbles.len() % 2 != 0;
    let mut result = Vec::new();

    let flags = if is_leaf { 0x20 } else { 0x00 };

    if odd {
        result.push(flags | 0x10 | nibbles[0]);
        for chunk in nibbles[1..].chunks(2) {
            result.push((chunk[0] << 4) | chunk[1]);
        }
    } else {
        result.push(flags);
        for chunk in nibbles.chunks(2) {
            result.push((chunk[0] << 4) | chunk[1]);
        }
    }

    result
}

/// Convert bytes to nibbles
fn bytes_to_nibbles(data: &[u8]) -> Vec<u8> {
    let mut nibbles = Vec::with_capacity(data.len() * 2);
    for &byte in data {
        nibbles.push(byte >> 4);
        nibbles.push(byte & 0x0f);
    }
    nibbles
}

/// Convert 20-byte address to fixed-size array
fn address_to_bytes20(addr: alloy_primitives::Address) -> [u8; 20] {
    addr.0 .0
}

/// Compute keccak256
fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    let mut output = [0u8; 32];
    hasher.update(data);
    hasher.finalize(&mut output);
    output
}
