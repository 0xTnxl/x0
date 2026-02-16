//! Shared types between SP1 guest (STARK circuit) and host (prover)
//!
//! These types are used both inside the STARK prover (guest) and by the
//! host program that fetches EVM artifacts and submits proofs to Solana.
//!
//! The public inputs are committed by the guest and verified on Solana.
//! The private inputs (witness) are only used inside the guest and never
//! revealed to the verifier.

#![no_std]

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

// ============================================================================
// Public Inputs (committed by guest, verified on Solana)
// ============================================================================

/// Public inputs/outputs committed by the SP1 STARK proof
///
/// These values are cryptographically bound to the proof and verified
/// on Solana by the x0-bridge program after SP1 verification.
///
/// The borsh serialization must match the SP1PublicInputs struct in
/// programs/x0-bridge/src/state.rs exactly.
#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct EVMProofPublicInputs {
    /// Block hash where the transaction was mined (32 bytes)
    pub block_hash: [u8; 32],
    /// Block number
    pub block_number: u64,
    /// Transaction hash (32 bytes)
    pub tx_hash: [u8; 32],
    /// Transaction sender (20-byte EVM address)
    pub from: [u8; 20],
    /// Transaction recipient/contract (20-byte EVM address)
    pub to: [u8; 20],
    /// ETH value transferred (in wei)
    pub value: u64,
    /// Whether the transaction was successful (receipt.status == 1)
    pub success: bool,
    /// Extracted event logs from the receipt
    pub event_logs: Vec<EventLog>,

    // ====================================================================
    // Chain proof anchor — verified on-chain against trusted anchor state
    // ====================================================================

    /// Block number of the chain proof anchor (oldest block in the chain).
    ///
    /// The Solana verifier checks this against its `trusted_anchor_block`.
    pub chain_anchor_block: u64,

    /// Block hash of the chain proof anchor.
    ///
    /// The Solana verifier requires:
    ///   `chain_anchor_hash == bridge_state.trusted_anchor_hash`
    ///
    /// This is the root of trust: since the circuit cryptographically
    /// proved the chain `anchor → ... → target`, and the anchor hash
    /// is known-good, the target block (and its transactions) is valid.
    pub chain_anchor_hash: [u8; 32],
}

/// An event log extracted from an EVM transaction receipt
#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct EventLog {
    /// Contract that emitted the event (20 bytes)
    pub contract_address: [u8; 20],
    /// Indexed topics: topic[0] = keccak256(event signature)
    pub topics: Vec<[u8; 32]>,
    /// ABI-encoded non-indexed event data
    pub data: Vec<u8>,
}

// ============================================================================
// Private Inputs (witness — never revealed to verifier)
// ============================================================================

/// Private inputs provided to the SP1 guest program
///
/// These are the raw EVM artifacts fetched via RPC that the guest
/// program verifies inside the STARK circuit. They are never exposed
/// to the Solana verifier — only the public inputs above are committed.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EVMProofWitness {
    /// RLP-encoded block header (of the TARGET block containing the tx)
    pub block_header_rlp: Vec<u8>,
    /// Block hash (precomputed for validation)
    pub block_hash: [u8; 32],
    /// Block number
    pub block_number: u64,
    /// RLP-encoded transaction
    pub transaction_rlp: Vec<u8>,
    /// Transaction index within the block
    pub transaction_index: u32,
    /// RLP-encoded transaction receipt
    pub receipt_rlp: Vec<u8>,
    /// Merkle-Patricia Trie proof for transaction inclusion
    pub tx_proof_nodes: Vec<Vec<u8>>,
    /// Merkle-Patricia Trie proof for receipt inclusion
    pub receipt_proof_nodes: Vec<Vec<u8>>,
    /// Transaction sender (recovered from signature)
    pub from: [u8; 20],
    /// Transaction recipient
    pub to: [u8; 20],
    /// ETH value transferred
    pub value: u64,

    /// Chain proof: consecutive block headers from a trusted anchor to
    /// the target block. The circuit verifies cryptographic continuity
    /// (keccak256 hash chain) so the Solana verifier only needs to check
    /// that `chain_proof.headers[0]` matches a known-good anchor.
    pub chain_proof: ChainProof,

    /// Contract addresses to include in event log extraction.
    ///
    /// If non-empty, only logs emitted by these contracts are extracted.
    /// If empty, ALL logs from the receipt are included (legacy behavior).
    ///
    /// For the x0 bridge, this should contain the X0LockContract address.
    pub relevant_contracts: Vec<[u8; 20]>,

    /// Event topic signatures to include in event log extraction.
    ///
    /// If non-empty, only logs whose `topics[0]` (event signature) matches
    /// one of these values are extracted.
    /// If empty, ALL logs pass the topic filter (legacy behavior).
    ///
    /// For the x0 bridge, this should contain `LOCKED_EVENT_SIGNATURE`.
    pub relevant_topics: Vec<[u8; 32]>,
}

// ============================================================================
// Chain Proof Types
// ============================================================================

/// A cryptographic chain proof linking a trusted anchor block to a target block.
///
/// The circuit verifies:
/// 1. Each header hashes to its claimed hash via keccak256
/// 2. Each header's `parent_hash` field equals the hash of the previous header
/// 3. Block numbers are strictly sequential
///
/// This proves that `headers[N-1]` (the target) is on the same chain as
/// `headers[0]` (the anchor), assuming the anchor hash is trusted.
///
/// # Security
///
/// An attacker cannot forge this chain because it would require finding a
/// keccak256 preimage — a block header that hashes to a specific value
/// (complexity ~2^256). The anchor block hash is verified on-chain against
/// a governance-maintained trusted value.
///
/// # Size
///
/// Variable length: `target_block - anchor_block + 1` headers.
/// Bounded by `MAX_CHAIN_PROOF_DEPTH` (256 blocks ≈ 128 KB).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChainProof {
    /// Consecutive block headers from anchor (index 0) to target (last).
    ///
    /// `headers.len()` must be in `[2, MAX_CHAIN_PROOF_DEPTH]`.
    /// - `headers[0]` = anchor block (checked against on-chain trusted hash)
    /// - `headers[len-1]` = target block (contains the proven transaction)
    pub headers: Vec<BlockHeaderRLP>,
}

/// A block header with its RLP encoding and pre-extracted fields.
///
/// The RLP encoding is the canonical serialization used for keccak256 hashing.
/// The extracted fields (`number`, `parent_hash`) are stored separately for
/// convenience but are validated against the RLP inside the circuit.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockHeaderRLP {
    /// Full RLP-encoded block header (canonical serialization).
    ///
    /// `keccak256(rlp_encoded)` produces the block hash.
    pub rlp_encoded: Vec<u8>,

    /// Block number (extracted from RLP field index 8).
    pub number: u64,

    /// Parent block hash (extracted from RLP field index 0).
    ///
    /// Must equal `keccak256(headers[i-1].rlp_encoded)` for chain continuity.
    pub parent_hash: [u8; 32],
}

impl ChainProof {
    /// Validate the chain proof structure before proof generation.
    ///
    /// # Checks
    /// - At least 2 headers (anchor + target)
    /// - At most `MAX_CHAIN_PROOF_DEPTH` headers
    /// - All headers have non-empty RLP within size bounds
    /// - Block numbers are sequential
    /// - Parent hash linkage is correct (hash chain)
    pub fn validate(&self) -> Result<(), String> {
        if self.headers.len() < 2 {
            return Err(format!(
                "Chain proof must have at least 2 headers (anchor + target), got {}",
                self.headers.len(),
            ));
        }
        if self.headers.len() > MAX_CHAIN_PROOF_DEPTH {
            return Err(format!(
                "Chain proof too deep: {} headers (max {})",
                self.headers.len(),
                MAX_CHAIN_PROOF_DEPTH,
            ));
        }

        for (i, header) in self.headers.iter().enumerate() {
            if header.rlp_encoded.is_empty() {
                return Err(format!("Chain proof header {} has empty RLP", i));
            }
            if header.rlp_encoded.len() > MAX_BLOCK_HEADER_RLP_SIZE {
                return Err(format!(
                    "Chain proof header {} RLP too large: {} bytes (max {})",
                    i,
                    header.rlp_encoded.len(),
                    MAX_BLOCK_HEADER_RLP_SIZE,
                ));
            }
            if header.number == 0 && i > 0 {
                return Err(format!(
                    "Chain proof header {} has block number 0",
                    i,
                ));
            }
        }

        // Verify sequential block numbers
        for i in 1..self.headers.len() {
            if self.headers[i].number != self.headers[i - 1].number + 1 {
                return Err(format!(
                    "Chain proof block numbers not sequential: {} followed by {}",
                    self.headers[i - 1].number,
                    self.headers[i].number,
                ));
            }
        }

        Ok(())
    }
}

// ============================================================================
// Witness Validation
// ============================================================================

/// Maximum allowed depth for MPT proofs.
///
/// Ethereum's MPT has a key space of 32 bytes (64 nibbles). With branch
/// factor 16, the theoretical max depth is 64. In practice, tx/receipt
/// tries are much shallower — 20 levels handles well beyond the largest
/// blocks observed on Base.
pub const MAX_MPT_PROOF_DEPTH: usize = 20;

/// Maximum allowed RLP size for a block header (bytes).
///
/// Post-merge EIP-4844 headers can reach ~1 KB. We allow 2 KB for headroom.
pub const MAX_BLOCK_HEADER_RLP_SIZE: usize = 2048;

/// Maximum chain proof depth (number of consecutive block headers).
///
/// On Base (2-second blocks), 256 blocks ≈ 8.5 minutes.
/// The trusted anchor on Solana must be updated at least this frequently.
///
/// The chain proof includes headers[0] (anchor) through headers[N-1] (target),
/// so a depth of 256 means the target can be at most 255 blocks ahead of
/// the anchor.
///
/// Total overhead: 256 × ~500 bytes ≈ 128 KB (acceptable for STARK witness).
pub const MAX_CHAIN_PROOF_DEPTH: usize = 256;

/// Maximum allowed RLP size for a single transaction (bytes).
///
/// ERC-4337 bundles and large calldata can push transactions up to ~128 KB.
pub const MAX_TRANSACTION_RLP_SIZE: usize = 131_072;

/// Maximum allowed RLP size for a receipt (bytes).
///
/// Receipts with many log entries can be large but rarely exceed 128 KB.
pub const MAX_RECEIPT_RLP_SIZE: usize = 131_072;

/// Maximum number of contract addresses or topic filters in the witness.
///
/// Bounds the loop iteration inside the circuit to prevent cycle bloat.
/// In practice, the x0 bridge only needs 1-2 contract addresses and
/// 1-2 topic signatures (Locked, Transfer).
pub const MAX_RELEVANT_FILTERS: usize = 16;

impl EVMProofWitness {
    /// Validate witness structure before proof generation.
    ///
    /// Catches structural errors early so they surface as clear error
    /// messages rather than opaque circuit panics after minutes of proving.
    ///
    /// # Checks
    /// - Block hash is non-zero
    /// - Block header RLP is non-empty and within size bounds
    /// - Transaction RLP is non-empty and within size bounds
    /// - Receipt RLP is non-empty and within size bounds
    /// - MPT proof depths are within bounds
    /// - Block number is non-zero
    /// - Relevant contract/topic filters within bounds
    pub fn validate(&self) -> Result<(), String> {
        if self.block_hash == [0u8; 32] {
            return Err("Block hash must not be zero".into());
        }

        if self.block_header_rlp.is_empty() {
            return Err("Block header RLP must not be empty".into());
        }
        if self.block_header_rlp.len() > MAX_BLOCK_HEADER_RLP_SIZE {
            return Err(format!(
                "Block header RLP too large: {} bytes (max {})",
                self.block_header_rlp.len(),
                MAX_BLOCK_HEADER_RLP_SIZE,
            ));
        }

        if self.transaction_rlp.is_empty() {
            return Err("Transaction RLP must not be empty".into());
        }
        if self.transaction_rlp.len() > MAX_TRANSACTION_RLP_SIZE {
            return Err(format!(
                "Transaction RLP too large: {} bytes (max {})",
                self.transaction_rlp.len(),
                MAX_TRANSACTION_RLP_SIZE,
            ));
        }

        if self.receipt_rlp.is_empty() {
            return Err("Receipt RLP must not be empty".into());
        }
        if self.receipt_rlp.len() > MAX_RECEIPT_RLP_SIZE {
            return Err(format!(
                "Receipt RLP too large: {} bytes (max {})",
                self.receipt_rlp.len(),
                MAX_RECEIPT_RLP_SIZE,
            ));
        }

        if self.tx_proof_nodes.is_empty() {
            return Err("Transaction MPT proof must have at least one node".into());
        }
        if self.tx_proof_nodes.len() > MAX_MPT_PROOF_DEPTH {
            return Err(format!(
                "Transaction MPT proof too deep: {} levels (max {})",
                self.tx_proof_nodes.len(),
                MAX_MPT_PROOF_DEPTH,
            ));
        }

        if self.receipt_proof_nodes.is_empty() {
            return Err("Receipt MPT proof must have at least one node".into());
        }
        if self.receipt_proof_nodes.len() > MAX_MPT_PROOF_DEPTH {
            return Err(format!(
                "Receipt MPT proof too deep: {} levels (max {})",
                self.receipt_proof_nodes.len(),
                MAX_MPT_PROOF_DEPTH,
            ));
        }

        if self.block_number == 0 {
            return Err("Block number must not be zero".into());
        }

        // Relevant filter bounds
        if self.relevant_contracts.len() > MAX_RELEVANT_FILTERS {
            return Err(format!(
                "Too many relevant contracts: {} (max {})",
                self.relevant_contracts.len(),
                MAX_RELEVANT_FILTERS,
            ));
        }
        if self.relevant_topics.len() > MAX_RELEVANT_FILTERS {
            return Err(format!(
                "Too many relevant topics: {} (max {})",
                self.relevant_topics.len(),
                MAX_RELEVANT_FILTERS,
            ));
        }

        // Chain proof validation
        self.chain_proof.validate()?;

        // Target block must be the last header in the chain proof
        let chain_len = self.chain_proof.headers.len();
        let last_header = &self.chain_proof.headers[chain_len - 1];
        if last_header.number != self.block_number {
            return Err(format!(
                "Chain proof tail block {} does not match witness block_number {}",
                last_header.number, self.block_number,
            ));
        }

        Ok(())
    }
}

// ============================================================================
// Constants
// ============================================================================

/// keccak256("Locked(address,bytes32,uint256,uint256,bytes32)")
/// Event signature for the X0LockContract.Locked event
///
/// Solidity declaration:
///   event Locked(address indexed sender, bytes32 indexed solanaRecipient,
///                uint256 amount, uint256 nonce, bytes32 messageId)
///
/// Topics:  [0] = this hash, [1] = sender, [2] = solanaRecipient
/// Data:    abi.encode(amount, nonce, messageId)
pub const LOCKED_EVENT_SIGNATURE: [u8; 32] = [
    0x6e, 0xa4, 0xb3, 0xe5, 0xd5, 0xca, 0x80, 0xe1,
    0xec, 0x33, 0xaf, 0x6e, 0x82, 0x4b, 0x1d, 0x7f,
    0x59, 0x5b, 0x0b, 0x2f, 0x6d, 0x9d, 0x72, 0x42,
    0x22, 0xfc, 0xab, 0xd1, 0x8c, 0x36, 0xba, 0x15,
];

/// keccak256("Transfer(address,address,uint256)")
/// Standard ERC-20 Transfer event signature
pub const TRANSFER_EVENT_SIGNATURE: [u8; 32] = [
    0xdd, 0xf2, 0x52, 0xad, 0x1b, 0xe2, 0xc8, 0x9b,
    0x69, 0xc2, 0xb0, 0x68, 0xfc, 0x37, 0x8d, 0xaa,
    0x95, 0x2b, 0xa7, 0xf1, 0x63, 0xc4, 0xa1, 0x16,
    0x28, 0xf5, 0x5a, 0x4d, 0xf5, 0x23, 0xb3, 0xef,
];

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use alloc::vec;

    fn make_header(number: u64, parent_hash: [u8; 32]) -> BlockHeaderRLP {
        BlockHeaderRLP {
            rlp_encoded: vec![0xf8; 100], // fake RLP, just needs to be non-empty
            number,
            parent_hash,
        }
    }

    fn make_chain(start: u64, len: usize) -> ChainProof {
        let mut headers = Vec::with_capacity(len);
        for i in 0..len {
            headers.push(make_header(start + i as u64, [i as u8; 32]));
        }
        ChainProof { headers }
    }

    // -- ChainProof::validate tests --

    #[test]
    fn chain_proof_valid_two_headers() {
        let chain = make_chain(100, 2);
        assert!(chain.validate().is_ok());
    }

    #[test]
    fn chain_proof_valid_max_depth() {
        let chain = make_chain(100, MAX_CHAIN_PROOF_DEPTH);
        assert!(chain.validate().is_ok());
    }

    #[test]
    fn chain_proof_too_few_headers() {
        let chain = ChainProof {
            headers: vec![make_header(100, [0u8; 32])],
        };
        let err = chain.validate().unwrap_err();
        assert!(
            err.contains("at least 2"),
            "Expected 'at least 2' error, got: {}",
            err,
        );
    }

    #[test]
    fn chain_proof_empty() {
        let chain = ChainProof {
            headers: vec![],
        };
        let err = chain.validate().unwrap_err();
        assert!(err.contains("at least 2"));
    }

    #[test]
    fn chain_proof_exceeds_max_depth() {
        let chain = make_chain(100, MAX_CHAIN_PROOF_DEPTH + 1);
        let err = chain.validate().unwrap_err();
        assert!(
            err.contains("too deep"),
            "Expected 'too deep' error, got: {}",
            err,
        );
    }

    #[test]
    fn chain_proof_empty_rlp() {
        let mut chain = make_chain(100, 3);
        chain.headers[1].rlp_encoded = vec![];
        let err = chain.validate().unwrap_err();
        assert!(err.contains("empty RLP"));
    }

    #[test]
    fn chain_proof_oversized_rlp() {
        let mut chain = make_chain(100, 3);
        chain.headers[0].rlp_encoded = vec![0xf8; MAX_BLOCK_HEADER_RLP_SIZE + 1];
        let err = chain.validate().unwrap_err();
        assert!(err.contains("RLP too large"));
    }

    #[test]
    fn chain_proof_non_sequential_blocks() {
        let mut chain = make_chain(100, 3);
        chain.headers[2].number = 105; // should be 102
        let err = chain.validate().unwrap_err();
        assert!(err.contains("not sequential"));
    }

    #[test]
    fn chain_proof_block_number_zero_not_anchor() {
        let mut chain = make_chain(100, 3);
        chain.headers[1].number = 0;
        // This will also fail sequential check, but the important thing
        // is that it doesn't pass validation
        assert!(chain.validate().is_err());
    }

    // -- EVMProofWitness chain integration tests --

    fn make_minimal_witness(chain: ChainProof) -> EVMProofWitness {
        let target_block = chain.headers.last().unwrap().number;
        EVMProofWitness {
            block_header_rlp: vec![0xf8; 100],
            block_hash: [1u8; 32],
            block_number: target_block,
            transaction_rlp: vec![0xf8; 50],
            transaction_index: 0,
            receipt_rlp: vec![0xf8; 50],
            tx_proof_nodes: vec![vec![0xf8; 20]],
            receipt_proof_nodes: vec![vec![0xf8; 20]],
            from: [2u8; 20],
            to: [3u8; 20],
            value: 1000,
            chain_proof: chain,
            relevant_contracts: vec![],
            relevant_topics: vec![],
        }
    }

    #[test]
    fn witness_validates_with_valid_chain() {
        let chain = make_chain(100, 5);
        let witness = make_minimal_witness(chain);
        assert!(witness.validate().is_ok());
    }

    #[test]
    fn witness_rejects_chain_tail_mismatch() {
        let chain = make_chain(100, 5);
        let mut witness = make_minimal_witness(chain);
        witness.block_number = 999; // doesn't match chain tail
        let err = witness.validate().unwrap_err();
        assert!(
            err.contains("tail block"),
            "Expected 'tail block' mismatch error, got: {}",
            err,
        );
    }

    #[test]
    fn witness_propagates_chain_proof_error() {
        let chain = ChainProof { headers: vec![] }; // empty = invalid
        let mut witness = make_minimal_witness(make_chain(100, 2));
        witness.chain_proof = chain;
        assert!(witness.validate().is_err());
    }

    // -- EVMProofPublicInputs chain anchor fields --

    #[test]
    fn public_inputs_has_anchor_fields() {
        let pi = EVMProofPublicInputs {
            block_hash: [0u8; 32],
            block_number: 200,
            tx_hash: [0u8; 32],
            from: [0u8; 20],
            to: [0u8; 20],
            value: 0,
            success: true,
            event_logs: vec![],
            chain_anchor_block: 100,
            chain_anchor_hash: [0xABu8; 32],
        };
        assert_eq!(pi.chain_anchor_block, 100);
        assert_eq!(pi.chain_anchor_hash, [0xABu8; 32]);
    }

    // -- Serialization round-trip --

    #[test]
    fn chain_proof_serde_roundtrip() {
        let chain = make_chain(100, 10);
        let json = serde_json::to_string(&chain).unwrap();
        let restored: ChainProof = serde_json::from_str(&json).unwrap();
        assert_eq!(chain.headers.len(), restored.headers.len());
        assert_eq!(chain.headers[0].number, restored.headers[0].number);
        assert_eq!(chain.headers[9].number, restored.headers[9].number);
    }

    #[test]
    fn public_inputs_borsh_roundtrip() {
        let pi = EVMProofPublicInputs {
            block_hash: [1u8; 32],
            block_number: 999,
            tx_hash: [2u8; 32],
            from: [3u8; 20],
            to: [4u8; 20],
            value: 42,
            success: true,
            event_logs: vec![],
            chain_anchor_block: 500,
            chain_anchor_hash: [5u8; 32],
        };
        let bytes = borsh::to_vec(&pi).unwrap();
        let restored = EVMProofPublicInputs::try_from_slice(&bytes).unwrap();
        assert_eq!(restored.chain_anchor_block, 500);
        assert_eq!(restored.chain_anchor_hash, [5u8; 32]);
        assert_eq!(restored.block_number, 999);
    }

    // -- Witness validation: new fields --

    #[test]
    fn witness_validates_with_contract_filters() {
        let chain = make_chain(100, 3);
        let mut witness = make_minimal_witness(chain);
        witness.relevant_contracts = vec![[0xAAu8; 20], [0xBBu8; 20]];
        witness.relevant_topics = vec![[0xCCu8; 32]];
        assert!(witness.validate().is_ok());
    }

    #[test]
    fn witness_rejects_too_many_contracts() {
        let chain = make_chain(100, 3);
        let mut witness = make_minimal_witness(chain);
        witness.relevant_contracts = (0..=MAX_RELEVANT_FILTERS as u8)
            .map(|i| [i; 20])
            .collect();
        let err = witness.validate().unwrap_err();
        assert!(err.contains("Too many relevant contracts"));
    }

    #[test]
    fn witness_rejects_too_many_topics() {
        let chain = make_chain(100, 3);
        let mut witness = make_minimal_witness(chain);
        witness.relevant_topics = (0..=MAX_RELEVANT_FILTERS as u8)
            .map(|i| [i; 32])
            .collect();
        let err = witness.validate().unwrap_err();
        assert!(err.contains("Too many relevant topics"));
    }

    #[test]
    fn witness_rejects_zero_block_hash() {
        let chain = make_chain(100, 3);
        let mut witness = make_minimal_witness(chain);
        witness.block_hash = [0u8; 32];
        let err = witness.validate().unwrap_err();
        assert!(err.contains("Block hash must not be zero"));
    }

    #[test]
    fn witness_rejects_empty_block_header_rlp() {
        let chain = make_chain(100, 3);
        let mut witness = make_minimal_witness(chain);
        witness.block_header_rlp = vec![];
        let err = witness.validate().unwrap_err();
        assert!(err.contains("Block header RLP must not be empty"));
    }

    #[test]
    fn witness_rejects_oversized_block_header_rlp() {
        let chain = make_chain(100, 3);
        let mut witness = make_minimal_witness(chain);
        witness.block_header_rlp = vec![0xf8; MAX_BLOCK_HEADER_RLP_SIZE + 1];
        let err = witness.validate().unwrap_err();
        assert!(err.contains("Block header RLP too large"));
    }

    #[test]
    fn witness_rejects_empty_transaction_rlp() {
        let chain = make_chain(100, 3);
        let mut witness = make_minimal_witness(chain);
        witness.transaction_rlp = vec![];
        let err = witness.validate().unwrap_err();
        assert!(err.contains("Transaction RLP must not be empty"));
    }

    #[test]
    fn witness_rejects_empty_receipt_rlp() {
        let chain = make_chain(100, 3);
        let mut witness = make_minimal_witness(chain);
        witness.receipt_rlp = vec![];
        let err = witness.validate().unwrap_err();
        assert!(err.contains("Receipt RLP must not be empty"));
    }

    #[test]
    fn witness_rejects_empty_tx_proof() {
        let chain = make_chain(100, 3);
        let mut witness = make_minimal_witness(chain);
        witness.tx_proof_nodes = vec![];
        let err = witness.validate().unwrap_err();
        assert!(err.contains("Transaction MPT proof must have at least one node"));
    }

    #[test]
    fn witness_rejects_empty_receipt_proof() {
        let chain = make_chain(100, 3);
        let mut witness = make_minimal_witness(chain);
        witness.receipt_proof_nodes = vec![];
        let err = witness.validate().unwrap_err();
        assert!(err.contains("Receipt MPT proof must have at least one node"));
    }

    #[test]
    fn witness_rejects_zero_block_number() {
        let mut chain = make_chain(0, 3);
        // Fix sequential numbers to include 0
        chain.headers[0].number = 0;
        chain.headers[1].number = 1;
        chain.headers[2].number = 2;
        let mut witness = make_minimal_witness(make_chain(100, 3));
        witness.block_number = 0;
        let err = witness.validate().unwrap_err();
        assert!(err.contains("Block number must not be zero"));
    }

    #[test]
    fn witness_rejects_deep_tx_proof() {
        let chain = make_chain(100, 3);
        let mut witness = make_minimal_witness(chain);
        witness.tx_proof_nodes = (0..=MAX_MPT_PROOF_DEPTH)
            .map(|_| vec![0xf8; 10])
            .collect();
        let err = witness.validate().unwrap_err();
        assert!(err.contains("Transaction MPT proof too deep"));
    }

    // -- Witness serde roundtrip with new fields --

    #[test]
    fn witness_serde_roundtrip_with_filters() {
        let chain = make_chain(100, 3);
        let mut witness = make_minimal_witness(chain);
        witness.relevant_contracts = vec![[0xAAu8; 20]];
        witness.relevant_topics = vec![[0xBBu8; 32], [0xCCu8; 32]];

        let json = serde_json::to_string(&witness).unwrap();
        let restored: EVMProofWitness = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.relevant_contracts.len(), 1);
        assert_eq!(restored.relevant_contracts[0], [0xAAu8; 20]);
        assert_eq!(restored.relevant_topics.len(), 2);
        assert_eq!(restored.relevant_topics[0], [0xBBu8; 32]);
    }

    // -- Constants sanity checks --

    #[test]
    fn constants_are_sane() {
        assert!(MAX_MPT_PROOF_DEPTH >= 10);
        assert!(MAX_MPT_PROOF_DEPTH <= 64);
        assert!(MAX_BLOCK_HEADER_RLP_SIZE >= 1024);
        assert!(MAX_CHAIN_PROOF_DEPTH >= 64);
        assert!(MAX_CHAIN_PROOF_DEPTH <= 1024);
        assert!(MAX_TRANSACTION_RLP_SIZE >= 1024);
        assert!(MAX_RECEIPT_RLP_SIZE >= 1024);
        assert!(MAX_RELEVANT_FILTERS >= 4);
    }
}

