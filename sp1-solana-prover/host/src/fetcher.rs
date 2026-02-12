//! Solana state fetcher for SP1 proof witness generation
//!
//! Fetches all the cryptographic material needed to build a
//! SolanaProofWitness for the SP1 guest program.
//!
//! # Production Requirements
//!
//! In production, this module needs to:
//! 1. Query a Solana validator's `getAccountInfo` with proof support
//! 2. Fetch the bank hash for a finalized slot
//! 3. Fetch validator vote account data to reconstruct signatures
//! 4. Compute the Merkle proof from the account to the accounts hash
//!
//! Some of this requires extended RPC endpoints or direct validator access.
//! The Solana `getAccountInfo` RPC method doesn't natively return Merkle proofs,
//! so production deployments may use:
//! - Light Protocol's compressed account proofs
//! - A custom RPC sidecar that computes proofs from snapshots
//! - Direct validator integration for state access

use anyhow::Result;
use sha2::{Digest, Sha256};
use solana_client::rpc_client::RpcClient;
use solana_sdk::{account::Account, pubkey::Pubkey};
use tracing::{info, warn};
use x0_sp1_solana_common::{
    BankHashComponents, SolanaProofWitness, ValidatorSignature, ValidatorStake,
};

/// Fetch all witness data needed for the SP1 Solana state proof
///
/// # Arguments
/// * `rpc` - Solana RPC client
/// * `bridge_program` - x0-bridge program ID
/// * `pda` - BridgeOutMessage PDA address
/// * `account` - Pre-fetched account data
/// * `nonce` - Bridge out nonce
pub async fn fetch_witness(
    rpc: &RpcClient,
    bridge_program: &Pubkey,
    pda: &Pubkey,
    account: &Account,
    nonce: u64,
) -> Result<SolanaProofWitness> {
    info!("Building witness for BridgeOutMessage at slot...");

    // ========================================================================
    // Account data (already fetched)
    // ========================================================================

    let account_data = account.data.clone();
    let account_address = pda.to_bytes();
    let account_owner = account.owner.to_bytes();
    let account_lamports = account.lamports;
    let account_executable = account.executable;
    let account_rent_epoch = account.rent_epoch;

    // ========================================================================
    // Compute account hash (leaf in the accounts Merkle tree)
    // ========================================================================

    let mut leaf_preimage = Vec::new();
    leaf_preimage.extend_from_slice(&account_lamports.to_le_bytes());
    leaf_preimage.extend_from_slice(&account_rent_epoch.to_le_bytes());
    leaf_preimage.extend_from_slice(&(account_data.len() as u64).to_le_bytes());
    leaf_preimage.extend_from_slice(&account_data);
    leaf_preimage.extend_from_slice(&account_owner);
    leaf_preimage.push(account_executable as u8);
    leaf_preimage.extend_from_slice(&account_address);

    let leaf_hash: [u8; 32] = Sha256::digest(&leaf_preimage).into();

    // ========================================================================
    // TODO: Fetch Merkle proof from Solana
    //
    // In production, this requires either:
    // 1. A custom RPC endpoint that computes Merkle proofs
    // 2. A validator sidecar that provides account proofs from snapshots
    // 3. Light Protocol integration for compressed state proofs
    //
    // For now, we use placeholder data. The SP1 circuit will verify
    // the proof regardless — it just won't match real on-chain state
    // until the production fetcher is implemented.
    // ========================================================================

    warn!("Using mock Merkle proof — production fetcher not yet implemented");

    // Mock: single-level Merkle tree where the leaf IS the root
    let account_proof: Vec<[u8; 32]> = Vec::new();
    let account_leaf_index: u64 = 0;
    let accounts_hash = leaf_hash; // Mock: accounts_hash = leaf_hash (single account tree)

    // ========================================================================
    // TODO: Fetch bank hash and its components
    //
    // bank_hash = SHA-256(accounts_hash || sig_count || last_blockhash || parent_bank_hash)
    // ========================================================================

    warn!("Using mock bank hash — production fetcher not yet implemented");

    let bank_hash_components = BankHashComponents {
        signature_count: 1,
        last_blockhash: [0u8; 32],
        parent_bank_hash: [0u8; 32],
    };

    // Compute bank hash from components
    let mut bank_preimage = Vec::new();
    bank_preimage.extend_from_slice(&accounts_hash);
    bank_preimage.extend_from_slice(&bank_hash_components.signature_count.to_le_bytes());
    bank_preimage.extend_from_slice(&bank_hash_components.last_blockhash);
    bank_preimage.extend_from_slice(&bank_hash_components.parent_bank_hash);
    let bank_hash: [u8; 32] = Sha256::digest(&bank_preimage).into();

    // ========================================================================
    // TODO: Fetch validator signatures and stake data
    //
    // In production:
    // 1. Query vote accounts for the current epoch
    // 2. Find validators who voted on the target slot
    // 3. Extract their Ed25519 signatures over the bank hash
    // 4. Get stake weights from the epoch stake snapshot
    // ========================================================================

    warn!("Using mock validator signatures — production fetcher not yet implemented");

    let validator_signatures: Vec<ValidatorSignature> = Vec::new();
    let epoch_stakes: Vec<ValidatorStake> = Vec::new();
    let total_epoch_stake: u64 = 0;

    // Get the current slot
    let slot = rpc.get_slot().unwrap_or(0);

    // ========================================================================
    // Build complete witness
    // ========================================================================

    let witness = SolanaProofWitness {
        account_data,
        account_address,
        account_owner,
        account_lamports,
        account_executable,
        account_rent_epoch,
        account_proof,
        account_leaf_index,
        accounts_hash,
        bank_hash,
        bank_hash_components,
        validator_signatures,
        epoch_stakes,
        total_epoch_stake,
        slot,
    };

    info!(
        "Witness built: account_data_len={}, slot={}",
        witness.account_data.len(),
        witness.slot,
    );

    Ok(witness)
}
