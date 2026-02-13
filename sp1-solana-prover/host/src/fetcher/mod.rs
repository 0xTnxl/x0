//! Production-grade Solana state proof fetcher for SP1 witness generation
//!
//! Orchestrates all data fetching needed to assemble a `SolanaProofWitness`:
//!
//! 1. **Account State** — fetches the BridgeOutMessage PDA data + metadata
//! 2. **Delta Tree** — builds the fanout-16 Merkle tree of accounts modified
//!    in the target slot, generates inclusion proof
//! 3. **Bank Hash** — fetches/derives the bank hash components
//! 4. **Validator Votes** — scans subsequent blocks for vote transactions
//!    attesting to the bank hash, cross-references with epoch stakes
//!
//! # Production Deployment
//!
//! The `fetch_witness()` function is designed for devnet/testnet use via
//! standard RPC. For mainnet, critical components should be replaced:
//!
//! - **Delta accounts**: Use a Geyser gRPC plugin (e.g., Jito, Yellowstone)
//!   to capture exact account state at each slot. Standard RPC returns
//!   CURRENT state, which may differ for frequently-modified accounts.
//!
//! - **Parent bank hash**: Not available via standard RPC. Requires Geyser
//!   plugins or validator-local APIs. See `SlotStateProvider` trait below.
//!
//! - **Bank hash**: Can be derived from components, or obtained from vote
//!   transactions in subsequent blocks (validators vote on it).

pub mod merkle;
pub mod rpc;
pub mod tx_parser;
pub mod votes;

use anyhow::{Context, Result};
use solana_client::rpc_client::RpcClient;
use solana_sdk::{account::Account, clock::Slot, pubkey::Pubkey};
use tracing::{info, warn};
use x0_sp1_solana_common::{BankHashComponents, SolanaProofWitness};

/// Number of subsequent blocks to scan for votes on the target bank hash.
///
/// Validators typically vote within 1-4 slots. We scan 8 for safety.
const VOTE_LOOKAHEAD_SLOTS: u64 = 8;

/// Fetch all data needed to construct a `SolanaProofWitness` for an SP1 proof
///
/// # Arguments
/// * `rpc` - Solana RPC client
/// * `bridge_program` - x0-bridge program ID
/// * `pda` - BridgeOutMessage PDA address
/// * `account` - Pre-fetched account data (for the PDA)
///
/// # Returns
/// Complete `SolanaProofWitness` ready for SP1 proof generation
pub async fn fetch_witness(
    rpc: &RpcClient,
    bridge_program: &Pubkey,
    pda: &Pubkey,
    account: &Account,
) -> Result<SolanaProofWitness> {
    info!("=== Fetching SP1 Proof Witness ===");
    info!("BridgeOutMessage PDA: {}", pda);
    info!("Bridge program: {}", bridge_program);

    // ========================================================================
    // Step 1: Find the slot where the BridgeOutMessage was created
    // ========================================================================

    info!("[1/6] Finding account creation slot...");
    let slot = rpc::get_account_creation_slot(rpc, pda)
        .context("Failed to find creation slot for BridgeOutMessage")?;
    info!("BridgeOutMessage created at slot {}", slot);

    // Warn about epoch boundaries — bank hash has extra mixing
    if is_likely_epoch_boundary(rpc, slot)? {
        warn!(
            "Slot {} is near an epoch boundary. Bank hash may include \
             epoch_accounts_hash. Consider using a different slot.",
            slot
        );
    }

    // ========================================================================
    // Step 2: Fetch all accounts modified in the target slot (delta set)
    // ========================================================================

    info!("[2/6] Fetching accounts modified in slot {}...", slot);
    let delta_accounts = rpc::fetch_slot_delta_accounts(rpc, slot)
        .context("Failed to fetch delta accounts")?;

    info!("Delta set: {} accounts", delta_accounts.len());

    // Validate that the target PDA's state matches what we have
    if let Some((_, delta_acct)) = delta_accounts.iter().find(|(p, _)| p == pda) {
        if delta_acct.data != account.data {
            warn!(
                "Target PDA state in delta differs from fetched account! \
                 The account may have been modified since slot {}. \
                 Delta data: {} bytes, fetched data: {} bytes.",
                slot,
                delta_acct.data.len(),
                account.data.len(),
            );
        }
    }

    // Best-effort freshness check on delta accounts
    let stale_count = rpc::validate_delta_freshness(rpc, &delta_accounts, slot)
        .unwrap_or_else(|e| {
            warn!("Could not validate delta freshness: {}", e);
            0
        });

    if stale_count > 0 {
        warn!(
            "Proceeding with potentially stale delta state. \
             The Merkle root may not match the on-chain accounts_delta_hash. \
             For production, use a Geyser plugin for exact slot-level snapshots."
        );
    }

    // ========================================================================
    // Step 3: Build the accounts_delta_hash tree and inclusion proof
    // ========================================================================

    info!("[3/6] Building fanout-16 Merkle tree...");

    // Verify our target account exists in the delta set
    anyhow::ensure!(
        delta_accounts.iter().any(|(pubkey, _)| pubkey == pda),
        "BridgeOutMessage PDA not found in slot delta accounts"
    );

    // Compute account hashes for all delta accounts (sorted by pubkey)
    let mut sorted_entries: Vec<(Pubkey, [u8; 32])> = delta_accounts
        .iter()
        .map(|(pubkey, acct)| {
            let hash = merkle::compute_solana_account_hash(
                acct.lamports,
                &acct.owner.to_bytes(),
                acct.executable,
                acct.rent_epoch,
                &acct.data,
                &pubkey.to_bytes(),
            );
            (*pubkey, hash)
        })
        .collect();

    // Solana sorts by pubkey before building the tree
    sorted_entries.sort_by_key(|(pubkey, _)| *pubkey);

    // Find the target's position after sorting
    let sorted_target_index = sorted_entries
        .iter()
        .position(|(pubkey, _)| pubkey == pda)
        .expect("Target must be in sorted list");

    let hashes: Vec<[u8; 32]> = sorted_entries.iter().map(|(_, h)| *h).collect();

    // Compute the delta root
    let accounts_delta_hash = merkle::compute_merkle_root(&hashes);
    info!(
        "accounts_delta_hash: 0x{}",
        hex::encode(&accounts_delta_hash[..8])
    );

    // Generate inclusion proof
    let inclusion_proof = merkle::generate_inclusion_proof(&hashes, sorted_target_index);
    info!(
        "Inclusion proof: {} levels, target at sorted index {}",
        inclusion_proof.levels.len(),
        sorted_target_index
    );

    // Verify proof locally before sending to SP1
    let target_hash = hashes[sorted_target_index];
    assert!(
        merkle::verify_inclusion_proof(target_hash, &inclusion_proof, &accounts_delta_hash),
        "Local Merkle proof verification failed!"
    );
    info!("Local Merkle proof verification passed");

    // ========================================================================
    // Step 4: Derive bank hash components
    //
    // bank_hash = SHA-256(parent_bank_hash || delta_hash || sig_count_le || last_blockhash)
    //
    // LIMITATION: parent_bank_hash is not available via standard RPC.
    // We derive the bank hash from vote transactions instead.
    // ========================================================================

    info!("[4/6] Fetching bank hash components...");

    let block = rpc::fetch_block(rpc, slot)
        .context("Failed to fetch target block")?;

    let last_blockhash = block
        .blockhash
        .parse::<solana_sdk::hash::Hash>()
        .context("Failed to parse blockhash")?
        .to_bytes();

    // Count signatures in the block
    let signature_count: u64 = block
        .transactions
        .as_ref()
        .map_or(0, |txs| {
            txs.iter()
                .filter_map(|tx| tx.meta.as_ref())
                .filter(|meta| meta.err.is_none())
                .count() as u64
        });

    info!(
        "Block info: blockhash=0x{}, sig_count={}",
        hex::encode(&last_blockhash[..8]),
        signature_count
    );

    // ========================================================================
    // Step 5: Find the actual bank hash from validator votes
    //
    // Since we can't derive bank_hash without parent_bank_hash (which is not
    // available via standard RPC), we find it from validator votes.
    //
    // Validators in subsequent slots vote on slot hashes. We scan for votes
    // that reference our target slot, then extract the bank hash they voted on.
    //
    // SECURITY: We can't verify the bank hash matches our delta_hash without
    // the parent_bank_hash. The circuit still verifies the inclusion proof
    // chain: account → delta_hash → bank_hash → validator quorum.
    //
    // In production with Geyser, we'd have the parent_bank_hash and could
    // verify the derivation directly.
    // ========================================================================

    info!(
        "[5/6] Scanning {} subsequent slots for vote transactions...",
        VOTE_LOOKAHEAD_SLOTS
    );

    // Fetch vote accounts for cross-referencing
    let vote_accounts = rpc::fetch_vote_accounts(rpc)
        .context("Failed to fetch vote accounts")?;

    let (epoch_stakes, total_epoch_stake) = rpc::to_epoch_stakes(&vote_accounts);

    // Strategy: We need to find the bank hash for our slot.
    // Approach 1: Use getBlockCommitment or similar RPC to get the slot hash
    // Approach 2: Parse votes in subsequent blocks that reference our slot
    //
    // We use approach 2 since it provides the actual vote transactions we need.

    // First, try to get the bank hash from slot hashes
    // (Solana's SlotHashes sysvar maps recent slots to their bank hashes)
    let bank_hash = find_bank_hash_for_slot(rpc, slot, &vote_accounts)
        .context("Failed to find bank hash for slot")?;

    info!(
        "Bank hash for slot {}: 0x{}",
        slot,
        hex::encode(&bank_hash[..8])
    );

    // Now scan for vote transactions that voted on this bank hash
    let vote_blocks = rpc::fetch_vote_blocks(rpc, slot + 1, VOTE_LOOKAHEAD_SLOTS)
        .context("Failed to fetch vote blocks")?;

    let mut all_parsed_votes = Vec::new();
    for (vote_slot, vote_block) in &vote_blocks {
        let parsed = votes::extract_votes_for_bank_hash(vote_block, &bank_hash);
        info!("Slot {}: found {} votes", vote_slot, parsed.len());
        all_parsed_votes.extend(parsed);
    }

    // Convert to ValidatorVote structs with stake info
    let validator_votes = votes::to_validator_votes(&all_parsed_votes, &vote_accounts);

    let confirmed_stake: u64 = validator_votes.iter().map(|v| v.stake).sum();
    info!(
        "Validator votes: {} total, confirmed stake = {} ({:.1}% of total)",
        validator_votes.len(),
        confirmed_stake,
        (confirmed_stake as f64 / total_epoch_stake as f64) * 100.0
    );

    if confirmed_stake * 3 < total_epoch_stake * 2 {
        warn!(
            "Insufficient quorum! Need ≥ 66.7%, have {:.1}%. \
             Try increasing VOTE_LOOKAHEAD_SLOTS or waiting for more votes.",
            (confirmed_stake as f64 / total_epoch_stake as f64) * 100.0
        );
    }

    // ========================================================================
    // Step 6: Assemble the complete witness
    // ========================================================================

    info!("[6/6] Assembling witness...");

    // Bank hash components — for the circuit to re-derive
    // NOTE: parent_bank_hash is a placeholder when using standard RPC.
    // The circuit will verify via vote quorum instead.
    let bank_hash_components = BankHashComponents {
        parent_bank_hash: [0u8; 32], // Placeholder — see note above
        signature_count,
        last_blockhash,
    };

    let witness = SolanaProofWitness {
        account_data: account.data.clone(),
        account_address: pda.to_bytes(),
        account_owner: account.owner.to_bytes(),
        account_lamports: account.lamports,
        account_executable: account.executable,
        account_rent_epoch: account.rent_epoch,
        inclusion_proof,
        accounts_delta_hash,
        bank_hash,
        bank_hash_components,
        validator_votes,
        epoch_stakes,
        total_epoch_stake,
        slot,
    };

    info!("=== Witness assembly complete ===");
    info!("  Account data: {} bytes", witness.account_data.len());
    info!("  Inclusion proof: {} levels", witness.inclusion_proof.levels.len());
    info!("  Validator votes: {}", witness.validator_votes.len());
    info!("  Epoch stakes: {} validators", witness.epoch_stakes.len());
    info!(
        "  Confirmed stake: {:.1}%",
        (confirmed_stake as f64 / total_epoch_stake as f64) * 100.0
    );

    Ok(witness)
}

/// Check if a slot is near an epoch boundary
///
/// Epoch boundaries involve extra `epoch_accounts_hash` mixing in the bank hash
/// computation. We avoid these slots for simplicity.
fn is_likely_epoch_boundary(rpc: &RpcClient, slot: Slot) -> Result<bool> {
    let epoch_info = rpc
        .get_epoch_info()
        .context("Failed to get epoch info")?;

    let slots_per_epoch = epoch_info.slots_in_epoch;
    let slot_in_epoch = slot % slots_per_epoch;

    // Consider the first and last 10 slots of each epoch as boundary
    let at_boundary = slot_in_epoch < 10 || slot_in_epoch >= slots_per_epoch - 10;

    if at_boundary {
        warn!(
            "Slot {} is at position {} in epoch (length {}) — near boundary",
            slot, slot_in_epoch, slots_per_epoch
        );
    }

    Ok(at_boundary)
}

/// Find the bank hash for a specific slot
///
/// Uses multiple strategies:
/// 1. Parse vote transactions in subsequent slots to find votes referencing
///    the target slot's bank hash
/// 2. Use slot commitment information
///
/// The bank hash associates a slot with its state root. Validators vote on
/// (slot, bank_hash) pairs.
fn find_bank_hash_for_slot(
    rpc: &RpcClient,
    target_slot: Slot,
    vote_accounts: &[(Pubkey, Pubkey, u64)],
) -> Result<[u8; 32]> {
    info!("Finding bank hash for slot {}...", target_slot);

    // Strategy: Fetch the confirmed block and get its hash from the block itself
    // The block's previous_blockhash and blockhash fields are PoH hashes,
    // not bank hashes. We need to find the bank hash.
    //
    // The bank hash for a slot is included in vote transactions in subsequent
    // slots. We scan forward to find a confirmed vote.

    // Scan subsequent blocks for vote transactions
    let vote_blocks = rpc::fetch_vote_blocks(rpc, target_slot + 1, VOTE_LOOKAHEAD_SLOTS * 2)
        .context("Failed to fetch blocks for vote scanning")?;

    // Try to find the bank hash by parsing vote instruction data.
    // Vote instructions contain the slot number and corresponding bank hash.
    for (_block_slot, block) in &vote_blocks {
        if let Some(bank_hash) = try_extract_bank_hash_from_votes(block, target_slot, vote_accounts) {
            info!(
                "Found bank hash via vote in block: 0x{}",
                hex::encode(&bank_hash[..8])
            );
            return Ok(bank_hash);
        }
    }

    anyhow::bail!(
        "Could not find bank hash for slot {} in {} subsequent blocks. \
         The slot may not yet be finalized, or the vote lookahead is too short.",
        target_slot,
        VOTE_LOOKAHEAD_SLOTS * 2
    )
}

/// Try to extract the bank hash for a target slot from vote transactions in a block
///
/// Parses vote instruction data to find VoteStateUpdate/CompactUpdateVoteState/TowerSync
/// entries that reference the target slot, and extracts the associated bank hash.
fn try_extract_bank_hash_from_votes(
    block: &solana_transaction_status::UiConfirmedBlock,
    target_slot: Slot,
    vote_accounts: &[(Pubkey, Pubkey, u64)],
) -> Option<[u8; 32]> {
    let transactions = block.transactions.as_ref()?;
    let vote_program = tx_parser::VOTE_PROGRAM_ID_STR.parse::<Pubkey>().ok()?;

    for tx_with_meta in transactions {
        // Skip failed transactions
        if let Some(ref meta) = tx_with_meta.meta {
            if meta.err.is_some() {
                continue;
            }
        }

        let Some(raw_bytes) = tx_parser::decode_transaction_bytes(&tx_with_meta.transaction) else {
            continue;
        };
        let Some((message_bytes, _, account_keys)) = tx_parser::parse_raw_transaction(&raw_bytes) else {
            continue;
        };

        // Only trust votes from known validator vote authorities
        if !account_keys.is_empty() {
            let signer = &account_keys[0];
            if !vote_accounts.iter().any(|(auth, _, _)| auth == signer) {
                continue;
            }
        }

        // Find vote program index
        let vote_idx = account_keys.iter().position(|k| *k == vote_program)?;

        // Parse instructions
        let instructions = tx_parser::parse_instructions_from_message(&message_bytes)?;

        for (program_idx, ix_data, _) in &instructions {
            if *program_idx as usize != vote_idx {
                continue;
            }

            // Try to parse the vote instruction to find our target slot's hash
            if let Some(hash) = parse_vote_for_slot(ix_data, target_slot) {
                return Some(hash);
            }
        }
    }

    None
}

/// Parse a vote instruction to find a specific slot's bank hash
///
/// Supports multiple vote instruction variants:
/// - `UpdateVoteState` (tag 6): lockouts + root + hash + timestamp
/// - `CompactUpdateVoteState` (tag 12): compact lockouts + root + hash + timestamp
/// - `TowerSync` (tag 14, v1.18+): compact lockouts + root + hash + timestamp + block_id
///
/// Returns the bank hash if the vote references the target slot.
fn parse_vote_for_slot(ix_data: &[u8], target_slot: Slot) -> Option<[u8; 32]> {
    if ix_data.len() < 4 {
        return None;
    }

    let tag = u32::from_le_bytes(ix_data[0..4].try_into().ok()?);

    match tag {
        // CompactUpdateVoteState (tag = 12) — most common in v1.18
        12 | 14 => parse_compact_vote_state(&ix_data[4..], target_slot),

        // UpdateVoteState (tag = 6)
        6 => parse_update_vote_state(&ix_data[4..], target_slot),

        _ => None,
    }
}

/// Parse CompactUpdateVoteState / TowerSync instruction data
///
/// Layout:
///   [compact_u16: num_lockouts]
///   [lockouts: for each { compact_u16: slot_delta, u8: confirmation_count }]
///   [u8: has_root (0 or 1)]
///   [if has_root: u64 LE: root_slot]
///   [32 bytes: hash (bank hash)]
///   [u8: has_timestamp (0 or 1)]
///   [if has_timestamp: i64 LE: timestamp]
fn parse_compact_vote_state(data: &[u8], target_slot: Slot) -> Option<[u8; 32]> {
    let mut offset = 0;

    let (num_lockouts, bytes_read) = tx_parser::read_compact_u16(data, offset)?;
    offset += bytes_read;

    // Parse lockouts to find the target slot
    let mut current_slot: u64 = 0;
    let mut found_target = false;

    for _ in 0..num_lockouts {
        let (slot_delta, bytes_read) = tx_parser::read_compact_u16(data, offset)?;
        offset += bytes_read;

        current_slot = current_slot.checked_add(slot_delta as u64)?;

        if offset >= data.len() {
            return None;
        }
        let _confirmation_count = data[offset];
        offset += 1;

        if current_slot == target_slot {
            found_target = true;
        }
    }

    if !found_target {
        return None;
    }

    // Parse optional root
    if offset >= data.len() {
        return None;
    }
    let has_root = data[offset];
    offset += 1;
    if has_root == 1 {
        offset += 8; // Skip root slot (u64 LE)
    }

    // Next 32 bytes: the bank hash
    if offset + 32 > data.len() {
        return None;
    }

    let mut hash = [0u8; 32];
    hash.copy_from_slice(&data[offset..offset + 32]);

    Some(hash)
}

/// Parse UpdateVoteState instruction data
///
/// Layout:
///   [u32 LE: num_lockouts]
///   [lockouts: for each { u64 LE: slot, u32 LE: confirmation_count }]
///   [u8: has_root (0 or 1)]
///   [if has_root: u64 LE: root_slot]
///   [32 bytes: hash (bank hash)]
///   [u8: has_timestamp (0 or 1)]
///   [if has_timestamp: i64 LE: timestamp]
fn parse_update_vote_state(data: &[u8], target_slot: Slot) -> Option<[u8; 32]> {
    let mut offset = 0;

    if offset + 4 > data.len() {
        return None;
    }
    let num_lockouts = u32::from_le_bytes(data[offset..offset + 4].try_into().ok()?) as usize;
    offset += 4;

    let mut found_target = false;

    for _ in 0..num_lockouts {
        if offset + 12 > data.len() {
            return None;
        }
        let slot = u64::from_le_bytes(data[offset..offset + 8].try_into().ok()?);
        offset += 8;
        let _confirmation_count = u32::from_le_bytes(data[offset..offset + 4].try_into().ok()?);
        offset += 4;

        if slot == target_slot {
            found_target = true;
        }
    }

    if !found_target {
        return None;
    }

    // Parse optional root
    if offset >= data.len() {
        return None;
    }
    let has_root = data[offset];
    offset += 1;
    if has_root == 1 {
        offset += 8;
    }

    // Next 32 bytes: the bank hash
    if offset + 32 > data.len() {
        return None;
    }

    let mut hash = [0u8; 32];
    hash.copy_from_slice(&data[offset..offset + 32]);

    Some(hash)
}
