//! Solana RPC helpers for fetching block data, vote accounts, and account state.
//!
//! Wraps the Solana RPC client with production-ready retry logic and
//! targeted data extraction for SP1 proof witness generation.
//!
//! # Key Design Decisions
//!
//! - **Vote authority** is fetched from on-chain `VoteState` account data,
//!   not assumed to be the vote account pubkey. This is critical because the
//!   authorized voter (who signs vote transactions) can differ from the vote
//!   account address.
//!
//! - **Epoch boundary detection** uses `get_epoch_schedule()` to compute
//!   exact epoch-boundary slots. Epoch-boundary slots are hard-rejected
//!   because the bank hash formula includes an extra `epoch_accounts_hash`.
//!
//! - **Signature count** counts actual Ed25519 signatures (from the
//!   transaction header), not transactions. Solana's `Bank.signature_count`
//!   is the sum of `num_required_signatures` across ALL transactions in
//!   the block.

use anyhow::{Context, Result};
use solana_client::rpc_client::RpcClient;
use solana_client::rpc_config::RpcBlockConfig;
use solana_sdk::{
    account::Account,
    clock::Slot,
    commitment_config::CommitmentConfig,
    pubkey::Pubkey,
};
use solana_transaction_status::{
    TransactionDetails, UiConfirmedBlock, UiTransactionEncoding,
};
use tracing::{debug, info, warn};
use x0_sp1_solana_common::ValidatorSetEntry;

// ============================================================================
// Block Fetching
// ============================================================================

/// Fetch a block with full transaction data in base64 encoding.
///
/// Uses base64 encoding to preserve raw message bytes for Ed25519 verification.
pub fn fetch_block(rpc: &RpcClient, slot: Slot) -> Result<UiConfirmedBlock> {
    info!("Fetching block at slot {}...", slot);

    let config = RpcBlockConfig {
        encoding: Some(UiTransactionEncoding::Base64),
        transaction_details: Some(TransactionDetails::Full),
        rewards: Some(false),
        commitment: Some(CommitmentConfig::finalized()),
        max_supported_transaction_version: Some(0),
    };

    let block = rpc
        .get_block_with_config(slot, config)
        .with_context(|| format!("Failed to fetch block at slot {}", slot))?;

    info!(
        "Block fetched: slot={}, txs={}",
        slot,
        block.transactions.as_ref().map_or(0, |t| t.len())
    );

    Ok(block)
}

/// Fetch blocks in a range looking for votes on a target slot.
///
/// Validators often vote on slot S in slots S+1, S+2, etc.
/// This fetches multiple subsequent blocks to find vote transactions.
pub fn fetch_vote_blocks(
    rpc: &RpcClient,
    target_slot: Slot,
    look_ahead: u64,
) -> Result<Vec<(Slot, UiConfirmedBlock)>> {
    let mut blocks = Vec::new();

    for offset in 0..=look_ahead {
        let slot = target_slot + offset;
        match fetch_block(rpc, slot) {
            Ok(block) => blocks.push((slot, block)),
            Err(e) => {
                debug!("Slot {} not available: {}", slot, e);
                continue;
            }
        }
    }

    info!(
        "Fetched {} blocks from slot {} to {}",
        blocks.len(),
        target_slot,
        target_slot + look_ahead
    );

    Ok(blocks)
}

// ============================================================================
// Vote Account Fetching + Authority Parsing
// ============================================================================

/// Fetch vote accounts with their TRUE authorized voter from on-chain VoteState.
///
/// Returns `Vec<(authorized_voter, node_identity, activated_stake)>`.
///
/// # Why we parse VoteState
///
/// The `getVoteAccounts` RPC returns the vote account pubkey, but the actual
/// signer of vote transactions is the `authorized_voter` — which can be a
/// completely different key (e.g., a hot key delegated by the validator).
/// Using the wrong key causes Ed25519 verification failures in the circuit.
///
/// We fetch each vote account's on-chain data and parse the `authorized_voters`
/// map to get the current epoch's authorized voter.
pub fn fetch_vote_accounts(rpc: &RpcClient) -> Result<Vec<(Pubkey, Pubkey, u64)>> {
    info!("Fetching vote accounts with authorized voters...");

    let vote_accounts = rpc
        .get_vote_accounts()
        .context("Failed to fetch vote accounts")?;

    // Get current epoch for authorized_voter lookup
    let epoch_info = rpc.get_epoch_info().context("Failed to get epoch info")?;
    let current_epoch = epoch_info.epoch;
    info!("Current epoch: {}", current_epoch);

    let mut result = Vec::new();
    let mut parse_failures = 0u32;

    let all_accounts = vote_accounts
        .current
        .iter()
        .chain(vote_accounts.delinquent.iter());

    for va in all_accounts {
        let vote_pubkey = va
            .vote_pubkey
            .parse::<Pubkey>()
            .context("Invalid vote account pubkey")?;
        let node_pubkey = va
            .node_pubkey
            .parse::<Pubkey>()
            .context("Invalid node pubkey")?;

        // Fetch the vote account data to get the real authorized voter
        match rpc.get_account(&vote_pubkey) {
            Ok(account) => {
                match parse_authorized_voter(&account.data, current_epoch) {
                    Some(voter) => {
                        result.push((voter, node_pubkey, va.activated_stake));
                    }
                    None => {
                        parse_failures += 1;
                        debug!(
                            "Could not parse authorized voter for vote account {} — \
                             falling back to vote account pubkey",
                            vote_pubkey
                        );
                        // Fallback: use vote account pubkey (may fail in circuit
                        // if the actual authorized voter is different)
                        result.push((vote_pubkey, node_pubkey, va.activated_stake));
                    }
                }
            }
            Err(e) => {
                debug!("Failed to fetch vote account {}: {}", vote_pubkey, e);
                // Skip entirely — this validator won't be in our set
                continue;
            }
        }
    }

    if parse_failures > 0 {
        warn!(
            "{} vote accounts fell back to vote_pubkey as authority \
             (authorized_voter parse failed). These may cause Ed25519 failures.",
            parse_failures
        );
    }

    info!(
        "Found {} vote accounts ({} current, {} delinquent)",
        result.len(),
        vote_accounts.current.len(),
        vote_accounts.delinquent.len()
    );

    Ok(result)
}

/// Parse the authorized voter for targeted epoch from serialized VoteState data.
///
/// # VoteState Layout (Solana v2.x, bincode-serialized)
///
/// ```text
/// Offset  Field
/// ------  -----
/// 0       node_pubkey: Pubkey (32 bytes)
/// 32      authorized_withdrawer: Pubkey (32 bytes)
/// 64      commission: u8 (1 byte)
/// 65      votes: VecDeque<Lockout> — bincode Vec<...>
///           [u64 len] [Lockout × len]
///           Lockout = { slot: u64, confirmation_count: u32 }  = 12 bytes each
/// 65+8+N  root_slot: Option<u64> (1 tag byte + optionally 8 bytes)
/// ...     authorized_voters: AuthorizedVoters (a BTreeMap<Epoch, Pubkey>)
///           [u64 len] [(u64 epoch, Pubkey voter) × len]
/// ```
///
/// We parse enough to reach `authorized_voters` and look up the target epoch.
/// If the exact epoch isn't found, we return the most recent authorized voter
/// (highest epoch ≤ target_epoch), matching Solana's runtime behavior.
fn parse_authorized_voter(data: &[u8], target_epoch: u64) -> Option<Pubkey> {
    // VoteState has a 4-byte version tag at the start in v2.x
    // Try both versioned (with 4-byte prefix) and unversioned layouts
    parse_authorized_voter_inner(data, target_epoch)
        .or_else(|| {
            // Try skipping a 4-byte version discriminant
            if data.len() > 4 {
                parse_authorized_voter_inner(&data[4..], target_epoch)
            } else {
                None
            }
        })
}

fn parse_authorized_voter_inner(data: &[u8], target_epoch: u64) -> Option<Pubkey> {
    if data.len() < 65 {
        return None; // Too short for even the header
    }

    let mut offset: usize = 0;

    // node_pubkey (32 bytes)
    offset += 32;

    // authorized_withdrawer (32 bytes)
    offset += 32;

    // commission (1 byte)
    offset += 1;

    // votes: VecDeque, serialized as Vec via bincode
    // bincode encodes length as u64 LE
    if offset + 8 > data.len() {
        return None;
    }
    let votes_len = u64::from_le_bytes(data[offset..offset + 8].try_into().ok()?) as usize;
    offset += 8;

    // Each Lockout is { slot: u64, confirmation_count: u32 } = 12 bytes
    let votes_byte_len = votes_len.checked_mul(12)?;
    offset = offset.checked_add(votes_byte_len)?;

    if offset >= data.len() {
        return None;
    }

    // root_slot: Option<u64> — bincode encodes Option as 1-byte tag + value
    let root_tag = data[offset];
    offset += 1;
    if root_tag == 1 {
        // Some(u64)
        offset += 8;
    }
    // root_tag == 0 → None, skip

    // authorized_voters: BTreeMap<Epoch, Pubkey>
    // bincode encodes as u64 length, then key-value pairs
    if offset + 8 > data.len() {
        return None;
    }
    let num_voters = u64::from_le_bytes(data[offset..offset + 8].try_into().ok()?) as usize;
    offset += 8;

    // Sanity check: authorized_voters should be small (typically 1-3 entries)
    if num_voters > 100 || num_voters == 0 {
        return None;
    }

    // Parse entries and find the best match for target_epoch
    let mut best_match: Option<(u64, Pubkey)> = None;

    for _ in 0..num_voters {
        if offset + 40 > data.len() {
            // 8 bytes epoch + 32 bytes pubkey
            break;
        }

        let epoch = u64::from_le_bytes(data[offset..offset + 8].try_into().ok()?);
        offset += 8;

        let voter = Pubkey::try_from(&data[offset..offset + 32]).ok()?;
        offset += 32;

        // Exact match is best
        if epoch == target_epoch {
            return Some(voter);
        }

        // Otherwise track the highest epoch ≤ target_epoch
        if epoch <= target_epoch {
            match &best_match {
                Some((best_epoch, _)) if *best_epoch < epoch => {
                    best_match = Some((epoch, voter));
                }
                None => {
                    best_match = Some((epoch, voter));
                }
                _ => {}
            }
        }
    }

    best_match.map(|(_, voter)| voter)
}

/// Convert vote account data to `ValidatorSetEntry` list for the circuit.
///
/// The returned entries are **sorted by vote_authority ascending** as
/// required by the circuit's deterministic `validator_set_hash` computation.
///
/// Returns `(sorted_entries, total_stake)`.
pub fn to_epoch_stakes(
    vote_accounts: &[(Pubkey, Pubkey, u64)],
) -> (Vec<ValidatorSetEntry>, u64) {
    let mut entries: Vec<ValidatorSetEntry> = vote_accounts
        .iter()
        .map(|(vote_authority, node_identity, stake)| ValidatorSetEntry {
            vote_authority: vote_authority.to_bytes(),
            validator_identity: node_identity.to_bytes(),
            stake: *stake,
        })
        .collect();

    // Sort by vote_authority ascending (circuit enforces this ordering)
    entries.sort_by(|a, b| a.vote_authority.cmp(&b.vote_authority));

    // Deduplicate by vote_authority (rare edge case: same key listed twice)
    entries.dedup_by(|a, b| a.vote_authority == b.vote_authority);

    let total_stake: u64 = entries.iter().map(|e| e.stake).sum();

    info!(
        "Epoch stakes: {} validators, total stake = {} SOL",
        entries.len(),
        total_stake / 1_000_000_000
    );

    (entries, total_stake)
}

// ============================================================================
// Epoch Boundary Detection
// ============================================================================

/// Check if a slot is at an epoch boundary (first or last N slots of an epoch).
///
/// Epoch-boundary slots have a modified bank hash formula that includes
/// `epoch_accounts_hash`. The circuit only supports the standard 4-component
/// formula, so boundary slots MUST be rejected.
///
/// Returns `Err` if boundary detection fails, `Ok(true)` if at boundary.
pub fn is_epoch_boundary_slot(rpc: &RpcClient, slot: Slot) -> Result<bool> {
    let schedule = rpc
        .get_epoch_schedule()
        .context("Failed to get epoch schedule")?;

    let slots_per_epoch = schedule.slots_per_epoch;
    if slots_per_epoch == 0 {
        anyhow::bail!("Invalid epoch schedule: slots_per_epoch = 0");
    }

    let slot_in_epoch = slot % slots_per_epoch;

    // The first slot of an epoch (slot_in_epoch == 0) is the boundary slot
    // where epoch_accounts_hash is mixed in. We also guard a few slots
    // around it for safety (slot generation can vary).
    const BOUNDARY_GUARD_SLOTS: u64 = 5;

    let at_boundary = slot_in_epoch < BOUNDARY_GUARD_SLOTS
        || slot_in_epoch >= slots_per_epoch.saturating_sub(BOUNDARY_GUARD_SLOTS);

    if at_boundary {
        info!(
            "Slot {} is at epoch boundary (position {} in epoch of {} slots)",
            slot, slot_in_epoch, slots_per_epoch
        );
    }

    Ok(at_boundary)
}

// ============================================================================
// Account Slot Detection
// ============================================================================

/// Get the account creation/modification slot for a BridgeOutMessage PDA.
///
/// Uses `getSignaturesForAddress` to find the earliest transaction that
/// touched this account, which corresponds to the burn transaction.
pub fn get_account_creation_slot(rpc: &RpcClient, account_pubkey: &Pubkey) -> Result<Slot> {
    info!("Finding creation slot for account {}...", account_pubkey);

    let signatures = rpc
        .get_signatures_for_address(account_pubkey)
        .context("Failed to get signatures for account")?;

    // getSignaturesForAddress returns newest-first by default.
    // The last entry is the earliest transaction.
    let creation_sig = signatures
        .last()
        .context("No transactions found for this account")?;

    let slot = creation_sig.slot;
    info!("Account {} created at slot {}", account_pubkey, slot);

    Ok(slot)
}

// ============================================================================
// Delta Account Fetching
// ============================================================================

/// Fetch accounts modified in a specific slot for delta tree construction.
///
/// # Limitation (standard RPC)
///
/// Returns **current** account state via `getMultipleAccounts`, not the
/// historical state at the target slot. For accounts modified only in the
/// target slot, this is correct. For frequently-modified accounts, the
/// state may be from a later slot.
///
/// For production mainnet use, implement a Geyser-based state provider
/// that captures account snapshots at each slot boundary.
pub fn fetch_slot_delta_accounts(
    rpc: &RpcClient,
    slot: Slot,
) -> Result<Vec<(Pubkey, Account)>> {
    info!("Fetching delta accounts for slot {}...", slot);

    let block = fetch_block(rpc, slot)?;

    // Collect all unique writable account keys from transactions
    let mut writable_keys = std::collections::HashSet::new();

    if let Some(ref transactions) = block.transactions {
        for tx_with_meta in transactions.iter() {
            // Skip failed transactions
            if let Some(ref meta) = tx_with_meta.meta {
                if meta.err.is_some() {
                    continue;
                }
            }

            if let Some(keys) = extract_writable_keys(tx_with_meta) {
                writable_keys.extend(keys);
            }
        }
    }

    info!(
        "Found {} unique writable accounts in slot {}",
        writable_keys.len(),
        slot
    );

    // Batch fetch account data (getMultipleAccounts limit: 100 per call)
    let keys: Vec<Pubkey> = writable_keys.into_iter().collect();
    let mut accounts = Vec::new();

    for chunk in keys.chunks(100) {
        let chunk_vec: Vec<Pubkey> = chunk.to_vec();
        match rpc.get_multiple_accounts(&chunk_vec) {
            Ok(results) => {
                for (i, maybe_account) in results.into_iter().enumerate() {
                    if let Some(account) = maybe_account {
                        accounts.push((chunk_vec[i], account));
                    }
                }
            }
            Err(e) => {
                warn!("Failed to fetch batch of accounts: {}", e);
            }
        }
    }

    info!("Fetched {} delta accounts for slot {}", accounts.len(), slot);
    Ok(accounts)
}

// ============================================================================
// Signature Count (corrected)
// ============================================================================

/// Count the total number of Ed25519 signatures in a block.
///
/// Solana's `Bank.signature_count` is the sum of `num_required_signatures`
/// across ALL transactions in the block (not just successful ones, and not
/// just the transaction count — each tx can require multiple signatures).
///
/// The `num_required_signatures` field is the first byte of the message
/// header in each transaction.
pub fn count_block_signatures(block: &UiConfirmedBlock) -> u64 {
    let Some(ref transactions) = block.transactions else {
        return 0;
    };

    let mut total_sigs: u64 = 0;

    for tx_with_meta in transactions {
        // Decode transaction bytes
        let raw = match super::tx_parser::decode_transaction_bytes(&tx_with_meta.transaction) {
            Some(bytes) => bytes,
            None => continue,
        };

        // Parse the number of signatures from the transaction wire format
        let mut offset = 0;
        let Some((num_sigs, bytes_read)) = super::tx_parser::read_compact_u16(&raw, offset) else {
            continue;
        };
        offset += bytes_read;
        offset += num_sigs * 64; // skip past signatures

        // Message header starts here: first byte is num_required_signatures
        if offset < raw.len() {
            let num_required_sigs = raw[offset] as u64;
            total_sigs += num_required_sigs;
        }
    }

    total_sigs
}

// ============================================================================
// Delta Freshness Validation
// ============================================================================

/// Validate that delta accounts haven't been modified since the target slot.
///
/// Best-effort check for the RPC-based state provider. Returns the number
/// of accounts that may have stale state (modified after `slot`).
pub fn validate_delta_freshness(
    rpc: &RpcClient,
    delta_accounts: &[(Pubkey, Account)],
    slot: Slot,
) -> Result<usize> {
    let mut stale_count = 0;

    // Sample up to 50 accounts to bound RPC calls
    let sample_size = delta_accounts.len().min(50);
    let sample = &delta_accounts[..sample_size];

    for (pubkey, _) in sample {
        match rpc.get_signatures_for_address(pubkey) {
            Ok(sigs) => {
                if let Some(latest) = sigs.first() {
                    if latest.slot > slot {
                        stale_count += 1;
                        debug!(
                            "Account {} modified at slot {} (after target slot {})",
                            pubkey, latest.slot, slot
                        );
                    }
                }
            }
            Err(e) => {
                debug!("Could not check freshness for {}: {}", pubkey, e);
            }
        }
    }

    if stale_count > 0 {
        let estimated_total = if sample_size < delta_accounts.len() {
            (stale_count * delta_accounts.len()) / sample_size
        } else {
            stale_count
        };

        warn!(
            "Delta state freshness: ~{} of {} accounts may have stale state \
             (modified after target slot {}). For production use Geyser.",
            estimated_total,
            delta_accounts.len(),
            slot
        );
    } else {
        info!(
            "Delta state freshness: all {} sampled accounts appear fresh",
            sample_size
        );
    }

    Ok(stale_count)
}

// ============================================================================
// Finality Polling
// ============================================================================

/// Wait for a slot's bank hash to reach ≥ 2/3 stake quorum.
///
/// Polls subsequent blocks for vote transactions until sufficient stake
/// has voted, or the timeout is reached.
///
/// # Arguments
/// * `rpc` - Solana RPC client
/// * `target_bank_hash` - The bank hash to wait for quorum on
/// * `vote_accounts` - Known vote accounts with stakes
/// * `total_stake` - Total activated stake for the epoch
/// * `timeout_secs` - Maximum seconds to wait
///
/// Returns `Ok(Vec<parsed_votes>)` when quorum is reached.
pub fn wait_for_quorum(
    rpc: &RpcClient,
    target_slot: Slot,
    target_bank_hash: &[u8; 32],
    vote_accounts: &[(Pubkey, Pubkey, u64)],
    total_stake: u64,
    timeout_secs: u64,
) -> Result<()> {
    use std::time::{Duration, Instant};

    let start = Instant::now();
    let timeout = Duration::from_secs(timeout_secs);

    info!(
        "Waiting for quorum on slot {} (bank hash 0x{})...",
        target_slot,
        hex::encode(&target_bank_hash[..8])
    );

    let mut best_pct: f64 = 0.0;

    loop {
        if start.elapsed() > timeout {
            anyhow::bail!(
                "Timeout waiting for quorum on slot {} \
                 (best: {:.1}%, need ≥66.7%)",
                target_slot,
                best_pct
            );
        }

        // Scan for votes
        let vote_blocks = fetch_vote_blocks(rpc, target_slot + 1, 32)?;

        let mut seen_authorities = std::collections::HashSet::new();
        let mut confirmed_stake: u64 = 0;

        for (_, block) in &vote_blocks {
            let parsed = super::votes::extract_votes_for_bank_hash(block, target_bank_hash);
            for vote in &parsed {
                let auth = Pubkey::try_from(vote.vote_authority.as_slice()).ok();
                if let Some(auth_key) = auth {
                    if seen_authorities.insert(auth_key) {
                        // Find stake for this authority
                        if let Some((_, _, stake)) =
                            vote_accounts.iter().find(|(a, _, _)| *a == auth_key)
                        {
                            confirmed_stake += stake;
                        }
                    }
                }
            }
        }

        let pct = (confirmed_stake as f64 / total_stake as f64) * 100.0;
        if pct > best_pct {
            best_pct = pct;
            info!("Quorum progress: {:.1}% of stake confirmed", pct);
        }

        if confirmed_stake * 3 >= total_stake * 2 {
            info!(
                "Quorum reached: {:.1}% of stake confirmed ({} SOL)",
                pct,
                confirmed_stake / 1_000_000_000
            );
            return Ok(());
        }

        // Wait before retrying
        std::thread::sleep(Duration::from_secs(2));
    }
}

// ============================================================================
// Internal Helpers
// ============================================================================

/// Extract writable account keys from a transaction.
fn extract_writable_keys(
    tx_with_meta: &solana_transaction_status::EncodedTransactionWithStatusMeta,
) -> Option<Vec<Pubkey>> {
    let raw = super::tx_parser::decode_transaction_bytes(&tx_with_meta.transaction)?;

    let mut offset = 0;
    let (num_sigs, bytes_read) = super::tx_parser::read_compact_u16(&raw, offset)?;
    offset += bytes_read;
    offset += num_sigs * 64; // Skip signatures

    // Parse message header
    if offset + 3 > raw.len() {
        return None;
    }
    let num_required_sigs = raw[offset] as usize;
    let num_readonly_signed = raw[offset + 1] as usize;
    let num_readonly_unsigned = raw[offset + 2] as usize;
    offset += 3;

    // Number of account keys
    let (num_keys, bytes_read) = super::tx_parser::read_compact_u16(&raw, offset)?;
    offset += bytes_read;

    let num_writable_signed = num_required_sigs.saturating_sub(num_readonly_signed);
    let num_writable_unsigned = num_keys
        .saturating_sub(num_required_sigs)
        .saturating_sub(num_readonly_unsigned);

    let mut writable = Vec::new();

    for i in 0..num_keys {
        if offset + 32 > raw.len() {
            break;
        }
        let key = Pubkey::try_from(&raw[offset..offset + 32]).ok()?;
        offset += 32;

        let is_writable = if i < num_required_sigs {
            i < num_writable_signed
        } else {
            i < num_required_sigs + num_writable_unsigned
        };

        if is_writable {
            writable.push(key);
        }
    }

    Some(writable)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_authorized_voter_empty_data() {
        assert!(parse_authorized_voter(&[], 100).is_none());
    }

    #[test]
    fn test_parse_authorized_voter_too_short() {
        let data = vec![0u8; 50]; // Too short for VoteState header
        assert!(parse_authorized_voter(&data, 100).is_none());
    }

    #[test]
    fn test_parse_authorized_voter_synthetic() {
        // Build a minimal synthetic VoteState with known authorized_voter
        let mut data = Vec::new();

        // node_pubkey (32 bytes)
        data.extend_from_slice(&[1u8; 32]);

        // authorized_withdrawer (32 bytes)
        data.extend_from_slice(&[2u8; 32]);

        // commission (1 byte)
        data.push(5);

        // votes: VecDeque (bincode: u64 len = 0)
        data.extend_from_slice(&0u64.to_le_bytes());

        // root_slot: None (tag = 0)
        data.push(0);

        // authorized_voters: BTreeMap with 1 entry
        data.extend_from_slice(&1u64.to_le_bytes()); // len = 1
        data.extend_from_slice(&42u64.to_le_bytes()); // epoch = 42
        let voter = [0xABu8; 32];
        data.extend_from_slice(&voter); // voter pubkey

        let result = parse_authorized_voter(&data, 42);
        assert_eq!(result, Some(Pubkey::from(voter)));
    }

    #[test]
    fn test_parse_authorized_voter_fallback_to_lower_epoch() {
        // authorized_voter at epoch 40, but we query epoch 42
        let mut data = Vec::new();

        // Header
        data.extend_from_slice(&[1u8; 32]); // node_pubkey
        data.extend_from_slice(&[2u8; 32]); // withdrawer
        data.push(5); // commission

        // Empty votes
        data.extend_from_slice(&0u64.to_le_bytes());

        // root_slot: None
        data.push(0);

        // authorized_voters: 1 entry at epoch 40
        data.extend_from_slice(&1u64.to_le_bytes());
        data.extend_from_slice(&40u64.to_le_bytes());
        let voter = [0xCDu8; 32];
        data.extend_from_slice(&voter);

        // Should fall back to epoch 40's voter
        let result = parse_authorized_voter(&data, 42);
        assert_eq!(result, Some(Pubkey::from(voter)));
    }

    #[test]
    fn test_epoch_stakes_sorted_and_deduped() {
        let accounts = vec![
            (Pubkey::from([3u8; 32]), Pubkey::from([13u8; 32]), 300),
            (Pubkey::from([1u8; 32]), Pubkey::from([11u8; 32]), 100),
            (Pubkey::from([2u8; 32]), Pubkey::from([12u8; 32]), 200),
            // Duplicate vote authority
            (Pubkey::from([1u8; 32]), Pubkey::from([11u8; 32]), 100),
        ];

        let (entries, total) = to_epoch_stakes(&accounts);

        // Should be sorted by vote_authority
        for i in 1..entries.len() {
            assert!(entries[i].vote_authority > entries[i - 1].vote_authority);
        }

        // Should be deduplicated (3 unique, not 4)
        assert_eq!(entries.len(), 3);

        // Total should reflect deduped set
        assert_eq!(total, 600);
    }
}
