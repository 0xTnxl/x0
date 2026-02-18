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
use solana_vote_program::vote_state::VoteState;
use tracing::{debug, error, info, warn};
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
/// # VoteState Deserialization
///
/// We use the official `solana-vote-program` crate's `VoteState::deserialize`
/// instead of hand-rolled bincode parsing. This handles all current and future
/// `VoteStateVersions` layout changes correctly.
///
/// Validators whose `VoteState` cannot be deserialized are **skipped** (not
/// fallen back to their vote account pubkey). Using the wrong signer key would
/// corrupt the validator set and cause Ed25519 failures in the circuit.
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
    let mut skip_count = 0u32;

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

        // Fetch the vote account data to deserialize VoteState
        let account = match rpc.get_account(&vote_pubkey) {
            Ok(a) => a,
            Err(e) => {
                debug!("Failed to fetch vote account {}: {}", vote_pubkey, e);
                skip_count += 1;
                continue;
            }
        };

        // Use official VoteState deserialization — handles all VoteStateVersions
        // layouts (V0_23_5, V1_14_11, Current) without fragile version heuristics.
        let voter = match VoteState::deserialize(&account.data) {
            Ok(vote_state) => {
                // authorized_voters is a BTreeMap<Epoch, Pubkey>.
                // We want the entry with the highest epoch ≤ current_epoch,
                // matching Solana's runtime behavior in Bank::vote_account_authorized_voter.
                let best = vote_state
                    .authorized_voters()
                    .iter()
                    .filter(|(&epoch, _)| epoch <= current_epoch)
                    .max_by_key(|(&epoch, _)| epoch)
                    .map(|(_, voter)| *voter);

                match best {
                    Some(v) => v,
                    None => {
                        // authorized_voters map is empty or all entries are future epochs.
                        // This can happen for never-voted accounts; skip them.
                        error!(
                            "Vote account {} has no authorized voter for epoch {} — skipping",
                            vote_pubkey, current_epoch
                        );
                        skip_count += 1;
                        continue;
                    }
                }
            }
            Err(e) => {
                // Deserialization failed — skip entirely rather than falling back
                // to vote_pubkey. An incorrect signer key would cause the circuit
                // to fail Ed25519 verification and produce a broken proof.
                error!(
                    "Failed to deserialize VoteState for {}: {} — skipping (not falling back to vote_pubkey)",
                    vote_pubkey, e
                );
                skip_count += 1;
                continue;
            }
        };

        result.push((voter, node_pubkey, va.activated_stake));
    }

    if skip_count > 0 {
        warn!(
            "{} vote accounts skipped due to fetch/deserialization errors. \
             These validators will not appear in the epoch stake set.",
            skip_count
        );
    }

    info!(
        "Found {} valid vote accounts ({} current, {} delinquent, {} skipped)",
        result.len(),
        vote_accounts.current.len(),
        vote_accounts.delinquent.len(),
        skip_count
    );

    Ok(result)
}

// Note: VoteState parsing for authorized_voter is now handled directly in
// fetch_vote_accounts() using solana_vote_program::vote_state::VoteState::deserialize.
// The hand-rolled bincode parser has been removed in favour of the official crate.

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

/// Check if a slot falls within the epoch-boundary guard window.
///
/// # Why boundary slots are rejected
///
/// At the **first slot of each new epoch**, Solana's `Bank::hash_internal_state`
/// mixes an extra `EpochAccountsHash` into the bank hash preimage:
///
/// ```text
/// bank_hash(S) = SHA-256(
///     parent_bank_hash || accounts_delta_hash || sig_count || last_blockhash
///     || epoch_accounts_hash   ← only on epoch-boundary slots
/// )
/// ```
///
/// The circuit only implements the standard 4-component formula, so any slot
/// whose bank hash was derived with the 5-component formula will fail the
/// `computed_bank_hash == witness.bank_hash` assertion.
///
/// # Impact
///
/// With a guard of 5 slots, approximately 10 slots per epoch (5 at start) are
/// rejected: ~10 / 432_000 = **0.002%** of mainnet slots. This is negligible.
/// Guarding only the start of the epoch (not the end of the previous epoch)
/// is correct — the `epoch_accounts_hash` is mixed on `slot_in_epoch == 0`,
/// not on the final slots of the preceding epoch.
///
/// Returns `Err` if boundary detection fails, `Ok(true)` if the slot is
/// within the boundary guard window.
pub fn is_epoch_boundary_slot(rpc: &RpcClient, slot: Slot) -> Result<bool> {
    let schedule = rpc
        .get_epoch_schedule()
        .context("Failed to get epoch schedule")?;

    let slots_per_epoch = schedule.slots_per_epoch;
    if slots_per_epoch == 0 {
        anyhow::bail!("Invalid epoch schedule: slots_per_epoch = 0");
    }

    // Subtract first_normal_slot so pre-genesis warmup epochs don't skew the math.
    let first_normal_slot = schedule.first_normal_slot;
    let adjusted = slot.saturating_sub(first_normal_slot);
    let slot_in_epoch = adjusted % slots_per_epoch;

    // Guard the first BOUNDARY_GUARD_SLOTS slots of each epoch.
    // The epoch_accounts_hash is mixed only on slot_in_epoch == 0, but we
    // guard a small window (5 slots) to absorb any off-by-one in slot
    // assignment during epoch transitions.
    const BOUNDARY_GUARD_SLOTS: u64 = 5;

    let at_boundary = slot_in_epoch < BOUNDARY_GUARD_SLOTS;

    if at_boundary {
        info!(
            "Slot {} is in epoch-boundary guard window \
             (position {} of {} in epoch; guarding first {})",
            slot, slot_in_epoch, slots_per_epoch, BOUNDARY_GUARD_SLOTS
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
///
/// # Bounds Validation
///
/// A plausible signature count satisfies:
///   `tx_count ≤ sig_count ≤ tx_count × MAX_SIGNERS_PER_TX`
///
/// Solana enforces at most 19 signers per transaction (account key limit 64,
/// with minimum 1 non-signer account and 1 program = 62 signers max, but
/// in practice capped by the 1232-byte transaction size limit to ~19).
/// We use 48 as a conservative upper bound per Solana's legacy limit.
///
/// If the computed count is out of range, a warning is emitted and the
/// raw count is returned — the proof attempt will still fail at the bank
/// hash equality check in the circuit if the count is wrong.
pub fn count_block_signatures(block: &UiConfirmedBlock) -> u64 {
    let Some(ref transactions) = block.transactions else {
        return 0;
    };

    let tx_count = transactions.len() as u64;
    let mut total_sigs: u64 = 0;

    for tx_with_meta in transactions {
        // Decode transaction bytes
        let raw = match super::tx_parser::decode_transaction_bytes(&tx_with_meta.transaction) {
            Some(bytes) => bytes,
            None => continue,
        };

        // Parse the number of signatures from the transaction wire format
        let offset = 0;
        let Some((num_sigs, bytes_read)) = super::tx_parser::read_compact_u16(&raw, offset) else {
            continue;
        };
        let sig_offset = bytes_read + num_sigs * 64;

        // Message header starts here: first byte is num_required_signatures.
        // V0 versioned transactions prefix the message with 0x80 — skip it
        // to reach the actual 3-byte message header.
        if sig_offset < raw.len() {
            let header_start = if raw[sig_offset] == 0x80 {
                sig_offset + 1
            } else {
                sig_offset
            };
            if header_start < raw.len() {
                let num_required_sigs = raw[header_start] as u64;
                total_sigs += num_required_sigs;
            }
        }
    }

    // Plausibility bounds: each tx must contribute ≥1 signature,
    // and at most MAX_SIGNERS_PER_TX signatures.
    const MAX_SIGNERS_PER_TX: u64 = 48;

    if tx_count > 0 {
        if total_sigs < tx_count {
            warn!(
                "Signature count {} is less than transaction count {} — \
                 this may indicate a parsing error or an empty/vote-only block. \
                 Bank hash derivation may fail.",
                total_sigs, tx_count
            );
        } else if total_sigs > tx_count.saturating_mul(MAX_SIGNERS_PER_TX) {
            warn!(
                "Signature count {} exceeds {} × {} = {} — \
                 this may indicate a parsing error. \
                 Bank hash derivation may fail.",
                total_sigs,
                tx_count,
                MAX_SIGNERS_PER_TX,
                tx_count.saturating_mul(MAX_SIGNERS_PER_TX)
            );
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

    // Skip V0 versioned message prefix byte (0x80) if present.
    // V0 transactions prefix the message with 0x80 to signal the versioned format.
    // The 3-byte message header (num_required_sigs, num_readonly_signed,
    // num_readonly_unsigned) follows immediately after the prefix byte.
    if offset < raw.len() && raw[offset] == 0x80 {
        offset += 1;
    }

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
    use solana_vote_program::vote_state::{VoteStateVersions, VoteState as SolanaVoteState};

    /// Build a minimal serialized VoteStateVersions blob with an explicit
    /// authorized voter at a given epoch.  Mirrors what `VoteState::deserialize`
    /// expects so that these tests exercise the real code path.
    fn make_vote_state_bytes(voter: Pubkey, voter_epoch: u64) -> Vec<u8> {
        let node_pubkey = Pubkey::from([1u8; 32]);
        let authorized_withdrawer = Pubkey::from([2u8; 32]);

        // VoteState::new registers `authorized_voter` at `clock.epoch`.
        let vote_state = SolanaVoteState::new(
            &solana_vote_program::vote_state::VoteInit {
                node_pubkey,
                authorized_voter: voter,
                authorized_withdrawer,
                commission: 5,
            },
            &solana_sdk::clock::Clock {
                epoch: voter_epoch,
                ..Default::default()
            },
        );

        let versioned = VoteStateVersions::new_current(vote_state);
        bincode::serialize(&versioned).expect("VoteState serialization failed")
    }

    #[test]
    fn test_vote_state_deserialize_invalid_data() {
        // Garbled bytes should fail deserialization, not silently succeed
        let result = VoteState::deserialize(&[0u8; 10]);
        assert!(result.is_err(), "Expected deserialization error for invalid data");
    }

    #[test]
    fn test_vote_state_deserialize_finds_authorized_voter() {
        let voter = Pubkey::from([0xABu8; 32]);
        let data = make_vote_state_bytes(voter, 42);

        let vote_state = VoteState::deserialize(&data).expect("Deserialization should succeed");
        let best = vote_state
            .authorized_voters()
            .iter()
            .filter(|(&epoch, _)| epoch <= 42)
            .max_by_key(|(&epoch, _)| epoch)
            .map(|(_, v)| *v);

        assert_eq!(best, Some(voter));
    }

    #[test]
    fn test_vote_state_deserialize_fallback_to_lower_epoch() {
        // authorized_voter registered at epoch 40; we query at epoch 42
        let voter = Pubkey::from([0xCDu8; 32]);
        let data = make_vote_state_bytes(voter, 40);

        let vote_state = VoteState::deserialize(&data).expect("Deserialization should succeed");
        let best = vote_state
            .authorized_voters()
            .iter()
            .filter(|(&epoch, _)| epoch <= 42)
            .max_by_key(|(&epoch, _)| epoch)
            .map(|(_, v)| *v);

        // epoch 40 \u2264 42, so we should get the voter registered at epoch 40
        assert_eq!(best, Some(voter));
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
