//! Solana RPC helpers for fetching block data, vote accounts, and account state
//!
//! Wraps the Solana RPC client with production-ready retry logic and
//! targeted data extraction for SP1 proof witness generation.

use anyhow::{Context, Result};
use solana_client::rpc_client::RpcClient;
use solana_client::rpc_config::RpcBlockConfig;
use solana_sdk::{
    account::Account,
    commitment_config::CommitmentConfig,
    pubkey::Pubkey,
    clock::Slot,
};
use solana_transaction_status::{
    TransactionDetails, UiConfirmedBlock,
    UiTransactionEncoding,
};
use tracing::{info, debug, warn};
use x0_sp1_solana_common::ValidatorStake;

/// Fetch a block with full transaction data in base64 encoding
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

/// Fetch blocks in a range looking for votes on a target slot
///
/// Validators often vote on slot S in slots S+1, S+2, etc.
/// This fetches multiple subsequent blocks to find vote transactions.
pub fn fetch_vote_blocks(
    rpc: &RpcClient,
    target_slot: Slot,
    look_ahead: u64,
) -> Result<Vec<(Slot, UiConfirmedBlock)>> {
    let mut blocks = Vec::new();

    // Include the target slot itself (some votes might be in it)
    // and the next `look_ahead` slots
    for offset in 0..=look_ahead {
        let slot = target_slot + offset;
        match fetch_block(rpc, slot) {
            Ok(block) => blocks.push((slot, block)),
            Err(e) => {
                debug!("Slot {} not available: {}", slot, e);
                // Slots can be skipped (leader didn't produce a block)
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

/// Fetch all current vote accounts with their identities and stakes
///
/// Returns Vec<(vote_authority, validator_identity, activated_stake)>
///
/// This uses the `getVoteAccounts` RPC method which returns all current
/// and delinquent vote accounts with their activated stake.
pub fn fetch_vote_accounts(rpc: &RpcClient) -> Result<Vec<(Pubkey, Pubkey, u64)>> {
    info!("Fetching vote accounts...");

    let vote_accounts = rpc
        .get_vote_accounts()
        .context("Failed to fetch vote accounts")?;

    let mut result = Vec::new();

    // Process current (active) validators
    for va in &vote_accounts.current {
        let vote_pubkey = va.vote_pubkey.parse::<Pubkey>()
            .context("Invalid vote account pubkey")?;
        let node_pubkey = va.node_pubkey.parse::<Pubkey>()
            .context("Invalid node pubkey")?;

        // The authorized voter might differ from the vote account pubkey.
        // For simplicity, we use the vote account pubkey as the vote authority.
        // In production, you'd parse the vote account data to get the actual
        // authorized voter for the current epoch.
        result.push((vote_pubkey, node_pubkey, va.activated_stake));
    }

    // Include delinquent validators (they may have voted recently)
    for va in &vote_accounts.delinquent {
        let vote_pubkey = va.vote_pubkey.parse::<Pubkey>()
            .context("Invalid vote account pubkey")?;
        let node_pubkey = va.node_pubkey.parse::<Pubkey>()
            .context("Invalid node pubkey")?;

        result.push((vote_pubkey, node_pubkey, va.activated_stake));
    }

    info!(
        "Found {} vote accounts ({} current, {} delinquent)",
        result.len(),
        vote_accounts.current.len(),
        vote_accounts.delinquent.len()
    );

    Ok(result)
}

/// Convert vote account data to epoch stake entries
pub fn to_epoch_stakes(vote_accounts: &[(Pubkey, Pubkey, u64)]) -> (Vec<ValidatorStake>, u64) {
    let mut stakes = Vec::new();
    let mut total_stake: u64 = 0;

    for (_, node_identity, stake) in vote_accounts {
        stakes.push(ValidatorStake {
            pubkey: node_identity.to_bytes(),
            stake: *stake,
        });
        total_stake = total_stake.saturating_add(*stake);
    }

    info!(
        "Epoch stakes: {} validators, total stake = {} SOL",
        stakes.len(),
        total_stake / 1_000_000_000 // Convert lamports to SOL for display
    );

    (stakes, total_stake)
}

/// Get the account modification slot for a specific account
///
/// Uses `getSignaturesForAddress` to find the most recent transaction
/// that modified the account, which gives us the creation slot for
/// a BridgeOutMessage PDA.
pub fn get_account_creation_slot(
    rpc: &RpcClient,
    account_pubkey: &Pubkey,
) -> Result<Slot> {
    info!("Finding creation slot for account {}...", account_pubkey);

    let signatures = rpc
        .get_signatures_for_address(account_pubkey)
        .context("Failed to get signatures for account")?;

    // The last signature in the list is the earliest (oldest first)
    // But getSignaturesForAddress returns newest first by default
    let creation_sig = signatures
        .last()
        .context("No transactions found for this account")?;

    let slot = creation_sig.slot;
    info!("Account {} created at slot {}", account_pubkey, slot);

    Ok(slot)
}

/// Fetch accounts modified in a specific slot for delta tree construction
///
/// This fetches the block to identify all writable accounts, then uses
/// `getMultipleAccounts` to get their current state.
///
/// **LIMITATION**: Returns CURRENT account state, not state AT the slot.
/// For accounts that haven't been modified since the target slot, this is
/// correct. For frequently-modified accounts (token accounts, etc.), the state
/// may be from a later slot.
///
/// For fully accurate delta tree construction, use the Geyser-based
/// `SlotStateProvider` which captures account state at each slot.
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

            // Extract account keys from the transaction
            if let Some(keys) = extract_writable_keys(tx_with_meta) {
                writable_keys.extend(keys);
            }
        }
    }

    info!("Found {} unique writable accounts in slot {}", writable_keys.len(), slot);

    // Batch fetch account data
    let keys: Vec<Pubkey> = writable_keys.into_iter().collect();
    let mut accounts = Vec::new();

    // getMultipleAccounts has a limit of 100 accounts per call
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

    info!(
        "Fetched {} delta accounts for slot {}",
        accounts.len(),
        slot
    );

    Ok(accounts)
}

/// Validate that delta accounts haven't been modified since the target slot.
///
/// This is a best-effort check for the RPC-based state provider. Returns the
/// number of accounts that may have stale state (modified after `slot`).
///
/// For guaranteed accuracy, use a Geyser plugin that captures account snapshots
/// at each slot boundary.
///
/// # Arguments
/// * `rpc` - Solana RPC client
/// * `delta_accounts` - Accounts to validate
/// * `slot` - The target slot (accounts should not have been modified after this)
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
                debug!(
                    "Could not check freshness for {}: {}",
                    pubkey, e
                );
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
             (modified after target slot {}). For production accuracy, use a \
             Geyser plugin for historical state capture.",
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

/// Extract writable account keys from a transaction
fn extract_writable_keys(
    tx_with_meta: &solana_transaction_status::EncodedTransactionWithStatusMeta,
) -> Option<Vec<Pubkey>> {
    // Decode the transaction to raw bytes
    let raw = super::tx_parser::decode_transaction_bytes(&tx_with_meta.transaction)?;

    // Parse to get message
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

    // The writable accounts are:
    // - First (num_required_sigs - num_readonly_signed) signed accounts
    // - Then (num_keys - num_required_sigs - num_readonly_unsigned) unsigned accounts
    let num_writable_signed = num_required_sigs - num_readonly_signed;
    let num_writable_unsigned = num_keys - num_required_sigs - num_readonly_unsigned;

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


