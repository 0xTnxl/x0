//! Vote transaction parsing from Solana blocks
//!
//! Parses vote transactions to extract:
//! 1. The bank hash being voted on
//! 2. The validator's vote authority (signer)
//! 3. The Ed25519 signature over the serialized message
//! 4. The byte offset of the bank hash within the message
//!
//! # Solana Vote Transaction Structure
//!
//! Vote transactions use the Vote program (`Vote111...111`).
//! The instruction data contains a VoteStateUpdate or CompactUpdateVoteState
//! which includes the bank hash of the slot being voted on.
//!
//! # Supported Instruction Variants
//!
//! - `UpdateVoteState` (legacy, tag varies)
//! - `CompactUpdateVoteState` (current, tag = 12)
//! - `TowerSync` (v1.18+, tag = 14)
//!
//! The bank hash is always a 32-byte field within the vote instruction data.

use solana_sdk::pubkey::Pubkey;
use solana_transaction_status::{
    EncodedTransactionWithStatusMeta, UiConfirmedBlock,
};
use tracing::{info, trace, warn};
use x0_sp1_solana_common::ValidatorVote;

use super::tx_parser;



/// Parsed vote from a single transaction
#[derive(Debug, Clone)]
pub struct ParsedVoteTransaction {
    /// Validator authorized voter (signer of the transaction)
    pub vote_authority: [u8; 32],

    /// Ed25519 signature over the serialized transaction message
    pub signature: [u8; 64],

    /// The full serialized transaction message
    pub message_bytes: Vec<u8>,

    /// Byte offset of the bank hash within message_bytes
    pub bank_hash_offset: u32,
}

/// Extract all vote transactions from a block that vote on a specific bank hash
///
/// # Arguments
/// * `block` - Encoded block data from `getBlock` RPC
/// * `target_bank_hash` - The bank hash we're looking for
///
/// # Returns
/// Parsed vote transactions that reference the target bank hash
pub fn extract_votes_for_bank_hash(
    block: &UiConfirmedBlock,
    target_bank_hash: &[u8; 32],
) -> Vec<ParsedVoteTransaction> {
    let mut votes = Vec::new();

    let Some(ref transactions) = block.transactions else {
        warn!("Block has no transactions");
        return votes;
    };

    for tx_with_meta in transactions {
        if let Some(parsed) = try_parse_vote_transaction(tx_with_meta, target_bank_hash) {
            votes.push(parsed);
        }
    }

    info!(
        "Found {} vote(s) for bank hash 0x{}",
        votes.len(),
        hex::encode(&target_bank_hash[..8])
    );

    votes
}

/// Attempt to parse a single transaction as a vote for the target bank hash
fn try_parse_vote_transaction(
    tx_with_meta: &EncodedTransactionWithStatusMeta,
    target_bank_hash: &[u8; 32],
) -> Option<ParsedVoteTransaction> {
    // Skip failed transactions
    if let Some(ref meta) = tx_with_meta.meta {
        if meta.err.is_some() {
            return None;
        }
    }

    // Decode and parse the raw transaction
    let raw = tx_parser::decode_transaction_bytes(&tx_with_meta.transaction)?;
    let (message_bytes, signatures, account_keys) = tx_parser::parse_raw_transaction(&raw)?;

    // Find the vote instruction: look for the Vote program in account keys
    let vote_program_pubkey = tx_parser::VOTE_PROGRAM_ID_STR.parse::<Pubkey>().ok()?;
    let vote_program_index = account_keys.iter().position(|k| *k == vote_program_pubkey)?;

    // Parse the message to find instructions
    let instructions = tx_parser::parse_instructions_from_message(&message_bytes)?;

    for (ix_program_index, ix_data, ix_data_offset) in &instructions {
        if *ix_program_index as usize != vote_program_index {
            continue;
        }

        // This is a vote instruction — search for the bank hash within ix_data
        if let Some(hash_offset_in_data) = find_bank_hash_in_vote_data(ix_data, target_bank_hash) {
            // The offset within message_bytes = instruction data offset + offset within data
            let absolute_offset = *ix_data_offset + hash_offset_in_data;

            // Extract the first signature (vote authority signature)
            let mut sig = [0u8; 64];
            sig.copy_from_slice(&signatures[0]);

            // The vote authority is the first signer
            let mut vote_authority = [0u8; 32];
            vote_authority.copy_from_slice(&account_keys[0].to_bytes());

            return Some(ParsedVoteTransaction {
                vote_authority,
                signature: sig,
                message_bytes: message_bytes.clone(),
                bank_hash_offset: absolute_offset as u32,
            });
        }
    }

    None
}

/// Search vote instruction data for the target bank hash
///
/// The bank hash appears as a 32-byte field within the vote instruction data.
/// Different vote instruction variants place it at different offsets, but it's
/// always preceded by the lockouts/root data and followed by an optional timestamp.
///
/// Rather than parsing the exact variant, we scan for the 32-byte hash within
/// the instruction data. Given SHA-256 collision resistance, a false positive
/// (finding the hash at a wrong offset) has probability 2^{-256}.
fn find_bank_hash_in_vote_data(data: &[u8], target: &[u8; 32]) -> Option<usize> {
    if data.len() < 36 {
        // Minimum: 4-byte variant tag + 32-byte hash
        return None;
    }

    // Scan through the instruction data looking for the 32-byte hash
    // Start after the 4-byte variant discriminator
    for offset in 4..=(data.len().saturating_sub(32)) {
        if &data[offset..offset + 32] == target {
            trace!("Found bank hash at offset {} in vote instruction data", offset);
            return Some(offset);
        }
    }

    None
}

/// Convert parsed votes to ValidatorVote structs for the witness
///
/// Cross-references with vote account data to get validator identity and stake.
///
/// # Arguments
/// * `parsed_votes` - Votes parsed from block transactions
/// * `vote_accounts` - Map of vote authority → (validator_identity, stake)
pub fn to_validator_votes(
    parsed_votes: &[ParsedVoteTransaction],
    vote_accounts: &[(Pubkey, Pubkey, u64)], // (vote_authority, node_identity, stake)
) -> Vec<ValidatorVote> {
    parsed_votes
        .iter()
        .filter_map(|vote| {
            let authority_pubkey = Pubkey::try_from(vote.vote_authority.as_slice()).ok()?;

            // Find this vote authority in the vote accounts
            let (_, node_identity, stake) = vote_accounts
                .iter()
                .find(|(auth, _, _)| *auth == authority_pubkey)?;

            Some(ValidatorVote {
                vote_authority: vote.vote_authority,
                message_bytes: vote.message_bytes.clone(),
                signature: vote.signature,
                bank_hash_offset: vote.bank_hash_offset,
                validator_identity: node_identity.to_bytes(),
                stake: *stake,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_bank_hash_in_vote_data_found() {
        let target = [0xABu8; 32];

        // Synthesize data: 4-byte tag + some bytes + the target hash
        let mut data = vec![0u8; 4]; // tag
        data.extend_from_slice(&[0x01, 0x02, 0x03]); // padding
        data.extend_from_slice(&target); // the hash at offset 7
        data.extend_from_slice(&[0x00]); // trailing

        let result = find_bank_hash_in_vote_data(&data, &target);
        assert_eq!(result, Some(7));
    }

    #[test]
    fn test_find_bank_hash_in_vote_data_not_found() {
        let target = [0xABu8; 32];
        let data = vec![0u8; 100]; // All zeros — won't match

        let result = find_bank_hash_in_vote_data(&data, &target);
        assert_eq!(result, None);
    }

    #[test]
    fn test_find_bank_hash_in_vote_data_too_short() {
        let target = [0xABu8; 32];
        let data = vec![0u8; 35]; // Less than 36 bytes minimum

        let result = find_bank_hash_in_vote_data(&data, &target);
        assert_eq!(result, None);
    }

    #[test]
    fn test_find_bank_hash_at_end_of_data() {
        let target = [0xCDu8; 32];

        // Hash at the very end of the data
        let mut data = vec![0u8; 4]; // tag
        data.extend_from_slice(&target);

        let result = find_bank_hash_in_vote_data(&data, &target);
        assert_eq!(result, Some(4));
    }

    #[test]
    fn test_to_validator_votes_maps_correctly() {
        let authority = [1u8; 32];
        let node_id = [2u8; 32];

        let parsed = vec![ParsedVoteTransaction {
            vote_authority: authority,
            signature: [0u8; 64],
            message_bytes: vec![0x01, 0x02, 0x03],
            bank_hash_offset: 42,
        }];

        let vote_accounts = vec![(
            Pubkey::from(authority),
            Pubkey::from(node_id),
            1_000_000_000u64,
        )];

        let result = to_validator_votes(&parsed, &vote_accounts);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].vote_authority, authority);
        assert_eq!(result[0].validator_identity, node_id);
        assert_eq!(result[0].stake, 1_000_000_000);
        assert_eq!(result[0].bank_hash_offset, 42);
    }

    #[test]
    fn test_to_validator_votes_filters_unknown() {
        let authority = [1u8; 32];
        let unknown_authority = [99u8; 32];

        let parsed = vec![ParsedVoteTransaction {
            vote_authority: unknown_authority,
            signature: [0u8; 64],
            message_bytes: vec![],
            bank_hash_offset: 0,
        }];

        let vote_accounts = vec![(
            Pubkey::from(authority),
            Pubkey::from([2u8; 32]),
            1_000_000_000u64,
        )];

        let result = to_validator_votes(&parsed, &vote_accounts);
        assert_eq!(result.len(), 0, "Unknown authority should be filtered out");
    }
}
