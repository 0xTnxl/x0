//! Shared types between SP1 guest (STARK circuit) and host (prover) for
//! Solana state proofs used in outbound bridging (Solana → Base).
//!
//! # Architecture
//!
//! The guest program proves:
//! 1. A BridgeOutMessage account exists in a specific slot's accounts delta
//! 2. The accounts_delta_hash is committed to the bank hash
//! 3. The bank hash is attested by ≥ 2/3 of epoch stake via validator votes
//!
//! # Solana State Model
//!
//! Solana's bank hash at slot S commits to state changes via:
//!
//! ```text
//! bank_hash(S) = SHA-256(
//!     parent_bank_hash(S-1)
//!     || accounts_delta_hash(S)     ← hash of all accounts modified in slot S
//!     || signature_count(S)
//!     || last_blockhash(S)
//! )
//! ```
//!
//! The `accounts_delta_hash` is computed using a fanout-16 recursive Merkle
//! tree over the account hashes of all accounts modified in slot S, matching
//! Solana's `MERKLE_FANOUT = 16` constant.
//!
//! Validators vote on slot hashes by signing vote transactions which contain
//! the bank hash. The Ed25519 signature covers the serialized transaction
//! message, and the bank hash appears at a deterministic offset within the
//! vote instruction data.
//!
//! # Public Inputs
//!
//! The public inputs are ABI-encoded for verification on Base EVM by
//! the X0UnlockContract via the SP1 on-chain verifier.

#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

/// Solana uses fanout-16 for its accounts Merkle tree computation.
///
/// See: `solana-accounts-db/src/accounts_hash.rs::MERKLE_FANOUT`
pub const MERKLE_FANOUT: usize = 16;

// ============================================================================
// Public Inputs (committed by guest, verified on Base EVM)
// ============================================================================

/// Public inputs committed by the SP1 Solana state proof
///
/// These values are ABI-encoded and verified on Base by X0UnlockContract
/// via the SP1Verifier contract.
///
/// ABI encoding matches:
///   abi.encode(bridgeProgramId, nonce, solanaSender, evmRecipient, amount,
///              burnTimestamp, accountHash)
#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct SolanaProofPublicInputs {
    /// x0-bridge program ID on Solana (32 bytes)
    pub bridge_program_id: [u8; 32],

    /// Outbound bridge nonce (from BridgeOutMessage.nonce)
    pub nonce: u64,

    /// Solana sender address that burned x0-USD (32 bytes)
    pub solana_sender: [u8; 32],

    /// EVM recipient address on Base (20 bytes)
    pub evm_recipient: [u8; 20],

    /// Amount of x0-USD burned / USDC to release (micro-units, 6 decimals)
    pub amount: u64,

    /// Unix timestamp when the burn occurred on Solana
    pub burn_timestamp: i64,

    /// SHA-256 hash of the BridgeOutMessage account data (integrity check)
    pub account_hash: [u8; 32],
}

impl SolanaProofPublicInputs {
    /// ABI-encode for EVM verification
    ///
    /// Matches: abi.encode(bytes32, uint64, bytes32, address, uint64, int64, bytes32)
    /// Each value occupies exactly one 32-byte ABI slot.
    pub fn abi_encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(7 * 32);

        // bytes32: bridge_program_id
        buf.extend_from_slice(&self.bridge_program_id);

        // uint64: nonce — ABI-encoded as uint256 (left-padded)
        let mut nonce_slot = [0u8; 32];
        nonce_slot[24..32].copy_from_slice(&self.nonce.to_be_bytes());
        buf.extend_from_slice(&nonce_slot);

        // bytes32: solana_sender
        buf.extend_from_slice(&self.solana_sender);

        // address: evm_recipient — left-padded (12 zero bytes + 20 addr bytes)
        let mut addr_slot = [0u8; 32];
        addr_slot[12..32].copy_from_slice(&self.evm_recipient);
        buf.extend_from_slice(&addr_slot);

        // uint64: amount — ABI-encoded as uint256
        let mut amount_slot = [0u8; 32];
        amount_slot[24..32].copy_from_slice(&self.amount.to_be_bytes());
        buf.extend_from_slice(&amount_slot);

        // int64: burn_timestamp — ABI-encoded as int256 (sign-extended)
        let mut ts_slot = if self.burn_timestamp < 0 {
            [0xFFu8; 32]
        } else {
            [0u8; 32]
        };
        ts_slot[24..32].copy_from_slice(&self.burn_timestamp.to_be_bytes());
        buf.extend_from_slice(&ts_slot);

        // bytes32: account_hash
        buf.extend_from_slice(&self.account_hash);

        buf
    }
}

// ============================================================================
// Private Inputs (witness)
// ============================================================================

/// Private witness data for the SP1 Solana state proof
///
/// # Verification Chain
///
/// ```text
/// account_hash ──► accounts_delta_hash ──► bank_hash ──► validator votes
///   (computed)   (fanout-16 Merkle proof)  (SHA-256)       (Ed25519 quorum)
/// ```
#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct SolanaProofWitness {
    // -- Account data --
    pub account_data: Vec<u8>,
    pub account_address: [u8; 32],
    pub account_owner: [u8; 32],
    pub account_lamports: u64,
    pub account_executable: bool,
    pub account_rent_epoch: u64,

    // -- Account inclusion proof (account → accounts_delta_hash) --
    pub inclusion_proof: AccountInclusionProof,
    pub accounts_delta_hash: [u8; 32],

    // -- Bank hash --
    pub bank_hash: [u8; 32],
    pub bank_hash_components: BankHashComponents,

    // -- Validator vote attestations --
    pub validator_votes: Vec<ValidatorVote>,
    pub epoch_stakes: Vec<ValidatorStake>,
    pub total_epoch_stake: u64,

    // -- Slot info --
    pub slot: u64,
}

// ============================================================================
// Account Inclusion Proof (fanout-16 Merkle)
// ============================================================================

/// Proof of account inclusion in Solana's accounts_delta_hash
///
/// The accounts_delta_hash is a fanout-16 recursive Merkle tree over all
/// account hashes modified in a slot. This proof provides sibling hashes
/// at each tree level.
///
/// # Tree Structure (`MERKLE_FANOUT = 16`)
///
/// At each level, up to 16 children are concatenated and SHA-256 hashed
/// to produce their parent:
///
/// ```text
/// parent = SHA-256(child_0 || child_1 || ... || child_{n-1})
/// ```
///
/// The last group at each level may have fewer than 16 children.
///
/// For a slot with ~3000 modified accounts: ceil(log_16(3000)) = 3 levels,
/// proof size ≈ 3 × 15 × 32 = 1,440 bytes.
#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct AccountInclusionProof {
    /// Merkle proof levels from leaf to root
    pub levels: Vec<FanoutProofLevel>,

    /// Total accounts in the delta tree
    pub total_delta_accounts: u32,
}

/// One level in a fanout-16 Merkle proof
#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct FanoutProofLevel {
    /// Sibling hashes (up to 15 for full groups, fewer for partial)
    pub siblings: Vec<[u8; 32]>,

    /// Position of the target within its group (0..15)
    pub position: u8,
}

// ============================================================================
// Bank Hash Components
// ============================================================================

/// Components of the bank hash derivation
///
/// ```text
/// bank_hash = SHA-256(
///     parent_bank_hash || accounts_delta_hash || sig_count_le || last_blockhash
/// )
/// ```
///
/// Matches `Bank::hash_internal_state()` in `solana-runtime/src/bank.rs`.
///
/// **Note**: On epoch boundaries, Solana mixes in an additional
/// `epoch_accounts_hash`. The fetcher avoids epoch-boundary slots.
#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct BankHashComponents {
    /// Bank hash of the parent slot
    pub parent_bank_hash: [u8; 32],

    /// Number of transaction signatures in the block
    pub signature_count: u64,

    /// Last PoH blockhash of the block
    pub last_blockhash: [u8; 32],
}

// ============================================================================
// Validator Vote Attestation
// ============================================================================

/// A validator's vote attesting to a bank hash
///
/// # Circuit Verification
///
/// 1. `Ed25519(vote_authority, message_bytes, signature)` — authenticity
/// 2. `message_bytes[bank_hash_offset..+32] == target_bank_hash` — content
/// 3. `validator_identity` has `stake` in `epoch_stakes` — weight
///
/// The bank hash appears at a deterministic offset within the vote instruction
/// data in the serialized transaction message. The host parses the tx to find
/// this offset; the circuit verifies it.
#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct ValidatorVote {
    /// Authorized voter pubkey that signed the vote transaction
    pub vote_authority: [u8; 32],

    /// Full serialized transaction message (signed by vote_authority)
    pub message_bytes: Vec<u8>,

    /// Ed25519 signature over `message_bytes`
    #[serde(with = "serde_big_array::BigArray")]
    pub signature: [u8; 64],

    /// Byte offset where the target bank hash appears in `message_bytes`
    pub bank_hash_offset: u32,

    /// Validator identity (node pubkey) — for stake lookup
    pub validator_identity: [u8; 32],

    /// Activated stake (lamports)
    pub stake: u64,
}

/// Stake information for a validator in the current epoch
#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct ValidatorStake {
    /// Validator identity (node) pubkey
    pub pubkey: [u8; 32],

    /// Activated stake in lamports
    pub stake: u64,
}

// ============================================================================
// BridgeOutMessage Account Layout
// ============================================================================

/// Parsed BridgeOutMessage account data
///
/// Matches the Anchor account layout from x0-bridge/src/state.rs.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ParsedBridgeOutMessage {
    pub discriminator: [u8; 8],
    pub version: u8,
    pub nonce: u64,
    pub solana_sender: [u8; 32],
    pub evm_recipient: [u8; 20],
    pub amount: u64,
    pub burn_tx_signature: [u8; 32],
    pub burned_at: i64,
    pub status: u8,
    pub bump: u8,
}

impl ParsedBridgeOutMessage {
    /// Minimum account data size
    pub const DATA_SIZE: usize = 8 + 1 + 8 + 32 + 20 + 8 + 32 + 8 + 1 + 1 + 32;

    /// Parse from raw Anchor account data
    pub fn try_from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < Self::DATA_SIZE {
            return None;
        }

        let mut offset = 0;

        let mut discriminator = [0u8; 8];
        discriminator.copy_from_slice(&data[offset..offset + 8]);
        offset += 8;

        let version = data[offset];
        offset += 1;

        let nonce = u64::from_le_bytes(data[offset..offset + 8].try_into().ok()?);
        offset += 8;

        let mut solana_sender = [0u8; 32];
        solana_sender.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        let mut evm_recipient = [0u8; 20];
        evm_recipient.copy_from_slice(&data[offset..offset + 20]);
        offset += 20;

        let amount = u64::from_le_bytes(data[offset..offset + 8].try_into().ok()?);
        offset += 8;

        let mut burn_tx_signature = [0u8; 32];
        burn_tx_signature.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        let burned_at = i64::from_le_bytes(data[offset..offset + 8].try_into().ok()?);
        offset += 8;

        let status = data[offset];
        offset += 1;

        let bump = data[offset];

        Some(Self {
            discriminator,
            version,
            nonce,
            solana_sender,
            evm_recipient,
            amount,
            burn_tx_signature,
            burned_at,
            status,
            bump,
        })
    }
}
