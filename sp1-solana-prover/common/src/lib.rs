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
//!     bank_hash(S-1)
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
//!
//! # Security Model
//!
//! The circuit commits a `validator_set_hash` as a public output. The EVM
//! contract maintains a governance-updated `validatorSetHash` per Solana
//! epoch and rejects proofs with unknown hashes. This prevents a malicious
//! prover from fabricating epoch stakes to forge a quorum.

#![no_std]

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

/// Solana uses fanout-16 for its accounts Merkle tree computation.
///
/// See: `solana-accounts-db/src/accounts_hash.rs::MERKLE_FANOUT`
pub const MERKLE_FANOUT: usize = 16;

/// Anchor account name for BridgeOutMessage — used to compute discriminator.
///
/// The Anchor discriminator is `SHA-256("account:BridgeOutMessage")[..8]`.
/// The circuit computes this at runtime and validates the account data,
/// preventing a malicious host from supplying arbitrary account data that
/// happens to parse into the expected structure.
pub const BRIDGE_OUT_MESSAGE_ACCOUNT_NAME: &str = "BridgeOutMessage";

// ============================================================================
// Public Inputs (committed by guest, verified on Base EVM)
// ============================================================================

/// Public inputs committed by the SP1 Solana state proof.
///
/// These values are ABI-encoded and verified on Base by X0UnlockContract
/// via the SP1Verifier contract.
///
/// ABI encoding (10 × 32-byte slots):
/// ```text
/// abi.encode(
///     bytes32 bridgeProgramId,
///     uint64  nonce,
///     bytes32 solanaSender,
///     address evmRecipient,
///     uint64  amount,
///     int64   burnTimestamp,
///     bytes32 accountHash,
///     bytes32 validatorSetHash,
///     uint64  slot,
///     uint64  totalEpochStake
/// )
/// ```
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

    /// Commitment to the validator set used for quorum verification.
    ///
    /// Computed inside the circuit as:
    /// ```text
    /// SHA-256(
    ///   for each entry sorted by vote_authority ascending:
    ///     vote_authority(32) || validator_identity(32) || stake(8 BE)
    /// )
    /// ```
    ///
    /// The EVM contract maintains a governance-updated `validatorSetHash`
    /// per Solana epoch and rejects proofs with unknown hashes.
    pub validator_set_hash: [u8; 32],

    /// Solana slot at which the BridgeOutMessage was proven
    pub slot: u64,

    /// Total activated stake for the epoch (lamports).
    /// Committed publicly so the EVM contract can log / threshold-check.
    pub total_epoch_stake: u64,
}

impl SolanaProofPublicInputs {
    /// ABI-encode for EVM verification.
    ///
    /// Produces 10 × 32-byte ABI slots matching the Solidity signature:
    /// ```text
    /// abi.encode(bytes32, uint64, bytes32, address, uint64, int64, bytes32, bytes32, uint64, uint64)
    /// ```
    pub fn abi_encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(10 * 32);

        // Slot 0: bytes32 — bridge_program_id
        buf.extend_from_slice(&self.bridge_program_id);

        // Slot 1: uint64 — nonce (left-padded to uint256)
        let mut word = [0u8; 32];
        word[24..32].copy_from_slice(&self.nonce.to_be_bytes());
        buf.extend_from_slice(&word);

        // Slot 2: bytes32 — solana_sender
        buf.extend_from_slice(&self.solana_sender);

        // Slot 3: address — evm_recipient (left-padded: 12 zeros + 20 bytes)
        let mut addr_word = [0u8; 32];
        addr_word[12..32].copy_from_slice(&self.evm_recipient);
        buf.extend_from_slice(&addr_word);

        // Slot 4: uint64 — amount (left-padded to uint256)
        let mut word = [0u8; 32];
        word[24..32].copy_from_slice(&self.amount.to_be_bytes());
        buf.extend_from_slice(&word);

        // Slot 5: int64 — burn_timestamp (sign-extended to int256)
        let mut ts_word = if self.burn_timestamp < 0 {
            [0xFFu8; 32]
        } else {
            [0u8; 32]
        };
        ts_word[24..32].copy_from_slice(&self.burn_timestamp.to_be_bytes());
        buf.extend_from_slice(&ts_word);

        // Slot 6: bytes32 — account_hash
        buf.extend_from_slice(&self.account_hash);

        // Slot 7: bytes32 — validator_set_hash
        buf.extend_from_slice(&self.validator_set_hash);

        // Slot 8: uint64 — slot (left-padded to uint256)
        let mut word = [0u8; 32];
        word[24..32].copy_from_slice(&self.slot.to_be_bytes());
        buf.extend_from_slice(&word);

        // Slot 9: uint64 — total_epoch_stake (left-padded to uint256)
        let mut word = [0u8; 32];
        word[24..32].copy_from_slice(&self.total_epoch_stake.to_be_bytes());
        buf.extend_from_slice(&word);

        buf
    }
}

// ============================================================================
// Private Inputs (witness)
// ============================================================================

/// Private witness data for the SP1 Solana state proof.
///
/// # Verification Chain
///
/// ```text
/// account data ──► account_hash ──► accounts_delta_hash ──► bank_hash ──► validator votes
///   (parsed)        (SHA-256)      (fanout-16 Merkle)      (SHA-256)     (Ed25519 quorum)
/// ```
///
/// # Security Invariants
///
/// - `parent_bank_hash` MUST be non-zero (fetched from votes on slot S-1)
/// - `epoch_stakes` are committed via `validator_set_hash` in public inputs
/// - Vote deduplication is enforced by the circuit (per vote_authority)
/// - Epoch-boundary slots are rejected (bank hash formula adds extra terms)
#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct SolanaProofWitness {
    // -- Account data --

    /// Raw BridgeOutMessage account data (includes Anchor discriminator)
    pub account_data: Vec<u8>,

    /// BridgeOutMessage PDA address (32 bytes)
    pub account_address: [u8; 32],

    /// Account owner (must be x0-bridge program)
    pub account_owner: [u8; 32],

    /// Account lamports balance (must be > 0)
    pub account_lamports: u64,

    /// Account executable flag
    pub account_executable: bool,

    /// Account rent epoch
    pub account_rent_epoch: u64,

    // -- Account inclusion proof (account → accounts_delta_hash) --

    /// Fanout-16 Merkle inclusion proof
    pub inclusion_proof: AccountInclusionProof,

    /// Root of the accounts delta tree for the target slot
    pub accounts_delta_hash: [u8; 32],

    // -- Bank hash --

    /// Bank hash for the target slot (from validator votes)
    pub bank_hash: [u8; 32],

    /// Components for re-deriving the bank hash inside the circuit
    pub bank_hash_components: BankHashComponents,

    // -- Validator vote attestations --

    /// Individual validator votes attesting to the bank hash
    pub validator_votes: Vec<ValidatorVote>,

    /// Full validator set: (vote_authority, identity, stake) triples.
    /// Must be sorted by `vote_authority` ascending (deterministic hashing).
    pub epoch_stakes: Vec<ValidatorSetEntry>,

    /// Total activated stake for the epoch (sum of all epoch_stakes entries)
    pub total_epoch_stake: u64,

    // -- Slot info --

    /// Solana slot being proven
    pub slot: u64,
}

impl SolanaProofWitness {
    /// Pre-validate witness data before sending to the SP1 circuit.
    ///
    /// Catches common errors early, avoiding wasted proving time.
    /// Returns a human-readable error string on failure.
    pub fn validate(&self) -> Result<(), String> {
        // 1. Account data must be parseable
        if ParsedBridgeOutMessage::try_from_bytes(&self.account_data).is_none() {
            return Err("Cannot parse account data as BridgeOutMessage".into());
        }

        // 2. Bank hash must be non-zero
        if self.bank_hash == [0u8; 32] {
            return Err("Bank hash is zero — not fetched".into());
        }

        // 3. Parent bank hash must be non-zero (critical fix from review)
        if self.bank_hash_components.parent_bank_hash == [0u8; 32] {
            return Err(
                "Parent bank hash is zero — must be fetched from votes on slot S-1".into(),
            );
        }

        // 4. Last blockhash must be non-zero
        if self.bank_hash_components.last_blockhash == [0u8; 32] {
            return Err("Last blockhash is zero".into());
        }

        // 5. Must have validator votes
        if self.validator_votes.is_empty() {
            return Err("No validator votes provided".into());
        }

        // 6. Total epoch stake must be positive
        if self.total_epoch_stake == 0 {
            return Err("Total epoch stake is zero".into());
        }

        // 7. Epoch stakes must not be empty
        if self.epoch_stakes.is_empty() {
            return Err("Epoch stakes list is empty".into());
        }

        // 8. Lamports must be non-zero (zero-lamport accounts hash to [0;32])
        if self.account_lamports == 0 {
            return Err("Account lamports is zero — account hash would be zeroed".into());
        }

        // 9. Check vote stake arithmetic won't overflow
        let total_vote_stake: Option<u64> = self
            .validator_votes
            .iter()
            .try_fold(0u64, |acc, v| acc.checked_add(v.stake));
        if total_vote_stake.is_none() {
            return Err("Vote stake sum overflows u64".into());
        }

        // 10. Check quorum arithmetic won't overflow
        if total_vote_stake.unwrap().checked_mul(3).is_none() {
            return Err("Quorum LHS (confirmed_stake * 3) overflows u64".into());
        }
        if self.total_epoch_stake.checked_mul(2).is_none() {
            return Err("Quorum RHS (total_epoch_stake * 2) overflows u64".into());
        }

        // 11. Merkle proof well-formedness
        for (i, level) in self.inclusion_proof.levels.iter().enumerate() {
            if level.siblings.len() >= MERKLE_FANOUT {
                return Err(format!(
                    "Merkle level {} has {} siblings (max {})",
                    i,
                    level.siblings.len(),
                    MERKLE_FANOUT - 1
                ));
            }
            if level.position as usize > level.siblings.len() {
                return Err(format!(
                    "Merkle level {} position {} >= group size {}",
                    i,
                    level.position,
                    level.siblings.len() + 1
                ));
            }
        }

        // 12. Epoch stakes must be sorted by vote_authority (circuit requires this)
        for i in 1..self.epoch_stakes.len() {
            if self.epoch_stakes[i].vote_authority <= self.epoch_stakes[i - 1].vote_authority {
                return Err(format!(
                    "Epoch stakes not sorted by vote_authority at index {}",
                    i
                ));
            }
        }

        Ok(())
    }
}

// ============================================================================
// Account Inclusion Proof (fanout-16 Merkle)
// ============================================================================

/// Proof of account inclusion in Solana's accounts_delta_hash.
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

/// Components of the bank hash derivation.
///
/// ```text
/// bank_hash(S) = SHA-256(
///     bank_hash(S-1) || accounts_delta_hash(S) || sig_count_le(S) || last_blockhash(S)
/// )
/// ```
///
/// Matches `Bank::hash_internal_state()` in `solana-runtime/src/bank.rs`.
///
/// # Invariants
///
/// - `parent_bank_hash` MUST be the real bank hash of the parent slot,
///   fetched from validator votes on that slot. A zeroed value indicates
///   the host failed to fetch it and the circuit will abort.
///
/// - `signature_count` is the total number of Ed25519 signatures across
///   ALL transactions in the block (not the transaction count).
///
/// - On epoch boundaries, Solana mixes in an additional
///   `epoch_accounts_hash`. The host MUST reject epoch-boundary slots.
#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct BankHashComponents {
    /// Bank hash of the parent slot. MUST be non-zero.
    pub parent_bank_hash: [u8; 32],

    /// Total number of Ed25519 signatures across all transactions in the block.
    ///
    /// This is NOT the transaction count — each transaction can require
    /// multiple signatures. Matches Solana's `Bank.signature_count`.
    pub signature_count: u64,

    /// Last PoH blockhash of the block
    pub last_blockhash: [u8; 32],
}

// ============================================================================
// Validator Set (committed via public input hash)
// ============================================================================

/// A validator set entry binding vote authority → identity → stake.
///
/// The circuit computes `validator_set_hash` from all entries and commits
/// it as a public output. The EVM contract validates this hash against a
/// governance-maintained value per Solana epoch.
///
/// # Security
///
/// By committing the validator set hash as a public output, a malicious
/// prover cannot fabricate epoch stakes. The EVM contract independently
/// knows the correct hash for each epoch.
///
/// # Ordering
///
/// Entries in the witness MUST be sorted by `vote_authority` ascending
/// for deterministic hashing. The circuit enforces this ordering.
#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct ValidatorSetEntry {
    /// Authorized voter pubkey — the key that signs vote transactions
    pub vote_authority: [u8; 32],

    /// Validator node identity pubkey
    pub validator_identity: [u8; 32],

    /// Activated stake in lamports
    pub stake: u64,
}

// ============================================================================
// Validator Vote Attestation
// ============================================================================

/// A validator's vote attesting to a bank hash.
///
/// # Circuit Verification
///
/// 1. `Ed25519(vote_authority, message_bytes, signature)` — signature authenticity
/// 2. `message_bytes[bank_hash_offset..+32] == target_bank_hash` — vote content
/// 3. `vote_authority` exists in committed `epoch_stakes` with matching stake
/// 4. Deduplication: each `vote_authority` counted at most once
///
/// The bank hash appears at a deterministic offset within the vote instruction
/// data in the serialized transaction message. The host parses the tx to find
/// this offset; the circuit re-verifies the bytes at that offset.
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

    /// Validator identity (node pubkey) — cross-referenced with epoch_stakes
    pub validator_identity: [u8; 32],

    /// Activated stake (lamports) — cross-referenced with epoch_stakes
    pub stake: u64,
}

// ============================================================================
// BridgeOutMessage Account Layout
// ============================================================================

/// Parsed BridgeOutMessage account data.
///
/// Matches the Anchor account layout from `x0-bridge/src/state.rs`.
///
/// # Discriminator Validation
///
/// The Anchor discriminator (`SHA-256("account:BridgeOutMessage")[..8]`) is
/// validated by the circuit at runtime — not checked here — to avoid
/// hardcoding bytes in this `no_std` crate. The constant
/// [`BRIDGE_OUT_MESSAGE_ACCOUNT_NAME`] provides the account type name.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ParsedBridgeOutMessage {
    /// Anchor discriminator (8 bytes, validated by circuit)
    pub discriminator: [u8; 8],
    /// Account version for future migrations
    pub version: u8,
    /// Monotonic nonce
    pub nonce: u64,
    /// Solana address that burned x0-USD
    pub solana_sender: [u8; 32],
    /// EVM recipient address on Base (20 bytes)
    pub evm_recipient: [u8; 20],
    /// Amount of x0-USD burned (micro-units, 6 decimals)
    pub amount: u64,
    /// Solana transaction signature of the burn (first 32 bytes)
    pub burn_tx_signature: [u8; 32],
    /// Unix timestamp when burn occurred
    pub burned_at: i64,
    /// Current status (0 = Burned)
    pub status: u8,
    /// PDA bump seed
    pub bump: u8,
    /// Reserved space for future upgrades
    pub _reserved: [u8; 32],
}

impl ParsedBridgeOutMessage {
    /// Minimum account data size for a valid BridgeOutMessage.
    ///
    /// Layout: discriminator(8) + version(1) + nonce(8) + solana_sender(32) +
    ///         evm_recipient(20) + amount(8) + burn_tx_signature(32) +
    ///         burned_at(8) + status(1) + bump(1) + _reserved(32) = 151 bytes.
    ///
    /// Matches `BRIDGE_OUT_MESSAGE_SIZE` in `x0-common/src/constants.rs`.
    pub const DATA_SIZE: usize = 8 + 1 + 8 + 32 + 20 + 8 + 32 + 8 + 1 + 1 + 32;

    /// Parse from raw Anchor account data.
    ///
    /// Returns `None` if the data is too short to contain all fields.
    /// Does NOT validate the discriminator — that is done by the circuit
    /// using SHA-256 over the account name.
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
        offset += 1;

        let mut _reserved = [0u8; 32];
        _reserved.copy_from_slice(&data[offset..offset + 32]);

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
            _reserved,
        })
    }
}
