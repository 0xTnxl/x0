//! Shared types between SP1 guest (STARK circuit) and host (prover) for
//! Solana state proofs used in outbound bridging (Solana → Base).
//!
//! The guest program proves:
//! 1. A set of Solana validator Ed25519 signatures over a bank hash
//!    representing ≥ 2/3 of the stake in an epoch
//! 2. The bank hash commits to an accounts hash via Merkle path
//! 3. A BridgeOutMessage account exists at a specific PDA with specific data
//!    via a Merkle inclusion proof against the accounts hash
//!
//! The public inputs are ABI-encoded for verification on Base EVM by
//! the X0UnlockContract via the SP1 on-chain verifier.

#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

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
    /// x0-bridge program ID on Solana (32 bytes, for program ownership validation)
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
    pub fn abi_encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(7 * 32); // Each ABI slot is 32 bytes

        // bytes32: bridge_program_id
        buf.extend_from_slice(&self.bridge_program_id);

        // uint64: nonce — ABI-encoded as uint256 (left-padded to 32 bytes)
        let mut nonce_slot = [0u8; 32];
        nonce_slot[24..32].copy_from_slice(&self.nonce.to_be_bytes());
        buf.extend_from_slice(&nonce_slot);

        // bytes32: solana_sender
        buf.extend_from_slice(&self.solana_sender);

        // address: evm_recipient — ABI-encoded as address (left-padded, 12 + 20)
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
// Private Inputs (witness — only used inside guest circuit)
// ============================================================================

/// Private witness data for the SP1 Solana state proof
///
/// Contains all the cryptographic material needed to verify a Solana
/// account's existence and data, but is NOT revealed to the EVM verifier.
#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct SolanaProofWitness {
    /// The raw account data of the BridgeOutMessage PDA
    pub account_data: Vec<u8>,

    /// The PDA address of the BridgeOutMessage account (32 bytes)
    pub account_address: [u8; 32],

    /// Owner program of the account (should be x0-bridge program ID)
    pub account_owner: [u8; 32],

    /// Account lamports balance
    pub account_lamports: u64,

    /// Whether the account is executable
    pub account_executable: bool,

    /// Account rent epoch
    pub account_rent_epoch: u64,

    /// Merkle proof: path from account leaf → accounts hash
    /// Each element is a 32-byte sibling hash
    pub account_proof: Vec<[u8; 32]>,

    /// Leaf index in the accounts hash Merkle tree
    pub account_leaf_index: u64,

    /// The accounts hash (root of the accounts Merkle tree)
    pub accounts_hash: [u8; 32],

    /// Bank hash that commits to the accounts hash
    /// bank_hash = SHA-256(accounts_hash || ..._other_components)
    pub bank_hash: [u8; 32],

    /// Components of the bank hash derivation (for verification)
    pub bank_hash_components: BankHashComponents,

    /// Validator vote account signatures over the bank hash
    pub validator_signatures: Vec<ValidatorSignature>,

    /// Epoch stake information for quorum validation
    pub epoch_stakes: Vec<ValidatorStake>,

    /// Total active stake in the epoch
    pub total_epoch_stake: u64,

    /// Slot number of the bank hash
    pub slot: u64,
}

/// Components used to derive the bank hash
///
/// bank_hash = SHA-256(
///     accounts_hash
///     || signature_count.to_le_bytes()
///     || last_blockhash
///     || parent_bank_hash
/// )
#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct BankHashComponents {
    /// Number of signatures in the block
    pub signature_count: u64,

    /// Last blockhash of the block
    pub last_blockhash: [u8; 32],

    /// Parent bank hash
    pub parent_bank_hash: [u8; 32],
}

/// A validator's Ed25519 signature over a bank hash
#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct ValidatorSignature {
    /// Validator's Ed25519 public key (32 bytes)
    pub validator_pubkey: [u8; 32],

    /// Ed25519 signature over the bank hash (64 bytes)
    pub signature: [u8; 64],

    /// Stake weight of this validator in the epoch
    pub stake: u64,
}

/// Stake information for a validator in the epoch
#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct ValidatorStake {
    /// Validator identity pubkey
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
/// Used by the guest program to extract fields from raw account data.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ParsedBridgeOutMessage {
    /// Anchor discriminator (8 bytes)
    pub discriminator: [u8; 8],

    /// Account version
    pub version: u8,

    /// Outbound nonce
    pub nonce: u64,

    /// Solana sender address (32 bytes)
    pub solana_sender: [u8; 32],

    /// EVM recipient address (20 bytes)
    pub evm_recipient: [u8; 20],

    /// Amount (USDC micro-units)
    pub amount: u64,

    /// Burn transaction signature (32 bytes)
    pub burn_tx_signature: [u8; 32],

    /// Burn timestamp
    pub burned_at: i64,

    /// Status byte (0 = Burned)
    pub status: u8,

    /// PDA bump
    pub bump: u8,
}

impl ParsedBridgeOutMessage {
    /// Expected size of the serialized account data (excluding reserved)
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
