//! State structures for x0-bridge program
//!
//! Defines the on-chain account structures for the cross-chain bridge:
//! - BridgeConfig: Global bridge configuration and rate limiting
//! - BridgeMessage: Individual bridge message state (Hyperlane → Solana)
//! - EVMProofContext: Verified STARK proof data for an EVM transaction
//!
//! # Architecture
//!
//! The bridge uses a two-step process:
//! 1. Hyperlane delivers a message → BridgeMessage PDA (status: Received)
//! 2. SP1 STARK proof is verified → EVMProofContext PDA (status: ProofVerified)
//! 3. x0-USD is minted via CPI to x0-wrapper → (status: Minted)
//!
//! This separation ensures compute budget safety (~500k CU for STARK verification
//! + ~200k CU for CPI mint would exceed limits if combined).

use anchor_lang::prelude::*;
use x0_common::constants::*;

// ============================================================================
// Bridge Configuration
// ============================================================================

/// Global bridge configuration PDA
///
/// Controls which EVM contracts are trusted, which Hyperlane domains are
/// supported, rate limiting, and pause state.
///
/// Seeds: ["bridge_config"]
#[account]
#[derive(Debug)]
pub struct BridgeConfig {
    /// Account version for future migrations
    pub version: u8,

    /// Bridge administrator (should be multisig in production)
    pub admin: Pubkey,

    /// Hyperlane mailbox program on Solana
    pub hyperlane_mailbox: Pubkey,

    /// SP1 verifier program on Solana
    pub sp1_verifier: Pubkey,

    /// x0-wrapper program for CPI mint
    pub wrapper_program: Pubkey,

    /// x0-wrapper config PDA (passed to CPI)
    pub wrapper_config: Pubkey,

    /// USDC mint address on Solana
    pub usdc_mint: Pubkey,

    /// x0-USD wrapper mint address
    pub wrapper_mint: Pubkey,

    /// Bridge's USDC reserve token account
    /// (Holds USDC liquidity that backs minted x0-USD via wrapper CPI)
    pub bridge_usdc_reserve: Pubkey,

    /// Whether bridge operations are paused
    pub is_paused: bool,

    /// Total USDC bridged into Solana (all-time)
    pub total_bridged_in: u64,

    /// Total USDC bridged out of Solana (all-time, reserved for future use)
    pub total_bridged_out: u64,

    /// Monotonic nonce for message ordering
    pub nonce: u64,

    /// Rolling daily inflow volume for rate limiting
    pub daily_inflow_volume: u64,

    /// Timestamp when daily counter was last reset
    pub daily_inflow_reset_timestamp: i64,

    /// Whitelisted EVM lock contract addresses (20 bytes each)
    /// Only messages from these contracts are accepted
    pub allowed_evm_contracts: Vec<[u8; EVM_ADDRESS_SIZE]>,

    /// Supported Hyperlane origin domain IDs
    pub supported_domains: Vec<u32>,

    /// Monotonic nonce for timelocked admin actions
    pub admin_action_nonce: u64,

    /// PDA bump seed
    pub bump: u8,

    /// Reserved space for future upgrades
    pub _reserved: [u8; 56],
}

impl BridgeConfig {
    pub const fn space() -> usize {
        BRIDGE_CONFIG_SIZE
    }

    /// Check if a Hyperlane domain is supported
    pub fn is_domain_supported(&self, domain: u32) -> bool {
        self.supported_domains.contains(&domain)
    }

    /// Check if an EVM contract address is whitelisted
    pub fn is_contract_allowed(&self, address: &[u8; EVM_ADDRESS_SIZE]) -> bool {
        self.allowed_evm_contracts.contains(address)
    }

    /// Reset daily counter if 24 hours have passed
    pub fn maybe_reset_daily_counter(&mut self, current_timestamp: i64) {
        if current_timestamp - self.daily_inflow_reset_timestamp >= ROLLING_WINDOW_SECONDS {
            self.daily_inflow_volume = 0;
            self.daily_inflow_reset_timestamp = current_timestamp;
        }
    }
}

// ============================================================================
// Bridge Message
// ============================================================================

/// Status of a bridge message through its lifecycle
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug, PartialEq, Eq)]
pub enum BridgeMessageStatus {
    /// Message received from Hyperlane, awaiting proof verification
    Received,
    /// STARK proof verified, awaiting mint execution
    ProofVerified,
    /// x0-USD minted to recipient (terminal success state)
    Minted,
    /// Processing failed (terminal failure state)
    Failed,
}

impl Default for BridgeMessageStatus {
    fn default() -> Self {
        Self::Received
    }
}

/// A cross-chain bridge message received from Hyperlane
///
/// Created during the `handle_message` instruction when Hyperlane delivers
/// a message from the EVM lock contract. Tracks the message through the
/// full verification and minting pipeline.
///
/// Seeds: ["bridge_message", message_id]
#[account]
#[derive(Debug)]
pub struct BridgeMessage {
    /// Account version for future migrations
    pub version: u8,

    /// Hyperlane message ID (unique across all Hyperlane messages)
    pub message_id: [u8; 32],

    /// Origin Hyperlane domain (e.g., 8453 for Base)
    pub origin_domain: u32,

    /// Sender address on origin chain (EVM address padded to 32 bytes)
    pub sender: [u8; 32],

    /// Recipient Solana address
    pub recipient: Pubkey,

    /// Amount to bridge (USDC micro-units, 6 decimals)
    pub amount: u64,

    /// Unix timestamp when message was received
    pub received_at: i64,

    /// Current message status
    pub status: BridgeMessageStatus,

    /// EVM transaction hash from the lock (populated during proof verification)
    pub evm_tx_hash: [u8; 32],

    /// Monotonic nonce from the bridge config at time of receipt
    pub nonce: u64,

    /// PDA bump seed
    pub bump: u8,

    /// Reserved space for future upgrades
    pub _reserved: [u8; 32],
}

impl BridgeMessage {
    pub const fn space() -> usize {
        BRIDGE_MESSAGE_SIZE
    }
}

// ============================================================================
// EVM Proof Context
// ============================================================================

/// Type of EVM proof
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug, PartialEq, Eq)]
pub enum EVMProofType {
    /// Proof of a single EVM transaction
    Transaction,
    /// Proof of a batch of EVM transactions (future use)
    Batch,
}

/// An event log extracted from a verified EVM transaction
///
/// Contains the contract address, indexed topics, and data payload
/// from an EVM event emission. Used to extract deposit details.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
pub struct EVMEventLog {
    /// Contract that emitted the event (20 bytes)
    pub contract_address: [u8; EVM_ADDRESS_SIZE],
    /// Indexed topics (topic[0] = event signature hash)
    pub topics: Vec<[u8; EVM_HASH_SIZE]>,
    /// Non-indexed event data
    pub data: Vec<u8>,
}

impl EVMEventLog {
    /// Maximum serialized size of a single event log
    pub const fn max_size() -> usize {
        EVM_ADDRESS_SIZE +                           // contract_address
        4 + (MAX_EVENT_TOPICS * EVM_HASH_SIZE) +     // topics vec
        4 + MAX_EVENT_DATA_SIZE                      // data vec
    }
}

/// Verified EVM transaction proof context
///
/// Created when a STARK proof (SP1) is successfully verified. Contains the
/// public outputs from the proof that confirm the EVM transaction occurred.
/// Links to a BridgeMessage via message_id.
///
/// Mirrors the pattern from x0-zk-verifier's ProofContext, adapted for
/// cross-chain EVM state proofs instead of Token-2022 Groth16 proofs.
///
/// Seeds: ["evm_proof", message_id]
#[account]
#[derive(Debug)]
pub struct EVMProofContext {
    /// Account version for future migrations
    pub version: u8,

    /// Type of proof (Transaction or Batch)
    pub proof_type: EVMProofType,

    /// Whether the proof has been verified
    pub verified: bool,

    /// Unix timestamp when proof was verified
    pub verified_at: i64,

    /// EVM block hash where the transaction was included
    pub block_hash: [u8; EVM_HASH_SIZE],

    /// EVM block number
    pub block_number: u64,

    /// EVM transaction hash
    pub tx_hash: [u8; EVM_HASH_SIZE],

    /// Transaction sender (20-byte EVM address)
    pub from: [u8; EVM_ADDRESS_SIZE],

    /// Transaction recipient / contract (20-byte EVM address)
    pub to: [u8; EVM_ADDRESS_SIZE],

    /// ETH value transferred (in wei, typically 0 for ERC-20 locks)
    pub value: u64,

    /// Extracted event logs from the transaction
    pub event_logs: Vec<EVMEventLog>,

    /// Hyperlane message ID that this proof is linked to
    pub message_id: [u8; 32],

    /// PDA bump seed
    pub bump: u8,

    /// Reserved space for future upgrades
    pub _reserved: [u8; 32],
}

impl EVMProofContext {
    pub const fn space() -> usize {
        EVM_PROOF_CONTEXT_SIZE
    }

    /// Check if the proof context is still fresh (within validity window)
    pub fn is_fresh(&self, current_timestamp: i64) -> bool {
        current_timestamp - self.verified_at < BRIDGE_PROOF_VALIDITY_SECONDS
    }
}

// ============================================================================
// Hyperlane Message Body Encoding
// ============================================================================

/// The message body format sent from the EVM lock contract via Hyperlane
///
/// This is deserialized from the raw bytes passed in handle_message.
///
/// Layout (packed, big-endian for EVM compatibility):
///   [0..32]   recipient:    Solana pubkey (32 bytes)
///   [32..40]  amount:       uint64 big-endian (USDC micro-units)
///   [40..72]  evm_tx_hash:  bytes32 (lock transaction hash)
///   [72..80]  nonce:        uint64 big-endian (lock contract nonce)
#[derive(Clone, Debug)]
pub struct BridgeMessageBody {
    /// Solana recipient address
    pub recipient: Pubkey,
    /// Amount in USDC micro-units (6 decimals)
    pub amount: u64,
    /// EVM transaction hash where USDC was locked
    pub evm_tx_hash: [u8; 32],
    /// Nonce from the EVM lock contract
    pub nonce: u64,
}

impl BridgeMessageBody {
    /// Expected size of the serialized message body
    pub const ENCODED_SIZE: usize = 32 + 8 + 32 + 8; // 80 bytes

    /// Deserialize from big-endian encoded bytes (EVM format)
    ///
    /// # Security
    /// Uses exact size check (==) to prevent trailing data from hiding
    /// malicious payloads. Any extra bytes will cause an error.
    pub fn try_from_bytes(data: &[u8]) -> Result<Self> {
        require!(
            data.len() == Self::ENCODED_SIZE,
            x0_common::error::X0BridgeError::InvalidMessageBody
        );

        let recipient = Pubkey::try_from(&data[0..32])
            .map_err(|_| x0_common::error::X0BridgeError::InvalidRecipient)?;

        let mut amount_bytes = [0u8; 8];
        amount_bytes.copy_from_slice(&data[32..40]);
        let amount = u64::from_be_bytes(amount_bytes);

        let mut evm_tx_hash = [0u8; 32];
        evm_tx_hash.copy_from_slice(&data[40..72]);

        let mut nonce_bytes = [0u8; 8];
        nonce_bytes.copy_from_slice(&data[72..80]);
        let nonce = u64::from_be_bytes(nonce_bytes);

        Ok(Self {
            recipient,
            amount,
            evm_tx_hash,
            nonce,
        })
    }
}

// ============================================================================
// SP1 Proof Public Inputs
// ============================================================================

/// Public inputs/outputs committed by the SP1 STARK proof
///
/// These values are exposed to the Solana verifier and are cryptographically
/// bound to the proof. The prover commits these inside the STARK circuit
/// after verifying the EVM block header, transaction inclusion, and receipt.
///
/// Layout (borsh-serialized):
///   block_hash, block_number, tx_hash, from, to, value, success, event_count, events...
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
pub struct SP1PublicInputs {
    /// Block hash where the transaction was mined
    pub block_hash: [u8; EVM_HASH_SIZE],
    /// Block number
    pub block_number: u64,
    /// Transaction hash
    pub tx_hash: [u8; EVM_HASH_SIZE],
    /// Transaction sender (EVM address)
    pub from: [u8; EVM_ADDRESS_SIZE],
    /// Transaction recipient/contract (EVM address)
    pub to: [u8; EVM_ADDRESS_SIZE],
    /// ETH value transferred
    pub value: u64,
    /// Whether the transaction was successful
    pub success: bool,
    /// Extracted event logs
    pub event_logs: Vec<EVMEventLog>,
}

// ============================================================================
// Bridge Admin Timelock
// ============================================================================

/// Type of timelocked bridge admin action
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug, PartialEq)]
pub enum BridgeAdminActionType {
    /// Add an EVM contract to the allowed list
    AddEvmContract,
    /// Remove an EVM contract from the allowed list
    RemoveEvmContract,
    /// Add a supported Hyperlane domain
    AddDomain,
    /// Remove a supported Hyperlane domain
    RemoveDomain,
    /// Update the SP1 verifier program (rare, requires careful review)
    UpdateSp1Verifier,
}

/// A timelocked bridge admin action
///
/// Sensitive bridge operations require a 48-hour waiting period before
/// execution. This gives token holders and users time to react to
/// suspicious admin activity.
///
/// Note: Pause/unpause is NOT timelocked as it's needed for emergencies.
///
/// Seeds: ["bridge_admin_action", nonce.to_le_bytes()]
#[account]
#[derive(Debug)]
pub struct BridgeAdminAction {
    /// Nonce for unique action identification
    pub nonce: u64,

    /// Type of action
    pub action_type: BridgeAdminActionType,

    /// Scheduled execution timestamp (action can execute after this time)
    pub scheduled_at: i64,

    /// EVM contract address (for AddEvmContract/RemoveEvmContract)
    pub evm_contract: [u8; EVM_ADDRESS_SIZE],

    /// Domain ID (for AddDomain/RemoveDomain)
    pub domain: u32,

    /// New address value (for UpdateSp1Verifier, future use)
    pub new_address: Pubkey,

    /// Admin who scheduled this action
    pub scheduled_by: Pubkey,

    /// Whether this action has been executed
    pub executed: bool,

    /// Whether this action has been cancelled
    pub cancelled: bool,

    /// PDA bump seed
    pub bump: u8,

    /// Reserved for future use
    pub _reserved: [u8; 32],
}

impl BridgeAdminAction {
    pub const fn space() -> usize {
        BRIDGE_ADMIN_ACTION_SIZE
    }

    /// Check if action is ready to execute (timelock expired)
    pub fn is_ready(&self, current_timestamp: i64) -> bool {
        !self.executed && !self.cancelled && current_timestamp >= self.scheduled_at
    }

    /// Check if action is still pending (not ready yet)
    pub fn is_pending(&self, current_timestamp: i64) -> bool {
        !self.executed && !self.cancelled && current_timestamp < self.scheduled_at
    }
}
