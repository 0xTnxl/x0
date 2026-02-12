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

    /// Number of active entries in allowed_evm_contracts
    pub allowed_evm_contracts_count: u8,

    /// Whitelisted EVM lock contract addresses (20 bytes each)
    /// Only the first `allowed_evm_contracts_count` entries are active
    pub allowed_evm_contracts: [[u8; EVM_ADDRESS_SIZE]; MAX_ALLOWED_EVM_CONTRACTS],

    /// Number of active entries in supported_domains
    pub supported_domains_count: u8,

    /// Supported Hyperlane origin domain IDs
    /// Only the first `supported_domains_count` entries are active
    pub supported_domains: [u32; MAX_SUPPORTED_DOMAINS],

    /// Monotonic nonce for timelocked admin actions
    pub admin_action_nonce: u64,

    /// PDA bump seed
    pub bump: u8,

    /// Monotonic nonce for outbound bridge messages (Solana → Base)
    pub bridge_out_nonce: u64,

    /// Rolling daily outflow volume for rate limiting
    pub daily_outflow_volume: u64,

    /// Timestamp when daily outflow counter was last reset
    pub daily_outflow_reset_timestamp: i64,

    /// Reserved space for future upgrades (56 - 24 = 32 bytes remaining)
    pub _reserved: [u8; 32],
}

impl BridgeConfig {
    pub const fn space() -> usize {
        BRIDGE_CONFIG_SIZE
    }

    /// Check if a Hyperlane domain is supported
    pub fn is_domain_supported(&self, domain: u32) -> bool {
        let count = self.supported_domains_count as usize;
        self.supported_domains[..count].contains(&domain)
    }

    /// Check if an EVM contract address is whitelisted
    pub fn is_contract_allowed(&self, address: &[u8; EVM_ADDRESS_SIZE]) -> bool {
        let count = self.allowed_evm_contracts_count as usize;
        self.allowed_evm_contracts[..count].contains(address)
    }

    /// Add an EVM contract to the allowed list. Returns error if full or duplicate.
    pub fn add_contract(&mut self, contract: [u8; EVM_ADDRESS_SIZE]) -> Result<()> {
        let count = self.allowed_evm_contracts_count as usize;
        require!(count < MAX_ALLOWED_EVM_CONTRACTS, x0_common::error::X0BridgeError::TooManyEVMContracts);
        require!(!self.is_contract_allowed(&contract), x0_common::error::X0BridgeError::BridgeAlreadyInitialized);
        self.allowed_evm_contracts[count] = contract;
        self.allowed_evm_contracts_count += 1;
        Ok(())
    }

    /// Remove an EVM contract from the allowed list. Returns error if not found.
    pub fn remove_contract(&mut self, contract: &[u8; EVM_ADDRESS_SIZE]) -> Result<()> {
        let count = self.allowed_evm_contracts_count as usize;
        let pos = self.allowed_evm_contracts[..count]
            .iter()
            .position(|c| c == contract)
            .ok_or(x0_common::error::X0BridgeError::MessageNotFound)?;
        // Swap-remove: move last element into the gap
        self.allowed_evm_contracts[pos] = self.allowed_evm_contracts[count - 1];
        self.allowed_evm_contracts[count - 1] = [0u8; EVM_ADDRESS_SIZE];
        self.allowed_evm_contracts_count -= 1;
        Ok(())
    }

    /// Add a supported domain. Returns error if full or duplicate.
    pub fn add_domain(&mut self, domain: u32) -> Result<()> {
        let count = self.supported_domains_count as usize;
        require!(count < MAX_SUPPORTED_DOMAINS, x0_common::error::X0BridgeError::TooManySupportedDomains);
        require!(!self.is_domain_supported(domain), x0_common::error::X0BridgeError::TooManySupportedDomains);
        self.supported_domains[count] = domain;
        self.supported_domains_count += 1;
        Ok(())
    }

    /// Remove a supported domain. Returns error if not found.
    pub fn remove_domain(&mut self, domain: u32) -> Result<()> {
        let count = self.supported_domains_count as usize;
        let pos = self.supported_domains[..count]
            .iter()
            .position(|d| *d == domain)
            .ok_or(x0_common::error::X0BridgeError::UnsupportedDomain)?;
        // Swap-remove
        self.supported_domains[pos] = self.supported_domains[count - 1];
        self.supported_domains[count - 1] = 0;
        self.supported_domains_count -= 1;
        Ok(())
    }

    /// Reset daily counter if 24 hours have passed
    pub fn maybe_reset_daily_counter(&mut self, current_timestamp: i64) {
        if current_timestamp - self.daily_inflow_reset_timestamp >= ROLLING_WINDOW_SECONDS {
            self.daily_inflow_volume = 0;
            self.daily_inflow_reset_timestamp = current_timestamp;
        }
    }
    /// Reset daily outflow counter if 24 hours have passed
    pub fn maybe_reset_daily_outflow_counter(&mut self, current_timestamp: i64) {
        if current_timestamp - self.daily_outflow_reset_timestamp >= ROLLING_WINDOW_SECONDS {
            self.daily_outflow_volume = 0;
            self.daily_outflow_reset_timestamp = current_timestamp;
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

// ============================================================================
// Outbound Bridge (Solana → Base)
// ============================================================================

/// Status of an outbound bridge message
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug, PartialEq, Eq)]
pub enum BridgeOutStatus {
    /// x0-USD has been burned on Solana, awaiting USDC unlock on Base
    Burned,
    /// USDC has been unlocked on Base (terminal success — set off-chain or via future instruction)
    Unlocked,
    /// Bridge out failed (terminal failure state)
    Failed,
}

impl Default for BridgeOutStatus {
    fn default() -> Self {
        Self::Burned
    }
}

/// An outbound bridge message recording a burn of x0-USD on Solana
///
/// Created by `initiate_bridge_out`. The off-chain SP1 Solana prover
/// reads this PDA's data to generate a STARK proof that the X0UnlockContract
/// on Base verifies before releasing USDC.
///
/// Seeds: ["bridge_out_message", nonce.to_le_bytes()]
#[account]
#[derive(Debug)]
pub struct BridgeOutMessage {
    /// Account version for future migrations
    pub version: u8,

    /// Monotonic nonce (from BridgeConfig.bridge_out_nonce at time of burn)
    pub nonce: u64,

    /// Solana address that burned x0-USD
    pub solana_sender: Pubkey,

    /// EVM recipient address on Base (20 bytes)
    pub evm_recipient: [u8; EVM_ADDRESS_SIZE],

    /// Amount of x0-USD burned (USDC micro-units, 6 decimals)
    pub amount: u64,

    /// Solana transaction signature of the burn (first 32 bytes)
    pub burn_tx_signature: [u8; 32],

    /// Unix timestamp when burn occurred
    pub burned_at: i64,

    /// Current status
    pub status: BridgeOutStatus,

    /// PDA bump seed
    pub bump: u8,

    /// Reserved space for future upgrades
    pub _reserved: [u8; 32],
}

impl BridgeOutMessage {
    pub const fn space() -> usize {
        BRIDGE_OUT_MESSAGE_SIZE
    }
}

/// Message body format for outbound bridge (Solana → Base)
///
/// This is the canonical encoding that the SP1 Solana prover commits
/// and the X0UnlockContract on Base verifies.
///
/// Layout (packed, big-endian for EVM compatibility):
///   [0..20]   evm_recipient:  Base address (20 bytes)
///   [20..28]  amount:         uint64 big-endian (USDC micro-units)
///   [28..60]  burn_tx_sig:    bytes32 (Solana tx signature, first 32 bytes)
///   [60..68]  nonce:          uint64 big-endian (bridge_out_nonce)
#[derive(Clone, Debug)]
pub struct BridgeOutMessageBody {
    /// EVM recipient address on Base
    pub evm_recipient: [u8; EVM_ADDRESS_SIZE],
    /// Amount in USDC micro-units (6 decimals)
    pub amount: u64,
    /// Solana burn transaction signature (first 32 bytes)
    pub burn_tx_signature: [u8; 32],
    /// Outbound nonce
    pub nonce: u64,
}

impl BridgeOutMessageBody {
    /// Expected size of the serialized message body
    pub const ENCODED_SIZE: usize = 20 + 8 + 32 + 8; // 68 bytes

    /// Serialize to big-endian encoded bytes (EVM-compatible format)
    pub fn to_bytes(&self) -> [u8; Self::ENCODED_SIZE] {
        let mut buf = [0u8; Self::ENCODED_SIZE];
        buf[0..20].copy_from_slice(&self.evm_recipient);
        buf[20..28].copy_from_slice(&self.amount.to_be_bytes());
        buf[28..60].copy_from_slice(&self.burn_tx_signature);
        buf[60..68].copy_from_slice(&self.nonce.to_be_bytes());
        buf
    }

    /// Deserialize from big-endian encoded bytes
    pub fn try_from_bytes(data: &[u8]) -> Result<Self> {
        require!(
            data.len() == Self::ENCODED_SIZE,
            x0_common::error::X0BridgeError::InvalidMessageBody
        );

        let mut evm_recipient = [0u8; EVM_ADDRESS_SIZE];
        evm_recipient.copy_from_slice(&data[0..20]);

        let mut amount_bytes = [0u8; 8];
        amount_bytes.copy_from_slice(&data[20..28]);
        let amount = u64::from_be_bytes(amount_bytes);

        let mut burn_tx_signature = [0u8; 32];
        burn_tx_signature.copy_from_slice(&data[28..60]);

        let mut nonce_bytes = [0u8; 8];
        nonce_bytes.copy_from_slice(&data[60..68]);
        let nonce = u64::from_be_bytes(nonce_bytes);

        Ok(Self {
            evm_recipient,
            amount,
            burn_tx_signature,
            nonce,
        })
    }
}
