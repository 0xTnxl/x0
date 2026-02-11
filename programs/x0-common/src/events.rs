//! Event definitions for x0-01 protocol
//!
//! Events are emitted for indexing and off-chain tracking.

use anchor_lang::prelude::*;

// ============================================================================
// Guard Events
// ============================================================================

/// Emitted when a new agent policy is created
#[event]
pub struct PolicyCreated {
    /// The policy PDA address
    pub policy: Pubkey,
    /// The owner's address
    pub owner: Pubkey,
    /// The agent's signing key
    pub agent_signer: Pubkey,
    /// Initial daily limit
    pub daily_limit: u64,
    /// Unix timestamp of creation
    pub timestamp: i64,
}

/// Emitted when an agent policy is updated
#[event]
pub struct PolicyUpdated {
    /// The policy PDA address
    pub policy: Pubkey,
    /// New daily limit (if changed)
    pub daily_limit: Option<u64>,
    /// New agent signer (if changed)
    pub agent_signer: Option<Pubkey>,
    /// Unix timestamp of update
    pub timestamp: i64,
}

/// Emitted when an agent's authority is revoked
#[event]
pub struct AgentRevoked {
    /// The policy PDA address
    pub policy: Pubkey,
    /// The revoked agent signer
    pub revoked_signer: Pubkey,
    /// Unix timestamp of revocation
    pub timestamp: i64,
}

/// Emitted when a transfer is validated by the guard
#[event]
pub struct TransferValidated {
    /// The policy PDA address
    pub policy: Pubkey,
    /// Transfer amount
    pub amount: u64,
    /// Recipient address
    pub recipient: Pubkey,
    /// Current 24h spend after this transfer
    pub current_spend_24h: u64,
    /// Remaining daily allowance
    pub remaining_allowance: u64,
    /// Whether this was a confidential transfer
    pub is_confidential: bool,
    /// Unix timestamp
    pub timestamp: i64,
}

/// Emitted when a transfer is rejected by the guard
#[event]
pub struct TransferRejected {
    /// The policy PDA address
    pub policy: Pubkey,
    /// Attempted transfer amount
    pub amount: u64,
    /// Attempted recipient
    pub recipient: Pubkey,
    /// Reason code
    pub reason_code: u16,
    /// Unix timestamp
    pub timestamp: i64,
}

/// Emitted when a Blink is generated for human approval
#[event]
pub struct BlinkGenerated {
    /// The policy PDA address
    pub policy: Pubkey,
    /// The agent that triggered the Blink
    pub agent: Pubkey,
    /// Requested amount
    pub amount: u64,
    /// Requested recipient
    pub recipient: Pubkey,
    /// Blink expiration timestamp
    pub expires_at: i64,
    /// Unix timestamp of generation
    pub timestamp: i64,
}

/// Emitted when whitelist is updated
///
/// # LOW-2: String Field Size Limits
/// - `mode`: Maximum 32 characters. One of: "none", "merkle", "bloom", "explicit"
#[event]
pub struct WhitelistUpdated {
    /// The policy PDA address
    pub policy: Pubkey,
    /// New whitelist mode (max 32 chars: "none", "merkle", "bloom", "explicit")
    pub mode: String,
    /// Unix timestamp
    pub timestamp: i64,
}

// ============================================================================
// Escrow Events
// ============================================================================

/// Emitted when an escrow is created
#[event]
pub struct EscrowCreated {
    /// The escrow PDA address
    pub escrow: Pubkey,
    /// Buyer address
    pub buyer: Pubkey,
    /// Seller address
    pub seller: Pubkey,
    /// Optional arbiter address
    pub arbiter: Option<Pubkey>,
    /// Escrow amount
    pub amount: u64,
    /// Service memo hash
    pub memo_hash: [u8; 32],
    /// Escrow timeout timestamp
    pub timeout: i64,
    /// Unix timestamp of creation
    pub timestamp: i64,
}

/// Emitted when an escrow is funded
#[event]
pub struct EscrowFunded {
    /// The escrow PDA address
    pub escrow: Pubkey,
    /// Amount funded
    pub amount: u64,
    /// Unix timestamp
    pub timestamp: i64,
}

/// Emitted when seller marks delivery complete
#[event]
pub struct DeliveryMarked {
    /// The escrow PDA address
    pub escrow: Pubkey,
    /// Delivery proof hash
    pub proof_hash: Option<[u8; 32]>,
    /// Unix timestamp
    pub timestamp: i64,
}

/// Emitted when a dispute is initiated
#[event]
pub struct DisputeInitiated {
    /// The escrow PDA address
    pub escrow: Pubkey,
    /// Party that initiated the dispute
    pub initiator: Pubkey,
    /// Evidence hash
    pub evidence_hash: [u8; 32],
    /// Unix timestamp
    pub timestamp: i64,
}

/// Emitted when funds are released to seller
#[event]
pub struct FundsReleased {
    /// The escrow PDA address
    pub escrow: Pubkey,
    /// Amount released
    pub amount: u64,
    /// Recipient (seller)
    pub recipient: Pubkey,
    /// Whether this was auto-release
    pub is_auto_release: bool,
    /// Unix timestamp
    pub timestamp: i64,
}

/// Emitted when funds are refunded to buyer
///
/// # LOW-2: String Field Size Limits
/// - `reason`: Maximum 128 characters. Truncated if exceeded.
#[event]
pub struct FundsRefunded {
    /// The escrow PDA address
    pub escrow: Pubkey,
    /// Amount refunded
    pub amount: u64,
    /// Recipient (buyer)
    pub recipient: Pubkey,
    /// Reason for refund (max 128 chars, truncated if exceeded)
    pub reason: String,
    /// Unix timestamp
    pub timestamp: i64,
}

/// Emitted when a dispute is resolved
#[event]
pub struct DisputeResolved {
    /// The escrow PDA address
    pub escrow: Pubkey,
    /// Resolver (arbiter or auto)
    pub resolver: Pubkey,
    /// Winner of the dispute
    pub winner: Pubkey,
    /// Amount awarded to winner
    pub amount: u64,
    /// Unix timestamp
    pub timestamp: i64,
}

// ============================================================================
// Registry Events
// ============================================================================

/// Emitted when an agent registers in the registry
///
/// # LOW-2: String Field Size Limits
/// - `endpoint`: Maximum 200 characters. URLs exceeding this are rejected.
#[event]
pub struct AgentRegistered {
    /// The registry entry PDA
    pub registry_entry: Pubkey,
    /// The agent's policy PDA
    pub agent_id: Pubkey,
    /// Service endpoint URL (max 200 chars)
    pub endpoint: String,
    /// Number of capabilities registered
    pub capability_count: u8,
    /// Unix timestamp
    pub timestamp: i64,
}

/// Emitted when an agent updates their registry entry
///
/// # LOW-2: String Field Size Limits
/// - `updated_fields`: Maximum 10 field names, each max 32 characters.
///   Field names: "endpoint", "capabilities", "price_oracle", "is_active", etc.
#[event]
pub struct RegistryUpdated {
    /// The registry entry PDA
    pub registry_entry: Pubkey,
    /// Fields that were updated (max 10 fields, each max 32 chars)
    pub updated_fields: Vec<String>,
    /// Unix timestamp
    pub timestamp: i64,
}

/// Emitted when an agent deregisters from the registry
#[event]
pub struct AgentDeregistered {
    /// The registry entry PDA
    pub registry_entry: Pubkey,
    /// The agent's policy PDA
    pub agent_id: Pubkey,
    /// Unix timestamp
    pub timestamp: i64,
}

// ============================================================================
// Reputation Events
// ============================================================================

/// Emitted when a reputation account is initialized
#[event]
pub struct ReputationInitialized {
    /// The reputation PDA
    pub reputation: Pubkey,
    /// The agent's policy PDA
    pub agent_id: Pubkey,
    /// Unix timestamp
    pub timestamp: i64,
}

/// Emitted when reputation is updated after a transaction
///
/// # LOW-2: String Field Size Limits
/// - `update_type`: Maximum 32 characters. One of: "success", "dispute", "resolution", "decay"
#[event]
pub struct ReputationUpdated {
    /// The reputation PDA
    pub reputation: Pubkey,
    /// Update type (max 32 chars: "success", "dispute", "resolution", "decay")
    pub update_type: String,
    /// New total transactions count
    pub total_transactions: u64,
    /// New reputation score (scaled by 1000 for precision)
    pub score_scaled: u32,
    /// Unix timestamp
    pub timestamp: i64,
}

// ============================================================================
// Token Events
// ============================================================================

/// Emitted when a confidential transfer is executed
#[event]
pub struct ConfidentialTransferExecuted {
    /// Source account (agent)
    pub source: Pubkey,
    /// Destination account
    pub destination: Pubkey,
    /// Encrypted amount ciphertext (for auditor)
    pub encrypted_amount: Option<[u8; 64]>,
    /// Unix timestamp
    pub timestamp: i64,
}

/// Emitted for audit log entries (confidential mode with auditor)
#[event]
pub struct AuditLog {
    /// The agent's policy PDA
    pub agent: Pubkey,
    /// Encrypted amount ciphertext (decryptable by auditor)
    pub ciphertext: [u8; 64],
    /// Unix timestamp
    pub timestamp: i64,
}

// ============================================================================
// Protocol Events
// ============================================================================

/// Emitted when protocol configuration is updated
///
/// # LOW-2: String Field Size Limits
/// - `update_description`: Maximum 256 characters. Truncated if exceeded.
#[event]
pub struct ProtocolConfigUpdated {
    /// Protocol config PDA
    pub config: Pubkey,
    /// Admin who made the update
    pub admin: Pubkey,
    /// Description of what was updated (max 256 chars)
    pub update_description: String,
    /// Unix timestamp
    pub timestamp: i64,
}

/// Emitted when protocol is paused/unpaused
///
/// # LOW-2: String Field Size Limits
/// - `reason`: Maximum 128 characters. Truncated if exceeded.
#[event]
pub struct ProtocolPaused {
    /// Protocol config PDA
    pub config: Pubkey,
    /// Whether protocol is now paused
    pub is_paused: bool,
    /// Reason for pause (max 128 chars)
    pub reason: String,
    /// Unix timestamp
    pub timestamp: i64,
}

// ============================================================================
// Wrapper Events
// ============================================================================

/// Emitted when wrapper is initialized
#[event]
pub struct WrapperInitialized {
    /// The wrapper config PDA
    pub config: Pubkey,
    /// The USDC mint address
    pub usdc_mint: Pubkey,
    /// The wrapper mint address
    pub wrapper_mint: Pubkey,
    /// The reserve account address
    pub reserve_account: Pubkey,
    /// Initial admin
    pub admin: Pubkey,
    /// Unix timestamp
    pub timestamp: i64,
}

/// Emitted when USDC is deposited and x0-USD is minted
#[event]
pub struct DepositMinted {
    /// User who deposited
    pub user: Pubkey,
    /// Amount of USDC deposited
    pub usdc_amount: u64,
    /// Amount of x0-USD minted (same as usdc_amount, 1:1)
    pub wrapper_minted: u64,
    /// New reserve balance
    pub reserve_balance: u64,
    /// New outstanding supply
    pub outstanding_supply: u64,
    /// Unix timestamp
    pub timestamp: i64,
}

/// Emitted when x0-USD is burned and USDC is redeemed
#[event]
pub struct RedemptionCompleted {
    /// User who redeemed
    pub user: Pubkey,
    /// Amount of x0-USD burned
    pub amount_burned: u64,
    /// Amount of USDC paid out (after fee)
    pub usdc_paid: u64,
    /// Fee collected
    pub fee_collected: u64,
    /// New reserve balance
    pub reserve_balance: u64,
    /// New outstanding supply
    pub outstanding_supply: u64,
    /// Unix timestamp
    pub timestamp: i64,
}

/// Emitted when reserve ratio falls below warning threshold
#[event]
pub struct ReserveAlert {
    /// Reserve ratio scaled by 10000 (10000 = 1.0)
    pub reserve_ratio: u64,
    /// Current reserve balance
    pub reserve_balance: u64,
    /// Current outstanding supply
    pub outstanding_supply: u64,
    /// Alert severity level
    pub severity: AlertLevel,
    /// Unix timestamp
    pub timestamp: i64,
}

/// Alert severity levels
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug, PartialEq)]
pub enum AlertLevel {
    /// Reserve ratio < 1.01 (less than 1% overcollateralization)
    Warning,
    /// Reserve ratio < 1.0 (undercollateralized)
    Critical,
}

/// Emitted when wrapper is paused/unpaused
#[event]
pub struct WrapperPausedEvent {
    /// Wrapper config PDA
    pub config: Pubkey,
    /// Whether wrapper is now paused
    pub is_paused: bool,
    /// Admin who triggered the action
    pub admin: Pubkey,
    /// Unix timestamp
    pub timestamp: i64,
}

/// Emitted when redemption fee is updated
#[event]
pub struct FeeRateUpdated {
    /// Wrapper config PDA
    pub config: Pubkey,
    /// Old fee rate in bps
    pub old_fee_bps: u16,
    /// New fee rate in bps
    pub new_fee_bps: u16,
    /// Admin who triggered the action
    pub admin: Pubkey,
    /// Unix timestamp
    pub timestamp: i64,
}

/// Emitted when an admin action is scheduled
#[event]
pub struct AdminActionScheduled {
    /// Admin action PDA
    pub action: Pubkey,
    /// Type of action
    pub action_type: String,
    /// When the action can be executed
    pub scheduled_timestamp: i64,
    /// Admin who scheduled
    pub admin: Pubkey,
    /// Unix timestamp when scheduled
    pub timestamp: i64,
}

/// Emitted when an admin action is executed
#[event]
pub struct AdminActionExecuted {
    /// Admin action PDA
    pub action: Pubkey,
    /// Type of action
    pub action_type: String,
    /// Admin who executed
    pub admin: Pubkey,
    /// Unix timestamp
    pub timestamp: i64,
}

/// Emitted when an admin action is cancelled
#[event]
pub struct AdminActionCancelled {
    /// Admin action PDA
    pub action: Pubkey,
    /// Admin who cancelled
    pub admin: Pubkey,
    /// Unix timestamp
    pub timestamp: i64,
}

/// Emitted when emergency withdrawal occurs
#[event]
pub struct EmergencyWithdrawal {
    /// Wrapper config PDA
    pub config: Pubkey,
    /// Amount withdrawn
    pub amount: u64,
    /// Destination address
    pub destination: Pubkey,
    /// Admin who executed
    pub admin: Pubkey,
    /// Unix timestamp
    pub timestamp: i64,
}

/// Emitted when admin is transferred
#[event]
pub struct AdminTransferred {
    /// Wrapper config PDA
    pub config: Pubkey,
    /// Previous admin
    pub old_admin: Pubkey,
    /// New admin
    pub new_admin: Pubkey,
    /// Unix timestamp
    pub timestamp: i64,
}

// ============================================================================
// Bridge Events (Base → Solana cross-chain)
// ============================================================================

/// Emitted when the bridge is initialized
#[event]
pub struct BridgeInitialized {
    /// Bridge config PDA
    pub config: Pubkey,
    /// Admin address
    pub admin: Pubkey,
    /// Hyperlane mailbox program
    pub hyperlane_mailbox: Pubkey,
    /// SP1 verifier program
    pub sp1_verifier: Pubkey,
    /// USDC mint address
    pub usdc_mint: Pubkey,
    /// Unix timestamp
    pub timestamp: i64,
}

/// Emitted when a cross-chain message is received from Hyperlane
#[event]
pub struct BridgeMessageReceived {
    /// Bridge message PDA
    pub message_pda: Pubkey,
    /// Hyperlane message ID
    pub message_id: [u8; 32],
    /// Origin Hyperlane domain
    pub origin_domain: u32,
    /// Sender address on origin chain (padded to 32 bytes)
    pub sender: [u8; 32],
    /// Recipient address on Solana
    pub recipient: Pubkey,
    /// Amount to bridge (in micro-units)
    pub amount: u64,
    /// Unix timestamp
    pub timestamp: i64,
}

/// Emitted when a STARK proof is verified for a bridge message
#[event]
pub struct BridgeProofVerified {
    /// EVM proof context PDA
    pub proof_context: Pubkey,
    /// Linked bridge message PDA
    pub message_pda: Pubkey,
    /// Hyperlane message ID
    pub message_id: [u8; 32],
    /// EVM block number where lock occurred
    pub evm_block_number: u64,
    /// EVM transaction hash
    pub evm_tx_hash: [u8; 32],
    /// Verified amount
    pub amount: u64,
    /// Unix timestamp
    pub timestamp: i64,
}

/// Emitted when x0-USD is minted via verified bridge deposit
#[event]
pub struct BridgeMintExecuted {
    /// Bridge message PDA
    pub message_pda: Pubkey,
    /// Hyperlane message ID
    pub message_id: [u8; 32],
    /// Recipient who received x0-USD
    pub recipient: Pubkey,
    /// Amount of x0-USD minted
    pub amount: u64,
    /// Origin domain (e.g., Base)
    pub origin_domain: u32,
    /// New bridge total inflow
    pub total_bridged_in: u64,
    /// Unix timestamp
    pub timestamp: i64,
}

/// Emitted when bridge daily rate limit resets
#[event]
pub struct BridgeDailyReset {
    /// Bridge config PDA
    pub config: Pubkey,
    /// Previous day's total volume
    pub previous_volume: u64,
    /// Unix timestamp
    pub timestamp: i64,
}

/// Emitted when bridge is paused or unpaused
#[event]
pub struct BridgePausedEvent {
    /// Bridge config PDA
    pub config: Pubkey,
    /// Whether bridge is now paused
    pub is_paused: bool,
    /// Admin who triggered
    pub admin: Pubkey,
    /// Unix timestamp
    pub timestamp: i64,
}

/// Emitted when an EVM contract is added/removed from the allowed list
#[event]
pub struct BridgeContractUpdated {
    /// Bridge config PDA
    pub config: Pubkey,
    /// EVM contract address (20 bytes)
    pub evm_contract: [u8; 20],
    /// Whether the contract was added (true) or removed (false)
    pub added: bool,
    /// Admin who triggered
    pub admin: Pubkey,
    /// Unix timestamp
    pub timestamp: i64,
}

// ============================================================================
// Wrapper-Side Bridge Events
// ============================================================================

/// Emitted by x0-wrapper when bridge_mint is called
#[event]
pub struct WrapperBridgeMint {
    /// The bridge program that invoked bridge_mint
    pub bridge_program: Pubkey,
    /// Recipient of the minted x0-USD
    pub recipient: Pubkey,
    /// Amount of x0-USD minted
    pub amount: u64,
    /// New reserve USDC balance
    pub reserve_balance: u64,
    /// New outstanding wrapper supply
    pub outstanding_supply: u64,
    /// Unix timestamp
    pub timestamp: i64,
}

/// Emitted when the bridge program address is updated in WrapperConfig
#[event]
pub struct WrapperBridgeProgramUpdated {
    /// Previous bridge program address
    pub old_bridge_program: Pubkey,
    /// New bridge program address
    pub new_bridge_program: Pubkey,
    /// Admin who made the change
    pub admin: Pubkey,
    /// Unix timestamp
    pub timestamp: i64,
}

// ============================================================================
// Bridge Admin Timelock Events
// ============================================================================

/// Emitted when a timelocked admin action is scheduled
#[event]
pub struct BridgeAdminActionScheduled {
    /// Action PDA
    pub action_pda: Pubkey,
    /// Action nonce
    pub nonce: u64,
    /// Type of action (0=AddEvmContract, 1=RemoveEvmContract, 2=AddDomain, 3=RemoveDomain, 4=UpdateSp1Verifier)
    pub action_type: u8,
    /// Scheduled execution time
    pub scheduled_at: i64,
    /// EVM contract (if applicable)
    pub evm_contract: [u8; 20],
    /// Domain (if applicable)
    pub domain: u32,
    /// Admin who scheduled
    pub admin: Pubkey,
    /// Unix timestamp when scheduled
    pub timestamp: i64,
}

/// Emitted when a timelocked admin action is executed
#[event]
pub struct BridgeAdminActionExecuted {
    /// Action PDA
    pub action_pda: Pubkey,
    /// Action nonce
    pub nonce: u64,
    /// Type of action
    pub action_type: u8,
    /// Admin who executed
    pub admin: Pubkey,
    /// Unix timestamp when executed
    pub timestamp: i64,
}

/// Emitted when a timelocked admin action is cancelled
#[event]
pub struct BridgeAdminActionCancelled {
    /// Action PDA
    pub action_pda: Pubkey,
    /// Action nonce
    pub nonce: u64,
    /// Type of action
    pub action_type: u8,
    /// Admin who cancelled
    pub admin: Pubkey,
    /// Unix timestamp when cancelled
    pub timestamp: i64,
}

/// Emitted when the circuit breaker is triggered
#[event]
pub struct BridgeCircuitBreakerTriggered {
    /// Bridge config PDA
    pub config: Pubkey,
    /// Total bridged in at time of trigger
    pub total_bridged_in: u64,
    /// Circuit breaker threshold
    pub threshold: u64,
    /// Unix timestamp
    pub timestamp: i64,
}
