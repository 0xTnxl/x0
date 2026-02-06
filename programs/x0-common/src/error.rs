//! Error codes for x0-01 protocol (Appendix A compliant)
//!
//! # LOW-3: Error Code Numbering Scheme
//!
//! Error codes follow a structured numbering system for easy identification:
//!
//! ## Category Ranges (High Byte)
//! - 0x1100-0x11FF: Guard/Policy errors (core policy violations)
//! - 0x1200-0x12FF: Escrow errors (payment/escrow operations)
//! - 0x1300-0x13FF: Registry errors (agent discovery/registration)
//! - 0x1400-0x14FF: Reputation errors (reputation tracking)
//! - 0x1500-0x15FF: Token errors (SPL token operations)
//!
//! ## Subcategory Ranges (Low Nibble of High Byte)
//! Within each category, errors are grouped:
//! - 0xNN00-0xNN0F: Core/fundamental errors
//! - 0xNN10-0xNN1F: Configuration errors
//! - 0xNN20-0xNN2F: State transition errors
//! - 0xNN30-0xNN3F: Validation errors
//! - 0xNN40-0xNN4F: Authorization errors
//! - 0xNN50-0xNN5F: Rate limiting errors
//!
//! ## Adding New Errors
//! 1. Identify the correct category (Guard, Escrow, Registry, etc.)
//! 2. Find the appropriate subcategory
//! 3. Use the next sequential number in that subcategory
//! 4. Update this documentation if adding a new subcategory
//!
//! ## Reserved Ranges
//! - 0x1180-0x119F: Reserved for security-related guard errors
//! - 0x1280-0x129F: Reserved for security-related escrow errors

use anchor_lang::prelude::*;

/// Error codes for x0_guard program
#[error_code]
pub enum X0GuardError {
    // ========================================================================
    // Policy Errors (0x1100-0x110F)
    // ========================================================================
    
    /// Recipient address is not in the agent's whitelist
    #[msg("Recipient not whitelisted")]
    RecipientNotWhitelisted, // 0x1101

    /// Agent has exceeded their rolling 24-hour spending limit
    #[msg("Daily spending limit exceeded")]
    DailyLimitExceeded, // 0x1102

    /// Merkle proof verification failed for whitelist check
    #[msg("Invalid Merkle proof")]
    InvalidMerkleProof, // 0x1103

    /// Bloom filter is corrupted or misconfigured
    #[msg("Invalid Bloom filter configuration")]
    InvalidBloomFilter, // 0x1104

    /// Agent policy PDA does not exist for this agent
    #[msg("Agent policy not found")]
    PolicyNotFound, // 0x1105

    /// Transaction was signed by unauthorized key
    #[msg("Unauthorized signer")]
    UnauthorizedSigner, // 0x1106

    /// Zero-knowledge proof verification failed
    #[msg("Confidential transfer proof verification failed")]
    ConfidentialTransferFailed, // 0x1107

    // ========================================================================
    // Policy Configuration Errors (0x1110-0x111F)
    // ========================================================================
    
    /// Daily limit exceeds maximum allowed
    #[msg("Daily limit exceeds maximum")]
    DailyLimitTooHigh, // 0x1110

    /// Daily limit is below minimum threshold
    #[msg("Daily limit below minimum")]
    DailyLimitTooLow, // 0x1111

    /// Whitelist configuration is invalid
    #[msg("Invalid whitelist configuration")]
    InvalidWhitelistConfig, // 0x1112

    /// Merkle proof is missing when required
    #[msg("Missing Merkle proof")]
    MissingMerkleProof, // 0x1113

    /// Policy is already initialized
    #[msg("Policy already initialized")]
    PolicyAlreadyInitialized, // 0x1114

    /// Policy owner mismatch
    #[msg("Policy owner mismatch")]
    PolicyOwnerMismatch, // 0x1115

    /// Agent signer already set
    #[msg("Agent signer already active")]
    AgentSignerActive, // 0x1116

    /// Rolling window is full
    #[msg("Rolling window overflow")]
    RollingWindowOverflow, // 0x1117

    /// Agent must be a delegate, not the token account owner
    #[msg("Delegation required: agent must be delegate, not owner")]
    DelegationRequired, // 0x1118

    /// Token account owner does not match policy owner
    #[msg("Token account owner must match policy owner")]
    TokenAccountOwnerMismatch, // 0x1119

    /// Self-delegation attack detected (owner == agent_signer)
    #[msg("Self-delegation not allowed")]
    SelfDelegationNotAllowed, // 0x111A

    /// Transfer from wrong token account (bound account mismatch)
    #[msg("Transfer must originate from bound token account")]
    BoundTokenAccountMismatch, // 0x111B

    /// Invalid token account data
    #[msg("Invalid token account data")]
    InvalidTokenAccountData, // 0x111C

    /// Invalid ZK proof account owner (must be Token-2022 program)
    #[msg("ZK proof account must be owned by Token-2022 program")]
    InvalidZkProofOwner, // 0x111D

    /// ZK proof context validation failed
    #[msg("ZK proof context does not match transfer parameters")]
    ZkProofContextMismatch, // 0x111E

    /// Missing ZK proof for confidential transfer
    #[msg("ZK proof required for confidential transfer")]
    MissingZkProof, // 0x111F

    // ========================================================================
    // Transfer Errors (0x1120-0x112F)
    // ========================================================================

    /// Insufficient token balance for transfer
    #[msg("Insufficient funds")]
    InsufficientFunds, // 0x110A (keeping original code for compatibility)

    /// Transfer amount is zero
    #[msg("Transfer amount cannot be zero")]
    ZeroTransferAmount, // 0x1120

    /// Transfer amount exceeds single transaction limit
    #[msg("Transfer amount exceeds maximum")]
    TransferAmountTooHigh, // 0x1121

    /// Invalid memo hash format
    #[msg("Invalid memo hash")]
    InvalidMemoHash, // 0x1122

    /// Timestamp is invalid or too far in the past
    #[msg("Invalid timestamp")]
    InvalidTimestamp, // 0x1123

    // ========================================================================
    // Blink Errors (0x1130-0x113F)
    // ========================================================================

    /// Blink rate limit exceeded
    #[msg("Blink rate limit exceeded")]
    BlinkRateLimitExceeded, // 0x1130

    /// Blink has expired
    #[msg("Blink expired")]
    BlinkExpired, // 0x1131

    /// Invalid Blink signature
    #[msg("Invalid Blink signature")]
    InvalidBlinkSignature, // 0x1132

    /// Blink already processed
    #[msg("Blink already processed")]
    BlinkAlreadyProcessed, // 0x1133

    // ========================================================================
    // Medium Severity Error Codes (0x1140-0x114F)
    // ========================================================================

    /// MEDIUM-2: Policy update rate limit exceeded
    #[msg("Policy updates are rate limited - try again later")]
    PolicyUpdateTooFrequent, // 0x1140

    /// MEDIUM-8: Single transaction limit exceeded
    #[msg("Transaction exceeds single transaction limit")]
    SingleTransactionLimitExceeded, // 0x1141

    /// MEDIUM-12: Transfer amount below minimum threshold
    #[msg("Transfer amount below minimum threshold")]
    TransferAmountTooSmall, // 0x1142

    /// MEDIUM-10: Extra account metas already initialized
    #[msg("Extra account metas already initialized")]
    ExtraMetasAlreadyInitialized, // 0x1143

    /// MEDIUM-10: Caller is not the mint authority
    #[msg("Only the mint authority can initialize extra account metas")]
    UnauthorizedExtraMetasInitializer, // 0x1144
}

/// Error codes for x0_escrow program
#[error_code]
pub enum X0EscrowError {
    // ========================================================================
    // Escrow State Errors (0x1108-0x1109 for compatibility, then 0x1200+)
    // ========================================================================

    /// Escrow has expired
    #[msg("Escrow timeout reached")]
    EscrowExpired, // 0x1108

    /// Operation not allowed in current escrow state
    #[msg("Invalid escrow state for this operation")]
    InvalidEscrowState, // 0x1109

    // ========================================================================
    // Escrow Configuration Errors (0x1200-0x120F)
    // ========================================================================

    /// Escrow timeout is too short
    #[msg("Escrow timeout too short")]
    EscrowTimeoutTooShort, // 0x1200

    /// Escrow timeout is too long
    #[msg("Escrow timeout too long")]
    EscrowTimeoutTooLong, // 0x1201

    /// Buyer and seller cannot be the same
    #[msg("Buyer and seller must be different")]
    SameBuyerAndSeller, // 0x1202

    /// Invalid arbiter configuration
    #[msg("Invalid arbiter")]
    InvalidArbiter, // 0x1203

    /// Escrow amount is zero
    #[msg("Escrow amount cannot be zero")]
    ZeroEscrowAmount, // 0x1204

    /// Escrow already exists
    #[msg("Escrow already exists")]
    EscrowAlreadyExists, // 0x1205

    /// Invalid mint account (wrong owner or type)
    #[msg("Invalid mint account")]
    InvalidMint, // 0x1206

    // ========================================================================
    // Escrow Operation Errors (0x1210-0x121F)
    // ========================================================================

    /// Only buyer can fund escrow
    #[msg("Only buyer can fund escrow")]
    OnlyBuyerCanFund, // 0x1210

    /// Only seller can mark as delivered
    #[msg("Only seller can mark as delivered")]
    OnlySellerCanDeliver, // 0x1211

    /// Only buyer can release funds
    #[msg("Only buyer can release funds")]
    OnlyBuyerCanRelease, // 0x1212

    /// Only arbiter can resolve dispute
    #[msg("Only arbiter can resolve dispute")]
    OnlyArbiterCanResolve, // 0x1213

    /// Invalid evidence hash
    #[msg("Invalid evidence hash")]
    InvalidEvidenceHash, // 0x1214

    /// Dispute already initiated
    #[msg("Dispute already initiated")]
    DisputeAlreadyInitiated, // 0x1215

    /// Cannot dispute before delivery
    #[msg("Cannot dispute before delivery")]
    CannotDisputeBeforeDelivery, // 0x1216

    /// MEDIUM-6: Arbiter attempting to resolve too early
    #[msg("Arbiter must wait for resolution delay period")]
    ArbiterResolutionTooEarly, // 0x1217

    /// MEDIUM-6: Dispute evidence required for arbiter resolution
    #[msg("Dispute evidence required before arbiter resolution")]
    DisputeEvidenceRequired, // 0x1218
}

/// Error codes for x0_registry program
#[error_code]
pub enum X0RegistryError {
    // ========================================================================
    // Registry Entry Errors (0x1300-0x130F)
    // ========================================================================

    /// Agent already registered
    #[msg("Agent already registered")]
    AgentAlreadyRegistered, // 0x1300

    /// Agent not found in registry
    #[msg("Agent not found")]
    AgentNotFound, // 0x1301

    /// Invalid endpoint URL
    #[msg("Invalid endpoint URL")]
    InvalidEndpoint, // 0x1302

    /// Endpoint URL too long
    #[msg("Endpoint too long")]
    EndpointTooLong, // 0x1303

    /// Too many capabilities
    #[msg("Too many capabilities")]
    TooManyCapabilities, // 0x1304

    /// Invalid capability type
    #[msg("Invalid capability type")]
    InvalidCapabilityType, // 0x1305

    /// Capability metadata too long
    #[msg("Capability metadata too long")]
    CapabilityMetadataTooLong, // 0x1306

    /// Insufficient listing fee
    #[msg("Insufficient listing fee")]
    InsufficientListingFee, // 0x1307

    /// Unauthorized registry update
    #[msg("Unauthorized registry update")]
    UnauthorizedRegistryUpdate, // 0x1308

    /// Registry entry expired
    #[msg("Registry entry expired")]
    RegistryEntryExpired, // 0x1309
}

/// Error codes for x0_reputation program
#[error_code]
pub enum X0ReputationError {
    // ========================================================================
    // Reputation Errors (0x1400-0x140F)
    // ========================================================================

    /// Reputation account not found
    #[msg("Reputation account not found")]
    ReputationNotFound, // 0x1400

    /// Reputation already initialized
    #[msg("Reputation already initialized")]
    ReputationAlreadyInitialized, // 0x1401

    /// Invalid reputation update
    #[msg("Invalid reputation update")]
    InvalidReputationUpdate, // 0x1402

    /// Unauthorized reputation update
    #[msg("Unauthorized reputation update")]
    UnauthorizedReputationUpdate, // 0x1403

    /// Insufficient transactions for reputation score
    #[msg("Insufficient transactions for reputation")]
    InsufficientTransactions, // 0x1404

    /// Reputation score out of range
    #[msg("Reputation score out of range")]
    ReputationScoreOutOfRange, // 0x1405

    /// Invalid policy account
    #[msg("Invalid policy account")]
    InvalidPolicyAccount, // 0x1406

    /// Unauthorized action
    #[msg("Unauthorized")]
    Unauthorized, // 0x1407
}

/// Error codes for x0_token program
#[error_code]
pub enum X0TokenError {
    // ========================================================================
    // Token Errors (0x1500-0x150F)
    // ========================================================================

    /// Mint already initialized
    #[msg("Mint already initialized")]
    MintAlreadyInitialized, // 0x1500

    /// Invalid mint authority
    #[msg("Invalid mint authority")]
    InvalidMintAuthority, // 0x1501

    /// Invalid transfer hook program
    #[msg("Invalid transfer hook program")]
    InvalidTransferHookProgram, // 0x1502

    /// Confidential transfers not enabled
    #[msg("Confidential transfers not enabled")]
    ConfidentialTransfersNotEnabled, // 0x1503

    /// Invalid token decimals
    #[msg("Invalid token decimals")]
    InvalidTokenDecimals, // 0x1504

    /// Transfer hook validation failed
    #[msg("Transfer hook validation failed")]
    TransferHookValidationFailed, // 0x1505

    // ========================================================================
    // Confidential Transfer Errors (0x1506-0x151F)
    // ========================================================================

    /// Account not configured for confidential transfers
    #[msg("Account not configured for confidential transfers")]
    AccountNotConfiguredForConfidential, // 0x1506

    /// Invalid ElGamal public key
    #[msg("Invalid ElGamal public key")]
    InvalidElGamalPubkey, // 0x1507

    /// Invalid pubkey validity proof
    #[msg("Invalid pubkey validity proof")]
    InvalidPubkeyValidityProof, // 0x1508

    /// Invalid zero ciphertext proof
    #[msg("Invalid zero ciphertext proof")]
    InvalidZeroCiphertextProof, // 0x1509

    /// Invalid withdraw proof
    #[msg("Invalid withdraw proof")]
    InvalidWithdrawProof, // 0x150A

    /// Confidential balance insufficient
    #[msg("Confidential balance insufficient")]
    ConfidentialBalanceInsufficient, // 0x150B

    /// Pending balance not applied
    #[msg("Pending balance must be applied before this operation")]
    PendingBalanceNotApplied, // 0x150C

    /// Maximum pending balance credit counter exceeded
    #[msg("Maximum pending balance credit counter exceeded - apply pending balance")]
    MaxPendingBalanceCreditsExceeded, // 0x150D

    /// Confidential credits disabled on this account
    #[msg("Confidential credits are disabled on this account")]
    ConfidentialCreditsDisabled, // 0x150E

    /// Amount exceeds maximum for confidential transfers
    #[msg("Amount exceeds maximum for confidential transfers (2^48 - 1)")]
    AmountExceedsConfidentialMax, // 0x150F

    /// Proof context account mismatch
    #[msg("Proof context account does not match expected")]
    ProofContextMismatch, // 0x1510

    /// Proof verification failed
    #[msg("Zero-knowledge proof verification failed")]
    ProofVerificationFailed, // 0x1511

    /// Auditor ElGamal pubkey required
    #[msg("Auditor ElGamal pubkey is required for this operation")]
    AuditorPubkeyRequired, // 0x1512

    /// Non-confidential credits disabled
    #[msg("Non-confidential credits are disabled on this account")]
    NonConfidentialCreditsDisabled, // 0x1513

    /// Account already configured for confidential transfers
    #[msg("Account is already configured for confidential transfers")]
    AccountAlreadyConfigured, // 0x1514

    /// Invalid decryptable balance ciphertext
    #[msg("Invalid decryptable balance ciphertext format")]
    InvalidDecryptableBalance, // 0x1515
}

/// Error codes for x0_wrapper program
#[error_code]
pub enum X0WrapperError {
    // ========================================================================
    // Wrapper State Errors (0x1600-0x160F)
    // ========================================================================

    /// Wrapper is paused
    #[msg("Wrapper operations are paused")]
    WrapperPaused, // 0x1600

    /// Wrapper already initialized
    #[msg("Wrapper already initialized")]
    WrapperAlreadyInitialized, // 0x1601

    /// Wrapper not initialized
    #[msg("Wrapper not initialized")]
    WrapperNotInitialized, // 0x1602

    /// Invalid USDC mint address
    #[msg("Invalid USDC mint address")]
    InvalidUsdcMint, // 0x1603

    /// Invalid wrapper mint address
    #[msg("Invalid wrapper mint address")]
    InvalidWrapperMint, // 0x1604

    /// Decimal mismatch between USDC and wrapper
    #[msg("Token decimal mismatch")]
    DecimalMismatch, // 0x1605

    /// Invalid mint configuration (extension error)
    #[msg("Invalid mint configuration")]
    InvalidMintConfiguration, // 0x1606

    // ========================================================================
    // Reserve & Invariant Errors (0x1610-0x161F)
    // ========================================================================

    /// Insufficient reserve for redemption
    #[msg("Insufficient reserve balance")]
    InsufficientReserve, // 0x1610

    /// Reserve invariant violated
    #[msg("Reserve invariant violated: reserve < supply")]
    ReserveInvariantViolated, // 0x1611

    /// Reserve ratio below warning threshold
    #[msg("Reserve ratio below warning threshold")]
    ReserveRatioWarning, // 0x1612

    /// Reserve ratio critical
    #[msg("Reserve ratio critical: undercollateralized")]
    ReserveRatioCritical, // 0x1613

    // ========================================================================
    // Amount & Fee Errors (0x1620-0x162F)
    // ========================================================================

    /// Deposit amount too small
    #[msg("Deposit amount below minimum")]
    DepositTooSmall, // 0x1620

    /// Redemption amount too small
    #[msg("Redemption amount below minimum")]
    RedemptionTooSmall, // 0x1621

    /// Redemption amount exceeds per-transaction limit
    #[msg("Redemption exceeds per-transaction limit")]
    RedemptionTooLarge, // 0x1622

    /// Daily redemption limit exceeded
    #[msg("Daily redemption limit exceeded")]
    DailyRedemptionLimitExceeded, // 0x1623

    /// Fee rate exceeds maximum
    #[msg("Fee rate exceeds maximum allowed")]
    FeeRateTooHigh, // 0x1624

    /// Fee rate below minimum
    #[msg("Fee rate below minimum allowed")]
    FeeRateTooLow, // 0x1625

    /// Math overflow in fee calculation
    #[msg("Math overflow in calculation")]
    MathOverflow, // 0x1626

    /// Math underflow in calculation
    #[msg("Math underflow in calculation")]
    MathUnderflow, // 0x1627

    // ========================================================================
    // Authorization Errors (0x1630-0x163F)
    // ========================================================================

    /// Unauthorized admin operation
    #[msg("Unauthorized: admin required")]
    Unauthorized, // 0x1630

    /// Invalid multisig configuration
    #[msg("Invalid multisig configuration")]
    InvalidMultisig, // 0x1631

    /// Pending admin transfer not found
    #[msg("No pending admin transfer")]
    NoPendingAdminTransfer, // 0x1632

    /// Caller is not the pending admin
    #[msg("Caller is not the pending admin")]
    NotPendingAdmin, // 0x1633

    // ========================================================================
    // Timelock Errors (0x1640-0x164F)
    // ========================================================================

    /// Admin action not found
    #[msg("Admin action not found")]
    AdminActionNotFound, // 0x1640

    /// Admin action already executed
    #[msg("Admin action already executed")]
    AdminActionAlreadyExecuted, // 0x1641

    /// Admin action cancelled
    #[msg("Admin action was cancelled")]
    AdminActionCancelled, // 0x1642

    /// Timelock not expired
    #[msg("Timelock period not yet expired")]
    TimelockNotExpired, // 0x1643

    /// Timelock expired
    #[msg("Timelock period has expired")]
    TimelockExpired, // 0x1644

    /// Invalid action type
    #[msg("Invalid admin action type")]
    InvalidActionType, // 0x1645
}

/// Unified error type for cross-program invocations
#[derive(Clone, Debug)]
pub enum X0Error {
    Guard(X0GuardError),
    Escrow(X0EscrowError),
    Registry(X0RegistryError),
    Reputation(X0ReputationError),
    Token(X0TokenError),
    Wrapper(X0WrapperError),
}
