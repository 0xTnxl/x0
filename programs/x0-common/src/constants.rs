//! Protocol constants for x0-01
//!
//! These values are used across all x0 programs and define the protocol's
//! core parameters. Many are governance-adjustable (see Appendix C).

use anchor_lang::prelude::*;
use solana_program::pubkey;

// ============================================================================
// Protocol Program IDs (for cross-program authorization)
// ============================================================================

/// x0-escrow program ID - authorized to update reputation
pub const ESCROW_PROGRAM_ID: Pubkey = pubkey!("AhaDyVm8LBxpUwFdArA37LnHvNx6cNWe3KAiy8zGqhHF");

/// x0-guard program ID
pub const GUARD_PROGRAM_ID: Pubkey = pubkey!("2uYGW3fQUGfhrwVbkupdasXBpRPfGYBGTLUdaPTXU9vP");

/// x0-reputation program ID
pub const REPUTATION_PROGRAM_ID: Pubkey = pubkey!("FfzkTWRGAJQPDePbujZdEhKHqC1UpqvDrpv4TEiWpx6y");

// ============================================================================
// Protocol Identifiers
// ============================================================================

/// Protocol version string
pub const PROTOCOL_VERSION: &str = "2.0";

/// Protocol name for x402 headers
pub const PROTOCOL_NAME: &str = "x0-01";

/// Network identifier
pub const NETWORK_MAINNET: &str = "solana-mainnet";
pub const NETWORK_DEVNET: &str = "solana-devnet";
pub const NETWORK_LOCALNET: &str = "solana-localnet";

// ============================================================================
// Fee Configuration (Governance Adjustable)
// ============================================================================

/// Protocol fee in basis points (0.8% = 80 bps)
/// This is enforced at the Token-2022 level via TransferFee extension
pub const PROTOCOL_FEE_BASIS_POINTS: u16 = 80;

/// Maximum protocol fee (10% = 1000 bps) - governance safety cap
pub const MAX_PROTOCOL_FEE_BASIS_POINTS: u16 = 1000;

/// Minimum protocol fee in token micro-units (prevents fee avoidance via dust transfers)
/// Set to 1 token unit (1,000,000 with 6 decimals = 1 USDC)
pub const MIN_PROTOCOL_FEE: u64 = 1;

/// Fee denominator (basis points)
pub const FEE_DENOMINATOR: u64 = 10_000;

// ============================================================================
// Time Constants
// ============================================================================

/// Seconds in a 24-hour rolling window
pub const ROLLING_WINDOW_SECONDS: i64 = 86_400;

/// Maximum entries in the rolling window (~10 min intervals over 24h)
pub const MAX_ROLLING_WINDOW_ENTRIES: usize = 144;

/// Blink expiration time in seconds (15 minutes)
pub const BLINK_EXPIRY_SECONDS: i64 = 900;

/// Default escrow timeout in seconds (72 hours)
pub const DEFAULT_ESCROW_TIMEOUT_SECONDS: i64 = 259_200;

/// Minimum escrow timeout (1 hour)
pub const MIN_ESCROW_TIMEOUT_SECONDS: i64 = 3_600;

/// Maximum escrow timeout (30 days)
pub const MAX_ESCROW_TIMEOUT_SECONDS: i64 = 2_592_000;

// ============================================================================
// Slot-Based Time Constants (HIGH-1: Clock Manipulation Protection)
// ============================================================================

/// Approximate slots per second on Solana mainnet (400ms per slot = 2.5 slots/sec)
pub const SLOTS_PER_SECOND: u64 = 2;

/// Slots in a 24-hour rolling window (144 slots/min * 60 * 24 = 207,360)
/// Using conservative estimate for clock manipulation protection
pub const ROLLING_WINDOW_SLOTS: u64 = 216_000; // ~24 hours with buffer

/// Conservative buffer for time-based checks (5 minutes in slots)
/// Accounts for clock skew and validator manipulation within bounds
pub const TIME_CHECK_BUFFER_SLOTS: u64 = 750;

/// Slots for escrow timeout buffer (adds ~10 minutes safety margin)
pub const ESCROW_TIMEOUT_BUFFER_SLOTS: u64 = 1_500;

// ============================================================================
// Rate Limiting
// ============================================================================

/// Maximum Blinks per hour per agent (anti-spam)
pub const MAX_BLINKS_PER_HOUR: u8 = 3;

/// Cost in lamports to generate a Blink (burned)
pub const BLINK_GENERATION_COST_LAMPORTS: u64 = 1_000_000; // 0.001 SOL

/// MEDIUM-2: Minimum slots between policy updates (rate limiting)
/// ~5 minutes to prevent governance spam attacks
pub const POLICY_UPDATE_COOLDOWN_SLOTS: u64 = 750;

/// MEDIUM-6: Arbiter dispute resolution delay in slots
/// ~24 hours delay to prevent rushed malicious resolutions
pub const ARBITER_RESOLUTION_DELAY_SLOTS: u64 = 216_000;

// ============================================================================
// Policy Limits
// ============================================================================

/// Maximum daily limit in token micro-units (1M tokens)
pub const MAX_DAILY_LIMIT: u64 = 1_000_000_000_000; // 1M with 6 decimals

/// Minimum daily limit (prevents dust attacks)
pub const MIN_DAILY_LIMIT: u64 = 1_000_000; // 1 token with 6 decimals

/// MEDIUM-12: Minimum transfer amount (prevents dust/spam transfers)
/// 100 micro-units = 0.0001 tokens (with 6 decimals)
pub const MIN_TRANSFER_AMOUNT: u64 = 100;

/// Default daily limit for new policies
pub const DEFAULT_DAILY_LIMIT: u64 = 100_000_000_000; // 100K with 6 decimals

// ============================================================================
// Whitelist Limits
// ============================================================================

/// Maximum addresses in Merkle whitelist (practical limit for proof size)
pub const MAX_MERKLE_WHITELIST_SIZE: usize = 10_000;

/// Maximum Merkle proof depth (log2 of max whitelist size)
pub const MAX_MERKLE_PROOF_DEPTH: usize = 14;

/// Bloom filter size in bytes (4KB for ~1000 items @ 1% FP rate)
pub const BLOOM_FILTER_SIZE_BYTES: usize = 4_096;

/// Number of hash functions for Bloom filter
pub const BLOOM_HASH_COUNT: u8 = 7;

/// Maximum domain prefixes for Domain whitelist mode
pub const MAX_DOMAIN_PREFIXES: usize = 100;

/// Domain prefix length in bytes
pub const DOMAIN_PREFIX_LENGTH: usize = 8;

// ============================================================================
// Account Size Constants
// ============================================================================

/// Base size of AgentPolicy account (without variable-length fields)
pub const AGENT_POLICY_BASE_SIZE: usize = 8 + // discriminator
    32 + // owner
    32 + // agent_signer  
    8 +  // daily_limit
    1 +  // privacy_level discriminator
    33 + // optional auditor pubkey
    1 +  // whitelist_mode discriminator
    1 +  // bump
    4;   // rolling_window vec length prefix

/// Size per SpendingEntry
pub const SPENDING_ENTRY_SIZE: usize = 8 + 8; // amount + timestamp

/// Maximum AgentPolicy account size
pub const MAX_AGENT_POLICY_SIZE: usize = AGENT_POLICY_BASE_SIZE + 
    (MAX_ROLLING_WINDOW_ENTRIES * SPENDING_ENTRY_SIZE) +
    BLOOM_FILTER_SIZE_BYTES + // max whitelist data size
    256; // buffer for future extensions

/// Agent registry entry size
pub const AGENT_REGISTRY_SIZE: usize = 8 + // discriminator
    32 + // agent_id
    256 + // endpoint (max 256 bytes)
    4 + (10 * 512) + // capabilities vec (max 10, 512 bytes each)
    32 + // price_oracle
    32 + // reputation_pda
    8;   // last_updated

/// Escrow account size
pub const ESCROW_ACCOUNT_SIZE: usize = 8 + // discriminator
    32 + // buyer
    32 + // seller
    33 + // optional arbiter
    8 +  // amount
    32 + // memo_hash
    1 +  // state
    8 +  // timeout
    8;   // created_at

/// Reputation account size
pub const REPUTATION_ACCOUNT_SIZE: usize = 8 + // discriminator
    32 + // agent_id
    8 +  // total_transactions
    8 +  // successful_transactions
    8 +  // disputed_transactions
    8 +  // resolved_in_favor
    4 +  // average_response_time_ms
    8;   // last_updated

// ============================================================================
// PDA Seeds
// ============================================================================

/// Seed prefix for AgentPolicy PDA
pub const AGENT_POLICY_SEED: &[u8] = b"agent_policy";

/// Seed prefix for Escrow PDA
pub const ESCROW_SEED: &[u8] = b"escrow";

/// Seed prefix for Registry PDA
pub const REGISTRY_SEED: &[u8] = b"registry";

/// Seed prefix for Reputation PDA
pub const REPUTATION_SEED: &[u8] = b"reputation";

/// Seed prefix for Protocol Config PDA
pub const PROTOCOL_CONFIG_SEED: &[u8] = b"protocol_config";

/// Seed prefix for Treasury PDA
pub const TREASURY_SEED: &[u8] = b"treasury";

// ============================================================================
// Compute Unit Estimates
// ============================================================================

/// Estimated CU for public transfer validation
pub const CU_PUBLIC_TRANSFER: u32 = 3_400;

/// Estimated CU for confidential transfer validation
pub const CU_CONFIDENTIAL_TRANSFER: u32 = 50_300;

/// Estimated CU for escrow creation
pub const CU_ESCROW_CREATION: u32 = 2_800;

/// Estimated CU for policy update
pub const CU_POLICY_UPDATE: u32 = 1_500;

/// Estimated CU for Merkle proof verification
pub const CU_MERKLE_VERIFY: u32 = 2_000;

/// Estimated CU for Bloom filter verification
pub const CU_BLOOM_VERIFY: u32 = 800;

/// Estimated CU for Domain prefix verification
pub const CU_DOMAIN_VERIFY: u32 = 400;

// ============================================================================
// Reputation System
// ============================================================================

/// Reputation score weights
pub const REPUTATION_SUCCESS_WEIGHT: f64 = 0.7;
pub const REPUTATION_RESOLUTION_WEIGHT: f64 = 0.2;
pub const REPUTATION_DISPUTE_WEIGHT: f64 = 0.1;

/// Monthly reputation decay rate (1%)
pub const REPUTATION_DECAY_RATE_BPS: u16 = 100;

/// Minimum transactions for reliable reputation score
/// MEDIUM-9: Used to determine if agent has established reputation
pub const MIN_TRANSACTIONS_FOR_REPUTATION: u64 = 10;

// ============================================================================
// Registry Configuration
// ============================================================================

/// Registry listing fee in lamports (0.1 SOL)
pub const REGISTRY_LISTING_FEE_LAMPORTS: u64 = 100_000_000;

/// Maximum endpoint URL length
pub const MAX_ENDPOINT_LENGTH: usize = 256;

/// Maximum capabilities per agent
pub const MAX_CAPABILITIES_PER_AGENT: usize = 10;

/// Maximum capability metadata length
pub const MAX_CAPABILITY_METADATA_LENGTH: usize = 256;

/// Maximum capability type length
pub const MAX_CAPABILITY_TYPE_LENGTH: usize = 64;

/// Registry entry TTL in seconds (5 minutes for cache)
pub const REGISTRY_TTL_SECONDS: u64 = 300;

// ============================================================================
// x0-USD Wrapper Configuration
// ============================================================================

/// Seed prefix for Wrapper Config PDA
pub const WRAPPER_CONFIG_SEED: &[u8] = b"wrapper_config";

/// Seed prefix for Wrapper Stats PDA  
pub const WRAPPER_STATS_SEED: &[u8] = b"wrapper_stats";

/// Seed prefix for Reserve (USDC) PDA
pub const WRAPPER_RESERVE_SEED: &[u8] = b"reserve";

/// Seed prefix for Wrapper Mint authority PDA
pub const WRAPPER_MINT_AUTHORITY_SEED: &[u8] = b"mint_authority";

/// Seed prefix for Admin Action (timelock) PDA
pub const ADMIN_ACTION_SEED: &[u8] = b"admin_action";

/// Redemption fee in basis points (0.8% = 80 bps)
pub const WRAPPER_REDEMPTION_FEE_BPS: u16 = 80;

/// Minimum redemption fee (10 bps = 0.1%)
pub const MIN_WRAPPER_FEE_BPS: u16 = 10;

/// Maximum redemption fee (500 bps = 5%)
pub const MAX_WRAPPER_FEE_BPS: u16 = 500;

/// Maximum redemption per transaction (100,000 USDC with 6 decimals)
pub const MAX_REDEMPTION_PER_TX: u64 = 100_000_000_000;

/// Maximum daily redemptions (1,000,000 USDC with 6 decimals)
pub const MAX_DAILY_REDEMPTIONS: u64 = 1_000_000_000_000;

/// Minimum reserve ratio scaled by 10000 (1.0 = 10000, 1.01 = 10100)
pub const MIN_RESERVE_RATIO_SCALED: u64 = 10_000;

/// Warning threshold for reserve ratio (1.01)
pub const RESERVE_WARNING_THRESHOLD: u64 = 10_100;

/// Timelock duration for admin operations (48 hours in seconds)
pub const ADMIN_TIMELOCK_SECONDS: i64 = 172_800;

/// Minimum deposit amount (1 USDC with 6 decimals)
pub const MIN_DEPOSIT_AMOUNT: u64 = 1_000_000;

/// Minimum redemption amount (1 USDC with 6 decimals)
pub const MIN_REDEMPTION_AMOUNT: u64 = 1_000_000;

/// Wrapper token decimals (must match USDC)
pub const WRAPPER_DECIMALS: u8 = 6;

/// Wrapper Config account size
pub const WRAPPER_CONFIG_SIZE: usize = 8 + // discriminator
    32 + // admin (multisig)
    32 + // pending_admin
    32 + // usdc_mint
    32 + // wrapper_mint
    32 + // reserve_account
    2 +  // redemption_fee_bps
    1 +  // is_paused
    1 +  // bump
    64;  // reserved

/// Wrapper Stats account size
pub const WRAPPER_STATS_SIZE: usize = 8 + // discriminator
    8 +  // reserve_usdc_balance
    8 +  // outstanding_wrapper_supply
    8 +  // total_deposits
    8 +  // total_redemptions
    8 +  // total_fees_collected
    8 +  // daily_redemption_volume
    8 +  // daily_redemption_reset_timestamp
    8 +  // last_updated
    1 +  // bump
    64;  // reserved

/// Admin Action account size
pub const ADMIN_ACTION_SIZE: usize = 8 + // discriminator
    1 +  // action_type
    8 +  // scheduled_timestamp
    8 +  // new_value (for fee changes etc)
    32 + // new_admin (for admin transfers)
    1 +  // executed
    1 +  // cancelled
    1 +  // bump
    32;  // reserved

// ============================================================================
// Confidential Transfer Configuration
// ============================================================================

/// Size of ElGamal public key (compressed Ristretto point)
pub const ELGAMAL_PUBKEY_SIZE: usize = 32;

/// Size of AES ciphertext for decryptable balance
/// This is the encrypted value that only the account owner can decrypt
pub const DECRYPTABLE_BALANCE_SIZE: usize = 36;

/// Size of ElGamal ciphertext (two compressed Ristretto points)
pub const ELGAMAL_CIPHERTEXT_SIZE: usize = 64;

/// Maximum deposit/transfer amount for confidential transfers
/// Token-2022 limits this to 2^48 - 1 for ZK proof efficiency
pub const MAX_CONFIDENTIAL_AMOUNT: u64 = (1u64 << 48) - 1;

/// Maximum pending balance credit counter
/// Limits how many incoming transfers before apply_pending_balance is required
pub const MAX_PENDING_BALANCE_CREDIT_COUNTER: u64 = 65536;

/// Seed prefix for Confidential Transfer proof context state
pub const CT_PROOF_CONTEXT_SEED: &[u8] = b"ct_proof";

/// Size of PubkeyValidityProof (for account configuration)
pub const PUBKEY_VALIDITY_PROOF_SIZE: usize = 64;

/// Size of ZeroCiphertextProof (for empty account verification)
pub const ZERO_CIPHERTEXT_PROOF_SIZE: usize = 96;

/// Size of WithdrawProof (for confidential withdrawal)
pub const WITHDRAW_PROOF_SIZE: usize = 160;

/// Size of TransferProof data (for confidential transfer)
/// Includes ciphertext validity and range proofs
pub const TRANSFER_PROOF_SIZE: usize = 288;

/// Confidential transfer account extension additional space
pub const CONFIDENTIAL_ACCOUNT_EXTENSION_SIZE: usize = 
    1 +  // approved
    ELGAMAL_PUBKEY_SIZE +  // elgamal_pubkey
    8 +  // pending_balance_lo
    8 +  // pending_balance_hi  
    8 +  // available_balance
    DECRYPTABLE_BALANCE_SIZE +  // decryptable_available_balance
    1 +  // allow_confidential_credits
    1 +  // allow_non_confidential_credits
    8 +  // pending_balance_credit_counter
    8 +  // maximum_pending_balance_credit_counter
    8 +  // expected_pending_balance_credit_counter
    8;   // actual_pending_balance_credit_counter
