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

/// Reputation score weights (used in calculate_score formula)
/// S = W_s * success_rate + W_r * resolution_rate + W_d * (1 - dispute_rate) + W_f * (1 - failure_rate)
pub const REPUTATION_SUCCESS_WEIGHT: f64 = 0.60;
pub const REPUTATION_RESOLUTION_WEIGHT: f64 = 0.15;
pub const REPUTATION_DISPUTE_WEIGHT: f64 = 0.10;
pub const REPUTATION_FAILURE_WEIGHT: f64 = 0.15;

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
    33 + // pending_admin (Option<Pubkey>)
    32 + // usdc_mint
    32 + // wrapper_mint
    32 + // reserve_account
    2 +  // redemption_fee_bps
    1 +  // is_paused
    32 + // bridge_program
    1 +  // bump
    32;  // reserved

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

// ============================================================================
// Cross-Chain Bridge Configuration (Base → Solana via Hyperlane + SP1)
// ============================================================================

/// keccak256("Locked(address,bytes32,uint256,uint256,bytes32)")
///
/// Event signature for the X0LockContract.Locked event on Base.
/// Used by verify_evm_proof to locate and validate the deposit event
/// in the ZK-proven receipt logs.
///
/// Solidity declaration:
///   event Locked(address indexed sender, bytes32 indexed solanaRecipient,
///                uint256 amount, uint256 nonce, bytes32 messageId)
///
/// Topics:  [0] = this hash, [1] = sender, [2] = solanaRecipient
/// Data:    abi.encode(amount, nonce, messageId)
pub const LOCKED_EVENT_SIGNATURE: [u8; 32] = [
    0x6e, 0xa4, 0xb3, 0xe5, 0xd5, 0xca, 0x80, 0xe1,
    0xec, 0x33, 0xaf, 0x6e, 0x82, 0x4b, 0x1d, 0x7f,
    0x59, 0x5b, 0x0b, 0x2f, 0x6d, 0x9d, 0x72, 0x42,
    0x22, 0xfc, 0xab, 0xd1, 0x8c, 0x36, 0xba, 0x15,
];

/// keccak256("Transfer(address,address,uint256)")
/// Standard ERC-20 Transfer event signature (used in tests)
pub const TRANSFER_EVENT_SIGNATURE: [u8; 32] = [
    0xdd, 0xf2, 0x52, 0xad, 0x1b, 0xe2, 0xc8, 0x9b,
    0x69, 0xc2, 0xb0, 0x68, 0xfc, 0x37, 0x8d, 0xaa,
    0x95, 0x2b, 0xa7, 0xf1, 0x63, 0xc4, 0xa1, 0x16,
    0x28, 0xf5, 0x5a, 0x4d, 0xf5, 0x23, 0xb3, 0xef,
];

/// x0-bridge program ID
pub const BRIDGE_PROGRAM_ID: Pubkey = pubkey!("4FuyKfQysHxcTeNJtz5rBzzS8kmjn2DdkgXH1Q7edXa7");

/// Seed prefix for BridgeConfig PDA
pub const BRIDGE_CONFIG_SEED: &[u8] = b"bridge_config";

/// Seed prefix for BridgeMessage PDA
pub const BRIDGE_MESSAGE_SEED: &[u8] = b"bridge_message";

/// Seed prefix for EVMProofContext PDA
pub const EVM_PROOF_CONTEXT_SEED: &[u8] = b"evm_proof";

/// Seed prefix for bridge USDC reserve PDA
pub const BRIDGE_RESERVE_SEED: &[u8] = b"bridge_reserve";

/// Seed prefix for bridge reserve authority PDA
pub const BRIDGE_RESERVE_AUTHORITY_SEED: &[u8] = b"bridge_reserve_authority";

/// Seed prefix for Hyperlane message recipient PDA (matches Hyperlane convention)
pub const HYPERLANE_MESSAGE_RECIPIENT_SEED: &[u8] = b"hyperlane_message_recipient";

/// Seed prefix for Hyperlane handle account metas
pub const HYPERLANE_HANDLE_ACCOUNT_METAS_SEED: &[u8] = b"handle_account_metas";

/// Seed prefix for bridge operator PDA
pub const BRIDGE_OPERATOR_SEED: &[u8] = b"bridge_operator";

/// Hyperlane domain ID for Base mainnet
pub const HYPERLANE_DOMAIN_BASE: u32 = 8453;

/// Hyperlane domain ID for Base Sepolia (testnet)
pub const HYPERLANE_DOMAIN_BASE_SEPOLIA: u32 = 84532;

/// Hyperlane domain ID for Solana mainnet
pub const HYPERLANE_DOMAIN_SOLANA: u32 = 1399811149;

/// Hyperlane domain ID for Solana devnet
pub const HYPERLANE_DOMAIN_SOLANA_DEVNET: u32 = 1399811150;

/// STARK proof validity window in seconds (10 minutes)
/// Accounts for: Hyperlane relay (~2-3 min) + SP1 proving (~1 min) + submission buffer
pub const BRIDGE_PROOF_VALIDITY_SECONDS: i64 = 600;

/// Maximum bridge transfer amount per transaction (100,000 USDC with 6 decimals)
pub const MAX_BRIDGE_AMOUNT_PER_TX: u64 = 100_000_000_000;

/// Minimum bridge transfer amount (10 USDC with 6 decimals)
/// Higher minimum than wrapper to account for cross-chain gas costs
pub const MIN_BRIDGE_AMOUNT: u64 = 10_000_000;

/// Maximum daily bridge inflow (5,000,000 USDC with 6 decimals)
pub const MAX_DAILY_BRIDGE_INFLOW: u64 = 5_000_000_000_000;

/// Maximum number of allowed EVM lock contracts
pub const MAX_ALLOWED_EVM_CONTRACTS: usize = 10;

/// Maximum number of supported Hyperlane domains
pub const MAX_SUPPORTED_DOMAINS: usize = 10;

/// Maximum number of event logs in a proof context
pub const MAX_EVENT_LOGS: usize = 10;

/// Maximum event data size in bytes
pub const MAX_EVENT_DATA_SIZE: usize = 256;

/// Maximum number of event topics
pub const MAX_EVENT_TOPICS: usize = 4;

/// EVM address size in bytes
pub const EVM_ADDRESS_SIZE: usize = 20;

/// EVM hash size in bytes
pub const EVM_HASH_SIZE: usize = 32;

/// Bridge message body maximum size (serialized proof data + metadata)
pub const MAX_BRIDGE_MESSAGE_BODY_SIZE: usize = 1024;

/// Estimated CU for STARK proof verification (SP1)
pub const CU_STARK_VERIFICATION: u32 = 500_000;

/// Estimated CU for bridge mint execution (CPI into x0-wrapper)
pub const CU_BRIDGE_MINT: u32 = 200_000;

/// BridgeConfig account size
pub const BRIDGE_CONFIG_SIZE: usize = 8 + // discriminator
    1 +  // version
    32 + // admin
    32 + // hyperlane_mailbox
    32 + // sp1_verifier
    32 + // wrapper_program
    32 + // wrapper_config
    32 + // usdc_mint
    32 + // wrapper_mint
    32 + // bridge_usdc_reserve
    1 +  // is_paused
    8 +  // total_bridged_in
    8 +  // total_bridged_out
    8 +  // nonce
    8 +  // daily_inflow_volume
    8 +  // daily_inflow_reset_timestamp
    1 + // allowed_evm_contracts_count
    (MAX_ALLOWED_EVM_CONTRACTS * EVM_ADDRESS_SIZE) + // allowed_evm_contracts (fixed array)
    1 + // supported_domains_count
    (MAX_SUPPORTED_DOMAINS * 4) + // supported_domains (fixed array)
    8 +  // admin_action_nonce
    1 +  // bump
    8 +  // bridge_out_nonce (outbound monotonic nonce)
    8 +  // daily_outflow_volume (rolling outbound rate limiting)
    8 +  // daily_outflow_reset_timestamp
    32;  // reserved (56 - 24 = 32 bytes remaining)

/// Circuit breaker threshold (100M USDC with 6 decimals)
/// If total_bridged_in exceeds this, bridge auto-pauses
pub const BRIDGE_CIRCUIT_BREAKER_THRESHOLD: u64 = 100_000_000_000_000;

// ============================================================================
// Outbound Bridge (Solana → Base) Constants
// ============================================================================

/// Seed prefix for BridgeOutMessage PDA
pub const BRIDGE_OUT_MESSAGE_SEED: &[u8] = b"bridge_out_message";

/// Maximum USDC that can be bridged out per transaction (same as inbound)
pub const MAX_BRIDGE_OUT_AMOUNT_PER_TX: u64 = MAX_BRIDGE_AMOUNT_PER_TX;

/// Minimum USDC that can be bridged out per transaction (same as inbound)
pub const MIN_BRIDGE_OUT_AMOUNT: u64 = MIN_BRIDGE_AMOUNT;

/// Maximum daily outflow volume (5M USDC with 6 decimals, matching inflow)
pub const MAX_DAILY_BRIDGE_OUTFLOW: u64 = 5_000_000_000_000;

/// Circuit breaker threshold for outbound (100M USDC with 6 decimals)
pub const BRIDGE_OUT_CIRCUIT_BREAKER_THRESHOLD: u64 = 100_000_000_000_000;

/// BridgeOutMessage account size
pub const BRIDGE_OUT_MESSAGE_SIZE: usize = 8 + // discriminator
    1 +  // version
    8 +  // nonce (monotonic bridge_out_nonce from BridgeConfig)
    32 + // solana_sender
    20 + // evm_recipient (Base address)
    8 +  // amount (USDC micro-units)
    32 + // burn_tx_signature (Solana tx sig)
    8 +  // burned_at timestamp
    1 +  // status (Burned / Unlocked / Failed)
    1 +  // bump
    32;  // reserved

/// Hyperlane PDA seed components (must match Hyperlane Sealevel programs)
pub const HYPERLANE_SEED: &[u8] = b"hyperlane";
pub const HYPERLANE_SEPARATOR: &[u8] = b"-";
pub const HYPERLANE_PROCESS_AUTHORITY: &[u8] = b"process_authority";

/// BridgeMessage account size
pub const BRIDGE_MESSAGE_SIZE: usize = 8 + // discriminator
    1 +  // version
    32 + // message_id (Hyperlane)
    4 +  // origin_domain
    32 + // sender (EVM address padded to 32)
    32 + // recipient (Solana pubkey)
    8 +  // amount
    8 +  // received_at
    1 +  // status
    32 + // evm_tx_hash
    8 +  // nonce
    1 +  // bump
    32;  // reserved

/// EVMProofContext account size
pub const EVM_PROOF_CONTEXT_SIZE: usize = 8 + // discriminator
    1 +  // version
    1 +  // proof_type
    1 +  // verified
    8 +  // verified_at
    32 + // block_hash
    8 +  // block_number
    32 + // tx_hash
    20 + // from (EVM address)
    20 + // to (EVM address)
    8 +  // value
    4 + (MAX_EVENT_LOGS * (20 + 4 + (MAX_EVENT_TOPICS * 32) + 4 + MAX_EVENT_DATA_SIZE)) + // event_logs
    32 + // message_id (links to BridgeMessage)
    1 +  // bump
    32;  // reserved

// ============================================================================
// Bridge Admin Timelock Configuration
// ============================================================================

/// Seed prefix for BridgeAdminAction PDA
pub const BRIDGE_ADMIN_ACTION_SEED: &[u8] = b"bridge_admin_action";

/// Timelock duration for bridge admin operations (48 hours in seconds)
pub const BRIDGE_ADMIN_TIMELOCK_SECONDS: i64 = 172_800;

/// BridgeAdminAction account size
pub const BRIDGE_ADMIN_ACTION_SIZE: usize = 8 + // discriminator
    8 +  // nonce
    1 +  // action_type
    8 +  // scheduled_at
    20 + // evm_contract
    4 +  // domain
    32 + // new_address
    32 + // scheduled_by
    1 +  // executed
    1 +  // cancelled
    1 +  // bump
    32;  // reserved
