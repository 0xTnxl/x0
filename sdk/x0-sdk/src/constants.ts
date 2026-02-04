/**
 * Protocol constants matching on-chain values
 */

import { PublicKey } from "@solana/web3.js";
import BN from "bn.js";

// ============================================================================
// Program IDs (matching deployed devnet programs)
// ============================================================================

export const X0_GUARD_PROGRAM_ID = new PublicKey(
  "2uYGW3fQUGfhrwVbkupdasXBpRPfGYBGTLUdaPTXU9vP"
);

export const X0_TOKEN_PROGRAM_ID = new PublicKey(
  "EHHTCSyGkmnsBhGsvCmLzKgcSxtsN31ScrfiwcCbjHci"
);

export const X0_REGISTRY_PROGRAM_ID = new PublicKey(
  "Bebty49EPhFoANKDw7TqLQ2bX61ackNav5iNkj36eVJo"
);

export const X0_ESCROW_PROGRAM_ID = new PublicKey(
  "AhaDyVm8LBxpUwFdArA37LnHvNx6cNWe3KAiy8zGqhHF"
);

export const X0_REPUTATION_PROGRAM_ID = new PublicKey(
  "FfzkTWRGAJQPDePbujZdEhKHqC1UpqvDrpv4TEiWpx6y"
);

export const X0_WRAPPER_PROGRAM_ID = new PublicKey(
  "EomiXBbg94Smu4ipDoJtuguazcd1KjLFDFJt2fCabvJ8"
);

// ============================================================================
// Protocol Configuration
// ============================================================================

/** Protocol version string */
export const PROTOCOL_VERSION = "2.0";

/** Protocol name for x402 headers */
export const PROTOCOL_NAME = "x0-01";

/** Network identifiers */
export const NETWORKS = {
  MAINNET: "solana-mainnet",
  DEVNET: "solana-devnet",
  LOCALNET: "solana-localnet",
} as const;

// ============================================================================
// Fee Configuration
// ============================================================================

/** Protocol fee in basis points (0.8% = 80 bps) */
export const PROTOCOL_FEE_BASIS_POINTS = 80;

/** Fee denominator for basis points calculation */
export const FEE_DENOMINATOR = 10_000;

// ============================================================================
// Time Constants
// ============================================================================

/** Seconds in a 24-hour rolling window */
export const ROLLING_WINDOW_SECONDS = 86_400;

/** Maximum entries in the rolling window */
export const MAX_ROLLING_WINDOW_ENTRIES = 144;

/** Blink expiration time in seconds (15 minutes) */
export const BLINK_EXPIRY_SECONDS = 900;

/** Default escrow timeout in seconds (72 hours) */
export const DEFAULT_ESCROW_TIMEOUT_SECONDS = 259_200;

/** Minimum escrow timeout (1 hour) */
export const MIN_ESCROW_TIMEOUT_SECONDS = 3_600;

/** Maximum escrow timeout (30 days) */
export const MAX_ESCROW_TIMEOUT_SECONDS = 2_592_000;

// ============================================================================
// Rate Limiting
// ============================================================================

/** Maximum Blinks per hour per agent */
export const MAX_BLINKS_PER_HOUR = 3;

/** Cost in lamports to generate a Blink (0.001 SOL) */
export const BLINK_GENERATION_COST_LAMPORTS = new BN(1_000_000);

// ============================================================================
// Policy Limits
// ============================================================================

/** Maximum daily limit in token micro-units (1M tokens with 6 decimals) */
export const MAX_DAILY_LIMIT = new BN("1000000000000");

/** Minimum daily limit (1 token with 6 decimals) */
export const MIN_DAILY_LIMIT = new BN(1_000_000);

/** Default daily limit for new policies (100K with 6 decimals) */
export const DEFAULT_DAILY_LIMIT = new BN("100000000000");

// ============================================================================
// Whitelist Configuration
// ============================================================================

/** Bloom filter size in bytes (4KB) */
export const BLOOM_FILTER_SIZE_BYTES = 4_096;

/** Number of hash functions for Bloom filter */
export const BLOOM_HASH_COUNT = 7;

/** Maximum domain prefixes for Domain whitelist mode */
export const MAX_DOMAIN_PREFIXES = 100;

/** Domain prefix length in bytes */
export const DOMAIN_PREFIX_LENGTH = 8;

// ============================================================================
// PDA Seeds
// ============================================================================

export const PDA_SEEDS = {
  AGENT_POLICY: Buffer.from("agent_policy"),
  ESCROW: Buffer.from("escrow"),
  REGISTRY: Buffer.from("registry"),
  REPUTATION: Buffer.from("reputation"),
  PROTOCOL_CONFIG: Buffer.from("protocol_config"),
  TREASURY: Buffer.from("treasury"),
} as const;

// ============================================================================
// Registry Configuration
// ============================================================================

/** Registry listing fee in lamports (0.1 SOL) */
export const REGISTRY_LISTING_FEE_LAMPORTS = new BN(100_000_000);

/** Maximum endpoint URL length */
export const MAX_ENDPOINT_LENGTH = 256;

/** Maximum capabilities per agent */
export const MAX_CAPABILITIES_PER_AGENT = 10;

/** Maximum capabilities - alias for registry use */
export const MAX_CAPABILITIES = 10;

/** Maximum metadata size in bytes */
export const MAX_METADATA_SIZE = 1024;

// ============================================================================
// Escrow Configuration
// ============================================================================

/** Default auto-release delay in seconds (7 days) */
export const AUTO_RELEASE_DELAY_SECONDS = 604_800;

/** Default delivery timeout in seconds (72 hours) */
export const DELIVERY_TIMEOUT_SECONDS = 259_200;

// ============================================================================
// Reputation Configuration
// ============================================================================

/** Default reputation score for new agents (8500 = 85.00%) */
export const DEFAULT_REPUTATION_SCORE = 8500;

/** Reputation decay rate in basis points per period */
export const REPUTATION_DECAY_RATE_BPS = 100;

/** Reputation decay period in seconds (30 days) */
export const REPUTATION_DECAY_PERIOD_SECONDS = 2_592_000;

/** Minimum transactions for reliable reputation score */
export const MIN_TRANSACTIONS_FOR_REPUTATION = 10;

// ============================================================================
// Wrapper (x0-USD) Configuration
// ============================================================================

/** Wrapper config PDA seed */
export const WRAPPER_CONFIG_SEED = Buffer.from("wrapper_config");

/** Wrapper stats PDA seed */
export const WRAPPER_STATS_SEED = Buffer.from("wrapper_stats");

/** Wrapper reserve PDA seed */
export const WRAPPER_RESERVE_SEED = Buffer.from("reserve");

/** Wrapper mint authority PDA seed */
export const WRAPPER_MINT_AUTHORITY_SEED = Buffer.from("mint_authority");

/** Redemption fee in basis points (0.8% = 80 bps) */
export const WRAPPER_REDEMPTION_FEE_BPS = 80;

/** Minimum wrapper fee (10 bps = 0.1%) */
export const MIN_WRAPPER_FEE_BPS = 10;

/** Maximum wrapper fee (500 bps = 5%) */
export const MAX_WRAPPER_FEE_BPS = 500;

/** Maximum redemption per transaction (100,000 USDC) */
export const MAX_REDEMPTION_PER_TX = new BN("100000000000");

/** Maximum daily redemptions (1,000,000 USDC) */
export const MAX_DAILY_REDEMPTIONS = new BN("1000000000000");

/** Minimum reserve ratio scaled by 10000 (1.0 = 10000) */
export const MIN_RESERVE_RATIO_SCALED = 10000;

/** Admin timelock duration (48 hours in seconds) */
export const ADMIN_TIMELOCK_SECONDS = 172800;

/** Minimum deposit amount (1 USDC) */
export const MIN_DEPOSIT_AMOUNT = new BN(1_000_000);

/** Minimum redemption amount (1 USDC) */
export const MIN_REDEMPTION_AMOUNT = new BN(1_000_000);

/** Wrapper token decimals (must match USDC) */
export const WRAPPER_DECIMALS = 6;

// ============================================================================
// Confidential Transfer Configuration
// ============================================================================

// Note: MAX_CONFIDENTIAL_AMOUNT is exported from confidential.ts

/** Maximum pending balance credit counter */
export const MAX_PENDING_BALANCE_CREDIT_COUNTER = 65536;

/** Confidential transfer proof context seed */
export const CT_PROOF_CONTEXT_SEED = Buffer.from("ct_proof");

// ============================================================================
// Slot-Based Time Constants (for clock manipulation protection)
// ============================================================================

/** Approximate slots per second on Solana mainnet */
export const SLOTS_PER_SECOND = 2;

/** Slots in a 24-hour rolling window (~24 hours with buffer) */
export const ROLLING_WINDOW_SLOTS = 216000;

/** Arbiter dispute resolution delay in slots (~24 hours) */
export const ARBITER_RESOLUTION_DELAY_SLOTS = 216000;

/** Policy update cooldown in slots (~5 minutes) */
export const POLICY_UPDATE_COOLDOWN_SLOTS = 750;
