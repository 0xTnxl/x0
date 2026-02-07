/**
 * Type definitions for x0-01 protocol
 */

import { PublicKey } from "@solana/web3.js";
import BN from "bn.js";

// ============================================================================
// Whitelist Types
// ============================================================================

/** Whitelist verification mode */
export enum WhitelistMode {
  /** No whitelist - all recipients allowed */
  None = 0,
  /** Merkle tree verification with off-chain proof */
  Merkle = 1,
  /** Bloom filter probabilistic verification */
  Bloom = 2,
  /** Domain prefix matching for partner networks */
  Domain = 3,
}

/** Merkle whitelist configuration */
export interface MerkleWhitelistData {
  mode: WhitelistMode.Merkle;
  /** 32-byte Merkle root */
  root: Uint8Array;
}

/** Bloom filter whitelist configuration */
export interface BloomWhitelistData {
  mode: WhitelistMode.Bloom;
  /** Bloom filter bits */
  bits: Uint8Array;
  /** Number of hash functions */
  hashCount: number;
}

/** Domain prefix whitelist configuration */
export interface DomainWhitelistData {
  mode: WhitelistMode.Domain;
  /** List of allowed 8-byte address prefixes */
  allowedPrefixes: Uint8Array[];
}

/** No whitelist configuration */
export interface NoWhitelistData {
  mode: WhitelistMode.None;
}

/** Union type for all whitelist configurations */
export type WhitelistData =
  | MerkleWhitelistData
  | BloomWhitelistData
  | DomainWhitelistData
  | NoWhitelistData;

/** Merkle proof for whitelist verification */
export interface MerkleProof {
  /** Sibling hashes from leaf to root */
  path: Uint8Array[];
}

// ============================================================================
// Privacy Types
// ============================================================================

/** Privacy level for transfers */
export enum PrivacyLevel {
  /** Standard SPL transfers with visible amounts */
  Public = 0,
  /** ZK-encrypted amounts using confidential transfers */
  Confidential = 1,
}

/** Confidential privacy configuration */
export interface ConfidentialPrivacy {
  level: PrivacyLevel.Confidential;
  /** Optional auditor who can decrypt amounts */
  auditor?: PublicKey;
}

/** Public privacy configuration */
export interface PublicPrivacy {
  level: PrivacyLevel.Public;
}

/** Union type for privacy configurations */
export type PrivacyConfig = ConfidentialPrivacy | PublicPrivacy;

// ============================================================================
// Policy Types
// ============================================================================

/** Agent policy configuration (for creating/updating) */
export interface AgentPolicyConfig {
  /** Human owner's cold wallet address */
  owner: PublicKey;
  /** Agent's hot-key for signing transactions */
  agentSigner: PublicKey;
  /** Maximum tokens spendable in 24h rolling window */
  dailyLimit: BN;
  /** Maximum tokens spendable in 24h (alias for dailyLimit) */
  spendLimit?: BN;
  /** Maximum single transaction amount */
  txLimit?: BN;
  /** Whitelist configuration */
  whitelist: WhitelistData;
  /** Privacy level configuration */
  privacy: PrivacyConfig;
  /** Privacy level (numeric, for direct use) */
  privacyLevel?: PrivacyLevel;
  /** Whitelist mode (numeric, for direct use) */
  whitelistMode?: WhitelistMode;
  /** Whitelist data bytes (raw) */
  whitelistData?: Uint8Array;
  /** Optional auditor key for compliance */
  auditorKey?: PublicKey;
}

/** Full agent policy account data (on-chain state) */
export interface AgentPolicyAccount {
  /** Human owner's cold wallet address */
  owner: PublicKey;
  /** Agent's hot-key for signing transactions */
  agentSigner: PublicKey;
  /** Maximum tokens spendable in 24h rolling window */
  dailyLimit: BN;
  /** Alias: Maximum tokens spendable (for policy.ts compatibility) */
  spendLimit?: BN;
  /** Alias: Maximum single transaction amount */
  txLimit?: BN;
  /** Maximum single transaction amount */
  maxSingleTransaction: BN | null;
  /** Total spent in current rolling window */
  currentSpend: BN;
  /** Rolling spend amount (alias for currentSpend) */
  rollingSpend?: BN;
  /** Window start timestamp (for rolling window calculations) */
  windowStart?: number;
  /** Privacy level */
  privacyLevel: PrivacyLevel;
  /** Whitelist mode */
  whitelistMode: WhitelistMode;
  /** Whitelist data bytes */
  whitelistData: Uint8Array;
  /** Whether the policy is active */
  isActive: boolean;
  /** Whether delegation is required */
  requireDelegation: boolean;
  /** Bound token account (if any) */
  boundTokenAccount: PublicKey | null;
  /** Rolling window entries */
  rollingWindow: SpendingEntry[];
  /** Last update timestamp */
  lastUpdated: number;
  /** PDA bump seed */
  bump: number;
}

/** Spending entry in the rolling window */
export interface SpendingEntry {
  /** Amount spent in token micro-units */
  amount: BN;
  /** Unix timestamp when the spend occurred */
  timestamp: number;
}

/** Current spending statistics */
export interface SpendingStats {
  /** Total spent in current 24h window */
  totalSpent24h: BN;
  /** Number of transactions in window */
  transactionCount: number;
  /** Remaining allowance */
  remainingAllowance: BN;
  /** Timestamp when oldest entry expires */
  oldestEntryExpiry: number;
}

// ============================================================================
// Escrow Types
// ============================================================================

/** Escrow state (numeric for on-chain matching) */
export enum EscrowState {
  /** Escrow created but not yet funded */
  Created = 0,
  /** Buyer has deposited funds */
  Funded = 1,
  /** Seller claims delivery is complete */
  Delivered = 2,
  /** Either party has initiated a dispute */
  Disputed = 3,
  /** Funds released to seller (terminal) */
  Released = 4,
  /** Funds returned to buyer (terminal) */
  Refunded = 5,
  /** Cancelled before funding (terminal) */
  Cancelled = 6,
}

/** Escrow configuration */
export interface EscrowConfig {
  /** Buyer address */
  buyer: PublicKey;
  /** Seller address */
  seller: PublicKey;
  /** Optional arbiter for disputes */
  arbiter?: PublicKey;
  /** Amount to escrow */
  amount: BN;
  /** SHA256 hash of expected service/deliverable */
  memoHash: Uint8Array;
  /** Timeout in seconds */
  timeoutSeconds: number;
}

/** Escrow account data */
export interface EscrowAccount {
  /** Account version for future migrations */
  version: number;
  /** Buyer address */
  buyer: PublicKey;
  /** Seller address */
  seller: PublicKey;
  /** Optional arbiter */
  arbiter?: PublicKey;
  /** Amount held */
  amount: BN;
  /** Service memo hash */
  memoHash: Uint8Array;
  /** Current state */
  state: EscrowState;
  /** Timeout timestamp */
  timeout: number;
  /** Creation timestamp */
  createdAt: number;
  /** Delivery proof hash */
  deliveryProof?: Uint8Array;
  /** Dispute evidence hash */
  disputeEvidence?: Uint8Array;
  /** Token mint */
  mint: PublicKey;
  /** Token decimals */
  tokenDecimals: number;
  /** Slot when dispute was initiated (for arbiter delay) */
  disputeInitiatedSlot: number;
  /** PDA bump */
  bump: number;
}

/** Parameters for creating an escrow */
export interface CreateEscrowParams {
  /** Buyer address */
  buyer: PublicKey;
  /** Seller address */
  seller: PublicKey;
  /** Optional arbiter for disputes */
  arbiter?: PublicKey;
  /** Amount to escrow */
  amount: BN;
  /** Service description memo */
  memo: string;
  /** Service memo (alias for memo, for compatibility) */
  serviceMemo?: string;
  /** Timeout in seconds (maps to on-chain timeout_seconds) */
  timeoutSeconds?: number;
  /** @deprecated Use timeoutSeconds instead */
  deliveryTimeout?: number;
  /** Token mint */
  mint: PublicKey;
}

/** Escrow parameters for x402 */
export interface EscrowParams {
  /** Whether to use escrow for this payment */
  useEscrow: boolean;
  /** Arbiter for disputes */
  arbiter?: PublicKey;
  /** Auto-release delay in seconds */
  autoReleaseDelay?: number;
  /** Delivery timeout in seconds */
  deliveryTimeout?: number;
}

// ============================================================================
// Registry Types
// ============================================================================

/** Capability offered by an agent */
export interface Capability {
  /** Type of capability (e.g., "llm-inference") */
  type: string;
  /** Alias: Type of capability (for registry.ts compatibility) */
  capType?: string;
  /** JSON metadata blob with details (models, pricing, rates, etc.) */
  metadata: string;
}

/** Registry entry (alias for consistency) */
export interface AgentRegistryEntry {
  /** Agent's policy PDA */
  agentId: PublicKey;
  /** Owner address (optional) */
  owner?: PublicKey;
  /** Service endpoint URL */
  endpoint: string;
  /** List of capabilities */
  capabilities: Capability[];
  /** Reputation PDA */
  reputationPda: PublicKey;
  /** Last update timestamp */
  lastUpdated: number;
  /** Whether entry is active */
  isActive: boolean;
}

/** Registry entry */
export type RegistryEntry = AgentRegistryEntry;

/** Parameters for registering an agent */
export interface RegisterAgentParams {
  /** Agent policy ID */
  agentPolicyId: PublicKey;
  /** Owner address (optional, inferred from wallet) */
  owner?: PublicKey;
  /** Service endpoint URL */
  endpoint: string;
  /** List of capabilities */
  capabilities: Capability[];
  /** Metadata JSON */
  metadata?: string;
  /** Alias: Metadata JSON string */
  metadataJson?: string;
}

// ============================================================================
// Reputation Types
// ============================================================================

/** Reputation account data (alias for consistency) */
export interface AgentReputationAccount {
  /** Account version (1 = original, 2 = with failed_transactions) */
  version: number;
  /** Agent's policy PDA */
  agentId: PublicKey;
  /** Total completed transactions */
  totalTransactions: BN;
  /** Successful (undisputed) transactions */
  successfulTransactions: BN;
  /** Disputed transactions */
  disputedTransactions: BN;
  /** Disputes resolved in favor */
  resolvedInFavor: BN;
  /** Failed transactions (policy rejections) */
  failedTransactions: BN;
  /** Average response time in ms */
  averageResponseTimeMs: number;
  /** Last update timestamp */
  lastUpdated: number;
  /** Last activity timestamp */
  lastActivityAt?: number;
  /** Last decay applied timestamp */
  lastDecayAt?: number;
  /** Total volume transacted */
  totalVolume?: BN;
  /** Cumulative response time for average calculation */
  cumulativeResponseTimeMs: BN;
  /** PDA bump */
  bump: number;
}

/** Reputation account data */
export type ReputationAccount = AgentReputationAccount;

/** Reputation snapshot for history */
export interface ReputationSnapshot {
  /** Timestamp */
  timestamp: number;
  /** Score at this point */
  score: number;
  /** Total transactions at this point */
  totalTransactions: number;
  /** Success rate */
  successRate: number;
}

/** Calculated reputation score */
export interface ReputationScore {
  /** Score from 0.0 to 1.0 */
  score: number;
  /** Whether score is reliable (enough transactions) */
  isReliable: boolean;
  /** Component breakdown */
  components: {
    successRate: number;
    resolutionRate: number;
    disputeRate: number;
  };
}

// ============================================================================
// x402 Types
// ============================================================================

/** x402 Payment Request (from 402 response header) */
export interface X402PaymentRequest {
  /** Protocol identifier */
  protocol: string;
  /** Protocol version */
  version: string;
  /** Token mint address */
  mint: string;
  /** Amount in micro-units */
  amount: string;
  /** Recipient address */
  recipient: string;
  /** SHA256 hash of resource identifier */
  memoHash: string;
  /** Solana network */
  network: string;
  /** Challenge nonce */
  challenge: string;
  /** Expiration timestamp */
  expiresAt: number;
  /** Escrow parameters (optional) */
  escrow?: EscrowParams;
}

/** x402 response header */
export interface X402Header {
  /** The full X-Payment-Required header value */
  raw: string;
  /** Parsed payment request */
  request: X402PaymentRequest;
}

/** Payment receipt after successful payment */
export interface PaymentReceipt {
  /** Transaction signature */
  signature: string;
  /** Amount paid */
  amount: string;
  /** Recipient address */
  recipient: string;
  /** Memo hash */
  memoHash: string;
  /** Block time */
  blockTime: number;
  /** Slot */
  slot: number;
  /** Whether escrow was used */
  usedEscrow: boolean;
  /** Escrow address if used */
  escrowAddress?: string;
}

/** x402 Error codes */
export enum X402ErrorCode {
  /** Service requires payment */
  PaymentRequired = 402,
  /** Wrong amount/recipient */
  PaymentMismatch = 409,
  /** Challenge nonce expired */
  PaymentExpired = 410,
  /** Agent balance too low */
  InsufficientFunds = "402.1",
  /** Daily limit reached */
  LimitExceeded = "402.2",
  /** Recipient not whitelisted */
  NotWhitelisted = "402.3",
}

// ============================================================================
// Blink Types
// ============================================================================

/** Blink parameter for actions */
export interface BlinkParameter {
  /** Parameter name */
  name: string;
  /** Parameter type */
  type: "text" | "number" | "signature" | "pubkey";
  /** Whether required */
  required: boolean;
  /** Description */
  description: string;
  /** Optional label for display */
  label?: string;
}

/** Blink action type */
export interface BlinkAction {
  /** Button label */
  label: string;
  /** Action type identifier */
  type: string;
  /** Action URL (optional, for API-based actions) */
  href?: string;
  /** Action parameters */
  parameters: BlinkParameter[];
}

/** Blink metadata - flexible structure for different blink types */
export interface BlinkMetadata {
  /** Agent policy PDA (for transfer approvals) */
  agentId?: string;
  /** Policy ID */
  policyId?: string;
  /** Owner address */
  owner?: string;
  /** Current 24h spend (formatted) */
  currentSpend24h?: string;
  /** Requested amount (formatted) */
  requestedAmount?: string;
  /** Amount as string */
  amount?: string;
  /** Recipient address */
  recipient?: string;
  /** Reason for request */
  reason?: string;
  /** Memo */
  memo?: string;
  /** Escrow ID (for escrow blinks) */
  escrowId?: string;
  /** Buyer address */
  buyer?: string;
  /** Seller address */
  seller?: string;
  /** Service memo */
  serviceMemo?: string;
  /** New daily limit (for policy updates) */
  newDailyLimit?: string;
  /** Policy changes (for policy update blinks) */
  changes?: Record<string, unknown>;
}

/** Complete Blink structure (Solana Action) */
export interface Blink {
  /** Unique blink identifier */
  id: string;
  /** Action type */
  type: string;
  /** Title for display */
  title: string;
  /** Description for user */
  description: string;
  /** Icon emoji or URL */
  icon: string;
  /** Display label (short) */
  label?: string;
  /** Whether disabled */
  disabled: boolean;
  /** Available actions */
  actions: BlinkAction[];
  /** Available actions (links format for compatibility) */
  links?: {
    actions: BlinkAction[];
  };
  /** Request metadata */
  metadata: BlinkMetadata;
  /** Expiration timestamp */
  expiresAt: number;
  /** Creation timestamp */
  createdAt: number;
}

/** Solana Actions API response format */
export interface SolanaActionsResponse {
  /** Icon URL */
  icon: string;
  /** Title */
  title: string;
  /** Description */
  description: string;
  /** Button label */
  label: string;
  /** Whether disabled */
  disabled: boolean;
  /** Error message if any */
  error?: { message: string };
  /** Links with actions */
  links?: {
    actions: {
      label: string;
      href: string;
      parameters?: {
        name: string;
        label: string;
        required: boolean;
      }[];
    }[];
  };
}

// ============================================================================
// Transaction Types
// ============================================================================

/** Transaction result */
export interface TransactionResult {
  /** Transaction signature */
  signature: string;
  /** Confirmation status */
  confirmed: boolean;
  /** Block time */
  blockTime?: number;
  /** Slot */
  slot: number;
}

/** Payment execution options */
export interface PaymentOptions {
  /** Skip preflight simulation */
  skipPreflight?: boolean;
  /** Commitment level */
  commitment?: "processed" | "confirmed" | "finalized";
  /** Maximum retries */
  maxRetries?: number;
}

/** Simulation result */
export interface SimulationResult {
  /** Whether simulation succeeded */
  success: boolean;
  /** Logs from simulation */
  logs: string[];
  /** Compute units consumed */
  unitsConsumed?: number;
  /** Error message if failed */
  error?: string;
}
