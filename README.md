# x0-01

On-chain settlement infrastructure for autonomous agent transactions.

## Problem Statement

Autonomous agents require financial transaction capabilities, but existing models present a binary choice: either grant unrestricted access to funds (dangerous) or require human approval for every transaction (defeats autonomy). Neither approach scales for real-world agent deployments.

## Solution

x0-01 implements a policy-enforced delegation layer using Token-2022 transfer hooks. Every token transfer routes through an on-chain guard that validates the transaction against owner-defined spending policies in real-time. Agents operate autonomously within boundaries; policy violations are rejected at the protocol level.

## x0-USD: The Standard Token for AI Agents

**x0-USD** is a 1:1 USDC-backed stablecoin designed specifically for AI agent transactions:

- **Deposit USDC → Receive x0-USD** (1:1 ratio, no fee)
- **Burn x0-USD → Receive USDC** (0.8% redemption fee)
- **Built-in Transfer Hook** → x0-guard validates ALL transfers
- **Token-2022 Extensions** → Future-proof with confidential transfers support

### Why x0-USD?

Instead of each business minting their own token, **x0-USD is THE standard token** that all AI agents interact with. Every x0-USD transfer is automatically validated by x0-guard's policy enforcement—no additional setup required.

```
User deposits USDC → x0-wrapper mints x0-USD → Agent spends x0-USD → x0-guard validates → Recipient receives x0-USD → Recipient redeems for USDC
```

## Architecture

```
                                 ┌──────────────────┐
                                 │   Human Owner    │
                                 │  (Cold Wallet)   │
                                 └────────┬─────────┘
                                          │ defines policy
                                          ▼
┌──────────────┐    signs     ┌──────────────────┐    CPI    ┌──────────────────┐
│    Agent     │─────────────▶│   Token-2022     │──────────▶│    x0-guard      │
│  (Hot Key)   │              │    Transfer      │           │  Transfer Hook   │
└──────────────┘              └──────────────────┘           └────────┬─────────┘
                                                                      │
                              ┌───────────────────────────────────────┘
                              │ validates:
                              │  - daily spending limit
                              │  - single transaction limit  
                              │  - whitelist membership
                              │  - privacy level compliance
                              │  - delegation verification
                              ▼
                    ┌──────────────────┐
                    │  Accept/Reject   │
                    └──────────────────┘
```

## Programs

Six Solana programs deployed on devnet:

| Program | Address | Purpose |
|---------|---------|---------|
| x0-guard | `2uYGW3fQUGfhrwVbkupdasXBpRPfGYBGTLUdaPTXU9vP` | Transfer hook for policy enforcement |
| x0-token | `EHHTCSyGkmnsBhGsvCmLzKgcSxtsN31ScrfiwcCbjHci` | Token-2022 mint with extensions |
| x0-escrow | `AhaDyVm8LBxpUwFdArA37LnHvNx6cNWe3KAiy8zGqhHF` | Conditional payments with disputes |
| x0-registry | `Bebty49EPhFoANKDw7TqLQ2bX61ackNav5iNkj36eVJo` | Agent discovery service |
| x0-reputation | `FfzkTWRGAJQPDePbujZdEhKHqC1UpqvDrpv4TEiWpx6y` | Transaction-based trust scoring |
| x0-wrapper | `EomiXBbg94Smu4ipDoJtuguazcd1KjLFDFJt2fCabvJ8` | 1:1 USDC-backed wrapper token |

---

## x0-guard

On-chain firewall implementing the Transfer Hook interface. Invoked by Token-2022 for every transfer of x0-tokens.

### Policy Structure

```rust
pub struct AgentPolicy {
    pub owner: Pubkey,                           // Human cold wallet (full authority)
    pub agent_signer: Pubkey,                    // Agent hot key (delegated signer)
    pub daily_limit: u64,                        // Max spend per 24h rolling window
    pub max_single_transaction: Option<u64>,     // Per-transaction cap
    pub rolling_window: Vec<SpendingEntry>,      // Recent transactions for limit calc
    pub privacy_level: PrivacyLevel,             // Public or Confidential
    pub whitelist_mode: WhitelistMode,           // None, Merkle, Bloom, or Domain
    pub whitelist_data: WhitelistData,           // Mode-specific whitelist storage
    pub is_active: bool,                         // Owner pause switch
    pub require_delegation: bool,                // Prevents self-delegation bypass
    pub bound_token_account: Option<Pubkey>,     // Optional account binding
}
```

### Whitelist Modes

**Merkle**: Exact address verification. Off-chain proof required per transaction. Supports up to 10,000 addresses with 14-level proof depth. Best for static, known recipient sets.

**Bloom**: Probabilistic verification with 1% false positive rate. 4KB filter supporting ~1,000 addresses. No per-transaction proof required. Best for dynamic whitelists where occasional false positives are acceptable.

**Domain**: 8-byte address prefix matching. Allows entire program-derived address spaces. Best for partner network integrations.

### Validation Flow

```rust
fn validate_transfer(ctx: Context<ValidateTransfer>, amount: u64, merkle_proof: Option<MerkleProof>) {
    // 1. Policy active check
    require!(policy.is_active, PolicyNotFound);
    
    // 2. Delegation verification - prevents bypass attacks
    require!(source_authority == policy.agent_signer, UnauthorizedSigner);
    require!(source_account.owner == policy.owner, TokenAccountOwnerMismatch);
    
    // 3. Account binding (if configured)
    if let Some(bound) = policy.bound_token_account {
        require!(source_account.key() == bound, InvalidTokenAccount);
    }
    
    // 4. Spending limits
    require!(amount >= MIN_TRANSFER_AMOUNT, TransferAmountTooSmall);
    if let Some(max_tx) = policy.max_single_transaction {
        require!(amount <= max_tx, SingleTransactionLimitExceeded);
    }
    require!(!policy.would_exceed_limit(amount, timestamp), DailyLimitExceeded);
    
    // 5. Whitelist verification
    require!(policy.whitelist_data.verify(&destination, merkle_proof.as_ref())?, RecipientNotWhitelisted);
    
    // 6. Privacy enforcement
    if matches!(policy.privacy_level, PrivacyLevel::Confidential { .. }) {
        // Verify confidential transfer proofs
    }
    
    // 7. Record spend
    check_and_update_limit(policy, amount, timestamp)?;
}
```

### Rate Limiting

- Policy updates: 750 slots (~5 minutes) cooldown between modifications
- Blink generation: 3 per hour per agent
- Rolling window: 144 entries (10-minute granularity over 24 hours)

---

## x0-token

Token-2022 mint configuration with three extensions:

### Transfer Hook Extension

Routes every transfer through x0-guard. Cannot be bypassed - enforcement happens at the token program level.

```rust
pub fn initialize_mint(ctx: Context<InitializeMint>, decimals: u8, enable_confidential: bool) {
    // Create mint with extensions
    let extensions = [
        ExtensionType::TransferHook,
        ExtensionType::TransferFeeConfig,
        ExtensionType::ConfidentialTransferMint, // if enabled
    ];
    
    // Configure transfer hook to point to x0-guard
    transfer_hook::initialize(
        &ctx.accounts.token_2022_program,
        &ctx.accounts.mint,
        Some(X0_GUARD_PROGRAM_ID),
        Some(X0_GUARD_PROGRAM_ID),
    )?;
    
    // Configure 0.8% transfer fee
    transfer_fee::initialize(
        &ctx.accounts.token_2022_program,
        &ctx.accounts.mint,
        Some(&fee_authority),
        Some(&withdraw_authority),
        PROTOCOL_FEE_BASIS_POINTS,
        MAX_TRANSFER_FEE,
    )?;
}
```

### Transfer Fee Extension

0.8% (80 basis points) protocol fee on every transfer. Fees accumulate in token accounts and are harvested to a treasury.

### Confidential Transfer Extension

Optional ZK-encrypted balances using ElGamal encryption. Transaction amounts are hidden on-chain but the x0-guard transfer hook still validates policy compliance through zero-knowledge proofs.

Account-level operations (configure, withdraw, apply_pending_balance) are executed directly via spl-token-2022. The guard validates transfers regardless of confidential mode.

---

## x0-escrow

Conditional payments with dispute resolution for high-value or risky transactions.

### State Machine

```
Created → Funded → Delivered → Released
    │         │         │
    │         │         └──▶ Disputed → Resolved
    │         │
    │         └──▶ Timeout → Refunded
    │
    └──▶ Cancelled
```

### Escrow Structure

```rust
pub struct EscrowAccount {
    pub buyer: Pubkey,                      // Payer
    pub seller: Pubkey,                     // Recipient
    pub arbiter: Option<Pubkey>,            // Third-party resolver
    pub amount: u64,                        // Escrowed tokens
    pub memo_hash: [u8; 32],                // SHA256 of expected deliverable
    pub state: EscrowState,                 // Current state
    pub timeout: i64,                       // Auto-refund timestamp
    pub delivery_proof: Option<[u8; 32]>,   // Seller's proof hash
    pub dispute_evidence: Option<[u8; 32]>, // Dispute evidence hash
    pub dispute_initiated_slot: u64,        // For arbiter delay
}
```

### Timeout Configuration

- Minimum: 1 hour
- Maximum: 30 days
- Default: 72 hours

### Arbiter Resolution Delay

216,000 slots (~24 hours) between dispute initiation and arbiter resolution. Prevents rushed malicious resolutions.

### Auto-Release

If seller marks delivery and buyer doesn't dispute within 72 hours, seller can claim via `claim_auto_release`.

---

## x0-registry

On-chain agent discovery service. Agents register endpoints and capabilities for service consumers to query.

### Registry Structure

```rust
pub struct AgentRegistry {
    pub agent_id: Pubkey,                   // Agent's identity
    pub endpoint: String,                   // Service URL (max 256 bytes)
    pub capabilities: Vec<Capability>,      // Offered services
    pub reputation_pda: Pubkey,             // Link to reputation account
    pub is_active: bool,                    // Availability flag
    pub last_updated: i64,                  // Timestamp
}

pub struct Capability {
    pub capability_type: CapabilityType,    // Enum of service types
    pub description: String,                // Human-readable description
    pub price: u64,                         // Price in micro-units
    pub version: String,                    // API version
}
```

### Capability Types

- TextGeneration
- ImageGeneration
- CodeExecution
- DataAnalysis
- WebSearch
- Custom(String)

---

## x0-reputation

Transaction-based trust scoring oracle.

### Reputation Structure

```rust
pub struct AgentReputation {
    pub agent_id: Pubkey,
    pub total_transactions: u64,
    pub successful_transactions: u64,
    pub disputed_transactions: u64,
    pub disputes_won: u64,
    pub total_volume: u128,                 // Cumulative transaction value
    pub avg_response_time_ms: u32,          // Rolling average
    pub last_decay_timestamp: i64,          // Monthly decay tracking
    pub score: u32,                         // Computed score (0-10000)
}
```

### Score Calculation

```
base_score = (successful / total) * 10000
dispute_penalty = disputed * 50 (capped at 2000)
favor_recovery = disputes_won * 25
decay = months_since_last_tx * 100 (capped at 1000)

final_score = max(0, base_score - dispute_penalty + favor_recovery - decay)
```

### Authorized Callers

Only x0-escrow can update reputation metrics (via CPI). Prevents self-reporting.

---

## x0-wrapper

1:1 USDC-backed wrapper token (x0-USD) with protocol fee on redemption.

### Key Invariant

```
reserve_usdc_balance >= outstanding_x0_usd_supply
```

Enforced on every operation. Checked before any token transfer.

### Operations

**Deposit**: USDC in, x0-USD out at 1:1. No fee.

**Redeem**: x0-USD burned, USDC returned minus 0.8% fee.

### Admin Controls

All admin operations require 48-hour timelock:
- Fee rate changes
- Pause/unpause
- Emergency withdrawal

Emergency pause (immediate) available for critical situations.

### State

```rust
pub struct WrapperConfig {
    pub admin: Pubkey,
    pub pending_admin: Option<Pubkey>,
    pub usdc_mint: Pubkey,
    pub wrapper_mint: Pubkey,
    pub redemption_fee_bps: u16,
    pub is_paused: bool,
    pub total_deposited: u64,
    pub total_redeemed: u64,
    pub total_fees_collected: u64,
}
```

---

## SDK

TypeScript client for all protocol operations.

### Installation

```bash
npm install @x0-protocol/sdk
```

### Initialization

```typescript
import { X0Client } from "@x0-protocol/sdk";
import { Connection, Keypair } from "@solana/web3.js";

const connection = new Connection("https://api.devnet.solana.com");
const wallet = {
  publicKey: keypair.publicKey,
  signTransaction: async (tx) => {
    tx.sign(keypair);
    return tx;
  },
};

const client = new X0Client({
  connection,
  wallet,
  settlementMint: SETTLEMENT_MINT_ADDRESS,
});
```

### Policy Management

```typescript
// Create agent policy
const policy = await client.policy.create({
  agentSigner: agentKeypair.publicKey,
  dailyLimit: new BN(100_000_000), // 100 tokens (6 decimals)
  whitelist: {
    mode: WhitelistMode.Merkle,
    root: merkleRoot,
  },
  privacy: {
    level: PrivacyLevel.Public,
  },
});

// Update policy
await client.policy.update(policyPda, {
  dailyLimit: new BN(200_000_000),
});

// Pause policy (emergency)
await client.policy.setActive(policyPda, false);

// Revoke agent authority
await client.policy.revoke(policyPda);
```

### Escrow Operations

```typescript
// Create escrow
const escrow = await client.escrow.create({
  seller: sellerPubkey,
  amount: new BN(50_000_000),
  memoHash: sha256(serviceDescription),
  timeoutSeconds: 86400 * 3, // 3 days
  arbiter: arbiterPubkey, // optional
});

// Fund escrow
await client.escrow.fund(escrowPda);

// Mark delivered (seller)
await client.escrow.markDelivered(escrowPda, proofHash);

// Release funds (buyer confirms)
await client.escrow.release(escrowPda);

// Dispute (buyer)
await client.escrow.dispute(escrowPda, evidenceHash);

// Resolve (arbiter)
await client.escrow.resolve(escrowPda, releaseToSeller: true);
```

### x402 Protocol

HTTP 402 Payment Required responses for agent-to-agent payments.

```typescript
// Server side: Build 402 response
import { buildX402ResponseHeaders } from "@x0-protocol/sdk";

const headers = buildX402ResponseHeaders({
  recipient: serviceProviderPubkey,
  amount: new BN(1_000_000),
  resource: "/api/inference",
  escrow: {
    useEscrow: true,
    deliveryTimeout: 3600,
  },
});

// Return 402 with headers
response.status(402).set({
  "X-Accept-Payment": headers.raw,
});

// Client side: Parse and pay
import { parseX402FromResponse, fetchWithPayment } from "@x0-protocol/sdk";

const result = await fetchWithPayment(
  "https://agent.example.com/api/inference",
  { method: "POST", body: JSON.stringify(query) },
  client,
  agentKeypair
);
```

### Confidential Transfers

```typescript
import { ConfidentialClient } from "@x0-protocol/sdk";

const confidential = new ConfidentialClient(connection, wallet);

// Configure account for confidential transfers
await confidential.configureAccount(mint, tokenAccount, ownerKeypair);

// Deposit to confidential balance
await confidential.deposit(tokenAccount, mint, amount);

// Apply pending balance (makes received tokens spendable)
await confidential.applyPendingBalance(tokenAccount, ownerKeypair, mint);

// Withdraw from confidential to public balance
await confidential.withdraw(tokenAccount, mint, amount, ownerKeypair);
```

### Registry Operations

```typescript
// Register agent
await client.registry.register({
  endpoint: "https://agent.example.com",
  capabilities: [
    {
      type: CapabilityType.TextGeneration,
      description: "GPT-4 inference",
      price: 1_000_000,
      version: "1.0",
    },
  ],
});

// Query agents by capability
const agents = await client.registry.findByCapability(CapabilityType.TextGeneration);
```

### Wrapper Operations

```typescript
import { WrapperClient } from "@x0-protocol/sdk";

const wrapper = new WrapperClient(connection, wallet);

// Deposit USDC, receive x0-USD
await wrapper.deposit(usdcAmount);

// Redeem x0-USD for USDC (0.8% fee)
await wrapper.redeem(x0UsdAmount);
```

---

## Protocol Constants

```typescript
// Fees
PROTOCOL_FEE_BASIS_POINTS = 80           // 0.8%
FEE_DENOMINATOR = 10_000

// Time
ROLLING_WINDOW_SECONDS = 86_400          // 24 hours
BLINK_EXPIRY_SECONDS = 900               // 15 minutes
DEFAULT_ESCROW_TIMEOUT_SECONDS = 259_200 // 72 hours

// Limits
MAX_DAILY_LIMIT = 1_000_000_000_000      // 1M tokens
MIN_TRANSFER_AMOUNT = 100                // Dust prevention
MAX_BLINKS_PER_HOUR = 3
MAX_MERKLE_PROOF_DEPTH = 14
BLOOM_FILTER_SIZE_BYTES = 4_096

// Rate limiting
POLICY_UPDATE_COOLDOWN_SLOTS = 750       // ~5 minutes
ARBITER_RESOLUTION_DELAY_SLOTS = 216_000 // ~24 hours
```

---

## Development

### Prerequisites

- Rust 1.75+
- Solana CLI 1.18+
- Anchor 0.30.1
- Node.js 18+

### Build

```bash
# Programs
anchor build --no-idl

# SDK
cd sdk/x0-sdk && npm run build
```

### Test

```bash
# SDK type checking
cd sdk/x0-sdk && npx tsc --noEmit

# Rust checks
cargo check
cargo clippy
```

### Deploy

```bash
# Devnet
solana program deploy target/deploy/x0_guard.so --url devnet --program-id target/deploy/x0_guard-keypair.json

# All programs
anchor deploy --provider.cluster devnet
```

---

## Security Model

### Trust Assumptions

1. Token-2022 transfer hooks cannot be bypassed for configured mints
2. Solana clock is bounded within slots (not exact timestamps)
3. PDA derivation is deterministic and collision-resistant
4. Owner cold wallet is secure

### Attack Mitigations

**Delegation Bypass**: The guard verifies source_authority matches agent_signer AND token account owner matches policy owner. Self-delegation (owner = agent) is detectable via require_delegation flag.

**Clock Manipulation**: Critical timing uses slot-based checks with conservative buffers rather than raw timestamps.

**Reentrancy**: State mutations occur before CPIs. Check-effects-interactions pattern enforced.

**Overflow**: All arithmetic uses saturating/checked operations.

**Dust Attacks**: Minimum transfer amount enforced (100 micro-units).

**Governance Spam**: Policy updates rate-limited to 750 slots.

---

## License

Apache-2.0
