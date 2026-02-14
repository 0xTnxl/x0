# x0 Protocol — Solana Foundation Developer Tooling Grant Proposal

**Applicant:** Blessed Tosin-Oyinbo Olamide  
**Project:** x0 Protocol — Decentralized Payment Infrastructure for Autonomous Agents  
**Repository:** [github.com/0xtnxl/x0](https://github.com/0xtnxl/x0) (MIT License)  
**Requested Amount:** $75,000 USD  
**Date:** February 14, 2026

---

## 1. Overview of Ecosystem Impact

### How x0 Is a Public Good for Solana Developers

There is no production-ready, open-source payment infrastructure purpose-built for autonomous AI agents on Solana. Developers building agent-powered products today must cobble together raw SPL transfers, manual escrow logic, and ad-hoc trust systems — all without standardized spending controls, dispute resolution, or payment negotiation. This is the gap x0 fills.

**x0 is fully open-source, permissionless, and composable.** Any developer can integrate x0 into their agent framework, SaaS product, or DeFi protocol without permission, licensing, or vendor lock-in. The entire codebase — 16,500+ lines of Rust across 9 on-chain programs, 10,400+ lines of TypeScript SDK, and formal documentation — is MIT-licensed and publicly available.

### Specific Benefits to Solana Developers

1. **Drop-in agent payment SDK.** `@x0-protocol/sdk` provides a single `X0Client` entrypoint with typed methods for policy management, escrow, token wrapping, agent discovery, HTTP 402 negotiation, confidential transfers, and Blink generation. A developer can integrate agent payments in under 50 lines of TypeScript.

2. **Programmable spending policies without custom programs.** x0-guard uses Token-2022 transfer hooks to enforce per-agent spending limits, whitelist verification (Merkle, Bloom, or domain-prefix), and privacy controls. Developers get fine-grained agent delegation without writing or deploying their own on-chain programs — they configure policies through the SDK.

3. **Standardized payment negotiation (HTTP 402).** x0 implements the first production-ready HTTP 402 protocol on Solana. Any API can respond with a 402 status and an `X-Accept-Payment` header; agents automatically parse the payment request, execute on-chain settlement, and retry with cryptographic proof. This enables pay-per-call APIs, metered compute, and autonomous service procurement.

4. **Trustless escrow with dispute resolution.** x0-escrow provides a complete state machine (Created → Funded → Delivered → Released/Refunded/Disputed) with auto-release timeouts, third-party arbitration, and CPI-backed reputation updates. Developers building agent marketplaces, freelance platforms, or compute exchanges get escrow out of the box.

5. **On-chain reputation oracle.** x0-reputation provides a transparent, Sybil-resistant trust score for every agent address. The weighted formula (60% success rate, 15% dispute resolution, 10% dispute frequency, 15% failure rate) with 1% monthly decay gives developers a reliable signal for agent trustworthiness — usable in their own programs via CPI.

6. **Agent discovery registry.** x0-registry enables agents to advertise capabilities (e.g., "text-generation", "image-classification") with JSON metadata (pricing, versions, endpoints). Other agents or developer UIs can query by capability type, sorted by reputation. This is the missing "DNS for agents" on Solana.

7. **Privacy-preserving transfers.** x0 integrates Token-2022 confidential transfers with on-chain Groth16 proof verification (x0-zk-verifier) and client-side proof generation compiled to WebAssembly. Developers can offer encrypted-balance agent wallets without building ZK infrastructure from scratch.

8. **Composable via CPI.** Every x0 program exposes well-defined CPI interfaces. Third-party programs can invoke x0-reputation for trust checks, x0-guard for policy validation, or x0-wrapper for USDC-backed minting. x0 is infrastructure, not an application — it's designed to be built on.

### Why This Matters Now

The autonomous agent market is accelerating. Frameworks like AutoGPT, CrewAI, LangGraph, and Solana's own agent initiatives are proliferating — but none have standardized payment rails. Without infrastructure like x0, every agent framework will reinvent payment handling, fragmenting the ecosystem. x0 provides a single, audited, composable foundation that the entire Solana agent ecosystem can build on.

---

## 2. Product Design

### 2.1 Architecture

x0 is a modular protocol of 9 interoperating Solana programs, a shared library crate, a TypeScript SDK, and a WASM cryptographic module:

```
┌──────────────────────────────────────────────────────┐
│                External Dependencies                  │
│              USDC (SPL Token) · Token-2022            │
└──────────────┬────────────────────┬───────────────────┘
               │                    │
┌──────────────▼──────────┐ ┌──────▼───────────────────┐
│       x0-wrapper        │ │       x0-token           │
│  USDC ↔ x0-USD wrapping │ │  Mint with extensions    │
│  Reserve invariants      │ │  TransferHook + ConfTx   │
└──────────────┬──────────┘ └──────┬───────────────────┘
               │                    │ (hook CPI)
               │             ┌──────▼───────────────────┐
               │             │       x0-guard           │
               │             │  Policy enforcement       │
               │             │  Limits · Whitelists      │
               │             └──────┬───────────────────┘
               │                    │ (CPI)
┌──────────────▼──────────┐ ┌──────▼───────────────────┐
│       x0-escrow         │ │     x0-reputation        │
│  Conditional payments    │ │  Trust scoring oracle    │
│  Dispute resolution      │ │  Temporal decay          │
└─────────────────────────┘ └──────────────────────────┘
┌─────────────────────────┐ ┌──────────────────────────┐
│       x0-registry       │ │     x0-zk-verifier       │
│  Agent discovery         │ │  Groth16 on-chain verify │
└─────────────────────────┘ └──────────────────────────┘
┌──────────────────────────────────────────────────────┐
│                   x0-common (library)                 │
│      Constants · Error codes · Events · Types         │
└──────────────────────────────────────────────────────┘
┌──────────────────────────────────────────────────────┐
│             x0-zk-proofs (WASM, off-chain)            │
│        Client-side Groth16 proof generation           │
└──────────────────────────────────────────────────────┘
```

**CPI dependency graph:**
- x0-token → x0-guard (transfer hook)
- x0-guard → x0-reputation (trust-aware policy validation)
- x0-escrow → x0-reputation (success/dispute/resolution events)
- x0-wrapper → x0-token (mint/burn x0-USD)
- x0-zk-verifier ← x0-zk-proofs (client submits proofs)

### 2.2 Core Components

#### x0-guard (Policy Enforcement — 1,851 LOC Rust)

The central innovation. Token-2022's `TransferHook` interface calls x0-guard on every x0-USD transfer. The guard loads the sender's `AgentPolicy` PDA and validates:

- **Rolling 24-hour spend limit:** Sliding window of 144 entries (~10-min granularity). Max configurable limit: 1,000,000 tokens. Default: 100,000.
- **Whitelist verification:** Three modes — Merkle proof (up to 10,000 addresses, 14-level tree), Bloom filter (4KB, ~1% false positive rate for 1,000 addresses), or domain-prefix matching (8-byte address prefixes).
- **Privacy level enforcement:** Public, shielded (counter only), or confidential (ElGamal-encrypted balances).
- **Dust prevention:** Minimum transfer of 100 micro-units.
- **Cooldown enforcement:** 750-slot (~5-minute) cooldown between policy updates.

All validation happens atomically within the transfer instruction. Failed validation reverts the entire transfer.

#### x0-wrapper (USDC Wrapper — 2,362 LOC Rust)

Manages the 1:1 USDC-backed x0-USD stablecoin:

- **Deposit:** User sends USDC → receives equal x0-USD. Reserve increases, supply increases. Invariant preserved.
- **Redeem:** User burns x0-USD → receives USDC minus 0.8% fee (80 bps). Fee accumulates in reserve, strengthening the peg.
- **Reserve invariant:** `USDC_reserve ≥ x0USD_supply` — formally proven, enforced on every operation.
- **Governance:** All admin actions (fee changes, pause, emergency withdraw) require 48-hour timelock via PDA-based `AdminAction` accounts.

#### x0-escrow (Conditional Payments — 1,261 LOC Rust)

Full state machine: Created → Funded → Delivered → Released | Refunded | Disputed → Resolved.

- **Auto-release:** If buyer doesn't dispute within timeout (default 72 hours, configurable 1h–30d), seller can claim.
- **Arbiter resolution:** Neutral third-party resolves disputes after a 24-hour delay (216,000 slots).
- **Reputation integration:** Successful releases and dispute resolutions update x0-reputation via CPI.

#### x0-reputation (Trust Oracle — 1,051 LOC Rust)

Weighted scoring formula: `S = 0.60·success_rate + 0.15·resolution_rate + 0.10·(1-dispute_rate) + 0.15·(1-failure_rate)`

- **Sybil resistance:** New agents start at 0.5 (not 1.0), requiring 10+ transactions for a reliable score.
- **Temporal decay:** 1% monthly decay on success count (half-life ≈ 69 months).
- **Authorization:** Only x0-escrow and x0-guard can update metrics via CPI. No self-reporting.

#### x0-registry (Agent Discovery — 496 LOC Rust)

On-chain agent directory:

- Register with endpoint URL and up to 10 capabilities (JSON metadata: pricing, API version, rate limits).
- Listing fee: 0.1 SOL (Sybil deterrent).
- Queryable by capability type, sortable by reputation score.

#### x0-zk-verifier (ZK Verification — 774 LOC Rust)

On-chain Groth16 proof verification for confidential transfers over the Ristretto255 curve. Paired with x0-zk-proofs (WASM) for client-side proof generation.

#### x0-common (Shared Library — 3,504 LOC Rust)

Constants, error codes, event definitions, state types, Bloom/Merkle whitelist implementations. All programs share this crate to ensure type safety and consistency across the protocol.

### 2.3 SDK (`@x0-protocol/sdk`)

The TypeScript SDK (10,400+ LOC) wraps all program interactions into a clean developer API:

```typescript
import { X0Client } from "@x0-protocol/sdk";

const client = new X0Client(connection, wallet);

// Create a policy-enforced agent
await client.createPolicy(agentKey, {
  dailyLimit: 100_000,
  whitelistMode: "merkle",
  privacyLevel: "public",
});

// Wrap USDC into x0-USD
await client.deposit(1000_000000); // 1,000 USDC

// Create escrow for agent service
const escrow = await client.createEscrow({
  seller: serviceAgent,
  amount: 50_000000,
  timeout: 72 * 3600,
});

// HTTP 402 automatic payment
const response = await fetchWithPayment("https://api.agent.ai/generate", {
  client,
  body: { prompt: "..." },
});
```

**17 modules** covering: policy management, escrow lifecycle, wrapper operations, agent discovery, reputation queries, HTTP 402 protocol, Blink generation, confidential transfers, and ZK proof operations.

### 2.4 Technology Stack

| Layer | Technology |
|---|---|
| On-chain programs | Rust, Anchor 0.30.1 |
| Token standard | Solana Token-2022 (TransferHook, ConfidentialTransfer, TransferFee) |
| SDK | TypeScript, `@coral-xyz/anchor` 0.30.1, `@solana/web3.js` 1.95 |
| ZK proofs | Groth16 over Ristretto255, Rust → WASM (client-side) |
| Testing | Rust unit tests, TypeScript (ts-mocha), Solidity (Foundry) |
| Documentation | Mintlify (hosted docs), LaTeX (whitepaper) |

### 2.5 Proof of Concept

**x0 is not a concept — it is a working implementation.** The codebase is fully built:

- **16,500+ lines of Rust** across 9 Solana programs and 1 shared library
- **10,400+ lines of TypeScript** SDK with 17 modules
- **10 test files** (SDK unit tests, Rust tests, Solidity/Foundry tests)
- **7 programs deployed to devnet** (guard, token, escrow, registry, reputation, wrapper, zk-verifier)
- **Formal whitepaper** (55 pages, LaTeX) with security proofs, formal definitions, and empirical benchmarks
- **Hosted documentation** at x0protocol.dev (SDK guides, protocol reference, security analysis)

The grant is not for building x0 — it is for **auditing, hardening, documenting, and driving adoption** of a working protocol.

### 2.6 Cross-Chain Extension (FROSTGATE)

The protocol also includes an optional cross-chain bridge (FROSTGATE) for Base ↔ Solana trustless bridging using Hyperlane messaging and SP1 STARK proofs. FROSTGATE is architecturally independent from the core protocol — x0 operates fully on Solana without it. It is not part of this grant's scope.

---

## 3. Budget Breakdown (Milestones)

**Total Requested: $75,000 USD**

### 3.1 Milestone Category: Completed First Version (Beta)

#### Milestone 1 — Security Audit (4 Core Programs) — $40,000

**Scope:** Professional third-party security audit of x0-guard, x0-token, x0-wrapper, x0-escrow, and x0-reputation by a reputable Solana-specialized firm (Trail of Bits, OtterSec, or equivalent).

**Justification:** These five programs hold user funds (wrapper reserves, escrow deposits) and enforce access control (spending policies, reputation updates). A professional audit is non-negotiable before mainnet. Agent payment infrastructure handling real USDC demands the same audit standards as DeFi protocols.

**Deliverables:**
- Audit report covering all 5 programs (~7,500 LOC Rust)
- Remediation of all Critical and High findings
- Public disclosure of the audit report
- On-chain program verification (Anchor verifiable builds)

**Testing plan:** The audit firm will receive full access to the codebase, test suites, the whitepaper's formal security analysis (covering invariants, attack vectors, and threat model), and a dedicated communication channel for questions. Pre-audit, we will run a self-assessment against the OWASP Smart Contract Top 10 and Solana-specific vulnerability classes (PDA validation, signer checks, account ownership, reentrancy).

**Payment:** $40,000 upon delivery of the final audit report and remediation of all Critical/High findings.

---

#### Milestone 2 — Technical Documentation — $8,000

**Scope:** Complete developer documentation sufficient for independent integration without support.

**Deliverables:**
- **SDK Reference:** Full API documentation for all 17 SDK modules with TypeDoc-generated reference
- **Integration Guides:** Step-by-step tutorials for 4 key workflows:
  1. Setting up agent spending policies
  2. Implementing HTTP 402 pay-per-call APIs
  3. Using escrow for agent service payments
  4. Querying reputation for trust-aware routing
- **Video Tutorials:** 3–4 recorded walkthroughs (15–20 min each) covering SDK setup, policy configuration, and escrow lifecycle
- **Architecture Guide:** Protocol internals document covering CPI flow, PDA derivation, and state account layouts
- **Example Applications:** 2 working example projects (agent payment bot, HTTP 402 API server)

**Testing plan:** Documentation will be validated by having 2–3 external developers (outside the core team) follow the guides cold and report friction points. Guides will be updated until a developer unfamiliar with x0 can integrate within 1 hour.

**Payment:** $8,000 upon publication of all documentation and completion of external developer validation.

---

#### Milestone 3 — Devnet → Testnet → Mainnet Deployment — $3,000

**Scope:** Progressive deployment pipeline from devnet (current) through testnet to mainnet-beta.

**Deliverables:**
- Testnet deployment of all 7 audited programs with Anchor verifiable builds
- Mainnet deployment with verified program authority and upgrade authority documentation
- RPC infrastructure setup (Helius or Triton) for SDK default endpoints
- Monitoring dashboard (program error rates, transaction throughput, reserve ratio)
- Deployment runbook documenting the exact steps and verification procedures

**Testing plan:** Each deployment stage will include a full regression suite: SDK integration tests against the deployed programs, manual verification of all PDA derivations, and a checklist of account ownership and signer validations.

**Payment:** $3,000 upon successful mainnet deployment and verification.

---

### 3.2 Milestone Category: Maintenance (6 Months)

**Total Maintenance Budget: $12,000** (from Developer Compensation allocation)

**Scope:** 6 months of active maintenance post-mainnet launch, including:

- Triaging and resolving GitHub issues within 72 hours
- Bug fixes for all Critical/High severity issues within 48 hours
- Compatibility updates for Anchor, `@solana/web3.js`, and Token-2022 breaking changes
- SDK patch releases as needed
- Monthly dependency audits and security updates
- Community support in Discord/GitHub Discussions

**Satisfaction criteria:** Maintenance quality will be measured by:
- Issue response time (target: <72 hours for triage, <1 week for resolution)
- Zero unresolved Critical/High bugs at any month's end
- SDK compatibility with the latest stable Anchor and `@solana/web3.js` versions

**Payment:** $2,000 per month for 6 months, paid at end of each month upon satisfactory maintenance activity.

---

### 3.3 Milestone Category: Developer Compensation

**Total Developer Compensation: $20,000**

Of this, $12,000 is allocated to the 6-month maintenance period (above). The remaining $8,000 covers:

- Pre-audit code hardening and test coverage expansion (Month 1)
- Audit remediation and code changes per auditor findings (Month 2)
- Mainnet deployment, monitoring setup, and launch support (Month 3)

**Payment:** Split across Milestones 1–3 completion.

---

### 3.4 Milestone Category: User Adoption

**Total Adoption Budget: $4,000** (Community Building allocation)

#### Adoption Milestone A — Developer Integrations

**Target:** 5 projects or developer teams integrating `@x0-protocol/sdk` within 6 months of mainnet launch.

**Metric:** A qualifying integration is a deployed application (devnet or mainnet) that imports `@x0-protocol/sdk` and calls at least one core function (policy creation, escrow, wrapper, or x402). Verified by on-chain transaction history and/or public repository evidence.

**Tracking:** We will maintain a public integrations registry at x0protocol.dev/integrations listing each project, their use case, and on-chain program IDs.

**Incentive plan:**
- Integration bounties: $200–$500 per qualifying integration (total $2,000 allocated)
- Technical support for integrating teams via dedicated Discord channel

**Payment:** For each 25% increment (i.e., each qualifying integration beyond the first), 25% of the $2,000 bounty pool is released. Full $2,000 released at 5 integrations.

#### Adoption Milestone B — Developer Awareness

**Target:** 500 unique SDK downloads (npm) and 100 GitHub stars within 6 months.

**Tracking:** npm download statistics (`npm-stat.com` / npmjs.com package page), GitHub repository insights.

**Activities:**
- Conference attendance (Solana Breakpoint or equivalent) — $500
- Developer-targeted content (Twitter/X threads, blog posts, dev forum posts) — $500
- Bounties for community-built integrations and tutorials — $500
- Educational content sponsorship (YouTube devs, newsletters) — $500

**Payment:** For each 25% increment of either metric (125 downloads or 25 stars), 25% of the $2,000 awareness budget is released.

---

## 4. Budget Summary

| Item | Amount | Category |
|---|---|---|
| Security Audit (5 core programs) | $40,000 | Beta Milestone 1 |
| Technical Documentation | $8,000 | Beta Milestone 2 |
| Devnet → Testnet → Mainnet Deployment | $3,000 | Beta Milestone 3 |
| Developer Compensation (pre-audit, remediation, launch) | $8,000 | Beta Milestones 1–3 |
| Maintenance (6 months × $2,000/mo) | $12,000 | Maintenance Milestones |
| Community Building & Adoption | $4,000 | Adoption Milestones A & B |
| **Total** | **$75,000** | |

---

## 5. Timeline

| Month | Activity |
|---|---|
| **Month 1** | Code hardening, test coverage expansion, audit firm selection and engagement |
| **Month 2** | Audit in progress, documentation writing, video recording |
| **Month 3** | Audit remediation, testnet deployment, documentation publication |
| **Month 4** | Mainnet deployment, SDK v1.0 release, launch announcement |
| **Month 5–9** | Maintenance, community building, adoption tracking, conference attendance |
| **Month 10** | Final adoption metrics report, grant completion |

---

## 6. Team

**Blessed Tosin-Oyinbo Olamide** — Sole developer and architect of the x0 protocol. Designed and implemented the full system from architecture through deployment: 16,500+ lines of Rust (9 Solana programs), 10,400+ lines of TypeScript SDK, EVM contracts (Solidity/Foundry), SP1 ZK circuits, and a 55-page formal whitepaper with security proofs. Deep expertise in Solana's runtime, Token-2022 extensions, Anchor framework, and zero-knowledge proof systems.

---

## 7. Links

- **Repository:** [github.com/0xtnxl/x0](https://github.com/0xtnxl/x0)
- **Documentation:** [x0protocol.dev](https://x0protocol.dev)
- **Whitepaper:** Available in repository at `/whitepaper/whitepaper.pdf`
- **License:** MIT
- **Devnet Programs:** Deployed — program IDs listed in `Anchor.toml`
