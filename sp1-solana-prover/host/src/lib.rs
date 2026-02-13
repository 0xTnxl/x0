//! x0 SP1 Solana State Prover — Library
//!
//! Proves that a `BridgeOutMessage` PDA exists on Solana with valid burned
//! status, enabling trustless USDC release on Base via the SP1 STARK verifier.
//!
//! # Modules
//!
//! - [`fetcher`] — Fetches all on-chain data needed for the proof witness
//! - [`prover`] — Generates SP1 STARK proofs from the assembled witness
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────┐     ┌──────────────────┐     ┌──────────────┐
//! │  Solana RPC  │────▶│  fetcher module  │────▶│  SP1 Prover  │
//! │ (or Geyser)  │     │                  │     │              │
//! │              │     │  • Account state  │     │  • STARK     │
//! │  • blocks    │     │  • Merkle proof   │     │    circuit   │
//! │  • votes     │     │  • Bank hash      │     │  • Proof gen │
//! │  • accounts  │     │  • Vote quorum    │     │  • Verify    │
//! └─────────────┘     └──────────────────┘     └──────────────┘
//! ```

pub mod fetcher;
pub mod prover;
