//! x0 SP1 EVM (Base) Prover — Library
//!
//! Proves that a `Locked()` event was emitted on Base by X0LockContract,
//! enabling trustless USDC release on Solana via the SP1 STARK verifier.
//!
//! # Modules
//!
//! - [`artifacts`] — Fetches EVM block/tx/receipt artifacts via multi-RPC consensus
//! - [`prover`] — Generates SP1 STARK proofs from the assembled witness
//! - [`multi_rpc`] — Multi-endpoint RPC consensus provider
//! - [`solana_bridge`] — Fetches the trusted chain anchor from Solana
//! - [`l1_finality`] — Verifies L1 Ethereum finality for Base L2 blocks
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────┐     ┌──────────────────┐     ┌──────────────┐
//! │  Base L2 RPC  │────▶│ artifacts module │────▶│  SP1 Prover  │
//! │  (consensus)  │     │                  │     │              │
//! │               │     │  • Block header  │     │  • STARK     │
//! │  • block data │     │  • MPT proofs    │     │    circuit   │
//! │  • tx/receipt │     │  • Chain proof   │     │  • Proof gen │
//! │               │     │  • Event logs    │     │  • Verify    │
//! └──────────────┘     └──────────────────┘     └──────────────┘
//!       ▲
//!  Solana RPC
//!  (trusted anchor)
//! ```

pub mod artifacts;
pub mod l1_finality;
pub mod multi_rpc;
pub mod prover;
pub mod solana_bridge;
