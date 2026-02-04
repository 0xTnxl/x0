//! x0-common: Shared types, constants, and utilities for the x0-01 protocol
//!
//! This crate provides the foundational primitives used across all x0 programs:
//! - Error codes (Appendix A compliant)
//! - Shared enums and types (EscrowState, Capability, AdminActionType)
//! - Whitelist implementations (Merkle, Bloom, Domain)
//! - Protocol constants and configuration
//!
//! NOTE: This is a library crate, not a program. It does NOT have a declare_id!
//! Account structs with #[account] are defined in their respective program crates.

pub mod constants;
pub mod error;
pub mod events;
pub mod state;
pub mod utils;
pub mod whitelist;

pub use constants::*;
pub use error::*;
pub use events::*;
pub use state::*;
pub use utils::*;
pub use whitelist::*;
