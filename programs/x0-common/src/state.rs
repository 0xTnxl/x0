//! Shared types for x0-01 protocol
//!
//! This module contains shared enums and types used across multiple programs.
//! 
//! NOTE: Account structs with #[account] are defined in their respective program
//! crates to ensure correct Anchor owner validation:
//! - AgentPolicy, ProtocolConfig -> x0-guard/src/state.rs
//! - AgentReputation -> x0-reputation/src/state.rs
//! - AgentRegistry -> x0-registry/src/state.rs
//! - EscrowAccount -> x0-escrow/src/state.rs
//! - WrapperConfig, WrapperStats, AdminAction -> x0-wrapper/src/state.rs

use anchor_lang::prelude::*;

use crate::constants::*;

// ============================================================================
// Shared Enums (used across programs)
// ============================================================================

/// State of an escrow account (used by x0-escrow)
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug, PartialEq, Default)]
pub enum EscrowState {
    /// Escrow created but not yet funded
    #[default]
    Created,
    /// Buyer has deposited funds
    Funded,
    /// Seller claims delivery is complete
    Delivered,
    /// Either party has initiated a dispute
    Disputed,
    /// Funds released to seller (terminal)
    Released,
    /// Funds returned to buyer (terminal)
    Refunded,
    /// Cancelled before funding (terminal)
    Cancelled,
}

/// A capability offered by an agent (used by x0-registry)
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug, PartialEq)]
pub struct Capability {
    /// Type of capability (e.g., "llm-inference", "data-scraping")
    pub capability_type: String,
    /// JSON metadata blob with details (models, pricing, etc.)
    pub metadata: String,
}

impl Capability {
    /// Maximum size of a capability entry
    pub const MAX_SIZE: usize = MAX_CAPABILITY_TYPE_LENGTH + MAX_CAPABILITY_METADATA_LENGTH + 8;
}

/// Type of admin action for timelock (used by x0-wrapper)
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug, PartialEq)]
pub enum AdminActionType {
    /// Change redemption fee rate
    SetFeeRate,
    /// Pause/unpause operations
    SetPaused,
    /// Emergency withdrawal
    EmergencyWithdraw,
    /// Transfer admin to new address
    TransferAdmin,
}
