//! State structures for x0-registry program
//!
//! Defines the on-chain account structures owned by x0-registry.

use anchor_lang::prelude::*;
use x0_common::constants::*;

/// An agent's entry in the discovery registry
///
/// # LOW-4: Version Field for Upgrades
/// The `version` field enables future account migrations.
#[account]
#[derive(Debug)]
pub struct AgentRegistry {
    /// Account version for future migrations (LOW-4)
    /// Version 1: Initial structure
    pub version: u8,

    /// The agent's policy PDA (primary identifier)
    pub agent_id: Pubkey,

    /// The agent's service endpoint URL
    pub endpoint: String,

    /// List of capabilities the agent offers
    pub capabilities: Vec<Capability>,

    /// PDA for dynamic pricing oracle
    pub price_oracle: Option<Pubkey>,

    /// PDA for the agent's reputation account
    pub reputation_pda: Pubkey,

    /// Unix timestamp of last update
    pub last_updated: i64,

    /// Whether the registry entry is active
    pub is_active: bool,

    /// Owner who can update this entry
    pub owner: Pubkey,

    /// PDA bump seed
    pub bump: u8,

    /// Reserved space for future upgrades (reduced by 1 for version field)
    pub _reserved: [u8; 31],
}

impl AgentRegistry {
    pub const fn space() -> usize {
        AGENT_REGISTRY_SIZE + 64 // Add reserved space
    }
}

/// A capability offered by an agent
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
