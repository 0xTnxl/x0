//! x0-registry: On-chain agent discovery and capability advertisement
//!
//! This program enables the Discovery Protocol from the x402 specification:
//! - Agents register their endpoints and capabilities
//! - Service consumers query for agents by capability type
//! - Reputation is linked for trust scoring

// Suppress cfg warnings from Anchor/Solana macros (toolchain version mismatch)
#![allow(unexpected_cfgs)]
// Suppress ambiguous glob re-export warnings (handlers have same name in different modules)
#![allow(ambiguous_glob_reexports)]

use anchor_lang::prelude::*;

pub mod instructions;
pub mod state;

pub use instructions::*;
pub use state::{AgentRegistry, Capability};
pub use x0_common::{
    constants::*,
    error::X0RegistryError,
    events::*,
};

declare_id!("Bebty49EPhFoANKDw7TqLQ2bX61ackNav5iNkj36eVJo");

#[program]
pub mod x0_registry {
    use super::*;

    /// Register a new agent in the discovery registry
    ///
    /// # Arguments
    /// * `endpoint` - The agent's service endpoint URL
    /// * `capabilities` - List of capabilities the agent offers
    pub fn register_agent(
        ctx: Context<RegisterAgent>,
        endpoint: String,
        capabilities: Vec<Capability>,
    ) -> Result<()> {
        instructions::register_agent::handler(ctx, endpoint, capabilities)
    }

    /// Update an existing registry entry
    ///
    /// # Arguments
    /// * `new_endpoint` - Optional new endpoint URL
    /// * `new_capabilities` - Optional new capabilities list
    pub fn update_registry(
        ctx: Context<UpdateRegistry>,
        new_endpoint: Option<String>,
        new_capabilities: Option<Vec<Capability>>,
    ) -> Result<()> {
        instructions::update_registry::handler(ctx, new_endpoint, new_capabilities)
    }

    /// Deactivate a registry entry
    pub fn deactivate_entry(ctx: Context<DeactivateEntry>) -> Result<()> {
        instructions::deactivate_entry::handler(ctx)
    }

    /// Reactivate a registry entry
    pub fn reactivate_entry(ctx: Context<ReactivateEntry>) -> Result<()> {
        instructions::reactivate_entry::handler(ctx)
    }

    /// Remove an agent from the registry (close account)
    pub fn deregister_agent(ctx: Context<DeregisterAgent>) -> Result<()> {
        instructions::deregister_agent::handler(ctx)
    }
}
