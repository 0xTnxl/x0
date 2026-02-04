//! Reactivate a registry entry

use anchor_lang::prelude::*;

use crate::state::AgentRegistry;
use x0_common::{
    constants::*,
    error::X0RegistryError,
};

/// Accounts for reactivating a registry entry
#[derive(Accounts)]
pub struct ReactivateEntry<'info> {
    /// The owner (must sign)
    #[account(
        constraint = owner.key() == registry_entry.owner @ X0RegistryError::UnauthorizedRegistryUpdate
    )]
    pub owner: Signer<'info>,

    /// The registry entry to reactivate
    #[account(
        mut,
        seeds = [REGISTRY_SEED, registry_entry.agent_id.as_ref()],
        bump = registry_entry.bump,
    )]
    pub registry_entry: Account<'info, AgentRegistry>,
}

pub fn handler(ctx: Context<ReactivateEntry>) -> Result<()> {
    let registry = &mut ctx.accounts.registry_entry;
    let clock = Clock::get()?;

    registry.is_active = true;
    registry.last_updated = clock.unix_timestamp;

    msg!(
        "Registry entry reactivated: agent_id={}",
        registry.agent_id
    );

    Ok(())
}
