//! Deregister an agent from the registry

use anchor_lang::prelude::*;

use crate::state::AgentRegistry;
use x0_common::{
    constants::*,
    error::X0RegistryError,
    events::AgentDeregistered,
};

/// Accounts for deregistering an agent
#[derive(Accounts)]
pub struct DeregisterAgent<'info> {
    /// The owner (must sign, receives rent)
    #[account(
        mut,
        constraint = owner.key() == registry_entry.owner @ X0RegistryError::UnauthorizedRegistryUpdate
    )]
    pub owner: Signer<'info>,

    /// The registry entry to close
    #[account(
        mut,
        seeds = [REGISTRY_SEED, registry_entry.agent_id.as_ref()],
        bump = registry_entry.bump,
        close = owner,
    )]
    pub registry_entry: Account<'info, AgentRegistry>,
}

pub fn handler(ctx: Context<DeregisterAgent>) -> Result<()> {
    let clock = Clock::get()?;
    let agent_id = ctx.accounts.registry_entry.agent_id;

    // Emit event before closing
    emit!(AgentDeregistered {
        registry_entry: ctx.accounts.registry_entry.key(),
        agent_id,
        timestamp: clock.unix_timestamp,
    });

    msg!(
        "Agent deregistered: agent_id={}",
        agent_id
    );

    Ok(())
}
