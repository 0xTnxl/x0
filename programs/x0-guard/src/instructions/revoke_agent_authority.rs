//! Revoke an agent's authority (emergency key rotation)

use anchor_lang::prelude::*;
use crate::state::AgentPolicy;
use x0_common::{
    constants::*,
    error::X0GuardError,
    events::AgentRevoked,
};

/// Accounts for revoking agent authority
#[derive(Accounts)]
pub struct RevokeAgentAuthority<'info> {
    /// The policy owner (must sign)
    #[account(
        constraint = owner.key() == agent_policy.owner @ X0GuardError::PolicyOwnerMismatch
    )]
    pub owner: Signer<'info>,

    /// The policy to update
    #[account(
        mut,
        seeds = [AGENT_POLICY_SEED, owner.key().as_ref()],
        bump = agent_policy.bump,
    )]
    pub agent_policy: Account<'info, AgentPolicy>,
}

pub fn handler(ctx: Context<RevokeAgentAuthority>) -> Result<()> {
    let policy = &mut ctx.accounts.agent_policy;
    let clock = Clock::get()?;

    let revoked_signer = policy.agent_signer;
    
    // Set agent signer to the default pubkey (all zeros) to invalidate
    policy.agent_signer = Pubkey::default();
    
    // Also deactivate the policy for safety
    policy.is_active = false;

    // Emit event
    emit!(AgentRevoked {
        policy: policy.key(),
        revoked_signer,
        timestamp: clock.unix_timestamp,
    });

    msg!(
        "Agent authority revoked: policy={}, revoked_signer={}",
        policy.key(),
        revoked_signer
    );

    Ok(())
}
