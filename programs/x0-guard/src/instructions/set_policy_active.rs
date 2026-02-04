//! Set policy active/paused state

use anchor_lang::prelude::*;
use crate::state::AgentPolicy;
use x0_common::{
    constants::*,
    error::X0GuardError,
};

/// Accounts for setting policy active state
#[derive(Accounts)]
pub struct SetPolicyActive<'info> {
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

pub fn handler(ctx: Context<SetPolicyActive>, is_active: bool) -> Result<()> {
    let policy = &mut ctx.accounts.agent_policy;

    policy.is_active = is_active;

    msg!(
        "Policy active state changed: policy={}, is_active={}",
        policy.key(),
        is_active
    );

    Ok(())
}
