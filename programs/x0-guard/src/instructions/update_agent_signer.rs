//! Update the agent signer key

use anchor_lang::prelude::*;
use crate::state::AgentPolicy;
use x0_common::{
    constants::*,
    error::X0GuardError,
    events::PolicyUpdated,
};

/// Accounts for updating the agent signer
#[derive(Accounts)]
pub struct UpdateAgentSigner<'info> {
    /// The policy owner (must sign)
    #[account(
        constraint = owner.key() == agent_policy.owner @ X0GuardError::PolicyOwnerMismatch
    )]
    pub owner: Signer<'info>,

    /// The new agent signer
    /// CHECK: This is just a public key reference, validated by owner
    pub new_agent_signer: UncheckedAccount<'info>,

    /// The policy to update
    #[account(
        mut,
        seeds = [AGENT_POLICY_SEED, owner.key().as_ref()],
        bump = agent_policy.bump,
    )]
    pub agent_policy: Account<'info, AgentPolicy>,
}

pub fn handler(ctx: Context<UpdateAgentSigner>, new_agent_signer: Pubkey) -> Result<()> {
    let policy = &mut ctx.accounts.agent_policy;
    let clock = Clock::get()?;

    let old_signer = policy.agent_signer;
    policy.agent_signer = new_agent_signer;

    // Emit event
    emit!(PolicyUpdated {
        policy: policy.key(),
        daily_limit: None,
        agent_signer: Some(new_agent_signer),
        timestamp: clock.unix_timestamp,
    });

    msg!(
        "Agent signer updated: policy={}, old={}, new={}",
        policy.key(),
        old_signer,
        new_agent_signer
    );

    Ok(())
}
