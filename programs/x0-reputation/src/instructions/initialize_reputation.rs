//! Initialize a reputation account

use anchor_lang::prelude::*;

use crate::state::AgentReputation;
use x0_common::{
    constants::*,
    events::ReputationInitialized,
};

/// Accounts for initializing reputation
#[derive(Accounts)]
pub struct InitializeReputation<'info> {
    /// The payer for account creation
    #[account(mut)]
    pub payer: Signer<'info>,

    /// The agent's policy PDA
    /// CHECK: This is the agent's policy address
    pub agent_policy: UncheckedAccount<'info>,

    /// The reputation PDA to create
    #[account(
        init,
        payer = payer,
        space = AgentReputation::space(),
        seeds = [REPUTATION_SEED, agent_policy.key().as_ref()],
        bump,
    )]
    pub reputation: Account<'info, AgentReputation>,

    /// System program
    pub system_program: Program<'info, System>,
}

pub fn handler(ctx: Context<InitializeReputation>) -> Result<()> {
    let clock = Clock::get()?;
    let reputation = &mut ctx.accounts.reputation;

    // Initialize reputation state
    reputation.version = 2; // Version 2: Added failed_transactions field
    reputation.agent_id = ctx.accounts.agent_policy.key();
    reputation.total_transactions = 0;
    reputation.successful_transactions = 0;
    reputation.disputed_transactions = 0;
    reputation.resolved_in_favor = 0;
    reputation.failed_transactions = 0;
    reputation.average_response_time_ms = 0;
    reputation.cumulative_response_time_ms = 0;
    reputation.last_updated = clock.unix_timestamp;
    reputation.last_decay_applied = clock.unix_timestamp;
    reputation.bump = ctx.bumps.reputation;
    reputation._reserved = [0u8; 23]; // Reduced for new fields

    // Emit event
    emit!(ReputationInitialized {
        reputation: reputation.key(),
        agent_id: reputation.agent_id,
        timestamp: clock.unix_timestamp,
    });

    msg!(
        "Reputation initialized: agent_id={}",
        reputation.agent_id
    );

    Ok(())
}
