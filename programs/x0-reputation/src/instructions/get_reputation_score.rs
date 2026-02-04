//! Get the current reputation score

use anchor_lang::prelude::*;

use crate::state::AgentReputation;
use x0_common::constants::*;

/// Accounts for getting reputation score
#[derive(Accounts)]
pub struct GetReputationScore<'info> {
    /// The reputation account to query
    #[account(
        seeds = [REPUTATION_SEED, reputation.agent_id.as_ref()],
        bump = reputation.bump,
    )]
    pub reputation: Account<'info, AgentReputation>,
}

pub fn handler(ctx: Context<GetReputationScore>) -> Result<u32> {
    let reputation = &ctx.accounts.reputation;

    // Calculate score (scaled by 1000 for precision without decimals)
    let score = (reputation.calculate_score() * 1000.0) as u32;

    msg!(
        "Reputation score: agent={}, score={}/1000, reliable={}",
        reputation.agent_id,
        score,
        reputation.has_reliable_score()
    );

    Ok(score)
}
