//! Record a dispute resolution in agent's favor
//!
//! SECURITY: Only the escrow program can record favorable resolutions.
//! This prevents agents from inflating their own reputation by
//! claiming false dispute resolutions.

use anchor_lang::prelude::*;

use crate::state::AgentReputation;
use x0_common::{
    constants::*,
    error::X0ReputationError,
    events::ReputationUpdated,
};

/// Accounts for recording resolution in favor
#[derive(Accounts)]
pub struct RecordResolutionFavor<'info> {
    /// The authority - MUST be the escrow program
    /// CRITICAL-5 FIX: Only escrow program can record favorable resolutions
    /// (agents cannot self-report favorable resolutions to prevent gaming)
    #[account(
        constraint = authority.key() == ESCROW_PROGRAM_ID
            @ X0ReputationError::UnauthorizedReputationUpdate
    )]
    pub authority: Signer<'info>,

    /// The reputation account to update
    #[account(
        mut,
        seeds = [REPUTATION_SEED, reputation.agent_id.as_ref()],
        bump = reputation.bump,
    )]
    pub reputation: Account<'info, AgentReputation>,
}

pub fn handler(ctx: Context<RecordResolutionFavor>) -> Result<()> {
    let reputation = &mut ctx.accounts.reputation;
    let clock = Clock::get()?;

    // Record resolution in favor
    reputation.record_resolution_favor(clock.unix_timestamp);

    // Calculate score (scaled by 1000)
    let score = (reputation.calculate_score() * 1000.0) as u32;

    // Emit event
    emit!(ReputationUpdated {
        reputation: reputation.key(),
        update_type: "resolution_favor".to_string(),
        total_transactions: reputation.total_transactions,
        score_scaled: score,
        timestamp: clock.unix_timestamp,
    });

    msg!(
        "Resolution in favor recorded: agent={}, resolved={}, score={}",
        reputation.agent_id,
        reputation.resolved_in_favor,
        score
    );

    Ok(())
}
