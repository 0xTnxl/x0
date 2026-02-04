//! Get current spend information (view function)

use anchor_lang::prelude::*;
use crate::state::AgentPolicy;
use x0_common::constants::*;

/// Accounts for getting current spend
#[derive(Accounts)]
pub struct GetCurrentSpend<'info> {
    /// The policy to query
    #[account(
        seeds = [AGENT_POLICY_SEED, agent_policy.owner.as_ref()],
        bump = agent_policy.bump,
    )]
    pub agent_policy: Account<'info, AgentPolicy>,
}

pub fn handler(ctx: Context<GetCurrentSpend>) -> Result<(u64, u64, i64)> {
    let policy = &ctx.accounts.agent_policy;
    let clock = Clock::get()?;
    
    let current_timestamp = clock.unix_timestamp;
    let cutoff = current_timestamp - ROLLING_WINDOW_SECONDS;
    
    // Calculate current spend
    let current_spend: u64 = policy
        .rolling_window
        .iter()
        .filter(|entry| entry.timestamp > cutoff)
        .map(|entry| entry.amount)
        .sum();
    
    // Calculate remaining allowance
    let remaining = policy.daily_limit.saturating_sub(current_spend);
    
    // Find oldest entry timestamp that's still valid
    let oldest_entry = policy
        .rolling_window
        .iter()
        .filter(|entry| entry.timestamp > cutoff)
        .map(|entry| entry.timestamp)
        .min()
        .unwrap_or(0);
    
    // Calculate when the oldest entry will expire (freeing up limit)
    let oldest_expiry = if oldest_entry > 0 {
        oldest_entry + ROLLING_WINDOW_SECONDS
    } else {
        0
    };

    msg!(
        "Current spend: {}, Remaining: {}, Next expiry: {}",
        current_spend,
        remaining,
        oldest_expiry
    );

    Ok((current_spend, remaining, oldest_expiry))
}
