//! Apply monthly reputation decay

use anchor_lang::prelude::*;

use crate::state::AgentReputation;
use x0_common::constants::*;

/// Seconds in a month (30 days)
const SECONDS_PER_MONTH: i64 = 30 * 24 * 60 * 60;

/// Accounts for applying decay
#[derive(Accounts)]
pub struct ApplyDecay<'info> {
    /// Anyone can trigger decay (permissionless)
    pub caller: Signer<'info>,

    /// The reputation account to update
    #[account(
        mut,
        seeds = [REPUTATION_SEED, reputation.agent_id.as_ref()],
        bump = reputation.bump,
    )]
    pub reputation: Account<'info, AgentReputation>,
}

pub fn handler(ctx: Context<ApplyDecay>) -> Result<()> {
    let reputation = &mut ctx.accounts.reputation;
    let clock = Clock::get()?;

    // Calculate months since last decay
    let elapsed = clock.unix_timestamp - reputation.last_decay_applied;
    let months_elapsed = elapsed / SECONDS_PER_MONTH;

    if months_elapsed <= 0 {
        msg!("No decay needed yet");
        return Ok(());
    }

    // Apply 1% decay per month to successful transactions only (HIGH-8)
    // This prevents stale reputations from dominating while maintaining
    // accurate total transaction counts.
    //
    // FIXED: Previously decayed both successful AND total, which maintained
    // the same ratio and made decay pointless. Now only successful_transactions
    // decays, causing old positive reputation to fade over time.
    let decay_factor = 100u64.saturating_sub(REPUTATION_DECAY_RATE_BPS as u64); // 99 for 1% decay
    let decay_iterations = months_elapsed.min(12) as u32; // Max 12 months at once

    // Calculate compound decay in one operation to avoid rounding errors (HIGH-8)
    // decay_multiplier = decay_factor^iterations, decay_divisor = 100^iterations
    let decay_multiplier = decay_factor.saturating_pow(decay_iterations);
    let decay_divisor = 100u64.saturating_pow(decay_iterations);

    // Only decay successful transactions - total_transactions is an immutable historical count
    reputation.successful_transactions = reputation
        .successful_transactions
        .saturating_mul(decay_multiplier)
        .saturating_div(decay_divisor.max(1)); // Prevent division by zero

    reputation.last_decay_applied = clock.unix_timestamp;
    reputation.last_updated = clock.unix_timestamp;

    msg!(
        "Decay applied: agent={}, months={}, new_total={}",
        reputation.agent_id,
        months_elapsed,
        reputation.total_transactions
    );

    Ok(())
}
