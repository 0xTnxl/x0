//! Record a failed transaction (policy rejection)
//!
//! SECURITY: Only authorized callers can update reputation:
//! - The guard program (after rejecting a transfer)
//! - The policy owner (for self-reported failures)
//!
//! This tracks when an agent attempts transactions that violate their policy:
//! - Exceeded daily spending limit
//! - Exceeded per-transaction limit
//! - Destination not on whitelist
//! - Policy is paused
//!
//! Failures hurt reputation because they indicate the agent is:
//! - Poorly configured
//! - Attempting unauthorized actions
//! - Not respecting rate limits

use anchor_lang::prelude::*;

use crate::state::AgentReputation;
use x0_common::{
    constants::*,
    error::X0ReputationError,
    events::ReputationUpdated,
};

/// Accounts for recording a failure
#[derive(Accounts)]
pub struct RecordFailure<'info> {
    /// The authority (guard program or policy owner)
    pub authority: Signer<'info>,

    /// The agent's policy PDA - used to verify authority is the owner
    /// CHECK: We manually verify this is owned by x0-guard and matches reputation.agent_id
    #[account()]
    pub agent_policy: UncheckedAccount<'info>,

    /// The reputation account to update
    #[account(
        mut,
        seeds = [REPUTATION_SEED, reputation.agent_id.as_ref()],
        bump = reputation.bump,
        constraint = reputation.agent_id == agent_policy.key() 
            @ X0ReputationError::InvalidPolicyAccount
    )]
    pub reputation: Account<'info, AgentReputation>,
}

/// Error codes for policy failures
/// These match X0GuardError codes for consistency
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum FailureReason {
    /// Daily spending limit exceeded
    DailyLimitExceeded = 0x1102,
    /// Per-transaction limit exceeded
    SingleTransactionLimitExceeded = 0x1141,
    /// Destination not on whitelist
    DestinationNotWhitelisted = 0x1120,
    /// Policy is paused
    PolicyNotActive = 0x1101,
    /// Cooldown period not elapsed
    CooldownNotElapsed = 0x1140,
    /// Other/unknown failure
    Unknown = 0xFFFF,
}

pub fn handler(ctx: Context<RecordFailure>, error_code: u32) -> Result<()> {
    // Verify authority is either guard program or policy owner
    if ctx.accounts.authority.key() != GUARD_PROGRAM_ID {
        // Verify the policy account is owned by x0-guard
        let policy_info = &ctx.accounts.agent_policy;
        require!(
            policy_info.owner == &GUARD_PROGRAM_ID,
            X0ReputationError::InvalidPolicyAccount
        );

        // Deserialize to verify authority is the policy owner
        let policy_data = policy_info.try_borrow_data()?;
        // Skip 8-byte discriminator, read owner (32 bytes after version byte)
        if policy_data.len() < 41 {
            return Err(X0ReputationError::InvalidPolicyAccount.into());
        }
        let owner_bytes: [u8; 32] = policy_data[9..41].try_into().unwrap();
        let policy_owner = Pubkey::new_from_array(owner_bytes);
        
        require!(
            policy_owner == ctx.accounts.authority.key(),
            X0ReputationError::UnauthorizedReputationUpdate
        );
    }

    let reputation = &mut ctx.accounts.reputation;
    let clock = Clock::get()?;

    // Record failure
    reputation.record_failure(error_code, clock.unix_timestamp);

    // Calculate score (scaled by 1000)
    let score = (reputation.calculate_score() * 1000.0) as u32;

    // Emit event with failure details
    emit!(ReputationUpdated {
        reputation: reputation.key(),
        update_type: format!("failure:{:#x}", error_code),
        total_transactions: reputation.total_transactions,
        score_scaled: score,
        timestamp: clock.unix_timestamp,
    });

    msg!(
        "Failure recorded: agent={}, error_code={:#x}, failed_count={}, score={}",
        reputation.agent_id,
        error_code,
        reputation.failed_transactions,
        score
    );

    Ok(())
}
