//! Record a successful transaction
//!
//! SECURITY: Only authorized callers can update reputation:
//! - The escrow program (after successful fund release)
//! - The policy owner (for self-reported off-chain transactions)

use anchor_lang::prelude::*;

use crate::state::AgentReputation;
use x0_common::{
    constants::*,
    error::X0ReputationError,
    events::ReputationUpdated,
};

/// Accounts for recording success
#[derive(Accounts)]
pub struct RecordSuccess<'info> {
    /// The authority (escrow program or policy owner)
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

pub fn handler(ctx: Context<RecordSuccess>, response_time_ms: u32) -> Result<()> {
    // Verify authority is either escrow program or policy owner
    if ctx.accounts.authority.key() != ESCROW_PROGRAM_ID {
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

    // Record success
    reputation.record_success(response_time_ms, clock.unix_timestamp);

    // Calculate score (scaled by 1000)
    let score = (reputation.calculate_score() * 1000.0) as u32;

    // Emit event
    emit!(ReputationUpdated {
        reputation: reputation.key(),
        update_type: "success".to_string(),
        total_transactions: reputation.total_transactions,
        score_scaled: score,
        timestamp: clock.unix_timestamp,
    });

    msg!(
        "Success recorded: agent={}, total={}, score={}",
        reputation.agent_id,
        reputation.total_transactions,
        score
    );

    Ok(())
}
