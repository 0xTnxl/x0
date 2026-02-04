//! Record a dispute
//!
//! SECURITY: Only authorized callers can update reputation:
//! - The escrow program (when a dispute is raised)
//! - The policy owner (for self-reported disputes - rare but valid)

use anchor_lang::prelude::*;

use crate::state::AgentReputation;
use x0_common::{
    constants::*,
    error::X0ReputationError,
    events::ReputationUpdated,
};

/// Accounts for recording a dispute
#[derive(Accounts)]
pub struct RecordDispute<'info> {
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

pub fn handler(ctx: Context<RecordDispute>) -> Result<()> {
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

    // Record dispute
    reputation.record_dispute(clock.unix_timestamp);

    // Calculate score (scaled by 1000)
    let score = (reputation.calculate_score() * 1000.0) as u32;

    // Emit event
    emit!(ReputationUpdated {
        reputation: reputation.key(),
        update_type: "dispute".to_string(),
        total_transactions: reputation.total_transactions,
        score_scaled: score,
        timestamp: clock.unix_timestamp,
    });

    msg!(
        "Dispute recorded: agent={}, disputed={}, score={}",
        reputation.agent_id,
        reputation.disputed_transactions,
        score
    );

    Ok(())
}
