//! Close reputation instruction - allows owner to close and reclaim rent

use anchor_lang::prelude::*;
use crate::state::AgentReputation;
use x0_common::constants::GUARD_PROGRAM_ID;

/// Accounts for closing a reputation account
#[derive(Accounts)]
pub struct CloseReputation<'info> {
    /// The policy owner (must match policy.owner)
    #[account(mut)]
    pub owner: Signer<'info>,

    /// The agent's policy PDA - verifies ownership
    /// CHECK: We manually verify this is owned by x0-guard
    #[account()]
    pub agent_policy: UncheckedAccount<'info>,

    /// The reputation account to close
    #[account(
        mut,
        seeds = [b"reputation", agent_policy.key().as_ref()],
        bump = reputation.bump,
        close = owner,
    )]
    pub reputation: Account<'info, AgentReputation>,

    pub system_program: Program<'info, System>,
}

pub fn handler(ctx: Context<CloseReputation>) -> Result<()> {
    // Verify the policy account is owned by x0-guard
    let policy_info = &ctx.accounts.agent_policy;
    require!(
        policy_info.owner == &GUARD_PROGRAM_ID,
        x0_common::error::X0ReputationError::InvalidPolicyAccount
    );

    // Deserialize to verify owner matches
    let policy_data = policy_info.try_borrow_data()?;
    // Skip 8-byte discriminator, read owner (32 bytes after version byte)
    if policy_data.len() < 41 {
        return Err(x0_common::error::X0ReputationError::InvalidPolicyAccount.into());
    }
    let owner_bytes: [u8; 32] = policy_data[9..41].try_into().unwrap();
    let policy_owner = Pubkey::new_from_array(owner_bytes);
    
    require!(
        policy_owner == ctx.accounts.owner.key(),
        x0_common::error::X0ReputationError::Unauthorized
    );

    msg!("Reputation account closed, rent returned to owner");
    Ok(())
}
