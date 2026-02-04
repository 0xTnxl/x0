//! Record a Blink generation event (rate-limited)

use anchor_lang::prelude::*;
use crate::state::AgentPolicy;
use x0_common::{
    constants::*,
    error::X0GuardError,
    events::BlinkGenerated,
};

/// Accounts for recording a Blink
#[derive(Accounts)]
pub struct RecordBlink<'info> {
    /// The agent signer (pays the Blink cost)
    #[account(mut)]
    pub agent: Signer<'info>,

    /// The policy for this agent
    #[account(
        mut,
        seeds = [AGENT_POLICY_SEED, agent_policy.owner.as_ref()],
        bump = agent_policy.bump,
        constraint = agent.key() == agent_policy.agent_signer @ X0GuardError::UnauthorizedSigner,
    )]
    pub agent_policy: Account<'info, AgentPolicy>,

    /// Treasury to receive Blink cost (burned)
    /// CHECK: This is the protocol treasury PDA
    #[account(mut)]
    pub treasury: UncheckedAccount<'info>,

    /// System program for transfer
    pub system_program: Program<'info, System>,
}

pub fn handler(
    ctx: Context<RecordBlink>,
    amount: u64,
    recipient: Pubkey,
    reason: String,
) -> Result<()> {
    let policy = &mut ctx.accounts.agent_policy;
    let clock = Clock::get()?;

    // Check rate limit
    require!(
        policy.check_blink_rate_limit(clock.unix_timestamp),
        X0GuardError::BlinkRateLimitExceeded
    );

    // Transfer Blink cost to treasury (burned/collected)
    let transfer_ix = anchor_lang::solana_program::system_instruction::transfer(
        ctx.accounts.agent.key,
        ctx.accounts.treasury.key,
        BLINK_GENERATION_COST_LAMPORTS,
    );
    
    anchor_lang::solana_program::program::invoke(
        &transfer_ix,
        &[
            ctx.accounts.agent.to_account_info(),
            ctx.accounts.treasury.to_account_info(),
            ctx.accounts.system_program.to_account_info(),
        ],
    )?;

    let expires_at = clock.unix_timestamp + BLINK_EXPIRY_SECONDS;

    // Emit event
    emit!(BlinkGenerated {
        policy: policy.key(),
        agent: ctx.accounts.agent.key(),
        amount,
        recipient,
        expires_at,
        timestamp: clock.unix_timestamp,
    });

    msg!(
        "Blink generated: policy={}, amount={}, recipient={}, reason={}, expires_at={}",
        policy.key(),
        amount,
        recipient,
        reason,
        expires_at
    );

    Ok(())
}
