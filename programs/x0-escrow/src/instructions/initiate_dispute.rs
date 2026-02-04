//! Initiate a dispute

use anchor_lang::prelude::*;

use crate::state::{EscrowAccount, EscrowState};
use x0_common::{
    constants::*,
    error::X0EscrowError,
    events::DisputeInitiated,
};

/// Accounts for initiating a dispute
#[derive(Accounts)]
pub struct InitiateDispute<'info> {
    /// The initiator (buyer or seller)
    pub initiator: Signer<'info>,

    /// The escrow account
    #[account(
        mut,
        seeds = [ESCROW_SEED, escrow.buyer.as_ref(), escrow.seller.as_ref(), &escrow.memo_hash],
        bump = escrow.bump,
        constraint = (initiator.key() == escrow.buyer || initiator.key() == escrow.seller),
        constraint = escrow.state == EscrowState::Delivered @ X0EscrowError::CannotDisputeBeforeDelivery,
    )]
    pub escrow: Account<'info, EscrowAccount>,

    /// The seller's reputation account (optional - for CPI update)
    /// CHECK: Validated by reputation program via CPI
    #[account(mut)]
    pub seller_reputation: Option<UncheckedAccount<'info>>,

    /// The seller's policy account (required for reputation CPI)
    /// CHECK: Validated by reputation program via CPI
    pub seller_policy: Option<UncheckedAccount<'info>>,

    /// The reputation program
    /// CHECK: Validated by program ID
    pub reputation_program: Option<UncheckedAccount<'info>>,
}

pub fn handler(
    ctx: Context<InitiateDispute>,
    evidence_hash: [u8; 32],
) -> Result<()> {
    let escrow = &mut ctx.accounts.escrow;
    let clock = Clock::get()?;

    // Check not already disputed
    require!(
        escrow.state != EscrowState::Disputed,
        X0EscrowError::DisputeAlreadyInitiated
    );

    // Capture seller for CPI
    let seller = escrow.seller;
    let buyer = escrow.buyer;

    // Update state
    escrow.state = EscrowState::Disputed;
    escrow.dispute_evidence = Some(evidence_hash);
    // MEDIUM-6: Record when dispute was initiated for arbiter delay
    escrow.dispute_initiated_slot = clock.slot;

    // ========================================================================
    // CPI: Record dispute on seller's reputation
    // ========================================================================
    if let (Some(reputation_account), Some(policy_account), Some(reputation_program)) = (
        &ctx.accounts.seller_reputation,
        &ctx.accounts.seller_policy,
        &ctx.accounts.reputation_program,
    ) {
        // Build PDA signer seeds for escrow
        let seeds = &[
            ESCROW_SEED,
            buyer.as_ref(),
            seller.as_ref(),
            &escrow.memo_hash,
            &[escrow.bump],
        ];
        let signer_seeds = &[&seeds[..]];

        // Build CPI context for record_dispute
        let cpi_accounts = x0_reputation::cpi::accounts::RecordDispute {
            authority: escrow.to_account_info(),
            agent_policy: policy_account.to_account_info(),
            reputation: reputation_account.to_account_info(),
        };
        
        let cpi_ctx = CpiContext::new_with_signer(
            reputation_program.to_account_info(),
            cpi_accounts,
            signer_seeds,
        );

        x0_reputation::cpi::record_dispute(cpi_ctx)?;
        
        msg!("Dispute recorded on seller reputation: {}", seller);
    }

    // Emit event
    emit!(DisputeInitiated {
        escrow: escrow.key(),
        initiator: ctx.accounts.initiator.key(),
        evidence_hash,
        timestamp: clock.unix_timestamp,
    });

    msg!(
        "Dispute initiated: escrow={}, initiator={}",
        escrow.key(),
        ctx.accounts.initiator.key()
    );

    Ok(())
}
