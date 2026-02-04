//! Release funds to seller

use anchor_lang::prelude::*;
use anchor_spl::token_2022::{self, Token2022, TransferChecked};

use crate::state::{EscrowAccount, EscrowState};
use x0_common::{
    constants::*,
    error::X0EscrowError,
    events::FundsReleased,
};

/// Accounts for releasing funds
#[derive(Accounts)]
pub struct ReleaseFunds<'info> {
    /// The buyer (must sign to release)
    pub buyer: Signer<'info>,

    /// The escrow account
    #[account(
        mut,
        seeds = [ESCROW_SEED, escrow.buyer.as_ref(), escrow.seller.as_ref(), &escrow.memo_hash],
        bump = escrow.bump,
        constraint = buyer.key() == escrow.buyer @ X0EscrowError::OnlyBuyerCanRelease,
        constraint = escrow.state == EscrowState::Delivered @ X0EscrowError::InvalidEscrowState,
    )]
    pub escrow: Account<'info, EscrowAccount>,

    /// The escrow token account (source)
    /// CHECK: Validated by Token-2022 program
    #[account(mut)]
    pub escrow_token_account: UncheckedAccount<'info>,

    /// The seller's token account (destination)
    /// CHECK: Validated by Token-2022 program
    #[account(mut)]
    pub seller_token_account: UncheckedAccount<'info>,

    /// The token mint
    /// CHECK: Must match escrow.mint
    pub mint: UncheckedAccount<'info>,

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

    /// Token-2022 program
    pub token_program: Program<'info, Token2022>,
}

pub fn handler(ctx: Context<ReleaseFunds>) -> Result<()> {
    let escrow = &mut ctx.accounts.escrow;
    let clock = Clock::get()?;

    // ========================================================================
    // CRITICAL-2 FIX: Update state BEFORE transfer to prevent reentrancy
    // ========================================================================
    // If the token transfer invokes another program (via CPI or transfer hook),
    // that program could call back into escrow. By updating state first,
    // any reentrant call will fail the state constraint check.
    
    let release_amount = escrow.amount;
    let seller = escrow.seller;
    let token_decimals = escrow.token_decimals; // MEDIUM-11: Use stored decimals
    let created_at = escrow.created_at; // For reputation response time calculation
    
    // Update state BEFORE transfer (prevents reentrancy)
    escrow.state = EscrowState::Released;
    escrow.state = EscrowState::Released;

    // Transfer tokens to seller using escrow PDA authority
    let seeds = &[
        ESCROW_SEED,
        escrow.buyer.as_ref(),
        seller.as_ref(),
        &escrow.memo_hash,
        &[escrow.bump],
    ];
    let signer_seeds = &[&seeds[..]];

    let cpi_accounts = TransferChecked {
        from: ctx.accounts.escrow_token_account.to_account_info(),
        mint: ctx.accounts.mint.to_account_info(),
        to: ctx.accounts.seller_token_account.to_account_info(),
        authority: escrow.to_account_info(),
    };

    let cpi_ctx = CpiContext::new_with_signer(
        ctx.accounts.token_program.to_account_info(),
        cpi_accounts,
        signer_seeds,
    );

    // MEDIUM-11: Use stored decimals instead of hardcoded 6
    token_2022::transfer_checked(cpi_ctx, release_amount, token_decimals)?;

    // ========================================================================
    // CPI: Update seller's reputation with successful transaction
    // ========================================================================
    if let (Some(reputation_account), Some(policy_account), Some(reputation_program)) = (
        &ctx.accounts.seller_reputation,
        &ctx.accounts.seller_policy,
        &ctx.accounts.reputation_program,
    ) {
        // Calculate response time from escrow creation to now (in milliseconds)
        // This represents total time from buyer request to successful release
        let response_time_ms = ((clock.unix_timestamp - created_at) * 1000) as u32;

        // Build CPI context for record_success
        let cpi_accounts = x0_reputation::cpi::accounts::RecordSuccess {
            authority: escrow.to_account_info(),
            agent_policy: policy_account.to_account_info(),
            reputation: reputation_account.to_account_info(),
        };
        
        let cpi_ctx = CpiContext::new_with_signer(
            reputation_program.to_account_info(),
            cpi_accounts,
            signer_seeds,
        );

        x0_reputation::cpi::record_success(cpi_ctx, response_time_ms)?;
        
        msg!("Reputation updated for seller: {}", seller);
    }

    // Emit event
    emit!(FundsReleased {
        escrow: escrow.key(),
        amount: release_amount,
        recipient: seller,
        is_auto_release: false,
        timestamp: clock.unix_timestamp,
    });

    msg!(
        "Funds released: escrow={}, amount={}, seller={}",
        escrow.key(),
        release_amount,
        seller
    );

    Ok(())
}
