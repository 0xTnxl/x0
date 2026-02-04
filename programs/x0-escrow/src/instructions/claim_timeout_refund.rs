//! Claim timeout refund

use anchor_lang::prelude::*;
use anchor_spl::token_2022::{self, Token2022, TransferChecked};

use crate::state::{EscrowAccount, EscrowState};
use x0_common::{
    constants::*,
    error::X0EscrowError,
    events::FundsRefunded,
};

/// Accounts for claiming timeout refund
#[derive(Accounts)]
pub struct ClaimTimeoutRefund<'info> {
    /// The buyer (must sign)
    pub buyer: Signer<'info>,

    /// The escrow account
    #[account(
        mut,
        seeds = [ESCROW_SEED, escrow.buyer.as_ref(), escrow.seller.as_ref(), &escrow.memo_hash],
        bump = escrow.bump,
        constraint = buyer.key() == escrow.buyer @ X0EscrowError::OnlyBuyerCanFund,
        constraint = escrow.state == EscrowState::Funded @ X0EscrowError::InvalidEscrowState,
    )]
    pub escrow: Account<'info, EscrowAccount>,

    /// The escrow token account
    /// CHECK: Validated by Token-2022 program
    #[account(mut)]
    pub escrow_token_account: UncheckedAccount<'info>,

    /// The buyer's token account
    /// CHECK: Validated by Token-2022 program
    #[account(mut)]
    pub buyer_token_account: UncheckedAccount<'info>,

    /// The token mint
    /// CHECK: Must match escrow.mint
    pub mint: UncheckedAccount<'info>,

    /// Token-2022 program
    pub token_program: Program<'info, Token2022>,
}

pub fn handler(ctx: Context<ClaimTimeoutRefund>) -> Result<()> {
    let escrow = &mut ctx.accounts.escrow;
    let clock = Clock::get()?;

    // Check timeout has passed (seller failed to deliver in time)
    require!(
        clock.unix_timestamp > escrow.timeout,
        X0EscrowError::EscrowExpired
    );

    // ========================================================================
    // CRITICAL-2 FIX: Update state BEFORE transfer to prevent reentrancy
    // ========================================================================
    let refund_amount = escrow.amount;
    let buyer = escrow.buyer;
    let seller = escrow.seller;
    let token_decimals = escrow.token_decimals; // MEDIUM-11: Use stored decimals
    
    // Update state BEFORE transfer (prevents reentrancy)
    escrow.state = EscrowState::Refunded;

    // Transfer tokens back to buyer
    let seeds = &[
        ESCROW_SEED,
        buyer.as_ref(),
        seller.as_ref(),
        &escrow.memo_hash,
        &[escrow.bump],
    ];
    let signer_seeds = &[&seeds[..]];

    let cpi_accounts = TransferChecked {
        from: ctx.accounts.escrow_token_account.to_account_info(),
        mint: ctx.accounts.mint.to_account_info(),
        to: ctx.accounts.buyer_token_account.to_account_info(),
        authority: escrow.to_account_info(),
    };

    let cpi_ctx = CpiContext::new_with_signer(
        ctx.accounts.token_program.to_account_info(),
        cpi_accounts,
        signer_seeds,
    );

    // MEDIUM-11: Use stored decimals instead of hardcoded 6
    token_2022::transfer_checked(cpi_ctx, refund_amount, token_decimals)?;

    emit!(FundsRefunded {
        escrow: escrow.key(),
        amount: refund_amount,
        recipient: buyer,
        reason: "Seller failed to deliver before timeout".to_string(),
        timestamp: clock.unix_timestamp,
    });

    msg!(
        "Timeout refund claimed: escrow={}, buyer={}, amount={}",
        escrow.key(),
        buyer,
        refund_amount
    );

    Ok(())
}
