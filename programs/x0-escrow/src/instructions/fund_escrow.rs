//! Fund an escrow

use anchor_lang::prelude::*;
use anchor_spl::token_2022::{self, Token2022, TransferChecked};

use crate::state::{EscrowAccount, EscrowState};
use x0_common::{
    constants::*,
    error::X0EscrowError,
    events::EscrowFunded,
};

/// Accounts for funding an escrow
#[derive(Accounts)]
pub struct FundEscrow<'info> {
    /// The buyer (must sign)
    pub buyer: Signer<'info>,

    /// The escrow account
    #[account(
        mut,
        seeds = [ESCROW_SEED, escrow.buyer.as_ref(), escrow.seller.as_ref(), &escrow.memo_hash],
        bump = escrow.bump,
        constraint = buyer.key() == escrow.buyer @ X0EscrowError::OnlyBuyerCanFund,
        constraint = escrow.state == EscrowState::Created @ X0EscrowError::InvalidEscrowState,
    )]
    pub escrow: Account<'info, EscrowAccount>,

    /// The buyer's token account
    /// CHECK: Validated by Token-2022 program
    #[account(mut)]
    pub buyer_token_account: UncheckedAccount<'info>,

    /// The escrow token account (PDA-controlled)
    /// CHECK: Validated by Token-2022 program
    #[account(mut)]
    pub escrow_token_account: UncheckedAccount<'info>,

    /// The token mint
    /// CHECK: Must match escrow.mint
    pub mint: UncheckedAccount<'info>,

    /// Token-2022 program
    pub token_program: Program<'info, Token2022>,
}

pub fn handler(ctx: Context<FundEscrow>) -> Result<()> {
    let escrow = &mut ctx.accounts.escrow;
    let clock = Clock::get()?;

    // Check escrow hasn't expired
    require!(
        clock.unix_timestamp < escrow.timeout,
        X0EscrowError::EscrowExpired
    );

    // Transfer tokens to escrow
    let cpi_accounts = TransferChecked {
        from: ctx.accounts.buyer_token_account.to_account_info(),
        mint: ctx.accounts.mint.to_account_info(),
        to: ctx.accounts.escrow_token_account.to_account_info(),
        authority: ctx.accounts.buyer.to_account_info(),
    };

    let cpi_ctx = CpiContext::new(
        ctx.accounts.token_program.to_account_info(),
        cpi_accounts,
    );

    // MEDIUM-11: Use stored token decimals instead of hardcoded 6
    token_2022::transfer_checked(cpi_ctx, escrow.amount, escrow.token_decimals)?;

    // Update state
    escrow.state = EscrowState::Funded;

    // Emit event
    emit!(EscrowFunded {
        escrow: escrow.key(),
        amount: escrow.amount,
        timestamp: clock.unix_timestamp,
    });

    msg!(
        "Escrow funded: escrow={}, amount={}",
        escrow.key(),
        escrow.amount
    );

    Ok(())
}
