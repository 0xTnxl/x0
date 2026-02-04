//! Cancel escrow (before funding)

use anchor_lang::prelude::*;

use crate::state::{EscrowAccount, EscrowState};
use x0_common::{
    constants::*,
    error::X0EscrowError,
};

/// Accounts for cancelling an escrow
#[derive(Accounts)]
pub struct CancelEscrow<'info> {
    /// The buyer (must sign)
    #[account(mut)]
    pub buyer: Signer<'info>,

    /// The escrow account to close
    #[account(
        mut,
        seeds = [ESCROW_SEED, escrow.buyer.as_ref(), escrow.seller.as_ref(), &escrow.memo_hash],
        bump = escrow.bump,
        constraint = buyer.key() == escrow.buyer @ X0EscrowError::OnlyBuyerCanFund,
        constraint = escrow.state == EscrowState::Created @ X0EscrowError::InvalidEscrowState,
        close = buyer,
    )]
    pub escrow: Account<'info, EscrowAccount>,
}

pub fn handler(ctx: Context<CancelEscrow>) -> Result<()> {
    // The account is closed by Anchor via the `close = buyer` constraint
    // Rent is returned to buyer
    
    msg!(
        "Escrow cancelled: escrow={}",
        ctx.accounts.escrow.key()
    );

    Ok(())
}
