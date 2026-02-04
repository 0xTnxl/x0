//! Mark delivery complete

use anchor_lang::prelude::*;

use crate::state::{EscrowAccount, EscrowState};
use x0_common::{
    constants::*,
    error::X0EscrowError,
    events::DeliveryMarked,
};

/// Accounts for marking delivery
#[derive(Accounts)]
pub struct MarkDelivered<'info> {
    /// The seller (must sign)
    pub seller: Signer<'info>,

    /// The escrow account
    #[account(
        mut,
        seeds = [ESCROW_SEED, escrow.buyer.as_ref(), escrow.seller.as_ref(), &escrow.memo_hash],
        bump = escrow.bump,
        constraint = seller.key() == escrow.seller @ X0EscrowError::OnlySellerCanDeliver,
        constraint = escrow.state == EscrowState::Funded @ X0EscrowError::InvalidEscrowState,
    )]
    pub escrow: Account<'info, EscrowAccount>,
}

pub fn handler(
    ctx: Context<MarkDelivered>,
    proof_hash: Option<[u8; 32]>,
) -> Result<()> {
    let escrow = &mut ctx.accounts.escrow;
    let clock = Clock::get()?;

    // Update state
    escrow.state = EscrowState::Delivered;
    escrow.delivery_proof = proof_hash;

    // Emit event
    emit!(DeliveryMarked {
        escrow: escrow.key(),
        proof_hash,
        timestamp: clock.unix_timestamp,
    });

    msg!(
        "Delivery marked: escrow={}, proof={:?}",
        escrow.key(),
        proof_hash.is_some()
    );

    Ok(())
}
