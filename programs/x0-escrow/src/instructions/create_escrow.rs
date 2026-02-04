//! Create a new escrow

use anchor_lang::prelude::*;
use anchor_lang::solana_program::system_program;
use crate::state::{EscrowAccount, EscrowState};
use x0_common::{
    constants::*,
    error::X0EscrowError,
    events::EscrowCreated,
    utils::validate_escrow_timeout,
};

/// MEDIUM-11: Extract decimals from Token-2022 mint account data
/// Standard mint layout has decimals at byte offset 44
fn get_mint_decimals(mint_info: &AccountInfo) -> Result<u8> {
    let data = mint_info.try_borrow_data()?;
    require!(data.len() >= 45, X0EscrowError::InvalidMint);
    Ok(data[44])
}

/// Accounts for creating an escrow
#[derive(Accounts)]
#[instruction(amount: u64, memo_hash: [u8; 32])]
pub struct CreateEscrow<'info> {
    /// The buyer (payer for escrow creation)
    #[account(mut)]
    pub buyer: Signer<'info>,

    /// The seller (recipient if escrow released)
    /// CHECK: This is just a public key reference, validated to be a system account (HIGH-7)
    #[account(
        constraint = *seller.owner == system_program::ID @ X0EscrowError::InvalidArbiter
    )]
    pub seller: UncheckedAccount<'info>,

    /// The escrow PDA
    #[account(
        init,
        payer = buyer,
        space = EscrowAccount::space(),
        seeds = [ESCROW_SEED, buyer.key().as_ref(), seller.key().as_ref(), &memo_hash],
        bump,
    )]
    pub escrow: Account<'info, EscrowAccount>,

    /// The token mint for this escrow
    /// CHECK: Validated as Token-2022 mint with ownership check (HIGH-7)
    #[account(
        constraint = *mint.owner == spl_token_2022::id() @ X0EscrowError::InvalidMint
    )]
    pub mint: UncheckedAccount<'info>,

    /// System program
    pub system_program: Program<'info, System>,
}

pub fn handler(
    ctx: Context<CreateEscrow>,
    amount: u64,
    memo_hash: [u8; 32],
    timeout_seconds: i64,
    arbiter: Option<Pubkey>,
) -> Result<()> {
    // Validate inputs
    require!(amount > 0, X0EscrowError::ZeroEscrowAmount);
    require!(
        ctx.accounts.buyer.key() != ctx.accounts.seller.key(),
        X0EscrowError::SameBuyerAndSeller
    );
    validate_escrow_timeout(timeout_seconds)?;

    let clock = Clock::get()?;
    let escrow = &mut ctx.accounts.escrow;

    // Initialize escrow state
    escrow.version = 1; // LOW-4: Account versioning for migrations
    escrow.buyer = ctx.accounts.buyer.key();
    escrow.seller = ctx.accounts.seller.key();
    escrow.arbiter = arbiter;
    escrow.amount = amount;
    escrow.memo_hash = memo_hash;
    escrow.state = EscrowState::Created;
    // HIGH-6: Use checked_add to prevent overflow creating past-expired escrows
    escrow.timeout = clock.unix_timestamp
        .checked_add(timeout_seconds)
        .ok_or(X0EscrowError::EscrowTimeoutTooLong)?;
    escrow.created_at = clock.unix_timestamp;
    escrow.delivery_proof = None;
    escrow.dispute_evidence = None;
    escrow.mint = ctx.accounts.mint.key();
    // MEDIUM-11: Store token decimals from mint to avoid hardcoded assumptions
    // Token-2022 mints have a standard layout with decimals at offset 44
    escrow.token_decimals = get_mint_decimals(&ctx.accounts.mint.to_account_info())?;
    // MEDIUM-6: Initialize dispute slot to 0 (will be set when dispute initiated)
    escrow.dispute_initiated_slot = 0;
    escrow.bump = ctx.bumps.escrow;
    escrow._reserved = [0u8; 22]; // Reduced for version field

    // Emit event
    emit!(EscrowCreated {
        escrow: escrow.key(),
        buyer: escrow.buyer,
        seller: escrow.seller,
        arbiter,
        amount,
        memo_hash,
        timeout: escrow.timeout,
        timestamp: clock.unix_timestamp,
    });

    msg!(
        "Escrow created: buyer={}, seller={}, amount={}, timeout={}",
        escrow.buyer,
        escrow.seller,
        amount,
        escrow.timeout
    );

    Ok(())
}
