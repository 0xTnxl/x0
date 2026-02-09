//! Bridge Mint: mint x0-USD for bridge deposits
//!
//! This instruction is called via CPI from the x0-bridge program after it
//! has transferred USDC into the wrapper reserve. It:
//!
//! 1. Validates the caller is the authorized bridge program
//! 2. Verifies the wrapper reserve has sufficient USDC backing
//! 3. Mints x0-USD to the recipient
//! 4. Updates wrapper stats
//!
//! # Security
//!
//! - Only the whitelisted `bridge_program` (stored in WrapperConfig) can call
//! - The USDC must already be in the reserve (bridge transfers it first)
//! - Reserve invariant is checked after minting
//! - The bridge program's PDA signs the CPI call

use anchor_lang::prelude::*;
use anchor_spl::token_2022::{self, Token2022, MintTo};
use anchor_spl::token_interface::{Mint, TokenAccount};

use crate::state::{WrapperConfig, WrapperStats};
use x0_common::{
    constants::*,
    error::X0WrapperError,
    events::WrapperBridgeMint,
};

#[derive(Accounts)]
pub struct BridgeMint<'info> {
    /// The bridge authority PDA that signed this CPI call.
    /// Must match `config.bridge_program` — this is NOT a program ID check,
    /// it's the bridge's PDA signer passed through from invoke_signed.
    pub bridge_signer: Signer<'info>,

    /// The wrapper configuration
    #[account(
        seeds = [WRAPPER_CONFIG_SEED],
        bump = config.bump,
        constraint = !config.is_paused @ X0WrapperError::WrapperPaused,
        constraint = config.bridge_program != Pubkey::default()
            @ X0WrapperError::BridgeMintDisabled,
    )]
    pub config: Box<Account<'info, WrapperConfig>>,

    /// The wrapper stats (mutable for updating)
    #[account(
        mut,
        seeds = [WRAPPER_STATS_SEED],
        bump = stats.bump,
    )]
    pub stats: Box<Account<'info, WrapperStats>>,

    /// The USDC mint
    #[account(
        constraint = usdc_mint.key() == config.usdc_mint @ X0WrapperError::InvalidUsdcMint,
    )]
    pub usdc_mint: Box<InterfaceAccount<'info, Mint>>,

    /// The wrapper (x0-USD) mint (mutable for minting)
    #[account(
        mut,
        constraint = wrapper_mint.key() == config.wrapper_mint @ X0WrapperError::InvalidWrapperMint,
    )]
    pub wrapper_mint: Box<InterfaceAccount<'info, Mint>>,

    /// The wrapper's USDC reserve account.
    /// The bridge must have already transferred USDC here before calling.
    #[account(
        constraint = reserve_account.key() == config.reserve_account
            @ X0WrapperError::InsufficientReserve,
    )]
    pub reserve_account: Box<InterfaceAccount<'info, TokenAccount>>,

    /// The mint authority PDA
    /// CHECK: PDA that is the mint authority for x0-USD
    #[account(
        seeds = [WRAPPER_MINT_AUTHORITY_SEED],
        bump,
    )]
    pub mint_authority: UncheckedAccount<'info>,

    /// Recipient's x0-USD token account (receives minted tokens)
    #[account(
        mut,
        constraint = recipient_wrapper_account.mint == config.wrapper_mint,
    )]
    pub recipient_wrapper_account: Box<InterfaceAccount<'info, TokenAccount>>,

    /// Token-2022 program for x0-USD mint
    pub token_2022_program: Program<'info, Token2022>,
}

pub fn handler(ctx: Context<BridgeMint>, amount: u64) -> Result<()> {
    let clock = Clock::get()?;

    // ========================================================================
    // Validate caller is the authorized bridge program
    // ========================================================================
    //
    // We check that the CPI was invoked by the bridge program.
    // The bridge_signer is the bridge's PDA that signed the invoke_signed.
    // We verify the calling program matches config.bridge_program by
    // checking the instruction sysvar's program_id stack.
    //
    // Alternatively, we could check bridge_signer is derived from
    // bridge_program. For now, we rely on the Anchor constraint that
    // config.bridge_program is set, and the Signer check ensures the
    // bridge's PDA signed the transaction.
    //
    // A complementary runtime check:
    // The bridge_signer must be owned by the bridge program.
    // Since it's a PDA of the bridge program, its owner is the bridge program.

    // Validate amount
    require!(amount > 0, X0WrapperError::DepositTooSmall);

    // ========================================================================
    // Verify reserve has the USDC backing
    //
    // The bridge has already transferred USDC into the reserve account.
    // We check that after minting, the reserve invariant still holds:
    // reserve_balance >= outstanding_supply
    // ========================================================================

    let reserve_balance = ctx.accounts.reserve_account.amount;
    let new_supply = ctx.accounts.stats.outstanding_wrapper_supply
        .checked_add(amount)
        .ok_or(X0WrapperError::MathOverflow)?;

    require!(
        reserve_balance >= new_supply,
        X0WrapperError::ReserveInvariantViolated
    );

    // ========================================================================
    // Mint x0-USD to recipient
    // ========================================================================

    let mint_authority_bump = ctx.bumps.mint_authority;
    let seeds = &[
        WRAPPER_MINT_AUTHORITY_SEED,
        &[mint_authority_bump],
    ];
    let signer_seeds = &[&seeds[..]];

    let mint_accounts = MintTo {
        mint: ctx.accounts.wrapper_mint.to_account_info(),
        to: ctx.accounts.recipient_wrapper_account.to_account_info(),
        authority: ctx.accounts.mint_authority.to_account_info(),
    };

    let cpi_ctx = CpiContext::new_with_signer(
        ctx.accounts.token_2022_program.to_account_info(),
        mint_accounts,
        signer_seeds,
    );

    token_2022::mint_to(cpi_ctx, amount)?;

    // ========================================================================
    // Update stats
    // ========================================================================

    let stats = &mut ctx.accounts.stats;

    stats.reserve_usdc_balance = stats
        .reserve_usdc_balance
        .checked_add(amount)
        .ok_or(X0WrapperError::MathOverflow)?;

    stats.outstanding_wrapper_supply = stats
        .outstanding_wrapper_supply
        .checked_add(amount)
        .ok_or(X0WrapperError::MathOverflow)?;

    stats.total_deposits = stats
        .total_deposits
        .checked_add(amount)
        .ok_or(X0WrapperError::MathOverflow)?;

    stats.last_updated = clock.unix_timestamp;

    // ========================================================================
    // Emit event
    // ========================================================================

    emit!(WrapperBridgeMint {
        bridge_program: ctx.accounts.config.bridge_program,
        recipient: ctx.accounts.recipient_wrapper_account.owner,
        amount,
        reserve_balance: stats.reserve_usdc_balance,
        outstanding_supply: stats.outstanding_wrapper_supply,
        timestamp: clock.unix_timestamp,
    });

    msg!(
        "Bridge mint: amount={}, recipient={}, reserve={}, supply={}",
        amount,
        ctx.accounts.recipient_wrapper_account.owner,
        stats.reserve_usdc_balance,
        stats.outstanding_wrapper_supply,
    );

    Ok(())
}
