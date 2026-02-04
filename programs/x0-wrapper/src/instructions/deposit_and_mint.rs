//! Deposit USDC and mint x0-USD
//!
//! This instruction atomically:
//! 1. Transfers USDC from user to reserve PDA
//! 2. Mints x0-USD to user at 1:1 ratio
//! 3. Updates stats
//! 4. Emits DepositMinted event
//!
//! No fee is charged on deposits to encourage adoption.

use anchor_lang::prelude::*;
use anchor_spl::token_2022::{self, Token2022, MintTo};
use anchor_spl::token_interface::{Mint, TokenAccount, TokenInterface, TransferChecked};

use crate::state::{WrapperConfig, WrapperStats};
use x0_common::{
    constants::*,
    error::X0WrapperError,
    events::DepositMinted,
};

#[derive(Accounts)]
pub struct DepositAndMint<'info> {
    /// The user depositing USDC
    #[account(mut)]
    pub user: Signer<'info>,

    /// The wrapper configuration (boxed to reduce stack usage)
    #[account(
        seeds = [WRAPPER_CONFIG_SEED],
        bump = config.bump,
        constraint = !config.is_paused @ X0WrapperError::WrapperPaused,
    )]
    pub config: Box<Account<'info, WrapperConfig>>,

    /// The wrapper stats (mutable for updating, boxed)
    #[account(
        mut,
        seeds = [WRAPPER_STATS_SEED],
        bump = stats.bump,
    )]
    pub stats: Box<Account<'info, WrapperStats>>,

    /// The USDC mint (boxed)
    #[account(
        constraint = usdc_mint.key() == config.usdc_mint @ X0WrapperError::InvalidUsdcMint,
    )]
    pub usdc_mint: Box<InterfaceAccount<'info, Mint>>,

    /// The wrapper (x0-USD) mint (boxed)
    #[account(
        mut,
        constraint = wrapper_mint.key() == config.wrapper_mint @ X0WrapperError::InvalidWrapperMint,
    )]
    pub wrapper_mint: Box<InterfaceAccount<'info, Mint>>,

    /// User's USDC token account (source, boxed)
    #[account(
        mut,
        constraint = user_usdc_account.mint == config.usdc_mint,
        constraint = user_usdc_account.owner == user.key(),
    )]
    pub user_usdc_account: Box<InterfaceAccount<'info, TokenAccount>>,

    /// User's wrapper token account (destination, boxed)
    #[account(
        mut,
        constraint = user_wrapper_account.mint == config.wrapper_mint,
        constraint = user_wrapper_account.owner == user.key(),
    )]
    pub user_wrapper_account: Box<InterfaceAccount<'info, TokenAccount>>,

    /// The USDC reserve account (boxed)
    #[account(
        mut,
        constraint = reserve_account.key() == config.reserve_account @ X0WrapperError::InsufficientReserve,
    )]
    pub reserve_account: Box<InterfaceAccount<'info, TokenAccount>>,

    /// The mint authority PDA (same derivation as initialize_mint)
    /// CHECK: PDA that is the mint authority
    #[account(
        seeds = [WRAPPER_MINT_AUTHORITY_SEED],
        bump,
    )]
    pub mint_authority: UncheckedAccount<'info>,

    /// Token-2022 program for wrapper mint
    pub token_2022_program: Program<'info, Token2022>,

    /// Token program for USDC
    pub usdc_token_program: Interface<'info, TokenInterface>,
}

pub fn handler(ctx: Context<DepositAndMint>, amount: u64) -> Result<()> {
    let clock = Clock::get()?;

    // Validate amount
    require!(
        amount >= MIN_DEPOSIT_AMOUNT,
        X0WrapperError::DepositTooSmall
    );

    // ========================================================================
    // Step 1: Transfer USDC from user to reserve
    // ========================================================================
    
    let transfer_accounts = TransferChecked {
        from: ctx.accounts.user_usdc_account.to_account_info(),
        mint: ctx.accounts.usdc_mint.to_account_info(),
        to: ctx.accounts.reserve_account.to_account_info(),
        authority: ctx.accounts.user.to_account_info(),
    };

    let cpi_ctx = CpiContext::new(
        ctx.accounts.usdc_token_program.to_account_info(),
        transfer_accounts,
    );

    anchor_spl::token_interface::transfer_checked(cpi_ctx, amount, WRAPPER_DECIMALS)?;

    // ========================================================================
    // Step 2: Mint x0-USD to user (1:1 ratio)
    // ========================================================================

    let mint_authority_bump = ctx.bumps.mint_authority;
    let seeds = &[
        WRAPPER_MINT_AUTHORITY_SEED,
        &[mint_authority_bump],
    ];
    let signer_seeds = &[&seeds[..]];

    let mint_accounts = MintTo {
        mint: ctx.accounts.wrapper_mint.to_account_info(),
        to: ctx.accounts.user_wrapper_account.to_account_info(),
        authority: ctx.accounts.mint_authority.to_account_info(),
    };

    let cpi_ctx = CpiContext::new_with_signer(
        ctx.accounts.token_2022_program.to_account_info(),
        mint_accounts,
        signer_seeds,
    );

    token_2022::mint_to(cpi_ctx, amount)?;

    // ========================================================================
    // Step 3: Update stats
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
    // Step 4: Emit event
    // ========================================================================

    emit!(DepositMinted {
        user: ctx.accounts.user.key(),
        usdc_amount: amount,
        wrapper_minted: amount,
        reserve_balance: stats.reserve_usdc_balance,
        outstanding_supply: stats.outstanding_wrapper_supply,
        timestamp: clock.unix_timestamp,
    });

    msg!(
        "Deposit completed: user={}, amount={}, new_reserve={}, new_supply={}",
        ctx.accounts.user.key(),
        amount,
        stats.reserve_usdc_balance,
        stats.outstanding_wrapper_supply
    );

    Ok(())
}
