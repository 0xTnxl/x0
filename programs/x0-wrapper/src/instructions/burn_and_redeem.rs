//! Burn x0-USD and redeem USDC
//!
//! This instruction atomically:
//! 1. Validates reserve invariant BEFORE any changes
//! 2. Updates state BEFORE transfers (reentrancy protection)
//! 3. Burns x0-USD from user
//! 4. Calculates payout with fee (rounds DOWN to protect reserve)
//! 5. Transfers USDC from reserve to user
//! 6. Emits RedemptionCompleted event
//!
//! Fee: 0.8% by default (configurable via timelock)

use anchor_lang::prelude::*;
use anchor_spl::token_2022::{self, Token2022, Burn};
use anchor_spl::token_interface::{Mint, TokenAccount, TokenInterface, TransferChecked};

use crate::state::{WrapperConfig, WrapperStats};
use x0_common::{
    constants::*,
    error::X0WrapperError,
    events::{RedemptionCompleted, ReserveAlert, AlertLevel},
};

#[derive(Accounts)]
pub struct BurnAndRedeem<'info> {
    /// The user redeeming x0-USD
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

    /// User's wrapper token account (source - will be burned, boxed)
    #[account(
        mut,
        constraint = user_wrapper_account.mint == config.wrapper_mint,
        constraint = user_wrapper_account.owner == user.key(),
    )]
    pub user_wrapper_account: Box<InterfaceAccount<'info, TokenAccount>>,

    /// User's USDC token account (destination, boxed)
    #[account(
        mut,
        constraint = user_usdc_account.mint == config.usdc_mint,
        constraint = user_usdc_account.owner == user.key(),
    )]
    pub user_usdc_account: Box<InterfaceAccount<'info, TokenAccount>>,

    /// The USDC reserve account (boxed)
    #[account(
        mut,
        constraint = reserve_account.key() == config.reserve_account @ X0WrapperError::InsufficientReserve,
    )]
    pub reserve_account: Box<InterfaceAccount<'info, TokenAccount>>,

    /// The reserve authority PDA
    /// CHECK: PDA that owns the reserve
    #[account(
        seeds = [b"reserve_authority"],
        bump,
    )]
    pub reserve_authority: UncheckedAccount<'info>,

    /// Token-2022 program for wrapper mint
    pub token_2022_program: Program<'info, Token2022>,

    /// Token program for USDC
    pub usdc_token_program: Interface<'info, TokenInterface>,
}

/// Calculate fee and payout with checked math
/// Returns (fee, payout) or error
fn calculate_payout(amount: u64, fee_bps: u16) -> Result<(u64, u64)> {
    // fee = amount * fee_bps / 10000 (rounds DOWN)
    let fee = amount
        .checked_mul(fee_bps as u64)
        .and_then(|f| f.checked_div(FEE_DENOMINATOR))
        .ok_or(X0WrapperError::MathOverflow)?;
    
    // payout = amount - fee
    let payout = amount
        .checked_sub(fee)
        .ok_or(X0WrapperError::MathUnderflow)?;
    
    Ok((fee, payout))
}

pub fn handler(ctx: Context<BurnAndRedeem>, amount: u64) -> Result<()> {
    let clock = Clock::get()?;
    let config = &ctx.accounts.config;
    let stats = &mut ctx.accounts.stats;

    // ========================================================================
    // Pre-validation checks
    // ========================================================================

    // Check minimum amount
    require!(
        amount >= MIN_REDEMPTION_AMOUNT,
        X0WrapperError::RedemptionTooSmall
    );

    // Check per-transaction limit
    require!(
        amount <= MAX_REDEMPTION_PER_TX,
        X0WrapperError::RedemptionTooLarge
    );

    // Reset daily counter if needed
    stats.maybe_reset_daily_counter(clock.unix_timestamp);

    // Check daily limit
    let new_daily_volume = stats
        .daily_redemption_volume
        .checked_add(amount)
        .ok_or(X0WrapperError::MathOverflow)?;
    
    require!(
        new_daily_volume <= MAX_DAILY_REDEMPTIONS,
        X0WrapperError::DailyRedemptionLimitExceeded
    );

    // Calculate payout with fee
    let (fee, payout) = calculate_payout(amount, config.redemption_fee_bps)?;

    // ========================================================================
    // CRITICAL: Validate reserve BEFORE allowing redemption
    // ========================================================================
    
    // Check that reserve has sufficient balance for payout
    require!(
        stats.reserve_usdc_balance >= payout,
        X0WrapperError::InsufficientReserve
    );

    // Validate reserve invariant: reserve >= supply (after this redemption)
    let new_reserve = stats
        .reserve_usdc_balance
        .checked_sub(payout)
        .ok_or(X0WrapperError::MathUnderflow)?;
    
    let new_supply = stats
        .outstanding_wrapper_supply
        .checked_sub(amount)
        .ok_or(X0WrapperError::MathUnderflow)?;
    
    // After redemption: reserve should still be >= supply
    // (Actually reserve >= supply should hold because fee stays in reserve)
    // But we add the fee to reserve tracking explicitly
    let new_reserve_with_fee = new_reserve
        .checked_add(fee)
        .ok_or(X0WrapperError::MathOverflow)?;
    
    // This should always be true if math is correct, but verify anyway
    require!(
        new_reserve_with_fee >= new_supply,
        X0WrapperError::ReserveInvariantViolated
    );

    // ========================================================================
    // CRITICAL-2 FIX: Update state BEFORE transfers (reentrancy protection)
    // ========================================================================

    // Update all stats atomically before any external calls
    stats.reserve_usdc_balance = new_reserve; // Fee stays in reserve conceptually
    stats.outstanding_wrapper_supply = new_supply;
    stats.total_redemptions = stats
        .total_redemptions
        .checked_add(amount)
        .ok_or(X0WrapperError::MathOverflow)?;
    stats.total_fees_collected = stats
        .total_fees_collected
        .checked_add(fee)
        .ok_or(X0WrapperError::MathOverflow)?;
    stats.daily_redemption_volume = new_daily_volume;
    stats.last_updated = clock.unix_timestamp;

    // ========================================================================
    // Step 1: Burn x0-USD from user
    // ========================================================================

    let burn_accounts = Burn {
        mint: ctx.accounts.wrapper_mint.to_account_info(),
        from: ctx.accounts.user_wrapper_account.to_account_info(),
        authority: ctx.accounts.user.to_account_info(),
    };

    let cpi_ctx = CpiContext::new(
        ctx.accounts.token_2022_program.to_account_info(),
        burn_accounts,
    );

    token_2022::burn(cpi_ctx, amount)?;

    // ========================================================================
    // Step 2: Transfer USDC from reserve to user
    // ========================================================================

    let reserve_authority_bump = ctx.bumps.reserve_authority;
    let seeds = &[
        b"reserve_authority".as_ref(),
        &[reserve_authority_bump],
    ];
    let signer_seeds = &[&seeds[..]];

    let transfer_accounts = TransferChecked {
        from: ctx.accounts.reserve_account.to_account_info(),
        mint: ctx.accounts.usdc_mint.to_account_info(),
        to: ctx.accounts.user_usdc_account.to_account_info(),
        authority: ctx.accounts.reserve_authority.to_account_info(),
    };

    let cpi_ctx = CpiContext::new_with_signer(
        ctx.accounts.usdc_token_program.to_account_info(),
        transfer_accounts,
        signer_seeds,
    );

    anchor_spl::token_interface::transfer_checked(cpi_ctx, payout, WRAPPER_DECIMALS)?;

    // ========================================================================
    // Step 3: Check for reserve warnings and emit events
    // ========================================================================

    // Check reserve ratio and emit warning if needed
    if let Some(ratio) = stats.reserve_ratio_scaled() {
        if ratio < MIN_RESERVE_RATIO_SCALED {
            emit!(ReserveAlert {
                reserve_ratio: ratio,
                reserve_balance: stats.reserve_usdc_balance,
                outstanding_supply: stats.outstanding_wrapper_supply,
                severity: AlertLevel::Critical,
                timestamp: clock.unix_timestamp,
            });
        } else if ratio < RESERVE_WARNING_THRESHOLD {
            emit!(ReserveAlert {
                reserve_ratio: ratio,
                reserve_balance: stats.reserve_usdc_balance,
                outstanding_supply: stats.outstanding_wrapper_supply,
                severity: AlertLevel::Warning,
                timestamp: clock.unix_timestamp,
            });
        }
    }

    emit!(RedemptionCompleted {
        user: ctx.accounts.user.key(),
        amount_burned: amount,
        usdc_paid: payout,
        fee_collected: fee,
        reserve_balance: stats.reserve_usdc_balance,
        outstanding_supply: stats.outstanding_wrapper_supply,
        timestamp: clock.unix_timestamp,
    });

    msg!(
        "Redemption completed: user={}, burned={}, paid={}, fee={}",
        ctx.accounts.user.key(),
        amount,
        payout,
        fee
    );

    Ok(())
}
