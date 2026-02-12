//! Bridge Burn: burn x0-USD and return USDC to bridge reserve
//!
//! This instruction is called via CPI from the x0-bridge program during
//! outbound bridging (Solana → Base). It:
//!
//! 1. Validates the caller is the authorized bridge program
//! 2. Burns x0-USD from the user's token account
//! 3. Transfers USDC from the wrapper reserve to the bridge's USDC reserve
//! 4. Updates wrapper stats
//!
//! # Security
//!
//! - Only the whitelisted `bridge_program` (stored in WrapperConfig) can call
//! - The user must have signed the outer transaction (bridge_out instruction)
//! - Reserve invariant is maintained: reserve >= supply after burn
//! - The bridge program's PDA signs the CPI call (same as bridge_mint)
//!
//! # Inverse of bridge_mint
//!
//! bridge_mint: bridge transfers USDC into wrapper reserve → wrapper mints x0-USD
//! bridge_burn: wrapper burns x0-USD → wrapper transfers USDC to bridge reserve

use anchor_lang::prelude::*;
use anchor_spl::token_2022::{self, Token2022, Burn};
use anchor_spl::token_interface::{Mint, TokenAccount, TokenInterface, TransferChecked};

use crate::state::{WrapperConfig, WrapperStats};
use x0_common::{
    constants::*,
    error::X0WrapperError,
    events::WrapperBridgeBurn,
};

#[derive(Accounts)]
pub struct BridgeBurn<'info> {
    /// The bridge authority PDA that signed this CPI call.
    ///
    /// SECURITY: Must match `config.bridge_program` exactly.
    /// This prevents unauthorized callers from burning x0-USD.
    /// The bridge program's PDA (bridge_reserve_authority) signs the CPI.
    #[account(
        constraint = bridge_signer.key() == config.bridge_program
            @ X0WrapperError::UnauthorizedBridgeProgram,
    )]
    pub bridge_signer: Signer<'info>,

    /// The user who is burning their x0-USD (must have signed outer tx)
    pub user: Signer<'info>,

    /// The wrapper configuration
    #[account(
        seeds = [WRAPPER_CONFIG_SEED],
        bump = config.bump,
        constraint = !config.is_paused @ X0WrapperError::WrapperPaused,
        constraint = config.bridge_program != Pubkey::default()
            @ X0WrapperError::BridgeBurnDisabled,
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

    /// The wrapper (x0-USD) mint (mutable for burning)
    #[account(
        mut,
        constraint = wrapper_mint.key() == config.wrapper_mint @ X0WrapperError::InvalidWrapperMint,
    )]
    pub wrapper_mint: Box<InterfaceAccount<'info, Mint>>,

    /// User's x0-USD token account (source — will be burned)
    #[account(
        mut,
        constraint = user_wrapper_account.mint == config.wrapper_mint,
        constraint = user_wrapper_account.owner == user.key(),
    )]
    pub user_wrapper_account: Box<InterfaceAccount<'info, TokenAccount>>,

    /// The wrapper's USDC reserve account (source of USDC to send to bridge)
    #[account(
        mut,
        constraint = reserve_account.key() == config.reserve_account
            @ X0WrapperError::InsufficientReserve,
    )]
    pub reserve_account: Box<InterfaceAccount<'info, TokenAccount>>,

    /// The reserve authority PDA (signer for USDC transfer out of reserve)
    /// CHECK: PDA that owns the reserve
    #[account(
        seeds = [b"reserve_authority"],
        bump,
    )]
    pub reserve_authority: UncheckedAccount<'info>,

    /// Bridge's USDC reserve account (destination for USDC)
    #[account(mut)]
    pub bridge_usdc_reserve: Box<InterfaceAccount<'info, TokenAccount>>,

    /// Token-2022 program for wrapper (x0-USD) burn
    pub token_2022_program: Program<'info, Token2022>,

    /// Token program for USDC transfers
    pub usdc_token_program: Interface<'info, TokenInterface>,
}

pub fn handler(ctx: Context<BridgeBurn>, amount: u64) -> Result<()> {
    let clock = Clock::get()?;

    // ========================================================================
    // Validate amount
    // ========================================================================

    require!(amount > 0, X0WrapperError::DepositTooSmall);

    // ========================================================================
    // Validate reserve has enough USDC to send to bridge
    // ========================================================================

    let reserve_balance = ctx.accounts.reserve_account.amount;
    require!(
        reserve_balance >= amount,
        X0WrapperError::InsufficientReserve
    );

    // Validate supply is sufficient for burn
    require!(
        ctx.accounts.stats.outstanding_wrapper_supply >= amount,
        X0WrapperError::InsufficientWrapperSupply
    );

    // ========================================================================
    // CRITICAL: Update state BEFORE transfers (reentrancy protection)
    // ========================================================================

    let stats = &mut ctx.accounts.stats;

    let new_reserve = stats
        .reserve_usdc_balance
        .checked_sub(amount)
        .ok_or(X0WrapperError::MathUnderflow)?;

    let new_supply = stats
        .outstanding_wrapper_supply
        .checked_sub(amount)
        .ok_or(X0WrapperError::MathUnderflow)?;

    // After burn: reserve should still be >= supply (no fee on bridge burn)
    require!(
        new_reserve >= new_supply,
        X0WrapperError::ReserveInvariantViolated
    );

    stats.reserve_usdc_balance = new_reserve;
    stats.outstanding_wrapper_supply = new_supply;
    stats.total_redemptions = stats
        .total_redemptions
        .checked_add(amount)
        .ok_or(X0WrapperError::MathOverflow)?;
    stats.last_updated = clock.unix_timestamp;

    // ========================================================================
    // Step 1: Burn x0-USD from user (user signed outer tx)
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
    // Step 2: Transfer USDC from wrapper reserve → bridge reserve
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
        to: ctx.accounts.bridge_usdc_reserve.to_account_info(),
        authority: ctx.accounts.reserve_authority.to_account_info(),
    };

    let cpi_ctx = CpiContext::new_with_signer(
        ctx.accounts.usdc_token_program.to_account_info(),
        transfer_accounts,
        signer_seeds,
    );

    anchor_spl::token_interface::transfer_checked(cpi_ctx, amount, WRAPPER_DECIMALS)?;

    // ========================================================================
    // Step 3: Emit event
    // ========================================================================

    emit!(WrapperBridgeBurn {
        bridge_program: ctx.accounts.config.bridge_program,
        user: ctx.accounts.user.key(),
        amount,
        usdc_transferred: amount,
        reserve_balance: stats.reserve_usdc_balance,
        outstanding_supply: stats.outstanding_wrapper_supply,
        timestamp: clock.unix_timestamp,
    });

    msg!(
        "Bridge burn: amount={}, user={}, reserve={}, supply={}",
        amount,
        ctx.accounts.user.key(),
        stats.reserve_usdc_balance,
        stats.outstanding_wrapper_supply,
    );

    Ok(())
}
