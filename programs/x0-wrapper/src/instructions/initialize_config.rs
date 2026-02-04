//! Initialize the x0-USD wrapper config (Phase 1)
//!
//! This instruction creates:
//! 1. The WrapperConfig PDA
//! 2. The WrapperStats PDA

use anchor_lang::prelude::*;

use crate::state::{WrapperConfig, WrapperStats};
use x0_common::{
    constants::*,
    error::X0WrapperError,
};

#[derive(Accounts)]
pub struct InitializeConfig<'info> {
    /// The admin who will control the wrapper (should be multisig)
    #[account(mut)]
    pub admin: Signer<'info>,

    /// The wrapper configuration PDA
    #[account(
        init,
        payer = admin,
        space = WrapperConfig::space(),
        seeds = [WRAPPER_CONFIG_SEED],
        bump,
    )]
    pub config: Box<Account<'info, WrapperConfig>>,

    /// The wrapper stats PDA
    #[account(
        init,
        payer = admin,
        space = WrapperStats::space(),
        seeds = [WRAPPER_STATS_SEED],
        bump,
    )]
    pub stats: Box<Account<'info, WrapperStats>>,

    /// The USDC mint address (just the pubkey, not loaded)
    /// CHECK: Validated in handler
    pub usdc_mint: UncheckedAccount<'info>,

    /// System program
    pub system_program: Program<'info, System>,
}

pub fn handler(ctx: Context<InitializeConfig>, redemption_fee_bps: u16) -> Result<()> {
    // Validate fee rate
    require!(
        redemption_fee_bps >= MIN_WRAPPER_FEE_BPS && redemption_fee_bps <= MAX_WRAPPER_FEE_BPS,
        X0WrapperError::FeeRateTooHigh
    );

    let clock = Clock::get()?;

    // Derive wrapper mint PDA (for storing in config)
    let usdc_mint_key = ctx.accounts.usdc_mint.key();
    let (wrapper_mint, _) = Pubkey::find_program_address(
        &[b"wrapper_mint", usdc_mint_key.as_ref()],
        ctx.program_id,
    );

    // Derive reserve account PDA (for storing in config)
    let (reserve_account, _) = Pubkey::find_program_address(
        &[WRAPPER_RESERVE_SEED, usdc_mint_key.as_ref()],
        ctx.program_id,
    );

    // Initialize config
    let config = &mut ctx.accounts.config;
    config.admin = ctx.accounts.admin.key();
    config.pending_admin = None;
    config.usdc_mint = usdc_mint_key;
    config.wrapper_mint = wrapper_mint;
    config.reserve_account = reserve_account;
    config.redemption_fee_bps = redemption_fee_bps;
    config.is_paused = false;
    config.bump = ctx.bumps.config;
    config._reserved = [0u8; 64];

    // Initialize stats
    let stats = &mut ctx.accounts.stats;
    stats.reserve_usdc_balance = 0;
    stats.outstanding_wrapper_supply = 0;
    stats.total_deposits = 0;
    stats.total_redemptions = 0;
    stats.total_fees_collected = 0;
    stats.daily_redemption_volume = 0;
    stats.daily_redemption_reset_timestamp = clock.unix_timestamp;
    stats.last_updated = clock.unix_timestamp;
    stats.bump = ctx.bumps.stats;
    stats._reserved = [0u8; 64];

    msg!(
        "Config initialized: usdc_mint={}, fee_bps={}",
        config.usdc_mint,
        config.redemption_fee_bps
    );

    Ok(())
}
