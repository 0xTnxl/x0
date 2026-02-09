//! Replenish the bridge USDC reserve
//!
//! Anyone can deposit USDC into the bridge's reserve account to provide
//! the liquidity needed for minting x0-USD when bridge messages arrive.
//!
//! The reserve is consumed when execute_mint CPIs into x0-wrapper,
//! transferring USDC from the bridge reserve into the wrapper's reserve.
//!
//! Reserve replenishment sources:
//! - Protocol treasury
//! - Arbitrageurs / market makers
//! - Circle CCTP settlement (Base USDC → Solana USDC)

use anchor_lang::prelude::*;
use anchor_spl::token_interface::{Mint, TokenAccount, TokenInterface, TransferChecked};

use crate::state::BridgeConfig;
use x0_common::{
    constants::*,
    error::X0BridgeError,
};

#[derive(Accounts)]
pub struct ReplenishReserve<'info> {
    /// The USDC depositor
    #[account(mut)]
    pub depositor: Signer<'info>,

    /// Bridge configuration
    #[account(
        seeds = [BRIDGE_CONFIG_SEED],
        bump = config.bump,
    )]
    pub config: Box<Account<'info, BridgeConfig>>,

    /// USDC mint
    #[account(
        constraint = usdc_mint.key() == config.usdc_mint,
    )]
    pub usdc_mint: Box<InterfaceAccount<'info, Mint>>,

    /// Depositor's USDC token account (source)
    #[account(
        mut,
        constraint = depositor_usdc_account.mint == config.usdc_mint,
        constraint = depositor_usdc_account.owner == depositor.key(),
    )]
    pub depositor_usdc_account: Box<InterfaceAccount<'info, TokenAccount>>,

    /// Bridge USDC reserve (destination)
    #[account(
        mut,
        constraint = bridge_usdc_reserve.key() == config.bridge_usdc_reserve
            @ X0BridgeError::InsufficientBridgeReserve,
    )]
    pub bridge_usdc_reserve: Box<InterfaceAccount<'info, TokenAccount>>,

    /// Token program for USDC
    pub usdc_token_program: Interface<'info, TokenInterface>,
}

pub fn handler(ctx: Context<ReplenishReserve>, amount: u64) -> Result<()> {
    // Validate minimum amount (same as bridge minimum)
    require!(
        amount >= MIN_BRIDGE_AMOUNT,
        X0BridgeError::AmountTooSmall
    );

    // Transfer USDC from depositor to bridge reserve
    let transfer_accounts = TransferChecked {
        from: ctx.accounts.depositor_usdc_account.to_account_info(),
        mint: ctx.accounts.usdc_mint.to_account_info(),
        to: ctx.accounts.bridge_usdc_reserve.to_account_info(),
        authority: ctx.accounts.depositor.to_account_info(),
    };

    let cpi_ctx = CpiContext::new(
        ctx.accounts.usdc_token_program.to_account_info(),
        transfer_accounts,
    );

    anchor_spl::token_interface::transfer_checked(cpi_ctx, amount, WRAPPER_DECIMALS)?;

    msg!(
        "Bridge reserve replenished: depositor={}, amount={}, new_balance={}",
        ctx.accounts.depositor.key(),
        amount,
        ctx.accounts.bridge_usdc_reserve.amount + amount,
    );

    Ok(())
}
