//! Execute emergency withdrawal

use anchor_lang::prelude::*;
use anchor_spl::token_interface::{TokenAccount, TokenInterface, TransferChecked, Mint};

use crate::state::{AdminAction, AdminActionType, WrapperConfig, WrapperStats};
use x0_common::{
    constants::*,
    error::X0WrapperError,
    events::{AdminActionExecuted, EmergencyWithdrawal},
};

#[derive(Accounts)]
pub struct ExecuteEmergencyWithdraw<'info> {
    /// The admin (must be current admin)
    #[account(
        constraint = admin.key() == config.admin @ X0WrapperError::Unauthorized,
    )]
    pub admin: Signer<'info>,

    /// The wrapper configuration (boxed to reduce stack usage)
    #[account(
        mut,
        seeds = [WRAPPER_CONFIG_SEED],
        bump = config.bump,
    )]
    pub config: Box<Account<'info, WrapperConfig>>,

    /// The wrapper stats (boxed)
    #[account(
        mut,
        seeds = [WRAPPER_STATS_SEED],
        bump = stats.bump,
    )]
    pub stats: Box<Account<'info, WrapperStats>>,

    /// The admin action PDA (boxed)
    #[account(
        mut,
        constraint = !action.executed @ X0WrapperError::AdminActionAlreadyExecuted,
        constraint = !action.cancelled @ X0WrapperError::AdminActionCancelled,
    )]
    pub action: Box<Account<'info, AdminAction>>,

    /// The USDC mint (boxed)
    pub usdc_mint: Box<InterfaceAccount<'info, Mint>>,

    /// The USDC reserve account (boxed)
    #[account(
        mut,
        constraint = reserve_account.key() == config.reserve_account,
    )]
    pub reserve_account: Box<InterfaceAccount<'info, TokenAccount>>,

    /// The destination token account (boxed)
    #[account(
        mut,
        constraint = destination_account.mint == config.usdc_mint,
        constraint = destination_account.key() == action.destination,
    )]
    pub destination_account: Box<InterfaceAccount<'info, TokenAccount>>,

    /// The reserve authority PDA
    /// CHECK: PDA that owns the reserve
    #[account(
        seeds = [b"reserve_authority"],
        bump,
    )]
    pub reserve_authority: UncheckedAccount<'info>,

    /// Token program for USDC
    pub usdc_token_program: Interface<'info, TokenInterface>,
}

pub fn handler(ctx: Context<ExecuteEmergencyWithdraw>) -> Result<()> {
    let clock = Clock::get()?;
    let action = &mut ctx.accounts.action;
    let stats = &mut ctx.accounts.stats;

    // Verify action type
    require!(
        action.action_type == AdminActionType::EmergencyWithdraw,
        X0WrapperError::InvalidActionType
    );

    // Verify timelock has expired
    require!(
        clock.unix_timestamp >= action.scheduled_timestamp,
        X0WrapperError::TimelockNotExpired
    );

    let amount = action.new_value;
    
    // Verify sufficient reserve
    require!(
        stats.reserve_usdc_balance >= amount,
        X0WrapperError::InsufficientReserve
    );

    // Update stats BEFORE transfer (reentrancy protection)
    stats.reserve_usdc_balance = stats
        .reserve_usdc_balance
        .checked_sub(amount)
        .ok_or(X0WrapperError::MathUnderflow)?;
    stats.last_updated = clock.unix_timestamp;

    action.executed = true;

    // Transfer USDC from reserve to destination
    let reserve_authority_bump = ctx.bumps.reserve_authority;
    let seeds = &[
        b"reserve_authority".as_ref(),
        &[reserve_authority_bump],
    ];
    let signer_seeds = &[&seeds[..]];

    let transfer_accounts = TransferChecked {
        from: ctx.accounts.reserve_account.to_account_info(),
        mint: ctx.accounts.usdc_mint.to_account_info(),
        to: ctx.accounts.destination_account.to_account_info(),
        authority: ctx.accounts.reserve_authority.to_account_info(),
    };

    let cpi_ctx = CpiContext::new_with_signer(
        ctx.accounts.usdc_token_program.to_account_info(),
        transfer_accounts,
        signer_seeds,
    );

    anchor_spl::token_interface::transfer_checked(cpi_ctx, amount, WRAPPER_DECIMALS)?;

    emit!(EmergencyWithdrawal {
        config: ctx.accounts.config.key(),
        amount,
        destination: ctx.accounts.destination_account.key(),
        admin: ctx.accounts.admin.key(),
        timestamp: clock.unix_timestamp,
    });

    emit!(AdminActionExecuted {
        action: action.key(),
        action_type: "EmergencyWithdraw".to_string(),
        admin: ctx.accounts.admin.key(),
        timestamp: clock.unix_timestamp,
    });

    msg!(
        "Emergency withdrawal executed: amount={}, destination={}",
        amount,
        ctx.accounts.destination_account.key()
    );

    Ok(())
}
