//! Initialize the x0-bridge configuration
//!
//! Creates:
//! 1. BridgeConfig PDA - global bridge settings
//! 2. Bridge USDC reserve token account
//!
//! Must be called once by the initial admin before the bridge is operational.

use anchor_lang::prelude::*;
use anchor_spl::token_interface::{Mint, TokenAccount, TokenInterface};

use crate::state::BridgeConfig;
use x0_common::{
    constants::*,
    error::X0BridgeError,
    events::BridgeInitialized,
};

#[derive(Accounts)]
pub struct Initialize<'info> {
    /// The admin who will control the bridge (should be multisig)
    #[account(mut)]
    pub admin: Signer<'info>,

    /// The bridge configuration PDA
    #[account(
        init,
        payer = admin,
        space = BridgeConfig::space(),
        seeds = [BRIDGE_CONFIG_SEED],
        bump,
    )]
    pub config: Box<Account<'info, BridgeConfig>>,

    /// The USDC mint on Solana
    #[account(
        constraint = usdc_mint.decimals == WRAPPER_DECIMALS @ X0BridgeError::InvalidWrapperProgram,
    )]
    pub usdc_mint: Box<InterfaceAccount<'info, Mint>>,

    /// Bridge USDC reserve token account (PDA-owned)
    #[account(
        init,
        payer = admin,
        token::mint = usdc_mint,
        token::authority = reserve_authority,
        token::token_program = usdc_token_program,
        seeds = [BRIDGE_RESERVE_SEED, usdc_mint.key().as_ref()],
        bump,
    )]
    pub bridge_usdc_reserve: Box<InterfaceAccount<'info, TokenAccount>>,

    /// The reserve authority PDA (signs for USDC transfers out of reserve)
    /// CHECK: PDA that owns the reserve
    #[account(
        seeds = [BRIDGE_RESERVE_AUTHORITY_SEED],
        bump,
    )]
    pub reserve_authority: UncheckedAccount<'info>,

    /// Token program for USDC
    pub usdc_token_program: Interface<'info, TokenInterface>,

    /// System program
    pub system_program: Program<'info, System>,
}

#[allow(clippy::too_many_arguments)]
pub fn handler(
    ctx: Context<Initialize>,
    hyperlane_mailbox: Pubkey,
    sp1_verifier: Pubkey,
    wrapper_program: Pubkey,
    wrapper_config: Pubkey,
    wrapper_mint: Pubkey,
    allowed_evm_contracts: Vec<[u8; 20]>,
    supported_domains: Vec<u32>,
) -> Result<()> {
    let clock = Clock::get()?;

    // Validate contract list size
    require!(
        allowed_evm_contracts.len() <= MAX_ALLOWED_EVM_CONTRACTS,
        X0BridgeError::TooManyEVMContracts
    );

    // Validate domain list size
    require!(
        supported_domains.len() <= MAX_SUPPORTED_DOMAINS,
        X0BridgeError::TooManySupportedDomains
    );

    // Initialize config
    let config = &mut ctx.accounts.config;
    config.version = 1;
    config.admin = ctx.accounts.admin.key();
    config.hyperlane_mailbox = hyperlane_mailbox;
    config.sp1_verifier = sp1_verifier;
    config.wrapper_program = wrapper_program;
    config.wrapper_config = wrapper_config;
    config.usdc_mint = ctx.accounts.usdc_mint.key();
    config.wrapper_mint = wrapper_mint;
    config.bridge_usdc_reserve = ctx.accounts.bridge_usdc_reserve.key();
    config.is_paused = false;
    config.total_bridged_in = 0;
    config.total_bridged_out = 0;
    config.nonce = 0;
    config.daily_inflow_volume = 0;
    config.daily_inflow_reset_timestamp = clock.unix_timestamp;
    config.allowed_evm_contracts = allowed_evm_contracts;
    config.supported_domains = supported_domains;
    config.admin_action_nonce = 0;
    config.bump = ctx.bumps.config;
    config._reserved = [0u8; 56];

    emit!(BridgeInitialized {
        config: config.key(),
        admin: config.admin,
        hyperlane_mailbox: config.hyperlane_mailbox,
        sp1_verifier: config.sp1_verifier,
        usdc_mint: config.usdc_mint,
        timestamp: clock.unix_timestamp,
    });

    msg!(
        "Bridge initialized: admin={}, mailbox={}, domains={:?}",
        config.admin,
        config.hyperlane_mailbox,
        config.supported_domains,
    );

    Ok(())
}
