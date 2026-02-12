//! Initialize the x0-bridge configuration
//!
//! Uses a three-step pattern to avoid SBF stack overflow:
//!
//! 1. `create_config`  — allocates the BridgeConfig PDA (lightweight)
//! 2. `create_reserve` — creates the USDC reserve token account (lightweight)
//! 3. `initialize`     — populates the config via `#[account(zero)]`
//!
//! All three can be packed into a single transaction.

use anchor_lang::prelude::*;
use anchor_spl::token_interface::{Mint, TokenAccount, TokenInterface};

use crate::state::BridgeConfig;
use x0_common::{
    constants::*,
    error::X0BridgeError,
    events::BridgeInitialized,
};

// ============================================================================
// Step 1: Allocate config PDA only
// ============================================================================

/// Allocate the BridgeConfig PDA. Minimal struct — avoids BridgeConfig
/// deserialization entirely, keeping the stack frame small.
#[derive(Accounts)]
pub struct CreateConfig<'info> {
    #[account(mut)]
    pub admin: Signer<'info>,

    /// CHECK: We only allocate space here; `initialize` populates via `zero`.
    #[account(
        init,
        payer = admin,
        space = BridgeConfig::space(),
        seeds = [BRIDGE_CONFIG_SEED],
        bump,
        owner = crate::ID,
    )]
    pub config: UncheckedAccount<'info>,

    pub system_program: Program<'info, System>,
}

pub fn create_config_handler(ctx: Context<CreateConfig>) -> Result<()> {
    msg!("Bridge config PDA created: {}", ctx.accounts.config.key());
    Ok(())
}

// ============================================================================
// Step 2: Create the USDC reserve token account
// ============================================================================

/// Create the bridge USDC reserve token account (PDA-owned).
/// Separate from create_config to stay under the 4096-byte stack limit.
#[derive(Accounts)]
pub struct CreateReserve<'info> {
    #[account(mut)]
    pub admin: Signer<'info>,

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

    pub usdc_token_program: Interface<'info, TokenInterface>,
    pub system_program: Program<'info, System>,
}

pub fn create_reserve_handler(ctx: Context<CreateReserve>) -> Result<()> {
    // Validate USDC decimals
    require!(
        ctx.accounts.usdc_mint.decimals == WRAPPER_DECIMALS,
        X0BridgeError::InvalidWrapperProgram
    );
    msg!(
        "Bridge USDC reserve created: {}",
        ctx.accounts.bridge_usdc_reserve.key()
    );
    Ok(())
}

// ============================================================================
// Step 3: Populate the config (uses `zero` — no init stack pressure)
// ============================================================================

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(mut)]
    pub admin: Signer<'info>,

    /// Config PDA (already allocated by create_config).
    /// `zero` checks discriminator is all-zero and writes it, but
    /// skips the heavy `init` codegen.
    #[account(
        zero,
        seeds = [BRIDGE_CONFIG_SEED],
        bump,
    )]
    pub config: Box<Account<'info, BridgeConfig>>,

    pub usdc_mint: Box<InterfaceAccount<'info, Mint>>,

    /// Bridge USDC reserve (already created by create_reserve)
    #[account(
        seeds = [BRIDGE_RESERVE_SEED, usdc_mint.key().as_ref()],
        bump,
    )]
    pub bridge_usdc_reserve: Box<InterfaceAccount<'info, TokenAccount>>,
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

    // Build fixed-size arrays from input Vecs
    let mut evm_contracts_arr = [[0u8; EVM_ADDRESS_SIZE]; MAX_ALLOWED_EVM_CONTRACTS];
    for (i, contract) in allowed_evm_contracts.iter().enumerate() {
        evm_contracts_arr[i] = *contract;
    }

    let mut domains_arr = [0u32; MAX_SUPPORTED_DOMAINS];
    for (i, domain) in supported_domains.iter().enumerate() {
        domains_arr[i] = *domain;
    }

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
    config.allowed_evm_contracts_count = allowed_evm_contracts.len() as u8;
    config.allowed_evm_contracts = evm_contracts_arr;
    config.supported_domains_count = supported_domains.len() as u8;
    config.supported_domains = domains_arr;
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
        &config.supported_domains[..config.supported_domains_count as usize],
    );

    Ok(())
}
