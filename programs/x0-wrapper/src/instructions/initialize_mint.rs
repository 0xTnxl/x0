//! Initialize the x0-USD wrapper mint and reserve (Phase 2)
//!
//! This instruction creates:
//! 1. The x0-USD mint with Token-2022 + Transfer Hook extension
//! 2. The USDC reserve token account
//!
//! The Transfer Hook points to x0-guard, making x0-USD the standard
//! token that all AI agents interact with. Every transfer is validated
//! by x0-guard's policy enforcement.
//!
//! Must be called after initialize_config

use anchor_lang::prelude::*;
use anchor_lang::solana_program::program::invoke;
use anchor_lang::system_program;
use anchor_spl::token_2022::{self, Token2022};
use anchor_spl::token_interface::{Mint, TokenAccount, TokenInterface};
use spl_token_2022::{
    extension::{transfer_hook::instruction::initialize as initialize_transfer_hook, ExtensionType},
    state::Mint as MintState,
};

use crate::state::WrapperConfig;
use x0_common::{
    constants::*,
    error::X0WrapperError,
    events::WrapperInitialized,
};

#[derive(Accounts)]
pub struct InitializeMint<'info> {
    /// The admin who will control the wrapper (must match config.admin)
    #[account(mut)]
    pub admin: Signer<'info>,

    /// The wrapper configuration PDA (must be initialized)
    #[account(
        mut,
        seeds = [WRAPPER_CONFIG_SEED],
        bump = config.bump,
        constraint = config.admin == admin.key() @ X0WrapperError::Unauthorized,
    )]
    pub config: Box<Account<'info, WrapperConfig>>,

    /// The USDC mint
    #[account(
        constraint = usdc_mint.key() == config.usdc_mint @ X0WrapperError::InvalidUsdcMint,
        constraint = usdc_mint.decimals == WRAPPER_DECIMALS @ X0WrapperError::DecimalMismatch,
    )]
    pub usdc_mint: Box<InterfaceAccount<'info, Mint>>,

    /// The x0-USD wrapper mint (to be created via CPI)
    /// CHECK: Will be initialized as Token-2022 mint via CPI
    #[account(
        mut,
        seeds = [b"wrapper_mint", usdc_mint.key().as_ref()],
        bump,
    )]
    pub wrapper_mint: UncheckedAccount<'info>,

    /// The mint authority PDA
    /// CHECK: PDA that will be mint authority
    #[account(
        seeds = [WRAPPER_MINT_AUTHORITY_SEED],
        bump,
    )]
    pub mint_authority: UncheckedAccount<'info>,

    /// The USDC reserve account (PDA-owned)
    #[account(
        init,
        payer = admin,
        token::mint = usdc_mint,
        token::authority = reserve_authority,
        token::token_program = usdc_token_program,
        seeds = [WRAPPER_RESERVE_SEED, usdc_mint.key().as_ref()],
        bump,
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

    /// Token program for USDC (could be Token or Token-2022)
    pub usdc_token_program: Interface<'info, TokenInterface>,

    /// System program
    pub system_program: Program<'info, System>,

    /// Rent sysvar
    pub rent: Sysvar<'info, Rent>,
}

pub fn handler(ctx: Context<InitializeMint>) -> Result<()> {
    let clock = Clock::get()?;

    // Calculate space for Token-2022 mint WITH TransferHook extension
    let extensions = vec![ExtensionType::TransferHook];
    let mint_size = ExtensionType::try_calculate_account_len::<MintState>(&extensions)
        .map_err(|_| X0WrapperError::InvalidMintConfiguration)?;
    
    let rent = ctx.accounts.rent.minimum_balance(mint_size);

    // Derive wrapper_mint bump for PDA signer
    let usdc_mint_key = ctx.accounts.usdc_mint.key();
    let wrapper_mint_bump = ctx.bumps.wrapper_mint;
    let wrapper_mint_seeds = &[
        b"wrapper_mint" as &[u8],
        usdc_mint_key.as_ref(),
        &[wrapper_mint_bump],
    ];

    // Create the wrapper mint account owned by Token-2022
    system_program::create_account(
        CpiContext::new_with_signer(
            ctx.accounts.system_program.to_account_info(),
            system_program::CreateAccount {
                from: ctx.accounts.admin.to_account_info(),
                to: ctx.accounts.wrapper_mint.to_account_info(),
            },
            &[wrapper_mint_seeds],
        ),
        rent,
        mint_size as u64,
        &spl_token_2022::id(),
    )?;

    // Initialize Transfer Hook extension pointing to x0-guard
    // This makes x0-USD the standard token for AI agent transactions
    let init_hook_ix = initialize_transfer_hook(
        &spl_token_2022::id(),
        &ctx.accounts.wrapper_mint.key(),
        Some(ctx.accounts.mint_authority.key()), // hook authority
        Some(GUARD_PROGRAM_ID),                   // x0-guard validates all transfers!
    )?;

    invoke(
        &init_hook_ix,
        &[ctx.accounts.wrapper_mint.to_account_info()],
    )?;

    // Initialize the mint with Token-2022
    let cpi_accounts = token_2022::InitializeMint2 {
        mint: ctx.accounts.wrapper_mint.to_account_info(),
    };
    let cpi_ctx = CpiContext::new(
        ctx.accounts.token_2022_program.to_account_info(),
        cpi_accounts,
    );
    token_2022::initialize_mint2(
        cpi_ctx,
        WRAPPER_DECIMALS,
        &ctx.accounts.mint_authority.key(),
        Some(&ctx.accounts.mint_authority.key()),
    )?;

    // Update config with wrapper_mint and reserve_account
    let config = &mut ctx.accounts.config;
    config.wrapper_mint = ctx.accounts.wrapper_mint.key();
    config.reserve_account = ctx.accounts.reserve_account.key();

    emit!(WrapperInitialized {
        config: config.key(),
        usdc_mint: config.usdc_mint,
        wrapper_mint: config.wrapper_mint,
        reserve_account: config.reserve_account,
        admin: config.admin,
        timestamp: clock.unix_timestamp,
    });

    msg!(
        "x0-USD initialized with transfer hook -> x0-guard: wrapper_mint={}, reserve={}",
        config.wrapper_mint,
        config.reserve_account
    );

    Ok(())
}
