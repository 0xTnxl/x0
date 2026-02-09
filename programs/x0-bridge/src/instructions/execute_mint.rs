//! Execute minting of x0-USD for a verified bridge deposit (Step 3)
//!
//! After both the Hyperlane message is received (Step 1) and the STARK
//! proof is verified (Step 2), this instruction mints x0-USD to the
//! recipient via CPI to x0-wrapper's `bridge_mint`.
//!
//! # CPI Flow
//!
//! 1. Transfer USDC from bridge_usdc_reserve → wrapper's USDC reserve
//! 2. CPI into x0-wrapper::bridge_mint — wrapper validates reserve
//!    invariant and mints x0-USD to the recipient
//!
//! This preserves the 1:1 reserve invariant (reserve >= supply).
//!
//! # Permissionless
//!
//! Anyone can call this to execute mints for verified messages.
//! This enables keeper services to process bridge deposits automatically.

use anchor_lang::prelude::*;
use anchor_spl::token_2022::Token2022;
use anchor_spl::token_interface::{Mint, TokenAccount, TokenInterface, TransferChecked};

use x0_wrapper::cpi::accounts::BridgeMint as WrapperBridgeMintAccounts;
use x0_wrapper::program::X0Wrapper;

use crate::state::{BridgeConfig, BridgeMessage, BridgeMessageStatus, EVMProofContext};
use x0_common::{
    constants::*,
    error::X0BridgeError,
    events::BridgeMintExecuted,
};

#[derive(Accounts)]
pub struct ExecuteMint<'info> {
    /// Payer for transaction fees (keeper/relayer)
    #[account(mut)]
    pub payer: Signer<'info>,

    /// Bridge configuration
    #[account(
        mut,
        seeds = [BRIDGE_CONFIG_SEED],
        bump = config.bump,
        constraint = !config.is_paused @ X0BridgeError::BridgePaused,
    )]
    pub config: Box<Account<'info, BridgeConfig>>,

    /// The verified bridge message
    #[account(
        mut,
        seeds = [BRIDGE_MESSAGE_SEED, &bridge_message.message_id],
        bump = bridge_message.bump,
        constraint = bridge_message.status == BridgeMessageStatus::ProofVerified
            @ X0BridgeError::InvalidMessageStatus,
    )]
    pub bridge_message: Box<Account<'info, BridgeMessage>>,

    /// The verified EVM proof context
    #[account(
        seeds = [EVM_PROOF_CONTEXT_SEED, &bridge_message.message_id],
        bump = proof_context.bump,
        constraint = proof_context.verified @ X0BridgeError::ProofNotVerified,
        constraint = proof_context.message_id == bridge_message.message_id
            @ X0BridgeError::ProofMessageMismatch,
    )]
    pub proof_context: Box<Account<'info, EVMProofContext>>,

    // ========================================================================
    // Bridge reserve accounts (source of USDC)
    // ========================================================================

    /// Bridge's USDC reserve (source)
    #[account(
        mut,
        constraint = bridge_usdc_reserve.key() == config.bridge_usdc_reserve
            @ X0BridgeError::InsufficientBridgeReserve,
    )]
    pub bridge_usdc_reserve: Box<InterfaceAccount<'info, TokenAccount>>,

    /// Bridge reserve authority PDA (signer for reserve transfers & CPI)
    /// CHECK: PDA validated by seeds
    #[account(
        seeds = [BRIDGE_RESERVE_AUTHORITY_SEED],
        bump,
    )]
    pub bridge_reserve_authority: UncheckedAccount<'info>,

    // ========================================================================
    // x0-wrapper CPI accounts (typed via Anchor CPI)
    // ========================================================================

    /// x0-wrapper config PDA
    /// CHECK: Validated by x0-wrapper during CPI
    #[account(
        constraint = wrapper_config.key() == config.wrapper_config
            @ X0BridgeError::InvalidWrapperProgram,
    )]
    pub wrapper_config: UncheckedAccount<'info>,

    /// x0-wrapper stats PDA (mutable for CPI)
    /// CHECK: Validated by x0-wrapper during CPI
    #[account(mut)]
    pub wrapper_stats: UncheckedAccount<'info>,

    /// USDC mint
    #[account(
        constraint = usdc_mint.key() == config.usdc_mint,
    )]
    pub usdc_mint: Box<InterfaceAccount<'info, Mint>>,

    /// x0-USD wrapper mint (mutable for minting)
    #[account(
        mut,
        constraint = wrapper_mint.key() == config.wrapper_mint,
    )]
    pub wrapper_mint: Box<InterfaceAccount<'info, Mint>>,

    /// x0-wrapper's USDC reserve (destination for bridge USDC)
    #[account(mut)]
    pub wrapper_reserve_account: Box<InterfaceAccount<'info, TokenAccount>>,

    /// x0-wrapper's mint authority PDA
    /// CHECK: Validated by x0-wrapper during CPI
    pub wrapper_mint_authority: UncheckedAccount<'info>,

    /// Recipient's x0-USD token account (receives minted tokens)
    #[account(
        mut,
        constraint = recipient_wrapper_account.mint == config.wrapper_mint,
        constraint = recipient_wrapper_account.owner == bridge_message.recipient
            @ X0BridgeError::InvalidRecipient,
    )]
    pub recipient_wrapper_account: Box<InterfaceAccount<'info, TokenAccount>>,

    // ========================================================================
    // Programs
    // ========================================================================

    /// x0-wrapper program (typed for Anchor CPI)
    pub wrapper_program: Program<'info, X0Wrapper>,

    /// Token-2022 program for x0-USD mint
    pub token_2022_program: Program<'info, Token2022>,

    /// Token program for USDC transfers
    pub usdc_token_program: Interface<'info, TokenInterface>,
}

pub fn handler(ctx: Context<ExecuteMint>) -> Result<()> {
    let clock = Clock::get()?;
    let config = &mut ctx.accounts.config;
    let bridge_message = &mut ctx.accounts.bridge_message;
    let proof_context = &ctx.accounts.proof_context;

    // ========================================================================
    // Pre-validation
    // ========================================================================

    // Verify proof is fresh (within validity window)
    require!(
        proof_context.is_fresh(clock.unix_timestamp),
        X0BridgeError::ProofExpired
    );

    let amount = bridge_message.amount;

    // Verify bridge reserve has sufficient USDC liquidity
    require!(
        ctx.accounts.bridge_usdc_reserve.amount >= amount,
        X0BridgeError::InsufficientBridgeReserve
    );

    // ========================================================================
    // Step 1: Transfer USDC from bridge reserve → x0-wrapper reserve
    // ========================================================================

    let reserve_authority_bump = ctx.bumps.bridge_reserve_authority;
    let reserve_seeds = &[
        BRIDGE_RESERVE_AUTHORITY_SEED,
        &[reserve_authority_bump],
    ];
    let signer_seeds = &[&reserve_seeds[..]];

    let transfer_accounts = TransferChecked {
        from: ctx.accounts.bridge_usdc_reserve.to_account_info(),
        mint: ctx.accounts.usdc_mint.to_account_info(),
        to: ctx.accounts.wrapper_reserve_account.to_account_info(),
        authority: ctx.accounts.bridge_reserve_authority.to_account_info(),
    };

    anchor_spl::token_interface::transfer_checked(
        CpiContext::new_with_signer(
            ctx.accounts.usdc_token_program.to_account_info(),
            transfer_accounts,
            signer_seeds,
        ),
        amount,
        WRAPPER_DECIMALS,
    )?;

    // ========================================================================
    // Step 2: CPI to x0-wrapper::bridge_mint
    //
    // The wrapper's bridge_mint instruction:
    //   1. Validates bridge_signer is authorized (config.bridge_program)
    //   2. Verifies reserve invariant (reserve >= supply after mint)
    //   3. Mints x0-USD to recipient via mint authority PDA
    //   4. Updates wrapper stats atomically
    // ========================================================================

    let cpi_accounts = WrapperBridgeMintAccounts {
        bridge_signer: ctx.accounts.bridge_reserve_authority.to_account_info(),
        config: ctx.accounts.wrapper_config.to_account_info(),
        stats: ctx.accounts.wrapper_stats.to_account_info(),
        usdc_mint: ctx.accounts.usdc_mint.to_account_info(),
        wrapper_mint: ctx.accounts.wrapper_mint.to_account_info(),
        reserve_account: ctx.accounts.wrapper_reserve_account.to_account_info(),
        mint_authority: ctx.accounts.wrapper_mint_authority.to_account_info(),
        recipient_wrapper_account: ctx.accounts.recipient_wrapper_account.to_account_info(),
        token_2022_program: ctx.accounts.token_2022_program.to_account_info(),
    };

    let cpi_ctx = CpiContext::new_with_signer(
        ctx.accounts.wrapper_program.to_account_info(),
        cpi_accounts,
        signer_seeds, // bridge_reserve_authority PDA signs
    );

    x0_wrapper::cpi::bridge_mint(cpi_ctx, amount)?;

    msg!(
        "Minted {} x0-USD to {} via bridge CPI",
        amount,
        bridge_message.recipient,
    );

    // ========================================================================
    // Step 3: Update state
    // ========================================================================

    // Update bridge message to terminal state
    bridge_message.status = BridgeMessageStatus::Minted;

    // Update bridge totals
    config.total_bridged_in = config
        .total_bridged_in
        .checked_add(amount)
        .ok_or(X0BridgeError::MathOverflow)?;

    // ========================================================================
    // Step 4: Emit event
    // ========================================================================

    emit!(BridgeMintExecuted {
        message_pda: bridge_message.key(),
        message_id: bridge_message.message_id,
        recipient: bridge_message.recipient,
        amount,
        origin_domain: bridge_message.origin_domain,
        total_bridged_in: config.total_bridged_in,
        timestamp: clock.unix_timestamp,
    });

    msg!(
        "Bridge mint executed: message_id={}, recipient={}, amount={}",
        hex::encode(bridge_message.message_id),
        bridge_message.recipient,
        amount,
    );

    Ok(())
}
