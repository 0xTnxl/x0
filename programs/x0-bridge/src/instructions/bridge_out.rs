//! Initiate Bridge Out: burn x0-USD on Solana for USDC unlock on Base
//!
//! This instruction is called by users who want to bridge x0-USD from Solana
//! back to USDC on Base. It:
//!
//! 1. Validates the outbound bridge is not paused and limits are respected
//! 2. CPIs into x0-wrapper::bridge_burn to burn x0-USD and return USDC to bridge reserve
//! 3. Creates a BridgeOutMessage PDA recording the burn details
//! 4. The off-chain SP1 Solana prover reads this PDA to generate a STARK proof
//! 5. The X0UnlockContract on Base verifies the proof and releases USDC
//!
//! # Security
//!
//! - Per-transaction amount limits (same as inbound)
//! - Daily outflow rate limiting
//! - Circuit breaker on total_bridged_out
//! - EVM recipient validation (no zero address)
//! - Bridge pause check
//! - Monotonic nonce for ordering and replay prevention
//!
//! # Permissionless Verification
//!
//! After this instruction creates the BridgeOutMessage PDA, anyone can:
//! 1. Run the SP1 Solana prover to generate a STARK proof of the PDA's existence
//! 2. Submit the proof to X0UnlockContract.unlock() on Base
//! The unlock is permissionless given a valid proof — no trusted relayer needed.

use anchor_lang::prelude::*;
use anchor_spl::token_2022::Token2022;
use anchor_spl::token_interface::{Mint, TokenAccount, TokenInterface};

use x0_wrapper::cpi::accounts::BridgeBurn as WrapperBridgeBurnAccounts;
use x0_wrapper::program::X0Wrapper;

use crate::state::{BridgeConfig, BridgeOutMessage, BridgeOutStatus};
use x0_common::{
    constants::*,
    error::X0BridgeError,
    events::{BridgeOutInitiated, BridgeOutCircuitBreakerTriggered},
};

#[derive(Accounts)]
pub struct InitiateBridgeOut<'info> {
    /// The user burning x0-USD and initiating the bridge out
    #[account(mut)]
    pub user: Signer<'info>,

    /// Bridge configuration (mutable for nonce increment and rate limiting)
    #[account(
        mut,
        seeds = [BRIDGE_CONFIG_SEED],
        bump = config.bump,
        constraint = !config.is_paused @ X0BridgeError::BridgePaused,
    )]
    pub config: Box<Account<'info, BridgeConfig>>,

    /// BridgeOutMessage PDA — created to record this outbound transfer
    ///
    /// Seeds: ["bridge_out_message", nonce.to_le_bytes()]
    /// The nonce is read from config.bridge_out_nonce BEFORE increment.
    #[account(
        init,
        payer = user,
        space = BridgeOutMessage::space(),
        seeds = [BRIDGE_OUT_MESSAGE_SEED, &config.bridge_out_nonce.to_le_bytes()],
        bump,
    )]
    pub bridge_out_message: Box<Account<'info, BridgeOutMessage>>,

    // ========================================================================
    // Bridge reserve accounts
    // ========================================================================

    /// Bridge's USDC reserve (receives USDC from wrapper via CPI)
    #[account(
        mut,
        constraint = bridge_usdc_reserve.key() == config.bridge_usdc_reserve
            @ X0BridgeError::InsufficientBridgeReserve,
    )]
    pub bridge_usdc_reserve: Box<InterfaceAccount<'info, TokenAccount>>,

    /// Bridge reserve authority PDA (signer for CPI to wrapper)
    /// CHECK: PDA validated by seeds
    #[account(
        seeds = [BRIDGE_RESERVE_AUTHORITY_SEED],
        bump,
    )]
    pub bridge_reserve_authority: UncheckedAccount<'info>,

    // ========================================================================
    // x0-wrapper CPI accounts
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

    /// x0-USD wrapper mint (mutable for burning)
    #[account(
        mut,
        constraint = wrapper_mint.key() == config.wrapper_mint,
    )]
    pub wrapper_mint: Box<InterfaceAccount<'info, Mint>>,

    /// User's x0-USD token account (source — x0-USD burned from here)
    #[account(
        mut,
        constraint = user_wrapper_account.mint == config.wrapper_mint,
        constraint = user_wrapper_account.owner == user.key(),
    )]
    pub user_wrapper_account: Box<InterfaceAccount<'info, TokenAccount>>,

    /// x0-wrapper's USDC reserve (source of USDC sent to bridge reserve)
    #[account(mut)]
    pub wrapper_reserve_account: Box<InterfaceAccount<'info, TokenAccount>>,

    /// x0-wrapper's reserve authority PDA
    /// CHECK: Validated by x0-wrapper during CPI
    pub wrapper_reserve_authority: UncheckedAccount<'info>,

    // ========================================================================
    // Programs
    // ========================================================================

    /// x0-wrapper program (typed for Anchor CPI)
    pub wrapper_program: Program<'info, X0Wrapper>,

    /// Token-2022 program for x0-USD burn
    pub token_2022_program: Program<'info, Token2022>,

    /// Token program for USDC transfers
    pub usdc_token_program: Interface<'info, TokenInterface>,

    /// System program for PDA creation
    pub system_program: Program<'info, System>,
}

pub fn handler(
    ctx: Context<InitiateBridgeOut>,
    evm_recipient: [u8; 20],
    amount: u64,
) -> Result<()> {
    let clock = Clock::get()?;
    let config = &mut ctx.accounts.config;

    // ========================================================================
    // Pre-validation
    // ========================================================================

    // Validate EVM recipient is not zero address
    require!(
        evm_recipient != [0u8; 20],
        X0BridgeError::InvalidEvmRecipient
    );

    // Validate amount within limits
    require!(
        amount >= MIN_BRIDGE_OUT_AMOUNT,
        X0BridgeError::OutboundAmountTooSmall
    );
    require!(
        amount <= MAX_BRIDGE_OUT_AMOUNT_PER_TX,
        X0BridgeError::OutboundAmountTooLarge
    );

    // Reset daily outflow counter if 24 hours have passed
    config.maybe_reset_daily_outflow_counter(clock.unix_timestamp);

    // Check daily outflow limit
    let new_daily_outflow = config
        .daily_outflow_volume
        .checked_add(amount)
        .ok_or(X0BridgeError::MathOverflow)?;

    require!(
        new_daily_outflow <= MAX_DAILY_BRIDGE_OUTFLOW,
        X0BridgeError::DailyOutflowLimitExceeded
    );

    // Check user has sufficient x0-USD balance
    require!(
        ctx.accounts.user_wrapper_account.amount >= amount,
        X0BridgeError::InsufficientBridgeReserve
    );

    // ========================================================================
    // Step 1: CPI to x0-wrapper::bridge_burn
    //
    // The wrapper's bridge_burn instruction:
    //   1. Validates bridge_signer is authorized (config.bridge_program)
    //   2. Burns x0-USD from the user
    //   3. Transfers USDC from wrapper reserve → bridge reserve
    //   4. Updates wrapper stats
    // ========================================================================

    let reserve_authority_bump = ctx.bumps.bridge_reserve_authority;
    let reserve_seeds = &[
        BRIDGE_RESERVE_AUTHORITY_SEED,
        &[reserve_authority_bump],
    ];
    let signer_seeds = &[&reserve_seeds[..]];

    let cpi_accounts = WrapperBridgeBurnAccounts {
        bridge_signer: ctx.accounts.bridge_reserve_authority.to_account_info(),
        user: ctx.accounts.user.to_account_info(),
        config: ctx.accounts.wrapper_config.to_account_info(),
        stats: ctx.accounts.wrapper_stats.to_account_info(),
        usdc_mint: ctx.accounts.usdc_mint.to_account_info(),
        wrapper_mint: ctx.accounts.wrapper_mint.to_account_info(),
        user_wrapper_account: ctx.accounts.user_wrapper_account.to_account_info(),
        reserve_account: ctx.accounts.wrapper_reserve_account.to_account_info(),
        reserve_authority: ctx.accounts.wrapper_reserve_authority.to_account_info(),
        bridge_usdc_reserve: ctx.accounts.bridge_usdc_reserve.to_account_info(),
        token_2022_program: ctx.accounts.token_2022_program.to_account_info(),
        usdc_token_program: ctx.accounts.usdc_token_program.to_account_info(),
    };

    let cpi_ctx = CpiContext::new_with_signer(
        ctx.accounts.wrapper_program.to_account_info(),
        cpi_accounts,
        signer_seeds,
    );

    x0_wrapper::cpi::bridge_burn(cpi_ctx, amount)?;

    msg!(
        "Burned {} x0-USD from {} via wrapper CPI",
        amount,
        ctx.accounts.user.key(),
    );

    // ========================================================================
    // Step 2: Update bridge state
    // ========================================================================

    let current_nonce = config.bridge_out_nonce;

    // Update totals
    let new_total_bridged_out = config
        .total_bridged_out
        .checked_add(amount)
        .ok_or(X0BridgeError::MathOverflow)?;

    // ========================================================================
    // CIRCUIT BREAKER: Auto-pause if outbound threshold exceeded
    // ========================================================================

    if new_total_bridged_out > BRIDGE_OUT_CIRCUIT_BREAKER_THRESHOLD {
        config.is_paused = true;

        emit!(BridgeOutCircuitBreakerTriggered {
            config: ctx.accounts.config.key(),
            total_bridged_out: new_total_bridged_out,
            threshold: BRIDGE_OUT_CIRCUIT_BREAKER_THRESHOLD,
            timestamp: clock.unix_timestamp,
        });

        msg!(
            "OUTBOUND CIRCUIT BREAKER TRIGGERED: total_bridged_out={} exceeds threshold={}",
            new_total_bridged_out,
            BRIDGE_OUT_CIRCUIT_BREAKER_THRESHOLD,
        );

        return Err(X0BridgeError::OutboundCircuitBreakerTriggered.into());
    }

    config.total_bridged_out = new_total_bridged_out;
    config.daily_outflow_volume = new_daily_outflow;
    config.bridge_out_nonce = current_nonce
        .checked_add(1)
        .ok_or(X0BridgeError::MathOverflow)?;

    // ========================================================================
    // Step 3: Populate BridgeOutMessage PDA
    // ========================================================================

    let bridge_out_message = &mut ctx.accounts.bridge_out_message;
    bridge_out_message.version = 1;
    bridge_out_message.nonce = current_nonce;
    bridge_out_message.solana_sender = ctx.accounts.user.key();
    bridge_out_message.evm_recipient = evm_recipient;
    bridge_out_message.amount = amount;
    // Burn tx signature: use a deterministic placeholder — the actual Solana
    // tx signature is not available inside the program. The SP1 prover will
    // read this PDA's data and prove its existence, so the nonce serves as
    // the unique identifier instead.
    bridge_out_message.burn_tx_signature = [0u8; 32];
    bridge_out_message.burned_at = clock.unix_timestamp;
    bridge_out_message.status = BridgeOutStatus::Burned;
    bridge_out_message.bump = ctx.bumps.bridge_out_message;

    // ========================================================================
    // Step 4: Emit event
    // ========================================================================

    emit!(BridgeOutInitiated {
        message_pda: bridge_out_message.key(),
        nonce: current_nonce,
        solana_sender: ctx.accounts.user.key(),
        evm_recipient,
        amount,
        total_bridged_out: config.total_bridged_out,
        timestamp: clock.unix_timestamp,
    });

    msg!(
        "Bridge out initiated: nonce={}, sender={}, evm_recipient=0x{}, amount={}",
        current_nonce,
        ctx.accounts.user.key(),
        hex::encode(evm_recipient),
        amount,
    );

    Ok(())
}
