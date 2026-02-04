//! Deposit tokens from public balance to confidential (encrypted) balance
//!
//! This instruction moves tokens from the account's public (visible) balance
//! into its encrypted confidential balance. The deposited tokens will appear
//! in the account's "pending" balance until apply_pending_balance is called.
//!
//! ## Flow
//! 1. Account has public balance of X tokens
//! 2. User calls deposit_confidential(amount)
//! 3. Public balance decreases by amount
//! 4. Confidential pending balance increases (encrypted)
//! 5. User calls apply_pending_balance to make tokens available

use anchor_lang::prelude::*;
use anchor_lang::solana_program::program::invoke;
use anchor_spl::token_2022::Token2022;
use spl_token_2022::{
    extension::{
        confidential_transfer::{
            ConfidentialTransferAccount,
            instruction::deposit,
        },
        BaseStateWithExtensions,
        StateWithExtensions,
    },
    state::Account as TokenAccount,
};

use x0_common::{
    constants::MAX_CONFIDENTIAL_AMOUNT,
    error::X0TokenError,
};

/// Accounts for depositing to confidential balance
#[derive(Accounts)]
pub struct DepositConfidential<'info> {
    /// The account owner (must sign)
    pub owner: Signer<'info>,

    /// The token account to deposit from/to
    /// Must be configured for confidential transfers
    /// CHECK: Validated as Token-2022 account with confidential transfer extension
    #[account(mut)]
    pub token_account: UncheckedAccount<'info>,

    /// The token mint
    /// CHECK: Validated as Token-2022 mint
    pub mint: UncheckedAccount<'info>,

    /// Token-2022 program
    pub token_program: Program<'info, Token2022>,
}

/// Deposit tokens from public balance to confidential balance
///
/// # Arguments
/// * `amount` - The amount of tokens to deposit (in base units)
/// * `decimals` - The token decimals (must match mint)
///
/// # Security
/// - Validates account is owned by signer
/// - Validates account is configured for confidential transfers
/// - Validates amount is within confidential transfer limits
/// - Validates sufficient public balance
pub fn handler(
    ctx: Context<DepositConfidential>,
    amount: u64,
    decimals: u8,
) -> Result<()> {
    let token_account = &ctx.accounts.token_account;
    let mint = &ctx.accounts.mint;
    let owner = &ctx.accounts.owner;

    // ========================================================================
    // Validation: Amount limits
    // ========================================================================

    require!(
        amount > 0,
        X0TokenError::InvalidTokenDecimals
    );

    require!(
        amount <= MAX_CONFIDENTIAL_AMOUNT,
        X0TokenError::AmountExceedsConfidentialMax
    );

    // ========================================================================
    // Validation: Token account ownership and configuration
    // ========================================================================

    require!(
        *token_account.owner == spl_token_2022::id(),
        X0TokenError::InvalidMintAuthority
    );

    let token_account_data = token_account.try_borrow_data()?;
    let token_account_state = StateWithExtensions::<TokenAccount>::unpack(&token_account_data)?;

    require!(
        token_account_state.base.owner == owner.key(),
        X0TokenError::InvalidMintAuthority
    );

    require!(
        token_account_state.base.mint == mint.key(),
        X0TokenError::InvalidMintAuthority
    );

    require!(
        token_account_state.base.amount >= amount,
        X0TokenError::ConfidentialBalanceInsufficient
    );

    let ct_account = token_account_state
        .get_extension::<ConfidentialTransferAccount>()
        .map_err(|_| X0TokenError::AccountNotConfiguredForConfidential)?;

    require!(
        bool::from(ct_account.approved),
        X0TokenError::AccountNotConfiguredForConfidential
    );

    require!(
        bool::from(ct_account.allow_confidential_credits),
        X0TokenError::ConfidentialCreditsDisabled
    );

    drop(token_account_data);

    // ========================================================================
    // Call Token-2022 Deposit
    // ========================================================================

    let deposit_ix = deposit(
        &spl_token_2022::id(),
        token_account.key,
        mint.key,
        amount,
        decimals,
        owner.key,
        &[],
    )?;

    invoke(
        &deposit_ix,
        &[
            token_account.to_account_info(),
            mint.to_account_info(),
            owner.to_account_info(),
        ],
    )?;

    msg!(
        "Deposited {} tokens to confidential balance: account={}",
        amount,
        token_account.key()
    );

    Ok(())
}
