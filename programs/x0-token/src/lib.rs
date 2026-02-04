//! x0-token: Token-2022 mint configuration for x0-01 protocol
//!
//! This program manages the x0-Token mint with the following extensions:
//! 1. **Transfer Hook**: Routes every transfer through x0_guard for validation
//! 2. **Confidential Transfer**: Enables ZK-encrypted amounts using ElGamal
//! 3. **Transfer Fee**: Collects 0.8% protocol fee on every transfer
//!
//! ## Account-Level Confidential Transfer Operations
//!
//! The following operations should be performed directly via spl-token-2022:
//! - `configure_account` - Initialize account for confidential transfers
//! - `withdraw` - Move tokens from confidential to public balance
//! - `apply_pending_balance` - Make received confidential tokens spendable
//! - `empty_account` - Prove zero balance before closing
//!
//! These don't need x0-specific wrappers. The x0-guard transfer hook validates
//! all transfers regardless of whether they're confidential.

// Suppress cfg warnings from Anchor/Solana macros (toolchain version mismatch)
#![allow(unexpected_cfgs)]
// Suppress ambiguous glob re-export warnings (handlers have same name in different modules)
#![allow(ambiguous_glob_reexports)]

use anchor_lang::prelude::*;
use anchor_spl::token_2022::spl_token_2022::{
    extension::ExtensionType,
    state::Mint,
};

pub mod instructions;

pub use instructions::*;
pub use x0_common::{constants::*, error::X0TokenError, events::*};

declare_id!("EHHTCSyGkmnsBhGsvCmLzKgcSxtsN31ScrfiwcCbjHci");

#[program]
pub mod x0_token {
    use super::*;

    /// Initialize the x0-Token mint with all required extensions
    ///
    /// This creates a new Token-2022 mint configured with:
    /// - Transfer Hook pointing to x0_guard program
    /// - Confidential Transfer extension (optional)
    /// - Transfer Fee of 0.8% (80 basis points)
    ///
    /// # Arguments
    /// * `decimals` - Token decimals (recommended: 6)
    /// * `enable_confidential` - Whether to enable confidential transfers
    pub fn initialize_mint(
        ctx: Context<InitializeMint>,
        decimals: u8,
        enable_confidential: bool,
    ) -> Result<()> {
        instructions::initialize_mint::handler(ctx, decimals, enable_confidential)
    }

    /// Configure the confidential transfer extension
    ///
    /// Must be called after initialize_mint if confidential transfers are enabled.
    /// Sets up the mint to support encrypted balances and transfers.
    /// 
    /// Note: The auditor ElGamal pubkey must be configured separately client-side
    /// as it requires heavy ZK cryptographic operations. This instruction enables
    /// confidential transfers without an auditor initially.
    /// 
    /// # Arguments
    /// * `auto_approve_new_accounts` - Whether new accounts auto-approved for confidential transfers
    pub fn configure_confidential_transfers(
        ctx: Context<ConfigureConfidential>,
        auto_approve_new_accounts: bool,
    ) -> Result<()> {
        instructions::configure_confidential::handler(ctx, auto_approve_new_accounts)
    }

    /// Deposit tokens from public balance to confidential balance
    ///
    /// Moves tokens from visible balance to encrypted balance.
    /// Tokens will appear in pending until apply_pending_balance is called
    /// (via direct spl-token-2022 instruction).
    pub fn deposit_confidential(
        ctx: Context<DepositConfidential>,
        amount: u64,
        decimals: u8,
    ) -> Result<()> {
        instructions::deposit_confidential::handler(ctx, amount, decimals)
    }

    /// Mint tokens to an account
    ///
    /// Only callable by the mint authority.
    pub fn mint_tokens(ctx: Context<MintTokens>, amount: u64) -> Result<()> {
        instructions::mint_tokens::handler(ctx, amount)
    }

    /// Harvest withheld fees from token accounts to the mint
    ///
    /// Collects fees from source accounts and deposits them into the mint's
    /// withheld amount. Call this before withdraw_fees.
    ///
    /// Remaining accounts: The token accounts to harvest fees from.
    pub fn harvest_fees<'info>(ctx: Context<'_, '_, 'info, 'info, WithdrawFees<'info>>) -> Result<()> {
        instructions::withdraw_fees::handler_harvest(ctx)
    }

    /// Withdraw collected transfer fees
    ///
    /// Withdraws accumulated fees from the mint to the treasury account.
    /// Call harvest_fees first to collect fees from individual accounts.
    pub fn withdraw_fees(ctx: Context<WithdrawFees>) -> Result<()> {
        instructions::withdraw_fees::handler(ctx)
    }
}

/// Calculate the space required for a Token-2022 mint with extensions
pub fn calculate_mint_space(enable_confidential: bool) -> usize {
    let mut extensions = vec![
        ExtensionType::TransferHook,
        ExtensionType::TransferFeeConfig,
    ];

    if enable_confidential {
        extensions.push(ExtensionType::ConfidentialTransferMint);
    }

    ExtensionType::try_calculate_account_len::<Mint>(&extensions).unwrap()
}
