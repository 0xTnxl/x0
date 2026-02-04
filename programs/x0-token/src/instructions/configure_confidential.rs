//! Configure confidential transfer extension on the mint
//!
//! This enables the ConfidentialTransferMint extension, allowing token holders
//! to opt into confidential (encrypted) balances and transfers using ElGamal
//! encryption and zero-knowledge proofs.
//!
//! Note: The actual ZK cryptography setup (ElGamal keypair generation, proofs)
//! must be done client-side as it requires heavy cryptographic operations
//! not suitable for on-chain execution. This instruction only sets up the
//! mint-level configuration.

use anchor_lang::prelude::*;
use anchor_lang::solana_program::program::invoke;
use anchor_spl::token_2022::Token2022;
use spl_token_2022::extension::confidential_transfer::instruction::initialize_mint as ct_initialize_mint;

/// Accounts for configuring confidential transfers on the mint
#[derive(Accounts)]
pub struct ConfigureConfidential<'info> {
    /// The authority that can configure the mint (typically mint authority)
    pub authority: Signer<'info>,

    /// The mint to configure - must have ConfidentialTransferMint extension space allocated
    /// CHECK: Validated as Token-2022 mint
    #[account(mut)]
    pub mint: UncheckedAccount<'info>,

    /// Token-2022 program
    pub token_program: Program<'info, Token2022>,
}

pub fn handler(
    ctx: Context<ConfigureConfidential>,
    auto_approve_new_accounts: bool,
) -> Result<()> {
    // Note: The auditor ElGamal pubkey requires client-side ZK SDK setup.
    // For this instruction, we pass None for auditor - it can be updated later
    // via update_mint if needed. The full auditor setup requires:
    // 1. Client generates ElGamalKeypair using solana-zk-token-sdk
    // 2. Client serializes the pubkey and passes to update_mint instruction
    //
    // This initial configuration enables confidential transfers without an auditor.

    // Build the initialize confidential transfer mint instruction
    // This sets up the mint to support confidential transfers
    let init_ct_ix = ct_initialize_mint(
        &spl_token_2022::ID,
        ctx.accounts.mint.key,
        Some(ctx.accounts.authority.key()), // authority to modify confidential transfer params
        auto_approve_new_accounts,          // whether new accounts auto-approved for CT
        None,                               // auditor - set to None, can be configured later
    )?;

    invoke(
        &init_ct_ix,
        &[
            ctx.accounts.mint.to_account_info(),
            ctx.accounts.authority.to_account_info(),
        ],
    )?;

    msg!(
        "Confidential transfers configured on mint: {}, auto_approve={}",
        ctx.accounts.mint.key(),
        auto_approve_new_accounts,
    );

    Ok(())
}
