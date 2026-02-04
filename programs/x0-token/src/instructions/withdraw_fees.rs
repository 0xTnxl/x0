//! Withdraw collected transfer fees from Token-2022 accounts
//!
//! The TransferFee extension withholds fees in sender accounts during transfers.
//! This instruction harvests those withheld fees to the protocol treasury.

use anchor_lang::prelude::*;
use anchor_lang::solana_program::program::invoke;
use anchor_spl::token_2022::Token2022;
use spl_token_2022::extension::transfer_fee::instruction::{
    harvest_withheld_tokens_to_mint,
    withdraw_withheld_tokens_from_mint,
};

/// Accounts for withdrawing fees
#[derive(Accounts)]
pub struct WithdrawFees<'info> {
    /// The withdraw withheld authority (set during mint initialization)
    pub authority: Signer<'info>,

    /// The x0-Token mint
    /// CHECK: Validated as Token-2022 mint with TransferFeeConfig extension
    #[account(mut)]
    pub mint: UncheckedAccount<'info>,

    /// The destination for withdrawn fees (protocol treasury)
    /// CHECK: Validated as Token-2022 token account for this mint
    #[account(mut)]
    pub destination: UncheckedAccount<'info>,

    /// Token-2022 program
    pub token_program: Program<'info, Token2022>,
}

/// First step: Harvest withheld fees from token accounts to the mint
/// This collects fees from multiple accounts into the mint's withheld amount
pub fn handler_harvest<'info>(
    ctx: Context<'_, '_, 'info, 'info, WithdrawFees<'info>>,
) -> Result<()> {
    // Collect remaining accounts as source token accounts with withheld fees
    if ctx.remaining_accounts.is_empty() {
        msg!("No source accounts to harvest from");
        return Ok(());
    }

    // Collect pubkey references for the instruction
    let source_pubkeys: Vec<&Pubkey> = ctx.remaining_accounts
        .iter()
        .map(|a| a.key)
        .collect();

    // Build the harvest instruction
    // This moves withheld tokens from source accounts to the mint
    let harvest_ix = harvest_withheld_tokens_to_mint(
        &spl_token_2022::ID,
        ctx.accounts.mint.key,
        source_pubkeys.as_slice(),
    )?;

    // Collect account infos for CPI
    let mut account_infos = vec![ctx.accounts.mint.to_account_info()];
    for source in ctx.remaining_accounts {
        account_infos.push(source.clone());
    }

    invoke(&harvest_ix, &account_infos)?;

    msg!(
        "Harvested withheld fees from {} accounts to mint",
        ctx.remaining_accounts.len()
    );

    Ok(())
}

/// Second step: Withdraw harvested fees from mint to treasury
pub fn handler(ctx: Context<WithdrawFees>) -> Result<()> {
    // Withdraw all withheld tokens from the mint to the destination
    let withdraw_ix = withdraw_withheld_tokens_from_mint(
        &spl_token_2022::ID,
        ctx.accounts.mint.key,
        ctx.accounts.destination.key,
        ctx.accounts.authority.key,
        &[], // No additional multisig signers
    )?;

    invoke(
        &withdraw_ix,
        &[
            ctx.accounts.mint.to_account_info(),
            ctx.accounts.destination.to_account_info(),
            ctx.accounts.authority.to_account_info(),
        ],
    )?;

    msg!(
        "Withdrew withheld fees from mint to treasury: {}",
        ctx.accounts.destination.key()
    );

    Ok(())
}
