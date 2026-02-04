//! Mint tokens to an account

use anchor_lang::prelude::*;
use anchor_spl::token_2022::{self, MintTo, Token2022};

/// Accounts for minting tokens
#[derive(Accounts)]
pub struct MintTokens<'info> {
    /// The mint authority
    pub authority: Signer<'info>,

    /// The mint
    /// CHECK: Validated by Token-2022 program and ownership check (HIGH-7)
    #[account(
        mut,
        constraint = *mint.owner == spl_token_2022::id() @ ProgramError::IllegalOwner
    )]
    pub mint: UncheckedAccount<'info>,

    /// The destination token account
    /// CHECK: Validated by Token-2022 program and ownership check (HIGH-7)
    #[account(
        mut,
        constraint = *destination.owner == spl_token_2022::id() @ ProgramError::IllegalOwner
    )]
    pub destination: UncheckedAccount<'info>,

    /// Token-2022 program
    pub token_program: Program<'info, Token2022>,
}

pub fn handler(ctx: Context<MintTokens>, amount: u64) -> Result<()> {
    // Mint tokens using Token-2022
    let cpi_accounts = MintTo {
        mint: ctx.accounts.mint.to_account_info(),
        to: ctx.accounts.destination.to_account_info(),
        authority: ctx.accounts.authority.to_account_info(),
    };

    let cpi_ctx = CpiContext::new(
        ctx.accounts.token_program.to_account_info(),
        cpi_accounts,
    );

    token_2022::mint_to(cpi_ctx, amount)?;

    msg!(
        "Minted {} tokens to {}",
        amount,
        ctx.accounts.destination.key()
    );

    Ok(())
}
