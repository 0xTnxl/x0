//! Initialize the x0-Token mint with Token-2022 extensions

use anchor_lang::prelude::*;
use anchor_lang::solana_program::program::invoke;
use anchor_spl::token_2022::Token2022;
use spl_token_2022::{
    extension::{
        transfer_fee::instruction::initialize_transfer_fee_config,
        transfer_hook::instruction::initialize as initialize_transfer_hook,
        ExtensionType,
    },
    instruction::initialize_mint2,
    state::Mint,
};

use x0_common::constants::*;

/// The x0_guard program ID for transfer hook
pub const X0_GUARD_PROGRAM_ID: &str = "x0Grd1111111111111111111111111111111111111111";

/// Accounts for initializing the x0-Token mint
#[derive(Accounts)]
pub struct InitializeMint<'info> {
    /// The payer for account creation
    #[account(mut)]
    pub payer: Signer<'info>,

    /// The mint authority (will be the protocol admin)
    pub mint_authority: Signer<'info>,

    /// The mint account to initialize
    /// CHECK: This will be initialized as a Token-2022 mint
    #[account(mut)]
    pub mint: Signer<'info>,

    /// The fee receiver account (treasury)
    /// CHECK: This is the protocol treasury
    pub fee_receiver: UncheckedAccount<'info>,

    /// Token-2022 program
    pub token_program: Program<'info, Token2022>,

    /// System program
    pub system_program: Program<'info, System>,

    /// Rent sysvar
    pub rent: Sysvar<'info, Rent>,
}

pub fn handler(
    ctx: Context<InitializeMint>,
    decimals: u8,
    enable_confidential: bool,
) -> Result<()> {
    let mint = &ctx.accounts.mint;
    let payer = &ctx.accounts.payer;
    let _token_program = &ctx.accounts.token_program; // Unused: using raw invoke calls
    let system_program = &ctx.accounts.system_program;

    // Calculate required space for mint with extensions
    let mut extensions = vec![
        ExtensionType::TransferHook,
        ExtensionType::TransferFeeConfig,
    ];

    if enable_confidential {
        extensions.push(ExtensionType::ConfidentialTransferMint);
    }

    let space = ExtensionType::try_calculate_account_len::<Mint>(&extensions)
        .map_err(|_| ProgramError::InvalidAccountData)?;

    // Create the mint account
    let rent = Rent::get()?;
    let lamports = rent.minimum_balance(space);

    let create_account_ix = anchor_lang::solana_program::system_instruction::create_account(
        payer.key,
        mint.key,
        lamports,
        space as u64,
        &spl_token_2022::ID,
    );

    invoke(
        &create_account_ix,
        &[
            payer.to_account_info(),
            mint.to_account_info(),
            system_program.to_account_info(),
        ],
    )?;

    // Initialize Transfer Hook extension
    let guard_program_id = X0_GUARD_PROGRAM_ID.parse::<Pubkey>().unwrap();
    let init_hook_ix = initialize_transfer_hook(
        &spl_token_2022::ID,
        mint.key,
        Some(ctx.accounts.mint_authority.key()),
        Some(guard_program_id),
    )?;

    invoke(
        &init_hook_ix,
        &[
            mint.to_account_info(),
            ctx.accounts.mint_authority.to_account_info(),
        ],
    )?;

    // Initialize Transfer Fee extension
    // Fee: 0.8% = 80 basis points
    // Maximum fee: u64::MAX (no cap)
    let init_fee_ix = initialize_transfer_fee_config(
        &spl_token_2022::ID,
        mint.key,
        Some(&ctx.accounts.mint_authority.key()), // transfer fee config authority
        Some(&ctx.accounts.fee_receiver.key()),   // withdraw withheld authority
        PROTOCOL_FEE_BASIS_POINTS,                // 80 basis points = 0.8%
        u64::MAX,                                  // no maximum fee cap
    )?;

    invoke(
        &init_fee_ix,
        &[
            mint.to_account_info(),
            ctx.accounts.mint_authority.to_account_info(),
        ],
    )?;

    // Initialize the mint itself
    let init_mint_ix = initialize_mint2(
        &spl_token_2022::ID,
        mint.key,
        &ctx.accounts.mint_authority.key(),
        None, // No freeze authority
        decimals,
    )?;

    invoke(
        &init_mint_ix,
        &[mint.to_account_info()],
    )?;

    msg!(
        "x0-Token mint initialized: mint={}, decimals={}, confidential={}",
        mint.key(),
        decimals,
        enable_confidential
    );

    Ok(())
}
