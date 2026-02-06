//! Initialize extra account metas for Transfer Hook

use anchor_lang::prelude::*;
use spl_tlv_account_resolution::{
    account::ExtraAccountMeta,
    seeds::Seed,
    state::ExtraAccountMetaList,
};
use spl_transfer_hook_interface::instruction::ExecuteInstruction;

use x0_common::constants::*;
use x0_common::error::X0GuardError;
use spl_token_2022::extension::StateWithExtensions;

// Import spl_token_2022 ID for ownership validation (HIGH-7)

/// Accounts for initializing extra account metas
#[derive(Accounts)]
pub struct InitializeExtraAccountMetas<'info> {
    /// The payer for account creation
    #[account(mut)]
    pub payer: Signer<'info>,

    /// The mint authority (MEDIUM-10: must match Token-2022 mint authority)
    pub mint_authority: Signer<'info>,

    /// The mint for which to initialize extra metas
    /// CHECK: Validated that it's owned by Token-2022 program (HIGH-7)
    #[account(
        constraint = *mint.owner == spl_token_2022::id() @ ProgramError::IllegalOwner
    )]
    pub mint: UncheckedAccount<'info>,

    /// The extra account metas PDA to create
    /// CHECK: Will be initialized with extra account meta data
    #[account(
        mut,
        seeds = [b"extra-account-metas", mint.key().as_ref()],
        bump,
    )]
    pub extra_account_metas: UncheckedAccount<'info>,

    /// System program
    pub system_program: Program<'info, System>,
}

pub fn handler(ctx: Context<InitializeExtraAccountMetas>) -> Result<()> {
    // MEDIUM-10 FIX: Prevent re-initialization by checking if account already has data
    // This prevents griefing by re-initializing with wrong configuration
    {
        let extra_metas_data = ctx.accounts.extra_account_metas.try_borrow_data()?;
        require!(
            extra_metas_data.iter().all(|&b| b == 0) || extra_metas_data.is_empty(),
            X0GuardError::ExtraMetasAlreadyInitialized
        );
    }

    // MEDIUM-10 FIX: Verify the signer is the mint authority
    {
        let mint_data = ctx.accounts.mint.try_borrow_data()?;
        let mint_state = StateWithExtensions::<spl_token_2022::state::Mint>::unpack(&mint_data)
            .map_err(|_| ProgramError::InvalidAccountData)?;

        match mint_state.base.mint_authority {
            spl_token_2022::solana_program::program_option::COption::Some(authority) => {
                require!(
                    ctx.accounts.mint_authority.key() == authority,
                    X0GuardError::UnauthorizedExtraMetasInitializer
                );
            }
            spl_token_2022::solana_program::program_option::COption::None => {
                return Err(ProgramError::InvalidAccountData.into());
            }
        }
    }

    // Define the extra accounts needed for transfer validation
    // 
    // The Transfer Hook Execute instruction receives these accounts:
    // 0: source (token account)
    // 1: mint
    // 2: destination (token account)
    // 3: source authority (owner/delegate - this is the agent signer)
    // 4: extra account metas PDA
    // 5+: additional accounts defined here
    //
    // We need to add:
    // - AgentPolicy PDA (derived from source authority via seeds)

    // Calculate required space
    let extra_metas_count = 1; // Just the AgentPolicy PDA for now
    let space = ExtraAccountMetaList::size_of(extra_metas_count)
        .map_err(|_| ProgramError::InvalidAccountData)?;

    // Create the extra account metas PDA
    let mint_key = ctx.accounts.mint.key();
    let seeds = &[
        b"extra-account-metas".as_ref(),
        mint_key.as_ref(),
        &[ctx.bumps.extra_account_metas],
    ];
    let signer_seeds = &[&seeds[..]];

    // Create account
    let rent = Rent::get()?;
    let lamports = rent.minimum_balance(space);

    anchor_lang::system_program::create_account(
        CpiContext::new_with_signer(
            ctx.accounts.system_program.to_account_info(),
            anchor_lang::system_program::CreateAccount {
                from: ctx.accounts.payer.to_account_info(),
                to: ctx.accounts.extra_account_metas.to_account_info(),
            },
            signer_seeds,
        ),
        lamports,
        space as u64,
        &crate::ID,
    )?;

    // Define the extra account metas
    // Account 0 (index 5 in the execute): AgentPolicy PDA
    // The PDA is derived from the SOURCE TOKEN ACCOUNT OWNER, not the authority
    //
    // Execute instruction accounts layout:
    // 0: source (token account)
    // 1: mint
    // 2: destination (token account)
    // 3: source_authority (the signer - could be owner or delegate/agent)
    // 4: extra_account_metas PDA
    // 5+: additional accounts defined here
    //
    // Token account layout (first 64 bytes):
    // bytes 0-31: mint pubkey
    // bytes 32-63: owner pubkey
    //
    // So we extract bytes 32-63 from account[0] to get the token account owner
    let extra_metas = [
        // AgentPolicy PDA derived from source token account's owner
        ExtraAccountMeta::new_with_seeds(
            &[
                // Literal seed: "agent_policy"
                Seed::Literal {
                    bytes: AGENT_POLICY_SEED.to_vec(),
                },
                // Account data seed: owner field from source token account (index 0)
                // Token account owner is at bytes 32-63
                Seed::AccountData {
                    account_index: 0,
                    data_index: 32,
                    length: 32,
                },
            ],
            false, // is_signer
            true,  // is_writable (for rolling window updates)
        )
        .map_err(|_| ProgramError::InvalidAccountData)?,
    ];

    // Write the extra account metas to the PDA
    let mut data = ctx.accounts.extra_account_metas.try_borrow_mut_data()?;
    ExtraAccountMetaList::init::<ExecuteInstruction>(&mut data, &extra_metas)
        .map_err(|_| ProgramError::InvalidAccountData)?;

    msg!(
        "Extra account metas initialized for mint: {}",
        ctx.accounts.mint.key()
    );

    Ok(())
}
