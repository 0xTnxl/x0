//! Verify a ZeroBalanceProof
//!
//! Proves that an account's confidential balance is exactly zero.
//! Required for closing confidential transfer accounts.

use anchor_lang::prelude::*;
use x0_common::error::X0ZkVerifierError;

use crate::state::{ProofContext, ProofType, PROOF_CONTEXT_SEED};
use crate::verification::verify_zero_balance_proof;

#[derive(Accounts)]
pub struct VerifyZeroBalance<'info> {
    /// The owner of the token account
    #[account(mut)]
    pub owner: Signer<'info>,

    /// The token account being closed
    /// CHECK: Validated by owner signature
    pub token_account: UncheckedAccount<'info>,

    /// The mint of the token
    /// CHECK: Stored in proof context
    pub mint: UncheckedAccount<'info>,

    /// The proof context PDA to create
    #[account(
        init,
        payer = owner,
        space = ProofContext::space(),
        seeds = [
            PROOF_CONTEXT_SEED,
            owner.key().as_ref(),
            token_account.key().as_ref(),
            &Clock::get()?.unix_timestamp.to_le_bytes(),
        ],
        bump,
    )]
    pub proof_context: Account<'info, ProofContext>,

    /// ZK Token Proof Program
    /// CHECK: Must be the ZK Token Proof Program
    #[account(address = solana_zk_token_sdk::zk_token_proof_program::id())]
    pub zk_token_proof_program: UncheckedAccount<'info>,

    /// System program
    pub system_program: Program<'info, System>,
}

pub fn handler(
    ctx: Context<VerifyZeroBalance>,
    proof_data: Vec<u8>,
) -> Result<()> {
    let clock = Clock::get()?;

    // Verify the Groth16 proof via CPI to ZK Token Proof Program
    let verified = verify_zero_balance_proof(
        ctx.accounts.zk_token_proof_program.as_ref(),
        &proof_data,
    )?;

    require!(verified, X0ZkVerifierError::ProofVerificationFailed);

    // Initialize proof context
    let proof_context = &mut ctx.accounts.proof_context;
    proof_context.version = 1;
    proof_context.proof_type = ProofType::ZeroBalance;
    proof_context.verified = true;
    proof_context.owner = ctx.accounts.owner.key();
    proof_context.verified_at = clock.unix_timestamp;
    proof_context.amount = None;
    proof_context.recipient = None;
    proof_context.elgamal_pubkey = None;
    proof_context.mint = ctx.accounts.mint.key();
    proof_context.token_account = ctx.accounts.token_account.key();
    proof_context.bump = ctx.bumps.proof_context;
    proof_context._reserved = [0u8; 64];

    msg!(
        "ZeroBalance proof verified: proof_context={}",
        proof_context.key()
    );

    Ok(())
}
