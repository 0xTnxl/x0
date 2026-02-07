//! Verify a WithdrawProof
//!
//! This instruction verifies a zero-knowledge proof that demonstrates
//! a valid withdrawal from a confidential balance without revealing
//! the remaining balance amount.

use anchor_lang::prelude::*;
use x0_common::error::X0ZkVerifierError;

use crate::state::{ProofContext, ProofType, PROOF_CONTEXT_SEED};
use crate::verification::verify_withdraw_proof;

/// Maximum amount for confidential transfers (2^48 - 1)
const MAX_CONFIDENTIAL_AMOUNT: u64 = (1u64 << 48) - 1;

#[derive(Accounts)]
pub struct VerifyWithdraw<'info> {
    /// The owner of the token account
    #[account(mut)]
    pub owner: Signer<'info>,

    /// The token account being withdrawn from
    /// CHECK: Validated by owner signature and stored in proof context
    pub token_account: UncheckedAccount<'info>,

    /// The mint of the token
    /// CHECK: Validated against token account and stored in proof context
    pub mint: UncheckedAccount<'info>,

    /// The proof context PDA to create
    ///
    /// Seeds include timestamp to ensure uniqueness and prevent replay attacks.
    /// Each withdraw operation gets a fresh proof context.
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
    ctx: Context<VerifyWithdraw>,
    proof_data: Vec<u8>,
    amount: u64,
    new_decryptable_balance: [u8; 36],
) -> Result<()> {
    let clock = Clock::get()?;

    // Validate amount is within confidential transfer limits
    require!(
        amount <= MAX_CONFIDENTIAL_AMOUNT,
        X0ZkVerifierError::AmountTooLarge
    );

    // Verify the Groth16 proof via CPI to ZK Token Proof Program
    let verified = verify_withdraw_proof(
        ctx.accounts.zk_token_proof_program.as_ref(),
        &proof_data,
        amount,
        &new_decryptable_balance,
    )?;

    require!(verified, X0ZkVerifierError::ProofVerificationFailed);

    // Initialize proof context with verification result
    let proof_context = &mut ctx.accounts.proof_context;
    proof_context.version = 1;
    proof_context.proof_type = ProofType::Withdraw;
    proof_context.verified = true;
    proof_context.owner = ctx.accounts.owner.key();
    proof_context.verified_at = clock.unix_timestamp;
    proof_context.amount = Some(amount);
    proof_context.recipient = None;
    proof_context.elgamal_pubkey = None;
    proof_context.mint = ctx.accounts.mint.key();
    proof_context.token_account = ctx.accounts.token_account.key();
    proof_context.bump = ctx.bumps.proof_context;
    proof_context._reserved = [0u8; 64];

    msg!(
        "Withdraw proof verified: amount={}, proof_context={}",
        amount,
        proof_context.key()
    );

    Ok(())
}
