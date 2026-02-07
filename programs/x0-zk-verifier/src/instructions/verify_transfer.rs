//! Verify a TransferProof
//!
//! Verifies a confidential transfer between two accounts.

use anchor_lang::prelude::*;
use x0_common::error::X0ZkVerifierError;

use crate::state::{ProofContext, ProofType, PROOF_CONTEXT_SEED};
use crate::verification::verify_transfer_proof;

/// Maximum amount for confidential transfers (2^48 - 1)
const MAX_CONFIDENTIAL_AMOUNT: u64 = (1u64 << 48) - 1;

#[derive(Accounts)]
pub struct VerifyTransfer<'info> {
    /// The owner of the source token account
    #[account(mut)]
    pub owner: Signer<'info>,

    /// The source token account
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
    ctx: Context<VerifyTransfer>,
    proof_data: Vec<u8>,
    amount: u64,
    recipient: Pubkey,
) -> Result<()> {
    let clock = Clock::get()?;

    // Validate amount is within confidential transfer limits
    require!(
        amount <= MAX_CONFIDENTIAL_AMOUNT,
        X0ZkVerifierError::AmountTooLarge
    );

    // Verify the Transfer proof via CPI to ZK Token Proof Program
    let verified = verify_transfer_proof(
        ctx.accounts.zk_token_proof_program.as_ref(),
        &proof_data,
        amount,
        &recipient,
    )?;

    require!(verified, X0ZkVerifierError::ProofVerificationFailed);

    // Initialize proof context with verification result
    let proof_context = &mut ctx.accounts.proof_context;
    proof_context.version = 1;
    proof_context.proof_type = ProofType::Transfer;
    proof_context.verified = true;
    proof_context.owner = ctx.accounts.owner.key();
    proof_context.verified_at = clock.unix_timestamp;
    proof_context.amount = Some(amount);
    proof_context.recipient = Some(recipient);
    proof_context.elgamal_pubkey = None;
    proof_context.mint = ctx.accounts.mint.key();
    proof_context.token_account = ctx.accounts.token_account.key();
    proof_context.bump = ctx.bumps.proof_context;
    proof_context._reserved = [0u8; 64];

    msg!(
        "Transfer proof verified: amount={}, recipient={}, proof_context={}",
        amount,
        recipient,
        proof_context.key()
    );

    Ok(())
}
