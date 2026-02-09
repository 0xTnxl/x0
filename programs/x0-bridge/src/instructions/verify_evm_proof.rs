//! Verify an EVM transaction STARK proof (Step 2)
//!
//! Takes an SP1 STARK proof and verifies it via CPI to the SP1 verifier
//! program on Solana. Creates an EVMProofContext PDA linked to the
//! corresponding BridgeMessage.
//!
//! # Compute Budget
//!
//! STARK verification consumes ~500k compute units. This is why proof
//! verification and minting are separate instructions — combining them
//! would exceed Solana's ~1.4M CU transaction limit when factoring in
//! Token-2022 CPI overhead.
//!
//! # Permissionless
//!
//! Anyone can submit valid proofs. This enables keeper/relayer services
//! to operate without special permissions.

use anchor_lang::prelude::*;
use anchor_lang::solana_program::program::invoke;

use crate::state::{
    BridgeConfig, BridgeMessage, BridgeMessageStatus,
    EVMProofContext, EVMProofType, SP1PublicInputs,
};
use x0_common::{
    constants::*,
    error::X0BridgeError,
    events::BridgeProofVerified,
};

#[derive(Accounts)]
#[instruction(message_id: [u8; 32])]
pub struct VerifyEVMProof<'info> {
    /// Payer for proof context account creation
    #[account(mut)]
    pub payer: Signer<'info>,

    /// Bridge configuration (for SP1 verifier address)
    #[account(
        seeds = [BRIDGE_CONFIG_SEED],
        bump = config.bump,
        constraint = !config.is_paused @ X0BridgeError::BridgePaused,
    )]
    pub config: Box<Account<'info, BridgeConfig>>,

    /// The bridge message this proof is for
    #[account(
        mut,
        seeds = [BRIDGE_MESSAGE_SEED, &message_id],
        bump = bridge_message.bump,
        constraint = bridge_message.status == BridgeMessageStatus::Received
            @ X0BridgeError::InvalidMessageStatus,
    )]
    pub bridge_message: Box<Account<'info, BridgeMessage>>,

    /// EVM proof context PDA (created by this instruction)
    #[account(
        init,
        payer = payer,
        space = EVMProofContext::space(),
        seeds = [EVM_PROOF_CONTEXT_SEED, &message_id],
        bump,
    )]
    pub proof_context: Box<Account<'info, EVMProofContext>>,

    /// SP1 verifier program
    ///
    /// CHECK: Validated against config.sp1_verifier
    #[account(
        constraint = sp1_verifier.key() == config.sp1_verifier
            @ X0BridgeError::InvalidSP1Verifier,
    )]
    pub sp1_verifier: UncheckedAccount<'info>,

    /// System program
    pub system_program: Program<'info, System>,
}

pub fn handler(
    ctx: Context<VerifyEVMProof>,
    message_id: [u8; 32],
    proof: Vec<u8>,
    public_values: Vec<u8>,
) -> Result<()> {
    let clock = Clock::get()?;

    // ========================================================================
    // Step 1: Verify the STARK proof via CPI to SP1 verifier
    // ========================================================================

    msg!("Verifying STARK proof ({} bytes)...", proof.len());

    // Build the SP1 verify instruction
    // The SP1 Solana verifier expects:
    //   - proof bytes
    //   - public values bytes
    //   - verifier state account (if applicable)
    //
    // SP1 verification instruction layout:
    //   discriminator (8 bytes) + proof_len (4) + proof + public_values_len (4) + public_values
    let mut verify_data = Vec::with_capacity(8 + 4 + proof.len() + 4 + public_values.len());

    // SP1 verify discriminator (first 8 bytes of SHA256("global:verify"))
    let discriminator: [u8; 8] = {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(b"global:verify");
        let hash = hasher.finalize();
        let mut disc = [0u8; 8];
        disc.copy_from_slice(&hash[..8]);
        disc
    };
    verify_data.extend_from_slice(&discriminator);

    // Proof bytes (length-prefixed)
    verify_data.extend_from_slice(&(proof.len() as u32).to_le_bytes());
    verify_data.extend_from_slice(&proof);

    // Public values bytes (length-prefixed)
    verify_data.extend_from_slice(&(public_values.len() as u32).to_le_bytes());
    verify_data.extend_from_slice(&public_values);

    let verify_ix = solana_program::instruction::Instruction {
        program_id: ctx.accounts.sp1_verifier.key(),
        accounts: vec![
            solana_program::instruction::AccountMeta::new_readonly(
                ctx.accounts.payer.key(),
                true,
            ),
        ],
        data: verify_data,
    };

    invoke(
        &verify_ix,
        &[
            ctx.accounts.payer.to_account_info(),
            ctx.accounts.sp1_verifier.to_account_info(),
        ],
    )
    .map_err(|_| X0BridgeError::ProofVerificationFailed)?;

    msg!("✓ STARK proof verified");

    // ========================================================================
    // Step 2: Decode and validate public values
    // ========================================================================

    let public_inputs: SP1PublicInputs =
        SP1PublicInputs::try_from_slice(&public_values)
            .map_err(|_| X0BridgeError::InvalidPublicValues)?;

    // Validate EVM transaction was successful
    require!(
        public_inputs.success,
        X0BridgeError::EVMTransactionFailed
    );

    // Validate the EVM tx hash matches the bridge message
    require!(
        public_inputs.tx_hash == ctx.accounts.bridge_message.evm_tx_hash,
        X0BridgeError::ProofMessageMismatch
    );

    // ========================================================================
    // Step 3: Create proof context
    // ========================================================================

    let proof_context = &mut ctx.accounts.proof_context;
    proof_context.version = 1;
    proof_context.proof_type = EVMProofType::Transaction;
    proof_context.verified = true;
    proof_context.verified_at = clock.unix_timestamp;
    proof_context.block_hash = public_inputs.block_hash;
    proof_context.block_number = public_inputs.block_number;
    proof_context.tx_hash = public_inputs.tx_hash;
    proof_context.from = public_inputs.from;
    proof_context.to = public_inputs.to;
    proof_context.value = public_inputs.value;
    proof_context.event_logs = public_inputs.event_logs;
    proof_context.message_id = message_id;
    proof_context.bump = ctx.bumps.proof_context;
    proof_context._reserved = [0u8; 32];

    // ========================================================================
    // Step 4: Update bridge message status
    // ========================================================================

    let bridge_message = &mut ctx.accounts.bridge_message;
    bridge_message.status = BridgeMessageStatus::ProofVerified;

    // ========================================================================
    // Step 5: Emit event
    // ========================================================================

    emit!(BridgeProofVerified {
        proof_context: proof_context.key(),
        message_pda: bridge_message.key(),
        message_id,
        evm_block_number: proof_context.block_number,
        evm_tx_hash: proof_context.tx_hash,
        amount: bridge_message.amount,
        timestamp: clock.unix_timestamp,
    });

    msg!(
        "Proof verified: message_id={}, block={}, tx={}",
        hex::encode(message_id),
        proof_context.block_number,
        hex::encode(proof_context.tx_hash),
    );

    Ok(())
}
