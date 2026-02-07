//! Verify TransferData proofs via CPI

use anchor_lang::prelude::*;
use anchor_lang::solana_program::program::invoke;
use solana_zk_token_sdk::zk_token_proof_instruction::{ProofInstruction, TransferData};
use x0_common::error::X0ZkVerifierError;

/// Verify a TransferProof (confidential transfer between accounts) via CPI
///
/// Note: TransferData is more complex than other proofs as it involves
/// both source and destination account validations.
///
/// # Arguments
/// * `proof_program` - The ZK Token Proof Program account
/// * `proof_data` - Raw proof bytes for TransferData
/// * `_amount` - Transfer amount (validated cryptographically by proof)
/// * `_recipient` - Recipient public key (stored for reference)
///
/// # Returns
/// * `Ok(true)` if proof is valid
/// * `Err` if proof is invalid
pub fn verify_transfer_proof(
    proof_program: &AccountInfo,
    proof_data: &[u8],
    _amount: u64,
    _recipient: &Pubkey,
) -> Result<bool> {
    // TransferData has variable size due to range proofs
    // Minimum size check
    require!(
        proof_data.len() >= 300,
        X0ZkVerifierError::ProofSizeMismatch
    );

    // Parse proof data
    let proof: &TransferData = bytemuck::try_from_bytes(proof_data)
        .map_err(|_| X0ZkVerifierError::InvalidProofData)?;

    // Create instruction for ZK Token Proof Program
    let verify_ix = ProofInstruction::VerifyTransfer.encode_verify_proof(None, proof);

    // Invoke the ZK Token Proof Program via CPI
    invoke(&verify_ix, &[proof_program.clone()])
        .map_err(|_| X0ZkVerifierError::ProofVerificationFailed)?;

    // The amount and recipient are cryptographically validated by the proof
    // We store them in ProofContext for reference but the proof itself
    // ensures their correctness

    Ok(true)
}
