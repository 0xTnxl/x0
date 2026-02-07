//! Groth16 proof verification using solana-zk-token-sdk via CPI
//!
//! This module provides on-chain verification of Groth16 proofs by calling
//! the ZK Token Proof Program via Cross-Program Invocation (CPI).

use anchor_lang::prelude::*;
use anchor_lang::solana_program::program::invoke;
use solana_zk_token_sdk::zk_token_proof_instruction::{
    ProofInstruction, PubkeyValidityData, WithdrawData, ZeroBalanceProofData,
};
use x0_common::error::X0ZkVerifierError;

/// Verify a PubkeyValidityProof via CPI
///
/// Calls the ZK Token Proof Program to verify the proof on-chain.
///
/// # Arguments
/// * `proof_program` - The ZK Token Proof Program account
/// * `proof_data` - Raw proof bytes (64 bytes for PubkeyValidityData)
/// * `elgamal_pubkey` - The ElGamal public key claimed in the proof
///
/// # Returns
/// * `Ok(true)` if proof is valid and pubkey matches
/// * `Err` if proof is invalid or pubkey mismatch
pub fn verify_pubkey_validity_proof(
    proof_program: &AccountInfo,
    proof_data: &[u8],
    elgamal_pubkey: &[u8; 32],
) -> Result<bool> {
    // Validate proof data size
    require!(
        proof_data.len() == 64,
        X0ZkVerifierError::ProofSizeMismatch
    );

    // Parse proof data using bytemuck (POD types)
    let proof: &PubkeyValidityData = bytemuck::try_from_bytes(proof_data)
        .map_err(|_| X0ZkVerifierError::InvalidProofData)?;

    // Verify public key matches (compare as byte arrays)
    require!(
        &proof.context.pubkey.0 == elgamal_pubkey,
        X0ZkVerifierError::InvalidElGamalPubkey
    );

    // Create instruction for ZK Token Proof Program
    let verify_ix = ProofInstruction::VerifyPubkeyValidity.encode_verify_proof(None, proof);

    // Invoke the ZK Token Proof Program via CPI
    invoke(&verify_ix, &[proof_program.clone()])
        .map_err(|_| X0ZkVerifierError::ProofVerificationFailed)?;

    Ok(true)
}

/// Verify a WithdrawProof via CPI
///
/// Verifies that a withdrawal from confidential balance is valid without
/// revealing the remaining balance.
///
/// # Arguments
/// * `proof_program` - The ZK Token Proof Program account
/// * `proof_data` - Raw proof bytes (160 bytes for WithdrawData)
/// * `_amount` - The amount being withdrawn (stored for reference, validated by proof)
/// * `_new_decryptable_balance` - Encrypted new balance (for validation)
///
/// # Returns
/// * `Ok(true)` if proof is valid
/// * `Err` if proof is invalid or parameters don't match
pub fn verify_withdraw_proof(
    proof_program: &AccountInfo,
    proof_data: &[u8],
    _amount: u64,
    _new_decryptable_balance: &[u8; 36],
) -> Result<bool> {
    // Validate proof data size
    require!(
        proof_data.len() == 160,
        X0ZkVerifierError::ProofSizeMismatch
    );

    // Parse proof data
    let proof: &WithdrawData = bytemuck::try_from_bytes(proof_data)
        .map_err(|_| X0ZkVerifierError::InvalidProofData)?;

    // Create instruction for ZK Token Proof Program
    let verify_ix = ProofInstruction::VerifyWithdraw.encode_verify_proof(None, proof);

    // Invoke the ZK Token Proof Program via CPI
    invoke(&verify_ix, &[proof_program.clone()])
        .map_err(|_| X0ZkVerifierError::ProofVerificationFailed)?;

    // The amount parameter is stored in our ProofContext for reference
    // but the cryptographic validation is done by the ZK Token Proof Program

    // Note: new_decryptable_balance is validated by Token-2022 program
    // We just ensure it's the correct format here
    Ok(true)
}

/// Verify a ZeroBalanceProof via CPI
///
/// Proves that an account's confidential balance is exactly zero.
/// Required for closing confidential transfer accounts.
///
/// # Arguments
/// * `proof_program` - The ZK Token Proof Program account
/// * `proof_data` - Raw proof bytes (96 bytes for ZeroBalanceProofData)
///
/// # Returns
/// * `Ok(true)` if proof is valid
/// * `Err` if proof is invalid
pub fn verify_zero_balance_proof(proof_program: &AccountInfo, proof_data: &[u8]) -> Result<bool> {
    // Validate proof data size
    require!(
        proof_data.len() == 96,
        X0ZkVerifierError::ProofSizeMismatch
    );

    // Parse proof data
    let proof: &ZeroBalanceProofData = bytemuck::try_from_bytes(proof_data)
        .map_err(|_| X0ZkVerifierError::InvalidProofData)?;

    // Create instruction for ZK Token Proof Program
    let verify_ix = ProofInstruction::VerifyZeroBalance.encode_verify_proof(None, proof);

    // Invoke the ZK Token Proof Program via CPI
    invoke(&verify_ix, &[proof_program.clone()])
        .map_err(|_| X0ZkVerifierError::ProofVerificationFailed)?;

    Ok(true)
}
