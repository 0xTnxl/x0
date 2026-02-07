//! Groth16 zero-knowledge proof generation for Token-2022 confidential transfers
//!
//! Proof types:
//! 1. PubkeyValidityProof - Proves ElGamal public key is valid
//! 2. WithdrawProof - Proves withdrawal amount and updates balance
//! 3. ZeroBalanceProof - Proves account balance is zero for closure

use solana_zk_token_sdk::{
    encryption::elgamal::ElGamalCiphertext,
    zk_token_proof_instruction::{
        PubkeyValidityData, WithdrawData, ZeroBalanceProofData,
    },
};
use wasm_bindgen::prelude::*;

use crate::elgamal::reconstruct_keypair;
use crate::utils::X0Error;

/// Generate PubkeyValidityProof
///
/// # Arguments
/// * `elgamal_keypair` - 64-byte ElGamal keypair (secret_key || public_key)
///
/// # Returns
/// * `Uint8Array` - Serialized PubkeyValidityData proof bytes
#[wasm_bindgen]
pub fn generate_pubkey_validity_proof(
    elgamal_keypair: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let keypair = reconstruct_keypair(elgamal_keypair)?;

    let proof_data = PubkeyValidityData::new(&keypair).map_err(|e| {
        X0Error::ProofGenerationFailed(format!("PubkeyValidityData: {}", e))
    })?;

    let proof_bytes = bytemuck::bytes_of(&proof_data).to_vec();
    Ok(proof_bytes)
}

/// Generate WithdrawProof
///
/// # Arguments
/// * `elgamal_keypair` - 64-byte ElGamal keypair (secret_key || public_key)
/// * `balance_ciphertext` - 64-byte ElGamal ciphertext of current balance
/// * `withdraw_amount` - Amount to withdraw (u64)
///
/// # Returns
/// * `JsValue` - Object with:
///   - `proofData`: Uint8Array - Serialized WithdrawData proof
///   - `newBalance`: BigInt - New balance after withdrawal (for AE encryption by caller)
#[wasm_bindgen]
pub fn generate_withdraw_proof(
    elgamal_keypair: &[u8],
    balance_ciphertext: &[u8],
    withdraw_amount: u64,
) -> Result<JsValue, JsValue> {
    let keypair = reconstruct_keypair(elgamal_keypair)?;

    // Parse ciphertext
    let mut ct_bytes = [0u8; 64];
    ct_bytes.copy_from_slice(
        balance_ciphertext
            .get(..64)
            .ok_or_else(|| X0Error::InvalidCiphertext("Expected 64 bytes".to_string()))?,
    );
    let ciphertext = ElGamalCiphertext::from_bytes(&ct_bytes)
        .ok_or_else(|| X0Error::InvalidCiphertext("Invalid ElGamalCiphertext".to_string()))?;

    // Decrypt current balance
    let current_balance = ciphertext
        .decrypt_u32(&keypair.secret())
        .ok_or_else(|| X0Error::InvalidCiphertext("Balance decryption failed".to_string()))?;

    if (current_balance as u64) < withdraw_amount {
        return Err(X0Error::ProofGenerationFailed(format!(
            "Insufficient balance: {} < {}",
            current_balance, withdraw_amount
        ))
        .into());
    }

    let new_balance = current_balance as u64 - withdraw_amount;

    // Generate proof
    let proof_data = WithdrawData::new(
        withdraw_amount,
        &keypair,
        new_balance,
        &ciphertext,
    )
    .map_err(|e| X0Error::ProofGenerationFailed(format!("WithdrawData: {}", e)))?;

    // Serialize proof
    let proof_bytes = bytemuck::bytes_of(&proof_data).to_vec();

    // Return JS object with proof and new balance
    let result = js_sys::Object::new();
    let proof_array = js_sys::Uint8Array::from(&proof_bytes[..]);

    js_sys::Reflect::set(&result, &"proofData".into(), &proof_array)?;
    js_sys::Reflect::set(
        &result,
        &"newBalance".into(),
        &JsValue::from(new_balance),
    )?;

    Ok(result.into())
}

/// Generate ZeroBalanceProof
///
/// # Arguments
/// * `elgamal_keypair` - 64-byte ElGamal keypair (secret_key || public_key)
/// * `balance_ciphertext` - 64-byte ElGamal ciphertext of current balance
///
/// # Returns
/// * `Uint8Array` - Serialized ZeroBalanceProofData proof bytes
#[wasm_bindgen]
pub fn generate_zero_balance_proof(
    elgamal_keypair: &[u8],
    balance_ciphertext: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let keypair = reconstruct_keypair(elgamal_keypair)?;

    // Parse ciphertext
    let mut ct_bytes = [0u8; 64];
    ct_bytes.copy_from_slice(
        balance_ciphertext
            .get(..64)
            .ok_or_else(|| X0Error::InvalidCiphertext("Expected 64 bytes".to_string()))?,
    );
    let ciphertext = ElGamalCiphertext::from_bytes(&ct_bytes)
        .ok_or_else(|| X0Error::InvalidCiphertext("Invalid ElGamalCiphertext".to_string()))?;

    // Verify balance is zero
    let balance = ciphertext
        .decrypt_u32(&keypair.secret())
        .ok_or_else(|| X0Error::InvalidCiphertext("Balance decryption failed".to_string()))?;

    if balance != 0 {
        return Err(X0Error::ProofGenerationFailed(format!(
            "Balance is not zero: {}",
            balance
        ))
        .into());
    }

    let proof_data = ZeroBalanceProofData::new(&keypair, &ciphertext).map_err(|e| {
        X0Error::ProofGenerationFailed(format!("ZeroBalanceProofData: {}", e))
    })?;

    let proof_bytes = bytemuck::bytes_of(&proof_data).to_vec();
    Ok(proof_bytes)
}
