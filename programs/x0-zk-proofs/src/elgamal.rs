//! ElGamal keypair reconstruction and decryption
//!
//! Uses solana-zk-token-sdk's ElGamalKeypair::from_bytes to reconstruct
//! keypairs from their serialized form (64 bytes = 32-byte secret + 32-byte public).
//! Also provides ElGamal ciphertext decryption for pending balance calculations.

use solana_zk_token_sdk::encryption::elgamal::{ElGamalKeypair, ElGamalCiphertext};
use wasm_bindgen::prelude::*;

use crate::utils::{validate_length, X0Error};

/// Reconstruct an ElGamal keypair from 64 bytes (secret_key || public_key)
pub(crate) fn reconstruct_keypair(keypair_bytes: &[u8]) -> Result<ElGamalKeypair, X0Error> {
    validate_length(keypair_bytes, 64)?;

    let mut bytes = [0u8; 64];
    bytes.copy_from_slice(keypair_bytes);

    ElGamalKeypair::from_bytes(&bytes).ok_or_else(|| {
        X0Error::InvalidKeypair("Failed to reconstruct ElGamalKeypair from bytes".to_string())
    })
}

/// Decrypt an ElGamal ciphertext to u64
///
/// This is used for decrypting pending balance lo/hi parts in confidential transfers.
/// Token-2022 splits large amounts into low and high parts (lo + hi * 2^16).
///
/// # Arguments
/// * `elgamal_keypair` - 64-byte ElGamal keypair (secret_key || public_key)
/// * `ciphertext` - 64-byte ElGamal ciphertext
///
/// # Returns
/// * `u64` - Decrypted value (0 to 2^32-1 for lo/hi parts)
///
/// # Errors
/// * InvalidKeypair - If keypair reconstruction fails
/// * InvalidCiphertext - If ciphertext is malformed or decryption fails
#[wasm_bindgen]
pub fn decrypt_elgamal_u64(
    elgamal_keypair: &[u8],
    ciphertext: &[u8],
) -> Result<u64, JsValue> {
    // Reconstruct keypair
    let keypair = reconstruct_keypair(elgamal_keypair)
        .map_err(|e| JsValue::from_str(&format!("Keypair error: {}", e)))?;

    // Validate ciphertext length
    validate_length(ciphertext, 64)
        .map_err(|e| JsValue::from_str(&format!("Ciphertext length error: {}", e)))?;

    // Parse ciphertext
    let mut ct_bytes = [0u8; 64];
    ct_bytes.copy_from_slice(ciphertext);

    let ct = ElGamalCiphertext::from_bytes(&ct_bytes)
        .ok_or_else(|| JsValue::from_str("Invalid ElGamalCiphertext format"))?;

    // Decrypt to u32 (Token-2022 uses u32 for lo/hi parts)
    let value = ct
        .decrypt_u32(&keypair.secret())
        .ok_or_else(|| JsValue::from_str("ElGamal decryption failed - ciphertext may be corrupted"))?;

    Ok(value as u64)
}
