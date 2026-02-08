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

#[cfg(test)]
mod tests {
    use super::*;
    use solana_zk_token_sdk::encryption::elgamal::ElGamalKeypair;

    // ========================================================================
    // reconstruct_keypair
    // ========================================================================

    #[test]
    fn reconstruct_keypair_roundtrip() {
        let keypair = ElGamalKeypair::new_rand();
        let bytes = keypair.to_bytes();

        let reconstructed = reconstruct_keypair(&bytes).unwrap();
        assert_eq!(
            keypair.to_bytes(),
            reconstructed.to_bytes(),
            "roundtrip keypair bytes must match"
        );
    }

    #[test]
    fn reconstruct_keypair_deterministic() {
        let keypair = ElGamalKeypair::new_rand();
        let bytes = keypair.to_bytes();

        let r1 = reconstruct_keypair(&bytes).unwrap();
        let r2 = reconstruct_keypair(&bytes).unwrap();
        assert_eq!(r1.to_bytes(), r2.to_bytes(), "same input → same keypair");
    }

    #[test]
    fn reconstruct_keypair_too_short() {
        let err = reconstruct_keypair(&[0u8; 32]).unwrap_err();
        match err {
            X0Error::InvalidLength {
                expected: 64,
                actual: 32,
            } => {}
            _ => panic!("Expected InvalidLength, got: {err}"),
        }
    }

    #[test]
    fn reconstruct_keypair_too_long() {
        let err = reconstruct_keypair(&[0u8; 128]).unwrap_err();
        match err {
            X0Error::InvalidLength {
                expected: 64,
                actual: 128,
            } => {}
            _ => panic!("Expected InvalidLength, got: {err}"),
        }
    }

    #[test]
    fn reconstruct_keypair_empty() {
        let err = reconstruct_keypair(&[]).unwrap_err();
        match err {
            X0Error::InvalidLength {
                expected: 64,
                actual: 0,
            } => {}
            _ => panic!("Expected InvalidLength, got: {err}"),
        }
    }

    #[test]
    fn reconstruct_keypair_all_zeros_accepted_by_sdk() {
        // Solana's ElGamalKeypair::from_bytes accepts all-zero bytes
        // (identity point). Verify our wrapper matches SDK behavior.
        let result = reconstruct_keypair(&[0u8; 64]);
        // The SDK accepts this — it's a degenerate keypair but not rejected
        assert!(result.is_ok(), "SDK accepts all-zero bytes as valid keypair");
    }

    // ========================================================================
    // Decryption logic (testing crypto directly, not through #[wasm_bindgen]
    // boundary — JsValue::from_str panics on non-wasm32 targets)
    // ========================================================================

    /// Helper: reconstruct keypair from bytes and decrypt a ciphertext
    fn decrypt_via_internal(keypair_bytes: &[u8], ct_bytes: &[u8]) -> Result<u64, String> {
        let kp = reconstruct_keypair(keypair_bytes).map_err(|e| e.to_string())?;
        validate_length(ct_bytes, 64).map_err(|e| e.to_string())?;

        let mut arr = [0u8; 64];
        arr.copy_from_slice(ct_bytes);
        let ct = ElGamalCiphertext::from_bytes(&arr)
            .ok_or_else(|| "invalid ciphertext format".to_string())?;

        ct.decrypt_u32(&kp.secret())
            .map(|v| v as u64)
            .ok_or_else(|| "decryption failed".to_string())
    }

    #[test]
    fn decrypt_roundtrip_zero() {
        let kp = ElGamalKeypair::new_rand();
        let ct = kp.pubkey().encrypt(0u64);
        assert_eq!(decrypt_via_internal(&kp.to_bytes(), &ct.to_bytes()).unwrap(), 0);
    }

    #[test]
    fn decrypt_roundtrip_small_value() {
        let kp = ElGamalKeypair::new_rand();
        let ct = kp.pubkey().encrypt(42u64);
        assert_eq!(decrypt_via_internal(&kp.to_bytes(), &ct.to_bytes()).unwrap(), 42);
    }

    #[test]
    fn decrypt_roundtrip_u16_max() {
        // Token-2022 lo/hi parts use u16 range; this is the typical max per-part
        let kp = ElGamalKeypair::new_rand();
        let value = u16::MAX as u64; // 65535
        let ct = kp.pubkey().encrypt(value);
        assert_eq!(decrypt_via_internal(&kp.to_bytes(), &ct.to_bytes()).unwrap() as u64, value);
    }

    #[test]
    fn decrypt_roundtrip_various_values() {
        let kp = ElGamalKeypair::new_rand();
        for &value in &[1u64, 100, 255, 1000, 10_000, 50_000] {
            let ct = kp.pubkey().encrypt(value);
            let decrypted = decrypt_via_internal(&kp.to_bytes(), &ct.to_bytes()).unwrap();
            assert_eq!(decrypted as u64, value, "mismatch for value {value}");
        }
    }

    #[test]
    fn decrypt_same_value_different_ciphertexts() {
        // ElGamal encryption is randomized; two encryptions of same value → different ciphertexts
        let kp = ElGamalKeypair::new_rand();
        let ct1 = kp.pubkey().encrypt(100u64);
        let ct2 = kp.pubkey().encrypt(100u64);

        assert_ne!(
            ct1.to_bytes(),
            ct2.to_bytes(),
            "randomized encryption should produce different ciphertexts"
        );

        assert_eq!(decrypt_via_internal(&kp.to_bytes(), &ct1.to_bytes()).unwrap(), 100);
        assert_eq!(decrypt_via_internal(&kp.to_bytes(), &ct2.to_bytes()).unwrap(), 100);
    }

    #[test]
    fn decrypt_wrong_keypair_fails() {
        let kp1 = ElGamalKeypair::new_rand();
        let kp2 = ElGamalKeypair::new_rand();
        let ct = kp1.pubkey().encrypt(42u64);

        // Decrypting with wrong key → discrete log fails (returns None)
        let result = decrypt_via_internal(&kp2.to_bytes(), &ct.to_bytes());
        if let Ok(val) = result {
            assert_ne!(val, 42, "wrong key must not decrypt to correct value");
        }
    }

    #[test]
    fn decrypt_invalid_keypair_length() {
        let kp = ElGamalKeypair::new_rand();
        let ct = kp.pubkey().encrypt(1u64);
        assert!(decrypt_via_internal(&[0u8; 32], &ct.to_bytes()).is_err());
    }

    #[test]
    fn decrypt_invalid_ciphertext_length_short() {
        let kp = ElGamalKeypair::new_rand();
        assert!(decrypt_via_internal(&kp.to_bytes(), &[0u8; 32]).is_err());
    }

    #[test]
    fn decrypt_invalid_ciphertext_length_long() {
        let kp = ElGamalKeypair::new_rand();
        assert!(decrypt_via_internal(&kp.to_bytes(), &[0u8; 128]).is_err());
    }

    #[test]
    fn decrypt_empty_ciphertext() {
        let kp = ElGamalKeypair::new_rand();
        assert!(decrypt_via_internal(&kp.to_bytes(), &[]).is_err());
    }
}
