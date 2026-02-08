//! Utility functions and error types for ZK proof generation

use thiserror::Error;
use wasm_bindgen::prelude::*;

/// Custom error type for x0-zk-proofs
#[derive(Error, Debug)]
pub enum X0Error {
    #[error("Invalid ElGamal keypair: {0}")]
    InvalidKeypair(String),

    #[error("Invalid ciphertext: {0}")]
    InvalidCiphertext(String),

    #[error("Proof generation failed: {0}")]
    ProofGenerationFailed(String),

    #[error("Invalid input length: expected {expected}, got {actual}")]
    InvalidLength { expected: usize, actual: usize },
}

/// Convert X0Error to JsValue for WASM boundary
impl From<X0Error> for JsValue {
    fn from(err: X0Error) -> Self {
        JsValue::from_str(&err.to_string())
    }
}

/// Helper to validate byte slice length
pub(crate) fn validate_length(bytes: &[u8], expected: usize) -> Result<(), X0Error> {
    if bytes.len() != expected {
        return Err(X0Error::InvalidLength {
            expected,
            actual: bytes.len(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // validate_length
    // ========================================================================

    #[test]
    fn validate_length_exact_match() {
        assert!(validate_length(&[0u8; 64], 64).is_ok());
    }

    #[test]
    fn validate_length_empty_expects_zero() {
        assert!(validate_length(&[], 0).is_ok());
    }

    #[test]
    fn validate_length_too_short() {
        let err = validate_length(&[0u8; 32], 64).unwrap_err();
        match err {
            X0Error::InvalidLength {
                expected: 64,
                actual: 32,
            } => {}
            _ => panic!("Expected InvalidLength {{ expected: 64, actual: 32 }}, got: {err}"),
        }
    }

    #[test]
    fn validate_length_too_long() {
        let err = validate_length(&[0u8; 128], 64).unwrap_err();
        match err {
            X0Error::InvalidLength {
                expected: 64,
                actual: 128,
            } => {}
            _ => panic!("Expected InvalidLength {{ expected: 64, actual: 128 }}, got: {err}"),
        }
    }

    #[test]
    fn validate_length_empty_vs_nonzero() {
        let err = validate_length(&[], 1).unwrap_err();
        match err {
            X0Error::InvalidLength {
                expected: 1,
                actual: 0,
            } => {}
            _ => panic!("Expected InvalidLength {{ expected: 1, actual: 0 }}, got: {err}"),
        }
    }

    #[test]
    fn validate_length_single_byte() {
        assert!(validate_length(&[0xFF], 1).is_ok());
    }

    // ========================================================================
    // X0Error display messages
    // ========================================================================

    #[test]
    fn error_display_invalid_keypair() {
        let err = X0Error::InvalidKeypair("bad key data".into());
        let msg = err.to_string();
        assert!(msg.contains("Invalid ElGamal keypair"), "got: {msg}");
        assert!(msg.contains("bad key data"), "got: {msg}");
    }

    #[test]
    fn error_display_invalid_ciphertext() {
        let err = X0Error::InvalidCiphertext("corrupt".into());
        let msg = err.to_string();
        assert!(msg.contains("Invalid ciphertext"), "got: {msg}");
        assert!(msg.contains("corrupt"), "got: {msg}");
    }

    #[test]
    fn error_display_proof_generation_failed() {
        let err = X0Error::ProofGenerationFailed("sigma protocol failed".into());
        let msg = err.to_string();
        assert!(msg.contains("Proof generation failed"), "got: {msg}");
        assert!(msg.contains("sigma protocol failed"), "got: {msg}");
    }

    #[test]
    fn error_display_invalid_length() {
        let err = X0Error::InvalidLength {
            expected: 64,
            actual: 32,
        };
        let msg = err.to_string();
        assert!(msg.contains("64"), "got: {msg}");
        assert!(msg.contains("32"), "got: {msg}");
    }

    // ========================================================================
    // X0Error → JsValue conversion
    // ========================================================================

    // Note: X0Error → JsValue conversion (From<X0Error> for JsValue) cannot be
    // tested natively because JsValue::from_str panics on non-wasm32 targets.
    // That conversion is covered by the wasm_bindgen_test suite in tests/wasm_tests.rs.
}
