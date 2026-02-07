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
