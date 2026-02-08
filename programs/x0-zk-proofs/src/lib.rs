//! WASM-compiled Groth16 zero-knowledge proof generation for x0 SDK
//!
//! This crate provides WebAssembly bindings to solana-zk-token-sdk for generating
//! cryptographically secure Groth16 proofs for Token-2022 confidential transfers.
//!
//! # Proof Types
//!
//! 1. **PubkeyValidityProof**: Proves ElGamal public key is valid
//! 2. **WithdrawProof**: Proves withdrawal amount and updates balance
//! 3. **ZeroBalanceProof**: Proves account balance is zero (for account closure)

use wasm_bindgen::prelude::*;

mod elgamal;
mod proofs;
mod utils;

pub use proofs::*;

/// WASM module version
#[wasm_bindgen]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_returns_cargo_version() {
        let v = version();
        assert_eq!(v, env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn version_is_semver() {
        let v = version();
        let parts: Vec<&str> = v.split('.').collect();
        assert_eq!(parts.len(), 3, "version should be semver: {v}");
        for part in &parts {
            part.parse::<u32>()
                .unwrap_or_else(|_| panic!("non-numeric semver component: {part}"));
        }
    }
}
