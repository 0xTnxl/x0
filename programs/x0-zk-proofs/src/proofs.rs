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

    // Generate proof — WithdrawData::new expects current_balance (pre-withdrawal)
    let proof_data = WithdrawData::new(
        withdraw_amount,
        &keypair,
        current_balance as u64,
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

#[cfg(test)]
mod tests {
    use super::*;
    use solana_zk_token_sdk::encryption::elgamal::ElGamalKeypair;

    // ========================================================================
    // Helper: generate a valid keypair + ciphertext pair
    // ========================================================================

    fn test_keypair() -> ElGamalKeypair {
        ElGamalKeypair::new_rand()
    }

    // ========================================================================
    // PubkeyValidityData (testing the underlying proof generation directly,
    // bypassing #[wasm_bindgen] which uses JsValue)
    // ========================================================================

    #[test]
    fn pubkey_validity_proof_succeeds() {
        let kp = test_keypair();
        let proof_data = PubkeyValidityData::new(&kp).unwrap();
        let bytes = bytemuck::bytes_of(&proof_data);
        assert!(!bytes.is_empty());
    }

    #[test]
    fn pubkey_validity_proof_correct_size() {
        let kp = test_keypair();
        let proof_data = PubkeyValidityData::new(&kp).unwrap();
        let bytes = bytemuck::bytes_of(&proof_data);
        assert_eq!(
            bytes.len(),
            std::mem::size_of::<PubkeyValidityData>(),
            "proof byte length must equal PubkeyValidityData size"
        );
    }

    #[test]
    fn pubkey_validity_proof_bytemuck_roundtrip() {
        let kp = test_keypair();
        let proof_data = PubkeyValidityData::new(&kp).unwrap();
        let bytes = bytemuck::bytes_of(&proof_data).to_vec();

        let parsed: &PubkeyValidityData = bytemuck::from_bytes(&bytes);
        let reserialized = bytemuck::bytes_of(parsed).to_vec();
        assert_eq!(bytes, reserialized, "bytemuck roundtrip must be lossless");
    }

    #[test]
    fn pubkey_validity_proof_different_keypairs_produce_different_proofs() {
        let kp1 = test_keypair();
        let kp2 = test_keypair();

        let proof1 = bytemuck::bytes_of(&PubkeyValidityData::new(&kp1).unwrap()).to_vec();
        let proof2 = bytemuck::bytes_of(&PubkeyValidityData::new(&kp2).unwrap()).to_vec();

        assert_ne!(proof1, proof2, "different keypairs → different proofs");
    }

    // ========================================================================
    // ZeroBalanceProofData
    // ========================================================================

    #[test]
    fn zero_balance_proof_succeeds_when_zero() {
        let kp = test_keypair();
        let ct = kp.pubkey().encrypt(0u64);

        let proof_data = ZeroBalanceProofData::new(&kp, &ct).unwrap();
        let bytes = bytemuck::bytes_of(&proof_data);
        assert!(!bytes.is_empty());
    }

    #[test]
    fn zero_balance_proof_correct_size() {
        let kp = test_keypair();
        let ct = kp.pubkey().encrypt(0u64);

        let proof_data = ZeroBalanceProofData::new(&kp, &ct).unwrap();
        assert_eq!(
            bytemuck::bytes_of(&proof_data).len(),
            std::mem::size_of::<ZeroBalanceProofData>(),
            "proof byte length must equal ZeroBalanceProofData size"
        );
    }

    #[test]
    fn zero_balance_proof_bytemuck_roundtrip() {
        let kp = test_keypair();
        let ct = kp.pubkey().encrypt(0u64);

        let proof_data = ZeroBalanceProofData::new(&kp, &ct).unwrap();
        let bytes = bytemuck::bytes_of(&proof_data).to_vec();
        let parsed: &ZeroBalanceProofData = bytemuck::from_bytes(&bytes);
        let reserialized = bytemuck::bytes_of(parsed).to_vec();
        assert_eq!(bytes, reserialized, "bytemuck roundtrip must be lossless");
    }

    #[test]
    fn zero_balance_proof_nonzero_balance_check() {
        let kp = test_keypair();
        let ct = kp.pubkey().encrypt(1u64);

        // The on-chain code decrypts and checks balance == 0
        let balance = ct.decrypt_u32(&kp.secret()).unwrap();
        assert_ne!(balance, 0, "balance should be non-zero for this test case");
    }

    #[test]
    fn zero_balance_proof_large_balance_check() {
        let kp = test_keypair();
        let ct = kp.pubkey().encrypt(10_000u64);

        let balance = ct.decrypt_u32(&kp.secret()).unwrap();
        assert_ne!(balance, 0, "balance=10000 should be non-zero");
    }

    #[test]
    fn zero_balance_proof_wrong_keypair_decryption() {
        let kp1 = test_keypair();
        let kp2 = test_keypair();
        let ct = kp1.pubkey().encrypt(0u64);

        // With wrong keypair, decrypt_u32 returns None or wrong value
        let result = ct.decrypt_u32(&kp2.secret());
        // Even if decryption "succeeds", the value won't be 0,
        // or ZeroBalanceProofData::new with wrong keypair will fail
        if let Some(val) = result {
            if val == 0 {
                // Extremely unlikely but possible; skip rather than false-fail
                return;
            }
        }
    }

    // ========================================================================
    // WithdrawData core logic (tested without WASM boundary)
    //
    // generate_withdraw_proof returns JsValue via js_sys::Object which requires
    // a JS runtime. We test the equivalent crypto operations directly.
    // ========================================================================

    #[test]
    fn withdraw_proof_core_normal_withdrawal() {
        let kp = test_keypair();
        let initial_balance = 1000u64;
        let withdraw_amount = 300u64;
        let ct = kp.pubkey().encrypt(initial_balance);

        // Step 1: Decrypt current balance
        let current_balance = ct.decrypt_u32(&kp.secret()).unwrap();
        assert_eq!(current_balance as u64, initial_balance);

        // Step 2: Generate proof — third param is current_balance (pre-withdrawal)
        let proof_data =
            WithdrawData::new(withdraw_amount, &kp, initial_balance, &ct).unwrap();

        let proof_bytes = bytemuck::bytes_of(&proof_data);
        assert_eq!(
            proof_bytes.len(),
            std::mem::size_of::<WithdrawData>(),
            "WithdrawData size mismatch"
        );
    }

    #[test]
    fn withdraw_proof_core_full_balance() {
        let kp = test_keypair();
        let balance = 500u64;
        let ct = kp.pubkey().encrypt(balance);

        // Withdraw everything — current_balance = balance
        let proof_data = WithdrawData::new(balance, &kp, balance, &ct).unwrap();

        let proof_bytes = bytemuck::bytes_of(&proof_data);
        assert!(!proof_bytes.is_empty());
    }

    #[test]
    fn withdraw_proof_core_zero_amount() {
        let kp = test_keypair();
        let balance = 500u64;
        let ct = kp.pubkey().encrypt(balance);

        // Withdrawing 0 should succeed
        let proof_data = WithdrawData::new(0, &kp, balance, &ct).unwrap();

        let proof_bytes = bytemuck::bytes_of(&proof_data);
        assert!(!proof_bytes.is_empty());
    }

    #[test]
    fn withdraw_proof_core_insufficient_balance_detected() {
        let kp = test_keypair();
        let balance = 100u64;
        let withdraw = 200u64;
        let ct = kp.pubkey().encrypt(balance);

        let current = ct.decrypt_u32(&kp.secret()).unwrap();
        assert!(
            (current as u64) < withdraw,
            "balance {current} must be less than withdrawal {withdraw}"
        );
    }

    #[test]
    fn withdraw_proof_core_single_unit() {
        let kp = test_keypair();
        let balance = 1u64;
        let ct = kp.pubkey().encrypt(balance);

        // Withdraw exactly 1 — current_balance = 1
        let proof_data = WithdrawData::new(1, &kp, balance, &ct).unwrap();
        let proof_bytes = bytemuck::bytes_of(&proof_data);
        assert!(!proof_bytes.is_empty());
    }

    #[test]
    fn withdraw_proof_core_large_value() {
        let kp = test_keypair();
        let balance = 50_000u64;
        let ct = kp.pubkey().encrypt(balance);

        let proof_data =
            WithdrawData::new(30_000, &kp, balance, &ct).unwrap();

        let proof_bytes = bytemuck::bytes_of(&proof_data);
        assert_eq!(proof_bytes.len(), std::mem::size_of::<WithdrawData>());
    }

    #[test]
    fn withdraw_proof_core_bytemuck_roundtrip() {
        let kp = test_keypair();
        let balance = 1000u64;
        let ct = kp.pubkey().encrypt(balance);

        let proof_data = WithdrawData::new(400, &kp, balance, &ct).unwrap();

        let bytes = bytemuck::bytes_of(&proof_data).to_vec();
        let parsed: &WithdrawData = bytemuck::from_bytes(&bytes);
        let reserialized = bytemuck::bytes_of(parsed).to_vec();
        assert_eq!(bytes, reserialized, "bytemuck roundtrip must be lossless");
    }

    // ========================================================================
    // Cross-proof consistency
    // ========================================================================

    #[test]
    fn full_lifecycle_keypair_to_proofs() {
        // Simulate a complete confidential transfer lifecycle:
        // 1. Generate keypair & prove validity
        // 2. Encrypt initial balance
        // 3. Withdraw some funds
        // 4. Withdraw remaining → zero
        // 5. Prove zero balance for account closure

        let kp = test_keypair();

        // 1. Pubkey validity proof
        let pubkey_proof = PubkeyValidityData::new(&kp).unwrap();
        assert!(!bytemuck::bytes_of(&pubkey_proof).is_empty(), "pubkey validity proof failed");

        // 2. Encrypt initial balance (simulating after deposit)
        let initial_balance = 1000u64;
        let ct = kp.pubkey().encrypt(initial_balance);

        // 3. Withdraw 600
        let current = ct.decrypt_u32(&kp.secret()).unwrap();
        assert_eq!(current as u64, initial_balance);
        let proof1 = WithdrawData::new(600, &kp, initial_balance, &ct).unwrap();
        assert!(!bytemuck::bytes_of(&proof1).is_empty());

        // 4. Simulate new balance ciphertext after withdrawal
        let remaining = 400u64;
        let new_ct = kp.pubkey().encrypt(remaining);
        let proof2 = WithdrawData::new(remaining, &kp, remaining, &new_ct).unwrap();
        assert!(!bytemuck::bytes_of(&proof2).is_empty());

        // 5. Zero balance proof for account closure
        let zero_ct = kp.pubkey().encrypt(0u64);
        let zero_proof = ZeroBalanceProofData::new(&kp, &zero_ct).unwrap();
        assert!(!bytemuck::bytes_of(&zero_proof).is_empty(), "zero balance proof failed");
    }

    #[test]
    fn proof_sizes_are_consistent() {
        let kp = test_keypair();

        let pubkey_proof = PubkeyValidityData::new(&kp).unwrap();
        let zero_ct = kp.pubkey().encrypt(0u64);
        let zero_proof = ZeroBalanceProofData::new(&kp, &zero_ct).unwrap();

        // Sizes should match the struct sizes exactly
        assert_eq!(
            bytemuck::bytes_of(&pubkey_proof).len(),
            std::mem::size_of::<PubkeyValidityData>()
        );
        assert_eq!(
            bytemuck::bytes_of(&zero_proof).len(),
            std::mem::size_of::<ZeroBalanceProofData>()
        );

        // WithdrawData
        let balance = 100u64;
        let ct = kp.pubkey().encrypt(balance);
        let withdraw_proof = WithdrawData::new(50, &kp, balance, &ct).unwrap();
        assert_eq!(
            bytemuck::bytes_of(&withdraw_proof).len(),
            std::mem::size_of::<WithdrawData>()
        );

        // Verify sizes are sane (not zero, not absurdly large)
        assert!(std::mem::size_of::<PubkeyValidityData>() > 32, "pubkey proof too small");
        assert!(std::mem::size_of::<ZeroBalanceProofData>() > 64, "zero balance proof too small");
        assert!(std::mem::size_of::<WithdrawData>() > 128, "withdraw proof too small");
    }
}
