//! WASM boundary integration tests for x0-zk-proofs
//!
//! These tests validate the public `#[wasm_bindgen]` API surface.
//! Run with: `wasm-pack test --node` (requires wasm-pack + Node.js)
//!
//! Note: These tests only compile and run on wasm32 targets.
//! Native unit tests are in each source module and run via `cargo test`.

#![cfg(target_arch = "wasm32")]

use wasm_bindgen::JsValue;
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

// Import the WASM functions
use x0_zk_proofs::{
    decrypt_elgamal_u64, generate_pubkey_validity_proof, generate_withdraw_proof,
    generate_zero_balance_proof, version,
};

// ============================================================================
// Helper: create test data using solana-zk-token-sdk crypto primitives
// ============================================================================

fn fresh_keypair_bytes() -> Vec<u8> {
    use solana_zk_token_sdk::encryption::elgamal::ElGamalKeypair;
    ElGamalKeypair::new_rand().to_bytes().to_vec()
}

fn encrypt_value(keypair_bytes: &[u8], value: u64) -> Vec<u8> {
    use solana_zk_token_sdk::encryption::elgamal::ElGamalKeypair;
    let mut arr = [0u8; 64];
    arr.copy_from_slice(keypair_bytes);
    let kp = ElGamalKeypair::from_bytes(&arr).unwrap();
    kp.pubkey().encrypt(value).to_bytes().to_vec()
}

// ============================================================================
// version()
// ============================================================================

#[wasm_bindgen_test]
fn wasm_version_returns_semver() {
    let v = version();
    assert!(!v.is_empty());
    let parts: Vec<&str> = v.split('.').collect();
    assert_eq!(parts.len(), 3, "version should be semver: {v}");
}

// ============================================================================
// decrypt_elgamal_u64
// ============================================================================

#[wasm_bindgen_test]
fn wasm_decrypt_roundtrip() {
    let kp = fresh_keypair_bytes();
    let ct = encrypt_value(&kp, 42);
    assert_eq!(decrypt_elgamal_u64(&kp, &ct).unwrap(), 42);
}

#[wasm_bindgen_test]
fn wasm_decrypt_zero() {
    let kp = fresh_keypair_bytes();
    let ct = encrypt_value(&kp, 0);
    assert_eq!(decrypt_elgamal_u64(&kp, &ct).unwrap(), 0);
}

#[wasm_bindgen_test]
fn wasm_decrypt_invalid_keypair_length() {
    let ct = vec![0u8; 64];
    assert!(decrypt_elgamal_u64(&[0u8; 32], &ct).is_err());
}

#[wasm_bindgen_test]
fn wasm_decrypt_empty_ciphertext() {
    let kp = fresh_keypair_bytes();
    assert!(decrypt_elgamal_u64(&kp, &[]).is_err());
}

// ============================================================================
// generate_pubkey_validity_proof
// ============================================================================

#[wasm_bindgen_test]
fn wasm_pubkey_validity_proof() {
    let kp = fresh_keypair_bytes();
    let proof = generate_pubkey_validity_proof(&kp).unwrap();
    assert!(!proof.is_empty());
}

#[wasm_bindgen_test]
fn wasm_pubkey_validity_proof_invalid_kp() {
    assert!(generate_pubkey_validity_proof(&[0u8; 32]).is_err());
}

// ============================================================================
// generate_withdraw_proof (only works in JS runtime — uses js_sys::Object)
// ============================================================================

#[wasm_bindgen_test]
fn wasm_withdraw_proof_success() {
    let kp = fresh_keypair_bytes();
    let ct = encrypt_value(&kp, 1000);
    let result = generate_withdraw_proof(&kp, &ct, 300);
    assert!(result.is_ok(), "withdraw proof should succeed");

    // Result is a JS object with proofData and newBalance
    let obj = result.unwrap();
    let proof_data = js_sys::Reflect::get(&obj, &"proofData".into()).unwrap();
    assert!(proof_data.is_instance_of::<js_sys::Uint8Array>());

    let new_balance = js_sys::Reflect::get(&obj, &"newBalance".into()).unwrap();
    assert_eq!(new_balance.as_f64().unwrap() as u64, 700);
}

#[wasm_bindgen_test]
fn wasm_withdraw_proof_insufficient_balance() {
    let kp = fresh_keypair_bytes();
    let ct = encrypt_value(&kp, 100);
    assert!(
        generate_withdraw_proof(&kp, &ct, 200).is_err(),
        "should fail with insufficient balance"
    );
}

#[wasm_bindgen_test]
fn wasm_withdraw_proof_full_balance() {
    let kp = fresh_keypair_bytes();
    let ct = encrypt_value(&kp, 500);
    let result = generate_withdraw_proof(&kp, &ct, 500);
    assert!(result.is_ok(), "full withdrawal should succeed");
}

// ============================================================================
// generate_zero_balance_proof
// ============================================================================

#[wasm_bindgen_test]
fn wasm_zero_balance_proof_success() {
    let kp = fresh_keypair_bytes();
    let ct = encrypt_value(&kp, 0);
    let proof = generate_zero_balance_proof(&kp, &ct).unwrap();
    assert!(!proof.is_empty());
}

#[wasm_bindgen_test]
fn wasm_zero_balance_proof_nonzero_fails() {
    let kp = fresh_keypair_bytes();
    let ct = encrypt_value(&kp, 1);
    assert!(generate_zero_balance_proof(&kp, &ct).is_err());
}

// ============================================================================
// Full lifecycle (WASM boundary)
// ============================================================================

#[wasm_bindgen_test]
fn wasm_full_lifecycle() {
    let kp = fresh_keypair_bytes();

    // 1. Pubkey proof
    let _pubkey_proof = generate_pubkey_validity_proof(&kp).unwrap();

    // 2. Encrypt balance, withdraw
    let ct = encrypt_value(&kp, 1000);
    let result = generate_withdraw_proof(&kp, &ct, 600).unwrap();
    let new_bal = js_sys::Reflect::get(&result, &"newBalance".into())
        .unwrap()
        .as_f64()
        .unwrap() as u64;
    assert_eq!(new_bal, 400);

    // 3. Zero balance proof after withdrawing everything
    let zero_ct = encrypt_value(&kp, 0);
    let _zero_proof = generate_zero_balance_proof(&kp, &zero_ct).unwrap();
}
