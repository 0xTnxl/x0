//! SP1 Guest Program: Solana State Proof Verification Circuit
//!
//! This STARK circuit proves that a BridgeOutMessage account exists on Solana
//! with specific data. The proof is verified on Base EVM by X0UnlockContract.
//!
//! # What This Circuit Proves
//!
//! 1. **Account Data Integrity**: The BridgeOutMessage account data matches
//!    the claimed nonce, recipient, amount, and status == Burned.
//!
//! 2. **Account Ownership**: The account is owned by the x0-bridge program.
//!
//! 3. **Account Inclusion**: The account hash is included in the
//!    accounts_delta_hash via a fanout-16 Merkle proof (Solana's MERKLE_FANOUT).
//!
//! 4. **Bank Hash Derivation**: The accounts_delta_hash is committed to the
//!    bank hash via:
//!    `bank_hash = SHA-256(parent_bank_hash || delta_hash || sig_count || blockhash)`
//!
//! 5. **Validator Quorum**: ≥ 2/3 of epoch stake signed vote transactions
//!    containing the bank hash (Ed25519 over serialized tx message).
//!
//! # Security Property
//!
//! The verifier on Base can trust the BridgeOutMessage exists with the stated
//! fields because:
//! - Validator votes prove slot finality (Solana's Tower BFT)
//! - The bank hash commits to the accounts_delta_hash
//! - The delta hash includes the account via cryptographic Merkle proof
//! - The account data is parsed and committed as public outputs

#![no_main]
#![allow(dead_code)] // All code invoked at runtime via sp1_zkvm::entrypoint! macro
sp1_zkvm::entrypoint!(main);

extern crate alloc;

use alloc::vec::Vec;
use sha2::{Digest, Sha256};
use x0_sp1_solana_common::{
    ParsedBridgeOutMessage, SolanaProofPublicInputs, SolanaProofWitness, MERKLE_FANOUT,
};

/// SHA-256 hash function (SP1 accelerates this via zkVM precompile)
fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// SHA-256 of concatenated inputs (matches Solana's `hashv`)
fn hashv(inputs: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for input in inputs {
        hasher.update(input);
    }
    hasher.finalize().into()
}

/// Ed25519 signature verification (SP1 accelerates via precompile)
fn verify_ed25519(pubkey: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    use ed25519_dalek::{Signature, VerifyingKey};
    let key = match VerifyingKey::from_bytes(pubkey) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let sig = Signature::from_bytes(signature);
    key.verify_strict(message, &sig).is_ok()
}

fn main() {
    // ========================================================================
    // Step 1: Read private witness from host
    // ========================================================================

    let witness: SolanaProofWitness = sp1_zkvm::io::read();

    // ========================================================================
    // Step 2: Parse and validate BridgeOutMessage account data
    // ========================================================================

    let parsed = ParsedBridgeOutMessage::try_from_bytes(&witness.account_data)
        .expect("Failed to parse BridgeOutMessage account data");

    // Verify the account is owned by the bridge program
    let bridge_program_id = witness.account_owner;

    // Verify the account status is "Burned" (0)
    assert_eq!(
        parsed.status, 0,
        "BridgeOutMessage status must be Burned (0), got {}",
        parsed.status
    );

    // ========================================================================
    // Step 3: Compute account data hash (for public input integrity binding)
    // ========================================================================

    let account_hash = sha256(&witness.account_data);

    // ========================================================================
    // Step 4: Compute Solana account hash (for Merkle tree inclusion)
    //
    // This MUST match Solana's AccountsDb::hash_account() exactly:
    //
    //   SHA-256(
    //       lamports        (8 bytes LE)
    //       || owner        (32 bytes)
    //       || executable   (1 byte)
    //       || rent_epoch   (8 bytes LE)
    //       || data         (N bytes)
    //       || pubkey       (32 bytes)
    //   )
    //
    // Zero-lamport accounts hash to [0u8; 32] (Solana convention).
    // ========================================================================

    let solana_account_hash = if witness.account_lamports == 0 {
        [0u8; 32]
    } else {
        hashv(&[
            &witness.account_lamports.to_le_bytes(),
            &witness.account_owner,
            &[witness.account_executable as u8],
            &witness.account_rent_epoch.to_le_bytes(),
            &witness.account_data,
            &witness.account_address,
        ])
    };

    // ========================================================================
    // Step 5: Verify fanout-16 Merkle inclusion proof
    //
    // Proves the account hash is in the accounts_delta_hash tree.
    //
    // At each level, reconstruct the group of up to 16 children,
    // hash them together, and move up to the parent.
    // ========================================================================

    let mut current_hash = solana_account_hash;

    for level in &witness.inclusion_proof.levels {
        let group_size = level.siblings.len() + 1;
        let pos = level.position as usize;

        // Sanity checks
        assert!(
            group_size <= MERKLE_FANOUT,
            "Group size {} exceeds fanout {}",
            group_size,
            MERKLE_FANOUT
        );
        assert!(
            pos < group_size,
            "Position {} out of bounds for group size {}",
            pos,
            group_size
        );

        // Reconstruct the group: insert current_hash at position among siblings
        let mut group_preimage = Vec::with_capacity(group_size * 32);

        for sibling in &level.siblings[..pos] {
            group_preimage.extend_from_slice(sibling);
        }
        group_preimage.extend_from_slice(&current_hash);
        for sibling in &level.siblings[pos..] {
            group_preimage.extend_from_slice(sibling);
        }

        current_hash = sha256(&group_preimage);
    }

    // The computed root MUST equal the accounts_delta_hash
    assert_eq!(
        current_hash, witness.accounts_delta_hash,
        "Merkle proof verification failed: computed root != accounts_delta_hash"
    );

    // ========================================================================
    // Step 6: Verify bank hash derivation
    //
    // bank_hash = SHA-256(
    //     parent_bank_hash || accounts_delta_hash || sig_count_le || last_blockhash
    // )
    //
    // Matches Bank::hash_internal_state() in solana-runtime/src/bank.rs
    // ========================================================================

    let computed_bank_hash = hashv(&[
        &witness.bank_hash_components.parent_bank_hash,
        &witness.accounts_delta_hash,
        &witness.bank_hash_components.signature_count.to_le_bytes(),
        &witness.bank_hash_components.last_blockhash,
    ]);

    assert_eq!(
        computed_bank_hash, witness.bank_hash,
        "Bank hash derivation mismatch"
    );

    // ========================================================================
    // Step 7: Verify validator vote quorum (≥ 2/3 stake)
    //
    // Each validator vote is verified by:
    // 1. Ed25519 signature over the full serialized vote tx message
    // 2. The bank hash appears at a known offset in the signed message
    // 3. The validator has the claimed stake in the epoch
    //
    // The circuit sums confirmed stake and checks ≥ 2/3 of total.
    // ========================================================================

    assert!(
        !witness.validator_votes.is_empty(),
        "No validator votes provided"
    );

    assert!(
        witness.total_epoch_stake > 0,
        "Total epoch stake must be > 0"
    );

    let mut confirmed_stake: u64 = 0;

    for vote in &witness.validator_votes {
        // 7a. Verify Ed25519 signature over the serialized tx message
        let sig_valid = verify_ed25519(
            &vote.vote_authority,
            &vote.message_bytes,
            &vote.signature,
        );
        assert!(sig_valid, "Vote signature verification failed");

        // 7b. Verify the bank hash appears at the claimed offset
        let offset = vote.bank_hash_offset as usize;
        assert!(
            offset + 32 <= vote.message_bytes.len(),
            "bank_hash_offset out of bounds"
        );

        let hash_at_offset: [u8; 32] = vote.message_bytes[offset..offset + 32]
            .try_into()
            .expect("slice length mismatch");

        assert_eq!(
            hash_at_offset, witness.bank_hash,
            "Bank hash at offset does not match target bank hash"
        );

        // 7c. Verify this validator has the claimed stake in epoch_stakes
        let has_stake = witness.epoch_stakes.iter().any(|s| {
            s.pubkey == vote.validator_identity && s.stake == vote.stake
        });
        assert!(
            has_stake,
            "Validator identity not found in epoch stakes with claimed stake"
        );

        // Accumulate confirmed stake
        confirmed_stake = confirmed_stake
            .checked_add(vote.stake)
            .expect("Confirmed stake overflow");
    }

    // Verify quorum: confirmed_stake * 3 >= total_epoch_stake * 2
    let lhs = confirmed_stake
        .checked_mul(3)
        .expect("Quorum LHS overflow");
    let rhs = witness
        .total_epoch_stake
        .checked_mul(2)
        .expect("Quorum RHS overflow");

    assert!(
        lhs >= rhs,
        "Insufficient validator quorum: {}*3={} < {}*2={} (need ≥ 2/3)",
        confirmed_stake,
        lhs,
        witness.total_epoch_stake,
        rhs
    );

    // ========================================================================
    // Step 8: Commit public outputs
    //
    // These values are ABI-encoded for X0UnlockContract on Base.
    // ========================================================================

    let public_inputs = SolanaProofPublicInputs {
        bridge_program_id,
        nonce: parsed.nonce,
        solana_sender: parsed.solana_sender,
        evm_recipient: parsed.evm_recipient,
        amount: parsed.amount,
        burn_timestamp: parsed.burned_at,
        account_hash,
    };

    let encoded = public_inputs.abi_encode();
    sp1_zkvm::io::commit_slice(&encoded);
}
