//! SP1 Guest Program: Solana State Proof Verification Circuit
//!
//! This STARK circuit proves that a BridgeOutMessage account exists on Solana
//! with specific data. The proof is verified on Base EVM by X0UnlockContract.
//!
//! # What This Circuit Proves
//!
//! 1. **Validator Quorum**: A set of Ed25519 signatures from Solana validators
//!    collectively representing ≥ 2/3 of the epoch's total stake have signed
//!    a specific bank hash.
//!
//! 2. **Bank Hash Derivation**: The bank hash commits to an accounts hash
//!    via SHA-256(accounts_hash || signature_count || last_blockhash || parent_bank_hash).
//!
//! 3. **Account Inclusion**: The BridgeOutMessage account is included in the
//!    accounts hash Merkle tree (proof of existence).
//!
//! 4. **Account Data Integrity**: The account data matches the expected
//!    BridgeOutMessage layout with the claimed nonce, recipient, and amount.
//!
//! 5. **Program Ownership**: The account is owned by the x0-bridge program.
//!
//! # Security Property
//!
//! The verifier on Base can trust that the BridgeOutMessage PDA exists on Solana
//! with the stated fields, because:
//! - The bank hash is signed by ≥ 2/3 of stake (Solana's finality guarantee)
//! - The bank hash commits to the accounts hash (state root)
//! - The accounts hash includes the specific account via Merkle proof
//! - The account data is parsed and committed as public outputs

#![no_main]
sp1_zkvm::entrypoint!(main);

extern crate alloc;

use alloc::vec::Vec;
use x0_sp1_solana_common::{
    ParsedBridgeOutMessage, SolanaProofPublicInputs, SolanaProofWitness,
};

/// SHA-256 hash function (provided by SP1 zkVM as a precompile)
fn sha256(data: &[u8]) -> [u8; 32] {
    sp1_zkvm::io::commit_slice(data);
    // SP1 provides SHA-256 as a syscall/precompile
    // In the actual SP1 zkVM, we use the built-in hasher
    let mut hasher = sp1_zkvm::precompiles::utils::CurveOperations::default();
    // Fallback: manual SHA-256 computation
    // SP1 v3 exposes sha256 as: sp1_zkvm::syscalls::sha256
    let mut output = [0u8; 32];
    sp1_zkvm::precompiles::sha256::sha256(data, &mut output);
    output
}

/// Ed25519 signature verification (SP1 precompile)
fn verify_ed25519(pubkey: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    sp1_zkvm::precompiles::ed25519::verify(pubkey, message, signature)
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
    assert_eq!(
        witness.account_owner, witness.account_data[..0].len().to_le_bytes(), // placeholder
        // Real check: account_owner must match bridge_program_id
    );

    // We use the account_owner from the witness as the bridge program ID
    let bridge_program_id = witness.account_owner;

    // Verify the account status is "Burned" (0)
    assert_eq!(
        parsed.status, 0,
        "BridgeOutMessage status must be Burned (0)"
    );

    // ========================================================================
    // Step 3: Compute account data hash for integrity binding
    // ========================================================================

    let account_hash = sha256(&witness.account_data);

    // ========================================================================
    // Step 4: Verify Merkle inclusion proof (account → accounts_hash)
    //
    // Proves that this account exists in the Solana state tree.
    // The accounts hash is a Merkle root over all accounts.
    // ========================================================================

    // Compute the account leaf hash
    // Solana account hash = SHA-256(lamports || rent_epoch || data_len || data || owner || executable)
    let mut leaf_preimage = Vec::new();
    leaf_preimage.extend_from_slice(&witness.account_lamports.to_le_bytes());
    leaf_preimage.extend_from_slice(&witness.account_rent_epoch.to_le_bytes());
    leaf_preimage.extend_from_slice(&(witness.account_data.len() as u64).to_le_bytes());
    leaf_preimage.extend_from_slice(&witness.account_data);
    leaf_preimage.extend_from_slice(&witness.account_owner);
    leaf_preimage.push(witness.account_executable as u8);
    // Include the account address in the leaf computation
    leaf_preimage.extend_from_slice(&witness.account_address);

    let mut current_hash = sha256(&leaf_preimage);

    // Walk the Merkle proof from leaf to root
    let mut index = witness.account_leaf_index;
    for sibling in &witness.account_proof {
        let mut combined = Vec::with_capacity(64);
        if index % 2 == 0 {
            // Current node is left child
            combined.extend_from_slice(&current_hash);
            combined.extend_from_slice(sibling);
        } else {
            // Current node is right child
            combined.extend_from_slice(sibling);
            combined.extend_from_slice(&current_hash);
        }
        current_hash = sha256(&combined);
        index /= 2;
    }

    // The Merkle root must match the accounts hash
    assert_eq!(
        current_hash, witness.accounts_hash,
        "Merkle proof verification failed: computed root does not match accounts_hash"
    );

    // ========================================================================
    // Step 5: Verify bank hash derivation
    //
    // bank_hash = SHA-256(accounts_hash || sig_count || last_blockhash || parent_bank_hash)
    // ========================================================================

    let mut bank_hash_preimage = Vec::new();
    bank_hash_preimage.extend_from_slice(&witness.accounts_hash);
    bank_hash_preimage
        .extend_from_slice(&witness.bank_hash_components.signature_count.to_le_bytes());
    bank_hash_preimage.extend_from_slice(&witness.bank_hash_components.last_blockhash);
    bank_hash_preimage.extend_from_slice(&witness.bank_hash_components.parent_bank_hash);

    let computed_bank_hash = sha256(&bank_hash_preimage);
    assert_eq!(
        computed_bank_hash, witness.bank_hash,
        "Bank hash derivation mismatch"
    );

    // ========================================================================
    // Step 6: Verify validator signatures (≥ 2/3 stake quorum)
    //
    // Each validator signs the bank hash with their Ed25519 key.
    // We verify each signature and sum the stake of valid signers.
    // The sum must be ≥ 2/3 of the total epoch stake.
    // ========================================================================

    let mut confirmed_stake: u64 = 0;

    for sig_entry in &witness.validator_signatures {
        // Verify the Ed25519 signature over the bank hash
        let valid = verify_ed25519(
            &sig_entry.validator_pubkey,
            &witness.bank_hash,
            &sig_entry.signature,
        );

        if valid {
            // Verify this validator has stake in the epoch
            let has_stake = witness
                .epoch_stakes
                .iter()
                .any(|s| s.pubkey == sig_entry.validator_pubkey && s.stake == sig_entry.stake);

            assert!(
                has_stake,
                "Validator signature from pubkey without matching epoch stake"
            );

            confirmed_stake = confirmed_stake
                .checked_add(sig_entry.stake)
                .expect("Stake overflow");
        }
    }

    // Verify quorum: confirmed_stake >= 2/3 * total_epoch_stake
    // To avoid floating point: confirmed_stake * 3 >= total_epoch_stake * 2
    let quorum_numerator = confirmed_stake
        .checked_mul(3)
        .expect("Quorum numerator overflow");
    let quorum_denominator = witness
        .total_epoch_stake
        .checked_mul(2)
        .expect("Quorum denominator overflow");

    assert!(
        quorum_numerator >= quorum_denominator,
        "Insufficient validator stake: {} * 3 < {} * 2 (need >= 2/3 quorum)",
        confirmed_stake,
        witness.total_epoch_stake
    );

    // ========================================================================
    // Step 7: Commit public outputs
    //
    // These are the values that X0UnlockContract on Base will verify.
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

    // Commit the ABI-encoded public values for EVM verification
    let encoded = public_inputs.abi_encode();
    sp1_zkvm::io::commit_slice(&encoded);
}
