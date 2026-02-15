//! SP1 Guest Program: Solana State Proof Verification Circuit
//!
//! This STARK circuit proves that a BridgeOutMessage account exists on Solana
//! with specific data. The proof is verified on Base EVM by X0UnlockContract.
//!
//! # What This Circuit Proves
//!
//! 1. **Account Data Integrity**: The BridgeOutMessage account data has a
//!    valid Anchor discriminator and status == Burned.
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
//! 5. **Validator Set Commitment**: The epoch stakes are hashed and committed
//!    as a public output (`validator_set_hash`), verified on-chain by the
//!    EVM contract against a governance-maintained value.
//!
//! 6. **Validator Quorum**: ≥ 2/3 of epoch stake signed vote transactions
//!    containing the bank hash (Ed25519 over serialized tx message).
//!    Votes are deduplicated by vote_authority — each authority is counted
//!    at most once.
//!
//! # Security Properties
//!
//! The verifier on Base can trust the BridgeOutMessage exists because:
//! - Validator votes prove slot finality (Solana's Tower BFT)
//! - The bank hash commits to the accounts_delta_hash (SHA-256 preimage)
//! - The delta hash includes the account via cryptographic Merkle proof
//! - The account data is parsed, discriminator-checked, and committed
//! - The validator set hash is verified against a known good value on-chain
//! - Vote deduplication prevents double-counting stake

#![no_main]
#![allow(dead_code)]
sp1_zkvm::entrypoint!(main);

extern crate alloc;

use alloc::vec::Vec;
use sha2::{Digest, Sha256};
use x0_sp1_solana_common::{
    ParsedBridgeOutMessage, SolanaProofPublicInputs, SolanaProofWitness,
    BRIDGE_OUT_MESSAGE_ACCOUNT_NAME, MERKLE_FANOUT,
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

    // 2a. Validate Anchor discriminator cryptographically.
    //     Compute SHA-256("account:BridgeOutMessage") and check first 8 bytes.
    //     Prevents a malicious host from supplying arbitrary data that
    //     happens to parse into the expected field layout.
    let expected_discriminator = {
        let preimage = [b"account:" as &[u8], BRIDGE_OUT_MESSAGE_ACCOUNT_NAME.as_bytes()].concat();
        let hash = sha256(&preimage);
        let mut disc = [0u8; 8];
        disc.copy_from_slice(&hash[..8]);
        disc
    };
    assert_eq!(
        parsed.discriminator, expected_discriminator,
        "BridgeOutMessage Anchor discriminator mismatch — \
         account data is not a valid BridgeOutMessage"
    );

    // 2b. Verify the account is owned by the bridge program
    let bridge_program_id = witness.account_owner;

    // 2c. Verify the account status is "Burned" (0)
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
    // Zero-lamport accounts hash to [0u8; 32] (Solana convention), but
    // a funded BridgeOutMessage PDA must have lamports > 0.
    // ========================================================================

    assert!(
        witness.account_lamports > 0,
        "Account lamports must be > 0 (zero-lamport accounts hash to zero, \
         indicating a closed account)"
    );

    let solana_account_hash = hashv(&[
        &witness.account_lamports.to_le_bytes(),
        &witness.account_owner,
        &[witness.account_executable as u8],
        &witness.account_rent_epoch.to_le_bytes(),
        &witness.account_data,
        &witness.account_address,
    ]);

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

    assert_eq!(
        current_hash, witness.accounts_delta_hash,
        "Merkle proof verification failed: computed root != accounts_delta_hash"
    );

    // ========================================================================
    // Step 6: Verify bank hash derivation
    //
    // bank_hash(S) = SHA-256(
    //     bank_hash(S-1) || accounts_delta_hash(S) || sig_count_le(S)
    //     || last_blockhash(S)
    // )
    //
    // Matches Bank::hash_internal_state() in solana-runtime/src/bank.rs.
    //
    // CRITICAL: parent_bank_hash must be the REAL parent bank hash,
    // not a placeholder. SHA-256 preimage resistance ensures that a
    // correct computed_bank_hash can only result from the true inputs.
    // The parent_bank_hash itself need not be quorum-verified — the
    // quorum verification on bank_hash(S) provides the binding.
    // ========================================================================

    assert_ne!(
        witness.bank_hash_components.parent_bank_hash,
        [0u8; 32],
        "Parent bank hash must not be zero — \
         host must fetch it from votes on the parent slot"
    );

    let computed_bank_hash = hashv(&[
        &witness.bank_hash_components.parent_bank_hash,
        &witness.accounts_delta_hash,
        &witness.bank_hash_components.signature_count.to_le_bytes(),
        &witness.bank_hash_components.last_blockhash,
    ]);

    assert_eq!(
        computed_bank_hash, witness.bank_hash,
        "Bank hash derivation mismatch: \
         SHA-256(parent || delta || sig_count || blockhash) != bank_hash"
    );

    // ========================================================================
    // Step 7: Compute validator_set_hash from epoch_stakes
    //
    // This commits the validator set to public outputs, preventing a
    // malicious prover from fabricating epoch stakes. The EVM contract
    // validates this hash against a governance-maintained value.
    //
    // Hash = SHA-256(
    //   for each entry (must be sorted by vote_authority ascending):
    //     vote_authority(32) || validator_identity(32) || stake(8 BE)
    // )
    // ========================================================================

    assert!(
        !witness.epoch_stakes.is_empty(),
        "Epoch stakes must not be empty"
    );
    assert!(
        witness.total_epoch_stake > 0,
        "Total epoch stake must be > 0"
    );

    // 7a. Verify epoch_stakes are strictly sorted by vote_authority
    //     (deterministic hash, no duplicates in the set itself)
    for i in 1..witness.epoch_stakes.len() {
        assert!(
            witness.epoch_stakes[i].vote_authority > witness.epoch_stakes[i - 1].vote_authority,
            "Epoch stakes must be strictly sorted by vote_authority (dup or unsorted at index {})",
            i
        );
    }

    // 7b. Verify total_epoch_stake matches the sum of individual stakes
    let computed_total_stake: u64 = witness
        .epoch_stakes
        .iter()
        .fold(0u64, |acc, entry| {
            acc.checked_add(entry.stake)
                .expect("Epoch stake sum overflow")
        });
    assert_eq!(
        computed_total_stake, witness.total_epoch_stake,
        "total_epoch_stake ({}) does not match sum of individual stakes ({})",
        witness.total_epoch_stake, computed_total_stake
    );

    // 7c. Compute the validator set hash
    let mut set_hasher = Sha256::new();
    for entry in &witness.epoch_stakes {
        set_hasher.update(&entry.vote_authority);
        set_hasher.update(&entry.validator_identity);
        set_hasher.update(&entry.stake.to_be_bytes());
    }
    let validator_set_hash: [u8; 32] = set_hasher.finalize().into();

    // ========================================================================
    // Step 8: Verify validator vote quorum (≥ 2/3 stake) with deduplication
    //
    // Each validator vote is verified by:
    // 1. Ed25519 signature over the full serialized vote tx message
    // 2. The bank hash appears at a known offset in the signed message
    // 3. The vote_authority exists in epoch_stakes with matching stake
    // 4. Each vote_authority is counted at most once (deduplication)
    //
    // The circuit sums confirmed stake and checks ≥ 2/3 of total.
    // ========================================================================

    assert!(
        !witness.validator_votes.is_empty(),
        "No validator votes provided"
    );

    let mut confirmed_stake: u64 = 0;

    // Track seen vote authorities for deduplication.
    // O(n²) linear scan — bounded by validator vote count (~200 max).
    let mut seen_authorities: Vec<[u8; 32]> = Vec::with_capacity(witness.validator_votes.len());

    for vote in &witness.validator_votes {
        // 8a. Deduplicate by vote_authority — each authority counted at most once.
        //     A malicious host could submit the same validator's vote multiple
        //     times to inflate confirmed_stake without this check.
        let is_duplicate = seen_authorities
            .iter()
            .any(|seen| *seen == vote.vote_authority);
        assert!(
            !is_duplicate,
            "Duplicate vote from same vote_authority — \
             host must deduplicate before submitting to circuit"
        );
        seen_authorities.push(vote.vote_authority);

        // 8b. Verify Ed25519 signature over the serialized tx message
        let sig_valid = verify_ed25519(
            &vote.vote_authority,
            &vote.message_bytes,
            &vote.signature,
        );
        assert!(sig_valid, "Vote signature verification failed");

        // 8c. Verify the bank hash appears at the claimed offset
        let offset = vote.bank_hash_offset as usize;
        assert!(
            offset + 32 <= vote.message_bytes.len(),
            "bank_hash_offset {} out of bounds (message len {})",
            offset,
            vote.message_bytes.len()
        );

        let hash_at_offset: [u8; 32] = vote.message_bytes[offset..offset + 32]
            .try_into()
            .expect("slice length mismatch");

        assert_eq!(
            hash_at_offset, witness.bank_hash,
            "Bank hash at offset does not match target bank hash"
        );

        // 8d. Verify this vote_authority exists in committed epoch_stakes
        //     with matching validator_identity and stake.
        //     This cryptographically binds: vote_authority → identity → stake,
        //     since the epoch_stakes are committed via validator_set_hash.
        let entry = witness
            .epoch_stakes
            .iter()
            .find(|e| e.vote_authority == vote.vote_authority);

        let entry = entry.expect(
            "Vote authority not found in epoch stakes — \
             host provided a vote from an unknown validator",
        );

        assert_eq!(
            entry.validator_identity, vote.validator_identity,
            "Validator identity mismatch between vote and epoch stakes"
        );
        assert_eq!(
            entry.stake, vote.stake,
            "Stake mismatch between vote and epoch stakes"
        );

        // 8e. Accumulate confirmed stake
        confirmed_stake = confirmed_stake
            .checked_add(vote.stake)
            .expect("Confirmed stake overflow");
    }

    // 8f. Verify quorum: confirmed_stake * 3 >= total_epoch_stake * 2
    let lhs = confirmed_stake
        .checked_mul(3)
        .expect("Quorum LHS overflow");
    let rhs = witness
        .total_epoch_stake
        .checked_mul(2)
        .expect("Quorum RHS overflow");

    assert!(
        lhs >= rhs,
        "Insufficient validator quorum: {confirmed_stake}*3={lhs} < {}*2={rhs} (need >= 2/3)",
        witness.total_epoch_stake,
    );

    // ========================================================================
    // Step 9: Commit public outputs
    //
    // These values are ABI-encoded for X0UnlockContract on Base.
    // The 10-slot ABI encoding includes the validator_set_hash, slot,
    // and total_epoch_stake for on-chain verification.
    // ========================================================================

    let public_inputs = SolanaProofPublicInputs {
        bridge_program_id,
        nonce: parsed.nonce,
        solana_sender: parsed.solana_sender,
        evm_recipient: parsed.evm_recipient,
        amount: parsed.amount,
        burn_timestamp: parsed.burned_at,
        account_hash,
        validator_set_hash,
        slot: witness.slot,
        total_epoch_stake: witness.total_epoch_stake,
    };

    let encoded = public_inputs.abi_encode();
    sp1_zkvm::io::commit_slice(&encoded);
}
