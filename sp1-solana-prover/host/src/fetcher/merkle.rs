//! Fanout-16 Merkle tree implementation matching Solana's accounts hash computation
//!
//! Solana uses a recursive fanout-16 tree to compute the `accounts_delta_hash`
//! from account hashes. This module replicates the exact algorithm for:
//!
//! 1. Building the tree from a set of account hashes
//! 2. Computing the root (matches Solana's `accounts_delta_hash`)
//! 3. Generating inclusion proofs for individual accounts
//!
//! # Algorithm
//!
//! At each level, hashes are grouped into chunks of 16 (the last chunk may
//! be smaller). Each chunk is hashed: `SHA-256(h0 || h1 || ... || h15)`.
//! This produces N/16 hashes for the next level. Recurse until one hash remains.
//!
//! This matches:
//! `solana-accounts-db/src/accounts_hash.rs::compute_merkle_root_and_capitalization_loop()`

use sha2::{Digest, Sha256};
use x0_sp1_solana_common::{AccountInclusionProof, FanoutProofLevel, MERKLE_FANOUT};

/// Compute the Merkle root of a set of hashes using Solana's fanout-16 algorithm
///
/// The input hashes MUST be sorted by pubkey (ascending) — this is the caller's
/// responsibility and matches Solana's convention.
pub fn compute_merkle_root(hashes: &[[u8; 32]]) -> [u8; 32] {
    if hashes.is_empty() {
        return [0u8; 32]; // Solana returns Hash::default() for empty sets
    }
    if hashes.len() == 1 {
        return hashes[0];
    }

    // Compute next level: group into chunks of MERKLE_FANOUT and hash each
    let next_level: Vec<[u8; 32]> = hashes
        .chunks(MERKLE_FANOUT)
        .map(|chunk| hash_chunk(chunk))
        .collect();

    compute_merkle_root(&next_level)
}

/// Generate a Merkle inclusion proof for a leaf at the given index
///
/// Returns the proof levels from leaf to root, with sibling hashes at each level.
///
/// # Arguments
/// * `hashes` - All leaves (sorted by pubkey, matching Solana's order)
/// * `target_index` - Index of the target leaf in `hashes`
pub fn generate_inclusion_proof(
    hashes: &[[u8; 32]],
    target_index: usize,
) -> AccountInclusionProof {
    assert!(!hashes.is_empty(), "Cannot generate proof for empty tree");
    assert!(
        target_index < hashes.len(),
        "target_index {} out of bounds for {} hashes",
        target_index,
        hashes.len()
    );

    let total_delta_accounts = hashes.len() as u32;
    let mut levels = Vec::new();

    let mut current_level = hashes.to_vec();
    let mut current_index = target_index;

    while current_level.len() > 1 {
        // Figure out which chunk our target is in
        let chunk_index = current_index / MERKLE_FANOUT;
        let position_in_chunk = current_index % MERKLE_FANOUT;

        // Get the chunk boundaries
        let chunk_start = chunk_index * MERKLE_FANOUT;
        let chunk_end = (chunk_start + MERKLE_FANOUT).min(current_level.len());
        let chunk = &current_level[chunk_start..chunk_end];

        // Extract siblings (all elements except the target)
        let siblings: Vec<[u8; 32]> = chunk
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != position_in_chunk)
            .map(|(_, h)| *h)
            .collect();

        levels.push(FanoutProofLevel {
            siblings,
            position: position_in_chunk as u8,
        });

        // Compute next level
        let next_level: Vec<[u8; 32]> = current_level
            .chunks(MERKLE_FANOUT)
            .map(|c| hash_chunk(c))
            .collect();

        current_level = next_level;
        current_index = chunk_index; // Our target is now at this index in the next level
    }

    AccountInclusionProof {
        levels,
        total_delta_accounts,
    }
}

/// Verify a Merkle inclusion proof (host-side verification before submitting to SP1)
///
/// Returns true if the proof verifies correctly.
pub fn verify_inclusion_proof(
    leaf_hash: [u8; 32],
    proof: &AccountInclusionProof,
    expected_root: &[u8; 32],
) -> bool {
    let mut current = leaf_hash;

    for level in &proof.levels {
        let group_size = level.siblings.len() + 1;
        let pos = level.position as usize;

        if pos >= group_size || group_size > MERKLE_FANOUT {
            return false;
        }

        // Reconstruct the group
        let mut group = Vec::with_capacity(group_size * 32);
        for sibling in &level.siblings[..pos] {
            group.extend_from_slice(sibling);
        }
        group.extend_from_slice(&current);
        for sibling in &level.siblings[pos..] {
            group.extend_from_slice(sibling);
        }

        current = sha256_hash(&group);
    }

    current == *expected_root
}

/// Hash a chunk of up to MERKLE_FANOUT hashes (Solana's per-level computation)
fn hash_chunk(chunk: &[[u8; 32]]) -> [u8; 32] {
    if chunk.len() == 1 {
        return chunk[0];
    }

    let mut preimage = Vec::with_capacity(chunk.len() * 32);
    for h in chunk {
        preimage.extend_from_slice(h);
    }
    sha256_hash(&preimage)
}

/// SHA-256 helper
fn sha256_hash(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// Compute Solana's account hash (matching AccountsDb::hash_account)
///
/// Field order: lamports || owner || executable || rent_epoch || data || pubkey
pub fn compute_solana_account_hash(
    lamports: u64,
    owner: &[u8; 32],
    executable: bool,
    rent_epoch: u64,
    data: &[u8],
    pubkey: &[u8; 32],
) -> [u8; 32] {
    if lamports == 0 {
        return [0u8; 32];
    }

    let preimage_len = 8 + 32 + 1 + 8 + data.len() + 32;
    let mut preimage = Vec::with_capacity(preimage_len);

    preimage.extend_from_slice(&lamports.to_le_bytes());
    preimage.extend_from_slice(owner);
    preimage.push(executable as u8);
    preimage.extend_from_slice(&rent_epoch.to_le_bytes());
    preimage.extend_from_slice(data);
    preimage.extend_from_slice(pubkey);

    sha256_hash(&preimage)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_leaf_tree() {
        let hash = [42u8; 32];
        let root = compute_merkle_root(&[hash]);
        assert_eq!(root, hash);
    }

    #[test]
    fn test_two_leaf_tree() {
        let h0 = [1u8; 32];
        let h1 = [2u8; 32];
        let root = compute_merkle_root(&[h0, h1]);

        let mut preimage = Vec::new();
        preimage.extend_from_slice(&h0);
        preimage.extend_from_slice(&h1);
        let expected: [u8; 32] = Sha256::digest(&preimage).into();

        assert_eq!(root, expected);
    }

    #[test]
    fn test_proof_roundtrip() {
        // Create 50 random-ish hashes (simulating a small delta)
        let hashes: Vec<[u8; 32]> = (0u32..50)
            .map(|i| {
                let mut h = [0u8; 32];
                h[0..4].copy_from_slice(&i.to_le_bytes());
                sha256_hash(&h)
            })
            .collect();

        let root = compute_merkle_root(&hashes);

        // Generate and verify proof for each leaf
        for i in 0..hashes.len() {
            let proof = generate_inclusion_proof(&hashes, i);
            assert!(
                verify_inclusion_proof(hashes[i], &proof, &root),
                "Proof failed for leaf {}",
                i
            );
        }
    }

    #[test]
    fn test_fanout_exact_16() {
        let hashes: Vec<[u8; 32]> = (0u32..16)
            .map(|i| {
                let mut h = [0u8; 32];
                h[0..4].copy_from_slice(&i.to_le_bytes());
                h
            })
            .collect();

        let root = compute_merkle_root(&hashes);
        let proof = generate_inclusion_proof(&hashes, 7);

        assert_eq!(proof.levels.len(), 1); // Single level for 16 leaves
        assert_eq!(proof.levels[0].siblings.len(), 15);
        assert_eq!(proof.levels[0].position, 7);
        assert!(verify_inclusion_proof(hashes[7], &proof, &root));
    }

    #[test]
    fn test_proof_3000_leaves() {
        // Realistic: ~3000 accounts modified in a slot
        let hashes: Vec<[u8; 32]> = (0u32..3000)
            .map(|i| {
                let mut h = [0u8; 32];
                h[0..4].copy_from_slice(&i.to_le_bytes());
                sha256_hash(&h)
            })
            .collect();

        let root = compute_merkle_root(&hashes);

        // Verify a few proofs
        for &idx in &[0, 1500, 2999] {
            let proof = generate_inclusion_proof(&hashes, idx);
            assert!(
                verify_inclusion_proof(hashes[idx], &proof, &root),
                "Proof failed for leaf {} in 3000-leaf tree",
                idx
            );
            // Should be 3 levels for 3000 leaves with fanout 16
            assert!(proof.levels.len() <= 3, "Expected ≤3 levels, got {}", proof.levels.len());
        }
    }
}
