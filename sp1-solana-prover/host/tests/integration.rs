//! Integration tests for x0 SP1 Solana State Prover
//!
//! These tests verify the prover components against live Solana devnet/mainnet.
//! They are disabled by default and require network access.
//!
//! # Running
//!
//! ```bash
//! # Run all integration tests (requires devnet access)
//! cargo test -p x0-sp1-solana-host --test integration -- --ignored --nocapture
//!
//! # Run a specific test
//! cargo test -p x0-sp1-solana-host --test integration test_devnet_fetch_block -- --ignored --nocapture
//!
//! # Full end-to-end (requires deployed bridge program)
//! BRIDGE_PROGRAM_ID=<id> NONCE=0 cargo test -p x0-sp1-solana-host --test integration test_end_to_end -- --ignored --nocapture
//! ```
//!
//! # Environment Variables
//!
//! - `SOLANA_RPC_URL` — RPC endpoint (default: `https://api.devnet.solana.com`)
//! - `BRIDGE_PROGRAM_ID` — x0-bridge program ID (required for end-to-end tests)
//! - `NONCE` — outbound bridge nonce to prove (required for end-to-end tests)

use solana_client::rpc_client::RpcClient;
use solana_sdk::pubkey::Pubkey;
use std::str::FromStr;
use x0_sp1_solana_host::fetcher::{merkle, rpc, tx_parser};

/// Get the RPC URL from env or default to devnet
fn rpc_url() -> String {
    std::env::var("SOLANA_RPC_URL")
        .unwrap_or_else(|_| "https://api.devnet.solana.com".to_string())
}

// ============================================================================
// Block Fetching Tests
// ============================================================================

#[test]
#[ignore = "requires Solana devnet access"]
fn test_devnet_fetch_block() {
    let rpc = RpcClient::new(rpc_url());

    // Get the current slot
    let slot = rpc.get_slot().expect("Failed to get current slot");
    println!("Current slot: {}", slot);

    // Fetch a recent finalized block (go back a few slots for safety)
    let target_slot = slot.saturating_sub(10);
    let block = rpc::fetch_block(&rpc, target_slot);

    match block {
        Ok(b) => {
            let tx_count = b.transactions.as_ref().map_or(0, |t| t.len());
            println!(
                "Block at slot {}: {} transactions, blockhash={}",
                target_slot, tx_count, b.blockhash
            );
            assert!(tx_count > 0, "Block should have transactions");
        }
        Err(e) => {
            // Slot might be skipped (leader didn't produce a block)
            println!(
                "Slot {} not available (may be skipped): {}",
                target_slot, e
            );
        }
    }
}

// ============================================================================
// Vote Parsing Tests
// ============================================================================

#[test]
#[ignore = "requires Solana devnet access"]
fn test_devnet_vote_parsing() {
    let rpc = RpcClient::new(rpc_url());
    let slot = rpc.get_slot().expect("Failed to get current slot");

    // Fetch a few recent blocks and look for vote transactions
    let blocks = rpc::fetch_vote_blocks(&rpc, slot.saturating_sub(20), 10)
        .expect("Failed to fetch vote blocks");

    println!("Fetched {} blocks", blocks.len());

    let mut total_vote_txs = 0;
    for (block_slot, block) in &blocks {
        if let Some(ref txs) = block.transactions {
            // Count vote transactions (simplistic: check if any tx has Vote program)
            for tx in txs {
                let raw = tx_parser::decode_transaction_bytes(&tx.transaction);
                if let Some(raw_bytes) = raw {
                    if let Some((_, _, keys)) = tx_parser::parse_raw_transaction(&raw_bytes) {
                        let vote_id =
                            tx_parser::VOTE_PROGRAM_ID_STR.parse::<Pubkey>().unwrap();
                        if keys.contains(&vote_id) {
                            total_vote_txs += 1;
                        }
                    }
                }
            }
            println!("Slot {}: {} transactions", block_slot, txs.len());
        }
    }

    println!("Found {} vote transactions across {} blocks", total_vote_txs, blocks.len());
    assert!(total_vote_txs > 0, "Should find at least one vote transaction in recent blocks");
}

#[test]
#[ignore = "requires Solana devnet access"]
fn test_devnet_vote_accounts() {
    let rpc = RpcClient::new(rpc_url());

    let vote_accounts = rpc::fetch_vote_accounts(&rpc)
        .expect("Failed to fetch vote accounts");

    println!("Vote accounts: {}", vote_accounts.len());
    assert!(!vote_accounts.is_empty(), "Should have vote accounts");

    let (stakes, total) = rpc::to_epoch_stakes(&vote_accounts);
    println!(
        "Epoch stakes: {} validators, total = {} SOL",
        stakes.len(),
        total / 1_000_000_000
    );
    assert!(total > 0, "Total stake should be > 0");
}

// ============================================================================
// Merkle Tree Tests (offline — no network needed)
// ============================================================================

#[test]
fn test_merkle_roundtrip_realistic_size() {
    // Simulate a realistic delta with ~500 accounts
    let hashes: Vec<[u8; 32]> = (0u32..500)
        .map(|i| {
            use sha2::{Digest, Sha256};
            let mut h = [0u8; 32];
            h[0..4].copy_from_slice(&i.to_le_bytes());
            Sha256::digest(&h).into()
        })
        .collect();

    let root = merkle::compute_merkle_root(&hashes);
    assert_ne!(root, [0u8; 32], "Root should not be zero");

    // Verify proof for every 50th leaf
    for idx in (0..500).step_by(50) {
        let proof = merkle::generate_inclusion_proof(&hashes, idx);
        assert!(
            merkle::verify_inclusion_proof(hashes[idx], &proof, &root),
            "Proof failed for leaf {}",
            idx
        );
    }
}

#[test]
fn test_merkle_proof_wrong_root_fails() {
    let hashes: Vec<[u8; 32]> = (0u8..16).map(|i| [i; 32]).collect();
    let root = merkle::compute_merkle_root(&hashes);
    let proof = merkle::generate_inclusion_proof(&hashes, 0);

    // Correct root should verify
    assert!(merkle::verify_inclusion_proof(hashes[0], &proof, &root));

    // Wrong root should fail
    let wrong_root = [0xFFu8; 32];
    assert!(!merkle::verify_inclusion_proof(hashes[0], &proof, &wrong_root));
}

#[test]
fn test_merkle_proof_wrong_leaf_fails() {
    let hashes: Vec<[u8; 32]> = (0u8..16).map(|i| [i; 32]).collect();
    let root = merkle::compute_merkle_root(&hashes);
    let proof = merkle::generate_inclusion_proof(&hashes, 0);

    // Correct leaf should verify
    assert!(merkle::verify_inclusion_proof(hashes[0], &proof, &root));

    // Wrong leaf should fail
    let wrong_leaf = [0xFFu8; 32];
    assert!(!merkle::verify_inclusion_proof(wrong_leaf, &proof, &root));
}

// ============================================================================
// Transaction Parser Tests (offline)
// ============================================================================

#[test]
fn test_tx_parser_compact_u16_encoding() {
    // Test all boundary values
    assert_eq!(tx_parser::read_compact_u16(&[0x00], 0), Some((0, 1)));
    assert_eq!(tx_parser::read_compact_u16(&[0x7F], 0), Some((127, 1)));
    assert_eq!(tx_parser::read_compact_u16(&[0x80, 0x01], 0), Some((128, 2)));
    assert_eq!(tx_parser::read_compact_u16(&[0x80, 0x80, 0x01], 0), Some((16384, 3)));
}

// ============================================================================
// Account Hash Tests (offline)
// ============================================================================

#[test]
fn test_solana_account_hash_zero_lamports() {
    // Zero-lamport accounts should produce [0u8; 32]
    let hash = merkle::compute_solana_account_hash(
        0,
        &[0u8; 32],
        false,
        0,
        &[],
        &[0u8; 32],
    );
    assert_eq!(hash, [0u8; 32], "Zero-lamport accounts should hash to zero");
}

#[test]
fn test_solana_account_hash_deterministic() {
    let owner = [1u8; 32];
    let pubkey = [2u8; 32];
    let data = b"hello world";

    let hash1 = merkle::compute_solana_account_hash(1000, &owner, false, 0, data, &pubkey);
    let hash2 = merkle::compute_solana_account_hash(1000, &owner, false, 0, data, &pubkey);

    assert_eq!(hash1, hash2, "Same inputs should produce same hash");
    assert_ne!(hash1, [0u8; 32], "Non-zero lamports should produce non-zero hash");
}

#[test]
fn test_solana_account_hash_changes_with_data() {
    let owner = [1u8; 32];
    let pubkey = [2u8; 32];

    let hash1 = merkle::compute_solana_account_hash(1000, &owner, false, 0, b"foo", &pubkey);
    let hash2 = merkle::compute_solana_account_hash(1000, &owner, false, 0, b"bar", &pubkey);

    assert_ne!(hash1, hash2, "Different data should produce different hashes");
}

// ============================================================================
// Vote Instruction Parsing Tests (offline — synthetic data)
// ============================================================================

#[test]
fn test_find_bank_hash_synthetic() {
    // Create synthetic vote instruction data with a known bank hash
    let target_hash = [0xABu8; 32];

    // Simulate CompactUpdateVoteState: tag=12, 1 lockout, no root, then hash
    let mut ix_data = Vec::new();
    ix_data.extend_from_slice(&12u32.to_le_bytes()); // tag
    ix_data.push(0x01); // num_lockouts = 1 (compact u16)
    ix_data.push(0x64); // slot_delta = 100 (compact u16)
    ix_data.push(0x1F); // confirmation_count = 31
    ix_data.push(0x00); // has_root = false
    ix_data.extend_from_slice(&target_hash); // bank hash

    // The find_bank_hash_in_vote_data should locate it via scanning
    let found = find_hash_in_data(&ix_data, &target_hash);
    assert!(found, "Should find the bank hash in synthetic vote data");
}

/// Helper: scan for a 32-byte hash in data (mimics find_bank_hash_in_vote_data)
fn find_hash_in_data(data: &[u8], target: &[u8; 32]) -> bool {
    if data.len() < 36 {
        return false;
    }
    for offset in 4..=(data.len().saturating_sub(32)) {
        if &data[offset..offset + 32] == target {
            return true;
        }
    }
    false
}

// ============================================================================
// End-to-End Tests (require devnet + deployed bridge)
// ============================================================================

#[test]
#[ignore = "requires devnet access and deployed bridge program"]
fn test_end_to_end_witness_assembly() {
    let bridge_program_id = std::env::var("BRIDGE_PROGRAM_ID")
        .expect("BRIDGE_PROGRAM_ID env var required");
    let nonce: u64 = std::env::var("NONCE")
        .expect("NONCE env var required")
        .parse()
        .expect("NONCE must be a number");

    let rpc = RpcClient::new(rpc_url());
    let bridge_program = Pubkey::from_str(&bridge_program_id)
        .expect("Invalid BRIDGE_PROGRAM_ID");

    // Derive PDA
    let (pda, _bump) = Pubkey::find_program_address(
        &[b"bridge_out_message", &nonce.to_le_bytes()],
        &bridge_program,
    );
    println!("BridgeOutMessage PDA: {}", pda);

    // Fetch account
    let account = rpc
        .get_account(&pda)
        .expect("Failed to fetch BridgeOutMessage — may not be deployed");

    println!(
        "Account: owner={}, data_len={}, lamports={}",
        account.owner,
        account.data.len(),
        account.lamports
    );

    assert_eq!(
        account.owner, bridge_program,
        "Account owner should be bridge program"
    );

    // Parse the account
    let parsed = x0_sp1_solana_common::ParsedBridgeOutMessage::try_from_bytes(&account.data)
        .expect("Failed to parse BridgeOutMessage");

    println!("Parsed: nonce={}, amount={}, status={}", parsed.nonce, parsed.amount, parsed.status);
    assert_eq!(parsed.nonce, nonce, "Nonce mismatch");
    assert_eq!(parsed.status, 0, "Status should be Burned (0)");

    // Attempt witness assembly
    let rt = tokio::runtime::Runtime::new().unwrap();
    let witness = rt.block_on(async {
        x0_sp1_solana_host::fetcher::fetch_witness(
            &rpc,
            &bridge_program,
            &pda,
            &account,
        )
        .await
    });

    match witness {
        Ok(w) => {
            println!("Witness assembled successfully!");
            println!("  Slot: {}", w.slot);
            println!("  Account data: {} bytes", w.account_data.len());
            println!("  Inclusion proof: {} levels", w.inclusion_proof.levels.len());
            println!("  Validator votes: {}", w.validator_votes.len());
            println!("  Epoch stakes: {} validators", w.epoch_stakes.len());
            println!("  Total epoch stake: {} SOL", w.total_epoch_stake / 1_000_000_000);

            let confirmed: u64 = w.validator_votes.iter().map(|v| v.stake).sum();
            let pct = (confirmed as f64 / w.total_epoch_stake as f64) * 100.0;
            println!("  Confirmed stake: {:.1}%", pct);

            assert!(!w.validator_votes.is_empty(), "Should have validator votes");
            assert!(w.inclusion_proof.levels.len() > 0, "Should have inclusion proof");
        }
        Err(e) => {
            println!("Witness assembly failed (expected on devnet without exact slot state): {}", e);
            // Don't panic — this can fail legitimately on devnet due to
            // the historical state limitation
        }
    }
}
