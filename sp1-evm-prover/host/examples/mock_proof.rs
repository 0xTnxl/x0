//! Mock Proof End-to-End Example
//!
//! Fetches a real Base EVM transaction and runs the full proof pipeline
//! using the SP1 mock prover (native execution, no ZK overhead).
//!
//! # Usage
//!
//! ```bash
//! BASE_RPC_URLS=https://mainnet.base.org,https://base.llamarpc.com \
//! ETH_L1_RPC_URL=https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY \
//! TX_HASH=0xabc123... \
//! BRIDGE_PROGRAM_ID=<solana_program_id> \
//! SOLANA_RPC_URL=https://api.mainnet-beta.solana.com \
//!   cargo run -p x0-sp1-evm-host --example mock_proof
//! ```
//!
//! For an offline dry-run without Solana, set:
//!   SKIP_SOLANA_ANCHOR=1
//! and provide:
//!   ANCHOR_BLOCK=<block_number>
//!   ANCHOR_HASH=0x<32_bytes_hex>
//!
//! # What This Does
//!
//! 1. Fetches the trusted anchor from Solana (or uses explicit env vars)
//! 2. Fetches EVM block/tx/receipt artifacts via multi-RPC consensus
//! 3. Fetches L1 finality confirmation
//! 4. Builds the EVMProofWitness
//! 5. Runs `prover::generate_mock_proof` — executes the SP1 guest
//!    natively without generating a real ZK proof
//! 6. Prints proof size and public inputs

use anyhow::{Context, Result};

// Re-use the modules from the host crate
use x0_sp1_evm_host::{artifacts, multi_rpc, prover, solana_bridge};
use x0_sp1_evm_common::{LOCKED_EVENT_SIGNATURE};
use solana_sdk::pubkey::Pubkey;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    // ========================================================================
    // Configuration from env vars
    // ========================================================================
    let rpc_urls_raw = std::env::var("BASE_RPC_URLS")
        .context("BASE_RPC_URLS env var required (comma-separated, ≥2 URLs)")?;
    let rpc_urls: Vec<String> = rpc_urls_raw.split(',').map(|s| s.trim().to_string()).collect();
    anyhow::ensure!(rpc_urls.len() >= 2, "BASE_RPC_URLS must contain at least 2 URLs");

    let eth_l1_rpc = std::env::var("ETH_L1_RPC_URL")
        .context("ETH_L1_RPC_URL env var required")?;

    let tx_hash = std::env::var("TX_HASH")
        .context("TX_HASH env var required (hex, 0x-prefixed)")?;

    let network = std::env::var("BASE_NETWORK")
        .unwrap_or_else(|_| "base-mainnet".to_string());

    let min_consensus: usize = std::env::var("MIN_CONSENSUS")
        .unwrap_or_else(|_| "2".to_string())
        .parse()
        .context("MIN_CONSENSUS must be a positive integer")?;

    // ========================================================================
    // Step 1: Anchor
    // ========================================================================
    let (anchor_block, anchor_hash) = if std::env::var("SKIP_SOLANA_ANCHOR").as_deref() == Ok("1") {
        let block: u64 = std::env::var("ANCHOR_BLOCK")
            .context("ANCHOR_BLOCK required when SKIP_SOLANA_ANCHOR=1")?
            .parse()
            .context("ANCHOR_BLOCK must be a u64")?;
        let hash_hex = std::env::var("ANCHOR_HASH")
            .context("ANCHOR_HASH required when SKIP_SOLANA_ANCHOR=1")?;
        let hash_hex = hash_hex.strip_prefix("0x").unwrap_or(&hash_hex);
        let hash_bytes = hex::decode(hash_hex).context("ANCHOR_HASH must be valid hex")?;
        anyhow::ensure!(hash_bytes.len() == 32, "ANCHOR_HASH must be 32 bytes");
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&hash_bytes);
        tracing::info!("Using explicit anchor: block={}, hash=0x{}", block, hex::encode(arr));
        (block, arr)
    } else {
        let solana_rpc = std::env::var("SOLANA_RPC_URL")
            .unwrap_or_else(|_| "https://api.mainnet-beta.solana.com".to_string());
        let bridge_program_str = std::env::var("BRIDGE_PROGRAM_ID")
            .context("BRIDGE_PROGRAM_ID env var required (or set SKIP_SOLANA_ANCHOR=1)")?;
        let bridge_program: Pubkey = bridge_program_str
            .parse()
            .context("Invalid BRIDGE_PROGRAM_ID")?;
        let client = solana_bridge::SolanaBridgeClient::new(&solana_rpc)?;
        client.fetch_trusted_anchor(&bridge_program).await?
    };

    // ========================================================================
    // Step 2: Build consensus provider & fetch artifacts
    // ========================================================================
    tracing::info!("Initialising {}-of-{} RPC consensus provider...", min_consensus, rpc_urls.len());
    let provider = multi_rpc::ConsensusProvider::new(rpc_urls, min_consensus)
        .context("Failed to create consensus provider")?;

    let lock_contract_env = std::env::var("LOCK_CONTRACT").ok();
    let relevant_contracts: Vec<[u8; 20]> = match lock_contract_env {
        Some(ref addr) => {
            let s = addr.strip_prefix("0x").unwrap_or(addr);
            let b = hex::decode(s).context("Invalid LOCK_CONTRACT hex")?;
            anyhow::ensure!(b.len() == 20, "LOCK_CONTRACT must be 20 bytes");
            let mut arr = [0u8; 20];
            arr.copy_from_slice(&b);
            vec![arr]
        }
        None => vec![],
    };
    let relevant_topics = vec![LOCKED_EVENT_SIGNATURE];

    tracing::info!("Fetching EVM artifacts for tx {}...", tx_hash);
    let witness = artifacts::fetch_evm_artifacts(
        &provider,
        &eth_l1_rpc,
        &network,
        &tx_hash,
        anchor_block,
        anchor_hash,
        relevant_contracts,
        relevant_topics,
    )
    .await
    .context("Failed to fetch EVM artifacts")?;

    tracing::info!(
        "Artifacts fetched: block={}, tx_index={}",
        witness.block_number,
        witness.transaction_index,
    );

    // ========================================================================
    // Step 3: Generate mock proof
    // ========================================================================
    tracing::warn!("Generating MOCK proof — output is NOT verifiable on-chain");
    let (proof_bytes, public_inputs) = prover::generate_mock_proof(&witness)
        .context("Mock proof generation failed")?;

    // ========================================================================
    // Step 4: Print results
    // ========================================================================
    tracing::info!("✓ Mock proof generated successfully!");
    tracing::info!("  Proof size:   {} bytes", proof_bytes.len());
    tracing::info!("  Block number: {}", public_inputs.block_number);
    tracing::info!("  Tx hash:      0x{}", hex::encode(public_inputs.tx_hash));
    tracing::info!("  From:         0x{}", hex::encode(public_inputs.from));
    tracing::info!("  To:           0x{}", hex::encode(public_inputs.to));
    tracing::info!("  Value:        {} wei", public_inputs.value);
    tracing::info!("  Success:      {}", public_inputs.success);
    tracing::info!("  Event logs:   {}", public_inputs.event_logs.len());
    tracing::info!(
        "  Chain anchor: block={}, hash=0x{}",
        public_inputs.chain_anchor_block,
        hex::encode(public_inputs.chain_anchor_hash),
    );

    // Optionally write to files
    let out_proof = std::env::var("OUTPUT_PROOF").unwrap_or_else(|_| "mock_proof.bin".to_string());
    let out_pi = std::env::var("OUTPUT_PUBLIC_INPUTS")
        .unwrap_or_else(|_| "mock_public_inputs.json".to_string());

    std::fs::write(&out_proof, &proof_bytes)
        .with_context(|| format!("Failed to write proof to {}", out_proof))?;
    let pi_json = serde_json::to_string_pretty(&public_inputs)
        .context("Failed to serialise public inputs")?;
    std::fs::write(&out_pi, &pi_json)
        .with_context(|| format!("Failed to write public inputs to {}", out_pi))?;

    tracing::info!("  Written: {} ({} bytes)", out_proof, proof_bytes.len());
    tracing::info!("  Written: {}", out_pi);

    Ok(())
}
