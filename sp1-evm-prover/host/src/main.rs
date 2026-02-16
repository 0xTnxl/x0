//! SP1 Host Program: EVM Artifact Fetcher & STARK Proof Generator
//!
//! This program runs off-chain and:
//!
//! 1. Fetches EVM block headers, transactions, and receipts from an RPC node
//! 2. Constructs Merkle-Patricia Trie inclusion proofs
//! 3. Feeds everything into the SP1 prover as private witness
//! 4. Saves the resulting STARK proof for submission to Solana
//!
//! # Usage
//!
//! ```bash
//! x0-sp1-host prove \
//!   --rpc-url https://mainnet.base.org \
//!   --tx-hash 0xabc123... \
//!   --anchor-block 12345678 \
//!   --anchor-hash 0xdeadbeef... \
//!   --output proof.bin
//! ```
//!
//! The generated proof can then be submitted to the x0-bridge program
//! on Solana via the `verify_evm_proof` instruction.

mod artifacts;
mod prover;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tracing_subscriber::EnvFilter;
use x0_sp1_evm_common::{LOCKED_EVENT_SIGNATURE, TRANSFER_EVENT_SIGNATURE};

#[derive(Parser)]
#[command(name = "x0-sp1-host")]
#[command(about = "Generate STARK proofs for x0 cross-chain bridge")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a STARK proof for an EVM lock transaction
    Prove {
        /// Base (EVM) RPC URL
        #[arg(long, env = "BASE_RPC_URL")]
        rpc_url: String,

        /// Transaction hash to prove (hex, 0x-prefixed)
        #[arg(long)]
        tx_hash: String,

        /// Output file path for the serialized proof
        #[arg(long, default_value = "proof.bin")]
        output: PathBuf,

        /// Output file for public inputs (JSON)
        #[arg(long, default_value = "public_inputs.json")]
        public_inputs_output: PathBuf,

        /// Trusted anchor block number (chain proof starts here)
        #[arg(long, env = "ANCHOR_BLOCK")]
        anchor_block: u64,

        /// Trusted anchor block hash (hex, 0x-prefixed, 32 bytes)
        #[arg(long, env = "ANCHOR_HASH")]
        anchor_hash: String,

        /// X0LockContract address to filter event logs (hex, 0x-prefixed)
        /// If not set, all contract logs are included.
        #[arg(long, env = "LOCK_CONTRACT")]
        lock_contract: Option<String>,

        /// Include Transfer events in addition to Locked events
        #[arg(long, default_value = "false")]
        include_transfer_events: bool,

        /// Use mock prover (for testing, does NOT generate a real proof)
        #[arg(long, default_value = "false")]
        mock: bool,
    },

    /// Verify a previously generated proof locally (for testing)
    Verify {
        /// Path to the proof file
        #[arg(long)]
        proof: PathBuf,

        /// Path to the public inputs file
        #[arg(long)]
        public_inputs: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Prove {
            rpc_url,
            tx_hash,
            output,
            public_inputs_output,
            anchor_block,
            anchor_hash,
            lock_contract,
            include_transfer_events,
            mock,
        } => {
            tracing::info!("Starting proof generation for tx: {}", tx_hash);

            // Parse anchor hash from hex string
            let anchor_hash_str = anchor_hash.strip_prefix("0x").unwrap_or(&anchor_hash);
            let anchor_hash_bytes = hex::decode(anchor_hash_str)
                .context("Invalid anchor hash hex")?;
            anyhow::ensure!(
                anchor_hash_bytes.len() == 32,
                "Anchor hash must be 32 bytes, got {}",
                anchor_hash_bytes.len()
            );
            let mut anchor_hash_arr = [0u8; 32];
            anchor_hash_arr.copy_from_slice(&anchor_hash_bytes);

            tracing::info!(
                "Chain proof anchor: block={}, hash=0x{}",
                anchor_block,
                hex::encode(anchor_hash_arr),
            );

            // Parse event log filters
            let relevant_contracts: Vec<[u8; 20]> = if let Some(ref addr) = lock_contract {
                let addr_str = addr.strip_prefix("0x").unwrap_or(addr);
                let addr_bytes = hex::decode(addr_str)
                    .context("Invalid lock contract address hex")?;
                anyhow::ensure!(
                    addr_bytes.len() == 20,
                    "Lock contract address must be 20 bytes, got {}",
                    addr_bytes.len()
                );
                let mut addr_arr = [0u8; 20];
                addr_arr.copy_from_slice(&addr_bytes);
                tracing::info!("Filtering logs by contract: 0x{}", hex::encode(addr_arr));
                vec![addr_arr]
            } else {
                vec![] // no filter = include all contracts
            };

            let mut relevant_topics: Vec<[u8; 32]> = vec![LOCKED_EVENT_SIGNATURE];
            if include_transfer_events {
                relevant_topics.push(TRANSFER_EVENT_SIGNATURE);
            }
            tracing::info!(
                "Filtering logs by {} event signature(s)",
                relevant_topics.len(),
            );

            // Step 1: Fetch EVM artifacts (including chain proof)
            tracing::info!("Fetching EVM artifacts from {}", rpc_url);
            let witness = artifacts::fetch_evm_artifacts(
                &rpc_url, &tx_hash, anchor_block, anchor_hash_arr,
                relevant_contracts, relevant_topics,
            )
                .await
                .context("Failed to fetch EVM artifacts")?;

            tracing::info!(
                "Fetched artifacts: block={}, tx_index={}",
                witness.block_number,
                witness.transaction_index,
            );

            // Step 2: Generate proof
            let (proof_bytes, public_inputs) = if mock {
                tracing::warn!("Using MOCK prover — proof will NOT verify on-chain");
                prover::generate_mock_proof(&witness)?
            } else {
                tracing::info!("Generating STARK proof (this may take a few minutes)...");
                prover::generate_proof(&witness)?
            };

            // Step 3: Save outputs
            std::fs::write(&output, &proof_bytes)
                .context("Failed to write proof file")?;
            tracing::info!("Proof written to: {}", output.display());

            let public_inputs_json = serde_json::to_string_pretty(&public_inputs)
                .context("Failed to serialize public inputs")?;
            std::fs::write(&public_inputs_output, &public_inputs_json)
                .context("Failed to write public inputs file")?;
            tracing::info!(
                "Public inputs written to: {}",
                public_inputs_output.display()
            );

            tracing::info!("Proof generation complete!");
        }

        Commands::Verify {
            proof,
            public_inputs,
        } => {
            tracing::info!("Verifying proof: {}", proof.display());

            let proof_bytes = std::fs::read(&proof)
                .context("Failed to read proof file")?;
            let public_inputs_json = std::fs::read_to_string(&public_inputs)
                .context("Failed to read public inputs file")?;
            let public_inputs: x0_sp1_evm_common::EVMProofPublicInputs =
                serde_json::from_str(&public_inputs_json)
                    .context("Failed to deserialize public inputs")?;

            prover::verify_proof(&proof_bytes, &public_inputs)?;
            tracing::info!("Proof verified successfully!");
        }
    }

    Ok(())
}
