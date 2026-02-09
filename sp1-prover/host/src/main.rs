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
            mock,
        } => {
            tracing::info!("Starting proof generation for tx: {}", tx_hash);

            // Step 1: Fetch EVM artifacts
            tracing::info!("Fetching EVM artifacts from {}", rpc_url);
            let witness = artifacts::fetch_evm_artifacts(&rpc_url, &tx_hash)
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
            let public_inputs: x0_sp1_common::EVMProofPublicInputs =
                serde_json::from_str(&public_inputs_json)
                    .context("Failed to deserialize public inputs")?;

            prover::verify_proof(&proof_bytes, &public_inputs)?;
            tracing::info!("Proof verified successfully!");
        }
    }

    Ok(())
}
