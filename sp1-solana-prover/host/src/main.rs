//! SP1 Host Program: Solana State Proof Generation for Outbound Bridge
//!
//! Fetches a BridgeOutMessage PDA from Solana, retrieves all the
//! cryptographic material needed (account data, Merkle proof, bank hash,
//! validator signatures), and generates an SP1 STARK proof.
//!
//! The generated proof is submitted to X0UnlockContract.unlock() on Base.
//!
//! # Usage
//!
//! ```bash
//! x0-sp1-solana-host \
//!   --rpc-url https://api.devnet.solana.com \
//!   --bridge-program 4FuyKfQysHxcTeNJtz5rBzzS8kmjn2DdkgXH1Q7edXa7 \
//!   --nonce 0 \
//!   --output proof.bin
//! ```

use anyhow::{Context, Result};
use clap::Parser;
use sha2::{Digest, Sha256};
use solana_client::rpc_client::RpcClient;
use solana_sdk::pubkey::Pubkey;
use std::str::FromStr;
use tracing::{info, warn};
use x0_sp1_solana_common::{
    BankHashComponents, ParsedBridgeOutMessage, SolanaProofWitness, ValidatorSignature,
    ValidatorStake,
};

mod fetcher;
mod prover;

/// SP1 Solana State Proof Generator for x0 Outbound Bridge
#[derive(Parser, Debug)]
#[command(name = "x0-sp1-solana-host")]
#[command(about = "Generate SP1 STARK proofs of Solana BridgeOutMessage accounts")]
struct Args {
    /// Solana RPC endpoint URL
    #[arg(long, env = "SOLANA_RPC_URL")]
    rpc_url: String,

    /// x0-bridge program ID on Solana
    #[arg(long, env = "BRIDGE_PROGRAM_ID")]
    bridge_program: String,

    /// Outbound bridge nonce to prove
    #[arg(long)]
    nonce: u64,

    /// Output file for the proof
    #[arg(long, default_value = "proof.bin")]
    output: String,

    /// Output file for the public values
    #[arg(long, default_value = "public_values.bin")]
    public_values_output: String,

    /// SP1 proving mode: "mock", "local", "network"
    #[arg(long, default_value = "mock")]
    mode: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();

    info!("x0 SP1 Solana State Prover");
    info!("RPC: {}", args.rpc_url);
    info!("Bridge program: {}", args.bridge_program);
    info!("Nonce: {}", args.nonce);

    // ========================================================================
    // Step 1: Connect to Solana and fetch BridgeOutMessage account
    // ========================================================================

    let rpc = RpcClient::new(&args.rpc_url);
    let bridge_program = Pubkey::from_str(&args.bridge_program)
        .context("Invalid bridge program ID")?;

    // Derive BridgeOutMessage PDA
    let (pda, _bump) = Pubkey::find_program_address(
        &[b"bridge_out_message", &args.nonce.to_le_bytes()],
        &bridge_program,
    );

    info!("BridgeOutMessage PDA: {}", pda);

    // Fetch the account
    let account = rpc
        .get_account(&pda)
        .context("Failed to fetch BridgeOutMessage account — may not exist")?;

    info!(
        "Account: owner={}, data_len={}, lamports={}",
        account.owner,
        account.data.len(),
        account.lamports,
    );

    // Verify the account is owned by the bridge program
    if account.owner != bridge_program {
        anyhow::bail!(
            "Account owner mismatch: expected {}, got {}",
            bridge_program,
            account.owner
        );
    }

    // Parse the account data
    let parsed = ParsedBridgeOutMessage::try_from_bytes(&account.data)
        .context("Failed to parse BridgeOutMessage account data")?;

    info!("Parsed BridgeOutMessage:");
    info!("  nonce: {}", parsed.nonce);
    info!("  amount: {} (micro-USDC)", parsed.amount);
    info!("  evm_recipient: 0x{}", hex::encode(parsed.evm_recipient));
    info!(
        "  solana_sender: {}",
        Pubkey::from(parsed.solana_sender)
    );
    info!("  status: {} (0=Burned)", parsed.status);
    info!("  burned_at: {}", parsed.burned_at);

    // Verify the nonce matches
    if parsed.nonce != args.nonce {
        anyhow::bail!(
            "Nonce mismatch: expected {}, got {}",
            args.nonce,
            parsed.nonce
        );
    }

    // Verify the account status is Burned (0)
    if parsed.status != 0 {
        anyhow::bail!(
            "Account status is not Burned (0): got {}",
            parsed.status
        );
    }

    // ========================================================================
    // Step 2: Fetch state proof material
    //
    // In production, this involves:
    // 1. Getting the latest finalized slot's bank hash
    // 2. Getting the accounts hash from that slot
    // 3. Computing the Merkle proof for our account in the accounts tree
    // 4. Fetching validator vote account signatures for the bank hash
    //
    // This is complex and requires deep Solana RPC integration.
    // For now, we build the witness structure and use mock data for testing.
    // ========================================================================

    info!("Fetching state proof material...");

    let witness = fetcher::fetch_witness(
        &rpc,
        &bridge_program,
        &pda,
        &account,
        args.nonce,
    )
    .await
    .context("Failed to fetch witness data")?;

    // ========================================================================
    // Step 3: Generate SP1 STARK proof
    // ========================================================================

    info!("Generating SP1 proof (mode: {})...", args.mode);

    let (proof_bytes, public_values) = prover::generate_proof(
        &witness,
        &args.mode,
    )
    .await
    .context("Failed to generate SP1 proof")?;

    // ========================================================================
    // Step 4: Write outputs
    // ========================================================================

    std::fs::write(&args.output, &proof_bytes)
        .context("Failed to write proof file")?;

    std::fs::write(&args.public_values_output, &public_values)
        .context("Failed to write public values file")?;

    info!("Proof written to: {}", args.output);
    info!("Public values written to: {}", args.public_values_output);
    info!(
        "Proof size: {} bytes, Public values size: {} bytes",
        proof_bytes.len(),
        public_values.len()
    );

    Ok(())
}
