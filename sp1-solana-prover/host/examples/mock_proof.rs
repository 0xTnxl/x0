//! Mock Proof End-to-End Example
//!
//! Fetches a real Solana BridgeOutMessage account and runs the full proof
//! pipeline using the SP1 mock prover (native execution, no ZK overhead).
//!
//! # Usage
//!
//! ```bash
//! SOLANA_RPC_URL=https://api.devnet.solana.com \
//! BRIDGE_PROGRAM_ID=<program_id> \
//! NONCE=0 \
//!   cargo run -p x0-sp1-solana-host --example mock_proof
//! ```
//!
//! # What This Does
//!
//! 1. Fetches the BridgeOutMessage PDA from Solana
//! 2. Fetches the full proof witness (account hash, Merkle proof,
//!    bank hash, validator votes, epoch stakes)
//! 3. Runs `prover::generate_proof(&witness, "mock")` — executes the
//!    SP1 guest natively (no ZK overhead, ~seconds)
//! 4. Prints proof size and public values
//! 5. Writes `mock_proof.bin` and `mock_public_values.bin`

use anyhow::{Context, Result};
use solana_client::rpc_client::RpcClient;
use solana_sdk::pubkey::Pubkey;
use std::str::FromStr;

use x0_sp1_solana_host::{fetcher, prover};
use x0_sp1_solana_common::ParsedBridgeOutMessage;

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
    let rpc_url = std::env::var("SOLANA_RPC_URL")
        .unwrap_or_else(|_| "https://api.devnet.solana.com".to_string());
    let bridge_program_str = std::env::var("BRIDGE_PROGRAM_ID")
        .context("BRIDGE_PROGRAM_ID env var required")?;
    let nonce: u64 = std::env::var("NONCE")
        .unwrap_or_else(|_| "0".to_string())
        .parse()
        .context("NONCE must be a u64")?;
    let quorum_timeout_secs: u64 = std::env::var("QUORUM_TIMEOUT_SECS")
        .unwrap_or_else(|_| "120".to_string())
        .parse()
        .context("QUORUM_TIMEOUT_SECS must be a u64")?;
    let skip_quorum = std::env::var("SKIP_QUORUM_WAIT").as_deref() == Ok("1");

    tracing::info!("x0 SP1 Solana Mock Proof Example");
    tracing::info!("RPC:            {}", rpc_url);
    tracing::info!("Bridge program: {}", bridge_program_str);
    tracing::info!("Nonce:          {}", nonce);
    tracing::info!("Skip quorum:    {}", skip_quorum);

    let bridge_program = Pubkey::from_str(&bridge_program_str)
        .context("Invalid BRIDGE_PROGRAM_ID")?;

    // ========================================================================
    // Step 1: Connect to Solana and fetch BridgeOutMessage account
    // ========================================================================
    let rpc = RpcClient::new(&rpc_url);

    let (pda, _bump) = Pubkey::find_program_address(
        &[b"bridge_out_message", &nonce.to_le_bytes()],
        &bridge_program,
    );
    tracing::info!("BridgeOutMessage PDA: {}", pda);

    let account = rpc
        .get_account(&pda)
        .context("Failed to fetch BridgeOutMessage account — is it deployed?")?;

    anyhow::ensure!(
        account.owner == bridge_program,
        "Account owner mismatch: expected {}, got {}",
        bridge_program,
        account.owner,
    );

    let parsed = ParsedBridgeOutMessage::try_from_bytes(&account.data)
        .context("Failed to parse BridgeOutMessage account data")?;

    tracing::info!("Parsed BridgeOutMessage:");
    tracing::info!("  nonce:         {}", parsed.nonce);
    tracing::info!("  amount:        {} (micro-USDC)", parsed.amount);
    tracing::info!("  evm_recipient: 0x{}", hex::encode(parsed.evm_recipient));
    tracing::info!("  status:        {} (0=Burned)", parsed.status);
    tracing::info!("  burned_at:     {}", parsed.burned_at);

    anyhow::ensure!(parsed.nonce == nonce, "Nonce mismatch");
    anyhow::ensure!(parsed.status == 0, "Account status is not Burned (got {})", parsed.status);

    // ========================================================================
    // Step 2: Fetch witness
    // ========================================================================
    tracing::info!("Fetching proof witness...");
    tracing::warn!("This requires quorum-confirmed votes and may take up to {}s", quorum_timeout_secs);

    let witness = fetcher::fetch_witness(
        &rpc,
        &bridge_program,
        &pda,
        &account,
        !skip_quorum,
        quorum_timeout_secs,
    )
    .await
    .context("Failed to fetch witness")?;

    // ========================================================================
    // Step 3: Generate mock proof
    // ========================================================================
    tracing::warn!("Generating MOCK proof — output is NOT verifiable on-chain");
    let (proof_bytes, public_values) = prover::generate_proof(&witness, "mock")
        .await
        .context("Mock proof generation failed")?;

    // ========================================================================
    // Step 4: Print results
    // ========================================================================
    tracing::info!("✓ Mock proof generated successfully!");
    tracing::info!("  Proof size:        {} bytes", proof_bytes.len());
    tracing::info!("  Public values size: {} bytes", public_values.len());

    // Optionally write to files
    let out_proof = std::env::var("OUTPUT_PROOF")
        .unwrap_or_else(|_| "mock_proof.bin".to_string());
    let out_pv = std::env::var("OUTPUT_PUBLIC_VALUES")
        .unwrap_or_else(|_| "mock_public_values.bin".to_string());

    std::fs::write(&out_proof, &proof_bytes)
        .with_context(|| format!("Failed to write proof to {}", out_proof))?;
    std::fs::write(&out_pv, &public_values)
        .with_context(|| format!("Failed to write public values to {}", out_pv))?;

    tracing::info!("  Written: {} ({} bytes)", out_proof, proof_bytes.len());
    tracing::info!("  Written: {} ({} bytes)", out_pv, public_values.len());

    Ok(())
}
