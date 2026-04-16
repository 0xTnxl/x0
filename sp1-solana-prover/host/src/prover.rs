//! SP1 proof generation for Solana state proofs
//!
//! Generates STARK proofs using the SP1 SDK. Supports multiple proving modes:
//! - `mock`: Fast simulation for testing (no real proof generated)
//! - `local`: Generate proof locally (requires significant compute)
//! - `network`: Generate proof via SP1 proving network (recommended for production)

use anyhow::{Context, Result};
use sp1_sdk::{HashableKey, ProverClient, SP1Stdin};
use tracing::info;
use x0_sp1_solana_common::SolanaProofWitness;

/// Path to the SP1 guest ELF binary.
///
/// `cargo prove build` in the guest crate emits the ELF to:
///   `target/elf-compilation/riscv64im-succinct-zkvm-elf/release/solana-state-verifier`
///
/// Override via the `SP1_GUEST_ELF` environment variable.
const DEFAULT_GUEST_ELF_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../target/elf-compilation/riscv64im-succinct-zkvm-elf/release/solana-state-verifier",
);

fn load_guest_elf() -> Result<Vec<u8>> {
    let path = std::env::var("SP1_GUEST_ELF")
        .unwrap_or_else(|_| DEFAULT_GUEST_ELF_PATH.to_string());
    std::fs::read(&path)
        .with_context(|| format!("Failed to read guest ELF from {}. Build the guest first.", path))
}

/// Generate an SP1 STARK proof for the given Solana state witness
///
/// # Arguments
/// * `witness` - The complete Solana proof witness with all cryptographic material
/// * `mode` - Proving mode: "mock", "local", or "network"
///
/// # Returns
/// * `(proof_bytes, public_values_bytes)` - The serialized proof and public values
pub async fn generate_proof(
    witness: &SolanaProofWitness,
    mode: &str,
) -> Result<(Vec<u8>, Vec<u8>)> {
    // Pre-validate the witness before spending compute on proof generation.
    // This catches structural errors early (wrong account size, zeroed hashes,
    // insufficient quorum) that would otherwise only surface as opaque circuit
    // panics after minutes of proving.
    info!("Pre-validating witness...");
    witness
        .validate()
        .map_err(|e| anyhow::anyhow!(e))
        .context("Witness pre-validation failed — fix inputs before proving")?;
    info!("Witness pre-validation passed");

    info!("Setting up SP1 prover client (mode: {})...", mode);

    // Load the guest ELF at runtime
    let guest_elf = load_guest_elf()?;

    // Create SP1 stdin and write the witness
    let mut stdin = SP1Stdin::new();
    stdin.write(witness);

    // Create the appropriate prover client
    let client = match mode {
        "mock" => {
            info!("Using mock prover — no real STARK proof generated");
            ProverClient::mock()
        }
        "local" => {
            info!("Using local prover — this may take several minutes");
            ProverClient::local()
        }
        "network" => {
            info!("Using SP1 proving network");
            ProverClient::network()
        }
        _ => {
            anyhow::bail!("Unknown proving mode: {}. Use 'mock', 'local', or 'network'", mode);
        }
    };

    // Setup the proving key and verifying key
    let (pk, vk) = client.setup(&guest_elf);
    info!("Verification key: {:?}", vk.bytes32());

    // Generate the proof
    info!("Generating proof...");
    let proof = client
        .prove(&pk, stdin)
        .compressed()
        .run()
        .context("SP1 proof generation failed")?;

    info!("Proof generated successfully!");

    // Verify the proof locally before submitting
    info!("Verifying proof locally...");
    client
        .verify(&proof, &vk)
        .context("Local proof verification failed")?;

    info!("Local verification passed!");

    // Extract public values
    let public_values = proof.public_values.to_vec();

    // Serialize the proof
    let proof_bytes = bincode::serialize(&proof)
        .context("Failed to serialize proof")?;

    info!(
        "Proof size: {} bytes, Public values: {} bytes",
        proof_bytes.len(),
        public_values.len()
    );

    Ok((proof_bytes, public_values))
}
