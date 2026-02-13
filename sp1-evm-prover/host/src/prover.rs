//! SP1 Proof Generation & Verification
//!
//! Wraps the SP1 SDK to generate and verify STARK proofs using the
//! EVM verifier guest program.

use anyhow::{Context, Result};
use sp1_sdk::{ProverClient, SP1Stdin};
use x0_sp1_evm_common::{EVMProofPublicInputs, EVMProofWitness};

/// The ELF binary of the SP1 guest program.
///
/// This is embedded at compile time from the guest build output.
/// To build the guest:
///
/// ```bash
/// cd sp1-evm-prover/guest
/// cargo prove build
/// ```
///
/// The ELF path is relative to the host crate root.
const EVM_VERIFIER_ELF: &[u8] = include_bytes!("../../guest/elf/riscv32im-succinct-zkvm-elf");

/// Generate a STARK proof for an EVM transaction
///
/// This feeds the witness into the SP1 prover and returns:
/// - The serialized proof (for submission to Solana)
/// - The public inputs (committed by the guest)
///
/// # Performance
///
/// Proof generation takes 2-10 minutes depending on:
/// - Block size (affects RLP decoding in circuit)
/// - Number of transactions (affects MPT proof depth)
/// - Machine specs (CPU cores, RAM)
pub fn generate_proof(
    witness: &EVMProofWitness,
) -> Result<(Vec<u8>, EVMProofPublicInputs)> {
    let client = ProverClient::new();

    let mut stdin = SP1Stdin::new();
    stdin.write(witness);

    // Generate the proof
    let (pk, vk) = client.setup(EVM_VERIFIER_ELF);
    let proof = client
        .prove(&pk, stdin)
        .compressed()
        .run()
        .context("SP1 proof generation failed")?;

    // Extract public inputs from proof output
    let public_inputs_bytes = proof.public_values.as_slice();
    let public_inputs: EVMProofPublicInputs =
        borsh::BorshDeserialize::try_from_slice(public_inputs_bytes)
            .context("Failed to deserialize public inputs from proof output")?;

    // Verify the proof locally before returning
    client
        .verify(&proof, &vk)
        .context("Local proof verification failed")?;

    // Serialize the proof for Solana submission
    let proof_bytes = bincode::serialize(&proof)
        .context("Failed to serialize proof")?;

    tracing::info!(
        "Proof generated: {} bytes, block={}, tx_hash={}",
        proof_bytes.len(),
        public_inputs.block_number,
        hex::encode(public_inputs.tx_hash),
    );

    Ok((proof_bytes, public_inputs))
}

/// Generate a mock proof (for testing only — NOT verifiable on-chain)
///
/// This executes the guest program without generating a real STARK proof.
/// Useful for testing the full pipeline without the proof generation overhead.
pub fn generate_mock_proof(
    witness: &EVMProofWitness,
) -> Result<(Vec<u8>, EVMProofPublicInputs)> {
    let client = ProverClient::mock();

    let mut stdin = SP1Stdin::new();
    stdin.write(witness);

    let (pk, _vk) = client.setup(EVM_VERIFIER_ELF);
    let proof = client
        .prove(&pk, stdin)
        .run()
        .context("SP1 mock execution failed")?;

    let public_inputs_bytes = proof.public_values.as_slice();
    let public_inputs: EVMProofPublicInputs =
        borsh::BorshDeserialize::try_from_slice(public_inputs_bytes)
            .context("Failed to deserialize public inputs from mock proof")?;

    let proof_bytes = bincode::serialize(&proof)
        .context("Failed to serialize mock proof")?;

    tracing::info!(
        "Mock proof generated: {} bytes, block={}, tx_hash={}",
        proof_bytes.len(),
        public_inputs.block_number,
        hex::encode(public_inputs.tx_hash),
    );

    Ok((proof_bytes, public_inputs))
}

/// Verify a previously generated proof
pub fn verify_proof(
    proof_bytes: &[u8],
    expected_public_inputs: &EVMProofPublicInputs,
) -> Result<()> {
    let client = ProverClient::new();

    let proof: sp1_sdk::SP1ProofWithPublicValues = bincode::deserialize(proof_bytes)
        .context("Failed to deserialize proof")?;

    // Verify the public inputs match expectations
    let proof_public_inputs: EVMProofPublicInputs =
        borsh::BorshDeserialize::try_from_slice(proof.public_values.as_slice())
            .context("Failed to deserialize proof public inputs")?;

    if proof_public_inputs.block_hash != expected_public_inputs.block_hash {
        anyhow::bail!("Block hash mismatch");
    }
    if proof_public_inputs.tx_hash != expected_public_inputs.tx_hash {
        anyhow::bail!("Transaction hash mismatch");
    }

    let (_pk, vk) = client.setup(EVM_VERIFIER_ELF);
    client
        .verify(&proof, &vk)
        .context("Proof verification failed")?;

    Ok(())
}
