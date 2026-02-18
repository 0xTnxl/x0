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
    // Pre-validate witness structure before spending compute on proof generation.
    witness
        .validate()
        .map_err(|e| anyhow::anyhow!(e))
        .context("Witness pre-validation failed — fix inputs before proving")?;

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
    // Pre-validate even for mock proofs — catches bugs early.
    witness
        .validate()
        .map_err(|e| anyhow::anyhow!(e))
        .context("Witness pre-validation failed — fix inputs before proving")?;

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

    // Verify the public inputs match expectations — every security-relevant
    // field must match. A partial check would allow a proof over a valid tx
    // to be replayed with forged from/to/value in the public inputs file.
    let proof_public_inputs: EVMProofPublicInputs =
        borsh::BorshDeserialize::try_from_slice(proof.public_values.as_slice())
            .context("Failed to deserialize proof public inputs")?;

    if proof_public_inputs.block_hash != expected_public_inputs.block_hash {
        anyhow::bail!("Public input mismatch: block_hash");
    }
    if proof_public_inputs.block_number != expected_public_inputs.block_number {
        anyhow::bail!("Public input mismatch: block_number");
    }
    if proof_public_inputs.tx_hash != expected_public_inputs.tx_hash {
        anyhow::bail!("Public input mismatch: tx_hash");
    }
    if proof_public_inputs.from != expected_public_inputs.from {
        anyhow::bail!("Public input mismatch: from");
    }
    if proof_public_inputs.to != expected_public_inputs.to {
        anyhow::bail!("Public input mismatch: to");
    }
    if proof_public_inputs.value != expected_public_inputs.value {
        anyhow::bail!("Public input mismatch: value");
    }
    if proof_public_inputs.chain_anchor_block != expected_public_inputs.chain_anchor_block {
        anyhow::bail!("Public input mismatch: chain_anchor_block");
    }
    if proof_public_inputs.chain_anchor_hash != expected_public_inputs.chain_anchor_hash {
        anyhow::bail!("Public input mismatch: chain_anchor_hash");
    }

    let (_pk, vk) = client.setup(EVM_VERIFIER_ELF);
    client
        .verify(&proof, &vk)
        .context("Proof verification failed")?;

    Ok(())
}
