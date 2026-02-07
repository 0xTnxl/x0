//! x0-zk-verifier: On-chain Groth16 proof verification for Token-2022
//!
//! This program verifies zero-knowledge proofs and creates proof context
//! state accounts that Token-2022 can reference for confidential transfers.
//!
//! # Architecture
//!
//! The verifier receives proof data generated off-chain via WASM, verifies
//! it using solana-zk-token-sdk, and creates a ProofContext PDA that stores
//! the verification result. This PDA can then be passed to Token-2022
//! confidential transfer instructions.
//!
//! # Security
//!
//! - All proof verification uses battle-tested solana-zk-token-sdk
//! - Proof contexts include timestamps to prevent replay attacks
//! - Amount limits enforced (MAX_CONFIDENTIAL_AMOUNT = 2^48 - 1)

#![allow(unexpected_cfgs)]
#![allow(ambiguous_glob_reexports)]

use anchor_lang::prelude::*;

pub mod instructions;
pub mod state;
pub mod verification;

pub use instructions::*;
pub use state::*;

declare_id!("zQWSrznKgcK8aHA4ry7xbSCdP36FqgUHj766YM3pwre");

#[program]
pub mod x0_zk_verifier {
    use super::*;

    /// Verify a PubkeyValidityProof
    ///
    /// Creates a proof context state account after successful verification.
    /// This proof is required to configure a token account for confidential transfers.
    ///
    /// # Arguments
    /// * `proof_data` - Serialized PubkeyValidityData (64 bytes)
    /// * `elgamal_pubkey` - The ElGamal public key being verified (32 bytes)
    pub fn verify_pubkey_validity(
        ctx: Context<VerifyPubkeyValidity>,
        proof_data: Vec<u8>,
        elgamal_pubkey: [u8; 32],
    ) -> Result<()> {
        instructions::verify_pubkey_validity::handler(ctx, proof_data, elgamal_pubkey)
    }

    /// Verify a WithdrawProof
    ///
    /// Verifies the proof and stores withdrawal parameters in proof context.
    /// This proof is required to withdraw from confidential to public balance.
    ///
    /// # Arguments
    /// * `proof_data` - Serialized WithdrawData (160 bytes)
    /// * `amount` - Amount being withdrawn
    /// * `new_decryptable_balance` - Encrypted new balance (36 bytes AE ciphertext)
    pub fn verify_withdraw(
        ctx: Context<VerifyWithdraw>,
        proof_data: Vec<u8>,
        amount: u64,
        new_decryptable_balance: [u8; 36],
    ) -> Result<()> {
        instructions::verify_withdraw::handler(ctx, proof_data, amount, new_decryptable_balance)
    }

    /// Verify a ZeroBalanceProof
    ///
    /// Used for account closure verification. Proves that the account's
    /// confidential balance is exactly zero.
    ///
    /// # Arguments
    /// * `proof_data` - Serialized ZeroBalanceProofData (96 bytes)
    pub fn verify_zero_balance(
        ctx: Context<VerifyZeroBalance>,
        proof_data: Vec<u8>,
    ) -> Result<()> {
        instructions::verify_zero_balance::handler(ctx, proof_data)
    }

    /// Verify a TransferProof
    ///
    /// Verifies confidential transfer between two accounts.
    ///
    /// # Arguments
    /// * `proof_data` - Serialized TransferData
    /// * `amount` - Amount being transferred
    /// * `recipient` - Recipient's public key
    pub fn verify_transfer(
        ctx: Context<VerifyTransfer>,
        proof_data: Vec<u8>,
        amount: u64,
        recipient: Pubkey,
    ) -> Result<()> {
        instructions::verify_transfer::handler(ctx, proof_data, amount, recipient)
    }
}
