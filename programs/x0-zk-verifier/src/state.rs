//! State structures for x0-zk-verifier program
//!
//! Defines the ProofContext account structure that stores verification results
//! for zero-knowledge proofs used in Token-2022 confidential transfers.

use anchor_lang::prelude::*;

/// Type of zero-knowledge proof
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug, PartialEq, Eq)]
pub enum ProofType {
    /// PubkeyValidityProof - proves ElGamal public key is valid
    PubkeyValidity,
    /// WithdrawProof - proves withdrawal amount is valid
    Withdraw,
    /// ZeroBalanceProof - proves balance is exactly zero
    ZeroBalance,
    /// TransferProof - proves confidential transfer is valid
    Transfer,
}

/// Proof context state account
///
/// This PDA stores the result of on-chain proof verification and
/// serves as proof-of-verification for Token-2022 instructions.
/// The account is created by the verifier program after successfully
/// verifying a Groth16 proof.
#[account]
#[derive(Debug)]
pub struct ProofContext {
    /// Account version for future migrations
    pub version: u8,

    /// Type of proof verified
    pub proof_type: ProofType,

    /// Whether the proof passed verification
    pub verified: bool,

    /// The account owner who can use this proof
    pub owner: Pubkey,

    /// Timestamp when proof was verified (Unix timestamp)
    pub verified_at: i64,

    /// Amount (for Withdraw/Transfer proofs)
    pub amount: Option<u64>,

    /// Recipient (for Transfer proofs)
    pub recipient: Option<Pubkey>,

    /// ElGamal public key (for PubkeyValidity proofs)
    pub elgamal_pubkey: Option<[u8; 32]>,

    /// The mint this proof is for
    pub mint: Pubkey,

    /// The token account this proof is for
    pub token_account: Pubkey,

    /// PDA bump seed
    pub bump: u8,

    /// Reserved space for future upgrades
    pub _reserved: [u8; 64],
}

impl ProofContext {
    /// Calculate space required for ProofContext account
    pub const fn space() -> usize {
        8 +       // discriminator
        1 +       // version
        1 +       // proof_type (enum discriminant)
        1 +       // verified
        32 +      // owner
        8 +       // verified_at
        1 + 8 +   // amount: Option<u64>
        1 + 32 +  // recipient: Option<Pubkey>
        1 + 32 +  // elgamal_pubkey: Option<[u8; 32]>
        32 +      // mint
        32 +      // token_account
        1 +       // bump
        64        // _reserved
    }

    /// Check if proof is still fresh (within 5 minutes)
    ///
    /// Proofs should not be reused for extended periods to prevent
    /// replay attacks. A 5-minute window is sufficient for transaction
    /// construction and submission.
    pub fn is_fresh(&self, current_timestamp: i64) -> bool {
        const PROOF_VALIDITY_SECONDS: i64 = 300; // 5 minutes
        current_timestamp - self.verified_at < PROOF_VALIDITY_SECONDS
    }
}

/// Seed for proof context PDA derivation
pub const PROOF_CONTEXT_SEED: &[u8] = b"proof-context";
