//! Shared types between SP1 guest (STARK circuit) and host (prover)
//!
//! These types are used both inside the STARK prover (guest) and by the
//! host program that fetches EVM artifacts and submits proofs to Solana.
//!
//! The public inputs are committed by the guest and verified on Solana.
//! The private inputs (witness) are only used inside the guest and never
//! revealed to the verifier.

#![no_std]

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

// ============================================================================
// Public Inputs (committed by guest, verified on Solana)
// ============================================================================

/// Public inputs/outputs committed by the SP1 STARK proof
///
/// These values are cryptographically bound to the proof and verified
/// on Solana by the x0-bridge program after SP1 verification.
///
/// The borsh serialization must match the SP1PublicInputs struct in
/// programs/x0-bridge/src/state.rs exactly.
#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct EVMProofPublicInputs {
    /// Block hash where the transaction was mined (32 bytes)
    pub block_hash: [u8; 32],
    /// Block number
    pub block_number: u64,
    /// Transaction hash (32 bytes)
    pub tx_hash: [u8; 32],
    /// Transaction sender (20-byte EVM address)
    pub from: [u8; 20],
    /// Transaction recipient/contract (20-byte EVM address)
    pub to: [u8; 20],
    /// ETH value transferred (in wei)
    pub value: u64,
    /// Whether the transaction was successful (receipt.status == 1)
    pub success: bool,
    /// Extracted event logs from the receipt
    pub event_logs: Vec<EventLog>,
}

/// An event log extracted from an EVM transaction receipt
#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct EventLog {
    /// Contract that emitted the event (20 bytes)
    pub contract_address: [u8; 20],
    /// Indexed topics: topic[0] = keccak256(event signature)
    pub topics: Vec<[u8; 32]>,
    /// ABI-encoded non-indexed event data
    pub data: Vec<u8>,
}

// ============================================================================
// Private Inputs (witness — never revealed to verifier)
// ============================================================================

/// Private inputs provided to the SP1 guest program
///
/// These are the raw EVM artifacts fetched via RPC that the guest
/// program verifies inside the STARK circuit. They are never exposed
/// to the Solana verifier — only the public inputs above are committed.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EVMProofWitness {
    /// RLP-encoded block header
    pub block_header_rlp: Vec<u8>,
    /// Block hash (precomputed for validation)
    pub block_hash: [u8; 32],
    /// Block number
    pub block_number: u64,
    /// RLP-encoded transaction
    pub transaction_rlp: Vec<u8>,
    /// Transaction index within the block
    pub transaction_index: u32,
    /// RLP-encoded transaction receipt
    pub receipt_rlp: Vec<u8>,
    /// Merkle-Patricia Trie proof for transaction inclusion
    pub tx_proof_nodes: Vec<Vec<u8>>,
    /// Merkle-Patricia Trie proof for receipt inclusion
    pub receipt_proof_nodes: Vec<Vec<u8>>,
    /// Transaction sender (recovered from signature)
    pub from: [u8; 20],
    /// Transaction recipient
    pub to: [u8; 20],
    /// ETH value transferred
    pub value: u64,
}

// ============================================================================
// Witness Validation
// ============================================================================

/// Maximum allowed depth for MPT proofs.
///
/// Ethereum's MPT has a key space of 32 bytes (64 nibbles). With branch
/// factor 16, the theoretical max depth is 64. In practice, tx/receipt
/// tries are much shallower — 20 levels handles well beyond the largest
/// blocks observed on Base.
pub const MAX_MPT_PROOF_DEPTH: usize = 20;

/// Maximum allowed RLP size for a block header (bytes).
///
/// Post-merge EIP-4844 headers can reach ~1 KB. We allow 2 KB for headroom.
pub const MAX_BLOCK_HEADER_RLP_SIZE: usize = 2048;

/// Maximum allowed RLP size for a single transaction (bytes).
///
/// ERC-4337 bundles and large calldata can push transactions up to ~128 KB.
pub const MAX_TRANSACTION_RLP_SIZE: usize = 131_072;

/// Maximum allowed RLP size for a receipt (bytes).
///
/// Receipts with many log entries can be large but rarely exceed 128 KB.
pub const MAX_RECEIPT_RLP_SIZE: usize = 131_072;

impl EVMProofWitness {
    /// Validate witness structure before proof generation.
    ///
    /// Catches structural errors early so they surface as clear error
    /// messages rather than opaque circuit panics after minutes of proving.
    ///
    /// # Checks
    /// - Block hash is non-zero
    /// - Block header RLP is non-empty and within size bounds
    /// - Transaction RLP is non-empty and within size bounds
    /// - Receipt RLP is non-empty and within size bounds
    /// - MPT proof depths are within bounds
    /// - Block number is non-zero
    pub fn validate(&self) -> Result<(), String> {
        if self.block_hash == [0u8; 32] {
            return Err("Block hash must not be zero".into());
        }

        if self.block_header_rlp.is_empty() {
            return Err("Block header RLP must not be empty".into());
        }
        if self.block_header_rlp.len() > MAX_BLOCK_HEADER_RLP_SIZE {
            return Err(format!(
                "Block header RLP too large: {} bytes (max {})",
                self.block_header_rlp.len(),
                MAX_BLOCK_HEADER_RLP_SIZE,
            ));
        }

        if self.transaction_rlp.is_empty() {
            return Err("Transaction RLP must not be empty".into());
        }
        if self.transaction_rlp.len() > MAX_TRANSACTION_RLP_SIZE {
            return Err(format!(
                "Transaction RLP too large: {} bytes (max {})",
                self.transaction_rlp.len(),
                MAX_TRANSACTION_RLP_SIZE,
            ));
        }

        if self.receipt_rlp.is_empty() {
            return Err("Receipt RLP must not be empty".into());
        }
        if self.receipt_rlp.len() > MAX_RECEIPT_RLP_SIZE {
            return Err(format!(
                "Receipt RLP too large: {} bytes (max {})",
                self.receipt_rlp.len(),
                MAX_RECEIPT_RLP_SIZE,
            ));
        }

        if self.tx_proof_nodes.is_empty() {
            return Err("Transaction MPT proof must have at least one node".into());
        }
        if self.tx_proof_nodes.len() > MAX_MPT_PROOF_DEPTH {
            return Err(format!(
                "Transaction MPT proof too deep: {} levels (max {})",
                self.tx_proof_nodes.len(),
                MAX_MPT_PROOF_DEPTH,
            ));
        }

        if self.receipt_proof_nodes.is_empty() {
            return Err("Receipt MPT proof must have at least one node".into());
        }
        if self.receipt_proof_nodes.len() > MAX_MPT_PROOF_DEPTH {
            return Err(format!(
                "Receipt MPT proof too deep: {} levels (max {})",
                self.receipt_proof_nodes.len(),
                MAX_MPT_PROOF_DEPTH,
            ));
        }

        if self.block_number == 0 {
            return Err("Block number must not be zero".into());
        }

        Ok(())
    }
}

// ============================================================================
// Constants
// ============================================================================

/// keccak256("Locked(address,bytes32,uint256,uint256,bytes32)")
/// Event signature for the X0LockContract.Locked event
///
/// Solidity declaration:
///   event Locked(address indexed sender, bytes32 indexed solanaRecipient,
///                uint256 amount, uint256 nonce, bytes32 messageId)
///
/// Topics:  [0] = this hash, [1] = sender, [2] = solanaRecipient
/// Data:    abi.encode(amount, nonce, messageId)
pub const LOCKED_EVENT_SIGNATURE: [u8; 32] = [
    0x6e, 0xa4, 0xb3, 0xe5, 0xd5, 0xca, 0x80, 0xe1,
    0xec, 0x33, 0xaf, 0x6e, 0x82, 0x4b, 0x1d, 0x7f,
    0x59, 0x5b, 0x0b, 0x2f, 0x6d, 0x9d, 0x72, 0x42,
    0x22, 0xfc, 0xab, 0xd1, 0x8c, 0x36, 0xba, 0x15,
];

/// keccak256("Transfer(address,address,uint256)")
/// Standard ERC-20 Transfer event signature
pub const TRANSFER_EVENT_SIGNATURE: [u8; 32] = [
    0xdd, 0xf2, 0x52, 0xad, 0x1b, 0xe2, 0xc8, 0x9b,
    0x69, 0xc2, 0xb0, 0x68, 0xfc, 0x37, 0x8d, 0xaa,
    0x95, 0x2b, 0xa7, 0xf1, 0x63, 0xc4, 0xa1, 0x16,
    0x28, 0xf5, 0x5a, 0x4d, 0xf5, 0x23, 0xb3, 0xef,
];
