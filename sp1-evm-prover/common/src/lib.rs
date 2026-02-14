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
