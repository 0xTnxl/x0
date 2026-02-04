//! State structures for x0-escrow program
//!
//! Defines the on-chain account structures owned by x0-escrow.

use anchor_lang::prelude::*;
use x0_common::constants::*;

/// An escrow account for conditional payments with dispute resolution
///
/// # LOW-4: Version Field for Upgrades
/// The `version` field enables future account migrations.
#[account]
#[derive(Debug)]
pub struct EscrowAccount {
    /// Account version for future migrations (LOW-4)
    /// Version 1: Initial structure
    pub version: u8,

    /// The buyer (payer) of the escrow
    pub buyer: Pubkey,

    /// The seller (recipient) of the escrow
    pub seller: Pubkey,

    /// Optional third-party arbiter for dispute resolution
    pub arbiter: Option<Pubkey>,

    /// Amount held in escrow (in token micro-units)
    pub amount: u64,

    /// SHA256 hash of the expected service/deliverable
    pub memo_hash: [u8; 32],

    /// Current state of the escrow
    pub state: EscrowState,

    /// Unix timestamp when escrow expires (auto-refund)
    pub timeout: i64,

    /// Unix timestamp when escrow was created
    pub created_at: i64,

    /// Optional delivery proof hash (set by seller)
    pub delivery_proof: Option<[u8; 32]>,

    /// Optional evidence hash for disputes
    pub dispute_evidence: Option<[u8; 32]>,

    /// Token mint for this escrow
    pub mint: Pubkey,

    /// MEDIUM-11: Token decimals (prevents hardcoded decimals assumption)
    pub token_decimals: u8,

    /// MEDIUM-6: Slot when dispute was initiated (for arbiter delay)
    pub dispute_initiated_slot: u64,

    /// PDA bump seed
    pub bump: u8,

    /// Reserved space for future upgrades (reduced by 1 for version field)
    pub _reserved: [u8; 22],
}

impl EscrowAccount {
    pub const fn space() -> usize {
        ESCROW_ACCOUNT_SIZE + 32 + 32 + 32 + 32 // Add optional fields and reserved
    }

    /// Check if escrow has expired
    pub fn is_expired(&self, current_timestamp: i64) -> bool {
        current_timestamp > self.timeout
    }

    /// Check if escrow can be auto-released (72h after delivery without dispute)
    pub fn can_auto_release(&self, current_timestamp: i64) -> bool {
        if self.state != EscrowState::Delivered {
            return false;
        }
        // Auto-release 72 hours after delivery
        current_timestamp > self.timeout
    }
}

/// State of an escrow account
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug, PartialEq, Default)]
pub enum EscrowState {
    /// Escrow created but not yet funded
    #[default]
    Created,
    /// Buyer has deposited funds
    Funded,
    /// Seller claims delivery is complete
    Delivered,
    /// Either party has initiated a dispute
    Disputed,
    /// Funds released to seller (terminal)
    Released,
    /// Funds returned to buyer (terminal)
    Refunded,
    /// Cancelled before funding (terminal)
    Cancelled,
}
