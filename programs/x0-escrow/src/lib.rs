//! x0-escrow: Conditional payments with dispute resolution
//!
//! This program provides escrow functionality for high-value or risky transactions:
//! - Funds held until service delivery confirmed
//! - Optional third-party arbiter for disputes
//! - Auto-release after timeout if no dispute
//! - Reputation integration for trust scoring

// Suppress cfg warnings from Anchor/Solana macros (toolchain version mismatch)
#![allow(unexpected_cfgs)]
// Suppress ambiguous glob re-export warnings (handlers have same name in different modules)
#![allow(ambiguous_glob_reexports)]

use anchor_lang::prelude::*;

pub mod instructions;
pub mod state;

pub use instructions::*;
pub use state::{EscrowAccount, EscrowState};
pub use x0_common::{
    constants::*,
    error::X0EscrowError,
    events::*,
};

declare_id!("AhaDyVm8LBxpUwFdArA37LnHvNx6cNWe3KAiy8zGqhHF");

#[program]
pub mod x0_escrow {
    use super::*;

    /// Create a new escrow
    ///
    /// # Arguments
    /// * `amount` - Amount to escrow
    /// * `memo_hash` - SHA256 hash of the expected service/deliverable
    /// * `timeout_seconds` - Seconds until auto-refund (min 1h, max 30d)
    /// * `arbiter` - Optional third-party for dispute resolution
    pub fn create_escrow(
        ctx: Context<CreateEscrow>,
        amount: u64,
        memo_hash: [u8; 32],
        timeout_seconds: i64,
        arbiter: Option<Pubkey>,
    ) -> Result<()> {
        instructions::create_escrow::handler(ctx, amount, memo_hash, timeout_seconds, arbiter)
    }

    /// Fund an escrow (buyer deposits tokens)
    pub fn fund_escrow(ctx: Context<FundEscrow>) -> Result<()> {
        instructions::fund_escrow::handler(ctx)
    }

    /// Mark delivery complete (seller claims delivery)
    ///
    /// # Arguments
    /// * `proof_hash` - Optional hash of delivery proof
    pub fn mark_delivered(
        ctx: Context<MarkDelivered>,
        proof_hash: Option<[u8; 32]>,
    ) -> Result<()> {
        instructions::mark_delivered::handler(ctx, proof_hash)
    }

    /// Release funds to seller (buyer confirms satisfaction)
    pub fn release_funds(ctx: Context<ReleaseFunds>) -> Result<()> {
        instructions::release_funds::handler(ctx)
    }

    /// Initiate a dispute
    ///
    /// # Arguments
    /// * `evidence_hash` - Hash of dispute evidence
    pub fn initiate_dispute(
        ctx: Context<InitiateDispute>,
        evidence_hash: [u8; 32],
    ) -> Result<()> {
        instructions::initiate_dispute::handler(ctx, evidence_hash)
    }

    /// Resolve a dispute (arbiter decision)
    ///
    /// # Arguments
    /// * `release_to_seller` - If true, release to seller; if false, refund to buyer
    pub fn resolve_dispute(
        ctx: Context<ResolveDispute>,
        release_to_seller: bool,
    ) -> Result<()> {
        instructions::resolve_dispute::handler(ctx, release_to_seller)
    }

    /// Claim auto-release after timeout (seller claims if buyer doesn't dispute)
    pub fn claim_auto_release(ctx: Context<ClaimAutoRelease>) -> Result<()> {
        instructions::claim_auto_release::handler(ctx)
    }

    /// Claim refund after timeout (buyer claims if seller doesn't deliver)
    pub fn claim_timeout_refund(ctx: Context<ClaimTimeoutRefund>) -> Result<()> {
        instructions::claim_timeout_refund::handler(ctx)
    }

    /// Cancel escrow (only before funding)
    pub fn cancel_escrow(ctx: Context<CancelEscrow>) -> Result<()> {
        instructions::cancel_escrow::handler(ctx)
    }
}
