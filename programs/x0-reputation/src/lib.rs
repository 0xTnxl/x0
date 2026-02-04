//! x0-reputation: On-chain reputation oracle for agent trust scoring
//!
//! This program tracks transaction history and computes reputation scores:
//! - Successful transactions increase reputation
//! - Disputes decrease reputation
//! - Favorable dispute resolution partially restores reputation
//! - Monthly decay prevents stale reputations

// Suppress cfg warnings from Anchor/Solana macros (toolchain version mismatch)
#![allow(unexpected_cfgs)]
// Suppress ambiguous glob re-export warnings (handlers have same name in different modules)
#![allow(ambiguous_glob_reexports)]

use anchor_lang::prelude::*;

pub mod instructions;
pub mod state;

pub use instructions::*;
pub use state::AgentReputation;
pub use x0_common::{
    constants::*,
    error::X0ReputationError,
    events::*,
};

declare_id!("FfzkTWRGAJQPDePbujZdEhKHqC1UpqvDrpv4TEiWpx6y");

#[program]
pub mod x0_reputation {
    use super::*;

    /// Initialize a reputation account for an agent
    pub fn initialize_reputation(ctx: Context<InitializeReputation>) -> Result<()> {
        instructions::initialize_reputation::handler(ctx)
    }

    /// Record a successful transaction
    ///
    /// # Arguments
    /// * `response_time_ms` - Response time in milliseconds for averaging
    pub fn record_success(
        ctx: Context<RecordSuccess>,
        response_time_ms: u32,
    ) -> Result<()> {
        instructions::record_success::handler(ctx, response_time_ms)
    }

    /// Record a failed transaction (policy rejection)
    ///
    /// Called when an agent attempts a transfer that violates their policy.
    /// Failures hurt reputation as they indicate misconfiguration or abuse.
    ///
    /// # Arguments
    /// * `error_code` - The X0GuardError code that caused the rejection
    pub fn record_failure(
        ctx: Context<RecordFailure>,
        error_code: u32,
    ) -> Result<()> {
        instructions::record_failure::handler(ctx, error_code)
    }

    /// Record a dispute initiation
    pub fn record_dispute(ctx: Context<RecordDispute>) -> Result<()> {
        instructions::record_dispute::handler(ctx)
    }

    /// Record a dispute resolution in agent's favor
    pub fn record_resolution_favor(ctx: Context<RecordResolutionFavor>) -> Result<()> {
        instructions::record_resolution_favor::handler(ctx)
    }

    /// Apply monthly reputation decay
    pub fn apply_decay(ctx: Context<ApplyDecay>) -> Result<()> {
        instructions::apply_decay::handler(ctx)
    }

    /// Get the current reputation score (view function)
    pub fn get_reputation_score(ctx: Context<GetReputationScore>) -> Result<u32> {
        instructions::get_reputation_score::handler(ctx)
    }

    /// Migrate a reputation account from v1 to v2 layout
    ///
    /// This handles accounts created before failed_transactions was added.
    /// Only the policy owner can call this.
    pub fn migrate_reputation(ctx: Context<MigrateReputation>) -> Result<()> {
        instructions::migrate_reputation::handler(ctx)
    }

    /// Close a reputation account and reclaim rent
    pub fn close_reputation(ctx: Context<CloseReputation>) -> Result<()> {
        instructions::close_reputation::handler(ctx)
    }
}
