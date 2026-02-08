//! State structures for x0-reputation program
//!
//! Defines the on-chain account structures owned by x0-reputation.

use anchor_lang::prelude::*;
use x0_common::constants::*;

/// An agent's reputation account tracking transaction history
///
/// # LOW-4: Version Field for Upgrades
/// The `version` field enables future account migrations.
#[account]
#[derive(Debug)]
pub struct AgentReputation {
    /// Account version for future migrations (LOW-4)
    /// Version 1: Initial structure
    /// Version 2: Added failed_transactions field
    pub version: u8,

    /// The agent's policy PDA (links reputation to agent)
    pub agent_id: Pubkey,

    /// Total number of completed transactions
    pub total_transactions: u64,

    /// Number of successful (undisputed) transactions
    pub successful_transactions: u64,

    /// Number of disputed transactions
    pub disputed_transactions: u64,

    /// Number of disputes resolved in this agent's favor
    pub resolved_in_favor: u64,

    /// Number of failed transactions (policy rejections)
    /// Tracked separately from disputes - these are agent errors, not user disputes
    pub failed_transactions: u64,

    /// Average response time in milliseconds
    pub average_response_time_ms: u32,

    /// Cumulative response time for averaging
    pub cumulative_response_time_ms: u64,

    /// Unix timestamp of last update
    pub last_updated: i64,

    /// Unix timestamp of last decay application
    pub last_decay_applied: i64,

    /// PDA bump seed
    pub bump: u8,

    /// Reserved space for future upgrades (reduced for new fields)
    pub _reserved: [u8; 23],
}

impl AgentReputation {
    pub const fn space() -> usize {
        8 +   // Anchor discriminator
        1 +   // version: u8
        32 +  // agent_id: Pubkey
        8 +   // total_transactions: u64
        8 +   // successful_transactions: u64
        8 +   // disputed_transactions: u64
        8 +   // resolved_in_favor: u64
        8 +   // failed_transactions: u64
        4 +   // average_response_time_ms: u32
        8 +   // cumulative_response_time_ms: u64
        8 +   // last_updated: i64
        8 +   // last_decay_applied: i64
        1 +   // bump: u8
        23    // _reserved: [u8; 23]
    }

    /// Calculate the reputation score (0.0 to 1.0 (now 0.5 after MEDIUM-9 FIX))
    ///
    /// MEDIUM-9 FIX: New agents with no disputes get neutral (0.5) resolution rate
    /// instead of perfect (1.0), preventing artificial score inflation.
    ///
    /// Score factors:
    /// - Success rate (successful / total attempted)
    /// - Failure rate (policy rejections hurt reputation)
    /// - Dispute rate (user disputes)
    /// - Resolution rate (disputes won)
    pub fn calculate_score(&self) -> f64 {
        // Total attempts = successful + failed + disputed
        let total_attempts = self.successful_transactions
            .saturating_add(self.failed_transactions)
            .saturating_add(self.disputed_transactions);
        
        if total_attempts == 0 {
            return 0.0;
        }

        // Success rate considers all attempts (not just completed transactions)
        let success_rate = self.successful_transactions as f64 / total_attempts as f64;
        
        // Failure rate (policy rejections) - penalizes agents that frequently hit limits
        let failure_rate = self.failed_transactions as f64 / total_attempts as f64;
        
        let dispute_rate = self.disputed_transactions as f64 / total_attempts as f64;
        
        // MEDIUM-9: Fair resolution rate for new agents
        let resolution_rate = if self.disputed_transactions > 0 {
            self.resolved_in_favor as f64 / self.disputed_transactions as f64
        } else if total_attempts < MIN_TRANSACTIONS_FOR_REPUTATION {
            0.5 // Neutral score for new agents without disputes
        } else {
            1.0 // Perfect only if no disputes AND established reputation
        };

        // Weighted score: 60% success, 15% resolution, 10% inverse dispute, 15% inverse failure
        (success_rate * REPUTATION_SUCCESS_WEIGHT)
            + (resolution_rate * REPUTATION_RESOLUTION_WEIGHT)
            + ((1.0 - dispute_rate) * REPUTATION_DISPUTE_WEIGHT)
            + ((1.0 - failure_rate) * REPUTATION_FAILURE_WEIGHT)
    }

    /// Check if agent has minimum transactions for reliable score
    pub fn has_reliable_score(&self) -> bool {
        self.total_transactions >= MIN_TRANSACTIONS_FOR_REPUTATION
    }

    /// Record a successful transaction
    pub fn record_success(&mut self, response_time_ms: u32, current_timestamp: i64) {
        self.total_transactions += 1;
        self.successful_transactions += 1;
        self.cumulative_response_time_ms += response_time_ms as u64;
        self.average_response_time_ms = 
            (self.cumulative_response_time_ms / self.total_transactions) as u32;
        self.last_updated = current_timestamp;
    }

    /// Record a disputed transaction
    pub fn record_dispute(&mut self, current_timestamp: i64) {
        self.disputed_transactions += 1;
        self.last_updated = current_timestamp;
    }

    /// Record a failed transaction (policy rejection)
    /// 
    /// Called when an agent attempts a transfer that violates their policy:
    /// - Exceeded daily limit
    /// - Exceeded per-transaction limit
    /// - Destination not whitelisted
    /// - Policy paused
    ///
    /// Failures are tracked separately from disputes because:
    /// - Disputes are user complaints about completed transactions
    /// - Failures are agent errors (hitting configured limits)
    pub fn record_failure(&mut self, _error_code: u32, current_timestamp: i64) {
        self.failed_transactions += 1;
        self.last_updated = current_timestamp;
        // Note: error_code is stored for future analytics but not used in scoring yet
    }

    /// Record dispute resolution in favor of this agent
    pub fn record_resolution_favor(&mut self, current_timestamp: i64) {
        self.resolved_in_favor += 1;
        self.last_updated = current_timestamp;
    }
}
