//! State structures specific to x0-guard program
//!
//! Most state is defined in x0-common, but guard-specific
//! helper types are defined here.

use anchor_lang::prelude::*;

/// Extra account meta configuration for transfer hook
#[account]
#[derive(Debug)]
pub struct ExtraAccountMetaList {
    /// The authority that can update this config
    pub authority: Pubkey,
    /// Number of extra accounts required
    pub extra_account_count: u8,
    /// PDA bump
    pub bump: u8,
}

impl ExtraAccountMetaList {
    pub const fn space() -> usize {
        8 + // discriminator
        32 + // authority
        1 + // extra_account_count
        1   // bump
    }
}

/// Transfer validation result for internal use
#[derive(Debug, Clone, PartialEq)]
pub enum ValidationResult {
    /// Transfer is approved
    Approved,
    /// Transfer requires human approval via Blink
    RequiresBlink {
        reason: BlinkReason,
    },
    /// Transfer is rejected
    Rejected {
        error_code: u16,
    },
}

/// Reason a Blink is required
#[derive(Debug, Clone, PartialEq)]
pub enum BlinkReason {
    /// Daily limit would be exceeded
    DailyLimitExceeded {
        current_spend: u64,
        requested_amount: u64,
        daily_limit: u64,
    },
    /// Recipient not in whitelist
    RecipientNotWhitelisted {
        recipient: Pubkey,
    },
    /// Amount exceeds emergency threshold
    EmergencyThreshold {
        amount: u64,
        threshold: u64,
    },
}

/// Rolling window statistics for monitoring
#[derive(Debug, Clone, AnchorSerialize, AnchorDeserialize)]
pub struct SpendingStats {
    /// Total spent in current 24h window
    pub total_spent_24h: u64,
    /// Number of transactions in window
    pub transaction_count: u32,
    /// Timestamp of oldest entry
    pub oldest_entry: i64,
    /// Timestamp of newest entry
    pub newest_entry: i64,
    /// Average transaction size
    pub avg_transaction_size: u64,
}

impl SpendingStats {
    pub fn from_window(window: &[x0_common::state::SpendingEntry], current_timestamp: i64) -> Self {
        let cutoff = current_timestamp - x0_common::constants::ROLLING_WINDOW_SECONDS;
        
        let valid_entries: Vec<_> = window
            .iter()
            .filter(|e| e.timestamp > cutoff)
            .collect();
        
        if valid_entries.is_empty() {
            return Self {
                total_spent_24h: 0,
                transaction_count: 0,
                oldest_entry: 0,
                newest_entry: 0,
                avg_transaction_size: 0,
            };
        }
        
        let total: u64 = valid_entries.iter().map(|e| e.amount).sum();
        let oldest = valid_entries.iter().map(|e| e.timestamp).min().unwrap_or(0);
        let newest = valid_entries.iter().map(|e| e.timestamp).max().unwrap_or(0);
        let count = valid_entries.len() as u32;
        
        Self {
            total_spent_24h: total,
            transaction_count: count,
            oldest_entry: oldest,
            newest_entry: newest,
            avg_transaction_size: total / (count as u64).max(1),
        }
    }
}
