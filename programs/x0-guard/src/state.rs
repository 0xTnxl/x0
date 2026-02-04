//! State structures for x0-guard program
//!
//! Defines the on-chain account structures owned by x0-guard:
//! - AgentPolicy: Core policy account for agent spending authority
//! - ProtocolConfig: Global protocol configuration
//! - ExtraAccountMetaList: Transfer hook configuration

use anchor_lang::prelude::*;

use x0_common::constants::*;
use x0_common::whitelist::{WhitelistData, WhitelistMode};

// ============================================================================
// Agent Policy
// ============================================================================

/// The core policy account that defines an agent's spending authority.
/// This is a PDA derived from the owner's public key.
///
/// # LOW-4: Version Field for Upgrades
/// The `version` field enables future account migrations. When account
/// structure changes, increment the version and add migration logic.
#[account]
#[derive(Debug)]
pub struct AgentPolicy {
    /// Account version for future migrations (LOW-4)
    /// Version 1: Initial structure
    pub version: u8,

    /// The human owner's cold wallet address (has full control)
    pub owner: Pubkey,

    /// The agent's hot-key for signing transactions (e.g., Lit Protocol PKP)
    pub agent_signer: Pubkey,

    /// Maximum token units the agent can spend in a rolling 24-hour window
    pub daily_limit: u64,

    /// MEDIUM-8: Maximum single transaction amount (optional)
    /// When set, individual transfers cannot exceed this amount
    pub max_single_transaction: Option<u64>,

    /// Rolling window of recent spending entries for limit enforcement
    pub rolling_window: Vec<SpendingEntry>,

    /// Privacy level for transfers (Public or Confidential)
    pub privacy_level: PrivacyLevel,

    /// Whitelist mode configuration
    pub whitelist_mode: WhitelistMode,

    /// Mode-specific whitelist data
    pub whitelist_data: WhitelistData,

    /// Optional auditor key for compliance (can decrypt confidential amounts)
    pub auditor_key: Option<Pubkey>,

    /// Number of Blinks generated in the current hour (rate limiting)
    pub blinks_this_hour: u8,

    /// Timestamp of the current hour window for Blink rate limiting
    pub blink_hour_start: i64,

    /// Whether the agent is currently active (can be paused by owner)
    pub is_active: bool,

    /// PDA bump seed
    pub bump: u8,

    /// Delegation mode: requires the agent to be a delegate, not the token owner
    /// This prevents bypass attacks where owner sets themselves as agent_signer
    pub require_delegation: bool,

    /// The token account that must be used with this policy (optional enforcement)
    /// When set, only transfers from this specific token account are allowed
    pub bound_token_account: Option<Pubkey>,

    /// MEDIUM-2: Last slot when policy was updated (rate limiting)
    pub last_update_slot: u64,

    /// Reserved space for future upgrades (reduced by 1 for version field)
    pub _reserved: [u8; 12],
}

impl AgentPolicy {
    /// Calculate the space required for an AgentPolicy account (HIGH-5)
    pub const fn space() -> usize {
        8 +   // Anchor discriminator
        1 +   // LOW-4: version: u8
        32 +  // owner: Pubkey
        32 +  // agent_signer: Pubkey
        8 +   // daily_limit: u64
        1 + 8 + // MEDIUM-8: max_single_transaction: Option<u64>
        4 + (MAX_ROLLING_WINDOW_ENTRIES * SPENDING_ENTRY_SIZE) + // rolling_window: Vec<SpendingEntry>
        1 + 1 + 32 + // privacy_level: PrivacyLevel enum (1 discriminant + 1 option + 32 pubkey)
        1 +   // whitelist_mode: WhitelistMode enum discriminant
        1 + 4 + BLOOM_FILTER_SIZE_BYTES + 1 + // whitelist_data: largest variant (Bloom) with enum discriminant
        1 + 32 + // auditor_key: Option<Pubkey>
        1 +   // blinks_this_hour: u8
        8 +   // blink_hour_start: i64
        1 +   // is_active: bool
        1 +   // bump: u8
        1 +   // require_delegation: bool
        1 + 32 + // bound_token_account: Option<Pubkey>
        8 +   // MEDIUM-2: last_update_slot: u64
        12    // _reserved: [u8; 12]
    }

    /// Calculate current 24h spend from rolling window
    pub fn current_spend(&self, current_timestamp: i64) -> u64 {
        let cutoff = current_timestamp - ROLLING_WINDOW_SECONDS;
        self.rolling_window
            .iter()
            .filter(|entry| entry.timestamp > cutoff)
            .fold(0u64, |acc, entry| acc.saturating_add(entry.amount))
    }

    /// Check if a transfer would exceed the daily limit
    pub fn would_exceed_limit(&self, amount: u64, current_timestamp: i64) -> bool {
        let current_spend = self.current_spend(current_timestamp);
        current_spend.saturating_add(amount) > self.daily_limit
    }

    /// Check and update the Blink rate limit
    pub fn check_blink_rate_limit(&mut self, current_timestamp: i64) -> bool {
        let current_hour = current_timestamp / 3600;
        let window_hour = self.blink_hour_start / 3600;

        if current_hour != window_hour {
            self.blink_hour_start = current_timestamp;
            self.blinks_this_hour = 0;
        }

        if self.blinks_this_hour >= MAX_BLINKS_PER_HOUR {
            return false;
        }

        self.blinks_this_hour += 1;
        true
    }
}

/// A single spending entry in the rolling window
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug, PartialEq)]
pub struct SpendingEntry {
    /// Amount spent in token micro-units
    pub amount: u64,
    /// Unix timestamp when the spend occurred
    pub timestamp: i64,
}

impl SpendingEntry {
    pub const SIZE: usize = SPENDING_ENTRY_SIZE;
}

/// Privacy level for transfers
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug, PartialEq, Default)]
pub enum PrivacyLevel {
    /// Standard SPL transfers with visible amounts
    #[default]
    Public,
    /// ZK-encrypted amounts using confidential transfers
    Confidential {
        /// Optional auditor who can decrypt amounts for compliance
        auditor: Option<Pubkey>,
    },
}

// ============================================================================
// Protocol Configuration
// ============================================================================

/// Global protocol configuration (singleton PDA)
#[account]
#[derive(Debug)]
pub struct ProtocolConfig {
    /// Protocol administrator (can update config)
    pub admin: Pubkey,

    /// Treasury address for protocol fees
    pub treasury: Pubkey,

    /// Current protocol fee in basis points
    pub fee_basis_points: u16,

    /// Blink generation cost in lamports
    pub blink_cost_lamports: u64,

    /// Registry listing fee in lamports
    pub registry_fee_lamports: u64,

    /// Whether protocol is paused (emergency)
    pub is_paused: bool,

    /// Unix timestamp of last config update
    pub last_updated: i64,

    /// PDA bump seed
    pub bump: u8,

    /// Reserved space for future upgrades
    pub _reserved: [u8; 64],
}

impl ProtocolConfig {
    pub const fn space() -> usize {
        8 + // discriminator
        32 + // admin
        32 + // treasury
        2 + // fee_basis_points
        8 + // blink_cost_lamports
        8 + // registry_fee_lamports
        1 + // is_paused
        8 + // last_updated
        1 + // bump
        64  // reserved
    }
}

// ============================================================================
// Transfer Hook Configuration
// ============================================================================

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

// ============================================================================
// Internal Types (not accounts)
// ============================================================================

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
    pub fn from_window(window: &[SpendingEntry], current_timestamp: i64) -> Self {
        let cutoff = current_timestamp - ROLLING_WINDOW_SECONDS;
        
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
