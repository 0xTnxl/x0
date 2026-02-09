//! State structures for x0-wrapper program
//!
//! Defines the on-chain account structures owned by x0-wrapper.

use anchor_lang::prelude::*;
use x0_common::constants::*;

/// Configuration for the x0-USD wrapper token
#[account]
#[derive(Debug)]
pub struct WrapperConfig {
    /// Admin address (should be multisig)
    pub admin: Pubkey,

    /// Pending admin for two-step admin transfer
    pub pending_admin: Option<Pubkey>,

    /// The underlying USDC mint address
    pub usdc_mint: Pubkey,

    /// The wrapper token (x0-USD) mint address
    pub wrapper_mint: Pubkey,

    /// The reserve token account (holds USDC backing)
    pub reserve_account: Pubkey,

    /// Current redemption fee in basis points
    pub redemption_fee_bps: u16,

    /// Whether deposits and redemptions are paused
    pub is_paused: bool,

    /// Authorized bridge program (for bridge_mint CPI)
    /// Set via set_bridge_program admin instruction.
    /// When Pubkey::default(), bridge minting is disabled.
    pub bridge_program: Pubkey,

    /// PDA bump seed
    pub bump: u8,

    /// Reserved space for future upgrades
    pub _reserved: [u8; 32],
}

impl WrapperConfig {
    pub const fn space() -> usize {
        WRAPPER_CONFIG_SIZE
    }
}

/// Statistics and operational metrics for the wrapper
#[account]
#[derive(Debug)]
pub struct WrapperStats {
    /// Current USDC balance in reserve
    pub reserve_usdc_balance: u64,

    /// Outstanding wrapper token supply
    pub outstanding_wrapper_supply: u64,

    /// Total deposits (all-time)
    pub total_deposits: u64,

    /// Total redemptions (all-time)
    pub total_redemptions: u64,

    /// Total fees collected (all-time)
    pub total_fees_collected: u64,

    /// Daily redemption volume (resets every 24h)
    pub daily_redemption_volume: u64,

    /// Timestamp when daily counter was last reset
    pub daily_redemption_reset_timestamp: i64,

    /// Last update timestamp
    pub last_updated: i64,

    /// PDA bump seed
    pub bump: u8,

    /// Reserved space for future upgrades
    pub _reserved: [u8; 64],
}

impl WrapperStats {
    pub const fn space() -> usize {
        WRAPPER_STATS_SIZE
    }

    /// Calculate reserve ratio scaled by 10000 (10000 = 1.0)
    pub fn reserve_ratio_scaled(&self) -> Option<u64> {
        if self.outstanding_wrapper_supply == 0 {
            return Some(10_000); // 1.0 if no supply
        }
        self.reserve_usdc_balance
            .checked_mul(10_000)?
            .checked_div(self.outstanding_wrapper_supply)
    }

    /// Check if reserve ratio is healthy (>= 1.0)
    pub fn is_healthy(&self) -> bool {
        match self.reserve_ratio_scaled() {
            Some(ratio) => ratio >= MIN_RESERVE_RATIO_SCALED,
            None => false, // Overflow means something is very wrong
        }
    }

    /// Check if reserve is at warning level
    pub fn is_warning(&self) -> bool {
        match self.reserve_ratio_scaled() {
            Some(ratio) => ratio < RESERVE_WARNING_THRESHOLD && ratio >= MIN_RESERVE_RATIO_SCALED,
            None => false,
        }
    }

    /// Reset daily counter if 24 hours have passed
    pub fn maybe_reset_daily_counter(&mut self, current_timestamp: i64) {
        if current_timestamp - self.daily_redemption_reset_timestamp >= ROLLING_WINDOW_SECONDS {
            self.daily_redemption_volume = 0;
            self.daily_redemption_reset_timestamp = current_timestamp;
        }
    }
}

/// Type of admin action for timelock
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug, PartialEq)]
pub enum AdminActionType {
    /// Change redemption fee rate
    SetFeeRate,
    /// Pause/unpause operations
    SetPaused,
    /// Emergency withdrawal
    EmergencyWithdraw,
    /// Transfer admin to new address
    TransferAdmin,
}

/// A timelocked admin action
#[account]
#[derive(Debug)]
pub struct AdminAction {
    /// Type of action
    pub action_type: AdminActionType,

    /// When the action can be executed
    pub scheduled_timestamp: i64,

    /// New value (interpretation depends on action_type)
    /// - SetFeeRate: new fee in bps (as u64)
    /// - SetPaused: 1 for pause, 0 for unpause
    /// - EmergencyWithdraw: amount to withdraw
    pub new_value: u64,

    /// New admin address (only for TransferAdmin)
    pub new_admin: Pubkey,

    /// Destination for emergency withdraw
    pub destination: Pubkey,

    /// Whether this action has been executed
    pub executed: bool,

    /// Whether this action has been cancelled
    pub cancelled: bool,

    /// PDA bump seed
    pub bump: u8,

    /// Reserved space
    pub _reserved: [u8; 32],
}

impl AdminAction {
    pub const fn space() -> usize {
        ADMIN_ACTION_SIZE
    }

    /// Check if action is ready to execute
    pub fn is_ready(&self, current_timestamp: i64) -> bool {
        !self.executed && !self.cancelled && current_timestamp >= self.scheduled_timestamp
    }

    /// Check if action is still pending (not ready yet)
    pub fn is_pending(&self, current_timestamp: i64) -> bool {
        !self.executed && !self.cancelled && current_timestamp < self.scheduled_timestamp
    }
}
