//! x0-USD Wrapper Token Program
//!
//! This program implements a 1:1 USDC-backed wrapper token with the following features:
//!
//! - **Deposit & Mint**: Users deposit USDC and receive x0-USD at 1:1 ratio (no fee)
//! - **Burn & Redeem**: Users burn x0-USD to receive USDC (0.8% fee deducted)
//! - **Transfer Hook Compatible**: x0-USD uses Token-2022 with transfer hooks for guard validation
//! - **Reserve Invariant**: On-chain enforcement that reserve >= supply at all times
//! - **Timelock Admin**: All admin operations require 48-hour timelock
//! - **Emergency Controls**: Pause functionality and emergency withdrawal with multisig
//!
//! # Security Architecture
//!
//! 1. **Reentrancy Protection**: State updates BEFORE all token transfers
//! 2. **Checked Math**: All arithmetic uses checked operations to prevent overflow
//! 3. **Reserve Validation**: Every redemption validates reserve sufficiency
//! 4. **Admin Timelock**: Sensitive operations require scheduling 48h in advance
//! 5. **Multisig Ready**: Admin should be a Squads multisig for production
//!
//! # Key Invariant
//!
//! ```text
//! reserve_usdc_balance >= outstanding_wrapper_supply (always, after fees/rounding)
//! ```

// Suppress cfg warnings from Anchor/Solana macros (toolchain version mismatch)
#![allow(unexpected_cfgs)]
// Suppress ambiguous glob re-export warnings (handlers have same name in different modules)
#![allow(ambiguous_glob_reexports)]

use anchor_lang::prelude::*;

pub mod instructions;
pub mod state;

use instructions::*;
pub use state::{AdminAction, AdminActionType, WrapperConfig, WrapperStats};

declare_id!("EomiXBbg94Smu4ipDoJtuguazcd1KjLFDFJt2fCabvJ8");

#[program]
pub mod x0_wrapper {
    use super::*;

    // ========================================================================
    // Initialization (split into two phases to avoid stack overflow)
    // ========================================================================

    /// Initialize the wrapper config and stats PDAs (Phase 1)
    pub fn initialize_config(
        ctx: Context<InitializeConfig>,
        redemption_fee_bps: u16,
    ) -> Result<()> {
        instructions::initialize_config::handler(ctx, redemption_fee_bps)
    }

    /// Initialize the wrapper mint and reserve account (Phase 2)
    pub fn initialize_mint(ctx: Context<InitializeMint>) -> Result<()> {
        instructions::initialize_mint::handler(ctx)
    }

    // ========================================================================
    // Core Operations
    // ========================================================================

    /// Deposit USDC and mint x0-USD at 1:1 ratio (no fee)
    pub fn deposit_and_mint(
        ctx: Context<DepositAndMint>,
        amount: u64,
    ) -> Result<()> {
        instructions::deposit_and_mint::handler(ctx, amount)
    }

    /// Burn x0-USD and redeem USDC (redemption fee applied)
    pub fn burn_and_redeem(
        ctx: Context<BurnAndRedeem>,
        amount: u64,
    ) -> Result<()> {
        instructions::burn_and_redeem::handler(ctx, amount)
    }

    // ========================================================================
    // Admin Operations (with Timelock)
    // ========================================================================

    /// Schedule a fee rate change (requires 48h timelock)
    pub fn schedule_fee_change(
        ctx: Context<ScheduleAdminAction>,
        new_fee_bps: u16,
    ) -> Result<()> {
        instructions::admin::schedule_fee_change::handler(ctx, new_fee_bps)
    }

    /// Execute a previously scheduled fee rate change
    pub fn execute_fee_change(
        ctx: Context<ExecuteAdminAction>,
    ) -> Result<()> {
        instructions::admin::execute_fee_change::handler(ctx)
    }

    /// Schedule pause/unpause (requires 48h timelock)
    pub fn schedule_pause(
        ctx: Context<ScheduleAdminAction>,
        pause: bool,
    ) -> Result<()> {
        instructions::admin::schedule_pause::handler(ctx, pause)
    }

    /// Execute a previously scheduled pause/unpause
    pub fn execute_pause(
        ctx: Context<ExecuteAdminAction>,
    ) -> Result<()> {
        instructions::admin::execute_pause::handler(ctx)
    }

    /// Emergency pause (immediate, no timelock - for critical situations only)
    /// Requires admin signature and emits alert
    pub fn emergency_pause(
        ctx: Context<EmergencyPause>,
    ) -> Result<()> {
        instructions::admin::emergency_pause::handler(ctx)
    }

    /// Schedule emergency withdrawal (requires 48h timelock)
    pub fn schedule_emergency_withdraw(
        ctx: Context<ScheduleAdminAction>,
        amount: u64,
        destination: Pubkey,
    ) -> Result<()> {
        instructions::admin::schedule_emergency_withdraw::handler(ctx, amount, destination)
    }

    /// Execute a previously scheduled emergency withdrawal
    pub fn execute_emergency_withdraw(
        ctx: Context<ExecuteEmergencyWithdraw>,
    ) -> Result<()> {
        instructions::admin::execute_emergency_withdraw::handler(ctx)
    }

    /// Cancel a scheduled admin action
    pub fn cancel_admin_action(
        ctx: Context<CancelAdminAction>,
    ) -> Result<()> {
        instructions::admin::cancel_admin_action::handler(ctx)
    }

    /// Initiate admin transfer (two-step process)
    pub fn initiate_admin_transfer(
        ctx: Context<InitiateAdminTransfer>,
        new_admin: Pubkey,
    ) -> Result<()> {
        instructions::admin::initiate_admin_transfer::handler(ctx, new_admin)
    }

    /// Accept admin transfer (must be called by new admin)
    pub fn accept_admin_transfer(
        ctx: Context<AcceptAdminTransfer>,
    ) -> Result<()> {
        instructions::admin::accept_admin_transfer::handler(ctx)
    }
}
