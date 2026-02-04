//! Admin operations for x0-wrapper
//!
//! All sensitive admin operations use a 48-hour timelock pattern:
//! 1. Admin schedules the action
//! 2. Wait 48 hours
//! 3. Admin (or anyone) executes the action
//!
//! This prevents immediate malicious changes and gives users time to exit.

// Re-exports are accessed via explicit module paths from lib.rs
#![allow(unused_imports)]

pub mod schedule_fee_change;
pub mod execute_fee_change;
pub mod schedule_pause;
pub mod execute_pause;
pub mod emergency_pause;
pub mod schedule_emergency_withdraw;
pub mod execute_emergency_withdraw;
pub mod cancel_admin_action;
pub mod initiate_admin_transfer;
pub mod accept_admin_transfer;

pub use schedule_fee_change::*;
pub use execute_fee_change::*;
pub use schedule_pause::*;
pub use execute_pause::*;
pub use emergency_pause::*;
pub use schedule_emergency_withdraw::*;
pub use execute_emergency_withdraw::*;
pub use cancel_admin_action::*;
pub use initiate_admin_transfer::*;
pub use accept_admin_transfer::*;

use anchor_lang::prelude::*;

use crate::state::{WrapperConfig, AdminAction};
use x0_common::{
    constants::*,
    error::X0WrapperError,
};

/// Common accounts for scheduling admin actions
#[derive(Accounts)]
#[instruction(action_nonce: u64)]
pub struct ScheduleAdminAction<'info> {
    /// The admin (must be current admin)
    #[account(
        mut,
        constraint = admin.key() == config.admin @ X0WrapperError::Unauthorized,
    )]
    pub admin: Signer<'info>,

    /// The wrapper configuration (boxed to reduce stack usage)
    #[account(
        seeds = [WRAPPER_CONFIG_SEED],
        bump = config.bump,
    )]
    pub config: Box<Account<'info, WrapperConfig>>,

    /// The admin action PDA (to be created, boxed)
    #[account(
        init,
        payer = admin,
        space = AdminAction::space(),
        seeds = [ADMIN_ACTION_SEED, &action_nonce.to_le_bytes()],
        bump,
    )]
    pub action: Box<Account<'info, AdminAction>>,

    /// System program
    pub system_program: Program<'info, System>,
}

/// Common accounts for executing admin actions
#[derive(Accounts)]
pub struct ExecuteAdminAction<'info> {
    /// The admin (must be current admin)
    #[account(
        constraint = admin.key() == config.admin @ X0WrapperError::Unauthorized,
    )]
    pub admin: Signer<'info>,

    /// The wrapper configuration (mutable, boxed)
    #[account(
        mut,
        seeds = [WRAPPER_CONFIG_SEED],
        bump = config.bump,
    )]
    pub config: Box<Account<'info, WrapperConfig>>,

    /// The admin action PDA (boxed)
    #[account(
        mut,
        constraint = !action.executed @ X0WrapperError::AdminActionAlreadyExecuted,
        constraint = !action.cancelled @ X0WrapperError::AdminActionCancelled,
    )]
    pub action: Box<Account<'info, AdminAction>>,
}

/// Accounts for cancelling admin actions
#[derive(Accounts)]
pub struct CancelAdminAction<'info> {
    /// The admin (must be current admin)
    #[account(
        constraint = admin.key() == config.admin @ X0WrapperError::Unauthorized,
    )]
    pub admin: Signer<'info>,

    /// The wrapper configuration (boxed)
    #[account(
        seeds = [WRAPPER_CONFIG_SEED],
        bump = config.bump,
    )]
    pub config: Box<Account<'info, WrapperConfig>>,

    /// The admin action PDA (boxed)
    #[account(
        mut,
        constraint = !action.executed @ X0WrapperError::AdminActionAlreadyExecuted,
        constraint = !action.cancelled @ X0WrapperError::AdminActionCancelled,
    )]
    pub action: Box<Account<'info, AdminAction>>,
}

/// Accounts for emergency pause (no timelock)
#[derive(Accounts)]
pub struct EmergencyPause<'info> {
    /// The admin (must be current admin)
    #[account(
        constraint = admin.key() == config.admin @ X0WrapperError::Unauthorized,
    )]
    pub admin: Signer<'info>,

    /// The wrapper configuration (mutable, boxed)
    #[account(
        mut,
        seeds = [WRAPPER_CONFIG_SEED],
        bump = config.bump,
    )]
    pub config: Box<Account<'info, WrapperConfig>>,
}

/// Accounts for initiating admin transfer
#[derive(Accounts)]
pub struct InitiateAdminTransfer<'info> {
    /// The current admin
    #[account(
        constraint = admin.key() == config.admin @ X0WrapperError::Unauthorized,
    )]
    pub admin: Signer<'info>,

    /// The wrapper configuration (mutable, boxed)
    #[account(
        mut,
        seeds = [WRAPPER_CONFIG_SEED],
        bump = config.bump,
    )]
    pub config: Box<Account<'info, WrapperConfig>>,
}

/// Accounts for accepting admin transfer
#[derive(Accounts)]
pub struct AcceptAdminTransfer<'info> {
    /// The new admin (must match pending_admin)
    pub new_admin: Signer<'info>,

    /// The wrapper configuration (mutable, boxed)
    #[account(
        mut,
        seeds = [WRAPPER_CONFIG_SEED],
        bump = config.bump,
        constraint = config.pending_admin == Some(new_admin.key()) @ X0WrapperError::NotPendingAdmin,
    )]
    pub config: Box<Account<'info, WrapperConfig>>,
}
