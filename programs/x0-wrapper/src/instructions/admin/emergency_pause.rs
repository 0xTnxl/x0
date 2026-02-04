//! Emergency pause (immediate, no timelock)
//!
//! This is the ONLY admin operation that bypasses the timelock.
//! It can only PAUSE, never unpause. Unpausing requires the normal timelock.
//! Use only in emergencies (exploit detected, oracle manipulation, etc.)

use anchor_lang::prelude::*;

use x0_common::events::{WrapperPausedEvent, ReserveAlert, AlertLevel};

use super::EmergencyPause;

pub fn handler(ctx: Context<EmergencyPause>) -> Result<()> {
    let clock = Clock::get()?;
    let config = &mut ctx.accounts.config;

    // Set paused
    config.is_paused = true;

    emit!(WrapperPausedEvent {
        config: config.key(),
        is_paused: true,
        admin: ctx.accounts.admin.key(),
        timestamp: clock.unix_timestamp,
    });

    // Emit critical alert
    emit!(ReserveAlert {
        reserve_ratio: 0, // Unknown in this context
        reserve_balance: 0,
        outstanding_supply: 0,
        severity: AlertLevel::Critical,
        timestamp: clock.unix_timestamp,
    });

    msg!("EMERGENCY PAUSE ACTIVATED by {}", ctx.accounts.admin.key());

    Ok(())
}
