//! Schedule emergency withdrawal

use anchor_lang::prelude::*;

use crate::state::AdminActionType;
use x0_common::{
    constants::*,
    events::AdminActionScheduled,
};

use super::ScheduleAdminAction;

pub fn handler(ctx: Context<ScheduleAdminAction>, amount: u64, destination: Pubkey) -> Result<()> {
    let clock = Clock::get()?;
    let action = &mut ctx.accounts.action;

    action.action_type = AdminActionType::EmergencyWithdraw;
    action.scheduled_timestamp = clock.unix_timestamp + ADMIN_TIMELOCK_SECONDS;
    action.new_value = amount;
    action.new_admin = Pubkey::default();
    action.destination = destination;
    action.executed = false;
    action.cancelled = false;
    action.bump = ctx.bumps.action;
    action._reserved = [0u8; 32];

    emit!(AdminActionScheduled {
        action: action.key(),
        action_type: "EmergencyWithdraw".to_string(),
        scheduled_timestamp: action.scheduled_timestamp,
        admin: ctx.accounts.admin.key(),
        timestamp: clock.unix_timestamp,
    });

    msg!(
        "Emergency withdrawal scheduled: amount={}, destination={}, executable_at={}",
        amount,
        destination,
        action.scheduled_timestamp
    );

    Ok(())
}
