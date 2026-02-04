//! Schedule pause/unpause

use anchor_lang::prelude::*;

use crate::state::AdminActionType;
use x0_common::{
    constants::*,
    events::AdminActionScheduled,
};

use super::ScheduleAdminAction;

pub fn handler(ctx: Context<ScheduleAdminAction>, pause: bool) -> Result<()> {
    let clock = Clock::get()?;
    let action = &mut ctx.accounts.action;

    action.action_type = AdminActionType::SetPaused;
    action.scheduled_timestamp = clock.unix_timestamp + ADMIN_TIMELOCK_SECONDS;
    action.new_value = if pause { 1 } else { 0 };
    action.new_admin = Pubkey::default();
    action.destination = Pubkey::default();
    action.executed = false;
    action.cancelled = false;
    action.bump = ctx.bumps.action;
    action._reserved = [0u8; 32];

    emit!(AdminActionScheduled {
        action: action.key(),
        action_type: "SetPaused".to_string(),
        scheduled_timestamp: action.scheduled_timestamp,
        admin: ctx.accounts.admin.key(),
        timestamp: clock.unix_timestamp,
    });

    msg!(
        "Pause scheduled: pause={}, executable_at={}",
        pause,
        action.scheduled_timestamp
    );

    Ok(())
}
