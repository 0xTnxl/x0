//! Execute a scheduled pause/unpause

use anchor_lang::prelude::*;

use crate::state::AdminActionType;
use x0_common::{
    error::X0WrapperError,
    events::{AdminActionExecuted, WrapperPausedEvent},
};

use super::ExecuteAdminAction;

pub fn handler(ctx: Context<ExecuteAdminAction>) -> Result<()> {
    let clock = Clock::get()?;
    let action = &mut ctx.accounts.action;
    let config = &mut ctx.accounts.config;

    // Verify action type
    require!(
        action.action_type == AdminActionType::SetPaused,
        X0WrapperError::InvalidActionType
    );

    // Verify timelock has expired
    require!(
        clock.unix_timestamp >= action.scheduled_timestamp,
        X0WrapperError::TimelockNotExpired
    );

    let is_paused = action.new_value == 1;
    config.is_paused = is_paused;
    action.executed = true;

    emit!(WrapperPausedEvent {
        config: config.key(),
        is_paused,
        admin: ctx.accounts.admin.key(),
        timestamp: clock.unix_timestamp,
    });

    emit!(AdminActionExecuted {
        action: action.key(),
        action_type: "SetPaused".to_string(),
        admin: ctx.accounts.admin.key(),
        timestamp: clock.unix_timestamp,
    });

    msg!("Wrapper paused state: {}", is_paused);

    Ok(())
}
