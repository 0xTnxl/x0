//! Execute a scheduled fee rate change

use anchor_lang::prelude::*;

use crate::state::AdminActionType;
use x0_common::{
    error::X0WrapperError,
    events::{AdminActionExecuted, FeeRateUpdated},
};

use super::ExecuteAdminAction;

pub fn handler(ctx: Context<ExecuteAdminAction>) -> Result<()> {
    let clock = Clock::get()?;
    let action = &mut ctx.accounts.action;
    let config = &mut ctx.accounts.config;

    // Verify action type
    require!(
        action.action_type == AdminActionType::SetFeeRate,
        X0WrapperError::InvalidActionType
    );

    // Verify timelock has expired
    require!(
        clock.unix_timestamp >= action.scheduled_timestamp,
        X0WrapperError::TimelockNotExpired
    );

    let old_fee_bps = config.redemption_fee_bps;
    let new_fee_bps = action.new_value as u16;

    // Update fee rate
    config.redemption_fee_bps = new_fee_bps;
    action.executed = true;

    emit!(FeeRateUpdated {
        config: config.key(),
        old_fee_bps,
        new_fee_bps,
        admin: ctx.accounts.admin.key(),
        timestamp: clock.unix_timestamp,
    });

    emit!(AdminActionExecuted {
        action: action.key(),
        action_type: "SetFeeRate".to_string(),
        admin: ctx.accounts.admin.key(),
        timestamp: clock.unix_timestamp,
    });

    msg!(
        "Fee rate updated: {} -> {} bps",
        old_fee_bps,
        new_fee_bps
    );

    Ok(())
}
