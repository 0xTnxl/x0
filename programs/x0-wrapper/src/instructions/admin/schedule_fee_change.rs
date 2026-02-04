//! Schedule a fee rate change

use anchor_lang::prelude::*;

use crate::state::AdminActionType;
use x0_common::{
    constants::*,
    error::X0WrapperError,
    events::AdminActionScheduled,
};

use super::ScheduleAdminAction;

pub fn handler(ctx: Context<ScheduleAdminAction>, new_fee_bps: u16) -> Result<()> {
    let clock = Clock::get()?;

    // Validate fee rate
    require!(
        new_fee_bps >= MIN_WRAPPER_FEE_BPS,
        X0WrapperError::FeeRateTooLow
    );
    require!(
        new_fee_bps <= MAX_WRAPPER_FEE_BPS,
        X0WrapperError::FeeRateTooHigh
    );

    let action = &mut ctx.accounts.action;
    
    action.action_type = AdminActionType::SetFeeRate;
    action.scheduled_timestamp = clock.unix_timestamp + ADMIN_TIMELOCK_SECONDS;
    action.new_value = new_fee_bps as u64;
    action.new_admin = Pubkey::default();
    action.destination = Pubkey::default();
    action.executed = false;
    action.cancelled = false;
    action.bump = ctx.bumps.action;
    action._reserved = [0u8; 32];

    emit!(AdminActionScheduled {
        action: action.key(),
        action_type: "SetFeeRate".to_string(),
        scheduled_timestamp: action.scheduled_timestamp,
        admin: ctx.accounts.admin.key(),
        timestamp: clock.unix_timestamp,
    });

    msg!(
        "Fee change scheduled: new_fee_bps={}, executable_at={}",
        new_fee_bps,
        action.scheduled_timestamp
    );

    Ok(())
}
