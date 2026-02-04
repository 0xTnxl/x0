//! Cancel a scheduled admin action

use anchor_lang::prelude::*;

use x0_common::events::AdminActionCancelled;

use super::CancelAdminAction;

pub fn handler(ctx: Context<CancelAdminAction>) -> Result<()> {
    let clock = Clock::get()?;
    let action = &mut ctx.accounts.action;

    action.cancelled = true;

    emit!(AdminActionCancelled {
        action: action.key(),
        admin: ctx.accounts.admin.key(),
        timestamp: clock.unix_timestamp,
    });

    msg!("Admin action cancelled: {}", action.key());

    Ok(())
}
