//! Accept admin transfer

use anchor_lang::prelude::*;

use x0_common::events::AdminTransferred;

use super::AcceptAdminTransfer;

pub fn handler(ctx: Context<AcceptAdminTransfer>) -> Result<()> {
    let clock = Clock::get()?;
    let config = &mut ctx.accounts.config;
    
    let old_admin = config.admin;
    let new_admin = ctx.accounts.new_admin.key();

    config.admin = new_admin;
    config.pending_admin = None;

    emit!(AdminTransferred {
        config: config.key(),
        old_admin,
        new_admin,
        timestamp: clock.unix_timestamp,
    });

    msg!(
        "Admin transfer completed: {} -> {}",
        old_admin,
        new_admin
    );

    Ok(())
}
