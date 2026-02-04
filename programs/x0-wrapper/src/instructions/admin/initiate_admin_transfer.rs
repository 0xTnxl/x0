//! Initiate admin transfer (two-step process)

use anchor_lang::prelude::*;

use super::InitiateAdminTransfer;

pub fn handler(ctx: Context<InitiateAdminTransfer>, new_admin: Pubkey) -> Result<()> {
    let config = &mut ctx.accounts.config;
    
    config.pending_admin = Some(new_admin);

    msg!(
        "Admin transfer initiated: {} -> {} (pending acceptance)",
        ctx.accounts.admin.key(),
        new_admin
    );

    Ok(())
}
