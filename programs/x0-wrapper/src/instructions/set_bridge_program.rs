//! Set the authorized bridge program for bridge_mint CPI
//!
//! Admin-only instruction to set or update which bridge program
//! is allowed to call bridge_mint.

use anchor_lang::prelude::*;

use crate::state::WrapperConfig;
use x0_common::{
    constants::*,
    error::X0WrapperError,
    events::WrapperBridgeProgramUpdated,
};

#[derive(Accounts)]
pub struct SetBridgeProgram<'info> {
    /// The wrapper admin
    #[account(
        constraint = admin.key() == config.admin @ X0WrapperError::Unauthorized,
    )]
    pub admin: Signer<'info>,

    /// The wrapper configuration (mutable to update bridge_program)
    #[account(
        mut,
        seeds = [WRAPPER_CONFIG_SEED],
        bump = config.bump,
    )]
    pub config: Box<Account<'info, WrapperConfig>>,
}

pub fn handler(ctx: Context<SetBridgeProgram>, bridge_program: Pubkey) -> Result<()> {
    let clock = Clock::get()?;
    let config = &mut ctx.accounts.config;

    let old_bridge_program = config.bridge_program;
    config.bridge_program = bridge_program;

    emit!(WrapperBridgeProgramUpdated {
        old_bridge_program,
        new_bridge_program: bridge_program,
        admin: ctx.accounts.admin.key(),
        timestamp: clock.unix_timestamp,
    });

    msg!(
        "Bridge program updated: {} -> {}",
        old_bridge_program,
        bridge_program,
    );

    Ok(())
}
