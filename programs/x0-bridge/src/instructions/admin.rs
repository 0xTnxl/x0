//! Admin operations for the bridge
//!
//! Manage whitelisted EVM contracts, supported domains, and pause state.
//! All operations require admin authority.

use anchor_lang::prelude::*;

use crate::state::BridgeConfig;
use x0_common::{
    constants::*,
    error::X0BridgeError,
    events::{BridgeContractUpdated, BridgePausedEvent},
};

#[derive(Accounts)]
pub struct AdminAction<'info> {
    /// The bridge admin
    pub admin: Signer<'info>,

    /// Bridge configuration (mutable for updates)
    #[account(
        mut,
        seeds = [BRIDGE_CONFIG_SEED],
        bump = config.bump,
        constraint = config.admin == admin.key() @ X0BridgeError::Unauthorized,
    )]
    pub config: Box<Account<'info, BridgeConfig>>,
}

/// Add an EVM contract address to the allowed list
pub fn add_allowed_contract(
    ctx: Context<AdminAction>,
    evm_contract: [u8; 20],
) -> Result<()> {
    let clock = Clock::get()?;
    let config = &mut ctx.accounts.config;

    config.add_contract(evm_contract)?;

    emit!(BridgeContractUpdated {
        config: config.key(),
        evm_contract,
        added: true,
        admin: ctx.accounts.admin.key(),
        timestamp: clock.unix_timestamp,
    });

    msg!(
        "Added EVM contract: 0x{}",
        hex::encode(evm_contract),
    );

    Ok(())
}

/// Remove an EVM contract address from the allowed list
pub fn remove_allowed_contract(
    ctx: Context<AdminAction>,
    evm_contract: [u8; 20],
) -> Result<()> {
    let clock = Clock::get()?;
    let config = &mut ctx.accounts.config;

    config.remove_contract(&evm_contract)?;

    emit!(BridgeContractUpdated {
        config: config.key(),
        evm_contract,
        added: false,
        admin: ctx.accounts.admin.key(),
        timestamp: clock.unix_timestamp,
    });

    msg!(
        "Removed EVM contract: 0x{}",
        hex::encode(evm_contract),
    );

    Ok(())
}

/// Add a supported Hyperlane domain ID
pub fn add_supported_domain(
    ctx: Context<AdminAction>,
    domain: u32,
) -> Result<()> {
    let config = &mut ctx.accounts.config;

    config.add_domain(domain)?;

    msg!("Added supported domain: {}", domain);

    Ok(())
}

/// Pause or unpause the bridge
pub fn set_paused(
    ctx: Context<AdminAction>,
    paused: bool,
) -> Result<()> {
    let clock = Clock::get()?;
    let config = &mut ctx.accounts.config;

    config.is_paused = paused;

    emit!(BridgePausedEvent {
        config: config.key(),
        is_paused: paused,
        admin: ctx.accounts.admin.key(),
        timestamp: clock.unix_timestamp,
    });

    msg!(
        "Bridge {}: admin={}",
        if paused { "paused" } else { "unpaused" },
        ctx.accounts.admin.key(),
    );

    Ok(())
}
