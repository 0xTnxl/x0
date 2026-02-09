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

    // Check capacity
    require!(
        config.allowed_evm_contracts.len() < MAX_ALLOWED_EVM_CONTRACTS,
        X0BridgeError::TooManyEVMContracts
    );

    // Check not already present
    require!(
        !config.is_contract_allowed(&evm_contract),
        X0BridgeError::BridgeAlreadyInitialized // Reuse: contract already exists
    );

    config.allowed_evm_contracts.push(evm_contract);

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

    let initial_len = config.allowed_evm_contracts.len();
    config.allowed_evm_contracts.retain(|c| c != &evm_contract);

    require!(
        config.allowed_evm_contracts.len() < initial_len,
        X0BridgeError::MessageNotFound // Reuse: contract not found
    );

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

    require!(
        config.supported_domains.len() < MAX_SUPPORTED_DOMAINS,
        X0BridgeError::TooManySupportedDomains
    );

    require!(
        !config.is_domain_supported(domain),
        X0BridgeError::BridgeAlreadyInitialized // Reuse: domain already exists
    );

    config.supported_domains.push(domain);

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
