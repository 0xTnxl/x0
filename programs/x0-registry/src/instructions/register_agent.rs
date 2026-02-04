//! Register a new agent in the registry

use anchor_lang::prelude::*;
use anchor_lang::solana_program::program::invoke;

use crate::state::{AgentRegistry, Capability};
use x0_common::{
    constants::*,
    error::X0RegistryError,
    events::AgentRegistered,
    utils::{validate_capability_type, validate_endpoint},
};

/// Accounts for registering an agent
#[derive(Accounts)]
pub struct RegisterAgent<'info> {
    /// The owner who will control this registry entry
    #[account(mut)]
    pub owner: Signer<'info>,

    /// The agent policy PDA (links registry to policy)
    /// CHECK: This is the agent's policy address
    pub agent_policy: UncheckedAccount<'info>,

    /// The registry entry PDA
    #[account(
        init,
        payer = owner,
        space = AgentRegistry::space(),
        seeds = [REGISTRY_SEED, agent_policy.key().as_ref()],
        bump,
    )]
    pub registry_entry: Account<'info, AgentRegistry>,

    /// The reputation PDA for this agent
    /// CHECK: Will be created by x0-reputation program
    pub reputation_pda: UncheckedAccount<'info>,

    /// Treasury to receive listing fee
    /// CHECK: Protocol treasury
    #[account(mut)]
    pub treasury: UncheckedAccount<'info>,

    /// System program
    pub system_program: Program<'info, System>,
}

pub fn handler(
    ctx: Context<RegisterAgent>,
    endpoint: String,
    capabilities: Vec<Capability>,
) -> Result<()> {
    // ========================================================================
    // MEDIUM-7 FIX: Validate ALL inputs BEFORE any state changes or payments
    // ========================================================================
    // This ensures user doesn't pay fees if their input is invalid.
    // In Anchor, account init happens during constraint processing (before handler),
    // but we still validate inputs before the fee transfer.
    
    // Validate endpoint
    validate_endpoint(&endpoint)?;

    // Validate capabilities
    require!(
        capabilities.len() <= MAX_CAPABILITIES_PER_AGENT,
        X0RegistryError::TooManyCapabilities
    );

    for cap in &capabilities {
        validate_capability_type(&cap.capability_type)?;
        require!(
            cap.metadata.len() <= MAX_CAPABILITY_METADATA_LENGTH,
            X0RegistryError::CapabilityMetadataTooLong
        );
    }

    // ========================================================================
    // All validations passed - now safe to pay fee
    // ========================================================================
    let transfer_ix = anchor_lang::solana_program::system_instruction::transfer(
        ctx.accounts.owner.key,
        ctx.accounts.treasury.key,
        REGISTRY_LISTING_FEE_LAMPORTS,
    );

    invoke(
        &transfer_ix,
        &[
            ctx.accounts.owner.to_account_info(),
            ctx.accounts.treasury.to_account_info(),
            ctx.accounts.system_program.to_account_info(),
        ],
    )?;

    let clock = Clock::get()?;
    let registry = &mut ctx.accounts.registry_entry;

    // Initialize registry entry
    registry.version = 1; // LOW-4: Account versioning for migrations
    registry.agent_id = ctx.accounts.agent_policy.key();
    registry.endpoint = endpoint.clone();
    registry.capabilities = capabilities.clone();
    registry.price_oracle = None;
    registry.reputation_pda = ctx.accounts.reputation_pda.key();
    registry.last_updated = clock.unix_timestamp;
    registry.is_active = true;
    registry.owner = ctx.accounts.owner.key();
    registry.bump = ctx.bumps.registry_entry;
    registry._reserved = [0u8; 31]; // Reduced for version field

    // Emit event
    emit!(AgentRegistered {
        registry_entry: registry.key(),
        agent_id: registry.agent_id,
        endpoint,
        capability_count: capabilities.len() as u8,
        timestamp: clock.unix_timestamp,
    });

    msg!(
        "Agent registered: agent_id={}, endpoint={}, capabilities={}",
        registry.agent_id,
        registry.endpoint,
        registry.capabilities.len()
    );

    Ok(())
}
