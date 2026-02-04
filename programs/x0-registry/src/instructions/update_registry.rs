//! Update an existing registry entry

use anchor_lang::prelude::*;

use crate::state::{AgentRegistry, Capability};
use x0_common::{
    constants::*,
    error::X0RegistryError,
    events::RegistryUpdated,
    utils::{validate_capability_type, validate_endpoint},
};

/// Accounts for updating a registry entry
#[derive(Accounts)]
pub struct UpdateRegistry<'info> {
    /// The owner (must sign)
    #[account(
        constraint = owner.key() == registry_entry.owner @ X0RegistryError::UnauthorizedRegistryUpdate
    )]
    pub owner: Signer<'info>,

    /// The registry entry to update
    #[account(
        mut,
        seeds = [REGISTRY_SEED, registry_entry.agent_id.as_ref()],
        bump = registry_entry.bump,
    )]
    pub registry_entry: Account<'info, AgentRegistry>,
}

pub fn handler(
    ctx: Context<UpdateRegistry>,
    new_endpoint: Option<String>,
    new_capabilities: Option<Vec<Capability>>,
) -> Result<()> {
    let registry = &mut ctx.accounts.registry_entry;
    let clock = Clock::get()?;
    let mut updated_fields = Vec::new();

    // Update endpoint if provided
    if let Some(endpoint) = new_endpoint {
        validate_endpoint(&endpoint)?;
        registry.endpoint = endpoint;
        updated_fields.push("endpoint".to_string());
    }

    // Update capabilities if provided
    if let Some(capabilities) = new_capabilities {
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

        registry.capabilities = capabilities;
        updated_fields.push("capabilities".to_string());
    }

    registry.last_updated = clock.unix_timestamp;

    // Emit event
    emit!(RegistryUpdated {
        registry_entry: registry.key(),
        updated_fields,
        timestamp: clock.unix_timestamp,
    });

    msg!(
        "Registry updated: agent_id={}",
        registry.agent_id
    );

    Ok(())
}
