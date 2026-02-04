//! Initialize a new agent policy

use anchor_lang::prelude::*;
use crate::state::{AgentPolicy, PrivacyLevel};
use x0_common::{
    constants::*,
    error::X0GuardError,
    events::PolicyCreated,
    utils::validate_daily_limit,
    whitelist::{WhitelistData, WhitelistMode},
};

/// Accounts for initializing a new agent policy
#[derive(Accounts)]
pub struct InitializePolicy<'info> {
    /// The owner who will control this policy (cold wallet)
    #[account(mut)]
    pub owner: Signer<'info>,

    /// The agent's hot-key that will sign transactions
    /// CHECK: This is just a public key reference, validated by owner
    pub agent_signer: UncheckedAccount<'info>,

    /// The policy PDA to be created
    #[account(
        init,
        payer = owner,
        space = AgentPolicy::space(),
        seeds = [AGENT_POLICY_SEED, owner.key().as_ref()],
        bump,
    )]
    pub agent_policy: Account<'info, AgentPolicy>,

    /// System program for account creation
    pub system_program: Program<'info, System>,
}

pub fn handler(
    ctx: Context<InitializePolicy>,
    daily_limit: u64,
    whitelist_mode: WhitelistMode,
    whitelist_data: WhitelistData,
    privacy_level: PrivacyLevel,
) -> Result<()> {
    // Validate daily limit
    validate_daily_limit(daily_limit)?;

    // Validate whitelist mode matches data
    validate_whitelist_config(&whitelist_mode, &whitelist_data)?;

    let policy = &mut ctx.accounts.agent_policy;
    let clock = Clock::get()?;

    // Initialize policy state
    policy.version = 1; // LOW-4: Account versioning for migrations
    policy.owner = ctx.accounts.owner.key();
    policy.agent_signer = ctx.accounts.agent_signer.key();
    policy.daily_limit = daily_limit;
    policy.max_single_transaction = None; // MEDIUM-8: Optional, can be set later
    policy.rolling_window = Vec::new();
    policy.privacy_level = privacy_level;
    policy.whitelist_mode = whitelist_mode;
    policy.whitelist_data = whitelist_data;
    policy.auditor_key = None;
    policy.blinks_this_hour = 0;
    policy.blink_hour_start = clock.unix_timestamp;
    policy.is_active = true;
    policy.bump = ctx.bumps.agent_policy;
    policy.require_delegation = false;
    policy.bound_token_account = None;
    policy.last_update_slot = 0; // MEDIUM-2: Allow immediate first update
    policy._reserved = [0u8; 12]; // Reduced for version field

    // Emit event
    emit!(PolicyCreated {
        policy: policy.key(),
        owner: policy.owner,
        agent_signer: policy.agent_signer,
        daily_limit,
        timestamp: clock.unix_timestamp,
    });

    msg!(
        "Policy created: owner={}, agent={}, limit={}",
        policy.owner,
        policy.agent_signer,
        daily_limit
    );

    Ok(())
}

/// Validate that whitelist mode and data are compatible
fn validate_whitelist_config(mode: &WhitelistMode, data: &WhitelistData) -> Result<()> {
    match (mode, data) {
        (WhitelistMode::None, WhitelistData::None) => Ok(()),
        (WhitelistMode::Merkle, WhitelistData::Merkle { .. }) => Ok(()),
        (WhitelistMode::Bloom, WhitelistData::Bloom { filter }) => {
            // Validate bloom filter configuration
            require!(
                !filter.bits.is_empty() && filter.bits.len() <= BLOOM_FILTER_SIZE_BYTES,
                X0GuardError::InvalidBloomFilter
            );
            require!(
                filter.hash_count > 0 && filter.hash_count <= 16,
                X0GuardError::InvalidBloomFilter
            );
            Ok(())
        }
        (WhitelistMode::Domain, WhitelistData::Domain { allowed_prefixes }) => {
            require!(
                !allowed_prefixes.is_empty() && allowed_prefixes.len() <= MAX_DOMAIN_PREFIXES,
                X0GuardError::InvalidWhitelistConfig
            );
            Ok(())
        }
        _ => Err(X0GuardError::InvalidWhitelistConfig.into()),
    }
}
