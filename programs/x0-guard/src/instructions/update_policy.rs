//! Update an existing agent policy

use anchor_lang::prelude::*;
use crate::state::{AgentPolicy, PrivacyLevel};
use x0_common::{
    constants::*,
    error::X0GuardError,
    events::PolicyUpdated,
    utils::validate_daily_limit,
    whitelist::{WhitelistData, WhitelistMode},
};

/// Accounts for updating an agent policy
#[derive(Accounts)]
pub struct UpdatePolicy<'info> {
    /// The policy owner (must sign)
    #[account(
        constraint = owner.key() == agent_policy.owner @ X0GuardError::PolicyOwnerMismatch
    )]
    pub owner: Signer<'info>,

    /// The policy to update
    #[account(
        mut,
        seeds = [AGENT_POLICY_SEED, owner.key().as_ref()],
        bump = agent_policy.bump,
    )]
    pub agent_policy: Account<'info, AgentPolicy>,
}

pub fn handler(
    ctx: Context<UpdatePolicy>,
    new_daily_limit: Option<u64>,
    new_whitelist_mode: Option<WhitelistMode>,
    new_whitelist_data: Option<WhitelistData>,
    new_privacy_level: Option<PrivacyLevel>,
    new_auditor_key: Option<Pubkey>,
    new_max_single_transaction: Option<Option<u64>>, // MEDIUM-8: Optional single tx limit
) -> Result<()> {
    let policy = &mut ctx.accounts.agent_policy;
    let clock = Clock::get()?;

    // MEDIUM-2: Rate limit policy updates to prevent governance spam
    let current_slot = clock.slot;
    require!(
        current_slot >= policy.last_update_slot.saturating_add(POLICY_UPDATE_COOLDOWN_SLOTS),
        X0GuardError::PolicyUpdateTooFrequent
    );
    policy.last_update_slot = current_slot;

    // Update daily limit if provided
    if let Some(limit) = new_daily_limit {
        validate_daily_limit(limit)?;
        policy.daily_limit = limit;
    }

    // MEDIUM-8: Update single transaction limit if provided
    // Using Option<Option<u64>> to allow setting to None explicitly
    if let Some(max_single) = new_max_single_transaction {
        // Validate max_single doesn't exceed daily_limit if set
        if let Some(limit) = max_single {
            require!(limit <= policy.daily_limit, X0GuardError::SingleTransactionLimitExceeded);
        }
        policy.max_single_transaction = max_single;
    }

    // Update whitelist mode if provided
    if let Some(mode) = new_whitelist_mode {
        policy.whitelist_mode = mode;
    }

    // Update whitelist data if provided
    if let Some(data) = new_whitelist_data {
        // Validate mode and data are compatible
        validate_whitelist_config(&policy.whitelist_mode, &data)?;
        policy.whitelist_data = data;
    }

    // Update privacy level if provided
    if let Some(level) = new_privacy_level {
        policy.privacy_level = level;
    }

    // Update auditor key if provided (can be set to Some or None)
    if new_auditor_key.is_some() {
        policy.auditor_key = new_auditor_key;
    }

    // Emit event
    emit!(PolicyUpdated {
        policy: policy.key(),
        daily_limit: new_daily_limit,
        agent_signer: None,
        timestamp: clock.unix_timestamp,
    });

    msg!(
        "Policy updated: policy={}, limit={:?}",
        policy.key(),
        new_daily_limit
    );

    Ok(())
}

/// Validate that whitelist mode and data are compatible
fn validate_whitelist_config(mode: &WhitelistMode, data: &WhitelistData) -> Result<()> {
    match (mode, data) {
        (WhitelistMode::None, WhitelistData::None) => Ok(()),
        (WhitelistMode::Merkle, WhitelistData::Merkle { .. }) => Ok(()),
        (WhitelistMode::Bloom, WhitelistData::Bloom { filter }) => {
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
