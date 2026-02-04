//! x0-guard: On-chain firewall for agent spending policies
//!
//! This program serves as the cryptographic source of truth for all spending policies.
//! It manages PDAs for each agent and enforces:
//! - Rolling 24-hour spending limits
//! - Whitelist verification (Merkle, Bloom, Domain modes)
//! - Privacy level enforcement (Public vs Confidential)
//!
//! The guard is invoked via Token-2022's Transfer Hook mechanism for every transfer.

// Suppress cfg warnings from Anchor/Solana macros (toolchain version mismatch)
#![allow(unexpected_cfgs)]
// Suppress ambiguous glob re-export warnings (handlers have same name in different modules)
#![allow(ambiguous_glob_reexports)]

use anchor_lang::prelude::*;
use spl_transfer_hook_interface::instruction::TransferHookInstruction;
use solana_program::program_error::ProgramError;
use spl_token_2022::state::Account as SplTokenAccount;
use spl_token_2022::extension::StateWithExtensions;

pub mod instructions;
pub mod state;
pub mod transfer_hook;

pub use instructions::*;
pub use state::*;
pub use transfer_hook::*;

// Re-export common types
pub use x0_common::{
    constants::*, 
    error::X0GuardError, 
    events::*,
    whitelist::*,
};

// Export state types from this crate
pub use crate::state::{AgentPolicy, PrivacyLevel, SpendingEntry};

declare_id!("2uYGW3fQUGfhrwVbkupdasXBpRPfGYBGTLUdaPTXU9vP");

#[program]
pub mod x0_guard {
    use super::*;

    // ========================================================================
    // Policy Management Instructions
    // ========================================================================

    /// Initialize a new agent policy
    ///
    /// Creates a PDA to store the agent's spending policy, including:
    /// - Daily spending limit
    /// - Whitelist configuration
    /// - Privacy settings
    ///
    /// # Arguments
    /// * `daily_limit` - Maximum tokens spendable in 24h rolling window
    /// * `whitelist_mode` - How to verify recipients (Merkle/Bloom/Domain/None)
    /// * `privacy_level` - Public or Confidential transfers
    pub fn initialize_policy(
        ctx: Context<InitializePolicy>,
        daily_limit: u64,
        whitelist_mode: WhitelistMode,
        whitelist_data: WhitelistData,
        privacy_level: PrivacyLevel,
    ) -> Result<()> {
        instructions::initialize_policy::handler(
            ctx,
            daily_limit,
            whitelist_mode,
            whitelist_data,
            privacy_level,
        )
    }

    /// Update an existing agent policy
    ///
    /// Only the policy owner can update. Updates are applied immediately.
    /// MEDIUM-2: Rate limited to prevent governance spam attacks.
    pub fn update_policy(
        ctx: Context<UpdatePolicy>,
        new_daily_limit: Option<u64>,
        new_whitelist_mode: Option<WhitelistMode>,
        new_whitelist_data: Option<WhitelistData>,
        new_privacy_level: Option<PrivacyLevel>,
        new_auditor_key: Option<Pubkey>,
        new_max_single_transaction: Option<Option<u64>>, // MEDIUM-8: Single tx limit
    ) -> Result<()> {
        instructions::update_policy::handler(
            ctx,
            new_daily_limit,
            new_whitelist_mode,
            new_whitelist_data,
            new_privacy_level,
            new_auditor_key,
            new_max_single_transaction,
        )
    }

    /// Update the agent signer key
    ///
    /// Allows the owner to rotate the agent's hot-key.
    /// The old key is immediately invalidated.
    pub fn update_agent_signer(
        ctx: Context<UpdateAgentSigner>,
        new_agent_signer: Pubkey,
    ) -> Result<()> {
        instructions::update_agent_signer::handler(ctx, new_agent_signer)
    }

    /// Revoke the agent's authority
    ///
    /// Immediately invalidates the agent's hot-key, preventing further transactions.
    /// Used in case of key compromise.
    pub fn revoke_agent_authority(ctx: Context<RevokeAgentAuthority>) -> Result<()> {
        instructions::revoke_agent_authority::handler(ctx)
    }

    /// Pause or unpause the agent policy
    ///
    /// Paused policies reject all transfers.
    pub fn set_policy_active(ctx: Context<SetPolicyActive>, is_active: bool) -> Result<()> {
        instructions::set_policy_active::handler(ctx, is_active)
    }

    // ========================================================================
    // Transfer Hook Instructions (Called by Token-2022)
    // ========================================================================

    /// Validate a transfer (Transfer Hook entry point)
    ///
    /// This is called by the Token-2022 program via CPI for every transfer
    /// of x0-Tokens. It enforces all policy rules.
    pub fn validate_transfer(
        ctx: Context<ValidateTransfer>,
        amount: u64,
        merkle_proof: Option<MerkleProof>,
    ) -> Result<()> {
        transfer_hook::validate_transfer::handler(ctx, amount, merkle_proof)
    }

    /// Initialize extra account metas for transfer hook
    ///
    /// Required by SPL Transfer Hook interface. Sets up the additional
    /// accounts needed for the guard to validate transfers.
    pub fn initialize_extra_account_metas(
        ctx: Context<InitializeExtraAccountMetas>,
    ) -> Result<()> {
        transfer_hook::initialize_extra_metas::handler(ctx)
    }

    // ========================================================================
    // Blink Generation (Human-in-the-Loop)
    // ========================================================================

    /// Record a Blink generation event
    ///
    /// Called when an agent needs human approval. Rate-limited to prevent spam.
    pub fn record_blink(
        ctx: Context<RecordBlink>,
        amount: u64,
        recipient: Pubkey,
        reason: String,
    ) -> Result<()> {
        instructions::record_blink::handler(ctx, amount, recipient, reason)
    }

    // ========================================================================
    // View Functions (Read-only helpers)
    // ========================================================================

    /// Get the current 24h spend for an agent
    ///
    /// Returns (current_spend, remaining_allowance, oldest_entry_expiry)
    pub fn get_current_spend(ctx: Context<GetCurrentSpend>) -> Result<(u64, u64, i64)> {
        instructions::get_current_spend::handler(ctx)
    }

    // ========================================================================
    // Transfer Hook Fallback (SPL Interface Compatibility)
    // ========================================================================
    
    /// Fallback handler for SPL Transfer Hook interface
    ///
    /// Token-2022's Transfer Hook uses a specific instruction format that doesn't
    /// match Anchor's discriminator format. This fallback catches those calls.
    pub fn fallback<'info>(
        _program_id: &Pubkey,
        accounts: &'info [AccountInfo<'info>],
        data: &[u8],
    ) -> Result<()> {
        // Parse the transfer hook instruction
        let instruction = TransferHookInstruction::unpack(data)
            .map_err(|_| ProgramError::InvalidInstructionData)?;

        match instruction {
            TransferHookInstruction::Execute { amount } => {
                // Validate we have enough accounts
                // Execute expects: source, mint, dest, authority, extra_metas, [additional...]
                if accounts.len() < 6 {
                    return Err(ProgramError::NotEnoughAccountKeys.into());
                }

                let source_info = &accounts[0];
                let _mint_info = &accounts[1];
                let _dest_info = &accounts[2];
                let authority_info = &accounts[3];
                let _extra_metas_info = &accounts[4];
                let policy_info = &accounts[5];

                // Deserialize the source token account using SPL Token-2022's StateWithExtensions
                let source_data = source_info.try_borrow_data()?;
                let source_account = StateWithExtensions::<SplTokenAccount>::unpack(&source_data)
                    .map_err(|_| ProgramError::InvalidAccountData)?;

                // The authority should be the delegate (agent signer)
                let agent_signer = authority_info.key;

                // Deserialize and validate the policy
                let mut policy_data = policy_info.try_borrow_mut_data()?;
                
                // Anchor accounts have 8-byte discriminator
                if policy_data.len() < 8 {
                    return Err(ProgramError::InvalidAccountData.into());
                }
                let policy = AgentPolicy::try_deserialize(&mut policy_data.as_ref())
                    .map_err(|_| ProgramError::InvalidAccountData)?;

                // Validate policy is active (using PolicyNotFound as inactive indicator)
                require!(policy.is_active, X0GuardError::PolicyNotFound);

                // Validate agent signer matches
                require!(
                    *agent_signer == policy.agent_signer,
                    X0GuardError::UnauthorizedSigner
                );

                // Validate source account owner matches policy owner
                // Use .base to access the core token account data
                require!(
                    source_account.base.owner == policy.owner,
                    X0GuardError::UnauthorizedSigner
                );

                // Check rolling spend limit
                let clock = Clock::get()?;
                let mut policy_mut = AgentPolicy::try_deserialize(&mut policy_data.as_ref())
                    .map_err(|_| ProgramError::InvalidAccountData)?;
                
                check_and_update_limit(&mut policy_mut, amount, clock.unix_timestamp)?;
                
                // Serialize back the updated policy
                policy_mut.try_serialize(&mut policy_data.as_mut())?;

                msg!("Transfer validated: {} tokens", amount);
                Ok(())
            }
            _ => {
                // Other transfer hook instructions (like InitializeExtraAccountMetas)
                // are handled by the normal Anchor instruction routing
                Err(ProgramError::InvalidInstructionData.into())
            }
        }
    }
}

// ============================================================================
// Shared Validation Helpers
// ============================================================================

/// Check and update the rolling spend window
///
/// MEDIUM-1 FIX: Removes old entries FIRST using retain(), then checks space
/// before adding new entry. This prevents temporary size overflow and uses
/// efficient O(n) retain instead of O(n²) repeated remove(0).
pub fn check_and_update_limit(
    policy: &mut AgentPolicy,
    amount: u64,
    current_timestamp: i64,
) -> Result<()> {
    // MEDIUM-1: Remove entries older than 24 hours FIRST
    let cutoff = current_timestamp - ROLLING_WINDOW_SECONDS;
    policy.rolling_window.retain(|entry| entry.timestamp > cutoff);

    // Calculate current 24h spend using saturating arithmetic (CRITICAL-3)
    let current_spend: u64 = policy
        .rolling_window
        .iter()
        .fold(0u64, |acc, entry| acc.saturating_add(entry.amount));

    // Check limit
    require!(
        current_spend.saturating_add(amount) <= policy.daily_limit,
        X0GuardError::DailyLimitExceeded
    );

    // MEDIUM-1: Check space BEFORE adding (prevents temporary overflow)
    require!(
        policy.rolling_window.len() < MAX_ROLLING_WINDOW_ENTRIES,
        X0GuardError::RollingWindowOverflow
    );

    // Add new entry (safe now that we've verified space)
    policy.rolling_window.push(SpendingEntry {
        amount,
        timestamp: current_timestamp,
    });

    Ok(())
}
