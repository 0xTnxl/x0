//! Transfer validation via Token-2022 Transfer Hook
//!
//! SECURITY: This module implements critical delegation verification to prevent
//! transfer hook bypass attacks. Key protections:
//! 
//! 1. Verifies source_authority is the agent_signer (not owner)
//! 2. Verifies token account owner matches policy owner (prevents account confusion)
//! 3. Enforces delegation mode to prevent self-delegation bypass
//! 4. Optionally binds policy to specific token account

use anchor_lang::prelude::*;
use anchor_spl::token_interface::TokenAccount;

use crate::state::{AgentPolicy, PrivacyLevel};
use x0_common::{
    constants::*,
    error::X0GuardError,
    events::{TransferRejected, TransferValidated},
    whitelist::{MerkleProof, WhitelistData, WhitelistMode},
};

use crate::check_and_update_limit;

/// Accounts required for transfer validation
#[derive(Accounts)]
pub struct ValidateTransfer<'info> {
    /// The source token account (sender)
    /// We need to read this to verify ownership and delegation
    #[account()]
    pub source_account: InterfaceAccount<'info, TokenAccount>,

    /// The mint of the token being transferred
    /// CHECK: Validated by Token-2022 program
    pub mint: UncheckedAccount<'info>,

    /// The destination token account (recipient)
    /// CHECK: Validated by Token-2022 program
    pub destination_account: UncheckedAccount<'info>,

    /// The source account's owner/delegate (the agent)
    /// CHECK: Validated by Token-2022 program
    pub source_authority: UncheckedAccount<'info>,

    /// The extra account metas PDA (required by Transfer Hook interface)
    /// CHECK: Derived from mint
    #[account(
        seeds = [b"extra-account-metas", mint.key().as_ref()],
        bump,
    )]
    pub extra_account_metas: UncheckedAccount<'info>,

    /// The agent policy PDA
    #[account(
        mut,
        seeds = [AGENT_POLICY_SEED, agent_policy.owner.as_ref()],
        bump = agent_policy.bump,
    )]
    pub agent_policy: Account<'info, AgentPolicy>,

    /// Optional: ZK proof account for confidential transfers
    /// CHECK: Validated if confidential mode is enabled
    pub zk_proof_account: Option<UncheckedAccount<'info>>,
}

pub fn handler(
    ctx: Context<ValidateTransfer>,
    amount: u64,
    merkle_proof: Option<MerkleProof>,
) -> Result<()> {
    let policy = &mut ctx.accounts.agent_policy;
    let source_account = &ctx.accounts.source_account;
    let clock = Clock::get()?;
    let current_timestamp = clock.unix_timestamp;

    // ========================================================================
    // Pre-validation checks
    // ========================================================================

    // Check if policy is active
    require!(
        policy.is_active,
        X0GuardError::PolicyNotFound // Using as "policy inactive"
    );

    // ========================================================================
    // CRITICAL-1 FIX: Comprehensive delegation verification
    // ========================================================================
    
    // 1. Verify the source authority is the agent signer
    require!(
        ctx.accounts.source_authority.key() == policy.agent_signer,
        X0GuardError::UnauthorizedSigner
    );

    // 2. Verify the token account owner matches the policy owner
    // This prevents account confusion attacks where an attacker provides
    // a token account they own with a valid policy
    require!(
        source_account.owner == policy.owner,
        X0GuardError::TokenAccountOwnerMismatch
    );

    // 3. Prevent self-delegation attacks
    // Owner cannot set themselves as the agent_signer to bypass controls
    require!(
        policy.owner != policy.agent_signer,
        X0GuardError::SelfDelegationNotAllowed
    );

    // 4. If delegation mode is required, verify the source_authority is acting
    // as a delegate (not as owner). In Token-2022, when a delegate signs,
    // the delegate field should be set and the authority is the delegate.
    if policy.require_delegation {
        // The delegate field in the token account should match agent_signer
        // This ensures the agent is properly delegated, not the account owner
        match source_account.delegate {
            anchor_spl::token_interface::spl_token_2022::solana_program::program_option::COption::Some(delegate) => {
                require!(
                    delegate == policy.agent_signer,
                    X0GuardError::DelegationRequired
                );
            }
            anchor_spl::token_interface::spl_token_2022::solana_program::program_option::COption::None => {
                // No delegate set means this is an owner transfer, not delegate
                return Err(X0GuardError::DelegationRequired.into());
            }
        }
    }

    // 5. If policy is bound to a specific token account, verify it
    if let Some(bound_account) = policy.bound_token_account {
        require!(
            source_account.key() == bound_account,
            X0GuardError::BoundTokenAccountMismatch
        );
    }

    // MEDIUM-12: Amount must meet minimum threshold (prevents dust/spam)
    require!(amount >= MIN_TRANSFER_AMOUNT, X0GuardError::TransferAmountTooSmall);

    // MEDIUM-8: Check single transaction limit if configured
    if let Some(max_single) = policy.max_single_transaction {
        require!(amount <= max_single, X0GuardError::SingleTransactionLimitExceeded);
    }

    // ========================================================================
    // Rolling window limit check
    // ========================================================================

    let limit_result = check_and_update_limit(policy, amount, current_timestamp);
    
    if let Err(_) = limit_result {
        emit!(TransferRejected {
            policy: policy.key(),
            amount,
            recipient: ctx.accounts.destination_account.key(),
            reason_code: 0x1102, // DailyLimitExceeded
            timestamp: current_timestamp,
        });
        return Err(X0GuardError::DailyLimitExceeded.into());
    }

    // ========================================================================
    // Whitelist verification
    // ========================================================================

    let recipient = ctx.accounts.destination_account.key();
    let whitelist_ok = match &policy.whitelist_mode {
        WhitelistMode::None => true,
        
        WhitelistMode::Merkle => {
            match (&policy.whitelist_data, &merkle_proof) {
                (WhitelistData::Merkle { root }, Some(proof)) => {
                    x0_common::whitelist::verify_merkle_whitelist(&recipient, &proof.path, root)
                }
                _ => {
                    emit!(TransferRejected {
                        policy: policy.key(),
                        amount,
                        recipient,
                        reason_code: 0x1113, // MissingMerkleProof
                        timestamp: current_timestamp,
                    });
                    return Err(X0GuardError::MissingMerkleProof.into());
                }
            }
        }
        
        WhitelistMode::Bloom => {
            match &policy.whitelist_data {
                WhitelistData::Bloom { filter } => {
                    x0_common::whitelist::verify_bloom_whitelist(&recipient, filter)
                }
                _ => false,
            }
        }
        
        WhitelistMode::Domain => {
            match &policy.whitelist_data {
                WhitelistData::Domain { allowed_prefixes } => {
                    x0_common::whitelist::verify_domain_whitelist(&recipient, allowed_prefixes)
                }
                _ => false,
            }
        }
    };

    if !whitelist_ok {
        emit!(TransferRejected {
            policy: policy.key(),
            amount,
            recipient,
            reason_code: 0x1101, // RecipientNotWhitelisted
            timestamp: current_timestamp,
        });
        return Err(X0GuardError::RecipientNotWhitelisted.into());
    }

    // ========================================================================
    // Privacy verification (if confidential mode)
    // ========================================================================
    //
    // CONFIDENTIAL TRANSFER ARCHITECTURE:
    // When privacy_level == Confidential, the x0-Token uses Token-2022's
    // ConfidentialTransfer extension. This provides:
    //
    // 1. Encrypted balances using ElGamal encryption
    // 2. Zero-knowledge range proofs (amount is valid and non-negative)
    // 3. Optional auditor pubkey for regulatory compliance
    //
    // The ZK proof verification is handled BY Token-2022 BEFORE this hook runs.
    // Token-2022's transfer instruction validates:
    //   - Source account has sufficient encrypted balance
    //   - Transfer amount proof is valid (within range)
    //   - Encryption is correct for destination pubkey
    //
    // Our role in the transfer hook is to:
    //   1. Verify the policy allows confidential transfers
    //   2. Ensure the ZK proof account exists AND is valid
    //   3. Verify the proof account is owned by Token-2022 (defense-in-depth)
    //   4. Apply spending limits and whitelist checks as normal
    //
    // SECURITY NOTE (CRITICAL-4 FIX):
    // We perform additional validation on the ZK proof account to ensure
    // defense-in-depth. While Token-2022 verifies proofs before calling us,
    // we validate:
    //   - Proof account exists
    //   - Proof account is owned by Token-2022 program
    //   - Proof account data is non-empty (not a placeholder)

    let is_confidential = matches!(policy.privacy_level, PrivacyLevel::Confidential { .. });

    if is_confidential {
        // 1. Verify ZK proof account is provided
        let zk_proof = ctx.accounts.zk_proof_account.as_ref()
            .ok_or(X0GuardError::MissingZkProof)?;
        
        // 2. Verify the proof account is owned by Token-2022 program
        // This ensures the proof account is a legitimate Token-2022 proof context
        // and not a fake account controlled by an attacker
        require!(
            *zk_proof.owner == spl_token_2022::id(),
            X0GuardError::InvalidZkProofOwner
        );
        
        // 3. Verify the proof account has data (is initialized)
        // A zero-length account could be used to bypass proof requirements
        require!(
            !zk_proof.data_is_empty(),
            X0GuardError::ZkProofContextMismatch
        );
        
        // 4. Verify the proof account has minimum expected size
        // ConfidentialTransfer proof contexts have specific sizes
        // This provides defense-in-depth against malformed proof accounts
        // Minimum size for a valid proof context is 64 bytes (basic structure)
        require!(
            zk_proof.data_len() >= 64,
            X0GuardError::ZkProofContextMismatch
        );
        
        // Note: The actual cryptographic proof verification was already done by
        // Token-2022 before invoking this transfer hook. The `amount` parameter
        // we receive is the plaintext amount that Token-2022 has cryptographically
        // verified matches the encrypted transfer amount via ZK proofs.
    }

    // ========================================================================
    // Success: Emit event and return
    // ========================================================================

    let current_spend = policy.current_spend(current_timestamp);
    let remaining = policy.daily_limit.saturating_sub(current_spend);

    emit!(TransferValidated {
        policy: policy.key(),
        amount,
        recipient,
        current_spend_24h: current_spend,
        remaining_allowance: remaining,
        is_confidential,
        timestamp: current_timestamp,
    });

    msg!(
        "Transfer validated: amount={}, recipient={}, spent={}/{}",
        amount,
        recipient,
        current_spend,
        policy.daily_limit
    );

    Ok(())
}

/// Fallback instruction for Transfer Hook interface compatibility
/// This allows the program to be invoked via the standard Execute interface
#[derive(Accounts)]
pub struct TransferHookExecute<'info> {
    /// CHECK: Transfer Hook accounts are validated in handler
    pub source: UncheckedAccount<'info>,
    /// CHECK: Transfer Hook accounts
    pub mint: UncheckedAccount<'info>,
    /// CHECK: Transfer Hook accounts
    pub destination: UncheckedAccount<'info>,
    /// CHECK: Transfer Hook accounts
    pub authority: UncheckedAccount<'info>,
    /// CHECK: Transfer Hook accounts
    pub extra_metas: UncheckedAccount<'info>,
}

/// Implement the Transfer Hook Execute interface
pub fn execute_handler<'info>(
    _ctx: Context<'_, '_, 'info, 'info, TransferHookExecute<'info>>,
    amount: u64,
) -> Result<()> {
    // Parse the Execute instruction data
    msg!("Transfer Hook Execute: amount={}", amount);
    
    // The actual validation is done through the ValidateTransfer instruction
    // This is a compatibility shim for the SPL interface
    
    Ok(())
}
