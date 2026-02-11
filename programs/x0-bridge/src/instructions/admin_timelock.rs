//! Timelocked admin operations for the bridge
//!
//! Sensitive bridge operations require a 48-hour waiting period before
//! execution. This gives token holders and users time to react to
//! suspicious admin activity.
//!
//! # Timelocked Operations
//! - AddEvmContract: Add a new EVM lock contract to the whitelist
//! - RemoveEvmContract: Remove an EVM lock contract from the whitelist
//! - AddDomain: Add a new Hyperlane domain
//! - RemoveDomain: Remove a Hyperlane domain
//! - UpdateSp1Verifier: Update the SP1 verifier program (rare)
//!
//! # Non-Timelocked Operations
//! - Pause/Unpause: Needed for emergencies, remains instant
//!
//! # Workflow
//! 1. Admin calls `schedule_*` to create a BridgeAdminAction PDA
//! 2. 48 hours must pass
//! 3. Admin calls `execute_admin_action` to apply the change
//! 4. Optionally, admin can `cancel_admin_action` during the waiting period

use anchor_lang::prelude::*;

use crate::state::{BridgeAdminAction, BridgeAdminActionType, BridgeConfig};
use x0_common::{
    constants::*,
    error::X0BridgeError,
    events::{
        BridgeAdminActionScheduled, BridgeAdminActionExecuted, 
        BridgeAdminActionCancelled, BridgeContractUpdated,
    },
};

// ============================================================================
// Schedule Admin Action
// ============================================================================

#[derive(Accounts)]
pub struct ScheduleAdminAction<'info> {
    /// The bridge admin
    #[account(mut)]
    pub admin: Signer<'info>,

    /// Bridge configuration
    #[account(
        mut,
        seeds = [BRIDGE_CONFIG_SEED],
        bump = config.bump,
        constraint = config.admin == admin.key() @ X0BridgeError::Unauthorized,
    )]
    pub config: Box<Account<'info, BridgeConfig>>,

    /// The admin action PDA to create
    #[account(
        init,
        payer = admin,
        space = BridgeAdminAction::space(),
        seeds = [
            BRIDGE_ADMIN_ACTION_SEED,
            &config.admin_action_nonce.to_le_bytes(),
        ],
        bump,
    )]
    pub admin_action: Box<Account<'info, BridgeAdminAction>>,

    /// System program
    pub system_program: Program<'info, System>,
}

/// Schedule adding an EVM contract to the allowed list (48h timelock)
pub fn schedule_add_evm_contract(
    ctx: Context<ScheduleAdminAction>,
    evm_contract: [u8; 20],
) -> Result<()> {
    let clock = Clock::get()?;
    let config = &mut ctx.accounts.config;
    let action = &mut ctx.accounts.admin_action;

    // Validate contract not already in list
    require!(
        !config.is_contract_allowed(&evm_contract),
        X0BridgeError::TooManyEVMContracts // Reuse: already exists
    );

    // Validate capacity
    require!(
        config.allowed_evm_contracts.len() < MAX_ALLOWED_EVM_CONTRACTS,
        X0BridgeError::TooManyEVMContracts
    );

    // Initialize action
    let nonce = config.admin_action_nonce;
    action.nonce = nonce;
    action.action_type = BridgeAdminActionType::AddEvmContract;
    action.scheduled_at = clock.unix_timestamp + BRIDGE_ADMIN_TIMELOCK_SECONDS;
    action.evm_contract = evm_contract;
    action.domain = 0;
    action.new_address = Pubkey::default();
    action.scheduled_by = ctx.accounts.admin.key();
    action.executed = false;
    action.cancelled = false;
    action.bump = ctx.bumps.admin_action;
    action._reserved = [0u8; 32];

    // Increment nonce
    config.admin_action_nonce = config
        .admin_action_nonce
        .checked_add(1)
        .ok_or(X0BridgeError::MathOverflow)?;

    emit!(BridgeAdminActionScheduled {
        action_pda: action.key(),
        nonce,
        action_type: 0, // AddEvmContract
        scheduled_at: action.scheduled_at,
        evm_contract,
        domain: 0,
        admin: ctx.accounts.admin.key(),
        timestamp: clock.unix_timestamp,
    });

    msg!(
        "Scheduled AddEvmContract: contract=0x{}, executes_at={}",
        hex::encode(evm_contract),
        action.scheduled_at,
    );

    Ok(())
}

/// Schedule removing an EVM contract from the allowed list (48h timelock)
pub fn schedule_remove_evm_contract(
    ctx: Context<ScheduleAdminAction>,
    evm_contract: [u8; 20],
) -> Result<()> {
    let clock = Clock::get()?;
    let config = &mut ctx.accounts.config;
    let action = &mut ctx.accounts.admin_action;

    // Validate contract is in list
    require!(
        config.is_contract_allowed(&evm_contract),
        X0BridgeError::MessageNotFound // Reuse: not found
    );

    // Initialize action
    let nonce = config.admin_action_nonce;
    action.nonce = nonce;
    action.action_type = BridgeAdminActionType::RemoveEvmContract;
    action.scheduled_at = clock.unix_timestamp + BRIDGE_ADMIN_TIMELOCK_SECONDS;
    action.evm_contract = evm_contract;
    action.domain = 0;
    action.new_address = Pubkey::default();
    action.scheduled_by = ctx.accounts.admin.key();
    action.executed = false;
    action.cancelled = false;
    action.bump = ctx.bumps.admin_action;
    action._reserved = [0u8; 32];

    // Increment nonce
    config.admin_action_nonce = config
        .admin_action_nonce
        .checked_add(1)
        .ok_or(X0BridgeError::MathOverflow)?;

    emit!(BridgeAdminActionScheduled {
        action_pda: action.key(),
        nonce,
        action_type: 1, // RemoveEvmContract
        scheduled_at: action.scheduled_at,
        evm_contract,
        domain: 0,
        admin: ctx.accounts.admin.key(),
        timestamp: clock.unix_timestamp,
    });

    msg!(
        "Scheduled RemoveEvmContract: contract=0x{}, executes_at={}",
        hex::encode(evm_contract),
        action.scheduled_at,
    );

    Ok(())
}

/// Schedule adding a Hyperlane domain (48h timelock)
pub fn schedule_add_domain(
    ctx: Context<ScheduleAdminAction>,
    domain: u32,
) -> Result<()> {
    let clock = Clock::get()?;
    let config = &mut ctx.accounts.config;
    let action = &mut ctx.accounts.admin_action;

    // Validate domain not already supported
    require!(
        !config.is_domain_supported(domain),
        X0BridgeError::TooManySupportedDomains // Reuse: already exists
    );

    // Validate capacity
    require!(
        config.supported_domains.len() < MAX_SUPPORTED_DOMAINS,
        X0BridgeError::TooManySupportedDomains
    );

    // Initialize action
    let nonce = config.admin_action_nonce;
    action.nonce = nonce;
    action.action_type = BridgeAdminActionType::AddDomain;
    action.scheduled_at = clock.unix_timestamp + BRIDGE_ADMIN_TIMELOCK_SECONDS;
    action.evm_contract = [0u8; 20];
    action.domain = domain;
    action.new_address = Pubkey::default();
    action.scheduled_by = ctx.accounts.admin.key();
    action.executed = false;
    action.cancelled = false;
    action.bump = ctx.bumps.admin_action;
    action._reserved = [0u8; 32];

    // Increment nonce
    config.admin_action_nonce = config
        .admin_action_nonce
        .checked_add(1)
        .ok_or(X0BridgeError::MathOverflow)?;

    emit!(BridgeAdminActionScheduled {
        action_pda: action.key(),
        nonce,
        action_type: 2, // AddDomain
        scheduled_at: action.scheduled_at,
        evm_contract: [0u8; 20],
        domain,
        admin: ctx.accounts.admin.key(),
        timestamp: clock.unix_timestamp,
    });

    msg!(
        "Scheduled AddDomain: domain={}, executes_at={}",
        domain,
        action.scheduled_at,
    );

    Ok(())
}

/// Schedule removing a Hyperlane domain (48h timelock)
pub fn schedule_remove_domain(
    ctx: Context<ScheduleAdminAction>,
    domain: u32,
) -> Result<()> {
    let clock = Clock::get()?;
    let config = &mut ctx.accounts.config;
    let action = &mut ctx.accounts.admin_action;

    // Validate domain is currently supported
    require!(
        config.is_domain_supported(domain),
        X0BridgeError::UnsupportedDomain
    );

    // Initialize action
    let nonce = config.admin_action_nonce;
    action.nonce = nonce;
    action.action_type = BridgeAdminActionType::RemoveDomain;
    action.scheduled_at = clock.unix_timestamp + BRIDGE_ADMIN_TIMELOCK_SECONDS;
    action.evm_contract = [0u8; 20];
    action.domain = domain;
    action.new_address = Pubkey::default();
    action.scheduled_by = ctx.accounts.admin.key();
    action.executed = false;
    action.cancelled = false;
    action.bump = ctx.bumps.admin_action;
    action._reserved = [0u8; 32];

    // Increment nonce
    config.admin_action_nonce = config
        .admin_action_nonce
        .checked_add(1)
        .ok_or(X0BridgeError::MathOverflow)?;

    emit!(BridgeAdminActionScheduled {
        action_pda: action.key(),
        nonce,
        action_type: 3, // RemoveDomain
        scheduled_at: action.scheduled_at,
        evm_contract: [0u8; 20],
        domain,
        admin: ctx.accounts.admin.key(),
        timestamp: clock.unix_timestamp,
    });

    msg!(
        "Scheduled RemoveDomain: domain={}, executes_at={}",
        domain,
        action.scheduled_at,
    );

    Ok(())
}

// ============================================================================
// Execute Admin Action
// ============================================================================

#[derive(Accounts)]
#[instruction(nonce: u64)]
pub struct ExecuteAdminAction<'info> {
    /// The bridge admin
    pub admin: Signer<'info>,

    /// Bridge configuration
    #[account(
        mut,
        seeds = [BRIDGE_CONFIG_SEED],
        bump = config.bump,
        constraint = config.admin == admin.key() @ X0BridgeError::Unauthorized,
    )]
    pub config: Box<Account<'info, BridgeConfig>>,

    /// The admin action PDA to execute
    #[account(
        mut,
        seeds = [BRIDGE_ADMIN_ACTION_SEED, &nonce.to_le_bytes()],
        bump = admin_action.bump,
        constraint = !admin_action.executed @ X0BridgeError::AdminActionAlreadyExecuted,
        constraint = !admin_action.cancelled @ X0BridgeError::AdminActionCancelled,
    )]
    pub admin_action: Box<Account<'info, BridgeAdminAction>>,
}

/// Execute a previously scheduled admin action after timelock expires
pub fn execute_admin_action(
    ctx: Context<ExecuteAdminAction>,
    nonce: u64,
) -> Result<()> {
    let clock = Clock::get()?;
    let config = &mut ctx.accounts.config;
    let action = &mut ctx.accounts.admin_action;

    // Verify nonce matches
    require!(
        action.nonce == nonce,
        X0BridgeError::InvalidActionNonce
    );

    // Verify timelock has expired
    require!(
        action.is_ready(clock.unix_timestamp),
        X0BridgeError::TimelockNotExpired
    );

    // Execute action based on type
    let action_type_byte: u8 = match action.action_type {
        BridgeAdminActionType::AddEvmContract => {
            // Re-validate capacity (may have changed since scheduling)
            require!(
                config.allowed_evm_contracts.len() < MAX_ALLOWED_EVM_CONTRACTS,
                X0BridgeError::TooManyEVMContracts
            );
            // Re-validate not already added
            require!(
                !config.is_contract_allowed(&action.evm_contract),
                X0BridgeError::TooManyEVMContracts
            );
            
            config.allowed_evm_contracts.push(action.evm_contract);
            
            emit!(BridgeContractUpdated {
                config: config.key(),
                evm_contract: action.evm_contract,
                added: true,
                admin: ctx.accounts.admin.key(),
                timestamp: clock.unix_timestamp,
            });
            
            msg!("Executed: Added EVM contract 0x{}", hex::encode(action.evm_contract));
            0
        }
        BridgeAdminActionType::RemoveEvmContract => {
            let initial_len = config.allowed_evm_contracts.len();
            config.allowed_evm_contracts.retain(|c| c != &action.evm_contract);
            
            require!(
                config.allowed_evm_contracts.len() < initial_len,
                X0BridgeError::MessageNotFound
            );
            
            emit!(BridgeContractUpdated {
                config: config.key(),
                evm_contract: action.evm_contract,
                added: false,
                admin: ctx.accounts.admin.key(),
                timestamp: clock.unix_timestamp,
            });
            
            msg!("Executed: Removed EVM contract 0x{}", hex::encode(action.evm_contract));
            1
        }
        BridgeAdminActionType::AddDomain => {
            require!(
                config.supported_domains.len() < MAX_SUPPORTED_DOMAINS,
                X0BridgeError::TooManySupportedDomains
            );
            require!(
                !config.is_domain_supported(action.domain),
                X0BridgeError::TooManySupportedDomains
            );
            
            config.supported_domains.push(action.domain);
            msg!("Executed: Added domain {}", action.domain);
            2
        }
        BridgeAdminActionType::RemoveDomain => {
            let initial_len = config.supported_domains.len();
            config.supported_domains.retain(|d| *d != action.domain);
            
            require!(
                config.supported_domains.len() < initial_len,
                X0BridgeError::UnsupportedDomain
            );
            
            msg!("Executed: Removed domain {}", action.domain);
            3
        }
        BridgeAdminActionType::UpdateSp1Verifier => {
            config.sp1_verifier = action.new_address;
            msg!("Executed: Updated SP1 verifier to {}", action.new_address);
            4
        }
    };

    // Mark action as executed
    action.executed = true;

    emit!(BridgeAdminActionExecuted {
        action_pda: action.key(),
        nonce,
        action_type: action_type_byte,
        admin: ctx.accounts.admin.key(),
        timestamp: clock.unix_timestamp,
    });

    Ok(())
}

// ============================================================================
// Cancel Admin Action
// ============================================================================

#[derive(Accounts)]
#[instruction(nonce: u64)]
pub struct CancelAdminAction<'info> {
    /// The bridge admin
    pub admin: Signer<'info>,

    /// Bridge configuration (for admin verification)
    #[account(
        seeds = [BRIDGE_CONFIG_SEED],
        bump = config.bump,
        constraint = config.admin == admin.key() @ X0BridgeError::Unauthorized,
    )]
    pub config: Box<Account<'info, BridgeConfig>>,

    /// The admin action PDA to cancel
    #[account(
        mut,
        seeds = [BRIDGE_ADMIN_ACTION_SEED, &nonce.to_le_bytes()],
        bump = admin_action.bump,
        constraint = !admin_action.executed @ X0BridgeError::AdminActionAlreadyExecuted,
        constraint = !admin_action.cancelled @ X0BridgeError::AdminActionCancelled,
    )]
    pub admin_action: Box<Account<'info, BridgeAdminAction>>,
}

/// Cancel a previously scheduled admin action
pub fn cancel_admin_action(
    ctx: Context<CancelAdminAction>,
    nonce: u64,
) -> Result<()> {
    let clock = Clock::get()?;
    let action = &mut ctx.accounts.admin_action;

    // Verify nonce matches
    require!(
        action.nonce == nonce,
        X0BridgeError::InvalidActionNonce
    );

    let action_type_byte: u8 = match action.action_type {
        BridgeAdminActionType::AddEvmContract => 0,
        BridgeAdminActionType::RemoveEvmContract => 1,
        BridgeAdminActionType::AddDomain => 2,
        BridgeAdminActionType::RemoveDomain => 3,
        BridgeAdminActionType::UpdateSp1Verifier => 4,
    };

    // Mark action as cancelled
    action.cancelled = true;

    emit!(BridgeAdminActionCancelled {
        action_pda: action.key(),
        nonce,
        action_type: action_type_byte,
        admin: ctx.accounts.admin.key(),
        timestamp: clock.unix_timestamp,
    });

    msg!("Cancelled admin action: nonce={}", nonce);

    Ok(())
}
