//! x0-bridge: Cross-chain bridge receiver for Base → Solana
//!
//! Receives USDC lock proofs from Base via Hyperlane and mints x0-USD
//! on Solana via CPI to x0-wrapper, maintaining the reserve invariant.
//!
//! # Architecture
//!
//! ```text
//! Base (EVM)                         Solana
//! ┌──────────────────┐              ┌───────────────────────────┐
//! │ X0LockContract   │              │ x0-bridge                 │
//! │                  │  Hyperlane   │                           │
//! │ lock(USDC)       │ ─────────►  │ 1. handle_message()       │
//! │ → dispatch()     │  Relayer    │    → BridgeMessage PDA    │
//! └──────────────────┘              │                           │
//!                                   │ 2. verify_evm_proof()     │
//!             SP1 Prover            │    → EVMProofContext PDA  │
//!             (off-chain)           │                           │
//!                                   │ 3. execute_mint()         │
//!                                   │    → CPI x0-wrapper       │
//!                                   │    → x0-USD to recipient  │
//!                                   └───────────────────────────┘
//! ```
//!
//! # Security
//!
//! - Hyperlane ISM validates message delivery (signatures, replay protection)
//! - SP1 STARK proofs cryptographically verify EVM state (block, tx, receipt)
//! - Two-step verification prevents compute budget exhaustion
//! - Rate limiting prevents bridge flooding
//! - Whitelisted EVM contracts prevent unauthorized lock sources
//! - CPI to x0-wrapper maintains 1:1 USDC reserve invariant

#![allow(unexpected_cfgs)]
#![allow(ambiguous_glob_reexports)]

use anchor_lang::prelude::*;

pub mod instructions;
pub mod state;

pub use instructions::*;
pub use state::*;

declare_id!("4FuyKfQysHxcTeNJtz5rBzzS8kmjn2DdkgXH1Q7edXa7");

#[program]
pub mod x0_bridge {
    use super::*;

    // ========================================================================
    // Initialization (three-step: create_config + create_reserve + initialize)
    // ========================================================================

    /// Step 1: Allocate the BridgeConfig PDA.
    ///
    /// Split from `initialize` to avoid SBF's 4096-byte stack limit.
    /// All three steps can be packed into a single transaction.
    pub fn create_config(ctx: Context<CreateConfig>) -> Result<()> {
        instructions::initialize::create_config_handler(ctx)
    }

    /// Step 2: Create the bridge USDC reserve token account.
    pub fn create_reserve(ctx: Context<CreateReserve>) -> Result<()> {
        instructions::initialize::create_reserve_handler(ctx)
    }

    /// Step 3: Populate the bridge configuration.
    ///
    /// Sets up the bridge with:
    /// - Hyperlane mailbox address
    /// - SP1 verifier program address
    /// - x0-wrapper program for CPI minting
    /// - Initial whitelisted EVM contracts and supported domains
    ///
    /// Must be called by the initial admin (should be multisig).
    /// Requires `create_config` to have run first.
    pub fn initialize(
        ctx: Context<Initialize>,
        hyperlane_mailbox: Pubkey,
        sp1_verifier: Pubkey,
        wrapper_program: Pubkey,
        wrapper_config: Pubkey,
        wrapper_mint: Pubkey,
        allowed_evm_contracts: Vec<[u8; 20]>,
        supported_domains: Vec<u32>,
    ) -> Result<()> {
        instructions::initialize::handler(
            ctx,
            hyperlane_mailbox,
            sp1_verifier,
            wrapper_program,
            wrapper_config,
            wrapper_mint,
            allowed_evm_contracts,
            supported_domains,
        )
    }

    // ========================================================================
    // Hyperlane Message Reception (Step 1)
    // ========================================================================

    /// Handle an incoming Hyperlane message
    ///
    /// Called by the Hyperlane mailbox after ISM validation passes.
    /// Decodes the message body and creates a BridgeMessage PDA with
    /// status = Received.
    ///
    /// # Security
    /// - Validates caller is the Hyperlane mailbox process authority
    /// - Validates origin domain is supported
    /// - Validates sender is a whitelisted EVM lock contract
    /// - Validates amount within limits
    /// - Prevents replay via unique message_id PDA derivation
    pub fn handle_message(
        ctx: Context<HandleMessage>,
        origin: u32,
        sender: [u8; 32],
        message_body: Vec<u8>,
    ) -> Result<()> {
        instructions::handle_message::handler(ctx, origin, sender, message_body)
    }

    // ========================================================================
    // STARK Proof Verification (Step 2)
    // ========================================================================

    /// Verify a STARK proof for an EVM transaction
    ///
    /// Takes an SP1 proof and its public values, verifies it via the
    /// SP1 verifier program, and creates an EVMProofContext PDA linked
    /// to the corresponding BridgeMessage.
    ///
    /// This is a permissionless instruction — anyone (keeper, relayer) can
    /// submit valid proofs.
    ///
    /// # Arguments
    /// * `message_id` - The Hyperlane message ID to link the proof to
    /// * `proof` - The SP1 STARK proof bytes
    /// * `public_values` - The borsh-serialized SP1PublicInputs
    pub fn verify_evm_proof(
        ctx: Context<VerifyEVMProof>,
        message_id: [u8; 32],
        proof: Vec<u8>,
        public_values: Vec<u8>,
    ) -> Result<()> {
        instructions::verify_evm_proof::handler(ctx, message_id, proof, public_values)
    }

    // ========================================================================
    // Mint Execution (Step 3)
    // ========================================================================

    /// Execute the x0-USD mint for a verified bridge deposit
    ///
    /// Reads the verified EVMProofContext and BridgeMessage, then CPIs
    /// into x0-wrapper to deposit USDC from the bridge reserve and mint
    /// x0-USD to the recipient.
    ///
    /// This is a permissionless instruction — anyone (keeper, relayer) can
    /// execute mints for verified messages.
    ///
    /// # Security
    /// - Checks BridgeMessage status == ProofVerified
    /// - Checks EVMProofContext is fresh (within validity window)
    /// - Checks proof amount matches message amount
    /// - CPI to x0-wrapper maintains reserve invariant
    pub fn execute_mint(ctx: Context<ExecuteMint>) -> Result<()> {
        instructions::execute_mint::handler(ctx)
    }

    // ========================================================================
    // Admin Operations
    // ========================================================================

    /// Add an EVM contract to the allowed list
    pub fn add_allowed_contract(
        ctx: Context<AdminAction>,
        evm_contract: [u8; 20],
    ) -> Result<()> {
        instructions::admin::add_allowed_contract(ctx, evm_contract)
    }

    /// Remove an EVM contract from the allowed list
    pub fn remove_allowed_contract(
        ctx: Context<AdminAction>,
        evm_contract: [u8; 20],
    ) -> Result<()> {
        instructions::admin::remove_allowed_contract(ctx, evm_contract)
    }

    /// Add a supported Hyperlane domain
    pub fn add_supported_domain(
        ctx: Context<AdminAction>,
        domain: u32,
    ) -> Result<()> {
        instructions::admin::add_supported_domain(ctx, domain)
    }

    /// Pause or unpause the bridge
    pub fn set_paused(
        ctx: Context<AdminAction>,
        paused: bool,
    ) -> Result<()> {
        instructions::admin::set_paused(ctx, paused)
    }

    // ========================================================================
    // Timelocked Admin Operations (48h delay)
    // ========================================================================

    /// Schedule adding an EVM contract (48h timelock)
    pub fn schedule_add_evm_contract(
        ctx: Context<ScheduleAdminAction>,
        evm_contract: [u8; 20],
    ) -> Result<()> {
        instructions::admin_timelock::schedule_add_evm_contract(ctx, evm_contract)
    }

    /// Schedule removing an EVM contract (48h timelock)
    pub fn schedule_remove_evm_contract(
        ctx: Context<ScheduleAdminAction>,
        evm_contract: [u8; 20],
    ) -> Result<()> {
        instructions::admin_timelock::schedule_remove_evm_contract(ctx, evm_contract)
    }

    /// Schedule adding a Hyperlane domain (48h timelock)
    pub fn schedule_add_domain(
        ctx: Context<ScheduleAdminAction>,
        domain: u32,
    ) -> Result<()> {
        instructions::admin_timelock::schedule_add_domain(ctx, domain)
    }

    /// Schedule removing a Hyperlane domain (48h timelock)
    pub fn schedule_remove_domain(
        ctx: Context<ScheduleAdminAction>,
        domain: u32,
    ) -> Result<()> {
        instructions::admin_timelock::schedule_remove_domain(ctx, domain)
    }

    /// Execute a scheduled admin action (after 48h)
    pub fn execute_admin_action(
        ctx: Context<ExecuteAdminAction>,
        nonce: u64,
    ) -> Result<()> {
        instructions::admin_timelock::execute_admin_action(ctx, nonce)
    }

    /// Cancel a scheduled admin action
    pub fn cancel_admin_action(
        ctx: Context<CancelAdminAction>,
        nonce: u64,
    ) -> Result<()> {
        instructions::admin_timelock::cancel_admin_action(ctx, nonce)
    }

    /// Replenish the bridge USDC reserve
    ///
    /// Allows anyone to deposit USDC into the bridge's reserve account.
    /// This provides the liquidity needed for minting x0-USD via
    /// x0-wrapper CPI.
    pub fn replenish_reserve(
        ctx: Context<ReplenishReserve>,
        amount: u64,
    ) -> Result<()> {
        instructions::replenish_reserve::handler(ctx, amount)
    }
}
