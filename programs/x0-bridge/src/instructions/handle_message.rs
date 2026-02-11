//! Handle incoming Hyperlane message (Step 1)
//!
//! This instruction is called by the Hyperlane mailbox after ISM validation.
//! It decodes the message body and creates a BridgeMessage PDA.
//!
//! # Hyperlane Integration
//!
//! On Sealevel (Solana), Hyperlane's mailbox calls the recipient program
//! with three arguments: origin domain, sender address, and message body.
//! The mailbox process authority PDA must be the caller.
//!
//! # Security: Process Authority Validation
//!
//! The `process_authority` MUST be a PDA derived from the Hyperlane mailbox
//! program using these seeds:
//!   ["hyperlane", "-", "process_authority", "-", <this_program_id>]
//!
//! This ensures only the legitimate Hyperlane mailbox can call this instruction.
//! Without this check, anyone could forge messages.
//!
//! # Message Body Format
//!
//! The message body is encoded by the EVM lock contract:
//! ```text
//! [0..32]   recipient:    Solana pubkey
//! [32..40]  amount:       uint64 big-endian
//! [40..72]  evm_tx_hash:  bytes32
//! [72..80]  nonce:        uint64 big-endian
//! ```

use anchor_lang::prelude::*;

use crate::state::{BridgeConfig, BridgeMessage, BridgeMessageBody, BridgeMessageStatus};
use x0_common::{
    constants::*,
    error::X0BridgeError,
    events::BridgeMessageReceived,
};

/// Derive the expected Hyperlane process authority PDA
///
/// Matches Hyperlane Sealevel mailbox:
/// https://github.com/hyperlane-xyz/hyperlane-monorepo/blob/main/rust/sealevel/programs/mailbox/src/pda_seeds.rs
///
/// Seeds: ["hyperlane", "-", "process_authority", "-", recipient_program_id]
/// Program: hyperlane_mailbox
fn derive_hyperlane_process_authority(
    hyperlane_mailbox: &Pubkey,
    recipient_program: &Pubkey,
) -> Pubkey {
    Pubkey::find_program_address(
        &[
            HYPERLANE_SEED,
            HYPERLANE_SEPARATOR,
            HYPERLANE_PROCESS_AUTHORITY,
            HYPERLANE_SEPARATOR,
            recipient_program.as_ref(),
        ],
        hyperlane_mailbox,
    ).0
}

#[derive(Accounts)]
#[instruction(origin: u32, sender: [u8; 32], message_body: Vec<u8>)]
pub struct HandleMessage<'info> {
    /// Payer for account creation (typically the Hyperlane relayer)
    #[account(mut)]
    pub payer: Signer<'info>,

    /// Hyperlane mailbox process authority
    ///
    /// This PDA proves the message was delivered through the Hyperlane mailbox.
    /// The mailbox program derives this PDA and uses it as the caller authority
    /// when invoking the recipient's handle instruction.
    ///
    /// SECURITY: Must be derived from the Hyperlane mailbox using:
    ///   seeds = ["hyperlane", "-", "process_authority", "-", this_program_id]
    ///   program_id = config.hyperlane_mailbox
    ///
    /// CHECK: Validated in handler via derive_hyperlane_process_authority()
    pub process_authority: Signer<'info>,

    /// Hyperlane mailbox program
    ///
    /// CHECK: Validated against config.hyperlane_mailbox
    #[account(
        constraint = hyperlane_mailbox.key() == config.hyperlane_mailbox
            @ X0BridgeError::InvalidMailbox,
    )]
    pub hyperlane_mailbox: UncheckedAccount<'info>,

    /// Bridge configuration (validates domain, sender, paused state)
    #[account(
        mut,
        seeds = [BRIDGE_CONFIG_SEED],
        bump = config.bump,
        constraint = !config.is_paused @ X0BridgeError::BridgePaused,
    )]
    pub config: Box<Account<'info, BridgeConfig>>,

    /// Bridge message PDA (created for this message)
    ///
    /// Seeded by the Hyperlane message ID to prevent replay attacks.
    /// If a message with the same ID is processed twice, the PDA init
    /// will fail with an AccountAlreadyInUse error.
    ///
    /// The message_id is derived from a SHA256 of origin + sender + body
    /// computed by the caller (Hyperlane relayer provides this).
    #[account(
        init,
        payer = payer,
        space = BridgeMessage::space(),
        seeds = [
            BRIDGE_MESSAGE_SEED,
            &compute_message_id(origin, &sender, &message_body),
        ],
        bump,
    )]
    pub bridge_message: Box<Account<'info, BridgeMessage>>,

    /// System program
    pub system_program: Program<'info, System>,
}

/// Compute a deterministic message ID from origin, sender, and body.
///
/// This must match the message ID computation on the Hyperlane side.
/// Uses SHA-256 for consistency with Hyperlane's message format.
fn compute_message_id(origin: u32, sender: &[u8; 32], body: &[u8]) -> [u8; 32] {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(origin.to_be_bytes());
    hasher.update(sender);
    hasher.update(body);
    hasher.finalize().into()
}

pub fn handler(
    ctx: Context<HandleMessage>,
    origin: u32,
    sender: [u8; 32],
    message_body: Vec<u8>,
) -> Result<()> {
    let clock = Clock::get()?;
    let config = &mut ctx.accounts.config;

    // ========================================================================
    // CRITICAL: Validate Hyperlane Process Authority
    //
    // This is the primary security check that prevents message spoofing.
    // The process_authority must be a PDA derived from the Hyperlane mailbox.
    // ========================================================================

    let expected_process_authority = derive_hyperlane_process_authority(
        &ctx.accounts.hyperlane_mailbox.key(),
        &crate::ID,  // Our program ID is the recipient
    );

    require!(
        ctx.accounts.process_authority.key() == expected_process_authority,
        X0BridgeError::InvalidProcessAuthority
    );

    // ========================================================================
    // Validation
    // ========================================================================

    // Validate origin domain is supported
    require!(
        config.is_domain_supported(origin),
        X0BridgeError::UnsupportedDomain
    );

    // Validate EVM sender format: first 12 bytes must be zeros
    // Hyperlane uses 32-byte addresses; EVM addresses are left-padded with 12 zeros
    require!(
        sender[0..12] == [0u8; 12],
        X0BridgeError::InvalidSenderFormat
    );

    // Extract the 20-byte EVM address from the 32-byte Hyperlane format
    let mut evm_sender = [0u8; EVM_ADDRESS_SIZE];
    evm_sender.copy_from_slice(&sender[12..32]);
    require!(
        config.is_contract_allowed(&evm_sender),
        X0BridgeError::UnauthorizedSenderContract
    );

    // Validate message body size
    require!(
        message_body.len() <= MAX_BRIDGE_MESSAGE_BODY_SIZE,
        X0BridgeError::MessageBodyTooLarge
    );

    // Decode message body
    let body = BridgeMessageBody::try_from_bytes(&message_body)?;

    // Validate amount
    require!(
        body.amount >= MIN_BRIDGE_AMOUNT,
        X0BridgeError::AmountTooSmall
    );
    require!(
        body.amount <= MAX_BRIDGE_AMOUNT_PER_TX,
        X0BridgeError::AmountTooLarge
    );

    // Check daily inflow rate limit
    config.maybe_reset_daily_counter(clock.unix_timestamp);
    let new_daily_volume = config
        .daily_inflow_volume
        .checked_add(body.amount)
        .ok_or(X0BridgeError::MathOverflow)?;
    require!(
        new_daily_volume <= MAX_DAILY_BRIDGE_INFLOW,
        X0BridgeError::DailyInflowLimitExceeded
    );

    // ========================================================================
    // State Updates
    // ========================================================================

    // Update config
    config.nonce = config
        .nonce
        .checked_add(1)
        .ok_or(X0BridgeError::MathOverflow)?;
    config.daily_inflow_volume = new_daily_volume;

    // Compute and store message ID
    let message_id = compute_message_id(origin, &sender, &message_body);

    // Initialize bridge message
    let bridge_message = &mut ctx.accounts.bridge_message;
    bridge_message.version = 1;
    bridge_message.message_id = message_id;
    bridge_message.origin_domain = origin;
    bridge_message.sender = sender;
    bridge_message.recipient = body.recipient;
    bridge_message.amount = body.amount;
    bridge_message.received_at = clock.unix_timestamp;
    bridge_message.status = BridgeMessageStatus::Received;
    bridge_message.evm_tx_hash = body.evm_tx_hash;
    bridge_message.nonce = config.nonce;
    bridge_message.bump = ctx.bumps.bridge_message;
    bridge_message._reserved = [0u8; 32];

    // ========================================================================
    // Event
    // ========================================================================

    emit!(BridgeMessageReceived {
        message_pda: bridge_message.key(),
        message_id,
        origin_domain: origin,
        sender,
        recipient: body.recipient,
        amount: body.amount,
        timestamp: clock.unix_timestamp,
    });

    msg!(
        "Bridge message received: id={}, origin={}, amount={}, recipient={}",
        hex::encode(message_id),
        origin,
        body.amount,
        body.recipient,
    );

    Ok(())
}
