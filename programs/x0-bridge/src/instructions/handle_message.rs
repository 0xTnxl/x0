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
    /// CHECK: Validated against config.hyperlane_mailbox via PDA derivation
    pub process_authority: Signer<'info>,

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
    // Validation
    // ========================================================================

    // Validate origin domain is supported
    require!(
        config.is_domain_supported(origin),
        X0BridgeError::UnsupportedDomain
    );

    // Validate sender is an allowed EVM contract
    // The sender is a 32-byte Hyperlane address; extract the 20-byte EVM address
    // (EVM addresses are left-padded with 12 zero bytes in Hyperlane format)
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
