//! Verify an EVM transaction STARK proof (Step 2)
//!
//! Takes an SP1 STARK proof and verifies it via CPI to the SP1 verifier
//! program on Solana. Creates an EVMProofContext PDA linked to the
//! corresponding BridgeMessage.
//!
//! # Compute Budget
//!
//! STARK verification consumes ~500k compute units. This is why proof
//! verification and minting are separate instructions — combining them
//! would exceed Solana's ~1.4M CU transaction limit when factoring in
//! Token-2022 CPI overhead.
//!
//! # Permissionless
//!
//! Anyone can submit valid proofs. This enables keeper/relayer services
//! to operate without special permissions.

use anchor_lang::prelude::*;
use anchor_lang::solana_program::program::invoke;

use crate::state::{
    BridgeConfig, BridgeMessage, BridgeMessageStatus,
    EVMProofContext, EVMEventLog, EVMProofType, SP1PublicInputs,
};
use x0_common::{
    constants::*,
    error::X0BridgeError,
    events::BridgeProofVerified,
};

#[derive(Accounts)]
#[instruction(message_id: [u8; 32])]
pub struct VerifyEVMProof<'info> {
    /// Payer for proof context account creation
    #[account(mut)]
    pub payer: Signer<'info>,

    /// Bridge configuration (for SP1 verifier address)
    #[account(
        seeds = [BRIDGE_CONFIG_SEED],
        bump = config.bump,
        constraint = !config.is_paused @ X0BridgeError::BridgePaused,
    )]
    pub config: Box<Account<'info, BridgeConfig>>,

    /// The bridge message this proof is for
    #[account(
        mut,
        seeds = [BRIDGE_MESSAGE_SEED, &message_id],
        bump = bridge_message.bump,
        constraint = bridge_message.status == BridgeMessageStatus::Received
            @ X0BridgeError::InvalidMessageStatus,
    )]
    pub bridge_message: Box<Account<'info, BridgeMessage>>,

    /// EVM proof context PDA (created by this instruction)
    #[account(
        init,
        payer = payer,
        space = EVMProofContext::space(),
        seeds = [EVM_PROOF_CONTEXT_SEED, &message_id],
        bump,
    )]
    pub proof_context: Box<Account<'info, EVMProofContext>>,

    /// SP1 verifier program
    ///
    /// CHECK: Validated against config.sp1_verifier
    #[account(
        constraint = sp1_verifier.key() == config.sp1_verifier
            @ X0BridgeError::InvalidSP1Verifier,
    )]
    pub sp1_verifier: UncheckedAccount<'info>,

    /// System program
    pub system_program: Program<'info, System>,
}

pub fn handler(
    ctx: Context<VerifyEVMProof>,
    message_id: [u8; 32],
    proof: Vec<u8>,
    public_values: Vec<u8>,
) -> Result<()> {
    let clock = Clock::get()?;

    // ========================================================================
    // Step 1: Verify the STARK proof via CPI to SP1 verifier
    // ========================================================================

    msg!("Verifying STARK proof ({} bytes)...", proof.len());

    // Build the SP1 verify instruction
    // The SP1 Solana verifier expects:
    //   - proof bytes
    //   - public values bytes
    //   - verifier state account (if applicable)
    //
    // SP1 verification instruction layout:
    //   discriminator (8 bytes) + proof_len (4) + proof + public_values_len (4) + public_values
    let mut verify_data = Vec::with_capacity(8 + 4 + proof.len() + 4 + public_values.len());

    // SP1 verify discriminator (first 8 bytes of SHA256("global:verify"))
    let discriminator: [u8; 8] = {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(b"global:verify");
        let hash = hasher.finalize();
        let mut disc = [0u8; 8];
        disc.copy_from_slice(&hash[..8]);
        disc
    };
    verify_data.extend_from_slice(&discriminator);

    // Proof bytes (length-prefixed)
    verify_data.extend_from_slice(&(proof.len() as u32).to_le_bytes());
    verify_data.extend_from_slice(&proof);

    // Public values bytes (length-prefixed)
    verify_data.extend_from_slice(&(public_values.len() as u32).to_le_bytes());
    verify_data.extend_from_slice(&public_values);

    let verify_ix = solana_program::instruction::Instruction {
        program_id: ctx.accounts.sp1_verifier.key(),
        accounts: vec![
            solana_program::instruction::AccountMeta::new_readonly(
                ctx.accounts.payer.key(),
                true,
            ),
        ],
        data: verify_data,
    };

    invoke(
        &verify_ix,
        &[
            ctx.accounts.payer.to_account_info(),
            ctx.accounts.sp1_verifier.to_account_info(),
        ],
    )
    .map_err(|_| X0BridgeError::ProofVerificationFailed)?;

    msg!("✓ STARK proof verified");

    // ========================================================================
    // Step 2: Decode and validate public values
    // ========================================================================

    let public_inputs: SP1PublicInputs =
        SP1PublicInputs::try_from_slice(&public_values)
            .map_err(|_| X0BridgeError::InvalidPublicValues)?;

    // Validate EVM transaction was successful
    require!(
        public_inputs.success,
        X0BridgeError::EVMTransactionFailed
    );

    // Validate the EVM tx hash matches the bridge message
    require!(
        public_inputs.tx_hash == ctx.accounts.bridge_message.evm_tx_hash,
        X0BridgeError::ProofMessageMismatch
    );

    // ========================================================================
    // Step 2b: Validate Locked event from ZK-proven receipt logs
    //
    // CRITICAL SECURITY: The ZK proof cryptographically binds event logs to
    // the proven receipt. We MUST validate these logs against the Hyperlane
    // message data to prevent a compromised Hyperlane relay from injecting
    // fake amounts/recipients while pointing to a real (but unrelated) tx.
    //
    // Without this check, an attacker who controls the Hyperlane ISM could:
    //   1. Lock $1 USDC on Base → real tx_hash
    //   2. Forge a Hyperlane message claiming $1M for attacker's address
    //   3. Submit a valid STARK proof for the $1 lock
    //   4. verify_evm_proof would pass (tx_hash matches, proof is valid)
    //   5. execute_mint mints $1M x0-USD → attacker drains the bridge
    //
    // The fix: extract the Locked event from the proven logs and compare
    // its amount, recipient, and nonce against the BridgeMessage.
    // ========================================================================

    validate_locked_event(
        &public_inputs.event_logs,
        &ctx.accounts.config,
        &ctx.accounts.bridge_message,
    )?;

    // ========================================================================
    // Step 3: Create proof context
    // ========================================================================

    let proof_context = &mut ctx.accounts.proof_context;
    proof_context.version = 1;
    proof_context.proof_type = EVMProofType::Transaction;
    proof_context.verified = true;
    proof_context.verified_at = clock.unix_timestamp;
    proof_context.block_hash = public_inputs.block_hash;
    proof_context.block_number = public_inputs.block_number;
    proof_context.tx_hash = public_inputs.tx_hash;
    proof_context.from = public_inputs.from;
    proof_context.to = public_inputs.to;
    proof_context.value = public_inputs.value;
    proof_context.event_logs = public_inputs.event_logs;
    proof_context.message_id = message_id;
    proof_context.bump = ctx.bumps.proof_context;
    proof_context._reserved = [0u8; 32];

    // ========================================================================
    // Step 4: Update bridge message status
    // ========================================================================

    let bridge_message = &mut ctx.accounts.bridge_message;
    bridge_message.status = BridgeMessageStatus::ProofVerified;

    // ========================================================================
    // Step 5: Emit event
    // ========================================================================

    emit!(BridgeProofVerified {
        proof_context: proof_context.key(),
        message_pda: bridge_message.key(),
        message_id,
        evm_block_number: proof_context.block_number,
        evm_tx_hash: proof_context.tx_hash,
        amount: bridge_message.amount,
        timestamp: clock.unix_timestamp,
    });

    msg!(
        "Proof verified: message_id={}, block={}, tx={}",
        hex::encode(message_id),
        proof_context.block_number,
        hex::encode(proof_context.tx_hash),
    );

    Ok(())
}

// ============================================================================
// Event Validation Helper
// ============================================================================

/// Validate the Locked event from ZK-proven receipt logs against the
/// BridgeMessage created by handle_message.
///
/// This is the core security check that ensures the ZK-proven on-chain
/// event data (amount, recipient) matches what Hyperlane reported.
///
/// # Event Layout (from X0LockContract.sol)
///
/// ```text
/// topics[0] = keccak256("Locked(address,bytes32,uint256,uint256,bytes32)")
/// topics[1] = sender (address, indexed → left-padded to 32 bytes)
/// topics[2] = solanaRecipient (bytes32, indexed)
/// data[0..32]   = amount (uint256, big-endian)
/// data[32..64]  = nonce (uint256, big-endian)
/// data[64..96]  = messageId (bytes32)
/// ```
pub fn validate_locked_event(
    event_logs: &[EVMEventLog],
    config: &BridgeConfig,
    bridge_message: &BridgeMessage,
) -> Result<()> {
    // Find the Locked event emitted by an allowed lock contract
    let locked_event = event_logs
        .iter()
        .find(|log| {
            // Check event signature (topic[0] == LOCKED_EVENT_SIGNATURE)
            log.topics.len() >= 3
                && log.topics[0] == LOCKED_EVENT_SIGNATURE
                // Check emitting contract is whitelisted
                && config.is_contract_allowed(&log.contract_address)
        })
        .ok_or(X0BridgeError::DepositEventNotFound)?;

    // Validate topic count: need at least 3 (signature, sender, solanaRecipient)
    require!(
        locked_event.topics.len() >= 3,
        X0BridgeError::EventTopicsMissing
    );

    // Validate data length: need at least 96 bytes (amount + nonce + messageId)
    require!(
        locked_event.data.len() >= 96,
        X0BridgeError::EventDataTooShort
    );

    // --- Validate recipient ---
    // topics[2] = solanaRecipient (bytes32 = raw 32-byte Solana pubkey)
    let event_recipient_bytes = &locked_event.topics[2];
    require!(
        event_recipient_bytes == bridge_message.recipient.as_ref(),
        X0BridgeError::EventRecipientMismatch
    );

    // --- Validate amount ---
    // data[0..32] = amount as uint256 (big-endian, 32 bytes)
    // USDC amounts fit in u64. The high 24 bytes must be zero.
    let amount_word = &locked_event.data[0..32];
    require!(
        amount_word[0..24] == [0u8; 24],
        X0BridgeError::EventAmountMismatch
    );
    let mut amount_bytes = [0u8; 8];
    amount_bytes.copy_from_slice(&amount_word[24..32]);
    let event_amount = u64::from_be_bytes(amount_bytes);
    require!(
        event_amount == bridge_message.amount,
        X0BridgeError::EventAmountMismatch
    );

    // --- Validate nonce ---
    // data[32..64] = nonce as uint256 (big-endian, 32 bytes)
    // The high 24 bytes must be zero (fits in u64).
    let nonce_word = &locked_event.data[32..64];
    require!(
        nonce_word[0..24] == [0u8; 24],
        X0BridgeError::EventNonceMismatch
    );

    msg!(
        "Locked event validated: amount={}, recipient={}",
        event_amount,
        bridge_message.recipient,
    );

    Ok(())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::EVMEventLog;

    /// Create an allowed EVM contract address for testing
    fn test_contract() -> [u8; EVM_ADDRESS_SIZE] {
        let mut addr = [0u8; EVM_ADDRESS_SIZE];
        addr[19] = 0x42; // 0x000...0042
        addr
    }

    /// Create a test Solana pubkey bytes
    fn test_recipient() -> Pubkey {
        Pubkey::new_from_array([0xAA; 32])
    }

    /// Encode a u64 as a 32-byte big-endian uint256 word
    fn encode_uint256(val: u64) -> Vec<u8> {
        let mut word = vec![0u8; 24];
        word.extend_from_slice(&val.to_be_bytes());
        word
    }

    /// Build a valid Locked event log for testing
    fn make_locked_event(
        contract: [u8; EVM_ADDRESS_SIZE],
        recipient: &Pubkey,
        amount: u64,
        nonce: u64,
    ) -> EVMEventLog {
        let mut data = Vec::new();
        data.extend_from_slice(&encode_uint256(amount));   // data[0..32]
        data.extend_from_slice(&encode_uint256(nonce));    // data[32..64]
        data.extend_from_slice(&[0xBB; 32]);               // data[64..96] = messageId

        EVMEventLog {
            contract_address: contract,
            topics: vec![
                LOCKED_EVENT_SIGNATURE,          // topics[0]: event sig
                [0x11; 32],                      // topics[1]: sender (indexed)
                recipient.to_bytes(),            // topics[2]: solanaRecipient
            ],
            data,
        }
    }

    /// Build a minimal BridgeConfig with one allowed contract
    fn make_config(allowed_contract: [u8; EVM_ADDRESS_SIZE]) -> BridgeConfig {
        let mut config = BridgeConfig {
            version: 1,
            admin: Pubkey::default(),
            hyperlane_mailbox: Pubkey::default(),
            sp1_verifier: Pubkey::default(),
            wrapper_program: Pubkey::default(),
            wrapper_config: Pubkey::default(),
            usdc_mint: Pubkey::default(),
            wrapper_mint: Pubkey::default(),
            bridge_usdc_reserve: Pubkey::default(),
            is_paused: false,
            total_bridged_in: 0,
            total_bridged_out: 0,
            nonce: 0,
            daily_inflow_volume: 0,
            daily_inflow_reset_timestamp: 0,
            allowed_evm_contracts_count: 1,
            allowed_evm_contracts: [[0u8; EVM_ADDRESS_SIZE]; MAX_ALLOWED_EVM_CONTRACTS],
            supported_domains_count: 0,
            supported_domains: [0u32; MAX_SUPPORTED_DOMAINS],
            admin_action_nonce: 0,
            bump: 0,
            bridge_out_nonce: 0,
            daily_outflow_volume: 0,
            daily_outflow_reset_timestamp: 0,
            _reserved: [0u8; 32],
        };
        config.allowed_evm_contracts[0] = allowed_contract;
        config
    }

    /// Build a minimal BridgeMessage for testing
    fn make_bridge_message(recipient: Pubkey, amount: u64) -> BridgeMessage {
        BridgeMessage {
            version: 1,
            message_id: [0u8; 32],
            origin_domain: 8453,
            sender: [0u8; 32],
            recipient,
            amount,
            received_at: 0,
            status: BridgeMessageStatus::Received,
            evm_tx_hash: [0u8; 32],
            nonce: 1,
            bump: 0,
            _reserved: [0u8; 32],
        }
    }

    #[test]
    fn test_valid_locked_event() {
        let contract = test_contract();
        let recipient = test_recipient();
        let amount = 1_000_000u64; // 1 USDC
        let event = make_locked_event(contract, &recipient, amount, 1);
        let config = make_config(contract);
        let msg = make_bridge_message(recipient, amount);

        let result = validate_locked_event(&[event], &config, &msg);
        assert!(result.is_ok(), "Valid event should pass: {:?}", result);
    }

    #[test]
    fn test_wrong_amount_rejected() {
        let contract = test_contract();
        let recipient = test_recipient();
        // Event says 1 USDC, message says 1,000,000 USDC
        let event = make_locked_event(contract, &recipient, 1_000_000, 1);
        let config = make_config(contract);
        let msg = make_bridge_message(recipient, 1_000_000_000_000);

        let result = validate_locked_event(&[event], &config, &msg);
        assert!(result.is_err(), "Amount mismatch should fail");
    }

    #[test]
    fn test_wrong_recipient_rejected() {
        let contract = test_contract();
        let legit_recipient = test_recipient();
        let attacker = Pubkey::new_from_array([0xFF; 32]);
        let amount = 1_000_000u64;

        // Event has legit recipient, message has attacker
        let event = make_locked_event(contract, &legit_recipient, amount, 1);
        let config = make_config(contract);
        let msg = make_bridge_message(attacker, amount);

        let result = validate_locked_event(&[event], &config, &msg);
        assert!(result.is_err(), "Recipient mismatch should fail");
    }

    #[test]
    fn test_unauthorized_contract_rejected() {
        let allowed = test_contract();
        let unauthorized = {
            let mut addr = [0u8; EVM_ADDRESS_SIZE];
            addr[19] = 0xFF; // Different contract
            addr
        };
        let recipient = test_recipient();
        let amount = 1_000_000u64;

        // Event is from unauthorized contract
        let event = make_locked_event(unauthorized, &recipient, amount, 1);
        let config = make_config(allowed);
        let msg = make_bridge_message(recipient, amount);

        let result = validate_locked_event(&[event], &config, &msg);
        assert!(result.is_err(), "Unauthorized contract should fail");
    }

    #[test]
    fn test_missing_event_rejected() {
        let contract = test_contract();
        let recipient = test_recipient();
        let config = make_config(contract);
        let msg = make_bridge_message(recipient, 1_000_000);

        // No events at all
        let result = validate_locked_event(&[], &config, &msg);
        assert!(result.is_err(), "Empty event logs should fail");
    }

    #[test]
    fn test_wrong_event_signature_rejected() {
        let contract = test_contract();
        let recipient = test_recipient();
        let amount = 1_000_000u64;

        // Build an event with wrong signature (Transfer instead of Locked)
        let mut event = make_locked_event(contract, &recipient, amount, 1);
        event.topics[0] = TRANSFER_EVENT_SIGNATURE;

        let config = make_config(contract);
        let msg = make_bridge_message(recipient, amount);

        let result = validate_locked_event(&[event], &config, &msg);
        assert!(result.is_err(), "Wrong event signature should fail");
    }

    #[test]
    fn test_short_data_rejected() {
        let contract = test_contract();
        let recipient = test_recipient();

        // Build event with data too short (only 64 bytes instead of 96)
        let event = EVMEventLog {
            contract_address: contract,
            topics: vec![
                LOCKED_EVENT_SIGNATURE,
                [0x11; 32],
                recipient.to_bytes(),
            ],
            data: vec![0u8; 64], // Too short — needs 96+ bytes
        };
        let config = make_config(contract);
        let msg = make_bridge_message(recipient, 1_000_000);

        let result = validate_locked_event(&[event], &config, &msg);
        assert!(result.is_err(), "Short data should fail");
    }

    #[test]
    fn test_too_few_topics_rejected() {
        let contract = test_contract();
        let recipient = test_recipient();
        let amount = 1_000_000u64;

        // Build event with only 2 topics (need at least 3)
        let event = EVMEventLog {
            contract_address: contract,
            topics: vec![
                LOCKED_EVENT_SIGNATURE,
                [0x11; 32],
                // Missing topics[2] (solanaRecipient)
            ],
            data: encode_uint256(amount)
                .into_iter()
                .chain(encode_uint256(1))
                .chain([0xBB; 32].into_iter())
                .collect(),
        };
        let config = make_config(contract);
        let msg = make_bridge_message(recipient, amount);

        let result = validate_locked_event(&[event], &config, &msg);
        assert!(result.is_err(), "Too few topics should fail");
    }

    #[test]
    fn test_correct_event_found_among_others() {
        let contract = test_contract();
        let recipient = test_recipient();
        let amount = 1_000_000u64;

        // Create a Transfer event (wrong type) and a valid Locked event
        let transfer_event = EVMEventLog {
            contract_address: contract,
            topics: vec![TRANSFER_EVENT_SIGNATURE, [0x11; 32], [0x22; 32]],
            data: encode_uint256(999),
        };
        let locked_event = make_locked_event(contract, &recipient, amount, 1);

        let config = make_config(contract);
        let msg = make_bridge_message(recipient, amount);

        // Locked event is second — should still be found
        let result = validate_locked_event(
            &[transfer_event, locked_event],
            &config,
            &msg,
        );
        assert!(result.is_ok(), "Should find correct event among others: {:?}", result);
    }

    /// The exact attack scenario from the security analysis:
    /// Attacker locks $1, forges Hyperlane message claiming $1M.
    #[test]
    fn test_amount_inflation_attack_blocked() {
        let contract = test_contract();
        let attacker = Pubkey::new_from_array([0xEE; 32]);

        // Real on-chain event: $1 USDC locked
        let real_event = make_locked_event(contract, &attacker, 1_000_000, 1);

        // Forged Hyperlane message claims: $1,000,000 USDC
        let config = make_config(contract);
        let forged_msg = make_bridge_message(attacker, 1_000_000_000_000);

        let result = validate_locked_event(&[real_event], &config, &forged_msg);
        assert!(
            result.is_err(),
            "Amount inflation attack MUST be blocked"
        );
    }

    /// Attack: correct amount but wrong recipient (redirect funds)
    #[test]
    fn test_recipient_redirect_attack_blocked() {
        let contract = test_contract();
        let legit_user = test_recipient();
        let attacker = Pubkey::new_from_array([0xEE; 32]);
        let amount = 100_000_000_000u64; // $100K USDC

        // Real event: $100K locked for legit_user
        let real_event = make_locked_event(contract, &legit_user, amount, 1);

        // Forged message: redirects to attacker
        let config = make_config(contract);
        let forged_msg = make_bridge_message(attacker, amount);

        let result = validate_locked_event(&[real_event], &config, &forged_msg);
        assert!(
            result.is_err(),
            "Recipient redirect attack MUST be blocked"
        );
    }
}
