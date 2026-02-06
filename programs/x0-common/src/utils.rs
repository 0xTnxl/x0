//! Utility functions for x0-01 protocol

use anchor_lang::prelude::*;
use sha2::{Digest, Sha256};

use crate::constants::*;

// ============================================================================
// Fee Calculations
// ============================================================================

/// Calculate the protocol fee for a given transfer amount
///
/// Enforces a minimum fee to prevent fee avoidance via dust transfer splitting.
/// For amounts < 125 tokens (with 6 decimals), the calculated fee would be 0,
/// so we enforce MIN_PROTOCOL_FEE to prevent protocol revenue loss.
///
/// # Arguments
/// * `amount` - The transfer amount in token micro-units
///
/// # Returns
/// The fee amount in token micro-units (minimum MIN_PROTOCOL_FEE if amount > 0)
pub fn calculate_protocol_fee(amount: u64) -> u64 {
    if amount == 0 {
        return 0;
    }
    
    // 0.8% = 80 basis points
    let fee = amount
        .saturating_mul(PROTOCOL_FEE_BASIS_POINTS as u64)
        .saturating_div(FEE_DENOMINATOR);
    
    // Enforce minimum fee to prevent dust transfer fee avoidance (HIGH-2)
    fee.max(MIN_PROTOCOL_FEE)
}

/// Calculate the protocol fee with a custom basis point rate
pub fn calculate_fee_with_rate(amount: u64, basis_points: u16) -> u64 {
    amount
        .saturating_mul(basis_points as u64)
        .saturating_div(FEE_DENOMINATOR)
}

/// Calculate the amount after fee deduction
pub fn amount_after_fee(amount: u64) -> u64 {
    amount.saturating_sub(calculate_protocol_fee(amount))
}

// ============================================================================
// Hash Utilities
// ============================================================================

/// Compute SHA256 hash of arbitrary data
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Compute memo hash from resource identifier
pub fn compute_memo_hash(resource_id: &str) -> [u8; 32] {
    sha256(resource_id.as_bytes())
}

/// Compute payment challenge hash
pub fn compute_challenge_hash(
    recipient: &Pubkey,
    amount: u64,
    nonce: &[u8],
) -> [u8; 32] {
    let mut data = Vec::with_capacity(32 + 8 + nonce.len());
    data.extend_from_slice(recipient.as_ref());
    data.extend_from_slice(&amount.to_le_bytes());
    data.extend_from_slice(nonce);
    sha256(&data)
}

// ============================================================================
// Time Utilities
// ============================================================================

/// Maximum allowed clock skew in seconds (LOW-5: increased from 60s to 300s)
/// Solana's clock can have variance between validators, 5 minutes accommodates this.
pub const MAX_CLOCK_SKEW_SECONDS: i64 = 300;

/// Check if a timestamp is within the valid range (not too old, not in future)
/// 
/// # LOW-5 Fix
/// Increased future window from 60s to 300s (5 minutes) to accommodate
/// Solana's clock variance across validators without rejecting legitimate transactions.
pub fn is_valid_timestamp(timestamp: i64, current_timestamp: i64) -> bool {
    // Allow up to 5 minutes in the future (for clock skew between validators)
    // Allow up to 24 hours in the past
    let max_future = current_timestamp + MAX_CLOCK_SKEW_SECONDS;
    let max_past = current_timestamp - ROLLING_WINDOW_SECONDS;
    
    timestamp <= max_future && timestamp >= max_past
}

/// Check if a Blink has expired
pub fn is_blink_expired(blink_created_at: i64, current_timestamp: i64) -> bool {
    current_timestamp > blink_created_at + BLINK_EXPIRY_SECONDS
}

/// Calculate the hour boundary for rate limiting
pub fn hour_boundary(timestamp: i64) -> i64 {
    (timestamp / 3600) * 3600
}

// ============================================================================
// Validation Utilities
// ============================================================================

/// Validate a daily limit is within bounds
pub fn validate_daily_limit(limit: u64) -> Result<()> {
    require!(
        limit >= MIN_DAILY_LIMIT,
        ValidationError::DailyLimitTooLow
    );
    require!(
        limit <= MAX_DAILY_LIMIT,
        ValidationError::DailyLimitTooHigh
    );
    Ok(())
}

/// Validate an escrow timeout is within bounds
pub fn validate_escrow_timeout(timeout_seconds: i64) -> Result<()> {
    require!(
        timeout_seconds >= MIN_ESCROW_TIMEOUT_SECONDS,
        ValidationError::EscrowTimeoutTooShort
    );
    require!(
        timeout_seconds <= MAX_ESCROW_TIMEOUT_SECONDS,
        ValidationError::EscrowTimeoutTooLong
    );
    Ok(())
}

/// Validate an endpoint URL format (basic validation)
pub fn validate_endpoint(endpoint: &str) -> Result<()> {
    require!(
        !endpoint.is_empty(),
        ValidationError::InvalidEndpoint
    );
    require!(
        endpoint.len() <= MAX_ENDPOINT_LENGTH,
        ValidationError::EndpointTooLong
    );
    require!(
        endpoint.starts_with("https://") || endpoint.starts_with("http://"),
        ValidationError::InvalidEndpoint
    );
    Ok(())
}

/// Validate capability type format
pub fn validate_capability_type(capability_type: &str) -> Result<()> {
    require!(
        !capability_type.is_empty(),
        ValidationError::InvalidCapabilityType
    );
    require!(
        capability_type.len() <= MAX_CAPABILITY_TYPE_LENGTH,
        ValidationError::CapabilityTypeTooLong
    );
    // Only allow alphanumeric and hyphens
    require!(
        capability_type.chars().all(|c| c.is_alphanumeric() || c == '-'),
        ValidationError::InvalidCapabilityType
    );
    Ok(())
}

// ============================================================================
// PDA Derivation
// ============================================================================

/// Derive the AgentPolicy PDA for an owner
pub fn derive_agent_policy_pda(owner: &Pubkey, program_id: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[AGENT_POLICY_SEED, owner.as_ref()],
        program_id,
    )
}

/// Derive the Escrow PDA for a buyer/seller/memo combination
pub fn derive_escrow_pda(
    buyer: &Pubkey,
    seller: &Pubkey,
    memo_hash: &[u8; 32],
    program_id: &Pubkey,
) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[ESCROW_SEED, buyer.as_ref(), seller.as_ref(), memo_hash],
        program_id,
    )
}

/// Derive the Registry PDA for an agent
pub fn derive_registry_pda(agent_id: &Pubkey, program_id: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[REGISTRY_SEED, agent_id.as_ref()],
        program_id,
    )
}

/// Derive the Reputation PDA for an agent
pub fn derive_reputation_pda(agent_id: &Pubkey, program_id: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[REPUTATION_SEED, agent_id.as_ref()],
        program_id,
    )
}

/// Derive the Protocol Config PDA
pub fn derive_protocol_config_pda(program_id: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[PROTOCOL_CONFIG_SEED],
        program_id,
    )
}

/// Derive the Treasury PDA
pub fn derive_treasury_pda(program_id: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[TREASURY_SEED],
        program_id,
    )
}

// ============================================================================
// Validation Error
// ============================================================================

#[error_code]
pub enum ValidationError {
    #[msg("Daily limit is below minimum")]
    DailyLimitTooLow,
    
    #[msg("Daily limit exceeds maximum")]
    DailyLimitTooHigh,
    
    #[msg("Escrow timeout is too short")]
    EscrowTimeoutTooShort,
    
    #[msg("Escrow timeout is too long")]
    EscrowTimeoutTooLong,
    
    #[msg("Invalid endpoint URL format")]
    InvalidEndpoint,
    
    #[msg("Endpoint URL too long")]
    EndpointTooLong,
    
    #[msg("Invalid capability type format")]
    InvalidCapabilityType,
    
    #[msg("Capability type too long")]
    CapabilityTypeTooLong,
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_fee_calculation() {
        // 0.8% of 1000 = 8
        assert_eq!(calculate_protocol_fee(1000), 8);
        
        // 0.8% of 10000 = 80
        assert_eq!(calculate_protocol_fee(10000), 80);
        
        // 0.8% of 1,000,000 = 8,000
        assert_eq!(calculate_protocol_fee(1_000_000), 8_000);
        
        // Edge case: 0
        assert_eq!(calculate_protocol_fee(0), 0);
        
        // Small amounts: MIN_PROTOCOL_FEE (1) enforced when calculated fee rounds to 0 (HIGH-2)
        assert_eq!(calculate_protocol_fee(1), 1);    // MIN_PROTOCOL_FEE applies
        assert_eq!(calculate_protocol_fee(100), 1);  // 0.8% of 100 = 0, MIN_PROTOCOL_FEE applies
        assert_eq!(calculate_protocol_fee(125), 1);  // 125 * 80 / 10000 = 1 (exact threshold)
    }

    #[test]
    fn test_amount_after_fee() {
        assert_eq!(amount_after_fee(10000), 10000 - 80);
        assert_eq!(amount_after_fee(1_000_000), 1_000_000 - 8_000);
    }

    #[test]
    fn test_timestamp_validation() {
        let now = 1706400000i64; // Some timestamp
        
        // Current time is valid
        assert!(is_valid_timestamp(now, now));
        
        // 1 hour ago is valid
        assert!(is_valid_timestamp(now - 3600, now));
        
        // 23 hours ago is valid
        assert!(is_valid_timestamp(now - 82800, now));
        
        // 25 hours ago is invalid
        assert!(!is_valid_timestamp(now - 90000, now));
        
        // 30 seconds in future is valid (clock skew)
        assert!(is_valid_timestamp(now + 30, now));
        
        // 2 minutes in future is valid (LOW-5: MAX_CLOCK_SKEW_SECONDS = 300s)
        assert!(is_valid_timestamp(now + 120, now));

        // 6 minutes in future is invalid (exceeds 300s skew window)
        assert!(!is_valid_timestamp(now + 360, now));
    }

    #[test]
    fn test_blink_expiry() {
        let created = 1706400000i64;
        
        // Not expired immediately
        assert!(!is_blink_expired(created, created));
        
        // Not expired after 14 minutes
        assert!(!is_blink_expired(created, created + 840));
        
        // Expired after 15 minutes + 1 second
        assert!(is_blink_expired(created, created + 901));
    }

    #[test]
    fn test_endpoint_validation() {
        assert!(validate_endpoint("https://example.com").is_ok());
        assert!(validate_endpoint("http://localhost:8080").is_ok());
        assert!(validate_endpoint("").is_err());
        assert!(validate_endpoint("ftp://example.com").is_err());
        
        let long_url = format!("https://{}", "a".repeat(MAX_ENDPOINT_LENGTH));
        assert!(validate_endpoint(&long_url).is_err());
    }

    #[test]
    fn test_capability_type_validation() {
        assert!(validate_capability_type("llm-inference").is_ok());
        assert!(validate_capability_type("data-scraping").is_ok());
        assert!(validate_capability_type("").is_err());
        assert!(validate_capability_type("with spaces").is_err());
        assert!(validate_capability_type("with_underscore").is_err());
    }
}
