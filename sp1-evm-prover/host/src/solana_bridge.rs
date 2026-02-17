//! Solana Bridge State Integration
//!
//! Fetches the trusted anchor block and hash from the x0-bridge program
//! on Solana. This eliminates manual CLI arguments and ensures the prover
//! always uses the on-chain trusted anchor.
//!
//! # Security Model
//!
//! The anchor is the root of trust for chain proof verification:
//! 1. Anchor stored on-chain in `BridgeState` account
//! 2. Governed by multisig (updateable via governance only)
//! 3. Prover fetches anchor automatically before each proof
//! 4. Circuit commits anchor in public inputs
//! 5. Solana verifier checks anchor matches on-chain value
//!
//! # Usage
//!
//! ```rust
//! let client = SolanaBridgeClient::new("https://api.mainnet-beta.solana.com")?;
//! let (anchor_block, anchor_hash) = client
//!     .fetch_trusted_anchor(&bridge_program_id)
//!     .await?;
//! ```

use anyhow::{bail, Context, Result};
use borsh::BorshDeserialize;
use solana_client::nonblocking::rpc_client::RpcClient;
use solana_sdk::pubkey::Pubkey;

/// Solana bridge client
pub struct SolanaBridgeClient {
    rpc: RpcClient,
}

/// Bridge state account structure
///
/// Must match the BorshDeserialize layout in the Solana program:
/// `programs/x0-bridge/src/state.rs`
#[derive(Debug, Clone, BorshDeserialize)]
pub struct BridgeState {
    /// Bump seed for PDA derivation
    #[allow(dead_code)]
    pub bump: u8,
    /// Governance authority pubkey
    #[allow(dead_code)]
    pub governance_authority: Pubkey,
    /// Paused state
    #[allow(dead_code)]
    pub paused: bool,
    /// Trusted anchor block number (Base L2)
    pub trusted_anchor_block: u64,
    /// Trusted anchor block hash (Base L2)
    pub trusted_anchor_hash: [u8; 32],
    /// Last update timestamp
    pub last_anchor_update: i64,
    // ... other fields (we only need anchor for now)
}

impl SolanaBridgeClient {
    /// Create a new Solana bridge client
    pub fn new(solana_rpc_url: &str) -> Result<Self> {
        let rpc = RpcClient::new(solana_rpc_url.to_string());
        tracing::info!("Initialized Solana bridge client: {}", solana_rpc_url);
        Ok(Self { rpc })
    }

    /// Fetch the current trusted anchor from the bridge state account
    ///
    /// # Arguments
    /// * `bridge_program_id` - The x0-bridge program ID on Solana
    ///
    /// # Returns
    /// * `(anchor_block, anchor_hash)` - The current trusted anchor
    pub async fn fetch_trusted_anchor(
        &self,
        bridge_program_id: &Pubkey,
    ) -> Result<(u64, [u8; 32])> {
        // Derive the bridge state PDA
        let (bridge_state_pda, _bump) = Pubkey::find_program_address(
            &[b"bridge_state"],
            bridge_program_id,
        );

        tracing::debug!("Fetching bridge state from PDA: {}", bridge_state_pda);

        // Fetch the account
        let account = self
            .rpc
            .get_account(&bridge_state_pda)
            .await
            .with_context(|| {
                format!(
                    "Failed to fetch bridge state account at {}. \
                     Is the bridge program deployed?",
                    bridge_state_pda
                )
            })?;

        // Verify account owner
        if account.owner != *bridge_program_id {
            bail!(
                "Bridge state account owner mismatch: expected {}, got {}",
                bridge_program_id,
                account.owner
            );
        }

        // Deserialize the state
        let state = BridgeState::try_from_slice(&account.data).with_context(|| {
            format!(
                "Failed to deserialize bridge state (size={} bytes). \
                 Struct layout may have changed.",
                account.data.len()
            )
        })?;

        tracing::info!(
            "✓ Fetched trusted anchor from Solana: block={}, hash=0x{}, updated_at={}",
            state.trusted_anchor_block,
            hex::encode(state.trusted_anchor_hash),
            state.last_anchor_update,
        );

        // Verify anchor is reasonable (not zero)
        if state.trusted_anchor_block == 0 {
            bail!("Bridge state has zero anchor block — not initialized?");
        }
        if state.trusted_anchor_hash == [0u8; 32] {
            bail!("Bridge state has zero anchor hash — not initialized?");
        }

        Ok((state.trusted_anchor_block, state.trusted_anchor_hash))
    }

    /// Check the age of the current anchor and warn if stale
    ///
    /// # Arguments
    /// * `bridge_program_id` - The x0-bridge program ID
    /// * `latest_l2_block` - The latest Base L2 block number
    ///
    /// # Security Note
    ///
    /// Stale anchors increase chain proof length (more circuit constraints,
    /// higher proving cost). We warn but don't fail — governance is
    /// responsible for timely anchor updates.
    pub async fn check_anchor_staleness(
        &self,
        bridge_program_id: &Pubkey,
        latest_l2_block: u64,
    ) -> Result<()> {
        let (anchor_block, _) = self.fetch_trusted_anchor(bridge_program_id).await?;

        let anchor_age = latest_l2_block.saturating_sub(anchor_block);

        // Warn if anchor is more than 6 hours old (on Base: ~10,800 blocks)
        const MAX_REASONABLE_ANCHOR_AGE: u64 = 10_800;

        if anchor_age > MAX_REASONABLE_ANCHOR_AGE {
            tracing::warn!(
                "⚠ Trusted anchor is {} blocks old (>{} threshold). \
                 Chain proofs will be longer and more expensive. \
                 Governance should update the anchor soon.",
                anchor_age,
                MAX_REASONABLE_ANCHOR_AGE,
            );
        } else {
            tracing::debug!("Anchor age OK: {} blocks", anchor_age);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bridge_state_pda_derivation() {
        let program_id = Pubkey::new_unique();
        let (pda, _bump) = Pubkey::find_program_address(&[b"bridge_state"], &program_id);

        // PDA should be deterministic
        let (pda2, _bump2) =
            Pubkey::find_program_address(&[b"bridge_state"], &program_id);
        assert_eq!(pda, pda2);

        // Different program = different PDA
        let other_program = Pubkey::new_unique();
        let (other_pda, _) =
            Pubkey::find_program_address(&[b"bridge_state"], &other_program);
        assert_ne!(pda, other_pda);
    }

    #[test]
    fn test_anchor_staleness_calculation() {
        let latest_block = 1_000_000;
        let anchor_block = 990_000;
        let age = latest_block.saturating_sub(anchor_block);
        assert_eq!(age, 10_000);
    }
}
