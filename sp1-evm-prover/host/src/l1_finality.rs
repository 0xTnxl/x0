//! L1 Finality Verification for Base (OP Stack)
//!
//! Verifies that Base L2 blocks have been posted to Ethereum L1 before
//! accepting them as final. This prevents proving transactions in blocks
//! that could be reorganized by the L2 sequencer.
//!
//! # Security Model
//!
//! Base blocks go through two stages:
//! 1. **Soft confirmation** (~2 seconds): Sequencer proposes block
//! 2. **L1 finality** (~15-20 minutes): Block's state root posted to L1
//!
//! Between stages, the sequencer can reorganize blocks. For financial
//! bridges, we MUST wait for L1 finality.
//!
//! # Architecture
//!
//! Base posts state roots to the `L2OutputOracle` contract on Ethereum L1:
//! - Contract: 0x56315b90c40730925ec5485cf004d835058518A0 (Base mainnet)
//! - Function: `getL2Output(uint256 _l2OutputIndex)`
//! - Returns: `OutputProposal` struct with `outputRoot` and `l2BlockNumber`
//!
//! # Usage
//!
//! ```rust
//! let verifier = L1FinalityVerifier::new(
//!     "https://eth.llamarpc.com",  // Ethereum L1 RPC
//!     Network::BaseMainnet,
//! )?;
//!
//! // Check if Base block 12345678 has been posted to L1
//! verifier.verify_l1_finality(12345678).await?;
//! ```

use alloy_primitives::{Address, U256};
use alloy_provider::{Provider, ProviderBuilder};
use alloy_sol_types::{sol, SolCall};
use alloy_transport_http::Http;
use anyhow::{bail, Context, Result};
use reqwest::Client;

/// Base network configurations
#[derive(Debug, Clone, Copy)]
pub enum Network {
    /// Base mainnet (chain ID 8453)
    BaseMainnet,
    /// Base Sepolia testnet (chain ID 84532)
    BaseSepolia,
}

impl Network {
    /// Get the L2OutputOracle contract address on L1
    pub fn output_oracle_address(&self) -> Address {
        match self {
            // Base mainnet OutputOracle on Ethereum L1
            Network::BaseMainnet => {
                "0x56315b90c40730925ec5485cf004d835058518A0"
                    .parse()
                    .unwrap()
            }
            // Base Sepolia OutputOracle on Sepolia L1
            Network::BaseSepolia => {
                "0x84457ca9D0163FbC4bbfe4Dfbb20ba46e48DF254"
                    .parse()
                    .unwrap()
            }
        }
    }

    /// Get the L2 chain ID
    pub fn chain_id(&self) -> u64 {
        match self {
            Network::BaseMainnet => 8453,
            Network::BaseSepolia => 84532,
        }
    }

    /// Get the network name as a string
    pub fn name(&self) -> &'static str {
        match self {
            Network::BaseMainnet => "Base Mainnet",
            Network::BaseSepolia => "Base Sepolia",
        }
    }
}

// Solidity interface for L2OutputOracle
sol! {
    interface L2OutputOracle {
        struct OutputProposal {
            bytes32 outputRoot;
            uint128 timestamp;
            uint128 l2BlockNumber;
        }

        function getL2Output(uint256 _l2OutputIndex) external view returns (OutputProposal memory);
        function latestOutputIndex() external view returns (uint256);
        function SUBMISSION_INTERVAL() external view returns (uint256);
    }
}

/// L1 finality verifier
pub struct L1FinalityVerifier {
    /// Ethereum L1 RPC provider
    l1_provider: alloy_provider::RootProvider<Http<Client>>,
    /// Base network configuration
    network: Network,
    /// OutputOracle contract address
    output_oracle: Address,
}

impl L1FinalityVerifier {
    /// Create a new L1 finality verifier
    ///
    /// # Arguments
    /// * `l1_rpc_url` - Ethereum L1 RPC endpoint
    /// * `network` - Base network (mainnet or testnet)
    pub fn new(l1_rpc_url: &str, network: Network) -> Result<Self> {
        let l1_provider = ProviderBuilder::new()
            .on_http(l1_rpc_url.parse().context("Invalid L1 RPC URL")?);

        let output_oracle = network.output_oracle_address();

        tracing::info!(
            "Initialized L1 finality verifier for {:?} (oracle={})",
            network,
            output_oracle,
        );

        Ok(Self {
            l1_provider,
            network,
            output_oracle,
        })
    }

    /// Verify that a Base L2 block has been posted to Ethereum L1
    ///
    /// # Returns
    /// - `Ok(())` if block is L1-finalized
    /// - `Err()` if block is not yet posted or verification fails
    pub async fn verify_l1_finality(&self, l2_block_number: u64) -> Result<()> {
        tracing::debug!(
            "Verifying L1 finality for {} block {} via oracle {}",
            self.network.name(),
            l2_block_number,
            self.output_oracle,
        );

        // Get the latest output index from the oracle
        let latest_index = self.get_latest_output_index().await?;

        tracing::debug!("Latest L1 output index: {}", latest_index);

        // Binary search to find the output that covers our block
        // (outputs are posted in batches, not for every block)
        let mut left = 0u64;
        let mut right = latest_index;
        let mut found_output: Option<(u64, L2OutputOracle::OutputProposal)> =
            None;

        while left <= right {
            let mid = (left + right) / 2;
            let output = self.get_l2_output(mid).await?;

            let output_block = output.l2BlockNumber as u64;

            if output_block == l2_block_number {
                // Exact match
                found_output = Some((mid, output));
                break;
            } else if output_block < l2_block_number {
                // Our block is after this output, search right
                left = mid + 1;
            } else {
                // Our block is before this output
                if mid == 0 {
                    break;
                }
                // Check if our block is between mid-1 and mid
                let prev_output = self.get_l2_output(mid - 1).await?;
                let prev_block = prev_output.l2BlockNumber as u64;

                if prev_block <= l2_block_number && l2_block_number < output_block
                {
                    // Our block is covered by the previous output
                    found_output = Some((mid - 1, prev_output));
                    break;
                }
                right = mid - 1;
            }
        }

        match found_output {
            Some((index, output)) => {
                tracing::info!(
                    "✓ {} block {} is L1-finalized (output_index={}, output_root=0x{}, chain_id={})",
                    self.network.name(),
                    l2_block_number,
                    index,
                    hex::encode(output.outputRoot),
                    self.network.chain_id(),
                );
                Ok(())
            }
            None => {
                // Block is not yet posted to L1
                let submission_interval =
                    self.get_submission_interval().await.unwrap_or(1800);
                let latest_finalized_block = if latest_index > 0 {
                    self.get_l2_output(latest_index).await?.l2BlockNumber as u64
                } else {
                    0
                };

                let blocks_behind = l2_block_number
                    .saturating_sub(latest_finalized_block);
                let estimated_wait_time =
                    (blocks_behind / submission_interval) * 15; // ~15 min per batch

                bail!(
                    "{} block {} is NOT L1-finalized. \
                     Latest finalized block: {} ({} blocks behind). \
                     Estimated wait time: ~{} minutes. \
                     \n\n\
                     This block has only soft-confirmation from the {} sequencer. \
                     For financial bridges, we require L1 finality to prevent reorg attacks.",
                    self.network.name(),
                    l2_block_number,
                    latest_finalized_block,
                    blocks_behind,
                    estimated_wait_time,
                    self.network.name(),
                );
            }
        }
    }

    /// Get the latest output index from the OutputOracle
    async fn get_latest_output_index(&self) -> Result<u64> {
        let call = L2OutputOracle::latestOutputIndexCall {};
        let calldata = call.abi_encode();

        let result = self
            .l1_provider
            .call(
                &alloy_rpc_types::TransactionRequest {
                    to: Some(self.output_oracle.into()),
                    input: alloy_rpc_types::TransactionInput::new(calldata.into()),
                    ..Default::default()
                },
            )
            .await
            .context("Failed to call latestOutputIndex()")?;

        let decoded = L2OutputOracle::latestOutputIndexCall::abi_decode_returns(&result, true)
            .context("Failed to decode latestOutputIndex() return")?;

        Ok(decoded._0.to::<u64>())
    }

    /// Get a specific L2 output by index
    async fn get_l2_output(
        &self,
        index: u64,
    ) -> Result<L2OutputOracle::OutputProposal> {
        let call = L2OutputOracle::getL2OutputCall {
            _l2OutputIndex: U256::from(index),
        };
        let calldata = call.abi_encode();

        let result = self
            .l1_provider
            .call(
                &alloy_rpc_types::TransactionRequest {
                    to: Some(self.output_oracle.into()),
                    input: alloy_rpc_types::TransactionInput::new(calldata.into()),
                    ..Default::default()
                },
            )
            .await
            .with_context(|| format!("Failed to call getL2Output({})", index))?;

        let decoded = L2OutputOracle::getL2OutputCall::abi_decode_returns(&result, true)
            .with_context(|| format!("Failed to decode getL2Output({}) return", index))?;

        Ok(decoded._0)
    }

    /// Get the submission interval (how often outputs are posted)
    async fn get_submission_interval(&self) -> Result<u64> {
        let call = L2OutputOracle::SUBMISSION_INTERVALCall {};
        let calldata = call.abi_encode();

        let result = self
            .l1_provider
            .call(
                &alloy_rpc_types::TransactionRequest {
                    to: Some(self.output_oracle.into()),
                    input: alloy_rpc_types::TransactionInput::new(calldata.into()),
                    ..Default::default()
                },
            )
            .await
            .context("Failed to call SUBMISSION_INTERVAL()")?;

        let decoded =
            L2OutputOracle::SUBMISSION_INTERVALCall::abi_decode_returns(&result, true)
                .context("Failed to decode SUBMISSION_INTERVAL() return")?;

        Ok(decoded._0.to::<u64>())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_addresses() {
        let mainnet_oracle = Network::BaseMainnet.output_oracle_address();
        assert_eq!(
            mainnet_oracle,
            "0x56315b90c40730925ec5485cf004d835058518A0"
                .parse::<Address>()
                .unwrap()
        );

        let sepolia_oracle = Network::BaseSepolia.output_oracle_address();
        assert_eq!(
            sepolia_oracle,
            "0x84457ca9D0163FbC4bbfe4Dfbb20ba46e48DF254"
                .parse::<Address>()
                .unwrap()
        );
    }

    #[test]
    fn test_network_chain_ids() {
        assert_eq!(Network::BaseMainnet.chain_id(), 8453);
        assert_eq!(Network::BaseSepolia.chain_id(), 84532);
    }
}
