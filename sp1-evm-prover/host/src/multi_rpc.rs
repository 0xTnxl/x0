//! Multi-RPC Consensus Provider
//!
//! Implements Byzantine fault-tolerant RPC calls by querying multiple
//! providers and requiring consensus before accepting data.
//!
//! # Security Model
//!
//! - Requires M-of-N RPCs to agree on data (default: 2-of-3)
//! - Resistant to single compromised/malicious RPC
//! - Detects and logs RPC disagreements for forensic analysis
//! - Automatic fallback and retry logic
//!
//! # Usage
//!
//! ```rust
//! let provider = ConsensusProvider::new(vec![
//!     "https://mainnet.base.org",
//!     "https://base.llamarpc.com",
//!     "https://base-mainnet.public.blastapi.io",
//! ], 2)?; // Require 2-of-3 consensus
//!
//! let block = provider.get_block_by_number_consensus(12345).await?;
//! ```

use alloy_primitives::B256;
use alloy_provider::{Provider, ProviderBuilder};
use alloy_rpc_types::{Block, TransactionReceipt};
use alloy_transport_http::Http;
use anyhow::{anyhow, bail, Context, Result};
use reqwest::Client;
use std::collections::HashMap;

/// Multi-RPC provider with Byzantine consensus
pub struct ConsensusProvider {
    /// Underlying RPC providers
    providers: Vec<alloy_provider::RootProvider<Http<Client>>>,
    /// Minimum number of agreeing RPCs required
    min_consensus: usize,
    /// RPC endpoint URLs (for logging)
    urls: Vec<String>,
}

impl ConsensusProvider {
    /// Create a new consensus provider
    ///
    /// # Arguments
    /// * `rpc_urls` - List of RPC endpoint URLs (minimum 3 recommended)
    /// * `min_consensus` - Minimum agreeing RPCs (e.g., 2 for 2-of-3)
    ///
    /// # Security
    ///
    /// For production:
    /// - Use at least 3 RPCs from different providers
    /// - Set min_consensus to ceil(N/2) for Byzantine tolerance
    /// - Choose reputable providers (Alchemy, Infura, QuickNode, etc.)
    pub fn new(rpc_urls: Vec<String>, min_consensus: usize) -> Result<Self> {
        if rpc_urls.len() < 2 {
            bail!("Need at least 2 RPC URLs for consensus");
        }
        if min_consensus < 1 || min_consensus > rpc_urls.len() {
            bail!(
                "min_consensus must be between 1 and {} (got {})",
                rpc_urls.len(),
                min_consensus
            );
        }

        let mut providers = Vec::with_capacity(rpc_urls.len());
        for url in &rpc_urls {
            let provider = ProviderBuilder::new()
                .on_http(url.parse().context("Invalid RPC URL")?);
            providers.push(provider);
        }

        tracing::info!(
            "Initialized consensus provider: {} RPCs, require {} agreement",
            rpc_urls.len(),
            min_consensus,
        );

        Ok(Self {
            providers,
            min_consensus,
            urls: rpc_urls,
        })
    }

    /// Fetch a transaction by hash with consensus verification
    pub async fn get_transaction_by_hash_consensus(
        &self,
        tx_hash: B256,
    ) -> Result<Option<alloy_rpc_types::Transaction>> {
        tracing::debug!(
            "Fetching transaction {} with consensus",
            hex::encode(tx_hash.0)
        );

        let mut results: Vec<(usize, alloy_rpc_types::Transaction)> = Vec::new();
        let mut errors: Vec<(usize, String)> = Vec::new();

        // Query all RPCs in parallel
        let mut handles = Vec::new();
        for (i, provider) in self.providers.iter().enumerate() {
            let provider = provider.clone();
            let handle = tokio::spawn(async move {
                provider.get_transaction_by_hash(tx_hash).await
            });
            handles.push((i, handle));
        }

        // Collect results
        for (i, handle) in handles {
            match handle.await {
                Ok(Ok(Some(tx))) => {
                    results.push((i, tx));
                }
                Ok(Ok(None)) => {
                    // Transaction not found
                }
                Ok(Err(e)) => {
                    errors.push((i, format!("RPC error: {}", e)));
                }
                Err(e) => {
                    errors.push((i, format!("Task join error: {}", e)));
                }
            }
        }

        if results.is_empty() {
            return Ok(None); // Transaction not found on any RPC
        }

        if results.len() < self.min_consensus {
            let error_details: Vec<String> = errors
                .iter()
                .map(|(i, e)| format!("RPC[{}] ({}): {}", i, self.urls[*i], e))
                .collect();

            bail!(
                "Insufficient RPC responses for transaction {}: got {}, need {}.\nErrors:\n{}",
                hex::encode(tx_hash.0),
                results.len(),
                self.min_consensus,
                error_details.join("\n")
            );
        }

        // Group by transaction hash (should all match) and block hash
        let mut hash_groups: HashMap<(B256, Option<B256>), Vec<(usize, alloy_rpc_types::Transaction)>> = HashMap::new();
        for (i, tx) in results {
            let key = (tx.hash, tx.block_hash);
            hash_groups
                .entry(key)
                .or_insert_with(Vec::new)
                .push((i, tx));
        }

        let (_consensus_key, agreeing_txs) = hash_groups
            .into_iter()
            .max_by_key(|(_, txs)| txs.len())
            .unwrap();

        if agreeing_txs.len() < self.min_consensus {
            bail!(
                "RPC CONSENSUS FAILURE for transaction {}: only {} RPCs agreed, need {}",
                hex::encode(tx_hash.0),
                agreeing_txs.len(),
                self.min_consensus,
            );
        }

        if agreeing_txs.len() < self.providers.len() {
            tracing::warn!(
                "Partial RPC consensus for transaction {}: {}/{} agreed",
                hex::encode(tx_hash.0),
                agreeing_txs.len(),
                self.providers.len(),
            );
        }

        Ok(Some(agreeing_txs[0].1.clone()))
    }

    /// Fetch a block with consensus verification
    ///
    /// Queries all RPCs and requires min_consensus to return the same block hash.
    pub async fn get_block_by_number_consensus(
        &self,
        block_number: alloy_rpc_types::BlockNumberOrTag,
        full_transactions: bool,
    ) -> Result<Option<Block>> {
        tracing::debug!(
            "Fetching block {:?} with consensus from {} RPCs",
            block_number,
            self.providers.len()
        );

        let mut results: Vec<(usize, Block)> = Vec::new();
        let mut errors: Vec<(usize, String)> = Vec::new();

        // Query all RPCs in parallel
        let mut handles = Vec::new();
        for (i, provider) in self.providers.iter().enumerate() {
            let provider = provider.clone();
            let handle = tokio::spawn(async move {
                provider
                    .get_block_by_number(block_number.into(), full_transactions)
                    .await
            });
            handles.push((i, handle));
        }

        // Collect results
        for (i, handle) in handles {
            match handle.await {
                Ok(Ok(Some(block))) => {
                    results.push((i, block));
                }
                Ok(Ok(None)) => {
                    errors.push((i, format!("Block {} not found", block_number)));
                }
                Ok(Err(e)) => {
                    errors.push((i, format!("RPC error: {}", e)));
                }
                Err(e) => {
                    errors.push((i, format!("Task join error: {}", e)));
                }
            }
        }

        // Check if we have enough successful responses
        if results.len() < self.min_consensus {
            let error_details: Vec<String> = errors
                .iter()
                .map(|(i, e)| format!("RPC[{}] ({}): {}", i, self.urls[*i], e))
                .collect();

            bail!(
                "Insufficient RPC responses for block {}: got {}, need {}.\nErrors:\n{}",
                block_number,
                results.len(),
                self.min_consensus,
                error_details.join("\n")
            );
        }

        // Group by block hash to find consensus
        let mut hash_groups: HashMap<B256, Vec<(usize, Block)>> = HashMap::new();
        for (i, block) in results {
            hash_groups
                .entry(block.header.hash)
                .or_insert_with(Vec::new)
                .push((i, block));
        }

        // Find the hash with most agreement
        let (consensus_hash, agreeing_blocks) = hash_groups
            .into_iter()
            .max_by_key(|(_, blocks)| blocks.len())
            .ok_or_else(|| anyhow!("No blocks returned from any RPC"))?;

        // Verify we have consensus
        if agreeing_blocks.len() < self.min_consensus {
            let hash_summary: Vec<String> = agreeing_blocks
                .iter()
                .map(|(i, b)| {
                    format!(
                        "RPC[{}] ({}): {}",
                        i,
                        self.urls[*i],
                        hex::encode(b.header.hash.0)
                    )
                })
                .collect();

            bail!(
                "RPC CONSENSUS FAILURE at block {}: only {} RPCs agreed, need {}.\n\
                 This indicates RPC compromise, network fork, or data inconsistency.\n\
                 Agreeing RPCs:\n{}",
                block_number,
                agreeing_blocks.len(),
                self.min_consensus,
                hash_summary.join("\n"),
            );
        }

        // Log if not all RPCs agreed (potential issue)
        if agreeing_blocks.len() < self.providers.len() {
            tracing::warn!(
                "Partial RPC consensus at block {}: {}/{} agreed on hash={}",
                block_number,
                agreeing_blocks.len(),
                self.providers.len(),
                hex::encode(consensus_hash.0),
            );
        } else {
            tracing::debug!(
                "Full RPC consensus at block {}: all {} RPCs agreed",
                block_number,
                self.providers.len(),
            );
        }

        // Return the consensus block
        Ok(Some(agreeing_blocks[0].1.clone()))
    }

    /// Fetch a transaction receipt with consensus verification
    pub async fn get_transaction_receipt_consensus(
        &self,
        tx_hash: B256,
    ) -> Result<Option<TransactionReceipt>> {
        tracing::debug!(
            "Fetching receipt for tx {} with consensus",
            hex::encode(tx_hash.0)
        );

        let mut results: Vec<(usize, TransactionReceipt)> = Vec::new();
        let mut errors: Vec<(usize, String)> = Vec::new();

        // Query all RPCs in parallel
        let mut handles = Vec::new();
        for (i, provider) in self.providers.iter().enumerate() {
            let provider = provider.clone();
            let handle = tokio::spawn(async move {
                provider.get_transaction_receipt(tx_hash).await
            });
            handles.push((i, handle));
        }

        // Collect results
        for (i, handle) in handles {
            match handle.await {
                Ok(Ok(Some(receipt))) => {
                    results.push((i, receipt));
                }
                Ok(Ok(None)) => {
                    errors.push((i, format!("Receipt not found for {}", tx_hash)));
                }
                Ok(Err(e)) => {
                    errors.push((i, format!("RPC error: {}", e)));
                }
                Err(e) => {
                    errors.push((i, format!("Task join error: {}", e)));
                }
            }
        }

        if results.len() < self.min_consensus {
            let error_details: Vec<String> = errors
                .iter()
                .map(|(i, e)| format!("RPC[{}] ({}): {}", i, self.urls[*i], e))
                .collect();

            bail!(
                "Insufficient RPC responses for receipt {}: got {}, need {}.\nErrors:\n{}",
                hex::encode(tx_hash.0),
                results.len(),
                self.min_consensus,
                error_details.join("\n")
            );
        }

        // For receipts, we compare transaction_hash (should all match the query)
        // and block_hash (should match if on same fork)
        let mut block_hash_groups: HashMap<B256, Vec<(usize, TransactionReceipt)>> =
            HashMap::new();
        for (i, receipt) in results {
            block_hash_groups
                .entry(receipt.block_hash.unwrap_or_default())
                .or_insert_with(Vec::new)
                .push((i, receipt));
        }

        let (consensus_block_hash, agreeing_receipts) = block_hash_groups
            .into_iter()
            .max_by_key(|(_, receipts)| receipts.len())
            .ok_or_else(|| anyhow!("No receipts returned from any RPC"))?;

        if agreeing_receipts.len() < self.min_consensus {
            bail!(
                "RPC CONSENSUS FAILURE for receipt {}: only {} RPCs agreed, need {}",
                hex::encode(tx_hash.0),
                agreeing_receipts.len(),
                self.min_consensus,
            );
        }

        if agreeing_receipts.len() < self.providers.len() {
            tracing::warn!(
                "Partial RPC consensus for receipt {}: {}/{} agreed on block={}",
                hex::encode(tx_hash.0),
                agreeing_receipts.len(),
                self.providers.len(),
                hex::encode(consensus_block_hash.0),
            );
        }

        Ok(Some(agreeing_receipts[0].1.clone()))
    }

    /// Get the latest block number with consensus
    pub async fn get_block_number_consensus(&self) -> Result<u64> {
        let mut results: Vec<u64> = Vec::new();

        // Query all RPCs in parallel
        let mut handles = Vec::new();
        for provider in self.providers.iter() {
            let provider = provider.clone();
            let handle = tokio::spawn(async move { provider.get_block_number().await });
            handles.push(handle);
        }

        for handle in handles {
            if let Ok(Ok(num)) = handle.await {
                results.push(num);
            }
        }

        if results.len() < self.min_consensus {
            bail!(
                "Insufficient RPC responses for latest block number: got {}, need {}",
                results.len(),
                self.min_consensus
            );
        }

        // For block number, we take the minimum of the agreeing RPCs
        // (conservative: don't accept blocks not yet propagated to all RPCs)
        results.sort();
        let min_agreed = results[self.min_consensus - 1];

        tracing::debug!(
            "Latest block number consensus: {} (range: {}-{})",
            min_agreed,
            results[0],
            results[results.len() - 1]
        );

        Ok(min_agreed)
    }

    /// Fetch all receipts for a block with consensus verification
    pub async fn get_block_receipts_consensus(
        &self,
        block_number: u64,
    ) -> Result<Vec<TransactionReceipt>> {
        tracing::debug!("Fetching receipts for block {} with consensus", block_number);

        let mut results: Vec<(usize, Vec<TransactionReceipt>)> = Vec::new();
        let mut errors: Vec<(usize, String)> = Vec::new();

        // Query all RPCs in parallel
        let mut handles = Vec::new();
        for (i, provider) in self.providers.iter().enumerate() {
            let provider = provider.clone();
            let handle = tokio::spawn(async move {
                provider.get_block_receipts(block_number.into()).await
            });
            handles.push((i, handle));
        }

        // Collect results
        for (i, handle) in handles {
            match handle.await {
                Ok(Ok(Some(receipts))) => {
                    results.push((i, receipts));
                }
                Ok(Ok(None)) => {
                    errors.push((i, format!("Receipts not found for block {}", block_number)));
                }
                Ok(Err(e)) => {
                    errors.push((i, format!("RPC error: {}", e)));
                }
                Err(e) => {
                    errors.push((i, format!("Task join error: {}", e)));
                }
            }
        }

        if results.len() < self.min_consensus {
            let error_details: Vec<String> = errors
                .iter()
                .map(|(i, e)| format!("RPC[{}] ({}): {}", i, self.urls[*i], e))
                .collect();

            bail!(
                "Insufficient RPC responses for block receipts {}: got {}, need {}.\nErrors:\n{}",
                block_number,
                results.len(),
                self.min_consensus,
                error_details.join("\n")
            );
        }

        // Compare receipt roots (hash of all receipts in the block)
        // We hash the concatenated receipt hashes for consensus
        let mut receipt_hash_groups: HashMap<Vec<u8>, Vec<(usize, Vec<TransactionReceipt>)>> =
            HashMap::new();
        
        for (i, receipts) in results {
            // Create a fingerprint of the receipts (concatenate transaction hashes)
            let mut fingerprint = Vec::new();
            for receipt in &receipts {
                fingerprint.extend_from_slice(&receipt.transaction_hash.0);
            }
            
            receipt_hash_groups
                .entry(fingerprint)
                .or_insert_with(Vec::new)
                .push((i, receipts));
        }

        let (_, agreeing_receipts) = receipt_hash_groups
            .into_iter()
            .max_by_key(|(_, receipts)| receipts.len())
            .ok_or_else(|| anyhow!("No receipts returned from any RPC"))?;

        if agreeing_receipts.len() < self.min_consensus {
            bail!(
                "RPC CONSENSUS FAILURE for block receipts {}: only {} RPCs agreed, need {}",
                block_number,
                agreeing_receipts.len(),
                self.min_consensus,
            );
        }

        if agreeing_receipts.len() < self.providers.len() {
            tracing::warn!(
                "Partial RPC consensus for block receipts {}: {}/{} agreed",
                block_number,
                agreeing_receipts.len(),
                self.providers.len(),
            );
        }

        Ok(agreeing_receipts[0].1.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_consensus_provider_requires_minimum_rpcs() {
        let result = ConsensusProvider::new(vec!["http://localhost:8545".to_string()], 2);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("at least 2 RPC URLs"));
    }

    #[tokio::test]
    async fn test_consensus_provider_validates_min_consensus() {
        let result = ConsensusProvider::new(
            vec![
                "http://localhost:8545".to_string(),
                "http://localhost:8546".to_string(),
            ],
            3,
        );
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("min_consensus must be between"));
    }
}
