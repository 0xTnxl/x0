//! Whitelist implementations for x0-01 protocol
//!
//! Supports three whitelist modes:
//! - Merkle: High security, exact address verification with off-chain proofs
//! - Bloom: Dynamic whitelist with probabilistic verification (1% FP rate)
//! - Domain: Partner networks with address prefix matching

use anchor_lang::prelude::*;
use sha2::{Digest, Sha256};
use solana_program::pubkey::Pubkey;

use crate::constants::*;

// ============================================================================
// Whitelist Mode Enum
// ============================================================================

/// The whitelist verification mode for an agent policy
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug, PartialEq, Default)]
pub enum WhitelistMode {
    /// No whitelist - all recipients allowed (dangerous, not recommended)
    #[default]
    None,

    /// Merkle tree verification with off-chain proof
    Merkle,

    /// Bloom filter probabilistic verification
    Bloom,

    /// Domain prefix matching for partner networks
    Domain,
}

// ============================================================================
// Whitelist Data Structures
// ============================================================================

/// Mode-specific whitelist data storage
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug, PartialEq, Default)]
pub enum WhitelistData {
    /// No whitelist data
    #[default]
    None,

    /// Merkle root for proof verification
    Merkle {
        /// The 32-byte Merkle root
        root: [u8; 32],
    },

    /// Bloom filter for probabilistic verification
    Bloom {
        /// The Bloom filter structure
        filter: BloomFilter,
    },

    /// Allowed address prefixes for domain matching
    Domain {
        /// List of allowed 8-byte address prefixes
        allowed_prefixes: Vec<[u8; DOMAIN_PREFIX_LENGTH]>,
    },
}

impl WhitelistData {
    /// Verify a recipient against this whitelist data
    pub fn verify(
        &self,
        recipient: &Pubkey,
        merkle_proof: Option<&MerkleProof>,
    ) -> Result<bool> {
        match self {
            WhitelistData::None => Ok(true), // No whitelist means all allowed
            
            WhitelistData::Merkle { root } => {
                let proof = merkle_proof.ok_or(error!(WhitelistError::MissingMerkleProof))?;
                Ok(verify_merkle_whitelist(recipient, &proof.path, root))
            }
            
            WhitelistData::Bloom { filter } => {
                Ok(verify_bloom_whitelist(recipient, filter))
            }
            
            WhitelistData::Domain { allowed_prefixes } => {
                Ok(verify_domain_whitelist(recipient, allowed_prefixes))
            }
        }
    }
}

// ============================================================================
// Merkle Whitelist
// ============================================================================

/// A Merkle proof for whitelist verification
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug, PartialEq)]
pub struct MerkleProof {
    /// The sibling hashes from leaf to root
    pub path: Vec<[u8; 32]>,
}

impl MerkleProof {
    /// Maximum serialized size
    pub const fn max_size() -> usize {
        4 + (MAX_MERKLE_PROOF_DEPTH * 32)
    }
}

/// Verify a recipient is in the Merkle whitelist
///
/// # Arguments
/// * `recipient` - The recipient's public key
/// * `proof` - Array of sibling hashes from leaf to root (max depth: MAX_MERKLE_PROOF_DEPTH)
/// * `root` - The expected Merkle root
///
/// # Returns
/// `true` if the proof is valid, `false` otherwise
///
/// # Security
/// - Depth is limited to MAX_MERKLE_PROOF_DEPTH (14) to prevent DoS via deep proof trees (HIGH-4)
/// - Each proof element requires ~2000 CU, so max depth limits compute usage to ~28,000 CU
///
/// # Performance (LOW-1)
/// Uses canonical ordering: smaller hash always goes first. This is more efficient
/// than sorting because it uses a single comparison instead of a full sort.
pub fn verify_merkle_whitelist(
    recipient: &Pubkey,
    proof: &[[u8; 32]],
    root: &[u8; 32],
) -> bool {
    // HIGH-4: Prevent DoS via excessively deep Merkle proofs
    // MAX_MERKLE_PROOF_DEPTH = 14 supports up to 16,384 addresses
    if proof.len() > MAX_MERKLE_PROOF_DEPTH {
        msg!("Merkle proof depth {} exceeds maximum {}", proof.len(), MAX_MERKLE_PROOF_DEPTH);
        return false;
    }

    // Hash the recipient public key as the leaf
    let mut hasher = Sha256::new();
    hasher.update(recipient.as_ref());
    let mut current: [u8; 32] = hasher.finalize().into();

    // Walk up the tree, combining with siblings
    // LOW-1 FIX: Use canonical ordering (min first, max second) for efficiency
    // This avoids repeated comparisons by using simple byte comparison
    for sibling in proof {
        let mut hasher = Sha256::new();
        
        // Canonical ordering: smaller hash comes first
        // This is O(1) comparison vs O(n log n) sort
        let (first, second) = if current < *sibling {
            (&current, sibling)
        } else {
            (sibling, &current)
        };
        
        hasher.update(first);
        hasher.update(second);
        
        current = hasher.finalize().into();
    }

    current == *root
}

/// Build a Merkle tree from a list of addresses and return the root
///
/// # Arguments
/// * `addresses` - List of whitelisted addresses
///
/// # Returns
/// The 32-byte Merkle root
pub fn build_merkle_root(addresses: &[Pubkey]) -> [u8; 32] {
    if addresses.is_empty() {
        return [0u8; 32];
    }

    // Hash all leaves
    let mut hashes: Vec<[u8; 32]> = addresses
        .iter()
        .map(|addr| {
            let mut hasher = Sha256::new();
            hasher.update(addr.as_ref());
            hasher.finalize().into()
        })
        .collect();

    // Pad to power of 2
    while hashes.len() & (hashes.len() - 1) != 0 {
        hashes.push([0u8; 32]);
    }

    // Build tree bottom-up
    while hashes.len() > 1 {
        let mut next_level = Vec::with_capacity(hashes.len() / 2);
        
        for chunk in hashes.chunks(2) {
            let mut hasher = Sha256::new();
            
            // Sort for consistent ordering
            if chunk[0] < chunk[1] {
                hasher.update(&chunk[0]);
                hasher.update(&chunk[1]);
            } else {
                hasher.update(&chunk[1]);
                hasher.update(&chunk[0]);
            }
            
            next_level.push(hasher.finalize().into());
        }
        
        hashes = next_level;
    }

    hashes[0]
}

/// Generate a Merkle proof for a specific address
///
/// # Arguments
/// * `addresses` - List of all whitelisted addresses
/// * `target` - The address to generate proof for
///
/// # Returns
/// `Some(MerkleProof)` if address is in list, `None` otherwise
pub fn generate_merkle_proof(addresses: &[Pubkey], target: &Pubkey) -> Option<MerkleProof> {
    let target_index = addresses.iter().position(|a| a == target)?;

    // Hash all leaves
    let mut hashes: Vec<[u8; 32]> = addresses
        .iter()
        .map(|addr| {
            let mut hasher = Sha256::new();
            hasher.update(addr.as_ref());
            hasher.finalize().into()
        })
        .collect();

    // Pad to power of 2
    while hashes.len() & (hashes.len() - 1) != 0 {
        hashes.push([0u8; 32]);
    }

    let mut proof_path = Vec::new();
    let mut index = target_index;

    // Build proof as we build tree
    while hashes.len() > 1 {
        // Get sibling index
        let sibling_index = if index % 2 == 0 { index + 1 } else { index - 1 };
        
        if sibling_index < hashes.len() {
            proof_path.push(hashes[sibling_index]);
        }

        // Build next level
        let mut next_level = Vec::with_capacity(hashes.len() / 2);
        for chunk in hashes.chunks(2) {
            let mut hasher = Sha256::new();
            if chunk[0] < chunk[1] {
                hasher.update(&chunk[0]);
                hasher.update(&chunk[1]);
            } else {
                hasher.update(&chunk[1]);
                hasher.update(&chunk[0]);
            }
            next_level.push(hasher.finalize().into());
        }
        
        hashes = next_level;
        index /= 2;
    }

    Some(MerkleProof { path: proof_path })
}

// ============================================================================
// Bloom Filter Whitelist
// ============================================================================

/// A Bloom filter for probabilistic whitelist verification
///
/// # Security Warning (HIGH-3: Bloom Filter False Positives)
///
/// Bloom filters have inherent false positive rates. With default configuration
/// (4KB filter, 7 hash functions, ~1000 items), the false positive rate is ~1%.
///
/// ## Attack Vector
/// An attacker could brute-force Pubkeys that hash to the same Bloom filter
/// positions as whitelisted addresses, potentially bypassing the whitelist.
///
/// ## False Positive Rate Calculation
/// - p = (1 - e^(-kn/m))^k
/// - With m=32768 bits, k=7 hashes, n=1000 items: p ≈ 0.82%
/// - With n=500 items: p ≈ 0.08%
///
/// ## Mitigation Recommendations
/// 1. For high-security policies, use Merkle mode instead
/// 2. Use Bloom as a first-pass filter, then verify via off-chain oracle
/// 3. Monitor for unusual transfer patterns that might indicate false positive exploitation
/// 4. Consider hybrid approach: Bloom filter + Merkle proof confirmation
///
/// ## Brute Force Cost Estimate
/// With 1% false positive rate, an attacker needs ~100 Pubkey generations
/// to find a collision. Each keypair generation is fast, so this is NOT
/// sufficient protection for high-value transfers.
///
/// ## Recommended Use Cases
/// - Low-value, high-volume transfers where speed matters
/// - Non-critical whitelists with monitoring
/// - As a deny-list rather than allow-list (false positives = extra blocks)
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug, PartialEq)]
pub struct BloomFilter {
    /// The bit array (4KB = 32,768 bits for ~1000 items @ 1% FP)
    pub bits: Vec<u8>,
    
    /// Number of hash functions (k)
    pub hash_count: u8,
}

impl Default for BloomFilter {
    fn default() -> Self {
        Self::new(BLOOM_FILTER_SIZE_BYTES, BLOOM_HASH_COUNT)
    }
}

impl BloomFilter {
    /// Create a new Bloom filter with specified size
    pub fn new(size_bytes: usize, hash_count: u8) -> Self {
        Self {
            bits: vec![0u8; size_bytes],
            hash_count,
        }
    }

    /// Calculate optimal filter parameters for given item count and FP rate
    ///
    /// # Arguments
    /// * `expected_items` - Expected number of items to insert
    /// * `false_positive_rate` - Desired false positive rate (e.g., 0.01 for 1%)
    ///
    /// # Returns
    /// (size_bytes, hash_count)
    pub fn optimal_params(expected_items: usize, false_positive_rate: f64) -> (usize, u8) {
        // m = -n * ln(p) / (ln(2)^2)
        let n = expected_items as f64;
        let p = false_positive_rate;
        let ln2_sq = std::f64::consts::LN_2 * std::f64::consts::LN_2;
        
        let m_bits = -n * p.ln() / ln2_sq;
        let m_bytes = ((m_bits / 8.0).ceil() as usize).max(1);
        
        // k = (m/n) * ln(2)
        let k = ((m_bits / n) * std::f64::consts::LN_2).round() as u8;
        let k = k.max(1).min(16);
        
        (m_bytes, k)
    }

    /// Add an address to the Bloom filter
    pub fn insert(&mut self, address: &Pubkey) {
        let bits_len = self.bits.len() * 8;
        
        for i in 0..self.hash_count {
            let hash = Self::hash_with_index(address, i);
            let bit_index = (hash % bits_len as u64) as usize;
            let byte_index = bit_index / 8;
            let bit_position = bit_index % 8;
            
            self.bits[byte_index] |= 1 << bit_position;
        }
    }

    /// Check if an address might be in the filter
    pub fn contains(&self, address: &Pubkey) -> bool {
        let bits_len = self.bits.len() * 8;
        
        for i in 0..self.hash_count {
            let hash = Self::hash_with_index(address, i);
            let bit_index = (hash % bits_len as u64) as usize;
            let byte_index = bit_index / 8;
            let bit_position = bit_index % 8;
            
            if (self.bits[byte_index] & (1 << bit_position)) == 0 {
                return false;
            }
        }
        
        true // Possibly in set (or false positive)
    }

    /// LOW-6: Calculate the saturation ratio of the Bloom filter
    /// Returns a value between 0.0 (empty) and 1.0 (fully saturated)
    /// 
    /// # Warning Thresholds
    /// - < 0.5: Healthy - expected false positive rate is low
    /// - 0.5-0.7: Warning - false positive rate is increasing
    /// - > 0.7: Critical - filter is saturated, high false positive rate
    pub fn saturation_ratio(&self) -> f64 {
        let total_bits = self.bits.len() * 8;
        let set_bits = self.count_set_bits();
        set_bits as f64 / total_bits as f64
    }

    /// LOW-6: Count the number of set bits in the filter
    pub fn count_set_bits(&self) -> usize {
        self.bits.iter().map(|byte| byte.count_ones() as usize).sum()
    }

    /// LOW-6: Check if the filter is saturated (high false positive risk)
    /// Returns true if saturation exceeds 70% threshold
    pub fn is_saturated(&self) -> bool {
        self.saturation_ratio() > 0.7
    }

    /// LOW-6: Estimate the current false positive rate based on saturation
    /// Uses formula: (1 - e^(-kn/m))^k where k=hash_count, n=items, m=bits
    /// Approximated here using saturation ratio
    pub fn estimated_false_positive_rate(&self) -> f64 {
        let saturation = self.saturation_ratio();
        saturation.powi(self.hash_count as i32)
    }

    /// Hash an address with an index to get different hash values
    fn hash_with_index(address: &Pubkey, index: u8) -> u64 {
        let mut hasher = Sha256::new();
        hasher.update(address.as_ref());
        hasher.update(&[index]);
        
        let hash = hasher.finalize();
        u64::from_le_bytes(hash[0..8].try_into().unwrap())
    }
}

/// Verify a recipient might be in the Bloom filter whitelist
pub fn verify_bloom_whitelist(recipient: &Pubkey, filter: &BloomFilter) -> bool {
    filter.contains(recipient)
}

// ============================================================================
// Domain Prefix Whitelist
// ============================================================================

/// Verify a recipient's address starts with an allowed prefix
pub fn verify_domain_whitelist(
    recipient: &Pubkey,
    allowed_prefixes: &[[u8; DOMAIN_PREFIX_LENGTH]],
) -> bool {
    let recipient_bytes = recipient.as_ref();
    let recipient_prefix: [u8; DOMAIN_PREFIX_LENGTH] = recipient_bytes[0..DOMAIN_PREFIX_LENGTH]
        .try_into()
        .unwrap();
    
    allowed_prefixes.contains(&recipient_prefix)
}

/// Extract the domain prefix from a public key
pub fn extract_domain_prefix(pubkey: &Pubkey) -> [u8; DOMAIN_PREFIX_LENGTH] {
    pubkey.as_ref()[0..DOMAIN_PREFIX_LENGTH].try_into().unwrap()
}

// ============================================================================
// Whitelist Error
// ============================================================================

#[error_code]
pub enum WhitelistError {
    #[msg("Merkle proof is required but not provided")]
    MissingMerkleProof,
    
    #[msg("Merkle proof is invalid")]
    InvalidMerkleProof,
    
    #[msg("Bloom filter is corrupted")]
    CorruptedBloomFilter,
    
    #[msg("Too many domain prefixes")]
    TooManyDomainPrefixes,
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_proof_single() {
        let addresses = vec![
            Pubkey::new_unique(),
        ];
        
        let root = build_merkle_root(&addresses);
        let proof = generate_merkle_proof(&addresses, &addresses[0]).unwrap();
        
        assert!(verify_merkle_whitelist(&addresses[0], &proof.path, &root));
    }

    #[test]
    fn test_merkle_proof_multiple() {
        let addresses: Vec<Pubkey> = (0..10).map(|_| Pubkey::new_unique()).collect();
        
        let root = build_merkle_root(&addresses);
        
        for addr in &addresses {
            let proof = generate_merkle_proof(&addresses, addr).unwrap();
            assert!(verify_merkle_whitelist(addr, &proof.path, &root));
        }
        
        // Test non-whitelisted address fails
        let non_listed = Pubkey::new_unique();
        assert!(!verify_merkle_whitelist(&non_listed, &[], &root));
    }

    #[test]
    fn test_bloom_filter() {
        let mut filter = BloomFilter::new(512, 7);
        
        let addresses: Vec<Pubkey> = (0..100).map(|_| Pubkey::new_unique()).collect();
        
        for addr in &addresses {
            filter.insert(addr);
        }
        
        // All inserted addresses should be found
        for addr in &addresses {
            assert!(filter.contains(addr));
        }
    }

    #[test]
    fn test_bloom_filter_false_positive_rate() {
        let (size, hash_count) = BloomFilter::optimal_params(1000, 0.01);
        let mut filter = BloomFilter::new(size, hash_count);
        
        // Insert 1000 addresses
        let addresses: Vec<Pubkey> = (0..1000).map(|_| Pubkey::new_unique()).collect();
        for addr in &addresses {
            filter.insert(addr);
        }
        
        // Test 10000 non-inserted addresses for false positives
        let mut false_positives = 0;
        for _ in 0..10000 {
            let test_addr = Pubkey::new_unique();
            if filter.contains(&test_addr) {
                false_positives += 1;
            }
        }
        
        // Should be around 1% (100 out of 10000), allow some variance
        let fp_rate = false_positives as f64 / 10000.0;
        assert!(fp_rate < 0.02, "False positive rate too high: {}", fp_rate);
    }

    #[test]
    fn test_domain_prefix_whitelist() {
        let addr1 = Pubkey::new_unique();
        let addr2 = Pubkey::new_unique();
        
        let prefix1 = extract_domain_prefix(&addr1);
        let prefix2 = extract_domain_prefix(&addr2);
        
        let allowed = vec![prefix1, prefix2];
        
        assert!(verify_domain_whitelist(&addr1, &allowed));
        assert!(verify_domain_whitelist(&addr2, &allowed));
        
        let addr3 = Pubkey::new_unique();
        // Very unlikely to have same prefix by chance
        if extract_domain_prefix(&addr3) != prefix1 && extract_domain_prefix(&addr3) != prefix2 {
            assert!(!verify_domain_whitelist(&addr3, &allowed));
        }
    }
}
