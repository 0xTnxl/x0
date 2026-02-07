/**
 * Utility functions for x0-01 protocol
 */

import { PublicKey } from "@solana/web3.js";
import { createHash } from "crypto";
import BN from "bn.js";
import {
  X0_GUARD_PROGRAM_ID,
  X0_ESCROW_PROGRAM_ID,
  X0_REGISTRY_PROGRAM_ID,
  X0_REPUTATION_PROGRAM_ID,
  PDA_SEEDS,
  PROTOCOL_FEE_BASIS_POINTS,
  FEE_DENOMINATOR,
  ROLLING_WINDOW_SECONDS,
  BLINK_EXPIRY_SECONDS,
} from "./constants";

// ============================================================================
// Fee Calculations
// ============================================================================

/**
 * Calculate the protocol fee for a given transfer amount
 * @param amount - Transfer amount in token micro-units
 * @returns Fee amount in token micro-units
 */
export function calculateProtocolFee(amount: BN): BN {
  return amount.mul(new BN(PROTOCOL_FEE_BASIS_POINTS)).div(new BN(FEE_DENOMINATOR));
}

/**
 * Calculate the amount after fee deduction
 * @param amount - Original amount
 * @returns Amount after fee
 */
export function amountAfterFee(amount: BN): BN {
  return amount.sub(calculateProtocolFee(amount));
}

// ============================================================================
// Instruction Discriminator
// ============================================================================

/**
 * Compute the Anchor instruction discriminator for a given instruction name.
 * This is the first 8 bytes of SHA-256("global:{instruction_name}").
 *
 * @param name - The snake_case instruction name (e.g., "initialize_policy")
 * @returns 8-byte Buffer discriminator
 */
export function getInstructionDiscriminator(name: string): Buffer {
  const hash = createHash("sha256")
    .update(`global:${name}`)
    .digest();
  return Buffer.from(hash.subarray(0, 8));
}

// ============================================================================
// Hash Utilities
// ============================================================================

/**
 * Compute SHA256 hash of data
 * @param data - Data to hash
 * @returns 32-byte hash
 */
export function sha256(data: Buffer | Uint8Array | string): Uint8Array {
  const hash = createHash("sha256");
  hash.update(typeof data === "string" ? Buffer.from(data) : data);
  return new Uint8Array(hash.digest());
}

/**
 * Compute memo hash from resource identifier
 * @param resourceId - Resource identifier string
 * @returns 32-byte hash
 */
export function computeMemoHash(resourceId: string): Uint8Array {
  return sha256(resourceId);
}

/**
 * Compute payment challenge hash
 * @param recipient - Recipient public key
 * @param amount - Transfer amount
 * @param nonce - Challenge nonce
 * @returns 32-byte hash
 */
export function computeChallengeHash(
  recipient: PublicKey,
  amount: BN,
  nonce: Uint8Array
): Uint8Array {
  const data = Buffer.concat([
    recipient.toBuffer(),
    amount.toArrayLike(Buffer, "le", 8),
    Buffer.from(nonce),
  ]);
  return sha256(data);
}

// ============================================================================
// Time Utilities
// ============================================================================

/**
 * Get current Unix timestamp in seconds
 */
export function now(): number {
  return Math.floor(Date.now() / 1000);
}

/**
 * Check if a timestamp is within the valid range
 * @param timestamp - Timestamp to check
 * @param currentTimestamp - Current timestamp (defaults to now)
 */
export function isValidTimestamp(
  timestamp: number,
  currentTimestamp: number = now()
): boolean {
  const maxFuture = currentTimestamp + 60;
  const maxPast = currentTimestamp - ROLLING_WINDOW_SECONDS;
  return timestamp <= maxFuture && timestamp >= maxPast;
}

/**
 * Check if a Blink has expired
 * @param blinkCreatedAt - When the Blink was created
 * @param currentTimestamp - Current timestamp (defaults to now)
 */
export function isBlinkExpired(
  blinkCreatedAt: number,
  currentTimestamp: number = now()
): boolean {
  return currentTimestamp > blinkCreatedAt + BLINK_EXPIRY_SECONDS;
}

/**
 * Format a timestamp as ISO string
 */
export function formatTimestamp(timestamp: number): string {
  return new Date(timestamp * 1000).toISOString();
}

// ============================================================================
// PDA Derivation
// ============================================================================

/**
 * Derive the AgentPolicy PDA for an owner
 * @param owner - Owner's public key
 * @returns [PDA address, bump seed]
 */
export function deriveAgentPolicyPda(owner: PublicKey): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [PDA_SEEDS.AGENT_POLICY, owner.toBuffer()],
    X0_GUARD_PROGRAM_ID
  );
}

/**
 * Derive the Escrow PDA
 * @param buyer - Buyer's public key
 * @param seller - Seller's public key
 * @param memoHash - Service memo hash
 * @returns [PDA address, bump seed]
 */
export function deriveEscrowPda(
  buyer: PublicKey,
  seller: PublicKey,
  memoHash: Uint8Array
): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [
      PDA_SEEDS.ESCROW,
      buyer.toBuffer(),
      seller.toBuffer(),
      Buffer.from(memoHash),
    ],
    X0_ESCROW_PROGRAM_ID
  );
}

/**
 * Derive the Registry PDA for an agent
 * @param agentId - Agent's policy PDA
 * @returns [PDA address, bump seed]
 */
export function deriveRegistryPda(agentId: PublicKey): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [PDA_SEEDS.REGISTRY, agentId.toBuffer()],
    X0_REGISTRY_PROGRAM_ID
  );
}

/**
 * Derive the Reputation PDA for an agent
 * @param agentId - Agent's policy PDA
 * @returns [PDA address, bump seed]
 */
export function deriveReputationPda(agentId: PublicKey): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [PDA_SEEDS.REPUTATION, agentId.toBuffer()],
    X0_REPUTATION_PROGRAM_ID
  );
}

// ============================================================================
// Amount Formatting
// ============================================================================

/**
 * Format token amount with decimals
 * @param amount - Amount in micro-units
 * @param decimals - Token decimals (default 6)
 * @returns Formatted string
 */
export function formatAmount(amount: BN, decimals: number = 6): string {
  const divisor = new BN(10).pow(new BN(decimals));
  const whole = amount.div(divisor);
  const fraction = amount.mod(divisor);
  
  const fractionStr = fraction.toString().padStart(decimals, "0");
  const trimmedFraction = fractionStr.replace(/0+$/, "");
  
  if (trimmedFraction) {
    return `${whole.toString()}.${trimmedFraction}`;
  }
  return whole.toString();
}

/**
 * Parse token amount string to micro-units
 * @param amountStr - Amount string (e.g., "100.5")
 * @param decimals - Token decimals (default 6)
 * @returns Amount in micro-units
 */
export function parseAmount(amountStr: string, decimals: number = 6): BN {
  const parts = amountStr.split(".");
  const whole = parts[0] ?? "0";
  const fraction = (parts[1] ?? "").padEnd(decimals, "0").slice(0, decimals);
  
  return new BN(whole + fraction);
}

// ============================================================================
// Validation
// ============================================================================

/**
 * Validate an endpoint URL
 * @param endpoint - URL to validate
 * @throws If URL is invalid
 */
export function validateEndpoint(endpoint: string): void {
  if (!endpoint || endpoint.length === 0) {
    throw new Error("Endpoint cannot be empty");
  }
  if (endpoint.length > 256) {
    throw new Error("Endpoint too long (max 256 characters)");
  }
  if (!endpoint.startsWith("https://") && !endpoint.startsWith("http://")) {
    throw new Error("Endpoint must start with http:// or https://");
  }
}

/**
 * Validate a capability type
 * @param type - Capability type string
 * @throws If type is invalid
 */
export function validateCapabilityType(type: string): void {
  if (!type || type.length === 0) {
    throw new Error("Capability type cannot be empty");
  }
  if (type.length > 64) {
    throw new Error("Capability type too long (max 64 characters)");
  }
  if (!/^[a-zA-Z0-9-]+$/.test(type)) {
    throw new Error("Capability type can only contain alphanumeric characters and hyphens");
  }
}

// ============================================================================
// Merkle Tree Utilities
// ============================================================================

/**
 * Build a Merkle root from a list of addresses
 * @param addresses - List of whitelisted addresses
 * @returns 32-byte Merkle root
 */
export function buildMerkleRoot(addresses: PublicKey[]): Uint8Array {
  if (addresses.length === 0) {
    return new Uint8Array(32);
  }

  // Hash all leaves
  let hashes = addresses.map((addr) => sha256(addr.toBuffer()));

  // Pad to power of 2
  while (hashes.length & (hashes.length - 1)) {
    hashes.push(new Uint8Array(32));
  }

  // Build tree bottom-up
  while (hashes.length > 1) {
    const nextLevel: Uint8Array[] = [];
    for (let i = 0; i < hashes.length; i += 2) {
      const left = hashes[i]!;
      const right = hashes[i + 1]!;
      
      // Sort for consistent ordering
      const [first, second] = compareBytes(left, right) < 0 
        ? [left, right] 
        : [right, left];
      
      nextLevel.push(sha256(Buffer.concat([Buffer.from(first), Buffer.from(second)])));
    }
    hashes = nextLevel;
  }

  return hashes[0]!;
}

/**
 * Generate a Merkle proof for a specific address
 * @param addresses - List of all whitelisted addresses
 * @param target - Address to generate proof for
 * @returns Merkle proof or null if address not in list
 */
export function generateMerkleProof(
  addresses: PublicKey[],
  target: PublicKey
): Uint8Array[] | null {
  const targetIndex = addresses.findIndex((a) => a.equals(target));
  if (targetIndex === -1) {
    return null;
  }

  // Hash all leaves
  let hashes = addresses.map((addr) => sha256(addr.toBuffer()));

  // Pad to power of 2
  while (hashes.length & (hashes.length - 1)) {
    hashes.push(new Uint8Array(32));
  }

  const proof: Uint8Array[] = [];
  let index = targetIndex;

  // Build proof as we build tree
  while (hashes.length > 1) {
    const siblingIndex = index % 2 === 0 ? index + 1 : index - 1;
    if (siblingIndex < hashes.length) {
      proof.push(hashes[siblingIndex]!);
    }

    // Build next level
    const nextLevel: Uint8Array[] = [];
    for (let i = 0; i < hashes.length; i += 2) {
      const left = hashes[i]!;
      const right = hashes[i + 1]!;
      
      const [first, second] = compareBytes(left, right) < 0 
        ? [left, right] 
        : [right, left];
      
      nextLevel.push(sha256(Buffer.concat([Buffer.from(first), Buffer.from(second)])));
    }
    
    hashes = nextLevel;
    index = Math.floor(index / 2);
  }

  return proof;
}

/**
 * Compare two byte arrays
 */
function compareBytes(a: Uint8Array, b: Uint8Array): number {
  for (let i = 0; i < Math.min(a.length, b.length); i++) {
    if (a[i]! < b[i]!) return -1;
    if (a[i]! > b[i]!) return 1;
  }
  return a.length - b.length;
}

// ============================================================================
// Bloom Filter Utilities
// ============================================================================

/**
 * Create a Bloom filter from a list of addresses
 * @param addresses - Addresses to add to filter
 * @param sizeBytes - Filter size in bytes
 * @param hashCount - Number of hash functions
 * @returns Bloom filter bits
 */
export function createBloomFilter(
  addresses: PublicKey[],
  sizeBytes: number = 4096,
  hashCount: number = 7
): Uint8Array {
  const bits = new Uint8Array(sizeBytes);
  const bitsLen = sizeBytes * 8;

  for (const addr of addresses) {
    for (let i = 0; i < hashCount; i++) {
      const hash = sha256(Buffer.concat([addr.toBuffer(), Buffer.from([i])]));
      const hashValue = new BN(hash.slice(0, 8), "le");
      const bitIndex = hashValue.mod(new BN(bitsLen)).toNumber();
      const byteIndex = Math.floor(bitIndex / 8);
      const bitPosition = bitIndex % 8;
      bits[byteIndex]! |= 1 << bitPosition;
    }
  }

  return bits;
}

/**
 * Check if an address might be in a Bloom filter
 * @param address - Address to check
 * @param bits - Bloom filter bits
 * @param hashCount - Number of hash functions
 * @returns True if possibly in filter (may have false positives)
 */
export function checkBloomFilter(
  address: PublicKey,
  bits: Uint8Array,
  hashCount: number = 7
): boolean {
  const bitsLen = bits.length * 8;

  for (let i = 0; i < hashCount; i++) {
    const hash = sha256(Buffer.concat([address.toBuffer(), Buffer.from([i])]));
    const hashValue = new BN(hash.slice(0, 8), "le");
    const bitIndex = hashValue.mod(new BN(bitsLen)).toNumber();
    const byteIndex = Math.floor(bitIndex / 8);
    const bitPosition = bitIndex % 8;
    
    if ((bits[byteIndex]! & (1 << bitPosition)) === 0) {
      return false;
    }
  }

  return true; // Possibly in set
}
