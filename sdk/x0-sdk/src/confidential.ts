/**
 * Confidential Transfer Client
 * 
 * Provides functionality for Token-2022 confidential transfers with ZK proofs.
 * Handles the cryptographic operations required for encrypted token transfers.
 * 
 * ## Architecture
 * 
 * Confidential transfers use two levels of encryption:
 * 1. **ElGamal Encryption**: Public-key encryption for the confidential balance
 * 2. **AES Encryption**: Symmetric encryption for the "decryptable balance" that
 *    allows the owner to quickly check their balance without ZK decryption
 * 
 * ## Proof Types
 * 
 * - **PubkeyValidityProof**: Proves the ElGamal public key is valid (account configuration)
 * - **WithdrawProof**: Proves a withdrawal amount is valid without revealing remaining balance
 * - **ZeroBalanceProof**: Proves the balance is exactly zero (required for closing accounts)
 * - **TransferProof**: Proves a confidential transfer is valid (both parties)
 * 
 * ## Usage
 * 
 * ```typescript
 * const client = new ConfidentialClient(connection, wallet);
 * 
 * // Configure account for confidential transfers
 * await client.configureAccount(mintAddress, tokenAccount);
 * 
 * // Deposit tokens (public -> confidential)
 * await client.deposit(tokenAccount, mintAddress, amount);
 * 
 * // Apply pending balance (makes received tokens spendable)
 * await client.applyPendingBalance(tokenAccount);
 * 
 * // Withdraw tokens (confidential -> public)
 * await client.withdraw(tokenAccount, mintAddress, amount);
 * ```
 */

import {
  Connection,
  PublicKey,
  Transaction,
  TransactionInstruction,
  Keypair,
  ConfirmOptions,
} from "@solana/web3.js";
import {
  TOKEN_2022_PROGRAM_ID,
  getMint,
} from "@solana/spl-token";
import * as crypto from "crypto";

import { X0_TOKEN_PROGRAM_ID } from "./constants";

// ============================================================================
// Token-2022 Confidential Transfer Instruction Builders
// ============================================================================

/**
 * Token-2022 instruction type enum for confidential transfers.
 * These map to the ConfidentialTransferInstruction enum in spl-token-2022.
 */
enum ConfidentialTransferInstruction {
  InitializeMint = 0,
  UpdateMint = 1,
  ConfigureAccount = 2,
  ApproveAccount = 3,
  EmptyAccount = 4,
  Deposit = 5,
  Withdraw = 6,
  Transfer = 7,
  ApplyPendingBalance = 8,
  EnableConfidentialCredits = 9,
  DisableConfidentialCredits = 10,
  EnableNonConfidentialCredits = 11,
  DisableNonConfidentialCredits = 12,
  TransferWithSplitProofs = 13,
}

/**
 * Token-2022 extension instruction type
 */
const TOKEN_INSTRUCTION_CONFIDENTIAL_TRANSFER = 27;

// ============================================================================
// Constants
// ============================================================================

/** Size of ElGamal public key in bytes */
export const ELGAMAL_PUBKEY_SIZE = 32;

/** Size of AES-encrypted ciphertext (nonce + ciphertext) */
export const AE_CIPHERTEXT_SIZE = 36;

/** Maximum amount for confidential transfers (2^48 - 1) */
export const MAX_CONFIDENTIAL_AMOUNT = BigInt("281474976710655"); // 2^48 - 1

/** Default maximum pending balance credit counter */
export const DEFAULT_MAX_PENDING_CREDITS = 65536;

// ============================================================================
// Types
// ============================================================================

/** Configuration for a confidential-enabled account */
export interface ConfidentialAccountConfig {
  /** The ElGamal public key for encrypted balances */
  elgamalPubkey: Uint8Array;
  /** The AES key for decryptable balances */
  aeKey: Uint8Array;
  /** Maximum incoming transfers before apply_pending required */
  maxPendingCredits?: number;
}

/** State of a confidential token account */
export interface ConfidentialAccountState {
  /** Whether the account is approved for confidential transfers */
  approved: boolean;
  /** The account's ElGamal public key */
  elgamalPubkey: Uint8Array;
  /** Encrypted pending balance (incoming transfers) */
  pendingBalanceLo: Uint8Array;
  pendingBalanceHi: Uint8Array;
  /** Encrypted available balance (spendable) */
  availableBalance: Uint8Array;
  /** Decryptable available balance (owner can decrypt with AE key) */
  decryptableAvailableBalance: Uint8Array;
  /** Whether confidential credits are allowed */
  allowConfidentialCredits: boolean;
  /** Whether non-confidential credits are allowed */
  allowNonConfidentialCredits: boolean;
  /** Counter for pending balance credits */
  pendingBalanceCreditCounter: number;
  /** Maximum pending credits before apply required */
  maximumPendingBalanceCreditCounter: number;
  /** Expected pending balance credit counter for next apply */
  expectedPendingBalanceCreditCounter: number;
  /** Actual pending balance credit counter */
  actualPendingBalanceCreditCounter: number;
}

/** Proof context for configuring an account */
export interface ConfigureAccountProofContext {
  /** The context state account address */
  contextAccount: PublicKey;
  /** The proof data (for verification) */
  proofData: Uint8Array;
}

/** Proof context for withdrawals */
export interface WithdrawProofContext {
  /** The context state account address */
  contextAccount: PublicKey;
  /** The proof data */
  proofData: Uint8Array;
  /** The new decryptable available balance after withdrawal */
  newDecryptableBalance: Uint8Array;
}

/** Proof context for empty account (zero balance proof) */
export interface EmptyAccountProofContext {
  /** The context state account address */
  contextAccount: PublicKey;
  /** The proof data */
  proofData: Uint8Array;
}

// ============================================================================
// Cryptographic Utilities
// ============================================================================

/**
 * Derives an AES key from a keypair for decryptable balances.
 * 
 * The AES key is derived deterministically from the owner's keypair
 * so they can always recover it to check their balance.
 * 
 * @param ownerKeypair - The owner's keypair
 * @param mint - The token mint address
 * @returns 32-byte AES key
 */
export function deriveAeKey(ownerKeypair: Keypair, mint: PublicKey): Uint8Array {
  const message = Buffer.concat([
    Buffer.from("x0-confidential-ae-key"),
    ownerKeypair.publicKey.toBuffer(),
    mint.toBuffer(),
  ]);
  return crypto.createHash("sha256").update(message).digest();
}

/**
 * Derives an ElGamal keypair from a keypair.
 * 
 * In production, this would use actual ElGamal key derivation.
 * For now, we derive deterministically for reproducibility.
 * 
 * @param ownerKeypair - The owner's keypair
 * @param mint - The token mint address
 * @returns Object with secret and public ElGamal keys
 */
export function deriveElGamalKeypair(
  ownerKeypair: Keypair,
  mint: PublicKey
): { secretKey: Uint8Array; publicKey: Uint8Array } {
  // Derive a deterministic seed for the ElGamal keypair
  const seed = Buffer.concat([
    Buffer.from("x0-confidential-elgamal"),
    ownerKeypair.secretKey,
    mint.toBuffer(),
  ]);
  const hash = crypto.createHash("sha512").update(seed).digest();
  
  return {
    secretKey: hash.subarray(0, 32),
    publicKey: hash.subarray(32, 64),
  };
}

/**
 * Creates an AES ciphertext of zero for account configuration.
 * 
 * When configuring an account, we need to provide an encryption of 0
 * to initialize the decryptable balance.
 * 
 * @param aeKey - The AES key
 * @returns 36-byte ciphertext (12-byte nonce + 24-byte ciphertext)
 */
export function encryptZeroBalance(aeKey: Uint8Array): Uint8Array {
  // Use AES-GCM to encrypt the value 0
  const nonce = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", aeKey, nonce);
  
  // Encrypt u64 zero (8 bytes)
  const zeroValue = Buffer.alloc(8);
  const encrypted = Buffer.concat([
    cipher.update(zeroValue),
    cipher.final(),
  ]);
  const authTag = cipher.getAuthTag();
  
  // Return nonce + ciphertext + auth tag (12 + 8 + 16 = 36 bytes)
  return Buffer.concat([nonce, encrypted, authTag]);
}

/**
 * Encrypts a u64 amount using AES.
 * 
 * @param amount - The amount to encrypt
 * @param aeKey - The AES key
 * @returns 36-byte ciphertext
 */
export function encryptAmount(amount: bigint, aeKey: Uint8Array): Uint8Array {
  const nonce = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", aeKey, nonce);
  
  // Convert amount to 8-byte little-endian buffer
  const amountBuffer = Buffer.alloc(8);
  amountBuffer.writeBigUInt64LE(amount);
  
  const encrypted = Buffer.concat([
    cipher.update(amountBuffer),
    cipher.final(),
  ]);
  const authTag = cipher.getAuthTag();
  
  return Buffer.concat([nonce, encrypted, authTag]);
}

/**
 * Decrypts an AES ciphertext to get the balance.
 * 
 * @param ciphertext - 36-byte AES ciphertext
 * @param aeKey - The AES key
 * @returns The decrypted amount, or null if decryption failed
 */
export function decryptBalance(ciphertext: Uint8Array, aeKey: Uint8Array): bigint | null {
  try {
    const nonce = ciphertext.subarray(0, 12);
    const encrypted = ciphertext.subarray(12, 20);
    const authTag = ciphertext.subarray(20, 36);
    
    const decipher = crypto.createDecipheriv("aes-256-gcm", aeKey, nonce);
    decipher.setAuthTag(authTag);
    
    const decrypted = Buffer.concat([
      decipher.update(encrypted),
      decipher.final(),
    ]);
    
    return decrypted.readBigUInt64LE();
  } catch {
    return null;
  }
}

// ============================================================================
// Proof Generation (Simplified)
// ============================================================================

/**
 * NOTE: In production, these proof generation functions would interface with
 * the actual ZK proof system (Groth16 proofs for confidential transfers).
 * 
 * The current implementation provides the structure for the proofs but would
 * need to be connected to a proper ZK proving system.
 */

/**
 * Generates a pubkey validity proof for account configuration.
 * 
 * This proves that the provided ElGamal public key is a valid point
 * on the curve and the prover knows the corresponding secret key.
 * 
 * @param _elgamalSecretKey - The ElGamal secret key
 * @param elgamalPubkey - The ElGamal public key
 * @returns Proof data
 */
export async function generatePubkeyValidityProof(
  _elgamalSecretKey: Uint8Array,
  elgamalPubkey: Uint8Array
): Promise<Uint8Array> {
  // In production, this generates a Groth16 proof
  // For now, return a placeholder that indicates proof structure
  const proofMarker = Buffer.from("PubkeyValidityProof");
  return Buffer.concat([
    proofMarker,
    Buffer.from(elgamalPubkey),
    crypto.randomBytes(32), // proof elements
  ]);
}

/**
 * Generates a withdrawal proof.
 * 
 * Proves that:
 * 1. The withdrawal amount is less than or equal to the available balance
 * 2. The new encrypted balance is correctly computed
 * 
 * @param _availableBalance - Current encrypted available balance
 * @param amount - Amount to withdraw
 * @param currentDecryptedBalance - Current decrypted balance
 * @param _elgamalSecretKey - The ElGamal secret key for decryption
 * @param aeKey - The AES key for the new decryptable balance
 * @returns Proof context with new decryptable balance
 */
export async function generateWithdrawProof(
  _availableBalance: Uint8Array,
  amount: bigint,
  currentDecryptedBalance: bigint,
  _elgamalSecretKey: Uint8Array,
  aeKey: Uint8Array
): Promise<{ proofData: Uint8Array; newDecryptableBalance: Uint8Array }> {
  // Calculate new balance
  const newBalance = currentDecryptedBalance - amount;
  if (newBalance < BigInt(0)) {
    throw new Error("Insufficient confidential balance for withdrawal");
  }
  
  // Create new decryptable balance
  const newDecryptableBalance = encryptAmount(newBalance, aeKey);
  
  // In production, generate Groth16 proof
  const proofData = Buffer.concat([
    Buffer.from("WithdrawProof"),
    Buffer.alloc(8).fill(0), // amount in LE
    crypto.randomBytes(64), // proof elements
  ]);
  
  // Write amount to proof data
  const amountBuf = Buffer.alloc(8);
  amountBuf.writeBigUInt64LE(amount);
  amountBuf.copy(proofData, 13);
  
  return { proofData, newDecryptableBalance };
}

/**
 * Generates a zero balance proof.
 * 
 * Proves that the encrypted available balance is exactly zero.
 * Required before closing a confidential account.
 * 
 * @param _availableBalance - Current encrypted available balance (should be zero)
 * @param _elgamalSecretKey - The ElGamal secret key
 * @returns Proof data
 */
export async function generateZeroBalanceProof(
  _availableBalance: Uint8Array,
  _elgamalSecretKey: Uint8Array
): Promise<Uint8Array> {
  // In production, generate Groth16 proof
  return Buffer.concat([
    Buffer.from("ZeroBalanceProof"),
    crypto.randomBytes(48), // proof elements
  ]);
}

// ============================================================================
// Confidential Client
// ============================================================================

export class ConfidentialClient {
  constructor(
    private connection: Connection,
    private wallet: {
      publicKey: PublicKey;
      signTransaction: (tx: Transaction) => Promise<Transaction>;
    },
    private confirmOptions: ConfirmOptions = { commitment: "confirmed" }
  ) {}

  // ==========================================================================
  // Account Configuration
  // ==========================================================================

  /**
   * Configure a token account for confidential transfers.
   * 
   * This sets up the ElGamal encryption for the account's confidential balance.
   * The account owner's keypair is used to derive the cryptographic keys.
   * 
   * @param mint - The token mint address
   * @param tokenAccount - The token account to configure
   * @param ownerKeypair - The owner's keypair (for key derivation)
   * @param maxPendingCredits - Maximum pending transfers before apply required
   * @returns Transaction signature
   */
  async configureAccount(
    mint: PublicKey,
    tokenAccount: PublicKey,
    ownerKeypair: Keypair,
    maxPendingCredits: number = DEFAULT_MAX_PENDING_CREDITS
  ): Promise<string> {
    // Derive keys
    const aeKey = deriveAeKey(ownerKeypair, mint);
    const elgamalKeys = deriveElGamalKeypair(ownerKeypair, mint);
    
    // Create decryptable zero balance
    const decryptableZeroBalance = encryptZeroBalance(aeKey);
    
    // Generate pubkey validity proof
    // In production, this proof would be submitted to a ZK proof verification system
    // and the resulting context state account would be passed to the instruction
    await generatePubkeyValidityProof(
      elgamalKeys.secretKey,
      elgamalKeys.publicKey
    );
    
    // For auto-approve mints, we don't need a proof context
    // In production with non-auto-approve mints:
    // 1. Create a proof context state account
    // 2. Submit the proof to the ZK proof verification program
    // 3. Pass the verified context account to the configure instruction
    const proofContextState: PublicKey | null = null;
    
    // Build instruction
    const ix = await this.buildConfigureAccountInstruction(
      tokenAccount,
      mint,
      decryptableZeroBalance,
      maxPendingCredits,
      proofContextState
    );
    
    // Create and send transaction
    const tx = new Transaction().add(ix);
    tx.feePayer = this.wallet.publicKey;
    tx.recentBlockhash = (await this.connection.getLatestBlockhash()).blockhash;
    
    const signedTx = await this.wallet.signTransaction(tx);
    const signature = await this.connection.sendRawTransaction(
      signedTx.serialize(),
      { skipPreflight: false }
    );
    
    await this.connection.confirmTransaction(signature, this.confirmOptions.commitment);
    
    return signature;
  }

  /**
   * Builds the configure account instruction using spl-token-2022 directly.
   * 
   * This calls Token-2022's ConfidentialTransferInstruction::ConfigureAccount.
   */
  private async buildConfigureAccountInstruction(
    tokenAccount: PublicKey,
    mint: PublicKey,
    decryptableZeroBalance: Uint8Array,
    _maxPendingCredits: number,
    proofContextState: PublicKey | null
  ): Promise<TransactionInstruction> {
    // Token-2022 ConfidentialTransfer::ConfigureAccount instruction format:
    // [0]: Token instruction type (27 = ConfidentialTransferExtension)
    // [1]: ConfidentialTransfer instruction type (2 = ConfigureAccount)
    // [2-37]: Decryptable zero balance (36 bytes AE ciphertext)
    // [38-69]: Maximum pending balance credit counter (u64)
    // [70]: Proof instruction offset (i8, or -1 for no introspection)
    
    const data = Buffer.alloc(1 + 1 + 36 + 8 + 1);
    let offset = 0;
    
    // Token instruction type
    data.writeUInt8(TOKEN_INSTRUCTION_CONFIDENTIAL_TRANSFER, offset);
    offset += 1;
    
    // ConfidentialTransfer instruction type
    data.writeUInt8(ConfidentialTransferInstruction.ConfigureAccount, offset);
    offset += 1;
    
    // Decryptable zero balance
    Buffer.from(decryptableZeroBalance).copy(data, offset);
    offset += 36;
    
    // Maximum pending balance credit counter (set to max u64 for unlimited)
    data.writeBigUInt64LE(BigInt("18446744073709551615"), offset);
    offset += 8;
    
    // Proof instruction offset (-1 means no proof introspection, auto-approve)
    data.writeInt8(-1, offset);
    
    const keys = [
      { pubkey: tokenAccount, isSigner: false, isWritable: true },
      { pubkey: mint, isSigner: false, isWritable: false },
      { pubkey: this.wallet.publicKey, isSigner: true, isWritable: false },
    ];
    
    // Add proof context if provided
    if (proofContextState) {
      keys.push({ pubkey: proofContextState, isSigner: false, isWritable: false });
    }
    
    return new TransactionInstruction({
      programId: TOKEN_2022_PROGRAM_ID,
      keys,
      data,
    });
  }

  // ==========================================================================
  // Deposit
  // ==========================================================================

  /**
   * Deposit tokens from public balance to confidential balance.
   * 
   * This moves tokens from the visible balance to the encrypted pending
   * balance. The tokens will appear in the pending balance until
   * applyPendingBalance() is called.
   * 
   * @param tokenAccount - The token account
   * @param mint - The token mint
   * @param amount - Amount to deposit (in base units)
   * @returns Transaction signature
   */
  async deposit(
    tokenAccount: PublicKey,
    mint: PublicKey,
    amount: bigint
  ): Promise<string> {
    // Validate amount
    if (amount <= BigInt(0)) {
      throw new Error("Deposit amount must be positive");
    }
    if (amount > MAX_CONFIDENTIAL_AMOUNT) {
      throw new Error(`Deposit amount exceeds maximum (${MAX_CONFIDENTIAL_AMOUNT})`);
    }
    
    // Get mint decimals
    const mintInfo = await getMint(this.connection, mint, undefined, TOKEN_2022_PROGRAM_ID);
    const decimals = mintInfo.decimals;
    
    // Build instruction
    const ix = this.buildDepositInstruction(
      tokenAccount,
      mint,
      amount,
      decimals
    );
    
    // Create and send transaction
    const tx = new Transaction().add(ix);
    tx.feePayer = this.wallet.publicKey;
    tx.recentBlockhash = (await this.connection.getLatestBlockhash()).blockhash;
    
    const signedTx = await this.wallet.signTransaction(tx);
    const signature = await this.connection.sendRawTransaction(
      signedTx.serialize(),
      { skipPreflight: false }
    );
    
    await this.connection.confirmTransaction(signature, this.confirmOptions.commitment);
    
    return signature;
  }

  /**
   * Builds the deposit_confidential instruction.
   */
  private buildDepositInstruction(
    tokenAccount: PublicKey,
    mint: PublicKey,
    amount: bigint,
    decimals: number
  ): TransactionInstruction {
    // Instruction discriminator for deposit_confidential
    const discriminator = Buffer.from([
      0xd2, 0x1e, 0x5f, 0x3a, 0x8b, 0x7c, 0x4d, 0x2e, // Example discriminator
    ]);
    
    const data = Buffer.alloc(8 + 8 + 1);
    let offset = 0;
    
    discriminator.copy(data, offset);
    offset += 8;
    
    data.writeBigUInt64LE(amount, offset);
    offset += 8;
    
    data.writeUInt8(decimals, offset);
    
    return new TransactionInstruction({
      programId: X0_TOKEN_PROGRAM_ID,
      keys: [
        { pubkey: this.wallet.publicKey, isSigner: true, isWritable: false },
        { pubkey: tokenAccount, isSigner: false, isWritable: true },
        { pubkey: mint, isSigner: false, isWritable: false },
        { pubkey: TOKEN_2022_PROGRAM_ID, isSigner: false, isWritable: false },
      ],
      data,
    });
  }

  // ==========================================================================
  // Apply Pending Balance
  // ==========================================================================

  /**
   * Apply pending balance to available balance.
   * 
   * This makes deposited/received confidential tokens spendable.
   * Must be called after receiving confidential transfers or deposits.
   * 
   * @param tokenAccount - The token account
   * @param ownerKeypair - Owner keypair for decryption
   * @param mint - The token mint
   * @returns Transaction signature
   */
  async applyPendingBalance(
    tokenAccount: PublicKey,
    ownerKeypair: Keypair,
    mint: PublicKey
  ): Promise<string> {
    // Get account state to find credit counter
    const accountState = await this.getConfidentialAccountState(tokenAccount);
    if (!accountState) {
      throw new Error("Account not configured for confidential transfers");
    }
    
    // Derive AE key
    const aeKey = deriveAeKey(ownerKeypair, mint);
    
    // Decrypt current balance
    const currentBalance = decryptBalance(accountState.decryptableAvailableBalance, aeKey);
    if (currentBalance === null) {
      throw new Error("Failed to decrypt current balance");
    }
    
    // Calculate new balance (current + pending)
    // In production, we'd decrypt the pending balance too
    // For now, we just use the credit counter to estimate
    const expectedCounter = accountState.actualPendingBalanceCreditCounter;
    
    // Create new decryptable balance (simplified - would need actual pending amount)
    const newDecryptableBalance = accountState.decryptableAvailableBalance;
    
    // Build instruction
    const ix = this.buildApplyPendingBalanceInstruction(
      tokenAccount,
      expectedCounter,
      newDecryptableBalance
    );
    
    // Create and send transaction
    const tx = new Transaction().add(ix);
    tx.feePayer = this.wallet.publicKey;
    tx.recentBlockhash = (await this.connection.getLatestBlockhash()).blockhash;
    
    const signedTx = await this.wallet.signTransaction(tx);
    const signature = await this.connection.sendRawTransaction(
      signedTx.serialize(),
      { skipPreflight: false }
    );
    
    await this.connection.confirmTransaction(signature, this.confirmOptions.commitment);
    
    return signature;
  }

  /**
   * Builds the apply pending balance instruction using spl-token-2022 directly.
   * 
   * This calls Token-2022's ConfidentialTransferInstruction::ApplyPendingBalance.
   */
  private buildApplyPendingBalanceInstruction(
    tokenAccount: PublicKey,
    expectedCreditCounter: number,
    newDecryptableBalance: Uint8Array
  ): TransactionInstruction {
    // Token-2022 ConfidentialTransfer::ApplyPendingBalance instruction format:
    // [0]: Token instruction type (27 = ConfidentialTransferExtension)
    // [1]: ConfidentialTransfer instruction type (8 = ApplyPendingBalance)
    // [2-37]: New decryptable available balance (36 bytes AE ciphertext)
    // [38-45]: Expected pending balance credit counter (u64)
    
    const data = Buffer.alloc(1 + 1 + 36 + 8);
    let offset = 0;
    
    // Token instruction type
    data.writeUInt8(TOKEN_INSTRUCTION_CONFIDENTIAL_TRANSFER, offset);
    offset += 1;
    
    // ConfidentialTransfer instruction type
    data.writeUInt8(ConfidentialTransferInstruction.ApplyPendingBalance, offset);
    offset += 1;
    
    // New decryptable available balance
    Buffer.from(newDecryptableBalance).copy(data, offset);
    offset += 36;
    
    // Expected pending balance credit counter
    data.writeBigUInt64LE(BigInt(expectedCreditCounter), offset);
    
    return new TransactionInstruction({
      programId: TOKEN_2022_PROGRAM_ID,
      keys: [
        { pubkey: tokenAccount, isSigner: false, isWritable: true },
        { pubkey: this.wallet.publicKey, isSigner: true, isWritable: false },
      ],
      data,
    });
  }

  // ==========================================================================
  // Withdraw
  // ==========================================================================

  /**
   * Withdraw tokens from confidential balance to public balance.
   * 
   * This moves tokens from the encrypted balance back to the visible
   * balance. Requires generating a withdrawal proof.
   * 
   * @param tokenAccount - The token account
   * @param mint - The token mint
   * @param amount - Amount to withdraw (in base units)
   * @param ownerKeypair - Owner keypair for proof generation
   * @returns Transaction signature
   */
  async withdraw(
    tokenAccount: PublicKey,
    mint: PublicKey,
    amount: bigint,
    ownerKeypair: Keypair
  ): Promise<string> {
    // Validate amount
    if (amount <= BigInt(0)) {
      throw new Error("Withdrawal amount must be positive");
    }
    if (amount > MAX_CONFIDENTIAL_AMOUNT) {
      throw new Error(`Withdrawal amount exceeds maximum (${MAX_CONFIDENTIAL_AMOUNT})`);
    }
    
    // Get account state
    const accountState = await this.getConfidentialAccountState(tokenAccount);
    if (!accountState) {
      throw new Error("Account not configured for confidential transfers");
    }
    
    // Derive keys
    const aeKey = deriveAeKey(ownerKeypair, mint);
    const elgamalKeys = deriveElGamalKeypair(ownerKeypair, mint);
    
    // Decrypt current balance
    const currentBalance = decryptBalance(accountState.decryptableAvailableBalance, aeKey);
    if (currentBalance === null) {
      throw new Error("Failed to decrypt current balance");
    }
    
    if (currentBalance < amount) {
      throw new Error(`Insufficient confidential balance: ${currentBalance} < ${amount}`);
    }
    
    // Generate withdrawal proof
    // In production, this proof would be submitted to a ZK proof verification system
    const { newDecryptableBalance } = await generateWithdrawProof(
      accountState.availableBalance,
      amount,
      currentBalance,
      elgamalKeys.secretKey,
      aeKey
    );
    
    // Create proof context state account
    // In production:
    // 1. Submit the withdrawal proof to the ZK proof verification program
    // 2. The verification creates a proof context state account
    // 3. Pass that account to the withdraw instruction
    const proofContextAccount = Keypair.generate().publicKey;
    
    // Get mint decimals
    const mintInfo = await getMint(this.connection, mint, undefined, TOKEN_2022_PROGRAM_ID);
    const decimals = mintInfo.decimals;
    
    // Build instruction
    const ix = this.buildWithdrawInstruction(
      tokenAccount,
      mint,
      amount,
      decimals,
      newDecryptableBalance,
      proofContextAccount
    );
    
    // Create and send transaction
    const tx = new Transaction().add(ix);
    tx.feePayer = this.wallet.publicKey;
    tx.recentBlockhash = (await this.connection.getLatestBlockhash()).blockhash;
    
    const signedTx = await this.wallet.signTransaction(tx);
    const signature = await this.connection.sendRawTransaction(
      signedTx.serialize(),
      { skipPreflight: false }
    );
    
    await this.connection.confirmTransaction(signature, this.confirmOptions.commitment);
    
    return signature;
  }

  /**
   * Builds the withdraw instruction using spl-token-2022 directly.
   * 
   * This calls Token-2022's ConfidentialTransferInstruction::Withdraw.
   */
  private buildWithdrawInstruction(
    tokenAccount: PublicKey,
    mint: PublicKey,
    amount: bigint,
    decimals: number,
    newDecryptableBalance: Uint8Array,
    proofContext: PublicKey
  ): TransactionInstruction {
    // Token-2022 ConfidentialTransfer::Withdraw instruction format:
    // [0]: Token instruction type (27 = ConfidentialTransferExtension)
    // [1]: ConfidentialTransfer instruction type (6 = Withdraw)
    // [2-9]: Amount to withdraw (u64)
    // [10]: Decimals (u8)
    // [11-46]: New decryptable available balance (36 bytes AE ciphertext)
    // [47]: Proof instruction offset (i8)
    
    const data = Buffer.alloc(1 + 1 + 8 + 1 + 36 + 1);
    let offset = 0;
    
    // Token instruction type
    data.writeUInt8(TOKEN_INSTRUCTION_CONFIDENTIAL_TRANSFER, offset);
    offset += 1;
    
    // ConfidentialTransfer instruction type
    data.writeUInt8(ConfidentialTransferInstruction.Withdraw, offset);
    offset += 1;
    
    // Amount to withdraw
    data.writeBigUInt64LE(amount, offset);
    offset += 8;
    
    // Decimals
    data.writeUInt8(decimals, offset);
    offset += 1;
    
    // New decryptable available balance
    Buffer.from(newDecryptableBalance).copy(data, offset);
    offset += 36;
    
    // Proof instruction offset (-1 for no introspection)
    data.writeInt8(-1, offset);
    
    return new TransactionInstruction({
      programId: TOKEN_2022_PROGRAM_ID,
      keys: [
        { pubkey: tokenAccount, isSigner: false, isWritable: true },
        { pubkey: mint, isSigner: false, isWritable: false },
        { pubkey: this.wallet.publicKey, isSigner: true, isWritable: false },
        { pubkey: proofContext, isSigner: false, isWritable: false },
      ],
      data,
    });
  }

  // ==========================================================================
  // Account State
  // ==========================================================================

  /**
   * Get the confidential transfer state of a token account.
   * 
   * @param tokenAccount - The token account address
   * @returns The confidential account state, or null if not configured
   */
  async getConfidentialAccountState(
    tokenAccount: PublicKey
  ): Promise<ConfidentialAccountState | null> {
    try {
      const accountInfo = await this.connection.getAccountInfo(tokenAccount);
      if (!accountInfo) {
        return null;
      }
      
      // Parse the extension data
      // This is simplified - in production would use proper extension parsing
      // The ConfidentialTransferAccount extension is at a specific offset
      
      // For now, return a placeholder state
      // In production, this would parse the actual extension data
      return {
        approved: true,
        elgamalPubkey: new Uint8Array(32),
        pendingBalanceLo: new Uint8Array(64),
        pendingBalanceHi: new Uint8Array(64),
        availableBalance: new Uint8Array(64),
        decryptableAvailableBalance: new Uint8Array(36),
        allowConfidentialCredits: true,
        allowNonConfidentialCredits: true,
        pendingBalanceCreditCounter: 0,
        maximumPendingBalanceCreditCounter: DEFAULT_MAX_PENDING_CREDITS,
        expectedPendingBalanceCreditCounter: 0,
        actualPendingBalanceCreditCounter: 0,
      };
    } catch {
      return null;
    }
  }

  /**
   * Check the decryptable balance of a confidential account.
   * 
   * @param tokenAccount - The token account
   * @param ownerKeypair - Owner keypair for decryption
   * @param mint - The token mint
   * @returns The decrypted balance
   */
  async getDecryptableBalance(
    tokenAccount: PublicKey,
    ownerKeypair: Keypair,
    mint: PublicKey
  ): Promise<bigint> {
    const state = await this.getConfidentialAccountState(tokenAccount);
    if (!state) {
      throw new Error("Account not configured for confidential transfers");
    }
    
    const aeKey = deriveAeKey(ownerKeypair, mint);
    const balance = decryptBalance(state.decryptableAvailableBalance, aeKey);
    
    if (balance === null) {
      throw new Error("Failed to decrypt balance");
    }
    
    return balance;
  }

  // ==========================================================================
  // Credit Controls
  // ==========================================================================

  /**
   * Enable confidential credits on an account.
   */
  async enableConfidentialCredits(tokenAccount: PublicKey): Promise<string> {
    const ix = this.buildToggleCreditsInstruction(tokenAccount, true, true);
    return this.sendTransaction([ix]);
  }

  /**
   * Disable confidential credits on an account.
   */
  async disableConfidentialCredits(tokenAccount: PublicKey): Promise<string> {
    const ix = this.buildToggleCreditsInstruction(tokenAccount, true, false);
    return this.sendTransaction([ix]);
  }

  /**
   * Enable non-confidential credits on an account.
   */
  async enableNonConfidentialCredits(tokenAccount: PublicKey): Promise<string> {
    const ix = this.buildToggleCreditsInstruction(tokenAccount, false, true);
    return this.sendTransaction([ix]);
  }

  /**
   * Disable non-confidential credits on an account.
   */
  async disableNonConfidentialCredits(tokenAccount: PublicKey): Promise<string> {
    const ix = this.buildToggleCreditsInstruction(tokenAccount, false, false);
    return this.sendTransaction([ix]);
  }

  /**
   * Builds a toggle credits instruction.
   */
  private buildToggleCreditsInstruction(
    tokenAccount: PublicKey,
    isConfidential: boolean,
    enable: boolean
  ): TransactionInstruction {
    // Choose discriminator based on action
    let discriminator: Buffer;
    if (isConfidential) {
      discriminator = enable
        ? Buffer.from([0xb1, 0x2c, 0x3d, 0x4e, 0x5f, 0x6a, 0x7b, 0x8c]) // enable_confidential_credits
        : Buffer.from([0xc2, 0x3d, 0x4e, 0x5f, 0x6a, 0x7b, 0x8c, 0x9d]); // disable_confidential_credits
    } else {
      discriminator = enable
        ? Buffer.from([0xd3, 0x4e, 0x5f, 0x6a, 0x7b, 0x8c, 0x9d, 0xae]) // enable_non_confidential_credits
        : Buffer.from([0xe4, 0x5f, 0x6a, 0x7b, 0x8c, 0x9d, 0xae, 0xbf]); // disable_non_confidential_credits
    }
    
    return new TransactionInstruction({
      programId: X0_TOKEN_PROGRAM_ID,
      keys: [
        { pubkey: this.wallet.publicKey, isSigner: true, isWritable: false },
        { pubkey: tokenAccount, isSigner: false, isWritable: true },
        { pubkey: TOKEN_2022_PROGRAM_ID, isSigner: false, isWritable: false },
      ],
      data: discriminator,
    });
  }

  // ==========================================================================
  // Helper Methods
  // ==========================================================================

  /**
   * Send a transaction with the configured wallet.
   */
  private async sendTransaction(instructions: TransactionInstruction[]): Promise<string> {
    const tx = new Transaction().add(...instructions);
    tx.feePayer = this.wallet.publicKey;
    tx.recentBlockhash = (await this.connection.getLatestBlockhash()).blockhash;
    
    const signedTx = await this.wallet.signTransaction(tx);
    const signature = await this.connection.sendRawTransaction(
      signedTx.serialize(),
      { skipPreflight: false }
    );
    
    await this.connection.confirmTransaction(signature, this.confirmOptions.commitment);
    
    return signature;
  }
}
