/**
 * ZK Verifier Client
 *
 * Client for the x0-zk-verifier program which verifies Groth16 ZK proofs
 * for Token-2022 confidential transfers and creates on-chain proof context
 * PDAs that can be consumed by Token-2022 instructions.
 *
 * ## Proof Types
 *
 * - **PubkeyValidity**: Proves an ElGamal public key is validly derived
 * - **Withdraw**: Proves a withdrawal amount is valid without revealing balance
 * - **ZeroBalance**: Proves an account's encrypted balance is exactly zero
 * - **Transfer**: Proves a confidential transfer is valid for both parties
 *
 * ## Flow
 *
 * 1. Generate proof client-side (via WASM or solana-zk-token-sdk)
 * 2. Submit proof to x0-zk-verifier → creates ProofContext PDA
 * 3. Pass ProofContext PDA to Token-2022 instruction as proof account
 * 4. ProofContext is valid for 5 minutes (300 seconds)
 */

import {
  Connection,
  PublicKey,
  TransactionInstruction,
  SystemProgram,
} from "@solana/web3.js";
import BN from "bn.js";
import { X0_ZK_VERIFIER_PROGRAM_ID } from "./constants";
import { getInstructionDiscriminator } from "./utils";

// ============================================================================
// Constants
// ============================================================================

/** PDA seed for proof context accounts */
const PROOF_CONTEXT_SEED = Buffer.from("proof-context");

/** Solana ZK Token Proof Program ID */
export const ZK_TOKEN_PROOF_PROGRAM_ID = new PublicKey(
  "ZkTokenProof1111111111111111111111111111111"
);

/** Proof context freshness window in seconds */
export const PROOF_CONTEXT_FRESHNESS_SECONDS = 300;

// ============================================================================
// Types
// ============================================================================

/** Proof type enum matching on-chain ProofType */
export enum ProofType {
  PubkeyValidity = 0,
  Withdraw = 1,
  ZeroBalance = 2,
  Transfer = 3,
}

/** On-chain ProofContext account data */
export interface ProofContext {
  /** Account version (currently 1) */
  version: number;
  /** Type of proof verified */
  proofType: ProofType;
  /** Whether proof was successfully verified */
  verified: boolean;
  /** Account owner who created the proof */
  owner: PublicKey;
  /** Unix timestamp when proof was verified */
  verifiedAt: number;
  /** Amount (for Withdraw and Transfer proofs) */
  amount: BN | null;
  /** Recipient (for Transfer proofs) */
  recipient: PublicKey | null;
  /** ElGamal public key (for PubkeyValidity proofs) */
  elgamalPubkey: Uint8Array | null;
  /** Token mint */
  mint: PublicKey;
  /** Token account */
  tokenAccount: PublicKey;
  /** PDA bump */
  bump: number;
}

// ============================================================================
// ZK Verifier Client
// ============================================================================

export class ZkVerifierClient {
  constructor(
    private connection: Connection,
    private programId: PublicKey = X0_ZK_VERIFIER_PROGRAM_ID
  ) {}

  // ==========================================================================
  // PDA Derivation
  // ==========================================================================

  /**
   * Derive proof context PDA.
   *
   * The PDA is unique per (owner, tokenAccount, timestamp) to prevent
   * replay attacks and allow multiple proofs per account.
   */
  deriveProofContextPda(
    owner: PublicKey,
    tokenAccount: PublicKey,
    timestamp: number
  ): [PublicKey, number] {
    const timestampBuf = Buffer.alloc(8);
    timestampBuf.writeBigInt64LE(BigInt(timestamp));

    return PublicKey.findProgramAddressSync(
      [
        PROOF_CONTEXT_SEED,
        owner.toBuffer(),
        tokenAccount.toBuffer(),
        timestampBuf,
      ],
      this.programId
    );
  }

  // ==========================================================================
  // Instruction Builders
  // ==========================================================================

  /**
   * Build instruction to verify a PubkeyValidity proof.
   *
   * Proves that an ElGamal public key is validly derived from a secret key.
   * Required when configuring accounts for confidential transfers.
   *
   * @param owner - Account owner (signer, payer)
   * @param tokenAccount - The token account being configured
   * @param mint - The token mint
   * @param proofData - 64-byte PubkeyValidityData proof
   * @param elgamalPubkey - 32-byte ElGamal public key
   * @param timestamp - Unix timestamp for PDA derivation (use current time)
   */
  buildVerifyPubkeyValidityInstruction(
    owner: PublicKey,
    tokenAccount: PublicKey,
    mint: PublicKey,
    proofData: Uint8Array,
    elgamalPubkey: Uint8Array,
    timestamp: number
  ): { instruction: TransactionInstruction; proofContextPda: PublicKey } {
    const [proofContextPda] = this.deriveProofContextPda(
      owner,
      tokenAccount,
      timestamp
    );

    const discriminator = getInstructionDiscriminator("verify_pubkey_validity");

    // Serialize: discriminator + Vec<u8> proof_data + [u8; 32] elgamal_pubkey
    const proofLenBuf = Buffer.alloc(4);
    proofLenBuf.writeUInt32LE(proofData.length);

    const data = Buffer.concat([
      discriminator,
      proofLenBuf,
      Buffer.from(proofData),
      Buffer.from(elgamalPubkey),
    ]);

    const keys = [
      { pubkey: owner, isSigner: true, isWritable: true },
      { pubkey: tokenAccount, isSigner: false, isWritable: false },
      { pubkey: mint, isSigner: false, isWritable: false },
      { pubkey: proofContextPda, isSigner: false, isWritable: true },
      { pubkey: ZK_TOKEN_PROOF_PROGRAM_ID, isSigner: false, isWritable: false },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ];

    return {
      instruction: new TransactionInstruction({
        programId: this.programId,
        keys,
        data,
      }),
      proofContextPda,
    };
  }

  /**
   * Build instruction to verify a Withdraw proof.
   *
   * Proves that a withdrawal amount is valid given the current encrypted
   * balance, without revealing the balance itself.
   *
   * @param owner - Account owner (signer, payer)
   * @param tokenAccount - The token account to withdraw from
   * @param mint - The token mint
   * @param proofData - 160-byte WithdrawData proof
   * @param amount - Amount to withdraw
   * @param newDecryptableBalance - 36-byte AES ciphertext of new balance
   * @param timestamp - Unix timestamp for PDA derivation
   */
  buildVerifyWithdrawInstruction(
    owner: PublicKey,
    tokenAccount: PublicKey,
    mint: PublicKey,
    proofData: Uint8Array,
    amount: bigint,
    newDecryptableBalance: Uint8Array,
    timestamp: number
  ): { instruction: TransactionInstruction; proofContextPda: PublicKey } {
    const [proofContextPda] = this.deriveProofContextPda(
      owner,
      tokenAccount,
      timestamp
    );

    const discriminator = getInstructionDiscriminator("verify_withdraw");

    // Serialize: discriminator + Vec<u8> proof_data + u64 amount + [u8; 36] new_decryptable_balance
    const proofLenBuf = Buffer.alloc(4);
    proofLenBuf.writeUInt32LE(proofData.length);

    const amountBuf = Buffer.alloc(8);
    amountBuf.writeBigUInt64LE(amount);

    const data = Buffer.concat([
      discriminator,
      proofLenBuf,
      Buffer.from(proofData),
      amountBuf,
      Buffer.from(newDecryptableBalance),
    ]);

    const keys = [
      { pubkey: owner, isSigner: true, isWritable: true },
      { pubkey: tokenAccount, isSigner: false, isWritable: false },
      { pubkey: mint, isSigner: false, isWritable: false },
      { pubkey: proofContextPda, isSigner: false, isWritable: true },
      { pubkey: ZK_TOKEN_PROOF_PROGRAM_ID, isSigner: false, isWritable: false },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ];

    return {
      instruction: new TransactionInstruction({
        programId: this.programId,
        keys,
        data,
      }),
      proofContextPda,
    };
  }

  /**
   * Build instruction to verify a ZeroBalance proof.
   *
   * Proves that an account's encrypted balance is exactly zero.
   * Required before closing a confidential token account.
   *
   * @param owner - Account owner (signer, payer)
   * @param tokenAccount - The token account to prove zero balance for
   * @param mint - The token mint
   * @param proofData - 96-byte ZeroBalanceProofData proof
   * @param timestamp - Unix timestamp for PDA derivation
   */
  buildVerifyZeroBalanceInstruction(
    owner: PublicKey,
    tokenAccount: PublicKey,
    mint: PublicKey,
    proofData: Uint8Array,
    timestamp: number
  ): { instruction: TransactionInstruction; proofContextPda: PublicKey } {
    const [proofContextPda] = this.deriveProofContextPda(
      owner,
      tokenAccount,
      timestamp
    );

    const discriminator = getInstructionDiscriminator("verify_zero_balance");

    // Serialize: discriminator + Vec<u8> proof_data
    const proofLenBuf = Buffer.alloc(4);
    proofLenBuf.writeUInt32LE(proofData.length);

    const data = Buffer.concat([
      discriminator,
      proofLenBuf,
      Buffer.from(proofData),
    ]);

    const keys = [
      { pubkey: owner, isSigner: true, isWritable: true },
      { pubkey: tokenAccount, isSigner: false, isWritable: false },
      { pubkey: mint, isSigner: false, isWritable: false },
      { pubkey: proofContextPda, isSigner: false, isWritable: true },
      { pubkey: ZK_TOKEN_PROOF_PROGRAM_ID, isSigner: false, isWritable: false },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ];

    return {
      instruction: new TransactionInstruction({
        programId: this.programId,
        keys,
        data,
      }),
      proofContextPda,
    };
  }

  /**
   * Build instruction to verify a Transfer proof.
   *
   * Proves that a confidential transfer is valid — the sender has sufficient
   * balance and the transfer amounts are correctly encrypted for both parties.
   *
   * @param owner - Account owner (signer, payer)
   * @param tokenAccount - The sender's token account
   * @param mint - The token mint
   * @param proofData - Variable-size TransferData proof (≥300 bytes)
   * @param amount - Transfer amount
   * @param recipient - Recipient's public key
   * @param timestamp - Unix timestamp for PDA derivation
   */
  buildVerifyTransferInstruction(
    owner: PublicKey,
    tokenAccount: PublicKey,
    mint: PublicKey,
    proofData: Uint8Array,
    amount: bigint,
    recipient: PublicKey,
    timestamp: number
  ): { instruction: TransactionInstruction; proofContextPda: PublicKey } {
    const [proofContextPda] = this.deriveProofContextPda(
      owner,
      tokenAccount,
      timestamp
    );

    const discriminator = getInstructionDiscriminator("verify_transfer");

    // Serialize: discriminator + Vec<u8> proof_data + u64 amount + Pubkey recipient
    const proofLenBuf = Buffer.alloc(4);
    proofLenBuf.writeUInt32LE(proofData.length);

    const amountBuf = Buffer.alloc(8);
    amountBuf.writeBigUInt64LE(amount);

    const data = Buffer.concat([
      discriminator,
      proofLenBuf,
      Buffer.from(proofData),
      amountBuf,
      recipient.toBuffer(),
    ]);

    const keys = [
      { pubkey: owner, isSigner: true, isWritable: true },
      { pubkey: tokenAccount, isSigner: false, isWritable: false },
      { pubkey: mint, isSigner: false, isWritable: false },
      { pubkey: proofContextPda, isSigner: false, isWritable: true },
      { pubkey: ZK_TOKEN_PROOF_PROGRAM_ID, isSigner: false, isWritable: false },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ];

    return {
      instruction: new TransactionInstruction({
        programId: this.programId,
        keys,
        data,
      }),
      proofContextPda,
    };
  }

  // ==========================================================================
  // Account Fetching
  // ==========================================================================

  /**
   * Fetch and parse a ProofContext account.
   */
  async fetchProofContext(
    proofContextAddress: PublicKey
  ): Promise<ProofContext | null> {
    const accountInfo = await this.connection.getAccountInfo(
      proofContextAddress
    );
    if (!accountInfo) return null;
    return this.parseProofContext(accountInfo.data);
  }

  /**
   * Check if a proof context is still fresh (within 5-minute window).
   */
  isProofFresh(proofContext: ProofContext): boolean {
    const now = Math.floor(Date.now() / 1000);
    return now - proofContext.verifiedAt < PROOF_CONTEXT_FRESHNESS_SECONDS;
  }

  // ==========================================================================
  // Parsing
  // ==========================================================================

  private parseProofContext(data: Buffer): ProofContext {
    let offset = 8; // Skip Anchor discriminator

    const version = data[offset]!;
    offset += 1;

    const proofType = data[offset]! as ProofType;
    offset += 1;

    const verified = data[offset]! === 1;
    offset += 1;

    const owner = new PublicKey(data.slice(offset, offset + 32));
    offset += 32;

    const verifiedAt = Number(
      Buffer.from(data.slice(offset, offset + 8)).readBigInt64LE()
    );
    offset += 8;

    // Option<u64> amount
    const hasAmount = data[offset]! === 1;
    offset += 1;
    const amount = hasAmount
      ? new BN(data.slice(offset, offset + 8), "le")
      : null;
    offset += 8;

    // Option<Pubkey> recipient
    const hasRecipient = data[offset]! === 1;
    offset += 1;
    const recipient = hasRecipient
      ? new PublicKey(data.slice(offset, offset + 32))
      : null;
    offset += 32;

    // Option<[u8; 32]> elgamal_pubkey
    const hasElgamal = data[offset]! === 1;
    offset += 1;
    const elgamalPubkey = hasElgamal
      ? new Uint8Array(data.slice(offset, offset + 32))
      : null;
    offset += 32;

    const mint = new PublicKey(data.slice(offset, offset + 32));
    offset += 32;

    const tokenAccount = new PublicKey(data.slice(offset, offset + 32));
    offset += 32;

    const bump = data[offset]!;

    return {
      version,
      proofType,
      verified,
      owner,
      verifiedAt,
      amount,
      recipient,
      elgamalPubkey,
      mint,
      tokenAccount,
      bump,
    };
  }
}
