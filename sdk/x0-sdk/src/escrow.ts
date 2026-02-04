/**
 * Escrow Operations Client
 * 
 * Client-side helpers for managing x0-escrow conditional payments.
 */

import {
  Connection,
  PublicKey,
  TransactionInstruction,
  SystemProgram,
  SYSVAR_CLOCK_PUBKEY,
} from "@solana/web3.js";
import {
  getAssociatedTokenAddressSync,
  TOKEN_2022_PROGRAM_ID,
} from "@solana/spl-token";
import { BN } from "@coral-xyz/anchor";
import {
  X0_ESCROW_PROGRAM_ID,
  X0_REPUTATION_PROGRAM_ID,
  AUTO_RELEASE_DELAY_SECONDS,
  DELIVERY_TIMEOUT_SECONDS,
} from "./constants";
import { deriveEscrowPda, computeMemoHash, now } from "./utils";
import type { EscrowAccount, EscrowState, CreateEscrowParams } from "./types";

// ============================================================================
// Types for reputation integration
// ============================================================================

/** Optional reputation accounts for escrow operations */
export interface ReputationAccounts {
  /** The seller's reputation PDA */
  sellerReputation: PublicKey;
  /** The seller's policy PDA */
  sellerPolicy: PublicKey;
  /** The reputation program ID (defaults to X0_REPUTATION_PROGRAM_ID) */
  reputationProgram?: PublicKey;
}

// ============================================================================
// Escrow Manager
// ============================================================================

export class EscrowManager {
  private connection: Connection;
  private programId: PublicKey;
  private tokenProgramId: PublicKey;

  constructor(
    connection: Connection,
    programId: PublicKey = X0_ESCROW_PROGRAM_ID,
    tokenProgramId: PublicKey = TOKEN_2022_PROGRAM_ID
  ) {
    this.connection = connection;
    this.programId = programId;
    this.tokenProgramId = tokenProgramId;
  }

  /**
   * Derive escrow PDA address
   */
  deriveEscrowAddress(
    buyer: PublicKey,
    seller: PublicKey,
    serviceMemo: string
  ): PublicKey {
    const memoHash = computeMemoHash(serviceMemo);
    const [pda] = deriveEscrowPda(buyer, seller, memoHash);
    return pda;
  }

  /**
   * Fetch an escrow account
   */
  async fetchEscrow(escrowAddress: PublicKey): Promise<EscrowAccount | null> {
    const accountInfo = await this.connection.getAccountInfo(escrowAddress);
    if (!accountInfo) {
      return null;
    }
    return this.parseEscrowAccount(accountInfo.data);
  }

  /**
   * Parse raw account data into EscrowAccount
   */
  private parseEscrowAccount(data: Buffer): EscrowAccount {
    // Skip 8-byte discriminator
    let offset = 8;

    const buyer = new PublicKey(data.slice(offset, offset + 32));
    offset += 32;

    const seller = new PublicKey(data.slice(offset, offset + 32));
    offset += 32;

    const memoHash = new Uint8Array(data.slice(offset, offset + 32));
    offset += 32;

    const amount = new BN(data.slice(offset, offset + 8), "le");
    offset += 8;

    const mint = new PublicKey(data.slice(offset, offset + 32));
    offset += 32;

    const createdAt = new BN(data.slice(offset, offset + 8), "le").toNumber();
    offset += 8;

    const deliveryTimeout = new BN(data.slice(offset, offset + 8), "le").toNumber();
    offset += 8;

    const autoReleaseDelay = new BN(data.slice(offset, offset + 8), "le").toNumber();
    offset += 8;

    const deliveredAt = data[offset] === 1
      ? new BN(data.slice(offset + 1, offset + 9), "le").toNumber()
      : null;
    offset += 9;

    const state = data[offset]! as EscrowState;
    offset += 1;

    // Arbiter (Option<Pubkey>)
    const hasArbiter = data[offset] === 1;
    offset += 1;
    const arbiter = hasArbiter
      ? new PublicKey(data.slice(offset, offset + 32))
      : undefined;
    offset += hasArbiter ? 32 : 0;

    // Dispute reason (Option<String>)
    const hasDisputeReason = data[offset] === 1;
    offset += 1;
    let disputeReason: string | undefined;
    if (hasDisputeReason) {
      const reasonLen = data.readUInt32LE(offset);
      offset += 4;
      disputeReason = data.slice(offset, offset + reasonLen).toString("utf-8");
      offset += reasonLen;
    }

    const bump = data[offset]!;

    return {
      buyer,
      seller,
      memoHash,
      amount,
      mint,
      createdAt,
      deliveryTimeout,
      autoReleaseDelay,
      deliveredAt,
      state,
      ...(arbiter && { arbiter }),
      ...(disputeReason && { disputeReason }),
      bump,
      timeout: deliveryTimeout,
      tokenDecimals: 6,
    };
  }

  // ============================================================================
  // Instruction Builders
  // ============================================================================

  /**
   * Build instruction to create a new escrow
   */
  buildCreateEscrowInstruction(params: CreateEscrowParams): {
    instruction: TransactionInstruction;
    escrowAddress: PublicKey;
  } {
    const serviceMemo = params.serviceMemo ?? params.memo;
    const memoHash = computeMemoHash(serviceMemo);
    const [escrowAddress] = deriveEscrowPda(
      params.buyer,
      params.seller,
      memoHash
    );

    // Discriminator for create_escrow
    const discriminator = Buffer.from([
      0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x70, 0x81
    ]);

    const deliveryTimeout = params.deliveryTimeout ?? DELIVERY_TIMEOUT_SECONDS;
    const autoReleaseDelay = params.autoReleaseDelay ?? AUTO_RELEASE_DELAY_SECONDS;

    const memoBytes = Buffer.from(serviceMemo, "utf-8");

    const data = Buffer.concat([
      discriminator,
      params.amount.toArrayLike(Buffer, "le", 8),
      Buffer.from(new Uint32Array([memoBytes.length]).buffer),
      memoBytes,
      Buffer.from(new BN(deliveryTimeout).toArrayLike(Buffer, "le", 8)),
      Buffer.from(new BN(autoReleaseDelay).toArrayLike(Buffer, "le", 8)),
      params.arbiter ? Buffer.concat([Buffer.from([1]), params.arbiter.toBuffer()]) : Buffer.from([0]),
    ]);

    const keys = [
      { pubkey: params.buyer, isSigner: true, isWritable: true },
      { pubkey: params.seller, isSigner: false, isWritable: false },
      { pubkey: escrowAddress, isSigner: false, isWritable: true },
      { pubkey: params.mint, isSigner: false, isWritable: false },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ];

    if (params.arbiter) {
      keys.push({ pubkey: params.arbiter, isSigner: false, isWritable: false });
    }

    return {
      instruction: new TransactionInstruction({
        programId: this.programId,
        keys,
        data,
      }),
      escrowAddress,
    };
  }

  /**
   * Build instruction to fund an escrow
   */
  buildFundEscrowInstruction(
    buyer: PublicKey,
    escrowAddress: PublicKey,
    mint: PublicKey,
    amount: BN
  ): TransactionInstruction {
    const buyerAta = getAssociatedTokenAddressSync(
      mint,
      buyer,
      false,
      this.tokenProgramId
    );

    const escrowVault = getAssociatedTokenAddressSync(
      mint,
      escrowAddress,
      true,
      this.tokenProgramId
    );

    const discriminator = Buffer.from([
      0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x70, 0x81, 0x92
    ]);

    const data = Buffer.concat([
      discriminator,
      amount.toArrayLike(Buffer, "le", 8),
    ]);

    const keys = [
      { pubkey: buyer, isSigner: true, isWritable: false },
      { pubkey: escrowAddress, isSigner: false, isWritable: true },
      { pubkey: buyerAta, isSigner: false, isWritable: true },
      { pubkey: escrowVault, isSigner: false, isWritable: true },
      { pubkey: mint, isSigner: false, isWritable: false },
      { pubkey: this.tokenProgramId, isSigner: false, isWritable: false },
    ];

    return new TransactionInstruction({
      programId: this.programId,
      keys,
      data,
    });
  }

  /**
   * Build instruction for seller to mark delivery complete
   */
  buildMarkDeliveredInstruction(
    seller: PublicKey,
    escrowAddress: PublicKey
  ): TransactionInstruction {
    const discriminator = Buffer.from([
      0x3c, 0x4d, 0x5e, 0x6f, 0x70, 0x81, 0x92, 0xa3
    ]);

    const keys = [
      { pubkey: seller, isSigner: true, isWritable: false },
      { pubkey: escrowAddress, isSigner: false, isWritable: true },
      { pubkey: SYSVAR_CLOCK_PUBKEY, isSigner: false, isWritable: false },
    ];

    return new TransactionInstruction({
      programId: this.programId,
      keys,
      data: discriminator,
    });
  }

  /**
   * Build instruction for buyer to release funds to seller
   * 
   * @param buyer - The buyer address (must sign)
   * @param seller - The seller address
   * @param escrowAddress - The escrow PDA
   * @param mint - The token mint
   * @param reputationAccounts - Optional reputation accounts for CPI update
   */
  buildReleaseFundsInstruction(
    buyer: PublicKey,
    seller: PublicKey,
    escrowAddress: PublicKey,
    mint: PublicKey,
    reputationAccounts?: ReputationAccounts
  ): TransactionInstruction {
    const escrowVault = getAssociatedTokenAddressSync(
      mint,
      escrowAddress,
      true,
      this.tokenProgramId
    );

    const sellerAta = getAssociatedTokenAddressSync(
      mint,
      seller,
      false,
      this.tokenProgramId
    );

    const discriminator = Buffer.from([
      0x4d, 0x5e, 0x6f, 0x70, 0x81, 0x92, 0xa3, 0xb4
    ]);

    const keys = [
      { pubkey: buyer, isSigner: true, isWritable: false },
      { pubkey: escrowAddress, isSigner: false, isWritable: true },
      { pubkey: escrowVault, isSigner: false, isWritable: true },
      { pubkey: sellerAta, isSigner: false, isWritable: true },
      { pubkey: mint, isSigner: false, isWritable: false },
      { pubkey: this.tokenProgramId, isSigner: false, isWritable: false },
    ];

    // Add optional reputation accounts for CPI
    if (reputationAccounts) {
      keys.push(
        { pubkey: reputationAccounts.sellerReputation, isSigner: false, isWritable: true },
        { pubkey: reputationAccounts.sellerPolicy, isSigner: false, isWritable: false },
        { 
          pubkey: reputationAccounts.reputationProgram ?? X0_REPUTATION_PROGRAM_ID, 
          isSigner: false, 
          isWritable: false 
        }
      );
    }

    return new TransactionInstruction({
      programId: this.programId,
      keys,
      data: discriminator,
    });
  }

  /**
   * Build instruction to initiate a dispute
   * 
   * @param disputeInitiator - The buyer or seller initiating the dispute
   * @param escrowAddress - The escrow PDA
   * @param reason - The dispute reason
   * @param reputationAccounts - Optional reputation accounts for CPI update
   */
  buildInitiateDisputeInstruction(
    disputeInitiator: PublicKey,
    escrowAddress: PublicKey,
    reason: string,
    reputationAccounts?: ReputationAccounts
  ): TransactionInstruction {
    const discriminator = Buffer.from([
      0x5e, 0x6f, 0x70, 0x81, 0x92, 0xa3, 0xb4, 0xc5
    ]);

    const reasonBytes = Buffer.from(reason, "utf-8");
    const data = Buffer.concat([
      discriminator,
      Buffer.from(new Uint32Array([reasonBytes.length]).buffer),
      reasonBytes,
    ]);

    const keys = [
      { pubkey: disputeInitiator, isSigner: true, isWritable: false },
      { pubkey: escrowAddress, isSigner: false, isWritable: true },
      { pubkey: SYSVAR_CLOCK_PUBKEY, isSigner: false, isWritable: false },
    ];

    // Add optional reputation accounts for CPI
    if (reputationAccounts) {
      keys.push(
        { pubkey: reputationAccounts.sellerReputation, isSigner: false, isWritable: true },
        { pubkey: reputationAccounts.sellerPolicy, isSigner: false, isWritable: false },
        { 
          pubkey: reputationAccounts.reputationProgram ?? X0_REPUTATION_PROGRAM_ID, 
          isSigner: false, 
          isWritable: false 
        }
      );
    }

    return new TransactionInstruction({
      programId: this.programId,
      keys,
      data,
    });
  }

  /**
   * Build instruction for arbiter to resolve a dispute
   */
  buildResolveDisputeInstruction(
    arbiter: PublicKey,
    escrowAddress: PublicKey,
    buyer: PublicKey,
    seller: PublicKey,
    mint: PublicKey,
    favorSeller: boolean
  ): TransactionInstruction {
    const escrowVault = getAssociatedTokenAddressSync(
      mint,
      escrowAddress,
      true,
      this.tokenProgramId
    );

    const recipient = favorSeller ? seller : buyer;
    const recipientAta = getAssociatedTokenAddressSync(
      mint,
      recipient,
      false,
      this.tokenProgramId
    );

    const discriminator = Buffer.from([
      0x6f, 0x70, 0x81, 0x92, 0xa3, 0xb4, 0xc5, 0xd6
    ]);

    const data = Buffer.concat([
      discriminator,
      Buffer.from([favorSeller ? 1 : 0]),
    ]);

    const keys = [
      { pubkey: arbiter, isSigner: true, isWritable: false },
      { pubkey: escrowAddress, isSigner: false, isWritable: true },
      { pubkey: escrowVault, isSigner: false, isWritable: true },
      { pubkey: recipientAta, isSigner: false, isWritable: true },
      { pubkey: mint, isSigner: false, isWritable: false },
      { pubkey: this.tokenProgramId, isSigner: false, isWritable: false },
    ];

    return new TransactionInstruction({
      programId: this.programId,
      keys,
      data,
    });
  }

  /**
   * Build instruction to claim auto-release after delivery + delay
   * 
   * @param seller - The seller address (must sign)
   * @param escrowAddress - The escrow PDA
   * @param mint - The token mint
   * @param reputationAccounts - Optional reputation accounts for CPI update
   */
  buildClaimAutoReleaseInstruction(
    seller: PublicKey,
    escrowAddress: PublicKey,
    mint: PublicKey,
    reputationAccounts?: ReputationAccounts
  ): TransactionInstruction {
    const escrowVault = getAssociatedTokenAddressSync(
      mint,
      escrowAddress,
      true,
      this.tokenProgramId
    );

    const sellerAta = getAssociatedTokenAddressSync(
      mint,
      seller,
      false,
      this.tokenProgramId
    );

    const discriminator = Buffer.from([
      0x70, 0x81, 0x92, 0xa3, 0xb4, 0xc5, 0xd6, 0xe7
    ]);

    const keys = [
      { pubkey: seller, isSigner: true, isWritable: false },
      { pubkey: escrowAddress, isSigner: false, isWritable: true },
      { pubkey: escrowVault, isSigner: false, isWritable: true },
      { pubkey: sellerAta, isSigner: false, isWritable: true },
      { pubkey: mint, isSigner: false, isWritable: false },
      { pubkey: this.tokenProgramId, isSigner: false, isWritable: false },
      { pubkey: SYSVAR_CLOCK_PUBKEY, isSigner: false, isWritable: false },
    ];

    // Add optional reputation accounts for CPI
    if (reputationAccounts) {
      keys.push(
        { pubkey: reputationAccounts.sellerReputation, isSigner: false, isWritable: true },
        { pubkey: reputationAccounts.sellerPolicy, isSigner: false, isWritable: false },
        { 
          pubkey: reputationAccounts.reputationProgram ?? X0_REPUTATION_PROGRAM_ID, 
          isSigner: false, 
          isWritable: false 
        }
      );
    }

    return new TransactionInstruction({
      programId: this.programId,
      keys,
      data: discriminator,
    });
  }

  /**
   * Build instruction to claim timeout refund (seller didn't deliver)
   */
  buildClaimTimeoutRefundInstruction(
    buyer: PublicKey,
    escrowAddress: PublicKey,
    mint: PublicKey
  ): TransactionInstruction {
    const escrowVault = getAssociatedTokenAddressSync(
      mint,
      escrowAddress,
      true,
      this.tokenProgramId
    );

    const buyerAta = getAssociatedTokenAddressSync(
      mint,
      buyer,
      false,
      this.tokenProgramId
    );

    const discriminator = Buffer.from([
      0x81, 0x92, 0xa3, 0xb4, 0xc5, 0xd6, 0xe7, 0xf8
    ]);

    const keys = [
      { pubkey: buyer, isSigner: true, isWritable: false },
      { pubkey: escrowAddress, isSigner: false, isWritable: true },
      { pubkey: escrowVault, isSigner: false, isWritable: true },
      { pubkey: buyerAta, isSigner: false, isWritable: true },
      { pubkey: mint, isSigner: false, isWritable: false },
      { pubkey: this.tokenProgramId, isSigner: false, isWritable: false },
      { pubkey: SYSVAR_CLOCK_PUBKEY, isSigner: false, isWritable: false },
    ];

    return new TransactionInstruction({
      programId: this.programId,
      keys,
      data: discriminator,
    });
  }

  /**
   * Build instruction to cancel unfunded escrow
   */
  buildCancelEscrowInstruction(
    buyer: PublicKey,
    escrowAddress: PublicKey
  ): TransactionInstruction {
    const discriminator = Buffer.from([
      0x92, 0xa3, 0xb4, 0xc5, 0xd6, 0xe7, 0xf8, 0x09
    ]);

    const keys = [
      { pubkey: buyer, isSigner: true, isWritable: true },
      { pubkey: escrowAddress, isSigner: false, isWritable: true },
    ];

    return new TransactionInstruction({
      programId: this.programId,
      keys,
      data: discriminator,
    });
  }

  // ============================================================================
  // Query Helpers
  // ============================================================================

  /**
   * Get all escrows for a buyer
   */
  async getEscrowsForBuyer(buyer: PublicKey): Promise<Array<{
    address: PublicKey;
    account: EscrowAccount;
  }>> {
    // Use getProgramAccounts with memcmp filter on buyer field
    const accounts = await this.connection.getProgramAccounts(this.programId, {
      filters: [
        { dataSize: 250 }, // Approximate account size
        { memcmp: { offset: 8, bytes: buyer.toBase58() } }, // After discriminator
      ],
    });

    return accounts.map(({ pubkey, account }) => ({
      address: pubkey,
      account: this.parseEscrowAccount(account.data as Buffer),
    }));
  }

  /**
   * Get all escrows for a seller
   */
  async getEscrowsForSeller(seller: PublicKey): Promise<Array<{
    address: PublicKey;
    account: EscrowAccount;
  }>> {
    const accounts = await this.connection.getProgramAccounts(this.programId, {
      filters: [
        { dataSize: 250 },
        { memcmp: { offset: 40, bytes: seller.toBase58() } }, // After discriminator + buyer
      ],
    });

    return accounts.map(({ pubkey, account }) => ({
      address: pubkey,
      account: this.parseEscrowAccount(account.data as Buffer),
    }));
  }

  // ============================================================================
  // State Helpers
  // ============================================================================

  /**
   * Get human-readable escrow state
   */
  getStateLabel(state: EscrowState): string {
    const labels: Record<EscrowState, string> = {
      0: "Created",
      1: "Funded",
      2: "Delivered",
      3: "Disputed",
      4: "Released",
      5: "Refunded",
      6: "Cancelled",
    };
    return labels[state] ?? "Unknown";
  }

  /**
   * Check if escrow can be auto-released
   */
  canAutoRelease(escrow: EscrowAccount): boolean {
    if (escrow.state !== 2) return false; // Must be Delivered
    if (!escrow.deliveredAt) return false;
    
    const releaseTime = escrow.deliveredAt + escrow.autoReleaseDelay;
    return now() >= releaseTime;
  }

  /**
   * Check if escrow can be refunded due to timeout
   */
  canTimeoutRefund(escrow: EscrowAccount): boolean {
    if (escrow.state !== 1) return false; // Must be Funded (not delivered)
    
    const timeoutTime = escrow.createdAt + escrow.deliveryTimeout;
    return now() >= timeoutTime;
  }

  /**
   * Get time until auto-release (in seconds)
   */
  getTimeUntilAutoRelease(escrow: EscrowAccount): number | null {
    if (escrow.state !== 2 || !escrow.deliveredAt) return null;
    
    const releaseTime = escrow.deliveredAt + escrow.autoReleaseDelay;
    const remaining = releaseTime - now();
    return remaining > 0 ? remaining : 0;
  }

  /**
   * Get time until timeout refund (in seconds)
   */
  getTimeUntilTimeout(escrow: EscrowAccount): number | null {
    if (escrow.state !== 1) return null;
    
    const timeoutTime = escrow.createdAt + escrow.deliveryTimeout;
    const remaining = timeoutTime - now();
    return remaining > 0 ? remaining : 0;
  }
}
