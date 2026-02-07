/**
 * x0-USD Wrapper Client
 * 
 * Client for wrapping USDC into x0-USD and redeeming back.
 * x0-USD is the protocol's native token with transfer hooks and fees.
 */

import {
  Connection,
  PublicKey,
  TransactionInstruction,
  SystemProgram,
  SYSVAR_RENT_PUBKEY,
} from "@solana/web3.js";
import { TOKEN_2022_PROGRAM_ID, getAssociatedTokenAddressSync } from "@solana/spl-token";
import BN from "bn.js";
import {
  X0_WRAPPER_PROGRAM_ID,
  ADMIN_ACTION_SEED,
} from "./constants";
import { getInstructionDiscriminator } from "./utils";

// ============================================================================
// PDA Seeds
// ============================================================================

const WRAPPER_CONFIG_SEED = Buffer.from("wrapper_config");
const WRAPPER_STATS_SEED = Buffer.from("wrapper_stats");
const WRAPPER_RESERVE_SEED = Buffer.from("reserve");
const WRAPPER_MINT_AUTHORITY_SEED = Buffer.from("mint_authority");

// ============================================================================
// Types
// ============================================================================

/** Wrapper configuration state */
export interface WrapperConfig {
  /** Admin (should be multisig) */
  admin: PublicKey;
  /** Pending admin for transfer */
  pendingAdmin: PublicKey | null;
  /** USDC mint address */
  usdcMint: PublicKey;
  /** x0-USD wrapper mint */
  wrapperMint: PublicKey;
  /** USDC reserve account */
  reserveAccount: PublicKey;
  /** Redemption fee in basis points */
  redemptionFeeBps: number;
  /** Whether wrapper is paused */
  isPaused: boolean;
  /** PDA bump */
  bump: number;
}

/** Wrapper statistics */
export interface WrapperStats {
  /** Current USDC balance in reserve */
  reserveUsdcBalance: BN;
  /** Outstanding wrapper token supply */
  outstandingWrapperSupply: BN;
  /** Total deposits (all-time) */
  totalDeposits: BN;
  /** Total redemptions (all-time) */
  totalRedemptions: BN;
  /** Total fees collected (all-time) */
  totalFeesCollected: BN;
  /** Daily redemption volume (resets every 24h) */
  dailyRedemptionVolume: BN;
  /** Timestamp when daily counter was last reset */
  dailyRedemptionResetTimestamp: number;
  /** Last update timestamp */
  lastUpdated: number;
  /** PDA bump */
  bump: number;
}

/** Admin action type enum matching on-chain AdminActionType */
export enum AdminActionType {
  /** Change redemption fee rate */
  SetFeeRate = 0,
  /** Pause/unpause operations */
  SetPaused = 1,
  /** Emergency withdrawal */
  EmergencyWithdraw = 2,
  /** Transfer admin to new address */
  TransferAdmin = 3,
}

/** A timelocked admin action */
export interface AdminAction {
  /** Type of action */
  actionType: AdminActionType;
  /** When the action can be executed (unix timestamp) */
  scheduledTimestamp: number;
  /** New value (interpretation depends on actionType) */
  newValue: BN;
  /** New admin address (only for TransferAdmin) */
  newAdmin: PublicKey;
  /** Destination for emergency withdraw */
  destination: PublicKey;
  /** Whether this action has been executed */
  executed: boolean;
  /** Whether this action has been cancelled */
  cancelled: boolean;
  /** PDA bump */
  bump: number;
}

// ============================================================================
// Wrapper Client
// ============================================================================

export class WrapperClient {
  constructor(
    private connection: Connection,
    private programId: PublicKey = X0_WRAPPER_PROGRAM_ID
  ) {}

  // ============================================================================
  // PDA Derivation
  // ============================================================================

  /** Derive wrapper config PDA */
  deriveConfigPda(): [PublicKey, number] {
    return PublicKey.findProgramAddressSync(
      [WRAPPER_CONFIG_SEED],
      this.programId
    );
  }

  /** Derive wrapper stats PDA */
  deriveStatsPda(): [PublicKey, number] {
    return PublicKey.findProgramAddressSync(
      [WRAPPER_STATS_SEED],
      this.programId
    );
  }

  /** Derive reserve account PDA */
  deriveReservePda(usdcMint: PublicKey): [PublicKey, number] {
    return PublicKey.findProgramAddressSync(
      [WRAPPER_RESERVE_SEED, usdcMint.toBuffer()],
      this.programId
    );
  }

  /** Derive wrapper mint PDA */
  deriveWrapperMintPda(usdcMint: PublicKey): [PublicKey, number] {
    return PublicKey.findProgramAddressSync(
      [Buffer.from("wrapper_mint"), usdcMint.toBuffer()],
      this.programId
    );
  }

  /** Derive mint authority PDA */
  deriveMintAuthorityPda(wrapperMint: PublicKey): [PublicKey, number] {
    return PublicKey.findProgramAddressSync(
      [WRAPPER_MINT_AUTHORITY_SEED, wrapperMint.toBuffer()],
      this.programId
    );
  }

  // ============================================================================
  // Account Fetching
  // ============================================================================

  /** Fetch wrapper configuration */
  async fetchConfig(): Promise<WrapperConfig | null> {
    const [configPda] = this.deriveConfigPda();
    const accountInfo = await this.connection.getAccountInfo(configPda);
    if (!accountInfo) return null;
    return this.parseConfig(accountInfo.data);
  }

  /** Fetch wrapper statistics */
  async fetchStats(): Promise<WrapperStats | null> {
    const [statsPda] = this.deriveStatsPda();
    const accountInfo = await this.connection.getAccountInfo(statsPda);
    if (!accountInfo) return null;
    return this.parseStats(accountInfo.data);
  }

  // ============================================================================
  // Instruction Builders
  // ============================================================================

  /**
   * Build instruction to deposit USDC and mint x0-USD
   */
  buildDepositAndMintInstruction(
    user: PublicKey,
    amount: BN,
    usdcMint: PublicKey,
    usdcTokenProgram: PublicKey
  ): TransactionInstruction {
    const [configPda] = this.deriveConfigPda();
    const [statsPda] = this.deriveStatsPda();
    const [reservePda] = this.deriveReservePda(usdcMint);
    const [wrapperMintPda] = this.deriveWrapperMintPda(usdcMint);
    const [mintAuthorityPda] = this.deriveMintAuthorityPda(wrapperMintPda);

    const userUsdcAta = getAssociatedTokenAddressSync(
      usdcMint,
      user,
      false,
      usdcTokenProgram
    );

    const userWrapperAta = getAssociatedTokenAddressSync(
      wrapperMintPda,
      user,
      false,
      TOKEN_2022_PROGRAM_ID
    );

    const discriminator = getInstructionDiscriminator("deposit_and_mint");

    const data = Buffer.concat([
      discriminator,
      amount.toArrayLike(Buffer, "le", 8),
    ]);

    const keys = [
      { pubkey: user, isSigner: true, isWritable: true },
      { pubkey: configPda, isSigner: false, isWritable: false },
      { pubkey: statsPda, isSigner: false, isWritable: true },
      { pubkey: usdcMint, isSigner: false, isWritable: false },
      { pubkey: wrapperMintPda, isSigner: false, isWritable: true },
      { pubkey: userUsdcAta, isSigner: false, isWritable: true },
      { pubkey: userWrapperAta, isSigner: false, isWritable: true },
      { pubkey: reservePda, isSigner: false, isWritable: true },
      { pubkey: mintAuthorityPda, isSigner: false, isWritable: false },
      { pubkey: TOKEN_2022_PROGRAM_ID, isSigner: false, isWritable: false },
      { pubkey: usdcTokenProgram, isSigner: false, isWritable: false },
    ];

    return new TransactionInstruction({
      programId: this.programId,
      keys,
      data,
    });
  }

  /**
   * Build instruction to burn x0-USD and redeem USDC
   */
  buildBurnAndRedeemInstruction(
    user: PublicKey,
    amount: BN,
    usdcMint: PublicKey,
    usdcTokenProgram: PublicKey
  ): TransactionInstruction {
    const [configPda] = this.deriveConfigPda();
    const [statsPda] = this.deriveStatsPda();
    const [reservePda] = this.deriveReservePda(usdcMint);
    const [wrapperMintPda] = this.deriveWrapperMintPda(usdcMint);

    const [reserveAuthorityPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("reserve_authority")],
      this.programId
    );

    const userUsdcAta = getAssociatedTokenAddressSync(
      usdcMint,
      user,
      false,
      usdcTokenProgram
    );

    const userWrapperAta = getAssociatedTokenAddressSync(
      wrapperMintPda,
      user,
      false,
      TOKEN_2022_PROGRAM_ID
    );

    const discriminator = getInstructionDiscriminator("burn_and_redeem");

    const data = Buffer.concat([
      discriminator,
      amount.toArrayLike(Buffer, "le", 8),
    ]);

    const keys = [
      { pubkey: user, isSigner: true, isWritable: true },
      { pubkey: configPda, isSigner: false, isWritable: false },
      { pubkey: statsPda, isSigner: false, isWritable: true },
      { pubkey: usdcMint, isSigner: false, isWritable: false },
      { pubkey: wrapperMintPda, isSigner: false, isWritable: true },
      { pubkey: userWrapperAta, isSigner: false, isWritable: true },
      { pubkey: userUsdcAta, isSigner: false, isWritable: true },
      { pubkey: reservePda, isSigner: false, isWritable: true },
      { pubkey: reserveAuthorityPda, isSigner: false, isWritable: false },
      { pubkey: TOKEN_2022_PROGRAM_ID, isSigner: false, isWritable: false },
      { pubkey: usdcTokenProgram, isSigner: false, isWritable: false },
    ];

    return new TransactionInstruction({
      programId: this.programId,
      keys,
      data,
    });
  }

  // ============================================================================
  // Admin Instruction Builders
  // ============================================================================

  /** Derive admin action PDA */
  deriveAdminActionPda(nonce: BN): [PublicKey, number] {
    return PublicKey.findProgramAddressSync(
      [ADMIN_ACTION_SEED, nonce.toArrayLike(Buffer, "le", 8)],
      this.programId
    );
  }

  /**
   * Build instruction to initialize wrapper configuration.
   * This creates the WrapperConfig and WrapperStats PDAs.
   */
  buildInitializeConfigInstruction(
    admin: PublicKey,
    usdcMint: PublicKey,
    redemptionFeeBps: number
  ): TransactionInstruction {
    const [configPda] = this.deriveConfigPda();
    const [statsPda] = this.deriveStatsPda();

    const discriminator = getInstructionDiscriminator("initialize_config");

    const data = Buffer.alloc(8 + 2);
    discriminator.copy(data, 0);
    data.writeUInt16LE(redemptionFeeBps, 8);

    const keys = [
      { pubkey: admin, isSigner: true, isWritable: true },
      { pubkey: configPda, isSigner: false, isWritable: true },
      { pubkey: statsPda, isSigner: false, isWritable: true },
      { pubkey: usdcMint, isSigner: false, isWritable: false },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ];

    return new TransactionInstruction({
      programId: this.programId,
      keys,
      data,
    });
  }

  /**
   * Build instruction to initialize wrapper mint.
   * Creates the x0-USD Token-2022 mint with extensions and the USDC reserve.
   */
  buildInitializeMintInstruction(
    admin: PublicKey,
    usdcMint: PublicKey,
    usdcTokenProgram: PublicKey
  ): TransactionInstruction {
    const [configPda] = this.deriveConfigPda();
    const [wrapperMintPda] = this.deriveWrapperMintPda(usdcMint);
    const [mintAuthorityPda] = this.deriveMintAuthorityPda(wrapperMintPda);
    const [reservePda] = this.deriveReservePda(usdcMint);

    const [reserveAuthorityPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("reserve_authority")],
      this.programId
    );

    const discriminator = getInstructionDiscriminator("initialize_mint");

    const keys = [
      { pubkey: admin, isSigner: true, isWritable: true },
      { pubkey: configPda, isSigner: false, isWritable: true },
      { pubkey: usdcMint, isSigner: false, isWritable: false },
      { pubkey: wrapperMintPda, isSigner: false, isWritable: true },
      { pubkey: mintAuthorityPda, isSigner: false, isWritable: false },
      { pubkey: reservePda, isSigner: false, isWritable: true },
      { pubkey: reserveAuthorityPda, isSigner: false, isWritable: false },
      { pubkey: TOKEN_2022_PROGRAM_ID, isSigner: false, isWritable: false },
      { pubkey: usdcTokenProgram, isSigner: false, isWritable: false },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      { pubkey: SYSVAR_RENT_PUBKEY, isSigner: false, isWritable: false },
    ];

    return new TransactionInstruction({
      programId: this.programId,
      keys,
      data: discriminator,
    });
  }

  /**
   * Build instruction to schedule a fee change (timelocked).
   * Must wait ADMIN_TIMELOCK_SECONDS before execution.
   * 
   * @param admin - Admin signer
   * @param actionNonce - Unique nonce for the admin action PDA
   * @param newFeeBps - New redemption fee in basis points
   */
  buildScheduleFeeChangeInstruction(
    admin: PublicKey,
    actionNonce: BN,
    newFeeBps: number
  ): TransactionInstruction {
    const [configPda] = this.deriveConfigPda();
    const [actionPda] = this.deriveAdminActionPda(actionNonce);

    const discriminator = getInstructionDiscriminator("schedule_fee_change");

    const data = Buffer.alloc(8 + 8 + 2);
    discriminator.copy(data, 0);
    actionNonce.toArrayLike(Buffer, "le", 8).copy(data, 8);
    data.writeUInt16LE(newFeeBps, 16);

    const keys = [
      { pubkey: admin, isSigner: true, isWritable: true },
      { pubkey: configPda, isSigner: false, isWritable: false },
      { pubkey: actionPda, isSigner: false, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ];

    return new TransactionInstruction({
      programId: this.programId,
      keys,
      data,
    });
  }

  /**
   * Build instruction to execute a scheduled fee change.
   * Only succeeds after timelock period has elapsed.
   */
  buildExecuteFeeChangeInstruction(
    admin: PublicKey,
    actionPda: PublicKey
  ): TransactionInstruction {
    const [configPda] = this.deriveConfigPda();

    const discriminator = getInstructionDiscriminator("execute_fee_change");

    const keys = [
      { pubkey: admin, isSigner: true, isWritable: false },
      { pubkey: configPda, isSigner: false, isWritable: true },
      { pubkey: actionPda, isSigner: false, isWritable: true },
    ];

    return new TransactionInstruction({
      programId: this.programId,
      keys,
      data: discriminator,
    });
  }

  /**
   * Build instruction to schedule a pause/unpause (timelocked).
   */
  buildSchedulePauseInstruction(
    admin: PublicKey,
    actionNonce: BN,
    pause: boolean
  ): TransactionInstruction {
    const [configPda] = this.deriveConfigPda();
    const [actionPda] = this.deriveAdminActionPda(actionNonce);

    const discriminator = getInstructionDiscriminator("schedule_pause");

    const data = Buffer.alloc(8 + 8 + 1);
    discriminator.copy(data, 0);
    actionNonce.toArrayLike(Buffer, "le", 8).copy(data, 8);
    data.writeUInt8(pause ? 1 : 0, 16);

    const keys = [
      { pubkey: admin, isSigner: true, isWritable: true },
      { pubkey: configPda, isSigner: false, isWritable: false },
      { pubkey: actionPda, isSigner: false, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ];

    return new TransactionInstruction({
      programId: this.programId,
      keys,
      data,
    });
  }

  /**
   * Build instruction to execute a scheduled pause/unpause.
   */
  buildExecutePauseInstruction(
    admin: PublicKey,
    actionPda: PublicKey
  ): TransactionInstruction {
    const [configPda] = this.deriveConfigPda();

    const discriminator = getInstructionDiscriminator("execute_pause");

    const keys = [
      { pubkey: admin, isSigner: true, isWritable: false },
      { pubkey: configPda, isSigner: false, isWritable: true },
      { pubkey: actionPda, isSigner: false, isWritable: true },
    ];

    return new TransactionInstruction({
      programId: this.programId,
      keys,
      data: discriminator,
    });
  }

  /**
   * Build instruction for emergency pause (bypasses timelock).
   * Immediately pauses the wrapper — no timelock required.
   */
  buildEmergencyPauseInstruction(
    admin: PublicKey
  ): TransactionInstruction {
    const [configPda] = this.deriveConfigPda();

    const discriminator = getInstructionDiscriminator("emergency_pause");

    const keys = [
      { pubkey: admin, isSigner: true, isWritable: false },
      { pubkey: configPda, isSigner: false, isWritable: true },
    ];

    return new TransactionInstruction({
      programId: this.programId,
      keys,
      data: discriminator,
    });
  }

  /**
   * Build instruction to schedule an emergency withdrawal (timelocked).
   * 
   * @param admin - Admin signer
   * @param actionNonce - Unique nonce for the admin action PDA
   * @param amount - Amount of USDC to withdraw from reserve
   * @param destination - Destination pubkey (must match on execution)
   */
  buildScheduleEmergencyWithdrawInstruction(
    admin: PublicKey,
    actionNonce: BN,
    amount: BN,
    destination: PublicKey
  ): TransactionInstruction {
    const [configPda] = this.deriveConfigPda();
    const [actionPda] = this.deriveAdminActionPda(actionNonce);

    const discriminator = getInstructionDiscriminator("schedule_emergency_withdraw");

    const data = Buffer.alloc(8 + 8 + 8 + 32);
    discriminator.copy(data, 0);
    actionNonce.toArrayLike(Buffer, "le", 8).copy(data, 8);
    amount.toArrayLike(Buffer, "le", 8).copy(data, 16);
    destination.toBuffer().copy(data, 24);

    const keys = [
      { pubkey: admin, isSigner: true, isWritable: true },
      { pubkey: configPda, isSigner: false, isWritable: false },
      { pubkey: actionPda, isSigner: false, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ];

    return new TransactionInstruction({
      programId: this.programId,
      keys,
      data,
    });
  }

  /**
   * Build instruction to execute an emergency withdrawal.
   * Transfers USDC from reserve to the scheduled destination.
   */
  buildExecuteEmergencyWithdrawInstruction(
    admin: PublicKey,
    actionPda: PublicKey,
    usdcMint: PublicKey,
    destinationAccount: PublicKey,
    usdcTokenProgram: PublicKey
  ): TransactionInstruction {
    const [configPda] = this.deriveConfigPda();
    const [statsPda] = this.deriveStatsPda();
    const [reservePda] = this.deriveReservePda(usdcMint);

    const [reserveAuthorityPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("reserve_authority")],
      this.programId
    );

    const discriminator = getInstructionDiscriminator("execute_emergency_withdraw");

    const keys = [
      { pubkey: admin, isSigner: true, isWritable: false },
      { pubkey: configPda, isSigner: false, isWritable: true },
      { pubkey: statsPda, isSigner: false, isWritable: true },
      { pubkey: actionPda, isSigner: false, isWritable: true },
      { pubkey: usdcMint, isSigner: false, isWritable: false },
      { pubkey: reservePda, isSigner: false, isWritable: true },
      { pubkey: destinationAccount, isSigner: false, isWritable: true },
      { pubkey: reserveAuthorityPda, isSigner: false, isWritable: false },
      { pubkey: usdcTokenProgram, isSigner: false, isWritable: false },
    ];

    return new TransactionInstruction({
      programId: this.programId,
      keys,
      data: discriminator,
    });
  }

  /**
   * Build instruction to cancel a scheduled admin action.
   */
  buildCancelAdminActionInstruction(
    admin: PublicKey,
    actionPda: PublicKey
  ): TransactionInstruction {
    const [configPda] = this.deriveConfigPda();

    const discriminator = getInstructionDiscriminator("cancel_admin_action");

    const keys = [
      { pubkey: admin, isSigner: true, isWritable: false },
      { pubkey: configPda, isSigner: false, isWritable: false },
      { pubkey: actionPda, isSigner: false, isWritable: true },
    ];

    return new TransactionInstruction({
      programId: this.programId,
      keys,
      data: discriminator,
    });
  }

  /**
   * Build instruction to initiate an admin transfer (2-step process).
   * Sets the pending admin; new admin must call accept_admin_transfer.
   */
  buildInitiateAdminTransferInstruction(
    admin: PublicKey,
    newAdmin: PublicKey
  ): TransactionInstruction {
    const [configPda] = this.deriveConfigPda();

    const discriminator = getInstructionDiscriminator("initiate_admin_transfer");

    const data = Buffer.alloc(8 + 32);
    discriminator.copy(data, 0);
    newAdmin.toBuffer().copy(data, 8);

    const keys = [
      { pubkey: admin, isSigner: true, isWritable: false },
      { pubkey: configPda, isSigner: false, isWritable: true },
    ];

    return new TransactionInstruction({
      programId: this.programId,
      keys,
      data,
    });
  }

  /**
   * Build instruction to accept an admin transfer.
   * Must be signed by the pending admin set in initiate_admin_transfer.
   */
  buildAcceptAdminTransferInstruction(
    newAdmin: PublicKey
  ): TransactionInstruction {
    const [configPda] = this.deriveConfigPda();

    const discriminator = getInstructionDiscriminator("accept_admin_transfer");

    const keys = [
      { pubkey: newAdmin, isSigner: true, isWritable: false },
      { pubkey: configPda, isSigner: false, isWritable: true },
    ];

    return new TransactionInstruction({
      programId: this.programId,
      keys,
      data: discriminator,
    });
  }

  // ============================================================================
  // Helper Methods
  // ============================================================================

  /**
   * Calculate redemption fee
   * @param amount Amount to redeem
   * @param feeBps Fee in basis points
   * @returns [fee, payout]
   */
  calculateRedemptionFee(amount: BN, feeBps: number): [BN, BN] {
    const fee = amount.muln(feeBps).divn(10000);
    const payout = amount.sub(fee);
    return [fee, payout];
  }

  /**
   * Calculate reserve ratio
   * @param reserve USDC reserve balance
   * @param supply x0-USD supply
   * @returns Ratio scaled by 10000 (10000 = 1.0)
   */
  calculateReserveRatio(reserve: BN, supply: BN): number {
    if (supply.isZero()) return 10000;
    return reserve.muln(10000).div(supply).toNumber();
  }

  /**
   * Check if reserve ratio is healthy (>= 1.0)
   */
  isReserveHealthy(reserve: BN, supply: BN): boolean {
    return this.calculateReserveRatio(reserve, supply) >= 10000;
  }

  // ============================================================================
  // Parsing
  // ============================================================================

  private parseConfig(data: Buffer): WrapperConfig {
    // Skip 8-byte discriminator
    let offset = 8;

    const admin = new PublicKey(data.slice(offset, offset + 32));
    offset += 32;

    const hasPendingAdmin = data[offset] === 1;
    offset += 1;
    const pendingAdmin = hasPendingAdmin
      ? new PublicKey(data.slice(offset, offset + 32))
      : null;
    offset += 32;

    const usdcMint = new PublicKey(data.slice(offset, offset + 32));
    offset += 32;

    const wrapperMint = new PublicKey(data.slice(offset, offset + 32));
    offset += 32;

    const reserveAccount = new PublicKey(data.slice(offset, offset + 32));
    offset += 32;

    const redemptionFeeBps = data.readUInt16LE(offset);
    offset += 2;

    const isPaused = data[offset] === 1;
    offset += 1;

    const bump = data[offset];

    return {
      admin,
      pendingAdmin,
      usdcMint,
      wrapperMint,
      reserveAccount,
      redemptionFeeBps,
      isPaused,
      bump,
    };
  }

  private parseStats(data: Buffer): WrapperStats {
    // Skip 8-byte discriminator
    let offset = 8;

    const reserveUsdcBalance = new BN(data.slice(offset, offset + 8), "le");
    offset += 8;

    const outstandingWrapperSupply = new BN(data.slice(offset, offset + 8), "le");
    offset += 8;

    const totalDeposits = new BN(data.slice(offset, offset + 8), "le");
    offset += 8;

    const totalRedemptions = new BN(data.slice(offset, offset + 8), "le");
    offset += 8;

    const totalFeesCollected = new BN(data.slice(offset, offset + 8), "le");
    offset += 8;

    const dailyRedemptionVolume = new BN(data.slice(offset, offset + 8), "le");
    offset += 8;

    const dailyRedemptionResetTimestamp = new BN(data.slice(offset, offset + 8), "le").toNumber();
    offset += 8;

    const lastUpdated = new BN(data.slice(offset, offset + 8), "le").toNumber();
    offset += 8;

    const bump = data[offset]!;

    return {
      reserveUsdcBalance,
      outstandingWrapperSupply,
      totalDeposits,
      totalRedemptions,
      totalFeesCollected,
      dailyRedemptionVolume,
      dailyRedemptionResetTimestamp,
      lastUpdated,
      bump,
    };
  }
}
