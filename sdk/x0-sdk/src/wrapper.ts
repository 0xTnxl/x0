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
} from "@solana/web3.js";
import { TOKEN_2022_PROGRAM_ID, getAssociatedTokenAddressSync } from "@solana/spl-token";
import BN from "bn.js";
import {
  X0_WRAPPER_PROGRAM_ID,
} from "./constants";

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
  /** Total USDC deposited */
  totalDeposited: BN;
  /** Total x0-USD minted */
  totalMinted: BN;
  /** Total x0-USD redeemed */
  totalRedeemed: BN;
  /** Total fees collected */
  totalFees: BN;
  /** Current reserve balance */
  currentReserve: BN;
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

    const discriminator = Buffer.from([
      0xf7, 0x5d, 0x3e, 0x1f, 0x2a, 0x4b, 0x6c, 0x8d
    ]);

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

    const discriminator = Buffer.from([
      0xa8, 0x6e, 0x4f, 0x20, 0x3b, 0x5c, 0x7d, 0x9e
    ]);

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

    const totalDeposited = new BN(data.slice(offset, offset + 8), "le");
    offset += 8;

    const totalMinted = new BN(data.slice(offset, offset + 8), "le");
    offset += 8;

    const totalRedeemed = new BN(data.slice(offset, offset + 8), "le");
    offset += 8;

    const totalFees = new BN(data.slice(offset, offset + 8), "le");
    offset += 8;

    const currentReserve = new BN(data.slice(offset, offset + 8), "le");
    offset += 8;

    const bump = data[offset];

    return {
      totalDeposited,
      totalMinted,
      totalRedeemed,
      totalFees,
      currentReserve,
      bump,
    };
  }
}
