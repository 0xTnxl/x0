/**
 * x0-Token Client
 * 
 * Client for managing x0-Token mints with Token-2022 extensions:
 * - Transfer Hook (routes to x0-guard)
 * - Transfer Fee (0.8% protocol fee)
 * - Confidential Transfers (optional ZK-encrypted amounts)
 */

import {
  Connection,
  PublicKey,
  TransactionInstruction,
  SystemProgram,
  Keypair,
  SYSVAR_RENT_PUBKEY,
} from "@solana/web3.js";
import {
  TOKEN_2022_PROGRAM_ID,
  getAssociatedTokenAddressSync,
  createAssociatedTokenAccountInstruction,
} from "@solana/spl-token";
import BN from "bn.js";
import { sha256 } from "@noble/hashes/sha256";
import {
  X0_TOKEN_PROGRAM_ID,
  X0_GUARD_PROGRAM_ID,
  PROTOCOL_FEE_BASIS_POINTS,
} from "./constants";

// ============================================================================
// Types
// ============================================================================

/** Configuration for initializing a new x0-Token mint */
export interface InitializeMintParams {
  /** The mint keypair (must sign) */
  mint: Keypair;
  /** The mint authority (must sign) */
  mintAuthority: PublicKey;
  /** Token decimals (recommended: 6) */
  decimals: number;
  /** Fee receiver address (treasury) */
  feeReceiver: PublicKey;
  /** Enable confidential transfers (default: false) */
  enableConfidential?: boolean;
}

/** Configuration for minting tokens */
export interface MintTokensParams {
  /** The mint address */
  mint: PublicKey;
  /** The destination token account */
  destination: PublicKey;
  /** Amount to mint (in base units) */
  amount: BN;
}

/** Configuration for configuring confidential transfers on a mint */
export interface ConfigureConfidentialParams {
  /** The mint address */
  mint: PublicKey;
  /** Auto-approve new accounts for confidential transfers */
  autoApproveNewAccounts?: boolean;
}

/** Configuration for depositing to confidential balance */
export interface DepositConfidentialParams {
  /** The mint address */
  mint: PublicKey;
  /** The token account */
  tokenAccount: PublicKey;
  /** Amount to deposit (in base units) */
  amount: BN;
}

/** Mint information with extension data */
export interface X0TokenMintInfo {
  /** Mint address */
  address: PublicKey;
  /** Mint authority */
  mintAuthority: PublicKey | null;
  /** Current supply */
  supply: BN;
  /** Token decimals */
  decimals: number;
  /** Transfer hook program ID */
  transferHookProgramId: PublicKey | null;
  /** Transfer fee basis points */
  transferFeeBps: number;
  /** Fee receiver */
  feeReceiver: PublicKey | null;
  /** Confidential transfers enabled */
  confidentialEnabled: boolean;
}

// ============================================================================
// Instruction Discriminators
// ============================================================================

function getInstructionDiscriminator(namespace: string, name: string): Buffer {
  const preimage = `${namespace}:${name}`;
  const hash = sha256(Buffer.from(preimage));
  return Buffer.from(hash.slice(0, 8));
}

// ============================================================================
// Token Client
// ============================================================================

export class TokenClient {
  constructor(
    private connection: Connection,
    private programId: PublicKey = X0_TOKEN_PROGRAM_ID
  ) {}

  // ============================================================================
  // Instruction Builders
  // ============================================================================

  /**
   * Build instruction to initialize a new x0-Token mint with extensions
   * 
   * The mint will be configured with:
   * - Transfer Hook pointing to x0-guard
   * - Transfer Fee of 0.8%
   * - Confidential Transfers (if enabled)
   */
  buildInitializeMintInstruction(
    params: InitializeMintParams,
    payer: PublicKey
  ): TransactionInstruction {
    const {
      mint,
      mintAuthority,
      decimals,
      feeReceiver,
      enableConfidential = false,
    } = params;

    const discriminator = getInstructionDiscriminator("global", "initialize_mint");

    // Encode: discriminator (8) + decimals (u8) + enable_confidential (bool)
    const data = Buffer.alloc(8 + 1 + 1);
    discriminator.copy(data, 0);
    data.writeUInt8(decimals, 8);
    data.writeUInt8(enableConfidential ? 1 : 0, 9);

    return new TransactionInstruction({
      programId: this.programId,
      keys: [
        { pubkey: payer, isSigner: true, isWritable: true },
        { pubkey: mintAuthority, isSigner: true, isWritable: false },
        { pubkey: mint.publicKey, isSigner: true, isWritable: true },
        { pubkey: feeReceiver, isSigner: false, isWritable: false },
        { pubkey: TOKEN_2022_PROGRAM_ID, isSigner: false, isWritable: false },
        { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
        { pubkey: SYSVAR_RENT_PUBKEY, isSigner: false, isWritable: false },
      ],
      data,
    });
  }

  /**
   * Build instruction to configure confidential transfers on a mint
   */
  buildConfigureConfidentialInstruction(
    params: ConfigureConfidentialParams,
    authority: PublicKey
  ): TransactionInstruction {
    const { mint, autoApproveNewAccounts = true } = params;

    const discriminator = getInstructionDiscriminator(
      "global",
      "configure_confidential_transfers"
    );

    // Encode: discriminator (8) + auto_approve (bool)
    const data = Buffer.alloc(8 + 1);
    discriminator.copy(data, 0);
    data.writeUInt8(autoApproveNewAccounts ? 1 : 0, 8);

    return new TransactionInstruction({
      programId: this.programId,
      keys: [
        { pubkey: authority, isSigner: true, isWritable: false },
        { pubkey: mint, isSigner: false, isWritable: true },
        { pubkey: TOKEN_2022_PROGRAM_ID, isSigner: false, isWritable: false },
      ],
      data,
    });
  }

  /**
   * Build instruction to mint tokens
   */
  buildMintTokensInstruction(
    params: MintTokensParams,
    authority: PublicKey
  ): TransactionInstruction {
    const { mint, destination, amount } = params;

    const discriminator = getInstructionDiscriminator("global", "mint_tokens");

    // Encode: discriminator (8) + amount (u64)
    const data = Buffer.alloc(8 + 8);
    discriminator.copy(data, 0);
    data.writeBigUInt64LE(BigInt(amount.toString()), 8);

    return new TransactionInstruction({
      programId: this.programId,
      keys: [
        { pubkey: authority, isSigner: true, isWritable: false },
        { pubkey: mint, isSigner: false, isWritable: true },
        { pubkey: destination, isSigner: false, isWritable: true },
        { pubkey: TOKEN_2022_PROGRAM_ID, isSigner: false, isWritable: false },
      ],
      data,
    });
  }

  /**
   * Build instruction to deposit tokens from public to confidential balance
   */
  buildDepositConfidentialInstruction(
    params: DepositConfidentialParams,
    owner: PublicKey
  ): TransactionInstruction {
    const { mint, tokenAccount, amount } = params;

    const discriminator = getInstructionDiscriminator(
      "global",
      "deposit_to_confidential"
    );

    // Encode: discriminator (8) + amount (u64)
    const data = Buffer.alloc(8 + 8);
    discriminator.copy(data, 0);
    data.writeBigUInt64LE(BigInt(amount.toString()), 8);

    return new TransactionInstruction({
      programId: this.programId,
      keys: [
        { pubkey: owner, isSigner: true, isWritable: false },
        { pubkey: tokenAccount, isSigner: false, isWritable: true },
        { pubkey: mint, isSigner: false, isWritable: false },
        { pubkey: TOKEN_2022_PROGRAM_ID, isSigner: false, isWritable: false },
      ],
      data,
    });
  }

  /**
   * Build instruction to withdraw protocol fees from token accounts
   */
  buildWithdrawFeesInstruction(
    mint: PublicKey,
    sourceAccounts: PublicKey[],
    feeReceiver: PublicKey,
    authority: PublicKey
  ): TransactionInstruction {
    const discriminator = getInstructionDiscriminator("global", "withdraw_fees");

    // Encode: discriminator only (no additional args)
    const data = Buffer.from(discriminator);

    const keys = [
      { pubkey: authority, isSigner: true, isWritable: false },
      { pubkey: mint, isSigner: false, isWritable: false },
      { pubkey: feeReceiver, isSigner: false, isWritable: true },
      { pubkey: TOKEN_2022_PROGRAM_ID, isSigner: false, isWritable: false },
      // Add source accounts
      ...sourceAccounts.map((account) => ({
        pubkey: account,
        isSigner: false,
        isWritable: true,
      })),
    ];

    return new TransactionInstruction({
      programId: this.programId,
      keys,
      data,
    });
  }

  /**
   * Build instruction to harvest withheld transfer fees from token accounts.
   * 
   * Unlike withdraw_fees which moves fees to the fee receiver,
   * harvest_fees collects withheld fees from individual token accounts
   * back to the mint's withheld amount, where they can then be withdrawn.
   * 
   * @param mint - The token mint
   * @param authority - The mint authority (signer)
   * @param sourceAccounts - Token accounts to harvest fees from (passed as remaining accounts)
   */
  buildHarvestFeesInstruction(
    mint: PublicKey,
    authority: PublicKey,
    sourceAccounts: PublicKey[]
  ): TransactionInstruction {
    const discriminator = getInstructionDiscriminator("global", "harvest_fees");

    const data = Buffer.from(discriminator);

    const keys = [
      { pubkey: authority, isSigner: true, isWritable: false },
      { pubkey: mint, isSigner: false, isWritable: true },
      { pubkey: TOKEN_2022_PROGRAM_ID, isSigner: false, isWritable: false },
      // Source accounts to harvest from (remaining accounts)
      ...sourceAccounts.map((account) => ({
        pubkey: account,
        isSigner: false,
        isWritable: true,
      })),
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
   * Get the associated token address for a Token-2022 mint
   */
  getAssociatedTokenAddress(mint: PublicKey, owner: PublicKey): PublicKey {
    return getAssociatedTokenAddressSync(mint, owner, false, TOKEN_2022_PROGRAM_ID);
  }

  /**
   * Build instruction to create an associated token account for Token-2022
   */
  buildCreateATAInstruction(
    mint: PublicKey,
    owner: PublicKey,
    payer: PublicKey
  ): TransactionInstruction {
    const ata = this.getAssociatedTokenAddress(mint, owner);
    return createAssociatedTokenAccountInstruction(
      payer,
      ata,
      owner,
      mint,
      TOKEN_2022_PROGRAM_ID
    );
  }

  /**
   * Fetch mint information including extension data
   */
  async fetchMintInfo(mint: PublicKey): Promise<X0TokenMintInfo | null> {
    const accountInfo = await this.connection.getAccountInfo(mint);
    if (!accountInfo) {
      return null;
    }

    // Parse mint data (simplified - production would use spl-token-2022 parsing)
    const data = accountInfo.data;
    
    // Basic mint data starts at offset 0
    // This is a simplified parser - production would use @solana/spl-token
    const mintAuthorityOption = data.readUInt32LE(0);
    const mintAuthority = mintAuthorityOption === 1
      ? new PublicKey(data.slice(4, 36))
      : null;
    
    const supply = new BN(data.slice(36, 44), "le");
    const decimals = data.readUInt8(44);

    // For full extension parsing, use @solana/spl-token's getMint with Token-2022
    return {
      address: mint,
      mintAuthority,
      supply,
      decimals,
      transferHookProgramId: X0_GUARD_PROGRAM_ID, // Known for x0-tokens
      transferFeeBps: PROTOCOL_FEE_BASIS_POINTS,
      feeReceiver: null, // Would need extension parsing
      confidentialEnabled: false, // Would need extension parsing
    };
  }

  /**
   * Calculate transfer fee for an amount
   */
  calculateTransferFee(amount: BN): BN {
    // 0.8% = 80 basis points
    return amount.mul(new BN(PROTOCOL_FEE_BASIS_POINTS)).div(new BN(10000));
  }

  /**
   * Calculate amount after transfer fee deduction
   */
  calculateAmountAfterFee(amount: BN): BN {
    const fee = this.calculateTransferFee(amount);
    return amount.sub(fee);
  }
}

// ============================================================================
// Convenience Functions
// ============================================================================

/**
 * Create a TokenClient instance
 */
export function createTokenClient(
  connection: Connection,
  programId: PublicKey = X0_TOKEN_PROGRAM_ID
): TokenClient {
  return new TokenClient(connection, programId);
}

/**
 * Derive extra account metas PDA for transfer hook
 */
export function deriveExtraAccountMetasPda(mint: PublicKey): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("extra-account-metas"), mint.toBuffer()],
    X0_GUARD_PROGRAM_ID
  );
}
