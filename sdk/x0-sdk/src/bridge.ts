/**
 * x0 Bridge Client
 *
 * TypeScript SDK for the x0 cross-chain bridge (Base → Solana).
 * Handles:
 *   - Bridge config initialization
 *   - USDC reserve management
 *   - EVM proof submission
 *   - Mint execution
 *   - Admin operations (pause, domain management, etc.)
 *
 * @example
 * ```ts
 * import { BridgeClient } from "@x0-protocol/sdk";
 * import { Connection, PublicKey } from "@solana/web3.js";
 *
 * const connection = new Connection("https://api.devnet.solana.com");
 * const bridge = new BridgeClient(connection);
 *
 * // Fetch bridge config
 * const config = await bridge.fetchConfig();
 * console.log("Total bridged in:", config.totalBridgedIn.toString());
 *
 * // Build verify + mint instructions
 * const verifyIx = bridge.buildVerifyEvmProofInstruction({
 *   messageId, proofData, publicValues, operator
 * });
 * ```
 *
 * @packageDocumentation
 */

import {
  Connection,
  PublicKey,
  TransactionInstruction,
  SystemProgram,
  SYSVAR_CLOCK_PUBKEY,
  SYSVAR_RENT_PUBKEY,
} from "@solana/web3.js";
import {
  TOKEN_2022_PROGRAM_ID,
  TOKEN_PROGRAM_ID,
  getAssociatedTokenAddressSync,
  ASSOCIATED_TOKEN_PROGRAM_ID,
} from "@solana/spl-token";
import BN from "bn.js";
import { getInstructionDiscriminator } from "./utils";
import { X0_BRIDGE_PROGRAM_ID, X0_WRAPPER_PROGRAM_ID } from "./constants";

// ============================================================================
// PDA Seeds (matching on-chain constants)
// ============================================================================

const BRIDGE_CONFIG_SEED = Buffer.from("bridge_config");
const BRIDGE_MESSAGE_SEED = Buffer.from("bridge_message");
const EVM_PROOF_CONTEXT_SEED = Buffer.from("evm_proof_context");
const BRIDGE_RESERVE_SEED = Buffer.from("bridge_reserve");
const BRIDGE_RESERVE_AUTHORITY_SEED = Buffer.from("bridge_reserve_authority");

// ============================================================================
// Types
// ============================================================================

/** On-chain BridgeConfig account data */
export interface BridgeConfig {
  admin: PublicKey;
  operator: PublicKey;
  wrapperProgram: PublicKey;
  sp1VerifierProgram: PublicKey;
  hyperlaneMailbox: PublicKey;
  bridgeReserve: PublicKey;
  usdcMint: PublicKey;
  wrapperMint: PublicKey;
  allowedDomains: number[];
  allowedEvmContracts: Uint8Array[];
  totalBridgedIn: BN;
  totalBridgedOut: BN;
  dailyVolume: BN;
  dailyVolumeReset: BN;
  isPaused: boolean;
  nonceCounter: BN;
  bump: number;
  version: number;
}

/** On-chain BridgeMessage account data */
export interface BridgeMessage {
  originDomain: number;
  sender: Uint8Array; // 20 bytes EVM address
  recipient: PublicKey;
  amount: BN;
  nonce: BN;
  messageId: Uint8Array; // 32 bytes
  hyperlaneMessageId: Uint8Array; // 32 bytes
  receivedAt: BN;
  status: BridgeMessageStatus;
  bump: number;
  version: number;
}

export enum BridgeMessageStatus {
  Received = 0,
  ProofVerified = 1,
  Minted = 2,
  Failed = 3,
}

/** On-chain EVMProofContext account data */
export interface EVMProofContext {
  version: number;
  proofType: EVMProofType;
  verified: boolean;
  verifiedAt: BN;
  blockHash: Uint8Array;
  blockNumber: BN;
  txHash: Uint8Array;
  evmSender: Uint8Array;
  evmContract: Uint8Array;
  amount: BN;
  solanaRecipient: PublicKey;
  nonce: BN;
  eventSignature: Uint8Array;
  isConsumed: boolean;
  bump: number;
}

export enum EVMProofType {
  LockDeposit = 0,
  BatchDeposit = 1,
}

/** Parameters for initializing the bridge */
export interface InitializeBridgeParams {
  admin: PublicKey;
  operator: PublicKey;
  wrapperProgram: PublicKey;
  sp1VerifierProgram: PublicKey;
  hyperlaneMailbox: PublicKey;
  usdcMint: PublicKey;
  wrapperMint: PublicKey;
  initialDomains: number[];
}

/** Parameters for verifying an EVM proof */
export interface VerifyEvmProofParams {
  messageId: Uint8Array; // 32 bytes
  proofData: Buffer;
  publicValues: Buffer;
  operator: PublicKey;
}

/** Parameters for executing a mint after proof verification */
export interface ExecuteMintParams {
  messageId: Uint8Array; // 32 bytes
  recipient: PublicKey;
  operator: PublicKey;
  wrapperConfig: PublicKey;
  wrapperMintAuthority: PublicKey;
  wrapperStats: PublicKey;
  wrapperReserveAccount: PublicKey;
}

/** Parameters for replenishing the bridge reserve */
export interface ReplenishReserveParams {
  amount: BN;
  depositor: PublicKey;
  depositorUsdcAccount: PublicKey;
}

// ============================================================================
// Bridge Client
// ============================================================================

export class BridgeClient {
  constructor(
    private connection: Connection,
    private programId: PublicKey = X0_BRIDGE_PROGRAM_ID
  ) {}

  // --------------------------------------------------------------------------
  // PDA Derivation
  // --------------------------------------------------------------------------

  /** Derive the BridgeConfig PDA */
  deriveConfigPda(): [PublicKey, number] {
    return PublicKey.findProgramAddressSync(
      [BRIDGE_CONFIG_SEED],
      this.programId
    );
  }

  /** Derive the BridgeMessage PDA for a given message ID */
  deriveMessagePda(messageId: Uint8Array): [PublicKey, number] {
    return PublicKey.findProgramAddressSync(
      [BRIDGE_MESSAGE_SEED, Buffer.from(messageId)],
      this.programId
    );
  }

  /** Derive the EVMProofContext PDA for a given message ID */
  deriveProofContextPda(messageId: Uint8Array): [PublicKey, number] {
    return PublicKey.findProgramAddressSync(
      [EVM_PROOF_CONTEXT_SEED, Buffer.from(messageId)],
      this.programId
    );
  }

  /** Derive the bridge reserve authority PDA */
  deriveReserveAuthorityPda(): [PublicKey, number] {
    return PublicKey.findProgramAddressSync(
      [BRIDGE_RESERVE_AUTHORITY_SEED],
      this.programId
    );
  }

  /** Derive the bridge USDC reserve token account PDA */
  deriveReservePda(usdcMint: PublicKey): [PublicKey, number] {
    return PublicKey.findProgramAddressSync(
      [BRIDGE_RESERVE_SEED, usdcMint.toBuffer()],
      this.programId
    );
  }

  // --------------------------------------------------------------------------
  // Account Fetching
  // --------------------------------------------------------------------------

  /** Fetch and deserialize the BridgeConfig account */
  async fetchConfig(): Promise<BridgeConfig | null> {
    const [configPda] = this.deriveConfigPda();
    const accountInfo = await this.connection.getAccountInfo(configPda);

    if (!accountInfo) {
      return null;
    }

    return this.deserializeBridgeConfig(accountInfo.data);
  }

  /** Fetch and deserialize a BridgeMessage account */
  async fetchMessage(messageId: Uint8Array): Promise<BridgeMessage | null> {
    const [messagePda] = this.deriveMessagePda(messageId);
    const accountInfo = await this.connection.getAccountInfo(messagePda);

    if (!accountInfo) {
      return null;
    }

    return this.deserializeBridgeMessage(accountInfo.data);
  }

  /** Fetch and deserialize an EVMProofContext account */
  async fetchProofContext(
    messageId: Uint8Array
  ): Promise<EVMProofContext | null> {
    const [proofPda] = this.deriveProofContextPda(messageId);
    const accountInfo = await this.connection.getAccountInfo(proofPda);

    if (!accountInfo) {
      return null;
    }

    return this.deserializeEVMProofContext(accountInfo.data);
  }

  /** Check if the bridge is currently paused */
  async isPaused(): Promise<boolean> {
    const config = await this.fetchConfig();
    return config?.isPaused ?? true;
  }

  /** Get remaining daily volume capacity */
  async remainingDailyVolume(): Promise<BN> {
    const config = await this.fetchConfig();
    if (!config) {
      return new BN(0);
    }

    const now = Math.floor(Date.now() / 1000);
    const resetAt = config.dailyVolumeReset.toNumber();

    // If 24 hours have passed since last reset, full limit is available
    if (now >= resetAt + 86_400) {
      return new BN("50000000000000"); // 50M USDC default
    }

    const dailyLimit = new BN("50000000000000");
    const remaining = dailyLimit.sub(config.dailyVolume);
    return remaining.isNeg() ? new BN(0) : remaining;
  }

  // --------------------------------------------------------------------------
  // Instruction Builders
  // --------------------------------------------------------------------------

  /** Build the initialize bridge instruction */
  buildInitializeInstruction(
    params: InitializeBridgeParams
  ): TransactionInstruction {
    const [configPda] = this.deriveConfigPda();
    const [reserveAuthority] = this.deriveReserveAuthorityPda();
    const [bridgeReserve] = this.deriveReservePda(params.usdcMint);

    const discriminator = getInstructionDiscriminator("initialize");

    // Serialize args: domains as u32 LE array
    const domainsBuf = Buffer.alloc(4 + params.initialDomains.length * 4);
    domainsBuf.writeUInt32LE(params.initialDomains.length, 0);
    params.initialDomains.forEach((d, i) => {
      domainsBuf.writeUInt32LE(d, 4 + i * 4);
    });

    const data = Buffer.concat([discriminator, domainsBuf]);

    const keys = [
      { pubkey: params.admin, isSigner: true, isWritable: true },
      { pubkey: configPda, isSigner: false, isWritable: true },
      { pubkey: bridgeReserve, isSigner: false, isWritable: true },
      { pubkey: reserveAuthority, isSigner: false, isWritable: false },
      { pubkey: params.usdcMint, isSigner: false, isWritable: false },
      { pubkey: params.wrapperMint, isSigner: false, isWritable: false },
      { pubkey: params.wrapperProgram, isSigner: false, isWritable: false },
      { pubkey: params.sp1VerifierProgram, isSigner: false, isWritable: false },
      { pubkey: params.hyperlaneMailbox, isSigner: false, isWritable: false },
      { pubkey: params.operator, isSigner: false, isWritable: false },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      { pubkey: TOKEN_PROGRAM_ID, isSigner: false, isWritable: false },
      { pubkey: SYSVAR_RENT_PUBKEY, isSigner: false, isWritable: false },
    ];

    return new TransactionInstruction({
      programId: this.programId,
      keys,
      data,
    });
  }

  /** Build the verify_evm_proof instruction */
  buildVerifyEvmProofInstruction(
    params: VerifyEvmProofParams
  ): TransactionInstruction {
    const [configPda] = this.deriveConfigPda();
    const [proofContextPda] = this.deriveProofContextPda(params.messageId);

    const discriminator = getInstructionDiscriminator("verify_evm_proof");

    // Serialize: message_id (32) + proof_data (len-prefixed) + public_values (len-prefixed)
    const messageIdBuf = Buffer.from(params.messageId);

    const proofLenBuf = Buffer.alloc(4);
    proofLenBuf.writeUInt32LE(params.proofData.length, 0);

    const publicValuesLenBuf = Buffer.alloc(4);
    publicValuesLenBuf.writeUInt32LE(params.publicValues.length, 0);

    const data = Buffer.concat([
      discriminator,
      messageIdBuf,
      proofLenBuf,
      params.proofData,
      publicValuesLenBuf,
      params.publicValues,
    ]);

    const keys = [
      { pubkey: params.operator, isSigner: true, isWritable: true },
      { pubkey: configPda, isSigner: false, isWritable: true },
      { pubkey: proofContextPda, isSigner: false, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      { pubkey: SYSVAR_CLOCK_PUBKEY, isSigner: false, isWritable: false },
    ];

    return new TransactionInstruction({
      programId: this.programId,
      keys,
      data,
    });
  }

  /** Build the execute_mint instruction */
  buildExecuteMintInstruction(
    params: ExecuteMintParams,
    usdcMint: PublicKey,
    wrapperMint: PublicKey
  ): TransactionInstruction {
    const [configPda] = this.deriveConfigPda();
    const [messagePda] = this.deriveMessagePda(params.messageId);
    const [proofContextPda] = this.deriveProofContextPda(params.messageId);
    const [reserveAuthority] = this.deriveReserveAuthorityPda();
    const [bridgeReserve] = this.deriveReservePda(usdcMint);

    // Recipient's x0-USD ATA (Token-2022)
    const recipientWrapperAccount = getAssociatedTokenAddressSync(
      wrapperMint,
      params.recipient,
      true,
      TOKEN_2022_PROGRAM_ID
    );

    const discriminator = getInstructionDiscriminator("execute_mint");
    const data = Buffer.concat([discriminator]);

    const keys = [
      { pubkey: params.operator, isSigner: true, isWritable: true },
      { pubkey: configPda, isSigner: false, isWritable: true },
      { pubkey: messagePda, isSigner: false, isWritable: true },
      { pubkey: proofContextPda, isSigner: false, isWritable: true },
      { pubkey: bridgeReserve, isSigner: false, isWritable: true },
      { pubkey: reserveAuthority, isSigner: false, isWritable: false },
      { pubkey: recipientWrapperAccount, isSigner: false, isWritable: true },
      { pubkey: usdcMint, isSigner: false, isWritable: false },
      { pubkey: wrapperMint, isSigner: false, isWritable: true },
      {
        pubkey: params.wrapperConfig,
        isSigner: false,
        isWritable: false,
      },
      {
        pubkey: params.wrapperMintAuthority,
        isSigner: false,
        isWritable: false,
      },
      { pubkey: params.wrapperStats, isSigner: false, isWritable: true },
      {
        pubkey: params.wrapperReserveAccount,
        isSigner: false,
        isWritable: true,
      },
      { pubkey: X0_WRAPPER_PROGRAM_ID, isSigner: false, isWritable: false },
      { pubkey: TOKEN_2022_PROGRAM_ID, isSigner: false, isWritable: false },
      { pubkey: TOKEN_PROGRAM_ID, isSigner: false, isWritable: false },
      { pubkey: SYSVAR_CLOCK_PUBKEY, isSigner: false, isWritable: false },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ];

    return new TransactionInstruction({
      programId: this.programId,
      keys,
      data,
    });
  }

  /** Build the replenish_reserve instruction */
  buildReplenishReserveInstruction(
    params: ReplenishReserveParams,
    usdcMint: PublicKey
  ): TransactionInstruction {
    const [configPda] = this.deriveConfigPda();
    const [bridgeReserve] = this.deriveReservePda(usdcMint);

    const discriminator = getInstructionDiscriminator("replenish_reserve");
    const amountBuf = Buffer.alloc(8);
    amountBuf.writeBigUInt64LE(BigInt(params.amount.toString()), 0);
    const data = Buffer.concat([discriminator, amountBuf]);

    const keys = [
      { pubkey: params.depositor, isSigner: true, isWritable: true },
      { pubkey: configPda, isSigner: false, isWritable: true },
      { pubkey: params.depositorUsdcAccount, isSigner: false, isWritable: true },
      { pubkey: bridgeReserve, isSigner: false, isWritable: true },
      { pubkey: usdcMint, isSigner: false, isWritable: false },
      { pubkey: TOKEN_PROGRAM_ID, isSigner: false, isWritable: false },
    ];

    return new TransactionInstruction({
      programId: this.programId,
      keys,
      data,
    });
  }

  /** Build the pause_bridge instruction */
  buildPauseBridgeInstruction(
    admin: PublicKey,
    paused: boolean
  ): TransactionInstruction {
    const [configPda] = this.deriveConfigPda();
    const discriminator = getInstructionDiscriminator("pause_bridge");
    const pausedBuf = Buffer.from([paused ? 1 : 0]);
    const data = Buffer.concat([discriminator, pausedBuf]);

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

  /** Build the add_allowed_domain instruction */
  buildAddDomainInstruction(
    admin: PublicKey,
    domain: number
  ): TransactionInstruction {
    const [configPda] = this.deriveConfigPda();
    const discriminator = getInstructionDiscriminator("add_allowed_domain");
    const domainBuf = Buffer.alloc(4);
    domainBuf.writeUInt32LE(domain, 0);
    const data = Buffer.concat([discriminator, domainBuf]);

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

  /** Build the remove_allowed_domain instruction */
  buildRemoveDomainInstruction(
    admin: PublicKey,
    domain: number
  ): TransactionInstruction {
    const [configPda] = this.deriveConfigPda();
    const discriminator = getInstructionDiscriminator("remove_allowed_domain");
    const domainBuf = Buffer.alloc(4);
    domainBuf.writeUInt32LE(domain, 0);
    const data = Buffer.concat([discriminator, domainBuf]);

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

  /** Build the add_evm_contract instruction */
  buildAddEvmContractInstruction(
    admin: PublicKey,
    evmContract: Uint8Array // 20 bytes
  ): TransactionInstruction {
    const [configPda] = this.deriveConfigPda();
    const discriminator = getInstructionDiscriminator("add_evm_contract");
    const data = Buffer.concat([discriminator, Buffer.from(evmContract)]);

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

  /** Build the update_operator instruction */
  buildUpdateOperatorInstruction(
    admin: PublicKey,
    newOperator: PublicKey
  ): TransactionInstruction {
    const [configPda] = this.deriveConfigPda();
    const discriminator = getInstructionDiscriminator("update_operator");
    const data = Buffer.concat([
      discriminator,
      newOperator.toBuffer(),
    ]);

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

  // --------------------------------------------------------------------------
  // Private Helpers
  // --------------------------------------------------------------------------

  /** Deserialize bridge config from raw account data */
  private deserializeBridgeConfig(data: Buffer): BridgeConfig {
    let offset = 8; // Skip Anchor discriminator

    const admin = new PublicKey(data.subarray(offset, offset + 32));
    offset += 32;
    const operator = new PublicKey(data.subarray(offset, offset + 32));
    offset += 32;
    const wrapperProgram = new PublicKey(data.subarray(offset, offset + 32));
    offset += 32;
    const sp1VerifierProgram = new PublicKey(
      data.subarray(offset, offset + 32)
    );
    offset += 32;
    const hyperlaneMailbox = new PublicKey(data.subarray(offset, offset + 32));
    offset += 32;
    const bridgeReserve = new PublicKey(data.subarray(offset, offset + 32));
    offset += 32;
    const usdcMint = new PublicKey(data.subarray(offset, offset + 32));
    offset += 32;
    const wrapperMint = new PublicKey(data.subarray(offset, offset + 32));
    offset += 32;

    // Vec<u32> allowed_domains
    const domainsLen = data.readUInt32LE(offset);
    offset += 4;
    const allowedDomains: number[] = [];
    for (let i = 0; i < domainsLen; i++) {
      allowedDomains.push(data.readUInt32LE(offset));
      offset += 4;
    }

    // Vec<[u8; 20]> allowed_evm_contracts
    const contractsLen = data.readUInt32LE(offset);
    offset += 4;
    const allowedEvmContracts: Uint8Array[] = [];
    for (let i = 0; i < contractsLen; i++) {
      allowedEvmContracts.push(
        new Uint8Array(data.subarray(offset, offset + 20))
      );
      offset += 20;
    }

    const totalBridgedIn = new BN(data.subarray(offset, offset + 8), "le");
    offset += 8;
    const totalBridgedOut = new BN(data.subarray(offset, offset + 8), "le");
    offset += 8;
    const dailyVolume = new BN(data.subarray(offset, offset + 8), "le");
    offset += 8;
    const dailyVolumeReset = new BN(data.subarray(offset, offset + 8), "le");
    offset += 8;
    const isPaused = data[offset] === 1;
    offset += 1;
    const nonceCounter = new BN(data.subarray(offset, offset + 8), "le");
    offset += 8;
    const bump = data[offset];
    offset += 1;
    const version = data[offset];
    offset += 1;

    return {
      admin,
      operator,
      wrapperProgram,
      sp1VerifierProgram,
      hyperlaneMailbox,
      bridgeReserve,
      usdcMint,
      wrapperMint,
      allowedDomains,
      allowedEvmContracts,
      totalBridgedIn,
      totalBridgedOut,
      dailyVolume,
      dailyVolumeReset,
      isPaused,
      nonceCounter,
      bump,
      version,
    };
  }

  /** Deserialize bridge message from raw account data */
  private deserializeBridgeMessage(data: Buffer): BridgeMessage {
    let offset = 8; // Skip Anchor discriminator

    const originDomain = data.readUInt32LE(offset);
    offset += 4;
    const sender = new Uint8Array(data.subarray(offset, offset + 20));
    offset += 20;
    const recipient = new PublicKey(data.subarray(offset, offset + 32));
    offset += 32;
    const amount = new BN(data.subarray(offset, offset + 8), "le");
    offset += 8;
    const nonce = new BN(data.subarray(offset, offset + 8), "le");
    offset += 8;
    const messageId = new Uint8Array(data.subarray(offset, offset + 32));
    offset += 32;
    const hyperlaneMessageId = new Uint8Array(
      data.subarray(offset, offset + 32)
    );
    offset += 32;
    const receivedAt = new BN(data.subarray(offset, offset + 8), "le");
    offset += 8;
    const statusByte = data[offset];
    offset += 1;
    const status: BridgeMessageStatus = statusByte;
    const bump = data[offset];
    offset += 1;
    const version = data[offset];
    offset += 1;

    return {
      originDomain,
      sender,
      recipient,
      amount,
      nonce,
      messageId,
      hyperlaneMessageId,
      receivedAt,
      status,
      bump,
      version,
    };
  }

  /** Deserialize EVM proof context from raw account data */
  private deserializeEVMProofContext(data: Buffer): EVMProofContext {
    let offset = 8; // Skip Anchor discriminator

    const version = data[offset];
    offset += 1;
    const proofType: EVMProofType = data[offset];
    offset += 1;
    const verified = data[offset] === 1;
    offset += 1;
    const verifiedAt = new BN(data.subarray(offset, offset + 8), "le");
    offset += 8;
    const blockHash = new Uint8Array(data.subarray(offset, offset + 32));
    offset += 32;
    const blockNumber = new BN(data.subarray(offset, offset + 8), "le");
    offset += 8;
    const txHash = new Uint8Array(data.subarray(offset, offset + 32));
    offset += 32;
    const evmSender = new Uint8Array(data.subarray(offset, offset + 20));
    offset += 20;
    const evmContract = new Uint8Array(data.subarray(offset, offset + 20));
    offset += 20;
    const amount = new BN(data.subarray(offset, offset + 8), "le");
    offset += 8;
    const solanaRecipient = new PublicKey(data.subarray(offset, offset + 32));
    offset += 32;
    const nonce = new BN(data.subarray(offset, offset + 8), "le");
    offset += 8;
    const eventSignature = new Uint8Array(data.subarray(offset, offset + 32));
    offset += 32;
    const isConsumed = data[offset] === 1;
    offset += 1;
    const bump = data[offset];
    offset += 1;

    return {
      version,
      proofType,
      verified,
      verifiedAt,
      blockHash,
      blockNumber,
      txHash,
      evmSender,
      evmContract,
      amount,
      solanaRecipient,
      nonce,
      eventSignature,
      isConsumed,
      bump,
    };
  }
}
