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
 *   - Timelocked admin operations (schedule, execute, cancel)
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
 *   messageId, proofData, publicValues, payer, sp1Verifier
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
} from "@solana/web3.js";
import {
  TOKEN_2022_PROGRAM_ID,
  TOKEN_PROGRAM_ID,
  getAssociatedTokenAddressSync,
} from "@solana/spl-token";
import BN from "bn.js";
import { getInstructionDiscriminator } from "./utils";
import {
  X0_BRIDGE_PROGRAM_ID,
  X0_WRAPPER_PROGRAM_ID,
  LOCKED_EVENT_SIGNATURE,
  MAX_DAILY_BRIDGE_INFLOW,
  MAX_DAILY_BRIDGE_OUTFLOW,
  ROLLING_WINDOW_SECONDS,
} from "./constants";

// ============================================================================
// PDA Seeds (matching on-chain x0_common::constants)
// ============================================================================

const BRIDGE_CONFIG_SEED = Buffer.from("bridge_config");
const BRIDGE_MESSAGE_SEED = Buffer.from("bridge_message");
const EVM_PROOF_CONTEXT_SEED = Buffer.from("evm_proof");
const BRIDGE_RESERVE_SEED = Buffer.from("bridge_reserve");
const BRIDGE_RESERVE_AUTHORITY_SEED = Buffer.from("bridge_reserve_authority");
const BRIDGE_ADMIN_ACTION_SEED = Buffer.from("bridge_admin_action");
const BRIDGE_OUT_MESSAGE_SEED = Buffer.from("bridge_out_message");

// ============================================================================
// Types
// ============================================================================

/** On-chain BridgeConfig account data */
export interface BridgeConfig {
  version: number;
  admin: PublicKey;
  hyperlaneMailbox: PublicKey;
  sp1Verifier: PublicKey;
  wrapperProgram: PublicKey;
  wrapperConfig: PublicKey;
  usdcMint: PublicKey;
  wrapperMint: PublicKey;
  bridgeUsdcReserve: PublicKey;
  isPaused: boolean;
  totalBridgedIn: BN;
  totalBridgedOut: BN;
  nonce: BN;
  dailyInflowVolume: BN;
  dailyInflowResetTimestamp: BN;
  allowedEvmContracts: Uint8Array[];
  supportedDomains: number[];
  adminActionNonce: BN;
  bump: number;
  // --- Outbound bridge fields (Solana → Base) ---
  bridgeOutNonce: BN;
  dailyOutflowVolume: BN;
  dailyOutflowResetTimestamp: BN;
}

/**
 * On-chain BridgeMessage account data
 *
 * Field order matches Rust struct:
 *   version, message_id, origin_domain, sender([u8;32]),
 *   recipient, amount, received_at, status, evm_tx_hash,
 *   nonce, bump, _reserved
 */
export interface BridgeMessage {
  version: number;
  messageId: Uint8Array; // 32 bytes
  originDomain: number;
  sender: Uint8Array; // 32 bytes (EVM address left-padded to 32)
  recipient: PublicKey;
  amount: BN;
  receivedAt: BN;
  status: BridgeMessageStatus;
  evmTxHash: Uint8Array; // 32 bytes
  nonce: BN;
  bump: number;
}

export enum BridgeMessageStatus {
  Received = 0,
  ProofVerified = 1,
  Minted = 2,
  Failed = 3,
}

/** Status of an outbound bridge message (Solana → Base) */
export enum BridgeOutStatus {
  Burned = 0,
  Unlocked = 1,
  Failed = 2,
}

/**
 * On-chain BridgeOutMessage account data
 *
 * Field order matches Rust struct:
 *   version, nonce, solana_sender, evm_recipient([u8;20]),
 *   amount, burn_tx_signature([u8;32]), burned_at,
 *   status, bump, _reserved
 */
export interface BridgeOutMessage {
  version: number;
  nonce: BN;
  solanaSender: PublicKey;
  evmRecipient: Uint8Array; // 20 bytes
  amount: BN;
  burnTxSignature: Uint8Array; // 32 bytes
  burnedAt: BN;
  status: BridgeOutStatus;
  bump: number;
}

/**
 * On-chain EVMProofContext account data
 *
 * Field order matches Rust struct:
 *   version, proof_type, verified, verified_at, block_hash,
 *   block_number, tx_hash, from([u8;20]), to([u8;20]), value,
 *   event_logs, message_id, bump, _reserved
 */
export interface EVMProofContext {
  version: number;
  proofType: EVMProofType;
  verified: boolean;
  verifiedAt: BN;
  blockHash: Uint8Array; // 32 bytes
  blockNumber: BN;
  txHash: Uint8Array; // 32 bytes
  from: Uint8Array; // 20 bytes EVM address
  to: Uint8Array; // 20 bytes EVM address
  value: BN;
  eventLogs: EVMEventLog[];
  messageId: Uint8Array; // 32 bytes
  bump: number;
}

/** Matches on-chain EVMEventLog struct */
export interface EVMEventLog {
  contractAddress: Uint8Array; // 20 bytes
  topics: Uint8Array[]; // each 32 bytes
  data: Uint8Array;
}

export enum EVMProofType {
  Transaction = 0,
  Batch = 1,
}

/**
 * Parameters for initializing the bridge.
 *
 * On-chain accounts: admin, config, usdc_mint, bridge_usdc_reserve,
 *   reserve_authority, usdc_token_program, system_program
 * On-chain args:     hyperlane_mailbox, sp1_verifier, wrapper_program,
 *   wrapper_config, wrapper_mint, allowed_evm_contracts, supported_domains
 */
export interface InitializeBridgeParams {
  admin: PublicKey;
  usdcMint: PublicKey;
  /** Token program for USDC (TOKEN_PROGRAM_ID or TOKEN_2022_PROGRAM_ID) */
  usdcTokenProgram?: PublicKey;
  // --- Instruction args (serialized in data, not passed as accounts) ---
  hyperlaneMailbox: PublicKey;
  sp1Verifier: PublicKey;
  wrapperProgram: PublicKey;
  wrapperConfig: PublicKey;
  wrapperMint: PublicKey;
  allowedEvmContracts: Uint8Array[]; // each 20 bytes
  supportedDomains: number[];
}

/** Parameters for verifying an EVM proof */
export interface VerifyEvmProofParams {
  messageId: Uint8Array; // 32 bytes
  proofData: Buffer;
  publicValues: Buffer;
  payer: PublicKey;
  sp1Verifier: PublicKey;
}

/** Parameters for executing a mint after proof verification */
export interface ExecuteMintParams {
  messageId: Uint8Array; // 32 bytes
  payer: PublicKey;
  recipient: PublicKey;
  wrapperConfig: PublicKey;
  wrapperStats: PublicKey;
  wrapperMintAuthority: PublicKey;
  wrapperReserveAccount: PublicKey;
}

/** Parameters for replenishing the bridge reserve */
export interface ReplenishReserveParams {
  amount: BN;
  depositor: PublicKey;
  depositorUsdcAccount: PublicKey;
}

/**
 * Parameters for initiating a bridge out (Solana → Base).
 *
 * Burns x0-USD on Solana and creates a BridgeOutMessage PDA for
 * off-chain SP1 proof generation and USDC unlock on Base.
 */
export interface InitiateBridgeOutParams {
  /** User initiating the bridge out (signer) */
  user: PublicKey;
  /** EVM recipient address (20 bytes) */
  evmRecipient: Uint8Array;
  /** Amount of x0-USD to burn (USDC 6 decimals) */
  amount: BN;
  /** USDC mint address on Solana */
  usdcMint: PublicKey;
  /** x0-USD wrapper mint address (Token-2022) */
  wrapperMint: PublicKey;
  /** x0-wrapper config PDA */
  wrapperConfig: PublicKey;
  /** x0-wrapper stats PDA */
  wrapperStats: PublicKey;
  /** x0-wrapper USDC reserve token account */
  wrapperReserveAccount: PublicKey;
  /** x0-wrapper reserve authority PDA */
  wrapperReserveAuthority: PublicKey;
  /** Token program for USDC (defaults to TOKEN_PROGRAM_ID) */
  usdcTokenProgram?: PublicKey;
}

/** Parameters for scheduling a timelocked admin action */
export interface ScheduleAdminActionParams {
  admin: PublicKey;
  nonce: BN;
}

/** Parameters for executing/cancelling a timelocked admin action */
export interface AdminActionNonceParams {
  admin: PublicKey;
  nonce: BN;
}

/**
 * SP1 STARK proof public inputs — the JSON shape output by
 * `x0-sp1-host prove --public-inputs-output public_inputs.json`.
 *
 * Matches `EVMProofPublicInputs` in `sp1-evm-prover/common/src/lib.rs` and
 * `SP1PublicInputs` in `programs/x0-bridge/src/state.rs`.
 *
 * These are the values cryptographically committed inside the STARK
 * circuit and verified on-chain by the SP1 verifier program.
 *
 * IMPORTANT: The on-chain `verify_evm_proof` instruction now validates
 * the Locked event from `event_logs` against the BridgeMessage data
 * (amount, recipient, contract address). This prevents a compromised
 * Hyperlane from injecting fake amounts or recipients.
 */
export interface SP1PublicInputs {
  /** EVM block hash (32 bytes as number array) */
  block_hash: number[];
  /** EVM block number */
  block_number: number;
  /** EVM transaction hash (32 bytes as number array) */
  tx_hash: number[];
  /** Transaction sender — 20-byte EVM address as number array */
  from: number[];
  /** Transaction recipient/contract — 20-byte EVM address as number array */
  to: number[];
  /** ETH value transferred in wei (0 for ERC-20 locks) */
  value: number;
  /** Whether the EVM transaction succeeded (receipt.status == 1) */
  success: boolean;
  /** Extracted event logs from the transaction receipt */
  event_logs: SP1EventLog[];
}

/** Event log entry in SP1 public inputs JSON (matches sp1-evm-prover/common EventLog) */
export interface SP1EventLog {
  /** Contract that emitted the event (20 bytes as number array) */
  contract_address: number[];
  /** Indexed topics — topic[0] = event signature hash (each 32 bytes) */
  topics: number[][];
  /** ABI-encoded non-indexed event data (byte array) */
  data: number[];
}

// ============================================================================
// Locked Event Parsing & Validation
// ============================================================================

/**
 * Parsed contents of a Locked event from the X0LockContract.
 *
 * Solidity declaration:
 *   event Locked(address indexed sender, bytes32 indexed solanaRecipient,
 *                uint256 amount, uint256 nonce, bytes32 messageId)
 */
export interface ParsedLockedEvent {
  /** EVM address of the lock contract that emitted the event (20 bytes) */
  contractAddress: Uint8Array;
  /** EVM address of the USDC sender (from topics[1], 20 bytes right-aligned in 32) */
  sender: Uint8Array;
  /** Solana recipient pubkey bytes (from topics[2], 32 bytes) */
  solanaRecipient: Uint8Array;
  /** USDC amount locked (from data[0..32] as uint256 → BN) */
  amount: BN;
  /** Lock nonce on the EVM side (from data[32..64] as uint256 → BN) */
  nonce: BN;
  /** Hyperlane message ID returned by dispatch (from data[64..96], 32 bytes) */
  messageId: Uint8Array;
}

/**
 * Find and parse the Locked event from SP1 public inputs event logs.
 *
 * Searches `event_logs` for an event whose topic[0] matches
 * `LOCKED_EVENT_SIGNATURE` and whose `contract_address` is in the
 * `allowedContracts` set.
 *
 * This mirrors the on-chain validation in `verify_evm_proof` and
 * allows SDK consumers to inspect proof contents before submitting.
 *
 * @param eventLogs - Event logs from SP1PublicInputs.event_logs
 * @param allowedContracts - Whitelisted lock contract addresses (each 20 bytes)
 * @returns The parsed Locked event, or null if not found
 *
 * @example
 * ```ts
 * const inputs = JSON.parse(fs.readFileSync("public_inputs.json", "utf-8"));
 * const locked = findLockedEvent(inputs.event_logs, [lockContractAddr]);
 * if (!locked) throw new Error("No Locked event in proof");
 * console.log("Amount:", locked.amount.toString());
 * console.log("Recipient:", new PublicKey(locked.solanaRecipient).toBase58());
 * ```
 */
export function findLockedEvent(
  eventLogs: SP1EventLog[],
  allowedContracts: Uint8Array[]
): ParsedLockedEvent | null {
  const sigBytes = LOCKED_EVENT_SIGNATURE;

  for (const log of eventLogs) {
    // Need at least 3 topics (signature, sender, solanaRecipient)
    if (log.topics.length < 3) continue;

    // Check event signature
    const topic0 = Buffer.from(log.topics[0]);
    if (!topic0.equals(sigBytes)) continue;

    // Check contract is whitelisted
    const contractAddr = new Uint8Array(log.contract_address);
    const isAllowed = allowedContracts.some((allowed) =>
      Buffer.from(allowed).equals(Buffer.from(contractAddr))
    );
    if (!isAllowed) continue;

    // Check data length (need 96 bytes: amount + nonce + messageId)
    if (log.data.length < 96) continue;

    // Parse topics
    const senderTopic = new Uint8Array(log.topics[1]);
    // EVM address is right-aligned in 32 bytes: extract last 20
    const sender = senderTopic.slice(12, 32);
    const solanaRecipient = new Uint8Array(log.topics[2]);

    // Parse data (all uint256, big-endian)
    const dataBuf = Buffer.from(log.data);

    // amount: data[0..32] — uint256, extract last 8 bytes as BN
    const amountWord = dataBuf.subarray(0, 32);
    const amount = new BN(amountWord.subarray(24, 32), "be");

    // nonce: data[32..64]
    const nonceWord = dataBuf.subarray(32, 64);
    const nonce = new BN(nonceWord.subarray(24, 32), "be");

    // messageId: data[64..96]
    const messageId = new Uint8Array(dataBuf.subarray(64, 96));

    return {
      contractAddress: contractAddr,
      sender,
      solanaRecipient,
      amount,
      nonce,
      messageId,
    };
  }

  return null;
}

/**
 * Validate that SP1 public inputs event logs match a BridgeMessage.
 *
 * Performs the same validation that the on-chain `verify_evm_proof`
 * instruction does, but in TypeScript for off-chain pre-checks.
 * This lets SDK consumers detect mismatches before paying for an
 * on-chain transaction that would fail.
 *
 * @param publicInputs - The SP1 proof public inputs
 * @param bridgeMessage - The on-chain BridgeMessage to validate against
 * @param allowedContracts - Whitelisted lock contract addresses
 * @returns An object with `valid` (boolean) and `error` (string if invalid)
 *
 * @example
 * ```ts
 * const inputs = JSON.parse(fs.readFileSync("public_inputs.json", "utf-8"));
 * const msg = await bridge.fetchMessage(messageId);
 * const result = validateProofAgainstMessage(
 *   inputs, msg!, config.allowedEvmContracts
 * );
 * if (!result.valid) throw new Error(`Pre-check failed: ${result.error}`);
 * ```
 */
export function validateProofAgainstMessage(
  publicInputs: SP1PublicInputs,
  bridgeMessage: BridgeMessage,
  allowedContracts: Uint8Array[]
): { valid: boolean; error?: string } {
  // Check tx_hash match
  const proofTxHash = Buffer.from(publicInputs.tx_hash);
  const messageTxHash = Buffer.from(bridgeMessage.evmTxHash);
  if (!proofTxHash.equals(messageTxHash)) {
    return { valid: false, error: "tx_hash mismatch between proof and bridge message" };
  }

  // Check success
  if (!publicInputs.success) {
    return { valid: false, error: "EVM transaction was not successful" };
  }

  // Find and validate Locked event
  const locked = findLockedEvent(publicInputs.event_logs, allowedContracts);
  if (!locked) {
    return {
      valid: false,
      error: "No Locked event from an allowed contract found in proof event logs",
    };
  }

  // Validate recipient
  const eventRecipient = Buffer.from(locked.solanaRecipient);
  const messageRecipient = bridgeMessage.recipient.toBuffer();
  if (!eventRecipient.equals(messageRecipient)) {
    return {
      valid: false,
      error: `Recipient mismatch: event=${eventRecipient.toString("hex")} message=${messageRecipient.toString("hex")}`,
    };
  }

  // Validate amount
  if (!locked.amount.eq(bridgeMessage.amount)) {
    return {
      valid: false,
      error: `Amount mismatch: event=${locked.amount.toString()} message=${bridgeMessage.amount.toString()}`,
    };
  }

  return { valid: true };
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

  /** Derive the BridgeAdminAction PDA for a given nonce */
  deriveAdminActionPda(nonce: BN): [PublicKey, number] {
    const nonceBuf = Buffer.alloc(8);
    nonceBuf.writeBigUInt64LE(BigInt(nonce.toString()), 0);
    return PublicKey.findProgramAddressSync(
      [BRIDGE_ADMIN_ACTION_SEED, nonceBuf],
      this.programId
    );
  }

  /** Derive the BridgeOutMessage PDA for a given outbound nonce */
  deriveBridgeOutMessagePda(nonce: BN): [PublicKey, number] {
    const nonceBuf = Buffer.alloc(8);
    nonceBuf.writeBigUInt64LE(BigInt(nonce.toString()), 0);
    return PublicKey.findProgramAddressSync(
      [BRIDGE_OUT_MESSAGE_SEED, nonceBuf],
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
    if (!accountInfo) return null;
    return this.deserializeBridgeConfig(accountInfo.data);
  }

  /** Fetch and deserialize a BridgeMessage account */
  async fetchMessage(messageId: Uint8Array): Promise<BridgeMessage | null> {
    const [messagePda] = this.deriveMessagePda(messageId);
    const accountInfo = await this.connection.getAccountInfo(messagePda);
    if (!accountInfo) return null;
    return this.deserializeBridgeMessage(accountInfo.data);
  }

  /** Fetch and deserialize an EVMProofContext account */
  async fetchProofContext(
    messageId: Uint8Array
  ): Promise<EVMProofContext | null> {
    const [proofPda] = this.deriveProofContextPda(messageId);
    const accountInfo = await this.connection.getAccountInfo(proofPda);
    if (!accountInfo) return null;
    return this.deserializeEVMProofContext(accountInfo.data);
  }

  /** Fetch and deserialize a BridgeOutMessage account by nonce */
  async fetchBridgeOutMessage(nonce: BN): Promise<BridgeOutMessage | null> {
    const [messagePda] = this.deriveBridgeOutMessagePda(nonce);
    const accountInfo = await this.connection.getAccountInfo(messagePda);
    if (!accountInfo) return null;
    return this.deserializeBridgeOutMessage(accountInfo.data);
  }

  /** Check if the bridge is currently paused */
  async isPaused(): Promise<boolean> {
    const config = await this.fetchConfig();
    return config?.isPaused ?? true;
  }

  /** Get remaining daily inbound volume capacity */
  async remainingDailyVolume(): Promise<BN> {
    const config = await this.fetchConfig();
    if (!config) return new BN(0);

    const now = Math.floor(Date.now() / 1000);
    const resetAt = config.dailyInflowResetTimestamp.toNumber();

    // If 24 hours have passed since last reset, full limit is available
    if (now >= resetAt + ROLLING_WINDOW_SECONDS) {
      return MAX_DAILY_BRIDGE_INFLOW;
    }

    const remaining = MAX_DAILY_BRIDGE_INFLOW.sub(config.dailyInflowVolume);
    return remaining.isNeg() ? new BN(0) : remaining;
  }

  /** Get remaining daily outbound volume capacity */
  async remainingDailyOutflowVolume(): Promise<BN> {
    const config = await this.fetchConfig();
    if (!config) return new BN(0);

    const now = Math.floor(Date.now() / 1000);
    const resetAt = config.dailyOutflowResetTimestamp.toNumber();

    if (now >= resetAt + ROLLING_WINDOW_SECONDS) {
      return MAX_DAILY_BRIDGE_OUTFLOW;
    }

    const remaining = MAX_DAILY_BRIDGE_OUTFLOW.sub(config.dailyOutflowVolume);
    return remaining.isNeg() ? new BN(0) : remaining;
  }

  // --------------------------------------------------------------------------
  // Instruction Builders
  // --------------------------------------------------------------------------

  /**
   * Build all three initialization instructions as a convenience.
   *
   * Returns [createConfig, createReserve, initialize] — add all three
   * to a single transaction.
   */
  buildInitializeInstructions(
    params: InitializeBridgeParams
  ): TransactionInstruction[] {
    return [
      this.buildCreateConfigInstruction(params.admin),
      this.buildCreateReserveInstruction(params.admin, params.usdcMint, params.usdcTokenProgram),
      this.buildInitializeInstruction(params),
    ];
  }

  /**
   * Step 1: Allocate the BridgeConfig PDA.
   *
   * On-chain accounts: admin(signer,mut), config(init), system_program
   */
  buildCreateConfigInstruction(
    admin: PublicKey
  ): TransactionInstruction {
    const [configPda] = this.deriveConfigPda();
    const discriminator = getInstructionDiscriminator("create_config");
    const data = Buffer.from(discriminator);

    const keys = [
      { pubkey: admin, isSigner: true, isWritable: true },
      { pubkey: configPda, isSigner: false, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ];

    return new TransactionInstruction({
      programId: this.programId,
      keys,
      data,
    });
  }

  /**
   * Step 2: Create the bridge USDC reserve token account.
   *
   * On-chain accounts: admin(signer,mut), usdc_mint, bridge_usdc_reserve(init),
   *   reserve_authority, usdc_token_program, system_program
   */
  buildCreateReserveInstruction(
    admin: PublicKey,
    usdcMint: PublicKey,
    usdcTokenProgram: PublicKey = TOKEN_PROGRAM_ID
  ): TransactionInstruction {
    const [bridgeReserve] = this.deriveReservePda(usdcMint);
    const [reserveAuthority] = this.deriveReserveAuthorityPda();
    const discriminator = getInstructionDiscriminator("create_reserve");
    const data = Buffer.from(discriminator);

    const keys = [
      { pubkey: admin, isSigner: true, isWritable: true },
      { pubkey: usdcMint, isSigner: false, isWritable: false },
      { pubkey: bridgeReserve, isSigner: false, isWritable: true },
      { pubkey: reserveAuthority, isSigner: false, isWritable: false },
      { pubkey: usdcTokenProgram, isSigner: false, isWritable: false },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ];

    return new TransactionInstruction({
      programId: this.programId,
      keys,
      data,
    });
  }

  /**
   * Step 3: Populate the bridge configuration.
   *
   * On-chain accounts: admin(signer,mut), config(zero,mut), usdc_mint,
   *   bridge_usdc_reserve
   *
   * On-chain args: hyperlane_mailbox, sp1_verifier, wrapper_program,
   *   wrapper_config, wrapper_mint, allowed_evm_contracts, supported_domains
   */
  buildInitializeInstruction(
    params: InitializeBridgeParams
  ): TransactionInstruction {
    const [configPda] = this.deriveConfigPda();
    const [bridgeReserve] = this.deriveReservePda(params.usdcMint);

    const discriminator = getInstructionDiscriminator("initialize");

    // Serialize args
    const contractsVecLen = Buffer.alloc(4);
    contractsVecLen.writeUInt32LE(params.allowedEvmContracts.length, 0);
    const contractsData = Buffer.concat(
      params.allowedEvmContracts.map((c) => Buffer.from(c))
    );

    const domainsVecLen = Buffer.alloc(4);
    domainsVecLen.writeUInt32LE(params.supportedDomains.length, 0);
    const domainsData = Buffer.alloc(params.supportedDomains.length * 4);
    params.supportedDomains.forEach((d, i) => {
      domainsData.writeUInt32LE(d, i * 4);
    });

    const data = Buffer.concat([
      discriminator,
      params.hyperlaneMailbox.toBuffer(),
      params.sp1Verifier.toBuffer(),
      params.wrapperProgram.toBuffer(),
      params.wrapperConfig.toBuffer(),
      params.wrapperMint.toBuffer(),
      contractsVecLen,
      contractsData,
      domainsVecLen,
      domainsData,
    ]);

    // Account order matches Initialize<'info> struct
    const keys = [
      { pubkey: params.admin, isSigner: true, isWritable: true },
      { pubkey: configPda, isSigner: false, isWritable: true },
      { pubkey: params.usdcMint, isSigner: false, isWritable: false },
      { pubkey: bridgeReserve, isSigner: false, isWritable: false },
    ];

    return new TransactionInstruction({
      programId: this.programId,
      keys,
      data,
    });
  }

  /**
   * Build the verify_evm_proof instruction.
   *
   * On-chain accounts (in order):
   *   payer(signer,mut), config, bridge_message(mut),
   *   proof_context(init,mut), sp1_verifier, system_program
   */
  buildVerifyEvmProofInstruction(
    params: VerifyEvmProofParams
  ): TransactionInstruction {
    const [configPda] = this.deriveConfigPda();
    const [messagePda] = this.deriveMessagePda(params.messageId);
    const [proofContextPda] = this.deriveProofContextPda(params.messageId);

    const discriminator = getInstructionDiscriminator("verify_evm_proof");

    // Serialize: message_id([u8;32]) + proof(Vec<u8>) + public_values(Vec<u8>)
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

    // Account order matches VerifyEVMProof<'info> struct
    const keys = [
      { pubkey: params.payer, isSigner: true, isWritable: true },
      { pubkey: configPda, isSigner: false, isWritable: false },
      { pubkey: messagePda, isSigner: false, isWritable: true },
      { pubkey: proofContextPda, isSigner: false, isWritable: true },
      { pubkey: params.sp1Verifier, isSigner: false, isWritable: false },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ];

    return new TransactionInstruction({
      programId: this.programId,
      keys,
      data,
    });
  }

  /**
   * Build the execute_mint instruction.
   *
   * On-chain accounts (in order):
   *   payer(signer,mut), config(mut), bridge_message(mut),
   *   proof_context(read-only), bridge_usdc_reserve(mut),
   *   bridge_reserve_authority,
   *   wrapper_config, wrapper_stats(mut), usdc_mint, wrapper_mint(mut),
   *   wrapper_reserve_account(mut), wrapper_mint_authority,
   *   recipient_wrapper_account(mut),
   *   wrapper_program, token_2022_program, usdc_token_program
   */
  buildExecuteMintInstruction(
    params: ExecuteMintParams,
    usdcMint: PublicKey,
    wrapperMint: PublicKey,
    usdcTokenProgram: PublicKey = TOKEN_PROGRAM_ID
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
    const data = Buffer.from(discriminator);

    // Account order matches ExecuteMint<'info> struct
    const keys = [
      { pubkey: params.payer, isSigner: true, isWritable: true },
      { pubkey: configPda, isSigner: false, isWritable: true },
      { pubkey: messagePda, isSigner: false, isWritable: true },
      { pubkey: proofContextPda, isSigner: false, isWritable: false },
      { pubkey: bridgeReserve, isSigner: false, isWritable: true },
      { pubkey: reserveAuthority, isSigner: false, isWritable: false },
      { pubkey: params.wrapperConfig, isSigner: false, isWritable: false },
      { pubkey: params.wrapperStats, isSigner: false, isWritable: true },
      { pubkey: usdcMint, isSigner: false, isWritable: false },
      { pubkey: wrapperMint, isSigner: false, isWritable: true },
      { pubkey: params.wrapperReserveAccount, isSigner: false, isWritable: true },
      { pubkey: params.wrapperMintAuthority, isSigner: false, isWritable: false },
      { pubkey: recipientWrapperAccount, isSigner: false, isWritable: true },
      { pubkey: X0_WRAPPER_PROGRAM_ID, isSigner: false, isWritable: false },
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
   * Build the replenish_reserve instruction.
   *
   * On-chain accounts (in order):
   *   depositor(signer,mut), config, usdc_mint,
   *   depositor_usdc_account(mut), bridge_usdc_reserve(mut),
   *   usdc_token_program
   */
  buildReplenishReserveInstruction(
    params: ReplenishReserveParams,
    usdcMint: PublicKey,
    usdcTokenProgram: PublicKey = TOKEN_PROGRAM_ID
  ): TransactionInstruction {
    const [configPda] = this.deriveConfigPda();
    const [bridgeReserve] = this.deriveReservePda(usdcMint);

    const discriminator = getInstructionDiscriminator("replenish_reserve");
    const amountBuf = Buffer.alloc(8);
    amountBuf.writeBigUInt64LE(BigInt(params.amount.toString()), 0);
    const data = Buffer.concat([discriminator, amountBuf]);

    // Account order matches ReplenishReserve<'info> struct
    const keys = [
      { pubkey: params.depositor, isSigner: true, isWritable: true },
      { pubkey: configPda, isSigner: false, isWritable: false },
      { pubkey: usdcMint, isSigner: false, isWritable: false },
      { pubkey: params.depositorUsdcAccount, isSigner: false, isWritable: true },
      { pubkey: bridgeReserve, isSigner: false, isWritable: true },
      { pubkey: usdcTokenProgram, isSigner: false, isWritable: false },
    ];

    return new TransactionInstruction({
      programId: this.programId,
      keys,
      data,
    });
  }

  /**
   * Build the initiate_bridge_out instruction.
   *
   * Burns x0-USD on Solana and creates a BridgeOutMessage PDA for
   * off-chain SP1 Solana proof generation and USDC unlock on Base.
   *
   * On-chain accounts (in order):
   *   user(signer,mut), config(mut), bridge_out_message(init,mut),
   *   bridge_usdc_reserve(mut), bridge_reserve_authority,
   *   wrapper_config, wrapper_stats(mut), usdc_mint,
   *   wrapper_mint(mut), user_wrapper_account(mut),
   *   wrapper_reserve_account(mut), wrapper_reserve_authority,
   *   wrapper_program, token_2022_program, usdc_token_program,
   *   system_program
   *
   * On-chain args: evm_recipient([u8;20]), amount(u64)
   *
   * @param params - Bridge out parameters
   * @param currentBridgeOutNonce - The current config.bridgeOutNonce
   *   (read from fetchConfig before calling). The PDA is derived
   *   from this nonce.
   */
  buildInitiateBridgeOutInstruction(
    params: InitiateBridgeOutParams,
    currentBridgeOutNonce: BN,
  ): TransactionInstruction {
    const [configPda] = this.deriveConfigPda();
    const [bridgeOutMessagePda] = this.deriveBridgeOutMessagePda(currentBridgeOutNonce);
    const [bridgeReserve] = this.deriveReservePda(params.usdcMint);
    const [reserveAuthority] = this.deriveReserveAuthorityPda();

    // User's x0-USD ATA (Token-2022)
    const userWrapperAccount = getAssociatedTokenAddressSync(
      params.wrapperMint,
      params.user,
      false,
      TOKEN_2022_PROGRAM_ID
    );

    const discriminator = getInstructionDiscriminator("initiate_bridge_out");

    // Serialize args: evm_recipient([u8;20]) + amount(u64 LE)
    const amountBuf = Buffer.alloc(8);
    amountBuf.writeBigUInt64LE(BigInt(params.amount.toString()), 0);
    const data = Buffer.concat([
      discriminator,
      Buffer.from(params.evmRecipient),
      amountBuf,
    ]);

    const usdcTokenProgram = params.usdcTokenProgram ?? TOKEN_PROGRAM_ID;

    // Account order matches InitiateBridgeOut<'info> struct
    const keys = [
      { pubkey: params.user, isSigner: true, isWritable: true },
      { pubkey: configPda, isSigner: false, isWritable: true },
      { pubkey: bridgeOutMessagePda, isSigner: false, isWritable: true },
      { pubkey: bridgeReserve, isSigner: false, isWritable: true },
      { pubkey: reserveAuthority, isSigner: false, isWritable: false },
      { pubkey: params.wrapperConfig, isSigner: false, isWritable: false },
      { pubkey: params.wrapperStats, isSigner: false, isWritable: true },
      { pubkey: params.usdcMint, isSigner: false, isWritable: false },
      { pubkey: params.wrapperMint, isSigner: false, isWritable: true },
      { pubkey: userWrapperAccount, isSigner: false, isWritable: true },
      { pubkey: params.wrapperReserveAccount, isSigner: false, isWritable: true },
      { pubkey: params.wrapperReserveAuthority, isSigner: false, isWritable: false },
      { pubkey: X0_WRAPPER_PROGRAM_ID, isSigner: false, isWritable: false },
      { pubkey: TOKEN_2022_PROGRAM_ID, isSigner: false, isWritable: false },
      { pubkey: usdcTokenProgram, isSigner: false, isWritable: false },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ];

    return new TransactionInstruction({
      programId: this.programId,
      keys,
      data,
    });
  }

  // --------------------------------------------------------------------------
  // Admin Instruction Builders (immediate — no timelock)
  // --------------------------------------------------------------------------

  /**
   * Build the set_paused instruction (pause or unpause the bridge).
   *
   * On-chain accounts: admin(signer), config(mut)
   * On-chain name:     set_paused
   */
  buildSetPausedInstruction(
    admin: PublicKey,
    paused: boolean
  ): TransactionInstruction {
    const [configPda] = this.deriveConfigPda();
    const discriminator = getInstructionDiscriminator("set_paused");
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

  /**
   * Build the add_allowed_contract instruction.
   *
   * On-chain accounts: admin(signer), config(mut)
   */
  buildAddAllowedContractInstruction(
    admin: PublicKey,
    evmContract: Uint8Array // 20 bytes
  ): TransactionInstruction {
    const [configPda] = this.deriveConfigPda();
    const discriminator = getInstructionDiscriminator("add_allowed_contract");
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

  /**
   * Build the remove_allowed_contract instruction.
   *
   * On-chain accounts: admin(signer), config(mut)
   */
  buildRemoveAllowedContractInstruction(
    admin: PublicKey,
    evmContract: Uint8Array // 20 bytes
  ): TransactionInstruction {
    const [configPda] = this.deriveConfigPda();
    const discriminator = getInstructionDiscriminator("remove_allowed_contract");
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

  /**
   * Build the add_supported_domain instruction.
   *
   * On-chain accounts: admin(signer), config(mut)
   */
  buildAddSupportedDomainInstruction(
    admin: PublicKey,
    domain: number
  ): TransactionInstruction {
    const [configPda] = this.deriveConfigPda();
    const discriminator = getInstructionDiscriminator("add_supported_domain");
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

  // --------------------------------------------------------------------------
  // Timelocked Admin Instruction Builders (48h delay)
  // --------------------------------------------------------------------------

  /**
   * Schedule adding an EVM contract (48h timelock).
   *
   * On-chain accounts: admin(signer,mut), config(mut), admin_action(init,mut), system_program
   */
  buildScheduleAddEvmContractInstruction(
    params: ScheduleAdminActionParams,
    evmContract: Uint8Array // 20 bytes
  ): TransactionInstruction {
    const [configPda] = this.deriveConfigPda();
    const [actionPda] = this.deriveAdminActionPda(params.nonce);

    const discriminator = getInstructionDiscriminator("schedule_add_evm_contract");
    const data = Buffer.concat([discriminator, Buffer.from(evmContract)]);

    const keys = [
      { pubkey: params.admin, isSigner: true, isWritable: true },
      { pubkey: configPda, isSigner: false, isWritable: true },
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
   * Schedule removing an EVM contract (48h timelock).
   *
   * On-chain accounts: admin(signer,mut), config(mut), admin_action(init,mut), system_program
   */
  buildScheduleRemoveEvmContractInstruction(
    params: ScheduleAdminActionParams,
    evmContract: Uint8Array // 20 bytes
  ): TransactionInstruction {
    const [configPda] = this.deriveConfigPda();
    const [actionPda] = this.deriveAdminActionPda(params.nonce);

    const discriminator = getInstructionDiscriminator("schedule_remove_evm_contract");
    const data = Buffer.concat([discriminator, Buffer.from(evmContract)]);

    const keys = [
      { pubkey: params.admin, isSigner: true, isWritable: true },
      { pubkey: configPda, isSigner: false, isWritable: true },
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
   * Schedule adding a Hyperlane domain (48h timelock).
   *
   * On-chain accounts: admin(signer,mut), config(mut), admin_action(init,mut), system_program
   */
  buildScheduleAddDomainInstruction(
    params: ScheduleAdminActionParams,
    domain: number
  ): TransactionInstruction {
    const [configPda] = this.deriveConfigPda();
    const [actionPda] = this.deriveAdminActionPda(params.nonce);

    const discriminator = getInstructionDiscriminator("schedule_add_domain");
    const domainBuf = Buffer.alloc(4);
    domainBuf.writeUInt32LE(domain, 0);
    const data = Buffer.concat([discriminator, domainBuf]);

    const keys = [
      { pubkey: params.admin, isSigner: true, isWritable: true },
      { pubkey: configPda, isSigner: false, isWritable: true },
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
   * Schedule removing a Hyperlane domain (48h timelock).
   *
   * On-chain accounts: admin(signer,mut), config(mut), admin_action(init,mut), system_program
   */
  buildScheduleRemoveDomainInstruction(
    params: ScheduleAdminActionParams,
    domain: number
  ): TransactionInstruction {
    const [configPda] = this.deriveConfigPda();
    const [actionPda] = this.deriveAdminActionPda(params.nonce);

    const discriminator = getInstructionDiscriminator("schedule_remove_domain");
    const domainBuf = Buffer.alloc(4);
    domainBuf.writeUInt32LE(domain, 0);
    const data = Buffer.concat([discriminator, domainBuf]);

    const keys = [
      { pubkey: params.admin, isSigner: true, isWritable: true },
      { pubkey: configPda, isSigner: false, isWritable: true },
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
   * Execute a scheduled admin action (after 48h timelock expires).
   *
   * On-chain accounts: admin(signer), config(mut), admin_action(mut)
   */
  buildExecuteAdminActionInstruction(
    params: AdminActionNonceParams
  ): TransactionInstruction {
    const [configPda] = this.deriveConfigPda();
    const [actionPda] = this.deriveAdminActionPda(params.nonce);

    const discriminator = getInstructionDiscriminator("execute_admin_action");
    const nonceBuf = Buffer.alloc(8);
    nonceBuf.writeBigUInt64LE(BigInt(params.nonce.toString()), 0);
    const data = Buffer.concat([discriminator, nonceBuf]);

    const keys = [
      { pubkey: params.admin, isSigner: true, isWritable: false },
      { pubkey: configPda, isSigner: false, isWritable: true },
      { pubkey: actionPda, isSigner: false, isWritable: true },
    ];

    return new TransactionInstruction({
      programId: this.programId,
      keys,
      data,
    });
  }

  /**
   * Cancel a scheduled admin action.
   *
   * On-chain accounts: admin(signer), config, admin_action(mut)
   */
  buildCancelAdminActionInstruction(
    params: AdminActionNonceParams
  ): TransactionInstruction {
    const [configPda] = this.deriveConfigPda();
    const [actionPda] = this.deriveAdminActionPda(params.nonce);

    const discriminator = getInstructionDiscriminator("cancel_admin_action");
    const nonceBuf = Buffer.alloc(8);
    nonceBuf.writeBigUInt64LE(BigInt(params.nonce.toString()), 0);
    const data = Buffer.concat([discriminator, nonceBuf]);

    const keys = [
      { pubkey: params.admin, isSigner: true, isWritable: false },
      { pubkey: configPda, isSigner: false, isWritable: false },
      { pubkey: actionPda, isSigner: false, isWritable: true },
    ];

    return new TransactionInstruction({
      programId: this.programId,
      keys,
      data,
    });
  }

  // --------------------------------------------------------------------------
  // SP1 Public Inputs Helpers
  // --------------------------------------------------------------------------

  /**
   * Borsh-serialize SP1 public inputs for on-chain verification.
   *
   * Takes the JSON output from `x0-sp1-host prove` and produces the
   * `publicValues` buffer expected by `buildVerifyEvmProofInstruction`.
   *
   * Borsh layout (must match SP1PublicInputs in x0-bridge state.rs):
   *   block_hash([u8;32]) + block_number(u64) + tx_hash([u8;32])
   *   + from([u8;20]) + to([u8;20]) + value(u64) + success(bool)
   *   + event_logs(Vec<EVMEventLog>)
   *
   * @example
   * ```ts
   * const inputs = JSON.parse(fs.readFileSync("public_inputs.json", "utf-8"));
   * const publicValues = bridge.serializeSP1PublicInputs(inputs);
   * const proofData = Buffer.from(fs.readFileSync("proof.bin"));
   * const ix = bridge.buildVerifyEvmProofInstruction({
   *   messageId, proofData, publicValues, payer, sp1Verifier
   * });
   * ```
   */
  serializeSP1PublicInputs(inputs: SP1PublicInputs): Buffer {
    const parts: Buffer[] = [];

    // block_hash: [u8; 32] — fixed array, no length prefix
    parts.push(Buffer.from(new Uint8Array(inputs.block_hash)));

    // block_number: u64 LE
    const blockNumBuf = Buffer.alloc(8);
    blockNumBuf.writeBigUInt64LE(BigInt(inputs.block_number), 0);
    parts.push(blockNumBuf);

    // tx_hash: [u8; 32]
    parts.push(Buffer.from(new Uint8Array(inputs.tx_hash)));

    // from: [u8; 20]
    parts.push(Buffer.from(new Uint8Array(inputs.from)));

    // to: [u8; 20]
    parts.push(Buffer.from(new Uint8Array(inputs.to)));

    // value: u64 LE
    const valueBuf = Buffer.alloc(8);
    valueBuf.writeBigUInt64LE(BigInt(inputs.value), 0);
    parts.push(valueBuf);

    // success: bool (1 byte)
    parts.push(Buffer.from([inputs.success ? 1 : 0]));

    // event_logs: Vec<EVMEventLog> — u32 LE length prefix + each item
    const logsLenBuf = Buffer.alloc(4);
    logsLenBuf.writeUInt32LE(inputs.event_logs.length, 0);
    parts.push(logsLenBuf);

    for (const log of inputs.event_logs) {
      // contract_address: [u8; 20]
      parts.push(Buffer.from(new Uint8Array(log.contract_address)));

      // topics: Vec<[u8; 32]> — u32 LE length + each 32 bytes
      const topicsLenBuf = Buffer.alloc(4);
      topicsLenBuf.writeUInt32LE(log.topics.length, 0);
      parts.push(topicsLenBuf);
      for (const topic of log.topics) {
        parts.push(Buffer.from(new Uint8Array(topic)));
      }

      // data: Vec<u8> — u32 LE length + bytes
      const dataLenBuf = Buffer.alloc(4);
      dataLenBuf.writeUInt32LE(log.data.length, 0);
      parts.push(dataLenBuf);
      parts.push(Buffer.from(new Uint8Array(log.data)));
    }

    return Buffer.concat(parts);
  }

  /**
   * Deserialize SP1 public inputs from a borsh-encoded buffer back
   * into the JS object. Useful for inspecting on-chain proof context
   * public values.
   */
  deserializeSP1PublicInputs(buf: Buffer): SP1PublicInputs {
    let offset = 0;

    const block_hash = Array.from(buf.subarray(offset, offset + 32)); offset += 32;
    const block_number = Number(buf.readBigUInt64LE(offset)); offset += 8;
    const tx_hash = Array.from(buf.subarray(offset, offset + 32)); offset += 32;
    const from = Array.from(buf.subarray(offset, offset + 20)); offset += 20;
    const to = Array.from(buf.subarray(offset, offset + 20)); offset += 20;
    const value = Number(buf.readBigUInt64LE(offset)); offset += 8;
    const success = buf[offset] === 1; offset += 1;

    const logsLen = buf.readUInt32LE(offset); offset += 4;
    const event_logs: SP1EventLog[] = [];
    for (let i = 0; i < logsLen; i++) {
      const contract_address = Array.from(buf.subarray(offset, offset + 20)); offset += 20;

      const topicsLen = buf.readUInt32LE(offset); offset += 4;
      const topics: number[][] = [];
      for (let j = 0; j < topicsLen; j++) {
        topics.push(Array.from(buf.subarray(offset, offset + 32))); offset += 32;
      }

      const dataLen = buf.readUInt32LE(offset); offset += 4;
      const data = Array.from(buf.subarray(offset, offset + dataLen)); offset += dataLen;

      event_logs.push({ contract_address, topics, data });
    }

    return { block_hash, block_number, tx_hash, from, to, value, success, event_logs };
  }

  // --------------------------------------------------------------------------
  // Private Helpers — Deserialization
  // --------------------------------------------------------------------------

  /**
   * Deserialize BridgeConfig from raw account data.
   *
   * Field order matches Rust struct:
   *   version, admin, hyperlane_mailbox, sp1_verifier, wrapper_program,
   *   wrapper_config, usdc_mint, wrapper_mint, bridge_usdc_reserve,
   *   is_paused, total_bridged_in, total_bridged_out, nonce,
   *   daily_inflow_volume, daily_inflow_reset_timestamp,
   *   allowed_evm_contracts, supported_domains, admin_action_nonce,
   *   bump, _reserved
   */
  private deserializeBridgeConfig(data: Buffer): BridgeConfig {
    let offset = 8; // Skip Anchor discriminator

    const version = data[offset]; offset += 1;
    const admin = new PublicKey(data.subarray(offset, offset + 32)); offset += 32;
    const hyperlaneMailbox = new PublicKey(data.subarray(offset, offset + 32)); offset += 32;
    const sp1Verifier = new PublicKey(data.subarray(offset, offset + 32)); offset += 32;
    const wrapperProgram = new PublicKey(data.subarray(offset, offset + 32)); offset += 32;
    const wrapperConfig = new PublicKey(data.subarray(offset, offset + 32)); offset += 32;
    const usdcMint = new PublicKey(data.subarray(offset, offset + 32)); offset += 32;
    const wrapperMint = new PublicKey(data.subarray(offset, offset + 32)); offset += 32;
    const bridgeUsdcReserve = new PublicKey(data.subarray(offset, offset + 32)); offset += 32;
    const isPaused = data[offset] === 1; offset += 1;
    const totalBridgedIn = new BN(data.subarray(offset, offset + 8), "le"); offset += 8;
    const totalBridgedOut = new BN(data.subarray(offset, offset + 8), "le"); offset += 8;
    const nonce = new BN(data.subarray(offset, offset + 8), "le"); offset += 8;
    const dailyInflowVolume = new BN(data.subarray(offset, offset + 8), "le"); offset += 8;
    const dailyInflowResetTimestamp = new BN(data.subarray(offset, offset + 8), "le"); offset += 8;

    // allowed_evm_contracts_count: u8
    const contractsCount = data[offset]; offset += 1;
    // allowed_evm_contracts: [[u8; 20]; 10] — fixed array, always 200 bytes
    const allowedEvmContracts: Uint8Array[] = [];
    for (let i = 0; i < 10; i++) {
      if (i < contractsCount) {
        allowedEvmContracts.push(new Uint8Array(data.subarray(offset, offset + 20)));
      }
      offset += 20;
    }

    // supported_domains_count: u8
    const domainsCount = data[offset]; offset += 1;
    // supported_domains: [u32; 10] — fixed array, always 40 bytes
    const supportedDomains: number[] = [];
    for (let i = 0; i < 10; i++) {
      if (i < domainsCount) {
        supportedDomains.push(data.readUInt32LE(offset));
      }
      offset += 4;
    }

    const adminActionNonce = new BN(data.subarray(offset, offset + 8), "le"); offset += 8;
    const bump = data[offset]; offset += 1;

    // Outbound bridge fields (consumed from former _reserved space)
    const bridgeOutNonce = new BN(data.subarray(offset, offset + 8), "le"); offset += 8;
    const dailyOutflowVolume = new BN(data.subarray(offset, offset + 8), "le"); offset += 8;
    const dailyOutflowResetTimestamp = new BN(data.subarray(offset, offset + 8), "le"); offset += 8;
    // _reserved: [u8; 32] — skip

    return {
      version, admin, hyperlaneMailbox, sp1Verifier,
      wrapperProgram, wrapperConfig, usdcMint, wrapperMint,
      bridgeUsdcReserve, isPaused, totalBridgedIn, totalBridgedOut,
      nonce, dailyInflowVolume, dailyInflowResetTimestamp,
      allowedEvmContracts, supportedDomains, adminActionNonce, bump,
      bridgeOutNonce, dailyOutflowVolume, dailyOutflowResetTimestamp,
    };
  }

  /**
   * Deserialize BridgeMessage from raw account data.
   *
   * Field order matches Rust struct:
   *   version(u8), message_id([u8;32]), origin_domain(u32),
   *   sender([u8;32]), recipient(Pubkey), amount(u64),
   *   received_at(i64), status(enum u8), evm_tx_hash([u8;32]),
   *   nonce(u64), bump(u8), _reserved([u8;32])
   */
  private deserializeBridgeMessage(data: Buffer): BridgeMessage {
    let offset = 8; // Skip Anchor discriminator

    const version = data[offset]; offset += 1;
    const messageId = new Uint8Array(data.subarray(offset, offset + 32)); offset += 32;
    const originDomain = data.readUInt32LE(offset); offset += 4;
    const sender = new Uint8Array(data.subarray(offset, offset + 32)); offset += 32;
    const recipient = new PublicKey(data.subarray(offset, offset + 32)); offset += 32;
    const amount = new BN(data.subarray(offset, offset + 8), "le"); offset += 8;
    const receivedAt = new BN(data.subarray(offset, offset + 8), "le"); offset += 8;
    const status: BridgeMessageStatus = data[offset]; offset += 1;
    const evmTxHash = new Uint8Array(data.subarray(offset, offset + 32)); offset += 32;
    const nonce = new BN(data.subarray(offset, offset + 8), "le"); offset += 8;
    const bump = data[offset]; offset += 1;
    // _reserved: [u8; 32] — skip

    return {
      version, messageId, originDomain, sender,
      recipient, amount, receivedAt, status,
      evmTxHash, nonce, bump,
    };
  }

  /**
   * Deserialize EVMProofContext from raw account data.
   *
   * Field order matches Rust struct:
   *   version(u8), proof_type(enum u8), verified(bool u8),
   *   verified_at(i64), block_hash([u8;32]), block_number(u64),
   *   tx_hash([u8;32]), from([u8;20]), to([u8;20]), value(u64),
   *   event_logs(Vec<EVMEventLog>), message_id([u8;32]),
   *   bump(u8), _reserved([u8;32])
   */
  private deserializeEVMProofContext(data: Buffer): EVMProofContext {
    let offset = 8; // Skip Anchor discriminator

    const version = data[offset]; offset += 1;
    const proofType: EVMProofType = data[offset]; offset += 1;
    const verified = data[offset] === 1; offset += 1;
    const verifiedAt = new BN(data.subarray(offset, offset + 8), "le"); offset += 8;
    const blockHash = new Uint8Array(data.subarray(offset, offset + 32)); offset += 32;
    const blockNumber = new BN(data.subarray(offset, offset + 8), "le"); offset += 8;
    const txHash = new Uint8Array(data.subarray(offset, offset + 32)); offset += 32;
    const from = new Uint8Array(data.subarray(offset, offset + 20)); offset += 20;
    const to = new Uint8Array(data.subarray(offset, offset + 20)); offset += 20;
    const value = new BN(data.subarray(offset, offset + 8), "le"); offset += 8;

    // Vec<EVMEventLog> event_logs
    const logsLen = data.readUInt32LE(offset); offset += 4;
    const eventLogs: EVMEventLog[] = [];
    for (let i = 0; i < logsLen; i++) {
      // contract_address: [u8; 20]
      const contractAddress = new Uint8Array(data.subarray(offset, offset + 20));
      offset += 20;

      // topics: Vec<[u8; 32]>
      const topicsLen = data.readUInt32LE(offset); offset += 4;
      const topics: Uint8Array[] = [];
      for (let j = 0; j < topicsLen; j++) {
        topics.push(new Uint8Array(data.subarray(offset, offset + 32)));
        offset += 32;
      }

      // data: Vec<u8>
      const dataLen = data.readUInt32LE(offset); offset += 4;
      const logData = new Uint8Array(data.subarray(offset, offset + dataLen));
      offset += dataLen;

      eventLogs.push({ contractAddress, topics, data: logData });
    }

    const messageId = new Uint8Array(data.subarray(offset, offset + 32)); offset += 32;
    const bump = data[offset]; offset += 1;
    // _reserved: [u8; 32] — skip

    return {
      version, proofType, verified, verifiedAt,
      blockHash, blockNumber, txHash, from, to, value,
      eventLogs, messageId, bump,
    };
  }

  /**
   * Deserialize BridgeOutMessage from raw account data.
   *
   * Field order matches Rust struct:
   *   version(u8), nonce(u64), solana_sender(Pubkey),
   *   evm_recipient([u8;20]), amount(u64), burn_tx_signature([u8;32]),
   *   burned_at(i64), status(enum u8), bump(u8), _reserved([u8;32])
   */
  private deserializeBridgeOutMessage(data: Buffer): BridgeOutMessage {
    let offset = 8; // Skip Anchor discriminator

    const version = data[offset]; offset += 1;
    const nonce = new BN(data.subarray(offset, offset + 8), "le"); offset += 8;
    const solanaSender = new PublicKey(data.subarray(offset, offset + 32)); offset += 32;
    const evmRecipient = new Uint8Array(data.subarray(offset, offset + 20)); offset += 20;
    const amount = new BN(data.subarray(offset, offset + 8), "le"); offset += 8;
    const burnTxSignature = new Uint8Array(data.subarray(offset, offset + 32)); offset += 32;
    const burnedAt = new BN(data.subarray(offset, offset + 8), "le"); offset += 8;
    const status: BridgeOutStatus = data[offset]; offset += 1;
    const bump = data[offset]; offset += 1;
    // _reserved: [u8; 32] — skip

    return {
      version, nonce, solanaSender, evmRecipient,
      amount, burnTxSignature, burnedAt, status, bump,
    };
  }
}
