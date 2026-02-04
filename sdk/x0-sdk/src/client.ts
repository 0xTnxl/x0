/**
 * X0 Client
 * 
 * Main client class for interacting with the x0-01 protocol.
 * Provides a unified interface for all protocol operations.
 */

import {
  Connection,
  PublicKey,
  Transaction,
  TransactionInstruction,
  Commitment,
  ConfirmOptions,
  Signer,
} from "@solana/web3.js";
import {
  getAssociatedTokenAddressSync,
  TOKEN_2022_PROGRAM_ID,
  createAssociatedTokenAccountInstruction,
  createTransferCheckedInstruction,
} from "@solana/spl-token";
import { BN } from "@coral-xyz/anchor";

import { PolicyManager } from "./policy";
import { EscrowManager } from "./escrow";
import { RegistryManager } from "./registry";
import { ReputationManager } from "./reputation";
import {
  X0_GUARD_PROGRAM_ID,
  X0_TOKEN_PROGRAM_ID,
  X0_ESCROW_PROGRAM_ID,
  X0_REGISTRY_PROGRAM_ID,
  X0_REPUTATION_PROGRAM_ID,
} from "./constants";
import {
  deriveAgentPolicyPda,
  deriveRegistryPda,
  deriveReputationPda,
  calculateProtocolFee,
} from "./utils";
import {
  generateTransferBlink,
  generateBlinkUrl,
} from "./blink";
import {
  fetchWithPayment,
} from "./x402";
import type {
  AgentPolicyConfig,
  AgentPolicyAccount,
  AgentRegistryEntry,
  AgentReputationAccount,
  CreateEscrowParams,
  RegisterAgentParams,
  Capability,
  Blink,
} from "./types";

// ============================================================================
// Client Configuration
// ============================================================================

export interface X0ClientConfig {
  connection: Connection;
  wallet?: {
    publicKey: PublicKey;
    signTransaction: (tx: Transaction) => Promise<Transaction>;
    signAllTransactions?: (txs: Transaction[]) => Promise<Transaction[]>;
  };
  commitment?: Commitment;
  confirmOptions?: ConfirmOptions;
  
  // Program IDs (override defaults for custom deployments)
  guardProgramId?: PublicKey;
  tokenProgramId?: PublicKey;
  escrowProgramId?: PublicKey;
  registryProgramId?: PublicKey;
  reputationProgramId?: PublicKey;
  
  // Token-2022 mint for the settlement token
  settlementMint?: PublicKey;
}

// ============================================================================
// X0 Client
// ============================================================================

export class X0Client {
  readonly connection: Connection;
  readonly commitment: Commitment;
  readonly confirmOptions: ConfirmOptions;
  
  // Program IDs
  readonly guardProgramId: PublicKey;
  readonly tokenProgramId: PublicKey;
  readonly escrowProgramId: PublicKey;
  readonly registryProgramId: PublicKey;
  readonly reputationProgramId: PublicKey;
  
  // Settlement token mint
  settlementMint: PublicKey | null;
  
  // Sub-managers
  readonly policy: PolicyManager;
  readonly escrow: EscrowManager;
  readonly registry: RegistryManager;
  readonly reputation: ReputationManager;
  
  // Wallet (optional - for signing transactions)
  private wallet?: X0ClientConfig["wallet"];

  constructor(config: X0ClientConfig) {
    this.connection = config.connection;
    this.commitment = config.commitment ?? "confirmed";
    this.confirmOptions = config.confirmOptions ?? {
      commitment: this.commitment,
      preflightCommitment: this.commitment,
    };
    
    this.wallet = config.wallet;
    
    // Program IDs
    this.guardProgramId = config.guardProgramId ?? X0_GUARD_PROGRAM_ID;
    this.tokenProgramId = config.tokenProgramId ?? X0_TOKEN_PROGRAM_ID;
    this.escrowProgramId = config.escrowProgramId ?? X0_ESCROW_PROGRAM_ID;
    this.registryProgramId = config.registryProgramId ?? X0_REGISTRY_PROGRAM_ID;
    this.reputationProgramId = config.reputationProgramId ?? X0_REPUTATION_PROGRAM_ID;
    
    this.settlementMint = config.settlementMint ?? null;
    
    // Initialize sub-managers
    this.policy = new PolicyManager(this.connection, this.guardProgramId);
    this.escrow = new EscrowManager(this.connection, this.escrowProgramId);
    this.registry = new RegistryManager(this.connection, this.registryProgramId);
    this.reputation = new ReputationManager(this.connection, this.reputationProgramId);
  }

  /**
   * Get the current wallet public key
   */
  get walletPublicKey(): PublicKey | null {
    return this.wallet?.publicKey ?? null;
  }

  /**
   * Set the settlement mint
   */
  setSettlementMint(mint: PublicKey): void {
    this.settlementMint = mint;
  }

  /**
   * Connect a wallet
   */
  connectWallet(wallet: X0ClientConfig["wallet"]): void {
    this.wallet = wallet;
  }

  // ============================================================================
  // Transaction Helpers
  // ============================================================================

  /**
   * Build and send a transaction
   */
  async sendTransaction(
    instructions: TransactionInstruction[],
    signers: Signer[] = [],
    options?: ConfirmOptions
  ): Promise<string> {
    if (!this.wallet) {
      throw new Error("Wallet not connected");
    }

    const tx = new Transaction();
    tx.add(...instructions);

    const { blockhash, lastValidBlockHeight } = 
      await this.connection.getLatestBlockhash(this.commitment);
    tx.recentBlockhash = blockhash;
    tx.lastValidBlockHeight = lastValidBlockHeight;
    tx.feePayer = this.wallet.publicKey;

    // Add additional signers
    if (signers.length > 0) {
      tx.partialSign(...signers);
    }

    // Wallet signs
    const signedTx = await this.wallet.signTransaction(tx);

    const signature = await this.connection.sendRawTransaction(
      signedTx.serialize(),
      options ?? this.confirmOptions
    );

    await this.connection.confirmTransaction(
      {
        signature,
        blockhash,
        lastValidBlockHeight,
      },
      this.commitment
    );

    return signature;
  }

  /**
   * Simulate a transaction
   */
  async simulateTransaction(
    instructions: TransactionInstruction[]
  ): Promise<{
    success: boolean;
    logs: string[];
    unitsConsumed?: number;
    error?: string;
  }> {
    if (!this.wallet) {
      throw new Error("Wallet not connected");
    }

    const tx = new Transaction();
    tx.add(...instructions);

    const { blockhash } = await this.connection.getLatestBlockhash();
    tx.recentBlockhash = blockhash;
    tx.feePayer = this.wallet.publicKey;

    const result = await this.connection.simulateTransaction(tx);
    
    const errStr = result.value.err ? JSON.stringify(result.value.err) : undefined;

    return {
      success: result.value.err === null,
      logs: result.value.logs ?? [],
      ...(result.value.unitsConsumed !== undefined && { unitsConsumed: result.value.unitsConsumed }),
      ...(errStr && { error: errStr }),
    };
  }

  // ============================================================================
  // Policy Operations
  // ============================================================================

  /**
   * Initialize a new agent policy
   */
  async initializePolicy(
    agentSigner: PublicKey,
    config: AgentPolicyConfig
  ): Promise<{ signature: string; policyAddress: PublicKey }> {
    if (!this.wallet) {
      throw new Error("Wallet not connected");
    }

    const { instruction, policyAddress } = 
      await this.policy.buildInitializePolicyInstruction(
        this.wallet.publicKey,
        agentSigner,
        config
      );

    const signature = await this.sendTransaction([instruction]);

    return { signature, policyAddress };
  }

  /**
   * Get the policy for the current wallet
   */
  async getMyPolicy(): Promise<AgentPolicyAccount | null> {
    if (!this.wallet) {
      throw new Error("Wallet not connected");
    }

    return this.policy.fetchPolicyByOwner(this.wallet.publicKey);
  }

  /**
   * Update policy parameters
   */
  async updatePolicy(
    updates: Partial<AgentPolicyConfig>
  ): Promise<string> {
    if (!this.wallet) {
      throw new Error("Wallet not connected");
    }

    const policyAddress = this.policy.derivePolicyAddress(this.wallet.publicKey);
    const instruction = this.policy.buildUpdatePolicyInstruction(
      this.wallet.publicKey,
      policyAddress,
      updates
    );

    return this.sendTransaction([instruction]);
  }

  /**
   * Rotate agent signer key
   */
  async rotateAgentSigner(newSigner: PublicKey): Promise<string> {
    if (!this.wallet) {
      throw new Error("Wallet not connected");
    }

    const policyAddress = this.policy.derivePolicyAddress(this.wallet.publicKey);
    const instruction = this.policy.buildUpdateAgentSignerInstruction(
      this.wallet.publicKey,
      policyAddress,
      newSigner
    );

    return this.sendTransaction([instruction]);
  }

  /**
   * Emergency kill switch - revoke all agent authority
   */
  async revokeAgentAuthority(): Promise<string> {
    if (!this.wallet) {
      throw new Error("Wallet not connected");
    }

    const policyAddress = this.policy.derivePolicyAddress(this.wallet.publicKey);
    const instruction = this.policy.buildRevokeAgentAuthorityInstruction(
      this.wallet.publicKey,
      policyAddress
    );

    return this.sendTransaction([instruction]);
  }

  // ============================================================================
  // Escrow Operations
  // ============================================================================

  /**
   * Create and fund an escrow in one transaction
   */
  async createEscrow(params: CreateEscrowParams): Promise<{
    signature: string;
    escrowAddress: PublicKey;
  }> {
    if (!this.wallet) {
      throw new Error("Wallet not connected");
    }

    if (!this.settlementMint) {
      throw new Error("Settlement mint not set");
    }

    const createResult = this.escrow.buildCreateEscrowInstruction({
      ...params,
      buyer: this.wallet.publicKey,
      mint: this.settlementMint,
    });

    const fundInstruction = this.escrow.buildFundEscrowInstruction(
      this.wallet.publicKey,
      createResult.escrowAddress,
      this.settlementMint,
      params.amount
    );

    const signature = await this.sendTransaction([
      createResult.instruction,
      fundInstruction,
    ]);

    return {
      signature,
      escrowAddress: createResult.escrowAddress,
    };
  }

  /**
   * Release escrow funds to seller
   */
  async releaseEscrow(escrowAddress: PublicKey): Promise<string> {
    if (!this.wallet) {
      throw new Error("Wallet not connected");
    }

    if (!this.settlementMint) {
      throw new Error("Settlement mint not set");
    }

    const escrow = await this.escrow.fetchEscrow(escrowAddress);
    if (!escrow) {
      throw new Error("Escrow not found");
    }

    const instruction = this.escrow.buildReleaseFundsInstruction(
      this.wallet.publicKey,
      escrow.seller,
      escrowAddress,
      this.settlementMint
    );

    return this.sendTransaction([instruction]);
  }

  /**
   * Initiate a dispute
   */
  async initiateDispute(
    escrowAddress: PublicKey,
    reason: string
  ): Promise<string> {
    if (!this.wallet) {
      throw new Error("Wallet not connected");
    }

    const instruction = this.escrow.buildInitiateDisputeInstruction(
      this.wallet.publicKey,
      escrowAddress,
      reason
    );

    return this.sendTransaction([instruction]);
  }

  // ============================================================================
  // Registry Operations
  // ============================================================================

  /**
   * Register an agent in the discovery registry
   */
  async registerAgent(params: Omit<RegisterAgentParams, "owner" | "agentPolicyId">): Promise<{
    signature: string;
    registryAddress: PublicKey;
  }> {
    if (!this.wallet) {
      throw new Error("Wallet not connected");
    }

    const policyAddress = this.policy.derivePolicyAddress(this.wallet.publicKey);

    const { instruction, registryAddress } = 
      this.registry.buildRegisterAgentInstruction({
        ...params,
        owner: this.wallet.publicKey,
        agentPolicyId: policyAddress,
      });

    const signature = await this.sendTransaction([instruction]);

    return { signature, registryAddress };
  }

  /**
   * Update registry entry
   */
  async updateRegistry(updates: {
    endpoint?: string;
    capabilities?: Capability[];
    metadataJson?: string;
  }): Promise<string> {
    if (!this.wallet) {
      throw new Error("Wallet not connected");
    }

    const policyAddress = this.policy.derivePolicyAddress(this.wallet.publicKey);
    const registryAddress = this.registry.deriveRegistryAddress(policyAddress);

    const instruction = this.registry.buildUpdateRegistryInstruction(
      this.wallet.publicKey,
      registryAddress,
      updates
    );

    return this.sendTransaction([instruction]);
  }

  /**
   * Find agents by capability
   */
  async findAgents(capType: string): Promise<AgentRegistryEntry[]> {
    const results = await this.registry.findAgentsByCapability(capType);
    return results.map((r) => r.entry);
  }

  // ============================================================================
  // Reputation Operations
  // ============================================================================

  /**
   * Get reputation for an agent
   */
  async getAgentReputation(agentPolicyId: PublicKey): Promise<{
    account: AgentReputationAccount | null;
    score: number;
    tier: string;
  }> {
    const account = await this.reputation.fetchReputationByAgent(agentPolicyId);
    
    if (!account) {
      return { account: null, score: 5000, tier: "new" };
    }

    const score = this.reputation.calculateScore(account);
    const { tier } = this.reputation.getReputationTier(score);

    return { account, score, tier };
  }

  /**
   * Get top trusted agents
   */
  async getTopAgents(limit: number = 10): Promise<Array<{
    agentId: PublicKey;
    score: number;
    tier: string;
  }>> {
    const results = await this.reputation.getTopAgents(limit);
    
    return results.map(({ account, score }) => ({
      agentId: account.agentId,
      score,
      tier: this.reputation.getReputationTier(score).tier,
    }));
  }

  // ============================================================================
  // Transfer Operations
  // ============================================================================

  /**
   * Execute a direct transfer (agent-initiated)
   */
  async transfer(
    recipient: PublicKey,
    amount: BN,
    agentSigner?: Signer
  ): Promise<string> {
    if (!this.wallet) {
      throw new Error("Wallet not connected");
    }

    if (!this.settlementMint) {
      throw new Error("Settlement mint not set");
    }

    const senderAta = getAssociatedTokenAddressSync(
      this.settlementMint,
      this.wallet.publicKey,
      false,
      TOKEN_2022_PROGRAM_ID
    );

    const recipientAta = getAssociatedTokenAddressSync(
      this.settlementMint,
      recipient,
      false,
      TOKEN_2022_PROGRAM_ID
    );

    const instructions: TransactionInstruction[] = [];

    // Check if recipient ATA exists
    const recipientAtaInfo = await this.connection.getAccountInfo(recipientAta);
    if (!recipientAtaInfo) {
      instructions.push(
        createAssociatedTokenAccountInstruction(
          this.wallet.publicKey,
          recipientAta,
          recipient,
          this.settlementMint,
          TOKEN_2022_PROGRAM_ID
        )
      );
    }

    // Add transfer instruction
    // Note: In production, this would go through x0-guard transfer hook validation
    instructions.push(
      createTransferCheckedInstruction(
        senderAta,
        this.settlementMint,
        recipientAta,
        this.wallet.publicKey,
        BigInt(amount.toString()),
        6, // decimals
        [],
        TOKEN_2022_PROGRAM_ID
      )
    );

    const signers = agentSigner ? [agentSigner] : [];
    return this.sendTransaction(instructions, signers);
  }

  // ============================================================================
  // Blink Operations
  // ============================================================================

  /**
   * Generate a Blink for transfer approval
   */
  generateTransferApprovalBlink(params: {
    recipient: PublicKey;
    amount: BN;
    description: string;
    memo?: string;
  }): Blink {
    if (!this.wallet) {
      throw new Error("Wallet not connected");
    }

    const policyAddress = this.policy.derivePolicyAddress(this.wallet.publicKey);

    return generateTransferBlink({
      policyId: policyAddress,
      owner: this.wallet.publicKey,
      recipient: params.recipient,
      amount: params.amount,
      description: params.description,
      ...(params.memo && { memo: params.memo }),
    });
  }

  /**
   * Generate a shareable URL for a Blink
   */
  getBlinkUrl(blink: Blink, baseUrl: string): string {
    return generateBlinkUrl(blink, baseUrl);
  }

  // ============================================================================
  // x402 Operations
  // ============================================================================

  /**
   * Fetch a resource with automatic x402 payment handling
   */
  async fetchWithPayment(
    url: string,
    options?: RequestInit
  ): Promise<Response> {
    if (!this.wallet) {
      throw new Error("Wallet not connected");
    }

    return fetchWithPayment(url, options, async (request) => {
      // Execute the payment
      const recipient = new PublicKey(request.recipient);
      const amount = new BN(request.amount);
      const signature = await this.transfer(recipient, amount);
      
      // Get transaction slot
      const tx = await this.connection.getTransaction(signature, {
        commitment: "confirmed",
        maxSupportedTransactionVersion: 0,
      });

      if (!tx) {
        return null;
      }

      return {
        signature,
        slot: tx.slot,
        payer: this.wallet!.publicKey,
      };
    });
  }

  // ============================================================================
  // Utility Methods
  // ============================================================================

  /**
   * Get the associated token address for a wallet
   */
  getTokenAddress(owner: PublicKey): PublicKey {
    if (!this.settlementMint) {
      throw new Error("Settlement mint not set");
    }

    return getAssociatedTokenAddressSync(
      this.settlementMint,
      owner,
      false,
      TOKEN_2022_PROGRAM_ID
    );
  }

  /**
   * Get token balance for a wallet
   */
  async getBalance(owner: PublicKey): Promise<BN> {
    const ata = this.getTokenAddress(owner);
    
    try {
      const account = await this.connection.getTokenAccountBalance(ata);
      return new BN(account.value.amount);
    } catch {
      return new BN(0);
    }
  }

  /**
   * Get my token balance
   */
  async getMyBalance(): Promise<BN> {
    if (!this.wallet) {
      throw new Error("Wallet not connected");
    }

    return this.getBalance(this.wallet.publicKey);
  }

  /**
   * Calculate protocol fee for an amount
   */
  getProtocolFee(amount: BN): BN {
    return calculateProtocolFee(amount);
  }

  /**
   * Derive all PDAs for an owner
   */
  derivePDAs(owner: PublicKey): {
    policy: PublicKey;
    registry: PublicKey;
    reputation: PublicKey;
  } {
    const [policy] = deriveAgentPolicyPda(owner);
    const [registry] = deriveRegistryPda(policy);
    const [reputation] = deriveReputationPda(policy);

    return { policy, registry, reputation };
  }
}

// ============================================================================
// Factory Function
// ============================================================================

/**
 * Create a new X0Client instance
 */
export function createX0Client(config: X0ClientConfig): X0Client {
  return new X0Client(config);
}

/**
 * Create a client connected to devnet
 */
export function createDevnetClient(
  wallet?: X0ClientConfig["wallet"]
): X0Client {
  const config: X0ClientConfig = {
    connection: new Connection("https://api.devnet.solana.com", "confirmed"),
  };
  if (wallet) {
    config.wallet = wallet;
  }
  return new X0Client(config);
}

/**
 * Create a client connected to mainnet
 */
export function createMainnetClient(
  wallet?: X0ClientConfig["wallet"],
  rpcUrl?: string
): X0Client {
  const config: X0ClientConfig = {
    connection: new Connection(
      rpcUrl ?? "https://api.mainnet-beta.solana.com",
      "confirmed"
    ),
  };
  if (wallet) {
    config.wallet = wallet;
  }
  return new X0Client(config);
}
