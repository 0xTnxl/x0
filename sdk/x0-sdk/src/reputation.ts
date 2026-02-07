/**
 * Reputation Oracle Client
 * 
 * Client-side helpers for querying and managing agent reputation.
 */

import {
  Connection,
  PublicKey,
  TransactionInstruction,
  SystemProgram,
  SYSVAR_CLOCK_PUBKEY,
} from "@solana/web3.js";
import { BN } from "@coral-xyz/anchor";
import {
  X0_REPUTATION_PROGRAM_ID,
  REPUTATION_DECAY_RATE_BPS,
  REPUTATION_DECAY_PERIOD_SECONDS,
  DEFAULT_REPUTATION_SCORE,
} from "./constants";
import { deriveReputationPda, now, getInstructionDiscriminator } from "./utils";
import type { AgentReputationAccount, ReputationSnapshot } from "./types";

// ============================================================================
// Reputation Calculation Constants
// ============================================================================

const SCORE_BASE = 10000; // Base points for 100%

// ============================================================================
// Reputation Manager
// ============================================================================

export class ReputationManager {
  private connection: Connection;
  private programId: PublicKey;

  constructor(
    connection: Connection,
    programId: PublicKey = X0_REPUTATION_PROGRAM_ID
  ) {
    this.connection = connection;
    this.programId = programId;
  }

  /**
   * Derive reputation PDA for an agent
   */
  deriveReputationAddress(agentPolicyId: PublicKey): PublicKey {
    const [pda] = deriveReputationPda(agentPolicyId);
    return pda;
  }

  /**
   * Fetch a reputation account
   */
  async fetchReputation(
    reputationAddress: PublicKey
  ): Promise<AgentReputationAccount | null> {
    const accountInfo = await this.connection.getAccountInfo(reputationAddress);
    if (!accountInfo) {
      return null;
    }
    return this.parseReputationAccount(accountInfo.data);
  }

  /**
   * Fetch reputation by agent policy ID
   */
  async fetchReputationByAgent(
    agentPolicyId: PublicKey
  ): Promise<AgentReputationAccount | null> {
    const address = this.deriveReputationAddress(agentPolicyId);
    return this.fetchReputation(address);
  }

  /**
   * Parse raw account data into AgentReputationAccount
   * Handles both v1 (legacy) and v2 (with failed_transactions) layouts
   */
  private parseReputationAccount(data: Buffer): AgentReputationAccount {
    let offset = 8; // Skip discriminator

    // V2 layout:
    // [disc:8][ver:1][agent_id:32][total:8][success:8][disputed:8][resolved:8][failed:8][avg_resp:4][cumul_resp:8][last_upd:8][last_decay:8][bump:1][reserved:23]
    const version = data[offset]!;
    offset += 1;

    const agentId = new PublicKey(data.slice(offset, offset + 32));
    offset += 32;

    const totalTransactions = new BN(data.slice(offset, offset + 8), "le");
    offset += 8;

    const successfulTransactions = new BN(data.slice(offset, offset + 8), "le");
    offset += 8;

    const disputedTransactions = new BN(data.slice(offset, offset + 8), "le");
    offset += 8;

    const resolvedInFavor = new BN(data.slice(offset, offset + 8), "le");
    offset += 8;

    // V2 has failed_transactions, V1 doesn't
    let failedTransactions: BN;
    if (version >= 2) {
      failedTransactions = new BN(data.slice(offset, offset + 8), "le");
      offset += 8;
    } else {
      failedTransactions = new BN(0);
    }

    const averageResponseTimeMs = data.readUInt32LE(offset);
    offset += 4;

    const cumulativeResponseTimeMs = new BN(data.slice(offset, offset + 8), "le");
    offset += 8;

    const lastUpdated = new BN(data.slice(offset, offset + 8), "le").toNumber();
    offset += 8;

    const lastDecayApplied = new BN(data.slice(offset, offset + 8), "le").toNumber();
    offset += 8;

    const bump = data[offset]!;

    return {
      version,
      agentId,
      totalTransactions,
      successfulTransactions,
      disputedTransactions,
      resolvedInFavor,
      failedTransactions,
      averageResponseTimeMs,
      lastUpdated,
      lastActivityAt: lastUpdated,
      lastDecayAt: lastDecayApplied,
      cumulativeResponseTimeMs,
      bump,
    };
  }

  // ============================================================================
  // Instruction Builders
  // ============================================================================

  /**
   * Build instruction to initialize reputation for an agent
   */
  buildInitializeReputationInstruction(
    payer: PublicKey,
    agentPolicyId: PublicKey
  ): {
    instruction: TransactionInstruction;
    reputationAddress: PublicKey;
  } {
    const [reputationAddress] = deriveReputationPda(agentPolicyId);

    const discriminator = getInstructionDiscriminator("initialize_reputation");

    const keys = [
      { pubkey: payer, isSigner: true, isWritable: true },
      { pubkey: agentPolicyId, isSigner: false, isWritable: false },
      { pubkey: reputationAddress, isSigner: false, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ];

    return {
      instruction: new TransactionInstruction({
        programId: this.programId,
        keys,
        data: discriminator,
      }),
      reputationAddress,
    };
  }

  /**
   * Build instruction to record a successful transaction
   * Note: This would typically be called by the escrow program via CPI
   */
  buildRecordSuccessInstruction(
    authority: PublicKey,
    reputationAddress: PublicKey,
    volume: BN
  ): TransactionInstruction {
    const discriminator = getInstructionDiscriminator("record_success");

    const data = Buffer.concat([
      discriminator,
      volume.toArrayLike(Buffer, "le", 8),
    ]);

    const keys = [
      { pubkey: authority, isSigner: true, isWritable: false },
      { pubkey: reputationAddress, isSigner: false, isWritable: true },
      { pubkey: SYSVAR_CLOCK_PUBKEY, isSigner: false, isWritable: false },
    ];

    return new TransactionInstruction({
      programId: this.programId,
      keys,
      data,
    });
  }

  /**
   * Build instruction to record a dispute
   */
  buildRecordDisputeInstruction(
    authority: PublicKey,
    reputationAddress: PublicKey
  ): TransactionInstruction {
    const discriminator = getInstructionDiscriminator("record_dispute");

    const keys = [
      { pubkey: authority, isSigner: true, isWritable: false },
      { pubkey: reputationAddress, isSigner: false, isWritable: true },
      { pubkey: SYSVAR_CLOCK_PUBKEY, isSigner: false, isWritable: false },
    ];

    return new TransactionInstruction({
      programId: this.programId,
      keys,
      data: discriminator,
    });
  }

  /**
   * Build instruction to record dispute resolution in agent's favor
   */
  buildRecordResolutionFavorInstruction(
    authority: PublicKey,
    reputationAddress: PublicKey
  ): TransactionInstruction {
    const discriminator = getInstructionDiscriminator("record_resolution_favor");

    const keys = [
      { pubkey: authority, isSigner: true, isWritable: false },
      { pubkey: reputationAddress, isSigner: false, isWritable: true },
      { pubkey: SYSVAR_CLOCK_PUBKEY, isSigner: false, isWritable: false },
    ];

    return new TransactionInstruction({
      programId: this.programId,
      keys,
      data: discriminator,
    });
  }

  /**
   * Build instruction to record a failed transaction (policy rejection)
   * 
   * Called when an agent attempts a transfer that violates their policy.
   * Only the x0-guard program or the policy owner can call this.
   * 
   * @param authority - The policy owner or x0-guard program
   * @param agentPolicyId - The agent's policy PDA
   * @param reputationAddress - The reputation PDA
   * @param errorCode - The error code that caused the rejection
   */
  buildRecordFailureInstruction(
    authority: PublicKey,
    agentPolicyId: PublicKey,
    reputationAddress: PublicKey,
    errorCode: number
  ): TransactionInstruction {
    const discriminator = getInstructionDiscriminator("record_failure");

    const data = Buffer.concat([
      discriminator,
      Buffer.from(new Uint32Array([errorCode]).buffer),
    ]);

    const keys = [
      { pubkey: authority, isSigner: true, isWritable: false },
      { pubkey: agentPolicyId, isSigner: false, isWritable: false },
      { pubkey: reputationAddress, isSigner: false, isWritable: true },
    ];

    return new TransactionInstruction({
      programId: this.programId,
      keys,
      data,
    });
  }

  /**
   * Build instruction to migrate a v1 reputation account to v2
   * 
   * This handles accounts created before failed_transactions was added.
   * Only the policy owner can call this.
   * 
   * @param owner - The policy owner
   * @param agentPolicyId - The agent's policy PDA
   * @param reputationAddress - The reputation PDA
   */
  buildMigrateReputationInstruction(
    owner: PublicKey,
    agentPolicyId: PublicKey,
    reputationAddress: PublicKey
  ): TransactionInstruction {
    const discriminator = getInstructionDiscriminator("migrate_reputation");

    const keys = [
      { pubkey: owner, isSigner: true, isWritable: true },
      { pubkey: agentPolicyId, isSigner: false, isWritable: false },
      { pubkey: reputationAddress, isSigner: false, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ];

    return new TransactionInstruction({
      programId: this.programId,
      keys,
      data: discriminator,
    });
  }

  /**
   * Build instruction to apply time-based decay
   */
  buildApplyDecayInstruction(
    reputationAddress: PublicKey
  ): TransactionInstruction {
    const discriminator = getInstructionDiscriminator("apply_decay");

    const keys = [
      { pubkey: reputationAddress, isSigner: false, isWritable: true },
      { pubkey: SYSVAR_CLOCK_PUBKEY, isSigner: false, isWritable: false },
    ];

    return new TransactionInstruction({
      programId: this.programId,
      keys,
      data: discriminator,
    });
  }

  /**
   * Build instruction to close a reputation account and reclaim rent.
   * 
   * Only the policy owner can close the reputation account.
   * The lamports are returned to the owner.
   * 
   * @param owner - The policy owner (signer, receives rent)
   * @param agentPolicyId - The agent's policy PDA
   */
  buildCloseReputationInstruction(
    owner: PublicKey,
    agentPolicyId: PublicKey
  ): TransactionInstruction {
    const [reputationAddress] = deriveReputationPda(agentPolicyId);

    const discriminator = getInstructionDiscriminator("close_reputation");

    const keys = [
      { pubkey: owner, isSigner: true, isWritable: true },
      { pubkey: agentPolicyId, isSigner: false, isWritable: false },
      { pubkey: reputationAddress, isSigner: false, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ];

    return new TransactionInstruction({
      programId: this.programId,
      keys,
      data: discriminator,
    });
  }

  // ============================================================================
  // Score Calculation
  // ============================================================================

  /**
   * Calculate reputation score from account data
   * 
   * V2 scoring formula (weighted components):
   * - 60% success rate (successful / total)
   * - 15% resolution rate (resolved / disputes, neutral if no disputes)
   * - 10% inverse dispute rate (1 - disputes/total)
   * - 15% inverse failure rate (1 - failures/total)
   * 
   * Returns a value between 0 and 10000 (representing 0% to 100%)
   */
  calculateScore(account: AgentReputationAccount): number {
    const totalTx = account.totalTransactions.toNumber();
    const successTx = account.successfulTransactions.toNumber();
    const disputedTx = account.disputedTransactions.toNumber();
    const resolvedTx = account.resolvedInFavor.toNumber();
    const failedTx = account.failedTransactions?.toNumber() ?? 0;

    // New agents start at neutral score
    if (totalTx === 0) {
      return DEFAULT_REPUTATION_SCORE;
    }

    // Calculate component rates
    const successRate = successTx / totalTx;
    const disputeRate = disputedTx / totalTx;
    const failureRate = failedTx / totalTx;
    
    // Resolution rate: neutral (0.5) if no disputes
    const resolutionRate = disputedTx > 0 ? resolvedTx / disputedTx : 0.5;

    // Weighted score calculation (matches on-chain formula)
    const weightedScore =
      successRate * 0.6 +           // 60% success
      resolutionRate * 0.15 +       // 15% resolution
      (1.0 - disputeRate) * 0.10 +  // 10% inverse dispute
      (1.0 - failureRate) * 0.15;   // 15% inverse failure

    let score = Math.floor(weightedScore * SCORE_BASE);

    // Apply time-based decay
    const currentTime = now();
    const lastActivity = account.lastActivityAt ?? 0;
    const timeSinceActivity = currentTime - lastActivity;
    const decayPeriods = Math.floor(timeSinceActivity / REPUTATION_DECAY_PERIOD_SECONDS);
    
    if (decayPeriods > 0) {
      const decayFactor = Math.pow(
        1 - REPUTATION_DECAY_RATE_BPS / 10000,
        decayPeriods
      );
      score = Math.floor(score * decayFactor);
    }

    return Math.max(0, Math.min(SCORE_BASE, score));
  }

  /**
   * Calculate score with decay applied from current time
   */
  calculateScoreWithDecay(
    account: AgentReputationAccount,
    currentTime?: number
  ): number {
    const time = currentTime ?? now();
    const baseScore = this.calculateScore(account);
    
    const lastDecay = account.lastDecayAt ?? 0;
    const timeSinceDecay = time - lastDecay;
    const decayPeriods = Math.floor(timeSinceDecay / REPUTATION_DECAY_PERIOD_SECONDS);
    
    if (decayPeriods <= 0) {
      return baseScore;
    }

    const decayFactor = Math.pow(
      1 - REPUTATION_DECAY_RATE_BPS / 10000,
      decayPeriods
    );
    
    return Math.floor(baseScore * decayFactor);
  }

  /**
   * Get reputation tier from score
   */
  getReputationTier(score: number): {
    tier: "legendary" | "excellent" | "good" | "fair" | "poor" | "untrusted";
    label: string;
    minScore: number;
  } {
    if (score >= 9500) {
      return { tier: "legendary", label: "Legendary", minScore: 9500 };
    }
    if (score >= 8500) {
      return { tier: "excellent", label: "Excellent", minScore: 8500 };
    }
    if (score >= 7000) {
      return { tier: "good", label: "Good", minScore: 7000 };
    }
    if (score >= 5000) {
      return { tier: "fair", label: "Fair", minScore: 5000 };
    }
    if (score >= 2500) {
      return { tier: "poor", label: "Poor", minScore: 2500 };
    }
    return { tier: "untrusted", label: "Untrusted", minScore: 0 };
  }

  /**
   * Format score as percentage string
   */
  formatScoreAsPercentage(score: number): string {
    return `${(score / 100).toFixed(2)}%`;
  }

  /**
   * Get a snapshot of reputation data
   */
  getSnapshot(account: AgentReputationAccount): ReputationSnapshot {
    const score = this.calculateScore(account);
    
    const totalTx = account.totalTransactions.toNumber();
    const successTx = account.successfulTransactions.toNumber();
    
    const successRate = totalTx > 0
      ? successTx / totalTx
      : 0;

    const lastActivity = account.lastActivityAt ?? 0;

    return {
      timestamp: lastActivity,
      score,
      totalTransactions: totalTx,
      successRate,
    };
  }

  /**
   * Get detailed reputation information
   */
  getDetailedSnapshot(account: AgentReputationAccount): {
    agentId: PublicKey;
    score: number;
    tier: string;
    tierLabel: string;
    totalTransactions: number;
    successfulTransactions: number;
    disputedTransactions: number;
    resolvedInFavor: number;
    successRate: number;
    disputeRate: number;
    totalVolume?: BN;
    lastActivityAt: number;
    isActive: boolean;
  } {
    const score = this.calculateScore(account);
    const tier = this.getReputationTier(score);
    
    const totalTx = account.totalTransactions.toNumber();
    const successTx = account.successfulTransactions.toNumber();
    const disputedTx = account.disputedTransactions.toNumber();
    
    const successRate = totalTx > 0
      ? successTx / totalTx
      : 0;
    
    const disputeRate = totalTx > 0
      ? disputedTx / totalTx
      : 0;

    const lastActivity = account.lastActivityAt ?? 0;

    return {
      agentId: account.agentId,
      score,
      tier: tier.tier,
      tierLabel: tier.label,
      
      totalTransactions: totalTx,
      successfulTransactions: successTx,
      disputedTransactions: disputedTx,
      resolvedInFavor: account.resolvedInFavor.toNumber(),
      
      successRate,
      disputeRate,
      
      ...(account.totalVolume && { totalVolume: account.totalVolume }),
      lastActivityAt: lastActivity,
      
      isActive: (now() - lastActivity) < 30 * 24 * 60 * 60, // Active within 30 days
    };
  }

  // ============================================================================
  // Query Methods
  // ============================================================================

  /**
   * Get all reputation accounts
   */
  async getAllReputations(): Promise<Array<{
    address: PublicKey;
    account: AgentReputationAccount;
  }>> {
    const accounts = await this.connection.getProgramAccounts(this.programId);

    return accounts.map(({ pubkey, account }) => ({
      address: pubkey,
      account: this.parseReputationAccount(account.data as Buffer),
    }));
  }

  /**
   * Get top agents by reputation score
   */
  async getTopAgents(limit: number = 10): Promise<Array<{
    address: PublicKey;
    account: AgentReputationAccount;
    score: number;
  }>> {
    const allReputations = await this.getAllReputations();
    
    return allReputations
      .map(({ address, account }) => ({
        address,
        account,
        score: this.calculateScore(account),
      }))
      .sort((a, b) => b.score - a.score)
      .slice(0, limit);
  }

  /**
   * Get agents above a minimum score threshold
   */
  async getAgentsAboveThreshold(
    minScore: number
  ): Promise<Array<{
    address: PublicKey;
    account: AgentReputationAccount;
    score: number;
  }>> {
    const allReputations = await this.getAllReputations();
    
    return allReputations
      .map(({ address, account }) => ({
        address,
        account,
        score: this.calculateScore(account),
      }))
      .filter(({ score }) => score >= minScore);
  }

  /**
   * Check if an agent meets a minimum reputation requirement
   */
  async meetsReputationRequirement(
    agentPolicyId: PublicKey,
    minScore: number
  ): Promise<boolean> {
    const account = await this.fetchReputationByAgent(agentPolicyId);
    
    if (!account) {
      return false;
    }

    const score = this.calculateScore(account);
    return score >= minScore;
  }

  // ============================================================================
  // Analytics
  // ============================================================================

  /**
   * Calculate average reputation score across all agents
   */
  async getAverageScore(): Promise<number> {
    const allReputations = await this.getAllReputations();
    
    if (allReputations.length === 0) {
      return DEFAULT_REPUTATION_SCORE;
    }

    const totalScore = allReputations.reduce(
      (sum, { account }) => sum + this.calculateScore(account),
      0
    );

    return Math.floor(totalScore / allReputations.length);
  }

  /**
   * Get reputation distribution by tier
   */
  async getDistributionByTier(): Promise<Record<string, number>> {
    const allReputations = await this.getAllReputations();
    
    const distribution: Record<string, number> = {
      legendary: 0,
      excellent: 0,
      good: 0,
      fair: 0,
      poor: 0,
      untrusted: 0,
    };

    for (const { account } of allReputations) {
      const score = this.calculateScore(account);
      const { tier } = this.getReputationTier(score);
      distribution[tier]++;
    }

    return distribution;
  }
}
