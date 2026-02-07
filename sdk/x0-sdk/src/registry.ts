/**
 * Agent Registry Client
 * 
 * Client-side helpers for agent discovery and registration.
 */

import {
  Connection,
  PublicKey,
  TransactionInstruction,
  SystemProgram,
} from "@solana/web3.js";
import { BN } from "@coral-xyz/anchor";
import {
  X0_REGISTRY_PROGRAM_ID,
  MAX_CAPABILITIES,
  MAX_METADATA_SIZE,
} from "./constants";
import { deriveRegistryPda, getInstructionDiscriminator } from "./utils";
import type {
  AgentRegistryEntry,
  Capability,
  RegisterAgentParams,
} from "./types";

// ============================================================================
// Registry Manager
// ============================================================================

export class RegistryManager {
  private connection: Connection;
  private programId: PublicKey;

  constructor(
    connection: Connection,
    programId: PublicKey = X0_REGISTRY_PROGRAM_ID
  ) {
    this.connection = connection;
    this.programId = programId;
  }

  /**
   * Derive registry entry PDA for an agent
   */
  deriveRegistryAddress(agentPolicyId: PublicKey): PublicKey {
    const [pda] = deriveRegistryPda(agentPolicyId);
    return pda;
  }

  /**
   * Fetch a registry entry
   */
  async fetchRegistryEntry(
    entryAddress: PublicKey
  ): Promise<AgentRegistryEntry | null> {
    const accountInfo = await this.connection.getAccountInfo(entryAddress);
    if (!accountInfo) {
      return null;
    }
    return this.parseRegistryEntry(accountInfo.data);
  }

  /**
   * Fetch a registry entry by agent policy ID
   */
  async fetchRegistryByAgent(
    agentPolicyId: PublicKey
  ): Promise<AgentRegistryEntry | null> {
    const entryAddress = this.deriveRegistryAddress(agentPolicyId);
    return this.fetchRegistryEntry(entryAddress);
  }

  /**
   * Parse raw account data into AgentRegistryEntry
   */
  private parseRegistryEntry(data: Buffer): AgentRegistryEntry {
    let offset = 8; // Skip discriminator

    // version: u8 (skip)
    offset += 1;

    const agentId = new PublicKey(data.slice(offset, offset + 32));
    offset += 32;

    // Endpoint (String)
    const endpointLen = data.readUInt32LE(offset);
    offset += 4;
    const endpoint = data.slice(offset, offset + endpointLen).toString("utf-8");
    offset += endpointLen;

    // Capabilities (Vec<Capability>) - on-chain: { capability_type: String, metadata: String }
    const capsLen = data.readUInt32LE(offset);
    offset += 4;
    const capabilities: Capability[] = [];
    
    for (let i = 0; i < capsLen; i++) {
      const typeLen = data.readUInt32LE(offset);
      offset += 4;
      const capType = data.slice(offset, offset + typeLen).toString("utf-8");
      offset += typeLen;

      const metaLen = data.readUInt32LE(offset);
      offset += 4;
      const metadata = data.slice(offset, offset + metaLen).toString("utf-8");
      offset += metaLen;

      capabilities.push({ capType, type: capType, metadata });
    }

    // price_oracle: Option<Pubkey>
    const hasPriceOracle = data[offset]! === 1;
    offset += 1;
    if (hasPriceOracle) {
      offset += 32; // skip the pubkey
    }

    // reputation_pda: Pubkey
    const reputationPda = new PublicKey(data.slice(offset, offset + 32));
    offset += 32;

    // last_updated: i64
    const lastUpdated = new BN(data.slice(offset, offset + 8), "le").toNumber();
    offset += 8;

    // is_active: bool
    const isActive = data[offset]! === 1;
    offset += 1;

    // owner: Pubkey
    const owner = new PublicKey(data.slice(offset, offset + 32));
    offset += 32;

    // bump: u8
    // const bump = data[offset]!;

    return {
      agentId,
      owner,
      endpoint,
      capabilities,
      reputationPda,
      lastUpdated,
      isActive,
    };
  }

  // ============================================================================
  // Instruction Builders
  // ============================================================================

  /**
   * Build instruction to register a new agent
   */
  buildRegisterAgentInstruction(params: RegisterAgentParams & { owner: PublicKey }): {
    instruction: TransactionInstruction;
    registryAddress: PublicKey;
  } {
    const [registryAddress] = deriveRegistryPda(params.agentPolicyId);

    // Validate
    if (params.capabilities.length > MAX_CAPABILITIES) {
      throw new Error(`Too many capabilities (max ${MAX_CAPABILITIES})`);
    }
    
    const metadataJson = params.metadataJson ?? params.metadata ?? "{}";
    const metadataBytes = Buffer.from(metadataJson, "utf-8");
    if (metadataBytes.length > MAX_METADATA_SIZE) {
      throw new Error(`Metadata too large (max ${MAX_METADATA_SIZE} bytes)`);
    }

    const discriminator = getInstructionDiscriminator("register_agent");

    const endpointBytes = Buffer.from(params.endpoint, "utf-8");

    // Serialize capabilities (on-chain: Vec<Capability { capability_type: String, metadata: String }>)
    const capParts: Buffer[] = [];
    capParts.push(Buffer.from(new Uint32Array([params.capabilities.length]).buffer));
    
    for (const cap of params.capabilities) {
      const capType = cap.capType ?? cap.type;
      const typeBytes = Buffer.from(capType, "utf-8");
      capParts.push(Buffer.from(new Uint32Array([typeBytes.length]).buffer));
      capParts.push(typeBytes);

      const capMeta = cap.metadata ?? "";
      const metaBytes = Buffer.from(capMeta, "utf-8");
      capParts.push(Buffer.from(new Uint32Array([metaBytes.length]).buffer));
      capParts.push(metaBytes);
    }

    const data = Buffer.concat([
      discriminator,
      Buffer.from(new Uint32Array([endpointBytes.length]).buffer),
      endpointBytes,
      ...capParts,
      Buffer.from(new Uint32Array([metadataBytes.length]).buffer),
      metadataBytes,
    ]);

    const keys = [
      { pubkey: params.owner, isSigner: true, isWritable: true },
      { pubkey: params.agentPolicyId, isSigner: false, isWritable: false },
      { pubkey: registryAddress, isSigner: false, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ];

    return {
      instruction: new TransactionInstruction({
        programId: this.programId,
        keys,
        data,
      }),
      registryAddress,
    };
  }

  /**
   * Build instruction to update registry entry
   */
  buildUpdateRegistryInstruction(
    owner: PublicKey,
    registryAddress: PublicKey,
    updates: {
      endpoint?: string;
      capabilities?: Capability[];
      metadataJson?: string;
    }
  ): TransactionInstruction {
    const discriminator = getInstructionDiscriminator("update_registry");

    const parts: Buffer[] = [discriminator];

    // Option<String> endpoint
    if (updates.endpoint) {
      const endpointBytes = Buffer.from(updates.endpoint, "utf-8");
      parts.push(Buffer.from([1]));
      parts.push(Buffer.from(new Uint32Array([endpointBytes.length]).buffer));
      parts.push(endpointBytes);
    } else {
      parts.push(Buffer.from([0]));
    }

    // Option<Vec<Capability>> capabilities
    if (updates.capabilities) {
      parts.push(Buffer.from([1]));
      parts.push(Buffer.from(new Uint32Array([updates.capabilities.length]).buffer));
      
      for (const cap of updates.capabilities) {
        const capType = cap.capType ?? cap.type;
        const typeBytes = Buffer.from(capType, "utf-8");
        parts.push(Buffer.from(new Uint32Array([typeBytes.length]).buffer));
        parts.push(typeBytes);

        const capMeta = cap.metadata ?? "";
        const metaBytes = Buffer.from(capMeta, "utf-8");
        parts.push(Buffer.from(new Uint32Array([metaBytes.length]).buffer));
        parts.push(metaBytes);
      }
    } else {
      parts.push(Buffer.from([0]));
    }

    // Option<String> metadataJson
    if (updates.metadataJson) {
      const metaBytes = Buffer.from(updates.metadataJson, "utf-8");
      parts.push(Buffer.from([1]));
      parts.push(Buffer.from(new Uint32Array([metaBytes.length]).buffer));
      parts.push(metaBytes);
    } else {
      parts.push(Buffer.from([0]));
    }

    const data = Buffer.concat(parts);

    const keys = [
      { pubkey: owner, isSigner: true, isWritable: false },
      { pubkey: registryAddress, isSigner: false, isWritable: true },
    ];

    return new TransactionInstruction({
      programId: this.programId,
      keys,
      data,
    });
  }

  /**
   * Build instruction to deactivate registry entry
   */
  buildDeactivateInstruction(
    owner: PublicKey,
    registryAddress: PublicKey
  ): TransactionInstruction {
    const discriminator = getInstructionDiscriminator("deactivate_entry");

    const keys = [
      { pubkey: owner, isSigner: true, isWritable: false },
      { pubkey: registryAddress, isSigner: false, isWritable: true },
    ];

    return new TransactionInstruction({
      programId: this.programId,
      keys,
      data: discriminator,
    });
  }

  /**
   * Build instruction to reactivate registry entry
   */
  buildReactivateInstruction(
    owner: PublicKey,
    registryAddress: PublicKey
  ): TransactionInstruction {
    const discriminator = getInstructionDiscriminator("reactivate_entry");

    const keys = [
      { pubkey: owner, isSigner: true, isWritable: false },
      { pubkey: registryAddress, isSigner: false, isWritable: true },
    ];

    return new TransactionInstruction({
      programId: this.programId,
      keys,
      data: discriminator,
    });
  }

  /**
   * Build instruction to deregister agent (close account)
   */
  buildDeregisterInstruction(
    owner: PublicKey,
    registryAddress: PublicKey
  ): TransactionInstruction {
    const discriminator = getInstructionDiscriminator("deregister_agent");

    const keys = [
      { pubkey: owner, isSigner: true, isWritable: true },
      { pubkey: registryAddress, isSigner: false, isWritable: true },
    ];

    return new TransactionInstruction({
      programId: this.programId,
      keys,
      data: discriminator,
    });
  }

  // ============================================================================
  // Discovery Methods
  // ============================================================================

  /**
   * Get all active agents
   */
  async getAllActiveAgents(): Promise<Array<{
    address: PublicKey;
    entry: AgentRegistryEntry;
  }>> {
    const accounts = await this.connection.getProgramAccounts(this.programId, {
      filters: [
        // Filter by isActive = true
        // This is a simplified filter - actual offset depends on account structure
      ],
    });

    const results = accounts
      .map(({ pubkey, account }) => ({
        address: pubkey,
        entry: this.parseRegistryEntry(account.data as Buffer),
      }))
      .filter((r) => r.entry.isActive);

    return results;
  }

  /**
   * Search agents by capability type
   */
  async findAgentsByCapability(
    capType: string
  ): Promise<Array<{
    address: PublicKey;
    entry: AgentRegistryEntry;
    matchingCapability: Capability;
  }>> {
    const allAgents = await this.getAllActiveAgents();

    return allAgents
      .map(({ address, entry }) => {
        const matchingCapability = entry.capabilities.find(
          (c) => (c.capType ?? c.type) === capType
        );
        if (!matchingCapability) return null;
        return { address, entry, matchingCapability };
      })
      .filter((r): r is NonNullable<typeof r> => r !== null);
  }

  /**
   * Find cheapest agent for a capability.
   * 
   * Parses pricing from the capability's metadata JSON field.
   * Expected metadata format: `{ "pricing": 1000, ... }` (pricing in micro-units)
   * Returns null if no agents found or none have pricing metadata.
   */
  async findCheapestAgent(
    capType: string
  ): Promise<{
    address: PublicKey;
    entry: AgentRegistryEntry;
    capability: Capability;
    pricing: number;
  } | null> {
    const agents = await this.findAgentsByCapability(capType);
    
    if (agents.length === 0) return null;

    // Extract pricing from metadata
    const withPricing = agents.map(({ address, entry, matchingCapability }) => {
      let pricing = Infinity;
      try {
        const meta = JSON.parse(matchingCapability.metadata);
        if (typeof meta.pricing === "number") {
          pricing = meta.pricing;
        }
      } catch {
        // No valid pricing metadata
      }
      return { address, entry, capability: matchingCapability, pricing };
    }).filter(a => a.pricing < Infinity);

    if (withPricing.length === 0) return null;

    const cheapest = withPricing.reduce((best, current) =>
      current.pricing < best.pricing ? current : best
    );
    
    return cheapest;
  }

  /**
   * Find agents by endpoint domain
   */
  async findAgentsByDomain(
    domain: string
  ): Promise<Array<{
    address: PublicKey;
    entry: AgentRegistryEntry;
  }>> {
    const allAgents = await this.getAllActiveAgents();
    
    return allAgents.filter(({ entry }) => {
      try {
        const url = new URL(entry.endpoint);
        return url.hostname === domain || url.hostname.endsWith(`.${domain}`);
      } catch {
        return false;
      }
    });
  }

  // ============================================================================
  // Capability Helpers
  // ============================================================================

  /**
   * Create a capability definition
   * 
   * On-chain capabilities have a type string and a JSON metadata blob.
   * Use the metadata field to encode pricing, versioning, and other details.
   */
  createCapability(
    capType: string,
    metadata: string = "{}"
  ): Capability {
    return {
      capType,
      type: capType,
      metadata,
    };
  }

  /**
   * Common capability types
   */
  static readonly CAPABILITY_TYPES = {
    TEXT_GENERATION: "text-generation",
    IMAGE_GENERATION: "image-generation",
    CODE_EXECUTION: "code-execution",
    WEB_SEARCH: "web-search",
    DATA_ANALYSIS: "data-analysis",
    EMBEDDING: "embedding",
    SPEECH_TO_TEXT: "speech-to-text",
    TEXT_TO_SPEECH: "text-to-speech",
    TRANSLATION: "translation",
    SUMMARIZATION: "summarization",
    CUSTOM: "custom",
  } as const;

  /**
   * Validate capability type format
   */
  isValidCapabilityType(capType: string): boolean {
    return /^[a-zA-Z0-9-]+$/.test(capType) && capType.length <= 64;
  }

  /**
   * Build metadata JSON for registration
   */
  buildMetadata(metadata: {
    name?: string;
    description?: string;
    version?: string;
    documentation?: string;
    terms?: string;
    contact?: string;
    tags?: string[];
    rateLimit?: {
      requestsPerMinute: number;
      burstLimit: number;
    };
  }): string {
    return JSON.stringify(metadata);
  }

  /**
   * Parse metadata JSON
   */
  parseMetadata(metadataJson: string): Record<string, unknown> {
    try {
      return JSON.parse(metadataJson);
    } catch {
      return {};
    }
  }
}
