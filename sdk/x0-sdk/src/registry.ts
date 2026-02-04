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
import { deriveRegistryPda } from "./utils";
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

    const agentId = new PublicKey(data.slice(offset, offset + 32));
    offset += 32;

    const owner = new PublicKey(data.slice(offset, offset + 32));
    offset += 32;

    // Endpoint (String)
    const endpointLen = data.readUInt32LE(offset);
    offset += 4;
    const endpoint = data.slice(offset, offset + endpointLen).toString("utf-8");
    offset += endpointLen;

    // Capabilities (Vec<Capability>)
    const capsLen = data.readUInt32LE(offset);
    offset += 4;
    const capabilities: Capability[] = [];
    
    for (let i = 0; i < capsLen; i++) {
      const typeLen = data.readUInt32LE(offset);
      offset += 4;
      const capType = data.slice(offset, offset + typeLen).toString("utf-8");
      offset += typeLen;

      const version = data.readUInt16LE(offset);
      offset += 2;

      // Pricing (BN as u64)
      const pricingLow = data.readUInt32LE(offset);
      const pricingHigh = data.readUInt32LE(offset + 4);
      offset += 8;
      const pricing = new BN(pricingLow).add(new BN(pricingHigh).shln(32));

      capabilities.push({ capType, type: capType, version, pricing, metadata: "" });
    }

    // Skip metadata JSON (String) - not currently used but reserved for future
    const metadataLen = data.readUInt32LE(offset);
    offset += 4 + metadataLen;

    // Skip registered timestamp - reserved for future use
    offset += 8;

    const lastActiveAt = new BN(data.slice(offset, offset + 8), "le").toNumber();
    offset += 8;

    const isActive = data[offset] === 1;
    // Note: bump is at offset+1 but not currently needed

    return {
      agentId,
      owner,
      endpoint,
      capabilities,
      reputationPda: agentId, // placeholder - in production derive from agentId
      lastUpdated: lastActiveAt,
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

    const discriminator = Buffer.from([
      0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11
    ]);

    const endpointBytes = Buffer.from(params.endpoint, "utf-8");

    // Serialize capabilities
    const capParts: Buffer[] = [];
    capParts.push(Buffer.from(new Uint32Array([params.capabilities.length]).buffer));
    
    for (const cap of params.capabilities) {
      const capType = cap.capType ?? cap.type;
      const typeBytes = Buffer.from(capType, "utf-8");
      capParts.push(Buffer.from(new Uint32Array([typeBytes.length]).buffer));
      capParts.push(typeBytes);
      capParts.push(Buffer.from(new Uint16Array([cap.version]).buffer));
      capParts.push(cap.pricing.toArrayLike(Buffer, "le", 8));
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
    const discriminator = Buffer.from([
      0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22
    ]);

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
        parts.push(Buffer.from(new Uint16Array([cap.version]).buffer));
        parts.push(cap.pricing.toArrayLike(Buffer, "le", 8));
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
    const discriminator = Buffer.from([
      0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33
    ]);

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
    const discriminator = Buffer.from([
      0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44
    ]);

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
    const discriminator = Buffer.from([
      0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55
    ]);

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
   * Find cheapest agent for a capability
   */
  async findCheapestAgent(
    capType: string
  ): Promise<{
    address: PublicKey;
    entry: AgentRegistryEntry;
    capability: Capability;
  } | null> {
    const agents = await this.findAgentsByCapability(capType);
    
    if (agents.length === 0) return null;

    const cheapest = agents.reduce((best, current) => {
      if (current.matchingCapability.pricing.lt(best.matchingCapability.pricing)) {
        return current;
      }
      return best;
    });
    
    return {
      address: cheapest.address,
      entry: cheapest.entry,
      capability: cheapest.matchingCapability,
    };
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
   */
  createCapability(
    capType: string,
    version: number,
    pricingPerCall: BN
  ): Capability {
    return {
      capType,
      type: capType,
      version,
      pricing: pricingPerCall,
      metadata: "",
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
