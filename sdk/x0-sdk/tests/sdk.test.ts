import { expect } from "chai";
import { Connection, Keypair, PublicKey, LAMPORTS_PER_SOL } from "@solana/web3.js";
import { BN } from "@coral-xyz/anchor";
import {
  X0Client,
  createDevnetClient,
  PolicyManager,
  EscrowManager,
  RegistryManager,
  ReputationManager,
  WhitelistMode,
  PrivacyLevel,
} from "../src";

describe("x0-sdk", () => {
  let connection: Connection;
  let client: X0Client;
  let testWallet: Keypair;

  before(async () => {
    connection = new Connection("http://localhost:8899", "confirmed");
    testWallet = Keypair.generate();

    // Airdrop for testing
    const airdropSig = await connection.requestAirdrop(
      testWallet.publicKey,
      2 * LAMPORTS_PER_SOL
    );
    await connection.confirmTransaction(airdropSig);

    client = new X0Client({
      connection,
      wallet: {
        publicKey: testWallet.publicKey,
        signTransaction: async (tx) => {
          tx.sign(testWallet);
          return tx;
        },
      },
    });
  });

  describe("PolicyManager", () => {
    const policyManager = new PolicyManager(connection);

    it("should derive policy PDA correctly", () => {
      const owner = Keypair.generate().publicKey;
      const pda = policyManager.derivePolicyAddress(owner);
      expect(pda).to.be.instanceOf(PublicKey);
    });

    it("should build conservative preset", () => {
      const preset = policyManager.getConservativePreset();
      expect(preset.spendLimit.toNumber()).to.equal(100_000_000);
      expect(preset.txLimit.toNumber()).to.equal(10_000_000);
      expect(preset.privacyLevel).to.equal(PrivacyLevel.Public);
    });

    it("should build Merkle whitelist", () => {
      const addresses = [
        Keypair.generate().publicKey,
        Keypair.generate().publicKey,
        Keypair.generate().publicKey,
      ];
      const root = policyManager.buildMerkleWhitelist(addresses);
      expect(root).to.have.length(32);
    });

    it("should build Bloom filter whitelist", () => {
      const addresses = [
        Keypair.generate().publicKey,
        Keypair.generate().publicKey,
      ];
      const filter = policyManager.buildBloomWhitelist(addresses);
      expect(filter.length).to.be.greaterThan(0);
    });

    it("should calculate remaining spend capacity", () => {
      const mockPolicy = {
        owner: Keypair.generate().publicKey,
        agentSigner: Keypair.generate().publicKey,
        spendLimit: new BN(1_000_000_000),
        txLimit: new BN(100_000_000),
        rollingSpend: new BN(500_000_000),
        windowStart: Math.floor(Date.now() / 1000) - 3600,
        privacyLevel: PrivacyLevel.Public,
        whitelistMode: WhitelistMode.None,
        isActive: true,
        bump: 255,
        whitelistData: new Uint8Array(),
        // Required AgentPolicyAccount fields
        dailyLimit: new BN(1_000_000_000),
        maxSingleTransaction: new BN(100_000_000),
        currentSpend: new BN(500_000_000),
        requireDelegation: false,
        boundTokenAccount: null,
        rollingWindow: [],
        lastUpdated: Math.floor(Date.now() / 1000) - 3600,
      };

      const remaining = policyManager.getRemainingSpendCapacity(mockPolicy);
      expect(remaining.toNumber()).to.equal(500_000_000);
    });
  });

  describe("EscrowManager", () => {
    const escrowManager = new EscrowManager(connection);

    it("should derive escrow PDA correctly", () => {
      const buyer = Keypair.generate().publicKey;
      const seller = Keypair.generate().publicKey;
      const memo = "test-service";
      
      const pda = escrowManager.deriveEscrowAddress(buyer, seller, memo);
      expect(pda).to.be.instanceOf(PublicKey);
    });

    it("should get state label", () => {
      expect(escrowManager.getStateLabel(0)).to.equal("Created");
      expect(escrowManager.getStateLabel(1)).to.equal("Funded");
      expect(escrowManager.getStateLabel(4)).to.equal("Released");
    });
  });

  describe("RegistryManager", () => {
    const registryManager = new RegistryManager(connection);

    it("should validate capability types", () => {
      expect(registryManager.isValidCapabilityType("text-generation")).to.be.true;
      expect(registryManager.isValidCapabilityType("invalid type!")).to.be.false;
    });

    it("should create capability", () => {
      const cap = registryManager.createCapability(
        "text-generation",
        1,
        new BN(1_000_000)
      );
      
      expect(cap.capType).to.equal("text-generation");
      expect(cap.version).to.equal(1);
      expect(cap.pricing.toNumber()).to.equal(1_000_000);
    });

    it("should build metadata JSON", () => {
      const json = registryManager.buildMetadata({
        name: "Test Agent",
        description: "A test agent",
        version: "1.0.0",
      });
      
      const parsed = JSON.parse(json);
      expect(parsed.name).to.equal("Test Agent");
    });
  });

  describe("ReputationManager", () => {
    const reputationManager = new ReputationManager(connection);

    it("should get reputation tier", () => {
      expect(reputationManager.getReputationTier(9500).tier).to.equal("legendary");
      expect(reputationManager.getReputationTier(8500).tier).to.equal("excellent");
      expect(reputationManager.getReputationTier(7000).tier).to.equal("good");
      expect(reputationManager.getReputationTier(5000).tier).to.equal("fair");
    });

    it("should format score as percentage", () => {
      expect(reputationManager.formatScoreAsPercentage(9500)).to.equal("95.00%");
      expect(reputationManager.formatScoreAsPercentage(7543)).to.equal("75.43%");
    });
  });

  describe("X0Client", () => {
    it("should derive all PDAs for an owner", () => {
      const owner = Keypair.generate().publicKey;
      const pdas = client.derivePDAs(owner);
      
      expect(pdas.policy).to.be.instanceOf(PublicKey);
      expect(pdas.registry).to.be.instanceOf(PublicKey);
      expect(pdas.reputation).to.be.instanceOf(PublicKey);
    });

    it("should calculate protocol fee", () => {
      const amount = new BN(1_000_000_000); // 1000 tokens
      const fee = client.getProtocolFee(amount);
      
      // 50 bps = 0.5%
      expect(fee.toNumber()).to.equal(5_000_000);
    });
  });
});
