import { expect } from "chai";
import { PublicKey, Keypair } from "@solana/web3.js";
import { BN } from "@coral-xyz/anchor";
import {
  calculateProtocolFee,
  amountAfterFee,
  sha256,
  computeMemoHash,
  now,
  isBlinkExpired,
  formatTimestamp,
  deriveAgentPolicyPda,
  deriveEscrowPda,
  deriveRegistryPda,
  deriveReputationPda,
  formatAmount,
  parseAmount,
  validateEndpoint,
  validateCapabilityType,
  buildMerkleRoot,
  generateMerkleProof,
  createBloomFilter,
  checkBloomFilter,
} from "../src/utils";
import { BLINK_EXPIRY_SECONDS } from "../src/constants";

describe("Utility Functions", () => {
  describe("Fee calculations", () => {
    it("should calculate protocol fee correctly", () => {
      const amount = new BN(1_000_000_000); // 1000 tokens
      const fee = calculateProtocolFee(amount);
      
      // 50 bps = 0.5%
      expect(fee.toNumber()).to.equal(5_000_000);
    });

    it("should calculate amount after fee", () => {
      const amount = new BN(1_000_000_000);
      const afterFee = amountAfterFee(amount);
      
      expect(afterFee.toNumber()).to.equal(995_000_000);
    });

    it("should handle zero amount", () => {
      const fee = calculateProtocolFee(new BN(0));
      expect(fee.toNumber()).to.equal(0);
    });
  });

  describe("Hash utilities", () => {
    it("should compute SHA256 hash", () => {
      const hash = sha256("hello world");
      expect(hash).to.have.length(32);
    });

    it("should compute consistent hashes", () => {
      const hash1 = sha256("test");
      const hash2 = sha256("test");
      expect(Buffer.from(hash1).equals(Buffer.from(hash2))).to.be.true;
    });

    it("should compute memo hash", () => {
      const hash = computeMemoHash("service-request-123");
      expect(hash).to.have.length(32);
    });
  });

  describe("Time utilities", () => {
    it("should get current timestamp", () => {
      const timestamp = now();
      const jsTimestamp = Math.floor(Date.now() / 1000);
      expect(timestamp).to.be.approximately(jsTimestamp, 1);
    });

    it("should format timestamp as ISO string", () => {
      const timestamp = 1700000000;
      const formatted = formatTimestamp(timestamp);
      expect(formatted).to.match(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/);
    });
  });

  describe("PDA derivation", () => {
    it("should derive agent policy PDA", () => {
      const owner = Keypair.generate().publicKey;
      const [pda, bump] = deriveAgentPolicyPda(owner);
      
      expect(pda).to.be.instanceOf(PublicKey);
      expect(bump).to.be.a("number");
      expect(bump).to.be.lessThanOrEqual(255);
    });

    it("should derive consistent PDAs", () => {
      const owner = Keypair.generate().publicKey;
      const [pda1] = deriveAgentPolicyPda(owner);
      const [pda2] = deriveAgentPolicyPda(owner);
      
      expect(pda1.equals(pda2)).to.be.true;
    });

    it("should derive escrow PDA", () => {
      const buyer = Keypair.generate().publicKey;
      const seller = Keypair.generate().publicKey;
      const memoHash = sha256("test-memo");
      
      const [pda, bump] = deriveEscrowPda(buyer, seller, memoHash);
      
      expect(pda).to.be.instanceOf(PublicKey);
      expect(bump).to.be.a("number");
    });

    it("should derive registry PDA", () => {
      const agentId = Keypair.generate().publicKey;
      const [pda, bump] = deriveRegistryPda(agentId);
      
      expect(pda).to.be.instanceOf(PublicKey);
      expect(bump).to.be.a("number");
    });

    it("should derive reputation PDA", () => {
      const agentId = Keypair.generate().publicKey;
      const [pda, bump] = deriveReputationPda(agentId);
      
      expect(pda).to.be.instanceOf(PublicKey);
      expect(bump).to.be.a("number");
    });
  });

  describe("Amount formatting", () => {
    it("should format amount with decimals", () => {
      expect(formatAmount(new BN(1_000_000), 6)).to.equal("1");
      expect(formatAmount(new BN(1_500_000), 6)).to.equal("1.5");
      expect(formatAmount(new BN(1_234_567), 6)).to.equal("1.234567");
      expect(formatAmount(new BN(500_000), 6)).to.equal("0.5");
    });

    it("should parse amount string", () => {
      expect(parseAmount("1", 6).toNumber()).to.equal(1_000_000);
      expect(parseAmount("1.5", 6).toNumber()).to.equal(1_500_000);
      expect(parseAmount("0.001", 6).toNumber()).to.equal(1_000);
      expect(parseAmount("100.123456", 6).toNumber()).to.equal(100_123_456);
    });

    it("should round parse to decimals", () => {
      // "1.1234567890" should be truncated to 6 decimals
      expect(parseAmount("1.1234567890", 6).toNumber()).to.equal(1_123_456);
    });
  });

  describe("Validation", () => {
    it("should validate endpoints", () => {
      expect(() => validateEndpoint("https://api.example.com")).to.not.throw();
      expect(() => validateEndpoint("http://localhost:3000")).to.not.throw();
      expect(() => validateEndpoint("")).to.throw("empty");
      expect(() => validateEndpoint("ftp://invalid.com")).to.throw("http");
    });

    it("should validate capability types", () => {
      expect(() => validateCapabilityType("text-generation")).to.not.throw();
      expect(() => validateCapabilityType("code-execution")).to.not.throw();
      expect(() => validateCapabilityType("")).to.throw("empty");
      expect(() => validateCapabilityType("invalid type!")).to.throw("alphanumeric");
    });
  });

  describe("Merkle tree", () => {
    it("should build Merkle root from addresses", () => {
      const addresses = [
        Keypair.generate().publicKey,
        Keypair.generate().publicKey,
        Keypair.generate().publicKey,
      ];
      
      const root = buildMerkleRoot(addresses);
      expect(root).to.have.length(32);
    });

    it("should return zero root for empty list", () => {
      const root = buildMerkleRoot([]);
      expect(root).to.have.length(32);
      expect(root.every((b) => b === 0)).to.be.true;
    });

    it("should generate consistent roots", () => {
      const addresses = [
        Keypair.generate().publicKey,
        Keypair.generate().publicKey,
      ];
      
      const root1 = buildMerkleRoot(addresses);
      const root2 = buildMerkleRoot(addresses);
      
      expect(Buffer.from(root1).equals(Buffer.from(root2))).to.be.true;
    });

    it("should generate valid Merkle proof", () => {
      const addresses = [
        Keypair.generate().publicKey,
        Keypair.generate().publicKey,
        Keypair.generate().publicKey,
        Keypair.generate().publicKey,
      ];
      
      const proof = generateMerkleProof(addresses, addresses[2]);
      expect(proof).to.not.be.null;
      expect(proof!.length).to.be.greaterThan(0);
    });

    it("should return null proof for non-member", () => {
      const addresses = [Keypair.generate().publicKey];
      const nonMember = Keypair.generate().publicKey;
      
      const proof = generateMerkleProof(addresses, nonMember);
      expect(proof).to.be.null;
    });
  });

  describe("Bloom filter", () => {
    it("should create Bloom filter", () => {
      const addresses = [
        Keypair.generate().publicKey,
        Keypair.generate().publicKey,
        Keypair.generate().publicKey,
      ];
      
      const filter = createBloomFilter(addresses, 512, 7);
      expect(filter).to.have.length(512);
    });

    it("should check membership (possibly)", () => {
      const addresses = [
        Keypair.generate().publicKey,
        Keypair.generate().publicKey,
      ];
      
      const filter = createBloomFilter(addresses, 512, 7);
      
      // Members should always return true
      expect(checkBloomFilter(addresses[0], filter, 7)).to.be.true;
      expect(checkBloomFilter(addresses[1], filter, 7)).to.be.true;
    });

    it("should have low false positive rate", () => {
      const members = Array.from({ length: 100 }, () => Keypair.generate().publicKey);
      const filter = createBloomFilter(members, 4096, 7);
      
      // Check 100 non-members
      let falsePositives = 0;
      for (let i = 0; i < 100; i++) {
        const nonMember = Keypair.generate().publicKey;
        if (checkBloomFilter(nonMember, filter, 7)) {
          falsePositives++;
        }
      }
      
      // With these parameters, false positive rate should be < 10%
      expect(falsePositives).to.be.lessThan(10);
    });
  });
});
