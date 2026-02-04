import { expect } from "chai";
import { Keypair } from "@solana/web3.js";
import { BN } from "@coral-xyz/anchor";
import {
  generateTransferBlink,
  generateEscrowReleaseBlink,
  generatePolicyUpdateBlink,
  generateBlinkUrl,
  parseBlinkFromUrl,
  isBlinkExpiredFromBlink,
  validateBlink,
  buildActionsMetadata,
} from "../src/blink";

describe("Blink Generation", () => {
  describe("generateTransferBlink", () => {
    it("should generate a valid transfer approval Blink", () => {
      const blink = generateTransferBlink({
        policyId: Keypair.generate().publicKey,
        owner: Keypair.generate().publicKey,
        recipient: Keypair.generate().publicKey,
        amount: new BN(1_000_000),
        description: "Pay for AI service",
        memo: "service-request-123",
      });

      expect(blink.id).to.have.length(16);
      expect(blink.type).to.equal("transfer_approval");
      expect(blink.title).to.equal("Approve Agent Transfer");
      expect(blink.actions).to.have.length(2);
      expect(blink.actions[0].label).to.equal("Approve");
      expect(blink.actions[1].label).to.equal("Reject");
    });

    it("should set expiration correctly", () => {
      const now = Math.floor(Date.now() / 1000);
      const expiresIn = 600; // 10 minutes

      const blink = generateTransferBlink({
        policyId: Keypair.generate().publicKey,
        owner: Keypair.generate().publicKey,
        recipient: Keypair.generate().publicKey,
        amount: new BN(1_000_000),
        description: "Test",
        expiresIn,
      });

      expect(blink.expiresAt).to.be.approximately(now + expiresIn, 2);
    });
  });

  describe("generateEscrowReleaseBlink", () => {
    it("should generate a valid escrow release Blink", () => {
      const blink = generateEscrowReleaseBlink({
        escrowId: Keypair.generate().publicKey,
        buyer: Keypair.generate().publicKey,
        seller: Keypair.generate().publicKey,
        amount: new BN(5_000_000),
        serviceMemo: "Code review completed",
      });

      expect(blink.type).to.equal("escrow_release");
      expect(blink.actions).to.have.length(2);
      expect(blink.actions[0].label).to.equal("Release Funds");
      expect(blink.actions[1].label).to.equal("Dispute");
    });
  });

  describe("generatePolicyUpdateBlink", () => {
    it("should generate a policy update Blink with changes", () => {
      const blink = generatePolicyUpdateBlink({
        policyId: Keypair.generate().publicKey,
        owner: Keypair.generate().publicKey,
        changes: {
          spendLimit: new BN(10_000_000_000),
          privacyLevel: 2,
        },
      });

      expect(blink.type).to.equal("policy_update");
      expect(blink.description).to.include("Spend limit");
      expect(blink.description).to.include("Privacy: Private");
    });
  });

  describe("URL handling", () => {
    it("should generate and parse Blink URL", () => {
      const original = generateTransferBlink({
        policyId: Keypair.generate().publicKey,
        owner: Keypair.generate().publicKey,
        recipient: Keypair.generate().publicKey,
        amount: new BN(1_000_000),
        description: "Test",
      });

      const url = generateBlinkUrl(original, "https://app.x0.io");
      expect(url).to.include("https://app.x0.io/blink/");
      expect(url).to.include("data=");

      // Extract data parameter
      const urlObj = new URL(url);
      const data = urlObj.searchParams.get("data");
      expect(data).to.not.be.null;

      const parsed = parseBlinkFromUrl(data!);
      expect(parsed).to.not.be.null;
      expect(parsed!.id).to.equal(original.id);
      expect(parsed!.type).to.equal(original.type);
    });
  });

  describe("validation", () => {
    it("should validate Blink structure", () => {
      const valid = generateTransferBlink({
        policyId: Keypair.generate().publicKey,
        owner: Keypair.generate().publicKey,
        recipient: Keypair.generate().publicKey,
        amount: new BN(1_000_000),
        description: "Test",
      });

      expect(validateBlink(valid)).to.be.true;
      expect(validateBlink(null)).to.be.false;
      expect(validateBlink({})).to.be.false;
      expect(validateBlink({ id: "test" })).to.be.false;
    });

    it("should detect expired Blinks", () => {
      const blink = generateTransferBlink({
        policyId: Keypair.generate().publicKey,
        owner: Keypair.generate().publicKey,
        recipient: Keypair.generate().publicKey,
        amount: new BN(1_000_000),
        description: "Test",
        expiresIn: -100, // Expired 100 seconds ago
      });

      expect(isBlinkExpiredFromBlink(blink)).to.be.true;
    });

    it("should not flag non-expired Blinks", () => {
      const blink = generateTransferBlink({
        policyId: Keypair.generate().publicKey,
        owner: Keypair.generate().publicKey,
        recipient: Keypair.generate().publicKey,
        amount: new BN(1_000_000),
        description: "Test",
        expiresIn: 600, // 10 minutes
      });

      expect(isBlinkExpiredFromBlink(blink)).to.be.false;
    });
  });

  describe("Actions metadata", () => {
    it("should build Solana Actions metadata", () => {
      const blink = generateTransferBlink({
        policyId: Keypair.generate().publicKey,
        owner: Keypair.generate().publicKey,
        recipient: Keypair.generate().publicKey,
        amount: new BN(1_000_000),
        description: "Approve payment for AI service",
      });

      const metadata = buildActionsMetadata(blink);

      expect(metadata.title).to.equal("Approve Agent Transfer");
      expect(metadata.description).to.equal("Approve payment for AI service");
      expect(metadata.disabled).to.be.false;
      expect(metadata.links?.actions).to.have.length(2);
    });

    it("should mark expired Blink as disabled", () => {
      const blink = generateTransferBlink({
        policyId: Keypair.generate().publicKey,
        owner: Keypair.generate().publicKey,
        recipient: Keypair.generate().publicKey,
        amount: new BN(1_000_000),
        description: "Test",
        expiresIn: -100,
      });

      const metadata = buildActionsMetadata(blink);
      expect(metadata.disabled).to.be.true;
      expect(metadata.error?.message).to.equal("This action has expired");
    });
  });
});
