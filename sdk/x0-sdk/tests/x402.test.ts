import { expect } from "chai";
import { PublicKey, Keypair } from "@solana/web3.js";
import { BN } from "@coral-xyz/anchor";
import {
  parseX402Response,
  buildX402Header,
  buildX402ResponseHeaders,
  buildPaymentProofHeader,
  buildPaymentHeaders,
  generatePaymentReceipt,
} from "../src/x402";

describe("x402 Protocol", () => {
  describe("parseX402Response", () => {
    it("should parse valid x402 response", () => {
      const recipient = Keypair.generate().publicKey;
      const amount = new BN(1_000_000);
      
      const header = buildX402Header({
        recipient,
        amount,
        resource: "/api/generate",
        memo: "Text generation",
      });

      const result = parseX402Response(402, {
        "X-Accept-Payment": header,
      });

      expect(result).to.not.be.null;
      // parseX402Response returns strings, not PublicKey/BN
      expect(result!.recipient).to.equal(recipient.toBase58());
      expect(result!.amount).to.equal(amount.toString());
      // memo becomes memoHash in the response
      expect(result!.memoHash).to.equal("Text generation");
    });

    it("should return null for non-402 status", () => {
      const result = parseX402Response(200, {});
      expect(result).to.be.null;
    });

    it("should return null for missing header", () => {
      const result = parseX402Response(402, {});
      expect(result).to.be.null;
    });

    it("should parse escrow parameters", () => {
      const recipient = Keypair.generate().publicKey;
      const arbiter = Keypair.generate().publicKey;
      
      const header = buildX402Header({
        recipient,
        amount: new BN(5_000_000),
        resource: "/api/service",
        escrow: {
          useEscrow: true,
          deliveryTimeout: 3600,
          autoReleaseDelay: 86400,
          arbiter,
        },
      });

      const result = parseX402Response(402, {
        "x-accept-payment": header, // lowercase header name
      });

      expect(result).to.not.be.null;
      expect(result!.escrow).to.not.be.undefined;
      expect(result!.escrow!.deliveryTimeout).to.equal(3600);
      expect(result!.escrow!.autoReleaseDelay).to.equal(86400);
      // arbiter is returned as a PublicKey after parsing
      expect(result!.escrow!.arbiter!.toBase58()).to.equal(arbiter.toBase58());
    });
  });

  describe("buildX402ResponseHeaders", () => {
    it("should build complete response headers", () => {
      const recipient = Keypair.generate().publicKey;
      
      const headers = buildX402ResponseHeaders({
        recipient,
        amount: new BN(1_000_000),
        resource: "/api/test",
      });

      // buildX402ResponseHeaders returns an X402Header object with raw and request
      expect(headers.raw).to.be.a("string");
      expect(headers.request).to.not.be.undefined;
      expect(headers.request.recipient).to.equal(recipient.toBase58());
      expect(headers.request.amount).to.equal("1000000");
    });
  });

  describe("Payment proof", () => {
    it("should build payment proof header", () => {
      const payer = Keypair.generate().publicKey;
      const signature = "5KtP" + "a".repeat(84); // Mock signature
      
      const header = buildPaymentProofHeader(signature, 12345, payer);
      
      // Should be base64 encoded
      expect(header).to.be.a("string");
      
      // Decode and verify
      const decoded = JSON.parse(Buffer.from(header, "base64").toString());
      expect(decoded.signature).to.equal(signature);
      expect(decoded.slot).to.equal(12345);
      expect(decoded.payer).to.equal(payer.toBase58());
      expect(decoded.timestamp).to.be.a("number");
    });

    it("should build payment headers", () => {
      const payer = Keypair.generate().publicKey;
      const signature = "5KtP" + "b".repeat(84);
      
      const headers = buildPaymentHeaders(signature, 12345, payer);

      expect(headers["X-Payment-Proof"]).to.be.a("string");
      expect(headers["X-Payment-Version"]).to.equal("x0-01-v1");
    });
  });

  describe("Payment receipt", () => {
    it("should generate payment receipt", () => {
      const payer = Keypair.generate().publicKey;
      const recipient = Keypair.generate().publicKey;
      const signature = "5KtP" + "c".repeat(84);
      
      const receipt = generatePaymentReceipt({
        signature,
        slot: 12345,
        payer,
        recipient,
        amount: new BN(1_000_000),
        resource: "/api/generate",
      });

      // PaymentReceipt has string fields
      expect(receipt.signature).to.equal(signature);
      expect(receipt.slot).to.equal(12345);
      expect(receipt.recipient).to.equal(recipient.toBase58());
      expect(receipt.amount).to.equal("1000000");
      expect(receipt.memoHash).to.equal("/api/generate");
      expect(receipt.blockTime).to.be.a("number");
      expect(receipt.usedEscrow).to.be.false;
    });

    it("should generate unique signatures for different receipts", () => {
      const payer = Keypair.generate().publicKey;
      const recipient = Keypair.generate().publicKey;
      
      const receipt1 = generatePaymentReceipt({
        signature: "sig1" + "a".repeat(84),
        slot: 1,
        payer,
        recipient,
        amount: new BN(1_000_000),
        resource: "/api/a",
      });

      const receipt2 = generatePaymentReceipt({
        signature: "sig2" + "b".repeat(84),
        slot: 2,
        payer,
        recipient,
        amount: new BN(1_000_000),
        resource: "/api/b",
      });

      // Receipts are unique by their signature
      expect(receipt1.signature).to.not.equal(receipt2.signature);
      expect(receipt1.slot).to.not.equal(receipt2.slot);
    });
  });
});
