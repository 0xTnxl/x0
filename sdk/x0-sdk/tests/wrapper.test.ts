import { expect } from "chai";
import { Connection, PublicKey, Keypair } from "@solana/web3.js";
import { TOKEN_PROGRAM_ID } from "@solana/spl-token";
import { BN } from "@coral-xyz/anchor";
import { WrapperClient } from "../src/wrapper";

describe("WrapperClient", () => {
  let connection: Connection;
  let client: WrapperClient;
  
  // Known USDC mint for testing
  const usdcMint = new PublicKey("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v");

  before(() => {
    connection = new Connection("http://localhost:8899", "confirmed");
    client = new WrapperClient(connection);
  });

  describe("PDA Derivation", () => {
    it("should derive config PDA correctly", () => {
      const [configPda, bump] = client.deriveConfigPda();
      expect(configPda).to.be.instanceOf(PublicKey);
      expect(bump).to.be.a("number");
      expect(bump).to.be.lessThanOrEqual(255);
    });

    it("should derive stats PDA correctly", () => {
      const [statsPda, bump] = client.deriveStatsPda();
      expect(statsPda).to.be.instanceOf(PublicKey);
      expect(bump).to.be.a("number");
    });

    it("should derive reserve PDA correctly", () => {
      const [reservePda, bump] = client.deriveReservePda(usdcMint);
      expect(reservePda).to.be.instanceOf(PublicKey);
      expect(bump).to.be.a("number");
    });

    it("should derive wrapper mint PDA correctly", () => {
      const [mintPda, bump] = client.deriveWrapperMintPda(usdcMint);
      expect(mintPda).to.be.instanceOf(PublicKey);
      expect(bump).to.be.a("number");
    });

    it("should derive mint authority PDA correctly", () => {
      const [wrapperMint] = client.deriveWrapperMintPda(usdcMint);
      const [authorityPda, bump] = client.deriveMintAuthorityPda(wrapperMint);
      expect(authorityPda).to.be.instanceOf(PublicKey);
      expect(bump).to.be.a("number");
    });

    it("should derive consistent PDAs", () => {
      const [pda1] = client.deriveConfigPda();
      const [pda2] = client.deriveConfigPda();
      expect(pda1.equals(pda2)).to.be.true;
    });
  });

  describe("Fee Calculations", () => {
    it("should calculate redemption fee correctly", () => {
      const amount = new BN(1_000_000); // 1 USDC
      const feeBps = 50; // 0.5%
      
      const [fee, payout] = client.calculateRedemptionFee(amount, feeBps);
      
      expect(fee.toNumber()).to.equal(5_000); // 0.5% of 1_000_000
      expect(payout.toNumber()).to.equal(995_000);
      expect(fee.add(payout).eq(amount)).to.be.true;
    });

    it("should handle zero fee", () => {
      const amount = new BN(1_000_000);
      const feeBps = 0;
      
      const [fee, payout] = client.calculateRedemptionFee(amount, feeBps);
      
      expect(fee.toNumber()).to.equal(0);
      expect(payout.toNumber()).to.equal(1_000_000);
    });

    it("should handle high fee", () => {
      const amount = new BN(1_000_000);
      const feeBps = 500; // 5%
      
      const [fee, payout] = client.calculateRedemptionFee(amount, feeBps);
      
      expect(fee.toNumber()).to.equal(50_000);
      expect(payout.toNumber()).to.equal(950_000);
    });
  });

  describe("Reserve Ratio", () => {
    it("should calculate reserve ratio correctly", () => {
      const reserve = new BN(1_000_000);
      const supply = new BN(1_000_000);
      
      const ratio = client.calculateReserveRatio(reserve, supply);
      expect(ratio).to.equal(10000); // 1.0
    });

    it("should handle over-collateralized reserve", () => {
      const reserve = new BN(1_200_000);
      const supply = new BN(1_000_000);
      
      const ratio = client.calculateReserveRatio(reserve, supply);
      expect(ratio).to.equal(12000); // 1.2
    });

    it("should handle under-collateralized reserve", () => {
      const reserve = new BN(800_000);
      const supply = new BN(1_000_000);
      
      const ratio = client.calculateReserveRatio(reserve, supply);
      expect(ratio).to.equal(8000); // 0.8
    });

    it("should return 10000 for zero supply", () => {
      const reserve = new BN(1_000_000);
      const supply = new BN(0);
      
      const ratio = client.calculateReserveRatio(reserve, supply);
      expect(ratio).to.equal(10000); // Default 1.0
    });

    it("should detect healthy reserve", () => {
      const reserve = new BN(1_000_000);
      const supply = new BN(1_000_000);
      
      expect(client.isReserveHealthy(reserve, supply)).to.be.true;
    });

    it("should detect unhealthy reserve", () => {
      const reserve = new BN(900_000);
      const supply = new BN(1_000_000);
      
      expect(client.isReserveHealthy(reserve, supply)).to.be.false;
    });
  });

  describe("Instruction Building", () => {
    it("should build deposit and mint instruction", () => {
      const user = Keypair.generate().publicKey;
      const amount = new BN(1_000_000);
      
      const ix = client.buildDepositAndMintInstruction(
        user,
        amount,
        usdcMint,
        TOKEN_PROGRAM_ID
      );

      expect(ix).to.not.be.null;
      expect(ix.programId.toBase58()).to.be.a("string");
      expect(ix.keys.length).to.be.greaterThan(0);
      expect(ix.data.length).to.be.greaterThan(0);
      
      // First key should be the user (signer)
      expect(ix.keys[0].isSigner).to.be.true;
      expect(ix.keys[0].isWritable).to.be.true;
      expect(ix.keys[0].pubkey.equals(user)).to.be.true;
    });

    it("should build burn and redeem instruction", () => {
      const user = Keypair.generate().publicKey;
      const amount = new BN(1_000_000);
      
      const ix = client.buildBurnAndRedeemInstruction(
        user,
        amount,
        usdcMint,
        TOKEN_PROGRAM_ID
      );

      expect(ix).to.not.be.null;
      expect(ix.programId.toBase58()).to.be.a("string");
      expect(ix.keys.length).to.be.greaterThan(0);
      expect(ix.data.length).to.be.greaterThan(0);
      
      // First key should be the user (signer)
      expect(ix.keys[0].isSigner).to.be.true;
      expect(ix.keys[0].isWritable).to.be.true;
      expect(ix.keys[0].pubkey.equals(user)).to.be.true;
    });

    it("should include correct data encoding", () => {
      const user = Keypair.generate().publicKey;
      const amount = new BN(1_000_000);
      
      const ix = client.buildDepositAndMintInstruction(
        user,
        amount,
        usdcMint,
        TOKEN_PROGRAM_ID
      );

      // Data should be discriminator (8 bytes) + amount (8 bytes)
      expect(ix.data.length).to.equal(16);
      
      // Extract amount from instruction data
      const amountBytes = ix.data.slice(8, 16);
      const extractedAmount = new BN(amountBytes, "le");
      expect(extractedAmount.eq(amount)).to.be.true;
    });
  });
});
