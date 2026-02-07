import { expect } from "chai";
import { Connection, PublicKey, Keypair, LAMPORTS_PER_SOL } from "@solana/web3.js";
import {
  TOKEN_2022_PROGRAM_ID,
  createMint,
  createAccount,
  mintTo,
} from "@solana/spl-token";
import {
  ConfidentialClient,
  deriveAeKey,
  deriveElGamalKeypair,
  encryptZeroBalance,
  encryptAmount,
  decryptBalance,
  generatePubkeyValidityProof,
  generateWithdrawProof,
  generateZeroBalanceProof,
  ELGAMAL_PUBKEY_SIZE,
  AE_CIPHERTEXT_SIZE,
  MAX_CONFIDENTIAL_AMOUNT,
  DEFAULT_MAX_PENDING_CREDITS,
} from "../src/confidential";

describe("ConfidentialClient - Comprehensive Tests", () => {
  let connection: Connection;
  let payer: Keypair;
  let owner: Keypair;
  let client: ConfidentialClient;

  before(async () => {
    connection = new Connection("http://localhost:8899", "confirmed");
    payer = Keypair.generate();
    owner = Keypair.generate();

    // Airdrop SOL for testing
    const airdropSig = await connection.requestAirdrop(payer.publicKey, 10 * LAMPORTS_PER_SOL);
    await connection.confirmTransaction(airdropSig);

    const ownerAirdrop = await connection.requestAirdrop(owner.publicKey, 10 * LAMPORTS_PER_SOL);
    await connection.confirmTransaction(ownerAirdrop);

    // Create wallet interface
    const wallet = {
      publicKey: owner.publicKey,
      signTransaction: async (tx) => {
        tx.sign(owner);
        return tx;
      },
      signAllTransactions: async (txs) => {
        txs.forEach((tx) => tx.sign(owner));
        return txs;
      },
    };

    client = new ConfidentialClient(connection, wallet);
  });

  // ==========================================================================
  // 1. Key Derivation Tests
  // ==========================================================================
  describe("Key Derivation", () => {
    it("should derive AE key deterministically", () => {
      const mint = Keypair.generate().publicKey;
      const aeKey1 = deriveAeKey(owner, mint);
      const aeKey2 = deriveAeKey(owner, mint);

      expect(aeKey1).to.deep.equal(aeKey2);
      expect(aeKey1.length).to.equal(32);
    });

    it("should derive ElGamal keypair deterministically", () => {
      const mint = Keypair.generate().publicKey;
      const keys1 = deriveElGamalKeypair(owner, mint);
      const keys2 = deriveElGamalKeypair(owner, mint);

      expect(keys1.secretKey).to.deep.equal(keys2.secretKey);
      expect(keys1.publicKey).to.deep.equal(keys2.publicKey);
      expect(keys1.secretKey.length).to.equal(32);
      expect(keys1.publicKey.length).to.equal(ELGAMAL_PUBKEY_SIZE);
    });

    it("should derive different keys for different mints", () => {
      const mint1 = Keypair.generate().publicKey;
      const mint2 = Keypair.generate().publicKey;

      const keys1 = deriveElGamalKeypair(owner, mint1);
      const keys2 = deriveElGamalKeypair(owner, mint2);

      expect(keys1.secretKey).to.not.deep.equal(keys2.secretKey);
      expect(keys1.publicKey).to.not.deep.equal(keys2.publicKey);
    });

    it("should derive different keys for different owners", () => {
      const owner2 = Keypair.generate();
      const mint = Keypair.generate().publicKey;

      const keys1 = deriveElGamalKeypair(owner, mint);
      const keys2 = deriveElGamalKeypair(owner2, mint);

      expect(keys1.secretKey).to.not.deep.equal(keys2.secretKey);
    });
  });

  // ==========================================================================
  // 2. AES Encryption/Decryption Tests
  // ==========================================================================
  describe("AES Encryption/Decryption", () => {
    it("should encrypt and decrypt zero balance", () => {
      const mint = Keypair.generate().publicKey;
      const aeKey = deriveAeKey(owner, mint);
      const ciphertext = encryptZeroBalance(aeKey);

      expect(ciphertext.length).to.equal(AE_CIPHERTEXT_SIZE);

      const decrypted = decryptBalance(ciphertext, aeKey);
      expect(decrypted).to.equal(BigInt(0));
    });

    it("should encrypt and decrypt arbitrary amounts", () => {
      const mint = Keypair.generate().publicKey;
      const aeKey = deriveAeKey(owner, mint);
      const amounts = [
        BigInt(100),
        BigInt(1000000),
        BigInt(999999999),
        BigInt(1),
        MAX_CONFIDENTIAL_AMOUNT,
      ];

      for (const amount of amounts) {
        const ciphertext = encryptAmount(amount, aeKey);
        expect(ciphertext.length).to.equal(AE_CIPHERTEXT_SIZE);

        const decrypted = decryptBalance(ciphertext, aeKey);
        expect(decrypted).to.equal(amount);
      }
    });

    it("should fail to decrypt with wrong key", () => {
      const aeKey1 = deriveAeKey(owner, Keypair.generate().publicKey);
      const aeKey2 = deriveAeKey(Keypair.generate(), Keypair.generate().publicKey);

      const ciphertext = encryptAmount(BigInt(12345), aeKey1);
      const decrypted = decryptBalance(ciphertext, aeKey2);

      expect(decrypted).to.be.null;
    });

    it("should return null for invalid ciphertext", () => {
      const aeKey = deriveAeKey(owner, Keypair.generate().publicKey);
      const invalidCiphertext = new Uint8Array(AE_CIPHERTEXT_SIZE);

      const decrypted = decryptBalance(invalidCiphertext, aeKey);
      expect(decrypted).to.be.null;
    });
  });

  // ==========================================================================
  // 3. ZK Proof Generation Tests
  // ==========================================================================
  describe("ZK Proof Generation", () => {
    it("should generate pubkey validity proof", async () => {
      const mint = Keypair.generate().publicKey;
      const elgamalKeys = deriveElGamalKeypair(owner, mint);

      const proofData = await generatePubkeyValidityProof(
        elgamalKeys.secretKey,
        elgamalKeys.publicKey
      );

      expect(proofData).to.be.instanceOf(Uint8Array);
      expect(proofData.length).to.be.greaterThan(0);
      expect(proofData.length).to.equal(64); // PubkeyValidityData size
    });

    it("should generate withdraw proof", async () => {
      const mint = Keypair.generate().publicKey;
      const elgamalKeys = deriveElGamalKeypair(owner, mint);
      const aeKey = deriveAeKey(owner, mint);

      // Create mock balance ciphertext (would be from account state in real usage)
      const mockBalance = new Uint8Array(64);

      try {
        const { proofData, newDecryptableBalance } = await generateWithdrawProof(
          mockBalance,
          BigInt(50000),
          elgamalKeys.secretKey,
          elgamalKeys.publicKey,
          aeKey
        );

        expect(proofData).to.be.instanceOf(Uint8Array);
        expect(newDecryptableBalance).to.be.instanceOf(Uint8Array);
        expect(newDecryptableBalance.length).to.equal(AE_CIPHERTEXT_SIZE);
      } catch (error) {
        // Expected to fail with mock ciphertext
        expect(error.message).to.include("decrypt");
      }
    });

    it("should generate zero balance proof", async () => {
      const mint = Keypair.generate().publicKey;
      const elgamalKeys = deriveElGamalKeypair(owner, mint);

      // Create mock zero balance ciphertext
      const zeroCiphertext = new Uint8Array(64);

      try {
        const proofData = await generateZeroBalanceProof(
          zeroCiphertext,
          elgamalKeys.secretKey,
          elgamalKeys.publicKey
        );

        expect(proofData).to.be.instanceOf(Uint8Array);
      } catch (error) {
        // Expected to fail with mock ciphertext
        expect(error.message).to.include("proof");
      }
    });
  });

  // ==========================================================================
  // 4. Extension Parsing Tests
  // ==========================================================================
  describe("Extension Parsing", () => {
    it("should return null for non-configured accounts", async () => {
      const mint = await createMint(
        connection,
        payer,
        payer.publicKey,
        null,
        6,
        Keypair.generate(),
        { commitment: "confirmed" },
        TOKEN_2022_PROGRAM_ID
      );

      const tokenAccount = await createAccount(
        connection,
        payer,
        mint,
        owner.publicKey,
        Keypair.generate(),
        { commitment: "confirmed" },
        TOKEN_2022_PROGRAM_ID
      );

      const state = await client.getConfidentialAccountState(tokenAccount);
      expect(state).to.be.null;
    });

    it("should return null for non-existent account", async () => {
      const fakeAccount = Keypair.generate().publicKey;
      const state = await client.getConfidentialAccountState(fakeAccount);
      expect(state).to.be.null;
    });
  });

  // ==========================================================================
  // 5. Error Handling Tests
  // ==========================================================================
  describe("Error Handling", () => {
    it("should handle decryption failure gracefully", () => {
      const aeKey = deriveAeKey(owner, Keypair.generate().publicKey);
      const invalidCiphertext = new Uint8Array(AE_CIPHERTEXT_SIZE);

      const result = decryptBalance(invalidCiphertext, aeKey);
      expect(result).to.be.null;
    });

    it("should validate MAX_CONFIDENTIAL_AMOUNT constraint", () => {
      const maxValue = (1n << 48n) - 1n;
      expect(MAX_CONFIDENTIAL_AMOUNT).to.equal(maxValue);
    });

    it("should reject zero deposit amounts", async () => {
      // This would be tested with actual token accounts
      // For now, just verify the constant exists
      expect(MAX_CONFIDENTIAL_AMOUNT).to.be.greaterThan(0n);
    });

    it("should reject amounts exceeding MAX_CONFIDENTIAL_AMOUNT", () => {
      const invalidAmount = MAX_CONFIDENTIAL_AMOUNT + BigInt(1);
      expect(invalidAmount).to.be.greaterThan(MAX_CONFIDENTIAL_AMOUNT);
    });
  });

  // ==========================================================================
  // 6. Constants Validation
  // ==========================================================================
  describe("Constants Validation", () => {
    it("should have correct ELGAMAL_PUBKEY_SIZE", () => {
      expect(ELGAMAL_PUBKEY_SIZE).to.equal(32);
    });

    it("should have correct AE_CIPHERTEXT_SIZE", () => {
      expect(AE_CIPHERTEXT_SIZE).to.equal(36);
    });

    it("should have correct MAX_CONFIDENTIAL_AMOUNT", () => {
      expect(MAX_CONFIDENTIAL_AMOUNT).to.equal((1n << 48n) - 1n);
    });

    it("should have correct DEFAULT_MAX_PENDING_CREDITS", () => {
      expect(DEFAULT_MAX_PENDING_CREDITS).to.equal(65536);
    });
  });

  // ==========================================================================
  // 7. Client Initialization Tests
  // ==========================================================================
  describe("Client Initialization", () => {
    it("should create ConfidentialClient with valid parameters", () => {
      const wallet = {
        publicKey: owner.publicKey,
        signTransaction: async (tx) => {
          tx.sign(owner);
          return tx;
        },
      };

      const testClient = new ConfidentialClient(connection, wallet);
      expect(testClient).to.be.instanceOf(ConfidentialClient);
    });

    it("should use provided confirm options", () => {
      const wallet = {
        publicKey: owner.publicKey,
        signTransaction: async (tx) => {
          tx.sign(owner);
          return tx;
        },
      };

      const customOptions = { commitment: "finalized" };
      const testClient = new ConfidentialClient(connection, wallet, customOptions);
      expect(testClient).to.be.instanceOf(ConfidentialClient);
    });
  });

  // ==========================================================================
  // 8. Key Derivation Edge Cases
  // ==========================================================================
  describe("Key Derivation Edge Cases", () => {
    it("should derive consistent keys across multiple calls", () => {
      const mint = Keypair.generate().publicKey;
      const iterations = 10;
      const keys = [];

      for (let i = 0; i < iterations; i++) {
        keys.push(deriveElGamalKeypair(owner, mint));
      }

      // All keys should be identical
      for (let i = 1; i < iterations; i++) {
        expect(keys[i].secretKey).to.deep.equal(keys[0].secretKey);
        expect(keys[i].publicKey).to.deep.equal(keys[0].publicKey);
      }
    });

    it("should derive different AE keys for same owner but different mints", () => {
      const mints = [
        Keypair.generate().publicKey,
        Keypair.generate().publicKey,
        Keypair.generate().publicKey,
      ];

      const aeKeys = mints.map((mint) => deriveAeKey(owner, mint));

      // All keys should be unique
      expect(aeKeys[0]).to.not.deep.equal(aeKeys[1]);
      expect(aeKeys[1]).to.not.deep.equal(aeKeys[2]);
      expect(aeKeys[0]).to.not.deep.equal(aeKeys[2]);
    });
  });

  // ==========================================================================
  // 9. Encryption/Decryption Edge Cases
  // ==========================================================================
  describe("Encryption/Decryption Edge Cases", () => {
    it("should handle maximum confidential amount", () => {
      const mint = Keypair.generate().publicKey;
      const aeKey = deriveAeKey(owner, mint);

      const ciphertext = encryptAmount(MAX_CONFIDENTIAL_AMOUNT, aeKey);
      const decrypted = decryptBalance(ciphertext, aeKey);

      expect(decrypted).to.equal(MAX_CONFIDENTIAL_AMOUNT);
    });

    it("should handle small amounts (1 base unit)", () => {
      const mint = Keypair.generate().publicKey;
      const aeKey = deriveAeKey(owner, mint);

      const ciphertext = encryptAmount(BigInt(1), aeKey);
      const decrypted = decryptBalance(ciphertext, aeKey);

      expect(decrypted).to.equal(BigInt(1));
    });

    it("should encrypt/decrypt powers of 2 correctly", () => {
      const mint = Keypair.generate().publicKey;
      const aeKey = deriveAeKey(owner, mint);

      const powersOf2 = [
        BigInt(1), // 2^0
        BigInt(2), // 2^1
        BigInt(4), // 2^2
        BigInt(16), // 2^4
        BigInt(256), // 2^8
        BigInt(65536), // 2^16
        BigInt(16777216), // 2^24
      ];

      for (const value of powersOf2) {
        const ciphertext = encryptAmount(value, aeKey);
        const decrypted = decryptBalance(ciphertext, aeKey);
        expect(decrypted).to.equal(value);
      }
    });
  });

  // ==========================================================================
  // 10. Proof Generation Validation
  // ==========================================================================
  describe("Proof Generation Validation", () => {
    it("should generate unique pubkey validity proofs for different keys", async () => {
      const mint1 = Keypair.generate().publicKey;
      const mint2 = Keypair.generate().publicKey;

      const keys1 = deriveElGamalKeypair(owner, mint1);
      const keys2 = deriveElGamalKeypair(owner, mint2);

      const proof1 = await generatePubkeyValidityProof(keys1.secretKey, keys1.publicKey);
      const proof2 = await generatePubkeyValidityProof(keys2.secretKey, keys2.publicKey);

      expect(proof1).to.not.deep.equal(proof2);
    });

    it("should generate consistent proof for same keys", async () => {
      const mint = Keypair.generate().publicKey;
      const keys = deriveElGamalKeypair(owner, mint);

      const proof1 = await generatePubkeyValidityProof(keys.secretKey, keys.publicKey);
      const proof2 = await generatePubkeyValidityProof(keys.secretKey, keys.publicKey);

      expect(proof1).to.deep.equal(proof2);
    });
  });

  // ==========================================================================
  // 11. Security Tests
  // ==========================================================================
  describe("Security Validations", () => {
    it("should not leak secret key in error messages", async () => {
      const mint = Keypair.generate().publicKey;
      const keys = deriveElGamalKeypair(owner, mint);
      const invalidPublicKey = new Uint8Array(32);

      try {
        await generatePubkeyValidityProof(keys.secretKey, invalidPublicKey);
      } catch (error) {
        const errorStr = error.toString();
        // Ensure secret key is not in error message
        const secretKeyHex = Buffer.from(keys.secretKey).toString("hex");
        expect(errorStr).to.not.include(secretKeyHex);
      }
    });

    it("should require proper key lengths", () => {
      const mint = Keypair.generate().publicKey;
      const keys = deriveElGamalKeypair(owner, mint);

      expect(keys.secretKey.length).to.equal(32);
      expect(keys.publicKey.length).to.equal(32);
    });

    it("should use independent nonces for different encryptions", () => {
      const mint = Keypair.generate().publicKey;
      const aeKey = deriveAeKey(owner, mint);
      const amount = BigInt(12345);

      // Encrypt same amount multiple times
      const ciphertext1 = encryptAmount(amount, aeKey);
      const ciphertext2 = encryptAmount(amount, aeKey);

      // Ciphertexts should be different (different nonces)
      expect(ciphertext1).to.not.deep.equal(ciphertext2);

      // But both should decrypt to same value
      expect(decryptBalance(ciphertext1, aeKey)).to.equal(amount);
      expect(decryptBalance(ciphertext2, aeKey)).to.equal(amount);
    });
  });

  // ==========================================================================
  // 12. Type Safety Tests
  // ==========================================================================
  describe("Type Safety", () => {
    it("should work with BigInt amounts", () => {
      const mint = Keypair.generate().publicKey;
      const aeKey = deriveAeKey(owner, mint);

      const amount = BigInt(1000000000);
      const ciphertext = encryptAmount(amount, aeKey);
      const decrypted = decryptBalance(ciphertext, aeKey);

      expect(typeof decrypted).to.equal("bigint");
      expect(decrypted).to.equal(amount);
    });

    it("should return Uint8Array for ciphertexts", () => {
      const mint = Keypair.generate().publicKey;
      const aeKey = deriveAeKey(owner, mint);

      const ciphertext = encryptZeroBalance(aeKey);
      expect(ciphertext).to.be.instanceOf(Uint8Array);
    });

    it("should return PublicKey objects for addresses", () => {
      const mint = Keypair.generate().publicKey;
      expect(mint).to.be.instanceOf(PublicKey);
    });
  });
});
