/**
 * Tests for x0 Bridge SDK module
 *
 * Covers:
 * - Locked event parsing from SP1 public inputs
 * - Event validation against BridgeMessage
 * - SP1 public inputs serialization/deserialization roundtrip
 * - PDA derivation consistency
 * - Edge cases (missing events, wrong signatures, truncated data)
 */

import { expect } from "chai";
import { PublicKey } from "@solana/web3.js";
import BN from "bn.js";
import {
  BridgeClient,
  BridgeMessage,
  BridgeMessageStatus,
  SP1PublicInputs,
  SP1EventLog,
  findLockedEvent,
  validateProofAgainstMessage,
} from "../src/bridge";
import {
  LOCKED_EVENT_SIGNATURE,
  TRANSFER_EVENT_SIGNATURE,
  HYPERLANE_DOMAIN_BASE,
  MAX_DAILY_BRIDGE_INFLOW,
  MIN_BRIDGE_AMOUNT,
  MAX_BRIDGE_AMOUNT_PER_TX,
  EVM_ADDRESS_SIZE,
  EVM_HASH_SIZE,
  BRIDGE_PROOF_VALIDITY_SECONDS,
  BRIDGE_ADMIN_TIMELOCK_SECONDS,
} from "../src/constants";

// ============================================================================
// Test Helpers
// ============================================================================

/** Build a test EVM contract address */
function testContract(): Uint8Array {
  const addr = new Uint8Array(20);
  addr[19] = 0x42;
  return addr;
}

/** Build a test Solana pubkey */
function testRecipient(): PublicKey {
  return new PublicKey(Buffer.alloc(32, 0xaa));
}

/** Encode a u64 value as a 32-byte big-endian uint256 word (number array) */
function encodeUint256(val: number | BN): number[] {
  const bn = BN.isBN(val) ? val : new BN(val);
  const word = new Array(32).fill(0);
  const bytes = bn.toArray("be");
  // Right-align in 32 bytes
  for (let i = 0; i < bytes.length; i++) {
    word[32 - bytes.length + i] = bytes[i];
  }
  return word;
}

/** Build a valid Locked event log for testing */
function makeLockedEvent(
  contract: Uint8Array,
  recipient: PublicKey,
  amount: number,
  nonce: number
): SP1EventLog {
  // topics[0] = LOCKED_EVENT_SIGNATURE
  const topic0 = Array.from(LOCKED_EVENT_SIGNATURE);
  // topics[1] = sender address (left-padded to 32 bytes)
  const topic1 = new Array(32).fill(0);
  topic1[31] = 0x11;
  // topics[2] = solanaRecipient (32 bytes)
  const topic2 = Array.from(recipient.toBytes());

  // data = abi.encode(amount, nonce, messageId)
  const data = [
    ...encodeUint256(amount),   // data[0..32]
    ...encodeUint256(nonce),    // data[32..64]
    ...new Array(32).fill(0xbb), // data[64..96] = messageId
  ];

  return {
    contract_address: Array.from(contract),
    topics: [topic0, topic1, topic2],
    data,
  };
}

/** Build a minimal BridgeMessage for testing */
function makeBridgeMessage(
  recipient: PublicKey,
  amount: number,
  txHash?: Uint8Array
): BridgeMessage {
  return {
    version: 1,
    messageId: new Uint8Array(32),
    originDomain: HYPERLANE_DOMAIN_BASE,
    sender: new Uint8Array(32),
    recipient,
    amount: new BN(amount),
    receivedAt: new BN(0),
    status: BridgeMessageStatus.Received,
    evmTxHash: txHash ?? new Uint8Array(32),
    nonce: new BN(1),
    bump: 0,
  };
}

/** Build minimal SP1PublicInputs for testing */
function makePublicInputs(
  eventLogs: SP1EventLog[],
  txHash?: number[],
  success = true
): SP1PublicInputs {
  return {
    block_hash: new Array(32).fill(0),
    block_number: 12345678,
    tx_hash: txHash ?? new Array(32).fill(0),
    from: new Array(20).fill(0x11),
    to: new Array(20).fill(0x42),
    value: 0,
    success,
    event_logs: eventLogs,
  };
}

// ============================================================================
// Tests
// ============================================================================

describe("Bridge SDK", () => {
  // --------------------------------------------------------------------------
  // Constants
  // --------------------------------------------------------------------------

  describe("Constants", () => {
    it("LOCKED_EVENT_SIGNATURE should be 32 bytes", () => {
      expect(LOCKED_EVENT_SIGNATURE.length).to.equal(32);
    });

    it("TRANSFER_EVENT_SIGNATURE should be 32 bytes", () => {
      expect(TRANSFER_EVENT_SIGNATURE.length).to.equal(32);
    });

    it("LOCKED and TRANSFER signatures should differ", () => {
      expect(
        Buffer.from(LOCKED_EVENT_SIGNATURE).equals(
          Buffer.from(TRANSFER_EVENT_SIGNATURE)
        )
      ).to.be.false;
    });

    it("bridge constants should have correct values", () => {
      expect(HYPERLANE_DOMAIN_BASE).to.equal(8453);
      expect(EVM_ADDRESS_SIZE).to.equal(20);
      expect(EVM_HASH_SIZE).to.equal(32);
      expect(BRIDGE_PROOF_VALIDITY_SECONDS).to.equal(600);
      expect(BRIDGE_ADMIN_TIMELOCK_SECONDS).to.equal(172_800);
      expect(MIN_BRIDGE_AMOUNT.toNumber()).to.equal(10_000_000);
      expect(MAX_BRIDGE_AMOUNT_PER_TX.toString()).to.equal("100000000000");
      expect(MAX_DAILY_BRIDGE_INFLOW.toString()).to.equal("5000000000000");
    });
  });

  // --------------------------------------------------------------------------
  // findLockedEvent
  // --------------------------------------------------------------------------

  describe("findLockedEvent", () => {
    it("should find a valid Locked event", () => {
      const contract = testContract();
      const recipient = testRecipient();
      const event = makeLockedEvent(contract, recipient, 1_000_000, 1);

      const result = findLockedEvent([event], [contract]);
      expect(result).to.not.be.null;
      expect(result!.amount.toNumber()).to.equal(1_000_000);
      expect(
        Buffer.from(result!.solanaRecipient).equals(recipient.toBuffer())
      ).to.be.true;
    });

    it("should return null for empty event logs", () => {
      const contract = testContract();
      const result = findLockedEvent([], [contract]);
      expect(result).to.be.null;
    });

    it("should reject events with wrong signature", () => {
      const contract = testContract();
      const recipient = testRecipient();
      const event = makeLockedEvent(contract, recipient, 1_000_000, 1);
      // Replace with Transfer signature
      event.topics[0] = Array.from(TRANSFER_EVENT_SIGNATURE);

      const result = findLockedEvent([event], [contract]);
      expect(result).to.be.null;
    });

    it("should reject events from unauthorized contracts", () => {
      const allowed = testContract();
      const unauthorized = new Uint8Array(20);
      unauthorized[19] = 0xff;
      const recipient = testRecipient();
      const event = makeLockedEvent(unauthorized, recipient, 1_000_000, 1);

      const result = findLockedEvent([event], [allowed]);
      expect(result).to.be.null;
    });

    it("should reject events with too few topics", () => {
      const contract = testContract();
      const event: SP1EventLog = {
        contract_address: Array.from(contract),
        topics: [Array.from(LOCKED_EVENT_SIGNATURE), new Array(32).fill(0)],
        data: new Array(96).fill(0),
      };

      const result = findLockedEvent([event], [contract]);
      expect(result).to.be.null;
    });

    it("should reject events with short data", () => {
      const contract = testContract();
      const recipient = testRecipient();
      const event = makeLockedEvent(contract, recipient, 1_000_000, 1);
      event.data = event.data.slice(0, 64); // Truncate to 64 bytes (need 96)

      const result = findLockedEvent([event], [contract]);
      expect(result).to.be.null;
    });

    it("should find correct event among multiple logs", () => {
      const contract = testContract();
      const recipient = testRecipient();

      // Transfer event (wrong type)
      const transferEvent: SP1EventLog = {
        contract_address: Array.from(contract),
        topics: [
          Array.from(TRANSFER_EVENT_SIGNATURE),
          new Array(32).fill(0x11),
          new Array(32).fill(0x22),
        ],
        data: encodeUint256(999),
      };

      // Valid Locked event
      const lockedEvent = makeLockedEvent(contract, recipient, 5_000_000, 7);

      const result = findLockedEvent(
        [transferEvent, lockedEvent],
        [contract]
      );
      expect(result).to.not.be.null;
      expect(result!.amount.toNumber()).to.equal(5_000_000);
      expect(result!.nonce.toNumber()).to.equal(7);
    });

    it("should parse messageId from event data", () => {
      const contract = testContract();
      const recipient = testRecipient();
      const event = makeLockedEvent(contract, recipient, 100, 1);

      const result = findLockedEvent([event], [contract]);
      expect(result).to.not.be.null;
      // messageId is 32 bytes of 0xBB (set in makeLockedEvent)
      expect(Buffer.from(result!.messageId).every((b) => b === 0xbb)).to.be
        .true;
    });

    it("should extract sender address from topics[1]", () => {
      const contract = testContract();
      const recipient = testRecipient();
      const event = makeLockedEvent(contract, recipient, 100, 1);

      const result = findLockedEvent([event], [contract]);
      expect(result).to.not.be.null;
      // Sender is right-aligned: last byte is 0x11
      expect(result!.sender[19]).to.equal(0x11);
      expect(result!.sender.length).to.equal(20);
    });
  });

  // --------------------------------------------------------------------------
  // validateProofAgainstMessage
  // --------------------------------------------------------------------------

  describe("validateProofAgainstMessage", () => {
    it("should pass for valid matching proof and message", () => {
      const contract = testContract();
      const recipient = testRecipient();
      const amount = 1_000_000;
      const event = makeLockedEvent(contract, recipient, amount, 1);
      const inputs = makePublicInputs([event]);
      const msg = makeBridgeMessage(recipient, amount);

      const result = validateProofAgainstMessage(inputs, msg, [contract]);
      expect(result.valid).to.be.true;
      expect(result.error).to.be.undefined;
    });

    it("should fail on tx_hash mismatch", () => {
      const contract = testContract();
      const recipient = testRecipient();
      const event = makeLockedEvent(contract, recipient, 1_000_000, 1);
      const inputs = makePublicInputs([event], new Array(32).fill(0xaa));
      const msg = makeBridgeMessage(
        recipient,
        1_000_000,
        new Uint8Array(32).fill(0xbb) // Different tx hash
      );

      const result = validateProofAgainstMessage(inputs, msg, [contract]);
      expect(result.valid).to.be.false;
      expect(result.error).to.include("tx_hash mismatch");
    });

    it("should fail on unsuccessful EVM transaction", () => {
      const contract = testContract();
      const recipient = testRecipient();
      const event = makeLockedEvent(contract, recipient, 1_000_000, 1);
      const inputs = makePublicInputs([event], undefined, false);
      const msg = makeBridgeMessage(recipient, 1_000_000);

      const result = validateProofAgainstMessage(inputs, msg, [contract]);
      expect(result.valid).to.be.false;
      expect(result.error).to.include("not successful");
    });

    it("should fail when no Locked event found", () => {
      const contract = testContract();
      const recipient = testRecipient();
      const inputs = makePublicInputs([]); // No events
      const msg = makeBridgeMessage(recipient, 1_000_000);

      const result = validateProofAgainstMessage(inputs, msg, [contract]);
      expect(result.valid).to.be.false;
      expect(result.error).to.include("No Locked event");
    });

    it("should fail on recipient mismatch", () => {
      const contract = testContract();
      const legitRecipient = testRecipient();
      const attacker = new PublicKey(Buffer.alloc(32, 0xee));
      const amount = 1_000_000;

      // Event has legit recipient, message has attacker
      const event = makeLockedEvent(contract, legitRecipient, amount, 1);
      const inputs = makePublicInputs([event]);
      const msg = makeBridgeMessage(attacker, amount);

      const result = validateProofAgainstMessage(inputs, msg, [contract]);
      expect(result.valid).to.be.false;
      expect(result.error).to.include("Recipient mismatch");
    });

    it("should fail on amount mismatch", () => {
      const contract = testContract();
      const recipient = testRecipient();

      // Event says 1 USDC, message says 1M USDC
      const event = makeLockedEvent(contract, recipient, 1_000_000, 1);
      const inputs = makePublicInputs([event]);
      const msg = makeBridgeMessage(recipient, 1_000_000_000_000);

      const result = validateProofAgainstMessage(inputs, msg, [contract]);
      expect(result.valid).to.be.false;
      expect(result.error).to.include("Amount mismatch");
    });

    it("should block amount inflation attack ($1 lock → $1M claim)", () => {
      const contract = testContract();
      const attacker = new PublicKey(Buffer.alloc(32, 0xee));

      // Real event: $1 USDC locked
      const event = makeLockedEvent(contract, attacker, 1_000_000, 1);
      const inputs = makePublicInputs([event]);

      // Forged message: $1M USDC
      const msg = makeBridgeMessage(attacker, 1_000_000_000_000);

      const result = validateProofAgainstMessage(inputs, msg, [contract]);
      expect(result.valid).to.be.false;
      expect(result.error).to.include("Amount mismatch");
    });

    it("should block recipient redirect attack", () => {
      const contract = testContract();
      const legitUser = testRecipient();
      const attacker = new PublicKey(Buffer.alloc(32, 0xee));
      const amount = 100_000_000_000; // $100K

      // Real event: $100K for legit user
      const event = makeLockedEvent(contract, legitUser, amount, 1);
      const inputs = makePublicInputs([event]);

      // Forged message: redirect to attacker
      const msg = makeBridgeMessage(attacker, amount);

      const result = validateProofAgainstMessage(inputs, msg, [contract]);
      expect(result.valid).to.be.false;
      expect(result.error).to.include("Recipient mismatch");
    });
  });

  // --------------------------------------------------------------------------
  // SP1 Public Inputs Serialization
  // --------------------------------------------------------------------------

  describe("SP1PublicInputs serialization roundtrip", () => {
    // BridgeClient needs a connection, but serialize/deserialize don't use it
    const bridge = new BridgeClient(null as any);

    it("should roundtrip empty event logs", () => {
      const inputs: SP1PublicInputs = {
        block_hash: new Array(32).fill(0xaa),
        block_number: 12345678,
        tx_hash: new Array(32).fill(0xbb),
        from: new Array(20).fill(0x11),
        to: new Array(20).fill(0x22),
        value: 0,
        success: true,
        event_logs: [],
      };

      const buf = bridge.serializeSP1PublicInputs(inputs);
      const decoded = bridge.deserializeSP1PublicInputs(buf);

      expect(decoded.block_number).to.equal(inputs.block_number);
      expect(decoded.success).to.equal(inputs.success);
      expect(decoded.value).to.equal(inputs.value);
      expect(decoded.event_logs.length).to.equal(0);
      expect(decoded.block_hash).to.deep.equal(inputs.block_hash);
      expect(decoded.tx_hash).to.deep.equal(inputs.tx_hash);
      expect(decoded.from).to.deep.equal(inputs.from);
      expect(decoded.to).to.deep.equal(inputs.to);
    });

    it("should roundtrip with event logs", () => {
      const contract = testContract();
      const recipient = testRecipient();
      const event = makeLockedEvent(contract, recipient, 50_000_000, 42);

      const inputs = makePublicInputs([event]);
      const buf = bridge.serializeSP1PublicInputs(inputs);
      const decoded = bridge.deserializeSP1PublicInputs(buf);

      expect(decoded.event_logs.length).to.equal(1);
      expect(decoded.event_logs[0].topics.length).to.equal(3);
      expect(decoded.event_logs[0].contract_address).to.deep.equal(
        Array.from(contract)
      );
      expect(decoded.event_logs[0].data.length).to.equal(96);

      // Verify the Locked event can still be found after roundtrip
      const locked = findLockedEvent(decoded.event_logs, [contract]);
      expect(locked).to.not.be.null;
      expect(locked!.amount.toNumber()).to.equal(50_000_000);
    });

    it("should roundtrip with multiple event logs", () => {
      const contract = testContract();
      const recipient = testRecipient();

      const event1: SP1EventLog = {
        contract_address: Array.from(contract),
        topics: [
          Array.from(TRANSFER_EVENT_SIGNATURE),
          new Array(32).fill(0x11),
          new Array(32).fill(0x22),
        ],
        data: encodeUint256(100),
      };
      const event2 = makeLockedEvent(contract, recipient, 9_999_999, 5);

      const inputs = makePublicInputs([event1, event2]);
      const buf = bridge.serializeSP1PublicInputs(inputs);
      const decoded = bridge.deserializeSP1PublicInputs(buf);

      expect(decoded.event_logs.length).to.equal(2);
      // First is Transfer
      expect(decoded.event_logs[0].topics[0]).to.deep.equal(
        Array.from(TRANSFER_EVENT_SIGNATURE)
      );
      // Second is Locked
      expect(decoded.event_logs[1].topics[0]).to.deep.equal(
        Array.from(LOCKED_EVENT_SIGNATURE)
      );
    });
  });

  // --------------------------------------------------------------------------
  // PDA Derivation
  // --------------------------------------------------------------------------

  describe("PDA Derivation", () => {
    const bridge = new BridgeClient(null as any);

    it("should derive config PDA deterministically", () => {
      const [pda1] = bridge.deriveConfigPda();
      const [pda2] = bridge.deriveConfigPda();
      expect(pda1.equals(pda2)).to.be.true;
    });

    it("should derive different message PDAs for different IDs", () => {
      const id1 = new Uint8Array(32).fill(0x01);
      const id2 = new Uint8Array(32).fill(0x02);
      const [pda1] = bridge.deriveMessagePda(id1);
      const [pda2] = bridge.deriveMessagePda(id2);
      expect(pda1.equals(pda2)).to.be.false;
    });

    it("should derive proof context PDA for a message ID", () => {
      const id = new Uint8Array(32).fill(0xab);
      const [messagePda] = bridge.deriveMessagePda(id);
      const [proofPda] = bridge.deriveProofContextPda(id);
      // Should be different accounts (different seeds)
      expect(messagePda.equals(proofPda)).to.be.false;
    });

    it("should derive bridge out message PDA from nonce", () => {
      const [pda1] = bridge.deriveBridgeOutMessagePda(new BN(0));
      const [pda2] = bridge.deriveBridgeOutMessagePda(new BN(1));
      expect(pda1.equals(pda2)).to.be.false;
    });

    it("should derive admin action PDA from nonce", () => {
      const [pda1] = bridge.deriveAdminActionPda(new BN(0));
      const [pda2] = bridge.deriveAdminActionPda(new BN(1));
      expect(pda1.equals(pda2)).to.be.false;
    });
  });
});
