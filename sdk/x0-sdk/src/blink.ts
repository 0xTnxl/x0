/**
 * Solana Actions (Blinks) Generator
 * 
 * Implements Blink generation for human-in-the-loop approval workflows.
 * Based on x0-01 Yellow Paper Section 4.4.
 */

import { PublicKey, Transaction, TransactionInstruction } from "@solana/web3.js";
import BN from "bn.js";
import { sha256, now } from "./utils";
import { BLINK_EXPIRY_SECONDS } from "./constants";
import type { Blink, BlinkAction } from "./types";

// ============================================================================
// Blink Generation
// ============================================================================

/**
 * Generate a Blink for human approval of a transfer
 */
export function generateTransferBlink(params: {
  policyId: PublicKey;
  owner: PublicKey;
  recipient: PublicKey;
  amount: BN;
  description: string;
  memo?: string;
  expiresIn?: number; // seconds
}): Blink {
  const expiresIn = params.expiresIn ?? BLINK_EXPIRY_SECONDS;
  const expiresAt = now() + expiresIn;
  
  // Generate unique Blink ID
  const blinkData = Buffer.concat([
    params.policyId.toBuffer(),
    params.recipient.toBuffer(),
    params.amount.toArrayLike(Buffer, "le", 8),
    Buffer.from(new BN(now()).toArrayLike(Buffer, "le", 8)),
  ]);
  const blinkId = Buffer.from(sha256(blinkData)).toString("hex").slice(0, 16);

  const actions: BlinkAction[] = [
    {
      label: "Approve",
      type: "approve",
      parameters: [
        {
          name: "signature",
          type: "signature",
          required: true,
          description: "Sign to approve this transfer",
        },
      ],
    },
    {
      label: "Reject",
      type: "reject",
      parameters: [],
    },
  ];

  return {
    id: blinkId,
    type: "transfer_approval",
    title: "Approve Agent Transfer",
    description: params.description,
    icon: "💸",
    disabled: false,
    
    // Transfer details
    metadata: {
      policyId: params.policyId.toBase58(),
      owner: params.owner.toBase58(),
      recipient: params.recipient.toBase58(),
      amount: params.amount.toString(),
      ...(params.memo && { memo: params.memo }),
    },
    
    actions,
    expiresAt,
    createdAt: now(),
  };
}

/**
 * Generate a Blink for escrow release approval
 */
export function generateEscrowReleaseBlink(params: {
  escrowId: PublicKey;
  buyer: PublicKey;
  seller: PublicKey;
  amount: BN;
  serviceMemo: string;
  expiresIn?: number;
}): Blink {
  const expiresIn = params.expiresIn ?? BLINK_EXPIRY_SECONDS;
  const expiresAt = now() + expiresIn;

  const blinkData = Buffer.concat([
    params.escrowId.toBuffer(),
    Buffer.from(new BN(now()).toArrayLike(Buffer, "le", 8)),
  ]);
  const blinkId = Buffer.from(sha256(blinkData)).toString("hex").slice(0, 16);

  const actions: BlinkAction[] = [
    {
      label: "Release Funds",
      type: "release",
      parameters: [
        {
          name: "signature",
          type: "signature",
          required: true,
          description: "Sign to release funds to seller",
        },
      ],
    },
    {
      label: "Dispute",
      type: "dispute",
      parameters: [
        {
          name: "reason",
          type: "text",
          required: true,
          description: "Reason for dispute",
        },
        {
          name: "signature",
          type: "signature",
          required: true,
          description: "Sign to initiate dispute",
        },
      ],
    },
  ];

  return {
    id: blinkId,
    type: "escrow_release",
    title: "Escrow Service Complete",
    description: `Service completed: ${params.serviceMemo}`,
    icon: "🔐",
    disabled: false,
    
    metadata: {
      escrowId: params.escrowId.toBase58(),
      buyer: params.buyer.toBase58(),
      seller: params.seller.toBase58(),
      amount: params.amount.toString(),
      serviceMemo: params.serviceMemo,
    },
    
    actions,
    expiresAt,
    createdAt: now(),
  };
}

/**
 * Generate a Blink for policy update approval
 */
export function generatePolicyUpdateBlink(params: {
  policyId: PublicKey;
  owner: PublicKey;
  changes: {
    spendLimit?: BN;
    txLimit?: BN;
    privacyLevel?: number;
    whitelistMode?: number;
  };
  expiresIn?: number;
}): Blink {
  const expiresIn = params.expiresIn ?? BLINK_EXPIRY_SECONDS;
  const expiresAt = now() + expiresIn;

  const blinkData = Buffer.concat([
    params.policyId.toBuffer(),
    Buffer.from("policy_update"),
    Buffer.from(new BN(now()).toArrayLike(Buffer, "le", 8)),
  ]);
  const blinkId = Buffer.from(sha256(blinkData)).toString("hex").slice(0, 16);

  // Build description of changes
  const changeDescriptions: string[] = [];
  if (params.changes.spendLimit) {
    changeDescriptions.push(`Spend limit: ${params.changes.spendLimit.toString()}`);
  }
  if (params.changes.txLimit) {
    changeDescriptions.push(`Transaction limit: ${params.changes.txLimit.toString()}`);
  }
  if (params.changes.privacyLevel !== undefined) {
    const levels = ["Public", "Semi-Private", "Private"];
    changeDescriptions.push(`Privacy: ${levels[params.changes.privacyLevel]}`);
  }
  if (params.changes.whitelistMode !== undefined) {
    const modes = ["Off", "Merkle", "Bloom", "Domain"];
    changeDescriptions.push(`Whitelist: ${modes[params.changes.whitelistMode]}`);
  }

  const actions: BlinkAction[] = [
    {
      label: "Approve Changes",
      type: "approve",
      parameters: [
        {
          name: "signature",
          type: "signature",
          required: true,
          description: "Sign to approve policy changes",
        },
      ],
    },
    {
      label: "Reject",
      type: "reject",
      parameters: [],
    },
  ];

  return {
    id: blinkId,
    type: "policy_update",
    title: "Approve Policy Changes",
    description: `Changes requested:\n${changeDescriptions.join("\n")}`,
    icon: "⚙️",
    disabled: false,
    
    metadata: {
      policyId: params.policyId.toBase58(),
      owner: params.owner.toBase58(),
      changes: {
        spendLimit: params.changes.spendLimit?.toString(),
        txLimit: params.changes.txLimit?.toString(),
        privacyLevel: params.changes.privacyLevel,
        whitelistMode: params.changes.whitelistMode,
      },
    },
    
    actions,
    expiresAt,
    createdAt: now(),
  };
}

// ============================================================================
// Blink URL Generation
// ============================================================================

/**
 * Generate a shareable URL for a Blink
 * @param blink - The Blink to encode
 * @param baseUrl - Base URL for the Blink handler (e.g., your app's domain)
 * @returns Shareable URL
 */
export function generateBlinkUrl(blink: Blink, baseUrl: string): string {
  const encoded = Buffer.from(JSON.stringify(blink)).toString("base64url");
  return `${baseUrl}/blink/${blink.id}?data=${encoded}`;
}

/**
 * Generate a Solana Actions compliant URL
 * @param blink - The Blink
 * @param actionsApiUrl - Actions API endpoint
 * @returns Solana Actions URL
 */
export function generateActionsUrl(blink: Blink, actionsApiUrl: string): string {
  return `solana-action:${actionsApiUrl}/actions/${blink.id}`;
}

/**
 * Parse a Blink from URL data parameter
 * @param data - Base64url encoded Blink data
 * @returns Parsed Blink or null if invalid
 */
export function parseBlinkFromUrl(data: string): Blink | null {
  try {
    const decoded = Buffer.from(data, "base64url").toString("utf-8");
    return JSON.parse(decoded) as Blink;
  } catch {
    return null;
  }
}

// ============================================================================
// Blink Validation
// ============================================================================

/**
 * Check if a Blink has expired
 */
export function isBlinkExpiredFromBlink(blink: Blink): boolean {
  return now() > blink.expiresAt;
}

/**
 * Validate Blink structure
 */
export function validateBlink(blink: unknown): blink is Blink {
  if (!blink || typeof blink !== "object") return false;
  
  const b = blink as Record<string, unknown>;
  
  return (
    typeof b.id === "string" &&
    typeof b.type === "string" &&
    typeof b.title === "string" &&
    typeof b.description === "string" &&
    Array.isArray(b.actions) &&
    typeof b.expiresAt === "number" &&
    typeof b.createdAt === "number"
  );
}

// ============================================================================
// Blink Response Handling
// ============================================================================

/**
 * Response structure for Blink action execution
 */
export interface BlinkActionResponse {
  success: boolean;
  type: string;
  transaction?: string; // Base64 encoded transaction
  signature?: string;
  message?: string;
  error?: string;
}

/**
 * Build a transaction for Blink approval
 * This returns a partially signed transaction that the owner must sign
 */
export function buildBlinkApprovalTransaction(params: {
  blink: Blink;
  instructions: TransactionInstruction[];
  feePayer: PublicKey;
  recentBlockhash: string;
}): Transaction {
  const tx = new Transaction({
    feePayer: params.feePayer,
    recentBlockhash: params.recentBlockhash,
  });

  // Add a memo instruction with Blink ID for tracking
  // In production, import @solana/spl-memo
  // For now, we just add the provided instructions
  tx.add(...params.instructions);

  return tx;
}

/**
 * Serialize a transaction for Blink response
 */
export function serializeBlinkTransaction(
  transaction: Transaction,
  requireAllSignatures: boolean = false
): string {
  const serialized = transaction.serialize({
    requireAllSignatures,
    verifySignatures: false,
  });
  return Buffer.from(serialized).toString("base64");
}

// ============================================================================
// Solana Actions Metadata
// ============================================================================

/**
 * Build Solana Actions metadata response
 * This is the GET response for an action URL
 */
export function buildActionsMetadata(blink: Blink): {
  icon: string;
  title: string;
  description: string;
  label: string;
  disabled: boolean;
  error?: { message: string };
  links?: {
    actions: Array<{
      label: string;
      href: string;
      parameters?: Array<{
        name: string;
        label: string;
        required: boolean;
      }>;
    }>;
  };
} {
  const isExpired = isBlinkExpiredFromBlink(blink);

  return {
    icon: blink.icon ?? "https://example.com/icon.png",
    title: blink.title,
    description: blink.description,
    label: blink.actions[0]?.label ?? "Execute",
    disabled: blink.disabled || isExpired,
    ...(isExpired && { error: { message: "This action has expired" } }),
    links: {
      actions: blink.actions.map((action) => ({
        label: action.label,
        href: `/api/actions/${blink.id}/${action.type}`,
        parameters: action.parameters?.map((p) => ({
          name: p.name,
          label: p.description,
          required: p.required,
        })),
      })),
    },
  };
}

// ============================================================================
// QR Code Data
// ============================================================================

/**
 * Generate data for QR code display
 * @param blink - The Blink
 * @param actionsApiUrl - Actions API endpoint
 * @returns QR code data string
 */
export function generateQRData(blink: Blink, actionsApiUrl: string): string {
  // Solana Pay / Actions QR format
  return `solana:${actionsApiUrl}/api/actions/${blink.id}`;
}
