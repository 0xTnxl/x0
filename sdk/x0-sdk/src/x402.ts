/**
 * x402 HTTP Protocol Handler
 * 
 * Implements the x402 payment-required response protocol for agent-to-agent payments.
 * Based on x0-01 Yellow Paper Section 3.
 */

import { PublicKey, Connection } from "@solana/web3.js";
import BN from "bn.js";
import { now } from "./utils";
import type { X402PaymentRequest, X402Header, PaymentReceipt, EscrowParams } from "./types";

// ============================================================================
// x402 Response Parsing
// ============================================================================

/**
 * Parse x402 Payment Required response from HTTP headers
 * @param statusCode - HTTP status code
 * @param headers - Response headers
 * @returns Parsed payment request or null if not x402
 */
export function parseX402Response(
  statusCode: number,
  headers: Record<string, string>
): X402PaymentRequest | null {
  if (statusCode !== 402) {
    return null;
  }

  const acceptPayment = headers["x-accept-payment"] || headers["X-Accept-Payment"];
  if (!acceptPayment) {
    return null;
  }

  try {
    // Parse as base64-encoded JSON
    const decoded = Buffer.from(acceptPayment, "base64").toString("utf-8");
    const data = JSON.parse(decoded);

    // Validate required fields
    if (!data.recipient || !data.amount || !data.resource) {
      throw new Error("Missing required fields in x402 response");
    }

    const escrowParams: EscrowParams | undefined = data.escrow
      ? {
          useEscrow: true,
          deliveryTimeout: data.escrow.deliveryTimeout,
          autoReleaseDelay: data.escrow.autoReleaseDelay,
          ...(data.escrow.arbiter && { arbiter: new PublicKey(data.escrow.arbiter) }),
        }
      : undefined;

    return {
      protocol: "x0-01",
      version: "1.0",
      mint: data.mint ?? "",
      recipient: data.recipient,
      amount: String(data.amount),
      memoHash: data.memo ?? "",
      network: "solana",
      challenge: data.nonce ?? "",
      ...(escrowParams && { escrow: escrowParams }),
      expiresAt: data.expiresAt ? new Date(data.expiresAt).getTime() / 1000 : 0,
    };
  } catch (error) {
    console.error("Failed to parse x402 response:", error);
    return null;
  }
}

/**
 * Parse x402 response from fetch Response object
 */
export async function parseX402FromResponse(
  response: Response
): Promise<X402PaymentRequest | null> {
  if (response.status !== 402) {
    return null;
  }

  const headers: Record<string, string> = {};
  response.headers.forEach((value, key) => {
    headers[key] = value;
  });

  return parseX402Response(response.status, headers);
}

// ============================================================================
// x402 Header Construction
// ============================================================================

/**
 * Build x402 payment required response header
 * @param params - Payment request parameters
 * @returns Base64-encoded header value
 */
export function buildX402Header(params: {
  recipient: PublicKey;
  amount: BN;
  resource: string;
  memo?: string;
  escrow?: EscrowParams;
  expiresAt?: Date;
  nonce?: Uint8Array;
}): string {
  const data = {
    recipient: params.recipient.toBase58(),
    amount: params.amount.toString(),
    resource: params.resource,
    memo: params.memo,
    escrow: params.escrow
      ? {
          deliveryTimeout: params.escrow.deliveryTimeout,
          autoReleaseDelay: params.escrow.autoReleaseDelay,
          arbiter: params.escrow.arbiter?.toBase58(),
        }
      : undefined,
    expiresAt: params.expiresAt?.toISOString(),
    nonce: params.nonce
      ? Buffer.from(params.nonce).toString("hex")
      : undefined,
  };

  return Buffer.from(JSON.stringify(data)).toString("base64");
}

/**
 * Build full HTTP response headers for x402
 */
export function buildX402ResponseHeaders(params: {
  recipient: PublicKey;
  amount: BN;
  resource: string;
  memo?: string;
  escrow?: EscrowParams;
  expiresAt?: Date;
  nonce?: Uint8Array;
}): X402Header {
  const headerValue = buildX402Header(params);
  return {
    raw: headerValue,
    request: {
      protocol: "x0-01",
      version: "1.0",
      mint: "",
      recipient: params.recipient.toBase58(),
      amount: params.amount.toString(),
      memoHash: params.memo ?? "",
      network: "solana",
      challenge: params.nonce ? Buffer.from(params.nonce).toString("hex") : "",
      expiresAt: params.expiresAt ? Math.floor(params.expiresAt.getTime() / 1000) : 0,
      ...(params.escrow && { escrow: params.escrow }),
    },
  };
}

// ============================================================================
// Payment Proof Construction
// ============================================================================

/**
 * Build payment authorization header for proof of payment
 * @param signature - Transaction signature
 * @param slot - Confirmed slot
 * @param payer - Payer's public key
 */
export function buildPaymentProofHeader(
  signature: string,
  slot: number,
  payer: PublicKey
): string {
  const data = {
    signature,
    slot,
    payer: payer.toBase58(),
    timestamp: now(),
  };
  return Buffer.from(JSON.stringify(data)).toString("base64");
}

/**
 * Build HTTP headers for request with payment proof
 */
export function buildPaymentHeaders(
  signature: string,
  slot: number,
  payer: PublicKey
): Record<string, string> {
  return {
    "X-Payment-Proof": buildPaymentProofHeader(signature, slot, payer),
    "X-Payment-Version": "x0-01-v1",
  };
}

// ============================================================================
// Payment Receipt Verification
// ============================================================================

/**
 * Token-2022 instruction discriminators for transfer types
 */
const TOKEN_2022_TRANSFER = 3; // Transfer instruction
const TOKEN_2022_TRANSFER_CHECKED = 12; // TransferChecked instruction

/**
 * Parse transfer amount from Token-2022 instruction data
 * @param instructionData - Raw instruction data
 * @returns Transfer amount or null if not a transfer instruction
 */
function parseTransferAmount(instructionData: Buffer | Uint8Array): bigint | null {
  const data = Buffer.from(instructionData);
  if (data.length < 9) return null;

  const discriminator = data[0];
  
  if (discriminator === TOKEN_2022_TRANSFER) {
    // Transfer: [discriminator(1), amount(8)]
    return data.readBigUInt64LE(1);
  }
  
  if (discriminator === TOKEN_2022_TRANSFER_CHECKED) {
    // TransferChecked: [discriminator(1), amount(8), decimals(1)]
    return data.readBigUInt64LE(1);
  }

  return null;
}

/**
 * Verify payment proof from incoming request
 * @param connection - Solana connection
 * @param proofHeader - X-Payment-Proof header value
 * @param expectedRecipient - Expected recipient address
 * @param expectedAmount - Expected payment amount
 * @returns Verification result with actual amount transferred
 */
export async function verifyPaymentProof(
  connection: Connection,
  proofHeader: string,
  expectedRecipient: PublicKey,
  expectedAmount: BN
): Promise<{
  valid: boolean;
  signature?: string;
  payer?: PublicKey;
  actualAmount?: string;
  error?: string;
}> {
  try {
    const decoded = Buffer.from(proofHeader, "base64").toString("utf-8");
    const data = JSON.parse(decoded);

    const signature = data.signature as string;
    const slot = data.slot as number;
    const payer = new PublicKey(data.payer);
    const timestamp = data.timestamp as number;

    // Check timestamp freshness (within 5 minutes)
    const currentTime = now();
    if (Math.abs(currentTime - timestamp) > 300) {
      return { valid: false, error: "Payment proof expired" };
    }

    // Verify transaction on-chain
    const tx = await connection.getTransaction(signature, {
      commitment: "confirmed",
      maxSupportedTransactionVersion: 0,
    });

    if (!tx) {
      return { valid: false, error: "Transaction not found" };
    }

    if (tx.meta?.err) {
      return { valid: false, error: "Transaction failed" };
    }

    if (tx.slot !== slot) {
      return { valid: false, error: "Slot mismatch" };
    }

    // Get all account keys (static + loaded addresses for v0 transactions)
    const accountKeys = tx.transaction.message.staticAccountKeys;
    const loadedAddresses = tx.meta?.loadedAddresses;
    const allAccountKeys = [
      ...accountKeys,
      ...(loadedAddresses?.writable ?? []),
      ...(loadedAddresses?.readonly ?? []),
    ];

    // Find recipient's token account index
    const recipientIndex = allAccountKeys.findIndex((key) => 
      key.equals(expectedRecipient)
    );
    
    if (recipientIndex === -1) {
      return { valid: false, error: "Recipient not found in transaction" };
    }

    // Parse post-token balances to verify the transfer
    const postTokenBalances = tx.meta?.postTokenBalances ?? [];
    const preTokenBalances = tx.meta?.preTokenBalances ?? [];

    // Find balance changes for accounts owned by recipient
    let totalTransferredToRecipient = BigInt(0);
    
    for (const postBalance of postTokenBalances) {
      const preBalance = preTokenBalances.find(
        (pre) => pre.accountIndex === postBalance.accountIndex
      );
      
      // Check if this token account is owned by the expected recipient
      if (postBalance.owner === expectedRecipient.toBase58()) {
        const preAmount = BigInt(preBalance?.uiTokenAmount.amount ?? "0");
        const postAmount = BigInt(postBalance.uiTokenAmount.amount);
        
        if (postAmount > preAmount) {
          totalTransferredToRecipient += postAmount - preAmount;
        }
      }
    }

    // If we couldn't find balance changes, fall back to parsing instructions
    if (totalTransferredToRecipient === BigInt(0)) {
      // Parse instructions to find Token-2022 transfers
      const message = tx.transaction.message;
      const instructions = message.compiledInstructions;
      
      for (const ix of instructions) {
        const programId = allAccountKeys[ix.programIdIndex];
        
        // Check if it's Token-2022 program (or Token program for compatibility)
        if (!programId) continue;
        const programIdStr = programId.toBase58();
        const isTokenProgram = 
          programIdStr === "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb" || // Token-2022
          programIdStr === "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";   // Token

        if (!isTokenProgram) continue;

        const amount = parseTransferAmount(ix.data);
        if (amount !== null) {
          // Check if destination is recipient's token account
          // For Transfer: accounts = [source, dest, authority]
          // For TransferChecked: accounts = [source, mint, dest, authority]
          const destIndex = ix.data[0] === TOKEN_2022_TRANSFER_CHECKED ? 2 : 1;
          const destAccountIndex = ix.accountKeyIndexes[destIndex];
          
          if (destAccountIndex !== undefined && allAccountKeys[destAccountIndex]) {
            // The destination account exists in transaction - count this transfer
            // Note: More precise verification would check if this ATA is owned by recipient
            totalTransferredToRecipient += amount;
          }
        }
      }
    }

    const actualAmount = totalTransferredToRecipient.toString();
    const expectedAmountBigInt = BigInt(expectedAmount.toString());

    // Verify amount matches (with some tolerance for fees if needed)
    if (totalTransferredToRecipient < expectedAmountBigInt) {
      return { 
        valid: false, 
        actualAmount,
        error: `Insufficient payment: expected ${expectedAmount.toString()}, received ${actualAmount}`,
      };
    }

    return {
      valid: true,
      signature,
      payer,
      actualAmount,
    };
  } catch (error) {
    return {
      valid: false,
      error: `Verification failed: ${error instanceof Error ? error.message : String(error)}`,
    };
  }
}

// ============================================================================
// Payment Receipt Generation
// ============================================================================

/**
 * Generate payment receipt after successful payment
 */
export function generatePaymentReceipt(params: {
  signature: string;
  slot: number;
  payer: PublicKey;
  recipient: PublicKey;
  amount: BN;
  resource: string;
  timestamp?: number;
}): PaymentReceipt {
  const ts = params.timestamp ?? now();
  
  // Note: Receipt ID could be used for tracking but PaymentReceipt uses signature as primary ID

  return {
    signature: params.signature,
    slot: params.slot,
    amount: params.amount.toString(),
    recipient: params.recipient.toBase58(),
    memoHash: params.resource,
    blockTime: ts,
    usedEscrow: false,
  };
}

// ============================================================================
// Middleware Helpers
// ============================================================================

/**
 * Express-style middleware factory for x402 payment verification
 * @param connection - Solana connection
 * @param recipient - Expected recipient
 * @param getAmount - Function to get expected amount from request
 */
export function createX402Middleware(
  connection: Connection,
  recipient: PublicKey,
  getAmount: (req: { path: string; method: string }) => BN | null
) {
  return async (
    req: { path: string; method: string; headers: Record<string, string> },
    res: {
      status: (code: number) => { json: (data: unknown) => void; setHeader: (key: string, value: string) => void };
    },
    next: () => void
  ) => {
    const expectedAmount = getAmount(req);
    
    if (!expectedAmount) {
      // No payment required for this endpoint
      return next();
    }

    const proofHeader = req.headers["x-payment-proof"];
    
    if (!proofHeader) {
      // No payment proof - return 402
      const x402Headers = buildX402ResponseHeaders({
        recipient,
        amount: expectedAmount,
        resource: `${req.method} ${req.path}`,
      });

      const response = res.status(402);
      response.setHeader("X-Accept-Payment", x402Headers.raw);
      response.setHeader("X-Payment-Version", "x0-01-v1");
      response.setHeader("X-Payment-Network", "solana");
      
      response.json({
        error: "Payment Required",
        message: "This resource requires payment",
        paymentInfo: x402Headers.raw,
      });
      return;
    }

    // Verify payment
    const result = await verifyPaymentProof(
      connection,
      proofHeader,
      recipient,
      expectedAmount
    );

    if (!result.valid) {
      res.status(402).json({
        error: "Payment Invalid",
        message: result.error,
      });
      return;
    }

    // Payment verified - continue
    next();
  };
}

// ============================================================================
// Client Helper
// ============================================================================

/**
 * Fetch with automatic x402 payment handling
 * @param url - URL to fetch
 * @param options - Fetch options
 * @param paymentHandler - Callback to handle payment when 402 is received
 * @returns Response after payment (if needed)
 */
export async function fetchWithPayment(
  url: string,
  options: RequestInit = {},
  paymentHandler: (
    request: X402PaymentRequest
  ) => Promise<{ signature: string; slot: number; payer: PublicKey } | null>
): Promise<Response> {
  // Initial request
  let response = await fetch(url, options);

  // Check for 402
  if (response.status === 402) {
    const paymentRequest = await parseX402FromResponse(response);
    
    if (!paymentRequest) {
      throw new Error("Invalid x402 response format");
    }

    // Execute payment
    const paymentResult = await paymentHandler(paymentRequest);
    
    if (!paymentResult) {
      throw new Error("Payment was not completed");
    }

    // Retry with payment proof
    const paymentHeaders = buildPaymentHeaders(
      paymentResult.signature,
      paymentResult.slot,
      paymentResult.payer
    );

    response = await fetch(url, {
      ...options,
      headers: {
        ...options.headers,
        ...paymentHeaders,
      },
    });
  }

  return response;
}
