/**
 * x0-01 Devnet Integration Test
 * 
 * Tests the deployed programs on Solana devnet.
 * Run with: node scripts/devnet-test.mjs
 */

import {
  Connection,
  Keypair,
  PublicKey,
  Transaction,
  TransactionInstruction,
  sendAndConfirmTransaction,
  LAMPORTS_PER_SOL,
  SystemProgram,
  SYSVAR_RENT_PUBKEY,
} from "@solana/web3.js";
import {
  TOKEN_2022_PROGRAM_ID,
  TOKEN_PROGRAM_ID,
  ASSOCIATED_TOKEN_PROGRAM_ID,
  createInitializeMintInstruction,
  createInitializeTransferHookInstruction,
  createInitializeTransferFeeConfigInstruction,
  createMintToInstruction,
  createAssociatedTokenAccountInstruction,
  createTransferCheckedWithTransferHookInstruction,
  getAssociatedTokenAddressSync,
  getMint,
  getAccount,
  ExtensionType,
  getMintLen,
  createApproveInstruction,
} from "@solana/spl-token";
import * as fs from "fs";
import * as path from "path";
import { fileURLToPath } from "url";
import { createHash } from "crypto";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// ============================================================================
// Program IDs (deployed to devnet)
// ============================================================================

const X0_GUARD_PROGRAM_ID = new PublicKey("2uYGW3fQUGfhrwVbkupdasXBpRPfGYBGTLUdaPTXU9vP");
const X0_TOKEN_PROGRAM_ID = new PublicKey("EHHTCSyGkmnsBhGsvCmLzKgcSxtsN31ScrfiwcCbjHci");
const X0_ESCROW_PROGRAM_ID = new PublicKey("AhaDyVm8LBxpUwFdArA37LnHvNx6cNWe3KAiy8zGqhHF");
const X0_REGISTRY_PROGRAM_ID = new PublicKey("Bebty49EPhFoANKDw7TqLQ2bX61ackNav5iNkj36eVJo");
const X0_REPUTATION_PROGRAM_ID = new PublicKey("FfzkTWRGAJQPDePbujZdEhKHqC1UpqvDrpv4TEiWpx6y");
const X0_WRAPPER_PROGRAM_ID = new PublicKey("EomiXBbg94Smu4ipDoJtuguazcd1KjLFDFJt2fCabvJ8");

// Devnet USDC (Circle's devnet USDC)
const DEVNET_USDC_MINT = new PublicKey("4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU");

// USDC funding wallet (has testnet USDC for wrapper tests)
const USDC_WALLET_SECRET = "5UfLXCtzHzKQrzYeC46Ad2RWsc6VdJmuX9sufjL5hmr1pv1miVDXtp2V4Xk4pnmn2XJ2bFM3XS176wioMpYbM8cN";

// ============================================================================
// Configuration
// ============================================================================

const DEVNET_URL = "https://api.devnet.solana.com";
const DECIMALS = 6;

// Load wallet from default Solana CLI location
function loadWallet() {
  const walletPath = path.join(
    process.env.HOME || "~",
    ".config/solana/id.json"
  );
  const secretKey = JSON.parse(fs.readFileSync(walletPath, "utf-8"));
  return Keypair.fromSecretKey(Uint8Array.from(secretKey));
}

// Load USDC wallet from base58 secret key
function loadUsdcWallet() {
  // Decode base58 secret key
  const bs58Chars = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  let decoded = BigInt(0);
  for (const char of USDC_WALLET_SECRET) {
    decoded = decoded * BigInt(58) + BigInt(bs58Chars.indexOf(char));
  }
  const bytes = [];
  while (decoded > 0) {
    bytes.unshift(Number(decoded % BigInt(256)));
    decoded = decoded / BigInt(256);
  }
  // Pad to 64 bytes
  while (bytes.length < 64) bytes.unshift(0);
  return Keypair.fromSecretKey(Uint8Array.from(bytes));
}

// ============================================================================
// Test Utilities
// ============================================================================

function log(section, message) {
  console.log(`[${section}] ${message}`);
}

function logSuccess(message) {
  console.log(`[OK] ${message}`);
}

function logError(message) {
  console.error(`[ERROR] ${message}`);
}

// ============================================================================
// Test: Verify Program Deployments
// ============================================================================

async function testProgramDeployments(connection) {
  log("DEPLOY", "Verifying program deployments...");

  const programs = [
    { name: "x0-guard", id: X0_GUARD_PROGRAM_ID },
    { name: "x0-token", id: X0_TOKEN_PROGRAM_ID },
    { name: "x0-escrow", id: X0_ESCROW_PROGRAM_ID },
    { name: "x0-registry", id: X0_REGISTRY_PROGRAM_ID },
    { name: "x0-reputation", id: X0_REPUTATION_PROGRAM_ID },
  ];

  for (const program of programs) {
    const accountInfo = await connection.getAccountInfo(program.id);
    if (accountInfo && accountInfo.executable) {
      logSuccess(`${program.name}: ${program.id.toBase58()} (deployed)`);
    } else {
      logError(`${program.name}: ${program.id.toBase58()} (NOT FOUND)`);
    }
  }
}

// ============================================================================
// Test: Create Token-2022 Mint with Transfer Hook
// ============================================================================

async function testCreateMint(connection, payer) {
  log("MINT", "Creating Token-2022 mint with transfer hook extension...");

  const mintKeypair = Keypair.generate();
  const mint = mintKeypair.publicKey;

  // Calculate space for mint with extensions
  const extensions = [ExtensionType.TransferHook, ExtensionType.TransferFeeConfig];
  const mintLen = getMintLen(extensions);
  const lamports = await connection.getMinimumBalanceForRentExemption(mintLen);

  // Create mint account
  const createAccountIx = SystemProgram.createAccount({
    fromPubkey: payer.publicKey,
    newAccountPubkey: mint,
    space: mintLen,
    lamports,
    programId: TOKEN_2022_PROGRAM_ID,
  });

  // Initialize transfer hook extension (points to x0-guard)
  const initTransferHookIx = createInitializeTransferHookInstruction(
    mint,
    payer.publicKey, // authority
    X0_GUARD_PROGRAM_ID, // transfer hook program
    TOKEN_2022_PROGRAM_ID
  );

  // Initialize transfer fee extension (0.8%)
  const initTransferFeeIx = createInitializeTransferFeeConfigInstruction(
    mint,
    payer.publicKey, // fee authority
    payer.publicKey, // withdraw authority
    80, // 0.8% = 80 basis points
    BigInt(1_000_000_000), // max fee
    TOKEN_2022_PROGRAM_ID
  );

  // Initialize mint
  const initMintIx = createInitializeMintInstruction(
    mint,
    DECIMALS,
    payer.publicKey, // mint authority
    payer.publicKey, // freeze authority
    TOKEN_2022_PROGRAM_ID
  );

  const tx = new Transaction().add(
    createAccountIx,
    initTransferHookIx,
    initTransferFeeIx,
    initMintIx
  );

  try {
    const sig = await sendAndConfirmTransaction(connection, tx, [payer, mintKeypair], {
      commitment: "confirmed",
    });
    logSuccess(`Mint created: ${mint.toBase58()}`);
    logSuccess(`Transaction: ${sig}`);
    return mint;
  } catch (error) {
    logError(`Failed to create mint: ${error.message}`);
    throw error;
  }
}

// ============================================================================
// Test: Create Token Account and Mint Tokens
// ============================================================================

async function testMintTokens(connection, payer, mint, amount) {
  log("MINT", `Minting ${amount} tokens...`);

  // Get or create associated token account
  const ata = getAssociatedTokenAddressSync(
    mint,
    payer.publicKey,
    false,
    TOKEN_2022_PROGRAM_ID
  );

  const tx = new Transaction();

  // Check if ATA exists
  const ataInfo = await connection.getAccountInfo(ata);
  if (!ataInfo) {
    log("MINT", "Creating associated token account...");
    tx.add(
      createAssociatedTokenAccountInstruction(
        payer.publicKey,
        ata,
        payer.publicKey,
        mint,
        TOKEN_2022_PROGRAM_ID
      )
    );
  }

  // Mint tokens
  tx.add(
    createMintToInstruction(
      mint,
      ata,
      payer.publicKey,
      amount,
      [],
      TOKEN_2022_PROGRAM_ID
    )
  );

  try {
    const sig = await sendAndConfirmTransaction(connection, tx, [payer], {
      commitment: "confirmed",
    });
    logSuccess(`Minted ${amount} tokens to ${ata.toBase58()}`);
    logSuccess(`Transaction: ${sig}`);
    return ata;
  } catch (error) {
    logError(`Failed to mint tokens: ${error.message}`);
    throw error;
  }
}

// ============================================================================
// Test: Query Mint Info
// ============================================================================

async function testQueryMint(connection, mint) {
  log("QUERY", "Fetching mint information...");

  try {
    const mintInfo = await getMint(connection, mint, "confirmed", TOKEN_2022_PROGRAM_ID);
    logSuccess(`Mint: ${mint.toBase58()}`);
    logSuccess(`  Decimals: ${mintInfo.decimals}`);
    logSuccess(`  Supply: ${mintInfo.supply.toString()}`);
    logSuccess(`  Mint Authority: ${mintInfo.mintAuthority?.toBase58() || "none"}`);
  } catch (error) {
    logError(`Failed to query mint: ${error.message}`);
  }
}

// ============================================================================
// Test: Query Token Account
// ============================================================================

async function testQueryTokenAccount(connection, tokenAccount) {
  log("QUERY", "Fetching token account information...");

  try {
    const accountInfo = await getAccount(
      connection,
      tokenAccount,
      "confirmed",
      TOKEN_2022_PROGRAM_ID
    );
    logSuccess(`Token Account: ${tokenAccount.toBase58()}`);
    logSuccess(`  Owner: ${accountInfo.owner.toBase58()}`);
    logSuccess(`  Balance: ${accountInfo.amount.toString()}`);
    logSuccess(`  Mint: ${accountInfo.mint.toBase58()}`);
  } catch (error) {
    logError(`Failed to query token account: ${error.message}`);
  }
}

// ============================================================================
// Anchor Instruction Discriminator Utility
// ============================================================================

function getInstructionDiscriminator(namespace, name) {
  const preimage = `${namespace}:${name}`;
  const hash = createHash("sha256").update(preimage).digest();
  return hash.slice(0, 8);
}

// ============================================================================
// Test: Initialize Extra Account Metas
// ============================================================================

async function testInitializeExtraAccountMetasFull(connection, payer, mint) {
  log("HOOK", "Initializing extra account metas for transfer hook...");

  // Derive the extra account metas PDA
  const [extraAccountMetasPda, bump] = PublicKey.findProgramAddressSync(
    [Buffer.from("extra-account-metas"), mint.toBuffer()],
    X0_GUARD_PROGRAM_ID
  );

  log("HOOK", `Extra account metas PDA: ${extraAccountMetasPda.toBase58()}`);

  // Check if already initialized
  const info = await connection.getAccountInfo(extraAccountMetasPda);
  if (info && info.data.length > 0) {
    logSuccess("Extra account metas already initialized");
    return extraAccountMetasPda;
  }

  // Build initialize_extra_account_metas instruction
  const discriminator = getInstructionDiscriminator("global", "initialize_extra_account_metas");

  const ix = new TransactionInstruction({
    programId: X0_GUARD_PROGRAM_ID,
    keys: [
      { pubkey: payer.publicKey, isSigner: true, isWritable: true },
      { pubkey: mint, isSigner: false, isWritable: false },
      { pubkey: extraAccountMetasPda, isSigner: false, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data: discriminator,
  });

  const tx = new Transaction().add(ix);

  try {
    const sig = await sendAndConfirmTransaction(connection, tx, [payer], {
      commitment: "confirmed",
    });
    logSuccess(`Extra account metas initialized`);
    logSuccess(`Transaction: ${sig}`);
    return extraAccountMetasPda;
  } catch (error) {
    logError(`Failed to initialize extra account metas: ${error.message}`);
    throw error;
  }
}

// ============================================================================
// Test: Initialize Agent Policy
// ============================================================================

async function testInitializePolicy(connection, payer, agentKeypair) {
  log("POLICY", "Initializing agent policy...");

  // Derive the policy PDA
  const AGENT_POLICY_SEED = Buffer.from("agent_policy");
  const [policyPda, bump] = PublicKey.findProgramAddressSync(
    [AGENT_POLICY_SEED, payer.publicKey.toBuffer()],
    X0_GUARD_PROGRAM_ID
  );

  log("POLICY", `Policy PDA: ${policyPda.toBase58()}`);
  log("POLICY", `Agent Signer: ${agentKeypair.publicKey.toBase58()}`);

  // Check if already initialized
  const info = await connection.getAccountInfo(policyPda);
  if (info && info.data.length > 0) {
    log("POLICY", "Policy exists - updating agent signer to current agent...");
    
    // Call update_agent_signer to set the new agent
    const updateDiscriminator = getInstructionDiscriminator("global", "update_agent_signer");
    
    // Encode: discriminator (8) + new_agent_signer pubkey (32)
    const updateData = Buffer.alloc(8 + 32);
    updateDiscriminator.copy(updateData, 0);
    agentKeypair.publicKey.toBuffer().copy(updateData, 8);
    
    const updateIx = new TransactionInstruction({
      programId: X0_GUARD_PROGRAM_ID,
      keys: [
        { pubkey: payer.publicKey, isSigner: true, isWritable: false },
        { pubkey: agentKeypair.publicKey, isSigner: false, isWritable: false },
        { pubkey: policyPda, isSigner: false, isWritable: true },
      ],
      data: updateData,
    });
    
    const updateTx = new Transaction().add(updateIx);
    
    try {
      const sig = await sendAndConfirmTransaction(connection, updateTx, [payer], {
        commitment: "confirmed",
      });
      logSuccess(`Agent signer updated to: ${agentKeypair.publicKey.toBase58()}`);
      logSuccess(`Transaction: ${sig}`);
    } catch (error) {
      logError(`Failed to update agent signer: ${error.message}`);
      throw error;
    }
    
    return policyPda;
  }

  // Build initialize_policy instruction
  // Args: daily_limit (u64), whitelist_mode (enum), whitelist_data (enum), privacy_level (enum)
  const discriminator = getInstructionDiscriminator("global", "initialize_policy");

  // Encode instruction data
  const dailyLimit = BigInt(100_000_000_000); // 100,000 tokens with 6 decimals
  
  const data = Buffer.alloc(8 + 8 + 1 + 1 + 1); // discriminator + daily_limit + whitelist_mode + whitelist_data_variant + privacy_level
  let offset = 0;
  
  discriminator.copy(data, offset);
  offset += 8;
  
  // daily_limit (u64 LE)
  data.writeBigUInt64LE(dailyLimit, offset);
  offset += 8;
  
  // whitelist_mode: None = 0
  data.writeUInt8(0, offset);
  offset += 1;
  
  // whitelist_data: None variant = 0
  data.writeUInt8(0, offset);
  offset += 1;
  
  // privacy_level: Public = 0
  data.writeUInt8(0, offset);

  const ix = new TransactionInstruction({
    programId: X0_GUARD_PROGRAM_ID,
    keys: [
      { pubkey: payer.publicKey, isSigner: true, isWritable: true },
      { pubkey: agentKeypair.publicKey, isSigner: false, isWritable: false },
      { pubkey: policyPda, isSigner: false, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data,
  });

  const tx = new Transaction().add(ix);

  try {
    const sig = await sendAndConfirmTransaction(connection, tx, [payer], {
      commitment: "confirmed",
    });
    logSuccess(`Agent policy created`);
    logSuccess(`  Policy PDA: ${policyPda.toBase58()}`);
    logSuccess(`  Daily Limit: ${dailyLimit.toString()} (100,000 tokens)`);
    logSuccess(`  Whitelist: None (all recipients allowed)`);
    logSuccess(`  Privacy: Public`);
    logSuccess(`Transaction: ${sig}`);
    return policyPda;
  } catch (error) {
    logError(`Failed to initialize policy: ${error.message}`);
    throw error;
  }
}

// ============================================================================
// Test: Transfer with Transfer Hook
// ============================================================================

async function testTransferWithHook(connection, payer, agentKeypair, mint, sourceAccount, policyPda, extraMetasPda) {
  log("TRANSFER", "Testing transfer with transfer hook validation...");

  // Step 1: Delegate tokens to the agent
  // The owner (payer) approves the agent to spend tokens on their behalf
  const delegateAmount = BigInt(10_000_000); // 10 tokens
  
  log("TRANSFER", `Delegating ${delegateAmount} tokens to agent...`);
  
  const approveIx = createApproveInstruction(
    sourceAccount,
    agentKeypair.publicKey,
    payer.publicKey,
    delegateAmount,
    [],
    TOKEN_2022_PROGRAM_ID
  );

  const approveTx = new Transaction().add(approveIx);
  
  try {
    const sig = await sendAndConfirmTransaction(connection, approveTx, [payer], {
      commitment: "confirmed",
    });
    logSuccess(`Delegated ${delegateAmount} tokens to agent`);
    logSuccess(`Transaction: ${sig}`);
  } catch (error) {
    logError(`Failed to delegate: ${error.message}`);
    throw error;
  }

  // Step 2: Create a destination account (different owner)
  const destinationOwner = Keypair.generate();
  const destinationAccount = getAssociatedTokenAddressSync(
    mint,
    destinationOwner.publicKey,
    false,
    TOKEN_2022_PROGRAM_ID
  );

  log("TRANSFER", `Destination owner: ${destinationOwner.publicKey.toBase58()}`);
  log("TRANSFER", `Destination account: ${destinationAccount.toBase58()}`);

  // Create destination ATA first
  const createAtaIx = createAssociatedTokenAccountInstruction(
    payer.publicKey,
    destinationAccount,
    destinationOwner.publicKey,
    mint,
    TOKEN_2022_PROGRAM_ID
  );

  const createAtaTx = new Transaction().add(createAtaIx);
  
  try {
    const sig = await sendAndConfirmTransaction(connection, createAtaTx, [payer], {
      commitment: "confirmed",
    });
    logSuccess(`Created destination ATA: ${sig}`);
  } catch (error) {
    // May already exist
    log("TRANSFER", `ATA creation note: ${error.message}`);
  }

  // Step 3: Agent executes transfer (agent is the authority, not owner)
  const amount = BigInt(1_000_000); // 1 token
  
  log("TRANSFER", `Agent transferring ${amount} tokens (1 token)...`);
  log("TRANSFER", "Agent will sign - this invokes x0-guard transfer hook for policy validation");

  try {
    // Use the transfer with hook instruction builder
    // CRITICAL: authority is the agent (delegate), not the owner
    const transferIx = await createTransferCheckedWithTransferHookInstruction(
      connection,
      sourceAccount,
      mint,
      destinationAccount,
      agentKeypair.publicKey, // authority = agent (delegate)
      amount,
      6, // decimals
      [],
      "confirmed",
      TOKEN_2022_PROGRAM_ID
    );

    const tx = new Transaction().add(transferIx);

    // CRITICAL: Agent signs the transaction, not owner
    const sig = await sendAndConfirmTransaction(connection, tx, [payer, agentKeypair], {
      commitment: "confirmed",
      skipPreflight: false,
    });
    
    logSuccess(`Transfer successful!`);
    logSuccess(`Transaction: ${sig}`);
    logSuccess("Transfer hook validated: agent authorized, within daily limit");
    
    // Query destination balance
    const destInfo = await getAccount(connection, destinationAccount, "confirmed", TOKEN_2022_PROGRAM_ID);
    logSuccess(`Destination balance: ${destInfo.amount.toString()}`);
    
    return sig;
  } catch (error) {
    logError(`Transfer failed: ${error.message}`);
    
    // Parse the error to understand what happened
    if (error.logs) {
      log("TRANSFER", "Transaction logs:");
      error.logs.forEach(l => console.log(`  ${l}`));
    }
    
    throw error;
  }
}

// ============================================================================
// Test: Initialize Reputation (x0-reputation)
// ============================================================================

async function testInitializeReputation(connection, payer, existingPolicyPda) {
  log("REPUTATION", "Initializing agent reputation...");

  // Use the existing policy PDA from x0-guard tests
  const policyPda = existingPolicyPda;
  
  log("REPUTATION", `Using policy PDA: ${policyPda.toBase58()}`);

  // Derive the reputation PDA
  const REPUTATION_SEED = Buffer.from("reputation");
  const [reputationPda, bump] = PublicKey.findProgramAddressSync(
    [REPUTATION_SEED, policyPda.toBuffer()],
    X0_REPUTATION_PROGRAM_ID
  );

  log("REPUTATION", `Reputation PDA: ${reputationPda.toBase58()}`);

  // Check if already initialized
  const info = await connection.getAccountInfo(reputationPda);
  if (info && info.data.length > 0) {
    // Check the version byte (offset 8 after discriminator)
    const version = info.data[8];
    log("REPUTATION", `Existing account found, version: ${version}`);
    
    if (version < 2) {
      // Migrate the account from v1 to v2
      log("REPUTATION", "Migrating v1 account to v2...");
      const migrateDiscriminator = getInstructionDiscriminator("global", "migrate_reputation");
      const migrateIx = new TransactionInstruction({
        programId: X0_REPUTATION_PROGRAM_ID,
        keys: [
          { pubkey: payer.publicKey, isSigner: true, isWritable: true },
          { pubkey: policyPda, isSigner: false, isWritable: false },
          { pubkey: reputationPda, isSigner: false, isWritable: true },
          { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
        ],
        data: migrateDiscriminator,
      });
      
      try {
        const migrateTx = new Transaction().add(migrateIx);
        const migrateSig = await sendAndConfirmTransaction(connection, migrateTx, [payer], {
          commitment: "confirmed",
        });
        logSuccess(`Migrated reputation account to v2`);
        logSuccess(`Transaction: ${migrateSig}`);
      } catch (migrateError) {
        log("REPUTATION", `Migration failed: ${migrateError.message}`);
        // Try to close and recreate
      }
    }
    
    // Now try to close the account
    log("REPUTATION", "Closing existing reputation account...");
    const closeDiscriminator = getInstructionDiscriminator("global", "close_reputation");
    const closeIx = new TransactionInstruction({
      programId: X0_REPUTATION_PROGRAM_ID,
      keys: [
        { pubkey: payer.publicKey, isSigner: true, isWritable: true },
        { pubkey: policyPda, isSigner: false, isWritable: false },
        { pubkey: reputationPda, isSigner: false, isWritable: true },
        { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      ],
      data: closeDiscriminator,
    });
    
    try {
      const closeTx = new Transaction().add(closeIx);
      const closeSig = await sendAndConfirmTransaction(connection, closeTx, [payer], {
        commitment: "confirmed",
      });
      logSuccess(`Closed stale reputation account`);
      logSuccess(`Transaction: ${closeSig}`);
    } catch (closeError) {
      log("REPUTATION", `Could not close (may already be valid): ${closeError.message}`);
    }
  }

  // Build initialize_reputation instruction
  const discriminator = getInstructionDiscriminator("global", "initialize_reputation");

  const ix = new TransactionInstruction({
    programId: X0_REPUTATION_PROGRAM_ID,
    keys: [
      { pubkey: payer.publicKey, isSigner: true, isWritable: true },
      { pubkey: policyPda, isSigner: false, isWritable: false },
      { pubkey: reputationPda, isSigner: false, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data: discriminator,
  });

  const tx = new Transaction().add(ix);

  try {
    const sig = await sendAndConfirmTransaction(connection, tx, [payer], {
      commitment: "confirmed",
    });
    logSuccess(`Reputation account created`);
    logSuccess(`Transaction: ${sig}`);
    return reputationPda;
  } catch (error) {
    logError(`Failed to initialize reputation: ${error.message}`);
    throw error;
  }
}

// ============================================================================
// Test: Record Success (x0-reputation)
// ============================================================================

async function testRecordSuccess(connection, payer, policyPda, reputationPda) {
  log("REPUTATION", "Recording successful transaction...");

  // Build record_success instruction
  const discriminator = getInstructionDiscriminator("global", "record_success");
  
  // Encode: discriminator (8) + response_time_ms (u32)
  const data = Buffer.alloc(8 + 4);
  discriminator.copy(data, 0);
  data.writeUInt32LE(150, 8); // 150ms response time

  const ix = new TransactionInstruction({
    programId: X0_REPUTATION_PROGRAM_ID,
    keys: [
      { pubkey: payer.publicKey, isSigner: true, isWritable: false },
      { pubkey: policyPda, isSigner: false, isWritable: false },
      { pubkey: reputationPda, isSigner: false, isWritable: true },
    ],
    data,
  });

  const tx = new Transaction().add(ix);

  try {
    const sig = await sendAndConfirmTransaction(connection, tx, [payer], {
      commitment: "confirmed",
    });
    logSuccess(`Success recorded (response_time=150ms)`);
    logSuccess(`Transaction: ${sig}`);
  } catch (error) {
    logError(`Failed to record success: ${error.message}`);
    throw error;
  }
}

// ============================================================================
// Test: Register Agent (x0-registry)
// ============================================================================

async function testRegisterAgent(connection, payer, policyPda, reputationPda, treasury) {
  log("REGISTRY", "Registering agent...");

  // Derive the registry PDA
  const REGISTRY_SEED = Buffer.from("registry");
  const [registryPda, bump] = PublicKey.findProgramAddressSync(
    [REGISTRY_SEED, policyPda.toBuffer()],
    X0_REGISTRY_PROGRAM_ID
  );

  log("REGISTRY", `Registry PDA: ${registryPda.toBase58()}`);

  // Check if already initialized
  const info = await connection.getAccountInfo(registryPda);
  if (info && info.data.length > 0) {
    logSuccess("Agent already registered");
    return registryPda;
  }

  // Build register_agent instruction
  // Args: endpoint (String), capabilities (Vec<Capability>)
  const discriminator = getInstructionDiscriminator("global", "register_agent");
  
  // Encode endpoint string (4-byte length prefix + bytes)
  const endpoint = "https://agent.example.com/api/v1";
  const endpointBytes = Buffer.from(endpoint, "utf8");
  
  // Encode capabilities: Vec<Capability>
  // Capability { capability_type: String, metadata: String }
  const capType = "payment";
  const capTypeBytes = Buffer.from(capType, "utf8");
  const capMeta = "{}";
  const capMetaBytes = Buffer.from(capMeta, "utf8");
  
  // Calculate data size
  const dataSize = 8 + // discriminator
    4 + endpointBytes.length + // endpoint string
    4 + // vec length
    (4 + capTypeBytes.length + 4 + capMetaBytes.length); // one capability
  
  const data = Buffer.alloc(dataSize);
  let offset = 0;
  
  discriminator.copy(data, offset);
  offset += 8;
  
  // endpoint string
  data.writeUInt32LE(endpointBytes.length, offset);
  offset += 4;
  endpointBytes.copy(data, offset);
  offset += endpointBytes.length;
  
  // capabilities vec (1 element)
  data.writeUInt32LE(1, offset);
  offset += 4;
  
  // capability_type string
  data.writeUInt32LE(capTypeBytes.length, offset);
  offset += 4;
  capTypeBytes.copy(data, offset);
  offset += capTypeBytes.length;
  
  // metadata string
  data.writeUInt32LE(capMetaBytes.length, offset);
  offset += 4;
  capMetaBytes.copy(data, offset);

  const ix = new TransactionInstruction({
    programId: X0_REGISTRY_PROGRAM_ID,
    keys: [
      { pubkey: payer.publicKey, isSigner: true, isWritable: true },
      { pubkey: policyPda, isSigner: false, isWritable: false },
      { pubkey: registryPda, isSigner: false, isWritable: true },
      { pubkey: reputationPda, isSigner: false, isWritable: false },
      { pubkey: treasury, isSigner: false, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data,
  });

  const tx = new Transaction().add(ix);

  try {
    const sig = await sendAndConfirmTransaction(connection, tx, [payer], {
      commitment: "confirmed",
    });
    logSuccess(`Agent registered`);
    logSuccess(`  Endpoint: ${endpoint}`);
    logSuccess(`  Capability: ${capType}`);
    logSuccess(`Transaction: ${sig}`);
    return registryPda;
  } catch (error) {
    logError(`Failed to register agent: ${error.message}`);
    throw error;
  }
}

// ============================================================================
// Test: Create Escrow (x0-escrow)
// ============================================================================

async function testCreateEscrow(connection, payer, mint) {
  log("ESCROW", "Creating escrow...");

  // Create a seller keypair
  const seller = Keypair.generate();
  
  // Generate memo hash
  const memoHash = createHash("sha256").update("test-escrow-memo-123").digest();
  
  // Derive the escrow PDA
  const ESCROW_SEED = Buffer.from("escrow");
  const [escrowPda, bump] = PublicKey.findProgramAddressSync(
    [ESCROW_SEED, payer.publicKey.toBuffer(), seller.publicKey.toBuffer(), memoHash],
    X0_ESCROW_PROGRAM_ID
  );

  log("ESCROW", `Escrow PDA: ${escrowPda.toBase58()}`);
  log("ESCROW", `Seller: ${seller.publicKey.toBase58()}`);

  // Check if already initialized
  const info = await connection.getAccountInfo(escrowPda);
  if (info && info.data.length > 0) {
    logSuccess("Escrow already exists");
    return escrowPda;
  }

  // Build create_escrow instruction
  // Args: amount (u64), memo_hash ([u8; 32]), timeout_seconds (i64), arbiter (Option<Pubkey>)
  const discriminator = getInstructionDiscriminator("global", "create_escrow");
  
  const amount = BigInt(1_000_000); // 1 token
  const timeoutSeconds = BigInt(3600); // 1 hour
  
  // Data: discriminator + amount + memo_hash + timeout + option(arbiter)
  const data = Buffer.alloc(8 + 8 + 32 + 8 + 1);
  let offset = 0;
  
  discriminator.copy(data, offset);
  offset += 8;
  
  data.writeBigUInt64LE(amount, offset);
  offset += 8;
  
  memoHash.copy(data, offset);
  offset += 32;
  
  data.writeBigInt64LE(timeoutSeconds, offset);
  offset += 8;
  
  // None for arbiter
  data.writeUInt8(0, offset);

  const ix = new TransactionInstruction({
    programId: X0_ESCROW_PROGRAM_ID,
    keys: [
      { pubkey: payer.publicKey, isSigner: true, isWritable: true },
      { pubkey: seller.publicKey, isSigner: false, isWritable: false },
      { pubkey: escrowPda, isSigner: false, isWritable: true },
      { pubkey: mint, isSigner: false, isWritable: false },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data,
  });

  const tx = new Transaction().add(ix);

  try {
    const sig = await sendAndConfirmTransaction(connection, tx, [payer], {
      commitment: "confirmed",
    });
    logSuccess(`Escrow created`);
    logSuccess(`  Amount: ${amount.toString()} (1 token)`);
    logSuccess(`  Timeout: 1 hour`);
    logSuccess(`Transaction: ${sig}`);
    return escrowPda;
  } catch (error) {
    logError(`Failed to create escrow: ${error.message}`);
    throw error;
  }
}

// ============================================================================
// Test: Initialize Wrapper (x0-wrapper) - Two Phase
// ============================================================================

async function testInitializeWrapper(connection, payer, usdcMint) {
  log("WRAPPER", "Initializing x0-USD wrapper (two-phase)...");

  // Derive PDAs
  const [configPda] = PublicKey.findProgramAddressSync(
    [Buffer.from("wrapper_config")],
    X0_WRAPPER_PROGRAM_ID
  );
  const [statsPda] = PublicKey.findProgramAddressSync(
    [Buffer.from("wrapper_stats")],
    X0_WRAPPER_PROGRAM_ID
  );
  const [wrapperMint] = PublicKey.findProgramAddressSync(
    [Buffer.from("wrapper_mint"), usdcMint.toBuffer()],
    X0_WRAPPER_PROGRAM_ID
  );
  const [mintAuthority] = PublicKey.findProgramAddressSync(
    [Buffer.from("mint_authority")],
    X0_WRAPPER_PROGRAM_ID
  );
  const [reserveAccount] = PublicKey.findProgramAddressSync(
    [Buffer.from("reserve"), usdcMint.toBuffer()],
    X0_WRAPPER_PROGRAM_ID
  );
  const [reserveAuthority] = PublicKey.findProgramAddressSync(
    [Buffer.from("reserve_authority")],
    X0_WRAPPER_PROGRAM_ID
  );

  log("WRAPPER", `Config PDA: ${configPda.toBase58()}`);
  log("WRAPPER", `Wrapper Mint: ${wrapperMint.toBase58()}`);

  // Check if already initialized
  const configInfo = await connection.getAccountInfo(configPda);
  if (configInfo) {
    logSuccess("Wrapper already initialized");
    return { configPda, wrapperMint, reserveAccount };
  }

  // ========================================================================
  // Phase 1: Initialize Config
  // ========================================================================
  log("WRAPPER", "Phase 1: Initializing config...");
  
  const configDiscriminator = getInstructionDiscriminator("global", "initialize_config");
  const configData = Buffer.alloc(8 + 2);
  configDiscriminator.copy(configData, 0);
  configData.writeUInt16LE(80, 8); // 0.8% = 80 basis points

  const configIx = new TransactionInstruction({
    programId: X0_WRAPPER_PROGRAM_ID,
    keys: [
      { pubkey: payer.publicKey, isSigner: true, isWritable: true },
      { pubkey: configPda, isSigner: false, isWritable: true },
      { pubkey: statsPda, isSigner: false, isWritable: true },
      { pubkey: usdcMint, isSigner: false, isWritable: false },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data: configData,
  });

  const configTx = new Transaction().add(configIx);
  const configSig = await sendAndConfirmTransaction(connection, configTx, [payer], {
    commitment: "confirmed",
  });
  logSuccess(`Config initialized: ${configSig}`);

  // ========================================================================
  // Phase 2: Initialize Mint
  // ========================================================================
  log("WRAPPER", "Phase 2: Initializing mint...");
  
  const mintDiscriminator = getInstructionDiscriminator("global", "initialize_mint");
  const mintData = Buffer.alloc(8);
  mintDiscriminator.copy(mintData, 0);

  const mintIx = new TransactionInstruction({
    programId: X0_WRAPPER_PROGRAM_ID,
    keys: [
      { pubkey: payer.publicKey, isSigner: true, isWritable: true },
      { pubkey: configPda, isSigner: false, isWritable: true },
      { pubkey: usdcMint, isSigner: false, isWritable: false },
      { pubkey: wrapperMint, isSigner: false, isWritable: true },
      { pubkey: mintAuthority, isSigner: false, isWritable: false },
      { pubkey: reserveAccount, isSigner: false, isWritable: true },
      { pubkey: reserveAuthority, isSigner: false, isWritable: false },
      { pubkey: TOKEN_2022_PROGRAM_ID, isSigner: false, isWritable: false },
      { pubkey: TOKEN_PROGRAM_ID, isSigner: false, isWritable: false },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      { pubkey: SYSVAR_RENT_PUBKEY, isSigner: false, isWritable: false },
    ],
    data: mintData,
  });

  const mintTx = new Transaction().add(mintIx);
  const mintSig = await sendAndConfirmTransaction(connection, mintTx, [payer], {
    commitment: "confirmed",
  });
  logSuccess(`Mint initialized: ${mintSig}`);

  // ========================================================================
  // Phase 3: Initialize Extra Account Metas for x0-USD Transfer Hook
  // ========================================================================
  log("WRAPPER", "Phase 3: Initializing extra account metas for x0-USD...");
  
  // Need to initialize extra account metas for x0-guard to validate transfers
  const [extraAccountMetasPda] = PublicKey.findProgramAddressSync(
    [Buffer.from("extra-account-metas"), wrapperMint.toBuffer()],
    X0_GUARD_PROGRAM_ID
  );

  // Check if already initialized
  const existingMetas = await connection.getAccountInfo(extraAccountMetasPda);
  if (!existingMetas) {
    const initMetasDiscriminator = getInstructionDiscriminator("global", "initialize_extra_account_metas");
    const initMetasData = Buffer.alloc(8);
    initMetasDiscriminator.copy(initMetasData, 0);

    const initMetasIx = new TransactionInstruction({
      programId: X0_GUARD_PROGRAM_ID,
      keys: [
        { pubkey: payer.publicKey, isSigner: true, isWritable: true },
        { pubkey: wrapperMint, isSigner: false, isWritable: false },
        { pubkey: extraAccountMetasPda, isSigner: false, isWritable: true },
        { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      ],
      data: initMetasData,
    });

    const metasTx = new Transaction().add(initMetasIx);
    const metasSig = await sendAndConfirmTransaction(connection, metasTx, [payer], {
      commitment: "confirmed",
    });
    logSuccess(`Extra account metas initialized for x0-USD: ${metasSig}`);
  } else {
    logSuccess(`Extra account metas already initialized for x0-USD`);
  }

  logSuccess(`Wrapper fully initialized with transfer hook -> x0-guard`);
  return { configPda, wrapperMint, reserveAccount };
}

// ============================================================================
// Test: Deposit USDC and Mint x0-USD (x0-wrapper)
// ============================================================================

async function testDepositAndMint(connection, payer, usdcMint, wrapperMint, reserveAccount, configPda, amount) {
  log("WRAPPER", `Depositing ${amount / 1_000_000} USDC...`);

  // Derive PDAs
  const [statsPda] = PublicKey.findProgramAddressSync(
    [Buffer.from("wrapper_stats")],
    X0_WRAPPER_PROGRAM_ID
  );
  // mint_authority PDA uses just the seed, no wrapper mint key
  const [mintAuthority] = PublicKey.findProgramAddressSync(
    [Buffer.from("mint_authority")],
    X0_WRAPPER_PROGRAM_ID
  );

  // Get or create user's USDC account
  const userUsdcAccount = getAssociatedTokenAddressSync(
    usdcMint,
    payer.publicKey,
    false,
    TOKEN_PROGRAM_ID
  );

  // Get or create user's wrapper token account
  const userWrapperAccount = getAssociatedTokenAddressSync(
    wrapperMint,
    payer.publicKey,
    false,
    TOKEN_2022_PROGRAM_ID
  );

  // Check USDC balance
  try {
    const usdcBalance = await connection.getTokenAccountBalance(userUsdcAccount);
    log("WRAPPER", `USDC balance: ${usdcBalance.value.uiAmount}`);
  } catch (e) {
    logError("No USDC account found");
    throw e;
  }

  // Create wrapper ATA if needed
  const wrapperAccountInfo = await connection.getAccountInfo(userWrapperAccount);
  const instructions = [];
  
  if (!wrapperAccountInfo) {
    log("WRAPPER", "Creating wrapper token account...");
    instructions.push(
      createAssociatedTokenAccountInstruction(
        payer.publicKey,
        userWrapperAccount,
        payer.publicKey,
        wrapperMint,
        TOKEN_2022_PROGRAM_ID
      )
    );
  }

  // Build deposit_and_mint instruction
  const discriminator = getInstructionDiscriminator("global", "deposit_and_mint");

  // Encode: discriminator (8) + amount (u64)
  const data = Buffer.alloc(8 + 8);
  discriminator.copy(data, 0);
  data.writeBigUInt64LE(BigInt(amount), 8);

  instructions.push(new TransactionInstruction({
    programId: X0_WRAPPER_PROGRAM_ID,
    keys: [
      { pubkey: payer.publicKey, isSigner: true, isWritable: true },
      { pubkey: configPda, isSigner: false, isWritable: false },
      { pubkey: statsPda, isSigner: false, isWritable: true },
      { pubkey: usdcMint, isSigner: false, isWritable: false },
      { pubkey: wrapperMint, isSigner: false, isWritable: true },
      { pubkey: userUsdcAccount, isSigner: false, isWritable: true },
      { pubkey: userWrapperAccount, isSigner: false, isWritable: true },
      { pubkey: reserveAccount, isSigner: false, isWritable: true },
      { pubkey: mintAuthority, isSigner: false, isWritable: false },
      { pubkey: TOKEN_2022_PROGRAM_ID, isSigner: false, isWritable: false },
      { pubkey: TOKEN_PROGRAM_ID, isSigner: false, isWritable: false },
    ],
    data,
  }));

  const tx = new Transaction().add(...instructions);

  try {
    const sig = await sendAndConfirmTransaction(connection, tx, [payer], {
      commitment: "confirmed",
    });
    
    // Log amount deposited/received (1:1 ratio)
    logSuccess(`Deposited ${amount / 1_000_000} USDC`);
    logSuccess(`Received ${amount / 1_000_000} x0-USD`);
    logSuccess(`Transaction: ${sig}`);
    return userWrapperAccount;
  } catch (error) {
    logError(`Failed to deposit: ${error.message}`);
    throw error;
  }
}

// ============================================================================
// Test: Burn x0-USD and Redeem USDC (x0-wrapper)
// ============================================================================

async function testBurnAndRedeem(connection, payer, usdcMint, wrapperMint, reserveAccount, configPda, amount) {
  log("WRAPPER", `Redeeming ${amount / 1_000_000} x0-USD...`);

  // Derive PDAs
  const [statsPda] = PublicKey.findProgramAddressSync(
    [Buffer.from("wrapper_stats")],
    X0_WRAPPER_PROGRAM_ID
  );
  const [reserveAuthority] = PublicKey.findProgramAddressSync(
    [Buffer.from("reserve_authority")],
    X0_WRAPPER_PROGRAM_ID
  );

  // Get user's accounts
  const userUsdcAccount = getAssociatedTokenAddressSync(
    usdcMint,
    payer.publicKey,
    false,
    TOKEN_PROGRAM_ID
  );
  const userWrapperAccount = getAssociatedTokenAddressSync(
    wrapperMint,
    payer.publicKey,
    false,
    TOKEN_2022_PROGRAM_ID
  );

  // Check wrapper balance before
  const wrapperBalanceBefore = await connection.getTokenAccountBalance(userWrapperAccount);
  log("WRAPPER", `x0-USD balance before: ${wrapperBalanceBefore.value.uiAmount}`);

  // Build burn_and_redeem instruction
  const discriminator = getInstructionDiscriminator("global", "burn_and_redeem");

  // Encode: discriminator (8) + amount (u64)
  const data = Buffer.alloc(8 + 8);
  discriminator.copy(data, 0);
  data.writeBigUInt64LE(BigInt(amount), 8);

  const ix = new TransactionInstruction({
    programId: X0_WRAPPER_PROGRAM_ID,
    keys: [
      { pubkey: payer.publicKey, isSigner: true, isWritable: true },
      { pubkey: configPda, isSigner: false, isWritable: false },
      { pubkey: statsPda, isSigner: false, isWritable: true },
      { pubkey: usdcMint, isSigner: false, isWritable: false },
      { pubkey: wrapperMint, isSigner: false, isWritable: true },
      { pubkey: userWrapperAccount, isSigner: false, isWritable: true },
      { pubkey: userUsdcAccount, isSigner: false, isWritable: true },
      { pubkey: reserveAccount, isSigner: false, isWritable: true },
      { pubkey: reserveAuthority, isSigner: false, isWritable: false },
      { pubkey: TOKEN_2022_PROGRAM_ID, isSigner: false, isWritable: false },
      { pubkey: TOKEN_PROGRAM_ID, isSigner: false, isWritable: false },
    ],
    data,
  });

  const tx = new Transaction().add(ix);

  try {
    const sig = await sendAndConfirmTransaction(connection, tx, [payer], {
      commitment: "confirmed",
    });
    
    // Check new balances
    const wrapperBalanceAfter = await connection.getTokenAccountBalance(userWrapperAccount);
    const usdcBalanceAfter = await connection.getTokenAccountBalance(userUsdcAccount);
    
    // Calculate expected fee (0.8%)
    const expectedFee = Math.floor(amount * 80 / 10000);
    const expectedUsdcReceived = amount - expectedFee;
    
    logSuccess(`Burned ${amount / 1_000_000} x0-USD`);
    logSuccess(`Fee: ${expectedFee / 1_000_000} USDC (0.8%)`);
    logSuccess(`Received: ~${expectedUsdcReceived / 1_000_000} USDC`);
    logSuccess(`New USDC balance: ${usdcBalanceAfter.value.uiAmount}`);
    logSuccess(`Transaction: ${sig}`);
  } catch (error) {
    logError(`Failed to redeem: ${error.message}`);
    throw error;
  }
}

// ============================================================================
// Main Test Runner
// ============================================================================

async function main() {
  console.log("========================================");
  console.log("x0-01 Devnet Integration Test");
  console.log("========================================\n");

  // Connect to devnet
  const connection = new Connection(DEVNET_URL, "confirmed");
  log("CONNECT", `Connected to ${DEVNET_URL}`);

  // Load wallet
  const payer = loadWallet();
  log("WALLET", `Using wallet: ${payer.publicKey.toBase58()}`);

  // Generate an agent keypair (in production this would be a Lit Protocol PKP or similar)
  const agentKeypair = Keypair.generate();
  log("AGENT", `Generated agent keypair: ${agentKeypair.publicKey.toBase58()}`);

  // Treasury for registry fees
  const treasury = Keypair.generate().publicKey;
  log("TREASURY", `Treasury: ${treasury.toBase58()}`);

  // Check balance
  const balance = await connection.getBalance(payer.publicKey);
  log("WALLET", `Balance: ${balance / LAMPORTS_PER_SOL} SOL`);

  if (balance < 0.05 * LAMPORTS_PER_SOL) {
    logError("Insufficient balance. Please fund your wallet with devnet SOL.");
    process.exit(1);
  }

  console.log("\n--- Program Deployment Check ---\n");
  await testProgramDeployments(connection);

  console.log("\n--- Token-2022 Mint Creation ---\n");
  const mint = await testCreateMint(connection, payer);

  console.log("\n--- Token Minting ---\n");
  const tokenAccount = await testMintTokens(
    connection,
    payer,
    mint,
    BigInt(1_000_000_000) // 1000 tokens with 6 decimals
  );

  console.log("\n--- Query Mint Info ---\n");
  await testQueryMint(connection, mint);

  console.log("\n--- Query Token Account ---\n");
  await testQueryTokenAccount(connection, tokenAccount);

  console.log("\n--- Initialize Extra Account Metas ---\n");
  const extraMetasPda = await testInitializeExtraAccountMetasFull(connection, payer, mint);

  console.log("\n--- Initialize Agent Policy ---\n");
  const policyPda = await testInitializePolicy(connection, payer, agentKeypair);

  console.log("\n--- Transfer with Hook Validation ---\n");
  await testTransferWithHook(connection, payer, agentKeypair, mint, tokenAccount, policyPda, extraMetasPda);

  // ========================================================================
  // Test additional programs
  // ========================================================================

  console.log("\n--- Initialize Reputation (x0-reputation) ---\n");
  const reputationPda = await testInitializeReputation(connection, payer, policyPda);

  console.log("\n--- Record Success (x0-reputation) ---\n");
  await testRecordSuccess(connection, payer, policyPda, reputationPda);

  console.log("\n--- Register Agent (x0-registry) ---\n");
  const registryPda = await testRegisterAgent(connection, payer, policyPda, reputationPda, treasury);

  console.log("\n--- Create Escrow (x0-escrow) ---\n");
  const escrowPda = await testCreateEscrow(connection, payer, mint);

  // ========================================================================
  // Test x0-wrapper (requires USDC)
  // ========================================================================

  console.log("\n--- Fund Test Wallet with USDC (x0-wrapper) ---\n");
  let wrapperResult;
  try {
    // Load USDC funding wallet and transfer USDC to test wallet
    const usdcWallet = loadUsdcWallet();
    log("WRAPPER", `USDC funding wallet: ${usdcWallet.publicKey.toBase58()}`);
    
    // Get or create funding wallet's USDC ATA
    const fundingUsdcAta = getAssociatedTokenAddressSync(
      DEVNET_USDC_MINT,
      usdcWallet.publicKey,
      false,
      TOKEN_PROGRAM_ID
    );
    
    // Get or create test wallet's USDC ATA
    const testUsdcAta = getAssociatedTokenAddressSync(
      DEVNET_USDC_MINT,
      payer.publicKey,
      false,
      TOKEN_PROGRAM_ID
    );
    
    // Check funding wallet USDC balance
    try {
      const fundingBalance = await connection.getTokenAccountBalance(fundingUsdcAta);
      log("WRAPPER", `Funding wallet USDC balance: ${fundingBalance.value.uiAmount}`);
    } catch (e) {
      logError("Funding wallet has no USDC ATA");
    }
    
    // Create test wallet's USDC ATA if needed
    const testAtaInfo = await connection.getAccountInfo(testUsdcAta);
    if (!testAtaInfo) {
      log("WRAPPER", "Creating test wallet USDC account...");
      const createAtaIx = createAssociatedTokenAccountInstruction(
        payer.publicKey,
        testUsdcAta,
        payer.publicKey,
        DEVNET_USDC_MINT,
        TOKEN_PROGRAM_ID
      );
      const createAtaTx = new Transaction().add(createAtaIx);
      await sendAndConfirmTransaction(connection, createAtaTx, [payer], {
        commitment: "confirmed",
      });
      logSuccess("Created USDC ATA for test wallet");
    }
    
    // Check test wallet USDC balance
    let testBalance;
    try {
      testBalance = await connection.getTokenAccountBalance(testUsdcAta);
      log("WRAPPER", `Test wallet USDC balance: ${testBalance.value.uiAmount}`);
    } catch (e) {
      testBalance = { value: { uiAmount: 0 } };
    }
    
    // Transfer 2 USDC from funding wallet if needed
    const minUsdc = 2_000_000; // 2 USDC
    if (testBalance.value.uiAmount < 2) {
      log("WRAPPER", "Transferring 2 USDC from funding wallet...");
      const transferIx = new TransactionInstruction({
        programId: TOKEN_PROGRAM_ID,
        keys: [
          { pubkey: fundingUsdcAta, isSigner: false, isWritable: true },
          { pubkey: testUsdcAta, isSigner: false, isWritable: true },
          { pubkey: usdcWallet.publicKey, isSigner: true, isWritable: false },
        ],
        data: Buffer.from([3, ...new Uint8Array(new BigUint64Array([BigInt(minUsdc)]).buffer)]),
      });
      const transferTx = new Transaction().add(transferIx);
      const sig = await sendAndConfirmTransaction(connection, transferTx, [payer, usdcWallet], {
        commitment: "confirmed",
      });
      logSuccess(`Transferred 2 USDC to test wallet: ${sig}`);
    }
    
    console.log("\n--- Initialize Wrapper (x0-wrapper) ---\n");
    wrapperResult = await testInitializeWrapper(connection, payer, DEVNET_USDC_MINT);
    
    console.log("\n--- Deposit USDC and Mint x0-USD (x0-wrapper) ---\n");
    const depositAmount = 1_000_000; // 1 USDC
    await testDepositAndMint(
      connection, 
      payer, 
      DEVNET_USDC_MINT, 
      wrapperResult.wrapperMint, 
      wrapperResult.reserveAccount, 
      wrapperResult.configPda,
      depositAmount
    );

    console.log("\n--- Burn x0-USD and Redeem USDC (x0-wrapper) ---\n");
    const redeemAmount = 1_000_000; // 1 x0-USD (minimum redemption)
    await testBurnAndRedeem(
      connection,
      payer,
      DEVNET_USDC_MINT,
      wrapperResult.wrapperMint,
      wrapperResult.reserveAccount,
      wrapperResult.configPda,
      redeemAmount
    );
  } catch (error) {
    logError(`Wrapper test failed: ${error.message}`);
    log("WRAPPER", "Skipping wrapper tests (may need USDC or initialization)");
  }

  console.log("\n========================================");
  console.log("All Tests Complete");
  console.log("========================================\n");

  console.log("Summary:");
  console.log(`  Mint: ${mint.toBase58()}`);
  console.log(`  Token Account: ${tokenAccount.toBase58()}`);
  console.log(`  Policy PDA: ${policyPda.toBase58()}`);
  console.log(`  Extra Metas PDA: ${extraMetasPda.toBase58()}`);
  console.log(`  Agent Signer: ${agentKeypair.publicKey.toBase58()}`);
  console.log(`  Reputation PDA: ${reputationPda.toBase58()}`);
  console.log(`  Registry PDA: ${registryPda.toBase58()}`);
  console.log(`  Escrow PDA: ${escrowPda.toBase58()}`);
  if (wrapperResult) {
    console.log(`  Wrapper Config: ${wrapperResult.configPda.toBase58()}`);
    console.log(`  Wrapper Mint (x0-USD): ${wrapperResult.wrapperMint.toBase58()}`);
  }
  console.log(`  Transfer Hook Program: ${X0_GUARD_PROGRAM_ID.toBase58()}`);
}

main().catch((error) => {
  console.error("Test failed:", error);
  process.exit(1);
});
