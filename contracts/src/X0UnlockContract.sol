// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/// @title ISP1Verifier
/// @notice Interface for the SP1 STARK proof verifier deployed on Base
/// @dev The official SP1 verifier contract: https://docs.succinct.xyz/
interface ISP1Verifier {
    /// @notice Verifies an SP1 proof
    /// @param programVKey The verification key of the SP1 program
    /// @param publicValues The public values committed by the proof
    /// @param proofBytes The encoded SP1 proof
    function verifyProof(
        bytes32 programVKey,
        bytes calldata publicValues,
        bytes calldata proofBytes
    ) external view;
}

/// @title X0UnlockContract
/// @author x0 Protocol Core Team
/// @notice Releases USDC on Base after verifying SP1 STARK proofs of Solana burns.
///
/// @dev This is the outbound bridge endpoint (Solana → Base):
///   1. User burns x0-USD on Solana via x0-bridge::initiate_bridge_out()
///   2. This creates a BridgeOutMessage PDA on Solana
///   3. SP1 Solana prover generates a STARK proof of the PDA's existence
///   4. Anyone submits the proof to this contract's unlock() function
///   5. Contract verifies proof via SP1Verifier and releases USDC to recipient
///
/// Security:
///   - SP1 STARK proof verification (trustless, same security as inbound direction)
///   - Replay protection via processedNonces mapping
///   - Daily outflow rate limiting
///   - Per-transaction amount limits
///   - Pausable by admin in emergencies
///   - Reentrancy-guarded
///   - Admin can deposit USDC liquidity
///
/// @custom:security-contact security@x0protocol.dev
contract X0UnlockContract is Ownable, Pausable, ReentrancyGuard {
    using SafeERC20 for IERC20;

    // ========================================================================
    // Events
    // ========================================================================

    /// @notice Emitted when USDC is released after SP1 proof verification
    /// @param evmRecipient The Base address receiving USDC
    /// @param solanaSender The Solana address that burned x0-USD (32 bytes)
    /// @param amount The amount of USDC released (6 decimals)
    /// @param nonce The outbound bridge nonce from Solana
    event Unlocked(
        address indexed evmRecipient,
        bytes32 indexed solanaSender,
        uint256 amount,
        uint256 nonce
    );

    /// @notice Emitted when USDC is deposited for liquidity
    /// @param depositor The address that deposited USDC
    /// @param amount The amount deposited
    event Deposited(address indexed depositor, uint256 amount);

    /// @notice Emitted when admin withdraws excess USDC
    /// @param to Recipient of the withdrawal
    /// @param amount Amount withdrawn
    event AdminWithdraw(address indexed to, uint256 amount);

    /// @notice Emitted when configuration is updated
    event ConfigUpdated(string parameter);

    /// @notice Emitted when circuit breaker is triggered
    event CircuitBreakerTriggered(uint256 totalUnlocked, uint256 threshold);

    // ========================================================================
    // Errors
    // ========================================================================

    error AmountTooSmall(uint256 amount, uint256 minimum);
    error AmountTooLarge(uint256 amount, uint256 maximum);
    error InvalidRecipient();
    error DailyLimitExceeded(uint256 requested, uint256 remaining);
    error NonceAlreadyProcessed(uint256 nonce);
    error InsufficientLiquidity(uint256 requested, uint256 available);
    error ZeroAddress();
    error ProofVerificationFailed();
    error InvalidPublicValues();
    error InvalidProgramVKey();

    // ========================================================================
    // Immutables
    // ========================================================================

    /// @notice USDC token contract on Base (6 decimals)
    IERC20 public immutable USDC;

    /// @notice SP1 Verifier contract on Base
    ISP1Verifier public immutable SP1_VERIFIER;

    // ========================================================================
    // State Variables
    // ========================================================================

    /// @notice Verification key of the SP1 Solana prover program
    /// @dev Set during construction, updatable by admin (with care)
    bytes32 public programVKey;

    /// @notice x0-bridge program ID on Solana (for public values validation)
    bytes32 public solanaBridgeProgram;

    /// @notice Minimum unlock amount (USDC base units, 6 decimals)
    /// @dev Must match Solana MIN_BRIDGE_OUT_AMOUNT: 10 USDC = 10_000_000
    uint256 public minUnlockAmount;

    /// @notice Maximum unlock amount per transaction (USDC base units)
    /// @dev Must match Solana MAX_BRIDGE_OUT_AMOUNT_PER_TX: 100K USDC = 100_000_000_000
    uint256 public maxUnlockAmount;

    /// @notice Daily volume limit for unlocks (USDC base units)
    /// @dev Must match Solana MAX_DAILY_BRIDGE_OUTFLOW: 5M USDC = 5_000_000_000_000
    uint256 public dailyLimit;

    /// @notice Current daily unlock volume
    uint256 public dailyVolume;

    /// @notice Timestamp of last daily volume reset
    uint256 public dailyVolumeResetAt;

    /// @notice Total USDC unlocked (all-time)
    uint256 public totalUnlockedAmount;

    /// @notice Total USDC deposited as liquidity
    uint256 public totalDeposited;

    /// @notice Circuit breaker threshold (auto-pause if exceeded)
    /// @dev Must match Solana BRIDGE_OUT_CIRCUIT_BREAKER_THRESHOLD
    uint256 public circuitBreakerThreshold;

    /// @notice Mapping to track processed nonces (replay protection)
    /// @dev nonce => true if already processed
    mapping(uint256 => bool) public processedNonces;

    // ========================================================================
    // Constructor
    // ========================================================================

    /// @param _usdc USDC token address on Base
    /// @param _sp1Verifier SP1 Verifier contract address on Base
    /// @param _programVKey Verification key of the SP1 Solana prover program
    /// @param _solanaBridgeProgram x0-bridge program ID on Solana (bytes32)
    /// @param _admin Admin address (should be multisig)
    constructor(
        address _usdc,
        address _sp1Verifier,
        bytes32 _programVKey,
        bytes32 _solanaBridgeProgram,
        address _admin
    ) Ownable(_admin) {
        if (_usdc == address(0)) revert ZeroAddress();
        if (_sp1Verifier == address(0)) revert ZeroAddress();
        if (_programVKey == bytes32(0)) revert InvalidProgramVKey();
        if (_solanaBridgeProgram == bytes32(0)) revert ZeroAddress();

        USDC = IERC20(_usdc);
        SP1_VERIFIER = ISP1Verifier(_sp1Verifier);
        programVKey = _programVKey;
        solanaBridgeProgram = _solanaBridgeProgram;

        // Default limits matching Solana constants
        minUnlockAmount = 10_000_000;              // 10 USDC
        maxUnlockAmount = 100_000_000_000;         // 100K USDC
        dailyLimit = 5_000_000_000_000;            // 5M USDC
        circuitBreakerThreshold = 100_000_000_000_000; // 100M USDC
        dailyVolumeResetAt = block.timestamp;
    }

    // ========================================================================
    // Core: Unlock USDC with SP1 Proof
    // ========================================================================

    /// @notice Release USDC to an EVM recipient after verifying an SP1 STARK proof
    ///         that a BridgeOutMessage PDA exists on Solana with the specified burn details.
    ///
    /// @dev Public values layout (ABI-encoded from SP1 Solana prover):
    ///   - bridgeProgramId: bytes32   — Solana x0-bridge program ID
    ///   - nonce:           uint64    — Outbound bridge nonce
    ///   - solanaSender:    bytes32   — Solana address that burned x0-USD
    ///   - evmRecipient:    address   — Base address to receive USDC (20 bytes)
    ///   - amount:          uint64    — Amount in USDC micro-units (6 decimals)
    ///   - burnTimestamp:   int64     — Unix timestamp of the burn on Solana
    ///   - accountHash:     bytes32   — SHA256 hash of the BridgeOutMessage account data
    ///
    /// @param proofBytes The SP1 STARK proof bytes
    /// @param publicValues The ABI-encoded public values from the proof
    function unlock(
        bytes calldata proofBytes,
        bytes calldata publicValues
    ) external whenNotPaused nonReentrant {
        // ====================================================================
        // Step 1: Decode public values
        // ====================================================================

        (
            bytes32 proofBridgeProgram,
            uint64 proofNonce,
            bytes32 proofSolanaSender,
            address proofEvmRecipient,
            uint64 proofAmount,
            /* int64 proofBurnTimestamp */,
            /* bytes32 proofAccountHash */
        ) = abi.decode(
            publicValues,
            (bytes32, uint64, bytes32, address, uint64, int64, bytes32)
        );

        // ====================================================================
        // Step 2: Validate public values
        // ====================================================================

        // Verify the proof is for our bridge program
        if (proofBridgeProgram != solanaBridgeProgram) {
            revert InvalidPublicValues();
        }

        // Validate recipient
        if (proofEvmRecipient == address(0)) {
            revert InvalidRecipient();
        }

        // Validate amount
        uint256 amount = uint256(proofAmount);
        if (amount < minUnlockAmount) {
            revert AmountTooSmall(amount, minUnlockAmount);
        }
        if (amount > maxUnlockAmount) {
            revert AmountTooLarge(amount, maxUnlockAmount);
        }

        // Check replay protection
        uint256 nonceVal = uint256(proofNonce);
        if (processedNonces[nonceVal]) {
            revert NonceAlreadyProcessed(nonceVal);
        }

        // ====================================================================
        // Step 3: Verify SP1 STARK proof
        // ====================================================================

        // This reverts if the proof is invalid
        try SP1_VERIFIER.verifyProof(programVKey, publicValues, proofBytes) {
            // Proof verified successfully
        } catch {
            revert ProofVerificationFailed();
        }

        // ====================================================================
        // Step 4: Check rate limits
        // ====================================================================

        _checkAndUpdateDailyVolume(amount);

        // Check liquidity
        uint256 balance = USDC.balanceOf(address(this));
        if (balance < amount) {
            revert InsufficientLiquidity(amount, balance);
        }

        // ====================================================================
        // Step 5: Update state BEFORE transfer (reentrancy protection)
        // ====================================================================

        processedNonces[nonceVal] = true;
        totalUnlockedAmount += amount;

        // Circuit breaker check
        if (totalUnlockedAmount > circuitBreakerThreshold) {
            _pause();
            emit CircuitBreakerTriggered(totalUnlockedAmount, circuitBreakerThreshold);
            // Still complete this unlock since proof is valid, but pause after
        }

        // ====================================================================
        // Step 6: Transfer USDC to recipient
        // ====================================================================

        USDC.safeTransfer(proofEvmRecipient, amount);

        emit Unlocked(proofEvmRecipient, proofSolanaSender, amount, nonceVal);
    }

    // ========================================================================
    // Liquidity Management
    // ========================================================================

    /// @notice Deposit USDC into the unlock pool
    /// @dev Anyone can deposit. Admin should manage rebalancing from X0LockContract.
    /// @param amount Amount of USDC to deposit
    function deposit(uint256 amount) external {
        if (amount == 0) revert AmountTooSmall(0, 1);

        USDC.safeTransferFrom(msg.sender, address(this), amount);
        totalDeposited += amount;

        emit Deposited(msg.sender, amount);
    }

    /// @notice Get current USDC balance available for unlocks
    function availableLiquidity() external view returns (uint256) {
        return USDC.balanceOf(address(this));
    }

    // ========================================================================
    // Admin: Configuration
    // ========================================================================

    /// @notice Update the SP1 program verification key
    /// @dev CRITICAL: Only change if redeploying the SP1 Solana prover program
    function setProgramVKey(bytes32 _programVKey) external onlyOwner {
        if (_programVKey == bytes32(0)) revert InvalidProgramVKey();
        programVKey = _programVKey;
        emit ConfigUpdated("programVKey");
    }

    /// @notice Update the Solana bridge program ID
    function setSolanaBridgeProgram(bytes32 _solanaBridgeProgram) external onlyOwner {
        if (_solanaBridgeProgram == bytes32(0)) revert ZeroAddress();
        solanaBridgeProgram = _solanaBridgeProgram;
        emit ConfigUpdated("solanaBridgeProgram");
    }

    function setMinUnlockAmount(uint256 _minUnlockAmount) external onlyOwner {
        minUnlockAmount = _minUnlockAmount;
        emit ConfigUpdated("minUnlockAmount");
    }

    function setMaxUnlockAmount(uint256 _maxUnlockAmount) external onlyOwner {
        maxUnlockAmount = _maxUnlockAmount;
        emit ConfigUpdated("maxUnlockAmount");
    }

    function setDailyLimit(uint256 _dailyLimit) external onlyOwner {
        dailyLimit = _dailyLimit;
        emit ConfigUpdated("dailyLimit");
    }

    function setCircuitBreakerThreshold(uint256 _threshold) external onlyOwner {
        circuitBreakerThreshold = _threshold;
        emit ConfigUpdated("circuitBreakerThreshold");
    }

    /// @notice Withdraw USDC (admin rebalancing)
    function adminWithdrawUsdc(address to, uint256 amount) external onlyOwner {
        if (to == address(0)) revert ZeroAddress();
        USDC.safeTransfer(to, amount);
        emit AdminWithdraw(to, amount);
    }

    function pause() external onlyOwner {
        _pause();
    }

    function unpause() external onlyOwner {
        _unpause();
    }

    // ========================================================================
    // View Functions
    // ========================================================================

    /// @notice Check if a nonce has been processed
    function isNonceProcessed(uint256 nonceVal) external view returns (bool) {
        return processedNonces[nonceVal];
    }

    /// @notice Get remaining daily unlock volume
    function remainingDailyVolume() external view returns (uint256) {
        if (block.timestamp >= dailyVolumeResetAt + 1 days) {
            return dailyLimit;
        }
        if (dailyVolume >= dailyLimit) {
            return 0;
        }
        return dailyLimit - dailyVolume;
    }

    // ========================================================================
    // Internal Helpers
    // ========================================================================

    /// @dev Check and update daily volume, reverting if limit exceeded
    function _checkAndUpdateDailyVolume(uint256 amount) internal {
        if (block.timestamp >= dailyVolumeResetAt + 1 days) {
            dailyVolume = 0;
            dailyVolumeResetAt = block.timestamp;
        }

        uint256 newVolume = dailyVolume + amount;
        if (newVolume > dailyLimit) {
            revert DailyLimitExceeded(amount, dailyLimit - dailyVolume);
        }
        dailyVolume = newVolume;
    }
}
