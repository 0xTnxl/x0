// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/// @title IMailbox
/// @notice Minimal Hyperlane Mailbox interface for dispatching messages
interface IMailbox {
    function dispatch(
        uint32 destinationDomain,
        bytes32 recipientAddress,
        bytes calldata messageBody
    ) external payable returns (bytes32 messageId);

    function quoteDispatch(
        uint32 destinationDomain,
        bytes32 recipientAddress,
        bytes calldata messageBody
    ) external view returns (uint256 fee);
}

/// @title X0LockContract
/// @author x0 Protocol Core Team
/// @notice Locks USDC on Base (EVM) and dispatches Hyperlane messages
///         to the x0-bridge program on Solana for cross-chain minting.
///
/// @dev Flow:
///   1. User approves USDC spending to this contract
///   2. User calls lock() with amount and Solana recipient
///   3. Contract transfers USDC from user to itself (locked)
///   4. Contract dispatches a Hyperlane message to Solana
///   5. On Solana: x0-bridge receives message → verifies STARK proof → mints x0-USD
///
/// Security:
///   - Pausable by admin in case of emergency
///   - Reentrancy-guarded on lock()
///   - Minimum/maximum lock amounts enforced
///   - Nonce tracking prevents replay
///   - Admin can unlock and return funds in case of bridge failure
///
/// @custom:security-contact security@x0protocol.dev
contract X0LockContract is Ownable, Pausable, ReentrancyGuard {
    using SafeERC20 for IERC20;

    // ========================================================================
    // Events
    // ========================================================================

    /// @notice Emitted when USDC is locked for cross-chain bridging
    /// @param sender The EVM address that locked USDC
    /// @param solanaRecipient The Solana pubkey that will receive x0-USD (32 bytes)
    /// @param amount The amount of USDC locked (6 decimals)
    /// @param nonce Unique sequential nonce for this lock
    /// @param messageId Hyperlane message ID returned by dispatch
    event Locked(
        address indexed sender,
        bytes32 indexed solanaRecipient,
        uint256 amount,
        uint256 nonce,
        bytes32 messageId
    );

    /// @notice Emitted when locked USDC is returned by admin (failure recovery)
    /// @param recipient The EVM address receiving the returned USDC
    /// @param amount The amount of USDC returned
    /// @param nonce The nonce of the original lock
    event Unlocked(
        address indexed recipient,
        uint256 amount,
        uint256 nonce
    );

    /// @notice Emitted when the admin withdraws accumulated fees or excess funds
    event AdminWithdraw(address indexed to, uint256 amount);

    /// @notice Emitted when configuration parameters are updated
    event ConfigUpdated(string parameter);

    // ========================================================================
    // Errors
    // ========================================================================

    error AmountTooSmall(uint256 amount, uint256 minimum);
    error AmountTooLarge(uint256 amount, uint256 maximum);
    error InvalidSolanaRecipient();
    error DailyLimitExceeded(uint256 requested, uint256 remaining);
    error InsufficientMsgValue(uint256 provided, uint256 required);
    error LockAlreadyUnlocked(uint256 nonce);
    error LockNotFound(uint256 nonce);
    error ZeroAddress();

    // ========================================================================
    // State Variables
    // ========================================================================

    /// @notice USDC token contract (6 decimals on Base)
    IERC20 public immutable usdc;

    /// @notice Hyperlane Mailbox contract for dispatching cross-chain messages
    IMailbox public immutable mailbox;

    /// @notice Solana destination domain ID in Hyperlane
    /// @dev Solana mainnet = 1399811149, devnet may differ
    uint32 public solanaDomain;

    /// @notice Address of the x0-bridge program on Solana (as bytes32)
    /// @dev This is the Hyperlane recipient address
    bytes32 public solanaBridgeAddress;

    /// @notice Monotonically increasing nonce for lock transactions
    uint256 public nonce;

    /// @notice Minimum lock amount (in USDC base units, 6 decimals)
    /// @dev Default: 1 USDC = 1_000_000
    uint256 public minLockAmount;

    /// @notice Maximum lock amount per transaction (in USDC base units)
    /// @dev Default: 10,000,000 USDC = 10_000_000_000_000
    uint256 public maxLockAmount;

    /// @notice Daily volume limit (in USDC base units)
    uint256 public dailyLimit;

    /// @notice Current daily volume
    uint256 public dailyVolume;

    /// @notice Timestamp of last daily volume reset
    uint256 public dailyVolumeResetAt;

    /// @notice Total USDC locked via this contract
    uint256 public totalLocked;

    /// @notice Total USDC unlocked (returned) via admin
    uint256 public totalUnlocked;

    // ========================================================================
    // Lock Record (for failure recovery / admin unlock)
    // ========================================================================

    struct LockRecord {
        address sender;
        bytes32 solanaRecipient;
        uint256 amount;
        uint256 timestamp;
        bytes32 messageId;
        bool unlocked; // true if admin returned funds
    }

    /// @notice Mapping from nonce to lock record
    mapping(uint256 => LockRecord) public lockRecords;

    // ========================================================================
    // Constructor
    // ========================================================================

    /// @param _usdc USDC token address on Base
    /// @param _mailbox Hyperlane Mailbox address on Base
    /// @param _solanaDomain Hyperlane domain ID for Solana
    /// @param _solanaBridgeAddress x0-bridge program address on Solana (bytes32)
    constructor(
        address _usdc,
        address _mailbox,
        uint32 _solanaDomain,
        bytes32 _solanaBridgeAddress,
        address _admin
    ) Ownable(_admin) {
        if (_usdc == address(0)) revert ZeroAddress();
        if (_mailbox == address(0)) revert ZeroAddress();
        if (_solanaBridgeAddress == bytes32(0)) revert InvalidSolanaRecipient();

        usdc = IERC20(_usdc);
        mailbox = IMailbox(_mailbox);
        solanaDomain = _solanaDomain;
        solanaBridgeAddress = _solanaBridgeAddress;

        // Default limits (USDC has 6 decimals)
        minLockAmount = 1_000_000;           // 1 USDC
        maxLockAmount = 10_000_000_000_000;  // 10M USDC
        dailyLimit = 50_000_000_000_000;     // 50M USDC
        dailyVolumeResetAt = block.timestamp;
    }

    // ========================================================================
    // Core: Lock USDC
    // ========================================================================

    /// @notice Lock USDC and dispatch a Hyperlane message to Solana
    /// @param amount Amount of USDC to lock (6 decimals)
    /// @param solanaRecipient Solana public key of the recipient (32 bytes)
    /// @return messageId Hyperlane message ID
    /// @return lockNonce The nonce assigned to this lock
    function lock(
        uint256 amount,
        bytes32 solanaRecipient
    )
        external
        payable
        whenNotPaused
        nonReentrant
        returns (bytes32 messageId, uint256 lockNonce)
    {
        // Validate inputs
        if (amount < minLockAmount) {
            revert AmountTooSmall(amount, minLockAmount);
        }
        if (amount > maxLockAmount) {
            revert AmountTooLarge(amount, maxLockAmount);
        }
        if (solanaRecipient == bytes32(0)) {
            revert InvalidSolanaRecipient();
        }

        // Check and update daily volume
        _checkAndUpdateDailyVolume(amount);

        // Assign nonce
        lockNonce = nonce;
        nonce += 1;

        // Transfer USDC from user to this contract
        usdc.safeTransferFrom(msg.sender, address(this), amount);
        totalLocked += amount;

        // Encode message body for Solana x0-bridge handle_message
        // Format: [solanaRecipient (32 bytes)][amount (u64 LE)][nonce (u64 LE)][evmSender (20 bytes)]
        bytes memory messageBody = abi.encodePacked(
            solanaRecipient,                    // 32 bytes
            _toLE64(uint64(amount)),            // 8 bytes (little-endian for Solana)
            _toLE64(uint64(lockNonce)),         // 8 bytes (little-endian for Solana)
            bytes20(msg.sender)                 // 20 bytes
        );

        // Get required fee for Hyperlane dispatch
        uint256 fee = mailbox.quoteDispatch(
            solanaDomain,
            solanaBridgeAddress,
            messageBody
        );
        if (msg.value < fee) {
            revert InsufficientMsgValue(msg.value, fee);
        }

        // Dispatch message via Hyperlane
        messageId = mailbox.dispatch{value: fee}(
            solanaDomain,
            solanaBridgeAddress,
            messageBody
        );

        // Store lock record
        lockRecords[lockNonce] = LockRecord({
            sender: msg.sender,
            solanaRecipient: solanaRecipient,
            amount: amount,
            timestamp: block.timestamp,
            messageId: messageId,
            unlocked: false
        });

        // Refund excess ETH
        if (msg.value > fee) {
            (bool success, ) = msg.sender.call{value: msg.value - fee}("");
            require(success, "ETH refund failed");
        }

        emit Locked(msg.sender, solanaRecipient, amount, lockNonce, messageId);
    }

    /// @notice Get a quote for the Hyperlane dispatch fee
    /// @param amount Amount of USDC (for message body construction)
    /// @param solanaRecipient Solana recipient pubkey
    /// @return fee Required ETH fee for the dispatch
    function quoteLock(
        uint256 amount,
        bytes32 solanaRecipient
    ) external view returns (uint256 fee) {
        bytes memory messageBody = abi.encodePacked(
            solanaRecipient,
            _toLE64(uint64(amount)),
            _toLE64(uint64(nonce)),
            bytes20(msg.sender)
        );

        fee = mailbox.quoteDispatch(
            solanaDomain,
            solanaBridgeAddress,
            messageBody
        );
    }

    // ========================================================================
    // Admin: Emergency Unlock
    // ========================================================================

    /// @notice Return locked USDC to original sender (failure recovery)
    /// @dev Only callable by admin for cases where bridging failed
    /// @param lockNonce The nonce of the lock to reverse
    function adminUnlock(uint256 lockNonce) external onlyOwner {
        LockRecord storage record = lockRecords[lockNonce];
        if (record.sender == address(0)) {
            revert LockNotFound(lockNonce);
        }
        if (record.unlocked) {
            revert LockAlreadyUnlocked(lockNonce);
        }

        record.unlocked = true;
        totalUnlocked += record.amount;

        usdc.safeTransfer(record.sender, record.amount);

        emit Unlocked(record.sender, record.amount, lockNonce);
    }

    /// @notice Withdraw excess funds (accumulated ETH fees, etc.)
    /// @param to Recipient address
    /// @param amount Amount to withdraw
    function adminWithdrawETH(address to, uint256 amount) external onlyOwner {
        if (to == address(0)) revert ZeroAddress();
        (bool success, ) = to.call{value: amount}("");
        require(success, "ETH withdrawal failed");
        emit AdminWithdraw(to, amount);
    }

    // ========================================================================
    // Admin: Configuration
    // ========================================================================

    function setSolanaDomain(uint32 _solanaDomain) external onlyOwner {
        solanaDomain = _solanaDomain;
        emit ConfigUpdated("solanaDomain");
    }

    function setSolanaBridgeAddress(bytes32 _solanaBridgeAddress) external onlyOwner {
        if (_solanaBridgeAddress == bytes32(0)) revert InvalidSolanaRecipient();
        solanaBridgeAddress = _solanaBridgeAddress;
        emit ConfigUpdated("solanaBridgeAddress");
    }

    function setMinLockAmount(uint256 _minLockAmount) external onlyOwner {
        minLockAmount = _minLockAmount;
        emit ConfigUpdated("minLockAmount");
    }

    function setMaxLockAmount(uint256 _maxLockAmount) external onlyOwner {
        maxLockAmount = _maxLockAmount;
        emit ConfigUpdated("maxLockAmount");
    }

    function setDailyLimit(uint256 _dailyLimit) external onlyOwner {
        dailyLimit = _dailyLimit;
        emit ConfigUpdated("dailyLimit");
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

    /// @notice Get lock record details
    function getLockRecord(uint256 lockNonce)
        external
        view
        returns (
            address sender,
            bytes32 solanaRecipient,
            uint256 amount,
            uint256 timestamp,
            bytes32 messageId,
            bool unlocked
        )
    {
        LockRecord storage record = lockRecords[lockNonce];
        return (
            record.sender,
            record.solanaRecipient,
            record.amount,
            record.timestamp,
            record.messageId,
            record.unlocked
        );
    }

    /// @notice Get total USDC currently locked (locked - unlocked)
    function activeLocked() external view returns (uint256) {
        return totalLocked - totalUnlocked;
    }

    /// @notice Get remaining daily volume
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
        // Reset daily volume if 24 hours have passed
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

    /// @dev Convert uint64 to little-endian bytes (for Solana compatibility)
    function _toLE64(uint64 value) internal pure returns (bytes8) {
        return bytes8(
            bytes8(uint64(
                ((uint64(value) & 0xFF) << 56) |
                ((uint64(value) & 0xFF00) << 40) |
                ((uint64(value) & 0xFF0000) << 24) |
                ((uint64(value) & 0xFF000000) << 8) |
                ((uint64(value) & 0xFF00000000) >> 8) |
                ((uint64(value) & 0xFF0000000000) >> 24) |
                ((uint64(value) & 0xFF000000000000) >> 40) |
                ((uint64(value) & 0xFF00000000000000) >> 56)
            ))
        );
    }

    /// @dev Allow contract to receive ETH (for Hyperlane fee refunds)
    receive() external payable {}
}
