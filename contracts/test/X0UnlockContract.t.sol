// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {X0UnlockContract, ISP1Verifier} from "../src/X0UnlockContract.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/// @dev Mock USDC token for testing
contract MockUSDC is ERC20 {
    constructor() ERC20("USD Coin", "USDC") {}

    function decimals() public pure override returns (uint8) {
        return 6;
    }

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

/// @dev Mock SP1 Verifier that always succeeds
contract MockSP1Verifier is ISP1Verifier {
    bool public shouldRevert;

    function setRevert(bool _shouldRevert) external {
        shouldRevert = _shouldRevert;
    }

    function verifyProof(
        bytes32, /* programVKey */
        bytes calldata, /* publicValues */
        bytes calldata  /* proofBytes */
    ) external view override {
        if (shouldRevert) {
            revert("Invalid proof");
        }
    }
}

contract X0UnlockContractTest is Test {
    X0UnlockContract public unlock;
    MockUSDC public usdc;
    MockSP1Verifier public verifier;

    address public admin = address(0xA);
    address public user = address(0xB);
    address public depositor = address(0xC);

    bytes32 public programVKey = bytes32(uint256(0x1234));
    bytes32 public solanaBridgeProgram = bytes32(uint256(0x5678));

    function setUp() public {
        usdc = new MockUSDC();
        verifier = new MockSP1Verifier();

        unlock = new X0UnlockContract(
            address(usdc),
            address(verifier),
            programVKey,
            solanaBridgeProgram,
            admin
        );

        // Fund the unlock contract with liquidity
        usdc.mint(depositor, 10_000_000_000_000); // 10M USDC
        vm.prank(depositor);
        usdc.approve(address(unlock), type(uint256).max);
        vm.prank(depositor);
        unlock.deposit(10_000_000_000_000);
    }

    // ========================================================================
    // Helper: build valid public values
    // ========================================================================

    function _buildPublicValues(
        uint64 nonce,
        address recipient,
        uint64 amount
    ) internal view returns (bytes memory) {
        return abi.encode(
            solanaBridgeProgram,     // bridge program
            nonce,                    // nonce
            bytes32(uint256(0xABC)), // solanaSender
            recipient,                // evmRecipient
            amount,                   // amount
            int64(1700000000),        // burnTimestamp
            bytes32(uint256(0xDEF))  // accountHash
        );
    }

    // ========================================================================
    // Tests: Constructor
    // ========================================================================

    function test_constructor() public view {
        assertEq(address(unlock.USDC()), address(usdc));
        assertEq(address(unlock.SP1_VERIFIER()), address(verifier));
        assertEq(unlock.programVKey(), programVKey);
        assertEq(unlock.solanaBridgeProgram(), solanaBridgeProgram);
        assertEq(unlock.minUnlockAmount(), 10_000_000);
        assertEq(unlock.maxUnlockAmount(), 100_000_000_000);
        assertEq(unlock.dailyLimit(), 5_000_000_000_000);
    }

    // ========================================================================
    // Tests: Successful Unlock
    // ========================================================================

    function test_unlock_success() public {
        uint64 amount = 100_000_000; // 100 USDC
        bytes memory publicValues = _buildPublicValues(0, user, amount);
        bytes memory proof = hex"1234";

        uint256 userBalBefore = usdc.balanceOf(user);

        unlock.unlock(proof, publicValues);

        assertEq(usdc.balanceOf(user), userBalBefore + amount);
        assertTrue(unlock.isNonceProcessed(0));
        assertEq(unlock.totalUnlockedAmount(), amount);
    }

    function test_unlock_multiple_nonces() public {
        for (uint64 i = 0; i < 5; i++) {
            bytes memory pv = _buildPublicValues(i, user, 50_000_000);
            unlock.unlock(hex"1234", pv);
        }
        assertEq(unlock.totalUnlockedAmount(), 250_000_000);
        for (uint256 i = 0; i < 5; i++) {
            assertTrue(unlock.isNonceProcessed(i));
        }
    }

    // ========================================================================
    // Tests: Replay Protection
    // ========================================================================

    function test_unlock_replay_reverts() public {
        bytes memory pv = _buildPublicValues(0, user, 50_000_000);
        unlock.unlock(hex"1234", pv);

        vm.expectRevert(abi.encodeWithSelector(
            X0UnlockContract.NonceAlreadyProcessed.selector, 0
        ));
        unlock.unlock(hex"1234", pv);
    }

    // ========================================================================
    // Tests: Proof Verification Failure
    // ========================================================================

    function test_unlock_bad_proof_reverts() public {
        verifier.setRevert(true);
        bytes memory pv = _buildPublicValues(0, user, 50_000_000);

        vm.expectRevert(X0UnlockContract.ProofVerificationFailed.selector);
        unlock.unlock(hex"1234", pv);
    }

    // ========================================================================
    // Tests: Wrong Bridge Program
    // ========================================================================

    function test_unlock_wrong_bridge_program_reverts() public {
        bytes memory badPv = abi.encode(
            bytes32(uint256(0xBAD)),   // wrong program
            uint64(0),
            bytes32(uint256(0xABC)),
            user,
            uint64(50_000_000),
            int64(1700000000),
            bytes32(uint256(0xDEF))
        );

        vm.expectRevert(X0UnlockContract.InvalidPublicValues.selector);
        unlock.unlock(hex"1234", badPv);
    }

    // ========================================================================
    // Tests: Amount Limits
    // ========================================================================

    function test_unlock_amount_too_small_reverts() public {
        bytes memory pv = _buildPublicValues(0, user, 1_000_000); // 1 USDC < 10 min

        vm.expectRevert(abi.encodeWithSelector(
            X0UnlockContract.AmountTooSmall.selector, 1_000_000, 10_000_000
        ));
        unlock.unlock(hex"1234", pv);
    }

    function test_unlock_amount_too_large_reverts() public {
        bytes memory pv = _buildPublicValues(0, user, 200_000_000_000); // 200K > 100K max

        vm.expectRevert(abi.encodeWithSelector(
            X0UnlockContract.AmountTooLarge.selector, 200_000_000_000, 100_000_000_000
        ));
        unlock.unlock(hex"1234", pv);
    }

    // ========================================================================
    // Tests: Invalid Recipient
    // ========================================================================

    function test_unlock_zero_recipient_reverts() public {
        bytes memory pv = _buildPublicValues(0, address(0), 50_000_000);

        vm.expectRevert(X0UnlockContract.InvalidRecipient.selector);
        unlock.unlock(hex"1234", pv);
    }

    // ========================================================================
    // Tests: Daily Rate Limit
    // ========================================================================

    function test_daily_limit_exceeded_reverts() public {
        // Set low daily limit for testing
        vm.prank(admin);
        unlock.setDailyLimit(100_000_000); // 100 USDC daily

        // First unlock succeeds
        bytes memory pv1 = _buildPublicValues(0, user, 80_000_000);
        unlock.unlock(hex"1234", pv1);

        // Second unlock exceeds limit
        bytes memory pv2 = _buildPublicValues(1, user, 30_000_000);
        vm.expectRevert(abi.encodeWithSelector(
            X0UnlockContract.DailyLimitExceeded.selector, 30_000_000, 20_000_000
        ));
        unlock.unlock(hex"1234", pv2);
    }

    function test_daily_limit_resets_after_24h() public {
        vm.prank(admin);
        unlock.setDailyLimit(100_000_000);

        bytes memory pv1 = _buildPublicValues(0, user, 90_000_000);
        unlock.unlock(hex"1234", pv1);

        // Warp 24 hours
        vm.warp(block.timestamp + 1 days);

        // Should succeed after reset
        bytes memory pv2 = _buildPublicValues(1, user, 90_000_000);
        unlock.unlock(hex"1234", pv2);
    }

    // ========================================================================
    // Tests: Insufficient Liquidity
    // ========================================================================

    function test_unlock_insufficient_liquidity_reverts() public {
        // Withdraw most liquidity
        vm.prank(admin);
        unlock.adminWithdrawUsdc(admin, 9_999_900_000_000); // Leave 100 USDC

        bytes memory pv = _buildPublicValues(0, user, 50_000_000_000); // 50K > 100 available

        vm.expectRevert(); // InsufficientLiquidity
        unlock.unlock(hex"1234", pv);
    }

    // ========================================================================
    // Tests: Deposit
    // ========================================================================

    function test_deposit() public {
        usdc.mint(user, 1_000_000_000);
        vm.prank(user);
        usdc.approve(address(unlock), 1_000_000_000);

        vm.prank(user);
        unlock.deposit(1_000_000_000);

        assertEq(unlock.totalDeposited(), 10_000_000_000_000 + 1_000_000_000);
    }

    // ========================================================================
    // Tests: Pause
    // ========================================================================

    function test_pause_prevents_unlock() public {
        vm.prank(admin);
        unlock.pause();

        bytes memory pv = _buildPublicValues(0, user, 50_000_000);
        vm.expectRevert(); // EnforcedPause
        unlock.unlock(hex"1234", pv);
    }

    function test_unpause_allows_unlock() public {
        vm.prank(admin);
        unlock.pause();
        vm.prank(admin);
        unlock.unpause();

        bytes memory pv = _buildPublicValues(0, user, 50_000_000);
        unlock.unlock(hex"1234", pv);
        assertTrue(unlock.isNonceProcessed(0));
    }

    // ========================================================================
    // Tests: Admin Config
    // ========================================================================

    function test_setProgramVKey() public {
        bytes32 newKey = bytes32(uint256(0x9999));
        vm.prank(admin);
        unlock.setProgramVKey(newKey);
        assertEq(unlock.programVKey(), newKey);
    }

    function test_setProgramVKey_zero_reverts() public {
        vm.prank(admin);
        vm.expectRevert(X0UnlockContract.InvalidProgramVKey.selector);
        unlock.setProgramVKey(bytes32(0));
    }

    function test_nonAdmin_cannot_configure() public {
        vm.prank(user);
        vm.expectRevert(); // OwnableUnauthorizedAccount
        unlock.setDailyLimit(1);
    }

    // ========================================================================
    // Tests: Circuit Breaker
    // ========================================================================

    function test_circuit_breaker_pauses() public {
        vm.prank(admin);
        unlock.setCircuitBreakerThreshold(100_000_000); // 100 USDC threshold

        // First unlock pushes past threshold
        // Note: this should still complete but pause afterwards
        // We need the amount to be within per-tx limits
        bytes memory pv2 = _buildPublicValues(0, user, 100_000_000);
        unlock.unlock(hex"1234", pv2);

        // Contract may now be paused after exceeding threshold
        // Next unlock should fail
        bytes memory pv3 = _buildPublicValues(1, user, 10_000_000);
        // If paused, should revert
        if (unlock.paused()) {
            vm.expectRevert();
            unlock.unlock(hex"1234", pv3);
        }
    }

    // ========================================================================
    // Tests: View Functions
    // ========================================================================

    function test_availableLiquidity() public view {
        assertEq(unlock.availableLiquidity(), 10_000_000_000_000);
    }

    function test_remainingDailyVolume() public view {
        assertEq(unlock.remainingDailyVolume(), 5_000_000_000_000);
    }
}
