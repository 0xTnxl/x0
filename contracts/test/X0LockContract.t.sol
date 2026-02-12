// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {X0LockContract} from "../src/X0LockContract.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/// @title Mock USDC token for testing
contract MockUSDC is IERC20 {
    string public name = "USD Coin";
    string public symbol = "USDC";
    uint8 public decimals = 6;

    mapping(address => uint256) private _balances;
    mapping(address => mapping(address => uint256)) private _allowances;
    uint256 private _totalSupply;

    function totalSupply() external view returns (uint256) { return _totalSupply; }
    function balanceOf(address account) external view returns (uint256) { return _balances[account]; }

    function transfer(address to, uint256 amount) external returns (bool) {
        _balances[msg.sender] -= amount;
        _balances[to] += amount;
        emit Transfer(msg.sender, to, amount);
        return true;
    }

    function allowance(address owner, address spender) external view returns (uint256) {
        return _allowances[owner][spender];
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        _allowances[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        _allowances[from][msg.sender] -= amount;
        _balances[from] -= amount;
        _balances[to] += amount;
        emit Transfer(from, to, amount);
        return true;
    }

    function mint(address to, uint256 amount) external {
        _balances[to] += amount;
        _totalSupply += amount;
        emit Transfer(address(0), to, amount);
    }
}

/// @title Mock Hyperlane Mailbox for testing
contract MockMailbox {
    uint256 public dispatchCount;

    function dispatch(
        uint32, /* destinationDomain */
        bytes32, /* recipientAddress */
        bytes calldata /* messageBody */
    ) external payable returns (bytes32 messageId) {
        dispatchCount++;
        messageId = keccak256(abi.encodePacked(dispatchCount, block.timestamp));
    }

    function quoteDispatch(
        uint32, /* destinationDomain */
        bytes32, /* recipientAddress */
        bytes calldata /* messageBody */
    ) external pure returns (uint256 fee) {
        return 0.001 ether; // Mock fee
    }
}

contract X0LockContractTest is Test {
    X0LockContract public lockContract;
    MockUSDC public usdc;
    MockMailbox public mailbox;

    address public admin = address(0xAD);
    address public user = address(0xBEEF);
    bytes32 public solanaRecipient = bytes32(uint256(0x1234));
    uint32 public solanaDomain = 1399811149;
    bytes32 public solanaBridgeAddr = bytes32(uint256(0x5678));

    function setUp() public {
        usdc = new MockUSDC();
        mailbox = new MockMailbox();

        lockContract = new X0LockContract(
            address(usdc),
            address(mailbox),
            solanaDomain,
            solanaBridgeAddr,
            admin
        );

        // Fund user
        usdc.mint(user, 1_000_000_000_000); // 1M USDC
        vm.prank(user);
        usdc.approve(address(lockContract), type(uint256).max);

        // Fund user with ETH for Hyperlane fees
        vm.deal(user, 10 ether);
    }

    /// @dev Test basic lock flow
    function test_lock_basic() public {
        uint256 amount = 100_000_000; // 100 USDC

        vm.prank(user);
        (bytes32 messageId, uint256 lockNonce) = lockContract.lock{value: 0.01 ether}(
            amount,
            solanaRecipient
        );

        assertEq(lockNonce, 0);
        assertNotEq(messageId, bytes32(0));
        assertEq(usdc.balanceOf(address(lockContract)), amount);
        assertEq(lockContract.totalLocked(), amount);
        assertEq(lockContract.nonce(), 1);
    }

    /// @dev Test minimum amount enforcement
    function test_lock_reverts_below_minimum() public {
        uint256 amount = 9_999_999; // < 10 USDC

        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(
                X0LockContract.AmountTooSmall.selector,
                amount,
                10_000_000
            )
        );
        lockContract.lock{value: 0.01 ether}(amount, solanaRecipient);
    }

    /// @dev Test maximum amount enforcement
    function test_lock_reverts_above_maximum() public {
        uint256 amount = 100_000_000_001; // > 100K USDC

        usdc.mint(user, amount);
        vm.prank(user);
        usdc.approve(address(lockContract), amount);

        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(
                X0LockContract.AmountTooLarge.selector,
                amount,
                100_000_000_000
            )
        );
        lockContract.lock{value: 0.01 ether}(amount, solanaRecipient);
    }

    /// @dev Test zero recipient reverts
    function test_lock_reverts_zero_recipient() public {
        vm.prank(user);
        vm.expectRevert(X0LockContract.InvalidSolanaRecipient.selector);
        lockContract.lock{value: 0.01 ether}(10_000_000, bytes32(0));
    }

    /// @dev Test pause prevents locking
    function test_lock_reverts_when_paused() public {
        vm.prank(admin);
        lockContract.pause();

        vm.prank(user);
        vm.expectRevert();
        lockContract.lock{value: 0.01 ether}(1_000_000, solanaRecipient);
    }

    /// @dev Test admin unlock
    function test_admin_unlock() public {
        uint256 amount = 100_000_000;

        vm.prank(user);
        (, uint256 lockNonce) = lockContract.lock{value: 0.01 ether}(
            amount,
            solanaRecipient
        );

        uint256 userBalBefore = usdc.balanceOf(user);

        vm.prank(admin);
        lockContract.adminUnlock(lockNonce);

        assertEq(usdc.balanceOf(user), userBalBefore + amount);
        assertEq(lockContract.totalUnlocked(), amount);
    }

    /// @dev Test double unlock reverts
    function test_admin_unlock_reverts_double() public {
        uint256 amount = 100_000_000;

        vm.prank(user);
        (, uint256 lockNonce) = lockContract.lock{value: 0.01 ether}(
            amount,
            solanaRecipient
        );

        vm.prank(admin);
        lockContract.adminUnlock(lockNonce);

        vm.prank(admin);
        vm.expectRevert(
            abi.encodeWithSelector(
                X0LockContract.LockAlreadyUnlocked.selector,
                lockNonce
            )
        );
        lockContract.adminUnlock(lockNonce);
    }

    /// @dev Test sequential nonces
    function test_sequential_nonces() public {
        vm.startPrank(user);

        (, uint256 n0) = lockContract.lock{value: 0.01 ether}(10_000_000, solanaRecipient);
        (, uint256 n1) = lockContract.lock{value: 0.01 ether}(20_000_000, solanaRecipient);
        (, uint256 n2) = lockContract.lock{value: 0.01 ether}(30_000_000, solanaRecipient);

        vm.stopPrank();

        assertEq(n0, 0);
        assertEq(n1, 1);
        assertEq(n2, 2);
    }

    /// @dev Test active locked calculation
    function test_active_locked() public {
        vm.prank(user);
        lockContract.lock{value: 0.01 ether}(100_000_000, solanaRecipient);

        vm.prank(user);
        lockContract.lock{value: 0.01 ether}(50_000_000, solanaRecipient);

        assertEq(lockContract.activeLocked(), 150_000_000);

        vm.prank(admin);
        lockContract.adminUnlock(0);

        assertEq(lockContract.activeLocked(), 50_000_000);
    }

    /// @dev Test quoteLock returns a fee
    function test_quote_lock() public view {
        uint256 fee = lockContract.quoteLock(100_000_000, solanaRecipient);
        assertEq(fee, 0.001 ether);
    }

    /// @dev Test config updates by admin
    function test_config_updates() public {
        vm.startPrank(admin);

        lockContract.setMinLockAmount(5_000_000);
        assertEq(lockContract.minLockAmount(), 5_000_000);

        lockContract.setMaxLockAmount(1_000_000_000_000);
        assertEq(lockContract.maxLockAmount(), 1_000_000_000_000);

        lockContract.setDailyLimit(100_000_000_000_000);
        assertEq(lockContract.dailyLimit(), 100_000_000_000_000);

        lockContract.setSolanaDomain(42);
        assertEq(lockContract.solanaDomain(), 42);

        vm.stopPrank();
    }

    /// @dev Test non-admin cannot configure
    function test_config_reverts_non_admin() public {
        vm.prank(user);
        vm.expectRevert();
        lockContract.setMinLockAmount(0);
    }
}
