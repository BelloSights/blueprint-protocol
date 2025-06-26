// SPDX-License-Identifier: Apache-2.0
/*
__________.__                             .__        __   
\______   \  |  __ __   ____ _____________|__| _____/  |_ 
 |    |  _/  | |  |  \_/ __ \\____ \_  __ \  |/    \   __\
 |    |   \  |_|  |  /\  ___/|  |_> >  | \/  |   |  \  |  
 |______  /____/____/  \___  >   __/|__|  |__|___|  /__|  
        \/                 \/|__|                 \/      
*/
pragma solidity ^0.8.26;

import {IERC20} from '@openzeppelin/contracts/token/ERC20/IERC20.sol';
import {SafeTransferLib} from '@solady/utils/SafeTransferLib.sol';
import {AccessControlUpgradeable} from '@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol';
import {Initializable} from '@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol';
import {UUPSUpgradeable} from '@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol';
import {PausableUpgradeable} from '@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol';

import {Currency} from '@uniswap/v4-core/src/types/Currency.sol';
import {IPoolManager} from '@uniswap/v4-core/src/interfaces/IPoolManager.sol';
import {PoolId, PoolIdLibrary} from '@uniswap/v4-core/src/types/PoolId.sol';
import {PoolKey} from '@uniswap/v4-core/src/types/PoolKey.sol';
import {BalanceDelta} from '@uniswap/v4-core/src/types/BalanceDelta.sol';
import {SwapParams} from '@uniswap/v4-core/src/types/PoolOperation.sol';

/**
 * BlueprintBuybackEscrow - Simplified upgradeable contract for fee collection and manual buybacks
 * 
 * Features:
 * - Upgradeable using UUPS pattern
 * - Role-based access control with BUYBACK_MANAGER_ROLE for decentralized buyback execution
 * - Receives both ERC20 tokens and native ETH fees
 * - Manual buyback execution by authorized managers
 * - Emergency pause functionality
 */
contract BlueprintBuybackEscrow is 
    Initializable,
    AccessControlUpgradeable,
    UUPSUpgradeable,
    PausableUpgradeable 
{
    using PoolIdLibrary for PoolKey;

    // Role definitions
    bytes32 public constant BUYBACK_MANAGER_ROLE = keccak256("BUYBACK_MANAGER_ROLE");
    bytes32 public constant EMERGENCY_ROLE = keccak256("EMERGENCY_ROLE");
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");

    error InsufficientBalance();
    error InvalidPool();
    error BuybackFailed();
    error UnauthorizedCaller();
    error InvalidAddress();

    event FeesReceived(PoolId indexed poolId, address indexed token, uint256 amount);
    event NativeFeesReceived(PoolId indexed poolId, uint256 amount);
    event BuybackExecuted(PoolId indexed poolId, address indexed token, uint256 amountIn, uint256 amountOut);
    event TokensBurned(address indexed token, uint256 amount);
    event BlueprintHookUpdated(address indexed oldHook, address indexed newHook);

    /// The pool manager for executing swaps
    IPoolManager public poolManager;
    
    /// The native token address (address(0) for native ETH)
    address public nativeToken;
    
    /// The Blueprint token address
    address public blueprintToken;
    
    /// Maps pool IDs to accumulated ERC20 token fees by token address
    mapping(PoolId => mapping(address => uint256)) public accumulatedTokenFees;
    
    /// Maps pool IDs to accumulated native ETH fees
    mapping(PoolId => uint256) public accumulatedNativeFees;
    
    /// Maps pool IDs to their pool keys for buyback execution
    mapping(PoolId => PoolKey) public poolKeys;
    
    /// The BlueprintNetworkHook that sends fees to this contract
    address public blueprintHook;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /**
     * Initialize the upgradeable contract
     *
     * @param _poolManager The Uniswap V4 PoolManager
     * @param _nativeToken The native token address (address(0) for native ETH)
     * @param _blueprintToken The Blueprint token address (can be address(0) initially)
     * @param _admin The admin address (receives all roles initially)
     */
    function initialize(
        IPoolManager _poolManager,
        address _nativeToken,
        address _blueprintToken,
        address _admin
    ) public initializer {
        if (_admin == address(0)) {
            revert InvalidAddress();
        }
        // Note: _nativeToken can be address(0) for native ETH

        __AccessControl_init();
        __UUPSUpgradeable_init();
        __Pausable_init();

        poolManager = _poolManager;
        nativeToken = _nativeToken;
        blueprintToken = _blueprintToken; // Allow address(0) initially
        
        // Set up roles
        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(BUYBACK_MANAGER_ROLE, _admin);
        _grantRole(EMERGENCY_ROLE, _admin);
        _grantRole(UPGRADER_ROLE, _admin);
    }

    /**
     * Set the BlueprintNetworkHook address
     * Only callable by DEFAULT_ADMIN_ROLE
     *
     * @param _blueprintHook The BlueprintNetworkHook address
     */
    function setBlueprintHook(address _blueprintHook) external onlyRole(DEFAULT_ADMIN_ROLE) whenNotPaused {
        if (_blueprintHook == address(0)) revert InvalidAddress();
        
        address oldHook = blueprintHook;
        blueprintHook = _blueprintHook;
        
        emit BlueprintHookUpdated(oldHook, _blueprintHook);
    }

    /**
     * Register a pool for buyback operations
     * Only callable by DEFAULT_ADMIN_ROLE
     *
     * @param _poolKey The pool key to register
     */
    function registerPool(PoolKey calldata _poolKey) external onlyRole(DEFAULT_ADMIN_ROLE) whenNotPaused {
        PoolId poolId = _poolKey.toId();
        poolKeys[poolId] = _poolKey;
    }

    /**
     * Receive ERC20 token fees from the BlueprintNetworkHook
     *
     * @param _poolId The pool ID the fees are from
     * @param _token The token address
     * @param _amount The amount of fees received
     */
    function receiveTokenFees(PoolId _poolId, address _token, uint256 _amount) external whenNotPaused {
        if (msg.sender != blueprintHook) revert UnauthorizedCaller();
        
        accumulatedTokenFees[_poolId][_token] += _amount;
        emit FeesReceived(_poolId, _token, _amount);
    }

    /**
     * Receive native ETH fees from the BlueprintNetworkHook
     *
     * @param _poolId The pool ID the fees are from
     */
    function receiveNativeFees(PoolId _poolId) external payable whenNotPaused {
        if (msg.sender != blueprintHook) revert UnauthorizedCaller();
        
        accumulatedNativeFees[_poolId] += msg.value;
        emit NativeFeesReceived(_poolId, msg.value);
    }

    /**
     * Execute buyback for a specific pool using ERC20 tokens
     * Only callable by BUYBACK_MANAGER_ROLE
     *
     * @param _poolId The pool ID to execute buyback for
     * @param _token The token to use for buyback
     * @param _amount The amount to use for buyback (0 = use all accumulated)
     */
    function executeBuyback(PoolId _poolId, address _token, uint256 _amount) external onlyRole(BUYBACK_MANAGER_ROLE) whenNotPaused {
        uint256 availableAmount = accumulatedTokenFees[_poolId][_token];
        if (availableAmount == 0) revert InsufficientBalance();
        
        uint256 buybackAmount = _amount == 0 ? availableAmount : _amount;
        if (buybackAmount > availableAmount) revert InsufficientBalance();
        
        // Reduce accumulated fees
        accumulatedTokenFees[_poolId][_token] -= buybackAmount;
        
        // Execute the buyback swap
        uint256 tokensReceived = _executeSwap(_poolId, _token, buybackAmount);
        
        emit BuybackExecuted(_poolId, _token, buybackAmount, tokensReceived);
    }

    /**
     * Execute buyback for a specific pool using native ETH
     * Only callable by BUYBACK_MANAGER_ROLE
     *
     * @param _poolId The pool ID to execute buyback for
     * @param _amount The amount to use for buyback (0 = use all accumulated)
     */
    function executeBuybackNative(PoolId _poolId, uint256 _amount) external onlyRole(BUYBACK_MANAGER_ROLE) whenNotPaused {
        uint256 availableAmount = accumulatedNativeFees[_poolId];
        if (availableAmount == 0) revert InsufficientBalance();
        
        uint256 buybackAmount = _amount == 0 ? availableAmount : _amount;
        if (buybackAmount > availableAmount) revert InsufficientBalance();
        
        // Reduce accumulated fees
        accumulatedNativeFees[_poolId] -= buybackAmount;
        
        // Execute the buyback swap
        uint256 tokensReceived = _executeSwap(_poolId, nativeToken, buybackAmount);
        
        emit BuybackExecuted(_poolId, nativeToken, buybackAmount, tokensReceived);
    }

    /**
     * Burn tokens that have been bought back
     * Only callable by BUYBACK_MANAGER_ROLE
     *
     * @param _token The token to burn
     * @param _amount The amount to burn (0 = burn all)
     */
    function burnTokens(address _token, uint256 _amount) external onlyRole(BUYBACK_MANAGER_ROLE) whenNotPaused {
        uint256 balance = IERC20(_token).balanceOf(address(this));
        if (balance == 0) revert InsufficientBalance();
        
        uint256 burnAmount = _amount == 0 ? balance : _amount;
        if (burnAmount > balance) revert InsufficientBalance();
        
        // Burn tokens by sending to dead address
        IERC20(_token).transfer(0x000000000000000000000000000000000000dEaD, burnAmount);
        
        emit TokensBurned(_token, burnAmount);
    }

    /**
     * Emergency withdrawal of tokens
     * Only callable by EMERGENCY_ROLE
     *
     * @param _token Token to withdraw (address(0) for native ETH)
     * @param _to Recipient address
     * @param _amount Amount to withdraw
     */
    function emergencyWithdraw(address _token, address _to, uint256 _amount) external onlyRole(EMERGENCY_ROLE) {
        if (_to == address(0)) revert InvalidAddress();
        
        if (_token == address(0)) {
            // Withdraw native ETH
            payable(_to).transfer(_amount);
        } else {
            // Withdraw ERC20 token
            IERC20(_token).transfer(_to, _amount);
        }
    }

    /**
     * Emergency pause function
     * Only callable by EMERGENCY_ROLE
     */
    function pause() external onlyRole(EMERGENCY_ROLE) {
        _pause();
    }

    /**
     * Unpause function
     * Only callable by EMERGENCY_ROLE
     */
    function unpause() external onlyRole(EMERGENCY_ROLE) {
        _unpause();
    }

    /**
     * Get the accumulated token fees for a pool
     *
     * @param _poolId The pool ID
     * @param _token The token address
     * @return The accumulated fees
     */
    function getAccumulatedTokenFees(PoolId _poolId, address _token) external view returns (uint256) {
        return accumulatedTokenFees[_poolId][_token];
    }

    /**
     * Get the accumulated native fees for a pool
     *
     * @param _poolId The pool ID
     * @return The accumulated fees
     */
    function getAccumulatedNativeFees(PoolId _poolId) external view returns (uint256) {
        return accumulatedNativeFees[_poolId];
    }

    // Internal Functions

    /**
     * Execute a swap to buy back tokens
     *
     * @param _poolId The pool ID to swap in
     * @param _token The input token address
     * @param _amount The amount to swap
     * @return The amount of tokens bought
     */
    function _executeSwap(PoolId _poolId, address _token, uint256 _amount) internal returns (uint256) {
        PoolKey memory poolKey = poolKeys[_poolId];
        if (poolKey.fee == 0) revert InvalidPool();
        
        // Determine swap direction
        bool zeroForOne;
        
        if (Currency.unwrap(poolKey.currency0) == _token) {
            // Input token is currency0
            zeroForOne = true;
        } else if (Currency.unwrap(poolKey.currency1) == _token) {
            // Input token is currency1
            zeroForOne = false;
        } else {
            revert InvalidPool();
        }
        
        SwapParams memory params = SwapParams({
            zeroForOne: zeroForOne,
            amountSpecified: int256(_amount),
            sqrtPriceLimitX96: 0
        });
        
        // Execute the swap
        BalanceDelta delta = poolManager.swap(poolKey, params, "");
        
        // Return the amount of tokens bought (absolute value of the negative delta)
        int128 deltaAmount = zeroForOne ? delta.amount1() : delta.amount0();
        return deltaAmount < 0 ? uint256(uint128(-deltaAmount)) : 0;
    }

    /**
     * Set the Blueprint token address
     * Only callable by DEFAULT_ADMIN_ROLE
     *
     * @param _blueprintToken The Blueprint token address
     */
    function setBlueprintToken(address _blueprintToken) external onlyRole(DEFAULT_ADMIN_ROLE) whenNotPaused {
        if (_blueprintToken == address(0)) revert InvalidAddress();
        
        blueprintToken = _blueprintToken;
    }

    /**
     * Authorize upgrade function for UUPS
     * Only callable by UPGRADER_ROLE
     */
    function _authorizeUpgrade(address newImplementation) 
        internal 
        override 
        onlyRole(UPGRADER_ROLE) 
    {
        // Additional upgrade validation can be added here
    }

    /**
     * Override supportsInterface to include AccessControl
     */
    function supportsInterface(bytes4 interfaceId) 
        public 
        view 
        override(AccessControlUpgradeable) 
        returns (bool) 
    {
        return super.supportsInterface(interfaceId);
    }

    /**
     * Receive ETH deposits
     */
    receive() external payable {
        // Allow contract to receive ETH
    }

    /**
     * Fallback function
     */
    fallback() external payable {
        // Allow contract to receive ETH
    }
} 