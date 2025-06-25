// SPDX-License-Identifier: MIT
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


/**
 * BuybackEscrow - Upgradeable contract with configurable buyback parameters
 * 
 * Features:
 * - Upgradeable using UUPS pattern
 * - Role-based access control
 * - Configurable buyback thresholds and intervals
 * - Multiple buyback strategies
 * - Emergency pause functionality
 */
contract BuybackEscrow is 
    Initializable,
    AccessControlUpgradeable,
    UUPSUpgradeable,
    PausableUpgradeable 
{

    using PoolIdLibrary for PoolKey;

    // Role definitions
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant BUYBACK_MANAGER_ROLE = keccak256("BUYBACK_MANAGER_ROLE");
    bytes32 public constant EMERGENCY_ROLE = keccak256("EMERGENCY_ROLE");
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");

    error InsufficientBalance();
    error InvalidPool();
    error BuybackFailed();
    error UnauthorizedCaller();
    error InvalidAddress();
    error InvalidThreshold();

    event FeesReceived(PoolId indexed poolId, uint256 amount);
    event BuybackExecuted(PoolId indexed poolId, uint256 ethSpent, uint256 tokensBought);
    event TokensBurned(address indexed token, uint256 amount);
    event BuybackThresholdUpdated(uint256 newThreshold);
    event AutoBuybackToggled(bool enabled);
    event BuybackIntervalUpdated(uint256 newInterval);
    event BlueprintHookUpdated(address indexed oldHook, address indexed newHook);

    /// The pool manager for executing swaps
    IPoolManager public poolManager;
    
    /// The native token (ETH/WETH)
    address public nativeToken;
    
    /// The Blueprint token address
    address public blueprintToken;
    
    /// Minimum ETH balance before buyback can be executed
    uint256 public buybackThreshold;
    
    /// Whether automatic buybacks are enabled
    bool public autoBuybackEnabled;
    
    /// Time between automatic buybacks
    uint256 public buybackInterval;
    
    /// Maps pool IDs to accumulated fees
    mapping(PoolId => uint256) public accumulatedFees;
    
    /// Maps pool IDs to last buyback timestamp
    mapping(PoolId => uint256) public lastBuyback;
    
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
     * @param _nativeToken The native token (ETH/WETH)
     * @param _blueprintToken The Blueprint token address (can be address(0) initially)
     * @param _admin The admin address (receives all roles initially)
     * @param _initialThreshold Initial buyback threshold
     * @param _initialInterval Initial buyback interval
     */
    function initialize(
        IPoolManager _poolManager,
        address _nativeToken,
        address _blueprintToken,
        address _admin,
        uint256 _initialThreshold,
        uint256 _initialInterval
    ) public initializer {
        if (_admin == address(0) || _nativeToken == address(0)) {
            revert InvalidAddress();
        }
        if (_initialThreshold == 0) revert InvalidThreshold();

        __AccessControl_init();
        __UUPSUpgradeable_init();
        __Pausable_init();

        poolManager = _poolManager;
        nativeToken = _nativeToken;
        blueprintToken = _blueprintToken; // Allow address(0) initially
        
        // Set up roles
        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(ADMIN_ROLE, _admin);
        _grantRole(BUYBACK_MANAGER_ROLE, _admin);
        _grantRole(EMERGENCY_ROLE, _admin);
        _grantRole(UPGRADER_ROLE, _admin);

        // Set initial configuration
        buybackThreshold = _initialThreshold;
        buybackInterval = _initialInterval;
        autoBuybackEnabled = true;
    }

    /**
     * Set the BlueprintNetworkHook address
     * Only callable by ADMIN_ROLE
     *
     * @param _blueprintHook The BlueprintNetworkHook address
     */
    function setBlueprintHook(address _blueprintHook) external onlyRole(ADMIN_ROLE) whenNotPaused {
        if (_blueprintHook == address(0)) revert InvalidAddress();
        
        address oldHook = blueprintHook;
        blueprintHook = _blueprintHook;
        
        emit BlueprintHookUpdated(oldHook, _blueprintHook);
    }

    /**
     * Register a pool for buyback operations
     * Only callable by ADMIN_ROLE
     *
     * @param _poolKey The pool key to register
     */
    function registerPool(PoolKey calldata _poolKey) external onlyRole(ADMIN_ROLE) whenNotPaused {
        PoolId poolId = _poolKey.toId();
        poolKeys[poolId] = _poolKey;
    }

    /**
     * Receive fees from the BlueprintNetworkHook
     *
     * @param _poolId The pool ID the fees are from
     * @param _amount The amount of fees received
     */
    function receiveFees(PoolId _poolId, uint256 _amount) external whenNotPaused {
        if (msg.sender != blueprintHook) revert UnauthorizedCaller();
        
        accumulatedFees[_poolId] += _amount;
        emit FeesReceived(_poolId, _amount);
        
        // Trigger automatic buyback if conditions are met
        if (autoBuybackEnabled && _shouldExecuteBuyback(_poolId)) {
            _executeBuyback(_poolId);
        }
    }

    /**
     * Execute buyback for a specific pool
     * Only callable by BUYBACK_MANAGER_ROLE
     *
     * @param _poolId The pool ID to execute buyback for
     */
    function executeBuyback(PoolId _poolId) external onlyRole(BUYBACK_MANAGER_ROLE) whenNotPaused {
        _executeBuyback(_poolId);
    }

    /**
     * Execute buybacks for multiple pools
     * Only callable by BUYBACK_MANAGER_ROLE
     *
     * @param _poolIds Array of pool IDs to execute buybacks for
     */
    function executeBuybackBatch(PoolId[] calldata _poolIds) external onlyRole(BUYBACK_MANAGER_ROLE) whenNotPaused {
        for (uint256 i = 0; i < _poolIds.length; i++) {
            if (_shouldExecuteBuyback(_poolIds[i])) {
                _executeBuyback(_poolIds[i]);
            }
        }
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
     * Set the buyback threshold
     * Only callable by BUYBACK_MANAGER_ROLE
     *
     * @param _threshold New threshold in wei
     */
    function setBuybackThreshold(uint256 _threshold) external onlyRole(BUYBACK_MANAGER_ROLE) whenNotPaused {
        if (_threshold == 0) revert InvalidThreshold();
        buybackThreshold = _threshold;
        emit BuybackThresholdUpdated(_threshold);
    }

    /**
     * Toggle automatic buyback functionality
     * Only callable by BUYBACK_MANAGER_ROLE
     *
     * @param _enabled Whether to enable automatic buybacks
     */
    function setAutoBuyback(bool _enabled) external onlyRole(BUYBACK_MANAGER_ROLE) whenNotPaused {
        autoBuybackEnabled = _enabled;
        emit AutoBuybackToggled(_enabled);
    }

    /**
     * Set the buyback interval
     * Only callable by BUYBACK_MANAGER_ROLE
     *
     * @param _interval New interval in seconds
     */
    function setBuybackInterval(uint256 _interval) external onlyRole(BUYBACK_MANAGER_ROLE) whenNotPaused {
        buybackInterval = _interval;
        emit BuybackIntervalUpdated(_interval);
    }

    /**
     * Emergency withdrawal of tokens
     * Only callable by EMERGENCY_ROLE
     *
     * @param _token Token to withdraw
     * @param _to Recipient address
     * @param _amount Amount to withdraw
     */
    function emergencyWithdraw(address _token, address _to, uint256 _amount) external onlyRole(EMERGENCY_ROLE) {
        if (_to == address(0)) revert InvalidAddress();
        IERC20(_token).transfer(_to, _amount);
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
     * Get the accumulated fees for a pool
     *
     * @param _poolId The pool ID
     * @return The accumulated fees
     */
    function getAccumulatedFees(PoolId _poolId) external view returns (uint256) {
        return accumulatedFees[_poolId];
    }

    /**
     * Check if a buyback should be executed for a pool
     *
     * @param _poolId The pool ID to check
     * @return Whether buyback should be executed
     */
    function shouldExecuteBuyback(PoolId _poolId) external view returns (bool) {
        return _shouldExecuteBuyback(_poolId);
    }

    // Internal Functions

    /**
     * Internal function to check if buyback should be executed
     *
     * @param _poolId The pool ID to check
     * @return Whether buyback should be executed
     */
    function _shouldExecuteBuyback(PoolId _poolId) internal view returns (bool) {
        // Check if we have enough accumulated fees
        if (accumulatedFees[_poolId] < buybackThreshold) {
            return false;
        }
        
        // Check if enough time has passed since last buyback
        if (block.timestamp < lastBuyback[_poolId] + buybackInterval) {
            return false;
        }
        
        // Check if pool is registered
        if (poolKeys[_poolId].fee == 0) {
            return false;
        }
        
        return true;
    }

    /**
     * Internal function to execute buyback
     *
     * @param _poolId The pool ID to execute buyback for
     */
    function _executeBuyback(PoolId _poolId) internal {
        if (!_shouldExecuteBuyback(_poolId)) revert BuybackFailed();
        
        PoolKey memory poolKey = poolKeys[_poolId];
        uint256 ethAmount = accumulatedFees[_poolId];
        
        // Reset accumulated fees
        accumulatedFees[_poolId] = 0;
        lastBuyback[_poolId] = block.timestamp;
        
        // Execute the buyback swap
        uint256 tokensBought = _executeSwap(poolKey, ethAmount);
        
        emit BuybackExecuted(_poolId, ethAmount, tokensBought);
    }

    /**
     * Execute a swap to buy back tokens
     *
     * @param _poolKey The pool key to swap in
     * @param _ethAmount The amount of ETH to swap
     * @return The amount of tokens bought
     */
    function _executeSwap(PoolKey memory _poolKey, uint256 _ethAmount) internal returns (uint256) {
        // Determine swap direction
        // We want to swap ETH/BP for Creator tokens
        bool zeroForOne;
        
        if (Currency.unwrap(_poolKey.currency0) == blueprintToken) {
            // BP is currency0, creator token is currency1
            zeroForOne = true;
        } else {
            // Creator token is currency0, BP is currency1
            zeroForOne = false;
        }
        
        IPoolManager.SwapParams memory params = IPoolManager.SwapParams({
            zeroForOne: zeroForOne,
            amountSpecified: int256(_ethAmount),
            sqrtPriceLimitX96: 0
        });
        
        // Execute the swap
        BalanceDelta delta = poolManager.swap(_poolKey, params, "");
        
        // Return the amount of tokens bought (absolute value of the negative delta)
        int128 deltaAmount = zeroForOne ? delta.amount1() : delta.amount0();
        return deltaAmount < 0 ? uint256(uint128(-deltaAmount)) : 0;
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

    /**
     * Set the Blueprint token address
     * Only callable by ADMIN_ROLE
     *
     * @param _blueprintToken The Blueprint token address
     */
    function setBlueprintToken(address _blueprintToken) external onlyRole(ADMIN_ROLE) whenNotPaused {
        if (_blueprintToken == address(0)) revert InvalidAddress();
        
        blueprintToken = _blueprintToken;
    }
} 