// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {PoolKey} from '@uniswap/v4-core/src/types/PoolKey.sol';
import {BalanceDelta} from '@uniswap/v4-core/src/types/BalanceDelta.sol';
import {Currency} from '@uniswap/v4-core/src/types/Currency.sol';
import {PoolId, PoolIdLibrary} from '@uniswap/v4-core/src/types/PoolId.sol';
import {IPoolManager} from '@uniswap/v4-core/src/interfaces/IPoolManager.sol';
import {IUnlockCallback} from '@uniswap/v4-core/src/interfaces/callback/IUnlockCallback.sol';
import {IHooks} from '@uniswap/v4-core/src/interfaces/IHooks.sol';
import {IERC20} from '@openzeppelin/contracts/token/ERC20/IERC20.sol';
import {SafeERC20} from '@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol';
import {Initializable} from '@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol';
import {CurrencySettler} from '@flaunch/libraries/CurrencySettler.sol';

import {AnyPositionManager} from '@flaunch/AnyPositionManager.sol';
import {RewardPool} from '@flaunch/RewardPool.sol';
import {BuybackEscrow} from '@flaunch/escrows/BuybackEscrow.sol';
import {MemecoinTreasury} from './treasury/MemecoinTreasury.sol';

/**
 * @title BlueprintPositionManager
 * @notice Manages liquidity positions for Blueprint Protocol pools with enhanced fee distribution
 * @dev Maintains compatibility with existing Flaunch infrastructure while adding Blueprint functionality
 */
contract BlueprintPositionManager is AnyPositionManager, Initializable {
    constructor(ConstructorParams memory params) AnyPositionManager(params) {}

    using PoolIdLibrary for PoolKey;
    using CurrencySettler for Currency;
    using SafeERC20 for IERC20;

    // Blueprint Protocol specific events
    event BlueprintPoolCreated(PoolId indexed poolId, address indexed blueprintToken, address indexed creatorToken);
    event BlueprintSwap(address indexed user, address indexed token, uint256 ethAmount, uint256 bpAmount, uint256 creatorAmount);
    event XPAwarded(address indexed user, address indexed token, uint256 xpAmount, string reason);

    // Blueprint Protocol state
    address public blueprintToken;
    PoolKey public ethBpPoolKey;
    address public bpTreasury;
    RewardPool public rewardPool;
    BuybackEscrow public buybackEscrow;
    
    // Blueprint fee configuration (60/20/10/10)
    struct BlueprintFeeConfig {
        uint24 buybackFee;    // 60% = 6000 basis points
        uint24 creatorFee;    // 20% = 2000 basis points  
        uint24 bpTreasuryFee; // 10% = 1000 basis points
        uint24 rewardPoolFee; // 10% = 1000 basis points
    }
    
    BlueprintFeeConfig public blueprintFeeConfig;
    
    // Track Blueprint pools separately from regular Flaunch pools
    mapping(address => PoolKey) public blueprintCreatorPools; // creator token => BP/Creator pool
    mapping(address => bool) public isBlueprintToken; // track which tokens use Blueprint flow
    
    // Struct for swap callback data
    struct SwapCallbackData {
        address user;
        address creatorToken;
        uint256 minCreatorOut;
        uint256 ethAmount;
    }
    
    error BlueprintNotInitialized();
    error OnlyBlueprintTokens();
    error InvalidBlueprintFee();

    /**
     * @notice Initialize Blueprint Protocol functionality
     * @param _blueprintToken The Blueprint base token address
     * @param _bpTreasury Blueprint treasury address  
     * @param _rewardPool XP-based reward pool address
     * @param _buybackEscrow Buyback escrow address
     */
    function initializeBlueprint(
        address _blueprintToken,
        address _bpTreasury,
        address _rewardPool,
        address _buybackEscrow
    ) external initializer onlyOwner {
        if (_blueprintToken == address(0) || _bpTreasury == address(0) || 
            _rewardPool == address(0) || _buybackEscrow == address(0)) {
            revert BlueprintNotInitialized();
        }
        
        blueprintToken = _blueprintToken;
        bpTreasury = _bpTreasury;
        rewardPool = RewardPool(_rewardPool);
        buybackEscrow = BuybackEscrow(payable(_buybackEscrow));
        
        // Set default fee configuration (60/20/10/10)
        blueprintFeeConfig = BlueprintFeeConfig({
            buybackFee: 6000,    // 60%
            creatorFee: 2000,    // 20%
            bpTreasuryFee: 1000, // 10%
            rewardPoolFee: 1000  // 10%
        });
        
        // Create ETH/BP base pool
        _createEthBpPool();
    }

    /**
     * @notice Blueprint-specific flaunch that creates BP/Creator pools
     */
    function blueprintFlaunch(FlaunchParams calldata _params) external returns (address payable memecoinTreasury, uint256 tokenId) {
        if (blueprintToken == address(0)) revert BlueprintNotInitialized();
        if (!approvedMemecoinCreator[msg.sender]) revert CallerIsNotApprovedCreator();
        if (flaunchContract.tokenId(_params.memecoin) != 0) revert AlreadyFlaunched();

        // Mark this as a Blueprint token
        isBlueprintToken[_params.memecoin] = true;
        
        // Create ETH/BP pool if it doesn't exist yet
        if (Currency.unwrap(ethBpPoolKey.currency0) == address(0)) {
            _createEthBpPool();
        }
        
        // Use existing flaunch infrastructure for ERC721 creation
        (memecoinTreasury, tokenId) = flaunchContract.flaunch(_params);

        // Create BP/Creator pool instead of flETH/Creator
        bool currencyFlipped = blueprintToken >= _params.memecoin;
        
        PoolKey memory _poolKey = PoolKey({
            currency0: Currency.wrap(!currencyFlipped ? blueprintToken : _params.memecoin),
            currency1: Currency.wrap(currencyFlipped ? blueprintToken : _params.memecoin),
            fee: 0,
            tickSpacing: 60,
            hooks: IHooks(address(this))
        });

        // Store Blueprint pool separately
        blueprintCreatorPools[_params.memecoin] = _poolKey;
        _poolKeys[_params.memecoin] = _poolKey; // Also store in main mapping for compatibility
        
        PoolId poolId = _poolKey.toId();

        // Set creator fee allocation
        if (_params.creatorFeeAllocation != 0) {
            creatorFee[poolId] = _params.creatorFeeAllocation;
        }

        // Initialize pool with Blueprint pricing
        poolManager.initialize(
            _poolKey,
            initialPrice.getSqrtPriceX96(msg.sender, currencyFlipped, _params.initialPriceParams)
        );

        // Initialize treasury with Blueprint pool
        MemecoinTreasury(memecoinTreasury).initialize(
            payable(address(this)), 
            address(actionManager), 
            blueprintToken, // Use BP token instead of native
            _poolKey
        );

        emit BlueprintPoolCreated(poolId, blueprintToken, _params.memecoin);
        emit PoolCreated({
            _poolId: poolId,
            _memecoin: _params.memecoin,
            _memecoinTreasury: memecoinTreasury,
            _tokenId: tokenId,
            _currencyFlipped: currencyFlipped,
            _params: _params
        });

        _emitPoolStateUpdate(poolId, IHooks.afterInitialize.selector, abi.encode(tokenId, _params));
    }
    
    /**
     * @notice Route ETH → BP → Creator tokens (Blueprint Protocol flow)
     * @param _creatorToken The target creator token
     * @param _minCreatorOut Minimum creator tokens to receive
     * @return creatorAmount Amount of creator tokens received
     */
    function routeEthToCreator(
        address _creatorToken,
        uint256 _minCreatorOut
    ) external payable returns (uint256 creatorAmount) {
        if (!isBlueprintToken[_creatorToken]) revert OnlyBlueprintTokens();
        
        // Use unlock callback pattern for swaps
        SwapCallbackData memory callbackData = SwapCallbackData({
            user: msg.sender,
            creatorToken: _creatorToken,
            minCreatorOut: _minCreatorOut,
            ethAmount: msg.value
        });
        
        bytes memory result = poolManager.unlock(abi.encode(callbackData));
        creatorAmount = abi.decode(result, (uint256));
        
        // Track XP for user (buy event)
        _trackBlueprintEvent(msg.sender, _creatorToken, true);
        
        emit BlueprintSwap(msg.sender, _creatorToken, msg.value, 0, creatorAmount);
    }
    
    /**
     * @notice Override _unlockCallback to handle Blueprint swap routing
     */
    function _unlockCallback(bytes calldata data) internal override returns (bytes memory) {
        // Check if this is a Blueprint swap callback
        if (data.length > 0) {
            try this.decodeBlueprintSwapData(data) returns (SwapCallbackData memory callbackData) {
                if (callbackData.user != address(0)) {
                    return _handleBlueprintSwapCallback(callbackData);
                }
            } catch {
                // If decoding fails, fall back to parent implementation
            }
        }
        
        // Fall back to parent implementation for other callbacks
        return super._unlockCallback(data);
    }
    
    /**
     * @notice Helper function to decode Blueprint swap data (external for try-catch)
     */
    function decodeBlueprintSwapData(bytes calldata data) external pure returns (SwapCallbackData memory) {
        return abi.decode(data, (SwapCallbackData));
    }
    
    /**
     * @notice Handle Blueprint swap callback
     */
    function _handleBlueprintSwapCallback(SwapCallbackData memory data) internal returns (bytes memory) {
        // Step 1: Swap ETH for BP tokens via ETH/BP pool
        uint256 bpAmount = _swapEthForBp(data.ethAmount);
        
        // Step 2: Swap BP for Creator tokens via BP/Creator pool  
        uint256 creatorAmount = _swapBpForCreator(data.creatorToken, bpAmount);
        
        require(creatorAmount >= data.minCreatorOut, "Insufficient output");
        
        // Transfer creator tokens to user
        IERC20(data.creatorToken).transfer(data.user, creatorAmount);
        
        return abi.encode(creatorAmount);
    }
    
    /**
     * @notice Override afterSwap to handle Blueprint fee distribution
     */
    function afterSwap(
        address _sender,
        PoolKey calldata _key,
        IPoolManager.SwapParams calldata _params,
        BalanceDelta _delta,
        bytes calldata _hookData
    ) public override onlyPoolManager returns (bytes4 selector_, int128 hookDeltaUnspecified_) {
        
        // Check if this is a Blueprint pool
        address token0 = Currency.unwrap(_key.currency0);
        address token1 = Currency.unwrap(_key.currency1);
        
        bool isBlueprintPool = (token0 == blueprintToken || token1 == blueprintToken) && 
                              (isBlueprintToken[token0] || isBlueprintToken[token1]);
        
        if (isBlueprintPool) {
            // Handle Blueprint-specific fee distribution
            _handleBlueprintSwap(_sender, _key, _params, _delta, _hookData);
            
            // Track XP event
            address creatorToken = token0 == blueprintToken ? token1 : token0;
            bool isBuy = _params.amountSpecified > 0; // Simplified logic
            _trackBlueprintEvent(_sender, creatorToken, isBuy);
            
            selector_ = IHooks.afterSwap.selector;
            hookDeltaUnspecified_ = 0; // Blueprint pools handle fees differently
        } else {
            // Use original Flaunch logic for non-Blueprint pools
            return super.afterSwap(_sender, _key, _params, _delta, _hookData);
        }
    }
    
    // Internal Blueprint Functions
    
    /**
     * @notice Create the ETH/BP base pool
     */
    function _createEthBpPool() internal {
        bool currencyFlipped = nativeToken >= blueprintToken;
        
        ethBpPoolKey = PoolKey({
            currency0: Currency.wrap(!currencyFlipped ? nativeToken : blueprintToken),
            currency1: Currency.wrap(currencyFlipped ? nativeToken : blueprintToken),
            fee: 3000, // 0.3% fee
            tickSpacing: 60,
            hooks: IHooks(address(this))
        });
        
        // Initialize the ETH/BP pool
        poolManager.initialize(ethBpPoolKey, _getDefaultSqrtPrice());
    }
    
    /**
     * @notice Swap ETH for BP tokens (called within unlock callback)
     */
    function _swapEthForBp(uint256 _ethAmount) internal returns (uint256 bpAmount) {
        IPoolManager.SwapParams memory params = IPoolManager.SwapParams({
            zeroForOne: nativeToken == Currency.unwrap(ethBpPoolKey.currency0),
            amountSpecified: int256(_ethAmount),
            sqrtPriceLimitX96: nativeToken == Currency.unwrap(ethBpPoolKey.currency0) 
                ? 4295343490 // MIN_SQRT_PRICE + some buffer (from TickMath tests)
                : 1461373636630004318706518188784493106690254656249 // MAX_SQRT_PRICE - 1 (from TickMath tests)
        });
        
        BalanceDelta delta = poolManager.swap(ethBpPoolKey, params, "");
        
        // Determine which currency is which
        bool ethIsCurrency0 = nativeToken == Currency.unwrap(ethBpPoolKey.currency0);
        int128 bpDelta = ethIsCurrency0 ? delta.amount1() : delta.amount0();
        int128 ethDelta = ethIsCurrency0 ? delta.amount0() : delta.amount1();
        
        // BP amount is the absolute value of the BP delta (we receive BP, so it should be positive)
        bpAmount = bpDelta > 0 ? uint256(uint128(bpDelta)) : 0;
        
        // Handle settlement using proper currency settlement pattern
        if (ethDelta < 0) {
            // We owe ETH to the pool - settle the debt
            uint256 ethOwed = uint256(uint128(-ethDelta));
            Currency.wrap(nativeToken).settle(poolManager, address(this), ethOwed, false);
        }
        if (bpDelta > 0) {
            // We receive BP from the pool - take the credit
            uint256 bpReceived = uint256(uint128(bpDelta));
            Currency.wrap(blueprintToken).take(poolManager, address(this), bpReceived, false);
        }
        
        require(bpAmount > 0, "No BP tokens received");
    }
    
    /**
     * @notice Swap BP tokens for Creator tokens (called within unlock callback)
     */
    function _swapBpForCreator(address _creatorToken, uint256 _bpAmount) internal returns (uint256 creatorAmount) {
        require(_bpAmount > 0, "BP amount cannot be zero");
        
        PoolKey memory poolKey = blueprintCreatorPools[_creatorToken];
        
        IPoolManager.SwapParams memory params = IPoolManager.SwapParams({
            zeroForOne: blueprintToken == Currency.unwrap(poolKey.currency0),
            amountSpecified: int256(_bpAmount),
            sqrtPriceLimitX96: blueprintToken == Currency.unwrap(poolKey.currency0)
                ? 4295343490 // MIN_SQRT_PRICE + some buffer (from TickMath tests)
                : 1461373636630004318706518188784493106690254656249 // MAX_SQRT_PRICE - 1 (from TickMath tests)
        });
        
        BalanceDelta delta = poolManager.swap(poolKey, params, "");
        
        // Determine which currency is which
        bool bpIsCurrency0 = blueprintToken == Currency.unwrap(poolKey.currency0);
        int128 creatorDelta = bpIsCurrency0 ? delta.amount1() : delta.amount0();
        int128 bpDelta = bpIsCurrency0 ? delta.amount0() : delta.amount1();
        
        // Creator amount is the absolute value of the creator delta (we receive creator tokens)
        creatorAmount = creatorDelta > 0 ? uint256(uint128(creatorDelta)) : 0;
        
        // Handle settlement using proper currency settlement pattern
        if (bpDelta < 0) {
            // We owe BP to the pool - settle the debt
            uint256 bpOwed = uint256(uint128(-bpDelta));
            Currency.wrap(blueprintToken).settle(poolManager, address(this), bpOwed, false);
        }
        if (creatorDelta > 0) {
            // We receive creator tokens from the pool - take the credit
            uint256 creatorReceived = uint256(uint128(creatorDelta));
            Currency.wrap(_creatorToken).take(poolManager, address(this), creatorReceived, false);
        }
        
        require(creatorAmount > 0, "No creator tokens received");
    }
    
    /**
     * @notice Handle Blueprint-specific fee distribution (60/20/10/10)
     */
    function _handleBlueprintSwap(
        address _sender,
        PoolKey calldata _key,
        IPoolManager.SwapParams calldata _params,
        BalanceDelta _delta,
        bytes calldata _hookData
    ) internal {
        // Calculate swap fees
        uint256 swapFee = _calculateBlueprintFees(_delta);
        
        if (swapFee > 0) {
            // Distribute according to Blueprint model: 60/20/10/10
            uint256 buybackAmount = swapFee * blueprintFeeConfig.buybackFee / 10000;
            uint256 creatorAmount = swapFee * blueprintFeeConfig.creatorFee / 10000;
            uint256 bpTreasuryAmount = swapFee * blueprintFeeConfig.bpTreasuryFee / 10000;
            uint256 rewardPoolAmount = swapFee * blueprintFeeConfig.rewardPoolFee / 10000;
            
            // Transfer to respective contracts
            if (buybackAmount > 0) {
                IERC20(blueprintToken).transfer(address(buybackEscrow), buybackAmount);
            }
            if (bpTreasuryAmount > 0) {
                IERC20(blueprintToken).transfer(bpTreasury, bpTreasuryAmount);
            }
            if (rewardPoolAmount > 0) {
                IERC20(blueprintToken).transfer(address(rewardPool), rewardPoolAmount);
            }
            // Creator amount goes to treasury (handled by existing logic)
        }
    }
    
    /**
     * @notice Track XP events for Blueprint Protocol
     */
    function _trackBlueprintEvent(address _user, address _token, bool _isBuy) internal {
        try rewardPool.trackBuyEvent(_user, _token) {
            uint256 xpAmount = _isBuy ? 10 : 5; // Default XP amounts
            emit XPAwarded(_user, _token, xpAmount, _isBuy ? "Buy Event" : "Sell Event");
        } catch {
            // Silently fail to not block swaps
        }
    }
    
    /**
     * @notice Calculate Blueprint-specific fees
     */
    function _calculateBlueprintFees(BalanceDelta _delta) internal pure returns (uint256) {
        // 1% swap fee on Blueprint pools
        int128 amount = _delta.amount0() > 0 ? _delta.amount0() : _delta.amount1();
        return uint256(uint128(amount > 0 ? amount : -amount)) / 100; // 1% fee
    }
    
    /**
     * @notice Get default sqrt price for pools
     */
    function _getDefaultSqrtPrice() internal pure returns (uint160) {
        return 79228162514264337593543950336; // sqrt(1) in Q64.96 format
    }
    
    /**
     * @notice Update Blueprint fee configuration
     * @param _newConfig New fee configuration
     */
    function updateBlueprintFeeConfig(BlueprintFeeConfig calldata _newConfig) external onlyOwner {
        uint24 totalFees = _newConfig.buybackFee + _newConfig.creatorFee + _newConfig.bpTreasuryFee + _newConfig.rewardPoolFee;
        if (totalFees != 10000) revert InvalidBlueprintFee(); // Must total 100%
        
        blueprintFeeConfig = _newConfig;
    }
    
    /**
     * @notice Get Blueprint fee configuration
     */
    function getBlueprintFeeConfig() external view returns (BlueprintFeeConfig memory) {
        return blueprintFeeConfig;
    }
    
    /**
     * @notice Get ETH/BP pool key
     */
    function getEthBpPoolKey() external view returns (PoolKey memory) {
        return ethBpPoolKey;
    }
    
    /**
     * @notice Get Blueprint pool for a creator token
     */
    function getBlueprintPool(address _creatorToken) external view returns (PoolKey memory) {
        return blueprintCreatorPools[_creatorToken];
    }
    
    /**
     * @notice Check if a token uses Blueprint Protocol
     */
    function isBlueprint(address _token) external view returns (bool) {
        return isBlueprintToken[_token];
    }
    
    /**
     * @notice Test helper function to mark a token as Blueprint token (only for testing)
     * @dev This should only be used in test environments
     */
    function markAsBlueprintToken(address _token, PoolKey memory _poolKey) external onlyOwner {
        isBlueprintToken[_token] = true;
        blueprintCreatorPools[_token] = _poolKey;
    }
} 