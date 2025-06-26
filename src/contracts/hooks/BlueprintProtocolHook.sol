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

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ERC721} from "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";

import {Currency} from "@uniswap/v4-core/src/types/Currency.sol";
import {IPoolManager} from "@uniswap/v4-core/src/interfaces/IPoolManager.sol";
import {PoolId, PoolIdLibrary} from "@uniswap/v4-core/src/types/PoolId.sol";
import {PoolKey} from "@uniswap/v4-core/src/types/PoolKey.sol";
import {Hooks, IHooks} from "@uniswap/v4-core/src/libraries/Hooks.sol";
import {BalanceDelta} from "@uniswap/v4-core/src/types/BalanceDelta.sol";
import {BeforeSwapDelta, BeforeSwapDeltaLibrary} from "@uniswap/v4-core/src/types/BeforeSwapDelta.sol";
import {IUnlockCallback} from "@uniswap/v4-core/src/interfaces/callback/IUnlockCallback.sol";
import {LPFeeLibrary} from "@uniswap/v4-core/src/libraries/LPFeeLibrary.sol";
import {ModifyLiquidityParams, SwapParams} from "@uniswap/v4-core/src/types/PoolOperation.sol";

import {BaseHook} from "@uniswap-periphery/utils/BaseHook.sol";

import {IBlueprintProtocol} from "@flaunch-interfaces/IBlueprintProtocol.sol";
import {IBlueprintFactory} from "@flaunch-interfaces/IBlueprintFactory.sol";

/**
 * @title BlueprintProtocolHook
 * @notice Unified Blueprint Protocol hook and position manager
 * @dev Combines hook functionality with position management for Blueprint Protocol
 * Features:
 * - Single hook for all Blueprint pools
 * - ETH → BP → Creator token routing
 * - Configurable fee distribution (60/20/10/10)
 * - Position NFT management
 * - XP tracking and rewards
 * - Role-based access control
 * - Upgradeable architecture
 */
contract BlueprintProtocolHook is
    BaseHook,
    AccessControlUpgradeable,
    UUPSUpgradeable,
    PausableUpgradeable,
    ReentrancyGuardUpgradeable,
    IBlueprintProtocol
{
    using PoolIdLibrary for PoolKey;
    using SafeERC20 for IERC20;
    using LPFeeLibrary for uint24;

    // Role definitions
    bytes32 public constant FEE_MANAGER_ROLE = keccak256("FEE_MANAGER_ROLE");
    bytes32 public constant TREASURY_MANAGER_ROLE =
        keccak256("TREASURY_MANAGER_ROLE");
    bytes32 public constant CREATOR_MANAGER_ROLE =
        keccak256("CREATOR_MANAGER_ROLE");
    bytes32 public constant EMERGENCY_ROLE = keccak256("EMERGENCY_ROLE");
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");

    // Constants
    uint24 public constant MAX_FEE_PERCENTAGE = 100_00; // 100% in basis points
    uint256 public constant DEFAULT_BLUEPRINT_SUPPLY = 10_000_000_000 ether; // 10B tokens
    uint256 private constant MIN_SQRT_PRICE = 4295128739; // sqrt(1) + small buffer
    uint256 private constant MAX_SQRT_PRICE =
        1461446703485210103287273052203988822378723970341; // sqrt(2^128) - 1

    // Blueprint Protocol Fee: 1% total fee (10000 in LPFeeLibrary units where 1000000 = 100%)
    uint24 public constant BLUEPRINT_FEE = 10000; // 1% in LPFeeLibrary units

    // Core Protocol State
    address public override blueprintToken;
    PoolKey private _ethBpPoolKey;
    address public factory;
    FeeConfiguration public feeConfig;
    address private _admin;

    // Treasury and Reward Contracts
    address public treasury;
    address public buybackEscrow;
    address public rewardPool;
    address public nativeToken; // WETH

    // Creator Management
    mapping(address => bool) public approvedCreators;
    mapping(address => PoolKey) public creatorPoolKeys;
    mapping(address => address) public creatorTreasuries;
    mapping(address => address[]) public creatorTokensByCreator;

    // Position Management (simplified for V2)
    uint256 private _nextTokenId = 1;
    mapping(uint256 => uint256) public positionRewards; // BP rewards for position

    // Callback Data Structures
    struct SwapCallbackData {
        address user;
        address creatorToken;
        uint256 minOut;
        uint256 inputAmount;
        bool isEthToCreator; // true for ETH->Creator, false for Creator->ETH
    }

    // Position Management Structs (from IBlueprintPositionManager)
    struct PositionInfo {
        PoolKey poolKey;
        int24 tickLower;
        int24 tickUpper;
        uint128 liquidity;
        uint256 feeGrowthInside0LastX128;
        uint256 feeGrowthInside1LastX128;
        uint128 tokensOwed0;
        uint128 tokensOwed1;
        uint256 bpRewardsOwed;
    }

    struct MintParams {
        PoolKey poolKey;
        int24 tickLower;
        int24 tickUpper;
        uint256 amount0Desired;
        uint256 amount1Desired;
        uint256 amount0Min;
        uint256 amount1Min;
        address recipient;
        uint256 deadline;
    }

    struct IncreaseLiquidityParams {
        uint256 tokenId;
        uint256 amount0Desired;
        uint256 amount1Desired;
        uint256 amount0Min;
        uint256 amount1Min;
        uint256 deadline;
    }

    struct DecreaseLiquidityParams {
        uint256 tokenId;
        uint128 liquidity;
        uint256 amount0Min;
        uint256 amount1Min;
        uint256 deadline;
    }

    struct CollectParams {
        uint256 tokenId;
        address recipient;
        uint128 amount0Max;
        uint128 amount1Max;
    }

    // Events
    event BlueprintProtocolInitialized(
        address indexed blueprintToken,
        address indexed factory
    );
    event CreatorApproved(address indexed creator, bool approved);
    event FeeConfigurationUpdated(FeeConfiguration newConfig);
    event SwapRouted(
        address indexed user,
        address indexed creatorToken,
        uint256 ethAmount,
        uint256 bpAmount,
        uint256 creatorAmount
    );
    event SwapExecuted(
        PoolId indexed poolId,
        address indexed sender,
        BalanceDelta delta
    );

    // Errors
    error NotInitialized();
    error CreatorNotApproved();
    error InvalidFeeConfiguration();
    error InvalidAddress();
    error InsufficientOutput();
    error PoolNotFound();
    error OnlyFactory();
    error SwapFailed();
    error MustUseDynamicFee();

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor(IPoolManager _poolManager) BaseHook(_poolManager) {
        _disableInitializers();
    }

    /**
     * @notice Initialize the Blueprint Protocol (simplified version for V2)
     * @param admin Admin address that receives all initial roles
     * @param _factory Blueprint Factory address (can be zero initially)
     */
    function initialize(address admin, address _factory) public initializer {
        if (admin == address(0)) {
            revert InvalidAddress();
        }

        __AccessControl_init();
        __UUPSUpgradeable_init();
        __Pausable_init();
        __ReentrancyGuard_init();

        // Set factory (can be set later if zero)
        factory = _factory;

        // Store admin address
        _admin = admin;

        // Set up roles - admin gets all roles initially
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(FEE_MANAGER_ROLE, admin);
        _grantRole(TREASURY_MANAGER_ROLE, admin);
        _grantRole(CREATOR_MANAGER_ROLE, admin);
        _grantRole(EMERGENCY_ROLE, admin);
        _grantRole(UPGRADER_ROLE, admin);

        // Set default fee configuration (60/20/10/10)
        feeConfig = FeeConfiguration({
            buybackFee: 6000, // 60%
            creatorFee: 2000, // 20%
            bpTreasuryFee: 1000, // 10%
            rewardPoolFee: 1000, // 10%
            active: true
        });
    }

    /**
     * @notice Initialize Blueprint token (pool creation handled by factory)
     * @param _blueprintToken Address of deployed Blueprint token
     * @param _nativeToken Address of native token (WETH)
     */
    function initializeBlueprintToken(
        address _blueprintToken,
        address _nativeToken
    ) external onlyRole(DEFAULT_ADMIN_ROLE) whenNotPaused {
        if (_blueprintToken == address(0)) revert InvalidAddress();
        if (_nativeToken == address(0)) revert InvalidAddress();

        blueprintToken = _blueprintToken;
        nativeToken = _nativeToken;

        emit BlueprintProtocolInitialized(_blueprintToken, factory);
    }

    /**
     * @notice Register ETH/BP pool after factory creates it (only callable by factory)
     * @param poolKey Pool key of the created ETH/BP pool
     */
    function registerEthBpPool(PoolKey calldata poolKey) external override {
        if (msg.sender != factory) revert OnlyFactory();
        if (blueprintToken == address(0)) revert NotInitialized();

        // Store ETH/BP pool information
        _ethBpPoolKey = poolKey;

        emit PoolCreated(
            poolKey.toId(),
            Currency.unwrap(poolKey.currency0),
            Currency.unwrap(poolKey.currency1)
        );
    }

    // =============================================================
    //                    CORE PROTOCOL FUNCTIONS
    // =============================================================

    /**
     * @notice Register a creator pool after factory creates it (only callable by factory)
     * @param creatorToken Address of creator token
     * @param _treasury Address of creator treasury
     * @param poolKey Pool key of the created pool
     */
    function registerCreatorPool(
        address creatorToken,
        address _treasury,
        PoolKey calldata poolKey
    ) external override {
        if (msg.sender != factory) revert OnlyFactory();
        if (blueprintToken == address(0)) revert NotInitialized();

        // Store pool information for swap routing
        creatorPoolKeys[creatorToken] = poolKey;
        creatorTreasuries[creatorToken] = _treasury;

        emit PoolCreated(
            poolKey.toId(),
            Currency.unwrap(poolKey.currency0),
            Currency.unwrap(poolKey.currency1)
        );
    }

    /**
     * @notice Route ETH to Creator tokens (ETH → BP → Creator)
     * @param creatorToken Target creator token
     * @param minCreatorOut Minimum creator tokens to receive
     * @return creatorAmount Amount of creator tokens received
     */
    function routeEthToCreator(
        address creatorToken,
        uint256 minCreatorOut
    )
        external
        payable
        override
        nonReentrant
        whenNotPaused
        returns (uint256 creatorAmount)
    {
        if (msg.value == 0) revert InsufficientOutput();
        if (creatorPoolKeys[creatorToken].fee == 0) revert PoolNotFound();

        SwapCallbackData memory callbackData = SwapCallbackData({
            user: msg.sender,
            creatorToken: creatorToken,
            minOut: minCreatorOut,
            inputAmount: msg.value,
            isEthToCreator: true
        });

        bytes memory result = poolManager.unlock(abi.encode(callbackData));
        creatorAmount = abi.decode(result, (uint256));

        // Track XP for buy event
        _trackXpEvent(msg.sender, creatorToken, true, creatorAmount);

        emit TokensRouted(msg.sender, msg.value, 0, creatorAmount);
    }

    /**
     * @notice Route Creator tokens to ETH (Creator → BP → ETH)
     * @param creatorToken Creator token to sell
     * @param creatorAmount Amount of creator tokens to sell
     * @param minEthOut Minimum ETH to receive
     * @return ethAmount Amount of ETH received
     */
    function routeCreatorToEth(
        address creatorToken,
        uint256 creatorAmount,
        uint256 minEthOut
    ) external override nonReentrant whenNotPaused returns (uint256 ethAmount) {
        if (creatorAmount == 0) revert InsufficientOutput();
        if (creatorPoolKeys[creatorToken].fee == 0) revert PoolNotFound();

        // Transfer creator tokens from user
        IERC20(creatorToken).safeTransferFrom(
            msg.sender,
            address(this),
            creatorAmount
        );

        SwapCallbackData memory callbackData = SwapCallbackData({
            user: msg.sender,
            creatorToken: creatorToken,
            minOut: minEthOut,
            inputAmount: creatorAmount,
            isEthToCreator: false
        });

        bytes memory result = poolManager.unlock(abi.encode(callbackData));
        ethAmount = abi.decode(result, (uint256));

        // Track XP for sell event
        _trackXpEvent(msg.sender, creatorToken, false, creatorAmount);

        emit TokensRouted(msg.sender, ethAmount, 0, creatorAmount);
    }

    // =============================================================
    //                    UNLOCK CALLBACK
    // =============================================================

    /**
     * @notice Handle swap routing callback
     */
    function _unlockCallback(
        bytes calldata data
    ) internal returns (bytes memory) {
        SwapCallbackData memory callbackData = abi.decode(
            data,
            (SwapCallbackData)
        );

        if (callbackData.isEthToCreator) {
            return _handleEthToCreatorSwap(callbackData);
        } else {
            return _handleCreatorToEthSwap(callbackData);
        }
    }

    // =============================================================
    //                    HOOK FUNCTIONS
    // =============================================================

    /**
     * @notice Hook called before swaps to set dynamic fees
     * Only applies fees to user-initiated swaps, not hook-initiated swaps
     */
    function _beforeSwap(
        address sender,
        PoolKey calldata key,
        SwapParams calldata,
        bytes calldata
    )
        internal
        virtual
        override
        returns (bytes4, BeforeSwapDelta, uint24)
    {
        // Skip fee collection for hook-initiated swaps to prevent loops
        if (sender == address(this)) {
            return (
                this.beforeSwap.selector,
                BeforeSwapDeltaLibrary.ZERO_DELTA,
                0
            );
        }

        // Apply 1% fee to all Blueprint pool swaps using dynamic fee override
        if (_isBlueprintPool(key)) {
            uint24 feeWithFlag = BLUEPRINT_FEE | LPFeeLibrary.OVERRIDE_FEE_FLAG;
            return (
                this.beforeSwap.selector,
                BeforeSwapDeltaLibrary.ZERO_DELTA,
                feeWithFlag
            );
        }

        return (this.beforeSwap.selector, BeforeSwapDeltaLibrary.ZERO_DELTA, 0);
    }

    /**
     * @notice Hook called after swaps to collect and distribute fees
     */
    function _afterSwap(
        address sender,
        PoolKey calldata key,
        SwapParams calldata,
        BalanceDelta delta,
        bytes calldata
    ) internal virtual override returns (bytes4, int128) {
        // Skip fee distribution for hook-initiated swaps to prevent loops
        if (sender == address(this)) {
            return (this.afterSwap.selector, 0);
        }

        // For now, just emit an event for successful swaps
        // TODO: Implement proper fee collection and distribution
        if (_isBlueprintPool(key)) {
            emit SwapExecuted(key.toId(), sender, delta);
        }

        return (this.afterSwap.selector, 0);
    }

    /**
     * @notice Hook called before pool initialization to enforce dynamic fees
     */
    function _beforeInitialize(
        address,
        PoolKey calldata key,
        uint160
    ) internal view virtual override returns (bytes4) {
        // Enforce that Blueprint pools must use dynamic fees
        if (_isBlueprintPool(key) && !key.fee.isDynamicFee()) {
            revert MustUseDynamicFee();
        }
        return this.beforeInitialize.selector;
    }

    /**
     * @notice Define hook permissions
     */
    function getHookPermissions()
        public
        pure
        override
        returns (Hooks.Permissions memory)
    {
        return
            Hooks.Permissions({
                beforeInitialize: true, // Enable to enforce dynamic fees
                afterInitialize: false,
                beforeAddLiquidity: false,
                afterAddLiquidity: false,
                beforeRemoveLiquidity: false,
                afterRemoveLiquidity: false,
                beforeSwap: true, // Enable to set dynamic fees
                afterSwap: true, // Enable to collect and distribute fees
                beforeDonate: false,
                afterDonate: false,
                beforeSwapReturnDelta: false,
                afterSwapReturnDelta: false,
                afterAddLiquidityReturnDelta: false,
                afterRemoveLiquidityReturnDelta: false
            });
    }

    // =============================================================
    //                    INTERNAL FUNCTIONS
    // =============================================================

    /**
     * @notice Handle ETH to Creator token swap with 1% total fee
     */
    function _handleEthToCreatorSwap(
        SwapCallbackData memory data
    ) internal returns (bytes memory) {
        // Calculate 1% total fee on input ETH amount
        uint256 totalFeeAmount = (data.inputAmount * 10000) / 1000000; // 1% = 10000/1000000
        uint256 swapAmount = data.inputAmount - totalFeeAmount;

        // Step 1: Swap ETH for BP (using amount after fee)
        // Hook-initiated swaps will be detected by sender == address(this) in beforeSwap/afterSwap
        uint256 bpAmount = _swapEthForBp(swapAmount);

        // Step 2: Swap BP for Creator tokens
        uint256 creatorAmount = _swapBpForCreator(data.creatorToken, bpAmount);

        if (creatorAmount < data.minOut) revert InsufficientOutput();

        // Step 3: Distribute fees (in ETH)
        _distributeFeeInEth(totalFeeAmount, data.creatorToken);

        // Transfer creator tokens to user
        IERC20(data.creatorToken).safeTransfer(data.user, creatorAmount);

        return abi.encode(creatorAmount);
    }

    /**
     * @notice Handle Creator token to ETH swap with 1% total fee
     */
    function _handleCreatorToEthSwap(
        SwapCallbackData memory data
    ) internal returns (bytes memory) {
        // Step 1: Swap Creator tokens for BP
        // Hook-initiated swaps will be detected by sender == address(this) in beforeSwap/afterSwap
        uint256 bpAmount = _swapCreatorForBp(
            data.creatorToken,
            data.inputAmount
        );

        // Step 2: Swap BP for ETH
        uint256 ethAmount = _swapBpForEth(bpAmount);

        // Calculate 1% total fee on output ETH amount
        uint256 totalFeeAmount = (ethAmount * 10000) / 1000000; // 1% = 10000/1000000
        uint256 userEthAmount = ethAmount - totalFeeAmount;

        if (userEthAmount < data.minOut) revert InsufficientOutput();

        // Step 3: Distribute fees (in ETH)
        _distributeFeeInEth(totalFeeAmount, data.creatorToken);

        // Transfer ETH to user (after fee)
        (bool success, ) = data.user.call{value: userEthAmount}("");
        if (!success) revert SwapFailed();

        return abi.encode(userEthAmount);
    }

    /**
     * @notice Swap ETH for BP tokens
     */
    function _swapEthForBp(
        uint256 ethAmount
    ) internal returns (uint256 bpAmount) {
        SwapParams memory params = SwapParams({
            zeroForOne: nativeToken == Currency.unwrap(_ethBpPoolKey.currency0),
            amountSpecified: int256(ethAmount),
            sqrtPriceLimitX96: 0 // No price limit
        });

        BalanceDelta delta = poolManager.swap(_ethBpPoolKey, params, "");

        // Extract BP amount from delta (negative delta means we receive tokens)
        bool ethIsCurrency0 = nativeToken ==
            Currency.unwrap(_ethBpPoolKey.currency0);
        int128 bpDelta = ethIsCurrency0 ? delta.amount1() : delta.amount0();

        bpAmount = bpDelta < 0 ? uint256(uint128(-bpDelta)) : 0;
        if (bpAmount == 0) revert SwapFailed();
    }

    /**
     * @notice Swap BP for Creator tokens
     */
    function _swapBpForCreator(
        address creatorToken,
        uint256 bpAmount
    ) internal returns (uint256 creatorAmount) {
        PoolKey memory poolKey = creatorPoolKeys[creatorToken];

        SwapParams memory params = SwapParams({
            zeroForOne: blueprintToken == Currency.unwrap(poolKey.currency0),
            amountSpecified: int256(bpAmount),
            sqrtPriceLimitX96: 0
        });

        BalanceDelta delta = poolManager.swap(poolKey, params, "");

        // Extract creator token amount from delta (negative delta means we receive tokens)
        bool bpIsCurrency0 = blueprintToken ==
            Currency.unwrap(poolKey.currency0);
        int128 creatorDelta = bpIsCurrency0 ? delta.amount1() : delta.amount0();

        creatorAmount = creatorDelta < 0 ? uint256(uint128(-creatorDelta)) : 0;
        if (creatorAmount == 0) revert SwapFailed();
    }

    /**
     * @notice Swap Creator tokens for BP
     */
    function _swapCreatorForBp(
        address creatorToken,
        uint256 creatorAmount
    ) internal returns (uint256 bpAmount) {
        PoolKey memory poolKey = creatorPoolKeys[creatorToken];

        SwapParams memory params = SwapParams({
            zeroForOne: creatorToken == Currency.unwrap(poolKey.currency0),
            amountSpecified: int256(creatorAmount),
            sqrtPriceLimitX96: 0
        });

        BalanceDelta delta = poolManager.swap(poolKey, params, "");

        // Extract BP amount from delta (negative delta means we receive tokens)
        bool creatorIsCurrency0 = creatorToken ==
            Currency.unwrap(poolKey.currency0);
        int128 bpDelta = creatorIsCurrency0 ? delta.amount1() : delta.amount0();

        bpAmount = bpDelta < 0 ? uint256(uint128(-bpDelta)) : 0;
        if (bpAmount == 0) revert SwapFailed();
    }

    /**
     * @notice Swap BP for ETH
     */
    function _swapBpForEth(
        uint256 bpAmount
    ) internal returns (uint256 ethAmount) {
        SwapParams memory params = SwapParams({
            zeroForOne: blueprintToken ==
                Currency.unwrap(_ethBpPoolKey.currency0),
            amountSpecified: int256(bpAmount),
            sqrtPriceLimitX96: 0
        });

        BalanceDelta delta = poolManager.swap(_ethBpPoolKey, params, "");

        // Extract ETH amount from delta (negative delta means we receive tokens)
        bool bpIsCurrency0 = blueprintToken ==
            Currency.unwrap(_ethBpPoolKey.currency0);
        int128 ethDelta = bpIsCurrency0 ? delta.amount1() : delta.amount0();

        ethAmount = ethDelta < 0 ? uint256(uint128(-ethDelta)) : 0;
        if (ethAmount == 0) revert SwapFailed();
    }

    /**
     * @notice Distribute fees in ETH according to Blueprint model (60/20/10/10)
     * @param totalFeeAmount Total fee amount in ETH (1% of swap)
     * @param creatorToken Address of creator token (for creator fee allocation)
     */
    function _distributeFeeInEth(
        uint256 totalFeeAmount,
        address creatorToken
    ) internal {
        if (totalFeeAmount == 0) return;

        // Calculate fee distribution (60/20/10/10)
        uint256 buybackAmount = (totalFeeAmount * feeConfig.buybackFee) / 10000; // 60%
        uint256 creatorAmount = (totalFeeAmount * feeConfig.creatorFee) / 10000; // 20%
        uint256 treasuryAmount = (totalFeeAmount * feeConfig.bpTreasuryFee) /
            10000; // 10%
        uint256 rewardPoolAmount = (totalFeeAmount * feeConfig.rewardPoolFee) /
            10000; // 10%

        // Send ETH to buyback escrow
        if (buybackAmount > 0 && buybackEscrow != address(0)) {
            (bool success, ) = buybackEscrow.call{value: buybackAmount}("");
            if (!success) revert SwapFailed();
        }

        // Send ETH to creator treasury
        if (creatorAmount > 0) {
            address creatorTreasury = creatorTreasuries[creatorToken];
            if (creatorTreasury != address(0)) {
                (bool success, ) = creatorTreasury.call{value: creatorAmount}(
                    ""
                );
                if (!success) revert SwapFailed();
            }
        }

        // Send ETH to BP treasury
        if (treasuryAmount > 0 && treasury != address(0)) {
            (bool success, ) = treasury.call{value: treasuryAmount}("");
            if (!success) revert SwapFailed();
        }

        // Send ETH to reward pool
        if (rewardPoolAmount > 0 && rewardPool != address(0)) {
            (bool success, ) = rewardPool.call{value: rewardPoolAmount}("");
            if (!success) revert SwapFailed();
        }

        emit FeesDistributed(
            PoolId.wrap(bytes32(0)), // Not pool-specific anymore
            buybackAmount,
            creatorAmount,
            treasuryAmount,
            rewardPoolAmount
        );
    }

    /**
     * @notice Collect and distribute fees (simplified for V2)
     * TODO: Implement proper fee collection and distribution
     */
    function _collectAndDistributeFees(
        PoolKey calldata key,
        BalanceDelta delta
    ) internal {
        // Simplified implementation - just emit event for now
        // Complex fee distribution will be implemented in a future version
        emit SwapExecuted(key.toId(), msg.sender, delta);
    }

    /**
     * @notice Calculate fee amount from swap delta
     * @param key Pool key for the swap
     * @param delta Balance delta from the swap
     * @return feeAmount Calculated fee amount
     */
    function _calculateFeeFromDelta(
        PoolKey calldata key,
        BalanceDelta delta
    ) internal view returns (uint256) {
        // Get the larger absolute value from the delta (this represents the input amount)
        uint256 amount0 = delta.amount0() < 0
            ? uint256(uint128(-delta.amount0()))
            : uint256(uint128(delta.amount0()));
        uint256 amount1 = delta.amount1() < 0
            ? uint256(uint128(-delta.amount1()))
            : uint256(uint128(delta.amount1()));

        uint256 inputAmount = amount0 > amount1 ? amount0 : amount1;

        // Calculate 1% fee on the input amount
        return (inputAmount * BLUEPRINT_FEE) / 1000000; // BLUEPRINT_FEE = 10000 = 1%
    }

    /**
     * @notice Determine which currency the fee should be collected in
     * @param key Pool key for the swap
     * @param delta Balance delta from the swap
     * @return feeCurrency Currency to collect fees in
     */
    function _getFeeCurrency(
        PoolKey calldata key,
        BalanceDelta delta
    ) internal pure returns (Currency) {
        // Collect fees in the input token (the one with positive delta)
        if (delta.amount0() > 0) {
            return key.currency0;
        } else {
            return key.currency1;
        }
    }

    /**
     * @notice Collect fees from the pool manager
     * @param key Pool key
     * @param currency Currency to collect
     * @param amount Amount to collect
     * @return collected Actual amount collected
     */
    function _collectFeesFromPool(
        PoolKey calldata key,
        Currency currency,
        uint256 amount
    ) internal returns (uint256 collected) {
        // In Uniswap V4, fees are automatically collected by the pool manager
        // We need to use the take/settle mechanism to extract our fees

        try poolManager.take(currency, address(this), uint128(amount)) {
            collected = amount;
        } catch {
            // If we can't collect the full amount, try to collect what's available
            uint256 available = currency.balanceOf(address(poolManager));
            if (available > 0) {
                uint128 collectAmount = uint128(
                    available > amount ? amount : available
                );
                try poolManager.take(currency, address(this), collectAmount) {
                    collected = collectAmount;
                } catch {
                    collected = 0;
                }
            }
        }
    }

    /**
     * @notice Convert collected fees to ETH
     * @param feeCurrency Currency of the collected fees
     * @param amount Amount to convert
     * @return ethAmount Amount of ETH after conversion
     */
    function _convertFeeToEth(
        Currency feeCurrency,
        uint256 amount
    ) internal returns (uint256 ethAmount) {
        // If fee is already in ETH (native token), no conversion needed
        if (Currency.unwrap(feeCurrency) == nativeToken) {
            return amount;
        }

        // If fee is in Blueprint token, convert BP -> ETH
        if (Currency.unwrap(feeCurrency) == blueprintToken) {
            return _swapBpForEth(amount);
        }

        // If fee is in creator token, convert Creator -> BP -> ETH
        // First convert creator token to BP
        address creatorToken = Currency.unwrap(feeCurrency);
        uint256 bpAmount = _swapCreatorForBp(creatorToken, amount);

        // Then convert BP to ETH
        return _swapBpForEth(bpAmount);
    }

    /**
     * @notice Get creator token address from pool key
     * @param key Pool key
     * @return creatorToken Address of creator token, or zero if not a creator pool
     */
    function _getCreatorTokenFromPool(
        PoolKey calldata key
    ) internal view returns (address creatorToken) {
        // Check if currency0 is blueprint token, then currency1 is creator token
        if (Currency.unwrap(key.currency0) == blueprintToken) {
            return Currency.unwrap(key.currency1);
        }

        // Check if currency1 is blueprint token, then currency0 is creator token
        if (Currency.unwrap(key.currency1) == blueprintToken) {
            return Currency.unwrap(key.currency0);
        }

        // If neither is blueprint token, this might be ETH/BP pool
        // In that case, return zero (no specific creator)
        return address(0);
    }

    /**
     * @notice Check if pool is a Blueprint pool
     */
    function _isBlueprintPool(
        PoolKey calldata key
    ) internal view returns (bool) {
        // During initialization, blueprintToken might not be set yet
        if (blueprintToken == address(0)) {
            return false;
        }
        return (Currency.unwrap(key.currency0) == blueprintToken ||
            Currency.unwrap(key.currency1) == blueprintToken);
    }

    /**
     * @notice Track XP events
     */
    function _trackXpEvent(
        address user,
        address token,
        bool isBuy,
        uint256 amount
    ) internal {
        // XP tracking logic - emit event for now
        uint256 xpAmount = isBuy ? 10 : 5; // Base XP amounts
        emit XPAwarded(
            user,
            token,
            xpAmount,
            isBuy ? "Buy Event" : "Sell Event"
        );
    }

    /**
     * @notice Validate fee configuration
     */
    function _validateFeeConfiguration(
        FeeConfiguration memory config
    ) internal pure {
        if (
            config.buybackFee > MAX_FEE_PERCENTAGE ||
            config.creatorFee > MAX_FEE_PERCENTAGE ||
            config.bpTreasuryFee > MAX_FEE_PERCENTAGE ||
            config.rewardPoolFee > MAX_FEE_PERCENTAGE
        ) {
            revert InvalidFeeConfiguration();
        }

        uint24 totalFees = config.buybackFee +
            config.creatorFee +
            config.bpTreasuryFee +
            config.rewardPoolFee;
        if (totalFees > MAX_FEE_PERCENTAGE) {
            revert InvalidFeeConfiguration();
        }
    }

    /**
     * @notice Get initial sqrt price for pools
     */
    function _getInitialSqrtPrice() internal pure returns (uint160) {
        return 79228162514264337593543950336; // sqrt(1) in Q64.96 format
    }

    // =============================================================
    //                    ADMIN FUNCTIONS
    // =============================================================

    /**
     * @notice Approve creator to deploy tokens
     */
    function approveCreator(
        address creator,
        bool approved
    ) external override onlyRole(CREATOR_MANAGER_ROLE) {
        approvedCreators[creator] = approved;
        emit CreatorApproved(creator, approved);
    }

    /**
     * @notice Update fee configuration
     */
    function updateFeeConfiguration(
        FeeConfiguration calldata newConfig
    ) external override onlyRole(FEE_MANAGER_ROLE) {
        _validateFeeConfiguration(newConfig);
        feeConfig = newConfig;
        emit FeeConfigurationUpdated(newConfig);
    }

    /**
     * @notice Set factory address
     */
    function setFactory(
        address newFactory
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (newFactory == address(0)) revert InvalidAddress();
        factory = newFactory;
    }

    /**
     * @notice Update treasury address
     */
    function updateTreasury(
        address newTreasury
    ) external onlyRole(TREASURY_MANAGER_ROLE) {
        if (newTreasury == address(0)) revert InvalidAddress();
        treasury = newTreasury;
    }

    /**
     * @notice Emergency pause
     */
    function pause() external onlyRole(EMERGENCY_ROLE) {
        _pause();
    }

    /**
     * @notice Unpause
     */
    function unpause() external onlyRole(EMERGENCY_ROLE) {
        _unpause();
    }

    // =============================================================
    //                    VIEW FUNCTIONS
    // =============================================================

    function ethBpPoolKey() external view override returns (PoolKey memory) {
        return _ethBpPoolKey;
    }

    function getCreatorPoolKey(
        address creatorToken
    ) external view override returns (PoolKey memory) {
        return creatorPoolKeys[creatorToken];
    }

    function isApprovedCreator(
        address creator
    ) external view override returns (bool) {
        return approvedCreators[creator];
    }

    function getFeeConfiguration()
        external
        view
        override
        returns (FeeConfiguration memory)
    {
        return feeConfig;
    }

    function owner() external view returns (address) {
        return _admin;
    }

    /**
     * @notice Authorize upgrade function for UUPS
     */
    function _authorizeUpgrade(
        address newImplementation
    ) internal override onlyRole(UPGRADER_ROLE) {
        // Additional upgrade validation can be added here
    }

    /**
     * @notice Override supportsInterface to include all inherited interfaces
     */
    function supportsInterface(
        bytes4 interfaceId
    ) public view override(AccessControlUpgradeable) returns (bool) {
        return super.supportsInterface(interfaceId);
    }

    // Handle ETH transfers
    receive() external payable {}
}
