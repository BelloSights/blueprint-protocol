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
import {SafeERC20} from '@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol';
import {ERC721} from '@openzeppelin/contracts/token/ERC721/ERC721.sol';
import {AccessControlUpgradeable} from '@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol';
import {Initializable} from '@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol';
import {UUPSUpgradeable} from '@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol';
import {PausableUpgradeable} from '@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol';
import {ReentrancyGuardUpgradeable} from '@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol';

import {Currency} from '@uniswap/v4-core/src/types/Currency.sol';
import {IPoolManager} from '@uniswap/v4-core/src/interfaces/IPoolManager.sol';
import {PoolId, PoolIdLibrary} from '@uniswap/v4-core/src/types/PoolId.sol';
import {PoolKey} from '@uniswap/v4-core/src/types/PoolKey.sol';
import {Hooks, IHooks} from '@uniswap/v4-core/src/libraries/Hooks.sol';
import {BalanceDelta} from '@uniswap/v4-core/src/types/BalanceDelta.sol';
import {IUnlockCallback} from '@uniswap/v4-core/src/interfaces/callback/IUnlockCallback.sol';

import {BaseHook} from '@uniswap-periphery/base/hooks/BaseHook.sol';

import {IBlueprintProtocol} from '@flaunch-interfaces/IBlueprintProtocol.sol';
import {IBlueprintFactory} from '@flaunch-interfaces/IBlueprintFactory.sol';

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

    // Role definitions
    bytes32 public constant FEE_MANAGER_ROLE = keccak256("FEE_MANAGER_ROLE");
    bytes32 public constant TREASURY_MANAGER_ROLE = keccak256("TREASURY_MANAGER_ROLE");
    bytes32 public constant CREATOR_MANAGER_ROLE = keccak256("CREATOR_MANAGER_ROLE");
    bytes32 public constant EMERGENCY_ROLE = keccak256("EMERGENCY_ROLE");
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");

    // Constants
    uint24 public constant MAX_FEE_PERCENTAGE = 100_00; // 100% in basis points
    uint256 public constant DEFAULT_BLUEPRINT_SUPPLY = 10_000_000_000 ether; // 10B tokens
    uint256 private constant MIN_SQRT_PRICE = 4295128739; // sqrt(1) + small buffer
    uint256 private constant MAX_SQRT_PRICE = 1461446703485210103287273052203988822378723970341; // sqrt(2^128) - 1

    // Core Protocol State
    address public override blueprintToken;
    PoolKey private _ethBpPoolKey;
    address public factory;
    FeeConfiguration public feeConfig;
    
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
    event BlueprintProtocolInitialized(address indexed blueprintToken, address indexed factory);
    event CreatorApproved(address indexed creator, bool approved);
    event FeeConfigurationUpdated(FeeConfiguration newConfig);
    event SwapRouted(address indexed user, address indexed creatorToken, uint256 ethAmount, uint256 bpAmount, uint256 creatorAmount);

    // Errors
    error NotInitialized();
    error CreatorNotApproved();
    error InvalidFeeConfiguration();
    error InvalidAddress();
    error InsufficientOutput();
    error PoolNotFound();
    error OnlyFactory();
    error SwapFailed();

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor(IPoolManager _poolManager) 
        BaseHook(_poolManager)
    {
        _disableInitializers();
    }

    /**
     * @notice Initialize the Blueprint Protocol (simplified version for V2)
     * @param _admin Admin address that receives all initial roles
     * @param _factory Blueprint Factory address (can be zero initially)
     */
    function initialize(address _admin, address _factory) public initializer {
        if (_admin == address(0)) {
            revert InvalidAddress();
        }

        __AccessControl_init();
        __UUPSUpgradeable_init();
        __Pausable_init();
        __ReentrancyGuard_init();

        // Set factory (can be set later if zero)
        factory = _factory;

        // Set up roles - admin gets all roles initially
        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(FEE_MANAGER_ROLE, _admin);
        _grantRole(TREASURY_MANAGER_ROLE, _admin);
        _grantRole(CREATOR_MANAGER_ROLE, _admin);
        _grantRole(EMERGENCY_ROLE, _admin);
        _grantRole(UPGRADER_ROLE, _admin);

        // Set default fee configuration (60/20/10/10)
        feeConfig = FeeConfiguration({
            buybackFee: 6000,    // 60%
            creatorFee: 2000,    // 20%
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
    function initializeBlueprintToken(address _blueprintToken, address _nativeToken) 
        external 
        onlyRole(DEFAULT_ADMIN_ROLE) 
        whenNotPaused 
    {
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
    function registerEthBpPool(PoolKey calldata poolKey) 
        external 
        override 
    {
        if (msg.sender != factory) revert OnlyFactory();
        if (blueprintToken == address(0)) revert NotInitialized();
        
        // Store ETH/BP pool information
        _ethBpPoolKey = poolKey;
        
        emit PoolCreated(poolKey.toId(), Currency.unwrap(poolKey.currency0), Currency.unwrap(poolKey.currency1));
    }

    // =============================================================
    //                    CORE PROTOCOL FUNCTIONS
    // =============================================================

    /**
     * @notice Register a creator pool after factory creates it (only callable by factory)
     * @param creatorToken Address of creator token
     * @param treasury Address of creator treasury
     * @param poolKey Pool key of the created pool
     */
    function registerCreatorPool(address creatorToken, address treasury, PoolKey calldata poolKey) 
        external 
        override 
    {
        if (msg.sender != factory) revert OnlyFactory();
        if (blueprintToken == address(0)) revert NotInitialized();
        
        // Store pool information for swap routing
        creatorPoolKeys[creatorToken] = poolKey;
        creatorTreasuries[creatorToken] = treasury;
        
        emit PoolCreated(poolKey.toId(), Currency.unwrap(poolKey.currency0), Currency.unwrap(poolKey.currency1));
    }

    /**
     * @notice Route ETH to Creator tokens (ETH → BP → Creator)
     * @param creatorToken Target creator token
     * @param minCreatorOut Minimum creator tokens to receive
     * @return creatorAmount Amount of creator tokens received
     */
    function routeEthToCreator(address creatorToken, uint256 minCreatorOut) 
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
    function routeCreatorToEth(address creatorToken, uint256 creatorAmount, uint256 minEthOut) 
        external 
        override 
        nonReentrant 
        whenNotPaused 
        returns (uint256 ethAmount) 
    {
        if (creatorAmount == 0) revert InsufficientOutput();
        if (creatorPoolKeys[creatorToken].fee == 0) revert PoolNotFound();

        // Transfer creator tokens from user
        IERC20(creatorToken).safeTransferFrom(msg.sender, address(this), creatorAmount);

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
    function _unlockCallback(bytes calldata data) internal override returns (bytes memory) {
        SwapCallbackData memory callbackData = abi.decode(data, (SwapCallbackData));
        
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
     * @notice Hook called after swaps to distribute fees
     */
    function afterSwap(
        address,
        PoolKey calldata key,
        IPoolManager.SwapParams memory,
        BalanceDelta,
        bytes calldata
    ) external override onlyPoolManager whenNotPaused returns (bytes4, int128) {
        if (_isBlueprintPool(key)) {
            _distributeFees(key.toId(), key);
        }
        return (this.afterSwap.selector, 0);
    }

    /**
     * @notice Define hook permissions
     */
    function getHookPermissions() public pure override returns (Hooks.Permissions memory) {
        return Hooks.Permissions({
            beforeInitialize: false,
            afterInitialize: false,
            beforeAddLiquidity: false,
            afterAddLiquidity: false,
            beforeRemoveLiquidity: false,
            afterRemoveLiquidity: false,
            beforeSwap: false,
            afterSwap: true,
            beforeDonate: false,
            afterDonate: false,
            beforeSwapReturnDelta: false,
            afterSwapReturnDelta: false,
            afterAddLiquidityReturnDelta: false,
            afterRemoveLiquidityReturnDelta: false
        });
    }

    // =============================================================
    //                    POSITION MANAGEMENT STUBS
    // =============================================================
    
    // Note: Position management functions will be implemented in next iteration
    // These are stubs to satisfy the interface
    
    function mint(MintParams calldata) external payable returns (uint256, uint128, uint256, uint256) {
        revert("Not implemented yet");
    }
    
    function increaseLiquidity(IncreaseLiquidityParams calldata) external payable returns (uint128, uint256, uint256) {
        revert("Not implemented yet");
    }
    
    function decreaseLiquidity(DecreaseLiquidityParams calldata) external returns (uint256, uint256) {
        revert("Not implemented yet");
    }
    
    function collect(CollectParams calldata) external returns (uint256, uint256) {
        revert("Not implemented yet");
    }
    
    function burn(uint256) external {
        revert("Not implemented yet");
    }
    
    function collectBpRewards(uint256) external returns (uint256) {
        revert("Not implemented yet");
    }
    
    function getRewardsOwed(uint256) external view returns (uint256) {
        return 0; // Not implemented yet
    }

    function positions(uint256) external view returns (PositionInfo memory) {
        revert("Not implemented yet");
    }



    // =============================================================
    //                    INTERNAL FUNCTIONS
    // =============================================================

    /**
     * @notice Handle ETH to Creator token swap
     */
    function _handleEthToCreatorSwap(SwapCallbackData memory data) internal returns (bytes memory) {
        // Step 1: Swap ETH for BP
        uint256 bpAmount = _swapEthForBp(data.inputAmount);
        
        // Step 2: Swap BP for Creator tokens
        uint256 creatorAmount = _swapBpForCreator(data.creatorToken, bpAmount);
        
        if (creatorAmount < data.minOut) revert InsufficientOutput();
        
        // Transfer creator tokens to user
        IERC20(data.creatorToken).safeTransfer(data.user, creatorAmount);
        
        return abi.encode(creatorAmount);
    }

    /**
     * @notice Handle Creator token to ETH swap
     */
    function _handleCreatorToEthSwap(SwapCallbackData memory data) internal returns (bytes memory) {
        // Step 1: Swap Creator tokens for BP
        uint256 bpAmount = _swapCreatorForBp(data.creatorToken, data.inputAmount);
        
        // Step 2: Swap BP for ETH
        uint256 ethAmount = _swapBpForEth(bpAmount);
        
        if (ethAmount < data.minOut) revert InsufficientOutput();
        
        // Transfer ETH to user
        (bool success,) = data.user.call{value: ethAmount}("");
        if (!success) revert SwapFailed();
        
        return abi.encode(ethAmount);
    }





    /**
     * @notice Swap ETH for BP tokens
     */
    function _swapEthForBp(uint256 ethAmount) internal returns (uint256 bpAmount) {
        IPoolManager.SwapParams memory params = IPoolManager.SwapParams({
            zeroForOne: nativeToken == Currency.unwrap(_ethBpPoolKey.currency0),
            amountSpecified: int256(ethAmount),
            sqrtPriceLimitX96: 0 // No price limit
        });
        
        BalanceDelta delta = poolManager.swap(_ethBpPoolKey, params, "");
        
        // Extract BP amount from delta (negative delta means we receive tokens)
        bool ethIsCurrency0 = nativeToken == Currency.unwrap(_ethBpPoolKey.currency0);
        int128 bpDelta = ethIsCurrency0 ? delta.amount1() : delta.amount0();
        
        bpAmount = bpDelta < 0 ? uint256(uint128(-bpDelta)) : 0;
        if (bpAmount == 0) revert SwapFailed();
    }

    /**
     * @notice Swap BP for Creator tokens
     */
    function _swapBpForCreator(address creatorToken, uint256 bpAmount) internal returns (uint256 creatorAmount) {
        PoolKey memory poolKey = creatorPoolKeys[creatorToken];
        
        IPoolManager.SwapParams memory params = IPoolManager.SwapParams({
            zeroForOne: blueprintToken == Currency.unwrap(poolKey.currency0),
            amountSpecified: int256(bpAmount),
            sqrtPriceLimitX96: 0
        });
        
        BalanceDelta delta = poolManager.swap(poolKey, params, "");
        
        // Extract creator token amount from delta (negative delta means we receive tokens)
        bool bpIsCurrency0 = blueprintToken == Currency.unwrap(poolKey.currency0);
        int128 creatorDelta = bpIsCurrency0 ? delta.amount1() : delta.amount0();
        
        creatorAmount = creatorDelta < 0 ? uint256(uint128(-creatorDelta)) : 0;
        if (creatorAmount == 0) revert SwapFailed();
    }

    /**
     * @notice Swap Creator tokens for BP
     */
    function _swapCreatorForBp(address creatorToken, uint256 creatorAmount) internal returns (uint256 bpAmount) {
        PoolKey memory poolKey = creatorPoolKeys[creatorToken];
        
        IPoolManager.SwapParams memory params = IPoolManager.SwapParams({
            zeroForOne: creatorToken == Currency.unwrap(poolKey.currency0),
            amountSpecified: int256(creatorAmount),
            sqrtPriceLimitX96: 0
        });
        
        BalanceDelta delta = poolManager.swap(poolKey, params, "");
        
        // Extract BP amount from delta (negative delta means we receive tokens)
        bool creatorIsCurrency0 = creatorToken == Currency.unwrap(poolKey.currency0);
        int128 bpDelta = creatorIsCurrency0 ? delta.amount1() : delta.amount0();
        
        bpAmount = bpDelta < 0 ? uint256(uint128(-bpDelta)) : 0;
        if (bpAmount == 0) revert SwapFailed();
    }

    /**
     * @notice Swap BP for ETH
     */
    function _swapBpForEth(uint256 bpAmount) internal returns (uint256 ethAmount) {
        IPoolManager.SwapParams memory params = IPoolManager.SwapParams({
            zeroForOne: blueprintToken == Currency.unwrap(_ethBpPoolKey.currency0),
            amountSpecified: int256(bpAmount),
            sqrtPriceLimitX96: 0
        });
        
        BalanceDelta delta = poolManager.swap(_ethBpPoolKey, params, "");
        
        // Extract ETH amount from delta (negative delta means we receive tokens)
        bool bpIsCurrency0 = blueprintToken == Currency.unwrap(_ethBpPoolKey.currency0);
        int128 ethDelta = bpIsCurrency0 ? delta.amount1() : delta.amount0();
        
        ethAmount = ethDelta < 0 ? uint256(uint128(-ethDelta)) : 0;
        if (ethAmount == 0) revert SwapFailed();
    }

    /**
     * @notice Distribute fees according to Blueprint model (60/20/10/10)
     */
    function _distributeFees(PoolId poolId, PoolKey calldata key) internal {
        // Fee distribution logic will be implemented based on actual pool fee accumulation
        // This is a placeholder for the fee distribution mechanism
        emit FeesDistributed(poolId, 0, 0, 0, 0);
    }

    /**
     * @notice Check if pool is a Blueprint pool
     */
    function _isBlueprintPool(PoolKey calldata key) internal view returns (bool) {
        return (Currency.unwrap(key.currency0) == blueprintToken || 
                Currency.unwrap(key.currency1) == blueprintToken);
    }

    /**
     * @notice Track XP events
     */
    function _trackXpEvent(address user, address token, bool isBuy, uint256 amount) internal {
        // XP tracking logic - emit event for now
        uint256 xpAmount = isBuy ? 10 : 5; // Base XP amounts
        emit XPAwarded(user, token, xpAmount, isBuy ? "Buy Event" : "Sell Event");
    }

    /**
     * @notice Validate fee configuration
     */
    function _validateFeeConfiguration(FeeConfiguration memory config) internal pure {
        if (config.buybackFee > MAX_FEE_PERCENTAGE ||
            config.creatorFee > MAX_FEE_PERCENTAGE ||
            config.bpTreasuryFee > MAX_FEE_PERCENTAGE ||
            config.rewardPoolFee > MAX_FEE_PERCENTAGE) {
            revert InvalidFeeConfiguration();
        }
        
        uint24 totalFees = config.buybackFee + config.creatorFee + config.bpTreasuryFee + config.rewardPoolFee;
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
    function approveCreator(address creator, bool approved) 
        external 
        override 
        onlyRole(CREATOR_MANAGER_ROLE) 
    {
        approvedCreators[creator] = approved;
        emit CreatorApproved(creator, approved);
    }

    /**
     * @notice Update fee configuration
     */
    function updateFeeConfiguration(FeeConfiguration calldata newConfig) 
        external 
        override 
        onlyRole(FEE_MANAGER_ROLE) 
    {
        _validateFeeConfiguration(newConfig);
        feeConfig = newConfig;
        emit FeeConfigurationUpdated(newConfig);
    }

    /**
     * @notice Set factory address
     */
    function setFactory(address newFactory) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (newFactory == address(0)) revert InvalidAddress();
        factory = newFactory;
    }

    /**
     * @notice Set blueprint hook (this contract serves as its own hook)
     */
    function setBlueprintHook(address) external onlyRole(DEFAULT_ADMIN_ROLE) {
        // This contract is its own hook, so this is a no-op
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

    function getCreatorPoolKey(address creatorToken) external view override returns (PoolKey memory) {
        return creatorPoolKeys[creatorToken];
    }

    function isApprovedCreator(address creator) external view override returns (bool) {
        return approvedCreators[creator];
    }

    function getFeeConfiguration() external view override returns (FeeConfiguration memory) {
        return feeConfig;
    }

    function blueprintHook() external view returns (address) {
        return address(this);
    }

    /**
     * @notice Authorize upgrade function for UUPS
     */
    function _authorizeUpgrade(address newImplementation) 
        internal 
        override 
        onlyRole(UPGRADER_ROLE) 
    {
        // Additional upgrade validation can be added here
    }

    /**
     * @notice Override supportsInterface to include all inherited interfaces
     */
    function supportsInterface(bytes4 interfaceId) 
        public 
        view 
        override(AccessControlUpgradeable) 
        returns (bool) 
    {
        return super.supportsInterface(interfaceId);
    }

    // Handle ETH transfers
    receive() external payable {}
} 