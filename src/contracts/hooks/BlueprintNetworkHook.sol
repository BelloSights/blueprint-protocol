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
import {Hooks, IHooks} from '@uniswap/v4-core/src/libraries/Hooks.sol';
import {BalanceDelta} from '@uniswap/v4-core/src/types/BalanceDelta.sol';

import {BaseHook} from '@uniswap-periphery/base/hooks/BaseHook.sol';

import {FeeEscrow} from '@flaunch/escrows/FeeEscrow.sol';
import {TokenSupply} from '@flaunch/libraries/TokenSupply.sol';
import {Memecoin} from '@flaunch/Memecoin.sol';

import {IMemecoin} from '@flaunch-interfaces/IMemecoin.sol';

import {ERC1967Proxy} from '@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol';

interface IRewardPool {
    function trackBuyEvent(address user, address token) external;
    function trackSellEvent(address user, address token) external;
    function depositRewards(uint256 amount) external;
}


/**
 * BlueprintNetworkHook - Upgradeable hook with configurable fees and role-based access control
 * 
 * Features:
 * - Upgradeable using UUPS pattern
 * - Role-based access control for configuration changes
 * - Configurable fee distribution percentages
 * - Emergency pause functionality
 * - Multiple admin roles for different responsibilities
 */
contract BlueprintNetworkHook is 
    Initializable,
    BaseHook, 
    AccessControlUpgradeable,
    UUPSUpgradeable,
    PausableUpgradeable 
{

    using PoolIdLibrary for PoolKey;

    // Role definitions
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant FEE_MANAGER_ROLE = keccak256("FEE_MANAGER_ROLE");
    bytes32 public constant TREASURY_MANAGER_ROLE = keccak256("TREASURY_MANAGER_ROLE");
    bytes32 public constant EMERGENCY_ROLE = keccak256("EMERGENCY_ROLE");
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");

    error BlueprintTokenNotInitialized();
    error CreatorTokenNotFound();
    error InsufficientLiquidity();
    error InvalidRoutingPath();
    error OnlyBlueprintFactory();
    error InvalidFeePercentage();
    error InvalidAddress();
    error FeeTotalExceeds100Percent();

    event BlueprintPoolCreated(PoolId indexed poolId, address indexed blueprintToken);
    event CreatorPoolCreated(PoolId indexed poolId, address indexed creatorToken, address indexed blueprintToken);
    event TokensRouted(address indexed user, uint ethAmount, uint bpAmount, uint creatorAmount);
    event FeesDistributed(PoolId indexed poolId, uint buybackAmount, uint creatorAmount, uint bpTreasuryAmount, uint rewardPoolAmount);
    event FeeDistributionUpdated(uint24 buybackFee, uint24 creatorFee, uint24 bpTreasuryFee);
    event BpTreasuryUpdated(address indexed oldTreasury, address indexed newTreasury);
    event BuybackEscrowUpdated(address indexed oldEscrow, address indexed newEscrow);
    event BlueprintSupplyUpdated(uint256 newSupply);

    /**
     * Configurable fee distribution structure
     */
    struct FeeConfiguration {
        uint24 buybackFee;      // Fee percentage for buyback escrow (basis points)
        uint24 creatorFee;      // Fee percentage for creator/treasury (basis points)
        uint24 bpTreasuryFee;   // Fee percentage for BP treasury (basis points)
        uint24 rewardPoolFee;   // Fee percentage for XP reward pool (basis points)
        bool active;            // Whether this configuration is active
    }

    /// The Blueprint token (configurable supply network token)
    address public blueprintToken;
    
    /// ETH/BP pool key
    PoolKey public ethBpPoolKey;
    
    /// BP treasury for operations
    address public bpTreasury;
    
    /// Buyback escrow contract
    address public buybackEscrow;
    
    /// XP-based reward pool contract
    address public rewardPool;
    
    /// Maps creator tokens to their BP/Creator pool keys
    mapping(address => PoolKey) public creatorPoolKeys;
    
    /// Maps creator tokens to their treasury addresses
    mapping(address => address) public creatorTreasuries;
    
    /// Configurable fee distribution
    FeeConfiguration public feeConfig;
    
    /// Configurable Blueprint token supply
    uint256 public blueprintSupply;

    /// Core fee management variables
    address public nativeToken;
    address public flayGovernance;
    FeeEscrow public feeEscrow;

    /// Maximum fee percentage (100% in basis points)
    uint24 public constant MAX_FEE_PERCENTAGE = 100_00;

    /// Default Blueprint token supply (10 billion tokens)
    uint256 public constant DEFAULT_BLUEPRINT_SUPPLY = 10_000_000_000 ether;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor(IPoolManager _poolManager) BaseHook(_poolManager) {
        _disableInitializers();
    }

         /**
      * Initialize the upgradeable contract
      *
      * @param _nativeToken The native ETH token (WETH)
      * @param _admin The admin address (receives all roles initially)
      * @param _flayGovernance The FLAY governance address
      * @param _feeEscrow The fee escrow contract
      * @param _bpTreasury BP treasury for operations
      * @param _buybackEscrow Buyback escrow contract
      * @param _rewardPool XP-based reward pool contract
      * @param _initialFeeConfig Initial fee configuration
      */
         function initialize(
         address _nativeToken,
         address _admin,
         address _flayGovernance,
         address _feeEscrow,
         address _bpTreasury,
         address _buybackEscrow,
         address _rewardPool,
         FeeConfiguration memory _initialFeeConfig
     ) public initializer {
        if (_admin == address(0) || _bpTreasury == address(0) || _buybackEscrow == address(0) || _rewardPool == address(0)) {
            revert InvalidAddress();
        }

        __AccessControl_init();
        __UUPSUpgradeable_init();
        __Pausable_init();

        // Set core parameters
        nativeToken = _nativeToken;
        flayGovernance = _flayGovernance;
        feeEscrow = FeeEscrow(payable(_feeEscrow));

        // Set up roles
        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(ADMIN_ROLE, _admin);
        _grantRole(FEE_MANAGER_ROLE, _admin);
        _grantRole(TREASURY_MANAGER_ROLE, _admin);
        _grantRole(EMERGENCY_ROLE, _admin);
        _grantRole(UPGRADER_ROLE, _admin);

        // Set initial configuration
        bpTreasury = _bpTreasury;
        buybackEscrow = _buybackEscrow;
        rewardPool = _rewardPool;
        blueprintSupply = DEFAULT_BLUEPRINT_SUPPLY;
        
        // Validate and set fee configuration
        _validateFeeConfiguration(_initialFeeConfig);
        feeConfig = _initialFeeConfig;
    }

    /**
     * Initialize the Blueprint network by creating the BP token and ETH/BP pool
     * Only callable by ADMIN_ROLE
     *
     * @param _blueprintTokenImpl Blueprint token implementation address
     */
    function initializeBlueprintNetwork(address _blueprintTokenImpl) 
        external 
        onlyRole(ADMIN_ROLE) 
        whenNotPaused 
    {
        // Deploy Blueprint token with configurable supply
        blueprintToken = _deployBlueprintToken(_blueprintTokenImpl);
        
        // Create ETH/BP pool
        _createEthBpPool();
        
        // Mint BP tokens and add initial liquidity to ETH/BP pool
        _setupInitialLiquidity();
    }

    /**
     * Create a new creator token pool using BP as the base token
     * Only callable by ADMIN_ROLE
     *
     * @param _creatorToken The creator token address
     * @param _creatorTreasury The creator's treasury address
     * @param _initialSupply Initial supply for the creator token
     */
    function createCreatorPool(
        address _creatorToken,
        address _creatorTreasury,
        uint256 _initialSupply
    ) external onlyRole(ADMIN_ROLE) whenNotPaused returns (PoolKey memory poolKey) {
        if (blueprintToken == address(0)) revert BlueprintTokenNotInitialized();
        if (_creatorToken == address(0) || _creatorTreasury == address(0)) revert InvalidAddress();
        
        // Create BP/Creator pool
        poolKey = _createBpCreatorPool(_creatorToken);
        
        // Store creator pool information
        creatorPoolKeys[_creatorToken] = poolKey;
        creatorTreasuries[_creatorToken] = _creatorTreasury;
        
        // Set up initial liquidity (25% of creator token supply)
        uint256 liquidityAmount = _initialSupply * 25 / 100;
        _setupCreatorLiquidity(_creatorToken, liquidityAmount);
        
        emit CreatorPoolCreated(poolKey.toId(), _creatorToken, blueprintToken);
    }

    /**
     * Route ETH to creator tokens via BP
     * ETH → BP → Creator Token
     *
     * @param _creatorToken The target creator token
     * @param _minCreatorOut Minimum creator tokens to receive
     */
    function routeEthToCreator(
        address _creatorToken,
        uint256 _minCreatorOut
    ) external payable whenNotPaused returns (uint256 creatorAmount) {
        if (msg.value == 0) revert InsufficientLiquidity();
        if (blueprintToken == address(0)) revert BlueprintTokenNotInitialized();
        if (creatorPoolKeys[_creatorToken].fee == 0) revert CreatorTokenNotFound();

        // Step 1: Swap ETH for BP tokens
        uint256 bpAmount = _swapEthForBp(msg.value);
        
        // Step 2: Swap BP tokens for Creator tokens
        creatorAmount = _swapBpForCreator(_creatorToken, bpAmount);
        
        if (creatorAmount < _minCreatorOut) revert InsufficientLiquidity();
        
        // Transfer creator tokens to user
        IERC20(_creatorToken).transfer(msg.sender, creatorAmount);
        
        // Track buy event for XP system
        _trackBuyEvent(msg.sender, _creatorToken);
        
        emit TokensRouted(msg.sender, msg.value, bpAmount, creatorAmount);
    }

    /**
     * Update fee distribution configuration
     * Only callable by FEE_MANAGER_ROLE
     *
     * @param _newFeeConfig New fee configuration
     */
    function updateFeeConfiguration(FeeConfiguration memory _newFeeConfig) 
        external 
        onlyRole(FEE_MANAGER_ROLE) 
        whenNotPaused 
    {
        _validateFeeConfiguration(_newFeeConfig);
        
        feeConfig = _newFeeConfig;
        
        emit FeeDistributionUpdated(
            _newFeeConfig.buybackFee,
            _newFeeConfig.creatorFee,
            _newFeeConfig.bpTreasuryFee
        );
    }

    /**
     * Update BP treasury address
     * Only callable by TREASURY_MANAGER_ROLE
     *
     * @param _newTreasury New treasury address
     */
    function updateBpTreasury(address _newTreasury) 
        external 
        onlyRole(TREASURY_MANAGER_ROLE) 
        whenNotPaused 
    {
        if (_newTreasury == address(0)) revert InvalidAddress();
        
        address oldTreasury = bpTreasury;
        bpTreasury = _newTreasury;
        
        emit BpTreasuryUpdated(oldTreasury, _newTreasury);
    }

    /**
     * Update buyback escrow address
     * Only callable by TREASURY_MANAGER_ROLE
     *
     * @param _newEscrow New buyback escrow address
     */
    function updateBuybackEscrow(address _newEscrow) 
        external 
        onlyRole(TREASURY_MANAGER_ROLE) 
        whenNotPaused 
    {
        if (_newEscrow == address(0)) revert InvalidAddress();
        
        address oldEscrow = buybackEscrow;
        buybackEscrow = _newEscrow;
        
        emit BuybackEscrowUpdated(oldEscrow, _newEscrow);
    }

    /**
     * Update Blueprint token supply for future deployments
     * Only callable by ADMIN_ROLE
     *
     * @param _newSupply New Blueprint token supply
     */
    function updateBlueprintSupply(uint256 _newSupply) 
        external 
        onlyRole(ADMIN_ROLE) 
        whenNotPaused 
    {
        blueprintSupply = _newSupply;
        emit BlueprintSupplyUpdated(_newSupply);
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
     * Hook called after swaps to distribute fees according to configurable model
     */
    function afterSwap(
        address,
        PoolKey calldata _key,
        IPoolManager.SwapParams memory,
        BalanceDelta,
        bytes calldata
    ) external override onlyPoolManager whenNotPaused returns (bytes4, int128) {
        PoolId poolId = _key.toId();
        
        // Only process fees for creator token pools
        if (_isCreatorPool(_key)) {
            _distributeFees(poolId, _key);
        }
        
        return (this.afterSwap.selector, 0);
    }

    /**
     * Define hook permissions
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

    /**
     * Get current fee configuration
     */
    function getFeeConfiguration() external view returns (FeeConfiguration memory) {
        return feeConfig;
    }

    // Internal Functions

    /**
     * Validate fee configuration to ensure percentages are valid
     */
    function _validateFeeConfiguration(FeeConfiguration memory _config) internal pure {
        if (_config.buybackFee > MAX_FEE_PERCENTAGE ||
            _config.creatorFee > MAX_FEE_PERCENTAGE ||
            _config.bpTreasuryFee > MAX_FEE_PERCENTAGE ||
            _config.rewardPoolFee > MAX_FEE_PERCENTAGE) {
            revert InvalidFeePercentage();
        }
        
        uint24 totalFees = _config.buybackFee + _config.creatorFee + _config.bpTreasuryFee + _config.rewardPoolFee;
        if (totalFees > MAX_FEE_PERCENTAGE) {
            revert FeeTotalExceeds100Percent();
        }
    }

    /**
     * Deploy Blueprint token using proxy pattern
     */
    function _deployBlueprintToken(address _implementation) internal returns (address) {
        // Create initialization data for the Blueprint token
        bytes memory initData = abi.encodeCall(
            IMemecoin.initialize,
            (
                "Blueprint Network Token",
                "BP", 
                ""
            )
        );
        
        // Deploy Blueprint token as proxy
        ERC1967Proxy tokenProxy = new ERC1967Proxy(
            _implementation,
            initData
        );
        
        address token = address(tokenProxy);
        
        // Mint configurable supply to this contract
        IMemecoin(token).mint(address(this), blueprintSupply);
        
        return token;
    }

    /**
     * Create ETH/BP pool
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
        
        // Initialize the pool
        poolManager.initialize(ethBpPoolKey, _getInitialSqrtPrice());
        
        emit BlueprintPoolCreated(ethBpPoolKey.toId(), blueprintToken);
    }

    /**
     * Create BP/Creator pool
     */
    function _createBpCreatorPool(address _creatorToken) internal returns (PoolKey memory) {
        bool currencyFlipped = blueprintToken >= _creatorToken;
        
        PoolKey memory poolKey = PoolKey({
            currency0: Currency.wrap(!currencyFlipped ? blueprintToken : _creatorToken),
            currency1: Currency.wrap(currencyFlipped ? blueprintToken : _creatorToken),
            fee: 3000, // 0.3% fee
            tickSpacing: 60,
            hooks: IHooks(address(this))
        });
        
        // Initialize the pool
        poolManager.initialize(poolKey, _getInitialSqrtPrice());
        
        return poolKey;
    }

    /**
     * Set up initial liquidity for ETH/BP pool
     */
    function _setupInitialLiquidity() internal {
        // Add initial liquidity to ETH/BP pool
        // This would typically involve calling poolManager.addLiquidity
        // Implementation depends on specific liquidity management requirements
    }

    /**
     * Set up initial liquidity for creator token pool
     */
    function _setupCreatorLiquidity(address _creatorToken, uint256 _liquidityAmount) internal {
        // Transfer BP tokens for initial liquidity
        IERC20(blueprintToken).transfer(address(poolManager), _liquidityAmount);
        
        // Add initial liquidity to BP/Creator pool
        // Implementation depends on specific liquidity management requirements
    }

    /**
     * Swap ETH for BP tokens
     */
    function _swapEthForBp(uint256 _ethAmount) internal returns (uint256 bpAmount) {
        // Implement ETH → BP swap using the ETH/BP pool
        // This would use poolManager.swap() with the appropriate parameters
        
        IPoolManager.SwapParams memory params = IPoolManager.SwapParams({
            zeroForOne: nativeToken == Currency.unwrap(ethBpPoolKey.currency0),
            amountSpecified: int256(_ethAmount),
            sqrtPriceLimitX96: 0
        });
        
        BalanceDelta delta = poolManager.swap(ethBpPoolKey, params, "");
        
        // Extract BP amount from delta
        int128 deltaAmount = delta.amount1();
        bpAmount = deltaAmount < 0 ? uint256(uint128(-deltaAmount)) : 0;
    }

    /**
     * Swap BP tokens for Creator tokens
     */
    function _swapBpForCreator(address _creatorToken, uint256 _bpAmount) internal returns (uint256 creatorAmount) {
        PoolKey memory poolKey = creatorPoolKeys[_creatorToken];
        
        IPoolManager.SwapParams memory params = IPoolManager.SwapParams({
            zeroForOne: blueprintToken == Currency.unwrap(poolKey.currency0),
            amountSpecified: int256(_bpAmount),
            sqrtPriceLimitX96: 0
        });
        
        BalanceDelta delta = poolManager.swap(poolKey, params, "");
        
        // Extract creator token amount from delta
        int128 deltaAmount = delta.amount1();
        creatorAmount = deltaAmount < 0 ? uint256(uint128(-deltaAmount)) : 0;
    }

    /**
     * Distribute fees according to configurable Blueprint network model
     * New distribution: 60% buyback, 20% creator, 10% BP treasury, 10% reward pool
     */
    function _distributeFees(PoolId _poolId, PoolKey calldata _key) internal {
        // Get the swap fees collected
        uint256 totalFees = _getAccumulatedFees(_poolId);
        
        if (totalFees == 0 || !feeConfig.active) return;
        
        // Calculate fee splits using configurable percentages
        uint256 buybackAmount = totalFees * feeConfig.buybackFee / MAX_FEE_PERCENTAGE;
        uint256 creatorAmount = totalFees * feeConfig.creatorFee / MAX_FEE_PERCENTAGE;
        uint256 bpTreasuryAmount = totalFees * feeConfig.bpTreasuryFee / MAX_FEE_PERCENTAGE;
        uint256 rewardPoolAmount = totalFees * feeConfig.rewardPoolFee / MAX_FEE_PERCENTAGE;
        
        // Distribute to buyback escrow
        if (buybackAmount > 0) {
            IERC20(nativeToken).transfer(buybackEscrow, buybackAmount);
        }
        
        // Distribute to creator & treasury
        if (creatorAmount > 0) {
            address creatorTreasury = _getCreatorTreasury(_key);
            if (creatorTreasury != address(0)) {
                IERC20(nativeToken).transfer(creatorTreasury, creatorAmount);
            }
        }
        
        // Distribute to BP treasury
        if (bpTreasuryAmount > 0) {
            IERC20(nativeToken).transfer(bpTreasury, bpTreasuryAmount);
        }
        
        // Distribute to reward pool
        if (rewardPoolAmount > 0) {
            // Convert to BP tokens and deposit to reward pool
            _depositToRewardPool(rewardPoolAmount);
        }
        
        emit FeesDistributed(_poolId, buybackAmount, creatorAmount, bpTreasuryAmount, rewardPoolAmount);
    }

    /**
     * Check if a pool is a creator token pool
     */
    function _isCreatorPool(PoolKey calldata _key) internal view returns (bool) {
        // Check if this is a BP/Creator pool by comparing currencies
        return (Currency.unwrap(_key.currency0) == blueprintToken || 
                Currency.unwrap(_key.currency1) == blueprintToken) &&
               PoolId.unwrap(_key.toId()) != PoolId.unwrap(ethBpPoolKey.toId());
    }

    /**
     * Get creator treasury for a pool
     */
    function _getCreatorTreasury(PoolKey calldata _key) internal view returns (address) {
        address creatorToken = Currency.unwrap(_key.currency0) == blueprintToken ? 
                              Currency.unwrap(_key.currency1) : 
                              Currency.unwrap(_key.currency0);
        return creatorTreasuries[creatorToken];
    }

    /**
     * Get accumulated fees for a pool
     */
    function _getAccumulatedFees(PoolId _poolId) internal pure returns (uint256) {
        // This would typically get fees from the pool manager or fee tracking system
        // Implementation depends on how fees are tracked in the system
        return 0; // Placeholder
    }

    /**
     * Get initial sqrt price for pools
     */
    function _getInitialSqrtPrice() internal pure returns (uint160) {
        // Return a reasonable initial price
        // This should be calculated based on desired initial price ratio
        return 79228162514264337593543950336; // sqrt(1) in Q64.96 format
    }

    /**
     * Track buy event for XP system
     */
    function _trackBuyEvent(address _user, address _token) internal {
        if (rewardPool != address(0)) {
            try IRewardPool(rewardPool).trackBuyEvent(_user, _token) {
                // Buy event tracked successfully
            } catch {
                // Silently fail to not block swaps
            }
        }
    }

    /**
     * Track sell event for XP system
     */
    function _trackSellEvent(address _user, address _token) internal {
        if (rewardPool != address(0)) {
            try IRewardPool(rewardPool).trackSellEvent(_user, _token) {
                // Sell event tracked successfully
            } catch {
                // Silently fail to not block swaps
            }
        }
    }

    /**
     * Deposit fees to reward pool by converting to BP tokens
     */
    function _depositToRewardPool(uint256 _feeAmount) internal {
        if (rewardPool != address(0) && blueprintToken != address(0)) {
            // Convert ETH fees to BP tokens first
            uint256 bpAmount = _swapEthForBp(_feeAmount);
            
            if (bpAmount > 0) {
                // Transfer BP tokens to reward pool
                IERC20(blueprintToken).transfer(rewardPool, bpAmount);
                
                try IRewardPool(rewardPool).depositRewards(bpAmount) {
                    // Deposit successful
                } catch {
                    // Silently fail to not block fee distribution
                }
            }
        }
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
} 