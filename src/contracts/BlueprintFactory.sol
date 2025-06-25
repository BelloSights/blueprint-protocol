// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {LibClone} from "@solady/utils/LibClone.sol";
import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {IPoolManager} from "@uniswap/v4-core/src/interfaces/IPoolManager.sol";
import {PoolId, PoolIdLibrary} from "@uniswap/v4-core/src/types/PoolId.sol";
import {PoolKey} from "@uniswap/v4-core/src/types/PoolKey.sol";

import {BlueprintNetworkHook} from "@flaunch/hooks/BlueprintNetworkHook.sol";
import {BuybackEscrow} from "@flaunch/escrows/BuybackEscrow.sol";
import {RewardPool} from "@flaunch/RewardPool.sol";
import {Flaunch} from "@flaunch/Flaunch.sol";
import {AnyFlaunch} from "@flaunch/AnyFlaunch.sol";
import {PositionManager} from "@flaunch/PositionManager.sol";
import {AnyPositionManager} from "@flaunch/AnyPositionManager.sol";
import {Memecoin} from "@flaunch/Memecoin.sol";
import {TokenSupply} from "@flaunch/libraries/TokenSupply.sol";

import {IMemecoin} from "@flaunch-interfaces/IMemecoin.sol";

/**
 * BlueprintFactory - Upgradeable factory with role-based access control
 *
 * Features:
 * - Upgradeable using UUPS pattern
 * - Role-based access control for different operations
 * - Deploys Blueprint Network contracts as upgradeable proxies
 * - Configurable parameters for network management
 * - Emergency pause functionality
 */
contract BlueprintFactory is
    Initializable,
    AccessControlUpgradeable,
    UUPSUpgradeable,
    PausableUpgradeable
{
    using PoolIdLibrary for PoolKey;

    // Role definitions
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant DEPLOYER_ROLE = keccak256("DEPLOYER_ROLE");
    bytes32 public constant CREATOR_ROLE = keccak256("CREATOR_ROLE");
    bytes32 public constant EMERGENCY_ROLE = keccak256("EMERGENCY_ROLE");
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");

    error BlueprintNetworkNotInitialized();
    error BlueprintNetworkAlreadyInitialized();
    error InvalidParameters();
    error TokenCreationFailed();
    error PoolCreationFailed();
    error InvalidAddress();

    event BlueprintNetworkDeployed(
        address indexed blueprintHook,
        address indexed buybackEscrow,
        address indexed blueprintToken
    );

    event CreatorTokenLaunched(
        address indexed creatorToken,
        address indexed creator,
        address indexed treasury,
        PoolId poolId,
        uint256 tokenId
    );

    event BlueprintTreasuryUpdated(address indexed newTreasury);
    event ConfigurationUpdated(
        string parameter,
        address oldValue,
        address newValue
    );

    /// Configuration struct for fee distribution
    struct FeeConfiguration {
        uint24 buybackFee; // Fee percentage for buyback escrow (basis points)
        uint24 creatorFee; // Fee percentage for creator/treasury (basis points)
        uint24 bpTreasuryFee; // Fee percentage for BP treasury (basis points)
        uint24 rewardPoolFee; // Fee percentage for XP reward pool (basis points)
        bool active; // Whether this configuration is active
    }

    /// The Uniswap V4 Pool Manager
    IPoolManager public poolManager;

    /// The native token (WETH/ETH)
    address public nativeToken;

    /// The existing Flaunch contract
    Flaunch public flaunchContract;

    /// The existing AnyFlaunch contract for importing tokens
    AnyFlaunch public anyFlaunchContract;

    /// The Blueprint Network Hook (proxy address)
    BlueprintNetworkHook public blueprintHook;

    /// The Buyback Escrow contract (proxy address)
    BuybackEscrow public buybackEscrow;

    /// The XP-based Reward Pool contract (proxy address)
    RewardPool public rewardPool;

    /// The Blueprint token address
    address public blueprintToken;

    /// The Blueprint treasury address
    address public bpTreasury;

    /// Whether the Blueprint network is initialized
    bool public initialized;

    /// Memecoin implementation for token creation
    address public memecoinImplementation;

    /// Treasury implementation for creator treasuries
    address public treasuryImplementation;

    /// Blueprint Network Hook implementation (for proxy deployments)
    address public blueprintHookImplementation;

    /// Buyback Escrow implementation (for proxy deployments)
    address public buybackEscrowImplementation;

    /// Reward Pool implementation (for proxy deployments)
    address public rewardPoolImplementation;

    /// Fee configuration for the network
    FeeConfiguration public feeConfig;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /**
     * Initialize the upgradeable factory
     *
     * @param _poolManager The Uniswap V4 Pool Manager
     * @param _nativeToken The native token (WETH/ETH)
     * @param _flaunchContract The existing Flaunch contract
     * @param _anyFlaunchContract The existing AnyFlaunch contract
     * @param _memecoinImplementation The Memecoin implementation
     * @param _treasuryImplementation The Treasury implementation
     * @param _bpTreasury The Blueprint treasury address
     * @param _admin The admin address (receives all roles initially)
     * @param _blueprintHookImpl Blueprint Hook implementation address
     * @param _buybackEscrowImpl Buyback Escrow implementation address
     * @param _rewardPoolImpl Reward Pool implementation address
     */
    function initialize(
        IPoolManager _poolManager,
        address _nativeToken,
        Flaunch _flaunchContract,
        AnyFlaunch _anyFlaunchContract,
        address _memecoinImplementation,
        address _treasuryImplementation,
        address _bpTreasury,
        address _admin,
        address _blueprintHookImpl,
        address _buybackEscrowImpl,
        address _rewardPoolImpl
    ) public initializer {
        if (
            _admin == address(0) ||
            _nativeToken == address(0) ||
            _bpTreasury == address(0) ||
            _blueprintHookImpl == address(0) ||
            _buybackEscrowImpl == address(0) ||
            _rewardPoolImpl == address(0)
        ) {
            revert InvalidAddress();
        }

        __AccessControl_init();
        __UUPSUpgradeable_init();
        __Pausable_init();

        poolManager = _poolManager;
        nativeToken = _nativeToken;
        flaunchContract = _flaunchContract;
        anyFlaunchContract = _anyFlaunchContract;
        memecoinImplementation = _memecoinImplementation;
        treasuryImplementation = _treasuryImplementation;
        bpTreasury = _bpTreasury;
        blueprintHookImplementation = _blueprintHookImpl;
        buybackEscrowImplementation = _buybackEscrowImpl;
        rewardPoolImplementation = _rewardPoolImpl;

        // Set up roles
        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(ADMIN_ROLE, _admin);
        _grantRole(DEPLOYER_ROLE, _admin);
        _grantRole(CREATOR_ROLE, _admin);
        _grantRole(EMERGENCY_ROLE, _admin);
        _grantRole(UPGRADER_ROLE, _admin);

        // Set default fee configuration (60/20/10/10 split)
        feeConfig = FeeConfiguration({
            buybackFee: 60_00, // 60%
            creatorFee: 20_00, // 20%
            bpTreasuryFee: 10_00, // 10%
            rewardPoolFee: 10_00, // 10%
            active: true
        });
    }

    /**
     * Initialize the Blueprint Network by deploying all necessary contracts as proxies
     * Only callable by DEPLOYER_ROLE
     *
     * @param _flayGovernance The FLAY governance address
     * @param _feeEscrow The fee escrow contract address
     * @param _buybackThreshold Initial buyback threshold
     * @param _buybackInterval Initial buyback interval
     */
    function initializeBlueprintNetwork(
        address _flayGovernance,
        address _feeEscrow,
        uint256 _buybackThreshold,
        uint256 _buybackInterval
    ) external onlyRole(DEPLOYER_ROLE) whenNotPaused {
        if (initialized) revert BlueprintNetworkAlreadyInitialized();
        if (_flayGovernance == address(0) || _feeEscrow == address(0))
            revert InvalidAddress();

        // Deploy Buyback Escrow as proxy
        bytes memory buybackInitData = abi.encodeCall(
            BuybackEscrow.initialize,
            (
                poolManager,
                nativeToken,
                address(0), // Will be set after Blueprint token is created
                msg.sender, // Deployer gets initial admin role
                _buybackThreshold,
                _buybackInterval
            )
        );

        ERC1967Proxy buybackProxy = new ERC1967Proxy(
            buybackEscrowImplementation,
            buybackInitData
        );
        buybackEscrow = BuybackEscrow(payable(address(buybackProxy)));

        // Deploy Reward Pool as proxy (we'll set blueprint token after it's created)
        bytes memory rewardInitData = abi.encodeCall(
            RewardPool.initialize,
            (
                msg.sender, // Deployer gets initial admin role
                address(0) // Will be set after Blueprint token is created
            )
        );

        ERC1967Proxy rewardProxy = new ERC1967Proxy(
            rewardPoolImplementation,
            rewardInitData
        );
        rewardPool = RewardPool(address(rewardProxy));

        // Use the pre-deployed BlueprintNetworkHook (must be deployed with correct permissions)
        blueprintHook = BlueprintNetworkHook(blueprintHookImplementation);

        // Initialize the hook with the factory as initial admin (if not already initialized)
        BlueprintNetworkHook.FeeConfiguration
            memory hookFeeConfig = BlueprintNetworkHook.FeeConfiguration({
                buybackFee: feeConfig.buybackFee,
                creatorFee: feeConfig.creatorFee,
                bpTreasuryFee: feeConfig.bpTreasuryFee,
                rewardPoolFee: feeConfig.rewardPoolFee,
                active: feeConfig.active
            });

        try
            blueprintHook.initialize(
                nativeToken,
                address(this), // Factory gets initial admin role to grant itself ADMIN_ROLE
                _flayGovernance,
                _feeEscrow,
                bpTreasury,
                address(buybackEscrow),
                address(rewardPool),
                hookFeeConfig
            )
        {
            // Hook was successfully initialized by this factory
            // Grant this factory ADMIN_ROLE on the hook so it can call initializeBlueprintNetwork
            blueprintHook.grantRole(blueprintHook.ADMIN_ROLE(), address(this));

            // Transfer admin roles to the original admin
            blueprintHook.grantRole(
                blueprintHook.DEFAULT_ADMIN_ROLE(),
                msg.sender
            );
            blueprintHook.grantRole(blueprintHook.ADMIN_ROLE(), msg.sender);
            blueprintHook.renounceRole(
                blueprintHook.DEFAULT_ADMIN_ROLE(),
                address(this)
            );
        } catch {
            // Hook was already initialized, grant ourselves the ADMIN_ROLE if we have DEFAULT_ADMIN_ROLE
            try
                blueprintHook.grantRole(
                    blueprintHook.ADMIN_ROLE(),
                    address(this)
                )
            {} catch {}
        }

        // Initialize the Blueprint network (creates BP token and ETH/BP pool)
        blueprintHook.initializeBlueprintNetwork(memecoinImplementation);

        // Get the Blueprint token address
        blueprintToken = blueprintHook.blueprintToken();

        // Set the Blueprint hook in the buyback escrow
        buybackEscrow.setBlueprintHook(address(blueprintHook));

        // Set the Blueprint token in the buyback escrow
        buybackEscrow.setBlueprintToken(blueprintToken);

        initialized = true;

        emit BlueprintNetworkDeployed(
            address(blueprintHook),
            address(buybackEscrow),
            blueprintToken
        );
    }

    /**
     * Launch a new creator token using the Blueprint Network
     * Only callable by CREATOR_ROLE
     *
     * @param _creator The creator address
     * @param _name The token name
     * @param _symbol The token symbol
     * @param _tokenUri The token URI
     * @param _initialSupply The initial token supply (default 10B if 0)
     * @param _creatorFeeAllocation The creator's fee allocation percentage
     * @return creatorToken The address of the created token
     * @return treasury The address of the creator's treasury
     * @return tokenId The ERC721 token ID representing ownership
     */
    function launchCreatorToken(
        address _creator,
        string calldata _name,
        string calldata _symbol,
        string calldata _tokenUri,
        uint256 _initialSupply,
        uint24 _creatorFeeAllocation
    )
        external
        onlyRole(CREATOR_ROLE)
        whenNotPaused
        returns (
            address creatorToken,
            address payable treasury,
            uint256 tokenId
        )
    {
        if (!initialized) revert BlueprintNetworkNotInitialized();
        if (_creator == address(0)) revert InvalidParameters();

        return
            _launchCreatorTokenInternal(
                _creator,
                _name,
                _symbol,
                _tokenUri,
                _initialSupply,
                _creatorFeeAllocation
            );
    }

    /**
     * Launch a creator token by importing an existing token
     * Only callable by CREATOR_ROLE
     *
     * @param _existingToken The existing token to import
     * @param _creator The creator address
     * @param _creatorFeeAllocation The creator's fee allocation percentage
     * @return treasury The address of the creator's treasury
     * @return tokenId The ERC721 token ID representing ownership
     */
    function importCreatorToken(
        address _existingToken,
        address _creator,
        uint24 _creatorFeeAllocation
    )
        external
        onlyRole(CREATOR_ROLE)
        whenNotPaused
        returns (address payable treasury, uint256 tokenId)
    {
        if (!initialized) revert BlueprintNetworkNotInitialized();
        if (_existingToken == address(0) || _creator == address(0))
            revert InvalidParameters();

        // Use AnyFlaunch to create the ERC721 representation
        AnyPositionManager.FlaunchParams
            memory flaunchParams = AnyPositionManager.FlaunchParams({
                memecoin: _existingToken,
                creator: _creator,
                creatorFeeAllocation: _creatorFeeAllocation,
                initialPriceParams: "",
                feeCalculatorParams: ""
            });

        (treasury, tokenId) = anyFlaunchContract.flaunch(flaunchParams);

        // Get the token's current supply
        uint256 totalSupply = IERC20(_existingToken).totalSupply();

        // Create the BP/Creator pool through the Blueprint hook
        PoolKey memory poolKey = blueprintHook.createCreatorPool(
            _existingToken,
            address(treasury),
            totalSupply
        );

        // Register the pool in the buyback escrow
        buybackEscrow.registerPool(poolKey);

        emit CreatorTokenLaunched(
            _existingToken,
            _creator,
            address(treasury),
            poolKey.toId(),
            tokenId
        );

        return (treasury, tokenId);
    }

    /**
     * Update the Blueprint treasury address
     * Only callable by ADMIN_ROLE
     *
     * @param _newTreasury The new treasury address
     */
    function setBpTreasury(
        address _newTreasury
    ) external onlyRole(ADMIN_ROLE) whenNotPaused {
        if (_newTreasury == address(0)) revert InvalidAddress();

        address oldTreasury = bpTreasury;
        bpTreasury = _newTreasury;

        // Update in the hook as well
        if (initialized) {
            blueprintHook.updateBpTreasury(_newTreasury);
        }

        emit BlueprintTreasuryUpdated(_newTreasury);
    }

    /**
     * Update fee configuration
     * Only callable by ADMIN_ROLE
     *
     * @param _newFeeConfig New fee configuration
     */
    function updateFeeConfiguration(
        BlueprintNetworkHook.FeeConfiguration memory _newFeeConfig
    ) external onlyRole(ADMIN_ROLE) whenNotPaused {
        feeConfig = FeeConfiguration({
            buybackFee: _newFeeConfig.buybackFee,
            creatorFee: _newFeeConfig.creatorFee,
            bpTreasuryFee: _newFeeConfig.bpTreasuryFee,
            rewardPoolFee: _newFeeConfig.rewardPoolFee,
            active: _newFeeConfig.active
        });

        // Update in the hook as well
        if (initialized) {
            blueprintHook.updateFeeConfiguration(_newFeeConfig);
        }
    }

    /**
     * Emergency pause function
     * Only callable by EMERGENCY_ROLE
     */
    function pause() external onlyRole(EMERGENCY_ROLE) {
        _pause();

        // Pause child contracts if initialized
        if (initialized) {
            blueprintHook.pause();
            buybackEscrow.pause();
        }
    }

    /**
     * Unpause function
     * Only callable by EMERGENCY_ROLE
     */
    function unpause() external onlyRole(EMERGENCY_ROLE) {
        _unpause();

        // Unpause child contracts if initialized
        if (initialized) {
            blueprintHook.unpause();
            buybackEscrow.unpause();
        }
    }

    /**
     * Get the Blueprint token address
     */
    function getBlueprintToken() external view returns (address) {
        if (!initialized) revert BlueprintNetworkNotInitialized();
        return blueprintToken;
    }

    /**
     * Get the Blueprint hook address for direct access to pool keys
     */
    function getBlueprintHook() external view returns (address) {
        if (!initialized) revert BlueprintNetworkNotInitialized();
        return address(blueprintHook);
    }

    /**
     * Route ETH to creator tokens via the Blueprint Network
     *
     * @param _creatorToken The target creator token
     * @param _minCreatorOut Minimum creator tokens to receive
     */
    function routeEthToCreator(
        address _creatorToken,
        uint256 _minCreatorOut
    ) external payable whenNotPaused returns (uint256 creatorAmount) {
        if (!initialized) revert BlueprintNetworkNotInitialized();

        return
            blueprintHook.routeEthToCreator{value: msg.value}(
                _creatorToken,
                _minCreatorOut
            );
    }

    // Internal Functions

    /**
     * Internal function to launch a creator token (splits logic to avoid stack too deep)
     */
    function _launchCreatorTokenInternal(
        address _creator,
        string calldata _name,
        string calldata _symbol,
        string calldata _tokenUri,
        uint256 _initialSupply,
        uint24 _creatorFeeAllocation
    )
        internal
        returns (
            address creatorToken,
            address payable treasury,
            uint256 tokenId
        )
    {
        // Use default supply if not specified
        uint256 supply = _initialSupply == 0
            ? TokenSupply.INITIAL_SUPPLY
            : _initialSupply;

        // Create the creator token
        creatorToken = _createCreatorToken(_name, _symbol, _tokenUri, supply);

        // Create and register treasury
        (treasury, tokenId) = _createAndRegisterTreasury(
            creatorToken,
            _creator,
            _creatorFeeAllocation
        );

        // Create pool and register
        _createPoolAndRegister(
            creatorToken,
            treasury,
            supply,
            _creator,
            tokenId
        );

        return (creatorToken, treasury, tokenId);
    }

    /**
     * Create and register treasury
     */
    function _createAndRegisterTreasury(
        address creatorToken,
        address _creator,
        uint24 _creatorFeeAllocation
    ) internal returns (address payable treasury, uint256 tokenId) {
        // Use AnyFlaunch to create the ERC721 representation
        (treasury, tokenId) = anyFlaunchContract.flaunch(
            AnyPositionManager.FlaunchParams({
                memecoin: creatorToken,
                creator: _creator,
                creatorFeeAllocation: _creatorFeeAllocation,
                initialPriceParams: "",
                feeCalculatorParams: ""
            })
        );
    }

    /**
     * Create pool and register
     */
    function _createPoolAndRegister(
        address creatorToken,
        address payable treasury,
        uint256 supply,
        address _creator,
        uint256 tokenId
    ) internal {
        // Create the BP/Creator pool through the Blueprint hook
        PoolKey memory poolKey = blueprintHook.createCreatorPool(
            creatorToken,
            address(treasury),
            supply
        );

        // Register the pool in the buyback escrow
        buybackEscrow.registerPool(poolKey);

        emit CreatorTokenLaunched(
            creatorToken,
            _creator,
            address(treasury),
            poolKey.toId(),
            tokenId
        );
    }

    /**
     * Create a new creator token
     *
     * @param _name The token name
     * @param _symbol The token symbol
     * @param _tokenUri The token URI
     * @param _supply The token supply
     * @return The address of the created token
     */
    function _createCreatorToken(
        string calldata _name,
        string calldata _symbol,
        string calldata _tokenUri,
        uint256 _supply
    ) internal returns (address) {
        // Generate a unique salt for the token
        bytes32 salt = keccak256(
            abi.encodePacked(_name, _symbol, block.timestamp, msg.sender)
        );

        // Deploy the token using CREATE2
        address token = LibClone.cloneDeterministic(
            memecoinImplementation,
            salt
        );

        // Initialize the token
        IMemecoin(token).initialize(_name, _symbol, _tokenUri);

        // Mint the initial supply to this factory (will be distributed to pools)
        IMemecoin(token).mint(address(this), _supply);

        return token;
    }

    /**
     * Create a treasury for a creator token
     *
     * @param _creatorToken The creator token address
     * @return The address of the created treasury
     */
    function _createCreatorTreasury(
        address _creatorToken
    ) internal returns (address payable) {
        // Generate a unique salt for the treasury
        bytes32 salt = keccak256(
            abi.encodePacked(_creatorToken, block.timestamp)
        );

        // Deploy the treasury using CREATE2
        address payable treasury = payable(
            LibClone.cloneDeterministic(treasuryImplementation, salt)
        );

        return treasury;
    }

    /**
     * Authorize upgrade function for UUPS
     * Only callable by UPGRADER_ROLE
     */
    function _authorizeUpgrade(
        address newImplementation
    ) internal override onlyRole(UPGRADER_ROLE) {}

    /**
     * Override supportsInterface to include AccessControl
     */
    function supportsInterface(
        bytes4 interfaceId
    ) public view override(AccessControlUpgradeable) returns (bool) {
        return super.supportsInterface(interfaceId);
    }
}
