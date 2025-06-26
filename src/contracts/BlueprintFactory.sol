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
import {LibClone} from "@solady/utils/LibClone.sol";
import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";

import {IPoolManager} from "@uniswap/v4-core/src/interfaces/IPoolManager.sol";
import {IHooks} from "@uniswap/v4-core/src/interfaces/IHooks.sol";
import {PoolId, PoolIdLibrary} from "@uniswap/v4-core/src/types/PoolId.sol";
import {PoolKey} from "@uniswap/v4-core/src/types/PoolKey.sol";
import {Currency} from "@uniswap/v4-core/src/types/Currency.sol";
import {LPFeeLibrary} from "@uniswap/v4-core/src/libraries/LPFeeLibrary.sol";

import {BlueprintProtocolHook} from "@flaunch/hooks/BlueprintProtocolHook.sol";
import {BlueprintBuybackEscrow} from "@flaunch/escrows/BlueprintBuybackEscrow.sol";
import {BlueprintRewardPool} from "@flaunch/BlueprintRewardPool.sol";

import {Memecoin} from "@flaunch/Memecoin.sol";
import {TokenSupply} from "@flaunch/libraries/TokenSupply.sol";

import {IMemecoin} from "@flaunch-interfaces/IMemecoin.sol";
import {IBlueprintFactory} from "@flaunch-interfaces/IBlueprintFactory.sol";
import {IBlueprintProtocol} from "@flaunch-interfaces/IBlueprintProtocol.sol";
import {IBlueprintRewardPool} from "../interfaces/IBlueprintRewardPool.sol";
import {CreatorCoin} from "./BlueprintCreatorCoin.sol";

/**
 * BlueprintFactory - Upgradeable factory with role-based access control
 *
 * Features:
 * - Upgradeable using UUPS pattern
 * - Role-based access control for different operations
 * - Deploys Blueprint Protocol contracts as upgradeable proxies
 * - Manages multiple reward pools with XP-based distributions
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

    // ===== CONSTANTS =====
    string public constant SIGNING_DOMAIN = "BLUEPRINT_PROTOCOL";
    string public constant SIGNATURE_VERSION = "1";

    // Role definitions
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

    // Reward Pool Factory Errors
    error NoPoolForId();
    error PoolAlreadyExists();
    error PoolNotActive();
    error InvalidPoolId();

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

    // Reward Pool Factory Events
    event RewardPoolCreated(
        uint256 indexed poolId,
        address indexed pool,
        string name,
        string description
    );
    event RewardPoolActivated(uint256 indexed poolId);
    event RewardPoolDeactivated(uint256 indexed poolId);
    event RewardPoolUserAdded(
        uint256 indexed poolId,
        address indexed user,
        uint256 xp
    );
    event RewardPoolXPUpdated(
        uint256 indexed poolId,
        address indexed user,
        uint256 oldXP,
        uint256 newXP
    );
    event RewardPoolUserPenalized(
        uint256 indexed poolId,
        address indexed user,
        uint256 xpRemoved
    );

    /// Configuration struct for fee distribution
    struct FeeConfiguration {
        uint24 buybackFee; // Fee percentage for buyback escrow (basis points)
        uint24 creatorFee; // Fee percentage for creator/treasury (basis points)
        uint24 bpTreasuryFee; // Fee percentage for BP treasury (basis points)
        uint24 rewardPoolFee; // Fee percentage for XP reward pool (basis points)
        bool active; // Whether this configuration is active
    }

    /// Reward Pool Information
    struct RewardPoolInfo {
        uint256 poolId;
        address pool;
        bool active;
        string name;
        string description;
    }

    /// The Uniswap V4 Pool Manager
    IPoolManager public poolManager;

    /// The native token (WETH/ETH)
    address public nativeToken;

    /// The Blueprint Protocol Hook (proxy address)
    BlueprintProtocolHook public blueprintHook;

    /// The Buyback Escrow contract (proxy address)
    BlueprintBuybackEscrow public buybackEscrow;

    /// The XP-based Reward Pool contract (proxy address) - Main reward pool
    BlueprintRewardPool public rewardPool;

    /// The Blueprint token address
    address public blueprintToken;

    /// The Blueprint treasury address
    address public treasury;

    /// Whether the Blueprint network is initialized
    bool public initialized;

    /// Creatorcoin implementation for token creation
    address public creatorcoinImplementation;

    /// Blueprint Protocol Hook implementation (for proxy deployments)
    address public blueprintHookImplementation;

    /// Buyback Escrow implementation (for proxy deployments)
    address public buybackEscrowImplementation;

    /// Reward Pool implementation (for proxy deployments)
    address public rewardPoolImplementation;

    /// Fee configuration for the network
    FeeConfiguration public feeConfig;

    // ===== REWARD POOL FACTORY STATE =====

    /// Next pool ID for reward pools
    uint256 public nextRewardPoolId;

    /// Mapping from poolId to its info
    mapping(uint256 => RewardPoolInfo) public rewardPools;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /**
     * Initialize the upgradeable factory
     *
     * @param _poolManager The Uniswap V4 Pool Manager
     * @param _admin The admin address (receives all roles initially)
     * @param _treasury The Blueprint treasury address
     * @param _nativeToken The native token (WETH/ETH)
     * @param _creatorcoinImplementation The Creatorcoin implementation
     * @param _blueprintHookImpl Blueprint Hook implementation address
     * @param _buybackEscrowImpl Buyback Escrow implementation address
     * @param _rewardPoolImpl Reward Pool implementation address
     */
    function initialize(
        IPoolManager _poolManager,
        address _admin,
        address _treasury,
        address _nativeToken,
        address _creatorcoinImplementation,
        address _blueprintHookImpl,
        address _buybackEscrowImpl,
        address _rewardPoolImpl
    ) public initializer {
        if (
            _admin == address(0) ||
            _treasury == address(0) ||
            _blueprintHookImpl == address(0) ||
            _buybackEscrowImpl == address(0) ||
            _rewardPoolImpl == address(0)
        ) {
            revert InvalidAddress();
        }
        // Note: _nativeToken can be address(0) for native ETH

        __AccessControl_init();
        __UUPSUpgradeable_init();
        __Pausable_init();

        poolManager = _poolManager;
        nativeToken = _nativeToken;
        creatorcoinImplementation = _creatorcoinImplementation;
        treasury = _treasury;
        blueprintHookImplementation = _blueprintHookImpl;
        buybackEscrowImplementation = _buybackEscrowImpl;
        rewardPoolImplementation = _rewardPoolImpl;

        // Set up roles
        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(DEPLOYER_ROLE, _admin);
        _grantRole(CREATOR_ROLE, _admin);
        _grantRole(EMERGENCY_ROLE, _admin);
        _grantRole(UPGRADER_ROLE, _admin);

        // Set default fee configuration (60/20/10/10 split)
        feeConfig = FeeConfiguration({
            buybackFee: 6000, // 0.6%
            creatorFee: 2000, // 0.2%
            bpTreasuryFee: 1000, // 0.1%
            rewardPoolFee: 1000, // 0.1%
            active: true
        });

        // Initialize reward pool factory state
        nextRewardPoolId = 1;
    }

    /**
     * Initialize the Blueprint Protocol by deploying all necessary contracts as proxies
     * Only callable by DEPLOYER_ROLE
     *
     * @param _governance The governance address for Blueprint protocol
     */
    function initializeBlueprintNetwork(
        address _governance
    ) external onlyRole(DEPLOYER_ROLE) whenNotPaused {
        if (initialized) revert BlueprintNetworkAlreadyInitialized();
        if (_governance == address(0)) revert InvalidAddress();

        // Deploy Buyback Escrow as proxy
        bytes memory buybackInitData = abi.encodeCall(
            BlueprintBuybackEscrow.initialize,
            (
                poolManager,
                nativeToken,
                address(0), // Will be set after Blueprint token is created
                msg.sender // Deployer gets initial admin role
            )
        );

        ERC1967Proxy buybackProxy = new ERC1967Proxy(
            buybackEscrowImplementation,
            buybackInitData
        );
        buybackEscrow = BlueprintBuybackEscrow(payable(address(buybackProxy)));

        // Deploy Reward Pool as proxy (we'll set blueprint token after it's created)
        bytes memory rewardInitData = abi.encodeCall(
            BlueprintRewardPool.initialize,
            (
                address(this), // Factory is the admin for the main reward pool
                SIGNING_DOMAIN,
                SIGNATURE_VERSION
            )
        );

        ERC1967Proxy rewardProxy = new ERC1967Proxy(
            rewardPoolImplementation,
            rewardInitData
        );
        rewardPool = BlueprintRewardPool(payable(address(rewardProxy)));

        // Use the pre-deployed BlueprintProtocolHook (must be deployed with correct permissions)
        blueprintHook = BlueprintProtocolHook(
            payable(blueprintHookImplementation)
        );

        // Initialize the hook with the factory as initial admin (if not already initialized)
        IBlueprintProtocol.FeeConfiguration
            memory hookFeeConfig = IBlueprintProtocol.FeeConfiguration({
                buybackFee: feeConfig.buybackFee,
                creatorFee: feeConfig.creatorFee,
                bpTreasuryFee: feeConfig.bpTreasuryFee,
                rewardPoolFee: feeConfig.rewardPoolFee,
                active: feeConfig.active
            });

        try
            blueprintHook.initialize(
                address(this), // admin
                address(this) // factory
            )
        {
            // Hook was successfully initialized by this factory
            // Grant this factory DEFAULT_ADMIN_ROLE on the hook so it can call initializeBlueprintNetwork
            blueprintHook.grantRole(
                blueprintHook.DEFAULT_ADMIN_ROLE(),
                address(this)
            );

            // Transfer admin roles to the original admin
            blueprintHook.grantRole(
                blueprintHook.DEFAULT_ADMIN_ROLE(),
                msg.sender
            );
            blueprintHook.grantRole(
                blueprintHook.DEFAULT_ADMIN_ROLE(),
                msg.sender
            );
            blueprintHook.renounceRole(
                blueprintHook.DEFAULT_ADMIN_ROLE(),
                address(this)
            );
        } catch {
            // Hook was already initialized, grant ourselves the DEFAULT_ADMIN_ROLE if we have DEFAULT_ADMIN_ROLE
            try
                blueprintHook.grantRole(
                    blueprintHook.DEFAULT_ADMIN_ROLE(),
                    address(this)
                )
            {} catch {}
        }

        // Deploy Blueprint token first
        blueprintToken = _createBlueprintToken();

        // Initialize the Blueprint token in hook
        blueprintHook.initializeBlueprintToken(blueprintToken, nativeToken);

        // Create ETH/BP pool through factory
        _createEthBpPool();

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

    // ===== REWARD POOL FACTORY FUNCTIONS =====

    /**
     * Creates a new reward pool
     * Only callable by DEFAULT_ADMIN_ROLE
     *
     * @param name Name of the reward pool
     * @param description Description of the reward pool
     * @return poolId The unique identifier of the newly created pool
     */
    function createRewardPool(
        string calldata name,
        string calldata description
    ) external onlyRole(DEFAULT_ADMIN_ROLE) returns (uint256) {
        if (rewardPoolImplementation == address(0)) revert InvalidAddress();

        uint256 poolId = nextRewardPoolId;

        // Create a clone of the shared implementation
        address clone = Clones.clone(rewardPoolImplementation);

        // Initialize the clone
        IBlueprintRewardPool(clone).initialize(
            address(this),
            SIGNING_DOMAIN,
            SIGNATURE_VERSION
        );

        rewardPools[poolId] = RewardPoolInfo({
            poolId: poolId,
            pool: clone,
            active: false, // Pools start inactive
            name: name,
            description: description
        });

        emit RewardPoolCreated(poolId, clone, name, description);

        unchecked {
            nextRewardPoolId++;
        }

        return poolId;
    }

    /**
     * Activates a reward pool to allow claiming
     * Only callable by DEFAULT_ADMIN_ROLE
     *
     * @param poolId The identifier of the pool to activate
     */
    function activateRewardPool(
        uint256 poolId
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        RewardPoolInfo storage info = rewardPools[poolId];
        if (info.pool == address(0)) revert NoPoolForId();

        info.active = true;
        IBlueprintRewardPool(info.pool).setActive(true);
        emit RewardPoolActivated(poolId);
    }

    /**
     * Deactivates a reward pool to prevent claiming
     * Only callable by DEFAULT_ADMIN_ROLE
     *
     * @param poolId The identifier of the pool to deactivate
     */
    function deactivateRewardPool(
        uint256 poolId
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        RewardPoolInfo storage info = rewardPools[poolId];
        if (info.pool == address(0)) revert NoPoolForId();

        info.active = false;
        IBlueprintRewardPool(info.pool).setActive(false);
        emit RewardPoolDeactivated(poolId);
    }

    /**
     * Adds a new user to a reward pool with initial XP
     * Only callable by DEFAULT_ADMIN_ROLE
     *
     * @param poolId The pool identifier
     * @param user The user address to add
     * @param xp The initial XP amount for the user
     */
    function addUserToRewardPool(
        uint256 poolId,
        address user,
        uint256 xp
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        RewardPoolInfo storage info = rewardPools[poolId];
        if (info.pool == address(0)) revert NoPoolForId();

        IBlueprintRewardPool(info.pool).addUser(user, xp);
        emit RewardPoolUserAdded(poolId, user, xp);
    }

    /**
     * Updates XP for an existing user in a reward pool
     * Only callable by DEFAULT_ADMIN_ROLE
     *
     * @param poolId The pool identifier
     * @param user The user address
     * @param newXP The new XP amount
     */
    function updateRewardPoolUserXP(
        uint256 poolId,
        address user,
        uint256 newXP
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        RewardPoolInfo storage info = rewardPools[poolId];
        if (info.pool == address(0)) revert NoPoolForId();

        uint256 oldXP = IBlueprintRewardPool(info.pool).getUserXP(user);
        IBlueprintRewardPool(info.pool).updateUserXP(user, newXP);
        emit RewardPoolXPUpdated(poolId, user, oldXP, newXP);
    }

    /**
     * Penalizes a user by removing XP from a reward pool
     * Only callable by DEFAULT_ADMIN_ROLE
     *
     * @param poolId The pool identifier
     * @param user The user address
     * @param xpToRemove Amount of XP to remove
     */
    function penalizeRewardPoolUser(
        uint256 poolId,
        address user,
        uint256 xpToRemove
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        RewardPoolInfo storage info = rewardPools[poolId];
        if (info.pool == address(0)) revert NoPoolForId();

        IBlueprintRewardPool(info.pool).penalizeUser(user, xpToRemove);
        emit RewardPoolUserPenalized(poolId, user, xpToRemove);
    }

    /**
     * Adds multiple users to a reward pool with initial XP in batches
     * Only callable by DEFAULT_ADMIN_ROLE
     *
     * @param poolId The pool identifier
     * @param users Array of user addresses to add
     * @param xpAmounts Array of initial XP amounts for users
     */
    function batchAddUsersToRewardPool(
        uint256 poolId,
        address[] calldata users,
        uint256[] calldata xpAmounts
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        RewardPoolInfo storage info = rewardPools[poolId];
        if (info.pool == address(0)) revert NoPoolForId();

        IBlueprintRewardPool(info.pool).batchAddUsers(users, xpAmounts);

        // Emit individual events for each user for compatibility
        for (uint256 i = 0; i < users.length; ) {
            emit RewardPoolUserAdded(poolId, users[i], xpAmounts[i]);
            unchecked {
                ++i;
            }
        }
    }

    /**
     * Updates XP for multiple existing users in batches
     * Only callable by DEFAULT_ADMIN_ROLE
     *
     * @param poolId The pool identifier
     * @param users Array of user addresses
     * @param newXPAmounts Array of new XP amounts
     */
    function batchUpdateRewardPoolUserXP(
        uint256 poolId,
        address[] calldata users,
        uint256[] calldata newXPAmounts
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        RewardPoolInfo storage info = rewardPools[poolId];
        if (info.pool == address(0)) revert NoPoolForId();

        // Get old XP values for events
        uint256[] memory oldXPAmounts = new uint256[](users.length);
        for (uint256 i = 0; i < users.length; ) {
            oldXPAmounts[i] = IBlueprintRewardPool(info.pool).getUserXP(
                users[i]
            );
            unchecked {
                ++i;
            }
        }

        IBlueprintRewardPool(info.pool).batchUpdateUserXP(users, newXPAmounts);

        // Emit individual events for each user for compatibility
        for (uint256 i = 0; i < users.length; ) {
            emit RewardPoolXPUpdated(
                poolId,
                users[i],
                oldXPAmounts[i],
                newXPAmounts[i]
            );
            unchecked {
                ++i;
            }
        }
    }

    /**
     * Penalizes multiple users by removing XP in batches
     * Only callable by DEFAULT_ADMIN_ROLE
     *
     * @param poolId The pool identifier
     * @param users Array of user addresses
     * @param xpToRemove Array of XP amounts to remove
     */
    function batchPenalizeRewardPoolUsers(
        uint256 poolId,
        address[] calldata users,
        uint256[] calldata xpToRemove
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        RewardPoolInfo storage info = rewardPools[poolId];
        if (info.pool == address(0)) revert NoPoolForId();

        IBlueprintRewardPool(info.pool).batchPenalizeUsers(users, xpToRemove);

        // Emit individual events for each user for compatibility
        for (uint256 i = 0; i < users.length; ) {
            emit RewardPoolUserPenalized(poolId, users[i], xpToRemove[i]);
            unchecked {
                ++i;
            }
        }
    }

    /**
     * Grants signer role to an address for a specific pool
     * Only callable by DEFAULT_ADMIN_ROLE
     *
     * @param poolId The pool identifier
     * @param signer The address to grant signer role
     */
    function grantRewardPoolSignerRole(
        uint256 poolId,
        address signer
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        RewardPoolInfo storage info = rewardPools[poolId];
        if (info.pool == address(0)) revert NoPoolForId();

        IBlueprintRewardPool(info.pool).grantSignerRole(signer);
    }

    /**
     * Revokes signer role from an address for a specific pool
     * Only callable by DEFAULT_ADMIN_ROLE
     *
     * @param poolId The pool identifier
     * @param signer The address to revoke signer role from
     */
    function revokeRewardPoolSignerRole(
        uint256 poolId,
        address signer
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        RewardPoolInfo storage info = rewardPools[poolId];
        if (info.pool == address(0)) revert NoPoolForId();

        IBlueprintRewardPool(info.pool).revokeSignerRole(signer);
    }

    /**
     * Takes a snapshot of current balances for reward distribution
     * Only callable by DEFAULT_ADMIN_ROLE
     *
     * @param poolId The pool identifier
     * @param tokenAddresses Array of ERC20 token addresses to snapshot
     */
    function takeRewardPoolSnapshot(
        uint256 poolId,
        address[] calldata tokenAddresses
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        RewardPoolInfo storage info = rewardPools[poolId];
        if (info.pool == address(0)) revert NoPoolForId();

        IBlueprintRewardPool(info.pool).takeSnapshot(tokenAddresses);
    }

    /**
     * Takes a snapshot of only native ETH for reward distribution
     * Only callable by DEFAULT_ADMIN_ROLE
     *
     * @param poolId The pool identifier
     */
    function takeRewardPoolNativeSnapshot(
        uint256 poolId
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        RewardPoolInfo storage info = rewardPools[poolId];
        if (info.pool == address(0)) revert NoPoolForId();

        IBlueprintRewardPool(info.pool).takeNativeSnapshot();
    }

    /**
     * Emergency withdrawal of funds from a reward pool
     * Only callable by DEFAULT_ADMIN_ROLE
     *
     * @param poolId The pool identifier
     * @param tokenAddress Token address (address(0) for native)
     * @param to Recipient address
     * @param amount Amount to withdraw
     * @param tokenType Type of token (NATIVE or ERC20 only)
     */
    function emergencyWithdrawFromRewardPool(
        uint256 poolId,
        address tokenAddress,
        address to,
        uint256 amount,
        IBlueprintRewardPool.TokenType tokenType
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        RewardPoolInfo storage info = rewardPools[poolId];
        if (info.pool == address(0)) revert NoPoolForId();

        IBlueprintRewardPool(info.pool).emergencyWithdraw(
            tokenAddress,
            to,
            amount,
            tokenType
        );
    }

    /**
     * Gets reward pool information
     *
     * @param poolId The pool identifier
     * @return Pool information struct
     */
    function getRewardPoolInfo(
        uint256 poolId
    ) external view returns (RewardPoolInfo memory) {
        return rewardPools[poolId];
    }

    /**
     * Gets the reward pool address for a given pool ID
     *
     * @param poolId The pool identifier
     * @return The pool address
     */
    function getRewardPoolAddress(
        uint256 poolId
    ) external view returns (address) {
        RewardPoolInfo storage info = rewardPools[poolId];
        if (info.pool == address(0)) revert NoPoolForId();
        return info.pool;
    }

    /**
     * Checks if a reward pool is active
     *
     * @param poolId The pool identifier
     * @return True if pool is active
     */
    function isRewardPoolActive(uint256 poolId) external view returns (bool) {
        return rewardPools[poolId].active;
    }

    // ===== BUYBACK ESCROW FACTORY FUNCTIONS =====

    /// Buyback Escrow Information
    struct BuybackEscrowInfo {
        uint256 escrowId;
        address escrow;
        bool active;
        string name;
        string description;
    }

    /// Next escrow ID for buyback escrows
    uint256 public nextBuybackEscrowId;

    /// Mapping from escrowId to its info
    mapping(uint256 => BuybackEscrowInfo) public buybackEscrows;

    // Buyback Escrow Factory Events
    event BuybackEscrowCreated(
        uint256 indexed escrowId,
        address indexed escrow,
        string name,
        string description
    );
    event BuybackEscrowActivated(uint256 indexed escrowId);
    event BuybackEscrowDeactivated(uint256 indexed escrowId);
    event BuybackExecuted(
        uint256 indexed escrowId,
        address indexed token,
        uint256 amountIn,
        uint256 amountOut
    );
    event BuybackEscrowPoolRegistered(
        uint256 indexed escrowId,
        PoolId indexed poolId
    );

    /**
     * Creates a new buyback escrow
     * Only callable by DEFAULT_ADMIN_ROLE
     *
     * @param name Name of the buyback escrow
     * @param description Description of the buyback escrow
     * @return escrowId The unique identifier of the newly created escrow
     */
    function createBuybackEscrow(
        string calldata name,
        string calldata description
    ) external onlyRole(DEFAULT_ADMIN_ROLE) returns (uint256) {
        if (buybackEscrowImplementation == address(0)) revert InvalidAddress();

        uint256 escrowId = nextBuybackEscrowId;

        // Create a clone of the shared implementation
        address clone = Clones.clone(buybackEscrowImplementation);

        // Initialize the clone
        BlueprintBuybackEscrow(payable(clone)).initialize(
            poolManager,
            nativeToken,
            blueprintToken,
            address(this) // Factory is the admin
        );

        buybackEscrows[escrowId] = BuybackEscrowInfo({
            escrowId: escrowId,
            escrow: clone,
            active: false, // Escrows start inactive
            name: name,
            description: description
        });

        emit BuybackEscrowCreated(escrowId, clone, name, description);

        unchecked {
            nextBuybackEscrowId++;
        }

        return escrowId;
    }

    /**
     * Activates a buyback escrow to allow operations
     * Only callable by DEFAULT_ADMIN_ROLE
     *
     * @param escrowId The identifier of the escrow to activate
     */
    function activateBuybackEscrow(
        uint256 escrowId
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        BuybackEscrowInfo storage info = buybackEscrows[escrowId];
        if (info.escrow == address(0)) revert NoPoolForId();

        info.active = true;
        BlueprintBuybackEscrow(payable(info.escrow)).unpause();
        emit BuybackEscrowActivated(escrowId);
    }

    /**
     * Deactivates a buyback escrow to prevent operations
     * Only callable by DEFAULT_ADMIN_ROLE
     *
     * @param escrowId The identifier of the escrow to deactivate
     */
    function deactivateBuybackEscrow(
        uint256 escrowId
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        BuybackEscrowInfo storage info = buybackEscrows[escrowId];
        if (info.escrow == address(0)) revert NoPoolForId();

        info.active = false;
        BlueprintBuybackEscrow(payable(info.escrow)).pause();
        emit BuybackEscrowDeactivated(escrowId);
    }

    /**
     * Registers a pool for buyback operations in an escrow
     * Only callable by DEFAULT_ADMIN_ROLE
     *
     * @param escrowId The escrow identifier
     * @param poolKey The pool key to register
     */
    function registerPoolInBuybackEscrow(
        uint256 escrowId,
        PoolKey calldata poolKey
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        BuybackEscrowInfo storage info = buybackEscrows[escrowId];
        if (info.escrow == address(0)) revert NoPoolForId();

        BlueprintBuybackEscrow(payable(info.escrow)).registerPool(poolKey);
        emit BuybackEscrowPoolRegistered(escrowId, poolKey.toId());
    }

    /**
     * Sets the Blueprint hook for a buyback escrow
     * Only callable by DEFAULT_ADMIN_ROLE
     *
     * @param escrowId The escrow identifier
     * @param hookAddress The Blueprint hook address
     */
    function setBuybackEscrowHook(
        uint256 escrowId,
        address hookAddress
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        BuybackEscrowInfo storage info = buybackEscrows[escrowId];
        if (info.escrow == address(0)) revert NoPoolForId();

        BlueprintBuybackEscrow(payable(info.escrow)).setBlueprintHook(
            hookAddress
        );
    }

    /**
     * Sets the Blueprint token for a buyback escrow
     * Only callable by DEFAULT_ADMIN_ROLE
     *
     * @param escrowId The escrow identifier
     * @param tokenAddress The Blueprint token address
     */
    function setBuybackEscrowToken(
        uint256 escrowId,
        address tokenAddress
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        BuybackEscrowInfo storage info = buybackEscrows[escrowId];
        if (info.escrow == address(0)) revert NoPoolForId();

        BlueprintBuybackEscrow(payable(info.escrow)).setBlueprintToken(
            tokenAddress
        );
    }

    /**
     * Executes buyback for a specific pool using ERC20 tokens
     * Only callable by DEFAULT_ADMIN_ROLE or addresses with BUYBACK_MANAGER_ROLE on the escrow
     *
     * @param escrowId The escrow identifier
     * @param poolId The pool ID to execute buyback for
     * @param token The token to use for buyback
     * @param amount The amount to use for buyback (0 = use all accumulated)
     */
    function executeBuyback(
        uint256 escrowId,
        PoolId poolId,
        address token,
        uint256 amount
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        BuybackEscrowInfo storage info = buybackEscrows[escrowId];
        if (info.escrow == address(0)) revert NoPoolForId();

        BlueprintBuybackEscrow(payable(info.escrow)).executeBuyback(
            poolId,
            token,
            amount
        );
        emit BuybackExecuted(escrowId, token, amount, 0); // Note: actual amount out would need to be tracked
    }

    /**
     * Executes buyback for a specific pool using native ETH
     * Only callable by DEFAULT_ADMIN_ROLE or addresses with BUYBACK_MANAGER_ROLE on the escrow
     *
     * @param escrowId The escrow identifier
     * @param poolId The pool ID to execute buyback for
     * @param amount The amount to use for buyback (0 = use all accumulated)
     */
    function executeBuybackNative(
        uint256 escrowId,
        PoolId poolId,
        uint256 amount
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        BuybackEscrowInfo storage info = buybackEscrows[escrowId];
        if (info.escrow == address(0)) revert NoPoolForId();

        BlueprintBuybackEscrow(payable(info.escrow)).executeBuybackNative(
            poolId,
            amount
        );
        emit BuybackExecuted(escrowId, nativeToken, amount, 0); // Note: actual amount out would need to be tracked
    }

    /**
     * Burns tokens that have been bought back
     * Only callable by DEFAULT_ADMIN_ROLE
     *
     * @param escrowId The escrow identifier
     * @param token The token to burn
     * @param amount The amount to burn (0 = burn all)
     */
    function burnBuybackTokens(
        uint256 escrowId,
        address token,
        uint256 amount
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        BuybackEscrowInfo storage info = buybackEscrows[escrowId];
        if (info.escrow == address(0)) revert NoPoolForId();

        BlueprintBuybackEscrow(payable(info.escrow)).burnTokens(token, amount);
    }

    /**
     * Emergency withdrawal from a buyback escrow
     * Only callable by DEFAULT_ADMIN_ROLE
     *
     * @param escrowId The escrow identifier
     * @param token Token to withdraw (address(0) for native ETH)
     * @param to Recipient address
     * @param amount Amount to withdraw
     */
    function emergencyWithdrawFromBuybackEscrow(
        uint256 escrowId,
        address token,
        address to,
        uint256 amount
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        BuybackEscrowInfo storage info = buybackEscrows[escrowId];
        if (info.escrow == address(0)) revert NoPoolForId();

        BlueprintBuybackEscrow(payable(info.escrow)).emergencyWithdraw(
            token,
            to,
            amount
        );
    }

    /**
     * Grants buyback manager role to an address for a specific escrow
     * Only callable by DEFAULT_ADMIN_ROLE
     *
     * @param escrowId The escrow identifier
     * @param manager The address to grant buyback manager role
     */
    function grantBuybackManagerRole(
        uint256 escrowId,
        address manager
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        BuybackEscrowInfo storage info = buybackEscrows[escrowId];
        if (info.escrow == address(0)) revert NoPoolForId();

        BlueprintBuybackEscrow escrow = BlueprintBuybackEscrow(
            payable(info.escrow)
        );
        escrow.grantRole(escrow.BUYBACK_MANAGER_ROLE(), manager);
    }

    /**
     * Revokes buyback manager role from an address for a specific escrow
     * Only callable by DEFAULT_ADMIN_ROLE
     *
     * @param escrowId The escrow identifier
     * @param manager The address to revoke buyback manager role from
     */
    function revokeBuybackManagerRole(
        uint256 escrowId,
        address manager
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        BuybackEscrowInfo storage info = buybackEscrows[escrowId];
        if (info.escrow == address(0)) revert NoPoolForId();

        BlueprintBuybackEscrow escrow = BlueprintBuybackEscrow(
            payable(info.escrow)
        );
        escrow.revokeRole(escrow.BUYBACK_MANAGER_ROLE(), manager);
    }

    /**
     * Gets buyback escrow information
     *
     * @param escrowId The escrow identifier
     * @return Escrow information struct
     */
    function getBuybackEscrowInfo(
        uint256 escrowId
    ) external view returns (BuybackEscrowInfo memory) {
        return buybackEscrows[escrowId];
    }

    /**
     * Gets the buyback escrow address for a given escrow ID
     *
     * @param escrowId The escrow identifier
     * @return The escrow address
     */
    function getBuybackEscrowAddress(
        uint256 escrowId
    ) external view returns (address) {
        BuybackEscrowInfo storage info = buybackEscrows[escrowId];
        if (info.escrow == address(0)) revert NoPoolForId();
        return info.escrow;
    }

    /**
     * Checks if a buyback escrow is active
     *
     * @param escrowId The escrow identifier
     * @return True if escrow is active
     */
    function isBuybackEscrowActive(
        uint256 escrowId
    ) external view returns (bool) {
        return buybackEscrows[escrowId].active;
    }

    /**
     * Gets accumulated token fees for a pool in a buyback escrow
     *
     * @param escrowId The escrow identifier
     * @param poolId The pool ID
     * @param token The token address
     * @return The accumulated fees
     */
    function getBuybackEscrowTokenFees(
        uint256 escrowId,
        PoolId poolId,
        address token
    ) external view returns (uint256) {
        BuybackEscrowInfo storage info = buybackEscrows[escrowId];
        if (info.escrow == address(0)) revert NoPoolForId();

        return
            BlueprintBuybackEscrow(payable(info.escrow))
                .getAccumulatedTokenFees(poolId, token);
    }

    /**
     * Gets accumulated native fees for a pool in a buyback escrow
     *
     * @param escrowId The escrow identifier
     * @param poolId The pool ID
     * @return The accumulated fees
     */
    function getBuybackEscrowNativeFees(
        uint256 escrowId,
        PoolId poolId
    ) external view returns (uint256) {
        BuybackEscrowInfo storage info = buybackEscrows[escrowId];
        if (info.escrow == address(0)) revert NoPoolForId();

        return
            BlueprintBuybackEscrow(payable(info.escrow))
                .getAccumulatedNativeFees(poolId);
    }

    // ===== EXISTING BLUEPRINT FACTORY FUNCTIONS =====

    /**
     * Launch a new creator token using the Blueprint Protocol
     * Only callable by CREATOR_ROLE
     *
     * @param _creator The creator address
     * @param _name The token name
     * @param _symbol The token symbol
     * @param _tokenUri The token URI
     * @param _initialSupply The initial token supply (default 10B if 0)
     * @return creatorToken The address of the created token
     * @return treasuryAddress The address of the creator's treasury
     */
    function launchCreatorCoin(
        address _creator,
        string calldata _name,
        string calldata _symbol,
        string calldata _tokenUri,
        uint256 _initialSupply
    )
        external
        onlyRole(CREATOR_ROLE)
        whenNotPaused
        returns (address creatorToken, address payable treasuryAddress)
    {
        if (!initialized) revert BlueprintNetworkNotInitialized();
        if (_creator == address(0)) revert InvalidParameters();

        return
            _launchCreatorTokenInternal(
                _creator,
                _name,
                _symbol,
                _tokenUri,
                _initialSupply
            );
    }

    /**
     * Update the Blueprint treasury address
     * Only callable by DEFAULT_ADMIN_ROLE
     *
     * @param _newTreasury The new treasury address
     */
    function setBpTreasury(
        address _newTreasury
    ) external onlyRole(DEFAULT_ADMIN_ROLE) whenNotPaused {
        if (_newTreasury == address(0)) revert InvalidAddress();

        address oldTreasury = treasury;
        treasury = _newTreasury;

        // Note: V2 hook doesn't have updateBpTreasury function
        // Treasury updates are handled through role-based access

        emit BlueprintTreasuryUpdated(_newTreasury);
    }

    /**
     * Update fee configuration
     * Only callable by DEFAULT_ADMIN_ROLE
     *
     * @param _newFeeConfig New fee configuration
     */
    function updateFeeConfiguration(
        IBlueprintProtocol.FeeConfiguration memory _newFeeConfig
    ) external onlyRole(DEFAULT_ADMIN_ROLE) whenNotPaused {
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
     * Route ETH to creator tokens via the Blueprint Protocol
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
        uint256 _initialSupply
    ) internal returns (address creatorToken, address payable treasuryAddress) {
        // Use default supply if not specified
        uint256 supply = _initialSupply == 0
            ? TokenSupply.INITIAL_SUPPLY
            : _initialSupply;

        // Create buyback escrow as treasury directly
        treasuryAddress = _createCreatorBuybackEscrow(_creator);

        // Create the creator token
        creatorToken = _createCreatorToken(
            _name,
            _symbol,
            _tokenUri,
            supply,
            _creator,
            treasuryAddress
        );

        // Create pool and register
        _createPoolAndRegister(creatorToken, treasuryAddress, supply, _creator);

        return (creatorToken, treasuryAddress);
    }

    /**
     * Create pool and register
     */
    function _createPoolAndRegister(
        address creatorToken,
        address payable treasuryAddress,
        uint256 supply,
        address _creator
    ) internal {
        // Get blueprint token from hook
        address bpToken = blueprintHook.blueprintToken();
        if (bpToken == address(0)) revert PoolCreationFailed();

        // Create BP/Creator pool key
        bool currencyFlipped = bpToken >= creatorToken;

        PoolKey memory poolKey = PoolKey({
            currency0: Currency.wrap(!currencyFlipped ? bpToken : creatorToken),
            currency1: Currency.wrap(currencyFlipped ? bpToken : creatorToken),
            fee: LPFeeLibrary.DYNAMIC_FEE_FLAG, // Use dynamic fee flag for hook-managed fees
            tickSpacing: 60,
            hooks: IHooks(address(blueprintHook))
        });

        // Initialize the pool directly through pool manager
        poolManager.initialize(poolKey, _getInitialSqrtPrice());

        // Store pool information in the hook for swap routing
        blueprintHook.registerCreatorPool(
            creatorToken,
            address(treasuryAddress),
            poolKey
        );

        // Register the pool in the buyback escrow
        buybackEscrow.registerPool(poolKey);

        emit CreatorTokenLaunched(
            creatorToken,
            _creator,
            address(treasuryAddress),
            poolKey.toId(),
            0 // No tokenId since we're not using Flaunch
        );
    }

    /**
     * Create ETH/BP pool through factory
     */
    function _createEthBpPool() internal {
        // Ensure proper currency ordering (currency0 < currency1)
        (Currency currency0, Currency currency1) = nativeToken < blueprintToken
            ? (Currency.wrap(nativeToken), Currency.wrap(blueprintToken))
            : (Currency.wrap(blueprintToken), Currency.wrap(nativeToken));

        PoolKey memory ethBpPoolKey = PoolKey({
            currency0: currency0,
            currency1: currency1,
            fee: LPFeeLibrary.DYNAMIC_FEE_FLAG, // Use dynamic fee flag for hook-managed fees
            tickSpacing: 60,
            hooks: IHooks(address(blueprintHook))
        });

        // Initialize the pool directly through pool manager
        poolManager.initialize(ethBpPoolKey, _getInitialSqrtPrice());

        // Register the ETH/BP pool with the hook
        blueprintHook.registerEthBpPool(ethBpPoolKey);

        // Register the pool in the buyback escrow
        buybackEscrow.registerPool(ethBpPoolKey);
    }

    /**
     * Get initial sqrt price for pool initialization
     */
    function _getInitialSqrtPrice() internal pure returns (uint160) {
        // Returns sqrt(1) in Q64.96 format (1:1 price ratio)
        return 79228162514264337593543950336;
    }

    /**
     * Deploy Blueprint token
     */
    function _createBlueprintToken() internal returns (address) {
        // Generate a unique salt for the token
        bytes32 salt = keccak256(
            abi.encodePacked("BlueprintToken", block.timestamp, address(this))
        );

        // Deploy the token using CREATE2
        address token = LibClone.cloneDeterministic(
            creatorcoinImplementation,
            salt
        );

        // Initialize the Blueprint token
        IMemecoin(token).initialize("Blueprint", "BP", "");

        // Set factory-specific properties for CreatorCoin
        if (token.code.length > 0) {
            try CreatorCoin(token).setCreator(address(this)) {} catch {}
            try CreatorCoin(token).setTreasury(payable(treasury)) {} catch {}
        }

        // Mint the initial supply to the hook (it will manage BP tokens)
        IMemecoin(token).mint(address(blueprintHook), 10_000_000_000 ether); // 10B BP tokens

        return token;
    }

    /**
     * Create a new creator token
     *
     * @param _name The token name
     * @param _symbol The token symbol
     * @param _tokenUri The token URI
     * @param _supply The token supply
     * @param _creator The creator address
     * @param _treasury The treasury address
     * @return The address of the created token
     */
    function _createCreatorToken(
        string calldata _name,
        string calldata _symbol,
        string calldata _tokenUri,
        uint256 _supply,
        address _creator,
        address payable _treasury
    ) internal returns (address) {
        // Generate a unique salt for the token
        bytes32 salt = keccak256(
            abi.encodePacked(_name, _symbol, block.timestamp, msg.sender)
        );

        // Deploy the token using CREATE2
        address token = LibClone.cloneDeterministic(
            creatorcoinImplementation,
            salt
        );

        // Initialize the token
        IMemecoin(token).initialize(_name, _symbol, _tokenUri);

        // Set factory-specific properties for CreatorCoin
        if (token.code.length > 0) {
            try CreatorCoin(token).setCreator(_creator) {} catch {}
            try CreatorCoin(token).setTreasury(_treasury) {} catch {}
        }

        // Mint the initial supply to this factory (will be distributed to pools)
        IMemecoin(token).mint(address(this), _supply);

        return token;
    }

    /**
     * Create a buyback escrow for a creator token (replaces treasury)
     *
     * @param _creator The creator address
     * @return The address of the created buyback escrow (treasury)
     */
    function _createCreatorBuybackEscrow(
        address _creator
    ) internal returns (address payable) {
        // Generate a unique salt for the buyback escrow
        bytes32 salt = keccak256(abi.encodePacked(_creator, block.timestamp));

        // Deploy the buyback escrow using CREATE2 (serves as enhanced treasury)
        address payable treasuryAddress = payable(
            LibClone.cloneDeterministic(buybackEscrowImplementation, salt)
        );

        // Initialize the buyback escrow as treasury
        BlueprintBuybackEscrow(treasuryAddress).initialize(
            poolManager,
            nativeToken,
            blueprintToken,
            address(this) // Factory is the admin
        );

        return treasuryAddress;
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
