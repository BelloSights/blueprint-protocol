// SPDX-License-Identifier: Apache-2.0
/*
__________.__                             .__        __   
\______   \  |  __ __   ____ _____________|__| _____/  |_ 
 |    |  _/  | |  |  \_/ __ \\____ \_  __ \  |/    \   __\
 |    |   \  |_|  |  /\  ___/|  |_> >  | \/  |   |  \  |  
 |______  /____/____/  \___  >   __/|__|  |__|___|  /__|  
        \/                 \/|__|                 \/      
*/
pragma solidity 0.8.26;

import {EIP712Upgradeable} from "@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import {IERC20} from "@openzeppelin/contracts/interfaces/IERC20.sol";
import {IBlueprintRewardPool} from "@flaunch-interfaces/IBlueprintRewardPool.sol";

/// @title BlueprintRewardPool
/// @notice XP-based reward pool that distributes rewards based on user XP percentage
/// @dev Users receive rewards proportional to their XP: (userXP / totalXP) * poolRewards
contract BlueprintRewardPool is
    Initializable,
    AccessControlUpgradeable,
    UUPSUpgradeable,
    EIP712Upgradeable,
    ReentrancyGuardUpgradeable,
    IBlueprintRewardPool
{
    using ECDSA for bytes32;

    // ===== ERRORS =====
    error RewardPool__OnlyFactory();
    error RewardPool__PoolNotActive();
    error RewardPool__UserNotInPool();
    error RewardPool__InvalidSignature();
    error RewardPool__NonceAlreadyUsed();
    error RewardPool__InvalidNonce();
    error RewardPool__InsufficientRewards();
    error RewardPool__ZeroAddress();
    error RewardPool__ZeroXP();
    error RewardPool__UserAlreadyExists();
    error RewardPool__TransferFailed();
    error RewardPool__InvalidTokenType();
    error RewardPool__InvalidXPAmount();
    error RewardPool__AlreadyClaimed();
    error RewardPool__CannotUpdateXPWhenActive();
    error RewardPool__InsufficientPoolBalance();
    error RewardPool__CannotWithdrawWhenActive();

    // ===== STATE VARIABLES =====
    address public s_factory;
    bool public s_active;

    // EIP-712 domain separator components
    string public s_signingDomain;
    string public s_signatureVersion;

    // XP tracking
    mapping(address => uint256) public s_userXP;
    address[] public s_users;
    mapping(address => bool) public s_isUser;
    uint256 public s_totalXP;

    // Nonce tracking for replay protection (per-user)
    mapping(address => mapping(uint256 => bool)) public s_usedNonces;
    mapping(address => uint256) public s_userNonceCounter;

    // Snapshot system for reward distribution
    mapping(address => uint256) public s_rewardSnapshots; // ERC20 snapshots
    uint256 public s_nativeRewardSnapshot; // ETH snapshot
    bool public s_snapshotTaken; // Whether snapshot has been taken

    // Claim tracking to prevent double claiming
    mapping(address => mapping(address => mapping(TokenType => bool)))
        public s_hasClaimed;

    // Track total claimed amounts to prevent over-allocation
    mapping(address => mapping(TokenType => uint256)) public s_totalClaimed;

    // Roles
    bytes32 public constant SIGNER_ROLE = keccak256("SIGNER");

    // EIP-712 typehashes
    bytes32 internal constant CLAIM_DATA_HASH =
        keccak256(
            "ClaimData(address user,uint256 nonce,address tokenAddress,uint8 tokenType)"
        );

    // Constants for precision
    uint256 public constant PRECISION = 1000; // 3 decimal places (0.001 = 0.1%)

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @notice Initializes the reward pool
    /// @param factory The factory contract address
    /// @param signingDomain The EIP-712 signing domain
    /// @param signatureVersion The signature version
    function initialize(
        address factory,
        string calldata signingDomain,
        string calldata signatureVersion
    ) external initializer {
        if (factory == address(0)) revert RewardPool__ZeroAddress();

        __AccessControl_init();
        __UUPSUpgradeable_init();
        __EIP712_init(signingDomain, signatureVersion);
        __ReentrancyGuard_init();

        s_factory = factory;
        s_signingDomain = signingDomain;
        s_signatureVersion = signatureVersion;
        s_active = false;

        // Grant admin role to factory
        _grantRole(DEFAULT_ADMIN_ROLE, s_factory);
    }

    /// @notice Modifier to ensure only factory can call admin functions
    modifier onlyFactory() {
        if (msg.sender != s_factory) revert RewardPool__OnlyFactory();
        _;
    }

    /// @notice Modifier to ensure pool is active
    modifier onlyActive() {
        if (!s_active) revert RewardPool__PoolNotActive();
        _;
    }

    /// @notice Sets the active state of the pool
    /// @param active True to activate, false to deactivate
    function setActive(bool active) external onlyFactory {
        s_active = active;
        if (active) {
            emit PoolActivated();
        } else {
            emit PoolDeactivated();
        }
    }

    /// @notice Takes a snapshot of current balances for reward distribution
    /// @param tokenAddresses Array of ERC20 token addresses to snapshot
    function takeSnapshot(
        address[] calldata tokenAddresses
    ) external onlyFactory {
        _takeSnapshotWithTokens(tokenAddresses);
    }

    /// @notice Takes a snapshot of only native ETH for reward distribution
    function takeNativeSnapshot() external onlyFactory {
        _takeSnapshot();
    }

    /// @notice Internal function to take snapshot of native ETH only
    function _takeSnapshot() internal {
        s_nativeRewardSnapshot = address(this).balance;
        s_snapshotTaken = true;

        // Emit event with empty token arrays
        address[] memory emptyTokens = new address[](0);
        uint256[] memory emptyAmounts = new uint256[](0);
        emit SnapshotTaken(s_nativeRewardSnapshot, emptyTokens, emptyAmounts);
    }

    /// @notice Internal function to take snapshot with specific tokens
    /// @param tokenAddresses Array of ERC20 token addresses to snapshot
    function _takeSnapshotWithTokens(
        address[] calldata tokenAddresses
    ) internal {
        // Snapshot native ETH
        s_nativeRewardSnapshot = address(this).balance;

        // Snapshot ERC20 tokens
        uint256[] memory tokenAmounts = new uint256[](tokenAddresses.length);
        for (uint256 i = 0; i < tokenAddresses.length; i++) {
            uint256 balance = IERC20(tokenAddresses[i]).balanceOf(
                address(this)
            );
            s_rewardSnapshots[tokenAddresses[i]] = balance;
            tokenAmounts[i] = balance;
        }

        s_snapshotTaken = true;
        emit SnapshotTaken(
            s_nativeRewardSnapshot,
            tokenAddresses,
            tokenAmounts
        );
    }

    /// @notice Adds a new user to the pool with initial XP
    /// @param user User address
    /// @param xp Initial XP amount
    function addUser(address user, uint256 xp) external onlyFactory {
        if (s_active) revert RewardPool__CannotUpdateXPWhenActive();
        if (user == address(0)) revert RewardPool__ZeroAddress();
        if (xp == 0) revert RewardPool__ZeroXP();
        if (s_isUser[user]) revert RewardPool__UserAlreadyExists();

        s_userXP[user] = xp;
        s_users.push(user);
        s_isUser[user] = true;
        s_totalXP += xp;

        emit UserAdded(user, xp);
    }

    /// @notice Updates XP for an existing user
    /// @param user User address
    /// @param newXP New XP amount
    function updateUserXP(address user, uint256 newXP) external onlyFactory {
        if (s_active) revert RewardPool__CannotUpdateXPWhenActive();
        if (!s_isUser[user]) revert RewardPool__UserNotInPool();

        uint256 oldXP = s_userXP[user];
        s_totalXP = s_totalXP - oldXP + newXP;
        s_userXP[user] = newXP;

        // Remove user if XP becomes 0
        if (newXP == 0) {
            s_isUser[user] = false;
            // Note: We keep them in s_users array for historical tracking
        }

        emit UserXPUpdated(user, oldXP, newXP);
    }

    /// @notice Penalizes a user by removing XP
    /// @param user User address
    /// @param xpToRemove Amount of XP to remove
    function penalizeUser(
        address user,
        uint256 xpToRemove
    ) external onlyFactory {
        if (s_active) revert RewardPool__CannotUpdateXPWhenActive();
        if (!s_isUser[user]) revert RewardPool__UserNotInPool();

        uint256 currentXP = s_userXP[user];
        uint256 newXP = currentXP > xpToRemove ? currentXP - xpToRemove : 0;

        s_totalXP = s_totalXP - (currentXP - newXP);
        s_userXP[user] = newXP;

        emit UserPenalized(user, currentXP - newXP);
    }

    /// @notice Grants signer role to an address
    /// @param signer Address to grant signer role
    function grantSignerRole(address signer) external onlyFactory {
        _grantRole(SIGNER_ROLE, signer);
    }

    /// @notice Revokes signer role from an address
    /// @param signer Address to revoke signer role
    function revokeSignerRole(address signer) external onlyFactory {
        _revokeRole(SIGNER_ROLE, signer);
    }

    /// @notice Checks if a user can claim rewards and calculates their allocation
    /// @param user User address
    /// @param tokenAddress Token address
    /// @param tokenType Type of token
    /// @return canClaim True if user can claim
    /// @return allocation User's reward allocation
    function checkClaimEligibility(
        address user,
        address tokenAddress,
        TokenType tokenType
    ) external view returns (bool canClaim, uint256 allocation) {
        if (
            !s_active || !s_isUser[user] || s_totalXP == 0 || !s_snapshotTaken
        ) {
            return (false, 0);
        }

        // Check if user has already claimed this token type
        if (s_hasClaimed[user][tokenAddress][tokenType]) {
            return (false, 0);
        }

        uint256 userXP = s_userXP[user];
        if (userXP == 0) {
            return (false, 0);
        }

        // CRITICAL: Validate tokenAddress and tokenType combination
        if (tokenType == TokenType.NATIVE) {
            // NATIVE token MUST use address(0)
            if (tokenAddress != address(0)) {
                return (false, 0); // Invalid: NATIVE with non-zero address
            }
        } else if (tokenType == TokenType.ERC20) {
            // ERC20 token MUST NOT use address(0)
            if (tokenAddress == address(0)) {
                return (false, 0); // Invalid: ERC20 with zero address
            }
        } else {
            return (false, 0); // Only NATIVE and ERC20 supported
        }

        // Get snapshot amount for this token type
        uint256 snapshotAmount;
        if (tokenType == TokenType.NATIVE) {
            snapshotAmount = s_nativeRewardSnapshot;
        } else if (tokenType == TokenType.ERC20) {
            snapshotAmount = s_rewardSnapshots[tokenAddress];
        } else {
            return (false, 0); // Only NATIVE and ERC20 supported
        }

        if (snapshotAmount == 0) {
            return (false, 0);
        }

        // Calculate user's allocation from snapshot: (userXP / totalXP) * snapshotAmount
        // Using PRECISION for better accuracy with small amounts
        allocation =
            ((snapshotAmount * userXP * PRECISION) / s_totalXP) /
            PRECISION;

        // Check if there are sufficient available rewards to fulfill this allocation
        uint256 availableRewards;
        if (tokenType == TokenType.NATIVE) {
            availableRewards = address(this).balance;
        } else if (tokenType == TokenType.ERC20) {
            availableRewards = IERC20(tokenAddress).balanceOf(address(this));
        }

        // If available rewards are less than allocation, user cannot claim
        if (availableRewards < allocation) {
            return (false, 0);
        }

        canClaim = allocation > 0;
        return (canClaim, allocation);
    }

    /// @notice Claims rewards based on XP percentage
    /// @param data Claim data struct
    /// @param signature EIP-712 signature
    function claimReward(
        ClaimData calldata data,
        bytes calldata signature
    ) external nonReentrant onlyActive {
        // Verify the user is in the pool
        if (!s_isUser[data.user]) revert RewardPool__UserNotInPool();
        if (data.user != msg.sender) revert RewardPool__InvalidSignature();

        // CRITICAL: Validate tokenAddress and tokenType combination
        if (data.tokenType == TokenType.NATIVE) {
            // NATIVE token MUST use address(0)
            if (data.tokenAddress != address(0))
                revert RewardPool__InvalidTokenType();
        } else if (data.tokenType == TokenType.ERC20) {
            // ERC20 token MUST NOT use address(0)
            if (data.tokenAddress == address(0))
                revert RewardPool__InvalidTokenType();
        } else {
            revert RewardPool__InvalidTokenType(); // Only NATIVE and ERC20 supported
        }

        // Check if user has already claimed this token type
        if (s_hasClaimed[data.user][data.tokenAddress][data.tokenType]) {
            revert RewardPool__AlreadyClaimed();
        }

        // Verify signature and nonce
        _validateSignature(data, signature);

        // Calculate user's reward allocation using checkClaimEligibility logic
        (bool canClaim, uint256 rewardAmount) = this.checkClaimEligibility(
            data.user,
            data.tokenAddress,
            data.tokenType
        );

        if (!canClaim || rewardAmount == 0)
            revert RewardPool__InsufficientRewards();

        // Validate sufficient balance exists and transfer
        if (data.tokenType == TokenType.NATIVE) {
            if (address(this).balance < rewardAmount)
                revert RewardPool__InsufficientPoolBalance();

            (bool success, ) = payable(data.user).call{value: rewardAmount}("");
            if (!success) revert RewardPool__TransferFailed();
        } else if (data.tokenType == TokenType.ERC20) {
            uint256 contractBalance = IERC20(data.tokenAddress).balanceOf(
                address(this)
            );
            if (contractBalance < rewardAmount)
                revert RewardPool__InsufficientPoolBalance();

            IERC20(data.tokenAddress).transfer(data.user, rewardAmount);
        } else {
            revert RewardPool__InvalidTokenType();
        }

        // Mark as claimed and update total claimed
        s_hasClaimed[data.user][data.tokenAddress][data.tokenType] = true;
        s_totalClaimed[data.tokenAddress][data.tokenType] += rewardAmount;

        emit RewardClaimed(
            data.user,
            data.tokenAddress,
            rewardAmount,
            data.tokenType,
            s_userXP[data.user],
            s_totalXP
        );
    }

    /// @notice Emergency withdrawal function (factory only)
    /// @dev Can only be called when pool is inactive to protect user claims
    /// @param tokenAddress Token address (address(0) for native)
    /// @param to Recipient address
    /// @param amount Amount to withdraw
    /// @param tokenType Type of token (NATIVE or ERC20 only)
    function emergencyWithdraw(
        address tokenAddress,
        address to,
        uint256 amount,
        TokenType tokenType
    ) external onlyFactory {
        // Prevent withdrawal when pool is active to protect user claims
        if (s_active) revert RewardPool__CannotWithdrawWhenActive();

        // CRITICAL: Validate tokenAddress and tokenType combination
        if (tokenType == TokenType.NATIVE) {
            // NATIVE token MUST use address(0)
            if (tokenAddress != address(0))
                revert RewardPool__InvalidTokenType();
        } else if (tokenType == TokenType.ERC20) {
            // ERC20 token MUST NOT use address(0)
            if (tokenAddress == address(0))
                revert RewardPool__InvalidTokenType();
        } else {
            revert RewardPool__InvalidTokenType(); // Only NATIVE and ERC20 supported
        }
        if (tokenType == TokenType.NATIVE) {
            if (address(this).balance < amount)
                revert RewardPool__InsufficientPoolBalance();
            (bool success, ) = payable(to).call{value: amount}("");
            if (!success) revert RewardPool__TransferFailed();
        } else if (tokenType == TokenType.ERC20) {
            uint256 contractBalance = IERC20(tokenAddress).balanceOf(
                address(this)
            );
            if (contractBalance < amount) {
                revert RewardPool__InsufficientPoolBalance();
            }
            IERC20(tokenAddress).transfer(to, amount);
        } else {
            revert RewardPool__InvalidTokenType();
        }

        // Update total claimed to maintain accounting consistency
        s_totalClaimed[tokenAddress][tokenType] += amount;
    }

    /// @notice Gets user XP
    /// @param user User address
    /// @return User's XP amount
    function getUserXP(address user) external view returns (uint256) {
        return s_userXP[user];
    }

    /// @notice Checks if user is in the pool
    /// @param user User address
    /// @return True if user is in the pool
    function isUser(address user) external view returns (bool) {
        return s_isUser[user];
    }

    /// @notice Gets total number of users
    /// @return Total number of users in the pool
    function getTotalUsers() external view returns (uint256) {
        return s_users.length;
    }

    /// @notice Gets user at index
    /// @param index User index
    /// @return User address at the given index
    function getUserAtIndex(uint256 index) external view returns (address) {
        return s_users[index];
    }

    /// @notice Checks if a user has already claimed rewards for a specific token
    /// @param user User address
    /// @param tokenAddress Token address
    /// @param tokenType Type of token
    /// @return True if user has already claimed
    function hasClaimed(
        address user,
        address tokenAddress,
        TokenType tokenType
    ) external view returns (bool) {
        return s_hasClaimed[user][tokenAddress][tokenType];
    }

    /// @notice Gets total amount claimed for a specific token
    /// @param tokenAddress Token address
    /// @param tokenType Type of token
    /// @return Total amount claimed
    function getTotalClaimed(
        address tokenAddress,
        TokenType tokenType
    ) external view returns (uint256) {
        return s_totalClaimed[tokenAddress][tokenType];
    }

    /// @notice Gets the snapshot amount for a token type
    /// @param tokenAddress Token address (use address(0) for native)
    /// @param tokenType The token type (NATIVE or ERC20)
    /// @return amount The snapshot amount
    function getSnapshotAmount(
        address tokenAddress,
        TokenType tokenType
    ) external view returns (uint256 amount) {
        // CRITICAL: Validate tokenAddress and tokenType combination
        if (tokenType == TokenType.NATIVE) {
            // NATIVE token MUST use address(0)
            if (tokenAddress != address(0)) return 0;
            return s_nativeRewardSnapshot;
        } else if (tokenType == TokenType.ERC20) {
            // ERC20 token MUST NOT use address(0)
            if (tokenAddress == address(0)) return 0;
            return s_rewardSnapshots[tokenAddress];
        }
        return 0;
    }

    /// @notice Gets the current available balance (actual contract balance)
    /// @param tokenAddress Token address (use address(0) for native)
    /// @param tokenType The token type (NATIVE or ERC20)
    /// @return balance The current available balance
    function getAvailableRewards(
        address tokenAddress,
        TokenType tokenType
    ) external view returns (uint256 balance) {
        // CRITICAL: Validate tokenAddress and tokenType combination
        if (tokenType == TokenType.NATIVE) {
            // NATIVE token MUST use address(0)
            if (tokenAddress != address(0)) return 0;
            return address(this).balance;
        } else if (tokenType == TokenType.ERC20) {
            // ERC20 token MUST NOT use address(0)
            if (tokenAddress == address(0)) return 0;
            return IERC20(tokenAddress).balanceOf(address(this));
        }
        return 0;
    }

    /// @notice Gets total rewards from snapshot + claimed amount
    /// @param tokenAddress Token address (use address(0) for native)
    /// @param tokenType The token type (NATIVE or ERC20)
    /// @return total The total rewards (snapshot + claimed)
    function getTotalRewards(
        address tokenAddress,
        TokenType tokenType
    ) external view returns (uint256 total) {
        // CRITICAL: Validate tokenAddress and tokenType combination
        if (tokenType == TokenType.NATIVE) {
            // NATIVE token MUST use address(0)
            if (tokenAddress != address(0)) return 0;
        } else if (tokenType == TokenType.ERC20) {
            // ERC20 token MUST NOT use address(0)
            if (tokenAddress == address(0)) return 0;
        } else {
            return 0; // Invalid token type
        }

        uint256 snapshotAmount;
        if (tokenType == TokenType.NATIVE) {
            snapshotAmount = s_nativeRewardSnapshot;
        } else if (tokenType == TokenType.ERC20) {
            snapshotAmount = s_rewardSnapshots[tokenAddress];
        }
        return snapshotAmount + s_totalClaimed[tokenAddress][tokenType];
    }

    /// @notice Gets the current nonce counter for a user
    /// @param user User address
    /// @return Current nonce counter
    function getUserNonceCounter(address user) external view returns (uint256) {
        return s_userNonceCounter[user];
    }

    /// @notice Checks if a user has used a specific nonce
    /// @param user User address
    /// @param nonce Nonce to check
    /// @return True if nonce has been used
    function isNonceUsed(
        address user,
        uint256 nonce
    ) external view returns (bool) {
        return s_usedNonces[user][nonce];
    }

    /// @notice Gets the next available nonce for a user
    /// @param user User address
    /// @return Next available nonce (current counter + 1)
    function getNextNonce(address user) external view returns (uint256) {
        return s_userNonceCounter[user] + 1;
    }

    /// @notice Validates EIP-712 signature and nonce
    /// @param data Claim data
    /// @param signature Signature to validate
    function _validateSignature(
        ClaimData calldata data,
        bytes calldata signature
    ) internal {
        // Check if this user has already used this nonce
        if (s_usedNonces[data.user][data.nonce])
            revert RewardPool__NonceAlreadyUsed();

        bytes32 digest = _hashTypedDataV4(
            keccak256(
                abi.encode(
                    CLAIM_DATA_HASH,
                    data.user,
                    data.nonce,
                    data.tokenAddress,
                    data.tokenType
                )
            )
        );

        address signer = digest.recover(signature);
        if (!hasRole(SIGNER_ROLE, signer))
            revert RewardPool__InvalidSignature();

        // Mark this nonce as used for this user
        s_usedNonces[data.user][data.nonce] = true;

        // Update user's nonce counter
        if (data.nonce > s_userNonceCounter[data.user]) {
            s_userNonceCounter[data.user] = data.nonce;
        }
    }

    /// @notice Authorizes contract upgrades
    /// @param newImplementation New implementation address
    function _authorizeUpgrade(
        address newImplementation
    ) internal override onlyRole(DEFAULT_ADMIN_ROLE) {}

    /// @notice Supports interface check
    function supportsInterface(
        bytes4 interfaceId
    ) public view override(AccessControlUpgradeable) returns (bool) {
        return super.supportsInterface(interfaceId);
    }

    /// @notice Fallback function to receive native tokens
    receive() external payable {
        // ETH is received - no special handling needed
        // Snapshots will capture the balance when taken
    }

    /// @notice Fallback function
    fallback() external payable {
        // ETH is received - no special handling needed
        // Snapshots will capture the balance when taken
    }

    // ===== BATCH USER MANAGEMENT FUNCTIONS =====

    /// @notice Adds multiple users to the pool with initial XP in batches
    /// @param users Array of user addresses
    /// @param xpAmounts Array of initial XP amounts
    /// @dev Gas-optimized for large user sets. Arrays must be same length.
    /// @dev Duplicate detection handled client-side for gas efficiency.
    function batchAddUsers(
        address[] calldata users,
        uint256[] calldata xpAmounts
    ) external onlyFactory {
        if (s_active) revert RewardPool__CannotUpdateXPWhenActive();
        if (users.length != xpAmounts.length || users.length == 0)
            revert RewardPool__InvalidXPAmount();

        uint256 totalXPToAdd = 0;
        uint256 batchSize = users.length;

        // First pass: validate all inputs and calculate total XP
        for (uint256 i = 0; i < batchSize; ) {
            address user = users[i];
            uint256 xp = xpAmounts[i];

            if (user == address(0)) revert RewardPool__ZeroAddress();
            if (xp == 0) revert RewardPool__ZeroXP();
            if (s_isUser[user]) revert RewardPool__UserAlreadyExists();

            totalXPToAdd += xp; // Solidity 0.8+ has built-in overflow protection

            unchecked {
                ++i;
            }
        }

        // Second pass: add all users (state changes)
        for (uint256 i = 0; i < batchSize; ) {
            address user = users[i];
            uint256 xp = xpAmounts[i];

            s_userXP[user] = xp;
            s_users.push(user);
            s_isUser[user] = true;

            emit UserAdded(user, xp);

            unchecked {
                ++i;
            }
        }

        // Update total XP once (gas efficient)
        s_totalXP += totalXPToAdd;

        emit BatchUsersAdded(users, xpAmounts, batchSize);
    }

    /// @notice Updates XP for multiple existing users in batches
    /// @param users Array of user addresses
    /// @param newXPAmounts Array of new XP amounts
    /// @dev Gas-optimized for large user sets. Arrays must be same length.
    function batchUpdateUserXP(
        address[] calldata users,
        uint256[] calldata newXPAmounts
    ) external onlyFactory {
        if (s_active) revert RewardPool__CannotUpdateXPWhenActive();
        if (users.length != newXPAmounts.length || users.length == 0)
            revert RewardPool__InvalidXPAmount();

        uint256 batchSize = users.length;
        uint256[] memory oldXPAmounts = new uint256[](batchSize);
        uint256 totalXPChange = 0;
        bool isXPIncreasing = true;

        // First pass: validate and calculate XP changes
        for (uint256 i = 0; i < batchSize; ) {
            address user = users[i];
            uint256 newXP = newXPAmounts[i];

            if (!s_isUser[user]) revert RewardPool__UserNotInPool();

            uint256 oldXP = s_userXP[user];
            oldXPAmounts[i] = oldXP;

            if (i == 0) {
                // Determine direction of XP change based on first user
                isXPIncreasing = newXP >= oldXP;
                totalXPChange = isXPIncreasing
                    ? (newXP - oldXP)
                    : (oldXP - newXP);
            } else {
                // Accumulate XP changes
                if (isXPIncreasing && newXP >= oldXP) {
                    totalXPChange += (newXP - oldXP);
                } else if (isXPIncreasing && newXP < oldXP) {
                    // Mixed directions, need to handle carefully
                    if (totalXPChange >= (oldXP - newXP)) {
                        totalXPChange -= (oldXP - newXP);
                    } else {
                        totalXPChange = (oldXP - newXP) - totalXPChange;
                        isXPIncreasing = false;
                    }
                } else if (!isXPIncreasing && newXP <= oldXP) {
                    totalXPChange += (oldXP - newXP);
                } else if (!isXPIncreasing && newXP > oldXP) {
                    // Mixed directions, need to handle carefully
                    if (totalXPChange >= (newXP - oldXP)) {
                        totalXPChange -= (newXP - oldXP);
                    } else {
                        totalXPChange = (newXP - oldXP) - totalXPChange;
                        isXPIncreasing = true;
                    }
                }
            }

            unchecked {
                ++i;
            }
        }

        // Second pass: update user XP and handle user removal for zero XP
        for (uint256 i = 0; i < batchSize; ) {
            address user = users[i];
            uint256 newXP = newXPAmounts[i];
            uint256 oldXP = oldXPAmounts[i];

            s_userXP[user] = newXP;

            // Remove user if XP becomes 0
            if (newXP == 0) {
                s_isUser[user] = false;
                // Note: We keep them in s_users array for historical tracking
            }

            emit UserXPUpdated(user, oldXP, newXP);

            unchecked {
                ++i;
            }
        }

        // Update total XP based on calculated change
        if (isXPIncreasing) {
            s_totalXP += totalXPChange;
        } else {
            s_totalXP = s_totalXP >= totalXPChange
                ? s_totalXP - totalXPChange
                : 0;
        }

        emit BatchUsersUpdated(users, oldXPAmounts, newXPAmounts, batchSize);
    }

    /// @notice Penalizes multiple users by removing XP in batches
    /// @param users Array of user addresses
    /// @param xpToRemove Array of XP amounts to remove
    /// @dev Gas-optimized for large user sets. Arrays must be same length.
    function batchPenalizeUsers(
        address[] calldata users,
        uint256[] calldata xpToRemove
    ) external onlyFactory {
        if (s_active) revert RewardPool__CannotUpdateXPWhenActive();
        if (users.length != xpToRemove.length || users.length == 0)
            revert RewardPool__InvalidXPAmount();

        uint256 batchSize = users.length;
        uint256 totalXPRemoved = 0;

        // First pass: validate all inputs and calculate total XP to remove
        for (uint256 i = 0; i < batchSize; ) {
            address user = users[i];
            uint256 xpPenalty = xpToRemove[i];

            if (!s_isUser[user]) revert RewardPool__UserNotInPool();

            uint256 currentXP = s_userXP[user];
            uint256 actualXPRemoved = currentXP > xpPenalty
                ? xpPenalty
                : currentXP;
            totalXPRemoved += actualXPRemoved;

            unchecked {
                ++i;
            }
        }

        // Second pass: apply penalties
        for (uint256 i = 0; i < batchSize; ) {
            address user = users[i];
            uint256 xpPenalty = xpToRemove[i];

            uint256 currentXP = s_userXP[user];
            uint256 newXP = currentXP > xpPenalty ? currentXP - xpPenalty : 0;
            uint256 actualXPRemoved = currentXP - newXP;

            s_userXP[user] = newXP;

            emit UserPenalized(user, actualXPRemoved);

            unchecked {
                ++i;
            }
        }

        // Update total XP once
        s_totalXP = s_totalXP >= totalXPRemoved
            ? s_totalXP - totalXPRemoved
            : 0;

        emit BatchUsersPenalized(users, xpToRemove, batchSize);
    }
}
