// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

/**
 * @title RewardPool
 * @notice XP-based reward pool system that tracks user engagement and distributes rewards proportionally
 * @dev Upgradeable contract with role-based access control and XP management
 */
contract RewardPool is 
    Initializable, 
    UUPSUpgradeable, 
    AccessControlUpgradeable, 
    PausableUpgradeable,
    ReentrancyGuardUpgradeable 
{
    using SafeERC20 for IERC20;

    // Roles
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant XP_MANAGER_ROLE = keccak256("XP_MANAGER_ROLE");
    bytes32 public constant HOOK_ROLE = keccak256("HOOK_ROLE");
    bytes32 public constant EMERGENCY_ROLE = keccak256("EMERGENCY_ROLE");
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");

    // XP Configuration
    struct XPConfig {
        uint256 buyEventXP;      // XP awarded per buy event
        uint256 sellEventXP;     // XP awarded per sell event (can be negative penalty)
        uint256 minClaimAmount;  // Minimum reward amount to claim
        bool buyTrackingEnabled; // Enable/disable buy event tracking
        bool sellTrackingEnabled; // Enable/disable sell event tracking
    }

    // User Data
    struct UserData {
        uint256 totalXP;         // Total XP accumulated
        uint256 buyEvents;       // Number of buy events
        uint256 sellEvents;      // Number of sell events
        uint256 lastClaimTime;   // Last time user claimed rewards
        bool isAllowlisted;      // Whether user is eligible for rewards
        bool isPenalized;        // Whether user is penalized/blocked
    }

    // Reward Period
    struct RewardPeriod {
        uint256 startTime;
        uint256 endTime;
        uint256 totalRewards;
        uint256 totalXPSnapshot;
        bool finalized;
    }

    // State Variables
    mapping(address => UserData) public userData;
    mapping(uint256 => RewardPeriod) public rewardPeriods;
    mapping(address => mapping(uint256 => bool)) public hasClaimed; // user => period => claimed
    
    XPConfig public xpConfig;
    uint256 public totalXP;
    uint256 public currentPeriod;
    uint256 public totalUsersAllowlisted;
    
    address public blueprintToken;
    address public blueprintHook;
    
    // Events
    event XPAwarded(address indexed user, uint256 amount, string reason);
    event XPPenalized(address indexed user, uint256 amount, string reason);
    event UserAllowlisted(address indexed user);
    event UserRemovedFromAllowlist(address indexed user);
    event UserPenalized(address indexed user, string reason);
    event UserUnpenalized(address indexed user);
    event RewardsClaimed(address indexed user, uint256 period, uint256 amount);
    event RewardPeriodStarted(uint256 indexed period, uint256 startTime, uint256 totalRewards);
    event RewardPeriodFinalized(uint256 indexed period, uint256 totalXP);
    event BuyEventTracked(address indexed user, address indexed token);
    event SellEventTracked(address indexed user, address indexed token);
    event XPConfigUpdated(XPConfig newConfig);

    // Custom Errors
    error NotAllowlisted();
    error UserIsPenalized();
    error PeriodNotActive();
    error PeriodNotFinalized();
    error AlreadyClaimed();
    error InsufficientRewards();
    error NoXPToReward();
    error InvalidConfiguration();
    error InvalidPeriod();

    /**
     * @notice Initialize the RewardPool contract
     * @param _admin Admin address
     * @param _blueprintToken Blueprint token address for rewards
     */
    function initialize(
        address _admin,
        address _blueprintToken
    ) public initializer {
        __AccessControl_init();
        __Pausable_init();
        __ReentrancyGuard_init();
        __UUPSUpgradeable_init();

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(ADMIN_ROLE, _admin);
        _grantRole(XP_MANAGER_ROLE, _admin);
        _grantRole(EMERGENCY_ROLE, _admin);
        _grantRole(UPGRADER_ROLE, _admin);

        blueprintToken = _blueprintToken;
        
        // Default XP configuration
        xpConfig = XPConfig({
            buyEventXP: 10,
            sellEventXP: 5,
            minClaimAmount: 1e18, // 1 BP token minimum
            buyTrackingEnabled: true,
            sellTrackingEnabled: true
        });

        currentPeriod = 0;
    }

    // XP Management Functions

    /**
     * @notice Add a user to the allowlist
     * @param _user User address to allowlist
     */
    function addToAllowlist(address _user) external onlyRole(XP_MANAGER_ROLE) {
        if (!userData[_user].isAllowlisted) {
            userData[_user].isAllowlisted = true;
            totalUsersAllowlisted++;
            emit UserAllowlisted(_user);
        }
    }

    /**
     * @notice Remove a user from the allowlist
     * @param _user User address to remove
     */
    function removeFromAllowlist(address _user) external onlyRole(XP_MANAGER_ROLE) {
        if (userData[_user].isAllowlisted) {
            userData[_user].isAllowlisted = false;
            totalUsersAllowlisted--;
            emit UserRemovedFromAllowlist(_user);
        }
    }

    /**
     * @notice Penalize a user (blocks them from earning/claiming rewards)
     * @param _user User address to penalize
     * @param _reason Reason for penalization
     */
    function penalizeUser(address _user, string calldata _reason) external onlyRole(XP_MANAGER_ROLE) {
        userData[_user].isPenalized = true;
        emit UserPenalized(_user, _reason);
    }

    /**
     * @notice Remove penalty from a user
     * @param _user User address to unpenalize
     */
    function unpenalizeUser(address _user) external onlyRole(XP_MANAGER_ROLE) {
        userData[_user].isPenalized = false;
        emit UserUnpenalized(_user);
    }

    /**
     * @notice Award XP to a user
     * @param _user User address
     * @param _amount XP amount to award
     * @param _reason Reason for XP award
     */
    function awardXP(
        address _user, 
        uint256 _amount, 
        string calldata _reason
    ) external onlyRole(XP_MANAGER_ROLE) {
        if (!userData[_user].isAllowlisted) revert NotAllowlisted();
        if (userData[_user].isPenalized) revert UserIsPenalized();

        userData[_user].totalXP += _amount;
        totalXP += _amount;
        
        emit XPAwarded(_user, _amount, _reason);
    }

    /**
     * @notice Remove XP from a user (penalty)
     * @param _user User address
     * @param _amount XP amount to remove
     * @param _reason Reason for XP penalty
     */
    function penalizeXP(
        address _user,
        uint256 _amount,
        string calldata _reason
    ) external onlyRole(XP_MANAGER_ROLE) {
        if (userData[_user].totalXP >= _amount) {
            userData[_user].totalXP -= _amount;
            totalXP -= _amount;
        } else {
            totalXP -= userData[_user].totalXP;
            userData[_user].totalXP = 0;
        }
        
        emit XPPenalized(_user, _amount, _reason);
    }

    // Event Tracking Functions (called by BlueprintNetworkHook)

    /**
     * @notice Track a buy event for XP calculation
     * @param _user User who made the purchase
     * @param _token Token that was purchased
     */
    function trackBuyEvent(address _user, address _token) external onlyRole(HOOK_ROLE) {
        if (!xpConfig.buyTrackingEnabled) return;
        if (!userData[_user].isAllowlisted) return;
        if (userData[_user].isPenalized) return;

        userData[_user].buyEvents++;
        userData[_user].totalXP += xpConfig.buyEventXP;
        totalXP += xpConfig.buyEventXP;

        emit BuyEventTracked(_user, _token);
        emit XPAwarded(_user, xpConfig.buyEventXP, "Buy Event");
    }

    /**
     * @notice Track a sell event for XP calculation
     * @param _user User who made the sale
     * @param _token Token that was sold
     */
    function trackSellEvent(address _user, address _token) external onlyRole(HOOK_ROLE) {
        if (!xpConfig.sellTrackingEnabled) return;
        if (!userData[_user].isAllowlisted) return;
        if (userData[_user].isPenalized) return;

        userData[_user].sellEvents++;
        userData[_user].totalXP += xpConfig.sellEventXP;
        totalXP += xpConfig.sellEventXP;

        emit SellEventTracked(_user, _token);
        emit XPAwarded(_user, xpConfig.sellEventXP, "Sell Event");
    }

    // Reward Period Management

    /**
     * @notice Start a new reward period
     * @param _duration Duration of the reward period in seconds
     * @param _totalRewards Total rewards to distribute in this period
     */
    function startRewardPeriod(
        uint256 _duration,
        uint256 _totalRewards
    ) external onlyRole(ADMIN_ROLE) {
        if (currentPeriod > 0 && !rewardPeriods[currentPeriod].finalized) {
            revert PeriodNotFinalized();
        }

        currentPeriod++;
        rewardPeriods[currentPeriod] = RewardPeriod({
            startTime: block.timestamp,
            endTime: block.timestamp + _duration,
            totalRewards: _totalRewards,
            totalXPSnapshot: 0,
            finalized: false
        });

        emit RewardPeriodStarted(currentPeriod, block.timestamp, _totalRewards);
    }

    /**
     * @notice Finalize the current reward period (takes XP snapshot)
     */
    function finalizeRewardPeriod() external onlyRole(ADMIN_ROLE) {
        if (currentPeriod == 0) revert InvalidPeriod();
        
        RewardPeriod storage period = rewardPeriods[currentPeriod];
        if (block.timestamp < period.endTime) revert PeriodNotActive();
        if (period.finalized) revert PeriodNotActive();

        period.totalXPSnapshot = totalXP;
        period.finalized = true;

        emit RewardPeriodFinalized(currentPeriod, totalXP);
    }

    // Claiming Functions

    /**
     * @notice Calculate claimable rewards for a user in a specific period
     * @param _user User address
     * @param _period Reward period
     * @return claimableAmount Amount of rewards claimable
     */
    function calculateClaimableRewards(
        address _user,
        uint256 _period
    ) public view returns (uint256 claimableAmount) {
        if (_period == 0 || _period > currentPeriod) return 0;
        
        RewardPeriod memory period = rewardPeriods[_period];
        if (!period.finalized) return 0;
        if (hasClaimed[_user][_period]) return 0;
        
        UserData memory user = userData[_user];
        if (!user.isAllowlisted || user.isPenalized || user.totalXP == 0) return 0;
        
        if (period.totalXPSnapshot == 0) return 0;
        
        // Calculate user's share: (userXP / totalXP) * totalRewards
        claimableAmount = (user.totalXP * period.totalRewards) / period.totalXPSnapshot;
        
        if (claimableAmount < xpConfig.minClaimAmount) return 0;
    }

    /**
     * @notice Claim rewards for a specific period
     * @param _period Reward period to claim from
     */
    function claimRewards(uint256 _period) external nonReentrant whenNotPaused {
        if (!userData[msg.sender].isAllowlisted) revert NotAllowlisted();
        if (userData[msg.sender].isPenalized) revert UserIsPenalized();
        if (hasClaimed[msg.sender][_period]) revert AlreadyClaimed();

        uint256 claimableAmount = calculateClaimableRewards(msg.sender, _period);
        if (claimableAmount == 0) revert InsufficientRewards();

        hasClaimed[msg.sender][_period] = true;
        userData[msg.sender].lastClaimTime = block.timestamp;
        
        IERC20(blueprintToken).safeTransfer(msg.sender, claimableAmount);
        
        emit RewardsClaimed(msg.sender, _period, claimableAmount);
    }

    /**
     * @notice Claim rewards for multiple periods at once
     * @param _periods Array of periods to claim from
     */
    function claimMultiplePeriods(uint256[] calldata _periods) external nonReentrant whenNotPaused {
        if (!userData[msg.sender].isAllowlisted) revert NotAllowlisted();
        if (userData[msg.sender].isPenalized) revert UserIsPenalized();

        uint256 totalClaimable = 0;
        
        for (uint256 i = 0; i < _periods.length; i++) {
            if (hasClaimed[msg.sender][_periods[i]]) continue;
            
            uint256 claimable = calculateClaimableRewards(msg.sender, _periods[i]);
            if (claimable > 0) {
                hasClaimed[msg.sender][_periods[i]] = true;
                totalClaimable += claimable;
                emit RewardsClaimed(msg.sender, _periods[i], claimable);
            }
        }
        
        if (totalClaimable == 0) revert InsufficientRewards();
        
        userData[msg.sender].lastClaimTime = block.timestamp;
        IERC20(blueprintToken).safeTransfer(msg.sender, totalClaimable);
    }

    // Configuration Functions

    /**
     * @notice Update XP configuration
     * @param _newConfig New XP configuration
     */
    function updateXPConfig(XPConfig calldata _newConfig) external onlyRole(ADMIN_ROLE) {
        xpConfig = _newConfig;
        emit XPConfigUpdated(_newConfig);
    }

    /**
     * @notice Set the Blueprint hook address
     * @param _hook Hook address
     */
    function setBlueprintHook(address _hook) external onlyRole(ADMIN_ROLE) {
        blueprintHook = _hook;
        _grantRole(HOOK_ROLE, _hook);
    }

    /**
     * @notice Deposit rewards into the contract
     * @param _amount Amount to deposit
     */
    function depositRewards(uint256 _amount) external onlyRole(ADMIN_ROLE) {
        IERC20(blueprintToken).safeTransferFrom(msg.sender, address(this), _amount);
    }

    // Emergency Functions

    /**
     * @notice Emergency withdrawal function
     * @param _token Token to withdraw
     * @param _amount Amount to withdraw
     */
    function emergencyWithdraw(
        address _token,
        uint256 _amount
    ) external onlyRole(EMERGENCY_ROLE) {
        IERC20(_token).safeTransfer(msg.sender, _amount);
    }

    /**
     * @notice Pause the contract
     */
    function pause() external onlyRole(EMERGENCY_ROLE) {
        _pause();
    }

    /**
     * @notice Unpause the contract
     */
    function unpause() external onlyRole(EMERGENCY_ROLE) {
        _unpause();
    }

    // View Functions

    /**
     * @notice Get user data
     * @param _user User address
     * @return User data struct
     */
    function getUserData(address _user) external view returns (UserData memory) {
        return userData[_user];
    }

    /**
     * @notice Get reward period data
     * @param _period Period number
     * @return Reward period struct
     */
    function getRewardPeriod(uint256 _period) external view returns (RewardPeriod memory) {
        return rewardPeriods[_period];
    }

    /**
     * @notice Check if user has claimed rewards for a period
     * @param _user User address
     * @param _period Period number
     * @return Whether user has claimed
     */
    function hasUserClaimed(address _user, uint256 _period) external view returns (bool) {
        return hasClaimed[_user][_period];
    }

    // Upgradeable Functions

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
     * @notice Override supportsInterface to include AccessControl
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