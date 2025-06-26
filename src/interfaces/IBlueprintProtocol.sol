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

import {PoolKey} from '@uniswap/v4-core/src/types/PoolKey.sol';
import {PoolId} from '@uniswap/v4-core/src/types/PoolId.sol';

/**
 * @title IBlueprintProtocol
 * @notice Main interface for Blueprint Protocol functionality
 * @dev Defines core functions for token deployment, routing, and management
 */
interface IBlueprintProtocol {
    
    // Events
    event BlueprintTokenDeployed(address indexed blueprintToken, uint256 supply);
    event CreatorTokenDeployed(address indexed creatorToken, address indexed creator, uint256 initialSupply);
    event PoolCreated(PoolId indexed poolId, address indexed token0, address indexed token1);
    event TokensRouted(address indexed user, uint256 ethAmount, uint256 bpAmount, uint256 creatorAmount);
    event XPAwarded(address indexed user, address indexed token, uint256 xpAmount, string reason);
    event FeesDistributed(PoolId indexed poolId, uint256 buybackAmount, uint256 creatorAmount, uint256 bpTreasuryAmount, uint256 rewardPoolAmount);
    
    // Structs
    struct CreatorTokenParams {
        string name;
        string symbol;
        string metadata;
        uint256 initialSupply;
        address creator;
        uint24 creatorFeeAllocation; // Basis points (0-10000)
    }
    
    struct FeeConfiguration {
        uint24 buybackFee;      // 60% = 6000 basis points
        uint24 creatorFee;      // 20% = 2000 basis points  
        uint24 bpTreasuryFee;   // 10% = 1000 basis points
        uint24 rewardPoolFee;   // 10% = 1000 basis points
        bool active;
    }
    
    // Core Functions
    function registerEthBpPool(PoolKey calldata poolKey) external;
    function registerCreatorPool(address creatorToken, address treasury, PoolKey calldata poolKey) external;
    function routeEthToCreator(address creatorToken, uint256 minCreatorOut) external payable returns (uint256 creatorAmount);
    function routeCreatorToEth(address creatorToken, uint256 creatorAmount, uint256 minEthOut) external returns (uint256 ethAmount);
    
    // View Functions
    function blueprintToken() external view returns (address);
    function ethBpPoolKey() external view returns (PoolKey memory);
    function getCreatorPoolKey(address creatorToken) external view returns (PoolKey memory);
    function isApprovedCreator(address creator) external view returns (bool);
    function getFeeConfiguration() external view returns (FeeConfiguration memory);
    
    // Admin Functions
    function approveCreator(address creator, bool approved) external;
    function updateFeeConfiguration(FeeConfiguration calldata newConfig) external;
} 