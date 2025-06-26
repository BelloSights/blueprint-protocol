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
 * @title IBlueprintFactory
 * @notice Interface for Blueprint Protocol token factory
 * @dev Handles deployment of Blueprint and Creator tokens
 */
interface IBlueprintFactory {
    
    // Events
    event BlueprintTokenCreated(address indexed blueprintToken, uint256 totalSupply);
    event CreatorTokenCreated(address indexed creatorToken, address indexed creator, uint256 initialSupply);
    event CreatorApproved(address indexed creator, bool approved);
    event TokenImplementationUpdated(address indexed oldImplementation, address indexed newImplementation);
    
    // Errors
    error BlueprintTokenAlreadyExists();
    error CreatorNotApproved();
    error InvalidTokenImplementation();
    error InvalidSupply();
    error TokenCreationFailed();
    
    // Structs
    struct CreatorTokenConfig {
        string name;
        string symbol;
        string metadata;
        uint256 initialSupply;
        address creator;
        bytes additionalData;
    }
    
    struct BlueprintTokenConfig {
        string name;
        string symbol;
        uint256 totalSupply;
        address treasury;
        bytes additionalData;
    }
    
    // Core Functions
    function deployBlueprintToken(BlueprintTokenConfig calldata config) external returns (address blueprintToken);
    function deployCreatorToken(CreatorTokenConfig calldata config) external returns (address creatorToken);
    
    // Admin Functions
    function approveCreator(address creator, bool approved) external;
    function setTokenImplementation(address newImplementation) external;
    function setBlueprintHook(address hookAddress) external;
    
    // View Functions
    function blueprintToken() external view returns (address);
    function isApprovedCreator(address creator) external view returns (bool);
    function getTokenImplementation() external view returns (address);
    function blueprintHook() external view returns (address);
    function getCreatorTokens(address creator) external view returns (address[] memory);
} 