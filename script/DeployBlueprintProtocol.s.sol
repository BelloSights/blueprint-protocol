// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {IPoolManager} from "@uniswap/v4-core/src/interfaces/IPoolManager.sol";
import {Hooks} from "@uniswap/v4-core/src/libraries/Hooks.sol";

import {BlueprintProtocolHook} from "@flaunch/hooks/BlueprintProtocolHook.sol";
import {BlueprintFactory} from "@flaunch/BlueprintFactory.sol";
import {CreatorCoin} from "@flaunch/BlueprintCreatorCoin.sol";
import {BlueprintBuybackEscrow} from "@flaunch/escrows/BlueprintBuybackEscrow.sol";
import {BlueprintRewardPool} from "@flaunch/BlueprintRewardPool.sol";
import {IBlueprintFactory} from "@flaunch-interfaces/IBlueprintFactory.sol";
import {IBlueprintProtocol} from "@flaunch-interfaces/IBlueprintProtocol.sol";
import {HookMiner} from "../test/utils/HookMiner.sol";

/**
 * @title DeployBlueprintProtocol
 * @notice Deploy script for the complete Blueprint Protocol
 * @dev Deploys factory, hook, implementations and initializes the system
 */
contract DeployBlueprintProtocol is Script {
    // Deployment configuration
    struct DeploymentConfig {
        address poolManager;
        address nativeToken; // Address(0) for native ETH
        address admin;
        address treasury;
        IBlueprintProtocol.FeeConfiguration feeConfig;
        string blueprintName;
        string blueprintSymbol;
        string blueprintMetadataURI;
        uint256 blueprintInitialSupply; // Total initial supply
    }

    // Deployed contract addresses
    struct DeployedContracts {
        address hookImplementation;
        address hookProxy;
        address factoryImplementation;
        address factoryProxy;
        address creatorCoinImplementation;
        address buybackEscrowImplementation;
        address rewardPoolImplementation;
        address blueprintToken;
    }

    function run() external {
        // Load deployment configuration
        DeploymentConfig memory config = _loadConfig();

        // Start deployment
        vm.startBroadcast();

        DeployedContracts memory contracts = _deployProtocol(config);

        vm.stopBroadcast();

        // Log deployment results
        _logDeployment(contracts, config);

        // Save deployment to file
        _saveDeployment(contracts);
    }

    /**
     * @notice Deploy the complete Blueprint Protocol
     */
    function _deployProtocol(
        DeploymentConfig memory config
    ) internal returns (DeployedContracts memory contracts) {
        console.log("=== Deploying Blueprint Protocol ===");

        // 1. Deploy implementation contracts
        console.log("1. Deploying implementation contracts...");
        contracts.creatorCoinImplementation = address(new CreatorCoin());
        contracts.buybackEscrowImplementation = address(
            new BlueprintBuybackEscrow()
        );
        contracts.rewardPoolImplementation = address(new BlueprintRewardPool());

        console.log(
            "   Creator Coin Implementation:",
            contracts.creatorCoinImplementation
        );
        console.log(
            "   Buyback Escrow Implementation:",
            contracts.buybackEscrowImplementation
        );
        console.log(
            "   Reward Pool Implementation:",
            contracts.rewardPoolImplementation
        );

        // 2. Mine and deploy hook with proper flags
        console.log("2. Mining and deploying hook...");
        // Need BEFORE_INITIALIZE_FLAG, BEFORE_SWAP_FLAG and AFTER_SWAP_FLAG for Blueprint Protocol
        uint160 hookFlags = uint160(
            Hooks.BEFORE_INITIALIZE_FLAG | // bit 0 - to enforce dynamic fees
                Hooks.BEFORE_SWAP_FLAG | // bit 6 - to set dynamic fees
                Hooks.AFTER_SWAP_FLAG // bit 7 - to collect and distribute fees
        );

        (address hookAddress, bytes32 salt) = HookMiner.find(
            address(this),
            hookFlags,
            type(BlueprintProtocolHook).creationCode,
            abi.encode(config.poolManager)
        );

        contracts.hookImplementation = address(
            new BlueprintProtocolHook{salt: salt}(
                IPoolManager(config.poolManager)
            )
        );

        console.log("   Hook Implementation:", contracts.hookImplementation);
        console.log("   Hook Salt:", vm.toString(salt));

        // 3. Deploy factory implementation
        console.log("3. Deploying factory implementation...");
        contracts.factoryImplementation = address(new BlueprintFactory());
        console.log(
            "   Factory Implementation:",
            contracts.factoryImplementation
        );

        // 4. Deploy factory proxy
        console.log("4. Deploying factory proxy...");
        bytes memory factoryInitData = abi.encodeCall(
            BlueprintFactory.initialize,
            (
                IPoolManager(config.poolManager),
                config.admin,
                config.treasury,
                config.nativeToken,
                contracts.creatorCoinImplementation,
                contracts.hookImplementation,
                contracts.buybackEscrowImplementation,
                contracts.rewardPoolImplementation
            )
        );

        contracts.factoryProxy = address(
            new ERC1967Proxy(contracts.factoryImplementation, factoryInitData)
        );
        console.log("   Factory Proxy:", contracts.factoryProxy);

        // 5. Initialize hook with factory address
        console.log("5. Initializing hook...");
        BlueprintProtocolHook hook = BlueprintProtocolHook(
            payable(contracts.hookImplementation)
        );

        // Initialize hook with admin, but factory needs network initialization permissions
        hook.initialize(config.admin, contracts.factoryProxy);

        // Grant the factory DEFAULT_ADMIN_ROLE so it can initialize the network
        hook.grantRole(hook.DEFAULT_ADMIN_ROLE(), contracts.factoryProxy);

        console.log("   Hook initialized with factory");
        console.log("   Factory granted DEFAULT_ADMIN_ROLE on hook");

        // 6. Initialize Blueprint Network (this handles everything!)
        console.log(
            "6. Initializing Blueprint Network with anti-dump distribution..."
        );
        console.log("   This will:");
        console.log("   - Deploy and initialize all proxy contracts");
        console.log("   - Create Blueprint token with 75/25 distribution");
        console.log("   - Create ETH/BP pool with proper liquidity");
        console.log("   - Set up all contract relationships");

        BlueprintFactory(contracts.factoryProxy).initializeBlueprintNetwork(
            config.admin // governance address
        );

        // Get the deployed Blueprint token address
        contracts.blueprintToken = BlueprintFactory(contracts.factoryProxy)
            .blueprintToken();

        console.log("   Blueprint Network initialized successfully");
        console.log("   Blueprint Token:", contracts.blueprintToken);
        console.log(
            "   Anti-dump distribution: 75%% buyback escrow, 25%% pool liquidity"
        );

        // 7. Update fee configuration
        console.log("7. Setting fee configuration...");
        BlueprintFactory(contracts.factoryProxy).updateFeeConfiguration(
            config.feeConfig
        );
        console.log("   Fee configuration set");

        console.log("=== Blueprint Protocol Deployment Complete ===");
    }

    /**
     * @notice Load deployment configuration
     */
    function _loadConfig()
        internal
        view
        returns (DeploymentConfig memory config)
    {
        // Load from environment variables with realistic defaults

        config.poolManager = vm.envOr("POOL_MANAGER", address(0));
        config.nativeToken = vm.envOr("NATIVE_TOKEN", address(0)); // Use address(0) for native ETH
        config.admin = vm.envOr("ADMIN", msg.sender);
        config.treasury = vm.envOr("BP_TREASURY", msg.sender);

        // Blueprint token configuration (handled internally by initializeBlueprintNetwork)
        config.blueprintName = "Blueprint Protocol"; // Fixed internally
        config.blueprintSymbol = "BP"; // Fixed internally
        config.blueprintMetadataURI = ""; // Fixed internally
        config.blueprintInitialSupply = 10000000000 * 10 ** 18; // 10B tokens (fixed internally)

        // Realistic fee configuration: 1% total fees split 60/20/10/10
        // Note: In Uniswap V4, 3000 = 0.3%, so we need to scale appropriately
        // For 1% total: 10000 = 1%, split as 60/20/10/10
        config.feeConfig = IBlueprintProtocol.FeeConfiguration({
            buybackFee: 6000, // 0.6% to buyback (6000 = 0.6%)
            creatorFee: 2000, // 0.2% to creator (2000 = 0.2%)
            bpTreasuryFee: 1000, // 0.1% to BP treasury (1000 = 0.1%)
            rewardPoolFee: 1000, // 0.1% to reward pool (1000 = 0.1%)
            active: true
        });

        // Validate critical addresses
        require(
            config.poolManager != address(0),
            "PoolManager address required"
        );
        require(config.admin != address(0), "Admin address required");
        require(config.treasury != address(0), "BP Treasury address required");

        // Validate fee configuration (total should be reasonable)
        uint256 totalFees = config.feeConfig.buybackFee +
            config.feeConfig.creatorFee +
            config.feeConfig.bpTreasuryFee +
            config.feeConfig.rewardPoolFee;
        require(totalFees <= 10_000, "Total fees cannot exceed 1%"); // Max 1% total fees
        require(totalFees > 0, "Total fees must be greater than 0");

        console.log("Configuration loaded:");
        console.log(
            "  Total Fees: %s basis points (%.2f%%)",
            totalFees,
            (totalFees * 100) / 10000
        );
        console.log(
            "  Native Token: %s",
            config.nativeToken == address(0)
                ? "Native ETH"
                : vm.toString(config.nativeToken)
        );
        console.log("  Blueprint Token Supply: 10B BP tokens (fixed)");
        console.log("  Treasury Allocation (75%%): 7.5B BP tokens");
        console.log("  Admin Allocation (25%%): 2.5B BP tokens");
    }

    /**
     * @notice Log deployment results
     */
    function _logDeployment(
        DeployedContracts memory contracts,
        DeploymentConfig memory config
    ) internal view {
        console.log("\n=== DEPLOYMENT SUMMARY ===");
        console.log(
            "Network: %s (Chain ID: %s)",
            _getNetworkName(),
            vm.toString(block.chainid)
        );
        console.log("");
        console.log("Core Contracts:");
        console.log("  Factory Proxy:              %s", contracts.factoryProxy);
        console.log(
            "  Factory Implementation:     %s",
            contracts.factoryImplementation
        );
        console.log(
            "  Hook Implementation:        %s",
            contracts.hookImplementation
        );
        console.log("");
        console.log("Implementation Contracts:");
        console.log(
            "  Creator Coin Implementation: %s",
            contracts.creatorCoinImplementation
        );
        console.log(
            "  Buyback Escrow Implementation: %s",
            contracts.buybackEscrowImplementation
        );
        console.log(
            "  Reward Pool Implementation: %s",
            contracts.rewardPoolImplementation
        );
        console.log("");
        console.log("Blueprint Token:");
        console.log("  Address:     %s", contracts.blueprintToken);
        console.log("  Name:        %s", config.blueprintName);
        console.log("  Symbol:      %s", config.blueprintSymbol);
        console.log("  Metadata:    %s", config.blueprintMetadataURI);
        console.log("  Total Supply: 10B BP tokens");

        console.log("");
        console.log("Blueprint Token Distribution (Anti-Dump):");
        console.log("  Buyback Escrow (75%%): 7.5B BP tokens");
        console.log("  Pool Liquidity (25%%): 2.5B BP tokens");
        console.log("");
        console.log("Fee Configuration (basis points):");
        console.log(
            "  Buyback Fee:     %s (%.2f%%)",
            config.feeConfig.buybackFee,
            (config.feeConfig.buybackFee * 100) / 10000
        );
        console.log(
            "  Creator Fee:     %s (%.2f%%)",
            config.feeConfig.creatorFee,
            (config.feeConfig.creatorFee * 100) / 10000
        );
        console.log(
            "  BP Treasury Fee: %s (%.2f%%)",
            config.feeConfig.bpTreasuryFee,
            (config.feeConfig.bpTreasuryFee * 100) / 10000
        );
        console.log(
            "  Reward Pool Fee: %s (%.2f%%)",
            config.feeConfig.rewardPoolFee,
            (config.feeConfig.rewardPoolFee * 100) / 10000
        );
        uint256 totalFees = config.feeConfig.buybackFee +
            config.feeConfig.creatorFee +
            config.feeConfig.bpTreasuryFee +
            config.feeConfig.rewardPoolFee;
        console.log(
            "  Total Fees:      %s (%.2f%%)",
            totalFees,
            (totalFees * 100) / 10000
        );
        console.log("==============================\n");

        console.log("Next steps:");
        console.log("1. Verify contracts on block explorer");
        console.log(
            "2. Create first Blueprint creator coin (with 75/25 distribution)"
        );
        console.log("3. Test ETH -> Creator routing");
        console.log("4. Set up reward pools for creators");
        console.log("5. Configure buyback automation");
        console.log(
            "6. Note: 75%% of BP tokens are in buyback escrow for anti-dump protection"
        );
    }

    /**
     * @notice Get network name for display
     */
    function _getNetworkName() internal view returns (string memory) {
        uint256 chainId = block.chainid;
        if (chainId == 1) return "Ethereum Mainnet";
        if (chainId == 8453) return "Base Mainnet";
        if (chainId == 84532) return "Base Sepolia";
        if (chainId == 31337) return "Local/Anvil";
        if (chainId == 11155111) return "Sepolia";
        return "Unknown Network";
    }

    /**
     * @notice Save deployment addresses to file
     */
    function _saveDeployment(DeployedContracts memory contracts) internal {
        string memory deploymentJson = string.concat(
            "{\n",
            '  "network": "',
            _getNetworkName(),
            '",\n',
            '  "chainId": "',
            vm.toString(block.chainid),
            '",\n',
            '  "timestamp": "',
            vm.toString(block.timestamp),
            '",\n',
            '  "factoryProxy": "',
            vm.toString(contracts.factoryProxy),
            '",\n',
            '  "factoryImplementation": "',
            vm.toString(contracts.factoryImplementation),
            '",\n',
            '  "hookImplementation": "',
            vm.toString(contracts.hookImplementation),
            '",\n',
            '  "creatorCoinImplementation": "',
            vm.toString(contracts.creatorCoinImplementation),
            '",\n',
            '  "buybackEscrowImplementation": "',
            vm.toString(contracts.buybackEscrowImplementation),
            '",\n',
            '  "rewardPoolImplementation": "',
            vm.toString(contracts.rewardPoolImplementation),
            '",\n',
            '  "blueprintToken": "',
            vm.toString(contracts.blueprintToken),
            '"\n',
            "}"
        );

        string memory outputPath = string.concat(
            "./deployments/blueprint-protocol-",
            vm.toString(block.chainid),
            ".json"
        );
        vm.writeFile(outputPath, deploymentJson);
        console.log("Deployment saved to: %s", outputPath);
    }
}
