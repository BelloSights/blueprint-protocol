# Environment file selection
ENV_FILE := .env
ifeq ($(findstring --network local,$(ARGS)),--network local)
ENV_FILE := .env.test
endif

# Load environment variables
-include $(ENV_FILE)

.PHONY: install build test coverage test_blueprint_compilation test_blueprint_network test_blueprint_hook test_blueprint_factory test_buyback_escrow test_upgradeable test_blueprint_all test_blueprint_comprehensive test_blueprint_v2 test_reward_pool deploy_blueprint_factory deploy_blueprint_hook deploy_buyback_escrow deploy_blueprint_network deploy_blueprint_network_local deploy_all_blueprint upgrade_blueprint_factory upgrade_blueprint_hook upgrade_buyback_escrow upgrade_blueprint_network verify_blueprint_factory verify_blueprint_hook verify_buyback_escrow verify_blueprint_network verify_blueprint_factory_base_sepolia verify_blueprint_hook_base_sepolia verify_buyback_escrow_base_sepolia verify_blueprint_network_base_sepolia help_blueprint help

DEFAULT_ANVIL_PRIVATE_KEY := 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80

NETWORK_ARGS := --rpc-url http://localhost:8545 --private-key $(DEFAULT_ANVIL_PRIVATE_KEY) --broadcast

# Base Mainnet
ifeq ($(findstring --network base,$(ARGS)),--network base)
	NETWORK_ARGS := --rpc-url $(BASE_MAINNET_RPC) --private-key $(PRIVATE_KEY) --broadcast -vvvv
endif

# Base Sepolia
ifeq ($(findstring --network base_sepolia,$(ARGS)),--network base_sepolia)
	NETWORK_ARGS := --rpc-url $(BASE_SEPOLIA_RPC) --private-key $(PRIVATE_KEY) --broadcast -vvvv
endif

# Cyber Testnet
ifeq ($(findstring --network cyber_testnet,$(ARGS)),--network cyber_testnet)
	NETWORK_ARGS := --rpc-url $(CYBER_TESTNET_RPC) --private-key $(PRIVATE_KEY) --broadcast -vvvv
endif

# Cyber Mainnet 
ifeq ($(findstring --network cyber,$(ARGS)),--network cyber)
	NETWORK_ARGS := --rpc-url $(CYBER_MAINNET_RPC) --private-key $(PRIVATE_KEY) --broadcast -vvvv
endif

# Zero Network
ifeq ($(findstring --network zero,$(ARGS)),--network zero)
	NETWORK_ARGS := --rpc-url https://rpc.zerion.io/v1/zero --private-key $(PRIVATE_KEY) --broadcast --chain 543210 --zksync -vvvv
endif

# Local network
ifeq ($(findstring --network local,$(ARGS)),--network local)
	NETWORK_ARGS := --rpc-url http://localhost:8545 --private-key $(PRIVATE_KEY) --broadcast -vvvv
endif

# Add to NETWORK_ARGS handling
ifeq ($(findstring --unsafe,$(ARGS)),--unsafe)
	NETWORK_ARGS += --unsafe
endif

# Basic commands
install:; forge install
build:; forge build

test:
	@source .env.test && forge clean && forge test -vvvv --ffi

test-coverage:
	@source .env.test && forge coverage --ffi

coverage :; forge coverage --ffi --report debug > coverage-report.txt
snapshot :; forge snapshot --ffi

# Blueprint Protocol specific tests
test_blueprint_compilation:
	@echo "Testing Blueprint Protocol contract compilation..."
	@source .env.test && forge build --force --via-ir

test_blueprint_network:
	@echo "Running Blueprint Protocol system tests..."
	@source .env.test && forge test --match-contract BlueprintNetworkTest -vvvv --ffi



test_blueprint_hook:
	@echo "Running BlueprintNetworkHook tests..."
	@source .env.test && forge test --match-contract BlueprintNetworkHookTest -vvvv --ffi

test_blueprint_factory:
	@echo "Running BlueprintFactory tests..."
	@source .env.test && forge test --match-contract BlueprintFactoryTest -vvvv --ffi

test_buyback_escrow:
	@echo "Running BlueprintBuybackEscrow tests..."
	@source .env.test && forge test --match-contract BlueprintBuybackEscrowTest -vvvv --ffi

test_upgradeable:
	@echo "Running upgradeable Blueprint Protocol tests..."
	@source .env.test && forge test --match-contract UpgradeableBlueprintNetworkTest -vvvv --ffi

test_blueprint_all:
	@echo "Running ALL Blueprint Protocol tests..."
	@source .env.test && forge test --match-contract "BlueprintFactoryTest|BlueprintBuybackEscrowTest|BlueprintRewardPoolTest" -vvvv --ffi

test_blueprint_comprehensive:
	@echo "Running comprehensive Blueprint Protocol tests (all Blueprint files)..."
	@source .env.test && forge test --match-path "*Blueprint*" -vvvv --ffi

test_blueprint_v2:
	@echo "Running Blueprint Protocol V2 comprehensive tests..."
	@source .env.test && forge test --match-contract BlueprintProtocolV2ComprehensiveTest -vvvv --ffi

test_blueprint_core:
	@echo "Running core Blueprint Protocol tests..."
	@source .env.test && forge test --match-contract "BlueprintFactoryTest|BlueprintNetworkHookTest" -vvvv --ffi

test_reward_pool:
	@echo "Running BlueprintRewardPool tests..."
	@source .env.test && forge test --match-contract BlueprintRewardPoolTest -vvvv --ffi

# Blueprint Protocol deployment commands
deploy_blueprint_factory:
	@echo "Deploying Blueprint Factory (upgradeable)..."
	@source $(ENV_FILE) && forge script script/DeployBlueprintFactory.s.sol:DeployBlueprintFactory $(NETWORK_ARGS) --ffi --via-ir

deploy_blueprint_hook:
	@echo "Deploying Blueprint Protocol Hook (upgradeable)..."
	@source $(ENV_FILE) && forge script script/DeployBlueprintHook.s.sol:DeployBlueprintHook $(NETWORK_ARGS) --ffi --via-ir

deploy_buyback_escrow:
	@echo "Deploying Buyback Escrow (upgradeable)..."
	@source $(ENV_FILE) && forge script script/DeployBuybackEscrow.s.sol:DeployBuybackEscrow $(NETWORK_ARGS) --ffi --via-ir

deploy_blueprint_network: deploy_blueprint_factory deploy_blueprint_hook deploy_buyback_escrow
	@echo "Deploying complete Blueprint Protocol system..."
	@source $(ENV_FILE) && forge script script/DeployBlueprintNetwork.s.sol:DeployBlueprintNetwork $(NETWORK_ARGS) --ffi --via-ir
	@echo "Blueprint Protocol deployment completed!"

deploy_blueprint_network_local:
	@echo "Deploying Blueprint Protocol to local network..."
	@source .env.test && forge script script/DeployBlueprintNetwork.s.sol:DeployBlueprintNetwork \
		--rpc-url http://localhost:8545 \
		--private-key $(DEFAULT_ANVIL_PRIVATE_KEY) \
		--broadcast \
		--ffi \
		--via-ir \
		-vvvv

deploy_all_blueprint: deploy_blueprint_network
	@echo "Complete Blueprint Protocol deployment finished!"

# Blueprint Protocol upgrade commands
upgrade_blueprint_factory:
	@echo "Upgrading Blueprint Factory..."
	@source $(ENV_FILE) && forge script script/UpgradeBlueprintFactory.s.sol:UpgradeBlueprintFactory $(NETWORK_ARGS) \
		--ffi \
		--via-ir \
		--sig "run()"

upgrade_blueprint_hook:
	@echo "Upgrading Blueprint Protocol Hook..."
	@source $(ENV_FILE) && forge script script/UpgradeBlueprintHook.s.sol:UpgradeBlueprintHook $(NETWORK_ARGS) \
		--ffi \
		--via-ir \
		--sig "run()"

upgrade_buyback_escrow:
	@echo "Upgrading Buyback Escrow..."
	@source $(ENV_FILE) && forge script script/UpgradeBuybackEscrow.s.sol:UpgradeBuybackEscrow $(NETWORK_ARGS) \
		--ffi \
		--via-ir \
		--sig "run()"

upgrade_blueprint_network: upgrade_blueprint_factory upgrade_blueprint_hook upgrade_buyback_escrow
	@echo "All Blueprint Protocol contracts upgraded successfully!"

# Blueprint Protocol verification commands
verify_blueprint_factory:
	@if [ -z "${BLUEPRINT_FACTORY_ADDRESS}" ]; then \
		echo "Usage: make verify_blueprint_factory BLUEPRINT_FACTORY_ADDRESS=0x..."; \
		exit 1; \
	fi
	@echo "Verifying Blueprint Factory implementation..."
	@forge verify-contract \
		${BLUEPRINT_FACTORY_ADDRESS} \
		"src/contracts/BlueprintFactory.sol:BlueprintFactory" \
		--chain-id ${CHAIN_ID} \
		--verifier etherscan \
		--etherscan-api-key ${ETHERSCAN_API_KEY} \
		--watch

verify_blueprint_hook:
	@if [ -z "${BLUEPRINT_HOOK_ADDRESS}" ]; then \
		echo "Usage: make verify_blueprint_hook BLUEPRINT_HOOK_ADDRESS=0x..."; \
		exit 1; \
	fi
	@echo "Verifying Blueprint Protocol Hook implementation..."
	@forge verify-contract \
		${BLUEPRINT_HOOK_ADDRESS} \
		"src/contracts/hooks/BlueprintNetworkHook.sol:BlueprintNetworkHook" \
		--chain-id ${CHAIN_ID} \
		--verifier etherscan \
		--etherscan-api-key ${ETHERSCAN_API_KEY} \
		--watch

verify_buyback_escrow:
	@if [ -z "${BUYBACK_ESCROW_ADDRESS}" ]; then \
		echo "Usage: make verify_buyback_escrow BUYBACK_ESCROW_ADDRESS=0x..."; \
		exit 1; \
	fi
	@echo "Verifying Buyback Escrow implementation..."
	@forge verify-contract \
		${BUYBACK_ESCROW_ADDRESS} \
		"src/contracts/escrows/BlueprintBuybackEscrow.sol:BlueprintBuybackEscrow" \
		--chain-id ${CHAIN_ID} \
		--verifier etherscan \
		--etherscan-api-key ${ETHERSCAN_API_KEY} \
		--watch

verify_blueprint_network: verify_blueprint_factory verify_blueprint_hook verify_buyback_escrow
	@echo "All Blueprint Protocol contracts verified successfully!"

# Network-specific Blueprint Protocol verification commands
verify_blueprint_factory_base_sepolia:
	@if [ -z "${BLUEPRINT_FACTORY_ADDRESS}" ]; then \
		echo "Usage: make verify_blueprint_factory_base_sepolia BLUEPRINT_FACTORY_ADDRESS=0x..."; \
		exit 1; \
	fi
	@forge verify-contract \
		${BLUEPRINT_FACTORY_ADDRESS} \
		"src/contracts/BlueprintFactory.sol:BlueprintFactory" \
		--chain-id 84532 \
		--etherscan-api-key ${BASESCAN_API_KEY} \
		--rpc-url ${BASE_SEPOLIA_RPC} \
		--watch

verify_blueprint_hook_base_sepolia:
	@if [ -z "${BLUEPRINT_HOOK_ADDRESS}" ]; then \
		echo "Usage: make verify_blueprint_hook_base_sepolia BLUEPRINT_HOOK_ADDRESS=0x..."; \
		exit 1; \
	fi
	@forge verify-contract \
		${BLUEPRINT_HOOK_ADDRESS} \
		"src/contracts/hooks/BlueprintNetworkHook.sol:BlueprintNetworkHook" \
		--chain-id 84532 \
		--etherscan-api-key ${BASESCAN_API_KEY} \
		--rpc-url ${BASE_SEPOLIA_RPC} \
		--watch

verify_buyback_escrow_base_sepolia:
	@if [ -z "${BUYBACK_ESCROW_ADDRESS}" ]; then \
		echo "Usage: make verify_buyback_escrow_base_sepolia BUYBACK_ESCROW_ADDRESS=0x..."; \
		exit 1; \
	fi
	@forge verify-contract \
		${BUYBACK_ESCROW_ADDRESS} \
		"src/contracts/escrows/BlueprintBuybackEscrow.sol:BlueprintBuybackEscrow" \
		--chain-id 84532 \
		--etherscan-api-key ${BASESCAN_API_KEY} \
		--rpc-url ${BASE_SEPOLIA_RPC} \
		--watch

verify_blueprint_network_base_sepolia: verify_blueprint_factory_base_sepolia verify_blueprint_hook_base_sepolia verify_buyback_escrow_base_sepolia
	@echo "All Blueprint Protocol contracts verified on Base Sepolia successfully!"

# Help commands
help_blueprint:
	@echo "Blueprint Protocol Commands:"
	@echo ""
	@echo "TESTING:"
	@echo "  make test_blueprint_compilation  - Test contract compilation"
	@echo "  make test_blueprint_network      - Run Blueprint Protocol tests"

	@echo "  make test_blueprint_hook         - Run BlueprintNetworkHook tests"
	@echo "  make test_blueprint_factory      - Run BlueprintFactory tests"
	@echo "  make test_buyback_escrow         - Run BlueprintBuybackEscrow tests"
	@echo "  make test_upgradeable           - Run upgradeable functionality tests"
	@echo "  make test_blueprint_all         - Run all Blueprint Protocol tests"
	@echo "  make test_blueprint_comprehensive - Run ALL Blueprint-related test files"
	@echo "  make test_blueprint_v2          - Run Blueprint Protocol V2 comprehensive tests"
	@echo "  make test_blueprint_core        - Run core Blueprint functionality tests"
	@echo "  make test_reward_pool           - Run BlueprintRewardPool tests"
	@echo ""
	@echo "DEPLOYMENT:"
	@echo "  make deploy_blueprint_factory   - Deploy Blueprint Factory (upgradeable)"
	@echo "  make deploy_blueprint_hook      - Deploy Blueprint Protocol Hook (upgradeable)"
	@echo "  make deploy_buyback_escrow      - Deploy Buyback Escrow (upgradeable)"
	@echo "  make deploy_blueprint_network   - Deploy complete Blueprint Protocol system"
	@echo "  make deploy_blueprint_network_local - Deploy to local network"
	@echo "  make deploy_all_blueprint       - Deploy everything Blueprint related"
	@echo ""
	@echo "UPGRADES:"
	@echo "  make upgrade_blueprint_factory  - Upgrade Blueprint Factory"
	@echo "  make upgrade_blueprint_hook     - Upgrade Blueprint Protocol Hook"
	@echo "  make upgrade_buyback_escrow     - Upgrade Buyback Escrow"
	@echo "  make upgrade_blueprint_network  - Upgrade all Blueprint contracts"
	@echo ""
	@echo "VERIFICATION:"
	@echo "  make verify_blueprint_factory BLUEPRINT_FACTORY_ADDRESS=0x..."
	@echo "  make verify_blueprint_hook BLUEPRINT_HOOK_ADDRESS=0x..."
	@echo "  make verify_buyback_escrow BUYBACK_ESCROW_ADDRESS=0x..."
	@echo "  make verify_blueprint_network   - Verify all contracts"
	@echo "  make verify_blueprint_network_base_sepolia - Verify on Base Sepolia"
	@echo ""
	@echo "NETWORK FLAGS:"
	@echo "  --network local          - Local development network"
	@echo "  --network base_sepolia   - Base Sepolia testnet"
	@echo "  --network base           - Base mainnet"
	@echo "  --network cyber_testnet  - Cyber testnet"
	@echo "  --network cyber          - Cyber mainnet"
	@echo "  --network zero           - Zero Network"
	@echo ""
	@echo "EXAMPLES:"
	@echo "  make test_blueprint_all"
	@echo "  make test_reward_pool"
	@echo "  make deploy_blueprint_network --network base_sepolia"
	@echo "  make verify_blueprint_factory BLUEPRINT_FACTORY_ADDRESS=0x123... --network base_sepolia"
	@echo "  make upgrade_blueprint_network --network base"

help:
	@echo "Blueprint Protocol Project - Available Commands"
	@echo "=============================================="
	@echo ""
	@echo "BASIC COMMANDS:"
	@echo "  make install        - Install dependencies"
	@echo "  make build          - Build all contracts"
	@echo "  make test           - Run all tests"
	@echo "  make coverage       - Generate coverage report"
	@echo ""
	@echo "BLUEPRINT NETWORK:"
	@echo "  make help_blueprint - Show detailed Blueprint Protocol commands"
	@echo "  make test_blueprint_all - Run all Blueprint Protocol tests"
	@echo "  make test_blueprint_comprehensive - Run ALL Blueprint-related test files"
	@echo "  make test_blueprint_v2 - Run Blueprint Protocol V2 comprehensive tests"
	@echo "  make deploy_blueprint_network - Deploy Blueprint Protocol system"
	@echo ""
	@echo "For detailed Blueprint Protocol commands, run: make help_blueprint"