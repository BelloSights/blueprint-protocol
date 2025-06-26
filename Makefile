# Environment file selection
ENV_FILE := .env
ifeq ($(findstring --network local,$(ARGS)),--network local)
ENV_FILE := .env.test
endif

# Load environment variables
-include $(ENV_FILE)

.PHONY: install build test coverage test_blueprint_protocol_hook test_all_hooks test_blueprint_all deploy help network-info

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

# Ink Mainnet
ifeq ($(findstring --network ink,$(ARGS)),--network ink)
	NETWORK_ARGS := --rpc-url $(INK_MAINNET_RPC) --private-key $(PRIVATE_KEY) --broadcast -vvvv
endif

# Ink Sepolia Testnet
ifeq ($(findstring --network ink_sepolia,$(ARGS)),--network ink_sepolia)
	NETWORK_ARGS := --rpc-url $(INK_SEPOLIA_RPC) --private-key $(PRIVATE_KEY) --broadcast -vvvv
endif

# Unichain Mainnet
ifeq ($(findstring --network unichain,$(ARGS)),--network unichain)
	NETWORK_ARGS := --rpc-url $(UNICHAIN_MAINNET_RPC) --private-key $(PRIVATE_KEY) --broadcast -vvvv
endif

# Unichain Sepolia Testnet
ifeq ($(findstring --network unichain_sepolia,$(ARGS)),--network unichain_sepolia)
	NETWORK_ARGS := --rpc-url $(UNICHAIN_SEPOLIA_RPC) --private-key $(PRIVATE_KEY) --broadcast -vvvv
endif

# Local network
ifeq ($(findstring --network local,$(ARGS)),--network local)
	NETWORK_ARGS := --rpc-url http://localhost:8545 --private-key $(PRIVATE_KEY) --broadcast -vvvv
endif

# Add unsafe flag if specified
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

# Core Blueprint Protocol tests
test_blueprint_protocol_hook:
	@echo "Running BlueprintProtocolHook tests..."
	@source .env.test && forge test --match-contract BlueprintProtocolHookTest -vvvv --ffi

test_blueprint_all:
	@echo "Running all Blueprint tests..."
	@source .env.test && forge test --match-contract "ArchitectureVerificationTest|BlueprintBuybackEscrowTest|BlueprintFactoryTest|BlueprintProtocolTest|BlueprintRewardPoolTest" -vvvv --ffi

test_all_hooks:
	@echo "Running all hook tests..."
	@source .env.test && forge test --match-path "test/hooks/*" -vvvv --ffi

# Deployment
deploy:
	@echo "Deploying Blueprint Protocol..."
	@source $(ENV_FILE) && forge script script/DeployBlueprintProtocol.s.sol:DeployBlueprintProtocol $(NETWORK_ARGS) --ffi --via-ir

# Network information
network-info:
	@echo "Available Networks:"
	@echo "=================="
	@echo ""
	@echo "LOCAL DEVELOPMENT:"
	@echo "  --network local              - Local development (localhost:8545)"
	@echo ""
	@echo "BASE NETWORKS:"
	@echo "  --network base               - Base Mainnet (Chain ID: 8453)"
	@echo "  --network base_sepolia       - Base Sepolia Testnet (Chain ID: 84532)"
	@echo ""
	@echo "INK NETWORKS:"
	@echo "  --network ink                - Ink Mainnet (Chain ID: 57073)"
	@echo "  --network ink_sepolia        - Ink Sepolia Testnet (Chain ID: 763373)"
	@echo ""
	@echo "UNICHAIN NETWORKS:"
	@echo "  --network unichain           - Unichain Mainnet (Chain ID: 130)"
	@echo "  --network unichain_sepolia   - Unichain Sepolia Testnet (Chain ID: 1301)"
	@echo ""
	@echo "Required Environment Variables:"
	@echo "  INK_MAINNET_RPC=https://rpc-gel.inkonchain.com"
	@echo "  INK_SEPOLIA_RPC=https://rpc-gel-sepolia.inkonchain.com"
	@echo "  UNICHAIN_MAINNET_RPC=https://mainnet.unichain.org"
	@echo "  UNICHAIN_SEPOLIA_RPC=https://sepolia.unichain.org"
	@echo ""
	@echo "Block Explorers:"
	@echo "  Ink Mainnet: https://explorer.inkonchain.com"
	@echo "  Ink Sepolia: https://explorer-sepolia.inkonchain.com"
	@echo "  Unichain Mainnet: https://uniscan.xyz"
	@echo "  Unichain Sepolia: https://sepolia.uniscan.xyz"

# Help
help:
	@echo "Blueprint Protocol Project - Available Commands"
	@echo "=============================================="
	@echo ""
	@echo "BASIC COMMANDS:"
	@echo "  make install              - Install dependencies"
	@echo "  make build                - Build all contracts"
	@echo "  make test                 - Run all tests"
	@echo "  make coverage             - Generate coverage report"
	@echo ""
	@echo "SPECIFIC TESTS:"
	@echo "  make test_blueprint_protocol_hook - Run BlueprintProtocolHook tests"
	@echo "  make test_blueprint_factory      - Run BlueprintFactory tests"
	@echo ""
	@echo "DEPLOYMENT:"
	@echo "  make deploy                      - Deploy Blueprint Protocol"
	@echo "  make network-info                - Show available networks and configuration"
	@echo ""
	@echo "NETWORK FLAGS:"
	@echo "  --network local                  - Local development network"
	@echo "  --network base_sepolia           - Base Sepolia testnet"
	@echo "  --network base                   - Base mainnet"
	@echo "  --network ink_sepolia            - Ink Sepolia testnet"
	@echo "  --network ink                    - Ink mainnet"
	@echo "  --network unichain               - Unichain mainnet"
	@echo "  --network unichain_sepolia       - Unichain sepolia testnet"
	@echo ""
	@echo "EXAMPLES:"
	@echo "  make test_blueprint_protocol_hook"
	@echo "  make test_all_hooks"
	@echo "  make deploy --network base_sepolia"
	@echo "  make deploy --network ink_sepolia"
	@echo "  make deploy --network ink"
	@echo "  make deploy --network unichain_sepolia"
	@echo "  make deploy --network unichain"
	@echo "  make network-info"