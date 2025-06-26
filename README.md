<p align="center">
  <br>
  <a href="https://bp.fun" target="_blank">
    <img width="300" height="100" src="./assets/blueprint.png" alt="Blueprint Logo">
  </a>
  <br><br>
</p>

[![Twitter](https://img.shields.io/twitter/follow/bpdotfun?color=blue&style=flat-square)](https://twitter.com/bpdotfun)
[![LICENSE](https://img.shields.io/badge/license-Apache--2.0-blue?logo=apache)](./LICENSE)

# Blueprint Protocol Contracts

This repository contains smart contracts that power the Blueprint Protocol ecosystem. The protocol enables automated creator coin launches paired with BP network token, featuring dynamic fee distribution, automated buyback mechanisms, and reward pools for sustainable creator economies. The contracts include:

- **Blueprint Protocol Factory** – Core contract for creator coin launches and pool management
- **Blueprint Protocol Hook** – Uniswap V4 hook for dynamic fee management and cross-pool swapping
- **Buyback Escrow** – Automated buyback mechanisms for market stabilization
- **Reward Pool** – Incentive distribution system for swap participants

---

## Table of Contents

- [Overview](#overview)
- [Smart Contract Details](#smart-contract-details)
  - [Core Contracts](#core-contracts)
  - [Fee Management](#fee-management)
  - [Liquidity & Trading](#liquidity--trading)
- [Protocol Architecture](#protocol-architecture)
- [Contract Addresses](#contract-addresses)
- [Setup and Installation](#setup-and-installation)
- [Deployment](#deployment)
- [Testing](#testing)
- [SDK](#sdk)
- [Future Plans](#future-plans)
- [Troubleshooting](#troubleshooting)
- [License](#license)

---

## Overview

Blueprint Protocol's smart contract suite enables automated creator coin launches with sophisticated liquidity management and fee distribution. Built on Uniswap V4, the protocol features hook-based architecture that automatically manages fees, liquidity, and trading mechanics across creator coin ecosystems.

**Key Features:**
- **Creator Coin Launches** – Automated launches paired with BP network token
- **Dynamic Fee Management** – 1% flat fee across all Blueprint Protocol pools
- **Automated Fee Distribution** – 60% rewards, 20% creator, 10% buyback, 10% treasury
- **Cross-Pool Swapping** – ETH ↔ BP ↔ Creator coin routing with optimal paths
- **Buyback Mechanisms** – Automated market stabilization and growth promotion

---

## Smart Contract Details

### Core Contracts

#### Blueprint Protocol Factory
- **Purpose:**  
  Core contract for creator coin launches and pool management, handling deployment of buyback escrows and reward pools.
- **Key Features:**
  - Creator coin launch management paired with BP token
  - Buyback escrow deployment and configuration
  - Reward pool creation and management
  - Integration with Blueprint Protocol Hook for fee routing
- **File:** [BlueprintFactory.sol](./src/contracts/BlueprintFactory.sol)

#### Blueprint Protocol Hook
- **Purpose:**  
  Uniswap V4 hook that handles dynamic fee management, cross-pool swapping, and fee distribution across creator coin ecosystems.
- **Key Features:**
  - Dynamic fee enforcement (1% flat fee across all pools)
  - ETH ↔ BP ↔ Creator coin swap routing
  - Cross-pool swap optimization
  - Automated fee distribution to rewards, creators, buyback, and treasury
- **File:** [BlueprintProtocolHook.sol](./src/contracts/hooks/BlueprintProtocolHook.sol)

#### Buyback Escrow
- **Purpose:**  
  Manages automated buyback mechanisms for market stabilization and growth promotion.
- **Key Features:**
  - Automated buyback execution
  - Market stabilization mechanisms
  - Integration with fee distribution system (receives 10% of total fees)
- **File:** [BuybackEscrow.sol](./src/contracts/escrows/BuybackEscrow.sol)

#### Reward Pool
- **Purpose:**  
  Incentive distribution system for swap participants and ecosystem growth.
- **Key Features:**
  - Swap participant reward distribution
  - Incentive mechanism for trading activity
  - Receives 60% of total trading fees for distribution
- **File:** [RewardPool.sol](./src/contracts/rewards/RewardPool.sol)

### Fee Management

The protocol implements a flat 1% fee structure with dynamic enforcement:

- **1% Total Fee** distributed as:
  - **60% to Reward Pool** – Incentivizes swap participation
  - **20% to Creator** – Promotes creator journey and engagement
  - **10% to Buyback Escrow** – Stabilizes and promotes Blueprint Protocol growth
  - **10% to Treasury** – Funds future protocol development

### Liquidity & Trading

- **Cross-Pool Routing** – Optimal swap paths: ETH ↔ BP ↔ Creator coins
- **Dynamic Fee Enforcement** – Consistent 1% fee across all Blueprint Protocol pools
- **Automated Buybacks** – Market stabilization through escrow mechanisms
- **Reward Distribution** – Participant incentives for trading activity

---

## Protocol Architecture

```
Creator Coin Launch Flow:
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   BP Factory    │───▶│  Creator Pool    │───▶│  Buyback Escrow │
│                 │    │  (BP + Creator)  │    │                 │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Reward Pool   │    │ Blueprint Hook   │    │ Fee Distribution│
│                 │    │  (1% Dynamic)    │    │  (60/20/10/10)  │
└─────────────────┘    └──────────────────┘    └─────────────────┘

Swap Routes:
ETH ──────▶ BP ──────▶ Creator Coin A
 │                           │
 └─────▶ Creator Coin B ◀────┘
         (via BP routing)
```

---

### Uniswap V4 Addresses
| Contract              | Base                                         | Base Sepolia                                 |
|-----------------------|----------------------------------------------|----------------------------------------------|
| PoolManager           | `0x498581fF718922c3f8e6A244956aF099B2652b2b` | `0x05E73354cFDd6745C338b50BcFDfA3Aa6fA03408` |
| PositionDescriptor    | `0x176690c5819A05123b3cD80bd4AA2846cD347489` | `0x33E61BCa1cDa979E349Bf14840BD178Cc7d0F55D` |
| ProxyAdmin            | `0x9B95aF8b4C29346722235D74Da8Fc5E9E3232Eb3` | `[Unknown]`                                  |
| PositionManager       | `0x7C5f5A4bBd8fD63184577525326123B519429bDc` | `0x4B2C77d209D3405F41a037Ec6c77F7F5b8e2ca80` |
| Quoter                | `0x0d5e0F971ED27FBfF6c2837bf31316121532048D` | `0x4A6513c898fe1B2d0E78d3b0e0A4a151589B1cBa` |
| StateView             | `0xA3c0c9b65baD0b08107Aa264b0f3dB444b867A71` | `0x571291b572ed32ce6751a2Cb2486EbEe8DEfB9B4` |
| UniversalRouter       | `0x6fF5693b99212Da76ad316178A184AB56D299b43` | `0x492E6456D9528771018DeB9E87ef7750EF184104` |

---

## Setup and Installation

Ensure you have [Foundry](https://book.getfoundry.sh) installed and updated:

```bash
foundryup
```

Clone the repository and install dependencies:

```bash
git clone https://github.com/BelloSights/flaunchgg-contracts.git
cd flaunchgg-contracts
forge install
```

Copy `.env.sample` to `.env` and configure your environment variables:

```bash
cp .env.sample .env
# Edit .env with your configuration
```

Build the contracts:

```bash
make build
```

---

## Deployment

The contracts can be deployed using Forge scripts with the Makefile commands.

### Deploy Blueprint Protocol

```bash
make deploy_blueprint_protocol ARGS="--network base_sepolia"
```

### Deploy Hook System

```bash
make deploy_hook_system ARGS="--network base_sepolia"
```

### Deploy Position Manager

```bash
make deploy_position_manager ARGS="--network base_sepolia"
```

### Verification

For Blueprint Protocol implementation contracts:

```bash
make verify_blueprint_implementation_base_sepolia
```

For hook implementation contracts:

```bash
make verify_hook_implementation_base_sepolia
```

For custom contract verification:

```bash
make verify_base_sepolia ADDRESS=0x... CONTRACT=src/contracts/AnyFlaunch.sol:AnyFlaunch
```

### Local Development

For local development with Anvil:

```bash
anvil
```

In a new terminal, run:

```bash
forge script script/Anvil.s.sol --rpc-url http://localhost:8545 --private-key <ANVIL_PRIVATE_KEY> --broadcast --via-ir
```

---

## Testing

Run the complete test suite:

```bash
make test
```

Run specific test categories:

```bash
# Test Blueprint Protocol hooks
make test_blueprint_protocol_hook

# Test all hooks
make test_all_hooks

# Test position manager
make test_any_position_manager

# Run comprehensive tests
make test_comprehensive
```

Or directly with Forge:

```bash
forge test
```

For verbose output:

```bash
forge test -vvv
```

---

## SDK

The Blueprint Protocol SDK provides TypeScript bindings for seamless integration. 

To generate SDK ABIs:

```bash
jq '.abi' out/BlueprintProtocolHook.sol/BlueprintProtocolHook.json > ../flaunch-sdk/src/abi/BlueprintProtocolHook.ts
jq '.abi' out/BlueprintFactory.sol/BlueprintFactory.json > ../flaunch-sdk/src/abi/BlueprintFactory.ts
jq '.abi' out/BuybackEscrow.sol/BuybackEscrow.json > ../flaunch-sdk/src/abi/BuybackEscrow.ts
jq '.abi' out/RewardPool.sol/RewardPool.json > ../flaunch-sdk/src/abi/RewardPool.ts
```

For more information, see the [Blueprint Protocol SDK](../flaunch-sdk/README.md).

---

## Future Plans

The Blueprint Protocol is continuously evolving to support new features and improvements:

### 1. **Enhanced Cross-Pool Swapping**
- **Creator-to-Creator Swaps** – Direct CREATOR A → BP → CREATOR B routing with optimal swap paths
- **Multi-Hop Optimization** – Advanced routing algorithms for minimal slippage and fees

### 2. **Flaunch Protocol Integration**
- **Unified Launch Platform** – Integration with existing Flaunch Protocol infrastructure
- **Legacy Support** – Backward compatibility with existing Flaunch tokens and mechanisms

### 3. **Decentralized Buyback Infrastructure**
- **EigenLayer Integration** – Leverage EigenLayer to reward users who help stabilize creator coin markets
- **Efficient Buyback Mechanisms** – Decentralized buyback execution for improved low market cap efficiency
- **Community-Driven Stabilization** – Incentivize community participation in market stabilization

### 4. **JIT Liquidity Mechanisms**
- **Dynamic Liquidity Provision** – Just-in-time liquidity to reduce slippage on creator coin swaps
- **Enhanced Buyback Hooks** – Additional liquidity provision during high-slippage scenarios
- **Improved Swap Efficiency** – Higher earnings per swap through optimized liquidity deployment

---

## Troubleshooting

### Common Issues

- **Foundry Installation Issues:**  
  If you encounter "Permission Denied" errors during `forge install`, ensure your GitHub SSH keys are correctly added. Refer to [GitHub SSH documentation](https://docs.github.com/en/authentication/connecting-to-github-with-ssh).

- **Hook Function Compilation Errors:**  
  Ensure you're using the correct BaseHook pattern with internal `_beforeSwap`/`_afterSwap` functions. The Blueprint Protocol uses the updated Uniswap V4 hook architecture.

- **Test Failures:**  
  If tests fail due to price limit issues, verify that you're using the correct price limit constants from the inherited Deployers contract.

- **Deployment Failures:**  
  Ensure that the correct flags and salt values are used (especially for CREATE2 deployments) and verify that your deployer address matches the expected CREATE2 proxy address if applicable.

### Getting Help

For additional support:
- Review the [Blueprint Protocol Documentation](https://docs.blueprint.gg/)
- Check the [GitHub Issues](https://github.com/BelloSights/flaunchgg-contracts/issues)
- Join our [Discord Community](https://discord.gg/blueprint)

---

## License

This repository is released under the [Apache 2.0 License](./LICENSE). Some files (such as tests and scripts) may be licensed under MIT.
