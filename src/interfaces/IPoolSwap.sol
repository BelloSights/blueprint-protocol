// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {BalanceDelta} from '@uniswap/v4-core/src/types/BalanceDelta.sol';
import {IPoolManager} from '@uniswap/v4-core/src/interfaces/IPoolManager.sol';
import {PoolKey} from '@uniswap/v4-core/src/types/PoolKey.sol';
import {SwapParams} from '@uniswap/v4-core/src/types/PoolOperation.sol';


interface IPoolSwap {

    function swap(PoolKey memory _key, SwapParams memory _params) external payable returns (BalanceDelta);

    function swap(PoolKey memory _key, SwapParams memory _params, address _referrer) external payable returns (BalanceDelta delta_);

}
