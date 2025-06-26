// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {BalanceDelta} from '@uniswap/v4-core/src/types/BalanceDelta.sol';
import {IPoolManager} from '@uniswap/v4-core/src/interfaces/IPoolManager.sol';
import {SwapParams} from '@uniswap/v4-core/src/types/PoolOperation.sol';
import {PoolKey} from '@uniswap/v4-core/src/types/PoolKey.sol';
import {PoolId} from '@uniswap/v4-core/src/types/PoolId.sol';

import {IFeeCalculator} from '@flaunch-interfaces/IFeeCalculator.sol';


/**
 * This implementation of the {IFeeCalculator} just returns the same base swapFee that
 * is assinged in the FeeDistribution struct.
 */
contract StaticFeeCalculator is IFeeCalculator {

    /**
     * For a static value we simply return the `_baseFee` that was passed in with no
     * additional multipliers or calculations.
     *
     * @param _baseFee The base swap fee
     *
     * @return swapFee_ The calculated swap fee to use
     */
    function determineSwapFee(
        PoolKey memory /* _poolKey */,
        SwapParams memory /* _params */,
        uint24 _baseFee
    ) public pure returns (uint24 swapFee_) {
        return _baseFee;
    }

    /**
     * Tracks information regarding ongoing swaps for pools, though for this static
     * approach we only confirm the caller and don't process any further information.
     */
    function trackSwap(address, PoolKey calldata, SwapParams calldata, BalanceDelta, bytes calldata) public view {}

    /**
     * We don't need any specific Flaunch parameters to be assigned to this calculator, so we
     * can just provide empty logic.
     */
    function setFlaunchParams(PoolId _poolId, bytes calldata _params) external override {
        // ..
    }

}
