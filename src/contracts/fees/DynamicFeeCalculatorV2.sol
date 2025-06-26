// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {BalanceDelta} from '@uniswap/v4-core/src/types/BalanceDelta.sol';
import {FixedPointMathLib} from '@solady/utils/FixedPointMathLib.sol';
import {IPoolManager} from '@uniswap/v4-core/src/interfaces/IPoolManager.sol';
import {SwapParams} from '@uniswap/v4-core/src/types/PoolOperation.sol';
import {PoolKey} from '@uniswap/v4-core/src/types/PoolKey.sol';
import {PoolId, PoolIdLibrary} from '@uniswap/v4-core/src/types/PoolId.sol';
import {Currency} from '@uniswap/v4-core/src/types/Currency.sol';

import {IFeeCalculator} from '@flaunch-interfaces/IFeeCalculator.sol';


/**
 * Calculates the fee to be paid for a swap based on the amount of volume being transacted in
 * the pool. The more value in the swaps, combined with a faster rate of swaps, will result in
 * an increased price which will decrease rapidly to normalise the fee.
 */
contract DynamicFeeCalculatorV2 is IFeeCalculator {

    using PoolIdLibrary for PoolKey;

    /// Thrown when `trackSwap` is called by unauthorized address
    error CallerNotPositionManager();

    /**
     * Contains information regarding token1 accumulated volume and fee for a specific pool.
     * 
     * @member currentFeeScaled The current fee scaled by 1e18
     * @member lastFeeIncreaseTime The timestamp of the last fee increase
     * @member accumulatorWeightedVolume The time weighted volume of token1 swaps, the latest swap has the most weight
     * @member accumulatorLastUpdateTime The timestamp of the last update to the accumulator
     */
    struct PoolInfo {
        uint24 currentFeeScaled;
        uint lastFeeIncreaseTime;
        uint accumulatorWeightedVolume;
        uint accumulatorLastUpdateTime;
    }

    /// The fee charged for swaps has to be always greater than MINIMUM_FEE represented
    /// in basis points.
    uint internal constant MINIMUM_FEE_SCALED = 1_0000; // 1% in bps scaled by 1_00

    /// The fee charged for swaps has to be always less than MAXIMUM_FEE represented in
    /// basis points.
    uint internal constant MAXIMUM_FEE_SCALED = 50_0000; // 50% in bps scaled by 1_00

    /// The time window for which we account for the aggregate volume of swaps as well as
    /// the window after which the fee will linearly decrease to the minimum fee.
    uint internal constant ROLLING_FEE_WINDOW_DURATION = 1 hours;

    /// The total token supply of the memecoin
    uint internal constant TOTAL_TOKEN_SUPPLY = 100e27;

    /// The token volume threshold at which the fee starts to increase
    uint internal constant INCREASE_TOKEN_VOLUME_THRESHOLD = 5e24; // 0.5% of the total supply

    /// The decay rate per second for the accumulator. This is used to linearly decay the influence
    /// of older swap volumes on the fee calculation.
    uint internal constant DECAY_RATE_PER_SECOND = 277777777777777; // 1/3600 scaled to 1e18

    /// The {PositionManager} contract address
    address public immutable positionManager;

    /// Our native token
    address public immutable nativeToken;

    /// Maps our `PoolInfo` to each pool
    mapping (PoolId _poolId => PoolInfo _poolInfo) public poolInfos;

    /**
     * Assigns our {PositionManager} address to ensure that `trackSwap` is only called
     * by approved sources.
     *
     * @param _positionManager The address of our {PositionManager} contract
     * @param _nativeToken The native token used for Flaunch
     */
    constructor (address _positionManager, address _nativeToken) {
        positionManager = _positionManager;
        nativeToken = _nativeToken;
    }

    /**
     * Gets the current swap fee for the pool.
     *
     * @dev This will always be less than the `MAXIMUM_FEE` as this will have been
     * constrained during the `trackSwap`.
     *
     * @param _poolKey The pool key of the Uniswap V4 pool
     * @param _baseFee The base swap fee
     *
     * @return swapFee_ The calculated swap fee to use
     */
    function determineSwapFee(
        PoolKey memory _poolKey,
        SwapParams memory /* _params */,
        uint24 _baseFee
    ) external view returns (uint24 swapFee_) {
        PoolId poolId = _poolKey.toId();

        uint timeElapsed = block.timestamp - poolInfos[poolId].lastFeeIncreaseTime;
        uint swapFeeScaled;

        // If there's no fee increase within the last rolling fee window, fees return back to the minimum
        if (timeElapsed >= ROLLING_FEE_WINDOW_DURATION) {
            swapFeeScaled = MINIMUM_FEE_SCALED;
        } else {
            // Calculate the fee decrease based on the time elapsed since the last fee increase
            uint24 currentFeeScaled = poolInfos[poolId].currentFeeScaled;

            // Fee should linearly tend towards the minimum fee over the rolling fee window
            uint feeDecreaseScaled = ((currentFeeScaled - MINIMUM_FEE_SCALED) * timeElapsed) / ROLLING_FEE_WINDOW_DURATION;
            swapFeeScaled = currentFeeScaled - feeDecreaseScaled;
        }

        // Ensure that the swap fee is at least the base fee scale down the result to bps
        swapFee_ = uint24(FixedPointMathLib.max(swapFeeScaled, _baseFee * 1_00) / 1_00);
    }

    /**
     * After a swap is made, we track the additional logic to calculate the new fee
     * premium based on the transaction volume.
     *
     * @param _key The key for the pool
     * @param _delta The amount owed to the caller (positive) or owed to the pool (negative)
     */
    function trackSwap(
        address /* _sender */,
        PoolKey calldata _key,
        SwapParams calldata /* _params */,
        BalanceDelta _delta,
        bytes calldata /* _hookData */
    ) external {
        // Ensure that this call is coming from the {PositionManager}
        if (msg.sender != positionManager) revert CallerNotPositionManager();

        // Load our PoolInfo, opened as storage to update values
        PoolId poolId = _key.toId();
        PoolInfo storage poolInfo = poolInfos[poolId];

        // Absolute amount of non-native token swapped
        int deltaVolume = int(
            Currency.unwrap(_key.currency0) == nativeToken ? _delta.amount1() : _delta.amount0()
        );

        uint newVolume = uint(deltaVolume < 0 ? -deltaVolume : deltaVolume);

        // Update accumulator
        uint timeElapsed = block.timestamp - poolInfo.accumulatorLastUpdateTime;
        if (timeElapsed > ROLLING_FEE_WINDOW_DURATION) {
            // Reset the accumulator if the rolling fee window has passed
            poolInfo.accumulatorWeightedVolume = 0;
        } else {
            unchecked {
                // The influence of older swaps should linearly diminish as time passes. This ensures
                // that the most recent swap has a stronger influence on the fee than older swaps.
                uint decayFactor = 1e18 - (DECAY_RATE_PER_SECOND * timeElapsed);

                // Perform a pre-check to detect potential overflow
                if (poolInfo.accumulatorWeightedVolume > type(uint).max / decayFactor) {
                    // Overflow would occur, return the maximum uint value
                    poolInfo.accumulatorWeightedVolume = type(uint).max / 1 ether;
                } else {
                    poolInfo.accumulatorWeightedVolume = poolInfo.accumulatorWeightedVolume * decayFactor / 1 ether;
                }
            }
        }

        // Ensure that the `newVolume` won't overflow the `accumulatorWeightedVolume` value
        unchecked {
            if (poolInfo.accumulatorWeightedVolume > type(uint).max - newVolume) {
                poolInfo.accumulatorWeightedVolume = type(uint).max;
            } else {
                poolInfo.accumulatorWeightedVolume += newVolume;
            }
        }

        poolInfo.accumulatorLastUpdateTime = block.timestamp;

        if (poolInfo.accumulatorWeightedVolume >= INCREASE_TOKEN_VOLUME_THRESHOLD) {
            uint newFeeScaled;

            // Calculate the fee based on the accumulated volume of token1
            if (poolInfo.accumulatorWeightedVolume >= TOTAL_TOKEN_SUPPLY) {
                // If the volume exceeds the total token supply, the fee should be capped at
                // the maximum.
                newFeeScaled = MAXIMUM_FEE_SCALED;
            } else {
                // Linearly interpolate the fee for a volume range of 0.5% - 100% of total supply
                // to a fee of 1% - 50%.
                uint volumeAboveThreshold = poolInfo.accumulatorWeightedVolume - INCREASE_TOKEN_VOLUME_THRESHOLD;
                uint totalRange = TOTAL_TOKEN_SUPPLY - INCREASE_TOKEN_VOLUME_THRESHOLD;
                newFeeScaled = MINIMUM_FEE_SCALED + FixedPointMathLib.mulDivUp(volumeAboveThreshold, (MAXIMUM_FEE_SCALED - MINIMUM_FEE_SCALED), totalRange);
            }

            // Set storage if the fee has changed
            if (newFeeScaled != poolInfo.currentFeeScaled) {
                poolInfo.currentFeeScaled = uint24(newFeeScaled);
                poolInfo.lastFeeIncreaseTime = block.timestamp;
            }
        }
    }

    /**
     * We don't need any specific Flaunch parameters to be assigned to this calculator, so we
     * can just provide empty logic.
     */
    function setFlaunchParams(PoolId _poolId, bytes calldata _params) external override {
        // ..
    }
}
