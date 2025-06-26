// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {BalanceDelta} from '@uniswap/v4-core/src/types/BalanceDelta.sol';
import {IPoolManager} from '@uniswap/v4-core/src/interfaces/IPoolManager.sol';
import {SwapParams} from '@uniswap/v4-core/src/types/PoolOperation.sol';
import {PoolId, PoolIdLibrary} from '@uniswap/v4-core/src/types/PoolId.sol';
import {PoolKey} from '@uniswap/v4-core/src/types/PoolKey.sol';

import {IFeeCalculator} from '@flaunch-interfaces/IFeeCalculator.sol';


/**
 * Calculates the fee to be paid for a swap based on the amount of volume being transacted in
 * the pool. The more value in the swaps, combined with a faster rate of swaps, will result in
 * an increased price which will decrease rapidly to normalise the fee.
 *
 * This is a modified implementation of Brokkr Finance VolumeFee:
 * https://github.com/BrokkrFinance/hooks-poc/blob/main/src/VolumeFee.sol
 *
 * @dev This has been replaced by {DynamicFeeCalculatorV2} and should not be used.
 */
contract DynamicFeeCalculator is IFeeCalculator {

    using PoolIdLibrary for PoolKey;

    /// Fee can only be increased, if the aggreageted volume is greater than FEE_INCREASE_TOKEN1_UNIT
    /// `fee increase = aggregated volume / FEE_INCREASE_TOKEN1_UNIT * FEE_INCREASE_PER_TOKEN1_UNIT`
    uint internal constant FEE_INCREASE_TOKEN1_UNIT = 1e22;

    /// Fee can only be decrased, if the elapsed time since the last fee decrease is greater than FEE_DECREASE_TIME_UNIT
    /// `fee decrease = time elapsed since last decrease / FEE_DECREASE_TIME_UNIT * FEE_DECREASE_PER_TIME_UNIT`
    uint internal constant FEE_DECREASE_TIME_UNIT = 10;

    /// The fee charged for swaps has to be always greater than MINIMUM_FEE represented
    /// in basis points.
    uint internal constant MINIMUM_FEE = 1_0000;

    /// The fee charged for swaps has to be always less than MAXIMUM_FEE represented in
    /// basis points.
    uint internal constant MAXIMUM_FEE = 40_0000;

    /// Fee changes will only be written to storage, if they are bigger than
    /// MINIMUM_FEE_THRESHOLD bps.
    uint internal constant MINIMUM_FEE_THRESHOLD = 100;

    /// Fee increase in basis points per token1 units. 0.05 percent is represented
    /// as 500.
    uint24 internal constant FEE_INCREASE_PER_TOKEN1_UNIT = 3;

    // Fee decrease in basis point per second. 0.01 fee decrease per time unit is
    // represented as 100.
    uint24 internal constant FEE_DECREASE_PER_TIME_UNIT = 10;


    /**
     * Contains information about regarding token1 fee volume and fee accumulation
     * for a specific pool.
     *
     * @dev We could pack this struct more tightly around the timestamp, but this would
     * have an offset cost in coversion logic that may not make it beneficial.
     *
     * @member token1SoFar The current aggregated swap volume for which no fee
     * increase has yet been accounted for.
     * @member lastFeeDecreaseTime The last time the fee was decreased, represented
     * in unixtime.
     * @member currentFee The current fee that is used to charge swappers.
     */
    struct PoolInfo {
        uint24 currentFee;
        uint lastFeeDecreaseTime;
        uint token1SoFar;
    }

    /// Thrown when `trackSwap` is called by unauthorized address
    error CallerNotPositionManager();

    /// Maps our `PoolInfo` to each pool
    mapping (PoolId _poolId => PoolInfo _poolInfo) public poolInfos;

    /// The {PositionManager} contract address
    address public immutable positionManager;

    /**
     * Assigns our {PositionManager} address to ensure that `trackSwap` is only called
     * by approved sources.
     *
     * @param _positionManager The address of our {PositionManager} contract
     */
    constructor (address _positionManager) {
        positionManager = _positionManager;
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
    ) public view returns (uint24 swapFee_) {
        PoolInfo memory poolInfo = poolInfos[_poolKey.toId()];

        // Get the current fee premium, reduced by the amount of time passed
        uint feeDecrease = (block.timestamp - poolInfo.lastFeeDecreaseTime) / FEE_DECREASE_TIME_UNIT * FEE_DECREASE_PER_TIME_UNIT;

        // Get the current fee, either from the premium or the `baseFee`
        swapFee_ = uint24(uint(
            _max(
                int(int24(poolInfo.currentFee)) - int(feeDecrease),
                int(int24(_baseFee)) * 100
            )
        ) / 100);
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
    ) public {
        // Ensure that this call is coming from the {PositionManager}
        if (msg.sender != positionManager) {
            revert CallerNotPositionManager();
        }

        PoolId poolId = _key.toId();
        PoolInfo storage poolInfo = poolInfos[poolId];

        // If we have an empty PoolInfo struct, then we need to initialise it
        if (poolInfo.lastFeeDecreaseTime == 0) {
            poolInfo.lastFeeDecreaseTime = block.timestamp;
        }

        // Calculate the reduction of fees based on the last time that fee decreased
        uint feeDecrease = ((block.timestamp - poolInfo.lastFeeDecreaseTime) / FEE_DECREASE_TIME_UNIT) * FEE_DECREASE_PER_TIME_UNIT;
        int feeChange = -int(feeDecrease);

        // Increase the number of captured tokens by the swap size
        uint token1SoFar = poolInfo.token1SoFar + uint(int(_key.currency0 > _key.currency1 ? _delta.amount0() : _delta.amount1()));

        // Determine the fee increase
        uint feeIncrease = ((token1SoFar / FEE_INCREASE_TOKEN1_UNIT) * FEE_INCREASE_PER_TOKEN1_UNIT);
        feeChange += int(feeIncrease);

        // Ensure change has surpassed threshold
        if ((feeChange < 0 ? -feeChange : feeChange) > int(MINIMUM_FEE_THRESHOLD)) {
            // If we have a fee decrease, then we want to record this as the last time
            // it happened.
            if (feeDecrease != 0) {
                poolInfo.lastFeeDecreaseTime =
                    poolInfo.lastFeeDecreaseTime +
                    ((feeDecrease / FEE_DECREASE_PER_TIME_UNIT) * FEE_DECREASE_TIME_UNIT);
            }

            // Update the number of tokens taken so far
            poolInfo.token1SoFar = token1SoFar - (feeIncrease * FEE_INCREASE_TOKEN1_UNIT) / FEE_INCREASE_PER_TOKEN1_UNIT;

            // Calculate our new fee based on the min/max range
            uint newFee = uint(
                _max(
                    _min(
                        int(int24(poolInfo.currentFee)) + feeChange,
                        int(MAXIMUM_FEE)
                    ),
                    int(MINIMUM_FEE)
                )
            );

            // if the currentFee was at the MAXIMUM_FEE or MINIMUM_FEE, then even when abs(feeChange) > 0
            // the storage write might be avoided
            if (newFee != poolInfo.currentFee) {
                poolInfo.currentFee = uint24(newFee);
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

    /**
     * Determine the max value of two ints.
     */
    function _max(int _a, int _b) internal pure returns (int) {
        return _a > _b ? _a : _b;
    }

    /**
     * Determine the min value of two ints.
     */
    function _min(int _a, int _b) internal pure returns (int) {
        return _a < _b ? _a : _b;
    }

}
