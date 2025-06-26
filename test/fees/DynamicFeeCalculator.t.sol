// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {IPoolManager} from '@uniswap/v4-core/src/interfaces/IPoolManager.sol';
import {SwapParams} from '@uniswap/v4-core/src/types/PoolOperation.sol';
import {IHooks} from '@uniswap/v4-core/src/libraries/Hooks.sol';
import {TickMath} from '@uniswap/v4-core/src/libraries/TickMath.sol';
import {toBalanceDelta} from '@uniswap/v4-core/src/types/BalanceDelta.sol';
import {Currency} from '@uniswap/v4-core/src/types/Currency.sol';
import {PoolKey} from '@uniswap/v4-core/src/types/PoolKey.sol';

import {DynamicFeeCalculator} from '@flaunch/fees/DynamicFeeCalculator.sol';

import {FlaunchTest} from '../FlaunchTest.sol';


contract DynamicFeeCalculatorTest is FlaunchTest {

    address internal constant POSITION_MANAGER = address(10);

    DynamicFeeCalculator feeCalculator;

    PoolKey internal _poolKey;

    function setUp() public {
        feeCalculator = new DynamicFeeCalculator(POSITION_MANAGER);

        // Set up an example {PoolKey}
        _poolKey = PoolKey({
            currency0: Currency.wrap(address(1)),
            currency1: Currency.wrap(address(2)),
            fee: 0,
            tickSpacing: 60,
            hooks: IHooks(POSITION_MANAGER)
        });
    }

    function test_CanReferencePositionManager() public view {
        assertEq(feeCalculator.positionManager(), POSITION_MANAGER);
    }

    function test_CanDetermineSwapFee() public {
        vm.startPrank(POSITION_MANAGER);

        // 3 ether swap at 1% base rate. The first few swapos won't break a premium, but
        // then we will start to see an increase.
        assertEq(feeCalculator.determineSwapFee(_poolKey, _getSwapParams(3e24), 1_00), 1_00);
        _trackSwap(3e24);

        assertEq(feeCalculator.determineSwapFee(_poolKey, _getSwapParams(3e25), 1_00), 1_00);
        _trackSwap(3e25);

        assertEq(feeCalculator.determineSwapFee(_poolKey, _getSwapParams(5e24), 1_00), 1_90);
        _trackSwap(5e24);

        assertEq(feeCalculator.determineSwapFee(_poolKey, _getSwapParams(15e23), 1_00), 2_05);
        _trackSwap(15e23);

        assertEq(feeCalculator.determineSwapFee(_poolKey, _getSwapParams(3e24), 1_00), 2_09);

        // Allow some time to pass and confirm that the fee has reduced
        vm.warp(block.timestamp + 2 hours);
        assertEq(feeCalculator.determineSwapFee(_poolKey, _getSwapParams(3e24), 1_00), 1_37);
        _trackSwap(3e24);

        // Another swap! Woo!
        assertEq(feeCalculator.determineSwapFee(_poolKey, _getSwapParams(1e18), 1_00), 1_46);

        // Now we can skip a lot of time to make sure we don't drop past minimum
        vm.warp(block.timestamp + 1 days);
        assertEq(feeCalculator.determineSwapFee(_poolKey, _getSwapParams(1e18), 1_00), 1_00);

        vm.stopPrank();
    }

    function test_CanTrackSwap() public {
        vm.prank(POSITION_MANAGER);
        _trackSwap(3e27);
    }

    function test_CannotTrackSwapFromUnknownCaller(address _caller) public {
        vm.assume(_caller != POSITION_MANAGER);

        vm.startPrank(_caller);

        vm.expectRevert(DynamicFeeCalculator.CallerNotPositionManager.selector);
        _trackSwap(3e27);

        vm.stopPrank();
    }

    function test_CanHandleVariedSwapDeltas() public {
        int128 _amountSpecified = 3 ether;

        vm.startPrank(POSITION_MANAGER);

        feeCalculator.trackSwap(
            address(1),
            _poolKey,
            SwapParams({
                zeroForOne: true,
                amountSpecified: int(_amountSpecified),
                sqrtPriceLimitX96: uint160(int160(TickMath.minUsableTick(_poolKey.tickSpacing)))
            }),
            toBalanceDelta(-(_amountSpecified / 2), _amountSpecified),
            ''
        );

        feeCalculator.trackSwap(
            address(1),
            _poolKey,
            SwapParams({
                zeroForOne: true,
                amountSpecified: int(-_amountSpecified),
                sqrtPriceLimitX96: uint160(int160(TickMath.maxUsableTick(_poolKey.tickSpacing)))
            }),
            toBalanceDelta(-_amountSpecified, _amountSpecified * 2),
            ''
        );

        feeCalculator.trackSwap(
            address(1),
            _poolKey,
            SwapParams({
                zeroForOne: false,
                amountSpecified: int(_amountSpecified),
                sqrtPriceLimitX96: uint160(int160(TickMath.maxUsableTick(_poolKey.tickSpacing)))
            }),
            toBalanceDelta(-_amountSpecified, _amountSpecified * 2),
            ''
        );

        feeCalculator.trackSwap(
            address(1),
            _poolKey,
            SwapParams({
                zeroForOne: false,
                amountSpecified: int(-_amountSpecified),
                sqrtPriceLimitX96: uint160(int160(TickMath.minUsableTick(_poolKey.tickSpacing)))
            }),
            toBalanceDelta(-(_amountSpecified / 2), _amountSpecified),
            ''
        );

        vm.stopPrank();
    }

    function _trackSwap(int128 _amountSpecified) internal {
        feeCalculator.trackSwap(
            address(1),
            _poolKey,
            SwapParams({
                zeroForOne: true,
                amountSpecified: int(_amountSpecified),
                sqrtPriceLimitX96: uint160(int160(TickMath.minUsableTick(_poolKey.tickSpacing)))
            }),
            toBalanceDelta(-(_amountSpecified / 2), _amountSpecified),
            ''
        );
    }

}
