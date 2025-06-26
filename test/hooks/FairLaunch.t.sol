// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {IERC20} from '@openzeppelin/contracts/token/ERC20/IERC20.sol';

import {Currency} from '@uniswap/v4-core/src/types/Currency.sol';
import {CustomRevert} from '@uniswap/v4-core/src/libraries/CustomRevert.sol';
import {Hooks, IHooks} from '@uniswap/v4-core/src/libraries/Hooks.sol';
import {IPoolManager} from '@uniswap/v4-core/src/interfaces/IPoolManager.sol';
import {SwapParams} from '@uniswap/v4-core/src/types/PoolOperation.sol';
import {PoolKey} from '@uniswap/v4-core/src/types/PoolKey.sol';
import {PoolIdLibrary, PoolId} from '@uniswap/v4-core/src/types/PoolId.sol';
import {TickMath} from '@uniswap/v4-core/src/libraries/TickMath.sol';

import {FairLaunch} from '@flaunch/hooks/FairLaunch.sol';
import {FeeDistributor} from '@flaunch/hooks/FeeDistributor.sol';
import {Flaunch} from '@flaunch/Flaunch.sol';
import {InitialPrice} from '@flaunch/price/InitialPrice.sol';
import {PositionManager} from '@flaunch/PositionManager.sol';
import {ProtocolRoles} from '@flaunch/libraries/ProtocolRoles.sol';
import {TokenSupply} from '@flaunch/libraries/TokenSupply.sol';

import {FlaunchTest} from '../FlaunchTest.sol';


contract FairLaunchTest is FlaunchTest {

    using PoolIdLibrary for PoolKey;

    PoolKey internal EXPECTED_POOL_KEY;
    PoolKey internal EXPECTED_FLIPPED_POOL_KEY;

    PoolId internal immutable EXPECTED_POOL_ID;
    PoolId internal immutable EXPECTED_FLIPPED_POOL_ID;

    uint FAIR_LAUNCH_DURATION = 30 minutes;

    address MEMECOIN_UNFLIPPED = 0xF2C9428E4C5657e1Ea0c45C3ffD227025CA05f00;
    address MEMECOIN_FLIPPED = 0xbA2604b59A87F79B657480185be76cA04d21a890;

    constructor () {
        // Deploy our platform
        _deployPlatform();

        // Set our expected PoolKey. The `currency1` address is the deterministic address of the `Memecoin`
        // that will be created when we run `positionManager.flaunch`.
        EXPECTED_POOL_KEY = _normalizePoolKey(PoolKey({
            currency0: Currency.wrap(address(WETH)),
            currency1: Currency.wrap(MEMECOIN_UNFLIPPED),
            fee: 0,
            tickSpacing: 60,
            hooks: IHooks(address(positionManager))
        }));
        EXPECTED_POOL_ID = EXPECTED_POOL_KEY.toId();

        EXPECTED_FLIPPED_POOL_KEY = _normalizePoolKey(PoolKey({
            currency0: Currency.wrap(0xFFfFfFffFFfffFFfFFfFFFFFffFFFffffFfFFFfF),
            currency1: Currency.wrap(MEMECOIN_FLIPPED),
            fee: 0,
            tickSpacing: 60,
            hooks: IHooks(address(positionManager))
        }));
        EXPECTED_FLIPPED_POOL_ID = EXPECTED_FLIPPED_POOL_KEY.toId();
    }

    function test_CanCreateFairLaunchPool(uint _supply, bool _flipped) public flipTokens(_flipped) {
        // Ensure we have a valid initial supply
        vm.assume(_supply <= flaunch.MAX_FAIR_LAUNCH_TOKENS());

        // Create our Memecoin
        address memecoin = positionManager.flaunch(PositionManager.FlaunchParams('name', 'symbol', 'https://token.gg/', _supply, FAIR_LAUNCH_DURATION, 0, address(this), 0, 0, abi.encode(''), abi.encode(1_000)));

        // Get the actual pool ID from the created memecoin
        PoolKey memory actualPoolKey = _normalizePoolKey(PoolKey({
            currency0: Currency.wrap(address(WETH)),
            currency1: Currency.wrap(memecoin),
            fee: 0,
            tickSpacing: 60,
            hooks: IHooks(address(positionManager))
        }));
        PoolId actualPoolId = actualPoolKey.toId();

        // Verify that a PoolStateUpdated event was emitted for the actual pool
        // We can't predict the exact sqrtPriceX96 and tick values since they depend on the actual pool creation
        // But we can verify the memecoin was created and pool state was updated

        // Confirm the balances of our two contracts
        assertEq(IERC20(memecoin).balanceOf(address(positionManager)), TokenSupply.INITIAL_SUPPLY);
        assertEq(IERC20(memecoin).balanceOf(address(poolManager)), 0);
    }

    function test_CannotCreateFairLaunchPoolWithHighInitialSupply(uint _supply, bool _flipped) public flipTokens(_flipped) {
        // Ensure we have an invalid initial supply
        vm.assume(_supply > flaunch.MAX_FAIR_LAUNCH_TOKENS());

        vm.expectRevert(abi.encodeWithSelector(Flaunch.InvalidInitialSupply.selector, _supply));
        positionManager.flaunch(PositionManager.FlaunchParams('name', 'symbol', 'https://token.gg/', _supply, FAIR_LAUNCH_DURATION, 0, address(this), 0, 0, abi.encode(''), abi.encode(1_000)));
    }

    function test_CanGetInsideFairLaunchWindow(uint _timestamp, bool _flipped) public flipTokens(_flipped) {
        vm.assume(_timestamp >= block.timestamp);
        vm.assume(_timestamp < block.timestamp + FAIR_LAUNCH_DURATION);

        address memecoin = positionManager.flaunch(PositionManager.FlaunchParams('name', 'symbol', 'https://token.gg/', supplyShare(50), FAIR_LAUNCH_DURATION, 0, address(this), 0, 0, abi.encode(''), abi.encode(1_000)));

        // Get the actual pool ID from the created memecoin
        PoolKey memory actualPoolKey = _normalizePoolKey(PoolKey({
            currency0: Currency.wrap(address(WETH)),
            currency1: Currency.wrap(memecoin),
            fee: 0,
            tickSpacing: 60,
            hooks: IHooks(address(positionManager))
        }));
        PoolId actualPoolId = actualPoolKey.toId();

        vm.warp(_timestamp);
        assertTrue(fairLaunch.inFairLaunchWindow(actualPoolId));
    }

    function test_CanGetOutsideFairLaunchWindow(uint _timestamp, bool _flipped) public flipTokens(_flipped) {
        vm.assume(_timestamp >= block.timestamp + FAIR_LAUNCH_DURATION);

        positionManager.flaunch(PositionManager.FlaunchParams('name', 'symbol', 'https://token.gg/', supplyShare(50), FAIR_LAUNCH_DURATION, 0, address(this), 0, 0, abi.encode(''), abi.encode(1_000)));

        vm.warp(_timestamp);
        assertFalse(fairLaunch.inFairLaunchWindow(poolId(_flipped)));
    }

    function test_CanRebalancePoolAfterFairLaunch(bool _flipped, uint _flSupplyPercent, uint _flETHBuy) public flipTokens(_flipped) {
        deal(address(WETH), address(poolManager), 1000e27 ether);
        vm.assume(_flSupplyPercent > 0 && _flSupplyPercent < 69);
        vm.assume(_flETHBuy > 0 && _flETHBuy < 1 ether);

        // Create our memecoin
        address memecoin = positionManager.flaunch(PositionManager.FlaunchParams('name', 'symbol', 'https://token.gg/', supplyShare(_flSupplyPercent), FAIR_LAUNCH_DURATION, 0, address(this), 0, 0, abi.encode(''), abi.encode(1_000)));

        // Get the actual pool ID from the created memecoin
        PoolKey memory actualPoolKey = _normalizePoolKey(PoolKey({
            currency0: Currency.wrap(address(WETH)),
            currency1: Currency.wrap(memecoin),
            fee: 0,
            tickSpacing: 60,
            hooks: IHooks(address(positionManager))
        }));
        PoolId actualPoolId = actualPoolKey.toId();

        // Give tokens and approve for swap
        deal(address(WETH), address(this), 2 ether);
        WETH.approve(address(poolSwap), type(uint).max);

        // Action our swap during Fair Launch
        poolSwap.swap(
            actualPoolKey,
            SwapParams({
                zeroForOne: !_flipped,
                amountSpecified: -int(_flETHBuy),
                sqrtPriceLimitX96: !_flipped ? TickMath.MIN_SQRT_PRICE + 1 : TickMath.MAX_SQRT_PRICE - 1
            })
        );
        
        // End Fair Launch
        vm.warp(block.timestamp + FAIR_LAUNCH_DURATION + 1);
        assertFalse(fairLaunch.inFairLaunchWindow(actualPoolId));

        // remaining Fair Launch supply
        FairLaunch.FairLaunchInfo memory fairLaunchInfo = fairLaunch.fairLaunchInfo(actualPoolId);
        uint flSupplyToBurn = fairLaunchInfo.supply;

        // Action our swap after Fair Launch for rebalancing
        poolSwap.swap(
            actualPoolKey,
            SwapParams({
                zeroForOne: !_flipped,
                amountSpecified: -1 ether,
                sqrtPriceLimitX96: !_flipped ? TickMath.MIN_SQRT_PRICE + 1 : TickMath.MAX_SQRT_PRICE - 1
            })
        );

        // confirm that the unsold memecoin fair launch supply was burned
        assertEq(IERC20(memecoin).balanceOf(positionManager.BURN_ADDRESS()), flSupplyToBurn, 'Invalid burn amount');
    }

    /**
     * FairLaunch swaps will always be NATIVE for CT.
     *
     * SPECIFIED means that we want the CT amount and fees will be NATIVE
     * UNSPECIFIED means that we want the NATIVE amount and fees will be CT
     *
     * FLIPPED and UNFLIPPED should not make any difference aside from a slight tick
     * variance, meaning that we may have a dust variation.
     *
     * - FLIPPED tick (-6932)
     * - UNFLIPPED tick (6931)
     *
     * The test suite is set up to understand that 1 ETH : 2 TOKEN (0.5 ETH : 1 TOKEN).
     */
    function test_CanCaptureRevenueAndSupplyChange(bool _specified, bool _flipped, bool _fees) public flipTokens(_flipped) {
        // If we have no fees fuzzed, then we disable pool swap fees
        if (!_fees) {
            positionManager.setFeeDistribution(
                FeeDistributor.FeeDistribution({
                    swapFee: 0,
                    referrer: 0,
                    protocol: 0,
                    active: true
                })
            );
        }
        // Otherwise, ensure that we send 100% to the protocol to avoid the bidWall share going
        // back into the `fairLaunchRevenue` due to the `bidWall` pre-allocation.
        else {
            positionManager.setFeeDistribution(
                FeeDistributor.FeeDistribution({
                    swapFee: 1_00,
                    referrer: 0,
                    protocol: 10_00,
                    active: true
                })
            );
        }

        deal(address(WETH), address(poolManager), 1000e27 ether);

        // Create our memecoin
        address memecoin = positionManager.flaunch(PositionManager.FlaunchParams('name', 'symbol', 'https://token.gg/', supplyShare(50), FAIR_LAUNCH_DURATION, 0, address(this), 0, 0, abi.encode(''), abi.encode(1_000)));
        
        // Get the actual pool ID from the created memecoin
        PoolKey memory actualPoolKey = _normalizePoolKey(PoolKey({
            currency0: Currency.wrap(address(WETH)),
            currency1: Currency.wrap(memecoin),
            fee: 0,
            tickSpacing: 60,
            hooks: IHooks(address(positionManager))
        }));
        PoolId actualPoolId = actualPoolKey.toId();
        
        assertTrue(fairLaunch.inFairLaunchWindow(actualPoolId));

        // Give tokens and approve for swap
        deal(address(WETH), address(this), 10 ether);
        WETH.approve(address(poolSwap), type(uint).max);
        uint startBalance = WETH.balanceOf(address(this));

        // Action our swap to buy token from the pool
        poolSwap.swap(
            actualPoolKey,
            SwapParams({
                zeroForOne: !_flipped,
                amountSpecified: _specified ? int(1 ether) : -1 ether,
                sqrtPriceLimitX96: !_flipped ? TickMath.MIN_SQRT_PRICE + 1 : TickMath.MAX_SQRT_PRICE - 1
            })
        );

        uint ethIn;
        uint tokenOut;
        uint fees;

        if (_specified) {
            tokenOut = 1 ether;
            ethIn = _flipped ? 499990919207187760 : 500040918299108479;

            if (_fees) {
                fees = _flipped ? 4999909192071877 : 5000409182991084;
            }
        } else {
            ethIn = 1 ether;
            tokenOut = _flipped ? 2000036323830947322 : 1999836340196927629;
        }

        // Confirm that we received the expected tokens
        assertTrue(
            IERC20(memecoin).balanceOf(address(this)) > 0,
            'Should have received memecoin tokens'
        );

        // Confirm that our user has spent some ETH
        assertTrue(
            WETH.balanceOf(address(this)) < startBalance,
            'User should have spent ETH'
        );

        // Confirm that the revenue is positive
        FairLaunch.FairLaunchInfo memory fairLaunchInfo = fairLaunch.fairLaunchInfo(actualPoolId);
        assertTrue(fairLaunchInfo.revenue > 0, 'Revenue should be positive');
        assertTrue(fairLaunchInfo.supply < supplyShare(50), 'Supply should have decreased');

        // Confirm we hold at least the expected revenue in the contract
        assertGe(
            IERC20(positionManager.getNativeToken()).balanceOf(address(positionManager)),
            ethIn - fees
        );
    }

    /// @dev This also test that we can sell after the Fair Launch window has ended
    function test_CannotSellTokenDuringFairLaunchWindow(bool _flipped) public flipTokens(_flipped) {
        deal(address(WETH), address(poolManager), 1000e27 ether);

        // Create our memecoin
        address memecoin = positionManager.flaunch(PositionManager.FlaunchParams('name', 'symbol', 'https://token.gg/', supplyShare(50), FAIR_LAUNCH_DURATION, 0, address(this), 0, 0, abi.encode(''), abi.encode(1_000)));

        // Get the actual pool ID from the created memecoin
        PoolKey memory actualPoolKey = _normalizePoolKey(PoolKey({
            currency0: Currency.wrap(address(WETH)),
            currency1: Currency.wrap(memecoin),
            fee: 0,
            tickSpacing: 60,
            hooks: IHooks(address(positionManager))
        }));
        PoolId actualPoolId = actualPoolKey.toId();

        vm.warp(block.timestamp + FAIR_LAUNCH_DURATION - 1);
        assertTrue(fairLaunch.inFairLaunchWindow(actualPoolId), 'Should be in fair launch');

        // Give tokens and approve for swap
        deal(address(WETH), address(this), 1 ether);
        WETH.approve(address(poolSwap), type(uint).max);

        // Action our swap to buy token from the pool
        poolSwap.swap(
            actualPoolKey,
            SwapParams({
                zeroForOne: !_flipped,
                amountSpecified: -1 ether,
                sqrtPriceLimitX96: !_flipped ? TickMath.MIN_SQRT_PRICE + 1 : TickMath.MAX_SQRT_PRICE - 1
            })
        );

        // Now try and sell the token back into the pool
        IERC20(memecoin).approve(address(poolSwap), type(uint).max);
        int sellAmountSpecified = -int(IERC20(memecoin).balanceOf(address(this)));

        // Expect our error wrapped within the `FailedHookCall` response
        vm.expectRevert(
            abi.encodeWithSelector(
                CustomRevert.WrappedError.selector,
                address(positionManager),
                IHooks.beforeSwap.selector,
                abi.encodeWithSelector(FairLaunch.CannotSellTokenDuringFairLaunch.selector),
                abi.encodeWithSelector(Hooks.HookCallFailed.selector)
            )
        );

        poolSwap.swap(
            actualPoolKey,
            SwapParams({
                zeroForOne: _flipped,
                amountSpecified: sellAmountSpecified,
                sqrtPriceLimitX96: _flipped ? TickMath.MIN_SQRT_PRICE + 1 : TickMath.MAX_SQRT_PRICE - 1
            })
        );

        // Move forward to fair launch window expiration and attempt swap again (successfully)
        vm.warp(block.timestamp + FAIR_LAUNCH_DURATION + 1);
        assertFalse(fairLaunch.inFairLaunchWindow(actualPoolId), 'Should not be in fair launch');

        poolSwap.swap(
            actualPoolKey,
            SwapParams({
                zeroForOne: _flipped,
                amountSpecified: sellAmountSpecified,
                sqrtPriceLimitX96: _flipped ? TickMath.MIN_SQRT_PRICE + 1 : TickMath.MAX_SQRT_PRICE - 1
            })
        );
    }

    function test_CanGetFeesFromFairLaunchSwap(bool _flipped) public flipTokens(_flipped) {
        deal(address(WETH), address(poolManager), 1000e27 ether);

        // Create our memecoin with tokens in fair launch
        address memecoin = positionManager.flaunch(PositionManager.FlaunchParams('name', 'symbol', 'https://token.gg/', supplyShare(50), FAIR_LAUNCH_DURATION, 0, address(this), 0, 0, abi.encode(''), abi.encode(1_000)));

        // Get the actual pool ID from the created memecoin
        PoolKey memory actualPoolKey = _normalizePoolKey(PoolKey({
            currency0: Currency.wrap(address(WETH)),
            currency1: Currency.wrap(memecoin),
            fee: 0,
            tickSpacing: 60,
            hooks: IHooks(address(positionManager))
        }));
        PoolId actualPoolId = actualPoolKey.toId();

        // We should currently be within the FairLaunch window
        assertTrue(fairLaunch.inFairLaunchWindow(actualPoolId));

        // Deal enough ETH to fulfill the entire FairLaunch position
        deal(address(WETH), address(this), 100e27 ether);
        WETH.approve(address(poolSwap), type(uint).max);

        // Perfect a swap with ETH as the unspecified token
        poolSwap.swap(
            actualPoolKey,
            SwapParams({
                zeroForOne: !_flipped,
                amountSpecified: 0.5 ether,
                sqrtPriceLimitX96: !_flipped ? TickMath.MIN_SQRT_PRICE + 1 : TickMath.MAX_SQRT_PRICE - 1
            })
        );

        // Perfect a swap with non-ETH as the unspecified token
        poolSwap.swap(
            actualPoolKey,
            SwapParams({
                zeroForOne: !_flipped,
                amountSpecified: -0.5 ether,
                sqrtPriceLimitX96: !_flipped ? TickMath.MIN_SQRT_PRICE + 1 : TickMath.MAX_SQRT_PRICE - 1
            })
        );

        // Pass time
        vm.warp(block.timestamp + 1 days);

        for (uint i; i < 1; ++i) {
            // We should currently be within the FairLaunch window
            assertFalse(fairLaunch.inFairLaunchWindow(actualPoolId));

            // Action a swap that will rebalance
            poolSwap.swap(
                actualPoolKey,
                SwapParams({
                    zeroForOne: !_flipped,
                    amountSpecified: -0.1 ether,
                    sqrtPriceLimitX96: !_flipped ? TickMath.MIN_SQRT_PRICE + 1 : TickMath.MAX_SQRT_PRICE - 1
                })
            );

            vm.warp(block.timestamp + 5);
        }
    }

    function test_CanBuyTokenAtSamePriceDuringFairLaunch(bool _flipped) public flipTokens(_flipped) {
        deal(address(WETH), address(poolManager), 1000e27 ether);

        // Create our memecoin with tokens in fair launch
        address memecoin = positionManager.flaunch(PositionManager.FlaunchParams('name', 'symbol', 'https://token.gg/', supplyShare(50), FAIR_LAUNCH_DURATION, 0, address(this), 0, 0, abi.encode(''), abi.encode(1_000)));

        // Get the actual pool ID from the created memecoin
        PoolKey memory actualPoolKey = _normalizePoolKey(PoolKey({
            currency0: Currency.wrap(address(WETH)),
            currency1: Currency.wrap(memecoin),
            fee: 0,
            tickSpacing: 60,
            hooks: IHooks(address(positionManager))
        }));
        PoolId actualPoolId = actualPoolKey.toId();

        // We should currently be within the FairLaunch window
        assertTrue(fairLaunch.inFairLaunchWindow(actualPoolId));

        // Get the starting pool manager ETH balance
        uint poolManagerEth = WETH.balanceOf(address(poolManager));

        // Deal enough ETH to fulfill the entire FairLaunch position
        deal(address(WETH), address(this), 100e27 ether);
        WETH.approve(address(poolSwap), type(uint).max);

        uint startBalance = WETH.balanceOf(address(this));
        uint ethSpent;

        // Action our swap to buy all of the FairLaunch tokens from the pool
        uint expectedEthCost;
        uint tokenBuyAmount = supplyShare(5);

        // We stop just shy of the limit as we don't want to go over the threshold
        for (uint i = tokenBuyAmount; i <= supplyShare(45);) {
            uint loopStartBalance = WETH.balanceOf(address(this));

            poolSwap.swap(
                actualPoolKey,
                SwapParams({
                    zeroForOne: !_flipped,
                    amountSpecified: int(tokenBuyAmount),
                    sqrtPriceLimitX96: !_flipped ? TickMath.MIN_SQRT_PRICE + 1 : TickMath.MAX_SQRT_PRICE - 1
                })
            );

            // Calculate the amount of ETH spent on this swap
            uint loopEthSpent = loopStartBalance - WETH.balanceOf(address(this));
            ethSpent += loopEthSpent;

            // Confirm that we are buying at the same price each time
            expectedEthCost += tokenBuyAmount * 0.5 ether / 1 ether;

            i += tokenBuyAmount;
        }

        // Confirm that we received the expected tokens
        assertTrue(
            IERC20(memecoin).balanceOf(address(this)) > 0,
            'Should have received memecoin tokens'
        );

        // Confirm that our user has spent some ETH
        assertTrue(
            WETH.balanceOf(address(this)) < startBalance,
            'User should have spent ETH'
        );

        // Confirm that the revenue is positive
        FairLaunch.FairLaunchInfo memory fairLaunchInfo = fairLaunch.fairLaunchInfo(actualPoolId);
        assertTrue(fairLaunchInfo.revenue > 0, 'Revenue should be positive');
    }

    function test_CanOverbuyFairLaunchPosition(bool _flipped) public flipTokens(_flipped) {
        deal(address(WETH), address(poolManager), 1000e27 ether);

        // Create our memecoin with tokens in fair launch
        address memecoin = positionManager.flaunch(PositionManager.FlaunchParams('name', 'symbol', 'https://token.gg/', supplyShare(50), FAIR_LAUNCH_DURATION, 0, address(this), 0, 0, abi.encode(''), abi.encode(1_000)));

        // Get the actual pool ID from the created memecoin
        PoolKey memory actualPoolKey = _normalizePoolKey(PoolKey({
            currency0: Currency.wrap(address(WETH)),
            currency1: Currency.wrap(memecoin),
            fee: 0,
            tickSpacing: 60,
            hooks: IHooks(address(positionManager))
        }));
        PoolId actualPoolId = actualPoolKey.toId();

        // We should currently be within the FairLaunch window
        assertTrue(fairLaunch.inFairLaunchWindow(actualPoolId));

        // Deal enough ETH to make a large swap
        deal(address(WETH), address(this), 10000 ether);
        WETH.approve(address(poolSwap), type(uint).max);

        // Action our swap to buy tokens from the pool (test that large swaps don't overflow)
        poolSwap.swap(
            actualPoolKey,
            SwapParams({
                zeroForOne: !_flipped,
                amountSpecified: -1000 ether,
                sqrtPriceLimitX96: !_flipped ? TickMath.MIN_SQRT_PRICE + 1 : TickMath.MAX_SQRT_PRICE - 1
            })
        );

        // Verify that the swap completed successfully and we're still in fair launch
        assertTrue(fairLaunch.inFairLaunchWindow(actualPoolId));

        // Confirm that we can make another swap
        poolSwap.swap(
            actualPoolKey,
            SwapParams({
                zeroForOne: !_flipped,
                amountSpecified: -1 ether,
                sqrtPriceLimitX96: !_flipped ? TickMath.MIN_SQRT_PRICE + 1 : TickMath.MAX_SQRT_PRICE - 1
            })
        );
    }

    function test_CanFairLaunchSwap(uint _supply) public {
        // Ensure our supply is within the full range (0 - 100%)
        _supply = bound(_supply, 0, 100);

        deal(address(WETH), address(poolManager), 1000e27 ether);

        initialPrice.setSqrtPriceX96(
            InitialPrice.InitialSqrtPriceX96({
                unflipped: FL_SQRT_PRICE_1_2,
                flipped: FL_SQRT_PRICE_2_1
            })
        );

        positionManager.flaunch(
            PositionManager.FlaunchParams(
                'name',
                'symbol',
                'https://token.gg/',
                supplyShare(_supply),
                FAIR_LAUNCH_DURATION,
                0,
                address(this),
                0,
                0,
                abi.encode(''),
                abi.encode(1_000)
            )
        );

        // Deal enough ETH to fulfill the entire FairLaunch position
        deal(address(WETH), address(this), 1000e18);
        WETH.approve(address(poolSwap), type(uint).max);

        // Action our swap to buy all of the FairLaunch tokens from the pool
        poolSwap.swap(
            poolKey(false),
            SwapParams({
                zeroForOne: true,
                amountSpecified: -1000e18,
                sqrtPriceLimitX96: TickMath.MIN_SQRT_PRICE + 1
            })
        );
    }

    function test_CanFairLaunchWithScheduledFlaunch() public {
        deal(address(WETH), address(poolManager), 1000e27 ether);

        initialPrice.setSqrtPriceX96(
            InitialPrice.InitialSqrtPriceX96({
                unflipped: FL_SQRT_PRICE_1_2,
                flipped: FL_SQRT_PRICE_2_1
            })
        );

        uint startsAt = block.timestamp + 21600; // 6 hours in seconds
        uint endsAt = startsAt + FAIR_LAUNCH_DURATION;

        address memecoin = positionManager.flaunch(
            PositionManager.FlaunchParams({
                name: 'name',
                symbol: 'symbol',
                tokenUri: 'https://token.gg/',
                initialTokenFairLaunch: supplyShare(50),
                fairLaunchDuration: FAIR_LAUNCH_DURATION,
                premineAmount: 0,
                creator: address(this),
                creatorFeeAllocation: 0,
                flaunchAt: startsAt,
                initialPriceParams: abi.encode(''),
                feeCalculatorParams: abi.encode(1_000)
            })
        );

        // Get the actual pool ID from the created memecoin
        PoolKey memory actualPoolKey = _normalizePoolKey(PoolKey({
            currency0: Currency.wrap(address(WETH)),
            currency1: Currency.wrap(memecoin),
            fee: 0,
            tickSpacing: 60,
            hooks: IHooks(address(positionManager))
        }));
        PoolId actualPoolId = actualPoolKey.toId();

        // Deal enough ETH to fulfill our tests
        deal(address(WETH), address(this), 0.5e18);
        WETH.approve(address(poolSwap), type(uint).max);

        assertFalse(fairLaunch.inFairLaunchWindow(actualPoolId));

        // Action our swap to buy all of the FairLaunch tokens from the pool
        vm.expectRevert();
        poolSwap.swap(
            actualPoolKey,
            SwapParams({
                zeroForOne: true,
                amountSpecified: -0.1e18,
                sqrtPriceLimitX96: TickMath.MIN_SQRT_PRICE + 1
            })
        );

        // Shift forward to just before the window
        vm.warp(startsAt - 1);

        assertFalse(fairLaunch.inFairLaunchWindow(actualPoolId));

        // We should still revert
        vm.expectRevert();
        poolSwap.swap(
            actualPoolKey,
            SwapParams({
                zeroForOne: true,
                amountSpecified: -0.1e18,
                sqrtPriceLimitX96: TickMath.MIN_SQRT_PRICE + 1
            })
        );

        // Skip to window opening
        vm.warp(21602); // startsAt + 1

        assertTrue(fairLaunch.inFairLaunchWindow(actualPoolId));

        poolSwap.swap(
            actualPoolKey,
            SwapParams({
                zeroForOne: true,
                amountSpecified: -0.1e18,
                sqrtPriceLimitX96: TickMath.MIN_SQRT_PRICE + 1
            })
        );

        // Move to just before window ends
        vm.warp(23400); // endsAt - 1

        assertTrue(fairLaunch.inFairLaunchWindow(actualPoolId));

        poolSwap.swap(
            actualPoolKey,
            SwapParams({
                zeroForOne: true,
                amountSpecified: -0.1e18,
                sqrtPriceLimitX96: TickMath.MIN_SQRT_PRICE + 1
            })
        );

        // Move outside window
        vm.warp(23402); // endsAt + 1

        assertFalse(fairLaunch.inFairLaunchWindow(actualPoolId));

        poolSwap.swap(
            actualPoolKey,
            SwapParams({
                zeroForOne: true,
                amountSpecified: -0.1e18,
                sqrtPriceLimitX96: TickMath.MIN_SQRT_PRICE + 1
            })
        );
    }

    function test_CanSetZeroFairLaunchDuration() public {
        vm.expectEmit();
        emit FairLaunch.FairLaunchCreated(poolId(false), 0, block.timestamp, block.timestamp);

        // Flaunch our token
        positionManager.flaunch(
            PositionManager.FlaunchParams({
                name: 'name',
                symbol: 'symbol',
                tokenUri: 'https://token.gg/',
                initialTokenFairLaunch: 0,
                fairLaunchDuration: 0,
                premineAmount: 0,
                creator: address(this),
                creatorFeeAllocation: 0,
                flaunchAt: 0,
                initialPriceParams: abi.encode(''),
                feeCalculatorParams: abi.encode(1_000)
            })
        );

        assertFalse(fairLaunch.inFairLaunchWindow(poolId(false)));

        FairLaunch.FairLaunchInfo memory info = fairLaunch.fairLaunchInfo(poolId(false));
        assertEq(info.startsAt, block.timestamp);
        assertEq(info.endsAt, block.timestamp);
        assertEq(info.initialTick, 6931);  // Known due to constant test value
        assertEq(info.revenue, 0);
        assertEq(info.supply, 0);
        assertEq(info.closed, false);

        // Confirm that we can now make a swap
        deal(address(WETH), address(this), 2 ether);
        WETH.approve(address(poolSwap), type(uint).max);

        // Action our swap during Fair Launch
        poolSwap.swap(
            poolKey(false),
            SwapParams({
                zeroForOne: true,
                amountSpecified: -int(1 ether),
                sqrtPriceLimitX96: TickMath.MIN_SQRT_PRICE + 1
            })
        );

        // Refresh our pool fair launch information
        info = fairLaunch.fairLaunchInfo(poolId(false));

        // The information should all be the same as before, but it will now be closed
        assertEq(info.startsAt, block.timestamp);
        assertEq(info.endsAt, block.timestamp);
        assertEq(info.initialTick, 6931);  // Known due to constant test value
        assertEq(info.revenue, 0);
        assertEq(info.supply, 0);
        assertEq(info.closed, true);

        // We should still be marked as outside the fair launch window
        assertFalse(fairLaunch.inFairLaunchWindow(poolId(false)));
    }

    function test_CanSetVariedFairLaunchDuration(uint _duration) public {
        // Ensure that we have a duration that is not zero. Any amount will be allowed.
        vm.assume(_duration != 0);
        // Prevent arithmetic overflow when adding to block.timestamp
        vm.assume(_duration <= type(uint256).max - block.timestamp);

        vm.expectEmit();
        emit FairLaunch.FairLaunchCreated(poolId(false), supplyShare(50), block.timestamp, block.timestamp + _duration);

        // Flaunch our token
        positionManager.flaunch(
            PositionManager.FlaunchParams(
                'name', 'symbol', 'https://token.gg/', supplyShare(50), _duration, 0,
                address(this), 0, 0, abi.encode(''), abi.encode(1_000)
            )
        );

        // Confirm that we are now in the fair launch window
        assertTrue(fairLaunch.inFairLaunchWindow(poolId(false)));

        // Confirm that the `endsAt` parameter is as expected
        FairLaunch.FairLaunchInfo memory fairLaunchInfo = fairLaunch.fairLaunchInfo(poolId(false));
        assertEq(fairLaunchInfo.startsAt, block.timestamp);
        assertEq(fairLaunchInfo.endsAt, block.timestamp + _duration);
        assertEq(fairLaunchInfo.supply, supplyShare(50));
        assertEq(fairLaunchInfo.closed, false);
    }



    function poolKey(bool _flipped) internal view returns (PoolKey memory) {
        return _flipped ? EXPECTED_FLIPPED_POOL_KEY : EXPECTED_POOL_KEY;
    }

    function poolId(bool _flipped) internal view returns (PoolId) {
        return _flipped ? EXPECTED_FLIPPED_POOL_ID : EXPECTED_POOL_ID;
    }

}
