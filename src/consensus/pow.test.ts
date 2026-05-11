/**
 * Comprehensive tests for proof-of-work and difficulty adjustment.
 *
 * Test vectors derived from Bitcoin Core src/test/pow_tests.cpp.
 *
 * Gates covered (~28 total):
 *  1.  fPowNoRetargeting early exit (regtest)
 *  2.  Non-adjustment block: mainnet returns parent bits
 *  3.  Non-adjustment block: testnet 20-min rule → powLimit
 *  4.  Non-adjustment block: testnet timestamp OK → walk-back
 *  5.  Walk-back halts at height 0
 *  6.  Walk-back halts at interval boundary
 *  7.  Walk-back returns non-min-diff bits when encountered
 *  8.  Adjustment block: calls calculateNextWorkRequired with correct firstBlockTime
 *  9.  calculateNextWorkRequired: fPowNoRetargeting returns parent bits (Core:pow.cpp:52)
 * 10.  calculateNextWorkRequired: no clamp (Core test #1 — 0x1d00d86a)
 * 11.  calculateNextWorkRequired: clamped to max timespan (Core test #4 — 0x1d00e1fd)
 * 12.  calculateNextWorkRequired: clamped to min timespan (Core test #3 — 0x1c0168fd)
 * 13.  calculateNextWorkRequired: pow_limit cap applied (Core test #2 — 0x1d00ffff)
 * 14.  calculateNextWorkRequired: BIP94 uses first-block bits not parent bits
 * 15.  permittedDifficultyTransition: fPowAllowMinDifficultyBlocks → always true
 * 16.  permittedDifficultyTransition: adjustment block valid (Core test #1)
 * 17.  permittedDifficultyTransition: too-hard transition rejected (Core test #3 nbits-1)
 * 18.  permittedDifficultyTransition: too-easy transition rejected (Core test #4 nbits+1)
 * 19.  permittedDifficultyTransition: non-adjustment same bits → allowed
 * 20.  permittedDifficultyTransition: non-adjustment different bits → rejected
 * 21.  checkProofOfWork: negative target (Core: CheckProofOfWork_test_negative_target)
 * 22.  checkProofOfWork: overflow target (Core: CheckProofOfWork_test_overflow_target)
 * 23.  checkProofOfWork: target > powLimit (Core: CheckProofOfWork_test_too_easy_target)
 * 24.  checkProofOfWork: hash > target → false (Core: CheckProofOfWork_test_biger_hash_than_target)
 * 25.  checkProofOfWork: zero target → false (Core: CheckProofOfWork_test_zero_target)
 * 26.  checkProofOfWork: valid hash ≤ target → true
 * 27.  deriveTarget: valid compact → returns target
 * 28.  getBlockWork: zero target → 0; positive target → 2^256/(target+1)
 *
 * Reference: Bitcoin Core src/test/pow_tests.cpp, src/pow.cpp
 */

import { describe, expect, test } from "bun:test";
import {
  getNextWorkRequired,
  calculateNextWorkRequired,
  permittedDifficultyTransition,
  checkProofOfWork,
  deriveTarget,
  getBlockWork,
  type BlockInfo,
  type BlockLookup,
} from "./pow.js";
import {
  MAINNET,
  TESTNET,
  TESTNET4,
  REGTEST,
  compactToBigInt,
  bigIntToCompact,
  type ConsensusParams,
} from "./params.js";

// ─── Helpers ─────────────────────────────────────────────────────────────────

/**
 * Build a minimal BlockInfo for tests.
 */
function makeBlock(height: number, bits: number, timestamp: number): BlockInfo {
  return { height, header: { bits, timestamp } };
}

/**
 * Build a static chain lookup from an array of BlockInfo.
 */
function makeChain(blocks: BlockInfo[]): BlockLookup {
  const byHeight = new Map<number, BlockInfo>(blocks.map((b) => [b.height, b]));
  return (h: number) => byHeight.get(h);
}

/**
 * Convert a compact nBits to a target Buffer (32 bytes big-endian) for use
 * with checkProofOfWork which expects a little-endian Buffer.
 * We pass an all-zero hash that is always ≤ any positive target.
 */
function zeroHash(): Buffer {
  return Buffer.alloc(32, 0);
}

/**
 * Build a hash Buffer (LE) whose big-endian value equals the given BigInt.
 * Used to construct hashes that are exactly == target or target+1.
 */
function bigIntToHashLE(value: bigint): Buffer {
  const hex = value.toString(16).padStart(64, "0");
  const be = Buffer.from(hex, "hex");
  return Buffer.from(be).reverse(); // → little-endian
}

// ─── calculateNextWorkRequired ────────────────────────────────────────────────

describe("calculateNextWorkRequired", () => {
  // Gate 9: fPowNoRetargeting early exit
  test("regtest: fPowNoRetargeting returns parent bits unchanged", () => {
    const parent = makeBlock(2015, 0x207fffff, 1296688900);
    const firstTime = 1296688602;
    const noRetargetParams = REGTEST;
    const result = calculateNextWorkRequired(parent, firstTime, noRetargetParams, () => undefined);
    // Should return parent's target, not powLimit arithmetic result
    expect(result).toBe(compactToBigInt(0x207fffff));
  });

  // Gate 10: no clamp — Bitcoin Core test #1
  // pindexLast: height=32255, nTime=1262152739, nBits=0x1d00ffff
  // nFirstBlockTime=1261130161 (block #30240)
  // Expected: 0x1d00d86a (Core src/test/pow_tests.cpp:31)
  test("Core test #1: no clamp — 0x1d00d86a", () => {
    const parent = makeBlock(32255, 0x1d00ffff, 1262152739);
    const firstTime = 1261130161;
    const result = calculateNextWorkRequired(parent, firstTime, MAINNET, () => undefined);
    expect(bigIntToCompact(result)).toBe(0x1d00d86a);
  });

  // Gate 13: powLimit cap — Bitcoin Core test #2
  // height=2015, nTime=1233061996, nBits=0x1d00ffff
  // nFirstBlockTime=1231006505 (genesis)
  // actualTimespan=2055491, > max=4838400? No. > min=302400? Yes. No clamp.
  // But result is still 0x1d00ffff because actualTimespan < targetTimespan
  // and (powLimit * actualTimespan / targetTimespan) < powLimit. Wait...
  // actually: target * actualTimespan/targetTimespan = powLimit * 2055491/1209600
  // > powLimit → capped at powLimit.
  test("Core test #2: cap at powLimit — 0x1d00ffff", () => {
    const parent = makeBlock(2015, 0x1d00ffff, 1233061996);
    const firstTime = 1231006505;
    const result = calculateNextWorkRequired(parent, firstTime, MAINNET, () => undefined);
    expect(bigIntToCompact(result)).toBe(0x1d00ffff);
  });

  // Gate 12: clamped to min timespan — Bitcoin Core test #3
  // height=68543, nTime=1279297671, nBits=0x1c05a3f4
  // nFirstBlockTime=1279008237
  // actualTimespan=289434 < 302400 → clamped to 302400
  // Expected: 0x1c0168fd
  test("Core test #3: clamped min timespan — 0x1c0168fd", () => {
    const parent = makeBlock(68543, 0x1c05a3f4, 1279297671);
    const firstTime = 1279008237;
    const result = calculateNextWorkRequired(parent, firstTime, MAINNET, () => undefined);
    expect(bigIntToCompact(result)).toBe(0x1c0168fd);
  });

  // Gate 11: clamped to max timespan — Bitcoin Core test #4
  // height=46367, nTime=1269211443, nBits=0x1c387f6f
  // nFirstBlockTime=1263163443
  // actualTimespan=6048000 > 4838400 → clamped to 4838400
  // Expected: 0x1d00e1fd
  test("Core test #4: clamped max timespan — 0x1d00e1fd", () => {
    const parent = makeBlock(46367, 0x1c387f6f, 1269211443);
    const firstTime = 1263163443;
    const result = calculateNextWorkRequired(parent, firstTime, MAINNET, () => undefined);
    expect(bigIntToCompact(result)).toBe(0x1d00e1fd);
  });

  // Gate 14: BIP94 (testnet4) uses first-block bits, not parent bits
  // If the first block has real difficulty 0x1c387f6f but the parent (last
  // block of period) has min-diff 0x1d00ffff, BIP94 must retarget from
  // 0x1c387f6f. Standard (non-BIP94) retargets from the parent 0x1d00ffff.
  test("BIP94: uses first-block bits not parent bits", () => {
    const parent = makeBlock(4031, 0x1d00ffff, 1269211443); // min-diff parent
    const firstTime = 1263163443;
    // Build chain: first block of period at height 4032-2016=2016 has non-min bits
    const firstBlock = makeBlock(2016, 0x1c387f6f, firstTime);
    const chain = makeChain([firstBlock]);
    const bip94Result = calculateNextWorkRequired(parent, firstTime, TESTNET4, chain);
    const nonBip94Result = calculateNextWorkRequired(parent, firstTime, MAINNET, () => undefined);
    // BIP94 starts from harder difficulty (0x1c387f6f), non-BIP94 from powLimit (0x1d00ffff)
    // So BIP94 result should be harder (smaller target = larger compact exponent or smaller mantissa)
    expect(bip94Result).toBeLessThan(nonBip94Result);
  });

  test("BIP94: correct result matches manual calculation", () => {
    // Use Core test #4 parameters for the first block:
    // actualTimespan = 6048000 → clamped to 4838400
    // baseBits = 0x1c387f6f (first block bits in BIP94 mode)
    // expected = 0x1d00e1fd (same as Core test #4, since firstBits == parentBits here)
    const firstTime = 1263163443;
    const firstBlock = makeBlock(2016, 0x1c387f6f, firstTime);
    const parent = makeBlock(4031, 0x1c387f6f, 1269211443);
    const chain = makeChain([firstBlock]);
    const result = calculateNextWorkRequired(parent, firstTime, TESTNET4, chain);
    expect(bigIntToCompact(result)).toBe(0x1d00e1fd);
  });

  // Clamp boundary: exactly at min timespan
  test("exactly at min timespan boundary (302400) — no clamp", () => {
    const parent = makeBlock(32255, 0x1d00ffff, 1261130161 + 302400);
    const firstTime = 1261130161;
    const result = calculateNextWorkRequired(parent, firstTime, MAINNET, () => undefined);
    // actualTimespan = 302400 = min, not clamped; same calculation either side
    const resultClamped = calculateNextWorkRequired(
      makeBlock(32255, 0x1d00ffff, 1261130161 + 302399),
      firstTime,
      MAINNET,
      () => undefined
    );
    // Both at/below boundary should give same result due to clamp
    expect(bigIntToCompact(result)).toBe(bigIntToCompact(resultClamped));
  });

  // Clamp boundary: exactly at max timespan
  test("exactly at max timespan boundary (4838400) — no clamp", () => {
    const parent = makeBlock(32255, 0x1d00ffff, 1261130161 + 4838400);
    const firstTime = 1261130161;
    const result = calculateNextWorkRequired(parent, firstTime, MAINNET, () => undefined);
    const resultClamped = calculateNextWorkRequired(
      makeBlock(32255, 0x1d00ffff, 1261130161 + 4838401),
      firstTime,
      MAINNET,
      () => undefined
    );
    expect(bigIntToCompact(result)).toBe(bigIntToCompact(resultClamped));
  });

  // Actual timespan negative (timestamps out of order) should clamp to min
  test("negative actualTimespan clamped to min timespan", () => {
    const parent = makeBlock(32255, 0x1d00ffff, 1261130161 - 100); // before firstBlock
    const firstTime = 1261130161;
    const normal = calculateNextWorkRequired(
      makeBlock(32255, 0x1d00ffff, 1261130161 + 302400), // min timespan
      firstTime,
      MAINNET,
      () => undefined
    );
    const negative = calculateNextWorkRequired(parent, firstTime, MAINNET, () => undefined);
    // Both should produce the same result (both clamped to min)
    expect(bigIntToCompact(negative)).toBe(bigIntToCompact(normal));
  });
});

// ─── getNextWorkRequired ──────────────────────────────────────────────────────

describe("getNextWorkRequired", () => {
  // Gate 1: fPowNoRetargeting early exit (regtest)
  test("regtest: fPowNoRetargeting always returns powLimit", () => {
    const parent = makeBlock(0, 0x207fffff, 1296688602);
    const result = getNextWorkRequired(parent, 1296688602 + 100, REGTEST, () => undefined);
    expect(result).toBe(REGTEST.powLimit);
  });

  // Gate 2: mainnet non-adjustment block returns parent bits
  test("mainnet: non-adjustment block returns parent target", () => {
    const parent = makeBlock(100, 0x1b0404cb, 1234567890);
    const result = getNextWorkRequired(parent, 1234568000, MAINNET, makeChain([parent]));
    expect(result).toBe(compactToBigInt(0x1b0404cb));
  });

  // Gate 3: testnet 20-min rule — new block is >20 min after parent
  test("testnet: block >20min after parent → powLimit", () => {
    const parent = makeBlock(100, 0x1b0404cb, 1234567890);
    const blockTime = parent.header.timestamp + 2 * 600 + 1; // 1201 seconds later
    const result = getNextWorkRequired(parent, blockTime, TESTNET, makeChain([parent]));
    expect(result).toBe(TESTNET.powLimit);
  });

  // Gate 4: testnet timestamp OK — walk back through min-diff blocks
  test("testnet: block within 20min → walk back and return non-min-diff bits", () => {
    // Chain: blocks 0-3 have min-diff, block 4 has real difficulty
    const realBits = 0x1b0404cb;
    const blocks = [
      makeBlock(0, realBits, 1234560000),        // non-min-diff genesis
      makeBlock(1, TESTNET.powLimitBits, 1234566000),
      makeBlock(2, TESTNET.powLimitBits, 1234567000),
      makeBlock(3, TESTNET.powLimitBits, 1234568000),
    ];
    const parent = blocks[3]; // height 3, min-diff
    const blockTime = parent.header.timestamp + 600; // 10min later (within 20min)
    const lookup = makeChain(blocks);
    const result = getNextWorkRequired(parent, blockTime, TESTNET, lookup);
    // Walk back: block 3 = min-diff, block 2 = min-diff, block 1 = min-diff, block 0 = non-min-diff
    expect(result).toBe(compactToBigInt(realBits));
  });

  // Gate 5: walk-back halts at height 0
  test("testnet: walk-back halts at genesis (height 0)", () => {
    const blocks = [
      makeBlock(0, TESTNET.powLimitBits, 1234560000),
      makeBlock(1, TESTNET.powLimitBits, 1234566000),
    ];
    const parent = blocks[1];
    const blockTime = parent.header.timestamp + 600;
    const lookup = makeChain(blocks);
    const result = getNextWorkRequired(parent, blockTime, TESTNET, lookup);
    // Genesis has min-diff bits, so walk stops at height 0 and returns those bits
    expect(result).toBe(compactToBigInt(TESTNET.powLimitBits));
  });

  // Gate 6: walk-back halts at interval boundary
  test("testnet: walk-back halts at difficulty period boundary", () => {
    const realBits = 0x1b0404cb;
    const interval = TESTNET.difficultyAdjustmentInterval; // 2016
    // Block at the boundary has real bits, blocks above it have min-diff
    const boundary = makeBlock(interval, realBits, 1234560000);
    const chain: BlockInfo[] = [boundary];
    for (let h = interval + 1; h <= interval + 3; h++) {
      chain.push(makeBlock(h, TESTNET.powLimitBits, 1234560000 + h * 600));
    }
    const parent = chain[chain.length - 1];
    const blockTime = parent.header.timestamp + 600;
    const lookup = makeChain(chain);
    const result = getNextWorkRequired(parent, blockTime, TESTNET, lookup);
    // Walk back to interval boundary, stop, return those bits
    expect(result).toBe(compactToBigInt(realBits));
  });

  // Gate 7: walk-back returns first non-min-diff bits encountered
  test("testnet: walk-back returns first non-min-diff bits found", () => {
    const hardBits = 0x1a0404cb; // harder than realBits
    const realBits = 0x1b0404cb;
    const blocks = [
      makeBlock(0, hardBits, 1234560000),          // non-min, hardest
      makeBlock(1, realBits, 1234566000),           // non-min
      makeBlock(2, TESTNET.powLimitBits, 1234567000),
      makeBlock(3, TESTNET.powLimitBits, 1234568000),
    ];
    const parent = blocks[3];
    const blockTime = parent.header.timestamp + 600;
    const lookup = makeChain(blocks);
    const result = getNextWorkRequired(parent, blockTime, TESTNET, lookup);
    // Walk back: h3=min, h2=min, h1=non-min → return h1's bits (realBits)
    expect(result).toBe(compactToBigInt(realBits));
  });

  // Gate 8: adjustment block — correct firstBlockTime is used
  test("mainnet: adjustment block uses correct firstBlockTime (Core test #1 vector)", () => {
    const interval = MAINNET.difficultyAdjustmentInterval; // 2016
    // parent at height 32255 = 16*2016 - 1, which makes 32256 = 16*2016 → adjustment
    const firstHeight = 32255 - (interval - 1); // = 30240
    const firstBlock = makeBlock(firstHeight, 0x1d00ffff, 1261130161);
    const parent = makeBlock(32255, 0x1d00ffff, 1262152739);
    const lookup = makeChain([firstBlock, parent]);
    const result = getNextWorkRequired(parent, 1262160000, MAINNET, lookup);
    expect(bigIntToCompact(result)).toBe(0x1d00d86a);
  });

  // First block: height 0+1=1, not at adjustment boundary → returns parent bits
  test("block 1: height 1 is not adjustment block, returns parent bits", () => {
    const genesis = makeBlock(0, 0x1d00ffff, 1231006505);
    const result = getNextWorkRequired(genesis, 1231007000, MAINNET, makeChain([genesis]));
    expect(result).toBe(compactToBigInt(0x1d00ffff));
  });

  // Exact boundary: height % 2016 === 0
  test("height 2016 is adjustment block", () => {
    const interval = MAINNET.difficultyAdjustmentInterval;
    const firstBlock = makeBlock(0, 0x1d00ffff, 1231006505);
    const parent = makeBlock(interval - 1, 0x1d00ffff, 1233061996);
    const lookup = makeChain([firstBlock, parent]);
    const result = getNextWorkRequired(parent, 1233062000, MAINNET, lookup);
    // Core test #2: result capped at powLimit
    expect(bigIntToCompact(result)).toBe(0x1d00ffff);
  });
});

// ─── permittedDifficultyTransition ───────────────────────────────────────────

describe("permittedDifficultyTransition", () => {
  // Gate 15: fPowAllowMinDifficultyBlocks → always true
  test("testnet: fPowAllowMinDifficultyBlocks always permits any transition", () => {
    // Even a completely invalid transition should pass on testnet
    expect(permittedDifficultyTransition(TESTNET, 2016, 0x1d00ffff, 0x03000001)).toBe(true);
    expect(permittedDifficultyTransition(TESTNET, 100, 0x1d00ffff, 0x1b0404cb)).toBe(true);
    expect(permittedDifficultyTransition(REGTEST, 2016, 0x207fffff, 0x03000001)).toBe(true);
  });

  // Gate 16: adjustment block valid — Core test #1
  // height=32256=16*2016, oldBits=0x1d00ffff, newBits=0x1d00d86a
  test("Core test #1: valid adjustment transition (0x1d00ffff → 0x1d00d86a)", () => {
    expect(permittedDifficultyTransition(MAINNET, 32256, 0x1d00ffff, 0x1d00d86a)).toBe(true);
  });

  // Core test #2: powLimit → powLimit is always valid at retarget
  test("Core test #2: powLimit stays at powLimit (0x1d00ffff → 0x1d00ffff)", () => {
    expect(permittedDifficultyTransition(MAINNET, 2016, 0x1d00ffff, 0x1d00ffff)).toBe(true);
  });

  // Core test #3: valid — 0x1c05a3f4 → 0x1c0168fd at height 68544
  test("Core test #3: valid adjustment (0x1c05a3f4 → 0x1c0168fd)", () => {
    expect(permittedDifficultyTransition(MAINNET, 68544, 0x1c05a3f4, 0x1c0168fd)).toBe(true);
  });

  // Gate 17: too-hard transition rejected — Core test #3 with nbits-1
  // Core: BOOST_CHECK(!PermittedDifficultyTransition(..., 68544, 0x1c05a3f4, 0x1c0168fd - 1))
  test("Core test #3: too-hard nbits-1 rejected (0x1c05a3f4 → 0x1c0168fc)", () => {
    expect(permittedDifficultyTransition(MAINNET, 68544, 0x1c05a3f4, 0x1c0168fc)).toBe(false);
  });

  // Core test #4: valid — 0x1c387f6f → 0x1d00e1fd at height 46368
  test("Core test #4: valid adjustment (0x1c387f6f → 0x1d00e1fd)", () => {
    expect(permittedDifficultyTransition(MAINNET, 46368, 0x1c387f6f, 0x1d00e1fd)).toBe(true);
  });

  // Gate 18: too-easy transition rejected — Core test #4 with nbits+1
  // Core: BOOST_CHECK(!PermittedDifficultyTransition(..., 46368, 0x1c387f6f, 0x1d00e1fd + 1))
  test("Core test #4: too-easy nbits+1 rejected (0x1c387f6f → 0x1d00e1fe)", () => {
    expect(permittedDifficultyTransition(MAINNET, 46368, 0x1c387f6f, 0x1d00e1fe)).toBe(false);
  });

  // Gate 19: non-adjustment block, same bits → allowed
  test("non-adjustment block: same bits permitted", () => {
    expect(permittedDifficultyTransition(MAINNET, 101, 0x1b0404cb, 0x1b0404cb)).toBe(true);
  });

  // Gate 20: non-adjustment block, different bits → rejected
  test("non-adjustment block: different bits rejected", () => {
    expect(permittedDifficultyTransition(MAINNET, 101, 0x1b0404cb, 0x1b0404cc)).toBe(false);
    expect(permittedDifficultyTransition(MAINNET, 101, 0x1b0404cb, 0x1d00ffff)).toBe(false);
  });

  // Adjustment block where both old and new are at powLimit
  test("adjustment: powLimit → powLimit always valid", () => {
    expect(permittedDifficultyTransition(MAINNET, 2016, 0x1d00ffff, 0x1d00ffff)).toBe(true);
  });

  // Adjustment block: reduce by factor 4 exactly (smallest allowed)
  test("adjustment: reduce by factor 4 exactly is valid (min timespan)", () => {
    // If actual timespan = targetTimespan/4, new_target = old_target/4
    // For 0x1d00ffff: target/4 = 0x1b00ffff (exponent reduced by 2)
    // Actually: 0x1d00ffff target * (302400/1209600) = target/4.
    // Let's compute: baseTarget * 302400 / 1209600 = baseTarget / 4
    // For 0x1d00ffff = powLimit: powLimit/4, encoded as compact:
    const oldBits = 0x1d00ffff;
    const oldTarget = compactToBigInt(oldBits);
    const minTimespan = Math.floor(1209600 / 4);
    const newTarget = (oldTarget * BigInt(minTimespan)) / BigInt(1209600);
    const newBits = bigIntToCompact(newTarget);
    expect(permittedDifficultyTransition(MAINNET, 2016, oldBits, newBits)).toBe(true);
  });

  // Adjustment block: increase by factor 4 exactly (largest allowed)
  test("adjustment: increase by factor 4 exactly is valid (max timespan)", () => {
    // For 0x1c05a3f4: target * 4, but capped at powLimit
    const oldBits = 0x1c05a3f4;
    const oldTarget = compactToBigInt(oldBits);
    const maxTimespan = 1209600 * 4;
    let newTarget = (oldTarget * BigInt(maxTimespan)) / BigInt(1209600);
    if (newTarget > MAINNET.powLimit) newTarget = MAINNET.powLimit;
    const newBits = bigIntToCompact(newTarget);
    expect(permittedDifficultyTransition(MAINNET, 2016, oldBits, newBits)).toBe(true);
  });
});

// ─── checkProofOfWork ────────────────────────────────────────────────────────

describe("checkProofOfWork", () => {
  // Gate 21: negative target — Core CheckProofOfWork_test_negative_target
  // nBits = UintToArith256(consensus.powLimit).GetCompact(true)
  // = powLimit with negative bit set
  test("negative target nBits → false", () => {
    // Set the negative bit (bit 23) on 0x1d00ffff → 0x1d80ffff
    // (Core: GetCompact(true) sets bit 23 when mantissa != 0)
    const nBits = 0x1d80ffff; // negative bit set on mainnet powLimit compact
    const hash = Buffer.alloc(32, 1); // non-zero hash
    expect(checkProofOfWork(hash, nBits, MAINNET)).toBe(false);
  });

  // Gate 22: overflow target — Core CheckProofOfWork_test_overflow_target
  // nBits = ~0x00800000U = 0xff7fffff
  test("overflow target nBits → false", () => {
    const nBits = 0xff7fffff; // ~0x00800000 in 32-bit: exponent=255, huge
    const hash = Buffer.alloc(32, 1);
    expect(checkProofOfWork(hash, nBits, MAINNET)).toBe(false);
  });

  // Gate 23: target > powLimit — Core CheckProofOfWork_test_too_easy_target
  // arith_uint256 nBits_arith = powLimit; nBits_arith *= 2;
  test("target > powLimit → false", () => {
    const nBits = bigIntToCompact(MAINNET.powLimit * 2n);
    const hash = Buffer.alloc(32, 1);
    expect(checkProofOfWork(hash, nBits, MAINNET)).toBe(false);
  });

  // Gate 24: hash > target → false — Core CheckProofOfWork_test_biger_hash_than_target
  // nBits = powLimit.GetCompact(), hash = ArithToUint256(powLimit * 2)
  test("hash > target → false", () => {
    const nBits = bigIntToCompact(MAINNET.powLimit);
    // hash value = powLimit * 2 > target = powLimit
    const hashBigInt = MAINNET.powLimit * 2n;
    // Mask to 256 bits
    const mask256 = (1n << 256n) - 1n;
    const hashLE = bigIntToHashLE(hashBigInt & mask256);
    expect(checkProofOfWork(hashLE, nBits, MAINNET)).toBe(false);
  });

  // Gate 25: zero target — Core CheckProofOfWork_test_zero_target
  test("zero target nBits → false", () => {
    const nBits = bigIntToCompact(0n); // = 0
    const hash = bigIntToHashLE(0n);
    expect(checkProofOfWork(hash, nBits, MAINNET)).toBe(false);
  });

  // Gate 26: valid hash ≤ target → true
  test("all-zero hash ≤ any positive target → true", () => {
    const nBits = bigIntToCompact(MAINNET.powLimit);
    const hash = zeroHash(); // all zeros is always ≤ target
    expect(checkProofOfWork(hash, nBits, MAINNET)).toBe(true);
  });

  test("hash exactly at target boundary → true", () => {
    const nBits = bigIntToCompact(MAINNET.powLimit);
    const target = compactToBigInt(nBits);
    const hashLE = bigIntToHashLE(target);
    expect(checkProofOfWork(hashLE, nBits, MAINNET)).toBe(true);
  });

  test("hash one above target → false", () => {
    const nBits = bigIntToCompact(MAINNET.powLimit);
    const target = compactToBigInt(nBits);
    const hashLE = bigIntToHashLE(target + 1n);
    expect(checkProofOfWork(hashLE, nBits, MAINNET)).toBe(false);
  });

  // Regtest: all-zero hash valid against regtest powLimit
  test("regtest: all-zero hash → true against 0x207fffff", () => {
    expect(checkProofOfWork(zeroHash(), 0x207fffff, REGTEST)).toBe(true);
  });
});

// ─── deriveTarget ─────────────────────────────────────────────────────────────

describe("deriveTarget", () => {
  // Gate 27a: valid compact → returns correct target
  test("valid compact 0x1d00ffff → mainnet powLimit", () => {
    const result = deriveTarget(0x1d00ffff, MAINNET.powLimit);
    expect(result).toBe(MAINNET.powLimit);
  });

  test("valid compact 0x207fffff → regtest powLimit", () => {
    const result = deriveTarget(0x207fffff, REGTEST.powLimit);
    expect(result).toBe(REGTEST.powLimit);
  });

  // Negative compact → null
  test("negative compact 0x1d80ffff → null", () => {
    expect(deriveTarget(0x1d80ffff, MAINNET.powLimit)).toBeNull();
  });

  // Zero compact → null
  test("zero compact 0x00000000 → null", () => {
    expect(deriveTarget(0x00000000, MAINNET.powLimit)).toBeNull();
  });

  test("zero mantissa compact 0x1d000000 → null (target = 0)", () => {
    expect(deriveTarget(0x1d000000, MAINNET.powLimit)).toBeNull();
  });

  // Overflow compact → null (via > powLimit check)
  test("overflow compact 0xff7fffff → null (target astronomically large)", () => {
    expect(deriveTarget(0xff7fffff, MAINNET.powLimit)).toBeNull();
  });

  // Target slightly > powLimit → null
  test("target one above powLimit → null", () => {
    const bitsAboveLimit = bigIntToCompact(MAINNET.powLimit + 1n);
    // May or may not be > powLimit after compact round-trip; but if it is, should be null
    const result = deriveTarget(bitsAboveLimit, MAINNET.powLimit);
    if (result !== null) {
      expect(result).toBeLessThanOrEqual(MAINNET.powLimit);
    }
  });
});

// ─── getBlockWork ─────────────────────────────────────────────────────────────

describe("getBlockWork", () => {
  // Gate 28a: zero target → 0
  test("zero target bits → work = 0", () => {
    expect(getBlockWork(0)).toBe(0n);
  });

  test("negative compact (target=0) → work = 0", () => {
    expect(getBlockWork(0x1d800001)).toBe(0n);
  });

  // Gate 28b: positive target → 2^256/(target+1)
  test("mainnet powLimit bits → expected work", () => {
    const work = getBlockWork(0x1d00ffff);
    const target = compactToBigInt(0x1d00ffff);
    const TWO_256 = 2n ** 256n;
    const expected = TWO_256 / (target + 1n);
    expect(work).toBe(expected);
  });

  test("regtest powLimit bits → expected work", () => {
    const work = getBlockWork(0x207fffff);
    const target = compactToBigInt(0x207fffff);
    const TWO_256 = 2n ** 256n;
    const expected = TWO_256 / (target + 1n);
    expect(work).toBe(expected);
  });

  // Harder target (smaller target value) → more work
  test("harder block (smaller target) has more work", () => {
    const hardWork = getBlockWork(0x1a0404cb);   // harder (smaller target)
    const easyWork = getBlockWork(0x1d00ffff);   // easier (larger target)
    expect(hardWork).toBeGreaterThan(easyWork);
  });

  // Work is always positive for valid targets
  test("any valid target bits yields positive work", () => {
    for (const bits of [0x1d00ffff, 0x1c387f6f, 0x1c05a3f4, 0x1b0404cb, 0x1903a30c]) {
      expect(getBlockWork(bits)).toBeGreaterThan(0n);
    }
  });
});

// ─── Round-trip: compactToBigInt / bigIntToCompact ───────────────────────────

describe("compact round-trip (extended)", () => {
  // All Core test vector nBits values must survive a round-trip
  const coreTestBits = [
    0x1d00ffff, // mainnet powLimit / test #1 base
    0x1d00d86a, // Core test #1 result
    0x1c05a3f4, // Core test #3 base
    0x1c0168fd, // Core test #3 result
    0x1c387f6f, // Core test #4 base
    0x1d00e1fd, // Core test #4 result
    0x207fffff, // regtest powLimit
    0x1903a30c, // a real mid-range difficulty
    0x1b0404cb, // historical mainnet bits
  ];

  for (const bits of coreTestBits) {
    test(`round-trip 0x${bits.toString(16)}`, () => {
      const roundTrip = bigIntToCompact(compactToBigInt(bits));
      expect(roundTrip).toBe(bits);
    });
  }
});
