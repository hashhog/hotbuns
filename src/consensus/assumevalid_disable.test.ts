/**
 * VERIFY-FIRST regression tests for the assume-valid DISABLE knob
 * (`--assumevalid=0` / `--noassumevalid` / env `HOTBUNS_ASSUMEVALID=0`), used by
 * the mainnet-replay harness to force FULL script verification of all history.
 *
 * The knob works entirely at the params level: `disableAssumeValid(params)`
 * zeroes `assumeValidHeight` and clears `assumedValid` (the hash). The two live
 * callers of the gate (`sync/blocks.ts:3572`, `mempool/mempool.ts:2132`) source
 * `assumedValidHash` from `params.assumedValid`, and `shouldSkipScripts()`
 * short-circuits to `skip=false` the instant that hash is undefined — mirroring
 * Bitcoin Core validation.cpp, where a null/Nothing assumed-valid block makes
 * the skip gate always fall through to full verification.
 *
 * EFFECTIVE assertion (test 3): a block BELOW the old assumevalid height that
 * satisfies ALL five skip conditions returns skip=true with the fleet-standard
 * mainnet params, and skip=false once the params are passed through
 * disableAssumeValid() — proving the flag flips the actual code path, not dead
 * code.
 */

import { describe, expect, test } from "bun:test";
import {
  shouldSkipScripts,
  type AssumeValidContext,
  type AssumeValidBlockEntry,
} from "./assumevalid.js";
import { MAINNET, disableAssumeValid } from "./params.js";

// ---------------------------------------------------------------------------
// Fixture: a canonical chain where BLOCK_BELOW is an ancestor of the
// fleet-standard mainnet assumevalid block, and all DoS/chainwork conditions
// are satisfied so that (with AV enabled) the skip WOULD fire.
// ---------------------------------------------------------------------------

const BEST_HEADER_BITS = 0x207fffff; // getBitsProof = 2
const POW_TARGET_SPACING = 600;

// Reuse the REAL mainnet assumevalid hash so the "enabled" branch exercises the
// exact value production wires in via params.assumedValid.
const AV_HASH = MAINNET.assumedValid as string;
const AV_HEIGHT = 500;

// A block strictly below the old assumevalid height — the region the harness
// cares about (~99% of history that default assumevalid would skip).
const BLOCK_BELOW_HASH =
  "bbbb000000000000000000000000000000000000000000000000000000000002";
const BLOCK_BELOW_HEIGHT = 300;

const BLOCK_BELOW_CHAIN_WORK = 5_000n;
const AV_CHAIN_WORK = 8_000n;

const BLOCK_INDEX = new Map<string, AssumeValidBlockEntry>([
  [AV_HASH, { hash: AV_HASH, height: AV_HEIGHT, chainWork: AV_CHAIN_WORK }],
  [
    BLOCK_BELOW_HASH,
    {
      hash: BLOCK_BELOW_HASH,
      height: BLOCK_BELOW_HEIGHT,
      chainWork: BLOCK_BELOW_CHAIN_WORK,
    },
  ],
]);

const CANONICAL_CHAIN_BY_HEIGHT = new Map<number, AssumeValidBlockEntry>([
  [
    BLOCK_BELOW_HEIGHT,
    {
      hash: BLOCK_BELOW_HASH,
      height: BLOCK_BELOW_HEIGHT,
      chainWork: BLOCK_BELOW_CHAIN_WORK,
    },
  ],
  [AV_HEIGHT, { hash: AV_HASH, height: AV_HEIGHT, chainWork: AV_CHAIN_WORK }],
]);

const BEST_HEADER: AssumeValidBlockEntry = {
  hash: "dddd000000000000000000000000000000000000000000000000000000000004",
  height: 600,
  chainWork: 15_000n,
};

/**
 * A context for a block BELOW the old assumevalid height that satisfies every
 * skip condition. `assumedValidHash` is left to the caller so we can feed it
 * either the enabled (real hash) or disabled (undefined) params.
 */
function ctxForBelowBlock(
  assumedValidHash: string | undefined,
): AssumeValidContext {
  return {
    pindex: {
      hash: BLOCK_BELOW_HASH,
      height: BLOCK_BELOW_HEIGHT,
      chainWork: BLOCK_BELOW_CHAIN_WORK,
    },
    assumedValidHash,
    getBlockByHash: (h) => BLOCK_INDEX.get(h) ?? null,
    getBlockAtHeight: (h) => CANONICAL_CHAIN_BY_HEIGHT.get(h) ?? null,
    bestHeader: BEST_HEADER,
    minimumChainWork: 100n,
    bestHeaderBits: BEST_HEADER_BITS,
    powTargetSpacing: POW_TARGET_SPACING,
  };
}

// ---------------------------------------------------------------------------
// Test 1: disableAssumeValid() zeroes the params (height + hash)
// ---------------------------------------------------------------------------

describe("disableAssumeValid — params override", () => {
  test("clears assumedValid hash and zeroes assumeValidHeight", () => {
    // Precondition: mainnet ships a real assumevalid hash + non-zero height.
    expect(MAINNET.assumedValid).toBeTruthy();
    expect(MAINNET.assumeValidHeight).toBeGreaterThan(0);

    const disabled = disableAssumeValid(MAINNET);
    expect(disabled.assumedValid).toBeUndefined();
    expect(disabled.assumeValidHeight).toBe(0);
  });

  test("does not mutate the source params object", () => {
    const before = MAINNET.assumedValid;
    disableAssumeValid(MAINNET);
    expect(MAINNET.assumedValid).toBe(before);
    expect(MAINNET.assumeValidHeight).toBeGreaterThan(0);
  });
});

// ---------------------------------------------------------------------------
// Test 2: control — with AV ENABLED, the below-AV block DOES skip scripts
// (establishes that the fixture reaches the skip=true path, so test 3 is a
//  genuine flip and not vacuously false).
// ---------------------------------------------------------------------------

describe("assumevalid ENABLED (control)", () => {
  test("block below assumevalid height → skip=true", () => {
    const result = shouldSkipScripts(ctxForBelowBlock(MAINNET.assumedValid));
    expect(result.skip).toBe(true);
    expect(result.reason).toContain("SKIP scripts");
  });
});

// ---------------------------------------------------------------------------
// Test 3: EFFECTIVE — with the DISABLE knob, the SAME below-AV block goes
// through FULL script verification (skip=false).
// ---------------------------------------------------------------------------

describe("assumevalid DISABLED (--assumevalid=0)", () => {
  test("block below old assumevalid height → skip=false (full verify)", () => {
    const disabled = disableAssumeValid(MAINNET);
    const result = shouldSkipScripts(ctxForBelowBlock(disabled.assumedValid));

    // EFFECTIVE assert: the computed skip decision is false — the script
    // verification code path runs for a block that WOULD have been skipped
    // (test 2) under the default fleet-standard params.
    expect(result.skip).toBe(false);
    expect(result.reason).toContain("assumevalid=0");
  });
});
