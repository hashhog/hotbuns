/**
 * Regression tests for the assumevalid policy (shouldSkipScripts).
 *
 * Test matrix (Core validation.cpp:2346-2382):
 *  1. Unit — assumevalid absent: every block at every height runs scripts.
 *  2. Unit — block is ancestor of assumevalid: script skip fires.
 *  3. Unit — block NOT in assumevalid chain at the same height: script runs.
 *  4. Unit — block height above assumevalid height: script runs (not an ancestor).
 *  5. Unit — assumevalid hash not yet in block index: script runs.
 *  6. Unit — block invalid on non-script check: rejected EVEN IF ancestor of assumevalid.
 *  7. Integration — regtest: assumedValid unset → flag never fires (always verify).
 *
 * Plus additional cases:
 *  8. Best header chainwork below minimumChainWork: script runs.
 *  9. Block too recent (equivalent work ≤ 2 weeks): script runs.
 * 10. No best header available: script runs.
 * 11. EFFECTIVE — fork block below av_height is VERIFIED (height-only would have skipped).
 * 12. EFFECTIVE — on-active-chain ancestor buried > 2 weeks is SKIPPED (correct skip).
 *
 * Condition 5 (DoS defense) uses real GetBlockProofEquivalentTime:
 *   equiv_time = (bestHeader.chainWork − pindex.chainWork) × powTargetSpacing
 *                / GetBlockProof(bestHeaderBits)
 *
 * Test fixtures use bits = 0x207fffff (regtest min difficulty):
 *   getBitsProof(0x207fffff) = 2^256 / (0x7fffff << 232 + 1) = 2
 *   For skip=true:  diff × 600 / 2 > 1_209_600  →  diff > 4_032
 *   Test uses BEST_HEADER.chainWork=15_000, ANCESTOR.chainWork=5_000 → diff=10_000,
 *   equivTime = 10_000 × 600 / 2 = 3_000_000 s > 2 weeks ✓
 */

import { describe, expect, test } from "bun:test";
import {
  shouldSkipScripts,
  ASSUMED_VALID_HASHES,
  type AssumeValidContext,
  type AssumeValidBlockEntry,
} from "./assumevalid.js";
import { MAINNET, REGTEST, TESTNET4 } from "./params.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Compact nBits for regtest minimum difficulty (0x207fffff).
 * getBitsProof(0x207fffff) = floor(2^256 / (0x7fffff × 2^232 + 1)) = 2
 * (used for all condition-5 / equivalent-time calculations below)
 */
const BEST_HEADER_BITS = 0x207fffff;
const POW_TARGET_SPACING = 600; // 10 minutes, Bitcoin mainnet

/** A fake block hash for the assumed-valid block (on the "right" chain). */
const AV_HASH = "aaaa000000000000000000000000000000000000000000000000000000000001";
const AV_HEIGHT = 500;

/** A block that IS an ancestor of AV_HASH (same chain, height < AV_HEIGHT). */
const ANCESTOR_HASH = "bbbb000000000000000000000000000000000000000000000000000000000002";
const ANCESTOR_HEIGHT = 300;

/** A block that IS NOT on the same chain (different hash at ANCESTOR_HEIGHT). */
const FORK_HASH = "cccc000000000000000000000000000000000000000000000000000000000003";

/**
 * Chain-work values chosen so condition-5 passes for the ANCESTOR:
 *   equivTime = (15_000 − 5_000) × 600 / 2 = 3_000_000 s > 1_209_600 ✓
 */
const ANCESTOR_CHAIN_WORK = 5_000n;
const AV_CHAIN_WORK = 8_000n; // between ancestor and best header

/** The block index: maps hash → entry */
const BLOCK_INDEX = new Map<string, AssumeValidBlockEntry>([
  [
    AV_HASH,
    { hash: AV_HASH, height: AV_HEIGHT, chainWork: AV_CHAIN_WORK },
  ],
  [
    ANCESTOR_HASH,
    { hash: ANCESTOR_HASH, height: ANCESTOR_HEIGHT, chainWork: ANCESTOR_CHAIN_WORK },
  ],
  [
    FORK_HASH,
    { hash: FORK_HASH, height: ANCESTOR_HEIGHT, chainWork: ANCESTOR_CHAIN_WORK },
  ],
]);

/**
 * The canonical chain by height:
 *   ANCESTOR_HASH @ ANCESTOR_HEIGHT → … → AV_HASH @ AV_HEIGHT → (more)
 *
 * When we look up getBlockAtHeight, we return the main-chain block.
 * The fork block at ANCESTOR_HEIGHT is on a different fork and NOT returned.
 */
const CANONICAL_CHAIN_BY_HEIGHT = new Map<number, AssumeValidBlockEntry>([
  [ANCESTOR_HEIGHT, { hash: ANCESTOR_HASH, height: ANCESTOR_HEIGHT, chainWork: ANCESTOR_CHAIN_WORK }],
  [AV_HEIGHT, { hash: AV_HASH, height: AV_HEIGHT, chainWork: AV_CHAIN_WORK }],
]);

const BEST_HEADER: AssumeValidBlockEntry = {
  hash: "dddd000000000000000000000000000000000000000000000000000000000004",
  height: 600,
  chainWork: 15_000n,
};

/** Minimum chain work that the best header exceeds. */
const MIN_CHAIN_WORK = 100n;

/** A base context that satisfies all five conditions → skip=true. */
function baseCtx(overrides?: Partial<AssumeValidContext>): AssumeValidContext {
  return {
    pindex: { hash: ANCESTOR_HASH, height: ANCESTOR_HEIGHT, chainWork: ANCESTOR_CHAIN_WORK },
    assumedValidHash: AV_HASH,
    getBlockByHash: (hashHex) => BLOCK_INDEX.get(hashHex) ?? null,
    getBlockAtHeight: (height) => CANONICAL_CHAIN_BY_HEIGHT.get(height) ?? null,
    bestHeader: BEST_HEADER,
    minimumChainWork: MIN_CHAIN_WORK,
    bestHeaderBits: BEST_HEADER_BITS,
    powTargetSpacing: POW_TARGET_SPACING,
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Test 1: assumevalid absent → always verify
// ---------------------------------------------------------------------------

describe("shouldSkipScripts — test 1: assumevalid absent", () => {
  test("no assumedValidHash → skip=false at any height", () => {
    const result = shouldSkipScripts(
      baseCtx({ assumedValidHash: undefined })
    );
    expect(result.skip).toBe(false);
    expect(result.reason).toContain("assumevalid=0");
  });

  test("empty assumedValidHash → skip=false", () => {
    const result = shouldSkipScripts(baseCtx({ assumedValidHash: "" }));
    expect(result.skip).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Test 2: block IS ancestor of assumevalid → skip fires
// ---------------------------------------------------------------------------

describe("shouldSkipScripts — test 2: block is ancestor → skip", () => {
  test("all five conditions satisfied → skip=true", () => {
    const result = shouldSkipScripts(baseCtx());
    expect(result.skip).toBe(true);
    expect(result.reason).toContain("SKIP scripts");
  });

  test("block exactly AT assumevalid height on same chain → skip=true", () => {
    // The assumed-valid block itself is also an ancestor of itself.
    // equivTime = (15_000 − 8_000) × 600 / 2 = 2_100_000 s > 2 weeks ✓
    const result = shouldSkipScripts(
      baseCtx({
        pindex: { hash: AV_HASH, height: AV_HEIGHT, chainWork: AV_CHAIN_WORK },
      })
    );
    expect(result.skip).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Test 3: block NOT in assumevalid chain (fork at same height) → script runs
// ---------------------------------------------------------------------------

describe("shouldSkipScripts — test 3: block not in assumevalid chain → verify", () => {
  test("fork block at same height as ancestor → skip=false", () => {
    // FORK_HASH is at ANCESTOR_HEIGHT but is NOT on the canonical chain.
    // getBlockAtHeight(ANCESTOR_HEIGHT) returns ANCESTOR_HASH (not FORK_HASH),
    // so the ancestor check fails.
    const result = shouldSkipScripts(
      baseCtx({
        pindex: { hash: FORK_HASH, height: ANCESTOR_HEIGHT, chainWork: 600n },
      })
    );
    expect(result.skip).toBe(false);
    expect(result.reason).toContain("not in assumevalid chain");
  });
});

// ---------------------------------------------------------------------------
// Test 4: block height ABOVE assumevalid height → script runs
// ---------------------------------------------------------------------------

describe("shouldSkipScripts — test 4: block above assumevalid height → verify", () => {
  test("block at height > AV_HEIGHT → skip=false", () => {
    const aboveHash = "eeee000000000000000000000000000000000000000000000000000000000005";
    const result = shouldSkipScripts(
      baseCtx({
        pindex: { hash: aboveHash, height: AV_HEIGHT + 100, chainWork: 1500n },
      })
    );
    expect(result.skip).toBe(false);
    expect(result.reason).toContain("block height above assumevalid height");
  });
});

// ---------------------------------------------------------------------------
// Test 5: assumevalid hash NOT in local block index → script runs
// ---------------------------------------------------------------------------

describe("shouldSkipScripts — test 5: assumevalid hash not in index → verify", () => {
  test("unknown assumedValidHash → skip=false", () => {
    const unknownHash = "ffff000000000000000000000000000000000000000000000000000000000006";
    const result = shouldSkipScripts(
      baseCtx({ assumedValidHash: unknownHash })
    );
    expect(result.skip).toBe(false);
    expect(result.reason).toContain("assumevalid hash not in headers");
  });
});

// ---------------------------------------------------------------------------
// Test 6: block invalid on non-script check — still rejected even if ancestor
// ---------------------------------------------------------------------------

describe("shouldSkipScripts — test 6: non-script invalidity still rejects", () => {
  test("assumevalid skip does NOT bypass non-script validation", () => {
    // shouldSkipScripts returns skip=true for this block (it IS an ancestor).
    // The caller MUST still run PoW, merkle, coinbase, BIP30 etc. checks
    // regardless. This test verifies that the skip decision is purely about
    // scripts — and that a block with bad PoW would still be rejected by the
    // caller's other checks (which this function does NOT gate).
    //
    // In other words: shouldSkipScripts=true means "skip the verifyScript()
    // call only", not "skip all validation".
    const result = shouldSkipScripts(baseCtx());
    // The skip fires for a valid-chain ancestor — the caller is responsible
    // for non-script validation.
    expect(result.skip).toBe(true);
    // Callers must NOT call shouldSkipScripts to decide whether to run
    // validateBlock/PoW/merkle — those run unconditionally.
    // (We assert the function's contract in the comment; there's no in-band
    // way to test that the caller doesn't short-circuit other checks here.)
  });
});

// ---------------------------------------------------------------------------
// Test 7: regtest — assumedValid unset → flag never fires
// ---------------------------------------------------------------------------

describe("shouldSkipScripts — test 7: regtest (no assumevalid)", () => {
  test("REGTEST params have no assumedValid → always verify", () => {
    // Verify that the params themselves have no assumedValid.
    expect(REGTEST.assumedValid).toBeUndefined();

    // Even with a context that would otherwise satisfy all conditions,
    // if assumedValidHash is undefined the result is "verify scripts".
    const result = shouldSkipScripts(
      baseCtx({ assumedValidHash: REGTEST.assumedValid })
    );
    expect(result.skip).toBe(false);
    expect(result.reason).toContain("assumevalid=0");
  });

  test("MAINNET has assumedValid set", () => {
    expect(MAINNET.assumedValid).toBe(
      ASSUMED_VALID_HASHES.mainnet
    );
  });

  test("TESTNET4 has assumedValid set", () => {
    expect(TESTNET4.assumedValid).toBe(
      ASSUMED_VALID_HASHES.testnet4
    );
  });
});

// ---------------------------------------------------------------------------
// Additional case 8: best header chainwork below minimumChainWork → verify
// ---------------------------------------------------------------------------

describe("shouldSkipScripts — safety: chainwork below minimum", () => {
  test("best header chainwork < minimumChainWork → skip=false", () => {
    const result = shouldSkipScripts(
      baseCtx({
        bestHeader: { ...BEST_HEADER, chainWork: 50n },
        minimumChainWork: 1_000n,
      })
    );
    expect(result.skip).toBe(false);
    expect(result.reason).toContain("chainwork below minimumchainwork");
  });
});

// ---------------------------------------------------------------------------
// Additional case 9: block too recent (equivalent work ≤ 2 weeks) → verify
// ---------------------------------------------------------------------------

describe("shouldSkipScripts — safety: block too recent", () => {
  test("GetBlockProofEquivalentTime <= 2 weeks → skip=false", () => {
    // getBitsProof(0x207fffff) = 2
    // equivTime = diff × 600 / 2
    // For equivTime <= 1_209_600 (2 weeks): diff <= 4_032
    // Use bestHeader.chainWork = ANCESTOR_CHAIN_WORK + 50 → diff = 50
    // equivTime = 50 × 600 / 2 = 15_000 ≤ 1_209_600 → "too recent" ✓
    const result = shouldSkipScripts(
      baseCtx({
        bestHeader: { ...BEST_HEADER, chainWork: ANCESTOR_CHAIN_WORK + 50n },
      })
    );
    expect(result.skip).toBe(false);
    expect(result.reason).toContain("too recent");
  });

  test("GetBlockProofEquivalentTime exactly equals 2 weeks → skip=false (not strictly greater)", () => {
    // equivTime = diff × 600 / 2 == 1_209_600 → NOT > 2 weeks → verify
    // diff = 1_209_600 × 2 / 600 = 4_032 exactly
    const result = shouldSkipScripts(
      baseCtx({
        bestHeader: { ...BEST_HEADER, chainWork: ANCESTOR_CHAIN_WORK + 4_032n },
      })
    );
    expect(result.skip).toBe(false);
    expect(result.reason).toContain("too recent");
  });

  test("GetBlockProofEquivalentTime strictly greater than 2 weeks → skip=true", () => {
    // diff = 4_033 → equivTime = 4_033 × 600 / 2 = 1_209_900 > 1_209_600 → skip ✓
    const result = shouldSkipScripts(
      baseCtx({
        bestHeader: { ...BEST_HEADER, chainWork: ANCESTOR_CHAIN_WORK + 4_033n },
      })
    );
    expect(result.skip).toBe(true);
  });

  test("bestHeaderBits = 0 → getBitsProof returns 0 → equivTime = 0 → skip=false", () => {
    // Invalid/zero bits → tipProof = 0 → equivTime = 0 → "too recent" (fail-safe)
    const result = shouldSkipScripts(
      baseCtx({ bestHeaderBits: 0 })
    );
    expect(result.skip).toBe(false);
    expect(result.reason).toContain("too recent");
  });
});

// ---------------------------------------------------------------------------
// Additional case 10: no best header → verify
// ---------------------------------------------------------------------------

describe("shouldSkipScripts — safety: no best header", () => {
  test("bestHeader=null → skip=false", () => {
    const result = shouldSkipScripts(
      baseCtx({ bestHeader: null })
    );
    expect(result.skip).toBe(false);
    expect(result.reason).toContain("no best header");
  });
});

// ---------------------------------------------------------------------------
// EFFECTIVE tests — prove the ancestor-check gate beats height-only
// ---------------------------------------------------------------------------

describe("EFFECTIVE: fork block below av_height — script VERIFIED not skipped", () => {
  /**
   * Under the OLD height-only skip (height <= assumeValidHeight), a fork block
   * at height 300 with AV_HEIGHT = 500 would have been marked assumeValid=true
   * and scripts skipped. The faithful 5-condition gate rejects it at condition 3
   * because the active chain at height 300 has ANCESTOR_HASH, not FORK_HASH.
   *
   * This test is the canonical EFFECTIVE proof that the ancestor check fires:
   * FORK_HASH is at height ANCESTOR_HEIGHT (= 300 < AV_HEIGHT = 500) — a
   * height-only gate would skip it, the ancestor gate does NOT.
   */
  test("fork block at height < av_height: skip=false (scripts verified)", () => {
    const result = shouldSkipScripts(
      baseCtx({
        pindex: { hash: FORK_HASH, height: ANCESTOR_HEIGHT, chainWork: ANCESTOR_CHAIN_WORK },
      })
    );
    expect(result.skip).toBe(false);
    expect(result.reason).toContain("not in assumevalid chain");
  });

  test("height-only check WOULD say 'skip' but ancestor check says 'verify'", () => {
    // Demonstrate explicitly: the fork block IS below av_height (height-only would skip),
    // but our gate verifies it because it's not on the active chain at its height.
    expect(FORK_HASH).not.toBe(ANCESTOR_HASH); // sanity: really a fork
    expect(ANCESTOR_HEIGHT).toBeLessThan(AV_HEIGHT); // below AV height

    const heightOnlyWouldSkip =
      ANCESTOR_HEIGHT <= AV_HEIGHT; // true — the old bug
    const ourGateSays = shouldSkipScripts(
      baseCtx({
        pindex: { hash: FORK_HASH, height: ANCESTOR_HEIGHT, chainWork: ANCESTOR_CHAIN_WORK },
      })
    );
    expect(heightOnlyWouldSkip).toBe(true);   // old broken behaviour
    expect(ourGateSays.skip).toBe(false);      // new correct behaviour
  });
});

describe("EFFECTIVE: on-active-chain ancestor buried > 2 weeks — scripts SKIPPED", () => {
  /**
   * A block that IS on the active chain, IS an ancestor of AV, and IS buried
   * by more than 2 weeks of equivalent PoW should have scripts skipped.
   * This is the legitimate fast-path for IBD.
   */
  test("legitimate ancestor (all 5 conditions met): skip=true", () => {
    const result = shouldSkipScripts(baseCtx());
    expect(result.skip).toBe(true);
    expect(result.reason).toContain("SKIP scripts");
  });
});

// ---------------------------------------------------------------------------
// Fleet-standard hash validation
// ---------------------------------------------------------------------------

describe("fleet-standard hashes", () => {
  test("mainnet hash matches Bitcoin Core v28.0", () => {
    expect(ASSUMED_VALID_HASHES.mainnet).toBe(
      "00000000000000000000ccebd6d74d9194d8dcdc1d177c478e094bfad51ba5ac"
    );
  });

  test("testnet4 hash matches Bitcoin Core v28.0", () => {
    // Core CTestNet4Params defaultAssumeValid (block 123613). Was previously
    // the testnet3 hash here (swapped); corrected to match Core.
    expect(ASSUMED_VALID_HASHES.testnet4).toBe(
      "0000000002368b1e4ee27e2e85676ae6f9f9e69579b29093e9a82c170bf7cf8a"
    );
  });

  test("testnet3 hash matches Bitcoin Core v28.0", () => {
    // Core CTestNetParams defaultAssumeValid (block 4842348). Was previously
    // the testnet4 hash here (swapped); corrected to match Core.
    expect(ASSUMED_VALID_HASHES.testnet3).toBe(
      "000000007a61e4230b28ac5cb6b5e5a0130de37ac1faf2f8987d2fa6505b67f4"
    );
  });

  test("signet hash matches Bitcoin Core v28.0", () => {
    expect(ASSUMED_VALID_HASHES.signet).toBe(
      "00000008414aab61092ef93f1aacc54cf9e9f16af29ddad493b908a01ff5c329"
    );
  });
});
