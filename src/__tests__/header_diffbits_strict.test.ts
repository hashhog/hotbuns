/**
 * Regression test for P0-4 (CORE-PARITY-AUDIT/hotbuns-P0-FOUND.md).
 *
 * sync/headers.ts validateHeader() previously accepted a header whose `bits`
 * differed from the expected GetNextWorkRequired result, as long as the
 * decoded target stayed within `[expected/2, expected*2]`.  That is a
 * +/-50% cheap-mining attack vector: a peer could publish blocks at half
 * the required difficulty and hotbuns would accept them, even though every
 * other Bitcoin node would reject them.
 *
 * Bitcoin Core enforces strict equality (validation.cpp
 * ContextualCheckBlockHeader):
 *   if (block.nBits != GetNextWorkRequired(pindexPrev, &block, consensusParams))
 *     return state.Invalid(BlockValidationResult::BLOCK_INVALID_HEADER,
 *                          "bad-diffbits", ...);
 *
 * Fix: the [/2, *2] tolerance window was deleted; validateHeader now returns
 * `bad-diffbits` if header.bits !== bigIntToCompact(getNextTarget(parent)).
 *
 * Test setup:
 *   - REGTEST-derived params with retargeting RE-ENABLED so getNextTarget at
 *     a non-retarget height returns compactToBigInt(parent.bits) (the
 *     mainnet-shape rule), NOT the unconditional powLimit fallback.
 *   - Keep REGTEST's huge powLimit (powLimitBits = 0x207fffff) so the
 *     test header's PoW is trivially satisfied at any nonce — the test
 *     never blocks on hashing.
 *   - Parent at height 100 with bits chosen so:
 *       * the value round-trips through compact encoding
 *         (bigIntToCompact(compactToBigInt(b)) == b)
 *       * the target has 50%+ headroom up to powLimit (so a "1.5x easier"
 *         tampered bits can be encoded without tripping the powLimit gate)
 */

import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { mkdtemp, rm } from "fs/promises";
import { tmpdir } from "os";
import { join } from "path";
import { ChainDB } from "../storage/database.js";
import {
  REGTEST,
  compactToBigInt,
  bigIntToCompact,
  type ConsensusParams,
} from "../consensus/params.js";
import { type BlockHeader, getBlockHash } from "../validation/block.js";
import { HeaderSync, type HeaderChainEntry } from "../sync/headers.js";

// REGTEST baseline + retargeting ON so the diffbits check has something to
// compare against.  Disable min-difficulty fallback to avoid the 20-minute
// rule short-circuit in getNextWorkRequired.
const TEST_PARAMS: ConsensusParams = {
  ...REGTEST,
  fPowNoRetargeting: false,
  fPowAllowMinDifficultyBlocks: false,
};

// Parent bits in the lower-half of REGTEST's powLimit range.
//   target(0x1f100000) = 0x100000 * 256^28 ~ 2^244
//   powLimit(REGTEST)  ~ 2^255 - 1
// So 1.5x and +/-1-mantissa-unit tampering all fit under powLimit.
// And 0x1f100000 round-trips through compact encoding (mantissa
// high-bit clear, no leading zero).
const PARENT_BITS = 0x1f100000;

function mineToTarget(template: BlockHeader, target: bigint): BlockHeader {
  for (let nonce = 0; nonce < 10_000_000; nonce++) {
    const h = { ...template, nonce };
    const rev = Buffer.from(getBlockHash(h)).reverse();
    if (BigInt("0x" + rev.toString("hex")) <= target) {
      return h;
    }
  }
  throw new Error("Mining failed within nonce budget");
}

describe("P0-4 header diffbits strict equality", () => {
  let dbPath: string;
  let db: ChainDB;
  let headerSync: HeaderSync;

  beforeEach(async () => {
    dbPath = await mkdtemp(join(tmpdir(), "hotbuns-diffbits-strict-test-"));
    db = new ChainDB(dbPath);
    await db.open();
    headerSync = new HeaderSync(db, TEST_PARAMS);
    headerSync.initGenesis();
  });

  afterEach(async () => {
    await db.close();
    await rm(dbPath, { recursive: true, force: true });
  });

  function makeParent(timestamp = 1700000000): HeaderChainEntry {
    return {
      hash: TEST_PARAMS.genesisBlockHash,
      header: {
        version: 4,
        prevBlock: Buffer.alloc(32, 0),
        merkleRoot: Buffer.alloc(32, 0xab),
        timestamp,
        bits: PARENT_BITS,
        nonce: 0,
      },
      // Height 100: well inside the 0..2015 retarget interval, so
      // getNextWorkRequired returns compactToBigInt(parent.header.bits).
      height: 100,
      chainWork: 0n,
      status: "valid-header",
    };
  }

  test("sanity: parent_bits round-trips through compact encoding", () => {
    expect(bigIntToCompact(compactToBigInt(PARENT_BITS))).toBe(PARENT_BITS);
    expect(compactToBigInt(PARENT_BITS)).toBeLessThanOrEqual(TEST_PARAMS.powLimit);
  });

  test("header with bits == expected (parent.bits) is accepted", () => {
    const parent = makeParent();
    const target = compactToBigInt(PARENT_BITS);

    const candidate = mineToTarget(
      {
        version: 4,
        prevBlock: parent.hash,
        merkleRoot: Buffer.alloc(32, 0xcd),
        timestamp: parent.header.timestamp + 600,
        bits: PARENT_BITS,
        nonce: 0,
      },
      target
    );

    const result = headerSync.validateHeader(candidate, parent);
    expect(result.valid).toBe(true);
  });

  test("header with bits encoding 1.5x easier target is rejected with bad-diffbits", () => {
    // The OLD permissive code accepted any actualTarget in the window
    //   [expectedTarget / 2, expectedTarget * 2]
    // 1.5x easier sits squarely inside that window.  Strict check must reject.
    const parent = makeParent();
    const expectedTarget = compactToBigInt(PARENT_BITS);
    const easierTarget = (expectedTarget * 3n) / 2n;
    const tamperedBits = bigIntToCompact(easierTarget);

    expect(tamperedBits).not.toBe(PARENT_BITS);
    expect(compactToBigInt(tamperedBits)).toBeLessThanOrEqual(TEST_PARAMS.powLimit);
    // Confirm we're inside the OLD tolerance window so we exercise the
    // new strict path, not the powLimit gate or some other failure.
    expect(easierTarget).toBeLessThan(expectedTarget * 2n);
    expect(easierTarget).toBeGreaterThan(expectedTarget / 2n);

    const candidate = mineToTarget(
      {
        version: 4,
        prevBlock: parent.hash,
        merkleRoot: Buffer.alloc(32, 0xcd),
        timestamp: parent.header.timestamp + 600,
        bits: tamperedBits,
        nonce: 0,
      },
      compactToBigInt(tamperedBits)
    );

    const result = headerSync.validateHeader(candidate, parent);
    expect(result.valid).toBe(false);
    expect(result.error).toContain("bad-diffbits");
  });

  test("header with bits one mantissa unit easier is rejected (no tolerance)", () => {
    const parent = makeParent();
    const tamperedBits = PARENT_BITS + 1; // 0x1f100000 -> 0x1f100001
    expect(tamperedBits).not.toBe(PARENT_BITS);
    expect(compactToBigInt(tamperedBits)).toBeLessThanOrEqual(TEST_PARAMS.powLimit);

    const candidate = mineToTarget(
      {
        version: 4,
        prevBlock: parent.hash,
        merkleRoot: Buffer.alloc(32, 0xcd),
        timestamp: parent.header.timestamp + 600,
        bits: tamperedBits,
        nonce: 0,
      },
      compactToBigInt(tamperedBits)
    );

    const result = headerSync.validateHeader(candidate, parent);
    expect(result.valid).toBe(false);
    expect(result.error).toContain("bad-diffbits");
  });

  test("header with bits one mantissa unit harder is rejected (no tolerance)", () => {
    const parent = makeParent();
    const tamperedBits = PARENT_BITS - 1; // 0x1f100000 -> 0x1f0fffff
    expect(tamperedBits).not.toBe(PARENT_BITS);

    const candidate = mineToTarget(
      {
        version: 4,
        prevBlock: parent.hash,
        merkleRoot: Buffer.alloc(32, 0xcd),
        timestamp: parent.header.timestamp + 600,
        bits: tamperedBits,
        nonce: 0,
      },
      compactToBigInt(tamperedBits)
    );

    const result = headerSync.validateHeader(candidate, parent);
    expect(result.valid).toBe(false);
    expect(result.error).toContain("bad-diffbits");
  });
});
