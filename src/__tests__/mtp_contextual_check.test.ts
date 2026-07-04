/**
 * W85 — MedianTimePast + ContextualCheckBlockHeader comprehensive audit.
 *
 * Covers all gates from Bitcoin Core validation.cpp:4080-4121 and chain.h:230-246:
 *
 *  Gate 1  bad-diffbits      nBits != GetNextWorkRequired           (val.cpp:4088)
 *  Gate 2  time-too-old      timestamp <= MTP-of-11                 (val.cpp:4092)
 *  Gate 3  time-timewarp-attack  BIP-94: diff-period block too early (val.cpp:4097)
 *  Gate 4  time-too-new      timestamp > now + MAX_FUTURE_BLOCK_TIME (val.cpp:4108)
 *  Gate 5  bad-version(v<2)  after BIP34 activation                 (val.cpp:4113)
 *  Gate 6  bad-version(v<3)  after BIP66 activation                 (val.cpp:4114)
 *  Gate 7  bad-version(v<4)  after BIP65 activation                 (val.cpp:4115)
 *  Gate 8  MTP computation   getMedianTimePast: sort+median of ≤11   (chain.h:233)
 *  Gate 9  bip22Result       error-string → BIP-22 code mapping
 *
 * Reference constants (consensus/consensus.h + chain.h):
 *   MAX_FUTURE_BLOCK_TIME = 7200 (2 * 60 * 60)
 *   nMedianTimeSpan = 11
 *   MAX_TIMEWARP = 600
 */

import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { mkdtemp, rm } from "fs/promises";
import { tmpdir } from "os";
import { join } from "path";
import { ChainDB } from "../storage/database.js";
import {
  REGTEST,
  TESTNET4,
  compactToBigInt,
  bigIntToCompact,
  type ConsensusParams,
} from "../consensus/params.js";
import { type BlockHeader, getBlockHash, computeMedianTimePast } from "../validation/block.js";
import { HeaderSync, type HeaderChainEntry } from "../sync/headers.js";
import { bip22Result } from "../validation/errors.js";

// ─── Shared test infrastructure ──────────────────────────────────────────────

/**
 * REGTEST with retargeting ON and min-diff fallback OFF.
 * Avoids the 20-min testnet min-difficulty short-circuit so that the
 * strict diffbits check fires.
 */
const REGTEST_RETARGET: ConsensusParams = {
  ...REGTEST,
  fPowNoRetargeting: false,
  fPowAllowMinDifficultyBlocks: false,
};

/**
 * BIP-94-enabled params with a tiny diff-adjustment interval (10 blocks) and
 * REGTEST-level PoW so that timewarp tests can produce a chain of length
 * (interval-1) without significant CPU overhead.
 *
 * The BIP-94 timewarp check fires only at height % difficultyAdjustmentInterval == 0
 * and only when enforce_BIP94 == true.
 */
const BIP94_PARAMS: ConsensusParams = {
  ...REGTEST,
  enforce_BIP94: true,
  fPowNoRetargeting: true,        // keep target constant; no retarget arithmetic
  fPowAllowMinDifficultyBlocks: false,
  difficultyAdjustmentInterval: 10, // trigger at height 10, 20, 30, …
};

function mineToTarget(template: BlockHeader, target: bigint): BlockHeader {
  for (let nonce = 0; nonce < 10_000_000; nonce++) {
    const h = { ...template, nonce };
    const rev = Buffer.from(getBlockHash(h)).reverse();
    if (BigInt("0x" + rev.toString("hex")) <= target) {
      return h;
    }
  }
  throw new Error("Mining failed within nonce budget — increase budget or lower target");
}

/** Build a parent HeaderChainEntry at a given height with given bits/timestamp. */
function makeParent(
  opts: {
    height?: number;
    timestamp?: number;
    bits?: number;
    params?: ConsensusParams;
  } = {}
): HeaderChainEntry {
  const params = opts.params ?? REGTEST;
  return {
    hash: params.genesisBlockHash,
    header: {
      version: 4,
      prevBlock: Buffer.alloc(32, 0),
      merkleRoot: Buffer.alloc(32, 0xab),
      timestamp: opts.timestamp ?? 1_700_000_000,
      bits: opts.bits ?? params.powLimitBits,
      nonce: 0,
    },
    height: opts.height ?? 100,
    chainWork: 0n,
    status: "valid-header",
  };
}

// ─── Setup/teardown helpers ───────────────────────────────────────────────────

let dbPath: string;
let db: ChainDB;
let headerSync: HeaderSync;

async function setup(params: ConsensusParams = REGTEST): Promise<void> {
  dbPath = await mkdtemp(join(tmpdir(), "hotbuns-mtp-test-"));
  db = new ChainDB(dbPath);
  await db.open();
  headerSync = new HeaderSync(db, params);
  headerSync.initGenesis();
}

async function teardown(): Promise<void> {
  await db.close();
  await rm(dbPath, { recursive: true, force: true });
}

// ─── Gate 8: getMedianTimePast correctness ───────────────────────────────────

describe("Gate 8 — getMedianTimePast (chain.h:233-245)", () => {
  beforeEach(() => setup(REGTEST));
  afterEach(teardown);

  test("MTP of a single block equals its own timestamp (genesis)", () => {
    const genesis = headerSync.getBestHeader()!;
    expect(headerSync.getMedianTimePast(genesis)).toBe(genesis.header.timestamp);
  });

  test("computeMedianTimePast: median of 11 ascending timestamps = middle element", () => {
    // [100,200,...,1100] sorted → median at index 5 (0-based) = 600
    const ts = [100, 200, 300, 400, 500, 600, 700, 800, 900, 1000, 1100];
    expect(computeMedianTimePast(ts)).toBe(600);
  });

  test("computeMedianTimePast: truncates to at most 11 elements", () => {
    // Extra elements beyond 11 are ignored; first 11 are [10..110], median = 60
    const ts = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 9999];
    expect(computeMedianTimePast(ts)).toBe(60);
  });

  test("computeMedianTimePast: empty array returns 0 (genesis guard)", () => {
    expect(computeMedianTimePast([])).toBe(0);
  });

  test("computeMedianTimePast: single element returns that element", () => {
    expect(computeMedianTimePast([42])).toBe(42);
  });

  test("computeMedianTimePast: even-count array takes lower-middle index", () => {
    // 4 elements sorted → index 2 (0-based at n/2 = 2)
    const ts = [1, 2, 3, 4];
    // n=4, Math.floor(4/2)=2, sorted[2]=3
    expect(computeMedianTimePast(ts)).toBe(3);
  });

  test("getMedianTimePast via HeaderSync: 3 blocks in chain", async () => {
    // Genesis timestamp = REGTEST genesis ~1296688602
    const peer: any = {
      host: "127.0.0.1", port: 8333, state: "connected",
      versionPayload: { startHeight: 1000 }, send: () => {},
    };
    const g = headerSync.getBestHeader()!;
    const t0 = g.header.timestamp;

    // Build 2 more blocks
    const h1 = mineToTarget(
      { version: 4, prevBlock: g.hash, merkleRoot: Buffer.alloc(32, 1),
        timestamp: t0 + 600, bits: REGTEST.powLimitBits, nonce: 0 },
      compactToBigInt(REGTEST.powLimitBits)
    );
    const h2 = mineToTarget(
      { version: 4, prevBlock: getBlockHash(h1), merkleRoot: Buffer.alloc(32, 2),
        timestamp: t0 + 1200, bits: REGTEST.powLimitBits, nonce: 0 },
      compactToBigInt(REGTEST.powLimitBits)
    );
    await headerSync.processHeaders([h1, h2], peer);

    const tip = headerSync.getBestHeader()!;
    // 3 timestamps: [t0, t0+600, t0+1200]. Sorted: same. n=3, index 1 → t0+600.
    expect(headerSync.getMedianTimePast(tip)).toBe(t0 + 600);
  });
});

// ─── Gate 2: time-too-old ─────────────────────────────────────────────────────

describe("Gate 2 — time-too-old: timestamp must be > MTP (val.cpp:4092)", () => {
  beforeEach(() => setup(REGTEST));
  afterEach(teardown);

  test("rejects header with timestamp == MTP (BIP-113 strict >)", () => {
    const parent = makeParent({ timestamp: 1_700_000_000 });
    // With only parent in chain, MTP = parent.timestamp.
    const candidate = mineToTarget(
      { version: 4, prevBlock: parent.hash, merkleRoot: Buffer.alloc(32, 0xcc),
        timestamp: parent.header.timestamp, // == MTP → must reject
        bits: REGTEST.powLimitBits, nonce: 0 },
      compactToBigInt(REGTEST.powLimitBits)
    );
    const result = headerSync.validateHeader(candidate, parent);
    expect(result.valid).toBe(false);
    expect(result.error).toContain("time-too-old");
  });

  test("rejects header with timestamp == MTP - 1", () => {
    const parent = makeParent({ timestamp: 1_700_000_000 });
    const candidate = mineToTarget(
      { version: 4, prevBlock: parent.hash, merkleRoot: Buffer.alloc(32, 0xcc),
        timestamp: parent.header.timestamp - 1,
        bits: REGTEST.powLimitBits, nonce: 0 },
      compactToBigInt(REGTEST.powLimitBits)
    );
    const result = headerSync.validateHeader(candidate, parent);
    expect(result.valid).toBe(false);
    expect(result.error).toContain("time-too-old");
  });

  test("accepts header with timestamp == MTP + 1 (strictly greater)", () => {
    const parent = makeParent({ timestamp: 1_700_000_000 });
    const candidate = mineToTarget(
      { version: 4, prevBlock: parent.hash, merkleRoot: Buffer.alloc(32, 0xcc),
        timestamp: parent.header.timestamp + 1, // MTP+1 → accept
        bits: REGTEST.powLimitBits, nonce: 0 },
      compactToBigInt(REGTEST.powLimitBits)
    );
    const result = headerSync.validateHeader(candidate, parent);
    expect(result.valid).toBe(true);
  });
});

// ─── Gate 4: time-too-new ─────────────────────────────────────────────────────

describe("Gate 4 — time-too-new: timestamp must not exceed now + 7200s (val.cpp:4108)", () => {
  beforeEach(() => setup(REGTEST));
  afterEach(teardown);

  const MAX_FUTURE_BLOCK_TIME = 2 * 60 * 60; // 7200 seconds

  test("rejects header > now + 7200 (MAX_FUTURE_BLOCK_TIME)", () => {
    const parent = makeParent({ timestamp: 1_700_000_000 });
    const futureTs = Math.floor(Date.now() / 1000) + MAX_FUTURE_BLOCK_TIME + 1;
    const candidate = mineToTarget(
      { version: 4, prevBlock: parent.hash, merkleRoot: Buffer.alloc(32, 0xcd),
        timestamp: futureTs,
        bits: REGTEST.powLimitBits, nonce: 0 },
      compactToBigInt(REGTEST.powLimitBits)
    );
    const result = headerSync.validateHeader(candidate, parent);
    expect(result.valid).toBe(false);
    expect(result.error).toContain("time-too-new");
  });

  test("accepts header at now + 7199 (one second before limit)", () => {
    const parent = makeParent({ timestamp: 1_700_000_000 });
    const nearFutureTs = Math.floor(Date.now() / 1000) + MAX_FUTURE_BLOCK_TIME - 1;
    const candidate = mineToTarget(
      { version: 4, prevBlock: parent.hash, merkleRoot: Buffer.alloc(32, 0xce),
        timestamp: nearFutureTs,
        bits: REGTEST.powLimitBits, nonce: 0 },
      compactToBigInt(REGTEST.powLimitBits)
    );
    const result = headerSync.validateHeader(candidate, parent);
    // Should pass time-too-new; may fail other gates but not time-too-new.
    // Guard: result.error may be undefined when valid=true.
    if (!result.valid) {
      expect(result.error).not.toContain("time-too-new");
    }
  });
});

// ─── Gate 3: time-timewarp-attack (BIP-94, val.cpp:4097) ─────────────────────

describe("Gate 3 — time-timewarp-attack: BIP-94 enforce_BIP94 (val.cpp:4097-4105)", () => {
  // The check only fires when:
  //   1. params.enforce_BIP94 == true
  //   2. (height % difficultyAdjustmentInterval) == 0  (first block of each period)
  //   3. header.timestamp < parent.header.timestamp - MAX_TIMEWARP (600s)
  //
  // We use BIP94_PARAMS (diffAdjInterval=10) so the chain to height 9 is only
  // 9 blocks — fast to build.  The 10th block (height=10) is the diff boundary.
  //
  // For timewarp to fire and NOT be shadowed by time-too-old, the candidate
  // timestamp must be:
  //   - > MTP(parent at height 9)         (pass time-too-old)
  //   - < parent.timestamp - 600          (trip timewarp)
  //
  // We achieve this by building blocks 1-9 with very LOW timestamps (1000..9000)
  // so MTP of block 9 is low, then setting block 9's own timestamp HIGH
  // (e.g. 1_700_000_000).  A candidate at (MTP+1) to (1_700_000_000 - 601)
  // satisfies both conditions.

  const DIFF_INTERVAL = BIP94_PARAMS.difficultyAdjustmentInterval; // 10
  const MAX_TIMEWARP = 600;

  let bip94DbPath: string;
  let bip94Db: ChainDB;
  let bip94Sync: HeaderSync;

  /** Build a chain of `n` blocks.  Mines each block to the powLimit target. */
  async function buildChain(
    params: ConsensusParams,
    hs: HeaderSync,
    count: number,
    getTimestamp: (i: number) => number
  ): Promise<void> {
    const peer: any = {
      host: "127.0.0.1", port: 8333, state: "connected",
      versionPayload: { startHeight: count + 10 }, send: () => {},
    };
    const target = compactToBigInt(params.powLimitBits);
    let prevHash = hs.getBestHeader()!.hash;
    for (let i = 0; i < count; i++) {
      const ts = getTimestamp(i + 1);
      const template = {
        version: 4,
        prevBlock: prevHash,
        merkleRoot: Buffer.alloc(32, i & 0xff),
        timestamp: ts,
        bits: params.powLimitBits,
        nonce: 0,
      };
      const mined = mineToTarget(template, target);
      await hs.processHeaders([mined], peer);
      const best = hs.getBestHeader();
      if (!best || best.height < i + 1) {
        throw new Error(`buildChain: block ${i+1} was not accepted by processHeaders`);
      }
      prevHash = best.hash;
    }
  }

  beforeEach(async () => {
    bip94DbPath = await mkdtemp(join(tmpdir(), "hotbuns-bip94-test-"));
    bip94Db = new ChainDB(bip94DbPath);
    await bip94Db.open();
    bip94Sync = new HeaderSync(bip94Db, BIP94_PARAMS);
    bip94Sync.initGenesis();
  });

  afterEach(async () => {
    await bip94Db.close();
    await rm(bip94DbPath, { recursive: true, force: true });
  });

  test("rejects timewarp block on diff-adjustment boundary (timestamp < prev - 600)", async () => {
    // Build blocks 1-8 at low timestamps (1_700_000_100, +600 each).
    // Block 9 (height=9) at a HIGH timestamp to make parent.timestamp >> MTP.
    const BASE_LOW_TS = 1_700_000_100;
    await buildChain(BIP94_PARAMS, bip94Sync, 8, (i) => BASE_LOW_TS + i * 600);
    // Now add block 9 with a timestamp 2 hours after block 8's timestamp.
    const peer: any = {
      host: "127.0.0.1", port: 8333, state: "connected",
      versionPayload: { startHeight: 20 }, send: () => {},
    };
    const blk8 = bip94Sync.getBestHeader()!;
    const HIGH_TS = blk8.header.timestamp + 7200; // jump 2h
    const blk9template = mineToTarget(
      { version: 4, prevBlock: blk8.hash, merkleRoot: Buffer.alloc(32, 0x09),
        timestamp: HIGH_TS, bits: BIP94_PARAMS.powLimitBits, nonce: 0 },
      compactToBigInt(BIP94_PARAMS.powLimitBits)
    );
    await bip94Sync.processHeaders([blk9template], peer);
    const parent = bip94Sync.getBestHeader()!;
    expect(parent.height).toBe(9);

    // MTP of block 9 = median of timestamps of blocks 9..max(1, 9-10) = blocks 1-9.
    // Sorted timestamps: [BASE+600, BASE+1200, ..., BASE+4800, HIGH_TS].
    // The 9 timestamps sorted: 9 elements, median = index 4 = BASE + 600*4 = BASE+2400.
    const parentMTP = bip94Sync.getMedianTimePast(parent);

    // candidate.timestamp must be > parentMTP AND < HIGH_TS - 600 to trigger timewarp.
    // Use parentMTP + 1.
    const candidateTs = parentMTP + 1;
    expect(candidateTs).toBeLessThan(HIGH_TS - MAX_TIMEWARP); // satisfies both conditions

    const candidate = {
      version: 4,
      prevBlock: parent.hash,
      merkleRoot: Buffer.alloc(32, 0x0a),
      timestamp: candidateTs,
      bits: BIP94_PARAMS.powLimitBits,
      nonce: 0,
    };
    const result = bip94Sync.validateHeader(candidate, parent);
    expect(result.valid).toBe(false);
    expect(result.error).toContain("time-timewarp-attack");
  });

  test("accepts block at diff boundary when timestamp >= parent.timestamp - 600", async () => {
    // Same setup as above, but use a candidate timestamp = HIGH_TS - 600.
    // That is NOT < HIGH_TS - 600, so timewarp check must not fire.
    const BASE_LOW_TS = 1_700_100_000;
    await buildChain(BIP94_PARAMS, bip94Sync, 8, (i) => BASE_LOW_TS + i * 600);
    const peer: any = {
      host: "127.0.0.1", port: 8333, state: "connected",
      versionPayload: { startHeight: 20 }, send: () => {},
    };
    const blk8 = bip94Sync.getBestHeader()!;
    const HIGH_TS = blk8.header.timestamp + 7200;
    const blk9template = mineToTarget(
      { version: 4, prevBlock: blk8.hash, merkleRoot: Buffer.alloc(32, 0x09),
        timestamp: HIGH_TS, bits: BIP94_PARAMS.powLimitBits, nonce: 0 },
      compactToBigInt(BIP94_PARAMS.powLimitBits)
    );
    await bip94Sync.processHeaders([blk9template], peer);
    const parent = bip94Sync.getBestHeader()!;
    expect(parent.height).toBe(9);

    // timestamp = HIGH_TS - 600 → NOT < HIGH_TS - 600 → timewarp must not fire.
    const candidateTs = HIGH_TS - MAX_TIMEWARP; // exactly at boundary
    const candidate = {
      version: 4, prevBlock: parent.hash, merkleRoot: Buffer.alloc(32, 0x0b),
      timestamp: candidateTs, bits: BIP94_PARAMS.powLimitBits, nonce: 0,
    };
    const result = bip94Sync.validateHeader(candidate, parent);
    if (!result.valid) {
      expect(result.error).not.toContain("time-timewarp-attack");
    }
  });

  test("does NOT fire on non-diff-adjustment height (height % 10 != 0)", () => {
    // Parent at height 4 → new block at height 5, NOT a diff boundary for interval=10.
    const parentTs = 1_700_000_000;
    const parent = makeParent({
      height: 4,
      timestamp: parentTs,
      bits: BIP94_PARAMS.powLimitBits,
      params: BIP94_PARAMS,
    });
    // Use a timestamp that would trip timewarp if this were a diff boundary.
    const candidate = {
      version: 4, prevBlock: parent.hash, merkleRoot: Buffer.alloc(32, 0xcc),
      timestamp: parentTs - MAX_TIMEWARP - 100, bits: BIP94_PARAMS.powLimitBits, nonce: 0,
    };
    const result = bip94Sync.validateHeader(candidate, parent);
    if (!result.valid) {
      expect(result.error).not.toContain("time-timewarp-attack");
    }
  });

  test("does NOT fire when enforce_BIP94=false even at diff boundary", () => {
    // REGTEST has enforce_BIP94=false — timewarp check must never fire.
    // Use headerSync (initialized with plain REGTEST params).
    const parentTs = 1_700_000_000;
    const parent = makeParent({
      // height = diffAdjInterval-1 for REGTEST (2016-1 = 2015); use simplified height
      height: DIFF_INTERVAL - 1, // 9
      timestamp: parentTs,
      bits: REGTEST.powLimitBits,
      params: REGTEST,
    });
    // timestamp wildly before parent — would trip timewarp on BIP94-enabled chain.
    const candidate = {
      version: 4, prevBlock: parent.hash, merkleRoot: Buffer.alloc(32, 0xdd),
      timestamp: parentTs - MAX_TIMEWARP - 100, bits: REGTEST.powLimitBits, nonce: 0,
    };
    const result = headerSync.validateHeader(candidate, parent);
    if (!result.valid) {
      expect(result.error).not.toContain("time-timewarp-attack");
    }
  });
});

// ─── Gates 5/6/7: bad-version ────────────────────────────────────────────────

describe("Gates 5/6/7 — bad-version: rejected version blocks (val.cpp:4113-4118)", () => {
  // Use params where BIP34/66/65 activate at height 1/1/1 (TESTNET4 / REGTEST).
  // REGTEST: bip34Height=1, bip65Height=1, bip66Height=1 (Core parity,
  // kernel/chainparams.cpp:536-539).
  // TESTNET4: all at height 1.

  // For simplicity use REGTEST-like params where all activate at height 1.
  const ALLBIP_PARAMS: ConsensusParams = {
    ...REGTEST,
    bip34Height: 1,
    bip65Height: 1,
    bip66Height: 1,
  };

  let avDbPath: string;
  let avDb: ChainDB;
  let avSync: HeaderSync;

  beforeEach(async () => {
    avDbPath = await mkdtemp(join(tmpdir(), "hotbuns-badver-test-"));
    avDb = new ChainDB(avDbPath);
    await avDb.open();
    avSync = new HeaderSync(avDb, ALLBIP_PARAMS);
    avSync.initGenesis();
  });

  afterEach(async () => {
    await avDb.close();
    await rm(avDbPath, { recursive: true, force: true });
  });

  test("rejects version=1 block after BIP34 activation", () => {
    const parent = makeParent({ height: 0, params: ALLBIP_PARAMS });
    // height = 1 >= bip34Height=1 → require version >= 2.
    const candidate = mineToTarget(
      { version: 1, prevBlock: parent.hash, merkleRoot: Buffer.alloc(32, 0x11),
        timestamp: parent.header.timestamp + 600,
        bits: ALLBIP_PARAMS.powLimitBits, nonce: 0 },
      compactToBigInt(ALLBIP_PARAMS.powLimitBits)
    );
    const result = avSync.validateHeader(candidate, parent);
    expect(result.valid).toBe(false);
    expect(result.error).toContain("bad-version");
    expect(result.error).toContain("00000001");
  });

  test("rejects version=2 block after BIP66 activation", () => {
    const parent = makeParent({ height: 0, params: ALLBIP_PARAMS });
    const candidate = mineToTarget(
      { version: 2, prevBlock: parent.hash, merkleRoot: Buffer.alloc(32, 0x22),
        timestamp: parent.header.timestamp + 600,
        bits: ALLBIP_PARAMS.powLimitBits, nonce: 0 },
      compactToBigInt(ALLBIP_PARAMS.powLimitBits)
    );
    const result = avSync.validateHeader(candidate, parent);
    expect(result.valid).toBe(false);
    expect(result.error).toContain("bad-version");
    expect(result.error).toContain("00000002");
  });

  test("rejects version=3 block after BIP65 activation", () => {
    const parent = makeParent({ height: 0, params: ALLBIP_PARAMS });
    const candidate = mineToTarget(
      { version: 3, prevBlock: parent.hash, merkleRoot: Buffer.alloc(32, 0x33),
        timestamp: parent.header.timestamp + 600,
        bits: ALLBIP_PARAMS.powLimitBits, nonce: 0 },
      compactToBigInt(ALLBIP_PARAMS.powLimitBits)
    );
    const result = avSync.validateHeader(candidate, parent);
    expect(result.valid).toBe(false);
    expect(result.error).toContain("bad-version");
    expect(result.error).toContain("00000003");
  });

  test("accepts version=4 block after all BIP activations", () => {
    const parent = makeParent({ height: 0, params: ALLBIP_PARAMS });
    const candidate = mineToTarget(
      { version: 4, prevBlock: parent.hash, merkleRoot: Buffer.alloc(32, 0x44),
        timestamp: parent.header.timestamp + 600,
        bits: ALLBIP_PARAMS.powLimitBits, nonce: 0 },
      compactToBigInt(ALLBIP_PARAMS.powLimitBits)
    );
    const result = avSync.validateHeader(candidate, parent);
    expect(result.valid).toBe(true);
  });

  test("version=1 accepted before BIP34 activation (height=0)", () => {
    // Use mainnet-like params with bip34Height=227931; at height 0 BIP34 is not active.
    // Use REGTEST powLimit so we don't actually have to mine to mainnet difficulty.
    const PRE_BIP34_PARAMS: ConsensusParams = {
      ...REGTEST,
      bip34Height: 227931,
      bip65Height: 388381,
      bip66Height: 363725,
      fPowNoRetargeting: true,
    };
    const parent = makeParent({ height: 0, params: PRE_BIP34_PARAMS });
    // At height 1, bip34Height=227931 is not yet active → version 1 is OK.
    const candidate = mineToTarget(
      { version: 1, prevBlock: parent.hash, merkleRoot: Buffer.alloc(32, 0x55),
        timestamp: parent.header.timestamp + 600,
        bits: PRE_BIP34_PARAMS.powLimitBits, nonce: 0 },
      compactToBigInt(PRE_BIP34_PARAMS.powLimitBits)
    );
    let preBip34Sync: HeaderSync;
    let preBip34Db: ChainDB;
    let preBip34DbPath: string;
    // Inline setup/teardown
    return (async () => {
      preBip34DbPath = await mkdtemp(join(tmpdir(), "hotbuns-pre-bip34-test-"));
      preBip34Db = new ChainDB(preBip34DbPath);
      await preBip34Db.open();
      preBip34Sync = new HeaderSync(preBip34Db, PRE_BIP34_PARAMS);
      preBip34Sync.initGenesis();
      try {
        const result = preBip34Sync.validateHeader(candidate, parent);
        expect(result.valid).toBe(true);
      } finally {
        await preBip34Db.close();
        await rm(preBip34DbPath, { recursive: true, force: true });
      }
    })();
  });
});

// ─── Gate 1: bad-diffbits (val.cpp:4088) ─────────────────────────────────────
// (Already heavily covered by header_diffbits_strict.test.ts — just one
// smoke test here to confirm the error string starts with "bad-diffbits".)

describe("Gate 1 — bad-diffbits: nBits must match GetNextWorkRequired (val.cpp:4088)", () => {
  let rDb: ChainDB;
  let rDbPath: string;
  let rSync: HeaderSync;

  beforeEach(async () => {
    rDbPath = await mkdtemp(join(tmpdir(), "hotbuns-diffbits-mtp-test-"));
    rDb = new ChainDB(rDbPath);
    await rDb.open();
    rSync = new HeaderSync(rDb, REGTEST_RETARGET);
    rSync.initGenesis();
  });

  afterEach(async () => {
    await rDb.close();
    await rm(rDbPath, { recursive: true, force: true });
  });

  test("wrong nBits emits 'bad-diffbits' error string", () => {
    const parent = makeParent({ height: 100, bits: 0x1f100000 });
    const wrongBits = 0x1f100001; // one mantissa unit off
    const candidate = mineToTarget(
      { version: 4, prevBlock: parent.hash, merkleRoot: Buffer.alloc(32, 0xff),
        timestamp: parent.header.timestamp + 600,
        bits: wrongBits, nonce: 0 },
      compactToBigInt(wrongBits)
    );
    const result = rSync.validateHeader(candidate, parent);
    expect(result.valid).toBe(false);
    expect(result.error).toContain("bad-diffbits");
  });
});

// ─── Gate 9: bip22Result error-string mapping ────────────────────────────────

describe("Gate 9 — bip22Result: maps error strings to BIP-22 reject reasons", () => {
  test("time-too-old maps correctly", () => {
    expect(bip22Result("time-too-old: block's timestamp 100 <= MTP 200")).toBe("time-too-old");
  });

  test("time-too-new maps correctly", () => {
    expect(bip22Result("time-too-new: block timestamp too far in the future")).toBe("time-too-new");
  });

  test("time-timewarp-attack maps correctly (new in W85)", () => {
    expect(bip22Result("time-timewarp-attack: block's timestamp is too early on diff adjustment block"))
      .toBe("time-timewarp-attack");
  });

  test("bad-version(0x00000001) maps to bad-version(0x00000001)", () => {
    const result = bip22Result("bad-version(0x00000001): rejected nVersion=0x00000001 block");
    expect(result).toContain("bad-version");
  });

  test("bad-diffbits maps correctly", () => {
    expect(bip22Result("bad-diffbits: expected bits abc, got def")).toBe("bad-diffbits");
  });

  test("high-hash maps correctly", () => {
    expect(bip22Result("high-hash: proof of work failed")).toBe("high-hash");
  });

  test("unknown error falls through to 'rejected'", () => {
    expect(bip22Result("some unknown random error")).toBe("rejected");
  });
});
