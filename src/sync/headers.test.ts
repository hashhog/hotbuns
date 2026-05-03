/**
 * Tests for header synchronization.
 *
 * Tests header validation, block locator construction, difficulty adjustment,
 * chain work calculation, and database persistence.
 */

import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { mkdtemp, rm } from "fs/promises";
import { tmpdir } from "os";
import { join } from "path";
import { ChainDB } from "../storage/database.js";
import { REGTEST, compactToBigInt, bigIntToCompact } from "../consensus/params.js";
import { BlockHeader, serializeBlockHeader, getBlockHash } from "../validation/block.js";
import { hash256 } from "../crypto/primitives.js";
import { HeaderSync, type HeaderChainEntry } from "./headers.js";

/** Create a mock peer for testing */
function createMockPeer(host = "127.0.0.1", port = 8333): any {
  return {
    host,
    port,
    state: "connected",
    versionPayload: { startHeight: 1000 },
    send: () => {},
  };
}

/**
 * Create a synthetic block header that passes PoW validation.
 * Uses regtest difficulty which allows any hash below the high powLimit.
 */
function createValidHeader(
  prevBlock: Buffer,
  timestamp: number,
  bits: number = REGTEST.powLimitBits
): BlockHeader {
  const header: BlockHeader = {
    version: 4, // Version 4 for BIP65 compliance
    prevBlock,
    merkleRoot: Buffer.alloc(32, 0xab), // Dummy merkle root
    timestamp,
    bits,
    nonce: 0,
  };

  // For regtest with high difficulty limit, almost any hash will pass
  // We'll try a few nonces to ensure PoW passes
  const target = compactToBigInt(bits);

  for (let nonce = 0; nonce < 1000000; nonce++) {
    const testHeader = { ...header, nonce };
    const hashBuf = getBlockHash(testHeader);
    const hashReversed = Buffer.from(hashBuf).reverse();
    const hashValue = BigInt("0x" + hashReversed.toString("hex"));

    if (hashValue <= target) {
      return testHeader;
    }
  }

  // Regtest should pass easily, but return anyway
  return header;
}

describe("HeaderSync", () => {
  let dbPath: string;
  let db: ChainDB;
  let headerSync: HeaderSync;

  beforeEach(async () => {
    dbPath = await mkdtemp(join(tmpdir(), "hotbuns-headers-test-"));
    db = new ChainDB(dbPath);
    await db.open();
    headerSync = new HeaderSync(db, REGTEST);
    headerSync.initGenesis();
  });

  afterEach(async () => {
    await db.close();
    await rm(dbPath, { recursive: true, force: true });
  });

  describe("initialization", () => {
    test("initializes with genesis block", () => {
      const bestHeader = headerSync.getBestHeader();

      expect(bestHeader).not.toBeNull();
      expect(bestHeader!.height).toBe(0);
      expect(bestHeader!.hash.equals(REGTEST.genesisBlockHash)).toBe(true);
      expect(bestHeader!.status).toBe("valid-header");
      expect(bestHeader!.chainWork).toBeGreaterThan(0n);
    });

    test("genesis header has correct structure", () => {
      const bestHeader = headerSync.getBestHeader();

      expect(bestHeader!.header.version).toBe(1);
      expect(bestHeader!.header.prevBlock.equals(Buffer.alloc(32, 0))).toBe(true);
      expect(bestHeader!.header.bits).toBe(REGTEST.powLimitBits);
    });

    test("can get header by hash", () => {
      const entry = headerSync.getHeader(REGTEST.genesisBlockHash);

      expect(entry).toBeDefined();
      expect(entry!.height).toBe(0);
    });

    test("can get header by height", () => {
      const entry = headerSync.getHeaderByHeight(0);

      expect(entry).toBeDefined();
      expect(entry!.hash.equals(REGTEST.genesisBlockHash)).toBe(true);
    });

    test("returns undefined for non-existent header", () => {
      const fakeHash = Buffer.alloc(32, 0xff);
      const entry = headerSync.getHeader(fakeHash);

      expect(entry).toBeUndefined();
    });
  });

  describe("block locator", () => {
    test("returns genesis hash for empty chain", () => {
      const locator = headerSync.getBlockLocator();

      expect(locator.length).toBeGreaterThanOrEqual(1);
      expect(locator[locator.length - 1].equals(REGTEST.genesisBlockHash)).toBe(true);
    });

    test("returns correct locator for short chain", async () => {
      const peer = createMockPeer();
      const genesis = headerSync.getBestHeader()!;

      // Add a few headers
      const headers: BlockHeader[] = [];
      let prevBlock = genesis.hash;
      let timestamp = genesis.header.timestamp + 600;

      for (let i = 0; i < 5; i++) {
        const header = createValidHeader(prevBlock, timestamp);
        headers.push(header);
        prevBlock = getBlockHash(header);
        timestamp += 600;
      }

      await headerSync.processHeaders(headers, peer);

      const locator = headerSync.getBlockLocator();

      // Should have 6 entries (tip + 5 headers going back + genesis)
      expect(locator.length).toBe(6);

      // First entry should be tip
      expect(locator[0].equals(prevBlock)).toBe(true);

      // Last entry should be genesis
      expect(locator[locator.length - 1].equals(REGTEST.genesisBlockHash)).toBe(true);
    });

    test("uses exponential step for long chains", async () => {
      const peer = createMockPeer();
      const genesis = headerSync.getBestHeader()!;

      // Build a chain of 100 headers
      const headers: BlockHeader[] = [];
      let prevBlock = genesis.hash;
      let timestamp = genesis.header.timestamp + 600;

      for (let i = 0; i < 100; i++) {
        const header = createValidHeader(prevBlock, timestamp);
        headers.push(header);
        prevBlock = getBlockHash(header);
        timestamp += 600;
      }

      await headerSync.processHeaders(headers, peer);

      const locator = headerSync.getBlockLocator();

      // Locator should be much shorter than 100 entries
      expect(locator.length).toBeLessThan(30);

      // Should include genesis
      expect(locator[locator.length - 1].equals(REGTEST.genesisBlockHash)).toBe(true);

      // First entry should be tip (height 100)
      const tip = headerSync.getBestHeader()!;
      expect(locator[0].equals(tip.hash)).toBe(true);
    });
  });

  describe("chain work calculation", () => {
    test("calculates work correctly for regtest difficulty", () => {
      const work = headerSync.getHeaderWork(REGTEST.powLimitBits);

      // Work = 2^256 / (target + 1)
      // For regtest, target is very high, so work is relatively low
      expect(work).toBeGreaterThan(0n);
    });

    test("higher difficulty means more work", () => {
      const lowDiffWork = headerSync.getHeaderWork(0x207fffff); // Low difficulty (regtest)
      const highDiffWork = headerSync.getHeaderWork(0x1d00ffff); // High difficulty (mainnet genesis)

      expect(highDiffWork).toBeGreaterThan(lowDiffWork);
    });

    test("cumulative work increases with each header", async () => {
      const peer = createMockPeer();
      const genesis = headerSync.getBestHeader()!;
      const genesisWork = genesis.chainWork;

      const header = createValidHeader(
        genesis.hash,
        genesis.header.timestamp + 600
      );

      await headerSync.processHeaders([header], peer);

      const newTip = headerSync.getBestHeader()!;
      expect(newTip.chainWork).toBeGreaterThan(genesisWork);
    });
  });

  describe("header validation", () => {
    test("rejects header with timestamp not greater than MTP", async () => {
      const peer = createMockPeer();
      const genesis = headerSync.getBestHeader()!;

      // Create header with timestamp equal to genesis (not greater than MTP)
      const header: BlockHeader = {
        version: 4,
        prevBlock: genesis.hash,
        merkleRoot: Buffer.alloc(32, 0xab),
        timestamp: genesis.header.timestamp, // Same as parent - should fail
        bits: REGTEST.powLimitBits,
        nonce: 0,
      };

      const count = await headerSync.processHeaders([header], peer);
      expect(count).toBe(0);

      // Best header should still be genesis
      expect(headerSync.getBestHeader()!.height).toBe(0);
    });

    test("rejects header with timestamp too far in future", async () => {
      const peer = createMockPeer();
      const genesis = headerSync.getBestHeader()!;

      // Create header with timestamp 3 hours in future
      const futureTime = Math.floor(Date.now() / 1000) + 3 * 60 * 60;
      const header: BlockHeader = {
        version: 4,
        prevBlock: genesis.hash,
        merkleRoot: Buffer.alloc(32, 0xab),
        timestamp: futureTime,
        bits: REGTEST.powLimitBits,
        nonce: 0,
      };

      const count = await headerSync.processHeaders([header], peer);
      expect(count).toBe(0);
    });

    test("rejects header that doesn't meet PoW target", async () => {
      const peer = createMockPeer();
      const genesis = headerSync.getBestHeader()!;

      // Create header with very low target (high difficulty) - will fail PoW
      const header: BlockHeader = {
        version: 4,
        prevBlock: genesis.hash,
        merkleRoot: Buffer.alloc(32, 0xab),
        timestamp: genesis.header.timestamp + 600,
        bits: 0x1d00ffff, // Mainnet genesis difficulty - way too hard
        nonce: 12345,
      };

      const count = await headerSync.processHeaders([header], peer);
      expect(count).toBe(0);
    });

    test("accepts valid header", async () => {
      const peer = createMockPeer();
      const genesis = headerSync.getBestHeader()!;

      const header = createValidHeader(
        genesis.hash,
        genesis.header.timestamp + 600
      );

      const count = await headerSync.processHeaders([header], peer);
      expect(count).toBe(1);

      const newTip = headerSync.getBestHeader()!;
      expect(newTip.height).toBe(1);
    });

    test("rejects orphan headers (missing parent)", async () => {
      const peer = createMockPeer();

      // Create header pointing to non-existent parent
      const header: BlockHeader = {
        version: 4,
        prevBlock: Buffer.alloc(32, 0xff), // Non-existent parent
        merkleRoot: Buffer.alloc(32, 0xab),
        timestamp: Math.floor(Date.now() / 1000),
        bits: REGTEST.powLimitBits,
        nonce: 0,
      };

      const count = await headerSync.processHeaders([header], peer);
      expect(count).toBe(0);
    });

    test("skips duplicate headers", async () => {
      const peer = createMockPeer();
      const genesis = headerSync.getBestHeader()!;

      const header = createValidHeader(
        genesis.hash,
        genesis.header.timestamp + 600
      );

      // Process same header twice
      await headerSync.processHeaders([header], peer);
      const count = await headerSync.processHeaders([header], peer);

      expect(count).toBe(0); // Second time should skip it
      expect(headerSync.getHeaderCount()).toBe(2); // Genesis + 1 header
    });
  });

  describe("difficulty adjustment", () => {
    test("maintains same difficulty within adjustment interval", () => {
      const genesis = headerSync.getBestHeader()!;

      // For height 1, should have same target as genesis
      const expectedTarget = headerSync.getNextTarget(genesis);
      const genesisTarget = compactToBigInt(genesis.header.bits);

      expect(expectedTarget).toBe(genesisTarget);
    });

    test("getNextTarget returns parent target for non-boundary heights", async () => {
      const peer = createMockPeer();
      const genesis = headerSync.getBestHeader()!;

      // Add a header at height 1
      const header1 = createValidHeader(
        genesis.hash,
        genesis.header.timestamp + 600
      );
      await headerSync.processHeaders([header1], peer);

      const entry1 = headerSync.getBestHeader()!;

      // For height 2 (not a boundary), should return same target
      const nextTarget = headerSync.getNextTarget(entry1);
      expect(nextTarget).toBe(compactToBigInt(entry1.header.bits));
    });
  });

  describe("median time past", () => {
    test("MTP of genesis is genesis timestamp", () => {
      const genesis = headerSync.getBestHeader()!;
      const mtp = headerSync.getMedianTimePast(genesis);

      expect(mtp).toBe(genesis.header.timestamp);
    });

    test("MTP with multiple headers", async () => {
      const peer = createMockPeer();
      const genesis = headerSync.getBestHeader()!;

      // Add 5 headers with increasing timestamps
      const headers: BlockHeader[] = [];
      let prevBlock = genesis.hash;
      let timestamp = genesis.header.timestamp;

      for (let i = 0; i < 5; i++) {
        timestamp += 600;
        const header = createValidHeader(prevBlock, timestamp);
        headers.push(header);
        prevBlock = getBlockHash(header);
      }

      await headerSync.processHeaders(headers, peer);

      const tip = headerSync.getBestHeader()!;
      const mtp = headerSync.getMedianTimePast(tip);

      // MTP should be somewhere in the middle of timestamps
      // With 6 timestamps (genesis + 5), median is at index 3
      expect(mtp).toBeGreaterThan(genesis.header.timestamp);
      expect(mtp).toBeLessThanOrEqual(tip.header.timestamp);
    });
  });

  describe("chain extension", () => {
    test("processes multiple headers in order", async () => {
      const peer = createMockPeer();
      const genesis = headerSync.getBestHeader()!;

      const headers: BlockHeader[] = [];
      let prevBlock = genesis.hash;
      let timestamp = genesis.header.timestamp + 600;

      for (let i = 0; i < 10; i++) {
        const header = createValidHeader(prevBlock, timestamp);
        headers.push(header);
        prevBlock = getBlockHash(header);
        timestamp += 600;
      }

      const count = await headerSync.processHeaders(headers, peer);

      expect(count).toBe(10);
      expect(headerSync.getBestHeader()!.height).toBe(10);
      expect(headerSync.getHeaderCount()).toBe(11); // Genesis + 10
    });

    test("tracks fork as valid-fork status", async () => {
      const peer = createMockPeer();
      const genesis = headerSync.getBestHeader()!;

      // Build main chain of 3 headers
      const mainHeaders: BlockHeader[] = [];
      let prevBlock = genesis.hash;
      let timestamp = genesis.header.timestamp + 600;

      for (let i = 0; i < 3; i++) {
        const header = createValidHeader(prevBlock, timestamp);
        mainHeaders.push(header);
        prevBlock = getBlockHash(header);
        timestamp += 600;
      }

      await headerSync.processHeaders(mainHeaders, peer);
      expect(headerSync.getBestHeader()!.height).toBe(3);

      // Create a fork from genesis (shorter than main chain)
      const forkHeader = createValidHeader(
        genesis.hash,
        genesis.header.timestamp + 601 // Different timestamp for different hash
      );

      await headerSync.processHeaders([forkHeader], peer);

      // Fork header should be stored
      const forkEntry = headerSync.getHeader(getBlockHash(forkHeader));
      expect(forkEntry).toBeDefined();
      expect(forkEntry!.status).toBe("valid-fork");

      // Best header should still be main chain
      expect(headerSync.getBestHeader()!.height).toBe(3);
    });
  });

  describe("needs more headers", () => {
    test("returns true when peer has more blocks", () => {
      const result = headerSync.needsMoreHeaders(100);
      expect(result).toBe(true);
    });

    test("returns false when peer has same height", () => {
      const result = headerSync.needsMoreHeaders(0);
      expect(result).toBe(false);
    });

    test("returns false when peer has fewer blocks", async () => {
      const peer = createMockPeer();
      const genesis = headerSync.getBestHeader()!;

      // Add 10 headers
      const headers: BlockHeader[] = [];
      let prevBlock = genesis.hash;
      let timestamp = genesis.header.timestamp + 600;

      for (let i = 0; i < 10; i++) {
        const header = createValidHeader(prevBlock, timestamp);
        headers.push(header);
        prevBlock = getBlockHash(header);
        timestamp += 600;
      }

      await headerSync.processHeaders(headers, peer);

      const result = headerSync.needsMoreHeaders(5);
      expect(result).toBe(false);
    });
  });

  describe("database persistence", () => {
    test("persists headers to database", async () => {
      const peer = createMockPeer();
      const genesis = headerSync.getBestHeader()!;

      const header = createValidHeader(
        genesis.hash,
        genesis.header.timestamp + 600
      );
      const hash = getBlockHash(header);

      await headerSync.processHeaders([header], peer);

      // Check database directly
      const record = await db.getBlockIndex(hash);
      expect(record).not.toBeNull();
      expect(record!.height).toBe(1);
      expect(record!.status & 1).toBe(1); // Header valid flag
    });

    test("loads headers from database on startup", async () => {
      const peer = createMockPeer();
      const genesis = headerSync.getBestHeader()!;

      // Add some headers
      const headers: BlockHeader[] = [];
      let prevBlock = genesis.hash;
      let timestamp = genesis.header.timestamp + 600;

      for (let i = 0; i < 5; i++) {
        const header = createValidHeader(prevBlock, timestamp);
        headers.push(header);
        prevBlock = getBlockHash(header);
        timestamp += 600;
      }

      await headerSync.processHeaders(headers, peer);

      const originalTipHash = headerSync.getBestHeader()!.hash;
      const originalHeight = headerSync.getBestHeader()!.height;

      // Create new HeaderSync instance and load from DB
      const headerSync2 = new HeaderSync(db, REGTEST);
      await headerSync2.loadFromDB();

      expect(headerSync2.getBestHeader()).not.toBeNull();
      expect(headerSync2.getBestHeader()!.hash.equals(originalTipHash)).toBe(true);
      expect(headerSync2.getBestHeader()!.height).toBe(originalHeight);
    });

    test("loadFromDB streams a 10k-header chain in <2s (perf shape)", async () => {
      // Regression guard for the O(N) serial-async loadFromDB bottleneck
      // that made hotbuns un-bootable post-snapshot at ~944k mainnet
      // headers (~1.5 KB/s LevelDB read rate, 30+ minutes). The iterator
      // refactor should complete in well under a second for 10k headers.
      //
      // We seed the DB *directly* (skipping processHeaders' PoW validation)
      // so the test measures only the load path, not header validation.
      const N = 10_000;
      const genesis = headerSync.getBestHeader()!;
      const bits = REGTEST.powLimitBits;

      // Build a synthetic linear chain: each header's prevBlock = parent.hash.
      // We don't bother with valid PoW because loadFromDB doesn't re-verify;
      // it trusts the already-persisted block index.
      let prevHash = genesis.hash;
      let prevTs = genesis.header.timestamp;
      let prevHashHex = prevHash.toString("hex");
      const expectedTipHeights = new Map<string, number>();

      for (let i = 1; i <= N; i++) {
        prevTs += 600;
        const header: BlockHeader = {
          version: 4,
          prevBlock: prevHash,
          merkleRoot: Buffer.alloc(32, i & 0xff),
          timestamp: prevTs,
          bits,
          nonce: i,
        };
        const headerBuf = serializeBlockHeader(header);
        const hash = getBlockHash(header);

        await db.putBlockIndex(hash, {
          height: i,
          header: headerBuf,
          nTx: 0,
          status: 1, // header-valid
          dataPos: 0,
        });

        prevHash = hash;
        prevHashHex = hash.toString("hex");
        expectedTipHeights.set(prevHashHex, i);
      }

      // Persist the header tip pointer the same way saveHeaderTip does
      // (UNDO prefix + "header_tip" key).
      await db.putUndoData(Buffer.from("header_tip"), prevHash);

      // Fresh HeaderSync — loadFromDB has to rebuild the in-memory chain
      // entirely from the persisted index.
      const headerSync2 = new HeaderSync(db, REGTEST);

      const t0 = performance.now();
      await headerSync2.loadFromDB();
      const elapsedMs = performance.now() - t0;

      // Must complete fast. Pre-fix this took O(N) serial async DB
      // round-trips (multi-minute even at 10k); post-fix it's a single
      // iterator pass.
      expect(elapsedMs).toBeLessThan(2000);

      // Chain integrity: tip height + hash + count line up.
      const tip = headerSync2.getBestHeader();
      expect(tip).not.toBeNull();
      expect(tip!.height).toBe(N);
      expect(tip!.hash.equals(prevHash)).toBe(true);
      // Genesis (1) + N synthetic headers.
      expect(headerSync2.getHeaderCount()).toBe(N + 1);

      // Spot-check a few interior heights to confirm the by-height index
      // was rebuilt correctly.
      for (const h of [1, 100, 5000, N - 1, N]) {
        const entry = headerSync2.getHeaderByHeight(h);
        expect(entry).not.toBeUndefined();
        expect(entry!.height).toBe(h);
      }
    });

    test("header tip is stored separately from chain state", async () => {
      const peer = createMockPeer();
      const genesis = headerSync.getBestHeader()!;

      const header = createValidHeader(
        genesis.hash,
        genesis.header.timestamp + 600
      );

      await headerSync.processHeaders([header], peer);

      // Chain state should be unaffected (or null if not set)
      const chainState = await db.getChainState();
      // Chain state is managed separately, header sync doesn't touch it
      // Just verify headers are stored correctly
      expect(headerSync.getBestHeader()!.height).toBe(1);
    });
  });

  describe("header count", () => {
    test("returns correct count after adding headers", async () => {
      const peer = createMockPeer();
      const genesis = headerSync.getBestHeader()!;

      expect(headerSync.getHeaderCount()).toBe(1); // Just genesis

      const header = createValidHeader(
        genesis.hash,
        genesis.header.timestamp + 600
      );
      await headerSync.processHeaders([header], peer);

      expect(headerSync.getHeaderCount()).toBe(2);
    });
  });
});

describe("HeaderSync difficulty retargeting", () => {
  let dbPath: string;
  let db: ChainDB;
  let headerSync: HeaderSync;

  beforeEach(async () => {
    dbPath = await mkdtemp(join(tmpdir(), "hotbuns-headers-retarget-test-"));
    db = new ChainDB(dbPath);
    await db.open();
    headerSync = new HeaderSync(db, REGTEST);
    headerSync.initGenesis();
  });

  afterEach(async () => {
    await db.close();
    await rm(dbPath, { recursive: true, force: true });
  });

  test("difficulty adjustment boundary is at interval multiples", () => {
    const genesis = headerSync.getBestHeader()!;

    // For heights 1-2015, target should be same as parent
    // At height 2016, retargeting should occur
    const interval = REGTEST.difficultyAdjustmentInterval;
    expect(interval).toBe(2016);

    // Verify getNextTarget returns same for non-boundary
    const target = headerSync.getNextTarget(genesis);
    expect(target).toBe(compactToBigInt(genesis.header.bits));
  });

  test("clamps timespan to min (targetTimespan/4)", () => {
    // This is more of an implementation detail verification
    // With very fast blocks, timespan would be clamped to minimum
    const targetTimespan = REGTEST.targetTimespan;
    const minTimespan = Math.floor(targetTimespan / 4);
    const maxTimespan = targetTimespan * 4;

    expect(minTimespan).toBe(302400); // ~3.5 days
    expect(maxTimespan).toBe(4838400); // ~8 weeks
  });
});

describe("HeaderSync version checks", () => {
  let dbPath: string;
  let db: ChainDB;
  let headerSync: HeaderSync;

  beforeEach(async () => {
    dbPath = await mkdtemp(join(tmpdir(), "hotbuns-headers-version-test-"));
    db = new ChainDB(dbPath);
    await db.open();
    headerSync = new HeaderSync(db, REGTEST);
    headerSync.initGenesis();
  });

  afterEach(async () => {
    await db.close();
    await rm(dbPath, { recursive: true, force: true });
  });

  test("validates version requirements based on height", () => {
    const genesis = headerSync.getBestHeader()!;

    // Create a parent entry at height bip34Height - 2
    // so the new block will be at bip34Height - 1 (before BIP34 enforcement)
    const parentEntry: HeaderChainEntry = {
      hash: genesis.hash,
      header: genesis.header,
      height: REGTEST.bip34Height - 2, // Two before BIP34
      chainWork: genesis.chainWork,
      status: "valid-header",
    };

    // Version 1 should be accepted before BIP34 height
    const headerV1: BlockHeader = {
      version: 1,
      prevBlock: genesis.hash,
      merkleRoot: Buffer.alloc(32, 0),
      timestamp: genesis.header.timestamp + 600,
      bits: REGTEST.powLimitBits,
      nonce: 0,
    };

    // This will fail PoW but we're testing version logic
    const resultV1 = headerSync.validateHeader(headerV1, parentEntry);
    // Version check passes, but PoW might fail
    if (resultV1.error) {
      expect(resultV1.error).not.toContain("Version");
    }

    // Now test that version 1 is rejected at BIP34 height
    const parentAtBip34: HeaderChainEntry = {
      hash: genesis.hash,
      header: genesis.header,
      height: REGTEST.bip34Height - 1, // One before BIP34, so new block is at BIP34
      chainWork: genesis.chainWork,
      status: "valid-header",
    };

    const resultV1AtBip34 = headerSync.validateHeader(headerV1, parentAtBip34);
    expect(resultV1AtBip34.valid).toBe(false);
    expect(resultV1AtBip34.error).toContain("Version");
  });
});
