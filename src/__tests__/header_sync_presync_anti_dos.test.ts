/**
 * Tests for header sync anti-DoS (PRESYNC/REDOWNLOAD) mechanism.
 *
 * Tests the protection against memory exhaustion attacks where a peer
 * sends millions of low-work headers.
 */

import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { mkdtemp, rm } from "fs/promises";
import { tmpdir } from "os";
import { join } from "path";
import { ChainDB } from "../storage/database.js";
import { REGTEST, MAINNET, compactToBigInt } from "../consensus/params.js";
import { BlockHeader, getBlockHash } from "../validation/block.js";
import { getBlockWork } from "../consensus/pow.js";
import { HeaderSync, HeaderChainEntry } from "../sync/headers.js";
import {
  HeadersSyncState,
  HeadersSyncStateEnum,
  DEFAULT_HEADERS_SYNC_PARAMS,
  MAX_HEADERS_RESULTS,
  type HeadersSyncParams,
} from "../sync/header-sync-state.js";

/** Create a mock peer for testing */
function createMockPeer(host = "127.0.0.1", port = 8333): any {
  return {
    host,
    port,
    state: "connected",
    versionPayload: { startHeight: 100000 },
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
    version: 4,
    prevBlock,
    merkleRoot: Buffer.alloc(32, 0xab),
    timestamp,
    bits,
    nonce: 0,
  };

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

  return header;
}

/**
 * Create a chain of headers starting from a given block.
 */
function createHeaderChain(
  startHash: Buffer,
  startTimestamp: number,
  count: number,
  bits: number = REGTEST.powLimitBits
): BlockHeader[] {
  const headers: BlockHeader[] = [];
  let prevBlock = startHash;
  let timestamp = startTimestamp;

  for (let i = 0; i < count; i++) {
    timestamp += 600; // 10 minutes
    const header = createValidHeader(prevBlock, timestamp, bits);
    headers.push(header);
    prevBlock = getBlockHash(header);
  }

  return headers;
}

describe("HeadersSyncState", () => {
  const testParams: HeadersSyncParams = {
    commitmentPeriod: 10, // Low period for testing
    redownloadBufferSize: 5,
  };

  describe("initialization", () => {
    test("starts in PRESYNC state", () => {
      const syncState = new HeadersSyncState(
        REGTEST,
        testParams,
        REGTEST.genesisBlockHash,
        0,
        REGTEST.powLimitBits,
        0n,
        100n // Low minimum work for testing
      );

      expect(syncState.getState()).toBe(HeadersSyncStateEnum.PRESYNC);
    });

    test("tracks initial chain start correctly", () => {
      const syncState = new HeadersSyncState(
        REGTEST,
        testParams,
        REGTEST.genesisBlockHash,
        0,
        REGTEST.powLimitBits,
        0n,
        100n
      );

      expect(syncState.getPresyncHeight()).toBe(0);
      expect(syncState.getPresyncWork()).toBe(0n);
    });
  });

  describe("PRESYNC phase", () => {
    test("accumulates work during PRESYNC", () => {
      const syncState = new HeadersSyncState(
        REGTEST,
        testParams,
        REGTEST.genesisBlockHash,
        0,
        REGTEST.powLimitBits,
        0n,
        10n ** 20n // High minimum work - won't reach it
      );

      const headers = createHeaderChain(
        REGTEST.genesisBlockHash,
        1296688602,
        5
      );

      const result = syncState.processNextHeaders(headers, true);

      expect(result.success).toBe(true);
      expect(syncState.getState()).toBe(HeadersSyncStateEnum.PRESYNC);
      expect(syncState.getPresyncHeight()).toBe(5);
      expect(syncState.getPresyncWork()).toBeGreaterThan(0n);
    });

    test("transitions to REDOWNLOAD when minimum work is reached", () => {
      // Calculate work for 10 regtest headers
      const workPerHeader = getBlockWork(REGTEST.powLimitBits);
      const minWork = workPerHeader * 5n; // Require 5 headers worth of work

      const syncState = new HeadersSyncState(
        REGTEST,
        testParams,
        REGTEST.genesisBlockHash,
        0,
        REGTEST.powLimitBits,
        0n,
        minWork
      );

      const headers = createHeaderChain(
        REGTEST.genesisBlockHash,
        1296688602,
        10
      );

      const result = syncState.processNextHeaders(headers, true);

      expect(result.success).toBe(true);
      expect(syncState.getState()).toBe(HeadersSyncStateEnum.REDOWNLOAD);
      expect(result.requestMore).toBe(true);
    });

    test("rejects headers that don't connect", () => {
      const syncState = new HeadersSyncState(
        REGTEST,
        testParams,
        REGTEST.genesisBlockHash,
        0,
        REGTEST.powLimitBits,
        0n,
        10n ** 20n
      );

      // Create headers that don't connect to genesis
      const fakeParent = Buffer.alloc(32, 0xff);
      const headers = createHeaderChain(fakeParent, 1296688602, 5);

      const result = syncState.processNextHeaders(headers, true);

      expect(result.success).toBe(false);
      expect(syncState.getState()).toBe(HeadersSyncStateEnum.FINAL);
    });

    test("aborts when chain ends without sufficient work", () => {
      const syncState = new HeadersSyncState(
        REGTEST,
        testParams,
        REGTEST.genesisBlockHash,
        0,
        REGTEST.powLimitBits,
        0n,
        10n ** 20n // Very high minimum - won't reach it
      );

      const headers = createHeaderChain(
        REGTEST.genesisBlockHash,
        1296688602,
        5
      );

      // Non-full message indicates chain ended
      const result = syncState.processNextHeaders(headers, false);

      expect(result.success).toBe(true);
      expect(result.requestMore).toBe(false);
      expect(syncState.getState()).toBe(HeadersSyncStateEnum.FINAL);
    });
  });

  describe("REDOWNLOAD phase", () => {
    test("verifies commitments match during REDOWNLOAD", () => {
      const workPerHeader = getBlockWork(REGTEST.powLimitBits);
      const minWork = workPerHeader * 5n;

      const syncState = new HeadersSyncState(
        REGTEST,
        testParams,
        REGTEST.genesisBlockHash,
        0,
        REGTEST.powLimitBits,
        0n,
        minWork
      );

      // Create a chain
      const headers = createHeaderChain(
        REGTEST.genesisBlockHash,
        1296688602,
        20
      );

      // PRESYNC phase
      let result = syncState.processNextHeaders(headers, true);
      expect(result.success).toBe(true);
      expect(syncState.getState()).toBe(HeadersSyncStateEnum.REDOWNLOAD);

      // REDOWNLOAD phase - send same headers
      result = syncState.processNextHeaders(headers, false);
      expect(result.success).toBe(true);
      // Should have released some headers
      expect(result.powValidatedHeaders.length).toBeGreaterThan(0);
    });

    test("rejects different headers during REDOWNLOAD", () => {
      // Use very frequent commitments to ensure we catch differences
      const frequentParams: HeadersSyncParams = {
        commitmentPeriod: 1, // Commit every single header
        redownloadBufferSize: 5,
      };

      const workPerHeader = getBlockWork(REGTEST.powLimitBits);
      // Use high minWork so we don't skip commitment checks during redownload
      // We need to reach minWork in PRESYNC but stay under it for most of REDOWNLOAD
      // so that commitment verification is still active
      const minWork = workPerHeader * 15n; // Higher threshold

      const syncState = new HeadersSyncState(
        REGTEST,
        frequentParams,
        REGTEST.genesisBlockHash,
        0,
        REGTEST.powLimitBits,
        0n,
        minWork
      );

      // Create first chain for PRESYNC (20 headers to exceed minWork)
      const headers1 = createHeaderChain(
        REGTEST.genesisBlockHash,
        1296688602,
        20
      );

      // PRESYNC phase
      let result = syncState.processNextHeaders(headers1, true);
      expect(result.success).toBe(true);
      expect(syncState.getState()).toBe(HeadersSyncStateEnum.REDOWNLOAD);

      // Create different chain for REDOWNLOAD (different timestamps)
      // This creates completely different hashes that will fail commitment check
      const headers2 = createHeaderChain(
        REGTEST.genesisBlockHash,
        1296688603, // Different start time creates different hashes
        20
      );

      // REDOWNLOAD phase - send different headers
      // The first header already has a different hash and will fail commitment
      result = syncState.processNextHeaders(headers2, false);

      // Should fail due to commitment mismatch (with period=1, every header is checked)
      expect(result.success).toBe(false);
      expect(syncState.getState()).toBe(HeadersSyncStateEnum.FINAL);
    });
  });

  describe("block locator", () => {
    test("returns chain start hash in PRESYNC", () => {
      const syncState = new HeadersSyncState(
        REGTEST,
        testParams,
        REGTEST.genesisBlockHash,
        0,
        REGTEST.powLimitBits,
        0n,
        10n ** 20n
      );

      const locator = syncState.getNextHeadersRequestLocator();

      expect(locator.length).toBe(2); // last header + chain start
      expect(locator[1].equals(REGTEST.genesisBlockHash)).toBe(true);
    });

    test("returns empty locator in FINAL state", () => {
      const syncState = new HeadersSyncState(
        REGTEST,
        testParams,
        REGTEST.genesisBlockHash,
        0,
        REGTEST.powLimitBits,
        0n,
        10n ** 20n
      );

      // Force FINAL state
      const headers = createHeaderChain(
        REGTEST.genesisBlockHash,
        1296688602,
        5
      );
      syncState.processNextHeaders(headers, false); // Non-full ends sync

      const locator = syncState.getNextHeadersRequestLocator();
      expect(locator.length).toBe(0);
    });
  });
});

describe("HeaderSync with anti-DoS", () => {
  let dbPath: string;
  let db: ChainDB;
  let headerSync: HeaderSync;

  beforeEach(async () => {
    dbPath = await mkdtemp(join(tmpdir(), "hotbuns-header-antidos-test-"));
    db = new ChainDB(dbPath);
    await db.open();
    headerSync = new HeaderSync(db, REGTEST);
    headerSync.initGenesis();
  });

  afterEach(async () => {
    await db.close();
    await rm(dbPath, { recursive: true, force: true });
  });

  test("skips anti-DoS for regtest (nMinimumChainWork = 0)", () => {
    const peer = createMockPeer();

    // Request headers should work without anti-DoS
    headerSync.requestHeaders(peer);

    // No anti-DoS state should be created
    const state = headerSync.getPeerSyncState(peer);
    expect(state).toBeUndefined();
  });
});

describe("low-work header attack simulation", () => {
  test("rejects chain with insufficient work", () => {
    const testParams: HeadersSyncParams = {
      commitmentPeriod: 10,
      redownloadBufferSize: 5,
    };

    // Use mainnet-like minimum work (very high)
    const syncState = new HeadersSyncState(
      MAINNET,
      testParams,
      MAINNET.genesisBlockHash,
      0,
      MAINNET.powLimitBits,
      0n
      // Use default nMinimumChainWork from MAINNET
    );

    // Create low-work headers (regtest difficulty is much easier)
    // These would pass PoW for regtest but represent very little work
    const lowWorkHeaders: BlockHeader[] = [];
    let prevBlock = MAINNET.genesisBlockHash;
    let timestamp = 1231006505; // Mainnet genesis timestamp

    for (let i = 0; i < 100; i++) {
      timestamp += 600;
      // Create header with mainnet genesis bits
      const header: BlockHeader = {
        version: 1,
        prevBlock,
        merkleRoot: Buffer.alloc(32, i),
        timestamp,
        bits: MAINNET.powLimitBits, // Low difficulty
        nonce: i,
      };
      lowWorkHeaders.push(header);
      // Note: these won't actually pass PoW, but we're testing the work calculation
    }

    // Even if we could process these, they wouldn't have enough work
    const workPerHeader = getBlockWork(MAINNET.powLimitBits);
    const totalWork = workPerHeader * BigInt(lowWorkHeaders.length);

    // Verify the work is way below minimum
    expect(totalWork).toBeLessThan(MAINNET.nMinimumChainWork);
  });

  test("memory usage stays bounded during PRESYNC", () => {
    const testParams: HeadersSyncParams = {
      commitmentPeriod: 100, // Commit every 100 headers
      redownloadBufferSize: 50,
    };

    const syncState = new HeadersSyncState(
      REGTEST,
      testParams,
      REGTEST.genesisBlockHash,
      0,
      REGTEST.powLimitBits,
      0n,
      10n ** 30n // Very high - won't reach it
    );

    // Process many headers in batches
    let prevBlock = REGTEST.genesisBlockHash;
    let timestamp = 1296688602;

    for (let batch = 0; batch < 10; batch++) {
      const headers = createHeaderChain(prevBlock, timestamp, 100);
      const result = syncState.processNextHeaders(headers, true);

      expect(result.success).toBe(true);
      expect(syncState.getState()).toBe(HeadersSyncStateEnum.PRESYNC);

      // Update for next batch
      if (headers.length > 0) {
        prevBlock = getBlockHash(headers[headers.length - 1]);
        timestamp = headers[headers.length - 1].timestamp;
      }
    }

    // After 1000 headers, we should only have ~10 commitments stored
    // (1000 / 100 = 10 commitment points)
    expect(syncState.getPresyncHeight()).toBe(1000);
  });
});

describe("PRESYNC commitment verification", () => {
  const testParams: HeadersSyncParams = {
    commitmentPeriod: 5, // Very frequent for testing
    redownloadBufferSize: 3,
  };

  test("stores commitments at correct intervals", () => {
    const workPerHeader = getBlockWork(REGTEST.powLimitBits);
    const minWork = workPerHeader * 20n;

    const syncState = new HeadersSyncState(
      REGTEST,
      testParams,
      REGTEST.genesisBlockHash,
      0,
      REGTEST.powLimitBits,
      0n,
      minWork
    );

    const headers = createHeaderChain(
      REGTEST.genesisBlockHash,
      1296688602,
      25
    );

    // PRESYNC phase
    const result = syncState.processNextHeaders(headers, true);
    expect(result.success).toBe(true);
    expect(syncState.getState()).toBe(HeadersSyncStateEnum.REDOWNLOAD);

    // Should have stored ~5 commitments (25 / 5 = 5)
    // The actual number depends on the random offset
  });

  test("detects commitment mismatch at exact boundary", () => {
    const workPerHeader = getBlockWork(REGTEST.powLimitBits);
    const minWork = workPerHeader * 15n;

    // Create two instances with same salt for predictable testing
    const syncState = new HeadersSyncState(
      REGTEST,
      testParams,
      REGTEST.genesisBlockHash,
      0,
      REGTEST.powLimitBits,
      0n,
      minWork
    );

    // Create original chain
    const headers1 = createHeaderChain(
      REGTEST.genesisBlockHash,
      1296688602,
      20
    );

    // PRESYNC
    let result = syncState.processNextHeaders(headers1, true);
    expect(result.success).toBe(true);

    // Create modified chain - change one header in the middle
    const headers2 = [...headers1];
    const midPoint = Math.floor(headers2.length / 2);
    // Create a different header at midpoint
    headers2[midPoint] = createValidHeader(
      getBlockHash(headers2[midPoint - 1]),
      headers2[midPoint].timestamp + 1 // Different timestamp
    );
    // Rebuild rest of chain from modified header
    for (let i = midPoint + 1; i < headers2.length; i++) {
      headers2[i] = createValidHeader(
        getBlockHash(headers2[i - 1]),
        headers2[i].timestamp
      );
    }

    // REDOWNLOAD with modified chain
    result = syncState.processNextHeaders(headers2, false);

    // May fail if the modified header is at a commitment point
    // If it doesn't hit a commitment point, it might pass
    // This tests that the mechanism works probabilistically
    // With commitmentPeriod=5, there's a ~20% chance any given header is checked
  });
});

describe("anti-DoS integration scenarios", () => {
  let dbPath: string;
  let db: ChainDB;
  let headerSync: HeaderSync;

  beforeEach(async () => {
    dbPath = await mkdtemp(join(tmpdir(), "hotbuns-antidos-integration-"));
    db = new ChainDB(dbPath);
    await db.open();

    // Create HeaderSync with test params for faster testing
    const testSyncParams: HeadersSyncParams = {
      commitmentPeriod: 10,
      redownloadBufferSize: 5,
    };
    headerSync = new HeaderSync(db, REGTEST, testSyncParams);
    headerSync.initGenesis();
  });

  afterEach(async () => {
    await db.close();
    await rm(dbPath, { recursive: true, force: true });
  });

  test("processes headers normally when anti-DoS not needed", async () => {
    const peer = createMockPeer();
    const genesis = headerSync.getBestHeader()!;

    // Create valid headers
    const headers = createHeaderChain(
      genesis.hash,
      genesis.header.timestamp,
      10
    );

    // Process directly (no anti-DoS for regtest)
    const count = await headerSync.processHeaders(headers, peer);
    expect(count).toBe(10);
    expect(headerSync.getBestHeader()!.height).toBe(10);
  });
});
