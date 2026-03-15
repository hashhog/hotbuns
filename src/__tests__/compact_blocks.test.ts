/**
 * Tests for BIP152 compact block relay.
 */

import { describe, expect, test, beforeEach } from "bun:test";
import {
  deriveSipHashKeys,
  computeShortTxId,
  computeShortTxIdValue,
  shortIdToValue,
  valueToShortId,
  createCompactBlockFromBlock,
  PartiallyDownloadedBlock,
  ReadStatus,
  CompactBlockManager,
  createBlockTxnResponse,
  SHORT_TXID_LENGTH,
  COMPACT_BLOCK_VERSION_1,
  COMPACT_BLOCK_VERSION_2,
  MAX_HIGH_BANDWIDTH_PEERS,
} from "../p2p/compact_blocks.js";
import { serializeBlockHeader } from "../validation/block.js";
import { getTxId, getWTxId } from "../validation/tx.js";
import { sipHash24 } from "../storage/indexes.js";
import type { Block, BlockHeader } from "../validation/block.js";
import type { Transaction } from "../validation/tx.js";
import type { CmpctBlockPayload } from "../p2p/messages.js";
import type { MempoolEntry } from "../mempool/mempool.js";

// ============================================================================
// Test Helpers
// ============================================================================

/**
 * Create a mock block header.
 */
function createMockHeader(nonce: number = 0): BlockHeader {
  return {
    version: 1,
    prevBlock: Buffer.alloc(32, 0x01),
    merkleRoot: Buffer.alloc(32, 0x02),
    timestamp: 1600000000,
    bits: 0x1d00ffff,
    nonce,
  };
}

/**
 * Create a mock transaction.
 */
function createMockTx(id: number, hasWitness: boolean = false): Transaction {
  const tx: Transaction = {
    version: 1,
    inputs: [
      {
        prevOut: {
          txid: Buffer.alloc(32, id),
          vout: 0,
        },
        scriptSig: Buffer.from([0x00]),
        sequence: 0xffffffff,
        witness: hasWitness ? [Buffer.from([0x30, 0x44]), Buffer.alloc(33, id)] : [],
      },
    ],
    outputs: [
      {
        value: 50000000n,
        scriptPubKey: Buffer.from([0x76, 0xa9, 0x14, ...Buffer.alloc(20, id), 0x88, 0xac]),
      },
    ],
    lockTime: 0,
  };

  return tx;
}

/**
 * Create a mock coinbase transaction.
 */
function createMockCoinbase(height: number = 1): Transaction {
  return {
    version: 1,
    inputs: [
      {
        prevOut: {
          txid: Buffer.alloc(32, 0x00),
          vout: 0xffffffff,
        },
        scriptSig: Buffer.from([0x01, height & 0xff]),
        sequence: 0xffffffff,
        witness: [],
      },
    ],
    outputs: [
      {
        value: 5000000000n,
        scriptPubKey: Buffer.from([0x76, 0xa9, 0x14, ...Buffer.alloc(20, 0xaa), 0x88, 0xac]),
      },
    ],
    lockTime: 0,
  };
}

/**
 * Create a mock block with transactions.
 */
function createMockBlock(txCount: number, hasWitness: boolean = false): Block {
  const transactions: Transaction[] = [createMockCoinbase()];
  for (let i = 1; i < txCount; i++) {
    transactions.push(createMockTx(i, hasWitness));
  }
  return {
    header: createMockHeader(),
    transactions,
  };
}

/**
 * Create a mock mempool with specific transactions.
 */
function createMockMempool(txs: Transaction[]): {
  getTransaction(txid: Buffer): MempoolEntry | null;
  getAllEntries(): MempoolEntry[];
} {
  const entries: MempoolEntry[] = txs.map((tx) => ({
    tx,
    txid: getTxId(tx),
    fee: 1000n,
    feeRate: 1,
    vsize: 200,
    weight: 800,
    addedTime: Date.now(),
    height: 1,
    spentBy: new Set(),
    dependsOn: new Set(),
    ancestorCount: 1,
    ancestorSize: 200,
    descendantCount: 1,
    descendantSize: 200,
  }));

  const txidMap = new Map<string, MempoolEntry>();
  for (const entry of entries) {
    txidMap.set(entry.txid.toString("hex"), entry);
  }

  return {
    getTransaction(txid: Buffer): MempoolEntry | null {
      return txidMap.get(txid.toString("hex")) ?? null;
    },
    getAllEntries(): MempoolEntry[] {
      return entries;
    },
  };
}

// ============================================================================
// SipHash Short ID Tests
// ============================================================================

describe("BIP152 short ID calculation", () => {
  test("deriveSipHashKeys produces 64-bit keys", () => {
    const header = serializeBlockHeader(createMockHeader());
    const nonce = 0x123456789abcdef0n;

    const [k0, k1] = deriveSipHashKeys(header, nonce);

    // Keys should be valid bigints
    expect(typeof k0).toBe("bigint");
    expect(typeof k1).toBe("bigint");
    // Keys should be 64-bit (fit in uint64)
    expect(k0 < 2n ** 64n).toBe(true);
    expect(k1 < 2n ** 64n).toBe(true);
  });

  test("deriveSipHashKeys is deterministic", () => {
    const header = serializeBlockHeader(createMockHeader());
    const nonce = 0xfedcba9876543210n;

    const [k0a, k1a] = deriveSipHashKeys(header, nonce);
    const [k0b, k1b] = deriveSipHashKeys(header, nonce);

    expect(k0a).toBe(k0b);
    expect(k1a).toBe(k1b);
  });

  test("different nonces produce different keys", () => {
    const header = serializeBlockHeader(createMockHeader());

    const [k0a, k1a] = deriveSipHashKeys(header, 1n);
    const [k0b, k1b] = deriveSipHashKeys(header, 2n);

    // Very unlikely to be equal
    expect(k0a === k0b && k1a === k1b).toBe(false);
  });

  test("computeShortTxId produces 6-byte result", () => {
    const [k0, k1] = [0x0706050403020100n, 0x0f0e0d0c0b0a0908n];
    const wtxid = Buffer.alloc(32, 0xab);

    const shortId = computeShortTxId(k0, k1, wtxid);

    expect(shortId.length).toBe(SHORT_TXID_LENGTH);
  });

  test("computeShortTxId is deterministic", () => {
    const [k0, k1] = [0x123456789abcdef0n, 0xfedcba9876543210n];
    const wtxid = Buffer.alloc(32, 0xcd);

    const shortId1 = computeShortTxId(k0, k1, wtxid);
    const shortId2 = computeShortTxId(k0, k1, wtxid);

    expect(shortId1.equals(shortId2)).toBe(true);
  });

  test("computeShortTxId matches SipHash truncated to 6 bytes", () => {
    const [k0, k1] = [0x0001020304050607n, 0x08090a0b0c0d0e0fn];
    const wtxid = Buffer.alloc(32, 0x42);

    const shortId = computeShortTxId(k0, k1, wtxid);
    const fullHash = sipHash24(k0, k1, wtxid);
    const expected = fullHash & 0xffffffffffffn;

    const shortIdValue = shortIdToValue(shortId);
    expect(shortIdValue).toBe(expected);
  });

  test("shortIdToValue and valueToShortId are inverse operations", () => {
    const originalValue = 0x123456789abcn;
    const shortId = valueToShortId(originalValue);
    const recovered = shortIdToValue(shortId);

    expect(recovered).toBe(originalValue);
  });

  test("shortIdToValue throws on invalid length", () => {
    expect(() => shortIdToValue(Buffer.alloc(5))).toThrow("Invalid short ID length");
    expect(() => shortIdToValue(Buffer.alloc(7))).toThrow("Invalid short ID length");
  });
});

// ============================================================================
// Compact Block Creation Tests
// ============================================================================

describe("BIP152 compact block creation", () => {
  test("createCompactBlockFromBlock includes coinbase in prefilled", () => {
    const block = createMockBlock(3);
    const nonce = 0x1234567890abcdefn;

    const compact = createCompactBlockFromBlock(block, nonce);

    // Coinbase should be prefilled
    expect(compact.prefilledTxns.length).toBeGreaterThanOrEqual(1);
    expect(compact.prefilledTxns[0].index).toBe(0);
    expect(compact.prefilledTxns[0].tx).toBe(block.transactions[0]);
  });

  test("createCompactBlockFromBlock creates short IDs for non-coinbase txs", () => {
    const block = createMockBlock(5);
    const nonce = 0n;

    const compact = createCompactBlockFromBlock(block, nonce);

    // Should have 4 short IDs (all non-coinbase txs)
    expect(compact.shortIds.length).toBe(4);

    // Each short ID should be 6 bytes
    for (const shortId of compact.shortIds) {
      expect(shortId.length).toBe(6);
    }
  });

  test("createCompactBlockFromBlock preserves header", () => {
    const block = createMockBlock(2);
    const nonce = 123n;

    const compact = createCompactBlockFromBlock(block, nonce);

    expect(compact.header).toBe(block.header);
    expect(compact.nonce).toBe(nonce);
  });

  test("createCompactBlockFromBlock respects peerMempoolTxids", () => {
    const block = createMockBlock(4);
    const nonce = 999n;

    // Only tx at index 2 is expected in peer's mempool
    const wtxid = getWTxId(block.transactions[2]);
    const peerMempoolTxids = new Set([wtxid.toString("hex")]);

    const compact = createCompactBlockFromBlock(block, nonce, peerMempoolTxids);

    // Prefilled: coinbase (0), tx 1, tx 3
    expect(compact.prefilledTxns.length).toBe(3);
    // Short ID: only tx 2
    expect(compact.shortIds.length).toBe(1);
  });

  test("total tx count equals shortIds + prefilledTxns", () => {
    const block = createMockBlock(10);
    const nonce = 42n;

    const compact = createCompactBlockFromBlock(block, nonce);

    expect(compact.shortIds.length + compact.prefilledTxns.length).toBe(10);
  });
});

// ============================================================================
// Partially Downloaded Block Tests
// ============================================================================

describe("BIP152 PartiallyDownloadedBlock", () => {
  test("initData returns OK for valid compact block", () => {
    const block = createMockBlock(5);
    const nonce = 12345n;
    const compact = createCompactBlockFromBlock(block, nonce);
    const blockHash = "0".repeat(64);

    const partial = new PartiallyDownloadedBlock(compact, blockHash);
    const status = partial.initData(compact);

    expect(status).toBe(ReadStatus.OK);
  });

  test("initData populates prefilled transactions", () => {
    const block = createMockBlock(3);
    const compact = createCompactBlockFromBlock(block, 0n);
    const blockHash = "1".repeat(64);

    const partial = new PartiallyDownloadedBlock(compact, blockHash);
    partial.initData(compact);

    // Coinbase should be available
    expect(partial.isTxAvailable(0)).toBe(true);
    expect(partial.prefilledCount).toBe(1);
  });

  test("fillFromMempool finds matching transactions", () => {
    const block = createMockBlock(4);
    const nonce = 777n;
    const compact = createCompactBlockFromBlock(block, nonce);
    const blockHash = "2".repeat(64);

    // Mempool has all non-coinbase transactions
    const mempool = createMockMempool(block.transactions.slice(1));

    const partial = new PartiallyDownloadedBlock(compact, blockHash);
    partial.initData(compact);
    const missing = partial.fillFromMempool(mempool);

    // All transactions should be found
    expect(missing.length).toBe(0);
    expect(partial.isComplete()).toBe(true);
    expect(partial.mempoolCount).toBe(3);
  });

  test("fillFromMempool reports missing transactions", () => {
    const block = createMockBlock(5);
    const nonce = 888n;
    const compact = createCompactBlockFromBlock(block, nonce);
    const blockHash = "3".repeat(64);

    // Mempool only has transactions 1 and 2 (missing 3 and 4)
    const mempool = createMockMempool(block.transactions.slice(1, 3));

    const partial = new PartiallyDownloadedBlock(compact, blockHash);
    partial.initData(compact);
    const missing = partial.fillFromMempool(mempool);

    // Should be missing transactions at indices 3 and 4
    expect(missing.length).toBe(2);
    expect(partial.isComplete()).toBe(false);
  });

  test("fillFromBlockTxn completes reconstruction", () => {
    const block = createMockBlock(4);
    const nonce = 999n;
    const compact = createCompactBlockFromBlock(block, nonce);
    const blockHash = "4".repeat(64);

    // Empty mempool
    const mempool = createMockMempool([]);

    const partial = new PartiallyDownloadedBlock(compact, blockHash);
    partial.initData(compact);
    const missing = partial.fillFromMempool(mempool);

    // Should be missing all non-coinbase txs
    expect(missing.length).toBe(3);

    // Fill with blocktxn response
    const missingTxs = missing.map((i) => block.transactions[i]);
    const success = partial.fillFromBlockTxn(missingTxs);

    expect(success).toBe(true);
    expect(partial.isComplete()).toBe(true);
  });

  test("getBlock returns full block when complete", () => {
    const block = createMockBlock(3);
    const nonce = 111n;
    const compact = createCompactBlockFromBlock(block, nonce);
    const blockHash = "5".repeat(64);

    const mempool = createMockMempool(block.transactions.slice(1));

    const partial = new PartiallyDownloadedBlock(compact, blockHash);
    partial.initData(compact);
    partial.fillFromMempool(mempool);

    const reconstructed = partial.getBlock();

    expect(reconstructed).not.toBeNull();
    expect(reconstructed!.transactions.length).toBe(3);
  });

  test("getBlock returns null when incomplete", () => {
    const block = createMockBlock(5);
    const compact = createCompactBlockFromBlock(block, 0n);
    const blockHash = "6".repeat(64);

    const mempool = createMockMempool([]);

    const partial = new PartiallyDownloadedBlock(compact, blockHash);
    partial.initData(compact);
    partial.fillFromMempool(mempool);

    expect(partial.getBlock()).toBeNull();
  });
});

// ============================================================================
// CompactBlockManager Tests
// ============================================================================

describe("BIP152 CompactBlockManager", () => {
  let manager: CompactBlockManager;

  beforeEach(() => {
    manager = new CompactBlockManager();
  });

  test("handleSendCmpct updates peer state", () => {
    manager.handleSendCmpct("peer1", true, COMPACT_BLOCK_VERSION_2);

    expect(manager.peerSupportsCompact("peer1")).toBe(true);
    expect(manager.getNegotiatedVersion("peer1")).toBe(COMPACT_BLOCK_VERSION_2);
  });

  test("handleSendCmpct with disabled clears support", () => {
    manager.handleSendCmpct("peer1", true, COMPACT_BLOCK_VERSION_2);
    manager.handleSendCmpct("peer1", false, 0n);

    expect(manager.peerSupportsCompact("peer1")).toBe(false);
  });

  test("getNegotiatedVersion returns minimum version", () => {
    // Peer supports version 1, we support version 2
    manager.handleSendCmpct("peer1", true, COMPACT_BLOCK_VERSION_1);

    expect(manager.getNegotiatedVersion("peer1")).toBe(COMPACT_BLOCK_VERSION_1);
  });

  test("high bandwidth peer limit is enforced", () => {
    // Add MAX_HIGH_BANDWIDTH_PEERS peers
    for (let i = 0; i < MAX_HIGH_BANDWIDTH_PEERS; i++) {
      expect(manager.addHighBandwidthPeer(`peer${i}`)).toBe(true);
    }

    // Next one should fail
    expect(manager.addHighBandwidthPeer("peerExtra")).toBe(false);
  });

  test("removeHighBandwidthPeer allows new peers", () => {
    for (let i = 0; i < MAX_HIGH_BANDWIDTH_PEERS; i++) {
      manager.addHighBandwidthPeer(`peer${i}`);
    }

    manager.removeHighBandwidthPeer("peer0");

    expect(manager.addHighBandwidthPeer("peerNew")).toBe(true);
  });

  test("startBlockReconstruction initializes partial block", () => {
    const block = createMockBlock(4);
    const compact = createCompactBlockFromBlock(block, 123n);
    const blockHash = "7".repeat(64);

    manager.handleSendCmpct("peer1", true, COMPACT_BLOCK_VERSION_2);

    const partial = manager.startBlockReconstruction(compact, blockHash, "peer1");

    expect(partial).not.toBeNull();
    expect(partial!.blockHash).toBe(blockHash);
  });

  test("handleBlockTxn completes reconstruction", () => {
    const block = createMockBlock(3);
    const compact = createCompactBlockFromBlock(block, 456n);
    const blockHash = "8".repeat(64);
    const blockHashBuf = Buffer.from(blockHash, "hex");

    manager.handleSendCmpct("peer1", true, COMPACT_BLOCK_VERSION_2);

    const partial = manager.startBlockReconstruction(compact, blockHash, "peer1");
    expect(partial).not.toBeNull();

    // Empty mempool - all non-coinbase txs missing
    const mempool = createMockMempool([]);
    const missing = manager.tryFillFromMempool(partial!, mempool);

    // Create blocktxn response
    const missingTxs = missing.map((i) => block.transactions[i]);
    const reconstructed = manager.handleBlockTxn("peer1", {
      blockHash: blockHashBuf,
      transactions: missingTxs,
    });

    expect(reconstructed).not.toBeNull();
    expect(reconstructed!.transactions.length).toBe(3);
  });

  test("removePeer cleans up state", () => {
    manager.handleSendCmpct("peer1", true, COMPACT_BLOCK_VERSION_2);
    manager.addHighBandwidthPeer("peer1");

    manager.removePeer("peer1");

    expect(manager.peerSupportsCompact("peer1")).toBe(false);
    expect(manager.isHighBandwidthPeer("peer1")).toBe(false);
  });

  test("statistics are tracked correctly", () => {
    const block = createMockBlock(3);
    const compact = createCompactBlockFromBlock(block, 789n);
    const blockHash = "9".repeat(64);

    manager.handleSendCmpct("peer1", true, COMPACT_BLOCK_VERSION_2);

    const partial = manager.startBlockReconstruction(compact, blockHash, "peer1");

    // With full mempool
    const mempool = createMockMempool(block.transactions.slice(1));
    manager.tryFillFromMempool(partial!, mempool);

    const stats = manager.getStats();
    expect(stats.compactBlocksReceived).toBe(1);
    expect(stats.successfulReconstructions).toBe(1);
    expect(stats.mempoolHits).toBe(2); // 2 non-coinbase txs
  });

  test("getSuccessRate calculates correctly", () => {
    const mempool = createMockMempool([]);

    // Create blocks with varying reconstruction success
    for (let i = 0; i < 3; i++) {
      const block = createMockBlock(2); // Just coinbase + 1 tx
      const compact = createCompactBlockFromBlock(block, BigInt(i));
      const blockHash = `${i}`.repeat(64);

      manager.handleSendCmpct("peer1", true, COMPACT_BLOCK_VERSION_2);
      const partial = manager.startBlockReconstruction(compact, blockHash, "peer1");

      // All will need requests since mempool is empty
      if (partial) {
        manager.tryFillFromMempool(partial, mempool);
      }
    }

    // All needed requests, none were pure successes
    expect(manager.getSuccessRate()).toBe(0);
  });
});

// ============================================================================
// createBlockTxnResponse Tests
// ============================================================================

describe("BIP152 blocktxn response", () => {
  test("createBlockTxnResponse extracts requested transactions", () => {
    const block = createMockBlock(5);
    const blockHash = Buffer.alloc(32, 0xab);

    const request = {
      blockHash,
      indexes: [1, 3],
    };

    const response = createBlockTxnResponse(block, request);

    expect(response).not.toBeNull();
    expect(response!.transactions.length).toBe(2);
    expect(response!.transactions[0]).toBe(block.transactions[1]);
    expect(response!.transactions[1]).toBe(block.transactions[3]);
  });

  test("createBlockTxnResponse returns null for invalid index", () => {
    const block = createMockBlock(3);
    const blockHash = Buffer.alloc(32, 0xcd);

    const request = {
      blockHash,
      indexes: [0, 10], // Index 10 is out of bounds
    };

    const response = createBlockTxnResponse(block, request);

    expect(response).toBeNull();
  });

  test("createBlockTxnResponse handles empty request", () => {
    const block = createMockBlock(3);
    const blockHash = Buffer.alloc(32, 0xef);

    const request = {
      blockHash,
      indexes: [],
    };

    const response = createBlockTxnResponse(block, request);

    expect(response).not.toBeNull();
    expect(response!.transactions.length).toBe(0);
  });
});

// ============================================================================
// Short ID Collision Tests
// ============================================================================

describe("BIP152 short ID collision handling", () => {
  test("duplicate short IDs in compact block cause FAILED status", () => {
    const block = createMockBlock(3);
    const nonce = 0n;
    const compact = createCompactBlockFromBlock(block, nonce);
    const blockHash = "a".repeat(64);

    // Manually create a collision by duplicating a short ID
    if (compact.shortIds.length >= 2) {
      compact.shortIds[1] = compact.shortIds[0].slice();
    }

    const partial = new PartiallyDownloadedBlock(compact, blockHash);
    const status = partial.initData(compact);

    expect(status).toBe(ReadStatus.FAILED);
  });
});

// ============================================================================
// Integration Tests
// ============================================================================

describe("BIP152 full reconstruction flow", () => {
  test("complete reconstruction with mempool only", () => {
    const block = createMockBlock(6);
    const nonce = 0xdeadbeefcafen;

    // Create compact block
    const compact = createCompactBlockFromBlock(block, nonce);

    // Verify structure
    expect(compact.prefilledTxns.length).toBe(1); // Only coinbase
    expect(compact.shortIds.length).toBe(5); // 5 non-coinbase txs

    // Create mempool with all transactions
    const mempool = createMockMempool(block.transactions.slice(1));

    // Reconstruct
    const blockHash = "b".repeat(64);
    const partial = new PartiallyDownloadedBlock(compact, blockHash);
    const initStatus = partial.initData(compact);
    expect(initStatus).toBe(ReadStatus.OK);

    const missing = partial.fillFromMempool(mempool);
    expect(missing.length).toBe(0);

    const reconstructed = partial.getBlock();
    expect(reconstructed).not.toBeNull();
    expect(reconstructed!.transactions.length).toBe(6);

    // Verify all transactions match
    for (let i = 0; i < block.transactions.length; i++) {
      const originalTxid = getTxId(block.transactions[i]);
      const reconstructedTxid = getTxId(reconstructed!.transactions[i]);
      expect(originalTxid.equals(reconstructedTxid)).toBe(true);
    }
  });

  test("reconstruction with getblocktxn fallback", () => {
    const block = createMockBlock(5);
    const nonce = 0xcafebaben;

    const compact = createCompactBlockFromBlock(block, nonce);

    // Mempool only has some transactions
    const mempool = createMockMempool([block.transactions[1], block.transactions[3]]);

    const blockHash = "c".repeat(64);
    const partial = new PartiallyDownloadedBlock(compact, blockHash);
    partial.initData(compact);

    const missing = partial.fillFromMempool(mempool);

    // Should be missing indices 2 and 4
    expect(missing.length).toBe(2);
    expect(missing).toContain(2);
    expect(missing).toContain(4);

    // Fill with blocktxn
    const missingTxs = [block.transactions[2], block.transactions[4]];
    const success = partial.fillFromBlockTxn(missingTxs);
    expect(success).toBe(true);

    const reconstructed = partial.getBlock();
    expect(reconstructed).not.toBeNull();
    expect(reconstructed!.transactions.length).toBe(5);
  });

  test("witness transactions are handled correctly", () => {
    // Create block with witness transactions
    const block = createMockBlock(4, true);
    const nonce = 0x1234n;

    const compact = createCompactBlockFromBlock(block, nonce, new Set(), COMPACT_BLOCK_VERSION_2);

    // wtxid should be used for short ID (differs from txid for witness txs)
    const wtxid = getWTxId(block.transactions[1]);
    const txid = getTxId(block.transactions[1]);

    // For witness txs, these should differ
    if (block.transactions[1].inputs[0].witness?.length) {
      expect(wtxid.equals(txid)).toBe(false);
    }

    // Reconstruction should still work
    const mempool = createMockMempool(block.transactions.slice(1));
    const blockHash = "d".repeat(64);
    const partial = new PartiallyDownloadedBlock(compact, blockHash);
    partial.initData(compact);
    const missing = partial.fillFromMempool(mempool);

    expect(missing.length).toBe(0);
  });
});
