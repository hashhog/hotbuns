/**
 * Tests for block download and IBD synchronization.
 *
 * Tests block download state management, in-order processing,
 * stall detection, and UTXO updates.
 */

import { describe, test, expect, beforeEach, afterEach, mock } from "bun:test";
import { mkdtemp, rm } from "fs/promises";
import { tmpdir } from "os";
import { join } from "path";
import { ChainDB } from "../storage/database.js";
import { REGTEST, compactToBigInt } from "../consensus/params.js";
import {
  Block,
  BlockHeader,
  serializeBlockHeader,
  getBlockHash,
  computeMerkleRoot,
} from "../validation/block.js";
import { Transaction, serializeTx, getTxId } from "../validation/tx.js";
import { hash256 } from "../crypto/primitives.js";
import { HeaderSync } from "./headers.js";
import { BlockSync, type BlockDownloadState } from "./blocks.js";

/** Create a mock peer for testing */
function createMockPeer(host = "127.0.0.1", port = 8333): any {
  return {
    host,
    port,
    state: "connected",
    versionPayload: { startHeight: 1000, services: 0x409n },
    send: mock(() => {}),
  };
}

/** Create a mock peer manager for testing */
function createMockPeerManager(peers: any[] = []): any {
  const handlers: Map<string, Array<(peer: any, msg: any) => void>> = new Map();

  return {
    getConnectedPeers: () => peers,
    onMessage: (type: string, handler: (peer: any, msg: any) => void) => {
      const existing = handlers.get(type) ?? [];
      existing.push(handler);
      handlers.set(type, existing);
    },
    broadcast: mock(() => {}),
    increaseBanScore: mock(() => {}),
    updateBestHeight: mock(() => {}),
    // Helper to trigger handlers in tests
    _triggerMessage: (type: string, peer: any, msg: any) => {
      const existing = handlers.get(type) ?? [];
      for (const handler of existing) {
        handler(peer, msg);
      }
    },
  };
}

/**
 * Create a valid coinbase transaction (non-segwit, no witness).
 */
function createCoinbaseTx(height: number, value: bigint = 5000000000n): Transaction {
  // BIP34 height encoding
  const heightScript = Buffer.alloc(4);
  heightScript.writeUInt32LE(height);

  return {
    version: 1,
    inputs: [
      {
        prevOut: {
          txid: Buffer.alloc(32, 0),
          vout: 0xffffffff,
        },
        scriptSig: Buffer.concat([
          Buffer.from([0x03]), // Push 3 bytes
          heightScript.subarray(0, 3),
        ]),
        sequence: 0xffffffff,
        witness: [], // No witness for non-segwit coinbase
      },
    ],
    outputs: [
      {
        value,
        scriptPubKey: Buffer.from([
          0x76, 0xa9, 0x14, // OP_DUP OP_HASH160 PUSH20
          ...Buffer.alloc(20, 0x11), // Dummy pubkey hash
          0x88, 0xac, // OP_EQUALVERIFY OP_CHECKSIG
        ]),
      },
    ],
    lockTime: 0,
  };
}

/**
 * Create a valid block with proper merkle root and PoW.
 */
function createValidBlock(
  prevBlock: Buffer,
  timestamp: number,
  height: number
): Block {
  const coinbaseTx = createCoinbaseTx(height);

  // Compute merkle root from txid
  const txid = getTxId(coinbaseTx);
  const merkleRoot = computeMerkleRoot([txid]);

  // Build header with correct merkle root
  const baseHeader: BlockHeader = {
    version: 4,
    prevBlock,
    merkleRoot,
    timestamp,
    bits: REGTEST.powLimitBits,
    nonce: 0,
  };

  // Mine to find valid nonce
  const target = compactToBigInt(REGTEST.powLimitBits);
  for (let nonce = 0; nonce < 10000000; nonce++) {
    const header = { ...baseHeader, nonce };
    const hashBuf = getBlockHash(header);
    const hashReversed = Buffer.from(hashBuf).reverse();
    const hashValue = BigInt("0x" + hashReversed.toString("hex"));

    if (hashValue <= target) {
      return {
        header,
        transactions: [coinbaseTx],
      };
    }
  }

  // Should always find a valid nonce for regtest
  return {
    header: baseHeader,
    transactions: [coinbaseTx],
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

describe("BlockSync", () => {
  let dbPath: string;
  let db: ChainDB;
  let headerSync: HeaderSync;
  let blockSync: BlockSync;

  beforeEach(async () => {
    dbPath = await mkdtemp(join(tmpdir(), "hotbuns-blocks-test-"));
    db = new ChainDB(dbPath);
    await db.open();
    headerSync = new HeaderSync(db, REGTEST);
    headerSync.initGenesis();
    blockSync = new BlockSync(db, REGTEST, headerSync);
  });

  afterEach(async () => {
    await blockSync.stop();
    await db.close();
    await rm(dbPath, { recursive: true, force: true });
  });

  describe("initialization", () => {
    test("initializes with correct default state", () => {
      const state = blockSync.getState();

      expect(state.pendingBlocks.size).toBe(0);
      expect(state.downloadedBlocks.size).toBe(0);
      expect(state.nextHeightToProcess).toBe(1);
      expect(state.nextHeightToRequest).toBe(1);
    });

    test("starts with IBD not complete", () => {
      expect(blockSync.isIBDComplete()).toBe(false);
    });

    test("progress is 0% initially", () => {
      expect(blockSync.getProgress()).toBe(0);
    });
  });

  describe("block download state", () => {
    test("tracks pending block requests", async () => {
      const peer = createMockPeer();
      const peerManager = createMockPeerManager([peer]);

      // Create a valid block at height 1
      const genesis = headerSync.getBestHeader()!;
      const block1 = createValidBlock(
        genesis.hash,
        genesis.header.timestamp + 600,
        1
      );

      // Add the header from this block
      await headerSync.processHeaders([block1.header], peer);

      // Create block sync with peer manager
      const bs = new BlockSync(db, REGTEST, headerSync, peerManager);
      await bs.start();

      // Give time for requestBlocks to run
      await new Promise((resolve) => setTimeout(resolve, 10));

      const state = bs.getState();
      // Should have requested the block at height 1
      expect(state.pendingBlocks.size).toBe(1);

      await bs.stop();
    });

    test("stores downloaded blocks until processed", async () => {
      const peer = createMockPeer();

      // Create valid blocks for heights 1, 2, 3
      const genesis = headerSync.getBestHeader()!;
      const blocks: Block[] = [];
      let prevBlock = genesis.hash;
      let timestamp = genesis.header.timestamp + 600;

      for (let i = 0; i < 3; i++) {
        const block = createValidBlock(prevBlock, timestamp, i + 1);
        blocks.push(block);
        prevBlock = getBlockHash(block.header);
        timestamp += 600;
      }

      // Add headers
      const headers = blocks.map((b) => b.header);
      await headerSync.processHeaders(headers, peer);

      // Simulate receiving block at height 2 before height 1
      const block2Hash = getBlockHash(blocks[1].header);
      await blockSync.handleBlock(peer, blocks[1]);

      const state = blockSync.getState();
      // Block 2 should be stored but not processed (waiting for block 1)
      expect(state.downloadedBlocks.has(block2Hash.toString("hex"))).toBe(true);
      expect(state.nextHeightToProcess).toBe(1); // Still waiting for block 1
    });
  });

  describe("in-order processing", () => {
    test("processes blocks in height order", async () => {
      const peer = createMockPeer();

      // Create valid blocks
      const genesis = headerSync.getBestHeader()!;
      const blocks: Block[] = [];
      let prevBlock = genesis.hash;
      let timestamp = genesis.header.timestamp + 600;

      for (let i = 0; i < 5; i++) {
        const block = createValidBlock(prevBlock, timestamp, i + 1);
        blocks.push(block);
        prevBlock = getBlockHash(block.header);
        timestamp += 600;
      }

      // Add headers
      const headers = blocks.map((b) => b.header);
      await headerSync.processHeaders(headers, peer);

      // Deliver blocks in random order: 3, 1, 4, 2, 5
      const order = [2, 0, 3, 1, 4]; // indices into blocks array

      for (const idx of order) {
        await blockSync.handleBlock(peer, blocks[idx]);
      }

      const state = blockSync.getState();
      // All blocks should be processed in order
      expect(state.nextHeightToProcess).toBe(6);
      expect(state.downloadedBlocks.size).toBe(0);
    });

    test("waits for missing blocks before proceeding", async () => {
      const peer = createMockPeer();

      // Create valid blocks
      const genesis = headerSync.getBestHeader()!;
      const blocks: Block[] = [];
      let prevBlock = genesis.hash;
      let timestamp = genesis.header.timestamp + 600;

      for (let i = 0; i < 3; i++) {
        const block = createValidBlock(prevBlock, timestamp, i + 1);
        blocks.push(block);
        prevBlock = getBlockHash(block.header);
        timestamp += 600;
      }

      // Add headers
      const headers = blocks.map((b) => b.header);
      await headerSync.processHeaders(headers, peer);

      // Deliver blocks 2 and 3, but not 1
      for (const idx of [1, 2]) {
        await blockSync.handleBlock(peer, blocks[idx]);
      }

      const state = blockSync.getState();
      // Should still be waiting for block 1
      expect(state.nextHeightToProcess).toBe(1);
      // Blocks 2 and 3 should be buffered
      expect(state.downloadedBlocks.size).toBe(2);
    });
  });

  describe("stall detection", () => {
    test("detects stalled requests", async () => {
      const peer = createMockPeer();
      // Use empty peer manager so re-requests don't happen
      const peerManager = createMockPeerManager([]);

      // Create a valid block
      const genesis = headerSync.getBestHeader()!;
      const block1 = createValidBlock(
        genesis.hash,
        genesis.header.timestamp + 600,
        1
      );
      await headerSync.processHeaders([block1.header], peer);

      const bs = new BlockSync(db, REGTEST, headerSync, peerManager);

      // Set running to true (normally done by start())
      (bs as any).running = true;

      // Manually manipulate state to simulate a stalled request
      const hash = getBlockHash(block1.header);
      const peerKey = `${peer.host}:${peer.port}`;

      // Set up peer in-flight tracking
      (bs as any).peerInFlight.set(peerKey, {
        count: 1,
        lastResponse: Date.now(),
        stallTimeout: 5000,
      });

      bs.getState().pendingBlocks.set(hash.toString("hex"), {
        height: 1,
        peer: peerKey,
        requestedAt: Date.now() - 100000, // 100 seconds ago
        timeout: 5000, // 5 second timeout
      });
      bs.getState().nextHeightToRequest = 2;

      // Trigger stall handling
      bs.handleStalled();

      const state = bs.getState();
      // Stalled request should be cleared (no peers available to re-request)
      expect(state.pendingBlocks.has(hash.toString("hex"))).toBe(false);
      // nextHeightToRequest should be reset
      expect(state.nextHeightToRequest).toBe(1);

      await bs.stop();
    });

    test("increases peer ban score on repeated stalls", async () => {
      const peer = createMockPeer();
      const peerManager = createMockPeerManager([peer]);

      // Create valid blocks
      const genesis = headerSync.getBestHeader()!;
      const blocks: Block[] = [];
      let prevBlock = genesis.hash;
      let timestamp = genesis.header.timestamp + 600;

      for (let i = 0; i < 10; i++) {
        const block = createValidBlock(prevBlock, timestamp, i + 1);
        blocks.push(block);
        prevBlock = getBlockHash(block.header);
        timestamp += 600;
      }

      const headers = blocks.map((b) => b.header);
      await headerSync.processHeaders(headers, peer);

      const bs = new BlockSync(db, REGTEST, headerSync, peerManager);
      const peerKey = `${peer.host}:${peer.port}`;

      // Set running to true (normally done by start())
      (bs as any).running = true;

      // Set up peer in-flight tracking
      (bs as any).peerInFlight.set(peerKey, {
        count: 6,
        lastResponse: Date.now(),
        stallTimeout: 5000,
      });

      // Simulate many stalled requests from the same peer
      for (let i = 0; i < 6; i++) {
        const hash = getBlockHash(blocks[i].header);
        bs.getState().pendingBlocks.set(hash.toString("hex"), {
          height: i + 1,
          peer: peerKey,
          requestedAt: Date.now() - 100000,
          timeout: 5000,
        });
      }

      bs.handleStalled();

      // Should have tried to increase ban score
      expect(peerManager.increaseBanScore).toHaveBeenCalled();

      await bs.stop();
    });
  });

  describe("IBD completion", () => {
    test("marks IBD complete when all blocks processed", async () => {
      const peer = createMockPeer();

      // Create a valid block at height 1
      const genesis = headerSync.getBestHeader()!;
      const block1 = createValidBlock(
        genesis.hash,
        genesis.header.timestamp + 600,
        1
      );
      await headerSync.processHeaders([block1.header], peer);

      // Deliver the block
      await blockSync.handleBlock(peer, block1);

      expect(blockSync.isIBDComplete()).toBe(true);
    });

    test("reports correct progress during IBD", async () => {
      const peer = createMockPeer();

      // Create valid blocks
      const genesis = headerSync.getBestHeader()!;
      const blocks: Block[] = [];
      let prevBlock = genesis.hash;
      let timestamp = genesis.header.timestamp + 600;

      for (let i = 0; i < 10; i++) {
        const block = createValidBlock(prevBlock, timestamp, i + 1);
        blocks.push(block);
        prevBlock = getBlockHash(block.header);
        timestamp += 600;
      }

      const headers = blocks.map((b) => b.header);
      await headerSync.processHeaders(headers, peer);

      // Process 5 blocks
      for (let i = 0; i < 5; i++) {
        await blockSync.handleBlock(peer, blocks[i]);
      }

      const progress = blockSync.getProgress();
      expect(progress).toBeCloseTo(50, 0); // 50% complete
    });
  });

  describe("block validation", () => {
    test("rejects blocks that fail validation", async () => {
      const peer = createMockPeer();

      // Create a valid block to get header
      const genesis = headerSync.getBestHeader()!;
      const block1 = createValidBlock(
        genesis.hash,
        genesis.header.timestamp + 600,
        1
      );
      await headerSync.processHeaders([block1.header], peer);

      // Create an invalid block (no transactions)
      const invalidBlock: Block = {
        header: block1.header,
        transactions: [], // Empty - invalid
      };

      const result = await blockSync.connectBlock(invalidBlock, 1);
      expect(result).toBe(false);
    });

    test("accepts valid blocks", async () => {
      const peer = createMockPeer();

      // Create a valid block
      const genesis = headerSync.getBestHeader()!;
      const block1 = createValidBlock(
        genesis.hash,
        genesis.header.timestamp + 600,
        1
      );
      await headerSync.processHeaders([block1.header], peer);

      const result = await blockSync.connectBlock(block1, 1);
      expect(result).toBe(true);

      // Flush and verify chain state
      await blockSync.stop();
      const chainState = await db.getChainState();
      expect(chainState).not.toBeNull();
      expect(chainState!.bestHeight).toBe(1);
    });

    test("rejects blocks that don't match header", async () => {
      const peer = createMockPeer();

      // Create two different valid blocks at height 1
      const genesis = headerSync.getBestHeader()!;
      const block1 = createValidBlock(
        genesis.hash,
        genesis.header.timestamp + 600,
        1
      );
      const block1Alt = createValidBlock(
        genesis.hash,
        genesis.header.timestamp + 601, // Different timestamp
        1
      );

      // Add the first block's header
      await headerSync.processHeaders([block1.header], peer);

      // Try to connect the alternate block (different header)
      const result = await blockSync.connectBlock(block1Alt, 1);
      expect(result).toBe(false);
    });
  });

  describe("UTXO management", () => {
    test("creates UTXOs for block outputs", async () => {
      const peer = createMockPeer();

      // Create a valid block
      const genesis = headerSync.getBestHeader()!;
      const block1 = createValidBlock(
        genesis.hash,
        genesis.header.timestamp + 600,
        1
      );
      await headerSync.processHeaders([block1.header], peer);

      await blockSync.handleBlock(peer, block1);

      // Flush to database
      await blockSync.stop();

      // Check UTXO was created for coinbase output
      const coinbaseTxid = getTxId(block1.transactions[0]);
      const utxo = await db.getUTXO(coinbaseTxid, 0);

      expect(utxo).not.toBeNull();
      expect(utxo!.coinbase).toBe(true);
      expect(utxo!.height).toBe(1);
    });
  });

  describe("database persistence", () => {
    test("persists block data to database", async () => {
      const peer = createMockPeer();

      // Create a valid block
      const genesis = headerSync.getBestHeader()!;
      const block1 = createValidBlock(
        genesis.hash,
        genesis.header.timestamp + 600,
        1
      );
      await headerSync.processHeaders([block1.header], peer);

      await blockSync.handleBlock(peer, block1);
      await blockSync.stop(); // Flush

      const blockHash = getBlockHash(block1.header);

      // Check block index
      const blockIndex = await db.getBlockIndex(blockHash);
      expect(blockIndex).not.toBeNull();
      expect(blockIndex!.height).toBe(1);
      expect(blockIndex!.status & 4).toBe(4); // txs-valid

      // Check raw block data
      const rawBlock = await db.getBlock(blockHash);
      expect(rawBlock).not.toBeNull();
    });

    test("updates chain state on block connect", async () => {
      const peer = createMockPeer();

      // Create a valid block
      const genesis = headerSync.getBestHeader()!;
      const block1 = createValidBlock(
        genesis.hash,
        genesis.header.timestamp + 600,
        1
      );
      await headerSync.processHeaders([block1.header], peer);

      await blockSync.handleBlock(peer, block1);

      const chainState = await db.getChainState();
      expect(chainState).not.toBeNull();
      expect(chainState!.bestHeight).toBe(1);
      expect(
        chainState!.bestBlockHash.equals(getBlockHash(block1.header))
      ).toBe(true);
    });
  });

  describe("peer request distribution", () => {
    test("distributes requests across multiple peers", async () => {
      const peer1 = createMockPeer("192.168.1.1", 8333);
      const peer2 = createMockPeer("192.168.1.2", 8333);
      const peer3 = createMockPeer("192.168.1.3", 8333);
      const peerManager = createMockPeerManager([peer1, peer2, peer3]);

      // Create valid blocks
      const genesis = headerSync.getBestHeader()!;
      const blocks: Block[] = [];
      let prevBlock = genesis.hash;
      let timestamp = genesis.header.timestamp + 600;

      for (let i = 0; i < 30; i++) {
        const block = createValidBlock(prevBlock, timestamp, i + 1);
        blocks.push(block);
        prevBlock = getBlockHash(block.header);
        timestamp += 600;
      }

      const headers = blocks.map((b) => b.header);
      await headerSync.processHeaders(headers, peer1);

      const bs = new BlockSync(db, REGTEST, headerSync, peerManager);
      await bs.start();

      // Give time for requestBlocks to run
      await new Promise((resolve) => setTimeout(resolve, 50));

      // All three peers should have received some requests
      expect(peer1.send).toHaveBeenCalled();
      expect(peer2.send).toHaveBeenCalled();
      expect(peer3.send).toHaveBeenCalled();

      await bs.stop();
    });
  });
});

describe("BlockSync getdata batching", () => {
  let dbPath: string;
  let db: ChainDB;
  let headerSync: HeaderSync;

  beforeEach(async () => {
    dbPath = await mkdtemp(join(tmpdir(), "hotbuns-blocks-getdata-test-"));
    db = new ChainDB(dbPath);
    await db.open();
    headerSync = new HeaderSync(db, REGTEST);
    headerSync.initGenesis();
  });

  afterEach(async () => {
    await db.close();
    await rm(dbPath, { recursive: true, force: true });
  });

  test("sends multiple inv items per getdata message", async () => {
    const peer = createMockPeer();
    const peerManager = createMockPeerManager([peer]);

    // Create valid blocks
    const genesis = headerSync.getBestHeader()!;
    const blocks: Block[] = [];
    let prevBlock = genesis.hash;
    let timestamp = genesis.header.timestamp + 600;

    for (let i = 0; i < 10; i++) {
      const block = createValidBlock(prevBlock, timestamp, i + 1);
      blocks.push(block);
      prevBlock = getBlockHash(block.header);
      timestamp += 600;
    }

    const headers = blocks.map((b) => b.header);
    await headerSync.processHeaders(headers, peer);

    const bs = new BlockSync(db, REGTEST, headerSync, peerManager);
    await bs.start();

    await new Promise((resolve) => setTimeout(resolve, 50));

    // Check that getdata was sent with multiple items
    const sendCalls = peer.send.mock.calls;
    expect(sendCalls.length).toBeGreaterThan(0);

    // Find getdata messages
    const getdataCalls = sendCalls.filter(
      (call: any) => call[0].type === "getdata"
    );
    expect(getdataCalls.length).toBeGreaterThan(0);

    // At least one getdata should have multiple items
    const multiItemGetdata = getdataCalls.some(
      (call: any) => call[0].payload.inventory.length > 1
    );
    expect(multiItemGetdata).toBe(true);

    await bs.stop();
  });
});
