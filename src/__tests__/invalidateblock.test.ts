/**
 * Tests for chain management RPCs: invalidateblock, reconsiderblock, preciousblock.
 *
 * These RPCs allow manual control over block validity status:
 * - invalidateblock: Mark a block and descendants as invalid, trigger reorg
 * - reconsiderblock: Clear invalid status from a block and ancestors
 * - preciousblock: Mark a block for tie-breaking preference
 *
 * Reference: Bitcoin Core validation.cpp (InvalidateBlock, ReconsiderBlock, PreciousBlock)
 */

import { describe, it, expect, beforeEach, afterEach } from "bun:test";
import { mkdir, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { ChainDB, BlockStatus } from "../storage/database.js";
import { ChainStateManager, type ChainManagementResult } from "../chain/state.js";
import { REGTEST } from "../consensus/params.js";
import { serializeBlock, deserializeBlock, computeMerkleRoot, getBlockHash, type Block, type BlockHeader } from "../validation/block.js";
import { getTxId, type Transaction } from "../validation/tx.js";
import { BufferWriter } from "../wire/serialization.js";

// Helper to create a minimal coinbase transaction
function createCoinbaseTx(height: number, extraNonce: number = 0): Transaction {
  const writer = new BufferWriter();

  // scriptSig: height encoded per BIP34 + extra nonce
  const heightBytes = encodeScriptNum(height);
  const scriptSig = Buffer.concat([
    Buffer.from([heightBytes.length]),
    heightBytes,
    Buffer.from([4]),
    Buffer.alloc(4, extraNonce),
  ]);

  return {
    version: 1,
    inputs: [
      {
        prevOut: {
          txid: Buffer.alloc(32, 0),
          vout: 0xffffffff,
        },
        scriptSig,
        sequence: 0xffffffff,
        witness: [],
      },
    ],
    outputs: [
      {
        value: 5000000000n, // 50 BTC
        scriptPubKey: Buffer.from([0x51]), // OP_TRUE
      },
    ],
    lockTime: 0,
  };
}

// Encode a number for BIP34 height in coinbase
function encodeScriptNum(n: number): Buffer {
  if (n === 0) return Buffer.alloc(0);
  if (n < 0) throw new Error("Negative numbers not supported");

  const result: number[] = [];
  let absValue = n;
  while (absValue > 0) {
    result.push(absValue & 0xff);
    absValue >>= 8;
  }

  // If MSB has high bit set, add a 0x00 to indicate positive
  if (result[result.length - 1] & 0x80) {
    result.push(0);
  }

  return Buffer.from(result);
}

// Create a minimal valid block
function createBlock(
  prevHash: Buffer,
  height: number,
  transactions?: Transaction[]
): Block {
  const txs = transactions || [createCoinbaseTx(height)];
  const txids = txs.map((tx) => getTxId(tx));
  const merkleRoot = computeMerkleRoot(txids);

  const header: BlockHeader = {
    version: 0x20000000,
    prevBlock: prevHash,
    merkleRoot,
    timestamp: Math.floor(Date.now() / 1000),
    bits: REGTEST.powLimitBits,
    nonce: 0,
  };

  return { header, transactions: txs };
}

// Serialize a block header to 80 bytes
function serializeBlockHeader(header: BlockHeader): Buffer {
  const writer = new BufferWriter();
  writer.writeInt32LE(header.version);
  writer.writeHash(header.prevBlock);
  writer.writeHash(header.merkleRoot);
  writer.writeUInt32LE(header.timestamp);
  writer.writeUInt32LE(header.bits);
  writer.writeUInt32LE(header.nonce);
  return writer.toBuffer();
}

describe("Chain Management RPCs", () => {
  let dataDir: string;
  let db: ChainDB;
  let chainState: ChainStateManager;

  beforeEach(async () => {
    dataDir = join(
      tmpdir(),
      `hotbuns-invalidate-test-${Date.now()}-${Math.random().toString(36).slice(2)}`
    );
    await mkdir(dataDir, { recursive: true });

    db = new ChainDB(join(dataDir, "blocks.db"));
    await db.open();

    chainState = new ChainStateManager(db, REGTEST);
    await chainState.load();
  });

  afterEach(async () => {
    await db.close();
    try {
      await rm(dataDir, { recursive: true, force: true });
    } catch {
      // Ignore cleanup errors
    }
  });

  describe("BlockStatus flags", () => {
    it("should have FAILED_VALID flag defined", () => {
      expect(BlockStatus.FAILED_VALID).toBe(32);
    });

    it("should have FAILED_CHILD flag defined", () => {
      expect(BlockStatus.FAILED_CHILD).toBe(64);
    });

    it("should have OPT_WITNESS flag defined", () => {
      expect(BlockStatus.OPT_WITNESS).toBe(128);
    });
  });

  describe("invalidateBlock", () => {
    it("should return error for non-existent block", async () => {
      const fakeHash = Buffer.alloc(32, 0x42);
      const result = await chainState.invalidateBlock(fakeHash);

      expect(result.success).toBe(false);
      expect(result.error).toBe("Block not found");
    });

    it("should refuse to invalidate genesis block", async () => {
      // Create and store genesis block
      const genesisBlock = createBlock(Buffer.alloc(32, 0), 0);
      const genesisHash = getBlockHash(genesisBlock.header);
      const headerBytes = serializeBlockHeader(genesisBlock.header);

      await db.putBlockIndex(genesisHash, {
        height: 0,
        header: headerBytes,
        nTx: 1,
        status: BlockStatus.HEADER_VALID | BlockStatus.HAVE_DATA,
        dataPos: 0,
      });

      const result = await chainState.invalidateBlock(genesisHash);

      expect(result.success).toBe(false);
      expect(result.error).toBe("Cannot invalidate genesis block");
    });

    it("should mark a block as invalid", async () => {
      // Create two blocks
      const block0 = createBlock(Buffer.alloc(32, 0), 0);
      const hash0 = getBlockHash(block0.header);
      const header0Bytes = serializeBlockHeader(block0.header);

      await db.putBlockIndex(hash0, {
        height: 0,
        header: header0Bytes,
        nTx: 1,
        status: BlockStatus.HEADER_VALID | BlockStatus.HAVE_DATA,
        dataPos: 0,
      });

      const block1 = createBlock(hash0, 1);
      const hash1 = getBlockHash(block1.header);
      const header1Bytes = serializeBlockHeader(block1.header);

      await db.putBlockIndex(hash1, {
        height: 1,
        header: header1Bytes,
        nTx: 1,
        status: BlockStatus.HEADER_VALID | BlockStatus.HAVE_DATA,
        dataPos: 0,
      });

      // Invalidate block 1
      const result = await chainState.invalidateBlock(hash1);

      expect(result.success).toBe(true);

      // Check that it's marked invalid
      const isInvalid = await chainState.isBlockInvalid(hash1);
      expect(isInvalid).toBe(true);
    });

    it("should return success if block already invalid", async () => {
      const block = createBlock(Buffer.alloc(32, 0), 1);
      const hash = getBlockHash(block.header);
      const headerBytes = serializeBlockHeader(block.header);

      // Store with FAILED_VALID already set
      await db.putBlockIndex(hash, {
        height: 1,
        header: headerBytes,
        nTx: 1,
        status: BlockStatus.HEADER_VALID | BlockStatus.FAILED_VALID,
        dataPos: 0,
      });

      const result = await chainState.invalidateBlock(hash);

      expect(result.success).toBe(true);
      expect(result.blocksAffected).toBe(0);
    });
  });

  describe("reconsiderBlock", () => {
    it("should return error for non-existent block", async () => {
      const fakeHash = Buffer.alloc(32, 0x99);
      const result = await chainState.reconsiderBlock(fakeHash);

      expect(result.success).toBe(false);
      expect(result.error).toBe("Block not found");
    });

    it("should return success for block not marked invalid", async () => {
      const block = createBlock(Buffer.alloc(32, 0), 1);
      const hash = getBlockHash(block.header);
      const headerBytes = serializeBlockHeader(block.header);

      await db.putBlockIndex(hash, {
        height: 1,
        header: headerBytes,
        nTx: 1,
        status: BlockStatus.HEADER_VALID | BlockStatus.HAVE_DATA,
        dataPos: 0,
      });

      const result = await chainState.reconsiderBlock(hash);

      expect(result.success).toBe(true);
      expect(result.blocksAffected).toBe(0);
    });

    it("should clear FAILED_VALID flag", async () => {
      const block = createBlock(Buffer.alloc(32, 0), 1);
      const hash = getBlockHash(block.header);
      const headerBytes = serializeBlockHeader(block.header);

      // Store with FAILED_VALID set
      await db.putBlockIndex(hash, {
        height: 1,
        header: headerBytes,
        nTx: 1,
        status: BlockStatus.HEADER_VALID | BlockStatus.FAILED_VALID,
        dataPos: 0,
      });

      // Verify it's invalid
      expect(await chainState.isBlockInvalid(hash)).toBe(true);

      // Reconsider
      const result = await chainState.reconsiderBlock(hash);

      expect(result.success).toBe(true);
      expect(result.blocksAffected).toBeGreaterThanOrEqual(1);

      // Verify no longer invalid
      expect(await chainState.isBlockInvalid(hash)).toBe(false);
    });

    it("should clear FAILED_CHILD flag", async () => {
      const block = createBlock(Buffer.alloc(32, 0), 1);
      const hash = getBlockHash(block.header);
      const headerBytes = serializeBlockHeader(block.header);

      // Store with FAILED_CHILD set
      await db.putBlockIndex(hash, {
        height: 1,
        header: headerBytes,
        nTx: 1,
        status: BlockStatus.HEADER_VALID | BlockStatus.FAILED_CHILD,
        dataPos: 0,
      });

      // Verify it's invalid
      expect(await chainState.isBlockInvalid(hash)).toBe(true);

      // Reconsider
      const result = await chainState.reconsiderBlock(hash);

      expect(result.success).toBe(true);

      // Verify no longer invalid
      expect(await chainState.isBlockInvalid(hash)).toBe(false);
    });
  });

  describe("preciousBlock", () => {
    it("should return error for non-existent block", async () => {
      const fakeHash = Buffer.alloc(32, 0xaa);
      const result = await chainState.preciousBlock(fakeHash);

      expect(result.success).toBe(false);
      expect(result.error).toBe("Block not found");
    });

    it("should refuse to mark invalid block as precious", async () => {
      const block = createBlock(Buffer.alloc(32, 0), 1);
      const hash = getBlockHash(block.header);
      const headerBytes = serializeBlockHeader(block.header);

      // Store with FAILED_VALID set
      await db.putBlockIndex(hash, {
        height: 1,
        header: headerBytes,
        nTx: 1,
        status: BlockStatus.HEADER_VALID | BlockStatus.FAILED_VALID,
        dataPos: 0,
      });

      const result = await chainState.preciousBlock(hash);

      expect(result.success).toBe(false);
      expect(result.error).toBe("Cannot mark invalid block as precious");
    });

    it("should mark a valid block as precious", async () => {
      const block = createBlock(Buffer.alloc(32, 0), 1);
      const hash = getBlockHash(block.header);
      const headerBytes = serializeBlockHeader(block.header);

      await db.putBlockIndex(hash, {
        height: 1,
        header: headerBytes,
        nTx: 1,
        status: BlockStatus.HEADER_VALID | BlockStatus.HAVE_DATA,
        dataPos: 0,
      });

      const result = await chainState.preciousBlock(hash);

      expect(result.success).toBe(true);
      expect(chainState.isPreciousBlock(hash)).toBe(true);
    });

    it("should track precious block", async () => {
      const block = createBlock(Buffer.alloc(32, 0), 1);
      const hash = getBlockHash(block.header);
      const headerBytes = serializeBlockHeader(block.header);

      await db.putBlockIndex(hash, {
        height: 1,
        header: headerBytes,
        nTx: 1,
        status: BlockStatus.HEADER_VALID | BlockStatus.HAVE_DATA,
        dataPos: 0,
      });

      // Initially no precious block
      expect(chainState.getPreciousBlock()).toBeNull();

      // Mark as precious
      await chainState.preciousBlock(hash);

      // Now it should be tracked
      const precious = chainState.getPreciousBlock();
      expect(precious).not.toBeNull();
      expect(precious!.equals(hash)).toBe(true);
    });

    it("should replace previous precious block", async () => {
      // Create two blocks
      const block1 = createBlock(Buffer.alloc(32, 0), 1);
      const hash1 = getBlockHash(block1.header);
      const header1Bytes = serializeBlockHeader(block1.header);

      const block2 = createBlock(hash1, 2);
      const hash2 = getBlockHash(block2.header);
      const header2Bytes = serializeBlockHeader(block2.header);

      await db.putBlockIndex(hash1, {
        height: 1,
        header: header1Bytes,
        nTx: 1,
        status: BlockStatus.HEADER_VALID | BlockStatus.HAVE_DATA,
        dataPos: 0,
      });

      await db.putBlockIndex(hash2, {
        height: 2,
        header: header2Bytes,
        nTx: 1,
        status: BlockStatus.HEADER_VALID | BlockStatus.HAVE_DATA,
        dataPos: 0,
      });

      // Mark block1 as precious
      await chainState.preciousBlock(hash1);
      expect(chainState.isPreciousBlock(hash1)).toBe(true);
      expect(chainState.isPreciousBlock(hash2)).toBe(false);

      // Mark block2 as precious (replaces block1)
      await chainState.preciousBlock(hash2);
      expect(chainState.isPreciousBlock(hash1)).toBe(false);
      expect(chainState.isPreciousBlock(hash2)).toBe(true);
    });
  });

  describe("isBlockInvalid", () => {
    it("should return false for non-existent block", async () => {
      const fakeHash = Buffer.alloc(32, 0xbb);
      const isInvalid = await chainState.isBlockInvalid(fakeHash);
      expect(isInvalid).toBe(false);
    });

    it("should return false for valid block", async () => {
      const block = createBlock(Buffer.alloc(32, 0), 1);
      const hash = getBlockHash(block.header);
      const headerBytes = serializeBlockHeader(block.header);

      await db.putBlockIndex(hash, {
        height: 1,
        header: headerBytes,
        nTx: 1,
        status: BlockStatus.HEADER_VALID | BlockStatus.HAVE_DATA,
        dataPos: 0,
      });

      const isInvalid = await chainState.isBlockInvalid(hash);
      expect(isInvalid).toBe(false);
    });

    it("should return true for FAILED_VALID block", async () => {
      const block = createBlock(Buffer.alloc(32, 0), 1);
      const hash = getBlockHash(block.header);
      const headerBytes = serializeBlockHeader(block.header);

      await db.putBlockIndex(hash, {
        height: 1,
        header: headerBytes,
        nTx: 1,
        status: BlockStatus.HEADER_VALID | BlockStatus.FAILED_VALID,
        dataPos: 0,
      });

      const isInvalid = await chainState.isBlockInvalid(hash);
      expect(isInvalid).toBe(true);
    });

    it("should return true for FAILED_CHILD block", async () => {
      const block = createBlock(Buffer.alloc(32, 0), 1);
      const hash = getBlockHash(block.header);
      const headerBytes = serializeBlockHeader(block.header);

      await db.putBlockIndex(hash, {
        height: 1,
        header: headerBytes,
        nTx: 1,
        status: BlockStatus.HEADER_VALID | BlockStatus.FAILED_CHILD,
        dataPos: 0,
      });

      const isInvalid = await chainState.isBlockInvalid(hash);
      expect(isInvalid).toBe(true);
    });
  });

  describe("ChainManagementResult", () => {
    it("should have correct shape for success", async () => {
      const block = createBlock(Buffer.alloc(32, 0), 1);
      const hash = getBlockHash(block.header);
      const headerBytes = serializeBlockHeader(block.header);

      await db.putBlockIndex(hash, {
        height: 1,
        header: headerBytes,
        nTx: 1,
        status: BlockStatus.HEADER_VALID | BlockStatus.HAVE_DATA,
        dataPos: 0,
      });

      const result = await chainState.invalidateBlock(hash);

      expect(result).toHaveProperty("success");
      expect(result.success).toBe(true);
      expect(result.error).toBeUndefined();
    });

    it("should have correct shape for failure", async () => {
      const result = await chainState.invalidateBlock(Buffer.alloc(32, 0x42));

      expect(result).toHaveProperty("success");
      expect(result.success).toBe(false);
      expect(result).toHaveProperty("error");
      expect(typeof result.error).toBe("string");
    });
  });
});

describe("Integration: invalidate and reconsider workflow", () => {
  let dataDir: string;
  let db: ChainDB;
  let chainState: ChainStateManager;

  beforeEach(async () => {
    dataDir = join(
      tmpdir(),
      `hotbuns-invalidate-integ-${Date.now()}-${Math.random().toString(36).slice(2)}`
    );
    await mkdir(dataDir, { recursive: true });

    db = new ChainDB(join(dataDir, "blocks.db"));
    await db.open();

    chainState = new ChainStateManager(db, REGTEST);
    await chainState.load();
  });

  afterEach(async () => {
    await db.close();
    try {
      await rm(dataDir, { recursive: true, force: true });
    } catch {
      // Ignore cleanup errors
    }
  });

  it("should invalidate then reconsider a block", async () => {
    const block = createBlock(Buffer.alloc(32, 0), 1);
    const hash = getBlockHash(block.header);
    const headerBytes = serializeBlockHeader(block.header);

    await db.putBlockIndex(hash, {
      height: 1,
      header: headerBytes,
      nTx: 1,
      status: BlockStatus.HEADER_VALID | BlockStatus.HAVE_DATA,
      dataPos: 0,
    });

    // Initially valid
    expect(await chainState.isBlockInvalid(hash)).toBe(false);

    // Invalidate
    const invalidateResult = await chainState.invalidateBlock(hash);
    expect(invalidateResult.success).toBe(true);
    expect(await chainState.isBlockInvalid(hash)).toBe(true);

    // Reconsider
    const reconsiderResult = await chainState.reconsiderBlock(hash);
    expect(reconsiderResult.success).toBe(true);
    expect(await chainState.isBlockInvalid(hash)).toBe(false);
  });

  it("should not allow precious on invalidated block", async () => {
    const block = createBlock(Buffer.alloc(32, 0), 1);
    const hash = getBlockHash(block.header);
    const headerBytes = serializeBlockHeader(block.header);

    await db.putBlockIndex(hash, {
      height: 1,
      header: headerBytes,
      nTx: 1,
      status: BlockStatus.HEADER_VALID | BlockStatus.HAVE_DATA,
      dataPos: 0,
    });

    // Invalidate first
    await chainState.invalidateBlock(hash);

    // Try to mark precious - should fail
    const result = await chainState.preciousBlock(hash);
    expect(result.success).toBe(false);
    expect(result.error).toBe("Cannot mark invalid block as precious");
  });

  it("should allow precious after reconsider", async () => {
    const block = createBlock(Buffer.alloc(32, 0), 1);
    const hash = getBlockHash(block.header);
    const headerBytes = serializeBlockHeader(block.header);

    await db.putBlockIndex(hash, {
      height: 1,
      header: headerBytes,
      nTx: 1,
      status: BlockStatus.HEADER_VALID | BlockStatus.HAVE_DATA,
      dataPos: 0,
    });

    // Invalidate
    await chainState.invalidateBlock(hash);
    expect(await chainState.isBlockInvalid(hash)).toBe(true);

    // Reconsider
    await chainState.reconsiderBlock(hash);
    expect(await chainState.isBlockInvalid(hash)).toBe(false);

    // Now precious should work
    const result = await chainState.preciousBlock(hash);
    expect(result.success).toBe(true);
    expect(chainState.isPreciousBlock(hash)).toBe(true);
  });
});
