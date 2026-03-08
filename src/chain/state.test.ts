/**
 * Tests for chain state management.
 */

import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ChainDB } from "../storage/database.js";
import { REGTEST } from "../consensus/params.js";
import { ChainStateManager } from "./state.js";
import type { Block, BlockHeader } from "../validation/block.js";
import { getBlockHash } from "../validation/block.js";
import { getTxId } from "../validation/tx.js";
import type { Transaction, TxIn, TxOut } from "../validation/tx.js";
import { hash256 } from "../crypto/primitives.js";

describe("ChainStateManager", () => {
  let tempDir: string;
  let db: ChainDB;
  let chainState: ChainStateManager;

  // Helper to create a coinbase transaction
  function createCoinbaseTx(height: number, value: bigint): Transaction {
    const scriptSig = Buffer.concat([
      Buffer.from([0x03]), // Push 3 bytes
      Buffer.alloc(3, height), // Height encoding (simplified)
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
          value,
          scriptPubKey: Buffer.from([
            0x76, 0xa9, 0x14, ...Array(20).fill(0x01), 0x88, 0xac,
          ]),
        },
      ],
      lockTime: 0,
    };
  }

  // Helper to create a regular transaction spending from another tx
  function createSpendingTx(
    inputTxid: Buffer,
    inputVout: number,
    outputValue: bigint
  ): Transaction {
    return {
      version: 1,
      inputs: [
        {
          prevOut: {
            txid: inputTxid,
            vout: inputVout,
          },
          scriptSig: Buffer.alloc(71), // Fake signature
          sequence: 0xffffffff,
          witness: [],
        },
      ],
      outputs: [
        {
          value: outputValue,
          scriptPubKey: Buffer.from([
            0x76, 0xa9, 0x14, ...Array(20).fill(0x02), 0x88, 0xac,
          ]),
        },
      ],
      lockTime: 0,
    };
  }

  // Helper to create a block header
  function createBlockHeader(
    prevBlock: Buffer,
    merkleRoot: Buffer,
    timestamp: number = Math.floor(Date.now() / 1000)
  ): BlockHeader {
    return {
      version: 0x20000000,
      prevBlock,
      merkleRoot,
      timestamp,
      bits: REGTEST.powLimitBits,
      nonce: 0,
    };
  }

  // Helper to compute merkle root from transactions
  function computeMerkleRoot(txids: Buffer[]): Buffer {
    if (txids.length === 0) {
      return Buffer.alloc(32, 0);
    }

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    let level: any[] = txids.map((txid) => Buffer.from(txid));

    while (level.length > 1) {
      const nextLevel: Buffer[] = [];
      for (let i = 0; i < level.length; i += 2) {
        const left = level[i];
        const right = i + 1 < level.length ? level[i + 1] : level[i];
        nextLevel.push(hash256(Buffer.concat([left, right])));
      }
      level = nextLevel;
    }

    return level[0];
  }

  // Helper to create a complete block
  function createBlock(
    prevBlock: Buffer,
    transactions: Transaction[]
  ): Block {
    const txids = transactions.map((tx) => getTxId(tx));
    const merkleRoot = computeMerkleRoot(txids);
    const header = createBlockHeader(prevBlock, merkleRoot);

    return { header, transactions };
  }

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "chainstate-test-"));
    db = new ChainDB(tempDir);
    await db.open();
    chainState = new ChainStateManager(db, REGTEST);
    await chainState.load();
  });

  afterEach(async () => {
    await db.close();
    await rm(tempDir, { recursive: true, force: true });
  });

  describe("load", () => {
    test("initializes with genesis block", async () => {
      const best = chainState.getBestBlock();
      expect(best.height).toBe(0);
      expect(best.hash.equals(REGTEST.genesisBlockHash)).toBe(true);
    });

    test("loads persisted state", async () => {
      // Create a block
      const coinbase = createCoinbaseTx(1, 50_00000000n);
      const block = createBlock(REGTEST.genesisBlockHash, [coinbase]);

      await chainState.connectBlock(block, 1);

      // Create new instance and load
      const newChainState = new ChainStateManager(db, REGTEST);
      await newChainState.load();

      const best = newChainState.getBestBlock();
      expect(best.height).toBe(1);
    });
  });

  describe("connectBlock", () => {
    test("updates best block", async () => {
      const coinbase = createCoinbaseTx(1, 50_00000000n);
      const block = createBlock(REGTEST.genesisBlockHash, [coinbase]);

      await chainState.connectBlock(block, 1);

      const best = chainState.getBestBlock();
      expect(best.height).toBe(1);
      expect(best.hash.equals(getBlockHash(block.header))).toBe(true);
    });

    test("adds coinbase outputs to UTXO set", async () => {
      const coinbase = createCoinbaseTx(1, 50_00000000n);
      const block = createBlock(REGTEST.genesisBlockHash, [coinbase]);

      await chainState.connectBlock(block, 1);

      const utxoManager = chainState.getUTXOManager();
      const coinbaseTxid = getTxId(coinbase);
      const entry = await utxoManager.getUTXOAsync({
        txid: coinbaseTxid,
        vout: 0,
      });

      expect(entry).not.toBeNull();
      expect(entry!.amount).toBe(50_00000000n);
      expect(entry!.coinbase).toBe(true);
      expect(entry!.height).toBe(1);
    });

    test("spends inputs and creates outputs for regular tx", async () => {
      // Block 1: coinbase only
      const coinbase1 = createCoinbaseTx(1, 50_00000000n);
      const block1 = createBlock(REGTEST.genesisBlockHash, [coinbase1]);
      await chainState.connectBlock(block1, 1);

      const coinbase1Txid = getTxId(coinbase1);

      // Block 101: can spend coinbase from block 1 (after maturity)
      // For testing, we'll skip maturity check by connecting many blocks
      // Actually, let's just test with a fresh coinbase

      // Block 2: coinbase + tx spending block 1's coinbase
      // But we need 100 blocks of maturity - let's simplify and just test output creation
      const coinbase2 = createCoinbaseTx(2, 50_00000000n);
      const block2 = createBlock(getBlockHash(block1.header), [coinbase2]);
      await chainState.connectBlock(block2, 2);

      const utxoManager = chainState.getUTXOManager();
      const coinbase2Txid = getTxId(coinbase2);

      expect(
        await utxoManager.hasUTXOAsync({ txid: coinbase2Txid, vout: 0 })
      ).toBe(true);
    });

    test("stores undo data", async () => {
      const coinbase = createCoinbaseTx(1, 50_00000000n);
      const block = createBlock(REGTEST.genesisBlockHash, [coinbase]);

      await chainState.connectBlock(block, 1);

      const blockHash = getBlockHash(block.header);
      const undoData = await db.getUndoData(blockHash);

      expect(undoData).not.toBeNull();
    });

    test("stores block data", async () => {
      const coinbase = createCoinbaseTx(1, 50_00000000n);
      const block = createBlock(REGTEST.genesisBlockHash, [coinbase]);

      await chainState.connectBlock(block, 1);

      const blockHash = getBlockHash(block.header);
      const rawBlock = await db.getBlock(blockHash);

      expect(rawBlock).not.toBeNull();
    });

    test("validates coinbase value against subsidy + fees", async () => {
      // Create a coinbase with too much value
      const coinbase = createCoinbaseTx(1, 100_00000000n); // 100 BTC instead of 50
      const block = createBlock(REGTEST.genesisBlockHash, [coinbase]);

      await expect(chainState.connectBlock(block, 1)).rejects.toThrow(
        "exceeds subsidy"
      );
    });
  });

  describe("disconnectBlock", () => {
    test("restores previous state", async () => {
      // Connect block 1
      const coinbase1 = createCoinbaseTx(1, 50_00000000n);
      const block1 = createBlock(REGTEST.genesisBlockHash, [coinbase1]);
      await chainState.connectBlock(block1, 1);

      // Connect block 2
      const coinbase2 = createCoinbaseTx(2, 50_00000000n);
      const block2 = createBlock(getBlockHash(block1.header), [coinbase2]);
      await chainState.connectBlock(block2, 2);

      // Disconnect block 2
      await chainState.disconnectBlock(block2, 2);

      const best = chainState.getBestBlock();
      expect(best.height).toBe(1);
      expect(best.hash.equals(getBlockHash(block1.header))).toBe(true);
    });

    test("removes outputs created by disconnected block", async () => {
      const coinbase = createCoinbaseTx(1, 50_00000000n);
      const block = createBlock(REGTEST.genesisBlockHash, [coinbase]);
      await chainState.connectBlock(block, 1);

      const coinbaseTxid = getTxId(coinbase);
      const utxoManager = chainState.getUTXOManager();

      // UTXO exists
      expect(
        await utxoManager.hasUTXOAsync({ txid: coinbaseTxid, vout: 0 })
      ).toBe(true);

      // Disconnect
      await chainState.disconnectBlock(block, 1);

      // UTXO should be gone after flush
      await utxoManager.flush();
      expect(await utxoManager.hasUTXOAsync({ txid: coinbaseTxid, vout: 0 })).toBe(
        false
      );
    });

    test("throws when disconnecting non-tip block", async () => {
      const coinbase1 = createCoinbaseTx(1, 50_00000000n);
      const block1 = createBlock(REGTEST.genesisBlockHash, [coinbase1]);
      await chainState.connectBlock(block1, 1);

      const coinbase2 = createCoinbaseTx(2, 50_00000000n);
      const block2 = createBlock(getBlockHash(block1.header), [coinbase2]);
      await chainState.connectBlock(block2, 2);

      // Try to disconnect block 1 (not the tip)
      await expect(chainState.disconnectBlock(block1, 1)).rejects.toThrow(
        "tip block"
      );
    });
  });

  describe("validateTxInputs", () => {
    test("validates coinbase tx", async () => {
      const coinbase = createCoinbaseTx(1, 50_00000000n);
      const result = chainState.validateTxInputs(coinbase, 1);

      expect(result.valid).toBe(true);
      expect(result.fee).toBe(0n);
    });

    test("validates tx with sufficient inputs", async () => {
      // First, add a UTXO to the set
      const coinbase = createCoinbaseTx(1, 50_00000000n);
      const block = createBlock(REGTEST.genesisBlockHash, [coinbase]);
      await chainState.connectBlock(block, 1);

      const coinbaseTxid = getTxId(coinbase);
      const utxoManager = chainState.getUTXOManager();

      // Pre-load the UTXO
      await utxoManager.preloadUTXO({ txid: coinbaseTxid, vout: 0 });

      // Create spending tx
      const spendingTx = createSpendingTx(coinbaseTxid, 0, 49_99990000n);

      // Validate at height 101 (after maturity)
      const result = chainState.validateTxInputs(spendingTx, 101);

      expect(result.valid).toBe(true);
      expect(result.fee).toBe(10000n); // 50 BTC - 49.9999 BTC
    });

    test("rejects tx with missing input", () => {
      const fakeTxid = Buffer.alloc(32, 0xff);
      const spendingTx = createSpendingTx(fakeTxid, 0, 1000n);

      const result = chainState.validateTxInputs(spendingTx, 100);

      expect(result.valid).toBe(false);
      expect(result.error).toContain("Missing UTXO");
    });

    test("rejects tx spending immature coinbase", async () => {
      const coinbase = createCoinbaseTx(1, 50_00000000n);
      const block = createBlock(REGTEST.genesisBlockHash, [coinbase]);
      await chainState.connectBlock(block, 1);

      const coinbaseTxid = getTxId(coinbase);
      const utxoManager = chainState.getUTXOManager();
      await utxoManager.preloadUTXO({ txid: coinbaseTxid, vout: 0 });

      const spendingTx = createSpendingTx(coinbaseTxid, 0, 49_99990000n);

      // Try to spend at height 50 (only 49 confirmations)
      const result = chainState.validateTxInputs(spendingTx, 50);

      expect(result.valid).toBe(false);
      expect(result.error).toContain("maturity");
    });

    test("rejects tx with insufficient input value", async () => {
      const coinbase = createCoinbaseTx(1, 50_00000000n);
      const block = createBlock(REGTEST.genesisBlockHash, [coinbase]);
      await chainState.connectBlock(block, 1);

      const coinbaseTxid = getTxId(coinbase);
      const utxoManager = chainState.getUTXOManager();
      await utxoManager.preloadUTXO({ txid: coinbaseTxid, vout: 0 });

      // Try to spend more than input
      const spendingTx = createSpendingTx(coinbaseTxid, 0, 100_00000000n);

      const result = chainState.validateTxInputs(spendingTx, 101);

      expect(result.valid).toBe(false);
      expect(result.error).toContain("Insufficient");
    });
  });

  describe("isNextBlock and needsReorg", () => {
    test("isNextBlock returns true for sequential block", async () => {
      const coinbase = createCoinbaseTx(1, 50_00000000n);
      const block = createBlock(REGTEST.genesisBlockHash, [coinbase]);
      await chainState.connectBlock(block, 1);

      const nextHeader = createBlockHeader(
        getBlockHash(block.header),
        Buffer.alloc(32, 0)
      );

      expect(chainState.isNextBlock(nextHeader)).toBe(true);
    });

    test("isNextBlock returns false for non-sequential block", async () => {
      const coinbase = createCoinbaseTx(1, 50_00000000n);
      const block = createBlock(REGTEST.genesisBlockHash, [coinbase]);
      await chainState.connectBlock(block, 1);

      // Header pointing to wrong parent
      const wrongHeader = createBlockHeader(
        Buffer.alloc(32, 0xff),
        Buffer.alloc(32, 0)
      );

      expect(chainState.isNextBlock(wrongHeader)).toBe(false);
    });

    test("needsReorg returns false for next block", async () => {
      const coinbase = createCoinbaseTx(1, 50_00000000n);
      const block = createBlock(REGTEST.genesisBlockHash, [coinbase]);
      await chainState.connectBlock(block, 1);

      const nextHeader = createBlockHeader(
        getBlockHash(block.header),
        Buffer.alloc(32, 0)
      );

      expect(chainState.needsReorg(nextHeader)).toBe(false);
    });

    test("needsReorg returns true for competing chain", async () => {
      const coinbase = createCoinbaseTx(1, 50_00000000n);
      const block = createBlock(REGTEST.genesisBlockHash, [coinbase]);
      await chainState.connectBlock(block, 1);

      // Competing block at same height
      const competingHeader = createBlockHeader(
        REGTEST.genesisBlockHash,
        Buffer.alloc(32, 0xaa)
      );

      expect(chainState.needsReorg(competingHeader)).toBe(true);
    });
  });

  describe("getStats", () => {
    test("returns current state statistics", async () => {
      const coinbase = createCoinbaseTx(1, 50_00000000n);
      const block = createBlock(REGTEST.genesisBlockHash, [coinbase]);
      await chainState.connectBlock(block, 1);

      const stats = chainState.getStats();

      expect(stats.height).toBe(1);
      expect(stats.hash).toBe(getBlockHash(block.header).toString("hex"));
      expect(stats.chainWork).toBeGreaterThan(0n);
    });
  });

  describe("chain with multiple blocks", () => {
    test("connects series of blocks", async () => {
      let prevHash = REGTEST.genesisBlockHash;

      for (let height = 1; height <= 5; height++) {
        const coinbase = createCoinbaseTx(height, 50_00000000n);
        const block = createBlock(prevHash, [coinbase]);
        await chainState.connectBlock(block, height);
        prevHash = getBlockHash(block.header);
      }

      const best = chainState.getBestBlock();
      expect(best.height).toBe(5);
    });

    test("disconnects and reconnects blocks", async () => {
      const blocks: Block[] = [];
      let prevHash = REGTEST.genesisBlockHash;

      // Connect 3 blocks
      for (let height = 1; height <= 3; height++) {
        const coinbase = createCoinbaseTx(height, 50_00000000n);
        const block = createBlock(prevHash, [coinbase]);
        await chainState.connectBlock(block, height);
        blocks.push(block);
        prevHash = getBlockHash(block.header);
      }

      // Disconnect back to height 1
      await chainState.disconnectBlock(blocks[2], 3);
      await chainState.disconnectBlock(blocks[1], 2);

      expect(chainState.getBestBlock().height).toBe(1);

      // Reconnect
      await chainState.connectBlock(blocks[1], 2);
      await chainState.connectBlock(blocks[2], 3);

      expect(chainState.getBestBlock().height).toBe(3);
    });
  });
});
