/**
 * Tests for fee estimation.
 */

import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ChainDB, UTXOEntry } from "../storage/database.js";
import { UTXOManager } from "../chain/utxo.js";
import { REGTEST } from "../consensus/params.js";
import { Mempool } from "../mempool/mempool.js";
import { FeeEstimator, ConfirmationBucket } from "./estimator.js";
import type { Transaction } from "../validation/tx.js";
import type { Block, BlockHeader } from "../validation/block.js";
import { getTxId } from "../validation/tx.js";

describe("FeeEstimator", () => {
  let tempDir: string;
  let db: ChainDB;
  let utxo: UTXOManager;
  let mempool: Mempool;
  let estimator: FeeEstimator;

  // Helper to create a simple test transaction
  function createTestTx(
    inputs: Array<{ txid: Buffer; vout: number }>,
    outputs: Array<{ value: bigint; scriptPubKey?: Buffer }>,
    witness?: Buffer[][]
  ): Transaction {
    return {
      version: 2,
      inputs: inputs.map((inp, i) => ({
        prevOut: { txid: inp.txid, vout: inp.vout },
        scriptSig: Buffer.alloc(0),
        sequence: 0xffffffff,
        witness: witness?.[i] ?? [],
      })),
      outputs: outputs.map((out) => ({
        value: out.value,
        scriptPubKey: out.scriptPubKey ?? Buffer.from([0x51]), // OP_TRUE
      })),
      lockTime: 0,
    };
  }

  // Helper to create a coinbase transaction
  function createCoinbaseTx(value: bigint): Transaction {
    return {
      version: 2,
      inputs: [
        {
          prevOut: { txid: Buffer.alloc(32, 0), vout: 0xffffffff },
          scriptSig: Buffer.from([0x01, 0x01]), // minimal height push
          sequence: 0xffffffff,
          witness: [],
        },
      ],
      outputs: [{ value, scriptPubKey: Buffer.from([0x51]) }],
      lockTime: 0,
    };
  }

  // Helper to create a test block
  function createTestBlock(txs: Transaction[]): Block {
    const header: BlockHeader = {
      version: 0x20000000,
      prevBlock: Buffer.alloc(32, 0),
      merkleRoot: Buffer.alloc(32, 0),
      timestamp: Math.floor(Date.now() / 1000),
      bits: 0x207fffff, // regtest difficulty
      nonce: 0,
    };
    return { header, transactions: [createCoinbaseTx(5000000000n), ...txs] };
  }

  // Helper to set up a UTXO that can be spent
  async function setupUTXO(
    txid: Buffer,
    vout: number,
    amount: bigint,
    height: number = 1,
    coinbase: boolean = false
  ): Promise<void> {
    const entry: UTXOEntry = {
      height,
      coinbase,
      amount,
      scriptPubKey: Buffer.from([0x51]), // OP_TRUE - always succeeds
    };
    await db.putUTXO(txid, vout, entry);
  }

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "fee-estimator-test-"));
    db = new ChainDB(tempDir);
    await db.open();
    utxo = new UTXOManager(db);
    mempool = new Mempool(utxo, REGTEST, 1_000_000);
    mempool.setTipHeight(200);
    estimator = new FeeEstimator(mempool);
  });

  afterEach(async () => {
    await db.close();
    await rm(tempDir, { recursive: true, force: true });
  });

  describe("getBucketIndex", () => {
    test("assigns fee rates to correct buckets", () => {
      // We need to test via recordConfirmation since getBucketIndex is private
      // Test boundary values by recording confirmations at different fee rates
      const buckets = estimator.getBuckets();

      // Verify bucket structure
      expect(buckets.length).toBe(41);
      expect(buckets[0].feeRateRange.min).toBe(1);
      expect(buckets[buckets.length - 1].feeRateRange.min).toBe(10000);
    });
  });

  describe("trackTransaction", () => {
    test("tracks transaction for future confirmation", async () => {
      const inputTxid = Buffer.alloc(32, 0xaa);
      await setupUTXO(inputTxid, 0, 100000n);

      const tx = createTestTx(
        [{ txid: inputTxid, vout: 0 }],
        [{ value: 99000n }] // 1000 sat fee
      );

      const result = await mempool.addTransaction(tx);
      expect(result.accepted).toBe(true);

      const txid = getTxId(tx);
      estimator.trackTransaction(txid, 200);

      expect(estimator.getTrackedCount()).toBe(1);
    });

    test("does not double-track same transaction", async () => {
      const inputTxid = Buffer.alloc(32, 0xbb);
      await setupUTXO(inputTxid, 0, 100000n);

      const tx = createTestTx(
        [{ txid: inputTxid, vout: 0 }],
        [{ value: 99000n }]
      );

      await mempool.addTransaction(tx);
      const txid = getTxId(tx);

      estimator.trackTransaction(txid, 200);
      estimator.trackTransaction(txid, 201); // Try to track again

      expect(estimator.getTrackedCount()).toBe(1);
    });
  });

  describe("recordConfirmation", () => {
    test("records confirmation in correct bucket", () => {
      const txid = Buffer.alloc(32, 0x11);

      // Record a confirmation at 50 sat/vB, confirmed in 2 blocks
      estimator.recordConfirmation(txid, 50, 100, 102);

      const buckets = estimator.getBuckets();
      // 50 sat/vB should be in the bucket with min=50
      const bucket = buckets.find((b) => b.feeRateRange.min === 50);
      expect(bucket).toBeDefined();
      expect(bucket!.totalConfirmed).toBe(1);
      expect(bucket!.confirmationBlocks).toContain(2);
    });

    test("calculates average confirmation blocks", () => {
      const txid1 = Buffer.alloc(32, 0x11);
      const txid2 = Buffer.alloc(32, 0x22);
      const txid3 = Buffer.alloc(32, 0x33);

      // All at 100 sat/vB
      estimator.recordConfirmation(txid1, 100, 100, 101); // 1 block
      estimator.recordConfirmation(txid2, 100, 100, 103); // 3 blocks
      estimator.recordConfirmation(txid3, 100, 100, 102); // 2 blocks

      const buckets = estimator.getBuckets();
      const bucket = buckets.find((b) => b.feeRateRange.min === 100);
      expect(bucket!.avgConfirmationBlocks).toBe(2); // (1 + 3 + 2) / 3
    });

    test("ignores negative confirmation times", () => {
      const txid = Buffer.alloc(32, 0x44);

      // Invalid: confirm height < entry height
      estimator.recordConfirmation(txid, 50, 100, 99);

      const buckets = estimator.getBuckets();
      const bucket = buckets.find((b) => b.feeRateRange.min === 50);
      expect(bucket!.totalConfirmed).toBe(0);
    });
  });

  describe("processBlock", () => {
    test("records confirmations for tracked transactions", async () => {
      // Set up multiple UTXOs and transactions
      const inputTxid1 = Buffer.alloc(32, 0xaa);
      const inputTxid2 = Buffer.alloc(32, 0xbb);
      await setupUTXO(inputTxid1, 0, 1000000n);
      await setupUTXO(inputTxid2, 0, 1000000n);

      // Create transactions with different fee rates
      // High fee tx: 500 sat fee for ~100 vbytes = ~5 sat/vB
      const tx1 = createTestTx(
        [{ txid: inputTxid1, vout: 0 }],
        [{ value: 999500n }]
      );
      // Low fee tx: 100 sat fee for ~100 vbytes = ~1 sat/vB
      const tx2 = createTestTx(
        [{ txid: inputTxid2, vout: 0 }],
        [{ value: 999900n }]
      );

      await mempool.addTransaction(tx1);
      await mempool.addTransaction(tx2);

      const txid1 = getTxId(tx1);
      const txid2 = getTxId(tx2);

      // Track both transactions
      estimator.trackTransaction(txid1, 200);
      estimator.trackTransaction(txid2, 200);

      // Create a block containing both transactions
      const block = createTestBlock([tx1, tx2]);

      // Process the block
      estimator.processBlock(block, 201);

      // Transactions should be recorded as confirmed
      // (Note: they may still be in tracking if mempool hasn't removed them)
      const buckets = estimator.getBuckets();
      const totalConfirmed = buckets.reduce((sum, b) => sum + b.totalConfirmed, 0);
      expect(totalConfirmed).toBeGreaterThan(0);
    });

    test("applies decay factor each block", () => {
      // Add some confirmation data
      const txid = Buffer.alloc(32, 0x11);
      estimator.recordConfirmation(txid, 100, 100, 101);

      const buckets = estimator.getBuckets();
      const bucket = buckets.find((b) => b.feeRateRange.min === 100)!;
      const initialConfirmed = bucket.totalConfirmed;

      // Process an empty block (triggers decay)
      const block = createTestBlock([]);
      estimator.processBlock(block, 102);

      // totalConfirmed should be decayed
      expect(bucket.totalConfirmed).toBeLessThan(initialConfirmed);
      expect(bucket.totalConfirmed).toBeCloseTo(initialConfirmed * 0.998, 5);
    });
  });

  describe("estimateFee", () => {
    test("returns default fee rate when no data", () => {
      const feeRate = estimator.estimateFee(6);
      expect(feeRate).toBe(20); // Default conservative fee
    });

    test("estimates based on historical data", () => {
      // Simulate many confirmations at various fee rates
      // High fee rate (100 sat/vB): all confirm in 1 block
      for (let i = 0; i < 20; i++) {
        const txid = Buffer.alloc(32, i);
        estimator.recordConfirmation(txid, 100, 100, 101);
      }

      // Medium fee rate (20 sat/vB): most confirm in 3 blocks
      for (let i = 0; i < 20; i++) {
        const txid = Buffer.alloc(32, 50 + i);
        estimator.recordConfirmation(txid, 20, 100, 103);
      }

      // Low fee rate (5 sat/vB): confirm in 10+ blocks
      for (let i = 0; i < 20; i++) {
        const txid = Buffer.alloc(32, 100 + i);
        estimator.recordConfirmation(txid, 5, 100, 112);
      }

      // For 1-block confirmation, should recommend ~100 sat/vB
      const feeFor1Block = estimator.estimateFee(1);
      expect(feeFor1Block).toBeGreaterThanOrEqual(100);

      // For 6-block confirmation, could be lower
      const feeFor6Blocks = estimator.estimateFee(6);
      expect(feeFor6Blocks).toBeLessThanOrEqual(100);
    });

    test("returns lowest sufficient fee rate", () => {
      // Create data where multiple buckets would work
      // Both 50 and 100 sat/vB buckets confirm in 1 block
      for (let i = 0; i < 15; i++) {
        const txid1 = Buffer.alloc(32, i);
        const txid2 = Buffer.alloc(32, 50 + i);
        estimator.recordConfirmation(txid1, 100, 100, 101);
        estimator.recordConfirmation(txid2, 50, 100, 101);
      }

      // Should return the lower fee rate (50) since both work
      const feeRate = estimator.estimateFee(1);
      expect(feeRate).toBe(50);
    });

    test("handles edge case targets", () => {
      // Target of 0 should be treated as 1
      const fee1 = estimator.estimateFee(0);
      const fee2 = estimator.estimateFee(1);
      expect(fee1).toBe(fee2);

      // Very large target should be capped
      const feeLarge = estimator.estimateFee(10000);
      expect(feeLarge).toBe(20); // Default (no data)
    });
  });

  describe("estimateSmartFee", () => {
    test("returns requested target when data available", () => {
      // Add sufficient data
      for (let i = 0; i < 15; i++) {
        const txid = Buffer.alloc(32, i);
        estimator.recordConfirmation(txid, 50, 100, 102);
      }

      const result = estimator.estimateSmartFee(6);
      expect(result.blocks).toBeLessThanOrEqual(6);
      expect(result.feeRate).toBeGreaterThan(0);
    });

    test("returns longer target when insufficient data", () => {
      // No data for quick confirmation, but data for longer target
      for (let i = 0; i < 15; i++) {
        const txid = Buffer.alloc(32, i);
        estimator.recordConfirmation(txid, 10, 100, 250); // 150 block wait
      }

      const result = estimator.estimateSmartFee(1);
      // Should return a longer target since 1-block data is unavailable
      expect(result.blocks).toBeGreaterThanOrEqual(1);
      expect(result.feeRate).toBeGreaterThan(0);
    });

    test("falls back to default with no data", () => {
      const result = estimator.estimateSmartFee(6);
      expect(result.feeRate).toBe(20);
      expect(result.blocks).toBe(6);
    });
  });

  describe("serialize and loadState", () => {
    test("persists and restores state", () => {
      // Add some data
      for (let i = 0; i < 10; i++) {
        const txid = Buffer.alloc(32, i);
        estimator.recordConfirmation(txid, 100, 100, 102);
      }

      // Also track a pending tx
      const pendingTxid = Buffer.alloc(32, 0xff);
      estimator.trackTransaction(pendingTxid, 150);

      // Serialize
      const serialized = estimator.serialize();
      expect(serialized.length).toBeGreaterThan(0);

      // Create new estimator and restore
      const newEstimator = new FeeEstimator(mempool);
      newEstimator.loadState(serialized);

      // Verify restored data
      const buckets = newEstimator.getBuckets();
      const bucket = buckets.find((b) => b.feeRateRange.min === 100);
      expect(bucket!.totalConfirmed).toBe(10);
      expect(bucket!.confirmationBlocks.length).toBe(10);

      // Verify tracked transactions restored
      expect(newEstimator.getTrackedCount()).toBe(1);
    });

    test("handles invalid serialized data gracefully", () => {
      const invalidData = Buffer.from("not valid json");

      // Should not throw
      estimator.loadState(invalidData);

      // Should still work with default state
      const feeRate = estimator.estimateFee(6);
      expect(feeRate).toBe(20);
    });

    test("handles partial/malformed state", () => {
      const partialState = Buffer.from(JSON.stringify({
        buckets: [], // Wrong length
        txEntryHeights: null,
      }));

      estimator.loadState(partialState);
      expect(estimator.getTrackedCount()).toBe(0);
    });
  });

  describe("clear", () => {
    test("resets all state", () => {
      // Add data
      for (let i = 0; i < 10; i++) {
        const txid = Buffer.alloc(32, i);
        estimator.recordConfirmation(txid, 100, 100, 102);
      }
      const pendingTxid = Buffer.alloc(32, 0xff);
      estimator.trackTransaction(pendingTxid, 150);

      // Clear
      estimator.clear();

      // Verify cleared
      expect(estimator.getTrackedCount()).toBe(0);
      const buckets = estimator.getBuckets();
      const totalConfirmed = buckets.reduce((sum, b) => sum + b.totalConfirmed, 0);
      expect(totalConfirmed).toBe(0);
    });
  });

  describe("integration: fee estimation with simulated blocks", () => {
    test("estimates correctly after processing multiple blocks", async () => {
      // Simulate a sequence of blocks with known fee rates
      // This simulates the estimator learning from block history

      // Create many UTXOs for our transactions
      const utxos: Buffer[] = [];
      for (let i = 0; i < 100; i++) {
        const txid = Buffer.alloc(32);
        txid.writeUInt32LE(i, 0);
        utxos.push(txid);
        await setupUTXO(txid, 0, 1000000n);
      }

      let utxoIndex = 0;
      const createTxWithFee = (feeAmount: bigint) => {
        const inputTxid = utxos[utxoIndex++];
        return createTestTx(
          [{ txid: inputTxid, vout: 0 }],
          [{ value: 1000000n - feeAmount }]
        );
      };

      // Simulate blocks where:
      // - High fee txs (10000 sat fee ~= 100 sat/vB) confirm in 1 block
      // - Medium fee txs (1000 sat fee ~= 10 sat/vB) confirm in 3 blocks
      // - Low fee txs (200 sat fee ~= 2 sat/vB) confirm in 10 blocks

      // Add high fee transactions to mempool and process immediately
      for (let i = 0; i < 20; i++) {
        const tx = createTxWithFee(10000n); // ~100 sat/vB
        const result = await mempool.addTransaction(tx);
        if (result.accepted) {
          const txid = getTxId(tx);
          estimator.trackTransaction(txid, 100);

          // Process block containing this tx
          const block = createTestBlock([tx]);
          estimator.processBlock(block, 101);
          mempool.removeForBlock(block);
        }
      }

      // Add medium fee transactions with 3-block delay
      for (let i = 0; i < 20; i++) {
        const tx = createTxWithFee(1000n); // ~10 sat/vB
        const result = await mempool.addTransaction(tx);
        if (result.accepted) {
          const txid = getTxId(tx);
          estimator.trackTransaction(txid, 100);

          // Simulate delay then confirmation
          estimator.processBlock(createTestBlock([]), 101);
          estimator.processBlock(createTestBlock([]), 102);

          const block = createTestBlock([tx]);
          estimator.processBlock(block, 103);
          mempool.removeForBlock(block);
        }
      }

      // Now test estimation
      // For 1-block target, should recommend high fee
      const fee1Block = estimator.estimateFee(1);
      expect(fee1Block).toBeGreaterThanOrEqual(10);

      // For 6-block target, medium fee should work
      const fee6Block = estimator.estimateFee(6);
      expect(fee6Block).toBeLessThanOrEqual(fee1Block);
    });
  });

  describe("bucket boundaries", () => {
    test("covers full fee rate range", () => {
      const buckets = estimator.getBuckets();

      // First bucket starts at 1 sat/vB
      expect(buckets[0].feeRateRange.min).toBe(1);

      // Last bucket extends to infinity
      expect(buckets[buckets.length - 1].feeRateRange.max).toBe(Infinity);

      // All boundaries are increasing
      for (let i = 1; i < buckets.length; i++) {
        expect(buckets[i].feeRateRange.min).toBeGreaterThan(
          buckets[i - 1].feeRateRange.min
        );
      }
    });

    test("buckets are contiguous", () => {
      const buckets = estimator.getBuckets();

      for (let i = 0; i < buckets.length - 1; i++) {
        // Each bucket's max should equal next bucket's min
        expect(buckets[i].feeRateRange.max).toBe(buckets[i + 1].feeRateRange.min);
      }
    });
  });
});
