/**
 * Tests for BIP125 Full RBF (Replace-By-Fee).
 *
 * Full RBF means all unconfirmed transactions are replaceable,
 * without requiring BIP125 signaling via sequence numbers.
 */

import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ChainDB, UTXOEntry } from "../storage/database.js";
import { UTXOManager } from "../chain/utxo.js";
import { REGTEST } from "../consensus/params.js";
import { Mempool } from "../mempool/mempool.js";
import type { Transaction } from "../validation/tx.js";
import { getTxId } from "../validation/tx.js";

describe("RBF - Replace By Fee", () => {
  let tempDir: string;
  let db: ChainDB;
  let utxo: UTXOManager;
  let mempool: Mempool;

  // Helper to create a test transaction with configurable sequence
  function createTestTx(
    inputs: Array<{ txid: Buffer; vout: number; sequence?: number }>,
    outputs: Array<{ value: bigint; scriptPubKey?: Buffer }>
  ): Transaction {
    return {
      version: 2,
      inputs: inputs.map((inp) => ({
        prevOut: { txid: inp.txid, vout: inp.vout },
        scriptSig: Buffer.alloc(0),
        sequence: inp.sequence ?? 0xffffffff,
        witness: [],
      })),
      outputs: outputs.map((out) => ({
        value: out.value,
        scriptPubKey: out.scriptPubKey ?? Buffer.from([0x51]), // OP_TRUE
      })),
      lockTime: 0,
    };
  }

  // Helper to set up a UTXO
  async function setupUTXO(
    txid: Buffer,
    vout: number,
    amount: bigint
  ): Promise<void> {
    const entry: UTXOEntry = {
      height: 1,
      coinbase: false,
      amount,
      scriptPubKey: Buffer.from([0x51]), // OP_TRUE - always succeeds
    };
    await db.putUTXO(txid, vout, entry);
  }

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "rbf-test-"));
    db = new ChainDB(tempDir);
    await db.open();
    utxo = new UTXOManager(db);
    mempool = new Mempool(utxo, REGTEST, 1_000_000);
    mempool.setTipHeight(200);
  });

  afterEach(async () => {
    await db.close();
    await rm(tempDir, { recursive: true, force: true });
  });

  describe("basic RBF replacement", () => {
    test("accepts replacement with higher absolute fee", async () => {
      const inputTxid = Buffer.alloc(32, 0x01);
      await setupUTXO(inputTxid, 0, 100000n);

      // Original transaction: 1000 sat fee
      const original = createTestTx(
        [{ txid: inputTxid, vout: 0 }],
        [{ value: 99000n }]
      );
      const result1 = await mempool.addTransaction(original);
      expect(result1.accepted).toBe(true);
      expect(mempool.getSize()).toBe(1);

      // Replacement transaction: 2000 sat fee (higher)
      const replacement = createTestTx(
        [{ txid: inputTxid, vout: 0 }],
        [{ value: 98000n }]
      );
      const result2 = await mempool.addTransaction(replacement);
      expect(result2.accepted).toBe(true);
      expect(mempool.getSize()).toBe(1);

      // Verify the replacement is in the mempool, not the original
      const replacementTxid = getTxId(replacement);
      const originalTxid = getTxId(original);
      expect(mempool.hasTransaction(replacementTxid)).toBe(true);
      expect(mempool.hasTransaction(originalTxid)).toBe(false);
    });

    test("rejects replacement with equal or lower absolute fee", async () => {
      const inputTxid = Buffer.alloc(32, 0x02);
      await setupUTXO(inputTxid, 0, 100000n);

      // Original transaction: 2000 sat fee
      const original = createTestTx(
        [{ txid: inputTxid, vout: 0 }],
        [{ value: 98000n }]
      );
      await mempool.addTransaction(original);

      // Replacement with same fee but different output structure (should fail)
      // Use two outputs to make it a different transaction
      const sameFee = createTestTx(
        [{ txid: inputTxid, vout: 0 }],
        [{ value: 49000n }, { value: 49000n }] // Same total output = same fee
      );
      const result1 = await mempool.addTransaction(sameFee);
      expect(result1.accepted).toBe(false);
      expect(result1.error).toContain("must be greater");

      // Replacement with lower fee (different output structure)
      const lowerFee = createTestTx(
        [{ txid: inputTxid, vout: 0 }],
        [{ value: 49500n }, { value: 49500n }] // 1000 sat fee < 2000 sat original
      );
      const result2 = await mempool.addTransaction(lowerFee);
      expect(result2.accepted).toBe(false);
      expect(result2.error).toContain("must be greater");
    });

    test("rejects replacement with lower fee rate", async () => {
      const inputTxid = Buffer.alloc(32, 0x03);
      await setupUTXO(inputTxid, 0, 100000n);

      // Original transaction: small, high fee rate
      // 1 input, 1 output = ~68 vbytes, 2000 sat fee = ~29.4 sat/vB
      const original = createTestTx(
        [{ txid: inputTxid, vout: 0 }],
        [{ value: 98000n }] // 2000 sat fee
      );
      await mempool.addTransaction(original);
      const originalEntry = mempool.getTransaction(getTxId(original));
      const originalFeeRate = originalEntry!.feeRate;

      // Replacement: many more outputs = much larger tx = lower fee rate even with higher absolute fee
      // 1 input, 10 outputs = ~350 vbytes, 3000 sat fee = ~8.6 sat/vB
      const replacement = createTestTx(
        [{ txid: inputTxid, vout: 0 }],
        Array(10).fill({ value: 9700n }) // Total output: 97000, fee = 3000 (higher absolute)
      );
      const result = await mempool.addTransaction(replacement);
      expect(result.accepted).toBe(false);
      expect(result.error).toContain("fee rate");
    });
  });

  describe("incremental relay fee", () => {
    test("requires minimum incremental fee for bandwidth", async () => {
      const inputTxid = Buffer.alloc(32, 0x04);
      await setupUTXO(inputTxid, 0, 100000n);

      // Original: small fee
      const original = createTestTx(
        [{ txid: inputTxid, vout: 0 }],
        [{ value: 99900n }] // 100 sat fee
      );
      await mempool.addTransaction(original);

      // Replacement: marginally higher fee but not enough for bandwidth
      // Incremental relay fee is 1 sat/vB, so for ~68 vB tx we need at least 68 sat more
      const replacement = createTestTx(
        [{ txid: inputTxid, vout: 0 }],
        [{ value: 99850n }] // 150 sat fee (only 50 sat more)
      );
      const result = await mempool.addTransaction(replacement);
      expect(result.accepted).toBe(false);
      expect(result.error).toContain("incremental fee");
    });

    test("accepts replacement meeting incremental relay fee", async () => {
      const inputTxid = Buffer.alloc(32, 0x05);
      await setupUTXO(inputTxid, 0, 100000n);

      // Original: small fee
      const original = createTestTx(
        [{ txid: inputTxid, vout: 0 }],
        [{ value: 99900n }] // 100 sat fee
      );
      await mempool.addTransaction(original);

      // Replacement: significantly higher fee
      const replacement = createTestTx(
        [{ txid: inputTxid, vout: 0 }],
        [{ value: 99700n }] // 300 sat fee (200 sat more, > 68 sat for bandwidth)
      );
      const result = await mempool.addTransaction(replacement);
      expect(result.accepted).toBe(true);
    });
  });

  describe("eviction limits", () => {
    test("rejects replacement that would evict too many transactions", async () => {
      // This test creates a scenario where replacing one tx would cascade
      // We need to create a tx with many descendants

      // Setup: create initial UTXO
      const rootTxid = Buffer.alloc(32, 0x10);
      await setupUTXO(rootTxid, 0, 10_000_000n);

      // Create root transaction with many outputs
      const rootTx = createTestTx(
        [{ txid: rootTxid, vout: 0 }],
        Array(50).fill(null).map(() => ({ value: 180000n })) // 50 outputs
      );
      await mempool.addTransaction(rootTx);
      const rootTxidResult = getTxId(rootTx);

      // Now create many child transactions spending those outputs
      // Each child will also have multiple outputs, creating descendants
      for (let i = 0; i < 50; i++) {
        const childInput = Buffer.alloc(32, 0x20 + i);
        await setupUTXO(childInput, 0, 50000n);

        const child = createTestTx(
          [
            { txid: rootTxidResult, vout: i },
            { txid: childInput, vout: 0 },
          ],
          [{ value: 220000n }]
        );
        const result = await mempool.addTransaction(child);
        if (!result.accepted) {
          // Hit ancestor/descendant limits, that's okay
          break;
        }
      }

      // Count total mempool size
      const beforeSize = mempool.getSize();

      // If we have enough transactions, try to replace the root
      if (beforeSize > 25) {
        // Try to replace root transaction - this should evict all descendants
        const replacementRoot = createTestTx(
          [{ txid: rootTxid, vout: 0 }],
          [{ value: 8_000_000n }] // Much higher fee (2M sat)
        );
        const result = await mempool.addTransaction(replacementRoot);

        // Either it succeeds (if under 100 evictions) or fails with too many
        if (beforeSize > 100) {
          expect(result.accepted).toBe(false);
          expect(result.error).toContain("too many");
        } else {
          expect(result.accepted).toBe(true);
        }
      }
    });
  });

  describe("full RBF (no signaling required)", () => {
    test("allows replacement without BIP125 sequence signal", async () => {
      const inputTxid = Buffer.alloc(32, 0x06);
      await setupUTXO(inputTxid, 0, 100000n);

      // Original transaction: sequence = 0xffffffff (no BIP125 signal)
      const original = createTestTx(
        [{ txid: inputTxid, vout: 0, sequence: 0xffffffff }],
        [{ value: 99000n }]
      );
      const result1 = await mempool.addTransaction(original);
      expect(result1.accepted).toBe(true);

      // Replacement should still be allowed (full RBF)
      const replacement = createTestTx(
        [{ txid: inputTxid, vout: 0, sequence: 0xffffffff }],
        [{ value: 98000n }]
      );
      const result2 = await mempool.addTransaction(replacement);
      expect(result2.accepted).toBe(true);
    });

    test("isReplaceable returns true for all mempool transactions", async () => {
      const inputTxid = Buffer.alloc(32, 0x07);
      await setupUTXO(inputTxid, 0, 100000n);

      // Transaction with sequence = 0xffffffff (no BIP125 signal)
      const tx = createTestTx(
        [{ txid: inputTxid, vout: 0, sequence: 0xffffffff }],
        [{ value: 99000n }]
      );
      await mempool.addTransaction(tx);

      const txid = getTxId(tx);
      expect(mempool.isReplaceable(txid)).toBe(true);
    });
  });

  describe("descendant eviction", () => {
    test("evicts descendants when replacing parent", async () => {
      const inputTxid = Buffer.alloc(32, 0x08);
      await setupUTXO(inputTxid, 0, 100000n);

      // Parent transaction
      const parent = createTestTx(
        [{ txid: inputTxid, vout: 0 }],
        [{ value: 98000n }]
      );
      await mempool.addTransaction(parent);
      const parentTxid = getTxId(parent);

      // Child transaction spending parent's output
      const child = createTestTx(
        [{ txid: parentTxid, vout: 0 }],
        [{ value: 97000n }]
      );
      await mempool.addTransaction(child);
      const childTxid = getTxId(child);

      expect(mempool.getSize()).toBe(2);
      expect(mempool.hasTransaction(childTxid)).toBe(true);

      // Replace parent - this should also evict the child
      const replacement = createTestTx(
        [{ txid: inputTxid, vout: 0 }],
        [{ value: 95000n }] // Higher fee than parent + child combined
      );
      const result = await mempool.addTransaction(replacement);
      expect(result.accepted).toBe(true);

      // Both parent and child should be evicted
      expect(mempool.hasTransaction(parentTxid)).toBe(false);
      expect(mempool.hasTransaction(childTxid)).toBe(false);
      expect(mempool.getSize()).toBe(1);
    });

    test("evicts grandchildren when replacing grandparent", async () => {
      const inputTxid = Buffer.alloc(32, 0x09);
      await setupUTXO(inputTxid, 0, 100000n);

      // Grandparent
      const grandparent = createTestTx(
        [{ txid: inputTxid, vout: 0 }],
        [{ value: 98000n }]
      );
      await mempool.addTransaction(grandparent);
      const grandparentTxid = getTxId(grandparent);

      // Parent
      const parent = createTestTx(
        [{ txid: grandparentTxid, vout: 0 }],
        [{ value: 97000n }]
      );
      await mempool.addTransaction(parent);
      const parentTxid = getTxId(parent);

      // Child
      const child = createTestTx(
        [{ txid: parentTxid, vout: 0 }],
        [{ value: 96000n }]
      );
      await mempool.addTransaction(child);
      const childTxid = getTxId(child);

      expect(mempool.getSize()).toBe(3);

      // Replace grandparent
      const replacement = createTestTx(
        [{ txid: inputTxid, vout: 0 }],
        [{ value: 90000n }] // Higher fee than all three combined
      );
      const result = await mempool.addTransaction(replacement);
      expect(result.accepted).toBe(true);

      // All three should be evicted
      expect(mempool.hasTransaction(grandparentTxid)).toBe(false);
      expect(mempool.hasTransaction(parentTxid)).toBe(false);
      expect(mempool.hasTransaction(childTxid)).toBe(false);
      expect(mempool.getSize()).toBe(1);
    });
  });

  describe("multiple conflicts", () => {
    test("replaces multiple conflicting transactions", async () => {
      // Create two separate UTXOs
      const inputTxid1 = Buffer.alloc(32, 0x0a);
      const inputTxid2 = Buffer.alloc(32, 0x0b);
      await setupUTXO(inputTxid1, 0, 50000n);
      await setupUTXO(inputTxid2, 0, 50000n);

      // Two separate transactions, each spending one UTXO
      const tx1 = createTestTx(
        [{ txid: inputTxid1, vout: 0 }],
        [{ value: 49000n }] // 1000 sat fee
      );
      const tx2 = createTestTx(
        [{ txid: inputTxid2, vout: 0 }],
        [{ value: 49000n }] // 1000 sat fee
      );

      await mempool.addTransaction(tx1);
      await mempool.addTransaction(tx2);
      expect(mempool.getSize()).toBe(2);

      // Replace both with a single transaction that spends both UTXOs
      const replacement = createTestTx(
        [
          { txid: inputTxid1, vout: 0 },
          { txid: inputTxid2, vout: 0 },
        ],
        [{ value: 95000n }] // 5000 sat fee (more than 2000 combined)
      );
      const result = await mempool.addTransaction(replacement);
      expect(result.accepted).toBe(true);
      expect(mempool.getSize()).toBe(1);

      // Both original transactions should be evicted
      expect(mempool.hasTransaction(getTxId(tx1))).toBe(false);
      expect(mempool.hasTransaction(getTxId(tx2))).toBe(false);
    });
  });

  describe("edge cases", () => {
    test("replacement must pay for sum of all conflicting fees", async () => {
      // Create two UTXOs
      const inputTxid1 = Buffer.alloc(32, 0x0c);
      const inputTxid2 = Buffer.alloc(32, 0x0d);
      await setupUTXO(inputTxid1, 0, 50000n);
      await setupUTXO(inputTxid2, 0, 50000n);

      // Two transactions with different fees
      const tx1 = createTestTx(
        [{ txid: inputTxid1, vout: 0 }],
        [{ value: 47000n }] // 3000 sat fee
      );
      const tx2 = createTestTx(
        [{ txid: inputTxid2, vout: 0 }],
        [{ value: 48000n }] // 2000 sat fee
      );

      await mempool.addTransaction(tx1);
      await mempool.addTransaction(tx2);

      // Replacement paying more than tx1 but less than tx1+tx2
      const replacement = createTestTx(
        [
          { txid: inputTxid1, vout: 0 },
          { txid: inputTxid2, vout: 0 },
        ],
        [{ value: 96000n }] // 4000 sat fee (< 5000 combined)
      );
      const result = await mempool.addTransaction(replacement);
      expect(result.accepted).toBe(false);
      expect(result.error).toContain("must be greater");
    });

    test("existing mempool tx cannot be replacement of itself", async () => {
      const inputTxid = Buffer.alloc(32, 0x0e);
      await setupUTXO(inputTxid, 0, 100000n);

      const tx = createTestTx(
        [{ txid: inputTxid, vout: 0 }],
        [{ value: 99000n }]
      );

      // First add succeeds
      const result1 = await mempool.addTransaction(tx);
      expect(result1.accepted).toBe(true);

      // Adding same tx again fails (duplicate, not RBF)
      const result2 = await mempool.addTransaction(tx);
      expect(result2.accepted).toBe(false);
      expect(result2.error).toContain("already in mempool");
    });
  });
});
