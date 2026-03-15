/**
 * Tests for mempool ancestor/descendant limits.
 *
 * Bitcoin Core enforces:
 * - MAX_ANCESTORS = 25 (including self)
 * - MAX_DESCENDANTS = 25 (including self)
 * - MAX_ANCESTOR_SIZE = 101,000 vbytes
 * - MAX_DESCENDANT_SIZE = 101,000 vbytes
 */

import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ChainDB, type UTXOEntry } from "../storage/database.js";
import { UTXOManager } from "../chain/utxo.js";
import { REGTEST } from "../consensus/params.js";
import { Mempool } from "../mempool/mempool.js";
import type { Transaction } from "../validation/tx.js";
import { getTxId } from "../validation/tx.js";

describe("Mempool ancestor/descendant limits", () => {
  let tempDir: string;
  let db: ChainDB;
  let utxo: UTXOManager;
  let mempool: Mempool;

  // Helper to create a simple test transaction
  function createTestTx(
    inputs: Array<{ txid: Buffer; vout: number }>,
    outputs: Array<{ value: bigint }>
  ): Transaction {
    return {
      version: 2,
      inputs: inputs.map((inp) => ({
        prevOut: { txid: inp.txid, vout: inp.vout },
        scriptSig: Buffer.alloc(0),
        sequence: 0xffffffff,
        witness: [],
      })),
      outputs: outputs.map((out) => ({
        value: out.value,
        scriptPubKey: Buffer.from([0x51]), // OP_TRUE
      })),
      lockTime: 0,
    };
  }

  async function setupUTXO(
    txid: Buffer,
    vout: number,
    amount: bigint
  ): Promise<void> {
    const entry: UTXOEntry = {
      height: 1,
      coinbase: false,
      amount,
      scriptPubKey: Buffer.from([0x51]),
    };
    await db.putUTXO(txid, vout, entry);
  }

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "mempool-limits-"));
    db = new ChainDB(tempDir);
    await db.open();
    utxo = new UTXOManager(db);
    mempool = new Mempool(utxo, REGTEST);
    mempool.setTipHeight(200);
  });

  afterEach(async () => {
    await db.close();
    await rm(tempDir, { recursive: true, force: true });
  });

  describe("ancestor count limit (25)", () => {
    test("accepts chain of exactly 25 transactions", async () => {
      const initialTxid = Buffer.alloc(32, 0x01);
      await setupUTXO(initialTxid, 0, 1_000_000n);

      let prevTxid: Buffer = initialTxid;

      // Create 25 chained transactions (all should succeed)
      for (let i = 0; i < 25; i++) {
        const tx = createTestTx(
          [{ txid: prevTxid, vout: 0 }],
          [{ value: 900_000n - BigInt(i * 1000) }]
        );
        const result = await mempool.addTransaction(tx);
        expect(result.accepted).toBe(true);
        prevTxid = Buffer.from(getTxId(tx));
      }

      expect(mempool.getSize()).toBe(25);
    });

    test("rejects 26th transaction in chain (exceeds ancestor limit)", async () => {
      const initialTxid = Buffer.alloc(32, 0x02);
      await setupUTXO(initialTxid, 0, 1_000_000n);

      let prevTxid: Buffer = initialTxid;

      // Create 25 chained transactions
      for (let i = 0; i < 25; i++) {
        const tx = createTestTx(
          [{ txid: prevTxid, vout: 0 }],
          [{ value: 900_000n - BigInt(i * 1000) }]
        );
        const result = await mempool.addTransaction(tx);
        expect(result.accepted).toBe(true);
        prevTxid = Buffer.from(getTxId(tx));
      }

      // The 26th should fail
      const finalTx = createTestTx(
        [{ txid: prevTxid, vout: 0 }],
        [{ value: 800_000n }]
      );
      const result = await mempool.addTransaction(finalTx);
      expect(result.accepted).toBe(false);
      expect(result.error).toContain("ancestor");
    });

    test("cached ancestorCount is accurate", async () => {
      const initialTxid = Buffer.alloc(32, 0x03);
      await setupUTXO(initialTxid, 0, 1_000_000n);

      let prevTxid: Buffer = initialTxid;

      // Create 10 chained transactions
      for (let i = 0; i < 10; i++) {
        const tx = createTestTx(
          [{ txid: prevTxid, vout: 0 }],
          [{ value: 900_000n - BigInt(i * 1000) }]
        );
        await mempool.addTransaction(tx);
        const txid = getTxId(tx);
        const entry = mempool.getTransaction(txid);

        // Each tx should have (i + 1) ancestors including itself
        expect(entry!.ancestorCount).toBe(i + 1);
        prevTxid = Buffer.from(txid);
      }
    });
  });

  describe("descendant count limit (25)", () => {
    test("accepts parent with exactly 24 children (25 descendants including self)", async () => {
      // Create parent with multiple outputs
      const parentInput = Buffer.alloc(32, 0x10);
      await setupUTXO(parentInput, 0, 10_000_000n);

      const parent = createTestTx(
        [{ txid: parentInput, vout: 0 }],
        Array(25).fill({ value: 300_000n })
      );
      await mempool.addTransaction(parent);
      const parentTxid = getTxId(parent);

      // Create 24 children (parent + 24 children = 25 total)
      for (let i = 0; i < 24; i++) {
        const childInput = Buffer.alloc(32, 0x20 + i);
        await setupUTXO(childInput, 0, 100_000n);

        const child = createTestTx(
          [
            { txid: parentTxid, vout: i },
            { txid: childInput, vout: 0 },
          ],
          [{ value: 350_000n }]
        );
        const result = await mempool.addTransaction(child);
        expect(result.accepted).toBe(true);
      }

      // Parent should now have 25 descendants (itself + 24 children)
      const parentEntry = mempool.getTransaction(parentTxid);
      expect(parentEntry!.descendantCount).toBe(25);
    });

    test("rejects child when parent already has 25 descendants", async () => {
      // Create parent with multiple outputs
      const parentInput = Buffer.alloc(32, 0x30);
      await setupUTXO(parentInput, 0, 10_000_000n);

      const parent = createTestTx(
        [{ txid: parentInput, vout: 0 }],
        Array(26).fill({ value: 300_000n })
      );
      await mempool.addTransaction(parent);
      const parentTxid = getTxId(parent);

      // Create 24 children first
      for (let i = 0; i < 24; i++) {
        const childInput = Buffer.alloc(32, 0x40 + i);
        await setupUTXO(childInput, 0, 100_000n);

        const child = createTestTx(
          [
            { txid: parentTxid, vout: i },
            { txid: childInput, vout: 0 },
          ],
          [{ value: 350_000n }]
        );
        const result = await mempool.addTransaction(child);
        expect(result.accepted).toBe(true);
      }

      // The 25th child should fail
      const extraInput = Buffer.alloc(32, 0x60);
      await setupUTXO(extraInput, 0, 100_000n);

      const extraChild = createTestTx(
        [
          { txid: parentTxid, vout: 24 },
          { txid: extraInput, vout: 0 },
        ],
        [{ value: 350_000n }]
      );
      const result = await mempool.addTransaction(extraChild);
      expect(result.accepted).toBe(false);
      expect(result.error).toContain("descendant");
    });

    test("cached descendantCount is accurate", async () => {
      const parentInput = Buffer.alloc(32, 0x70);
      await setupUTXO(parentInput, 0, 10_000_000n);

      const parent = createTestTx(
        [{ txid: parentInput, vout: 0 }],
        Array(10).fill({ value: 300_000n })
      );
      await mempool.addTransaction(parent);
      const parentTxid = getTxId(parent);

      // Create 5 children
      for (let i = 0; i < 5; i++) {
        const childInput = Buffer.alloc(32, 0x80 + i);
        await setupUTXO(childInput, 0, 100_000n);

        const child = createTestTx(
          [
            { txid: parentTxid, vout: i },
            { txid: childInput, vout: 0 },
          ],
          [{ value: 350_000n }]
        );
        await mempool.addTransaction(child);

        // Parent descendant count should increase
        const parentEntry = mempool.getTransaction(parentTxid);
        expect(parentEntry!.descendantCount).toBe(i + 2); // Self + children
      }
    });
  });

  describe("ancestor size limit (101,000 vbytes)", () => {
    test("ancestorSize tracks cumulative size correctly", async () => {
      // Create a chain of 5 transactions and verify ancestorSize accumulates
      const initialTxid = Buffer.alloc(32, 0x90);
      await setupUTXO(initialTxid, 0, 10_000_000n);

      let prevTxid: Buffer = initialTxid;
      let prevValue = 10_000_000n;
      let expectedTotalSize = 0;
      const entries: Array<{ txid: Buffer; vsize: number }> = [];

      // Create 5 chained transactions
      for (let i = 0; i < 5; i++) {
        const fee = 1000n;
        const outputValue = prevValue - fee;
        const tx = createTestTx(
          [{ txid: prevTxid, vout: 0 }],
          [{ value: outputValue }]
        );
        const result = await mempool.addTransaction(tx);
        expect(result.accepted).toBe(true);

        const txid = getTxId(tx);
        const entry = mempool.getTransaction(txid);
        expectedTotalSize += entry!.vsize;

        // Verify ancestorSize equals sum of all ancestor vsizes
        expect(entry!.ancestorSize).toBe(expectedTotalSize);

        entries.push({ txid, vsize: entry!.vsize });
        prevTxid = Buffer.from(txid);
        prevValue = outputValue;
      }
    });

    test("cached ancestorSize is accurate", async () => {
      const initialTxid = Buffer.alloc(32, 0xa0);
      await setupUTXO(initialTxid, 0, 1_000_000n);

      let prevTxid: Buffer = initialTxid;
      let expectedSize = 0;

      // Create 5 chained transactions
      for (let i = 0; i < 5; i++) {
        const tx = createTestTx(
          [{ txid: prevTxid, vout: 0 }],
          [{ value: 900_000n - BigInt(i * 1000) }]
        );
        await mempool.addTransaction(tx);
        const txid = getTxId(tx);
        const entry = mempool.getTransaction(txid);

        expectedSize += entry!.vsize;
        expect(entry!.ancestorSize).toBe(expectedSize);
        prevTxid = Buffer.from(txid);
      }
    });
  });

  describe("package limit edge cases", () => {
    test("diamond dependency pattern respects limits", async () => {
      // Create a diamond: A -> B, A -> C, B -> D, C -> D
      // D has 4 ancestors including itself
      const inputA = Buffer.alloc(32, 0xd0);
      const inputBC = Buffer.alloc(32, 0xd1);
      await setupUTXO(inputA, 0, 1_000_000n);
      await setupUTXO(inputBC, 0, 1_000_000n);

      // Transaction A with 2 outputs
      const txA = createTestTx(
        [{ txid: inputA, vout: 0 }],
        [{ value: 400_000n }, { value: 400_000n }]
      );
      await mempool.addTransaction(txA);
      const txidA = getTxId(txA);

      // Transaction B spending A's first output
      const txB = createTestTx(
        [{ txid: txidA, vout: 0 }],
        [{ value: 350_000n }]
      );
      await mempool.addTransaction(txB);
      const txidB = getTxId(txB);

      // Transaction C spending A's second output
      const txC = createTestTx(
        [{ txid: txidA, vout: 1 }],
        [{ value: 350_000n }]
      );
      await mempool.addTransaction(txC);
      const txidC = getTxId(txC);

      // Transaction D spending both B and C
      const txD = createTestTx(
        [
          { txid: txidB, vout: 0 },
          { txid: txidC, vout: 0 },
        ],
        [{ value: 600_000n }]
      );
      const result = await mempool.addTransaction(txD);
      expect(result.accepted).toBe(true);

      const entryD = mempool.getTransaction(getTxId(txD));
      // D has ancestors: A, B, C, and itself = 4
      expect(entryD!.ancestorCount).toBe(4);
    });

    test("removing transaction updates ancestor descendant stats", async () => {
      const inputA = Buffer.alloc(32, 0xe0);
      await setupUTXO(inputA, 0, 1_000_000n);

      // Create parent
      const parent = createTestTx(
        [{ txid: inputA, vout: 0 }],
        [{ value: 900_000n }]
      );
      await mempool.addTransaction(parent);
      const parentTxid = getTxId(parent);

      // Create child
      const child = createTestTx(
        [{ txid: parentTxid, vout: 0 }],
        [{ value: 800_000n }]
      );
      await mempool.addTransaction(child);
      const childTxid = getTxId(child);

      // Parent should have 2 descendants
      let parentEntry = mempool.getTransaction(parentTxid);
      expect(parentEntry!.descendantCount).toBe(2);

      // Remove child
      mempool.removeTransaction(childTxid);

      // Parent should have 1 descendant (itself)
      parentEntry = mempool.getTransaction(parentTxid);
      expect(parentEntry!.descendantCount).toBe(1);
    });
  });
});
