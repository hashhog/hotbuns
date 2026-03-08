/**
 * Tests for transaction mempool.
 */

import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ChainDB, UTXOEntry } from "../storage/database.js";
import { UTXOManager } from "../chain/utxo.js";
import { REGTEST } from "../consensus/params.js";
import { Mempool, MempoolEntry } from "./mempool.js";
import type { Transaction, OutPoint } from "../validation/tx.js";
import { getTxId, getTxVSize } from "../validation/tx.js";
import type { Block } from "../validation/block.js";

describe("Mempool", () => {
  let tempDir: string;
  let db: ChainDB;
  let utxo: UTXOManager;
  let mempool: Mempool;

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
        scriptPubKey: out.scriptPubKey ?? Buffer.from([0x51]), // OP_TRUE for simplicity
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
    tempDir = await mkdtemp(join(tmpdir(), "mempool-test-"));
    db = new ChainDB(tempDir);
    await db.open();
    utxo = new UTXOManager(db);
    mempool = new Mempool(utxo, REGTEST, 1_000_000); // 1MB max for tests
    mempool.setTipHeight(200); // Well past coinbase maturity
  });

  afterEach(async () => {
    await db.close();
    await rm(tempDir, { recursive: true, force: true });
  });

  describe("addTransaction", () => {
    test("accepts valid transaction spending confirmed UTXO", async () => {
      const inputTxid = Buffer.alloc(32, 0xaa);
      await setupUTXO(inputTxid, 0, 10000n);

      const tx = createTestTx(
        [{ txid: inputTxid, vout: 0 }],
        [{ value: 9000n }] // 1000 sat fee
      );

      const result = await mempool.addTransaction(tx);
      expect(result.accepted).toBe(true);
      expect(mempool.getSize()).toBe(1);
    });

    test("rejects coinbase transaction", async () => {
      const tx = createCoinbaseTx(50_00000000n);
      const result = await mempool.addTransaction(tx);
      expect(result.accepted).toBe(false);
      expect(result.error).toContain("Coinbase");
    });

    test("rejects duplicate transaction", async () => {
      const inputTxid = Buffer.alloc(32, 0xbb);
      await setupUTXO(inputTxid, 0, 10000n);

      const tx = createTestTx(
        [{ txid: inputTxid, vout: 0 }],
        [{ value: 9000n }]
      );

      await mempool.addTransaction(tx);
      const result = await mempool.addTransaction(tx);

      expect(result.accepted).toBe(false);
      expect(result.error).toContain("already in mempool");
    });

    test("rejects transaction with missing input", async () => {
      const tx = createTestTx(
        [{ txid: Buffer.alloc(32, 0xff), vout: 0 }],
        [{ value: 9000n }]
      );

      const result = await mempool.addTransaction(tx);
      expect(result.accepted).toBe(false);
      expect(result.error).toContain("Missing input");
    });

    test("rejects transaction with insufficient fee", async () => {
      const inputTxid = Buffer.alloc(32, 0xcc);
      await setupUTXO(inputTxid, 0, 10000n);

      const tx = createTestTx(
        [{ txid: inputTxid, vout: 0 }],
        [{ value: 9999n }] // Only 1 sat fee - below 1 sat/vB
      );

      const result = await mempool.addTransaction(tx);
      expect(result.accepted).toBe(false);
      expect(result.error).toContain("Fee rate");
    });

    test("rejects transaction spending immature coinbase", async () => {
      const inputTxid = Buffer.alloc(32, 0xdd);
      // Coinbase at height 150, tip at 200 = only 50 confirmations (need 100)
      await setupUTXO(inputTxid, 0, 50_00000000n, 150, true);

      const tx = createTestTx(
        [{ txid: inputTxid, vout: 0 }],
        [{ value: 49_00000000n }]
      );

      const result = await mempool.addTransaction(tx);
      expect(result.accepted).toBe(false);
      expect(result.error).toContain("Coinbase maturity");
    });

    test("accepts transaction spending mature coinbase", async () => {
      const inputTxid = Buffer.alloc(32, 0xee);
      // Coinbase at height 50, tip at 200 = 150 confirmations (> 100)
      await setupUTXO(inputTxid, 0, 50_00000000n, 50, true);

      const tx = createTestTx(
        [{ txid: inputTxid, vout: 0 }],
        [{ value: 49_00000000n }]
      );

      const result = await mempool.addTransaction(tx);
      expect(result.accepted).toBe(true);
    });

    test("rejects transaction with outputs exceeding inputs", async () => {
      const inputTxid = Buffer.alloc(32, 0x11);
      await setupUTXO(inputTxid, 0, 10000n);

      const tx = createTestTx(
        [{ txid: inputTxid, vout: 0 }],
        [{ value: 20000n }] // More output than input
      );

      const result = await mempool.addTransaction(tx);
      expect(result.accepted).toBe(false);
      expect(result.error).toContain("Insufficient input");
    });
  });

  describe("double-spend detection", () => {
    test("rejects transaction spending same output as existing mempool tx", async () => {
      const inputTxid = Buffer.alloc(32, 0x22);
      await setupUTXO(inputTxid, 0, 10000n);

      const tx1 = createTestTx(
        [{ txid: inputTxid, vout: 0 }],
        [{ value: 9000n }]
      );

      const tx2 = createTestTx(
        [{ txid: inputTxid, vout: 0 }],
        [{ value: 8000n }] // Different output but same input
      );

      await mempool.addTransaction(tx1);
      const result = await mempool.addTransaction(tx2);

      expect(result.accepted).toBe(false);
      expect(result.error).toContain("Double-spend conflict");
    });
  });

  describe("chained transactions", () => {
    test("accepts transaction spending unconfirmed output", async () => {
      const inputTxid = Buffer.alloc(32, 0x33);
      await setupUTXO(inputTxid, 0, 10000n);

      // First transaction
      const tx1 = createTestTx(
        [{ txid: inputTxid, vout: 0 }],
        [{ value: 9000n }]
      );
      await mempool.addTransaction(tx1);

      const tx1id = getTxId(tx1);

      // Second transaction spending tx1's output
      const tx2 = createTestTx(
        [{ txid: tx1id, vout: 0 }],
        [{ value: 8000n }]
      );

      const result = await mempool.addTransaction(tx2);
      expect(result.accepted).toBe(true);

      // Verify dependency tracking
      const entry1 = mempool.getTransaction(tx1id);
      const entry2 = mempool.getTransaction(getTxId(tx2));

      expect(entry1!.spentBy.has(getTxId(tx2).toString("hex"))).toBe(true);
      expect(entry2!.dependsOn.has(tx1id.toString("hex"))).toBe(true);
    });

    test("removing parent removes dependent children", async () => {
      const inputTxid = Buffer.alloc(32, 0x44);
      await setupUTXO(inputTxid, 0, 10000n);

      // Parent transaction
      const parent = createTestTx(
        [{ txid: inputTxid, vout: 0 }],
        [{ value: 9000n }]
      );
      await mempool.addTransaction(parent);
      const parentTxid = getTxId(parent);

      // Child transaction
      const child = createTestTx(
        [{ txid: parentTxid, vout: 0 }],
        [{ value: 8000n }]
      );
      await mempool.addTransaction(child);

      expect(mempool.getSize()).toBe(2);

      // Remove parent
      mempool.removeTransaction(parentTxid, true);

      expect(mempool.getSize()).toBe(0);
      expect(mempool.getTransaction(parentTxid)).toBeNull();
      expect(mempool.getTransaction(getTxId(child))).toBeNull();
    });
  });

  describe("fee rate ordering", () => {
    test("returns transactions sorted by fee rate descending", async () => {
      // Create 3 UTXOs
      for (let i = 0; i < 3; i++) {
        const txid = Buffer.alloc(32, 0x50 + i);
        await setupUTXO(txid, 0, 10000n);
      }

      // Add transactions with different fee rates
      const lowFeeTx = createTestTx(
        [{ txid: Buffer.alloc(32, 0x50), vout: 0 }],
        [{ value: 9900n }] // 100 sat fee
      );
      const medFeeTx = createTestTx(
        [{ txid: Buffer.alloc(32, 0x51), vout: 0 }],
        [{ value: 9500n }] // 500 sat fee
      );
      const highFeeTx = createTestTx(
        [{ txid: Buffer.alloc(32, 0x52), vout: 0 }],
        [{ value: 9000n }] // 1000 sat fee
      );

      await mempool.addTransaction(lowFeeTx);
      await mempool.addTransaction(medFeeTx);
      await mempool.addTransaction(highFeeTx);

      const sorted = mempool.getTransactionsByFeeRate();

      expect(sorted.length).toBe(3);
      expect(sorted[0].fee).toBe(1000n); // highest first
      expect(sorted[1].fee).toBe(500n);
      expect(sorted[2].fee).toBe(100n); // lowest last
    });
  });

  describe("removeForBlock", () => {
    test("removes confirmed transactions from mempool", async () => {
      const inputTxid = Buffer.alloc(32, 0x55);
      await setupUTXO(inputTxid, 0, 10000n);

      const tx = createTestTx(
        [{ txid: inputTxid, vout: 0 }],
        [{ value: 9000n }]
      );
      await mempool.addTransaction(tx);

      expect(mempool.getSize()).toBe(1);

      // Create a block containing this transaction
      const block: Block = {
        header: {
          version: 0x20000000,
          prevBlock: Buffer.alloc(32, 0),
          merkleRoot: Buffer.alloc(32, 0),
          timestamp: Math.floor(Date.now() / 1000),
          bits: 0x207fffff,
          nonce: 0,
        },
        transactions: [createCoinbaseTx(50_00000000n), tx],
      };

      mempool.removeForBlock(block);

      expect(mempool.getSize()).toBe(0);
    });

    test("removes conflicting transactions when block contains double-spend", async () => {
      const inputTxid = Buffer.alloc(32, 0x66);
      await setupUTXO(inputTxid, 0, 10000n);

      // Add tx to mempool
      const mempoolTx = createTestTx(
        [{ txid: inputTxid, vout: 0 }],
        [{ value: 9000n }]
      );
      await mempool.addTransaction(mempoolTx);

      // Different tx in block spends same input
      const blockTx = createTestTx(
        [{ txid: inputTxid, vout: 0 }],
        [{ value: 8000n }]
      );

      const block: Block = {
        header: {
          version: 0x20000000,
          prevBlock: Buffer.alloc(32, 0),
          merkleRoot: Buffer.alloc(32, 0),
          timestamp: Math.floor(Date.now() / 1000),
          bits: 0x207fffff,
          nonce: 0,
        },
        transactions: [createCoinbaseTx(50_00000000n), blockTx],
      };

      mempool.removeForBlock(block);

      // Mempool tx should be removed as conflicting
      expect(mempool.getSize()).toBe(0);
    });

    test("updates dependency tracking when parent is confirmed", async () => {
      const inputTxid = Buffer.alloc(32, 0x77);
      await setupUTXO(inputTxid, 0, 10000n);

      // Parent transaction
      const parent = createTestTx(
        [{ txid: inputTxid, vout: 0 }],
        [{ value: 9000n }]
      );
      await mempool.addTransaction(parent);
      const parentTxid = getTxId(parent);

      // Child transaction
      const child = createTestTx(
        [{ txid: parentTxid, vout: 0 }],
        [{ value: 8000n }]
      );
      await mempool.addTransaction(child);
      const childTxid = getTxId(child);

      // Block confirms only the parent
      const block: Block = {
        header: {
          version: 0x20000000,
          prevBlock: Buffer.alloc(32, 0),
          merkleRoot: Buffer.alloc(32, 0),
          timestamp: Math.floor(Date.now() / 1000),
          bits: 0x207fffff,
          nonce: 0,
        },
        transactions: [createCoinbaseTx(50_00000000n), parent],
      };

      mempool.removeForBlock(block);

      // Child should still be in mempool but no longer depend on parent
      expect(mempool.getSize()).toBe(1);
      const childEntry = mempool.getTransaction(childTxid);
      expect(childEntry).not.toBeNull();
      expect(childEntry!.dependsOn.has(parentTxid.toString("hex"))).toBe(false);
    });
  });

  describe("eviction", () => {
    test("evicts lowest fee-rate transactions when mempool is full", async () => {
      // Create a very small mempool
      const smallMempool = new Mempool(utxo, REGTEST, 500); // 500 vbytes max
      smallMempool.setTipHeight(200);

      // Create UTXOs
      for (let i = 0; i < 10; i++) {
        const txid = Buffer.alloc(32, 0x80 + i);
        await setupUTXO(txid, 0, 100000n);
      }

      // Add transactions until we exceed limit
      const txs: Transaction[] = [];
      const fees = [100n, 500n, 1000n, 200n, 800n]; // Different fees

      for (let i = 0; i < 5; i++) {
        const tx = createTestTx(
          [{ txid: Buffer.alloc(32, 0x80 + i), vout: 0 }],
          [{ value: 100000n - fees[i] }]
        );
        txs.push(tx);
        await smallMempool.addTransaction(tx);
      }

      // Verify some were evicted
      const info = smallMempool.getInfo();
      expect(info.bytes).toBeLessThanOrEqual(500);

      // Highest fee-rate transactions should remain
      const remaining = smallMempool.getTransactionsByFeeRate();
      for (const entry of remaining) {
        // Only high-fee transactions should remain
        expect(entry.feeRate).toBeGreaterThanOrEqual(info.minFeeRate);
      }
    });
  });

  describe("getInfo", () => {
    test("returns correct statistics", async () => {
      const inputTxid = Buffer.alloc(32, 0x99);
      await setupUTXO(inputTxid, 0, 10000n);

      const tx = createTestTx(
        [{ txid: inputTxid, vout: 0 }],
        [{ value: 9000n }]
      );
      await mempool.addTransaction(tx);

      const info = mempool.getInfo();

      expect(info.size).toBe(1);
      expect(info.bytes).toBeGreaterThan(0);
      expect(info.minFeeRate).toBe(1);
    });
  });

  describe("clear", () => {
    test("removes all entries", async () => {
      const inputTxid = Buffer.alloc(32, 0xaa);
      await setupUTXO(inputTxid, 0, 10000n);

      const tx = createTestTx(
        [{ txid: inputTxid, vout: 0 }],
        [{ value: 9000n }]
      );
      await mempool.addTransaction(tx);

      expect(mempool.getSize()).toBe(1);

      mempool.clear();

      expect(mempool.getSize()).toBe(0);
      expect(mempool.getInfo().bytes).toBe(0);
    });
  });

  describe("getAllTxids", () => {
    test("returns all transaction IDs", async () => {
      // Create multiple transactions
      for (let i = 0; i < 3; i++) {
        const txid = Buffer.alloc(32, 0xb0 + i);
        await setupUTXO(txid, 0, 10000n);

        const tx = createTestTx(
          [{ txid, vout: 0 }],
          [{ value: 9000n }]
        );
        await mempool.addTransaction(tx);
      }

      const txids = mempool.getAllTxids();
      expect(txids.length).toBe(3);

      // Each should be a valid 32-byte buffer
      for (const txid of txids) {
        expect(txid.length).toBe(32);
      }
    });
  });

  describe("hasTransaction", () => {
    test("returns true for existing transaction", async () => {
      const inputTxid = Buffer.alloc(32, 0xc0);
      await setupUTXO(inputTxid, 0, 10000n);

      const tx = createTestTx(
        [{ txid: inputTxid, vout: 0 }],
        [{ value: 9000n }]
      );
      await mempool.addTransaction(tx);

      expect(mempool.hasTransaction(getTxId(tx))).toBe(true);
    });

    test("returns false for non-existent transaction", async () => {
      expect(mempool.hasTransaction(Buffer.alloc(32, 0xff))).toBe(false);
    });
  });
});

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

  async function setupUTXO(txid: Buffer, vout: number, amount: bigint): Promise<void> {
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

  test("rejects transaction exceeding ancestor count limit", async () => {
    // Create a long chain of 26 transactions (exceeds 25 ancestor limit)
    const initialTxid = Buffer.alloc(32, 0x01);
    await setupUTXO(initialTxid, 0, 1000000n);

    let prevTxid: Buffer = initialTxid;

    // Create 25 chained transactions
    for (let i = 0; i < 25; i++) {
      const tx = createTestTx(
        [{ txid: prevTxid, vout: 0 }],
        [{ value: 900000n - BigInt(i * 1000) }]
      );
      const result = await mempool.addTransaction(tx);
      if (!result.accepted) {
        // Should fail at some point due to ancestor limit
        expect(result.error).toContain("ancestors");
        return;
      }
      prevTxid = Buffer.from(getTxId(tx));
    }

    // The 26th should definitely fail
    const finalTx = createTestTx(
      [{ txid: prevTxid, vout: 0 }],
      [{ value: 800000n }]
    );
    const result = await mempool.addTransaction(finalTx);
    expect(result.accepted).toBe(false);
    expect(result.error).toContain("ancestors");
  });

  test("rejects transaction when parent has too many descendants", async () => {
    // Create a parent with many children
    const parentInput = Buffer.alloc(32, 0x02);
    await setupUTXO(parentInput, 0, 1000000n);

    // Parent has multiple outputs
    const parent = createTestTx(
      [{ txid: parentInput, vout: 0 }],
      Array(26).fill({ value: 30000n })
    );
    await mempool.addTransaction(parent);
    const parentTxid = getTxId(parent);

    // Create 25 children spending different outputs of parent
    for (let i = 0; i < 25; i++) {
      // Each child needs its own input (from parent or confirmed)
      const childInput = Buffer.alloc(32, 0x10 + i);
      await setupUTXO(childInput, 0, 50000n);

      const child = createTestTx(
        [
          { txid: parentTxid, vout: i },
          { txid: childInput, vout: 0 },
        ],
        [{ value: 70000n }]
      );
      const result = await mempool.addTransaction(child);
      if (!result.accepted) {
        expect(result.error).toContain("descendants");
        return;
      }
    }

    // One more child should fail
    const extraInput = Buffer.alloc(32, 0x40);
    await setupUTXO(extraInput, 0, 50000n);

    const extraChild = createTestTx(
      [
        { txid: parentTxid, vout: 25 },
        { txid: extraInput, vout: 0 },
      ],
      [{ value: 70000n }]
    );
    const result = await mempool.addTransaction(extraChild);
    expect(result.accepted).toBe(false);
    expect(result.error).toContain("descendants");
  });
});
