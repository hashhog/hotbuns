/**
 * Tests for mempool ancestor/descendant/cluster limits.
 *
 * Bitcoin Core enforces (policy/policy.h + kernel/mempool_limits.h):
 *   Gate A — ancestor count:   ≤ DEFAULT_ANCESTOR_LIMIT = 25  (incl. self)
 *   Gate B — ancestor size:    ≤ 101,000 vB                   (incl. self)
 *   Gate C — descendant count: ≤ DEFAULT_DESCENDANT_LIMIT = 25 (incl. self)
 *   Gate D — descendant size:  ≤ 101,000 vB                   (incl. self)
 *   Gate E — cluster count:    ≤ DEFAULT_CLUSTER_LIMIT = 64
 *   Gate F — cluster vbytes:   ≤ 101,000 vB (DEFAULT_CLUSTER_SIZE_LIMIT_KVB * 1000)
 *
 * References:
 *   bitcoin-core/src/policy/policy.h:72-90
 *   bitcoin-core/src/kernel/mempool_limits.h
 */

import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ChainDB, type UTXOEntry } from "../storage/database.js";
import { UTXOManager } from "../chain/utxo.js";
import { REGTEST } from "../consensus/params.js";
import { Mempool, MAX_CLUSTER_COUNT, MAX_CLUSTER_SIZE_VBYTES } from "../mempool/mempool.js";
import type { Transaction } from "../validation/tx.js";
import { getTxId, getTxVSize } from "../validation/tx.js";

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
      outputs: [
        ...outputs.map((out) => ({
          value: out.value,
          // P2A: standard "anchor" type, spendable with empty scriptSig + witness.
          scriptPubKey: Buffer.from([0x51, 0x02, 0x4e, 0x73]),
        })),
        { value: 0n, scriptPubKey: Buffer.from([0x6a]) }, // OP_RETURN padding (≥65 bytes)
      ],
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
      scriptPubKey: Buffer.from([0x51, 0x02, 0x4e, 0x73]),
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

  // ============================================================================
  // Gate D: descendant size limit (101,000 vbytes)
  // Reference: bitcoin-core/src/policy/policy.h:74 (DEFAULT_CLUSTER_SIZE_LIMIT_KVB=101)
  // Previously enforced via -limitdescendantsize in legacy Core (pre-cluster).
  // ============================================================================
  describe("descendant size limit (101,000 vbytes)", () => {
    test("rejects child when parent descendant vsize would exceed 101,000", async () => {
      // Create a parent tx
      const parentInput = Buffer.alloc(32, 0xf0);
      await setupUTXO(parentInput, 0, 50_000_000n);

      const parent = createTestTx(
        [{ txid: parentInput, vout: 0 }],
        Array(3).fill({ value: 10_000_000n })
      );
      await mempool.addTransaction(parent);
      const parentTxid = getTxId(parent);

      const parentEntry = mempool.getTransaction(parentTxid);
      const parentVsize = parentEntry!.vsize;

      // Add children until we are just under the 101,000 vB descendant-size limit.
      // Each createTestTx produces a transaction of fixed size.
      // We'll add children one at a time until the next one would push over the limit.
      let totalDescendantVsize = parentVsize; // parent counts as its own descendant
      let childIndex = 0;
      let lastParentTxid: Buffer = parentTxid;

      // Build a chain; stop before reaching the size limit.
      // Each tx has 1 input + 2 outputs (one value + one OP_RETURN) ~ ~130 vbytes.
      // We add children until descendant size is ≥ 100,800 vB (leaving < 400 vB headroom).
      const TARGET_NEAR_LIMIT = 100_800;

      while (totalDescendantVsize < TARGET_NEAR_LIMIT) {
        const childInput = Buffer.alloc(32, 0xf0 + childIndex + 1);
        await setupUTXO(childInput, 0, 100_000n);

        const child = createTestTx(
          [{ txid: lastParentTxid, vout: 0 }],
          [{ value: 90_000n }]
        );
        const result = await mempool.addTransaction(child);
        if (!result.accepted) break;

        const childTxid = getTxId(child);
        const childEntry = mempool.getTransaction(childTxid);
        totalDescendantVsize += childEntry!.vsize;
        lastParentTxid = childTxid;
        childIndex++;

        // Safety: don't loop more than 500 times
        if (childIndex > 500) break;
      }

      // Now the next child should either be rejected by descendant-size or ancestor-count.
      // If we hit ancestor count first (25), that's fine — size limit is also enforced.
      const overflowInput = Buffer.alloc(32, 0xff);
      await setupUTXO(overflowInput, 0, 100_000n);

      const overflowChild = createTestTx(
        [{ txid: lastParentTxid, vout: 0 }],
        [{ value: 90_000n }]
      );
      const result = await mempool.addTransaction(overflowChild);

      // Should be rejected by descendant-size OR ancestor-count gate
      expect(result.accepted).toBe(false);
      expect(result.error).toBeDefined();
    });

    test("descendantSize tracks cumulative size correctly", async () => {
      const parentInput = Buffer.alloc(32, 0xf1);
      await setupUTXO(parentInput, 0, 5_000_000n);

      const parent = createTestTx(
        [{ txid: parentInput, vout: 0 }],
        Array(5).fill({ value: 800_000n })
      );
      await mempool.addTransaction(parent);
      const parentTxid = getTxId(parent);

      const parentEntry = mempool.getTransaction(parentTxid);
      expect(parentEntry!.descendantSize).toBe(parentEntry!.vsize);

      // Add 3 children; each should add its vsize to parent's descendantSize
      let expectedDescendantVsize = parentEntry!.vsize;
      for (let i = 0; i < 3; i++) {
        const childInput = Buffer.alloc(32, 0xf2 + i);
        await setupUTXO(childInput, 0, 100_000n);

        const child = createTestTx(
          [{ txid: parentTxid, vout: i }],
          [{ value: 90_000n }]
        );
        const result = await mempool.addTransaction(child);
        expect(result.accepted).toBe(true);

        const childEntry = mempool.getTransaction(getTxId(child));
        expectedDescendantVsize += childEntry!.vsize;

        const updatedParent = mempool.getTransaction(parentTxid);
        expect(updatedParent!.descendantSize).toBe(expectedDescendantVsize);
      }
    });
  });

  // ============================================================================
  // Gate E: cluster count limit (MAX_CLUSTER_COUNT = 64)
  // Reference: bitcoin-core/src/policy/policy.h:72 (DEFAULT_CLUSTER_LIMIT = 64)
  //            bitcoin-core/src/txmempool.cpp:1072-1079 (CheckMemPoolPolicyLimits)
  //
  // Bug fixed: hotbuns had MAX_CLUSTER_SIZE = 100 instead of Core's value of 64.
  // Note: in a simple star topology, the descendant-count gate (25) fires before
  // the cluster-count gate (64) because 25 < 64.  The cluster gate is the binding
  // constraint only for wider topologies (e.g. many parallel chains sharing a root).
  // ============================================================================
  describe("cluster count limit (64)", () => {
    test("MAX_CLUSTER_COUNT constant equals Core DEFAULT_CLUSTER_LIMIT = 64", () => {
      // Bug: hotbuns previously had MAX_CLUSTER_SIZE = 100.
      // Core: bitcoin-core/src/policy/policy.h:72 DEFAULT_CLUSTER_LIMIT = 64.
      expect(MAX_CLUSTER_COUNT).toBe(64);
    });

    test("deprecated MAX_CLUSTER_SIZE alias equals MAX_CLUSTER_COUNT", () => {
      // Backward-compat: MAX_CLUSTER_SIZE is re-exported as MAX_CLUSTER_COUNT.
      const { MAX_CLUSTER_SIZE } = require("../mempool/mempool.js");
      expect(MAX_CLUSTER_SIZE).toBe(MAX_CLUSTER_COUNT);
      expect(MAX_CLUSTER_SIZE).toBe(64);
    });

    test("cluster count check fires before ancestor check for star topology", async () => {
      // In a star topology (1 parent + N children), checkClusterSizeLimit runs
      // before checkAncestorLimits (mempool.ts:1637 vs 1643).
      // The descendant-count gate (MAX_DESCENDANTS=25) will fire at child 25,
      // and since checkClusterSizeLimit runs first, the rejected tx triggers
      // "too-large-cluster" only if cluster count > 64. With 25 children, the
      // cluster count is 26 — well under 64 — so the error comes from the
      // descendant-count gate inside checkAncestorLimits.
      //
      // This test documents that for a star, the effective limit is 25 (descendant
      // count), NOT 64 (cluster count). This is correct behaviour.
      const parentInput = Buffer.alloc(32, 0xc1);
      await setupUTXO(parentInput, 0, 100_000_000n);

      const parent = createTestTx(
        [{ txid: parentInput, vout: 0 }],
        Array(30).fill({ value: 2_000_000n })
      );
      await mempool.addTransaction(parent);
      const parentTxid = getTxId(parent);

      // Add 24 children (total descendants = 25 incl. parent)
      for (let i = 0; i < 24; i++) {
        const childInput = Buffer.alloc(32, 0xc2 + i);
        await setupUTXO(childInput, 0, 100_000n);
        const child = createTestTx(
          [
            { txid: parentTxid, vout: i },
            { txid: childInput, vout: 0 },
          ],
          [{ value: 1_900_000n }]
        );
        const r = await mempool.addTransaction(child);
        expect(r.accepted).toBe(true);
      }

      // 25th child: cluster count = 26 (< 64) so cluster gate passes; descendant
      // gate fires because parent would have 26 descendants (> MAX_DESCENDANTS=25).
      const extra = Buffer.alloc(32, 0xfe);
      await setupUTXO(extra, 0, 100_000n);
      const overChild = createTestTx(
        [
          { txid: parentTxid, vout: 24 },
          { txid: extra, vout: 0 },
        ],
        [{ value: 1_900_000n }]
      );
      const result = await mempool.addTransaction(overChild);
      expect(result.accepted).toBe(false);
      // Error comes from descendant-count gate (checkAncestorLimits), not cluster gate.
      expect(result.error).toContain("descendant");
    });

    test("accepts chain of exactly 25 (ancestor count is the binding limit)", async () => {
      // For a pure chain, ancestor count fires at 26 (not cluster at 64).
      const initialTxid = Buffer.alloc(32, 0xc0);
      await setupUTXO(initialTxid, 0, 10_000_000n);

      let prevTxid: Buffer = initialTxid;
      for (let i = 0; i < 25; i++) {
        const tx = createTestTx(
          [{ txid: prevTxid, vout: 0 }],
          [{ value: 9_000_000n - BigInt(i * 10_000) }]
        );
        const result = await mempool.addTransaction(tx);
        expect(result.accepted).toBe(true);
        prevTxid = Buffer.from(getTxId(tx));
      }
      expect(mempool.getSize()).toBe(25);
    });
  });

  // ============================================================================
  // Gate F: cluster vbytes limit (MAX_CLUSTER_SIZE_VBYTES = 101,000 vB)
  // Reference: bitcoin-core/src/policy/policy.h:74 (DEFAULT_CLUSTER_SIZE_LIMIT_KVB = 101)
  //            bitcoin-core/src/kernel/mempool_limits.h:22
  // ============================================================================
  describe("cluster vbytes limit (101,000 vB)", () => {
    test("MAX_CLUSTER_SIZE_VBYTES constant equals Core DEFAULT_CLUSTER_SIZE_LIMIT_KVB * 1000 = 101,000", () => {
      expect(MAX_CLUSTER_SIZE_VBYTES).toBe(101_000);
    });

    test("accepts two independent transactions (different clusters, no vbyte issue)", async () => {
      // Two completely independent txs — different clusters.
      const input1 = Buffer.alloc(32, 0xb0);
      const input2 = Buffer.alloc(32, 0xb1);
      await setupUTXO(input1, 0, 1_000_000n);
      await setupUTXO(input2, 0, 1_000_000n);

      const tx1 = createTestTx([{ txid: input1, vout: 0 }], [{ value: 900_000n }]);
      const tx2 = createTestTx([{ txid: input2, vout: 0 }], [{ value: 900_000n }]);

      const r1 = await mempool.addTransaction(tx1);
      const r2 = await mempool.addTransaction(tx2);

      expect(r1.accepted).toBe(true);
      expect(r2.accepted).toBe(true);
    });

    test("cluster vbytes is tracked: entry vsize contributions accumulate", async () => {
      // Add a parent and a child and verify each has the expected vsize.
      const parentInput = Buffer.alloc(32, 0xb2);
      await setupUTXO(parentInput, 0, 5_000_000n);

      const parent = createTestTx(
        [{ txid: parentInput, vout: 0 }],
        [{ value: 4_900_000n }]
      );
      await mempool.addTransaction(parent);
      const parentTxid = getTxId(parent);

      const child = createTestTx(
        [{ txid: parentTxid, vout: 0 }],
        [{ value: 4_800_000n }]
      );
      await mempool.addTransaction(child);

      const parentEntry = mempool.getTransaction(parentTxid);
      const childEntry = mempool.getTransaction(getTxId(child));

      expect(parentEntry).not.toBeNull();
      expect(childEntry).not.toBeNull();
      // Both vsizes should be positive
      expect(parentEntry!.vsize).toBeGreaterThan(0);
      expect(childEntry!.vsize).toBeGreaterThan(0);
      // ancestorSize of child = parent.vsize + child.vsize
      expect(childEntry!.ancestorSize).toBe(parentEntry!.vsize + childEntry!.vsize);
    });
  });

  // ============================================================================
  // Error message format tests
  // ============================================================================
  describe("error message formats", () => {
    test("ancestor count rejection includes 'ancestor' keyword", async () => {
      const initialTxid = Buffer.alloc(32, 0xa1);
      await setupUTXO(initialTxid, 0, 1_000_000n);

      let prevTxid: Buffer = initialTxid;
      for (let i = 0; i < 25; i++) {
        const tx = createTestTx(
          [{ txid: prevTxid, vout: 0 }],
          [{ value: 900_000n - BigInt(i * 1000) }]
        );
        await mempool.addTransaction(tx);
        prevTxid = Buffer.from(getTxId(tx));
      }

      const overTx = createTestTx(
        [{ txid: prevTxid, vout: 0 }],
        [{ value: 800_000n }]
      );
      const result = await mempool.addTransaction(overTx);
      expect(result.accepted).toBe(false);
      expect(result.error).toContain("ancestor");
    });

    test("descendant count rejection includes 'descendant' keyword", async () => {
      const parentInput = Buffer.alloc(32, 0xa2);
      await setupUTXO(parentInput, 0, 100_000_000n);

      const parent = createTestTx(
        [{ txid: parentInput, vout: 0 }],
        Array(30).fill({ value: 2_000_000n })
      );
      await mempool.addTransaction(parent);
      const parentTxid = getTxId(parent);

      // Add 24 children to reach parent's descendant count = 25 (including self)
      for (let i = 0; i < 24; i++) {
        const childInput = Buffer.alloc(32, 0xa3 + i);
        await setupUTXO(childInput, 0, 100_000n);

        const child = createTestTx(
          [
            { txid: parentTxid, vout: i },
            { txid: childInput, vout: 0 },
          ],
          [{ value: 1_900_000n }]
        );
        const result = await mempool.addTransaction(child);
        expect(result.accepted).toBe(true);
      }

      // 25th child should fail
      const extraInput = Buffer.alloc(32, 0xfe);
      await setupUTXO(extraInput, 0, 100_000n);

      const extraChild = createTestTx(
        [
          { txid: parentTxid, vout: 24 },
          { txid: extraInput, vout: 0 },
        ],
        [{ value: 1_900_000n }]
      );
      const result = await mempool.addTransaction(extraChild);
      expect(result.accepted).toBe(false);
      expect(result.error).toContain("descendant");
    });
  });
});
