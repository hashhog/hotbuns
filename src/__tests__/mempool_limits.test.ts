/**
 * Tests for mempool CLUSTER limits.
 *
 * Bitcoin Core v31 REPLACED the ancestor/descendant limits with cluster limits.
 * The old gates — ancestor count 25, ancestor size 101,000 vB, descendant count
 * 25, descendant size 101,000 vB — are gone, along with their reject token
 * `too-long-mempool-chain`, which no longer appears anywhere in the Core tree.
 *
 * What Core enforces now, in WEIGHT UNITS throughout:
 *
 *   per-tx contribution := max(tx_weight, tx_sigops_cost * 20)
 *                          GetSigOpsAdjustedWeight, policy/policy.cpp:390,
 *                          fed to TxGraph at txmempool.cpp:1017
 *   cluster_size        := Σ (per-tx contribution)   — NO per-tx division,
 *                                                      NO per-tx rounding
 *   reject if cluster_size  > 404,000  (= 101,000 vB * WITNESS_SCALE_FACTOR,
 *                                        txmempool.cpp:181)
 *   reject if cluster_count > 64       (DEFAULT_CLUSTER_LIMIT, policy.h:72)
 *
 * Both comparisons are strictly `>` — the single oversize test at
 * txgraph.cpp:2059 — so 64 ACCEPTS and 65 REJECTS.
 *
 * Reject token is the bare "too-large-cluster" with an EMPTY debug string
 * (validation.cpp:1024, :1116, :1343, :1521).
 *
 * Scope: this is mempool POLICY. None of it affects block validation.
 *
 * Still enforced and deliberately untouched by these tests:
 *   - TRUC/v3 2-ancestor / 2-descendant limits (see truc.test.ts)
 *   - MAX_PACKAGE_COUNT = 25, a DIFFERENT limit (see package.test.ts)
 *
 * References:
 *   bitcoin-core/src/policy/policy.h:50,72,74
 *   bitcoin-core/src/kernel/mempool_limits.h:20-22
 *   bitcoin-core/src/txmempool.cpp:181, :1017
 *   bitcoin-core/src/policy/policy.cpp:390
 *   bitcoin-core/src/txgraph.cpp:2059
 */

import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ChainDB, type UTXOEntry } from "../storage/database.js";
import { UTXOManager } from "../chain/utxo.js";
import { REGTEST } from "../consensus/params.js";
import {
  Mempool,
  MAX_CLUSTER_COUNT,
  MAX_CLUSTER_SIZE_VBYTES,
  MAX_CLUSTER_SIZE_WEIGHT,
  MAX_PACKAGE_COUNT,
  TRUC_ANCESTOR_LIMIT,
  TRUC_DESCENDANT_LIMIT,
  DEFAULT_BYTES_PER_SIGOP,
} from "../mempool/mempool.js";
import type { Transaction } from "../validation/tx.js";
import { getTxId, getTxVSize, getSigOpsAdjustedWeight } from "../validation/tx.js";

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

  // A standard bare 1-of-1 multisig scriptPubKey:
  //   OP_1 <33-byte pubkey> OP_1 OP_CHECKMULTISIG
  // Standard because DEFAULT_PERMIT_BAREMULTISIG is true (policy.h:52). Used as a
  // sigop-dense but small-weight output so that max(weight, sigops*20) is
  // dominated by the sigop term.
  function bareMultisigScript(): Buffer {
    const pubkey = Buffer.alloc(33, 0x02);
    pubkey[0] = 0x02;
    return Buffer.concat([
      Buffer.from([0x51, 0x21]), // OP_1, PUSH33
      pubkey,
      Buffer.from([0x51, 0xae]), // OP_1, OP_CHECKMULTISIG
    ]);
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

  describe("ancestor count (no longer a gate — cluster count is)", () => {
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

    test("ACCEPTS the 26th transaction in a chain (Core v31 removed the 25-ancestor gate)", async () => {
      // Regression pin for Wave A. Before the cluster-limit change this tx was
      // rejected with `too-long-mempool-chain`. Core v31 deleted that gate
      // outright — a 26-long chain is only 26 txs and ~7,700 WU, far inside both
      // cluster bounds (64 / 404,000), so Core accepts it.
      //
      // Matches diff-test corpus entry `cluster-linear-26` (all 26 accept).
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

      // The 26th now succeeds.
      const finalTx = createTestTx(
        [{ txid: prevTxid, vout: 0 }],
        [{ value: 800_000n }]
      );
      const result = await mempool.addTransaction(finalTx);
      expect(result.accepted).toBe(true);
      expect(mempool.getSize()).toBe(26);
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

  describe("descendant count (no longer a gate — cluster count is)", () => {
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

    test("ACCEPTS a 25th child (Core v31 removed the 25-descendant gate)", async () => {
      // Regression pin for Wave A. Before the cluster-limit change this was
      // rejected with `too-long-mempool-chain`. The resulting cluster is
      // 1 parent + 25 children = 26 txs, well inside the 64 cluster-count bound,
      // so Core accepts.
      //
      // Matches diff-test corpus entry `cluster-fan-26` (all accept).
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

      // The 25th child now succeeds.
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
      expect(result.accepted).toBe(true);

      // Parent now has 26 descendants (itself + 25 children) — no longer a gate.
      const parentEntry = mempool.getTransaction(parentTxid);
      expect(parentEntry!.descendantCount).toBe(26);
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
  describe("descendant size (no longer a gate — cluster weight is)", () => {
    test("a long chain is bounded, and the bound is the CLUSTER gate", async () => {
      // The per-ancestor descendant-vsize gate is gone. What still bounds an
      // unbounded chain is checkClusterSizeLimit. With these small fixtures
      // (~296 WU each) the count bound (64) is reached long before the weight
      // bound (404,000 WU), so the chain terminates at exactly 64 entries with
      // the bare `too-large-cluster` token.
      //
      // This test exists to prove the deletion of the descendant gates did NOT
      // leave the chain unbounded.
      const rootTxid = Buffer.alloc(32, 0xf0);
      await setupUTXO(rootTxid, 0, 50_000_000n);

      let prevTxid: Buffer = rootTxid;
      let accepted = 0;
      let firstError: string | undefined;

      for (let i = 0; i < 200; i++) {
        const tx = createTestTx(
          [{ txid: prevTxid, vout: 0 }],
          [{ value: 40_000_000n - BigInt(i * 100_000) }]
        );
        const result = await mempool.addTransaction(tx);
        if (!result.accepted) {
          firstError = result.error;
          break;
        }
        accepted++;
        prevTxid = Buffer.from(getTxId(tx));
      }

      // Bounded, and bounded by the cluster-count gate at exactly 64.
      expect(accepted).toBe(MAX_CLUSTER_COUNT);
      expect(firstError).toBe("too-large-cluster");
      expect(mempool.getSize()).toBe(MAX_CLUSTER_COUNT);
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
  // Cluster count limit (MAX_CLUSTER_COUNT = 64)
  // Reference: bitcoin-core/src/policy/policy.h:72 (DEFAULT_CLUSTER_LIMIT = 64)
  //            bitcoin-core/src/txgraph.cpp:2059 (strict `>` oversize test)
  //
  // Since Core v31 removed the ancestor/descendant gates, the cluster count is
  // the binding constraint for EVERY topology — chain, star and sibling-fan
  // alike — not just for wide ones.
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

    test("BOUNDARY: a 64-tx chain is accepted, the 65th is rejected", async () => {
      // The core boundary assertion. Core's oversize test (txgraph.cpp:2059) is
      // `total_count > m_max_cluster_count`, i.e. strictly greater — so a cluster
      // of exactly 64 is legal and 65 is not. An implementation using `>=` would
      // reject tx[63]; one with no count bound at all (or one that merely bumped
      // MAX_PACKAGE_COUNT to 64) would accept all 65.
      //
      // Matches diff-test corpus entries `cluster-linear-64` and `cluster-linear-65`.
      const initialTxid = Buffer.alloc(32, 0xc0);
      await setupUTXO(initialTxid, 0, 100_000_000n);

      let prevTxid: Buffer = initialTxid;
      for (let i = 0; i < MAX_CLUSTER_COUNT; i++) {
        const tx = createTestTx(
          [{ txid: prevTxid, vout: 0 }],
          [{ value: 90_000_000n - BigInt(i * 100_000) }]
        );
        const result = await mempool.addTransaction(tx);
        // Every one of the first 64 must be accepted — including the 64th.
        expect(result.accepted).toBe(true);
        prevTxid = Buffer.from(getTxId(tx));
      }
      expect(mempool.getSize()).toBe(64);

      // The 65th makes the cluster 65 > 64 and must be rejected.
      const overflow = createTestTx(
        [{ txid: prevTxid, vout: 0 }],
        [{ value: 80_000_000n }]
      );
      const result = await mempool.addTransaction(overflow);
      expect(result.accepted).toBe(false);
      expect(result.error).toBe("too-large-cluster");
      expect(mempool.getSize()).toBe(64);
    });

    test("count is scoped to the CONNECTED COMPONENT, not the ancestor set", async () => {
      // Sibling fan-out: one root, then N children each spending a distinct root
      // output. Every child has only 2 ancestors (itself + root), so an
      // implementation that scoped the count to the ancestor set would accept
      // arbitrarily many. The connected component, however, grows by 1 per child
      // and must stop at 64 total.
      //
      // Matches diff-test corpus entry `cluster-sibling-72`.
      const rootInput = Buffer.alloc(32, 0xc1);
      await setupUTXO(rootInput, 0, 200_000_000n);

      const root = createTestTx(
        [{ txid: rootInput, vout: 0 }],
        Array(80).fill({ value: 2_000_000n })
      );
      expect((await mempool.addTransaction(root)).accepted).toBe(true);
      const rootTxid = getTxId(root);

      let accepted = 0;
      let firstError: string | undefined;
      for (let i = 0; i < 80; i++) {
        const child = createTestTx(
          [{ txid: rootTxid, vout: i }],
          [{ value: 1_900_000n }]
        );
        const r = await mempool.addTransaction(child);
        if (!r.accepted) {
          firstError = r.error;
          break;
        }
        accepted++;
      }

      // root + 63 children = 64 in the component; the 64th child would make 65.
      expect(accepted).toBe(MAX_CLUSTER_COUNT - 1);
      expect(firstError).toBe("too-large-cluster");
      expect(mempool.getSize()).toBe(MAX_CLUSTER_COUNT);
    });

    test("independent clusters are counted separately", async () => {
      // Two disjoint 40-tx chains total 80 transactions but form two clusters of
      // 40 each, so neither trips the 64 bound. Guards against a gate that
      // accidentally measures the whole mempool.
      for (const [seed, tag] of [[0xd0, "a"], [0xd1, "b"]] as const) {
        const rootTxid = Buffer.alloc(32, seed);
        await setupUTXO(rootTxid, 0, 100_000_000n);
        let prevTxid: Buffer = rootTxid;
        for (let i = 0; i < 40; i++) {
          const tx = createTestTx(
            [{ txid: prevTxid, vout: 0 }],
            [{ value: 90_000_000n - BigInt(i * 100_000) }]
          );
          const r = await mempool.addTransaction(tx);
          expect(`${tag}${i}:${r.accepted}`).toBe(`${tag}${i}:true`);
          prevTxid = Buffer.from(getTxId(tx));
        }
      }
      expect(mempool.getSize()).toBe(80);
    });
  });

  // ============================================================================
  // Cluster size limit — enforced in WEIGHT units (404,000 WU)
  // Reference: bitcoin-core/src/policy/policy.h:74 (DEFAULT_CLUSTER_SIZE_LIMIT_KVB = 101)
  //            bitcoin-core/src/kernel/mempool_limits.h:22
  //            bitcoin-core/src/txmempool.cpp:181  (* WITNESS_SCALE_FACTOR)
  //            bitcoin-core/src/policy/policy.cpp:390 (GetSigOpsAdjustedWeight)
  // ============================================================================
  describe("cluster size limit (404,000 weight units)", () => {
    test("MAX_CLUSTER_SIZE_VBYTES constant equals Core DEFAULT_CLUSTER_SIZE_LIMIT_KVB * 1000 = 101,000", () => {
      // This is the CONFIG-facing value, reported by getmempoolinfo.limitclustersize
      // (Core rpc/mempool.cpp:1062). It is not the enforcement unit.
      expect(MAX_CLUSTER_SIZE_VBYTES).toBe(101_000);
    });

    test("UNITS: enforcement constant is 404,000 WEIGHT units, = vbytes * WITNESS_SCALE_FACTOR", () => {
      // Core scales the vbyte config into weight exactly once, at
      // txmempool.cpp:181:
      //     max_cluster_size = cluster_size_vbytes * WITNESS_SCALE_FACTOR
      expect(MAX_CLUSTER_SIZE_WEIGHT).toBe(404_000);
      expect(MAX_CLUSTER_SIZE_WEIGHT).toBe(MAX_CLUSTER_SIZE_VBYTES * 4);
    });

    test("UNITS: per-tx contribution is max(weight, sigops * 20), not ceil(w/4)", () => {
      // policy.h:50 DEFAULT_BYTES_PER_SIGOP{20}
      // policy.cpp:390 GetSigOpsAdjustedWeight -> std::max(weight, sigop_cost * bytes_per_sigop)
      expect(DEFAULT_BYTES_PER_SIGOP).toBe(20);

      // Weight-dominated: sigops are cheap, weight wins.
      expect(getSigOpsAdjustedWeight(4000, 10, DEFAULT_BYTES_PER_SIGOP)).toBe(4000);
      // Sigop-dominated: 400 sigops * 20 = 8000 > 1216 weight (the exact numbers
      // produced by the 5-bare-multisig-output fixture used below).
      expect(getSigOpsAdjustedWeight(1216, 400, DEFAULT_BYTES_PER_SIGOP)).toBe(8000);
      // Boundary: equal — max() returns the shared value, no double counting.
      expect(getSigOpsAdjustedWeight(2000, 100, DEFAULT_BYTES_PER_SIGOP)).toBe(2000);
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

    test("SIGOP-BOUND: max(weight, sigops*20) is what trips the size limit", async () => {
      // The decisive test that cluster size is accumulated as sigop-adjusted
      // WEIGHT and not as raw weight.
      //
      // Fixture: each tx carries 5 bare 1-of-1 multisig outputs, which are
      // standard (DEFAULT_PERMIT_BAREMULTISIG) and sigop-dense. Measured on this
      // implementation, each such tx has:
      //     weight     = 1,216 WU
      //     sigOpCost  =   400
      //     adjWeight  = max(1216, 400 * 20) = 8,000 WU   <- sigop-dominated, 6.6x
      //
      // Therefore the cluster trips the 404,000 WU bound at:
      //     50 txs -> 400,000 <= 404,000   ACCEPT
      //     51 txs -> 408,000 >  404,000   REJECT
      //
      // Three ways an implementation gets this wrong, all caught here:
      //   * summing RAW weight    -> 51 * 1,216 = 62,016, accepts all 51+
      //   * count gate only       -> 51 < 64, accepts
      //   * bound in vbytes (101,000) against raw vsize -> also accepts
      // Only max(weight, sigops*20) summed in weight units stops at 50.
      const rootTxid = Buffer.alloc(32, 0xe0);
      await setupUTXO(rootTxid, 0, 100_000_000n);

      let prevTxid: Buffer = rootTxid;
      let value = 100_000_000n;
      let accepted = 0;
      let firstError: string | undefined;
      let perTxWeight = 0;
      let perTxSigOps = 0;

      for (let i = 0; i < 70; i++) {
        const next = value - 600_000n;
        const tx: Transaction = {
          version: 2,
          inputs: [
            {
              prevOut: { txid: prevTxid, vout: 0 },
              scriptSig: Buffer.alloc(0),
              sequence: 0xffffffff,
              witness: [],
            },
          ],
          outputs: [
            { value: next, scriptPubKey: Buffer.from([0x51, 0x02, 0x4e, 0x73]) },
            ...Array(5)
              .fill(0)
              .map(() => ({ value: 100_000n, scriptPubKey: bareMultisigScript() })),
            { value: 0n, scriptPubKey: Buffer.from([0x6a]) },
          ],
          lockTime: 0,
        };
        const r = await mempool.addTransaction(tx);
        if (!r.accepted) {
          firstError = r.error;
          break;
        }
        const entry = mempool.getTransaction(getTxId(tx))!;
        perTxWeight = entry.weight;
        perTxSigOps = entry.sigOpCost;
        accepted++;
        value = next;
        prevTxid = Buffer.from(getTxId(tx));
      }

      // Pin the fixture's own arithmetic so a change in sigop counting shows up
      // here as a fixture failure rather than silently moving the boundary.
      expect(perTxWeight).toBe(1216);
      expect(perTxSigOps).toBe(400);
      const adjWeight = getSigOpsAdjustedWeight(
        perTxWeight,
        perTxSigOps,
        DEFAULT_BYTES_PER_SIGOP
      );
      expect(adjWeight).toBe(8000);
      expect(adjWeight).toBeGreaterThan(perTxWeight); // sigop-dominated

      // The boundary itself, derived from the constants rather than hardcoded.
      const expectedAccepts = Math.floor(MAX_CLUSTER_SIZE_WEIGHT / adjWeight); // 50
      expect(expectedAccepts).toBe(50);
      expect(accepted).toBe(expectedAccepts);
      expect(accepted * adjWeight).toBeLessThanOrEqual(MAX_CLUSTER_SIZE_WEIGHT);
      expect((accepted + 1) * adjWeight).toBeGreaterThan(MAX_CLUSTER_SIZE_WEIGHT);
      expect(firstError).toBe("too-large-cluster");

      // Crucially, the COUNT gate did not fire — 51 is well under 64. The weight
      // gate is provably what rejected, and only sigop adjustment gets it there.
      expect(accepted + 1).toBeLessThan(MAX_CLUSTER_COUNT);
      expect(accepted * perTxWeight).toBeLessThan(MAX_CLUSTER_SIZE_WEIGHT);
    });
  });

  // ============================================================================
  // Reject-token format
  // ============================================================================
  describe("reject token format", () => {
    test("token is exactly 'too-large-cluster' with an EMPTY debug string", async () => {
      // Core: state.Invalid(TX_MEMPOOL_POLICY, "too-large-cluster", "")
      //   validation.cpp:1024, :1116, :1343, :1521
      // The debug argument is the empty string at all four call sites, so the
      // surfaced error carries NO count, NO size and NO txid. Asserting exact
      // equality (not `toContain`) is what pins that.
      const initialTxid = Buffer.alloc(32, 0xa1);
      await setupUTXO(initialTxid, 0, 100_000_000n);

      let prevTxid: Buffer = initialTxid;
      for (let i = 0; i < MAX_CLUSTER_COUNT; i++) {
        const tx = createTestTx(
          [{ txid: prevTxid, vout: 0 }],
          [{ value: 90_000_000n - BigInt(i * 100_000) }]
        );
        const r = await mempool.addTransaction(tx);
        expect(r.accepted).toBe(true);
        prevTxid = Buffer.from(getTxId(tx));
      }

      const overTx = createTestTx(
        [{ txid: prevTxid, vout: 0 }],
        [{ value: 80_000_000n }]
      );
      const result = await mempool.addTransaction(overTx);
      expect(result.accepted).toBe(false);
      expect(result.error).toBe("too-large-cluster");
      // No debug detail appended.
      expect(result.error).not.toContain("64");
      expect(result.error).not.toContain("count");
      expect(result.error).not.toContain(":");
    });

    test("'too-long-mempool-chain' is never emitted (Core v31 deleted the token)", async () => {
      // The old ancestor/descendant token must not survive anywhere in the
      // acceptance path. Drive a 70-long chain and a wide fan and assert no
      // rejection ever carries it.
      const seen: string[] = [];

      const chainRoot = Buffer.alloc(32, 0xa2);
      await setupUTXO(chainRoot, 0, 100_000_000n);
      let prevTxid: Buffer = chainRoot;
      for (let i = 0; i < 70; i++) {
        const tx = createTestTx(
          [{ txid: prevTxid, vout: 0 }],
          [{ value: 90_000_000n - BigInt(i * 100_000) }]
        );
        const r = await mempool.addTransaction(tx);
        if (!r.accepted) {
          seen.push(r.error ?? "");
          break;
        }
        prevTxid = Buffer.from(getTxId(tx));
      }

      expect(seen.length).toBeGreaterThan(0);
      for (const e of seen) {
        expect(e).not.toContain("too-long-mempool-chain");
        expect(e).toBe("too-large-cluster");
      }
    });
  });

  // ============================================================================
  // Limits that must NOT have changed in this wave
  // ============================================================================
  describe("adjacent limits are untouched", () => {
    test("MAX_PACKAGE_COUNT stays 25 — it is NOT the cluster count", () => {
      // A package is what may be submitted in one submitpackage call
      // (mempool.ts MAX_PACKAGE_COUNT). Raising it to 64 to "match" the cluster
      // limit would conflate two different limits.
      expect(MAX_PACKAGE_COUNT).toBe(25);
      expect(MAX_PACKAGE_COUNT).not.toBe(MAX_CLUSTER_COUNT);
    });

    test("TRUC 2-ancestor / 2-descendant limits stay 2/2", () => {
      // BIP 431. These are the ONLY surviving ancestor/descendant enforcement
      // after Core v31 and are unaffected by the cluster-limit change.
      expect(TRUC_ANCESTOR_LIMIT).toBe(2);
      expect(TRUC_DESCENDANT_LIMIT).toBe(2);
    });
  });
});
