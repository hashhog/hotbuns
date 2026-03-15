/**
 * Tests for TRUC (v3/BIP 431) policy.
 *
 * TRUC (Topologically Restricted Until Confirmation) transactions have stricter
 * relay rules to enable more reliable fee bumping:
 * - v3 tx can have at most 1 unconfirmed ancestor (parent) in mempool
 * - v3 tx can have at most 1 unconfirmed descendant (child)
 * - v3 child tx must be at most 1000 vbytes
 * - v3 parent can be up to 10000 vbytes
 * - v3 transactions are always replaceable (implicit RBF)
 * - v3 child can replace existing v3 child of same parent (sibling eviction)
 * - Non-v3 cannot spend unconfirmed v3 outputs; v3 cannot spend unconfirmed non-v3
 */

import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ChainDB, UTXOEntry } from "../storage/database.js";
import { UTXOManager } from "../chain/utxo.js";
import { REGTEST } from "../consensus/params.js";
import {
  Mempool,
  TRUC_VERSION,
  TRUC_ANCESTOR_LIMIT,
  TRUC_DESCENDANT_LIMIT,
  TRUC_MAX_VSIZE,
  TRUC_CHILD_MAX_VSIZE,
} from "../mempool/mempool.js";
import type { Transaction } from "../validation/tx.js";
import { getTxId, getTxVSize } from "../validation/tx.js";

describe("TRUC (v3) Policy", () => {
  let tempDir: string;
  let db: ChainDB;
  let utxo: UTXOManager;
  let mempool: Mempool;

  // Helper to create a test transaction with configurable version
  function createTestTx(
    version: number,
    inputs: Array<{ txid: Buffer; vout: number; sequence?: number }>,
    outputs: Array<{ value: bigint; scriptPubKey?: Buffer }>
  ): Transaction {
    return {
      version,
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

  // Helper to create a v3 transaction
  function createV3Tx(
    inputs: Array<{ txid: Buffer; vout: number }>,
    outputs: Array<{ value: bigint; scriptPubKey?: Buffer }>
  ): Transaction {
    return createTestTx(TRUC_VERSION, inputs, outputs);
  }

  // Helper to create a v2 transaction
  function createV2Tx(
    inputs: Array<{ txid: Buffer; vout: number }>,
    outputs: Array<{ value: bigint; scriptPubKey?: Buffer }>
  ): Transaction {
    return createTestTx(2, inputs, outputs);
  }

  // Helper to create a large transaction (exceeds TRUC_CHILD_MAX_VSIZE)
  function createLargeTx(
    version: number,
    inputs: Array<{ txid: Buffer; vout: number }>,
    totalValue: bigint,
    targetVsize: number
  ): Transaction {
    // Each output adds about 34 bytes (8 value + 1 scriptPubKey len + 25 P2PKH)
    // We want to create enough outputs to exceed targetVsize
    const outputCount = Math.ceil(targetVsize / 34);
    const valuePerOutput = (totalValue - 10000n) / BigInt(outputCount);

    const outputs: Array<{ value: bigint; scriptPubKey: Buffer }> = [];
    for (let i = 0; i < outputCount; i++) {
      outputs.push({
        value: valuePerOutput,
        // P2PKH-like scriptPubKey (25 bytes)
        scriptPubKey: Buffer.from([
          0x76,
          0xa9,
          0x14,
          ...Array(20).fill(i % 256),
          0x88,
          0xac,
        ]),
      });
    }

    return createTestTx(version, inputs, outputs);
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
    tempDir = await mkdtemp(join(tmpdir(), "truc-test-"));
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

  describe("constants", () => {
    test("TRUC constants are correct", () => {
      expect(TRUC_VERSION).toBe(3);
      expect(TRUC_ANCESTOR_LIMIT).toBe(2);
      expect(TRUC_DESCENDANT_LIMIT).toBe(2);
      expect(TRUC_MAX_VSIZE).toBe(10_000);
      expect(TRUC_CHILD_MAX_VSIZE).toBe(1000);
    });
  });

  describe("v3 version inheritance", () => {
    test("v3 tx can spend confirmed outputs", async () => {
      const inputTxid = Buffer.alloc(32, 0x01);
      await setupUTXO(inputTxid, 0, 100000n);

      const tx = createV3Tx([{ txid: inputTxid, vout: 0 }], [{ value: 99000n }]);
      const result = await mempool.addTransaction(tx);
      expect(result.accepted).toBe(true);
    });

    test("v3 tx can spend unconfirmed v3 outputs", async () => {
      const inputTxid = Buffer.alloc(32, 0x02);
      await setupUTXO(inputTxid, 0, 100000n);

      // Parent v3 tx
      const parent = createV3Tx(
        [{ txid: inputTxid, vout: 0 }],
        [{ value: 99000n }]
      );
      const parentResult = await mempool.addTransaction(parent);
      expect(parentResult.accepted).toBe(true);

      // Child v3 tx spending parent's output
      const child = createV3Tx(
        [{ txid: getTxId(parent), vout: 0 }],
        [{ value: 98000n }]
      );
      const childResult = await mempool.addTransaction(child);
      expect(childResult.accepted).toBe(true);
    });

    test("v3 tx cannot spend unconfirmed non-v3 outputs", async () => {
      const inputTxid = Buffer.alloc(32, 0x03);
      await setupUTXO(inputTxid, 0, 100000n);

      // Parent v2 tx
      const parent = createV2Tx(
        [{ txid: inputTxid, vout: 0 }],
        [{ value: 99000n }]
      );
      const parentResult = await mempool.addTransaction(parent);
      expect(parentResult.accepted).toBe(true);

      // Child v3 tx trying to spend v2 parent's output
      const child = createV3Tx(
        [{ txid: getTxId(parent), vout: 0 }],
        [{ value: 98000n }]
      );
      const childResult = await mempool.addTransaction(child);
      expect(childResult.accepted).toBe(false);
      expect(childResult.error).toContain("version=3 tx cannot spend from non-version=3");
    });

    test("non-v3 tx cannot spend unconfirmed v3 outputs", async () => {
      const inputTxid = Buffer.alloc(32, 0x04);
      await setupUTXO(inputTxid, 0, 100000n);

      // Parent v3 tx
      const parent = createV3Tx(
        [{ txid: inputTxid, vout: 0 }],
        [{ value: 99000n }]
      );
      const parentResult = await mempool.addTransaction(parent);
      expect(parentResult.accepted).toBe(true);

      // Child v2 tx trying to spend v3 parent's output
      const child = createV2Tx(
        [{ txid: getTxId(parent), vout: 0 }],
        [{ value: 98000n }]
      );
      const childResult = await mempool.addTransaction(child);
      expect(childResult.accepted).toBe(false);
      expect(childResult.error).toContain("non-version=3 tx cannot spend from version=3");
    });
  });

  describe("v3 ancestor limits", () => {
    test("v3 tx can have at most 1 unconfirmed ancestor", async () => {
      const inputTxid1 = Buffer.alloc(32, 0x10);
      const inputTxid2 = Buffer.alloc(32, 0x11);
      await setupUTXO(inputTxid1, 0, 100000n);
      await setupUTXO(inputTxid2, 0, 100000n);

      // Parent 1 (v3)
      const parent1 = createV3Tx(
        [{ txid: inputTxid1, vout: 0 }],
        [{ value: 99000n }]
      );
      await mempool.addTransaction(parent1);

      // Parent 2 (v3)
      const parent2 = createV3Tx(
        [{ txid: inputTxid2, vout: 0 }],
        [{ value: 99000n }]
      );
      await mempool.addTransaction(parent2);

      // Child trying to spend from both parents (2 ancestors = too many)
      const child = createV3Tx(
        [
          { txid: getTxId(parent1), vout: 0 },
          { txid: getTxId(parent2), vout: 0 },
        ],
        [{ value: 195000n }]
      );
      const result = await mempool.addTransaction(child);
      expect(result.accepted).toBe(false);
      expect(result.error).toContain("too many ancestors");
    });

    test("v3 tx cannot have a grandparent in mempool", async () => {
      const inputTxid = Buffer.alloc(32, 0x12);
      await setupUTXO(inputTxid, 0, 100000n);

      // Grandparent v3
      const grandparent = createV3Tx(
        [{ txid: inputTxid, vout: 0 }],
        [{ value: 99000n }]
      );
      await mempool.addTransaction(grandparent);

      // Parent v3
      const parent = createV3Tx(
        [{ txid: getTxId(grandparent), vout: 0 }],
        [{ value: 98000n }]
      );
      await mempool.addTransaction(parent);

      // The parent should be in mempool now
      expect(mempool.hasTransaction(getTxId(parent))).toBe(true);

      // Child v3 trying to spend from parent (which has grandparent = 2 ancestors)
      const child = createV3Tx(
        [{ txid: getTxId(parent), vout: 0 }],
        [{ value: 97000n }]
      );
      const result = await mempool.addTransaction(child);
      expect(result.accepted).toBe(false);
      expect(result.error).toContain("too many ancestors");
    });
  });

  describe("v3 descendant limits", () => {
    test("v3 parent can have exactly 1 child", async () => {
      const inputTxid = Buffer.alloc(32, 0x20);
      await setupUTXO(inputTxid, 0, 100000n);

      // Parent v3 with 2 outputs
      const parent = createV3Tx(
        [{ txid: inputTxid, vout: 0 }],
        [{ value: 49000n }, { value: 49000n }]
      );
      await mempool.addTransaction(parent);

      // First child succeeds
      const child1 = createV3Tx(
        [{ txid: getTxId(parent), vout: 0 }],
        [{ value: 48000n }]
      );
      const result1 = await mempool.addTransaction(child1);
      expect(result1.accepted).toBe(true);

      // Second child fails (parent already has a descendant)
      // Since this is v3 and triggers sibling eviction, but with same fee, it should fail
      const child2 = createV3Tx(
        [{ txid: getTxId(parent), vout: 1 }],
        [{ value: 48000n }] // Same fee as child1
      );
      const result2 = await mempool.addTransaction(child2);
      expect(result2.accepted).toBe(false);
      // Sibling eviction requires higher fee
      expect(result2.error).toContain("sibling eviction requires higher fee");
    });
  });

  describe("v3 size limits", () => {
    test("v3 parent can be up to TRUC_MAX_VSIZE", async () => {
      const inputTxid = Buffer.alloc(32, 0x30);
      // Need more input value for the larger tx
      await setupUTXO(inputTxid, 0, 10_000_000n);

      // Create a v3 tx that is just under the limit
      // With many outputs, we can increase the size
      const outputs: Array<{ value: bigint; scriptPubKey: Buffer }> = [];
      // Each output is ~34 bytes, so we need about 290 outputs to reach ~9900 vbytes
      for (let i = 0; i < 280; i++) {
        outputs.push({
          value: 30000n,
          scriptPubKey: Buffer.from([
            0x76,
            0xa9,
            0x14,
            ...Array(20).fill(i % 256),
            0x88,
            0xac,
          ]),
        });
      }

      const tx = createTestTx(TRUC_VERSION, [{ txid: inputTxid, vout: 0 }], outputs);
      const vsize = getTxVSize(tx);

      // Verify we're under the limit
      expect(vsize).toBeLessThanOrEqual(TRUC_MAX_VSIZE);

      const result = await mempool.addTransaction(tx);
      expect(result.accepted).toBe(true);
    });

    test("v3 tx exceeding TRUC_MAX_VSIZE is rejected", async () => {
      const inputTxid = Buffer.alloc(32, 0x31);
      await setupUTXO(inputTxid, 0, 20_000_000n);

      // Create a v3 tx that exceeds the limit
      const outputs: Array<{ value: bigint; scriptPubKey: Buffer }> = [];
      // Need ~300 outputs to exceed 10000 vbytes
      for (let i = 0; i < 310; i++) {
        outputs.push({
          value: 50000n,
          scriptPubKey: Buffer.from([
            0x76,
            0xa9,
            0x14,
            ...Array(20).fill(i % 256),
            0x88,
            0xac,
          ]),
        });
      }

      const tx = createTestTx(TRUC_VERSION, [{ txid: inputTxid, vout: 0 }], outputs);
      const vsize = getTxVSize(tx);

      // Verify we're over the limit
      expect(vsize).toBeGreaterThan(TRUC_MAX_VSIZE);

      const result = await mempool.addTransaction(tx);
      expect(result.accepted).toBe(false);
      expect(result.error).toContain("too big");
      expect(result.error).toContain(TRUC_MAX_VSIZE.toString());
    });

    test("v3 child must be at most TRUC_CHILD_MAX_VSIZE", async () => {
      const inputTxid = Buffer.alloc(32, 0x32);
      await setupUTXO(inputTxid, 0, 5_000_000n);

      // Parent v3
      const parent = createV3Tx(
        [{ txid: inputTxid, vout: 0 }],
        [{ value: 4_990_000n }]
      );
      await mempool.addTransaction(parent);

      // Create a large child (> 1000 vbytes)
      const outputs: Array<{ value: bigint; scriptPubKey: Buffer }> = [];
      // Each output ~34 bytes, need ~30 outputs to exceed 1000 vbytes
      for (let i = 0; i < 35; i++) {
        outputs.push({
          value: 100000n,
          scriptPubKey: Buffer.from([
            0x76,
            0xa9,
            0x14,
            ...Array(20).fill(i % 256),
            0x88,
            0xac,
          ]),
        });
      }

      const child = createTestTx(
        TRUC_VERSION,
        [{ txid: getTxId(parent), vout: 0 }],
        outputs
      );
      const childVsize = getTxVSize(child);

      // Verify child is over the child limit
      expect(childVsize).toBeGreaterThan(TRUC_CHILD_MAX_VSIZE);

      const result = await mempool.addTransaction(child);
      expect(result.accepted).toBe(false);
      expect(result.error).toContain("child tx is too big");
      expect(result.error).toContain(TRUC_CHILD_MAX_VSIZE.toString());
    });

    test("v3 child at or below TRUC_CHILD_MAX_VSIZE is accepted", async () => {
      const inputTxid = Buffer.alloc(32, 0x33);
      await setupUTXO(inputTxid, 0, 1_000_000n);

      // Parent v3
      const parent = createV3Tx(
        [{ txid: inputTxid, vout: 0 }],
        [{ value: 999_000n }]
      );
      await mempool.addTransaction(parent);

      // Small child (well under 1000 vbytes)
      const child = createV3Tx(
        [{ txid: getTxId(parent), vout: 0 }],
        [{ value: 998_000n }]
      );
      const childVsize = getTxVSize(child);

      // Verify child is under the limit
      expect(childVsize).toBeLessThanOrEqual(TRUC_CHILD_MAX_VSIZE);

      const result = await mempool.addTransaction(child);
      expect(result.accepted).toBe(true);
    });
  });

  describe("v3 sibling eviction", () => {
    test("v3 child can replace existing v3 sibling with higher fee", async () => {
      const inputTxid = Buffer.alloc(32, 0x40);
      await setupUTXO(inputTxid, 0, 1_000_000n);

      // Parent v3 with 2 outputs
      const parent = createV3Tx(
        [{ txid: inputTxid, vout: 0 }],
        [{ value: 499_000n }, { value: 499_000n }]
      );
      await mempool.addTransaction(parent);
      const parentTxid = getTxId(parent);

      // First child - low fee
      const sibling1 = createV3Tx(
        [{ txid: parentTxid, vout: 0 }],
        [{ value: 498_000n }] // 1000 sat fee
      );
      const result1 = await mempool.addTransaction(sibling1);
      expect(result1.accepted).toBe(true);
      const sibling1Txid = getTxId(sibling1);

      // Second child (sibling eviction) - higher fee
      const sibling2 = createV3Tx(
        [{ txid: parentTxid, vout: 1 }],
        [{ value: 496_000n }] // 3000 sat fee (higher)
      );
      const result2 = await mempool.addTransaction(sibling2);
      expect(result2.accepted).toBe(true);

      // First sibling should be evicted
      expect(mempool.hasTransaction(sibling1Txid)).toBe(false);
      expect(mempool.hasTransaction(getTxId(sibling2))).toBe(true);
    });

    test("v3 sibling eviction requires higher fee", async () => {
      const inputTxid = Buffer.alloc(32, 0x41);
      await setupUTXO(inputTxid, 0, 1_000_000n);

      // Parent v3 with 2 outputs
      const parent = createV3Tx(
        [{ txid: inputTxid, vout: 0 }],
        [{ value: 499_000n }, { value: 499_000n }]
      );
      await mempool.addTransaction(parent);
      const parentTxid = getTxId(parent);

      // First child - higher fee
      const sibling1 = createV3Tx(
        [{ txid: parentTxid, vout: 0 }],
        [{ value: 496_000n }] // 3000 sat fee
      );
      const result1 = await mempool.addTransaction(sibling1);
      expect(result1.accepted).toBe(true);
      const sibling1Txid = getTxId(sibling1);

      // Second child - lower fee (sibling eviction should fail)
      const sibling2 = createV3Tx(
        [{ txid: parentTxid, vout: 1 }],
        [{ value: 498_000n }] // 1000 sat fee (lower)
      );
      const result2 = await mempool.addTransaction(sibling2);
      expect(result2.accepted).toBe(false);
      expect(result2.error).toContain("sibling eviction requires higher fee");

      // First sibling should still be in mempool
      expect(mempool.hasTransaction(sibling1Txid)).toBe(true);
    });
  });

  describe("v3 implicit RBF", () => {
    test("v3 transactions are always replaceable", async () => {
      const inputTxid = Buffer.alloc(32, 0x50);
      await setupUTXO(inputTxid, 0, 100_000n);

      // v3 tx with final sequence (no BIP125 signal)
      const original = createTestTx(
        TRUC_VERSION,
        [{ txid: inputTxid, vout: 0, sequence: 0xffffffff }],
        [{ value: 99_000n }]
      );
      const result1 = await mempool.addTransaction(original);
      expect(result1.accepted).toBe(true);

      // Replacement v3 tx with higher fee
      const replacement = createTestTx(
        TRUC_VERSION,
        [{ txid: inputTxid, vout: 0, sequence: 0xffffffff }],
        [{ value: 98_000n }]
      );
      const result2 = await mempool.addTransaction(replacement);
      expect(result2.accepted).toBe(true);

      // Original should be evicted
      expect(mempool.hasTransaction(getTxId(original))).toBe(false);
      expect(mempool.hasTransaction(getTxId(replacement))).toBe(true);
    });
  });

  describe("v2 transactions unaffected", () => {
    test("v2 tx can have multiple mempool ancestors", async () => {
      const inputTxid1 = Buffer.alloc(32, 0x60);
      const inputTxid2 = Buffer.alloc(32, 0x61);
      await setupUTXO(inputTxid1, 0, 100_000n);
      await setupUTXO(inputTxid2, 0, 100_000n);

      // Two v2 parents
      const parent1 = createV2Tx(
        [{ txid: inputTxid1, vout: 0 }],
        [{ value: 99_000n }]
      );
      await mempool.addTransaction(parent1);

      const parent2 = createV2Tx(
        [{ txid: inputTxid2, vout: 0 }],
        [{ value: 99_000n }]
      );
      await mempool.addTransaction(parent2);

      // Child spending both parents (allowed for v2)
      const child = createV2Tx(
        [
          { txid: getTxId(parent1), vout: 0 },
          { txid: getTxId(parent2), vout: 0 },
        ],
        [{ value: 196_000n }]
      );
      const result = await mempool.addTransaction(child);
      expect(result.accepted).toBe(true);
    });

    test("v2 tx can have multiple descendants", async () => {
      const inputTxid = Buffer.alloc(32, 0x62);
      await setupUTXO(inputTxid, 0, 100_000n);

      // Parent v2 with 3 outputs
      const parent = createV2Tx(
        [{ txid: inputTxid, vout: 0 }],
        [{ value: 32_000n }, { value: 32_000n }, { value: 32_000n }]
      );
      await mempool.addTransaction(parent);

      // Multiple children (allowed for v2)
      for (let i = 0; i < 3; i++) {
        const child = createV2Tx(
          [{ txid: getTxId(parent), vout: i }],
          [{ value: 31_000n }]
        );
        const result = await mempool.addTransaction(child);
        expect(result.accepted).toBe(true);
      }

      expect(mempool.getSize()).toBe(4); // parent + 3 children
    });
  });
});
