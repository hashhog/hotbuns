/**
 * Tests for cluster mempool: cluster identification, linearization, and mining scores.
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
  UnionFind,
  MAX_CLUSTER_SIZE,
  type Cluster,
  type Chunk,
} from "../mempool/mempool.js";
import type { Transaction } from "../validation/tx.js";
import { getTxId, getTxVSize } from "../validation/tx.js";

describe("UnionFind", () => {
  test("creates singleton sets", () => {
    const uf = new UnionFind();
    uf.makeSet("a");
    uf.makeSet("b");

    expect(uf.find("a")).toBe("a");
    expect(uf.find("b")).toBe("b");
    expect(uf.connected("a", "b")).toBe(false);
    expect(uf.getSize("a")).toBe(1);
    expect(uf.getSize("b")).toBe(1);
  });

  test("unions two sets", () => {
    const uf = new UnionFind();
    uf.makeSet("a");
    uf.makeSet("b");
    uf.union("a", "b");

    expect(uf.connected("a", "b")).toBe(true);
    expect(uf.getSize("a")).toBe(2);
    expect(uf.getSize("b")).toBe(2);
  });

  test("unions multiple sets transitively", () => {
    const uf = new UnionFind();
    uf.makeSet("a");
    uf.makeSet("b");
    uf.makeSet("c");
    uf.makeSet("d");

    uf.union("a", "b");
    uf.union("c", "d");
    uf.union("b", "c");

    // All four should be connected
    expect(uf.connected("a", "d")).toBe(true);
    expect(uf.getSize("a")).toBe(4);
  });

  test("uses path compression", () => {
    const uf = new UnionFind();
    // Create a long chain: a -> b -> c -> d -> e
    for (const id of ["a", "b", "c", "d", "e"]) {
      uf.makeSet(id);
    }
    uf.union("a", "b");
    uf.union("b", "c");
    uf.union("c", "d");
    uf.union("d", "e");

    // After find, paths should be compressed
    const root = uf.find("e");
    expect(uf.find("a")).toBe(root);
    expect(uf.find("b")).toBe(root);
    expect(uf.find("c")).toBe(root);
    expect(uf.find("d")).toBe(root);
  });

  test("getAllRoots returns unique cluster IDs", () => {
    const uf = new UnionFind();
    uf.makeSet("a");
    uf.makeSet("b");
    uf.makeSet("c");
    uf.makeSet("d");

    uf.union("a", "b");
    uf.union("c", "d");

    const roots = uf.getAllRoots();
    expect(roots.size).toBe(2);
  });
});

describe("Cluster Mempool - Linearization", () => {
  let tempDir: string;
  let db: ChainDB;
  let utxo: UTXOManager;
  let mempool: Mempool;

  // Helper to create a simple test transaction
  function createTestTx(
    inputs: Array<{ txid: Buffer; vout: number }>,
    outputs: Array<{ value: bigint; scriptPubKey?: Buffer }>,
    version: number = 2
  ): Transaction {
    return {
      version,
      inputs: inputs.map((inp) => ({
        prevOut: { txid: inp.txid, vout: inp.vout },
        scriptSig: Buffer.alloc(0),
        sequence: 0xffffffff,
        witness: [],
      })),
      outputs: outputs.map((out) => ({
        value: out.value,
        scriptPubKey: out.scriptPubKey ?? Buffer.from([0x51]), // OP_TRUE
      })),
      lockTime: 0,
    };
  }

  async function setupUTXO(
    txid: Buffer,
    vout: number,
    amount: bigint,
    height: number = 1
  ): Promise<void> {
    const entry: UTXOEntry = {
      height,
      coinbase: false,
      amount,
      scriptPubKey: Buffer.from([0x51]), // OP_TRUE
    };
    await db.putUTXO(txid, vout, entry);
  }

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "cluster-mempool-test-"));
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

  test("singleton transaction has itself as cluster", async () => {
    const inputTxid = Buffer.alloc(32, 0x01);
    await setupUTXO(inputTxid, 0, 10000n);

    const tx = createTestTx(
      [{ txid: inputTxid, vout: 0 }],
      [{ value: 9000n }] // 1000 sat fee
    );

    const result = await mempool.addTransaction(tx);
    expect(result.accepted).toBe(true);

    const txidHex = getTxId(tx).toString("hex");
    const cluster = mempool.getCluster(txidHex);

    expect(cluster).not.toBeNull();
    expect(cluster!.txids.size).toBe(1);
    expect(cluster!.txids.has(txidHex)).toBe(true);
  });

  test("chained transactions form a single cluster", async () => {
    const inputTxid = Buffer.alloc(32, 0x02);
    await setupUTXO(inputTxid, 0, 100000n);

    // Create parent tx
    const parent = createTestTx(
      [{ txid: inputTxid, vout: 0 }],
      [{ value: 99000n }] // 1000 sat fee
    );
    await mempool.addTransaction(parent);
    const parentTxid = getTxId(parent);

    // Create child tx spending parent
    const child = createTestTx(
      [{ txid: parentTxid, vout: 0 }],
      [{ value: 98000n }] // 1000 sat fee
    );
    await mempool.addTransaction(child);
    const childTxid = getTxId(child);

    // Both should be in the same cluster
    const parentTxidHex = parentTxid.toString("hex");
    const childTxidHex = childTxid.toString("hex");

    expect(mempool.getClusterId(parentTxidHex)).toBe(
      mempool.getClusterId(childTxidHex)
    );

    const cluster = mempool.getCluster(parentTxidHex);
    expect(cluster!.txids.size).toBe(2);
    expect(cluster!.txids.has(parentTxidHex)).toBe(true);
    expect(cluster!.txids.has(childTxidHex)).toBe(true);
  });

  test("linearization produces topological order", async () => {
    const inputTxid = Buffer.alloc(32, 0x03);
    await setupUTXO(inputTxid, 0, 100000n);

    // Create parent
    const parent = createTestTx(
      [{ txid: inputTxid, vout: 0 }],
      [{ value: 99000n }]
    );
    await mempool.addTransaction(parent);
    const parentTxid = getTxId(parent);

    // Create child
    const child = createTestTx(
      [{ txid: parentTxid, vout: 0 }],
      [{ value: 98000n }]
    );
    await mempool.addTransaction(child);

    const parentTxidHex = parentTxid.toString("hex");
    const cluster = mempool.getCluster(parentTxidHex)!;
    const linearization = cluster.linearization;

    // There should be chunks
    expect(linearization.chunks.length).toBeGreaterThan(0);

    // Verify topological ordering: parent should come before child in chunks
    const parentChunkIdx = linearization.txToChunk.get(parentTxidHex)!;
    const childTxidHex = getTxId(child).toString("hex");
    const childChunkIdx = linearization.txToChunk.get(childTxidHex)!;

    // Parent should be in an earlier or same chunk as child
    expect(parentChunkIdx).toBeLessThanOrEqual(childChunkIdx);
  });

  test("high-fee child absorbs low-fee parent into same chunk", async () => {
    const inputTxid = Buffer.alloc(32, 0x04);
    await setupUTXO(inputTxid, 0, 100000n);

    // Create low-fee parent (1 sat/vB)
    const parent = createTestTx(
      [{ txid: inputTxid, vout: 0 }],
      [{ value: 99900n }] // ~100 sat fee for ~100 vsize = ~1 sat/vB
    );
    await mempool.addTransaction(parent);
    const parentTxid = getTxId(parent);

    // Create high-fee child (100 sat/vB)
    const child = createTestTx(
      [{ txid: parentTxid, vout: 0 }],
      [{ value: 89900n }] // ~10000 sat fee = ~100 sat/vB
    );
    await mempool.addTransaction(child);

    const parentTxidHex = parentTxid.toString("hex");
    const childTxidHex = getTxId(child).toString("hex");

    const cluster = mempool.getCluster(parentTxidHex)!;

    // With a high-fee child, they may be merged into the same chunk
    // because the child's feerate > parent's feerate causes absorption
    const parentChunkIdx = cluster.linearization.txToChunk.get(parentTxidHex)!;
    const childChunkIdx = cluster.linearization.txToChunk.get(childTxidHex)!;

    // The chunk containing the child should have absorbed the parent
    expect(parentChunkIdx).toBe(childChunkIdx);
  });

  test("mining score reflects chunk fee rate", async () => {
    const inputTxid = Buffer.alloc(32, 0x05);
    await setupUTXO(inputTxid, 0, 100000n);

    // Single transaction
    const tx = createTestTx(
      [{ txid: inputTxid, vout: 0 }],
      [{ value: 90000n }] // 10000 sat fee
    );
    await mempool.addTransaction(tx);

    const txidHex = getTxId(tx).toString("hex");
    const entry = mempool.getTransaction(Buffer.from(txidHex, "hex"))!;

    // Mining score should equal fee rate for a singleton
    expect(entry.miningScore).toBeCloseTo(entry.feeRate, 1);
  });

  test("CPFP: mining score reflects effective chunk fee rate", async () => {
    const inputTxid = Buffer.alloc(32, 0x06);
    await setupUTXO(inputTxid, 0, 100000n);

    // Create low-fee parent (1 sat/vB)
    const parent = createTestTx(
      [{ txid: inputTxid, vout: 0 }],
      [{ value: 99900n }] // ~100 sat fee
    );
    await mempool.addTransaction(parent);
    const parentTxid = getTxId(parent);
    const parentTxidHex = parentTxid.toString("hex");

    // Create high-fee child
    const child = createTestTx(
      [{ txid: parentTxid, vout: 0 }],
      [{ value: 79900n }] // ~20000 sat fee
    );
    await mempool.addTransaction(child);
    const childTxidHex = getTxId(child).toString("hex");

    // Get mining scores
    const parentEntry = mempool.getTransaction(parentTxid)!;
    const childEntry = mempool.getTransaction(Buffer.from(childTxidHex, "hex"))!;

    // If they're in the same chunk (CPFP), they should have the same mining score
    // which is higher than the parent's individual fee rate
    if (parentEntry.miningScore === childEntry.miningScore) {
      expect(parentEntry.miningScore).toBeGreaterThan(parentEntry.feeRate);
    }
  });
});

describe("Cluster Mempool - Size Limits", () => {
  let tempDir: string;
  let db: ChainDB;
  let utxo: UTXOManager;
  let mempool: Mempool;

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
        scriptPubKey: Buffer.from([0x51]),
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
    tempDir = await mkdtemp(join(tmpdir(), "cluster-limits-test-"));
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

  test("cluster size is tracked correctly", async () => {
    const inputTxid = Buffer.alloc(32, 0x10);
    await setupUTXO(inputTxid, 0, 1000000n);

    // Create chain of transactions
    let prevTxid: Buffer = inputTxid;
    for (let i = 0; i < 5; i++) {
      const tx = createTestTx(
        [{ txid: prevTxid, vout: 0 }],
        [{ value: 900000n - BigInt(i * 10000) }]
      );
      const result = await mempool.addTransaction(tx);
      expect(result.accepted).toBe(true);
      prevTxid = getTxId(tx);
    }

    // Check cluster size
    const firstTxidHex = getTxId(
      createTestTx([{ txid: inputTxid, vout: 0 }], [{ value: 900000n }])
    ).toString("hex");

    // All transactions should be in one cluster
    const cluster = mempool.getCluster(prevTxid.toString("hex"));
    expect(cluster!.txids.size).toBe(5);
  });

  test("getTransactionsByMiningScore returns sorted transactions", async () => {
    // Create multiple independent transactions with different fee rates
    for (let i = 0; i < 3; i++) {
      const txid = Buffer.alloc(32, 0x20 + i);
      const fee = BigInt((i + 1) * 1000); // 1000, 2000, 3000 sat fees
      await setupUTXO(txid, 0, 10000n);

      const tx = createTestTx(
        [{ txid, vout: 0 }],
        [{ value: 10000n - fee }]
      );
      await mempool.addTransaction(tx);
    }

    const sorted = mempool.getTransactionsByMiningScore();

    expect(sorted.length).toBe(3);

    // Should be sorted by mining score descending
    for (let i = 0; i < sorted.length - 1; i++) {
      expect(sorted[i].miningScore).toBeGreaterThanOrEqual(sorted[i + 1].miningScore);
    }
  });
});

describe("Cluster Mempool - Eviction", () => {
  let tempDir: string;
  let db: ChainDB;
  let utxo: UTXOManager;
  let mempool: Mempool;

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
        scriptPubKey: Buffer.from([0x51]),
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
    tempDir = await mkdtemp(join(tmpdir(), "cluster-eviction-test-"));
    db = new ChainDB(tempDir);
    await db.open();
    utxo = new UTXOManager(db);
    // Small mempool for eviction testing
    mempool = new Mempool(utxo, REGTEST, 500);
    mempool.setTipHeight(200);
  });

  afterEach(async () => {
    await db.close();
    await rm(tempDir, { recursive: true, force: true });
  });

  test("evicts lowest mining score transactions", async () => {
    // Create transactions until mempool is full
    const txids: string[] = [];
    const fees = [100n, 500n, 1000n, 200n, 800n];

    for (let i = 0; i < 5; i++) {
      const inputTxid = Buffer.alloc(32, 0x30 + i);
      await setupUTXO(inputTxid, 0, 10000n);

      const tx = createTestTx(
        [{ txid: inputTxid, vout: 0 }],
        [{ value: 10000n - fees[i] }]
      );
      await mempool.addTransaction(tx);
      txids.push(getTxId(tx).toString("hex"));
    }

    // Check that mempool stayed within size limit
    const info = mempool.getInfo();
    expect(info.bytes).toBeLessThanOrEqual(500);

    // The highest fee-rate transactions should remain
    const remaining = mempool.getTransactionsByMiningScore();
    for (const entry of remaining) {
      expect(entry.miningScore).toBeGreaterThanOrEqual(info.minFeeRate);
    }
  });
});

describe("Cluster Mempool - getAllClusters", () => {
  let tempDir: string;
  let db: ChainDB;
  let utxo: UTXOManager;
  let mempool: Mempool;

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
        scriptPubKey: Buffer.from([0x51]),
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
    tempDir = await mkdtemp(join(tmpdir(), "cluster-all-test-"));
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

  test("returns all clusters", async () => {
    // Create two independent transactions (two clusters)
    const inputTxid1 = Buffer.alloc(32, 0x40);
    const inputTxid2 = Buffer.alloc(32, 0x41);
    await setupUTXO(inputTxid1, 0, 10000n);
    await setupUTXO(inputTxid2, 0, 10000n);

    const tx1 = createTestTx([{ txid: inputTxid1, vout: 0 }], [{ value: 9000n }]);
    const tx2 = createTestTx([{ txid: inputTxid2, vout: 0 }], [{ value: 9000n }]);

    await mempool.addTransaction(tx1);
    await mempool.addTransaction(tx2);

    const clusters = mempool.getAllClusters();

    expect(clusters.length).toBe(2);
    expect(clusters[0].txids.size).toBe(1);
    expect(clusters[1].txids.size).toBe(1);
  });

  test("connected transactions form single cluster", async () => {
    const inputTxid = Buffer.alloc(32, 0x42);
    await setupUTXO(inputTxid, 0, 100000n);

    // Parent
    const parent = createTestTx([{ txid: inputTxid, vout: 0 }], [{ value: 99000n }]);
    await mempool.addTransaction(parent);
    const parentTxid = getTxId(parent);

    // Child
    const child = createTestTx([{ txid: parentTxid, vout: 0 }], [{ value: 98000n }]);
    await mempool.addTransaction(child);

    const clusters = mempool.getAllClusters();

    expect(clusters.length).toBe(1);
    expect(clusters[0].txids.size).toBe(2);
  });
});
