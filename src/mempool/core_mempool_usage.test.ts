/**
 * getmempoolinfo "usage" and the -maxmempool trim follow Core's
 * CTxMemPool::DynamicMemoryUsage() (txmempool.cpp:778).
 *
 * Every expected number below was measured on Bitcoin Core 31.1 regtest with
 * the same transaction shapes (P2WSH(OP_DROP OP_DROP OP_TRUE) spends whose
 * witness is two 80-byte items and the 3-byte script), each case on a freshly
 * started bitcoind so its pool starts empty like a new Mempool. Probe and
 * output: hashhog staged-patches/hotbuns-core-mempool-usage/.
 *
 * Core regtest rows this covers: warden_invalidated_submit usage-* and the
 * pressure / pressure-decay contents, where hotbuns' old JS-heap estimate
 * (about 2x Core's figure) trimmed the 5 MB pool to 6 of the 800-input
 * transactions while Core keeps 12.
 */

import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { createHash } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ChainDB } from "../storage/database.js";
import { UTXOManager } from "../chain/utxo.js";
import { REGTEST } from "../consensus/params.js";
import { Mempool } from "./mempool.js";
import type { Transaction } from "../validation/tx.js";
import { getTxId } from "../validation/tx.js";
import type { Block } from "../validation/block.js";

const DROP_SCRIPT = Buffer.from("755175", "hex"); // OP_DROP OP_DROP OP_TRUE
const DROP_P2WSH = Buffer.concat([
  Buffer.from([0x00, 0x20]),
  createHash("sha256").update(DROP_SCRIPT).digest(),
]);
const HEAVY_SCRIPT = Buffer.concat([Buffer.from([0x00, 0x14]), Buffer.alloc(20, 0x11)]);
const V = 100_000_000n;

function dropSpend(
  outpoints: Array<{ txid: Buffer; vout: number }>,
  outputs: Array<{ value: bigint; scriptPubKey: Buffer }>
): Transaction {
  return {
    version: 2,
    inputs: outpoints.map((prevOut) => ({
      prevOut,
      scriptSig: Buffer.alloc(0),
      sequence: 0xfffffffd,
      witness: [Buffer.alloc(80, 0x11), Buffer.alloc(80, 0x22), DROP_SCRIPT],
    })),
    outputs,
    lockTime: 0,
  };
}

describe("mempool usage matches Core 31.1 DynamicMemoryUsage", () => {
  let tempDir: string;
  let db: ChainDB;
  let mempool: Mempool;
  let nextFund = 1;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "hotbuns-core-usage-"));
    db = new ChainDB(tempDir);
    await db.open();
    mempool = new Mempool(new UTXOManager(db), REGTEST);
    mempool.setTipHeight(200);
  });

  afterEach(async () => {
    await db.close();
    await rm(tempDir, { recursive: true, force: true });
  });

  /** A confirmed DROP_P2WSH output worth V. */
  async function fund(): Promise<{ txid: Buffer; vout: number }> {
    const txid = Buffer.alloc(32);
    txid.writeUInt32LE(nextFund++, 0);
    txid[31] = 0x5c;
    await db.putUTXO(txid, 0, { height: 1, coinbase: false, amount: V, scriptPubKey: DROP_P2WSH });
    return { txid, vout: 0 };
  }

  async function accept(tx: Transaction): Promise<Buffer> {
    const result = await mempool.addTransaction(tx);
    expect(result.error ?? "accepted").toBe("accepted");
    return getTxId(tx);
  }

  function mine(txs: Transaction[]): void {
    const block = { header: {}, transactions: txs } as unknown as Block;
    mempool.removeForBlock(block);
  }

  test("lone 1-in/1-out P2WSH spend: usage 1272, emptied pool 64", async () => {
    const tx = dropSpend([await fund()], [{ value: V - 10_000n, scriptPubKey: HEAVY_SCRIPT }]);
    await accept(tx);
    expect(mempool.getInfo().usage).toBe(1272);
    mine([tx]);
    expect(mempool.getInfo().size).toBe(0);
    // Core's txns_randomized keeps its capacity when cleared.
    expect(mempool.getInfo().usage).toBe(64);
  });

  test("2-in/2-out spend: usage 1816", async () => {
    const tx = dropSpend(
      [await fund(), await fund()],
      [
        { value: V - 10_000n, scriptPubKey: HEAVY_SCRIPT },
        { value: V, scriptPubKey: DROP_P2WSH },
      ]
    );
    await accept(tx);
    expect(mempool.getInfo().usage).toBe(1816);
  });

  test("three singletons: usage 3800, emptied pool 64", async () => {
    const txs: Transaction[] = [];
    for (let i = 0; i < 3; i++) {
      const tx = dropSpend([await fund()], [
        { value: V - 10_000n - BigInt(i) * 1_000n, scriptPubKey: HEAVY_SCRIPT },
      ]);
      await accept(tx);
      txs.push(tx);
    }
    expect(mempool.getInfo().usage).toBe(3800);
    mine(txs);
    expect(mempool.getInfo().usage).toBe(64);
  });

  async function pair(parentFee: bigint, childFee: bigint): Promise<Transaction[]> {
    const parent = dropSpend([await fund()], [{ value: V - parentFee, scriptPubKey: DROP_P2WSH }]);
    const ptxid = await accept(parent);
    const child = dropSpend([{ txid: ptxid, vout: 0 }], [
      { value: V - parentFee - childFee, scriptPubKey: HEAVY_SCRIPT },
    ]);
    await accept(child);
    return [parent, child];
  }

  test("CPFP pair, one chunk: usage 2584, emptied pool 96", async () => {
    const txs = await pair(1_000n, 50_000n);
    expect(mempool.getInfo().usage).toBe(2584);
    mine(txs);
    expect(mempool.getInfo().usage).toBe(96);
  });

  test("pair whose child pays less, two chunks: usage 2648", async () => {
    await pair(50_000n, 1_000n);
    expect(mempool.getInfo().usage).toBe(2648);
  });

  test("3-transaction chain: usage 3768", async () => {
    const t1 = dropSpend([await fund()], [{ value: V - 2_000n, scriptPubKey: DROP_P2WSH }]);
    const id1 = await accept(t1);
    const t2 = dropSpend([{ txid: id1, vout: 0 }], [{ value: V - 4_000n, scriptPubKey: DROP_P2WSH }]);
    const id2 = await accept(t2);
    const t3 = dropSpend([{ txid: id2, vout: 0 }], [{ value: V - 6_000n, scriptPubKey: HEAVY_SCRIPT }]);
    await accept(t3);
    expect(mempool.getInfo().usage).toBe(3768);
  });

  test("-maxmempool at Core's usage of three singletons keeps all three", async () => {
    // Core trims only while DynamicMemoryUsage() > the limit (TrimToSize);
    // 3800 is exactly Core's usage for these three, so nothing is evicted.
    mempool = new Mempool(new UTXOManager(db), REGTEST, 3800);
    mempool.setTipHeight(200);
    for (let i = 0; i < 3; i++) {
      await accept(
        dropSpend([await fund()], [{ value: V - 10_000n - BigInt(i) * 1_000n, scriptPubKey: HEAVY_SCRIPT }])
      );
    }
    expect(mempool.getInfo().size).toBe(3);
    expect(mempool.getInfo().usage).toBe(3800);
  });

  test("-maxmempool one byte under Core's usage of three singletons evicts the lowest feerate", async () => {
    mempool = new Mempool(new UTXOManager(db), REGTEST, 3799);
    mempool.setTipHeight(200);
    const ids: string[] = [];
    for (let i = 0; i < 3; i++) {
      const tx = dropSpend([await fund()], [{ value: V - 10_000n - BigInt(i) * 1_000n, scriptPubKey: HEAVY_SCRIPT }]);
      const result = await mempool.addTransaction(tx);
      ids.push(getTxId(tx).toString("hex"));
      if (i < 2) expect(result.error ?? "accepted").toBe("accepted");
    }
    expect(mempool.getInfo().size).toBe(2);
    // The first transaction pays the least (10,000 sat); it is the one evicted.
    expect(mempool.hasTransaction(Buffer.from(ids[0], "hex"))).toBe(false);
  });
});
