/**
 * Core v31 cluster-mempool replacement rules (tools/core-regtest `rbf` group).
 *
 * bitcoin-core/src/validation.cpp MemPoolAccept::ReplacementChecks runs, in
 * order:
 *   1. GetEntriesForConflicts (policy/rbf.cpp): Rule 5 counts the distinct
 *      clusters the replacement conflicts with DIRECTLY
 *      (GetUniqueClusterCount > MAX_REPLACEMENT_CANDIDATES), not the number of
 *      evicted transactions. Reject "too many potential replacements".
 *   2. PaysForRBF: Rules 3 and 4 over every evicted transaction.
 *   3. StageRemoval + CheckMemPoolPolicyLimits: "too-large-cluster".
 *   4. ImprovesFeerateDiagram: "replacement-failed" with debug
 *      "insufficient feerate: does not improve feerate diagram".
 *
 * hotbuns used to count evictions (five clusters of 21 = 105 > 100, refused)
 * and ran the cluster limit after the diagram.
 */

import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ChainDB, UTXOEntry } from "../storage/database.js";
import { UTXOManager } from "../chain/utxo.js";
import { REGTEST } from "../consensus/params.js";
import { Mempool } from "../mempool/mempool.js";
import { RPCServer, RPCServerConfig, RPCServerDeps, RPCErrorCodes } from "../rpc/server.js";
import type { Transaction } from "../validation/tx.js";
import { getTxId, serializeTx } from "../validation/tx.js";

const RBF_SEQUENCE = 0xfffffffd;
const P2A = Buffer.from([0x51, 0x02, 0x4e, 0x73]);
const DIAGRAM_DETAIL = "insufficient feerate: does not improve feerate diagram";

function makeTx(
  inputs: Array<{ txid: Buffer; vout: number }>,
  outputs: bigint[],
): Transaction {
  return {
    version: 2,
    inputs: inputs.map((inp) => ({
      prevOut: { txid: inp.txid, vout: inp.vout },
      scriptSig: Buffer.alloc(0),
      sequence: RBF_SEQUENCE,
      witness: [],
    })),
    outputs: [
      ...outputs.map((value) => ({ value, scriptPubKey: P2A })),
      { value: 0n, scriptPubKey: Buffer.from([0x6a]) }, // OP_RETURN padding (>= 65 bytes)
    ],
    lockTime: 0,
  };
}

/** A confirmed coin with a txid unique to (tag, index). */
function coinId(tag: number, index: number): Buffer {
  const b = Buffer.alloc(32, tag);
  b.writeUInt32LE(index, 0);
  return b;
}

const display = (b: Buffer) => Buffer.from(b).reverse().toString("hex");

describe("Core v31 cluster RBF (ReplacementChecks)", () => {
  let tempDir: string;
  let db: ChainDB;
  let mempool: Mempool;

  async function confirmedCoin(txid: Buffer, amount: bigint): Promise<void> {
    const entry: UTXOEntry = { height: 1, coinbase: false, amount, scriptPubKey: P2A };
    await db.putUTXO(txid, 0, entry);
  }

  async function mustAccept(tx: Transaction): Promise<void> {
    const r = await mempool.addTransaction(tx);
    if (!r.accepted) throw new Error(`setup tx refused: ${r.error}`);
  }

  /** `count` independent one-tx clusters, each spending its own confirmed coin. */
  async function singleTxClusters(count: number, coinValue: bigint, fee: bigint): Promise<Buffer[]> {
    const coins: Buffer[] = [];
    for (let i = 0; i < count; i++) {
      const coin = coinId(0x40, i);
      await confirmedCoin(coin, coinValue);
      await mustAccept(makeTx([{ txid: coin, vout: 0 }], [coinValue - fee]));
      coins.push(coin);
    }
    return coins;
  }

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "cluster-rbf-test-"));
    db = new ChainDB(tempDir);
    await db.open();
    mempool = new Mempool(new UTXOManager(db), REGTEST, 1_000_000_000);
    mempool.setTipHeight(200);
  });

  afterEach(async () => {
    await db.close();
    await rm(tempDir, { recursive: true, force: true });
  });

  test("five conflicting clusters of 21 (105 evictions) is five candidates and is accepted", async () => {
    // The core-regtest rbf/clusters scenario: Core v31.1 accepts this.
    const coinValue = 50_000_000n;
    const coins: Buffer[] = [];
    for (let c = 0; c < 5; c++) {
      const coin = coinId(0x50, c);
      await confirmedCoin(coin, coinValue);
      coins.push(coin);
      const each = (coinValue - 1_000n) / 20n;
      const root = makeTx([{ txid: coin, vout: 0 }], Array(20).fill(each));
      await mustAccept(root);
      for (let i = 0; i < 20; i++) {
        await mustAccept(makeTx([{ txid: getTxId(root), vout: i }], [each - 1_000n]));
      }
    }
    expect(mempool.getSize()).toBe(105);

    const sweep = makeTx(
      coins.map((txid) => ({ txid, vout: 0 })),
      [coinValue * 5n - 200_000n],
    );
    const tested = await mempool.addTransaction(sweep, { testAccept: true });
    expect(tested.error).toBeUndefined();
    expect(tested.accepted).toBe(true);
    expect(mempool.getSize()).toBe(105);

    const submitted = await mempool.addTransaction(sweep);
    expect(submitted.accepted).toBe(true);
    expect(mempool.getSize()).toBe(1);
    expect(mempool.hasTransaction(getTxId(sweep))).toBe(true);
  });

  test("test-accepting a replacement leaves the replaced transaction in the pool", async () => {
    const coin = coinId(0x52, 0);
    await confirmedCoin(coin, 1_000_000n);
    const original = makeTx([{ txid: coin, vout: 0 }], [1_000_000n - 1_000n]);
    await mustAccept(original);
    const replacement = makeTx([{ txid: coin, vout: 0 }], [1_000_000n - 5_000n]);
    const r = await mempool.addTransaction(replacement, { testAccept: true });
    expect(r.accepted).toBe(true);
    expect(mempool.hasTransaction(getTxId(original))).toBe(true);
    expect(mempool.hasTransaction(getTxId(replacement))).toBe(false);
  });

  test("Rule 3 still sums the fees of every evicted transaction, not one per cluster", async () => {
    // Five clusters of 21 txs at 1,000 sat each = 105,000 sat evicted. A
    // replacement paying 100,000 covers five clusters' roots but not the
    // children: PaysForRBF refuses it.
    const coinValue = 50_000_000n;
    const coins: Buffer[] = [];
    for (let c = 0; c < 5; c++) {
      const coin = coinId(0x51, c);
      await confirmedCoin(coin, coinValue);
      coins.push(coin);
      const each = (coinValue - 1_000n) / 20n;
      const root = makeTx([{ txid: coin, vout: 0 }], Array(20).fill(each));
      await mustAccept(root);
      for (let i = 0; i < 20; i++) {
        await mustAccept(makeTx([{ txid: getTxId(root), vout: i }], [each - 1_000n]));
      }
    }
    const sweep = makeTx(coins.map((txid) => ({ txid, vout: 0 })), [coinValue * 5n - 100_000n]);
    const r = await mempool.addTransaction(sweep, { testAccept: true });
    expect(r.accepted).toBe(false);
    // PaysForRBF's text (Rule 3): 0.001 BTC against all 105 evicted txs' 0.00105.
    expect(r.error).toContain("less fees than conflicting txs; 0.001 < 0.00105");
    expect(mempool.getSize()).toBe(105);
  });

  test("101 directly conflicting clusters is refused as too many potential replacements", async () => {
    const coins = await singleTxClusters(101, 1_000_000n, 1_000n);
    const sweep = makeTx(coins.map((txid) => ({ txid, vout: 0 })), [101n * 1_000_000n - 500_000n]);
    const r = await mempool.addTransaction(sweep, { testAccept: true });
    expect(r.accepted).toBe(false);
    expect(r.rejectReason).toBe("too many potential replacements");
    expect(r.rejectDetails).toBe(
      `rejecting replacement ${display(getTxId(sweep))}; too many conflicting clusters (101 > 100)`,
    );
    expect(r.error).toBe(`too many potential replacements, ${r.rejectDetails}`);
  });

  test("exactly 100 directly conflicting clusters is accepted", async () => {
    const coins = await singleTxClusters(100, 1_000_000n, 1_000n);
    const sweep = makeTx(coins.map((txid) => ({ txid, vout: 0 })), [100n * 1_000_000n - 500_000n]);
    const r = await mempool.addTransaction(sweep);
    expect(r.error).toBeUndefined();
    expect(r.accepted).toBe(true);
    expect(mempool.getSize()).toBe(1);
  });

  test("a replacement that worsens the feerate diagram is replacement-failed", async () => {
    // The core-regtest rbf/diagram scenario: 1-in-1-out paying 5,000 replaced
    // by a 1-in-40-out paying 5,200. PaysForRBF passes, the diagram does not.
    const coin = coinId(0x60, 0);
    await confirmedCoin(coin, 50_000_000n);
    await mustAccept(makeTx([{ txid: coin, vout: 0 }], [50_000_000n - 5_000n]));
    const each = (50_000_000n - 5_200n) / 40n;
    const wide = makeTx([{ txid: coin, vout: 0 }], Array(40).fill(each));
    const r = await mempool.addTransaction(wide, { testAccept: true });
    expect(r.accepted).toBe(false);
    expect(r.rejectReason).toBe("replacement-failed");
    expect(r.rejectDetails).toBe(DIAGRAM_DETAIL);
    expect(r.error).toBe(`replacement-failed, ${DIAGRAM_DETAIL}`);
  });

  test("the staged cluster limit is checked before the diagram (too-large-cluster wins)", async () => {
    // A heavy parent P (~380k WU) with a small high-feerate child C. The
    // replacement R conflicts with C, is ~30k WU, and pays a feerate far below
    // C's: post-eviction {P, R} exceeds 404,000 WU AND the diagram is worse.
    // Core runs CheckMemPoolPolicyLimits first, so the answer is
    // too-large-cluster, not replacement-failed.
    const coin = coinId(0x70, 0);
    const outs = 7_200;
    const each = 1_000n;
    await confirmedCoin(coin, BigInt(outs) * each + 1_000_000n);
    const parent = makeTx([{ txid: coin, vout: 0 }], Array(outs).fill(each));
    await mustAccept(parent);
    const parentWeight = mempool.getTransaction(getTxId(parent))!.weight;
    expect(parentWeight).toBeGreaterThan(370_000);

    const child = makeTx([{ txid: getTxId(parent), vout: 0 }], [each - 500n]);
    await mustAccept(child);

    // ~600 outputs (~31k WU), funded by an extra confirmed coin so none is dust.
    const funding = coinId(0x71, 0);
    await confirmedCoin(funding, 10_000_000n);
    const rOuts = 600;
    const rEach = (10_000_000n + each - 2_000n) / BigInt(rOuts);
    const replacement = makeTx(
      [
        { txid: getTxId(parent), vout: 0 },
        { txid: funding, vout: 0 },
      ],
      Array(rOuts).fill(rEach),
    );
    const r = await mempool.addTransaction(replacement, { testAccept: true });
    expect(r.accepted).toBe(false);
    expect(r.error).toBe("too-large-cluster");
  });
});

describe("testmempoolaccept / sendrawtransaction report Core's replacement refusals", () => {
  // The RPC renders the mempool's refusal; the expected strings are what Core
  // v31.1 answered in tools/core-regtest rbf/diagram.
  const REFUSAL = {
    accepted: false,
    error: `replacement-failed, ${DIAGRAM_DETAIL}`,
    rejectReason: "replacement-failed",
    rejectDetails: DIAGRAM_DETAIL,
  };

  let server: RPCServer;
  let port = 19950;

  const tx = makeTx([{ txid: coinId(0x80, 0), vout: 0 }], [1_000n]);
  const hex = serializeTx(tx, true).toString("hex");

  beforeEach(() => {
    port++;
    const mempool = {
      hasTransaction: () => false,
      isTransactionConfirmed: async () => false,
      getTransaction: () => null,
      addTransaction: async () => REFUSAL,
    };
    const config: RPCServerConfig = { port, host: "127.0.0.1", noAuth: true };
    const deps: RPCServerDeps = {
      chainState: { getBestBlock: () => ({ hash: Buffer.alloc(32), height: 0 }) } as any,
      mempool: mempool as any,
      peerManager: { getConnectedPeers: () => [], broadcast() {}, listBanned: () => [] } as any,
      feeEstimator: { estimateSmartFee: (t: number) => ({ feeRate: 10, blocks: t }) } as any,
      headerSync: {} as any,
      db: { getTxIndex: async () => null } as any,
      params: REGTEST,
    };
    server = new RPCServer(config, deps);
    server.start();
  });

  afterEach(() => {
    server.stop();
  });

  async function rpc(method: string, params: unknown[]): Promise<any> {
    const res = await fetch(`http://127.0.0.1:${port}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
    });
    return res.json();
  }

  test("testmempoolaccept: reject-reason replacement-failed, reject-details is the ToString()", async () => {
    const res = await rpc("testmempoolaccept", [[hex]]);
    expect(res.error ?? null).toBeNull();
    expect(res.result[0].allowed).toBe(false);
    expect(res.result[0]["reject-reason"]).toBe("replacement-failed");
    expect(res.result[0]["reject-details"]).toBe(`replacement-failed, ${DIAGRAM_DETAIL}`);
  });

  test("sendrawtransaction: -26 with the ToString() message", async () => {
    const res = await rpc("sendrawtransaction", [hex]);
    expect(res.error.code).toBe(RPCErrorCodes.RPC_TRANSACTION_REJECTED);
    expect(res.error.message).toBe(`replacement-failed, ${DIAGRAM_DETAIL}`);
  });
});
