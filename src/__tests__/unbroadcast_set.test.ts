/**
 * Unbroadcast set: transactions submitted through sendrawtransaction stay
 * "unbroadcast" until a peer fetches them (getdata) or they leave the mempool.
 *
 * Reference: bitcoin-core/src/node/transaction.cpp BroadcastTransaction
 * (AddUnbroadcastTx), src/txmempool.cpp RemoveUnbroadcastTx (called from
 * removeUnchecked), src/net_processing.cpp ProcessGetData,
 * src/rpc/mempool.cpp (entryToJSON "unbroadcast", MempoolInfoToJSON
 * "unbroadcastcount").
 */

import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ChainDB, UTXOEntry } from "../storage/database.js";
import { UTXOManager } from "../chain/utxo.js";
import { REGTEST } from "../consensus/params.js";
import { Mempool } from "../mempool/mempool.js";
import { dumpMempool, loadMempool, importMempoolFile } from "../mempool/persist.js";
import { RPCServer, RPCServerConfig, RPCServerDeps } from "../rpc/server.js";
import { getTxId, serializeTx } from "../validation/tx.js";
import type { Transaction } from "../validation/tx.js";

let portCounter = 19743;
const P2A_SPK = Buffer.from([0x51, 0x02, 0x4e, 0x73]);
const OPRETURN_SPK = Buffer.from([0x6a]);

function makeTx(txid: Buffer, vout: number, value: bigint): Transaction {
  return {
    version: 2,
    inputs: [
      { prevOut: { txid, vout }, scriptSig: Buffer.alloc(0), sequence: 0xffffffff, witness: [] },
    ],
    outputs: [
      { value, scriptPubKey: P2A_SPK },
      { value: 0n, scriptPubKey: OPRETURN_SPK },
    ],
    lockTime: 0,
  };
}

describe("unbroadcast set", () => {
  let tempDir: string;
  let db: ChainDB;
  let mempool: Mempool;
  let server: RPCServer;
  let baseUrl: string;

  async function rpc(method: string, params: unknown[] = []): Promise<any> {
    const res = await fetch(baseUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
    });
    return res.json();
  }

  async function fund(seed: number): Promise<Buffer> {
    const inputTxid = Buffer.alloc(32, seed);
    const entry: UTXOEntry = { height: 1, coinbase: false, amount: 100_000n, scriptPubKey: P2A_SPK };
    await db.putUTXO(inputTxid, 0, entry);
    return inputTxid;
  }

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "unbroadcast-test-"));
    db = new ChainDB(tempDir);
    await db.open();
    mempool = new Mempool(new UTXOManager(db), REGTEST, 1_000_000);
    mempool.setTipHeight(200);
    const port = portCounter++;
    const config: RPCServerConfig = { port, host: "127.0.0.1", noAuth: true };
    const deps: RPCServerDeps = {
      chainState: {} as any,
      mempool: mempool as any,
      peerManager: { getConnectedPeers: () => [] } as any,
      feeEstimator: {} as any,
      headerSync: {} as any,
      db: db as any,
      params: REGTEST,
    };
    server = new RPCServer(config, deps);
    server.start();
    baseUrl = `http://127.0.0.1:${port}`;
  });

  afterEach(async () => {
    server.stop();
    await db.close();
    await rm(tempDir, { recursive: true, force: true });
  });

  test("sendrawtransaction marks the tx unbroadcast; direct mempool accept does not", async () => {
    const tx = makeTx(await fund(0xa1), 0, 90_000n);
    const hex = serializeTx(tx, true).toString("hex");
    const txid = getTxId(tx);
    const display = Buffer.from(txid).reverse().toString("hex");

    const sent = await rpc("sendrawtransaction", [hex]);
    expect(sent.result).toBe(display);

    const pool = (await rpc("getrawmempool", [true])).result;
    expect(pool[display].unbroadcast).toBe(true);
    expect((await rpc("getmempoolinfo")).result.unbroadcastcount).toBe(1);

    // A tx accepted from the network (not via RPC) is not unbroadcast.
    const p2p = makeTx(await fund(0xa2), 0, 90_000n);
    expect((await mempool.addTransaction(p2p)).accepted).toBe(true);
    const p2pDisplay = Buffer.from(getTxId(p2p)).reverse().toString("hex");
    const pool2 = (await rpc("getrawmempool", [true])).result;
    expect(pool2[p2pDisplay].unbroadcast).toBe(false);
    expect((await rpc("getmempoolinfo")).result.unbroadcastcount).toBe(1);
  });

  test("getmempoolentry reports unbroadcast", async () => {
    const tx = makeTx(await fund(0xa3), 0, 90_000n);
    await rpc("sendrawtransaction", [serializeTx(tx, true).toString("hex")]);
    const display = Buffer.from(getTxId(tx)).reverse().toString("hex");
    const entry = (await rpc("getmempoolentry", [display])).result;
    expect(entry.unbroadcast).toBe(true);
  });

  test("leaving the pool or an explicit remove clears unbroadcast", async () => {
    const a = makeTx(await fund(0xa4), 0, 90_000n);
    const b = makeTx(await fund(0xa5), 0, 90_000n);
    await rpc("sendrawtransaction", [serializeTx(a, true).toString("hex")]);
    await rpc("sendrawtransaction", [serializeTx(b, true).toString("hex")]);
    expect((await rpc("getmempoolinfo")).result.unbroadcastcount).toBe(2);

    mempool.removeTransaction(getTxId(a), true);
    expect((await rpc("getmempoolinfo")).result.unbroadcastcount).toBe(1);

    mempool.removeUnbroadcastTx(getTxId(b));
    expect((await rpc("getmempoolinfo")).result.unbroadcastcount).toBe(0);
  });

  test("unbroadcast set round-trips through mempool.dat (apply_unbroadcast_set)", async () => {
    const tx = makeTx(await fund(0xa6), 0, 90_000n);
    await rpc("sendrawtransaction", [serializeTx(tx, true).toString("hex")]);
    await dumpMempool(mempool, tempDir);

    const mempool2 = new Mempool(new UTXOManager(db), REGTEST, 1_000_000);
    mempool2.setTipHeight(200);
    // Startup load (Core LoadMempool at init) restores the set.
    const res = await loadMempool(mempool2, tempDir);
    expect(res.succeeded).toBe(1);
    expect(mempool2.isUnbroadcast(getTxId(tx))).toBe(true);

    // importmempool only restores it when apply_unbroadcast_set is true.
    const opts = { useCurrentTime: true, applyFeeDeltaPriority: false };
    const mempool3 = new Mempool(new UTXOManager(db), REGTEST, 1_000_000);
    mempool3.setTipHeight(200);
    await importMempoolFile(mempool3, join(tempDir, "mempool.dat"), { ...opts, applyUnbroadcastSet: false });
    expect(mempool3.isUnbroadcast(getTxId(tx))).toBe(false);
    const mempool4 = new Mempool(new UTXOManager(db), REGTEST, 1_000_000);
    mempool4.setTipHeight(200);
    await importMempoolFile(mempool4, join(tempDir, "mempool.dat"), { ...opts, applyUnbroadcastSet: true });
    expect(mempool4.isUnbroadcast(getTxId(tx))).toBe(true);
  });
});
