/**
 * Core 31 entryToJSON (rpc/mempool.cpp) emits `chunkweight` and `fees.chunk`
 * for every mempool entry: the size and (modified) fee of the entry's main
 * chunk in the cluster linearization. A CPFP child pays for its parent, so
 * both txs share one chunk.
 */
import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ChainDB, UTXOEntry } from "../storage/database.js";
import { UTXOManager } from "../chain/utxo.js";
import { REGTEST } from "../consensus/params.js";
import { Mempool } from "../mempool/mempool.js";
import { dumpMempool, loadMempool } from "../mempool/persist.js";
import { RPCServer, RPCServerConfig, RPCServerDeps } from "../rpc/server.js";
import { getTxId } from "../validation/tx.js";
import type { Transaction } from "../validation/tx.js";

// Unique per-run port base so parallel test files don't collide.
let portCounter = 19743;
function getTestPort(): number {
  return portCounter++;
}

// P2A "anchor" output (OP_1 <0x4e73>): standard, spendable with empty
// scriptSig + empty witness, so test chains need no real signatures.
const P2A_SPK = Buffer.from([0x51, 0x02, 0x4e, 0x73]);
// Bare OP_RETURN padding so the non-witness tx clears MIN_STANDARD_TX size.
const OPRETURN_SPK = Buffer.from([0x6a]);

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
      ...outputs.map((out) => ({ value: out.value, scriptPubKey: P2A_SPK })),
      { value: 0n, scriptPubKey: OPRETURN_SPK },
    ],
    lockTime: 0,
  };
}

/** Display-order (big-endian) hex of an internal-order txid buffer. */
function displayTxid(txidInternal: Buffer): string {
  return Buffer.from(txidInternal).reverse().toString("hex");
}

describe("mempool entry cluster fields (chunkweight, fees.chunk)", () => {
  let tempDir: string;
  let db: ChainDB;
  let utxo: UTXOManager;
  let mempool: Mempool;
  let server: RPCServer;
  let port: number;
  let baseUrl: string;

  async function rpc(method: string, params: unknown[] = []): Promise<any> {
    const res = await fetch(baseUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
    });
    return res.json();
  }

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "chunk-fields-test-"));
    db = new ChainDB(tempDir);
    await db.open();
    utxo = new UTXOManager(db);
    mempool = new Mempool(utxo, REGTEST, 1_000_000);
    mempool.setTipHeight(200); // past coinbase maturity

    port = getTestPort();
    const config: RPCServerConfig = { port, host: "127.0.0.1", noAuth: true };
    // Only `mempool` is exercised by the handlers under test; the rest are
    // never touched, so minimal stubs are sufficient to construct + start.
    const deps: RPCServerDeps = {
      chainState: {} as any,
      mempool: mempool as any,
      peerManager: {} as any,
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

  // Helper: put a spendable confirmed P2A UTXO, then build + accept a child tx.
  async function submitTx(
    inputSeed: number,
    inAmount: bigint,
    outAmount: bigint
  ): Promise<{ txidInternal: Buffer; internalHex: string; displayHex: string; fee: bigint }> {
    const inputTxid = Buffer.alloc(32, inputSeed);
    const entry: UTXOEntry = {
      height: 1,
      coinbase: false,
      amount: inAmount,
      scriptPubKey: P2A_SPK,
    };
    await db.putUTXO(inputTxid, 0, entry);

    const tx = createTestTx([{ txid: inputTxid, vout: 0 }], [{ value: outAmount }]);
    const result = await mempool.addTransaction(tx);
    expect(result.accepted).toBe(true);

    const txidInternal = getTxId(tx);
    return {
      txidInternal,
      internalHex: txidInternal.toString("hex"),
      displayHex: displayTxid(txidInternal),
      fee: inAmount - outAmount,
    };
  }

  test("getrawmempool(true) and getmempoolentry carry chunkweight and fees.chunk", async () => {
    // Parent: zero-ish fee. Child: pays enough that the pair forms one chunk.
    const inputTxid = Buffer.alloc(32, 0xcc);
    await db.putUTXO(inputTxid, 0, { height: 1, coinbase: false, amount: 100_000n, scriptPubKey: P2A_SPK });
    const parent = createTestTx([{ txid: inputTxid, vout: 0 }], [{ value: 99_000n }]); // fee 1000
    expect((await mempool.addTransaction(parent)).accepted).toBe(true);
    const parentId = getTxId(parent);
    const child = createTestTx([{ txid: parentId, vout: 0 }], [{ value: 80_000n }]); // fee 19000
    expect((await mempool.addTransaction(child)).accepted).toBe(true);
    const childId = getTxId(child);

    const pe = mempool.getTransaction(parentId)!;
    const ce = mempool.getTransaction(childId)!;
    const chunkVsize = pe.vsize + ce.vsize;
    const chunkFee = (pe.fee + ce.fee);

    const raw = (await rpc("getrawmempool", [true])).result;
    for (const id of [parentId, childId]) {
      const e = raw[displayTxid(id)];
      expect(e.chunkweight).toBe(chunkVsize);
      expect(e.fees.chunk).toBeCloseTo(Number(chunkFee) / 1e8, 12);
    }
    for (const id of [parentId, childId]) {
      const e = (await rpc("getmempoolentry", [displayTxid(id)])).result;
      expect(e.chunkweight).toBe(chunkVsize);
      expect(e.fees.chunk).toBeCloseTo(Number(chunkFee) / 1e8, 12);
    }
  });
});
