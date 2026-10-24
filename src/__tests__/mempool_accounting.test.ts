/**
 * Core 31 entryToJSON (rpc/mempool.cpp) accounting for a mempool entry:
 *
 *  - ancestor/descendant count, size and fees come from the full transitive
 *    ancestor/descendant set including the entry itself
 *    (CTxMemPool::CalculateAncestorData / CalculateDescendantData), and the
 *    fees are MODIFIED fees (GetModifiedFee, so prioritisetransaction counts);
 *  - depends lists the in-mempool parents' txids in display hex, sorted as
 *    strings (std::set<std::string>);
 *  - spentby lists the children's txids in display hex, sorted by the txid's
 *    internal byte order (GetChildren -> CompareIteratorByHash);
 *  - bip125-replaceable is the BIP-125 opt-in signal of the tx or an
 *    ancestor (IsRBFOptIn), not "replaceable under full RBF".
 */
import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ChainDB } from "../storage/database.js";
import { UTXOManager } from "../chain/utxo.js";
import { REGTEST } from "../consensus/params.js";
import { Mempool } from "../mempool/mempool.js";
import { RPCServer, RPCServerConfig, RPCServerDeps } from "../rpc/server.js";
import { getTxId } from "../validation/tx.js";
import type { Transaction } from "../validation/tx.js";

// Unique per-run port base so parallel test files don't collide.
let portCounter = 19843;
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
  outputs: Array<{ value: bigint }>,
  sequence = 0xffffffff
): Transaction {
  return {
    version: 2,
    inputs: inputs.map((inp) => ({
      prevOut: { txid: inp.txid, vout: inp.vout },
      scriptSig: Buffer.alloc(0),
      sequence,
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

const btc = (sats: bigint): number => Number(sats) / 100_000_000;

describe("mempool entry accounting (Core entryToJSON)", () => {
  let tempDir: string;
  let db: ChainDB;
  let mempool: Mempool;
  let server: RPCServer;
  let baseUrl: string;
  let seed = 0x10;

  async function rpc(method: string, params: unknown[] = []): Promise<any> {
    const res = await fetch(baseUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
    });
    const body = await res.json();
    expect(body.error ?? null).toBeNull();
    return body.result;
  }

  /** Both RPC views of one entry, so every assertion covers both paths. */
  async function views(txid: Buffer): Promise<any[]> {
    const display = displayTxid(txid);
    const pool = await rpc("getrawmempool", [true]);
    const entry = await rpc("getmempoolentry", [display]);
    expect(pool[display]).toBeDefined();
    return [pool[display], entry];
  }

  async function confirmedOutput(amount: bigint): Promise<Buffer> {
    const txid = Buffer.alloc(32, seed++);
    await db.putUTXO(txid, 0, { height: 1, coinbase: false, amount, scriptPubKey: P2A_SPK });
    return txid;
  }

  async function accept(tx: Transaction): Promise<Buffer> {
    const result = await mempool.addTransaction(tx);
    expect(result.error ?? null).toBeNull();
    expect(result.accepted).toBe(true);
    return getTxId(tx);
  }

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "mempool-accounting-test-"));
    db = new ChainDB(tempDir);
    await db.open();
    const utxo = new UTXOManager(db);
    mempool = new Mempool(utxo, REGTEST, 1_000_000);
    mempool.setTipHeight(200); // past coinbase maturity

    const port = getTestPort();
    const config: RPCServerConfig = { port, host: "127.0.0.1", noAuth: true };
    // Only `mempool` is exercised by the handlers under test.
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

  test("CPFP pair: parent descendant and child ancestor totals include both txs", async () => {
    // Parent pays 1000 sat, child pays 19000 sat for both (the core-regtest
    // mempool/entry rows: descendantsize 85 vs 170, fees.descendant).
    const input = await confirmedOutput(100_000n);
    const parentTx = createTestTx([{ txid: input, vout: 0 }], [{ value: 99_000n }]);
    const parent = await accept(parentTx);
    const childTx = createTestTx([{ txid: parent, vout: 0 }], [{ value: 80_000n }]);
    const child = await accept(childTx);

    const pv = mempool.getTransaction(parent)!.vsize;
    const cv = mempool.getTransaction(child)!.vsize;

    for (const p of await views(parent)) {
      expect(p.ancestorcount).toBe(1);
      expect(p.ancestorsize).toBe(pv);
      expect(p.fees.ancestor).toBe(btc(1_000n));
      expect(p.descendantcount).toBe(2);
      expect(p.descendantsize).toBe(pv + cv);
      expect(p.fees.descendant).toBe(btc(20_000n));
      expect(p.depends).toEqual([]);
      expect(p.spentby).toEqual([displayTxid(child)]);
    }
    for (const c of await views(child)) {
      expect(c.ancestorcount).toBe(2);
      expect(c.ancestorsize).toBe(pv + cv);
      expect(c.fees.ancestor).toBe(btc(20_000n));
      expect(c.descendantcount).toBe(1);
      expect(c.descendantsize).toBe(cv);
      expect(c.fees.descendant).toBe(btc(19_000n));
      expect(c.depends).toEqual([displayTxid(parent)]);
      expect(c.spentby).toEqual([]);
    }
  });

  test("ancestor/descendant counts are transitive (grandparent chain)", async () => {
    const input = await confirmedOutput(100_000n);
    const a = await accept(createTestTx([{ txid: input, vout: 0 }], [{ value: 99_000n }]));
    const b = await accept(createTestTx([{ txid: a, vout: 0 }], [{ value: 98_000n }]));
    const c = await accept(createTestTx([{ txid: b, vout: 0 }], [{ value: 97_000n }]));

    const va = mempool.getTransaction(a)!.vsize;
    const vb = mempool.getTransaction(b)!.vsize;
    const vc = mempool.getTransaction(c)!.vsize;

    for (const e of await views(a)) {
      expect(e.descendantcount).toBe(3);
      expect(e.descendantsize).toBe(va + vb + vc);
      expect(e.fees.descendant).toBe(btc(3_000n));
    }
    for (const e of await views(c)) {
      expect(e.ancestorcount).toBe(3);
      expect(e.ancestorsize).toBe(va + vb + vc);
      expect(e.fees.ancestor).toBe(btc(3_000n));
      expect(e.depends).toEqual([displayTxid(b)]);
    }
  });

  test("ancestor/descendant fees are modified fees (prioritisetransaction)", async () => {
    const input = await confirmedOutput(100_000n);
    const parent = await accept(createTestTx([{ txid: input, vout: 0 }], [{ value: 99_000n }]));
    const child = await accept(createTestTx([{ txid: parent, vout: 0 }], [{ value: 98_000n }]));
    await rpc("prioritisetransaction", [displayTxid(parent), 0, 5_000]);

    for (const p of await views(parent)) {
      expect(p.fees.base).toBe(btc(1_000n));
      expect(p.fees.modified).toBe(btc(6_000n));
      expect(p.fees.ancestor).toBe(btc(6_000n));
      expect(p.fees.descendant).toBe(btc(7_000n));
    }
    for (const c of await views(child)) {
      expect(c.fees.ancestor).toBe(btc(7_000n));
      expect(c.fees.descendant).toBe(btc(1_000n));
    }
  });

  test("depends sorted by display hex, spentby by internal txid bytes", async () => {
    // Two parents feeding one child, and two children of one parent.
    const in1 = await confirmedOutput(100_000n);
    const in2 = await confirmedOutput(100_000n);
    const p1 = await accept(createTestTx([{ txid: in1, vout: 0 }], [{ value: 49_000n }, { value: 50_000n }]));
    const p2 = await accept(createTestTx([{ txid: in2, vout: 0 }], [{ value: 99_000n }]));
    const join2 = await accept(
      createTestTx([{ txid: p1, vout: 0 }, { txid: p2, vout: 0 }], [{ value: 140_000n }])
    );
    const sibling = await accept(createTestTx([{ txid: p1, vout: 1 }], [{ value: 49_000n }]));

    const expectedDepends = [displayTxid(p1), displayTxid(p2)].sort();
    const expectedSpentby = [join2, sibling]
      .sort((x, y) => Buffer.compare(x, y))
      .map(displayTxid);

    for (const e of await views(join2)) {
      expect(e.depends).toEqual(expectedDepends);
      expect(e.ancestorcount).toBe(3);
    }
    for (const e of await views(p1)) {
      expect(e.spentby).toEqual(expectedSpentby);
      expect(e.descendantcount).toBe(3);
    }
  });

  test("bip125-replaceable reports the BIP-125 signal, not full-RBF replaceability", async () => {
    const in1 = await confirmedOutput(100_000n);
    const in2 = await confirmedOutput(100_000n);
    const final = await accept(createTestTx([{ txid: in1, vout: 0 }], [{ value: 99_000n }]));
    const signalling = await accept(
      createTestTx([{ txid: in2, vout: 0 }], [{ value: 99_000n }], 0xfffffffd)
    );
    // A non-signalling child inherits the signal from its ancestor.
    const inherits = await accept(createTestTx([{ txid: signalling, vout: 0 }], [{ value: 98_000n }]));

    for (const e of await views(final)) expect(e["bip125-replaceable"]).toBe(false);
    for (const e of await views(signalling)) expect(e["bip125-replaceable"]).toBe(true);
    for (const e of await views(inherits)) expect(e["bip125-replaceable"]).toBe(true);
  });
});
