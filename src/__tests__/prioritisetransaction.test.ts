/**
 * Roundtrip tests for prioritisetransaction + getprioritisedtransactions.
 *
 * Drives the REAL RPC handlers (over HTTP, in-process, single node) against a
 * REAL Mempool so the byte-shape of the JSON response is verified end-to-end —
 * no Core oracle, no full fleet. Covers:
 *   - prioritisetransaction stacks deltas additively
 *   - getprioritisedtransactions returns the exact Core shape (txid-keyed
 *     object; fee_delta always present; in_mempool bool; modified_fee ONLY
 *     when in_mempool)
 *   - modified_fee = base fee + delta
 *   - a non-zero legacy `dummy` arg is rejected
 *   - a net delta of 0 erases the entry
 *   - a delta on a txid NOT in the mempool appears with in_mempool=false and
 *     NO modified_fee
 *   - deltas survive a mempool.dat persist/load roundtrip
 *
 * Reference: bitcoin-core/src/rpc/mining.cpp:502/547,
 *   src/txmempool.cpp:630 PrioritiseTransaction / :673 GetPrioritisedTransactions.
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
// Randomised per-process port band (mirrors the 26682fc watchonly
// fix): each test file draws from a distinct band plus a random
// offset. Every band must stay BELOW the Linux client ephemeral
// range (ip_local_port_range 32768-60999) — a band inside it can
// collide with a kernel-assigned fetch() client socket and fail
// EADDRINUSE (observed on CI: ports 39450, 59180).
let portCounter = 25000 + Math.floor(Math.random() * 1000);
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

describe("prioritisetransaction / getprioritisedtransactions", () => {
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
    tempDir = await mkdtemp(join(tmpdir(), "prioritise-test-"));
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

  test("full roundtrip: stack, shape, dummy-reject, erase, not-in-mempool", async () => {
    const { internalHex, displayHex, fee } = await submitTx(0xaa, 100_000n, 90_000n);
    expect(fee).toBe(10_000n);

    // (1) +1000 -> fee_delta=1000, in_mempool=true, modified_fee=base+1000.
    const r1 = await rpc("prioritisetransaction", [displayHex, 0, 1000]);
    expect(r1.error).toBeUndefined();
    expect(r1.result).toBe(true);

    let pri = (await rpc("getprioritisedtransactions")).result;
    expect(Object.keys(pri)).toEqual([displayHex]);
    expect(pri[displayHex].fee_delta).toBe(1000);
    expect(pri[displayHex].in_mempool).toBe(true);
    expect(pri[displayHex].modified_fee).toBe(Number(fee) + 1000);
    // modified_fee is the only optional key; fee_delta + in_mempool always present.
    expect(Object.keys(pri[displayHex]).sort()).toEqual(
      ["fee_delta", "in_mempool", "modified_fee"].sort()
    );

    // getmempoolentry reflects the modified fee too (base + delta). The RPC
    // takes the user-facing DISPLAY-order txid and reverses it internally via
    // parseHashV (Core parity — the pre-existing display-order inconsistency
    // noted here previously has been fixed), so we look up by displayHex.
    // This assertion targets the fees.modified wiring (getModifiedFee), not the byte
    // order of the lookup. Core entryToJSON (mempool.cpp) emits fees as a nested
    // object only — top-level modifiedfee was removed for Core parity.
    const me = (await rpc("getmempoolentry", [displayHex])).result;
    // fees.modified is the canonical field (Core entryToJSON); no top-level modifiedfee.
    expect(me.fees.modified).toBeCloseTo((Number(fee) + 1000) / 1e8, 12);

    // (2) +500 STACKS additively -> 1500.
    await rpc("prioritisetransaction", [displayHex, 0, 500]);
    pri = (await rpc("getprioritisedtransactions")).result;
    expect(pri[displayHex].fee_delta).toBe(1500);
    expect(pri[displayHex].modified_fee).toBe(Number(fee) + 1500);

    // (3) NON-ZERO dummy is rejected with an RPC error (Core: -8 invalid param).
    const bad = await rpc("prioritisetransaction", [displayHex, 1.5, 100]);
    expect(bad.result).toBeUndefined();
    expect(bad.error).toBeDefined();
    expect(bad.error.code).toBe(-8);
    // The rejected call must not have mutated the delta.
    pri = (await rpc("getprioritisedtransactions")).result;
    expect(pri[displayHex].fee_delta).toBe(1500);

    // (4) -1500 brings net delta to 0 -> entry ERASED.
    await rpc("prioritisetransaction", [displayHex, 0, -1500]);
    pri = (await rpc("getprioritisedtransactions")).result;
    expect(pri[displayHex]).toBeUndefined();
    expect(Object.keys(pri)).toEqual([]);

    // (5) delta on a txid NOT in the mempool: in_mempool=false, NO modified_fee.
    const ghostInternal = Buffer.alloc(32, 0x11);
    const ghostDisplay = displayTxid(ghostInternal);
    await rpc("prioritisetransaction", [ghostDisplay, 0, 7777]);
    pri = (await rpc("getprioritisedtransactions")).result;
    expect(pri[ghostDisplay].fee_delta).toBe(7777);
    expect(pri[ghostDisplay].in_mempool).toBe(false);
    expect("modified_fee" in pri[ghostDisplay]).toBe(false);
    expect(Object.keys(pri[ghostDisplay]).sort()).toEqual(
      ["fee_delta", "in_mempool"].sort()
    );
  });

  test("negative delta on in-mempool tx lowers modified_fee and round-trips a sign", async () => {
    const { displayHex, fee } = await submitTx(0xbb, 100_000n, 90_000n);
    await rpc("prioritisetransaction", [displayHex, null, -3000]);
    const pri = (await rpc("getprioritisedtransactions")).result;
    expect(pri[displayHex].fee_delta).toBe(-3000);
    expect(pri[displayHex].in_mempool).toBe(true);
    expect(pri[displayHex].modified_fee).toBe(Number(fee) - 3000);
  });

  test("EFFECT: prioritising a low-base-fee tx ranks it ahead of a higher-base-fee peer in the block template", async () => {
    // Two INDEPENDENT txs (no shared inputs, no parent/child link), so each is
    // its own single-tx cluster — exactly the single-entry rank that FIX-72
    // routes through the modified fee. Same vsize (same shape) so feerate order
    // == fee order.
    //   A: base fee 5_000  (LOW)
    //   B: base fee 20_000 (HIGH)
    const A = await submitTx(0x30, 100_000n, 95_000n); // fee 5_000
    const B = await submitTx(0x31, 100_000n, 80_000n); // fee 20_000
    expect(A.fee).toBe(5_000n);
    expect(B.fee).toBe(20_000n);

    // BEFORE prioritisation: B (higher base fee) must rank first. This is the
    // un-prioritised baseline — proves the rank function is sane and that A
    // starts BEHIND B.
    const rankBefore = mempool
      .getTransactionsByFeeRate()
      .map((e) => e.txid.toString("hex"));
    expect(rankBefore.indexOf(B.internalHex)).toBeLessThan(
      rankBefore.indexOf(A.internalHex)
    );

    // Build the cluster-aware mining-score cache CLEAN *before* prioritising,
    // mirroring the real-node sequence (getblocktemplate builds the cache, then
    // the operator calls prioritisetransaction). prioritiseTransaction MUST mark
    // the cluster cache dirty (Core UpdateModifiedFee re-sorts in-place); without
    // that, getMiningScore()/getTransactionsByMiningScore() below would return
    // the STALE raw-fee rank and A would remain behind B.
    mempool.getTransactionsByMiningScore();

    // Prioritise A by +30_000 sat so A's MODIFIED fee (5_000 + 30_000 = 35_000)
    // exceeds B's base fee (20_000). Equal vsize ⇒ A's modified feerate now
    // beats B's.
    const r = await rpc("prioritisetransaction", [A.displayHex, 0, 30_000]);
    expect(r.error).toBeUndefined();
    expect(r.result).toBe(true);
    expect(mempool.getModifiedFee(A.txidInternal)).toBe(35_000n);

    // AFTER prioritisation: A must now rank AHEAD of B in BOTH selection paths
    // the miner consumes — (1) the flat fee-rate rank getTransactionsByFeeRate()
    // that template.ts selectTransactions() iterates, and (2) the cluster-aware
    // getTransactionsByMiningScore(). If the delta were display-only (the bug
    // this fix closes) A would still be behind B here.
    const rankAfterFlat = mempool
      .getTransactionsByFeeRate()
      .map((e) => e.txid.toString("hex"));
    expect(rankAfterFlat.indexOf(A.internalHex)).toBeLessThan(
      rankAfterFlat.indexOf(B.internalHex)
    );

    const rankAfterMining = mempool
      .getTransactionsByMiningScore()
      .map((e) => e.txid.toString("hex"));
    expect(rankAfterMining.indexOf(A.internalHex)).toBeLessThan(
      rankAfterMining.indexOf(B.internalHex)
    );

    // The single-entry mining SCORE of A now reflects the modified feerate
    // (35_000 / vsize), strictly above B's (20_000 / vsize).
    expect(mempool.getMiningScore(A.internalHex)).toBeGreaterThan(
      mempool.getMiningScore(B.internalHex)
    );

    // De-prioritising A back to net 0 must restore the ORIGINAL order (B first),
    // proving the effect is driven purely by the live delta and that delta-0 is
    // byte-identical to the un-prioritised baseline.
    await rpc("prioritisetransaction", [A.displayHex, 0, -30_000]);
    const rankRestored = mempool
      .getTransactionsByFeeRate()
      .map((e) => e.txid.toString("hex"));
    expect(rankRestored).toEqual(rankBefore);
  });

  test("EFFECT: under mempool pressure the lowest-MODIFIED-feerate tx is evicted; a prioritised low-base-fee tx survives", async () => {
    // Tight mempool so the two same-size txs cannot both fit: the cap admits
    // the first but forces a single TrimToSize eviction when the second
    // arrives. Since 76975fa maxSize bounds REAL HEAP USAGE (like Core's
    // -maxmempool), not raw vsize — each fixture tx accounts ~1717 bytes of
    // usage (74 vbytes), so a 2000-byte cap holds exactly one.
    const tinyUtxo = utxo;
    const tightPool = new Mempool(tinyUtxo, REGTEST, 2000);
    tightPool.setTipHeight(200);

    // Helper bound to the tight pool (mirrors submitTx but targets tightPool and
    // does NOT assert acceptance — the loser may be trimmed out immediately).
    async function submitInto(
      pool: Mempool,
      inputSeed: number,
      inAmount: bigint,
      outAmount: bigint
    ): Promise<{ txidInternal: Buffer; internalHex: string; displayHex: string }> {
      const inputTxid = Buffer.alloc(32, inputSeed);
      await db.putUTXO(inputTxid, 0, {
        height: 1,
        coinbase: false,
        amount: inAmount,
        scriptPubKey: P2A_SPK,
      });
      const tx = createTestTx([{ txid: inputTxid, vout: 0 }], [{ value: outAmount }]);
      await pool.addTransaction(tx);
      const txidInternal = getTxId(tx);
      return {
        txidInternal,
        internalHex: txidInternal.toString("hex"),
        displayHex: displayTxid(txidInternal),
      };
    }

    // LOW: base fee 5_000. HIGH: base fee 20_000.
    const low = await submitInto(tightPool, 0x40, 100_000n, 95_000n);
    // Prioritise LOW by +30_000 BEFORE the competitor arrives, so LOW's modified
    // feerate (35_000/vsize) beats HIGH's base (20_000/vsize). Core applies the
    // delta in-place via UpdateModifiedFee, so eviction must consult it.
    tightPool.prioritiseTransaction(low.txidInternal, 30_000n);
    expect(tightPool.getModifiedFee(low.txidInternal)).toBe(35_000n);

    const high = await submitInto(tightPool, 0x41, 100_000n, 80_000n);

    // Pool is over its 2000-byte heap-usage cap with both present, so exactly one of the
    // two same-size txs survives. With the fix, eviction picks the LOWEST
    // MODIFIED feerate ⇒ HIGH (base 20_000) is evicted, prioritised LOW
    // (modified 35_000) survives. Without the fix (raw base feerate) LOW would
    // be the one trimmed.
    expect(tightPool.hasTransaction(low.txidInternal)).toBe(true);
    expect(tightPool.hasTransaction(high.txidInternal)).toBe(false);
  });

  test("deltas survive a mempool.dat persist/load roundtrip", async () => {
    // One in-mempool tx with a delta + one not-in-mempool (ghost) delta.
    const { txidInternal, displayHex, fee } = await submitTx(0xcc, 100_000n, 90_000n);
    await rpc("prioritisetransaction", [displayHex, 0, 2500]);

    const ghostInternal = Buffer.alloc(32, 0x22);
    await rpc("prioritisetransaction", [displayTxid(ghostInternal), 0, -1234]);

    await dumpMempool(mempool, tempDir);

    // Fresh mempool over the SAME utxo/db, load the dump back.
    const mempool2 = new Mempool(utxo, REGTEST, 1_000_000);
    mempool2.setTipHeight(200);
    const load = await loadMempool(mempool2, tempDir);
    expect(load.succeeded).toBe(1);

    // In-mempool delta restored on the re-accepted tx (modified fee = base+delta).
    expect(mempool2.getModifiedFee(txidInternal)).toBe(fee + 2500n);

    // Not-in-mempool (negative, signed) delta restored too.
    const restored = mempool2.getPrioritisedTransactions();
    const byHex = new Map(
      restored.map((r) => [r.txid.toString("hex"), r])
    );
    const ghost = byHex.get(ghostInternal.toString("hex"));
    expect(ghost).toBeDefined();
    expect(ghost!.feeDelta).toBe(-1234n);
    expect(ghost!.inMempool).toBe(false);
    expect(ghost!.modifiedFee).toBeNull();

    const tx = byHex.get(txidInternal.toString("hex"));
    expect(tx).toBeDefined();
    expect(tx!.feeDelta).toBe(2500n);
    expect(tx!.inMempool).toBe(true);
    expect(tx!.modifiedFee).toBe(fee + 2500n);
  });
});
