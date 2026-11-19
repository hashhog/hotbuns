/**
 * TRUC sibling eviction must pass the same replacement checks as a direct
 * conflict (cffix-hotbuns-truc-sibling-rbf).
 *
 * Core: MemPoolAccept::PreChecks (validation.cpp) adds the sibling to
 * ws.m_conflicts and sets m_sibling_eviction; ReplacementChecks then runs
 * PaysForRBF (policy/rbf.cpp), which requires
 *   replacement_fee >= conflicting_fees + incremental_relay_feerate * vsize,
 * and ImprovesFeerateDiagram. A failure is "insufficient fee (including
 * sibling eviction)".
 *
 * Before this fix hotbuns ran its TRUC check after the RBF block had been
 * skipped (there were no direct conflicts) and only required
 * fee > sibling.fee, so a sibling could be replaced for 1 sat.
 */

import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ChainDB, UTXOEntry } from "../storage/database.js";
import { UTXOManager } from "../chain/utxo.js";
import { REGTEST } from "../consensus/params.js";
import { Mempool, TRUC_VERSION } from "../mempool/mempool.js";
import type { Transaction } from "../validation/tx.js";
import { getTxId, getTxVSize } from "../validation/tx.js";

const P2A = Buffer.from([0x51, 0x02, 0x4e, 0x73]);
// hotbuns' default incremental relay feerate: 100 sat/kvB = 0.1 sat/vB.
const INCREMENTAL_SAT_PER_VB = 0.1;

function v3Tx(inputs: Array<{ txid: Buffer; vout: number }>, outputs: bigint[]): Transaction {
  return {
    version: TRUC_VERSION,
    inputs: inputs.map((inp) => ({
      prevOut: { txid: inp.txid, vout: inp.vout },
      scriptSig: Buffer.alloc(0),
      sequence: 0xffffffff,
      witness: [],
    })),
    outputs: [
      ...outputs.map((value) => ({ value, scriptPubKey: P2A })),
      { value: 0n, scriptPubKey: Buffer.from([0x6a]) }, // OP_RETURN padding
    ],
    lockTime: 0,
  };
}

describe("TRUC sibling eviction runs PaysForRBF", () => {
  let tempDir: string;
  let db: ChainDB;
  let mempool: Mempool;

  const PARENT_OUT = 499_000n;
  const SIBLING_A_FEE = 1_000n;

  /** Parent with two outputs and child A on output 0, both in the mempool. */
  async function setup(seed: number): Promise<{ parentTxid: Buffer; aTxid: Buffer }> {
    const fundTxid = Buffer.alloc(32, seed);
    const entry: UTXOEntry = { height: 1, coinbase: false, amount: 1_000_000n, scriptPubKey: P2A };
    await db.putUTXO(fundTxid, 0, entry);

    const parent = v3Tx([{ txid: fundTxid, vout: 0 }], [PARENT_OUT, PARENT_OUT]);
    const rp = await mempool.addTransaction(parent);
    expect(rp.accepted).toBe(true);
    const parentTxid = getTxId(parent);

    const a = v3Tx([{ txid: parentTxid, vout: 0 }], [PARENT_OUT - SIBLING_A_FEE]);
    const ra = await mempool.addTransaction(a);
    expect(ra.accepted).toBe(true);
    return { parentTxid, aTxid: getTxId(a) };
  }

  function childB(parentTxid: Buffer, fee: bigint): Transaction {
    return v3Tx([{ txid: parentTxid, vout: 1 }], [PARENT_OUT - fee]);
  }

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "cffix-truc-sibling-rbf-"));
    db = new ChainDB(tempDir);
    await db.open();
    mempool = new Mempool(new UTXOManager(db), REGTEST, 1_000_000);
    mempool.setTipHeight(200);
  });

  afterEach(async () => {
    await db.close();
    await rm(tempDir, { recursive: true, force: true });
  });

  test("sibling replacement paying A.fee + 1 sat is refused with insufficient fee", async () => {
    const { parentTxid, aTxid } = await setup(0x71);
    const b = childB(parentTxid, SIBLING_A_FEE + 1n);
    // Sanity: the incremental fee for B is more than 1 sat, so 1 sat cannot pay it.
    expect(Math.ceil(INCREMENTAL_SAT_PER_VB * getTxVSize(b))).toBeGreaterThan(1);

    const r = await mempool.addTransaction(b);
    expect(r.accepted).toBe(false);
    expect(r.error).toContain("insufficient fee");
    expect(r.error).toContain("not enough additional fees to relay");
    expect(mempool.hasTransaction(aTxid)).toBe(true);
    expect(mempool.hasTransaction(getTxId(b))).toBe(false);
  });

  test("sibling replacement one sat short of the incremental fee is refused", async () => {
    const { parentTxid, aTxid } = await setup(0x72);
    const probe = childB(parentTxid, SIBLING_A_FEE);
    const required = BigInt(Math.ceil(INCREMENTAL_SAT_PER_VB * getTxVSize(probe)));
    const b = childB(parentTxid, SIBLING_A_FEE + required - 1n);
    expect(getTxVSize(b)).toBe(getTxVSize(probe));

    const r = await mempool.addTransaction(b);
    expect(r.accepted).toBe(false);
    expect(r.error).toContain("insufficient fee (including sibling eviction)");
    expect(mempool.hasTransaction(aTxid)).toBe(true);
  });

  test("sibling replacement paying A.fee + incremental * vsize(B) is accepted (control)", async () => {
    const { parentTxid, aTxid } = await setup(0x73);
    const probe = childB(parentTxid, SIBLING_A_FEE);
    const required = BigInt(Math.ceil(INCREMENTAL_SAT_PER_VB * getTxVSize(probe)));
    const b = childB(parentTxid, SIBLING_A_FEE + required);
    expect(getTxVSize(b)).toBe(getTxVSize(probe));

    const r = await mempool.addTransaction(b);
    expect(r.accepted).toBe(true);
    expect(mempool.hasTransaction(aTxid)).toBe(false);
    expect(mempool.hasTransaction(getTxId(b))).toBe(true);
  });

  test("sibling replacement paying less than A is refused (Rule 3, less fees)", async () => {
    const { parentTxid, aTxid } = await setup(0x74);
    const b = childB(parentTxid, SIBLING_A_FEE - 1n);
    const r = await mempool.addTransaction(b);
    expect(r.accepted).toBe(false);
    expect(r.error).toContain("insufficient fee (including sibling eviction)");
    expect(r.error).toContain("less fees than conflicting txs");
    expect(mempool.hasTransaction(aTxid)).toBe(true);
  });
});
