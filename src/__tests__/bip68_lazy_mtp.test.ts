/**
 * BIP-68 coin-MTP is computed lazily in ConnectBlock: only for inputs whose
 * relative lock is time-typed and not disabled, of txs with version >= 2
 * (unsigned) while BIP-68 is enforced — the exact inputs Core's
 * CalculateSequenceLocks reads GetMedianTimePast() for (tx_verify.cpp:66-99).
 *
 * Equivalence oracle: the old eager path, i.e. calculateSequenceLocks /
 * evaluateSequenceLocks over confirmations whose medianTimePast is filled for
 * EVERY input.  ~3,000 random vectors plus hand-picked edges must produce the
 * same accept/reject from coreConnectBlockChecks, and the provider must be
 * called only for time-typed inputs, at most once per coin height per block.
 */
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ChainDB } from "../storage/database.js";
import { REGTEST } from "../consensus/params.js";
import { UTXOManager } from "../chain/utxo.js";
import { coreConnectBlockChecks } from "../consensus/connect_block.js";
import type { Block } from "../validation/block.js";
import {
  calculateSequenceLocks,
  evaluateSequenceLocks,
  getTxId,
  SEQUENCE_LOCKTIME_DISABLE_FLAG,
  SEQUENCE_LOCKTIME_TYPE_FLAG,
  type Transaction,
} from "../validation/tx.js";

const SPK = Buffer.from([0x00, 0x14, ...Array(20).fill(0x11)]);
const TIP = 50_000;

/** Deterministic, non-monotone MTP by height (so a wrong height shows). */
const mtpAt = (h: number): number => 1_400_000_000 + h * 600 + ((h * 7919) % 1013);
/** The provider sync/blocks.ts wires: MTP of the block BEFORE the coin. */
const coinMTP = (coinHeight: number): number => (coinHeight <= 0 ? 0 : mtpAt(coinHeight - 1));

function coinbase(height: number, value: bigint): Transaction {
  return {
    version: 1,
    inputs: [
      {
        prevOut: { txid: Buffer.alloc(32, 0), vout: 0xffffffff },
        scriptSig: Buffer.from([0x03, height & 0xff, (height >> 8) & 0xff, (height >> 16) & 0xff, 0x51]),
        sequence: 0xffffffff,
        witness: [],
      },
    ],
    outputs: [{ value, scriptPubKey: SPK }],
    lockTime: 0,
  };
}

let dir: string;
let db: ChainDB;
beforeAll(async () => {
  dir = await mkdtemp(join(tmpdir(), "hotbuns-lazy-mtp-"));
  db = new ChainDB(dir);
  await db.open();
});
afterAll(async () => {
  await db.close();
  await rm(dir, { recursive: true, force: true });
});

let uniq = 0;

interface Vector {
  version: number;
  inputs: { seq: number; coinHeight: number }[];
  enforce: boolean;
  prevMTP: number;
}

/** Old eager decision (medianTimePast filled for every input). */
function eagerAccept(v: Vector, tx: Transaction): boolean {
  if (!(v.enforce && (v.version >>> 0) >= 2)) return true;
  const locks = calculateSequenceLocks(
    tx,
    v.enforce,
    v.inputs.map((i) => ({ height: i.coinHeight, medianTimePast: coinMTP(i.coinHeight) })),
  );
  return evaluateSequenceLocks(TIP, v.prevMTP, locks);
}

async function runVector(v: Vector): Promise<{ lazyOk: boolean; eagerOk: boolean; calls: number[] }> {
  const utxo = new UTXOManager(db);
  const cache = utxo.getCoinsViewCache();
  const prevOuts = v.inputs.map((inp) => {
    const txid = Buffer.alloc(32, 0);
    txid.writeUInt32LE(++uniq, 0);
    txid.writeUInt32LE(0xbeef, 28);
    cache.addCoin(
      { txid, vout: 0 },
      { txOut: { value: 100_000n, scriptPubKey: SPK }, height: inp.coinHeight, isCoinbase: false },
      false,
    );
    return { txid, vout: 0 };
  });
  const spend: Transaction = {
    version: v.version,
    inputs: v.inputs.map((inp, i) => ({
      prevOut: prevOuts[i]!,
      scriptSig: Buffer.alloc(0),
      sequence: inp.seq,
      witness: [],
    })),
    outputs: [{ value: 1_000n, scriptPubKey: SPK }],
    lockTime: 0,
  };
  const block: Block = {
    header: {
      version: 0x20000000,
      prevBlock: Buffer.alloc(32, 0xab),
      merkleRoot: getTxId(spend),
      timestamp: v.prevMTP + 1,
      bits: REGTEST.powLimitBits,
      nonce: 0,
    },
    transactions: [coinbase(TIP, 1n), spend],
  };
  const calls: number[] = [];
  const res = await coreConnectBlockChecks(block, TIP, utxo, REGTEST, {
    skipScripts: true,
    enforceBIP68: v.enforce,
    prevMTP: v.prevMTP,
    getUTXOMTP: (h: number) => {
      calls.push(h);
      return coinMTP(h);
    },
  });
  if (!res.ok && !/bad-txns-nonfinal/.test(res.error)) {
    throw new Error(`unexpected reject (not a sequence-lock failure): ${res.error}`);
  }
  return { lazyOk: res.ok, eagerOk: eagerAccept(v, spend), calls };
}

const needsTime = (version: number, seq: number, enforce: boolean): boolean =>
  enforce &&
  (version >>> 0) >= 2 &&
  ((seq >>> 0) & SEQUENCE_LOCKTIME_DISABLE_FLAG) === 0 &&
  (seq & SEQUENCE_LOCKTIME_TYPE_FLAG) !== 0;

function checkCalls(v: Vector, calls: number[]): void {
  const want = new Set(v.inputs.filter((i) => needsTime(v.version, i.seq, v.enforce)).map((i) => i.coinHeight));
  // Every call is for a time-typed input's height, and each height once.
  expect(new Set(calls)).toEqual(want);
  expect(calls.length).toBe(want.size);
}

describe("BIP-68 lazy coin MTP == eager path", () => {
  test("hand-picked BIP-68 edges", async () => {
    const T = SEQUENCE_LOCKTIME_TYPE_FLAG;
    const D = SEQUENCE_LOCKTIME_DISABLE_FLAG >>> 0;
    const h = TIP - 100;
    const base = coinMTP(h);
    const edges: Vector[] = [];
    for (const version of [1, 2, 3, -2147483646 /* 0x80000002 */, -1 /* 0xffffffff */, 0]) {
      for (const enforce of [true, false]) {
        for (const seq of [
          0xffffffff, 0xfffffffe, 0, 1, 99, 100, 101, 0xffff, 0x10000 | 5,
          T, T | 1, T | 0xffff, (T | 3) >>> 0, (D | T | 1) >>> 0, (D | 5) >>> 0, 0x7fffffff,
        ]) {
          // time lock exactly at the boundary: minTime = base + v*512 - 1
          const v512 = (seq & 0xffff) << 9;
          for (const prevMTP of [base + v512 - 1, base + v512, base + v512 + 1, 1, 2_000_000_000]) {
            edges.push({ version, enforce, prevMTP, inputs: [{ seq: seq >>> 0 === seq ? seq : seq >>> 0, coinHeight: h }] });
          }
        }
      }
    }
    let rejects = 0;
    for (const v of edges) {
      const r = await runVector(v);
      expect(r.lazyOk).toBe(r.eagerOk);
      if (!r.eagerOk) rejects++;
      checkCalls(v, r.calls);
    }
    console.log(`edge vectors: ${edges.length}, ${rejects} rejects`);
    // The vectors must actually exercise both outcomes.
    expect(rejects).toBeGreaterThan(50);
    expect(edges.length - rejects).toBeGreaterThan(50);
  });

  test("3,000 random multi-input vectors", async () => {
    let s = 0x5eed;
    const rnd = (n: number) => {
      // xorshift32 (Math.imul-free, exact in int32 arithmetic)
      s ^= s << 13;
      s ^= s >>> 17;
      s ^= s << 5;
      return (s >>> 0) % n;
    };
    const seqPool = (): number => {
      const k = rnd(6);
      const lock = [0, 1, 2, 10, 144, 200, 0xffff][rnd(7)]!;
      if (k === 0) return 0xffffffff;
      if (k === 1) return lock; // height type
      if (k === 2) return (SEQUENCE_LOCKTIME_TYPE_FLAG | lock) >>> 0; // time type
      if (k === 3) return (SEQUENCE_LOCKTIME_DISABLE_FLAG | SEQUENCE_LOCKTIME_TYPE_FLAG | lock) >>> 0;
      if (k === 4) return (rnd(0x7fffffff) * 2 + rnd(2)) >>> 0; // any 32-bit
      return 0xfffffffe;
    };
    let rejects = 0;
    let timeLocked = 0;
    for (let i = 0; i < 3000; i++) {
      const n = 1 + rnd(4);
      const inputs = Array.from({ length: n }, () => ({ seq: seqPool(), coinHeight: TIP - 1 - rnd(300) }));
      // Share heights across inputs sometimes (exercises the memo).
      if (n > 1 && rnd(2) === 0) inputs[1]!.coinHeight = inputs[0]!.coinHeight;
      const version = [1, 2, 2, 2, 3, -2147483646][rnd(6)]!;
      const enforce = rnd(8) !== 0;
      // prevMTP near the interesting range so time locks both pass and fail.
      const prevMTP = coinMTP(TIP - 1 - rnd(300)) + rnd(150_000) - 20_000;
      const v: Vector = { version, inputs, enforce, prevMTP };
      const r = await runVector(v);
      expect(r.lazyOk).toBe(r.eagerOk);
      checkCalls(v, r.calls);
      if (!r.eagerOk) rejects++;
      if (r.calls.length > 0) timeLocked++;
    }
    console.log(`random vectors: ${rejects} rejects, ${timeLocked} with time-typed inputs`);
    expect(rejects).toBeGreaterThan(100);
    expect(timeLocked).toBeGreaterThan(500);
  });
});
