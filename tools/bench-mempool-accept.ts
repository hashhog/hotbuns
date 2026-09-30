/**
 * Measure per-transaction acceptToMemoryPool cost as a function of the
 * existing mempool population.
 *
 *   bun run tools/bench-mempool-accept.ts [preload=20000] [probe=200] [chainEvery=0]
 *
 * preload     number of independent txs admitted before measuring
 * probe       number of txs whose admission is timed afterwards
 * chainEvery  if >0, every Nth probe tx spends an in-mempool parent
 *
 * Uses P2A outputs so no signature work is involved: what is measured is
 * mempool bookkeeping only.
 */
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ChainDB } from "../src/storage/database.js";
import { UTXOManager } from "../src/chain/utxo.js";
import { REGTEST } from "../src/consensus/params.js";
import { Mempool } from "../src/mempool/mempool.js";
import type { Transaction } from "../src/validation/tx.js";
import { getTxId } from "../src/validation/tx.js";

const P2A = Buffer.from([0x51, 0x02, 0x4e, 0x73]);
const preload = Number(process.argv[2] ?? 20000);
const probe = Number(process.argv[3] ?? 200);
const chainEvery = Number(process.argv[4] ?? 0);

function fundingTxid(i: number): Buffer {
  const b = Buffer.alloc(32);
  b.writeUInt32LE(i + 1, 0);
  b[31] = 0xee;
  return b;
}

function mkTx(prev: Buffer, vout: number, value: bigint): Transaction {
  return {
    version: 2,
    inputs: [{ prevOut: { txid: prev, vout }, scriptSig: Buffer.alloc(0), sequence: 0xffffffff, witness: [] }],
    outputs: [
      { value, scriptPubKey: P2A },
      { value: 0n, scriptPubKey: Buffer.from([0x6a]) },
    ],
    lockTime: 0,
  };
}

const dir = await mkdtemp(join(tmpdir(), "hotbuns-bench-mempool-"));
const db = new ChainDB(dir);
await db.open();
try {
  const utxo = new UTXOManager(db);
  const mempool = new Mempool(utxo, REGTEST, 2_000_000_000);
  mempool.setTipHeight(200);
  const total = preload + probe;
  for (let i = 0; i < total; i++) {
    await db.putUTXO(fundingTxid(i), 0, { height: 1, coinbase: false, amount: 100_000n, scriptPubKey: P2A });
  }

  const t0 = performance.now();
  const parents: Buffer[] = [];
  for (let i = 0; i < preload; i++) {
    const tx = mkTx(fundingTxid(i), 0, 99_000n);
    const r = await mempool.addTransaction(tx);
    if (!r.accepted) throw new Error(`preload ${i} rejected: ${r.error}`);
    if (parents.length < 1000) parents.push(getTxId(tx));
    if ((i + 1) % 5000 === 0) {
      console.log(`preload ${i + 1}: ${((performance.now() - t0) / 1000).toFixed(1)}s`);
    }
  }

  const times: number[] = [];
  let p = 0;
  for (let i = 0; i < probe; i++) {
    const useParent = chainEvery > 0 && i % chainEvery === 0 && p < parents.length;
    const tx = useParent ? mkTx(parents[p++], 0, 98_000n) : mkTx(fundingTxid(preload + i), 0, 99_000n);
    const s = performance.now();
    const r = await mempool.addTransaction(tx);
    times.push(performance.now() - s);
    if (!r.accepted) throw new Error(`probe ${i} rejected: ${r.error}`);
  }
  times.sort((a, b) => a - b);
  const mean = times.reduce((a, b) => a + b, 0) / times.length;
  console.log(
    JSON.stringify({
      preload,
      probe,
      chainEvery,
      mempoolSize: mempool.getSize(),
      meanMs: +mean.toFixed(3),
      p50Ms: +times[Math.floor(times.length / 2)].toFixed(3),
      p99Ms: +times[Math.floor(times.length * 0.99)].toFixed(3),
      maxMs: +times[times.length - 1].toFixed(3),
    })
  );
} finally {
  await db.close();
  await rm(dir, { recursive: true, force: true });
}
