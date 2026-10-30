/**
 * Crash safety of the two non-P2P chainstate writers (security audit
 * hotbuns-2026-10-29, findings H8 and H9).
 *
 * H8 — ChainStateManager.connectBlock (generateblock fallback, --import-blocks,
 * dumptxoutset rollback re-apply, reorganize) used to flush the coins for
 * block N in one write and the CHAIN_STATE marker for N several awaited writes
 * later. A crash in between left coins at N with the tip at N-1; on restart the
 * block is reconnected against coins that already spent its inputs, fails
 * bad-txns-inputs-missingorspent and is marked FAILED_VALID. Core writes coins
 * and the best block in one batch (txdb.cpp CCoinsViewDB::BatchWrite).
 *
 * H9 — ChainstateManager.loadSnapshot wrote snapshot coins straight into the
 * live UTXO keyspace before the content-hash gate, deleted nothing when the
 * gate (or the parser) refused, compared the stale-snapshot guard against a
 * hard-coded tip height of 0, and kept the rows it displaced for the sorted
 * import only in memory. Core loads into a separate chainstate_snapshot DB,
 * deletes it on any failure (validation.cpp ActivateSnapshot) and compares
 * against the real active tip.
 *
 * Crashes are simulated at the LevelDB layer: once a write that matches the
 * trigger has landed, every later write throws, as if the process had died.
 * The datadir is then reopened and loaded the way the node does at startup.
 */
import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ChainStateManager } from "../chain/state.js";
import { ChainstateManager, serializeSnapshotMetadata } from "../chain/snapshot.js";
import { REGTEST } from "../consensus/params.js";
import type { ConsensusParams } from "../consensus/params.js";
import { hash256 } from "../crypto/primitives.js";
import { BlockStatus, ChainDB, DBPrefix } from "../storage/database.js";
import type { Block, BlockHeader } from "../validation/block.js";
import { getBlockHash } from "../validation/block.js";
import type { Transaction } from "../validation/tx.js";
import { getTxId } from "../validation/tx.js";
import { writeVarIntCore } from "../wire/compressor.js";
import { BufferWriter } from "../wire/serialization.js";

// ── crash injection ──────────────────────────────────────────────────────────

interface CrashSwitch {
  crashed: boolean;
}

/**
 * Make every write after the first one whose keys satisfy `trigger` throw.
 * The triggering write itself lands (it is the last thing the "process" did).
 */
function armCrash(db: ChainDB, trigger: (keys: Buffer[], dels: Buffer[]) => boolean): CrashSwitch {
  const raw = (db as unknown as { db: any }).db;
  const sw: CrashSwitch = { crashed: false };
  const dead = () => {
    if (sw.crashed) throw new Error("simulated crash: process is gone");
  };
  const origPut = raw.put.bind(raw);
  const origDel = raw.del.bind(raw);
  const origBatch = raw.batch.bind(raw);
  const origClear = raw.clear.bind(raw);
  raw.put = async (k: Buffer, v: Buffer, ...r: unknown[]) => {
    dead();
    await origPut(k, v, ...r);
    if (trigger([k], [])) sw.crashed = true;
  };
  raw.del = async (k: Buffer, ...r: unknown[]) => {
    dead();
    await origDel(k, ...r);
    if (trigger([], [k])) sw.crashed = true;
  };
  raw.clear = async (...r: unknown[]) => {
    dead();
    await origClear(...r);
  };
  raw.batch = (...args: any[]) => {
    if (args.length > 0) {
      return (async () => {
        dead();
        await origBatch(...args);
        const ops = args[0] as { type: string; key: Buffer }[];
        const puts = ops.filter((o) => o.type === "put").map((o) => o.key);
        const dels = ops.filter((o) => o.type === "del").map((o) => o.key);
        if (trigger(puts, dels)) sw.crashed = true;
      })();
    }
    const b = origBatch();
    const puts: Buffer[] = [];
    const dels: Buffer[] = [];
    const bPut = b.put.bind(b);
    const bDel = b.del.bind(b);
    const bWrite = b.write.bind(b);
    b.put = (k: Buffer, v: Buffer, o?: unknown) => {
      puts.push(k);
      bPut(k, v, o);
      return b;
    };
    b.del = (k: Buffer, o?: unknown) => {
      dels.push(k);
      bDel(k, o);
      return b;
    };
    b.write = async (...r: unknown[]) => {
      dead();
      await bWrite(...r);
      if (trigger(puts, dels)) sw.crashed = true;
    };
    return b;
  };
  return sw;
}

/** Every row in the store, hex key -> hex value. */
async function dumpStore(db: ChainDB): Promise<Map<string, string>> {
  const raw = (db as unknown as { db: any }).db;
  const out = new Map<string, string>();
  for await (const [k, v] of raw.iterator()) {
    out.set(Buffer.from(k).toString("hex"), Buffer.from(v).toString("hex"));
  }
  return out;
}

function rowsWithPrefix(rows: Map<string, string>, prefix: number): string[] {
  const p = prefix.toString(16).padStart(2, "0");
  return [...rows.keys()].filter((k) => k.startsWith(p));
}

// ── block helpers (same shape as disconnect_block.test.ts) ───────────────────

const OP_TRUE = Buffer.from([0x51]);

function coinbaseTx(height: number, value: bigint): Transaction {
  return {
    version: 1,
    inputs: [
      {
        prevOut: { txid: Buffer.alloc(32, 0), vout: 0xffffffff },
        scriptSig: Buffer.concat([Buffer.from([0x03]), Buffer.alloc(3, height & 0xff), Buffer.from([height >>> 8, 0x99])]),
        sequence: 0xffffffff,
        witness: [],
      },
    ],
    outputs: [{ value, scriptPubKey: OP_TRUE }],
    lockTime: 0,
  };
}

function merkleRoot(txids: Buffer[]): Buffer {
  let level: Buffer[] = txids.map((t) => Buffer.from(t));
  while (level.length > 1) {
    const next: Buffer[] = [];
    for (let i = 0; i < level.length; i += 2) {
      next.push(hash256(Buffer.concat([level[i]!, level[i + 1] ?? level[i]!])));
    }
    level = next;
  }
  return level[0]!;
}

function makeBlock(prev: Buffer, txs: Transaction[]): Block {
  const header: BlockHeader = {
    version: 0x20000000,
    prevBlock: prev,
    merkleRoot: merkleRoot(txs.map(getTxId)),
    timestamp: Math.floor(Date.now() / 1000),
    bits: REGTEST.powLimitBits,
    nonce: 0,
  };
  return { header, transactions: txs };
}

// ── snapshot helpers ─────────────────────────────────────────────────────────

const BASE_HASH = Buffer.alloc(32, 0x11);
const BASE_HEIGHT = 10;

function snapTxid(i: number): Buffer {
  const t = Buffer.alloc(32, 0x5a);
  t.writeUInt32BE(i, 0);
  return t;
}

/** Core-format snapshot of `coins` P2PKH coins at height 2, sorted by txid. */
function snapshotBytes(coins: number, trailing = 0): Buffer {
  const w = new BufferWriter(coins * 64 + 64 + trailing);
  w.writeBytes(
    serializeSnapshotMetadata({
      networkMagic: REGTEST.networkMagic,
      baseBlockHash: BASE_HASH,
      coinsCount: BigInt(coins),
    }),
  );
  for (let i = 0; i < coins; i++) {
    w.writeBytes(snapTxid(i));
    w.writeVarInt(1); // outputs for this txid
    w.writeVarInt(0); // vout
    writeVarIntCore(w, 4n); // code: height 2, not coinbase
    writeVarIntCore(w, 0n); // compressed amount
    writeVarIntCore(w, 0n); // script type 0: P2PKH
    w.writeBytes(Buffer.alloc(20, 0x22));
  }
  if (trailing > 0) w.writeBytes(Buffer.alloc(trailing, 0xee));
  return w.toBuffer();
}

/** REGTEST with an assumeutxo entry for BASE_HASH whose commitment is wrong. */
const WRONG_HASH_PARAMS: ConsensusParams = {
  ...REGTEST,
  assumeutxo: new Map([
    [
      BASE_HASH.toString("hex"),
      { height: BASE_HEIGHT, hashSerialized: Buffer.alloc(32, 0x33), nChainTx: 1n, blockHash: BASE_HASH },
    ],
  ]),
};

// ── tests ────────────────────────────────────────────────────────────────────

describe("crash safety: connectBlock and snapshot load (audit H8, H9)", () => {
  let dir: string;
  let db: ChainDB;
  const prevUnsafe = process.env.HASHHOG_UNSAFE_SNAPSHOT_HEIGHT;

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "hotbuns-crash-safety-"));
    db = new ChainDB(join(dir, "db"));
    await db.open();
  });

  afterEach(async () => {
    if (prevUnsafe === undefined) delete process.env.HASHHOG_UNSAFE_SNAPSHOT_HEIGHT;
    else process.env.HASHHOG_UNSAFE_SNAPSHOT_HEIGHT = prevUnsafe;
    await db.close().catch(() => {});
    await rm(dir, { recursive: true, force: true });
  });

  /** Close the "crashed" store and reopen it the way the node boots. */
  async function restart(): Promise<ChainStateManager> {
    await db.close().catch(() => {});
    db = new ChainDB(join(dir, "db"));
    await db.open();
    const cs = new ChainStateManager(db, REGTEST);
    await cs.load();
    return cs;
  }

  // ── H8 ──
  test("H8: a crash right after connectBlock's coins land leaves coins and tip in agreement", async () => {
    const cs = new ChainStateManager(db, REGTEST);
    await cs.load();
    const cb = coinbaseTx(1, 50_00000000n);
    const block = makeBlock(REGTEST.genesisBlockHash, [cb]);
    const hash = getBlockHash(block.header);

    const sw = armCrash(db, (puts) => puts.some((k) => k[0] === DBPrefix.UTXO));
    await cs.connectBlock(block, 1).catch(() => {});
    expect(sw.crashed).toBe(true);

    const cs2 = await restart();
    const tip = cs2.getBestBlock();
    const coin = await db.getUTXO(getTxId(cb), 0);
    // The write that carried the coins is the commit point: the tip must
    // have moved with it, or the coins must not be there.
    expect({ tip: tip.height, coin: coin !== null }).toEqual({ tip: 1, coin: true });
    expect(tip.hash.equals(hash)).toBe(true);
    // Everything connectBlock persists for the block rode the same batch.
    expect(await db.getBlock(hash)).not.toBeNull();
    expect(await db.getUndoData(hash)).not.toBeNull();
    expect((await db.getBlockHashByHeight(1))?.equals(hash)).toBe(true);
    expect((await db.getTxIndex(getTxId(cb)))?.blockHash.equals(hash)).toBe(true);
    expect(await db.getChainWork(hash)).toBe(tip.chainWork);
    const idx = await db.getBlockIndex(hash);
    expect(idx?.height).toBe(1);
    expect((idx!.status & BlockStatus.FAILED_VALID) === 0).toBe(true);
  });

  test("H8: after a crash the next block connects on top (no FAILED_VALID replay)", async () => {
    const cs = new ChainStateManager(db, REGTEST);
    await cs.load();
    const b1 = makeBlock(REGTEST.genesisBlockHash, [coinbaseTx(1, 50_00000000n)]);
    const sw = armCrash(db, (puts) => puts.some((k) => k[0] === DBPrefix.UTXO));
    await cs.connectBlock(b1, 1).catch(() => {});
    expect(sw.crashed).toBe(true);

    const cs2 = await restart();
    const h = cs2.getBestBlock().height;
    const b2 = makeBlock(getBlockHash(b1.header), [coinbaseTx(2, 50_00000000n)]);
    if (h === 0) await cs2.connectBlock(b1, 1);
    await cs2.connectBlock(b2, 2);
    expect(cs2.getBestBlock().height).toBe(2);
  });

  // ── H9 ──
  async function freshManager(params: ConsensusParams = REGTEST): Promise<ChainstateManager> {
    const cs = new ChainStateManager(db, REGTEST);
    await cs.load();
    return new ChainstateManager(db, params);
  }

  async function writeSnap(name: string, bytes: Buffer): Promise<string> {
    const p = join(dir, name);
    await writeFile(p, bytes);
    return p;
  }

  test("H9: a wrong-content-hash snapshot leaves a fresh datadir untouched", async () => {
    const mgr = await freshManager(WRONG_HASH_PARAMS);
    const before = await dumpStore(db);
    const snap = await writeSnap("bad-hash.dat", snapshotBytes(50));
    await expect(mgr.loadSnapshot(snap)).rejects.toThrow(/Bad snapshot content hash/);
    expect(await dumpStore(db)).toEqual(before);
  });

  test("H9: a wrong-content-hash snapshot leaves an existing coins set untouched", async () => {
    const mgr = await freshManager(WRONG_HASH_PARAMS);
    await db.putUTXO(Buffer.alloc(32, 0x77), 0, {
      height: 1,
      coinbase: true,
      amount: 50_00000000n,
      scriptPubKey: OP_TRUE,
    });
    const before = await dumpStore(db);
    const snap = await writeSnap("bad-hash-live.dat", snapshotBytes(50));
    await expect(mgr.loadSnapshot(snap)).rejects.toThrow(/Bad snapshot content hash/);
    expect(await dumpStore(db)).toEqual(before);
  });

  test("H9: a malformed snapshot (trailing bytes) leaves the datadir untouched", async () => {
    process.env.HASHHOG_UNSAFE_SNAPSHOT_HEIGHT = String(BASE_HEIGHT);
    const mgr = await freshManager();
    const before = await dumpStore(db);
    const snap = await writeSnap("trailing.dat", snapshotBytes(50, 7));
    await expect(mgr.loadSnapshot(snap)).rejects.toThrow(/coins left over/);
    expect(await dumpStore(db)).toEqual(before);
  });

  test("H9: a crash after snapshot coins are written is rolled back at startup", async () => {
    process.env.HASHHOG_UNSAFE_SNAPSHOT_HEIGHT = String(BASE_HEIGHT);
    const mgr = await freshManager();
    const before = await dumpStore(db);
    const snap = await writeSnap("crash.dat", snapshotBytes(50));
    // Crash after the first write that carries snapshot coins (a txid with
    // the 0x5a fill), wherever the loader puts them.
    const sw = armCrash(db, (puts) => puts.some((k) => k.length === 37 && k[6] === 0x5a));
    await mgr.loadSnapshot(snap).catch(() => {});
    expect(sw.crashed).toBe(true);

    const cs2 = await restart();
    expect(cs2.getBestBlock().height).toBe(0);
    expect(await dumpStore(db)).toEqual(before);
  });

  test("H9: the stale-snapshot guard compares against the persisted tip, not 0", async () => {
    process.env.HASHHOG_UNSAFE_SNAPSHOT_HEIGHT = String(BASE_HEIGHT);
    await freshManager();
    // A datadir already synced past the snapshot base.
    await db.putChainState({ bestBlockHash: Buffer.alloc(32, 0x44), bestHeight: BASE_HEIGHT + 5, totalWork: 99n });
    const before = await dumpStore(db);
    const mgr = new ChainstateManager(db, REGTEST);
    const snap = await writeSnap("stale.dat", snapshotBytes(5));
    await expect(mgr.loadSnapshot(snap)).rejects.toThrow(/Work does not exceed active chainstate/);
    expect(await dumpStore(db)).toEqual(before);
  });

  test("H9: rows displaced for the sorted import survive a crash", async () => {
    process.env.HASHHOG_UNSAFE_SNAPSHOT_HEIGHT = String(BASE_HEIGHT);
    const mgr = await freshManager();
    const before = await dumpStore(db);
    // The genesis CHAIN_WORK row sits above the UTXO prefix and is displaced.
    expect(rowsWithPrefix(before, DBPrefix.CHAIN_WORK).length).toBeGreaterThan(0);
    const snap = await writeSnap("displace.dat", snapshotBytes(5));
    const sw = armCrash(db, (_puts, dels) => dels.some((k) => k[0] === DBPrefix.CHAIN_WORK));
    await mgr.loadSnapshot(snap, undefined, { isolateBulkLoad: true }).catch(() => {});
    expect(sw.crashed).toBe(true);

    await restart();
    const after = await dumpStore(db);
    for (const k of rowsWithPrefix(before, DBPrefix.CHAIN_WORK)) {
      expect(after.get(k)).toBe(before.get(k));
    }
  });

  test("H9: a successful load commits the coins and the snapshot tip together", async () => {
    process.env.HASHHOG_UNSAFE_SNAPSHOT_HEIGHT = String(BASE_HEIGHT);
    const mgr = await freshManager();
    const snap = await writeSnap("ok.dat", snapshotBytes(20));
    const res = await mgr.loadSnapshot(snap);
    expect(res.coinsLoaded).toBe(20n);
    const state = await db.getChainState();
    expect(state?.bestHeight).toBe(BASE_HEIGHT);
    expect(state?.bestBlockHash.equals(BASE_HASH)).toBe(true);
    expect(rowsWithPrefix(await dumpStore(db), DBPrefix.UTXO).length).toBe(20);
    expect(await db.getUTXO(snapTxid(19), 0)).not.toBeNull();
  });

  test("H9: a snapshot replaces, not merges into, an existing coins set", async () => {
    process.env.HASHHOG_UNSAFE_SNAPSHOT_HEIGHT = String(BASE_HEIGHT);
    const mgr = await freshManager();
    const stale = Buffer.alloc(32, 0x77);
    await db.putUTXO(stale, 0, { height: 1, coinbase: true, amount: 50_00000000n, scriptPubKey: OP_TRUE });
    const snap = await writeSnap("replace.dat", snapshotBytes(20));
    await mgr.loadSnapshot(snap);
    expect(await db.getUTXO(stale, 0)).toBeNull();
    expect(rowsWithPrefix(await dumpStore(db), DBPrefix.UTXO).length).toBe(20);
    expect((await db.getChainState())?.bestHeight).toBe(BASE_HEIGHT);
  });

  test("H9: a crash while a verified snapshot replaces the coins set finishes at startup", async () => {
    process.env.HASHHOG_UNSAFE_SNAPSHOT_HEIGHT = String(BASE_HEIGHT);
    const mgr = await freshManager();
    const stale = Buffer.alloc(32, 0x77);
    await db.putUTXO(stale, 0, { height: 1, coinbase: true, amount: 50_00000000n, scriptPubKey: OP_TRUE });
    const snap = await writeSnap("promote-crash.dat", snapshotBytes(20));
    // Crash on the first write that puts a snapshot coin into the live UTXO
    // keyspace.
    const sw = armCrash(db, (puts) =>
      puts.some((k) => k[0] === DBPrefix.UTXO && k.length === 37 && k[6] === 0x5a),
    );
    await mgr.loadSnapshot(snap).catch(() => {});
    expect(sw.crashed).toBe(true);

    const cs2 = await restart();
    // Either the load never happened or it completed: never a mix.
    expect(cs2.getBestBlock().height).toBe(BASE_HEIGHT);
    expect(await db.getUTXO(stale, 0)).toBeNull();
    expect(rowsWithPrefix(await dumpStore(db), DBPrefix.UTXO).length).toBe(20);
  });
});
