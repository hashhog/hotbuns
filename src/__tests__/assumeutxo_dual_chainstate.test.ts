/**
 * assumeutxo_dual_chainstate.test.ts — REAL background 2nd chainstate for
 * AssumeUTXO (Core dual-chainstate parity).
 *
 * Functional gate for activateSnapshotWithBackground + BackgroundValidator +
 * finishSnapshotActivation (src/chain/snapshot.ts), the hotbuns analogue of
 * Bitcoin Core's ActivateSnapshot / AddChainstate / MaybeCompleteSnapshotValidation
 * (validation.cpp:5588 / 6170 / 5967). Mirrors the landed cross-impl pilots:
 *   - blockbrew bfd429a (internal/consensus/assumeutxo_dual_chainstate_test.go)
 *   - lunarblock a39dd42 (spec/assumeutxo_dual_chainstate_spec.lua)
 *   - camlcoin  2675b31 (test/test_dual_chainstate_spec.ml)
 *
 * What it proves (the four assertions every pilot pins):
 *   (a) SEPARATE store — a write to the active (snapshot) chainstate's coins is
 *       NOT visible in the background chainstate's coins (aliasing falsification),
 *       and activation refuses to share the active store as the bg store.
 *   (b) REAL connect genesis->base — the background coins, after replaying every
 *       block into its OWN store, equal an INDEPENDENTLY-computed UTXO set (not
 *       empty, not a counter); the SPENT coin is gone.
 *   (c) ACCEPT — driving the background pass with the CORRECT assumeutxo hash
 *       flips the snapshot to validated.
 *   (d) ⭐ REJECT — driving it with a DELIBERATELY-WRONG assumed hash marks the
 *       snapshot invalid / surfaces a fatal error (the most important assertion:
 *       a wrong commitment must NEVER silently validate).
 *
 * Every run uses a UNIQUE temp dir (mkdtemp) for each LevelDB store so repeated
 * runs cannot reuse leftover DB state and false-green the falsification.
 */

import { describe, it, expect, beforeEach, afterEach } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  Chainstate,
  ChainstateStatus,
  activateSnapshotWithBackground,
  finishSnapshotActivation,
  BackgroundValidationResult,
  computeUTXOSetHash,
  type AssumeutxoData,
  type SnapshotActivation,
} from "../chain/snapshot.js";
import { ChainDB, DBPrefix } from "../storage/database.js";
import { REGTEST } from "../consensus/params.js";
import { getTxId, isCoinbase, type Transaction } from "../validation/tx.js";
import type { Block, BlockHeader } from "../validation/block.js";
import { UTXOManager, type Coin } from "../chain/utxo.js";
import { BufferReader } from "../wire/serialization.js";

// ─────────────────────────────────────────────────────────────────────────────
// Test chain construction
//
// Tiny genesis->base chain with a REAL spend so the background validator does
// genuine input-spending (not a counter). Base height = 2:
//   block 1: coinbase CB1 -> {CB1:0 = 50 BTC, script 0x51}
//   block 2: coinbase CB2 -> {CB2:0 = 50 BTC, script 0x52}
//            tx T spends CB1:0 -> {T:0 = 30 BTC (0x53), T:1 = 19 BTC (0x54)}
//
// Final UTXO set after connecting blocks 1..2 (CB1:0 SPENT in block 2):
//   {CB2:0, T:0, T:1}
// ─────────────────────────────────────────────────────────────────────────────

const COIN = 100_000_000n;

function dummyHeader(): BlockHeader {
  return {
    version: 1,
    prevBlock: Buffer.alloc(32),
    merkleRoot: Buffer.alloc(32),
    timestamp: 0,
    bits: 0x207fffff,
    nonce: 0,
  };
}

/** Coinbase tx with a unique scriptSig per height (so txids differ). */
function makeCoinbase(height: number, value: bigint, pkScript: Buffer): Transaction {
  return {
    version: 1,
    inputs: [
      {
        prevOut: { txid: Buffer.alloc(32), vout: 0xffffffff },
        scriptSig: Buffer.from([height & 0xff, (height >> 8) & 0xff, 0xaa]),
        sequence: 0xffffffff,
        witness: [],
      },
    ],
    outputs: [{ value, scriptPubKey: pkScript }],
    lockTime: 0,
  };
}

/** Non-coinbase tx spending a single prevout into the given outputs. */
function makeSpend(prevTxid: Buffer, prevVout: number, outs: { value: bigint; scriptPubKey: Buffer }[]): Transaction {
  return {
    version: 1,
    inputs: [
      {
        prevOut: { txid: prevTxid, vout: prevVout },
        scriptSig: Buffer.from([0x00]),
        sequence: 0xffffffff,
        witness: [],
      },
    ],
    outputs: outs,
    lockTime: 0,
  };
}

interface TestChain {
  blocks: Map<number, Block>;
  baseHeight: number;
  /** Ground-truth coins at base (computed by hand, NOT via the machinery). */
  expected: Map<string, Coin>;
  cb1Txid: Buffer;
}

function buildTestChain(): TestChain {
  const baseHeight = 2;

  const cb1 = makeCoinbase(1, 50n * COIN, Buffer.from([0x51]));
  const block1: Block = { header: dummyHeader(), transactions: [cb1] };
  const cb1Txid = getTxId(cb1);

  const cb2 = makeCoinbase(2, 50n * COIN, Buffer.from([0x52]));
  const spend = makeSpend(cb1Txid, 0, [
    { value: 30n * COIN, scriptPubKey: Buffer.from([0x53]) },
    { value: 19n * COIN, scriptPubKey: Buffer.from([0x54]) },
  ]);
  const block2: Block = { header: dummyHeader(), transactions: [cb2, spend] };
  const cb2Txid = getTxId(cb2);
  const spendTxid = getTxId(spend);

  const expected = new Map<string, Coin>();
  expected.set(`${cb2Txid.toString("hex")}:0`, {
    txOut: { value: 50n * COIN, scriptPubKey: Buffer.from([0x52]) },
    height: 2,
    isCoinbase: true,
  });
  expected.set(`${spendTxid.toString("hex")}:0`, {
    txOut: { value: 30n * COIN, scriptPubKey: Buffer.from([0x53]) },
    height: 2,
    isCoinbase: false,
  });
  expected.set(`${spendTxid.toString("hex")}:1`, {
    txOut: { value: 19n * COIN, scriptPubKey: Buffer.from([0x54]) },
    height: 2,
    isCoinbase: false,
  });

  return {
    blocks: new Map([
      [1, block1],
      [2, block2],
    ]),
    baseHeight,
    expected,
    cb1Txid,
  };
}

function getBlockFn(tc: TestChain): (height: number) => Promise<Block | null> {
  return async (height: number) => tc.blocks.get(height) ?? null;
}

/**
 * Replay the chain into a UTXOManager via REAL connection (spend inputs, add
 * outputs). Used to build the "active snapshot coins" reference store
 * independently of the machinery under test, and to derive the correct hash.
 */
async function replayChainInto(db: ChainDB, tc: TestChain): Promise<void> {
  const utxo = new UTXOManager(db);
  const cache = utxo.getCoinsViewCache();
  for (let h = 1; h <= tc.baseHeight; h++) {
    const block = tc.blocks.get(h)!;
    for (const tx of block.transactions) {
      const cb = isCoinbase(tx);
      if (!cb) {
        for (const input of tx.inputs) {
          const ok = await cache.spendCoin(input.prevOut);
          if (!ok) throw new Error(`reference replay: failed to spend at height ${h}`);
        }
      }
      const txid = getTxId(tx);
      for (let v = 0; v < tx.outputs.length; v++) {
        cache.addCoin(
          { txid, vout: v },
          { txOut: { value: tx.outputs[v].value, scriptPubKey: tx.outputs[v].scriptPubKey }, height: h, isCoinbase: cb },
          cb,
        );
      }
    }
  }
  await utxo.flush();
}

/** Scan all UTXOs from a ChainDB into a Map. */
async function scanUTXOs(db: ChainDB): Promise<Map<string, Coin>> {
  const out = new Map<string, Coin>();
  const utxoPrefix = Buffer.from([DBPrefix.UTXO]);
  const iterator = (db as any).db.iterator({
    gte: utxoPrefix,
    lt: Buffer.from([DBPrefix.UTXO + 1]),
  });
  try {
    for await (const [key, value] of iterator) {
      if (key.length !== 37) continue;
      const txid = key.subarray(1, 33);
      const vout = key.readUInt32LE(33);
      const reader = new BufferReader(value);
      const height = reader.readUInt32LE();
      const isCoinbase = reader.readUInt8() === 1;
      const amount = reader.readUInt64LE();
      const scriptPubKey = reader.readVarBytes();
      out.set(`${txid.toString("hex")}:${vout}`, {
        txOut: { value: amount, scriptPubKey },
        height,
        isCoinbase,
      });
    }
  } finally {
    await iterator.close();
  }
  return out;
}

describe("AssumeUTXO dual-chainstate (real background 2nd chainstate)", () => {
  let root: string;
  let openDBs: ChainDB[];
  let nextId: number;

  beforeEach(() => {
    // UNIQUE temp dir per test so leftover DB state can never false-green a run.
    root = mkdtempSync(join(tmpdir(), "hotbuns-dualcs-"));
    openDBs = [];
    nextId = 0;
  });

  afterEach(async () => {
    for (const db of openDBs) {
      await db.close().catch(() => {});
    }
    rmSync(root, { recursive: true, force: true });
  });

  /** Open a fresh ChainDB under a unique subdir of the per-test root. */
  async function freshDB(name: string): Promise<ChainDB> {
    const db = new ChainDB(join(root, `${name}-${nextId++}`));
    await db.open();
    openDBs.push(db);
    return db;
  }

  /** Build the active (snapshot) chainstate's coins + the correct base hash. */
  async function buildActiveSnapshot(tc: TestChain): Promise<{ active: ChainDB; correctHash: Buffer }> {
    const active = await freshDB("active");
    await replayChainInto(active, tc);
    const { hash } = await computeUTXOSetHash(active);
    return { active, correctHash: hash };
  }

  function makeSnapshotChainstate(active: ChainDB, baseHash: Buffer): Chainstate {
    const cs = new Chainstate(active, REGTEST, {
      snapshotBaseBlockHash: baseHash,
      status: ChainstateStatus.UNVALIDATED,
    });
    cs.tipHash = baseHash;
    cs.tipHeight = 2;
    return cs;
  }

  // ───────────────────────────────────────────────────────────────────────────
  // (a) SEPARATE store — aliasing falsification
  // ───────────────────────────────────────────────────────────────────────────

  it("(a) uses a SEPARATE store — an active-store write is NOT visible in the bg store; activation refuses an aliased store", async () => {
    const tc = buildTestChain();
    const { active, correctHash } = await buildActiveSnapshot(tc);
    const baseHash = Buffer.alloc(32, 0xba);
    const snapshotCS = makeSnapshotChainstate(active, baseHash);
    const au: AssumeutxoData = { height: tc.baseHeight, hashSerialized: correctHash, nChainTx: 0n, blockHash: baseHash };

    const bgDB = await freshDB("background");
    const activation = activateSnapshotWithBackground(snapshotCS, bgDB, au, getBlockFn(tc));

    // The bg store is a different object than the active store.
    expect(activation.background.backgroundDB()).not.toBe(active);
    expect(bgDB).not.toBe(active);

    // Write a sentinel coin into the ACTIVE store only.
    const sentinelTxid = Buffer.alloc(32, 0xde);
    await active.putUTXO(sentinelTxid, 7, { height: 1, coinbase: false, amount: 1n, scriptPubKey: Buffer.from([0x55]) });

    // It MUST NOT be visible in the background store (separate object).
    const seenInBg = await activation.background.backgroundDB().getUTXO(sentinelTxid, 7);
    expect(seenInBg).toBeNull();

    // And the activation refuses to share the active store as the bg store.
    expect(() => activateSnapshotWithBackground(snapshotCS, active, au, getBlockFn(tc))).toThrow(
      /background coins store must be separate/,
    );
  });

  // ───────────────────────────────────────────────────────────────────────────
  // (b) REAL connect genesis->base — bg coins == independently-computed set
  // ───────────────────────────────────────────────────────────────────────────

  it("(b) does REAL block connection genesis->base — bg store equals the independently-computed set, not empty/counter", async () => {
    const tc = buildTestChain();
    const { active, correctHash } = await buildActiveSnapshot(tc);
    const baseHash = Buffer.alloc(32, 0xba);
    const snapshotCS = makeSnapshotChainstate(active, baseHash);
    const au: AssumeutxoData = { height: tc.baseHeight, hashSerialized: correctHash, nChainTx: 0n, blockHash: baseHash };

    const bgDB = await freshDB("background");
    const activation = activateSnapshotWithBackground(snapshotCS, bgDB, au, getBlockFn(tc));

    // Before running, the bg store is genesis-empty (height 0, no coins).
    expect(activation.background.currentHeight()).toBe(0);
    const preCoins = await scanUTXOs(bgDB);
    expect(preCoins.size).toBe(0);

    // Drive the real genesis->base connection.
    const res = await activation.background.runToBase();
    expect(res).toBe(BackgroundValidationResult.VALIDATED);
    expect(activation.background.currentHeight()).toBe(tc.baseHeight);

    // The bg coins MUST equal the independently-computed final set, coin for coin.
    const got = await scanUTXOs(bgDB);
    expect(got.size).toBe(tc.expected.size);
    for (const [k, want] of tc.expected) {
      const g = got.get(k);
      expect(g).toBeDefined();
      expect(g!.txOut.value).toBe(want.txOut.value);
      expect(g!.height).toBe(want.height);
      expect(g!.isCoinbase).toBe(want.isCoinbase);
      expect(g!.txOut.scriptPubKey.equals(want.txOut.scriptPubKey)).toBe(true);
    }

    // The SPENT coin (CB1:0) is gone — the heart of "real connection vs counter".
    const cb1Coin = got.get(`${tc.cb1Txid.toString("hex")}:0`);
    expect(cb1Coin).toBeUndefined();
  });

  // ───────────────────────────────────────────────────────────────────────────
  // (c) ACCEPT — correct assumeutxo hash validates the snapshot
  // ───────────────────────────────────────────────────────────────────────────

  it("(c) ACCEPTS a correct assumeutxo hash — snapshot flips to validated", async () => {
    const tc = buildTestChain();
    const { active, correctHash } = await buildActiveSnapshot(tc);
    const baseHash = Buffer.alloc(32, 0xba);
    const snapshotCS = makeSnapshotChainstate(active, baseHash);
    const au: AssumeutxoData = { height: tc.baseHeight, hashSerialized: correctHash, nChainTx: 0n, blockHash: baseHash };

    const bgDB = await freshDB("background");
    const activation: SnapshotActivation = activateSnapshotWithBackground(snapshotCS, bgDB, au, getBlockFn(tc));

    // Snapshot starts UNVALIDATED (getchainstates validated=false).
    expect(snapshotCS.status).toBe(ChainstateStatus.UNVALIDATED);

    const res = await activation.background.runToBase();
    expect(res).toBe(BackgroundValidationResult.VALIDATED);
    expect(activation.background.error()).toBeNull();

    const { validated, error } = finishSnapshotActivation(activation);
    expect(validated).toBe(true);
    expect(error).toBeUndefined();
    expect(snapshotCS.status).toBe(ChainstateStatus.VALIDATED);
  });

  // ───────────────────────────────────────────────────────────────────────────
  // (d) ⭐ REJECT — a deliberately-wrong assumed hash must NEVER validate
  // ───────────────────────────────────────────────────────────────────────────

  it("(d) ⭐ REJECTS a deliberately-wrong assumeutxo hash — snapshot invalid + fatal error, NEVER silently validated", async () => {
    const tc = buildTestChain();
    const { active, correctHash } = await buildActiveSnapshot(tc);

    // Flip one bit of the correct hash to produce a deliberately-wrong commitment.
    const wrongHash = Buffer.from(correctHash);
    wrongHash[0] ^= 0x01;
    expect(wrongHash.equals(correctHash)).toBe(false);

    const baseHash = Buffer.alloc(32, 0xba);
    const snapshotCS = makeSnapshotChainstate(active, baseHash);
    const au: AssumeutxoData = { height: tc.baseHeight, hashSerialized: wrongHash, nChainTx: 0n, blockHash: baseHash };

    const bgDB = await freshDB("background");
    const activation = activateSnapshotWithBackground(snapshotCS, bgDB, au, getBlockFn(tc));

    const res = await activation.background.runToBase();
    expect(res).toBe(BackgroundValidationResult.INVALID);
    // The mismatch surfaces a fatal error (Core AbortNode).
    const runErr = activation.background.error();
    expect(runErr).not.toBeNull();
    expect(runErr!.message).toMatch(/mismatch/i);

    const { validated, error } = finishSnapshotActivation(activation);
    // ⭐ A wrong commitment must NEVER silently validate.
    expect(validated).toBe(false);
    expect(error).toBeDefined();
    expect(snapshotCS.status).toBe(ChainstateStatus.INVALID);
    expect(snapshotCS.status).not.toBe(ChainstateStatus.VALIDATED);
  });
});
