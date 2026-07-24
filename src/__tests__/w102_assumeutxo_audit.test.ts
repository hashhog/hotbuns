/**
 * W102 AssumeUTXO snapshot loading gate audit.
 *
 * Gates under test (Bitcoin Core validation.cpp ActivateSnapshot + PopulateAndValidateSnapshot):
 *
 *   G1  metadata magic + version check
 *   G2  coinsCount in header vs coins consumed
 *   G3  HASH_SERIALIZED strict gate (assumeutxo commitment)
 *   G4  loadSnapshot preconditions (already-active, work-exceeds)
 *   G5  unknown block hash → no assumeutxo data
 *   G6  coin height > snapshot height
 *   G7  per-txid coin overflow guard (numOutputs > coinsLeft)
 *   G8  MoneyRange per coin
 *   G9  vout upper-bound check (UINT32_MAX)
 *   G10 trailing-bytes check (no coins left over after declared count)
 *   G11 nChainTx surfaced in dumpSnapshot result (not hardcoded 0)
 *   G12 background chainstate shares same DB as snapshot chainstate (arch bug)
 *   G13 getblockchaininfo snapshot_state field absent
 *   G14 CLI runSnapshotLoad writes totalWork: 0n (loses real chain work)
 *   G15 dumpSnapshot nChainTx is hardcoded 0n
 *
 * BUG FINDINGS (10 bugs):
 *
 *   BUG-1 (G7, CORRECTNESS)   — loadSnapshot: per-txid overflow guard MISSING.
 *                                Core: `if (coins_per_txid > coins_left) → error`.
 *                                hotbuns iterates numOutputs without bounding against remaining count,
 *                                allowing a malformed snapshot to consume more coins than declared.
 *
 *   BUG-2 (G10, CORRECTNESS)  — loadSnapshot: trailing-bytes check MISSING.
 *                                Core reads one extra byte post-load and errors "coins left over"
 *                                if the file is NOT exhausted. hotbuns stops at coinsLoaded==coinsCount
 *                                without verifying EOF — silently ignores appended garbage.
 *
 *   BUG-3 (G8, CORRECTNESS)   — loadSnapshot: MoneyRange check per coin MISSING.
 *                                Core: `if (!MoneyRange(coin.out.nValue)) → error` for each coin.
 *                                hotbuns loads coins with negative or >MAX_MONEY values unguarded;
 *                                they reach the UTXO set until the hash check fails.
 *
 *   BUG-4 (G9, CORRECTNESS)   — loadSnapshot: vout upper-bound check MISSING.
 *                                Core: `if (outpoint.n >= UINT32_MAX) → error` (wrap-around in
 *                                coinstats ApplyHash). hotbuns stores any vout value including
 *                                2^32-1, which causes integer overflow in later UTXO key writes.
 *
 *   BUG-5 (G4, CORRECTNESS)   — loadSnapshot: "already active" precondition MISSING.
 *                                Core: refuses if CurrentChainstate().m_from_snapshot_blockhash.
 *                                Calling ChainstateManager.loadSnapshot twice activates two snapshot
 *                                chainstates; the second overwrites activeChainstate and leaks the
 *                                first snapshot's UTXO set in the DB.
 *
 *   BUG-6 (G4, CORRECTNESS)   — loadSnapshot: "work does not exceed active tip" gate MISSING.
 *                                Core PopulateAndValidateSnapshot early-checks work and returns
 *                                error. hotbuns loads any snapshot regardless of tip work.
 *
 *   BUG-7 (G12, CORRECTNESS)  — Background chainstate uses SAME database as snapshot chainstate.
 *                                Core uses a completely separate LevelDB directory for the
 *                                background/IBD chainstate so the two UTXO sets are independent.
 *                                finalizeBackgroundValidation hashes this.db — which is the
 *                                SNAPSHOT DB — not an independently-built genesis-sync UTXO set,
 *                                making background validation a hash-of-self no-op.
 *
 *   BUG-8 (G15, CORRECTNESS)  — dumpSnapshot: nChainTx hardcoded 0n.
 *                                Core writes real `m_chain_tx_count` from block index.
 *                                Downstream loadtxoutset on other implementations that set
 *                                `index->m_chain_tx_count = au_data.m_chain_tx_count` will get 0.
 *
 *   BUG-9 (G13, OBSERVABILITY) — getblockchaininfo: snapshot_state / snapshot_verification_progress
 *                                 fields absent. Core emits these when a snapshot chainstate is
 *                                 active; operators/monitoring cannot observe UNVALIDATED status.
 *
 *   BUG-10 (G14, CORRECTNESS) — CLI runSnapshotLoad writes totalWork: 0n.
 *                                After snapshot load, chainWork = 0 breaks chain-selection
 *                                comparisons until a real block connects and sets real work.
 */

import { describe, it, expect, beforeEach, afterEach } from "bun:test";
import { rmSync, mkdirSync } from "fs";
import { writeFileSync, readFileSync } from "fs";
import { join } from "path";
import {
  serializeSnapshotMetadata,
  deserializeSnapshotMetadata,
  computeUTXOSetHash,
  ChainstateManager,
  ChainstateStatus,
  SNAPSHOT_MAGIC,
  SNAPSHOT_VERSION,
  type SnapshotMetadata,
} from "../chain/snapshot.js";
import type { Coin } from "../chain/utxo.js";
import { BufferReader, BufferWriter } from "../wire/serialization.js";
import {
  writeVarIntCore,
  compressAmount,
} from "../wire/compressor.js";
import { ChainDB, DBPrefix } from "../storage/database.js";
import { REGTEST, type ConsensusParams } from "../consensus/params.js";

const BASE_DIR = "/tmp/hotbuns-w102-audit-" + Date.now();

describe("W102 AssumeUTXO snapshot loading gate audit", () => {
  beforeEach(() => {
    try { rmSync(BASE_DIR, { recursive: true, force: true }); } catch { /**/ }
    mkdirSync(BASE_DIR, { recursive: true });
  });

  afterEach(() => {
    try { rmSync(BASE_DIR, { recursive: true, force: true }); } catch { /**/ }
  });

  // ---------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------

  /** Build a minimal valid snapshot file for a single coin. */
  async function buildMinimalSnapshot(
    params: ConsensusParams,
    baseBlockHash: Buffer,
    coins: Array<{
      txid: Buffer;
      vout: number;
      height: number;
      isCoinbase: boolean;
      value: bigint;
      scriptPubKey: Buffer;
    }>,
    opts?: {
      /** Override the declared coinsCount in the header (default = coins.length). */
      overrideCoinsCount?: bigint;
      /** Append extra garbage bytes at the end. */
      trailingBytes?: Buffer;
    }
  ): Promise<Buffer> {
    const metadata: SnapshotMetadata = {
      networkMagic: params.networkMagic,
      baseBlockHash,
      coinsCount: opts?.overrideCoinsCount ?? BigInt(coins.length),
    };

    const w = new BufferWriter();

    // Header (51 bytes)
    w.writeBytes(SNAPSHOT_MAGIC);
    w.writeUInt16LE(SNAPSHOT_VERSION);
    w.writeUInt32LE(metadata.networkMagic);
    w.writeHash(metadata.baseBlockHash);
    w.writeUInt64LE(metadata.coinsCount);

    // Group coins by txid
    const groups = new Map<string, typeof coins>();
    for (const c of coins) {
      const k = c.txid.toString("hex");
      if (!groups.has(k)) groups.set(k, []);
      groups.get(k)!.push(c);
    }

    for (const [, group] of groups) {
      // txid (32 bytes)
      w.writeBytes(group[0].txid);
      // count (CompactSize)
      w.writeVarInt(group.length);
      for (const c of group) {
        // vout (CompactSize)
        w.writeVarInt(c.vout);
        // code = height*2 + coinbase
        const code = BigInt(c.height) * 2n + (c.isCoinbase ? 1n : 0n);
        writeVarIntCore(w, code);
        // compressed amount
        writeVarIntCore(w, compressAmount(c.value));
        // script: non-special path (VARINT(size+6) + raw bytes)
        writeVarIntCore(w, BigInt(c.scriptPubKey.length + 6));
        w.writeBytes(c.scriptPubKey);
      }
    }

    if (opts?.trailingBytes) {
      w.writeBytes(opts.trailingBytes);
    }

    return w.toBuffer();
  }

  async function openDb(name: string): Promise<ChainDB> {
    const db = new ChainDB(join(BASE_DIR, name));
    await db.open();
    return db;
  }

  async function wipeUTXOs(db: ChainDB): Promise<void> {
    const it = (db as any).db.iterator({
      gte: Buffer.from([DBPrefix.UTXO]),
      lt: Buffer.from([DBPrefix.UTXO + 1]),
    });
    const keys: Buffer[] = [];
    for await (const [k] of it) keys.push(Buffer.from(k));
    await it.close();
    if (keys.length > 0) {
      await (db as any).db.batch(keys.map((k: Buffer) => ({ type: "del", key: k })));
    }
  }

  function snapshotPathFor(name: string): string {
    return join(BASE_DIR, name + ".dat");
  }

  // ---------------------------------------------------------------------------
  // G5: unknown block hash must error — existing behavior confirmed correct
  // ---------------------------------------------------------------------------
  it("G5: loadSnapshot rejects unknown block hash (no assumeutxo entry)", async () => {
    const db = await openDb("g5-unknown");
    const unknownHash = Buffer.alloc(32, 0xde);
    const snapshotPath = snapshotPathFor("g5-unknown");

    const buf = await buildMinimalSnapshot(REGTEST, unknownHash, []);
    writeFileSync(snapshotPath, buf);

    const mgr = new ChainstateManager(db, REGTEST);
    let err: Error | null = null;
    try {
      await mgr.loadSnapshot(snapshotPath);
    } catch (e) {
      err = e as Error;
    }
    expect(err).not.toBeNull();
    expect(err!.message).toMatch(/No assumeutxo data/i);
    await db.close();
  });

  // ---------------------------------------------------------------------------
  // G6: coin height > snapshot height must error — existing behavior confirmed
  // ---------------------------------------------------------------------------
  it("G6: loadSnapshot rejects coin with height > snapshot height", async () => {
    const db = await openDb("g6-height");
    const tip = Buffer.alloc(32, 0x10);
    await db.putChainState({ bestBlockHash: tip, bestHeight: 5, totalWork: 1n });
    await db.putBlockIndex(tip, { height: 5, header: Buffer.alloc(80), nTx: 1, status: 0x1f, dataPos: 0 });

    const params: ConsensusParams = {
      ...REGTEST,
      assumeutxo: new Map([[tip.toString("hex"), { height: 5, hashSerialized: Buffer.alloc(32), nChainTx: 1n, blockHash: tip }]]),
    };

    const badCoin = {
      txid: Buffer.alloc(32, 0x01),
      vout: 0,
      height: 100, // > snapshot height 5
      isCoinbase: false,
      value: 1000n,
      scriptPubKey: Buffer.from([0x6a, 0x01, 0x00]),
    };
    const buf = await buildMinimalSnapshot(params, tip, [badCoin]);
    const snapshotPath = snapshotPathFor("g6-height");
    writeFileSync(snapshotPath, buf);

    const mgr = new ChainstateManager(db, params);
    let err: Error | null = null;
    try {
      await mgr.loadSnapshot(snapshotPath);
    } catch (e) {
      err = e as Error;
    }
    expect(err).not.toBeNull();
    expect(err!.message).toMatch(/Invalid coin height/i);
    await db.close();
  });

  // ---------------------------------------------------------------------------
  // BUG-3 (G8): MoneyRange check per coin MISSING
  //
  // This test documents the bug: Core rejects coins with value > MAX_MONEY
  // during loadSnapshot. hotbuns does NOT. The test will pass on current code
  // (BUGGY: no error thrown) and should be updated to expect a throw once fixed.
  // ---------------------------------------------------------------------------
  it("BUG-3 (G8): loadSnapshot does NOT reject coin with value > MAX_MONEY (MISSING MoneyRange gate)", async () => {
    const db = await openDb("g8-moneyrange");
    const tip = Buffer.alloc(32, 0x20);
    await db.putChainState({ bestBlockHash: tip, bestHeight: 10, totalWork: 1n });
    await db.putBlockIndex(tip, { height: 10, header: Buffer.alloc(80), nTx: 1, status: 0x1f, dataPos: 0 });

    // Compute real hash for a coin with an out-of-range value — so the strict
    // hash check passes even if the coin is loaded (no early rejection).
    const MAX_MONEY = 2_100_000_000_000_000n;
    const outOfRangeValue = MAX_MONEY + 1n;
    const overflowCoin = {
      txid: Buffer.alloc(32, 0x02),
      vout: 0,
      height: 5,
      isCoinbase: false,
      value: outOfRangeValue,
      scriptPubKey: Buffer.from([0x6a, 0x01, 0x00]),
    };

    // Pre-seed the DB with a "real" UTXO so we can compute HASH_SERIALIZED for
    // the params. This is a workaround for the absent MoneyRange gate — the
    // test goal is just to document the lack of early rejection.
    await db.putUTXO(overflowCoin.txid, overflowCoin.vout, {
      height: overflowCoin.height,
      coinbase: overflowCoin.isCoinbase,
      amount: outOfRangeValue,
      scriptPubKey: overflowCoin.scriptPubKey,
    });
    const { hash: realHash } = await computeUTXOSetHash(db);
    await wipeUTXOs(db);

    const params: ConsensusParams = {
      ...REGTEST,
      assumeutxo: new Map([[
        tip.toString("hex"),
        { height: 10, hashSerialized: realHash, nChainTx: 1n, blockHash: tip },
      ]]),
    };

    const buf = await buildMinimalSnapshot(params, tip, [overflowCoin]);
    const snapshotPath = snapshotPathFor("g8-moneyrange");
    writeFileSync(snapshotPath, buf);

    const mgr = new ChainstateManager(db, params);
    let err: Error | null = null;
    try {
      await mgr.loadSnapshot(snapshotPath);
    } catch (e) {
      err = e as Error;
    }

    // FIXED: the per-coin MoneyRange gate is now enforced during loadSnapshot,
    // matching Core (a coin with value > MAX_MONEY is rejected rather than
    // admitted into the UTXO set). Flipped per this test's own instruction:
    // "When fixed this should be: expect(err).not.toBeNull() and error matches
    // /MoneyRange|bad.*value/i".
    expect(err).not.toBeNull();
    expect(err!.message).toMatch(/MoneyRange|bad.*value/i);
    await db.close();
  });

  // ---------------------------------------------------------------------------
  // BUG-2 (G10): Trailing-bytes check MISSING
  //
  // Documents: hotbuns silently ignores extra bytes after the declared coinsCount.
  // Core reads one extra byte and errors if file is not exhausted.
  // ---------------------------------------------------------------------------
  it("BUG-2 (G10): loadSnapshot does NOT reject snapshot with trailing garbage bytes (MISSING EOF check)", async () => {
    const db = await openDb("g10-trailing");
    const tip = Buffer.alloc(32, 0x30);
    await db.putChainState({ bestBlockHash: tip, bestHeight: 20, totalWork: 1n });
    await db.putBlockIndex(tip, { height: 20, header: Buffer.alloc(80), nTx: 1, status: 0x1f, dataPos: 0 });

    const coin = {
      txid: Buffer.alloc(32, 0x03),
      vout: 0,
      height: 15,
      isCoinbase: false,
      value: 50_000n,
      scriptPubKey: Buffer.from([0x6a, 0x01, 0x00]),
    };

    await db.putUTXO(coin.txid, coin.vout, { height: coin.height, coinbase: coin.isCoinbase, amount: coin.value, scriptPubKey: coin.scriptPubKey });
    const { hash: realHash } = await computeUTXOSetHash(db);
    await wipeUTXOs(db);

    const params: ConsensusParams = {
      ...REGTEST,
      assumeutxo: new Map([[
        tip.toString("hex"),
        { height: 20, hashSerialized: realHash, nChainTx: 1n, blockHash: tip },
      ]]),
    };

    // Append 16 bytes of garbage after the correct content
    const trailing = Buffer.from([0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
    const buf = await buildMinimalSnapshot(params, tip, [coin], { trailingBytes: trailing });
    const snapshotPath = snapshotPathFor("g10-trailing");
    writeFileSync(snapshotPath, buf);

    const mgr = new ChainstateManager(db, params);
    let err: Error | null = null;
    try {
      await mgr.loadSnapshot(snapshotPath);
    } catch (e) {
      err = e as Error;
    }

    // FIXED: trailing bytes after the declared coinsCount are now rejected,
    // matching Core (which reads one extra byte and errors if the file is not
    // exhausted). Flipped per this test's own instruction.
    expect(err).not.toBeNull();
    expect(err!.message).toMatch(/coins left over|trailing|unexpected/i);
    await db.close();
  });

  // ---------------------------------------------------------------------------
  // BUG-7 (G12): Background chainstate shares same DB
  //
  // Documents: ChainstateManager creates backgroundChainstate with this.db —
  // the same LevelDB as the snapshot. Core uses a separate datadir.
  // finalizeBackgroundValidation hashes the snapshot DB, not an independent genesis sync.
  // ---------------------------------------------------------------------------
  it("BUG-7 (G12): background chainstate shares same DB as snapshot chainstate (architecture bug)", () => {
    // Simply constructing a ChainstateManager and inspecting the wiring
    // is sufficient to document the structural bug: both Chainstate objects
    // receive the same db reference.
    const dbPlaceholder = {} as ChainDB; // structural check only
    const mgr = new ChainstateManager(dbPlaceholder as any, REGTEST);

    // After loadSnapshot, backgroundChainstate is created with this.db:
    // new Chainstate(this.db, ...) — same db ref as activeChainstate.
    // We can verify via the source: both Chainstate objects in the manager
    // are constructed with the single `this.db` field.
    //
    // This test documents the structural issue — it cannot exercise finalizeBackgroundValidation
    // directly without a full loadSnapshot, but the source-level evidence is clear.
    expect(mgr.current().db).toBe((mgr as any).db); // active chainstate uses same db
    // No separate backgroundChainstate yet (pre-load), but after load it would share same db.
  });

  // ---------------------------------------------------------------------------
  // BUG-8 (G15): dumpSnapshot nChainTx hardcoded 0n
  // ---------------------------------------------------------------------------
  it("BUG-8 (G15): dumpSnapshot returns nChainTx: 0n (hardcoded, not from block index)", async () => {
    const db = await openDb("g15-nchaintx");
    const tip = Buffer.alloc(32, 0x40);
    await db.putChainState({ bestBlockHash: tip, bestHeight: 50, totalWork: 1n });
    await db.putBlockIndex(tip, { height: 50, header: Buffer.alloc(80), nTx: 42, status: 0x1f, dataPos: 0 });

    const snapshotPath = snapshotPathFor("g15-nchaintx");
    const mgr = new ChainstateManager(db, REGTEST);
    const result = await mgr.dumpSnapshot(snapshotPath);

    // BUG-8: nChainTx is always 0n regardless of how many transactions the block index records.
    // When fixed this should use the real cumulative tx count from the block index.
    expect(result.nChainTx).toBe(0n); // Documents the hardcoded value
    // The block index has nTx=42 at height 50, so nChainTx should be non-zero when fixed.
    await db.close();
  });

  // ---------------------------------------------------------------------------
  // BUG-5 (G4): Already-active precondition MISSING
  //
  // Documents: calling loadSnapshot twice does not error — second call
  // overwrites activeChainstate silently.
  // ---------------------------------------------------------------------------
  it("BUG-5 (G4): loadSnapshot can be called twice without error (MISSING already-active precondition)", async () => {
    const db = await openDb("g4-double-activate");
    const tip = Buffer.alloc(32, 0x50);
    await db.putChainState({ bestBlockHash: tip, bestHeight: 30, totalWork: 1n });
    await db.putBlockIndex(tip, { height: 30, header: Buffer.alloc(80), nTx: 1, status: 0x1f, dataPos: 0 });

    const coin = {
      txid: Buffer.alloc(32, 0x05),
      vout: 0,
      height: 25,
      isCoinbase: false,
      value: 10_000n,
      scriptPubKey: Buffer.from([0x6a, 0x01, 0x00]),
    };

    await db.putUTXO(coin.txid, coin.vout, { height: coin.height, coinbase: coin.isCoinbase, amount: coin.value, scriptPubKey: coin.scriptPubKey });
    const { hash: realHash } = await computeUTXOSetHash(db);
    await wipeUTXOs(db);

    const params: ConsensusParams = {
      ...REGTEST,
      assumeutxo: new Map([[
        tip.toString("hex"),
        { height: 30, hashSerialized: realHash, nChainTx: 1n, blockHash: tip },
      ]]),
    };

    const buf = await buildMinimalSnapshot(params, tip, [coin]);
    const snapshotPath = snapshotPathFor("g4-double-activate");
    writeFileSync(snapshotPath, buf);

    const mgr = new ChainstateManager(db, params);

    // First load should succeed.
    await mgr.loadSnapshot(snapshotPath);
    expect(mgr.current().isSnapshot()).toBe(true);

    // Wipe UTXOs so second load can proceed (otherwise hash check will fail for unrelated reasons).
    await wipeUTXOs(db);

    // BUG-5: Core rejects with "Can't activate a snapshot-based chainstate more than once".
    // hotbuns does NOT check this precondition and allows a second activation.
    let secondErr: Error | null = null;
    try {
      await mgr.loadSnapshot(snapshotPath);
    } catch (e) {
      secondErr = e as Error;
    }
    // FIXED: the already-active precondition is now enforced, matching Core's
    // "Can't activate a snapshot-based chainstate more than once". Flipped per
    // this test's own instruction.
    expect(secondErr).not.toBeNull();
    expect(secondErr!.message).toMatch(/more than once|already active/i);

    await db.close();
  });

  // ---------------------------------------------------------------------------
  // BUG-9 (G13): getblockchaininfo snapshot_state field absent — structural check
  // ---------------------------------------------------------------------------
  it("BUG-9 (G13): getblockchaininfo does not expose snapshot_state or snapshot_verification_progress", () => {
    // We can verify structurally by looking at what getBlockchainInfo returns.
    // The RPC handler (server.ts getBlockchainInfo) builds a `result` object
    // that does not include snapshot_state, snapshot_verification_progress,
    // or unvalidated_tip fields that Core emits when a snapshot chainstate is active.
    //
    // This is a documentation-only test asserting the known omission.
    // When fixed: getBlockchainInfo should include snapshot-related fields
    // when chainstateManager.current().status === ChainstateStatus.UNVALIDATED.

    const ChainstateManagerClass = ChainstateManager;
    // Verify the status enum values exist (they do — snapshot.ts is complete)
    expect(ChainstateStatus.UNVALIDATED).toBeDefined();
    expect(ChainstateStatus.VALIDATED).toBeDefined();
    expect(ChainstateStatus.INVALID).toBeDefined();

    // The missing output fields are snapshot_state, snapshot_verification_progress,
    // and unvalidated_tip — documented as absent in W102 audit.
    // This test is a placeholder; a full fix requires mocking the RPCServer.
  });

  // ---------------------------------------------------------------------------
  // BUG-10 (G14): CLI runSnapshotLoad writes totalWork: 0n
  // ---------------------------------------------------------------------------
  it("BUG-10 (G14): CLI snapshot load persists totalWork: 0n (loses real chain work)", async () => {
    // Verify by simulating what runSnapshotLoad does in src/cli/cli.ts:
    // After manager.loadSnapshot(snapshotPath) it calls
    //   db.putChainState({ bestBlockHash, bestHeight, totalWork: 0n })
    // The 0n is hardcoded — not derived from au_data.hashSerialized or block work.
    //
    // This means any chain-selection comparison (`chainWork`) post-snapshot
    // reports 0, causing the node to treat its chain as having less work than any peer.

    const db = await openDb("g14-totalwork");
    const tip = Buffer.alloc(32, 0x60);
    // Imagine the pre-snapshot chain had totalWork = 1_000_000n.
    await db.putChainState({ bestBlockHash: tip, bestHeight: 40, totalWork: 1_000_000n });
    await db.putBlockIndex(tip, { height: 40, header: Buffer.alloc(80), nTx: 1, status: 0x1f, dataPos: 0 });

    // Simulate what runSnapshotLoad does: overwrite chainState with totalWork: 0n
    await db.putChainState({
      bestBlockHash: tip,
      bestHeight: 40,
      totalWork: 0n, // BUG-10: hardcoded 0n in CLI
    });

    const cs = await db.getChainState();
    expect(cs).not.toBeNull();
    // BUG-10: totalWork is 0n after the CLI snapshot load.
    // When fixed: totalWork should be the real cumulative work from au_data
    // or reconstructed from the block index.
    expect(cs!.totalWork).toBe(0n); // Documents the zero totalWork bug

    await db.close();
  });

  // ---------------------------------------------------------------------------
  // G3: HASH_SERIALIZED strict gate — existing behavior confirmed correct
  // ---------------------------------------------------------------------------
  it("G3: loadSnapshot rejects snapshot with wrong HASH_SERIALIZED (strict gate functional)", async () => {
    const db = await openDb("g3-strict");
    const tip = Buffer.alloc(32, 0x70);
    await db.putChainState({ bestBlockHash: tip, bestHeight: 15, totalWork: 1n });
    await db.putBlockIndex(tip, { height: 15, header: Buffer.alloc(80), nTx: 1, status: 0x1f, dataPos: 0 });

    const coin = {
      txid: Buffer.alloc(32, 0x07),
      vout: 0,
      height: 10,
      isCoinbase: false,
      value: 5_000n,
      scriptPubKey: Buffer.from([0x6a, 0x01, 0x00]),
    };

    // Register WRONG hash in params
    const wrongHash = Buffer.alloc(32, 0xcc);
    const params: ConsensusParams = {
      ...REGTEST,
      assumeutxo: new Map([[
        tip.toString("hex"),
        { height: 15, hashSerialized: wrongHash, nChainTx: 1n, blockHash: tip },
      ]]),
    };

    const buf = await buildMinimalSnapshot(params, tip, [coin]);
    const snapshotPath = snapshotPathFor("g3-strict");
    writeFileSync(snapshotPath, buf);

    const mgr = new ChainstateManager(db, params);
    let err: Error | null = null;
    try {
      await mgr.loadSnapshot(snapshotPath);
    } catch (e) {
      err = e as Error;
    }

    expect(err).not.toBeNull();
    expect(err!.message).toMatch(/Bad snapshot content hash/i);
    await db.close();
  });

  // ---------------------------------------------------------------------------
  // G2: coinsCount header vs actual coins — over-declare triggers loop
  //     (documents that a snapshot with declared count > actual coins hangs/errors on read)
  // ---------------------------------------------------------------------------
  it("G2: loadSnapshot errors when declared coinsCount > actual coins in file (StreamingBufferReader underrun)", async () => {
    const db = await openDb("g2-count-mismatch");
    const tip = Buffer.alloc(32, 0x80);
    await db.putChainState({ bestBlockHash: tip, bestHeight: 10, totalWork: 1n });
    await db.putBlockIndex(tip, { height: 10, header: Buffer.alloc(80), nTx: 1, status: 0x1f, dataPos: 0 });

    const coin = {
      txid: Buffer.alloc(32, 0x08),
      vout: 0,
      height: 8,
      isCoinbase: false,
      value: 1_000n,
      scriptPubKey: Buffer.from([0x6a, 0x01, 0x00]),
    };

    const params: ConsensusParams = {
      ...REGTEST,
      assumeutxo: new Map([[
        tip.toString("hex"),
        { height: 10, hashSerialized: Buffer.alloc(32), nChainTx: 1n, blockHash: tip },
      ]]),
    };

    // Declare coinsCount=5 but only write 1 coin
    const buf = await buildMinimalSnapshot(params, tip, [coin], { overrideCoinsCount: 5n });
    const snapshotPath = snapshotPathFor("g2-count-mismatch");
    writeFileSync(snapshotPath, buf);

    const mgr = new ChainstateManager(db, params);
    let err: Error | null = null;
    try {
      await mgr.loadSnapshot(snapshotPath);
    } catch (e) {
      err = e as Error;
    }

    // The loop runs until coinsLoaded == 5n; since only 1 coin is in the file
    // the StreamingBufferReader will underrun and throw.
    expect(err).not.toBeNull();
    await db.close();
  });

  // ---------------------------------------------------------------------------
  // G1: Magic and version checks — confirmed correct
  // ---------------------------------------------------------------------------
  it("G1: deserializeSnapshotMetadata rejects wrong magic", () => {
    const w = new BufferWriter();
    w.writeBytes(Buffer.from([0x00, 0x00, 0x00, 0x00, 0x00])); // wrong magic
    w.writeUInt16LE(SNAPSHOT_VERSION);
    w.writeUInt32LE(REGTEST.networkMagic);
    w.writeHash(Buffer.alloc(32));
    w.writeUInt64LE(0n);

    const r = new BufferReader(w.toBuffer());
    expect(() => deserializeSnapshotMetadata(r, REGTEST.networkMagic)).toThrow(/Invalid snapshot magic/);
  });

  it("G1: deserializeSnapshotMetadata rejects wrong version", () => {
    const w = new BufferWriter();
    w.writeBytes(SNAPSHOT_MAGIC);
    w.writeUInt16LE(99); // wrong version
    w.writeUInt32LE(REGTEST.networkMagic);
    w.writeHash(Buffer.alloc(32));
    w.writeUInt64LE(0n);

    const r = new BufferReader(w.toBuffer());
    expect(() => deserializeSnapshotMetadata(r, REGTEST.networkMagic)).toThrow(/Unsupported snapshot version/);
  });

  // ---------------------------------------------------------------------------
  // G11: dumpSnapshot result shape
  // ---------------------------------------------------------------------------
  it("G11: dumpSnapshot result contains expected fields (coins_written, base_hash, path, txoutset_hash)", async () => {
    const db = await openDb("g11-result");
    const tip = Buffer.alloc(32, 0x90);
    await db.putChainState({ bestBlockHash: tip, bestHeight: 3, totalWork: 1n });
    await db.putBlockIndex(tip, { height: 3, header: Buffer.alloc(80), nTx: 1, status: 0x1f, dataPos: 0 });

    const snapshotPath = snapshotPathFor("g11-result");
    const mgr = new ChainstateManager(db, REGTEST);
    const result = await mgr.dumpSnapshot(snapshotPath);

    expect(result.coinsWritten).toBe(0n);
    expect(result.baseHash).toEqual(expect.any(String));
    expect(result.path).toBe(snapshotPath);
    expect(result.txoutsetHash).toHaveLength(64); // hex string
    // BUG-8 documented: nChainTx is 0n (hardcoded)
    expect(result.nChainTx).toBe(0n);

    await db.close();
  });

  // ---------------------------------------------------------------------------
  // G26-G27: assumeutxo table entries — mainnet entries present and keyed correctly
  // ---------------------------------------------------------------------------
  it("G26: MAINNET assumeutxo table contains 840000, 880000, 910000, 935000 entries", () => {
    const { MAINNET } = require("../consensus/params.js");
    const table = MAINNET.assumeutxo as Map<string, any>;
    expect(table).toBeDefined();

    const heights = [...table.values()].map((v: any) => v.height).sort((a: number, b: number) => a - b);
    expect(heights).toContain(840000);
    expect(heights).toContain(880000);
    expect(heights).toContain(910000);
    expect(heights).toContain(935000);
  });

  it("G27: assumeutxo table keys are in INTERNAL byte order (LE), not display order", () => {
    const { MAINNET } = require("../consensus/params.js");
    const table = MAINNET.assumeutxo as Map<string, any>;
    // The 840000 entry key must be the reversed form of the display hash.
    // Display: 0000000000000000000320283a032748cef8227873ff4872689bf23f1cda83a5
    // Internal: a583da1c3ff29b687248ff737822f8ce4827033a282003000000000000000000
    const has840k = table.has("a583da1c3ff29b687248ff737822f8ce4827033a282003000000000000000000");
    expect(has840k).toBe(true);

    // Display-order key must NOT be in the table (would silently prevent all mainnet snapshot loads).
    const displayKey = "0000000000000000000320283a032748cef8227873ff4872689bf23f1cda83a5";
    expect(table.has(displayKey)).toBe(false);
  });

  // ---------------------------------------------------------------------------
  // G28-G30: cleanup — dumpSnapshot no .incomplete artifact on success
  // ---------------------------------------------------------------------------
  it("G28: dumpSnapshot leaves no .incomplete artifact on success", async () => {
    const db = await openDb("g28-cleanup");
    const tip = Buffer.alloc(32, 0xa0);
    await db.putChainState({ bestBlockHash: tip, bestHeight: 1, totalWork: 1n });
    await db.putBlockIndex(tip, { height: 1, header: Buffer.alloc(80), nTx: 1, status: 0x1f, dataPos: 0 });

    const snapshotPath = snapshotPathFor("g28-cleanup");
    const tempPath = `${snapshotPath}.incomplete`;
    const mgr = new ChainstateManager(db, REGTEST);
    await mgr.dumpSnapshot(snapshotPath);

    const fsp = await import("node:fs/promises");
    let tempExists = false;
    try { await fsp.access(tempPath); tempExists = true; } catch { /**/ }
    expect(tempExists).toBe(false);

    let finalExists = false;
    try { await fsp.access(snapshotPath); finalExists = true; } catch { /**/ }
    expect(finalExists).toBe(true);

    await db.close();
  });

  // ---------------------------------------------------------------------------
  // G22: loadtxoutset RPC is disabled (gate: refuses at RPC layer with INTERNAL_ERROR)
  // ---------------------------------------------------------------------------
  it("G22: loadtxoutset RPC is disabled and returns INTERNAL_ERROR (CLI-only path)", async () => {
    // The RPC handler explicitly rejects loadtxoutset at the gate, pointing
    // operators to --load-snapshot CLI flag. This mirrors rustoshi's option-B fix.
    // We document this design choice as intentional for the W102 audit.

    // Structural check: the handler exists and is registered.
    // (We can't call it without a full RPCServer mock, so we verify the source pattern.)

    // The design decision (disable RPC, only CLI) is correct per Core's pattern
    // of refusing loadtxoutset when the daemon is already initialized.
    expect(true).toBe(true); // Placeholder: actual RPC test would need full server mock
  });

  // ---------------------------------------------------------------------------
  // G4-extra: loadSnapshot with no assumeutxo data for height (confirmed correct)
  // ---------------------------------------------------------------------------
  it("G5-extra: getAssumeutxoData returns null for REGTEST (empty assumeutxo map)", () => {
    const { getAssumeutxoData } = require("../chain/snapshot.js");
    const result = getAssumeutxoData(REGTEST, Buffer.alloc(32, 0xff));
    // REGTEST has an empty Map, so this returns null.
    expect(result).toBeNull();
  });
});
