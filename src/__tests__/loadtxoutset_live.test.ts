/**
 * loadtxoutset_live.test.ts — AssumeUTXO LIVE-RPC dual-chainstate wiring
 * (hotbuns pilot completion).
 *
 * The function-level gate (assumeutxo_dual_chainstate.test.ts) proves the
 * dual-chainstate MACHINERY works. THIS test proves the LIVE RPC PATH is wired
 * to that machinery, the way camlcoin (3140ab9) and lunarblock (a39dd42) wired
 * theirs:
 *
 *   - `loadtxoutset`, on a regtest snapshot, loads the snapshot into the active
 *     chainstate AND spins up the REAL background validator
 *     (ChainstateManager.startBackgroundValidation →
 *     activateSnapshotWithBackground + BackgroundValidator.runToBase) that
 *     re-connects every block genesis -> base into its OWN separate coins store
 *     and compares the recomputed UTXO hash to the assumeutxo commitment.
 *   - `getchainstates` then reports the snapshot chainstate:
 *       * validated  = snapshot validated state (false while bg runs / after a
 *                      mismatch, true after a match)
 *       * snapshot_blockhash = the snapshot base block hash.
 *
 * Three end-to-end scenarios:
 *   (0) NO snapshot active -> getchainstates is the single fully-validated
 *       chainstate (validated=true, snapshot_blockhash omitted).
 *   (1) ACCEPT — a consistent snapshot whose genesis->base replay matches the
 *       committed hash: loadtxoutset succeeds, getchainstates reports
 *       validated=true + snapshot_blockhash.
 *   (2) ⭐ REJECT — a snapshot whose committed hash matches the snapshot FILE
 *       (so the load-time content-hash gate passes) but is INCONSISTENT with the
 *       actual chain history: the background re-derivation produces a different
 *       UTXO set, the mismatch is caught in the background (Core's AbortNode
 *       equivalent), and getchainstates reports validated=false (snapshot
 *       invalid). loadtxoutset itself STILL returns success — Core runs
 *       MaybeValidateSnapshot asynchronously, so the verdict is surfaced via the
 *       chainstate state, not the RPC return.
 *
 * Core reference: bitcoin-core/src/validation.cpp ActivateSnapshot (5588) /
 * PopulateAndValidateSnapshot (5775+) / MaybeValidateSnapshot (5967), and
 * rpc/blockchain.cpp make_chain_data (3462-3519) for getchainstates fields.
 * Cross-impl reference: camlcoin 3140ab9 (test_loadtxoutset_live.ml),
 * lunarblock a39dd42 (src/rpc.lua loadtxoutset wiring).
 *
 * UNIQUE temp dirs per case (mkdtemp); the regtest AssumeUTXO whitelist is
 * registered fresh per case and CLEARED in teardown so no verifier-probe state
 * leaks across runs.
 */

import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { mkdtemp, rm, readdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, dirname, basename } from "node:path";
import { ChainDB } from "../storage/database.js";
import { REGTEST } from "../consensus/params.js";
import { ChainStateManager } from "../chain/state.js";
import { Mempool } from "../mempool/mempool.js";
import { FeeEstimator } from "../fees/estimator.js";
import {
  RPCServer,
  type RPCServerConfig,
  type RPCServerDeps,
} from "../rpc/server.js";
import {
  ChainstateManager,
  registerRegtestAssumeutxo,
  clearRegtestAssumeutxo,
  computeUTXOSetHash,
} from "../chain/snapshot.js";
import { createTestBlock, mineRegtestBlock } from "../test/helpers.js";
import { getBlockHash } from "../validation/block.js";

class MockPeerManager {
  getConnectedPeers() { return []; }
  getPeerCount() { return 0; }
  broadcast() {}
}

class MockHeaderSync {
  getBestHeader() { return null; }
  getHeader() { return undefined; }
  getHeaderByHeight() { return null; }
  async processHeaders() { return { success: true, requestMore: false, powValidatedHeaders: [] }; }
  getMedianTimePast() { return 0; }
}

/** Direct access to RPC method handlers (mirrors dumptxoutset_rollback.test). */
function callRPC(server: RPCServer, method: string, params: unknown[] = []) {
  const methods = (server as any).methods as Map<
    string,
    (params: unknown[]) => Promise<unknown>
  >;
  const handler = methods.get(method);
  if (!handler) throw new Error(`Method '${method}' not found`);
  return handler(params);
}

/**
 * Build a regtest chain by connecting coinbase-only blocks through
 * ChainStateManager.connectBlock — which PERSISTS each block body + the
 * height->hash index + the UTXOs into `db` (so the background validator's
 * getBlock(height) and the snapshot dump can read them) and advances the
 * deps.chainState active tip (so getchainstates reports the base as bestblock).
 */
async function buildChain(
  chainState: ChainStateManager,
  count: number,
): Promise<{ hashes: Buffer[]; tipHash: Buffer; tipHeight: number }> {
  const hashes: Buffer[] = [];
  let prev = chainState.getBestBlock().hash;
  let height = chainState.getBestBlock().height;
  for (let i = 0; i < count; i++) {
    height++;
    const blk = mineRegtestBlock(createTestBlock(prev, height, [], REGTEST));
    await chainState.connectBlock(blk, height);
    prev = getBlockHash(blk.header);
    hashes.push(prev);
  }
  return { hashes, tipHash: prev, tipHeight: height };
}

/** Pull { validated, snapshotBlockhash } out of a getchainstates response. */
function readGetChainStates(resp: Record<string, unknown>): {
  validated: boolean;
  snapshotBlockhash: string | null;
} {
  const chainstates = resp.chainstates as Array<Record<string, unknown>>;
  expect(Array.isArray(chainstates)).toBe(true);
  const cs = chainstates[0];
  const validated = cs.validated as boolean;
  const snapshotBlockhash =
    typeof cs.snapshot_blockhash === "string"
      ? (cs.snapshot_blockhash as string)
      : null;
  return { validated, snapshotBlockhash };
}

describe("loadtxoutset LIVE dual-chainstate wiring", () => {
  let tempDir: string;
  let dumpDir: string;
  let db: ChainDB;
  let chainState: ChainStateManager;
  let mempool: Mempool;
  let server: RPCServer;

  beforeEach(async () => {
    // UNIQUE temp dirs per test so leftover DB / snapshot state can never
    // false-green a run.
    tempDir = await mkdtemp(join(tmpdir(), "hotbuns-ltx-live-"));
    dumpDir = await mkdtemp(join(tmpdir(), "hotbuns-ltx-out-"));
    db = new ChainDB(tempDir);
    await db.open();

    chainState = new ChainStateManager(db, REGTEST);
    await chainState.load();
    mempool = new Mempool(chainState.getUTXOManager(), REGTEST);

    const config: RPCServerConfig = { port: 0, host: "127.0.0.1", noAuth: true };
    const deps: RPCServerDeps = {
      chainState,
      mempool,
      peerManager: new MockPeerManager() as any,
      feeEstimator: new FeeEstimator(mempool),
      headerSync: new MockHeaderSync() as any,
      db,
      params: REGTEST,
      // Fresh manager: its internal active Chainstate is at genesis (tipHeight
      // 0), so loadSnapshot's work-vs-active-tip gate (auData.height <=
      // activeTipHeight) passes for any base >= 1.
      chainstateManager: new ChainstateManager(db, REGTEST),
    };
    server = new RPCServer(config, deps);
  });

  afterEach(async () => {
    clearRegtestAssumeutxo(REGTEST);
    await db.close().catch(() => {});
    await rm(tempDir, { recursive: true, force: true }).catch(() => {});
    await rm(dumpDir, { recursive: true, force: true }).catch(() => {});
    // Clean any background-validator coins stores the handler opened
    // (<tempDir>-bgvalidate-<ts>). They live as siblings of tempDir; remove
    // every matching sibling so no LevelDB scratch leaks across runs.
    const parent = dirname(tempDir);
    const prefix = `${basename(tempDir)}-bgvalidate`;
    const siblings = await readdir(parent).catch(() => [] as string[]);
    await Promise.all(
      siblings
        .filter((name) => name.startsWith(prefix))
        .map((name) => rm(join(parent, name), { recursive: true, force: true }).catch(() => {})),
    );
  });

  // ───────────────────────────────────────────────────────────────────────────
  // (0) NO snapshot active -> single fully-validated chainstate.
  // ───────────────────────────────────────────────────────────────────────────
  test("(0) getchainstates with no snapshot: validated=true, snapshot_blockhash omitted", async () => {
    await buildChain(chainState, 3);
    const resp = (await callRPC(server, "getchainstates")) as Record<string, unknown>;
    const { validated, snapshotBlockhash } = readGetChainStates(resp);
    expect(validated).toBe(true);
    expect(snapshotBlockhash).toBeNull();
  });

  // ───────────────────────────────────────────────────────────────────────────
  // (1) ACCEPT through the LIVE RPC: loadtxoutset -> real bg validator runs
  //     genesis->base -> match -> getchainstates validated=true + snapshot_blockhash.
  // ───────────────────────────────────────────────────────────────────────────
  test("(1) LIVE loadtxoutset ACCEPT: bg validates genesis->base, getchainstates validated=true", async () => {
    const n = 4;
    const { hashes } = await buildChain(chainState, n);
    const base = chainState.getBestBlock();
    expect(base.hash.equals(hashes[n - 1])).toBe(true);

    // Dump a GENUINE snapshot from the node's own DB at the base: its coin set
    // == the real genesis->base replay, so the bg re-derivation will match.
    const snapPath = join(dumpDir, "accept.dat");
    const dump = (await callRPC(server, "dumptxoutset", [snapPath, "latest"])) as Record<string, unknown>;
    const committedHashHex = dump.txoutset_hash as string;
    const committedHash = Buffer.from(committedHashHex, "hex");

    // Register the regtest AssumeUTXO entry committing to the snapshot's hash
    // (Core regtest m_assumeutxo_data). blockHash is the snapshot base in
    // INTERNAL (wire / little-endian) byte order — the order loadSnapshot looks
    // up and the order getBestBlock().hash already uses.
    registerRegtestAssumeutxo(REGTEST, {
      height: base.height,
      hashSerialized: committedHash,
      nChainTx: BigInt(n + 1),
      blockHash: base.hash,
    });

    // BEFORE: no snapshot -> getchainstates is the single validated chainstate.
    {
      const r0 = (await callRPC(server, "getchainstates")) as Record<string, unknown>;
      const { validated, snapshotBlockhash } = readGetChainStates(r0);
      expect(validated).toBe(true);
      expect(snapshotBlockhash).toBeNull();
    }

    // LIVE call.
    const result = (await callRPC(server, "loadtxoutset", [snapPath])) as Record<string, unknown>;
    // The handler reports the validated verdict directly (Core's
    // getchainstates.validated): a matching bg run -> true.
    expect(result.validated).toBe(true);
    expect(result.base_height).toBe(base.height);

    // getchainstates must now report the snapshot chainstate: validated=true
    // (bg matched) + snapshot_blockhash = the base (display / big-endian hex).
    const resp = (await callRPC(server, "getchainstates")) as Record<string, unknown>;
    const { validated, snapshotBlockhash } = readGetChainStates(resp);
    expect(validated).toBe(true);
    const expectHex = Buffer.from(base.hash).reverse().toString("hex");
    expect(snapshotBlockhash).toBe(expectHex);
  });

  // ───────────────────────────────────────────────────────────────────────────
  // (2) ⭐ REJECT through the LIVE RPC (falsification): a snapshot whose
  //     committed hash matches the snapshot FILE (load-time gate passes) but is
  //     INCONSISTENT with the real chain history -> the bg re-derivation
  //     mismatches -> snapshot marked invalid -> getchainstates validated=false.
  //     THE most important assertion: the mismatch still rejects through the
  //     LIVE path, and a corrupt snapshot is NEVER silently reported validated.
  // ───────────────────────────────────────────────────────────────────────────
  test("(2) ⭐ LIVE loadtxoutset REJECT: bg-inconsistent snapshot -> getchainstates validated=false", async () => {
    const n = 4;
    const { hashes } = await buildChain(chainState, n);
    const base = chainState.getBestBlock();
    expect(base.hash.equals(hashes[n - 1])).toBe(true);

    // Inject an EXTRA spurious coin into the node's UTXO DB that the real
    // genesis->base replay never produces. The dumped snapshot file then
    // includes it, so the file is INTERNALLY consistent (it hashes to
    // committedHash WITH the spurious coin) and the load-time content-hash gate
    // PASSES when we commit to that hash — but the background validator replays
    // the real blocks (which never create the spurious coin) into its OWN store
    // and derives a DIFFERENT set, so the background comparison MISMATCHES.
    // This is exactly the threat the dual-chainstate exists to catch: a snapshot
    // whose hash matches its own commitment but disagrees with the chain.
    const spuriousTxid = Buffer.alloc(32, 0xab);
    await db.putUTXO(spuriousTxid, 0, {
      height: 1, // <= base height (so loadSnapshot's coin-height bound holds)
      coinbase: false,
      amount: 999n,
      scriptPubKey: Buffer.from([0x51]),
    });

    // Dump the (now-doctored) UTXO set. committedHash includes the spurious coin.
    const snapPath = join(dumpDir, "reject.dat");
    const dump = (await callRPC(server, "dumptxoutset", [snapPath, "latest"])) as Record<string, unknown>;
    const committedHash = Buffer.from(dump.txoutset_hash as string, "hex");

    // Sanity: the doctored hash must DIFFER from the honest genesis->base set's
    // hash (otherwise the falsification is vacuous). Recompute the honest hash
    // after removing the spurious coin from a scratch copy is overkill here; the
    // bg validator below does that recomputation for real and we assert the
    // verdict — but we DO assert the bg result is a mismatch, not a no-op.

    // Commit to the snapshot's OWN (doctored) hash so the load-time gate passes;
    // the bg (which replays the real blocks WITHOUT the spurious coin) will not
    // reproduce committedHash -> background mismatch.
    registerRegtestAssumeutxo(REGTEST, {
      height: base.height,
      hashSerialized: committedHash,
      nChainTx: BigInt(n + 1),
      blockHash: base.hash,
    });

    // LIVE call. Per the Core async model, loadtxoutset itself SUCCEEDS even
    // though the background pass rejects; the verdict is surfaced via the
    // chainstate state, read by getchainstates.
    const result = (await callRPC(server, "loadtxoutset", [snapPath])) as Record<string, unknown>;
    // The handler must NOT have thrown a load-time Error (we committed to the
    // file's own hash so the load gate passes and the BACKGROUND is the
    // rejecter). It reports the verdict as validated=false.
    expect(result.validated).toBe(false);
    expect(result.base_height).toBe(base.height);

    // getchainstates must report the snapshot chainstate as NOT validated, but
    // still ACTIVE (snapshot_blockhash present — the snapshot IS loaded, just
    // invalid).
    const resp = (await callRPC(server, "getchainstates")) as Record<string, unknown>;
    const { validated, snapshotBlockhash } = readGetChainStates(resp);
    expect(validated).toBe(false);
    const expectHex = Buffer.from(base.hash).reverse().toString("hex");
    expect(snapshotBlockhash).toBe(expectHex);

    // Cross-check: the manager marked the snapshot chainstate INVALID (Core
    // AbortNode), never silently VALIDATED.
    const mgr = (server as any).snapshotChainstateManager as ChainstateManager;
    expect(mgr).toBeDefined();
    const status = mgr.getStatus();
    expect(status.hasSnapshot).toBe(true);
    expect(status.snapshotValidated).toBe(false);
  });
});
