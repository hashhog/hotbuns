/**
 * loadtxoutset must own the chain for the whole snapshot activation.
 *
 * Core: loadtxoutset -> ChainstateManager::ActivateSnapshot swaps the coins
 * view under LOCK(::cs_main) (validation.cpp), so no block connects and no
 * flush runs while the active chainstate is being replaced. hotbuns' equivalent
 * of that lock is BlockSync.beginExclusiveChainOp (connect loop paused and the
 * in-flight connect drained), which dumptxoutset and gettxoutsetinfo already
 * take, plus blockSubmissionPaused so submitblock is refused for the window.
 *
 * Before the fix loadtxoutset took neither: loadSnapshot rewrote the coins
 * keyspace and the chain-state label while BlockSync's connect loop and its
 * flushes could still run against it.
 */
import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ChainDB } from "../storage/database.js";
import { REGTEST } from "../consensus/params.js";
import { ChainStateManager } from "../chain/state.js";
import { Mempool } from "../mempool/mempool.js";
import { FeeEstimator } from "../fees/estimator.js";
import { RPCServer, type RPCServerDeps } from "../rpc/server.js";
import { ChainstateManager } from "../chain/snapshot.js";

class MockPeerManager {
  getConnectedPeers() { return []; }
  getPeerCount() { return 0; }
  broadcast() {}
  removeLocalServices() {}
  addLocalServices() {}
}
class MockHeaderSync {
  getBestHeader() { return null; }
  getHeader() { return null; }
  getHeaderByHeight() { return null; }
  getMedianTimePast() { return 0; }
  async adoptChainTipAsBestHeader() {}
}

/** BlockSync stand-in that records the order of lock calls. */
class FakeBlockSync {
  events: string[] = [];
  begins = 0;
  ends = 0;
  held = 0;
  /** Block connect in flight for 100 ms after construction. */
  inFlight = true;
  constructor() {
    setTimeout(() => { this.inFlight = false; }, 100);
  }
  pauseForUTXOScan() {}
  resumeAfterUTXOScan() {}
  async beginExclusiveChainOp() {
    this.begins++;
    this.held++;
    this.events.push("begin");
    while (this.inFlight) await new Promise((r) => setTimeout(r, 5));
  }
  endExclusiveChainOp() {
    this.ends++;
    this.held--;
    this.events.push("end");
  }
  advanceFrontierPast() {
    this.events.push(`frontier(held=${this.held})`);
  }
}

describe("loadtxoutset holds the exclusive chain op", () => {
  let dir: string;
  let db: ChainDB;
  let server: RPCServer;
  let blockSync: FakeBlockSync;
  let manager: ChainstateManager;

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "hotbuns-loadtxo-excl-"));
    db = new ChainDB(dir);
    await db.open();
    const chainState = new ChainStateManager(db, REGTEST);
    await chainState.load();
    const mempool = new Mempool(chainState.getUTXOManager(), REGTEST);
    blockSync = new FakeBlockSync();
    manager = new ChainstateManager(db, REGTEST);
    const deps: RPCServerDeps = {
      chainState,
      mempool,
      peerManager: new MockPeerManager() as any,
      feeEstimator: new FeeEstimator(mempool),
      headerSync: new MockHeaderSync() as any,
      db,
      params: REGTEST,
      chainstateManager: manager,
      blockSync: blockSync as any,
    };
    server = new RPCServer({ port: 0, host: "127.0.0.1", noAuth: true }, deps);
  });

  afterEach(async () => {
    await db.close();
    await rm(dir, { recursive: true, force: true }).catch(() => {});
  });

  test("activation runs inside begin/end and submitblock is paused for it", async () => {
    const s = server as any;
    const baseHash = Buffer.alloc(32, 0x5a);
    let observed: { held: number; inFlight: boolean; submitPaused: boolean } | null = null;
    (manager as any).loadSnapshot = async () => {
      observed = {
        held: blockSync.held,
        inFlight: blockSync.inFlight,
        submitPaused: s.blockSubmissionPaused,
      };
      blockSync.events.push("loadSnapshot");
      return { baseBlockHash: baseHash, baseHeight: 7, coinsLoaded: 3n };
    };
    // Chain-state writes after loadSnapshot must be inside the lock too.
    const realPut = db.putChainState.bind(db);
    (db as any).putChainState = async (st: any) => {
      blockSync.events.push(`putChainState(held=${blockSync.held})`);
      return realPut(st);
    };
    (manager as any).startBackgroundValidation = async () => {
      blockSync.events.push("bgValidation");
      return null;
    };

    const result = await s.methods.get("loadtxoutset")(["/nonexistent.snapshot"]);
    expect(result.base_height).toBe(7);

    expect(blockSync.begins).toBe(1);
    expect(blockSync.ends).toBe(1);
    expect(observed).toEqual({ held: 1, inFlight: false, submitPaused: true });
    expect(blockSync.events).toEqual([
      "begin",
      "loadSnapshot",
      "putChainState(held=1)",
      "frontier(held=1)",
      "end",
      "bgValidation",
    ]);
    expect(s.blockSubmissionPaused).toBe(false);
  });

  test("the lock is released and submitblock un-paused when loadSnapshot throws", async () => {
    const s = server as any;
    let heldAtLoad = -1;
    (manager as any).loadSnapshot = async () => {
      heldAtLoad = blockSync.held;
      blockSync.events.push("loadSnapshot");
      throw new Error("assumeutxo: unrecognized base");
    };

    await expect(
      s.methods.get("loadtxoutset")(["/nonexistent.snapshot"]),
    ).rejects.toThrow("unrecognized base");

    expect(blockSync.begins).toBe(1);
    expect(heldAtLoad).toBe(1);
    expect(blockSync.ends).toBe(1);
    expect(blockSync.held).toBe(0);
    expect(blockSync.events).toEqual(["begin", "loadSnapshot", "end"]);
    expect(s.blockSubmissionPaused).toBe(false);
  });

  test("a submitblock-pause already in force is restored, not cleared", async () => {
    const s = server as any;
    s.blockSubmissionPaused = true;
    (manager as any).loadSnapshot = async () => {
      throw new Error("bad snapshot");
    };
    await expect(
      s.methods.get("loadtxoutset")(["/nonexistent.snapshot"]),
    ).rejects.toThrow("bad snapshot");
    expect(s.blockSubmissionPaused).toBe(true);
  });
});
