/**
 * gettxoutsetinfo must read a coin set that matches ONE height.
 *
 * Core holds cs_main for the whole of GetUTXOStats. hotbuns' equivalent is the
 * chain lock: block-connect is paused AND the in-flight connect is waited for
 * (BlockSync.beginExclusiveChainOp). pauseForUTXOScan alone only stops the NEXT
 * block, so the flush + coin walk could interleave with a block mid-connect and
 * report a coin set that mixes two heights under one bestblock label.
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
}
class MockHeaderSync {
  getBestHeader() { return null; }
  getHeader() { return null; }
  getHeaderByHeight() { return null; }
  getMedianTimePast() { return 0; }
}

/** BlockSync stand-in with a block connect that is mid-flight for 150 ms. */
class FakeBlockSync {
  inFlight = true;
  paused = 0;
  constructor() {
    setTimeout(() => { this.inFlight = false; }, 150);
  }
  pauseForUTXOScan() { this.paused++; }
  resumeAfterUTXOScan() { this.paused--; }
  async beginExclusiveChainOp() {
    this.paused++;
    while (this.inFlight) await new Promise((r) => setTimeout(r, 5));
  }
  endExclusiveChainOp() { this.paused--; }
}

describe("gettxoutsetinfo vs a connecting chain", () => {
  let dir: string;
  let db: ChainDB;
  let server: RPCServer;
  let blockSync: FakeBlockSync;

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "hotbuns-gtxosi-"));
    db = new ChainDB(dir);
    await db.open();
    const chainState = new ChainStateManager(db, REGTEST);
    await chainState.load();
    const mempool = new Mempool(chainState.getUTXOManager(), REGTEST);
    blockSync = new FakeBlockSync();
    const deps: RPCServerDeps = {
      chainState,
      mempool,
      peerManager: new MockPeerManager() as any,
      feeEstimator: new FeeEstimator(mempool),
      headerSync: new MockHeaderSync() as any,
      db,
      params: REGTEST,
      chainstateManager: new ChainstateManager(db, REGTEST),
      blockSync: blockSync as any,
    };
    server = new RPCServer({ port: 0, host: "127.0.0.1", noAuth: true }, deps);
  });

  afterEach(async () => {
    await db.close();
    await rm(dir, { recursive: true, force: true }).catch(() => {});
  });

  test("flush and coin walk run only after the in-flight connect has finished", async () => {
    const s = server as any;
    let inFlightAtFlush: boolean | null = null;
    s.forceFlushChainstateToDisk = async () => {
      inFlightAtFlush = blockSync.inFlight;
    };
    const handler = s.methods.get("gettxoutsetinfo");
    await handler([]);
    expect(inFlightAtFlush).toBe(false);
    expect(blockSync.paused).toBe(0);
  });
});
