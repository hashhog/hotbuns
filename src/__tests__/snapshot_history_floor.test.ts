/**
 * snapshot_history_floor.test.ts — a node that started from a UTXO snapshot
 * and never fetched the block bodies below the snapshot base must say so the
 * way Bitcoin Core v31.1 does.
 *
 * Core, measured on regtest after `loadtxoutset` with bodies 1..base never
 * downloaded (staged-patches/done-fleet-declare-prune-floor/core-measurement.txt):
 *
 *   - getblock(pre-base) and getblock(base): -1
 *     "Block not available (not fully downloaded)"  (rpc/blockchain.cpp
 *     CheckBlockDataAvailability: "pruned data" only when the block was
 *     really pruned). An unknown hash stays -5 "Block not found".
 *   - getblockchaininfo: pruned:false, no pruneheight.
 *   - getchainstates: the snapshot chainstate carries snapshot_blockhash and
 *     validated:false.
 *   - localservices AND the services field of the version message a peer
 *     receives: NODE_NETWORK cleared, NODE_NETWORK_LIMITED kept
 *     (rpc/blockchain.cpp loadtxoutset RemoveLocalServices(NODE_NETWORK);
 *     init.cpp: no NODE_NETWORK while a historical chainstate is unfinished,
 *     which survives a restart).
 *
 * A genesis-synced node keeps NODE_NETWORK (control).
 *
 * The restart cases import ../chain/snapshot_origin.js dynamically so that,
 * on a tree without it, they fail by name instead of failing the file.
 */

import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import type { TCPSocketListener, Socket } from "bun";
import { mkdtemp, rm, readdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, dirname, basename } from "node:path";
import { ChainDB, BlockStatus } from "../storage/database.js";
import { REGTEST } from "../consensus/params.js";
import { ChainStateManager } from "../chain/state.js";
import { Mempool } from "../mempool/mempool.js";
import { FeeEstimator } from "../fees/estimator.js";
import { RPCServer, type RPCServerConfig } from "../rpc/server.js";
import {
  ChainstateManager,
  registerRegtestAssumeutxo,
  clearRegtestAssumeutxo,
} from "../chain/snapshot.js";
import { PeerManager, ServiceFlags } from "../p2p/manager.js";
import {
  type NetworkMessage,
  MESSAGE_HEADER_SIZE,
  parseHeader,
  deserializeMessage,
  serializeMessage,
  ipv4ToBuffer,
} from "../p2p/messages.js";
import { createTestBlock, mineRegtestBlock } from "../test/helpers.js";
import { getBlockHash } from "../validation/block.js";
import { serializeBlockHeader } from "../validation/block.js";

const REGTEST_BUILTIN_ASSUMEUTXO = new Map(REGTEST.assumeutxo ?? []);
const NOT_FULLY_DOWNLOADED = "Block not available (not fully downloaded)";

class MockHeaderSync {
  getBestHeader() { return null; }
  getHeader() { return undefined; }
  getHeaderByHeight() { return null; }
  async adoptChainTipAsBestHeader() {}
  async processHeaders() { return { success: true, requestMore: false, powValidatedHeaders: [] }; }
  getMedianTimePast() { return 0; }
}

/** Minimal v1 peer that records the version message it receives. */
class VersionCapture {
  private server: TCPSocketListener<undefined> | null = null;
  private sock: Socket<undefined> | null = null;
  private buf: Buffer = Buffer.alloc(0);
  port = 0;
  received: NetworkMessage[] = [];

  start(): void {
    this.server = Bun.listen<undefined>({
      hostname: "127.0.0.1",
      port: 0,
      socket: {
        open: (s) => { this.sock = s; },
        data: (s, d) => {
          this.sock = s;
          this.buf = Buffer.concat([this.buf, Buffer.from(d)]);
          while (this.buf.length >= MESSAGE_HEADER_SIZE) {
            const h = parseHeader(this.buf);
            if (!h) break;
            const total = MESSAGE_HEADER_SIZE + h.length;
            if (this.buf.length < total) break;
            const msg = deserializeMessage(h, this.buf.subarray(MESSAGE_HEADER_SIZE, total));
            this.buf = this.buf.subarray(total);
            this.received.push(msg);
            if (msg.type === "version") this.answer();
          }
        },
        close: () => { this.sock = null; },
        error: () => { this.sock = null; },
      },
    });
    this.port = this.server.port;
  }

  private answer(): void {
    const send = (m: NetworkMessage) =>
      this.sock?.write(serializeMessage(REGTEST.networkMagic, m));
    send({
      type: "version",
      payload: {
        version: 70016,
        services: 0x409n,
        timestamp: BigInt(Math.floor(Date.now() / 1000)),
        addrRecv: { services: 0n, ip: ipv4ToBuffer("127.0.0.1"), port: 0 },
        addrFrom: { services: 0x409n, ip: ipv4ToBuffer("127.0.0.1"), port: this.port },
        nonce: 77n,
        userAgent: "/capture:0.0.1/",
        startHeight: 0,
        relay: true,
      },
    });
    send({ type: "verack", payload: null });
  }

  versionServices(): bigint | null {
    const v = this.received.find((m) => m.type === "version");
    return v ? (v.payload as { services: bigint }).services : null;
  }

  stop(): void {
    this.sock?.end();
    this.server?.stop(true);
  }
}

async function waitFor(cond: () => boolean, ms = 3000): Promise<void> {
  const t0 = Date.now();
  while (!cond()) {
    if (Date.now() - t0 > ms) throw new Error("waitFor timeout");
    await new Promise((r) => setTimeout(r, 10));
  }
}

function callRPC(server: RPCServer, method: string, params: unknown[] = []) {
  const methods = (server as any).methods as Map<string, (p: unknown[]) => Promise<unknown>>;
  const h = methods.get(method);
  if (!h) throw new Error(`Method '${method}' not found`);
  return h(params);
}

async function rpcError(server: RPCServer, method: string, params: unknown[]) {
  try {
    await callRPC(server, method, params);
  } catch (e) {
    const err = e as { code?: number; message?: string };
    return { code: err.code, message: err.message };
  }
  return null;
}

const display = (h: Buffer) => Buffer.from(h).reverse().toString("hex");

interface Node {
  dir: string;
  db: ChainDB;
  chainState: ChainStateManager;
  peerManager: PeerManager;
  server: RPCServer;
}

async function openNode(dir: string): Promise<Node> {
  const db = new ChainDB(dir);
  await db.open();
  const chainState = new ChainStateManager(db, REGTEST);
  await chainState.load();
  const mempool = new Mempool(chainState.getUTXOManager(), REGTEST);
  const peerManager = new PeerManager({
    maxOutbound: 8,
    maxInbound: 8,
    params: REGTEST,
    bestHeight: chainState.getBestBlock().height,
    datadir: dir + "-p2p",
  });
  const config: RPCServerConfig = { port: 0, host: "127.0.0.1", noAuth: true };
  const server = new RPCServer(config, {
    chainState,
    mempool,
    peerManager,
    feeEstimator: new FeeEstimator(mempool),
    headerSync: new MockHeaderSync() as any,
    db,
    params: REGTEST,
    chainstateManager: new ChainstateManager(db, REGTEST),
  });
  return { dir, db, chainState, peerManager, server };
}

async function closeNode(n: Node): Promise<void> {
  await n.peerManager.stop().catch(() => {});
  await n.db.close().catch(() => {});
}

/** Connect `n` outbound to a capturing peer; return the services it sent. */
async function versionServicesSentBy(n: Node): Promise<bigint> {
  const cap = new VersionCapture();
  cap.start();
  try {
    await n.peerManager.connectPeer("127.0.0.1", cap.port);
    await waitFor(() => cap.versionServices() !== null);
    return cap.versionServices()!;
  } finally {
    cap.stop();
  }
}

async function localServices(n: Node): Promise<bigint> {
  const info = (await callRPC(n.server, "getnetworkinfo")) as Record<string, unknown>;
  return BigInt("0x" + (info.localservices as string));
}

const NETWORK = ServiceFlags.NODE_NETWORK;
const LIMITED = ServiceFlags.NODE_NETWORK_LIMITED;

describe("snapshot node without history answers like Core", () => {
  let scratch: string[] = [];
  let prevV2: string | undefined;

  async function scratchDir(tag: string): Promise<string> {
    const d = await mkdtemp(join(tmpdir(), `hotbuns-histfloor-${tag}-`));
    scratch.push(d);
    return d;
  }

  beforeEach(() => {
    // The capture peer speaks v1 only.
    prevV2 = process.env.HOTBUNS_BIP324_V2;
    process.env.HOTBUNS_BIP324_V2 = "0";
  });

  afterEach(async () => {
    if (prevV2 === undefined) delete process.env.HOTBUNS_BIP324_V2;
    else process.env.HOTBUNS_BIP324_V2 = prevV2;
    clearRegtestAssumeutxo(REGTEST);
    for (const [, au] of REGTEST_BUILTIN_ASSUMEUTXO) registerRegtestAssumeutxo(REGTEST, au);
    for (const d of scratch) {
      const parent = dirname(d);
      const sibs = await readdir(parent).catch(() => [] as string[]);
      await Promise.all(
        sibs
          .filter((s) => s.startsWith(basename(d)))
          .map((s) => rm(join(parent, s), { recursive: true, force: true }).catch(() => {})),
      );
    }
    scratch = [];
  });

  /**
   * Build a 5-block chain on a source node, dump a snapshot at its tip, and
   * register it as a regtest assumeutxo entry. Returns the headers + file.
   */
  async function makeSnapshot(n = 5) {
    const src = await openNode(await scratchDir("src"));
    const headers: Buffer[] = [];
    const hashes: Buffer[] = [];
    let prev = src.chainState.getBestBlock().hash;
    for (let h = 1; h <= n; h++) {
      const blk = mineRegtestBlock(createTestBlock(prev, h, [], REGTEST));
      await src.chainState.connectBlock(blk, h);
      prev = getBlockHash(blk.header);
      hashes.push(prev);
      headers.push(serializeBlockHeader(blk.header));
    }
    const snapPath = join(await scratchDir("snap"), "utxo.dat");
    const dump = (await callRPC(src.server, "dumptxoutset", [snapPath, "latest"])) as Record<string, unknown>;
    registerRegtestAssumeutxo(REGTEST, {
      height: n,
      hashSerialized: Buffer.from(dump.txoutset_hash as string, "hex").reverse(),
      nChainTx: BigInt(n + 1),
      blockHash: prev,
      baseHeader: headers[n - 1],
    });
    await closeNode(src);
    return { headers, hashes, snapPath, base: prev, baseHeight: n };
  }

  /** Fresh node that knows the headers (Core: submitheader) but no bodies. */
  async function headersOnlyNode(snap: Awaited<ReturnType<typeof makeSnapshot>>) {
    const node = await openNode(await scratchDir("snapnode"));
    for (let i = 0; i < snap.hashes.length; i++) {
      await node.db.putBlockIndex(
        snap.hashes[i],
        { height: i + 1, header: snap.headers[i], nTx: 0, status: BlockStatus.HEADER_VALID, dataPos: 0 },
        { writeHeightIndex: false },
      );
    }
    return node;
  }

  test("loadtxoutset without history: getblock(pre-base) is -1 'not fully downloaded' at every verbosity", async () => {
    const snap = await makeSnapshot();
    const node = await headersOnlyNode(snap);
    try {
      await callRPC(node.server, "loadtxoutset", [snap.snapPath]);
      for (const v of [0, 1, 2]) {
        const e = await rpcError(node.server, "getblock", [display(snap.hashes[0]), v]);
        expect(e).toEqual({ code: -1, message: NOT_FULLY_DOWNLOADED });
      }
      // The snapshot base block itself (Core: also "not fully downloaded").
      const eb = await rpcError(node.server, "getblock", [display(snap.base)]);
      expect(eb).toEqual({ code: -1, message: NOT_FULLY_DOWNLOADED });
      // A hash that is not in the index stays -5 "Block not found".
      const en = await rpcError(node.server, "getblock", ["11".repeat(32)]);
      expect(en).toEqual({ code: -5, message: "Block not found" });
      // getblockheader still works below the floor.
      const hdr = (await callRPC(node.server, "getblockheader", [display(snap.hashes[0])])) as Record<string, unknown>;
      expect(hdr.height).toBe(1);
      // Not a pruned node.
      const bci = (await callRPC(node.server, "getblockchaininfo")) as Record<string, unknown>;
      expect(bci.pruned).toBe(false);
      expect("pruneheight" in bci).toBe(false);
    } finally {
      await closeNode(node);
    }
  }, 30000);

  test("loadtxoutset without history: localservices and the sent version message drop NODE_NETWORK", async () => {
    const snap = await makeSnapshot();
    const node = await headersOnlyNode(snap);
    try {
      expect((await localServices(node)) & NETWORK).toBe(NETWORK);
      await callRPC(node.server, "loadtxoutset", [snap.snapPath]);
      const local = await localServices(node);
      expect(local & NETWORK).toBe(0n);
      expect(local & LIMITED).toBe(LIMITED);
      const sent = await versionServicesSentBy(node);
      expect(sent & NETWORK).toBe(0n);
      expect(sent & LIMITED).toBe(LIMITED);
      const cs = (await callRPC(node.server, "getchainstates")) as { chainstates: Array<Record<string, unknown>> };
      const snapCs = cs.chainstates[cs.chainstates.length - 1];
      expect(snapCs.snapshot_blockhash).toBe(display(snap.base));
      expect(snapCs.validated).toBe(false);
    } finally {
      await closeNode(node);
    }
  }, 30000);

  test("after a restart a snapshot node without history still drops NODE_NETWORK and reports the snapshot chainstate", async () => {
    const { applySnapshotHistoryServices } = await import("../chain/snapshot_origin.js");
    const snap = await makeSnapshot();
    const first = await headersOnlyNode(snap);
    await callRPC(first.server, "loadtxoutset", [snap.snapPath]);
    await closeNode(first);

    const node = await openNode(first.dir);
    try {
      await applySnapshotHistoryServices(node.db, REGTEST, node.peerManager);
      const local = await localServices(node);
      expect(local & NETWORK).toBe(0n);
      expect(local & LIMITED).toBe(LIMITED);
      const sent = await versionServicesSentBy(node);
      expect(sent & NETWORK).toBe(0n);
      const cs = (await callRPC(node.server, "getchainstates")) as { chainstates: Array<Record<string, unknown>> };
      const snapCs = cs.chainstates[cs.chainstates.length - 1];
      expect(snapCs.blocks).toBe(snap.baseHeight);
      expect(snapCs.snapshot_blockhash).toBe(display(snap.base));
      expect(snapCs.validated).toBe(false);
      const e = await rpcError(node.server, "getblock", [display(snap.hashes[0])]);
      expect(e).toEqual({ code: -1, message: NOT_FULLY_DOWNLOADED });
    } finally {
      await closeNode(node);
    }
  }, 30000);

  test("a datadir from before the snapshot record existed is recognised from its assumeutxo base", async () => {
    const { applySnapshotHistoryServices, readSnapshotOrigin } = await import("../chain/snapshot_origin.js");
    const snap = await makeSnapshot();
    const node = await headersOnlyNode(snap);
    try {
      // What the snapshot loader left behind on old datadirs: the base on the
      // active chain with nTx 0 and no body, and no record of the load. Header
      // sync may since have rewritten its status to HEADER_VALID alone.
      for (let i = 0; i < snap.hashes.length; i++) {
        await node.db.putBlockHashByHeight(i + 1, snap.hashes[i]);
      }
      await node.db.putBlockIndex(snap.base, {
        height: snap.baseHeight, header: snap.headers[snap.baseHeight - 1],
        nTx: 0, status: BlockStatus.HEADER_VALID, dataPos: 0,
      });
      const origin = await readSnapshotOrigin(node.db, REGTEST);
      expect(origin).not.toBeNull();
      expect(origin!.baseHeight).toBe(snap.baseHeight);
      expect(origin!.baseHash.equals(snap.base)).toBe(true);
      await applySnapshotHistoryServices(node.db, REGTEST, node.peerManager);
      expect((await localServices(node)) & NETWORK).toBe(0n);
    } finally {
      await closeNode(node);
    }
  }, 30000);

  test("control: a genesis-synced node keeps NODE_NETWORK and a single validated chainstate", async () => {
    const { applySnapshotHistoryServices, readSnapshotOrigin } = await import("../chain/snapshot_origin.js");
    const snap = await makeSnapshot();
    // The same chain, connected from genesis with bodies, crossing the
    // registered assumeutxo base height.
    const node = await openNode(await scratchDir("genesis"));
    try {
      let prev = node.chainState.getBestBlock().hash;
      for (let h = 1; h <= snap.baseHeight + 2; h++) {
        const blk = mineRegtestBlock(createTestBlock(prev, h, [], REGTEST));
        await node.chainState.connectBlock(blk, h);
        prev = getBlockHash(blk.header);
      }
      expect(await readSnapshotOrigin(node.db, REGTEST)).toBeNull();
      await applySnapshotHistoryServices(node.db, REGTEST, node.peerManager);
      expect((await localServices(node)) & NETWORK).toBe(NETWORK);
      expect((await versionServicesSentBy(node)) & NETWORK).toBe(NETWORK);
      const cs = (await callRPC(node.server, "getchainstates")) as { chainstates: Array<Record<string, unknown>> };
      expect(cs.chainstates.length).toBe(1);
      expect(cs.chainstates[0].validated).toBe(true);
      expect("snapshot_blockhash" in cs.chainstates[0]).toBe(false);
    } finally {
      await closeNode(node);
    }
  }, 30000);

  test("control: loadtxoutset on a node holding every body re-enables NODE_NETWORK once validated", async () => {
    const snap = await makeSnapshot();
    void snap;
    const node = await openNode(await scratchDir("full"));
    try {
      let prev = node.chainState.getBestBlock().hash;
      const n = 4;
      for (let h = 1; h <= n; h++) {
        const blk = mineRegtestBlock(createTestBlock(prev, h, [], REGTEST));
        await node.chainState.connectBlock(blk, h);
        prev = getBlockHash(blk.header);
      }
      const p = join(await scratchDir("fullsnap"), "u.dat");
      const dump = (await callRPC(node.server, "dumptxoutset", [p, "latest"])) as Record<string, unknown>;
      registerRegtestAssumeutxo(REGTEST, {
        height: n,
        hashSerialized: Buffer.from(dump.txoutset_hash as string, "hex").reverse(),
        nChainTx: BigInt(n + 1),
        blockHash: prev,
      });
      const r = (await callRPC(node.server, "loadtxoutset", [p])) as Record<string, unknown>;
      expect(r.validated).toBe(true);
      // Core init.cpp: background download complete and not pruning ->
      // NODE_NETWORK is advertised again.
      expect((await localServices(node)) & NETWORK).toBe(NETWORK);
    } finally {
      await closeNode(node);
    }
  }, 30000);
});
