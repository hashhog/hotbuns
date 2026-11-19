/**
 * cffix-hotbuns-getblocktxn-pacing: the getblocktxn handler started one
 * detached handleGetBlockTxn per message, each a full-block DB read and
 * parse, with no per-peer limit, no send-pause and no stop on disconnect.
 * The getdata path had already been fixed for the same shape (audit H1,
 * getdata-serve-queue.test.ts).
 *
 * Core handles GETBLOCKTXN inside the per-peer ProcessMessage loop
 * (net_processing.cpp): ProcessMessages takes one message per pass, does
 * not take one while fPauseSend is set, and works the getdata queue first,
 * so a peer's getblocktxn replies are serial and paced by its own reading.
 *
 * These tests drive the registered "getblocktxn" message handler, the same
 * entry point the P2P layer uses. Regtest only: a temp ChainDB and a local
 * stub peer.
 */

import { describe, expect, test } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { REGTEST } from "../consensus/params.js";
import { ChainDB } from "../storage/database.js";
import * as blocks from "../sync/blocks.js";
import { BlockSync, GETDATA_MAX_SEND_BUFFER } from "../sync/blocks.js";

// Added by the fix; the fallback keeps this file compiling and running on master.
const GETBLOCKTXN_QUEUED_INDEXES_MAX: number =
  (blocks as any).GETBLOCKTXN_QUEUED_INDEXES_MAX ?? 4 * 65_536;
import { HeaderSync } from "../sync/headers.js";
import { InvType } from "../p2p/messages.js";
import { deserializeBlock, getBlockHash } from "../validation/block.js";
import { BufferReader } from "../wire/serialization.js";

const TEST_TIMEOUT = 30_000;
const N = 100;

interface Harness {
  dir: string;
  db: ChainDB;
  sync: any;
  hash: Buffer;
  handlers: Map<string, (peer: any, msg: any) => void>;
  reads: () => number;
  maxInFlight: () => number;
}

async function open(): Promise<Harness> {
  const dir = await mkdtemp(join(tmpdir(), "hotbuns-getblocktxn-pacing-"));
  const db = new ChainDB(join(dir, "blocks.db"));
  await db.open();
  const raw = REGTEST.genesisBlock;
  const hash = getBlockHash(deserializeBlock(new BufferReader(raw)).header);
  await db.putBlock(hash, raw);

  // Count reads and how many are in flight at once; a short delay makes
  // overlapping reads observable.
  let reads = 0;
  let inFlight = 0;
  let maxInFlight = 0;
  const getBlock = db.getBlock.bind(db);
  (db as any).getBlock = async (h: Buffer) => {
    reads++;
    inFlight++;
    if (inFlight > maxInFlight) maxInFlight = inFlight;
    try {
      await new Promise((r) => setTimeout(r, 2));
      return await getBlock(h);
    } finally {
      inFlight--;
    }
  };

  const sync: any = new BlockSync(db, REGTEST, new HeaderSync(db, REGTEST));
  // The block is the tip, well within MAX_BLOCKTXN_DEPTH.
  sync.state.nextHeightToProcess = 1;
  sync.headerSync.getHeader = (x: Buffer) => (x.equals(hash) ? { height: 0 } : undefined);

  const handlers = new Map<string, (peer: any, msg: any) => void>();
  sync.registerWithPeerManager({
    onMessage(type: string, fn: (peer: any, msg: any) => void) {
      handlers.set(type, fn);
    },
  });
  return {
    dir,
    db,
    sync,
    hash,
    handlers,
    reads: () => reads,
    maxInFlight: () => maxInFlight,
  };
}

async function close(h: Harness): Promise<void> {
  // Let any detached work settle before the DB goes away.
  await new Promise((r) => setTimeout(r, 50));
  await h.db.close();
  await rm(h.dir, { recursive: true, force: true });
}

function stubPeer() {
  const sent: any[] = [];
  const peer = {
    host: "127.0.0.1",
    port: 18444,
    state: "connected" as string,
    unsent: 0,
    send(msg: any) {
      sent.push(msg);
      return true;
    },
    pendingSendBytes() {
      return this.unsent;
    },
  };
  return { peer, sent };
}

function deliver(h: Harness, peer: any, n: number): void {
  const fn = h.handlers.get("getblocktxn")!;
  for (let i = 0; i < n; i++) {
    fn(peer, { type: "getblocktxn", payload: { blockHash: h.hash, indexes: [0] } });
  }
}

async function waitFor(cond: () => boolean, ms: number, label: string): Promise<void> {
  const start = Date.now();
  while (!cond()) {
    if (Date.now() - start > ms) throw new Error(`${label}: timed out after ${ms} ms`);
    await new Promise((r) => setTimeout(r, 5));
  }
}

describe("cffix: getblocktxn is paced like getdata", () => {
  test(
    "100 getblocktxn from a send-paused peer start at most one block read",
    async () => {
      const h = await open();
      try {
        const { peer, sent } = stubPeer();
        peer.unsent = GETDATA_MAX_SEND_BUFFER * 2;
        deliver(h, peer, N);
        await new Promise((r) => setTimeout(r, 300));
        // Master: 100 concurrent reads and 100 replies into a full buffer.
        expect(h.maxInFlight()).toBeLessThanOrEqual(1);
        expect(h.reads()).toBeLessThanOrEqual(1);
        expect(sent.length).toBe(0);

        // Once the peer reads, every request is answered, one read at a time.
        peer.unsent = 0;
        await waitFor(() => sent.length === N, 10_000, "all replies");
        expect(sent.every((m) => m.type === "blocktxn")).toBe(true);
        expect(h.reads()).toBe(N);
        expect(h.maxInFlight()).toBe(1);
      } finally {
        await close(h);
      }
    },
    TEST_TIMEOUT,
  );

  test(
    "a peer that disconnects gets no further getblocktxn reads",
    async () => {
      const h = await open();
      try {
        const { peer } = stubPeer();
        deliver(h, peer, N);
        await waitFor(() => h.reads() >= 3, 10_000, "first reads");
        const atDisconnect = h.reads();
        peer.state = "disconnected";
        h.handlers.get("__disconnect__")!(peer, { type: "__disconnect__" });
        await new Promise((r) => setTimeout(r, 300));
        expect(h.reads() - atDisconnect).toBeLessThanOrEqual(1);
        expect(h.reads()).toBeLessThan(N);
      } finally {
        await close(h);
      }
    },
    TEST_TIMEOUT,
  );

  test(
    "a send-paused peer cannot park unbounded getblocktxn indexes on its queue",
    async () => {
      const h = await open();
      try {
        const { peer, sent } = stubPeer();
        peer.unsent = GETDATA_MAX_SEND_BUFFER * 2;
        const fn = h.handlers.get("getblocktxn")!;
        const big = Array.from({ length: 60_000 }, (_, i) => i);
        for (let i = 0; i < 50; i++) {
          fn(peer, { type: "getblocktxn", payload: { blockHash: h.hash, indexes: big } });
        }
        await new Promise((r) => setTimeout(r, 100));
        // Whatever this peer has parked is held to the budget (on master
        // nothing is parked; each request is read at once instead).
        const q = h.sync.getDataQueues.get(peer);
        const parked = q
          ? q.items.slice(q.head).reduce(
              (n: number, it: any) => n + (it.getBlockTxn ? it.getBlockTxn.indexes.length : 0),
              0,
            )
          : 0;
        expect(parked).toBeLessThanOrEqual(GETBLOCKTXN_QUEUED_INDEXES_MAX);
        if (q) expect(q.getBlockTxnIndexes).toBe(parked);

        // The parked requests are still served once the peer reads; the
        // budget then frees up for new ones.
        peer.unsent = 0;
        await waitFor(() => !h.sync.getDataServing.get(peer), 10_000, "queue drained");
        expect(sent.length).toBe(0); // the indexes are out of range: no reply
        deliver(h, peer, 1);
        await waitFor(() => sent.length === 1, 10_000, "reply after drain");
        expect(sent[0].type).toBe("blocktxn");
      } finally {
        await close(h);
      }
    },
    TEST_TIMEOUT,
  );

  test(
    "getblocktxn waits behind the peer's earlier getdata, in order (Core: one queue)",
    async () => {
      const h = await open();
      try {
        const { peer, sent } = stubPeer();
        h.handlers.get("getdata")!(peer, {
          type: "getdata",
          payload: { inventory: [{ type: InvType.MSG_WITNESS_BLOCK, hash: h.hash }] },
        });
        deliver(h, peer, 1);
        await waitFor(() => sent.length === 2, 10_000, "both replies");
        expect(sent.map((m) => m.type)).toEqual(["rawblock", "blocktxn"]);
        expect(h.maxInFlight()).toBe(1);
      } finally {
        await close(h);
      }
    },
    TEST_TIMEOUT,
  );
});
