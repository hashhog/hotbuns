/**
 * Audit H1 (audits/security/hotbuns-2026-10-29.md): one getdata made the node
 * read, parse and re-serialize up to 50,000 blocks back to back, kept going
 * after the requesting peer disconnected, and ignored whether that peer was
 * reading what it was sent. Core serves getdata from a per-peer queue
 * (Peer::m_getdata_requests), one block per ProcessGetData pass, only while
 * !fPauseSend, sends the bytes it read from disk, and discards the queue in
 * FinalizeNode (net_processing.cpp:2407, 2518-2585).
 *
 * Regtest only: a fresh temp ChainDB holding the regtest genesis block, and a
 * local stub peer standing in for the attacker.
 */

import { describe, expect, test } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { REGTEST } from "../consensus/params.js";
import { ChainDB } from "../storage/database.js";
import { BlockSync } from "./blocks.js";
import { HeaderSync } from "./headers.js";
import { InvType, serializeMessage, type InvVector } from "../p2p/messages.js";
import { deserializeBlock, getBlockHash } from "../validation/block.js";
import { BufferReader } from "../wire/serialization.js";

const TEST_TIMEOUT = 30_000;

interface Harness {
  dir: string;
  db: ChainDB;
  sync: BlockSync;
  hash: Buffer;
  raw: Buffer;
  reads: () => number;
}

async function open(): Promise<Harness> {
  const dir = await mkdtemp(join(tmpdir(), "hotbuns-getdata-queue-"));
  const db = new ChainDB(join(dir, "blocks.db"));
  await db.open();
  const raw = REGTEST.genesisBlock;
  const hash = getBlockHash(deserializeBlock(new BufferReader(raw)).header);
  await db.putBlock(hash, raw);
  let reads = 0;
  const getBlock = db.getBlock.bind(db);
  (db as any).getBlock = async (h: Buffer) => {
    reads++;
    return getBlock(h);
  };
  const sync = new BlockSync(db, REGTEST, new HeaderSync(db, REGTEST));
  return { dir, db, sync, hash, raw, reads: () => reads };
}

async function close(h: Harness): Promise<void> {
  await h.db.close();
  await rm(h.dir, { recursive: true, force: true });
}

/** A local attacker peer: records what it is sent; its send buffer is settable. */
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

function blockInvs(hash: Buffer, n: number): InvVector[] {
  return Array.from({ length: n }, () => ({ type: InvType.MSG_WITNESS_BLOCK, hash }));
}

async function waitFor(cond: () => boolean, ms: number, label: string): Promise<void> {
  const start = Date.now();
  while (!cond()) {
    if (Date.now() - start > ms) throw new Error(`${label}: timed out after ${ms} ms`);
    await new Promise((r) => setTimeout(r, 5));
  }
}

describe("H1: getdata is served from a per-peer queue", () => {
  test(
    "a peer that disconnects mid-getdata gets no further block reads",
    async () => {
      const h = await open();
      try {
        const { peer } = stubPeer();
        const done = (h.sync as any).handleGetData(peer, blockInvs(h.hash, 20_000));
        await waitFor(() => h.reads() >= 3, 10_000, "first reads");
        const atDisconnect = h.reads();
        peer.state = "disconnected";
        await done;
        // Master went on to read all 20,000 blocks for a peer already gone.
        // At most the read already in flight may finish.
        expect(h.reads() - atDisconnect).toBeLessThanOrEqual(1);
        expect(h.reads()).toBeLessThan(20_000);
      } finally {
        await close(h);
      }
    },
    TEST_TIMEOUT,
  );

  test(
    "nothing is served while the peer has a full send buffer; serving resumes once it drains",
    async () => {
      const h = await open();
      try {
        const { peer, sent } = stubPeer();
        peer.unsent = 2_000_000; // over Core's 1000 KB -maxsendbuffer
        const done = (h.sync as any).handleGetData(peer, blockInvs(h.hash, 50));
        await new Promise((r) => setTimeout(r, 300));
        expect(h.reads()).toBe(0);
        expect(sent.length).toBe(0);

        peer.unsent = 0;
        await done;
        expect(h.reads()).toBe(50);
        expect(sent.length).toBe(50);
      } finally {
        await close(h);
      }
    },
    TEST_TIMEOUT,
  );

  test(
    "blocks go out as the stored bytes, byte-identical on the wire to the old re-serialization",
    async () => {
      const h = await open();
      try {
        const { peer, sent } = stubPeer();
        await (h.sync as any).handleGetData(peer, [
          { type: InvType.MSG_BLOCK, hash: h.hash },
          { type: InvType.MSG_WITNESS_BLOCK, hash: h.hash },
        ]);
        expect(sent.map((m) => m.type)).toEqual(["rawblock", "rawblock"]);
        for (const m of sent) expect(m.payload.raw.equals(h.raw)).toBe(true);

        // Control: what the old path sent (parse + serializeBlock) is the
        // same frame, so peers see no change.
        const block = deserializeBlock(new BufferReader(h.raw));
        const before = serializeMessage(REGTEST.networkMagic, { type: "block", payload: { block } });
        const after = serializeMessage(REGTEST.networkMagic, sent[0]);
        expect(after.equals(before)).toBe(true);
      } finally {
        await close(h);
      }
    },
    TEST_TIMEOUT,
  );

  test(
    "two getdata messages from one peer share one ordered queue, not two parallel loops",
    async () => {
      const h = await open();
      try {
        const { peer, sent } = stubPeer();
        const missA = Buffer.alloc(32, 0xa1);
        const missB = Buffer.alloc(32, 0xb2);
        const first = (h.sync as any).handleGetData(peer, [
          ...blockInvs(h.hash, 20),
          { type: InvType.MSG_TX, hash: missA },
        ]);
        const second = (h.sync as any).handleGetData(peer, [{ type: InvType.MSG_TX, hash: missB }]);
        await Promise.all([first, second]);
        // All 20 blocks precede both notfounds, in request order. Two
        // parallel loops would answer the second getdata first.
        expect(sent.map((m) => m.type)).toEqual([...Array(20).fill("rawblock"), "notfound"]);
        expect(sent[20].payload.inventory.map((i: InvVector) => i.hash)).toEqual([missA, missB]);
      } finally {
        await close(h);
      }
    },
    TEST_TIMEOUT,
  );

  test(
    "a peer's queue is capped at one maximal getdata (MAX_INV_SZ)",
    async () => {
      const h = await open();
      try {
        const { peer } = stubPeer();
        peer.unsent = 2_000_000; // hold the queue so it cannot drain
        (h.sync as any).handleGetData(peer, blockInvs(h.hash, 50_000));
        (h.sync as any).handleGetData(peer, blockInvs(h.hash, 50_000));
        const q = (h.sync as any).getDataQueues.get(peer);
        expect(q.items.length - q.head).toBe(50_000);
        peer.state = "disconnected";
        await (h.sync as any).getDataServing.get(peer);
      } finally {
        await close(h);
      }
    },
    TEST_TIMEOUT,
  );
});
