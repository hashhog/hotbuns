/**
 * cffix-hotbuns-prebase-frontier-anchor
 * Fingerprint: hotbuns:src/sync/headers.ts:processPreBaseHeaders:unbound-frontier-hijack
 *
 * A snapshot-booted node backfills headers [1 .. rootHeight] below its
 * header island along a single linear frontier. Pre-fix, ANY peer's
 * `headers` message whose first header's prevBlock was the frontier was
 * routed into the backfill, solicited or not, and every header passing
 * validateHeader advanced the frontier. Near genesis the difficulty is 1,
 * so one cheap valid-PoW fork header moved the frontier off the snapshot
 * chain; the honest reply (prevBlock = genesis) then no longer matched the
 * frontier and the gap could never close.
 *
 * Core never stores a header chain it cannot connect to the snapshot base
 * (ActivateSnapshot requires the base in m_block_index; headers come only
 * through ProcessHeadersMessage / HeadersSyncState). Here the anchor is the
 * request: only the peer the backfill getheaders went to may move the
 * frontier, and its reply may re-attach below a frontier a previous peer
 * moved onto a fork.
 */

import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { mkdtemp, rm } from "fs/promises";
import { tmpdir } from "os";
import { join } from "path";
import { ChainDB } from "../storage/database.js";
import {
  REGTEST,
  compactToBigInt,
  type ConsensusParams,
  type AssumeutxoData,
} from "../consensus/params.js";
import { HeaderSync } from "../sync/headers.js";
import { serializeBlockHeader, getBlockHash, type BlockHeader } from "../validation/block.js";

const RT_BITS = 0x207fffff;

/** Mine `n` real-PoW regtest headers on top of genesis (index 0 = genesis). */
function mineRegtestChain(n: number, salt: number): Array<{ header: BlockHeader; hash: Buffer }> {
  const genesisHeader: BlockHeader = {
    version: REGTEST.genesisBlock.readInt32LE(0),
    prevBlock: Buffer.from(REGTEST.genesisBlock.subarray(4, 36)),
    merkleRoot: Buffer.from(REGTEST.genesisBlock.subarray(36, 68)),
    timestamp: REGTEST.genesisBlock.readUInt32LE(68),
    bits: REGTEST.genesisBlock.readUInt32LE(72),
    nonce: REGTEST.genesisBlock.readUInt32LE(76),
  };
  const out = [{ header: genesisHeader, hash: REGTEST.genesisBlockHash }];
  const target = compactToBigInt(RT_BITS);
  for (let i = 1; i <= n; i++) {
    const header: BlockHeader = {
      version: 0x20000000,
      prevBlock: out[i - 1].hash,
      merkleRoot: Buffer.alloc(32, (salt * 31 + i) & 0xff),
      timestamp: genesisHeader.timestamp + i * 600,
      bits: RT_BITS,
      nonce: 0,
    };
    for (;;) {
      const h = getBlockHash(header);
      if (BigInt("0x" + Buffer.from(h).reverse().toString("hex")) <= target) {
        out.push({ header, hash: h });
        break;
      }
      header.nonce++;
    }
  }
  return out;
}

class FakePeer {
  host = "127.0.0.1";
  sent: Array<{ type: string; payload: any }> = [];
  constructor(public port: number) {}
  send(msg: { type: string; payload: any }): boolean {
    this.sent.push(msg);
    return true;
  }
  updateSyncedHeaders(): void {}
  misbehaving(): void {}
}

describe("cffix: pre-base backfill frontier is anchored to the request", () => {
  const BASE = 30;
  const TAIL = 11; // heights 20..30 seeded, island root = 20
  const ROOT = BASE - TAIL + 1;
  const chain = mineRegtestChain(BASE + 2, 1);
  const fork = mineRegtestChain(5, 9); // valid PoW, not on the path to the root
  const au: AssumeutxoData = {
    height: BASE,
    hashSerialized: Buffer.alloc(32, 0x33),
    nChainTx: BigInt(BASE + 1),
    blockHash: chain[BASE].hash,
    baseHeader: serializeBlockHeader(chain[BASE].header),
    chainWork: 0n,
    baseTailHeaders: chain.slice(ROOT, BASE + 1).map((c) => serializeBlockHeader(c.header)),
  };
  const params: ConsensusParams = {
    ...REGTEST,
    assumeutxo: new Map([[chain[BASE].hash.toString("hex"), au]]),
  };

  let dbPath: string;
  let db: ChainDB;

  beforeEach(async () => {
    dbPath = await mkdtemp(join(tmpdir(), "hotbuns-cffix-prebase-anchor-"));
    db = new ChainDB(dbPath);
    await db.open();
  });

  afterEach(async () => {
    await db.close();
    await rm(dbPath, { recursive: true, force: true });
  });

  async function islandNode(): Promise<HeaderSync> {
    const hs = new HeaderSync(db, params);
    hs.initGenesis();
    await hs.adoptChainTipAsBestHeader(chain[BASE].hash, BASE);
    return hs;
  }

  const send = (hs: HeaderSync, peer: FakePeer, hdrs: BlockHeader[]) =>
    (hs as any).handleHeadersMessage(peer, hdrs) as Promise<void>;

  test("an unsolicited valid-PoW fork header does not move the frontier; the real backfill reaches the root", async () => {
    const hs = await islandNode();
    expect(hs.getPreBaseBackfillStatus()).toEqual({ rootHeight: ROOT, frontierHeight: 0 });
    const honest = new FakePeer(1);
    const attacker = new FakePeer(2);
    hs.maybeRequestPreBaseHeaders(honest as any);
    expect(honest.sent).toHaveLength(1);

    // Attacker: one difficulty-1 header on genesis, never asked for.
    expect(fork[1].header.prevBlock.equals(REGTEST.genesisBlockHash)).toBe(true);
    await send(hs, attacker, [fork[1].header]);
    expect(hs.getPreBaseBackfillStatus()).toEqual({ rootHeight: ROOT, frontierHeight: 0 });
    expect(hs.getHeader(fork[1].hash)).toBeUndefined();

    // The honest peer's answer to our request links genesis to the root.
    await send(hs, honest, chain.slice(1, ROOT + 1).map((c) => c.header));
    expect(hs.hasPreBaseHeaderGap()).toBe(false);
    for (let h = 0; h <= BASE; h++) {
      expect(hs.getHeaderByHeight(h)?.hash.equals(chain[h].hash)).toBe(true);
    }
  });

  test("an unsolicited copy of the TRUE chain is also ignored (no request in flight)", async () => {
    const hs = await islandNode();
    const stranger = new FakePeer(3);
    await send(hs, stranger, chain.slice(1, 6).map((c) => c.header));
    expect(hs.getPreBaseBackfillStatus()).toEqual({ rootHeight: ROOT, frontierHeight: 0 });
  });

  test("after a solicited peer moves the frontier onto a fork, the next peer's reply from genesis re-attaches and reaches the root", async () => {
    const hs = await islandNode();
    const liar = new FakePeer(4);
    const honest = new FakePeer(5);
    hs.maybeRequestPreBaseHeaders(liar as any);
    await send(hs, liar, fork.slice(1, 4).map((c) => c.header));
    // The liar was asked, so its short fork is held as the frontier.
    expect(hs.getPreBaseBackfillStatus()).toEqual({ rootHeight: ROOT, frontierHeight: 3 });

    // Its follow-up request goes unanswered; the backfill moves to `honest`.
    (hs as any).preBaseInFlight.sentAt = 0;
    hs.maybeRequestPreBaseHeaders(honest as any);
    const req = honest.sent[honest.sent.length - 1];
    expect(req.type).toBe("getheaders");
    const loc: Buffer[] = req.payload.locatorHashes;
    expect(loc[loc.length - 1].equals(REGTEST.genesisBlockHash)).toBe(true);

    // A Core peer without the fork answers from genesis (last locator entry).
    await send(hs, honest, chain.slice(1, ROOT + 1).map((c) => c.header));
    expect(hs.hasPreBaseHeaderGap()).toBe(false);
    for (let h = 0; h <= BASE; h++) {
      expect(hs.getHeaderByHeight(h)?.hash.equals(chain[h].hash)).toBe(true);
    }
  });

  test("negative control: a solicited reply that attaches off the frontier's path is not a backfill reply", async () => {
    const hs = await islandNode();
    const peer = new FakePeer(6);
    hs.maybeRequestPreBaseHeaders(peer as any);
    await send(hs, peer, chain.slice(1, 6).map((c) => c.header));
    expect(hs.getPreBaseBackfillStatus()).toEqual({ rootHeight: ROOT, frontierHeight: 5 });
    // fork[2] attaches to fork[1], which is not stored at all.
    await send(hs, peer, [fork[2].header]);
    expect(hs.getPreBaseBackfillStatus()).toEqual({ rootHeight: ROOT, frontierHeight: 5 });
  });
});
