/**
 * Snapshot-booted header island: consensus MTP must never be computed from a
 * partial window, and the pre-base header backfill must link genesis to the
 * island by hash before blocks above the base are connected.
 *
 * Regression for R4 slice 940000-950000 (2026-10-03, hotbuns 8a5c19d): the
 * slice seeds base_tail_headers 937974..940000. Mainnet block 942168 spends a
 * coin created at 937977 with nSequence 0x004013c7 (time lock 5063 x 512 s).
 * Core: nCoinTime = GetAncestor(937976)->GetMedianTimePast(), the median of
 * 937966..937976 = 1771853536. hotbuns took the median of the 3 indexed
 * headers 937974..937976 = 1771855669 (2,133 s late), so
 *   minTime = 1771855669 + 2592256 - 1 = 1774447924 >= prevMTP 1774446410
 * and the VALID block was rejected bad-txns-nonfinal. With the true MTP,
 * minTime = 1774445791 < 1774446410 and the block is final.
 *
 * The timestamps below are mainnet's (getblockheader, 2026-10-03).
 */

import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { mkdtemp, rm } from "fs/promises";
import { tmpdir } from "os";
import { join } from "path";
import { ChainDB } from "../storage/database.js";
import {
  MAINNET,
  REGTEST,
  compactToBigInt,
  type ConsensusParams,
  type AssumeutxoData,
} from "../consensus/params.js";
import { HeaderSync, MissingAncestorHeaderError } from "./headers.js";
import {
  serializeBlockHeader,
  getBlockHash,
  type BlockHeader,
} from "../validation/block.js";
import { checkSequenceLocks, type Transaction } from "../validation/tx.js";

// ── 942168 fixture ─────────────────────────────────────────────────────────

/** Mainnet header times, heights 937966..937977. */
const MAINNET_TIMES: Array<[number, number]> = [
  [937966, 1771849622],
  [937967, 1771850239],
  [937968, 1771852311],
  [937969, 1771853345],
  [937970, 1771853423],
  [937971, 1771853536],
  [937972, 1771854580],
  [937973, 1771854720],
  [937974, 1771855429],
  [937975, 1771855669],
  [937976, 1771857430],
  [937977, 1771857754],
];
const BAND_START = 937974; // first seeded base_tail_headers height on the slice
const COIN_HEIGHT = 937977;
const SPEND_HEIGHT = 942168;
const PREV_MTP_942167 = 1774446410; // getblockheader(942167).mediantime
const CORE_COIN_MTP = 1771853536; // getblockheader(937976).mediantime
const SEQ_942168 = 0x004013c7;

/** Hash-linked synthetic headers carrying mainnet's timestamps. */
function linkedMainnetHeaders(): Array<{ height: number; header: BlockHeader; hash: Buffer }> {
  const out: Array<{ height: number; header: BlockHeader; hash: Buffer }> = [];
  let prev: Buffer = Buffer.alloc(32, 0x5a); // parent of 937966: never indexed
  for (const [height, timestamp] of MAINNET_TIMES) {
    const header: BlockHeader = {
      version: 0x20000000,
      prevBlock: prev,
      merkleRoot: Buffer.alloc(32, height & 0xff),
      timestamp,
      bits: 0x17023a04,
      nonce: height,
    };
    const hash = getBlockHash(header);
    out.push({ height, header, hash });
    prev = hash;
  }
  return out;
}

function tx942168Shape(): Transaction {
  return {
    version: 2,
    inputs: [
      {
        prevOut: { txid: Buffer.alloc(32, 0x11), vout: 0 },
        scriptSig: Buffer.alloc(0),
        sequence: SEQ_942168,
        witness: [],
      },
    ],
    outputs: [{ value: 1000n, scriptPubKey: Buffer.from([0x51]) }],
    lockTime: 0,
  };
}

describe("BIP-68 coin MTP on a snapshot header island (942168)", () => {
  let dbPath: string;
  let db: ChainDB;

  beforeEach(async () => {
    dbPath = await mkdtemp(join(tmpdir(), "hotbuns-prebase-mtp-"));
    db = new ChainDB(dbPath);
    await db.open();
  });

  afterEach(async () => {
    await db.close();
    await rm(dbPath, { recursive: true, force: true });
  });

  test("fixture arithmetic: Core's coin MTP makes 942168 final, the 3-header median does not", () => {
    const tx = tx942168Shape();
    const truncated = [1771855429, 1771855669, 1771857430].sort((a, b) => a - b)[1];
    expect(truncated).toBe(1771855669);
    expect(
      checkSequenceLocks(tx, true, SPEND_HEIGHT, PREV_MTP_942167, [
        { height: COIN_HEIGHT, medianTimePast: CORE_COIN_MTP },
      ]),
    ).toBe(true);
    expect(
      checkSequenceLocks(tx, true, SPEND_HEIGHT, PREV_MTP_942167, [
        { height: COIN_HEIGHT, medianTimePast: truncated },
      ]),
    ).toBe(false);
  });

  test("window runs off the island: refuses (no verdict), never a truncated median", async () => {
    const hs = new HeaderSync(db, MAINNET);
    hs.initGenesis();
    const all = linkedMainnetHeaders();
    // Seed only what the slice had: 937974.. (the band's bottom).
    for (const h of all.filter((x) => x.height >= BAND_START)) {
      await hs.seedHeader({ ...h, chainWork: 0x1000n + BigInt(h.height) });
    }

    let caught: unknown = null;
    let coinMTP: number | null = null;
    try {
      coinMTP = hs.getCoinMedianTimePast(COIN_HEIGHT);
    } catch (err) {
      caught = err;
    }
    // Pre-fix this returned 1771855669 and the block was rejected
    // bad-txns-nonfinal. It must refuse instead.
    expect(coinMTP).toBeNull();
    expect(caught).toBeInstanceOf(MissingAncestorHeaderError);
    expect((caught as MissingAncestorHeaderError).missingHeight).toBe(BAND_START - 1);
    // The refusal must not read as a consensus reject anywhere downstream.
    expect((caught as Error).message).toMatch(/^missing-ancestor-header:/);
    expect((caught as Error).message).not.toMatch(/nonfinal|non-final|bad-txns|sequence lock/i);
  });

  test("with the full 11-header window indexed: Core's MTP, and 942168 is final", async () => {
    const hs = new HeaderSync(db, MAINNET);
    hs.initGenesis();
    for (const h of linkedMainnetHeaders()) {
      await hs.seedHeader({ ...h, chainWork: 0x1000n + BigInt(h.height) });
    }
    const coinMTP = hs.getCoinMedianTimePast(COIN_HEIGHT);
    expect(coinMTP).toBe(CORE_COIN_MTP);
    expect(
      checkSequenceLocks(tx942168Shape(), true, SPEND_HEIGHT, PREV_MTP_942167, [
        { height: COIN_HEIGHT, medianTimePast: coinMTP },
      ]),
    ).toBe(true);
  });

  test("missing header AT the coin's ancestor height refuses (was 0 = every time lock satisfied)", async () => {
    const hs = new HeaderSync(db, MAINNET);
    hs.initGenesis();
    expect(() => hs.getCoinMedianTimePast(COIN_HEIGHT)).toThrow(MissingAncestorHeaderError);
  });

  test("a short window that ends at GENESIS is Core-legitimate, not a refusal", () => {
    const hs = new HeaderSync(db, MAINNET);
    hs.initGenesis();
    const g = hs.getHeaderByHeight(0)!;
    expect(hs.getMedianTimePastChecked(g)).toBe(g.header.timestamp);
    expect(hs.getCoinMedianTimePast(1)).toBe(g.header.timestamp);
  });
});

// ── Backfill end-to-end on regtest-mined headers ──────────────────────────

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
  port = 1;
  sent: Array<{ type: string; payload: any }> = [];
  send(msg: { type: string; payload: any }): boolean {
    this.sent.push(msg);
    return true;
  }
  updateSyncedHeaders(): void {}
  misbehaving(): void {}
}

describe("snapshot pre-base header backfill", () => {
  const BASE = 30;
  const TAIL = 11; // heights 20..30 seeded, island root = 20
  const ROOT = BASE - TAIL + 1;
  const chain = mineRegtestChain(BASE + 2, 1);
  const work = (bits: number) => {
    const t = compactToBigInt(bits);
    return (1n << 256n) / (t + 1n);
  };
  const realWork = (h: number) => {
    let w = 0n;
    for (let i = 0; i <= h; i++) w += work(chain[i].header.bits);
    return w;
  };
  const au: AssumeutxoData = {
    height: BASE,
    hashSerialized: Buffer.alloc(32, 0x33),
    nChainTx: BigInt(BASE + 1),
    blockHash: chain[BASE].hash,
    baseHeader: serializeBlockHeader(chain[BASE].header),
    chainWork: realWork(BASE),
    baseTailHeaders: chain.slice(ROOT, BASE + 1).map((c) => serializeBlockHeader(c.header)),
  };
  const params: ConsensusParams = {
    ...REGTEST,
    assumeutxo: new Map([[chain[BASE].hash.toString("hex"), au]]),
  };

  let dbPath: string;
  let db: ChainDB;

  beforeEach(async () => {
    dbPath = await mkdtemp(join(tmpdir(), "hotbuns-prebase-backfill-"));
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

  const deliver = (hs: HeaderSync, peer: FakePeer, from: number, to: number) =>
    (hs as any).handleHeadersMessage(
      peer,
      chain.slice(from, to + 1).map((c) => c.header),
    ) as Promise<void>;

  test("snapshot adoption detects the island and requests from genesis, stopping at the root", async () => {
    const hs = await islandNode();
    expect(hs.hasPreBaseHeaderGap()).toBe(true);
    expect(hs.getPreBaseBackfillStatus()).toEqual({ rootHeight: ROOT, frontierHeight: 0 });
    // The coin-MTP refusal is live while the gap exists.
    expect(() => hs.getCoinMedianTimePast(ROOT + 2)).toThrow(MissingAncestorHeaderError);

    const peer = new FakePeer();
    hs.maybeRequestPreBaseHeaders(peer as any);
    expect(peer.sent).toHaveLength(1);
    expect(peer.sent[0].type).toBe("getheaders");
    expect(peer.sent[0].payload.locatorHashes[0].equals(REGTEST.genesisBlockHash)).toBe(true);
    expect(peer.sent[0].payload.hashStop.equals(chain[ROOT].hash)).toBe(true);
  });

  test("backfill in two batches links by hash, closes the gap, fixes chainwork, persists", async () => {
    const hs = await islandNode();
    let completed = 0;
    hs.onPreBaseBackfillComplete(() => completed++);
    const peer = new FakePeer();

    await deliver(hs, peer, 1, 10);
    expect(hs.getPreBaseBackfillStatus()).toEqual({ rootHeight: ROOT, frontierHeight: 10 });
    // Continuation request goes out from the new frontier.
    const last = peer.sent[peer.sent.length - 1];
    expect(last.payload.locatorHashes[0].equals(chain[10].hash)).toBe(true);
    expect(completed).toBe(0);

    // Peer answers through the root (hashStop) — the root header links.
    await deliver(hs, peer, 11, ROOT);
    expect(hs.hasPreBaseHeaderGap()).toBe(false);
    expect(completed).toBe(1);
    for (let h = 0; h <= BASE; h++) {
      expect(hs.getHeaderByHeight(h)?.hash.equals(chain[h].hash)).toBe(true);
    }
    // Band carried synthetic work; now every entry is header-derived.
    expect(hs.getHeaderByHeight(ROOT)!.chainWork).toBe(realWork(ROOT));
    expect(hs.getHeaderByHeight(BASE)!.chainWork).toBe(realWork(BASE));
    // The coin MTP is now Core's.
    const ts = (h: number) => chain[h].header.timestamp;
    const window = [];
    for (let h = ROOT + 1; h > ROOT + 1 - 11; h--) window.push(ts(h));
    window.sort((a, b) => a - b);
    expect(hs.getCoinMedianTimePast(ROOT + 2)).toBe(window[5]);

    // Restart: the header chain loads as one tree from genesis — no gap.
    const hs2 = new HeaderSync(db, params);
    await hs2.loadFromDB();
    expect(hs2.hasPreBaseHeaderGap()).toBe(false);
    expect(hs2.getBestHeader()!.hash.equals(chain[BASE].hash)).toBe(true);
    expect(hs2.getBestHeader()!.chainWork).toBe(realWork(BASE));
  });

  test("restart mid-backfill resumes from the persisted frontier", async () => {
    const hs = await islandNode();
    const peer = new FakePeer();
    await deliver(hs, peer, 1, 12);

    const hs2 = new HeaderSync(db, params);
    await hs2.loadFromDB();
    expect(hs2.hasPreBaseHeaderGap()).toBe(true);
    expect(hs2.getPreBaseBackfillStatus()).toEqual({ rootHeight: ROOT, frontierHeight: 12 });
    const peer2 = new FakePeer();
    hs2.maybeRequestPreBaseHeaders(peer2 as any);
    expect(peer2.sent[0].payload.locatorHashes[0].equals(chain[12].hash)).toBe(true);
    await deliver(hs2, peer2, 13, ROOT);
    expect(hs2.hasPreBaseHeaderGap()).toBe(false);
  });

  test("negative: a valid-PoW chain that does not reach the root's hash never links", async () => {
    const hs = await islandNode();
    const other = mineRegtestChain(ROOT, 7); // same heights, different hashes
    const peer = new FakePeer();
    await (hs as any).handleHeadersMessage(
      peer,
      other.slice(1, ROOT + 1).map((c) => c.header),
    );
    expect(hs.hasPreBaseHeaderGap()).toBe(true);
    // Frontier reset to genesis so the next peer starts over.
    expect(hs.getPreBaseBackfillStatus()).toEqual({ rootHeight: ROOT, frontierHeight: 0 });
    expect(() => hs.getCoinMedianTimePast(ROOT + 2)).toThrow(MissingAncestorHeaderError);
  });

  test("negative: a header with bad PoW is refused and the frontier does not move past it", async () => {
    const hs = await islandNode();
    const peer = new FakePeer();
    const bad = chain.slice(1, 6).map((c) => ({ ...c.header }));
    // Re-mine nothing: bump the nonce of #3 until its hash MISSES the target.
    const target = compactToBigInt(RT_BITS);
    for (;;) {
      bad[2].nonce++;
      const h = getBlockHash(bad[2]);
      if (BigInt("0x" + Buffer.from(h).reverse().toString("hex")) > target) break;
    }
    await (hs as any).handleHeadersMessage(peer, bad);
    expect(hs.getPreBaseBackfillStatus()).toEqual({ rootHeight: ROOT, frontierHeight: 2 });
  });

  test("a full chain from genesis has no gap (live nodes are unaffected)", async () => {
    const hs = new HeaderSync(db, REGTEST);
    hs.initGenesis();
    await hs.processHeaders(chain.slice(1, BASE + 1).map((c) => c.header), null);
    expect(hs.refreshPreBaseGap()).toBeNull();
    expect(hs.hasPreBaseHeaderGap()).toBe(false);
  });
});
