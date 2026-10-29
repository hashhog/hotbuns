/**
 * Security audit C2 (audits/security/hotbuns-2026-10-29.md): the low-work
 * header anti-DoS gate (checkLowWorkHeaders) trusted the batch shape. It
 * summed each header's CLAIMED work without checking that the headers chain
 * onto each other or that any header's PoW matches its own nBits, and it let
 * any batch whose first header did not connect straight through. processHeaders
 * then resolved every header's parent separately, so:
 *
 *   (b) one trailing junk header with bits=0x03000001 (target 1, claims
 *       ~2^255 work, no real PoW) unlocked a low-work fork for storage;
 *   (a) a non-continuous high-work tail (or a random first prevBlock) did
 *       the same.
 *
 * Core ProcessHeadersMessage (net_processing.cpp:2985) runs CheckHeadersPoW
 * BEFORE anything else: HasValidProofOfWork on every header against its own
 * nBits, then CheckHeadersAreContinuous, each failure Misbehaving() (peer
 * discouraged/disconnected) with nothing stored. A batch whose first header
 * does not connect goes to HandleUnconnectingHeaders (:3034) and nothing in it
 * is stored.
 */

import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { mkdtemp, rm } from "fs/promises";
import { tmpdir } from "os";
import { join } from "path";
import { ChainDB } from "../storage/database.js";
import { REGTEST, compactToBigInt, type ConsensusParams } from "../consensus/params.js";
import { type BlockHeader, getBlockHash } from "../validation/block.js";
import { HeaderSync } from "./headers.js";
import { BanScores } from "../p2p/manager.js";

function hashValue(h: BlockHeader): bigint {
  return BigInt("0x" + Buffer.from(getBlockHash(h)).reverse().toString("hex"));
}

function mine(prevBlock: Buffer, timestamp: number, tag: number): BlockHeader {
  const bits = REGTEST.powLimitBits;
  const target = compactToBigInt(bits);
  const base: BlockHeader = {
    version: 4,
    prevBlock,
    merkleRoot: Buffer.alloc(32, tag),
    timestamp,
    bits,
    nonce: 0,
  };
  for (let nonce = 0; nonce < 1_000_000; nonce++) {
    const h = { ...base, nonce };
    if (hashValue(h) <= target) return h;
  }
  throw new Error("could not mine header");
}

function chain(prev: Buffer, startTs: number, n: number, tag: number): BlockHeader[] {
  const out: BlockHeader[] = [];
  let p = prev;
  let ts = startTs;
  for (let i = 0; i < n; i++) {
    ts += 600;
    const h = mine(p, ts, tag);
    out.push(h);
    p = getBlockHash(h);
  }
  return out;
}

function peer(host: string): any {
  return {
    host,
    port: 8333,
    state: "connected",
    versionPayload: { startHeight: 0 },
    sent: [] as any[],
    send(m: any) {
      this.sent.push(m);
      return true;
    },
    penalties: [] as Array<{ score: number; reason: string }>,
    misbehaving(score: number, reason: string) {
      this.penalties.push({ score, reason });
    },
    updateSyncedHeaders(_h: number) {},
  };
}

const HONEST_LEN = 200;
let params: ConsensusParams;
let dbPath: string;
let db: ChainDB;
let hs: HeaderSync;

async function deliver(from: any, headers: BlockHeader[]): Promise<void> {
  await (hs as any).handleHeadersMessage(from, headers);
}

async function expectNoneStored(headers: BlockHeader[]): Promise<void> {
  for (const h of headers) {
    expect(hs.getHeader(getBlockHash(h))).toBeUndefined();
    expect(await db.getBlockIndex(getBlockHash(h))).toBeNull();
  }
}

beforeEach(async () => {
  dbPath = await mkdtemp(join(tmpdir(), "hotbuns-lowwork-bypass-"));
  db = new ChainDB(dbPath);
  await db.open();
  const oneBlock = (2n ** 256n) / (compactToBigInt(REGTEST.powLimitBits) + 1n);
  params = { ...REGTEST, nMinimumChainWork: 5n * oneBlock };
  hs = new HeaderSync(db, params);
  hs.initGenesis();
  const g = hs.getBestHeader()!;
  const honest = chain(g.hash, g.header.timestamp, HONEST_LEN, 0x01);
  expect(await hs.processHeaders(honest, null)).toBe(HONEST_LEN);
});

afterEach(async () => {
  await db.close();
  await rm(dbPath, { recursive: true, force: true });
});

describe("C2: low-work gate cannot be bypassed by the batch shape (Core CheckHeadersPoW)", () => {
  test("trailing junk header claiming huge work (bits=0x03000001) does not unlock a low-work fork", async () => {
    const g = hs.getHeader(REGTEST.genesisBlockHash)!;
    const fork = chain(g.hash, g.header.timestamp + 1, 10, 0x77);
    const junk: BlockHeader = {
      version: 4,
      prevBlock: getBlockHash(fork[fork.length - 1]),
      merkleRoot: Buffer.alloc(32, 0xee),
      timestamp: fork[fork.length - 1].timestamp + 600,
      bits: 0x03000001, // target 1: claims ~2^255 work, PoW impossible
      nonce: 0,
    };
    // Sanity: the junk header alone out-claims the anti-DoS threshold.
    expect(hs.getHeaderWork(junk.bits) > hs.getAntiDoSWorkThreshold()).toBe(true);

    const p = peer("10.9.0.1");
    const before = hs.getHeaderCount();
    await deliver(p, [...fork, junk]);
    expect(hs.getHeaderCount()).toBe(before);
    await expectNoneStored(fork);
    expect(hs.getBestHeader()!.height).toBe(HONEST_LEN);
    // Core: Misbehaving("header with invalid proof of work") — discourage.
    expect(p.penalties.length).toBe(1);
    expect(p.penalties[0].score).toBe(BanScores.INVALID_BLOCK_HEADER);
  });

  test("non-continuous tail of valid-PoW headers does not unlock a low-work fork", async () => {
    const g = hs.getHeader(REGTEST.genesisBlockHash)!;
    const fork = chain(g.hash, g.header.timestamp + 1, 10, 0x78);
    // 60 real-PoW headers on an unknown parent: 70 blocks of claimed work,
    // above the threshold (tip 201 - 144 = 57), but they don't extend `fork`.
    const tail = chain(Buffer.alloc(32, 0x42), g.header.timestamp + 1, 60, 0x79);
    const p = peer("10.9.0.2");
    const before = hs.getHeaderCount();
    await deliver(p, [...fork, ...tail]);
    expect(hs.getHeaderCount()).toBe(before);
    await expectNoneStored(fork);
    // Core: Misbehaving("non-continuous headers sequence").
    expect(p.penalties.length).toBe(1);
    expect(p.penalties[0].score).toBe(BanScores.INVALID_BLOCK_HEADER);
  });

  test("random prevBlock in headers[0] does not skip the gate for the headers after it", async () => {
    const g = hs.getHeader(REGTEST.genesisBlockHash)!;
    const head = mine(Buffer.alloc(32, 0x43), g.header.timestamp + 1, 0x7a);
    const fork = chain(g.hash, g.header.timestamp + 1, 10, 0x7b);
    const p = peer("10.9.0.3");
    const before = hs.getHeaderCount();
    await deliver(p, [head, ...fork]);
    expect(hs.getHeaderCount()).toBe(before);
    await expectNoneStored(fork);
    expect(p.penalties.length).toBe(1);
    expect(p.penalties[0].score).toBe(BanScores.INVALID_BLOCK_HEADER);
  });

  // ---- controls ----

  test("control: a continuous batch that does not connect stores nothing and is not punished", async () => {
    // Core HandleUnconnectingHeaders: could be a benign BIP 130 announcement.
    const g = hs.getHeader(REGTEST.genesisBlockHash)!;
    const orphanChain = chain(Buffer.alloc(32, 0x44), g.header.timestamp + 1, 5, 0x7c);
    const p = peer("10.9.0.4");
    const before = hs.getHeaderCount();
    await deliver(p, orphanChain);
    expect(hs.getHeaderCount()).toBe(before);
    await expectNoneStored(orphanChain);
    expect(p.penalties.length).toBe(0);
  });

  test("control: honest tip extension is stored and not punished", async () => {
    const tip = hs.getBestHeader()!;
    const next = chain(tip.hash, tip.header.timestamp, 3, 0x02);
    const p = peer("10.9.0.5");
    await deliver(p, next);
    expect(hs.getBestHeader()!.height).toBe(HONEST_LEN + 3);
    expect(p.penalties.length).toBe(0);
  });

  test("control: near-tip fork within the 144-block buffer is stored and not punished", async () => {
    const forkParent = hs.getHeaderByHeight(HONEST_LEN - 3)!;
    const fork = chain(forkParent.hash, forkParent.header.timestamp + 1, 2, 0x03);
    const p = peer("10.9.0.6");
    const before = hs.getHeaderCount();
    await deliver(p, fork);
    expect(hs.getHeaderCount()).toBe(before + 2);
    expect(p.penalties.length).toBe(0);
  });
});
