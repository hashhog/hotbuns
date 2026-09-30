/**
 * Low-work header gate on the post-IBD (no PRESYNC state) headers path.
 *
 * Live mainnet 2026-09-30: hotbuns' block index held 2,000 difficulty-1
 * headers forking from GENESIS (timestamps Dec 2024, tip
 * 0000000002fdbec1…274d at height 2000) that Bitcoin Core never stores
 * (`getblockheader` on the tip → "Block not found"). They were inflating the
 * `hdrs=` index count (971,315 at a real tip of ~969,300).
 *
 * Root cause: once the best header passed nMinimumChainWork, a peer with no
 * PRESYNC/REDOWNLOAD state went straight to processHeaders(minPowChecked=true)
 * with no work check at all. Core's ProcessHeadersMessage runs
 * TryLowWorkHeadersSync (net_processing.cpp:2765) on EVERY headers message
 * that is not already on the best chain: if
 *   chain_start.nChainWork + claimed work < GetAntiDoSWorkThreshold()
 * (= max(tip work - 144 blocks of tip proof, nMinimumChainWork)) nothing is
 * stored; a full (2000) message starts a HeadersSyncState instead.
 */

import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { mkdtemp, rm } from "fs/promises";
import { tmpdir } from "os";
import { join } from "path";
import { ChainDB } from "../storage/database.js";
import { REGTEST, compactToBigInt, type ConsensusParams } from "../consensus/params.js";
import { type BlockHeader, getBlockHash } from "../validation/block.js";
import { HeaderSync } from "./headers.js";
import { HeadersSyncStateEnum, MAX_HEADERS_RESULTS } from "./header-sync-state.js";

function hashValue(h: BlockHeader): bigint {
  return BigInt("0x" + Buffer.from(getBlockHash(h)).reverse().toString("hex"));
}

/** Mine (or deliberately fail to mine) a regtest-difficulty header. */
function mine(prevBlock: Buffer, timestamp: number, opts: { bits?: number; badPow?: boolean; tag?: number } = {}): BlockHeader {
  const bits = opts.bits ?? REGTEST.powLimitBits;
  const target = compactToBigInt(bits);
  const base: BlockHeader = {
    version: 4,
    prevBlock,
    merkleRoot: Buffer.alloc(32, opts.tag ?? 0xab),
    timestamp,
    bits,
    nonce: 0,
  };
  for (let nonce = 0; nonce < 1_000_000; nonce++) {
    const h = { ...base, nonce };
    const ok = hashValue(h) <= target;
    if (ok !== !!opts.badPow) return h;
  }
  throw new Error("could not mine header");
}

function chain(prev: Buffer, startTs: number, n: number, tag: number): BlockHeader[] {
  const out: BlockHeader[] = [];
  let p = prev;
  let ts = startTs;
  for (let i = 0; i < n; i++) {
    ts += 600;
    const h = mine(p, ts, { tag });
    out.push(h);
    p = getBlockHash(h);
  }
  return out;
}

function peer(host: string): any {
  const sent: any[] = [];
  return {
    host,
    port: 8333,
    state: "connected",
    versionPayload: { startHeight: 0 },
    send: (m: any) => {
      sent.push(m);
      return true;
    },
    misbehaving: () => {},
    synced: [] as number[],
    updateSyncedHeaders(h: number) {
      this.synced.push(h);
    },
    sent,
  };
}

// regtest difficulty, but a non-zero minimum chain work (5 blocks' worth) so
// the node is past the IBD anti-DoS phase once it holds the honest chain —
// the state live mainnet is in.
const HONEST_LEN = 200;
let params: ConsensusParams;
let dbPath: string;
let db: ChainDB;
let hs: HeaderSync;
let honest: BlockHeader[];

async function deliver(from: any, headers: BlockHeader[]): Promise<void> {
  await (hs as any).handleHeadersMessage(from, headers);
}

beforeEach(async () => {
  dbPath = await mkdtemp(join(tmpdir(), "hotbuns-lowwork-gate-"));
  db = new ChainDB(dbPath);
  await db.open();
  const oneBlock = (2n ** 256n) / (compactToBigInt(REGTEST.powLimitBits) + 1n);
  params = { ...REGTEST, nMinimumChainWork: 5n * oneBlock };
  hs = new HeaderSync(db, params);
  hs.initGenesis();
  const g = hs.getBestHeader()!;
  honest = chain(g.hash, g.header.timestamp, HONEST_LEN, 0x01);
  // Honest sync already past nMinimumChainWork (processHeaders directly, as
  // a completed PRESYNC/REDOWNLOAD would release it).
  expect(await hs.processHeaders(honest, null)).toBe(HONEST_LEN);
  expect(hs.getBestHeader()!.height).toBe(HONEST_LEN);
});

afterEach(async () => {
  await db.close();
  await rm(dbPath, { recursive: true, force: true });
});

describe("low-work header gate (Core TryLowWorkHeadersSync)", () => {
  test("low-work fork from genesis is not stored (the live 2,000-header shape, non-full)", async () => {
    const g = hs.getHeader(REGTEST.genesisBlockHash)!;
    const fake = chain(g.hash, g.header.timestamp + 1, 10, 0x77);
    const before = hs.getHeaderCount();
    await deliver(peer("10.0.0.2"), fake);
    expect(hs.getHeaderCount()).toBe(before);
    for (const h of fake) expect(hs.getHeader(getBlockHash(h))).toBeUndefined();
    // Not persisted either (the live copy survived restarts via BLOCK_INDEX).
    expect(await db.getBlockIndex(getBlockHash(fake[9]))).toBeNull();
    expect(hs.getBestHeader()!.height).toBe(HONEST_LEN);
  });

  test("threshold is tip-relative: a fork above nMinimumChainWork but >144 blocks deep is rejected", async () => {
    // fork at height 20 with 10 headers: total ≈ 31 blocks of work, well
    // above nMinimumChainWork (5) but below tip(201) - 144 = 57.
    const forkParent = hs.getHeaderByHeight(20)!;
    const fork = chain(forkParent.hash, forkParent.header.timestamp + 1, 10, 0x55);
    const before = hs.getHeaderCount();
    await deliver(peer("10.0.0.3"), fork);
    expect(hs.getHeaderCount()).toBe(before);
  });

  test("full (2000) low-work message starts PRESYNC instead of storing", async () => {
    // A regtest fork cannot be low-work relative to a 200-block regtest chain
    // at equal difficulty, so model the live scale: the ACTIVE tip carries
    // mainnet-like work (1e6 blocks of it) while the 2000 fake headers carry
    // 2000.
    const tip = hs.getBestHeader()!;
    const proof = (2n ** 256n) / (compactToBigInt(REGTEST.powLimitBits) + 1n);
    hs.setActiveTipProvider(() => ({ hash: tip.hash, chainWork: 1_000_000n * proof }));
    const g = hs.getHeader(REGTEST.genesisBlockHash)!;
    const fake = chain(g.hash, g.header.timestamp + 1, MAX_HEADERS_RESULTS, 0x66);
    const p = peer("10.0.0.4");
    const before = hs.getHeaderCount();
    await deliver(p, fake);
    expect(hs.getHeaderCount()).toBe(before);
    const st = hs.getPeerSyncState(p);
    expect(st).toBeDefined();
    expect(st!.syncState.getState()).toBe(HeadersSyncStateEnum.PRESYNC);
    // and it asks the peer to continue (Core: IsContinuationOfLowWorkHeadersSync)
    expect(p.sent.some((m: any) => m.type === "getheaders")).toBe(true);
  }, 60_000);

  // ---- positive controls: honest traffic must still get through ----

  test("control: new-tip announcement is accepted", async () => {
    const tip = hs.getBestHeader()!;
    const next = chain(tip.hash, tip.header.timestamp, 1, 0x02);
    await deliver(peer("10.0.0.5"), next);
    expect(hs.getBestHeader()!.height).toBe(HONEST_LEN + 1);
  });

  test("control: near-tip fork (within 144 blocks) is stored", async () => {
    const forkParent = hs.getHeaderByHeight(HONEST_LEN - 3)!;
    const fork = chain(forkParent.hash, forkParent.header.timestamp + 1, 2, 0x03);
    const before = hs.getHeaderCount();
    await deliver(peer("10.0.0.6"), fork);
    expect(hs.getHeaderCount()).toBe(before + 2);
  });

  test("control: re-delivery of already-best-chain headers is not treated as low-work", async () => {
    // Core already_validated_work: last header is an ancestor of best header.
    const p = peer("10.0.0.7");
    await deliver(p, honest.slice(0, 10));
    // processHeaders ran (it records synced_headers for known headers); a
    // gated message would never reach it.
    expect(p.synced).toContain(10);
    expect(hs.getBestHeader()!.height).toBe(HONEST_LEN);
    expect(hs.getPeerSyncState(p)).toBeUndefined();
  });

  test("threshold value matches Core formula", () => {
    const tip = hs.getBestHeader()!;
    const proof = (2n ** 256n) / (compactToBigInt(REGTEST.powLimitBits) + 1n);
    expect(hs.getAntiDoSWorkThreshold()).toBe(tip.chainWork - 144n * proof);
    // The wired active tip wins over the best header.
    const g = hs.getHeader(REGTEST.genesisBlockHash)!;
    hs.setActiveTipProvider(() => ({ hash: g.hash, chainWork: g.chainWork }));
    expect(hs.getAntiDoSWorkThreshold()).toBe(params.nMinimumChainWork);
  });
});

// Consensus header checks Core's AcceptBlockHeader / ContextualCheckBlockHeader
// apply; exercised end-to-end through the P2P headers handler with enough work
// to pass the anti-DoS gate, so it is the header check that must refuse them.
describe("header consensus checks through the P2P headers path", () => {
  test("bad PoW (high-hash) is rejected", async () => {
    const tip = hs.getBestHeader()!;
    const bad = mine(tip.hash, tip.header.timestamp + 600, { badPow: true, tag: 0x10 });
    await deliver(peer("10.0.1.1"), [bad]);
    expect(hs.getHeader(getBlockHash(bad))).toBeUndefined();
  });

  test("bad bits (bad-diffbits) is rejected", async () => {
    const tip = hs.getBestHeader()!;
    const bad = mine(tip.hash, tip.header.timestamp + 600, { bits: 0x2000ffff, tag: 0x11 });
    await deliver(peer("10.0.1.2"), [bad]);
    expect(hs.getHeader(getBlockHash(bad))).toBeUndefined();
  });

  test("timestamp > now + 2h (time-too-new) is rejected", async () => {
    const tip = hs.getBestHeader()!;
    const bad = mine(tip.hash, Math.floor(Date.now() / 1000) + 3 * 3600, { tag: 0x12 });
    await deliver(peer("10.0.1.3"), [bad]);
    expect(hs.getHeader(getBlockHash(bad))).toBeUndefined();
  });

  test("timestamp <= MTP (time-too-old) is rejected", async () => {
    const tip = hs.getBestHeader()!;
    const bad = mine(tip.hash, hs.getMedianTimePast(tip), { tag: 0x13 });
    await deliver(peer("10.0.1.4"), [bad]);
    expect(hs.getHeader(getBlockHash(bad))).toBeUndefined();
  });
});
