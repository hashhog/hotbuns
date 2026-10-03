/**
 * A snapshot-booted node restarted before its next retarget must still be
 * able to validate that retarget.
 *
 * OBSERVED 2026-10-02 (ARCH-2.5, rung 900000): import with
 * --load-snapshot persisted the 2,026 `base_tail_headers` below the base
 * into BLOCK_INDEX, and the in-process adopt seeded them, so a
 * single-process run crossed 901,152 fine. After a restart, loadFromDB
 * skipped every one of them — the lowest (897,974) has no parent in the
 * index, so it was dropped ("Missing parent for header at height 897974"),
 * and each later one then had no parent either. The 901,152 header was
 * then rejected `bad-diffbits: retarget ancestor at height 899136
 * unreachable` on every delivery; the node wedged at 901,151 and logged
 * ~6.8M "Orphan header received" lines (~495 MB) in an hour.
 *
 * Core has no such island: LoadBlockIndex sees every pindex and the
 * snapshot base's ancestors carry real nChainWork. Here the band is
 * re-anchored at its root with work derived backwards from the base's
 * authoritative chainwork, so every entry ends up with its real cumulative
 * work and the base keeps exactly the chainwork it was imported with.
 *
 * Negative control: on master (d04997a) the restart cases fail at the
 * 899,136 lookup and at the 901,152 processHeaders.
 */

import { describe, test, expect, beforeEach, afterEach, spyOn } from "bun:test";
import { mkdtemp, rm } from "fs/promises";
import { tmpdir } from "os";
import { join } from "path";
import { ChainDB } from "../storage/database.js";
import { BlockStatus } from "../storage/database.js";
import {
  MAINNET,
  bigIntToCompact,
  compactToBigInt,
  type ConsensusParams,
  type AssumeutxoData,
} from "../consensus/params.js";
import { HeaderSync } from "./headers.js";
import {
  serializeBlockHeader,
  getBlockHash,
  type BlockHeader,
} from "../validation/block.js";
import { persistAssumeutxoTailHeaders } from "../chain/snapshot.js";

const BASE = 900_000;
const TAIL_N = 2_027; // 897,974..900,000 — the real rung-900000 band size
const RETARGET = 901_152;
const PERIOD_START = RETARGET - 2016; // 899,136
const EASY_BITS = 0x207fffff;
const T0 = 1_700_000_000;
const VERSION = 0x20000000;

/** Mainnet rules, but a PoW limit the test can mine against in a few tries. */
function easyParams(au?: AssumeutxoData): ConsensusParams {
  return {
    ...MAINNET,
    powLimit: compactToBigInt(EASY_BITS),
    powLimitBits: EASY_BITS,
    assumeutxo: au ? new Map([[au.blockHash.toString("hex"), au]]) : new Map(),
  };
}

function mine(prev: Buffer, height: number, bits: number): BlockHeader {
  const target = compactToBigInt(bits);
  for (let nonce = 0; ; nonce++) {
    const h: BlockHeader = {
      version: VERSION,
      prevBlock: prev,
      merkleRoot: Buffer.alloc(32, height % 251),
      timestamp: T0 + (height - (BASE - TAIL_N)) * 600,
      bits,
      nonce,
    };
    const v = BigInt("0x" + Buffer.from(getBlockHash(h)).reverse().toString("hex"));
    if (v <= target) return h;
  }
}

/** Ascending chain of headers at heights start..start+n-1 on top of `prev`. */
function chain(prev: Buffer, start: number, n: number): BlockHeader[] {
  const out: BlockHeader[] = [];
  for (let i = 0; i < n; i++) {
    const h = mine(prev, start + i, EASY_BITS);
    out.push(h);
    prev = getBlockHash(h);
  }
  return out;
}

describe("snapshot restart keeps the base_tail_headers band anchored", () => {
  let dbPath: string;
  let db: ChainDB;
  let au: AssumeutxoData;
  let baseHash: Buffer;
  let postBase: BlockHeader[];
  const BASE_WORK = 0x5_0000_0000_0000_0000_0000n;

  beforeEach(async () => {
    dbPath = await mkdtemp(join(tmpdir(), "hotbuns-snap-restart-"));
    db = new ChainDB(dbPath);
    await db.open();

    // The band's root has a real parent that is NOT in the index (897,973).
    const tail = chain(Buffer.alloc(32, 0xab), BASE - (TAIL_N - 1), TAIL_N);
    const raw = tail.map(serializeBlockHeader);
    baseHash = getBlockHash(tail[TAIL_N - 1]);
    au = {
      height: BASE,
      hashSerialized: Buffer.alloc(32, 0x33),
      nChainTx: 1n,
      blockHash: baseHash,
      baseHeader: raw[TAIL_N - 1],
      chainWork: BASE_WORK,
      baseTailHeaders: raw,
    };
    postBase = chain(baseHash, BASE + 1, RETARGET - 1 - BASE); // ..901,151

    // --- what cli.ts loadSnapshot persists on import ---
    await db.putChainState({ bestBlockHash: baseHash, bestHeight: BASE, totalWork: BASE_WORK });
    await db.putBlockIndex(baseHash, {
      height: BASE,
      header: au.baseHeader!,
      nTx: 0,
      status: BlockStatus.HEADER_VALID | BlockStatus.TXS_VALID | BlockStatus.HAVE_DATA,
      dataPos: 0,
    });
    await db.putChainWork(baseHash, BASE_WORK);
    expect(await persistAssumeutxoTailHeaders(db, au)).toBe(TAIL_N - 1);

    // --- first process: loadFromDB + adopt (the --load-snapshot path) ---
    const hs1 = new HeaderSync(db, easyParams(au));
    await hs1.loadFromDB();
    await hs1.adoptChainTipAsBestHeader(baseHash, BASE);
    for (let i = 0; i < postBase.length; i += 2000) {
      await hs1.processHeaders(postBase.slice(i, i + 2000));
    }
    // Precondition: a single process reaches 901,151 and can cross 901,152.
    expect(hs1.getBestHeader()!.height).toBe(RETARGET - 1);
    expect(hs1.getHeaderByHeight(PERIOD_START)).toBeDefined();
  });

  afterEach(async () => {
    await db.close();
    await rm(dbPath, { recursive: true, force: true });
  });

  async function crossRetarget(hs: HeaderSync): Promise<void> {
    const parent = hs.getBestHeader()!;
    expect(parent.height).toBe(RETARGET - 1);
    const ts = parent.header.timestamp + 600;
    const bits = bigIntToCompact(hs.getNextTarget(parent, ts));
    const target = compactToBigInt(bits);
    let h: BlockHeader;
    for (let nonce = 0; ; nonce++) {
      h = { version: VERSION, prevBlock: parent.hash, merkleRoot: Buffer.alloc(32, 7), timestamp: ts, bits, nonce };
      const v = BigInt("0x" + Buffer.from(getBlockHash(h)).reverse().toString("hex"));
      if (v <= target) break;
    }
    const accepted = await hs.processHeaders([h!]);
    expect(accepted).toBe(1);
    expect(hs.getBestHeader()!.height).toBe(RETARGET);
  }

  function expectBandAnchored(hs: HeaderSync, workAtBase: bigint): void {
    expect(hs.getBestHeader()!.height).toBe(RETARGET - 1);
    const start = BASE - (TAIL_N - 1);
    expect(hs.getHeaderByHeight(start)).toBeDefined();
    expect(hs.getHeaderByHeight(PERIOD_START)).toBeDefined();
    // Base keeps exactly the chainwork it was imported with: the band is
    // re-derived from it, not from a synthetic lower bound.
    expect(hs.getHeader(baseHash)!.chainWork).toBe(workAtBase);
    expect(hs.getHeaderByHeight(BASE)!.hash.equals(baseHash)).toBe(true);
  }

  test("restart with the campaign entry still loaded crosses the retarget", async () => {
    const hs2 = new HeaderSync(db, easyParams(au));
    await hs2.loadFromDB(); // restart: no --load-snapshot, so no adopt
    expectBandAnchored(hs2, BASE_WORK);
    await crossRetarget(hs2);
  });

  test("restart after the active tip moved past the base crosses the retarget", async () => {
    // Blocks 900,001..900,500 connected: chain state + per-block chainwork.
    const step = new HeaderSync(db, easyParams(au));
    await step.loadFromDB();
    const tip = step.getHeaderByHeight(BASE + 500)!;
    await db.putChainWork(tip.hash, tip.chainWork);
    await db.putChainState({ bestBlockHash: tip.hash, bestHeight: tip.height, totalWork: tip.chainWork });

    const hs2 = new HeaderSync(db, easyParams(au));
    await hs2.loadFromDB();
    expectBandAnchored(hs2, BASE_WORK);
    await crossRetarget(hs2);
  });

  test("restart WITHOUT the campaign entry anchors the band from the active tip", async () => {
    const step = new HeaderSync(db, easyParams(au));
    await step.loadFromDB();
    const tip = step.getHeaderByHeight(BASE + 500)!;
    await db.putChainWork(tip.hash, tip.chainWork);
    await db.putChainState({ bestBlockHash: tip.hash, bestHeight: tip.height, totalWork: tip.chainWork });

    const hs2 = new HeaderSync(db, easyParams()); // env unset on restart
    await hs2.loadFromDB();
    expectBandAnchored(hs2, BASE_WORK);
    await crossRetarget(hs2);
  });

  test("a genuinely disconnected header is still not anchored", async () => {
    const stray = mine(Buffer.alloc(32, 0xcd), 700_000, EASY_BITS);
    const strayHash = getBlockHash(stray);
    await db.putBlockIndex(strayHash, {
      height: 700_000,
      header: serializeBlockHeader(stray),
      nTx: 0,
      status: BlockStatus.HEADER_VALID,
      dataPos: 0,
    }, { writeHeightIndex: false });
    const hs2 = new HeaderSync(db, easyParams(au));
    await hs2.loadFromDB();
    expect(hs2.getHeader(strayHash)).toBeUndefined();
    expectBandAnchored(hs2, BASE_WORK);
  });

  test("a re-delivered batch of orphans logs one line, not one per header", async () => {
    const hs2 = new HeaderSync(db, easyParams(au));
    await hs2.loadFromDB();
    const orphans = chain(Buffer.alloc(32, 0xee), 950_000, 300);
    const warn = spyOn(console, "warn").mockImplementation(() => {});
    try {
      for (let round = 0; round < 5; round++) {
        expect(await hs2.processHeaders(orphans)).toBe(0);
      }
      const lines = warn.mock.calls
        .map((c) => String(c[0]))
        .filter((l) => l.startsWith("Orphan header received:"));
      expect(lines.length).toBe(1);
    } finally {
      warn.mockRestore();
    }
  });
});
