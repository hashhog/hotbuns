/**
 * Snapshot-boot must seed `base_tail_headers`, not only the base.
 *
 * Receipt 2026-09-11: after snapshot load hotbuns held genesis + the seeded
 * base (`hdrs=2`). GetNextWorkRequired at 60,480 needs height 58,464, which
 * is below the base, so the retarget was computed fail-open (parent bits)
 * and every later header was an orphan.
 *
 * Negative control: a 60,480 header carrying 60,479's bits must be rejected
 * when the period-start ancestor is missing (Core asserts pindexFirst).
 * Positive: seeding the tail band makes the ancestor resolvable.
 */

import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { mkdtemp, rm } from "fs/promises";
import { tmpdir } from "os";
import { join } from "path";
import { ChainDB } from "../storage/database.js";
import {
  MAINNET,
  compactToBigInt,
  bigIntToCompact,
  type ConsensusParams,
  type AssumeutxoData,
} from "../consensus/params.js";
import { HeaderSync } from "./headers.js";
import {
  serializeBlockHeader,
  getBlockHash,
  type BlockHeader,
} from "../validation/block.js";
import { getNextWorkRequired } from "../consensus/pow.js";

const BASE_HEIGHT = 60_000;
const PERIOD_START = 58_464; // 60480 - 2016
const PARENT_HEIGHT = 60_479;
const RETARGET_HEIGHT = 60_480;
const PARENT_BITS = 0x1c0f675c;
const PARENT_TIME = 1_281_893_874;

function linkedRaw(n: number, bits: number, startTime: number): Buffer[] {
  const raw: Buffer[] = [];
  let prev = Buffer.alloc(32, 0);
  for (let i = 0; i < n; i++) {
    const header: BlockHeader = {
      version: 4,
      prevBlock: prev,
      merkleRoot: Buffer.alloc(32, (i % 255) + 1),
      timestamp: startTime + i * 600,
      bits,
      nonce: i,
    };
    raw.push(serializeBlockHeader(header));
    prev = getBlockHash(header);
  }
  return raw;
}

function headerFromRaw(buf: Buffer): BlockHeader {
  return {
    version: buf.readInt32LE(0),
    prevBlock: Buffer.from(buf.subarray(4, 36)),
    merkleRoot: Buffer.from(buf.subarray(36, 68)),
    timestamp: buf.readUInt32LE(68),
    bits: buf.readUInt32LE(72),
    nonce: buf.readUInt32LE(76),
  };
}

describe("snapshot-boot base_tail_headers (retarget 60480)", () => {
  let dbPath: string;
  let db: ChainDB;

  beforeEach(async () => {
    dbPath = await mkdtemp(join(tmpdir(), "hotbuns-snapshot-tail-"));
    db = new ChainDB(dbPath);
    await db.open();
  });

  afterEach(async () => {
    await db.close();
    await rm(dbPath, { recursive: true, force: true });
  });

  test("negative: 60480 header with 60479 bits is rejected when 58464 is missing", async () => {
    const hs = new HeaderSync(db, MAINNET);
    hs.initGenesis();

    const parentHeader: BlockHeader = {
      version: 4,
      prevBlock: Buffer.alloc(32, 0),
      merkleRoot: Buffer.alloc(32, 0x11),
      timestamp: PARENT_TIME,
      bits: PARENT_BITS,
      nonce: 1,
    };
    const parentHash = getBlockHash(parentHeader);
    await hs.seedHeader({
      hash: parentHash,
      header: parentHeader,
      height: PARENT_HEIGHT,
      chainWork: 0x1000n,
    });
    const parent = hs.getHeader(parentHash)!;

    const candidate: BlockHeader = {
      version: 4,
      prevBlock: parentHash,
      merkleRoot: Buffer.alloc(32, 0x22),
      timestamp: PARENT_TIME + 600,
      bits: PARENT_BITS, // 60479's bits — the fail-open answer
      nonce: 2,
    };

    const verdict = hs.validateHeader(candidate, parent, {
      skipPow: true,
      now: PARENT_TIME + 600,
    });
    expect(verdict.valid).toBe(false);
    expect(verdict.error).toMatch(/bad-diffbits/);
    expect(verdict.error).toMatch(/58464/);
  });

  test("adoptChainTipAsBestHeader seeds the tail band below the base", async () => {
    const n = 16;
    const raw = linkedRaw(n, PARENT_BITS, 1_280_000_000);
    const last = headerFromRaw(raw[n - 1]);
    const baseHash = getBlockHash(last);
    const au: AssumeutxoData = {
      height: BASE_HEIGHT,
      hashSerialized: Buffer.alloc(32, 0x33),
      nChainTx: 1n,
      blockHash: baseHash,
      baseHeader: raw[n - 1],
      chainWork: 0x2000n,
      baseTailHeaders: raw,
    };
    const params: ConsensusParams = {
      ...MAINNET,
      assumeutxo: new Map([[baseHash.toString("hex"), au]]),
    };
    const hs = new HeaderSync(db, params);
    hs.initGenesis();
    expect(hs.getBestHeader()!.height).toBe(0);

    await hs.adoptChainTipAsBestHeader(baseHash, BASE_HEIGHT);

    const best = hs.getBestHeader();
    expect(best).not.toBeNull();
    expect(best!.height).toBe(BASE_HEIGHT);
    expect(best!.hash.equals(baseHash)).toBe(true);
    expect(hs.getHeaderCount()).toBe(n + 1); // genesis + band
    const startHeight = BASE_HEIGHT - (n - 1);
    expect(hs.getHeaderByHeight(startHeight)).toBeDefined();
    expect(hs.getHeaderByHeight(BASE_HEIGHT)?.hash.equals(baseHash)).toBe(true);
    // Hash-linked walk from the base reaches the oldest tail.
    let cur = hs.getHeader(baseHash);
    let steps = 0;
    while (cur && cur.height > startHeight) {
      cur = hs.getHeader(cur.header.prevBlock);
      steps++;
    }
    expect(cur?.height).toBe(startHeight);
    expect(steps).toBe(n - 1);
  });

  test("with the period-start ancestor linked, 60480 required bits is not parent bits", async () => {
    // Minimal hash-linked ancestry: 58464 <- 60479. getNextTarget walks
    // prevBlock, not consecutive heights.
    const first: BlockHeader = {
      version: 4,
      prevBlock: Buffer.alloc(32, 0),
      merkleRoot: Buffer.alloc(32, 0x01),
      timestamp: PARENT_TIME - 7 * 24 * 3600,
      bits: PARENT_BITS,
      nonce: 1,
    };
    const firstHash = getBlockHash(first);
    const parentHeader: BlockHeader = {
      version: 4,
      prevBlock: firstHash,
      merkleRoot: Buffer.alloc(32, 0x02),
      timestamp: PARENT_TIME,
      bits: PARENT_BITS,
      nonce: 2,
    };
    const parentHash = getBlockHash(parentHeader);

    const hs = new HeaderSync(db, MAINNET);
    hs.initGenesis();
    await hs.seedHeader({
      hash: firstHash,
      header: first,
      height: PERIOD_START,
      chainWork: 0x1000n,
    });
    await hs.seedHeader({
      hash: parentHash,
      header: parentHeader,
      height: PARENT_HEIGHT,
      chainWork: 0x2000n,
    });
    const parent = hs.getHeader(parentHash)!;

    const required = hs.getNextTarget(parent, PARENT_TIME + 600);
    const requiredBits = bigIntToCompact(required);
    expect(requiredBits).not.toBe(PARENT_BITS);

    const lookup = (h: number) => {
      const e = h === PERIOD_START ? hs.getHeader(firstHash) : h === PARENT_HEIGHT ? parent : undefined;
      return e
        ? { height: e.height, header: { timestamp: e.header.timestamp, bits: e.header.bits } }
        : undefined;
    };
    expect(required).toBe(
      getNextWorkRequired(
        { height: PARENT_HEIGHT, header: { timestamp: PARENT_TIME, bits: PARENT_BITS } },
        PARENT_TIME + 600,
        MAINNET,
        lookup,
      ),
    );
    expect(required).toBe(compactToBigInt(requiredBits));

    const wrong: BlockHeader = {
      version: 4,
      prevBlock: parentHash,
      merkleRoot: Buffer.alloc(32, 0x03),
      timestamp: PARENT_TIME + 600,
      bits: PARENT_BITS,
      nonce: 3,
    };
    const verdict = hs.validateHeader(wrong, parent, {
      skipPow: true,
      now: PARENT_TIME + 600,
    });
    expect(verdict.valid).toBe(false);
    expect(verdict.error).toMatch(/bad-diffbits/);
  });
});
