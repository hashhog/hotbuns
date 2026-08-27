/**
 * #47 chain-selection tier — work-vs-length pins on header-tip selection.
 *
 * Regtest cannot express work-vs-length through addHeaders (validateHeader's
 * bad-diffbits gate binds every header to GetNextWorkRequired), but the
 * boot-time loadFromDB() path is a REAL production path with no diffbits
 * gate: it trusts persisted BlockIndexRecords and recomputes chainWork from
 * each header's own bits (getHeaderWork(header.bits)), then applies the same
 * work-only selection predicate the live insert path uses
 * (chainWork > bestHeader.chainWork).  These tests persist two forks with
 * divergent bits and assert selection over the recomputed works.
 *
 * The comparator is currently SOUND (work-only bigint compare).  Binding
 * verified during authoring: substituting record height for chainWork in the
 * loader's predicate makes both tests fail (see #47 ledger entry).
 *
 * Record layout (loadFromDB): key = [0x62] || hash(32); value(96) =
 * height u32LE | header(80) | nTx u32LE | status u32LE (bit0 = valid) |
 * dataPos u32LE.  Stored hashes are trusted as-is, so fixture hashes are
 * synthetic markers, and the persisted header tip only gates entry into the
 * loader — final selection is recomputed from work.
 */

import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { mkdtemp, rm } from "fs/promises";
import { tmpdir } from "os";
import { join } from "path";
import { ChainDB } from "../storage/database.js";
import { REGTEST } from "../consensus/params.js";
import { HeaderSync } from "./headers.js";

const WEAK_BITS = REGTEST.powLimitBits; // 0x207fffff -> work ~2 per header
const STRONG_BITS = 0x1a400000; // target 2^206 -> work ~2^50 per header

function fakeHash(marker: number): Buffer {
  return Buffer.alloc(32, marker);
}

function makeRecordValue(height: number, prevHash: Buffer, bits: number): Buffer {
  const header = Buffer.alloc(80);
  header.writeInt32LE(4, 0); // version
  prevHash.copy(header, 4); // prevBlock
  Buffer.alloc(32, height).copy(header, 36); // merkleRoot (arbitrary)
  header.writeUInt32LE(1_600_000_000 + height * 600, 68); // timestamp
  header.writeUInt32LE(bits >>> 0, 72); // bits
  header.writeUInt32LE(0, 76); // nonce

  const value = Buffer.alloc(96);
  value.writeUInt32LE(height, 0);
  header.copy(value, 4);
  value.writeUInt32LE(0, 84); // nTx
  value.writeUInt32LE(1, 88); // status: bit0 = valid
  value.writeUInt32LE(0, 92); // dataPos
  return value;
}

async function putRecord(
  db: ChainDB,
  hash: Buffer,
  height: number,
  prevHash: Buffer,
  bits: number
): Promise<void> {
  const key = Buffer.concat([Buffer.from([0x62]), hash]);
  await (db as any).db.put(key, makeRecordValue(height, prevHash, bits));
}

describe("header-tip selection: work vs length (#47)", () => {
  let dbPath: string;
  let db: ChainDB;

  beforeEach(async () => {
    dbPath = await mkdtemp(join(tmpdir(), "hotbuns-workvslength-"));
    db = new ChainDB(dbPath);
    await db.open();
  });

  afterEach(async () => {
    await db.close();
    await rm(dbPath, { recursive: true, force: true });
  });

  /** Persist a 5-header weak fork and a 2-header strong fork off genesis. */
  async function persistForks(): Promise<{ lightTip: Buffer; heavyTip: Buffer }> {
    let prev = REGTEST.genesisBlockHash;
    let lightTip = prev;
    for (let h = 1; h <= 5; h++) {
      const hash = fakeHash(0x10 + h);
      await putRecord(db, hash, h, prev, WEAK_BITS);
      prev = hash;
      lightTip = hash;
    }
    prev = REGTEST.genesisBlockHash;
    let heavyTip = prev;
    for (let h = 1; h <= 2; h++) {
      const hash = fakeHash(0x20 + h);
      await putRecord(db, hash, h, prev, STRONG_BITS);
      prev = hash;
      heavyTip = hash;
    }
    return { lightTip, heavyTip };
  }

  test("heavier-but-shorter fork wins on reload", async () => {
    const { lightTip, heavyTip } = await persistForks();
    // Stored tip pointer deliberately claims the LIGHT tip: selection must be
    // recomputed from work, not restored from the pointer.
    await db.putUndoData(Buffer.from("header_tip"), lightTip);

    const hs = new HeaderSync(db, REGTEST);
    await hs.loadFromDB();

    const best = hs.getBestHeader();
    expect(best).not.toBeNull();
    expect(best!.hash.equals(heavyTip)).toBe(true);
    expect(best!.height).toBe(2);
  });

  test("longer-but-lighter fork is loaded but never displaces the heavy tip", async () => {
    const { lightTip, heavyTip } = await persistForks();
    await db.putUndoData(Buffer.from("header_tip"), heavyTip);

    const hs = new HeaderSync(db, REGTEST);
    await hs.loadFromDB();

    // The light fork's 5 headers all loaded (genesis + 5 light + 2 heavy)...
    expect(hs.getHeaderCount()).toBe(8);
    const lightEntry = (hs as any).headerChain.get(lightTip.toString("hex"));
    expect(lightEntry).toBeDefined();
    expect(lightEntry.status).toBe("valid-header");
    // ...its height exceeds the heavy tip's...
    expect(lightEntry.height).toBe(5);
    // ...and selection still refuses it: length never beats work.
    const best = hs.getBestHeader();
    expect(best!.hash.equals(heavyTip)).toBe(true);
  });
});
