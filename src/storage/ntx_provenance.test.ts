import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { mkdtemp, rm, readFile } from "fs/promises";
import { tmpdir } from "os";
import { join } from "path";
import { ChainDB, BlockStatus } from "./database.js";
import {
  reconcileNTxProvenance, reconcileNTxProvenanceOnce, txCountFromRawBlock, NTX_PROVENANCE_MARKER,
} from "./ntx_provenance.js";

const H = (b: number) => Buffer.alloc(32, b);
const rawBlock = (n: number) => Buffer.concat([Buffer.alloc(80, 1), Buffer.from([n]), Buffer.alloc(10, 2)]);

const V = BlockStatus.HEADER_VALID | BlockStatus.TXS_KNOWN | BlockStatus.TXS_VALID; // blocks.ts connect
const SNAPBASE = BlockStatus.HEADER_VALID | BlockStatus.TXS_VALID | BlockStatus.HAVE_DATA; // snapshot loader

describe("reconcileNTxProvenance (R3: no Core-sourced nTx survives)", () => {
  let dir: string;
  let db: ChainDB;

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "hotbuns-ntxprov-"));
    db = new ChainDB(join(dir, "db"));
    await db.open();
  });
  afterEach(async () => {
    await db.close();
    await rm(dir, { recursive: true, force: true });
  });

  async function put(hash: Buffer, height: number, nTx: number, status: number, body?: number) {
    await db.putBlockIndex(hash, { height, header: Buffer.alloc(80), nTx, status, dataPos: body ? 1 : 0 },
      { writeHeightIndex: false });
    if (body !== undefined) await db.putBlock(hash, rawBlock(body));
  }
  const nTxOf = async (h: Buffer) => (await db.getBlockIndex(h))!.nTx;

  test("each class lands on Core's nTx semantics; second run is a no-op", async () => {
    await put(H(1), 10, 5, V);                                   // validated here, body pruned -> kept
    await put(H(2), 11, 7, BlockStatus.HEADER_VALID);            // header-only with a Core nTx -> 0
    await put(H(3), 12, 9, SNAPBASE);                            // snapshot base with a Core nTx -> 0
    await put(H(4), 13, 0, V | BlockStatus.HAVE_DATA, 3);        // body held, nTx 0 -> filled 3
    await put(H(5), 14, 99, V | BlockStatus.HAVE_DATA, 4);       // body held, wrong nTx -> 4
    await put(H(6), 15, 4, V);                                   // chainparams assumeutxo base -> 0
    await put(H(7), 16, 0, BlockStatus.HEADER_VALID);            // header-only, 0 -> stays 0
    await put(H(8), 0, 1, SNAPBASE, 1);                          // genesis-shaped, body held -> recount
    await put(H(9), 17, 6, BlockStatus.HEADER_VALID, 6);         // side-branch body held -> kept via recount

    const bases = new Set([H(6).toString("hex")]);
    const r = await reconcileNTxProvenance(db, bases);
    expect(await nTxOf(H(1))).toBe(5);
    expect(await nTxOf(H(2))).toBe(0);
    expect(await nTxOf(H(3))).toBe(0);
    expect(await nTxOf(H(4))).toBe(3);
    expect(await nTxOf(H(5))).toBe(4);
    expect(await nTxOf(H(6))).toBe(0);
    expect(await nTxOf(H(7))).toBe(0);
    expect(await nTxOf(H(8))).toBe(1);
    expect(await nTxOf(H(9))).toBe(6);
    expect(r).toEqual({
      scanned: 9, keptValidated: 1, recounted: 3, corrected: 1, filled: 1, reset: 3, unreadable: 0,
    });

    const r2 = await reconcileNTxProvenance(db, bases);
    expect(r2.corrected + r2.filled + r2.reset).toBe(0);
    expect(r2.scanned).toBe(9);
  });

  test("never touches the active-chain height index", async () => {
    await db.putBlockHashByHeight(11, H(0xaa));
    await put(H(2), 11, 7, BlockStatus.HEADER_VALID);
    await reconcileNTxProvenance(db);
    expect((await db.getBlockHashByHeight(11))!.equals(H(0xaa))).toBe(true);
  });

  test("once-wrapper: first boot reconciles and marks, later boots skip", async () => {
    await put(H(2), 11, 7, BlockStatus.HEADER_VALID);
    const r1 = await reconcileNTxProvenanceOnce(db);
    expect(r1).not.toBeNull();
    expect(r1!.reset).toBe(1);
    expect(await db.getMarker(NTX_PROVENANCE_MARKER)).not.toBeNull();
    // A value planted after the marker is NOT rescanned: proves the skip.
    await put(H(3), 12, 9, BlockStatus.HEADER_VALID);
    expect(await reconcileNTxProvenanceOnce(db)).toBeNull();
    expect(await nTxOf(H(3))).toBe(9);
  });

  test("once-wrapper: an unreadable body leaves the marker unset (retry next boot)", async () => {
    await db.putBlockIndex(H(4), { height: 13, header: Buffer.alloc(80), nTx: 0,
      status: V | BlockStatus.HAVE_DATA, dataPos: 1 }, { writeHeightIndex: false });
    await db.putBlock(H(4), Buffer.alloc(80)); // header only: tx count unreadable
    const r = await reconcileNTxProvenanceOnce(db);
    expect(r!.unreadable).toBe(1);
    expect(await db.getMarker(NTX_PROVENANCE_MARKER)).toBeNull();
    expect(await reconcileNTxProvenanceOnce(db)).not.toBeNull();
  });

  test("tx count is the CompactSize after the 80-byte header", () => {
    expect(txCountFromRawBlock(rawBlock(1))).toBe(1);
    const big = Buffer.concat([Buffer.alloc(80), Buffer.from([0xfd, 0x10, 0x27])]);
    expect(txCountFromRawBlock(big)).toBe(10000);
    expect(() => txCountFromRawBlock(Buffer.alloc(80))).toThrow();
  });

  test("production startup path no longer contains any Core RPC / cookie access", async () => {
    const cli = await readFile(join(import.meta.dir, "../cli/cli.ts"), "utf8");
    expect(cli.includes("function migrateNTxBackfill")).toBe(false);
    expect(cli.includes('"bitcoin-core"')).toBe(false);
    expect(/fetch\("http:\/\/127\.0\.0\.1:8332/.test(cli)).toBe(false);
    expect(cli.includes("reconcileNTxProvenanceOnce(db")).toBe(true);
  });
});
