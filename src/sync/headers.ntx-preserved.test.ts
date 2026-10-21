/**
 * A header re-save must not erase the tx count of a connected block.
 *
 * Regression for the nightly consensus-diff (2026-10-21): getblockheader of
 * mainnet 945000 answered nTx 0 where Core answers 3994. Connected blocks
 * outside the reorg-retention window are stored with dataPos 0 (no body kept),
 * and HeaderSync.saveHeaderEntry only preserved an existing record when
 * `nTx > 0 && dataPos > 0`, so re-saving the header zeroed nTx and the
 * TXS_VALID/HAVE_DATA status bits, and the body-recount fallback in
 * getblockheader could not recover it (no body).
 */

import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { mkdtemp, rm } from "fs/promises";
import { tmpdir } from "os";
import { join } from "path";
import { ChainDB, BlockStatus } from "../storage/database.js";
import { REGTEST } from "../consensus/params.js";
import { HeaderSync, type HeaderChainEntry } from "./headers.js";
import { serializeBlockHeader, getBlockHash } from "../validation/block.js";

describe("HeaderSync.saveHeaderEntry preserves nTx of a connected block", () => {
  let dir: string;
  let db: ChainDB;

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "hb-ntx-"));
    db = new ChainDB(join(dir, "db"));
    await db.open();
  });
  afterEach(async () => {
    await db.close();
    await rm(dir, { recursive: true, force: true });
  });

  for (const dataPos of [0, 1]) {
    test(`nTx and status survive a header re-save (dataPos=${dataPos})`, async () => {
      const header = {
        version: 0x20000000,
        prevBlock: Buffer.alloc(32, 1),
        merkleRoot: Buffer.alloc(32, 2),
        timestamp: 1600000000,
        bits: 0x207fffff,
        nonce: 7,
      };
      const hash = getBlockHash(header);
      const status =
        BlockStatus.HEADER_VALID | BlockStatus.TXS_VALID | BlockStatus.HAVE_DATA;
      await db.putBlockIndex(
        hash,
        { height: 945000, header: serializeBlockHeader(header), nTx: 3994, status, dataPos },
        { writeHeightIndex: false },
      );

      const hs = new HeaderSync(db, REGTEST);
      const entry: HeaderChainEntry = {
        hash, header, height: 945000, chainWork: 1n, status: "valid-header",
      };
      await (hs as any).saveHeaderEntry(entry);

      const after = await db.getBlockIndex(hash);
      expect(after!.nTx).toBe(3994);
      expect(after!.status & BlockStatus.TXS_VALID).not.toBe(0);
      expect(after!.dataPos).toBe(dataPos);
    });
  }
});
