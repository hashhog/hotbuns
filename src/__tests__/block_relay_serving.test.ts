/**
 * Block relay serving parity (regtest relay test 2026-09-26).
 *
 * Two Bitcoin Core nodes that could only reach each other through hotbuns did
 * not converge:
 *  (1) hotbuns never answered a getheaders it had nothing new for. Core only
 *      clears m_last_getheaders_timestamp on a HEADERS reply, so its
 *      MaybeSendGetHeaders then suppressed the inv-triggered getheaders for
 *      HEADERS_RESPONSE_TIME (2 min) — every block hotbuns announced by inv in
 *      that window was ignored. Core's GETHEADERS handler always replies,
 *      with an empty `headers` when the peer is at our tip.
 *  (2) getdata(MSG_CMPCT_BLOCK) — how a Core peer that chose hotbuns as a
 *      BIP-152 high-bandwidth peer fetches a new tip — was silently dropped.
 */
import { describe, expect, test, beforeEach, afterEach } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { ChainDB } from "../storage/database.js";
import { BlockSync } from "../sync/blocks.js";
import { HeaderSync } from "../sync/headers.js";
import { REGTEST } from "../consensus/params.js";
import { InvType } from "../p2p/messages.js";
import type { NetworkMessage } from "../p2p/messages.js";
import { createHash } from "node:crypto";

function stubPeer() {
  const sent: NetworkMessage[] = [];
  const peer: any = {
    host: "127.0.0.1",
    port: 1,
    send(msg: NetworkMessage) {
      sent.push(msg);
      return true;
    },
  };
  return { peer, sent };
}

function sha256d(b: Buffer): Buffer {
  return createHash("sha256").update(createHash("sha256").update(b).digest()).digest();
}

describe("block relay serving", () => {
  let dataDir: string;
  let db: ChainDB;
  let headerSync: HeaderSync;

  beforeEach(async () => {
    dataDir = await mkdtemp(join(tmpdir(), "hotbuns-blockrelay-"));
    db = new ChainDB(join(dataDir, "blocks.db"));
    await db.open();
    headerSync = new HeaderSync(db, REGTEST);
  });

  afterEach(async () => {
    await db.close();
    await rm(dataDir, { recursive: true, force: true });
  });

  test("getheaders at our tip gets an EMPTY headers reply (Core always answers)", async () => {
    const { peer, sent } = stubPeer();
    const genesisHash = (REGTEST as any).genesisBlockHash as Buffer;
    await (headerSync as any).handleGetHeaders(peer, {
      version: 70016,
      locatorHashes: [genesisHash],
      hashStop: Buffer.alloc(32),
    });
    const headers = sent.filter((m) => m.type === "headers");
    expect(headers.length).toBe(1);
    expect((headers[0].payload as any).headers.length).toBe(0);
  });

  test("getdata(MSG_CMPCT_BLOCK) is answered with the block", async () => {
    const raw = (REGTEST as any).genesisBlock as Buffer;
    const hash = sha256d(raw.subarray(0, 80));
    await db.putBlock(hash, raw);
    const sync = new BlockSync(db, REGTEST, headerSync) as any;
    for (const type of [InvType.MSG_CMPCT_BLOCK, InvType.MSG_WITNESS_BLOCK]) {
      const { peer, sent } = stubPeer();
      await sync.handleGetData(peer, [{ type, hash }]);
      const blocks = sent.filter((m) => m.type === "block");
      expect(blocks.length).toBe(1);
    }
  });
});
