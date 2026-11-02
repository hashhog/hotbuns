/**
 * /rest/mempool/contents entries must carry Core's entryToJSON shape, the same
 * object getrawmempool(verbose) and getmempoolentry return (rpc/mempool.cpp
 * entryToJSON; rest.cpp rest_mempool calls MempoolToJSON(verbose=true)).
 *
 * hotbuns' REST handler built its own object: it added top-level `fee` and
 * `modifiedfee` (removed from Core in v23) and lacked `chunkweight`,
 * `fees.chunk`, `bip125-replaceable` and `unbroadcast`.
 * tools/core-regtest row warden_invalidated_submit/rest/tip100-contents.
 */

import { describe, test, expect, beforeAll, afterAll } from "bun:test";
import { RESTServer } from "../rpc/rest.js";
import { REGTEST } from "../consensus/params.js";
import type { Transaction } from "../validation/tx.js";

const txid = Buffer.alloc(32, 7);
const tx: Transaction = {
  version: 2,
  inputs: [
    { prevOut: { txid: Buffer.alloc(32, 9), vout: 0 }, scriptSig: Buffer.alloc(0), sequence: 0xfffffffd, witness: [] },
  ],
  outputs: [{ value: 1000n, scriptPubKey: Buffer.from([0x51]) }],
  lockTime: 0,
};

const mockMempool = {
  getAllTxids: () => [txid],
  getTransaction: () => ({
    tx, vsize: 100, weight: 400, fee: 1_000_000n, addedTime: 1700000000, height: 101,
  }),
  getEntryRelatives: () => ({
    descendantCount: 1, descendantSize: 100, ancestorCount: 1, ancestorSize: 100,
    ancestorFees: 1_000_000n, descendantFees: 1_000_000n, depends: [], spentby: [],
  }),
  getModifiedFee: () => 1_000_000n,
  getMainChunkFeerate: () => ({ fee: 1_000_000n, size: 400 }),
  getRBFOptInState: () => 1,
  isUnbroadcast: () => true,
};

describe("rest mempool/contents entry shape", () => {
  let server: RESTServer;
  let baseUrl: string;

  beforeAll(async () => {
    const port = 20332 + Math.floor(Math.random() * 1000);
    server = new RESTServer(
      { port, host: "127.0.0.1", txIndexEnabled: false },
      { chainState: {} as any, mempool: mockMempool as any, headerSync: {} as any, db: {} as any, params: REGTEST },
    );
    server.start();
    baseUrl = `http://127.0.0.1:${port}`;
    await new Promise((r) => setTimeout(r, 50));
  });
  afterAll(() => server.stop());

  test("entry has exactly Core 31's entryToJSON keys (no fee/modifiedfee)", async () => {
    const json: any = await (await fetch(`${baseUrl}/rest/mempool/contents.json`)).json();
    const e = json[Buffer.from(txid).reverse().toString("hex")];
    expect(Object.keys(e).sort()).toEqual(
      [
        "vsize", "weight", "time", "height", "descendantcount", "descendantsize",
        "ancestorcount", "ancestorsize", "chunkweight", "wtxid", "fees", "depends",
        "spentby", "bip125-replaceable", "unbroadcast",
      ].sort(),
    );
    expect(Object.keys(e.fees).sort()).toEqual(["ancestor", "base", "chunk", "descendant", "modified"]);
    expect(e.chunkweight).toBe(400);
    expect(e.fees.chunk).toBe(0.01);
    expect(typeof e["bip125-replaceable"]).toBe("boolean");
    expect(e.unbroadcast).toBe(true);
  });
});
