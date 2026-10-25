/**
 * /rest/mempool/info must carry the same object as the getmempoolinfo RPC
 * (Core: rest_mempool_info and getmempoolinfo both call MempoolInfoToJSON).
 */

import { describe, test, expect, beforeAll, afterAll } from "bun:test";
import { RESTServer } from "../rpc/rest.js";
import { REGTEST } from "../consensus/params.js";

// Key order of Core v31 MempoolInfoToJSON (rpc/mempool.cpp).
const CORE_KEYS = [
  "loaded",
  "size",
  "bytes",
  "usage",
  "total_fee",
  "maxmempool",
  "mempoolminfee",
  "minrelaytxfee",
  "incrementalrelayfee",
  "unbroadcastcount",
  "fullrbf",
  "permitbaremultisig",
  "maxdatacarriersize",
  "limitclustercount",
  "limitclustersize",
  "optimal",
];

const feeA = 12_345n;
const feeB = 100_000n;
const txids = [Buffer.alloc(32, 1), Buffer.alloc(32, 2)];

const mockMempool = {
  getInfo: () => ({ size: 2, bytes: 400, usage: 900, maxmempool: 300_000_000, minFeeRate: 1 }),
  getAllTxids: () => txids,
  getTransaction: (txid: Buffer) => ({ fee: txid[0] === 1 ? feeA : feeB }),
  // One of the two entries has not been announced to a peer yet.
  getUnbroadcastTxs: () => new Set([txids[1].toString("hex")]),
};

describe("rest mempool/info", () => {
  let server: RESTServer;
  let baseUrl: string;

  beforeAll(async () => {
    const port = 19332 + Math.floor(Math.random() * 1000);
    server = new RESTServer(
      { port, host: "127.0.0.1", txIndexEnabled: false },
      {
        chainState: {} as any,
        mempool: mockMempool as any,
        headerSync: {} as any,
        db: {} as any,
        params: REGTEST,
      }
    );
    server.start();
    baseUrl = `http://127.0.0.1:${port}`;
    await new Promise((r) => setTimeout(r, 50));
  });

  afterAll(() => server.stop());

  test("carries every Core 31 getmempoolinfo field, in Core's order", async () => {
    const res = await fetch(`${baseUrl}/rest/mempool/info.json`);
    expect(res.status).toBe(200);
    const json = await res.json();
    expect(Object.keys(json)).toEqual(CORE_KEYS);
  });

  test("total_fee sums the entry fees in BTC; policy fields use Core defaults", async () => {
    const json = await (await fetch(`${baseUrl}/rest/mempool/info.json`)).json();
    expect(json.total_fee).toBeCloseTo(Number(feeA + feeB) / 1e8, 12);
    expect(json.fullrbf).toBe(true);
    expect(json.permitbaremultisig).toBe(true);
    expect(json.maxdatacarriersize).toBe(100_000);
    expect(json.limitclustercount).toBe(64);
    expect(json.limitclustersize).toBe(101_000);
    expect(json.incrementalrelayfee).toBe(0.000001);
    expect(json.optimal).toBe(true);
  });

  test("unbroadcastcount is the live unbroadcast-set size, as in getmempoolinfo", async () => {
    const json = await (await fetch(`${baseUrl}/rest/mempool/info.json`)).json();
    expect(json.unbroadcastcount).toBe(1);
  });
});
