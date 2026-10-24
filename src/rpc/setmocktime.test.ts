/**
 * setmocktime (Core rpc/node.cpp): regtest-only mock clock. Drives the
 * mempool's rolling-fee decay and entry timestamps.
 */

import { describe, it, expect, afterEach } from "bun:test";
import { RPCServer, RPCErrorCodes } from "./server.js";
import { REGTEST, MAINNET } from "../consensus/params.js";
import { nowSeconds, setMockTime } from "../clock.js";

function makeServer(params: any): RPCServer {
  const deps: any = {
    chainState: { getBestBlock: () => ({ hash: Buffer.alloc(32), height: 0, chainWork: 0n }) },
    mempool: {},
    peerManager: {},
    feeEstimator: {},
    headerSync: {},
    db: {},
    params,
  };
  return new RPCServer({ port: 0, host: "127.0.0.1", noAuth: true } as any, deps);
}

describe("setmocktime", () => {
  afterEach(() => setMockTime(0));

  it("sets the mock clock on regtest and returns null", async () => {
    const s: any = makeServer(REGTEST);
    const r = await s.processRequest.call(s, { jsonrpc: "2.0", id: 1, method: "setmocktime", params: [1_700_000_000] });
    expect(r.error).toBeUndefined();
    expect(r.result).toBeNull();
    expect(nowSeconds()).toBe(1_700_000_000);
  });

  it("0 returns to the system clock", async () => {
    const s: any = makeServer(REGTEST);
    await s.processRequest.call(s, { jsonrpc: "2.0", id: 1, method: "setmocktime", params: [1_700_000_000] });
    await s.processRequest.call(s, { jsonrpc: "2.0", id: 2, method: "setmocktime", params: [0] });
    expect(Math.abs(nowSeconds() - Math.floor(Date.now() / 1000))).toBeLessThanOrEqual(1);
  });

  it("rejects a negative time with -8", async () => {
    const s: any = makeServer(REGTEST);
    const r = await s.processRequest.call(s, { jsonrpc: "2.0", id: 1, method: "setmocktime", params: [-1] });
    expect(r.error.code).toBe(RPCErrorCodes.INVALID_PARAMETER);
  });

  it("is refused off regtest", async () => {
    const s: any = makeServer(MAINNET);
    const r = await s.processRequest.call(s, { jsonrpc: "2.0", id: 1, method: "setmocktime", params: [1_700_000_000] });
    expect(r.error).toBeDefined();
    expect(r.error.message).toContain("regression testing (-regtest mode) only");
    expect(nowSeconds()).not.toBe(1_700_000_000);
  });
});
