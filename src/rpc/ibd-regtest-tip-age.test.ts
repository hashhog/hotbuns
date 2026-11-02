/**
 * initialblockdownload on regtest (Core validation.cpp IsInitialBlockDownload):
 * a tip older than max_tip_age (24h) against GetTime() keeps IBD true, and
 * -mocktime moves GetTime(). Regtest has no special exemption.
 */

import { describe, it, expect, afterEach } from "bun:test";
import { RPCServer } from "./server.js";
import { REGTEST } from "../consensus/params.js";
import { nowSeconds, setMockTime } from "../clock.js";

function makeServer(): any {
  const deps: any = {
    chainState: { getBestBlock: () => ({ hash: Buffer.alloc(32), height: 0, chainWork: 0n }) },
    mempool: {}, peerManager: {}, feeEstimator: {}, headerSync: {}, db: {}, params: REGTEST,
  };
  return new RPCServer({ port: 0, host: "127.0.0.1", noAuth: true } as any, deps);
}

describe("regtest initialblockdownload tip-age gate", () => {
  afterEach(() => setMockTime(0));

  it("is true while the regtest tip is older than 24h", () => {
    const s = makeServer();
    const stale = nowSeconds() - 3 * 24 * 3600;
    expect(s.computeInitialBlockDownload(0n, stale)).toBe(true);
  });

  it("latches false once the tip is recent, and stays false", () => {
    const s = makeServer();
    expect(s.computeInitialBlockDownload(0n, nowSeconds() - 60)).toBe(false);
    expect(s.computeInitialBlockDownload(0n, nowSeconds() - 3 * 24 * 3600)).toBe(false);
  });

  it("honours setmocktime: a backdated tip is current under mocktime", () => {
    const s = makeServer();
    const tip = nowSeconds() - 3 * 24 * 3600;
    setMockTime(tip + 10);
    expect(s.computeInitialBlockDownload(0n, tip)).toBe(false);
  });
});
