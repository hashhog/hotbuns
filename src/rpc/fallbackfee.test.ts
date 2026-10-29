/**
 * Core-style -fallbackfee for wallet sends (hotbuns-fallbackfee).
 *
 * Core (wallet/fees.cpp GetMinimumFeeRate): explicit fee_rate wins; else the
 * fee estimator; if it has no data, -fallbackfee; if that is 0 (the default),
 * the send fails with -6 "Fee estimation failed. Fallbackfee is disabled...".
 * hotbuns used to hardcode 1 sat/vB (send/sendtoaddress) and 20 sat/vB (the
 * estimator's "no data" value).
 */
import { describe, it, expect, afterEach } from "bun:test";
import { RPCServer, RPCServerConfig, RPCServerDeps } from "./server.js";
import { REGTEST } from "../consensus/params.js";

let nextPort = 39700 + (process.pid % 200);
const ADDR = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";

let seen: number[] = [];
let server: RPCServer | undefined;

function start(estimate: number, fallbackFeeSatVb?: number): number {
  const port = nextPort++;
  seen = [];
  const wallet = {
    isPrivateKeysDisabled: () => false,
    isLocked: () => false,
    createTransaction: (_o: unknown, feeRate: number) => {
      seen.push(feeRate);
      throw new Error("Insufficient funds"); // stop after the fee decision
    },
  };
  const deps = {
    chainState: { getBestBlock: () => ({ height: 0, hash: Buffer.alloc(32), chainWork: 0n }) },
    mempool: {},
    peerManager: { getConnectedPeers: () => [] },
    feeEstimator: { estimateSmartFee: (b: number) => ({ feeRate: estimate, blocks: b }) },
    headerSync: {},
    db: {},
    params: REGTEST,
    wallet,
    fallbackFeeSatVb,
  } as unknown as RPCServerDeps;
  const config: RPCServerConfig = { port, host: "127.0.0.1", noAuth: true };
  server = new RPCServer(config, deps);
  server.start();
  return port;
}

async function rpc(port: number, method: string, params: unknown[]): Promise<any> {
  const r = await fetch(`http://127.0.0.1:${port}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  return r.json();
}

afterEach(() => server?.stop());

const SEND = (p: number, feeRate: unknown = null) =>
  rpc(p, "send", [[{ [ADDR]: 0.1 }], null, null, feeRate]);
const STA = (p: number, feeRate: unknown = null) =>
  rpc(p, "sendtoaddress", [ADDR, 0.1, "", "", false, true, null, null, false, feeRate]);

describe("wallet send fee resolution", () => {
  for (const [name, call] of [["sendtoaddress", STA], ["send", SEND]] as const) {
    it(`${name}: no estimate and no fallbackfee -> -6, never builds a tx`, async () => {
      const p = start(0);
      const res = await call(p);
      expect(res.error?.code).toBe(-6);
      expect(res.error?.message).toContain("Fallbackfee is disabled");
      expect(seen).toEqual([]);
    });

    it(`${name}: no estimate + fallbackfee 20 sat/vB -> uses 20`, async () => {
      const p = start(0, 20);
      await call(p);
      expect(seen).toEqual([20]);
    });

    it(`${name}: estimator data wins over fallbackfee`, async () => {
      const p = start(7, 20);
      await call(p);
      expect(seen).toEqual([7]);
    });

    it(`${name}: explicit fee_rate needs neither estimate nor fallbackfee`, async () => {
      const p = start(0);
      await call(p, 3);
      expect(seen).toEqual([3]);
    });
  }
});
