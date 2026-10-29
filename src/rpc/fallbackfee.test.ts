/**
 * Core-style -fallbackfee for wallet sends (hotbuns-fallbackfee).
 *
 * Core (wallet/fees.cpp GetMinimumFeeRate): explicit fee_rate wins; else the
 * fee estimator; if it has no data, -fallbackfee; if that is 0 (the default),
 * the send fails with "Fee estimation failed. Fallbackfee is disabled...".
 * The code depends on the caller: sendtoaddress goes through SendMoney (-6,
 * RPC_WALLET_INSUFFICIENT_FUNDS); send, fundrawtransaction and
 * walletcreatefundedpsbt go through FundTransaction (-4, RPC_WALLET_ERROR).
 * A non-zero estimate/fallback is raised to the mempool minimum fee and then to
 * the required fee max(-mintxfee, -minrelaytxfee); a zero fallback is not.
 * hotbuns used to hardcode 1 sat/vB (send/sendtoaddress/fundrawtransaction/
 * walletcreatefundedpsbt) and 20 sat/vB (the estimator's "no data" value).
 */
import { describe, it, expect, afterEach } from "bun:test";
import { RPCServer, RPCServerConfig, RPCServerDeps } from "./server.js";
import { REGTEST } from "../consensus/params.js";

let nextPort = 39700 + (process.pid % 200);
const ADDR = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";
// createrawtransaction [] [{ADDR: 0.1}]: v2, no inputs, one P2WPKH output.
const RAW_NO_INPUTS =
  "02000000" + "00" + "01" + "8096980000000000" +
  "160014751e76e8199196d454941c45d1b3a323f1433bd6" + "00000000";

let seen: number[] = [];
let server: RPCServer | undefined;

interface Env {
  estimate: number; // sat/vB from the estimator; 0 = no data
  fallbackKvB?: number; // -fallbackfee in sat/kvB
  mempoolMinKvB?: number; // mempool GetMinFee(), sat/kvB
  relayMinSatVb?: number; // -minrelaytxfee, sat/vB
}

function start(env: Env): number {
  seen = [];
  const record = (feeRate: number) => {
    seen.push(feeRate);
    throw new Error("Insufficient funds"); // stop after the fee decision
  };
  const wallet = {
    isPrivateKeysDisabled: () => false,
    isLocked: () => false,
    createTransaction: (_o: unknown, feeRate: number) => record(feeRate),
    selectCoinsAdvanced: (_t: bigint, feeRate: number) => record(feeRate),
  };
  const deps = {
    chainState: { getBestBlock: () => ({ height: 0, hash: Buffer.alloc(32), chainWork: 0n }) },
    mempool: {
      getMinFee: () => env.mempoolMinKvB ?? 0,
      getMinRelayFeeRate: () => env.relayMinSatVb ?? 0.1,
    },
    peerManager: { getConnectedPeers: () => [] },
    feeEstimator: { estimateSmartFee: (b: number) => ({ feeRate: env.estimate, blocks: b }) },
    headerSync: {},
    db: {},
    params: REGTEST,
    wallet,
    fallbackFeeSatKvB: env.fallbackKvB,
  } as unknown as RPCServerDeps;
  // Skip ports another process already holds.
  for (let tries = 0; ; tries++) {
    const port = nextPort++;
    const config: RPCServerConfig = { port, host: "127.0.0.1", noAuth: true };
    server = new RPCServer(config, deps);
    try {
      server.start();
      return port;
    } catch (e) {
      if (tries >= 50) throw e;
    }
  }
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

type Call = (p: number, feeRate?: number) => Promise<any>;
const SEND: Call = (p, feeRate) => rpc(p, "send", [[{ [ADDR]: 0.1 }], null, null, feeRate ?? null]);
const STA: Call = (p, feeRate) =>
  rpc(p, "sendtoaddress", [ADDR, 0.1, "", "", false, true, null, null, false, feeRate ?? null]);
const FUND: Call = (p, feeRate) =>
  rpc(p, "fundrawtransaction", [RAW_NO_INPUTS, feeRate === undefined ? {} : { fee_rate: feeRate }]);
const PSBT: Call = (p, feeRate) =>
  rpc(p, "walletcreatefundedpsbt", [
    [],
    [{ [ADDR]: 0.1 }],
    0,
    feeRate === undefined ? {} : { fee_rate: feeRate },
  ]);

// [name, call, Core error code when estimation fails and fallbackfee is 0]
const CALLERS: Array<[string, Call, number]> = [
  ["sendtoaddress", STA, -6], // SendMoney -> RPC_WALLET_INSUFFICIENT_FUNDS
  ["send", SEND, -4], // FundTransaction -> RPC_WALLET_ERROR
  ["fundrawtransaction", FUND, -4],
  ["walletcreatefundedpsbt", PSBT, -4],
];

describe("wallet send fee resolution", () => {
  for (const [name, call, failCode] of CALLERS) {
    it(`${name}: no estimate and no fallbackfee -> ${failCode}, never builds a tx`, async () => {
      const p = start({ estimate: 0 });
      const res = await call(p);
      expect(res.error?.code).toBe(failCode);
      expect(res.error?.message).toBe(
        "Fee estimation failed. Fallbackfee is disabled. Wait a few blocks or enable -fallbackfee."
      );
      expect(seen).toEqual([]);
    });

    it(`${name}: zero fallback is not replaced by the required fee`, async () => {
      const p = start({ estimate: 0, fallbackKvB: 0, mempoolMinKvB: 5000, relayMinSatVb: 2 });
      const res = await call(p);
      expect(res.error?.code).toBe(failCode);
      expect(seen).toEqual([]);
    });

    it(`${name}: no estimate + fallbackfee 20 sat/vB -> uses 20`, async () => {
      const p = start({ estimate: 0, fallbackKvB: 20_000 });
      await call(p);
      expect(seen).toEqual([20]);
    });

    it(`${name}: estimator data wins over fallbackfee`, async () => {
      const p = start({ estimate: 7, fallbackKvB: 20_000 });
      await call(p);
      expect(seen).toEqual([7]);
    });

    it(`${name}: fallback below -mintxfee (1000 sat/kvB) is raised to it`, async () => {
      const p = start({ estimate: 0, fallbackKvB: 500 });
      await call(p);
      expect(seen).toEqual([1]);
    });

    it(`${name}: estimate below the mempool minimum is raised to it`, async () => {
      const p = start({ estimate: 2, mempoolMinKvB: 3456 });
      await call(p);
      expect(seen).toEqual([3.456]);
    });

    it(`${name}: required fee is max(-mintxfee, relay minimum)`, async () => {
      const p = start({ estimate: 2, mempoolMinKvB: 3000, relayMinSatVb: 4 });
      await call(p);
      expect(seen).toEqual([4]);
    });

    it(`${name}: explicit fee_rate needs neither estimate nor fallbackfee`, async () => {
      const p = start({ estimate: 0 });
      await call(p, 3);
      expect(seen).toEqual([3]);
    });

    it(`${name}: explicit fee_rate is not raised to the mempool minimum`, async () => {
      const p = start({ estimate: 0, mempoolMinKvB: 5000 });
      await call(p, 3);
      expect(seen).toEqual([3]);
    });
  }
});
