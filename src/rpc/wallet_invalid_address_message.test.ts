/**
 * An undecodable payment address is reported with Core's ParseOutputs text.
 *
 * Core (rpc/rawtransaction_util.cpp ParseOutputs, line 121) rejects an output
 * key that does not decode with
 *   JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Bitcoin address: " + name_)
 * where name_ is the address string as given. sendtoaddress (wallet/rpc/spend.cpp:328
 * ParseOutputs), send and walletcreatefundedpsbt (AddOutputs -> ParseOutputs)
 * all share it. hotbuns prefixed its own
 * decoder's message with "Invalid address: ", giving
 * "Invalid address: Invalid Bitcoin address: notanaddress" (core-regtest row
 * wallet/error/bad-address:message).
 */
import { describe, it, expect, afterEach } from "bun:test";
import { RPCServer, RPCServerDeps } from "./server.js";
import { startTestRpc } from "../test/rpc-listen.js";
import { REGTEST } from "../consensus/params.js";

let server: RPCServer | undefined;

function start(): number {
  const wallet = {
    isPrivateKeysDisabled: () => false,
    isLocked: () => false,
    createTransaction: () => {
      throw new Error("createTransaction must not be reached for a bad address");
    },
    selectCoinsAdvanced: () => {
      throw new Error("selectCoinsAdvanced must not be reached for a bad address");
    },
  };
  const deps = {
    chainState: { getBestBlock: () => ({ height: 0, hash: Buffer.alloc(32), chainWork: 0n }) },
    mempool: { getMinFee: () => 0, getMinRelayFeeRate: () => 0.1 },
    peerManager: { getConnectedPeers: () => [] },
    feeEstimator: { estimateSmartFee: (b: number) => ({ feeRate: 0, blocks: b }) },
    headerSync: {},
    db: {},
    params: REGTEST,
    wallet,
    fallbackFeeSatKvB: 1000,
  } as unknown as RPCServerDeps;
  const started = startTestRpc(deps);
  server = started.server;
  return started.port;
}

async function rpc(port: number, method: string, params: unknown[]): Promise<any> {
  const r = await fetch(`http://127.0.0.1:${port}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  return r.json();
}

afterEach(() => {
  server?.stop();
  server = undefined;
});

const BAD = "notanaddress";
const CORE_ERROR = { code: -5, message: `Invalid Bitcoin address: ${BAD}` };

describe("undecodable payment address uses Core's ParseOutputs message", () => {
  it("sendtoaddress", async () => {
    const port = start();
    const res = await rpc(port, "sendtoaddress", [BAD, 1]);
    expect(res.error).toEqual(CORE_ERROR);
  });

  it("send", async () => {
    const port = start();
    const res = await rpc(port, "send", [{ [BAD]: 1 }]);
    expect(res.error).toEqual(CORE_ERROR);
  });

  it("walletcreatefundedpsbt", async () => {
    const port = start();
    const res = await rpc(port, "walletcreatefundedpsbt", [[], { [BAD]: 1 }]);
    expect(res.error).toEqual(CORE_ERROR);
  });

  it("a bech32 string with a broken checksum", async () => {
    const port = start();
    // Looks like a regtest address but fails the checksum: Core still says
    // "Invalid Bitcoin address: <addr>" with nothing in front.
    const broken = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt081";
    const res = await rpc(port, "sendtoaddress", [broken, 1]);
    expect(res.error).toEqual({ code: -5, message: `Invalid Bitcoin address: ${broken}` });
  });
});
