/**
 * RPC integer arguments must be read at Core's width — and honoured.
 *
 * THE DEFECT (pinned here)
 * ------------------------
 * Measured against a regtest Bitcoin Core oracle
 * (tools/rpc-arg-differential.py), hotbuns ACCEPTED 16 out-of-int32 arguments
 * that Core refuses:
 *
 *   estimatesmartfee 2147483648   -> CLAMPED to 1008, answered as success
 *   getnetworkhashps 4294967296   -> ignored, answered for a 120-block window
 *   getnetworkhashps [1, <any>]   -> the HEIGHT argument was never read at all
 *   getnodeaddresses 2147483648   -> truncated
 *   waitforblockheight -2147483649-> waited on a wrapped height
 *
 * WHAT CORE DOES
 * --------------
 * Every numeric argument goes through `UniValue::getInt<T>()`
 * (src/univalue/include/univalue.h), which runs `std::from_chars` INTO THE
 * DESTINATION WIDTH. The width check therefore lives inside the conversion and
 * fires BEFORE the handler's own domain test:
 *
 *   out of width, or fractional  -> std::runtime_error("JSON integer out of
 *                                   range") -> RPC_MISC_ERROR (-1)
 *   converts, violates the range -> RPC_INVALID_PARAMETER (-8)
 *
 * That ordering is why an out-of-int32 `count` for getnodeaddresses is -1
 * while an in-range -1 is -8 "Address count out of range".
 *
 * Two of these were not merely unbounded but FABRICATIONS — an argument read
 * and then not honoured:
 *
 *   * estimatesmartfee/estimaterawfee CLAMPED conf_target into [1,1008], so a
 *     request for a 99999-block estimate came back as a 1008-block one,
 *     reported as success. Core's ParseConfirmTarget (rpc/util.cpp) rejects.
 *   * getnetworkhashps ignored `height` entirely and always measured at the
 *     tip, and had no handling for nblocks 0 / < -1 / -1. Core's
 *     GetNetworkHashPS (rpc/mining.cpp) rejects the first two and reads -1 as
 *     "since the last difficulty change".
 *
 * TEETH
 * -----
 * A handler that rejected everything would satisfy every rejection assertion,
 * so each block carries a CONTROL that must SUCCEED — and the getnetworkhashps
 * control asserts the height argument CHANGES THE ANSWER, which no amount of
 * extra validation can fake.
 *
 * References:
 *   bitcoin-core/src/univalue/include/univalue.h    getInt<Int>
 *   bitcoin-core/src/rpc/server.cpp                 std::exception -> -1
 *   bitcoin-core/src/rpc/util.cpp                   ParseConfirmTarget
 *   bitcoin-core/src/rpc/mining.cpp                 GetNetworkHashPS
 *   bitcoin-core/src/rpc/net.cpp                    getnodeaddresses count
 *   bitcoin-core/src/common/messages.cpp            FeeModeFromString
 */

import { describe, it, expect, beforeEach, afterEach } from "bun:test";
import { RPCServer, RPCServerConfig, RPCServerDeps } from "../rpc/server.js";
import { REGTEST } from "../consensus/params.js";

const OUT_OF_INT32 = [2147483648, -2147483649, 4294967296, -4294967297];

let portCounter = 29881;

const TIP_HEIGHT = 300;

/**
 * Deterministic per-height header.  Work is linear in height but TIME is NOT
 * (blocks come 4x slower above height 150), so the hashrate over a fixed
 * window genuinely depends on WHERE the window sits.  That is what lets the
 * control below distinguish "height honoured" from "height ignored" -- with a
 * linear clock both answers would be the same number and the control would
 * pass on the broken code too.
 */
function headerAt(height: number) {
  return {
    hash: Buffer.alloc(32, height & 0xff),
    height,
    chainWork: BigInt(height) * 1_000_000n,
    header: { timestamp: height <= 150 ? height * 10 : 1500 + (height - 150) * 40 },
  };
}

class MockChainStateManager {
  getBestBlock() {
    return { hash: Buffer.alloc(32, 0), height: TIP_HEIGHT, chainWork: 1000n };
  }
  getUTXOManager() {
    return { async getUTXOAsync() { return null; } };
  }
}
class MockMempool {
  getInfo() { return { size: 0, bytes: 0, minFeeRate: 1 }; }
  getAllTxids() { return []; }
  getTransaction() { return null; }
  hasTransaction() { return false; }
  getSize() { return 0; }
}
class MockPeerManager {
  getConnectedPeers() { return []; }
  broadcast() {}
  // The handler's real data source; named exactly so the in-range CONTROL
  // exercises the success path instead of dying in the mock.
  dumpAddrmanForRpc() { return []; }
}
class MockFeeEstimator {
  estimateSmartFee() { return { feeRate: 10, blocks: 6 }; }
  getBuckets() { return []; }
}
class MockHeaderSync {
  getBestHeader() {
    return { hash: Buffer.alloc(32, 0), height: TIP_HEIGHT, chainWork: 1000n };
  }
  getHeaderByHeight(h: number) {
    return h >= 0 && h <= TIP_HEIGHT ? headerAt(h) : undefined;
  }
  getHeader() { return undefined; }
  getMedianTimePast() { return 0; }
}
class MockChainDB {
  async getBlock() { return null; }
  async getBlockIndex() { return null; }
  async getBlockHashByHeight() { return null; }
  async getChainWork(): Promise<bigint | null> { return null; }
  async getChainState() {
    return { bestBlockHash: Buffer.alloc(32, 0), bestHeight: TIP_HEIGHT };
  }
  async getUTXO() { return null; }
}

function makeServer(): { server: RPCServer; port: number } {
  const port = portCounter++;
  const config: RPCServerConfig = { port, host: "127.0.0.1", noAuth: true };
  const deps: RPCServerDeps = {
    chainState: new MockChainStateManager() as any,
    mempool: new MockMempool() as any,
    peerManager: new MockPeerManager() as any,
    feeEstimator: new MockFeeEstimator() as any,
    headerSync: new MockHeaderSync() as any,
    db: new MockChainDB() as any,
    params: REGTEST,
  };
  const server = new RPCServer(config, deps);
  server.start();
  return { server, port };
}

describe("RPC integer-argument bounds (Core getInt<T> parity) — REGRESSION", () => {
  let server: RPCServer;
  let port: number;

  beforeEach(() => {
    const out = makeServer();
    server = out.server;
    port = out.port;
  });
  afterEach(() => { server.stop(); });

  async function call(method: string, params: any[]): Promise<any> {
    const r = await fetch(`http://127.0.0.1:${port}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
    });
    return r.json();
  }

  function expectError(resp: any, code: number, message?: string): void {
    expect(resp.result ?? null).toBeNull();
    expect(resp.error).toBeDefined();
    expect(typeof resp.error.code).toBe("number");
    expect(resp.error.code).toBe(code);
    if (message !== undefined) expect(resp.error.message).toBe(message);
  }

  const expectOutOfRange = (resp: any) =>
    expectError(resp, -1, "JSON integer out of range");

  describe("wait family (getInt<int>)", () => {
    it("rejects an out-of-int32 timeout on waitfornewblock", async () => {
      for (const v of OUT_OF_INT32) expectOutOfRange(await call("waitfornewblock", [v]));
    });

    it("rejects an out-of-int32 height on waitforblockheight", async () => {
      for (const v of OUT_OF_INT32) expectOutOfRange(await call("waitforblockheight", [v]));
    });

    it("rejects an out-of-int32 timeout on waitforblockheight", async () => {
      for (const v of OUT_OF_INT32) expectOutOfRange(await call("waitforblockheight", [1, v]));
    });

    it("CONTROL: an in-range negative timeout still gets Core's own message", async () => {
      expectError(await call("waitfornewblock", [-1]), -1, "Negative timeout");
    });
  });

  describe("getnodeaddresses count (getInt<int>, then -8)", () => {
    it("rejects an out-of-int32 count with the CONVERSION error", async () => {
      for (const v of OUT_OF_INT32) expectOutOfRange(await call("getnodeaddresses", [v]));
    });

    it("CONTROL: an in-range negative count keeps the -8 domain error", async () => {
      expectError(await call("getnodeaddresses", [-1]), -8, "Address count out of range");
    });

    it("CONTROL: an in-range count succeeds", async () => {
      const r = await call("getnodeaddresses", [1]);
      expect(r.error ?? null).toBeNull();
      expect(Array.isArray(r.result)).toBe(true);
    });
  });

  describe("estimatesmartfee / estimaterawfee conf_target", () => {
    it("rejects an out-of-int32 conf_target before the domain test", async () => {
      for (const m of ["estimatesmartfee", "estimaterawfee"]) {
        for (const v of OUT_OF_INT32) expectOutOfRange(await call(m, [v]));
      }
    });

    it("rejects an in-range conf_target above the highest tracked target", async () => {
      for (const m of ["estimatesmartfee", "estimaterawfee"]) {
        expectError(await call(m, [99999]), -8,
          "Invalid conf_target, must be between 1 and 1008");
      }
    });

    it("rejects conf_target below 1 instead of clamping up to 1", async () => {
      for (const m of ["estimatesmartfee", "estimaterawfee"]) {
        expectError(await call(m, [0]), -8,
          "Invalid conf_target, must be between 1 and 1008");
      }
    });

    it("rejects an unknown estimate_mode instead of ignoring it", async () => {
      for (const mode of ["", "garbage", "ECONOMICALLY"]) {
        expectError(await call("estimatesmartfee", [6, mode]), -8,
          'Invalid estimate_mode parameter, must be one of: "unset", "economical", "conservative"');
      }
    });

    it("CONTROL: a valid conf_target and every fee mode succeed", async () => {
      const plain = await call("estimatesmartfee", [6]);
      expect(plain.error ?? null).toBeNull();
      for (const mode of ["unset", "economical", "CONSERVATIVE", "Economical"]) {
        const r = await call("estimatesmartfee", [6, mode]);
        expect(r.error ?? null).toBeNull();
      }
    });
  });

  /**
   * Core builds createrawtransaction, createpsbt AND walletcreatefundedpsbt
   * from ONE routine (ConstructTransaction), so all three bound locktime to
   * [0, LOCKTIME_MAX].  Here only createrawtransaction did: createpsbt took
   * the value as-is and walletcreatefundedpsbt wrapped it with `>>> 0`, so
   * locktime 4294967296 silently became 0 and the reply reported success.
   */
  describe("locktime is the same argument in all three constructors", () => {
    const IN = [{ txid: "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b", vout: 0 }];
    const OUT = { data: "deadbeef" };

    it("rejects an out-of-LOCKTIME_MAX locktime on createrawtransaction and createpsbt", async () => {
      for (const m of ["createrawtransaction", "createpsbt"]) {
        for (const v of [4294967296, 8589934592]) {
          expectError(await call(m, [IN, OUT, v]), -8,
            "Invalid parameter, locktime out of range");
        }
        expectError(await call(m, [IN, OUT, -1]), -8,
          "Invalid parameter, locktime out of range");
        // Out of int64 fails the CONVERSION first, like every other argument.
        expectOutOfRange(await call(m, [IN, OUT, 1e300]));
      }
    });

    it("CONTROL: LOCKTIME_MAX itself is accepted by both", async () => {
      for (const m of ["createrawtransaction", "createpsbt"]) {
        const r = await call(m, [IN, OUT, 4294967295]);
        expect(r.error ?? null).toBeNull();
        expect(typeof r.result).toBe("string");
      }
    });
  });

  describe("getnetworkhashps (Arg<int> nblocks/height)", () => {
    it("rejects out-of-int32 nblocks and height", async () => {
      for (const v of OUT_OF_INT32) {
        expectOutOfRange(await call("getnetworkhashps", [v]));
        expectOutOfRange(await call("getnetworkhashps", [1, v]));
      }
    });

    it("rejects nblocks == 0 and nblocks < -1 instead of substituting 120", async () => {
      for (const v of [0, -2, -1000]) {
        expectError(await call("getnetworkhashps", [v]), -8,
          "Invalid nblocks. Must be a positive number or -1.");
      }
    });

    it("rejects a height above the tip instead of measuring at the tip", async () => {
      for (const v of [TIP_HEIGHT + 1, 99999999]) {
        expectError(await call("getnetworkhashps", [120, v]), -8,
          "Block does not exist at specified height");
      }
    });

    it("CONTROL: height is HONOURED — a lower height gives a different answer", async () => {
      const atTip = await call("getnetworkhashps", [10]);
      const atHeight = await call("getnetworkhashps", [10, 100]);
      expect(atTip.error ?? null).toBeNull();
      expect(atHeight.error ?? null).toBeNull();
      // Same window, different anchor: the mock's work/time grow at different
      // rates per height, so an ignored `height` shows up as an identical
      // number. This is the assertion the pre-fix code cannot pass.
      expect(typeof atHeight.result).toBe("number");
      expect(atHeight.result).not.toBe(atTip.result);
    });

    it("CONTROL: nblocks == -1 (since last difficulty change) is accepted", async () => {
      const r = await call("getnetworkhashps", [-1]);
      expect(r.error ?? null).toBeNull();
      expect(typeof r.result).toBe("number");
    });
  });
});
