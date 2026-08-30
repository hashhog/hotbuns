/**
 * Core's getInt<T> fails in the CONVERSION — so an out-of-int32 argument never
 * reaches the lookup, the domain test, or the handler's own error.
 *
 * THE DEFECT (pinned here)
 * ------------------------
 * #81 fixed the arguments hotbuns ACCEPTED out of range. This is the other
 * half: arguments hotbuns rejected, but with the WRONG error, because the
 * width check ran after — or instead of — the conversion. Measured against a
 * regtest Core oracle (tools/rpc-arg-differential.py): 29 findings, all four
 * hostile widths on each of
 *
 *   getblockhash 4294967296        -> -8  "Block height out of range"  (Core -1)
 *   getblock <h> 2147483648        -> -5  "Block not found"            (Core -1)
 *   getrawtransaction <t> -4294967297 -> -5 "No such ... transaction"  (Core -1)
 *   getchaintxstats 2147483648     -> -8  "Invalid block count"        (Core -1)
 *   createmultisig -2147483649 []  -> -32602                           (Core -1)
 *   gettxout <t> 4294967296        -> code "ERR_OUT_OF_RANGE"          (Core -1)
 *
 * The gettxout row is the worst of them: the unbounded vout reached Node's
 * Buffer.writeUInt32LE, whose RangeError escaped onto the wire with a STRING
 * `code`. JSON-RPC requires an integer there, so a client switching on
 * error.code got a type it cannot handle.
 *
 * WHAT CORE DOES
 * --------------
 * UniValue::getInt<T> runs std::from_chars INTO THE DESTINATION WIDTH, so:
 *   out of width / fractional -> RPC_MISC_ERROR (-1) "JSON integer out of range"
 *   converts, then violates the handler's domain -> that handler's own error.
 * Only surviving values reach the lookup. Note gettxout's `n` is
 * getInt<uint32_t>, so 2147483648 is a VALID vout while -1 is not.
 *
 * setban / disconnectnode: found by the differential's CONTROLS, not by
 * hostile integers (bitcoin-core/src/rpc/net.cpp):
 *   * an ABSOLUTE bantime in the past must be -8, not silently accepted;
 *   * re-banning must be -23 "Error: IP/Subnet already banned" — hotbuns had
 *     no already-banned check at all;
 *   * bantime <= 0 is NOT an error (0 means "use the default", a negative
 *     relative bantime records an already-expired ban) — hotbuns refused both
 *     with -32602;
 *   * a failed unban is -30 with Core's wording, not -1;
 *   * `nodeid` was never read. Every by-id disconnect — the form getpeerinfo's
 *     "id" field exists to feed — was refused with -32602.
 *
 * TEETH
 * -----
 * Rejecting everything would satisfy every rejection assertion, so each block
 * carries a CONTROL that must SUCCEED, and the by-nodeid control asserts the
 * RIGHT PEER was disconnected — which no amount of extra validation can fake.
 */

import { describe, it, expect, beforeEach, afterEach } from "bun:test";
import { RPCServer, RPCServerConfig, RPCServerDeps } from "../rpc/server.js";
import { REGTEST } from "../consensus/params.js";

const OUT_OF_INT32 = [2147483648, -2147483649, 4294967296, -4294967297];
const TXID = "a".repeat(64);
let portCounter = 31401;
const TIP_HEIGHT = 300;

class MockChainStateManager {
  getBestBlock() { return { hash: Buffer.alloc(32, 0), height: TIP_HEIGHT, chainWork: 1000n }; }
  getUTXOManager() { return { async getUTXOAsync() { return null; } }; }
}
class MockMempool {
  getInfo() { return { size: 0, bytes: 0, minFeeRate: 1 }; }
  getAllTxids() { return []; }
  getTransaction() { return null; }
  hasTransaction() { return false; }
  getSize() { return 0; }
}
class MockPeerManager {
  banned = new Set<string>();
  unbannedCalls: string[] = [];
  disconnected: string[] = [];
  peers = [
    { host: "10.0.0.1", port: 8333 },
    { host: "10.0.0.2", port: 8333 },
    { host: "10.0.0.3", port: 8333 },
  ];
  getConnectedPeers() { return this.peers; }
  broadcast() {}
  dumpAddrmanForRpc() { return []; }
  isBanned(a: string) { return this.banned.has(a); }
  banDurations: number[] = [];
  banAddress(a: string, d: number) { this.banned.add(a); this.banDurations.push(d); }
  unbanAddress(a: string) { this.unbannedCalls.push(a); return this.banned.delete(a); }
  disconnectPeer(k: string) { this.disconnected.push(k); }
}
class MockFeeEstimator {
  estimateSmartFee() { return { feeRate: 10, blocks: 6 }; }
  getBuckets() { return []; }
}
class MockHeaderSync {
  getBestHeader() { return { hash: Buffer.alloc(32, 0), height: TIP_HEIGHT, chainWork: 1000n }; }
  getHeaderByHeight() { return undefined; }
  getHeader() { return undefined; }
  getMedianTimePast() { return 0; }
}
class MockChainDB {
  async getBlock() { return null; }
  async getBlockIndex() { return null; }
  async getBlockHashByHeight() { return null; }
  async getChainWork(): Promise<bigint | null> { return null; }
  async getChainState() { return { bestBlockHash: Buffer.alloc(32, 0), bestHeight: TIP_HEIGHT }; }
  async getUTXO() { return null; }
}

describe("RPC conversion runs before the lookup (Core getInt<T> ordering) — REGRESSION", () => {
  let server: RPCServer;
  let port: number;
  let peerManager: MockPeerManager;

  beforeEach(() => {
    port = portCounter++;
    peerManager = new MockPeerManager();
    const config: RPCServerConfig = { port, host: "127.0.0.1", noAuth: true };
    const deps: RPCServerDeps = {
      chainState: new MockChainStateManager() as any,
      mempool: new MockMempool() as any,
      peerManager: peerManager as any,
      feeEstimator: new MockFeeEstimator() as any,
      headerSync: new MockHeaderSync() as any,
      db: new MockChainDB() as any,
      params: REGTEST,
    };
    server = new RPCServer(config, deps);
    server.start();
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
    expect(resp.error).toBeDefined();
    // JSON-RPC requires an INTEGER code. The gettxout leak put the string
    // "ERR_OUT_OF_RANGE" here, so this assertion is load-bearing.
    expect(typeof resp.error.code).toBe("number");
    expect(resp.error.code).toBe(code);
    if (message !== undefined) expect(resp.error.message).toBe(message);
  }
  const expectOutOfRange = (resp: any) => expectError(resp, -1, "JSON integer out of range");

  describe("the conversion beats the later error", () => {
    it("getblockhash: -1 from the conversion, not -8 from the height test", async () => {
      for (const v of OUT_OF_INT32) expectOutOfRange(await call("getblockhash", [v]));
    });
    it("getblock verbosity: -1, not -5 from the block lookup", async () => {
      for (const v of OUT_OF_INT32) expectOutOfRange(await call("getblock", ["0".repeat(64), v]));
    });
    it("getrawtransaction verbosity: -1, not -5 from the tx lookup", async () => {
      for (const v of OUT_OF_INT32) expectOutOfRange(await call("getrawtransaction", [TXID, v]));
    });
    it("getchaintxstats nblocks: -1, not -8 from the count test", async () => {
      for (const v of OUT_OF_INT32) expectOutOfRange(await call("getchaintxstats", [v]));
    });
    it("createmultisig nrequired: -1, even though pubkeys is also empty", async () => {
      for (const v of OUT_OF_INT32) expectOutOfRange(await call("createmultisig", [v, []]));
    });
    it("gettxout n: -1 with an INTEGER code, not a string ERR_OUT_OF_RANGE", async () => {
      for (const v of [4294967296, -1, -2147483649]) {
        expectOutOfRange(await call("gettxout", [TXID, v]));
      }
    });
    it("CONTROL: an in-range height still reaches the handler's own -8", async () => {
      expectError(await call("getblockhash", [-1]), -8, "Block height out of range");
    });
    it("CONTROL: n = 2147483648 is a VALID vout (uint32), so it reaches the lookup", async () => {
      const resp = await call("gettxout", [TXID, 2147483648]);
      expect(resp.error ?? null).toBeNull();
      expect(resp.result ?? null).toBeNull(); // no such UTXO, but not an error
    });
  });

  describe("setban parity", () => {
    it("an ABSOLUTE bantime in the past is refused, not accepted", async () => {
      expectError(await call("setban", ["1.2.3.4", "add", 1, true]),
        -8, "Error: Absolute timestamp is in the past");
      expect(peerManager.banned.size).toBe(0);
    });
    it("re-banning is -23, and the check runs before bantime is read", async () => {
      expect((await call("setban", ["1.2.3.4", "add"])).error ?? null).toBeNull();
      expectError(await call("setban", ["1.2.3.4", "add"]), -23, "Error: IP/Subnet already banned");
      // bantime is not even looked at on the already-banned path
      expectError(await call("setban", ["1.2.3.4", "add", 1, true]), -23,
        "Error: IP/Subnet already banned");
    });
    it("bantime 0 and negative relative bantimes are ACCEPTED, as Core accepts them", async () => {
      expect((await call("setban", ["1.2.3.4", "add", 0])).error ?? null).toBeNull();
      expect((await call("setban", ["5.6.7.8", "add", -4294967297])).error ?? null).toBeNull();
      expect((await call("setban", ["9.10.11.12", "add", -1])).error ?? null).toBeNull();
      expect(peerManager.banned.size).toBe(3);
    });
    it("a failed unban is -30 with Core's wording, not -1", async () => {
      expectError(await call("setban", ["1.2.3.4", "remove"]), -30,
        "Error: Unban failed. Requested address/subnet was not previously manually banned.");
    });
    it("CONTROL: an absolute bantime in the FUTURE is accepted", async () => {
      const future = Math.floor(Date.now() / 1000) + 3600;
      expect((await call("setban", ["1.2.3.4", "add", future, true])).error ?? null).toBeNull();
      expect(peerManager.banned.has("1.2.3.4")).toBe(true);
      // Teeth: an absolute timestamp must become a ~1h DURATION, not a 56-year
      // one. banAddress takes seconds-from-now; passing the raw epoch through
      // is the same bug class as ignoring the argument.
      expect(peerManager.banDurations[0]).toBeGreaterThan(3500);
      expect(peerManager.banDurations[0]).toBeLessThanOrEqual(3600);
    });
  });

  describe("disconnectnode honours nodeid", () => {
    it("disconnects THE PEER AT THAT ID — not -32602", async () => {
      const resp = await call("disconnectnode", ["", 1]);
      expect(resp.error ?? null).toBeNull();
      // Teeth: the id must select peer 1, the same mapping getpeerinfo reports.
      expect(peerManager.disconnected).toEqual(["10.0.0.2:8333"]);
    });
    it("an unconnected nodeid is -29, the same as an unconnected address", async () => {
      expectError(await call("disconnectnode", ["", 99]), -29, "Node not found in connected nodes");
      expectError(await call("disconnectnode", ["", -1]), -29, "Node not found in connected nodes");
      expect(peerManager.disconnected).toEqual([]);
    });
    it("supplying BOTH address and nodeid is -32602", async () => {
      expectError(await call("disconnectnode", ["10.0.0.1:8333", 0]), -32602,
        "Only one of address and nodeid should be provided.");
      expect(peerManager.disconnected).toEqual([]);
    });
    it("CONTROL: by-address still works", async () => {
      const resp = await call("disconnectnode", ["10.0.0.3:8333"]);
      expect(resp.error ?? null).toBeNull();
      expect(peerManager.disconnected).toEqual(["10.0.0.3:8333"]);
    });
  });
});
