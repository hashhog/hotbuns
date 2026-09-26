/**
 * R5 DATA-INTEGRITY class (QUEUES.md hotbuns item 0, measured 2026-09-25).
 *
 * Wrong ANSWERS — each expectation is Bitcoin Core's, from the source cited:
 *   getdeploymentinfo(<known hash>)  -5 for a block getblockheader serves: the
 *       display-order hex was looked up without byte reversal
 *       (rpc/blockchain.cpp getdeploymentinfo: ParseHashV + LookupBlockIndex).
 *   getchaintxstats   hung >300 s (O(height) walk from genesis) and counted an
 *       unreadable block as 0 txs; Core knows m_chain_tx_count only back to an
 *       anchor (genesis / assumeutxo base) and omits txcount otherwise
 *       (chain.h:129, node/blockstorage.cpp:440-487, rpc/blockchain.cpp:1878).
 *   testmempoolaccept  'deadbeef' answered a result array (Core -22), results
 *       lacked wtxid, missing inputs were not "missing-inputs", and an allowed
 *       tx reported fees.base 0 (rpc/mempool.cpp testmempoolaccept).
 *   decodescript 'zz'  answered as the empty script (Core ParseHexV -> -8).
 *   combinerawtransaction  merged a tx spending a coin that does not exist
 *       (Core -25 "Input not found or already spent").
 *   deriveaddresses   accepted no checksum (Core -5) and a range on an
 *       un-ranged descriptor (Core -8) (rpc/output_script.cpp:315-326).
 *   createpsbt        default nSequence 0xfffffffe; Core AddInputs uses
 *       rbf.value_or(true) -> 0xfffffffd (rawtransaction_util.cpp:49-55).
 *
 * TEETH: every rejection block carries a CONTROL that must SUCCEED.
 */

import { describe, it, expect, beforeEach, afterEach } from "bun:test";
import { RPCServer, RPCServerConfig, RPCServerDeps } from "../rpc/server.js";
import { REGTEST } from "../consensus/params.js";

let portCounter = 31701;

// ── a synthetic active chain 0..TIP, one coinbase per block ──────────────────
const TIP = 20;
function hashAt(h: number): Buffer {
  const b = Buffer.alloc(32, 0);
  b.writeUInt32LE(h + 1, 0);
  b[31] = 0x42;
  return b; // INTERNAL byte order
}
function display(buf: Buffer): string {
  return Buffer.from(buf).reverse().toString("hex");
}
function headerAt(h: number): Buffer {
  const hdr = Buffer.alloc(80, 0);
  hdr.writeUInt32LE(1_700_000_000 + h * 600, 68);
  return hdr;
}

class ChainDB {
  /** heights with NO height-index row (snapshot hole) */
  missing = new Set<number>();
  /** heights whose index nTx is 0 and whose body is absent (unknown nTx) */
  unknownNTx = new Set<number>();
  hashLookups = 0;
  async getBlockHashByHeight(h: number) {
    this.hashLookups++;
    if (h < 0 || h > TIP || this.missing.has(h)) return null;
    return hashAt(h);
  }
  async getBlockIndex(hash: Buffer) {
    for (let h = 0; h <= TIP; h++) {
      if (hashAt(h).equals(hash)) {
        return { height: h, nTx: this.unknownNTx.has(h) ? 0 : 1, header: headerAt(h) };
      }
    }
    return null;
  }
  async getBlock() { return null; }
  async updateBlockIndexNTx() {}
  async getChainWork(): Promise<bigint | null> { return null; }
  async getChainState() { return { bestBlockHash: hashAt(TIP), bestHeight: TIP }; }
  async getUTXO() { return null; }
}

class ChainState {
  coins = new Map<string, any>();
  getBestBlock() { return { hash: hashAt(TIP), height: TIP, chainWork: 1000n }; }
  getUTXOManager() {
    const coins = this.coins;
    return {
      async getUTXOAsync(op: { txid: Buffer; vout: number }) {
        return coins.get(`${op.txid.toString("hex")}:${op.vout}`) ?? null;
      },
    };
  }
}

class Mempool {
  nextResult: any = { accepted: false, error: "bad-txns-inputs-missingorspent: 01:0" };
  getInfo() { return { size: 0, bytes: 0, minFeeRate: 1 }; }
  getAllTxids() { return []; }
  getTransaction() { return null; }
  hasTransaction() { return false; }
  async isTransactionConfirmed() { return false; }
  async addTransaction() { return this.nextResult; }
  getSize() { return 0; }
}

// 1-in/1-out spend of prevout 01000…00:0 to P2WPKH 751e…3bd6 (the r5 probe).
const MISSING_INPUT_TX =
  "020000000101000000000000000000000000000000000000000000000000000000000000000000000000fdffffff01a086010000000000160014751e76e8199196d454941c45d1b3a323f1433bd600000000";
const MISSING_INPUT_TXID = "5df91f99045afe09848faea0ccad4f30937be5775bf19044c4ba1fbedca54a62";
const AAAA_TX =
  "0200000001aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0000000000fdffffff01a086010000000000160014751e76e8199196d454941c45d1b3a323f1433bd600000000";

describe("R5 data-integrity (hotbuns) — REGRESSION", () => {
  let server: RPCServer;
  let port: number;
  let db: ChainDB;
  let chainState: ChainState;
  let mempool: Mempool;

  function start(params: any = REGTEST) {
    port = portCounter++;
    const config: RPCServerConfig = { port, host: "127.0.0.1", noAuth: true };
    const deps: RPCServerDeps = {
      chainState: chainState as any,
      mempool: mempool as any,
      peerManager: { getConnectedPeers: () => [], broadcast() {} } as any,
      feeEstimator: { estimateSmartFee: () => ({ feeRate: 10, blocks: 6 }), getBuckets: () => [] } as any,
      headerSync: {
        getBestHeader: () => ({ hash: hashAt(TIP), height: TIP, chainWork: 1000n }),
        getHeaderByHeight: () => undefined,
        getHeader: () => undefined,
        getMedianTimePast: () => 0,
      } as any,
      db: db as any,
      params,
    };
    server = new RPCServer(config, deps);
    server.start();
  }

  beforeEach(() => {
    db = new ChainDB();
    chainState = new ChainState();
    mempool = new Mempool();
  });
  afterEach(() => { server?.stop(); });

  async function call(method: string, params: any[]): Promise<any> {
    const r = await fetch(`http://127.0.0.1:${port}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
    });
    return r.json();
  }
  function expectError(resp: any, code: number): void {
    expect(resp.error).toBeDefined();
    expect(resp.error.code).toBe(code);
  }

  describe("getdeploymentinfo", () => {
    it("resolves a known block by its DISPLAY-order hash", async () => {
      start();
      const resp = await call("getdeploymentinfo", [display(hashAt(5))]);
      expect(resp.error ?? null).toBeNull();
      expect(resp.result.height).toBe(5);
      expect(resp.result.hash).toBe(display(hashAt(5)));
    });
    it("CONTROL: an unknown hash is still -5", async () => {
      start();
      expectError(await call("getdeploymentinfo", ["00".repeat(31) + "01"]), -5);
    });
  });

  describe("getchaintxstats", () => {
    it("seeds from a chainparams assumeutxo base instead of walking to genesis", async () => {
      for (let h = 1; h < 10; h++) db.missing.add(h); // snapshot hole below base 10
      const au = new Map(REGTEST.assumeutxo ?? []);
      au.set(hashAt(10).toString("hex"), {
        height: 10, nChainTx: 1_000n, blockHash: hashAt(10), hashSerialized: Buffer.alloc(32),
      } as any);
      start({ ...REGTEST, assumeutxo: au });
      const resp = await call("getchaintxstats", [5]);
      expect(resp.error ?? null).toBeNull();
      expect(resp.result.txcount).toBe(1_010); // 1,000 through block 10 + 11..20
      expect(resp.result.window_tx_count).toBe(5);
    });
    it("a snapshot hole with no anchor is UNKNOWN: txcount omitted, no error", async () => {
      for (let h = 1; h < 10; h++) db.missing.add(h);
      start();
      const resp = await call("getchaintxstats", [5]);
      expect(resp.error ?? null).toBeNull();
      expect(resp.result.txcount).toBeUndefined();
      expect(resp.result.window_tx_count).toBeUndefined();
      expect(resp.result.window_final_block_height).toBe(TIP);
    });
    it("an unreadable block is unknown, never counted as zero transactions", async () => {
      db.unknownNTx.add(15);
      start();
      const resp = await call("getchaintxstats", [2]);
      expect(resp.error ?? null).toBeNull();
      expect(resp.result.txcount).toBeUndefined();
    });
    it("CONTROL: a complete chain from genesis counts every block", async () => {
      start();
      const resp = await call("getchaintxstats", [5]);
      expect(resp.result.txcount).toBe(TIP + 1);
      expect(resp.result.window_tx_count).toBe(5);
    });
    it("a repeat call reuses the cached count (no second walk to genesis)", async () => {
      start();
      await call("getchaintxstats", [0]);
      const before = db.hashLookups;
      await call("getchaintxstats", [0]);
      expect(db.hashLookups - before).toBeLessThan(5);
    });
  });

  describe("testmempoolaccept", () => {
    it("undecodable hex is RPC_DESERIALIZATION_ERROR -22 for the whole call", async () => {
      start();
      expectError(await call("testmempoolaccept", [["deadbeef"]]), -22);
      expectError(await call("testmempoolaccept", [[MISSING_INPUT_TX + "zz"]]), -22);
    });
    it("missing inputs: txid + wtxid + reject-reason 'missing-inputs' (Core shape)", async () => {
      start();
      const resp = await call("testmempoolaccept", [[MISSING_INPUT_TX]]);
      expect(resp.result).toEqual([
        { txid: MISSING_INPUT_TXID, wtxid: MISSING_INPUT_TXID, allowed: false, "reject-reason": "missing-inputs" },
      ]);
    });
    it("an allowed tx reports its REAL base fee, feerate and vsize", async () => {
      mempool.nextResult = { accepted: true, fee: 1_000n, vsize: 110 };
      start();
      const resp = await call("testmempoolaccept", [[MISSING_INPUT_TX]]);
      const r = resp.result[0];
      expect(r.allowed).toBe(true);
      expect(r.wtxid).toBe(MISSING_INPUT_TXID);
      expect(r.vsize).toBe(110);
      expect(r.fees.base).toBeCloseTo(0.00001, 10);
      expect(r.fees["effective-feerate"]).toBeCloseTo(0.0000909, 10); // floor(1000*1000/110) sat/kvB
      expect(r.fees["effective-includes"]).toEqual([MISSING_INPUT_TXID]);
    });
    it("max-fee-exceeded is decided on the real fee", async () => {
      mempool.nextResult = { accepted: true, fee: 5_000_000n, vsize: 110 }; // 0.05 BTC
      start();
      const r = (await call("testmempoolaccept", [[MISSING_INPUT_TX]])).result[0];
      expect(r.allowed).toBe(false);
      expect(r["reject-reason"]).toBe("max-fee-exceeded");
    });
  });

  describe("decodescript", () => {
    it("non-hex is RPC_INVALID_PARAMETER -8", async () => {
      start();
      expectError(await call("decodescript", ["zz"]), -8);
      expectError(await call("decodescript", ["51zz"]), -8);
      expectError(await call("decodescript", ["515"]), -8);
    });
    it("CONTROL: '' is the empty script and '51' is OP_TRUE", async () => {
      start();
      expect((await call("decodescript", [""])).error ?? null).toBeNull();
      expect((await call("decodescript", ["51"])).result.asm).toBe("1");
    });
  });

  describe("combinerawtransaction", () => {
    it("an input whose coin does not exist is RPC_VERIFY_ERROR -25", async () => {
      start();
      expectError(await call("combinerawtransaction", [[AAAA_TX, AAAA_TX]]), -25);
    });
    it("CONTROL: the same tx combines once its coin is in the UTXO set", async () => {
      chainState.coins.set(`${"aa".repeat(32)}:0`, { amount: 200_000n, scriptPubKey: Buffer.alloc(0), height: 1, coinbase: false });
      start();
      const resp = await call("combinerawtransaction", [[AAAA_TX, AAAA_TX]]);
      expect(resp.error ?? null).toBeNull();
      expect(resp.result).toBe(AAAA_TX);
    });
  });

  describe("deriveaddresses", () => {
    const KEY = "wpkh(03789ed0bb717d88f7d321a368d905e7430207ebbd82bd342cf11ae157a7ace5fd)";
    const RANGED = "wpkh(tpubD6NzVbkrYhZ4XgiXtGrdW5XDAPFCL9h7we1vwNCpn8tGbBcgfVYjXyhWo4E1xkh56hjod1RhGjxbaTLV3X4FyWuejifB9jusQ46QzG87VKp/0/*)";
    it("a descriptor without a checksum is -5 'Missing checksum'", async () => {
      start();
      const resp = await call("deriveaddresses", [KEY]);
      expectError(resp, -5);
      expect(resp.error.message).toBe("Missing checksum");
    });
    it("a range on an un-ranged descriptor is -8", async () => {
      start();
      const cs = (await call("getdescriptorinfo", [KEY])).result.checksum;
      expectError(await call("deriveaddresses", [`${KEY}#${cs}`, [0, 2]]), -8);
    });
    it("a ranged descriptor with no range is -8", async () => {
      start();
      const cs = (await call("getdescriptorinfo", [RANGED])).result.checksum;
      expectError(await call("deriveaddresses", [`${RANGED}#${cs}`]), -8);
    });
    it("CONTROL: checksummed calls still derive", async () => {
      start();
      const cs = (await call("getdescriptorinfo", [KEY])).result.checksum;
      expect((await call("deriveaddresses", [`${KEY}#${cs}`])).result).toHaveLength(1);
      const rcs = (await call("getdescriptorinfo", [RANGED])).result.checksum;
      expect((await call("deriveaddresses", [`${RANGED}#${rcs}`, [0, 2]])).result).toHaveLength(3);
    });
  });

  describe("createpsbt default nSequence (Core AddInputs)", () => {
    const INPUTS = [{ txid: "aa".repeat(32), vout: 0 }];
    const OUTPUTS = { bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080: 0.001 };
    function seqOf(psbtB64: string): number {
      const raw = Buffer.from(psbtB64, "base64");
      // magic(5) key(0x01,0x00) len(0x52) | tx: ver(4) nin(1) prevout(36) script(1) SEQ(4)
      return raw.readUInt32LE(5 + 2 + 1 + 4 + 1 + 36 + 1);
    }
    it("replaceable omitted -> 0xfffffffd, byte-identical to Core", async () => {
      start();
      const resp = await call("createpsbt", [INPUTS, OUTPUTS]);
      expect(resp.result).toBe(
        "cHNidP8BAFICAAAAAaqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqAAAAAAD9////AaCGAQAAAAAAFgAUdR526BmRltRUlBxF0bOjI/FDO9YAAAAAAAAA"
      );
      expect(seqOf(resp.result)).toBe(0xfffffffd);
    });
    it("replaceable=false: SEQUENCE_FINAL at locktime 0, MAX_SEQUENCE_NONFINAL otherwise", async () => {
      start();
      expect(seqOf((await call("createpsbt", [INPUTS, OUTPUTS, 0, false])).result)).toBe(0xffffffff);
      expect(seqOf((await call("createpsbt", [INPUTS, OUTPUTS, 5, false])).result)).toBe(0xfffffffe);
      expect(seqOf((await call("createpsbt", [INPUTS, OUTPUTS, 0, true])).result)).toBe(0xfffffffd);
    });
  });
});
