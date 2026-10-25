/**
 * Regtest address encoding in RPC output.
 *
 * Core encodes every address / addr() descriptor under the ACTIVE chain's
 * prefixes (key_io.cpp EncodeDestination; chainparams.cpp regtest:
 * SCRIPT_ADDRESS=196 -> "2...", bech32_hrp="bcrt"). Three RPC paths called
 * buildScriptPubKeyObj without the network and so emitted mainnet "3..." /
 * "bc1..." on regtest: getrawtransaction verbosity 2 (vout + prevout) and
 * scantxoutset unspents[].desc.
 */
import { describe, it, expect } from "bun:test";
import { RPCServer, RPCServerConfig, RPCServerDeps } from "../rpc/server.js";
import { REGTEST } from "../consensus/params.js";
import { DBPrefix } from "../storage/database.js";
import { BufferWriter } from "../wire/serialization.js";

const p2sh = Buffer.concat([Buffer.from("a914", "hex"), Buffer.alloc(20, 0x11), Buffer.from("87", "hex")]);
const p2wpkh = Buffer.concat([Buffer.from("0014", "hex"), Buffer.alloc(20, 0x22)]);

function makeServer(db: unknown): RPCServer {
  const config: RPCServerConfig = { port: 29990, host: "127.0.0.1", noAuth: true };
  const deps = {
    chainState: { getBestBlock: () => ({ hash: Buffer.alloc(32, 1), height: 5 }) } as any,
    mempool: {} as any,
    peerManager: {} as any,
    feeEstimator: {} as any,
    headerSync: {} as any,
    db: db as any,
    params: REGTEST,
  } as RPCServerDeps;
  return new RPCServer(config, deps);
}

describe("regtest address encoding", () => {
  it("getrawtransaction v2 vout + prevout use regtest prefixes", () => {
    const server = makeServer({}) as any;
    const tx = {
      version: 2,
      lockTime: 0,
      inputs: [{ prevOut: { txid: Buffer.alloc(32, 7), vout: 0 }, scriptSig: Buffer.alloc(0), sequence: 0xffffffff, witness: [] }],
      outputs: [
        { value: 1000n, scriptPubKey: p2sh },
        { value: 1000n, scriptPubKey: p2wpkh },
      ],
    };
    const prev = new Map([
      [`${Buffer.alloc(32, 7).toString("hex")}:0`, { amount: 5000n, height: 1, coinbase: false, scriptPubKey: p2wpkh }],
    ]);
    const r = server.formatTxForGetRawTxV2(tx, prev);
    const vout = r.vout as any[];
    expect(vout[0].scriptPubKey.address.startsWith("2")).toBe(true);
    expect(vout[0].scriptPubKey.desc.startsWith("addr(2")).toBe(true);
    expect(vout[1].scriptPubKey.address.startsWith("bcrt1q")).toBe(true);
    expect(vout[1].scriptPubKey.desc.startsWith("addr(bcrt1q")).toBe(true);
    const pv = (r.vin as any[])[0].prevout.scriptPubKey;
    expect(pv.address.startsWith("bcrt1q")).toBe(true);
    expect(pv.desc.startsWith("addr(bcrt1q")).toBe(true);
  });

  it("scantxoutset unspents[].desc uses the regtest address", async () => {
    const w = new BufferWriter();
    w.writeUInt32LE(3);
    w.writeUInt8(0);
    w.writeUInt64LE(1000n);
    w.writeVarBytes(p2sh);
    const key = Buffer.concat([Buffer.from([DBPrefix.UTXO]), Buffer.alloc(32, 9), Buffer.from([0, 0, 0, 0])]);
    const entries: Array<[Buffer, Buffer]> = [[key, w.toBuffer()]];
    const db = {
      db: { iterator: () => ({ async *[Symbol.asyncIterator]() { for (const e of entries) yield e; }, async close() {} }) },
      getBlockHashByHeight: async () => Buffer.alloc(32, 3),
    };
    const server = makeServer(db) as any;
    const res = await server.scanTxOutSet(["start", ["raw(" + p2sh.toString("hex") + ")"]]);
    const desc = (res.unspents[0] as any).desc as string;
    expect(desc.startsWith("addr(2")).toBe(true);
  });
});
