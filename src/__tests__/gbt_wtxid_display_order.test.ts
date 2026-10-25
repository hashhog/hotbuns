/**
 * getblocktemplate transactions[].hash is the wtxid in display (reversed)
 * byte order, like Core's `entry.pushKV("hash", tx.GetWitnessHash().GetHex())`
 * (bitcoin-core/src/rpc/mining.cpp). getWTxId() returns internal order, so
 * the RPC must reverse it, exactly as getrawtransaction / getblock do.
 *
 * Source-level pin (same style as w123_mining_gbt.test.ts); the behavioural
 * proof is the Core regtest ratchet rows gbt/template/segwit:transactions[n].hash.
 */
import { describe, it, expect } from "bun:test";
import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const SRC = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const RPC = readFileSync(resolve(SRC, "rpc", "server.ts"), "utf8");

function gbtBody(): string {
  const start = RPC.indexOf("private async getBlockTemplate(params: unknown[])");
  expect(start).toBeGreaterThan(-1);
  return RPC.slice(start, start + 12000);
}

describe("getblocktemplate transactions[].hash byte order", () => {
  it("emits the wtxid reversed to display order", () => {
    const body = gbtBody();
    expect(body).toContain('hash: Buffer.from(getWTxId(entry.tx)).reverse().toString("hex")');
  });
  it("does not emit the internal-order wtxid", () => {
    expect(gbtBody()).not.toContain('hash: getWTxId(entry.tx).toString("hex")');
  });
});
