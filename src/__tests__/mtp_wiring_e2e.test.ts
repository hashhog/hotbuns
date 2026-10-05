/**
 * BIP-113 / BIP-68 time context on the REAL binary (2026-10-05).
 *
 * Spawns `bun run src/index.ts` (what the live fleet runs) on regtest and
 * drives it over RPC and `--import-blocks=-`. Discriminates the two wiring
 * bugs a unit test of Mempool / ChainStateManager in isolation cannot see,
 * because both were "no production caller" bugs in cli.ts:
 *
 *   1. mempool tipMTP was never set (0) and no coin-MTP source was wired:
 *      every time-based nLockTime tx and every time-type relative lock was
 *      refused.  Core: CheckFinalTxAtTip / CalculateLockPointsAtTip.
 *   2. ChainStateManager.connectBlock (the --import-blocks path) used the
 *      block's OWN timestamp as prevMTP and coin MTP 0: blocks Core rejects
 *      (bad-txns-nonfinal) were ACCEPTED.  Core: ContextualCheckBlock
 *      (lock_time_cutoff = pprev MTP) and SequenceLocks in ConnectBlock.
 *
 * Expected values are derived from Core's rules on the fixture's
 * hand-computable timestamps (src/test/mtp_chain_fixture.ts), not from
 * hotbuns' own answers.
 */
import { describe, test, expect, beforeAll, afterAll } from "bun:test";
import { mkdtemp, rm, readdir, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { createServer } from "node:net";
import { getBlockHash, serializeBlock } from "../validation/block.js";
import { getTxId } from "../validation/tx.js";
import type { Block } from "../validation/block.js";
import { REGTEST } from "../consensus/params.js";
import {
  buildBaseChain,
  mineBlock,
  spendOpTrue,
  timeLock,
  importFrame,
  txHex,
  tsAt,
  mtpAt,
  BASE_TIP,
  FUND_HEIGHT,
  FUND_OUT_VALUE,
  type BaseChain,
} from "../test/mtp_chain_fixture.js";
import { deserializeBlock } from "../validation/block.js";
import { BufferReader } from "../wire/serialization.js";

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const BUN = process.execPath;

const GENESIS_TS = deserializeBlock(new BufferReader(REGTEST.genesisBlock)).header.timestamp;
const TIP_MTP = mtpAt(BASE_TIP, GENESIS_TS);          // = ts(115)
const COIN_MTP = mtpAt(FUND_HEIGHT - 1, GENESIS_TS);  // = ts(96)

async function freePort(): Promise<number> {
  for (let i = 0; i < 50; i++) {
    const p = 30100 + Math.floor(Math.random() * 300);
    const ok = await new Promise<boolean>((res) => {
      const s = createServer();
      s.once("error", () => res(false));
      s.listen(p, "127.0.0.1", () => s.close(() => res(true)));
    });
    if (ok) return p;
  }
  throw new Error("no free port in 30100-30399");
}

let chain: BaseChain;
const tmpDirs: string[] = [];

beforeAll(() => {
  chain = buildBaseChain();
  expect(TIP_MTP).toBe(tsAt(115));
  expect(COIN_MTP).toBe(tsAt(96));
});

afterAll(async () => {
  for (const d of tmpDirs) await rm(d, { recursive: true, force: true });
});

/** Run --import-blocks=- over the base chain + extra blocks; return stdout+stderr. */
async function runImport(extra: Block[]): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "hb-mtp-import-"));
  tmpDirs.push(dir);
  const port = await freePort();
  const rpcport = await freePort();
  const frames: Buffer[] = chain.blocks.map((b, i) => importFrame(i + 1, b));
  extra.forEach((b, i) => frames.push(importFrame(BASE_TIP + 1 + i, b)));
  const proc = Bun.spawn(
    [BUN, "run", "src/index.ts", "--network=regtest", `--datadir=${dir}`,
     `--port=${port}`, `--rpcport=${rpcport}`, "--import-blocks=-"],
    { cwd: REPO, stdin: "pipe", stdout: "pipe", stderr: "pipe" },
  );
  proc.stdin.write(Buffer.concat(frames));
  await proc.stdin.end();
  const killer = setTimeout(() => proc.kill(), 45_000);
  const [out, err] = await Promise.all([
    new Response(proc.stdout).text(),
    new Response(proc.stderr).text(),
  ]);
  await proc.exited;
  clearTimeout(killer);
  return out + err;
}

const nextBlock = (txs: ReturnType<typeof spendOpTrue>[]): Block =>
  mineBlock(chain.tipHash, BASE_TIP + 1, tsAt(BASE_TIP + 1), txs);
const fundTxid = () => getTxId(chain.fundTx);
const imported = (log: string): number => {
  const m = log.match(/Import complete: (\d+) blocks/);
  return m ? Number(m[1]) : -1;
};

describe("--import-blocks connect path uses Core's prevMTP + per-coin MTP", () => {
  test("control: base chain + a block with an nLockTime = prevMTP-1 tx imports in full", async () => {
    const tx = spendOpTrue(fundTxid(), 0, FUND_OUT_VALUE, { lockTime: TIP_MTP - 1, sequence: 0xfffffffe });
    const log = await runImport([nextBlock([tx])]);
    expect(imported(log)).toBe(BASE_TIP + 1);
    expect(log).not.toContain("Block validation failed");
  }, 60_000);

  test("nLockTime = prevMTP (Core: non-final, lock_time_cutoff = pprev MTP) is REJECTED", async () => {
    // Block timestamp ts(121) > TIP_MTP: using the block's own time as the
    // cutoff (the deployed bug) makes this tx final.
    const tx = spendOpTrue(fundTxid(), 0, FUND_OUT_VALUE, { lockTime: TIP_MTP, sequence: 0xfffffffe });
    const log = await runImport([nextBlock([tx])]);
    expect(log).toContain(`Block validation failed at height ${BASE_TIP + 1}`);
    expect(log).toContain("bad-txns-nonfinal");
    expect(imported(log)).toBe(BASE_TIP);
  }, 60_000);

  test("control: matured time-type relative lock (11 x 512 s) on a confirmed coin imports", async () => {
    const tx = spendOpTrue(fundTxid(), 1, FUND_OUT_VALUE, { sequence: timeLock(11) });
    const log = await runImport([nextBlock([tx])]);
    expect(imported(log)).toBe(BASE_TIP + 1);
    expect(log).not.toContain("Block validation failed");
  }, 60_000);

  test("unmatured time-type relative lock (12 x 512 s; coin MTP = MTP(101)) is REJECTED", async () => {
    // Core: minTime = MTP(101) + 6144 - 1 >= MTP(120) -> non-BIP68-final.
    // Deployed: coin MTP 0 -> minTime 6143 -> trivially satisfied.
    expect(COIN_MTP + 12 * 512 - 1).toBeGreaterThanOrEqual(TIP_MTP);
    const tx = spendOpTrue(fundTxid(), 1, FUND_OUT_VALUE, { sequence: timeLock(12) });
    const log = await runImport([nextBlock([tx])]);
    expect(log).toContain(`Block validation failed at height ${BASE_TIP + 1}`);
    expect(log).toContain("bad-txns-nonfinal");
    expect(imported(log)).toBe(BASE_TIP);
  }, 60_000);
});

// ---------------------------------------------------------------------------
// Live node: mempool admission + generateblock / submitblock (injectBlock path)
// ---------------------------------------------------------------------------

describe("running node: mempool time locks read the ACTIVE tip", () => {
  let proc: ReturnType<typeof Bun.spawn> | null = null;
  let rpcport = 0;
  let auth = "";
  let dir = "";
  let logBuf = "";

  async function rpc(method: string, params: unknown[] = []): Promise<any> {
    const r = await fetch(`http://127.0.0.1:${rpcport}/`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: auth },
      body: JSON.stringify({ jsonrpc: "1.0", id: 1, method, params }),
      signal: AbortSignal.timeout(30_000),
    });
    const j = (await r.json()) as { result: unknown; error: { message: string } | null };
    if (j.error) throw new Error(`${method}: ${j.error.message}`);
    return j.result;
  }

  async function findCookie(root: string): Promise<string | null> {
    const ents = await readdir(root, { withFileTypes: true }).catch(() => []);
    for (const e of ents) {
      const p = join(root, e.name);
      if (e.isFile() && e.name === ".cookie") return p;
      if (e.isDirectory()) {
        const f = await findCookie(p);
        if (f) return f;
      }
    }
    return null;
  }

  beforeAll(async () => {
    dir = await mkdtemp(join(tmpdir(), "hb-mtp-node-"));
    tmpDirs.push(dir);
    const port = await freePort();
    rpcport = await freePort();
    proc = Bun.spawn(
      [BUN, "run", "src/index.ts", "--network=regtest", `--datadir=${dir}`,
       `--port=${port}`, `--rpcport=${rpcport}`],
      { cwd: REPO, stdout: "pipe", stderr: "pipe" },
    );
    const drain = async (s: ReadableStream<Uint8Array>) => {
      const dec = new TextDecoder();
      for await (const c of s) logBuf += dec.decode(c);
    };
    void drain(proc.stdout as ReadableStream<Uint8Array>);
    void drain(proc.stderr as ReadableStream<Uint8Array>);
    const deadline = Date.now() + 40_000;
    for (;;) {
      if (Date.now() > deadline) throw new Error(`node did not come up:\n${logBuf.slice(-3000)}`);
      const c = await findCookie(dir);
      if (c) {
        auth = "Basic " + Buffer.from((await readFile(c, "utf8")).trim()).toString("base64");
        try { await rpc("getblockcount"); break; } catch { /* not ready */ }
      }
      await Bun.sleep(250);
    }
    for (const b of chain.blocks) {
      const res = await rpc("submitblock", [serializeBlock(b).toString("hex")]);
      if (res !== null && res !== "duplicate") throw new Error(`submitblock: ${res}`);
    }
    expect(await rpc("getblockcount")).toBe(BASE_TIP);
    const hdr = await rpc("getblockheader", [Buffer.from(chain.tipHash).reverse().toString("hex")]);
    expect(hdr.mediantime).toBe(TIP_MTP);
  }, 120_000);

  afterAll(async () => {
    if (!proc) return;
    try { await rpc("stop"); } catch { /* already gone */ }
    const t = setTimeout(() => proc!.kill(9), 20_000);
    await proc.exited;
    clearTimeout(t);
  }, 30_000);

  const accept = async (tx: ReturnType<typeof spendOpTrue>) =>
    (await rpc("testmempoolaccept", [[txHex(tx)]]))[0] as { allowed: boolean; "reject-reason"?: string };

  test("matured time-type relative lock on a CONFIRMED coin is ACCEPTED", async () => {
    const r = await accept(spendOpTrue(fundTxid(), 2, FUND_OUT_VALUE, { sequence: timeLock(11) }));
    expect(r["reject-reason"]).toBeUndefined();
    expect(r.allowed).toBe(true);
  }, 40_000);

  test("control: unmatured time-type relative lock (12 units) is REJECTED non-BIP68-final", async () => {
    const r = await accept(spendOpTrue(fundTxid(), 2, FUND_OUT_VALUE, { sequence: timeLock(12) }));
    expect(r.allowed).toBe(false);
    expect(String(r["reject-reason"])).toContain("non-BIP68-final");
  }, 40_000);

  test("nLockTime = tipMTP - 1 is ACCEPTED", async () => {
    const r = await accept(spendOpTrue(fundTxid(), 3, FUND_OUT_VALUE, { lockTime: TIP_MTP - 1, sequence: 0xfffffffe }));
    expect(r["reject-reason"]).toBeUndefined();
    expect(r.allowed).toBe(true);
  }, 40_000);

  test("control: nLockTime = tipMTP is REJECTED non-final", async () => {
    const r = await accept(spendOpTrue(fundTxid(), 3, FUND_OUT_VALUE, { lockTime: TIP_MTP, sequence: 0xfffffffe }));
    expect(r.allowed).toBe(false);
    expect(String(r["reject-reason"])).toContain("non-final");
  }, 40_000);

  test("child of an UNCONFIRMED parent with a height lock of 1 is REJECTED non-BIP68-final; lock 0 control accepted", async () => {
    const parent = spendOpTrue(fundTxid(), 4, FUND_OUT_VALUE);
    await rpc("sendrawtransaction", [txHex(parent)]);
    const pv = FUND_OUT_VALUE - 10_000n;
    const child1 = spendOpTrue(getTxId(parent), 0, pv, { sequence: 1 });
    const r1 = await accept(child1);
    expect(r1.allowed).toBe(false);
    expect(String(r1["reject-reason"])).toContain("non-BIP68-final");
    const child0 = spendOpTrue(getTxId(parent), 0, pv, { sequence: 0 });
    const r0 = await accept(child0);
    expect(r0["reject-reason"]).toBeUndefined();
    expect(r0.allowed).toBe(true);
  }, 40_000);

  test("submitblock of a block with an nLockTime = tipMTP tx is REJECTED (P2P/injectBlock path)", async () => {
    const tip = await rpc("getbestblockhash");
    const height = await rpc("getblockcount");
    const prev = Buffer.from(tip, "hex").reverse();
    const bad = spendOpTrue(fundTxid(), 5, FUND_OUT_VALUE, { lockTime: TIP_MTP, sequence: 0xfffffffe });
    const b = mineBlock(prev, height + 1, tsAt(height + 1), [bad]);
    const res = await rpc("submitblock", [serializeBlock(b).toString("hex")]);
    expect(String(res)).toContain("bad-txns-nonfinal");
    expect(await rpc("getblockcount")).toBe(height);
  }, 40_000);

  test("generateblock with an nLockTime = tipMTP tx is REJECTED", async () => {
    const height = await rpc("getblockcount");
    const bad = spendOpTrue(fundTxid(), 6, FUND_OUT_VALUE, { lockTime: TIP_MTP, sequence: 0xfffffffe });
    let err = "";
    try {
      // P2WSH(OP_TRUE) as a raw() descriptor-free address is not needed:
      // generateblock takes an address; use the bech32 of P2WSH(OP_TRUE).
      await rpc("generateblock", [
        "bcrt1qft5p2uhsdcdc3l2ua4ap5qqfg4pjaqlp250x7us7a8qqhrxrxfsqseac85",
        [txHex(bad)],
      ]);
    } catch (e) {
      err = (e as Error).message;
    }
    expect(err).toMatch(/non-final|nonfinal|rejected/);
    expect(await rpc("getblockcount")).toBe(height);
  }, 40_000);
});
