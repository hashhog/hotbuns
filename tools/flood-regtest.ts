/**
 * End-to-end RPC-starvation repro: flood a regtest hotbuns node with valid
 * transactions from ONE P2P peer while timing RPC `getblockcount`.
 *
 *   bun run tools/flood-regtest.ts --tree=<hotbuns checkout> [--fanouts=40]
 *       [--per=1000] [--chainEvery=4] [--basePort=39500] [--keep]
 *       [--nodeFlags="--cpu-prof-md --cpu-prof-dir=/some/dir"]
 *
 * What it does:
 *   1. starts `bun run src/index.ts --network=regtest` from --tree in a fresh
 *      temp datadir (the node under test; killed via tools/safe-kill.sh);
 *   2. mines 200+ blocks to an OP_TRUE P2WSH address, then confirms
 *      `fanouts` fan-out transactions of `per` outputs each;
 *   3. connects a fake v1 peer (version/verack/pong only) and writes
 *      fanouts*per 1-in-1-out spends as unsolicited `tx` messages as fast as
 *      the socket takes them; every `chainEvery`-th spend also gets a child
 *      spending it (exercises the in-mempool-parent / cluster path);
 *   4. meanwhile probes `getblockcount` back-to-back (120 s client timeout)
 *      and records each latency;
 *   5. waits for the mempool to stop growing and prints one JSON summary,
 *      including a digest of the sorted mempool txid set (to compare the
 *      accepted set between two trees fed the same input).
 *
 * The transactions are deterministic for given parameters, so two runs
 * against two trees see byte-identical input.
 */
import { spawn, spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, readdirSync, statSync, openSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { createHash, randomBytes } from "node:crypto";
import { serializeMessage, parseHeader, MESSAGE_HEADER_SIZE, deserializeMessage } from "../src/p2p/messages.js";
import type { NetworkMessage } from "../src/p2p/messages.js";
import { REGTEST } from "../src/consensus/params.js";
import { bech32Encode } from "../src/address/encoding.js";
import { serializeTx, getTxId, type Transaction } from "../src/validation/tx.js";

// ---------------------------------------------------------------- args
const args = new Map<string, string>();
for (const a of process.argv.slice(2)) {
  const m = /^--([^=]+)(?:=(.*))?$/.exec(a);
  if (m) args.set(m[1], m[2] ?? "1");
}
const tree = resolve(args.get("tree") ?? ".");
const FANOUTS = Number(args.get("fanouts") ?? 40);
const PER = Number(args.get("per") ?? 1000);
const CHAIN_EVERY = Number(args.get("chainEvery") ?? 4);
const BASE = Number(args.get("basePort") ?? 39500);
const KEEP = args.has("keep");
const RPC_PORT = BASE, P2P_PORT = BASE + 1, METRICS_PORT = BASE + 2;
const MAGIC = REGTEST.networkMagic;

// ---------------------------------------------------------------- scripts
const WITNESS_SCRIPT = Buffer.from([0x51]); // OP_TRUE
const PROGRAM = createHash("sha256").update(WITNESS_SCRIPT).digest();
const SPK = Buffer.concat([Buffer.from([0x00, 0x20]), PROGRAM]);
const ADDRESS = bech32Encode("bcrt", 0, PROGRAM);

function spend(prevTxid: Buffer, vout: number, outs: bigint[]): Transaction {
  return {
    version: 2,
    inputs: [{ prevOut: { txid: prevTxid, vout }, scriptSig: Buffer.alloc(0), sequence: 0xfffffffd, witness: [WITNESS_SCRIPT] }],
    outputs: outs.map((value) => ({ value, scriptPubKey: SPK })),
    lockTime: 0,
  };
}

// ---------------------------------------------------------------- node
const datadir = mkdtempSync(join(tmpdir(), "hotbuns-flood-"));
const logPath = join(datadir, "node.log");
const logFd = openSync(logPath, "a");
const node = spawn(
  process.execPath,
  [...(args.get("nodeFlags") ?? "").split(" ").filter(Boolean), "run", "src/index.ts", "--network=regtest", `--datadir=${datadir}`, `--rpcport=${RPC_PORT}`, `--port=${P2P_PORT}`, `--metrics-port=${METRICS_PORT}`],
  { cwd: tree, stdio: ["ignore", logFd, logFd], detached: false }
);
const nodePid = node.pid!;
console.error(`[flood] node pid=${nodePid} tree=${tree} datadir=${datadir}`);

function killNode(): void {
  const r = spawnSync("bash", [join(import.meta.dir, "../../../tools/safe-kill.sh"), "--pid", String(nodePid), "--expect", datadir], { encoding: "utf8" });
  if (r.status !== 0) {
    // Fall back to the child handle (same PID we started).
    try { node.kill("SIGTERM"); } catch { /* gone */ }
  }
}
process.on("exit", () => { try { killNode(); } catch { /* */ } });

function findCookie(dir: string): string | null {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (name === ".cookie") return p;
    try { if (statSync(p).isDirectory()) { const c = findCookie(p); if (c) return c; } } catch { /* */ }
  }
  return null;
}

let auth = "";
async function rpc(method: string, params: unknown[] = [], timeoutMs = 120_000): Promise<any> {
  const res = await fetch(`http://127.0.0.1:${RPC_PORT}/`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Basic ${auth}` },
    body: JSON.stringify({ jsonrpc: "1.0", id: 1, method, params }),
    signal: AbortSignal.timeout(timeoutMs),
  });
  const j = (await res.json()) as any;
  if (j.error) throw new Error(`${method}: ${JSON.stringify(j.error)}`);
  return j.result;
}

async function waitRpc(): Promise<void> {
  const deadline = Date.now() + 180_000;
  while (Date.now() < deadline) {
    const c = findCookie(datadir);
    if (c) {
      auth = Buffer.from(readFileSync(c, "utf8").trim()).toString("base64");
      try { await rpc("getblockcount", [], 5000); return; } catch { /* not yet */ }
    }
    await Bun.sleep(500);
  }
  throw new Error("node RPC never came up; see " + logPath);
}

// ---------------------------------------------------------------- fake peer
type Sock = { write(b: Buffer): number; end(): void };
let sock: Sock | null = null;
let pending: Buffer[] = [];
let drainWaiter: (() => void) | null = null;
let rbuf = Buffer.alloc(0);
let verackReceived = false;

function sendRaw(b: Buffer): void {
  pending.push(b);
  flush();
}
function flush(): void {
  while (sock && pending.length > 0) {
    const b = pending[0];
    const n = sock.write(b);
    if (n < b.length) { pending[0] = b.subarray(n); return; }
    pending.shift();
  }
  if (pending.length === 0 && drainWaiter) { const w = drainWaiter; drainWaiter = null; w(); }
}
const send = (m: NetworkMessage) => sendRaw(serializeMessage(MAGIC, m));

async function connectPeer(): Promise<void> {
  const zeroAddr = { services: 0n, ip: Buffer.alloc(16), port: 0 };
  await Bun.connect({
    hostname: "127.0.0.1",
    port: P2P_PORT,
    socket: {
      open(s) {
        sock = s as unknown as Sock;
        send({
          type: "version",
          payload: {
            version: 70016, services: 9n, timestamp: BigInt(Math.floor(Date.now() / 1000)),
            addrRecv: zeroAddr, addrFrom: zeroAddr, nonce: BigInt("0x" + randomBytes(8).toString("hex")),
            userAgent: "/flood-harness:0.1/", startHeight: 0, relay: true,
          },
        } as NetworkMessage);
      },
      data(_s, data) {
        rbuf = Buffer.concat([rbuf, data]);
        while (rbuf.length >= MESSAGE_HEADER_SIZE) {
          const h = parseHeader(rbuf);
          if (!h) break;
          const total = MESSAGE_HEADER_SIZE + h.length;
          if (rbuf.length < total) break;
          const payload = rbuf.subarray(MESSAGE_HEADER_SIZE, total);
          rbuf = Buffer.from(rbuf.subarray(total));
          if (h.command === "version") send({ type: "verack", payload: null } as NetworkMessage);
          else if (h.command === "verack") verackReceived = true;
          else if (h.command === "ping") {
            try {
              const m = deserializeMessage(h, payload) as any;
              send({ type: "pong", payload: { nonce: m.payload.nonce } } as NetworkMessage);
            } catch { /* */ }
          }
        }
      },
      drain() { flush(); },
      close() { sock = null; console.error("[flood] peer socket closed by node"); },
      error(_s, e) { console.error("[flood] peer socket error", e); },
    },
  });
  const deadline = Date.now() + 30_000;
  while (!verackReceived) {
    if (Date.now() > deadline) throw new Error("handshake timeout");
    await Bun.sleep(50);
  }
}

// ---------------------------------------------------------------- main
function pct(a: number[], p: number): number {
  if (a.length === 0) return NaN;
  const s = [...a].sort((x, y) => x - y);
  return +s[Math.min(s.length - 1, Math.floor(s.length * p))].toFixed(1);
}

try {
  await waitRpc();
  // Mine: FANOUTS mature coinbases need height >= FANOUTS + 100.
  const mineTo = Math.max(200, FANOUTS + 101);
  for (let h = await rpc("getblockcount"); h < mineTo; h = await rpc("getblockcount")) {
    await rpc("generatetoaddress", [Math.min(50, mineTo - h), ADDRESS], 600_000);
  }
  // Fan-outs from coinbases at heights 1..FANOUTS.
  const leaves: Array<{ txid: Buffer; vout: number; value: bigint }> = [];
  for (let i = 1; i <= FANOUTS; i++) {
    const bh = await rpc("getblockhash", [i]);
    const blk = await rpc("getblock", [bh, 2]);
    const cb = blk.tx[0];
    const cbValue = BigInt(Math.round(cb.vout[0].value * 1e8));
    const each = (cbValue - 100_000n) / BigInt(PER);
    const fan = spend(Buffer.from(cb.txid, "hex").reverse(), 0, new Array(PER).fill(each));
    await rpc("sendrawtransaction", [serializeTx(fan, true).toString("hex")]);
    const fid = getTxId(fan);
    for (let v = 0; v < PER; v++) leaves.push({ txid: fid, vout: v, value: each });
  }
  // Fan-outs exceed one block's weight: mine until they are all confirmed.
  for (let i = 0; i < 20 && (await rpc("getmempoolinfo")).size > 0; i++) {
    await rpc("generatetoaddress", [1, ADDRESS], 600_000);
  }
  const mp0 = await rpc("getmempoolinfo");
  if (mp0.size !== 0) throw new Error(`fan-outs not all mined (mempool size ${mp0.size})`);
  const ibd = (await rpc("getblockchaininfo")).initialblockdownload;
  console.error(`[flood] setup done: height=${await rpc("getblockcount")} leaves=${leaves.length} ibd=${ibd}`);

  // Build the flood (deterministic).
  const frames: Buffer[] = [];
  for (let i = 0; i < leaves.length; i++) {
    const l = leaves[i];
    const t = spend(l.txid, l.vout, [l.value - 1_000n]);
    frames.push(serializeMessage(MAGIC, { type: "tx", payload: { tx: t } } as NetworkMessage));
    if (CHAIN_EVERY > 0 && i % CHAIN_EVERY === 0) {
      const c = spend(getTxId(t), 0, [l.value - 2_000n]);
      frames.push(serializeMessage(MAGIC, { type: "tx", payload: { tx: c } } as NetworkMessage));
    }
  }

  await connectPeer();

  // RPC probe, back to back.
  const lat: Array<{ t: number; ms: number; ok: boolean }> = [];
  let probing = true;
  const t0 = performance.now();
  const probe = (async () => {
    while (probing) {
      const s = performance.now();
      let ok = true;
      try { await rpc("getblockcount", [], 120_000); } catch { ok = false; }
      lat.push({ t: (s - t0) / 1000, ms: performance.now() - s, ok });
      await Bun.sleep(100);
    }
  })();
  // Baseline probe (idle) for 3 s.
  await Bun.sleep(3000);
  const idleCount = lat.length;

  // Flood.
  const floodStart = performance.now();
  for (const f of frames) sendRaw(f);
  await new Promise<void>((r) => { if (pending.length === 0) r(); else drainWaiter = r; });
  const writeSecs = (performance.now() - floodStart) / 1000;
  console.error(`[flood] ${frames.length} tx messages written in ${writeSecs.toFixed(1)} s`);

  // Wait until the mempool stops growing for 15 s (or 30 min cap).
  let last = -1, stableSince = performance.now(), size = 0;
  const cap = performance.now() + 30 * 60_000;
  while (performance.now() < cap) {
    await Bun.sleep(2000);
    try { size = (await rpc("getmempoolinfo", [], 120_000)).size; } catch { continue; }
    if (size !== last) { last = size; stableSince = performance.now(); }
    else if (performance.now() - stableSince > 15_000) break;
  }
  const settleSecs = (stableSince - floodStart) / 1000;
  probing = false;
  await probe;

  const txids: string[] = await rpc("getrawmempool", [], 300_000);
  txids.sort();
  const digest = createHash("sha256").update(txids.join("\n")).digest("hex").slice(0, 16);
  const during = lat.slice(idleCount).filter((x) => x.t * 1000 <= settleSecs * 1000 + (floodStart - t0));
  const idle = lat.slice(0, idleCount);
  const logText = readFileSync(logPath, "utf8");
  const lagLines = logText.split("\n").filter((l) => l.includes("[loop-lag]"));
  const slowRpc = logText.split("\n").filter((l) => l.includes("[rpc] slow request"));
  let metrics = "";
  try { metrics = await (await fetch(`http://127.0.0.1:${METRICS_PORT}/metrics`, { signal: AbortSignal.timeout(60_000) })).text(); } catch { /* */ }
  const metric = (n: string) => { const m = new RegExp(`^${n} (\\S+)$`, "m").exec(metrics); return m ? Number(m[1]) : null; };

  console.log(JSON.stringify({
    tree,
    sentTxMessages: frames.length,
    mempoolSize: txids.length,
    mempoolDigest: digest,
    writeSecs: +writeSecs.toFixed(1),
    settleSecs: +settleSecs.toFixed(1),
    acceptRatePerSec: +(txids.length / Math.max(settleSecs, 0.001)).toFixed(1),
    rpcIdle: { n: idle.length, p50: pct(idle.map((x) => x.ms), 0.5), max: pct(idle.map((x) => x.ms), 1) },
    rpcDuringFlood: {
      n: during.length,
      failures: during.filter((x) => !x.ok).length,
      p50: pct(during.map((x) => x.ms), 0.5),
      p90: pct(during.map((x) => x.ms), 0.9),
      p99: pct(during.map((x) => x.ms), 0.99),
      max: pct(during.map((x) => x.ms), 1),
      over2s: during.filter((x) => x.ms > 2000).length,
    },
    loopLagLogLines: lagLines.length,
    loopLagMaxMsMetric: metric("bitcoin_event_loop_lag_max_ms"),
    rpcRequestMaxMsMetric: metric("bitcoin_rpc_request_max_ms"),
    slowRpcLogLines: slowRpc.length,
    peerStillConnected: sock !== null,
    log: KEEP ? logPath : undefined,
  }));
} finally {
  killNode();
  await Bun.sleep(1500);
  if (!KEEP) rmSync(datadir, { recursive: true, force: true });
}
process.exit(0);
