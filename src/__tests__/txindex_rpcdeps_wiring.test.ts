/**
 * `--txindex=1` must reach the RPC server through the real CLI wiring
 * (cli.ts rpcDeps). Boots the actual node on regtest; removing
 * `txindex: mergedConfig.txindex` from rpcDeps turns the flag-on test red.
 * Without the flag txindex stays off (Core DEFAULT_TXINDEX = false).
 */
import { describe, expect, test } from "bun:test";
import { mkdtemp, rm, readdir, readFile } from "fs/promises";
import { tmpdir } from "os";
import { join } from "path";
import net from "net";

const REPO = join(import.meta.dir, "..", "..");
const BUN = process.execPath;
const MISSING = "0000000000000000000000000000000000000000000000000000000000000001";

let nextPort = 30400;
async function freePort(): Promise<number> {
  for (let p = nextPort; p < 30700; p++) {
    const ok = await new Promise<boolean>((res) => {
      const s = net.createServer();
      s.once("error", () => res(false));
      s.listen(p, "127.0.0.1", () => s.close(() => res(true)));
    });
    if (ok) { nextPort = p + 1; return p; }
  }
  throw new Error("no free port");
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

async function withNode(
  flags: string[],
  fn: (rpc: (m: string, p?: unknown[]) => Promise<{ result: any; error: any }>) => Promise<void>,
): Promise<void> {
  const dir = await mkdtemp(join(tmpdir(), "hb-txindex-"));
  const port = await freePort();
  const rpcport = await freePort();
  let logBuf = "";
  const proc = Bun.spawn(
    [BUN, "run", "src/index.ts", "--network=regtest", `--datadir=${dir}`,
     `--port=${port}`, `--rpcport=${rpcport}`, ...flags],
    { cwd: REPO, stdout: "pipe", stderr: "pipe" },
  );
  const drain = async (s: ReadableStream<Uint8Array>) => {
    const dec = new TextDecoder();
    for await (const c of s) logBuf += dec.decode(c);
  };
  void drain(proc.stdout as ReadableStream<Uint8Array>);
  void drain(proc.stderr as ReadableStream<Uint8Array>);
  let auth = "";
  const rpc = async (method: string, params: unknown[] = []) => {
    const r = await fetch(`http://127.0.0.1:${rpcport}/`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: auth },
      body: JSON.stringify({ jsonrpc: "1.0", id: 1, method, params }),
      signal: AbortSignal.timeout(30_000),
    });
    return (await r.json()) as { result: any; error: any };
  };
  try {
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
    await fn(rpc);
  } finally {
    try { await rpc("stop"); } catch { /* gone */ }
    const t = setTimeout(() => proc.kill(9), 15_000);
    await proc.exited;
    clearTimeout(t);
    await rm(dir, { recursive: true, force: true });
  }
}

describe("--txindex reaches RPCServerDeps via cli.ts", () => {
  test("--txindex=1: getindexinfo lists txindex; getrawtransaction w/o blockhash does a lookup", async () => {
    await withNode(["--txindex=1"], async (rpc) => {
      const info = await rpc("getindexinfo");
      expect(Object.keys(info.result)).toContain("txindex");
      const r = await rpc("getrawtransaction", [MISSING]);
      expect(r.error.message).not.toContain("Use -txindex or provide a block hash");
      expect(r.error.message).toContain("No such mempool or blockchain transaction");
    });
  }, 90_000);

  test("no flag: txindex stays off (Core DEFAULT_TXINDEX=false)", async () => {
    await withNode([], async (rpc) => {
      const info = await rpc("getindexinfo");
      expect(Object.keys(info.result)).not.toContain("txindex");
      const r = await rpc("getrawtransaction", [MISSING]);
      expect(r.error.message).toContain("Use -txindex or provide a block hash");
    });
  }, 90_000);
});
