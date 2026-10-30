/**
 * Security audit 2026-10-29 (audits/security/hotbuns-2026-10-29.md), C3 + H5.
 *
 * C3: with no RPC credentials configured the node accepted the built-in
 *     `user:pass` (DEFAULT_CONFIG), so any local process -- or a web page via
 *     DNS rebinding -- had full RPC. Core has no default credentials: without
 *     -rpcpassword only the random cookie works (httprpc.cpp:245-262).
 *
 * H5: the /wallet/<name> segment was written into a field shared by every
 *     request, before authentication and before `await req.json()`. An
 *     unauthenticated POST /wallet/bob arriving while an authenticated
 *     POST /wallet/alice was still receiving its body re-routed alice's call
 *     to bob. Core reads the wallet name from each request's own URI
 *     (wallet/rpc/util.cpp:54-58).
 *
 * Everything here runs on regtest with fresh temp datadirs.
 */
import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach } from "bun:test";
import * as fs from "fs";
import * as net from "net";
import * as os from "os";
import * as path from "path";
import { RPCServer, RPCServerConfig, RPCServerDeps } from "./server.js";
import { REGTEST } from "../consensus/params.js";
import { parseArgs } from "../cli/cli.js";

const REPO = path.resolve(import.meta.dir, "../..");
let nextPort = 41000 + (process.pid % 2000) * 4;

function basic(user: string, pass: string): string {
  return "Basic " + Buffer.from(`${user}:${pass}`).toString("base64");
}

async function post(
  port: number,
  pathname: string,
  method: string,
  headers: Record<string, string> = {},
): Promise<{ status: number; body: any }> {
  const r = await fetch(`http://127.0.0.1:${port}${pathname}`, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...headers },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params: [] }),
  });
  const text = await r.text();
  let body: any = null;
  try {
    body = JSON.parse(text);
  } catch {
    body = text;
  }
  return { status: r.status, body };
}

// ---------------------------------------------------------------------------
// C3 -- default credentials
// ---------------------------------------------------------------------------

describe("C3: no built-in RPC credentials", () => {
  it("parseArgs with no --rpc-user/--rpc-password leaves both unset", () => {
    const { config } = parseArgs(["bun", "hotbuns", "--network=regtest"]);
    expect(config.rpcUser).toBeUndefined();
    expect(config.rpcPassword).toBeUndefined();
  });

  it("an empty --rpc-password= does not install a password", () => {
    const { config } = parseArgs(["bun", "hotbuns", "--network=regtest", "--rpc-user=alice", "--rpc-password="]);
    expect(config.rpcPassword).toBeUndefined();
  });

  it("CONTROL: explicit --rpc-user/--rpc-password still parse", () => {
    const { config } = parseArgs(["bun", "hotbuns", "--rpc-user=alice", "--rpc-password=s3cret"]);
    expect(config.rpcUser).toBe("alice");
    expect(config.rpcPassword).toBe("s3cret");
  });
});

type Node = { proc: ReturnType<typeof Bun.spawn>; datadir: string; rpcPort: number };

async function startRegtestNode(extra: string[]): Promise<Node> {
  const datadir = fs.mkdtempSync(path.join(os.tmpdir(), "hotbuns-c3-"));
  const rpcPort = nextPort++;
  const p2pPort = nextPort++;
  const proc = Bun.spawn(
    [
      process.execPath,
      "run",
      path.join(REPO, "src/index.ts"),
      "--network=regtest",
      `--datadir=${datadir}`,
      `--rpcport=${rpcPort}`,
      `--port=${p2pPort}`,
      "--metrics-port=0",
      "--nodnsseed",
      "--nodiscover",
      "--connect=127.0.0.1:1",
      "--listen=0",
      ...extra,
    ],
    { cwd: REPO, stdout: "ignore", stderr: "ignore" },
  );
  const cookie = path.join(datadir, ".cookie");
  const deadline = Date.now() + 60_000;
  while (Date.now() < deadline) {
    if (fs.existsSync(cookie) && fs.readFileSync(cookie, "utf8").startsWith("__cookie__:")) {
      try {
        const r = await fetch(`http://127.0.0.1:${rpcPort}/`, { method: "POST", body: "{}" });
        await r.text();
        return { proc, datadir, rpcPort };
      } catch {
        // listener not up yet
      }
    }
    await Bun.sleep(100);
  }
  proc.kill();
  throw new Error("regtest node did not come up within 60s");
}

async function stopRegtestNode(node: Node | undefined): Promise<void> {
  if (!node) return;
  node.proc.kill();
  await node.proc.exited;
  fs.rmSync(node.datadir, { recursive: true, force: true });
}

function cookieAuth(node: Node): string {
  const [user, pass] = fs.readFileSync(path.join(node.datadir, ".cookie"), "utf8").trim().split(":");
  return basic(user, pass);
}

describe("C3: regtest node started without credentials", () => {
  let node: Node;
  beforeAll(async () => {
    node = await startRegtestNode([]);
  }, 90_000);
  afterAll(async () => stopRegtestNode(node));

  it("rejects user:pass with 401", async () => {
    const r = await post(node.rpcPort, "/", "getblockcount", {
      Authorization: basic("user", "pass"),
    });
    expect(r.status).toBe(401);
  });

  it("rejects user:pass with a rebound Host header (audit proof shape)", async () => {
    const r = await post(node.rpcPort, "/", "getblockcount", {
      Authorization: basic("user", "pass"),
      Host: `attacker.example:${node.rpcPort}`,
    });
    expect(r.status).toBe(401);
  });

  it("CONTROL: the cookie works", async () => {
    const r = await post(node.rpcPort, "/", "getblockcount", { Authorization: cookieAuth(node) });
    expect(r.status).toBe(200);
    expect(r.body.result).toBe(0);
  });

  it("CONTROL: the CLI client authenticates with the cookie (getinfo)", async () => {
    const proc = Bun.spawn(
      [
        process.execPath,
        "run",
        path.join(REPO, "src/index.ts"),
        "--network=regtest",
        `--datadir=${node.datadir}`,
        `--rpcport=${node.rpcPort}`,
        "getinfo",
      ],
      { cwd: REPO, stdout: "pipe", stderr: "pipe" },
    );
    const out = await new Response(proc.stdout).text();
    const code = await proc.exited;
    expect(code).toBe(0);
    expect(JSON.parse(out).chain).toBe("regtest");
  }, 30_000);
});

describe("C3: regtest node started with explicit credentials", () => {
  let node: Node;
  beforeAll(async () => {
    node = await startRegtestNode(["--rpc-user=alice", "--rpc-password=s3cret"]);
  }, 90_000);
  afterAll(async () => stopRegtestNode(node));

  it("CONTROL: the configured pair works", async () => {
    const r = await post(node.rpcPort, "/", "getblockcount", {
      Authorization: basic("alice", "s3cret"),
    });
    expect(r.status).toBe(200);
    expect(r.body.result).toBe(0);
  });

  it("CONTROL: user:pass is still refused", async () => {
    const r = await post(node.rpcPort, "/", "getblockcount", {
      Authorization: basic("user", "pass"),
    });
    expect(r.status).toBe(401);
  });
});

// ---------------------------------------------------------------------------
// H5 -- per-request wallet routing
// ---------------------------------------------------------------------------

function fakeWallet() {
  return {
    getBalances: () => ({ trusted: 0n, untrustedPending: 0n, immature: 0n }),
    isPrivateKeysDisabled: () => false,
    getTxHistory: () => [],
    isBlank: () => false,
    isLocked: () => false,
    isEncrypted: () => false,
  };
}

function makeWalletServer(port: number, datadir: string): RPCServer {
  const wallets = new Map<string, unknown>([
    ["alice", fakeWallet()],
    ["bob", fakeWallet()],
  ]);
  const walletManager = {
    getWallet: (n: string) => wallets.get(n),
    getWalletCount: () => wallets.size,
    listWallets: () => [...wallets.keys()],
    getDefaultWallet: () => undefined,
    markDirty: () => {},
  };
  const deps = {
    chainState: { getBestBlock: () => ({ height: 0, hash: Buffer.alloc(32), chainWork: 0n }) },
    mempool: {},
    peerManager: { getConnectedPeers: () => [] },
    feeEstimator: {},
    headerSync: {},
    db: {},
    params: REGTEST,
    walletManager,
  } as unknown as RPCServerDeps;
  const config: RPCServerConfig = {
    port,
    host: "127.0.0.1",
    rpcUser: "testuser",
    rpcPassword: "testpass",
    datadir,
  };
  return new RPCServer(config, deps);
}

/**
 * Send an authenticated POST whose body arrives in two parts. Resolves
 * `sendRest` once the first part is on the wire; the returned promise
 * resolves with the parsed JSON response once the rest is sent.
 */
function stalledPost(
  port: number,
  pathname: string,
  method: string,
  auth: string,
): { headersSent: Promise<void>; sendRest: () => void; response: Promise<any> } {
  const body = JSON.stringify({ jsonrpc: "2.0", id: 1, method, params: [] });
  const head =
    `POST ${pathname} HTTP/1.1\r\n` +
    `Host: 127.0.0.1:${port}\r\n` +
    `Authorization: ${auth}\r\n` +
    `Content-Type: application/json\r\n` +
    `Content-Length: ${Buffer.byteLength(body)}\r\n` +
    `Connection: close\r\n\r\n`;
  const sock = net.createConnection({ host: "127.0.0.1", port });
  let raw = "";
  let resolveSent!: () => void;
  const headersSent = new Promise<void>((r) => (resolveSent = r));
  const response = new Promise<any>((resolve, reject) => {
    sock.on("data", (d) => (raw += d.toString()));
    sock.on("end", () => {
      const payload = raw.slice(raw.indexOf("\r\n\r\n") + 4);
      try {
        resolve(JSON.parse(payload.slice(payload.indexOf("{"), payload.lastIndexOf("}") + 1)));
      } catch (e) {
        reject(new Error(`unparseable response: ${raw}`));
      }
    });
    sock.on("error", reject);
  });
  sock.on("connect", () => {
    sock.write(head + body.slice(0, 10), () => resolveSent());
  });
  return { headersSent, sendRest: () => sock.write(body.slice(10)), response };
}

describe("H5: the wallet route belongs to the request that named it", () => {
  let server: RPCServer;
  let port: number;
  let datadir: string;
  const auth = basic("testuser", "testpass");

  beforeEach(() => {
    datadir = fs.mkdtempSync(path.join(os.tmpdir(), "hotbuns-h5-"));
    port = nextPort++;
    server = makeWalletServer(port, datadir);
    server.start();
  });
  afterEach(() => {
    server.stop();
    fs.rmSync(datadir, { recursive: true, force: true });
  });

  it("an unauthenticated POST /wallet/bob cannot re-route a stalled authenticated /wallet/alice call", async () => {
    const alice = stalledPost(port, "/wallet/alice", "getwalletinfo", auth);
    await alice.headersSent;
    await Bun.sleep(150); // alice's handler is now parked in `await req.json()`
    const bob = await post(port, "/wallet/bob", "getwalletinfo");
    expect(bob.status).toBe(401);
    alice.sendRest();
    const res = await alice.response;
    expect(res.error).toBeUndefined();
    expect(res.result.walletname).toBe("alice");
  });

  it("a concurrent authenticated /wallet/bob call does not re-route /wallet/alice", async () => {
    const alice = stalledPost(port, "/wallet/alice", "getwalletinfo", auth);
    await alice.headersSent;
    await Bun.sleep(150);
    const bob = await post(port, "/wallet/bob", "getwalletinfo", { Authorization: auth });
    expect(bob.status).toBe(200);
    expect(bob.body.result.walletname).toBe("bob");
    alice.sendRest();
    const res = await alice.response;
    expect(res.result.walletname).toBe("alice");
  });

  it("the route survives an await inside the handler while another wallet's request runs", async () => {
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    let entered!: () => void;
    const inside = new Promise<void>((r) => (entered = r));
    server.registerMethod("h5probe", async () => {
      entered();
      await gate;
      return (server as any).getCurrentWalletName();
    });
    const aliceP = post(port, "/wallet/alice", "h5probe", { Authorization: auth });
    await inside;
    const bob = await post(port, "/wallet/bob", "getwalletinfo", { Authorization: auth });
    expect(bob.body.result.walletname).toBe("bob");
    release();
    const alice = await aliceP;
    expect(alice.body.result).toBe("alice");
  });

  it("CONTROL: no /wallet/ segment with two wallets loaded is still -19", async () => {
    const r = await post(port, "/", "getwalletinfo", { Authorization: auth });
    expect(r.body.error.code).toBe(-19);
  });
});
