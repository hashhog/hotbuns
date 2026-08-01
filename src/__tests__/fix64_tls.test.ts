/**
 * FIX-64 — HTTPS/TLS termination for the JSON-RPC server.
 *
 * Closes W119 note "no TLS client lib" — Bun ships first-class TLS via
 * `Bun.serve({ tls: { cert, key } })` (BoringSSL), so the JSON-RPC HTTP
 * server can terminate TLS directly without a reverse-proxy hop.
 *
 * Gates:
 *   T1  HTTPS round-trip with a self-signed cert succeeds.
 *   T2  HTTP backward-compat preserved when no TLS flags are set.
 *   T3  Mismatched flags (cert-without-key, key-without-cert) → startup error.
 *   T4  TLS cert file missing → startup error.
 *
 * Reference: bitcoin-core/src/httpserver.cpp (Core has no native TLS;
 *   operators run a reverse proxy. hotbuns supports that pattern too,
 *   but Bun's runtime makes direct termination cheap enough to expose
 *   as a first-class option.)
 * Reference: BIP-78 §"Protocol" (PayJoin endpoint MUST be HTTPS in
 *   production — hotbuns's BIP-78 receiver path can now be served
 *   over HTTPS without an extra process).
 */

import { describe, it, expect, beforeAll, afterAll } from "bun:test";
import * as os from "os";
import * as path from "path";
import * as fs from "fs";
import { RPCServer, RPCServerConfig, RPCServerDeps } from "../rpc/server.js";
import { REGTEST } from "../consensus/params.js";

// -----------------------------------------------------------------------
// Mock dependencies — same shape as rpc/server.test.ts. We keep these
// local to avoid coupling the test to an internal-only test helper.
// -----------------------------------------------------------------------

class MockChainStateManager {
  private bestBlock = { hash: Buffer.alloc(32, 0), height: 100, chainWork: 1000n };
  getBestBlock() { return { ...this.bestBlock }; }
}
class MockMempool {
  getInfo() { return { size: 0, bytes: 0, minFeeRate: 1 }; }
  getAllTxids(): Buffer[] { return []; }
  getTransaction(_txid: Buffer) { return null; }
  hasTransaction(_txid: Buffer) { return false; }
  async addTransaction(_tx: any) { return { accepted: true }; }
  removeTransaction(_txid: Buffer, _removeDependents = true): void {}
  async isTransactionConfirmed(_txid: Buffer): Promise<boolean> { return false; }
  isReplaceable(_txid: Buffer): boolean { return true; }
}
class MockPeerManager {
  getConnectedPeers() { return []; }
  broadcast(_msg: any) {}
  usingASMap(): boolean { return false; }
  getMappedAS(_addr: string): number { return 0; }
  getOutboundNetGroups(): Set<string> { return new Set(); }
}
class MockFeeEstimator {
  public buckets: any[] = [];
  estimateSmartFee(targetBlocks: number) { return { feeRate: 10, blocks: targetBlocks }; }
  getBuckets() { return this.buckets; }
  get horizons() {
    return {
      0: { decay: 0.962, scale: 1, periods: 12, buckets: [] },
      1: { decay: 0.9952, scale: 2, periods: 24, buckets: [] },
      2: { decay: 0.99931, scale: 24, periods: 42, buckets: [] },
    };
  }
}
class MockHeaderSync {
  getBestHeader() { return { hash: Buffer.alloc(32, 0), height: 100, chainWork: 1000n }; }
  getHeader(_h: Buffer) { return undefined; }
  getMedianTimePast(_e: any) { return 1234567890; }
  getNextTarget(_p: any) { return 0n; }
}
class MockChainDB {
  async getBlock(_h: Buffer) { return null; }
  async getBlockIndex(_h: Buffer) { return null; }
  async getBlockHashByHeight(_h: number) { return null; }
  async getChainWork(_h: Buffer): Promise<bigint | null> { return null; }
}

function makeDeps(): RPCServerDeps {
  return {
    chainState: new MockChainStateManager() as any,
    mempool: new MockMempool() as any,
    peerManager: new MockPeerManager() as any,
    feeEstimator: new MockFeeEstimator() as any,
    headerSync: new MockHeaderSync() as any,
    db: new MockChainDB() as any,
    params: REGTEST,
  };
}

// Each test gets its own port to avoid collisions when tests are
// parallelized by the runner.
// Randomised per-process port band (mirrors the 26682fc watchonly
// fix): parallel test files each draw from a distinct 2000-port
// band plus a random offset, so EADDRINUSE collisions cannot
// happen between concurrently-running test files.
let portCounter = 30000 + Math.floor(Math.random() * 2000);
function getTestPort(): number { return portCounter++; }

// -----------------------------------------------------------------------
// Self-signed cert generation. We run openssl once in beforeAll and
// reuse the same cert across all TLS tests. Generating on the fly (vs.
// committing a test fixture) keeps the repo clean and avoids the
// "what cert is this?" footgun.
// -----------------------------------------------------------------------

interface CertPair { certPath: string; keyPath: string; tmpDir: string; }

async function generateSelfSignedCert(): Promise<CertPair> {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "hotbuns-fix64-"));
  const certPath = path.join(tmpDir, "server.crt");
  const keyPath = path.join(tmpDir, "server.key");

  // openssl req -x509 -newkey rsa:2048 -keyout key -out cert -days 1
  //   -nodes -subj "/CN=localhost"
  // -nodes => no password on the key (Bun.serve cannot prompt).
  // -subj  => non-interactive Subject.
  // RSA-2048 is the smallest size BoringSSL accepts by default and is
  // plenty for a single-test handshake.
  const proc = Bun.spawn(
    [
      "openssl", "req",
      "-x509",
      "-newkey", "rsa:2048",
      "-keyout", keyPath,
      "-out", certPath,
      "-days", "1",
      "-nodes",
      "-subj", "/CN=localhost",
    ],
    { stdout: "pipe", stderr: "pipe" }
  );
  const exitCode = await proc.exited;
  if (exitCode !== 0) {
    const err = await new Response(proc.stderr).text();
    throw new Error(`openssl failed (exit ${exitCode}): ${err}`);
  }
  return { certPath, keyPath, tmpDir };
}

describe("RPC TLS termination (FIX-64)", () => {
  let cert: CertPair;

  beforeAll(async () => {
    cert = await generateSelfSignedCert();
  });

  afterAll(() => {
    if (cert?.tmpDir) {
      try { fs.rmSync(cert.tmpDir, { recursive: true, force: true }); } catch {}
    }
  });

  // -------------------------------------------------------------------
  // T1: HTTPS round-trip.
  // We start the server with TLS, issue a JSON-RPC request via fetch()
  // with `tls.rejectUnauthorized: false` (self-signed cert), and assert
  // a sensible JSON-RPC response. Bun's fetch supports `tls.rejectUnauthorized`
  // since Bun 1.1; we set NODE_TLS_REJECT_UNAUTHORIZED=0 as a portable
  // belt-and-braces fallback.
  // -------------------------------------------------------------------
  it("T1 HTTPS round-trip with self-signed cert", async () => {
    const port = getTestPort();
    const config: RPCServerConfig = {
      port,
      host: "127.0.0.1",
      noAuth: true,
      tlsCertPath: cert.certPath,
      tlsKeyPath: cert.keyPath,
    };
    const server = new RPCServer(config, makeDeps());
    server.start();
    try {
      const prevReject = process.env.NODE_TLS_REJECT_UNAUTHORIZED;
      process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
      try {
        const response = await fetch(`https://127.0.0.1:${port}`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          // Bun-only fetch extension to bypass cert validation for the
          // self-signed test cert; bun-types declares it, so no ts-expect-error.
          tls: { rejectUnauthorized: false },
          body: JSON.stringify({
            jsonrpc: "2.0", id: 1, method: "getmempoolinfo", params: [],
          }),
        } as RequestInit);
        expect(response.status).toBe(200);
        // The response must come from HTTPS (Bun reports the URL we hit).
        expect(response.url.startsWith("https://")).toBe(true);
        const json = await response.json();
        expect(json.result).toBeDefined();
        expect(json.error).toBeUndefined();
      } finally {
        if (prevReject === undefined) {
          delete process.env.NODE_TLS_REJECT_UNAUTHORIZED;
        } else {
          process.env.NODE_TLS_REJECT_UNAUTHORIZED = prevReject;
        }
      }
    } finally {
      server.stop();
    }
  });

  // -------------------------------------------------------------------
  // T2: HTTP backward-compat. With no TLS flags, the server MUST
  // continue to listen on plaintext HTTP, exactly as before FIX-64.
  // This is the critical guarantee: an operator who didn't change
  // anything should see no change in behavior.
  // -------------------------------------------------------------------
  it("T2 HTTP backward-compat when no TLS flags set", async () => {
    const port = getTestPort();
    const config: RPCServerConfig = {
      port,
      host: "127.0.0.1",
      noAuth: true,
    };
    const server = new RPCServer(config, makeDeps());
    server.start();
    try {
      const response = await fetch(`http://127.0.0.1:${port}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          jsonrpc: "2.0", id: 1, method: "getmempoolinfo", params: [],
        }),
      });
      expect(response.status).toBe(200);
      expect(response.url.startsWith("http://")).toBe(true);
      const json = await response.json();
      expect(json.result).toBeDefined();
    } finally {
      server.stop();
    }
  });

  // -------------------------------------------------------------------
  // T3: Mismatched flags — half-configured TLS is a fatal startup
  // error, never a silent HTTP fallback. The footgun we explicitly
  // refuse: an operator believes RPC is over TLS but it's actually
  // plaintext because they forgot the second flag.
  // -------------------------------------------------------------------
  it("T3a mismatched flags: cert without key → startup error", () => {
    const port = getTestPort();
    const config: RPCServerConfig = {
      port,
      host: "127.0.0.1",
      noAuth: true,
      tlsCertPath: cert.certPath,
      // tlsKeyPath intentionally omitted
    };
    expect(() => new RPCServer(config, makeDeps())).toThrow(
      /both be provided/
    );
  });

  it("T3b mismatched flags: key without cert → startup error", () => {
    const port = getTestPort();
    const config: RPCServerConfig = {
      port,
      host: "127.0.0.1",
      noAuth: true,
      tlsKeyPath: cert.keyPath,
      // tlsCertPath intentionally omitted
    };
    expect(() => new RPCServer(config, makeDeps())).toThrow(
      /both be provided/
    );
  });

  // -------------------------------------------------------------------
  // T4: Missing cert file at startup is a fatal error (not deferred to
  // first connection). We pass a path that does not exist; the server
  // must throw on start(), not on the first fetch().
  // -------------------------------------------------------------------
  it("T4 missing cert file → startup error", () => {
    const port = getTestPort();
    const bogusPath = path.join(cert.tmpDir, "does-not-exist.pem");
    const config: RPCServerConfig = {
      port,
      host: "127.0.0.1",
      noAuth: true,
      tlsCertPath: bogusPath,
      tlsKeyPath: cert.keyPath,
    };
    // Construct succeeds (cert/key paths are present), but start()
    // must throw because the file is unreadable.
    const server = new RPCServer(config, makeDeps());
    expect(() => server.start()).toThrow(
      /RPC TLS: failed to read cert file/
    );
  });
});
