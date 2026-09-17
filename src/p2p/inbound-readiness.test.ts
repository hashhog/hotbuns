/**
 * Inbound P2P readiness — CHARTER "full P2P, outbound AND inbound".
 *
 * Control for QUEUES.md hotbuns item 0. Each requirement has a regtest
 * assertion that does not need mainnet:
 *
 *   (1) configurable bind, default 0.0.0.0 + [::], restrict via --bind
 *   (2) inbound version/verack appears in getpeerinfo with inbound: true
 *   (3) inbound slots are separate from outbound (flood cannot starve sync)
 *   (4) half-open handshake is reaped and frees the slot
 *   (5) inbound peer is served getheaders + getdata (a block) like outbound
 *
 * Negative control: a TCP connect that never sends version is disconnected
 * on the handshake timeout and does not keep occupying an inbound slot.
 */

import { describe, expect, test, beforeEach, afterEach } from "bun:test";
import type { Socket } from "bun";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  PeerManager,
  parseBindSpec,
  DEFAULT_BIND_HOSTS,
  DEFAULT_MAX_CONNECTIONS,
  type PeerManagerConfig,
} from "./manager.js";
import { Peer } from "./peer.js";
import {
  type NetworkMessage,
  MESSAGE_HEADER_SIZE,
  parseHeader,
  deserializeMessage,
  serializeMessage,
  ipv4ToBuffer,
  InvType,
} from "./messages.js";
import { REGTEST } from "../consensus/params.js";
import { HeaderSync } from "../sync/headers.js";
import { BlockSync } from "../sync/blocks.js";
import { ChainDB } from "../storage/database.js";
import { parseArgs } from "../cli/cli.js";
import { startTestRpc } from "../test/rpc-listen.js";
import { getBlockHash } from "../validation/block.js";

const TEST_TIMEOUT = 10_000;
const HANDSHAKE_MS = 250;

async function waitFor(
  condition: () => boolean,
  timeoutMs: number = 3000,
  label = "waitFor",
): Promise<void> {
  const start = Date.now();
  while (!condition()) {
    if (Date.now() - start > timeoutMs) {
      throw new Error(`${label} timeout after ${timeoutMs}ms`);
    }
    await new Promise((r) => setTimeout(r, 10));
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

/** Raw Bitcoin P2P client that dials an already-listening node (inbound). */
class InboundClient {
  socket: Socket<undefined> | null = null;
  recvBuffer: Buffer = Buffer.alloc(0);
  messages: NetworkMessage[] = [];
  closed = false;
  private magic: number;

  constructor(magic: number = REGTEST.networkMagic) {
    this.magic = magic;
  }

  async connect(port: number, host = "127.0.0.1"): Promise<void> {
    this.socket = await Bun.connect({
      hostname: host,
      port,
      socket: {
        data: (_socket, data) => {
          this.recvBuffer = Buffer.concat([this.recvBuffer, Buffer.from(data)]);
          this.processBuffer();
        },
        open: () => {},
        close: () => {
          this.closed = true;
          this.socket = null;
        },
        error: () => {
          this.closed = true;
          this.socket = null;
        },
      },
    });
  }

  private processBuffer(): void {
    while (this.recvBuffer.length >= MESSAGE_HEADER_SIZE) {
      const header = parseHeader(this.recvBuffer);
      if (!header) break;
      const totalLength = MESSAGE_HEADER_SIZE + header.length;
      if (this.recvBuffer.length < totalLength) break;
      const payload = this.recvBuffer.subarray(MESSAGE_HEADER_SIZE, totalLength);
      const msg = deserializeMessage(header, payload);
      this.recvBuffer = this.recvBuffer.subarray(totalLength);
      this.messages.push(msg);
    }
  }

  send(msg: NetworkMessage): void {
    if (!this.socket) throw new Error("not connected");
    this.socket.write(serializeMessage(this.magic, msg));
  }

  sendVersion(): void {
    const now = BigInt(Math.floor(Date.now() / 1000));
    const nonce = BigInt(Math.floor(Math.random() * Number.MAX_SAFE_INTEGER));
    this.send({
      type: "version",
      payload: {
        version: 70016,
        services: 0x0409n,
        timestamp: now,
        addrRecv: {
          services: 0n,
          ip: ipv4ToBuffer("127.0.0.1"),
          port: 0,
        },
        addrFrom: {
          services: 0x0409n,
          ip: ipv4ToBuffer("127.0.0.1"),
          port: 1,
        },
        nonce,
        userAgent: "/inbound-readiness:0.0.1/",
        startHeight: 0,
        relay: true,
      },
    });
  }

  sendVerack(): void {
    this.send({ type: "verack", payload: null });
  }

  async handshake(): Promise<void> {
    this.sendVersion();
    await waitFor(
      () => this.messages.some((m) => m.type === "version"),
      3000,
      "inbound version",
    );
    this.sendVerack();
    await waitFor(
      () => this.messages.some((m) => m.type === "verack"),
      3000,
      "inbound verack",
    );
  }

  close(): void {
    if (this.socket) {
      this.socket.end();
      this.socket = null;
    }
  }
}

/** Outbound-side mock that accepts a dial from the node under test. */
class MockPeerServer {
  private server: ReturnType<typeof Bun.listen> | null = null;
  port = 0;
  received: NetworkMessage[] = [];
  private recvBuffer: Buffer = Buffer.alloc(0);
  private client: Socket<undefined> | null = null;
  handshakeComplete = false;

  async start(): Promise<void> {
    this.server = Bun.listen<undefined>({
      hostname: "127.0.0.1",
      port: 0,
      socket: {
        data: (socket, data) => {
          this.client = socket;
          this.recvBuffer = Buffer.concat([this.recvBuffer, Buffer.from(data)]);
          this.drain();
        },
        open: (socket) => {
          this.client = socket;
        },
        close: () => {
          this.client = null;
        },
        error: () => {
          this.client = null;
        },
      },
    });
    this.port = this.server.port;
  }

  private drain(): void {
    while (this.recvBuffer.length >= MESSAGE_HEADER_SIZE) {
      const header = parseHeader(this.recvBuffer);
      if (!header) break;
      const total = MESSAGE_HEADER_SIZE + header.length;
      if (this.recvBuffer.length < total) break;
      const payload = this.recvBuffer.subarray(MESSAGE_HEADER_SIZE, total);
      const msg = deserializeMessage(header, payload);
      this.recvBuffer = this.recvBuffer.subarray(total);
      this.received.push(msg);
      if (msg.type === "version") {
        const now = BigInt(Math.floor(Date.now() / 1000));
        this.send({
          type: "version",
          payload: {
            version: 70016,
            services: 0x0409n,
            timestamp: now,
            addrRecv: {
              services: 0n,
              ip: ipv4ToBuffer("127.0.0.1"),
              port: 0,
            },
            addrFrom: {
              services: 0x0409n,
              ip: ipv4ToBuffer("127.0.0.1"),
              port: this.port,
            },
            nonce: BigInt(Math.floor(Math.random() * Number.MAX_SAFE_INTEGER)),
            userAgent: "/mock-outbound-target:0.0.1/",
            startHeight: 0,
            relay: true,
          },
        });
        this.send({ type: "verack", payload: null });
      }
      if (msg.type === "verack") this.handshakeComplete = true;
    }
  }

  send(msg: NetworkMessage): void {
    if (!this.client) return;
    this.client.write(serializeMessage(REGTEST.networkMagic, msg));
  }

  stop(): void {
    this.client?.end();
    this.client = null;
    this.server?.stop(true);
    this.server = null;
  }
}

function managerConfig(
  datadir: string,
  extra: Partial<PeerManagerConfig> = {},
): PeerManagerConfig {
  return {
    maxOutbound: 0,
    maxInbound: 8,
    maxOutboundFullRelay: 0,
    maxOutboundBlockRelay: 0,
    params: REGTEST,
    bestHeight: 0,
    datadir,
    listen: true,
    dnsSeed: false,
    port: 0,
    bind: ["127.0.0.1"],
    handshakeTimeoutMs: HANDSHAKE_MS,
    ...extra,
  };
}

async function rpcCall(
  port: number,
  method: string,
  params: unknown[] = [],
): Promise<any> {
  const response = await fetch(`http://127.0.0.1:${port}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  return response.json();
}

describe("parseBindSpec / CLI --bind", () => {
  test("default bind hosts are all-interfaces IPv4 and IPv6, not loopback", () => {
    expect(DEFAULT_BIND_HOSTS).toEqual(["0.0.0.0", "::"]);
    expect(DEFAULT_BIND_HOSTS.includes("127.0.0.1")).toBe(false);
    expect(DEFAULT_BIND_HOSTS.includes("::1")).toBe(false);
  });

  test("parses IPv4, IPv4:port, bracketed IPv6, and bare IPv6", () => {
    expect(parseBindSpec("0.0.0.0", 8333)).toEqual({ host: "0.0.0.0", port: 8333 });
    expect(parseBindSpec("127.0.0.1:8334", 8333)).toEqual({
      host: "127.0.0.1",
      port: 8334,
    });
    expect(parseBindSpec("[::]", 8333)).toEqual({ host: "::", port: 8333 });
    expect(parseBindSpec("[::1]:18444", 8333)).toEqual({ host: "::1", port: 18444 });
    expect(parseBindSpec("::", 8333)).toEqual({ host: "::", port: 8333 });
  });

  test("parseArgs --bind is repeatable and --maxconnections is parsed", () => {
    const result = parseArgs([
      "bun",
      "script.ts",
      "--bind=127.0.0.1",
      "--bind=[::1]",
      "--maxconnections=20",
    ]);
    expect(result.config.bind).toEqual(["127.0.0.1", "[::1]"]);
    expect(result.config.maxConnections).toBe(20);
  });

  test("parseArgs default bind is unset so the listener uses 0.0.0.0 and [::]", () => {
    const result = parseArgs(["bun", "script.ts"]);
    expect(result.config.bind).toBeUndefined();
    expect(result.config.listen).toBe(true);
    expect(result.config.maxConnections ?? DEFAULT_MAX_CONNECTIONS).toBe(125);
  });
});

describe("PeerManager bind addresses", () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "hotbuns-inbound-"));
  });

  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  test("default getBindAddresses is 0.0.0.0 and :: on the listen port", () => {
    const mgr = new PeerManager({
      ...managerConfig(tempDir),
      bind: undefined,
      port: 18444,
      listen: false,
    });
    expect(mgr.getBindAddresses()).toEqual([
      { host: "0.0.0.0", port: 18444 },
      { host: "::", port: 18444 },
    ]);
  });

  test("--bind=127.0.0.1 restricts the listener to loopback", async () => {
    const mgr = new PeerManager(managerConfig(tempDir, { bind: ["127.0.0.1"] }));
    expect(mgr.getBindAddresses()).toEqual([{ host: "127.0.0.1", port: 0 }]);
    await mgr.start();
    try {
      const live = mgr.getListeningBinds();
      expect(live.length).toBeGreaterThanOrEqual(1);
      expect(live.every((b) => b.host === "127.0.0.1")).toBe(true);
      expect(live[0].port).toBeGreaterThan(0);
    } finally {
      await mgr.stop();
    }
  });

  test("default listen binds all interfaces, not loopback", async () => {
    const mgr = new PeerManager(
      managerConfig(tempDir, { bind: undefined, port: 0 }),
    );
    await mgr.start();
    try {
      const live = mgr.getListeningBinds();
      const hosts = live.map((b) => b.host);
      // Bun's IPv6 sockets are often dual-stack (IPV6_V6ONLY=0), so one of
      // 0.0.0.0 / :: may fail with EADDRINUSE after the other succeeds.
      // Either all-interfaces bind satisfies the default; loopback does not.
      expect(hosts.some((h) => h === "0.0.0.0" || h === "::")).toBe(true);
      expect(hosts.includes("127.0.0.1")).toBe(false);
      // Dual-stack [::] (or IPv4 0.0.0.0) must still accept IPv4 clients.
      const port = live[0].port;
      const probe = await Bun.connect({
        hostname: "127.0.0.1",
        port,
        socket: { data() {}, open() {}, close() {}, error() {} },
      });
      probe.end();
    } finally {
      await mgr.stop();
    }
  });
});

describe("inbound handshake, getpeerinfo, serve, limits, half-open reap", () => {
  let tempDir: string;
  let db: ChainDB;
  let mgr: PeerManager;
  let headerSync: HeaderSync;
  let blockSync: BlockSync;
  let rpcPort = 0;
  let rpcStop: (() => void) | null = null;
  const clients: InboundClient[] = [];
  let prevV2Env: string | undefined;

  beforeEach(async () => {
    // Outbound v2 is default-on; the starvation control dials a v1 mock.
    prevV2Env = process.env.HOTBUNS_BIP324_V2;
    process.env.HOTBUNS_BIP324_V2 = "0";
    tempDir = await mkdtemp(join(tmpdir(), "hotbuns-inbound-"));
    db = new ChainDB(tempDir);
    await db.open();
    await db.putBlock(REGTEST.genesisBlockHash, REGTEST.genesisBlock);

    headerSync = new HeaderSync(db, REGTEST);
    headerSync.initGenesis();

    mgr = new PeerManager(
      managerConfig(tempDir, { maxInbound: 2, handshakeTimeoutMs: HANDSHAKE_MS }),
    );
    headerSync.registerWithPeerManager(mgr);
    blockSync = new BlockSync(db, REGTEST, headerSync, mgr);
    blockSync.registerWithPeerManager(mgr);

    const chainState = {
      getBestBlock: () => ({
        hash: REGTEST.genesisBlockHash,
        height: 0,
        chainWork: 1n,
      }),
    };
    const mempool = {
      getInfo: () => ({ size: 0, bytes: 0, minFeeRate: 0 }),
      getAllTxids: () => [],
    };
    const feeEstimator = {};
    const { server, port } = startTestRpc({
      chainState: chainState as any,
      mempool: mempool as any,
      peerManager: mgr as any,
      feeEstimator: feeEstimator as any,
      headerSync: headerSync as any,
      db: db as any,
      params: REGTEST,
    });
    rpcPort = port;
    rpcStop = () => server.stop();

    await mgr.start();
  });

  afterEach(async () => {
    for (const c of clients) c.close();
    clients.length = 0;
    rpcStop?.();
    rpcStop = null;
    await mgr.stop();
    await db.close();
    await rm(tempDir, { recursive: true, force: true });
    if (prevV2Env === undefined) delete process.env.HOTBUNS_BIP324_V2;
    else process.env.HOTBUNS_BIP324_V2 = prevV2Env;
  });

  function listenPort(): number {
    const live = mgr.getListeningBinds();
    expect(live.length).toBeGreaterThan(0);
    return live[0].port;
  }

  async function inboundHandshake(): Promise<InboundClient> {
    const client = new InboundClient();
    clients.push(client);
    await client.connect(listenPort());
    await client.handshake();
    await waitFor(
      () => mgr.getConnectedPeers().some((p) => p.state === "connected"),
      3000,
      "manager connected inbound",
    );
    return client;
  }

  test(
    "inbound version/verack appears in getpeerinfo with inbound:true and is served a block",
    async () => {
      const client = await inboundHandshake();

      const info = await rpcCall(rpcPort, "getpeerinfo");
      expect(info.error).toBeUndefined();
      expect(Array.isArray(info.result)).toBe(true);
      expect(info.result.length).toBeGreaterThanOrEqual(1);
      const inbound = info.result.find((p: { inbound: boolean }) => p.inbound);
      expect(inbound).toBeDefined();
      expect(inbound.inbound).toBe(true);
      expect(inbound.connection_type).toBe("inbound");
      expect(inbound.subver).toBe("/inbound-readiness:0.0.1/");

      client.send({
        type: "getheaders",
        payload: {
          version: 70016,
          locatorHashes: [],
          hashStop: Buffer.alloc(32, 0),
        },
      });
      await waitFor(
        () => client.messages.some((m) => m.type === "headers"),
        3000,
        "served headers",
      );
      const headersMsg = client.messages.find((m) => m.type === "headers");
      expect(headersMsg?.type).toBe("headers");
      if (headersMsg?.type === "headers") {
        expect(headersMsg.payload.headers.length).toBeGreaterThanOrEqual(1);
        const served = getBlockHash(headersMsg.payload.headers[0]);
        expect(served.equals(REGTEST.genesisBlockHash)).toBe(true);
      }

      client.send({
        type: "getdata",
        payload: {
          inventory: [{ type: InvType.MSG_BLOCK, hash: REGTEST.genesisBlockHash }],
        },
      });
      await waitFor(
        () => client.messages.some((m) => m.type === "block"),
        3000,
        "served block",
      );
      const blockMsg = client.messages.find((m) => m.type === "block");
      expect(blockMsg?.type).toBe("block");
      if (blockMsg?.type === "block") {
        expect(getBlockHash(blockMsg.payload.block.header).equals(REGTEST.genesisBlockHash)).toBe(
          true,
        );
      }
    },
    TEST_TIMEOUT,
  );

  test(
    "half-open inbound is reaped on handshake timeout and frees the slot",
    async () => {
      const client = new InboundClient();
      clients.push(client);
      await client.connect(listenPort());
      await waitFor(() => mgr.getInboundCount() === 1, 1000, "slot held");
      expect(mgr.getInboundCount()).toBe(1);

      await sleep(HANDSHAKE_MS + 200);
      await waitFor(() => mgr.getInboundCount() === 0, 1000, "slot freed");
      expect(mgr.getInboundCount()).toBe(0);
      expect(mgr.getConnectedPeers()).toHaveLength(0);

      const info = await rpcCall(rpcPort, "getpeerinfo");
      expect(info.result).toEqual([]);
    },
    TEST_TIMEOUT,
  );

  test(
    "inbound flood cannot starve an outbound slot",
    async () => {
      const target = new MockPeerServer();
      await target.start();
      try {
        await inboundHandshake();
        await inboundHandshake();
        expect(mgr.getInboundCount()).toBe(2);

        const third = new InboundClient();
        clients.push(third);
        await third.connect(listenPort());
        await sleep(50);
        // Full inbound: either rejected or an inbound is evicted. Outbound
        // must remain available either way.
        expect(mgr.getInboundCount()).toBeLessThanOrEqual(2);

        const outbound = await mgr.connectPeer("127.0.0.1", target.port, "full_relay");
        expect(outbound).toBeInstanceOf(Peer);
        await waitFor(
          () => target.handshakeComplete || outbound.state === "connected",
          3000,
          "outbound handshake",
        );
        expect(mgr.getFullRelayCount()).toBe(1);
        expect(mgr.getConnectionType(`${outbound.host}:${outbound.port}`)).toBe(
          "full_relay",
        );
      } finally {
        target.stop();
      }
    },
    TEST_TIMEOUT,
  );
});
