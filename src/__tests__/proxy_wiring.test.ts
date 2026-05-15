/**
 * FIX-56 / W117 BUG-1 — wiring tests for ProxyManager → PeerManager → Peer.
 *
 * Verifies:
 *   1. parseArgs() picks up --proxy / --onion / --i2psam / --cjdnsreachable
 *   2. PeerManager.resolveDialable() filters unreachable networks and
 *      produces the right dialable host string for each BIP-155 type.
 *   3. Peer.connect() dispatches outbound .onion / .b32.i2p connects
 *      through ProxyManager.connect rather than Bun.connect directly.
 *
 * Mocks ProxyManager so we never actually open a TCP connection.
 */

import { describe, it, expect, beforeEach, afterEach, mock } from "bun:test";
import { parseArgs } from "../cli/cli.js";
import { PeerManager } from "../p2p/manager.js";
import { Peer, type PeerConfig, type PeerEvents } from "../p2p/peer.js";
import { ProxyManager } from "../p2p/proxy.js";
import { BIP155Network } from "../p2p/addrv2.js";
import { REGTEST } from "../consensus/params.js";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

// ---------------------------------------------------------------------------
// parseArgs — CLI flag plumbing
// ---------------------------------------------------------------------------

describe("FIX-56: CLI proxy flags", () => {
  it("parses --proxy=host:port", () => {
    const { config } = parseArgs(["bun", "hotbuns", "start", "--proxy=127.0.0.1:9050"]);
    expect(config.proxy).toBe("127.0.0.1:9050");
  });

  it("parses --onion=host:port", () => {
    const { config } = parseArgs(["bun", "hotbuns", "start", "--onion=127.0.0.1:9050"]);
    expect(config.onion).toBe("127.0.0.1:9050");
  });

  it("parses --i2psam=host:port", () => {
    const { config } = parseArgs(["bun", "hotbuns", "start", "--i2psam=127.0.0.1:7656"]);
    expect(config.i2psam).toBe("127.0.0.1:7656");
  });

  it("parses --cjdnsreachable as bare flag", () => {
    const { config } = parseArgs(["bun", "hotbuns", "start", "--cjdnsreachable"]);
    expect(config.cjdnsReachable).toBe(true);
  });

  it("parses --cjdnsreachable=0 as false", () => {
    const { config } = parseArgs(["bun", "hotbuns", "start", "--cjdnsreachable=0"]);
    expect(config.cjdnsReachable).toBe(false);
  });

  it("leaves proxy flags undefined when not set", () => {
    const { config } = parseArgs(["bun", "hotbuns", "start"]);
    expect(config.proxy).toBeUndefined();
    expect(config.onion).toBeUndefined();
    expect(config.i2psam).toBeUndefined();
    expect(config.cjdnsReachable).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// PeerManager.resolveDialable — network reachability + dialable strings
// ---------------------------------------------------------------------------

describe("FIX-56: PeerManager.resolveDialable", () => {
  let datadir: string;

  beforeEach(async () => {
    datadir = await mkdtemp(join(tmpdir(), "hotbuns-fix56-"));
  });

  afterEach(async () => {
    await rm(datadir, { recursive: true, force: true });
  });

  function makeMgr(opts: {
    proxyManager?: ProxyManager | null;
    cjdnsReachable?: boolean;
  } = {}): PeerManager {
    return new PeerManager({
      maxOutbound: 8,
      maxInbound: 117,
      params: REGTEST,
      bestHeight: 0,
      datadir,
      proxyManager: opts.proxyManager ?? null,
      cjdnsReachable: opts.cjdnsReachable ?? false,
    });
  }

  it("returns ipv4 for BIP155 IPV4 regardless of proxy", () => {
    const mgr = makeMgr();
    const r = mgr.resolveDialable({
      host: "8.8.8.8",
      port: 8333,
      services: 1n,
      lastSeen: 0,
      banScore: 0,
      lastConnected: 0,
      networkId: BIP155Network.IPV4,
    });
    expect(r).toEqual({ host: "8.8.8.8", networkType: "ipv4" });
  });

  it("returns null for TorV3 without proxy manager", () => {
    const mgr = makeMgr();
    const r = mgr.resolveDialable({
      host: "deadbeef".repeat(8),
      port: 8333,
      services: 1n,
      lastSeen: 0,
      banScore: 0,
      lastConnected: 0,
      networkId: BIP155Network.TORV3,
      rawAddr: Buffer.alloc(32, 0x01),
    });
    expect(r).toBeNull();
  });

  it("returns .onion string for TorV3 when proxy manager present", () => {
    const fakeProxy = {} as ProxyManager; // Just needs to be non-null
    const mgr = makeMgr({ proxyManager: fakeProxy });
    const pubkey = Buffer.alloc(32, 0x01);
    const r = mgr.resolveDialable({
      host: pubkey.toString("hex"),
      port: 8333,
      services: 1n,
      lastSeen: 0,
      banScore: 0,
      lastConnected: 0,
      networkId: BIP155Network.TORV3,
      rawAddr: pubkey,
    });
    expect(r).not.toBeNull();
    expect(r!.networkType).toBe("onion");
    expect(r!.host).toMatch(/\.onion$/);
    // Tor v3 onion strings are exactly 56 base32 chars + ".onion" = 62 chars
    expect(r!.host.length).toBe(56 + ".onion".length);
  });

  it("returns null for I2P without proxy manager", () => {
    const mgr = makeMgr();
    const r = mgr.resolveDialable({
      host: "abcd".repeat(16),
      port: 0,
      services: 1n,
      lastSeen: 0,
      banScore: 0,
      lastConnected: 0,
      networkId: BIP155Network.I2P,
      rawAddr: Buffer.alloc(32, 0x02),
    });
    expect(r).toBeNull();
  });

  it("returns .b32.i2p string for I2P when proxy manager present", () => {
    const fakeProxy = {} as ProxyManager;
    const mgr = makeMgr({ proxyManager: fakeProxy });
    const hash = Buffer.alloc(32, 0x02);
    const r = mgr.resolveDialable({
      host: hash.toString("hex"),
      port: 0,
      services: 1n,
      lastSeen: 0,
      banScore: 0,
      lastConnected: 0,
      networkId: BIP155Network.I2P,
      rawAddr: hash,
    });
    expect(r).not.toBeNull();
    expect(r!.networkType).toBe("i2p");
    expect(r!.host).toMatch(/\.b32\.i2p$/);
  });

  it("returns null for CJDNS without --cjdnsreachable", () => {
    const cjdnsAddr = Buffer.alloc(16);
    cjdnsAddr[0] = 0xfc; // valid CJDNS prefix
    const mgr = makeMgr();
    const r = mgr.resolveDialable({
      host: cjdnsAddr.toString("hex"),
      port: 8333,
      services: 1n,
      lastSeen: 0,
      banScore: 0,
      lastConnected: 0,
      networkId: BIP155Network.CJDNS,
      rawAddr: cjdnsAddr,
    });
    expect(r).toBeNull();
  });

  it("returns IPv6 string for CJDNS when --cjdnsreachable=true", () => {
    const cjdnsAddr = Buffer.alloc(16);
    cjdnsAddr[0] = 0xfc;
    cjdnsAddr[1] = 0x12;
    const mgr = makeMgr({ cjdnsReachable: true });
    const r = mgr.resolveDialable({
      host: cjdnsAddr.toString("hex"),
      port: 8333,
      services: 1n,
      lastSeen: 0,
      banScore: 0,
      lastConnected: 0,
      networkId: BIP155Network.CJDNS,
      rawAddr: cjdnsAddr,
    });
    expect(r).not.toBeNull();
    expect(r!.networkType).toBe("cjdns");
    // First group is fc12, rest zero
    expect(r!.host.startsWith("fc12:")).toBe(true);
  });

  it("returns null for unknown network IDs", () => {
    const mgr = makeMgr();
    const r = mgr.resolveDialable({
      host: "x",
      port: 0,
      services: 1n,
      lastSeen: 0,
      banScore: 0,
      lastConnected: 0,
      networkId: 99,
    });
    expect(r).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// Peer.connect dispatch — proxy path vs direct path
// ---------------------------------------------------------------------------

describe("FIX-56: Peer.connect dispatches on networkType", () => {
  function makePeerConfig(
    overrides: Partial<PeerConfig> & { networkType?: PeerConfig["networkType"]; proxyManager?: ProxyManager }
  ): PeerConfig {
    return {
      host: "1.2.3.4",
      port: 8333,
      magic: REGTEST.networkMagic,
      protocolVersion: REGTEST.protocolVersion,
      services: REGTEST.services,
      userAgent: REGTEST.userAgent,
      bestHeight: 0,
      relay: true,
      ...overrides,
    };
  }

  it("uses ProxyManager.connect for networkType='onion'", async () => {
    const proxyConnect = mock(async (_h: string, _p: number) => {
      // Return a fake socket-like object with a reload() method.
      const sock: any = {
        reload: mock(() => {}),
        write: () => {},
        end: () => {},
        remoteAddress: "127.0.0.1",
      };
      return sock;
    });

    const fakeProxy = { connect: proxyConnect } as unknown as ProxyManager;
    const events: PeerEvents = {
      onConnect: mock(() => {}),
      onDisconnect: mock(() => {}),
      onMessage: mock(() => {}),
      onHandshakeComplete: mock(() => {}),
    };

    const peer = new Peer(
      makePeerConfig({
        host: "abc.onion",
        port: 8333,
        proxyManager: fakeProxy,
        networkType: "onion",
      }),
      events,
    );

    // Stub sendVersionMessage so we don't actually serialize/send.
    (peer as any).sendVersionMessage = mock(() => {});
    (peer as any).flushV2SendBuffer = mock(() => {});

    await peer.connect(/* useV2 */ false);

    expect(proxyConnect).toHaveBeenCalledTimes(1);
    const onionCall = proxyConnect.mock.calls[0] as unknown as [string, number];
    expect(onionCall[0]).toBe("abc.onion");
    expect(onionCall[1]).toBe(8333);
    expect(events.onConnect).toHaveBeenCalledTimes(1);
    expect((peer as any).sendVersionMessage).toHaveBeenCalledTimes(1);
    expect(peer.state).toBe("handshaking");

    peer.disconnect();
  });

  it("uses ProxyManager.connect for networkType='i2p'", async () => {
    const proxyConnect = mock(async () => {
      const sock: any = { reload: mock(() => {}), write: () => {}, end: () => {} };
      return sock;
    });
    const fakeProxy = { connect: proxyConnect } as unknown as ProxyManager;
    const events: PeerEvents = {
      onConnect: mock(() => {}),
      onDisconnect: mock(() => {}),
      onMessage: mock(() => {}),
      onHandshakeComplete: mock(() => {}),
    };

    const peer = new Peer(
      makePeerConfig({
        host: "abcd.b32.i2p",
        port: 0,
        proxyManager: fakeProxy,
        networkType: "i2p",
      }),
      events,
    );
    (peer as any).sendVersionMessage = mock(() => {});

    await peer.connect(false);

    expect(proxyConnect).toHaveBeenCalledTimes(1);
    const i2pCall = proxyConnect.mock.calls[0] as unknown as [string, number];
    expect(i2pCall[0]).toBe("abcd.b32.i2p");

    peer.disconnect();
  });

  it("does NOT use ProxyManager for networkType='ipv4' (clearnet)", async () => {
    // Use a localhost echo to confirm the direct path is selected.  We
    // create a Bun.listen-ing server, point the Peer at it, and require
    // that proxyManager.connect is NEVER invoked.
    const echo = Bun.listen<undefined>({
      hostname: "127.0.0.1",
      port: 0,
      socket: {
        data: (s, d) => { s.write(d); },
        open: () => {},
        close: () => {},
        error: () => {},
      },
    });

    try {
      const proxyConnect = mock(async () => {
        throw new Error("ProxyManager.connect must not be called for ipv4");
      });
      const fakeProxy = { connect: proxyConnect } as unknown as ProxyManager;
      const events: PeerEvents = {
        onConnect: mock(() => {}),
        onDisconnect: mock(() => {}),
        onMessage: mock(() => {}),
        onHandshakeComplete: mock(() => {}),
      };

      const peer = new Peer(
        makePeerConfig({
          host: "127.0.0.1",
          port: echo.port,
          proxyManager: fakeProxy, // Present but should not be used
          networkType: "ipv4",
        }),
        events,
      );
      (peer as any).sendVersionMessage = mock(() => {});

      await peer.connect(false);

      expect(proxyConnect).toHaveBeenCalledTimes(0);
      // The Bun.connect path resolved — onConnect should have been emitted.
      expect(events.onConnect).toHaveBeenCalledTimes(1);

      peer.disconnect();
    } finally {
      echo.stop();
    }
  });

  it("falls back to direct connect when proxyManager is undefined", async () => {
    const echo = Bun.listen<undefined>({
      hostname: "127.0.0.1",
      port: 0,
      socket: {
        data: (s, d) => { s.write(d); },
        open: () => {},
        close: () => {},
        error: () => {},
      },
    });

    try {
      const events: PeerEvents = {
        onConnect: mock(() => {}),
        onDisconnect: mock(() => {}),
        onMessage: mock(() => {}),
        onHandshakeComplete: mock(() => {}),
      };

      // .onion address + networkType=onion, but no proxyManager → direct.
      const peer = new Peer(
        makePeerConfig({
          host: "127.0.0.1",
          port: echo.port,
          networkType: "onion",
          // proxyManager: undefined
        }),
        events,
      );
      (peer as any).sendVersionMessage = mock(() => {});

      await peer.connect(false);
      expect(events.onConnect).toHaveBeenCalledTimes(1);
      peer.disconnect();
    } finally {
      echo.stop();
    }
  });
});
