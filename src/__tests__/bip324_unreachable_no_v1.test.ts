/**
 * Regression tests: an UNREACHABLE host must NOT trigger the BIP-324 v2→v1
 * fallback or poison the v1-only cache.
 *
 * Bug: PeerManager.connectPeer fell back to v1 (and called markV1Only) on ANY
 * exception from `peer.connect(useV2=true)` — including a TCP connect that never
 * established (refused / timed out). That wasted a second dial on a dead host
 * and, worse, cached the dead host as "v1-only", so a host that is actually
 * v2-capable (once reachable again) would be wrongly dialed v1-first until the
 * cache entry expired.
 *
 * Core parity: V2Transport::ShouldReconnectV1 (net.cpp:1555) returns false
 * unless the session actually got far enough to have SENT v1-header-worth of
 * bytes with NOTHING received — i.e. the TCP connection established and a
 * v1-only peer dropped our v2 garbage. An unreachable host never qualifies.
 *
 * Fix: Peer.tcpEstablished records whether the socket `open` callback fired;
 * connectPeer only falls back to v1 (+ markV1Only) when it did.
 */

import { describe, expect, test, beforeEach, afterEach } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PeerManager, type PeerManagerConfig } from "../p2p/manager.js";
import { Peer, type PeerConfig, type PeerEvents } from "../p2p/peer.js";
import { REGTEST } from "../consensus/params.js";

function peerConfig(port: number): PeerConfig {
  return {
    host: "127.0.0.1",
    port,
    magic: REGTEST.networkMagic,
    protocolVersion: 70016,
    services: 0n,
    userAgent: "/test:0.0.1/",
    bestHeight: 0,
    relay: true,
  };
}

const NOOP_EVENTS: PeerEvents = {
  onConnect: () => {},
  onDisconnect: () => {},
  onMessage: () => {},
  onHandshakeComplete: () => {},
};

/** Bind an ephemeral port then immediately close it, so a subsequent connect
 *  yields a FAST ECONNREFUSED (no 10s connect-timeout wait). */
function refusedPort(): number {
  const l = Bun.listen({
    hostname: "127.0.0.1",
    port: 0,
    socket: { data() {}, open() {} },
  });
  const p = l.port;
  l.stop(true);
  return p;
}

describe("BIP-324: unreachable host does not fall back to v1", () => {
  describe("Peer.tcpEstablished", () => {
    test("stays false when the host is unreachable (refused)", async () => {
      const peer = new Peer(peerConfig(refusedPort()), NOOP_EVENTS);
      await expect(peer.connect(/* useV2 */ true)).rejects.toThrow();
      expect(peer.tcpEstablished).toBe(false);
    });

    test("becomes true once the TCP connection opens", async () => {
      const srv = Bun.listen({
        hostname: "127.0.0.1",
        port: 0,
        socket: { data() {}, open() {} },
      });
      try {
        const peer = new Peer(peerConfig(srv.port), NOOP_EVENTS);
        // v1 path resolves at TCP open (no cipher handshake to await).
        await peer.connect(/* useV2 */ false);
        expect(peer.tcpEstablished).toBe(true);
        peer.disconnect();
      } finally {
        srv.stop(true);
      }
    });
  });

  describe("PeerManager.connectPeer", () => {
    let manager: PeerManager;
    let datadir: string;

    beforeEach(async () => {
      datadir = await mkdtemp(join(tmpdir(), "hotbuns-unreach-"));
      const config: PeerManagerConfig = {
        maxOutbound: 8,
        maxInbound: 117,
        params: REGTEST,
        bestHeight: 0,
        datadir,
        listen: false,
      };
      manager = new PeerManager(config);
    });

    afterEach(async () => {
      await manager.stop();
      await rm(datadir, { recursive: true, force: true });
    });

    test("an unreachable host throws and is NOT marked v1-only (no cache poison)", async () => {
      const port = refusedPort();
      const key = `127.0.0.1:${port}`;

      // v2 is default-on, so connectPeer attempts v2 first.
      await expect(manager.connectPeer("127.0.0.1", port, "full_relay")).rejects.toThrow();

      // The dead host must NOT have been cached as v1-only — that would make a
      // later (reachable) v2-capable peer at this address get dialed v1-first.
      expect(manager.isV1Only(key)).toBe(false);
      // And it must not be left dangling in the connecting set.
      expect((manager as any).connectingPeers.has(key)).toBe(false);
    });
  });
});
