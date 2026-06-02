/**
 * Tier-A leak-bound regression: knownAddresses (addrman) hard cap + eviction.
 *
 * Root cause: `PeerManager.knownAddresses` is a Map fed by every routable,
 * <3h-stale address in every incoming addr/addrv2 message, with NO cap, NO
 * eviction, and cross-restart persistence (saveAddresses/loadAddresses) — so it
 * (and peers.dat) grew monotonically. Fix: KNOWN_ADDRESSES_MAX = 81920 (Core
 * addrman ceiling), evict oldest-lastSeen on overflow, cap the save+load paths.
 * See CORE-PARITY-AUDIT/_hotbuns-rss-leak-rootcause-2026-06-02.md (Tier A.1).
 */

import { describe, expect, test, beforeEach, afterEach } from "bun:test";
import {
  PeerManager,
  type PeerManagerConfig,
  type PeerInfo,
  KNOWN_ADDRESSES_MAX,
} from "./manager.js";
import { REGTEST } from "../consensus/params.js";

/** BIP155 IPv4 network id (avoids importing the const enum across modules). */
const NETWORK_IPV4 = 1;
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

function makeConfig(datadir: string): PeerManagerConfig {
  return {
    maxOutbound: 8,
    maxInbound: 117,
    params: REGTEST,
    bestHeight: 0,
    datadir,
  };
}

/** A routable PeerInfo at index i with the given lastSeen (ms). */
function makeInfo(i: number, lastSeen: number): PeerInfo {
  // Map i -> a routable IPv4 in 8.0.0.0/8 (public, passes isRoutable).
  const b = (i >>> 16) & 0xff;
  const c = (i >>> 8) & 0xff;
  const d = i & 0xff;
  return {
    host: `8.${b}.${c}.${d}`,
    port: 8333,
    services: 1n,
    lastSeen,
    banScore: 0,
    lastConnected: 0,
    networkId: NETWORK_IPV4,
  };
}

describe("Tier A.1: knownAddresses cap + eviction", () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "hotbuns-knownaddr-"));
  });

  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  test("KNOWN_ADDRESSES_MAX matches Core addrman ceiling (81920)", () => {
    expect(KNOWN_ADDRESSES_MAX).toBe(81920);
  });

  test("addKnownAddress never exceeds the cap under repeated adds", () => {
    const mgr = new PeerManager(makeConfig(tempDir));
    const add = (key: string, info: PeerInfo) =>
      (mgr as any).addKnownAddress(key, info);

    // Insert past the cap with strictly increasing lastSeen. The eviction scan
    // is O(n) and only runs on the (rare) overflow path, so we overflow by a
    // small margin to keep this a fast unit test while still exercising the
    // saturated-cap eviction loop many times.
    const total = KNOWN_ADDRESSES_MAX + 200;
    for (let i = 0; i < total; i++) {
      const info = makeInfo(i, 1_000_000 + i);
      add(`${info.host}:${info.port}`, info);
    }

    const known = mgr.getKnownAddresses();
    expect(known.size).toBe(KNOWN_ADDRESSES_MAX);
  }, 30000);

  test("eviction drops the oldest-lastSeen entry first", () => {
    const mgr = new PeerManager(makeConfig(tempDir));
    const add = (key: string, info: PeerInfo) =>
      (mgr as any).addKnownAddress(key, info);

    // Fill exactly to the cap; entry 0 has the oldest lastSeen.
    for (let i = 0; i < KNOWN_ADDRESSES_MAX; i++) {
      const info = makeInfo(i, 1_000_000 + i);
      add(`${info.host}:${info.port}`, info);
    }
    const oldest = makeInfo(0, 1_000_000);
    const oldestKey = `${oldest.host}:${oldest.port}`;
    expect(mgr.getKnownAddresses().has(oldestKey)).toBe(true);

    // One more (newer) entry forces eviction of the oldest.
    const newer = makeInfo(KNOWN_ADDRESSES_MAX, 2_000_000);
    const newerKey = `${newer.host}:${newer.port}`;
    add(newerKey, newer);

    const known = mgr.getKnownAddresses();
    expect(known.size).toBe(KNOWN_ADDRESSES_MAX);
    expect(known.has(oldestKey)).toBe(false); // oldest evicted
    expect(known.has(newerKey)).toBe(true); // newcomer retained
  }, 30000);

  test("handleAddrMessage ingest path is capped (end-to-end wiring)", () => {
    const mgr = new PeerManager(makeConfig(tempDir));
    const now = Math.floor(Date.now() / 1000);

    // Build a single addr message larger than the cap and feed it straight
    // through the private handler (the gossip-ingest hot path).
    const addrs = [];
    const total = KNOWN_ADDRESSES_MAX + 200;
    for (let i = 0; i < total; i++) {
      const b = (i >>> 16) & 0xff;
      const c = (i >>> 8) & 0xff;
      const d = i & 0xff;
      const ipBuf = Buffer.alloc(16);
      ipBuf[10] = 0xff;
      ipBuf[11] = 0xff;
      ipBuf[12] = 8; // 8.b.c.d — routable
      ipBuf[13] = b;
      ipBuf[14] = c;
      ipBuf[15] = d;
      addrs.push({
        timestamp: now,
        addr: { services: 1n, ip: ipBuf, port: 8333 },
      });
    }

    (mgr as any).handleAddrMessage(undefined, { addrs });

    expect(mgr.getKnownAddresses().size).toBe(KNOWN_ADDRESSES_MAX);
  }, 30000);

  test("saveAddresses + loadAddresses both respect the cap across restart", async () => {
    // Manager 1: stuff the map past the cap, then save.
    const mgr1 = new PeerManager(makeConfig(tempDir));
    const add = (key: string, info: PeerInfo) =>
      (mgr1 as any).addKnownAddress(key, info);
    for (let i = 0; i < KNOWN_ADDRESSES_MAX + 200; i++) {
      const info = makeInfo(i, 1_000_000 + i);
      add(`${info.host}:${info.port}`, info);
    }
    expect(mgr1.getKnownAddresses().size).toBe(KNOWN_ADDRESSES_MAX);
    await (mgr1 as any).saveAddresses();

    // Manager 2: load the persisted file — must not exceed the cap.
    const mgr2 = new PeerManager(makeConfig(tempDir));
    await (mgr2 as any).loadAddresses();
    expect(mgr2.getKnownAddresses().size).toBeLessThanOrEqual(
      KNOWN_ADDRESSES_MAX
    );
  }, 30000);
});
