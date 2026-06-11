/**
 * Fixed-seed last-resort fallback (Core net.cpp:2607-2643 ThreadOpenConnections
 * fixed-seed trigger).
 *
 * hotbuns previously had NO Core-vetted fixed-IP last-resort injection: under
 * -nodnsseed (or when DNS resolution returned nothing) the known-address pool
 * stayed empty and the node could not bootstrap. This wires the curated
 * 40-IP fallback that fires ONLY when DNS produced nothing AND the book is
 * empty — one-shot, layered AFTER the normal DNS bootstrap, never a bypass.
 */

import { describe, expect, test, beforeEach, afterEach } from "bun:test";
import {
  PeerManager,
  type PeerManagerConfig,
  type PeerInfo,
  FIXED_SEEDS,
  isRoutable,
} from "./manager.js";
import { MAINNET, REGTEST } from "../consensus/params.js";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

function makeConfig(
  datadir: string,
  overrides: Partial<PeerManagerConfig> = {}
): PeerManagerConfig {
  return {
    maxOutbound: 8,
    maxInbound: 117,
    params: MAINNET,
    bestHeight: 0,
    datadir,
    // Default: DNS seeding on. Tests override per-case.
    ...overrides,
  };
}

const MAINNET_MAGIC = 0xd9b4bef9;
const REGTEST_MAGIC = 0xdab5bffa;
const TESTNET_MAGIC = 0x0709110b;
const TESTNET4_MAGIC = 0x283f161c;

describe("fixed-seed last-resort fallback", () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "hotbuns-fixedseeds-"));
  });

  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  test("mainnet carries exactly 40 routable IPv4:8333 fixed seeds", () => {
    const seeds = FIXED_SEEDS[MAINNET_MAGIC];
    expect(seeds).toBeDefined();
    expect(seeds.length).toBe(40);

    for (const { host, port } of seeds) {
      // IPv4 dotted-quad
      const parts = host.split(".");
      expect(parts.length).toBe(4);
      for (const p of parts) {
        const n = Number(p);
        expect(Number.isInteger(n)).toBe(true);
        expect(n).toBeGreaterThanOrEqual(0);
        expect(n).toBeLessThanOrEqual(255);
      }
      // Routable (public) per Core addrman.IsRoutable filter
      expect(isRoutable(host)).toBe(true);
      // All on the mainnet P2P port
      expect(port).toBe(8333);
    }

    // No duplicate hosts in the curated set
    const hosts = seeds.map((s) => s.host);
    expect(new Set(hosts).size).toBe(40);
  });

  test("non-mainnet networks carry no fixed seeds (Core clears vFixedSeeds)", () => {
    expect(FIXED_SEEDS[TESTNET_MAGIC] ?? []).toHaveLength(0);
    expect(FIXED_SEEDS[TESTNET4_MAGIC] ?? []).toHaveLength(0);
    expect(FIXED_SEEDS[REGTEST_MAGIC] ?? []).toHaveLength(0);
  });

  test("FIRES on empty book + DNS disabled (-nodnsseed) — immediate", () => {
    const mgr = new PeerManager(makeConfig(tempDir, { dnsSeed: false }));
    expect(mgr.getKnownAddresses().size).toBe(0);

    (mgr as any).maybeAddFixedSeeds();

    const known = mgr.getKnownAddresses();
    expect(known.size).toBe(40);
    // Every injected addr carries the "fixedseeds" provenance tag.
    for (const info of known.values()) {
      expect(info.source).toBe("fixedseeds");
    }
  });

  test("FIRES on empty book after the 60s grace even with DNS enabled", () => {
    const mgr = new PeerManager(makeConfig(tempDir, { dnsSeed: true }));
    expect(mgr.getKnownAddresses().size).toBe(0);

    // Within the grace window, DNS-enabled: must NOT fire yet (wait for DNS).
    (mgr as any).maybeAddFixedSeeds();
    expect(mgr.getKnownAddresses().size).toBe(0);

    // Simulate >60s elapsed since the connection loop anchored.
    (mgr as any).loopStartTs = Date.now() - 61_000;
    (mgr as any).maybeAddFixedSeeds();
    expect(mgr.getKnownAddresses().size).toBe(40);
  });

  test("does NOT fire when the book is non-empty (DNS already populated)", () => {
    const mgr = new PeerManager(makeConfig(tempDir, { dnsSeed: false }));
    // Seed the book with one DNS-learned address.
    const learned: PeerInfo = {
      host: "8.8.4.4",
      port: 8333,
      services: 1n,
      lastSeen: Date.now(),
      banScore: 0,
      lastConnected: 0,
    };
    (mgr as any).addKnownAddress("8.8.4.4:8333", learned);
    expect(mgr.getKnownAddresses().size).toBe(1);

    (mgr as any).maybeAddFixedSeeds();

    // Book non-empty ⇒ fallback suppressed; pool unchanged.
    expect(mgr.getKnownAddresses().size).toBe(1);
    expect(mgr.getKnownAddresses().has("8.8.4.4:8333")).toBe(true);
  });

  test("does NOT fire in -connect (connect-only) mode", () => {
    const mgr = new PeerManager(
      makeConfig(tempDir, { dnsSeed: false, connect: ["192.0.43.7:8333"] })
    );
    expect(mgr.isConnectOnly()).toBe(true);

    (mgr as any).maybeAddFixedSeeds();

    // No fixed seeds injected; only the pinned -connect peer may be present.
    const known = mgr.getKnownAddresses();
    for (const info of known.values()) {
      expect(info.source).not.toBe("fixedseeds");
    }
    expect(
      Array.from(known.values()).some((i) => i.source === "fixedseeds")
    ).toBe(false);
  });

  test("is one-shot — a second tick is a no-op", () => {
    const mgr = new PeerManager(makeConfig(tempDir, { dnsSeed: false }));
    (mgr as any).maybeAddFixedSeeds();
    expect(mgr.getKnownAddresses().size).toBe(40);

    // Even if the book is later cleared, the one-shot guard prevents re-firing.
    (mgr as any).knownAddresses.clear();
    (mgr as any).maybeAddFixedSeeds();
    expect(mgr.getKnownAddresses().size).toBe(0);
  });

  test("does NOT fire on a non-mainnet network (regtest)", () => {
    const mgr = new PeerManager(makeConfig(tempDir, { params: REGTEST, dnsSeed: false }));
    expect(mgr.getKnownAddresses().size).toBe(0);

    (mgr as any).maybeAddFixedSeeds();

    // Regtest FIXED_SEEDS is empty ⇒ nothing injected.
    expect(mgr.getKnownAddresses().size).toBe(0);
  });
});
