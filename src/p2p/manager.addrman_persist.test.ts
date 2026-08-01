/**
 * Regression: the bucketed AddrMan (Core CAddrMan) is the persisted source of
 * truth for peers.dat.
 *
 * Production blocker fixed: saveAddresses()/loadAddresses() used to serialize
 * the FLAT `knownAddresses` map, while the bucketed `addrMan` (used live for
 * feeler select/good/attempt) was NEVER persisted — so the node forgot its
 * NEW/TRIED placement and per-manager nKey salt on every restart (eclipse /
 * bootstrap fragility). The fix wires `addrMan.serialize()` into saveAddresses
 * and restores via `AddrMan.deserialize()` in loadAddresses.
 *
 * Oracle: bitcoin-core/src/addrman.cpp (Save on shutdown / Load on startup).
 *
 * These tests drive the LIVE lifecycle methods (saveAddresses/loadAddresses)
 * through a real on-disk peers.dat in a temp dir — not the AddrMan unit
 * serialize() in isolation (that is covered by addrman_axis2 / w128).
 */

import { describe, expect, test, beforeEach, afterEach } from "bun:test";
import {
  PeerManager,
  type PeerManagerConfig,
  type PeerInfo,
} from "./manager.js";
import { REGTEST } from "../consensus/params.js";
import { mkdtemp, rm, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

/** BIP155 IPv4 network id. */
const NETWORK_IPV4 = 1;

function makeConfig(datadir: string): PeerManagerConfig {
  return {
    maxOutbound: 8,
    maxInbound: 117,
    params: REGTEST,
    bestHeight: 0,
    datadir,
  };
}

/** A routable IPv4 PeerInfo in 8.0.0.0/8 (public, passes isRoutable). */
function makeInfo(i: number, lastSeen: number): PeerInfo {
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

describe("addrman persistence: peers.dat round-trips the bucketed AddrMan", () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "hotbuns-addrman-persist-"));
  });

  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  test("peers.dat is written in the bucketed ADDRMANV2 format (not the flat blob)", async () => {
    const mgr = new PeerManager(makeConfig(tempDir));
    const add = (info: PeerInfo) =>
      (mgr as any).addKnownAddress(`${info.host}:${info.port}`, info);
    for (let i = 0; i < 5; i++) add(makeInfo(i, 1_700_000_000 + i));

    await (mgr as any).saveAddresses();

    const raw = await readFile(join(tempDir, "peers.dat"));
    // The bucketed serializer emits a versioned, line-oriented header.
    expect(raw.toString("utf8").startsWith("ADDRMANV2 ")).toBe(true);
  });

  test("save -> reload restores the learned peer set into a fresh manager", async () => {
    // Manager 1: learn a set of routable peers, then persist. (The bucketed
    // addrman may drop some on NEW-table position collisions — exactly Core
    // CAddrMan Add_ — so we assert the round-trip preserves whatever addrman
    // RETAINED, not the raw input count.)
    const mgr1 = new PeerManager(makeConfig(tempDir));
    const add = (info: PeerInfo) =>
      (mgr1 as any).addKnownAddress(`${info.host}:${info.port}`, info);
    const N = 40;
    for (let i = 0; i < N; i++) add(makeInfo(i, 1_700_000_000 + i));

    const retained = new Set<string>(
      (mgr1 as any).addrMan
        .getEntries(false)
        .concat((mgr1 as any).addrMan.getEntries(true))
        .map((e: { host: string; port: number }) => `${e.host}:${e.port}`),
    );
    const sizeBefore = (mgr1 as any).addrMan.size();
    expect(sizeBefore).toBeGreaterThan(0);
    expect(retained.size).toBe(sizeBefore);

    await (mgr1 as any).saveAddresses();

    // Manager 2: cold construct, load from disk.
    const mgr2 = new PeerManager(makeConfig(tempDir));
    // A fresh manager starts empty (no peers learned yet).
    expect((mgr2 as any).addrMan.size()).toBe(0);
    expect(mgr2.getKnownAddresses().size).toBe(0);

    await (mgr2 as any).loadAddresses();

    // The bucketed addrman is restored from peers.dat with the SAME contents ...
    expect((mgr2 as any).addrMan.size()).toBe(sizeBefore);
    // ... and the flat live store (getaddr / outbound path) is re-hydrated with
    // exactly the persisted set.
    const known = mgr2.getKnownAddresses();
    expect(known.size).toBe(retained.size);
    for (const key of retained) {
      expect(known.has(key)).toBe(true);
    }
  });

  test("nKey salt and NEW/TRIED placement survive the round-trip", async () => {
    const mgr1 = new PeerManager(makeConfig(tempDir));
    const add = (info: PeerInfo) =>
      (mgr1 as any).addKnownAddress(`${info.host}:${info.port}`, info);
    for (let i = 0; i < 20; i++) add(makeInfo(i, 1_700_000_000 + i));

    // Promote one address NEW->TRIED so the round-trip must carry tried state.
    // Use the FIRST-inserted address: it is guaranteed a new-bucket slot (the
    // table was empty at insert time). A later address can lose its (bucket,
    // position) draw to an earlier non-terrible occupant under a random nKey
    // (Core Add_ keeps the incumbent), leaving refCount=0 so good() no-ops —
    // that made this test flake ~1-in-5 runs on makeInfo(3).
    const triedInfo = makeInfo(0, 1_700_000_000);
    (mgr1 as any).addrMan.good(triedInfo.host, triedInfo.port);
    expect((mgr1 as any).addrMan.isInTried(triedInfo.host, triedInfo.port)).toBe(
      true,
    );

    const nKeyBefore = (mgr1 as any).addrMan.getNKey().toString("hex");
    const placeBefore = (mgr1 as any).addrMan.findAddressEntry(
      triedInfo.host,
      triedInfo.port,
    );

    await (mgr1 as any).saveAddresses();

    const mgr2 = new PeerManager(makeConfig(tempDir));
    await (mgr2 as any).loadAddresses();

    // Same per-manager salt => deterministic bucket placement is reproducible.
    expect((mgr2 as any).addrMan.getNKey().toString("hex")).toBe(nKeyBefore);
    // The TRIED promotion is preserved.
    expect((mgr2 as any).addrMan.isInTried(triedInfo.host, triedInfo.port)).toBe(
      true,
    );
    const placeAfter = (mgr2 as any).addrMan.findAddressEntry(
      triedInfo.host,
      triedInfo.port,
    );
    expect(placeAfter).toEqual(placeBefore);
  });

  test("corrupt peers.dat cold-starts cleanly (no throw, empty book)", async () => {
    await Bun.write(join(tempDir, "peers.dat"), "not-a-valid-addrman-file\n");
    const mgr = new PeerManager(makeConfig(tempDir));
    await (mgr as any).loadAddresses(); // must not throw
    expect((mgr as any).addrMan.size()).toBe(0);
    expect(mgr.getKnownAddresses().size).toBe(0);
  });
});
