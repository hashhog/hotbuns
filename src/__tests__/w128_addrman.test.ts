/**
 * W128 — AddrMan + connman + peer selection audit (hotbuns).
 *
 * Reference:
 *   - bitcoin-core/src/addrman.cpp + addrman.h + addrman_impl.h
 *   - bitcoin-core/src/net.cpp ThreadOpenConnections
 *   - bitcoin-core/src/banman.cpp + banman.h
 *   - bitcoin-core/src/util/asmap.cpp
 *
 * 30 audit gates, classified PRESENT / PARTIAL / MISSING.
 *
 * ==========================================================================
 * AXIS #2 UPDATE (bucketed addrman landed). The original W128 audit found
 * "hotbuns has NO AddrMan in the Core sense" — a flat `Map<string, PeerInfo>`
 * with no bucketing. That gap is now CLOSED by the full Core CAddrMan in
 * `src/p2p/addrman.ts` (NEW[1024][64] + TRIED[256][64] + nKey salt +
 * GetNewBucket/GetTriedBucket/GetBucketPosition + Add/Good/Select +
 * tried-collision-evict + IsTerrible + versioned, corrupt-safe, bounded
 * peers.dat round-trip preserving placement). Mirrors blockbrew 6c5a463 /
 * rustoshi 361d81b.
 *
 * The bucket-structure gates below (G1..G14, the new-vs-tried split, the
 * eviction lifecycle, IsTerrible, getaddr filtering, bucketed peers.dat) have
 * been FLIPPED from "assert ABSENT" to "assert PRESENT + Core-correct" against
 * the new `addrman.ts` module. The remaining gates that target manager.ts's
 * connman / ThreadOpenConnections behaviour (feeler scheduling, nTries caps,
 * discouragement bloom, etc.) are unchanged — those are separate axes the
 * bucketed addrman does not touch.
 * ==========================================================================
 *
 * Running: bun test src/__tests__/w128_addrman.test.ts
 */

import { describe, it, expect } from "bun:test";
import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

import {
  getNetGroup,
  isLocalAddress,
  isRoutable,
  MAX_OUTBOUND_FULL_RELAY,
  MAX_OUTBOUND_BLOCK_RELAY,
  MAX_BLOCK_RELAY_ONLY_ANCHORS,
  MAX_FEELER_CONNECTIONS,
  FEELER_INTERVAL_MS,
  MAX_ADDR_TO_SEND,
  MAX_PCT_ADDR_TO_SEND,
  PeerManager,
} from "../p2p/manager.js";
import { REGTEST as REGTEST_W128 } from "../consensus/params.js";
import { DEFAULT_BAN_TIME } from "../p2p/banman.js";
import {
  AddrMan,
  ADDRMAN_NEW_BUCKET_COUNT,
  ADDRMAN_TRIED_BUCKET_COUNT,
  ADDRMAN_BUCKET_SIZE,
  ADDRMAN_NEW_BUCKETS_PER_ADDRESS,
  ADDRMAN_NEW_BUCKETS_PER_SOURCE_GROUP,
  ADDRMAN_TRIED_BUCKETS_PER_GROUP,
  ADDRMAN_HORIZON_SECS,
  ADDRMAN_RETRIES,
  ADDRMAN_MAX_FAILURES,
  ADDRMAN_CEILING,
  isTerrible,
  type AddrInfo,
} from "../p2p/addrman.js";

// ---------------------------------------------------------------------------
// Source-level fixtures.  Tests load the .ts source verbatim and grep for
// patterns rather than execute live network code (no socket binds in CI).
// ---------------------------------------------------------------------------

const __dirname = dirname(fileURLToPath(import.meta.url));
const SRC = resolve(__dirname, "..");
const MANAGER_SRC = readFileSync(resolve(SRC, "p2p", "manager.ts"), "utf8");
const BANMAN_SRC = readFileSync(resolve(SRC, "p2p", "banman.ts"), "utf8");
const PEER_SRC = readFileSync(resolve(SRC, "p2p", "peer.ts"), "utf8");
// AXIS #2: the bucketed addrman now lives in addrman.ts.
const ADDRMAN_SRC = readFileSync(resolve(SRC, "p2p", "addrman.ts"), "utf8");

// Fixed salt for deterministic placement in the flipped behavioural gates.
const W128_KEY = Buffer.from(
  "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
  "hex",
);
const W128_NOW = 1_700_000_000;
function mkAddrMan(): AddrMan {
  return new AddrMan({ nKey: W128_KEY, rngSeed: 1n });
}

// =============================================================================
// G1 — Tried table (256 buckets × 64 positions) — FIXED (was BUG-1)
// =============================================================================
describe("W128-G1: Tried table exists with 256 buckets × 64 positions — FIXED (axis #2)", () => {
  it("FIXED-1: ADDRMAN_TRIED_BUCKET_COUNT === 256 constant present", () => {
    expect(ADDRMAN_SRC).toMatch(/ADDRMAN_TRIED_BUCKET_COUNT/);
    expect(ADDRMAN_TRIED_BUCKET_COUNT).toBe(256);
  });
  it("FIXED-1: vvTried 2D structure exists with 256 buckets × 64 positions", () => {
    expect(ADDRMAN_SRC).toMatch(/vvTried/);
    const am = mkAddrMan();
    const internal = am as unknown as { vvTried: Int32Array[] };
    expect(internal.vvTried.length).toBe(256);
    expect(internal.vvTried[0]!.length).toBe(ADDRMAN_BUCKET_SIZE);
  });
  it("FIXED-1: addrman is bucketed (no longer a single flat Map)", () => {
    expect(ADDRMAN_SRC).toMatch(/vvNew/);
    expect(ADDRMAN_SRC).toMatch(/vvTried/);
  });
});

// =============================================================================
// G2 — New table (1024 buckets × 64 positions) — FIXED (was BUG-2)
// =============================================================================
describe("W128-G2: New table exists with 1024 buckets × 64 positions — FIXED (axis #2)", () => {
  it("FIXED-2: ADDRMAN_NEW_BUCKET_COUNT === 1024 constant present", () => {
    expect(ADDRMAN_SRC).toMatch(/ADDRMAN_NEW_BUCKET_COUNT/);
    expect(ADDRMAN_NEW_BUCKET_COUNT).toBe(1024);
  });
  it("FIXED-2: vvNew 2D structure exists with 1024 buckets × 64 positions", () => {
    expect(ADDRMAN_SRC).toMatch(/vvNew/);
    const am = mkAddrMan();
    const internal = am as unknown as { vvNew: Int32Array[] };
    expect(internal.vvNew.length).toBe(1024);
    expect(internal.vvNew[0]!.length).toBe(ADDRMAN_BUCKET_SIZE);
  });
});

// =============================================================================
// G3 — Secret nKey (256-bit) bucket seed — FIXED (was BUG-3)
// =============================================================================
describe("W128-G3: Secret nKey (256-bit) seeds bucket selection — FIXED (axis #2)", () => {
  it("FIXED-3: nKey field exists and is 256-bit (32 bytes)", () => {
    expect(ADDRMAN_SRC).toMatch(/\bnKey\b/);
    const am = mkAddrMan();
    expect(am.getNKey().length).toBe(32);
  });
  it("FIXED-3: a 256-bit secret is randomly generated when none is supplied", () => {
    expect(ADDRMAN_SRC).toMatch(/randomBytes\(32\)/);
    const a = new AddrMan();
    const b = new AddrMan();
    // Two fresh managers get distinct random salts.
    expect(a.getNKey().equals(b.getNKey())).toBe(false);
  });
  it("FIXED-3: the salt actually moves placement (different nKey -> different slot)", () => {
    const a = mkAddrMan();
    const b = new AddrMan({ nKey: Buffer.alloc(32, 0xab), rngSeed: 1n });
    a.add("203.0.113.5", 8333, "198.51.100.1", 1n, W128_NOW, W128_NOW);
    b.add("203.0.113.5", 8333, "198.51.100.1", 1n, W128_NOW, W128_NOW);
    const sa = a.newSlotOf("203.0.113.5", 8333)!;
    const sb = b.newSlotOf("203.0.113.5", 8333)!;
    expect(sa.bucket !== sb.bucket || sa.position !== sb.position).toBe(true);
  });
});

// =============================================================================
// G4 — GetTriedBucket(nKey, netgroup) — FIXED (was BUG-4)
// =============================================================================
describe("W128-G4: GetTriedBucket(nKey, netgroup) bucket assignment — FIXED (axis #2)", () => {
  it("FIXED-4: getTriedBucket function present and in-range [0,256)", () => {
    expect(ADDRMAN_SRC).toMatch(/getTriedBucket/);
    const am = mkAddrMan();
    const tb = am.getTriedBucket({ host: "8.8.8.8", port: 8333 }, Buffer.from("ipv4:8.8"));
    expect(tb).toBeGreaterThanOrEqual(0);
    expect(tb).toBeLessThan(256);
  });
  it("FIXED-4: tried bucket is deterministic for a fixed key", () => {
    const am = mkAddrMan();
    const g = Buffer.from("ipv4:8.8");
    expect(am.getTriedBucket({ host: "8.8.8.8", port: 8333 }, g)).toBe(
      mkAddrMan().getTriedBucket({ host: "8.8.8.8", port: 8333 }, g),
    );
  });
});

// =============================================================================
// G5 — GetNewBucket(nKey, source, netgroup) — FIXED (was BUG-5)
// =============================================================================
describe("W128-G5: GetNewBucket(nKey, source, netgroup) bucket assignment — FIXED (axis #2)", () => {
  it("FIXED-5: getNewBucket function present and in-range [0,1024)", () => {
    expect(ADDRMAN_SRC).toMatch(/getNewBucket/);
    const am = mkAddrMan();
    const nb = am.getNewBucket(Buffer.from("ipv4:203.0"), Buffer.from("ipv4:198.51"));
    expect(nb).toBeGreaterThanOrEqual(0);
    expect(nb).toBeLessThan(1024);
  });
  it("FIXED-5: the source group IS folded into the new-bucket selection", () => {
    const am = mkAddrMan();
    const addrGroup = Buffer.from("ipv4:203.0");
    // Two different source groups -> (overwhelmingly) different buckets.
    const buckets = new Set<number>();
    for (let i = 1; i <= 20; i++) {
      buckets.add(am.getNewBucket(addrGroup, Buffer.from(`ipv4:10.${i}`)));
    }
    expect(buckets.size).toBeGreaterThan(5);
  });
});

// =============================================================================
// G6 — GetBucketPosition(nKey, fNew, bucket) — FIXED (was BUG-6)
// =============================================================================
describe("W128-G6: GetBucketPosition(nKey, fNew, bucket) position-in-bucket — FIXED (axis #2)", () => {
  it("FIXED-6: getBucketPosition function present and in-range [0,64)", () => {
    expect(ADDRMAN_SRC).toMatch(/getBucketPosition/);
    const am = mkAddrMan();
    const p = am.getBucketPosition(true, 5, { host: "8.8.8.8", port: 8333 });
    expect(p).toBeGreaterThanOrEqual(0);
    expect(p).toBeLessThan(64);
  });
});

// =============================================================================
// G7 — ADDRMAN_NEW_BUCKETS_PER_ADDRESS=8 — FIXED (was BUG-7)
// =============================================================================
describe("W128-G7: ADDRMAN_NEW_BUCKETS_PER_ADDRESS=8 multi-bucket replication — FIXED (axis #2)", () => {
  it("FIXED-7: refCount / multi-bucket replication exists", () => {
    expect(ADDRMAN_SRC).toMatch(/refCount/);
    expect(ADDRMAN_NEW_BUCKETS_PER_ADDRESS).toBe(8);
  });
  it("FIXED-7: an address can occupy up to 8 new buckets (multiplicity cap)", () => {
    const am = mkAddrMan();
    const internal = am as unknown as { rng: { range(n: number): number } };
    internal.rng.range = () => 0; // open the 2^refCount stochastic gate (test)
    for (let i = 0; i < 50; i++) {
      am.add("8.8.8.8", 8333, `10.${i & 0xff}.${(i >> 8) & 0xff}.1`, 1n, W128_NOW + i, W128_NOW + i);
    }
    const entry = am.findAddressEntry("8.8.8.8", 8333)!;
    expect(entry.multiplicity).toBeGreaterThan(1);
    expect(entry.multiplicity).toBeLessThanOrEqual(8);
  });
});

// =============================================================================
// G8 — nAttempts / m_last_try / m_last_success — FIXED (was BUG-8)
// =============================================================================
describe("W128-G8: nAttempts / m_last_try / m_last_success tracking — FIXED (axis #2)", () => {
  it("FIXED-8: AddrInfo tracks attempts / lastTry / lastSuccess", () => {
    expect(ADDRMAN_SRC).toMatch(/attempts/);
    expect(ADDRMAN_SRC).toMatch(/lastTry/);
    expect(ADDRMAN_SRC).toMatch(/lastSuccess/);
  });
  it("FIXED-8: attempt() bumps nAttempts and stamps lastTry (not banScore)", () => {
    const am = mkAddrMan();
    am.add("8.8.8.8", 8333, "1.2.3.4", 1n, W128_NOW, W128_NOW);
    am.attempt("8.8.8.8", 8333, W128_NOW + 500);
    const internal = am as unknown as { mapInfo: Map<number, AddrInfo>; mapAddr: Map<string, number> };
    const id = internal.mapAddr.get("8.8.8.8:8333")!;
    const info = internal.mapInfo.get(id)!;
    expect(info.attempts).toBe(1);
    expect(info.lastTry).toBe(W128_NOW + 500);
  });
  it("FIXED-8: good() stamps lastSuccess and resets attempts", () => {
    const am = mkAddrMan();
    am.add("8.8.8.8", 8333, "1.2.3.4", 1n, W128_NOW, W128_NOW);
    am.attempt("8.8.8.8", 8333, W128_NOW + 500);
    am.good("8.8.8.8", 8333, W128_NOW + 1000);
    const internal = am as unknown as { mapInfo: Map<number, AddrInfo>; mapAddr: Map<string, number> };
    const info = internal.mapInfo.get(internal.mapAddr.get("8.8.8.8:8333")!)!;
    expect(info.lastSuccess).toBe(W128_NOW + 1000);
    expect(info.attempts).toBe(0);
  });
});

// =============================================================================
// G9 — IsTerrible() — FIXED (was BUG-9)
// =============================================================================
describe("W128-G9: IsTerrible(): horizon=30d, future-skew=10min, retry rules — FIXED (axis #2)", () => {
  it("FIXED-9: isTerrible function present", () => {
    expect(ADDRMAN_SRC).toMatch(/isTerrible|IsTerrible/);
  });
  it("FIXED-9: 30-day horizon constant present and enforced", () => {
    expect(ADDRMAN_HORIZON_SECS).toBe(30 * 24 * 60 * 60);
    const base: AddrInfo = {
      host: "8.8.8.8", port: 8333, services: 0n, source: "x",
      nTime: W128_NOW, lastSuccess: 0, lastTry: W128_NOW - 3600,
      attempts: 0, refCount: 1, inTried: false,
    };
    expect(isTerrible({ ...base, nTime: W128_NOW - (31 * 24 * 60 * 60) }, W128_NOW)).toBe(true);
  });
  it("FIXED-9: future-skew (now + 10min) marks an entry terrible", () => {
    const base: AddrInfo = {
      host: "8.8.8.8", port: 8333, services: 0n, source: "x",
      nTime: W128_NOW, lastSuccess: 0, lastTry: W128_NOW - 3600,
      attempts: 0, refCount: 1, inTried: false,
    };
    expect(isTerrible({ ...base, nTime: W128_NOW + 11 * 60 }, W128_NOW)).toBe(true);
  });
  it("FIXED-9: ADDRMAN_RETRIES=3 / ADDRMAN_MAX_FAILURES=10 constants present", () => {
    expect(ADDRMAN_SRC).toMatch(/ADDRMAN_RETRIES/);
    expect(ADDRMAN_SRC).toMatch(/ADDRMAN_MAX_FAILURES/);
    expect(ADDRMAN_RETRIES).toBe(3);
    expect(ADDRMAN_MAX_FAILURES).toBe(10);
  });
});

// =============================================================================
// G10 — Select uses bucketed random sampling, not predictable sort — FIXED
// =============================================================================
describe("W128-G10: Select() is bucketed random sampling (not predictable sort) — FIXED (axis #2)", () => {
  it("FIXED-10: select() exists and walks the bucket tables", () => {
    expect(ADDRMAN_SRC).toMatch(/select\(/);
    expect(ADDRMAN_SRC).toMatch(/searchTried/);
  });
  it("FIXED-10: select() returns a stored entry from the bucketed tables", () => {
    const am = mkAddrMan();
    am.add("8.8.8.8", 8333, "1.2.3.4", 1n, W128_NOW, W128_NOW);
    const s = am.select(false);
    expect(s).not.toBeNull();
    expect(s!.host).toBe("8.8.8.8");
  });
  it("FIXED-10: empty manager select() returns null (bounded, no infinite loop)", () => {
    expect(mkAddrMan().select(false)).toBeNull();
  });
});

// =============================================================================
// G11 — Add: nTime update + bounded ceiling — FIXED (was BUG-11)
// =============================================================================
describe("W128-G11: AddSingle: nTime update on re-advertisement + bounded — FIXED (axis #2)", () => {
  it("FIXED-11: re-adding with a newer nTime updates the entry's nTime", () => {
    const am = mkAddrMan();
    am.add("8.8.8.8", 8333, "1.2.3.4", 1n, W128_NOW, W128_NOW);
    am.add("8.8.8.8", 8333, "1.2.3.4", 1n, W128_NOW + 7200, W128_NOW + 7200);
    const internal = am as unknown as { mapInfo: Map<number, AddrInfo>; mapAddr: Map<string, number> };
    const info = internal.mapInfo.get(internal.mapAddr.get("8.8.8.8:8333")!)!;
    expect(info.nTime).toBe(W128_NOW + 7200);
  });
  it("FIXED-11: re-adding merges (ORs) service flags", () => {
    const am = mkAddrMan();
    am.add("8.8.8.8", 8333, "1.2.3.4", 1n, W128_NOW, W128_NOW);
    am.add("8.8.8.8", 8333, "1.2.3.4", 0b1000n, W128_NOW + 7200, W128_NOW + 7200);
    const internal = am as unknown as { mapInfo: Map<number, AddrInfo>; mapAddr: Map<string, number> };
    const info = internal.mapInfo.get(internal.mapAddr.get("8.8.8.8:8333")!)!;
    expect(info.services).toBe(0b1001n);
  });
});

// =============================================================================
// G12 — AddSingle: 2^nRefCount stochastic admission — FIXED (was BUG-12)
// =============================================================================
describe("W128-G12: AddSingle: 2^nRefCount stochastic admission test — FIXED (axis #2)", () => {
  it("FIXED-12: the 2^refCount stochastic multiplicity gate is present", () => {
    expect(ADDRMAN_SRC).toMatch(/1 << info\.refCount/);
    expect(ADDRMAN_SRC).toMatch(/this\.rng\.range\(factor\)/);
  });
  it("FIXED-12: a closed gate (range != 0) blocks the multiplicity increase", () => {
    const am = mkAddrMan();
    am.add("8.8.8.8", 8333, "1.2.3.4", 1n, W128_NOW, W128_NOW);
    const before = am.findAddressEntry("8.8.8.8", 8333)!.multiplicity;
    const internal = am as unknown as { rng: { range(n: number): number } };
    internal.rng.range = () => 1; // always fail the gate
    am.add("8.8.8.8", 8333, "9.9.9.9", 1n, W128_NOW + 1, W128_NOW + 1);
    expect(am.findAddressEntry("8.8.8.8", 8333)!.multiplicity).toBe(before);
  });
});

// =============================================================================
// G13 — Good(): tried-collision eviction back to NEW — FIXED (was BUG-13)
// =============================================================================
describe("W128-G13: Good(): tried-collision evicts occupant back to NEW — FIXED (axis #2)", () => {
  it("FIXED-13: good() promotes NEW -> TRIED", () => {
    const am = mkAddrMan();
    am.add("8.8.8.8", 8333, "1.2.3.4", 1n, W128_NOW, W128_NOW);
    expect(am.good("8.8.8.8", 8333, W128_NOW)).toBe(true);
    expect(am.isInTried("8.8.8.8", 8333)).toBe(true);
    expect(am.triedCount()).toBe(1);
    expect(am.newCount()).toBe(0);
  });
  it("FIXED-13: a tried-slot collision evicts the prior occupant back to NEW", () => {
    const am = mkAddrMan();
    const addrGroup = (h: string) =>
      Buffer.from(`ipv4:${h.split(".").slice(0, 2).join(".")}`);
    const slotKey = (h: string) => {
      const info = { host: h, port: 8333 };
      const tb = am.getTriedBucket(info, addrGroup(h));
      return `${tb}:${am.getBucketPosition(false, tb, info)}`;
    };
    const seen = new Map<string, string>();
    let aHost = "", bHost = "";
    for (let i = 1; i < 4000 && (aHost === "" || bHost === ""); i++) {
      const h = `10.0.${(i >> 8) & 0xff}.${i & 0xff}`;
      if (h.endsWith(".0") || h.endsWith(".255")) continue;
      const k = slotKey(h);
      const prev = seen.get(k);
      if (prev) { aHost = prev; bHost = h; break; }
      seen.set(k, h);
    }
    expect(aHost).not.toBe("");
    am.add(aHost, 8333, "1.2.3.4", 1n, W128_NOW, W128_NOW);
    am.good(aHost, 8333, W128_NOW);
    am.add(bHost, 8333, "1.2.3.4", 1n, W128_NOW, W128_NOW);
    am.good(bHost, 8333, W128_NOW);
    expect(am.isInTried(bHost, 8333)).toBe(true);
    expect(am.isInTried(aHost, 8333)).toBe(false);
    expect(am.newSlotOf(aHost, 8333)).not.toBeNull(); // evicted back to NEW
  });
});

// =============================================================================
// G14 — Select: 50/50 new/tried bias + new_only branch — FIXED (was BUG-14)
// =============================================================================
describe("W128-G14: Select: 50/50 new/tried + new_only branch — FIXED (axis #2)", () => {
  it("FIXED-14: searchTried / newOnly branch present", () => {
    expect(ADDRMAN_SRC).toMatch(/searchTried/);
    expect(ADDRMAN_SRC).toMatch(/newOnly/);
  });
  it("FIXED-14: 50/50 new-vs-tried coin flip present", () => {
    expect(ADDRMAN_SRC).toMatch(/this\.rng\.range\(2\) === 0/);
  });
  it("FIXED-14: newOnly select excludes a promoted (tried-only) address", () => {
    const am = mkAddrMan();
    am.add("8.8.8.8", 8333, "1.2.3.4", 1n, W128_NOW, W128_NOW);
    am.good("8.8.8.8", 8333, W128_NOW); // -> tried
    expect(am.select(true)).toBeNull(); // new table empty
    expect(am.select(false)).not.toBeNull(); // tried available
  });
});

// =============================================================================
// G15 — Select: per-network filter — PARTIAL (BUG-15)
// =============================================================================
describe("W128-G15: Select: per-network filter via reachable_nets — PARTIAL (BUG-15)", () => {
  it("PASS: getCandidateAddresses filters unreachable networks (BUG-5 W117 fix)", () => {
    // resolveDialable returns null for unreachable network IDs;
    // getCandidateAddresses skips those entries.
    expect(MANAGER_SRC).toMatch(/this\.resolveDialable\(info\) === null/);
  });
  it("BUG-15: no positive per-network selection (extra-network peer)", () => {
    // Core picks a peer from an under-represented network every ~5min.
    // hotbuns has cjdnsReachable + proxy presence but no
    // MaybePickPreferredNetwork-equivalent.
    expect(MANAGER_SRC).not.toMatch(/preferredNet|preferred_net|MaybePickPreferredNetwork/);
    expect(MANAGER_SRC).not.toMatch(/EXTRA_NETWORK_PEER_INTERVAL/);
  });
});

// =============================================================================
// G16 — nTries=100 cap inside fillConnections — MISSING (BUG-16)
// =============================================================================
describe("W128-G16: nTries=100 cap inside ThreadOpenConnections inner loop — MISSING (BUG-16)", () => {
  it("BUG-16: fillConnections has no nTries < 100 inner loop", () => {
    // fillConnections only iterates `candidates` once (a slice from
    // getCandidateAddresses) — no nTries counter.
    expect(MANAGER_SRC).not.toMatch(/nTries\s*<\s*100/);
    expect(MANAGER_SRC).not.toMatch(/nTries\s*\+\+/);
  });
  it("BUG-16: maintenance loop is 30s sleep (not tight-loop with cap)", () => {
    expect(MANAGER_SRC).toMatch(/setInterval\([^]*30_000/);
  });
});

// =============================================================================
// G17 — 10min && nTries<30 throttle — MISSING (BUG-17)
// =============================================================================
describe("W128-G17: `current_time - addr_last_try < 10min && nTries < 30` skip — MISSING (BUG-17)", () => {
  it("BUG-17: hotbuns uses 5min hardcoded (not 10min)", () => {
    // Line 1772: `now - info.lastConnected < 300_000`
    expect(MANAGER_SRC).toMatch(/now - info\.lastConnected < 300_000/);
  });
  it("BUG-17: hotbuns has no nTries<30 escape clause", () => {
    expect(MANAGER_SRC).not.toMatch(/nTries\s*<\s*30/);
  });
});

// =============================================================================
// G18 — HasAllDesirableServiceFlags filter (non-feeler) — PARTIAL (BUG-18)
// =============================================================================
describe("W128-G18: HasAllDesirableServiceFlags filter (non-feeler) — PARTIAL (BUG-18)", () => {
  it("PASS: NODE_WITNESS is preferred (sort)", () => {
    expect(MANAGER_SRC).toMatch(/Prefer NODE_WITNESS/);
  });
  it("PASS: NODE_NETWORK is preferred (sort)", () => {
    expect(MANAGER_SRC).toMatch(/Prefer NODE_NETWORK/);
  });
  it("BUG-18: NODE_WITNESS/NODE_NETWORK is sort-preference, NOT filter", () => {
    // SPV-only peers will appear at the bottom of the candidate list
    // but they DO appear.  Core continues (skips) them.
    expect(MANAGER_SRC).not.toMatch(/HasAllDesirableServiceFlags/);
    expect(MANAGER_SRC).not.toMatch(/hasAllDesirableServiceFlags/);
  });
  it("BUG-18: no MayHaveUsefulAddressDB filter for would-be feelers", () => {
    expect(MANAGER_SRC).not.toMatch(/MayHaveUsefulAddressDB|mayHaveUsefulAddressDB/);
  });
});

// =============================================================================
// G19 — IsBadPort skip (until 50 tries elapsed) — MISSING (BUG-19)
// =============================================================================
describe("W128-G19: IsBadPort skip (until 50 invalid addresses) — MISSING (BUG-19)", () => {
  it("BUG-19: no isBadPort / IsBadPort function in src/p2p", () => {
    expect(MANAGER_SRC).not.toMatch(/isBadPort|IsBadPort/);
  });
  it("BUG-19: no bad-port table (HTTP/SMTP/etc.)", () => {
    expect(MANAGER_SRC).not.toMatch(/BAD_PORTS|badPorts/);
  });
});

// =============================================================================
// G20 — FEELER connection type + 120s exponential — FIXED (anti-eclipse axis)
// =============================================================================
// FLIPPED from "assert ABSENT" to "assert PRESENT + Core-correct": the feeler
// probe (Core net.cpp ThreadOpenConnections FEELER branch) landed. The
// behavioural proof (select-from-NEW, promote-on-success-ONLY, off-budget,
// bounded) lives in feeler_anti_eclipse.test.ts; these gates pin the surface.
describe("W128-G20: FEELER connection type + 120s exponential schedule — FIXED", () => {
  it("FIXED: ConnectionType union now includes the 'feeler' variant", () => {
    expect(MANAGER_SRC).toMatch(
      /export type ConnectionType = "full_relay" \| "block_relay" \| "inbound" \| "feeler";/
    );
  });
  it("FIXED: FEELER_INTERVAL_MS present and an exp-jitter feeler delay exists", () => {
    expect(MANAGER_SRC).toMatch(/FEELER_INTERVAL_MS/);
    expect(MANAGER_SRC).toMatch(/randFeelerDelay/);
  });
  it("FIXED: MAX_FEELER_CONNECTIONS constant present (=1)", () => {
    expect(MANAGER_SRC).toMatch(/MAX_FEELER_CONNECTIONS/);
    expect(MAX_FEELER_CONNECTIONS).toBe(1);
  });
  it("FIXED: FEELER_INTERVAL_MS === 120_000 (Core net.h FEELER_INTERVAL=120s)", () => {
    expect(FEELER_INTERVAL_MS).toBe(120_000);
  });
});

// =============================================================================
// G21 — Anchor peers (2-slot block-relay) — PRESENT (no bug)
// =============================================================================
describe("W128-G21: Anchor peers loaded then unlinked (2-slot block-relay) — PRESENT", () => {
  it("PASS: MAX_BLOCK_RELAY_ONLY_ANCHORS === 2", () => {
    expect(MAX_BLOCK_RELAY_ONLY_ANCHORS).toBe(2);
  });
  it("PASS: loadAnchors deletes the file after read", () => {
    expect(MANAGER_SRC).toMatch(/await fs\.unlink\(path\);/);
  });
  it("PASS: saveAnchors writes up to MAX_BLOCK_RELAY_ONLY_ANCHORS entries", () => {
    expect(MANAGER_SRC).toMatch(/anchors\.length < MAX_BLOCK_RELAY_ONLY_ANCHORS/);
  });
  it("PASS: anchors fill before full-relay slots", () => {
    // First priority in fillConnections is anchors.
    expect(MANAGER_SRC).toMatch(/First priority: Connect to anchor peers/);
  });
});

// =============================================================================
// G22 — Outbound /16-or-ASN netgroup diversity — PRESENT (no bug)
// =============================================================================
describe("W128-G22: Outbound /16-or-ASN netgroup diversity (ipv46 only) — PRESENT", () => {
  it("PASS: getNetGroup IPv4 uses /16", () => {
    expect(getNetGroup("203.0.113.5")).toBe("ipv4:203.0");
    expect(getNetGroup("203.0.113.6")).toBe("ipv4:203.0");
    expect(getNetGroup("203.1.113.5")).toBe("ipv4:203.1");
  });
  it("PASS: getNetGroup IPv6 uses /32", () => {
    expect(getNetGroup("2001:db8::1")).toBe("ipv6:2001:0db8");
  });
  it("PASS: outboundNetGroups gates connectPeer", () => {
    expect(MANAGER_SRC).toMatch(/Already have outbound connection in netgroup/);
  });
  it("PASS: ASMap (-asmap) overrides /16 with ASN when loaded", () => {
    expect(MANAGER_SRC).toMatch(/asn:\$\{asn\}/);
  });
});

// =============================================================================
// G23 — ResolveCollisions before Select — MISSING (BUG-21)
// =============================================================================
describe("W128-G23: ResolveCollisions before Select on each iteration — MISSING (BUG-21)", () => {
  it("BUG-21: no ResolveCollisions called in fillConnections", () => {
    // Compound with BUG-13: hotbuns has no collision queue to resolve,
    // so the call site is also missing.
    expect(MANAGER_SRC).not.toMatch(/resolveCollisions|ResolveCollisions/);
  });
});

// =============================================================================
// G24 — AlreadyConnectedToAddress short-circuit — MISSING (BUG-22)
// =============================================================================
describe("W128-G24: AlreadyConnectedToAddress short-circuit + Good() — MISSING (BUG-22)", () => {
  it("BUG-22: no AlreadyConnectedToAddress (ignoring port)", () => {
    // hotbuns dedupes by `host:port` Map key — same host, different
    // port re-selects.
    expect(MANAGER_SRC).not.toMatch(/AlreadyConnectedToAddress|alreadyConnectedToAddress/);
  });
  it("BUG-22: getCandidateAddresses skip is exact key match only", () => {
    expect(MANAGER_SRC).toMatch(/this\.peers\.has\(key\)/);
  });
  it("FIXED (anti-eclipse axis): Good() promotion IS now called — on feeler success", () => {
    // FLIPPED: the original audit noted hotbuns "has no Good() either". The
    // anti-eclipse feeler axis now calls addrMan.good() to promote a NEW-table
    // address to TRIED ON A SUCCESSFUL FEELER HANDSHAKE (Core net.cpp feeler ->
    // addrman.Good()). That is a genuine, Core-correct Good() call, so the old
    // "no .good()" assertion is now (correctly) false. We pin the promotion
    // call-site instead so a refactor that drops it flips red.
    expect(MANAGER_SRC).toMatch(/this\.addrMan\.good\(/);
    // The remaining test-before-evict AlreadyConnectedToAddress short-circuit
    // (a distinct addrman path) is still out of scope — guarded above.
  });
});

// =============================================================================
// G25 — IsRoutable enforced for IPv4/IPv6/Tor/I2P/CJDNS — PARTIAL (BUG-23)
// =============================================================================
describe("W128-G25: IsRoutable enforced for IPv4/IPv6/Tor/I2P/CJDNS — PARTIAL (BUG-23)", () => {
  it("PASS: isRoutable rejects RFC1918 IPv4", () => {
    expect(isRoutable("10.0.0.1")).toBe(false);
    expect(isRoutable("192.168.1.1")).toBe(false);
    expect(isRoutable("172.16.0.1")).toBe(false);
  });
  it("PASS: isRoutable rejects loopback IPv4", () => {
    expect(isRoutable("127.0.0.1")).toBe(false);
    expect(isRoutable("0.0.0.0")).toBe(false);
  });
  it("PASS: isRoutable accepts global IPv4", () => {
    expect(isRoutable("8.8.8.8")).toBe(true);
  });
  it("BUG-23: isRoutable IPv6 returns false (NOT a routability check — pure rejection)", () => {
    // Line 312 admits the gap explicitly:
    //   `if (parts.length !== 4) return false; // Only IPv4 handled here`
    // This means every IPv6 / Tor / I2P / CJDNS address returns false
    // (so technically nothing routable gets through unless IPv4).  But
    // because handleAddrV2Message + addrV2ToPeerInfo do not call
    // isRoutable, non-IPv4 addrs bypass the check entirely.
    expect(isRoutable("2001:db8::1")).toBe(false);
    expect(isRoutable("fe80::1")).toBe(false); // link-local — should be unroutable
    expect(isRoutable("fc00::1")).toBe(false); // ULA — should be unroutable
  });
  it("BUG-23: isRoutable IS not called from handleAddrV2Message", () => {
    // The v2 path validates via isValidNetworkAddressV2 then calls
    // addrV2ToPeerInfo — no isRoutable on the IPv6 / Tor / I2P /
    // CJDNS branches.
    const v2Block = MANAGER_SRC.match(
      /private handleAddrV2Message[^]*?^\s\s\}/m
    );
    expect(v2Block).not.toBeNull();
    if (v2Block) {
      expect(v2Block[0]).not.toMatch(/isRoutable/);
    }
  });
  it("BUG-23: source comment admits the IPv4-only gap", () => {
    expect(MANAGER_SRC).toContain("Only IPv4 handled here");
  });
});

// =============================================================================
// G26 — getaddr response cap MAX_ADDR_TO_SEND=1000 — FIXED (anti-eclipse axis)
// =============================================================================
// FLIPPED: the incoming-getaddr responder + MAX_ADDR_TO_SEND cap landed.
describe("W128-G26: getaddr response capped at MAX_ADDR_TO_SEND=1000 — FIXED", () => {
  it("FIXED: MAX_ADDR_TO_SEND constant present (=1000)", () => {
    expect(MANAGER_SRC).toMatch(/MAX_ADDR_TO_SEND/);
    expect(MAX_ADDR_TO_SEND).toBe(1000);
  });
  it("FIXED: handlePeerMessage now routes incoming getaddr to a responder", () => {
    // The incoming direction now dispatches `msg.type === "getaddr"` to the
    // handleGetAddr responder (Core net_processing.cpp:4815). Both the dispatch
    // arm and the responder method must be present.
    expect(MANAGER_SRC).toMatch(/msg\.type === "getaddr"/);
    expect(MANAGER_SRC).toMatch(/private handleGetAddr\(peer: Peer\): void/);
  });
});

// =============================================================================
// G27 — getaddr response cap MAX_PCT_ADDR_TO_SEND=23 — FIXED (anti-eclipse axis)
// =============================================================================
// FLIPPED: the 23% cap formula min(1000, floor(0.23*size)) landed.
// Core AddrManImpl::GetAddr_ (addrman.cpp:800) uses size_t `max_pct*nNodes/100`
// = integer division = FLOOR, not ceil.
describe("W128-G27: getaddr response capped at MAX_PCT_ADDR_TO_SEND=23% — FIXED", () => {
  it("FIXED: MAX_PCT_ADDR_TO_SEND constant present (=23)", () => {
    expect(MANAGER_SRC).toMatch(/MAX_PCT_ADDR_TO_SEND/);
    expect(MAX_PCT_ADDR_TO_SEND).toBe(23);
  });
  it("FIXED: getAddrResponseCap applies min(1000, floor(0.23*size))", () => {
    const mgr = new PeerManager({
      maxOutbound: 8,
      maxInbound: 117,
      params: REGTEST_W128,
      bestHeight: 0,
      datadir: "/tmp/hotbuns-w128-getaddrcap",
    });
    // 23*100/100 = 23 (exact multiple)
    expect(mgr.getAddrResponseCap(100)).toBe(23);
    // min(1000, 23*100000/100) = 1000 (absolute cap dominates)
    expect(mgr.getAddrResponseCap(100_000)).toBe(1000);
    // floor(0.23 * 1) = 0 (distinguishing: ceil would give 1)
    expect(mgr.getAddrResponseCap(1)).toBe(0);
    // floor(0.23 * 10) = 2 (distinguishing: ceil would give 3)
    expect(mgr.getAddrResponseCap(10)).toBe(2);
  });
});

// =============================================================================
// G28 — IsTerrible filter available for getaddr — FIXED (axis #2)
// =============================================================================
describe("W128-G28: IsTerrible filter available (getaddr can exclude terrible) — FIXED (axis #2)", () => {
  it("FIXED-9-cover: the addrman exposes isTerrible for filtered enumeration", () => {
    expect(ADDRMAN_SRC).toMatch(/isTerrible/);
    // A getEntries-based getaddr path can now exclude terrible entries.
    const am = mkAddrMan();
    am.add("8.8.8.8", 8333, "1.2.3.4", 1n, W128_NOW, W128_NOW);
    const entries = am.getEntries(false);
    expect(entries.length).toBe(1);
    expect(entries.some((e) => isTerrible(e, W128_NOW))).toBe(false);
  });
});

// =============================================================================
// G29 — Discouragement bloom filter — MISSING (BUG-26)
// =============================================================================
describe("W128-G29: Discouragement bloom filter (50k, 1e-6 fp) — MISSING (BUG-26)", () => {
  it("BUG-26: BanManager only has hard bans (no discouragement)", () => {
    // BanManager interface: ban / unban / isBanned / sweepBanned.  No
    // Discourage / IsDiscouraged.
    expect(BANMAN_SRC).not.toMatch(/discourage|Discourage/);
    expect(BANMAN_SRC).not.toMatch(/IsDiscouraged|isDiscouraged/);
  });
  it("BUG-26: no rolling bloom filter for discouragement", () => {
    expect(BANMAN_SRC).not.toMatch(/RollingBloomFilter|rollingBloomFilter|bloomFilter/);
  });
  it("BUG-26: misbehaving() in peer.ts calls ban() directly (no discourage path)", () => {
    expect(PEER_SRC).toMatch(/onBan/);
    // Discouragement should be a no-disconnect, no-ban-list, only bloom
    // filter entry.  hotbuns has no such state.
  });
  it("PASS: DEFAULT_BAN_TIME === 24h (matches Core DEFAULT_MISBEHAVING_BANTIME)", () => {
    expect(DEFAULT_BAN_TIME).toBe(24 * 60 * 60);
  });
});

// =============================================================================
// G30 — bucketed addrman persistence round-trips placement + nKey — FIXED
// =============================================================================
describe("W128-G30: addrman persistence round-trips placement + nKey (versioned, corrupt-safe) — FIXED (axis #2)", () => {
  it("FIXED-1/2/3: addrman serialize/deserialize carries the nKey salt (versioned)", () => {
    expect(ADDRMAN_SRC).toMatch(/ADDRMAN_DAT_VERSION/);
    expect(ADDRMAN_SRC).toMatch(/ADDRMAN_DAT_MAGIC/);
    const am = mkAddrMan();
    am.add("8.8.8.8", 8333, "1.2.3.4", 1n, W128_NOW, W128_NOW);
    const restored = AddrMan.deserialize(am.serialize(), { rngSeed: 1n })!;
    expect(restored.getNKey().toString("hex")).toBe(am.getNKey().toString("hex"));
  });
  it("FIXED-1/2/3: restart preserves bucket placement (same nKey -> same slot)", () => {
    const am = mkAddrMan();
    am.add("203.0.113.5", 8333, "198.51.100.1", 1n, W128_NOW, W128_NOW);
    am.add("8.8.8.8", 8333, "1.2.3.4", 1n, W128_NOW, W128_NOW);
    am.good("8.8.8.8", 8333, W128_NOW); // tried
    const before = am.findAddressEntry("203.0.113.5", 8333)!;
    const restored = AddrMan.deserialize(am.serialize(), { rngSeed: 1n })!;
    const after = restored.findAddressEntry("203.0.113.5", 8333)!;
    expect(after.bucket).toBe(before.bucket);
    expect(after.position).toBe(before.position);
    expect(restored.isInTried("8.8.8.8", 8333)).toBe(true);
  });
  it("FIXED-1/2/3: corrupt input cold-starts (null) rather than throwing", () => {
    expect(AddrMan.deserialize("garbage\n")).toBeNull();
    expect(AddrMan.deserialize("")).toBeNull();
  });
});

// =============================================================================
// Cross-bug sanity check — `outboundNetGroups` is keyed consistently
// =============================================================================
describe("W128 cross-check: FIX-51 ASN-key vs /16-key consistency — PRESENT (regression-guarded)", () => {
  it("PASS: handlePeerDisconnect uses getNetGroupForAddr (asn-aware)", () => {
    // FIX-51 (prior wave) plumbed asmap-aware net group through the
    // disconnect path so the set entry matches what was inserted.
    // We pin that here so future refactors can't regress it.
    expect(MANAGER_SRC).toMatch(/FIX-51: use getNetGroupForAddr/);
  });
});

// =============================================================================
// Forward-regression guard — axis #2 bucket helpers must STAY present + correct
// =============================================================================
describe("W128 forward-regression guard: bucketed addrman helpers must remain", () => {
  it("guard: getTriedBucket / getNewBucket / getBucketPosition present in addrman.ts", () => {
    // The axis #2 bucketed addrman landed. This guard pins the Core helper
    // surface so a future refactor that rips it back out flips red.
    expect(ADDRMAN_SRC).toMatch(/getTriedBucket/);
    expect(ADDRMAN_SRC).toMatch(/getNewBucket/);
    expect(ADDRMAN_SRC).toMatch(/getBucketPosition/);
  });
  it("guard: isTerrible present in addrman.ts", () => {
    expect(ADDRMAN_SRC).toMatch(/isTerrible/);
  });
  it("guard: the bucket geometry constants stay at Core values", () => {
    expect(ADDRMAN_NEW_BUCKET_COUNT).toBe(1024);
    expect(ADDRMAN_TRIED_BUCKET_COUNT).toBe(256);
    expect(ADDRMAN_BUCKET_SIZE).toBe(64);
    expect(ADDRMAN_NEW_BUCKETS_PER_SOURCE_GROUP).toBe(64);
    expect(ADDRMAN_TRIED_BUCKETS_PER_GROUP).toBe(8);
    expect(ADDRMAN_CEILING).toBe(81920);
  });
  it("guard: ConnectionType now INCLUDES 'feeler' (anti-eclipse axis landed)", () => {
    // FLIPPED: the feeler axis landed; pin the variant so a refactor that rips
    // it back out flips red.
    expect(MANAGER_SRC).toMatch(
      /export type ConnectionType = "full_relay" \| "block_relay" \| "inbound" \| "feeler";/
    );
  });
});

// =============================================================================
// Public-API smoke: confirm exports we depend on are still exported
// =============================================================================
describe("W128 export smoke: public-API surface we reference is stable", () => {
  it("MAX_OUTBOUND_FULL_RELAY === 8", () => {
    expect(MAX_OUTBOUND_FULL_RELAY).toBe(8);
  });
  it("MAX_OUTBOUND_BLOCK_RELAY === 2", () => {
    expect(MAX_OUTBOUND_BLOCK_RELAY).toBe(2);
  });
  it("MAX_BLOCK_RELAY_ONLY_ANCHORS === 2", () => {
    expect(MAX_BLOCK_RELAY_ONLY_ANCHORS).toBe(2);
  });
  it("DEFAULT_BAN_TIME === 86400 (24h)", () => {
    expect(DEFAULT_BAN_TIME).toBe(86400);
  });
  it("isLocalAddress identifies loopback", () => {
    expect(isLocalAddress("127.0.0.1")).toBe(true);
    expect(isLocalAddress("::1")).toBe(true);
    expect(isLocalAddress("8.8.8.8")).toBe(false);
  });
});
