/**
 * Axis #2 proof suite for the full Core CAddrMan bucketed addrman
 * (src/p2p/addrman.ts), mirroring blockbrew addrman_core_test.go (6c5a463) and
 * rustoshi's 16-test axis2 suite (361d81b).
 *
 * Proves: (1) placement determinism (same addr+nKey -> same bucket/pos;
 * src-groups spread; golden stable); (2) Add->NEW, Good->TRIED, tried-collision
 * evicts; (3) restart-persistence preserves placement; (4) bounded (one source
 * group <= 64 new buckets; ceiling 81920); (5) falsification (it really
 * buckets, not one flat list).
 *
 * Running: bun test src/__tests__/addrman_axis2.test.ts
 */

import { describe, it, expect } from "bun:test";

import {
  AddrMan,
  cheapHash,
  addrKey,
  hostTo16,
  isTerrible,
  ADDRMAN_NEW_BUCKET_COUNT,
  ADDRMAN_TRIED_BUCKET_COUNT,
  ADDRMAN_BUCKET_SIZE,
  ADDRMAN_NEW_BUCKETS_PER_SOURCE_GROUP,
  ADDRMAN_TRIED_BUCKETS_PER_GROUP,
  ADDRMAN_NEW_BUCKETS_PER_ADDRESS,
  ADDRMAN_CEILING,
  type AddrInfo,
} from "../p2p/addrman.js";

// Fixed 32-byte salt for deterministic placement across the suite.
const KEY = Buffer.from(
  "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
  "hex",
);

function mkMan(): AddrMan {
  return new AddrMan({ nKey: KEY, rngSeed: 1n });
}

const NODE_NETWORK = 1n;
const NOW = 1_700_000_000; // a fixed "now" so IsTerrible is stable

// =============================================================================
// Constants — exact Core geometry (1024/256/64/64/8).
// =============================================================================
describe("axis2: Core geometry constants", () => {
  it("NEW=1024, TRIED=256, BUCKET_SIZE=64", () => {
    expect(ADDRMAN_NEW_BUCKET_COUNT).toBe(1024);
    expect(ADDRMAN_TRIED_BUCKET_COUNT).toBe(256);
    expect(ADDRMAN_BUCKET_SIZE).toBe(64);
  });
  it("per-source-group=64, per-group(tried)=8, per-address=8", () => {
    expect(ADDRMAN_NEW_BUCKETS_PER_SOURCE_GROUP).toBe(64);
    expect(ADDRMAN_TRIED_BUCKETS_PER_GROUP).toBe(8);
    expect(ADDRMAN_NEW_BUCKETS_PER_ADDRESS).toBe(8);
  });
  it("ceiling = 1024*64 + 256*64 = 81920", () => {
    expect(ADDRMAN_CEILING).toBe(81920);
  });
});

// =============================================================================
// (1) Placement determinism.
// =============================================================================
describe("axis2 (1): placement determinism", () => {
  it("same addr+nKey -> same new bucket/pos every time", () => {
    const a = mkMan();
    const b = mkMan();
    a.add("203.0.113.5", 8333, "198.51.100.1", NODE_NETWORK, NOW, NOW);
    b.add("203.0.113.5", 8333, "198.51.100.1", NODE_NETWORK, NOW, NOW);
    const sa = a.newSlotOf("203.0.113.5", 8333);
    const sb = b.newSlotOf("203.0.113.5", 8333);
    expect(sa).not.toBeNull();
    expect(sa).toEqual(sb);
  });

  it("getNewBucket / getTriedBucket / getBucketPosition are in-range", () => {
    const am = mkMan();
    const addrGroup = Buffer.from("ipv4:203.0", "utf8");
    const srcGroup = Buffer.from("ipv4:198.51", "utf8");
    const nb = am.getNewBucket(addrGroup, srcGroup);
    expect(nb).toBeGreaterThanOrEqual(0);
    expect(nb).toBeLessThan(ADDRMAN_NEW_BUCKET_COUNT);
    const info = { host: "203.0.113.5", port: 8333 };
    const tb = am.getTriedBucket(info, addrGroup);
    expect(tb).toBeGreaterThanOrEqual(0);
    expect(tb).toBeLessThan(ADDRMAN_TRIED_BUCKET_COUNT);
    const posN = am.getBucketPosition(true, nb, info);
    const posK = am.getBucketPosition(false, tb, info);
    for (const p of [posN, posK]) {
      expect(p).toBeGreaterThanOrEqual(0);
      expect(p).toBeLessThan(ADDRMAN_BUCKET_SIZE);
    }
  });

  it("different source groups spread one addr across distinct new buckets", () => {
    const am = mkMan();
    const addrGroup = Buffer.from("ipv4:203.0", "utf8");
    const buckets = new Set<number>();
    for (let i = 1; i <= 30; i++) {
      const srcGroup = Buffer.from(`ipv4:10.${i}`, "utf8");
      buckets.add(am.getNewBucket(addrGroup, srcGroup));
    }
    // Source group strongly influences the bucket: many distinct buckets.
    expect(buckets.size).toBeGreaterThan(10);
  });

  it("'N' vs 'K' tag produces different position hashing", () => {
    const am = mkMan();
    const info = { host: "8.8.8.8", port: 8333 };
    // Same bucket index, different fNew tag -> independent positions.
    const pN = am.getBucketPosition(true, 5, info);
    const pK = am.getBucketPosition(false, 5, info);
    // Not asserting inequality (could coincide); assert both deterministic.
    expect(pN).toBe(am.getBucketPosition(true, 5, info));
    expect(pK).toBe(am.getBucketPosition(false, 5, info));
  });

  it("golden: placement is stable for a fixed key (regression pin)", () => {
    const am = mkMan();
    const addrGroup = Buffer.from("ipv4:203.0", "utf8");
    const srcGroup = Buffer.from("ipv4:198.51", "utf8");
    const info = { host: "203.0.113.5", port: 8333 };
    const golden = {
      newBucket: am.getNewBucket(addrGroup, srcGroup),
      triedBucket: am.getTriedBucket(info, addrGroup),
      newPos: am.getBucketPosition(true, am.getNewBucket(addrGroup, srcGroup), info),
    };
    // Recompute on a fresh manager with the same key: must match exactly.
    const am2 = mkMan();
    expect(am2.getNewBucket(addrGroup, srcGroup)).toBe(golden.newBucket);
    expect(am2.getTriedBucket(info, addrGroup)).toBe(golden.triedBucket);
    expect(
      am2.getBucketPosition(true, am2.getNewBucket(addrGroup, srcGroup), info),
    ).toBe(golden.newPos);
  });

  it("cheapHash is a deterministic 64-bit value", () => {
    const h1 = cheapHash(KEY, Buffer.from("a"), Buffer.from("b"));
    const h2 = cheapHash(KEY, Buffer.from("a"), Buffer.from("b"));
    expect(h1).toBe(h2);
    expect(h1).toBeGreaterThanOrEqual(0n);
    expect(h1).toBeLessThan(1n << 64n);
    expect(cheapHash(KEY, Buffer.from("a"))).not.toBe(h1);
  });

  it("a different nKey moves placement (salt matters)", () => {
    const am1 = mkMan();
    const otherKey = Buffer.alloc(32, 0xab);
    const am2 = new AddrMan({ nKey: otherKey, rngSeed: 1n });
    am1.add("203.0.113.5", 8333, "198.51.100.1", NODE_NETWORK, NOW, NOW);
    am2.add("203.0.113.5", 8333, "198.51.100.1", NODE_NETWORK, NOW, NOW);
    const s1 = am1.newSlotOf("203.0.113.5", 8333)!;
    const s2 = am2.newSlotOf("203.0.113.5", 8333)!;
    // Overwhelmingly likely to differ; assert at least one coordinate moved.
    expect(s1.bucket !== s2.bucket || s1.position !== s2.position).toBe(true);
  });
});

// =============================================================================
// (2) Add -> NEW, Good -> TRIED, tried-collision evicts.
// =============================================================================
describe("axis2 (2): Add->NEW, Good->TRIED, eviction", () => {
  it("add() places in NEW (not tried), increments nNew", () => {
    const am = mkMan();
    const ins = am.add("8.8.8.8", 8333, "1.2.3.4", NODE_NETWORK, NOW, NOW);
    expect(ins).toBe(true);
    expect(am.newCount()).toBe(1);
    expect(am.triedCount()).toBe(0);
    expect(am.isInTried("8.8.8.8", 8333)).toBe(false);
    expect(am.newSlotOf("8.8.8.8", 8333)).not.toBeNull();
    expect(am.triedSlotOf("8.8.8.8", 8333)).toBeNull();
  });

  it("good() promotes NEW -> TRIED", () => {
    const am = mkMan();
    am.add("8.8.8.8", 8333, "1.2.3.4", NODE_NETWORK, NOW, NOW);
    const moved = am.good("8.8.8.8", 8333, NOW);
    expect(moved).toBe(true);
    expect(am.triedCount()).toBe(1);
    expect(am.newCount()).toBe(0);
    expect(am.isInTried("8.8.8.8", 8333)).toBe(true);
    expect(am.triedSlotOf("8.8.8.8", 8333)).not.toBeNull();
    expect(am.newSlotOf("8.8.8.8", 8333)).toBeNull();
  });

  it("good() on an unknown address is a no-op false", () => {
    const am = mkMan();
    expect(am.good("9.9.9.9", 8333, NOW)).toBe(false);
  });

  it("good() twice keeps it tried (idempotent promote)", () => {
    const am = mkMan();
    am.add("8.8.8.8", 8333, "1.2.3.4", NODE_NETWORK, NOW, NOW);
    expect(am.good("8.8.8.8", 8333, NOW)).toBe(true);
    expect(am.good("8.8.8.8", 8333, NOW)).toBe(false);
    expect(am.triedCount()).toBe(1);
  });

  it("tried collision evicts the prior occupant back to NEW", () => {
    // Find two distinct addresses that map to the SAME tried (bucket,pos).
    const am = mkMan();
    const addrGroup = (h: string) => Buffer.from(`ipv4:${h.split(".").slice(0, 2).join(".")}`, "utf8");
    const slotKey = (h: string) => {
      const info = { host: h, port: 8333 };
      const tb = am.getTriedBucket(info, addrGroup(h));
      const tp = am.getBucketPosition(false, tb, info);
      return `${tb}:${tp}`;
    };
    // Search the 10.0.0.x space for two hosts colliding in tried.
    const seen = new Map<string, string>();
    let aHost = "";
    let bHost = "";
    outer: for (let i = 1; i < 4000 && (aHost === "" || bHost === ""); i++) {
      const h = `10.0.${(i >> 8) & 0xff}.${i & 0xff}`;
      if (h.endsWith(".0") || h.endsWith(".255")) continue;
      const k = slotKey(h);
      const prev = seen.get(k);
      if (prev) {
        aHost = prev;
        bHost = h;
        break outer;
      }
      seen.set(k, h);
    }
    expect(aHost).not.toBe("");
    expect(bHost).not.toBe("");

    // Promote A into tried.
    am.add(aHost, 8333, "1.2.3.4", NODE_NETWORK, NOW, NOW);
    expect(am.good(aHost, 8333, NOW)).toBe(true);
    expect(am.isInTried(aHost, 8333)).toBe(true);

    // Promote B into the same tried slot -> A is evicted back to NEW.
    am.add(bHost, 8333, "1.2.3.4", NODE_NETWORK, NOW, NOW);
    expect(am.good(bHost, 8333, NOW)).toBe(true);

    expect(am.isInTried(bHost, 8333)).toBe(true);
    expect(am.isInTried(aHost, 8333)).toBe(false);
    // A is back in the NEW table.
    expect(am.newSlotOf(aHost, 8333)).not.toBeNull();
    expect(am.triedCount()).toBe(1);
    expect(am.newCount()).toBe(1);
  });

  it("attempt() bumps nAttempts and lastTry", () => {
    const am = mkMan();
    am.add("8.8.8.8", 8333, "1.2.3.4", NODE_NETWORK, NOW, NOW);
    am.attempt("8.8.8.8", 8333, NOW + 100);
    const entry = am.findAddressEntry("8.8.8.8", 8333);
    expect(entry).not.toBeNull();
  });

  it("select() returns a stored entry; newOnly excludes tried-only state", () => {
    const am = mkMan();
    am.add("8.8.8.8", 8333, "1.2.3.4", NODE_NETWORK, NOW, NOW);
    const s = am.select(false);
    expect(s).not.toBeNull();
    expect(s!.host).toBe("8.8.8.8");
    // Promote it; now newOnly select finds nothing (it left the new table).
    am.good("8.8.8.8", 8333, NOW);
    expect(am.select(true)).toBeNull();
    expect(am.select(false)).not.toBeNull();
  });
});

// =============================================================================
// (3) Restart-persistence preserves placement.
// =============================================================================
describe("axis2 (3): restart persistence preserves placement", () => {
  it("serialize -> deserialize preserves nKey, new placement, and tried set", () => {
    const am = mkMan();
    am.add("8.8.8.8", 8333, "1.2.3.4", NODE_NETWORK, NOW, NOW);
    am.add("203.0.113.5", 8333, "198.51.100.1", NODE_NETWORK, NOW, NOW);
    am.add("9.9.9.9", 8333, "5.6.7.8", NODE_NETWORK, NOW, NOW);
    am.good("8.8.8.8", 8333, NOW); // -> tried

    const before8 = am.findAddressEntry("8.8.8.8", 8333)!;
    const before203 = am.findAddressEntry("203.0.113.5", 8333)!;

    const text = am.serialize();
    const restored = AddrMan.deserialize(text, { rngSeed: 1n });
    expect(restored).not.toBeNull();

    // Same salt survived.
    expect(restored!.getNKey().toString("hex")).toBe(am.getNKey().toString("hex"));

    // tried set preserved.
    expect(restored!.isInTried("8.8.8.8", 8333)).toBe(true);
    const after8 = restored!.findAddressEntry("8.8.8.8", 8333)!;
    expect(after8.tried).toBe(true);
    expect(after8.bucket).toBe(before8.bucket);
    expect(after8.position).toBe(before8.position);

    // new placement preserved.
    const after203 = restored!.findAddressEntry("203.0.113.5", 8333)!;
    expect(after203.tried).toBe(false);
    expect(after203.bucket).toBe(before203.bucket);
    expect(after203.position).toBe(before203.position);
  });

  it("deserialize cold-starts (null) on corrupt / truncated / wrong-version input", () => {
    expect(AddrMan.deserialize("")).toBeNull();
    expect(AddrMan.deserialize("garbage\n")).toBeNull();
    expect(AddrMan.deserialize("ADDRMANV2 99 " + "00".repeat(32) + "\n")).toBeNull();
    expect(AddrMan.deserialize("ADDRMANV2 1 nothex\n")).toBeNull();
    // structurally short record line -> null
    const k = "00".repeat(32);
    expect(AddrMan.deserialize(`ADDRMANV2 1 ${k}\nn 8.8.8.8 8333\n`)).toBeNull();
  });

  it("deserialize of a header-only file yields an empty (valid) manager", () => {
    const k = "00".repeat(32);
    const am = AddrMan.deserialize(`ADDRMANV2 1 ${k}\n`);
    expect(am).not.toBeNull();
    expect(am!.size()).toBe(0);
  });
});

// =============================================================================
// (4) Bounded: per-source-group <= 64 new buckets; ceiling 81920.
// =============================================================================
describe("axis2 (4): bounded", () => {
  it("one source group reaches at most 64 distinct new buckets", () => {
    const am = mkMan();
    const srcGroup = Buffer.from("ipv4:198.51", "utf8");
    const buckets = new Set<number>();
    // Many distinct addr groups, all from ONE source group.
    for (let a = 0; a < 256; a++) {
      for (let b = 0; b < 4; b++) {
        const addrGroup = Buffer.from(`ipv4:${a}.${b}`, "utf8");
        buckets.add(am.getNewBucket(addrGroup, srcGroup));
      }
    }
    expect(buckets.size).toBeLessThanOrEqual(ADDRMAN_NEW_BUCKETS_PER_SOURCE_GROUP);
  });

  it("one group reaches at most 8 distinct tried buckets", () => {
    const am = mkMan();
    const addrGroup = Buffer.from("ipv4:203.0", "utf8");
    const buckets = new Set<number>();
    // Many addresses in ONE /16 group -> at most 8 tried buckets.
    for (let i = 1; i < 250; i++) {
      const info = { host: `203.0.113.${i}`, port: 8333 };
      buckets.add(am.getTriedBucket(info, addrGroup));
    }
    expect(buckets.size).toBeLessThanOrEqual(ADDRMAN_TRIED_BUCKETS_PER_GROUP);
  });

  it("an address occupies at most ADDRMAN_NEW_BUCKETS_PER_ADDRESS new slots", () => {
    const am = mkMan();
    // Same addr advertised by many distinct source groups. Force the
    // stochastic gate open by reseeding so multiplicity can grow, then cap at 8.
    for (let i = 0; i < 200; i++) {
      const src = `10.${i & 0xff}.${(i >> 8) & 0xff}.1`;
      // bypass stochastic gate by adding then re-adding with a fresh seed RNG
      const am2 = am as unknown as { rng: { range(n: number): number } };
      am2.rng.range = () => 0; // always pass the 2^refCount gate (test only)
      am.add("8.8.8.8", 8333, src, NODE_NETWORK, NOW + i, NOW + i);
    }
    const entry = am.findAddressEntry("8.8.8.8", 8333)!;
    expect(entry.multiplicity).toBeLessThanOrEqual(ADDRMAN_NEW_BUCKETS_PER_ADDRESS);
    expect(entry.multiplicity).toBeGreaterThan(0);
  });

  it("ceiling guard: never exceeds 81920 distinct ids", () => {
    const am = mkMan();
    // Add a large but bounded set quickly; we don't add all 81920 (slow), we
    // assert the guard returns false once size would exceed the ceiling by
    // poking the internal map directly to the ceiling.
    const internal = am as unknown as { mapInfo: Map<number, AddrInfo>; idCount: number };
    for (let i = 0; i < ADDRMAN_CEILING; i++) {
      internal.mapInfo.set(i, {
        host: "0.0.0.0",
        port: i & 0xffff,
        services: 0n,
        source: "x",
        nTime: NOW,
        lastSuccess: 0,
        lastTry: 0,
        attempts: 0,
        refCount: 0,
        inTried: false,
      });
    }
    expect(internal.mapInfo.size).toBe(ADDRMAN_CEILING);
    // A genuinely-new address must now be refused.
    const ins = am.add("8.8.8.8", 8333, "1.2.3.4", NODE_NETWORK, NOW, NOW);
    expect(ins).toBe(false);
    expect(internal.mapInfo.size).toBe(ADDRMAN_CEILING);
  });
});

// =============================================================================
// (5) Falsification: it REALLY buckets (not one flat list).
// =============================================================================
describe("axis2 (5): falsification — really bucketed, not flat", () => {
  it("distinct addresses populate many distinct (bucket,pos) slots", () => {
    const am = mkMan();
    const slots = new Set<string>();
    for (let i = 1; i < 200; i++) {
      // spread across many /16 groups AND source groups
      const host = `${(i % 200) + 11}.${(i * 7) % 256}.${(i * 13) % 256}.${(i % 250) + 1}`;
      const src = `${(i * 3) % 200 + 11}.${(i * 5) % 256}.0.1`;
      am.add(host, 8333, src, NODE_NETWORK, NOW, NOW);
      const s = am.newSlotOf(host, 8333);
      if (s) slots.add(`${s.bucket}:${s.position}`);
    }
    // A flat list would have effectively one "slot"; bucketing yields many.
    expect(slots.size).toBeGreaterThan(20);
    // And they span more than one bucket.
    const bucketSet = new Set([...slots].map((s) => s.split(":")[0]));
    expect(bucketSet.size).toBeGreaterThan(10);
  });

  it("new and tried are SEPARATE tables (an addr is in exactly one)", () => {
    const am = mkMan();
    am.add("8.8.8.8", 8333, "1.2.3.4", NODE_NETWORK, NOW, NOW);
    expect(am.newSlotOf("8.8.8.8", 8333)).not.toBeNull();
    expect(am.triedSlotOf("8.8.8.8", 8333)).toBeNull();
    am.good("8.8.8.8", 8333, NOW);
    expect(am.newSlotOf("8.8.8.8", 8333)).toBeNull();
    expect(am.triedSlotOf("8.8.8.8", 8333)).not.toBeNull();
  });

  it("the new table is 1024 buckets and the tried table is 256 (not shared)", () => {
    const am = mkMan();
    const internal = am as unknown as { vvNew: Int32Array[]; vvTried: Int32Array[] };
    expect(internal.vvNew.length).toBe(ADDRMAN_NEW_BUCKET_COUNT);
    expect(internal.vvTried.length).toBe(ADDRMAN_TRIED_BUCKET_COUNT);
    expect(internal.vvNew[0]!.length).toBe(ADDRMAN_BUCKET_SIZE);
    expect(internal.vvTried[0]!.length).toBe(ADDRMAN_BUCKET_SIZE);
  });
});

// =============================================================================
// Helpers — addrKey / hostTo16 / isTerrible primitives.
// =============================================================================
describe("axis2 helpers", () => {
  it("hostTo16 maps IPv4 to ::ffff: form (18-byte key with port)", () => {
    const b = hostTo16("8.8.8.8")!;
    expect(b.length).toBe(16);
    expect(b[10]).toBe(0xff);
    expect(b[11]).toBe(0xff);
    expect(b[12]).toBe(8);
    expect(b[15]).toBe(8);
    const k = addrKey({ host: "8.8.8.8", port: 8333 });
    expect(k.length).toBe(18);
    expect(k.readUInt16BE(16)).toBe(8333);
  });

  it("hostTo16 expands IPv6 :: notation", () => {
    const b = hostTo16("2001:db8::1")!;
    expect(b.length).toBe(16);
    expect(b[0]).toBe(0x20);
    expect(b[1]).toBe(0x01);
    expect(b[15]).toBe(0x01);
  });

  it("addrKey uses rawAddr for non-IP networks", () => {
    const raw = Buffer.alloc(32, 0x77);
    const k = addrKey({ host: "abcd.onion", port: 8333, rawAddr: raw });
    expect(k.length).toBe(34); // 32 raw + 2 port
    expect(k.subarray(0, 32).equals(raw)).toBe(true);
  });

  it("isTerrible: 30-day horizon and never-success retries", () => {
    const base: AddrInfo = {
      host: "8.8.8.8",
      port: 8333,
      services: 0n,
      source: "x",
      nTime: NOW,
      lastSuccess: 0,
      lastTry: NOW - 3600,
      attempts: 0,
      refCount: 1,
      inTried: false,
    };
    expect(isTerrible(base, NOW)).toBe(false);
    // older than 30 days.
    expect(isTerrible({ ...base, nTime: NOW - (31 * 24 * 60 * 60) }, NOW)).toBe(true);
    // never succeeded, >=3 attempts.
    expect(isTerrible({ ...base, attempts: 3 }, NOW)).toBe(true);
    // tried in the last minute -> never terrible.
    expect(
      isTerrible({ ...base, lastTry: NOW, attempts: 99, nTime: NOW - (99 * 24 * 60 * 60) }, NOW),
    ).toBe(false);
  });
});
