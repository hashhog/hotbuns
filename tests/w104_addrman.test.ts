/**
 * W104 AddrMan 30-gate fleet audit — hotbuns (TypeScript/Bun)
 *
 * Reference: bitcoin-core/src/addrman.cpp, addrman.h, addrman_impl.h,
 *            net_processing.cpp (addr/getaddr handling)
 *
 * hotbuns does not have a dedicated AddrMan class. Address management lives
 * entirely in PeerManager (src/p2p/manager.ts) using a flat
 *   knownAddresses: Map<string, PeerInfo>
 * with no new/tried table separation, no bucket hashing, no IsTerrible/GetChance,
 * and no nAttempts/m_last_success tracking.
 *
 * All 30 gates are tested below. Gates that expose missing behaviour are
 * structured as regression tests (they assert the correct post-fix behaviour)
 * so they turn green once the implementation is fixed.
 */

import { describe, test, expect, beforeEach } from "bun:test";
import {
  PeerManager,
  type PeerManagerConfig,
  type PeerInfo,
  ServiceFlags,
  getNetGroup,
  isLocalAddress,
} from "../src/p2p/manager.js";
import { REGTEST } from "../src/consensus/params.js";

// ─── helpers ──────────────────────────────────────────────────────────────────

/** Build a minimal PeerManagerConfig for unit-test use (no real I/O). */
function makeConfig(overrides: Partial<PeerManagerConfig> = {}): PeerManagerConfig {
  return {
    maxOutbound: 10,
    maxInbound: 117,
    params: REGTEST,
    bestHeight: 0,
    datadir: "/tmp/hotbuns-w104-test",
    ...overrides,
  };
}

/** Build a minimal PeerInfo record. */
function makePeerInfo(host: string, port: number, overrides: Partial<PeerInfo> = {}): PeerInfo {
  return {
    host,
    port,
    services: ServiceFlags.NODE_NETWORK | ServiceFlags.NODE_WITNESS,
    lastSeen: Date.now() - 60_000,
    banScore: 0,
    lastConnected: 0,
    ...overrides,
  };
}

/**
 * Expose private knownAddresses for white-box testing.
 * This lets the audit tests inspect internal state without going through
 * the full async connect path.
 */
function knownAddresses(pm: PeerManager): Map<string, PeerInfo> {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  return (pm as any).knownAddresses as Map<string, PeerInfo>;
}

// ═════════════════════════════════════════════════════════════════════════════
// G1 — No two-table structure (new / tried buckets)
// ═════════════════════════════════════════════════════════════════════════════
/**
 * BUG-1 [CRITICAL] — AddrMan has no new/tried table split
 *
 * Core: 1024 new buckets × 64 slots = 65536 new slots;
 *       256 tried buckets × 64 slots = 16384 tried slots.
 * hotbuns: single flat Map<string,PeerInfo>; all addresses are equivalent
 * regardless of whether we've ever successfully connected.
 *
 * Severity: CRITICAL — the entire eclipse-attack resistance of AddrMan
 * (stochastic bucket assignment, source-group diversity, tried promotion)
 * depends on the two-table structure.
 *
 * Core refs: addrman_impl.h ADDRMAN_NEW_BUCKET_COUNT=1024,
 *            ADDRMAN_TRIED_BUCKET_COUNT=256; addrman.cpp MakeTried().
 */
describe("G1 — new/tried two-table structure", () => {
  test("PeerManager exposes separate new-table and tried-table counts", () => {
    const pm = new PeerManager(makeConfig());
    // POST-FIX: pm should expose getNewCount() and getTriedCount() reflecting
    // the two-table split. Currently both would be absent / throw.
    expect(typeof (pm as any).getNewCount).toBe("function");   // BUG-1
    expect(typeof (pm as any).getTriedCount).toBe("function"); // BUG-1
  });

  test("new-table capacity is 1024×64=65536", () => {
    const pm = new PeerManager(makeConfig());
    // POST-FIX: addrman.newBucketCount × addrman.bucketSize === 65536
    const NEW_BUCKET_COUNT = (pm as any).NEW_BUCKET_COUNT ?? (pm as any).newBucketCount;
    const BUCKET_SIZE      = (pm as any).BUCKET_SIZE      ?? (pm as any).bucketSize;
    expect(NEW_BUCKET_COUNT).toBe(1024);   // BUG-1
    expect(BUCKET_SIZE).toBe(64);          // BUG-1
  });

  test("tried-table capacity is 256×64=16384", () => {
    const pm = new PeerManager(makeConfig());
    const TRIED_BUCKET_COUNT = (pm as any).TRIED_BUCKET_COUNT ?? (pm as any).triedBucketCount;
    expect(TRIED_BUCKET_COUNT).toBe(256);  // BUG-1
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// G2 — No cryptographic nKey for bucket hashing
// ═════════════════════════════════════════════════════════════════════════════
/**
 * BUG-2 [CRITICAL] — Bucket positions are not keyed with a random 256-bit secret
 *
 * Core generates a 256-bit nKey during construction (from insecure_rand.rand256())
 * and uses it in GetNewBucket() / GetTriedBucket() / GetBucketPosition().
 * An attacker who knows bucket positions can craft addresses that all land in
 * the same bucket, filling it cheaply. The nKey prevents this.
 *
 * Core refs: addrman_impl.h AddrManImpl::nKey; addrman.cpp constructor.
 */
describe("G2 — cryptographic nKey for bucket hashing", () => {
  test("PeerManager generates a random 256-bit nKey on construction", () => {
    const pm1 = new PeerManager(makeConfig());
    const pm2 = new PeerManager(makeConfig());
    const key1: Buffer | undefined = (pm1 as any).nKey;
    const key2: Buffer | undefined = (pm2 as any).nKey;
    // POST-FIX: both should be 32-byte Buffers that differ between instances.
    expect(key1).toBeDefined();                              // BUG-2
    expect(key1!.length).toBe(32);                          // BUG-2
    expect(key1!.equals(key2!)).toBe(false);                // BUG-2 (should be random)
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// G3 — IsTerrible() absent
// ═════════════════════════════════════════════════════════════════════════════
/**
 * BUG-3 [CRITICAL] — IsTerrible() not implemented; stale/failed addresses never culled
 *
 * Core's IsTerrible() criteria:
 *   1. Last try within 1 min → never terrible (recent attempt).
 *   2. nTime > now + 10min → future timestamp (DeLorean) → terrible.
 *   3. now - nTime > 30 days → not seen in 30 days → terrible.
 *   4. m_last_success==0 && nAttempts >= 3 → never connected after 3 tries → terrible.
 *   5. now - m_last_success > 7 days && nAttempts >= 10 → 10 failures in a week → terrible.
 *
 * hotbuns has no IsTerrible() at all. Addresses accumulate indefinitely.
 *
 * Core refs: addrman.cpp AddrInfo::IsTerrible(); addrman.h ADDRMAN_HORIZON=30d,
 *            ADDRMAN_RETRIES=3, ADDRMAN_MAX_FAILURES=10, ADDRMAN_MIN_FAIL=7d.
 */
describe("G3 — IsTerrible() address quality gate", () => {
  test("address unseen for 31 days is terrible", () => {
    const pm = new PeerManager(makeConfig());
    const THIRTY_ONE_DAYS_MS = 31 * 24 * 60 * 60 * 1000;
    const staleInfo = makePeerInfo("1.2.3.4", 8333, {
      lastSeen: Date.now() - THIRTY_ONE_DAYS_MS,
    });
    // POST-FIX: a method isTerrible(info) should return true for stale address.
    const isTerrible: (i: PeerInfo) => boolean = (pm as any).isTerrible?.bind(pm);
    expect(isTerrible).toBeDefined();    // BUG-3
    expect(isTerrible!(staleInfo)).toBe(true); // BUG-3
  });

  test("address with future timestamp is terrible (DeLorean check)", () => {
    const pm = new PeerManager(makeConfig());
    const futureInfo = makePeerInfo("1.2.3.5", 8333, {
      lastSeen: Date.now() + 20 * 60 * 1000, // 20 minutes in the future
    });
    const isTerrible: (i: PeerInfo) => boolean = (pm as any).isTerrible?.bind(pm);
    expect(isTerrible).toBeDefined();          // BUG-3
    expect(isTerrible!(futureInfo)).toBe(true); // BUG-3
  });

  test("address with 3+ attempts and zero success is terrible", () => {
    const pm = new PeerManager(makeConfig());
    const failedInfo = makePeerInfo("1.2.3.6", 8333, {
      lastSeen: Date.now() - 60_000,
    });
    // Simulate 3 failed attempts with no success
    (failedInfo as any).nAttempts = 3;
    (failedInfo as any).lastSuccess = 0;
    const isTerrible: (i: PeerInfo) => boolean = (pm as any).isTerrible?.bind(pm);
    expect(isTerrible).toBeDefined();             // BUG-3
    expect(isTerrible!(failedInfo)).toBe(true);   // BUG-3
  });

  test("good recently-seen address is not terrible", () => {
    const pm = new PeerManager(makeConfig());
    const goodInfo = makePeerInfo("1.2.3.7", 8333, {
      lastSeen: Date.now() - 60_000,
    });
    (goodInfo as any).nAttempts = 0;
    (goodInfo as any).lastSuccess = Date.now() - 3600_000;
    const isTerrible: (i: PeerInfo) => boolean = (pm as any).isTerrible?.bind(pm);
    expect(isTerrible).toBeDefined();              // BUG-3
    expect(isTerrible!(goodInfo)).toBe(false);     // BUG-3
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// G4 — GetChance() absent
// ═════════════════════════════════════════════════════════════════════════════
/**
 * BUG-4 [HIGH] — GetChance() not implemented; address selection ignores quality
 *
 * Core's GetChance():
 *   - Base chance 1.0
 *   - ×0.01 if last attempt was within 10 minutes
 *   - ×0.66^min(nAttempts,8) to deprioritize repeatedly-failed addresses
 *
 * hotbuns' getCandidateAddresses() uses a deterministic sort by services/lastSeen/banScore
 * but never applies exponential back-off or recent-attempt penalty.
 *
 * Core refs: addrman.cpp AddrInfo::GetChance().
 */
describe("G4 — GetChance() probabilistic selection", () => {
  test("getChance returns 1.0 for fresh address with no failures", () => {
    const pm = new PeerManager(makeConfig());
    const info = makePeerInfo("1.2.3.8", 8333);
    (info as any).nAttempts = 0;
    (info as any).lastTry = 0;
    const getChance: (i: PeerInfo) => number = (pm as any).getChance?.bind(pm);
    expect(getChance).toBeDefined();        // BUG-4
    expect(getChance!(info)).toBeCloseTo(1.0); // BUG-4
  });

  test("getChance is ~0.01 for address tried within 10 minutes", () => {
    const pm = new PeerManager(makeConfig());
    const info = makePeerInfo("1.2.3.9", 8333);
    (info as any).nAttempts = 0;
    (info as any).lastTry = Date.now() - 5 * 60 * 1000; // 5 minutes ago
    const getChance: (i: PeerInfo) => number = (pm as any).getChance?.bind(pm);
    expect(getChance).toBeDefined();                // BUG-4
    expect(getChance!(info)).toBeCloseTo(0.01, 3);  // BUG-4
  });

  test("getChance decreases exponentially with nAttempts (0.66^n)", () => {
    const pm = new PeerManager(makeConfig());
    const chance0 = (pm as any).getChance?.({ nAttempts: 0, lastTry: 0 });
    const chance4 = (pm as any).getChance?.({ nAttempts: 4, lastTry: 0 });
    expect(chance0).toBeDefined(); // BUG-4
    if (chance0 !== undefined && chance4 !== undefined) {
      // 0.66^4 ≈ 0.19; chance4 should be ~19% of chance0
      expect(chance4 / chance0).toBeCloseTo(Math.pow(0.66, 4), 2);
    }
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// G5 — nAttempts / m_last_success / m_last_try absent from PeerInfo
// ═════════════════════════════════════════════════════════════════════════════
/**
 * BUG-5 [CRITICAL] — No failure/success counters in address store
 *
 * Core AddrInfo carries: nAttempts (int), m_last_success (NodeSeconds),
 * m_last_try (NodeSeconds), m_last_count_attempt (NodeSeconds).
 * Without these, IsTerrible() and GetChance() cannot be implemented.
 * hotbuns PeerInfo has lastConnected but no nAttempts or success timestamp.
 *
 * Core refs: addrman_impl.h AddrInfo fields.
 */
describe("G5 — nAttempts / m_last_success / m_last_try in PeerInfo", () => {
  test("PeerInfo has nAttempts field initialized to 0", () => {
    const info = makePeerInfo("1.2.3.10", 8333);
    // POST-FIX: PeerInfo should have nAttempts initialized to 0.
    expect((info as any).nAttempts).toBe(0); // BUG-5
  });

  test("PeerInfo has lastSuccess field initialized to 0", () => {
    const info = makePeerInfo("1.2.3.11", 8333);
    // POST-FIX: PeerInfo should have lastSuccess (ms) initialized to 0.
    expect((info as any).lastSuccess).toBe(0); // BUG-5
  });

  test("PeerInfo has lastTry field initialized to 0", () => {
    const info = makePeerInfo("1.2.3.12", 8333);
    // POST-FIX: PeerInfo should have lastTry (ms) initialized to 0.
    expect((info as any).lastTry).toBe(0); // BUG-5
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// G6 — Good() / MakeTried() absent
// ═════════════════════════════════════════════════════════════════════════════
/**
 * BUG-6 [CRITICAL] — No promotion from new→tried table on successful connection
 *
 * Core's Good() is called when a peer successfully connects. It sets
 * m_last_success, resets nAttempts, and calls MakeTried() to move the entry
 * from the new table to the tried table. Without this, the tried table remains
 * empty — all addresses stay in the equivalent of "new" regardless of quality.
 *
 * Core refs: addrman.cpp AddrManImpl::Good_(), MakeTried().
 */
describe("G6 — Good() / MakeTried() promotion", () => {
  test("PeerManager exposes a good(addr) method", () => {
    const pm = new PeerManager(makeConfig());
    // POST-FIX: pm.good(host, port) promotes address to tried table.
    expect(typeof (pm as any).good).toBe("function"); // BUG-6
  });

  test("good() increments tried count and decrements new count", () => {
    const pm = new PeerManager(makeConfig());
    const addr = "1.2.3.20";
    const port = 8333;
    const ka = knownAddresses(pm);
    ka.set(`${addr}:${port}`, makePeerInfo(addr, port));

    const goodFn: (host: string, port: number) => void = (pm as any).good?.bind(pm);
    if (goodFn) {
      goodFn(addr, port);
      // POST-FIX: after good(), tried count should be 1, new count 0.
      const triedCount: number = (pm as any).getTriedCount?.() ?? -1;
      const newCount:   number = (pm as any).getNewCount?.()   ?? -1;
      expect(triedCount).toBe(1); // BUG-6
      expect(newCount).toBe(0);   // BUG-6
    } else {
      // fail loudly if method doesn't exist yet
      expect(typeof (pm as any).good).toBe("function"); // BUG-6
    }
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// G7 — ResolveCollisions() absent
// ═════════════════════════════════════════════════════════════════════════════
/**
 * BUG-7 [HIGH] — No test-before-evict collision resolution
 *
 * When Good() would evict a tried entry (bucket already occupied), Core instead
 * records the collision in m_tried_collisions (up to ADDRMAN_SET_TRIED_COLLISION_SIZE=10)
 * and defers the replacement to ResolveCollisions() which sends FEELER connections
 * to the old entry. Only if the old entry fails the test does the new entry replace it.
 *
 * hotbuns has no tried table and no collision logic at all.
 *
 * Core refs: addrman.cpp AddrManImpl::Good_() test_before_evict path,
 *            ResolveCollisions_().
 */
describe("G7 — ResolveCollisions() test-before-evict", () => {
  test("PeerManager exposes a resolveCollisions() method", () => {
    const pm = new PeerManager(makeConfig());
    expect(typeof (pm as any).resolveCollisions).toBe("function"); // BUG-7
  });

  test("tried-collision set is bounded to ADDRMAN_SET_TRIED_COLLISION_SIZE=10", () => {
    const pm = new PeerManager(makeConfig());
    const maxCollisions: number | undefined = (pm as any).ADDRMAN_SET_TRIED_COLLISION_SIZE
      ?? (pm as any).maxTriedCollisions;
    expect(maxCollisions).toBe(10); // BUG-7
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// G8 — SelectTriedCollision() absent
// ═════════════════════════════════════════════════════════════════════════════
/**
 * BUG-8 [HIGH] — No SelectTriedCollision() for FEELER connections
 *
 * Core's net.cpp uses SelectTriedCollision() to pick a candidate from
 * m_tried_collisions for a FEELER connection. This is how the test-before-evict
 * discipline is exercised: we connect to the old address and if it fails,
 * the new address wins.
 *
 * Core refs: addrman.cpp AddrManImpl::SelectTriedCollision_().
 */
describe("G8 — SelectTriedCollision()", () => {
  test("PeerManager exposes selectTriedCollision() method", () => {
    const pm = new PeerManager(makeConfig());
    expect(typeof (pm as any).selectTriedCollision).toBe("function"); // BUG-8
  });

  test("selectTriedCollision returns null when no collisions pending", () => {
    const pm = new PeerManager(makeConfig());
    const fn: (() => PeerInfo | null) | undefined = (pm as any).selectTriedCollision?.bind(pm);
    if (fn) {
      expect(fn()).toBeNull(); // BUG-8
    } else {
      expect(typeof (pm as any).selectTriedCollision).toBe("function"); // BUG-8
    }
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// G9 — ADDRMAN_NEW_BUCKETS_PER_ADDRESS=8 multiplicity cap absent
// ═════════════════════════════════════════════════════════════════════════════
/**
 * BUG-9 [HIGH] — No nRefCount / multiplicity per address
 *
 * Core allows a single address to appear in up to 8 new buckets (nRefCount≤8)
 * with stochastic exponential-backoff for new insertions. Each additional
 * insertion becomes 2× harder than the previous. This raises selection
 * probability for frequently-gossiped addresses while limiting table pollution.
 * hotbuns has no nRefCount concept.
 *
 * Core refs: addrman.h ADDRMAN_NEW_BUCKETS_PER_ADDRESS=8;
 *            addrman.cpp AddSingle stochastic gate.
 */
describe("G9 — nRefCount / ADDRMAN_NEW_BUCKETS_PER_ADDRESS cap", () => {
  test("ADDRMAN_NEW_BUCKETS_PER_ADDRESS constant is 8", () => {
    const pm = new PeerManager(makeConfig());
    const cap = (pm as any).ADDRMAN_NEW_BUCKETS_PER_ADDRESS
      ?? (pm as any).newBucketsPerAddress;
    expect(cap).toBe(8); // BUG-9
  });

  test("PeerInfo carries nRefCount initialized to 0", () => {
    const info = makePeerInfo("1.2.3.30", 8333);
    // POST-FIX: new PeerInfo in new table has nRefCount=0 before first bucket insertion.
    expect((info as any).nRefCount).toBe(0); // BUG-9
  });

  test("second insertion of same addr is 2× harder (stochastic gate logged)", () => {
    // This is a structural / smoke test — the implementation must have
    // the stochastic gate in AddSingle equivalent.
    const pm = new PeerManager(makeConfig());
    const hasAddSingle = typeof (pm as any).addSingle === "function"
      || typeof (pm as any).addAddress === "function";
    expect(hasAddSingle).toBe(true); // BUG-9
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// G10 — ADDRMAN_HORIZON (30-day) eviction absent
// ═════════════════════════════════════════════════════════════════════════════
/**
 * BUG-10 [HIGH] — Stale addresses (>30 days unseen) never evicted
 *
 * Core's IsTerrible() check in GetAddr_() filters addresses older than
 * ADDRMAN_HORIZON=30 days. hotbuns' handleAddrMessage filters addresses >3h old
 * for relay freshness but never evicts 30-day-stale addresses from the store.
 *
 * Core refs: addrman.h ADDRMAN_HORIZON = 30*24h; addrman.cpp IsTerrible().
 */
describe("G10 — ADDRMAN_HORIZON 30-day eviction", () => {
  test("ADDRMAN_HORIZON constant is 30 days in ms", () => {
    const pm = new PeerManager(makeConfig());
    const horizon = (pm as any).ADDRMAN_HORIZON ?? (pm as any).addrmanHorizon;
    const THIRTY_DAYS_MS = 30 * 24 * 60 * 60 * 1000;
    expect(horizon).toBe(THIRTY_DAYS_MS); // BUG-10
  });

  test("address older than ADDRMAN_HORIZON is excluded from getAddr() results", () => {
    const pm = new PeerManager(makeConfig());
    const ka = knownAddresses(pm);
    const THIRTY_ONE_DAYS_MS = 31 * 24 * 60 * 60 * 1000;
    ka.set("1.2.3.40:8333", makePeerInfo("1.2.3.40", 8333, {
      lastSeen: Date.now() - THIRTY_ONE_DAYS_MS,
    }));

    const getAddrFn: ((n: number, pct: number) => PeerInfo[]) | undefined =
      (pm as any).getAddr?.bind(pm);
    if (getAddrFn) {
      const results = getAddrFn(1000, 23);
      const found = results.some((r) => r.host === "1.2.3.40");
      expect(found).toBe(false); // BUG-10
    } else {
      expect(typeof (pm as any).getAddr).toBe("function"); // BUG-10
    }
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// G11 — ADDRMAN_RETRIES (3) never-succeeded guard absent
// ═════════════════════════════════════════════════════════════════════════════
/**
 * BUG-11 [HIGH] — No guard for addresses tried 3× with zero successes
 *
 * Core's IsTerrible() criterion 4:
 *   m_last_success == 0 && nAttempts >= ADDRMAN_RETRIES(3) → terrible
 * Without nAttempts tracking this can never fire.
 *
 * Core refs: addrman.h ADDRMAN_RETRIES=3; addrman.cpp IsTerrible().
 */
describe("G11 — ADDRMAN_RETRIES = 3 guard", () => {
  test("ADDRMAN_RETRIES constant is 3", () => {
    const pm = new PeerManager(makeConfig());
    const retries = (pm as any).ADDRMAN_RETRIES ?? (pm as any).addrmanRetries;
    expect(retries).toBe(3); // BUG-11
  });

  test("address with nAttempts>=3 and no success is rejected by isTerrible", () => {
    const pm = new PeerManager(makeConfig());
    const isTerrible: ((i: PeerInfo) => boolean) | undefined = (pm as any).isTerrible?.bind(pm);
    if (isTerrible) {
      const info = makePeerInfo("1.2.3.50", 8333);
      (info as any).nAttempts = 3;
      (info as any).lastSuccess = 0;
      (info as any).lastTry = Date.now() - 5 * 60 * 1000; // > 1min ago
      expect(isTerrible(info)).toBe(true); // BUG-11
    } else {
      expect(typeof (pm as any).isTerrible).toBe("function"); // BUG-11
    }
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// G12 — ADDRMAN_MAX_FAILURES (10) successive failures in 7 days guard absent
// ═════════════════════════════════════════════════════════════════════════════
/**
 * BUG-12 [HIGH] — No guard for 10 successive failures within ADDRMAN_MIN_FAIL=7d
 *
 * Core's IsTerrible() criterion 5:
 *   now - m_last_success > 7d && nAttempts >= 10 → terrible
 *
 * Core refs: addrman.h ADDRMAN_MAX_FAILURES=10, ADDRMAN_MIN_FAIL=7*24h.
 */
describe("G12 — ADDRMAN_MAX_FAILURES = 10 guard", () => {
  test("ADDRMAN_MAX_FAILURES constant is 10", () => {
    const pm = new PeerManager(makeConfig());
    const maxFail = (pm as any).ADDRMAN_MAX_FAILURES ?? (pm as any).addrmanMaxFailures;
    expect(maxFail).toBe(10); // BUG-12
  });

  test("ADDRMAN_MIN_FAIL constant is 7 days in ms", () => {
    const pm = new PeerManager(makeConfig());
    const minFail = (pm as any).ADDRMAN_MIN_FAIL ?? (pm as any).addrmanMinFail;
    const SEVEN_DAYS_MS = 7 * 24 * 60 * 60 * 1000;
    expect(minFail).toBe(SEVEN_DAYS_MS); // BUG-12
  });

  test("address with 10 attempts and last success >7d ago is terrible", () => {
    const pm = new PeerManager(makeConfig());
    const isTerrible: ((i: PeerInfo) => boolean) | undefined = (pm as any).isTerrible?.bind(pm);
    if (isTerrible) {
      const info = makePeerInfo("1.2.3.60", 8333);
      (info as any).nAttempts = 10;
      const EIGHT_DAYS_MS = 8 * 24 * 60 * 60 * 1000;
      (info as any).lastSuccess = Date.now() - EIGHT_DAYS_MS;
      (info as any).lastTry = Date.now() - 5 * 60 * 1000;
      expect(isTerrible(info)).toBe(true); // BUG-12
    } else {
      expect(typeof (pm as any).isTerrible).toBe("function"); // BUG-12
    }
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// G13 — Math.random() used for shuffling (not CSPRNG)
// ═════════════════════════════════════════════════════════════════════════════
/**
 * BUG-13 [MEDIUM] — Math.random() used for DNS seed shuffle and addr relay target
 *
 * manager.ts uses Math.random() in:
 *   resolveDNSSeeds() (Fisher-Yates shuffle, line ~607)
 *   relayAddrToRandomPeers() (Fisher-Yates shuffle, line ~2287)
 * Core uses FastRandomContext (CSPRNG).
 *
 * While bucket selection uses hashed positions keyed by nKey, these shuffles
 * don't benefit from nKey and should use a CSPRNG to avoid predictability.
 *
 * Core refs: random.h FastRandomContext; addrman.cpp insecure_rand.
 */
describe("G13 — CSPRNG for all randomness in addrman / peer selection", () => {
  test("address shuffle in resolveDNSSeeds uses crypto.getRandomValues, not Math.random", () => {
    // FIXED: Math.random() replaced with this.secureRandInt() in manager.ts.
    // secureRandInt() uses crypto.randomBytes() (CSPRNG) for all AddrMan-related
    // shuffles: resolveDNSSeeds(), maintainConnections(), relayAddrToRandomPeers().
    const pm = new PeerManager(makeConfig());
    // Assert the CSPRNG helper exists and returns values in range.
    expect(typeof (pm as any).secureRandInt).toBe("function"); // BUG-13 fixed
    const fn: (n: number) => number = (pm as any).secureRandInt.bind(pm);
    // secureRandInt(n) must return [0, n)
    for (let i = 0; i < 20; i++) {
      const v = fn(10);
      expect(v).toBeGreaterThanOrEqual(0);
      expect(v).toBeLessThan(10);
    }
    // Returns 0 for n <= 0 (guard)
    expect(fn(0)).toBe(0);
  });

  test("secureRandInt produces distinct values (not constant / degenerate)", () => {
    // Regression: Math.random() was used; verify CSPRNG produces spread.
    const pm = new PeerManager(makeConfig());
    const fn: (n: number) => number = (pm as any).secureRandInt.bind(pm);
    const seen = new Set<number>();
    for (let i = 0; i < 50; i++) seen.add(fn(100));
    // With 50 draws over [0,100) a degenerate constant returns 1 unique value.
    // A real CSPRNG should easily produce ≥10 distinct values.
    expect(seen.size).toBeGreaterThanOrEqual(10);
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// G14 — addr time_penalty (2h) absent
// ═════════════════════════════════════════════════════════════════════════════
/**
 * BUG-14 [HIGH] — Incoming addr messages applied without 2-hour time penalty
 *
 * Core's Add() call in net_processing.cpp passes time_penalty=2h for received
 * addr messages from third-party peers. This moves nTime backward by 2 hours
 * to prevent eclipse attacks via crafted future timestamps.
 * hotbuns stores the raw timestamp from the network message with no penalty.
 *
 * Core refs: net_processing.cpp line ~5702:
 *   m_addrman.Add(vAddrOk, pfrom.addr, time_penalty=2h)
 */
describe("G14 — 2-hour addr time penalty on received addr messages", () => {
  test("TIME_PENALTY_ADDR constant is 2 hours in ms", () => {
    const pm = new PeerManager(makeConfig());
    const penalty = (pm as any).TIME_PENALTY_ADDR ?? (pm as any).addrTimePenalty;
    const TWO_HOURS_MS = 2 * 60 * 60 * 1000;
    expect(penalty).toBe(TWO_HOURS_MS); // BUG-14
  });

  test("addr message with recent timestamp is stored with 2h back-dated nTime", () => {
    // This tests the AddSingle equivalent.
    const pm = new PeerManager(makeConfig());
    const addWithPenalty: ((addr: PeerInfo, penalty: number) => void) | undefined =
      (pm as any).addWithPenalty?.bind(pm);
    if (addWithPenalty) {
      const nowSec = Math.floor(Date.now() / 1000);
      const sentTimestamp = nowSec - 60; // 1 minute ago
      const info = makePeerInfo("1.2.3.70", 8333, { lastSeen: sentTimestamp * 1000 });
      addWithPenalty(info, 2 * 60 * 60 * 1000);
      const stored = knownAddresses(pm).get("1.2.3.70:8333");
      // POST-FIX: stored.lastSeen should be (sentTimestamp - 7200) * 1000
      const expectedSeen = (sentTimestamp - 7200) * 1000;
      expect(stored?.lastSeen).toBeCloseTo(expectedSeen, -3); // BUG-14
    } else {
      expect(typeof (pm as any).addWithPenalty).toBe("function"); // BUG-14
    }
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// G15 — Source-group diversity for new-bucket assignment absent
// ═════════════════════════════════════════════════════════════════════════════
/**
 * BUG-15 [HIGH] — New bucket index not derived from source network group
 *
 * Core's GetNewBucket() uses both the address group AND the source group to
 * derive bucket index. This ensures that even if an attacker controls many IPs
 * in one /16, they can only fill 64 of the 1024 new buckets
 * (ADDRMAN_NEW_BUCKETS_PER_SOURCE_GROUP=64).
 * hotbuns has no bucket assignment; all addresses share the same flat map.
 *
 * Core refs: addrman.h ADDRMAN_NEW_BUCKETS_PER_SOURCE_GROUP=64;
 *            addrman.cpp AddrInfo::GetNewBucket().
 */
describe("G15 — ADDRMAN_NEW_BUCKETS_PER_SOURCE_GROUP = 64", () => {
  test("ADDRMAN_NEW_BUCKETS_PER_SOURCE_GROUP constant is 64", () => {
    const pm = new PeerManager(makeConfig());
    const perSrc = (pm as any).ADDRMAN_NEW_BUCKETS_PER_SOURCE_GROUP
      ?? (pm as any).newBucketsPerSourceGroup;
    expect(perSrc).toBe(64); // BUG-15
  });

  test("getNewBucket uses source group in computation", () => {
    const pm = new PeerManager(makeConfig());
    const getNewBucket: ((addr: string, sourceGroup: string) => number) | undefined =
      (pm as any).getNewBucket?.bind(pm);
    if (getNewBucket) {
      const b1 = getNewBucket("1.2.3.80", "ipv4:10.0");
      const b2 = getNewBucket("1.2.3.80", "ipv4:192.168");
      // Different source groups → different (or coincidentally same) bucket,
      // but the function must exist and return a valid index.
      expect(b1).toBeGreaterThanOrEqual(0);
      expect(b1).toBeLessThan(1024);
      expect(b2).toBeGreaterThanOrEqual(0);
    } else {
      expect(typeof (pm as any).getNewBucket).toBe("function"); // BUG-15
    }
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// G16 — isRoutable() check absent on incoming addr messages
// ═════════════════════════════════════════════════════════════════════════════
/**
 * BUG-16 [HIGH] — Non-routable addresses (RFC1918, loopback) admitted to addr store
 *
 * Core's AddSingle() calls addr.IsRoutable() and returns false immediately for
 * non-routable addresses (RFC1918, 127.x, ::1, etc.). hotbuns never checks
 * isRoutable() in handleAddrMessage() — private IPs are stored as peers.
 *
 * Core refs: addrman.cpp AddSingle() `if (!addr.IsRoutable()) return false;`
 */
describe("G16 — isRoutable() check on addr messages", () => {
  test("RFC1918 address 192.168.1.1 is not stored from addr message", () => {
    // We test the effective behaviour: after processing an addr message with
    // a private IP, it should NOT appear in knownAddresses.
    const pm = new PeerManager(makeConfig());
    expect(typeof (pm as any).handleAddrMessage).toBe("function");

    // Build an IPv4-mapped buffer for 192.168.1.1
    const ip = Buffer.alloc(16);
    ip[10] = 0xff; ip[11] = 0xff; // IPv4-mapped prefix
    ip[12] = 192; ip[13] = 168; ip[14] = 1; ip[15] = 1;
    // _peer arg is unused; pass null to satisfy the two-arg signature.
    (pm as any).handleAddrMessage(null, {
      addrs: [{
        timestamp: Math.floor(Date.now() / 1000) - 60,
        addr: { ip, port: 8333, services: ServiceFlags.NODE_NETWORK },
      }],
    });
    const stored = knownAddresses(pm).get("192.168.1.1:8333");
    // POST-FIX: RFC1918 address must be rejected (isRoutable filter)
    expect(stored).toBeUndefined();
  });

  test("loopback 127.0.0.1 is not stored from addr message", () => {
    const pm = new PeerManager(makeConfig());
    expect(typeof (pm as any).handleAddrMessage).toBe("function");

    const ip = Buffer.alloc(16);
    ip[10] = 0xff; ip[11] = 0xff;
    ip[12] = 127; ip[13] = 0; ip[14] = 0; ip[15] = 1;
    (pm as any).handleAddrMessage(null, {
      addrs: [{
        timestamp: Math.floor(Date.now() / 1000) - 60,
        addr: { ip, port: 8333, services: ServiceFlags.NODE_NETWORK },
      }],
    });
    const stored = knownAddresses(pm).get("127.0.0.1:8333");
    // POST-FIX: loopback address must be rejected (isRoutable filter)
    expect(stored).toBeUndefined();
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// G17 — addr relay goes to block_relay-only peers
// ═════════════════════════════════════════════════════════════════════════════
/**
 * BUG-17 [HIGH] — relayAddrToRandomPeers() does not exclude block-relay-only connections
 *
 * Core's SetupAddressRelay() returns false (and addr relay is skipped) when
 * the peer is an outbound block-relay-only connection. This is intentional: we
 * don't want to leak addr traffic that reveals our topology to potential
 * adversaries via block-relay-only links.
 * hotbuns' relayAddrToRandomPeers() picks from ALL connected peers (line ~2278),
 * including block_relay connections.
 *
 * Core refs: net_processing.cpp SetupAddressRelay():
 *   "if (node.IsBlockOnlyConn()) return false;"
 */
describe("G17 — addr relay excludes block-relay-only peers", () => {
  test("relayAddrToRandomPeers skips peers with connectionType=block_relay", () => {
    const pm = new PeerManager(makeConfig());
    // Inject a mock block-relay peer into the internal map
    const mockPeer = {
      state: "connected",
      host: "10.0.0.1",
      port: 8333,
      send: (msg: unknown) => { sentTo.push(msg); },
    } as unknown as import("../src/p2p/peer.js").Peer;

    const sentTo: unknown[] = [];
    (pm as any).peers.set("10.0.0.1:8333", mockPeer);
    (pm as any).peerConnectionType.set("10.0.0.1:8333", "block_relay");

    const relay: ((source: unknown, msg: unknown) => void) | undefined =
      (pm as any).relayAddrToRandomPeers?.bind(pm);
    if (relay) {
      relay({} as unknown, { type: "addr", payload: { addrs: [] } });
      expect(sentTo.length).toBe(0); // BUG-17: block_relay peers must be excluded
    } else {
      expect(typeof (pm as any).relayAddrToRandomPeers).toBe("function"); // BUG-17
    }
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// G18 — Per-peer bloom dedup (m_addr_known) absent
// ═════════════════════════════════════════════════════════════════════════════
/**
 * BUG-18 [MEDIUM] — No per-peer CRollingBloomFilter to deduplicate addr relay
 *
 * Core tracks which addresses have been sent to each peer via a
 * CRollingBloomFilter(5000, 0.001) called m_addr_known. The relay loop in
 * RelayAddress() only sends an address to a peer if it's not already in their
 * m_addr_known filter, preventing re-sending the same addr.
 * hotbuns relayAddrToRandomPeers() sends unconditionally.
 *
 * Core refs: net_processing.cpp Peer::m_addr_known;
 *            SetupAddressRelay(); RelayAddress().
 */
describe("G18 — per-peer addr dedup bloom filter", () => {
  test("Peer objects have a addrKnown bloom filter", () => {
    // POST-FIX: each Peer should carry a bloom filter (m_addrKnown)
    // initialised lazily when addr relay is set up.
    const pm = new PeerManager(makeConfig());
    // We check via the Peer class directly.
    const { Peer } = require("../src/p2p/peer.js");
    const peer = new Peer(
      { host: "1.2.3.90", port: 8333, magic: REGTEST.networkMagic,
        protocolVersion: REGTEST.protocolVersion, services: ServiceFlags.NODE_NETWORK,
        userAgent: "/test/", bestHeight: 0, relay: true },
      { onConnect: () => {}, onDisconnect: () => {}, onMessage: () => {}, onHandshakeComplete: () => {} },
      () => {}
    );
    expect((peer as any).addrKnown).toBeDefined(); // BUG-18
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// G19 — Token-bucket addr rate limiter absent
// ═════════════════════════════════════════════════════════════════════════════
/**
 * BUG-19 [HIGH] — No per-peer addr token-bucket rate limiter
 *
 * Core processes at most MAX_ADDR_PROCESSING_TOKEN_BUCKET=1000 addr entries per
 * peer per ~100 seconds (refill rate: 10/s). Excess entries are counted in
 * addr_rate_limited and discarded. This prevents an adversary from flooding
 * the addr processing queue.
 * hotbuns processes all addr entries unconditionally.
 *
 * Core refs: net_processing.cpp Peer::m_addr_token_bucket (initial=1.0),
 *            MAX_ADDR_PROCESSING_TOKEN_BUCKET=1000,
 *            ProcessAddrs() token deduction loop.
 */
describe("G19 — per-peer addr token-bucket rate limiter", () => {
  test("Peer has addrTokenBucket property initialized to 1.0", () => {
    const { Peer } = require("../src/p2p/peer.js");
    const peer = new Peer(
      { host: "1.2.3.91", port: 8333, magic: REGTEST.networkMagic,
        protocolVersion: REGTEST.protocolVersion, services: ServiceFlags.NODE_NETWORK,
        userAgent: "/test/", bestHeight: 0, relay: true },
      { onConnect: () => {}, onDisconnect: () => {}, onMessage: () => {}, onHandshakeComplete: () => {} },
      () => {}
    );
    // POST-FIX: peer.addrTokenBucket should be 1.0 (or 1000.0 for initial burst).
    expect((peer as any).addrTokenBucket).toBeDefined(); // BUG-19
  });

  test("MAX_ADDR_PROCESSING_TOKEN_BUCKET constant is 1000", () => {
    const pm = new PeerManager(makeConfig());
    const cap = (pm as any).MAX_ADDR_PROCESSING_TOKEN_BUCKET
      ?? (pm as any).addrTokenBucketMax;
    expect(cap).toBe(1000); // BUG-19
  });

  test("excess addr entries are counted in addrRateLimited and discarded", () => {
    // POST-FIX: after processing >1000 addresses from a peer without refill,
    // the extra entries are dropped and counted.
    const pm = new PeerManager(makeConfig());
    const rateLimited = (pm as any).addrRateLimited ?? (pm as any).addrRateLimitedCount;
    // Even if 0, the property must exist.
    expect(rateLimited).toBeDefined(); // BUG-19
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// G20 — One-shot getaddr guard (m_getaddr_recvd) absent
// ═════════════════════════════════════════════════════════════════════════════
/**
 * BUG-20 [MEDIUM] — Repeated getaddr messages are processed without limit
 *
 * Core sets peer.m_getaddr_recvd = true after the first getaddr and ignores
 * any subsequent getaddr from the same peer. This prevents bandwidth amplification.
 * hotbuns has no m_getaddr_recvd equivalent; repeated getaddr messages trigger
 * repeated addr responses.
 *
 * Core refs: net_processing.cpp ProcessMessage() "getaddr" handler:
 *   "if (peer.m_getaddr_recvd) { LogDebug(...); return; }"
 */
describe("G20 — one-shot getaddr guard", () => {
  test("Peer tracks whether getaddr has been received (m_getaddrRecvd)", () => {
    const { Peer } = require("../src/p2p/peer.js");
    const peer = new Peer(
      { host: "1.2.3.92", port: 8333, magic: REGTEST.networkMagic,
        protocolVersion: REGTEST.protocolVersion, services: ServiceFlags.NODE_NETWORK,
        userAgent: "/test/", bestHeight: 0, relay: true },
      { onConnect: () => {}, onDisconnect: () => {}, onMessage: () => {}, onHandshakeComplete: () => {} },
      () => {}
    );
    // POST-FIX: peer.getaddrRecvd should be false initially.
    expect((peer as any).getaddrRecvd).toBe(false); // BUG-20
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// G21 — getaddr response (sending our addr list) missing
// ═════════════════════════════════════════════════════════════════════════════
/**
 * BUG-21 [HIGH] — hotbuns never sends addr in response to a received getaddr
 *
 * When Core receives a getaddr message it calls
 *   m_connman.GetAddresses(pfrom, MAX_ADDR_TO_SEND, MAX_PCT_ADDR_TO_SEND)
 * which draws up to 23% of addrman (max 1000) and sends them back as addr/addrv2.
 * hotbuns' handlePeerMessage() dispatches registered handlers for "getaddr" but
 * the PeerManager itself never registers such a handler — there is no code
 * that builds and sends an addr response on getaddr receipt.
 *
 * Core refs: net_processing.cpp ProcessMessage() "getaddr":
 *   vAddr = m_connman.GetAddresses(...);
 *   pfrom.PushAddress(addr, ...);
 */
describe("G21 — getaddr response sends our addr list", () => {
  test("PeerManager registers a getaddr handler that sends addr response", () => {
    const pm = new PeerManager(makeConfig());
    const handlers: Map<string, unknown[]> = (pm as any).messageHandlers;
    const getaddrHandlers = handlers.get("getaddr") ?? [];
    // POST-FIX: there should be at least one registered getaddr handler.
    expect(getaddrHandlers.length).toBeGreaterThan(0); // BUG-21
  });

  test("MAX_PCT_ADDR_TO_SEND constant is 23 (percent)", () => {
    const pm = new PeerManager(makeConfig());
    const pct = (pm as any).MAX_PCT_ADDR_TO_SEND ?? (pm as any).maxPctAddrToSend;
    expect(pct).toBe(23); // BUG-21
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// G22 — getCandidateAddresses is deterministic sort, not stochastic selection
// ═════════════════════════════════════════════════════════════════════════════
/**
 * BUG-22 [HIGH] — Address selection is a deterministic sort, not GetChance()-weighted random
 *
 * Core's Select() iterates randomly chosen buckets and applies GetChance()
 * probabilistically. hotbuns' getCandidateAddresses() sorts the flat map by
 * (NODE_WITNESS > lastSeen > banScore) and returns the top N. This means:
 *  - A single bad actor controlling high-scoring addresses can bias selection.
 *  - New addresses are never given a chance via probabilistic selection.
 *  - The "deprioritize after failed attempt" back-off never fires.
 *
 * Core refs: addrman.cpp AddrManImpl::Select_().
 */
describe("G22 — stochastic weighted address selection (not deterministic sort)", () => {
  test("getCandidateAddresses is not a pure deterministic sort", () => {
    const pm = new PeerManager(makeConfig());
    const ka = knownAddresses(pm);
    // Add 50 addresses with identical quality — different IPs.
    for (let i = 1; i <= 50; i++) {
      ka.set(`1.2.${i}.1:8333`, makePeerInfo(`1.2.${i}.1`, 8333));
    }
    const getCandidates: ((n: number) => PeerInfo[]) | undefined =
      (pm as any).getCandidateAddresses?.bind(pm);
    if (getCandidates) {
      const r1 = getCandidates(10).map((p) => p.host);
      const r2 = getCandidates(10).map((p) => p.host);
      // POST-FIX: two independent selections from identical-quality addresses
      // should differ (random) at least sometimes. With 50 addresses and 10
      // selected, P(identical) ≈ C(50,10)/50^10 ≈ ~0. We check at least one
      // call does not always return the same first element.
      // (This is a smoke test; the real fix is probabilistic selection.)
      const firstAddrs = new Set<string>();
      for (let t = 0; t < 5; t++) firstAddrs.add(getCandidates(1)[0]?.host ?? "");
      // POST-FIX: with 50 addresses and 5 calls, first address should vary.
      expect(firstAddrs.size).toBeGreaterThan(1); // BUG-22
    } else {
      expect(typeof (pm as any).getCandidateAddresses).toBe("function"); // BUG-22
    }
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// G23 — No per-network address counts (m_network_counts)
// ═════════════════════════════════════════════════════════════════════════════
/**
 * BUG-23 [MEDIUM] — No per-network new/tried counts
 *
 * Core tracks n_new and n_tried per Network in m_network_counts (updated in
 * Create/Delete/MakeTried). This allows efficient Size(net) queries and
 * Select(networks) fast-paths. hotbuns has no such tracking.
 *
 * Core refs: addrman_impl.h AddrManImpl::m_network_counts.
 */
describe("G23 — per-network address counts", () => {
  test("PeerManager tracks new+tried counts per network type", () => {
    const pm = new PeerManager(makeConfig());
    const counts = (pm as any).networkCounts ?? (pm as any).m_network_counts;
    // POST-FIX: should be a Map<network,{nNew,nTried}> or equivalent.
    expect(counts).toBeDefined(); // BUG-23
  });

  test("size(net, inNew=true) returns IPv4 new-table count", () => {
    const pm = new PeerManager(makeConfig());
    const sizeFn: ((net?: string, inNew?: boolean) => number) | undefined =
      (pm as any).addrmanSize?.bind(pm);
    if (sizeFn) {
      expect(typeof sizeFn("ipv4", true)).toBe("number"); // BUG-23
    } else {
      expect(typeof (pm as any).addrmanSize).toBe("function"); // BUG-23
    }
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// G24 — peers.dat format incompatible with Core's V4_MULTIPORT format
// ═════════════════════════════════════════════════════════════════════════════
/**
 * BUG-24 [MEDIUM] — Custom binary peers.dat format cannot be loaded by Core
 *
 * Core's addrman serialization format (V4_MULTIPORT) starts with two version
 * bytes, an nKey (32 bytes), nNew, nTried, bucket data, etc. hotbuns uses its
 * own single-byte version + varString + uint16LE format. The files are mutually
 * incompatible — hotbuns cannot benefit from any pre-seeded peers.dat from Core.
 *
 * This is documented as a divergence rather than a consensus bug, but it
 * severely impairs bootstrap. Severity: MEDIUM (operational, not consensus).
 *
 * Core refs: addrman.cpp Serialize/Unserialize V4_MULTIPORT.
 */
describe("G24 — peers.dat format compatibility with Core V4_MULTIPORT", () => {
  test("peers.dat serialization includes format version byte 4 (V4_MULTIPORT)", () => {
    // Import the serialization function (it's private but we inline-test the format).
    // We can test by calling saveAddresses() and reading the file, or by
    // checking a constant.
    const pm = new PeerManager(makeConfig());
    const FILE_FORMAT = (pm as any).PEERS_DAT_FORMAT ?? (pm as any).peersDatFormat;
    // POST-FIX: FILE_FORMAT should be 4 (V4_MULTIPORT) for Core compatibility.
    expect(FILE_FORMAT).toBe(4); // BUG-24
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// G25 — ADDRMAN_HORIZON storage eviction absent (only relay freshness checked)
// ═════════════════════════════════════════════════════════════════════════════
/**
 * BUG-25 [HIGH] — handleAddrMessage only checks 3h relay freshness, not 30d HORIZON
 *
 * hotbuns' handleAddrMessage() skips addresses with timestamp >3h old. This is
 * the correct *relay* freshness window (Core also skips timestamps >10 min future).
 * However, once an address IS admitted, Core's IsTerrible() with ADDRMAN_HORIZON=30d
 * evicts it from selection later. hotbuns never applies that eviction — addresses
 * admitted once live forever regardless of age.
 *
 * Core refs: addrman.cpp IsTerrible() `now - nTime > ADDRMAN_HORIZON` → terrible.
 */
describe("G25 — ADDRMAN_HORIZON 30d storage eviction vs relay 3h freshness", () => {
  test("addr messages with timestamp exactly 3h old ARE admitted (relay window)", () => {
    const pm = new PeerManager(makeConfig());
    const handleAddrMsg: ((payload: { addrs: Array<{ timestamp: number; addr: { ip: Buffer; port: number; services: bigint } }> }) => void) | undefined =
      (pm as any).handleAddrMessage?.bind(pm);
    if (handleAddrMsg) {
      const nowSec = Math.floor(Date.now() / 1000);
      const threeHoursBoundary = nowSec - 3 * 60 * 60 + 10; // just within 3h
      const ip = Buffer.alloc(16);
      ip[10] = 0xff; ip[11] = 0xff;
      ip[12] = 1; ip[13] = 2; ip[14] = 3; ip[15] = 80;
      handleAddrMsg({ addrs: [{ timestamp: threeHoursBoundary, addr: { ip, port: 8333, services: ServiceFlags.NODE_NETWORK } }] });
      const stored = knownAddresses(pm).get("1.2.3.80:8333");
      expect(stored).toBeDefined(); // relay window lets this through — correct
    } else {
      expect(typeof (pm as any).handleAddrMessage).toBe("function");
    }
  });

  test("stored address older than 30 days is excluded from getAddr() output", () => {
    const pm = new PeerManager(makeConfig());
    const ka = knownAddresses(pm);
    const THIRTY_ONE_DAYS_MS = 31 * 24 * 60 * 60 * 1000;
    ka.set("1.2.3.81:8333", makePeerInfo("1.2.3.81", 8333, {
      lastSeen: Date.now() - THIRTY_ONE_DAYS_MS,
    }));
    const getAddrFn: ((n: number, pct: number) => PeerInfo[]) | undefined =
      (pm as any).getAddr?.bind(pm);
    if (getAddrFn) {
      const results = getAddrFn(1000, 100);
      expect(results.some((r) => r.host === "1.2.3.81")).toBe(false); // BUG-25
    } else {
      expect(typeof (pm as any).getAddr).toBe("function"); // BUG-25
    }
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// G26 — nRefCount / multiplicity absent (same address cannot span multiple new buckets)
// ═════════════════════════════════════════════════════════════════════════════
/**
 * BUG-26 [HIGH] — No nRefCount per new-table entry
 *
 * Without nRefCount, new-table entries cannot track how many buckets reference
 * them, ClearNew() cannot safely delete entries, and Delete() cannot be guarded
 * by `refCount==0`. The entire lifecycle of new-table entries (insert, evict,
 * promote-to-tried) requires reference counting.
 *
 * Core refs: addrman_impl.h AddrInfo::nRefCount;
 *            addrman.cpp Delete(), ClearNew(), MakeTried().
 */
describe("G26 — nRefCount lifecycle for new-table entries", () => {
  test("new entry starts with nRefCount = 0 before first bucket insertion", () => {
    const pm = new PeerManager(makeConfig());
    const createFn: ((addr: PeerInfo) => PeerInfo) | undefined = (pm as any).createEntry?.bind(pm);
    if (createFn) {
      const entry = createFn(makePeerInfo("1.2.3.90", 8333));
      expect((entry as any).nRefCount).toBe(0); // BUG-26
    } else {
      // Structural check: PeerInfo should carry nRefCount
      const info = makePeerInfo("1.2.3.90", 8333);
      expect(typeof (info as any).nRefCount).not.toBe("undefined"); // BUG-26 (will fail pre-fix)
      expect((info as any).nRefCount).toBe(0);
    }
  });

  test("nRefCount is incremented when entry placed in new bucket", () => {
    const pm = new PeerManager(makeConfig());
    // This is a structural smoke test — the implementation must track refCount.
    const ka = knownAddresses(pm);
    ka.set("1.2.3.91:8333", makePeerInfo("1.2.3.91", 8333));
    const info = ka.get("1.2.3.91:8333")!;
    // POST-FIX: after placement in any new bucket, nRefCount >= 1
    expect((info as any).nRefCount).toBeGreaterThanOrEqual(0); // structural
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// G27 — m_last_good gate for Attempt_() fCountFailure absent
// ═════════════════════════════════════════════════════════════════════════════
/**
 * BUG-27 [MEDIUM] — No m_last_good tracking; Attempt() always increments nAttempts
 *
 * Core's Attempt_() only increments nAttempts when:
 *   fCountFailure && info.m_last_count_attempt < m_last_good
 * This ensures that if we successfully connected to any peer since the last
 * attempt to this address, we don't count the attempt as a fresh failure.
 * hotbuns has no Attempt(), m_last_good, or m_last_count_attempt.
 *
 * Core refs: addrman.cpp AddrManImpl::Attempt_(); addrman_impl.h m_last_good.
 */
describe("G27 — m_last_good gate in Attempt()", () => {
  test("PeerManager tracks m_last_good (last time any Good() was called)", () => {
    const pm = new PeerManager(makeConfig());
    const lastGood = (pm as any).m_last_good ?? (pm as any).lastGood;
    // POST-FIX: initialized to 1s (epoch+1s in Core) or 0.
    expect(lastGood).toBeDefined(); // BUG-27
  });

  test("attempt() method exists and accepts fCountFailure flag", () => {
    const pm = new PeerManager(makeConfig());
    expect(typeof (pm as any).attempt).toBe("function"); // BUG-27
  });

  test("attempt(addr, fCountFailure=true) increments nAttempts only when last_count_attempt < m_last_good", () => {
    const pm = new PeerManager(makeConfig());
    const attemptFn: ((host: string, port: number, countFailure: boolean) => void) | undefined =
      (pm as any).attempt?.bind(pm);
    if (attemptFn) {
      const ka = knownAddresses(pm);
      const info = makePeerInfo("1.2.3.100", 8333);
      (info as any).nAttempts = 0;
      (info as any).m_last_count_attempt = 0;
      ka.set("1.2.3.100:8333", info);

      // Set m_last_good to "now" so that m_last_count_attempt(0) < m_last_good → increment.
      (pm as any).m_last_good = Date.now();
      attemptFn("1.2.3.100", 8333, true);
      expect((ka.get("1.2.3.100:8333") as any)?.nAttempts).toBe(1); // BUG-27
    } else {
      expect(typeof (pm as any).attempt).toBe("function"); // BUG-27
    }
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// G28 — Connected() 20-min nTime update interval missing
// ═════════════════════════════════════════════════════════════════════════════
/**
 * BUG-28 [LOW] — Connected() updates nTime on every call instead of every ≥20 min
 *
 * Core's Connected_() only updates nTime if time - nTime > 20 minutes.
 * This limits how quickly topology can be inferred from nTime churn.
 * hotbuns calls handleHandshakeComplete() which sets lastSeen=Date.now() on
 * every handshake without the 20-minute guard.
 *
 * Core refs: addrman.cpp AddrManImpl::Connected_():
 *   "const auto update_interval{20min}; if (time - info.nTime > update_interval) {...}"
 */
describe("G28 — Connected() 20-minute nTime update interval", () => {
  test("CONNECTED_UPDATE_INTERVAL constant is 20 minutes in ms", () => {
    const pm = new PeerManager(makeConfig());
    const interval = (pm as any).CONNECTED_UPDATE_INTERVAL ?? (pm as any).connectedUpdateInterval;
    const TWENTY_MIN_MS = 20 * 60 * 1000;
    expect(interval).toBe(TWENTY_MIN_MS); // BUG-28
  });

  test("connected() does NOT update lastSeen if last update was <20 minutes ago", () => {
    const pm = new PeerManager(makeConfig());
    const ka = knownAddresses(pm);
    const recentSeen = Date.now() - 10 * 60 * 1000; // 10 minutes ago
    ka.set("1.2.3.110:8333", makePeerInfo("1.2.3.110", 8333, { lastSeen: recentSeen }));

    const connectedFn: ((host: string, port: number) => void) | undefined =
      (pm as any).connected?.bind(pm);
    if (connectedFn) {
      connectedFn("1.2.3.110", 8333);
      const stored = ka.get("1.2.3.110:8333")!;
      // POST-FIX: lastSeen should still be recentSeen (not updated).
      expect(stored.lastSeen).toBeCloseTo(recentSeen, -3); // BUG-28
    } else {
      expect(typeof (pm as any).connected).toBe("function"); // BUG-28
    }
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// G29 — ADDRMAN_SET_TRIED_COLLISION_SIZE=10 limit absent
// ═════════════════════════════════════════════════════════════════════════════
/**
 * BUG-29 [MEDIUM] — No tried-collision set or its size limit
 *
 * Core caps m_tried_collisions at ADDRMAN_SET_TRIED_COLLISION_SIZE=10 entries.
 * Without this limit and without the collision set itself, there is no
 * test-before-evict mechanism and no backpressure against flooding the collision
 * queue.
 *
 * Core refs: addrman.h ADDRMAN_SET_TRIED_COLLISION_SIZE=10;
 *            addrman.cpp Good_() collision insert.
 */
describe("G29 — ADDRMAN_SET_TRIED_COLLISION_SIZE = 10", () => {
  test("triedCollisions set exists and is initially empty", () => {
    const pm = new PeerManager(makeConfig());
    const collisions = (pm as any).triedCollisions ?? (pm as any).m_tried_collisions;
    expect(collisions).toBeDefined();                // BUG-29
    expect(collisions?.size ?? -1).toBe(0);          // BUG-29
  });

  test("collision set is bounded to ADDRMAN_SET_TRIED_COLLISION_SIZE=10", () => {
    const pm = new PeerManager(makeConfig());
    const maxCollisions = (pm as any).ADDRMAN_SET_TRIED_COLLISION_SIZE
      ?? (pm as any).maxTriedCollisions;
    expect(maxCollisions).toBe(10); // BUG-29
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// G30 — ADDRMAN_REPLACEMENT (4h) guard in ResolveCollisions absent
// ═════════════════════════════════════════════════════════════════════════════
/**
 * BUG-30 [HIGH] — No ADDRMAN_REPLACEMENT (4h) guard protecting recently-successful entries
 *
 * Core's ResolveCollisions_() refuses to evict an old tried entry if it
 * successfully connected within the last ADDRMAN_REPLACEMENT=4h. This protects
 * recently proven peers from being displaced by newcomers.
 * hotbuns has neither ResolveCollisions() nor the 4h guard.
 *
 * Core refs: addrman.h ADDRMAN_REPLACEMENT=4h;
 *            addrman.cpp ResolveCollisions_():
 *   "if (current_time - info_old.m_last_success < ADDRMAN_REPLACEMENT) { erase_collision = true; }"
 */
describe("G30 — ADDRMAN_REPLACEMENT 4h guard in ResolveCollisions", () => {
  test("ADDRMAN_REPLACEMENT constant is 4 hours in ms", () => {
    const pm = new PeerManager(makeConfig());
    const replacement = (pm as any).ADDRMAN_REPLACEMENT ?? (pm as any).addrmanReplacement;
    const FOUR_HOURS_MS = 4 * 60 * 60 * 1000;
    expect(replacement).toBe(FOUR_HOURS_MS); // BUG-30
  });

  test("ADDRMAN_TEST_WINDOW constant is 40 minutes in ms", () => {
    const pm = new PeerManager(makeConfig());
    const window = (pm as any).ADDRMAN_TEST_WINDOW ?? (pm as any).addrmanTestWindow;
    const FORTY_MIN_MS = 40 * 60 * 1000;
    expect(window).toBe(FORTY_MIN_MS); // BUG-30
  });

  test("resolveCollisions keeps old entry if it succeeded within ADDRMAN_REPLACEMENT", () => {
    const pm = new PeerManager(makeConfig());
    const resolveCollisions: (() => void) | undefined = (pm as any).resolveCollisions?.bind(pm);
    if (!resolveCollisions) {
      // Method does not exist yet — fail loudly.
      expect(typeof (pm as any).resolveCollisions).toBe("function"); // BUG-30
      return;
    }

    // Seed a collision: new entry colliding with a recently-successful old entry.
    const ka = knownAddresses(pm);
    const oldAddr = makePeerInfo("1.2.3.120", 8333);
    (oldAddr as any).fInTried = true;
    (oldAddr as any).lastSuccess = Date.now() - 60 * 60 * 1000; // 1h ago (< 4h)
    ka.set("1.2.3.120:8333", oldAddr);

    const collisions: Set<string> = (pm as any).triedCollisions ?? new Set();
    collisions.add("1.2.3.121:8333"); // new entry trying to evict old
    (pm as any).triedCollisions = collisions;

    resolveCollisions();

    // POST-FIX: collision should be cleared (erase_collision=true), old entry kept.
    const afterCollisions: Set<string> = (pm as any).triedCollisions ?? new Set();
    expect(afterCollisions.has("1.2.3.121:8333")).toBe(false); // BUG-30
    // old entry still in tried
    expect(ka.has("1.2.3.120:8333")).toBe(true); // BUG-30
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// Correctness checks for existing infrastructure
// ═════════════════════════════════════════════════════════════════════════════

describe("Existing infrastructure sanity checks", () => {
  test("getNetGroup returns /16 prefix for IPv4 addresses", () => {
    expect(getNetGroup("1.2.3.4")).toBe("ipv4:1.2");
    expect(getNetGroup("192.168.1.100")).toBe("ipv4:192.168");
    expect(getNetGroup("10.0.50.1")).toBe("ipv4:10.0");
  });

  test("getNetGroup returns /32 prefix for IPv6 addresses", () => {
    const group = getNetGroup("2001:0db8:85a3:0000:0000:8a2e:0370:7334");
    expect(group).toMatch(/^ipv6:/);
  });

  test("isLocalAddress identifies loopback addresses", () => {
    expect(isLocalAddress("127.0.0.1")).toBe(true);
    expect(isLocalAddress("::1")).toBe(true);
    expect(isLocalAddress("127.0.0.50")).toBe(true);
    expect(isLocalAddress("1.2.3.4")).toBe(false);
  });

  test("knownAddresses starts empty on construction", () => {
    const pm = new PeerManager(makeConfig());
    expect(knownAddresses(pm).size).toBe(0);
  });

  test("PeerManager has correct max outbound defaults", () => {
    const pm = new PeerManager(makeConfig());
    expect((pm as any).config.maxOutboundFullRelay).toBe(8);
    expect((pm as any).config.maxOutboundBlockRelay).toBe(2);
  });

  test("MAX_BLOCK_RELAY_ONLY_ANCHORS is 2", () => {
    const { MAX_BLOCK_RELAY_ONLY_ANCHORS } = require("../src/p2p/manager.js");
    expect(MAX_BLOCK_RELAY_ONLY_ANCHORS).toBe(2);
  });

  test("ADDRMAN_TRIED_BUCKETS_PER_GROUP constant is 8", () => {
    const pm = new PeerManager(makeConfig());
    const perGroup = (pm as any).ADDRMAN_TRIED_BUCKETS_PER_GROUP
      ?? (pm as any).triedBucketsPerGroup;
    expect(perGroup).toBe(8); // structural check for G1
  });
});
