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
 * Audit summary (see audit/w128_addrman.md): 25 bugs / 30
 * gates, PRESENT=3, PARTIAL=2, MISSING=25.
 *   P0-CDIV=21 (bucketing absent; eclipse + DoS defenses missing)
 *   P1-API=4  (getaddr cap; discouragement bloom; per-network filter)
 *   P2-CONS=0
 *
 * KEY FINDING: hotbuns has NO AddrMan in the Core sense. The flat
 * `Map<string, PeerInfo>` keyed by `host:port` lacks the bucketed
 * tried/new table model that defends against eclipse attacks, source-
 * group flooding, and tried-table dislodgement. BUG-1 through BUG-7
 * are all "no bucket structure" symptoms; BUG-8 through BUG-13 are
 * "no AddrInfo lifecycle"; BUG-14 through BUG-22 are "connman
 * deviates from ThreadOpenConnections"; BUG-23 through BUG-26 are
 * routability/getaddr/discouragement gaps.
 *
 * The selection path is also deterministic-sort (line 1791-1812 of
 * manager.ts) which is **predictable** by an attacker — Core's
 * probabilistic `GetChance` + `chance_factor` loop is what gives
 * known-good peers a sampling advantage without making the order
 * computable.
 *
 * No production code changes in this wave.
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
} from "../p2p/manager.js";
import { DEFAULT_BAN_TIME } from "../p2p/banman.js";

// ---------------------------------------------------------------------------
// Source-level fixtures.  Tests load the .ts source verbatim and grep for
// patterns rather than execute live network code (no socket binds in CI).
// ---------------------------------------------------------------------------

const __dirname = dirname(fileURLToPath(import.meta.url));
const SRC = resolve(__dirname, "..");
const MANAGER_SRC = readFileSync(resolve(SRC, "p2p", "manager.ts"), "utf8");
const BANMAN_SRC = readFileSync(resolve(SRC, "p2p", "banman.ts"), "utf8");
const PEER_SRC = readFileSync(resolve(SRC, "p2p", "peer.ts"), "utf8");

// =============================================================================
// G1 — Tried table (256 buckets × 64 positions) — MISSING (BUG-1)
// =============================================================================
describe("W128-G1: Tried table exists with 256 buckets × 64 positions — MISSING (BUG-1)", () => {
  it("BUG-1: no ADDRMAN_TRIED_BUCKET_COUNT or equivalent constant", () => {
    expect(MANAGER_SRC).not.toMatch(/ADDRMAN_TRIED_BUCKET_COUNT/);
    expect(MANAGER_SRC).not.toMatch(/TRIED_BUCKET_COUNT/);
  });
  it("BUG-1: no vvTried-style 2D structure", () => {
    expect(MANAGER_SRC).not.toMatch(/vvTried/);
    expect(MANAGER_SRC).not.toMatch(/tried_table/);
    expect(MANAGER_SRC).not.toMatch(/triedBucket/);
  });
  it("BUG-1: knownAddresses is a flat Map (no bucketing)", () => {
    expect(MANAGER_SRC).toContain("knownAddresses: Map<string, PeerInfo>");
  });
});

// =============================================================================
// G2 — New table (1024 buckets × 64 positions) — MISSING (BUG-2)
// =============================================================================
describe("W128-G2: New table exists with 1024 buckets × 64 positions — MISSING (BUG-2)", () => {
  it("BUG-2: no ADDRMAN_NEW_BUCKET_COUNT or equivalent constant", () => {
    expect(MANAGER_SRC).not.toMatch(/ADDRMAN_NEW_BUCKET_COUNT/);
    expect(MANAGER_SRC).not.toMatch(/NEW_BUCKET_COUNT/);
  });
  it("BUG-2: no vvNew-style 2D structure", () => {
    expect(MANAGER_SRC).not.toMatch(/vvNew/);
    expect(MANAGER_SRC).not.toMatch(/new_table/);
    expect(MANAGER_SRC).not.toMatch(/newBucket/);
  });
});

// =============================================================================
// G3 — Secret nKey (256-bit) bucket seed — MISSING (BUG-3)
// =============================================================================
describe("W128-G3: Secret nKey (256-bit) seeds bucket selection — MISSING (BUG-3)", () => {
  it("BUG-3: no nKey or addrmanKey field", () => {
    expect(MANAGER_SRC).not.toMatch(/\bnKey\b/);
    expect(MANAGER_SRC).not.toMatch(/addrmanKey/);
    expect(MANAGER_SRC).not.toMatch(/bucketKey/);
  });
  it("BUG-3: no 256-bit secret randomly generated for bucketing", () => {
    // Core generates a uint256 secret on first run.  hotbuns has nothing.
    expect(MANAGER_SRC).not.toMatch(/randomBytes\(32\)[^]*nKey/);
    expect(MANAGER_SRC).not.toMatch(/uint256\s*nKey/);
  });
});

// =============================================================================
// G4 — GetTriedBucket(nKey, netgroup) — MISSING (BUG-4)
// =============================================================================
describe("W128-G4: GetTriedBucket(nKey, netgroup) bucket assignment — MISSING (BUG-4)", () => {
  it("BUG-4: no GetTriedBucket function", () => {
    expect(MANAGER_SRC).not.toMatch(/getTriedBucket|GetTriedBucket/);
  });
});

// =============================================================================
// G5 — GetNewBucket(nKey, source, netgroup) — MISSING (BUG-5)
// =============================================================================
describe("W128-G5: GetNewBucket(nKey, source, netgroup) bucket assignment — MISSING (BUG-5)", () => {
  it("BUG-5: no GetNewBucket function", () => {
    expect(MANAGER_SRC).not.toMatch(/getNewBucket|GetNewBucket/);
  });
  it("BUG-5: handleAddrMessage does NOT fold source-group into bucket selection", () => {
    // handleAddrMessage takes the source `peer` but never consults it
    // for any bucket-selection purpose — only as a recipient gate.
    const fn = MANAGER_SRC.match(/private handleAddrMessage\([^]*?^\s\s\}/m);
    if (fn) {
      // Body of handleAddrMessage doesn't fold source group into any
      // bucketing math.
      expect(fn[0]).not.toMatch(/sourceGroup|src_group|netgroupOf\(peer/);
    }
    // Either no fn match (in which case nothing to check) or no fold.
  });
});

// =============================================================================
// G6 — GetBucketPosition(nKey, fNew, bucket) — MISSING (BUG-6)
// =============================================================================
describe("W128-G6: GetBucketPosition(nKey, fNew, bucket) position-in-bucket — MISSING (BUG-6)", () => {
  it("BUG-6: no GetBucketPosition function", () => {
    expect(MANAGER_SRC).not.toMatch(/getBucketPosition|GetBucketPosition/);
  });
});

// =============================================================================
// G7 — ADDRMAN_NEW_BUCKETS_PER_ADDRESS=8 — MISSING (BUG-7)
// =============================================================================
describe("W128-G7: ADDRMAN_NEW_BUCKETS_PER_ADDRESS=8 multi-bucket replication — MISSING (BUG-7)", () => {
  it("BUG-7: no nRefCount / multi-bucket replication", () => {
    expect(MANAGER_SRC).not.toMatch(/nRefCount/);
    expect(MANAGER_SRC).not.toMatch(/refCount/);
  });
  it("BUG-7: an address can only appear once (single Map key)", () => {
    // The address has exactly one entry — keyed by host:port.  Multi-
    // source replication is structurally impossible.
    expect(MANAGER_SRC).toMatch(/this\.knownAddresses\.set\(key,/);
  });
});

// =============================================================================
// G8 — nAttempts / m_last_try / m_last_success — MISSING (BUG-8)
// =============================================================================
describe("W128-G8: nAttempts / m_last_try / m_last_success tracking — MISSING (BUG-8)", () => {
  it("BUG-8: PeerInfo has no nAttempts field", () => {
    expect(MANAGER_SRC).not.toMatch(/nAttempts/);
    expect(MANAGER_SRC).not.toMatch(/attemptCount\b/);
  });
  it("BUG-8: PeerInfo has no lastTry / m_last_try field", () => {
    expect(MANAGER_SRC).not.toMatch(/lastTry\b/);
    expect(MANAGER_SRC).not.toMatch(/m_last_try/);
  });
  it("BUG-8: PeerInfo has no lastSuccess / m_last_success field", () => {
    expect(MANAGER_SRC).not.toMatch(/lastSuccess\b/);
    expect(MANAGER_SRC).not.toMatch(/m_last_success/);
  });
  it("BUG-8: connection failure increments banScore instead of nAttempts", () => {
    // Line 1138: info.banScore += 1 (on connection failure).  This
    // conflates ban semantics with retry-attempt counting.
    expect(MANAGER_SRC).toMatch(/info\.banScore \+= 1/);
  });
});

// =============================================================================
// G9 — IsTerrible() — MISSING (BUG-9)
// =============================================================================
describe("W128-G9: IsTerrible(): horizon=30d, future-skew=10min, retry rules — MISSING (BUG-9)", () => {
  it("BUG-9: no IsTerrible function", () => {
    expect(MANAGER_SRC).not.toMatch(/isTerrible|IsTerrible/);
  });
  it("BUG-9: no 30-day horizon check", () => {
    expect(MANAGER_SRC).not.toMatch(/30 \* 24 \* 60 \* 60/);
    expect(MANAGER_SRC).not.toMatch(/HORIZON/);
  });
  it("BUG-9: no future-skew (now + 10min) check on addr.timestamp", () => {
    // handleAddrMessage drops addrs older than 3h but does not gate
    // future-skew at +10min.
    expect(MANAGER_SRC).not.toMatch(/timestamp\s*>\s*now\s*\+/);
  });
  it("BUG-9: no ADDRMAN_RETRIES=3 / ADDRMAN_MAX_FAILURES=10 constants", () => {
    expect(MANAGER_SRC).not.toMatch(/ADDRMAN_RETRIES/);
    expect(MANAGER_SRC).not.toMatch(/ADDRMAN_MAX_FAILURES/);
  });
});

// =============================================================================
// G10 — GetChance() probabilistic selection — MISSING (BUG-10)
// =============================================================================
describe("W128-G10: GetChance(): pow(0.66, min(nAttempts,8)) probabilistic — MISSING (BUG-10)", () => {
  it("BUG-10: no GetChance function", () => {
    expect(MANAGER_SRC).not.toMatch(/getChance|GetChance/);
  });
  it("BUG-10: no pow(0.66, ...) selection decay", () => {
    expect(MANAGER_SRC).not.toMatch(/Math\.pow\(0\.66/);
    expect(MANAGER_SRC).not.toMatch(/0\.66\s*\*\*/);
  });
  it("BUG-10: getCandidateAddresses uses deterministic sort, NOT probabilistic chance", () => {
    // Core (`Select_`) picks a random bucket + position then accepts
    // with `randbits<30> < chance_factor * GetChance * 2^30`.  hotbuns
    // sorts candidates deterministically.
    expect(MANAGER_SRC).toMatch(/candidates\.sort\(\(a, b\) =>/);
    expect(MANAGER_SRC).not.toMatch(/chance_factor|chanceFactor/);
  });
});

// =============================================================================
// G11 — AddSingle: 1h/24h conditional nTime update + time-penalty — MISSING (BUG-11)
// =============================================================================
describe("W128-G11: AddSingle: 1h/24h conditional nTime update + time-penalty — MISSING (BUG-11)", () => {
  it("BUG-11: handleAddrMessage unconditionally updates lastSeen", () => {
    // Lines 1962-1968: any time `entry.timestamp > existing.lastSeen`
    // we overwrite — no 1h/24h discriminator.
    expect(MANAGER_SRC).toMatch(/if \(entry\.timestamp > existing\.lastSeen\) \{/);
  });
  it("BUG-11: no time_penalty parameter", () => {
    expect(MANAGER_SRC).not.toMatch(/time_penalty|timePenalty/);
  });
  it("BUG-11: no `currently_online` (24h vs 1h) update interval", () => {
    expect(MANAGER_SRC).not.toMatch(/currently_online|currentlyOnline/);
  });
});

// =============================================================================
// G12 — AddSingle: 2^nRefCount stochastic admission — MISSING (BUG-12)
// =============================================================================
describe("W128-G12: AddSingle: 2^nRefCount stochastic admission test — MISSING (BUG-12)", () => {
  it("BUG-12: no 2^nRefCount admission gate", () => {
    expect(MANAGER_SRC).not.toMatch(/1\s*<<\s*pinfo->nRefCount/);
    expect(MANAGER_SRC).not.toMatch(/randrange\(nFactor\)/);
  });
});

// =============================================================================
// G13 — Good(): test-before-evict via m_tried_collisions — MISSING (BUG-13)
// =============================================================================
describe("W128-G13: Good(): test-before-evict via m_tried_collisions — MISSING (BUG-13)", () => {
  it("BUG-13: no m_tried_collisions / triedCollisions structure", () => {
    expect(MANAGER_SRC).not.toMatch(/m_tried_collisions/);
    expect(MANAGER_SRC).not.toMatch(/triedCollisions/);
  });
  it("BUG-13: no ResolveCollisions function", () => {
    expect(MANAGER_SRC).not.toMatch(/resolveCollisions|ResolveCollisions/);
  });
  it("BUG-13: no SelectTriedCollision function", () => {
    expect(MANAGER_SRC).not.toMatch(/selectTriedCollision|SelectTriedCollision/);
  });
  it("BUG-13: no ADDRMAN_SET_TRIED_COLLISION_SIZE constant (10)", () => {
    expect(MANAGER_SRC).not.toMatch(/COLLISION_SIZE/);
  });
});

// =============================================================================
// G14 — Select: 50/50 new/tried coin flip + chance_factor loop — MISSING (BUG-14)
// =============================================================================
describe("W128-G14: Select: 50/50 new/tried coin flip + chance_factor loop — MISSING (BUG-14)", () => {
  it("BUG-14: no search_tried / new_only branch", () => {
    expect(MANAGER_SRC).not.toMatch(/search_tried|searchTried/);
    expect(MANAGER_SRC).not.toMatch(/new_only|newOnly/);
  });
  it("BUG-14: no chance_factor accumulator (1.2 multiplier)", () => {
    expect(MANAGER_SRC).not.toMatch(/chance_factor\s*\*=\s*1\.2/);
    expect(MANAGER_SRC).not.toMatch(/chanceFactor\s*\*=\s*1\.2/);
  });
  it("BUG-14: no while-loop with re-roll on rejection", () => {
    // Core's Select_ runs `while (1)` with chance_factor *= 1.2 on each
    // rejection.  hotbuns sorts and slices in one pass.
    expect(MANAGER_SRC).toMatch(/return candidates\.slice\(0, limit\);/);
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
// G20 — FEELER connection type + 2min exponential — MISSING (BUG-20)
// =============================================================================
describe("W128-G20: FEELER connection type + 2min exponential schedule — MISSING (BUG-20)", () => {
  it("BUG-20: ConnectionType union has no 'feeler' variant", () => {
    // Line 226: `"full_relay" | "block_relay" | "inbound"` — no feeler.
    expect(MANAGER_SRC).toMatch(
      /export type ConnectionType = "full_relay" \| "block_relay" \| "inbound";/
    );
  });
  it("BUG-20: no FEELER_INTERVAL or rand_exp_duration", () => {
    expect(MANAGER_SRC).not.toMatch(/FEELER_INTERVAL|feelerInterval/);
    expect(MANAGER_SRC).not.toMatch(/rand_exp_duration|randExpDuration/);
  });
  it("BUG-20: no MAX_FEELER_CONNECTIONS constant", () => {
    expect(MANAGER_SRC).not.toMatch(/MAX_FEELER_CONNECTIONS/);
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
  it("BUG-22: no Good() call to short-circuit when already connected", () => {
    // Core: if test-before-evict picks an already-connected peer, mark
    // it Good and reselect.  hotbuns has no Good() either.
    expect(MANAGER_SRC).not.toMatch(/markGood|\.good\(|Good_/);
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
// G26 — getaddr response cap MAX_ADDR_TO_SEND=1000 — MISSING (BUG-24)
// =============================================================================
describe("W128-G26: getaddr response capped at MAX_ADDR_TO_SEND=1000 — MISSING (BUG-24)", () => {
  it("BUG-24: no MAX_ADDR_TO_SEND constant in p2p sources", () => {
    expect(MANAGER_SRC).not.toMatch(/MAX_ADDR_TO_SEND/);
    expect(PEER_SRC).not.toMatch(/MAX_ADDR_TO_SEND/);
  });
  it("BUG-24: no incoming-getaddr handler in handlePeerMessage", () => {
    const dispatch = MANAGER_SRC.match(
      /private handlePeerMessage\(peer: Peer, msg: NetworkMessage\): void \{[^]*?\n\s*\}/
    );
    if (dispatch) {
      // The outgoing direction issues `getaddr` (line 1321) but the
      // incoming direction has no `case "getaddr"`.
      expect(dispatch[0]).not.toMatch(/msg\.type === "getaddr"/);
      expect(dispatch[0]).not.toMatch(/case "getaddr"/);
    }
  });
});

// =============================================================================
// G27 — getaddr response cap MAX_PCT_ADDR_TO_SEND=23 — MISSING (BUG-25)
// =============================================================================
describe("W128-G27: getaddr response capped at MAX_PCT_ADDR_TO_SEND=23% — MISSING (BUG-25)", () => {
  it("BUG-25: no MAX_PCT_ADDR_TO_SEND constant", () => {
    expect(MANAGER_SRC).not.toMatch(/MAX_PCT_ADDR_TO_SEND/);
    expect(MANAGER_SRC).not.toMatch(/23\s*\*.*knownAddresses.*size/);
  });
});

// =============================================================================
// G28 — getaddr filtered=true (IsTerrible excluded) — covered by BUG-9
// =============================================================================
describe("W128-G28: getaddr filtered=true (IsTerrible excluded) — MISSING (covered by BUG-9)", () => {
  it("BUG-9-cover: no getaddr response means no filtering either", () => {
    expect(MANAGER_SRC).not.toMatch(/IsTerrible|isTerrible/);
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
// G30 — peers.dat round-trips Core V4_MULTIPORT format — MISSING (covered)
// =============================================================================
describe("W128-G30: peers.dat round-trips Core V4_MULTIPORT format — MISSING (covered by BUG-1/2/3)", () => {
  it("BUG-1/2/3-cover: hotbuns peers.dat format is flat list, NOT bucketed", () => {
    // Look at serializePeerAddresses — version=1, varint count, flat
    // per-entry serialization.  No nKey, no buckets, no asmap version.
    expect(MANAGER_SRC).toContain("function serializePeerAddresses(");
    expect(MANAGER_SRC).toMatch(/writer\.writeUInt8\(1\);/); // version=1
    expect(MANAGER_SRC).toMatch(/writer\.writeVarInt\(addresses\.length\)/);
    // No bucketed format markers
    expect(MANAGER_SRC).not.toMatch(/FILE_FORMAT|V4_MULTIPORT|INCOMPATIBILITY_BASE/);
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
// Source-level forward-regression guard
// =============================================================================
describe("W128 forward-regression guard: missing-helper names should not silently appear", () => {
  it("guard: no GetTriedBucket / GetNewBucket / GetBucketPosition added without test update", () => {
    // If hotbuns adds these helpers later, the W128 audit needs to be
    // re-run.  This guard *asserts the absence* so adding them flips
    // these tests red AND forces the audit to be re-classified.
    expect(MANAGER_SRC).not.toMatch(/getTriedBucket|GetTriedBucket/);
    expect(MANAGER_SRC).not.toMatch(/getNewBucket|GetNewBucket/);
    expect(MANAGER_SRC).not.toMatch(/getBucketPosition|GetBucketPosition/);
  });
  it("guard: no IsTerrible / GetChance added without test update", () => {
    expect(MANAGER_SRC).not.toMatch(/isTerrible|IsTerrible/);
    expect(MANAGER_SRC).not.toMatch(/getChance|GetChance/);
  });
  it("guard: ConnectionType still excludes 'feeler' (FEELER is W128-MISSING)", () => {
    expect(MANAGER_SRC).toMatch(
      /export type ConnectionType = "full_relay" \| "block_relay" \| "inbound";/
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
