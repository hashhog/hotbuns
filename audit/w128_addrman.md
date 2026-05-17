# W128 — AddrMan + connman + peer selection audit (hotbuns)

**Impl:** hotbuns (TypeScript / Bun)
**Date:** 2026-05-17
**Status:** DISCOVERY — 25 BUGS / 30 gates (3 PRESENT / 2 PARTIAL / 25 MISSING)
**Tests:** `src/__tests__/w128_addrman.test.ts` (xfail/assertion-only)
**No production code changes.**

## Scope

This audit covers hotbuns' "AddrMan" + "connman" + outbound-peer-selection
surface and EXCLUDES BIP-155 (addrv2 serialization — already covered by
prior W### waves) and BIP-324 v2 transport (W98 / W117 BUG-7 / cipher
handshake). Focus is the *address book* + *bucketing* + *selection* +
*banman* axis.

## Reference

- `bitcoin-core/src/addrman.cpp` — `AddrManImpl::AddSingle`, `Good_`,
  `Attempt_`, `Select_`, `MakeTried`, `ResolveCollisions_`,
  `SelectTriedCollision_`, `GetAddr_`, `Connected_`, `SetServices_`,
  `Check`.
- `bitcoin-core/src/addrman.h` — `ADDRMAN_TRIED_BUCKETS_PER_GROUP{8}`,
  `ADDRMAN_NEW_BUCKETS_PER_SOURCE_GROUP{64}`,
  `ADDRMAN_NEW_BUCKETS_PER_ADDRESS{8}`, `ADDRMAN_HORIZON{30 days}`,
  `ADDRMAN_RETRIES{3}`, `ADDRMAN_MAX_FAILURES{10}`,
  `ADDRMAN_MIN_FAIL{7 days}`, `ADDRMAN_REPLACEMENT{4h}`,
  `ADDRMAN_SET_TRIED_COLLISION_SIZE{10}`, `ADDRMAN_TEST_WINDOW{40min}`.
- `bitcoin-core/src/addrman_impl.h` — `ADDRMAN_TRIED_BUCKET_COUNT{256}`,
  `ADDRMAN_NEW_BUCKET_COUNT{1024}`, `ADDRMAN_BUCKET_SIZE{64}`, `AddrInfo`,
  `IsTerrible`, `GetChance`.
- `bitcoin-core/src/net.cpp` — `ThreadOpenConnections` (anchor → full →
  block-relay → feeler → preferred-net), `AlreadyConnectedToAddress`,
  bad-port skip, `MAX_ADDR_TO_SEND{1000}`, `MAX_PCT_ADDR_TO_SEND{23}`,
  `outbound_ipv46_peer_netgroups`, `MAX_OUTBOUND_FULL_RELAY_CONNECTIONS{8}`,
  `MAX_BLOCK_RELAY_ONLY_CONNECTIONS{2}`, `MAX_FEELER_CONNECTIONS{1}`,
  `FEELER_INTERVAL{2min}`, `EXTRA_BLOCK_RELAY_ONLY_PEER_INTERVAL{5min}`,
  `MAX_ADDNODE_CONNECTIONS{8}`.
- `bitcoin-core/src/banman.h` — `DEFAULT_MISBEHAVING_BANTIME{24h}`,
  `DUMP_BANS_INTERVAL{15min}`, ban-vs-discouragement model
  (rolling bloom filter `CRollingBloomFilter{50000, 1e-6}`).
- `bitcoin-core/src/banman.cpp`, `bitcoin-core/src/util/asmap.cpp`.

## Background — Core's AddrMan in 60 seconds

Core stores known peer addresses in two tables organized as bucketed arrays:

- **New table:** 1024 buckets × 64 positions, indexed by
  `(secret_key, source_group, addr_group, addr)`. Where source_group is
  the /16 (or ASN, if asmap loaded) of the peer who *gave* us this addr.
  An address can sit in up to 8 buckets (replication based on
  multi-source-of-truth heuristic).
- **Tried table:** 256 buckets × 64 positions, indexed by
  `(secret_key, addr_group, addr)`. An address sits in exactly one
  tried bucket. Each address-group is spread over 8 tried buckets, so
  no single /16 can occupy more than `8 * 64 = 512` tried slots.
- **nKey:** 256-bit random secret seed regenerated on first run,
  persisted to peers.dat. Adversary cannot precompute "which bucket
  will this addr land in" because they don't know nKey.

`Select(new_only, networks)` flips a coin between new/tried (50/50 when
both populated), picks a random bucket, picks a random position, and
either accepts the entry (probability `GetChance * chance_factor`) or
restarts with `chance_factor *= 1.2`. `GetChance` is `0.66^min(nAttempts,8)`,
plus `*0.01` if the entry was attempted in the last 10 minutes.

`IsTerrible` (used by GetAddr, AddSingle replacement, etc.):
- nTime > now + 10min → terrible (from the future)
- now - nTime > 30 days → terrible (forgotten)
- (last_success == 0 && nAttempts >= 3) → terrible
- (now - last_success > 7 days && nAttempts >= 10) → terrible

Tried/new collision protocol: when `Good()` would land an entry on an
occupied tried slot, Core enqueues it in `m_tried_collisions` and emits
a **FEELER** to the *occupant* (test-before-evict). The new entry only
displaces the old one if the occupant fails to respond. Selection of
the test-before-evict candidate uses `SelectTriedCollision`. This is
the **single most important DoS defense** in Core's addrman because it
prevents attacker-flooded "new" entries from punting genuine
"tried" peers without verifying the original is dead.

## What hotbuns actually has

hotbuns has **no addrman**. It has `PeerManager.knownAddresses`, a flat
`Map<string, PeerInfo>` keyed by `host:port` with these fields:

```
PeerInfo { host, port, services, lastSeen, banScore,
           lastConnected, connectionType?, connectedTime?,
           minPingTime?, lastBlockTime?, lastTxTime?,
           networkId?, rawAddr? }
```

There are no buckets, no nKey, no source-group bucketing, no
multi-bucket replication, no nAttempts/last_success/last_try, no
IsTerrible, no GetChance, no FEELER, no collision resolution.

What is present:

- DNS-seed resolution + per-network fallback peer table (PRESENT).
- BIP-155 addrv2 ingest (out of scope — separate audit).
- `getCandidateAddresses(limit)`: deterministic sort by
  `(NODE_WITNESS desc, NODE_NETWORK desc, banScore asc, lastSeen desc)`.
- `fillConnections`: anchor (2) → full-relay (8) → block-relay (2)
  with /16-or-ASN netgroup diversity.
- `BanManager`: hard bans only (`isBanned`/`ban`/`unban`/`clearBanned`);
  no discouragement bloom filter.
- Inbound eviction `selectPeerToEvict` (out of scope — protective only,
  no addrman touchpoints).

`peers.dat` is a flat hotbuns-internal binary (version=1, varint count,
per-entry varstr host + u16 port + u64 services + u64 lastSeen +
u32 banScore + u64 lastConnected). **Not compatible with Core peers.dat.**

## Audit matrix (30 gates)

Severity classification (consistent with prior W### waves):

- **P0-CDIV**: behavioral / consensus-adjacent divergence with concrete
  attack surface (eclipse, DoS, addrman exhaustion).
- **P1-API**: wrong-shape result on the wire (e.g. `getaddr` over-cap,
  bad-port not skipped).
- **P2-CONS**: hotbuns-internal cleanup (constants, comments).

### Bucketing + structure

| # | Gate                                                         | Status   | Bug |
|---|--------------------------------------------------------------|----------|-----|
| G1 | Tried table exists with 256 buckets × 64 positions          | MISSING  | BUG-1  |
| G2 | New table exists with 1024 buckets × 64 positions           | MISSING  | BUG-2  |
| G3 | Secret nKey (256-bit) seeds bucket selection                | MISSING  | BUG-3  |
| G4 | GetTriedBucket(nKey, netgroup) bucket assignment            | MISSING  | BUG-4  |
| G5 | GetNewBucket(nKey, source, netgroup) bucket assignment      | MISSING  | BUG-5  |
| G6 | GetBucketPosition(nKey, fNew, bucket) position-in-bucket    | MISSING  | BUG-6  |
| G7 | ADDRMAN_NEW_BUCKETS_PER_ADDRESS=8 multi-bucket replication  | MISSING  | BUG-7  |

### Entry lifecycle

| # | Gate                                                         | Status   | Bug |
|---|--------------------------------------------------------------|----------|-----|
| G8  | nAttempts / m_last_try / m_last_success tracking            | MISSING  | BUG-8  |
| G9  | IsTerrible(): horizon=30d, future-skew=10min, retry rules   | MISSING  | BUG-9  |
| G10 | GetChance(): pow(0.66, min(nAttempts,8)) probabilistic      | MISSING  | BUG-10 |
| G11 | AddSingle: 1h/24h conditional nTime update + time-penalty   | MISSING  | BUG-11 |
| G12 | AddSingle: 2^nRefCount stochastic admission test            | MISSING  | BUG-12 |
| G13 | Good(): test-before-evict via m_tried_collisions             | MISSING  | BUG-13 |

### Selection + connman

| # | Gate                                                         | Status   | Bug |
|---|--------------------------------------------------------------|----------|-----|
| G14 | Select: 50/50 new/tried coin flip + chance_factor loop      | MISSING  | BUG-14 |
| G15 | Select: per-network filter via reachable_nets               | PARTIAL  | BUG-15 |
| G16 | nTries=100 cap inside ThreadOpenConnections inner loop      | MISSING  | BUG-16 |
| G17 | `current_time - addr_last_try < 10min && nTries < 30` skip  | MISSING  | BUG-17 |
| G18 | HasAllDesirableServiceFlags filter (non-feeler)             | PARTIAL  | BUG-18 |
| G19 | IsBadPort skip (until 50 invalid addresses)                  | MISSING  | BUG-19 |
| G20 | FEELER connection type + 2min exponential schedule          | MISSING  | BUG-20 |

### Peer manager / connman misc

| # | Gate                                                         | Status   | Bug |
|---|--------------------------------------------------------------|----------|-----|
| G21 | Anchor peers loaded then unlinked (2-slot block-relay)      | PRESENT  | —     |
| G22 | Outbound /16-or-ASN netgroup diversity (ipv46 only)         | PRESENT  | —     |
| G23 | ResolveCollisions before Select on each iteration           | MISSING  | BUG-21 |
| G24 | AlreadyConnectedToAddress short-circuit + Good()             | MISSING  | BUG-22 |
| G25 | IsRoutable enforced for IPv4/IPv6/Tor/I2P/CJDNS              | PARTIAL  | BUG-23 |

### GetAddr / banman / discourage

| # | Gate                                                         | Status   | Bug |
|---|--------------------------------------------------------------|----------|-----|
| G26 | getaddr response capped at MAX_ADDR_TO_SEND=1000              | MISSING  | BUG-24 |
| G27 | getaddr response capped at MAX_PCT_ADDR_TO_SEND=23%           | MISSING  | BUG-25 |
| G28 | getaddr filtered=true (IsTerrible excluded)                   | MISSING  | (covered by BUG-9) |
| G29 | Discouragement bloom filter (50k, 1e-6 false-positive)        | MISSING  | BUG-26 |
| G30 | peers.dat round-trips Core V4_MULTIPORT format                | MISSING  | (covered by BUG-1/2/3) |

## Bug catalogue (25 bugs)

### P0-CDIV — core eclipse / DoS defenses

**BUG-1 (P0-CDIV): No tried table.** hotbuns has no bucketed tried
table at all. A single attacker controlling one /16 with 1000 IPs can
fill ALL of `knownAddresses` over time because there is no per-group
limit. Core caps tried addresses from one /16 at `8 buckets × 64
positions = 512` and forces displacement collisions to go through the
test-before-evict protocol.
Site: `src/p2p/manager.ts:371` (`knownAddresses: Map<string, PeerInfo>`).

**BUG-2 (P0-CDIV): No new table.** Same surface as BUG-1 but for the
"new" table. The new-table source-group bucketing
(64 buckets per source-group) is what prevents a single attacker peer
from filling all 1024 new buckets via gossip. hotbuns is unprotected.

**BUG-3 (P0-CDIV): No secret bucketing key (nKey).** Core uses a random
256-bit `uint256 nKey` generated on first run, persisted to peers.dat,
and folded into every bucket computation. Without nKey, an attacker who
knows our addrman layout could precompute which addr lands in which
bucket — the entire bucketing defense becomes a no-op. hotbuns has no
analogue: bucket selection is hashing by host string equality only.
Site: no key exists.

**BUG-4 (P0-CDIV): No GetTriedBucket.** Missing. There is no function
that maps (addr, nKey, netgroup) → bucket index in `[0, 256)`. hotbuns
keys entries by `host:port` flat string.
Core: `src/addrman.cpp:28-33`.

**BUG-5 (P0-CDIV): No GetNewBucket.** Missing. Core's
`GetNewBucket(nKey, src, netgroupman)` folds the source group into the
hash so that two peers gossiping the same address land it in different
new buckets. hotbuns gossip-floods (`handleAddrMessage`) put every
addr in the same flat map under the same key regardless of source —
attacker-controlled gossip is **maximally** effective.
Core: `src/addrman.cpp:35-41`.

**BUG-6 (P0-CDIV): No GetBucketPosition.** Missing. Without it there's
no per-bucket per-position slot to displace; the entire collision /
displacement model is absent.
Core: `src/addrman.cpp:43-47`.

**BUG-7 (P0-CDIV): No ADDRMAN_NEW_BUCKETS_PER_ADDRESS=8 multi-bucket
replication.** Core puts well-gossiped addresses in up to 8 new buckets,
which proportionally increases their selection probability. hotbuns
addresses appear exactly once. Effect: addrman cannot prefer
multi-source-confirmed addresses over single-source noise.

**BUG-8 (P0-CDIV): No nAttempts / m_last_try / m_last_success.**
hotbuns conflates the three into `banScore += 1` (line 1138) and
`lastConnected` (line 1122). `lastConnected` is set on success only,
not on attempt — so a failing peer's "last try" is invisible. Effect:
no exponential backoff is possible; no failing-peer eviction is
possible; `IsTerrible` cannot exist.
Site: `src/p2p/manager.ts:1134-1140`.

**BUG-9 (P0-CDIV): No IsTerrible.** Missing entirely. The four
ejection criteria:
1. `now - nTime > 30 days` (horizon)
2. `nTime > now + 10min` (future skew)
3. `last_success == 0 && nAttempts >= 3`
4. `now - last_success > 7 days && nAttempts >= 10`
…are nowhere in hotbuns. Effect: addresses we have never reached but
got gossiped to us 6 months ago remain in `knownAddresses` forever
with `banScore=0`, ranked higher than recent good peers in the
deterministic-sort selection.

**BUG-10 (P0-CDIV): No GetChance.** Selection is a deterministic sort
by `(NODE_WITNESS, NODE_NETWORK, banScore, lastSeen)` (line 1791-1812).
Effect: the top-N candidates in `knownAddresses` are **predictable**
— an attacker who can guess our addresses can construct a controlled
ranking. Core's `randbits<30> < chance_factor * GetChance * 2^30`
gives every entry a probabilistic chance, making the eclipse-attack
plan harder to execute.

**BUG-11 (P0-CDIV): AddSingle missing 1h/24h conditional nTime update.**
Core's `AddSingle` only updates `pinfo->nTime` if the new advertisement
is at least 1h (currently-online) or 24h (offline) newer than the
stored value, with `time_penalty` subtracted. hotbuns unconditionally
overwrites whenever `entry.timestamp > existing.lastSeen` (line 1965)
— an attacker can keep our "lastSeen" pinned to now for any addr by
just repeating it every 5 seconds. Effect: skews selection ranking +
defeats the horizon check (if it existed).
Site: `src/p2p/manager.ts:1962-1970`.

**BUG-12 (P0-CDIV): No `2^nRefCount` stochastic admission test.** Core
prevents an address that already sits in N new buckets from being
gossiped into yet another bucket with probability `1 - 2^(-N)`. Without
this hotbuns has no mechanism at all because we have no buckets, but
the missing logic compounds BUG-7 — multi-source-confirmed addresses
are NOT preferred AND we don't gate their replication.

**BUG-13 (P0-CDIV): No test-before-evict / m_tried_collisions.** When
a successful connection (`Good`) would land an entry on an occupied
tried slot, Core enqueues the new entry as a "collision" and emits a
FEELER to the occupant. The occupant only gets displaced if it fails
the feeler. hotbuns has no FEELER at all (BUG-20) and no
`m_tried_collisions` set. Effect: a peer that connects from a
specific /16 can dislodge a long-running tried peer in the same /16
without giving the original peer a chance to prove it's still alive.

**BUG-14 (P0-CDIV): No 50/50 new/tried coin flip + chance_factor.**
hotbuns selection is a flat sort. Core: `Select_` flips a coin (when
both tables populated), picks a random bucket, picks a random
position, and `chance_factor *= 1.2` on each rejection — both
*surface* a wider entry set AND *prefer* entries that are not stale.
hotbuns selection ignores tried-vs-new entirely (no tables) and never
re-rolls.

**BUG-20 (P0-CDIV): No FEELER connection type + 2min exponential
schedule.** Core opens 1 short-lived feeler every ~2min (exponential
random). Feelers serve two purposes:
1. Test-before-evict (BUG-13).
2. Sustained eclipse-attack defense: a feeler picks from the **new**
   table only (`Select(/*new_only=*/true)`), so even if our outbound
   slots are all from one /16, every 2 minutes we probe a fresh new
   entry.

Effect: hotbuns has no eclipse-attack recovery path. Once our 8 +
2 outbound slots fill with attacker /16 peers, we never sample fresh
addresses until we restart.
Site: missing.

### P0-CDIV — connman selection rules

**BUG-21 (P0-CDIV): No ResolveCollisions called before Select.**
Core calls `addrman.ResolveCollisions()` at the top of every iteration
of `ThreadOpenConnections` (`src/net.cpp:2773`). hotbuns has nothing
to resolve because BUG-13. Listed separately because in a fixed
hotbuns this would be a separate fix wave.

**BUG-22 (P0-CDIV): No AlreadyConnectedToAddress short-circuit during
selection.** Core: if `Select` returns an addr we're already connected
to via feeler-test-before-evict, mark it `Good()` and re-Select.
hotbuns: `getCandidateAddresses` filters `this.peers.has(key)` (line
1762) — that **only** matches by exact key, not by `CNetAddr` (the
network address ignoring port). A peer that connects to us on port
8333 and re-advertises themselves on port 8334 would be re-selected
because the map keys differ. Core's
`AlreadyConnectedToAddress(addrConnect)` ignores port.
Site: `src/p2p/manager.ts:1762`.

**BUG-19 (P0-CDIV): No IsBadPort filter.** Core skips bad ports (HTTP,
SMTP, well-known service ports) until 50 invalid candidates have been
tried in the inner loop. hotbuns has no bad-port table. An adversary
who controls gossip can feed us addresses at port 25/80/110/etc.,
which a stock TCP `connect()` will sometimes succeed against
(captive portals, etc.) — leading to garbage handshake retries +
bandwidth waste.
Site: no `isBadPort` function in `src/p2p/`.

**BUG-16 (P0-CDIV): No nTries=100 limit in fillConnections inner
loop.** `fillConnections` (line 1672-1702) calls
`getCandidateAddresses(needed * 3)` once and tries each. If none of
the candidates connect (all banned, wrong netgroup, etc.), the
function returns and the outer maintenance loop sleeps 30 seconds
before retrying. Core opens connections in a tight inner loop with
`nTries <= 100` per iteration — bounded but vigorous. hotbuns'
30-second sleep means recovery from a partial-eclipse takes
**minutes** instead of seconds.

**BUG-17 (P0-CDIV): Recently-tried throttle is 5min hardcoded instead
of `10min && nTries < 30`.** Line 1772:
`now - info.lastConnected < 300_000` (5min). Core (net.cpp:2845):
`current_time - addr_last_try < 10min && nTries < 30`. Hotbuns is
both **too aggressive** (5min vs 10min, peers get retried too soon)
AND **never relents** (no `nTries < 30` escape — if every addr was
tried in the last 5min, hotbuns has nothing). After 30 retries, Core
will try a recently-tried peer anyway to escape an offline situation.

**BUG-18 (P0-API): HasAllDesirableServiceFlags is sort-preference only,
not a filter.** hotbuns `getCandidateAddresses` *sorts* by
`NODE_WITNESS` then `NODE_NETWORK` (1794-1803), so SPV-only peers can
appear in the candidate list — just at the bottom. Core (net.cpp:2852)
*continues* (skips) the candidate when
`!HasAllDesirableServiceFlags(addr.nServices)` for non-feeler outbound.
Effect: a `getCandidateAddresses(8)` call when 8 SPV peers are at the
top of the sorted list returns 8 SPV peers, despite full-relay slots
being the goal. Subsequent `connectPeer` may discover the peer doesn't
advertise NODE_NETWORK in its version handshake, but by then we've
wasted a slot.

**BUG-23 (P0-CDIV): IsRoutable only checks IPv4.** Line 311:
`if (parts.length !== 4) return false; // Only IPv4 handled here`. The
comment explicitly admits the gap. An IPv6 RFC4193 ULA (fc00::/7),
RFC4291 link-local (fe80::/10), or RFC4862 unicast-local-host
(::1/128) bypasses the routability check entirely. Tor / I2P /
CJDNS addresses are filtered by `resolveDialable` based on proxy
configuration but `isRoutable` itself is never called on them. Effect:
ANY non-IPv4 address survives `isRoutable` and reaches
`getCandidateAddresses`.
Site: `src/p2p/manager.ts:310-342`.

### P1-API — wrong-shape RPC / wire

**BUG-15 (P1-API): Per-network filter is partial.** Core's
`Select(new_only, networks)` filters to a specific network set
(used by `MaybePickPreferredNetwork` to pick a peer from an
underrepresented network). hotbuns has only `cjdnsReachable` and
proxy presence — no positive per-network selection. Effect: hotbuns
can't run Core's "extra network peer" logic (a peer from an
underrepresented network every ~5min to maintain network diversity).
Listed P1-API because it primarily affects connectivity diversity,
not selection correctness.

**BUG-24 (P1-API): getaddr response not capped at
MAX_ADDR_TO_SEND=1000.** I find no handler for incoming
`getaddr` in hotbuns at all. The outgoing direction sends `getaddr`
on maintenance (line 1321), but there's no `case "getaddr"` in
`handlePeerMessage` (line 1916+). Effect: peers that
`getaddr` us get nothing; they will time out their own addrman
fill.

**BUG-25 (P1-API): getaddr response not capped at 23%.** Compounds
BUG-24: with no handler there's no 23%/1000-cap either. Core's
`MAX_PCT_ADDR_TO_SEND=23` defends against accidentally leaking too
much of the addrman to one peer (privacy + DoS).

**BUG-26 (P1-API): No discouragement bloom filter.** Core's banman
maintains a separate `CRollingBloomFilter{50000, 1e-6}` for
"discouraged" peers — these are peers we still *accept* inbound from
(so they can recover) but we *prefer* for eviction and we *don't*
gossip their addresses. hotbuns conflates ban and discourage:
`peer.misbehaving` (peer.ts:874) calls `banManager.ban` which adds
a hard 24h ban entry. Effect:
1. Misbehaving peers can't recover.
2. hotbuns will gossip the discouraged addr because we have nothing
   stopping it.
3. The hard-ban map is unbounded (a malicious peer can rotate IPs
   and grow the map), which is the exact CVE that Core PR #25974
   fixed by moving to the bloom filter.

### P2-CONS — hotbuns-internal cleanup

(None separately listed — every miss above is consensus-adjacent.)

## Patterns observed (cross-impl notes for future waves)

1. **"Sort-not-filter" anti-pattern.** BUG-18 + BUG-15 are both cases
   where hotbuns sorts candidates by a preference instead of filtering
   them. Sort-based ranking is fine for in-band preference (NODE_WITNESS
   first) BUT does not preserve Core's invariant that some candidates
   are *invalid* for some slot types. Probably another impl has the
   same issue — worth a fleet sweep.

2. **"Single Map flat-address-book" anti-pattern.** BUG-1 through
   BUG-7 are not separate bugs in the implementation sense — they're
   one giant absence. hotbuns chose flat-map + deterministic-sort
   over Core's bucketed model. This is a recoverable architectural
   debt: any AddrMan implementation needs the bucketed model to defend
   against eclipse / DoS at scale. **The fix would be a new file
   `src/p2p/addrman.ts` that implements the bucketed tables and
   becomes the storage for `PeerManager.knownAddresses`.**

3. **"banScore as nAttempts" conflation.** BUG-8 documents how
   hotbuns reuses `banScore` for both "this peer misbehaved on the
   wire" (peer.ts misbehaving — 10pt-100pt single-event discourage)
   AND "this peer failed to connect" (manager.ts:1138 `banScore += 1`).
   The two concerns must be split. Probably a universal anti-pattern.

4. **"isRoutable IPv4-only" anti-pattern.** BUG-23 — the comment
   admits the gap. Worth a sweep across the fleet for the same
   `parts.length !== 4 return false` pattern.

5. **"5min hardcoded retry throttle" anti-pattern.** BUG-17 differs
   from Core in **two** axes — value and escape clause. The "value
   diverges *and* the escape is absent" combo is common across the
   fleet because impls tend to write a single-number throttle and
   forget the "after N tries, relent" branch.

## Test summary

`src/__tests__/w128_addrman.test.ts` exercises each gate and
catalogues PASS / XFAIL pattern. 25 xfail-style assertions document
the missing surface; 3 PASS assertions pin anchor-peer + netgroup-
diversity + DNS-seed fallback (the bits hotbuns actually has).
PARTIAL gates (G15, G18, G25) get **two** assertions: a "has
something" PASS and a "does the full Core thing" XFAIL.

Total: 30 audit gates / 25 bugs / 25 XFAIL / 5 PASS (G15 PARTIAL is
1 pass + 1 xfail; G18 + G25 similarly; G21 + G22 are full PASS).

## What this audit does NOT prove

- I did not run the test suite against a running peer. All
  observations are static-source. A running smoke test would
  surface additional dynamic issues (e.g. does `lastConnected`
  actually get set on attempt? Source-grep suggests no — it's
  only set on `connectPeer` success — but I didn't bind a port and
  inspect the behavior).
- I did not check hotbuns' peers.dat against Core's V4_MULTIPORT
  binary format byte-by-byte. They are obviously different formats
  (BUG-30 is implicit) but I did not write a round-trip vector.
- BIP-155 / addrv2 / Tor-v3 routing live outside this scope.
