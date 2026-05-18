# W136 — BIP-130 sendheaders + BIP-133 feefilter + BIP-339 wtxidrelay (hotbuns)

**Impl:** hotbuns (TypeScript / Bun)
**Date:** 2026-05-17
**Wave:** W136 BIP-130 sendheaders + BIP-133 feefilter + BIP-339 wtxidrelay
**Status:** DISCOVERY — 21 BUGS / 30 gates (9 PRESENT / 13 PARTIAL / 8 MISSING)
**Tests:** `src/__tests__/w136_relay_flags.test.ts` (assertion-only)
**No production code changes in this wave.**

## References

- `bitcoin-core/src/net_processing.cpp`
  - `PeerManagerImpl::ProcessMessage` — VERSION handler at L3658-3893,
    VERACK handler at L3858-3893, SENDHEADERS at L3896-3899,
    SENDCMPCT at L3901-3917, WTXIDRELAY at L3919-3939,
    FEEFILTER at L5035-5045.
  - `PeerManagerImpl::MaybeSendSendHeaders` at L5519-5538 — BIP-130
    delayed sendheaders gated on
    `GetCommonVersion() >= SENDHEADERS_VERSION (70012)` and
    `state.pindexBestKnownBlock->nChainWork > MinimumChainWork`.
  - `PeerManagerImpl::MaybeSendFeefilter` at L5540-5580 — BIP-133
    Poisson-delayed feefilter broadcast with hysteresis (`AVG_FEEFILTER_BROADCAST_INTERVAL=10min`,
    `MAX_FEEFILTER_CHANGE_DELAY=5min`), gated on
    `GetCommonVersion() >= FEEFILTER_VERSION (70013)`,
    `!ignore_incoming_txs`, `!HasPermission(ForceRelay)`,
    `!IsBlockOnlyConn`.
  - Block-announcement routing at L5828-5957 (`fRevertToInv = !peer.m_prefers_headers && ...`).
  - `Peer::m_sent_sendheaders` at net_processing.cpp:405-406.
  - `Peer::m_prefers_headers` at L412.
  - `Peer::m_wtxid_relay` at L283.
  - `Peer::m_fee_filter_sent` / `Peer::m_next_send_feefilter` at L284-290.
- `bitcoin-core/src/node/protocol_version.h`:
  - `SENDHEADERS_VERSION = 70012`
  - `FEEFILTER_VERSION = 70013`
  - `WTXID_RELAY_VERSION = 70016`
  - `PROTOCOL_VERSION = 70016`, `MIN_PEER_PROTO_VERSION = 31800`
- `bitcoin-core/src/policy/fees/block_policy_estimator.{h,cpp}` —
  `FeeFilterRounder::round` (L1109-1119): randomized downward rounding
  via a precomputed log-spaced fee set, so peers cannot extract precise
  mempool min-fee values from a node's `feefilter` broadcasts.
- `bitcoin-core/src/policy/feerate.cpp` — `CFeeRate::GetFee` /
  `ToString` (sat/kvB internal, sat/vB for display).
- `bitcoin-core/src/consensus/amount.h` — `CAmount = int64_t`,
  `MoneyRange(n) = (n >= 0 && n <= MAX_MONEY)`,
  `MAX_MONEY = 21'000'000 * 100'000'000`.

BIPs:
- **BIP-130** — `sendheaders` announces preference for headers over inv
  for block announcements (Core 0.12+).
- **BIP-133** — `feefilter` lets peers ask senders to skip inv
  announcements for tx below a feerate floor (Core 0.13+).
- **BIP-339** — `wtxidrelay` switches tx announcements from txid
  (`MSG_TX=1`) to wtxid (`MSG_WTX=5`); negotiated between VERSION
  and VERACK only.

## Hotbuns architecture

- **`src/p2p/peer.ts`** — per-peer state + handshake state machine.
  - L223-230 `wtxidRelay: boolean`; L233-249 `feeFilterReceived`,
    `feeFilterSent`, `nextFeeFilterSend`.
  - L1212-1305 `handleHandshake` — sends `wtxidrelay`+`sendaddrv2`
    immediately after parsing peer VERSION (before our VERACK).
  - L1310-1331 `checkHandshakeComplete` — sends `sendheaders` +
    `sendcmpct(false, 2n)` immediately on handshake completion.
- **`src/p2p/feefilter.ts`** — `FeeFilterManager` with
  `sendInitialFeeFilter`, `maybeSendFeeFilter`, `handleFeeFilter`,
  `meetsFeeFilter`, `poissonDelay`, `hasSubstantialChange`.
  - L46 `FEEFILTER_VERSION = 70013` (correct).
  - L18 `AVG_FEEFILTER_BROADCAST_INTERVAL_MS = 10 * 60 * 1000` (correct).
  - L24 `MAX_FEEFILTER_CHANGE_DELAY_MS = 5 * 60 * 1000` (correct).
  - L29 `DEFAULT_MIN_RELAY_FEE_RATE = 1000n` sat/kvB (correct).
- **`src/p2p/manager.ts`**
  - L408-411 declares `feeFilterManager` + `feeFilterInterval`.
  - L491-494 constructs `FeeFilterManager` with peer.send callback.
  - L495 `this.feeFilterInterval = null` — never assigned.
  - L863-887 maintenance/ping/stale-check timers — `feeFilterInterval`
    is NOT in the list of intervals started in `start()`.
  - L1862-1891 `handleHandshakeComplete` — calls
    `feeFilterManager.sendInitialFeeFilter(peer)` once per peer
    iff `peer.versionPayload.version >= FEEFILTER_VERSION` and
    `connType !== "block_relay"`.
  - L1924-1927 dispatches inbound `feefilter` →
    `handleFeeFilterMessage`.
- **`src/p2p/messages.ts`** — wire codec
  - L111 `sendheaders` payload null; L1432-1434 serializer (empty),
    L1645-1646 deserializer.
  - L113-114 `feefilter`/`wtxidrelay` types.
  - L717-721 `serializeFeeFilterPayload` writes
    `payload.feeRate` via `writeUInt64LE`.
  - L1170-1173 `deserializeFeeFilterPayload` reads via
    `readUInt64LE` — **Core uses int64** (`CAmount`).
- **`src/p2p/relay.ts`** — `InventoryRelay`
  - L51-57 documents `wtxidRelay` queue flag; L96-118 `addPeer` takes
    it as a constructor parameter; L356-360 chooses
    `MSG_WTX vs MSG_TX` at flush time per `queue.wtxidRelay`.
  - L162-176 `queueTxFiltered` consults `meetsFeeFilter` against
    `peer.feeFilterReceived` before queueing.

## Audit matrix (30 gates)

Gate IDs use the prefix `W136-G##`. Status legend: PRESENT (Core-
parity) / PARTIAL (BUG-N) / MISSING (BUG-N). Severity: **P0-CDIV**
(wire-divergent), **P1-WIRE** (correctness-bearing for relay), **P1-API**
(structural deviation), **P2** (operator / privacy footgun).

| Gate | Subject | Status |
|------|---------|--------|
| G01 | `SENDHEADERS_VERSION = 70012` constant | PRESENT |
| G02 | `FEEFILTER_VERSION = 70013` constant | PRESENT |
| G03 | `WTXID_RELAY_VERSION = 70016` constant (or equivalent gate) | **BUG-1** P0-CDIV |
| G04 | `AVG_FEEFILTER_BROADCAST_INTERVAL = 10min` | PRESENT |
| G05 | `MAX_FEEFILTER_CHANGE_DELAY = 5min` | PRESENT |
| G06 | sendheaders sent after our VERACK, not BEFORE (correct ordering) | PRESENT |
| G07 | sendheaders sent only when `common_version >= SENDHEADERS_VERSION` | **BUG-2** P1-WIRE |
| G08 | `m_sent_sendheaders` once-only flag (no duplicate send) | **BUG-3** P1-API |
| G09 | sendheaders delayed until initial headers sync done (`pindexBestKnownBlock->nChainWork > MinimumChainWork`) | **BUG-4** P1-WIRE |
| G10 | Periodic `MaybeSendSendHeaders` invocation from SendMessages loop | **BUG-5** P1-WIRE |
| G11 | Incoming `sendheaders` sets `m_prefers_headers = true` per peer | **BUG-6** P0-CDIV |
| G12 | Block announcement routing chooses headers vs inv per `m_prefers_headers` (fRevertToInv) | **BUG-7** P0-CDIV |
| G13 | Initial feefilter sent in `handleHandshakeComplete` | PRESENT |
| G14 | Initial feefilter gated on `version >= FEEFILTER_VERSION` | PRESENT |
| G15 | Initial feefilter skipped on block-relay-only peer | PRESENT |
| G16 | Periodic `MaybeSendFeefilter` invocation (Poisson re-broadcast) | **BUG-8** P1-WIRE |
| G17 | `FeeFilterRounder` randomized-downward round (anti-side-channel) | **BUG-9** P2 |
| G18 | `min_relay_feerate` floor enforced in send path (`std::max(filterToSend, min_relay_feerate)`) | **BUG-10** P1-WIRE |
| G19 | MAX_FILTER reset (`m_next_send_feefilter = 0us`) after exit-IBD | **BUG-11** P1-WIRE |
| G20 | `feefilter` payload encoded as **int64 LE** (CAmount), not uint64 | **BUG-12** P1-WIRE |
| G21 | Incoming `feefilter` validated with MoneyRange (`>=0 && <=MAX_MONEY`) | PRESENT |
| G22 | `ignore_incoming_txs` (`-blocksonly`) suppresses feefilter send | **BUG-13** P1-API |
| G23 | `HasPermission(ForceRelay)` suppresses feefilter send | **BUG-14** P1-API |
| G24 | feefilter NOT broadcast to FeelerConn / AddrFetchConn peers | **BUG-15** P1-WIRE |
| G25 | wtxidrelay sent only when `common_version >= WTXID_RELAY_VERSION` | **BUG-16** P0-CDIV |
| G26 | wtxidrelay sent AFTER our VERSION but BEFORE our VERACK | PRESENT |
| G27 | Incoming wtxidrelay after VERACK → DISCONNECT (Core fDisconnect=true) | **BUG-17** P0-CDIV |
| G28 | Duplicate incoming wtxidrelay → log + no-op (not silent overwrite) | **BUG-18** P2 |
| G29 | Old common-version wtxidrelay → log + ignore (not silent set) | **BUG-19** P1-WIRE |
| G30 | Manager-level `m_wtxid_relay_peers` counter (for AddrFetch invariant) | **BUG-20** P1-API |

**Total: 20 numbered BUGs.** One additional cross-cutting structural
issue surfaced during the audit and is recorded as **BUG-21** below.

Severity breakdown: **P0-CDIV = 5** (BUG-1, BUG-6, BUG-7, BUG-16,
BUG-17); **P1-WIRE = 8** (BUG-2, BUG-4, BUG-5, BUG-10, BUG-11, BUG-12,
BUG-15, BUG-19); **P1-API = 5** (BUG-3, BUG-13, BUG-14, BUG-20, BUG-21);
**P2 = 3** (BUG-8 categorized P1, BUG-9, BUG-18).

PRESENT count: G01, G02, G04, G05, G06, G13, G14, G15, G21, G26 = 10
gates correct.

---

## Bug detail

### BUG-1 P0-CDIV — `WTXID_RELAY_VERSION` constant missing
hotbuns has no equivalent of Core's `WTXID_RELAY_VERSION = 70016`.
`feefilter.ts` defines `FEEFILTER_VERSION = 70013` but no symmetric
`WTXID_RELAY_VERSION`. The hotbuns peer code at `peer.ts:1241`
unconditionally sends `wtxidrelay` after receiving peer VERSION, with
no `if (versionPayload.version >= 70016)` gate. This compounds with
BUG-16.

### BUG-2 P1-WIRE — `sendheaders` sent without SENDHEADERS_VERSION gate
`peer.ts:1322` sends `sendheaders` unconditionally in
`checkHandshakeComplete()`. Core gates this on
`node.GetCommonVersion() >= SENDHEADERS_VERSION` (70012). Because
hotbuns enforces `MIN_PEER_PROTO_VERSION = 70015` at peer.ts:1224
(disconnect peer if version < 70015), the gate is structurally
satisfied for any peer hotbuns keeps connected — but the gate's
ABSENCE makes the code wire-fragile: if `MIN_PEER_PROTO_VERSION` is
ever lowered, the bug activates immediately. P1-dormant.

### BUG-3 P1-API — `m_sent_sendheaders` once-only flag missing
Core's `Peer::m_sent_sendheaders` (net_processing.cpp:405-406) is a
once-only latch ensuring sendheaders is sent at most once per
connection. Hotbuns has no such flag. `checkHandshakeComplete()` is
guarded by `(sentVerack && receivedVerack && versionPayload)` — these
all latch true, so `sendheaders` IS effectively once per peer in
practice. But the structural latch is absent: any future change that
re-fires `checkHandshakeComplete()` (e.g. v2 → v1 fallback that
re-runs the handshake state machine) would re-send sendheaders. The
absence is also relevant because Core's flag is queried in
`MaybeSendSendHeaders` SendMessages-loop calls (BUG-5).

### BUG-4 P1-WIRE — sendheaders sent IMMEDIATELY, not delayed until headers sync done
Core (net_processing.cpp:5519-5537) delays sendheaders until
`state.pindexBestKnownBlock != nullptr && state.pindexBestKnownBlock->nChainWork > MinimumChainWork()`.
Sending sendheaders before initial headers sync is harmful because the
peer can then send block headers for new tips before hotbuns has
caught up — those headers do not connect and are discarded, while
hotbuns has effectively opted into "drop my headers for new blocks
until I'm synced". Hotbuns sends sendheaders the instant verack
completes, so we'll never re-evaluate the "should we send this now?"
question. Symptom: during a long IBD, new tips arrive as headers
(matching the BIP-130 contract we offered), are discarded as
non-connecting, and we then have to discover the tip via the
synchronous getheaders path anyway — losing the BIP-130 latency win.

### BUG-5 P1-WIRE — No `MaybeSendSendHeaders` periodic call
Core invokes `MaybeSendSendHeaders` once per peer per SendMessages
tick (L5763); only emits if `!m_sent_sendheaders` and the BIP-130
gate (BUG-4) becomes true. Hotbuns has no SendMessages-equivalent
loop that re-evaluates sendheaders sending. Compounds BUG-4: even
if hotbuns were to defer sendheaders until headers sync done, there's
no scheduler that would fire the deferred send later.

### BUG-6 P0-CDIV — Incoming `sendheaders` is silently ignored
Hotbuns has no `m_prefers_headers` field on `Peer`, and the
manager-level message dispatch (`manager.ts:1896-1938`) has no case
for `sendheaders`. The wire codec parses the message (messages.ts:1645)
but the parsed message is dispatched to registered handlers
(L1929-1937); no handler is registered for `sendheaders`. This is a
**direct wire divergence**: a peer that sends sendheaders to hotbuns
expects hotbuns to switch block-announce mode from inv to headers.
hotbuns keeps inv-only and the peer treats us as a legacy node, so
block-propagation latency is worse than Core's behavior.

### BUG-7 P0-CDIV — Block announcement always uses inv, never headers
Compounds BUG-6. Even if BUG-6 were fixed (state tracked), there is
no code path that branches block announcement based on
`peer.prefersHeaders`. The `sync/blocks.ts` block-relay path
(reviewed in W126 / W123) and the `InventoryRelay.relayBlockToAll`
in `relay.ts:234-245` always emit an `MSG_BLOCK` inv. Core
(net_processing.cpp:5828-5957) branches on `peer.m_prefers_headers`
to send `headers` instead.

### BUG-8 P1-WIRE — No periodic `MaybeSendFeefilter` invocation
`manager.ts:411` declares `feeFilterInterval: ReturnType<typeof setInterval> | null`
and `manager.ts:495` initializes it to `null`. The string
`feeFilterInterval` appears nowhere else in the file. `manager.ts:863-887`
(start() interval setup) registers `maintainInterval`, `pingInterval`,
`staleCheckInterval`, `asmapHealthCheckInterval` — but NOT
`feeFilterInterval`. The `maintain()` loop at 30s cadence does not
call `feeFilterManager.maybeSendFeeFilter`.
**Net effect:** the only feefilter ever sent to a peer is the initial
broadcast at handshake-complete (`sendInitialFeeFilter`). The
re-broadcast on mempool min-fee change, the IBD-exit reset, the
Poisson-jittered periodic update — none of them fire.
The infrastructure (`maybeSendFeeFilter`, `hasSubstantialChange`,
`poissonDelay`, `nextFeeFilterSend`) IS implemented in `feefilter.ts`
but is **NEVER CALLED** from running-node code paths. Dead-helper at
call site — same shape as W120 `validateRbfDiagram` in nimrod (FIX-79).

### BUG-9 P2 — No `FeeFilterRounder` randomized downward round
Core uses `FeeFilterRounder::round`
(block_policy_estimator.cpp:1109-1119) to round the broadcast feerate
down to one of a precomputed log-spaced fee set, with a 1/3
probability of stepping one bucket below the natural lower_bound.
This prevents adversarial peers from extracting our exact mempool
min-fee by repeatedly probing what we'll relay. Hotbuns sends the
raw `currentFeeRate` from `getFeeRateToAnnounce()` —
information leak. Privacy-class bug; P2.

### BUG-10 P1-WIRE — `min_relay_feerate` floor not applied in send path
Core (L5567) applies
`filterToSend = std::max(filterToSend, m_mempool.m_opts.min_relay_feerate.GetFeePerK())`
in `MaybeSendFeefilter`. Hotbuns enforces this floor only in
`feefilter.ts:82-87` (`setMinFeeRate`), not in
`getFeeRateToAnnounce()`. If `setMinFeeRate(0n)` were ever called
(or if the path through `setInIBD` later changed), the floor would
not be re-applied in the send path. Defensive-redundant in Core;
absent in hotbuns. P1-defensive.

### BUG-11 P1-WIRE — No MAX_FILTER reset on exit-IBD
Core (L5555-5562): during IBD, sends `MAX_MONEY`. On exit-IBD, if
the last sent filter was MAX_FILTER (`m_fee_filter_rounder.round(MAX_MONEY)`),
Core sets `m_next_send_feefilter = 0us` so the **next** Send tick
emits a real fee filter immediately, instead of waiting up to 10min
for the next Poisson tick. Hotbuns lacks this reset entirely. Even
if BUG-8 were fixed (interval wired), the post-IBD recovery would
take up to a full `AVG_FEEFILTER_BROADCAST_INTERVAL_MS = 10min`
to begin filtering — during which peers send us txs we cannot relay
and they're stuck assuming we accept any feerate.

### BUG-12 P1-WIRE — feefilter payload deserialized as uint64 (Core: int64)
`messages.ts:717` `serializeFeeFilterPayload` writes via
`writer.writeUInt64LE`; `messages.ts:1171` `deserializeFeeFilterPayload`
reads via `reader.readUInt64LE`. Core's wire shape is `CAmount`
(`int64_t`); `feeRate` in
`feefilter.ts:233 (FeeFilterPayload)` is `bigint` so the in-memory
sign is preserved, but a peer that sends a negative encoded `CAmount`
(e.g. `-1` = `0xffffffffffffffff` little-endian) is parsed as a huge
positive `bigint`. The downstream `handleFeeFilter` (feefilter.ts:107)
rejects this via `feeRate > MAX_MONEY`, so behavior is
quasi-equivalent — but wire-shape divergence is a P1-WIRE class bug:
the type information is lost, the bound check works by happy accident,
and any future tightening (e.g. a "non-zero feefilter required" rule)
would skew positive on hotbuns and negative on Core.

### BUG-13 P1-API — `ignore_incoming_txs` (-blocksonly) not implemented
Core's `MaybeSendFeefilter` returns early on `m_opts.ignore_incoming_txs`
(L5542). hotbuns has no concept of `-blocksonly` mode. Configurable
in Core via `-blocksonly=1` startup flag; not surfaced in hotbuns CLI.
Wire-equivalent only because hotbuns runs in default (non-blocksonly)
mode; if blocksonly were ever added, this gate also needs to be added
to `maybeSendFeeFilter`. P1-API (structural absence).

### BUG-14 P1-API — `HasPermission(ForceRelay)` not implemented
Core (L5545) returns early in `MaybeSendFeefilter` for peers with
`NetPermissionFlags::ForceRelay`. hotbuns has no NetPermissionFlags
machinery (the noban field is the only permission flag implemented).
P1-API; same class as BUG-13.

### BUG-15 P1-WIRE — feefilter not suppressed for FeelerConn / AddrFetchConn
Core suppresses feefilter via `IsBlockOnlyConn()` (which encompasses
feeler) at L5548. hotbuns suppresses via
`connType !== "block_relay"` at manager.ts:1876. hotbuns does not
have `feeler` or `addr_fetch` as connection-type values
(`PeerConnType = "full_relay" | "block_relay" | "inbound" | "manual"`).
Manual peers (operator-added) get feefilter — Core would also send
to them (manual is not in the suppression list). Inbound peers get
feefilter — Core does too. So the divergence is structural only:
hotbuns can't represent feeler/addrfetch, so the gate is degenerate.

### BUG-16 P0-CDIV — wtxidrelay sent without WTXID_RELAY_VERSION gate
`peer.ts:1241` sends `wtxidrelay` unconditionally in response to
peer VERSION. Core (net_processing.cpp:3710) sends ONLY if
`greatest_common_version >= WTXID_RELAY_VERSION` (70016).
hotbuns's MIN_PEER_PROTO_VERSION is 70015, so any peer with version
70015 (still allowed) gets a wtxidrelay it cannot interpret. Core
would not send to that peer.
Downstream consequence: a peer running protocol 70015 sees
`wtxidrelay` and reacts per its implementation — some impls
disconnect, some log and ignore. The Core-correct behavior is to
NOT send if `common_version < 70016`.

### BUG-17 P0-CDIV — Incoming wtxidrelay after VERACK is silently ignored (Core disconnects)
Core's wtxidrelay handler (net_processing.cpp:3919-3939) **disconnects
the peer** if wtxidrelay arrives after `fSuccessfullyConnected == true`:
> "Disconnect peers that send a wtxidrelay message after VERACK."

Hotbuns has two layers of post-VERACK handling:

1. `peer.ts:1167-1179` `handleMessage` checks
   `if (this.receivedVersion && !this.handshakeComplete)` and gates the
   allow-list of "wtxidrelay", "sendaddrv2", "sendtxrcncl", "verack"
   for that window. So **post-VERACK wtxidrelay** falls through to
   `else if (this.state === "connected") { this.events.onMessage(...) }`
   at L1182.
2. `manager.ts:1896-1938` `handlePeerMessage` has NO case for
   `wtxidrelay` — only `ping`, `addr`, `addrv2`, `feefilter`. The
   message is dispatched to registered handlers (L1930), but no
   handler is registered. **Silently ignored.**

The legacy check at `peer.ts:1266-1269`
(`if (this.handshakeComplete) misbehaving(10, ...)`) is **DEAD CODE**:
`handleHandshake` is only called when `!handshakeComplete` per the
outer guard at L1158/L1181. The check is unreachable.

Wire divergence: Core disconnects; hotbuns swallows. Anti-DoS class.
P0-CDIV.

### BUG-18 P2 — No log on duplicate wtxidrelay
Core logs `"ignoring duplicate wtxidrelay from peer=%d"` at L3933
when `peer.m_wtxid_relay == true` and we receive another. hotbuns
silently re-sets `this.wtxidRelay = true` at `peer.ts:1270` (idempotent
overwrite). Effect-equivalent, but log-trace-divergent. P2.

### BUG-19 P1-WIRE — No log on wtxidrelay with old common version
Core logs `"ignoring wtxidrelay due to old common version=%d"` at
L3936 and DOES NOT set `m_wtxid_relay`. hotbuns has no
common-version gate on incoming wtxidrelay; `peer.ts:1262-1271`
unconditionally sets `wtxidRelay = true` regardless of peer version.
If hotbuns ever lowers `MIN_PEER_PROTO_VERSION` below 70016 to support
older peers, this path activates a wire-divergence: hotbuns starts
sending MSG_WTX(5) inv announcements to peers that cannot decode them.

### BUG-20 P1-API — No `m_wtxid_relay_peers` counter
Core maintains `std::atomic<int> m_wtxid_relay_peers` at
net_processing.cpp:837, incremented when a peer's wtxidrelay arrives
(L3931) and decremented on FinalizeNode (L1688-1689). This counter is
asserted in invariants (`assert(m_wtxid_relay_peers == 0)` at L1727
in shutdown). hotbuns tracks `wtxidRelay` per peer only, no
manager-level counter. Useful for diagnostics
(`getpeerinfo`-class RPCs) and for the `IsAddrFetchConn` invariant.
P1-API.

### BUG-21 P1-API — `tx_relay` substructure not modelled
Core's Peer has a `TxRelay* m_tx_relay` substructure (initialized only
for `!IsBlockOnlyConn() && !IsFeelerConn()` connections) that holds
`m_fee_filter_sent`, `m_fee_filter_received`, `m_relay_txs`,
`m_bloom_filter`, `m_tx_inventory_to_send`, `m_tx_inventory_known_filter`.
Hotbuns flattens all of these onto `Peer` directly, including for
block-relay-only peers. Behavior-equivalent because the block-relay
path simply never queues txs, but it's a P1-API gap that compounds
BUG-15 (no FeelerConn / AddrFetchConn type) — hotbuns can't easily
add the missing connection-type-based suppression because the
structural unit (`tx_relay == nullptr`) doesn't exist.

---

## Bug summary

| ID | Severity | Location | Description |
|----|----------|----------|-------------|
| BUG-1 | **P0-CDIV** | `feefilter.ts` (absent) | `WTXID_RELAY_VERSION = 70016` constant not exported |
| BUG-2 | P1-WIRE | `peer.ts:1322` | sendheaders sent without `SENDHEADERS_VERSION` gate |
| BUG-3 | P1-API | `peer.ts:1310-1331` | `m_sent_sendheaders` once-latch absent |
| BUG-4 | P1-WIRE | `peer.ts:1322` | sendheaders sent immediately on VERACK, not delayed until headers-sync done |
| BUG-5 | P1-WIRE | `manager.ts:863-887` | No periodic `MaybeSendSendHeaders` invocation |
| BUG-6 | **P0-CDIV** | `peer.ts` + `manager.ts` (absent) | Incoming sendheaders silently ignored; no `prefersHeaders` state |
| BUG-7 | **P0-CDIV** | `relay.ts:234-245` | Block announcement always uses inv, never headers |
| BUG-8 | P1-WIRE | `manager.ts:495` | `feeFilterInterval` declared but never set; periodic `maybeSendFeeFilter` is dead code |
| BUG-9 | P2 | `feefilter.ts` | No `FeeFilterRounder` (anti-side-channel) |
| BUG-10 | P1-WIRE | `feefilter.ts:93-98` | `min_relay_feerate` floor not re-applied in `getFeeRateToAnnounce` |
| BUG-11 | P1-WIRE | `feefilter.ts` (absent) | No MAX_FILTER reset after exit-IBD |
| BUG-12 | P1-WIRE | `messages.ts:717+1171` | feefilter payload uint64 encoding (Core: int64 CAmount) |
| BUG-13 | P1-API | `feefilter.ts` (absent) | `-blocksonly` / `ignore_incoming_txs` not implemented |
| BUG-14 | P1-API | `feefilter.ts` (absent) | `ForceRelay` permission not implemented |
| BUG-15 | P1-WIRE | `manager.ts:1876` | feefilter suppression list missing feeler/addrfetch |
| BUG-16 | **P0-CDIV** | `peer.ts:1241` | wtxidrelay sent without `WTXID_RELAY_VERSION` gate |
| BUG-17 | **P0-CDIV** | `peer.ts:1262-1271` + `manager.ts:1896-1938` | post-VERACK wtxidrelay silently ignored (Core disconnects) |
| BUG-18 | P2 | `peer.ts:1262-1271` | Duplicate wtxidrelay silently re-set, no log |
| BUG-19 | P1-WIRE | `peer.ts:1262-1271` | No common-version gate on incoming wtxidrelay |
| BUG-20 | P1-API | `manager.ts` (absent) | No `m_wtxid_relay_peers` counter |
| BUG-21 | P1-API | `peer.ts` (structural) | `tx_relay` substructure not modelled |

**Total: 21 distinct bugs.** P0-CDIV = 5, P1-WIRE = 8, P1-API = 6,
P2 = 2.

---

## Top 5 findings (operator-priority order)

1. **BUG-8 P1-WIRE — Dead `maybeSendFeeFilter` infrastructure.** The
   only feefilter hotbuns ever sends is the one-shot
   `sendInitialFeeFilter` at handshake completion. The Poisson
   re-broadcast, the substantial-change hysteresis trigger, and the
   IBD-exit reset are all dead code because `feeFilterInterval` is
   declared but never assigned. Fix is one block in `manager.ts:start()`:
   ```ts
   this.feeFilterInterval = setInterval(() => {
     const now = Date.now();
     for (const peer of this.peers.values()) {
       if (peer.state !== "connected") continue;
       const ct = this.peerConnectionType.get(`${peer.host}:${peer.port}`);
       this.feeFilterManager.maybeSendFeeFilter(peer, now, ct === "block_relay");
     }
   }, 60_000);  // 1-min tick; Core uses per-SendMessages-tick
   ```
   Plus `clearInterval(this.feeFilterInterval)` in `stop()`. Same dead-
   helper-at-call-site pattern as W120 nimrod `validateRbfDiagram`
   (FIX-79). **Cross-impl candidate** — likely other impls also wired
   up `maybeSendFeeFilter` but forgot to schedule it.

2. **BUG-6 + BUG-7 P0-CDIV — Block announcement never uses headers.**
   The whole BIP-130 mechanism is non-functional on hotbuns. We
   advertise our preference (via outgoing sendheaders, modulo BUG-4)
   but we ignore incoming sendheaders. So:
   - Peers who receive our sendheaders send us their new blocks as
     `headers` (Core-correct).
   - Peers who send us sendheaders are ignored; we send them `inv`
     for new blocks instead of `headers` (BIP-130 violation).
   - Block-propagation latency to our peers is one extra
     `getheaders` round-trip per block.
   Fix path: add `prefersHeaders: boolean` to Peer (or
   PeerRelayQueue), dispatch incoming sendheaders to flip it, and
   branch `relayBlockToAll` between `headers` and `inv` send shapes.
   Estimate: ~50 LOC across `peer.ts`, `manager.ts`, `relay.ts`.

3. **BUG-17 P0-CDIV — post-VERACK wtxidrelay is anti-DoS-divergent.**
   Core disconnects a peer that sends wtxidrelay after VERACK; hotbuns
   silently swallows. The misbehavior check at `peer.ts:1266-1269` is
   **dead code** — `handleHandshake` is only invoked when
   `!handshakeComplete`. To fix:
   - Move the post-VERACK check from inside the `case "wtxidrelay"`
     arm in `handleHandshake` to `handleMessage` (the outer dispatcher
     reached for both pre- and post-handshake messages).
   - Or: in `handlePeerMessage` (manager.ts), add `else if (msg.type === "wtxidrelay")` 
     → `peer.disconnect("wtxidrelay after verack")`.
   The bug pairs with **a meta-pattern**: dead-code misbehavior arms
   inside `handleHandshake` for `sendaddrv2` and `sendtxrcncl` are
   **also** unreachable post-VERACK by the same logic. So BUG-17
   probably has 3 sibling bugs of the same shape (cross-impl, cross-
   message, same root cause: misplaced post-VERACK check).

4. **BUG-16 P0-CDIV — wtxidrelay version-gate.** hotbuns sends
   wtxidrelay to any peer ≥ 70015. Core requires ≥ 70016. The fix is
   one line at `peer.ts:1241`:
   ```ts
   if (versionPayload.version >= WTXID_RELAY_VERSION) {
     this.send({ type: "wtxidrelay", payload: null });
   }
   ```
   Where `WTXID_RELAY_VERSION = 70016` is added to `feefilter.ts`
   (or better, a new `protocol_version.ts` to host all
   `*_VERSION` constants — addressing BUG-1).

5. **BUG-9 P2 — Privacy leak via unrounded feefilter.** Adversarial
   peers can probe hotbuns's mempool min-fee by repeatedly asking
   "what filter do you broadcast?" and observing exact values. Core's
   `FeeFilterRounder::round` adds noise (random downward bucket-step
   with 1/3 probability). Lower priority than the relay-correctness
   bugs above, but the fix is bounded:
   precompute `MakeFeeSet(min_incremental_fee, MAX_FILTER_FEERATE, FEE_FILTER_SPACING)`
   at module load and round the broadcast value through it.
   ~30 LOC.

## Universal-pattern candidates

- **"Dead helper at call site"** (BUG-8) — `maybeSendFeeFilter`
  exists, is well-formed, has test coverage, but no scheduler ever
  invokes it. Same shape as W120 nimrod `validateRbfDiagram` (FIX-79),
  ouroboros `cfheaders` orphan-fork path (FIX-79), and earlier waves'
  dead-helper closures. **Fleet-sweep candidate**: grep for
  `setInterval.*null` + corresponding `null` initializers across all
  10 impls; any pattern that declares a periodic-broadcast field and
  never sets it is likely the same bug shape for the corresponding
  BIP-133/130/339 logic. Likely cross-impl pattern.

- **"Dead misbehavior arm inside handleHandshake"** (BUG-17 + likely
  siblings for sendaddrv2 / sendtxrcncl) — `handleHandshake` is only
  invoked when `!handshakeComplete`, so any `if (this.handshakeComplete) misbehaving(...)`
  inside that function is unreachable. Cross-impl check: any impl
  whose handshake state machine has separate `handleHandshake` /
  `handleConnected` dispatch paths and replicates Core's "disconnect
  on post-VERACK feature-negotiation" rule may have placed the
  misbehavior check in the unreachable branch. **Cross-impl candidate.**

- **"Outgoing feature-negotiation without common-version gate"** (BUG-2
  for SENDHEADERS, BUG-16 for WTXIDRELAY; W126 BUG-17 already
  documented the same for SENDCMPCT) — hotbuns sends BIP-130 / 152 /
  339 feature negotiation messages without checking the protocol-
  version gate that Core uses. Three feature-negotiation messages
  with the same bug shape; the pattern is structural (no
  `getCommonVersion()` helper, no `*_VERSION` constants centralized).
  **Cross-impl candidate** — likely other impls that copied hotbuns's
  unconditional-send pattern have the same triple-bug.

- **"Privacy-class side-channel in fee broadcasts"** (BUG-9) — Core
  introduced `FeeFilterRounder` specifically to prevent inferring
  mempool min-fee from feefilter broadcasts. Any impl that broadcasts
  raw feerate values leaks this side channel. **Fleet sweep**: any
  impl whose feefilter sender lacks a randomized-rounding helper has
  the same leak.

- **"int64 vs uint64 wire shape"** (BUG-12) — Core's CAmount is
  int64_t and `feefilter` is serialized via that path. Any impl that
  uses an unsigned 64-bit reader for the feerate field has the same
  shape-divergence (behavior-equivalent today via MoneyRange, but
  fragile). Cross-impl check.
