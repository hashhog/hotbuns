# W126 — BIP-152 Compact Blocks parity audit (hotbuns)

**Impl:** hotbuns (TypeScript / Bun)
**Date:** 2026-05-17
**Status:** DISCOVERY — 21 BUGS / 30 gates (8 PRESENT / 6 PARTIAL / 16 MISSING)
**Tests:** `src/__tests__/w126_bip152_compact_blocks.test.ts` (xfail/assertion-only)
**No production code changes.**

## Reference

- `bitcoin-core/src/blockencodings.cpp` + `blockencodings.h` —
  `CBlockHeaderAndShortTxIDs::FillShortTxIDSelector` /
  `GetShortID` / `PartiallyDownloadedBlock::InitData` /
  `PartiallyDownloadedBlock::FillBlock`.
- `bitcoin-core/src/net_processing.cpp` — SENDCMPCT / CMPCTBLOCK /
  GETBLOCKTXN / BLOCKTXN handlers, `MaybeSetPeerAsAnnouncingHeaderAndIDs`,
  `NewPoWValidBlock` fast-announce, `SendBlockTransactions`,
  `vExtraTxnForCompact` extra-tx pool.
- `bitcoin-core/src/node/protocol_version.h` —
  `SHORT_IDS_BLOCKS_VERSION = 70014`, `INVALID_CB_NO_BAN_VERSION = 70015`.
- `bitcoin-core/src/consensus/validation.cpp` — `IsBlockMutated()` used
  in `PartiallyDownloadedBlock::FillBlock` final mutation check.
- BIP-152 (Compact Block Relay).

## Background — BIP-152 contract

BIP-152 compresses block announcements from ~1 MB to ~10 KB by replacing
each non-coinbase transaction with a 6-byte short ID derived via
SipHash-2-4 with keys derived from the block header + nonce. The receiver
reconstructs the full block by matching short IDs against its mempool,
extra-tx pool (recently-evicted, conflicted, etc.), and prefilled txs.
Missing txs are requested via `getblocktxn`. Per BIP-152:

| Message | Wire shape |
|---------|------------|
| `sendcmpct` | `bool announce; uint64 version;` |
| `cmpctblock` | `CBlockHeader header; uint64 nonce; varint short_id_count; (6 bytes) × short_id_count; varint prefilled_count; (varint diff_idx; tx) × prefilled_count` |
| `getblocktxn` | `uint256 blockhash; varint count; (varint diff_idx) × count` |
| `blocktxn` | `uint256 blockhash; varint count; (tx) × count` |

Core lays out three protocol-version gates and three depth gates:

| Constant | Value | Purpose |
|----------|-------|---------|
| `SHORT_IDS_BLOCKS_VERSION` | 70014 | Min protocol version to advertise `sendcmpct` |
| `INVALID_CB_NO_BAN_VERSION` | 70015 | Min version to receive fast-announce cmpctblock |
| `CMPCTBLOCKS_VERSION` | 2 | Only v2 (witness-serialised) accepted on the wire |
| `MAX_CMPCTBLOCK_DEPTH` | 5 | Receiver refuses cmpctblock deeper than tip-5 |
| `MAX_BLOCKTXN_DEPTH` | 10 | Server refuses `getblocktxn` for blocks deeper than tip-10 |
| `MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK` | 3 | Maximum parallel cmpctblock attempts per block |

Three high-bandwidth peer slots are maintained via
`MaybeSetPeerAsAnnouncingHeaderAndIDs`, an LRU-style FIFO that promotes
peers whose latest-announced block validated cleanly.

## Architecture summary — hotbuns BIP-152 stack

- **One helper module**: `src/p2p/compact_blocks.ts` (~1041 lines). Contains
  - SipHash-2-4 short-id helpers (`deriveSipHashKeys`, `computeShortTxId`,
    `computeShortTxIdValue`, `shortIdToValue`, `valueToShortId`).
  - `createCompactBlockFromBlock` — block → compact payload.
  - `PartiallyDownloadedBlock` class with `initData` /
    `fillFromMempool` / `fillFromBlockTxn` / `getBlock` / mutation check.
  - `CompactBlockManager` class — per-peer negotiation state, statistics,
    high-bandwidth peer set (max 3), `handleSendCmpct`,
    `startBlockReconstruction`, `handleBlockTxn`, `removePeer`.
  - `createBlockTxnResponse` — server-side helper that turns a block + a
    `getblocktxn` request into a `blocktxn` payload.
- **Wire codec**: `src/p2p/messages.ts` lines 222-285 (types), 710-782
  (serializers), 1164-1249 (deserializers). All four BIP-152 message
  types are typed, serialised, and deserialised. DoS allocation cap is
  set at 65535 (uint16_t max) via `MAX_CMPCT_TOTAL_TX`.
- **Handshake hook**: `src/p2p/peer.ts:1324-1329` — every peer is
  notified `sendcmpct(enabled=false, version=2)` once verack completes.
- **Dispatch**: `src/sync/blocks.ts:638-724` — four `peerManager.onMessage`
  handlers wired for `sendcmpct` / `cmpctblock` / `getblocktxn` /
  `blocktxn`. All four are **log-only stubs** that never call into
  `CompactBlockManager`. The `cmpctblock` handler responds to every
  incoming cmpctblock by issuing a full-block `getdata` (BUG-2/BUG-3 —
  the existing comment at sync/blocks.ts:669 names CompactBlockManager
  as a "dead helper").

## The big finding — `CompactBlockManager` is a dead helper

The single largest finding of this audit is that `CompactBlockManager`,
`PartiallyDownloadedBlock`, `createCompactBlockFromBlock`,
`createBlockTxnResponse`, and `deriveSipHashKeys` are **wholly
unreferenced from any code path that actually runs at runtime**:

```
$ rg "CompactBlockManager\b|new PartiallyDownloadedBlock\b|createCompactBlockFromBlock\b|createBlockTxnResponse\b" hotbuns/src/
  src/p2p/compact_blocks.ts        — definitions only
  src/__tests__/compact_blocks.test.ts  — direct unit tests
  src/__tests__/w123_mining_gbt.test.ts — source-grep only (G29)
```

The `sync/blocks.ts:669` comment confirms this is known:

```ts
// Request the full block via getdata since we can't reconstruct
// from compact block without a mempool (BUG-2/BUG-3 — CompactBlockManager
// dead helper; wiring it is out of scope for FIX-42).
```

This is the **34th-streak** dead-helper-at-call-site finding documented
across the hashhog audit project. The 1041-line helper module is fully
correct against Core (every gate in the existing W89 unit tests
verifies a Core invariant), but at runtime the only thing hotbuns
actually does on receipt of a `cmpctblock` is fall back to a full block
download. This entirely defeats the purpose of BIP-152, which is to cut
block-propagation bandwidth by ~100x.

Sister observation — `sync/blocks.ts:687` only **logs** the contents of
`sendcmpct` and never stores the peer's preference; the very next
incoming cmpctblock from a high-bandwidth peer is treated identically to
any other peer (full-block fallback) because no state is kept.

## Bug inventory (21 distinct findings)

### P0-CDIV — consensus-divergent / spec-broken

- **BUG-1** (gate G15) — **`CompactBlockManager` is never wired into
  the message dispatch path.** `src/sync/blocks.ts:643-680` handles
  incoming `cmpctblock` by issuing a full-block `getdata` and never
  calling `manager.startBlockReconstruction()` /
  `partial.fillFromMempool()` / `partial.getBlock()`. Every cmpctblock
  on the wire is wasted. The 1041-line `compact_blocks.ts` module is
  effectively dead code on the active code path.
  - `src/p2p/compact_blocks.ts:717-1003` (`CompactBlockManager` class).
  - `src/sync/blocks.ts:643-680` (the call site that should use it).
  - Core: `src/net_processing.cpp:4574-4634` — the central
    `PartiallyDownloadedBlock` + `getblocktxn` orchestration that
    hotbuns has built but never invokes.
  - **Severity**: this is the entire BIP-152 protocol. Without this
    wiring hotbuns gains zero of the bandwidth savings BIP-152 promises.

- **BUG-2** (gate G18) — **`createBlockTxnResponse` is never called.**
  When a peer asks us via `getblocktxn` for missing transactions to
  reconstruct a block they received from us, hotbuns logs the request
  (after a depth check), then returns silently:
  ```ts
  // We don't serve compact blocks yet (BUG-5 — getblocktxn serve path is a stub).
  // The depth guard above is in place; full serving is out of scope for FIX-42.
  ```
  - `src/sync/blocks.ts:692-719` (the silent-drop handler).
  - `src/p2p/compact_blocks.ts:1016-1033` (the unused `createBlockTxnResponse`).
  - Core: `src/net_processing.cpp:4245-4304` calls
    `SendBlockTransactions(pfrom, peer, block, req)`. By not responding
    we look unreachable to compact-block-relay peers — they fall back
    to full-block `getdata` against another peer, but observers measure
    us as a "BIP-152-broken" node.

- **BUG-3** (gate G14) — **`blocktxn` handler is empty.** When we ask a
  peer for missing transactions via `getblocktxn` and they reply with
  `blocktxn`, the handler at `src/sync/blocks.ts:722-724` no-ops:
  ```ts
  peerManager.onMessage("blocktxn", (_peer, _msg) => {
    // We fall back to full block download, so we shouldn't receive these
  });
  ```
  This *is* internally consistent with BUG-1 (since we never issue
  `getblocktxn`, we should never receive `blocktxn`), but the moment
  BUG-1 is fixed BUG-3 must be fixed in lock-step or we'll silently
  drop the reply and stall forever. Currently a malicious peer that
  speculatively pushes `blocktxn` for any block hash gets no DoS
  penalty either.
  - Core: `src/net_processing.cpp:4714-4726` calls
    `ProcessCompactBlockTxns(pfrom, peer, resp)`.

- **BUG-4** (gate G16) — **`sendcmpct` handler is log-only.** The peer's
  HB preference, version, and "we provide compact blocks" flag are all
  discarded:
  ```ts
  peerManager.onMessage("sendcmpct", (peer, msg) => {
    if (msg.type === "sendcmpct") {
      console.log(`Peer ... supports compact blocks: ...`);
    }
  });
  ```
  - `src/sync/blocks.ts:683-690`. Should call
    `manager.handleSendCmpct(peerId, msg.payload.enabled, msg.payload.version)`.
  - Core: `src/net_processing.cpp:3901-3917` — store
    `m_provides_cmpctblocks`, `m_requested_hb_cmpctblocks`,
    `m_bip152_highbandwidth_from`. Without this we can't even
    enumerate which peers we *could* send compact blocks to.

- **BUG-5** (gate G24) — **No fast-announce path
  (`NewPoWValidBlock` equivalent).** Core's
  `PeerManagerImpl::NewPoWValidBlock` (`net_processing.cpp:2103-2152`)
  fires when *we* validate a new block and immediately pushes a
  cmpctblock to every HB peer for whom we have already announced the
  parent. hotbuns has no equivalent — when our chain advances we
  announce only via inv/headers, losing the BIP-152 latency advantage
  for outgoing announcements.
  - `src/p2p/compact_blocks.ts` exposes `createCompactBlockFromBlock`
    that would compose the payload, but it's never called from chain
    state. Confirmed by `rg "createCompactBlockFromBlock\b" src/`
    returning only test files.
  - Core line refs: 2103-2152.

### P0 — wrong default / wrong invariant

- **BUG-6** (gate G19) — **Outgoing `sendcmpct` always announces
  low-bandwidth.** `src/p2p/peer.ts:1326-1329` sends
  `{ enabled: false, version: 2n }` to every peer at handshake. Even
  after `MaybeSetPeerAsAnnouncingHeaderAndIDs` decides to promote three
  outbound peers, hotbuns never resends `sendcmpct(true, 2)` — so no
  peer ever knows we want them as a high-bandwidth source. Combined
  with BUG-5 this means hotbuns is completely passive in the BIP-152
  ecosystem: we neither push cmpctblocks nor receive HB cmpctblocks.
  - Core: `MaybeSetPeerAsAnnouncingHeaderAndIDs` calls
    `MakeAndPushMessage(*pfrom, NetMsgType::SENDCMPCT, /*high_bandwidth=*/true, ...)`
    at `net_processing.cpp:1323`.

- **BUG-7** (gate G20) — **`MaybeSetPeerAsAnnouncingHeaderAndIDs`
  equivalent is absent.** Core selects up to 3 outbound peers to act
  as our HB upstream after a peer's recently-relayed block validates
  cleanly (called from `BlockChecked` at 2196-2225). hotbuns has no
  `BlockChecked` callback that hooks chain validation back to peer
  selection. `CompactBlockManager.addHighBandwidthPeer()` exists
  (compact_blocks.ts:811-817) but is never called from chain state
  events — only from tests.
  - `src/p2p/compact_blocks.ts:811-817` (dead helper).
  - Core: `net_processing.cpp:1272-1329`.

- **BUG-8** (gate G3) — **`createCompactBlockFromBlock` always emits
  exactly one prefilled tx (the coinbase) — no predictive prefilling.**
  Core's TODO at `blockencodings.cpp:27` reads "Use our mempool prior
  to block acceptance to predictively fill more than just the
  coinbase." Although the comment marks this as a known suboptimality,
  Core still **uses peerMempoolTxids** when callers pass them. hotbuns
  exposes the `peerMempoolTxids` parameter but does **not** track per-peer
  mempool reception state, so callers can only pass an empty set in
  practice. When BIP-152 round-trips happen on a near-tip block the
  peer's mempool nearly always has the same set of txs as ours, so
  this is a per-block bandwidth amplifier *for the path we don't
  currently take*. Lower-priority because (a) it doesn't violate the
  spec and (b) the BUG-5 fast-announce path is missing too — fix
  BUG-5 first, then revisit BUG-8.

### P0-WIRE — wire-shape / serializer mismatch

- **BUG-9** (gate G5) — **`PrefilledTx.index` field type is `number`, but
  the differential gap is unbounded by uint16.** The serializer at
  `messages.ts:746` computes `diff = prefilled.index - lastIndex - 1`,
  writes it via `writeVarInt`, then sets `lastIndex = prefilled.index`.
  Core defines `PrefilledTransaction::index` as a `uint16_t`
  (`blockencodings.h:77`). The differentially-encoded gap can be up to
  the full uint16 range (65535), but JavaScript numbers can represent
  values up to 2^53-1, so a malicious peer could send a varint
  encoding for a 32-bit-or-larger diff, and hotbuns'
  `deserializeCmpctBlockPayload` would happily accept it
  (`messages.ts:1214-1218` — `const index = lastIndex + diff + 1` is
  unbounded). `initData` does check `absoluteIndex > 0xffff` at
  `compact_blocks.ts:425`, so the divergence is contained, but the
  decoder should reject before any allocation.
  - Core enforces uint16 strictly via `READWRITE(COMPACTSIZE(obj.index), ...)`
    plus `lastprefilledindex > std::numeric_limits<uint16_t>::max()` at
    `blockencodings.cpp:78`.

- **BUG-10** (gate G2) — **Per-PrefilledTx `index` is treated as a
  uint16 by the protocol but as a `number` (JavaScript int53) in
  hotbuns.** Same root cause as BUG-9 but at a different layer: the
  `PrefilledTx.index` type at `messages.ts:253-256` says `number;
  // differentially encoded index`, yet what's stored after
  `deserializeCmpctBlockPayload` is the **absolute** index. The
  docstring is wrong (the deserialiser converts diff → absolute on
  the way in). Cosmetic but actively misleading for anyone reading
  the type. The serialiser at `messages.ts:746` does the inverse
  (absolute → diff) on the way out. Recommend renaming docstring;
  better still, rename field to `absoluteIndex` since by the time it
  leaves the wire layer it IS absolute.

- **BUG-11** (gate G27) — **Differential-encoding decoder accepts
  non-strictly-increasing indices in `getblocktxn`.** Core enforces
  the strict-increasing invariant via the `DifferenceFormatter`
  (`blockencodings.h:34-42` — throws on overflow / wraparound) plus
  an explicit `Assume(req.indexes[i] > req.indexes[i-1])` at
  `net_processing.cpp:4250-4252`. hotbuns'
  `deserializeGetBlockTxnPayload` at `messages.ts:1224-1239` adds
  `diff + 1` to `lastIndex` per entry, so if the peer sends a diff
  of `0xffffffff` (uint32 max), `lastIndex` overflows
  silently into a negative-ish value when later JS `+ diff + 1`
  overflows past `Number.MAX_SAFE_INTEGER`. No `assertGt` /
  `assertLt` check is enforced. The downstream `createBlockTxnResponse`
  validator at `compact_blocks.ts:1022-1025` catches
  `idx >= block.transactions.length` but only returns null — never
  scores the peer or disconnects.
  - Core: `Misbehaving(peer, "getblocktxn with out-of-bounds tx indices")`
    at `net_processing.cpp:2603`.

### P1 — DoS / misbehaving-peer-disconnect gaps

- **BUG-12** (gate G22) — **No `Misbehaving()` score on
  `READ_STATUS_INVALID` from `PartiallyDownloadedBlock::initData`.**
  Core punishes with the score-100 `Misbehaving(peer, "invalid compact
  block")` at `net_processing.cpp:4594` whenever `initData` returns
  `READ_STATUS_INVALID`. Because hotbuns's dispatch path (BUG-1) never
  calls `initData`, we never reach this state. But the `compact_blocks.ts`
  `startBlockReconstruction` helper at lines 860-894 *just returns null*
  on invalid status and increments a stats counter — no peer-scoring
  hook is provided. Even if BUG-1 is fixed, the resulting wiring
  cannot DoS-score the peer because the helper doesn't take a "peer
  misbehaving callback" param.
  - Core: `net_processing.cpp:4592-4595`.

- **BUG-13** (gate G23) — **No `Misbehaving()` score for
  out-of-bounds tx indices in `getblocktxn`.** `createBlockTxnResponse`
  returns `null` (`compact_blocks.ts:1023`) when `idx >=
  block.transactions.length`, but Core punishes the peer with
  `Misbehaving(peer, "getblocktxn with out-of-bounds tx indices")` at
  `net_processing.cpp:2603`. Even after fixing BUG-2 (wire it up), the
  helper's return-null contract leaves no path for the call site to
  know which peer sent the bad request. Fix: return a discriminated
  result type with `{kind: "ok"; payload} | {kind: "misbehave"; reason: string}`.

- **BUG-14** (gate G28) — **No `Misbehaving()` on
  `cmpctblock` reconstruction-attempt-replay.** Core at
  `net_processing.cpp:3476` punishes a peer with score-100
  "previous compact block reconstruction attempt failed" when the
  peer sends `blocktxn` after we already filled the block (header is
  null). hotbuns has no equivalent because the entire `blocktxn`
  handler is empty (BUG-3).

- **BUG-15** (gate G29) — **No `Misbehaving()` on `blocktxn` that
  doesn't match `getblocktxn`.** Core at `net_processing.cpp:3487`
  punishes "invalid compact block/non-matching block transactions"
  when `FillBlock` returns `READ_STATUS_INVALID`. Same root cause as
  BUG-14.

- **BUG-16** (gate G30) — **Extra-tx pool (`vExtraTxnForCompact`)
  is not maintained.** Core maintains a ring buffer of recently
  rejected / orphan / replaced txs at
  `net_processing.cpp:997-999` + `1887-1890` (size set by
  `m_opts.max_extra_txs`, default 100, same as hotbuns's
  `MAX_EXTRA_TXN = 100` constant at `compact_blocks.ts:54`).
  `fillFromMempool` takes an `extraTxn` parameter but **nothing
  populates it from real chain events**. `rg "extraTxn" src/` shows
  only test code passing in fixtures. The constant `MAX_EXTRA_TXN`
  is exported but no ring buffer exists.
  - Core: `net_processing.cpp:1887-1890`.

### P1 — protocol-version gates

- **BUG-17** (gate G6) — **No `SHORT_IDS_BLOCKS_VERSION` gate on
  outgoing `sendcmpct`.** Core sends `sendcmpct` only when
  `pfrom.GetCommonVersion() >= SHORT_IDS_BLOCKS_VERSION` (70014) per
  `net_processing.cpp:3864-3870`. hotbuns sends `sendcmpct` to every
  peer regardless of their advertised version (`peer.ts:1324-1329`).
  A peer that advertised 70013 will receive a message they cannot
  parse — most clients will simply ignore it, but the spec says we
  shouldn't send it at all.

- **BUG-18** (gate G7) — **No `INVALID_CB_NO_BAN_VERSION` gate on
  outgoing fast-announce.** Core skips peers below 70015 in
  `NewPoWValidBlock` (`net_processing.cpp:2136`). hotbuns has no
  fast-announce path (BUG-5), so this gate is doubly absent. Tracking
  separately because the gate must exist when BUG-5 is fixed.

### P2 — internal inconsistency / dead-helper / test-comment-as-confession

- **BUG-19** (gate G25) — **"comment-as-confession" at
  `src/sync/blocks.ts:669-670`.** The comment names CompactBlockManager
  as a "dead helper" and explicitly defers the wiring to a (now-stale)
  FIX-42 task. This is the canonical "test-comment-as-confession"
  shape promoted to project-level meta-pattern in W122 — production
  code prose telling the reader the implementation is wrong. The
  same shape repeats at `src/sync/blocks.ts:717-718` ("BUG-5 — getblocktxn
  serve path is a stub"). FIX-42 is not in any open task list; the
  comments have outlived the planned fix.

- **BUG-20** (gate G26) — **`CompactBlockState.weWantHighBandwidth`
  is set but never read.** `compact_blocks.ts:771-779` (`sentSendCmpct`)
  writes the flag, but no code path checks
  `state.weWantHighBandwidth` to decide HB-peer behaviour. This is
  classic "well-engineered helper, never wired" — fields exist but
  the policy never consults them. `getNegotiatedVersion`,
  `isHighBandwidthPeer`, `addHighBandwidthPeer` similarly only read
  state set by tests.

- **BUG-21** (gate G21) — **`CompactBlockManager.removePeer` is
  never called on peer disconnect.** `compact_blocks.ts:971-975`
  cleans up the per-peer state map and HB set, but
  `src/p2p/manager.ts` (which controls peer disconnect events) has
  no integration. Memory leak: `CompactBlockManager.peerStates`
  grows unboundedly as peers connect and disconnect, while
  `highBandwidthPeers` accrues stale entries that prevent the next
  legitimate HB peer from being added (because `addHighBandwidthPeer`
  refuses past `MAX_HIGH_BANDWIDTH_PEERS = 3`).
  - The leak is dormant because BUG-1 means
    `CompactBlockManager` is never instantiated at runtime. Once
    BUG-1 is fixed, BUG-21 becomes a real memory leak.

## Gate matrix (30 gates)

| Gate | Topic | Status | Bug |
|------|-------|--------|-----|
| G1  | SipHash-2-4 short-id derivation present | **PRESENT** | — |
| G2  | uint16_t cap on PrefilledTx absolute index | **PARTIAL** | BUG-10 |
| G3  | Multi-tx prefilling beyond coinbase | **PARTIAL** | BUG-8 |
| G4  | `cmpctblock` message types defined / serialised | **PRESENT** | — |
| G5  | Differential encoding of prefilled indices on the wire | **PARTIAL** | BUG-9 |
| G6  | Outgoing `sendcmpct` gated by `SHORT_IDS_BLOCKS_VERSION` | **MISSING** | BUG-17 |
| G7  | Fast-announce gated by `INVALID_CB_NO_BAN_VERSION` | **MISSING** | BUG-18 |
| G8  | Only `CMPCTBLOCKS_VERSION = 2` accepted on the wire | **PRESENT** | — |
| G9  | `MAX_CMPCTBLOCK_DEPTH = 5` depth guard on receive | **PRESENT** | — |
| G10 | `MAX_BLOCKTXN_DEPTH = 10` depth guard on serve | **PRESENT** | — |
| G11 | `MAX_HIGH_BANDWIDTH_PEERS = 3` LRU limit | **PARTIAL** | BUG-21 |
| G12 | `IsBlockMutated` check in `FillBlock` | **PRESENT** | — |
| G13 | Bucket-size-12 DoS guard in `InitData` | **PRESENT** | — |
| G14 | `blocktxn` dispatch handler | **MISSING** | BUG-3 |
| G15 | `cmpctblock` dispatch handler calls `CompactBlockManager` | **MISSING** | BUG-1 |
| G16 | `sendcmpct` dispatch handler updates peer state | **MISSING** | BUG-4 |
| G17 | `MaybeSetPeerAsAnnouncingHeaderAndIDs` equivalent | **MISSING** | BUG-7 |
| G18 | `getblocktxn` serve path (calls `createBlockTxnResponse`) | **MISSING** | BUG-2 |
| G19 | HB-peer outgoing `sendcmpct(true, 2)` after promotion | **MISSING** | BUG-6 |
| G20 | `BlockChecked` → HB-peer selection hook | **MISSING** | BUG-7 |
| G21 | `removePeer` called on peer disconnect | **MISSING** | BUG-21 |
| G22 | `Misbehaving(peer, "invalid compact block")` on INVALID | **MISSING** | BUG-12 |
| G23 | `Misbehaving(peer, "getblocktxn ... out-of-bounds")` | **MISSING** | BUG-13 |
| G24 | `NewPoWValidBlock` fast-announce path | **MISSING** | BUG-5 |
| G25 | `compact_blocks.ts` referenced by chain/sync code path | **MISSING** | BUG-19 |
| G26 | `weWantHighBandwidth` state field read after write | **MISSING** | BUG-20 |
| G27 | Strict-increasing decoder check on `getblocktxn` indices | **MISSING** | BUG-11 |
| G28 | `Misbehaving` on "previous reconstruction attempt failed" | **MISSING** | BUG-14 |
| G29 | `Misbehaving` on `blocktxn` with non-matching txs | **MISSING** | BUG-15 |
| G30 | `vExtraTxnForCompact` ring buffer maintained | **MISSING** | BUG-16 |

**Tallies**: 8 PRESENT / 6 PARTIAL / 16 MISSING / 21 bugs.

## Top findings

1. **Dead-helper-at-call-site, fleet-wide.** `CompactBlockManager` is
   a textbook example of the dead-helper pattern: 1041 lines of
   well-engineered Core-parity code with 38 unit tests, **and zero
   runtime invocations**. The 34-streak across the project remains
   unbroken.
2. **"Test-comment-as-confession" repeats.** Production code prose at
   `sync/blocks.ts:669-670` and `:717-718` says "BUG-X — dead helper",
   "FIX-42 out of scope", "stub". These mark known but uncorrected
   gaps and have outlived their planned fix wave. Same shape as W120
   BUG-5 (FullRBF comment), W122 BUG-1 (blockfilters byte-exact
   comment).
3. **All four BIP-152 dispatch handlers are stubs.** `cmpctblock` /
   `sendcmpct` / `getblocktxn` / `blocktxn` (sync/blocks.ts:643-724)
   either log only or directly fall back to full-block download. The
   only working part of the BIP-152 protocol in hotbuns is the
   protocol *announcement* (peer.ts:1324-1329 sends `sendcmpct(false,
   2)`) and the message *codec* (messages.ts) — the entire interior
   of the protocol is not running.
4. **Hotbuns is invisible to compact-block-relay neighbours.** Because
   sending `enabled=false` low-bandwidth and never promoting peers to
   HB (BUG-6 + BUG-7), hotbuns appears to every BIP-152-supporting
   peer as a node that doesn't want compact blocks. We will never
   receive HB-fast-announces. Combined with BUG-5 (no outgoing
   fast-announce), hotbuns is *silent* in both directions of BIP-152.
5. **Misbehaving-peer-disconnect chain is broken throughout BIP-152.**
   Four distinct `Misbehaving()` punishment sites in Core's compact-
   block path (gates G22, G23, G28, G29) have no equivalent in hotbuns.
   This matches the meta-pattern from W121 BUG-5 (universal-DoS-gaps in
   filter dispatch) — DoS scoring is consistently the last thing to be
   wired when a new P2P feature is implemented, and BIP-152 is no
   exception.

## Out of scope

- BIP-152 v1 (non-witness) — Core rejects on receipt and only sends v2;
  hotbuns matches Core's "v2-only" behaviour at `compact_blocks.ts:756`.
- Cross-impl wire-vector cross-validation (would belong in a future
  W127-style fleet-wide audit).
- Wiring fixes — this is a discovery-only wave. Recommended next fix
  waves (in dependency order):
  1. **FIX-X**: wire `CompactBlockManager` into sync/blocks.ts
     dispatch (closes BUG-1 + BUG-3 + BUG-4 + BUG-21).
  2. **FIX-Y**: serve `getblocktxn` via `createBlockTxnResponse`
     (closes BUG-2 + BUG-13).
  3. **FIX-Z**: hook `NewPoWValidBlock` fast-announce +
     `BlockChecked` HB-peer promotion (closes BUG-5 + BUG-6 + BUG-7
     + BUG-18).
  4. **FIX-W**: wire `vExtraTxnForCompact` from
     mempool-rejected / orphan-pool events (closes BUG-16).
  5. **FIX-V**: differential-encoding decoder hardening (closes BUG-9
     + BUG-10 + BUG-11) + Misbehaving wiring (closes BUG-12 + BUG-14
     + BUG-15) + `SHORT_IDS_BLOCKS_VERSION` gate (closes BUG-17).
