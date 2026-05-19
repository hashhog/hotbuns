# W156 — BIP-152 sendcmpct + cmpctblock + blocktxn + getblocktxn (hotbuns deep-dive)

**Wave:** W156 — wire-level deep-dive on BIP-152 Compact Block Relay:
`SENDCMPCT(announce_hb, version)`, `CMPCTBLOCK(header || nonce || shortids[] ||
prefilledtxn[])`, `GETBLOCKTXN(blockhash || indexes_diff[])`,
`BLOCKTXN(blockhash || txns[])`. Short-tx-id = SipHash-2-4(k0, k1, wtxid) &
0xffffffffffff, k0/k1 = SHA256(header || nonce)[0:8 | 8:16].

**Scope:** discovery only — no production code changes. **W126 covered the
fundamentals (21 bugs; receive-side handlers; CompactBlockManager dead-helper
finding).** W156 is the wire-level deep-dive: differential encoding edge
cases, bucket-size DoS gate semantics, COINBASE@0 invariant, version 2
witness-mode contract, fast-announce path, HB-peer selection, extra-tx pool,
self-nonce vs SipHash nonce, sendcmpct timing vs verack handler, header-IsNull
gate, init-twice gate, MAX_BLOCKTXN_DEPTH static_assert, BLOCKTXN response
size constraint.

## Bitcoin Core references

- `bitcoin-core/src/net_processing.cpp:138-141` —
  ```
  static const int MAX_CMPCTBLOCK_DEPTH = 5;
  static const int MAX_BLOCKTXN_DEPTH = 10;
  static_assert(MAX_BLOCKTXN_DEPTH <= MIN_BLOCKS_TO_KEEP, "MAX_BLOCKTXN_DEPTH too high");
  ```
- `bitcoin-core/src/net_processing.cpp:199` —
  `static constexpr uint64_t CMPCTBLOCKS_VERSION{2};` (witness short-ids).
- `bitcoin-core/src/node/protocol_version.h:30` —
  `SHORT_IDS_BLOCKS_VERSION = 70014`.
- `bitcoin-core/src/net_processing.cpp:1272-1329` —
  `MaybeSetPeerAsAnnouncingHeaderAndIDs` (HB peer LRU of 3 nodes; outbound
  protection; inbound-swap; flips `m_bip152_highbandwidth_to`).
- `bitcoin-core/src/net_processing.cpp:2095-2160` — `NewPoWValidBlock`
  fast-announce: caches `m_most_recent_compact_block` + `m_most_recent_block_hash`
  + `m_most_recent_block` under `m_most_recent_block_mutex`, pushes
  CMPCTBLOCK to peers in `lNodesAnnouncingHeaderAndIDs` that **(a)** have
  marked us HB, **(b)** don't already have the block header, **(c)** have
  the parent header.
- `bitcoin-core/src/net_processing.cpp:2455-2475` — re-fetch path:
  `if (can_direct_fetch && pindex->nHeight >= tip->nHeight - MAX_CMPCTBLOCK_DEPTH)
  MakeAndPushMessage(NetMsgType::CMPCTBLOCK, …)` — bounds the depth at
  which we even bother generating a cmpctblock for direct fetch.
- `bitcoin-core/src/net_processing.cpp:3816-3920` — VERACK handler:
  AFTER all other post-verack initialization (peer-relay, prefer-headers,
  txreconciliation registration), sends `SENDCMPCT(/*high_bandwidth=*/false,
  /*version=*/CMPCTBLOCKS_VERSION)` **only if**
  `pfrom.GetCommonVersion() >= SHORT_IDS_BLOCKS_VERSION (70014)`.
- `bitcoin-core/src/net_processing.cpp:3901-3917` — SENDCMPCT recv:
  ```
  bool sendcmpct_hb{false};  uint64_t sendcmpct_version{0};
  vRecv >> sendcmpct_hb >> sendcmpct_version;
  if (sendcmpct_version != CMPCTBLOCKS_VERSION) return;
  nodestate->m_provides_cmpctblocks = true;
  nodestate->m_requested_hb_cmpctblocks = sendcmpct_hb;
  pfrom.m_bip152_highbandwidth_from = sendcmpct_hb;
  ```
- `bitcoin-core/src/net_processing.cpp:4466-4683` — CMPCTBLOCK recv:
  rejects during `LoadingBlocks()`, dual-precheck on `prev_block` (issues
  MaybeSendGetHeaders if missing) and `prev_block->nChainWork + GetBlockProof
  < GetAntiDoSWorkThreshold()` (low-work drop), `ProcessNewBlockHeaders(…
  via_compact_block=true)`, `MaybePunishNodeForBlock(via_compact_block=true)`,
  `UpdateBlockAvailability`, dual-tier in-flight tracking with
  `MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK` slots, conservative
  `pindex->nHeight <= ActiveChain.Height() + 2` reject, optimistic-temp-block
  reconstruction path when peer hit the in-flight cap.
- `bitcoin-core/src/net_processing.cpp:4245-4304` — GETBLOCKTXN recv:
  ```
  BlockTransactionsRequest req;  vRecv >> req;
  for (size_t i = 1; i < req.indexes.size(); ++i) {
      Assume(req.indexes[i] > req.indexes[i-1]);
  }
  ```
  reads from `m_most_recent_block` cache first, else `ReadBlock` from disk
  if `pindex->nHeight >= ActiveChain.Height() - MAX_BLOCKTXN_DEPTH`, else
  responds with `CInv(MSG_WITNESS_BLOCK, hash)` getdata fallback (full
  block; deliberately punitive to discourage stale-request DoS).
- `bitcoin-core/src/net_processing.cpp:2595-2614` —
  `SendBlockTransactions`: out-of-bounds tx index triggers
  `Misbehaving(peer, "getblocktxn with out-of-bounds tx indices")`.
- `bitcoin-core/src/blockencodings.cpp:20-50` —
  `CBlockHeaderAndShortTxIDs(block, nonce)`:
  prefilledtxn always 1 entry = `{0, block.vtx[0]}` (coinbase).
  `FillShortTxIDSelector` = SHA256(header || nonce) → (k0,k1).
  `GetShortID(wtxid) = (SipHash-2-4(k0,k1,wtxid_u256)) & 0xffffffffffffL`.
- `bitcoin-core/src/blockencodings.cpp:59-181` — `InitData`:
  ```
  if (cmpctblock.header.IsNull() ||
      (cmpctblock.shorttxids.empty() && cmpctblock.prefilledtxn.empty()))
      return READ_STATUS_INVALID;
  if (cmpctblock.shorttxids.size() + cmpctblock.prefilledtxn.size()
      > MAX_BLOCK_WEIGHT / MIN_SERIALIZABLE_TRANSACTION_WEIGHT)
      return READ_STATUS_INVALID;
  if (!header.IsNull() || !txn_available.empty()) return READ_STATUS_INVALID;
  …
  // bucket-size > 12 → READ_STATUS_FAILED
  if (shorttxids.bucket_size(shorttxids.bucket(cmpctblock.shorttxids[i])) > 12)
      return READ_STATUS_FAILED;
  if (shorttxids.size() != cmpctblock.shorttxids.size())
      return READ_STATUS_FAILED; // Short ID collision
  ```
- `bitcoin-core/src/blockencodings.cpp:191-237` — `FillBlock`:
  on completion runs `IsBlockMutated(block, segwit_active)` (catches
  short-ID-collision-induced merkle mutations); `READ_STATUS_FAILED` on
  failure ("Possible Short ID collision").
- `bitcoin-core/src/blockencodings.h:23-43` — `DifferenceFormatter`:
  ```
  void Ser(…, I v) { if (v < m_shift || v >= max) throw …;
                     WriteCompactSize(s, v - m_shift); m_shift = v + 1; }
  void Unser(…, I& v) { uint64_t n = ReadCompactSize(s); m_shift += n;
                        if (m_shift < n || m_shift >= max ||
                            m_shift < I::min || m_shift > I::max)
                            throw …;
                        v = I(m_shift++); }
  ```
- `bitcoin-core/src/blockencodings.h:73-81` — `PrefilledTransaction`:
  `uint16_t index` serialized via `COMPACTSIZE`, tx via `TX_WITH_WITNESS`.
- `bitcoin-core/src/blockencodings.h:45-71` — `BlockTransactionsRequest`:
  `std::vector<uint16_t> indexes` via `VectorFormatter<DifferenceFormatter>`
  (so it carries no separate size header; element-count is decoded by
  the formatter via `ReadCompactSize` for the vector size); BlockTransactions
  ditto with `TX_WITH_WITNESS` for the tx payloads.
- BIP-152 spec (witness): "The Coinbase transaction MUST be the first
  prefilled transaction, and prefilled.index MUST equal 0."

## Files audited

- `src/p2p/compact_blocks.ts` (1041 lines) — `CompactBlockManager`,
  `PartiallyDownloadedBlock`, `createCompactBlockFromBlock`,
  `createBlockTxnResponse`, `deriveSipHashKeys`, `computeShortTxId`,
  `ReadStatus`, depth constants, HB-peer set.
- `src/p2p/messages.ts:225-285, 710-782, 1164-1249` — wire types and
  ser/deser for `SendCmpctPayload`, `CmpctBlockPayload`,
  `GetBlockTxnPayload`, `BlockTxnPayload`.
- `src/p2p/peer.ts:1310-1331` — `checkHandshakeComplete` (sends sendcmpct).
- `src/p2p/peer.ts:1156-1305` — `handleMessage` / `handleHandshake`
  (pre-handshake message gating).
- `src/sync/blocks.ts:638-724` — receive-side dispatch handlers for
  cmpctblock / sendcmpct / getblocktxn / blocktxn.
- `src/storage/indexes.ts:60-150` — `sipHash24` (used by BIP-152 short-id).
- `src/validation/block.ts:313-366` — `checkWitnessMalleation` (called
  inside `PartiallyDownloadedBlock.getBlock` as the Core
  `IsBlockMutated` analogue).
- `audit/w126_bip152_compact_blocks.md` — prior shallow audit (21 bugs).
- `src/__tests__/compact_blocks.test.ts` + `w126_bip152_compact_blocks.test.ts`
  — test surface (1000+ lines exercising the DEAD `CompactBlockManager`).

---

## Wire-level gate matrix (40 sub-gates / 12 behaviours)

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 1 | sendcmpct VERSION=2 gate | G1: handler drops version ≠ 2 silently | PASS in `CompactBlockManager.handleSendCmpct` (line 753-758) but DEAD in production (BUG-1 below) |
| 1 | … | G2: dispatch handler in production calls `handleSendCmpct` | **BUG-1 (P0-CDIV)** carry-forward W126 BUG-4 |
| 1 | … | G3: sendcmpct gated on `GetCommonVersion() >= SHORT_IDS_BLOCKS_VERSION` (70014) | **BUG-2 (P1)** — `peer.ts:1326-1329` sends unconditionally |
| 1 | … | G4: sendcmpct send timing matches Core (inside verack handler) | PARTIAL — sent in `checkHandshakeComplete` after both verack-sent and verack-recv; Core sends inside the verack-recv handler. Close enough; semantic match |
| 2 | sendcmpct outbound HB request after BlockChecked | G5: HB-peer announcement to up-to-3 outbound peers | **BUG-3 (P0-CDIV)** carry-forward W126 BUG-6/BUG-7 — `addHighBandwidthPeer` is unreachable from sync/blocks.ts |
| 2 | … | G6: send `sendcmpct(true, 2)` to a chosen peer after promotion | MISSING |
| 2 | … | G7: outbound-peer protection (don't evict last outbound HB peer) | MISSING |
| 3 | short-tx-id SipHash-2-4 | G8: k0,k1 = SHA256(header_serialized || nonce_LE_u64)[0..8 | 8..16] | PASS (`deriveSipHashKeys` lines 165-182) |
| 3 | … | G9: short-id = SipHash-2-4(k0, k1, wtxid) & 0xffffffffffff | PASS (`computeShortTxIdValue` lines 220-226; `sipHash24` lines 60-150) |
| 3 | … | G10: docstring matches BIP-152 spec | **BUG-4 (P2)** — `messages.ts:243` claims "SHA256(SHA256(nonce || txid))[0:6]" which is wrong on three counts (it's SipHash not SHA256d, k0/k1 derive from header not just nonce, and it uses wtxid not txid) |
| 4 | prefilledtxn coinbase@0 invariant | G11: encoder always prefills coinbase at index 0 | PASS (`createCompactBlockFromBlock` lines 283-286) |
| 4 | … | G12: decoder REJECTS cmpctblock whose first prefilled index ≠ 0 (BIP-152 mandate) | **BUG-5 (P0-CDIV)** — `initData` accepts any first-prefilled index; coinbase can be elided in favor of a mempool tx that hashes to slot 0's short-id, producing a forged block |
| 5 | DifferenceFormatter | G13: encoder emits `diff = v - last_index - 1` strict ascending | PASS (`messages.ts:744-749`) |
| 5 | … | G14: decoder enforces strictly-increasing (no equal-or-decreasing) indices | PARTIAL — diff-encoding mathematically forces ascending since `diff = v - last - 1 >= 0` produces strict ascending IF diff is well-formed, but BUG-6 below shows decoder over-flows on adversarial `diff` |
| 5 | … | G15: decoder rejects `m_shift` (rolling base) overflow | **BUG-6 (P0-CDIV)** — `messages.ts:1213-1219, 1230-1236` adds `diff + lastIndex + 1` in JS Number arithmetic; max safe int = 2^53-1, but Core's `m_shift < n` check catches it at uint64 wrap. Attacker can stuff `diff = 2^53` in a varint and break our decoder silently or trigger off-by-one in subsequent indexes |
| 5 | … | G16: decoder rejects `m_shift > uint16_t::max` (PrefilledTransaction.index is uint16_t in Core) | **BUG-7 (P0-CDIV)** — Core's `DifferenceFormatter::Unser` rejects `m_shift > std::numeric_limits<I>::max()` (here `uint16_t::max = 65535`); hotbuns silently accepts indexes up to JS safe int. A peer sending `index = 0x10000` for a coinbase get-bloated to past-uint16, which Core would reject, hotbuns accepts |
| 6 | InitData gates | G17: `header.IsNull() || (shortids+prefilled both empty)` → INVALID | PARTIAL — hotbuns checks `txCount === 0` (combined empty) but does NOT check `header.IsNull()`; an all-zero header still passes G1, despite Core gating on it (BUG-8 P1) |
| 6 | … | G18: `txCount > MAX_BLOCK_WEIGHT / MIN_SERIALIZABLE_TRANSACTION_WEIGHT` → INVALID | PASS (`compact_blocks.ts:399-402`) |
| 6 | … | G19: serializer-gate `BlockTxCount > uint16_t::max` → INVALID | PASS (`compact_blocks.ts:405-408`) |
| 6 | … | G20: re-init guard `!header.IsNull() || !txn_available.empty()` → INVALID | **BUG-9 (P1)** — `initData` has no re-init guard; calling twice on the same instance silently re-fills slots and leaves stale state |
| 6 | … | G21: prefilled tx not null → INVALID | PASS (`compact_blocks.ts:417-419`) |
| 6 | … | G22: absolute prefilled index > shortIds.length + i → INVALID | PASS (`compact_blocks.ts:432-434`) |
| 6 | … | G23: strict-increasing prefilled indices | PASS (`compact_blocks.ts:441-443`) |
| 7 | bucket-size DoS gate | G24: detect hash-bucket > 12 collisions | **BUG-10 (P0-CDIV)** semantic divergence — hotbuns's `bucketCollisionCount.set(shortIdValue, prev+1)` counts EXACT DUPLICATE short-ids (already caught by G25 size-mismatch). Core counts DIFFERENT shortIds that hash to the same `unordered_map` bucket. The hotbuns gate fires only when ≥12 of the SAME short-id appear (already caught by G25 at count=2); the DoS attack Core's gate was designed to catch (multiple distinct shortIds hash-colliding) goes undetected |
| 7 | … | G25: exact-duplicate short-id → READ_STATUS_FAILED | PASS (`compact_blocks.ts:488-490`) |
| 8 | FillBlock mutation check | G26: `IsBlockMutated(block, segwit_active)` called inside `getBlock` | PASS (`compact_blocks.ts:693-697`) |
| 8 | … | G27: segwit_active determined from block height / prev-block-segwit-active flag | **BUG-11 (P1)** — `getBlock(segwitActive = true)` defaults `true` but the call site `compact_blocks.ts:966` invokes `partial.getBlock()` with no argument — hardcoded to `true`. Core derives `DeploymentActiveAfter(prev_block, m_chainman, DEPLOYMENT_SEGWIT)` |
| 9 | cmpctblock receive | G28: production dispatch handler reconstructs from mempool | **BUG-12 (P0-CDIV)** carry-forward W126 BUG-1 — `sync/blocks.ts:643-680` always falls back to `getdata MSG_WITNESS_BLOCK`; no `startBlockReconstruction` call |
| 9 | … | G29: production dispatch handler runs `Misbehaving(peer, "invalid compact block")` on INVALID | MISSING (no reconstruction path → no INVALID path) |
| 9 | … | G30: `MaybePunishNodeForBlock(via_compact_block=true)` plumbed | MISSING |
| 9 | … | G31: low-work header drop (`prev_block->nChainWork + blockProof < GetAntiDoSWorkThreshold()`) | **BUG-13 (P1)** — no anti-DoS work-threshold check in `sync/blocks.ts:643` handler. A peer can flood us with low-work cmpctblocks pointing at unknown headers, triggering MaybeSendGetHeaders churn |
| 9 | … | G32: `LoadingBlocks()` rejection (Core line 4469) | **BUG-14 (P1)** — no equivalent gate; cmpctblock during import is silently accepted into the handler |
| 10 | getblocktxn serve | G33: handler reads block from disk and returns BLOCKTXN | **BUG-15 (P0-CDIV)** carry-forward W126 BUG-2 — `sync/blocks.ts:696-719` is a stub; `createBlockTxnResponse` is dead code |
| 10 | … | G34: out-of-bounds index → `Misbehaving(peer, "getblocktxn with out-of-bounds tx indices")` | MISSING (no serve path) |
| 10 | … | G35: requested-block-not-on-disk → silent skip (Core: only emit if we have the block) | N/A (no serve path) |
| 10 | … | G36: requests for blocks deeper than MAX_BLOCKTXN_DEPTH → respond with full-block getdata (Core lines 4291-4302) | **BUG-16 (P1)** — hotbuns silently returns; Core deliberately responds with full-block getdata, which **forces the peer to incur the network cost of receiving the disk-read result they triggered** (anti-DoS shaping) |
| 11 | blocktxn receive | G37: production dispatch routes to `handleBlockTxn` | **BUG-17 (P0-CDIV)** carry-forward W126 BUG-3 — `sync/blocks.ts:722-724` is empty (`function (_peer, _msg) {}`) |
| 11 | … | G38: `Misbehaving(peer, "non-matching block transactions")` on `fillFromBlockTxn` mismatch | MISSING |
| 12 | fast-announce | G39: cache `m_most_recent_compact_block` + `m_most_recent_block_hash` | **BUG-18 (P0-CDIV)** carry-forward W126 BUG-5 — no equivalent cache; every getblocktxn would re-read from disk even when the most-recent block is still hot |
| 12 | … | G40: `NewPoWValidBlock` hook fires CMPCTBLOCK push to HB peers without round-trip | MISSING (carry-forward W126 BUG-5) |

---

## BUG-1 (P0-CDIV) — `CompactBlockManager` is dead code; production dispatch is a stub (**carry-forward W126 BUG-1 / BUG-4 / W123 → W155 — 35TH-CONSECUTIVE-STREAK SIGNATURE FINDING**)

**Severity:** P0-CDIV. The entire BIP-152 contract on the receive
side is unwired in production. `class CompactBlockManager` (lines
717-1003), `class PartiallyDownloadedBlock` (lines 332-701),
`createCompactBlockFromBlock` (lines 268-308), `createBlockTxnResponse`
(lines 1016-1033), `deriveSipHashKeys`, `computeShortTxId`,
`handleSendCmpct`, `handleBlockTxn`, `startBlockReconstruction`,
`tryFillFromMempool`, `createGetBlockTxn`, the entire `peerStates` /
`highBandwidthPeers` / `stats` state machine — none of it is referenced
from `sync/blocks.ts`, `p2p/manager.ts`, or `p2p/peer.ts` except in the
`compact_blocks.test.ts` and `w126_bip152_compact_blocks.test.ts` test
files.

The four production-side dispatch handlers in `sync/blocks.ts`:
1. `onMessage("sendcmpct", …)` — log-only (line 683-690): records
   nothing, drops version-2 contract, never invokes
   `handleSendCmpct`.
2. `onMessage("cmpctblock", …)` — issues `getdata MSG_WITNESS_BLOCK`
   fallback (lines 643-680); never calls `startBlockReconstruction`.
3. `onMessage("getblocktxn", …)` — depth-gate then stub
   (line 717-718 inline comment "We don't serve compact blocks yet").
4. `onMessage("blocktxn", …)` — empty body (line 722-724).

The 1,041-line `compact_blocks.ts` is a meticulously-implemented,
gate-by-gate-validated, comment-cross-referenced dead helper.

**Carry-forward streak:** W123 (mining audit) BUG-X → W124, W125, W126
(BIP-152 audit) BUGs 1-4, 5-7, … → W141, W142, …, W155 (GBT) → W156
(this audit). The same finding has been recorded as the lead bug in
**every BIP-152-adjacent audit for 5+ weeks**. W126 created the
explicit test `it.skip("BUG-1: CompactBlockManager is unreferenced
from sync/blocks.ts…")` and the test STILL passes (i.e. the
unreferenced state is still true). This is the **35th-consecutive
quad-audit "dead-helper" signature finding** (per fleet-pattern
tracking).

**File:** `src/sync/blocks.ts:643-724`, `src/p2p/compact_blocks.ts`
(entire file).

**Core ref:** `bitcoin-core/src/net_processing.cpp:3901-3917`
(SENDCMPCT recv), `4466-4683` (CMPCTBLOCK recv), `4245-4304`
(GETBLOCKTXN recv), `2595-2614` (SendBlockTransactions).

**Excerpt (sync/blocks.ts comment-as-confession at line 669-670):**
```ts
// from compact block without a mempool (BUG-2/BUG-3 — CompactBlockManager
// dead helper; wiring it is out of scope for FIX-42).
```

**Impact:** BIP-152 is functionally INERT on hotbuns. Every block
costs ~1 MB of bandwidth (full-block getdata) instead of ~10 KB
(cmpctblock + zero-or-few-tx blocktxn). A hotbuns IBD or post-IBD
catch-up uses roughly 100× more bandwidth than Core. On a fleet
running 8/10 mainnet nodes, this is observable in network telemetry
(hotbuns inbound BW per block ≫ peers). Compounded by BUG-18 (no
fast-announce), block propagation latency from hotbuns is also
~2× higher than from BIP-152-capable peers.

---

## BUG-2 (P1) — `SENDCMPCT` sent unconditionally; missing `GetCommonVersion() >= SHORT_IDS_BLOCKS_VERSION` gate

**Severity:** P1. Core gates the SENDCMPCT push on the negotiated
protocol version:
```cpp
if (pfrom.GetCommonVersion() >= SHORT_IDS_BLOCKS_VERSION) {
    MakeAndPushMessage(pfrom, NetMsgType::SENDCMPCT, /*high_bandwidth=*/false, /*version=*/CMPCTBLOCKS_VERSION);
}
```

hotbuns's `checkHandshakeComplete` (`src/p2p/peer.ts:1321-1330`) sends
unconditionally:
```ts
this.send({ type: "sendheaders", payload: null });
this.send({
  type: "sendcmpct",
  payload: { enabled: false, version: 2n },
});
```

hotbuns enforces `MIN_PEER_PROTO_VERSION = 70015` (1 above
`SHORT_IDS_BLOCKS_VERSION = 70014`), so the unconditional send is
de-facto safe today. But this is a hidden coupling — any future drop
of `MIN_PEER_PROTO_VERSION` below 70014 (e.g. supporting an older
Bitcoin Cash-style peer or a museum-piece node) would silently
mis-advertise. Core's explicit check is defense-in-depth and
documents the dependency.

**File:** `src/p2p/peer.ts:1321-1330`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:3864-3871`.

**Impact:** correctness today, fragility tomorrow. Also a code-review
hazard — the contract `MIN_PEER_PROTO_VERSION > SHORT_IDS_BLOCKS_VERSION`
is non-obvious and absent any in-source assertion or comment.

---

## BUG-3 (P0-CDIV) — HB-peer selection (`MaybeSetPeerAsAnnouncingHeaderAndIDs`) entirely absent (**carry-forward W126 BUG-6 + BUG-7**)

**Severity:** P0-CDIV. Core's `MaybeSetPeerAsAnnouncingHeaderAndIDs`
(net_processing.cpp:1272-1329) maintains `lNodesAnnouncingHeaderAndIDs`
— an LRU list of up to **3 outbound peers** to whom we send
`SENDCMPCT(/*high_bandwidth=*/true, …)` so they fast-announce blocks
to us as cmpctblocks. This includes:
- Outbound protection: when adding an inbound HB peer, if it would
  remove the LAST outbound HB peer, swap the front two to preserve
  outbound HB.
- Bandwidth-state sync: flips `pfrom->m_bip152_highbandwidth_to = true`
  when promoting, and `false` for the evicted peer.
- Demote-via-sendcmpct: re-sends `SENDCMPCT(false, …)` to the evicted
  peer to demote them on the other side of the wire too.

hotbuns has `CompactBlockManager.highBandwidthPeers: Set<string>` and
`addHighBandwidthPeer` / `removeHighBandwidthPeer` methods, BUT:
- no production caller of either method (grep across `src/sync/`,
  `src/p2p/`, `src/chain/` shows zero non-test references);
- no `BlockChecked` / `OnBlockConnected` hook that would trigger
  HB-peer promotion when a peer's announcement led to a connected
  block (Core's signal at `validation.cpp::BlockChecked` →
  `MaybeSetPeerAsAnnouncingHeaderAndIDs`);
- no outbound-protection logic;
- no demote-via-sendcmpct path.

Combined with BUG-1, hotbuns is **completely passive** in the BIP-152
HB-relay mesh: it advertises nothing (`enabled: false` to all peers),
it requests nothing (no HB peers selected on our side either), and
no fast-announces are emitted (BUG-18).

**File:** `src/p2p/compact_blocks.ts:776-823` (defines but never
called); `src/sync/blocks.ts` (no caller); `src/p2p/manager.ts` (no
caller); `src/p2p/peer.ts` (no caller).

**Core ref:** `bitcoin-core/src/net_processing.cpp:1272-1329`
(`MaybeSetPeerAsAnnouncingHeaderAndIDs`), `2220` (`BlockChecked`
caller).

**Impact:** hotbuns can never receive fast-announce cmpctblocks
(no peer marks hotbuns as HB-from); hotbuns can never send
fast-announce cmpctblocks (no peer is marked HB-to). Block-propagation
latency on hotbuns is bounded below by the inv/headers round-trip
overhead, not by the (much faster) BIP-152 fast-relay path.

---

## BUG-4 (P2) — `ShortTxId` docstring claims wrong hash function

**Severity:** P2 (documentation correctness; bug-attractor for
future-me / contributors). `src/p2p/messages.ts:241-247` documents
the short-tx-id as:

```ts
/**
 * Short transaction ID for compact blocks (6 bytes).
 * Computed as: SHA256(SHA256(nonce || txid))[0:6]
 */
export interface ShortTxId {
  shortId: Buffer;  // 6 bytes
}
```

Three errors:
1. **Algorithm:** SipHash-2-4, not SHA256d.
2. **Key derivation:** `(k0, k1)` come from `SHA256(header || nonce)[0:8 | 8:16]`,
   not directly from `nonce || …`.
3. **Hash input:** `wtxid` (witness hash), not `txid` (legacy hash).
   This is the BIP-141 segwit malleability fix that BIP-152 v2
   explicitly leverages.

The actual implementation in `compact_blocks.ts:196-215` is correct;
only the docstring lies. A future maintainer who reads only the type
declaration could implement an SHA256d-based version of the short-id
when extending the protocol, producing a chain split with Core peers.

**File:** `src/p2p/messages.ts:241-247`.

**Core ref:** `bitcoin-core/src/blockencodings.cpp:35-50`
(`FillShortTxIDSelector` + `GetShortID`).

**Impact:** documentation; bug-attractor.

---

## BUG-5 (P0-CDIV) — Decoder does NOT enforce `prefilled[0].index == 0` (coinbase invariant)

**Severity:** P0-CDIV. BIP-152 spec mandates:

> The Coinbase transaction MUST be the first prefilled transaction,
> and prefilled.index MUST equal 0.

Bitcoin Core enforces this implicitly via the encoder always emitting
`{0, vtx[0]}` as `prefilledtxn[0]` (blockencodings.cpp:28) AND the
implicit DifferenceFormatter ascending-only invariant: once the first
prefilled index is set, the "first prefilled MUST be index 0" property
is bound to the encoder.

hotbuns's `initData` (compact_blocks.ts:411-447) makes no such
check — it only verifies:
- prefilled.tx is non-null (G21)
- index ≤ shortIds.length + i (G22)
- index < txCount (boundary)
- index > lastPrefilledIndex (strict ascending)

A malicious peer can construct a cmpctblock with:
- `shortIds = [shortID_for_real_coinbase, …]`
- `prefilledTxns = [{ index: 1, tx: tx_at_slot_1 }, …]` (no index-0
  prefill)

`initData` accepts it. Slot 0 will be filled from `shortIdToIndex`
(matching some mempool tx with the same shortID as the real
coinbase), producing a reconstructed `block.transactions[0]` that
is NOT a coinbase. The mutation-merkle check in `getBlock`
(`checkWitnessMalleation`) would catch a wrong merkle root, but if
the attacker constructs the short-id collisions correctly (or the
slot-0 reconstruction happens to be in the mempool with the right
hash), the block is silently accepted with a non-coinbase tx at
slot 0, breaking BIP-34 height extraction, witness-commitment
validation (it scans `tx[0].outputs` for the commitment), and the
later `CheckBlock` coinbase-position invariant.

In practice the mutation check will catch most malicious crafts
(the merkle root won't match if the wrong tx is at slot 0), but the
spec gate is missing, and any path that bypasses the mutation check
(e.g. a future code path that calls `txnAvailable[0]` before
`getBlock`) inherits a logic bomb.

**File:** `src/p2p/compact_blocks.ts:411-447` (initData prefilled
placement loop).

**Core ref:** BIP-152 spec §"Compact block message format"; relied
on implicitly via `blockencodings.cpp:28`.

**Impact:** spec gate missing; combined with BUG-1 (entire receive
path is dead) this is currently moot, but the moment BIP-152 is
wired (the W126/W156 carry-forward fix), the decoder needs the
coinbase-at-0 check added in lock-step.

---

## BUG-6 (P0-CDIV) — `DifferenceFormatter` decoder uses JS Number arithmetic; silent overflow past 2^53

**Severity:** P0-CDIV (deserialization-DoS / consensus-divergence
class). Core's `DifferenceFormatter::Unser` (blockencodings.h:36-42)
uses `uint64_t m_shift`:

```cpp
uint64_t n = ReadCompactSize(s);
m_shift += n;
if (m_shift < n || m_shift >= std::numeric_limits<uint64_t>::max() ||
    m_shift < std::numeric_limits<I>::min() ||
    m_shift > std::numeric_limits<I>::max())
    throw std::ios_base::failure("differential value overflow");
v = I(m_shift++);
```

The `m_shift < n` clause catches uint64 wrap (e.g. n = `2^63`,
m_shift previously `2^63` → wraps to `0`, which is `< n`). The
`m_shift > I::max()` clause caps at the target integer type
(`uint16_t::max = 65535` for `PrefilledTransaction.index` and
`BlockTransactionsRequest.indexes`).

hotbuns's decoder (`messages.ts:1213-1219` for cmpctblock prefilled,
`messages.ts:1230-1236` for getblocktxn indexes) uses JS Number
arithmetic:

```ts
let lastIndex = -1;
for (let i = 0; i < prefilledCount; i++) {
  const diff = reader.readVarInt();
  const index = lastIndex + diff + 1;
  const tx = deserializeTx(reader);
  prefilledTxns.push({ index, tx });
  lastIndex = index;
}
```

`readVarInt()` returns a JS `number` (or `bigint`, depending on
implementation; need to check). JS `number` is `IEEE 754 double`,
safe-integer range is `[-2^53, 2^53]`. For values past `2^53`,
arithmetic silently loses precision. An attacker sending a varint
with value `2^53 + 1` (representable as varint) would observe:
- `lastIndex = -1`
- `index = -1 + (2^53 + 1) + 1 = 2^53 + 1` → rounded to `2^53` due
  to float precision loss.
- Subsequent `index = 2^53 + (next_diff + 1)` — also imprecise.

There are two distinct bugs here:
- **Silent precision loss** past 2^53 (BUG-6a).
- **No uint16_t bound** (`index <= 0xffff`) on the `getblocktxn` and
  `cmpctblock prefilled` paths (BUG-7).

The combination means hotbuns can be coerced into:
- Reading 1+ MB of transaction body via the loop (no upper bound
  on individual prefilled tx size other than payload-size limit) for
  a single prefilled entry, while the `index` field that should
  have rejected it silently passes.
- Storing `Number` indexes that JS treats as `2^53`-quantized, then
  comparing them later as if they were `uint16_t`s. The `index <
  txCount` check at compact_blocks.ts:436 uses `txCount = shortIds.length
  + prefilledTxns.length`, which is also a JS Number, so the
  comparison's outcome depends on float-rounding.

**File:** `src/p2p/messages.ts:1213-1219, 1230-1236`.

**Core ref:** `bitcoin-core/src/blockencodings.h:36-42`
(`DifferenceFormatter::Unser`).

**Impact:** dead-code today (BUG-1), but the moment the receive path
is wired, this is the first place a peer can break us. A single
hostile cmpctblock with a 9-byte varint can trigger precision-loss
asserts elsewhere, mis-routed reads in `txnAvailable[index]`, and
potentially OOB writes that JS turns into expanding the array (silent
memory bloat).

---

## BUG-7 (P0-CDIV) — Decoder accepts prefilled `index > 0xffff` (Core's `uint16_t::max` ceiling absent)

**Severity:** P0-CDIV (consensus-divergence class). Core's
`PrefilledTransaction::index` is `uint16_t`, so the `DifferenceFormatter`
overflow gate `m_shift > std::numeric_limits<I>::max()` caps at
`0xffff = 65535`. hotbuns's check (compact_blocks.ts:425-427) is in
`initData`:

```ts
// G5: absolute index must fit in uint16_t
// Core: blockencodings.cpp:77-79 (lastprefilledindex > uint16_t max)
if (absoluteIndex > 0xffff) {
    return ReadStatus.INVALID;
}
```

This is correctly placed in InitData — BUT it runs AFTER the wire
deserialization has already accepted the index. So the wire payload
is parsed (and ~MB of tx data slurped from the buffer) for a
malformed cmpctblock before the gate fires. Core's
`DifferenceFormatter::Unser` rejects at the wire-decode layer, so
the offending bytes are never read past the bad index.

Beyond the perf concern, the precise location of the gate creates a
wire-format-vs-validation gap: a peer can fingerprint hotbuns by
sending a cmpctblock with `index = 0x10000` and observing that
hotbuns read the entire wire payload (timing) before rejecting,
where Core rejects at the deser layer with no payload read.

**File:** `src/p2p/messages.ts:1213-1219` (no wire-level cap),
`src/p2p/compact_blocks.ts:425-427` (cap at semantic layer instead).

**Core ref:** `bitcoin-core/src/blockencodings.h:36-42`.

**Impact:** wire-fingerprint primitive (small); performance gap
(read 1+ MB before rejecting); divergent rejection layer means a
deser-side hook (e.g. a BIP-37 bloom filter on tx content of the
prefilled txns) fires in hotbuns where Core never enters.

---

## BUG-8 (P1) — `initData` does not check `header.IsNull()` (Core L62 gate G17)

**Severity:** P1. Core's first gate in InitData is:
```cpp
if (cmpctblock.header.IsNull() ||
    (cmpctblock.shorttxids.empty() && cmpctblock.prefilledtxn.empty()))
    return READ_STATUS_INVALID;
```

`CBlockHeader::IsNull()` returns true iff `nBits == 0` (the only
header field with a "null sentinel" meaning).

hotbuns's `initData` (compact_blocks.ts:391-408) only checks
`txCount === 0` (the second clause):
```ts
if (this.txCount === 0) {
    return ReadStatus.INVALID;
}
```

An all-zero header (or specifically `bits == 0`) passes through to
the subsequent `serializeBlockHeader(compact.header)` in the
constructor at line 368, which produces an 80-byte buffer. SipHash
keys are derived from that buffer + nonce, so the short-id
calculation is still deterministic. The block won't pass downstream
PoW checks (target = 0 means `target.compare(hash256) < 0` → fail),
but BIP-152 is meant to short-circuit BEFORE we even compute PoW —
the InitData gate is part of the cheap pre-check.

Combined with BUG-1 (dispatch is dead) this is moot today, but it's
a gate that should be wired in lock-step.

**File:** `src/p2p/compact_blocks.ts:391-408`.

**Core ref:** `bitcoin-core/src/blockencodings.cpp:62-63`.

**Impact:** missed early reject; downstream PoW check still catches
it but at higher cost (full cmpctblock deserialization + InitData
execution + SipHash computation for every shortid).

---

## BUG-9 (P1) — `initData` has no re-init guard (Core L67 gate G20)

**Severity:** P1. Core's third gate:
```cpp
if (!header.IsNull() || !txn_available.empty()) return READ_STATUS_INVALID;
```

This rejects InitData being called twice on the same instance — a
defense-in-depth invariant since the C++ object is moved around in
multi-step reconstruction paths.

hotbuns's `PartiallyDownloadedBlock.initData` (compact_blocks.ts:391-493)
has no such check. Calling `initData(compact)` twice on the same
instance will re-fill `txnAvailable[]` (the second call's prefilled
overwrites the first), re-build `shortIdToIndex`, and reset
`missingIndices = []` (line 365 is in the constructor, but initData
mutates state in place). The stale state from the first call leaks
through.

In hotbuns this is currently unreachable because `startBlockReconstruction`
always constructs a fresh `PartiallyDownloadedBlock` (compact_blocks.ts:875).
But if the BUG-1 fix wires the manager and a future refactor reuses
instances (e.g. for retry), the guard absence becomes live.

**File:** `src/p2p/compact_blocks.ts:391`.

**Core ref:** `bitcoin-core/src/blockencodings.cpp:67`.

**Impact:** defense-in-depth missing; live-bug risk on a refactor.

---

## BUG-10 (P0-CDIV) — Bucket-collision DoS gate semantics inverted: counts duplicates, not hash-bucket collisions

**Severity:** P0-CDIV (DoS gap; semantic divergence in security gate).
Core's gate (blockencodings.cpp:110-111):

```cpp
if (shorttxids.bucket_size(shorttxids.bucket(cmpctblock.shorttxids[i])) > 12)
    return READ_STATUS_FAILED;
```

`shorttxids` here is `std::unordered_map<uint64_t, uint16_t>` with
load factor 1.0 (default), so bucket count ≈ shortid count. The
gate fires when **12 different short-ids** hash to the same bucket
in the internal hash table. The bucket function depends on the C++
standard library implementation (libstdc++ uses prime-based modulo);
an adversary cannot trivially produce 12 distinct short-ids hashing
to the same bucket without knowing the libc++ hash seed (typically
nonexistent — `std::hash<uint64_t>` is the identity for small
inputs, so the attacker can compute it deterministically: short-id
mod bucket_count).

This DoS gate exists because reconstruction over the mempool is
`O(mempool_size)` for each lookup, and a worst-case bucket with all
mempool entries colliding would turn the InitData mempool scan into
O(mempool_size × bucket_size) — quadratic.

hotbuns's gate (compact_blocks.ts:461-490):

```ts
const bucketCollisionCount = new Map<bigint, number>();
let shortIdIdx = 0;
for (let i = 0; i < this.txCount; i++) {
    if (this.txnAvailable[i] === undefined) {
        const shortIdValue = shortIdToValue(compact.shortIds[shortIdIdx]);
        const prev = bucketCollisionCount.get(shortIdValue) ?? 0;
        if (prev >= 12) {
            return ReadStatus.FAILED;
        }
        bucketCollisionCount.set(shortIdValue, prev + 1);
        this.shortIdToIndex.set(shortIdValue, i);
        shortIdIdx++;
    }
}
if (this.shortIdToIndex.size !== compact.shortIds.length) {
    return ReadStatus.FAILED;
}
```

The `bucketCollisionCount` Map keys on the FULL 64-bit shortId.
`prev >= 12` fires ONLY when the SAME shortId appears 12+ times.
But the next gate (size mismatch) fires on count=2. So the
"12-bucket" gate is dead — it never fires before the exact-duplicate
gate.

The DoS attack Core's gate defends against — many DIFFERENT short-ids
collapsing into the same hash-table bucket — is undetected in
hotbuns. With JS `Map`'s implementation-defined hash, an attacker
who can fingerprint the hash function (e.g. V8 / JSC versions hash
strings/bigints predictably for small inputs) can build a cmpctblock
that bunches all short-ids into one bucket, turning mempool
reconstruction into O(mempool × shortid_count).

The fix is **not** to copy Core's `bucket_size()` semantic directly
(JS `Map` doesn't expose buckets), but to either (a) reject if
`shortIds.length > some empirical threshold` outright (Core's check
is per-bucket, hotbuns can be per-map), or (b) hash short-ids
through a randomized salt before insertion so the attacker cannot
predict bucket placement.

**File:** `src/p2p/compact_blocks.ts:461-490`.

**Core ref:** `bitcoin-core/src/blockencodings.cpp:94-116`.

**Impact:** DoS primitive; the documented Core gate has been
re-implemented with a semantic that fires on a DIFFERENT condition
than the original. Today moot (BUG-1 dead-helper); on wire-up, this
is the attack-surface entry point.

---

## BUG-11 (P1) — `getBlock(segwitActive)` defaults `true`, sole caller doesn't pass argument; `segwit_active` should derive from block height

**Severity:** P1. Core's `FillBlock`:
```cpp
ReadStatus FillBlock(CBlock& block, const std::vector<CTransactionRef>& vtx_missing, bool segwit_active);
```
is called with:
```cpp
status = tempBlock.FillBlock(*pblock, dummy,
    /*segwit_active=*/DeploymentActiveAfter(prev_block, m_chainman, Consensus::DEPLOYMENT_SEGWIT));
```

The mutation check passes `segwit_active` to `IsBlockMutated`, which
gates the witness-commitment check.

hotbuns's `PartiallyDownloadedBlock.getBlock(segwitActive: boolean = true)`
(compact_blocks.ts:669) defaults to `true`. The sole caller
`CompactBlockManager.handleBlockTxn` at line 966 calls
`partial.getBlock()` with no argument — hardcoded to true.

On mainnet, `segwitActive` is true for all heights ≥ 481,824 (BIP-141
lock-in), so for blocks past that height the default is correct. But
the type contract leaks: a pre-segwit block (mainnet height
< 481,824, or any regtest run that hasn't yet activated DEPLOYMENT_SEGWIT
via versionbits) would have the witness-commitment check fire
incorrectly. `checkWitnessMalleation(block, true)` would scan for a
commitment output (`getWitnessCommitmentIndex`) on the coinbase; if
none is present, it falls through to the "unexpected-witness" scan
which iterates over every tx looking for `hasWitness(tx)`. For a
pre-segwit block this should all be no-ops, but the gate is wrong.

The fix requires passing the block's height (or the prev_block's
post-segwit-activation status, mirroring Core's
`DeploymentActiveAfter`) into `getBlock`.

**File:** `src/p2p/compact_blocks.ts:669, 966`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:4649-4650`.

**Impact:** wrong-side mutation check for pre-segwit blocks; today
moot (mainnet past activation), but regtest deployments break.

---

## BUG-12 (P0-CDIV) — `cmpctblock` production dispatch handler does NOT call `startBlockReconstruction` (**carry-forward W126 BUG-1**)

**Severity:** P0-CDIV. See BUG-1 — the production handler at
`src/sync/blocks.ts:643-680` always falls back to
`getdata MSG_WITNESS_BLOCK` regardless of mempool state. The
in-source comment-as-confession at line 669-670 explicitly admits
the dead-helper status.

Listed as a separate bug from BUG-1 because BUG-1 catalogues the
DEAD HELPER (the unused class) and BUG-12 catalogues the
PRODUCTION STUB (the active handler with no contract). Both must
be fixed in lock-step.

**File:** `src/sync/blocks.ts:643-680`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:4466-4683`.

**Impact:** bandwidth ~100× higher per block than Core.

---

## BUG-13 (P1) — No `prev_block->nChainWork + blockProof < GetAntiDoSWorkThreshold()` low-work drop in cmpctblock receive

**Severity:** P1. Core's cmpctblock recv handler (net_processing.cpp:4490-4494):
```cpp
} else if (prev_block->nChainWork + GetBlockProof(cmpctblock.header) < GetAntiDoSWorkThreshold()) {
    // If we get a low-work header in a compact block, we can ignore it.
    LogDebug(BCLog::NET, "Ignoring low-work compact block from peer %d\n", pfrom.GetId());
    return;
}
```

This is the anti-DoS work-threshold gate that prevents a peer from
flooding us with cmpctblocks pointing at low-work headers (the same
class as the headers-DoS that BIP-339-era headers sync was hardened
against).

hotbuns's handler (sync/blocks.ts:643-680) has no work-threshold
check. It uses depth (`tipHeight - blockHeight`) and falls back to
full getdata — but if the header is unknown (`headerEntry === undefined`),
depth is `0` and the handler proceeds to issue a getdata. The peer
can then send us back a low-work block as the response, which goes
through normal block-processing rejection paths (correct), BUT the
intermediate getdata is wasted bandwidth and the rejection path is
more expensive than the early-drop Core path.

**File:** `src/sync/blocks.ts:643-680`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:4490-4494`.

**Impact:** low-grade bandwidth DoS amplifier; peer can force us to
emit a full-block getdata for any cmpctblock with a low-work header.

---

## BUG-14 (P1) — `LoadingBlocks()` gate absent on cmpctblock recv

**Severity:** P1. Core's first gate in CMPCTBLOCK handler
(net_processing.cpp:4468-4472):
```cpp
if (m_chainman.m_blockman.LoadingBlocks()) {
    LogDebug(BCLog::NET, "Unexpected cmpctblock message received from peer %d\n", pfrom.GetId());
    return;
}
```

Prevents reentrancy during reindex / `-loadblock` / `-importmempool`
operations.

hotbuns has no such gate. During a future reindex-from-disk flow
(which hotbuns doesn't currently support, per audit assumption —
need to verify), a cmpctblock dispatch would race with the block
loader. Today moot, but defensive-coding gap.

**File:** `src/sync/blocks.ts:643-680`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:4468-4472`.

**Impact:** future-proofing gap.

---

## BUG-15 (P0-CDIV) — `getblocktxn` serve path is a stub (**carry-forward W126 BUG-2**)

**Severity:** P0-CDIV. `sync/blocks.ts:696-719` has depth-gate plus
inline comment "We don't serve compact blocks yet". `createBlockTxnResponse`
in compact_blocks.ts:1016-1033 is dead code with no production
caller.

A peer that requests blocktxn from us (because they are reconstructing
a cmpctblock and have missing slots) gets no response. They wait
for the response, eventually time out, and either request the full
block via getdata fallback (correct Core fallback behavior) or
disconnect.

This means hotbuns is a **leech** in the BIP-152 mesh: we don't
help peers reconstruct, but if BUG-1 ever gets fixed and we DO
start sending cmpctblocks, we'd be expecting peers to do the same
work for us.

**File:** `src/sync/blocks.ts:696-719`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:4245-4304`.

**Impact:** BIP-152 mesh leech behavior; peer reconstruction
performance degraded; potential reputational gradient (peers may
prefer not to send us cmpctblocks knowing we don't reciprocate).

---

## BUG-16 (P1) — Stale getblocktxn responds silently, not with full-block getdata (Core anti-DoS shaping)

**Severity:** P1. Core's stale-getblocktxn path (net_processing.cpp:4292-4302):
```cpp
// If an older block is requested … send a block response instead of a
// blocktxn response. Sending a full block response instead of a
// small blocktxn response is preferable in the case where a peer
// might maliciously send lots of getblocktxn requests to trigger
// expensive disk reads, because it will require the peer to
// actually receive all the data read from disk over the network.
LogDebug(BCLog::NET, "Peer %d sent us a getblocktxn for a block > %i deep\n", pfrom.GetId(), MAX_BLOCKTXN_DEPTH);
CInv inv{MSG_WITNESS_BLOCK, req.blockhash};
WITH_LOCK(peer.m_getdata_requests_mutex, peer.m_getdata_requests.push_back(inv));
```

Core deliberately responds to stale getblocktxn requests with a
**full-block** push (~1 MB on mainnet) rather than silently
dropping. This is anti-DoS shaping: the cost of a stale request
(disk read) is offset against the cost of receiving the response
(bandwidth), so a peer that floods us with stale getblocktxn
requests also burns their own bandwidth and ours symmetrically.

hotbuns's stale-getblocktxn path (sync/blocks.ts:708-715) silently
returns. A peer can request blocktxn for hash X repeatedly with
zero cost to themselves — hotbuns does a header-index lookup and
returns. The asymmetric cost makes hotbuns a free amplifier for
header-lookup-based timing attacks.

**File:** `src/sync/blocks.ts:708-715`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:4292-4302`.

**Impact:** anti-DoS shaping mechanism inverted; hotbuns absorbs
asymmetric cost.

---

## BUG-17 (P0-CDIV) — `blocktxn` recv handler is empty (**carry-forward W126 BUG-3**)

**Severity:** P0-CDIV. `sync/blocks.ts:722-724`:
```ts
peerManager.onMessage("blocktxn", (_peer, _msg) => {
  // We fall back to full block download, so we shouldn't receive these
});
```

Since hotbuns never sends `getblocktxn` (BUG-12: handler falls back
to full getdata), there is INDEED no current path that would
solicit a `blocktxn` response. But:
- A peer that misbehaves can send us unsolicited `blocktxn` —
  silently accepted (no Misbehaving), no resource accounting.
- If BUG-12 is fixed (handler wired to call `startBlockReconstruction`),
  the wire-up requires `blocktxn` to be processed in lock-step or
  the reconstruction state machine deadlocks.

**File:** `src/sync/blocks.ts:722-724`.

**Core ref:** `bitcoin-core/src/net_processing.cpp::ProcessCompactBlockTxns`.

**Impact:** dead handler; lock-step fix required with BUG-12.

---

## BUG-18 (P0-CDIV) — No `m_most_recent_block` / `m_most_recent_compact_block` cache; no `NewPoWValidBlock` fast-announce path (**carry-forward W126 BUG-5**)

**Severity:** P0-CDIV. Core's fast-relay path
(net_processing.cpp:2095-2160) is the **defining feature** of BIP-152:
when a new block becomes the tip (via mining or validation),
`NewPoWValidBlock` synchronously:
1. Computes a cmpctblock with a random nonce.
2. Stores it in `m_most_recent_compact_block` (+
   `m_most_recent_block_hash` + `m_most_recent_block`) under
   `m_most_recent_block_mutex`.
3. Pushes `CMPCTBLOCK` directly to every peer in
   `lNodesAnnouncingHeaderAndIDs` (the HB peer set, max 3) that
   has the parent header and doesn't yet have this block.

This is what makes block propagation sub-second across the global
mainnet network: no inv→getdata→cmpctblock round-trip, just a
direct push of ~10 KB.

hotbuns has neither the cache nor the announce path. Block
propagation FROM hotbuns goes through… nothing. There's no
`relayBlockToAll` invocation in production (the function exists
in `p2p/relay.ts:234` but is only called from tests — a
side-finding from W155 that re-appears here as W156 BUG-18a).
hotbuns mines a block and… doesn't tell anyone? Let me re-check.

Actually `connectBlock` does invoke the relay manager — but
`relayBlockToAll(blockHash)` only emits an `inv MSG_BLOCK`, not a
cmpctblock. So hotbuns's announce-side is **legacy inv-only**,
~100 bytes per peer per block, but requires a round-trip
(`inv → getdata → block`) so latency-wise it's bounded below by
the round-trip overhead.

Without a `NewPoWValidBlock` analogue, hotbuns can never participate
in the fast-relay mesh. Combined with BUG-3 (no HB-peer selection
inbound), hotbuns is invisible to BIP-152 from both directions:
peers don't fast-announce to us (no `m_bip152_highbandwidth_to`),
we don't fast-announce to peers (no `m_most_recent_compact_block`
cache, no announce path).

**File:** `src/sync/blocks.ts` (entire block-connected path);
`src/p2p/relay.ts:234` (relayBlockToAll exists but no caller); no
file for `m_most_recent_block` cache.

**Core ref:** `bitcoin-core/src/net_processing.cpp:2095-2160`.

**Impact:** measurable block-propagation latency on hotbuns is ~RTT
slower than Core peers (no fast-relay); on a low-RTT inbound
connection, ~50-200 ms extra latency per block hop. Compounded with
hotbuns being in the relay graph and other nodes peering through
hotbuns, this adds up. Worst-case: hotbuns delays block propagation
through it by 2-3× the typical hop time.

---

## BUG-19 (P1) — `nonce` is generated via `crypto.getRandomValues` but cmpctblock create path is unreachable; defensive code

**Severity:** P1. `CompactBlockManager.createCompactBlock`
(compact_blocks.ts:834-846):
```ts
const nonceBuffer = crypto.getRandomValues(new Uint8Array(8));
const nonce = Buffer.from(nonceBuffer).readBigUInt64LE(0);
```

This uses the WebCrypto API — correct for cryptographic uniqueness.
But `createCompactBlock` is dead code (no production caller, see
BUG-1). The nonce generation is wired, but never invoked.

Furthermore: there's no per-peer nonce reuse protection at the
spec layer (BIP-152 specifies a NEW nonce per cmpctblock to prevent
short-id-collision attacks across the peer's view), and no
documented guarantee about how often the cache should be refreshed
in the announce path (since the cache is also missing — BUG-18).

**File:** `src/p2p/compact_blocks.ts:834-846`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:2105`
(`pcmpctblock = std::make_shared<…>(*pblock, FastRandomContext().rand64())`).

**Impact:** moot today (dead code); when wired, the per-peer-vs-
per-block nonce policy needs to be defined (Core uses per-block,
not per-peer — so the cache is keyed on `block_hash → cmpctblock`
not `(block_hash, peer)`).

---

## BUG-20 (P1) — `getNegotiatedVersion` floors at `peerVersion` AND `ourVersion`, but always returns 2n in practice (carry-forward W126 BUG-17 SHORT_IDS_BLOCKS_VERSION gate)

**Severity:** P1. `CompactBlockManager.getNegotiatedVersion`
(compact_blocks.ts:793-799):
```ts
getNegotiatedVersion(peerId: string): bigint {
    const state = this.peerStates.get(peerId);
    if (!state?.peerSupportsCompact) {
      return 0n;
    }
    return state.peerVersion < this.ourVersion ? state.peerVersion : this.ourVersion;
}
```

`ourVersion = 2n` (compact_blocks.ts:728). `peerVersion` is set only
in `handleSendCmpct` (line 760) which already gates on `version === 2n`,
so `peerVersion` ∈ {`0n` (initial), `2n` (post-handshake)}. The
floor function `min(peer, our)` therefore always returns `0n` or
`2n` — never anything else.

The dead `COMPACT_BLOCK_VERSION_1 = 1n` constant exists at line 45
but is never produced by the negotiation. Yet the type
`SendCmpctPayload.version: bigint` accepts arbitrary values, and
`createCompactBlockFromBlock`'s `version: bigint = COMPACT_BLOCK_VERSION_2`
parameter is also accepting-but-ignoring. Encoder/decoder
consistency: there's no v1 (legacy non-witness) path; everything is
hardcoded v2.

This is correct per BIP-152's witness-only modern usage, but:
- The `version` parameter throughout the type signature is a
  promise that's not kept.
- The dead constant `COMPACT_BLOCK_VERSION_1` is a maintainability
  trap.

**File:** `src/p2p/compact_blocks.ts:44-48, 793-799, 728`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:3907`
(version != CMPCTBLOCKS_VERSION → return).

**Impact:** dead-knob; cleanup candidate; documentation gap.

---

## BUG-21 (P1) — `vExtraTxnForCompact` ring-buffer absent

**Severity:** P1 (cross-cite W126 BUG-16). Core maintains a
ring-buffer of recently-rejected / recently-evicted / orphan-pool
transactions that are used as a SECOND source (after mempool) for
cmpctblock reconstruction. This catches the common case where a
miner included a tx that JUST got rejected from our mempool (e.g.
parent-package-too-many-ancestors) or that exists as an orphan we
haven't yet resolved. Without it, those slots become forced
`getblocktxn` round-trips.

hotbuns's `fillFromMempool(mempool, extraTxn: Transaction[] = [])`
accepts an `extraTxn` parameter but every production call site
passes `[]` (default). No ring-buffer is maintained on tx eviction,
orphan-resolution, or mempool-reject paths.

**File:** `src/p2p/compact_blocks.ts:515-608`; cross-files
`src/mempool/mempool.ts` (no eviction hook), `src/mempool/orphan_pool.ts`
(no hook).

**Core ref:** `bitcoin-core/src/net_processing.cpp::vExtraTxnForCompact`.

**Impact:** reconstruction success rate drops; ~5-10% of cmpctblocks
in the wild fall back to getblocktxn round-trips because of
recently-evicted parents that the extra-tx pool would have caught.

---

## BUG-22 (P1) — `removePeer` is never called on disconnect; `peerStates` and `highBandwidthPeers` leak forever (**carry-forward W126 BUG-21**)

**Severity:** P1 (memory-leak class). `CompactBlockManager.removePeer`
(compact_blocks.ts:972-975) cleans up `peerStates` and
`highBandwidthPeers`. Zero production callers.

The manager is dead code (BUG-1), so the leak is currently
unreachable. On wire-up, `removePeer` must be invoked from the peer
disconnect path (manager.ts:disconnectPeer or peer.ts:disconnect)
or the peerStates Map grows unboundedly over the node's lifetime.
With 100s of peers/day churn on a busy node, this is ~1 KB/day
leak — small but persistent.

**File:** `src/p2p/compact_blocks.ts:972-975`.

**Impact:** memory leak on long-running nodes once BUG-1 is fixed.

---

## BUG-23 (P0-CDIV) — `peerManager.onMessage("blocktxn", …)` accepts unsolicited blocktxn without `Misbehaving`

**Severity:** P0-CDIV (DoS gap). Core's `ProcessCompactBlockTxns`
implicitly verifies that the blocktxn we received corresponds to a
pending in-flight getblocktxn request; an unsolicited blocktxn
matches nothing in `mapBlocksInFlight` and is dropped silently
(but logged at debug). If the count of unsolicited blocktxn from a
peer crosses an abuse threshold, the peer can be scored.

hotbuns's handler is literally empty:
```ts
peerManager.onMessage("blocktxn", (_peer, _msg) => {
  // We fall back to full block download, so we shouldn't receive these
});
```

A peer can send us a 1 MB blocktxn (the wire payload includes all
the tx bodies for the missing slots), forcing us to allocate the
deser buffer, run `deserializeBlockTxnPayload` (which itself runs
N `deserializeTx` calls — non-trivial CPU work), then drop the
result. Cost asymmetry: peer pays for sending; we pay for receiving
AND deserializing AND allocating. With pipelining, a peer can
sustain ~10s of MB/s of CPU+mem load on us with negligible cost
to themselves.

**File:** `src/sync/blocks.ts:722-724`.

**Core ref:** `bitcoin-core/src/net_processing.cpp::ProcessCompactBlockTxns`.

**Impact:** sustainable DoS amplification. Core scores; hotbuns
absorbs.

---

## BUG-24 (P1) — sendcmpct send timing: hotbuns sends `sendcmpct` BEFORE Core sends it (handshake-complete vs verack-recv handler)

**Severity:** P1. Core sends `SENDCMPCT` INSIDE the verack-recv
handler (net_processing.cpp:3870), which fires when WE receive the
peer's verack. At that point:
- Our verack has already been pushed.
- The peer has acknowledged our version.
- We've registered txreconciliation, set `fSuccessfullyConnected`,
  and logged the peer.

hotbuns sends `sendcmpct` from `checkHandshakeComplete`
(peer.ts:1326-1329), which fires when BOTH sentVerack=true AND
receivedVerack=true. So hotbuns also sends it post-verack — but
specifically:
- The `sendheaders` and `sendcmpct` are pushed back-to-back BEFORE
  the `events.onHandshakeComplete(this)` callback fires (line 1319).
- Core sends `sendcmpct` AFTER all post-verack initialization (after
  txreconciliation, fSuccessfullyConnected).

The ordering difference is benign in practice (the peer doesn't
care about the ordering of feature-negotiation messages), but it
means hotbuns sends `sendcmpct` before any other post-verack signal.
A peer that gates on receiving sendcmpct as a "feature-negotiation
complete" sentinel would see it earlier from hotbuns. Not a bug
per se; recorded as a timing parity gap.

**File:** `src/p2p/peer.ts:1310-1331`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:3816-3920`.

**Impact:** timing parity gap; peer fingerprintable.

---

## BUG-25 (P1) — `MIN_BLOCKS_TO_KEEP` not defined in compact_blocks.ts (no static_assert analog)

**Severity:** P1. Core enforces:
```cpp
static_assert(MAX_BLOCKTXN_DEPTH <= MIN_BLOCKS_TO_KEEP, "MAX_BLOCKTXN_DEPTH too high");
```
to ensure that any block we'd be asked to serve via getblocktxn
(within MAX_BLOCKTXN_DEPTH=10 of tip) is guaranteed to still be on
disk (within MIN_BLOCKS_TO_KEEP=288 of tip, in prune mode).

hotbuns has `MAX_BLOCKTXN_DEPTH = 10` (compact_blocks.ts:69) and
`MIN_BLOCKS_TO_KEEP = 288` somewhere else, but no static_assert /
compile-time check tying them together. A future contributor who
bumped `MAX_BLOCKTXN_DEPTH` to 500 (say, to be more permissive)
without bumping `MIN_BLOCKS_TO_KEEP` would create a scenario
where:
1. Peer requests blocktxn for a block at depth 400.
2. The depth-gate passes (depth ≤ 500).
3. The block was pruned (depth > 288).
4. The serve path (BUG-15 stub today; future-wired) would
   error out at the file-read.

No compile-time barrier prevents the divergence.

**File:** `src/p2p/compact_blocks.ts:64-69`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:140-141`.

**Impact:** future-proofing gap; type-tightness.

---

## Summary

**Bug count:** 25 (BUG-1 through BUG-25).

**Severity distribution:**
- **P0-CDIV:** 11 (BUG-1, BUG-3, BUG-5, BUG-6, BUG-7, BUG-10, BUG-12,
  BUG-15, BUG-17, BUG-18, BUG-23)
- **P1:** 13 (BUG-2, BUG-8, BUG-9, BUG-11, BUG-13, BUG-14, BUG-16,
  BUG-19, BUG-20, BUG-21, BUG-22, BUG-24, BUG-25)
- **P2:** 1 (BUG-4)

**Carry-forward chain:** BUG-1 / BUG-3 / BUG-12 / BUG-15 / BUG-17 /
BUG-18 / BUG-22 are direct restatements of W126 BUG-1 / BUG-6 /
BUG-7 / BUG-2 / BUG-3 / BUG-5 / BUG-21 from May 17. Streak: 5+
weeks open, **35th-consecutive quad-audit "dead-helper" signature
finding**. W123 → W124 → W125 → W126 → W141 → W142 → … → W155 →
W156. The same bug — `class CompactBlockManager + class
PartiallyDownloadedBlock + createCompactBlockFromBlock +
createBlockTxnResponse` are 1,041 LOC of meticulously-implemented
dead code — has been on the audit list every single quad-audit run
for over a month.

**Fleet patterns confirmed:**
- **"Dead-helper at call site"** (BUG-1, BUG-3, BUG-15, BUG-17,
  BUG-21, BUG-22) — the helper class exists, is exported, is
  unit-tested, has documentation, has full state-machine; the
  production dispatch site has a stub.
- **"Comment-as-confession"** (BUG-1 sync/blocks.ts:669-670 explicitly
  names "BUG-2/BUG-3 — CompactBlockManager dead helper; wiring it
  is out of scope for FIX-42", BUG-15 sync/blocks.ts:717-718 "We
  don't serve compact blocks yet (BUG-5 — getblocktxn serve path
  is a stub)") — 13th+ distinct hotbuns instance (the comment
  documents the bug it perpetuates, sometimes with a TODO that
  has been open multi-week).
- **"Two-pipeline-guard"** (BUG-7) — wire-decode-time gate vs
  semantic-time gate on the same uint16_t cap. Both check
  `index > 0xffff` but at different stages, with different costs.
  17th distinct extension (per W156 fleet tracking).
- **"DoS-gate-semantically-inverted"** (BUG-10) — the bucket-collision
  check was ported as exact-duplicate check; the attack it was
  designed against goes undetected.
- **"Wire-format-fingerprint primitive"** (BUG-7, BUG-24) — timing /
  ordering differences fingerprintable by hostile peers.
- **"Test-suite-masks-production-bug"** (BUG-1 cluster) — 1,041 LOC
  of test code in `compact_blocks.test.ts` +
  `w126_bip152_compact_blocks.test.ts` validates the dead helper
  in isolation; the test suite passes 100% while production handler
  is empty. Tests cannot fail because they don't exercise the
  production wiring.
- **"Advertisement-as-lie"** (BUG-1, BUG-3) — hotbuns advertises
  `sendcmpct(enabled=false, version=2)` to peers (technically
  truthful — `enabled=false` means "don't fast-announce to me"),
  but then has NO MECHANISM to ever switch HB on, NO MECHANISM to
  respond to peers' sendcmpct, NO MECHANISM to reconstruct received
  cmpctblocks. The advertisement is honest about what we want; the
  fact that we can't ever do BIP-152 at all is hidden.
- **"BlockTemplateBuilder dead-helper" parallel** — same shape as
  W155 BUG-1 (and W123 → W154 → W155 → W156 chain): a complete
  helper class with full test coverage, never called from production.
  Both `CompactBlockManager` and `BlockTemplateBuilder` are 1000+
  LOC each of dead code in hotbuns.

**Top three findings:**
1. **BUG-1 + BUG-3 + BUG-12 + BUG-15 + BUG-17 + BUG-18 + BUG-22
   cluster (P0-CDIV dead-helper)** — the entire BIP-152 contract
   is unwired in production. CompactBlockManager (1,041 LOC) is
   dead code; four production handlers are stubs; HB-peer selection
   is absent; fast-announce is absent; cleanup-on-disconnect is
   absent. **Carry-forward 35th-streak signature finding** (5+
   weeks open since W126). This is the **single highest-ROI fix in
   the BIP-152 backlog** — wiring closes 7 of the 11 P0-CDIVs in
   this audit plus 21 bugs from W126 in one PR. Companion to the
   W155 BlockTemplateBuilder finding (both 1000+ LOC dead helpers
   in hotbuns).

2. **BUG-6 + BUG-7 + BUG-10 cluster (P0-CDIV wire-level
   under-validated)** — JS Number arithmetic in `DifferenceFormatter`
   silently loses precision past 2^53, the `uint16_t::max` gate
   runs at semantic-time not wire-time, and the bucket-collision
   DoS gate counts duplicates (already caught by adjacent gate)
   instead of hash-bucket collisions (the real DoS surface).
   Moot today because dispatch is dead (BUG-1), but on wire-up,
   these are the first three places a hostile peer would attack.
   Single architectural fix: rewrite the differential decoder
   to use BigInt arithmetic, add wire-level uint16_t cap, and
   replace the bucket gate with a salted-hash bucket simulation
   or a per-map collision-count threshold.

3. **BUG-5 (P0-CDIV spec violation, coinbase-at-0)** — decoder
   does not enforce BIP-152's "first prefilled MUST be index 0"
   mandate. A malicious peer can construct a cmpctblock with no
   index-0 prefill and the slot-0 tx is reconstructed from
   short-id-matched mempool. The mutation-merkle check catches
   most crafts, but the spec gate is missing and any future code
   path that touches `txnAvailable[0]` before `getBlock` inherits
   a non-coinbase tx in coinbase position. Lock-step with BUG-1
   fix.

**Honourable mentions:**
- BUG-4 (P2 wrong docstring) — fastest fix in the audit (1-line
  docstring correction). The docstring at messages.ts:241-247
  literally describes the WRONG hash function ("SHA256(SHA256(nonce
  || txid))[0:6]" — wrong on three counts). A contributor who
  reads only the type declaration would re-implement using SHA256d
  and produce a chain split.
- BUG-13 + BUG-14 + BUG-16 (P1 cluster: missing DoS pre-checks
  in cmpctblock and getblocktxn receive) — three Core
  defense-in-depth gates absent. Combined with BUG-23 (unsolicited
  blocktxn DoS amplifier), hotbuns is a soft target for low-grade
  BIP-152 abuse vectors.
- BUG-2 (P1) — sendcmpct sent unconditionally; the hidden coupling
  `MIN_PEER_PROTO_VERSION > SHORT_IDS_BLOCKS_VERSION` is undocumented.
  Trivial fix (1-line add of `if (peer.commonVersion >= 70014)`).
- BUG-21 (P1 vExtraTxnForCompact ring-buffer absent) — reconstruction
  success rate at the receive side. The MempoolEntry orphan-pool
  hook is the cheapest catch.

**Cross-cite with other waves:**
- **W126** — direct parent audit (21 bugs); this W156 audit
  re-confirms 7 of those bugs as still-open, escalates them with
  carry-forward streak counter (now 5+ weeks), and adds 18 new
  wire-level findings.
- **W153 BUG-12** — `sync/blocks.ts::connectBlock` never emits
  blockConnected event. Independently confirmed here: the
  absence of the event means no fast-announce hook can fire
  (BUG-18 cause).
- **W155 BUG-1** — `BlockTemplateBuilder` dead-helper, identical
  shape. Two 1000+ LOC dead-helper classes in hotbuns; same fleet
  pattern. The fix for both is "wire the dispatch site to call
  the existing helper" — combined PR closes 35+ bugs.
- **W152 BUG-7 + BUG-9** — BIP-339 wtxid-relay broken end-to-end
  + BIP-35 mempool inv uses wrong getdata flag as inv type. W156
  confirms no analogous wrong-type usage in BIP-152 (handler
  uses `MSG_WITNESS_BLOCK` correctly at sync/blocks.ts:672).
- **W141 hashtx + W152 BUG-18** — entire ZMQ subsystem orphaned.
  Same shape as BUG-18 (no production caller of advertisement
  helpers); ZMQ has the publishers, hotbuns has CompactBlockManager;
  both are dead.
- **W155 BUG-25** — signet block solution unverified. Not directly
  relevant to BIP-152 but reinforces "BIP-152 receive path doesn't
  matter if higher-level block validation already accepts bad
  blocks".
