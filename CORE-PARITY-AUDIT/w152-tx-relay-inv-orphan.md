# W152 — Tx relay + inv batching + orphan handling (hotbuns)

**Wave:** W152 — `RelayTransaction`, `InitiateTxBroadcastToAll`,
`AddTxAnnouncement`, `AddKnownTx`, `m_tx_inventory_to_send`,
`m_tx_inventory_known_filter` (per-peer CRollingBloomFilter),
`m_next_inv_send_time`, `INBOUND_INVENTORY_BROADCAST_INTERVAL=5s` /
`OUTBOUND_INVENTORY_BROADCAST_INTERVAL=2s`,
`INVENTORY_BROADCAST_PER_SECOND=14`, `INVENTORY_BROADCAST_MAX=1000`,
`MAX_INV_SZ=50000`, `MAX_GETDATA_SZ=1000`,
`MAX_PEER_TX_REQUEST_IN_FLIGHT=100`, `MAX_PEER_TX_ANNOUNCEMENTS=5000`,
`GETDATA_TX_INTERVAL=60s`, `TXID_RELAY_DELAY=2s` (BIP-339 anti-prefer
txid peers), `NONPREF_PEER_TX_DELAY=2s`, `OVERLOADED_PEER_TX_DELAY=2s`,
`RejectIncomingTxs` (block-relay-only / feeler / `-blocksonly`),
`MSG_TX` vs `MSG_WTX` (BIP-339) inv dispatch, `MSG_WITNESS_TX`
(BIP-144 getdata flag — NOT a valid inv type), wtxid-keyed orphan map,
`DEFAULT_MAX_ORPHAN_TRANSACTIONS=100` (legacy bound; modern Core uses
`DEFAULT_MAX_ORPHANAGE_LATENCY_SCORE=3000`), `ORPHAN_TX_EXPIRE_TIME=300s`,
`EraseForBlock` (Core erases orphans **conflicted** by a block tx,
not only ones literally confirmed), `EraseForPeer`, `txdownloadman`
+ `TxRequestTracker` (alternating-announcer scheduler), `BIP-37
NODE_BLOOM` filter / `mempool` (BIP-35) inv response, `m_relays_txs`
(peer's VERSION `fRelay` field).

**Scope:** discovery only — no production code changes.

**Bitcoin Core references**
- `bitcoin-core/src/net_processing.cpp:126` — `MAX_INV_SZ=50000`.
- `bitcoin-core/src/net_processing.cpp:128` — `MAX_GETDATA_SZ=1000`.
- `bitcoin-core/src/net_processing.cpp:165` —
  `INBOUND_INVENTORY_BROADCAST_INTERVAL=5s`.
- `bitcoin-core/src/net_processing.cpp:169` —
  `OUTBOUND_INVENTORY_BROADCAST_INTERVAL=2s`.
- `bitcoin-core/src/net_processing.cpp:172` —
  `INVENTORY_BROADCAST_PER_SECOND=14` (NOT 7).
- `bitcoin-core/src/net_processing.cpp:174` —
  `INVENTORY_BROADCAST_TARGET = 14 * 5 = 70`.
- `bitcoin-core/src/net_processing.cpp:176-178` —
  `INVENTORY_BROADCAST_MAX=1000` + static_assert ≥ TARGET, ≤ MAX_PEER_TX_ANNOUNCEMENTS.
- `bitcoin-core/src/net_processing.cpp:303` — per-peer
  `m_tx_inventory_known_filter` is a `CRollingBloomFilter{50000, 0.000001}`
  (rolling LRU of inv-already-seen).
- `bitcoin-core/src/net_processing.cpp:308` — per-peer
  `m_tx_inventory_to_send` is `std::set<Wtxid>` (wtxid-keyed always).
- `bitcoin-core/src/net_processing.cpp:1142-1149` — `AddKnownTx`
  inserts into `m_tx_inventory_known_filter`.
- `bitcoin-core/src/net_processing.cpp:2243-2263` —
  `InitiateTxBroadcastToAll`: skips peer if `m_next_inv_send_time == 0s`
  (handshake-pre window), filters via `m_tx_inventory_known_filter`,
  inserts wtxid into `m_tx_inventory_to_send`.
- `bitcoin-core/src/net_processing.cpp:3676-3691, 5598-5606` —
  `fRelay` parse + `RejectIncomingTxs` (block-relay-only and feeler
  connections may NEVER send us txs; in `-blocksonly` mode the peer
  needs `Relay` permission).
- `bitcoin-core/src/net_processing.cpp:4037-4125` — INV handler:
  drops MSG_TX inv on wtxidrelay peers (and vice-versa), rejects all
  tx-class inv on block-relay-only peers, calls `AddKnownTx` for every
  tx-class inv received.
- `bitcoin-core/src/net_processing.cpp:4385-4463` — TX handler:
  RejectIncomingTxs disconnect, IBD-skip, `AddKnownTx`,
  `m_txdownloadman.ReceivedTx`, `ProcessTransaction`, `ProcessValidTx`,
  `ProcessInvalidTx` (records into `m_recent_rejects`).
- `bitcoin-core/src/net_processing.cpp:5982-6088` — `SendMessages`
  inv-trickle loop: `NextInvToInbounds` (Poisson-spaced via network
  key for inbound) / `rand_exp_duration` (outbound),
  `make_heap`/`pop_heap` over `vInvTx` for fee-rate ordering,
  `broadcast_max = INVENTORY_BROADCAST_TARGET + (queue/1000)*5`
  clamped to `INVENTORY_BROADCAST_MAX=1000`, dispatches
  `peer.m_wtxid_relay ? CInv{MSG_WTX, wtxid} : CInv{MSG_TX, txid}`,
  filters via `m_fee_filter_received`, filters via per-peer bloom
  filter (BIP-37), inserts wtxid/txid into `m_tx_inventory_known_filter`
  on send.
- `bitcoin-core/src/node/txorphanage.h:21-23` —
  `DEFAULT_MAX_ORPHANAGE_LATENCY_SCORE=3000` (modern; legacy bound
  was `DEFAULT_MAX_ORPHAN_TRANSACTIONS=100`, which is the parity
  target hotbuns still tracks).
- `bitcoin-core/src/node/txorphanage.cpp:610-643` — `EraseForBlock`
  iterates each tx's `vin`, looks up `m_outpoint_to_orphan_wtxids[prevout]`,
  evicts every orphan that **conflicts** with the block tx (not only
  the orphan whose own txid was confirmed).
- `bitcoin-core/src/node/txorphanage.cpp:416-433` — `EraseForPeer`.
- `bitcoin-core/src/node/txorphanage.cpp:527-583` — `AddChildrenToWorkSet`
  (post-parent-arrival, Core randomises peer-announcer for re-eval).
- `bitcoin-core/src/node/txdownloadman.h:24-38` —
  `MAX_PEER_TX_REQUEST_IN_FLIGHT=100`, `MAX_PEER_TX_ANNOUNCEMENTS=5000`,
  `TXID_RELAY_DELAY=2s`, `NONPREF_PEER_TX_DELAY=2s`,
  `OVERLOADED_PEER_TX_DELAY=2s`, `GETDATA_TX_INTERVAL=60s`.
- `bitcoin-core/src/zmq/zmqnotificationinterface.cpp:180-196` —
  `BlockConnected` fans `NotifyTransaction` over EVERY tx in the
  block (drives both hashtx and rawtx topics).
- `bitcoin-core/src/zmq/zmqpublishnotifier.cpp:210-265` — hashblock,
  rawblock, hashtx, rawtx, sequence notifier classes.

**Files audited**
- `src/p2p/relay.ts` (386 lines) — `InventoryRelay`, per-peer queue,
  Poisson timer, `addPeer(peer, isInbound, wtxidRelay)`, `queueTx`,
  `queueTxFiltered`, `queueTxToAll`, `queueTxToAllFiltered`,
  `relayBlockNow`, `relayBlockToAll`, `flush`, `shuffleArray`,
  `poissonDelay`, constants `INBOUND_INVENTORY_BROADCAST_INTERVAL=5s`,
  `OUTBOUND_INVENTORY_BROADCAST_INTERVAL=2s`,
  `INVENTORY_BROADCAST_MAX=1000`, `INVENTORY_BATCH_SIZE=7`.
- `src/mempool/orphan_pool.ts` (421 lines) — `OrphanPool`,
  `MAX_ORPHAN_TRANSACTIONS=100`, `MAX_ORPHAN_TX_SIZE=100_000`,
  `MAX_PEER_ORPHAN_TX=50`, `ORPHAN_TX_EXPIRE_TIME=300`,
  `add`/`eraseTx`/`eraseForPeer`/`eraseForBlock`/`findByPrevout`/
  `findChildrenOf`/`onParentAdmitted`/`expireOldOrphans`/`evictRandom`.
- `src/sync/blocks.ts` (3300+ lines) — `handleInv` (961-1013),
  `handleGetData` (1018-1032), `notfound` handler (608-636) —
  block-only handlers; tx-class inv silently dropped.
- `src/cli/cli.ts` (3000+ lines) — orphan-pool wiring (1752-1846),
  tx-msg handler (1854-1888), `processOrphanCascade` (1897-1926),
  BIP-35 mempool inv response (1947-1971), `txRelay.addPeer(peer, true)`
  call site (1833) **fixed `wtxidRelay=false` default never overridden**.
- `src/p2p/peer.ts` (1455 lines) — `wtxidRelay` field (230, 364, 1262-1271),
  `connType` field (187, 346, 851), `relay` config (41, 926),
  `recordTxReceived` (1340-1345) **dead-data plumbing**,
  `feeFilterReceived` / `feeFilterSent` / `nextFeeFilterSend`,
  `noban`, `lastTxTime`.
- `src/p2p/messages.ts` (1711 lines) — `InvType` enum (169-185)
  with `MSG_TX=1`, `MSG_WTX=5`, `MSG_WITNESS_TX=0x40000001`,
  `MAX_INV_SZ=50_000`, `MAX_MESSAGE_SIZE = 4MB`, `deserializeInvPayload`
  (1091-1102) — DoS cap enforced for inv/getdata/notfound.
- `src/p2p/manager.ts` (2850 lines) — peer construction at line 1070,
  1085, 2354 — **never threads connType into the Peer constructor**;
  `handleHandshakeComplete` (1862-1891) fires `__connect__`;
  `connectionType` parameter at line 993 stored only in
  `peerConnectionType` map (line 1100) and the `info` row (line 1123),
  never propagated to `peer.connType` (which always defaults to "inbound").
- `src/rpc/server.ts` (8000+ lines) — `broadcastTxInv(txid)` at
  3507-3523 (immediate broadcast, bypasses InventoryRelay trickle).
- `src/mempool/mempool.ts` (4727 lines) — `reorgRefillUnchecked`
  at 2546-2603 (W150 BUG-10 carry-forward, fee=0 admission).
- `src/rpc/zmq.ts` (385 lines) — `notifyBlock` (206-223) does include
  hashtx-per-tx fan-out at lines 218-222, BUT `wireZMQNotifications`
  (354-384) is **never called from cli.ts or index.ts** — the entire
  ZMQ subsystem is dead-code.

---

## Gate matrix (37 sub-gates / 14 behaviours)

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 1 | DEFAULT_MAX_ORPHAN_TRANSACTIONS | G1: legacy cap = 100 | PASS (`orphan_pool.ts:41`) |
| 1 | … | G2: per-tx size = 100_000 (= MAX_STANDARD_TX_WEIGHT/4) | PASS (`orphan_pool.ts:50`) |
| 1 | … | G3: per-peer cap to prevent fill-attack | PASS (`orphan_pool.ts:60`, `MAX_PEER_ORPHAN_TX=50`) |
| 1 | … | G4: ORPHAN_TX_EXPIRE_TIME = 300s | PASS (`orphan_pool.ts:72`) |
| 1 | … | G5: EraseForBlock evicts orphans **conflicted by** block (not only confirmed) | **BUG-1** (orphan_pool.ts:274-285 only erases confirmed; comment-as-confession at 270-272 admits Core does both) |
| 2 | Poisson inv timer | G6: inbound 5s mean | PASS (`relay.ts:20`) |
| 2 | … | G7: outbound 2s mean | PASS (`relay.ts:27`) |
| 2 | … | G8: INVENTORY_BROADCAST_PER_SECOND = 14 | **BUG-2** (`INVENTORY_BATCH_SIZE=7` at `relay.ts:40` — half of Core's 14; INVENTORY_BROADCAST_TARGET should be 70 inv/5s for inbound) |
| 2 | … | G9: per-fan-out cap = `TARGET + (queue/1000)*5` clamped to 1000 | **BUG-3** (`relay.ts:335` uses fixed `min(7, 1000)` — no queue-size-aware ramp) |
| 3 | TXID_RELAY_DELAY=2s | G10: txid-only (non-wtxid) peers de-prioritised by 2s in tx request | **BUG-4** (no TxRequestTracker; tx-fetch flow entirely absent — vacuous; see BUG-15) |
| 4 | NONPREF_PEER_TX_DELAY=2s | G11: non-preferred inbound peers de-prioritised | **BUG-5** (cross-cite BUG-4) |
| 5 | OVERLOADED_PEER_TX_DELAY=2s | G12: peers at MAX_PEER_TX_REQUEST_IN_FLIGHT=100 in-flight de-prioritised | **BUG-6** (cross-cite BUG-4) |
| 6 | MSG_WTX vs MSG_TX dispatch | G13: peer-supports-wtxidrelay → MSG_WTX (=5) + wtxid | **BUG-7** (`relay.ts:356` reads `queue.wtxidRelay` — frozen at addPeer time; `cli.ts:1833` calls `addPeer(peer, true)` with default `wtxidRelay=false`; ALL relay traffic goes as MSG_TX + **txid** regardless of BIP-339 negotiation) |
| 6 | … | G14: legacy peer → MSG_TX (=1) + txid | PARTIAL (G13 means everyone gets the legacy path; correct on the wire for legacy peers, broken for BIP-339 peers) |
| 6 | … | G15: hash queued is the right one (wtxid vs txid) | **BUG-8** (`cli.ts:1867, 1911` always queues `getTxId(tx).toString("hex")` — TXID — and `relay.ts:357-360` blindly dispatches that hash as MSG_WTX or MSG_TX. For wtxidrelay peers we'd be sending the TXID with MSG_WTX type — wrong hash for the type.) |
| 6 | … | G16: BIP-35 mempool response uses correct inv type | **BUG-9** (`cli.ts:1966` always uses `InvType.MSG_WITNESS_TX = 0x40000001`, a BIP-144 getdata flag that's NOT a valid inv type — Core peers silently discard; comment-as-confession at 1955-1962 admits "hotbuns does not yet track per-peer wtxidrelay state" although `peer.wtxidRelay` IS tracked) |
| 7 | OrphanByParent map (O(1) lookup) | G17: prevout → orphans map | PARTIAL (`orphan_pool.ts:121` `byPrevout: Map<string, Set<string>>`; per-outpoint lookup is O(1), but `findChildrenOf` at 312-328 iterates the ENTIRE map for parent-txid prefix matching — O(byPrevout.size) per parent) |
| 8 | m_recently_announced_invs | G18: per-peer rolling LRU of recent-tx sent to peer | **BUG-10** (no analogue; `InventoryRelay` has no known-set; re-announces same tx repeatedly to peer that already saw it) |
| 8 | … | G19: m_tx_inventory_known_filter (CRollingBloomFilter, size 50000) | **BUG-10** cross-cite |
| 9 | txrequest GETDATA + timeout + reschedule | G20: per-peer in-flight request tracker | **BUG-11** (no `TxRequestTracker`/`m_txdownloadman` equivalent; hotbuns never issues tx getdata at all) |
| 9 | … | G21: GETDATA_TX_INTERVAL=60s before re-request from same peer | **BUG-11** cross-cite |
| 9 | … | G22: alternating-announcers (round-robin re-request from different peer) | **BUG-11** cross-cite |
| 10 | bloom-filter mempool dump on inv | G23: peerBloomFilters→ NODE_BLOOM advertise on services | PASS (`cli.ts:1477` ORs NODE_BLOOM into params.services) |
| 10 | … | G24: BIP-35 mempool RPC dispatch | PASS (`cli.ts:1947-1971`) |
| 10 | … | G25: filterload/filteradd/filterclear handlers | **BUG-12** (no handlers; W134 BUG-class — Core disconnects peers sending filter messages when NODE_BLOOM not advertised, hotbuns silently drops) |
| 10 | … | G26: per-peer CBloomFilter applied to tx-relay output | **BUG-13** (no per-peer bloom filter; relay.ts has no `bloomFilter` field; W103 G30) |
| 11 | inv message size cap MAX_INV_SZ=50000 | G27: incoming inv cap enforced before allocation | PASS (`messages.ts:1093-1096` rejects count > MAX_INV_SZ pre-alloc) |
| 11 | … | G28: incoming getdata cap MAX_GETDATA_SZ=1000 (not MAX_INV_SZ) | **BUG-14** (`messages.ts:1091-1102` getdata uses same `deserializeInvPayload` → cap is 50000, not 1000; 50× DoS amplification per getdata; W103 BUG-3 carry-forward) |
| 11 | … | G29: outgoing inv batching respects MAX_INV_SZ | PASS (`relay.ts:335` caps at INVENTORY_BROADCAST_MAX=1000, well below MAX_INV_SZ) |
| 12 | RejectIncomingTxs | G30: block-relay-only peers' tx messages disconnected (Misbehaving + disconnect) | **BUG-15** (`peer.connType` always defaults to "inbound"; `manager.ts:1070/1085/2354` never thread `connType` into Peer constructor; tx handler at `cli.ts:1854` has zero conn-type gate; W103 BUG-5 carry-forward) |
| 12 | … | G31: feeler peers' tx messages dropped | **BUG-15** cross-cite |
| 12 | … | G32: -blocksonly + non-Relay-permission peers' tx messages dropped | PARTIAL (no `-blocksonly` flag; W141 also identified) |
| 13 | versionPayload.fRelay handling | G33: peer's VERSION `fRelay=false` suppresses our outbound tx-relay TO that peer | **BUG-16** (`peer.ts:1226-1236` stores versionPayload but `versionPayload.relay` is parsed and NEVER consumed; we keep queuing tx invs to peers that asked for none) |
| 14 | wtxid-keyed orphan storage | G34: primary index by wtxid (BIP-339) | PASS (`orphan_pool.ts:111` `byWtxid: Map<string, OrphanEntry>`) |
| 14 | … | G35: secondary index by txid for legacy peer lookup | PASS (`orphan_pool.ts:114`) |
| 14 | … | G36: prevout → wtxid set | PASS (`orphan_pool.ts:121`) |
| 14 | … | G37: random eviction at global cap (matches Core EvictRandom historical) | PASS (`orphan_pool.ts:383-395`) |

---

## BUG-1 (P1) — `eraseForBlock` does not evict orphans **conflicted by** a block tx

**Severity:** P1. Bitcoin Core's `TxOrphanageImpl::EraseForBlock`
(`txorphanage.cpp:610-643`) iterates each tx in the connected block,
walks `block_tx.vin`, and for each prevout looks up
`m_outpoint_to_orphan_wtxids[prevout]` — EVERY orphan that spends an
outpoint also spent by a block tx is evicted, regardless of whether
the orphan itself appears in the block. This is the **conflict
detection** half of EraseForBlock: orphans waiting on a parent whose
output got spent by a block tx will never resolve, so leaving them
in the pool is pure waste (cap slots, latency-score budget, TTL
work).

hotbuns's `OrphanPool::eraseForBlock` (`orphan_pool.ts:274-285`):

```ts
eraseForBlock(confirmedTxids: Iterable<Buffer>): number {
  let removed = 0;
  for (const txid of confirmedTxids) {
    const wtxidHex = this.txidIndex.get(txid.toString("hex"));
    if (!wtxidHex) continue;
    ...
    this.removeEntry(entry);
    removed++;
  }
  return removed;
}
```

Only removes orphans whose own txid appears in the confirmed list.
Conflicted orphans (block tx spends the same prevout) are left in
the pool until the 5-minute TTL sweep. The comment at
`orphan_pool.ts:270-272` is a comment-as-confession:

> Caller passes confirmed txids when a new block is connected. This is
> the Core `EraseForBlock` hook; Core also evicts orphans whose inputs
> are now spent by another tx in the block, but for this simplified
> port we just remove orphans that themselves got mined.

**File:** `src/mempool/orphan_pool.ts:265-285`, comment-as-confession
at 270-272.

**Core ref:** `bitcoin-core/src/node/txorphanage.cpp:610-643`
(`EraseForBlock` walks each block tx's vin and looks up
`m_outpoint_to_orphan_wtxids[prevout]`).

**Impact:**
- Cap-slot waste: under sustained orphan-arrival, conflicted orphans
  occupy slots that legitimate retryable orphans need.
- Cascade-promote cost: `processOrphanCascade` at `cli.ts:1897-1926`
  iterates `block.transactions.map(processOrphanCascade)`, each of
  which calls `onParentAdmitted` → `findChildrenOf` → O(byPrevout.size)
  scan, walking past these now-unresolvable conflicts on every block.
- Latency-score equivalent: hotbuns uses count-based caps rather
  than Core's modern latency-score scheme, so the cost-of-leaving is
  bounded — but the structural divergence remains.
- Fleet pattern instance: 7th comment-as-confession in hotbuns
  W142-W152 tracking.

---

## BUG-2 (P1) — `INVENTORY_BATCH_SIZE = 7` is half of Core's `INVENTORY_BROADCAST_PER_SECOND = 14`

**Severity:** P1. Bitcoin Core's `INVENTORY_BROADCAST_PER_SECOND`
(`net_processing.cpp:172`) is `14` (not 7 as a casual read of older
docs suggests). `INVENTORY_BROADCAST_TARGET = 14 × 5 = 70` per
inbound 5-second tick. `INVENTORY_BROADCAST_MAX = 1000` is the upper
clamp.

hotbuns's `INVENTORY_BATCH_SIZE = 7` (`relay.ts:40`) is half of Core's
14. The comment at `relay.ts:38-40` says:

> Per the spec, batch up to 7 inv entries per peer per tick.

— this is a misreading of older spec text. Per `SendMessages` at
`net_processing.cpp:6045-6046`:

```cpp
size_t broadcast_max{INVENTORY_BROADCAST_TARGET + (tx_relay->m_tx_inventory_to_send.size()/1000)*5};
broadcast_max = std::min<size_t>(INVENTORY_BROADCAST_MAX, broadcast_max);
```

— the base target is 70 inv/inbound-tick, ramped by queue size (+5 per
1000 pending), clamped to 1000. hotbuns ships ≤7 inv/tick regardless
of queue depth.

**File:** `src/p2p/relay.ts:38-40, 335`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:172, 6045-6046`.

**Impact:** under burst tx-acceptance (a fresh post-IBD node catching
up on mempool), hotbuns drains its pendingTxs Set at 7/5s ≈ 1.4 inv/s
per peer, vs Core's 70/5s = 14 inv/s. Slow mempool propagation;
peer drift; pendingTxs grows unbounded. On a busy mainnet this is
the difference between "mempool converges in seconds" and "mempool
takes minutes to drain on connect".

---

## BUG-3 (P1) — Per-flush cap is fixed `min(7, 1000)`; no queue-size-aware ramp

**Severity:** P1. Cross-cite BUG-2. Even if `INVENTORY_BATCH_SIZE`
were corrected to 70, the relay flush at `relay.ts:335` is:

```ts
const maxToSend = Math.min(INVENTORY_BATCH_SIZE, INVENTORY_BROADCAST_MAX);
```

— a static `min(7, 1000) = 7`. Core's `broadcast_max =
INVENTORY_BROADCAST_TARGET + (queue/1000)*5` ramps the per-tick cap
upward as the queue grows, so a 5000-pending queue gets `70 + 25 = 95`
per tick (clamped to 1000). hotbuns has no such ramp; the queue
stays at-most-7-drained-per-tick indefinitely.

**File:** `src/p2p/relay.ts:335`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:6045-6046`.

**Impact:** mempool catch-up scales linearly with TICKS, not with
queue size. On a 10000-tx mempool, drain time per peer is
10000/7 × 5s = ~7140s = ~2 hours. Core would drain the same in
~30 minutes (ramped) or ~12 minutes (saturated at MAX=1000).

---

## BUG-4 / BUG-5 / BUG-6 (P1 cluster) — TxRequestTracker entirely absent (no GETDATA_TX, no per-peer in-flight, no announcement delays)

**Severity:** P1. Bitcoin Core's `m_txdownloadman` (Core's modern
TxRequestTracker) is the scheduler that decides, on every inv-class
announcement: WHICH peer to fetch from, WHEN to fetch, and HOW
many concurrent fetches per peer (`MAX_PEER_TX_REQUEST_IN_FLIGHT=100`).
It also implements the four "delay" gates: `TXID_RELAY_DELAY=2s`
(prefer wtxid-relay peers), `NONPREF_PEER_TX_DELAY=2s` (prefer
outbound full-relay), `OVERLOADED_PEER_TX_DELAY=2s` (back off from
peers at the cap), and `GETDATA_TX_INTERVAL=60s` (timeout for
re-request from a different peer).

hotbuns has **none** of this. The inv handler at `sync/blocks.ts:961-1013`
only handles MSG_BLOCK / MSG_WITNESS_BLOCK; MSG_TX / MSG_WTX /
MSG_WITNESS_TX inv entries fall through the loop body silently. There
is no per-peer tx request map, no tx getdata anywhere in the codebase,
no `m_txrequest` analog. The node relies entirely on peers PUSHING
txs to it via the `tx` message (post-connect, peer naturally relays
its mempool to us).

**File:** `src/sync/blocks.ts:961-1013` (handleInv block-only);
NO file implementing TxRequestTracker.

**Core ref:** `bitcoin-core/src/node/txdownloadman.h:24-38`,
`bitcoin-core/src/node/txdownloadman_impl.{h,cpp}`.

**Impact:**
- BUG-4 (TXID_RELAY_DELAY): vacuous, no fetch path.
- BUG-5 (NONPREF_PEER_TX_DELAY): vacuous, no fetch path.
- BUG-6 (OVERLOADED_PEER_TX_DELAY): vacuous, no fetch path.
- Underlying P2P-divergence: hotbuns is a tx-relay SINK with no
  active fetch — it cannot recover from a peer dropping the tx after
  announcing it, cannot multiplex requests across peers, cannot
  bound concurrent fetches per peer. Cross-impl divergence: every
  other hashhog impl is expected to implement the inv→getdata→tx
  flow; hotbuns short-circuits with peer-push-only.
- W103 BUG-7/-8/-9/-10/-11/-12/-16 carry-forwards.

---

## BUG-7 (P0-CDIV) — Inventory relay never dispatches MSG_WTX; `wtxidRelay` flag is frozen at addPeer time and never propagated from `peer.wtxidRelay`

**Severity:** P0-CDIV (BIP-339 wire-protocol divergence). The
`InventoryRelay.addPeer` signature is
`addPeer(peer, isInbound=false, wtxidRelay=false)`. The single
production call site at `cli.ts:1832-1834`:

```ts
peerManager.onMessage("__connect__", (peer) => {
  txRelay.addPeer(peer, true);  // wtxidRelay defaulted to false
});
```

— passes `isInbound=true` and lets `wtxidRelay` default to `false`.
The queue stores this stale value in `queue.wtxidRelay`
(`relay.ts:110`), and `flush` reads `queue.wtxidRelay` at
`relay.ts:356`:

```ts
const invType = queue.wtxidRelay ? InvType.MSG_WTX : InvType.MSG_TX;
```

`peer.wtxidRelay` (which IS correctly set during the handshake at
`peer.ts:1262-1271`) is NEVER consulted by the relay. Net effect:
**every relay-trickled inv goes as `MSG_TX` regardless of BIP-339
negotiation**, even with peers that signalled `wtxidrelay`.

Compounds with BUG-8 (the hash bytes queued are ALSO always txid).

**File:** `src/p2p/relay.ts:96-117, 110, 356`; `src/cli/cli.ts:1832-1834`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:2259, 6063-6065` —
`peer.m_wtxid_relay` is consulted LIVE on every inv dispatch.

**Impact:**
- BIP-339 wtxid-relay peers receive `MSG_TX + txid` inv (correct
  shape on wire) but Core's inv handler at `net_processing.cpp:4059-4063`
  explicitly **DROPS** MSG_TX inv on wtxidrelay peers:
  ```cpp
  if (peer.m_wtxid_relay) {
      if (inv.IsMsgTx()) continue;  // DROPPED
  }
  ```
  So **hotbuns's relay-trickled tx invs are silently discarded by
  Core peers that negotiated wtxidrelay**. Hotbuns appears to be
  relaying but no BIP-339 peer ever sees the inv → mempool propagation
  to BIP-339 peers is broken.
- Cross-cite BUG-8: even if the type were corrected to MSG_WTX, the
  hash bytes are txid, not wtxid — Core peers would look up the
  wrong hash in their `m_tx_inventory_known_filter`.

---

## BUG-8 (P0-CDIV) — Relay queues `txid.toString("hex")` for both peer classes; MSG_WTX dispatch would carry the WRONG hash

**Severity:** P0-CDIV. The relay queue is keyed by HEX-string at
`relay.ts:59 (Set<string>)` and `cli.ts:1867/1911`:

```ts
const txidHex = txid.toString("hex");
...
txRelay.queueTxToAllFiltered(txidHex, feeRate);
```

— **always passes txid**, never wtxid. `flush` at `relay.ts:357-360`
blindly reads the hex back to Buffer:

```ts
const invType = queue.wtxidRelay ? InvType.MSG_WTX : InvType.MSG_TX;
const inventory: InvVector[] = txidsToSend.map((txid) => ({
  type: invType,
  hash: Buffer.from(txid, "hex"),
}));
```

— and dispatches that hash as MSG_WTX if `queue.wtxidRelay` were
true. The hash bytes would be the **txid** but the inv type would
claim **wtxid**. Core's INV handler at line 4060-4062 would treat
this as "wtxid inv" and look up `inv.hash` in the wtxid-keyed
known-set; the receiver's mempool lookup would also use the wtxid
view (mismatched), so the receiver would (a) NOT recognise we
already have the tx and re-request, (b) on getdata fall through to
"tx not in mempool" and `notfound`.

Currently masked by BUG-7 (the dispatch is always `MSG_TX` so the
queued txid is the right hash for the type). **Fixing BUG-7 without
also fixing BUG-8 would activate this latent divergence.**

**File:** `src/p2p/relay.ts:43-64, 144-207, 357-360`;
`src/cli/cli.ts:1863-1867, 1908-1911`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:6056-6065`:
```cpp
const auto inv = peer.m_wtxid_relay ?
                     CInv{MSG_WTX, wtxid.ToUint256()} :
                     CInv{MSG_TX, txinfo.tx->GetHash().ToUint256()};
```
— Core picks the inv type AND the hash together from the right
hash-pair on the mempool entry.

**Impact:** latent P0-CDIV that activates whenever BUG-7 is fixed.
The relay layer needs to either (a) queue `{txid, wtxid}` pairs and
pick per-peer at flush, or (b) re-fetch the right hash from mempool
at flush time (Core's approach).

---

## BUG-9 (P0-CDIV) — BIP-35 mempool inv response uses `MSG_WITNESS_TX = 0x40000001` (a BIP-144 getdata flag, NOT a valid inv type)

**Severity:** P0-CDIV. Bitcoin Core peers treat
`0x40000001` (`MSG_WITNESS_TX`) as a **getdata flag** indicating "I
want this tx with witness data" — it is valid in a GETDATA message
but NOT in an INV. Core's inv handler at `net_processing.cpp:4079-4094`
dispatches inv items based on `inv.IsGenTxMsg()` which returns true
for MSG_TX and MSG_WTX only; MSG_WITNESS_TX is unknown:

```cpp
} else {
    LogDebug(BCLog::NET, "Unknown inv type \"%s\" received from peer=%d\n", ...);
}
```

Core silently logs and discards the entry — the BIP-35 response is
effectively a no-op for every Core peer.

hotbuns's BIP-35 mempool response at `cli.ts:1963-1970`:

```ts
for (let i = 0; i < txids.length; i += MAX_INV_PER_MESSAGE) {
  const slice = txids.slice(i, i + MAX_INV_PER_MESSAGE);
  const inventory: InvVector[] = slice.map((hash) => ({
    type: InvType.MSG_WITNESS_TX,  // 0x40000001 — WRONG for inv
    hash,
  }));
  peer.send({ type: "inv", payload: { inventory } });
}
```

The comment-as-confession at lines 1955-1962 admits:

> hotbuns does not yet track per-peer wtxidrelay state, so we
> conservatively advertise as MSG_WITNESS_TX — matches the existing
> relay path and is what Core emits for non-wtxidrelay peers (sans
> the witness flag, which we set to keep witness-capable receivers
> happy).

This is wrong on two counts: (1) hotbuns DOES track wtxidrelay state
in `peer.wtxidRelay`; (2) Core emits MSG_TX (=1) or MSG_WTX (=5),
NEVER MSG_WITNESS_TX (=0x40000001) in an inv.

**File:** `src/cli/cli.ts:1955-1971` (entire BIP-35 mempool handler).

**Core ref:** `bitcoin-core/src/protocol.h` (MSG_TX=1, MSG_WTX=5,
MSG_WITNESS_TX is the BIP-144 getdata bit-flag 0x40000001);
`bitcoin-core/src/net_processing.cpp:4079-4094` (inv handler
discards unknown inv types with a debug log).

**Impact:** BIP-35 `mempool` requests from Core peers receive a
response that contains zero usable inv entries (Core silently
discards every item). The full mempool dump is effectively a
no-op for cross-impl interoperability. hotbuns peers (also
hotbuns) accept MSG_WITNESS_TX in their inv handler because both
sides use the same wrong constant — divergence is visible only
when interoperating with Core (or any other compliant impl).
Comment-as-confession 8th hotbuns instance.

---

## BUG-10 (P1) — No `m_tx_inventory_known_filter` per-peer LRU; re-announces same tx to peer that announced it to us

**Severity:** P1 (privacy + bandwidth). Bitcoin Core maintains a
per-peer `CRollingBloomFilter m_tx_inventory_known_filter{50000,
0.000001}` (`net_processing.cpp:303`) tracking every inv hash the
peer has either announced to us or that we have announced to it.
`AddKnownTx` (`net_processing.cpp:1142-1149`) inserts on:
- every tx-class inv received from a peer (4086),
- every tx we deliver via the tx message (4404),
- every tx we successfully announce via inv (6019, 6082),
- every orphan-parent fetch initiated (3140).

The trickle loop at `net_processing.cpp:6067-6068` checks the filter
BEFORE sending:

```cpp
if (tx_relay->m_tx_inventory_known_filter.contains(inv.hash)) {
    continue;
}
```

— so we never inv to a peer a tx we know they already know.

hotbuns has NO such filter. The `InventoryRelay` queue (`relay.ts`)
is a flat `Set<string>` per peer with no de-duplication against
"peer already saw this". When peer A invs a tx to us and we accept it
into mempool, `cli.ts:1867` calls `txRelay.queueTxToAllFiltered(txid, ...)`
which adds the txid to peer A's pending set. The next flush sends
peer A back the tx they just gave us.

**File:** `src/p2p/relay.ts:43-64` (PeerRelayQueue has no `knownTxs`
field), 197-207 (`queueTxToAllFiltered` queues to every peer with no
known-set check).

**Core ref:** `bitcoin-core/src/net_processing.cpp:303, 1142-1149,
6067-6068`.

**Impact:**
- Bandwidth: each tx is invd back to the peer that gave it to us.
  Doubles inv-message volume on the inbound side.
- Privacy: peer learns we processed their tx by observing the
  re-announcement timing.
- Cross-cite W103 BUG-13 (AddKnownTx absent).

---

## BUG-11 (P1) — No tx-fetch flow at all; `MAX_PEER_TX_REQUEST_IN_FLIGHT`, `GETDATA_TX_INTERVAL` etc. are vacuous

**Severity:** P1. Cross-cite BUG-4/-5/-6. The entire inv→getdata→tx
flow for transactions is absent. hotbuns never issues `getdata` for
a tx; the only tx-flow is "peer pushes us a tx, we validate, we
relay it onward". On any of:
- peer announces inv but never sends the tx voluntarily,
- we want a tx because we need to fill a compact-block gap,
- we want a tx because we need an orphan parent,

hotbuns has no path. Compact blocks fall back to full-block
download (covered in W148). Orphans fall through `findChildrenOf`
which only retries from the already-stored pool — never asks any
peer to send the missing parent.

**File:** absence; no file implementing tx getdata.

**Core ref:** `bitcoin-core/src/node/txdownloadman_impl.cpp`
(TxRequestTracker — full request scheduler).

**Impact:** hotbuns relies on the receive-side push fully; works in
practice for normal mainnet operation (peers do push) but fails any
adversarial scenario where a peer advertises and then withholds.
Cross-impl divergence: every full-node impl ships the txrequest
scheduler.

---

## BUG-12 (P1) — filterload / filteradd / filterclear handlers absent

**Severity:** P1 (W134 carry-forward). Bitcoin Core's net_processing
handles BIP-37 filter messages at `net_processing.cpp:4964-5017`:
- `filterload`: reject + disconnect if NODE_BLOOM not advertised.
- `filteradd`: reject + disconnect if NODE_BLOOM not advertised.
- `filterclear`: reject + disconnect if NODE_BLOOM not advertised.

hotbuns has no handler for any of these. A peer sending `filterload`
to us when we have not advertised NODE_BLOOM gets silently dropped
(no misbehaving, no disconnect). When we DID advertise NODE_BLOOM
(via `--peerbloomfilters=1`), filterload is still silently dropped
because there's no handler at all.

**File:** `src/cli/cli.ts` and `src/p2p/manager.ts` — no
`onMessage("filterload", ...)` registration; the messages are parsed
into `NetworkMessage` but never handled.

**Core ref:** `bitcoin-core/src/net_processing.cpp:4964-5017`.

**Impact:** SPV peers cannot use hotbuns as a NODE_BLOOM provider
(broken BIP-37 service). When we advertise NODE_BLOOM we lie about
support. Cross-cite W103 BUG-4, W134 BUG-class.

---

## BUG-13 (P1) — No per-peer CBloomFilter applied to tx-relay output

**Severity:** P1 (W134 carry-forward). Core's
`tx_relay->m_bloom_filter` (`net_processing.cpp:6074`) gates tx-inv
output through `IsRelevantAndUpdate`:

```cpp
if (tx_relay->m_bloom_filter && !tx_relay->m_bloom_filter->IsRelevantAndUpdate(*txinfo.tx)) continue;
```

— SPV peers can request only matching txs.

hotbuns's `InventoryRelay.PeerRelayQueue` (`relay.ts:43-64`) has no
`bloomFilter` field. Even if a peer sent `filterload` (BUG-12 means
they couldn't), there's nowhere to store it.

**File:** `src/p2p/relay.ts:43-64`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:6074`.

**Impact:** cross-cite BUG-12.

---

## BUG-14 (P1) — getdata accepts up to MAX_INV_SZ=50000; should be MAX_GETDATA_SZ=1000

**Severity:** P1 (W103 BUG-3 carry-forward). Bitcoin Core's
`MAX_GETDATA_SZ=1000` (`net_processing.cpp:128`) is applied to inbound
getdata messages — peers sending more than 1000 items in one getdata
get `Misbehaving`. hotbuns's `deserializeInvPayload` at
`messages.ts:1091-1102` is shared between inv, getdata, and notfound
and applies a single `MAX_INV_SZ=50000` cap. A peer sending a
50000-item getdata is accepted, and `handleGetData` at `blocks.ts:1018-1032`
iterates all 50000, attempting to load each block from disk.

For block getdata, with each block up to 4MB that's 50000 × 4MB = 200GB
of disk reads enqueued per single getdata message. 50× DoS amplification.

**File:** `src/p2p/messages.ts:1091-1102` (shared deserialiser, no
per-message-type cap); `src/sync/blocks.ts:1018-1032` (no
size check on inbound getdata).

**Core ref:** `bitcoin-core/src/net_processing.cpp:128, 4131-4135`.

**Impact:** DoS-amplification path. A single 50000-item getdata for
blocks can saturate a hotbuns node's disk I/O for seconds.

---

## BUG-15 (P0-CDIV) — `peer.connType` always defaults to `"inbound"`; block-relay-only and feeler peers may send us tx messages with no rejection

**Severity:** P0-CDIV (Core safety invariant violated). Bitcoin Core's
`RejectIncomingTxs` (`net_processing.cpp:5598-5606`) is the gate that
prevents:
- block-relay-only outbound peers from sending us txs (privacy &
  protocol violation),
- feeler connections from sending us txs,
- `-blocksonly` mode peers without Relay permission from sending us
  txs.

When the check returns true, Core sets `pfrom.fDisconnect = true` and
returns immediately (no validation, no relay).

hotbuns has `peer.connType` (defined at `peer.ts:84` as
`"full_relay" | "block_relay" | "inbound" | "manual"`), and the
PeerManager DOES track per-key `connectionType` in
`peerConnectionType` (`manager.ts:1100`). But the peer-side field is
**never set from the manager**: the Peer constructor at
`manager.ts:1070, 1085, 2354` is called with only `(config, events, onBan)`
— no PeerOptions. The default at `peer.ts:346` is:

```ts
this.connType = options?.connType ?? "inbound";
```

So `peer.connType` is **always `"inbound"`** for every peer regardless
of whether it's actually outbound block-relay-only or feeler.

The tx-message handler at `cli.ts:1854-1888`:

```ts
peerManager.onMessage("tx", async (peer, msg) => {
  if (msg.type !== "tx") return;
  // IBD skip gate — mirrors Core net_processing.cpp:4395
  if (!blockSync.isIBDComplete()) return;
  const tx = msg.payload.tx;
  const result = await mempool.acceptToMemoryPool(tx);
  ...
});
```

— has NO `RejectIncomingTxs` analogue. A block-relay-only outbound peer
sending us a tx is silently accepted and relayed onward, **violating
the Core invariant that block-relay-only connections do not exchange
tx-relay traffic**.

**File:** `src/p2p/peer.ts:346`; `src/p2p/manager.ts:1070, 1085, 2354`
(constructor calls without PeerOptions); `src/cli/cli.ts:1854-1888`
(tx handler missing gate).

**Core ref:** `bitcoin-core/src/net_processing.cpp:5598-5606`
(`RejectIncomingTxs`), 4386-4390 (TX msg handler) and 4046-4084
(INV msg handler).

**Impact:**
- Privacy break: a block-relay-only peer using us as a side-channel
  to inject tx into our mempool can de-anonymise our wallet by
  observing which side of a tx we re-broadcast first (which we'd
  pick up via our own outbound trickle).
- Cross-impl divergence: Core peers expect block-relay-only conns
  to be silent on tx; if we send tx to such a peer (we don't track
  it, so we will), they may discourage us.
- Cross-cite W103 BUG-5, BUG-8.

---

## BUG-16 (P1) — Peer's VERSION `fRelay = false` parsed and stored but **never consumed**; we keep queuing tx invs to peers that asked for none

**Severity:** P1. Bitcoin Core's `fRelay=false` in a peer's VERSION
message signals "don't send me transactions" (BIP-37 / NODE_BLOOM
omission for outbound; explicit opt-out for inbound). Core's
`net_processing.cpp:3684-3700` initializes `tx_relay->m_relay_txs`
from `fRelay` and gates EVERY future `m_tx_inventory_to_send.insert`
on this flag (5993-5996: `if (!tx_relay->m_relay_txs)
tx_relay->m_tx_inventory_to_send.clear();`).

hotbuns parses `fRelay` at `messages.ts:1076` (in
`deserializeVersionPayload`), stores it on `peer.versionPayload.relay`
(`peer.ts:1236`), and has zero consumers in production code
(`grep -rn "versionPayload.relay" /home/work/hashhog/hotbuns/src/`
returns no consumers outside tests).

The relay-side `queueTxToAllFiltered` at `cli.ts:1867` and the RPC
`broadcastTxInv` at `rpc/server.ts:3507-3523` both iterate ALL
connected peers and queue/send the inv with no `peer.versionPayload.relay`
gate.

**File:** `src/p2p/peer.ts:163, 1236` (stored); no consumer.

**Core ref:** `bitcoin-core/src/net_processing.cpp:3684-3700`
(initializes `m_relay_txs` from fRelay); 5993-5996 (gate).

**Impact:**
- We send unwanted tx invs to peers that asked for none.
- Combined with BUG-15: a block-relay-only peer that sends VERSION
  with `fRelay=false` is doubly-violated: we send them tx invs AND
  we accept their tx pushes.
- "Dead-data plumbing" pattern, 3rd hotbuns instance this wave
  (cross-cite BUG-17, BUG-18).

---

## BUG-17 (P1) — `peer.recordTxReceived()` defined but never called; `lastTxTime` is dead-data

**Severity:** P1 ("dead-data plumbing" pattern). The Peer class
exposes `recordTxReceived()` at `peer.ts:1340-1345`:

```ts
recordTxReceived(): void {
  this.lastTxTime = Date.now();
}
```

A grep over `src/` shows **zero call sites** for this method. The
`lastTxTime` field is initialised to 0 (`peer.ts:351`) and never
updated. The only consumer is `rpc/server.ts:4391`:

```ts
last_transaction: peer.lastTxTime > 0 ? Math.floor(peer.lastTxTime / 1000) : 0,
```

— which always emits `0` for `getpeerinfo.last_transaction`.

Compounds with Core's `m_last_tx_time` (`net_processing.cpp:4452`) which
is used both for the RPC reporting AND for the stale-peer eviction
decisions in `EvictExtraOutboundPeers`. hotbuns doesn't have an
eviction policy that consumes this either, so it's dead at both
ends.

**File:** `src/p2p/peer.ts:191-192, 351, 1340-1345`; cli.ts tx
handler does NOT call `peer.recordTxReceived()`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:4452`.

**Impact:** `getpeerinfo.last_transaction` always reports 0; broken
monitoring contract. Combined with BUG-16 / BUG-18, three dead-data
plumbing instances in the tx-relay subsystem alone.

---

## BUG-18 (P1) — Entire ZMQ subsystem is **never instantiated**; `wireZMQNotifications` is dead-code; `--zmqpub*` flags are not parsed (W141 carry-forward)

**Severity:** P1 ("wiring-look-but-no-wire" pattern, fleet-wide).
`src/rpc/zmq.ts` defines a full `ZMQNotificationInterface` class
(line 101), publisher constructors, topic enumeration
(`hashblock`/`hashtx`/`rawblock`/`rawtx`/`sequence`), Core-parity
multipart message format, AND a `wireZMQNotifications` function at
line 354-384 that connects an EventEmitter to the publishers.

The hashtx per-tx fan-out is correctly coded at `zmq.ts:218-222`:

```ts
// hashtx for each transaction in block
for (const tx of block.transactions) {
  const txid = getTxId(tx);
  await this.publish("hashtx", txid);
}
```

— addressing W141's "hashtx per-tx fan-out missing on BlockConnected".

**However**, `cli.ts` and `index.ts` **never instantiate
`ZMQNotificationInterface` and never call `wireZMQNotifications`**.
`grep -rn "ZMQNotificationInterface\|wireZMQNotifications"
/home/work/hashhog/hotbuns/src/cli/cli.ts` returns nothing. The
`--zmqpubhashtx=tcp://...` and `--zmqpubhashblock=...` CLI flags are
not registered in `parseFlags`. The entire ZMQ subsystem is
orphaned.

So W141's "hashtx per-tx fan-out missing on BlockConnected" remains
substantively true even though the local fan-out code is correct:
no operator can ever activate the path.

**File:** `src/rpc/zmq.ts:101 (class), 218-222 (fan-out), 354-384
(wire)`; `src/cli/cli.ts` (no construction, no flag parse).

**Core ref:** `bitcoin-core/src/zmq/zmqnotificationinterface.cpp`
(constructed in init.cpp / kernel/chainstatemanager_opts setup).

**Impact:** W141 carry-forward — operator passing `--zmqpubhashtx`
gets no error (flag not recognised but silently ignored by the
permissive arg parser) and no ZMQ output. Cross-impl
divergence: every other hashhog impl exposes ZMQ via CLI.
Wiring-look-but-no-wire 5th hotbuns instance.

---

## BUG-19 (P1) — `reorgRefillUnchecked` admits txs with `fee=0n`, then `queueTxToAllFiltered` would drop them at feefilter; W150 BUG-10 cross-cite + tx-relay-extension

**Severity:** P1. W150 BUG-10 documented that
`mempool.ts::reorgRefillUnchecked` (lines 2546-2603) admits
disconnected txs with `fee = 0n, feeRate = 0` — bypassing
CheckTransaction, sigops, MoneyRange, fee-rate gates. The W150
analysis correctly identified the consensus / inflation primitives
opened. This W152 audit extends the finding to TX-RELAY:

`reorgRefillUnchecked` is called from `blocks.ts:2946` after a reorg.
The function admits txs directly to `this.entries` and does NOT call
the `notificationEmitter.emit("txAccepted", ...)` hook (compare to
`mempool.ts:2229` in `addTransaction`). So:

1. Reorg-refilled txs sit in mempool with `feeRate=0`.
2. They are NEVER announced to peers via inv (no
   `queueTxToAllFiltered` call path from `reorgRefillUnchecked`).
3. If a peer requests them via `mempool` (BIP-35), they would be
   included (via `getAllTxids()`) but invd with the broken
   `MSG_WITNESS_TX` type (BUG-9) so silently dropped by Core peers.

So reorg-refilled txs are **invisible to the rest of the network**
until they expire or are re-broadcast by the original sender.

**File:** `src/mempool/mempool.ts:2546-2603` (refill); no
post-refill relay call; `src/sync/blocks.ts:2941-2961` (caller).

**Core ref:** `bitcoin-core/src/validation.cpp` (`removeForBlock` +
`LimitMempoolSize`) leaves valid txs in mempool and Core then
re-announces them via the normal `m_tx_inventory_to_send` path
because the disconnect flow's "removeForReorg" call into
`PeerManagerImpl::RelayTransaction` reuses the standard relay.

**Impact:** post-reorg mempool desync between hotbuns and the
network. Combined with BUG-7/-8/-9, reorg-refilled txs are doubly
invisible.

---

## BUG-20 (P1) — `sendrawtransaction` calls `broadcastTxInv` synchronously, bypassing the inventory trickle

**Severity:** P1 (privacy + bandwidth). Bitcoin Core's
`sendrawtransaction` (RPC) calls `RelayTransaction` which queues
the tx in every peer's `m_tx_inventory_to_send` set (with the
known-set filter applied). The trickle then sends from each peer's
own Poisson-distributed timer, providing privacy through
indistinguishability between "I originated this tx" and "I relayed
this tx".

hotbuns's `RPCServer.broadcastTxInv` at `server.ts:3507-3523`:

```ts
private broadcastTxInv(txid: Buffer): void {
  for (const peer of this.peerManager.getConnectedPeers()) {
    const invType = peer.wtxidRelay ? InvType.MSG_WTX : InvType.MSG_TX;
    const invMsg: NetworkMessage = {
      type: "inv",
      payload: {
        inventory: [{ type: invType, hash: txid }],
      },
    };
    peer.send(invMsg);
  }
}
```

— issues an immediate `inv` to every connected peer in one tick. No
Poisson delay, no per-peer trickle, no known-set filter, no fee-filter
check. (Note: this path DOES correctly use `peer.wtxidRelay` —
contradicting the relay-side comment-as-confession at cli.ts:1958.)

**Privacy impact**: the immediate cross-peer broadcast leaks the
"origin peer" — every connected peer sees the inv at the same wall
clock time T. Real propagated invs arrive with Poisson jitter. A
network observer monitoring multiple peers can identify the origin
node from the synchronised T+0 burst.

**Bandwidth impact**: a tx is invd in 1 inv per peer (not amortised
into a batched inv as the trickle would do).

**File:** `src/rpc/server.ts:3245-3289, 3491, 3507-3523`.

**Core ref:** `bitcoin-core/src/net.cpp` /
`bitcoin-core/src/net_processing.cpp::InitiateTxBroadcastToAll`
(queue + trickle, no immediate broadcast).

**Impact:** sendrawtransaction privacy is broken vs Core; cross-impl
divergence in propagation timing observable from outside.

---

## BUG-21 (P1) — IBD-state inconsistency: `tx`-msg handler uses `blockSync.isIBDComplete()`, but other paths (BUG-7 G15 BIP-35) have no such gate

**Severity:** P1. Core's `IsInitialBlockDownload` is the canonical
gate for ALL tx-relay-related processing: tx msg handler
(`net_processing.cpp:4395`), inv tx handler (4088), BIP-35 mempool
response (also gated).

hotbuns's tx msg handler at `cli.ts:1857` correctly checks
`blockSync.isIBDComplete()`. But:
- The BIP-35 mempool handler at `cli.ts:1947-1971` has NO IBD gate.
  A peer requesting our mempool during IBD gets a (likely empty,
  but maybe non-empty if a `sendrawtransaction` injected) response.
- The orphan pool admission at `cli.ts:1879` has NO IBD gate;
  combined with the tx handler's IBD gate, the orphan branch is
  vacuous during IBD (the tx handler returns before reaching it).
- `processOrphanCascade` at `cli.ts:1814` (block-connect hook) and
  1873 (tx-admit hook) has NO IBD gate; during catch-up after IBD
  exits, the cascade can fire with stale entries.

**File:** `src/cli/cli.ts:1857` (gated), 1947 (ungated), 1814/1873
(ungated cascade).

**Core ref:** `bitcoin-core/src/net_processing.cpp:4088, 4395`.

**Impact:** inconsistent IBD-gating across tx-relay code paths;
asymmetric defensive depth.

---

## BUG-22 (P1) — `findChildrenOf` is O(byPrevout.size) per parent; cascades cost O(block_tx_count × byPrevout.size) per block

**Severity:** P1 (perf). `OrphanPool::findChildrenOf` at
`orphan_pool.ts:312-328`:

```ts
findChildrenOf(parentTxid: Buffer): OrphanEntry[] {
  const parentHex = parentTxid.toString("hex");
  const out: OrphanEntry[] = [];
  const seen = new Set<string>();
  for (const [key, set] of this.byPrevout) {
    const colon = key.indexOf(":");
    if (colon === -1) continue;
    if (key.slice(0, colon) !== parentHex) continue;
    ...
  }
  return out;
}
```

— iterates EVERY entry in `byPrevout` (up to MAX_ORPHAN_TX × avg_inputs
≈ 100 × 2 = 200 entries) for each parent txid. Then `cli.ts:1814`
calls `block.transactions.map((tx) => processOrphanCascade(tx))` and
each `processOrphanCascade` calls `onParentAdmitted(parent)` → `findChildrenOf`.
For a 3000-tx mainnet block, that's 3000 × 200 = 600,000 string
prefix comparisons per block. Within budget on modern CPUs but
unnecessary — Core uses `m_outpoint_to_orphan_it` for O(1) lookup.

**File:** `src/mempool/orphan_pool.ts:312-328`; `src/cli/cli.ts:1814`.

**Core ref:** `bitcoin-core/src/node/txorphanage.cpp` —
`m_outpoint_to_orphan_wtxids` (multimap-equivalent) gives O(1)
per-outpoint lookup.

**Impact:** mild perf regression on busy blocks. The right fix is an
explicit `byParentTxid: Map<string, Set<string>>` reverse-index.

---

## BUG-23 (P1) — Inventory `nextFlushTime` initialised with Poisson delay BEFORE handshake completes; potential premature flush

**Severity:** P1. `InventoryRelay.addPeer` at `relay.ts:96-117`:

```ts
const queue: PeerRelayQueue = {
  peer,
  isInbound,
  wtxidRelay,
  pendingTxs: new Set(),
  nextFlushTime: Date.now() + this.poissonDelay(interval),
  timer: null,
};
this.queues.set(key, queue);
this.scheduleFlush(queue);  // timer starts immediately
```

— sets `nextFlushTime = Date.now() + Poisson(interval)` and schedules
a flush immediately. The single call site at `cli.ts:1832-1834` fires
on `__connect__` which IS post-handshake (`manager.ts:1862-1891`), so
de-facto OK today. But there's no defensive check that the peer is
in `connected` state; a future refactor that fires `addPeer` from
`onConnect` (pre-handshake) would start invs being queued/flushed
before VERACK.

Core defends against this with the `m_next_inv_send_time == 0s`
sentinel (`net_processing.cpp:2257`) — invs are skipped until
`m_next_inv_send_time` is initialised non-zero, which happens only
after the relay-setup gating.

**File:** `src/p2p/relay.ts:107-117`; `src/cli/cli.ts:1832-1834`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:2257`.

**Impact:** latent — works today by virtue of caller discipline.
Defensive depth gap.

---

## BUG-24 (P1) — `queueTx`/`queueTxFiltered`/`queueTxToAll` silently no-op if peer not registered

**Severity:** P1. `InventoryRelay.queueTx(peer, txid)` at
`relay.ts:144-151`:

```ts
queueTx(peer: Peer, txid: string): void {
  const key = `${peer.host}:${peer.port}`;
  const queue = this.queues.get(key);

  if (queue) {
    queue.pendingTxs.add(txid);
  }
}
```

— if the queue doesn't exist for the peer (e.g., the peer disconnected
between the txAccepted event and the queue lookup, or `addPeer` was
never called), the tx is silently dropped without log or error.
Same shape in `queueTxToAll` at 183-187 (the iteration only sees
registered queues; peers connected but not registered are skipped).

Cross-cite BUG-23: if a peer connects but `addPeer` is fired
asynchronously from `__connect__` and the txAccept races, the first
few txs are lost.

Core has no equivalent silent-drop because the `tx_relay` is created
inline with `InitializeNode` and consulted under the same lock as
peer creation.

**File:** `src/p2p/relay.ts:144-207`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:2266-2275`
(`InitiateTxBroadcastPrivate` — explicit "already scheduled" log
on the no-op path).

**Impact:** very low; observation-only divergence.

---

## Summary

**Bug count:** 24 (BUG-1 through BUG-24).

**Severity distribution:**
- **P0-CDIV:** 4 (BUG-7, BUG-8, BUG-9, BUG-15)
- **P1:** 20 (BUG-1, BUG-2, BUG-3, BUG-4, BUG-5, BUG-6, BUG-10,
  BUG-11, BUG-12, BUG-13, BUG-14, BUG-16, BUG-17, BUG-18, BUG-19,
  BUG-20, BUG-21, BUG-22, BUG-23, BUG-24)

(Total: 4 + 20 = 24 ✓)

**Fleet patterns confirmed:**
- **"comment-as-confession" 8th hotbuns instance** (W142-W152
  tracking):
  - BUG-1 at `orphan_pool.ts:270-272` ("Core also evicts orphans
    whose inputs are now spent ... but for this simplified port we
    just remove orphans that themselves got mined")
  - BUG-9 at `cli.ts:1955-1962` ("hotbuns does not yet track per-peer
    wtxidrelay state" — false; the state IS tracked via peer.wtxidRelay)
- **"dead-data plumbing" pattern 3rd hotbuns instance this wave**:
  - BUG-16: `peer.versionPayload.relay` parsed + stored, zero consumers
  - BUG-17: `peer.recordTxReceived()` defined, zero call sites;
    `lastTxTime` is read but always 0
  - BUG-18: `wireZMQNotifications`/`ZMQNotificationInterface` defined
    and exported, zero instantiations
- **"wiring-look-but-no-wire" pattern 5th hotbuns instance** (BUG-18):
  CLI flags not parsed AND constructor not invoked AND wire function
  not called.
- **"two-pipeline guard" 17th distinct fleet extension** (BUG-7 vs
  BUG-20): RPC `broadcastTxInv` correctly uses `peer.wtxidRelay`
  LIVE; `InventoryRelay` flush uses a frozen `queue.wtxidRelay`
  defaulting to false. Two paths with the same goal, diverging on
  wtxidrelay tracking.
- **"asymmetric defensive depth" 4th hotbuns instance** (BUG-21):
  tx-msg handler has IBD gate, BIP-35 mempool handler does not.
- **"comparator default-value swallows the contract"** (BUG-7):
  `addPeer(peer, isInbound=false, wtxidRelay=false)` default-false
  swallows the BIP-339 contract; caller passes only 2 args, contract
  is wrong forever.
- **"frozen-at-init state vs live-at-use state"** (BUG-7 vs feefilter
  reading `queue.peer.feeFilterReceived` at `relay.ts:201` live):
  ASYMMETRIC inside the same struct — wtxidRelay is frozen, feeFilter
  is live; design contradiction.

**Carry-forwards confirmed STILL UNFIXED:**
- W103 BUG-3 (MAX_GETDATA_SZ=50000) → BUG-14
- W103 BUG-5 (block-relay-only tx accept) → BUG-15
- W103 BUG-7/-8/-9/-10/-11/-12/-16 (TxRequestTracker absence) → BUG-4/-5/-6/-11
- W103 BUG-13 (AddKnownTx) → BUG-10
- W103 BUG-14 (MSG_WITNESS_TX in relay) → resolved at relay.ts:356
  via the BUG-7 path, but BUG-9 carries it forward in BIP-35
- W134 (NODE_BLOOM filterload/filteradd/filterclear handlers) → BUG-12, BUG-13
- W141 (hashtx per-tx fan-out missing on BlockConnected) → BUG-18
  (hashtx fan-out IS coded; but the entire ZMQ subsystem is never
  instantiated, so the carry-forward stands substantively)
- W150 BUG-10 (reorgRefillUnchecked admits with fee=0, no validation) → BUG-19
- W144 BUG-3 (scriptFlagsFromBitmask wrong source) — does NOT
  intersect tx-relay paths directly; carried forward in W144's own
  domain.
- W145 BUG-2..6 (Assume-valid scope creep) — does NOT intersect
  tx-relay paths directly; carried forward in W145's own domain.

**Top three findings:**
1. **BUG-7 (P0-CDIV: BIP-339 wtxid-relay broken end-to-end)** —
   `InventoryRelay.addPeer(peer, true)` at `cli.ts:1833` lets
   `wtxidRelay` default to `false`, then `queue.wtxidRelay` is read
   at flush time (`relay.ts:356`). EVERY relay-trickled tx inv goes
   as MSG_TX regardless of BIP-339 negotiation. **Core peers that
   negotiated wtxidrelay explicitly DROP MSG_TX inv (`net_processing.cpp:4059-4063`)**,
   so hotbuns's relay-trickled tx invs are silently discarded by
   every Core peer that signalled wtxidrelay. Mempool propagation to
   modern peers is broken. Compounds with BUG-8 (the hash queued is
   txid, not wtxid — fixing BUG-7 alone activates BUG-8 latently).
2. **BUG-15 (P0-CDIV: `peer.connType` always defaults to "inbound";
   no RejectIncomingTxs gate)** — the Peer constructor at
   `manager.ts:1070/1085/2354` is never called with PeerOptions, so
   `peer.connType` defaults to `"inbound"` for every peer. The
   tx-msg handler at `cli.ts:1854-1888` has no connection-type gate.
   Block-relay-only outbound peers can send us tx and we accept +
   relay onward, violating Core's `RejectIncomingTxs` invariant. The
   underlying `peerManager.peerConnectionType` map at `manager.ts:1100`
   DOES track the right value — but the Peer object never sees it.
3. **BUG-9 (P0-CDIV: BIP-35 mempool inv uses `MSG_WITNESS_TX`,
   a BIP-144 getdata flag NOT a valid inv type)** — at `cli.ts:1966`
   every BIP-35 mempool response item is emitted with
   `type = InvType.MSG_WITNESS_TX = 0x40000001`. Core's inv handler
   (`net_processing.cpp:4079-4094`) does not recognise this as a
   tx-class inv (`IsGenTxMsg` returns false) and discards it with a
   debug log. **Every BIP-35 `mempool` request from a Core peer
   gets a response with zero usable inv entries**. The comment at
   `cli.ts:1955-1962` is a comment-as-confession admitting the bug.
