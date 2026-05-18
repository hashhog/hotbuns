# W153 — Mempool eviction + tx-removed signals + min-relay fee (hotbuns)

**Wave:** W153 — `TrimToSize`, `GetMinFee`, `RemoveStaged`, rolling-fee
decay, `MemPoolRemovalReason{EXPIRY,SIZELIMIT,REORG,BLOCK,CONFLICT,REPLACED}`,
`DEFAULT_MAX_MEMPOOL_SIZE_MB=300`, `DEFAULT_MEMPOOL_EXPIRY_HOURS=336`,
`DEFAULT_MIN_RELAY_TX_FEE=1000`, `DEFAULT_INCREMENTAL_RELAY_FEE=1000`,
`ROLLING_FEE_HALFLIFE=12h`, `MaybeUpdateMempoolForReorg`, removed-signal
fan-out (fee estimator + ZMQ + REST + tx-relay), `BlockConnected` /
`BlockDisconnected`, `prioritisetransaction` RPC.

**Scope:** discovery only — no production code changes.

**Bitcoin Core references**
- `bitcoin-core/src/txmempool.h:212` — `ROLLING_FEE_HALFLIFE = 60 * 60 * 12`
  (12 h; halved when usage < sizelimit/2, quartered when < sizelimit/4).
- `bitcoin-core/src/txmempool.cpp:405-431` — `removeForBlock` builds
  `txs_removed_for_block`, calls `removeUnchecked(it, MemPoolRemovalReason::BLOCK)`
  for each confirmed tx, then fires
  `m_opts.signals->MempoolTransactionsRemovedForBlock(...)`.
- `bitcoin-core/src/txmempool.cpp:778-782` — `DynamicMemoryUsage()`:
  `memusage::MallocUsage(sizeof(CTxMemPoolEntry) + 9 * sizeof(void*)) * mapTx.size() + … + cachedInnerUsage` —
  **NOT** vsize-equivalent; includes per-entry overhead (~9 pointers per
  multi_index + entry struct + index allocations).
- `bitcoin-core/src/txmempool.cpp:811-827` — `Expire(time)`: collects
  iterators with `entry_time < time`, expands via
  `CalculateDescendants`, calls
  `RemoveStaged(stage, MemPoolRemovalReason::EXPIRY)`.
- `bitcoin-core/src/txmempool.cpp:829-851` — `GetMinFee(sizelimit)`:
  rolling decay with 12 h half-life, scaled to ÷2 below half-full, ÷4
  below quarter-full; clears to 0 below `incremental_relay_feerate/2`;
  returns `max(rate, incremental_relay_feerate)`.
- `bitcoin-core/src/txmempool.cpp:853-859` — `trackPackageRemoved(rate)`:
  bumps `rollingMinimumFeeRate` and clears `blockSinceLastRollingFeeBump`.
- `bitcoin-core/src/txmempool.cpp:861-911` — `TrimToSize(sizelimit, *pvNoSpendsRemaining)`:
  while `DynamicMemoryUsage() > sizelimit`, evicts the **worst chunk**
  (lowest-feerate chunk in the cluster linearization) atomically with
  `MemPoolRemovalReason::SIZELIMIT`, adds the chunk's feerate +
  `incremental_relay_feerate` into `trackPackageRemoved`, and surfaces
  inputs that no longer have a spender so the caller can decide whether
  to evict the parents too.
- `bitcoin-core/src/kernel/mempool_options.h` —
  `DEFAULT_MAX_MEMPOOL_SIZE_MB = 300`,
  `DEFAULT_MEMPOOL_EXPIRY_HOURS = 336`,
  `DEFAULT_INCREMENTAL_RELAY_FEE = 1000 sat/kvB`.
- `bitcoin-core/src/policy/policy.h:48` —
  `DEFAULT_INCREMENTAL_RELAY_FEE{1000}` sat/kvB (= 1 sat/vB, not 0.1).
- `bitcoin-core/src/policy/settings.cpp` /
  `bitcoin-core/src/policy/feerate.h` —
  `DEFAULT_MIN_RELAY_TX_FEE = 1000` sat/kvB (= 1 sat/vB).
- `bitcoin-core/src/kernel/mempool_removal_reason.h:13-20` — enum
  `MemPoolRemovalReason{EXPIRY,SIZELIMIT,REORG,BLOCK,CONFLICT,REPLACED}`.
- `bitcoin-core/src/validation.cpp::MaybeUpdateMempoolForReorg` —
  disconnect-side: drops every tx that's no longer policy-valid against
  the new tip; per-tx revalidation through ATMP-equivalent path.
- `bitcoin-core/src/policy/fees/block_policy_estimator.h:207-216` —
  `processBlock(txs_removed_for_block, nBlockHeight)` /
  `processTransaction(NewMempoolTransactionInfo)` /
  `removeTx(Txid hash)` — the fee estimator's mempool integration API.
- `bitcoin-core/src/rpc/mempool.cpp::prioritisetransaction` — three-arg
  RPC: txid, dummy fee delta (ignored), fee delta (added to entry's
  `nFeeDelta`); persists to disk; survives restart via `mempool.dat`
  `mapDeltas` section.
- `bitcoin-core/src/init.cpp` — operator knobs `-maxmempool=<MB>`,
  `-mempoolexpiry=<hours>`, `-minrelaytxfee=<BTC/kvB>`,
  `-incrementalrelayfee=<BTC/kvB>`, `-mempoolfullrbf=<0|1>`,
  `-dustrelayfee=<BTC/kvB>`, `-datacarrier`, `-permitbaremultisig`.
- `bitcoin-core/src/zmq/zmqpublishnotifier.cpp` — hashtx fired per
  removed tx on `MempoolTransactionsRemovedForBlock` AND on the per-tx
  `TransactionRemovedFromMempool` signal.

**Files audited**
- `src/mempool/mempool.ts` — `Mempool` class, `MempoolEntry`, `evict()`
  (line 3299), `getMinFee()` (3243), `trackPackageRemoved()` (3217),
  `expire()` (3173), `removeForBlock()` (2332), `removeTransaction()`
  (2241), `removeTransactionInternal()` (3055), `readdTransactions()`
  (2487), `reorgRefillUnchecked()` (2546), `setMinFeeRate()` (3389),
  `setIncrementalRelayFee()` (3414), `setNotificationEmitter()` (1241),
  `getMinFeeRateKvB()` (3402), `getInfo()` (3374),
  `DEFAULT_MAX_SIZE=300_000_000` (546), `MEMPOOL_EXPIRY_SECONDS=336*60*60`
  (553), `ROLLING_FEE_HALFLIFE=12h` (562), `DEFAULT_MIN_FEE_RATE=0`
  (568), `DEFAULT_INCREMENTAL_RELAY_FEE=0.1` (576).
- `src/mempool/persist.ts` — `loadMempool`, `dumpMempool`,
  `MEMPOOL_DUMP_VERSION=2`, `mapDeltas` section.
- `src/rpc/zmq.ts` — `ZMQNotificationInterface`, `parseZMQArgs`,
  `wireZMQNotifications`, `notifyBlock`, `notifyBlockDisconnect`,
  `notifyTransactionAcceptance`, `notifyTransactionRemoval`,
  `SequenceLabel` (A/R/C/D).
- `src/cli/cli.ts` — `Mempool` instantiation (line 1541), notification
  emitter wiring (1787-1789), `feeEstimator.processBlock` site (1810),
  `feeEstimator.trackTransaction` (1872), `txRelay.queueTxToAllFiltered`
  (1867, 1911), arg parser (330-595, no `-maxmempool` / `-minrelaytxfee`
  / `-mempoolexpiry` / `-incrementalrelayfee` / `-zmqpub*` /
  `-alertnotify` / `-blocknotify` / `-walletnotify` / `-dustrelayfee` /
  `-prioritisetransaction`).
- `src/chain/state.ts` — `connectBlock` (line 423-473) emits
  `blockConnected` via `notificationEmitter`, calls `mempool.removeForBlock`;
  `disconnectBlock` (485-769) emits `blockDisconnected` but does NOT call
  `mempool.readd*` or trigger refill; `updateTip` (897-899) is bare
  setter — no emit; `reorganize` (779-817) walks disconnect/connect
  without mempool refill.
- `src/sync/blocks.ts` — `connectBlock` calls `chainStateManager.updateTip`
  (line 2863) but NOT `chainStateManager.connectBlock`, so the
  `blockConnected` event NEVER fires during the IBD / normal sync path;
  `removeForBlock` called directly (2895-2905); `readdTransactions` /
  `reorgRefillUnchecked` called only here (2941-2960).
- `src/rpc/server.ts` — `getMempoolInfo` (3548-3571) HARDCODES
  `maxmempool=300_000_000`, `minrelaytxfee=0.00001`,
  `incrementalrelayfee=0.00001`; `unbroadcastcount=0`; no
  `prioritisetransaction` registration.
- `src/rpc/rest.ts` — `handleMempool` (812-871) HARDCODES
  `maxmempool=300000000` and `minrelaytxfee=0.00001` for `/rest/mempool/info`.
- `src/fees/estimator.ts` — `processBlock(block, height)` (327-368):
  loops over `block.transactions`, queries `mempool.getTransaction(txid)`
  AFTER the block has been processed; no `removeTx(hash)` hook.
- `src/p2p/manager.ts` — `FeeFilterManager` instantiated (line 492);
  `feeFilterInterval = null` (411, 495) — **never set to any interval**.
- `src/p2p/relay.ts` — `InventoryRelay`: `addPeer`, `removePeer`,
  `queueTx`, `queueTxFiltered`, `queueTxToAll`, `queueTxToAllFiltered`
  — no `removeTx` / `forgetTx` to drop evicted txs from pending INV
  queues.

---

## Gate matrix (33 sub-gates / 9 behaviours)

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 1 | DEFAULT_MAX_MEMPOOL_SIZE_MB=300 enforcement | G1: maxSize default value | PARTIAL — `DEFAULT_MAX_SIZE=300_000_000` (mempool.ts:546) is in **vbytes**, not bytes of `DynamicMemoryUsage`; effective ceiling differs from Core (BUG-1) |
| 1 | … | G2: TrimToSize/evict fires when DynamicMemoryUsage > sizelimit | PARTIAL — `evict()` (3299) fires when `currentSize > maxSize`; `currentSize` is sum-of-vsize, not DynamicMemoryUsage (BUG-1) |
| 1 | … | G3: TrimToSize evicts entire worst-chunk atomically | PASS (mempool.ts:3305-3358; iterates cluster linearizations, picks tail-chunk, removes all txids in chunk) |
| 1 | … | G4: TrimToSize bumps rollingMinimumFeeRate via trackPackageRemoved(chunk_fee + incrementalRelayFee) | PASS (3330-3340) |
| 1 | … | G5: TrimToSize triggered from BOTH addTx AND reorgRefill paths | **BUG-2 (P0-CDIV)** — `evict()` is only called from `addTransaction` (line 2222); `reorgRefillUnchecked` (2546-2603) appends entries directly without calling `evict()`, so a deep reorg can push `currentSize` arbitrarily over `maxSize` |
| 1 | … | G6: TrimToSize triggered post-block-connect | **BUG-3 (P1)** — Core triggers prune+expire+trim from `LimitMempoolSize` on every connect; hotbuns has no equivalent — `removeForBlock` does NOT call `evict()`, so a block-connect that doesn't push past `maxSize` keeps stale low-fee txs forever |
| 2 | DEFAULT_MEMPOOL_EXPIRY_HOURS=336 enforcement | G7: MEMPOOL_EXPIRY_SECONDS=14d constant | PASS (mempool.ts:553) |
| 2 | … | G8: expire() called periodically or on block-connect | **BUG-4 (P0-CDIV)** — `Mempool.expire()` (3173) is **never invoked** from production code paths (grep `mempool.expire(` returns zero non-test hits); cli.ts wires `orphanPool.expireOldOrphans()` (1801) but the mempool `Mempool.expire()` is **dead code**. The 14-day expiry is unenforced |
| 3 | DEFAULT_MIN_RELAY_TX_FEE=1000 (1 sat/vB) enforcement | G9: minFeeRate default = 1 sat/vB | **BUG-5 (P0-CDIV)** — `DEFAULT_MIN_FEE_RATE = 0` (mempool.ts:568); a fresh node accepts every 1-satoshi-fee tx; Core's `DEFAULT_MIN_RELAY_TX_FEE = 1000 sat/kvB = 1 sat/vB` |
| 3 | … | G10: `-minrelaytxfee` CLI flag | **BUG-5 cross-cite** — no CLI parse for `--minrelaytxfee` / `--min-relay-tx-fee` (cli.ts:330-595); operator cannot raise the floor |
| 3 | … | G11: setMinFeeRate called from cli at startup | **BUG-5 cross-cite** — `mempool.setMinFeeRate` exists (3389) but no caller invokes it from cli.ts |
| 4 | DEFAULT_INCREMENTAL_RELAY_FEE=1000 (1 sat/vB) enforcement | G12: incrementalRelayFee default value | **BUG-6 (P0-CDIV)** — `DEFAULT_INCREMENTAL_RELAY_FEE = 0.1` sat/vB (mempool.ts:576) = 100 sat/kvB; Core: `1000 sat/kvB = 1 sat/vB`. **10× too low** |
| 4 | … | G13: `-incrementalrelayfee` CLI flag | **BUG-6 cross-cite** — no CLI parse; operator cannot override |
| 4 | … | G14: incrementalRelayFee used in RBF Rule #4 (`fee_delta >= incRelayFee * newVsize`) | PASS (mempool.ts:1877-1881) — uses correct sat/vB direct multiplication but at the wrong default constant |
| 5 | rolling-fee decay (ROLLING_FEE_HALFLIFE=12h) | G15: halflife constant | PASS (mempool.ts:562) |
| 5 | … | G16: halflife /= 4 when `currentSize < maxSize/4` | PARTIAL — implemented (3253-3254) but `currentSize` (vsize) vs `maxSize` (vsize) gives a different effective threshold than Core's `DynamicMemoryUsage` (BUG-1) |
| 5 | … | G17: halflife /= 2 when `currentSize < maxSize/2` | PARTIAL (same root cause, line 3255-3256) |
| 5 | … | G18: rate clamps to 0 below incrementalRelayFee/2 | PASS (3267-3271) |
| 5 | … | G19: return = `max(rolling, incrementalRelayFee_kvB)` | PASS (3274-3277) |
| 6 | MemPoolRemovalReason{6 variants} | G20: enum / reason argument exists | **BUG-7 (P0-CDIV)** — hotbuns has NO `MemPoolRemovalReason` enum, NO `reason` argument on `removeTransaction` / `removeTransactionInternal` / `removeForBlock`. Every removal-path is reasonless |
| 6 | … | G21: emit reason via ZMQ sequence label / hashtx | **BUG-7 cross-cite** — `txRemoved` event (mempool.ts:2316) carries `(txid, seq)` only; the ZMQ sequence label is hardcoded "R" (zmq.ts:32, 254-260) — no per-removal reason. Core's sequence body has the reason byte at offset 32 |
| 6 | … | G22: fee estimator distinguishes BLOCK vs SIZELIMIT vs REPLACED | **BUG-7 cross-cite** — `feeEstimator.processBlock` (estimator.ts:327) takes the block as-is, no per-tx reason from the mempool side |
| 7 | removed-signal fan-out | G23: fee estimator `removeTx` hook | **BUG-8 (P0-CDIV)** — `FeeEstimator` has NO `removeTx(hash)` method; when mempool evicts via SIZELIMIT / EXPIRY / CONFLICT / REPLACED, the estimator's `txEntryHeights` map continues to track them, polluting confirmation-time averages with txs that never confirmed |
| 7 | … | G24: ZMQ hashtx fan-out on BlockConnected | **BUG-9 (P0-WIRING)** — `notifyBlock` (zmq.ts:206-223) DOES iterate `block.transactions` and emit `hashtx` per tx — but ZMQ subsystem is **never instantiated in cli.ts** (verified: tests w141_zmq_rest_notify.test.ts:191-195 ASSERT `cli.ts` never contains `new ZMQNotificationInterface`). W141 + W152 BUG-18 carry-forward |
| 7 | … | G25: REST `/rest/tx/notifications` long-poll endpoint | **BUG-10 (P1)** — no `/rest/tx/notifications` or equivalent in `rest.ts`; Core exposes `headers` long-poll via `rest_headers`; hotbuns is read-only |
| 7 | … | G26: tx-relay drops evicted txs from pending INV queues | **BUG-11 (P0-CDIV)** — `InventoryRelay` (relay.ts:73) has no `removeTx` / `forgetTx`; once `queueTxToAllFiltered(txidHex, …)` (cli.ts:1867) queues a txid, INV is sent even after the tx was evicted by `evict()`. Peers then `getdata` a tx we no longer have → we either ignore the request (timeout) or respond `notfound` (W152 BUG-13/14) |
| 8 | BlockConnected / BlockDisconnected MaybeUpdateMempoolForReorg | G27: BlockConnected event emitted from BOTH chain/state.ts AND sync/blocks.ts | **BUG-12 (P0-CDIV)** — `chain/state.ts::connectBlock` (line 471) emits `blockConnected`; `sync/blocks.ts::connectBlock` (the IBD / normal sync path) NEVER emits `blockConnected` — it only calls `chainStateManager.updateTip` (2863) which is a bare setter. During IBD and normal post-IBD block reception, `feeEstimator.processBlock`, `orphanPool.eraseForBlock`, `orphanPool.expireOldOrphans`, and ZMQ hashblock/rawblock/hashtx fan-out NEVER FIRE |
| 8 | … | G28: chain/state.ts reorganize() refills mempool with disconnected txs | **BUG-13 (P0-CDIV)** — `reorganize()` (state.ts:779-817) walks disconnect/connect but does NOT call `mempool.readdTransactions` or `mempool.reorgRefillUnchecked`; only the BlockSync.connectBlock path refills (sync/blocks.ts:2941-2960). `invalidateblock` RPC, `generateblock` regtest, and `dumptxoutset` rollback are all stuck at Pattern B1 "no refill at all" |
| 8 | … | G29: revalidation against new tip's policy | PARTIAL — `readdTransactions` (mempool.ts:2487-2505) re-runs `addTransaction` (full validation); `reorgRefillUnchecked` (2546-2603) bypasses all checks (W150 BUG-10 carry-forward verified — fee=0n, feeRate=0, sigOpCost=0, ancestorCount=1 sentinel values) |
| 9 | prioritisetransaction RPC | G30: RPC method registered | **BUG-14 (P0-CDIV)** — no `prioritisetransaction` method in `rpc/server.ts` (verified via grep); `mempool.dat` `mapDeltas` section (persist.ts:78, 88) exists per the file format but is **read but never modified** — no production code path adds entries to it |
| 9 | … | G31: nFeeDelta surfaced in getmempoolentry / getrawmempool | PARTIAL — `modifiedfee` field returned (server.ts:3599) but always equals `fee` because no delta API exists |
| — | unrelated-but-cited | G32: feefilter periodic broadcast | **BUG-15 (P0-CDIV)** — `feeFilterInterval` declared null (manager.ts:411, 495) but **never set to an interval**. `FeeFilterManager.maybeSendFeeFilter` (feefilter.ts:121) is never invoked in production. BIP-133 feefilter to peers is **dead**. Mempool's `getMinFeeRateKvB()` (3402) is therefore never observed by peers |
| — | unrelated-but-cited | G33: removeForBlock emits per-tx removal signals for confirmed txs | **BUG-16 (P0-CDIV)** — `removeForBlock` (mempool.ts:2336-2356) directly mutates `entries / outpointIndex / currentSize` for confirmed txs WITHOUT going through `removeTransactionInternal` / `removeTransaction`, so the `txRemoved` event is NOT emitted for confirmed txs. Only conflicts get the event (via line 2375-2378). ZMQ sequence label "R" never fires for the typical case of "tx in mempool got mined" |

---

## BUG-1 (P0-CDIV) — `maxSize` is interpreted as vbytes instead of `DynamicMemoryUsage` bytes

**Severity:** P0-CDIV. Bitcoin Core's `DEFAULT_MAX_MEMPOOL_SIZE_MB = 300`
is enforced against `DynamicMemoryUsage()` which sums
`MallocUsage(sizeof(CTxMemPoolEntry) + 9 * sizeof(void*)) * mapTx.size()`
plus inner allocations for `mapNextTx`, `mapDeltas`, `txns_randomized`,
the txgraph, and the entry's own dynamic storage
(`bitcoin-core/src/txmempool.cpp:778-782`). For a typical mempool of
~150K entries this works out to ~300 MB RAM at the operator-visible
300 MB budget.

hotbuns's `Mempool.currentSize` (mempool.ts:1139, 1220) is the **sum of
`MempoolEntry.vsize`** — a tx's virtual byte count, not RAM occupancy.
A typical 2-in-2-out segwit tx has vsize ≈ 142 vB; the corresponding
in-memory `MempoolEntry` object holds the full `Transaction` (≈250 B
serialized + JS object overhead), the txid Buffer, the wtxid Buffer,
`spentBy/dependsOn` Sets, ancestor/descendant counters, cluster pointer,
ephemeral-dust pointer, etc. — easily 600-1000 bytes JS-side per entry,
plus V8 heap overhead.

At `maxSize = 300_000_000` vbytes, hotbuns admits ~2 M entries (300M /
142) before evicting. RAM usage at that point is ~1.5 GB conservatively.
The fleet-wide `300 MB` operator expectation is silently a `~1.5 GB`
operator surprise on hotbuns.

Compounding: the `getMinFee()` halflife scaling (mempool.ts:3253-3257)
compares `this.currentSize < this.maxSize / 4` and `< this.maxSize / 2`
— both using the same units. So the halflife-quarter and halflife-half
thresholds fire at much higher fill rates than Core, delaying rolling-min
decay.

**File:** `src/mempool/mempool.ts:546, 1139, 1220, 2221, 3253-3256, 3305`.

**Core ref:** `bitcoin-core/src/txmempool.cpp:778-782`
(`DynamicMemoryUsage`); `bitcoin-core/src/kernel/mempool_options.h`
(`DEFAULT_MAX_MEMPOOL_SIZE_MB = 300`).

**Excerpt (hotbuns, unit confusion)**
```ts
// mempool.ts:546
const DEFAULT_MAX_SIZE = 300_000_000;     // interpreted as bytes downstream

// mempool.ts:1136-1139
private maxSize: number;
private currentSize: number;              // sum of MempoolEntry.vsize

// mempool.ts:2220-2223
if (this.currentSize > this.maxSize) {    // vbytes > "bytes"
  this.evict();
}
```

**Impact:**
- **Operator surprise**: a hotbuns node with no `-maxmempool` knob and
  default `DEFAULT_MAX_SIZE` will consume ~5× the RAM that a Core node
  with `-maxmempool=300` does, under the same tx load.
- **Rolling-fee decay misfires**: halflife scaling fires at 5× higher
  entry counts → dynamic minimum fee decays too slowly in the
  "under quarter full" RAM regime.
- **Fleet pattern**: companion to W138 / W141 "constant ships but
  measurement unit diverges". Not present in this exact shape in other
  hotbuns waves but matches the `dust-relay-fee` archetype.

---

## BUG-2 (P0-CDIV) — `reorgRefillUnchecked` bypasses `evict()`; deep reorg can balloon mempool past `maxSize`

**Severity:** P0-CDIV. Bitcoin Core's `MaybeUpdateMempoolForReorg`
re-runs every disconnected tx through `AcceptToMemoryPoolWithTime` —
which includes `LimitMempoolSize` (the public wrapper around `TrimToSize`
+ `Expire`). Net effect: even after the disconnect of a 100-block reorg
re-adds thousands of txs, the mempool stays bounded by `-maxmempool`.

hotbuns's `reorgRefillUnchecked` (mempool.ts:2546-2603) bypasses every
checking path — by design, because hotbuns BlockSync does not persist
undo data so the UTXOs needed for `addTransaction` validation are
missing. The function directly appends each tx to `entries`, increments
`currentSize`, and indexes outpoints. **It never calls `this.evict()`**.

A 100-block reorg replaying ~50 K disconnected txs (a plausible mainnet
upper bound) at avg vsize 250 vB pushes `currentSize` by ~12.5 MB. By
itself harmless, but combined with a fully-loaded pre-reorg mempool, the
post-reorg `currentSize` overshoots `maxSize` and stays overshooting
until the next `addTransaction` happens to trigger `evict()`.

Worse: the unchecked entries have `fee = 0n`, `feeRate = 0`,
`miningScore = 0` (lines 2564-2583). When `evict()` finally runs, the
tail-chunk selection (cluster's last linearization chunk has lowest
fee-rate) picks these zero-fee unchecked entries first — but they HAVE
no parents recorded (`dependsOn = new Set<string>()` on line 2577), so
each is its own cluster of one. The evicted-tail-chunk feerate is 0
sat/vB; `trackPackageRemoved(0 + incrementalRelayKvB)` bumps the
rolling-min by exactly `incrementalRelayKvB = 100 sat/kvB = 0.1 sat/vB`.
The rolling-min then decays trivially.

**File:** `src/mempool/mempool.ts:2546-2603` (no `evict()` invocation);
cross-cite `src/sync/blocks.ts:2941-2960` (sole caller, in the IBD reorg
path).

**Core ref:** `bitcoin-core/src/validation.cpp::MaybeUpdateMempoolForReorg`
(per-tx ATMP including LimitMempoolSize → TrimToSize).

**Excerpt (hotbuns, missing evict)**
```ts
// mempool.ts:2589-2602
this.entries.set(txidHex, entry);
this.currentSize += vsize;

// Index spent outpoints so a later RBF / double-spend would
// surface this entry as a conflict (defence-in-depth).
for (const input of tx.inputs) {
  const outpointKey = `${input.prevOut.txid.toString("hex")}:${input.prevOut.vout}`;
  this.outpointIndex.set(outpointKey, txidHex);
}

console.log(
  `[mempool-reorg-refill] re-admitted disconnected tx ${txidHex.slice(0, 16)}... (vsize=${vsize})`
);
// MISSING: if (this.currentSize > this.maxSize) this.evict();
```

**Impact:**
- Reorg-refill bypasses the size ceiling. Plausible attack: peer pushes
  a 100-block side-chain reorg containing many tiny txs. We disconnect
  the old tip's blocks (taking their txs into the disconnect pool) and
  re-admit them via `reorgRefillUnchecked` without bound.
- Rolling-min-fee resets to ~0.1 sat/vB after the next eviction because
  the zero-fee unchecked entries dominate the worst-chunk selection.
- W150 BUG-10 carry-forward verified — fee=0n still present, no fix.

---

## BUG-3 (P1) — No post-block-connect `TrimToSize` / `Expire` sweep

**Severity:** P1. Bitcoin Core's `LimitMempoolSize` is called from
`MaybeUpdateMempoolForReorg` AND from `ChainstateManager::ProcessNewBlock`
on every connect, running both `TrimToSize(m_opts.max_size_bytes)` and
`Expire(m_opts.expiry)`. hotbuns's `removeForBlock` (mempool.ts:2332-2409)
removes confirmed txs and conflicts only; no `evict()` no `expire()` call
at the end. Stale low-fee txs accumulate until a new admission happens
to overshoot `maxSize`.

Combined with **BUG-4 (P0)** (expire never invoked anywhere), a 14-day
expiry window is effectively never enforced, and the mempool grows
monotonically between admission-triggered eviction events.

**File:** `src/mempool/mempool.ts:2332-2409` (no evict / expire at end of
removeForBlock).

**Core ref:** `bitcoin-core/src/validation.cpp::LimitMempoolSize`,
`ChainstateManager::ProcessNewBlock`.

**Impact:** mild memory leak between large admission events; expired txs
linger forever without manual RPC intervention.

---

## BUG-4 (P0-CDIV) — `Mempool.expire()` is dead code

**Severity:** P0-CDIV. Bitcoin Core's `Expire(time)` is invoked from
`LimitMempoolSize` (post-connect, periodic) AND from the scheduler at
fixed intervals so the 14-day mempool-expiry window is actually enforced.

hotbuns's `Mempool.expire()` (mempool.ts:3173-3206) is fully implemented
— it collects entries with `addedTime < cutoff`, expands via
`getDescendantSet`, removes each via `removeTransactionInternal`. But
**no production code path invokes it**:

```
$ grep -rn "mempool.expire(" hotbuns/src --include='*.ts' \
    | grep -v test
(empty)
```

The orphan-pool counterpart `orphanPool.expireOldOrphans()` (cli.ts:1801)
IS wired into the blockConnected handler, and the comment at cli.ts:1797
even cites the Core `EraseForBlock + LimitOrphans` cadence — but the
mempool's own `expire()` is **adjacent in the same handler and silently
forgotten**.

Net effect: a tx admitted to the mempool that never confirms (low-fee
during congestion, or a Replace-By-Fee race) stays in the pool **forever**
until either `evict()` evicts it on size pressure or the operator restarts
the daemon. The 14-day `DEFAULT_MEMPOOL_EXPIRY_HOURS` is unenforced.

**File:** `src/mempool/mempool.ts:3173-3206` (the dead helper);
`src/cli/cli.ts:1790-1828` (blockConnected handler where it SHOULD be
called next to `orphanPool.expireOldOrphans`).

**Core ref:** `bitcoin-core/src/txmempool.cpp:811-827` (`Expire`);
`bitcoin-core/src/validation.cpp::LimitMempoolSize` (caller).

**Impact:**
- 14-day expiry window unenforced → low-fee txs accumulate indefinitely.
- Mempool RAM growth is monotonic between large admissions.
- Combined with BUG-1 (no `-maxmempool` knob), no operator recourse.

---

## BUG-5 (P0-CDIV) — `DEFAULT_MIN_RELAY_TX_FEE = 0`; no `-minrelaytxfee` operator knob

**Severity:** P0-CDIV. Bitcoin Core's `DEFAULT_MIN_RELAY_TX_FEE = 1000`
sat/kvB = 1 sat/vB
(`bitcoin-core/src/policy/feerate.h` + `bitcoin-core/src/policy/settings.cpp`).
This is the **floor below which a tx is rejected as not paying enough for
network relay** — exists to bound the DoS surface of spamming the relay
graph with sub-economic txs.

hotbuns `DEFAULT_MIN_FEE_RATE = 0` (mempool.ts:568) and the constructor
assigns it as-is (line 1223). There is no CLI parse for
`-minrelaytxfee` (cli.ts:330-595), and no call to `mempool.setMinFeeRate`
from cli.ts. **A fresh hotbuns node ships with min-relay-fee = 0**, so
any tx with positive fee (or even fee=0, since the gate is `feeRate <
this.minFeeRate` which is `0 < 0` = false) gets admitted.

This means a hotbuns node:
- Admits 1-satoshi-fee txs (Core rejects).
- Disagrees with Core peers on which txs are relayable → it propagates
  txs that Core will refuse, churning the relay graph.
- Has no operator dial to raise the floor for spam-tolerance tuning.

The RPC `getmempoolinfo` lies about this (`server.ts:3566`):
```ts
minrelaytxfee: 0.00001,  // 1 sat/vB — hardcoded; doesn't reflect actual minFeeRate=0
```
So operators see "minrelaytxfee = 0.00001 BTC/kvB" in their JSON output
but the node is actually admitting at 0.

**File:** `src/mempool/mempool.ts:568, 1223`;
`src/cli/cli.ts:330-595` (no flag);
`src/rpc/server.ts:3566`, `src/rpc/rest.ts:828` (lying constants).

**Core ref:** `bitcoin-core/src/policy/feerate.h::DEFAULT_MIN_RELAY_TX_FEE`,
`bitcoin-core/src/init.cpp` (`-minrelaytxfee` arg).

**Impact:**
- Relay-graph spam DoS surface 1 sat/vB lower than Core peers.
- Operator-visible mismatch between RPC field and actual behaviour.
- No operator override.
- Fleet pattern "constant exposed in RPC ≠ constant enforced in mempool"
  — 6th distinct hotbuns instance of "RPC ships canonical value while
  the production path uses something else".

---

## BUG-6 (P0-CDIV) — `DEFAULT_INCREMENTAL_RELAY_FEE` is 10× too low

**Severity:** P0-CDIV. Bitcoin Core's
`DEFAULT_INCREMENTAL_RELAY_FEE = 1000` sat/kvB = **1 sat/vB**
(`bitcoin-core/src/policy/policy.h:48`). This is the per-vbyte increment
that RBF replacements must add (BIP-125 Rule 4) and that's added to the
TrimToSize-evicted-chunk fee rate before bumping `rollingMinimumFeeRate`.

hotbuns `DEFAULT_INCREMENTAL_RELAY_FEE = 0.1` sat/vB = 100 sat/kvB
(mempool.ts:576). The inline comment at 573 even reads:

> Bug fixed: was 1 sat/vB (10× too high), causing RBF Rule #4 to demand
> too much. Reference: bitcoin-core/src/policy/policy.h:48

This is a **comment-as-confession** that the value was **changed in the
WRONG direction** by some prior fix. Core's value is 1 sat/vB; the
hotbuns value was already correct at 1 sat/vB; someone "fixed" it to
0.1 thinking the unit was sat/kvB. The cited Core line (`policy.h:48`)
defines the value in sat/kvB (1000), so 1 sat/vB IS the Core value.

Downstream consequences:
- RBF Rule 4 only requires +0.1 sat/vB premium (Core: +1 sat/vB) — a
  Core-relay-graph attacker can churn RBF replacements at 1/10th Core's
  cost, replacing a 50-sat-fee tx with a 51-sat-fee tx instead of
  needing 100 sats. This **breaks RBF-amount-progressing economics
  across the fleet**.
- `trimToSize` bumps `rollingMinimumFeeRate` by only 100 sat/kvB after
  each evicted chunk — Core bumps by 1000 sat/kvB. The dynamic floor
  ramps up 10× slower under sustained eviction pressure.
- `getMinFee()` floor (line 3277) is `max(rolling, 100 sat/kvB)` vs
  Core's `max(rolling, 1000 sat/kvB)`. With rolling=0, hotbuns admits
  txs at 0.1 sat/vB; Core requires 1 sat/vB.

**File:** `src/mempool/mempool.ts:576`; cross-cite RPC at
`src/rpc/server.ts:3567` (hardcoded `0.00001` BTC/kvB = 1 sat/vB,
so the RPC lies again about the actual 0.1 sat/vB).

**Core ref:** `bitcoin-core/src/policy/policy.h:48`,
`bitcoin-core/src/init.cpp` (`-incrementalrelayfee`).

**Excerpt (hotbuns, comment-as-confession)**
```ts
// mempool.ts:570-576
/**
 * Default incremental relay fee rate (sat/vB).
 * Core policy.h:48: DEFAULT_INCREMENTAL_RELAY_FEE = 100 sat/kvB = 0.1 sat/vB.
 *                                                ^^^^^^^^^^^^^
 *                                                FALSE — Core value is 1000 sat/kvB
 * Bug fixed: was 1 sat/vB (10× too high), causing RBF Rule #4 to demand too much.
 *           ^^^^^^^^^^^^
 *           THE PREVIOUS VALUE WAS CORRECT; THIS "FIX" REGRESSED IT
 * Reference: bitcoin-core/src/policy/policy.h:48
 */
const DEFAULT_INCREMENTAL_RELAY_FEE = 0.1; // 100 sat/kvB
```

**Impact:**
- RBF replacement economics break: replacements are 10× cheaper than
  Core, so a Core-relay-graph cycle attack on a single tx costs 1/10
  what Core operators expect.
- Rolling-min-fee ramps up too slowly under TrimToSize pressure.
- Cross-cite RPC field at server.ts:3567 lies about actual value.

---

## BUG-7 (P0-CDIV) — `MemPoolRemovalReason` enum is entirely absent; every removal-path is reasonless

**Severity:** P0-CDIV. Bitcoin Core's
`kernel/mempool_removal_reason.h` defines six removal reasons that
`removeUnchecked` / `RemoveStaged` thread through to every signal
emitter:

```cpp
enum class MemPoolRemovalReason {
    EXPIRY, SIZELIMIT, REORG, BLOCK, CONFLICT, REPLACED,
};
```

Downstream consumers branch on the reason:
- **Fee estimator**: skip recording confirmation-time for `CONFLICT`
  and `REORG` because those txs weren't mined; record for `BLOCK`.
- **ZMQ sequence**: the sequence body's 32-byte hash is followed by a
  label byte (`A`/`R`/`C`/`D` — only `R` is a removal); but Core's
  `MempoolTransactionRemoved` signal also carries the reason which
  some subscribers parse to distinguish "tx replaced by better fee"
  from "tx fell out of mempool due to size".
- **Wallet**: shows different UI for "tx dropped from mempool" vs "tx
  replaced".

hotbuns has **zero awareness of removal reasons**:

```
$ grep -rn "MemPoolRemovalReason\|RemovalReason\|removalReason" \
    hotbuns/src/mempool/ hotbuns/src/rpc/ hotbuns/src/fees/
(empty)
```

Every removal site — `removeTransaction`, `removeTransactionInternal`,
`removeForBlock`, `expire`, `evict`, the RBF replace path —
emits the same reasonless `txRemoved` event. Downstream consumers
(fee estimator, ZMQ, wallet) cannot distinguish the six cases.

**File:** `src/mempool/mempool.ts:2241, 3055, 2332, 3173, 3299`;
`src/rpc/zmq.ts:255-260` (sequence emit, hardcoded label "R");
`src/fees/estimator.ts` (no reason argument anywhere).

**Core ref:** `bitcoin-core/src/kernel/mempool_removal_reason.h`,
`bitcoin-core/src/txmempool.cpp:417, 793-798, 825, 896`.

**Impact:**
- Fee estimator records confirmation-times for txs that were REPLACED
  / CONFLICTED / REORG'd — pollutes the moving average with
  "successfully relayed" data even though those txs never confirmed.
- ZMQ subscribers cannot distinguish "your tx was replaced" from
  "your tx was evicted under fee pressure" from the wire signal.
- Wallet UX cannot accurately report failure reason.

---

## BUG-8 (P0-CDIV) — Fee estimator has no `removeTx(hash)` hook; tracks evicted txs forever

**Severity:** P0-CDIV. Bitcoin Core's `CBlockPolicyEstimator` has
three mempool-side hooks
(`bitcoin-core/src/policy/fees/block_policy_estimator.h:207-216`):
- `processBlock(txs_removed_for_block, height)` — confirmations.
- `processTransaction(new_tx_info)` — admission.
- `removeTx(hash)` — eviction without confirmation.

The third is what allows the estimator to know "this tx was in the
mempool, did NOT confirm, was evicted under fee pressure — do not
include in the unconfirmed denominator". Without it, the estimator
overcounts the `totalUnconfirmed` bucket and underestimates the
confirmation probability at a given fee rate.

hotbuns `FeeEstimator` (estimator.ts:1-767) has `trackTransaction(txid,
height)` (line 251) and `processBlock(block, height)` (327). It has no
`removeTx` method, no signal subscription on `txRemoved`. The
`txEntryHeights` map (251, 320) is only cleaned up by:
- `processBlock` for txs that confirm (337-358),
- garbage-collection of entries older than `MAX_CONFIRMATION_BLOCKS * 2`
  (362-367).

Txs that are evicted by `evict()`, `removeTransaction(_, true)` cascade,
or RBF replacement stay in `txEntryHeights` indefinitely (until the
GC sweep). They pollute the per-bucket `totalUnconfirmed` counter via
`recordConfirmation`'s opposite-side logic, biasing the estimate.

**File:** `src/fees/estimator.ts:251, 320` (no removeTx hook);
`src/cli/cli.ts:1789` (mempool.setNotificationEmitter to chainEvents,
but no `chainEvents.on("txRemoved", ...)` calls `feeEstimator.removeTx`).

**Core ref:** `bitcoin-core/src/policy/fees/block_policy_estimator.h:216-217`
(`removeTx(Txid hash)`); `bitcoin-core/src/validation.cpp`
(`m_fee_estimator->removeTx` called from `MempoolTransactionRemoved`
signal subscriber).

**Impact:**
- Fee estimator overestimates "tx waiting in mempool" rates.
- Estimates `estimatesmartfee` return rates that don't match actual
  confirmation curves.
- The estimator's persisted state (`fee_estimates.json` per cli.ts:1545)
  carries the pollution across restarts.

---

## BUG-9 (P0-WIRING) — ZMQ subsystem entirely orphaned; hashtx fan-out unreachable in production

**Severity:** P0-WIRING (carry-forward W141 + W152 BUG-18, **verified**).
`ZMQNotificationInterface.notifyBlock` (zmq.ts:206-223) is correctly
implemented:

```ts
async notifyBlock(block: Block): Promise<void> {
  const blockHash = getBlockHash(block.header);
  await this.publish("hashblock", blockHash);
  await this.publish("rawblock", serializeBlock(block));
  await this.publishSequence(blockHash, "C");
  for (const tx of block.transactions) {     // <-- correct per-tx fan-out
    const txid = getTxId(tx);
    await this.publish("hashtx", txid);
  }
}
```

`wireZMQNotifications` (zmq.ts:354-384) subscribes to `blockConnected`,
`blockDisconnected`, `txAccepted`, `txRemoved`. The wiring is correct.

But `cli.ts` (the production startup path) **never instantiates
`ZMQNotificationInterface`** and **never calls `parseZMQArgs`**. The
arg parser at cli.ts:330-595 has no `case "zmqpubhashblock":` /
`case "zmqpubhashtx":` etc. There is a regression test that asserts
this:

```ts
// src/__tests__/w141_zmq_rest_notify.test.ts:191-195
test("cli.ts never instantiates ZMQNotificationInterface", () => {
  const src = await Bun.file("src/cli/cli.ts").text();
  expect(src).not.toContain('new ZMQNotificationInterface');
  expect(src).not.toContain('parseZMQArgs(');
  expect(src).not.toContain('wireZMQNotifications(');
});
```

The test is GREEN (verified by reading), which means the W152 BUG-18
finding ("entire ZMQ subsystem orphaned") is **regression-locked open**.
Operators that start hotbuns with `--zmqpubhashblock=tcp://…` see the
arg silently ignored — no error, no warning. The arg parser at
cli.ts:333-595 doesn't have a `default:` case that warns on unknown args
either.

**File:** `src/cli/cli.ts:330-595` (no zmq arg parse);
`src/rpc/zmq.ts:106-385` (subsystem defined but unwired);
`src/__tests__/w141_zmq_rest_notify.test.ts:191-195` (regression-locks
the bug).

**Core ref:** `bitcoin-core/src/init.cpp` (`-zmqpub*` arg parse);
`bitcoin-core/src/zmq/zmqpublishnotifier.cpp` (Notifier ctor/init).

**Impact:**
- All five ZMQ topics (`hashblock`, `hashtx`, `rawblock`, `rawtx`,
  `sequence`) are dead.
- Downstream consumers (electrs, fulcrum, mempool.space, nbxplorer)
  cannot subscribe to hotbuns.
- W141 + W152 carry-forward: this is the third audit cycle that's
  caught it; the regression test pins it in place rather than fixing it.

---

## BUG-10 (P1) — REST endpoint has no tx / block notification long-poll

**Severity:** P1. Bitcoin Core's REST API
(`bitcoin-core/src/rest.cpp`) exposes `rest_headers` (with `count`
parameter) and a long-poll variant. hotbuns's REST (rest.ts) lacks
`/rest/tx/notifications` or any equivalent. Operators wanting a
push-style notification stream are forced to either (a) wire ZMQ
(which is dead per BUG-9), (b) poll `getrawmempool` / `getblockcount`
on a timer, or (c) use the JSON-RPC subscribe primitives (which
hotbuns also doesn't have).

**File:** `src/rpc/rest.ts:807-871` (mempool endpoint, no notifications).

**Core ref:** `bitcoin-core/src/rest.cpp::rest_headers` long-poll mode.

**Impact:** ecosystem tools that prefer REST over ZMQ have no
notification path at all on hotbuns.

---

## BUG-11 (P0-CDIV) — `InventoryRelay` has no `removeTx`; we INV evicted txs

**Severity:** P0-CDIV. Bitcoin Core's `net_processing.cpp` maintains
per-peer `m_tx_inventory_to_send` queues that are filtered on every
trickle round against the mempool's current contents — a tx that was
evicted between INV-queue-and-send is dropped from the outbound INV.

hotbuns's `InventoryRelay` (relay.ts:73) provides `addPeer`, `removePeer`,
`queueTx`, `queueTxFiltered`, `queueTxToAll`, `queueTxToAllFiltered`.
There is no `removeTx` / `forgetTx` method. Once a txid is queued via
`queueTxToAllFiltered(txidHex, feeRate)` (cli.ts:1867 on admission,
1911 on orphan promotion), it sits in the per-peer queue until trickled
out — even if the mempool has since evicted the entry.

When a peer responds with `getdata` for the INV'd txid, hotbuns must
look up the tx in the mempool:
- If still present: send `tx` message. OK.
- If evicted: either ignore (W152 BUG-13 timeout discipline) or return
  `notfound` (W152 BUG-14 wrong reject reason).

Combined with **BUG-4 (no expire)** and **BUG-2 (reorgRefillUnchecked
zero-fee entries dominate eviction)**, this becomes a real bug pattern:
admission fires INV → admission-time low-fee tx evicted moments later
under fee pressure → peer requests, we say "notfound" / drop → peer
re-requests later thinking we're hoarding → tx-relay graph confused.

**File:** `src/p2p/relay.ts:73, 96-200` (no removeTx);
`src/cli/cli.ts:1787-1789` (notification emitter wiring) — no
`chainEvents.on("txRemoved", ...)` calls `txRelay.removeTx(...)`.

**Core ref:** `bitcoin-core/src/net_processing.cpp` —
`m_tx_inventory_to_send.find(invtx)` gated on mempool presence each
trickle round.

**Impact:**
- We INV evicted txs to peers → peers waste round-trips on `getdata`
  → response is either timeout or `notfound`.
- Combined with BUG-2 / BUG-4, the rate of inv-evicted-then-getdata
  is non-trivial during a reorg or fee spike.
- Mild DoS on peer bandwidth + our own response latency.

---

## BUG-12 (P0-CDIV) — `sync/blocks.ts` connect path NEVER emits `blockConnected`; fee estimator + orphan pool + ZMQ + cascade all silently dead during IBD

**Severity:** P0-CDIV. hotbuns has TWO connect paths:
1. **`chain/state.ts::connectBlock`** (line 423-473): emits
   `notificationEmitter.emit("blockConnected", block)` at line 471.
   Used by `regtest generateblock`, `invalidateblock`/`reconsiderblock`
   RPCs, and `dumptxoutset` rollback.
2. **`sync/blocks.ts::connectBlock`** (line ~2860-2900): IBD and
   normal-sync block reception. Calls `chainStateManager.updateTip(hash,
   height, chainWork)` (line 2863) but **NOT**
   `chainStateManager.connectBlock(...)`. `updateTip` is a bare setter
   (state.ts:897-899) — it just stores the tuple, never emits any
   event.

The `chainEvents` emitter wired in cli.ts:1788-1789 has subscribers for
`blockConnected`:
- `orphanPool.eraseForBlock(confirmedTxids)` (cli.ts:1793)
- `orphanPool.expireOldOrphans()` (cli.ts:1801)
- `feeEstimator.processBlock(block, blockHeight)` (cli.ts:1810)
- `processOrphanCascade(tx)` per tx (cli.ts:1814)

**None of these fire during normal operation** because `sync/blocks.ts`
is the only path that connects blocks during IBD and post-IBD normal
peer-sourced sync, and it never emits.

What this means in practice:
- **During IBD (10+ hours on mainnet)**: every block from genesis to
  tip is connected without firing any of the four downstream handlers.
  Orphan pool's `expireOldOrphans` never runs → stale orphans
  accumulate; orphan-cascade promotion never runs → children of
  newly-confirmed parents are never re-tried; fee estimator never
  records confirmations → `estimatesmartfee` returns garbage; ZMQ
  hashblock/rawblock/hashtx never fire (also unreachable per BUG-9).
- **Post-IBD normal operation**: same problem. Every block arriving
  from a peer goes through `sync/blocks.ts::connectBlock` (not
  `chain/state.ts::connectBlock`), so none of the four handlers fire.
- **Only `regtest generateblock` and RPC `invalidateblock` /
  `reconsiderblock`** fire the handlers — which is the test suite
  scenario, masking the production bug.

This is a "two-pipeline guard 17th distinct extension": two connect
paths exist with non-symmetric side effects.

**File:** `src/sync/blocks.ts:2860-2906` (the IBD connect, missing emit);
`src/chain/state.ts:423-473, 897-899` (the RPC-driven connect that
DOES emit; the bare `updateTip` setter that SHOULD also emit);
`src/cli/cli.ts:1788-1789, 1790-1829` (the 4-handler subscriber).

**Core ref:** `bitcoin-core/src/validation.cpp::ConnectTip` — single
path, single emit of `BlockConnected` signal regardless of caller.

**Excerpt (hotbuns, missing emit)**
```ts
// sync/blocks.ts:2860-2865
if (this.chainStateManager) {
  const headerEntry3 = this.headerSync.getHeaderByHeight(height);
  if (headerEntry3) {
    this.chainStateManager.updateTip(blockHash, height, headerEntry3.chainWork);
    //                              ^^^^^^^^^^^^^^^^
    //                              bare setter, no emit
  }
}

// MISSING:
// if (this.notificationEmitter) {
//   this.notificationEmitter.emit("blockConnected", block);
// }
```

**Impact:**
- **Fee estimator dead during IBD**: no `processBlock` calls during
  the entire history of the chain. `txEntryHeights` map is empty
  because `trackTransaction` is also gated on `!blockSync.isIBDComplete()`
  (cli.ts:1857 returns early). After IBD ends, the estimator starts
  tracking new admissions but never records confirmations (since
  `blockConnected` STILL doesn't fire from sync/blocks.ts).
- **Orphan pool sweep dead during IBD**: stale orphans linger.
- **Cascade-promote dead during IBD**: orphans whose parent just got
  confirmed are not re-evaluated.
- **ZMQ hashblock/rawblock/hashtx all dead** (compounded with BUG-9
  but would be dead even if BUG-9 were fixed).
- **Post-IBD normal operation**: all four handlers stay dead.

---

## BUG-13 (P0-CDIV) — `chain/state.ts::reorganize` does NOT refill the mempool

**Severity:** P0-CDIV. Bitcoin Core's
`ChainstateManager::MaybeUpdateMempoolForReorg` runs after every
disconnect/reconnect cycle, regardless of caller. hotbuns has two reorg
paths:

1. **`sync/blocks.ts::handleReorgUtxoAndCollect` → `sync/blocks.ts::connectBlock`**
   (line 2941-2960): IBD-time reorg. Calls `mempool.readdTransactions`
   (full check) or `mempool.reorgRefillUnchecked` (BUG-2 path).
   Wired.
2. **`chain/state.ts::reorganize`** (line 779-817): used by
   `invalidateblock` / `reconsiderblock` RPC and `dumptxoutset` rollback.
   Walks disconnect/connect via `disconnectBlock` (485-769) +
   `connectBlock` (423-473). **Neither path calls `mempool.readd*` or
   `mempool.reorgRefillUnchecked`**.

```
$ grep -n "readdTransactions\|reorgRefillUnchecked" \
    hotbuns/src/chain/state.ts hotbuns/src/rpc/server.ts
(empty)
```

Result: any operator using `bitcoin-cli invalidateblock <hash>` to
manually fork to a different tip experiences **mempool = empty**
after the reorg completes. Txs that were in disconnected blocks are
not re-admitted. Pattern B1 ("no refill at all") that was supposedly
fixed for the IBD path in W93 is still latent for the RPC-driven path.

**File:** `src/chain/state.ts:779-817` (`reorganize`),
`src/chain/state.ts:485-769` (`disconnectBlock`),
`src/chain/state.ts:423-473` (`connectBlock`).

**Core ref:** `bitcoin-core/src/validation.cpp::MaybeUpdateMempoolForReorg`.

**Impact:**
- `invalidateblock` RPC: post-reorg mempool empty.
- `reconsiderblock`: same.
- `dumptxoutset` snapshot rollback: same.
- Pattern B1 still latent for the second of two connect paths
  (cross-cite BUG-12 — they share a root: dual connect paths,
  inconsistent side-effect set).

---

## BUG-14 (P0-CDIV) — `prioritisetransaction` RPC absent; mempool.dat `mapDeltas` is read-only

**Severity:** P0-CDIV. Bitcoin Core's
`prioritisetransaction <txid> <dummy_fee_delta> <fee_delta>` is the
operator-facing way to nudge a tx up or down in mempool fee ordering
without altering its on-wire fee. The delta is stored in
`mempool.mapDeltas[txid] = nFeeDelta` and added to the entry's
`nFeeDelta` field on each `MempoolEntryHeight` mining-score calculation;
persists across restart via the `mapDeltas` section of `mempool.dat`.

hotbuns:
- No `prioritisetransaction` RPC handler (`grep prioritise
  hotbuns/src/rpc/` returns empty).
- `Mempool.entries` has no `feeDelta` field; `MempoolEntry` (mempool.ts:633-677)
  has `fee` and `feeRate` only.
- `persist.ts:14-23` documents the `mapDeltas` section in the on-disk
  format ("compactsize mapDeltas count; per mapDeltas: 32 bytes txid,
  int64 LE nFeeDelta") and reads it on load (persist.ts:78); but there
  is no production path that **adds** entries to that map.
- `server.ts:3599` returns `modifiedfee: Number(entry.fee) / 100_000_000`
  — always equal to `fee`, because hotbuns has no per-tx delta.

The dump path therefore writes an empty `mapDeltas` section (or
preserves what was loaded if a Core-written mempool.dat was loaded —
but then loses the deltas because no in-memory state tracks them).

**File:** `src/mempool/mempool.ts:633-677` (entry, no feeDelta);
`src/rpc/server.ts` (no prioritisetransaction);
`src/mempool/persist.ts:14-23, 78` (format known, only read).

**Core ref:** `bitcoin-core/src/rpc/mempool.cpp::prioritisetransaction`;
`bitcoin-core/src/txmempool.cpp::PrioritiseTransaction`,
`mapDeltas`.

**Impact:**
- Operators cannot prioritise stuck txs.
- Wallets that depend on prioritisetransaction for fee-bump UX (Sparrow,
  Specter) cannot integrate cleanly with hotbuns.
- `mempool.dat` loaded from a Core node loses its `mapDeltas` section
  on the round-trip (load discards, dump writes empty).
- Cross-impl divergence: every other hashhog impl that exposes
  `prioritisetransaction` differs from hotbuns at this RPC.

---

## BUG-15 (P0-CDIV) — `feeFilterInterval` never set; BIP-133 feefilter NEVER sent in production

**Severity:** P0-CDIV (fleet pattern: "feefilter never sends in production"
is the W134/W136 finding for 6 of 10 impls — **hotbuns confirmed as
6th instance**). `PeerManager` declares `private feeFilterInterval:
ReturnType<typeof setInterval> | null` (manager.ts:411) and initialises
it to `null` (line 495). It is **never set to an actual interval**.

`FeeFilterManager.maybeSendFeeFilter(peer, now, isBlockRelayOnly)`
(feefilter.ts:121) is the method that, when invoked periodically per
peer, sends the BIP-133 feefilter message. It is invoked **nowhere in
production**:

```
$ grep -rn "maybeSendFeeFilter\|feeFilterManager\." hotbuns/src/p2p/
manager.ts:37:  FeeFilterManager,
manager.ts:409:  private feeFilterManager: FeeFilterManager;
manager.ts:492:    this.feeFilterManager = new FeeFilterManager(...)
manager.ts:2759:  getFeeFilterManager(): FeeFilterManager {}
```

`FeeFilterManager` is instantiated, given a send callback, exposed via
a getter — but no production caller iterates peers and calls
`maybeSendFeeFilter` on a timer.

Net effect: hotbuns never tells peers "don't send me txs below
X sat/vB". Peers that respect BIP-133 (every modern Core node) continue
to push us txs at any feerate — we receive then reject (or accept under
BUG-5's 0 floor). Bandwidth waste; pre-relay validation cost for
sub-economic txs that Core peers would have filtered before sending.

**File:** `src/p2p/manager.ts:411, 495` (declared null, never set);
`src/p2p/feefilter.ts:121` (the unused sender).

**Core ref:** `bitcoin-core/src/net_processing.cpp::PeerManagerImpl::MaybeSendFeeFilter`
(invoked per peer on a Poisson-distributed timer).

**Impact:**
- Outbound feefilter never sent → Core peers don't filter sub-economic
  txs before sending to us.
- Bandwidth waste on the receive side.
- Mempool's `getMinFeeRateKvB()` value (mempool.ts:3402) is dead-data
  for the network — it's the right value, it's just never broadcast.
- Fleet pattern 6 of 10 impls confirmed (hotbuns joins the W136
  ZMQ-orphan / feefilter-dead consortium).

---

## BUG-16 (P0-CDIV) — `removeForBlock` does NOT emit `txRemoved` for confirmed txs; ZMQ sequence label "R" never fires for the canonical "tx got mined" case

**Severity:** P0-CDIV. Bitcoin Core's `removeForBlock`
(`bitcoin-core/src/txmempool.cpp:405-431`) goes through
`removeUnchecked(it, MemPoolRemovalReason::BLOCK)` for every confirmed
tx, which calls the per-tx `NotifyEntryRemoved` signal **AND** the bulk
`MempoolTransactionsRemovedForBlock` signal at the end. ZMQ subscribers
get a sequence-R label for every removed tx, with a reason byte
distinguishing BLOCK from EXPIRY etc.

hotbuns's `removeForBlock` (mempool.ts:2332-2356) **directly mutates
state** for confirmed txs:

```ts
// Remove the transaction (but not its dependents yet - they may also be confirmed)
const entry = this.entries.get(txidHex);
if (entry) {
  // Remove outpoint index entries
  for (const input of entry.tx.inputs) {
    const outpointKey = `${input.prevOut.txid.toString("hex")}:${input.prevOut.vout}`;
    this.outpointIndex.delete(outpointKey);
  }
  // Remove from entries
  this.entries.delete(txidHex);
  this.currentSize -= entry.vsize;
  // MISSING: notificationEmitter.emit("txRemoved", entry.txid, mempoolSequence++)
}
```

Only conflicts (line 2375-2378) go through `removeTransaction(_, true)`
which DOES emit `txRemoved`. The typical case — block lands, 100
confirmed txs leave the mempool — emits ZERO `txRemoved` events.

Combined with BUG-7 (no `MemPoolRemovalReason`), ZMQ subscribers cannot:
- Know that 100 of their tracked txs just confirmed (they only get a
  single `blockConnected` event, with the full block; they must
  re-diff their mempool view themselves).
- Distinguish "tx removed because it confirmed" from "tx removed
  because it was evicted under fee pressure".

The `mempoolSequence` counter (mempool.ts:1172, bumped in
`removeTransaction` line 2315) is also NOT incremented for these
confirmed removals. Downstream consumers relying on monotonic
mempoolSequence (Core's reference shape) see gaps in sequence numbers
that look like dropped events.

**File:** `src/mempool/mempool.ts:2332-2356` (direct mutation, no emit,
no sequence bump); contrast with line 2316 (the proper emit in
`removeTransaction`).

**Core ref:** `bitcoin-core/src/txmempool.cpp:405-431` (`removeForBlock`
uses `removeUnchecked` which emits per-tx signal).

**Impact:**
- ZMQ `sequence` topic emits NO per-tx events for confirmed txs (which
  is by far the highest-volume case).
- `mempoolSequence` counter has unexplained skips visible to
  subscribers, breaking their sequence-tracking logic.
- Fee estimator's would-be `removeTx` hook (if it existed per BUG-8)
  would not fire for confirmed txs through this path.
- Wallet integrations cannot incrementally reconcile mempool state on
  block-connect without re-querying full mempool.

---

## BUG-17 (P1) — RPC `getmempoolinfo` HARDCODES `maxmempool`, `minrelaytxfee`, `incrementalrelayfee`, `unbroadcastcount`

**Severity:** P1 (operator-visible lying RPC). `server.ts:3548-3571`:

```ts
return {
  loaded: true,
  size: info.size,
  bytes: info.bytes,
  usage: info.bytes, // Memory usage approximation
  total_fee: totalFee / 100_000_000,
  maxmempool: 300_000_000,       // hardcoded; ignores this.mempool.maxSize
  mempoolminfee: info.minFeeRate / 100_000,
  minrelaytxfee: 0.00001,        // hardcoded; ignores this.mempool.minFeeRate (which is 0)
  incrementalrelayfee: 0.00001,  // hardcoded 1 sat/vB; actual is 0.1 sat/vB (BUG-6)
  unbroadcastcount: 0,           // hardcoded; mempool has no unbroadcast tracking
  fullrbf: true,
};
```

Four fields lie:
- `maxmempool: 300_000_000` — should be `this.mempool.maxSize`. Operators
  who eventually get a `-maxmempool` knob (after BUG-1 / BUG-5 are fixed)
  would still see the wrong value in RPC output.
- `minrelaytxfee: 0.00001` — claims 1 sat/vB; actual `minFeeRate` is 0
  (BUG-5). Monitoring tools that scrape this field see "node is at
  Core defaults" while the node is actually at 0.
- `incrementalrelayfee: 0.00001` — claims 1 sat/vB; actual constant is
  0.1 sat/vB (BUG-6). Wallets that use this field to compute RBF
  bump-fee surplus underestimate by 10×.
- `unbroadcastcount: 0` — claims no unbroadcast txs; hotbuns has no
  unbroadcast-tx tracking at all (Core tracks txs we sent via RPC but
  haven't seen a peer relay back). Operators monitoring "are my
  sendrawtransactions actually propagating" see 0 always.

Plus REST `/rest/mempool/info` (rest.ts:819-831) has the same four lies.

**File:** `src/rpc/server.ts:3548-3571`; `src/rpc/rest.ts:819-831`.

**Core ref:** `bitcoin-core/src/rpc/mempool.cpp::getmempoolinfo`.

**Impact:** operator-visible monitoring divergence; tools that scrape
mempool info to dashboards report defaults that don't match runtime.

---

## BUG-18 (P1) — `extra-tx-for-compact` slot absent; orphan-pool integration with compact-block reconstruction missing

**Severity:** P1. Bitcoin Core's compact-block reconstruction
(`bitcoin-core/src/net_processing.cpp::ProcessCompactBlockTxns`)
maintains a small **extra-tx vector** (recently-evicted mempool txs,
sized `MAX_EXTRA_TXN_FOR_COMPACT_BLOCK = 100` per peer) that helps
reconstruct a compact block whose `prefilledtxn` were evicted from our
mempool between announcement and reception.

hotbuns has no equivalent. `evict()` (mempool.ts:3299) discards entries
to nowhere; the next compact block referencing one of these evicted
txs falls through to a `BLOCKTXN` round-trip.

**File:** `src/mempool/mempool.ts:3299-3369`;
`src/p2p/compact_blocks.ts` (no extra-tx slot).

**Core ref:**
`bitcoin-core/src/net_processing.cpp::MAX_EXTRA_TXN_FOR_COMPACT_BLOCK`.

**Impact:** mild bandwidth + latency cost on compact-block reception
when the announcer's prefilled tx was recently evicted by us.

---

## BUG-19 (P1) — `MEMPOOL_EXPIRY_SECONDS` is 14d as constant; no `-mempoolexpiry` operator knob

**Severity:** P1. `MEMPOOL_EXPIRY_SECONDS = 336 * 60 * 60` (mempool.ts:553)
matches Core's default — but Core also exposes `-mempoolexpiry=<hours>`
allowing operators to shorten (regtest, debug) or lengthen (research
nodes that want to preserve historical mempool snapshots).

hotbuns has no CLI parse for `-mempoolexpiry`. The constant is
hardcoded and (per BUG-4) also unused. So even if expiry were wired,
operators couldn't change it.

**File:** `src/mempool/mempool.ts:553`; `src/cli/cli.ts:330-595`
(no flag).

**Core ref:** `bitcoin-core/src/init.cpp` (`-mempoolexpiry`).

**Impact:** operator-knob-absent fleet pattern, 7th distinct hotbuns
instance.

---

## BUG-20 (P1) — `unbroadcast` set is absent; we have no record of txs we accepted-but-haven't-seen-relayed-back

**Severity:** P1. Bitcoin Core maintains
`m_unbroadcast_txids` (txmempool.h) — the set of txs we accepted to our
own mempool (via RPC or peer) but have not yet seen a peer announce
back to us. The periodic re-broadcast logic
(`bitcoin-core/src/net/process_messages.cpp::ScheduleReBroadcast`) uses
this to re-inv unbroadcast txs every `~10-15 min` until a peer
acknowledges back.

hotbuns: no `unbroadcast` set, no re-broadcast logic. A
`sendrawtransaction` that hits us during a network blip never gets
re-tried — if no peer ever asks for it via `getdata` in the next 10
minutes, it sits in our mempool unrelayed. The `mempool.dat` format
documents an `unbroadcast_txids` section (persist.ts:21-23) but the
load path reads it (persist.ts:79 `result.unbroadcast++`) and the
dump path writes an empty section.

**File:** `src/mempool/mempool.ts` (no unbroadcast set);
`src/mempool/persist.ts:21-23, 79` (read but never populated).

**Core ref:** `bitcoin-core/src/txmempool.h::m_unbroadcast_txids`;
`bitcoin-core/src/net/process_messages.cpp::ScheduleReBroadcast`.

**Impact:** `sendrawtransaction` is fire-and-forget — no re-broadcast
on relay failure. Cross-cite BUG-17 (`unbroadcastcount: 0` hardcoded).

---

## BUG-21 (P1) — `-blocknotify` / `-walletnotify` / `-alertnotify` operator knobs absent (W141 carry-forward)

**Severity:** P1 (fleet pattern: 7 of 10 impls per W141 — hotbuns
**confirmed as the 8th**). Bitcoin Core's three `*-notify` knobs
exec a shell command on block / wallet / alert events. Operators wire
these to systemd-notify, ntfy.sh, Slack webhooks etc.

hotbuns CLI parser (cli.ts:330-595) has no `case "blocknotify":` /
`"walletnotify":` / `"alertnotify":`. ConfigParser at cli.ts:647-770
also lacks them.

**File:** `src/cli/cli.ts:330-595, 647-770`.

**Core ref:** `bitcoin-core/src/init.cpp` (`-blocknotify`,
`-walletnotify`, `-alertnotify`); `bitcoin-core/src/common/run_command.cpp`
(safe shell-escape primitive).

**Impact:** operators using shell-out monitoring on Core have no
analogous wiring on hotbuns.

---

## BUG-22 (P2) — `reorgRefillUnchecked` sentinel-fields (W150 BUG-10 carry-forward verified)

**Severity:** P2 (regression-verification carry-forward). `reorgRefillUnchecked`
(mempool.ts:2546-2603) creates entries with sentinel values:
- `fee = 0n`
- `feeRate = 0`
- `dependsOn = new Set<string>()` (empty — no parent tracking)
- `ancestorCount = 1, ancestorSize = vsize` (singleton sentinel)
- `descendantCount = 1, descendantSize = vsize` (singleton sentinel)
- `miningScore = 0`
- `sigOpCost = 0`
- `ephemeralDustParents = new Set<string>()`, `hasEphemeralDust = false`

These sentinel entries are visible via `getrawmempool verbose=true` —
operators see `fee: 0`, `feeRate: 0`, `ancestor: { count: 1, … }` for
every refilled-after-reorg tx, even though the on-chain truth (these
were valid txs paying real fees, with real ancestor structure). RBF
comparisons against these refilled txs (BUG-2 cross-cite) compute the
wrong incremental fee requirement (0n + incrementalRelayFee instead
of actual fee + incrementalRelayFee).

W150 BUG-10 raised this; no fix has landed. The entry creation block
at line 2567-2587 is byte-identical to what was raised at W150.

**File:** `src/mempool/mempool.ts:2567-2587`.

**Core ref:** `bitcoin-core/src/validation.cpp::MaybeUpdateMempoolForReorg`
(full per-tx revalidation populates fee/feeRate/sigOpCost from real
input lookups; never uses sentinels).

**Impact:** RPC output lies about refilled txs; RBF against refilled
txs computes wrong premium; mining score 0 sends refilled txs to the
bottom of mining selection (correct for "we don't know fee, defer to
paying txs", but Core never has this problem because Core revalidates
properly).

---

## BUG-23 (P1) — `removeForBlock` does NOT trigger rolling-fee decay reset until next `getMinFee()` call

**Severity:** P1. `removeForBlock` (mempool.ts:2407-2408) sets:
```ts
this.lastRollingFeeUpdate = Math.floor(Date.now() / 1000);
this.blockSinceLastRollingFeeBump = true;
```
This is correct per Core (txmempool.cpp:426-427). However, the flag is
only consumed inside `getMinFee()` (line 3243-3278) which is lazy. Until
someone calls `getMinFee()` again, the rolling-min stays at whatever it
was. If `getMinFee()` is called every block via `feefilter` periodic
sender (which doesn't run — BUG-15) or via `getmempoolinfo` (which is
called by external monitoring), decay happens; otherwise it doesn't.

Compared to Core (which also decays lazily inside `GetMinFee`), this is
correct. **BUT** combined with BUG-15 (no feefilter periodic sender),
the only thing that triggers decay is `getmempoolinfo` RPC calls and
admission attempts. Long stretches of low admission activity leave the
rolling-min effectively frozen.

**File:** `src/mempool/mempool.ts:2407-2408, 3243-3278`.

**Core ref:** `bitcoin-core/src/txmempool.cpp:426-427, 829-851`.

**Impact:** subtle — rolling-min decays only when something queries it,
so periods of low traffic leave the floor higher than Core would have.
Marginal effect.

---

## BUG-24 (P2) — `Mempool` constructor has no parameter for incremental-relay-fee or min-relay-fee

**Severity:** P2 (API ergonomics). `Mempool` constructor (mempool.ts:1211-1236)
takes `(utxo, params, maxSize, notificationEmitter)`. The four operator
knobs `-maxmempool`, `-mempoolexpiry`, `-minrelaytxfee`,
`-incrementalrelayfee` map to:
- `maxSize` (passable, but cli.ts:1541 doesn't pass it),
- expiry: hardcoded constant (BUG-19),
- minRelayFee: hardcoded `DEFAULT_MIN_FEE_RATE = 0` (BUG-5),
- incrementalRelayFee: hardcoded `DEFAULT_INCREMENTAL_RELAY_FEE = 0.1`
  (BUG-6).

The setters (`setMaxSize` doesn't exist, `setMinFeeRate`, `setIncrementalRelayFee`)
are usable post-construction but cli.ts doesn't use them. Adding the
operator knobs (BUG-5, BUG-6, BUG-19) would require either passing them
through the constructor or wiring CLI → setter post-construction.

**File:** `src/mempool/mempool.ts:1211-1236, 3389-3416`.

**Core ref:** `bitcoin-core/src/kernel/mempool_options.h::MemPoolOptions`
(opts struct passed at construction).

**Impact:** API ergonomics; closely tied to BUG-5/BUG-6/BUG-19.

---

## Summary

**Bug count:** 24 (BUG-1 through BUG-24).

**Severity distribution:**
- **P0-CDIV:** 13 (BUG-1, BUG-2, BUG-4, BUG-5, BUG-6, BUG-7, BUG-8,
  BUG-11, BUG-12, BUG-13, BUG-14, BUG-15, BUG-16)
- **P0-WIRING:** 1 (BUG-9 — carry-forward W141 + W152 BUG-18 verified
  regression-locked open)
- **P1:** 9 (BUG-3, BUG-10, BUG-17, BUG-18, BUG-19, BUG-20, BUG-21,
  BUG-23)

Wait, P1 count: BUG-3, BUG-10, BUG-17, BUG-18, BUG-19, BUG-20, BUG-21,
BUG-23 = 8. Plus P2: BUG-22, BUG-24 = 2. Total: 13 + 1 + 8 + 2 = 24. ✓

**Fleet patterns confirmed:**
- **"Assume-valid scope creep"** (W145 carry-forward): UNFIXED in
  W145/W153 timeframe — not directly in scope of W153 but observed at
  mempool.ts:1208-1209 (`headerSync` setter exists, gated on
  `shouldSkipScripts`, comment admits "will always return verify scripts
  since they are above the assumevalid height" — dead-data plumbing).
- **"Two-pipeline guard 17th distinct extension"** (BUG-12): two
  connect paths (`chain/state.ts::connectBlock` vs
  `sync/blocks.ts::connectBlock`) with non-symmetric side-effect sets;
  the production-default path (sync/blocks.ts) is the one that's
  missing the emit. First W153 instance.
- **"Comment-as-confession"** (BUG-6 line 573 "Bug fixed: was 1 sat/vB
  (10× too high)"; BUG-9 regression test that locks the wiring gap in
  place; BUG-12 inline comment at mempool.ts:1206 admits the
  dead-data nature of the assumevalid setter) — 9th-11th distinct
  hotbuns instances.
- **"Wiring-look-but-no-wire"** (BUG-9, BUG-14, BUG-15, BUG-21): four
  W153 instances — ZMQ defined-but-unwired (BUG-9), prioritisetransaction
  format-known-but-no-RPC (BUG-14), FeeFilterManager constructed-but-no-interval
  (BUG-15), -blocknotify CLI-absent (BUG-21). Cumulative hotbuns instances:
  9.
- **"Dead-data plumbing"** (BUG-4 expire(), BUG-14 mapDeltas read-only,
  BUG-20 unbroadcast read-only, BUG-17 hardcoded RPC field): 4 W153
  instances.
- **"Constant defined / API shipped / no production path uses it"**
  (BUG-4 expire dead; BUG-5 setMinFeeRate never called; BUG-19
  MEMPOOL_EXPIRY_SECONDS constant referenced only by dead helper).
- **"RPC field lies about runtime value"** (BUG-17): four fields lie
  in getmempoolinfo + four in `/rest/mempool/info.json`.
- **"FeeFilter never sent in production fleet-wide"** (BUG-15): hotbuns
  joins 6 of 10 impls (W134/W136). Hotbuns confirmed as 6th.
- **"-*notify operator knobs absent fleet pattern"** (BUG-21): hotbuns
  joins 7 of 10 impls per W141. Hotbuns confirmed as 8th.

**Top three findings:**

1. **BUG-12 (P0-CDIV — `sync/blocks.ts` connect path never emits
   `blockConnected`)**: the IBD and normal-sync block-reception path
   silently bypasses the fee estimator, orphan pool sweep, orphan
   cascade-promote, and ZMQ block-event fan-out. During the entire 10+
   hour mainnet IBD, NONE of these handlers fire. Post-IBD, the same
   gap stays open because peer-sourced blocks still go through
   `sync/blocks.ts::connectBlock`, not `chain/state.ts::connectBlock`.
   The only thing that fires the handlers is regtest `generateblock` and
   the `invalidateblock` / `reconsiderblock` RPCs — i.e., the test-suite
   shape masks the production bug. Cross-cite BUG-13 (the same
   `chain/state.ts::reorganize` doesn't refill mempool either —
   symmetric gap on the opposite side, where the IBD path DOES the
   right thing and the RPC path doesn't).

2. **BUG-7 + BUG-8 + BUG-16 cluster (no `MemPoolRemovalReason` + no
   `removeTx` hook + `removeForBlock` doesn't emit per-tx)**: hotbuns
   has no concept of removal reason; the fee estimator never gets told
   about evictions; and the most common removal case (tx got mined) is
   the one that doesn't emit per-tx `txRemoved` events. The combination
   means the fee estimator's `txEntryHeights` map is polluted with
   long-ago-evicted txs forever, ZMQ subscribers can't reconcile their
   mempool view incrementally, and Core's six-way distinction
   (EXPIRY/SIZELIMIT/REORG/BLOCK/CONFLICT/REPLACED) is collapsed to
   "removed" with no further differentiation.

3. **BUG-5 + BUG-6 cluster (`DEFAULT_MIN_RELAY_TX_FEE = 0` and
   `DEFAULT_INCREMENTAL_RELAY_FEE = 0.1 sat/vB`)**: hotbuns ships with
   **zero min-relay-fee floor** and **10× too low incremental relay
   fee**. Net effect: hotbuns admits 1-satoshi-fee txs that Core
   rejects (cross-fleet relay-graph spam), allows 10× cheaper RBF
   churn cycles than Core operators expect, ramps up its TrimToSize
   rolling-min 10× slower under fee pressure, and lies about the actual
   value in `getmempoolinfo` / `/rest/mempool/info.json`. The inline
   comment at mempool.ts:573 — "Bug fixed: was 1 sat/vB (10× too high)"
   — is a textbook **comment-as-confession** that a previous fix
   went in the wrong direction.
