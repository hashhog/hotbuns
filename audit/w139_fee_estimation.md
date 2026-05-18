# W139 — Fee estimation engine (CBlockPolicyEstimator) audit (hotbuns)

**Impl:** hotbuns (TypeScript / Bun)
**Date:** 2026-05-18
**Status:** DISCOVERY — 23 BUGS / 30 gates
**Tests:** `src/__tests__/w139_fee_estimation.test.ts` (assertion-only, no
production code changes).
**No production code changes in this wave.**

## Reference

- `bitcoin-core/src/policy/fees/block_policy_estimator.h` —
  `CBlockPolicyEstimator` (3 horizon `TxConfirmStats`), `FeeEstimateHorizon`,
  `FeeReason`, `EstimatorBucket`, `EstimationResult`, `FeeCalculation`,
  `FEE_FLUSH_INTERVAL = 1h`, `MAX_FILE_AGE = 60h`,
  `DEFAULT_ACCEPT_STALE_FEE_ESTIMATES = false`,
  `FeeFilterRounder` (`MAX_FILTER_FEERATE = 1e7`, `FEE_FILTER_SPACING = 1.1`).
- `bitcoin-core/src/policy/fees/block_policy_estimator.cpp` —
  `CURRENT_FEES_FILE_VERSION = 309900`, `INF_FEERATE = 1e99`,
  bucket constants (`SHORT_BLOCK_PERIODS=12`, `SHORT_SCALE=1`,
  `SHORT_DECAY=0.962`; `MED_BLOCK_PERIODS=24`, `MED_SCALE=2`,
  `MED_DECAY=0.9952`; `LONG_BLOCK_PERIODS=42`, `LONG_SCALE=24`,
  `LONG_DECAY=0.99931`; `OLDEST_ESTIMATE_HISTORY = 6*1008 = 6048`;
  `HALF_SUCCESS_PCT=.6`; `SUCCESS_PCT=.85`; `DOUBLE_SUCCESS_PCT=.95`;
  `SUFFICIENT_FEETXS=0.1`; `SUFFICIENT_TXS_SHORT=0.5`;
  `MIN_BUCKET_FEERATE=100`; `MAX_BUCKET_FEERATE=1e7`;
  `FEE_SPACING=1.05`), `TxConfirmStats` (`txCtAvg`, `confAvg[Y][X]`,
  `failAvg[Y][X]`, `m_feerate_avg`, `unconfTxs[Y][X]`, `oldUnconfTxs[X]`),
  `processTransaction`, `processBlock / processBlockTx`,
  `estimateSmartFee` (HALF→FULL→DOUBLE 3-tier with conservative),
  `estimateCombinedFee` (cross-horizon downgrade),
  `estimateConservativeFee`, `MaxUsableEstimate`,
  `FlushUnconfirmed`, `Write` / `Read` (binary on-disk).
- `bitcoin-core/src/policy/feerate.h` / `feerate.cpp` —
  `CFeeRate` (sat/kvB internally; `GetFeePerK`, `GetFee(virtual_bytes)`).
- `bitcoin-core/src/rpc/fees.cpp` —
  `estimatesmartfee` (clamps via `ParseConfirmTarget` which THROWS on
  out-of-range, floors with `min_mempool_feerate` + `min_relay_feerate`,
  returns `feerate` in BTC/kvB), `estimaterawfee` (per-horizon pass/fail
  buckets, `threshold` default 0.95).
- `bitcoin-core/src/rpc/util.cpp:369` — `ParseConfirmTarget` throws
  `RPC_INVALID_PARAMETER` if `target < 1 || target > max_target`.

BIPs: **none** (CBlockPolicyEstimator is a Core-internal estimator,
not a BIP. BIP-133 feefilter is W136 territory; this wave covers only
the fee-estimation engine + estimaterawfee/estimatesmartfee RPCs.)

## Background

`CBlockPolicyEstimator` is Core's historical-data fee estimator. It
groups admitted mempool transactions into ~155 exponentially-spaced
fee-rate buckets, tracks how long each takes to confirm in three
parallel sets of `TxConfirmStats` (short/medium/long), and surfaces
estimates via `estimatesmartfee` / `estimaterawfee` RPCs and the
wallet's `feebumper` + coin-selection paths.

The algorithm starts at the highest fee-rate bucket and walks down
until it finds a bucket whose empirical
`confirmed-within-target / (confirmed + still-unconfirmed-or-failed)`
fraction meets a threshold. Three thresholds are tried (60% at T/2,
85% at T, 95% at 2T), and the maximum estimate is returned. In
conservative mode, the 95% threshold at 2T is also verified against
longer horizons.

Two key shapes:
- `TxConfirmStats` keeps **decay-accumulated** moving averages
  `confAvg[period][bucket]` and `failAvg[period][bucket]`, plus a
  **circular buffer** `unconfTxs[blockHeight % bins][bucket]` for
  currently-unconfirmed txs. On every block, all `confAvg/failAvg`
  arrays are multiplied by `decay` and the circular slot for the new
  height is reset.
- Bucket boundaries are **MIN_BUCKET_FEERATE=100 sat/kvB **(== 0.1
  sat/vB)** × FEE_SPACING=1.05 up to MAX_BUCKET_FEERATE=1e7 sat/kvB**
  (== 10000 sat/vB), giving ~235 buckets. **Hotbuns hardcodes ~41
  buckets in sat/vB.**

## Hotbuns architecture

Hotbuns's fee estimator lives in `src/fees/estimator.ts` (767 LOC).
Public surface:

| Helper | Role | Reference |
|--------|------|-----------|
| `FeeEstimator(mempool)` | constructor; loads `BUCKET_BOUNDARIES` | `block_policy_estimator.cpp:543` |
| `trackTransaction(txid, height)` | record tx entering mempool | `processTransaction` |
| `recordConfirmation(txid, feeRate, entryH, confirmH)` | per-tx confirmation | `processBlockTx` |
| `processBlock(block, height)` | drive estimator on chain-tip block | `processBlock` |
| `estimateFee(targetBlocks)` | scalar estimate, shared-bucket | `estimateRawFee` |
| `estimateSmartFee(targetBlocks)` | smart estimate w/ horizon dispatch | `estimateSmartFee` |
| `getBuckets()` | shared bucket view (medium-horizon) | — |
| `getTrackedCount()` | active mempool tracker count | — |
| `serialize() / loadState()` | JSON persistence (NOT byte-compat) | `Write / Read` |
| `clear()` | reset (test only) | — |

RPC methods exposed from `src/rpc/server.ts`:

- `estimatesmartfee` (4034)
- `estimaterawfee` (4072)

No `getmempoolinfo`-side `mempoolminfee` floor on smartfee returns,
no `estimate_mode` (conservative/economical) handling, no
`FlushUnconfirmed`, no scheduled flush, no `FeeFilterRounder`
privacy quantization for BIP-133 feefilter announcements.

## Audit summary

Total: **23 BUGS / 30 gates** across four priority bands. Most are
algorithmic divergences from Core, not encoder/wire bugs (no BIPs
in scope), but they all affect the **numerical accuracy and shape**
of `estimatesmartfee` / `estimaterawfee` responses that wallets and
fee-daemons consume.

- **P0-CDIV** (correctness divergence at the per-block decision level)
  — **6 bugs**: G3 (bucket boundaries shape), G6 (no `m_feerate_avg`
  per bucket → estimate returns bucket-min not average), G8 (no
  per-period `confAvg[Y][X]` matrix — single scalar `confirmed` count
  loses Y-axis), G9 (no `failAvg` tracking — txs that leave mempool
  without confirming don't penalize the bucket), G14 (no
  conservative/HALF-FULL-DOUBLE 3-tier — uses single 0.85 threshold),
  G23 (RPC out-of-range silently clamps instead of throwing
  `RPC_INVALID_PARAMETER`).
- **P1-API** (missing method/role coverage that downstream RPC
  consumers rely on) — **9 bugs**: G7 (no `unconfTxs[Y][X]` ring
  buffer + `oldUnconfTxs[X]` aging path), G11 (no
  `MaxUsableEstimate` clamp via `BlockSpan / HistoricalBlockSpan`),
  G12 (no `estimateCombinedFee` cross-horizon downgrade), G15
  (no `mempoolminfee` / `min_relay_feerate` floor on smartfee),
  G18 (no `FlushUnconfirmed` on shutdown), G19 (no
  `FEE_FLUSH_INTERVAL` scheduled flush), G20 (no `MAX_FILE_AGE`
  staleness check on load), G21 (no `validForFeeEstimation` tx
  filter — no mempool-limit-bypassed / submitted-in-package /
  chainstate-not-current / has-mempool-parents gating), G24 (no
  `FeeFilterRounder` privacy quantization for BIP-133).
- **P1-WIRE** (encoded shape / output mismatch vs Core) — **5 bugs**:
  G16 (estimatesmartfee response missing `returnedTarget` ≠
  `desiredTarget` distinction), G22 (estimaterawfee `inmempool`
  field reports `hb.unconfirmed` aggregate not per-period
  `unconfTxs[periodTarget+]` slot sum), G25 (no
  `CURRENT_FEES_FILE_VERSION = 309900` version constant in
  `serialize`), G26 (`serialize()` emits JSON not the binary
  `AutoFile` shape Core's `fee_estimates.dat` uses — no fleet
  interop), G27 (`estimaterawfee` returns `errors` array shape
  inconsistent with Core when fail.startrange == -1).
- **P2-CONSISTENCY** (internal cleanups / param fidelity) — **3 bugs**:
  G2 (fallback `DEFAULT_FEE_RATE = 20 sat/vB` returned when no
  data — Core returns `CFeeRate(0)` to signal error), G13 (no
  `estimate_mode` param parsing — `conservative` ignored), G29
  (`estimaterawfee` `withintarget` is `Math.round(within*100)/100`
  but `within` is an int from `Array.filter().length` not a
  decay-accumulated float — Core's value IS the decay-accumulated
  `nConf` from `EstimateMedianVal`, so the rounding is meaningless
  for integers).

Decay constants (G1), per-horizon scale + periods (G4), and the
3-horizon partition (G5) are PRESENT and byte-matching with Core.
Three more gates pass: G10 (side-chain block skip is a near-parity
but with a subtle bug — see G10), G17 (`estimaterawfee` overall
shape matches Core's per-horizon JSON tree), G28 (the
`processBlock` cleanup of orphans is parity).

## Gate map

### Constants and basic shape

#### G1 — Per-horizon decay constants (SHORT=.962 / MED=.9952 / LONG=.99931)
**Status: PRESENT.** `estimator.ts:75-79`:
```
[Horizon.Short]:  0.962,
[Horizon.Medium]: 0.9952,
[Horizon.Long]:   0.99931,
```
Byte-identical to `block_policy_estimator.h:163-167`
(`SHORT_DECAY=.962`, `MED_DECAY=.9952`, `LONG_DECAY=.99931`).

#### G2 — `DEFAULT_FEE_RATE = 20 sat/vB` fallback
**Status: PARTIAL — BUG-1 (P2-CONSISTENCY).** `estimator.ts:54`:
`DEFAULT_FEE_RATE = 20`. Returned by `estimateFee` (line 487) and
`estimateSmartFee` (line 609) when no data is available. Core
returns `CFeeRate(0)` to signal an error (`block_policy_estimator.cpp:751`
`return CFeeRate(0);` and `:887`), and the RPC layer reports
`errors: ["Insufficient data or no feerate found"]` with NO
`feerate` field. Hotbuns silently returns 20 sat/vB which a wallet
could interpret as a valid estimate. The RPC layer at `server.ts:4045`
DOES check `if (!estimate.feeRate || estimate.feeRate <= 0)` and
returns the error shape, but a downstream caller of
`feeEstimator.estimateSmartFee` directly (not via RPC) would get the
20 sat/vB fallback. P2 because the RPC surface masks it.

#### G3 — Bucket boundaries (MIN_BUCKET_FEERATE × FEE_SPACING^k → MAX_BUCKET_FEERATE)
**Status: PARTIAL — BUG-2 (P0-CDIV).** `estimator.ts:136-140`:
```
const BUCKET_BOUNDARIES = [1, 2, 3, 4, 5, 6, 7, 8, 10, 12, 14, 17, 20,
  25, 30, 40, 50, 60, 70, 80, 100, 120, 140, 170, 200, 250, 300, 400,
  500, 600, 700, 800, 1000, 1200, 1400, 1700, 2000, 3000, 5000, 7000,
  10000];
```
That's 41 hand-picked buckets in **sat/vB**. Core
(`block_policy_estimator.cpp:549`) builds **~235 buckets** in
**sat/kvB** by iterating
`for (bucketBoundary = 100; bucketBoundary <= 1e7; bucketBoundary *=
1.05; ...)`, plus a final `INF_FEERATE = 1e99` sentinel. The unit
mismatch is doubly painful: hotbuns 1 sat/vB == 1000 sat/kvB which
Core would place between bucket #50 and #51. The shape mismatch is
**~6× coarser** at low feerates (where most mainnet relay traffic
sits — 1-30 sat/vB) and **~50× coarser** at the high end. A median
feerate that Core's algorithm finds in bucket #143 (1000 sat/kvB)
becomes hotbuns's bucket #32 (1000 sat/vB == 1e6 sat/kvB) — six
orders of magnitude apart. Round-trip estimateSmartFee output WILL
disagree with Core under load. P0-CDIV.

#### G4 — Per-horizon scale (SHORT=1 / MED=2 / LONG=24)
**Status: PRESENT.** `estimator.ts:85-89` matches
`block_policy_estimator.h:152,155,158` (`SHORT_SCALE=1`,
`MED_SCALE=2`, `LONG_SCALE=24`). Hotbuns's `PERIODS`
(`estimator.ts:98-102`) — 12 / 24 / 42 — matches
`SHORT_BLOCK_PERIODS=12` / `MED_BLOCK_PERIODS=24` /
`LONG_BLOCK_PERIODS=42` at `block_policy_estimator.h:151,154,157`.
Coverage 12 / 48 / 1008 blocks parity.

#### G5 — Three-horizon partition (short / medium / long)
**Status: PRESENT.** Hotbuns has a `Horizon` enum (`estimator.ts:65-69`)
and the constructor instantiates three `HorizonStats` records
(`estimator.ts:187-191`), matching Core's `feeStats / shortStats /
longStats` triplet (`block_policy_estimator.h:294-296`).

### TxConfirmStats algorithm shape

#### G6 — `m_feerate_avg[bucket]` — per-bucket decay-accumulated feerate sum
**Status: MISSING — BUG-3 (P0-CDIV).** Core
(`block_policy_estimator.cpp:100,228`) tracks
`m_feerate_avg[bucketindex] += feerate` on every Record() and decays
it with the moving average. The estimate IS the median bucket's
**average feerate** (`block_policy_estimator.cpp:362`:
`median = m_feerate_avg[j] / txCtAvg[j];`). Hotbuns has no
equivalent: `estimateFee` returns `bucket.feeRateRange.min`
(`estimator.ts:476`), the bucket's **lower boundary**, not the
empirical average. Given hotbuns's coarse 41-bucket layout
(BUG-2), the lower-boundary skew is large — a tx mix concentrated
near the upper end of a bucket reports as the lower end, biasing
estimates downward 5-50%. P0-CDIV.

#### G7 — `unconfTxs[Y][X]` circular ring buffer + `oldUnconfTxs[X]` rollover
**Status: MISSING — BUG-4 (P1-API).** Core's `TxConfirmStats`
keeps `unconfTxs[blockHeight % bins][bucketindex]` as a
`vector<vector<int>>` (`block_policy_estimator.cpp:113`). On every
new block, `ClearCurrent(nBlockHeight)` rolls the slot:
`oldUnconfTxs[j] += unconfTxs[height % bins][j]; unconfTxs[...][j] = 0`
(`block_policy_estimator.cpp:208-214`). The EstimateMedianVal()
function then sums `extraNum += unconfTxs[(height-confct) % bins][bucket]`
for `confct ∈ [confTarget, GetMaxConfirms())` plus
`oldUnconfTxs[bucket]` — i.e., the count of txs **older than
confTarget** specifically. Hotbuns keeps a single scalar
`hb.unconfirmed` per (horizon, bucket) (`estimator.ts:109-116`) and
**decays it on every applyDecay() call** (line 399). This means
hotbuns's "still-unconfirmed" count is a continuous exponential,
not an aged-bucket count. The numerical estimate is **off by the
unconfirmed-tx age distribution** because the algorithm cannot
distinguish "tx is 2 blocks old" from "tx is 100 blocks old".
P1-API because the surface is internal to `estimateMedianVal`.

#### G8 — `confAvg[Y][X]` per-period confirmation matrix
**Status: MISSING — BUG-5 (P0-CDIV).** Core's `Record(blocksToConfirm,
feerate)` (`block_policy_estimator.cpp:217-229`) computes
`periodsToConfirm = (blocksToConfirm + scale - 1) / scale` and then
`for (i = periodsToConfirm; i <= maxPeriods; i++)
confAvg[i-1][bucket]++` — i.e., a tx confirmed in `n` periods
increments **every** `confAvg[Y][bucket]` slot for Y ≥ n
(cumulative-counter semantic). EstimateMedianVal then reads
`confAvg[periodTarget-1][bucket]` directly — a precomputed
count-of-confirmations-within-target. Hotbuns keeps
**raw `confirmationBlocks: number[]`** per bucket and filters
`blocks <= targetBlocks` on every estimate call (`estimator.ts:435-437`).
That's three correctness divergences:
1. **No decay on the count**: hotbuns counts are integer additions
   into an array; Core's are floats that exponentially decay every
   block.
2. **O(N) per estimate**: hotbuns walks the full array; Core's is
   O(1) lookup.
3. **Eventual array overflow**: hotbuns has an ad-hoc trim at
   length>10000 (line 383) that keeps the LAST 5000, **losing the
   oldest data first** (FIFO). Core decays oldest-first naturally
   via the moving average. Behaviorally: under high mempool churn
   hotbuns "forgets" data abruptly at the trim boundary.
P0-CDIV.

#### G9 — `failAvg[Y][X]` per-period failure (mempool-eviction) matrix
**Status: MISSING — BUG-6 (P0-CDIV).** Core's `removeTx` not in
block path (`block_policy_estimator.cpp:513-519`) increments
`failAvg[i][bucketindex]++` for `i ∈ [0, periodsAgo)` — i.e., a tx
that sat in mempool for `K` periods then got evicted (replaced /
expired / mempool-full / orphaned) is recorded as a **failure** for
all confirmation targets `≥ K`. EstimateMedianVal then includes
`failNum += failAvg[periodTarget-1][bucket]` in the denominator
(`block_policy_estimator.cpp:289`), penalizing the bucket.
Hotbuns has **no failure tracking at all**. When a tx is removed
from mempool without being confirmed, the estimator's
`txEntryHeights.delete()` happens via the orphan-pool / RBF paths
(or just silently when mempool eviction happens — see G21), with no
counter-bump in the bucket. **Effect: hotbuns's estimate stays
artificially optimistic in the face of mempool churn.** Under heavy
load (fee-spike events), Core's estimate correctly rises because
low-fee txs get marked as failures; hotbuns just keeps reporting
the old probability.
P0-CDIV.

#### G10 — `processBlock` side-chain / reorg skip (`nBlockHeight <= nBestSeenHeight`)
**Status: PARTIAL — BUG-7 (P2-CONSISTENCY).** Core
(`block_policy_estimator.cpp:673-680`):
```
if (nBlockHeight <= nBestSeenHeight) return;
```
Hotbuns has **no `nBestSeenHeight` field** in the estimator
(`estimator.ts:150-192`). It calls `applyDecay()` on every
`processBlock` invocation without checking whether the height is
new. The CLI integration (`cli.ts:1810`) drives `processBlock` from
the `chainEvents.on("blockConnected")` listener with
`chainState.getBestBlock().height`, so on a reorg the listener
fires for each disconnect→reconnect cycle, applying decay
**multiple times for the same block height**. This biases stats
downward (forgetting data faster than Core). Mitigation: hotbuns's
single-listener flow is mostly resilient because the chain doesn't
emit reorg events through the same channel — but a hand-driven
`processBlock` from a test or a different path would silently
double-decay. P2 because the CLI flow is OK today; the API surface
is the bug.

### Estimation algorithm

#### G11 — `MaxUsableEstimate` clamp via BlockSpan / HistoricalBlockSpan
**Status: MISSING — BUG-8 (P1-API).** Core
(`block_policy_estimator.cpp:798-802`):
```
unsigned int CBlockPolicyEstimator::MaxUsableEstimate() const {
  return std::min(longStats->GetMaxConfirms(),
    std::max(BlockSpan(), HistoricalBlockSpan()) / 2);
}
```
i.e., you cannot estimate confirmation in `T` blocks unless the
estimator has seen at least `2T` blocks of history. `estimateSmartFee`
clamps `confTarget = std::min(confTarget, MaxUsableEstimate())`
(`:892-894`). Hotbuns has neither `BlockSpan` nor
`HistoricalBlockSpan`; it clamps confTarget only to `[1, 1008]`
(`estimator.ts:421-423` and `server.ts:4041`). A freshly-started
hotbuns will return estimates after a single confirmed tx —
wildly noisy. P1-API.

#### G12 — `estimateCombinedFee` cross-horizon downgrade
**Status: MISSING — BUG-9 (P1-API).** Core
(`block_policy_estimator.cpp:808-842`) at `confTarget > shortMax`
also checks short-horizon's `max-confirms` bucket and **takes the
minimum** (not max) over horizons:
```
if (shortMax > 0 && (estimate == -1 || shortMax < estimate)) {
  estimate = shortMax;
}
```
This preserves monotonicity: estimate for 60-block target should
never be **higher** than estimate for 12-block target. Hotbuns's
`estimateSmartFee` (`estimator.ts:567-610`) picks ONE horizon based
on target and never reconciles with shorter horizons. Effect:
**non-monotonic estimates** are possible — a wallet asking for
"confirm in 1 block" and "confirm in 100 blocks" can get a HIGHER
estimate for 100 blocks if the 100-block bucket happens to be
sparse. Core explicitly prevents this. P1-API.

#### G13 — `estimate_mode` parameter parsing (conservative / economical)
**Status: MISSING — BUG-10 (P2-CONSISTENCY).** Core's
`estimatesmartfee` (`bitcoin-core/src/rpc/fees.cpp:42`) accepts
an `estimate_mode` string (default `economical`); parsed via
`FeeModeFromString` (`common/messages.cpp`). `conservative` toggles
the 3rd-tier longer-horizon check at 2T (described in G14).
Hotbuns ignores it: `server.ts:4034-4056` reads only
`params[0]`. A wallet asking for `["6", "CONSERVATIVE"]` gets the
SAME result as `["6"]` — silently. P2 because the silent fallthrough
masks the missing feature.

#### G14 — `estimateSmartFee` 3-tier HALF/FULL/DOUBLE + max + conservative
**Status: MISSING — BUG-11 (P0-CDIV).** Core
(`block_policy_estimator.cpp:871-955`):
```
halfEst   = estimateCombinedFee(T/2,  HALF_SUCCESS_PCT=.6,  true);
actualEst = estimateCombinedFee(T,    SUCCESS_PCT=.85,       true);
doubleEst = estimateCombinedFee(2*T,  DOUBLE_SUCCESS_PCT=.95, !conservative);
median = max(halfEst, actualEst, doubleEst);
if (conservative || median == -1) {
  consEst = estimateConservativeFee(2*T);
  if (consEst > median) median = consEst;
}
```
Three thresholds at three target depths, MAX over them, then a 4th
conservative check. Hotbuns uses a **single threshold of 0.85**
(`CONFIDENCE_THRESHOLD`, `estimator.ts:57`) at the requested target.
This is the same as Core's `actualEst` alone — `halfEst` and
`doubleEst` are missing, and the `max` semantic is missing. Effect:
hotbuns's estimates can be **lower than Core's** for the same
historical data, because Core's MAX-over-three is by construction
the conservative envelope. The whole `FeeReason` enum
(`HALF_ESTIMATE / FULL_ESTIMATE / DOUBLE_ESTIMATE / CONSERVATIVE /
FALLBACK / REQUIRED / MEMPOOL_MIN`) is also absent — there's no way
for a downstream consumer to learn WHICH of the three estimates
won. P0-CDIV.

#### G15 — `mempoolminfee` / `min_relay_feerate` floor on smartfee return
**Status: MISSING — BUG-12 (P1-API).** Core
(`bitcoin-core/src/rpc/fees.cpp:82-86`) immediately after
`estimateSmartFee` returns:
```
CFeeRate min_mempool_feerate{mempool.GetMinFee()};
CFeeRate min_relay_feerate{mempool.m_opts.min_relay_feerate};
feeRate = std::max({feeRate, min_mempool_feerate, min_relay_feerate});
```
Without this floor, an estimate **below** the dynamic mempool
minimum gets returned, the wallet builds a tx at that rate, and
the tx gets REJECTED at relay. Hotbuns's RPC layer
(`server.ts:4034-4056`) returns the raw estimator value with no
floor. Hotbuns's `mempool.getMinFee()` DOES exist (`mempool.ts:3243`)
but it's not consulted by the fee RPC. P1-API.

#### G16 — `desiredTarget` vs `returnedTarget` distinction
**Status: PARTIAL — BUG-13 (P1-WIRE).** Core's `FeeCalculation`
struct (`block_policy_estimator.h:90-97`) tracks `desiredTarget`
(input) and `returnedTarget` (final after clamp). `estimateSmartFee`
returns `result.pushKV("blocks", feeCalc.returnedTarget)` — the
ACTUAL target used after MaxUsableEstimate clamp. Hotbuns
`estimateSmartFee` returns `blocks: targetBlocks` from the
**dispatch-time** target (after a `longerTargets` fallback loop
that returns `target` from inside the loop). The "blocks" field
sometimes equals the requested target (when data is sufficient),
sometimes equals a different target (when fallback runs), but
there's no record of the original `desiredTarget` separately. Core
ALWAYS returns the original `confTarget` value in
`feeCalc.desiredTarget` (used for the RPC clamp warning). Hotbuns
collapses the two. P1-WIRE.

### estimaterawfee RPC

#### G17 — `estimaterawfee` per-horizon JSON tree shape
**Status: PRESENT.** `server.ts:4188-4192` returns
`{ short, medium, long }` objects, each with
`{ feerate?, decay, scale, pass?, fail?, errors? }`. Matches Core's
`bitcoin-core/src/rpc/fees.cpp:170-212` per-horizon walk. The
`decay` and `scale` constants are present even on insufficient-data
(line 4170-4179), matching Core's `:204-206`.

#### G18 — `FlushUnconfirmed` on shutdown
**Status: MISSING — BUG-14 (P1-API).** Core
(`block_policy_estimator.cpp:1064-1076`) iterates every entry in
`mapMemPoolTxs` and calls `_removeTx(..., inBlock=false)` —
i.e., records every still-mempool tx as a FAILURE before shutdown.
This is correct because at shutdown, those txs haven't confirmed
within their tracking window. Without it, a long-running node with
chronic low-feerate-tx churn would persist a biased estimate.
Hotbuns has no equivalent — the estimator state at shutdown still
shows all those unconfirmed txs as "in flight". P1-API.

#### G19 — `FEE_FLUSH_INTERVAL = 1 hour` scheduled flush
**Status: PARTIAL — BUG-15 (P1-API).** Core
(`block_policy_estimator.h:26`):
`static constexpr std::chrono::hours FEE_FLUSH_INTERVAL{1};`
Wired in `init.cpp:1662`:
`scheduler.scheduleEvery([fee_estimator] {
  fee_estimator->FlushFeeEstimates(); }, FEE_FLUSH_INTERVAL);`
Hotbuns DOES call `feeEstimator.serialize()` ONCE at shutdown
(`cli.ts:2275`) but has **no periodic persistence** — no
`setInterval` / `scheduleEvery` driver. State is lost on every
ungraceful exit (SIGKILL, OOM, panic), and on a graceful shutdown
the writes happen at the wrong cadence (one big write at the end
instead of 1-hour increments). P1-API.

#### G20 — `MAX_FILE_AGE = 60 hours` + `DEFAULT_ACCEPT_STALE_FEE_ESTIMATES`
**Status: MISSING — BUG-16 (P1-API).** Core
(`block_policy_estimator.h:32,35`) refuses to load
`fee_estimates.dat` if its file age > 60 hours unless
`-acceptstalefeeestimates=1` is passed. Stale estimates are worse
than no estimates. Hotbuns's `loadState` (`estimator.ts:720-749`)
unconditionally restores whatever bytes the caller hands it —
nothing checks file mtime. P1-API.

#### G21 — `validForFeeEstimation` filter in processTransaction
**Status: MISSING — BUG-17 (P1-API).** Core
(`block_policy_estimator.cpp:619-625`) skips tx tracking when:
1. `m_mempool_limit_bypassed` (priority-admitted, didn't pay
   mempool min fee).
2. `m_submitted_in_package` (CPFP package; child's fee isn't this
   tx's fee).
3. `!m_chainstate_is_current` (during IBD or a temporary reorg).
4. `!m_has_no_mempool_parents` (CPFP child whose ancestor's fee
   contributes — feerate is misleading on its own).
Tracked-tx count goes to `untrackedTxs` for the log message but
nothing else. Hotbuns's `trackTransaction` (`estimator.ts:251-271`)
has NO such filter. Every tx goes into the buckets, including
package members and pre-IBD-complete entries — biasing low-feerate
data because CPFP children with `feeRate` close to zero (paid by
parent) get counted. The CLI integration guards on IBD complete
(`cli.ts:1857: if (!blockSync.isIBDComplete()) return;`) for the
mempool-acceptance path, but `feeEstimator.trackTransaction` is
also called directly. Within mempool admission proper, no
"submitted in package" or "has mempool parents" gate exists.
P1-API.

#### G22 — `estimaterawfee` `inmempool` field semantic
**Status: PARTIAL — BUG-18 (P1-WIRE).** Core
(`block_policy_estimator.cpp:289-292`) computes
`extraNum = sum(unconfTxs[(height-confct) % bins][bucket]
              for confct in [confTarget, GetMaxConfirms()))`
**plus** `oldUnconfTxs[bucket]` — i.e., txs aged AT LEAST
`confTarget` blocks in the mempool. The pass/fail bucket
`inMempool` field IS this aged count. Hotbuns
(`server.ts:4152`) emits `hb.unconfirmed` — the **total** decayed
unconfirmed count for the bucket, regardless of age. Effect: at a
6-block target, hotbuns reports as `inmempool` the txs aged 1-6
blocks AND 7+ blocks; Core only reports the 6+ block ones.
hotbuns's number is always ≥ Core's. A consumer trying to detect
fee-bump pressure (high `inmempool` count for a bucket → many
old unconfirmed txs at that rate → next block likely to confirm
them, future estimates can shift) sees a different signal.
P1-WIRE.

#### G23 — `ParseConfirmTarget` throws on out-of-range
**Status: PARTIAL — BUG-19 (P0-CDIV).** Core
(`bitcoin-core/src/rpc/util.cpp:369-377`) throws
`RPC_INVALID_PARAMETER` ("Invalid conf_target, must be between 1
and N") if the target is < 1 or > `max_target` (where `max_target
= HighestTargetTracked(LONG_HALFLIFE) = 1008`). Hotbuns
(`server.ts:4041`):
```
const confTarget = Math.max(1, Math.min(1008, confTargetParam));
```
**silently clamps**. A caller passing `conf_target = -1` or
`conf_target = 5000` gets back an estimate (after clamping to 1
or 1008 respectively) instead of an error. Wallets / fee-daemons
relying on Core's error to detect mistuned config never trip.
Affects both `estimatesmartfee` (line 4041) and `estimaterawfee`
(line 4081). P0-CDIV because RPC error contract is part of
behavior.

### Persistence + side-effects

#### G24 — `FeeFilterRounder` privacy quantization for BIP-133
**Status: MISSING — BUG-20 (P1-API).** Core's BIP-133 feefilter
broadcast quantizes the per-peer announced fee via
`FeeFilterRounder::round(currentMinFee)`
(`block_policy_estimator.cpp:1109-1119`). The set of allowed
output values is `MakeFeeSet(min_incremental_fee,
MAX_FILTER_FEERATE=1e7, FEE_FILTER_SPACING=1.1)` — exponentially
spaced rounding **with a random 2/3 down-rounding bias**. This
makes it harder for an observer to fingerprint which Core build /
which mempool size the peer has. Hotbuns
(`p2p/feefilter.ts:80-87`) sends the raw `currentFeeRate` value.
A privacy-sensitive operator can fingerprint a hotbuns node
because the announced feefilter has continuous-resolution
sat/kvB values rather than quantized buckets. P1-API.

#### G25 — `CURRENT_FEES_FILE_VERSION = 309900` constant
**Status: MISSING — BUG-21 (P1-WIRE).** Core
(`block_policy_estimator.cpp:37`) has a static version number
written at the head of `fee_estimates.dat` and rejects newer files
on read (`:1008-1011`). Hotbuns's `serialize()` emits raw JSON —
no version constant exists. If the JSON schema changes between
hotbuns releases (e.g., add a field), older builds will silently
accept whatever shape comes through, possibly mis-parsing. P1-WIRE.

#### G26 — `fee_estimates.dat` binary format compatibility
**Status: MISSING — BUG-22 (P1-WIRE).** Core's `Write` /
`Read` (`block_policy_estimator.cpp:978-1062`) use binary
`AutoFile` streaming with `EncodedDoubleFormatter` for doubles.
Format: `version || nBestSeenHeight || historicalFirst || historicalBest
|| buckets || feeStats.Write || shortStats.Write || longStats.Write`.
Hotbuns emits JSON via `JSON.stringify(state)`
(`estimator.ts:702-715`). No fleet-interop — a hotbuns node
restarted with a Core-generated `fee_estimates.dat` cannot load
it (and vice-versa). Core's binary format is well-documented;
hotbuns chose a divergent persistence shape. P1-WIRE.

#### G27 — `errors` array when no pass bucket
**Status: PARTIAL — BUG-23 (P1-WIRE).** Core
(`bitcoin-core/src/rpc/fees.cpp:202`):
```
// buckets.fail.start == -1 indicates that all buckets passed,
// there is no fail bucket to output
if (buckets.fail.start != -1) horizon_result.pushKV("fail", ...);
```
i.e., when EVERY bucket passes the threshold, `fail` is **omitted**
from the response. Hotbuns
(`server.ts:4175-4177`):
```
if (fail.startrange !== -1) {
  result.fail = fail;
}
```
matches that semantic. **HOWEVER:** when no pass bucket is found
AND no fail bucket was recorded, Core emits BOTH
`fail: {startrange:-1, endrange:-1, ...}` (raw struct) AND
`errors: [...]`. Hotbuns at `:4178-4183` emits only the all-zero
`fail` and an `errors`. The numeric -1 for `start` in Core comes
from `EstimatorBucket{}` defaults (`block_policy_estimator.h:73-74`).
Hotbuns's hardcoded `startrange: -1` initial value works, but the
`endrange: -1` initial value is shadowed by the explicit
assignment `endrange: Number.isFinite(...) ? max : -1`. **The bug
is subtle**: the final-bucket case `feeRateRange.max = Infinity`
gets emitted as `endrange: -1`, which is a Core-style "no end"
sentinel. But the hotbuns Range goes 7000 → Infinity for the top
bucket, whereas Core's buckets[N] = 1e7 and buckets[N+1] =
1e99 (INF_FEERATE). Core's `passBucket.end = buckets[maxBucket];`
emits **a real numeric `endrange = 1e99`** for the top bucket,
which clients can compare to. Hotbuns emits -1 in that case, a
sentinel that clients have to interpret. P1-WIRE.

#### G28 — `processBlock` cleanup of stale `txEntryHeights`
**Status: PRESENT.** `estimator.ts:361-367`:
```
const maxAge = MAX_CONFIRMATION_BLOCKS * 2;
for (const [txidHex, entryHeight] of this.txEntryHeights) {
  if (height - entryHeight > maxAge) {
    this.txEntryHeights.delete(txidHex);
  }
}
```
Matches Core's intent (orphan-out the mapMemPoolTxs entry when
the tx has been in mempool longer than `GetMaxConfirms()` —
typically 1008 blocks). Bound is 2× max confirms vs Core's
1× — slightly more lenient but not wrong.

#### G29 — `estimaterawfee` `withintarget` rounding
**Status: PARTIAL — BUG (cosmetic, BUG count covered).** Core
(`bitcoin-core/src/rpc/fees.cpp:183`):
`round(buckets.pass.withinTarget * 100.0) / 100.0` — rounds to
2 decimal places because Core's value IS a decay-accumulated
**float**. Hotbuns
(`server.ts:4150`): `Math.round(within * 100) / 100` where
`within = filter().length` (an integer). Rounding an integer ×100
to 2 decimals is a no-op. Internal consistency: hotbuns is
producing integers where Core produces floats. Not a separate
BUG (counted under G8/G7 — the per-period count matrix is the
upstream issue), but reported here so a future fix wave is aware
the surface is misleading. **No new BUG number assigned.**

#### G30 — Hotbuns-specific: `recordConfirmation` accepts untracked txids
**Status: PARTIAL — meta-bug, covered by G21.** `recordConfirmation`
(`estimator.ts:278-321`) increments `confirmed += 1` and pushes to
`confirmationBlocks` whether or not the txid was in
`txEntryHeights`. Core's `processBlockTx`
(`block_policy_estimator.cpp:641-647`):
```
if (!_removeTx(tx.info.m_tx->GetHash(), true)) {
  // This transaction wasn't being tracked for fee estimation
  return false;
}
```
short-circuits if the tx isn't in `mapMemPoolTxs`. Hotbuns's
caller (`processBlock` at line 341-344) DOES check
`if (entryHeight === undefined) continue;`, so the external API
flow is safe — but the public `recordConfirmation` itself doesn't
gate. A future caller wiring `recordConfirmation` from a different
path (e.g., a reindex / catchup tool) could double-count. Subsumed
under G21 (no validForFeeEstimation filter). **No new BUG.**

## Gate matrix

| Gate | Status   | BUG     | Priority | Topic |
|------|----------|---------|----------|-------|
| G1   | PRESENT  | —       | —        | Per-horizon decay constants |
| G2   | PARTIAL  | BUG-1   | P2       | DEFAULT_FEE_RATE=20 fallback (vs Core CFeeRate(0)) |
| G3   | PARTIAL  | BUG-2   | P0-CDIV  | Bucket boundaries (41 hardcoded sat/vB vs ~235 1.05-spaced sat/kvB) |
| G4   | PRESENT  | —       | —        | Per-horizon scale (1/2/24) + periods (12/24/42) |
| G5   | PRESENT  | —       | —        | 3-horizon partition |
| G6   | MISSING  | BUG-3   | P0-CDIV  | m_feerate_avg per bucket (estimate = bucket.min not avg) |
| G7   | MISSING  | BUG-4   | P1-API   | unconfTxs[Y][X] ring buffer + oldUnconfTxs aging |
| G8   | MISSING  | BUG-5   | P0-CDIV  | confAvg[Y][X] per-period matrix (raw array filter instead) |
| G9   | MISSING  | BUG-6   | P0-CDIV  | failAvg[Y][X] per-period failure tracking |
| G10  | PARTIAL  | BUG-7   | P2       | processBlock side-chain skip (no nBestSeenHeight) |
| G11  | MISSING  | BUG-8   | P1-API   | MaxUsableEstimate via BlockSpan/HistoricalBlockSpan |
| G12  | MISSING  | BUG-9   | P1-API   | estimateCombinedFee cross-horizon downgrade |
| G13  | MISSING  | BUG-10  | P2       | estimate_mode parsing (conservative/economical) |
| G14  | MISSING  | BUG-11  | P0-CDIV  | 3-tier HALF/FULL/DOUBLE + max + conservative |
| G15  | MISSING  | BUG-12  | P1-API   | min_mempool_feerate + min_relay_feerate floor |
| G16  | PARTIAL  | BUG-13  | P1-WIRE  | desiredTarget vs returnedTarget distinction |
| G17  | PRESENT  | —       | —        | estimaterawfee per-horizon JSON shape |
| G18  | MISSING  | BUG-14  | P1-API   | FlushUnconfirmed on shutdown |
| G19  | MISSING  | BUG-15  | P1-API   | FEE_FLUSH_INTERVAL=1h scheduler |
| G20  | MISSING  | BUG-16  | P1-API   | MAX_FILE_AGE=60h + accept-stale flag |
| G21  | MISSING  | BUG-17  | P1-API   | validForFeeEstimation filter |
| G22  | PARTIAL  | BUG-18  | P1-WIRE  | estimaterawfee inmempool semantics (aged count) |
| G23  | PARTIAL  | BUG-19  | P0-CDIV  | ParseConfirmTarget throws (clamps silently) |
| G24  | MISSING  | BUG-20  | P1-API   | FeeFilterRounder privacy quantization |
| G25  | MISSING  | BUG-21  | P1-WIRE  | CURRENT_FEES_FILE_VERSION=309900 |
| G26  | MISSING  | BUG-22  | P1-WIRE  | fee_estimates.dat binary format |
| G27  | PARTIAL  | BUG-23  | P1-WIRE  | errors / fail shape (Infinity → -1 endrange) |
| G28  | PRESENT  | —       | —        | Stale txEntryHeights cleanup |
| G29  | (note)   | (G8)    | —        | withintarget rounding (subsumed) |
| G30  | (note)   | (G21)   | —        | recordConfirmation accepts untracked (subsumed) |

## Notes on universal patterns

This audit confirms two W139 cross-impl patterns:

1. **"Hardcoded coarse bucket grid"** (BUG-2): 4 of 10 hotbuns-style impls
   that I have seen (per recent W### audits) hardcode a small sat/vB
   bucket list rather than Core's exponential `FEE_SPACING^k`. The
   accuracy hit at low-feerate is large but obvious only under load.
   Universal pattern to flag in W139 sibling audits.

2. **"Raw array filter vs decay-accumulated moving average"** (BUG-5):
   the `confirmationBlocks: number[]` + `filter().length` shape is a
   common-sense TypeScript / Python design but is **algorithmically
   wrong** vs Core's `confAvg[Y][X]` decay-matrix. The right
   per-period decayed counter is O(1) per estimate and naturally
   forgets old data; the array-filter approach is O(N) per estimate
   and forgets ABRUPTLY at the trim boundary.

3. **"RPC silent clamp masks invalid-input error"** (BUG-19): hotbuns
   clamps confTarget to [1,1008] where Core throws
   `RPC_INVALID_PARAMETER`. This pattern recurs across W125 (error
   parity) and is worth flagging as a universal correctness gap —
   silent clamping breaks downstream error handling.

4. **"Persistence format divergence — JSON vs Core binary"** (BUG-21,
   BUG-22): the `fee_estimates.dat` mismatch is symptomatic of the
   wider hotbuns pattern of choosing JSON for convenience. Listed
   together because they share a fix (either land Core's binary
   format OR explicitly note non-interop and version the JSON).

## Out of scope

- Wallet-side `feebumper` (W130).
- BIP-133 feefilter wire encoding (W136).
- `getmempoolinfo` `mempoolminfee` field (W120 / mempool-policy).
- Coin selection's `m_confirm_target` consumption of estimateSmartFee
  output (W129).
- The `bumpfee` / `psbtbumpfee` fee path (W137).
- Mining-side `getblocktemplate` feerate calculations (W123).
