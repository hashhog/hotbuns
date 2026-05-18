# W151 — Package relay + BIP-125 RBF rules (hotbuns)

**Wave:** W151 — package relay (`MAX_PACKAGE_COUNT=25`,
`MAX_PACKAGE_WEIGHT=404_000`, `IsWellFormedPackage`,
`IsTopoSortedPackage`, `IsConsistentPackage`, `IsChildWithParents`,
`IsChildWithParentsTree`, `AcceptPackage`, `AcceptMultipleTransactions`,
`AcceptSubPackage`, `SubmitPackage`, `PackageRBFChecks`, `submitpackage`
RPC, `testmempoolaccept` package mode); BIP-125 Rules 1-5
(`SignalsOptInRBF`, `IsRBFOptIn`, `GetEntriesForConflicts`,
`HasNoNewUnconfirmed`, `EntriesAndTxidsDisjoint`, `PaysForRBF`,
`MAX_REPLACEMENT_CANDIDATES=100`, `ImprovesFeerateDiagram`);
`GetPackageHash` (BIP-331).

**Scope:** discovery only — no production code changes.

**Bitcoin Core references**
- `bitcoin-core/src/policy/rbf.h:26` — `static constexpr uint32_t
  MAX_REPLACEMENT_CANDIDATES{100};` and the explicit doc comment
  "the number of affected **clusters**" (not transactions).
- `bitcoin-core/src/policy/rbf.cpp:24-50` — `IsRBFOptIn` (walks
  mempool ancestors via `pool.CalculateMemPoolAncestors`).
- `bitcoin-core/src/policy/rbf.cpp:52-56` — `IsRBFOptInEmptyMempool`
  (no-ancestor path).
- `bitcoin-core/src/policy/rbf.cpp:58-83` — `GetEntriesForConflicts`
  (counts `pool.GetUniqueClusterCount(iters_conflicting)`, NOT
  total descendant set; refuses if > 100 clusters; then expands to
  full descendant set via `pool.CalculateDescendants`).
- `bitcoin-core/src/policy/rbf.cpp:85-98` — `EntriesAndTxidsDisjoint`.
- `bitcoin-core/src/policy/rbf.cpp:100-125` — `PaysForRBF` (Rule 3
  `replacement_fees < original_fees`, Rule 4 incremental fee gate;
  uses `m_modified_fees` not raw fee — modified by prioritisetransaction).
- `bitcoin-core/src/policy/rbf.cpp:127-140` — `ImprovesFeerateDiagram`
  (returns the chunk-comparison result; Core's `std::is_gt`
  requires STRICTLY GREATER — equal-feerate replacement is rejected).
- `bitcoin-core/src/policy/packages.h:19-25` — `MAX_PACKAGE_COUNT=25`,
  `MAX_PACKAGE_WEIGHT=404_000` constants and the
  `static_assert(MAX_PACKAGE_WEIGHT >= MAX_STANDARD_TX_WEIGHT)`,
  `static_assert(DEFAULT_CLUSTER_LIMIT >= MAX_PACKAGE_COUNT)` gates.
- `bitcoin-core/src/policy/packages.cpp:19-50` — `IsTopoSortedPackage`
  (linear-time via mutable `later_txids` set; the public 1-arg overload
  builds the set first).
- `bitcoin-core/src/policy/packages.cpp:52-77` — `IsConsistentPackage`
  (empty-vin → false; batch-add inputs per-tx, not 1-at-a-time, so
  intra-tx duplicates are caught by `CheckTransaction` not here).
- `bitcoin-core/src/policy/packages.cpp:79-117` — `IsWellFormedPackage`
  (count, weight, dup-detect, topo, consistency — in that order).
- `bitcoin-core/src/policy/packages.cpp:119-149` — `IsChildWithParents`,
  `IsChildWithParentsTree`.
- `bitcoin-core/src/policy/packages.cpp:151-170` — `GetPackageHash`:
  sort wtxids in **ascending numeric order** by reversing the byte
  iterator (`std::make_reverse_iterator(lhs.end()), …`) — i.e.
  most-significant byte at the END, comparison reads from the END.
  Concatenate and SHA-256.
- `bitcoin-core/src/validation.cpp:1037-1133` — `PackageRBFChecks`
  (requires exactly 2-tx 1-parent-1-child topology; refuses if either
  has in-mempool parents; aggregates conflicts; runs `PaysForRBF` and
  `ImprovesFeerateDiagram` against the changeset; emits
  `BCLog::TXPACKAGES` log line including `GetPackageHash`).
- `bitcoin-core/src/validation.cpp:1242-1316` — `SubmitPackage` (the
  workspace-commit half; not the topo entry point).
- `bitcoin-core/src/validation.cpp:1432-1564` —
  `AcceptMultipleTransactionsInternal` (per-tx PreChecks, per-tx
  `m_client_maxfeerate` check, TRUC, package feerate gate,
  `PackageRBFChecks`, cluster-size, ephemeral spends, per-tx
  PolicyScriptChecks, then `SubmitPackage`).
- `bitcoin-core/src/validation.cpp:1596-1620` — `AcceptSubPackage`
  (single-tx vs multi-tx fork; cleans up `m_view`/`m_viewmempool` on
  exit).
- `bitcoin-core/src/validation.cpp:1622-1771` — `AcceptPackage` (the
  topo entry point; pre-checks `IsWellFormedPackage` and
  `IsChildWithParents`; dedupes already-in-mempool txns via
  `m_pool.exists(wtxid)` / `m_pool.exists(txid)`; returns
  `MempoolTxDifferentWitness` for same-txid-different-witness mempool
  hits; merges per-tx results from individual + package validation
  rounds).
- `bitcoin-core/src/rpc/mempool.cpp:262-450` — `testmempoolaccept` RPC:
  routes 1-tx through `ChainstateManager::ProcessTransaction`,
  >1-tx through `ProcessNewPackage(test_accept=true)`; emits
  `package-error` field on PCKG_POLICY-level failures; emits
  `effective-feerate` + `effective-includes` non-optional for
  allowed=true; emits `wtxid` on every result (including failures);
  emits `reject-details` separately from `reject-reason`.
- `bitcoin-core/src/rpc/mempool.cpp:1302-1514` — `submitpackage` RPC:
  refuses `>1 && !IsChildWithParentsTree` at the RPC layer (before
  ProcessNewPackage); emits `other-wtxid` on DIFFERENT_WITNESS hits;
  emits per-tx `effective-feerate` and `effective-includes` only for
  `ResultType::VALID` (not for MEMPOOL_ENTRY).
- `bitcoin-core/src/util/rbf.h` — `MAX_BIP125_RBF_SEQUENCE=0xfffffffd`.

**Files audited**
- `src/mempool/rbf.ts` (140 lines) — `signalsOptInRBF`,
  `MAX_BIP125_RBF_SEQUENCE`, `MAX_REPLACEMENT_CANDIDATES=100`,
  `RBFTransactionState` enum, `isRBFOptIn`, `entriesAndTxidsDisjoint`.
- `src/mempool/mempool.ts` (4727 lines) — selectively audited:
  - 520-524 — `MAX_PACKAGE_COUNT`, `MAX_PACKAGE_WEIGHT`.
  - 583-628 — `PackageValidationResult`, `PackageTxResult`,
    `PackageResult` shape.
  - 1106-1116 — `AcceptToMemoryPoolOptions` (`maxFeeRateSatPerVB`,
    `testAccept`).
  - 1324-1900 — `addTransaction` RBF block (Rule 2/3/4/5/8 +
    `improvesFeerateDiagram`).
  - 2192-2194 — `testAccept` return shape.
  - 2546-2603 — `reorgRefillUnchecked` (W150 BUG-10 cross-cite).
  - 2663-2679 — `checkConflicts` (outpoint-index direct-conflict
    enumeration).
  - 3093-3158 — `getRBFOptInState`, `isReplaceable`,
    `static signalsOptInRBF`.
  - 3489-3542 — `checkClusterSizeLimit` (uses excludeTxids;
    cross-cite Core PackageRBFChecks).
  - 3624-3705 — linearization helpers.
  - 3707-3859 — `linearizeVirtualCluster`, `compareFeeDiagrams`.
  - 3862-3950 — `improvesFeerateDiagram`.
  - 4089-4410 — `submitPackage` (the only multi-tx entry point).
  - 4504-4707 — `isTopoSortedPackage`, `isConsistentPackage`,
    `isChildWithParents`, `isChildWithParentsTree`, `validatePackage`.
  - 4717-4727 — `getPackageHash`.
- `src/rpc/server.ts` (5500+ lines) — selectively audited:
  - 249 — `DEFAULT_MAX_FEE_RATE = 0.1` BTC/kvB.
  - 3186-3289 — `sendrawtransaction` (uses `broadcastTxInv` with txid,
    not wtxid — see BUG-3).
  - 3291-3496 — `submitPackage` RPC handler.
  - 3507-3523 — `broadcastTxInv` (BUG-3 origin).
  - 3543-3571 — `getmempoolinfo` (`fullrbf: true` hardcoded).
  - 3676-3796 — `testMempoolAccept` (per-tx loop, never package).
- `src/mempool/orphan_pool.ts` — `MAX_ORPHAN_TRANSACTIONS=100`,
  `MAX_ORPHAN_TX_SIZE=100_000`, `MAX_PEER_ORPHAN_TX=50`,
  `ORPHAN_TX_EXPIRE_TIME=300`.
- `src/p2p/peer.ts`, `src/p2p/messages.ts` — `sendpackages` message
  type defined and parsed; never sent; no BIP-331 negotiation logic.

---

## Gate matrix (44 sub-gates / 14 behaviours)

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 1 | `MAX_PACKAGE_COUNT=25` constant | G1: constant value matches Core | PASS (`mempool.ts:523`) |
| 1 | … | G2: enforced on `submitPackage` entry | PASS (`mempool.ts:4656` via `validatePackage`) |
| 1 | … | G3: enforced on `submitpackage` RPC pre-decode | PASS (`server.ts:3319`) |
| 1 | … | G4: enforced on `testmempoolaccept` RPC | PARTIAL — `server.ts:3689` uses literal `25` (not `MAX_PACKAGE_COUNT`); breaks if the constant ever changes |
| 2 | `MAX_PACKAGE_WEIGHT=404_000` | G5: constant value matches Core | PASS (`mempool.ts:524`) |
| 2 | … | G6: total-weight gate enforced when >1 tx | PASS (`mempool.ts:4670`) |
| 2 | … | G7: `static_assert(MAX_PACKAGE_WEIGHT >= MAX_STANDARD_TX_WEIGHT)` analogue | **BUG-1 (P2)** — TypeScript has no static-assert; the relation `MAX_PACKAGE_WEIGHT=404_000 >= MAX_STANDARD_TX_WEIGHT=400_000n` happens to hold but is unenforced by the type system. Cosmetic. |
| 3 | `IsTopoSortedPackage` semantics | G8: parent-after-child rejected | PASS (`mempool.ts:4514-4542`) |
| 3 | … | G9: linear-time via "later txids" set as Core does | DIVERGES — hotbuns uses an O(n²) `transactions.some(...)` lookup inside the loop (`mempool.ts:4528-4530`); Core builds the `later_txids` set once and uses `contains`. Correct but quadratic. P2. |
| 3 | … | G10: standalone (1-arg) overload calls 2-arg variant for code reuse | N/A — only one entry point. |
| 4 | `IsConsistentPackage` semantics | G11: rejects empty-vin tx | PASS (`mempool.ts:4555`) |
| 4 | … | G12: batch-adds inputs per-tx so intra-tx duplicates go elsewhere | **BUG-2 (P1)** — hotbuns adds inputs ONE-AT-A-TIME inside the same per-tx loop (`mempool.ts:4560-4566` then `4569-4572`). If a single tx in the package spends the same outpoint twice (which is a consensus error, `bad-txns-inputs-duplicate`), Core's gate falls through here and the consensus check fires elsewhere; hotbuns rejects with `conflict-in-package` (wrong error label, wrong rejection layer). |
| 5 | `IsChildWithParents` semantics | G13: last tx = child; all others must be input-providers | PASS (`mempool.ts:4585-4607`) |
| 5 | … | G14: package size < 2 returns false | PASS (`mempool.ts:4586`) |
| 5 | … | G15: enforced as PCKG_POLICY error at RPC layer | PASS (`mempool.ts:4175` — emits "package topology disallowed" message string, but the in-tree call uses `isChildWithParentsTree`, not `isChildWithParents`; see BUG-9 below) |
| 6 | `IsChildWithParentsTree` semantics | G16: rejects parent depending on another parent | PASS (`mempool.ts:4616-4638`) |
| 7 | `GetPackageHash` (BIP-331) | G17: byte-equivalent output to Core for the same input | **BUG-3 (P0-CDIV)** — `mempool.ts:4717-4727` uses `Buffer.compare(a, b)` which is forward-byte lexicographic. Core (`packages.cpp:159-162`) reverses the byte iterator before comparing (`std::make_reverse_iterator`), making the comparison numeric-ascending little-endian. The two sorts produce DIFFERENT orderings, so `getPackageHash` returns a different SHA-256 than Core. Breaks BIP-331 wire-format package-hash relay. |
| 8 | `signalsOptInRBF` | G18: ANY input nSequence ≤ 0xfffffffd → true | PASS (`rbf.ts:56-63`) |
| 8 | … | G19: `MAX_BIP125_RBF_SEQUENCE=0xfffffffd` constant correct | PASS (`rbf.ts:30`) |
| 9 | `IsRBFOptIn` (ancestor walk) | G20: tx itself signals → REPLACEABLE_BIP125 | PASS (`rbf.ts:92-93`) |
| 9 | … | G21: not in mempool → UNKNOWN | PASS (`rbf.ts:97-99`) |
| 9 | … | G22: ancestor signals → REPLACEABLE_BIP125 inheritance | PASS (`rbf.ts:101-106`) |
| 10 | BIP-125 Rule 1 (replaceability signaling) | G23: replacement target signals opt-in OR fullRBF active | PARTIAL — hotbuns ships fullRBF unconditionally (`server.ts:3569 fullrbf: true`); no `-mempoolfullrbf=0` knob, no per-peer fullrbf negotiation. Matches Core 28+ defaults but **cannot match the operator-knob behaviour** (BUG-4). |
| 11 | BIP-125 Rule 2 (HasNoNewUnconfirmed) | G24: replacement may not spend new unconfirmed input | PASS (`mempool.ts:1825-1845`) |
| 11 | … | G25: allowed-set = direct conflicts ∪ their mempool ancestors | PASS (`mempool.ts:1816-1834`) |
| 11 | … | G26: confirmed (chainstate) inputs always allowed | PASS (`mempool.ts:1837-1838` — only checks if `this.entries.has(parentHex)`) |
| 12 | BIP-125 Rule 3 (PaysForRBF — absolute) | G27: `fee < totalConflictingFee` rejected | PASS (`mempool.ts:1866-1871`) |
| 12 | … | G28: uses MODIFIED fees not raw fees | **BUG-5 (P2)** — hotbuns uses `entry.fee` (raw). prioritisetransaction RPC isn't implemented (`getmempoolentry` reports `modifiedFee == fee`), so behavior is currently equivalent. Listed for fleet-pattern continuity (Core uses `m_modified_fees` and a future prioritise-tx implementation would silently bypass Rule 3 increment). |
| 13 | BIP-125 Rule 4 (PaysForRBF — incremental) | G29: `additionalFee >= incrementalRelayFee * newVsize` | PASS (`mempool.ts:1874-1883`) |
| 13 | … | G30: incrementalRelayFee default = `0.1 sat/vB` (100 sat/kvB) | PASS (`mempool.ts:576`) |
| 13 | … | G31: rounding uses CEIL (Core: `relay_fee.GetFee(vsize)` rounds down) | **BUG-6 (P1)** — `mempool.ts:1877` `Math.ceil(this.incrementalRelayFee * vsize)`; Core's `CFeeRate::GetFee` returns `(nSize * nSatoshisPerK) / 1000`, integer-truncating (floor). hotbuns demands 1 sat MORE than Core for any non-multiple-of-1000 vsize. Tightens Rule 4 slightly — false-rejection of marginal replacements at the boundary. |
| 14 | BIP-125 Rule 5 (MAX_REPLACEMENT_CANDIDATES) | G32: bound applied to direct-conflict **clusters** | **BUG-7 (P0-CDIV)** — hotbuns counts `allConflictTxids.size` (direct conflicts ∪ ALL descendants, `mempool.ts:1498-1514`); Core counts `pool.GetUniqueClusterCount(iters_conflicting)` — distinct clusters only. **Asymmetry**: a 1-conflict / 1000-descendant cluster passes Core (1 cluster ≤ 100) but FAILS hotbuns (1001 candidates > 100). Legitimate fee-bumps on large clusters are false-rejected with "RBF would evict too many transactions". |
| 14 | … | G33: bound value matches Core (100) | PASS (`rbf.ts:37`) |
| 15 | `EntriesAndTxidsDisjoint` (formerly Rule 2 sister) | G34: replacement ancestor ∈ direct conflicts → reject | PASS (`mempool.ts:1853-1861` + `rbf.ts:129-140`) |
| 16 | `ImprovesFeerateDiagram` (Rule 6 / cluster-mempool) | G35: STRICTLY-GREATER comparison (`std::is_gt`) | PASS — `mempool.ts:3940-3949` treats "equal" as rejection. |
| 16 | … | G36: "incomparable" diagrams treated as rejection | PASS — falls through to the "insufficient feerate" return |
| 16 | … | G37: comment matches code | **BUG-8 (P2)** — `mempool.ts:3942-3943` says "Core accepts ties" which directly CONTRADICTS the implementation and Core's `std::is_gt`. Comment-as-confession, 5th distinct hotbuns instance. |
| 17 | `PackageRBFChecks` (validation.cpp:1037) | G38: only triggered for 1-parent-1-child topology | **BUG-9 (P0-CDIV)** — hotbuns has NO package-level RBF check at all. `submitPackage` (`mempool.ts:4358-4402`) just calls `addTransactionBypassFeeCheck(tx)` per tx, with the bypass setting `minFeeRate=0`. Each per-tx admission runs single-tx RBF in isolation, so a package containing a child that conflicts with a different in-mempool tx than the parent does is treated as two independent single-tx RBFs — wrong because: (a) Core REQUIRES the package have no in-mempool parents (`PackageRBFChecks` line 1063-1067), hotbuns does not enforce this; (b) Core REQUIRES a 1-parent-1-child topology, hotbuns allows wider topologies; (c) Core checks `package_feerate > parent_feerate` (the "anti-DoS fee" guard at line 1108-1112), hotbuns does not; (d) Core runs `ImprovesFeerateDiagram` on the PACKAGE changeset (line 1120-1124), hotbuns runs it per-tx, missing the package interaction. |
| 17 | … | G39: per-package aggregate-fee replacement (CPFP across the package) | **BUG-9 cross-cite** |
| 18 | `submitpackage` RPC dedup of already-in-mempool | G40: same-wtxid → emit existing result; same-txid-diff-wtxid → emit `other-wtxid` | **BUG-10 (P0-CDIV)** — hotbuns `submitPackage` (`mempool.ts:4211-4222`) only checks `this.entries.has(txid)`. If a tx has the same txid but a different witness (BIP-141), it is treated as "already accepted" and the existing entry's wtxid is reported as the result wtxid. Core (`validation.cpp:1676-1686`) returns `MempoolAcceptResult::MempoolTxDifferentWitness(entry.GetTx().GetWitnessHash())`. The RPC layer (`server.ts:3308-3496`) emits no `other-wtxid` field at all. Wallet code that relies on `other-wtxid` to detect a malleated submission silently fails. |
| 19 | `testmempoolaccept` package mode | G41: multi-tx input routes through package validation | **BUG-11 (P0-CDIV)** — `server.ts:3710-3793` loops over each tx and calls `addTransaction({testAccept: true})` **individually**. There is no path that invokes `submitPackage` in test-accept mode. So testing a 1-parent-1-child CPFP package — the entire reason testmempoolaccept supports multi-tx input — is broken. Each tx is tested as if alone; the parent fails on its own low fee rate, the child fails on missing parent input. RPC clients (e.g. core-lightning, eclair) that call `testmempoolaccept` to validate a fee-bumped CPFP before broadcast see false-negatives. |
| 19 | … | G42: response emits `wtxid` on every result (incl. failures) | **BUG-12 (P1)** — `server.ts:3711-3718`, `3725-3734`, `3779-3784`, `3786-3791` emit only `txid` on failure paths; the success path at line 3769 emits `wtxid`. Core emits `wtxid` on every result. |
| 19 | … | G43: response emits `package-error` field for PCKG_POLICY-level failures | **BUG-13 (P1)** — never emitted. `server.ts` testmempoolaccept reports per-tx errors only; no package-level error field. |
| 19 | … | G44: response emits real `fees.base` and `effective-feerate` for allowed=true | **BUG-14 (P0-CDIV)** — `server.ts:3756` hardcodes `feeRate = 0`, then `feeRateBTCkvB = 0`, then `fees.base = 0` (line 3773). The `addTransaction({testAccept: true})` path returns `{accepted: true}` with no fee/vsize info (`mempool.ts:2192-2194`), so no source for the field exists. The `maxFeeRate > 0 && feeRateBTCkvB > maxFeeRate` check at line 3760 ALWAYS PASSES (since feeRate=0 < any positive maxfeerate). The entire RPC `maxfeerate` parameter is dead code on the test path. |

---

## BUG-1 (P2) — `MAX_PACKAGE_WEIGHT >= MAX_STANDARD_TX_WEIGHT` not statically asserted

**Severity:** P2 (cosmetic / typing). Core's
`policy/packages.h:25-30` enforces TWO compile-time invariants:

```cpp
static_assert(MAX_PACKAGE_WEIGHT >= MAX_STANDARD_TX_WEIGHT);
static_assert(DEFAULT_CLUSTER_LIMIT >= MAX_PACKAGE_COUNT);
static_assert(MAX_PACKAGE_WEIGHT <= DEFAULT_CLUSTER_SIZE_LIMIT_KVB * WITNESS_SCALE_FACTOR * 1000);
```

These prevent a future tweak that would make a single standard tx
larger than the package weight gate (which would cause every single-tx
"package" to be rejected as too-large). hotbuns has no analogue.

**File:** `src/mempool/mempool.ts:523-540` (where the constants are
declared in different units — `MAX_PACKAGE_WEIGHT: number` vs
`MAX_STANDARD_TX_WEIGHT: bigint` — making even a runtime assertion
non-trivial).

**Core ref:** `bitcoin-core/src/policy/packages.h:25-30`.

**Impact:** future-proofing only; current values are safe
(404_000 ≥ 400_000n).

---

## BUG-2 (P1) — `isConsistentPackage` rejects intra-tx duplicate inputs as "conflict-in-package", obscuring the consensus error

**Severity:** P1 (error-label divergence, P2P-relay ambiguity). Core's
`IsConsistentPackage` (`packages.cpp:52-77`) explicitly batch-adds
inputs **per-tx** in a separate loop AFTER the per-input duplicate
check inside the same tx, with the comment:

```cpp
// Batch-add all the inputs for a tx at a time. If we added them 1 at a time, we could
// catch duplicate inputs within a single tx.  This is a more severe, consensus error,
// and we want to report that from CheckTransaction instead.
```

hotbuns (`mempool.ts:4550-4575`) checks `inputsSeen.has(outpointKey)`
INSIDE the per-input loop within a single tx, then adds **after**.
Result: an intra-tx duplicate input — which is a CONSENSUS error
(`bad-txns-inputs-duplicate`, `CheckTransaction` in Core
`consensus/tx_verify.cpp`) — is reported as a package-policy error
`conflict-in-package`. The mempool then drops the package with
"package-not-validated" wrapper from `submitPackage`, which is the
wrong rejection layer and the wrong reject-reason. A peer that
relayed the package would not be marked misbehaving for a consensus
violation.

**File:** `src/mempool/mempool.ts:4560-4572`.

**Core ref:** `bitcoin-core/src/policy/packages.cpp:73-74` (the
explicit "batch-add at end" comment).

**Excerpt (hotbuns, wrong order)**
```typescript
export function isConsistentPackage(transactions: Transaction[]): boolean {
  const inputsSeen = new Set<string>();
  for (const tx of transactions) {
    if (tx.inputs.length === 0) return false;
    for (const input of tx.inputs) {
      const outpointKey = `${input.prevOut.txid.toString("hex")}:${input.prevOut.vout}`;
      if (inputsSeen.has(outpointKey)) {
        return false;  // <-- HITS for intra-tx duplicates too
      }
    }
    for (const input of tx.inputs) {  // <-- should be the ONLY add path
      const outpointKey = `${input.prevOut.txid.toString("hex")}:${input.prevOut.vout}`;
      inputsSeen.add(outpointKey);
    }
  }
  return true;
}
```

**Impact:** wrong error string, wrong rejection layer; downstream
ban-score / misbehaviour scoring divergence; a peer that relayed a
consensus-broken tx gets a policy-error rather than a consensus-error
ban-bump.

---

## BUG-3 (P0-CDIV) — `getPackageHash` byte-order mismatch with Core's BIP-331

**Severity:** P0-CDIV (wire-format break). Core's `GetPackageHash`
sorts wtxids as numeric little-endian (most-significant byte LAST,
compare from end):

```cpp
std::sort(wtxids_copy.begin(), wtxids_copy.end(), [](const auto& lhs, const auto& rhs) {
    return std::lexicographical_compare(
        std::make_reverse_iterator(lhs.end()), std::make_reverse_iterator(lhs.begin()),
        std::make_reverse_iterator(rhs.end()), std::make_reverse_iterator(rhs.begin()));
});
```

hotbuns sorts by raw `Buffer.compare()` — a forward-byte lexicographic
comparison from byte 0:

```typescript
wtxids.sort((a, b) => Buffer.compare(a, b));
```

The two orderings DIFFER for any pair of wtxids whose first byte ties
or whose ordering is dominated by the high-order bytes (which are at
the END of the internal-form buffer). The concatenation order differs
and the SHA-256 of that concatenation differs.

**Consequence:** when BIP-331 (`sendpackages` / package-relay) is
implemented and hotbuns starts exchanging package hashes with other
implementations or Core, the hash hotbuns advertises will NOT match
the hash other nodes compute for the same set of transactions. Every
package handshake fails with mismatched hash → peer marks our package
inflight as stale → relay never converges.

**File:** `src/mempool/mempool.ts:4717-4727`.

**Core ref:** `bitcoin-core/src/policy/packages.cpp:151-170`.

**Excerpt (hotbuns, wrong sort)**
```typescript
export function getPackageHash(transactions: Transaction[]): Buffer {
  const wtxids = transactions.map((tx) => getWTxId(tx));
  // Sort wtxids lexicographically (comparing as byte arrays)
  wtxids.sort((a, b) => Buffer.compare(a, b));   // <-- FORWARD bytes, not REVERSED
  const concat = Buffer.concat(wtxids);
  return sha256Hash(concat);
}
```

**Impact:** BIP-331 package-relay interop break the first time it goes
live. Today there is no consumer (no `sendpackages`-negotiated peer
talks to hotbuns), so the bug is latent — but it's load-bearing for
the eventual package-relay rollout. Same shape as W141 BUG-class
"ZMQ hash byte-order LE vs Core display-order" (5/10 impls).

**Fleet pattern:** hash-byte-order mismatch, 3rd distinct fleet
instance (blockbrew W141 ZMQ hashtx byte-order; nimrod W141 mempool
seq encoding; this one for BIP-331 package hash).

---

## BUG-4 (P1) — `fullrbf` hardcoded `true`; no `-mempoolfullrbf` operator knob

**Severity:** P1. Core has a `-mempoolfullrbf` CLI flag (default
`true` since 28.0, default `false` before that — the famous "full RBF
upgrade controversy" of summer 2024). hotbuns hardcodes
`fullrbf: true` in the `getmempoolinfo` response (`server.ts:3569`)
and treats EVERY mempool tx as replaceable in `isReplaceable`
(`mempool.ts:3146-3149`).

There is no:
- `-mempoolfullrbf` CLI flag,
- `mempoolfullrbf` config option,
- per-peer fullrbf negotiation,
- `bip125-replaceable` enforcement in the conflict-handling path.

The `getRBFOptInState` method (`mempool.ts:3107-3134`) computes
the BIP-125 signal correctly and exposes it in
`getmempoolentry.bip125-replaceable`, but the value is purely
informational — no code path gates on it. A Bitcoin Core node
operator who explicitly opts OUT of fullrbf (`-mempoolfullrbf=0`)
expects Rule 1 enforcement; hotbuns has no way to match that mode.

**File:** `src/rpc/server.ts:3569` (hardcoded), `src/mempool/mempool.ts:3146-3149`
(unconditional fullrbf in `isReplaceable`).

**Core ref:** `bitcoin-core/src/init.cpp` `-mempoolfullrbf` flag;
`bitcoin-core/src/policy/rbf.cpp:24-50` `IsRBFOptIn` (the function
hotbuns CALLS for reporting but NOT for enforcement).

**Impact:** operator parity gap. Doesn't affect mainnet default
(Core 28+ defaults match hotbuns) but blocks operators who want
non-fullrbf for compliance / risk-management reasons.

---

## BUG-5 (P2) — RBF Rules 3/4 use raw fee, not modified fee

**Severity:** P2 (latent — prioritisetransaction not implemented).
Core's `PaysForRBF` (`policy/rbf.cpp:100-125`) consumes
`m_modified_fees` (post-prioritise) for both the original-fee sum
and the replacement-fee comparator. The caller in
`validation.cpp:984-1026` passes:

```cpp
PaysForRBF(/*original_fees=*/m_subpackage.m_conflicting_fees,
           /*replacement_fees=*/ws.m_modified_fees,
           /*replacement_vsize=*/ws.m_vsize,
           m_pool.m_opts.incremental_relay_feerate, hash)
```

with `m_modified_fees = m_base_fees + pool.GetPrioritisedFeeDelta(txid)`.

hotbuns (`mempool.ts:1866-1883`) uses raw `fee` and raw
`entry.fee`. Since prioritisetransaction RPC is **not implemented**
in hotbuns (`grep prioritise` in `src/rpc/server.ts` returns zero
hits), the two are identical today and the bug is latent. But:
- a future prioritisetransaction implementation that mutates a
  separate field would silently bypass Rule 3,
- the per-conflict fee field reported via `getmempoolentry.fees.modified`
  would diverge from the value used in RBF math.

**File:** `src/mempool/mempool.ts:1866-1883`.

**Core ref:** `bitcoin-core/src/policy/rbf.cpp:100-125`.

**Impact:** latent; activates when prioritisetransaction lands.

---

## BUG-6 (P1) — Rule 4 incremental-fee uses ceil(rate*vsize); Core uses floor

**Severity:** P1. Core's `CFeeRate::GetFee` (in
`policy/feerate.cpp`) is documented as "floor-rounded" — it computes
`(nSize * nSatoshisPerK) / 1000` using integer division. This means
for a replacement with vsize=141 and incremental rate=1 sat/vB
(1000 sat/kvB), the required incremental fee is
`floor(141*1000/1000) = 141 sats`.

hotbuns (`mempool.ts:1877`) uses:

```typescript
const requiredIncrementalFee = BigInt(Math.ceil(this.incrementalRelayFee * vsize));
```

For vsize=141 and incrementalRelayFee=0.1 sat/vB:
- hotbuns: `Math.ceil(0.1 * 141)` = `Math.ceil(14.1)` = **15 sats**.
- Core: `floor(141 * 100 / 1000)` = `14 sats`.

hotbuns demands 1 sat MORE than Core for any boundary case where
`incrementalRelayFee * vsize` is non-integer. A replacement that
Core accepts at exactly the floor will be FALSE-REJECTED by hotbuns.

**File:** `src/mempool/mempool.ts:1877`.

**Core ref:** `bitcoin-core/src/policy/feerate.cpp::CFeeRate::GetFee`.

**Excerpt (hotbuns)**
```typescript
const requiredIncrementalFee = BigInt(Math.ceil(this.incrementalRelayFee * vsize));
if (additionalFee < requiredIncrementalFee) {
  return { accepted: false, error: `RBF incremental fee ${additionalFee} < required ${requiredIncrementalFee}...` };
}
```

**Impact:** false-rejection of valid RBF replacements at the boundary;
cross-impl divergence with Core on identical fee-bump scenarios.

---

## BUG-7 (P0-CDIV) — Rule 5 (MAX_REPLACEMENT_CANDIDATES) counts total-evict-set, not direct-conflict-cluster count

**Severity:** P0-CDIV (false-rejection of valid RBF). Core's Rule 5
explicitly counts **distinct clusters** of direct conflicts, NOT the
total set of transactions to evict:

```cpp
// bitcoin-core/src/policy/rbf.cpp:64-75
auto num_clusters = pool.GetUniqueClusterCount(iters_conflicting);
if (num_clusters > MAX_REPLACEMENT_CANDIDATES) {
    return strprintf("rejecting replacement %s; too many conflicting clusters (%u > %d)",
            tx.GetHash().ToString(),
            num_clusters,
            MAX_REPLACEMENT_CANDIDATES);
}
// Calculate the set of all transactions that would have to be evicted.
for (CTxMemPool::txiter it : iters_conflicting) {
    pool.CalculateDescendants(it, all_conflicts);
}
```

The intent is to bound the **work** of the relinearization, not the
size of the eviction set — Core's rationale (comment line 65-68):
"This implies a bound on how many mempool clusters might need to be
re-sorted in order to process the replacement (though the actual
number of clusters we relinearize may be greater than this number,
due to cluster splitting)."

hotbuns counts the FULL eviction set (direct + descendants) AGAINST
the 100-bound:

```typescript
// mempool.ts:1498-1514
const allConflictTxids = new Set<string>();
for (const conflict of conflicts) {
  allConflictTxids.add(conflict.txid.toString("hex"));
  const descendants = this.getDescendantSet(conflict.txid.toString("hex"));
  for (const desc of descendants) {
    allConflictTxids.add(desc);
  }
}
if (allConflictTxids.size > MAX_REPLACEMENT_CANDIDATES) {
  return { accepted: false, error: `RBF would evict too many transactions: ${allConflictTxids.size} > ${MAX_REPLACEMENT_CANDIDATES}` };
}
```

**Asymmetry example:** a single direct-conflict tx with 500 in-mempool
descendants (one large CPFP cluster):
- Core: 1 cluster ≤ 100 → PASS.
- hotbuns: 501 candidates > 100 → REJECT with `RBF would evict too
  many transactions: 501 > 100`.

Conversely, 101 direct conflicts each with zero descendants:
- Core: 101 distinct clusters > 100 → REJECT.
- hotbuns: 101 candidates > 100 → REJECT.

So hotbuns rejects MORE than Core; legitimate cluster-mempool
fee-bumps fail with a wire-string divergence that mempool monitoring
treats as a transient failure.

**File:** `src/mempool/mempool.ts:1498-1514`.

**Core ref:** `bitcoin-core/src/policy/rbf.cpp:58-83`, the
`pool.GetUniqueClusterCount(iters_conflicting)` call.

**Impact:**
- False-rejection of valid RBF replacements against a single large
  cluster (e.g. a 200-tx chain getting fee-bumped at the head).
- Cross-impl divergence; wallet RBF code that succeeds against Core
  fails against hotbuns with a confusing error.
- Wire-string mismatch (`"too many conflicting clusters"` vs
  `"too many transactions"`) — RPC clients parsing reject-reason
  diverge.

---

## BUG-8 (P2) — `compareFeeDiagrams` comment claims Core accepts ties; code rejects them

**Severity:** P2 ("comment-as-confession", 5th distinct hotbuns
instance). At `mempool.ts:3942-3943`:

```typescript
if (cmp === "equal") {
  return "insufficient feerate: does not improve feerate diagram";
}
return null; // "better" → OK
```

But the comment immediately above says:

```typescript
// "equal" is technically a non-improvement, but Core accepts ties
// (std::is_gt — strictly greater is required).  We mirror that.
```

The comment says BOTH:
1. "Core accepts ties" (false — `std::is_gt` is STRICTLY greater),
2. "std::is_gt — strictly greater is required" (true).

The two halves of the comment contradict each other. The code is
correct (rejects ties), so this is a documentation bug — but it
demonstrates the same "comment-as-confession" pattern observed
across the fleet (W141 nimrod comment-as-confession 4th instance,
W149 blockbrew BUG-8 "Skip undo data generation during assume-valid
IBD for performance"). 5th distinct hotbuns instance.

**File:** `src/mempool/mempool.ts:3942-3943`.

**Core ref:** `bitcoin-core/src/policy/rbf.cpp:127-140` (`std::is_gt`).

**Impact:** documentation only; a future refactor that "fixes" the
"bug" of rejecting ties (the contradictory comment direction) would
silently weaken RBF to allow no-op feerate-diagram replacements,
opening a re-broadcast DoS vector.

---

## BUG-9 (P0-CDIV) — `submitPackage` has NO package-level RBF; per-tx admission with `addTransactionBypassFeeCheck` instead

**Severity:** P0-CDIV (multiple Core gates missing). Core's
`PackageRBFChecks` (`validation.cpp:1037-1133`) enforces FIVE gates
that have NO counterpart in hotbuns:

1. **Topology gate (lines 1050-1053)**: package must be exactly
   `workspaces.size() == 2 && IsChildWithParents(txns)`. hotbuns
   allows any `isChildWithParentsTree` topology, including
   1-parent-1-child with the child having multiple parents from the
   package — none of which are in-mempool. Wider topology = wider
   attack surface for RBF pinning.

2. **No-in-mempool-parents gate (lines 1063-1067)**: every workspace
   `ws.m_parents` must be empty — the package's transactions cannot
   themselves have mempool ancestors. Core says (comment 1057-1062):
   "If the package has in-mempool parents, we won't consider a
   package RBF since it would result in a cluster larger than 2."
   hotbuns does not check this. A package whose parent depends on
   another mempool tx silently bypasses what Core treats as a
   per-spec violation.

3. **Aggregate `PaysForRBF` (lines 1096-1102)**: applied with the
   PACKAGE's total modified fees against the aggregate conflict
   fees, attributing the error to the child tx. hotbuns applies
   per-tx Rule 3/4 in single-tx context — each tx in the package
   is evaluated against ITS conflicts, NOT the package against the
   union of all conflicts. CPFP-driven RBF where the child pays for
   the parent's replacement fee is not modelled.

4. **`package_feerate > parent_feerate` (lines 1106-1112)**: Core
   requires the child to be paying material additional anti-DoS fees,
   not just being a vehicle for the parent's RBF replacement. hotbuns
   has no analogue.

5. **`ImprovesFeerateDiagram` on the package changeset
   (lines 1120-1124)**: Core builds a changeset that adds the entire
   package and removes the entire set of conflicts, then compares
   the diagram. hotbuns runs `improvesFeerateDiagram` per-tx in
   isolation (`mempool.ts:1898-1908`), missing the package-wide
   interaction.

hotbuns's `submitPackage` (`mempool.ts:4358-4402`) just loops:

```typescript
for (const tx of transactions) {
  // ...
  const result = await this.addTransactionBypassFeeCheck(tx);
  // ...
}
```

where `addTransactionBypassFeeCheck` (`mempool.ts:4485-4501`)
temporarily sets `this.minFeeRate = 0` for the duration of
`addTransaction`. This is the OPPOSITE of what package RBF needs:
it bypasses the rolling-min-fee gate (which is bad for fee-bump
attacks during memory pressure) and runs per-tx RBF in isolation
(which is bad for cluster-mempool replacement analytics).

**File:** `src/mempool/mempool.ts:4079-4410` (`submitPackage`),
`4485-4501` (`addTransactionBypassFeeCheck`).

**Core ref:** `bitcoin-core/src/validation.cpp:1037-1133`
(`PackageRBFChecks`).

**Impact:**
- Cluster-mempool RBF correctness is broken for any package that
  involves conflicting in-mempool transactions; package CPFP RBF
  doesn't function as designed.
- `addTransactionBypassFeeCheck` temporarily mutates a shared field
  (`this.minFeeRate`), which means a concurrent `addTransaction` call
  from a different code path (P2P relay) sees the wrong minFeeRate.
  Not strictly a race because hotbuns is single-threaded JS, but the
  state mutation is "hostile" to any future worker-thread / concurrent
  refactor.
- Wire-string divergence: hotbuns reports `"transaction-rejected"` per
  the failing per-tx attempt; Core reports `"package RBF failed:
  ..."` with one of five specific sub-reasons. RPC clients that scrape
  reject-reason see different strings.

---

## BUG-10 (P0-CDIV) — `submitPackage` does not emit `other-wtxid` for same-txid-different-witness mempool hits

**Severity:** P0-CDIV (RPC contract divergence; wire-format break for
PSBT signing UX). Core's `AcceptPackage` (`validation.cpp:1676-1686`):

```cpp
} else if (m_pool.exists(txid)) {
    // Transaction with the same non-witness data but different witness (same txid,
    // different wtxid) already exists in the mempool.
    const auto& entry{*Assert(m_pool.GetEntry(txid))};
    results_final.emplace(wtxid, MempoolAcceptResult::MempoolTxDifferentWitness(entry.GetTx().GetWitnessHash()));
}
```

And `submitpackage` RPC (`rpc/mempool.cpp:1477-1479`):

```cpp
case MempoolAcceptResult::ResultType::DIFFERENT_WITNESS:
    result_inner.pushKV("other-wtxid", it->second.m_other_wtxid.value().GetHex());
    break;
```

hotbuns (`mempool.ts:4211-4222`) only checks
`this.entries.has(txid)`:

```typescript
if (this.entries.has(txid)) {
  const entry = this.entries.get(txid)!;
  txFees.set(txid, entry.fee);
  txVsizes.set(txid, entry.vsize);
  txResults.set(wtxid, {
    txid,
    wtxid,                    // <-- SUBMITTED wtxid, not the mempool's
    accepted: true,
    vsize: entry.vsize,
    fee: entry.fee,
  });
  continue;
}
```

The submitted wtxid is reported as the result wtxid, even when the
mempool entry has a DIFFERENT witness for the same txid. The RPC
response shape (`server.ts:3423-3454`) emits no `other-wtxid` field
in any code path — a `grep "other-wtxid"` over `src/` returns zero
hits.

**File:** `src/mempool/mempool.ts:4211-4222`,
`src/rpc/server.ts:3416-3460`.

**Core ref:** `bitcoin-core/src/validation.cpp:1676-1686`,
`bitcoin-core/src/rpc/mempool.cpp:1477-1479`.

**Impact:**
- Wallet code that submits a hex-witness-different-but-txid-same
  PSBT signing (e.g. anti-fee-sniping with malleated witness) and
  expects `other-wtxid` to detect the mempool's existing witness
  gets no signal. Signing flows that re-broadcast malleated
  witnesses silently overwrite their "we already saw a different
  witness" check.
- RPC contract divergence: Core's `submitpackage` schema documents
  `other-wtxid` as optional but ALWAYS emitted when the
  DIFFERENT_WITNESS condition fires. hotbuns clients can't depend
  on its presence.

---

## BUG-11 (P0-CDIV) — `testmempoolaccept` loops per-tx and never invokes `submitPackage` for multi-tx input

**Severity:** P0-CDIV (RPC contract divergence; broken CPFP test
path). Core's `testmempoolaccept`
(`rpc/mempool.cpp:343-348`):

```cpp
const PackageMempoolAcceptResult package_result = [&] {
    LOCK(::cs_main);
    if (txns.size() > 1) return ProcessNewPackage(chainstate, mempool, txns, /*test_accept=*/true, /*client_maxfeerate=*/{});
    return PackageMempoolAcceptResult(txns[0]->GetWitnessHash(),
                                      chainman.ProcessTransaction(txns[0], /*test_accept=*/true));
}();
```

>1 tx routes through `ProcessNewPackage(test_accept=true)`, which
runs the full `IsWellFormedPackage` + `IsChildWithParentsTree` +
`AcceptMultipleTransactionsInternal` pipeline with all the package
gates fired (TRUC, package feerate, RBF, cluster size, ephemeral
spends).

hotbuns (`server.ts:3710`):

```typescript
for (const rawtx of rawtxsParam) {
  // ...
  const result = await this.mempool.addTransaction(tx, { testAccept: true });
  // ...
}
```

Each tx is tested **individually**. The package as a whole is never
validated. Consequences:

1. **CPFP child below relay fee floor**: child has high enough
   feerate to fund the parent, but is checked in isolation against
   the missing parent → `bad-txns-inputs-missingorspent` reject.
   Core: `child_state == VALID` via package-feerate gate. hotbuns:
   `child_state == INVALID`.

2. **Parent below relay fee floor**: parent is checked alone and
   rejected for `min relay fee not met`. Core: depending on whether
   the parent has the `TX_RECONSIDERABLE` result type, package
   evaluation retries with the child funding it. hotbuns: never
   retries.

3. **Topology validation absent**: Core rejects a 2-parent / 1-child
   tree with `package-not-child-with-parents` at the policy layer
   if it doesn't fit the supported topology. hotbuns: silently
   tests each tx with no topology check.

4. **`package-error` field never emitted**: Core's `testmempoolaccept`
   pushes the `package-error` field when
   `package_result.m_state.GetResult() == PackageValidationResult::PCKG_POLICY`.
   hotbuns never emits this field (no `pushKV` analogue).

**File:** `src/rpc/server.ts:3676-3796`.

**Core ref:** `bitcoin-core/src/rpc/mempool.cpp:343-450`.

**Impact:**
- Wallet integrations (core-lightning, eclair, electrum, sparrow)
  that call `testmempoolaccept` on CPFP packages before broadcast
  see false-negatives on hotbuns; their fee-bump pre-flight check
  fails when the real broadcast would have succeeded.
- BIP-431 (TRUC) test paths cannot be exercised via
  `testmempoolaccept`; TRUC's whole point is to enable v3 RBF
  through the package path.
- Cross-impl divergence: the same `testmempoolaccept` call returns
  different results on Core vs hotbuns for the same package.

---

## BUG-12 (P1) — `testmempoolaccept` failures omit `wtxid`

**Severity:** P1 (RPC contract divergence). Core emits `wtxid` on
every result entry, including failures (`rpc/mempool.cpp:359`):

```cpp
result_inner.pushKV("txid", tx->GetHash().GetHex());
result_inner.pushKV("wtxid", tx->GetWitnessHash().GetHex());
```

These two fields are pushed BEFORE any per-tx success/failure
branching, so EVERY result entry has both.

hotbuns omits `wtxid` from every failure path:
- `server.ts:3711-3716` (not-a-string)
- `server.ts:3728-3734` (already-in-mempool)
- `server.ts:3739-3745` (already-confirmed)
- `server.ts:3760-3765` (max-fee-exceeded)
- `server.ts:3779-3784` (validation rejected)
- `server.ts:3786-3791` (TX decode failed)

Only the success path at line 3769 includes `wtxid`. Even worse, the
`txid: ""` placeholder is used in two error paths (line 3713, 3788)
where the tx was never deserialized — so the result entry has no
identifier at all.

**File:** `src/rpc/server.ts:3711-3791`.

**Core ref:** `bitcoin-core/src/rpc/mempool.cpp:357-359`.

**Impact:** RPC contract divergence; clients that key results by
wtxid (the canonical key in `submitpackage` responses) cannot do
the same in `testmempoolaccept` on hotbuns.

---

## BUG-13 (P1) — `testmempoolaccept` never emits the `package-error` field

**Severity:** P1 (RPC contract divergence). Core's
`testmempoolaccept` (`rpc/mempool.cpp:360-362`):

```cpp
if (package_result.m_state.GetResult() == PackageValidationResult::PCKG_POLICY) {
    result_inner.pushKV("package-error", package_result.m_state.ToString());
}
```

emits a top-level `package-error` field on every result entry when
the package as a whole failed `IsWellFormedPackage` /
`IsChildWithParents`. This is the canonical signal that the
**package** was malformed (not just an individual tx).

hotbuns has no analogous code path because it never invokes
`submitPackage` from `testmempoolaccept` (BUG-11) — but even if
BUG-11 were fixed by routing multi-tx through `submitPackage`, the
RPC layer (`server.ts:3678-3795`) emits no `package-error` field
in any branch.

**File:** `src/rpc/server.ts:3676-3796`.

**Core ref:** `bitcoin-core/src/rpc/mempool.cpp:360-362`.

**Impact:** RPC contract divergence; clients distinguishing
"package-level violation" from "per-tx violation" cannot do so on
hotbuns.

---

## BUG-14 (P0-CDIV) — `testmempoolaccept` always reports `fees.base = 0`; the `maxfeerate` parameter is dead code

**Severity:** P0-CDIV (response wire-format break; operator-knob
non-functional). At `server.ts:3753-3777`:

```typescript
if (result.accepted) {
  const vsize = getTxVSize(tx);
  // Fee is not returned by addTransaction; report 0 for now
  const feeRate = 0;
  const feeRateBTCkvB = (feeRate * 1000) / 100_000_000;

  // Check maxfeerate
  if (maxFeeRate > 0 && feeRateBTCkvB > maxFeeRate) {
    // ... never fires because feeRateBTCkvB == 0 < any positive maxfeerate
  } else {
    const resultEntry: Record<string, unknown> = {
      txid: txidHex,
      wtxid: getWTxId(tx).toString("hex"),
      allowed: true,
      vsize,
      fees: {
        base: 0,                              // <-- ALWAYS ZERO
      },
    };
    results.push(resultEntry);
  }
}
```

Core's `testmempoolaccept` for `allowed=true`
(`rpc/mempool.cpp:372-396`) emits:
- `fees.base` (the actual base fee in BTC),
- `fees.effective-feerate` (non-optional — package feerate or
  per-tx with prioritise modifications),
- `fees.effective-includes` (non-optional — the wtxids feeding
  effective-feerate).

hotbuns emits ONLY `base: 0`. None of `effective-feerate` or
`effective-includes`. The maxfeerate check ALWAYS passes because
0 < any positive value, so the entire `maxfeerate` parameter is
dead code on the validation path.

The root cause is `addTransaction({testAccept: true})` returning
just `{accepted: true}` without fee/vsize/feerate
(`mempool.ts:2192-2194`):

```typescript
if (options?.testAccept) {
  return { accepted: true };
}
```

No data is plumbed back to the RPC.

**File:** `src/rpc/server.ts:3753-3777`,
`src/mempool/mempool.ts:2192-2194`.

**Core ref:** `bitcoin-core/src/rpc/mempool.cpp:372-396`.

**Impact:**
- `maxfeerate` parameter is dead code; operator safety check
  doesn't trigger. A fat-finger `sendrawtransaction` test that
  Core would catch via testmempoolaccept (returning
  `allowed=false, reject-reason=max-fee-exceeded`) passes on hotbuns.
- Wallet integrations that scrape `effective-feerate` to display
  the actual rate to the user see no data.
- RPC contract divergence: schema says effective-feerate is
  non-optional, hotbuns never emits it.

---

## BUG-15 (P1) — `MAX_PACKAGE_COUNT` enforced via literal `25` in `testmempoolaccept` instead of the constant

**Severity:** P1 (cross-file constant fragmentation). At
`server.ts:3689-3693`:

```typescript
if (rawtxsParam.length > 25) {
  throw this.rpcError(
    RPCErrorCodes.INVALID_PARAMS,
    "Array must contain between 1 and 25 transactions"
  );
}
```

The literal `25` and the error string both hardcode the value
separately from the `MAX_PACKAGE_COUNT` constant (`mempool.ts:523`).
The same RPC's `submitpackage` handler at `server.ts:3319` correctly
uses `MAX_PACKAGE_COUNT`:

```typescript
if (packageParam.length === 0 || packageParam.length > MAX_PACKAGE_COUNT) {
  throw this.rpcError(..., `Array must contain between 1 and ${MAX_PACKAGE_COUNT} transactions.`);
}
```

A future bump of `MAX_PACKAGE_COUNT` (say, to 32) would update
`submitpackage` automatically but leave `testmempoolaccept` at 25 —
silent contract divergence within the same RPC server.

**File:** `src/rpc/server.ts:3689-3693`.

**Core ref:** `bitcoin-core/src/policy/packages.h:19`.

**Impact:** cross-file constant fragmentation; brittle to future
bumps.

---

## BUG-16 (P0-CDIV) — `broadcastTxInv` always sends the TXID even to BIP-339 wtxid-relay peers

**Severity:** P0-CDIV (BIP-339 wire-format break). Per BIP-339 and
Core `net_processing.cpp::RelayTransaction`:
- For peers that negotiated `wtxidrelay`: inv hash = **WTXID**,
  type = MSG_WTX (5).
- For legacy peers: inv hash = **TXID**, type = MSG_TX (1).

hotbuns's `broadcastTxInv` (`server.ts:3507-3523`):

```typescript
private broadcastTxInv(txid: Buffer): void {
  for (const peer of this.peerManager.getConnectedPeers()) {
    const invType = peer.wtxidRelay ? InvType.MSG_WTX : InvType.MSG_TX;
    const invMsg: NetworkMessage = {
      type: "inv",
      payload: {
        inventory: [
          {
            type: invType,
            hash: txid,                  // <-- ALWAYS txid, even when invType=MSG_WTX
          },
        ],
      },
    };
    peer.send(invMsg);
  }
}
```

The `invType` flips correctly based on `peer.wtxidRelay`, but the
`hash` field is ALWAYS `txid`. A BIP-339 peer receiving
`(MSG_WTX, <txid_bytes>)` looks up by wtxid, finds nothing, then
requests with `getdata(MSG_WTX, txid)`, hotbuns responds with the
tx (because it lazily fetches by either id) — but the conversation
is broken end-to-end:
- The peer's mempool sees a "new" wtxid (== txid) that doesn't match
  the real wtxid of the tx;
- `havePendingTx` checks in net_processing prevent re-announcement;
- Compact-block reconstruction (BIP-152) fails because the wtxids
  don't match.

Callers:
- `server.ts:3253` (sendrawtransaction re-broadcast),
- `server.ts:3286` (sendrawtransaction primary broadcast),
- `server.ts:3491` (submitpackage per-accepted-tx broadcast).

All three pass `txid`, never `wtxid`. The bug is uniform.

**File:** `src/rpc/server.ts:3253, 3286, 3491, 3507-3523`.

**Core ref:** `bitcoin-core/src/net_processing.cpp::RelayTransaction`,
BIP-339.

**Excerpt (hotbuns, inv hash mismatch)**
```typescript
const invType = peer.wtxidRelay ? InvType.MSG_WTX : InvType.MSG_TX;
// MISSING: const invHash = peer.wtxidRelay ? wtxid : txid;
const invMsg = { type: "inv", payload: { inventory: [{ type: invType, hash: txid }] }};
```

**Impact:**
- Any tx broadcast from hotbuns to a BIP-339-negotiated peer
  advertises with the wrong hash. Real-world impact today depends
  on whether Core / other impls fall back to looking up by either
  id (they don't strictly — wtxid relay is mutually exclusive).
- Compact-block reconstruction breakage (BIP-152): a hotbuns-mined
  block referencing locally-broadcast txs sends compact-blocks
  with wtxid-keyed short-ids; the peer's mempool has txid-keyed
  entries from our inv → short-id mismatch → full-block reconstruction
  → 1-RT relay regression.
- Cross-cite W141 BUG-class (multiple impls confirm hash-byte-order
  / hash-type wire-format slippage in mempool relay path).

---

## BUG-17 (P0-CDIV) — `reorgRefillUnchecked` admits txs with no validation and `fee=0n`; vector for double-spend pinning via RBF Rule 3

**Severity:** P0-CDIV (W150 BUG-10 carry-forward, RBF interaction
freshly identified). The `reorgRefillUnchecked` method
(`mempool.ts:2546-2603`) admits transactions during reorg-replay
with:

```typescript
const fee = 0n;
const feeRate = 0;
// ...
const entry: MempoolEntry = {
  tx,
  txid,
  fee,                          // <-- 0n
  feeRate,                      // <-- 0
  // ...
  dependsOn: new Set<string>(), // <-- unchecked path: no parent tracking
  // ...
  ephemeralDustParents: new Set<string>(),
  hasEphemeralDust: false,
  sigOpCost: 0,
};
this.entries.set(txidHex, entry);
this.currentSize += vsize;
for (const input of tx.inputs) {
  const outpointKey = `${input.prevOut.txid.toString("hex")}:${input.prevOut.vout}`;
  this.outpointIndex.set(outpointKey, txidHex);
}
```

The outpoint-index entry IS set, which means a later `checkConflicts`
call WILL surface this entry as a conflict. The downstream RBF code
then computes `totalConflictingFee += entry.fee` (`mempool.ts:1521`),
which adds `0n`. Result: a malicious replacement with `fee=1n` and
`vsize=141` will:
- Pass Rule 3 (`fee=1 >= totalConflictingFee=0`) trivially,
- Pass Rule 4 with any incremental fee ≥ 15 sats (which is
  effectively any non-degenerate replacement),
- Pass Rule 5 (single conflict, single descendant),
- Pass Rule 2 (no new unconfirmed inputs — none of the trivially-zero
  reorg-refill tx's inputs are spent by mempool ancestors).

The original (real) tx is then EVICTED at near-zero replacement cost.
The "reorg-refill" optimisation is **a per-tx zero-feed RBF pinning
pool** between disconnect and re-mining.

**File:** `src/mempool/mempool.ts:2546-2603`.

**Core ref:** `bitcoin-core/src/validation.cpp::ChainstateManager::MaybeRebroadcastTxs`
+ `MempoolAccept` cycle (Core re-validates disconnected txs through
the full `AcceptToMemoryPool` pipeline, computing real fees from the
chainstate UTXO set).

**Impact:**
- Cheap RBF pinning of any tx that survives a reorg: hotbuns
  re-admits with `fee=0n`, attacker observes the entry via
  `getrawmempool`, broadcasts a 1-sat-fee replacement, evicts the
  real tx.
- Total mempool fees reported via `getmempoolinfo.total_fee` are
  understated by exactly the sum of refilled-tx fees.
- W150 BUG-10 carry-forward — flagged 1 wave ago; still unfixed.

---

## BUG-18 (P1) — `sendpackages` (BIP-331) parsed but never sent, never negotiated, never enforced

**Severity:** P1 (BIP-331 dead-data plumbing — fleet pattern). hotbuns
parses the `sendpackages` P2P message in `p2p/messages.ts:1470-1471`
and `1665-1666`:

```typescript
case "sendpackages":
  command = "sendpackages";
  // ...
case "sendpackages":
  return { type: "sendpackages", payload: deserializeSendPackagesPayload(reader) };
```

But:
- No code path SENDS `sendpackages` to peers
  (grep over `src/p2p/peer.ts` for outbound `sendpackages` returns
  zero hits inside any handshake/init flow).
- No code path consults `peer.sendPackagesNegotiated` (it doesn't
  exist) to gate package-relay paths.
- `submitPackage` is only reachable via the RPC `submitpackage`
  handler, not via P2P inbound message.

The wire-format parser exists but does nothing with the received
message — Core's BIP-331 negotiation grants permission to send
`MSG_PKG_INFO` / `getpkgtxns` inventory requests, none of which
hotbuns implements. The Core-side peer that sees a hotbuns peer
NOT send `sendpackages` correctly downgrades to per-tx relay.
This is correct-but-degraded, not a wire break — but it's a
visible parity gap and a "dead-data plumbing" instance (fleet
pattern, ~10th distinct hotbuns instance).

**File:** `src/p2p/messages.ts:1444-1471, 1645-1666`,
`src/p2p/peer.ts` (no outbound), `src/p2p/manager.ts` (no inbound
handler).

**Core ref:** `bitcoin-core/src/net_processing.cpp` —
`m_wants_pkg_relay` peer flag, `sendpackages` send during version
handshake.

**Impact:** BIP-331 effectively disabled. Once package relay is
critical (e.g. for v3 / TRUC propagation under fee-bumping
adversarial conditions), this becomes a relay-path bottleneck.

---

## BUG-19 (P1) — `prioritisetransaction` RPC absent; RBF Rule 3 / Rule 4 / RBF diagram all use raw fees only

**Severity:** P1 (missing operator knob; cross-cite BUG-5).
`prioritisetransaction` lets an operator bump the effective fee
of a mempool entry by an arbitrary delta, which affects:
- Mining template selection,
- RBF Rule 3 / Rule 4 / `ImprovesFeerateDiagram` math (Core uses
  `m_modified_fees`),
- `getmempoolentry.fees.modified` reporting,
- Eviction order in `TrimToSize`.

hotbuns has NO `prioritisetransaction` RPC (grep over
`src/rpc/server.ts` returns zero hits). The mempool entry has no
modified-fee field. All RBF math, all mining selection, all
eviction work on raw `fee`.

A common operator pattern is "boost this stuck tx with
prioritisetransaction so the wallet's CPFP child sees the higher
parent fee in the diagram" — non-functional on hotbuns.

**File:** `src/rpc/server.ts` (no registration),
`src/mempool/mempool.ts` (`MempoolEntry` has no `modifiedFee` field).

**Core ref:** `bitcoin-core/src/rpc/mempool.cpp::prioritisetransaction`,
`bitcoin-core/src/txmempool.cpp::CTxMemPool::PrioritiseTransaction`.

**Impact:** missing operator knob; cross-cite BUG-5 (silent
field-shadowing if/when prioritise lands without updating RBF math).

---

## BUG-20 (P1) — `submitPackage` 1-tx path bypasses `validatePackage` and child-with-parents-tree

**Severity:** P1 (inconsistent error-path coverage). At
`mempool.ts:4105-4146`, the 1-tx path skips:
- `validatePackage` (count/weight/dup/topo/consistency),
- `isChildWithParentsTree` (topology gate),

and short-circuits straight to `addTransaction`. The `MAX_PACKAGE_WEIGHT`
gate is also skipped because `validatePackage` checks weight only
for `transactions.length > 1` (`mempool.ts:4670`).

Core's `AcceptPackage` ALSO checks `IsWellFormedPackage` (which
covers single-tx weight via the `MAX_PACKAGE_WEIGHT` clause guarded
by `package_count > 1`), but uniformly enters package validation
for size-1 packages too. The relevant test is the dedup-via-
`m_pool.exists` check, which hotbuns short-circuits past:

```typescript
// Single transaction - just use regular acceptance
if (transactions.length === 1) {
  // ...
  const result = await this.addTransaction(tx);
  // <-- no exists-check here
}
```

`addTransaction`'s own duplicate-detection at line 1354-1362
returns `txn-already-in-mempool` / `txn-same-nonwitness-data-in-mempool`,
which the RPC handler then maps to `error` field in the result
(line 4134) — not to "MEMPOOL_ENTRY" / "DIFFERENT_WITNESS" semantics.
This is a minor RPC contract divergence: Core would emit
`fees.base` for an already-in-mempool single-tx submission;
hotbuns emits `error`.

**File:** `src/mempool/mempool.ts:4105-4146`.

**Core ref:** `bitcoin-core/src/validation.cpp:1622-1716`
(`AcceptPackage` 1-tx and >1-tx paths share the dedup logic).

**Impact:** error-label divergence for `submitpackage` with
1-tx input that's already in mempool.

---

## BUG-21 (P1) — `addTransactionBypassFeeCheck` mutates `this.minFeeRate` instead of passing a per-call override

**Severity:** P1 (hostile to concurrency; "stateful temporary
mutation" anti-pattern). At `mempool.ts:4485-4501`:

```typescript
private async addTransactionBypassFeeCheck(
  tx: Transaction
): Promise<{ accepted: boolean; error?: string }> {
  const savedMinFeeRate = this.minFeeRate;
  this.minFeeRate = 0;
  try {
    const result = await this.addTransaction(tx);
    return result;
  } finally {
    this.minFeeRate = savedMinFeeRate;
  }
}
```

The pattern overwrites a shared instance field, runs
`addTransaction`, then restores. This:
- Breaks if `addTransaction` THROWS — the `finally` saves it, OK.
- Breaks if `addTransaction` is concurrently re-entered from another
  code path (P2P relay path, ZMQ notify) — the second caller sees
  `minFeeRate=0`. JS is single-threaded so this works today, but
  Bun's worker-thread support and any future concurrent refactor
  immediately exposes the race.
- Breaks if `addTransaction` awaits inside the call (which it
  DOES — multiple `await this.utxo.getUTXOAsync(...)` in the per-input
  loop). Between awaits, a different async operation runs on the
  event loop and observes `minFeeRate=0`. Concretely: a concurrent
  `sendrawtransaction` call observing `getMinFee()=0` would bypass
  the relay-fee floor for the duration of the bypass.

Core's equivalent threads `bypass_limits` through `ATMPArgs`
(`validation.cpp:451-489`), an immutable per-call struct.

**File:** `src/mempool/mempool.ts:4485-4501`.

**Core ref:** `bitcoin-core/src/validation.cpp:MempoolAccept::ATMPArgs::bypass_limits`.

**Impact:** correctness-trap for any future concurrent / worker
refactor; bypass-window during await re-entrance from a different
code path.

---

## Summary

**Bug count:** 21 (BUG-1 through BUG-21).

**Severity distribution:**
- **P0-CDIV:** 8 (BUG-3, BUG-7, BUG-9, BUG-10, BUG-11, BUG-14, BUG-16, BUG-17)
- **P1:** 10 (BUG-2, BUG-4, BUG-6, BUG-12, BUG-13, BUG-15, BUG-18, BUG-19, BUG-20, BUG-21)
- **P2:** 3 (BUG-1, BUG-5, BUG-8)

**Fleet patterns confirmed:**
- "comment-as-confession" (BUG-8) — 5th distinct hotbuns instance.
- "dead-data plumbing" (BUG-18) — `sendpackages` parsed but unused.
  ~10th distinct hotbuns instance per W141/W149 tracking.
- "hash-byte-order wire mismatch" (BUG-3) — 3rd distinct fleet
  instance after blockbrew W141 ZMQ hashtx LE-vs-display and nimrod
  W141 mempool seq encoding.
- "operator-knob absent" (BUG-4, BUG-19) — no `-mempoolfullrbf`,
  no `prioritisetransaction`.
- "RPC contract divergence cluster" (BUG-10, BUG-11, BUG-12, BUG-13,
  BUG-14) — five separate RPC-shape divergences from Core's
  submitpackage / testmempoolaccept contract.
- "constant fragmentation" (BUG-15) — literal `25` vs
  `MAX_PACKAGE_COUNT`.
- "stateful-temporary-mutation" (BUG-21) — shared field overwrite
  during await.
- "carry-forward unfixed" (BUG-17) — W150 BUG-10 (reorgRefillUnchecked
  with fee=0n) explicitly noted in task as still unfixed; RBF
  Rule 3 interaction freshly catalogued here.

**Top three findings:**
1. **BUG-9 (P0-CDIV `submitPackage` has no PackageRBFChecks)** —
   FIVE Core gates absent: topology (1-parent-1-child), no-in-mempool-
   parents, aggregate PaysForRBF, `package_feerate > parent_feerate`,
   package-changeset `ImprovesFeerateDiagram`. Per-tx
   `addTransactionBypassFeeCheck` replaces the whole pipeline. Package
   RBF is fundamentally non-functional; cluster-mempool CPFP-via-RBF
   misses the package interaction entirely.
2. **BUG-7 (P0-CDIV Rule 5 counts wrong dimension)** — Core counts
   distinct CLUSTERS of direct conflicts (bound = 100); hotbuns counts
   the total eviction set including all descendants. 1-conflict /
   1000-descendant cluster passes Core (1 cluster) but FAILS hotbuns
   (1001 candidates). Legitimate fee-bumps on large clusters
   false-rejected with the wrong wire string.
3. **BUG-16 + BUG-3 cluster (P0-CDIV wire-format breaks)** — BIP-339
   inv hash always TXID (BUG-16) even for wtxid-relay peers; BIP-331
   package hash sort order wrong (BUG-3, byte-forward vs Core's
   byte-reversed-as-numeric-LE). Together: hotbuns's per-tx broadcast
   to BIP-339 peers AND the eventual package-relay handshake hash
   would BOTH diverge from Core. BUG-16 is live today; BUG-3 is
   latent until BIP-331 is implemented.

**Cross-cite to in-flight fleet sweeps:**
- W144 `script_flag_exceptions` table fleet-wide (hotbuns origin
  via W150 BUG-7+17) — NOT touched in W151 (out of scope).
- W145 `Assume-valid scope creep` fleet-wide (hotbuns origin via
  W145 BUG-2..6 / W150 BUG-13) — NOT touched in W151 (out of scope).
- W150 BUG-10 `reorgRefillUnchecked fee=0n` carry-forward — cross-cited
  as BUG-17 here with a freshly catalogued RBF Rule 3 pinning vector.

**Operator-facing recommendations (out of scope for this audit but
queued for the next fix wave):**
1. **BUG-3 `getPackageHash` reverse-iterator sort** — 1-line:
   `wtxids.sort((a, b) => Buffer.compare(Buffer.from(a).reverse(), Buffer.from(b).reverse()))`
   or pre-reverse before sort. Closes BIP-331 wire-format break.
2. **BUG-7 Rule 5 cluster-count semantics** — replace
   `allConflictTxids.size > MAX_REPLACEMENT_CANDIDATES` with
   a per-conflict cluster lookup via `this.clusters.find` and
   `Set<string>` accumulator. ~10 LOC.
3. **BUG-16 `broadcastTxInv` wtxid lookup** — pass `tx` to
   `broadcastTxInv` and compute `peer.wtxidRelay ? getWTxId(tx) : getTxId(tx)`
   inside the per-peer loop. ~5 LOC across 3 callers.
4. **BUG-17 `reorgRefillUnchecked` full revalidation** — replace
   with proper `addTransaction` cycle that computes fee from
   chainstate UTXO; cross-cite W150 BUG-10 fix.
5. **BUG-9 `PackageRBFChecks` wiring** — implement Core's 5-gate
   sequence; requires a "changeset" abstraction or fold the gates
   inline. Larger refactor (~80 LOC).
6. **BUG-11 `testmempoolaccept` package path** — route multi-tx
   through `submitPackage(test_accept=true)`; requires plumbing
   the test-accept flag through `submitPackage`. ~30 LOC.
7. **BUG-14 `testmempoolaccept fees.base` plumbing** — return
   fee/vsize/feerate from `addTransaction({testAccept})`. ~15 LOC.
