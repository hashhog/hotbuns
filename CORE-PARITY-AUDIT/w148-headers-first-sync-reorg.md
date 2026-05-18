# W148 — Headers-first sync + chain selection + reorg (hotbuns)

**Wave:** W148 — Headers-first IBD, `ProcessNewBlockHeaders`,
`ActivateBestChain`, `ActivateBestChainStep`, `FindMostWorkChain`,
`ConnectTip`/`DisconnectTip`, `InvalidateBlock`/`ResetBlockFailureFlags`,
`fTooFarAhead`/`MIN_BLOCKS_TO_KEEP=288`, `CBlockIndex::nStatus` ordinal
validity ladder + flag bits, `nSequenceId`, `m_chain_tx_count`,
`nTimeMax`, `setBlockIndexCandidates`, PRESYNC/REDOWNLOAD chain-work
enforcement, ValidationInterface signals.

**Date:** 2026-05-18
**Impl:** hotbuns (TypeScript/Bun)
**Scope:** DISCOVERY only — no production code changes.

## Bitcoin Core references

- `bitcoin-core/src/validation.cpp:4183-4239` — `AcceptBlockHeader`
  (PoW + ContextualCheckBlockHeader + `min_pow_checked` gate +
  parent-FAILED check + AddToBlockIndex + `m_best_header` update).
- `bitcoin-core/src/validation.cpp:4242-4270` — `ProcessNewBlockHeaders`
  (loop body; one `cs_main` per batch; calls `CheckBlockIndex` after
  each header; `NotifyHeaderTip` after batch).
- `bitcoin-core/src/validation.cpp:3114-3171` — `FindMostWorkChain`
  (reverse iter over `setBlockIndexCandidates`, ancestor
  `BLOCK_FAILED_VALID` + missing-`HAVE_DATA` filter, candidate erase on
  failure, do-while retry loop).
- `bitcoin-core/src/validation.cpp:3191-3280` — `ActivateBestChainStep`
  (`DisconnectTip` to fork, `vpindexToConnect` descending walk chunked
  by 32, `ConnectTip` loop, `MaybeUpdateMempoolForReorg` after
  disconnect, `DisconnectedBlockTransactions.MAX_DISCONNECTED_TX_POOL_BYTES`
  cap).
- `bitcoin-core/src/validation.cpp:3323-3488` — `ActivateBestChain`
  (do-while loop releasing `cs_main` between iterations, breaks on
  `pindexMostWork == m_chain.Tip()`, `ReachedTarget()` exit; fires
  `BlockConnected` signal AFTER `cs_main` released).
- `bitcoin-core/src/validation.cpp:3055-3107` — `DisconnectTip`
  (read `CBlockUndo`, `DisconnectBlock`, save txs in
  `DisconnectedBlockTransactions`, `m_chain.SetTip(pprev)`,
  `BlockDisconnected` signal).
- `bitcoin-core/src/validation.cpp:3005-3110` — `ConnectTip`
  (read block, `ConnectBlock`, `BlockValidationState`, `m_chain.SetTip`,
  `BlockConnected` signal).
- `bitcoin-core/src/validation.cpp:3521-3697` — `InvalidateBlock`
  (descendant marking with `BLOCK_FAILED_VALID`; descendants get
  `BLOCK_FAILED_CHILD`).
- `bitcoin-core/src/validation.cpp:3711-3730` — `ResetBlockFailureFlags`
  (filters by `block_index.GetAncestor(nHeight) == pindex || pindex->GetAncestor(...)` AND `BLOCK_FAILED_VALID`).
- `bitcoin-core/src/validation.cpp:1940-1942, 3283-3291` —
  `IsInitialBlockDownload` / `UpdateIBDStatus` (`m_cached_is_ibd`
  latched to false when tip is recent AND chain-work >=
  `MinimumChainWork()`).
- `bitcoin-core/src/validation.cpp:1964-1984` — `InvalidChainFound`
  (recomputes `m_best_invalid`, re-derives `m_best_header` via
  `RecalculateBestHeader` if current `best_header` descends from
  invalid pindex).
- `bitcoin-core/src/validation.cpp:3765-3815` — `ReceivedBlockTransactions`
  (sets `nTx = block.vtx.size()`, `m_chain_tx_count = nTx +
  pprev->m_chain_tx_count`, walks descendants to propagate counts).
- `bitcoin-core/src/validation.cpp:4325` — `fTooFarAhead`
  (`pindex->nHeight > ActiveHeight() + MIN_BLOCKS_TO_KEEP` where
  `MIN_BLOCKS_TO_KEEP = 288`).
- `bitcoin-core/src/chain.h:42-86` — `BlockStatus` enum:
  `BLOCK_VALID_UNKNOWN=0`, `BLOCK_VALID_RESERVED=1`, `BLOCK_VALID_TREE=2`,
  `BLOCK_VALID_TRANSACTIONS=3`, `BLOCK_VALID_CHAIN=4`,
  `BLOCK_VALID_SCRIPTS=5` — **ordinal levels stored in low 3 bits**.
  Plus flag bits: `BLOCK_HAVE_DATA=8`, `BLOCK_HAVE_UNDO=16`,
  `BLOCK_FAILED_VALID=32`, `BLOCK_FAILED_CHILD=64`,
  `BLOCK_OPT_WITNESS=128`. `BLOCK_VALID_MASK = 7`.
- `bitcoin-core/src/chain.h:120-129, 149, 152` — `CBlockIndex` fields:
  `nTx`, `m_chain_tx_count`, `nSequenceId`, `nTimeMax`.
- `bitcoin-core/src/chain.h:254-271` — `CBlockIndex::IsValid(nUpTo)` does
  `(nStatus & BLOCK_VALID_MASK) >= nUpTo` (NOT bitwise);
  `RaiseValidity(nUpTo)` is monotonic `nStatus = (nStatus & ~BLOCK_VALID_MASK) | nUpTo`.
- `bitcoin-core/src/node/blockstorage.cpp` —
  `CBlockIndexWorkComparator::operator()` orders by chainwork DESC →
  `nSequenceId` ASC → pointer ASC.

## Files audited

- `src/chain/state.ts` — `ChainStateManager` (lines 183-1538):
  `connectBlock` (286-473), `disconnectBlock` (485-769),
  `reorganize` (779-817), `findForkPoint` (823-884),
  `invalidateBlock` (1210-1311), `markDescendantsInvalid` (1321-1360),
  `reconsiderBlock` (1373-1418), `clearDescendantInvalidFlags`
  (1428-1466), `preciousBlock` (1479-1514), `updateTip` (897-899),
  `isNextBlock` (1109-1111), `needsReorg` (1116-1121).
- `src/sync/headers.ts` — `HeaderSync` (lines 100-1168):
  `processHeaders` (349-483), `validateHeader` (512-628),
  `getMedianTimePast` (634-654), `requestHeaders` (751-825),
  `handleHeadersMessage` (850-928), `saveHeaderEntry` (1095-1137),
  `updateBestChain` (488-505), `getBlockLocator` (302-343).
  Genesis init (184-217). `MAX_NUM_UNCONNECTING_HEADERS_MSGS=10` (77).
- `src/sync/blocks.ts` — `BlockSync` (lines 277-3352):
  `connectBlock` (2383-2900), `handleBlock` (752-819),
  `injectBlock` (826-955), `handleInv` (961-1020),
  `processOrderedBlocks*` (1320-1640), `handleReorgUtxoAndCollect`
  (2019-2305), `disconnectBlockUtxo` (1776-1947), `collectDisconnectedTxs`
  (2323-2380). `MIN_BLOCKS_TO_KEEP = 288` (224). `MAX_REORG_DEPTH = 100`
  defined twice locally (2032, 2330).
- `src/sync/header-sync-state.ts` — `HeadersSyncState` (lines 128-672):
  PRESYNC/REDOWNLOAD state machine. `commitmentPeriod=641`,
  `redownloadBufferSize=15218` (62-65).
- `src/consensus/connect_block.ts` — `coreConnectBlockChecks`
  (241-741): the shared kernel for `ChainStateManager.connectBlock` AND
  `BlockSync.connectBlock`. Assume-valid fast path at lines 416-481.
- `src/storage/database.ts:38-50` — `BlockStatus` enum (modeled as
  bit-flags, NOT Core's 5-level ordinal ladder).

**Production code changes:** 0 (pure audit).

## Why this matters

Headers-first sync + chain selection + reorg is the outer control loop
of every Bitcoin full node. A bug at this layer means:

1. **Silent chain split** — the node accepts/rejects blocks Core would
   not (BIP-30 grandfather windows, fee invariants, sequence locks
   under assume-valid).
2. **Wedge / livelock** — node refuses to advance past a side-branch
   it should have switched to (W101 G1-G5 pattern: earlier higher-work
   chain on disk, no `setBlockIndexCandidates` reconsideration).
3. **DoS** — peer pushes a long invalid header chain; the node stores
   all headers without bounding chain-work or commitment verification,
   OOMing.
4. **Persistent corruption** — partial reorg leaves the on-disk UTXO
   set inconsistent with the tip pointer; restart pulls a non-valid
   tip from `chain-state` meta and silently advances onto it.

Three failure modes recur in hotbuns and all three are documented fleet
patterns:

1. **Two-pipeline guard.** `ChainStateManager.connectBlock`
   (state.ts:286), `BlockSync.connectBlock` (blocks.ts:2383), and the
   pre-W93 separate-write pattern coexist. The shared
   `coreConnectBlockChecks` (consensus/connect_block.ts:241) was
   introduced to deduplicate the consensus checks, but the **chain
   advancement, side-branch storage, reorg dispatch, candidate
   selection, and ValidationInterface emission** logic still lives in
   parallel — `state.ts::connectBlock` is used by generateblock /
   dumptxoutset reload / reorganize() reapply, while
   `blocks.ts::connectBlock` is used by IBD and submitblock. Pattern
   from W131 (OOP wrapper class + flat db.put production path).

2. **Assume-valid scope creep.** `coreConnectBlockChecks` opens a
   wholly separate `if (assumeValid)` branch (connect_block.ts:416-481)
   that re-implements the per-tx loop from scratch, dropping FIVE
   consensus gates that Core never skips: per-coin coinbase maturity,
   BIP-68 sequence locks, per-coin MoneyRange, per-tx
   `bad-txns-in-belowout`, per-tx accumulated-fee MoneyRange. This is
   the W145 BUG-2..6 cluster, still present at W148 audit time.

3. **Bit-flag BlockStatus, not ordinal ladder.** Core's `nStatus` low
   3 bits are an ORDINAL VALIDITY LEVEL (1..5), checked as
   `(nStatus & MASK) >= nUpTo`. Hotbuns models them as INDEPENDENT BIT
   FLAGS (`HEADER_VALID=1`, `TXS_KNOWN=2`, `TXS_VALID=4`, then jumps
   to `HAVE_DATA=8`). `BLOCK_VALID_TREE` (level 2) collides with
   `TXS_KNOWN` (bit 2) — same numeric value, different semantics.
   `RaiseValidity(nUpTo)` semantics impossible to express. (Cross-cite
   W109 G21-G22, W144 audit.)

## Audit framework (30 gates / 24 BUGS catalogued)

Gate legend:
- **PASS** — behaviour matches Core (regression pin).
- **BUG-N** — divergence, gap, or arithmetic-safety hazard.

| #   | Behaviour                                                                                       | Status |
|-----|--------------------------------------------------------------------------------------------------|--------|
| G1  | `ActivateBestChain` exists as the outer control loop                                             | **BUG-1** (missing; 3 pipelines coexist) |
| G2  | `setBlockIndexCandidates` sorted candidate set exists                                            | **BUG-2** (missing; cross-cite W101 G1-G5) |
| G3  | `FindMostWorkChain` scans candidates skipping FAILED/missing-DATA ancestors                       | **BUG-3** (missing function) |
| G4  | `ConnectTip` extracted as a discrete primitive                                                    | **BUG-4** (inline-only — `connectBlock` does ConnectBlock+Connect+UpdateTip in one async) |
| G5  | `DisconnectTip` extracted as a discrete primitive                                                 | **BUG-5** (inline-only; reorganize loops over disconnectBlock) |
| G6  | `MAX_REORG_DEPTH` matches Core's effective `MIN_BLOCKS_TO_KEEP=288`                              | **BUG-6** (set to 100; three independent literals) |
| G7  | `BlockStatus::VALID_*` are ordinal levels stored in low 3 bits                                    | **BUG-7** (modeled as bit-flags; cross-cite W109 G21) |
| G8  | `IsValid(nUpTo)` uses `(nStatus & MASK) >= nUpTo`, not bitwise `has(flag)`                       | **BUG-8** (no `IsValid` ladder helper; bitwise tests only) |
| G9  | `RaiseValidity(nUpTo)` is monotonic + replaces low-bit ordinal                                   | **BUG-9** (status set as unconditional OR-bits, no monotonic transition) |
| G10 | Chain candidates tie-broken by `nSequenceId` (Core), not block hash                              | **BUG-10** (`preciousBlock` sets a single `blockSequenceId` int, never consulted by tip-selection comparator) |
| G11 | `m_chain_tx_count` (nChainTx) cumulative counter on `BlockIndexRecord`                           | **BUG-11** (absent; only `nTx`) |
| G12 | `nTimeMax` (max-timestamp-self-and-ancestors) on `BlockIndexRecord`                              | **BUG-12** (absent) |
| G13 | Header path enforces parent-FAILED-VALID rejection ("bad-prevblk")                                | **BUG-13** (`processHeaders` never checks parent `FAILED_VALID`/`FAILED_CHILD`) |
| G14 | Headers persisted at AcceptBlockHeader time with `BLOCK_VALID_TREE` (level 2)                    | **BUG-14** (header path persists `HEADER_VALID=1` bit only; no level distinction; see also BUG-7) |
| G15 | `m_best_header` pointer distinct from chain tip, advanced on header arrival                       | PASS (`HeaderSync.bestHeader`; updates in `processHeaders` line 456) |
| G16 | `ProcessNewBlockHeaders` runs PoW + ContextualCheckBlockHeader BEFORE block download begins      | PASS (`validateHeader` runs in `processHeaders`; block downloads gated on `bestHeader`) |
| G17 | `setBlockIndexCandidates.erase(invalidated)` keeps candidate set consistent                       | **BUG-15** (no candidate set; cross-cite BUG-2) |
| G18 | `MaybeUpdateMempoolForReorg` post-reorg refill                                                    | PARTIAL (mempool refill done in `connectBlock` post-reorg path via `oldTipBeforeConnect` check; `state.ts::reorganize` does NOT refill mempool) |
| G19 | `BlockConnected` / `BlockDisconnected` signals fire AFTER `cs_main` released (ValidationInterface) | **BUG-16** (no ValidationInterface; raw EventEmitter; emitted INSIDE the async connect, no ordering guarantee) |
| G20 | `MAX_DISCONNECTED_TX_POOL_BYTES` cap on disconnect-pool RAM during reorg                         | **BUG-17** (cap absent; `disconnectedTxsOut` is an unbounded array) |
| G21 | Reorg walk uses skip-pointer (`pskip`) for O(log N) ancestor traversal                            | **BUG-18** (linear walk via `prevBlock`; cross-cite W109 G7) |
| G22 | Headers-first PRESYNC writes nothing to disk (memory-only commitments)                            | PASS (`header-sync-state.ts` design — `headerCommitments: boolean[]`) |
| G23 | After REDOWNLOAD the headers-presync-anchored chain-work is enforced (`min_pow_checked`)         | PARTIAL (`processHeaders` accepts `minPowChecked` param; PRESYNC path sets it true; submitblock direct-path sets it false; but PRESYNC enforcement and direct-path enforcement are NOT routed through the same gate — BUG-19) |
| G24 | `MAX_REORG_DEPTH` is a single canonical constant                                                  | **BUG-20** (literal appears at state.ts:796, blocks.ts:2032, blocks.ts:2330 — three independent definitions, fleet "duplicate-constant" smell) |
| G25 | `InvalidateBlock` walks descendants via `block_index` map by ancestry — NOT by linear height       | **BUG-21** (state.ts:1321-1360 iterates ALL block-index entries from disk for EVERY invalidate call; O(N) DB scan; cross-cite W101 G17) |
| G26 | `ReconsiderBlock` clears only `FAILED_VALID` from ancestors-OR-descendants (Core's filter)        | **BUG-22** (state.ts:1390-1407 walks ancestors UNCONDITIONALLY clearing both FAILED_VALID and FAILED_CHILD on every ancestor up to height 0; clears flags on UNRELATED ancestors) |
| G27 | `fTooFarAhead` gate at block-acceptance time                                                       | PASS (blocks.ts:778 — `headerEntry.height > activeHeight + MIN_BLOCKS_TO_KEEP`) |
| G28 | `BLOCK_OPT_WITNESS=128` flag present                                                              | PASS (database.ts:49 defines it) but **NEVER SET** in production code (dead-data) — see BUG-23 |
| G29 | `m_chain_tx_count` propagation walks descendants on ReceivedBlockTransactions                    | **BUG-11** (no counter exists; descendants never propagated) |
| G30 | `nSequenceId` insertion-order counter monotonically incremented on AddToBlockIndex                | **BUG-10** (`blockSequenceId` is mutated only by `preciousBlock`; never assigned at insertion time; default 0 for every block) |

Additional findings outside the gate matrix:
- **`HaveNumChainTxs` equivalent absent.** Core's `FindMostWorkChain`
  asserts `pindexTest->HaveNumChainTxs() || pindexTest->nHeight == 0`.
  Hotbuns has no `nChainTx` so missing-data candidates aren't even
  detectable at the candidate-set level (BUG-11 + BUG-2 compound).
- **Three `MAX_REORG_DEPTH = 100` literals.** Two in `blocks.ts`
  (handleReorgUtxoAndCollect line 2032, collectDisconnectedTxs line
  2330), one in `state.ts::reorganize` (line 796). All identical
  values today; a future change to one will silently diverge — fleet
  "duplicate-constant smell" (BUG-20).
- **Three independent ChainStateManager.preciousBlock / blockSequenceId
  uses, none consulted in any tip-selection comparator.** The
  precious-block accounting is a dead-data subsystem at W148. BUG-10
  P0-DEAD.

## BUGS

### BUG-1 — No `ActivateBestChain` function; chain advancement split across three independent pipelines, none re-evaluates side-branches when tip changes

**Severity:** P0-CDIV
**File:** `src/chain/state.ts:286-473` (`connectBlock` for generateblock /
dumptxoutset / reorganize); `src/sync/blocks.ts:2383-2900` (`connectBlock`
for IBD / submitblock); `src/sync/blocks.ts:1320-1640`
(`processOrderedBlocks` / `processOrderedBlocksInner` — the IBD outer loop).
**Core ref:** `bitcoin-core/src/validation.cpp:3323-3488` —
`Chainstate::ActivateBestChain` is the **single** outer loop that
re-runs `FindMostWorkChain` each iteration, advancing the tip until no
better candidate exists; releases `cs_main` between iterations.

**Description:**
Hotbuns has no `ActivateBestChain`. Block acceptance flows through
three pipelines, each with its own bespoke tip-advance code:

1. **IBD `processOrderedBlocks` (blocks.ts:1320)** — sequentially
   processes blocks in `state.downloadedBlocks` by ascending height,
   calling `connectBlock`; bounded retry with rewind to
   `lastFlushedHeight` on failure.
2. **`BlockSync.connectBlock` (blocks.ts:2383)** — extends tip OR
   triggers a one-shot `handleReorgUtxoAndCollect` reorg dispatch.
   Does NOT re-evaluate any other side-branch after the dispatch.
3. **`ChainStateManager.connectBlock` (state.ts:286)** — for
   generateblock / dumptxoutset reload / `reorganize` reapply. Does
   NOT consult `downloadedBlocks`, has no awareness of side-branches.

None of these paths re-evaluates blocks already on disk when the tip
changes. If a higher-work side-branch was submitted earlier and stored
via the side-branch path (blocks.ts:868-895), then the active tip
later changed, the side-branch is **never reconsidered for activation**
unless the operator calls `reconsiderblock` or re-submits the new tip.

**Excerpt — three pipelines doing similar jobs:**
```typescript
// blocks.ts:2383 — IBD + submitblock
async connectBlock(block: Block, height: number): Promise<boolean> {
  // ... pre-connect reorg dispatch ...
  if (!block.header.prevBlock.equals(oldTipBeforeConnect)) {
    reorgUtxoFixed = await this.handleReorgUtxoAndCollect(...);
  }
  // ... validateBlock + coreConnectBlockChecks ...
}

// state.ts:286 — generateblock / dumptxoutset / reorganize
async connectBlock(block: Block, height: number): Promise<void> {
  // ... coreConnectBlockChecks ... (no reorg dispatch!)
  await this.db.putBlock(...);
  await this.db.putBlockIndex(...);  // 7 separate awaits
}

// state.ts:779 — reorganize (called by invalidateBlock + outside)
async reorganize(newTip, getBlock) {
  // No depth-check before findForkPoint scans BOTH chains
  const { oldBlocks, newBlocks } = await this.findForkPoint(...);
  // ... cap check AFTER scan: OOM hazard if newTip is deep
}
```

**Impact:**
Two-pipeline guard fleet pattern (W131, W145, W147). A new code path
that should trigger `ActivateBestChain` (e.g. `reconsiderblock` after
clearing FAILED_VALID) silently no-ops because hotbuns has nowhere
central to call. The state.ts:1373-1418 `reconsiderBlock` even
comments "// For now, return success and let the header sync handle
reorg if needed" — which is false: header-sync only re-evaluates new
headers, never re-evaluates a now-valid candidate on disk.

---

### BUG-2 — `setBlockIndexCandidates` sorted candidate set absent; earlier-submitted higher-work side branches never become activation candidates

**Severity:** P0-CDIV
**File:** Nowhere (missing data structure).
**Core ref:** `bitcoin-core/src/validation.h:683` —
`std::set<CBlockIndex*, node::CBlockIndexWorkComparator> setBlockIndexCandidates;`
populated by `AcceptBlockHeader` + `AcceptBlock`; consumed by
`FindMostWorkChain`.

**Description:**
Cross-cite W101 G1-G5. Hotbuns has no in-memory candidate set. The
closest equivalent is `HeaderSync.bestHeader` + `headerChain` Map of
all known headers — but **that map's selection logic only tracks
the single best header by chainwork** (headers.ts:456-459):

```typescript
if (!this.bestHeader || chainWork > this.bestHeader.chainWork) {
  this.bestHeader = entry;
  this.updateBestChain(entry);
}
```

There is no sorted set of candidate tips. Concrete consequence: if
side-branch B3 (work=3) arrives via submitblock BEFORE the active tip
A2 (work=2) (e.g. via an out-of-order RPC re-issue), B3 takes over
`bestHeader`. But if A2 then arrives, A2 is rejected (less work) and
the active chain on disk continues on the lighter chain via the IBD
path, while `bestHeader` points at B3 — `BlockSync` and
`ChainStateManager` disagree on which is the tip until the operator
manually triggers `reconsiderblock`.

The W101 test file (`__tests__/w101_activate_best_chain.test.ts:167-172`)
ALREADY documents this gap as a regression test pin:

```typescript
expect((cs as unknown as Record<string, unknown>)["setBlockIndexCandidates"]).toBeUndefined();
expect(typeof (cs as unknown as Record<string, unknown>)["findMostWorkChain"]).not.toBe("function");
```

**Impact:**
CONSENSUS-DIVERGENT. Earlier-submitted higher-work side-branch
loses to lighter active chain unless explicitly reconsidered. The bug
is a structural absence, NOT a code bug — adding it requires designing
+ wiring a candidate-set Map across three pipelines.

---

### BUG-3 — `FindMostWorkChain` function absent; no logic for skipping FAILED-or-missing-DATA ancestors during chain selection

**Severity:** P0-CDIV
**File:** Nowhere (missing function).
**Core ref:** `bitcoin-core/src/validation.cpp:3114-3171` —
`FindMostWorkChain` walks back from a candidate tip and, if any
ancestor has `BLOCK_FAILED_VALID` or lacks `BLOCK_HAVE_DATA`, marks
the chain ineligible (sets `BLOCK_FAILED_VALID` on every descendant)
and continues the do-while loop to try the next-best candidate.

**Description:**
Without `FindMostWorkChain`, hotbuns has no way to express *"this
candidate is the best, but its parent is FAILED, so try the next
candidate"*. The closest substitute is the post-failure
`processOrderedBlocks` retry banner (blocks.ts:1469-1559) which:
- clears the UTXO cache,
- rewinds `nextHeightToProcess` to `lastFlushedHeight + 1`,
- re-requests the SAME blocks.

The "try the next-best candidate" path doesn't exist. If a peer feeds
a contiguous range that contains one invalid block, hotbuns gets stuck
in a 3-attempt retry loop, then either:
- emits a `[CONSENSUS-FAILURE]` banner (recoverable side-branch test),
- emits a `[CHAINSTATE-CORRUPTION]` banner and calls `process.exit(78)`
  (blocks.ts:1520 — terminates the node).

Neither path actually tries the next-best chain. A peer that delivers
invalid block at height N (chain A) and a valid alternative at the
same height (chain B) cannot induce hotbuns to switch — chain B's
block at height N is filtered out by the height-already-processed
check (blocks.ts:852-895 returns "duplicate") and stored as
side-branch, never activated.

**Impact:**
A malicious peer (or honest network split) can wedge hotbuns at a
specific height even when a valid alternative exists. Test-confirmed
in `w101_activate_best_chain.test.ts` G3 ("candidate with HAVE_DATA
missing is not pre-filtered by selection").

---

### BUG-4 — `ConnectTip` is not extracted as a primitive; consensus + DB write + tip advance + mempool eviction all inline in two non-trivial async functions

**Severity:** P1
**File:** `src/chain/state.ts:286-473` (one of two);
`src/sync/blocks.ts:2383-2900` (the other).
**Core ref:** `bitcoin-core/src/validation.cpp:3005-3110` — `ConnectTip`
is its own primitive: reads the block from disk, calls `ConnectBlock`,
updates `m_chain.SetTip`, fires `BlockConnected` signal. Everything
above (`CheckBlock`, `AcceptBlock`, `ActivateBestChainStep`) is layered
on top.

**Description:**
Both hotbuns `connectBlock` functions are ~150-500 lines of mixed
responsibilities: consensus checks → UTXO mutation → undo
serialization → block-body write → block-index write → chain-state
write → mempool eviction → filter index → notification emit →
peer-manager bestHeight bump. There is no
`ConnectTip(block, pindex)` primitive that callers can compose; the
shared `coreConnectBlockChecks` helper deduplicates the consensus
checks but the chain-tip advance is duplicated in two pipelines.

**Impact:**
Hard to reason about reorg correctness — a change to the post-connect
mempool refill in `blocks.ts::connectBlock` does NOT propagate to
`state.ts::connectBlock` because they're separately maintained. This
is the Pattern B-class failure that landed FIX-N in the
mempool-refill-on-reorg fleet audit
(`_mempool-refill-on-reorg-fleet-result-2026-05-05.md`).

---

### BUG-5 — `DisconnectTip` is not extracted as a primitive; reorg-side disconnect inlined into `ChainStateManager.disconnectBlock` AND `BlockSync.disconnectBlockUtxo`

**Severity:** P1
**File:** `src/chain/state.ts:485-769` (`disconnectBlock` — for
reorganize() + invalidateBlock + dumptxoutset reload);
`src/sync/blocks.ts:1776-1947` (`disconnectBlockUtxo` — for
`handleReorgUtxoAndCollect`).
**Core ref:** `bitcoin-core/src/validation.cpp:3055-3107` —
`DisconnectTip` is a single primitive that reads `CBlockUndo`, runs
`DisconnectBlock`, updates the tip pointer, fires `BlockDisconnected`
signal, and is composed by `ActivateBestChainStep`.

**Description:**
Hotbuns has TWO disconnect functions with overlapping responsibilities
(both call `ApplyTxInUndo` / `applyInputUndo`, both surface UNCLEAN,
both rewrite the UTXO best-block pointer) BUT differ on:
- which writes ride the atomic batch (state.ts: yes, via `extraOps`;
  blocks.ts: pieces are written separately),
- which trigger filter-index rewind (state.ts: yes; blocks.ts: yes,
  but at a different call-site),
- which trigger mempool refill (state.ts: no; blocks.ts: yes via
  `collectDisconnectedTxs`).

**Impact:**
Two disconnect functions = two ways for a future change to silently
diverge. Pattern B-class duplication.

---

### BUG-6 — `MAX_REORG_DEPTH = 100` is wrong; Core has NO max reorg depth (only `MIN_BLOCKS_TO_KEEP = 288` for prune protection)

**Severity:** P0-CDIV (depth-100 reorg-cap fleet pattern)
**File:** `src/chain/state.ts:796` (reorganize);
`src/sync/blocks.ts:2032` (`handleReorgUtxoAndCollect`);
`src/sync/blocks.ts:2330` (`collectDisconnectedTxs`).
**Core ref:** Bitcoin Core has NO `nMaxReorgDepth`. The reorg-depth
governance comes from:
1. Honest miners' chainwork — Bitcoin doesn't refuse deep reorgs by
   construction.
2. `MIN_BLOCKS_TO_KEEP = 288` (validation.h:76) — the prune-protection
   distance from tip, NOT a reorg cap.
3. The block-storage layer keeps recent `rev*.dat` undo data; pruning
   evicts blocks older than `MIN_BLOCKS_TO_KEEP + 1` from disk.

A reorg of depth >100 with valid chainwork SHOULD succeed in Core
(albeit with prune-recovery I/O penalties).

**Description:**
Hotbuns refuses any reorg deeper than 100 blocks across BOTH chain
states (state.ts:796 errors "reorg depth exceeds MAX_REORG_DEPTH=100";
blocks.ts:2032 in `handleReorgUtxoAndCollect` returns false
silently, falling back to in-place connect = UTXO divergence). This
is fleet-wide W148 pattern (rustoshi BUG-6, blockbrew BUG-5).

The comment in state.ts:794 says *"100 blocks is conservative; testnet
reorgs of this depth have never been observed on mainnet outside
testing"* — but the issue is that a 101-block reorg with more chainwork
is a CONSENSUS-VALID event that hotbuns rejects.

**Impact:**
Two failure modes:
1. `state.ts::reorganize` HARD ERRORS on deep reorg (the
   `reconsiderBlock` post-cleanup path), crashing the RPC caller.
2. `blocks.ts::handleReorgUtxoAndCollect` silently aborts the reorg
   AND falls back to in-place connect, leaving the UTXO set divergent
   from Core for the rest of the chain.

Cross-cite: same fleet pattern as W123 (blockbrew BUG-1 ~3 weeks
open), rustoshi W148 BUG-6 (`MAX_REORG_DEPTH=100`), blockbrew W148
BUG-5.

---

### BUG-7 — `BlockStatus` modeled as power-of-two bit flags instead of Core's 5-level ordinal validity ladder; `BLOCK_VALID_TREE` semantics impossible to express

**Severity:** P0-CDIV
**File:** `src/storage/database.ts:38-50`.
**Core ref:** `bitcoin-core/src/chain.h:42-86`. The Core enum is:

```cpp
BLOCK_VALID_UNKNOWN      =    0,
BLOCK_VALID_RESERVED     =    1,
BLOCK_VALID_TREE         =    2,  // pre-AddToBlockIndex
BLOCK_VALID_TRANSACTIONS =    3,  // post-ReceivedBlockTransactions
BLOCK_VALID_CHAIN        =    4,  // post-ConnectBlock
BLOCK_VALID_SCRIPTS      =    5,  // post-script-verify
BLOCK_VALID_MASK         =    7,  // 1|2|3|4|5 == 0b111
BLOCK_HAVE_DATA          =    8,
BLOCK_HAVE_UNDO          =   16,
BLOCK_FAILED_VALID       =   32,
BLOCK_FAILED_CHILD       =   64,
BLOCK_OPT_WITNESS        =  128,
```

The 5 validity levels are stored in the **low 3 bits** as an
ordinal. `IsValid(nUpTo)` does `(nStatus & 7) >= nUpTo`, which is
NOT a bit-test — it's a magnitude comparison.

**Description:**
Hotbuns:
```typescript
export const enum BlockStatus {
  HEADER_VALID = 1,
  TXS_KNOWN    = 2,
  TXS_VALID    = 4,
  HAVE_DATA    = 8,
  HAVE_UNDO    = 16,
  FAILED_VALID = 32,
  FAILED_CHILD = 64,
  OPT_WITNESS  = 128,
}
```

Three problems:
1. **`HEADER_VALID=1`, `TXS_KNOWN=2`, `TXS_VALID=4`** are
   independent bit flags, not ordinal levels. A block can have
   `TXS_VALID=4` set without `HEADER_VALID=1` — semantically
   nonsensical, but expressible.
2. **No `BLOCK_VALID_CHAIN` (level 4) or `BLOCK_VALID_SCRIPTS`
   (level 5) representation.** ConnectBlock vs script-verify success
   cannot be distinguished. Hotbuns sets
   `1 | 2 | 4 | 8 | 16` on every successful connect (blocks.ts:2799,
   state.ts:391) — all the bits at once.
3. **`BLOCK_VALID_MASK = 7` semantics impossible.** Core's
   `IsValid(BLOCK_VALID_TRANSACTIONS)` ("is this block at level 3 or
   better?") cannot be expressed because levels are not encoded as
   magnitudes.

**Impact:**
Cross-cite W109 G21-G22, W144 (script-verify flag derivation),
fleet-wide pattern (rustoshi W148 BUG-7 + W109 G21, blockbrew W148
BUG-9). Bug-prone in practice: a future bug that mistakenly OR's
`TXS_KNOWN=2` without `HEADER_VALID=1` would not be caught by an
invariant check — there is no `IsValid` helper.

---

### BUG-8 — No `IsValid(nUpTo)` ladder helper; every consumer open-codes a `(status & FLAG) !== 0` bitwise test, losing the level-comparison semantics

**Severity:** P1 (consequence of BUG-7)
**File:** every reader of `BlockIndexRecord.status` —
e.g. `state.ts:1231`, `state.ts:1342`, `state.ts:1381`, `state.ts:1394`,
`state.ts:1448`, `state.ts:1487`, `state.ts:1522`, `blocks.ts:976`,
`blocks.ts:1976`, `blocks.ts:2189`, `blocks.ts:2799`.
**Core ref:** `bitcoin-core/src/chain.h:254-258` —
`CBlockIndex::IsValid(BlockStatus nUpTo)` is `(nStatus & BLOCK_VALID_MASK) >= nUpTo`.

**Description:**
Every readsite is a bitwise mask test:
```typescript
if (idx.status & (BlockStatus.FAILED_VALID | BlockStatus.FAILED_CHILD)) { ... }
if ((existing.status & 4) !== 0) { ... }
```
No `IsValid(LEVEL_TRANSACTIONS)`-style accessor exists. Each new
consumer chooses its own bit-test. Cannot ask "is this block at
LEVEL_CHAIN (4) or better?" — the answer depends on which independent
bits were OR'd in.

**Impact:**
Magnifies BUG-7's risk. Cross-cite W109 G21 (rustoshi has same gap).

---

### BUG-9 — `RaiseValidity(nUpTo)` semantics not present; `updateBlockStatus` is an unconditional whole-status overwrite, not a monotonic level transition

**Severity:** P1 (consequence of BUG-7)
**File:** `src/storage/database.ts:777-…` (`updateBlockStatus`);
called from `state.ts:1280` (mark FAILED_VALID), `state.ts:1287`,
`state.ts:1351`, `state.ts:1400`, `state.ts:1460`,
`blocks.ts:881`, `blocks.ts:884`, `blocks.ts:2236`.
**Core ref:** `bitcoin-core/src/chain.h:265-271` —
`RaiseValidity(nUpTo)`:
```cpp
bool RaiseValidity(BlockStatus nUpTo) {
    if (nStatus & BLOCK_FAILED_MASK) return false;
    if ((nStatus & BLOCK_VALID_MASK) < nUpTo) {
        nStatus = (nStatus & ~BLOCK_VALID_MASK) | nUpTo;
        return true;
    }
    return false;
}
```

**Description:**
Hotbuns' `updateBlockStatus(hash, status)` just overwrites — no
monotonicity, no FAILED_MASK short-circuit. A caller that passes
`status = 1` after a previous `status = 1|2|4|8|16` would silently
ERASE bits. The mistake is structurally possible (and would not be
caught by tests).

In practice, all current call sites pass `idx.status | NEW_BITS`
(read-modify-write), but a future caller that forgets the OR will
silently drop bits. Pattern: rustoshi W148 BUG-9 has identical issue
(cross-cite W109 G22).

**Impact:**
Latent. Defense-in-depth absent. Would surface as silent corruption
of block-index status bits.

---

### BUG-10 — `nSequenceId` insertion-order counter absent; precious-block tie-breaking is dead code

**Severity:** P0-DEAD (precious block has no effect on chain selection)
**File:** `src/chain/state.ts:207-210, 1499-1506, 1528-1536`.
**Core ref:** `bitcoin-core/src/chain.h:149` —
`int32_t nSequenceId{0};` assigned at insertion into the block index.
`CBlockIndexWorkComparator` (blockstorage.cpp around line 19) orders
candidates by chainwork DESC, then `nSequenceId` ASC — so older
candidates beat newer ones, AND `preciousblock` works by setting
`nSequenceId = -nBlockReverseSequenceId` (negative).

**Description:**
Hotbuns has:
```typescript
private preciousBlockHash: Buffer | null = null;
private blockSequenceId: number = 0;
private lastPreciousChainwork: bigint = 0n;
```

These fields are **only** written by `preciousBlock` (state.ts:1499):
```typescript
this.preciousBlockHash = blockHash;
this.blockSequenceId--;
```

They are **read** only by `isPreciousBlock` (state.ts:1528) and
`getPreciousBlock` (state.ts:1535). Neither is consulted by any
chain-tip selection code. The `HeaderSync.processHeaders`
chain-selection logic at headers.ts:456 uses ONLY:
```typescript
if (!this.bestHeader || chainWork > this.bestHeader.chainWork) { ... }
```
Pure chainwork comparison, no tie-break input.

Furthermore, no block gets an `nSequenceId` at insertion time —
`HeaderSync.processHeaders` doesn't write any sequence counter to
`BlockIndexRecord`; the storage schema (database.ts:53-59) doesn't
even have a sequence-id field.

The comment in `preciousBlock` (state.ts:1508-1511) admits the gap:
```typescript
// If this block has equal or more work than our tip, we might want to switch
// For simplicity, we don't force a reorg here - that would require
// full chainwork calculation. Return success and let normal chain
// selection pick up the preference.
```

But "normal chain selection" never reads `preciousBlockHash`.

**Impact:**
`preciousblock` RPC silently no-ops. Operator running
`bitcoin-cli preciousblock <hash>` gets `null` (success) but the
chain does not switch. Same shape as rustoshi W148 BUG-10. Fleet
pattern.

---

### BUG-11 — `m_chain_tx_count` (cumulative tx count) absent; `getblockchaininfo nchaintx` returns wrong value; `FindMostWorkChain` cannot detect missing-data candidates at the index level

**Severity:** P1
**File:** `src/storage/database.ts:52-59` —
```typescript
export interface BlockIndexRecord {
  height: number;
  header: Buffer;
  nTx: number;        // per-block tx count
  status: number;
  dataPos: number;
}
```
**Core ref:** `bitcoin-core/src/chain.h:120-129` —
```cpp
unsigned int nTx{0};               // per-block
uint64_t m_chain_tx_count{0};      // cumulative from genesis
```
populated in `ReceivedBlockTransactions` (validation.cpp:3765-3815) by
walking descendants.

**Description:**
Hotbuns stores only `nTx`. There is no cumulative `m_chain_tx_count`
field. Consequences:
1. `getblockchaininfo nchaintx` (RPC) cannot return correct value; it
   would need to walk the full chain.
2. `FindMostWorkChain`'s `HaveNumChainTxs()` assertion — used to
   detect "header is in index but body never arrived" — cannot be
   implemented (the per-block nTx defaults to 0 and is only set on
   connect, which conflates the bit-flag and the counter).
3. `EstimateBlockTime` fallback cannot use `(m_chain_tx_count -
   pprev->m_chain_tx_count) / blocks` average.

**Impact:**
Cross-cite W109 G9 (rustoshi), W138 BUG-18 (blockbrew). Fleet-wide.

---

### BUG-12 — `nTimeMax` (max timestamp of self + ancestors) absent; `getchaintxstats` / `BlockHeader.GetBlockTime()` floor-rules cannot be enforced

**Severity:** P2
**File:** `src/storage/database.ts:52-59` (no nTimeMax field).
**Core ref:** `bitcoin-core/src/chain.h:152` —
`uint32_t nTimeMax{0};` populated in `BuildSkip` /
`AddToBlockIndex`. Each block tracks the max-timestamp-self-and-
ancestors so the prune-time floor (`pindex->nTimeMax >
GetAdjustedTime() - pruneAfterHeight`) can be evaluated in O(1) per
block.

**Description:**
Hotbuns has no `nTimeMax`. The prune-time floor logic in
storage/pruning.ts (out of scope for this audit) appears to use
height-based heuristics; W146 audit notes this.

**Impact:**
Time-based prune decisions can keep blocks longer than necessary, or
miss blocks that should be kept (cosmetic vs the BUG-11 chain-tx
gap).

---

### BUG-13 — `processHeaders` does not check `parent.status & FAILED_VALID|FAILED_CHILD`; peer can extend a chain rooted at an explicitly-invalidated block

**Severity:** P0-CDIV
**File:** `src/sync/headers.ts:349-465` (`processHeaders`); the
parent lookup at line 363 only verifies existence, not status.
**Core ref:** `bitcoin-core/src/validation.cpp:4220-4223` —
```cpp
if (pindexPrev->nStatus & BLOCK_FAILED_VALID) {
    return state.Invalid(BlockValidationResult::BLOCK_INVALID_PREV,
                         "bad-prevblk");
}
```

**Description:**
`processHeaders` does:
1. Skip-if-already-have check (line 357).
2. Parent-lookup (line 363) — returns orphan warning if missing.
3. `validateHeader` (line 373) — PoW + MTP + version + diffbits +
   timestamp + future-time.
4. Chain-work calc + checkpoint verify.
5. Insert into headerChain Map.

There is NO `if (parent.status & FAILED_VALID|FAILED_CHILD) reject` gate.
After `invalidateBlock` marks block X as `FAILED_VALID` and its
descendants as `FAILED_CHILD`, a peer can still feed new headers that
extend the X-rooted chain — those headers will be accepted into
`headerChain` and propagated via `updateBestChain` if they accumulate
enough work. Only the block-validation path (`connectBlock`) would
eventually fail when trying to actually connect them.

**Impact:**
Memory exhaustion vector — a peer can fill the `headerChain` Map with
unlimited headers descending from a known-bad block (PoW must still
match, but with low difficulty network this is cheap). Same shape as
blockbrew W148 BUG-1, rustoshi W148 — fleet pattern.

---

### BUG-14 — `saveHeaderEntry` persists status as bit-mask OR (`HEADER_VALID=1`); no `BLOCK_VALID_TREE` (level 2) level distinction at header-accept time

**Severity:** P1 (downstream of BUG-7)
**File:** `src/sync/headers.ts:1095-1137`.
**Core ref:** `bitcoin-core/src/validation.cpp:4239` (within
`AcceptBlockHeader`) — `pindexNew->RaiseValidity(BLOCK_VALID_TREE);`

**Description:**
Hotbuns:
```typescript
let status = 0;
if (entry.status === "valid-header" || entry.status === "valid-fork") {
  status |= 1;  // HEADER_VALID bit
}
```
There is no `BLOCK_VALID_TREE` (level 2) representation, and no
`RaiseValidity` semantics. The persisted status uses `HEADER_VALID=1`
which collides with Core's `BLOCK_VALID_RESERVED=1` ordinal value —
same numeric bit, different meaning.

The bit-flag mapping forces an ambiguity: a block that has passed
`AcceptBlockHeader` but NOT `AcceptBlock` (Core's
`BLOCK_VALID_TRANSACTIONS=3`) would be marked `HEADER_VALID=1` in
hotbuns; once it passes ConnectBlock, the status gets OR'd to
`1|2|4|8|16` (state.ts:391, blocks.ts:2799). The transition through
intermediate levels is lost.

**Impact:**
Cross-cite BUG-7. Downstream: any "list blocks at level N" query
cannot be expressed.

---

### BUG-15 — `invalidateBlock` does not erase the invalidated block from any candidate set (because no candidate set exists)

**Severity:** P0-CDIV (consequence of BUG-2)
**File:** `src/chain/state.ts:1210-1311`.
**Core ref:** `bitcoin-core/src/validation.cpp:3527-3530` —
`InvalidateBlock` calls `setBlockIndexCandidates.erase(pindex)` for
the invalidated tip + all descendants.

**Description:**
With no candidate set (BUG-2), there's nothing to erase. The current
`invalidateBlock` does:
1. Walk back from tip looking for the to-be-invalidated block.
2. Disconnect blocks in reverse order.
3. Mark each disconnected block `FAILED_VALID`.
4. Mark all descendants `FAILED_CHILD` via the full-DB-scan in
   `markDescendantsInvalid` (BUG-21).
5. Remove conflicting mempool txs.

After this, `HeaderSync.bestHeader` STILL points at the now-invalidated
chain's tip. The next `processHeaders` call from a peer that knows
about the invalidated chain will re-establish bestHeader at the bad
tip (because `processHeaders` doesn't check FAILED_VALID — BUG-13)
and trigger another connect attempt — which will fail at
`coreConnectBlockChecks` and trigger the bounded-retry banner.

**Impact:**
Wedge after invalidateBlock unless `bestHeader` is manually reset.
Cross-cite W101 G18.

---

### BUG-16 — ValidationInterface signals replaced by raw `EventEmitter`; `blockConnected`/`blockDisconnected` emitted INSIDE the async connect — no cs_main release semantics

**Severity:** P1
**File:** `src/chain/state.ts:188-230, 469-472, 766-768`;
`src/sync/blocks.ts` ALSO emits — but uses a different EventEmitter,
or NO emission at all (the canonical mempool removal happens directly
via `this.mempool.removeForBlock`).
**Core ref:** `bitcoin-core/src/validation.cpp:3043-3060` (within
`ConnectTip`) and 3088-3098 (within `DisconnectTip`) — both signals
fire AFTER `cs_main` is released; subscribers (mempool, wallet,
indexes, ZMQ) run on the validation thread but with the chainstate
lock NOT held, preventing deadlocks.

**Description:**
Hotbuns:
```typescript
private notificationEmitter: import("events").EventEmitter | null;
// state.ts:469
if (this.notificationEmitter) {
  this.notificationEmitter.emit("blockConnected", block);
}
```
Emission is synchronous inside the `connectBlock` async function,
AFTER all DB writes have completed. There is no lock to release
because hotbuns has no equivalent of `cs_main` — but the absence of
a "post-lock-release" semantic means:
- Subscribers (e.g. ZMQ publisher) run on the same async stack and
  block the connect path until they return.
- A slow subscriber back-pressures IBD.
- Multiple subscribers cannot be batched (no `BatchHeaderSequence` /
  `BatchEpoch`).

Additionally, **only `ChainStateManager.connectBlock` emits**;
`BlockSync.connectBlock` (the IBD pipeline) does NOT emit a
`blockConnected` signal directly — the ZMQ wiring goes through a
separate path in cli.ts. Two-pipeline.

**Impact:**
ZMQ subscribers seeing different event semantics depending on which
connect path fired the block. Subscribers cannot use the emit as a
signal that the block is "committed" because the chain-state write
may not have flushed (atTip + flush interval gating).

---

### BUG-17 — `DisconnectedBlockTransactions` size cap absent; `reorgDisconnectedTxs` is an unbounded array fed into mempool.readd

**Severity:** P1
**File:** `src/sync/blocks.ts:2114-2118, 2429`.
**Core ref:** `bitcoin-core/src/kernel/disconnected_transactions.h` —
`MAX_DISCONNECTED_TX_POOL_BYTES = 20 * 1'000'000` (20 MB). Core's
`DisconnectedBlockTransactions::addForBlock` evicts oldest entries
when adding would exceed the cap.

**Description:**
Hotbuns' reorg dispatch:
```typescript
let reorgDisconnectedTxs: Transaction[] = [];
// ... walking back the OLD chain ...
for (let i = 1; i < oldBlock.transactions.length; i++) {
  const tx = oldBlock.transactions[i];
  if (!isCoinbase(tx)) {
    disconnectedTxsOut.push(tx);
  }
}
```
No size cap. For a 100-block reorg with average 2,000 txs/block, that's
200,000 Transaction objects in the array — easily ~500MB of JS object
overhead. A malicious peer that triggers repeated reorgs can drive RSS
up arbitrarily.

(MAX_REORG_DEPTH=100 — BUG-6 — provides some bound, but at a 4MB/block
average that's still ~400MB peak per reorg attempt.)

**Impact:**
Memory pressure during reorg. Pattern from W101 G15.

---

### BUG-18 — Reorg ancestor walks use linear `prevBlock` traversal; no `pskip` skip-pointer optimization

**Severity:** P2
**File:** `src/sync/blocks.ts:2049-2074` (newConnectQueue walk
from newTip's prev backwards) — linear via `cursorEntry.header.prevBlock`;
`src/chain/state.ts:842-870` (`findForkPoint` — same).
**Core ref:** `bitcoin-core/src/chain.h:155, 200-217` —
`CBlockIndex::pskip` skip pointer enables `GetAncestor(height)` in
O(log N).

**Description:**
Hotbuns walks one parent at a time:
```typescript
while (cursor !== null && depth < MAX_REORG_DEPTH) {
  // ...
  const cursorEntry = this.headerSync.getHeader(cursor);
  cursor = cursorEntry.header.prevBlock;
  cursorHeight--;
  depth++;
}
```
For a 100-block reorg this is 100 hash lookups; fine. For an
`GetAncestor(targetHeight)`-style operation (e.g. used by `Chain.GetTip()`
when walking back to find BIP-34 activation height) this is O(N).

Mitigated by `MAX_REORG_DEPTH=100` cap (BUG-6).

**Impact:**
Performance only, not correctness. Cross-cite W109 G7 (rustoshi).

---

### BUG-19 — `min_pow_checked` enforcement asymmetric across paths; PRESYNC and submitblock-direct go through DIFFERENT gates

**Severity:** P1
**File:** `src/sync/headers.ts:401-407` (`processHeaders` direct path
checks `minPowChecked` arg);
`src/sync/header-sync-state.ts` (PRESYNC enforcement); `src/sync/blocks.ts:839`
(`injectBlock` calls `processHeaders([block.header], null, false)` with
`minPowChecked = false`).
**Core ref:** `bitcoin-core/src/validation.cpp:4229` —
```cpp
if (!min_pow_checked)
  return state.Invalid(BLOCK_HEADER_LOW_WORK, "too-little-chainwork");
```

**Description:**
Two paths can produce headers:
1. **PRESYNC/REDOWNLOAD** anti-DoS path — accumulates chainwork in
   commitments, releases headers only after `nMinimumChainWork`
   reached. Calls `processHeaders` with `minPowChecked = true`.
2. **Direct-from-peer path** — when `needsAntiDoS()` returns false
   (peer is "trusted" because we're past `nMinimumChainWork`).
   Calls `processHeaders` directly with `minPowChecked = true` —
   bypassing the gate.

The gate in `processHeaders` (headers.ts:401) is:
```typescript
if (!minPowChecked && this.params.nMinimumChainWork > 0n && chainWork < this.params.nMinimumChainWork) {
  // reject
}
```

Once `bestHeader.chainWork >= nMinimumChainWork`, EVERY incoming header
gets `minPowChecked = true` UNLESS the peer is freshly connected and
in PRESYNC. So a peer who connects mid-IBD can feed a low-work
side-chain via direct headers (post-IBD case), and the gate doesn't
fire because the bestHeader's chainwork is high — but the new chain's
chainwork could still be below `nMinimumChainWork`. The `chainWork`
in the gate is the CANDIDATE's chainwork (parent + headerWork), which
does climb monotonically along the side-chain... so the gate would
eventually catch a deliberately-low-difficulty side-chain.

The asymmetry: `injectBlock` (submitblock direct) calls with
`minPowChecked = false`, which forces the gate active. But the regular
P2P direct path (post-IBD) calls with `minPowChecked = true` (default
parameter), which DISABLES the gate.

**Impact:**
Post-IBD, a peer can feed a deliberately-low-difficulty side-chain;
those headers enter the index unmarked. Block downloads for that
chain will eventually fail at `validateHeader`'s diffbits check —
but the headers themselves sit in memory until disconnect.

---

### BUG-20 — `MAX_REORG_DEPTH = 100` defined as THREE separate literals; future change to one will diverge silently

**Severity:** P3
**File:** `src/chain/state.ts:796`,
`src/sync/blocks.ts:2032`, `src/sync/blocks.ts:2330`.
**Core ref:** N/A — Core has no MAX_REORG_DEPTH.

**Description:**
Three independent `const MAX_REORG_DEPTH = 100;` declarations in
three functions. If a future fix wants to remove the cap (or change
it to 288 to match `MIN_BLOCKS_TO_KEEP`), the chance of catching all
three is non-zero. Fleet "duplicate-constant smell" — same as
beamchain W143 BUG `merkle_pairs`/`merkle_pairs_check` byte-identical
helpers.

**Impact:**
Future-bug-prone, not currently buggy.

---

### BUG-21 — `markDescendantsInvalid` and `clearDescendantInvalidFlags` do a FULL DB SCAN over `iterateBlockIndexEntries` on every invalidate/reconsider call

**Severity:** P1
**File:** `src/chain/state.ts:1321-1360, 1428-1466`.
**Core ref:** `bitcoin-core/src/validation.cpp:3699-3707` —
`SetBlockFailureFlags` walks the in-memory `m_block_index` map (a
`std::unordered_map`) which is O(N) but with ~600k entries at mainnet
tip the constant factor is tiny (no disk I/O).

**Description:**
Hotbuns iterates the FULL block-index from disk:
```typescript
const allEntries: Array<[Buffer, BlockIndexRecord]> = [];
for await (const entry of this.db.iterateBlockIndexEntries()) {
  allEntries.push(entry);
}
allEntries.sort((a, b) => a[1].height - b[1].height);
for (const [hash, idx] of allEntries) {
  // ...
  const prevIdx = await this.db.getBlockIndex(prevBlockHash);  // EXTRA DB READ
  // ...
}
```

For each entry, ANOTHER DB read (`getBlockIndex(prevBlockHash)`) is
issued — `O(N)` DB reads + `O(N log N)` sort, with NO in-memory
block-index cache. At mainnet tip (~860k blocks), that's >800k disk
reads to mark descendants of a single invalidated block.

**Impact:**
`invalidateblock` RPC at mainnet height stalls the node for tens of
seconds. Cross-cite W101 G17.

---

### BUG-22 — `reconsiderBlock` walks ancestors UNCONDITIONALLY clearing both `FAILED_VALID` AND `FAILED_CHILD` from EVERY ancestor up to genesis

**Severity:** P0-CDIV
**File:** `src/chain/state.ts:1390-1407`.
**Core ref:** `bitcoin-core/src/validation.cpp:3711-3730` —
`ResetBlockFailureFlags` walks `m_block_index` and clears
`BLOCK_FAILED_VALID` only when:
- `pindex` is in the ancestor chain of `block_index[h]`, OR
- `block_index[h]` is in the ancestor chain of `pindex`, OR
- the entries are the same;
AND the entry has `BLOCK_FAILED_VALID` set. It does **NOT** touch
arbitrary ancestors.

**Description:**
Hotbuns:
```typescript
while (true) {
  const idx = await this.db.getBlockIndex(currentHash);
  if (!idx) break;
  const wasInvalid = idx.status & (BlockStatus.FAILED_VALID | BlockStatus.FAILED_CHILD);
  if (!wasInvalid) break;
  // Clear both flags
  const newStatus = idx.status & ~(BlockStatus.FAILED_VALID | BlockStatus.FAILED_CHILD);
  await this.db.updateBlockStatus(currentHash, newStatus);
  blocksCleared++;
  // Move to parent
  const parentHash = idx.header.subarray(4, 36);
  if (idx.height === 0) break;
  currentHash = parentHash;
}
```

This walks the ancestor chain CLEARING flags on every block, stopping
only when it hits a non-failed block or genesis. Two divergences from
Core:
1. **Clears both `FAILED_VALID` AND `FAILED_CHILD`** unconditionally.
   Core only clears `FAILED_VALID` (and `FAILED_CHILD` propagates from
   the parent state during a subsequent re-evaluation, not by direct
   bit-flip).
2. **Walks ANCESTORS, not descendants of the reconsidered block.**
   `reconsiderblock <hash>` is meant to "undo the invalidation of
   this block and the descendants that were marked FAILED_CHILD as
   a consequence", NOT "clear failure flags on the entire ancestor
   chain up to genesis". The descendant clearing happens in
   `clearDescendantInvalidFlags` (state.ts:1428), but the ancestor
   walk is gratuitous.

**Impact:**
- If multiple sibling chains were each independently invalidated,
  `reconsiderblock A` will clear failure flags on shared ancestors,
  which then makes the OTHER invalidated sibling re-eligible — even
  though only chain A was explicitly reconsidered.
- A subsequent `processHeaders` call from any peer can then re-grow
  the previously-invalidated sibling chain (BUG-13 says this happens
  silently anyway).

Same shape as blockbrew W148 BUG-12 — fleet pattern. Cross-cite W101
G19.

---

### BUG-23 — `BLOCK_OPT_WITNESS = 128` defined but never set in production code (dead-data)

**Severity:** P0-DEAD
**File:** `src/storage/database.ts:48-49`.
**Core ref:** `bitcoin-core/src/chain.h:64` — set in
`ReceivedBlockTransactions` when the block's witness data is present.

**Description:**
The enum value is exported and importable, but `grep "OPT_WITNESS"`
in src/ returns ONLY the definition. No production code sets it. Yet
the bit value 128 is reserved — a future bit-flag added at 128 would
silently collide.

Same fleet pattern as W138 fleet-wide ChainstateManager / W147 BUG-N
"defined but no production caller".

**Impact:**
Cosmetic dead-data. Latent collision risk if a new flag is added
without consulting the enum.

---

### BUG-24 — Assume-valid skips per-coin maturity + BIP-68 + per-coin MoneyRange + per-tx fee invariants (W145 BUG-2..6 cluster re-affirmed at the W148 layer)

**Severity:** P0-CDIV (Assume-valid scope creep — fleet pattern;
hotbuns is the canonical example from W145)
**File:** `src/consensus/connect_block.ts:411-481`.
**Core ref:** `bitcoin-core/src/validation.cpp:2480-2700`
(ConnectBlock) — `fScriptChecks = !fJustCheck && !fAssumeValid;`
gates ONLY the per-input `CheckInputScripts` call. Maturity, BIP-68,
MoneyRange, fee invariants are unconditional.

**Description:**
The `if (assumeValid)` branch (connect_block.ts:416-481) re-implements
the per-tx loop with FIVE unconditional Core gates dropped:

1. **Per-coin coinbase maturity** — Core's `Consensus::CheckTxInputs`
   (tx_verify.cpp:124-129) checks
   `prevheight < pindexPrev->nHeight + COINBASE_MATURITY`.
   Hotbuns assume-valid: gone.
2. **BIP-68 (CSV) sequence locks** — Core's `SequenceLocks`
   evaluation in ConnectBlock. Hotbuns assume-valid: gone.
3. **Per-coin MoneyRange** — Core's `MoneyRange(coin.out.nValue)`
   per input. Hotbuns assume-valid: gone (just sums into
   `avTotalInputValue` without range-checking).
4. **Per-tx `bad-txns-in-belowout`** — `if (nValueIn < tx.GetValueOut())`
   per tx. Hotbuns assume-valid: gone (block-wide accumulator only).
5. **Per-tx accumulated-fee MoneyRange** — `if (!MoneyRange(nFees))`
   per tx. Hotbuns assume-valid: gone.

The assume-valid path runs ONLY:
- coinbase-value check at end (block-wide).
- BIP-30 (gated outside the if-assumeValid block).
- IsFinalTx (gated outside).

So an `assumeValid=true` block can:
- Spend a coinbase output before its 100-block maturity has elapsed.
- Violate per-tx BIP-68 sequence-lock semantics.
- Have a per-coin or per-tx negative-fee situation that Core would
  catch.

**Impact:**
On mainnet replay with `-assumevalid=<defaulthash>`, hotbuns accepts
some blocks Core would reject. None of the gates Core enforces here
have ever fired on mainnet (the assumevalid window is presumed-good),
but the ATTACK SURFACE post-assumevalid is wider than Core's. A miner
that succeeds in publishing a sub-maturity-spend block AND that block
falls inside the operator's assumevalid window will:
- be accepted by hotbuns, rejected by Core,
- create a chain split.

Cross-cite: W145 BUG-2..6 cluster — the entire NEW PATTERN from this
month is anchored on hotbuns. Fleet pattern carried forward.

---

## Cross-impl notes

- **Three-pipeline drift** — hotbuns has TWO chain-state pipelines
  (`ChainStateManager` for generateblock / dumptxoutset, `BlockSync`
  for IBD / submitblock) sharing `coreConnectBlockChecks` for
  consensus but diverging on chain-tip advance, mempool-refill, ZMQ
  emission. Cross-cite W131 (OOP wrapper + flat-put), W147 BUG-14
  (snapshot vs production-DB diverge), W145 (Assume-valid scope creep
  introduces a 3rd internal pipeline inside `coreConnectBlockChecks`).
- **Assume-valid scope creep** — confirmed 2nd time in W148 wave.
  W145 BUG-2..6 still on disk as of W148 audit; no patch landed.
- **No `setBlockIndexCandidates`** — fleet-wide pattern, 100% of W148
  audits so far (rustoshi BUG-2, blockbrew BUG-3 area, nimrod TBD,
  now hotbuns BUG-2). Hotbuns has BOTH the W101 regression-test pin
  AND the absence persisting at W148.
- **`MAX_REORG_DEPTH=100` literal duplication** — 3 instances in
  hotbuns (BUG-20). rustoshi has 1 instance at 100 (W148 BUG-6;
  literal `MAX_REORG_DEPTH=100` at rpc/server.rs:1286).
- **`BlockStatus` bit-flags instead of 5-level ordinal** — fleet
  pattern: rustoshi W148 BUG-7 + W109 G21, blockbrew W148 BUG-9.
  Hotbuns BUG-7 makes 3 of 3 W148 impls audited so far.
- **`m_chain_tx_count` absent** — fleet pattern: rustoshi W148 BUG-11,
  blockbrew W148 BUG-11, hotbuns BUG-11. 3 of 3 so far.

## Severity rollup

| Severity        | Count |
|-----------------|-------|
| P0-CONS         | 0     |
| P0-CDIV         | 7 (BUG-1, BUG-2, BUG-3, BUG-6, BUG-13, BUG-15, BUG-22, BUG-24) |
| P0-DEAD         | 2 (BUG-10, BUG-23) |
| P0-SEC          | 0     |
| P1              | 9 (BUG-4, BUG-5, BUG-8, BUG-9, BUG-11, BUG-14, BUG-16, BUG-17, BUG-19, BUG-21) |
| P2              | 2 (BUG-12, BUG-18) |
| P3              | 1 (BUG-20) |

Total BUGS catalogued: **24**.

## Suggested fix priority

(Operator-facing impact, highest first.)

1. **BUG-24** — Assume-valid scope creep already on the W145 fix
   queue. Re-anchor at W148 confirms NO patch landed. ~1 day:
   move maturity + BIP-68 + MoneyRange + fee checks OUT of the
   `if (assumeValid)` branch into a shared pre-script-check block.
2. **BUG-22** — `reconsiderBlock` wrongly clears flags on shared
   ancestors. 5-line fix: walk ONLY the descendants of `blockHash`,
   not the ancestors. (Same shape as blockbrew W148 BUG-12.)
3. **BUG-13** — Header-path parent-FAILED check absent. 3-line fix:
   add `if (parent.status & (FAILED_VALID|FAILED_CHILD)) reject` at
   headers.ts:373.
4. **BUG-6** — `MAX_REORG_DEPTH=100`. Fleet sweep; either rationalize
   to a single canonical constant or replace with `MIN_BLOCKS_TO_KEEP`
   semantic where appropriate.
5. **BUG-10** — `preciousBlock` is a no-op. Either wire `nSequenceId`
   into the tip-selection comparator OR delete the
   `preciousBlockHash`/`blockSequenceId` fields and document that
   `preciousblock` RPC is unsupported.
6. **BUG-1, BUG-2, BUG-3** — `ActivateBestChain` + `setBlockIndexCandidates`
   + `FindMostWorkChain`. This is a multi-week subsystem rewrite, not
   a tactical fix — flag it as the W148 deferred owner.
