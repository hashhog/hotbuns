# W149 — Pruning + assumevalid + minimumchainwork (hotbuns)

**Wave:** W149 — `FindFilesToPrune`, `FindFilesToPruneManual`,
`PruneOneBlockFile`, `UnlinkPrunedFiles`, `MIN_BLOCKS_TO_KEEP=288`,
`MIN_DISK_SPACE_FOR_BLOCK_FILES=550 MiB`, `PRUNE_TARGET_MANUAL`,
`BLOCK_HAVE_DATA`/`HAVE_UNDO` bits, `defaultAssumeValid`,
`fScriptChecks` skip gate in `ConnectBlock`, `nMinimumChainWork`,
`pruneblockchain` RPC, prune-restart guard (`m_have_pruned` +
`-prune`/`-reindex` mismatch).

**Scope:** discovery only — no production code changes.

**Bitcoin Core references**
- `bitcoin-core/src/node/blockstorage.cpp:258-290` — `PruneOneBlockFile`
  (clears `BLOCK_HAVE_DATA | BLOCK_HAVE_UNDO`, zeros `nFile`/`nDataPos`/
  `nUndoPos`, inserts to `m_dirty_blockindex`, removes from `m_blocks_unlinked`).
- `bitcoin-core/src/node/blockstorage.cpp:292-319` — `FindFilesToPruneManual`
  (uses `chain.GetPruneRange(nManualPruneHeight)`, iterates all blockfiles,
  per-file shape: skip if entirely-pruned or partially-overlapping the keep
  range).
- `bitcoin-core/src/node/blockstorage.cpp:321-400` — `FindFilesToPrune`
  (auto): IBD adjusts `nBuffer` by `1MB * remaining_blocks`, halves target
  if a historical chainstate exists; `BLOCKFILE_CHUNK_SIZE +
  UNDOFILE_CHUNK_SIZE` buffer; bails if tip ≤ `PruneAfterHeight`.
- `bitcoin-core/src/node/blockstorage.h:407-408` — `GetPruneTarget()`;
  `PRUNE_TARGET_MANUAL = std::numeric_limits<uint64_t>::max()`.
- `bitcoin-core/src/node/blockstorage.h:242` — pruning gated by
  `CChainParams::nPruneAfterHeight` (mainnet=100000; testnet/signet=1000;
  regtest=1000; testnet4=1000).
- `bitcoin-core/src/validation.h:75-87` — `MIN_BLOCKS_TO_KEEP = 288`,
  `MIN_DISK_SPACE_FOR_BLOCK_FILES = 550 * 1024 * 1024`.
- `bitcoin-core/src/node/chainstate.cpp:56-58` — `LoadChainstate` rejects
  start when `m_have_pruned && !options.prune` ("You need to rebuild the
  database using -reindex to go back to unpruned mode").
- `bitcoin-core/src/validation.cpp:2330-2383` — assumevalid gate
  (`script_check_reason` set null only when all 5 conditions pass —
  ancestor-of-AV, ancestor-of-best-header, best-header chainwork ≥
  MinimumChainWork, 2-week equivalent-work delay).
- `bitcoin-core/src/validation.cpp:2333` — `assert(hashPrevBlock ==
  view.GetBestBlock())` view consistency precondition.
- `bitcoin-core/src/validation.cpp:2494-2497` — `fScriptChecks` is the
  ONLY gate that branches on assumevalid; maturity/MoneyRange/coinbase/
  sigops/BIP-30/BIP-68 all run regardless. See lines 2574 (`if
  (!tx.IsCoinBase() && fScriptChecks)`).
- `bitcoin-core/src/kernel/chainparams.cpp:109-110, 232-233, 332-333,
  423-424, 435-436, 557-558` — per-network `nMinimumChainWork`
  + `defaultAssumeValid` (mainnet 938343 / testnet4 4842348 / testnet3
  123613 / signet 293175; regtest+testnet4-anti-bury-set empty).
- `bitcoin-core/src/validation.cpp:4229` — `BLOCK_HEADER_LOW_WORK`
  ("too-little-chainwork") header-acceptance gate when `!min_pow_checked`.

**Files audited**
- `src/storage/pruning.ts` — `PruneManager`, `MIN_PRUNE_TARGET`,
  `PRUNE_TARGET_MANUAL = Number.MAX_SAFE_INTEGER`,
  `MIN_BLOCKS_TO_KEEP = 288`, `pruneOneBlockFile`, `findFilesToPrune`,
  `findFilesToPruneManual`, `maybePrune`, `pruneBlockchain`,
  `isBlockPruned`, `getFirstUnprunedHeight`, `getPruneInfo`,
  `unlinkPrunedFiles`, `calculateCurrentUsage`.
- `src/storage/database.ts` — `BlockStatus` enum (HEADER_VALID=1,
  TXS_KNOWN=2, TXS_VALID=4, HAVE_DATA=8, HAVE_UNDO=16, FAILED_VALID=32,
  FAILED_CHILD=64, OPT_WITNESS=128); `putPruneState`/`getPruneState`.
- `src/__tests__/pruning.test.ts` — coverage matrix for PruneManager.
- `src/consensus/assumevalid.ts` — `shouldSkipScripts`,
  `ASSUMED_VALID_HASHES`, 6-condition decision function, `TWO_WEEKS_IN_SECONDS`.
- `src/consensus/assumevalid.test.ts` — 7 + 3 unit tests covering the
  decision matrix.
- `src/test/assumevalid_bench.ts` — microbenchmark for skip vs verify
  path (uses real P2PKH fixture with secp256k1 FFI).
- `src/consensus/connect_block.ts` — `coreConnectBlockChecks`, the
  shared kernel; `assumeValid` fast path at lines 416-480 + `skipScripts`
  flag at line 573.
- `src/sync/blocks.ts:2477, 2501-2536, 2565-2588, 2178-2199,
  2963-2993` — IBD ConnectBlock dispatch + assumevalid context build +
  reorg-intermediate dispatch + auto-prune hook.
- `src/mempool/mempool.ts:2025-2072, 1246-1265` — assumevalid skip gate
  wired into ATMP (always returns false for mempool entries, but uses
  shared `shouldSkipScripts` helper).
- `src/sync/headers.ts:386-407, 827-842` — `nMinimumChainWork` gate at
  AcceptBlockHeader; `needsAntiDoS` predicate.
- `src/consensus/params.ts:387-1034` — per-network `nMinimumChainWork`,
  `assumeValidHeight`, `assumedValid`; MAINNET/TESTNET/TESTNET4/SIGNET/REGTEST.
- `src/rpc/server.ts:1255-1346, 1505-1510, 5749-5784, 7132-7140,
  5930-5956` — `getblockchaininfo` (with `pruneInfo`), pruned-block
  rejection in `getblock`, `pruneblockchain` RPC, `getblockfrompeer`
  prune check, `computeInitialBlockDownload`.
- `src/cli/cli.ts:389-409, 1499-1530, 2684` — `--prune=<n>` arg parse
  (0=off, 1=manual, ≥550=auto MiB), PruneManager construction.

---

## Gate matrix (30 sub-gates / 8 behaviours)

| #  | Behaviour | Sub-gate | Verdict |
|----|-----------|----------|---------|
| 1  | PruneOneBlockFile clears per-block flags | G1: clears `BLOCK_HAVE_DATA` on every block in the file | **BUG-1 (P0)** never updates block-index records; comment confesses "will be updated when we need to access them" — never happens |
| 1  | … | G2: clears `BLOCK_HAVE_UNDO` on every block in the file | **BUG-1 cross-cite** same gap |
| 1  | … | G3: zeros `nFile`/`nDataPos`/`nUndoPos` per record | **BUG-1 cross-cite** never touches per-block records |
| 1  | … | G4: removes pruned descendants from `m_blocks_unlinked` | **BUG-2 (P1)** no `m_blocks_unlinked`-equivalent at all |
| 2  | FindFilesToPrune (auto) | G5: skips if `chain.Height() <= PruneAfterHeight` | **BUG-3 (P1)** no `nPruneAfterHeight` field; auto-prune fires at any height ≥ MIN_BLOCKS_TO_KEEP |
| 2  | … | G6: IBD buffer scaled by `1MB × remaining_blocks` | **BUG-4 (P2)** buffer is just `BLOCKFILE_CHUNK_SIZE + UNDOFILE_CHUNK_SIZE` constant — repeated prune-events in IBD |
| 2  | … | G7: halves target when historical chainstate present (assumeUTXO 2-chainstate split) | **BUG-5 (P1)** no `num_chainstates` adjustment; assumeUTXO under prune mode will prune the historical chainstate's data |
| 2  | … | G8: respects `MIN_BLOCKS_TO_KEEP=288` from active tip | PASS (`pruning.ts:253`) |
| 3  | FindFilesToPruneManual (`pruneblockchain` RPC) | G9: uses `GetPruneRange(nManualPruneHeight)` | PARTIAL — uses `Math.min(targetHeight, chainHeight-MIN_BLOCKS_TO_KEEP)` inline (correct shape, no shared helper) |
| 3  | … | G10: skips file when partially-overlapping prune horizon | PASS (`pruning.ts:332`) |
| 3  | … | G11: `pruneblockchain` RPC dual-mode (auto target ≥ MIN_DISK_SPACE_FOR_BLOCK_FILES; height) | **BUG-6 (P1)** `pruneblockchain` RPC accepts only height — no "target/timestamp" overload; Core accepts EITHER height OR `> 1_000_000_000` timestamp |
| 3  | … | G12: RPC return value = `firstUnprunedHeight` | PASS (`server.ts:5783`) |
| 4  | Restart guard (`prune` state ↔ `-prune` arg) | G13: refuses start when `m_have_pruned && !prune` | **BUG-7 (P0-DATA)** no guard at all; user who runs `hotbuns --prune=550` once then restarts without `--prune` will use an empty/incomplete PruneManager and silently advance on a chain that has data gaps |
| 4  | … | G14: refuses `-reindex` over a pruned datadir without first clearing block files | **BUG-8 (P1)** no `--reindex` flag at all in hotbuns CLI; the entire reindex code path is missing (cross-cite: zero hits for "reindex" in `src/sync/`, `src/chain/`, `src/storage/`) |
| 5  | assumevalid scope (W145 carry-forward) | G15: only `fScriptChecks` is gated; maturity/MoneyRange/coinbase/sigops/BIP-30/BIP-68 run regardless | **BUG-9 (P0-CONS)** W145 finding NOT fixed — `coreConnectBlockChecks` "assumeValid" fast path at `connect_block.ts:416-480` SKIPS coinbase maturity, BIP-68, sigops counting, per-tx fee MoneyRange. Coinbase-value check restored as patch but the cluster remains |
| 5  | … | G16: 6-condition `shouldSkipScripts` mirrors Core's 5-clause `script_check_reason` chain | PASS (`assumevalid.ts:160-223`) |
| 5  | … | G17: 2-week equivalent-work delay uses `GetBlockProofEquivalentTime` | **BUG-10 (P1)** approximates with raw timestamp delta (`bestHeaderTimestamp - pindexTimestamp`); on a chain with extreme difficulty swings the work-equivalent time and wall-clock diverge — Core's helper handles this exactly. Docstring at `assumevalid.ts:122-128` acknowledges the approximation |
| 5  | … | G18: "ancestor of best header" — distinct from "ancestor of assumevalid" check | **BUG-11 (P1)** condition 4 collapsed into condition 3; assumevalid.ts:192-199 explicitly notes "in practice, since getBlockAtHeight returns the best-chain block at that height, condition 3 already ensures this" — but if `assumedValid` is set to a hash on a SIDE chain (operator override pointing at an invalidated tip), Core's distinct check rejects; hotbuns's collapsed check accepts |
| 6  | assumevalid wire-up | G19: gate called on the IBD ConnectBlock path | **BUG-12 (P0-CDIV)** TWO assumevalid mechanisms coexist: the `params.assumeValidHeight > 0 && height <= assumeValidHeight` height-comparison at `sync/blocks.ts:2477` AND the 6-condition `shouldSkipScripts` at line 2535 — the height-comparison drives the `assumeValid` (fast-path) flag, while `shouldSkipScripts` drives only `skipScripts`. The height-comparison ignores the 5 safety conditions (`assumedValid` set / present-in-index / ancestor-of-AV / chainwork / 2-week-delay) |
| 6  | … | G20: gate called on reorg-intermediate ConnectBlock path | **BUG-13 (P1)** reorg-intermediate at `sync/blocks.ts:2178` uses the SAME height-comparison shortcut (line 2178-2179) and never builds an AssumeValidContext — bypasses `shouldSkipScripts` entirely |
| 6  | … | G21: bench harness reflects production usage (script verification IS wired in IBD) | **BUG-14 (P1)** `test/assumevalid_bench.ts:23-26` confesses: "hotbuns's IBD path … does not currently invoke script verification — P2-OPT-ROUND-2 gap". The benchmark exercises the helper directly, not the production path, so the reported "10x speedup" doesn't reflect IBD reality |
| 7  | nMinimumChainWork | G22: per-network value matches Core kernel/chainparams.cpp | PASS (mainnet/testnet3/testnet4/signet/regtest all match exactly) |
| 7  | … | G23: `BLOCK_HEADER_LOW_WORK` rejection at AcceptBlockHeader misbehaves the sender | **BUG-15 (P1)** `headers.ts:401-407` only `continue`s after logging; no `peer.misbehaving(100, ...)` call. Core: `Misbehaving(100, "header invalid")`. Allows a low-chainwork-spamming peer to keep sending headers indefinitely |
| 7  | … | G24: IsInitialBlockDownload exits when tip-recent AND chainwork ≥ `nMinimumChainWork` | PARTIAL — `server.ts:5946-5948` uses the `<` (correct shape) and 24-hour `max_tip_age`, but the latch state lives in the RPC server, not in a single chainstate-wide cache. Two RPC servers behind a load balancer would each track separately |
| 7  | … | G25: `MinimumConnectedChainWork` used by net_processing to evict low-work peers | **BUG-16 (P1)** no `MinimumConnectedChainWork` analog in `p2p/manager.ts`; a peer that has advertised height but whose best header chainwork is below ours is never disconnected for that reason alone |
| 8  | `defaultAssumeValid` per-network parity | G26: mainnet `assumedValid` matches Core (938343 = 00000000…ba5ac) | PASS (`params.ts:450`) |
| 8  | … | G27: testnet3 `assumedValid` matches Core (123613) | PASS (`params.ts:745`) but **BUG-17 (P1)** testnet3 inherits MAINNET's `assumeValidHeight=938343` via spread, never overridden — `assumeValidHeight` and `assumedValid` are now for two DIFFERENT chains; the height-comparison fast path uses 938343 (mainnet's height) on testnet3 |
| 8  | … | G28: testnet4 `assumedValid` matches Core (4842348) | PASS (`params.ts:864`) but **BUG-18 (P0-CDIV)** `assumeValidHeight=123613` is TESTNET3's height (Core kernel/chainparams.cpp:332); testnet4's defaultAssumeValid block is at height 4842348. Height-comparison-driven fast path fires for blocks 0..123613 on testnet4 — but the AV hash points at block 4842348. Two networks' values silently swapped |
| 8  | … | G29: signet `assumedValid` matches Core (293175) | PASS (`params.ts:989`) but **BUG-19 (P1)** signet inherits `assumeValidHeight=938343` via spread (same shape as BUG-17) |
| 8  | … | G30: regtest `assumeValidHeight=0` AND `assumedValid=undefined` (explicit override) | PASS (`params.ts:1029-1031`) — the only network where the inherit-from-MAINNET trap is explicitly closed |

---

## BUG-1 (P0) — `pruneOneBlockFile` never clears `BLOCK_HAVE_DATA` / `HAVE_UNDO` on the block records

**Severity:** P0 (correctness gap). Bitcoin Core's `PruneOneBlockFile`
(blockstorage.cpp:258-290) iterates every `m_block_index` entry whose
`nFile == fileNumber` and:
```cpp
pindex->nStatus &= ~BLOCK_HAVE_DATA;
pindex->nStatus &= ~BLOCK_HAVE_UNDO;
pindex->nFile = 0;
pindex->nDataPos = 0;
pindex->nUndoPos = 0;
m_dirty_blockindex.insert(pindex);
```

hotbuns's `pruneOneBlockFile` (`pruning.ts:189-209`) **only**
overwrites the per-file aggregate (`createEmptyBlockFileInfo()`) and
leaves all `BlockIndexRecord.status` bytes untouched. The inline comment
self-confesses:

> // Update all block index records that reference this file
> // We need to iterate through the database and find blocks in this file
> // This is expensive, but necessary for correctness
> ...
> // For now, we mark the file info as empty
> // The block index records will be updated when we need to access them

This is **comment-as-confession (instance #6 in W76+ tracking)** —
the docstring explicitly states the correct behaviour and explicitly
declines to implement it. Net effect:

- `BlockIndexRecord.status` of every pruned block keeps `HAVE_DATA=8`
  + `HAVE_UNDO=16` bits set. Any consumer that inspects per-block status
  (e.g. `getblock` RPC, FindMostWorkChain analogs, `verifychain` if it
  existed, future assumeUTXO snapshot validation) sees the wrong shape.
- `dataPos` field still points at the pruned file's offset. A
  consumer that tries to read the block via the index → file mapping
  will receive ENOENT (the file was unlinked at `unlinkPrunedFiles`)
  rather than a clean "this block is pruned" signal.
- Cross-impl: this is the inverse of `isBlockPruned` — that function
  walks the per-file aggregate (correct), but `getBlockIndex` returns
  records with stale flags. RPC `getblock` happens to short-circuit on
  `isBlockPruned(blockIndex.height)` (`server.ts:1505`), but other
  paths (block index lookup by hash, getblockheader, getchaintips) do
  NOT, and will report `confirmations` based on stale data.

**File:** `src/storage/pruning.ts:189-209`

**Core ref:** `bitcoin-core/src/node/blockstorage.cpp:258-290`

---

## BUG-2 (P1) — No `m_blocks_unlinked` analog; orphan-block pruning silently absent

**Severity:** P1 (consensus-progress gap on long forks). Core's
`PruneOneBlockFile` also walks `m_blocks_unlinked` (the multimap of
parent → side-chain children whose parents have not yet been
validated) and erases any entry whose value is the pruned pindex.
Without this cleanup the multimap leaks across prune events; with it,
Core guarantees that a side-chain block whose body was pruned cannot
be re-selected as a candidate without redownloading.

hotbuns has no `m_blocks_unlinked`-equivalent at all (grep
`unlinked` across `src/`: zero hits). Side-branch acceptance during IBD
is also constrained (see W148 BUG-8 in blockbrew for cross-impl shape).
Once a side-branch body is pruned, hotbuns will silently retry
`FindMostWorkChain`-equivalent computations with a candidate that has
neither body nor undo data.

**File:** N/A (absent).

**Core ref:** `bitcoin-core/src/node/blockstorage.cpp:273-284`,
`bitcoin-core/src/node/blockstorage.h:362-364` (`m_blocks_unlinked`).

---

## BUG-3 (P1) — `nPruneAfterHeight` parameter entirely absent

**Severity:** P1 (resource/timing divergence). Core gates auto-prune on
`chain.m_chain.Height() > chainman.GetParams().PruneAfterHeight()`:
- mainnet `nPruneAfterHeight = 100_000`
- testnet3/testnet4 `nPruneAfterHeight = 1_000`
- signet `nPruneAfterHeight = 1_000_000`
- regtest `nPruneAfterHeight = 1_000`

A node syncing from genesis under `-prune=550` will NOT prune until the
active chain exceeds this threshold — preserving the early chain for
operators who need it for one-time scans (txindex bootstrap, fee history).

hotbuns has no such parameter in `ConsensusParams` (grep
`PruneAfterHeight\|pruneAfter`: zero hits in `params.ts`).
`findFilesToPrune` (`pruning.ts:240-295`) only enforces
`MIN_BLOCKS_TO_KEEP=288`, so auto-prune can fire as early as height 288.
A `-prune=550` node started on signet (Core would wait until h=1M) will
begin pruning at h=288, producing a vastly different on-disk shape from
a Core peer started at the same time.

**File:** `src/consensus/params.ts` (absent across all 5 network defs);
`src/storage/pruning.ts:240-258`.

**Core ref:** `bitcoin-core/src/node/blockstorage.cpp:343-345`,
`bitcoin-core/src/kernel/chainparams.cpp:97/220/319/410/543`.

---

## BUG-4 (P2) — Auto-prune buffer is a constant, not IBD-scaled

**Severity:** P2 (re-prune thrash). Core's `FindFilesToPrune`
(blockstorage.cpp:362-368) scales the safety buffer during IBD:
```cpp
if (chainman.IsInitialBlockDownload() && target_sync_height > chain_tip_height) {
    static constexpr uint64_t average_block_size = 1000000;
    const uint64_t remaining_blocks = target_sync_height - chain_tip_height;
    nBuffer += average_block_size * remaining_blocks;
}
```
This prevents prune-thrash early in IBD: prune one file → headroom →
download a chunk → headroom exhausted → prune one file → ... .

hotbuns's buffer (`pruning.ts:263`) is a flat `BLOCKFILE_CHUNK_SIZE +
UNDOFILE_CHUNK_SIZE = 17 MiB`. During mainnet IBD an `--prune=550` node
will hit the prune threshold every ~17 MiB of block download
(~17 blocks at modern sizes), triggering the O(file_count) usage scan
hundreds of thousands of times.

**File:** `src/storage/pruning.ts:262-264`

**Core ref:** `bitcoin-core/src/node/blockstorage.cpp:362-368`.

---

## BUG-5 (P1) — `num_chainstates` halving absent (assumeUTXO under prune)

**Severity:** P1 (assumeUTXO + prune correctness). Core's
`FindFilesToPrune` divides the target by `num_chainstates` (2 when a
historical chainstate is present alongside the snapshot chainstate,
`blockstorage.cpp:335-337`). Without this, an `assumeUTXO` node under
`-prune=N` would let the snapshot chainstate consume the entire prune
target, leaving zero headroom for the historical chainstate's blocks.

hotbuns's `findFilesToPrune` always uses
`Math.max(MIN_PRUNE_TARGET, this.pruneTarget)` (`pruning.ts:250`).
hotbuns has assumeUTXO scaffolding in `params.ts` (the `assumeutxo`
Map with 5 mainnet entries) but no dual-chainstate path; when one is
wired (W138 fleet-pattern), the prune accounting will be wrong.

**File:** `src/storage/pruning.ts:250`.

**Core ref:** `bitcoin-core/src/node/blockstorage.cpp:335-337`.

---

## BUG-6 (P1) — `pruneblockchain` RPC missing timestamp dual-mode

**Severity:** P1 (RPC parity / operator UX). Core's `pruneblockchain`
RPC (rpc/blockchain.cpp:`pruneblockchain`) accepts a height/timestamp
overload:
- `height <= 1_000_000_000` → interpret as block height
- `height > 1_000_000_000` → interpret as Unix timestamp; prune blocks
  whose timestamp is before this value

hotbuns's handler (`server.ts:5754-5784`) only validates
`heightParam >= 0 && integer && <= bestBlock.height` — a timestamp
argument (the more common operator usage, e.g. "prune everything older
than 6 months ago") raises `Blockchain is shorter than the attempted
prune height (<bestHeight>)`.

**File:** `src/rpc/server.ts:5754-5784`.

**Core ref:** Bitcoin Core `rpc/blockchain.cpp::pruneblockchain`
(dual-arg overload).

---

## BUG-7 (P0-DATA) — No prune-restart guard (`m_have_pruned && !options.prune`)

**Severity:** P0-DATA (silent data inconsistency, recoverable only by
manual wipe). Core's `LoadChainstate` (`node/chainstate.cpp:56-58`):
```cpp
if (chainman.m_blockman.m_have_pruned && !options.prune) {
    return {FAILURE, _("You need to rebuild the database using -reindex
                       to go back to unpruned mode. This will redownload
                       the entire blockchain")};
}
```

hotbuns has NO such guard. The CLI flow (`cli.ts:1513-1527`) only
constructs a `PruneManager` if `mergedConfig.prune > 0`. A user who
ran with `--prune=550`, pruned some files, then restarts without
`--prune` will:
1. Skip PruneManager construction entirely.
2. `getblockchaininfo.pruned` will be FALSE (no manager → defaults).
3. Block-index records still have `HAVE_DATA` set (BUG-1) so callers
   that consult only the record believe the data is available.
4. Any RPC that reaches the file layer (`getblock` calls `db.getBlock`
   which reads from blk*.dat) errors with ENOENT — but the
   `isBlockPruned` short-circuit at `server.ts:1505` is gated on
   `pruneManager?.isPruneMode()` which is now `undefined → false`,
   so the catch-all "Block not available (pruned data)" at line 1515
   fires instead with no context that pruning ever happened.

The pruning **state is persisted** (`db.putPruneState`), but is never
read on startup outside of `PruneManager.init()` — and `PruneManager`
isn't constructed if `--prune` is absent.

**File:** `src/cli/cli.ts:1513-1527`; `src/storage/pruning.ts:88-97`.

**Core ref:** `bitcoin-core/src/node/chainstate.cpp:54-58`.

---

## BUG-8 (P1) — `--reindex` flag entirely absent

**Severity:** P1 (operability + recovery from BUG-7). Core's `-reindex`
rebuilds the block index from blk*.dat files and `-reindex-chainstate`
rebuilds the UTXO set; both are critical recovery paths after database
corruption or for switching prune↔unprune mode.

hotbuns has no `--reindex` CLI flag (grep `reindex` in `src/cli/`:
zero hits) and no reindex code path (grep `reindex` outside
`logger.ts:38`: zero hits). The only recovery from BUG-7 is manual
deletion of the datadir.

**File:** `src/cli/cli.ts` (absent).

**Core ref:** `bitcoin-core/src/init.cpp` `-reindex`/`-reindex-chainstate`.

---

## BUG-9 (P0-CONS) — W145 "Assume-valid scope creep" NOT fixed; fast path skips maturity + MoneyRange + BIP-68 + sigops

**Severity:** P0-CONS (consensus). W145 (May 18 2026, 4-of-4 quad)
called out the hotbuns `assumeValid` fast path in `connect_block.ts`
as the canonical "Assume-valid scope creep" pattern: Core's
`fScriptChecks` gate ONLY suppresses signature/script verification
(`validation.cpp:2494, 2574`), but hotbuns's `coreConnectBlockChecks`
fast path at `connect_block.ts:416-480`:

```ts
if (assumeValid) {
  // ... spend inputs, add outputs ...
  // Coinbase-value check: consensus-critical, runs even under assumevalid.
  // ...
  return { ok: true, spentOutputs: [], ... };
}
```

The early `return` SKIPS, relative to the full-path (line 482-740):
- COINBASE_MATURITY enforcement (`coreConnectBlockChecks:533-542`)
- BIP-68 / CSV sequence locks (`:556-570`)
- Sigops cost ceiling `MAX_BLOCK_SIGOPS_COST` (`:683-694`)
- Per-coin MoneyRange (`:610-616`)
- Accumulated input MoneyRange (`:619-624`)
- Per-tx `bad-txns-in-belowout` (`:662-667`)
- Per-tx fee MoneyRange accumulator (`:669-678`)

Coinbase-value was restored as a patch (`:454-471`) — but the other
six were not. Carry-forward count: **W145 finding open ~24 hours,
no fix landed**. Mainnet impact: blocks at or below
`assumeValidHeight=938343` (the default) hit the fast path; if a
`-assumevalid=0` flag existed, the operator could opt out — but the
CLI has no `--assumevalid` arg at all (grep `assumevalid` in
`src/cli/`: zero hits except the `--prune` history comment).

Mempool `MoneyRange`-violating blocks below 938343 would normally be
caught at `CheckBlock` / `validateBlock` (called by
`sync/blocks.ts:2466`); hotbuns's `validateBlock` covers some but
verifying full Core parity here is outside W149 scope. The point of the
W145 P0-CONS is that the `coreConnectBlockChecks` fast path is the
contract for "assumevalid skips only scripts", and that contract is
broken.

**File:** `src/consensus/connect_block.ts:411-480`.

**Core ref:** `bitcoin-core/src/validation.cpp:2494-2497, 2574`.

**W145 cross-cite:** "Assume-valid scope creep" / NEW PATTERN
(hotbuns BUG-2..6 cluster).

---

## BUG-10 (P1) — 2-week guard approximates `GetBlockProofEquivalentTime` with raw timestamp delta

**Severity:** P1 (consensus-edge). Core's 2-week safety guard uses
`GetBlockProofEquivalentTime(bestHeader, pindex, bestHeader, params)`
(validation.cpp:2364), which computes how much wall-clock work the
chain between `pindex` and `bestHeader` REPRESENTS at the current
difficulty. The wall-clock timestamp delta is generally close to this
value but diverges on chains with:
- Difficulty drops (testnet 20-min rule, testnet4 BIP-94 retarget)
- Large stretches of orphan/uncle blocks
- Min-difficulty regtest

hotbuns's `shouldSkipScripts` (`assumevalid.ts:212`) does:
```ts
const equivalentTimeDelta = ctx.bestHeaderTimestamp - ctx.pindexTimestamp;
if (equivalentTimeDelta <= TWO_WEEKS_IN_SECONDS) { ... }
```

The docstring at lines 122-131 acknowledges:
> We approximate this as the block timestamp difference: bestHeader.timestamp - pindex.timestamp, which is safe and correct when the chain is far ahead of pindex.

"Safe" is true in the conservative direction (skip less often → more
verify), but the **direction can be wrong on testnet4**: a sequence
of min-difficulty blocks between pindex and bestHeader could have
timestamps several days apart but represent < 2 weeks of equivalent
work — then Core would refuse to skip, hotbuns would skip.

**File:** `src/consensus/assumevalid.ts:212`.

**Core ref:** `bitcoin-core/src/validation.cpp:2364` +
`bitcoin-core/src/pow.cpp::GetBlockProofEquivalentTime`.

---

## BUG-11 (P1) — Condition 4 (ancestor of best header) collapsed into condition 3

**Severity:** P1 (operator-override edge). Core's `script_check_reason`
chain (validation.cpp:2358-2361) checks ancestor-of-AV (cond 3) AND
ancestor-of-best-header (cond 4) as **distinct** gates:
```cpp
} else if (it->second.GetAncestor(pindex->nHeight) != pindex) {
    script_check_reason = "block not in assumevalid chain";
} else if (m_chainman.m_best_header->GetAncestor(pindex->nHeight) != pindex) {
    script_check_reason = "block not in best header chain";
}
```

hotbuns's `shouldSkipScripts` (`assumevalid.ts:192-199`) explicitly
collapses them:
> // Condition 4: ... In practice, since getBlockAtHeight returns the best-chain block at that height, condition 3 already ensures this when the assumed-valid block IS the best header or an ancestor of it. We check explicitly for safety.

But the "check explicitly for safety" is just `if (!ctx.bestHeader)
return false`. The actual ancestor-of-best-header test is never
performed. Scenario where this matters: operator sets
`-assumevalid=<hash>` to a side-chain tip that was invalidated by
RPC; condition 3 passes (the hash IS in the index and `pindex` IS its
ancestor) but Core's condition 4 would fail because best_header is on
the canonical chain, NOT a descendant of the invalidated AV hash.

**File:** `src/consensus/assumevalid.ts:192-199`.

**Core ref:** `bitcoin-core/src/validation.cpp:2360-2361`.

---

## BUG-12 (P0-CDIV) — Two assumevalid mechanisms coexist; height-comparison ignores 5 safety conditions

**Severity:** P0-CDIV (consensus-divergent). hotbuns's IBD ConnectBlock
dispatch at `sync/blocks.ts:2477` and 2535 uses TWO DISTINCT
assumevalid mechanisms in the same call:

```ts
// Line 2477 — drives the fast-path `assumeValid` flag (W145 scope creep)
const assumeValid = this.params.assumeValidHeight > 0 &&
                    height <= this.params.assumeValidHeight;

// Line 2535 — drives `skipScripts` flag (the 6-condition gate)
const skipScripts = shouldSkipScripts(avCtx).skip;
```

The fast-path `assumeValid` flag (BUG-9) is driven by a naive
height-comparison that ignores all 5 Core safety conditions
(assumed-valid hash configured / present-in-index / ancestor-of-AV /
best-header-chainwork ≥ MinimumChainWork / 2-week delay). The
`skipScripts` flag IS gated by `shouldSkipScripts`. But because the
fast path returns early at `connect_block.ts:480`, `skipScripts` is
**shadowed** when `assumeValid` is true — the 6-condition gate is
effectively dead code in the IBD steady-state.

Two-pipeline guard: shape repeats the **W125 / W138 / W140 two-pipeline
guard** family — distinct paths that diverge on a buggy predicate.

**File:** `src/sync/blocks.ts:2477, 2535-2588`;
`src/consensus/connect_block.ts:416-480` (fast-path return).

**Core ref:** `bitcoin-core/src/validation.cpp:2345-2383` (single
`script_check_reason` chain, one gate).

---

## BUG-13 (P1) — Reorg-intermediate ConnectBlock bypasses `shouldSkipScripts`

**Severity:** P1 (consensus-edge during reorgs). The reorg path at
`sync/blocks.ts:2178-2199` uses the same height-comparison shortcut
WITHOUT building an `AssumeValidContext` and never calls
`shouldSkipScripts`:
```ts
const intermAssumeValid =
  this.params.assumeValidHeight > 0 &&
  intermediate.height <= this.params.assumeValidHeight;
const intermResult = await coreConnectBlockChecks(intermBlock, ..., {
  assumeValid: intermAssumeValid,
  skipScripts: false,   // ← always false; gate not consulted
  ...
});
```

During a reorg over blocks at or below `assumeValidHeight`, the
intermediate connect uses the **fast-path scope-creep route** with
`skipScripts=false` — but since `assumeValid=true` triggers the fast
path's early return at `connect_block.ts:480`, `skipScripts` is again
shadowed. The 6-condition gate's 5 safety preconditions
(assumed-valid hash configured / present-in-index / 2-week delay etc.)
are not enforced on the reorg intermediate path.

**File:** `src/sync/blocks.ts:2178-2199`.

**Core ref:** `bitcoin-core/src/validation.cpp:3198-3220` (reorg
ConnectTip uses the same ConnectBlock entry, no special path).

---

## BUG-14 (P1) — `assumevalid_bench.ts` doesn't reflect production wiring

**Severity:** P1 (benchmark validity). `src/test/assumevalid_bench.ts`
self-documents the gap at lines 9-13, 20-26, 178-187:
> hotbuns's IBD path (BlockSync.connectBlock) does not currently
> invoke script verification — P2-OPT-ROUND-2 gap
> "hotbuns has verifyAllInputsParallel defined but never imported;
> script verification absent from IBD path".

The benchmark calls `verifyScript(scriptSig, scriptPubKey, witness,
flags, sigHasher)` directly with a synthetic P2PKH input. The
production IBD path in `sync/blocks.ts:2477` already does NOT call
script verification (since assumeValid=true skips it), and even when
the operator sets `assumeValidHeight=0` to force per-block script
verification, the helper path through `verifyAllInputsParallel` is
imported in `connect_block.ts:73-74` and IS called at line 585 — so
the benchmark's premise (P2-OPT-ROUND-2 still open) appears stale.

**File:** `src/test/assumevalid_bench.ts:9-13, 178-187`.

**Cross-cite:** `src/consensus/connect_block.ts:585` (`scriptResult =
await verifyAllInputsParallel(tx, inputUTXOs, scriptFlags);`).

Either the benchmark's claim is wrong (P2-OPT-ROUND-2 has been
closed) and the docstrings need updating, OR the production path
described at `connect_block.ts:585` has never executed in practice
(BUG-9's fast path returns at line 480 before this point). Both
findings would be worth a `t.Logf` confirmation — dead code marker.

---

## BUG-15 (P1) — `too-little-chainwork` reject doesn't misbehave the peer

**Severity:** P1 (DoS-mitigation gap). Core's AcceptBlockHeader at
validation.cpp:4229:
```cpp
if (!min_pow_checked) {
    return state.Invalid(BlockValidationResult::BLOCK_HEADER_LOW_WORK,
                         "too-little-chainwork");
}
```
The caller (`net_processing.cpp::ProcessHeadersMessage`) inspects the
`BlockValidationState` and triggers `Misbehaving(pfrom, 100,
"header invalid")`.

hotbuns's equivalent (`sync/headers.ts:401-407`) only logs and
`continue`s through the loop:
```ts
if (!minPowChecked && this.params.nMinimumChainWork > 0n &&
    chainWork < this.params.nMinimumChainWork) {
  console.warn(`Rejected low-chainwork header from ${fromPeer?.host ?? "local"}: ...`);
  continue;
}
```

No `peer.misbehaving(100, "too-little-chainwork")`. A peer that
spams sub-MinimumChainWork header batches is silently absorbed in
log noise and stays connected, occupying a slot.

**File:** `src/sync/headers.ts:401-407`.

**Core ref:** `bitcoin-core/src/validation.cpp:4229` +
`bitcoin-core/src/net_processing.cpp::ProcessHeadersMessage`
(Misbehaving call).

---

## BUG-16 (P1) — `MinimumConnectedChainWork` analog absent

**Severity:** P1 (peer-selection gap). Core's `net_processing.cpp`
exposes `MinimumConnectedChainWork()` (currently
`arith_uint256{1} << 100` — a much higher bar than `nMinimumChainWork`
for ACTIVE chain). Peers whose best chain falls below this bar are
preferentially evicted when the connection slots fill — this protects
against a partition where many low-work peers crowd out the few
high-work ones.

grep `MinimumConnectedChainWork\|minimumConnectedChainWork` across
`src/p2p/`: zero hits. No peer eviction prefers high-chainwork.
PeerManager (`src/p2p/manager.ts`) evicts on misbehavior score and
inactivity timeouts only.

**File:** `src/p2p/manager.ts` (absent).

**Core ref:** `bitcoin-core/src/net_processing.cpp::MinimumConnectedChainWork`.

---

## BUG-17 (P1) — TESTNET3 inherits MAINNET's `assumeValidHeight=938343` via spread

**Severity:** P1 (consensus-edge / silent dead-field). hotbuns's
TESTNET (testnet3) definition at `params.ts:718-768`:
```ts
export const TESTNET: ConsensusParams = {
  ...MAINNET,                                  // ← inherits assumeValidHeight: 938343
  // ... 50 other overrides ...
  assumedValid: "0000000002368b1e4ee27e2e85676ae6f9f9e69579b29093e9a82c170bf7cf8a",
  // ^ testnet3 height 123613 per Core
  // assumeValidHeight NEVER overridden
};
```

`testnet3.assumeValidHeight` ends up at **938343 (mainnet's value)**.
The height-comparison fast-path at `sync/blocks.ts:2477` fires for
all testnet3 blocks 0..938343 — but the `assumedValid` hash is for
block 123613. Two different heights for the same network.

The 6-condition `shouldSkipScripts` gate happens to mask this (via the
`pindex.height > assumedValidEntry.height` guard at
`assumevalid.ts:184` — if the AV entry IS in the index, the height
check is consistent), but the fast-path scope-creep route (BUG-9 +
BUG-12) is gated on `params.assumeValidHeight`, not the resolved AV
entry. So between height 123614 and 938343 on testnet3:
- `assumeValid = true` (fast path active, BUG-9 scope creep)
- `shouldSkipScripts = false` (the AV entry is at 123613, this block
  is above)
- Combined: fast path runs (skipping maturity etc.) but `skipScripts`
  is set to false (irrelevant due to early return)

**Net effect:** ~815k testnet3 blocks above 123613 hit the
scope-creep fast path even though the configured AV is far below them.

**File:** `src/consensus/params.ts:718-720, 745, 1028-1031`.

**Core ref:** `bitcoin-core/src/kernel/chainparams.cpp:332-333`.

---

## BUG-18 (P0-CDIV) — TESTNET4 `assumeValidHeight=123613` is TESTNET3's height (network values swapped)

**Severity:** P0-CDIV (consensus-divergent on testnet4 IBD). Core's
testnet4 `defaultAssumeValid` is at block 4842348
(`kernel/chainparams.cpp:233`). hotbuns:

```ts
export const TESTNET4: ConsensusParams = {
  ...MAINNET,
  // ... 30 overrides ...
  assumeValidHeight: 123613,    // ← TESTNET3's height!
  assumedValid: "000000007a61e4230b28ac5cb6b5e5a0130de37ac1faf2f8987d2fa6505b67f4",
  // ^ testnet4 block 4842348 — different chain, different height
};
```

The CLI comment at `params.ts:861-862` reads "Skip script/sigop
verification for blocks at or below this height. Testnet4 tip as of
2026-03: ~60k blocks, set conservatively." That comment is stale —
testnet4 has been at heights ≫ 60k since at least mid-2024, and the
fleet-standard `assumedValid` hash points at h=4842348, not 123613.

Two divergences:
1. The fast-path `assumeValid` flag (BUG-9 scope creep) fires for
   testnet4 blocks 0..123613 — a much narrower band than Core's
   block 0..4842348 (assumed valid up to 4.8M).
2. The fast-path scope creep DOES fire on those 123k blocks, applying
   non-Core-conformant validation (BUG-9 cluster).

The CLI also has no `--assumevalid` flag, so an operator cannot
correct this in-place; only a recompile.

**File:** `src/consensus/params.ts:861-864`.

**Core ref:** `bitcoin-core/src/kernel/chainparams.cpp:232-233`.

---

## BUG-19 (P1) — SIGNET inherits MAINNET's `assumeValidHeight=938343`

**Severity:** P1 (same shape as BUG-17, signet variant). SIGNET
(`params.ts:948-990`) spreads MAINNET and never overrides
`assumeValidHeight`. End state: signet uses `assumeValidHeight=938343`
but `assumedValid` is the signet hash at h=293175. Fast-path
scope-creep fires for signet blocks 0..938343 (signet's current tip is
~200k blocks as of mid-2026, so almost the whole chain).

**File:** `src/consensus/params.ts:948-989`.

**Core ref:** `bitcoin-core/src/kernel/chainparams.cpp:423-424`.

---

## BUG-20 (P1) — `isBlockPruned` returns true for any height above the live-file set

**Severity:** P1. The function (`pruning.ts:455-464`):
```ts
isBlockPruned(height: number): boolean {
  for (const info of this.blockFileInfo.values()) {
    if (info.nSize > 0 && info.nHeightFirst <= height && info.nHeightLast >= height) {
      return false;
    }
  }
  return this.havePruned;
}
```

For a future height (e.g. tip+1, tip+288) that has not yet been
allocated to any file, the loop finds no match and returns
`havePruned`. Once any prune event fires, the function then claims
EVERY height above the highest stored block is "pruned". RPC
`getblock` consumers using `confirmations = (blockIndex.height >
firstUnprunedHeight) ? ... : -1` will mis-report negative
confirmations for valid future tips.

**File:** `src/storage/pruning.ts:455-464`.

**Core ref:** `bitcoin-core/src/node/blockstorage.cpp:609-614`
(`IsBlockPruned`: uses `m_have_pruned && !(block.nStatus &
BLOCK_HAVE_DATA) && (block.nTx > 0)` — requires nTx>0 to confirm the
block was actually known to exist).

---

## BUG-21 (P2) — `PRUNE_TARGET_MANUAL = Number.MAX_SAFE_INTEGER` ≠ Core's `uint64_t::max()`

**Severity:** P2 (semantic encoding). Core's sentinel is
`std::numeric_limits<uint64_t>::max() = 18446744073709551615`. hotbuns
uses `Number.MAX_SAFE_INTEGER = 9007199254740991` (`pruning.ts:44`).
The comment at lines 35-43 acknowledges the divergence:
> we use `Number.MAX_SAFE_INTEGER` because that's the largest exact
> integer a JS `number` can hold (uint64::max would silently round).

This is correct for in-process semantics. But the persisted prune state
(`database.ts:751`) writes the value as `BigUInt64LE`:
```ts
buf.writeBigUInt64LE(BigInt(pruneTarget), 1);
```
On read it's converted back via `Number(value.readBigUInt64LE(1))`
(line 767). If a hypothetical future hotbuns persists Core's
`uint64::max` (e.g. via interop with a Core blocks/blocks_index dump),
the round-trip through `Number()` would round-down and the manual-mode
sentinel would not survive. Documented but not closed.

**File:** `src/storage/pruning.ts:34-44`,
`src/storage/database.ts:751, 767`.

---

## BUG-22 (P2) — `getPruneInfo()` omits `prune_target_size` for manual mode but reports `automatic_pruning: false`

**Severity:** P2 (RPC parity). Core's `getblockchaininfo` includes:
- `pruned: true` (always when prune > 0)
- `pruneheight: <int>` (always when pruned)
- `automatic_pruning: false` for `-prune=1` manual mode
- `prune_target_size: <bytes>` ONLY when automatic

hotbuns (`pruning.ts:469-505`) follows the same shape (PASS), but the
`pruneTarget = PRUNE_TARGET_MANUAL` sentinel
(`9007199254740991`) is NOT actually masked from any caller — if the
RPC server (`server.ts:1340-1342`) ever decides to emit it under a
flag rename, the unmasked sentinel would leak to the client as
`prune_target_size: 9007199254740991`. The check at `pruning.ts:496`
gates this correctly today, but the invariant relies on every future
caller remembering to check `automatic_pruning` first.

**File:** `src/storage/pruning.ts:469-505`,
`src/rpc/server.ts:1338-1343`.

---

## BUG-23 (P2) — No `FlushBlockFile`-equivalent; block files are append-only without explicit fsync

**Severity:** P2 (durability). Core's `FlushBlockFile`
(blockstorage.cpp:742-769) explicitly fsyncs the block file (with
`fFinalize` controlling whether the trailing zero-fill is removed)
and the undo file. hotbuns `src/storage/blockfile.ts` is append-only
via `fs.appendFile` / `fs.writeFile` and relies on the OS page cache
+ background flushing. A power-loss during IBD will lose the
most-recent block payload but the index record will still reference
its position — making startup recovery require a full file scan or
truncation, neither of which hotbuns implements.

(See W148 BUG-18 in blockbrew for the analogous "DisconnectBlock
failure does not halt the node" — same family: durability gaps that
manifest only on crash.)

**File:** `src/storage/blockfile.ts` (no fsync, no FlushBlockFile-equivalent).

**Core ref:** `bitcoin-core/src/node/blockstorage.cpp:742-769`.

---

## Fleet-pattern smells

- **Assume-valid scope creep** (P0-CONS, W145 carry-forward): BUG-9.
  Carry-forward count: W145 catalogued the cluster on May 18 2026;
  ~24h later it is **unfixed in production code**. Pattern is the
  hotbuns analogue of W128 banman 8/10 fleet-wide finding —
  consensus-critical gate misuses the "skip scripts" intent to also
  skip 5 other validation primitives.
- **Two-pipeline guard** (15th distinct extension across W76+
  tracking): BUG-12 — two assumevalid mechanisms (height-comparison +
  6-condition) coexist in the same call, with the height-comparison
  effectively shadowing the 6-condition gate via early-return.
- **Comment-as-confession (7th instance)**: BUG-1
  (`pruning.ts:195-200` — "Update all block index records that
  reference this file ... For now, we mark the file info as empty
  The block index records will be updated when we need to access
  them"); 4th instance directly admitting the missing implementation
  rather than just acknowledging an approximation. Cross-cite to
  rustoshi W141 + nimrod W142 + lunarblock W144 + ... .
- **Inherit-from-MAINNET silent dead-field cluster**: BUG-17,
  BUG-18, BUG-19. Three of four non-regtest networks (testnet3,
  testnet4, signet) inherit MAINNET's `assumeValidHeight=938343`
  via spread and silently use it. Only regtest closes the trap
  explicitly at `params.ts:1028-1031` ("assumeValidHeight must be 0
  (not the mainnet 938343 inherited via ...MAINNET)"). Same shape as
  W138 fleet-pattern dead-data plumbing — the field is set, but the
  per-network override is forgotten 3 of 4 times.
- **Dead-data plumbing**: BUG-3 (`nPruneAfterHeight` per-network
  field entirely absent; not just unconsulted, NEVER plumbed
  through). BUG-8 (`--reindex` flag entirely absent; recovery from
  BUG-7 impossible). Different from the W138 family which had the
  field but no caller — here the field doesn't even exist.
- **Carry-forward re-anchor**: BUG-9 is **W145's** P0-CONS finding
  re-confirmed at W149; ~24 hours, no fix. Same pattern as blockbrew
  W123 P0-CDIV `MsgTx.Version int32` carried to W148 (~3 weeks).
- **30-of-30 GATES — not fired**: this audit has 23 BUGs across 8
  behaviours; the prune subsystem is structurally similar to Core
  (BUGs cluster on per-block flag propagation, restart guards, and
  the dead `nPruneAfterHeight` field). Assumevalid is a single-clause
  divergence (the fast-path scope creep) with two amplifying gaps
  (BUG-12 mechanism duplication, BUG-13 reorg path).

---

## Summary

23 BUGs catalogued across 8 behaviours. Severity-totals:

- **P0-CONS** (consensus-divergent / divergence): 1 — BUG-9
  (W145 carry-forward; assume-valid scope creep)
- **P0-CDIV** (consensus-divergent): 2 — BUG-12 (two-mechanism
  assumevalid; height-comparison ignores 5 safety conditions),
  BUG-18 (testnet4 `assumeValidHeight=123613` is testnet3's value)
- **P0** (semantic gap): 1 — BUG-1 (pruneOneBlockFile leaves
  `HAVE_DATA`/`HAVE_UNDO` bits set on every record)
- **P0-DATA** (silent data inconsistency): 1 — BUG-7 (no
  prune-restart guard)
- **P1** (correctness / RPC parity / DoS): 14 — BUG-2, BUG-3,
  BUG-5, BUG-6, BUG-8, BUG-10, BUG-11, BUG-13, BUG-14, BUG-15,
  BUG-16, BUG-17, BUG-19, BUG-20
- **P2**: 4 — BUG-4, BUG-21, BUG-22, BUG-23

Highest-leverage fixes:

1. **BUG-9** (W145 carry-forward, P0-CONS, ~10 LOC): remove the
   fast-path early return in `coreConnectBlockChecks`. Restore
   maturity / BIP-68 / sigops / MoneyRange unconditionally; gate
   only the per-input `verifyScript` call on `skipScripts`. Closes
   BUG-12 + BUG-13 by side-effect (since the two-mechanism shadow
   only matters because the fast path exists).
2. **BUG-7** (P0-DATA, ~15 LOC): mirror Core's `LoadChainstate`
   guard at hotbuns startup. Refuse to launch when persisted
   `havePruned=true` but `mergedConfig.prune` is 0 or undefined.
   One-line message pointing at `--reindex` (also missing — BUG-8).
3. **BUG-1** (P0, ~30 LOC): inside `pruneOneBlockFile`, iterate
   `db.iterateBlockIndexEntries()` and clear `HAVE_DATA|HAVE_UNDO`
   on every record whose `dataPos` resolves to the pruned file.
   Closes the "stale `status` bits after prune" trap that affects
   getblock, getblockheader, getchaintips, and any future
   assumeUTXO consumer.
4. **BUG-18** (P0-CDIV, 1-line): change
   `assumeValidHeight: 123613` to `assumeValidHeight: 4842348` on
   testnet4 to match Core's `defaultAssumeValid` block height.
5. **BUG-17 + BUG-19** (P1, 1 line each): override
   `assumeValidHeight` on TESTNET (123613) and SIGNET (293175) to
   close the inherit-from-MAINNET trap.
6. **BUG-12** (P0-CDIV, ~5 LOC): delete the height-comparison
   `assumeValid` derivation at `sync/blocks.ts:2477`; drive both
   `assumeValid` (post-BUG-9 fix this collapses to `skipScripts`)
   and `skipScripts` from the same `shouldSkipScripts(avCtx)` call.
7. **BUG-15** (P1, 1-line): replace the `continue` at
   `sync/headers.ts:407` with `fromPeer?.misbehaving(100,
   "too-little-chainwork"); continue;`.

PRIORITY NEXT cross-impl sweep (from this audit):

- **Fleet-wide W145 assume-valid scope creep**: hotbuns BUG-9 is the
  canonical instance; the cluster has been catalogued in hotbuns +
  haskoin (W145 BUG-3 cache-mutation, separate but related family)
  + nimrod (W143 P0-CONS `--reindex` skips pipeline). One unified
  pattern: "fScriptChecks-misuse-to-skip-non-script-gates" —
  candidate for fleet sweep.
- **Fleet-wide "inherit-via-spread silently leaks default-network
  values"**: BUG-17/18/19 in hotbuns is the canonical instance;
  worth checking the other 9 impls for the same shape on
  `assumeValidHeight`, `nPruneAfterHeight`, `assumeutxo` map, and
  `nMinimumChainWork`.
