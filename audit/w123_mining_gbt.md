# W123 — Mining / GBT parity audit (hotbuns)

**Impl:** hotbuns (TypeScript / Bun)
**Date:** 2026-05-17
**Status:** DISCOVERY — 22 BUGS / 30 gates (10 PRESENT / 7 PARTIAL / 13 MISSING)
**Tests:** `src/__tests__/w123_mining_gbt.test.ts` (xfail/assertion-only)
**No production code changes.**

## Reference

- `bitcoin-core/src/node/miner.cpp` (BlockAssembler, CreateNewBlock,
  TestChunkBlockLimits, addChunks, GetMinimumTime, UpdateTime)
- `bitcoin-core/src/rpc/mining.cpp` (getblocktemplate, getmininginfo,
  submitblock, submitheader, prioritisetransaction,
  getprioritisedtransactions, getnetworkhashps, generatetoaddress,
  generatetodescriptor, generateblock)
- `bitcoin-core/src/policy/feefrac.cpp` (CompareChunks /
  ImprovesFeerateDiagram)
- `bitcoin-core/src/consensus/consensus.h` (`MAX_BLOCK_WEIGHT=4_000_000`,
  `MAX_BLOCK_SIGOPS_COST=80_000`, `MAX_BLOCK_SERIALIZED_SIZE=4_000_000`)
- `bitcoin-core/src/policy/policy.h` (`DEFAULT_BLOCK_RESERVED_WEIGHT=8000`,
  `DEFAULT_COINBASE_OUTPUT_MAX_ADDITIONAL_SIGOPS=400`)
- BIP-22 / BIP-23 / BIP-141 / BIP-152 / BIP-9

## Architecture summary

hotbuns has two parallel mining code paths:

1. **`src/mining/template.ts` `BlockTemplateBuilder.createTemplate()`** —
   the "good" path. Reads parent MTP, respects max_block_weight (with
   `>=`), reserves `BLOCK_RESERVED_WEIGHT=8000`, reserves
   `COINBASE_OUTPUT_MAX_ADDITIONAL_SIGOPS=400`, walks ancestors,
   enforces `isFinalTx`, applies `MAX_CONSECUTIVE_FAILURES=1000` early
   exit, uses `MAX_SEQUENCE_NONFINAL=0xfffffffe` for the coinbase
   `nSequence`, sets `lockTime=height-1`. **Bugs 1–9 fixed in W14/W63.**
2. **`src/rpc/server.ts` `getBlockTemplate()`** AND
   **`generateSingleBlock()`** — the "bad" path. Re-implements
   selection/coinbase from scratch and **does not call**
   `BlockTemplateBuilder`. **All Bug 1–9 lessons regressed here.**

This is a textbook **dead-helper at the call-site** pattern (universal
in this audit campaign — 33+ wave streak). The corrected mining engine
exists and is fully unit-tested (62 tests pass in
`template.test.ts`), but the production RPC entrypoints (the ONLY way a
miner actually reaches it) duplicate the logic with the original bugs
present.

## Bug inventory (22 distinct findings)

### P0-CDIV — block invalid / consensus-divergent

- **BUG-1** (gate G1) — `getBlockTemplate` RPC does **not** enforce
  per-tx `isFinalTx(tx, height, MTP)`. Mempool entries that are
  time-locked beyond the new block's MTP are happily emitted in the GBT
  `transactions` array. A naive miner that assembles the block as-is
  would produce a `bad-txns-nonfinal` block that every node on the
  network rejects.
  - `src/rpc/server.ts:5074-5113` iterates `mempool.getAllTxids()` with
    zero finality check. Core: `BlockAssembler::TestChunkTransactions()`
    in `node/miner.cpp:253-258`.

- **BUG-2** (gate G2) — `getBlockTemplate` does **not** enforce
  `MAX_BLOCK_WEIGHT`. The RPC only checks `MAX_BLOCK_SIGOPS_COST`. A
  mempool full of fat transactions would emit a template > 4_000_000
  WU. The dead-helper `BlockTemplateBuilder` does enforce this with
  `nBlockWeight + entry.weight >= maxBlockWeight`.
  - `src/rpc/server.ts:5074-5113`. Core: `TestChunkBlockLimits()` in
    `node/miner.cpp:241-242`.

- **BUG-3** (gate G3) — `getBlockTemplate` does **not** apply
  `BLOCK_RESERVED_WEIGHT=8000` to its reported `totalWeight`, and never
  initialises a sigops budget to
  `COINBASE_OUTPUT_MAX_ADDITIONAL_SIGOPS=400`. Both budgets start at 0
  in `server.ts:5069-5070`. A pool that trusts the reported `weight`
  field will build blocks `8000` WU lighter than `MAX_BLOCK_WEIGHT` is
  intended to allow them — and may overrun the per-block sigops limit
  by up to `~400`. Mirrors the W14 Bug 1+2+8 fixes that landed in
  template.ts; never re-landed in server.ts.
  - `src/rpc/server.ts:5069-5070,5072` vs.
    `src/mining/template.ts:349-352`.

- **BUG-4** (gate G3) — `getBlockTemplate` sigops gate uses `>` instead
  of `>=`. Core: `nBlockSigOpsCost + chunk_sigops_cost >=
  MAX_BLOCK_SIGOPS_COST` rejects equality (`node/miner.cpp:244`).
  hotbuns RPC accepts exact-equality, so a transaction that pushes
  total sigops to exactly 80000 is admitted; Core would reject it.
  - `src/rpc/server.ts:5081` (`> MAX_BLOCK_SIGOPS_COST`) vs.
    `src/mining/template.ts:408` (`>= maxSigOps`).

- **BUG-5** (gate G7) — `generateSingleBlock` (`generatetoaddress` /
  `generatetodescriptor` / `generateblock`) builds the coinbase with
  `sequence: 0xffffffff` (SEQUENCE_FINAL). Core uses
  `MAX_SEQUENCE_NONFINAL = 0xfffffffe` so the coinbase's
  `nLockTime = height - 1` is actually enforced. With SEQUENCE_FINAL,
  `IsFinalTx` ignores `nLockTime` entirely — the BIP34-style height
  timelock has no consensus effect. Same root-cause as W14 Bug 6.
  - `src/rpc/server.ts:5637,5677` vs. `node/miner.cpp:171`.

- **BUG-6** (gate G8) — `generateSingleBlock` builds the coinbase with
  `lockTime: 0` instead of `height - 1`. Core: `coinbaseTx.nLockTime =
  static_cast<uint32_t>(nHeight - 1)` (`node/miner.cpp:196`). Same as
  W14 Bug 5.
  - `src/rpc/server.ts:5647,5691`.

- **BUG-7** (gate G10) — `generateSingleBlock`'s `target` is unconditionally
  `this.params.powLimit` (regtest min-difficulty); it does **not** call
  `getNextTarget(parentEntry, ...)` for the new block. On testnet4 or
  mainnet, a `generatetoaddress` call would mine a block at genesis
  difficulty and every other node on the network would reject it for
  `high-hash`. This is the same P0-5 finding that motivated the
  `getblocktemplate` fix in `CORE-PARITY-AUDIT/hotbuns-P0-FOUND.md`,
  carried forward unfixed in `generateSingleBlock`.
  - `src/rpc/server.ts:5554`.

### P0-RPC — wrong RPC output shape / wrong semantics

- **BUG-8** (gate G11) — `getmininginfo`'s `next` object reports the
  **TIP**'s bits / difficulty / target, not the *next* block's. Core
  uses `NextEmptyBlockIndex(tip, ...)` to construct a synthetic next-
  block CBlockIndex and then calls
  `GetNextWorkRequired(&next_index, ...)` (`rpc/mining.cpp:480-487`).
  A pool that reads `next.bits` to decide what to mine to will mine
  the wrong target every retarget-boundary block.
  - `src/rpc/server.ts:7494-7499` (uses `tipBitsHex`/`tipTargetHex`
    verbatim).

- **BUG-9** (gate G11) — `getmininginfo.networkhashps` is hardcoded to
  `0`. Core delegates to `getnetworkhashps().HandleRequest(request)`
  (`rpc/mining.cpp:472`). hotbuns has the helper (`getNetworkHashPS()`
  at `server.ts:8888`) but does not call it from `getMiningInfo`.
  - `src/rpc/server.ts:7491`.

- **BUG-10** (gate G11) — `getmininginfo` does not report
  `currentblockweight` or `currentblocktx`. Core surfaces the weight
  and tx count of the last-assembled block via
  `BlockAssembler::m_last_block_weight` /
  `m_last_block_num_txs` (`rpc/mining.cpp:467-468`). hotbuns has no
  global tracking equivalent; the field is absent.
  - `src/rpc/server.ts:7485-7501`.

- **BUG-11** (gate G15) — `getblocktemplate` does **not** support
  `mode: "proposal"` (BIP-23). The RPC throws
  `"Only 'template' mode is supported"`. Mining pools that use proposal
  mode to sanity-check a block before submitting cannot use hotbuns.
  - `src/rpc/server.ts:5048-5049`. Core: `rpc/mining.cpp:730-752`.

- **BUG-12** (gate G16) — `submitheader` RPC is **MISSING**. Core
  registers it under the mining category (`rpc/mining.cpp:1157`).
  Light-client wallets and pools use submitheader to push a header
  without the full block.
  - No reference in `src/rpc/server.ts`.

- **BUG-13** (gate G17) — `prioritisetransaction` RPC is **MISSING**.
  Core ships it under the mining category (`rpc/mining.cpp:1153`). The
  mempool has no per-entry `feeDelta` modifier (`mempool/persist.ts:301`
  even says "hotbuns lacks a tx-level feeDelta prioritisation modifier,
  so 0n").
  - Cross-wave note: this is the same finding as **W120 BUG-6** (RBF /
    mempool audit) — universal pattern 6 of 10 impls. Now confirmed
    P0-shape from the mining angle as well.

- **BUG-14** (gate G17) — `getprioritisedtransactions` RPC is
  **MISSING** (counterpart to BUG-13). Core: `rpc/mining.cpp:1154`.

### P1-CDIV — consensus-relevant divergence (not block-invalid alone)

- **BUG-15** (gate G6) — neither `getBlockTemplate` nor
  `generateSingleBlock` honors BIP-94 timewarp clamp at the boundary
  block. Core: `GetMinimumTime` returns `max(MTP+1, parent_time -
  MAX_TIMEWARP)` when `height % DifficultyAdjustmentInterval == 0`
  (`node/miner.cpp:36-46`). hotbuns reports `mintime = MTP(parent) + 1`
  unconditionally. On testnet4 (the only chain where
  `enforce_BIP94=true` actually matters), a block at height 2016/4032/…
  could be assembled with a timestamp the chain rejects. BIP-94
  enforcement is present in `sync/headers.ts:562-567` and
  `validation/errors.ts:265-268` — so headers are rejected at validate
  time, but the *miner* is told a `mintime` that the validator will
  refuse.
  - `src/rpc/server.ts:5145-5147` and `src/mining/template.ts:265-267`.

- **BUG-16** (gate G18) — `getBlockTemplate` does **not** check the
  `connman.GetNodeCount(...)==0` or `miner.isInitialBlockDownload()`
  guards. Core throws `RPC_CLIENT_NOT_CONNECTED` /
  `RPC_CLIENT_IN_INITIAL_DOWNLOAD` for non-test chains
  (`rpc/mining.cpp:766-775`). hotbuns will happily emit a stale-tip
  template during IBD or with zero peers, producing a fork.
  - No reference in `src/rpc/server.ts:5060-5226`.

- **BUG-17** (gate G19) — `getBlockTemplate` does **not** implement
  BIP-22 longpoll. `longpollid` is emitted, but the parameter is
  ignored on subsequent calls; there is no `waitTipChanged` /
  `GetTransactionsUpdated` wait loop. Pools that use longpoll for
  better template freshness will fall back to busy-polling.
  - `src/rpc/server.ts:5215` only emits the id; Core:
    `rpc/mining.cpp:783-845`.

- **BUG-18** (gate G20) — `getBlockTemplate` does **not** implement the
  template caching that Core uses to avoid recreating a `BlockTemplate`
  on every call (`rpc/mining.cpp:860-884`: `static CBlockIndex*
  pindexPrev; if (!pindexPrev || ...) recreate`). hotbuns rebuilds
  from scratch every call, walking the entire mempool. For a real
  pool issuing GBT every 5s, this is wasteful but not divergent.

### P1-RPC — semantic mismatches in RPC output

- **BUG-19** (gate G12) — `generateSingleBlock` uses
  `Math.floor(Date.now() / 1000)` for the header timestamp with **no**
  enforcement of `>= MTP+1` (the rule it enforces correctly in
  `getblocktemplate.mintime` and `BlockTemplateBuilder.createTemplate`).
  On a regtest node where the wall clock is intentionally lagged, a
  generated block would have `time-too-old` and be rejected.
  - `src/rpc/server.ts:5565` — no `max(now, MTP+1)` analog. Core:
    `UpdateTime` in `node/miner.cpp:49-65`.

- **BUG-20** (gate G14) — `generateSingleBlock` does **not** include a
  dummy extranonce (`OP_0`) when `height <= 16`. Core: `if (height <=
  16, …, scriptSig << OP_0)` (`node/miner.cpp:188-193`). A regtest
  block at height ≤ 16 with the bare BIP34 push will fail
  `bad-cb-length` (`min coinbase scriptSig is 2 bytes`).
  - `src/rpc/server.ts:5624-5648,5654-5693`. Same root in
    `BlockTemplateBuilder.buildCoinbase()` at
    `src/mining/template.ts:481-485`.

### P1-DEAD — well-engineered helper that is never called

- **BUG-21** (gate G21) — `BlockTemplateBuilder` (685 LOC,
  `src/mining/template.ts`) is a **dead helper at the call-site**: it
  is exported but **never imported by `src/rpc/server.ts`**. The two
  RPC entrypoints (`getBlockTemplate`, `generateSingleBlock`)
  re-implement the selection / coinbase / commitment logic by hand and
  bring the W14 / W63 bugs back. Recommended fix: route both RPCs
  through `BlockTemplateBuilder.createTemplate()`. This single change
  closes BUG-1, BUG-2, BUG-3, BUG-4, BUG-5, BUG-6, BUG-7, BUG-19, and
  BUG-20 at once.
  - 33rd-consecutive-wave dead-helper pattern (per overnight memory).
  - The helper has 62 passing unit tests; the production code path has
    zero coverage of the W14 fixes.

### P2 — operator surface

- **BUG-22** (gate G13) — `getmininginfo.blockmintxfee` is hardcoded to
  `0.00001000` BTC/kvB. Core derives this from `-blockmintxfee`
  (`assembler_options.blockMinFeeRate.GetFeePerK()` in
  `rpc/mining.cpp:474-476`). hotbuns has no `-blockmintxfee` parsing.
  - `src/rpc/server.ts:7490`.

## Gate-by-gate matrix

| # | Gate | Status | Bugs | Note |
|---|------|--------|------|------|
| G1 | tx finality enforcement in template selection | PARTIAL | BUG-1 | helper enforces; RPC ignores |
| G2 | `MAX_BLOCK_WEIGHT` enforcement (`>=`) | PARTIAL | BUG-2 | helper enforces; RPC ignores |
| G3 | reserved-weight + reserved-coinbase-sigops budgeting | PARTIAL | BUG-3, BUG-4 | helper PRESENT; RPC zero |
| G4 | dependency / ancestor ordering | PARTIAL | — | RPC builds `depends` array but iteration order is mempool-map order, not topologically sorted; cluster mempool feeds linearizer (PRESENT in helper) but never reaches RPC |
| G5 | `MAX_CONSECUTIVE_FAILURES` early-exit (1000) | PARTIAL | — | PRESENT in helper; RPC has no early-exit |
| G6 | `mintime` includes BIP-94 timewarp clamp | MISSING | BUG-15 | universal across both paths |
| G7 | coinbase `nSequence = MAX_SEQUENCE_NONFINAL` | PARTIAL | BUG-5 | helper correct; generateSingleBlock wrong |
| G8 | coinbase `nLockTime = nHeight - 1` | PARTIAL | BUG-6 | helper correct; generateSingleBlock wrong |
| G9 | BIP-141 witness commitment (`OP_RETURN 0x24 0xaa21a9ed ...`) | PRESENT | — | both RPC paths emit it (correctly) |
| G10 | retarget via `GetNextWorkRequired` (next bits) | PARTIAL | BUG-7 | getblocktemplate correct; generateSingleBlock uses powLimit |
| G11 | `getmininginfo` next.bits / networkhashps / current-block fields | MISSING | BUG-8, BUG-9, BUG-10 | tip bits reported as next; networkhashps=0; no current* |
| G12 | `generateSingleBlock` timestamp via `max(now, MTP+1)` | MISSING | BUG-19 | wall-clock only |
| G13 | `blockmintxfee` from `-blockmintxfee` arg | MISSING | BUG-22 | hardcoded 0.00001 |
| G14 | coinbase scriptSig ≥ 2 bytes (`OP_0` dummy when h ≤ 16) | MISSING | BUG-20 | both paths emit a bare BIP34 push |
| G15 | GBT `mode: "proposal"` (BIP-23) | MISSING | BUG-11 | explicitly thrown |
| G16 | `submitheader` RPC | MISSING | BUG-12 | unregistered |
| G17 | `prioritisetransaction` / `getprioritisedtransactions` | MISSING | BUG-13, BUG-14 | mempool has no feeDelta |
| G18 | IBD / connman pre-checks on GBT | MISSING | BUG-16 | template returned during IBD or zero peers |
| G19 | BIP-22 longpoll (`longpollid` honored on subsequent call) | MISSING | BUG-17 | emit-only |
| G20 | template cache (`pindexPrev == tip` reuse) | MISSING | BUG-18 | rebuild every call |
| G21 | `BlockTemplateBuilder` actually called from production RPCs | MISSING | BUG-21 | dead helper, 685 LOC, 62 tests, 0 call sites |
| G22 | `submitblock` BIP-22 string returns (`duplicate`, `inconclusive`, `high-hash`, `time-too-old`) | PRESENT | — | wired with stateless prevalidate in W63 |
| G23 | BIP-141 `default_witness_commitment` emitted whenever segwit active | PRESENT | — | server.ts:5238-5256 |
| G24 | BIP-9 `vbavailable` / `rules` (csv / !segwit / taproot) | PRESENT | — | W108 G4/G19/G20 fixes |
| G25 | `computeNextBlockVersion` via BIP-9 state machine | PRESENT | — | both RPC paths use it |
| G26 | sigops cost stored on mempool entries (Core's `GetTransactionSigOpCost` analog) | PRESENT | — | `mempool.ts:1666-1675` |
| G27 | `BlockAssembler::AddToBlock`-equivalent `nBlockWeight += entry.weight` accounting | PRESENT | — | helper only |
| G28 | cluster-mempool feerate-diagram comparator (`ImprovesFeerateDiagram`) | PRESENT | — | mempool.ts:3695-3873 wired into RBF |
| G29 | BIP-152 compact-block reconstruction (`sendcmpct v2`, `cmpctblock`, `getblocktxn`/`blocktxn`, short-id wtxid SipHash) | PRESENT | — | `p2p/compact_blocks.ts:1041` LOC, fully wired |
| G30 | `getnetworkhashps` window calculation (workDiff / timeDiff) | PRESENT | — | `server.ts:8888-8912` |

PRESENT: 10 (G9, G22, G23, G24, G25, G26, G27, G28, G29, G30)
PARTIAL: 7  (G1, G2, G3, G4, G5, G7, G8, G10)
MISSING: 13 (G6, G11, G12, G13, G14, G15, G16, G17, G18, G19, G20, G21)

## Priority breakdown

- **P0-CDIV** (block-invalid / consensus): 7 — BUG-1, BUG-2, BUG-3,
  BUG-4, BUG-5, BUG-6, BUG-7
- **P0-RPC** (wrong RPC output / missing required RPC): 7 — BUG-8,
  BUG-9, BUG-10, BUG-11, BUG-12, BUG-13, BUG-14
- **P1**: 7 — BUG-15, BUG-16, BUG-17, BUG-18, BUG-19, BUG-20, BUG-21
- **P2**: 1 — BUG-22

## Recommended fix bundle (FIX-WIDE)

A single fix wave should:

1. Route `getBlockTemplate` and `generateSingleBlock` through
   `BlockTemplateBuilder.createTemplate()` (closes BUG-1, BUG-2, BUG-3,
   BUG-4, BUG-5, BUG-6, BUG-7, BUG-19, BUG-20, BUG-21 — **10 bugs
   killed by one wiring change**).
2. Track `m_last_block_weight` / `m_last_block_num_txs` (one
   `BlockAssembler`-equivalent state instance) and surface via
   `getmininginfo` (closes BUG-10).
3. Call `getNetworkHashPS()` from `getMiningInfo`; compute
   next-bits via `getNextTarget(tip, ...)` (closes BUG-8, BUG-9).
4. Add `prioritisetransaction` + `getprioritisedtransactions` RPCs
   backed by a per-entry `feeDelta: bigint` modifier in `MempoolEntry`
   (closes BUG-13, BUG-14; cleans up the W120 BUG-6 carry-forward).
5. Add `submitheader` RPC (closes BUG-12).
6. Add `mode: "proposal"` to `getblocktemplate` using existing
   `validateBlock` + `chainState.connectBlock(testOnly)` (closes
   BUG-11).
7. Wire BIP-94 timewarp clamp into `mintime` calculation (closes
   BUG-15).
8. Add IBD / connman guards on `getblocktemplate` (closes BUG-16).
9. Add `-blockmintxfee` parsing and surface in `getmininginfo` (closes
   BUG-22).
10. Add template caching keyed on `pindexPrev` and BIP-22 longpoll
    support (closes BUG-17, BUG-18).

## Cross-wave dependencies

- **W120 BUG-6** (mempool RBF audit) flagged `prioritisetransaction`
  missing — same root as BUG-13/14 here. A single feeDelta wiring fix
  in `MempoolEntry` plus the two RPC registrations closes both.
- **W14/W63** correctness fixes landed in
  `src/mining/template.ts` but never propagated to
  `src/rpc/server.ts`. Dead-helper-at-call-site pattern (33+
  consecutive waves observed in this project).
- **W108 G4/G19/G20** fixed `rules` / `vbavailable` / taproot in the
  RPC path — only the RPC path. The helper got the BIP-9 state machine
  via constructor opts but is never called from the RPC, so the W108
  fix is functionally inert (the RPC has its own correct version of
  it, in parallel).

## Risk profile

- Single hotbuns node in a mining pool would produce **block-invalid
  templates** under load (>4MWU mempool, sigop-heavy txs, time-locked
  txs in mempool, testnet4 BIP-94 boundary block, generate-toaddress
  on testnet4 / mainnet). Recovery cost: every other node on the
  network rejects and the pool earns 0 BTC for that template.
- Sub-pool with mixed clients on hotbuns as backup would see ~6
  classes of "weirdly invalid" rejections and likely root-cause to
  hotbuns within hours.
- A wallet using hotbuns RPC would see `getmininginfo.next.bits` lag by
  one retarget every 2016 blocks (mainnet) or every period (testnet4,
  more often). Risk depends on what consumers do with it.

## Tests

`src/__tests__/w123_mining_gbt.test.ts` (assertion-only audit tests,
no production code changes):

- 30 gate-checks: structural assertions about what is wired / present
  in current `src/`. Documents the bugs as **explicit assertions on
  current behaviour**, so any subsequent fix that closes a gate will
  predictably *flip the assertion*.

Run:

```bash
cd /home/work/hashhog/hotbuns
bun test src/__tests__/w123_mining_gbt.test.ts
```

## Status

DISCOVERY-only. No production code changes. Fix waves will be tracked
separately per the standard FIX-NN convention.
