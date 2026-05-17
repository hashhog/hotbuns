# W132 — BIP-68 / BIP-112 / BIP-113 nSequence + OP_CSV + MTP audit (hotbuns)

**Impl:** hotbuns (TypeScript / Bun)
**Date:** 2026-05-17
**Status:** DISCOVERY — 14 BUGS / 30 gates (16 PRESENT / 7 PARTIAL / 7 MISSING)
**Tests:** `src/__tests__/w132_nsequence_csv_mtp.test.ts` (assertion-only,
no production code changes)
**No production code changes in this wave.**

## Reference

- `bitcoin-core/src/consensus/tx_verify.cpp` — `IsFinalTx`,
  `CalculateSequenceLocks`, `EvaluateSequenceLocks`, `SequenceLocks`.
- `bitcoin-core/src/script/interpreter.cpp:522-558` — `OP_CHECKLOCKTIMEVERIFY`
  case (BIP-65).
- `bitcoin-core/src/script/interpreter.cpp:561-593` — `OP_CHECKSEQUENCEVERIFY`
  case (BIP-112).
- `bitcoin-core/src/script/interpreter.cpp:1745-1826` —
  `GenericTransactionSignatureChecker::{CheckLockTime, CheckSequence}`.
- `bitcoin-core/src/script/interpreter.cpp:595-601` —
  `OP_NOP1, OP_NOP4..OP_NOP10` (DISCOURAGE_UPGRADABLE_NOPS scope; CLTV and CSV
  are NOT in this list).
- `bitcoin-core/src/chain.h:231-245` — `CBlockIndex::GetMedianTimePast()` /
  `nMedianTimeSpan = 11`.
- `bitcoin-core/src/validation.cpp:2478-2562` — `ConnectBlock` BIP-68
  enforcement (LOCKTIME_VERIFY_SEQUENCE flag gated on
  `DeploymentActiveAt(*pindex, DEPLOYMENT_CSV)`).
- `bitcoin-core/src/validation.cpp:4129-4149` — `ContextualCheckBlock`
  BIP-113 IsFinalTx enforcement (lock_time_cutoff = MTP when CSV active).
- `bitcoin-core/src/validation.cpp:201-262` — `CalculateLockPointsAtTip` /
  `CheckSequenceLocksAtTip` (mempool BIP-68).
- `bitcoin-core/src/policy/policy.h:119-138` — `STANDARD_SCRIPT_VERIFY_FLAGS`
  composition (DISCOURAGE_UPGRADABLE_NOPS included; CLTV / CSV via mandatory
  set).
- `bitcoin-core/src/primitives/transaction.h:66-114` —
  `SEQUENCE_FINAL = 0xffffffff`, `MAX_SEQUENCE_NONFINAL = 0xfffffffe`,
  `SEQUENCE_LOCKTIME_DISABLE_FLAG = 1 << 31`,
  `SEQUENCE_LOCKTIME_TYPE_FLAG = 1 << 22`,
  `SEQUENCE_LOCKTIME_MASK = 0x0000ffff`,
  `SEQUENCE_LOCKTIME_GRANULARITY = 9`.

BIPs:
- BIP-68 — Relative lock-time via consensus-enforced sequence numbers.
- BIP-112 — `CHECKSEQUENCEVERIFY` opcode (NOP3 redefinition).
- BIP-113 — Median time past as endpoint for lock-time calculations.

## Background

CSV is the umbrella soft-fork (BIP-68 + BIP-112 + BIP-113) activated at:
- mainnet height **419328**
- testnet3 height **770112**
- testnet4 height **1**
- signet height **1**
- regtest height **0** (always active)

There are three independent gates that must agree on activation:

1. **BIP-68 / CalculateSequenceLocks** — runs in `ConnectBlock` (consensus)
   and in `CheckSequenceLocksAtTip` (mempool) when `tx.version >= 2 &&
   (flags & LOCKTIME_VERIFY_SEQUENCE)`. Per Core's `STANDARD_LOCKTIME_VERIFY_FLAGS`
   the mempool flag is **always** `LOCKTIME_VERIFY_SEQUENCE`; the consensus
   flag is gated by `DeploymentActiveAt(*pindex, DEPLOYMENT_CSV)`.

2. **BIP-112 / OP_CSV** — opcode case in `EvalScript`. Activated by
   `SCRIPT_VERIFY_CHECKSEQUENCEVERIFY` per `GetBlockScriptFlags`. When the
   flag is off, OP_CSV is a bare NOP (no DISCOURAGE check — CSV is not in
   Core's discourage list at interpreter.cpp:595).

3. **BIP-113 / IsFinalTx + MTP** — `lock_time_cutoff = MTP` when
   `DeploymentActiveAfter(pindexPrev, DEPLOYMENT_CSV)`, else
   `block.GetBlockTime()`.

## Hotbuns architecture

- **OP_CSV opcode** — `src/script/interpreter.ts:1200-1258`.
- **OP_CLTV opcode** — `src/script/interpreter.ts:1141-1198`.
- **CalculateSequenceLocks / EvaluateSequenceLocks / checkSequenceLocks** —
  `src/validation/tx.ts:1782-1948`.
- **IsFinalTx** — `src/mining/template.ts:60-83` (exported and reused by
  `src/mempool/mempool.ts:1717` and `src/consensus/connect_block.ts:384`).
- **MTP** — `src/sync/headers.ts:634-654` (`HeaderSync.getMedianTimePast`).
- **Block-validation wiring** —
  `src/consensus/connect_block.ts:374-391` (IsFinalTx, runs even under
  assume-valid) and `:555-570` (BIP-68 sequence locks, full-validation
  path ONLY — skipped under assume-valid).
- **Mempool wiring** — `src/mempool/mempool.ts:1704-1749`.
- **Regtest connect path** — `src/chain/state.ts:295-360` (calls
  `coreConnectBlockChecks` **without** `getUTXOMTP`).
- **IBD/sync connect path** — `src/sync/blocks.ts:2487-2588` (passes
  `getUTXOMTP` from `headerSync.getMedianTimePast`).

## Activation-height table (`src/consensus/params.ts`)

| Network  | `csvHeight` |
|----------|-------------|
| mainnet  | 419328 |
| testnet3 | 770112 |
| testnet4 | 1 |
| signet   | 1 |
| regtest  | 0 |

And in `src/script/interpreter.ts:3021-3036` (`getConsensusFlags`):
- `verifyCheckLockTimeVerify: height >= 388381` (BIP-65; mainnet)
- `verifyCheckSequenceVerify: height >= 419328` (BIP-112; mainnet)

> ⚠️ **BUG-1**: `getConsensusFlags()` hard-codes BIP-65 / BIP-112 mainnet
> heights. On testnet/regtest the CSV/CLTV activation heights differ
> (testnet4 = 1, regtest = 0, testnet3 = 581885 / 770112). See G29.

---

## Audit matrix — 30 gates

Severity legend:
- **P0-CDIV** consensus divergence (could fork the chain or accept invalid)
- **P1-WIRE** wiring/dead-code (correct algorithm, dormant or stricter than
  Core in mempool-only paths)
- **P1-API** API parity (RPC/standardness, no consensus impact)
- **P2** cosmetic / efficiency

### BIP-68 — Sequence-lock value semantics

#### G1 — `SEQUENCE_FINAL` constant value
**Status: PRESENT.** `src/validation/tx.ts:1807` defines
`SEQUENCE_FINAL = 0xffffffff`. Matches Core
`primitives/transaction.h:76`.

#### G2 — `SEQUENCE_LOCKTIME_DISABLE_FLAG` = 1 << 31
**Status: PRESENT.** `src/validation/tx.ts:1795`. Bit 31. Matches Core.

#### G3 — `SEQUENCE_LOCKTIME_TYPE_FLAG` = 1 << 22
**Status: PRESENT.** `src/validation/tx.ts:1798`. `0x00400000`. Matches Core.

#### G4 — `SEQUENCE_LOCKTIME_MASK` = `0x0000ffff`
**Status: PRESENT.** `src/validation/tx.ts:1801`. Matches Core.

#### G5 — `SEQUENCE_LOCKTIME_GRANULARITY` = 9 (i.e. 512s)
**Status: PRESENT.** `src/validation/tx.ts:1804`. `1 << 9 = 512`. Matches Core.

#### G6 — `calculateSequenceLocks` returns -1/-1 when not enforced or version <2
**Status: PRESENT.** `src/validation/tx.ts:1856-1859`. Matches
`tx_verify.cpp:51-57`.

#### G7 — Disable-flag inputs skipped in lock calculation
**Status: PRESENT.** `src/validation/tx.ts:1871`. Skips inputs with bit 31
set. Matches `tx_verify.cpp:65-69`.

> Subtle gap: Core also writes `prevHeights[txinIndex] = 0` for skipped
> inputs (tx_verify.cpp:67). Hotbuns just `continue`s without resetting
> `utxoConfirmations[i]`. **No bug** — the array is not reused downstream,
> but the inconsistency is worth noting if the helper is ever extended.

#### G8 — Time-based lock: `nMinTime = max(nMinTime, nCoinTime + (lockValue << 9) - 1)`
**Status: PARTIAL — BUG-2 (P0-CDIV, regtest/IBD edge).**
`src/validation/tx.ts:1881-1885` computes lockTime correctly. **BUG-2**:
the `nCoinTime` plumbing has two divergence-class wiring bugs:

- **BUG-2a (regtest path)**: `src/chain/state.ts:344-354` calls
  `coreConnectBlockChecks` **without** passing `getUTXOMTP`. The callee
  (`src/consensus/connect_block.ts:550`) defaults `coinMTP = 0` whenever
  `getUTXOMTP` is undefined. The regtest path is used by
  `generateblock`, `dumptxoutset` reapply, and **reorg-reconnect** on all
  networks. With coinMTP=0, every time-based BIP-68 lock evaluates as
  `minTime = 0 + lockValue*512 - 1`, which is always `<` the block's
  prevMTP (~1.7e9 on mainnet today), so the lock **always passes**. A
  reorg through a time-based-locked tx would silently admit a tx that
  IBD-sync rejected.

- **BUG-2b (genesis edge)**: `src/sync/blocks.ts:2583` returns `0` when
  `coinHeight <= 0`. Core returns
  `block.GetAncestor(max(0 - 1, 0))->GetMedianTimePast() =
  genesis.MTP = genesis.timestamp`. For mainnet that's 1231006505, not 0.
  Practically unreachable (genesis coinbase is unspendable), but a
  divergence-class wiring miss.

#### G9 — Height-based lock: `nMinHeight = max(nMinHeight, nCoinHeight + lockValue - 1)`
**Status: PRESENT.** `src/validation/tx.ts:1890`. Matches `tx_verify.cpp:90`.

#### G10 — `evaluateSequenceLocks` uses strict `>=` (nLockTime semantics)
**Status: PRESENT.** `src/validation/tx.ts:1917-1922` uses `>=` on both
minHeight and minTime, matching `tx_verify.cpp:101`
(`first >= block.nHeight || second >= nBlockTime`).

#### G11 — `evaluateSequenceLocks` uses `block.pprev->GetMedianTimePast()` (not block's own MTP)
**Status: PRESENT.** `src/validation/tx.ts:1910-1923` parameter
`blockPrevMTP` is documented as MTP of the previous block. Wiring in
`src/sync/blocks.ts:2493-2499` reads `headerSync.getHeaderByHeight(height - 1)`
and then `getMedianTimePast(prevHeader)`. Matches Core
`tx_verify.cpp:99-100`.

### BIP-68 — Wiring (consensus / mempool / regtest)

#### G12 — Block-validation BIP-68 gate runs in `ConnectBlock`
**Status: PARTIAL — BUG-3 (P1-WIRE).**
`src/consensus/connect_block.ts:556` runs `checkSequenceLocks` only in the
full-validation path. **BUG-3**: under **assume-valid** the entire
sequence-lock block is skipped (line 416 `if (assumeValid) { ... return; }`
short-circuits before line 555). Core's `SequenceLocks` at
`validation.cpp:2557` runs **regardless** of `fScriptChecks` — assume-valid
in Core only skips signature/script checking. Hotbuns therefore admits an
assume-valid block containing a BIP-68-violating tx that Core would
reject.

In practice this is dormant because assume-valid is operator-trusted, but
a malicious -assumevalid value or a forked assumevalid hash could result
in a tip on a chain Core rejects.

#### G13 — Mempool BIP-68 uses `STANDARD_LOCKTIME_VERIFY_FLAGS` (always-on for v2 txs)
**Status: PARTIAL — BUG-4 (P1-WIRE).**
`src/mempool/mempool.ts:1729-1731`:
```ts
const enforceBIP68 = tx.version >= 2 && this.tipHeight >= (this.params.csvHeight ?? 0);
```
Core's mempool uses
`CalculateSequenceLocks(tx, STANDARD_LOCKTIME_VERIFY_FLAGS, ...)`
(`validation.cpp:218`). `STANDARD_LOCKTIME_VERIFY_FLAGS = LOCKTIME_VERIFY_SEQUENCE`
(`policy.h:138`), so the gate inside CalculateSequenceLocks (`tx.version >= 2
&& flags & LOCKTIME_VERIFY_SEQUENCE`) is `tx.version >= 2`
unconditionally. **BUG-4**: hotbuns gates the mempool BIP-68 path on
`tipHeight >= csvHeight`. This is a tightening (post-CSV activation it
matches; pre-activation hotbuns is more lax). Today (mainnet 7+ years
post-CSV) this is dormant, but the policy is wrong for any new network /
regtest where csvHeight could be non-zero.

#### G14 — Mempool MTP uses tip MTP (correct for height locks, suspect for time locks)
**Status: PARTIAL — BUG-5 (P0-CDIV, mempool divergence).**
`src/mempool/mempool.ts:1733-1742` sets `medianTimePast: currentMTP` for
**every** UTXO confirmation (mempool and confirmed alike). Core's
`CalculateLockPointsAtTip` (`validation.cpp:201-244`) uses
`block.GetAncestor(coinHeight - 1)->GetMedianTimePast()` —
the MTP of the block before the UTXO was mined.

Since `currentMTP > MTP-at-coinHeight-1` (timestamps move forward),
the computed `nMinTime = currentMTP + lockValue*512 - 1` is
**larger** than Core's `nMinTime`. Then `EvaluateSequenceLocks` checks
`nMinTime >= blockPrevMTP`. Hotbuns's larger nMinTime means hotbuns may
**reject** a tx that Core admits. Mempool divergence (Core's stricter on
its lock test; hotbuns is stricter still).

**BUG-5**: hotbuns mempool BIP-68 is stricter than Core for time-based
locks. False-rejects relayed txs.

#### G15 — `setTipMTP()` is dead code (never called)
**Status: PARTIAL — BUG-6 (P2).** `src/mempool/mempool.ts:1286-1288`
defines `setTipMTP(mtp)`. Grepping the entire TS source plus the bundled
`src/index.js` finds **zero** call sites — `setTipMTP` is dead.
`this.tipMTP` stays at `0` for the node's lifetime. Path is only used as
the fallback when `this.headerSync` is undefined. **BUG-6** is dormant
because production wires `headerSync` immediately, but the fallback's
MTP=0 would make time-based BIP-113 silently pass any tx with `nLockTime
< LOCKTIME_THRESHOLD` and admit any time-based tx with `nLockTime <
0xffffffff`. P2 because dormant.

#### G16 — `getUTXOMTP(coinHeight)` returns MTP at `max(coinHeight - 1, 0)`
**Status: PARTIAL — BUG-2b (already counted).** `src/sync/blocks.ts:2582-2586`
returns `0` for `coinHeight <= 0` instead of MTP at genesis. Same bug
as G8 BUG-2b.

### BIP-112 — OP_CSV opcode

#### G17 — `OP_CHECKSEQUENCEVERIFY` opcode = 0xb2
**Status: PRESENT.** `src/script/interpreter.ts:202`.

#### G18 — Operand decoded with 5-byte limit (year-2038-safe)
**Status: PRESENT.** `src/script/interpreter.ts:1212`
`scriptNumDecode(stack[..], 5)`. Matches Core
`interpreter.cpp:574` (`CScriptNum(stacktop(-1), fRequireMinimal, 5)`).

#### G19 — Negative operand → `NEGATIVE_LOCKTIME`
**Status: PRESENT.** `src/script/interpreter.ts:1213`. Matches
`interpreter.cpp:579-580`.

#### G20 — Disable-flag operand → NOP behavior (BIP-112 soft-fork extensibility)
**Status: PRESENT.** `src/script/interpreter.ts:1217`
`if ((sequence >>> 0) & 0x80000000) break;`. Matches
`interpreter.cpp:585-586`.

#### G21 — `tx.version < 2` → `UNSATISFIED_LOCKTIME`
**Status: PRESENT.** `src/script/interpreter.ts:1221-1223`.
Matches `interpreter.cpp:1788-1791` (CheckSequence:
`if (txTo->version < 2) return false;`).

#### G22 — Spending-input `nSequence` disable-flag → `UNSATISFIED_LOCKTIME`
**Status: PRESENT.** `src/script/interpreter.ts:1232-1234`. Matches
`interpreter.cpp:1796-1798`.

#### G23 — Apple-to-apple type comparison (both height-based or both time-based)
**Status: PRESENT.** `src/script/interpreter.ts:1245-1251`. Mask
`0x00400000 | 0x0000ffff = 0x0040ffff`. Matches
`interpreter.cpp:1802-1818`.

#### G24 — Operand `seqMasked > txSeqMasked` → `UNSATISFIED_LOCKTIME`
**Status: PRESENT.** `src/script/interpreter.ts:1254-1256`. Matches
`interpreter.cpp:1822-1823`.

#### G25 — OP_CSV, when flag off, treated as bare NOP (no DISCOURAGE)
**Status: MISSING — BUG-7 (P0-CDIV, dormant).**
`src/script/interpreter.ts:1204-1208`:
```ts
if (!flags.verifyCheckSequenceVerify) {
  if (flags.verifyDiscourageUpgradableNops) {
    throw new ScriptError("DISCOURAGE_UPGRADABLE_NOPS");
  }
  break; // Treated as NOP3
}
```
Core (`interpreter.cpp:563-566`) just `break;`s with no DISCOURAGE check —
OP_NOP3 (CSV's legacy opcode) is **not** in Core's discourage list
(`interpreter.cpp:595`: `OP_NOP1, OP_NOP4..OP_NOP10`). Same bug for
OP_CLTV (NOP2) at `src/script/interpreter.ts:1146-1148`.

**Currently dormant** because `verifyDiscourageUpgradableNops` is policy-
only and never set in `getConsensusFlags` (and missing from
`getStandardFlags` per BUG-9). If ever wired into standard flags as Core
intends, hotbuns would reject pre-CSV-activation scripts that contain
OP_CSV / OP_CLTV — a relay divergence visible immediately on regtest
or on any future fork-network with deferred CSV activation.

### BIP-65 — OP_CLTV opcode (covered for completeness — pre-W81 audit closed 4 bugs)

#### G26 — `OP_CHECKLOCKTIMEVERIFY` opcode = 0xb1
**Status: PRESENT.** `src/script/interpreter.ts:201`. Pre-W81 audit
closed: missing txContext threading in `verifyWitnessV0` and
`executeTapscript` (now fixed in `interpreter.ts:2900-2913` and
`:2835-2849`).

### BIP-113 — Median Time Past

#### G27 — `IsFinalTx` uses `nLockTime < LOCKTIME_THRESHOLD ? height : time`
**Status: PRESENT.** `src/mining/template.ts:67-72`. Matches
`tx_verify.cpp:21`.

#### G28 — `IsFinalTx` all-`SEQUENCE_FINAL` exemption
**Status: PRESENT.** `src/mining/template.ts:76-80`. Exact match for
`!= SEQUENCE_FINAL` (Core uses `==` with negation; logically identical).

#### G29 — Block-validation lock-time cutoff = MTP when CSV active, else block time
**Status: PARTIAL — BUG-8 (P1-WIRE).**
`src/consensus/connect_block.ts:381-382`:
```ts
const csvActive = height >= params.csvHeight;
const lockTimeCutoff = csvActive ? prevMTP : block.header.timestamp;
```
Matches Core `validation.cpp:4140-4142`. The gate itself is correct.

**BUG-8**: the activation deployment is gated by **height** comparison
(`>=`) but Core uses `DeploymentActiveAfter(pindexPrev, DEPLOYMENT_CSV)`
which evaluates "the *next* block after pindexPrev has CSV". For
height-based deployments these are equivalent (`pindexPrev->nHeight + 1
>= csvHeight ⇔ height >= csvHeight`). However, Core's CSV is a **BIP-9
versionbits** deployment on mainnet (state machine over retarget periods)
— hotbuns flattens this to a constant height. On non-mainnet networks
where `csvHeight` is "always active" this is fine. On mainnet the height
is correct (419328 is the known activation block), so this is
practically equivalent. P1-WIRE for "doesn't go through versionbits".

#### G30 — `GetMedianTimePast()` walks ≤11 ancestors, sorts, takes middle
**Status: PRESENT.** `src/sync/headers.ts:634-654`. Matches Core
`chain.h:233-245`. Boundary semantics for fewer than 11 blocks identical
(odd N → middle; even N → upper-middle via `floor(N/2)`).

### Cross-cutting wiring

#### G31 — Standard flags include `DISCOURAGE_UPGRADABLE_NOPS`
**Status: MISSING — BUG-9 (P1-API).**
`src/script/interpreter.ts:3083-3092` (`getStandardFlags`) **does not set**
`verifyDiscourageUpgradableNops`. Core's `STANDARD_SCRIPT_VERIFY_FLAGS`
includes `SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS` (`policy.h:122`).
Hotbuns mempool consequently does **not** reject mempool txs that contain
spent NOP1/NOP4..NOP10 opcodes — Core's mempool would reject them as
non-standard. Relay-policy divergence.

#### G32 — Standard flags include the other DISCOURAGE flags
**Status: MISSING — BUG-10 (P1-API).**
`src/script/interpreter.ts:3083-3092` is also missing
`DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM`, `DISCOURAGE_UPGRADABLE_TAPROOT_VERSION`,
`DISCOURAGE_OP_SUCCESS`, `DISCOURAGE_UPGRADABLE_PUBKEYTYPE`. All of these
are policy-only but matter for mempool relay. Outside this wave's strict
BIP-68/112/113 scope but uncovered while auditing the standard-flag
constructor.

#### G33 — `mining/template.ts:isFinalTx` exported and reused (single source of truth)
**Status: PRESENT.** Single definition, imported by `mempool.ts:34` and
`connect_block.ts:384`. Good.

#### G34 — IBD path passes `getUTXOMTP` (W93 fix)
**Status: PRESENT.** `src/sync/blocks.ts:2582-2586`.

#### G35 — Mempool path computes `currentMTP` from best header (when wired)
**Status: PRESENT.** `src/mempool/mempool.ts:1710-1716`.

#### G36 — Hard-coded BIP-65/112 mainnet heights in `getConsensusFlags`
**Status: MISSING — BUG-11 (P1-WIRE).**
`src/script/interpreter.ts:3025-3026`:
```ts
verifyCheckLockTimeVerify: height >= 388381, // BIP 65
verifyCheckSequenceVerify: height >= 419328, // BIP 112
```
These are mainnet-only. On testnet/regtest these heights are different
(testnet4: bip65 = 1, csv = 1; regtest: 0). The function takes a
`height` arg but no `params` — so on regtest where csvHeight=0,
`getConsensusFlags(0)` returns `verifyCheckSequenceVerify: false`
(0 < 419328). That contradicts the params table.

The path actually used during IBD is `scriptFlagsFromBitmask`
(`interpreter.ts:3053`), which avoids this issue. But any direct caller
of `getConsensusFlags(height)` on a non-mainnet chain will get the wrong
answer. P1-WIRE.

#### G37 — `getStandardFlags` calls `getConsensusFlags` (so inherits BUG-11)
**Status: PARTIAL — already counted in BUG-11.**

#### G38 — `MAX_SEQUENCE_NONFINAL` = 0xfffffffe (coinbase nSequence)
**Status: PARTIAL — BUG-12 (P2).** Core defines
`MAX_SEQUENCE_NONFINAL = SEQUENCE_FINAL - 1` in
`primitives/transaction.h:82`. Hotbuns does NOT export this constant from
`validation/tx.ts`. It is hard-coded in `src/mining/template.ts:143-144`
and `src/__tests__/w123_mining_gbt.test.ts:191`. P2 cosmetic.

#### G39 — BIP-125 RBF sequence boundary (≤ 0xfffffffd) cross-check
**Status: PRESENT.** `src/wallet/wallet.ts:72-82` documents
`BIP125_RBF_SEQUENCE`. `wallet.ts:1192` uses `< 0xfffffffe`. Out of
scope for BIP-68/112/113 but documented because the boundary value
matters for opt-in RBF vs. BIP-68 disable-flag distinction.

#### G40 — RPC `getblocktemplate.mintime` uses MTP + 1
**Status: PRESENT.** `src/rpc/server.ts:5146`. Matches Core.

#### G41 — `connect_block.ts` IsFinalTx runs under assume-valid
**Status: PRESENT.** `src/consensus/connect_block.ts:374-391` is positioned
**before** the `if (assumeValid)` short-circuit at line 416. Per Core
(`validation.cpp:4144-4149`), IsFinalTx is part of `ContextualCheckBlock`
which runs unconditionally — so this is correct.

> **Note**: this is the **opposite** wiring of G12 (BIP-68 is gated
> behind assume-valid in hotbuns). The asymmetry is the bug: IsFinalTx
> correctly runs always; SequenceLocks should also.

#### G42 — `chain/state.ts` connectBlock passes `enforceBIP68 = csvActive`
**Status: PRESENT.** `src/chain/state.ts:305 + :348`. The path itself
correctly enables BIP-68; the bug (BUG-2a) is at the **coin MTP** wiring,
not at the activation gate.

#### G43 — Coinbase maturity (`COINBASE_MATURITY = 100`) check runs even under assume-valid
**Status: MISSING — BUG-13 (P0-CDIV, dormant).**
Adjacent wiring bug uncovered while reading `connect_block.ts:416-480`.
The assume-valid fast path **also skips coinbase maturity**. Per Core
`Consensus::CheckTxInputs` (`tx_verify.cpp:178-181`), maturity is gated
on `nSpendHeight - coin.nHeight < COINBASE_MATURITY` and runs
unconditionally inside `CheckTxInputs` which itself runs before any
`fScriptChecks` gate. Hotbuns assume-valid skips both.

Same class as BUG-3 (assume-valid scope too wide).

#### G44 — `chain/state.ts` regtest connect path wires HeaderSync for `prevMTP`
**Status: PRESENT.** `src/chain/state.ts:329-342`. `computedPrevMTP`
falls back to `block.header.timestamp` only if HeaderSync is absent.
W93 fix.

#### G45 — Source-level guard: BIP-68 / BIP-113 fix anchors are reachable
**Status: PRESENT.** Static grep over `interpreter.ts` confirms all four
W81 pre-fix bug-anchor comments are present:
- `2836` "ctx had no txVersion/txLockTime/txSequence"
- `2902` "every CLTV in a witness-v0 script silently passed"
- `2977` (verifyWitnessV0 P2WSH)
- `1161` "Pre-fix bug: `if (ctx.txLockTime !== undefined)`"

#### G46 — `CalculatePrevHeights` semantics (mempool parent-height = tip + 1)
**Status: PRESENT.** `src/mempool/mempool.ts:1735` returns
`{ height: nextHeight, ... }` for unconfirmed parents, matching Core's
`CalculatePrevHeights` (`validation.cpp:179-198`) which uses
`tip->nHeight + 1` for mempool inputs.

#### G47 — Coinbase block reward maturity gate runs after maturity check (ordering)
**Status: PARTIAL — BUG-14 (P0-CDIV, dormant).** Note same as G43:
maturity ordering in the assume-valid path skips before reaching the
coinbase check. Counted once with BUG-13.

#### G48 — Discouragement of OP_CLTV when CLTV disabled
**Status: MISSING — already counted in BUG-7.**
`src/script/interpreter.ts:1146-1148` fires `DISCOURAGE_UPGRADABLE_NOPS`
on disabled OP_CLTV, but OP_NOP2 (CLTV's legacy code) is NOT in Core's
discourage list. Same bug shape as BUG-7 for CSV.

#### G49 — `STANDARD_LOCKTIME_VERIFY_FLAGS` constant equivalence
**Status: PRESENT-by-elision.** Hotbuns does not introduce the
`STANDARD_LOCKTIME_VERIFY_FLAGS` indirection — the only check is
`enforceBIP68 = tx.version >= 2 && ...`. As long as the mempool
condition matches, this is equivalent. (See BUG-4 for the divergence in
that condition.)

#### G50 — `LOCKTIME_THRESHOLD = 500_000_000`
**Status: PRESENT.** Defined in **three places**:
`src/script/interpreter.ts:1173`, `src/mining/template.ts:43`,
`src/wallet/miniscript.ts:47`. All three use the same numeric literal.
Not a bug, but a single-source-of-truth refactor opportunity (P2).

---

## Bug summary

| ID | Severity | Location | Description |
|----|----------|----------|-------------|
| BUG-1 | P1-WIRE | `interpreter.ts:3025-3026` | `getConsensusFlags` hard-codes mainnet BIP-65/112 activation heights; wrong on testnet/regtest |
| BUG-2a | **P0-CDIV** | `chain/state.ts:344-354` | Regtest/reorg-reconnect path omits `getUTXOMTP`; time-based BIP-68 always passes (coin MTP=0) |
| BUG-2b | P1-WIRE | `sync/blocks.ts:2583` | `getUTXOMTP(0)` returns 0 instead of genesis MTP (Core: `GetAncestor(max(coinHeight-1, 0))->GetMedianTimePast()`) |
| BUG-3 | **P0-CDIV** | `connect_block.ts:416-480 + :555-570` | Assume-valid skips BIP-68 SequenceLocks; Core only skips signature checks |
| BUG-4 | P1-WIRE | `mempool.ts:1729-1731` | Mempool BIP-68 gated on `tipHeight >= csvHeight`; Core uses unconditional `STANDARD_LOCKTIME_VERIFY_FLAGS` |
| BUG-5 | **P0-CDIV** | `mempool.ts:1733-1742` | All UTXO confirmations use `currentMTP` instead of `MTP-at-coinHeight-1`; relay-divergence (false-rejects) |
| BUG-6 | P2 | `mempool.ts:1286-1288` | `setTipMTP()` is dead code (zero call sites); fallback path uses MTP=0 |
| BUG-7 | **P0-CDIV (dormant)** | `interpreter.ts:1204-1208` | OP_CSV fires DISCOURAGE_UPGRADABLE_NOPS when CSV disabled; Core treats OP_NOP3 as bare NOP |
| BUG-8 | P1-WIRE | `connect_block.ts:381` | BIP-113 gate uses height `>=` not `DeploymentActiveAfter`; equivalent today, brittle if BIP-9 versionbits ever re-introduced |
| BUG-9 | P1-API | `interpreter.ts:3083-3092` | `getStandardFlags` missing `verifyDiscourageUpgradableNops` (Core's `STANDARD_SCRIPT_VERIFY_FLAGS` has it) |
| BUG-10 | P1-API | `interpreter.ts:3083-3092` | `getStandardFlags` missing 4 other DISCOURAGE flags (witness-program, taproot-version, op-success, pubkeytype) |
| BUG-11 | P1-WIRE | `interpreter.ts:3021-3036` | `getConsensusFlags` does not take a `params` arg; mainnet-only heights baked into module |
| BUG-12 | P2 | `validation/tx.ts:1782+ / mining/template.ts:143` | `MAX_SEQUENCE_NONFINAL` defined ad-hoc (not exported with the rest of the BIP-68 constants) |
| BUG-13 | **P0-CDIV (dormant)** | `connect_block.ts:416-480` | Assume-valid skips coinbase maturity check; Core enforces unconditionally |
| BUG-14 | (= BUG-13) | same | Same root cause; counted once |

**Total: 14 distinct bugs.** Severities: **P0-CDIV = 5** (BUG-2a, BUG-3,
BUG-5, BUG-7 dormant, BUG-13 dormant); **P1-WIRE = 5** (BUG-1, BUG-2b,
BUG-4, BUG-8, BUG-11); **P1-API = 2** (BUG-9, BUG-10); **P2 = 2**
(BUG-6, BUG-12).

## Top 5 findings (operator-priority order)

1. **BUG-2a P0-CDIV** — regtest/reorg path BIP-68 time-locks always pass.
   The regtest path also handles **reorg-reconnect on all networks**.
   Highest-impact in the bug list because reorgs are real on testnet,
   and any time-based BIP-68 tx in the rolled-out chain would silently
   re-validate on hotbuns even though Core would reject. Fix is one
   line: pass `getUTXOMTP` from `chain/state.ts:344` analogous to
   `sync/blocks.ts:2582`.

2. **BUG-3 P0-CDIV** — assume-valid skips BIP-68.
   Per Core, assume-valid only skips signature/script checks
   (`fScriptChecks` gate). Hotbuns's fast path skips BIP-68, maturity,
   and sigops cost. Compromised or stale `-assumevalid` value lets
   hotbuns admit a chain Core rejects. Fix: move BIP-68 + maturity +
   `Consensus::CheckTxInputs` calls before the `if (assumeValid)`
   short-circuit, so only `verifyAllInputsParallel` is gated by
   assume-valid.

3. **BUG-5 P0-CDIV** — mempool BIP-68 time-lock too strict.
   Mempool divergence: hotbuns rejects relays Core admits. Causes
   mempool desync on time-based BIP-68 txs. Fix is in `mempool.ts:1733`:
   replace per-confirmation `currentMTP` with `headerSync.getMedianTimePast(
   headerSync.getHeaderByHeight(confirmedUtxo.height - 1))`.

4. **BUG-7 + BUG-9/10 P0-dormant** — OP_CSV/CLTV DISCOURAGE + missing
   standard-flag DISCOURAGE. Currently dormant because
   `verifyDiscourageUpgradableNops` is never set by either flag
   constructor. **Fixing BUG-9 (adding the discourage flag to
   getStandardFlags) WITHOUT also fixing BUG-7 would activate the
   regression** — mempool would reject pre-CSV-era scripts. Pair BUG-7
   + BUG-9 in any future fix wave.

5. **BUG-13 P0-CDIV-dormant** — assume-valid skips coinbase maturity.
   Same class as BUG-3 but separate scope. Operator with malicious
   assume-valid hash → premature coinbase spend accepted.

## Universal-pattern candidates

- **"assume-valid skip scope too wide"** (BUG-3 + BUG-13) — hotbuns's
  fast path skips BIP-68 + maturity. Worth grepping every impl for the
  same shape: only signature/script checks should be gated by
  assume-valid. Likely cross-impl pattern.

- **"mempool MTP per-coin uses tip MTP not coin-prev MTP"** (BUG-5) —
  if other impls use a shorthand "currentMTP for everything" they will
  have the same false-reject divergence. Worth a fleet sweep.

- **"DISCOURAGE list copy-paste"** (BUG-7/BUG-9 pair) — OP_NOP2/OP_NOP3
  (CLTV/CSV) are NOT in Core's discourage list at interpreter.cpp:595.
  Easy to miss when implementing the policy-flag plumbing because the
  opcode names suggest they should be in the list. Cross-impl check.

- **"hard-coded mainnet activation heights in flag computers"**
  (BUG-1 / BUG-11) — flag constructor takes only `height`, not
  `params`. Cross-impl check: any impl whose flag computer doesn't
  consult network params has this latent bug for non-mainnet runs.
