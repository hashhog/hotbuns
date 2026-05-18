# W150 — AcceptToMemoryPool + PreChecks + PolicyScriptChecks + ConsensusScriptChecks (hotbuns)

**Wave:** W150 — `AcceptToMemoryPool`, `AcceptSingleTransaction`,
`MemPoolAccept::PreChecks`, `PolicyScriptChecks` (STANDARD flags),
`ConsensusScriptChecks` (GetBlockScriptFlags), `IsStandardTx`,
`AreInputsStandard` / `ValidateInputsStandardness`, `IsWitnessStandard`,
`CheckTransaction` (CVE-2018-17144 / CVE-2010-5139 replay),
`CheckFeeRate`, `CheckInputsFromMempoolAndCache`,
`SpendsNonAnchorWitnessProg` (TX_WITNESS_STRIPPED), ATMPArgs
(`m_bypass_limits`, `m_test_accept`, `m_client_maxfeerate`,
`m_allow_replacement`, `m_package_feerates`), reject-code surface
(TX_NOT_STANDARD vs TX_CONSENSUS vs TX_MEMPOOL_POLICY), `-minrelaytxfee`,
`-incrementalrelayfee`, `-acceptnonstdtxn`, `-permitbaremultisig`,
`-datacarrier`, `-bytespersigop`, `-maxmempool`, `-mempoolexpiry`,
`-mempoolfullrbf`, `-dustrelayfee` operator knobs.

**Scope:** discovery only — no production code changes.

**Bitcoin Core references**
- `bitcoin-core/src/validation.cpp:435-981` — `MemPoolAccept` class,
  `MemPoolAccept::PreChecks(ATMPArgs& args, Workspace& ws)`.
- `bitcoin-core/src/validation.cpp:1135-1156` — `PolicyScriptChecks`
  with `constexpr script_verify_flags scriptVerifyFlags = STANDARD_SCRIPT_VERIFY_FLAGS`.
- `bitcoin-core/src/validation.cpp:1158-1189` — `ConsensusScriptChecks`
  with `currentBlockScriptVerifyFlags = GetBlockScriptFlags(*Tip(), m_chainman)`
  and the comment "This is also useful in case of bugs in the standard
  flags that cause transactions to pass as valid when they're actually
  invalid" (assumed-invariant: PolicyScriptChecks succeeded but
  ConsensusScriptChecks failed → `Assume(false)` / `BUG! PLEASE REPORT THIS`).
- `bitcoin-core/src/validation.cpp:451-489` — `ATMPArgs` (single-tx + package),
  fields: `m_accept_time`, `m_bypass_limits`, `m_coins_to_uncache`,
  `m_test_accept`, `m_allow_replacement`, `m_package_submission`,
  `m_package_feerates`, `m_client_maxfeerate`, `m_allow_sibling_eviction`.
- `bitcoin-core/src/validation.cpp:782-981` — `PreChecks`: 6 distinct
  ordered phases (CheckTransaction → coinbase reject → IsStandardTx →
  MIN_STANDARD_TX_NONWITNESS_SIZE → CheckFinalTxAtTip → mempool dup +
  conflict-detection + UTXO-lookup → CheckSequenceLocksAtTip +
  CheckTxInputs → ValidateInputsStandardness + IsWitnessStandard →
  GetTransactionSigOpCost + bad-txns-too-many-sigops → ChangeSet
  staging + PreCheckEphemeralTx → CheckFeeRate → SingleTRUCChecks).
- `bitcoin-core/src/policy/policy.h:48,70` — `DEFAULT_INCREMENTAL_RELAY_FEE = 100`
  sat/kvB (= 0.1 sat/vB), `DEFAULT_MIN_RELAY_TX_FEE = 100` sat/kvB
  (= 0.1 sat/vB).
- `bitcoin-core/src/policy/policy.h:42-78` — `MAX_P2SH_SIGOPS=15`,
  `MAX_STANDARD_TX_SIGOPS_COST=MAX_BLOCK_SIGOPS_COST/5=16000`,
  `MAX_TX_LEGACY_SIGOPS=2500`, `DEFAULT_BYTES_PER_SIGOP=20`,
  `DEFAULT_PERMIT_BAREMULTISIG=true`, `MAX_STANDARD_P2WSH_STACK_ITEMS=100`,
  `MAX_STANDARD_P2WSH_STACK_ITEM_SIZE=80`,
  `MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE=80`,
  `MAX_STANDARD_P2WSH_SCRIPT_SIZE=3600`,
  `MAX_STANDARD_SCRIPTSIG_SIZE=1650`,
  `DUST_RELAY_TX_FEE=3000`,
  `DEFAULT_CLUSTER_LIMIT=64`, `DEFAULT_CLUSTER_SIZE_LIMIT_KVB=101`,
  `DEFAULT_ANCESTOR_LIMIT=25`.
- `bitcoin-core/src/policy/policy.h:119-132` — `STANDARD_SCRIPT_VERIFY_FLAGS`
  = MANDATORY ∪ {STRICTENC, MINIMALDATA, DISCOURAGE_UPGRADABLE_NOPS,
  CLEANSTACK, MINIMALIF, NULLFAIL, LOW_S,
  DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM, WITNESS_PUBKEYTYPE,
  CONST_SCRIPTCODE, DISCOURAGE_UPGRADABLE_TAPROOT_VERSION,
  DISCOURAGE_OP_SUCCESS, DISCOURAGE_UPGRADABLE_PUBKEYTYPE} (14 added flags).
- `bitcoin-core/src/policy/policy.cpp:27-77` — `GetDustThreshold`,
  `IsDust`, `GetDust` (uses `IsUnspendable()` not just first-byte
  `OP_RETURN`); witness/non-witness input-size discount formula.
- `bitcoin-core/src/policy/policy.cpp:100-156` — `IsStandardTx`
  (version, weight, scriptSig push-only + size, scriptPubKey type,
  datacarrier budget, bare-multisig n≤3, dust gate via `GetDust(...)
  .size() > MAX_DUST_OUTPUTS_PER_TX`).
- `bitcoin-core/src/policy/policy.cpp:214-263` — `ValidateInputsStandardness`
  / `AreInputsStandard` (nonstandard, witness_unknown, P2SH redeem sigops).
- `bitcoin-core/src/policy/policy.cpp:265-352` — `IsWitnessStandard`.
- `bitcoin-core/src/node/txorphanage.h:21-23` — `DEFAULT_MAX_ORPHANAGE_LATENCY_SCORE = 3000`
  (weight-based, replaces legacy 100-count cap; no time-based expire).
- `bitcoin-core/src/init.cpp` — `-minrelaytxfee`, `-incrementalrelayfee`,
  `-acceptnonstdtxn`, `-permitbaremultisig`, `-datacarrier`,
  `-bytespersigop`, `-maxmempool`, `-mempoolexpiry`, `-mempoolfullrbf`,
  `-dustrelayfee`, `-limitancestorcount`, `-limitdescendantcount`.

**Files audited**
- `src/mempool/mempool.ts` — `Mempool.acceptToMemoryPool` (line 1303),
  `Mempool.addTransaction` (line 1324), `validateInputsStandardness`
  (430), `isWitnessStandard` (296), `preCheckEphemeralTx` (789),
  `checkEphemeralSpends` (837), `getDustThreshold` / `isDust` (703 / 737),
  `checkConflicts` (2663), `checkAncestorLimits` (2698),
  `checkClusterSizeLimit`, `improvesFeerateDiagram`, `getMinFee`
  (3243), `trackPackageRemoved`, `evict` (3299),
  `setMinFeeRate` / `setIncrementalRelayFee` / `setMaxSize` (no setter),
  `reorgRefillUnchecked` (2546), `readdTransactions` (2487), the
  `AcceptToMemoryPoolOptions` shape (1106), `MempoolEntry` shape
  (633), `DEFAULT_MIN_FEE_RATE` / `DEFAULT_INCREMENTAL_RELAY_FEE`
  (568 / 576), `DEFAULT_MAX_SIZE = 300_000_000` (546),
  `MEMPOOL_EXPIRY_SECONDS = 336 * 60 * 60` (553).
- `src/validation/tx.ts` — `validateTxBasic` (CheckTransaction analog,
  1022), `verifyInputSignature` (1499), `verifyAllInputsParallel`
  (1698), `verifyAllInputsSequential` (1745), `ScriptFlags` enum (20).
- `src/script/interpreter.ts` — `getConsensusFlags(height)` (3021),
  `getStandardFlags(height)` (3083), `scriptFlagsFromBitmask` (3053).
- `src/consensus/connect_block.ts` — `coreConnectBlockChecks`
  (`assumeValid` block at 416-480; full path at 482-741; per-script
  flag derivation at 574-577).
- `src/consensus/assumevalid.ts` — `shouldSkipScripts`, the canonical
  6-condition assumevalid gate (160).
- `src/consensus/params.ts` — `MAINNET`, `TESTNET`, `TESTNET4`, `SIGNET`,
  `REGTEST` and the spread-inheritance pattern from MAINNET.
- `src/sync/blocks.ts` — IBD `connectBlock` (calls `coreConnectBlockChecks`
  at 2565), reorg intermediate path at 2180, missing `verifyTaproot`
  arg at both sites.
- `src/chain/state.ts` — `connectBlock` (286, called by generateblock
  RPC + reorganize), missing `verifyTaproot` + skips `validateBlock`.
- `src/mempool/rbf.ts` — `signalsOptInRBF`, `isRBFOptIn`,
  `entriesAndTxidsDisjoint`, `MAX_BIP125_RBF_SEQUENCE`,
  `MAX_REPLACEMENT_CANDIDATES`.
- `src/mempool/orphan_pool.ts` — `MAX_ORPHAN_TRANSACTIONS = 100`,
  `MAX_PEER_ORPHAN_TX = 50`, `ORPHAN_TX_EXPIRE_TIME = 300`,
  `MAX_ORPHAN_TX_SIZE = 100_000`.
- `src/mempool/persist.ts` — `loadMempool` (336), drops `mapDeltas`
  silently (382).
- `src/rpc/server.ts` — `sendrawtransaction` (3266-3277), reports
  fixed `minrelaytxfee: 0.00001 BTC/kvB` / `incrementalrelayfee:
  0.00001 BTC/kvB` in getmempoolinfo (3566), generateblock at 5598
  (calls `chainState.connectBlock` without `validateBlock` first).
- `src/cli/cli.ts` — `parseArgs` (315-617), missing operator knobs.

---

## Gate matrix (38 sub-gates / 12 behaviours)

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 1 | PreChecks ordering | G1: CheckTransaction first | PASS — `validateTxBasic` at addTransaction:1329 |
| 1 | … | G2: coinbase reject AFTER CheckTransaction | PASS (line 1335) |
| 1 | … | G3: IsStandardTx (version, weight, scriptSig, scriptPubKey, datacarrier) | PASS — gates at 1365/1376/1410/1431 (inlined; no IsStandardTx() helper) |
| 1 | … | G4: MIN_STANDARD_TX_NONWITNESS_SIZE = 65 | PASS (line 1402) |
| 1 | … | G5: CheckFinalTxAtTip (BIP-113) | PASS (line 1717) — but BUG-3 below on header-sync-MTP fallback |
| 1 | … | G6: mempool wtxid + txid dup check | PASS (line 1354-1362) |
| 1 | … | G7: in-mempool conflict gather | PASS but **BUG-1** — no `m_allow_replacement` arg, always allows RBF |
| 1 | … | G8: UTXO-presence lookup with "txn-already-known" distinction | PASS (line 1582-1602) — **BUG-2** rejection-string formatted with outpoint |
| 1 | … | G9: CheckSequenceLocksAtTip (BIP-68) | PASS (line 1729-1748) |
| 1 | … | G10: CheckTxInputs (sum + MoneyRange + bad-txns-in-belowout) | PASS (line 1542-1650) |
| 1 | … | G11: ValidateInputsStandardness + IsWitnessStandard | PASS (line 1985 / 2003) |
| 1 | … | G12: GetTransactionSigOpCost with STANDARD flags | **BUG-4** — passes `verifyP2SH=true, verifyWitness=true` unconditionally instead of deriving from STANDARD flags or height |
| 1 | … | G13: bad-txns-too-many-sigops at MAX_STANDARD_TX_SIGOPS_COST = 16000 | PASS (line 1675) |
| 1 | … | G14: PreCheckEphemeralTx (dust + 0-fee) | PASS (line 1697) |
| 1 | … | G15: CheckFeeRate (rolling + static min-relay) | PASS (line 1771-1785), but **BUG-5** below: `DEFAULT_MIN_FEE_RATE = 0` vs Core 100 sat/kvB |
| 1 | … | G16: SingleTRUCChecks (BIP-431) | PASS (line 1913) |
| 2 | PolicyScriptChecks | G17: re-verify all inputs under STANDARD_SCRIPT_VERIFY_FLAGS | PARTIAL — **BUG-6** below: `getStandardFlags(height)` returns only 4 of 14 added Core flags (NULLFAIL, WITNESS_PUBKEYTYPE, STRICTENC, LOW_S); MINIMALIF / CLEANSTACK / CONST_SCRIPTCODE / MINIMALDATA / 4× DISCOURAGE_UPGRADABLE_*  / DISCOURAGE_OP_SUCCESS all absent |
| 3 | ConsensusScriptChecks | G18: re-verify under GetBlockScriptFlags(*Tip) | PARTIAL — **BUG-7** below: hotbuns has no `GetBlockScriptFlags` analog; uses `getConsensusFlags(this.tipHeight)` which is height-only and lacks `script_flag_exceptions` table (W144 fleet pattern) |
| 3 | … | G19: BUG-detect: PolicyScriptChecks PASS + ConsensusScriptChecks FAIL → Assume(false) "BUG! PLEASE REPORT THIS" | **BUG-8** absent — hotbuns just rejects with a generic `ConsensusScriptChecks: …` error, no `Assume`-class invariant fire |
| 3 | … | G20: SpendsNonAnchorWitnessProg → TX_WITNESS_STRIPPED disambiguation | **BUG-9** absent — hotbuns has no TX_WITNESS_STRIPPED detection; missing-witness vs script-fail reject reason is indistinguishable |
| 4 | ATMPArgs surface | G21: `m_test_accept` | PASS — `AcceptToMemoryPoolOptions.testAccept` (1115) |
| 4 | … | G22: `m_client_maxfeerate` | PASS — `maxFeeRateSatPerVB` (1108) |
| 4 | … | G23: `m_bypass_limits` (reorg replay) | **BUG-10** absent — `readdTransactions` calls plain `addTransaction` so feerate / cluster / coinbase-maturity gates fire on disconnected txs that Core would skip via `bypass_limits` |
| 4 | … | G24: `m_allow_replacement` | **BUG-1 cross-cite** absent |
| 4 | … | G25: `m_package_feerates` | absent (single-tx path only — TRUC + Package gates exist separately) |
| 5 | Operator knobs (CLI flags) | G26: `-minrelaytxfee` | **BUG-11** absent — no flag in `parseArgs`; setter `setMinFeeRate` exists but is never called from `cli.ts`; default `DEFAULT_MIN_FEE_RATE = 0` (Core: 0.1 sat/vB = 100 sat/kvB) |
| 5 | … | G27: `-incrementalrelayfee` | absent (no CLI flag; setter exists but is never called from cli) |
| 5 | … | G28: `-maxmempool` | **BUG-12** absent — constructor accepts `maxSize` but `cli.ts:1541` calls `new Mempool(utxo, params)` with no size arg; default `300_000_000` is locked-in |
| 5 | … | G29: `-mempoolexpiry` | absent (`MEMPOOL_EXPIRY_SECONDS = 336*60*60` hardcoded; persist.ts:339 takes a param but cli wires nothing) |
| 5 | … | G30: `-mempoolfullrbf` | absent — `fullrbf: true` is hardcoded in getmempoolinfo (3569); behaviour is always full-RBF; no opt-out |
| 5 | … | G31: `-acceptnonstdtxn` | absent — non-standard txs always rejected; no testnet-style "accept-any-tx" mode |
| 5 | … | G32: `-permitbaremultisig` | absent — `n>3` rejection at 1465 has no override |
| 5 | … | G33: `-datacarrier`, `-datacarriersize` | absent — `MAX_OP_RETURN_RELAY = 100_000` hardcoded |
| 5 | … | G34: `-bytespersigop` | absent — `DEFAULT_BYTES_PER_SIGOP = 20` hardcoded |
| 5 | … | G35: `-dustrelayfee` | absent — `DUST_RELAY_FEE = 3000` hardcoded |
| 6 | Assume-valid scope | G36: skip ONLY scripts (Core `fScriptChecks`) — never maturity / BIP-68 / sigops / MoneyRange / fee accounting | **BUG-13 (P0-CDIV — W145 BUG-2..6 carry-forward)** — `coreConnectBlockChecks` `assumeValid` branch (connect_block.ts:416-480) skips coinbase maturity, BIP-68, sigops counting, per-input MoneyRange + per-tx fee accounting. Core skips only sig verification |
| 6 | … | G37: TwoPipelineAssumeValid: `params.assumeValidHeight > 0 && height <= assumeValidHeight` (sync/blocks.ts:2477, chain/state.ts not gated) vs canonical `shouldSkipScripts()` 6-condition gate | **BUG-14** — two parallel decisions: blocks.ts uses BOTH (height-only `assumeValid` AND 6-condition `skipScripts`); state.ts uses NEITHER (always full); the two derived booleans coexist and gate different things |
| 7 | Reject-code surface | G38: TX_NOT_STANDARD vs TX_CONSENSUS vs TX_MEMPOOL_POLICY vs TX_MISSING_INPUTS distinction for p2p ban policy | **BUG-15** — `addTransaction` returns `{accepted, error: string}` only; no structured `TxValidationResult` enum so the p2p layer's `isMissingInputError()` heuristic is the only differentiator. Non-standard txs cannot be distinguished from consensus failures → can't ban-vs-silent-drop differentiate (Core: TX_NOT_STANDARD ≠ ban; TX_CONSENSUS → ban) |

---

## BUG-1 (P1) — `m_allow_replacement` ATMPArg is absent; admission always allows RBF

**Severity:** P1. Bitcoin Core's `MemPoolAccept::PreChecks` (validation.cpp:837-843)
honours `args.m_allow_replacement` — when **false**, a tx that conflicts
with an existing mempool entry is rejected immediately with
`"bip125-replacement-disallowed"` (TX_MEMPOOL_POLICY). The package path
(`AcceptMultipleTransactionsInternal`) passes `m_allow_replacement=false`
for sub-package validation so a child cannot covertly replace its
ancestor mid-flow. Various RPC paths also opt out via this knob.

hotbuns has no `allowReplacement` flag on `AcceptToMemoryPoolOptions`
(line 1106-1116). The conflict-detection path at `addTransaction` line
1488-1525 unconditionally enters the RBF replacement codepath when any
conflict is found — there is no way for a caller to require "single-tx
admission, refuse-if-conflicts". The package validator at line 4159 /
4368 uses `addTransaction` and inherits the always-RBF behaviour.

**File:** `src/mempool/mempool.ts:1106-1116, 1488-1525`.
**Core ref:** `validation.cpp:837-843` (PreChecks conflict gate).
**Impact:** package validation cannot enforce "no internal replacements"
invariant; `submitpackage` RPC behaves differently than Core.

---

## BUG-2 (P1) — Reject-reason strings include outpoint debug data; cross-impl wire-format divergence

**Severity:** P1. Bitcoin Core's `TxValidationState` separates the
reject **reason** (a fixed token like `"bad-txns-inputs-missingorspent"`)
from the debug **message** (free-form). The reason flows through
`bip22Result` / P2P REJECT messages unchanged; the debug message is
log-only.

hotbuns's `addTransaction` at line 1601 returns
``error: `bad-txns-inputs-missingorspent: ${outpointKey}` `` — the
outpoint key (txid:vout) is concatenated INTO the reject token. Same
pattern at:
- line 1336: `"Coinbase transaction not allowed in mempool"` (Core token: `"coinbase"`)
- line 1720: `"non-final: bad-txns-nonfinal"` (Core token: `"non-final"`)
- line 1746: `"non-BIP68-final: bad-txns-nonfinal"` (Core token: `"non-BIP68-final"`)
- line 1597: `"txn-already-known"` (PASS — clean)
- line 4117: `"tx has ephemeral dust but no child spending it"` (Core: `"missing-ephemeral-spends"`)

Wire-format divergence: a peer's REJECT msg payload will not match
Core's. RPC `testmempoolaccept` returns the suffixed string. Cross-impl
diff-test corpus that asserts on canonical token will mis-match.

**File:** `src/mempool/mempool.ts:1336, 1601, 1720, 1746, 4117`;
`src/validation/errors.ts` (no `TxValidationState` analog).
**Core ref:** `validation.cpp:782+` (TxValidationState .GetRejectReason()
vs .GetDebugMessage()).
**Impact:** wire-format parity for REJECT (BIP-61, still used for p2p
banning decisions); RPC test_accept output mismatch; W125 reject-string
parity series 7th instance (lunarblock W145 9-token sweep was the prior).

---

## BUG-3 (P1) — BIP-113 MTP source race in addTransaction

**Severity:** P1. `addTransaction` at line 1709-1716 picks the MTP for
`CheckFinalTxAtTip` from either the cached `this.tipMTP` field OR the
header-sync's `getMedianTimePast(bestHdr)`:

```ts
let currentMTP = this.tipMTP;
if (this.headerSync) {
  const bestHdr = this.headerSync.getBestHeader();
  if (bestHdr) {
    currentMTP = this.headerSync.getMedianTimePast(bestHdr);
  }
}
```

This races vs the actual tip in two ways:

1. `bestHeader` is the most-chain-work **header** (may be ahead of the
   actual connected tip during IBD). Using its MTP for tip+1 finality is
   wrong: Core uses `m_active_chainstate.m_chain.Tip()` MTP. Time-locked
   tx with `nLockTime > tipMTP` but `nLockTime <= bestHeaderMTP` would
   be accepted into a mempool whose tip cannot mine it yet.
2. `tipMTP` (the fallback) is plain field that the caller sets via
   `setTipMTP(int)` — but is `tipMTP` ever set? It's initialised to 0
   (line 1226) and there's no explicit `setTipMTP` consumer except in
   the unit tests. Confirmed: production code path never calls
   `setTipMTP` — fallback is permanently 0.

**File:** `src/mempool/mempool.ts:1226, 1709-1716`.
**Core ref:** `validation.cpp:819-820` — `CheckFinalTxAtTip(*Tip(), tx)`.
**Impact:** time-locked tx admission window inconsistent between
header-sync-wired and unwired contexts. Tests that don't wire header
sync would silently accept time-locked txs that Core would reject.

---

## BUG-4 (P0-CDIV) — `getTransactionSigOpCost` called with hardcoded `verifyP2SH=true, verifyWitness=true` instead of STANDARD-flag-derived

**Severity:** P0-CDIV. Bitcoin Core PreChecks (validation.cpp:908)
calls `GetTransactionSigOpCost(tx, m_view, STANDARD_SCRIPT_VERIFY_FLAGS)`
— the script-verify flag bitmask drives whether `MAX_PUBKEYS_PER_INPUT`
witness sigops, P2SH-redeem sigops, and legacy sigops are counted.

hotbuns at addTransaction:1666-1671:

```ts
const sigOpCost = getTransactionSigOpCost(
  tx, prevOutputsForSigOps,
  /* verifyP2SH */ true,
  /* verifyWitness */ true
);
```

— both flags are HARDCODED to `true`. There is no derivation from the
network's BIP-16 / BIP-141 activation heights. On regtest with
segwitHeight=0 this happens to match Core's STANDARD-flags behaviour
(both active from height 0). But on testnet3 mempool admission BEFORE
the BIP-141 activation height (834,624) hotbuns would count witness
sigops as 1 (under verifyWitness=true) where Core's STANDARD_SCRIPT_VERIFY_FLAGS-derived
count would also include them (so this happens to be OK). The
divergence flips during sync of pre-activation testnet3 blocks if a
testnet3 mempool admission ever happens during IBD (it's gated off via
the IBD-complete check, but verifyP2SH=true also fires on regtest
pre-bip16 which is height-0 anyway). Defense-in-depth violation
regardless: the constants should match the per-network gating.

**File:** `src/mempool/mempool.ts:1666-1671`.
**Core ref:** `validation.cpp:908`.
**Impact:** symptomatic on alt-networks where bip16Height ≠ 0 or
segwitHeight ≠ 0 with mempool admission active pre-activation. Latent
under current invariants; a future testnet activation height bump or a
manual `setTipHeight(0)` test exposes it.

---

## BUG-5 (P1) — `DEFAULT_MIN_FEE_RATE = 0` diverges from Core's 100 sat/kvB

**Severity:** P1. Core sets `DEFAULT_MIN_RELAY_TX_FEE = 100` sat/kvB
(= 0.1 sat/vB) at `policy.h:70`. The mempool admission path
(`CheckFeeRate` at `validation.cpp:948`) requires fee ≥ this floor by
default, so a fresh Core node refuses to relay 0-fee txs.

hotbuns at `mempool.ts:568`:

```ts
const DEFAULT_MIN_FEE_RATE = 0;
```

And no `-minrelaytxfee` flag in `cli/cli.ts` (BUG-11). Operator cannot
raise it. Effect: a fresh hotbuns mempool admits **any** non-zero-fee
tx (and even 0-fee dust-bearing TRUC). Core would silently drop.
Cross-impl divergence: a peer relaying a 0-fee tx to hotbuns gets it
accepted-and-rebroadcast; same peer relaying to Core gets it dropped.

**File:** `src/mempool/mempool.ts:568`; `src/cli/cli.ts` (no
`-minrelaytxfee` flag).
**Core ref:** `policy.h:70`, `validation.cpp:948`.
**Impact:** wire-relay divergence; potential DoS vector if low-fee txs
flood the mempool while peers' min-relay-fee filter prevents them from
forwarding the same txs.

---

## BUG-6 (P0-CDIV) — `getStandardFlags(height)` returns only 4 of 14 STANDARD flag additions; carry-forward of W144 BUG-3

**Severity:** P0-CDIV. Bitcoin Core's `STANDARD_SCRIPT_VERIFY_FLAGS`
(`policy.h:119-132`) is `MANDATORY ∪ { STRICTENC, MINIMALDATA,
DISCOURAGE_UPGRADABLE_NOPS, CLEANSTACK, MINIMALIF, NULLFAIL, LOW_S,
DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM, WITNESS_PUBKEYTYPE,
CONST_SCRIPTCODE, DISCOURAGE_UPGRADABLE_TAPROOT_VERSION,
DISCOURAGE_OP_SUCCESS, DISCOURAGE_UPGRADABLE_PUBKEYTYPE }` (14 added
bits). These are **compile-time constants** that apply to ALL mempool
admissions regardless of activation height (the mempool admits txs for
the NEXT block, so the post-activation rules always apply).

hotbuns at `interpreter.ts:3083-3092`:

```ts
export function getStandardFlags(height: number): ScriptFlags {
  const flags = getConsensusFlags(height);
  return {
    ...flags,
    verifyNullFail: height >= 481824,          // policy: BIP 146
    verifyWitnessPubkeyType: height >= 481824, // policy: BIP 141 standardness
    verifyStrictEncoding: height >= 363725,    // policy: BIP 66 standardness
    verifyLowS: height >= 363725,              // policy: BIP 62 rule 5
  };
}
```

— only **4 of 14** policy additions are present (NULLFAIL,
WITNESS_PUBKEYTYPE, STRICTENC, LOW_S). MISSING:
- `verifyMinimalIf` (defined in interpreter `ScriptFlags` interface,
  consulted at interpreter.ts:1072 — NEVER set in getStandardFlags)
- `verifyCleanStack` (defined, consulted at interpreter.ts:2290 —
  NEVER set)
- `verifyConstScriptCode` (not defined in `ScriptFlags` interface at all)
- `verifyMinimalData` (not defined; CHECKBIT)
- `verifyDiscourageUpgradableNOPs` (not defined)
- `verifyDiscourageUpgradableWitnessProgram` (not defined)
- `verifyDiscourageUpgradableTaprootVersion` (not defined)
- `verifyDiscourageOpSuccess` (not defined)
- `verifyDiscourageUpgradablePubkeyType` (not defined)

AND the 4 implemented flags are **height-gated** — on a fresh start
with `tipHeight = 0`, all four are OFF. Core's policy flags do not gate
on tip height; they always run. So at startup hotbuns admits txs that
Core would reject as non-standard for STRICTENC / LOW_S violations.

Compounding with the consensus side (`getConsensusFlags(height)`):
pre-activation heights gate consensus flags too, but those are
correctly the consensus rules. The policy-side gate is wrong.

**File:** `src/script/interpreter.ts:3083-3092`; `src/validation/tx.ts:20-32`
(ScriptFlags enum); `src/script/interpreter.ts:234-249` (ScriptFlags
interface — missing 9 flag fields).
**Core ref:** `policy.h:119-132` (constant; always-on); `interpreter.h`
(SCRIPT_VERIFY_* enum); W144 BUG-3.
**Impact:** mempool admits txs Core rejects as non-standard. Wire-relay
divergence: a peer's tx accepted into hotbuns mempool may be rejected
by every Core peer; hotbuns relays a tx its neighbours discard.
9-flag-class gap mirrors the W144 fleet-wide pattern (haskoin: missing
ALL 14; blockbrew: missing 9 of 13).

---

## BUG-7 (P0-CDIV) — `script_flag_exceptions` table entirely absent (mainnet replay chain-split)

**Severity:** P0-CDIV. Bitcoin Core's `GetBlockScriptFlags` consults a
hard-coded exception table for two mainnet blocks:
- h=174,062 (`0000000000000051b450faa040…`) — BIP-16 (P2SH) grandfather
  block. The standard `flags |= SCRIPT_VERIFY_P2SH` is overridden to
  OFF for this single block so the historical non-P2SH-compliant
  redeem-script script that paid into BIP-16 gets accepted.
- h=692,263 (`00000000000000000005c91cf2d2…`) — Taproot grandfather
  block: P2SH-wrapped output that fails BIP-341 P2TR enforcement.

These are encoded in `kernel/chainparams.cpp` `script_flag_exceptions`
map; consulted by `GetBlockScriptFlags` (validation.cpp:6298+).

hotbuns has **no script_flag_exceptions equivalent**. `grep -rn
script_flag_exceptions src/` returns nothing; `grep -rn 174062 src/`
returns nothing; `grep -rn 692263 src/` returns nothing.

Effect: a from-genesis mainnet replay reaches h=174,062 → hotbuns
applies SCRIPT_VERIFY_P2SH (active since BIP-16 activation block
173,805) → the grandfather block's coinbase-spending tx fails P2SH
redeem-script validation → block rejected → chain stalls at 174,061.
Same for Taproot at h=692,263.

This is the fleet-wide W144 pattern (9 of 10 impls confirmed; companion
to W128 banman 8/10).

**File:** `src/script/interpreter.ts:3021-3036` (`getConsensusFlags`);
`src/sync/blocks.ts:2576-2577` (per-block script-flag derivation).
**Core ref:** `kernel/chainparams.cpp` `script_flag_exceptions`;
`validation.cpp:6298+` `GetBlockScriptFlags`.
**Impact:** mainnet from-genesis IBD HARD-FAILS at h=174,062. Mitigated
in production by assume-valid (skips scripts up to height 938,343), but
a node running with `-assumevalid=0` or starting before 938,343 with
default config gets stuck. CVE-class on mainnet replay.

---

## BUG-8 (P1) — `Assume(false) / "BUG! PLEASE REPORT THIS"` invariant absent in ConsensusScriptChecks

**Severity:** P1. Bitcoin Core's `ConsensusScriptChecks`
(validation.cpp:1184) does:

```cpp
if (!CheckInputsFromMempoolAndCache(...)) {
    LogError("BUG! PLEASE REPORT THIS! CheckInputScripts failed against latest-block but not STANDARD flags %s, %s", hash.ToString(), state.ToString());
    return Assume(false);
}
```

The `Assume(false)` is a release-build LOG + debug-build ASSERT_FAIL.
It is the **bug-discovery invariant**: PolicyScriptChecks succeeded
under STANDARD_SCRIPT_VERIFY_FLAGS but ConsensusScriptChecks failed
under tip's consensus flags → either STANDARD has a bug that masks a
consensus failure, or the height-derivation is wrong.

hotbuns's parallel logic at `mempool.ts:2133-2140`:

```ts
const consensusFlags = getConsensusFlags(this.tipHeight);
const consensusResult = verifyAllInputs(consensusFlags);
if (!consensusResult.ok) {
  return { accepted: false, error: `ConsensusScriptChecks: ${consensusResult.reason}` };
}
```

— no logged-bug-marker, no assert, no telemetry. The "STANDARD passed
but CONSENSUS failed" condition silently rejects. Operators cannot
detect: (a) the BUG-6 STANDARD-flag-gap that lets a non-standard tx
through PolicyScriptChecks but then fails on a stricter consensus rule;
(b) a future hotbuns flag-derivation bug; (c) corrupt UTXO cache where
the cached script flag set diverged from the actual block's.

**File:** `src/mempool/mempool.ts:2133-2140`.
**Core ref:** `validation.cpp:1184-1186`.
**Impact:** loss of the canonical "bug! please report this" observability
gate; latent BUG-6 (STANDARD gap) cannot be flagged operationally.

---

## BUG-9 (P1) — `TX_WITNESS_STRIPPED` / `SpendsNonAnchorWitnessProg` detection absent

**Severity:** P1. Bitcoin Core's `PolicyScriptChecks` at
validation.cpp:1148-1151:

```cpp
if (!tx.HasWitness() && SpendsNonAnchorWitnessProg(tx, m_view)) {
    state.Invalid(TxValidationResult::TX_WITNESS_STRIPPED, ...);
}
```

When script verification fails AND the tx has NO witness data AND it
spends a non-anchor witness program (P2WPKH / P2WSH / P2TR), the
reject reason is upgraded to `TX_WITNESS_STRIPPED`. The p2p layer uses
this to handle **witness-stripped relay** — a malicious peer can
forward a tx without its witness; without this distinction the receiver
caches the failure as a definitive reject and never accepts the
properly-witnessed retransmit.

hotbuns has no `SpendsNonAnchorWitnessProg`, no `TX_WITNESS_STRIPPED`,
no analog. `grep -rn TX_WITNESS_STRIPPED src/` returns nothing.

**File:** `src/mempool/mempool.ts:2114-2141`; `src/p2p/manager.ts` and
related (no recent-rejects-witness-stripped exception list).
**Core ref:** `validation.cpp:1148-1151`;
`src/policy/policy.cpp:SpendsNonAnchorWitnessProg`.
**Impact:** witness-stripping attack vector: an adversarial peer forwards
witness-stripped txs to all peers, the receiver records the failure
under the txid, and the legitimate witness retransmit gets silently
suppressed by the `recently-rejected` cache. Latent DoS.

---

## BUG-10 (P0-CDIV) — `reorgRefillUnchecked` admits disconnected txs with `fee = 0n` and skipping CheckTransaction

**Severity:** P0-CDIV. Bitcoin Core's reorg-refill path uses
`m_bypass_limits = true` but still runs **every** validation gate:
CheckTransaction, CheckTxInputs, MoneyRange, script verification —
only the rate-limit and feerate gates are bypassed. The refilled tx
gets a real `m_modified_fees` value (it's verifiable because Core has
proper UTXO undo data).

hotbuns at `mempool.ts:2546-2603` implements `reorgRefillUnchecked`:

```ts
const fee = 0n;          // sentinel
const feeRate = 0;       // sentinel
const entry: MempoolEntry = {
  tx, txid, fee, feeRate, vsize, weight,
  addedTime: …, height: …,
  dependsOn: new Set(),  // unchecked path: no parent tracking
  ancestorCount: 1, ancestorSize: vsize,
  …
  sigOpCost: 0,
};
this.entries.set(txidHex, entry);
this.currentSize += vsize;
```

— NO call to `validateTxBasic` (CheckTransaction analog), NO call to
`isStandardTx`, NO script verification, NO conflict check, NO sigops
recalc, NO MoneyRange. Direct `entries.set(…)`.

CVE-class concerns:
1. **CVE-2018-17144 replay**: a disconnected tx with duplicate inputs
   (which Core never could have included in a valid block) would still
   be admitted to the mempool. Once admitted, miner-side block template
   construction would try to include it → block produced contains
   double-spend → Core peers reject the block → split.
2. **Inflation gateway**: zero-fee assignment lets the next block
   include the tx without fee accounting; a coinbase template builder
   not double-checking would over-pay subsidy + the disconnected fees
   that the refill code lost track of.
3. **MoneyRange bypass**: a corrupt persisted tx with value > MAX_MONEY
   would be admitted; the block template builder is the only line of
   defense.

The comment at line 2528 acknowledges the divergence ("This unchecked
admission is policy-correct for the refill case…") but the chain of
reasoning depends on the disconnect-side having full UTXO disconnect —
which hotbuns admits it does NOT have (line 2515-2522 "hotbuns's
IBD-time block connect does NOT persist undo data"). Comment-as-confession
8th instance.

**File:** `src/mempool/mempool.ts:2546-2603`.
**Core ref:** `validation.cpp:451-489` (ATMPArgs.m_bypass_limits);
`MaybeUpdateMempoolForReorg`.
**Impact:** CVE-2018-17144 replay primitive on reorg; mining template
fee accounting break.

---

## BUG-11 (P0-CDIV) — Operator cannot configure `-minrelaytxfee` / `-incrementalrelayfee` / `-maxmempool` / `-mempoolexpiry` / `-mempoolfullrbf` / `-acceptnonstdtxn` / `-permitbaremultisig` / `-datacarrier` / `-bytespersigop` / `-dustrelayfee`

**Severity:** P0-CDIV. Bitcoin Core exposes ~12 operator knobs for
mempool / policy. hotbuns's CLI parser (`cli.ts:315-617`) registers
zero of them. Setters exist on `Mempool` (line 3389 `setMinFeeRate`,
3414 `setIncrementalRelayFee`) but `cli.ts:1541` constructs the
Mempool without arguments and never calls these setters.

Specific impact per missing flag:

| Flag | Hardcoded value | Core default | Operator impact |
|------|-----------------|--------------|-----------------|
| `-minrelaytxfee` | 0 sat/vB | 0.1 sat/vB | hotbuns accepts 0-fee txs (BUG-5) |
| `-incrementalrelayfee` | 0.1 sat/vB | 0.1 sat/vB (match) | cannot tune RBF Rule-4 floor |
| `-maxmempool` | 300 MB | 300 MB (match) | cannot raise on big-RAM nodes; cannot lower for tests |
| `-mempoolexpiry` | 336 h | 336 h (match) | cannot tune expiry; persist.ts:339 takes an arg but cli wires nothing |
| `-mempoolfullrbf` | always true | true (default since v26) | cannot opt-out; getmempoolinfo reports `fullrbf: true` always |
| `-acceptnonstdtxn` | always false | false on mainnet, true on regtest/testnet | regtest cannot accept non-standard tx for tests |
| `-permitbaremultisig` | always true | true (match) | cannot opt-out for stricter operators |
| `-datacarrier` / `-datacarriersize` | 100_000 bytes hardcoded | 83 bytes (recent Core) | huge OP_RETURN budget divergence: 1200× Core's |
| `-bytespersigop` | 20 hardcoded | 20 (match) | cannot disable sigop-weighting |
| `-dustrelayfee` | 3000 sat/kvB hardcoded | 3000 (match) | cannot raise dust threshold |
| `-limitancestorcount` | 25 hardcoded | 25 (match) | cannot tune for tests |
| `-limitdescendantcount` | 25 hardcoded | 25 (match) | cannot tune |

**File:** `src/cli/cli.ts:315-617` (parseArgs — zero policy/mempool
flags); `src/cli/cli.ts:1541` (Mempool construction with no args);
`src/mempool/mempool.ts:130, 543-576` (hardcoded constants).
**Core ref:** `init.cpp` `-minrelaytxfee`, `-incrementalrelayfee`,
`-maxmempool`, `-mempoolexpiry`, `-mempoolfullrbf`, `-acceptnonstdtxn`,
`-permitbaremultisig`, `-datacarrier`, `-datacarriersize`,
`-bytespersigop`, `-dustrelayfee`.
**Impact:** operator cannot adapt the mempool for testnet, regtest, or
high-RAM environments. Migration from a Core node breaks: bitcoin.conf
settings are silently ignored. Significant: `-datacarriersize` divergence
allows OP_RETURN payloads ~1200× larger than recent Core — wallets that
filter on this gate behave differently.

---

## BUG-12 (P1) — `Mempool.maxSize` is locked at 300 MB; no `setMaxSize` / no constructor wiring

**Severity:** P1. Mempool constructor at `mempool.ts:1211-1216` accepts
`maxSize: number = DEFAULT_MAX_SIZE`. cli.ts:1541 calls:

```ts
const mempool = new Mempool(utxo, params);
```

— with no `maxSize` arg. The default 300_000_000 (300 MB) is locked in.
There is no `setMaxSize` setter on Mempool, so even if the
configuration were available, the value couldn't be changed at runtime.

**File:** `src/mempool/mempool.ts:1136-1219`; `src/cli/cli.ts:1541`.
**Core ref:** `init.cpp -maxmempool` (DEFAULT_MAX_MEMPOOL_SIZE_MB=300).
**Impact:** mid-size nodes (e.g. 8 GB RAM with `-maxmempool=4000`) get
the same 300 MB cap as a Raspberry Pi. RBF / fee-bump policy effectively
diverges from Core for operators who scale mempool.

---

## BUG-13 (P0-CDIV) — Assume-valid scope creep in `coreConnectBlockChecks.assumeValid` branch (W145 BUG-2..6 carry-forward, STILL UNFIXED)

**Severity:** P0-CDIV. Bitcoin Core's `fScriptChecks` flag (validation.cpp
ConnectBlock) gates ONLY signature verification (`CheckInputScripts`).
COINBASE_MATURITY, BIP-68 CSV, sigops ceiling, per-input MoneyRange,
per-tx fee accumulation, and the bad-txns-in-belowout invariant ALL
fire unconditionally regardless of fScriptChecks.

hotbuns at `connect_block.ts:416-480`, the `if (assumeValid) { … return …; }`
branch:

1. **Skips coinbase maturity** — non-assumeValid path runs at line
   533-541 inside the for-loop; assumeValid path's for-loop does not.
2. **Skips BIP-68 sequence locks** — non-assumeValid at 555-570;
   assumeValid path has no analog.
3. **Skips sigops counting** — `getTransactionSigOpCost` called at 633
   in full path only; assumeValid never sums sigops, so
   MAX_BLOCK_SIGOPS_COST is unenforced.
4. **Skips per-coin MoneyRange + accumulated MoneyRange** — full path
   at 611-624; assumeValid just `avTotalInputValue += spentEntry.amount`
   without bounds check.
5. **Skips per-tx fee accumulation + bad-txns-in-belowout** — full path
   at 652-678; assumeValid never derives per-tx fee. It DOES check
   coinbase ≤ subsidy + fees at the end (line 462-470) but using
   `avFees = avTotalInputValue - (avTotalOutputValue - avCoinbaseOutputValue)`
   which is a single post-hoc sum — won't catch a per-tx negative-fee
   (txin = 1 BTC, txout = 100 BTC) until it surfaces in the aggregate.
6. **Skips `validateTxBasic` (CVE-2018-17144 replay)** — `coreConnectBlockChecks`
   relies on the caller (sync/blocks.ts at 2466) calling `validateBlock`
   FIRST, which does run validateTxBasic. But the reorg-intermediate
   path at sync/blocks.ts:2180 and the chain/state.ts:344 path do NOT
   call validateBlock before coreConnectBlockChecks.

This is the **hotbuns origin** of the "Assume-valid scope creep" fleet
pattern. W145 BUG-2..6 cluster catalogued the same shape; remains
UNFIXED.

**File:** `src/consensus/connect_block.ts:416-480`.
**Core ref:** `validation.cpp` ConnectBlock — fScriptChecks gate
position.
**Impact:** if assume-valid is true (mainnet height ≤ 938,343), a
crafted block at that height with: (a) duplicate inputs (CVE-2018-17144
class), (b) sigops > 80,000, (c) coinbase-spent at depth < 100, or
(d) per-tx negative fee that doesn't surface in aggregate, would be
silently accepted.

---

## BUG-14 (P1) — Two-pipeline assume-valid decision (height-only `assumeValid` + 6-condition `skipScripts` coexist + diverge)

**Severity:** P1. `sync/blocks.ts:2477` computes:

```ts
const assumeValid = this.params.assumeValidHeight > 0 && height <= this.params.assumeValidHeight;
```

Then later (line 2535-2536) ALSO computes:

```ts
const skipScriptsResult = shouldSkipScripts(avCtx);
const skipScripts = skipScriptsResult.skip;
```

Both are passed to `coreConnectBlockChecks` (line 2571-2572):

```ts
{ assumeValid, skipScripts, … }
```

They gate **different things**: `assumeValid` (height-only) gates the
fast-path branch at connect_block.ts:416 (skips maturity / BIP-68 /
sigops / MoneyRange — see BUG-13). `skipScripts` (6-condition) gates
ONLY the per-input script verification at connect_block.ts:573 (inside
the FULL path). The two derived booleans drive overlapping but distinct
checks.

Pathological combinations:
- `assumeValid=false, skipScripts=true` — full validation EXCEPT
  scripts, which is fine (canonical Core behaviour).
- `assumeValid=true, skipScripts=false` — fast path triggered (skips
  maturity/BIP-68/sigops/etc.), `skipScripts=false` is dead because
  the fast path never reaches the script-verification block.
- `assumeValid=true, skipScripts=true` — same as above.
- `assumeValid=false, skipScripts=false` — full validation including
  scripts. Fine.

The third case is the canonical one for mainnet IBD below the
assume-valid height. The second case is unreachable but the **first
is the only one that's actually safe** — and you only get it when
`params.assumeValidHeight=0` (which is hotbuns's regtest config). On
mainnet IBD below 938,343 you get case 3/4 = the unsafe one.

Furthermore: `chain/state.ts:344-354` (the generateblock / reorganize /
dumptxoutset entry) passes `assumeValid: false, skipScripts: false` —
always full validation. So the policy decision is bifurcated between
two production paths: sync/blocks.ts uses the broken dual flag, state.ts
ignores assume-valid entirely.

**File:** `src/sync/blocks.ts:2477, 2535-2536, 2571-2572`;
`src/chain/state.ts:344-354`.
**Core ref:** `validation.cpp` ConnectBlock single `fScriptChecks` flag.
**Impact:** "two-pipeline guard" pattern, 16th distinct fleet instance.
Documentary AND functional divergence; chain/state.ts is the canonical
gate (always-verify) but sync/blocks.ts (IBD) uses the unsafe fast
path BUG-13 enables.

---

## BUG-15 (P1) — `addTransaction` returns `{ error: string }` — no structured TxValidationResult; p2p layer cannot ban-vs-drop differentiate

**Severity:** P1. Bitcoin Core's `MempoolAcceptResult::Failure` carries
a `TxValidationState` whose `result` enum is one of TX_CONSENSUS,
TX_NOT_STANDARD, TX_MEMPOOL_POLICY, TX_MISSING_INPUTS,
TX_PREMATURE_SPEND, TX_CONFLICT, TX_WITNESS_STRIPPED, etc. The p2p
layer uses this to decide:
- TX_CONSENSUS → ban peer (it sent a definitively-bad tx);
- TX_NOT_STANDARD / TX_MEMPOOL_POLICY → silent drop (peer is honest
  but tx is below policy threshold);
- TX_MISSING_INPUTS → orphan pool;
- TX_WITNESS_STRIPPED → suppress recent-rejects to allow witnessed
  retransmit (BUG-9).

hotbuns's `addTransaction` returns `{ accepted: boolean; error?: string }`
with the rejection reason embedded as a free-form string. `cli.ts:1770`
recovers TX_MISSING_INPUTS via `startsWith("bad-txns-inputs-missingorspent")
|| startsWith("Missing input:")` — a string-prefix sniff. Everything
else is treated as a silent drop. There is NO ban-the-peer codepath.

Concretely: a peer that sends a tx with a forged signature (Core would
classify as TX_CONSENSUS, ban score +100) gets the same treatment as a
peer that sends a 0.05-sat/vB tx (TX_NOT_STANDARD, no ban).

**File:** `src/mempool/mempool.ts` (return type of addTransaction);
`src/cli/cli.ts:1770-1780, 1874-1887`; `src/validation/errors.ts`
(no TxValidationResult enum).
**Core ref:** `validation.cpp` `TxValidationResult`,
`TxValidationState`, `MempoolAcceptResult::Failure`.
**Impact:** loss of P2P ban-policy granularity; misbehaving peers
cannot be disconnected from tx-relay-only attacks; defensive value
of CVE-class detection is forfeited.

---

## BUG-16 (P1) — `verifyTaproot` opt arg dropped at both `coreConnectBlockChecks` call sites; relies on default fallback

**Severity:** P1. `coreConnectBlockChecks` accepts an `opts.verifyTaproot`
boolean (`connect_block.ts:171-172`). The default at line 256 is
`height >= params.taprootHeight`. All three production call sites
omit `verifyTaproot`:
- `sync/blocks.ts:2576-2577`: passes `verifyP2SH` and `verifyWitness`
  but not `verifyTaproot`. Default fires.
- `sync/blocks.ts:2192-2193` (reorg intermediate): same.
- `chain/state.ts:350-351` (generateblock / reorganize): same.

This is "asymmetric defensive depth" — verifyP2SH and verifyWitness
both gated explicitly at the call site (`height >= params.bip16Height`,
`height >= params.segwitHeight`) but Taproot relies on the helper's
default. Two effects:
1. **Documentary**: someone reading sync/blocks.ts thinks Taproot is
   gated by `params.taprootHeight` but the gating is actually in
   connect_block.ts. Audit-resistance gap.
2. **Functional**: if any caller in the future passes
   `verifyTaproot: undefined` deliberately, the default fires and
   Taproot is always-on regardless of caller intent.

Also: `sync/blocks.ts:2477` derives `assumeValid` from `assumeValidHeight`
ONLY; if a future caller wanted to force-disable Taproot enforcement
(e.g. for a chain split test), there's no override surface.

**File:** `src/sync/blocks.ts:2192-2193, 2576-2577`;
`src/chain/state.ts:350-351`; `src/consensus/connect_block.ts:256`.
**Core ref:** `validation.cpp` GetBlockScriptFlags — explicit per-flag
derivation; no "default-from-height" silent fallback.
**Impact:** latent — works correctly today, but every future
flag-derivation reviewer must trace back to the helper to confirm
behaviour. Two-pipeline-guard 17th distinct fleet instance.

---

## BUG-17 (P1) — `scriptFlagsFromBitmask` derives DERSIG / CLTV / CSV / NULLDUMMY from `verifyWitness` (W144 BUG-3 carry-forward, STILL UNFIXED)

**Severity:** P1. `interpreter.ts:3053-3072` `scriptFlagsFromBitmask`:

```ts
export function scriptFlagsFromBitmask(bitmask: number): ScriptFlags {
  const verifyP2SH    = (bitmask & (1 << 0)) !== 0;
  const verifyWitness = (bitmask & (1 << 1)) !== 0;
  const verifyTaproot = (bitmask & (1 << 9)) !== 0;
  return {
    verifyP2SH, verifyWitness, verifyTaproot,
    // When SegWit (BIP-141) is active the accompanying consensus flags are also active.
    verifyDERSignatures:       verifyWitness,  // BIP-66, active since SegWit era
    verifyCheckLockTimeVerify: verifyWitness,  // BIP-65
    verifyCheckSequenceVerify: verifyWitness,  // BIP-112
    verifyNullDummy:           verifyWitness,  // BIP-147
    ...
  };
}
```

Comment claims "When SegWit (BIP-141) is active the accompanying
consensus flags are also active" — but the deployment order is BIP-66
(363,725) < BIP-65 (388,381) < BIP-112 (419,328) < BIP-147 = BIP-141
(481,824). At heights `363,725..481,823` (118,099 blocks on mainnet) —
**DERSIG should be active but Witness is not yet**. Under this
derivation, scripts at those heights would be validated WITHOUT
DERSIG → a non-DER-encoded signature would pass hotbuns's interpreter
but fail Core's. Chain-split candidate.

Similarly for CLTV (388,381..481,823) and CSV (419,328..481,823).

The caller (`connect_block.ts:574-577`) builds the bitmask as:

```ts
const scriptFlags =
  (verifyP2SH    ? ScriptFlags.VERIFY_P2SH    : ScriptFlags.VERIFY_NONE) |
  (verifyWitness ? ScriptFlags.VERIFY_WITNESS  : ScriptFlags.VERIFY_NONE) |
  (verifyTaproot ? ScriptFlags.VERIFY_TAPROOT  : ScriptFlags.VERIFY_NONE);
```

— so neither caller nor callee respects the BIP-66/65/112/147
intermediate activation heights. From-genesis mainnet IBD with
scripts-enabled would silently accept blocks at 363,725..481,823 that
violate BIP-66 / BIP-65 / BIP-112.

This was catalogued as W144 BUG-3; comments at line 3044-3046 even
reference "BUG-11/BUG-30 fix" but the fix only addressed Taproot/P2SH,
NOT the BIP-66/65/112/147 gating problem the comment acknowledges.
Comment-as-confession 9th instance.

**File:** `src/script/interpreter.ts:3053-3072`;
`src/consensus/connect_block.ts:574-577`.
**Core ref:** `validation.cpp::GetBlockScriptFlags` — each BIP gated by
its own activation height, not piggybacked onto SegWit.
**Impact:** mainnet 118,099-block IBD divergence at heights
363,725..481,823 (3-month chain segment). Latent for assume-valid users
(skips scripts up to 938,343), exposed for `-assumevalid=0` users.

---

## BUG-18 (P1) — Mempool config inherits from network params spread silently; W149 BUG-17+19 carry-forward

**Severity:** P1. `consensus/params.ts:718-768` (TESTNET) and 948-990
(SIGNET) both use `...MAINNET` spread without overriding
`assumeValidHeight` (938343), `subsidyHalvingInterval` (210_000), and
the policy/mempool-relevant fields that are not explicitly listed.

Specific divergences:

- **TESTNET3 `assumeValidHeight`**: inherits 938343 from MAINNET, BUT
  `assumedValid: "0000000002368b1e4ee27e2e85676ae6f9f9e69579b29093e9a82c170bf7cf8a"`
  is testnet3's block 123613 hash. The two fields disagree by network.
  In `sync/blocks.ts:2477` the derivation
  `assumeValidHeight > 0 && height <= assumeValidHeight` uses MAINNET's
  938343 — so testnet3 would treat blocks up to 938,343 as assume-valid
  even though testnet3 only ever reached ~5M blocks via the assume-valid
  HASH at block 123,613 (which itself fails the `getBlockByHash` check
  for the testnet3 chain). Latent dead-data; surfaces if `params.assumedValid`
  resolution becomes more permissive.

- **SIGNET `assumeValidHeight`**: inherits 938343 from MAINNET, with
  signet `assumedValid` set to block 293,175 hash. Same divergence
  shape.

- **TESTNET4 `assumeValidHeight`**: explicit override at line 862
  (123613) but `subsidyHalvingInterval` inherits MAINNET 210_000 —
  Core testnet4 actually uses 210_000 so this is OK (matches), but
  the inheritance happens silently.

This is the W149 BUG-17+19 "inherit-via-spread silent dead-field"
fleet pattern carry-forward, STILL UNFIXED.

**File:** `src/consensus/params.ts:718-768, 948-990`.
**Core ref:** `kernel/chainparams.cpp` — per-network explicit
construction; no shared base class spread.
**Impact:** `assumeValidHeight` derivation for testnet3/signet is
NOT what an operator would expect from reading the per-network
definition. Surfaces as confusing IBD behaviour: testnet3 wouldn't
exit IBD until block 938,343 wall-clock-age (which is never reached on
testnet3).

---

## BUG-19 (P1) — `chain/state.ts::connectBlock` skips `validateBlock` (CheckBlock analog) entirely

**Severity:** P1. `sync/blocks.ts:2466` calls `validateBlock` before
`coreConnectBlockChecks`, so the structural checks (merkle root,
witness commitment, BIP-34 height-in-coinbase, block weight, every
tx's CheckTransaction) all fire for the IBD path.

`chain/state.ts:344` calls `coreConnectBlockChecks` directly WITHOUT
calling `validateBlock` first. The three callers (per the doc comment
at line 279-282): generateblock (regtest mining), dumptxoutset rollback
re-apply, reorganize.

For generateblock:
- The block was constructed in-memory from a known-good template, so
  merkle root SHOULD be valid (computed at line 5573 of server.ts) —
  but a bug in template builder + skipping CheckBlock leaves no
  defense-in-depth.
- More concerning: a malicious wallet user calling `generateblock` with
  a hand-crafted block (the RPC takes a tx-list, not a block) could
  trigger structural bugs that CheckBlock would catch but `coreConnectBlockChecks`
  doesn't (witness commitment mismatch, missing BIP-34 height encoding).

For reorganize: the alternative-chain block was previously stored, so
trust depends on the storage layer — but the same defense-in-depth
argument applies.

For dumptxoutset rollback: similar; trust depends on disk integrity.

**File:** `src/chain/state.ts:286-380`; `src/sync/blocks.ts:2466`.
**Core ref:** `validation.cpp` `CheckBlock` is invoked at every
ConnectBlock entry (the helper signature requires it).
**Impact:** "Multi-pipeline bypass" / "Reorg-skips-CheckBlock" pattern,
hotbuns 4th distinct instance (after the W143 lunarblock/camlcoin/
nimrod/ouroboros findings). Latent: depends on caller invariant that
the block is "pre-validated", which holds for the generateblock
template case but not for the malicious-RPC case.

---

## BUG-20 (P1) — `loadMempool` decodes but DROPS `mapDeltas` (PrioritiseTransaction); dead-data plumbing

**Severity:** P1. `persist.ts:336-385` `loadMempool` decodes the
mempool.dat file format including the `mapDeltas` (PrioritiseTransaction
fee modifiers) and the unbroadcast txid set. Per Core's mempool.dat v2
format (line 17-23 of persist.ts), these are first-class fields.

Then at line 380-382:

```ts
result.unbroadcast = decoded.unbroadcast.size;
// Touch mapDeltas reference so an unused-var lint doesn't fire on
// future strict configs; the data is intentionally dropped today.
void decoded.mapDeltas;
```

— `mapDeltas` is `void`-discarded. There is no
`mempool.prioritiseTransaction(txid, delta)` setter to push the
priority deltas into. The persist.ts comment acknowledges the gap
("hotbuns does not yet expose PrioritiseTransaction or an unbroadcast
tracker"). Comment-as-confession 10th instance.

Effect: a node that round-trips through Core (Core writes mempool.dat
with mapDeltas; hotbuns loads; hotbuns later dumps) would silently
strip the priority deltas. An operator using `bitcoin-cli
prioritisetransaction` on the Core side, switching to hotbuns, would
lose all their priority overrides on first node restart.

The `unbroadcast` set IS decoded and reported (line 379), but there's
no `mempool.markUnbroadcast(txid)` setter either — only the count is
returned to the operator.

**File:** `src/mempool/persist.ts:336-385`.
**Core ref:** `node/mempool_persist.cpp` LoadMempool reads mapDeltas
and applies via `pool.PrioritiseTransaction(txid, delta)`.
**Impact:** silent data loss on dump/restore cycle; cross-impl
mempool.dat round-trip is lossy.

---

## BUG-21 (P1) — `getDustThreshold` doesn't honour `IsUnspendable()` size check; OP_RETURN-only first-byte sniff

**Severity:** P1. Core's `GetDustThreshold` (policy.cpp:43-44) returns
0 for any `IsUnspendable()` script:

```cpp
if (txout.scriptPubKey.IsUnspendable()) return 0;
```

And `IsUnspendable()` (script.h:563-566):

```cpp
return (size() > 0 && *begin() == OP_RETURN) || (size() > MAX_SCRIPT_SIZE);
```

— **TWO** conditions: starts with OP_RETURN, OR length > MAX_SCRIPT_SIZE
(10,000 bytes).

hotbuns at `mempool.ts:703-707`:

```ts
if (scriptPubKey.length > 0 && scriptPubKey[0] === 0x6a) {
  return 0n;
}
```

— only the OP_RETURN check. A script > 10,000 bytes that doesn't start
with OP_RETURN would NOT be exempted; isDust would mis-classify.
Latent: non-OP_RETURN scripts > 10,000 bytes are non-standard anyway,
but defense-in-depth gap.

Also: hotbuns hardcodes `DUST_RELAY_FEE = 3000` (line 88) so no
`-dustrelayfee` operator override (BUG-11 cross-cite).

**File:** `src/mempool/mempool.ts:703-707, 88`.
**Core ref:** `policy.cpp:43-44`; `script.h:563-566`.
**Impact:** edge-case dust mis-classification; effectively unreachable
under standardness checks but documentary divergence.

---

## BUG-22 (P1) — Orphan pool `ORPHAN_TX_EXPIRE_TIME = 300s` time-based eviction diverges from Core's modern weight-based latency-score scheme

**Severity:** P1. Comment at `orphan_pool.ts:34-50` acknowledges:
"Core's modern txorphanage uses a weight/latency-score scheme but the
historical bound is 100 announcements. We keep the simpler announcement
count here." But the time-based expire at line 72:

```ts
export const ORPHAN_TX_EXPIRE_TIME = 300; // seconds
```

— claims "Core PR #22503 tightened it to 300 s to reduce replay-pin
pressure" but the CURRENT Core (`node/txorphanage.h:21-23`) has
ELIMINATED the time-based expire entirely; orphans evict only on
weight-based latency score (`DEFAULT_MAX_ORPHANAGE_LATENCY_SCORE =
3000`). hotbuns is two generations behind.

Effect:
- A small orphan (< 1000 bytes) admitted at second T gets evicted at
  T+300s regardless of whether the parent later arrives. Core would
  hold it indefinitely until weight-pressure forces eviction.
- A peer attempting orphan-replay-attack must wait > 300s to retry —
  but Core has no such window so the attack works on Core indefinitely.
  hotbuns is MORE conservative here, but inconsistent with Core's
  behaviour means the cross-impl test corpus diverges.

**File:** `src/mempool/orphan_pool.ts:72`.
**Core ref:** `bitcoin-core/src/node/txorphanage.h:21-23`,
`node/txorphanage.cpp` (no time-based expire path).
**Impact:** cross-impl divergence on orphan-pool behaviour; honest
orphans get evicted before parents arrive in slow-propagation scenarios.

---

## BUG-23 (P1) — `feeEstimator.trackTransaction` only called on `tx` message path; mempool-internal admissions ignored

**Severity:** P1. `cli.ts:1872`:

```ts
feeEstimator.trackTransaction(txid, chainState.getBestBlock().height);
```

is called ONLY in the `peerManager.onMessage("tx", …)` handler when a
p2p tx is admitted. The other admission paths:
- `sendrawtransaction` RPC at `rpc/server.ts:3277` calls
  `mempool.addTransaction` — no `feeEstimator.trackTransaction` call.
- `submitpackage` RPC paths.
- `reorgRefillUnchecked` for disconnected txs.
- `processOrphanCascade` (some calls at cli.ts:1905) — child cascade
  appears to track at cli.ts:1909 but parent admission via the
  orphan-cascade-from-block path may miss.

Effect: fee estimation observes a SUBSET of admissions. The estimator
under-samples and reports stale buckets. Core's `processTransaction`
fires from inside `MemPoolAccept::Finalize`, not the caller — so EVERY
admission is tracked.

**File:** `src/cli/cli.ts:1872`; `src/rpc/server.ts:3277`.
**Core ref:** `policy/fees.cpp` `CBlockPolicyEstimator::processTransaction`
called from `txmempool.cpp::addNewTransaction`.
**Impact:** fee estimator confidence intervals incorrect; underestimates
mempool activity from RPC-driven and reorg-driven admissions.

---

## BUG-24 (P1) — `dump_state` (`reorgRefillUnchecked`) entry creates entries with `dependsOn: new Set()` ignoring intra-mempool ancestry

**Severity:** P1. Cross-cite BUG-10. The "unchecked refill" path creates
entries with `dependsOn: new Set<string>()` (line 2577) — declares the
disconnected tx has no parents. But on a reorg the disconnected block's
transactions DO have parents (other disconnected txs in the same block,
or pre-existing mempool entries that are now their parents).

Effect: the cluster mempool's ancestor/descendant accounting becomes
WRONG immediately after a reorg-refill. The cluster's linearization is
miscalculated. Subsequent RBF on those entries uses incorrect ancestor
sets. Subsequent `evict` (TrimToSize) uses incorrect chunk fee rates.
Mining template extracts pseudo-disjoint clusters that aren't disjoint.

The comment at line 2577 explicitly says "unchecked path: no parent
tracking" — comment-as-confession 11th instance.

**File:** `src/mempool/mempool.ts:2546-2603`.
**Core ref:** `txmempool.cpp` `addUnchecked` always sets parent/child
indices via `UpdateParentsOf`.
**Impact:** post-reorg mempool indices wrong; cluster mempool corruption
until the next addTransaction (which won't fix existing entries).

---

## Summary

**Bug count:** 24 (15 distinct + 9 carry-forwards / wire-divergence).

**P0-CDIV class:** 5 (BUG-4, BUG-7, BUG-10, BUG-11, BUG-13).
**P0-CONS class:** 0 (closest are BUG-7, BUG-10, BUG-13 — chain-split
on assume-valid scope creep + script_flag_exceptions absent + reorg
refill CVE-2018-17144 primitive).
**P1 class:** 19.

**Top findings:**

1. **BUG-13 (P0-CDIV) "Assume-valid scope creep" — W145 BUG-2..6
   carry-forward STILL UNFIXED**. The `coreConnectBlockChecks.assumeValid`
   branch (connect_block.ts:416-480) skips coinbase maturity, BIP-68,
   sigops counting, per-input MoneyRange, and per-tx fee accumulation.
   Core's `fScriptChecks` flag gates ONLY signature verification.
   hotbuns is the named ORIGIN of this fleet-wide pattern — it remains
   the worst instance of it. Combined with BUG-19 (chain/state.ts skips
   validateBlock for generateblock / reorganize), a from-genesis IBD
   below assume-valid height accepts blocks Core would reject for
   sigops > 80k, coinbase-spend at depth < 100, MoneyRange violations,
   negative-fee txs, or CVE-2018-17144 duplicate inputs.

2. **BUG-7 + BUG-17 (P0-CDIV) — `script_flag_exceptions` table absent
   + scriptFlagsFromBitmask derives DERSIG/CLTV/CSV/NULLDUMMY from
   `verifyWitness`** — both W144 BUG-3 family carry-forwards STILL
   UNFIXED. Combined: from-genesis mainnet IBD with scripts-enabled
   hard-fails at h=174,062 (BIP-16 grandfather) AND silently accepts
   118,099 blocks at heights 363,725..481,823 that violate
   BIP-66/65/112/147 signature/lock rules. Mitigated in production by
   the (broken-per-BUG-13) assume-valid skip, exposed for
   `-assumevalid=0` operators.

3. **BUG-10 (P0-CDIV) "reorg-refill unchecked admission" — CVE-2018-17144
   primitive on reorg**. `reorgRefillUnchecked` admits disconnected
   transactions to the mempool WITHOUT running `validateTxBasic`
   (CheckTransaction), WITHOUT script verification, WITHOUT conflict
   check, WITHOUT MoneyRange, and with `fee = 0n` sentinel. Inflation +
   double-spend gateway. Comment-as-confession explicitly admits the
   path is unsafe by Core standards.

**Three additional fleet-pattern instances confirmed:**

- BUG-11 — operator cannot configure 12+ standard Core knobs;
  `-minrelaytxfee`, `-incrementalrelayfee`, `-maxmempool`,
  `-mempoolexpiry`, `-mempoolfullrbf`, `-acceptnonstdtxn`,
  `-permitbaremultisig`, `-datacarrier`, `-datacarriersize`,
  `-bytespersigop`, `-dustrelayfee`, `-limitancestorcount`,
  `-limitdescendantcount` — all hardcoded. Operator parity gap.

- BUG-14 + BUG-16 — Two-pipeline assume-valid decision; verifyTaproot
  arg dropped (relies on helper default). 17th distinct two-pipeline
  guard fleet instance.

- BUG-18 — `params.ts` inherit-via-spread silent dead-field pattern;
  TESTNET3 + SIGNET inherit MAINNET's `assumeValidHeight=938343` while
  setting their own per-network `assumedValid` hash. W149 BUG-17+19
  carry-forward STILL UNFIXED.

**Carry-forward catches** (4):
- BUG-13: W145 BUG-2..6 "Assume-valid scope creep" — hotbuns ORIGIN —
  STILL UNFIXED.
- BUG-17: W144 BUG-3 `scriptFlagsFromBitmask` wrong-source — STILL
  UNFIXED.
- BUG-18: W149 BUG-17+19 inherit-via-spread silent dead-field — STILL
  UNFIXED.
- BUG-7: W144 fleet-wide `script_flag_exceptions` absent — STILL
  UNFIXED.

**Comment-as-confession instances (continues fleet pattern):**
- BUG-10 (reorgRefillUnchecked at line 2528): "This unchecked admission
  is policy-correct…" — but the preceding paragraph admits the prereq
  fails.
- BUG-17 (interpreter.ts:3044-3046): "BUG-11/BUG-30 fix" comment but
  the fix doesn't address BIP-66/65/112/147 gating.
- BUG-20 (persist.ts:376-378): "hotbuns does not yet expose
  PrioritiseTransaction" — admits the dead-data plumbing.
- BUG-22 (orphan_pool.ts:36-39): "Core's modern txorphanage uses a
  weight/latency-score scheme but the historical bound is 100" —
  admits two generations behind.
- BUG-24 (mempool.ts:2577): "unchecked path: no parent tracking" —
  admits cluster mempool corruption.

5 comment-as-confession instances in a single audit. Cumulative across
fleet: 12+ confirmed.

**New "production pipeline bypass" instances:** BUG-19 (chain/state.ts
skips validateBlock) is the **4th hotbuns instance** of the fleet-wide
W143/W145 "Multi-pipeline bypass" pattern. Companions: hotbuns W143
BUG-4 + hotbuns W145 BUG-2..6 + this BUG-19.
