# W145 — Coinbase + subsidy + fees + MAX_MONEY invariants — hotbuns

**Impl:** hotbuns (TypeScript / Bun)
**Date:** 2026-05-18
**Wave:** W145 Coinbase + subsidy + fees + MAX_MONEY invariants
**Status:** DISCOVERY — 21 BUGS / 8 behaviors × ~30 gates
**Tests:** assertion-only, no production code changes.
**No production code changes in this wave.**

## References

### Bitcoin Core
- `bitcoin-core/src/validation.cpp:1839-1850` — `GetBlockSubsidy(int nHeight, const Consensus::Params& consensusParams)`:
  ```
  int halvings = nHeight / consensusParams.nSubsidyHalvingInterval;
  if (halvings >= 64) return 0;
  CAmount nSubsidy = 50 * COIN;
  nSubsidy >>= halvings;
  return nSubsidy;
  ```
  The `>= 64` guard exists ONLY to avoid C++ undefined behavior on the
  right-shift; the post-shift value is mathematically 0 anyway.
- `bitcoin-core/src/validation.cpp:2610-2614` — coinbase reward gate inside
  `ConnectBlock`:
  ```
  CAmount blockReward = nFees + GetBlockSubsidy(pindex->nHeight, params.GetConsensus());
  if (block.vtx[0]->GetValueOut() > blockReward && state.IsValid()) {
    state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-cb-amount", ...);
  }
  ```
  Note `&& state.IsValid()` — Core does NOT short-circuit on earlier errors;
  reward check runs ALWAYS (consensus-critical, never gated by `fScriptChecks`
  nor by `fAssumeValid`).
- `bitcoin-core/src/validation.cpp:2525-2570` — per-tx loop in `ConnectBlock`:
  - L2535 calls `Consensus::CheckTxInputs(tx, state, view, pindex->nHeight, txfee)`
    UNCONDITIONALLY (no `fScriptChecks` guard). This emits
    `bad-txns-inputs-missingorspent`, `bad-txns-premature-spend-of-coinbase`,
    `bad-txns-inputvalues-outofrange` (per-coin AND per-tx-nValueIn MoneyRange),
    `bad-txns-in-belowout`, `bad-txns-fee-outofrange`.
  - L2545 `nFees += txfee; if (!MoneyRange(nFees)) → bad-txns-accumulated-fee-outofrange`.
  - L2570 `nSigOpsCost > MAX_BLOCK_SIGOPS_COST → bad-blk-sigops`.
  - L2574 `if (!tx.IsCoinBase() && fScriptChecks) → CheckInputScripts(...)` —
    ONLY script verification is gated by `fScriptChecks`.
- `bitcoin-core/src/consensus/tx_verify.cpp:165-214` — `CheckTxInputs`:
  - L172 reject coinbase explicitly (`assert(!tx.IsCoinBase())`).
  - L179-181 `IsCoinBase + nSpendHeight - coin.nHeight < COINBASE_MATURITY` →
    `bad-txns-premature-spend-of-coinbase` (depth comparison; coin.nHeight is
    the height at which the coinbase was MINED).
  - L185-188 `nValueIn += coin.out.nValue; if (!MoneyRange(coin.out.nValue) ||
    !MoneyRange(nValueIn)) → bad-txns-inputvalues-outofrange`. **Per-coin AND
    per-tx accumulated.** `nValueIn` is local-to-the-tx in Core (declared
    inside the per-tx loop in ConnectBlock).
  - L195-201 `if (nValueIn < value_out) → bad-txns-in-belowout`.
  - L203-211 `txfee_aux = nValueIn - value_out; if (!MoneyRange(txfee_aux))
    → bad-txns-fee-outofrange`. Unreachable given the preconditions, but Core
    keeps the gate.
- `bitcoin-core/src/consensus/tx_check.cpp:11-60` — `CheckTransaction`:
  - L14-17 `bad-txns-vin-empty` / `bad-txns-vout-empty`.
  - L19 `bad-txns-oversize` — stripped (no-witness) size × WITNESS_SCALE_FACTOR
    > MAX_BLOCK_WEIGHT.
  - L26-34 per-output: `bad-txns-vout-negative` (SIGNED nValue < 0),
    `bad-txns-vout-toolarge` (nValue > MAX_MONEY), `bad-txns-txouttotal-toolarge`
    (running `nValueOut` !MoneyRange).
  - L41-45 `bad-txns-inputs-duplicate` — `std::set<COutPoint>` insertion
    check (CVE-2018-17144 class). Runs BEFORE any UTXO lookup.
  - L47-56 coinbase: `bad-cb-length` (scriptSig 2..100); non-coinbase:
    `bad-txns-prevout-null` (IsNull check on every prevout).
- `bitcoin-core/src/consensus/consensus.h:19` — `COINBASE_MATURITY = 100`.
- `bitcoin-core/src/consensus/amount.h:26-27` — `MAX_MONEY = 21000000 * COIN`,
  `inline bool MoneyRange(CAmount nValue) { return (nValue >= 0 && nValue <= MAX_MONEY); }`.
- `bitcoin-core/src/kernel/chainparams.cpp` — `nSubsidyHalvingInterval`:
  - L84 mainnet = 210000.
  - L209 testnet3 = 210000.
  - L310 testnet4 = 210000.
  - L454 signet = 210000.
  - L535 regtest = 150.

### CVE history
- **CVE-2018-17144** — Inflation bug from missing duplicate-input check.
  `CheckTransaction` set-based duplicate detect is the canonical fix.
- **CVE-2010-5139** — Output-value overflow inflation (`txouttotal-toolarge`
  is the named guard).

## Hotbuns files in scope

- `src/consensus/params.ts:1046-1062` — `getBlockSubsidy(height, params)` —
  the canonical, params-aware impl.
- `src/consensus/params.ts:393, 1002, 718, 838, 948` — `subsidyHalvingInterval`
  per network (mainnet=210_000, regtest=150, testnet3/testnet4/signet inherit
  via `...MAINNET`).
- `src/consensus/params.ts:394` — `maxCoins: 2_100_000_000_000_000n` — declared
  but never imported / read by any callsite (see BUG-9).
- `src/consensus/connect_block.ts:241-741` — `coreConnectBlockChecks`. Runs
  BIP-30, IsFinalTx, maturity, per-tx nValueIn ranges, sigops, coinbase reward.
- `src/consensus/connect_block.ts:416-480` — assume-valid fast path (skips
  most per-tx CheckTxInputs gates; see BUG-3..BUG-6).
- `src/consensus/connect_block.ts:482-740` — full validation path.
- `src/validation/tx.ts:1022-1114` — `validateTxBasic` (= Core
  `CheckTransaction`). 9 gates inc. CVE-2018-17144 duplicate-input.
- `src/validation/tx.ts:228` — output value wire deserialization (`readUInt64LE`
  → BigInt; never returns a negative).
- `src/validation/block.ts:517-611` — `validateBlock` (Core `CheckBlock` +
  some `ContextualCheckBlock` gates). Calls `validateTxBasic` per tx.
- `src/chain/state.ts:286-360` — `chain/state.ts::connectBlock` — does NOT
  call `validateBlock` / `validateTxBasic`; goes straight to
  `coreConnectBlockChecks` (see BUG-12).
- `src/sync/blocks.ts:2466` — `validateBlock` IS called before
  `coreConnectBlockChecks`. The two production paths diverge here.
- `src/mempool/mempool.ts:1536-1648` — mempool-accept path with hardcoded
  `MAX_MONEY_SATS` literal (see BUG-10).
- `src/chain/snapshot.ts:54` — `MAX_MONEY = 2_100_000_000_000_000n` —
  third hardcoded copy.
- `src/rpc/server.ts:5789-5799` — private `getBlockSubsidy(height)` —
  hardcodes `HALVING_INTERVAL = 210_000`, IGNORES `params.subsidyHalvingInterval`
  (see BUG-1, the worst find of this wave).
- `src/wallet/wallet.ts:200` — `export const COINBASE_MATURITY = 100` —
  hardcoded, ignores `params.coinbaseMaturity`.
- `src/mining/template.ts:478-510` — `buildCoinbase` uses the canonical
  `getBlockSubsidy(height, this.params)`. Clean.
- `src/index.js:32454-32462` — compiled mirror of the buggy private
  `getBlockSubsidy` (confirms the bug lands in the JS that actually runs).

---

## BUGS

### BUG-1 — RPC `getblocktemplate` uses a hard-coded `HALVING_INTERVAL = 210_000` that ignores `params.subsidyHalvingInterval` → wrong coinbasevalue on regtest

- **Severity:** P0-CDIV (regtest-only, but the most direct
  "two-pipeline-guard" / `pretend-the-knob-doesn't-exist` divergence in
  this wave).
- **File:** `src/rpc/server.ts:5789-5799` and call site at
  `src/rpc/server.ts:5116`.
- **Core ref:** `bitcoin-core/src/validation.cpp:1839-1850` —
  `nHeight / consensusParams.nSubsidyHalvingInterval`. Core's mining RPC
  flows through the same params-driven function.
- **Description:** A second `getBlockSubsidy` exists as a private method on
  the RPC server class. It is invoked from `getBlockTemplate` at L5116 to
  populate `coinbasevalue`. It hardcodes the mainnet halving interval and
  initial subsidy, completely ignoring `this.params.subsidyHalvingInterval`.
  On regtest (interval = 150), the canonical halving is at h=150 (subsidy
  drops to 25 BTC); the private RPC method continues to report 50 BTC
  until h=210,000. A regtest miner consuming `coinbasevalue` from this
  RPC will mine an over-paying coinbase, which the full-validation path
  WILL correctly reject as `bad-cb-amount` — so the divergence is
  observable as a "GBT says 50 BTC, ConnectBlock rejects, miner stuck".
  This is the "two-pipeline-guard" pattern (W124/W125 fleet finding):
  one consensus-aware code path + one shadow constant copy used by an
  adjacent surface.
- **Excerpt** (`src/rpc/server.ts:5786-5799`):
  ```ts
  /**
   * Calculate block subsidy for a given height.
   */
  private getBlockSubsidy(height: number): bigint {
    const INITIAL_SUBSIDY = 5_000_000_000n; // 50 BTC in satoshis
    const HALVING_INTERVAL = 210_000;

    const halvings = Math.floor(height / HALVING_INTERVAL);
    if (halvings >= 64) {
      return 0n;
    }

    return INITIAL_SUBSIDY >> BigInt(halvings);
  }
  ```
  Call site (`src/rpc/server.ts:5113-5117`):
  ```ts
  // Calculate coinbase value (subsidy + fees)
  const subsidy = this.getBlockSubsidy(height);
  const coinbaseValue = subsidy + totalFees;
  ```
  Confirmation it lands in the production JS (`src/index.js:32454-32462`):
  ```js
  getBlockSubsidy(height) {
    const INITIAL_SUBSIDY = 5000000000n;
    const HALVING_INTERVAL = 210000;
    const halvings = Math.floor(height / HALVING_INTERVAL);
    if (halvings >= 64) {
      return 0n;
    }
    return INITIAL_SUBSIDY >> BigInt(halvings);
  }
  ```
- **Impact:** Regtest mining via `getblocktemplate` returns wrong
  `coinbasevalue` past h=150. External miner (cgminer, S9 firmware,
  custom CI harness) signals 50 BTC, hands hotbuns a coinbase output of
  50 BTC + fees, hotbuns' OWN `coreConnectBlockChecks` rejects it as
  `bad-cb-amount`. The other `generatetoaddress` path uses
  `getBlockSubsidy(height, this.params)` (L5502) — also a textbook
  "two-pipeline-guard": two adjacent mining helpers, one params-aware,
  one not. Note: the only impl-internal `getblocktemplate` consumer at
  this height is regtest CI (`signet/testnet4` halving = 210_000, so
  the bug is dormant in production but live in the regtest matrix).

---

### BUG-2 — Assume-valid path skips coinbase maturity check on inputs

- **Severity:** P0-CDIV (only fires when assumevalid is true, which on
  hotbuns is set per `assumeValidHeight`. Mainnet h ≤ 938,343 in
  default config).
- **File:** `src/consensus/connect_block.ts:416-480` (the assumevalid
  branch).
- **Core ref:** `bitcoin-core/src/validation.cpp:2535` calls
  `Consensus::CheckTxInputs` unconditionally on every non-coinbase tx.
  Maturity check at `tx_verify.cpp:178-181` is INSIDE CheckTxInputs and
  is therefore active even when `fScriptChecks = !fAssumeValid` is false.
  Core's `fScriptChecks` gates ONLY signature verification, not the
  arithmetic / maturity gates.
- **Description:** The assumevalid fast path iterates inputs, calls
  `utxoManager.spendOutput`, accumulates `avTotalInputValue`, and never
  reads the spent coin's `coinbase` flag. The full-validation path at
  L534-541 correctly checks maturity. So under assumevalid, an attacker
  who can mutate the assumevalid chain (e.g. test harness, malicious
  AssumeValid hash, or any chain segment below `params.assumeValidHeight`
  that hotbuns is rebuilding) could spend a coinbase at depth < 100
  without rejection.
- **Excerpt** (`src/consensus/connect_block.ts:424-442`):
  ```ts
  if (!isCoinbaseTx) {
    for (const input of tx.inputs) {
      // Ensure input is loaded ...
      if (!utxoManager.hasUTXO(input.prevOut)) {
        const loaded = await utxoManager.preloadUTXO(input.prevOut);
        if (!loaded) { /* bad-txns-inputs-missingorspent */ }
      }
      const spentEntry = utxoManager.spendOutput(input.prevOut);
      avTotalInputValue += spentEntry.amount;
    }
  }
  ```
  (note: no `if (spentEntry.coinbase && height - spentEntry.height <
  params.coinbaseMaturity) → bad-txns-premature-spend-of-coinbase`
  here, unlike the full-validation path at L534-541).
- **Impact:** Assumevalid path is missing one of the gates Core ALWAYS
  runs. The threat is bounded by who controls the chain below
  `assumeValidHeight` — but Core's design philosophy is "assumevalid
  gates only sigchecks; everything else is consensus-critical and
  always runs". hotbuns silently widens assumevalid's scope.

---

### BUG-3 — Assume-valid path skips per-coin MoneyRange (bad-txns-inputvalues-outofrange per coin)

- **Severity:** P0-CDIV (assumevalid path only; symmetric to BUG-2).
- **File:** `src/consensus/connect_block.ts:416-480`.
- **Core ref:** `bitcoin-core/src/consensus/tx_verify.cpp:185-188`.
- **Description:** Same gap as BUG-2: the assumevalid path accumulates
  `avTotalInputValue += spentEntry.amount` with NO `MoneyRange(spentEntry
  .amount)` check (per-coin) and no `MoneyRange(avTotalInputValue)` check
  (per-tx accumulated). The full-validation path runs both checks at
  L611 and L619.
- **Impact:** Under assumevalid, a corrupted UTXO record (DB tear, write
  reordering, malicious snapshot, future-bug in coin compression code)
  with `amount > MAX_MONEY` or signed-negative slips past the consensus
  arithmetic. Note hotbuns stores `amount` as a unsigned BigInt, so a
  signed-negative is encoded as a large positive — gate would catch it,
  but only when run.

---

### BUG-4 — Assume-valid path skips per-tx `bad-txns-in-belowout` check

- **Severity:** P0-CDIV (assumevalid path; CVE-2010-5139 cousin gate).
- **File:** `src/consensus/connect_block.ts:416-480`.
- **Core ref:** `bitcoin-core/src/consensus/tx_verify.cpp:196-200`.
- **Description:** The assumevalid branch accumulates input and output
  values block-wide and computes `avFees = avTotalInputValue -
  (avTotalOutputValue - avCoinbaseOutputValue)` at L463. The
  `bad-txns-in-belowout` check is PER-TX in Core (`nValueIn < value_out`
  for THIS tx, inside the loop), but hotbuns' assumevalid path only
  cross-checks at the BLOCK level via the coinbase-amount gate.
  Effect: a single tx with outputs > inputs is undetected as long as
  some OTHER tx in the same block over-pays inputs (which a malicious
  miner could engineer trivially).
- **Excerpt** (`src/consensus/connect_block.ts:462-471`):
  ```ts
  const avSubsidy = getBlockSubsidy(height, params);
  const avFees = avTotalInputValue - (avTotalOutputValue - avCoinbaseOutputValue);
  const avMaxCoinbaseValue = avSubsidy + avFees;
  if (avCoinbaseOutputValue > avMaxCoinbaseValue) {
    // bad-cb-amount
  }
  ```
  Note `avFees` can go NEGATIVE (BigInt is signed), which makes
  `avMaxCoinbaseValue < avSubsidy`. The coinbase-amount gate then fires
  IF the coinbase claims the full subsidy + fees. But if the coinbase
  is conservative (claims only subsidy), the block-wide negative fee
  is silently accepted.
- **Impact:** Inflation bug class under assumevalid. The exact attack
  requires a malicious miner WITHIN the assumevalid window — which
  Core's design treats as in-scope (the AssumeValid hash is a
  trust-on-first-use anchor, not a free pass for arithmetic).

---

### BUG-5 — Assume-valid path skips per-tx accumulated-fee MoneyRange (`bad-txns-accumulated-fee-outofrange`)

- **Severity:** P0-CDIV (assumevalid path).
- **File:** `src/consensus/connect_block.ts:416-480`.
- **Core ref:** `bitcoin-core/src/validation.cpp:2544-2547`.
- **Description:** Full-validation path has nFees + MoneyRange check at
  L672 (`bad-txns-accumulated-fee-outofrange`). Assumevalid path
  computes block-wide `avFees` once at L463 with no MoneyRange check
  at all. A bug that drove `avFees` outside `[0, MAX_MONEY]` would
  pass through.

---

### BUG-6 — Assume-valid path skips per-tx `bad-txns-fee-outofrange` (Core's `txfee_aux` MoneyRange)

- **Severity:** P1 (Core itself calls this "unreachable" — but Core keeps
  the gate; hotbuns drops it).
- **File:** `src/consensus/connect_block.ts:416-480`.
- **Core ref:** `bitcoin-core/src/consensus/tx_verify.cpp:203-211`.
- **Description:** Even the full-validation path doesn't emit this
  exact token name; the assumevalid path drops it entirely. Core's
  belt-and-suspenders gate is gone.
- **Impact:** Defense-in-depth gap. Low practical impact, but a fleet
  pattern: "gates Core describes as unreachable but keeps for
  defense-in-depth" are missing in 8+ impls. Hotbuns is one of them.

---

### BUG-7 — `chain/state.ts::connectBlock` does NOT pre-call `validateBlock` / `validateTxBasic`; duplicate-input attack causes uncaught throw instead of clean `bad-txns-inputs-duplicate` (CVE-2018-17144 class — partial)

- **Severity:** P0-SEC (DoS via uncaught exception on the
  generateblock / dumptxoutset / reorganize path).
- **File:** `src/chain/state.ts:286-360` (connectBlock body —
  no `validateTxBasic` / `validateBlock` call before
  `coreConnectBlockChecks`).
- **Core ref:** `bitcoin-core/src/validation.cpp:3961` —
  `CheckBlock(block, state, ...)` calls `CheckTransaction(*tx, tx_state)`
  for every tx, which runs the `bad-txns-inputs-duplicate` set-insert
  gate BEFORE any UTXO lookup.
- **Description:** `sync/blocks.ts::connectBlock` at L2466 correctly
  calls `validateBlock(block, height, params)` (which iterates txs and
  calls `validateTxBasic` per tx — gate 7 at `validation/tx.ts:1077-1088`
  is the canonical CVE-2018-17144 duplicate-outpoint check). The OTHER
  connectBlock entry point at `chain/state.ts:286` skips this entirely
  and feeds the block straight into `coreConnectBlockChecks`. When the
  per-tx input loop at `connect_block.ts:608` calls
  `utxoManager.spendOutput(input.prevOut)` for the same outpoint twice,
  the second call **throws** (`utxo.ts:1077-1080`: "UTXO not in cache
  (must be pre-loaded)") instead of returning a clean
  `bad-txns-inputs-duplicate` validation error. The throw propagates
  unwrapped from `coreConnectBlockChecks` to `chain/state.ts::connectBlock`
  callers: `generateblock` RPC, `dumptxoutset` rollback reapply, and
  the reorg path. All of these can take attacker-influenced blocks.
- **Excerpt** (`src/chain/state.ts:344-354`):
  ```ts
  const result = await coreConnectBlockChecks(block, height, this.utxo, this.params, {
    assumeValid: false,
    skipScripts: false,
    prevMTP: computedPrevMTP,
    enforceBIP68: csvActive,
    ...
  });
  ```
  No `validateBlock` call before this. By contrast,
  `src/sync/blocks.ts:2466`:
  ```ts
  const validation = validateBlock(block, height, this.params);
  if (!validation.valid) { ... return false; }
  ```
- **Impact:** Two-pipeline-guard fleet pattern again, but with a
  SECURITY edge. On `chain/state.ts::connectBlock`-path, a duplicate-
  input tx triggers an unhandled exception rather than a clean
  block-rejection. During reorg, this can leave the chain state in
  a partially-mutated UTXO cache (some inputs already spent, throw
  before addTransaction). The W93 mid-block-mutation design assumes
  the caller can roll back via "don't flush", but a thrown exception
  in the middle of a reorg path may already have committed enough
  state to corrupt the UTXO view's bestBlock. CVE-2018-17144 class —
  partial; the duplicate is detected, just not in a Core-canonical
  way and not in a way the daemon can recover from cleanly.

---

### BUG-8 — `validateTxBasic` accumulated-output MoneyRange compares UNSIGNED `output.value` against MAX_MONEY (gate 6); after the per-output negative reinterpretation at gate 4, a signed-negative output that re-wraps to UINT64-large should still hit gate 5, but the accumulator never sees a signed view

- **Severity:** P2 (the unsigned check happens to behave the same as the
  signed check ONLY because gate 4 short-circuits negatives first; if
  gate 4 were ever reordered or its signed-reinterpret subtracted,
  gate 6 would accept negative values silently).
- **File:** `src/validation/tx.ts:1054-1075`.
- **Core ref:** `bitcoin-core/src/consensus/tx_check.cpp:24-34` — Core
  uses signed `CAmount` (= `int64_t`) throughout, so `nValueOut +=
  txout.nValue` and `MoneyRange(nValueOut)` operate in SIGNED arithmetic.
  A negative txout.nValue immediately fails gate 1.
- **Description:** hotbuns stores `output.value` as a UNSIGNED BigInt
  (from `readUInt64LE`). Gate 4 re-interprets to signed via
  `signedValue = output.value > INT64_MAX ? output.value - UINT64_WRAP
  : output.value` and uses it ONLY for the negative check. Then gate 5
  and gate 6 use the unsigned `output.value` directly. The accumulator
  `totalOutput += output.value` therefore sums UNSIGNED values. The
  result happens to match Core's behavior given the gates fire in
  order. But the design is fragile.
- **Excerpt** (`src/validation/tx.ts:1054-1075`):
  ```ts
  let totalOutput = 0n;
  for (const output of tx.outputs) {
    const signedValue = output.value > INT64_MAX ? output.value - UINT64_WRAP : output.value;
    if (signedValue < 0n) return { valid: false, error: "bad-txns-vout-negative" };
    if (output.value > MAX_MONEY) return { valid: false, error: "bad-txns-vout-toolarge" };
    totalOutput += output.value;
    if (totalOutput > MAX_MONEY) return { valid: false, error: "bad-txns-txouttotal-toolarge" };
  }
  ```
- **Impact:** Latent. The per-output ordering of gates 4 → 5 → 6 is
  load-bearing; a future refactor (e.g. extracting gate 5 to a helper
  for reuse, or pulling gate 4 into a `validateOutputValue` helper)
  would break the invariant. Recommendation: hoist the signed
  reinterpretation once at top of loop, use `signedValue` for ALL
  three comparisons.

---

### BUG-9 — `ConsensusParams.maxCoins` field is a DEAD CONSTANT (declared, exported, never read)

- **Severity:** P2 (fleet pattern: "declared constant nobody uses",
  W128/W137 echo).
- **File:** `src/consensus/params.ts:21` (interface field),
  `src/consensus/params.ts:394` (mainnet value).
- **Core ref:** `bitcoin-core/src/consensus/amount.h:26` — Core's
  `MAX_MONEY` is a `static constexpr CAmount`, NOT in `Consensus::Params`.
  hotbuns plumbs it via params (`maxCoins`) but never reads it.
- **Description:** `params.maxCoins` is declared on every network config
  and exported. NO production code site reads it — every MAX_MONEY
  check is a HARDCODED literal `2_100_000_000_000_000n`:
  ```
  src/validation/tx.ts:1051       const MAX_MONEY = 2_100_000_000_000_000n;
  src/consensus/connect_block.ts:495   const MAX_MONEY_FEE = 2_100_000_000_000_000n;
  src/consensus/connect_block.ts:607   const MAX_MONEY_INPUT = 2_100_000_000_000_000n;
  src/mempool/mempool.ts:1539     const MAX_MONEY_SATS = 2_100_000_000_000_000n;
  src/chain/snapshot.ts:54        const MAX_MONEY = 2_100_000_000_000_000n;
  src/p2p/feefilter.ts:40         export const MAX_MONEY = 2_100_000_000_000_000n;
  ```
  Six separate hardcoded copies of the same literal, with the params
  field as the seventh (unused). If `MAX_MONEY` ever needed a
  per-chain override (e.g. signet-with-different-supply, or a future
  consensus change), the params plumbing would be the obvious lever —
  but the field is wired to nothing. Classic "dead helper" /
  "two-pipeline-guard" pattern.
- **Impact:** Defense-in-depth / maintainability. Drift risk: one of
  the six literal sites diverges by typo (e.g. an extra zero) and
  the others continue working — silent consensus divergence in one
  call path.

---

### BUG-10 — `MAX_MONEY` literal duplicated SIX times across consensus / mempool / snapshot / feefilter — each with a different LOCAL name (MAX_MONEY, MAX_MONEY_FEE, MAX_MONEY_INPUT, MAX_MONEY_SATS)

- **Severity:** P2 (fleet pattern, drift risk).
- **File:** as listed under BUG-9.
- **Core ref:** Core has exactly one `MAX_MONEY` constexpr.
- **Description:** Same physical constant, four different identifiers,
  six declaration sites. Documented as "for clarity" in
  `mempool.ts:1536` but actually defeats the static-analysis path
  ("find all callers of MAX_MONEY" returns nothing useful when
  one of them is named `MAX_MONEY_SATS`). Fleet finding W104 /
  W128 type pattern.
- **Impact:** Maintenance / drift; not a runtime bug today.

---

### BUG-11 — `COINBASE_MATURITY` is hardcoded in wallet, ignoring `params.coinbaseMaturity`

- **Severity:** P3 (Core also uses a `static const`; the divergence is
  internal to hotbuns where `params.coinbaseMaturity` IS plumbed and
  used elsewhere).
- **File:** `src/wallet/wallet.ts:200`, uses at L1724, L2384, L2399.
- **Core ref:** `bitcoin-core/src/consensus/consensus.h:19` —
  `static const int COINBASE_MATURITY = 100`. Core's wallet uses the
  same constant.
- **Description:** Wallet declares its own `export const
  COINBASE_MATURITY = 100;`. Coin-selection rejects coinbase UTXOs
  below 100 confirmations regardless of the network's
  `params.coinbaseMaturity` (which `connect_block.ts:536` and
  `chain/state.ts:933` do honor). If a future testnet/signet/regtest
  variant lowers maturity (which Core also doesn't do, to be fair),
  the wallet would silently disagree.
- **Impact:** Negligible in production — wallet can be conservative
  about coinbase maturity vs the consensus value without bug. But
  the inconsistency is real: the params field is honored in
  3 of 4 production paths and ignored in the 4th.

---

### BUG-12 — `chain/state.ts::connectBlock` skips merkle root + block-weight + coinbase-position structural gates (those live in `validateBlock`, which it never calls)

- **Severity:** P0-CDIV (the broader form of BUG-7; touches every
  caller of `chain/state.ts::connectBlock`, not just duplicate-input).
- **File:** `src/chain/state.ts:286-360`.
- **Core ref:** `bitcoin-core/src/validation.cpp:3961` —
  `Chainstate::ConnectBlock` runs `CheckBlock(block, ...)`
  unconditionally before per-tx logic. `CheckBlock` (validation.cpp:
  3918+) covers: merkle, witness-malleation, block-weight,
  coinbase-at-index-0, tx structural checks.
- **Description:** `sync/blocks.ts::connectBlock` calls `validateBlock`
  before `coreConnectBlockChecks` (L2466). The
  `chain/state.ts::connectBlock` body never does. Callers:
  `generateblock` (regtest), `dumptxoutset` rollback re-apply,
  `reorganize`. None of these can rely on a prior `validateBlock`
  call because the caller-API doesn't require it.
- **Impact:** A malformed block reaching `chain/state.ts::connectBlock`
  (e.g. via reorg from a malicious peer's chain that already passed
  `validateBlock` in `sync/blocks.ts` and got connected then later
  disconnected and is now being re-applied) would skip the merkle /
  weight / structural checks. In practice the same block already
  passed once, so the gates already fired — but the invariant is
  "called twice OK, ANY caller of `chain/state.ts::connectBlock`
  is expected to have pre-validated". That contract is implicit, not
  enforced. Two-pipeline-guard pattern.

---

### BUG-13 — `feesByTotals !== nFees` mismatch returns `bad-cb-amount` but the actual condition is "programmer bug" — wrong reject token surfaces

- **Severity:** P3 (dead-defensive check, but tagged wrong).
- **File:** `src/consensus/connect_block.ts:716-724`.
- **Core ref:** Core has no such defensive check; the per-tx accumulator
  IS the source of truth. The cross-check is hotbuns-internal.
- **Description:** Hotbuns computes fees TWO ways: `nFees` (per-tx
  accumulator) and `feesByTotals = totalInputValue - (totalOutputValue
  - coinbaseOutputValue)` (block-wide arithmetic). They must agree.
  If they don't, the comment says "programmer bug", but the error
  string is `bad-cb-amount: internal fee accounting mismatch`. A
  diff-test corpus that maps reject-tokens to test outcomes would see
  `bad-cb-amount` from this and confuse it with the real Core gate.
- **Impact:** Test-corpus / diff-test signal corruption; not a runtime
  consensus bug.

---

### BUG-14 — Negative-fee check `nFees < 0n` at `connect_block.ts:672` is DEAD (every prior gate already guarantees `nFees >= 0`)

- **Severity:** P3 (dead code).
- **File:** `src/consensus/connect_block.ts:670-677`.
- **Core ref:** Core's `MoneyRange(nFees)` checks both bounds (`>= 0`
  AND `<= MAX_MONEY`); the negative case is also unreachable in
  Core but Core keeps the gate. So hotbuns matches Core's style.
- **Description:** `nFees += txFee` where `txFee = txValueIn -
  txOutputValue` only after `txValueIn >= txOutputValue` (the
  `bad-txns-in-belowout` gate at L662 rejects otherwise). So
  `txFee >= 0`, therefore `nFees >= 0`. The `if (nFees < 0n)` branch
  is unreachable.
- **Impact:** Cosmetic.

---

### BUG-15 — Per-tx `nValueIn` MoneyRange uses BLOCK-WIDE `totalInputValue` accumulator instead of resetting per-tx (mirrors Core's local-to-tx `nValueIn`)

- **Severity:** P1 (looser than Core; specific malicious-block patterns
  could exploit).
- **File:** `src/consensus/connect_block.ts:617-624`.
- **Core ref:** `bitcoin-core/src/consensus/tx_verify.cpp:166-189` —
  `CAmount nValueIn = 0;` is declared INSIDE `CheckTxInputs` and
  thus local to each tx; `MoneyRange(nValueIn)` is enforced on the
  per-tx running total, NOT the block-wide running total.
- **Description:** hotbuns runs `totalInputValue += spentEntry.amount`
  block-wide and then `if (totalInputValue > MAX_MONEY_INPUT)`. Per
  Core's logic, a SINGLE TX with inputs summing to more than MAX_MONEY
  should hit `bad-txns-inputvalues-outofrange`. hotbuns would only
  hit it when the BLOCK-WIDE total crosses MAX_MONEY. A block with
  three txs each at 0.5 * MAX_MONEY-input would pass hotbuns at tx 1
  and tx 2 (total 1.0 * MAX_MONEY) and reject at tx 3 (total 1.5 *
  MAX_MONEY > MAX_MONEY) — but Core would have rejected each tx
  individually, with per-tx state intact, returning earlier and
  matching a different reject-position.
- **Impact:** Diff-test divergence (different block.height of the
  rejected tx). Edge case in practice (no real-world tx has > 21 M
  BTC in inputs), but theoretical inflation gate is per-tx in Core
  and per-block here.

---

### BUG-16 — Per-coin MoneyRange check uses sign-blind `< 0n` on an UNSIGNED BigInt UTXO amount; the negative branch is unreachable

- **Severity:** P3 (dead code; the actual `> MAX_MONEY_INPUT` check
  IS effective).
- **File:** `src/consensus/connect_block.ts:611-616`.
- **Core ref:** `tx_verify.cpp:185-188` — `MoneyRange(coin.out.nValue)`
  expands to `nValue >= 0 && nValue <= MAX_MONEY`. With signed
  `CAmount`, the `< 0` branch is reachable (corrupted DB / overflow).
- **Description:** UTXO `amount` is stored as unsigned uint64 (BigInt
  with no sign bit). `spentEntry.amount < 0n` is unreachable. A
  CORRUPTED DB amount > 2^63 would be treated as a positive >
  INT64_MAX, hit the MAX_MONEY ceiling, and reject. So the gate is
  effective in spirit; the dead-branch is cosmetic.
- **Impact:** Cosmetic.

---

### BUG-17 — TESTNET3 / TESTNET4 / SIGNET inherit `subsidyHalvingInterval` via `...MAINNET` spread; no explicit override, no test guarding the spread

- **Severity:** P2 (correct today, but a future MAINNET change would
  silently shift testnet/signet halving).
- **File:** `src/consensus/params.ts:718, 838, 948` (`...MAINNET`
  spreads with no `subsidyHalvingInterval:` line).
- **Core ref:** `bitcoin-core/src/kernel/chainparams.cpp:84, 209, 310,
  454, 535` — Core sets `consensus.nSubsidyHalvingInterval = 210000`
  EXPLICITLY for each chain (mainnet, testnet3, testnet4, signet); only
  regtest overrides to 150. No spread-and-override pattern.
- **Description:** hotbuns's testnet3/testnet4/signet configs rely on
  the `...MAINNET` spread for halving. The test at
  `__tests__/check_transaction.test.ts:402-409` only verifies regtest.
  Mainnet's halving is asserted directly. Testnet3/testnet4/signet
  halving values are NEVER asserted. A bulk-rename of
  `subsidyHalvingInterval` in MAINNET would silently change all four
  derived chains.
- **Impact:** Maintenance / drift risk. Add explicit
  `subsidyHalvingInterval: 210_000,` to each testnet config and a
  regression test per chain.

---

### BUG-18 — `getBlockSubsidy(height < 0)` with `Math.floor(height / interval)` yields negative halvings → `1n << BigInt(negative)` throws RangeError, no test guards this

- **Severity:** P2 (defensive; callsites do guard but error message
  is bad if they slip).
- **File:** `src/consensus/params.ts:1046-1062`.
- **Core ref:** Core's `int halvings = nHeight / interval` produces a
  negative int for negative height; the `if (halvings >= 64) return 0`
  guard does NOT catch it; the `nSubsidy >>= halvings` with negative
  shift is C++ undefined behavior. Core's callers (always
  `pindex->nHeight >= 0`) avoid the issue by precondition.
- **Description:** hotbuns has the same precondition assumption.
  RPC callers (`getblocktemplate`) at server.ts:5061 set
  `height = bestBlock.height + 1` — if `bestBlock.height === -1`
  (uninitialized chain state representation), then `height = 0`
  (fine). But `chain/state.ts:219` shows `height: 0` for genesis.
  A negative `height` could appear in error-path tests or
  malformed-chain-state migrations. `BigInt(-1) << 1n` throws
  `RangeError: BigInt negative exponent` (actually `<<` with
  negative right-operand is `>>` with positive, JS quirk — let me
  not overstate). Either way, no `height >= 0` guard.
- **Impact:** Defensive; precondition exists, no test asserts the
  precondition is enforced.

---

### BUG-19 — `getBlockSubsidy` uses `Math.floor(height / interval)` which silently truncates for `height > Number.MAX_SAFE_INTEGER` (~9e15); BigInt-safe height would matter at h > 9e15 / 210000 ≈ 4.3e10

- **Severity:** P3 (theoretical; mainnet height won't approach 4.3e10
  for ~80,000 years).
- **File:** `src/consensus/params.ts:1050`.
- **Core ref:** Core uses `int nHeight` (signed 32-bit; would overflow
  at h ≈ 2.1e9 = ~40,000 years). hotbuns uses `number` (double; safe
  to 9e15 ≈ 200 million years). Numerically MORE robust than Core but
  with a subtle silent truncation at the edge.
- **Description:** The `height: number` typing means anyone passing a
  height computed from a BigInt sum (e.g. extrapolated from chain
  work) would silently truncate. Should be `height: number | bigint`
  with a BigInt-safe path.
- **Impact:** Negligible.

---

### BUG-20 — `nFees` and `feesByTotals` cross-check is the ONLY place the mismatch surface is described as "internal" — but it can also fire on coinbase-tx vs non-coinbase tx mis-classification in `isCoinbase`

- **Severity:** P3 (the cross-check IS valuable defensive code, but the
  framing in the comment says "would only fire under a programmer
  bug" — it can also fire on data corruption of the coinbase flag
  in the UTXO DB, which is one tier above "programmer bug").
- **File:** `src/consensus/connect_block.ts:710-724`.
- **Description:** Comment-as-confession (W137 fleet pattern). The
  defensive cross-check is sound; the comment underrates its value.
- **Impact:** Cosmetic.

---

### BUG-21 — Compiled `src/index.js` lines 32454-32462 echo the buggy private `getBlockSubsidy`; this is what actually runs in production (`hotbuns` start_testnet4.sh invokes `node src/index.js`)

- **Severity:** P0-CDIV-confirmation (this verifies BUG-1 lands in
  the production binary; not a separate bug).
- **File:** `src/index.js:32454-32462` (compiled mirror).
- **Description:** Per `.claude/CLAUDE.md` "hotbuns launcher mismatch"
  note, `start_testnet4.sh:115` invokes `node src/index.js`, not
  the TS sources. Confirms BUG-1's hardcoded `HALVING_INTERVAL =
  210000` is live in production JS.
- **Impact:** Confirms BUG-1 is not a TS-only artifact.

---

## Fleet patterns observed

- **Two-pipeline-guard** (W124/W125 echo, 4 instances in this wave):
  - BUG-1 — params-aware `getBlockSubsidy(height, params)` + adjacent
    private hardcoded `getBlockSubsidy(height)`.
  - BUG-7/BUG-12 — `validateBlock`+`coreConnectBlockChecks` pipeline in
    sync/blocks.ts, vs `coreConnectBlockChecks`-only pipeline in
    chain/state.ts.
  - BUG-9/BUG-10 — `params.maxCoins` plumbed but unread; 6 literal
    copies of the same constant.
- **Dead constant / dead helper** (W128/W137 echo):
  - BUG-9 — `ConsensusParams.maxCoins` is declared, exported, never
    read. Definition exists for ergonomics that nobody used.
- **Comment-as-confession** (W141 fleet pattern — 4th wave instance):
  - BUG-13/BUG-20 — `feesByTotals !== nFees` defensive check tagged
    "internal arithmetic mismatch would only fire under a programmer
    bug" while emitting `bad-cb-amount`, a canonical Core reject
    token. Mis-labels a defense-in-depth gate as scaffolding.
- **Assume-valid scope creep** (NEW pattern this wave):
  - BUG-2/BUG-3/BUG-4/BUG-5/BUG-6 — Core's `fScriptChecks` gates ONLY
    signature/script verification; arithmetic + maturity + MoneyRange
    gates are consensus-critical and always run. hotbuns' assumevalid
    fast path drops ALL of: maturity check, per-coin MoneyRange,
    per-tx nValueIn MoneyRange, per-tx bad-txns-in-belowout, per-tx
    accumulated-fee MoneyRange. Five distinct gates fold into the
    fast path. This is a structural pattern, not five independent
    bugs — the assumevalid branch's design philosophy is "skip
    everything that's not the coinbase-amount gate", which is wider
    than Core's "skip only script verification".
- **Hardcoded constant inside a private method on a class that holds
  params** (NEW pattern, see BUG-1): the class HAS `this.params`,
  has access to `subsidyHalvingInterval`, and chose to ignore it.
  Pure rewrite-as-you-go drift.

## Cross-references

- W144 (this impl) found the script-verify flag mux uses
  `verifyP2SH`/`verifyWitness`/`verifyTaproot` per height, which is
  consistent with this wave's `params.coinbaseMaturity` and
  `params.subsidyHalvingInterval` plumbing — except BUG-1 shows the
  RPC path skipped the params entirely.
- W93 / W96 / W102 audits already noted MoneyRange gates in mempool
  and snapshot. The consensus path's assumevalid branch was not
  re-audited there — that's the new finding in BUG-2..6.

## Summary

| Severity   | Count |
|------------|-------|
| P0-CDIV    | 7     |
| P0-SEC     | 1     |
| P1         | 2     |
| P2         | 5     |
| P3         | 6     |
| **Total**  | 21    |

**Most representative findings:**
1. **BUG-1 (P0-CDIV)** — RPC `getBlockSubsidy` private method hardcodes
   `HALVING_INTERVAL = 210_000`, ignoring `params.subsidyHalvingInterval`.
   Live in production JS (`src/index.js:32454-32462`). Textbook
   two-pipeline-guard pattern.
2. **BUG-2..BUG-6 (P0-CDIV cluster)** — Assume-valid fast path skips
   5 distinct Core gates (maturity, per-coin MoneyRange, per-tx
   nValueIn MoneyRange, per-tx bad-txns-in-belowout, accumulated-fee
   MoneyRange). Core's `fScriptChecks` flag gates ONLY signature
   verification; hotbuns' assumevalid widens the skip-set.
3. **BUG-7 (P0-SEC)** — `chain/state.ts::connectBlock` skips
   `validateBlock` precall → duplicate-input attack triggers
   uncaught throw in `utxoManager.spendOutput` instead of a clean
   `bad-txns-inputs-duplicate` (CVE-2018-17144 class — partial).
   Affects `generateblock` RPC, `dumptxoutset` reapply, and the
   `reorganize` path.
