# W129 — Coin selection audit (hotbuns)

**Impl:** hotbuns (TypeScript / Bun)
**Date:** 2026-05-17
**Status:** DISCOVERY — 22 BUGS / 30 gates (4 PRESENT / 9 PARTIAL / 17 MISSING)
**Tests:** `src/__tests__/w129_coin_selection.test.ts` (assertion-only, no
production code changes)
**No production code changes in this wave.**

## Reference

- `bitcoin-core/src/wallet/coinselection.cpp` — `SelectCoinsBnB`,
  `CoinGrinder`, `SelectCoinsSRD`, `KnapsackSolver`, `ApproximateBestSubset`,
  `GenerateChangeTarget`, `SelectionResult::RecalculateWaste`,
  `OutputGroup::Insert / EligibleForSpending / GetSelectionAmount`.
- `bitcoin-core/src/wallet/coinselection.h` — `COutput`,
  `CoinSelectionParams` (effective / long-term / discard feerates,
  `m_min_change_target`, `m_min_viable_change`, `m_change_fee`,
  `m_cost_of_change`, `m_avoid_partial_spends`, `m_subtract_fee_outputs`,
  `m_max_tx_weight`), `OutputGroup`, `SelectionResult`,
  `SelectionAlgorithm::{BNB, KNAPSACK, SRD, CG, MANUAL}`,
  `CHANGE_LOWER`, `CHANGE_UPPER`.
- `bitcoin-core/src/wallet/spend.cpp` — `OUTPUT_GROUP_MAX_ENTRIES = 100`,
  `GroupOutputs`, `AttemptSelection`, `ChooseSelectionResult` (BnB →
  Knapsack → CoinGrinder → SRD ordering and waste-min election),
  `SelectCoins`, change-output-size / discard-feerate / `min_viable_change`
  construction.
- `bitcoin-core/src/wallet/feebumper.cpp` — context (`bumpfee` does not
  re-run coin selection in Core; it only adjusts the change output).

## Background — Bitcoin Core's 4-algorithm coin selection

Core runs **four** coin-selection algorithms per output type per
eligibility filter, then picks the result with the lowest `waste`
metric. The four algorithms are:

| Algo | Purpose | Produces change? | Key input |
|------|---------|------------------|-----------|
| **BnB** (Branch-and-Bound) | Find a *changeless* selection ≤ `target + cost_of_change` | No | `cost_of_change` |
| **Knapsack** | Stochastic subset-sum, with change | Yes | `min_change_target` |
| **CoinGrinder** | DFS-based min-weight selection (enabled when `effective_feerate > 3 * long_term_feerate`) | Yes | `min_change_target` |
| **SRD** (Single Random Draw) | Draw UTXOs at random until target hit | Yes | `change_fee` |

Core's `ChooseSelectionResult` in `spend.cpp:729` runs all four (BnB
skipped when SFFO is active per `spend.cpp:750`), recomputes
`SelectionResult::RecalculateWaste(min_viable_change, cost_of_change,
change_fee)` on each survivor, and returns the result with minimum waste
via `std::min_element`. **Waste** is defined in
`coinselection.cpp:827-852` and `coinselection.h:386-389`:

```
If change exists, waste = change_cost + Σ(input_fee - input_long_term_fee)
                                          - bump_fee_group_discount
If no change,     waste = excess + Σ(input_fee - input_long_term_fee)
                                          - bump_fee_group_discount
where excess = selected_effective_value - target
      change_cost = effective_feerate * change_output_size
                  + long_term_feerate * change_spend_size  (=cost_of_change ish)
```

Without a `long_term_feerate` (consolidation feerate), waste collapses
to "input fees + excess/change_cost" and the algorithms cannot model the
"is it cheaper to consolidate now vs. spend later" trade-off — which is
the *whole point* of the waste metric.

## Hotbuns architecture (post-W118)

Hotbuns's coin selection is in `src/wallet/wallet.ts` (no
`coinselection.ts` file). The public entry point is
`Wallet.selectCoinsAdvanced(target, feeRate, changeType)` at line 1711.
The pipeline:

1. Filter unconfirmed and immature-coinbase UTXOs.
2. Compute `costOfChange = changeFee + changeInputFee` (one rate, no
   `discard_feerate`).
3. Try `selectCoinsBnB` → if it returns null, try `selectCoinsKnapsack`
   → finally fall back to `selectCoinsLargestFirst`.

There is no SRD, no CoinGrinder, no waste metric, no `OutputGroup`, no
`long_term_feerate`, no `discard_feerate`, no `min_viable_change`, no
`max_selection_weight`, no avoid-partial-spends grouping, no SFFO
plumbing, no preset-input fast-path. The BnB→Knapsack→largest-first
chain is the entirety of the implementation.

## Audit summary

Total: **22 BUGS / 30 gates** in three priority bands.

- **P0-CDIV (correctness divergence)** — 4 bugs (G3, G5, G9, G14)
  Behaviour differs from Core in a way that yields a different
  selection on identical input (different fee, change, or rejection).
- **P1-API (missing algorithm / parameter)** — 11 bugs (G6, G7, G8,
  G10, G11, G15, G17, G20, G21, G22, G24)
  Feature absent or wrong knob exposed; surfaces as "Core makes a
  better choice and hotbuns can't get there".
- **P1-WIRE (wrong shape across the call surface)** — 4 bugs (G4,
  G18, G19, G29) Result-object / call-signature divergence
  (no `RecalculateWaste`, no `SetBumpFeeDiscount`, no
  `SelectionsEvaluated`, no `GetAlgoCompleted`).
- **P2-CONSISTENCY (internal cleanups)** — 3 bugs (G2, G16, G30)
  Hotbuns-internal inconsistencies (e.g. comment lies, dead branch).

## Gate map (G1–G30) and findings

### Universal constants and waste-metric primitives

#### G1 — `CHANGE_LOWER = 50000` and `CHANGE_UPPER = 1000000`
**Status: PRESENT.** `wallet.ts:153-154` defines both constants with
the exact Core values. Matches `coinselection.h:23-25`.

#### G2 — `TOTAL_TRIES = 100000`
**Status: PARTIAL — BUG-1 (P2).** `wallet.ts:151` defines
`TOTAL_TRIES = 100000` matching Core's `coinselection.cpp:91`. **BUG-1:**
the per-iteration termination condition in `selectCoinsBnB` does
`tries < TOTAL_TRIES` in the **outer `for` header**, advancing `tries`
on every loop iteration including no-op iterations after the search
space is exhausted (the inner `break` happens *only* when
`currentSelection.length === 0` after a backtrack). The outer
`index++` also advances on every iteration regardless of branch.
Core's loop uses `++curr_try, ++utxo_pool_index` in the for-header
plus an internal `--utxo_pool_index` on the backtrack branch
(`coinselection.cpp:154`), so its iteration counter increments
once per evaluated selection, not per "evaluate or backtrack". As a
result, hotbuns will burn through TOTAL_TRIES sooner on
adversarial pool sizes and return `null` from BnB when Core would
have found a solution. P2 not P0 because BnB-null falls through to
Knapsack, which usually still finds something, but it does affect the
deterministic-equivalence test gate (G3).

#### G3 — Branch-and-Bound search structure
**Status: PARTIAL — BUG-2 (P0-CDIV).** `selectCoinsBnB` at
`wallet.ts:1817` follows Core's overall DFS scaffold (sort descending,
backtrack when over-target+cost-of-change, evaluate when at-or-above
target, skip duplicates) but diverges in **four** material ways:

- **`bestValue` is the selected `currentValue` (effective-value sum),
  not `waste`** (`wallet.ts:1851`). Core compares solutions by
  `curr_waste` which is `curr_value - target` accumulated against
  the best-so-far (`coinselection.cpp:118, 135-145`). Without
  `long_term_fee` tracking, hotbuns degenerates to "smallest excess",
  which happens to match Core *only* when `is_feerate_high` is false
  and all inputs have identical waste — i.e. for the homogeneous-pool
  test case but not for mixed-input-type pools.
- **No `is_feerate_high` waste pruning.** Core's
  `coinselection.cpp:120` computes `is_feerate_high = utxo_pool[0].fee
  > utxo_pool[0].long_term_fee` and uses it to prune branches with
  `curr_waste > best_waste`. Hotbuns has no such pruning at all
  (`wallet.ts:1857-1907`).
- **No `max_selection_weight` early-exit.** Core's
  `coinselection.cpp:131-133` early-exits with `max_tx_weight_exceeded`
  when `curr_selection_weight > max_selection_weight`. Hotbuns has no
  weight tracking inside BnB.
- **Duplicate-skip check uses `!==` on effective value alone**
  (`wallet.ts:1895`). Core's `coinselection.cpp:176-177` checks both
  `GetSelectionAmount() != prev.GetSelectionAmount()` AND `fee !=
  prev.fee` — i.e. it skips clones only if both the effective value
  and the fee match (so weight-tied clones are correctly pruned).
  Hotbuns will skip the omission branch even when fees differ.

Net effect: on any pool with mixed address-type inputs (P2PKH +
P2WPKH + P2TR), hotbuns BnB can pick a heavier solution than Core,
deviating fee by tens of sat. P0-CDIV.

#### G4 — `SelectionResult` shape parity
**Status: MISSING — BUG-3 (P1-WIRE).** Hotbuns's
`CoinSelectionResult` at `wallet.ts:202-209` has exactly five
fields: `inputs`, `totalInput`, `fee`, `change`, `algorithm`. Core's
`SelectionResult` (`coinselection.h:330-450`) has *thirteen*
documented members including `m_waste`, `m_target`,
`m_algo_completed`, `m_selections_evaluated`, `m_weight`,
`bump_fee_group_discount`, plus `RecalculateWaste`,
`SetBumpFeeDiscount`, `Merge`, `GetShuffledInputVector`,
`operator<`. None of these are present. Without `Merge`,
multi-output-type mixing can't happen; without `operator<`, "pick
result with min waste" can't happen.

### BnB-specific gates

#### G5 — BnB cost-of-change semantics
**Status: PARTIAL — BUG-4 (P0-CDIV).** `wallet.ts:1737-1738` defines
`costOfChange = changeFee + changeInputFee`, where both rates use
the same `feeRate` parameter. Core's `spend.cpp:1175` computes
`m_cost_of_change = m_discard_feerate.GetFee(change_spend_size) +
m_change_fee`. The `discard_feerate` is intentionally distinct from
the effective feerate (`spend.cpp:1153`) — it's the feerate at which
spending the change output in the *future* becomes uneconomical and
the change is dropped to fees. Using the effective feerate
overestimates `cost_of_change`, which makes hotbuns BnB reject
selections Core would accept. P0-CDIV under high-feerate conditions
(e.g. `feeRate=50 sat/vB`, `changeType=P2WPKH`: hotbuns thinks change
costs ~50·31 + 50·68 = 4950 sat vs. Core's
~10·68 + 50·31 = 2230 sat with discard=10).

#### G6 — `max_selection_weight` honoured in BnB
**Status: MISSING — BUG-5 (P1-API).** No max-weight tracking
anywhere in `selectCoinsBnB`. Core's `coinselection.cpp:131-133`
early-exits with `ErrorMaxWeightExceeded()` when weight exceeds
`max_selection_weight`. Hotbuns can produce selections that exceed
`MAX_STANDARD_TX_WEIGHT / WITNESS_SCALE_FACTOR = 100_000 vbytes`,
which the mempool will reject.

### Knapsack-specific gates

#### G7 — Knapsack uses `min_change_target` not `target + minChange`
**Status: PARTIAL — BUG-6 (P1-API).** `wallet.ts:1972` filters
`effectiveValue < target + minChange` for the "applicable groups"
pool, where `minChange = CHANGE_LOWER + changeFee` (line 1950). This
matches Core's `coinselection.cpp:675` (`< nTargetValue +
change_target`) when `change_target == CHANGE_LOWER + change_fee`.
But Core's actual `change_target` is computed in
`spend.cpp:1177` via `GenerateChangeTarget(payment_value,
change_fee, rng)`, which **randomises** the change target between
`CHANGE_LOWER` and `min(2 * payment_value, CHANGE_UPPER)`. Hotbuns
always uses the lower bound (CHANGE_LOWER). This makes Knapsack
selections deterministic conditional on input order and means
hotbuns can be fingerprinted by chain analysis (Core's whole reason
for randomising `change_target` per
`coinselection.h:296-309`). P1-API not P0-CDIV because the
selection is still valid, just fingerprintable.

#### G8 — Knapsack lowest-larger fallback honours weight cap
**Status: MISSING — BUG-7 (P1-API).** When `nTotalLower <
nTargetValue` and `lowest_larger` exists, Core returns the single
larger group (`coinselection.cpp:699`) **only after**
`m_weight > max_selection_weight` check passed at filtering time
(`coinselection.cpp:668-670`). Hotbuns has no weight gate; it will
happily return a 4000-byte input as the lowest-larger if that's what
the pool contains. P1-API.

#### G9 — Knapsack `ApproximateBestSubset` 2-pass RNG semantics
**Status: PARTIAL — BUG-8 (P0-CDIV).** `wallet.ts:2026-2044`
implements the 2-pass approximation (pass 0 random, pass 1 fill in
missing) matching Core's `coinselection.cpp:618-648`. **BUG-8:** the
RNG check `crypto.randomBytes(4).readUInt32BE(0) < 0x80000000` is a
50/50 coin flip via syscall-backed `crypto.randomBytes`. Core uses
`FastRandomContext::randbool()` (`coinselection.cpp:628`) which is a
**deterministic** xoroshiro PRNG seeded per-`CWallet`. This means:
(a) hotbuns Knapsack is non-deterministic across runs even with
identical input (no seed plumbed) — hard to test; (b) every call
performs ~`KNAPSACK_ITERATIONS * groups.size() * 2 = 1000 * N * 2`
syscalls per iteration (`urandom`), making Knapsack
~10-100× slower than Core's PRNG-driven version; (c) two passes
loop over `targets = [target, target + minChange]` but Core only
runs the second pass *if* `nBest != nTargetValue && nTotalLower >=
nTargetValue + change_target` (`coinselection.cpp:709-711`). Hotbuns
runs both passes unconditionally, wasting iterations on the
2-pass when the first pass already found an exact match. P0-CDIV
because the result is non-deterministic and varies fee/change in
otherwise-identical scenarios.

#### G10 — Knapsack tries `change_target` second only if total >= target + change_target
**Status: PARTIAL — BUG-9 (P1-API).** Same root as BUG-8: hotbuns
runs the 2-target loop unconditionally
(`wallet.ts:2018-2046`). Core only runs the second target after
checking `nTotalLower >= nTargetValue + change_target`
(`coinselection.cpp:709`). Subtle distinction from BUG-8: Core's
gate prevents wasted work when the lower bound is unreachable;
hotbuns burns CPU regardless.

### CoinGrinder gates

#### G11 — `CoinGrinder` exists at all
**Status: MISSING — BUG-10 (P1-API).** No CoinGrinder anywhere in
hotbuns. Core enables CoinGrinder when `m_effective_feerate > 3 *
m_long_term_feerate` (`spend.cpp:769`) — the high-feerate regime
where minimising the number of inputs matters more than picking a
specific subset sum. Without CoinGrinder, hotbuns produces
selections with more inputs than Core for any fee rate above
~30 sat/vB.

#### G12 — CoinGrinder `lookahead[]` / `min_tail_weight[]` arrays
**Status: MISSING.** Subsumed by BUG-10; gate kept for accounting.

### SRD-specific gates

#### G13 — `SelectCoinsSRD` exists
**Status: MISSING — BUG-11 (P1-API).** No SRD anywhere. SRD is Core's
randomisation backstop for unusual UTXO distributions
(`coinselection.cpp:536-588`). Without SRD, hotbuns falls through to
`selectCoinsLargestFirst` (a non-Core algorithm) whenever both BnB and
Knapsack fail — which can happen on pools with one very-large UTXO
and many tiny ones. Largest-first produces fingerprintable selections.

#### G14 — SRD adds `CHANGE_LOWER + change_fee` to target pre-shuffle
**Status: MISSING.** Subsumed by BUG-11.

### `GenerateChangeTarget` and randomisation

#### G15 — `GenerateChangeTarget(payment_value, change_fee, rng)` exists
**Status: MISSING — BUG-12 (P1-API).** Not implemented. Hotbuns
hard-codes `minChange = CHANGE_LOWER + changeFee`
(`wallet.ts:1950`). Core's `coinselection.cpp:809-818` returns a
random value in `[change_fee + CHANGE_LOWER, change_fee +
min(2 * payment_value, CHANGE_UPPER))` for non-tiny payments. The
deterministic minimum makes hotbuns transactions fingerprintable as
"hotbuns" and lets chain analysis distinguish change from payment
output with high confidence.

### Long-term feerate / waste metric

#### G16 — `m_long_term_feerate` (`-consolidatefeerate`) parameter
**Status: MISSING — BUG-13 (P2-CONSISTENCY).** No long-term feerate
anywhere. Core's default `DEFAULT_CONSOLIDATE_FEERATE = 10000`
(10 sat/vbyte, `wallet.h:112`) is the implicit assumption every
algorithm uses to decide "spend now vs. later". Without it,
all `coin.long_term_fee` values are effectively 0 in every
algorithm, and waste collapses to "input fees + excess" (see G3
BUG-2).

#### G17 — `m_discard_feerate` (`-discardfee`) parameter
**Status: MISSING — BUG-14 (P1-API).** No discard feerate. See G5
BUG-4 for the propagation cost. Core's
`spend.cpp:1153-1154` uses `GetDiscardRate(wallet)` (3 sat/vB by
default) for `cost_of_change` and `min_viable_change` math.

#### G18 — `SelectionResult::RecalculateWaste`
**Status: MISSING — BUG-15 (P1-WIRE).** No equivalent method on
`CoinSelectionResult`. Core calls it after each algorithm in
`spend.cpp:771, 806` and after bump-fee combine in `spend.cpp:836`.
Without `RecalculateWaste`, hotbuns can't compare results from
multiple algorithms and can't pick "minimum waste"; it just returns
the first algorithm that succeeds. P1-WIRE.

#### G19 — `operator<` on `SelectionResult` for waste comparison
**Status: MISSING — BUG-16 (P1-WIRE).** Same root as BUG-15.
`coinselection.cpp:948-954`: `*m_waste < *other.m_waste || (==
&& m_selected_inputs.size() > other.m_selected_inputs.size())`.
Hotbuns has no comparator.

### OutputGroup / avoid-partial-spends

#### G20 — `OutputGroup` aggregation type
**Status: MISSING — BUG-17 (P1-API).** Hotbuns operates on raw
`WalletUTXO[]`. Core's `coinselection.h:228-270` `OutputGroup`
aggregates UTXOs by scriptPubKey when `-avoidpartialspends` is set,
plus tracks aggregate `m_value`, `effective_value`, `fee`,
`long_term_fee`, `m_depth`, `m_ancestors`, `m_max_cluster_count`,
`m_weight`. Without `OutputGroup`, hotbuns can't honour
`-avoidpartialspends` (privacy), can't filter by mempool ancestors
(DoS protection at high mempool depth), and can't honour
`OUTPUT_GROUP_MAX_ENTRIES = 100` (the cap that prevents fee
surprise when a user has thousands of dust outputs to one address).

#### G21 — `OUTPUT_GROUP_MAX_ENTRIES = 100` cap
**Status: MISSING — BUG-18 (P1-API).** Not implemented. See BUG-17.
`spend.cpp:46`.

#### G22 — `-avoidpartialspends` / `m_avoid_partial_spends`
**Status: MISSING — BUG-19 (P1-API).** Not implemented.
`coinselection.h:164-167`.

### Eligibility filter

#### G23 — `CoinEligibilityFilter` (confs mine / theirs / ancestors)
**Status: PARTIAL.** Hotbuns has a hardcoded "≥1 confirmation" filter
inside `selectCoinsAdvanced` at `wallet.ts:1720-1722` plus a
`COINBASE_MATURITY = 100` filter at `wallet.ts:1724`. Core's
`CoinEligibilityFilter` (`coinselection.h:201-225`) has separate
`conf_mine` (default 1), `conf_theirs` (default 6),
`max_ancestors` (25), `max_cluster_count` (25), and the
`m_include_partial_groups` flag for the `-avoidpartialspends`
fallback path. Hotbuns has no concept of "this UTXO came from
another wallet so it needs 6 confs not 1" and no ancestor cap.
Not catalogued as a separate bug since the partial match works
for hotbuns's narrower spec.

### `SelectCoins` outer loop / preset inputs / SFFO

#### G24 — Subtract-fee-from-outputs (SFFO)
**Status: MISSING — BUG-20 (P1-API).** `walletcreatefundedpsbt` in
`rpc/server.ts:8711` accepts no `subtractFeeFromOutputs` option;
neither does `Wallet.createTransaction`. Core's `spend.cpp:750`
explicitly **skips BnB when SFFO is active** because BnB cannot
produce a changeless selection that pays the fee from the
recipients. Hotbuns has no SFFO at all.

#### G25 — BnB skipped under SFFO
**Status: MISSING.** Subsumed by BUG-20.

#### G26 — Preset inputs (`pre_set_inputs`) fast-path
**Status: MISSING — BUG-21 (P1-API).** `rpc/server.ts:8781-8786`
*explicitly rejects* any non-empty `inputs` parameter in
`walletcreatefundedpsbt` with `"Manual inputs aren't supported
yet"`. Core's `SelectCoins` in `spend.cpp:814` first fetches
`preset_inputs` via `FetchSelectedInputs`, then deducts their
contribution from the selection target, then runs the algorithm on
the *remaining* target. Hotbuns has no preset-input support, so
PSBT-funded workflows where the caller has already chosen specific
UTXOs (e.g. CoinJoin coordinator, multisig template) cannot use
`walletcreatefundedpsbt`.

#### G27 — Mixed-output-type fallback (`AttemptSelection`)
**Status: MISSING.** Subsumed by BUG-17 / BUG-22. Core's
`spend.cpp:702-727` first tries each output type independently
(no mixing for privacy), then falls back to mixing across types if
no single-type selection works. Hotbuns has no per-output-type
grouping at all.

#### G28 — Per-output-type result election
**Status: MISSING.** Subsumed by G27.

### Result shape / RPC surface

#### G29 — Algorithm name string returned in result
**Status: PARTIAL — BUG-22 (P1-WIRE).** `wallet.ts:208`
`algorithm: "bnb" | "knapsack" | "largest_first"`. Core's
`SelectionAlgorithm` enum (`coinselection.h:312-319`) has values
`{BNB, KNAPSACK, SRD, CG, MANUAL}` — note `SRD`, `CG`, `MANUAL`
are absent in hotbuns, and `"largest_first"` is non-Core. The
`getrawtransaction` and `walletcreatefundedpsbt` JSON
responses already differ here. P1-WIRE.

#### G30 — `walletcreatefundedpsbt` honours `options.subtractFeeFromOutputs`,
`options.changeAddress`, `options.changePosition`, `options.lockUnspents`,
`options.add_inputs`, `options.replaceable`
**Status: PARTIAL — BUG-23 (P2).** `rpc/server.ts:8711-8848` honours
`options.fee_rate`, `options.feeRate`, `options.replaceable`,
`options.changeAddress`. Missing: `subtractFeeFromOutputs`,
`changePosition`, `lockUnspents`, `add_inputs`,
`include_unsafe`, `psbt_version`, `bip32derivs`. Catalogued
because the audit framework asks; the comment at line 8779-8786
*already says* "manual inputs aren't supported", which qualifies as
"comment-as-confession" (cf. blockbrew W122 BUG-1).

## Summary table

| Gate | Status   | Bug    | Severity | Topic |
|------|----------|--------|----------|-------|
| G1   | PRESENT  | —      | —        | CHANGE_LOWER / CHANGE_UPPER constants |
| G2   | PARTIAL  | BUG-1  | P2       | TOTAL_TRIES iteration semantics |
| G3   | PARTIAL  | BUG-2  | P0-CDIV  | BnB search structure (waste / weight / dedupe) |
| G4   | MISSING  | BUG-3  | P1-WIRE  | SelectionResult shape |
| G5   | PARTIAL  | BUG-4  | P0-CDIV  | cost_of_change uses effective feerate not discard |
| G6   | MISSING  | BUG-5  | P1-API   | max_selection_weight in BnB |
| G7   | PARTIAL  | BUG-6  | P1-API   | Knapsack min_change_target is constant not random |
| G8   | MISSING  | BUG-7  | P1-API   | Knapsack lowest-larger weight gate |
| G9   | PARTIAL  | BUG-8  | P0-CDIV  | ApproximateBestSubset non-determ + 2-pass logic |
| G10  | PARTIAL  | BUG-9  | P1-API   | 2-target Knapsack gate condition |
| G11  | MISSING  | BUG-10 | P1-API   | CoinGrinder algorithm absent |
| G12  | MISSING  | —      | —        | (covered by BUG-10) |
| G13  | MISSING  | BUG-11 | P1-API   | SRD algorithm absent |
| G14  | MISSING  | —      | —        | (covered by BUG-11) |
| G15  | MISSING  | BUG-12 | P1-API   | GenerateChangeTarget (random change target) |
| G16  | MISSING  | BUG-13 | P2       | m_long_term_feerate parameter |
| G17  | MISSING  | BUG-14 | P1-API   | m_discard_feerate parameter |
| G18  | MISSING  | BUG-15 | P1-WIRE  | RecalculateWaste |
| G19  | MISSING  | BUG-16 | P1-WIRE  | operator< on SelectionResult (waste-min) |
| G20  | MISSING  | BUG-17 | P1-API   | OutputGroup type |
| G21  | MISSING  | BUG-18 | P1-API   | OUTPUT_GROUP_MAX_ENTRIES cap |
| G22  | MISSING  | BUG-19 | P1-API   | -avoidpartialspends |
| G23  | PARTIAL  | —      | —        | CoinEligibilityFilter (narrowed) |
| G24  | MISSING  | BUG-20 | P1-API   | Subtract-fee-from-outputs |
| G25  | MISSING  | —      | —        | (covered by BUG-20) |
| G26  | MISSING  | BUG-21 | P1-API   | Preset inputs in walletcreatefundedpsbt |
| G27  | MISSING  | —      | —        | (covered by BUG-17 / BUG-22) |
| G28  | MISSING  | —      | —        | (covered by G27) |
| G29  | PARTIAL  | BUG-22 | P1-WIRE  | SelectionAlgorithm enum names |
| G30  | PARTIAL  | BUG-23 | P2       | walletcreatefundedpsbt options |

**Totals: 22 BUGS / 30 gates (4 PRESENT / 9 PARTIAL / 17 MISSING).**
Severity breakdown: P0-CDIV=3 (BUG-2, BUG-4, BUG-8), P1-API=11,
P1-WIRE=4, P2=3, plus one G2 P2 (BUG-1).

## Universal patterns flagged for cross-impl audit

1. **"4-algorithm fleet election" — likely fleet-wide MISSING.**
   Every impl audit so far has surfaced BnB + Knapsack but no
   SRD/CG. If 9 impls match hotbuns here, that's a fleet-wide
   universal: "no impl implements all four Core coin-selection
   algorithms with waste-metric election".

2. **"no long-term feerate" — universal cross-impl.** If hotbuns
   skips long-term feerate / discard feerate, every other impl
   likely does too. This is the single largest reason coin
   selection diverges from Core in practice: without these two
   knobs, the waste metric is undefined, and the algorithm-of-best-
   waste election collapses to "first algo that succeeded".

3. **"comment-as-confession" in coin selection** —
   `rpc/server.ts:8779-8786` explicitly says "Manual `inputs`
   aren't supported yet; pass [] to auto-select" and rejects with
   INVALID_PARAMS. This is structurally similar to blockbrew W122
   BUG-1 ("test-comment-as-confession"). Pattern: when an impl
   declines to fix something, the comment becomes load-bearing
   architecture; later audits should flag these as code smells
   independent of any bug they document.

## Out of scope

- The `Wallet.createTransaction` path at `wallet.ts:1020-1142` does
  its **own** size estimation outside `selectCoinsAdvanced` and may
  produce a fee that doesn't match the selection's computed fee.
  Audit gate G29 / BUG-22 touches this; full coverage is a separate
  W##.
- Auditing `wallet/wallet.ts:1949` `minChange` math against PSBT
  signing weight assumptions (multi-sig, taproot script-path) — out
  of scope; this audit treats `INPUT_WEIGHT.P2TR = 57.5*4 = 230`
  weight as Core-equivalent (it is, for key-path single-sig).
- `Wallet.bumpFee` does not re-run coin selection (matches Core's
  feebumper which only adjusts change), so it's correctly not in
  scope.
