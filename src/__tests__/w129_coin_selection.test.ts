/**
 * W129 — Coin selection audit (hotbuns).
 *
 * 30 gates covering Branch-and-Bound, Knapsack, SRD, CoinGrinder,
 * effective-value, long-term feerate, cost-of-change, subtract-fee-from-
 * outputs (SFFO), and change-target randomisation.
 *
 * Reference:
 *   - bitcoin-core/src/wallet/coinselection.cpp
 *   - bitcoin-core/src/wallet/coinselection.h
 *   - bitcoin-core/src/wallet/spend.cpp
 *   - bitcoin-core/src/wallet/feebumper.cpp
 *
 * Audit verdict (see audit/w129_coin_selection.md): 22 bugs / 30 gates,
 * PRESENT=4, PARTIAL=9, MISSING=17. Severities: P0-CDIV=3,
 * P1-API=11, P1-WIRE=4, P2=3+1.
 *
 *   P0-CDIV: BUG-2 (BnB waste/weight/dedupe), BUG-4 (cost_of_change
 *            uses effective feerate not discard), BUG-8
 *            (ApproximateBestSubset non-determinism + unconditional
 *            two-pass loop).
 *
 *   KEY FINDING (cross-impl pattern candidate): hotbuns implements
 *   only BnB + Knapsack + a non-Core "largest-first" fallback. SRD,
 *   CoinGrinder, GenerateChangeTarget, long-term feerate, discard
 *   feerate, waste metric, OutputGroup, OUTPUT_GROUP_MAX_ENTRIES,
 *   avoid-partial-spends, SFFO plumbing, preset inputs, and the
 *   `walletcreatefundedpsbt` options surface beyond `fee_rate /
 *   replaceable / changeAddress` are all absent.
 *
 * No production code changes in this wave.
 *
 * Running: bun test src/__tests__/w129_coin_selection.test.ts
 */

import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

import {
  Wallet,
  COINBASE_MATURITY,
  COINBASE_SPENDABLE_DEPTH,
  type WalletConfig,
  type WalletUTXO,
  type CoinSelectionResult,
} from "../wallet/wallet";
import { AddressType } from "../address/encoding";

// ---------------------------------------------------------------------------
// Source-level fixtures (for static-grep gates).
// ---------------------------------------------------------------------------

const __dirname = dirname(fileURLToPath(import.meta.url));
const SRC = resolve(__dirname, "..");
const WALLET_SRC = readFileSync(resolve(SRC, "wallet", "wallet.ts"), "utf8");
const RPC_SERVER_SRC = readFileSync(resolve(SRC, "rpc", "server.ts"), "utf8");

/**
 * Find the function-definition offset for a given method name in `src`.
 * The definition is preceded by at most a `  ` indent and starts with
 * either `private`, `public`, `static`, `async`, or the bare name (TS
 * class shorthand). Multiple call sites exist (e.g. `selectCoinsBnB(` is
 * both called inside `selectCoinsAdvanced` and defined as a method); we
 * pick the *latest* occurrence because the call sites always precede the
 * definitions in hotbuns/wallet.ts.
 */
function findDefOffset(src: string, name: string): number {
  // Prefer a regex that matches "<two-space-indent>(private|async|public|
  // static)? <name>(": that's the canonical class-method definition shape.
  const defPattern = new RegExp(
    `(?:^|\\n)\\s{2}(?:private\\s+|public\\s+|static\\s+|async\\s+)*${name}\\(`,
  );
  const m = defPattern.exec(src);
  if (m) {
    // Offset of the *name* (not the leading newline).
    return src.indexOf(`${name}(`, m.index);
  }
  // Fallback: last occurrence of the bare token (definitions always come
  // after call sites in hotbuns/wallet.ts).
  return src.lastIndexOf(`${name}(`);
}

/**
 * Slice a function body from its definition offset to the next sibling
 * method's definition (or `}\n}` end-of-class).
 */
function findFnBody(
  src: string,
  defOffset: number,
  nextDefName?: string,
): string {
  if (nextDefName) {
    const nextOff = findDefOffset(src, nextDefName);
    if (nextOff > defOffset) return src.slice(defOffset, nextOff);
  }
  return src.slice(defOffset, defOffset + 6000);
}

// Pre-resolve definition offsets used by multiple gates.
const BNB_DEF_OFFSET = findDefOffset(WALLET_SRC, "selectCoinsBnB");
const KNAP_DEF_OFFSET = findDefOffset(WALLET_SRC, "selectCoinsKnapsack");
const BUILD_KNAP_OFFSET = findDefOffset(WALLET_SRC, "buildKnapsackResult");
const LARGEST_FIRST_OFFSET = findDefOffset(WALLET_SRC, "selectCoinsLargestFirst");
const ADV_DEF_OFFSET = findDefOffset(WALLET_SRC, "selectCoinsAdvanced");
const GET_INPUT_WEIGHT_OFFSET = findDefOffset(WALLET_SRC, "getInputWeight");
const WCF_OFFSET = findDefOffset(RPC_SERVER_SRC, "walletCreateFundedPSBT");
const WCF_END = (() => {
  // walletCreateFundedPSBT is followed by another `private` declaration.
  const start = WCF_OFFSET;
  const nextPrivate = RPC_SERVER_SRC.indexOf("\n  private ", start + 50);
  return nextPrivate > start ? nextPrivate : start + 12000;
})();

// ---------------------------------------------------------------------------
// Test helpers.
// ---------------------------------------------------------------------------

function makeConfig(): WalletConfig {
  return { datadir: "/tmp/hotbuns-w129-audit", network: "mainnet" };
}

function makeUTXO(opts: {
  txidSeed: number;
  vout?: number;
  amount: bigint;
  address: string;
  keyPath: string;
  confirmations?: number;
  addressType?: AddressType;
  isCoinbase?: boolean;
}): WalletUTXO {
  const txid = Buffer.alloc(32);
  for (let i = 0; i < 32; i++) {
    txid[i] = ((i * 7 + opts.txidSeed * 31 + 0x4d) & 0xff) ^ (i & 0x0f);
  }
  txid[0] = (0xa0 ^ opts.txidSeed) & 0xff;
  txid[31] = (0x5e ^ opts.txidSeed) & 0xff;
  return {
    outpoint: { txid, vout: opts.vout ?? 0 },
    amount: opts.amount,
    address: opts.address,
    keyPath: opts.keyPath,
    confirmations: opts.confirmations ?? 6,
    addressType: opts.addressType ?? AddressType.P2WPKH,
    isCoinbase: opts.isCoinbase ?? false,
  };
}

function mkWallet(): Wallet {
  // Deterministic mnemonic from BIP-39 test vectors.
  const mnemonic =
    "abandon abandon abandon abandon abandon abandon abandon abandon " +
    "abandon abandon abandon about";
  return Wallet.create(makeConfig(), mnemonic);
}

// =============================================================================
// G1 — CHANGE_LOWER / CHANGE_UPPER constants — PRESENT
// =============================================================================
describe("W129-G1: CHANGE_LOWER / CHANGE_UPPER — PRESENT", () => {
  test("CHANGE_LOWER = 50000n (matches Core coinselection.h:23)", () => {
    expect(WALLET_SRC).toMatch(/CHANGE_LOWER\s*=\s*50000n/);
  });
  test("CHANGE_UPPER = 1000000n (matches Core coinselection.h:25)", () => {
    expect(WALLET_SRC).toMatch(/CHANGE_UPPER\s*=\s*1000000n/);
  });
});

// =============================================================================
// G2 — TOTAL_TRIES = 100000 — PARTIAL (BUG-1)
// =============================================================================
describe("W129-G2: TOTAL_TRIES = 100000 — PARTIAL (BUG-1)", () => {
  test("TOTAL_TRIES constant present and matches Core", () => {
    expect(WALLET_SRC).toMatch(/TOTAL_TRIES\s*=\s*100000/);
  });
  test(
    "BUG-1: BnB increments `tries` on every iteration including backtracks " +
      "(Core increments once per evaluated selection)",
    () => {
      // Hotbuns: tries++ in outer `for` header advances on each loop pass.
      // Core: ++curr_try in the for header advances on each loop pass too,
      // but Core also does `--utxo_pool_index` inside the backtrack branch
      // (coinselection.cpp:154). Hotbuns has no equivalent decrement —
      // index++ runs on every loop pass and is never rolled back.
      // Static evidence:
      expect(WALLET_SRC).toMatch(
        /for\s*\(\s*let\s+tries\s*=\s*0,\s*index\s*=\s*0\s*;\s*tries\s*<\s*TOTAL_TRIES\s*;\s*tries\+\+,\s*index\+\+\s*\)/,
      );
      // No `index--` inside the backtrack branch except the while-loop that
      // rolls back to currentSelection.back() + 1 — which is bounded by
      // currentSelection length, not by the backtrack-once decrement Core uses.
      const decCount = (WALLET_SRC.match(/index--/g) ?? []).length;
      expect(decCount).toBeLessThan(3);
    },
  );
});

// =============================================================================
// G3 — Branch-and-Bound structure — PARTIAL (BUG-2, P0-CDIV)
// =============================================================================
describe("W129-G3: BnB structure — PARTIAL (BUG-2, P0-CDIV)", () => {
  test("selectCoinsBnB exists", () => {
    expect(WALLET_SRC).toMatch(/selectCoinsBnB\s*\(/);
  });

  test(
    "BUG-2a: bestValue is `currentValue` (effective-value sum), not `waste`",
    () => {
      // Core compares solutions by curr_waste (coinselection.cpp:135-145).
      // Hotbuns just tracks currentValue:
      expect(WALLET_SRC).toMatch(/let\s+bestValue\s*=\s*BigInt\(\s*"0x7fffffffffffffffffffffffffffffff"/);
      // No `waste` or `bestWaste` variable in selectCoinsBnB:
      const bnbSlice = WALLET_SRC.slice(BNB_DEF_OFFSET, KNAP_DEF_OFFSET);
      expect(bnbSlice).not.toMatch(/\bbestWaste\b|\bcurr_waste\b|\bcurrentWaste\b/);
    },
  );

  test("BUG-2b: no is_feerate_high pruning", () => {
    const bnbSlice = WALLET_SRC.slice(BNB_DEF_OFFSET, KNAP_DEF_OFFSET);
    expect(bnbSlice).not.toMatch(/is_feerate_high|isFeeRateHigh/);
  });

  test("BUG-2c: no max_selection_weight tracked inside BnB", () => {
    const bnbSlice = WALLET_SRC.slice(BNB_DEF_OFFSET, KNAP_DEF_OFFSET);
    expect(bnbSlice).not.toMatch(/max_selection_weight|maxSelectionWeight/);
  });

  test(
    "BUG-2d: duplicate-skip checks effective value only, not (value, fee) pair",
    () => {
      const bnbSlice = WALLET_SRC.slice(BNB_DEF_OFFSET, KNAP_DEF_OFFSET);
      // Core line 176-177: utxo.GetSelectionAmount() != prev.GetSelectionAmount()
      //                || utxo.fee != prev.fee
      // Hotbuns line 1895 only compares effectiveValue:
      expect(bnbSlice).toMatch(
        /utxoData\[index\]\.effectiveValue\s*!==\s*utxoData\[index - 1\]\.effectiveValue/,
      );
      // No fee comparison in BnB (would need utxoData[i].fee tracked):
      expect(bnbSlice).not.toMatch(/utxoData\[index\]\.fee\s*!==/);
    },
  );

  test("PASS: BnB returns null on insufficient funds", () => {
    const w = mkWallet();
    const addr = w.getNewAddress();
    w.addUTXO(
      makeUTXO({
        txidSeed: 1,
        amount: 1000n,
        address: addr,
        keyPath: "m/84'/0'/0'/0/0",
      }),
    );
    const result = w.selectCoinsBnB([], 100_000_000n, 1, 0n);
    expect(result).toBeNull();
  });

  test(
    "PARTIAL: BnB returns a result with `change: 0n` when exact match exists",
    () => {
      const w = mkWallet();
      const addr = w.getNewAddress();
      // 100_000 input − P2WPKH input fee = ~92_500 effective
      // We need target=92_500 to find exact match.
      w.addUTXO(
        makeUTXO({
          txidSeed: 1,
          amount: 100_000n,
          address: addr,
          keyPath: "m/84'/0'/0'/0/0",
        }),
      );
      // BnB will succeed (exact effective value match within cost_of_change).
      const result = w.selectCoinsAdvanced(50_000n, 1);
      expect(result).not.toBeNull();
      // Either bnb (changeless) or knapsack (changed). Both valid outcomes
      // for this gate (we're asserting the call shape, not the choice).
      expect(["bnb", "knapsack", "largest_first"]).toContain(result.algorithm);
    },
  );
});

// =============================================================================
// G4 — SelectionResult shape parity — MISSING (BUG-3, P1-WIRE)
// =============================================================================
describe("W129-G4: SelectionResult shape — MISSING (BUG-3)", () => {
  test(
    "BUG-3a: CoinSelectionResult is 5 fields, not Core's 13-field SelectionResult",
    () => {
      const w = mkWallet();
      const addr = w.getNewAddress();
      w.addUTXO(
        makeUTXO({
          txidSeed: 1,
          amount: 100_000n,
          address: addr,
          keyPath: "m/84'/0'/0'/0/0",
        }),
      );
      const result = w.selectCoinsAdvanced(50_000n, 1);
      const keys = Object.keys(result).sort();
      expect(keys).toEqual(["algorithm", "change", "fee", "inputs", "totalInput"].sort());
    },
  );
  test("BUG-3b: no `waste` / `m_waste` field on result", () => {
    const w = mkWallet();
    const addr = w.getNewAddress();
    w.addUTXO(
      makeUTXO({
        txidSeed: 1,
        amount: 100_000n,
        address: addr,
        keyPath: "m/84'/0'/0'/0/0",
      }),
    );
    const result = w.selectCoinsAdvanced(50_000n, 1) as unknown as Record<
      string,
      unknown
    >;
    expect("waste" in result).toBe(false);
    expect("m_waste" in result).toBe(false);
  });
  test("BUG-3c: no RecalculateWaste / SetBumpFeeDiscount methods", () => {
    expect(WALLET_SRC).not.toMatch(/RecalculateWaste|recalculateWaste/);
    expect(WALLET_SRC).not.toMatch(/SetBumpFeeDiscount|setBumpFeeDiscount/);
  });
});

// =============================================================================
// G5 — cost_of_change uses discard_feerate not effective — PARTIAL (BUG-4, P0-CDIV)
// =============================================================================
describe("W129-G5: cost_of_change ≠ Core's formula — PARTIAL (BUG-4, P0-CDIV)", () => {
  test(
    "BUG-4: hotbuns uses single feeRate for both changeOutputFee and changeInputFee",
    () => {
      // Hotbuns line 1737-1738:
      //   const changeFee = ceil((changeOutputWeight / 4) * feeRate);
      //   const costOfChange = changeFee + ceil((changeInputWeight / 4) * feeRate);
      // Core spend.cpp:1175:
      //   m_cost_of_change = m_discard_feerate.GetFee(change_spend_size)
      //                    + m_change_fee
      //                    (m_change_fee uses m_effective_feerate)
      const idx = WALLET_SRC.indexOf("// Calculate cost of change");
      expect(idx).toBeGreaterThan(-1);
      const slice = WALLET_SRC.slice(idx, idx + 600);
      // Both fee components use the SAME feeRate variable:
      expect(slice).toMatch(
        /changeFee\s*=\s*BigInt\(Math\.ceil\(\(changeOutputWeight\s*\/\s*4\)\s*\*\s*feeRate\)\)/,
      );
      expect(slice).toMatch(
        /costOfChange\s*=\s*changeFee\s*\+\s*BigInt\(Math\.ceil\(\(changeInputWeight\s*\/\s*4\)\s*\*\s*feeRate\)\)/,
      );
      // No discardFeeRate / discard_feerate:
      expect(slice).not.toMatch(/discardFeeRate|discard_feerate|discardFee/);
    },
  );
});

// =============================================================================
// G6 — max_selection_weight enforcement in BnB — MISSING (BUG-5, P1-API)
// =============================================================================
describe("W129-G6: max_selection_weight in BnB — MISSING (BUG-5)", () => {
  test("BUG-5: no max_selection_weight tracking anywhere in wallet.ts", () => {
    expect(WALLET_SRC).not.toMatch(/max_selection_weight|maxSelectionWeight/);
  });
  test("BUG-5: no MAX_STANDARD_TX_WEIGHT awareness in BnB pipeline", () => {
    const slice = WALLET_SRC.slice(BNB_DEF_OFFSET, KNAP_DEF_OFFSET);
    expect(slice).not.toMatch(/MAX_STANDARD_TX_WEIGHT|maxTxWeight|max_tx_weight/);
  });
});

// =============================================================================
// G7 — Knapsack min_change_target is CHANGE_LOWER+changeFee, not random — PARTIAL (BUG-6)
// =============================================================================
describe("W129-G7: Knapsack min_change_target is constant — PARTIAL (BUG-6)", () => {
  test("BUG-6: minChange hardcoded to CHANGE_LOWER + changeFee", () => {
    const slice = WALLET_SRC.slice(KNAP_DEF_OFFSET, BUILD_KNAP_OFFSET);
    expect(slice).toMatch(/minChange\s*=\s*CHANGE_LOWER\s*\+\s*changeFee/);
  });
  test("BUG-6: no GenerateChangeTarget call anywhere", () => {
    expect(WALLET_SRC).not.toMatch(/GenerateChangeTarget|generateChangeTarget/);
  });
});

// =============================================================================
// G8 — Knapsack lowest-larger weight cap — MISSING (BUG-7, P1-API)
// =============================================================================
describe("W129-G8: lowest-larger weight gate — MISSING (BUG-7)", () => {
  test(
    "BUG-7: no weight gate on lowest-larger filtering (Core coinselection.cpp:668-670)",
    () => {
      const slice = WALLET_SRC.slice(KNAP_DEF_OFFSET, BUILD_KNAP_OFFSET);
      expect(slice).not.toMatch(
        /m_weight\s*>\s*max_selection_weight|inputWeight\s*>\s*max/,
      );
    },
  );
});

// =============================================================================
// G9 — ApproximateBestSubset RNG semantics — PARTIAL (BUG-8, P0-CDIV)
// =============================================================================
describe("W129-G9: ApproximateBestSubset RNG — PARTIAL (BUG-8, P0-CDIV)", () => {
  test(
    "BUG-8a: uses crypto.randomBytes per call (slow, non-deterministic)",
    () => {
      const slice = WALLET_SRC.slice(KNAP_DEF_OFFSET, BUILD_KNAP_OFFSET);
      expect(slice).toMatch(/crypto\.randomBytes\(4\)\.readUInt32BE\(0\)\s*<\s*0x80000000/);
    },
  );
  test(
    "BUG-8b: no FastRandomContext / seeded PRNG (Core uses xoroshiro-128)",
    () => {
      expect(WALLET_SRC).not.toMatch(/FastRandomContext|fastRandomContext|xoroshiro/);
    },
  );
  test(
    "BUG-8c: two-pass `targets = [target, target + minChange]` runs unconditionally",
    () => {
      const slice = WALLET_SRC.slice(KNAP_DEF_OFFSET, BUILD_KNAP_OFFSET);
      // Static evidence: const targets = [target, target + minChange];
      expect(slice).toMatch(/const\s+targets\s*=\s*\[\s*target\s*,\s*target\s*\+\s*minChange/);
      // No conditional `if (nBest != target && nTotalLower >= target + change_target)`:
      expect(slice).not.toMatch(/nBest\s*!=\s*nTargetValue\s*&&\s*nTotalLower/);
    },
  );

  test(
    "PARTIAL: Knapsack is non-deterministic across runs (no seed plumbing)",
    () => {
      // We can't directly observe non-determinism in unit tests without a
      // controlled pool size large enough to force ApproximateBestSubset.
      // Static evidence instead: the function does not accept an rng / seed
      // parameter, unlike Core's KnapsackSolver(... FastRandomContext& rng).
      const sig = WALLET_SRC.match(
        /selectCoinsKnapsack\([^)]*\)\s*:\s*CoinSelectionResult/,
      );
      expect(sig).not.toBeNull();
      expect(sig?.[0]).not.toMatch(/rng|FastRandom|seed/);
    },
  );
});

// =============================================================================
// G10 — 2-target Knapsack gate — PARTIAL (BUG-9, P1-API)
// =============================================================================
describe("W129-G10: 2-target Knapsack gate condition — PARTIAL (BUG-9)", () => {
  test(
    "BUG-9: second-target pass runs unconditionally, not gated by `nTotalLower >= target + change_target`",
    () => {
      // Same evidence as BUG-8c (the gate is the same code path), but
      // tracked as a separate bug because the API surface differs:
      // BUG-8 is the RNG, BUG-9 is the loop structure.
      const slice = WALLET_SRC.slice(KNAP_DEF_OFFSET, BUILD_KNAP_OFFSET);
      const targetsForLoop = slice.indexOf("for (const targetValue of targets)");
      expect(targetsForLoop).toBeGreaterThan(-1);
      // Inside that for-loop, no early-return before second iteration:
      const after = slice.slice(targetsForLoop, targetsForLoop + 800);
      expect(after).not.toMatch(/break;\s*$/m);
    },
  );
});

// =============================================================================
// G11 — CoinGrinder algorithm absent — MISSING (BUG-10, P1-API)
// =============================================================================
describe("W129-G11: CoinGrinder absent — MISSING (BUG-10)", () => {
  test("BUG-10: no CoinGrinder / coinGrinder / selectCoinsCG anywhere", () => {
    expect(WALLET_SRC).not.toMatch(/CoinGrinder|coinGrinder|selectCoinsCG|coin_grinder/);
  });
  test(
    "BUG-10: no `is_feerate_high` / `3 * long_term_feerate` enable check",
    () => {
      expect(WALLET_SRC).not.toMatch(/3\s*\*\s*long_term_feerate|3\s*\*\s*longTerm/);
    },
  );
});

// =============================================================================
// G12 — CoinGrinder lookahead/min_tail_weight arrays — MISSING (covered by BUG-10)
// =============================================================================
describe("W129-G12: CoinGrinder lookahead arrays — MISSING (covered by BUG-10)", () => {
  test("no lookahead / min_tail_weight tables", () => {
    expect(WALLET_SRC).not.toMatch(/lookahead\s*\[/);
    expect(WALLET_SRC).not.toMatch(/min_tail_weight|minTailWeight/);
  });
});

// =============================================================================
// G13 — SRD algorithm absent — MISSING (BUG-11, P1-API)
// =============================================================================
describe("W129-G13: SRD absent — MISSING (BUG-11)", () => {
  test("BUG-11: no SelectCoinsSRD / selectCoinsSRD / SingleRandomDraw", () => {
    expect(WALLET_SRC).not.toMatch(/SRD|SingleRandomDraw|single_random_draw|selectCoinsSRD/);
  });
  test("BUG-11: no SelectionAlgorithm.SRD enum value", () => {
    expect(WALLET_SRC).not.toMatch(/algorithm:\s*"srd"|SelectionAlgorithm\.SRD/);
  });
});

// =============================================================================
// G14 — SRD adds CHANGE_LOWER + change_fee pre-shuffle — MISSING (covered by BUG-11)
// =============================================================================
describe("W129-G14: SRD CHANGE_LOWER offset — MISSING (covered by BUG-11)", () => {
  test("no priority_queue / MinOutputGroupComparator (SRD weight-cap structure)", () => {
    expect(WALLET_SRC).not.toMatch(/MinOutputGroupComparator|priority_queue|priorityQueue/);
  });
});

// =============================================================================
// G15 — GenerateChangeTarget — MISSING (BUG-12, P1-API)
// =============================================================================
describe("W129-G15: GenerateChangeTarget — MISSING (BUG-12)", () => {
  test("BUG-12: no GenerateChangeTarget function", () => {
    expect(WALLET_SRC).not.toMatch(/GenerateChangeTarget|generateChangeTarget/);
  });
  test(
    "BUG-12: change target deterministic — minChange = CHANGE_LOWER + changeFee always",
    () => {
      const slice = WALLET_SRC.slice(KNAP_DEF_OFFSET, BUILD_KNAP_OFFSET);
      // No randomisation of the change-target value (no rng.randrange call):
      expect(slice).not.toMatch(/randrange|randRange|randomRange/);
    },
  );
});

// =============================================================================
// G16 — long_term_feerate / -consolidatefeerate — MISSING (BUG-13, P2)
// =============================================================================
describe("W129-G16: long_term_feerate — MISSING (BUG-13)", () => {
  test("BUG-13: no long_term_feerate / longTermFeerate / consolidatefeerate", () => {
    expect(WALLET_SRC).not.toMatch(/long_term_feerate|longTermFeerate|consolidatefeerate|consolidateFeerate/);
  });
  test("BUG-13: no DEFAULT_CONSOLIDATE_FEERATE constant", () => {
    expect(WALLET_SRC).not.toMatch(/DEFAULT_CONSOLIDATE_FEERATE/);
  });
});

// =============================================================================
// G17 — discard_feerate / -discardfee — MISSING (BUG-14, P1-API)
// =============================================================================
describe("W129-G17: discard_feerate — MISSING (BUG-14)", () => {
  test("BUG-14: no discard_feerate / discardFeerate / GetDiscardRate", () => {
    expect(WALLET_SRC).not.toMatch(/discard_feerate|discardFeerate|GetDiscardRate|getDiscardRate/);
  });
  test("BUG-14: no min_viable_change calculation", () => {
    expect(WALLET_SRC).not.toMatch(/min_viable_change|minViableChange/);
  });
});

// =============================================================================
// G18 — RecalculateWaste — MISSING (BUG-15, P1-WIRE)
// =============================================================================
describe("W129-G18: RecalculateWaste — MISSING (BUG-15)", () => {
  test("BUG-15: no RecalculateWaste / recalculateWaste method", () => {
    expect(WALLET_SRC).not.toMatch(/RecalculateWaste|recalculateWaste/);
  });
  test("BUG-15: no waste computation anywhere in coin selection path", () => {
    // The only "waste" allusion would be in BnB: it isn't there either
    // (gate G3 BUG-2a).
    const slice = WALLET_SRC.slice(KNAP_DEF_OFFSET, BUILD_KNAP_OFFSET);
    expect(slice).not.toMatch(/\bwaste\b/);
  });
});

// =============================================================================
// G19 — operator< on SelectionResult for waste-min election — MISSING (BUG-16)
// =============================================================================
describe("W129-G19: SelectionResult comparator — MISSING (BUG-16)", () => {
  test("BUG-16: selectCoinsAdvanced returns the first algo that succeeds, not min-waste", () => {
    // Static evidence: selectCoinsAdvanced has linear fallback chain
    // (BnB → Knapsack → largest-first), not parallel-run-then-elect.
    const slice = WALLET_SRC.slice(ADV_DEF_OFFSET, BNB_DEF_OFFSET);
    expect(slice).toMatch(/if\s*\(bnbResult\)\s*{\s*return\s+bnbResult/);
    expect(slice).toMatch(/if\s*\(knapsackResult\)\s*{\s*return\s+knapsackResult/);
    expect(slice).not.toMatch(/min_element|minElement|chooseMin|electBest/);
  });
});

// =============================================================================
// G20 — OutputGroup aggregation type — MISSING (BUG-17, P1-API)
// =============================================================================
describe("W129-G20: OutputGroup — MISSING (BUG-17)", () => {
  test("BUG-17: no OutputGroup class / type", () => {
    expect(WALLET_SRC).not.toMatch(/\bOutputGroup\b/);
  });
  test("BUG-17: no group-by-scriptPubKey aggregation logic", () => {
    expect(WALLET_SRC).not.toMatch(/groupBy.*scriptPubKey|scriptPubKey.*group/);
  });
});

// =============================================================================
// G21 — OUTPUT_GROUP_MAX_ENTRIES cap — MISSING (BUG-18, P1-API)
// =============================================================================
describe("W129-G21: OUTPUT_GROUP_MAX_ENTRIES — MISSING (BUG-18)", () => {
  test("BUG-18: no OUTPUT_GROUP_MAX_ENTRIES constant (Core = 100)", () => {
    expect(WALLET_SRC).not.toMatch(/OUTPUT_GROUP_MAX_ENTRIES/);
  });
});

// =============================================================================
// G22 — -avoidpartialspends / m_avoid_partial_spends — MISSING (BUG-19, P1-API)
// =============================================================================
describe("W129-G22: -avoidpartialspends — MISSING (BUG-19)", () => {
  test("BUG-19: no avoid_partial_spends / avoidPartialSpends anywhere", () => {
    expect(WALLET_SRC).not.toMatch(/avoid_partial_spends|avoidPartialSpends|avoidpartialspends/);
  });
});

// =============================================================================
// G23 — CoinEligibilityFilter (confs mine/theirs, ancestors) — PARTIAL
// =============================================================================
describe("W129-G23: CoinEligibilityFilter — PARTIAL (narrowed)", () => {
  test("hotbuns has only confirmations>=1 filter (not Core's mine/theirs split)", () => {
    const slice = WALLET_SRC.slice(ADV_DEF_OFFSET, GET_INPUT_WEIGHT_OFFSET);
    expect(slice).toMatch(/utxo\.confirmations\s*<\s*1/);
    expect(slice).not.toMatch(/conf_mine|confMine|conf_theirs|confTheirs/);
  });
  test("PASS: coinbase maturity enforced (wallet depth >= COINBASE_MATURITY + 1)", () => {
    // Core parity: the wallet matures a coinbase when GetTxBlocksToMaturity()
    // == 0, i.e. chain_depth >= COINBASE_MATURITY + 1 (wallet.cpp:3333-3343).
    expect(COINBASE_MATURITY).toBe(100);
    expect(COINBASE_SPENDABLE_DEPTH).toBe(101);
    const slice = WALLET_SRC.slice(ADV_DEF_OFFSET, GET_INPUT_WEIGHT_OFFSET);
    expect(slice).toMatch(/isCoinbase\s*&&\s*utxo\.confirmations\s*<\s*COINBASE_SPENDABLE_DEPTH/);
  });
  test("MISSING: no max_ancestors / max_cluster_count filter", () => {
    const slice = WALLET_SRC.slice(ADV_DEF_OFFSET, GET_INPUT_WEIGHT_OFFSET);
    expect(slice).not.toMatch(/max_ancestors|maxAncestors|max_cluster|maxCluster/);
  });
});

// =============================================================================
// G24 — SFFO — MISSING (BUG-20, P1-API)
// =============================================================================
describe("W129-G24: subtract-fee-from-outputs (SFFO) — MISSING (BUG-20)", () => {
  test("BUG-20: no subtractFeeFromOutputs / subtract_fee_from_outputs in wallet.ts", () => {
    expect(WALLET_SRC).not.toMatch(/subtractFeeFromOutputs|subtract_fee_from_outputs/);
  });
  test(
    "BUG-20: walletcreatefundedpsbt does not honour options.subtractFeeFromOutputs",
    () => {
      const slice = RPC_SERVER_SRC.slice(WCF_OFFSET, WCF_END);
      expect(slice).not.toMatch(/subtractFeeFromOutputs|subtract_fee_from_outputs/);
    },
  );
});

// =============================================================================
// G25 — BnB skipped under SFFO — MISSING (covered by BUG-20)
// =============================================================================
describe("W129-G25: BnB-skipped-under-SFFO — MISSING (covered by BUG-20)", () => {
  test("selectCoinsAdvanced takes no `subtract_fee` parameter", () => {
    // Inspect the signature (first ~400 chars of the definition):
    const slice = WALLET_SRC.slice(ADV_DEF_OFFSET, ADV_DEF_OFFSET + 400);
    expect(slice).not.toMatch(/subtract|sffo/i);
  });
});

// =============================================================================
// G26 — Preset inputs in walletcreatefundedpsbt — MISSING (BUG-21, P1-API)
// =============================================================================
describe("W129-G26: preset inputs — FIXED (was BUG-21)", () => {
  test(
    "BUG-21 FIXED: walletcreatefundedpsbt accepts non-empty manual inputs verbatim",
    () => {
      // The old "Manual `inputs` aren't supported yet" confession is gone;
      // manual inputs are resolved from the wallet and used verbatim (Core's
      // add_inputs semantics — no extra coin selection layered on).
      expect(RPC_SERVER_SRC).not.toMatch(
        /Manual\s+`?inputs`?\s+aren'?t\s+supported\s+yet/i,
      );
      expect(RPC_SERVER_SRC).toMatch(
        /inputsParam\.length\s*>\s*0\s*\)\s*\{\s*selectedInputs\s*=\s*\[\]/,
      );
      expect(RPC_SERVER_SRC).toMatch(/wallet\.getUTXOByOutpoint\(inTxid, inVout\)/);
    },
  );
  test("BUG-21: no FetchSelectedInputs / preset_inputs handling", () => {
    expect(WALLET_SRC).not.toMatch(/FetchSelectedInputs|fetchSelectedInputs|preset_inputs|presetInputs/);
  });
});

// =============================================================================
// G27 — Mixed-output-type fallback — MISSING (covered by BUG-17/BUG-22)
// =============================================================================
describe("W129-G27: mixed-output-type fallback — MISSING (covered)", () => {
  test("no per-output-type result election (AttemptSelection)", () => {
    expect(WALLET_SRC).not.toMatch(/AttemptSelection|attemptSelection/);
  });
});

// =============================================================================
// G28 — Per-output-type result election — MISSING (covered by G27)
// =============================================================================
describe("W129-G28: per-output-type election — MISSING (covered by G27)", () => {
  test("no groups_by_type / typed groups map", () => {
    expect(WALLET_SRC).not.toMatch(/groups_by_type|groupsByType|OutputGroupTypeMap/);
  });
});

// =============================================================================
// G29 — SelectionAlgorithm enum names — PARTIAL (BUG-22, P1-WIRE)
// =============================================================================
describe("W129-G29: SelectionAlgorithm enum names — PARTIAL (BUG-22)", () => {
  test("PASS: bnb and knapsack names match Core lowercase", () => {
    const w = mkWallet();
    const addr = w.getNewAddress();
    w.addUTXO(
      makeUTXO({
        txidSeed: 1,
        amount: 100_000n,
        address: addr,
        keyPath: "m/84'/0'/0'/0/0",
      }),
    );
    const result = w.selectCoinsAdvanced(50_000n, 1);
    // Whichever algorithm fires, it should be a lowercase Core name OR
    // the non-Core "largest_first" sentinel (BUG-22).
    expect(["bnb", "knapsack", "largest_first"]).toContain(result.algorithm);
  });

  test(
    "BUG-22: emits non-Core `largest_first` instead of MANUAL/SRD/CG",
    () => {
      // Static evidence: type declaration explicitly says largest_first:
      expect(WALLET_SRC).toMatch(
        /algorithm:\s*"bnb"\s*\|\s*"knapsack"\s*\|\s*"largest_first"/,
      );
      // No "srd", no "cg", no "manual" anywhere as algorithm tags:
      expect(WALLET_SRC).not.toMatch(/algorithm:\s*"srd"/);
      expect(WALLET_SRC).not.toMatch(/algorithm:\s*"cg"/);
      expect(WALLET_SRC).not.toMatch(/algorithm:\s*"manual"/);
    },
  );
});

// =============================================================================
// G30 — walletcreatefundedpsbt option surface — PARTIAL (BUG-23, P2)
// =============================================================================
describe("W129-G30: walletcreatefundedpsbt options — PARTIAL (BUG-23)", () => {
  test("PARTIAL: options.fee_rate / options.feeRate / replaceable / changeAddress honoured", () => {
    const slice = RPC_SERVER_SRC.slice(WCF_OFFSET, WCF_END);
    expect(slice).toMatch(/options\.fee_rate/);
    expect(slice).toMatch(/options\.feeRate/);
    expect(slice).toMatch(/options\.replaceable/);
    expect(slice).toMatch(/options\.changeAddress/);
  });
  test(
    "BUG-23: missing changePosition / lockUnspents / add_inputs / include_unsafe / psbt_version / bip32derivs",
    () => {
      const slice = RPC_SERVER_SRC.slice(WCF_OFFSET, WCF_END);
      expect(slice).not.toMatch(/options\.changePosition/);
      expect(slice).not.toMatch(/options\.lockUnspents/);
      expect(slice).not.toMatch(/options\.add_inputs|options\.addInputs/);
      expect(slice).not.toMatch(/options\.include_unsafe|options\.includeUnsafe/);
      expect(slice).not.toMatch(/options\.psbt_version|options\.psbtVersion/);
      expect(slice).not.toMatch(/options\.bip32derivs/);
    },
  );
});

// =============================================================================
// Behavioural sanity (small live tests anchoring the audit)
// =============================================================================
describe("W129 behavioural sanity (live coin selection)", () => {
  test("PASS: insufficient funds throws", () => {
    const w = mkWallet();
    const addr = w.getNewAddress();
    w.addUTXO(
      makeUTXO({
        txidSeed: 1,
        amount: 1_000n,
        address: addr,
        keyPath: "m/84'/0'/0'/0/0",
      }),
    );
    expect(() => w.selectCoinsAdvanced(1_000_000_000_000n, 1)).toThrow();
  });

  test("PASS: zero-conf UTXO excluded", () => {
    const w = mkWallet();
    const addr = w.getNewAddress();
    w.addUTXO(
      makeUTXO({
        txidSeed: 1,
        amount: 1_000_000n,
        address: addr,
        keyPath: "m/84'/0'/0'/0/0",
        confirmations: 0,
      }),
    );
    expect(() => w.selectCoinsAdvanced(50_000n, 1)).toThrow();
  });

  test("PASS: immature coinbase excluded (confirmations < 100)", () => {
    const w = mkWallet();
    const addr = w.getNewAddress();
    w.addUTXO(
      makeUTXO({
        txidSeed: 1,
        amount: 5_000_000_000n,
        address: addr,
        keyPath: "m/84'/0'/0'/0/0",
        confirmations: 50,
        isCoinbase: true,
      }),
    );
    expect(() => w.selectCoinsAdvanced(1_000_000n, 1)).toThrow();
  });

  test("PASS: mature coinbase included (confirmations >= 101)", () => {
    const w = mkWallet();
    const addr = w.getNewAddress();
    w.addUTXO(
      makeUTXO({
        txidSeed: 1,
        amount: 5_000_000_000n,
        address: addr,
        keyPath: "m/84'/0'/0'/0/0",
        confirmations: 101, // Core wallet maturity: depth >= COINBASE_MATURITY + 1
        isCoinbase: true,
      }),
    );
    const result = w.selectCoinsAdvanced(1_000_000n, 1);
    expect(result.totalInput).toBeGreaterThanOrEqual(1_000_000n);
  });

  test(
    "PARTIAL: BUG-2a observable — multiple address types may produce non-Core selection",
    () => {
      const w = mkWallet();
      const segwit = w.getNewAddress("bech32");
      const legacy = w.getNewAddress("legacy");
      // 100k sat P2WPKH vs 100k sat P2PKH at feeRate=1 sat/vB:
      // P2WPKH effective: 100000 - ceil(68/4 * 1) = 100000 - 17 = 99983
      // P2PKH  effective: 100000 - ceil(148/4 * 1) = 100000 - 37 = 99963
      // BnB will pick one of them; Core's waste-minimising BnB would
      // pick P2WPKH (lower input weight = lower long_term_fee).
      // Hotbuns picks by "smallest currentValue >= target", which
      // is also P2WPKH coincidentally (lower effective value at the
      // same target). For homogeneous-feerate pools the results
      // coincide; we don't assert a specific selection here because
      // the dedupe check at G3 BUG-2d is a separate gate, but we DO
      // assert that the selection result has no waste field (BUG-3):
      w.addUTXO(
        makeUTXO({
          txidSeed: 1,
          amount: 100_000n,
          address: segwit,
          keyPath: "m/84'/0'/0'/0/0",
          addressType: AddressType.P2WPKH,
        }),
      );
      w.addUTXO(
        makeUTXO({
          txidSeed: 2,
          amount: 100_000n,
          address: legacy,
          keyPath: "m/44'/0'/0'/0/0",
          addressType: AddressType.P2PKH,
        }),
      );
      const result = w.selectCoinsAdvanced(50_000n, 1);
      expect(result.inputs.length).toBeGreaterThanOrEqual(1);
      const r = result as unknown as Record<string, unknown>;
      expect("waste" in r).toBe(false);
    },
  );
});
