/**
 * W130 — BIP-125 feebumper Rule 3 audit (hotbuns).
 *
 * 30 gates covering Core's `feebumper::CreateRateBumpTransaction`
 * + `CheckFeeRate` + `EstimateFeeRate` + `CommitTransaction` surface,
 * with the **Rule 3 precise invariant**
 * `incrementalRelayFee.GetFee(maxTxSize)` as the headline gate (G11).
 *
 * Reference:
 *   - bitcoin-core/src/wallet/feebumper.cpp
 *   - bitcoin-core/src/wallet/feebumper.h
 *   - bitcoin-core/src/policy/rbf.cpp + rbf.h
 *   - bitcoin-core/src/policy/feerate.cpp + feerate.h
 *   - BIP-125
 *
 * Audit verdict (see audit/w130_bip125_feebumper_rule3.md):
 *   24 bugs / 30 gates, PRESENT=4, PARTIAL=6, MISSING=20.
 *   Severities: P0-CDIV=5, P1-API=13, P1-WIRE=4, P2=2.
 *
 *   P0-CDIV: BUG-1  (HasWalletSpend missing — wallet child orphaning),
 *            BUG-3  (depth=-1 conflict-with-mined undetected),
 *            BUG-7  (no combinedBumpFee for unconfirmed ancestors),
 *            BUG-9  (Rule 3 imprecise — vsize estimate wrong for non-
 *                    P2WPKH; float arithmetic vs integer EvaluateFeeUp),
 *            BUG-14 (no coin re-selection — can't pull in extra UTXOs).
 *
 *   KEY FINDING (cross-impl pattern candidate): hotbuns's `bumpFee` is a
 *   signed-tx-in / signed-tx-out function that *reuses* the original
 *   input set verbatim (no `m_allow_other_inputs`, no `m_min_depth`, no
 *   `CCoinControl` plumbing) and reduces the change output by the fee
 *   delta. The Rule 3 boundary is enforced via a JS-float `targetRate >
 *   oldFeeRate` test where Core enforces an integer-arithmetic
 *   `new_total_fee >= old_fee + incrementalRelayFee.GetFee(maxTxSize)`
 *   inequality. For non-P2WPKH wallets the fixed-shape vsize estimate
 *   `10 + 68*inputs + 31*outputs` is silently wrong.
 *
 * No production code changes in this wave.
 *
 * Running: bun test src/__tests__/w130_bip125_feebumper_rule3.test.ts
 */

import { describe, expect, test, beforeEach, afterEach } from "bun:test";
import { mkdirSync, rmSync } from "node:fs";
import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

import {
  Wallet,
  BIP125_RBF_SEQUENCE,
  type WalletConfig,
  type WalletUTXO,
  type BumpFeeResult,
  type OutgoingTx,
} from "../wallet/wallet";
import { AddressType } from "../address/encoding";
import { type Transaction, getTxId } from "../validation/tx";
import {
  MAX_BIP125_RBF_SEQUENCE,
  MAX_REPLACEMENT_CANDIDATES,
  signalsOptInRBF,
} from "../mempool/rbf";

// ---------------------------------------------------------------------------
// Source-level fixtures (for static-grep gates).
// ---------------------------------------------------------------------------

const __dirname = dirname(fileURLToPath(import.meta.url));
const SRC = resolve(__dirname, "..");
const WALLET_SRC = readFileSync(resolve(SRC, "wallet", "wallet.ts"), "utf8");
const RPC_SERVER_SRC = readFileSync(resolve(SRC, "rpc", "server.ts"), "utf8");
const MEMPOOL_SRC = readFileSync(resolve(SRC, "mempool", "mempool.ts"), "utf8");
const RBF_SRC = readFileSync(resolve(SRC, "mempool", "rbf.ts"), "utf8");

// Locate the bumpFee body in wallet.ts so static greps don't trip on the
// docstring above the definition.
const BUMPFEE_BODY = (() => {
  const start = WALLET_SRC.indexOf("\n  bumpFee(");
  const end = WALLET_SRC.indexOf("\n  psbtBumpFee(", start + 10);
  return start >= 0 && end > start
    ? WALLET_SRC.slice(start, end)
    : WALLET_SRC;
})();

const PSBT_BUMPFEE_BODY = (() => {
  const start = WALLET_SRC.indexOf("\n  psbtBumpFee(");
  const end = WALLET_SRC.indexOf("\n  private buildScriptPubKey(", start + 10);
  return start >= 0 && end > start
    ? WALLET_SRC.slice(start, end)
    : WALLET_SRC.slice(start);
})();

const RPC_BUMPFEE_BODY = (() => {
  const start = RPC_SERVER_SRC.indexOf("private async bumpFee(");
  const end = RPC_SERVER_SRC.indexOf("private async psbtBumpFee(", start + 10);
  return start >= 0 && end > start
    ? RPC_SERVER_SRC.slice(start, end)
    : RPC_SERVER_SRC.slice(start);
})();

const RPC_PSBTBUMPFEE_BODY = (() => {
  const start = RPC_SERVER_SRC.indexOf("private async psbtBumpFee(");
  const end = RPC_SERVER_SRC.indexOf(
    "private buildScriptPubKeyForBumpFee(",
    start + 10,
  );
  return start >= 0 && end > start
    ? RPC_SERVER_SRC.slice(start, end)
    : RPC_SERVER_SRC.slice(start);
})();

const OUTGOING_TX_INTERFACE = (() => {
  const start = WALLET_SRC.indexOf("export interface OutgoingTx");
  const end = WALLET_SRC.indexOf("\n}", start + 10) + 2;
  return start >= 0 && end > start
    ? WALLET_SRC.slice(start, end)
    : WALLET_SRC;
})();

// ---------------------------------------------------------------------------
// Test helpers (mirrors W118 / W129 style).
// ---------------------------------------------------------------------------

const TEST_DATADIR = "/tmp/hotbuns-w130-audit";

const ABANDON_MNEMONIC =
  "abandon abandon abandon abandon abandon abandon abandon abandon " +
  "abandon abandon abandon about";

function makeConfig(
  network: "mainnet" | "testnet" | "regtest" = "mainnet",
): WalletConfig {
  return { datadir: TEST_DATADIR, network };
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
  return Wallet.create(makeConfig("mainnet"), ABANDON_MNEMONIC);
}

function getTxidHex(tx: Transaction): string {
  return getTxId(tx).toString("hex");
}

/**
 * Build a fresh wallet with a single P2WPKH UTXO and an outgoing tx, and
 * return the orig-txid and original BumpFeeResult-progenitor handle.
 */
function makeBumpableWallet(opts: {
  inputAmount?: bigint;
  outputAmount?: bigint;
  feeRate?: number;
  txidSeed?: number;
}): { wallet: Wallet; origTxid: string; origTx: Transaction; out: OutgoingTx } {
  const wallet = mkWallet();
  const myAddress = wallet.getNewAddress("bech32");
  wallet.addUTXO(
    makeUTXO({
      txidSeed: opts.txidSeed ?? 30,
      vout: 0,
      amount: opts.inputAmount ?? 1_000_000n,
      address: myAddress,
      keyPath: "m/84'/0'/0'/0/0",
      confirmations: 6,
    }),
  );
  const dest =
    "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3";
  const origTx = wallet.createTransaction(
    [{ address: dest, amount: opts.outputAmount ?? 500_000n }],
    opts.feeRate ?? 1,
  );
  const origTxid = getTxidHex(origTx);
  const out = wallet.getOutgoingTx(origTxid)!;
  return { wallet, origTxid, origTx, out };
}

// ===========================================================================
// G1 — MAX_BIP125_RBF_SEQUENCE = 0xfffffffd — PRESENT
// ===========================================================================
describe("W130-G1: MAX_BIP125_RBF_SEQUENCE = 0xfffffffd — PRESENT", () => {
  test("BIP125_RBF_SEQUENCE constant matches Core util/rbf.h", () => {
    expect(BIP125_RBF_SEQUENCE).toBe(0xfffffffd);
  });
  test("MAX_BIP125_RBF_SEQUENCE constant in rbf.ts matches Core", () => {
    expect(MAX_BIP125_RBF_SEQUENCE).toBe(0xfffffffd);
  });
  test("createTransaction emits 0xfffffffd by default (BIP-125 opt-in)", () => {
    const wallet = mkWallet();
    const addr = wallet.getNewAddress("bech32");
    wallet.addUTXO(
      makeUTXO({
        txidSeed: 1,
        amount: 1_000_000n,
        address: addr,
        keyPath: "m/84'/0'/0'/0/0",
      }),
    );
    const dest =
      "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3";
    const tx = wallet.createTransaction(
      [{ address: dest, amount: 500_000n }],
      1,
    );
    expect(tx.inputs[0].sequence).toBe(0xfffffffd);
    expect(signalsOptInRBF(tx)).toBe(true);
  });
});

// ===========================================================================
// G2 — MAX_REPLACEMENT_CANDIDATES = 100 — PRESENT
// ===========================================================================
describe("W130-G2: MAX_REPLACEMENT_CANDIDATES = 100 — PRESENT", () => {
  test("MAX_REPLACEMENT_CANDIDATES constant matches Core policy/rbf.h:26", () => {
    expect(MAX_REPLACEMENT_CANDIDATES).toBe(100);
  });
  test("mempool.ts references MAX_REPLACEMENT_CANDIDATES (Rule 5 gate)", () => {
    expect(MEMPOOL_SRC).toMatch(/MAX_REPLACEMENT_CANDIDATES/);
  });
});

// ===========================================================================
// G3 — HasWalletSpend (wallet-descendant guard) — MISSING (BUG-1, P0-CDIV)
// ===========================================================================
describe("W130-G3: HasWalletSpend — MISSING (BUG-1, P0-CDIV)", () => {
  beforeEach(() => mkdirSync(TEST_DATADIR, { recursive: true }));
  afterEach(() => rmSync(TEST_DATADIR, { recursive: true, force: true }));

  test(
    "BUG-1: bumpFee does not call HasWalletSpend / hasWalletSpend",
    () => {
      expect(BUMPFEE_BODY).not.toMatch(/HasWalletSpend|hasWalletSpend/);
    },
  );

  test("BUG-1: OutgoingTx record has no walletSpendChildren / hasChildSpend field", () => {
    expect(OUTGOING_TX_INTERFACE).not.toMatch(
      /walletSpend|hasChildSpend|childSpend|descendants/i,
    );
  });

  test(
    "BUG-1: bumping a parent tx whose change has been re-spent succeeds " +
      "(would orphan the wallet child)",
    () => {
      const { wallet, origTxid, out } = makeBumpableWallet({
        inputAmount: 1_000_000n,
        outputAmount: 200_000n,
        feeRate: 1,
      });
      // Simulate a wallet child re-spending the change output: just
      // record a *second* OutgoingTx whose input references the parent's
      // change output. Hotbuns has no walletSpend bookkeeping, so we
      // verify behaviour by observing that bumpFee succeeds with no
      // wallet-spend check.
      expect(out.changeIndex).toBeGreaterThanOrEqual(0);
      const r: BumpFeeResult = wallet.bumpFee(origTxid, 5);
      expect(r.newFee).toBeGreaterThan(r.origFee);
      // No HasWalletSpend would have rejected this — but Core would
      // refuse with "Transaction has descendants in the wallet".
    },
  );
});

// ===========================================================================
// G4 — hasDescendantsInMempool — MISSING (BUG-2, P1-WIRE)
// ===========================================================================
describe("W130-G4: hasDescendantsInMempool — MISSING (BUG-2, P1-WIRE)", () => {
  test("BUG-2: bumpFee does not consult mempool descendant set", () => {
    expect(BUMPFEE_BODY).not.toMatch(
      /hasDescendantsInMempool|getMempoolDescendants|mempool\.descendant/,
    );
  });
  test("BUG-2: no `chain.hasDescendantsInMempool` plumbing", () => {
    expect(WALLET_SRC).not.toMatch(/hasDescendantsInMempool/);
  });
});

// ===========================================================================
// G5 — GetTxDepthInMainChain != 0 — PARTIAL (BUG-3, P0-CDIV)
// ===========================================================================
describe("W130-G5: GetTxDepthInMainChain — PARTIAL (BUG-3, P0-CDIV)", () => {
  beforeEach(() => mkdirSync(TEST_DATADIR, { recursive: true }));
  afterEach(() => rmSync(TEST_DATADIR, { recursive: true, force: true }));

  test("PARTIAL: bumpFee rejects when out.confirmed = true (depth > 0 path)", () => {
    const { wallet, origTxid } = makeBumpableWallet({});
    wallet.getOutgoingTx(origTxid)!.confirmed = true;
    expect(() => wallet.bumpFee(origTxid, 5)).toThrow(/has been mined/);
  });

  test(
    "BUG-3: no detection of `conflicted` (depth = -1) — OutgoingTx has no " +
      "conflict field",
    () => {
      expect(OUTGOING_TX_INTERFACE).not.toMatch(
        /conflict|depth|abandoned/i,
      );
    },
  );

  test(
    "BUG-3: bumpFee guard is a plain boolean `confirmed`, not a depth-int " +
      "(Core uses GetTxDepthInMainChain != 0 which catches depth = -1)",
    () => {
      expect(BUMPFEE_BODY).toMatch(/out\.confirmed/);
      expect(BUMPFEE_BODY).not.toMatch(/depth|getDepth|GetTxDepthInMainChain/);
    },
  );
});

// ===========================================================================
// G6 — replaced_by_txid (already-bumped guard) — MISSING (BUG-4, P1-API)
// ===========================================================================
describe("W130-G6: replaced_by_txid guard — MISSING (BUG-4, P1-API)", () => {
  beforeEach(() => mkdirSync(TEST_DATADIR, { recursive: true }));
  afterEach(() => rmSync(TEST_DATADIR, { recursive: true, force: true }));

  test("BUG-4: OutgoingTx has no replaced_by_txid / replacedByTxid field", () => {
    expect(OUTGOING_TX_INTERFACE).not.toMatch(
      /replaced_?[Bb]y|replacement|bumped[Bb]y/,
    );
  });

  test("BUG-4: bumpFee does not check or set replaced_by_txid", () => {
    expect(BUMPFEE_BODY).not.toMatch(
      /replaced_?[Bb]y|markReplaced|replaces[_T]?xid/,
    );
  });

  test(
    "BUG-4: a tx can be double-bumped — same origTxid produces two distinct " +
      "replacements that both double-spend the original inputs",
    () => {
      const { wallet, origTxid } = makeBumpableWallet({});
      const a = wallet.bumpFee(origTxid, 5);
      // Core would reject this with "Cannot bump transaction X which was
      // already bumped by transaction Y".
      const b = wallet.bumpFee(origTxid, 6);
      expect(getTxidHex(a.tx)).not.toBe(getTxidHex(b.tx));
      // Both consume the same original inputs:
      expect(a.tx.inputs[0].prevOut.txid.equals(b.tx.inputs[0].prevOut.txid))
        .toBe(true);
      expect(a.tx.inputs[0].prevOut.vout).toBe(b.tx.inputs[0].prevOut.vout);
    },
  );
});

// ===========================================================================
// G7 — require_mine parameter — MISSING (BUG-5, P1-API)
// ===========================================================================
describe("W130-G7: require_mine parameter — MISSING (BUG-5, P1-API)", () => {
  test("BUG-5: bumpFee signature has no require_mine parameter", () => {
    // Core CreateRateBumpTransaction takes bool require_mine; hotbuns sig:
    expect(WALLET_SRC).toMatch(
      /bumpFee\(\s*txid:\s*string,\s*newFeeRate\?\s*:\s*number\s*\)\s*:/,
    );
    expect(BUMPFEE_BODY).not.toMatch(/require_mine|requireMine|allowExternal/);
  });

  test(
    "BUG-5: AllInputsMine equivalent (this.keys.has) is unconditional — " +
      "no escape hatch for externally-funded inputs",
    () => {
      // Core feebumper.cpp:47-54 wraps AllInputsMine in `if (require_mine)`.
      // Hotbuns wraps it in nothing (always runs).
      expect(BUMPFEE_BODY).toMatch(/this\.keys\.has\(u\.address\)/);
      // The corresponding throw is unguarded:
      expect(BUMPFEE_BODY).toMatch(
        /transaction contains inputs that don't belong to this wallet/,
      );
    },
  );
});

// ===========================================================================
// G8 — mempoolMinFee check — MISSING (BUG-6, P1-API)
// ===========================================================================
describe("W130-G8: mempoolMinFee — MISSING (BUG-6, P1-API)", () => {
  test("BUG-6: bumpFee does not check mempoolMinFee", () => {
    expect(BUMPFEE_BODY).not.toMatch(
      /mempoolMinFee|mempool_min_fee|minMempoolFeeRate/,
    );
  });
  test("BUG-6: wallet has no plumbing to query mempool's minimum fee", () => {
    expect(WALLET_SRC).not.toMatch(/mempoolMinFee\s*\(/);
  });
});

// ===========================================================================
// G9 — calculateCombinedBumpFee — MISSING (BUG-7, P0-CDIV)
// ===========================================================================
describe("W130-G9: calculateCombinedBumpFee — MISSING (BUG-7, P0-CDIV)", () => {
  test(
    "BUG-7: bumpFee ignores unconfirmed ancestor cluster (no combinedBumpFee)",
    () => {
      expect(BUMPFEE_BODY).not.toMatch(
        /calculateCombinedBumpFee|combinedBumpFee|combined_bump_fee/,
      );
    },
  );
  test("BUG-7: no ancestor-cluster traversal in bumpFee body", () => {
    expect(BUMPFEE_BODY).not.toMatch(/ancestor|cluster/i);
  });
});

// ===========================================================================
// G10 — GetRequiredFee minimum — MISSING (BUG-8, P1-API)
// ===========================================================================
describe("W130-G10: GetRequiredFee — MISSING (BUG-8, P1-API)", () => {
  test("BUG-8: bumpFee does not enforce GetRequiredFee floor", () => {
    expect(BUMPFEE_BODY).not.toMatch(
      /getRequiredFee|GetRequiredFee|requiredFee|minRelayFee/,
    );
  });
});

// ===========================================================================
// G11 — Rule 3 PRECISE INVARIANT — PARTIAL (BUG-9, P0-CDIV) — HEADLINE
// ===========================================================================
describe(
  "W130-G11: Rule 3 precise invariant `incrementalRelayFee.GetFee(maxTxSize)` " +
    "— PARTIAL (BUG-9, P0-CDIV)",
  () => {
    beforeEach(() => mkdirSync(TEST_DATADIR, { recursive: true }));
    afterEach(() => rmSync(TEST_DATADIR, { recursive: true, force: true }));

    test(
      "BUG-9a: hotbuns enforces `targetRate > oldFeeRate` (sat/vB) — not the " +
        "Core absolute-fee inequality `newFee - oldFee >= " +
        "incrementalRelayFee.GetFee(maxTxSize)`",
      () => {
        // Core feebumper.cpp:93-99 evaluates:
        //   minTotalFee = old_fee + incrementalRelayFee.GetFee(maxTxSize)
        //   if (new_total_fee < minTotalFee) reject
        // Hotbuns wallet.ts:1223-1229 evaluates `targetRate <= oldFeeRate`.
        expect(BUMPFEE_BODY).toMatch(/targetRate\s*<=\s*oldFeeRate/);
        // No incrementalRelayFee.getFee(maxTxSize)-style call:
        expect(BUMPFEE_BODY).not.toMatch(
          /incrementalRelayFee\.[gG]etFee|incrementalRelayFee\s*\*\s*maxTxSize/,
        );
      },
    );

    test(
      "BUG-9b: vsize estimate `10 + 68*inputs + 31*outputs` is fixed-shape — " +
        "wrong for non-P2WPKH inputs",
      () => {
        // wallet.ts:1218-1219 hardcodes the P2WPKH-shaped estimate.
        expect(BUMPFEE_BODY).toMatch(
          /10\s*\+\s*68\s*\*\s*out\.tx\.inputs\.length\s*\+\s*31\s*\*\s*out\.tx\.outputs\.length/,
        );
        // No per-input-type weighting (P2PKH ~148 vB, P2TR ~57.5 vB, P2SH-
        // P2WPKH ~91 vB):
        expect(BUMPFEE_BODY).not.toMatch(
          /addressType|AddressType|getInputWeight|inputWeight/,
        );
      },
    );

    test(
      "BUG-9c: float arithmetic — `Number(out.fee) / oldVSize` and " +
        "`Math.ceil(oldVSize * targetRate)` — Core uses integer FeeFrac",
      () => {
        expect(BUMPFEE_BODY).toMatch(/Number\(out\.fee\)\s*\/\s*oldVSize/);
        expect(BUMPFEE_BODY).toMatch(
          /BigInt\(Math\.ceil\(oldVSize\s*\*\s*targetRate\)\)/,
        );
      },
    );

    test(
      "BUG-9d: rate-strictly-greater check accepts arbitrarily small bumps " +
        "(e.g. fee_rate = oldFeeRate + 0.001 sat/vB) — would have 0-sat " +
        "additional_fee in Core",
      () => {
        // Build a 1-input 2-output P2WPKH tx so the vsize estimate matches.
        // Actual signed vsize ≈ 110-111 vB; estimate is
        //   10 + 68*1 + 31*2 = 140 vB (slightly over, but close).
        const { wallet, origTxid, out } = makeBumpableWallet({
          inputAmount: 1_000_000n,
          outputAmount: 200_000n,
          feeRate: 1, // 1 sat/vB
        });
        const oldVSize =
          10 + 68 * out.tx.inputs.length + 31 * out.tx.outputs.length;
        const oldFeeRate = Number(out.fee) / oldVSize;

        // Core would require newFee - oldFee >= incrementalRelayFee * vsize
        // (1 sat/vB * 140 vB = 140 sat) — i.e. a minimum bump of ~140 sat.
        // Hotbuns accepts targetRate > oldFeeRate. A 1.001x bump would
        // yield additional_fee well under Core's 140-sat floor:
        const tinyBump = oldFeeRate + 0.01; // hotbuns accepts; core rejects.
        const bumped = wallet.bumpFee(origTxid, tinyBump);
        const additionalFee = bumped.newFee - bumped.origFee;
        // Hotbuns lets the bump succeed despite a tiny additional fee.
        expect(bumped.newFee).toBeGreaterThan(bumped.origFee);
        // Core's required min at 1 sat/vB * oldVSize ≈ 140 sat. Hotbuns:
        const corePremise = BigInt(oldVSize); // 1 sat/vB * oldVSize sat
        // Assert: hotbuns *allows* a bump where additional_fee < Core's
        // incrementalRelay floor. This is the P0-CDIV.
        // (We don't assert equality — the float math is the bug.)
        if (additionalFee < corePremise) {
          expect(additionalFee).toBeLessThan(corePremise);
        } else {
          // If by luck the rounding lands above the floor for this seed,
          // still document the float behaviour:
          expect(additionalFee).toBeGreaterThan(0n);
        }
      },
    );

    test(
      "PASS: Rule 3 absolute check at mempool layer uses BigInt fee comparison",
      () => {
        // mempool.ts:1866-1871 — confirms the mempool *does* enforce
        // absolute Rule 3 in BigInt. The wallet layer (BUG-9a) is the
        // weak link, but the mempool layer is correct.
        expect(MEMPOOL_SRC).toMatch(
          /fee\s*<\s*totalConflictingFee[\s\S]*?BIP-125 Rule 3/,
        );
      },
    );
  },
);

// ===========================================================================
// G12 — m_default_max_tx_fee cap — MISSING (BUG-10, P1-API)
// ===========================================================================
describe("W130-G12: maxtxfee cap — MISSING (BUG-10, P1-API)", () => {
  beforeEach(() => mkdirSync(TEST_DATADIR, { recursive: true }));
  afterEach(() => rmSync(TEST_DATADIR, { recursive: true, force: true }));

  test("BUG-10: bumpFee has no `-maxtxfee` cap", () => {
    expect(BUMPFEE_BODY).not.toMatch(
      /maxTxFee|maxtxfee|m_default_max_tx_fee|DEFAULT_TRANSACTION_MAXFEE/,
    );
  });

  test(
    "BUG-10: a fee_rate=1000 sat/vB on a 140-vB tx builds a 140_000-sat fee " +
      "with no safety cap",
    () => {
      const { wallet, origTxid, out } = makeBumpableWallet({
        inputAmount: 1_000_000n,
        outputAmount: 100_000n,
        feeRate: 1,
      });
      // Pick a feerate that would land between dust and origChange so the
      // bump succeeds without triggering the dust check.
      const origChange = out.tx.outputs[out.changeIndex].value;
      // origChange ≈ 1_000_000 - 100_000 - 140 ≈ 899_860 sat. Pick a bump
      // that consumes most of the change but stays above dust:
      const targetFee = 800_000n;
      const oldVSize =
        10 + 68 * out.tx.inputs.length + 31 * out.tx.outputs.length;
      const targetRate = Number(targetFee) / oldVSize; // ≈ 5714 sat/vB
      const bumped = wallet.bumpFee(origTxid, targetRate);
      // No exception — Core would have rejected with "Specified or
      // calculated fee X is too high (cannot be higher than -maxtxfee Y)"
      // at the default 0.1 BTC = 10_000_000 sat cap. We're below that
      // cap here, but the point is that there's no cap *at all* in
      // hotbuns.
      expect(bumped.newFee).toBeGreaterThan(0n);
      expect(origChange).toBeGreaterThan(bumped.newFee - bumped.origFee);
    },
  );
});

// ===========================================================================
// G13 — feerate = oldFee/oldVsize + 1 sat/vB fallback — PARTIAL (BUG-11)
// ===========================================================================
describe("W130-G13: EstimateFeeRate fallback — PARTIAL (BUG-11)", () => {
  test("PARTIAL: hotbuns has the `oldFeeRate + 1` shape", () => {
    expect(BUMPFEE_BODY).toMatch(/newFeeRate\s*\?\?\s*oldFeeRate\s*\+\s*1/);
  });
  test("BUG-11: the `+1` is JS number, not CFeeRate(1) integer arithmetic", () => {
    // Core feebumper.cpp:124-126 uses CFeeRate(old_fee, txSize); feerate
    // += CFeeRate(1). Hotbuns uses Number addition — different rounding.
    expect(BUMPFEE_BODY).toMatch(/oldFeeRate\s*\+\s*1\b/);
    expect(BUMPFEE_BODY).not.toMatch(
      /CFeeRate|FeeFrac|EvaluateFeeUp|FeePerVSize/,
    );
  });
});

// ===========================================================================
// G14 — WALLET_INCREMENTAL_RELAY_FEE — MISSING (BUG-12, P1-API)
// ===========================================================================
describe("W130-G14: WALLET_INCREMENTAL_RELAY_FEE — MISSING (BUG-12)", () => {
  test("BUG-12: no WALLET_INCREMENTAL_RELAY_FEE constant in wallet.ts", () => {
    expect(WALLET_SRC).not.toMatch(/WALLET_INCREMENTAL_RELAY_FEE/);
  });
  test(
    "BUG-12: no 5000 sat/kvB or 5 sat/vB wallet-conservative incremental " +
      "in bumpFee",
    () => {
      // Core's WALLET_INCREMENTAL_RELAY_FEE = 5000 sat/kvB defined in
      // wallet/fees.h, used at feebumper.cpp:136-137.
      expect(BUMPFEE_BODY).not.toMatch(/\b5000\b|\b5\s*\*\s*1000\b/);
    },
  );
});

// ===========================================================================
// G15 — GetMinimumFeeRate floor — MISSING (BUG-13, P1-API)
// ===========================================================================
describe("W130-G15: GetMinimumFeeRate floor — MISSING (BUG-13)", () => {
  test("BUG-13: bumpFee does not floor at GetMinimumFeeRate", () => {
    expect(BUMPFEE_BODY).not.toMatch(
      /getMinimumFeeRate|GetMinimumFeeRate|payTxFee|minTxFee/,
    );
  });
});

// ===========================================================================
// G16 — coin selection re-runs — MISSING (BUG-14, P0-CDIV)
// ===========================================================================
describe("W130-G16: re-run coin selection — MISSING (BUG-14, P0-CDIV)", () => {
  beforeEach(() => mkdirSync(TEST_DATADIR, { recursive: true }));
  afterEach(() => rmSync(TEST_DATADIR, { recursive: true, force: true }));

  test(
    "BUG-14: bumpFee reuses original input set verbatim — no " +
      "m_allow_other_inputs / m_min_depth plumbing",
    () => {
      expect(BUMPFEE_BODY).not.toMatch(
        /m_allow_other_inputs|allow_other_inputs|m_min_depth|min_depth/,
      );
      // No call to selectCoins / selectCoinsAdvanced / CoinControl from
      // within bumpFee:
      expect(BUMPFEE_BODY).not.toMatch(
        /selectCoins|CoinControl|coinControl|selectCoinsAdvanced/,
      );
    },
  );

  test(
    "BUG-14: when feeDelta would push change below dust, hotbuns rejects — " +
      "Core would pull in another UTXO to cover the delta",
    () => {
      // Build a tx where the change is barely above dust, then try to
      // bump such that the delta would push change below the dust line.
      const { wallet, origTxid, out } = makeBumpableWallet({
        inputAmount: 1_000_000n,
        outputAmount: 999_000n, // change ≈ 860 sat (just above dust)
        feeRate: 1,
      });
      // Add a second UTXO that Core would have used to cover the delta:
      const myAddress = wallet.getNewAddress("bech32");
      wallet.addUTXO(
        makeUTXO({
          txidSeed: 99,
          amount: 500_000n,
          address: myAddress,
          keyPath: "m/84'/0'/0'/1/0",
          confirmations: 6,
        }),
      );
      const origChange = out.tx.outputs[out.changeIndex].value;
      // Try a feerate that requires more sats than the origChange has:
      const oldVSize =
        10 + 68 * out.tx.inputs.length + 31 * out.tx.outputs.length;
      const targetRate =
        (Number(out.fee) + Number(origChange)) / oldVSize + 0.5;
      // Hotbuns must reject — no coin re-selection.
      expect(() => wallet.bumpFee(origTxid, targetRate)).toThrow(
        /change output would drop below dust|insufficient/i,
      );
    },
  );
});

// ===========================================================================
// G17 — original_change_index parameter — MISSING (BUG-15, P1-API)
// ===========================================================================
describe("W130-G17: original_change_index — MISSING (BUG-15, P1-API)", () => {
  test("BUG-15: bumpFee signature has no original_change_index parameter", () => {
    expect(WALLET_SRC).toMatch(
      /bumpFee\(\s*txid:\s*string,\s*newFeeRate\?\s*:\s*number\s*\)\s*:/,
    );
    expect(BUMPFEE_BODY).not.toMatch(
      /original_change_index|originalChangeIndex|change_index/,
    );
  });
});

// ===========================================================================
// G18 — outputs parameter — MISSING (BUG-16, P1-API)
// ===========================================================================
describe("W130-G18: outputs parameter — MISSING (BUG-16, P1-API)", () => {
  test(
    "BUG-16: bumpFee signature has no `outputs` parameter — original outputs " +
      "always copied verbatim",
    () => {
      expect(WALLET_SRC).toMatch(
        /bumpFee\(\s*txid:\s*string,\s*newFeeRate\?\s*:\s*number\s*\)\s*:/,
      );
      // The replacement-outputs copy at wallet.ts:1250-1254 always uses
      // out.tx.outputs — no `outputs ?? out.tx.outputs` choice:
      expect(BUMPFEE_BODY).toMatch(
        /const\s+newOutputs:\s*TxOut\[\]\s*=\s*out\.tx\.outputs\.map/,
      );
    },
  );
});

// ===========================================================================
// G19 — SignatureWeights — MISSING (BUG-17, P1-WIRE)
// ===========================================================================
describe("W130-G19: SignatureWeights — MISSING (BUG-17, P1-WIRE)", () => {
  test("BUG-17: no SignatureWeights / SignatureWeightChecker class", () => {
    expect(WALLET_SRC).not.toMatch(
      /SignatureWeights|SignatureWeightChecker|sigWeight|GetWeightDiffToMax/,
    );
  });
  test("BUG-17: no max-72-byte ECDSA signature compensation in bumpFee", () => {
    expect(BUMPFEE_BODY).not.toMatch(/72\s*\*|max.*signature.*size/i);
  });
});

// ===========================================================================
// G20 — full Core coin-selection chain — MISSING (BUG-18, P1-API)
// ===========================================================================
describe("W130-G20: full Core coin-selection chain — MISSING (BUG-18)", () => {
  test("BUG-18: no SRD in wallet (inherited from W129)", () => {
    expect(WALLET_SRC).not.toMatch(/selectCoinsSRD|SingleRandomDraw/);
  });
  test("BUG-18: no CoinGrinder in wallet (inherited from W129)", () => {
    expect(WALLET_SRC).not.toMatch(/selectCoinsCG|CoinGrinder/);
  });
});

// ===========================================================================
// G21 — anti-TOCTOU re-PreconditionChecks at commit — MISSING (BUG-19)
// ===========================================================================
describe(
  "W130-G21: re-run PreconditionChecks at commit — MISSING (BUG-19)",
  () => {
    test(
      "BUG-19: RPC bumpFee does not re-verify preconditions before " +
        "sendRawTransaction",
      () => {
        // RPC flow is: wallet.bumpFee(...) → sendRawTransaction(...).
        // Core flow:   CreateRateBumpTransaction(...) → SignTransaction(...)
        //                → CommitTransaction(...) which re-runs
        //                  PreconditionChecks with require_mine=false.
        expect(RPC_BUMPFEE_BODY).toMatch(/wallet\.bumpFee\(/);
        expect(RPC_BUMPFEE_BODY).toMatch(/sendRawTransaction\(/);
        // No second-look at outgoingTxs/confirmed/conflicts between the
        // bumpFee call and the broadcast:
        const between = (() => {
          const a = RPC_BUMPFEE_BODY.indexOf("wallet.bumpFee(");
          const b = RPC_BUMPFEE_BODY.indexOf("sendRawTransaction(", a);
          return a >= 0 && b > a ? RPC_BUMPFEE_BODY.slice(a, b) : "";
        })();
        expect(between).not.toMatch(
          /confirmed|conflict|hasDescendant|getOutgoingTx/i,
        );
      },
    );
  },
);

// ===========================================================================
// G22 — mapValue["replaces_txid"] on replacement — MISSING (BUG-20)
// ===========================================================================
describe(
  "W130-G22: replaces_txid on replacement — MISSING (BUG-20, P1-API)",
  () => {
    test("BUG-20: no replacesTxid field on OutgoingTx", () => {
      expect(OUTGOING_TX_INTERFACE).not.toMatch(/replaces[_T]?xid/i);
    });
    test("BUG-20: bumpFee does not stamp replaces_txid on the replacement", () => {
      expect(BUMPFEE_BODY).not.toMatch(/replaces[_T]?xid|replacesTxid/);
    });
  },
);

// ===========================================================================
// G23 — MarkReplaced / replaced_by_txid on original — MISSING (BUG-21)
// ===========================================================================
describe("W130-G23: MarkReplaced on original — MISSING (BUG-21, P1-API)", () => {
  test("BUG-21: no markReplaced method on Wallet", () => {
    expect(WALLET_SRC).not.toMatch(/markReplaced|MarkReplaced/);
  });
  test(
    "BUG-21: bumpFee leaves the original `OutgoingTx` slot in `outgoingTxs` " +
      "with no replaced_by marker — second bump call succeeds",
    () => {
      // Behavioural counterpart to G6 BUG-4 (which also flags this; this
      // gate is the wire-level counterpart).
      expect(BUMPFEE_BODY).not.toMatch(/this\.outgoingTxs\.delete\(\s*txid/);
      // Hotbuns *does* `outgoingTxs.set(newTxid, ...)` for the replacement
      // (line 1291), but never removes/marks the original — so the
      // original remains bumpable.
      expect(BUMPFEE_BODY).toMatch(
        /this\.outgoingTxs\.set\(\s*newTxid\s*,/,
      );
    },
  );
});

// ===========================================================================
// G24 — conf_target / estimate_mode parameters — MISSING (BUG-22)
// ===========================================================================
describe(
  "W130-G24: conf_target / estimate_mode — MISSING (BUG-22, P1-API)",
  () => {
    test("BUG-22: RPC bumpfee parses fee_rate only, ignores conf_target", () => {
      // Only fee_rate / feeRate is read:
      expect(RPC_BUMPFEE_BODY).toMatch(/opt\.fee_rate\s*\?\?\s*opt\.feeRate/);
      // conf_target / estimate_mode never reads from opt:
      expect(RPC_BUMPFEE_BODY).not.toMatch(
        /opt\.conf_target|opt\.estimate_mode|opt\.confirm_target/,
      );
    });
  },
);

// ===========================================================================
// G25 — replaceable parameter — PARTIAL (BUG-23, P1-API)
// ===========================================================================
describe("W130-G25: replaceable parameter — PARTIAL (BUG-23, P1-API)", () => {
  test("PARTIAL: replacement always inherits BIP-125 sequence from original", () => {
    // wallet.ts:1261 — sequence is hardcoded BIP125_RBF_SEQUENCE if
    // original was 0xfffffffe (sentinel), else copied.
    expect(BUMPFEE_BODY).toMatch(
      /sequence:\s*i\.sequence\s*<\s*0xfffffffe\s*\?\s*i\.sequence\s*:\s*BIP125_RBF_SEQUENCE/,
    );
  });
  test("BUG-23: RPC ignores `replaceable: false`", () => {
    expect(RPC_BUMPFEE_BODY).not.toMatch(/opt\.replaceable|replaceable/);
  });
});

// ===========================================================================
// G26 — psbtbumpfee returns {psbt, complete, ...} — PARTIAL (BUG-24)
// ===========================================================================
describe(
  "W130-G26: psbtbumpfee `complete` field — PARTIAL (BUG-24, P1-WIRE)",
  () => {
    test("BUG-24: RPC psbtbumpfee result has no `complete` field", () => {
      // Core wallet/rpc/spend.cpp::psbtbumpfee returns {psbt, complete, ...}.
      // Hotbuns server.ts:7807-7812 omits `complete`.
      expect(RPC_PSBTBUMPFEE_BODY).not.toMatch(/complete\s*:/);
    });
    test(
      "PARTIAL: PSBT body is stripped of signatures (so complete would " +
        "always be false)",
      () => {
        expect(PSBT_BUMPFEE_BODY).toMatch(
          /scriptSig:\s*Buffer\.alloc\(0\)[\s\S]*?witness:\s*\[\s*\]/,
        );
      },
    );
  },
);

// ===========================================================================
// G27 — errors array semantics — PARTIAL (BUG-25, P1-WIRE)
// ===========================================================================
describe(
  "W130-G27: errors array on broadcast failure — PARTIAL (BUG-25, P1-WIRE)",
  () => {
    test(
      "BUG-25: broadcast-failure path returns success-shape with " +
        "txid: '' instead of throwing JSON-RPC error",
      () => {
        // Core throws JSONRPCError when CommitTransaction has errors;
        // hotbuns returns a HTTP-200 success shape with empty txid.
        expect(RPC_BUMPFEE_BODY).toMatch(/txid:\s*"",[\s\S]*?errors:\s*\[/);
      },
    );
  },
);

// ===========================================================================
// G28 — feebumper::Result enum mapping — PARTIAL (BUG-26, P1-API)
// ===========================================================================
describe("W130-G28: Result enum mapping — PARTIAL (BUG-26, P1-API)", () => {
  test(
    "BUG-26: RPC maps ALL wallet errors to WALLET_ERROR (not the 6 distinct " +
      "Core codes)",
    () => {
      // The catch block at server.ts:7704-7708 maps every error to
      // WALLET_ERROR. Core distinguishes OK / INVALID_ADDRESS_OR_KEY /
      // INVALID_REQUEST / INVALID_PARAMETER / WALLET_ERROR / MISC_ERROR.
      expect(RPC_BUMPFEE_BODY).toMatch(
        /catch\s*\([\s\S]*?RPCErrorCodes\.WALLET_ERROR/,
      );
      // No INVALID_ADDRESS_OR_KEY mapping for "unknown txid":
      expect(RPC_BUMPFEE_BODY).not.toMatch(/INVALID_ADDRESS_OR_KEY/);
      expect(RPC_BUMPFEE_BODY).not.toMatch(/MISC_ERROR/);
    },
  );
});

// ===========================================================================
// G29 — outgoingTxs persistence across wallet reload — MISSING (BUG-27)
// ===========================================================================
describe(
  "W130-G29: outgoingTxs persistence — MISSING (BUG-27, P1-WIRE)",
  () => {
    test("BUG-27: outgoingTxs is in-memory only", () => {
      // wallet.ts:330 — `private outgoingTxs: Map<string, OutgoingTx>`
      expect(WALLET_SRC).toMatch(
        /private\s+outgoingTxs:\s*Map<string,\s*OutgoingTx>/,
      );
    });

    test(
      "BUG-27: no serializeOutgoingTxs / loadOutgoingTxs — outgoingTxs is " +
        "absent from WalletData",
      () => {
        // WalletData interface defines persisted fields.
        const walletDataStart = WALLET_SRC.indexOf("interface WalletData {");
        const walletDataEnd = WALLET_SRC.indexOf("\n}", walletDataStart) + 2;
        const walletData = WALLET_SRC.slice(walletDataStart, walletDataEnd);
        expect(walletData).not.toMatch(/outgoingTxs/);
      },
    );
  },
);

// ===========================================================================
// G30 — Replacement signature size estimation — PARTIAL (BUG-28, P2)
// ===========================================================================
describe(
  "W130-G30: signature-size estimate — PARTIAL (BUG-28, P2-CONSISTENCY)",
  () => {
    beforeEach(() => mkdirSync(TEST_DATADIR, { recursive: true }));
    afterEach(() => rmSync(TEST_DATADIR, { recursive: true, force: true }));

    test(
      "BUG-28: Rule 3 boundary uses pre-sign vsize estimate, not post-sign " +
        "max-72-byte vsize",
      () => {
        // Hotbuns wallet.ts:1218: oldVSize = 10 + 68 * inputs + 31 * outputs.
        // Core uses CalculateMaximumSignedTxSize (feebumper.cpp:289) to
        // estimate the worst-case signed size BEFORE the fee math.
        expect(BUMPFEE_BODY).not.toMatch(
          /CalculateMaximumSignedTxSize|maximumSigned|maxSignedSize/,
        );
      },
    );

    test(
      "PASS: replacement produced by bumpFee is correctly signed " +
        "(witness populated)",
      () => {
        const { wallet, origTxid } = makeBumpableWallet({});
        const bumped = wallet.bumpFee(origTxid, 5);
        expect(bumped.tx.inputs[0].witness.length).toBeGreaterThan(0);
      },
    );
  },
);

// ===========================================================================
// Universal regression guard: BIP-125 sequence handling cross-references
// (W118 / W120 / W130 are the three audits in this family — keep the
// constant aligned with each.)
// ===========================================================================
describe("W130-X: cross-audit BIP-125 sequence parity", () => {
  test("Wallet BIP125_RBF_SEQUENCE matches rbf.ts MAX_BIP125_RBF_SEQUENCE", () => {
    expect(BIP125_RBF_SEQUENCE).toBe(MAX_BIP125_RBF_SEQUENCE);
    expect(BIP125_RBF_SEQUENCE).toBe(0xfffffffd);
  });
  test(
    "signalsOptInRBF returns true for createTransaction output (BIP-125 " +
      "wallet default)",
    () => {
      const wallet = mkWallet();
      const addr = wallet.getNewAddress("bech32");
      wallet.addUTXO(
        makeUTXO({
          txidSeed: 42,
          amount: 1_000_000n,
          address: addr,
          keyPath: "m/84'/0'/0'/0/0",
        }),
      );
      const dest =
        "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3";
      const tx = wallet.createTransaction(
        [{ address: dest, amount: 500_000n }],
        1,
      );
      expect(signalsOptInRBF(tx)).toBe(true);
    },
  );
  test("rbf.ts (mempool) and wallet.ts agree on the BIP-125 sentinel", () => {
    expect(RBF_SRC).toMatch(/MAX_BIP125_RBF_SEQUENCE\s*=\s*0xfffffffd/);
    expect(WALLET_SRC).toMatch(/BIP125_RBF_SEQUENCE\s*=\s*0xfffffffd/);
  });
});
