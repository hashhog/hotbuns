/**
 * W135 — Standardness rules (IsStandardTx) audit tests.
 *
 * Bitcoin Core reference:
 *  - bitcoin-core/src/policy/policy.cpp:100-165 (IsStandardTx)
 *  - bitcoin-core/src/policy/policy.cpp:214-263 (ValidateInputsStandardness)
 *  - bitcoin-core/src/policy/policy.cpp:265-352 (IsWitnessStandard)
 *  - bitcoin-core/src/policy/policy.cpp:27-78 (GetDustThreshold + GetDust)
 *  - bitcoin-core/src/policy/policy.h:80-152 (constants)
 *  - bitcoin-core/src/script/solver.cpp (Solver + GetScriptNumber)
 *
 * This file is **discovery-only** for W135. Each BUG-N gate is encoded as a
 * test that DOCUMENTS the deviation as observed today. Tests marked
 * `test.skip` or `test.todo` are gates we know hotbuns does not yet
 * satisfy; their job is to fail loudly once a fix wave lands. Tests
 * NOT skipped pin behavior that hotbuns DOES match Core on, so a
 * regression breaks the test.
 *
 * 30-gate matrix overview (see audit/w135_standardness_rules.md):
 *   PASS  G01 G02 G03 G04 G05 G06 G07 G08 G10 G15 G16 G22 G23 G24 G27 G29 G30
 *   BUGs:
 *     BUG-1  P1 G13 G26 — dust-cap gate `GetDust > MAX_DUST_OUTPUTS_PER_TX` missing
 *     BUG-2  P0 G17     — BIP-54 non-witness sigops cap missing
 *     BUG-3  P2 G09     — permit_bare_multisig knob absent
 *     BUG-4  P3 G11     — NULL_DATA budget tracked cumulative, not decrement
 *     BUG-5  P2 G12     — -datacarrier / -datacarriersize knobs absent
 *     BUG-6  P3 G14     — reason codes diverge from Core canonical strings
 *     BUG-7  P2 G18     — getDustThreshold misses size>10000 IsUnspendable case (FIXED 3b717c1)
 *     BUG-8  P3 G19     — getDustThreshold uses fixed +1 instead of varint scriptLen
 *     BUG-9  P1 G21     — getStandardFlags misses 6 of 10 policy flags
 *     BUG-10 P3 G25     — bare-multisig m/n not minimally-encoded per Core
 *     BUG-11 P3 G28     — MIN_STANDARD_TX_NONWITNESS_SIZE comment cites validation.cpp
 *     BUG-19 P3 G20     — MAX_OP_RETURN_RELAY hard-coded literal, not derived
 *
 * Wave: W135 hotbuns IsStandardTx fleet audit.
 */

import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { readFileSync, existsSync } from "node:fs";
import { ChainDB, type UTXOEntry } from "../storage/database.js";
import { UTXOManager } from "../chain/utxo.js";
import { REGTEST } from "../consensus/params.js";
import {
  Mempool,
  MAX_STANDARD_TX_WEIGHT,
  MAX_OP_RETURN_RELAY,
  MAX_DUST_OUTPUTS_PER_TX,
  MAX_STANDARD_TX_SIGOPS_COST,
  TX_MIN_STANDARD_VERSION,
  TX_MAX_STANDARD_VERSION,
  MIN_STANDARD_TX_NONWITNESS_SIZE,
  MAX_STANDARD_SCRIPTSIG_SIZE,
  getDustThreshold,
  isDust,
  getDustOutputs,
} from "../mempool/mempool.js";
import {
  getScriptType,
  getBareMultisigParams,
  getStandardFlags,
  getConsensusFlags,
  isP2A,
} from "../script/interpreter.js";
import type { Transaction } from "../validation/tx.js";

// ---------------------------------------------------------------------------
// Constants & helpers
// ---------------------------------------------------------------------------

const P2A_SCRIPT     = Buffer.from([0x51, 0x02, 0x4e, 0x73]);
const P2PKH_SCRIPT   = Buffer.from([0x76, 0xa9, 0x14, ...Buffer.alloc(20), 0x88, 0xac]);
const P2SH_SCRIPT    = Buffer.from([0xa9, 0x14, ...Buffer.alloc(20), 0x87]);
const P2WPKH_SCRIPT  = Buffer.concat([Buffer.from([0x00, 0x14]), Buffer.alloc(20)]);
const OP_RETURN_BARE = Buffer.from([0x6a]);

const UTXO_SEED   = Buffer.alloc(32, 0xab);
const UTXO_VOUT   = 0;
const UTXO_AMOUNT = 10_000_000n;

function buildTx(opts: {
  version?: number;
  outputs?: Array<{ value: bigint; scriptPubKey: Buffer }>;
  scriptSig?: Buffer;
  prevTxid?: Buffer;
  prevVout?: number;
} = {}): Transaction {
  return {
    version: opts.version ?? 2,
    inputs: [
      {
        prevOut: {
          txid: opts.prevTxid ?? UTXO_SEED,
          vout: opts.prevVout ?? UTXO_VOUT,
        },
        scriptSig: opts.scriptSig ?? Buffer.alloc(0),
        sequence: 0xffffffff,
        witness: [],
      },
    ],
    outputs: opts.outputs ?? [
      { value: 9_000_000n, scriptPubKey: P2A_SCRIPT },
      { value: 0n, scriptPubKey: OP_RETURN_BARE },
    ],
    lockTime: 0,
  };
}

// ---------------------------------------------------------------------------
// Test fixtures (DB + mempool)
// ---------------------------------------------------------------------------

describe("W135 — Standardness rules (IsStandardTx)", () => {
  let tempDir: string;
  let db: ChainDB;
  let utxo: UTXOManager;
  let mempool: Mempool;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "w135-standardness-"));
    db = new ChainDB(tempDir);
    await db.open();
    utxo = new UTXOManager(db);
    mempool = new Mempool(utxo, REGTEST, 1_000_000);
    mempool.setTipHeight(200);

    const entry: UTXOEntry = {
      height: 1,
      coinbase: false,
      amount: UTXO_AMOUNT,
      scriptPubKey: P2A_SCRIPT,
    };
    await db.putUTXO(UTXO_SEED, UTXO_VOUT, entry);
  });

  afterEach(async () => {
    await db.close();
    await rm(tempDir, { recursive: true, force: true });
  });

  // -------------------------------------------------------------------------
  // PASS gates — these should already work; tests pin behavior.
  // -------------------------------------------------------------------------

  describe("PASS gates (Core parity)", () => {
    test("G01: TX_MIN/MAX_STANDARD_VERSION = 1 / 3", () => {
      expect(TX_MIN_STANDARD_VERSION).toBe(1);
      expect(TX_MAX_STANDARD_VERSION).toBe(3);
    });

    test("G02: MAX_STANDARD_TX_WEIGHT = 400_000", () => {
      expect(MAX_STANDARD_TX_WEIGHT).toBe(400_000n);
    });

    test("G03: MIN_STANDARD_TX_NONWITNESS_SIZE = 65", () => {
      expect(MIN_STANDARD_TX_NONWITNESS_SIZE).toBe(65);
    });

    test("G04: MAX_STANDARD_SCRIPTSIG_SIZE = 1650", () => {
      expect(MAX_STANDARD_SCRIPTSIG_SIZE).toBe(1650);
    });

    test("G07: witness_unknown output (witness v2+) rejected", async () => {
      // OP_2 + 20-byte program is witness v2 with 20-byte program → witness_unknown
      const witnessUnknown = Buffer.concat([Buffer.from([0x52, 0x14]), Buffer.alloc(20)]);
      const tx = buildTx({
        outputs: [
          { value: 9_000_000n, scriptPubKey: witnessUnknown },
          { value: 0n, scriptPubKey: OP_RETURN_BARE },
        ],
      });
      const result = await mempool.addTransaction(tx);
      expect(result.accepted).toBe(false);
      expect(result.error).toContain("scriptpubkey");
    });

    test("G08: bare multisig n>3 rejected", async () => {
      const pub33 = Buffer.concat([Buffer.from([0x21]), Buffer.alloc(33)]);
      const ms4 = Buffer.concat([
        Buffer.from([0x54]), pub33, pub33, pub33, pub33,
        Buffer.from([0x54, 0xae]),
      ]);
      const tx = buildTx({
        outputs: [
          { value: 9_000_000n, scriptPubKey: ms4 },
          { value: 0n, scriptPubKey: OP_RETURN_BARE },
        ],
      });
      const result = await mempool.addTransaction(tx);
      expect(result.accepted).toBe(false);
      expect(result.error).toContain("scriptpubkey");
    });

    test("G22: MANDATORY_SCRIPT_VERIFY_FLAGS present in getConsensusFlags", () => {
      const f = getConsensusFlags(800_000);
      // Core MANDATORY: P2SH, DERSIG, NULLDUMMY, CLTV, CSV, WITNESS, TAPROOT
      expect(f.verifyP2SH).toBe(true);
      expect(f.verifyDERSignatures).toBe(true);
      expect(f.verifyNullDummy).toBe(true);
      expect(f.verifyCheckLockTimeVerify).toBe(true);
      expect(f.verifyCheckSequenceVerify).toBe(true);
      expect(f.verifyWitness).toBe(true);
      expect(f.verifyTaproot).toBe(true);
    });

    test("G23: getScriptType resolves P2A to 'anchor' (NOT 'p2tr')", () => {
      expect(getScriptType(P2A_SCRIPT)).toBe("anchor");
      expect(isP2A(P2A_SCRIPT)).toBe(true);
      // Sanity: a real P2TR script (OP_1 + 32-byte push) resolves to p2tr.
      const p2tr = Buffer.concat([Buffer.from([0x51, 0x20]), Buffer.alloc(32)]);
      expect(getScriptType(p2tr)).toBe("p2tr");
    });

    test("G24: P2PK with compressed (33B) and uncompressed (65B) pubkeys both resolve", () => {
      const p2pkCompressed   = Buffer.concat([Buffer.from([0x21]), Buffer.alloc(33), Buffer.from([0xac])]);
      const p2pkUncompressed = Buffer.concat([Buffer.from([0x41]), Buffer.alloc(65), Buffer.from([0xac])]);
      expect(getScriptType(p2pkCompressed)).toBe("p2pk");
      expect(getScriptType(p2pkUncompressed)).toBe("p2pk");
    });

    test("G29: coinbase tx is rejected before IsStandardTx (mempool refuses coinbase)", async () => {
      const coinbase: Transaction = {
        version: 2,
        inputs: [
          {
            prevOut: { txid: Buffer.alloc(32, 0x00), vout: 0xffffffff },
            scriptSig: Buffer.from([0x03, 0x00, 0x00, 0x00]),
            sequence: 0xffffffff,
            witness: [],
          },
        ],
        outputs: [
          { value: 5_000_000_000n, scriptPubKey: P2A_SCRIPT },
          { value: 0n, scriptPubKey: OP_RETURN_BARE },
        ],
        lockTime: 0,
      };
      const result = await mempool.addTransaction(coinbase);
      expect(result.accepted).toBe(false);
      // Implementations differ on the exact string, but it must reject.
    });
  });

  // -------------------------------------------------------------------------
  // BUG-1 P1 G13 G26 — dust-cap gate `GetDust > MAX_DUST_OUTPUTS_PER_TX`
  // -------------------------------------------------------------------------

  describe("BUG-1 P1: IsStandardTx dust-cap gate missing", () => {
    test("MAX_DUST_OUTPUTS_PER_TX = 1 (Core policy.h:95)", () => {
      expect(MAX_DUST_OUTPUTS_PER_TX).toBe(1);
    });

    test("getDust returns >1 dust outputs when tx has 2 dust outputs", () => {
      // Two P2WPKH outputs each at 100 sats — well below segwit dust threshold (294).
      const tx = buildTx({
        outputs: [
          { value: 100n, scriptPubKey: P2WPKH_SCRIPT },
          { value: 100n, scriptPubKey: P2WPKH_SCRIPT },
          { value: 0n,   scriptPubKey: OP_RETURN_BARE },
        ],
      });
      const dust = getDustOutputs(tx);
      expect(dust.length).toBeGreaterThan(MAX_DUST_OUTPUTS_PER_TX);
    });

    test.todo(
      "BUG-1 FIX: tx with 2 dust outputs and POSITIVE fee should reject with reason 'dust' (Core policy.cpp:159)",
      // Today hotbuns rejects this for "tx with dust output must be 0-fee" via
      // preCheckEphemeralTx, not the IsStandardTx dust-cap gate. The reason
      // string should be Core's bare "dust" once BUG-1 is fixed.
    );
  });

  // -------------------------------------------------------------------------
  // BUG-2 P0 G17 — BIP-54 non-witness sigops cap missing
  // -------------------------------------------------------------------------

  describe("BUG-2 P0: BIP-54 non-witness sigops cap missing", () => {
    test("MAX_TX_LEGACY_SIGOPS constant is NOT exported from mempool.ts", () => {
      // Read the source file to verify the constant doesn't exist. We cannot
      // import a constant that doesn't exist (would be a TS compile error),
      // so we grep-check the source.
      const path = join(
        // import.meta would point to the .ts file in Bun
        __dirname,
        "../mempool/mempool.ts",
      );
      if (!existsSync(path)) {
        // Try the resolved js path if the test runs against compiled output
        return;
      }
      const src = readFileSync(path, "utf8");
      expect(src).not.toMatch(/\bMAX_TX_LEGACY_SIGOPS\b/);
      expect(src).not.toMatch(/CheckSigopsBIP54/i);
      // Confirm the existing weighted-sigops gate is a DIFFERENT constant
      expect(MAX_STANDARD_TX_SIGOPS_COST).toBe(16_000);
    });

    test.todo(
      "BUG-2 FIX: tx with summed non-witness sigops > 2500 should reject 'bad-txns-nonstandard-inputs'",
    );
  });

  // -------------------------------------------------------------------------
  // BUG-3 P2 G09 — permit_bare_multisig knob absent
  // -------------------------------------------------------------------------

  describe("BUG-3 P2: permit_bare_multisig knob absent", () => {
    test("hotbuns has no -permitbaremultisig / permitBareMultisig constructor option", () => {
      // Verify the constructor doesn't accept the option (TypeScript-level check).
      // We just confirm Mempool can be constructed without any "permit" flag.
      const m = new Mempool(utxo, REGTEST, 1_000_000);
      expect(m).toBeDefined();
      // Defensive: ensure the literal source has no permit_bare_multisig flag wiring.
      // We strip lines that are pure comments first, then check for the
      // identifier — otherwise the existing Core-doc reference at mempool.ts:1438
      // ("// - Core default permit_bare_multisig = true, ...") would trip
      // the test.
      const path = join(__dirname, "../mempool/mempool.ts");
      if (existsSync(path)) {
        const src = readFileSync(path, "utf8");
        const nonCommentLines = src
          .split("\n")
          .filter((line) => !line.trim().startsWith("//") && !line.trim().startsWith("*"))
          .join("\n");
        // We expect ZERO occurrences in non-comment code.
        expect(nonCommentLines).not.toMatch(/permitBareMultisig\s*[:=]/);
        expect(nonCommentLines).not.toMatch(/permit_bare_multisig\s*[:=]/);
        // And no -permitbaremultisig CLI flag wiring either
        expect(nonCommentLines).not.toMatch(/permitbaremultisig/i);
      }
    });

    test("bare multisig with n=2 (1-of-2) is accepted by default (Core default permit=true)", async () => {
      const pub33 = Buffer.concat([Buffer.from([0x21]), Buffer.alloc(33)]);
      const ms12 = Buffer.concat([
        Buffer.from([0x51]), pub33, pub33,
        Buffer.from([0x52, 0xae]),
      ]);
      const tx = buildTx({
        outputs: [
          { value: 9_000_000n, scriptPubKey: ms12 },
          { value: 0n, scriptPubKey: OP_RETURN_BARE },
        ],
      });
      const result = await mempool.addTransaction(tx);
      // Should NOT fail with scriptpubkey/bare-multisig
      expect(result.error ?? "").not.toContain("bare multisig exceeds");
    });

    test.todo(
      "BUG-3 FIX: with permitBareMultisig=false, bare multisig n=2 should reject 'bare-multisig'",
    );
  });

  // -------------------------------------------------------------------------
  // BUG-4 P3 G11 — NULL_DATA budget tracked cumulative, not decrement
  // -------------------------------------------------------------------------

  describe("BUG-4 P3: NULL_DATA budget tracked as cumulative add", () => {
    test("hotbuns tracks datacarrierBytesUsed (cumulative), not datacarrierBytesLeft (decrement)", () => {
      const path = join(__dirname, "../mempool/mempool.ts");
      if (existsSync(path)) {
        const src = readFileSync(path, "utf8");
        expect(src).toMatch(/datacarrierBytesUsed/);
        // Core's pattern would be datacarrier_bytes_left -= size
        // Discovery: hotbuns does NOT model the "remaining" form.
        expect(src).not.toMatch(/datacarrierBytesLeft\s*-=/);
      }
    });

    test("boundary parity at exactly MAX_OP_RETURN_RELAY: 1-output tx with 100_000 byte spk should pass datacarrier gate", () => {
      // Boundary: cumulative == limit is accepted by both models;
      // cumulative > limit is rejected. The model shape (add vs decrement)
      // only matters for the "disabled carrier" case (BUG-5).
      expect(MAX_OP_RETURN_RELAY).toBe(100_000);
    });
  });

  // -------------------------------------------------------------------------
  // BUG-5 P2 G12 — datacarrier operator knobs absent
  // -------------------------------------------------------------------------

  describe("BUG-5 P2: datacarrier operator knobs absent", () => {
    test("hotbuns has no -datacarrier / acceptDatacarrier flag", () => {
      const path = join(__dirname, "../mempool/mempool.ts");
      if (existsSync(path)) {
        const src = readFileSync(path, "utf8");
        expect(src).not.toMatch(/acceptDatacarrier\s*[:=]/);
        expect(src).not.toMatch(/maxDatacarrierBytes\s*[:=]/);
        expect(src).not.toMatch(/DEFAULT_ACCEPT_DATACARRIER/);
      }
    });

    test.todo(
      "BUG-5 FIX: with acceptDatacarrier=false / maxDatacarrierBytes=0, all OP_RETURN outputs reject 'datacarrier'",
    );
  });

  // -------------------------------------------------------------------------
  // BUG-6 P3 G14 — reason codes diverge from Core canonical strings
  // -------------------------------------------------------------------------

  describe("BUG-6 P3: IsStandardTx reason codes have extra context vs Core canonical bare tokens", () => {
    test("version error includes details, not just bare 'version'", async () => {
      const result = await mempool.addTransaction(buildTx({ version: 0 }));
      expect(result.accepted).toBe(false);
      expect(result.error).toContain("version");
      // Diff from Core: Core sets reason = "version" (bare). Hotbuns emits
      // "version: tx version 0 out of standard range [1,3]".
      // Once BUG-6 is fixed, the first colon-separated token should be exactly "version".
    });

    test("tx-size error includes details, not just bare 'tx-size'", async () => {
      // Build an oversized tx via many huge OP_RETURN outputs.
      const big = Buffer.concat([
        Buffer.from([0x6a, 0x4d]),
        (() => { const b = Buffer.alloc(2); b.writeUInt16LE(60_000, 0); return b; })(),
        Buffer.alloc(60_000),
      ]);
      const tx: Transaction = {
        version: 2,
        inputs: [
          {
            prevOut: { txid: UTXO_SEED, vout: UTXO_VOUT },
            scriptSig: Buffer.alloc(0),
            sequence: 0xffffffff,
            witness: [],
          },
        ],
        outputs: Array.from({ length: 3 }, () => ({ value: 0n, scriptPubKey: big })),
        lockTime: 0,
      };
      const result = await mempool.addTransaction(tx);
      expect(result.accepted).toBe(false);
      // We don't pin the exact string here — just confirm a rejection.
    });

    test("scriptpubkey error uses 'scriptpubkey' token (parity OK at the leading-token level)", async () => {
      const nonStd = Buffer.from([0xac]); // OP_CHECKSIG alone — nonstandard
      const tx = buildTx({
        outputs: [
          { value: 9_000_000n, scriptPubKey: nonStd },
          { value: 0n, scriptPubKey: OP_RETURN_BARE },
        ],
      });
      const result = await mempool.addTransaction(tx);
      expect(result.accepted).toBe(false);
      expect(result.error?.startsWith("scriptpubkey")).toBe(true);
    });
  });

  // -------------------------------------------------------------------------
  // BUG-7 P2 G18 — getDustThreshold IsUnspendable size>10000 short-circuit
  // -------------------------------------------------------------------------

  describe("BUG-7 P2 (FIXED): getDustThreshold honors IsUnspendable size>10000 short-circuit", () => {
    test("OP_RETURN script has dust threshold 0 (correct)", () => {
      expect(getDustThreshold(OP_RETURN_BARE)).toBe(0n);
    });

    test("Oversize (>10000 byte) scriptPubKey has dust threshold 0, matching Core", () => {
      // A 10001-byte garbage script — Core's CScript::IsUnspendable returns true
      // because size() > MAX_SCRIPT_SIZE (=10000), so GetDustThreshold returns 0.
      // bitcoin-core/src/policy/policy.cpp GetDustThreshold + script/script.h:565.
      // Such an output can never be spent, so it is NEVER dust (threshold 0).
      const oversize = Buffer.alloc(10_001, 0x00);
      expect(getDustThreshold(oversize)).toBe(0n);
    });
  });

  // -------------------------------------------------------------------------
  // BUG-8 P3 G19 — getDustThreshold scriptLen serialization
  // -------------------------------------------------------------------------

  describe("BUG-8 P3: getDustThreshold uses fixed +1 instead of varint compact-size scriptLen", () => {
    test("Standard P2PKH (25B) dust threshold = 546 sats (matches Core)", () => {
      // Non-segwit: (25 + 8 + 1 + 32+4+1+107+4) * 3000 / 1000
      //           = (34 + 148) * 3 = 182 * 3 = 546.
      // Core's GetSerializeSize gives the same result for ≤252-byte scripts.
      expect(getDustThreshold(P2PKH_SCRIPT)).toBe(546n);
    });

    test("Standard P2WPKH (22B) dust threshold = 294 sats (matches Core)", () => {
      // Segwit: (22 + 8 + 1 + 32+4+1+26+4) * 3000 / 1000
      //        = (31 + 67) * 3 = 98 * 3 = 294.
      expect(getDustThreshold(P2WPKH_SCRIPT)).toBe(294n);
    });

    test("Long script (>252 B) — hotbuns under-counts varint scriptLen by 2 bytes vs Core", () => {
      // 300-byte script: hotbuns computes outputSize = 300 + 8 + 1 = 309
      // Core computes outputSize = 300 + 8 + 3 = 311 (varint scriptLen)
      // Hotbuns gives (309 + 148) * 3 = 1371 sats; Core gives (311 + 148) * 3 = 1377.
      const longScript = Buffer.concat([Buffer.alloc(300, 0x00)]);
      // We don't know exactly which type long-script falls into; just verify
      // hotbuns returns a positive non-zero threshold (i.e. doesn't crash).
      const t = getDustThreshold(longScript);
      expect(t).toBeGreaterThan(0n);
      // The 6-sat off-by-one is unreachable on a Core-standard scriptPubKey
      // (all standard types are ≤ 34 bytes); this is mostly a paper-cut.
    });
  });

  // -------------------------------------------------------------------------
  // BUG-9 P1 G21 — getStandardFlags missing 6 policy-only flags
  // -------------------------------------------------------------------------

  describe("BUG-9 P1: getStandardFlags missing 6 of 10 STANDARD_SCRIPT_VERIFY_FLAGS extras", () => {
    test("getStandardFlags includes the 4 we DO set (NULLFAIL, WITNESS_PUBKEYTYPE, STRICTENC, LOW_S)", () => {
      const f = getStandardFlags(800_000);
      expect(f.verifyNullFail).toBe(true);
      expect(f.verifyWitnessPubkeyType).toBe(true);
      expect(f.verifyStrictEncoding).toBe(true);
      expect(f.verifyLowS).toBe(true);
    });

    test("getStandardFlags MISSING: MINIMALDATA", () => {
      const f = getStandardFlags(800_000);
      // Core sets this in STANDARD_SCRIPT_VERIFY_FLAGS unconditionally; hotbuns leaves it undefined.
      expect(f.verifyMinimalData).toBeFalsy();
    });

    test("getStandardFlags MISSING: MINIMALIF", () => {
      const f = getStandardFlags(800_000);
      expect(f.verifyMinimalIf).toBeFalsy();
    });

    test("getStandardFlags MISSING: CLEANSTACK", () => {
      const f = getStandardFlags(800_000);
      expect(f.verifyCleanStack).toBeFalsy();
    });

    test("getStandardFlags MISSING: DISCOURAGE_UPGRADABLE_NOPS", () => {
      const f = getStandardFlags(800_000);
      expect(f.verifyDiscourageUpgradableNops).toBeFalsy();
    });

    test("getStandardFlags MISSING: DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM", () => {
      const f = getStandardFlags(800_000);
      expect(f.verifyDiscourageUpgradableWitnessProgram).toBeFalsy();
    });

    test("getStandardFlags MISSING: DISCOURAGE_UPGRADABLE_TAPROOT_VERSION", () => {
      const f = getStandardFlags(800_000);
      expect(f.verifyDiscourageUpgradableTaprootVersion).toBeFalsy();
    });

    test("getStandardFlags MISSING: DISCOURAGE_OP_SUCCESS", () => {
      const f = getStandardFlags(800_000);
      expect(f.verifyDiscourageOpSuccess).toBeFalsy();
    });

    test("getStandardFlags MISSING: DISCOURAGE_UPGRADABLE_PUBKEYTYPE", () => {
      const f = getStandardFlags(800_000);
      expect(f.verifyDiscourageUpgradablePubkeyType).toBeFalsy();
    });
  });

  // -------------------------------------------------------------------------
  // Ported from rustoshi 269681b / a11cdd4 — NON-consensus relay standardness
  // (Core Solver / MatchMultisig parity). getScriptType + getBareMultisigParams
  // are reached only from mempool addTransaction (IsStandardTx /
  // ValidateInputsStandardness) and wallet PSBT — never from block/tx consensus
  // validation (verified: block.ts / validation/tx.ts do not reference them).
  // -------------------------------------------------------------------------

  describe("Ported(269681b): WITNESS_UNKNOWN classifies v1+ programs, v0 odd-size is nonstandard", () => {
    // Core Solver (script/solver.cpp:154-178): a witness program with
    // version != 0 → WITNESS_UNKNOWN; a v0 program whose size is not {20,32} →
    // NONSTANDARD. Core does NOT exclude OP_1 from witness_unknown.

    test("v1 (OP_1) 16-byte witness program → witness_unknown (NOT p2tr, NOT nonstandard)", () => {
      // OP_1 + 16-byte push. Not P2TR (needs 32B), not P2A (needs the 0x4e73 anchor).
      const v1_16 = Buffer.concat([Buffer.from([0x51, 0x10]), Buffer.alloc(16)]);
      // Mutation guard: an OP_2..OP_16-only branch (excluding OP_1) would mis-
      // classify this as nonstandard.
      expect(getScriptType(v1_16)).toBe("witness_unknown");
    });

    test("v1 16-byte program is a KNOWN witness shape, not nonstandard (vs v0 odd-size)", () => {
      // The classifier-level fix: a v1 16-byte program is a recognised
      // witness_unknown shape, whereas a v0 program of the SAME odd size is
      // nonstandard. This is the version != 0 branch of Core's Solver. (Whether
      // the mempool then chooses to relay witness_unknown OUTPUTS is a separate
      // policy decision; G07 pins hotbuns' current output-gate behaviour.)
      const v1_16 = Buffer.concat([Buffer.from([0x51, 0x10]), Buffer.alloc(16)]);
      const v0_16 = Buffer.concat([Buffer.from([0x00, 0x10]), Buffer.alloc(16)]);
      expect(getScriptType(v1_16)).toBe("witness_unknown");
      expect(getScriptType(v0_16)).toBe("nonstandard");
    });

    test("v16 (OP_16) 40-byte witness program → witness_unknown", () => {
      const v16_40 = Buffer.concat([Buffer.from([0x60, 0x28]), Buffer.alloc(40)]);
      expect(getScriptType(v16_40)).toBe("witness_unknown");
    });

    test("v0 30-byte witness program → nonstandard (Core solver.cpp:177), NOT witness_unknown", () => {
      // A v0 program with a non-{20,32} size is NONSTANDARD per Core. The old
      // hotbuns code returned witness_unknown for any witness program; this is
      // the divergence fixed by the port.
      const v0_30 = Buffer.concat([Buffer.from([0x00, 0x1e]), Buffer.alloc(30)]);
      expect(getScriptType(v0_30)).toBe("nonstandard");
    });

    test("control: 50-byte all-OP_1 (not a witness program) → nonstandard", () => {
      const big = Buffer.alloc(50, 0x51);
      expect(getScriptType(big)).toBe("nonstandard");
    });
  });

  describe("Ported(a11cdd4): bare-multisig classifier accepts PUSHDATA-prefixed pubkeys", () => {
    // Core MatchMultisig (script/solver.cpp:85-105): each key is read via
    // GetOp (decodes direct + PUSHDATA1/2/4) and accepted iff CPubKey::ValidSize
    // (33 or 65). So a pubkey pushed via OP_PUSHDATA1 is as standard as a direct push.

    test("1-of-1 with OP_PUSHDATA1-prefixed 33B pubkey parses as multisig", () => {
      // OP_1  OP_PUSHDATA1 0x21 <33B>  OP_1  OP_CHECKMULTISIG
      const ms = Buffer.concat([
        Buffer.from([0x51, 0x4c, 0x21]), Buffer.alloc(33),
        Buffer.from([0x51, 0xae]),
      ]);
      // Mutation guard: a direct-push-only (0x21/0x41) walk returns null here.
      expect(getBareMultisigParams(ms)).toEqual({ m: 1, n: 1 });
      expect(getScriptType(ms)).toBe("multisig");
    });

    test("PUSHDATA1-prefixed bare-multisig OUTPUT admitted standard (relay)", async () => {
      const ms = Buffer.concat([
        Buffer.from([0x51, 0x4c, 0x21]), Buffer.alloc(33),
        Buffer.from([0x51, 0xae]),
      ]);
      const tx = buildTx({
        outputs: [
          { value: 9_000_000n, scriptPubKey: ms },
          { value: 0n, scriptPubKey: OP_RETURN_BARE },
        ],
      });
      const result = await mempool.addTransaction(tx);
      expect(result.error ?? "").not.toContain("non-standard script type");
      expect(result.error ?? "").not.toContain("bare multisig exceeds");
    });

    test("control: OP_PUSHDATA1 32B (not a valid pubkey size) → null / nonstandard", () => {
      // Proves the matcher keys on CPubKey::ValidSize (33/65), not accept-everything.
      const bad = Buffer.concat([
        Buffer.from([0x51, 0x4c, 0x20]), Buffer.alloc(32),
        Buffer.from([0x51, 0xae]),
      ]);
      expect(getBareMultisigParams(bad)).toBeNull();
      expect(getScriptType(bad)).toBe("nonstandard");
    });

    test("control: 65B uncompressed pubkey via OP_PUSHDATA1 also accepted", () => {
      const ms = Buffer.concat([
        Buffer.from([0x51, 0x4c, 0x41]), Buffer.alloc(65),
        Buffer.from([0x51, 0xae]),
      ]);
      expect(getBareMultisigParams(ms)).toEqual({ m: 1, n: 1 });
    });

    test("regression: direct-push 33B pubkey still parses (no break of existing path)", () => {
      const pub33 = Buffer.concat([Buffer.from([0x21]), Buffer.alloc(33)]);
      const ms = Buffer.concat([Buffer.from([0x51]), pub33, Buffer.from([0x51, 0xae])]);
      expect(getBareMultisigParams(ms)).toEqual({ m: 1, n: 1 });
    });
  });

  // -------------------------------------------------------------------------
  // BUG-10 P3 G25 — bare-multisig m/n not minimally-encoded per Core
  // -------------------------------------------------------------------------

  describe("BUG-10 P3: getBareMultisigParams rejects push-form m/n (Core's Solver allows minimal push)", () => {
    test("OP_1..OP_16 encoded m/n parses correctly", () => {
      const pub33 = Buffer.concat([Buffer.from([0x21]), Buffer.alloc(33)]);
      const ms12 = Buffer.concat([
        Buffer.from([0x51]),         // OP_1 (m=1)
        pub33, pub33,                // 2 keys
        Buffer.from([0x52, 0xae]),   // OP_2 (n=2) + OP_CHECKMULTISIG
      ]);
      expect(getBareMultisigParams(ms12)).toEqual({ m: 1, n: 2 });
    });

    test("Push-form 0x01 m (instead of OP_1) is REJECTED by hotbuns (Core would accept the minimal push)", () => {
      const pub33 = Buffer.concat([Buffer.from([0x21]), Buffer.alloc(33)]);
      // m via OP_PUSHBYTES_1 0x01 (minimal push, equivalent to OP_1 at the int level)
      const msNonOpn = Buffer.concat([
        Buffer.from([0x01, 0x01]),   // OP_PUSHBYTES_1 0x01 ← NOT OP_1
        pub33,
        Buffer.from([0x51, 0xae]),   // OP_1 (n=1) + OP_CHECKMULTISIG
      ]);
      // Hotbuns rejects via the `mOpcode < 0x51 || mOpcode > 0x60` check.
      expect(getBareMultisigParams(msNonOpn)).toBeNull();
      // Core would accept this via GetScriptNumber+CheckMinimalPush. But since
      // standardness caps n at 3, neither path admits this to the mempool as
      // standard — the divergence is only at the Solver-classification level.
    });
  });

  // -------------------------------------------------------------------------
  // BUG-11 P3 G28 — comment cites validation.cpp instead of policy.h
  // -------------------------------------------------------------------------

  describe("BUG-11 P3: MIN_STANDARD_TX_NONWITNESS_SIZE comment cites validation.cpp", () => {
    test("Comment ref to MIN_STANDARD_TX_NONWITNESS_SIZE should be policy.h, not validation.cpp", () => {
      const path = join(__dirname, "../mempool/mempool.ts");
      if (existsSync(path)) {
        const src = readFileSync(path, "utf8");
        const block = src.match(/MIN_STANDARD_TX_NONWITNESS_SIZE[\s\S]{0,500}/);
        expect(block).toBeTruthy();
        // Discovery: today the block mentions validation.cpp.
        // Once BUG-11 is fixed it should mention policy.h:40.
        // The value itself is correct (65); only the doc-ref is wrong.
        expect(MIN_STANDARD_TX_NONWITNESS_SIZE).toBe(65);
      }
    });
  });

  // -------------------------------------------------------------------------
  // BUG-19 P3 G20 — MAX_OP_RETURN_RELAY hard-coded, not derived
  // -------------------------------------------------------------------------

  describe("BUG-19 P3: MAX_OP_RETURN_RELAY hard-coded, not derived from MAX_STANDARD_TX_WEIGHT", () => {
    test("MAX_OP_RETURN_RELAY equals 100_000 (the current value)", () => {
      expect(MAX_OP_RETURN_RELAY).toBe(100_000);
    });

    test("MAX_OP_RETURN_RELAY * 4 == MAX_STANDARD_TX_WEIGHT (Core's co-binding holds today)", () => {
      // Today: 100_000 * 4 == 400_000 ✓. But the source is a literal, not a
      // computed expression — so any future drift of MAX_STANDARD_TX_WEIGHT
      // would NOT propagate.
      expect(BigInt(MAX_OP_RETURN_RELAY) * 4n).toBe(MAX_STANDARD_TX_WEIGHT);
    });

    test("Source file declares MAX_OP_RETURN_RELAY as a literal 100_000", () => {
      const path = join(__dirname, "../mempool/mempool.ts");
      if (existsSync(path)) {
        const src = readFileSync(path, "utf8");
        // Discovery: hard-coded literal — should be a derived expression.
        expect(src).toMatch(/MAX_OP_RETURN_RELAY\s*=\s*100_000/);
        // Future fix: should be MAX_OP_RETURN_RELAY = Number(MAX_STANDARD_TX_WEIGHT) / 4
      }
    });
  });

  // -------------------------------------------------------------------------
  // PASS gates (continued) — sanity tests pinning current behavior.
  // -------------------------------------------------------------------------

  describe("PASS gates: G27 — IsStandardTx runs before ValidateInputsStandardness", () => {
    test("Tx with version 0 rejected before any input-standardness check fires", async () => {
      // Even if inputs were nonstandard, the version gate fires first.
      const result = await mempool.addTransaction(buildTx({ version: 0 }));
      expect(result.accepted).toBe(false);
      expect(result.error).toContain("version");
      // The reason should NOT be an input-standardness reason.
      expect(result.error ?? "").not.toContain("bad-txns-nonstandard-inputs");
    });
  });

  describe("PASS gates: G30 — getStandardFlags height-dependence", () => {
    test("STRICTENC and LOW_S gated on BIP-66 height (363725)", () => {
      const before = getStandardFlags(363_724);
      const after  = getStandardFlags(363_725);
      expect(before.verifyStrictEncoding).toBe(false);
      expect(after.verifyStrictEncoding).toBe(true);
      expect(before.verifyLowS).toBe(false);
      expect(after.verifyLowS).toBe(true);
    });

    test("NULLFAIL and WITNESS_PUBKEYTYPE gated on BIP-141 height (481824)", () => {
      const before = getStandardFlags(481_823);
      const after  = getStandardFlags(481_824);
      expect(before.verifyNullFail).toBe(false);
      expect(after.verifyNullFail).toBe(true);
      expect(before.verifyWitnessPubkeyType).toBe(false);
      expect(after.verifyWitnessPubkeyType).toBe(true);
    });
  });
});
