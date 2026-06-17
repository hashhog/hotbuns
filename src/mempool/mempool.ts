/**
 * Transaction mempool: unconfirmed transaction storage and eviction.
 *
 * Manages the pool of unconfirmed transactions waiting to be included in blocks.
 * Validates transactions, tracks dependencies between mempool transactions,
 * enforces fee-rate minimums, and evicts low-fee transactions when full.
 *
 * Uses cluster mempool architecture: transactions are organized into clusters
 * (connected components of the dependency graph) and each cluster is linearized
 * for optimal fee-rate ordering.
 */

import { EventEmitter } from "events";
import type { UTXOEntry } from "../storage/database.js";
import type { UTXOManager } from "../chain/utxo.js";
import type { ConsensusParams } from "../consensus/params.js";
import type { Block } from "../validation/block.js";
import {
  getTransactionSigOpCost,
  WITNESS_SCALE_FACTOR,
  countScriptSigOps,
} from "../validation/block.js";
import type { Transaction, OutPoint, UTXOConfirmation } from "../validation/tx.js";
import {
  validateTxBasic,
  getTxId,
  getWTxId,
  getTxWeight,
  getTxVSize,
  isCoinbase,
  serializeTx,
  checkSequenceLocks,
} from "../validation/tx.js";
import { isFinalTx } from "../mining/template.js";
import { sha256Hash } from "../crypto/primitives.js";
import {
  verifyScript,
  getConsensusFlags,
  getStandardFlags,
  isP2A,
  isP2SH,
  isP2WSH,
  isP2TR,
  isWitnessProgram,
  isPushOnly,
  getScriptType,
  getBareMultisigParams,
  type ScriptFlags,
} from "../script/interpreter.js";
import { sigHashLegacy, sigHashWitnessV0 } from "../validation/tx.js";
import {
  shouldSkipScripts,
  type AssumeValidBlockEntry,
} from "../consensus/assumevalid.js";
import {
  signalsOptInRBF,
  isRBFOptIn,
  entriesAndTxidsDisjoint,
  RBFTransactionState,
  MAX_BIP125_RBF_SEQUENCE,
  MAX_REPLACEMENT_CANDIDATES,
} from "./rbf.js";

/**
 * Maximum cluster count: maximum number of transactions in a cluster.
 * Bitcoin Core: policy/policy.h DEFAULT_CLUSTER_LIMIT = 64.
 * Reference: bitcoin-core/src/policy/policy.h:72
 */
export const MAX_CLUSTER_COUNT = 64;

/**
 * Maximum cluster size in vbytes.
 * Bitcoin Core: kernel/mempool_limits.h cluster_size_vbytes = DEFAULT_CLUSTER_SIZE_LIMIT_KVB * 1000 = 101,000.
 * Reference: bitcoin-core/src/policy/policy.h:74 (DEFAULT_CLUSTER_SIZE_LIMIT_KVB = 101)
 */
export const MAX_CLUSTER_SIZE_VBYTES = 101_000;

/**
 * @deprecated Use MAX_CLUSTER_COUNT instead.
 * Kept for backward-compat with existing imports in cluster_mempool.test.ts.
 */
export const MAX_CLUSTER_SIZE = MAX_CLUSTER_COUNT;

/**
 * Default dust relay fee rate in sat/kvB.
 * Used to calculate the dust threshold for outputs.
 */
const DUST_RELAY_FEE = 3000;

/**
 * Maximum number of dust outputs allowed per transaction.
 * Per ephemeral anchor policy, only one dust output is allowed.
 */
export const MAX_DUST_OUTPUTS_PER_TX = 1;

// ============================================================================
// IsStandardTx policy constants (mirrors bitcoin-core/src/policy/policy.h)
// ============================================================================

/**
 * Minimum standard transaction version (policy.h TX_MIN_STANDARD_VERSION = 1).
 * Version 0 is non-standard.
 */
export const TX_MIN_STANDARD_VERSION = 1;

/**
 * Maximum standard transaction version (policy.h TX_MAX_STANDARD_VERSION = 3).
 * Version > 3 is non-standard. TRUC uses version 3 (BIP-431).
 */
export const TX_MAX_STANDARD_VERSION = 3;

/**
 * Minimum non-witness serialized size for a standard transaction (65 bytes).
 * Mitigates CVE-2017-12842 (64-byte transaction / merkle-branch confusion).
 * Bitcoin Core: validation.cpp MIN_STANDARD_TX_NONWITNESS_SIZE = 65.
 */
export const MIN_STANDARD_TX_NONWITNESS_SIZE = 65;

/**
 * Maximum scriptSig size in bytes per input (policy.h MAX_STANDARD_SCRIPTSIG_SIZE = 1650).
 * Biggest standard scriptSig is 15-of-15 P2SH multisig (1627 bytes rounded to 1650).
 */
export const MAX_STANDARD_SCRIPTSIG_SIZE = 1650;

/**
 * Maximum cumulative OP_RETURN (nulldata) payload bytes per transaction.
 * policy.h MAX_OP_RETURN_RELAY = MAX_STANDARD_TX_WEIGHT / WITNESS_SCALE_FACTOR
 * = 400_000 / 4 = 100_000 bytes.
 */
export const MAX_OP_RETURN_RELAY = 100_000;

// ============================================================================
// IsWitnessStandard policy constants (mirrors bitcoin-core/src/policy/policy.h)
// Reference: bitcoin-core/src/policy/policy.cpp:265-352 (IsWitnessStandard)
// ============================================================================

/**
 * Maximum witness script (redeemScript) size for P2WSH inputs (3600 bytes).
 * policy.h MAX_STANDARD_P2WSH_SCRIPT_SIZE = 3600.
 */
export const MAX_STANDARD_P2WSH_SCRIPT_SIZE = 3_600;

/**
 * Maximum number of witness stack items (excluding witnessScript) for P2WSH (100).
 * policy.h MAX_STANDARD_P2WSH_STACK_ITEMS = 100.
 */
export const MAX_STANDARD_P2WSH_STACK_ITEMS = 100;

/**
 * Maximum size of each individual witness stack item for P2WSH inputs (80 bytes).
 * policy.h MAX_STANDARD_P2WSH_STACK_ITEM_SIZE = 80.
 */
export const MAX_STANDARD_P2WSH_STACK_ITEM_SIZE = 80;

/**
 * Maximum size of each individual tapscript witness stack item (80 bytes).
 * policy.h MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE = 80.
 */
export const MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE = 80;

/**
 * Taproot annex tag byte (0x50). Inputs with an annex are non-standard.
 * BIP-341: if the last witness stack item starts with 0x50, it is an annex.
 * policy.cpp ANNEX_TAG = 0x50.
 */
const ANNEX_TAG = 0x50;

/**
 * Taproot leaf version mask (0xfe). Masks the parity bit from the control block's
 * first byte to isolate the leaf version.
 * policy.cpp TAPROOT_LEAF_MASK = 0xfe.
 */
const TAPROOT_LEAF_MASK = 0xfe;

/**
 * Maximum weighted sigop cost for a standard transaction (policy.h).
 * Equals MAX_BLOCK_SIGOPS_COST / 5 = 80_000 / 5 = 16_000.
 * Reference: bitcoin-core/src/policy/policy.h:44
 *   static constexpr unsigned int MAX_STANDARD_TX_SIGOPS_COST{MAX_BLOCK_SIGOPS_COST/5};
 * Enforced in Bitcoin Core validation.cpp:941 before mempool admission.
 */
export const MAX_STANDARD_TX_SIGOPS_COST = 16_000;

/**
 * Default bytes-per-sigop for sigop-adjusted vsize calculation (policy.h).
 * Reference: bitcoin-core/src/policy/policy.h:50
 *   static constexpr unsigned int DEFAULT_BYTES_PER_SIGOP{20};
 * Used by GetVirtualTransactionSize() to compute sigop-adjusted vsize:
 *   adjWeight = max(weight, sigOpCost * bytes_per_sigop)
 *   vsize = ceil(adjWeight / WITNESS_SCALE_FACTOR)
 */
export const DEFAULT_BYTES_PER_SIGOP = 20;

/**
 * Taproot leaf version for tapscript (0xc0, BIP-342).
 * When (controlBlock[0] & TAPROOT_LEAF_MASK) === TAPROOT_LEAF_TAPSCRIPT,
 * the per-item stack size limit applies.
 * policy.cpp TAPROOT_LEAF_TAPSCRIPT = 0xc0.
 */
const TAPROOT_LEAF_TAPSCRIPT = 0xc0;

/**
 * Maximum number of sigops allowed in a P2SH redeem script (policy gate).
 *
 * Reference: bitcoin-core/src/policy/policy.h:42 — MAX_P2SH_SIGOPS = 15.
 * Used by `validateInputsStandardness` to reject P2SH inputs whose
 * redeem script declares more than 15 sigops, mirroring Core's
 * "p2sh redeemscript sigops exceed limit" policy gate.
 */
const MAX_P2SH_SIGOPS = 15;

/**
 * Evaluate a push-only scriptSig into a stack of buffer items.
 *
 * Used by isWitnessStandard() to extract the redeemScript from a P2SH input's
 * scriptSig without running full script validation. Mirrors what Bitcoin Core
 * does with EvalScript(..., SCRIPT_VERIFY_NONE, ...) in IsWitnessStandard:
 * it only needs the resulting stack, and the scriptSig has already been
 * validated as push-only by the IsStandardTx gate.
 *
 * Returns null if the scriptSig contains any opcode that is not a pure push
 * (which should not happen after the push-only gate, but we guard anyway).
 */
function evalPushOnlyScriptSig(scriptSig: Buffer): Buffer[] | null {
  const stack: Buffer[] = [];
  let i = 0;
  while (i < scriptSig.length) {
    const op = scriptSig[i];
    if (op === 0x00) {
      // OP_0 → push empty buffer
      stack.push(Buffer.alloc(0));
      i++;
    } else if (op >= 0x01 && op <= 0x4b) {
      // OP_PUSHBYTES_N
      const len = op;
      if (i + 1 + len > scriptSig.length) return null;
      stack.push(Buffer.from(scriptSig.subarray(i + 1, i + 1 + len)));
      i += 1 + len;
    } else if (op === 0x4c) {
      // OP_PUSHDATA1
      if (i + 1 >= scriptSig.length) return null;
      const len = scriptSig[i + 1];
      if (i + 2 + len > scriptSig.length) return null;
      stack.push(Buffer.from(scriptSig.subarray(i + 2, i + 2 + len)));
      i += 2 + len;
    } else if (op === 0x4d) {
      // OP_PUSHDATA2
      if (i + 2 >= scriptSig.length) return null;
      const len = scriptSig.readUInt16LE(i + 1);
      if (i + 3 + len > scriptSig.length) return null;
      stack.push(Buffer.from(scriptSig.subarray(i + 3, i + 3 + len)));
      i += 3 + len;
    } else if (op === 0x4e) {
      // OP_PUSHDATA4
      if (i + 4 >= scriptSig.length) return null;
      const len = scriptSig.readUInt32LE(i + 1);
      if (i + 5 + len > scriptSig.length) return null;
      stack.push(Buffer.from(scriptSig.subarray(i + 5, i + 5 + len)));
      i += 5 + len;
    } else if (op === 0x4f) {
      // OP_1NEGATE → push -1
      stack.push(Buffer.from([0x81]));
      i++;
    } else if (op >= 0x51 && op <= 0x60) {
      // OP_1 .. OP_16
      stack.push(Buffer.from([op - 0x50]));
      i++;
    } else {
      // Non-push opcode — should not happen after the push-only gate
      return null;
    }
  }
  return stack;
}

/**
 * IsWitnessStandard policy check.
 *
 * Mirrors Bitcoin Core's IsWitnessStandard() (policy/policy.cpp:265-352).
 * Called after the input UTXOs are resolved so that we have the prevout
 * scriptPubKey for each input.
 *
 * 6 gates (matching Core's order):
 *  1. P2A prevScript + any witness → reject "bad-witness-nonstandard"
 *  2. P2SH-wrapped: eval scriptSig → fail/empty reject; top item = redeemScript
 *  3. Non-witness prevScript + non-empty witness → reject "bad-witness-nonstandard"
 *  4. P2WSH v0 32B: witnessScript ≤ 3600B; ≤ 100 stack items; each item ≤ 80B
 *  5. P2TR v1 32B (not P2SH-wrapped): annex 0x50 → reject; tapscript leaf 0xc0
 *     → each item ≤ 80B; empty stack → reject
 *  6. Coinbase (handled by caller — coinbase txs skip the IsWitnessStandard check)
 *
 * @param tx  The transaction being evaluated.
 * @param inputUtxos  Resolved UTXOs for each input (same order as tx.inputs).
 * @returns  { ok: true } or { ok: false, reason: string }
 */
function isWitnessStandard(
  tx: Transaction,
  inputUtxos: Array<{ utxo: { scriptPubKey: Buffer }; input: (typeof tx.inputs)[0] }>
): { ok: true } | { ok: false; reason: string } {
  for (let i = 0; i < tx.inputs.length; i++) {
    const witness = tx.inputs[i].witness;

    // Skip inputs with no witness — they cannot be bloated.
    // Core skips vin[i] when scriptWitness.IsNull() (policy.cpp:274-275).
    if (witness.length === 0) continue;

    let prevScript = inputUtxos[i].utxo.scriptPubKey;

    // Gate 1: P2A prevScript + any witness → reject.
    // Core policy.cpp:283-285: if (prevScript.IsPayToAnchor()) return false;
    if (isP2A(prevScript)) {
      return { ok: false, reason: "bad-witness-nonstandard: P2A input must not carry witness data" };
    }

    // Gate 2: P2SH-wrapped witness programs.
    // Core policy.cpp:287-298: EvalScript(scriptSig → stack, redeemScript = stack.back()).
    let p2sh = false;
    if (isP2SH(prevScript)) {
      const scriptSig = tx.inputs[i].scriptSig;
      const stack = evalPushOnlyScriptSig(scriptSig);
      if (stack === null || stack.length === 0) {
        return { ok: false, reason: "bad-witness-nonstandard: P2SH scriptSig eval failed or produced empty stack" };
      }
      prevScript = stack[stack.length - 1];
      p2sh = true;
    }

    // Gate 3: non-witness prevScript + non-empty witness → reject.
    // Core policy.cpp:301-306: if (!prevScript.IsWitnessProgram(...)) return false;
    // Note: at this point prevScript is the redeemScript for P2SH, so we check if
    // it is a witness program. If it is not (and we already know witness is non-empty),
    // reject as non-standard witness stuffing.
    if (!isWitnessProgram(prevScript)) {
      return { ok: false, reason: "bad-witness-nonstandard: witness present for non-witness-program input" };
    }

    // Parse witness version and program from the (possibly unwrapped) prevScript.
    // isWitnessProgram guarantees: byte[0] = version opcode, byte[1] = pushLen, then program bytes.
    const witnessVersion = prevScript[0] === 0x00 ? 0 : prevScript[0] - 0x50;
    // prevScript[1] is the push-length byte (already validated by isWitnessProgram)
    const programLen = prevScript[1];

    // Gate 4: P2WSH (v0, 32-byte program) standard limits.
    // Core policy.cpp:309-318.
    if (witnessVersion === 0 && programLen === 32) {
      // witness[-1] is the witnessScript; its size must be ≤ 3600.
      const witnessScript = witness[witness.length - 1];
      if (witnessScript.length > MAX_STANDARD_P2WSH_SCRIPT_SIZE) {
        return { ok: false, reason: `bad-witness-nonstandard: P2WSH witnessScript too large (${witnessScript.length} > ${MAX_STANDARD_P2WSH_SCRIPT_SIZE})` };
      }
      // Remaining stack items (excluding witnessScript) must be ≤ 100.
      const sizeWitnessStack = witness.length - 1;
      if (sizeWitnessStack > MAX_STANDARD_P2WSH_STACK_ITEMS) {
        return { ok: false, reason: `bad-witness-nonstandard: P2WSH witness stack too deep (${sizeWitnessStack} > ${MAX_STANDARD_P2WSH_STACK_ITEMS})` };
      }
      // Each of those stack items must be ≤ 80 bytes.
      for (let j = 0; j < sizeWitnessStack; j++) {
        if (witness[j].length > MAX_STANDARD_P2WSH_STACK_ITEM_SIZE) {
          return { ok: false, reason: `bad-witness-nonstandard: P2WSH witness stack item ${j} too large (${witness[j].length} > ${MAX_STANDARD_P2WSH_STACK_ITEM_SIZE})` };
        }
      }
    }

    // Gate 5: P2TR (v1, 32-byte program, not P2SH-wrapped) Taproot limits.
    // Core policy.cpp:324-348.
    if (witnessVersion === 1 && programLen === 32 && !p2sh) {
      // Work with a mutable view of the stack (we may pop the annex).
      // In Core this is std::span, here we track an end index.
      let stackEnd = witness.length; // exclusive end index into witness[]

      // Check for annex: if ≥2 stack items and the last one starts with ANNEX_TAG.
      // Core policy.cpp:327-330.
      if (stackEnd >= 2 && witness[stackEnd - 1].length > 0 && witness[stackEnd - 1][0] === ANNEX_TAG) {
        return { ok: false, reason: "bad-witness-nonstandard: Taproot annex present" };
      }

      if (stackEnd >= 2) {
        // Script-path spend: 2+ items after optional annex removal.
        // Core policy.cpp:331-341: control_block = SpanPopBack(stack); SpanPopBack(script).
        const controlBlock = witness[stackEnd - 1];
        // stackEnd - 1 is the control block; stackEnd - 2 is the script; remaining are args.
        const numArgs = stackEnd - 2; // items before script and control block

        if (controlBlock.length === 0) {
          return { ok: false, reason: "bad-witness-nonstandard: Taproot control block is empty" };
        }
        if ((controlBlock[0] & TAPROOT_LEAF_MASK) === TAPROOT_LEAF_TAPSCRIPT) {
          // Leaf version 0xc0 (Tapscript, BIP-342): enforce per-item size limit.
          for (let j = 0; j < numArgs; j++) {
            if (witness[j].length > MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE) {
              return { ok: false, reason: `bad-witness-nonstandard: tapscript witness item ${j} too large (${witness[j].length} > ${MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE})` };
            }
          }
        }
        // Non-tapscript leaf versions: no additional policy limits applied.
      } else if (stackEnd === 1) {
        // Key-path spend: single stack item (signature). No policy limits.
      } else {
        // 0 stack elements: already invalid by consensus (Core policy.cpp:345-348).
        return { ok: false, reason: "bad-witness-nonstandard: Taproot witness stack is empty" };
      }
    }
  }

  return { ok: true };
}

/**
 * ValidateInputsStandardness policy check.
 *
 * Mirrors Bitcoin Core's `ValidateInputsStandardness()` (policy/policy.cpp:214-263).
 * Called during ATMP PreChecks after CheckTxInputs has resolved all prevouts.
 *
 * For each input:
 *  - If the prevScript classifies as `nonstandard` → reject "bad-txns-nonstandard-inputs".
 *  - If the prevScript classifies as `witness_unknown` (witness v2-v16) → reject
 *    "bad-txns-nonstandard-inputs (witness program undefined)". The script
 *    interpreter would also catch this via DISCOURAGE flags later, but Core
 *    rejects earlier as a defense-in-depth gate.
 *  - If the prevScript is P2SH, eval the (already-validated push-only) scriptSig
 *    to obtain the redeemScript (the top stack item), then count its sigops
 *    in accurate mode. Reject if the redeemScript count exceeds
 *    MAX_P2SH_SIGOPS (=15).
 *
 * Reference: bitcoin-core/src/policy/policy.cpp:226-260.
 *
 * @param tx          The transaction being validated.
 * @param inputUtxos  Resolved UTXOs for each input (same order as tx.inputs).
 */
function validateInputsStandardness(
  tx: Transaction,
  inputUtxos: Array<{ utxo: { scriptPubKey: Buffer }; input: (typeof tx.inputs)[0] }>
): { ok: true } | { ok: false; reason: string } {
  for (let i = 0; i < inputUtxos.length; i++) {
    const { utxo, input } = inputUtxos[i];
    const spk = utxo.scriptPubKey;
    const scriptType = getScriptType(spk);

    if (scriptType === "nonstandard") {
      return { ok: false, reason: `bad-txns-nonstandard-inputs: input ${i} script unknown` };
    }
    if (scriptType === "witness_unknown") {
      return {
        ok: false,
        reason: `bad-txns-nonstandard-inputs: input ${i} witness program is undefined`,
      };
    }
    if (scriptType === "p2sh") {
      // The scriptSig has already been validated as push-only by IsStandardTx.
      // Eval it to a stack; the top item is the redeemScript.
      const stack = evalPushOnlyScriptSig(input.scriptSig);
      if (stack === null) {
        return {
          ok: false,
          reason: `bad-txns-nonstandard-inputs: p2sh scriptsig malformed (input ${i})`,
        };
      }
      if (stack.length === 0) {
        return {
          ok: false,
          reason: `bad-txns-nonstandard-inputs: input ${i} P2SH redeemscript missing`,
        };
      }
      const redeemScript = stack[stack.length - 1];
      // Core uses accurate sigop counting on the redeemScript
      // (policy.cpp:254: subscript.GetSigOpCount(true)).
      const sigopCount = countScriptSigOps(redeemScript, true);
      if (sigopCount > MAX_P2SH_SIGOPS) {
        return {
          ok: false,
          reason: `bad-txns-nonstandard-inputs: p2sh redeemscript sigops exceed limit (input ${i}: ${sigopCount} > ${MAX_P2SH_SIGOPS})`,
        };
      }
    }
  }
  return { ok: true };
}

/**
 * Ancestor/descendant count limits.
 * Bitcoin Core: policy/policy.h DEFAULT_ANCESTOR_LIMIT = 25, DEFAULT_DESCENDANT_LIMIT = 25.
 * Reference: bitcoin-core/src/policy/policy.h:76-78
 *
 * In cluster-mempool Core (28+) these are enforced via MemPoolLimits and still active
 * alongside the cluster-count/size gates. Both gates apply.
 */
const MAX_ANCESTORS = 25;
const MAX_DESCENDANTS = 25;
/**
 * Maximum total vsize of in-mempool ancestors (including self).
 * Bitcoin Core: kernel/mempool_limits.h — historically DEFAULT_ANCESTOR_LIMIT_SIZE_KVB * 1000.
 * Defaults to 101,000 vbytes (101 kvB).
 * Reference: bitcoin-core/src/policy/policy.h (DEFAULT_CLUSTER_SIZE_LIMIT_KVB = 101 kvB shared limit)
 */
const MAX_ANCESTOR_SIZE = 101_000; // vbytes
/**
 * Maximum total vsize of in-mempool descendants (including self).
 * Bitcoin Core: kernel/mempool_limits.h — historically DEFAULT_DESCENDANT_LIMIT_SIZE_KVB * 1000.
 * Defaults to 101,000 vbytes (101 kvB).
 * Reference: bitcoin-core/src/policy/policy.h (DEFAULT_CLUSTER_SIZE_LIMIT_KVB = 101 kvB shared limit)
 */
const MAX_DESCENDANT_SIZE = 101_000; // vbytes

/**
 * TRUC (v3) policy constants per BIP 431.
 * v3 transactions have stricter relay rules to enable more reliable fee bumping.
 */
export const TRUC_VERSION = 3;
/** Maximum number of transactions including a TRUC tx and all its mempool ancestors. */
export const TRUC_ANCESTOR_LIMIT = 2;
/** Maximum number of transactions including an unconfirmed tx and its descendants. */
export const TRUC_DESCENDANT_LIMIT = 2;
/** Maximum sigop-adjusted virtual size of all v3 transactions. */
export const TRUC_MAX_VSIZE = 10_000;
/** Maximum sigop-adjusted virtual size of a tx which spends from an unconfirmed TRUC transaction. */
export const TRUC_CHILD_MAX_VSIZE = 1000;

/**
 * Package relay limits.
 * MAX_PACKAGE_COUNT: Maximum number of transactions in a package
 * MAX_PACKAGE_WEIGHT: Maximum total weight of a package (404,000 WU = 101 kvB)
 */
export const MAX_PACKAGE_COUNT = 25;
export const MAX_PACKAGE_WEIGHT = 404_000;

/**
 * Standard transaction weight ceiling (BIP-141 / policy).
 *
 * `MAX_STANDARD_TX_WEIGHT` is the relay-policy gate Bitcoin Core enforces
 * inside `IsStandardTx` (`bitcoin-core/src/policy/policy.cpp`). It is *not*
 * a consensus rule — the consensus limit is the per-block weight ceiling
 * (`maxBlockWeight = 4_000_000`). Standard txs are 10× tighter so a single
 * relay tx cannot crowd out the rest of the block.
 *
 * Stored as a bigint because the rest of hotbuns's serialization layer
 * uses bigints for 64-bit values.  Compared against `getTxWeight()` which
 * returns a regular `number` — a `BigInt(weight)` cast happens at the
 * comparison site to avoid bigint↔number mixing here.
 */
export const MAX_STANDARD_TX_WEIGHT = 400_000n;

/**
 * Default mempool size (300 MB).
 * kernel/mempool_options.h: DEFAULT_MAX_MEMPOOL_SIZE_MB = 300 → 300 * 1_000_000 bytes.
 */
const DEFAULT_MAX_SIZE = 300_000_000;

/**
 * Default mempool expiry in seconds (336 hours = 14 days).
 * kernel/mempool_options.h: DEFAULT_MEMPOOL_EXPIRY_HOURS = 336.
 * Reference: bitcoin-core/src/txmempool.cpp:811-827 (Expire)
 */
export const MEMPOOL_EXPIRY_SECONDS = 336 * 60 * 60; // 1_209_600 seconds

/**
 * Rolling fee halflife in seconds (12 hours).
 * Reference: bitcoin-core/src/txmempool.h:212
 *   static const int ROLLING_FEE_HALFLIFE = 60 * 60 * 12;
 * Used in GetMinFee() decay: rate /= pow(2, Δt / halflife).
 * Halflife is halved when pool is < half-full, quartered when < quarter-full.
 */
const ROLLING_FEE_HALFLIFE = 60 * 60 * 12; // 43_200 seconds

/**
 * Default minimum relay fee rate (sat/vB).
 *
 * This is the static min-relay floor (Core's `-minrelaytxfee`): a transaction
 * paying below it is rejected with "min relay fee not met". It is the initial
 * admission floor; the dynamic floor rises above it during TrimToSize eviction.
 *
 * Value: 0.1 sat/vB = 100 sat/kvB = 0.00000100 BTC/kvB. This is Core's actual
 * default — `DEFAULT_MIN_RELAY_TX_FEE{100}` in policy.h is 100 sat/kvB, and a
 * default-config Core node reports `minrelaytxfee: 0.00000100` /
 * `mempoolminfee: 0.00000100` from getmempoolinfo (confirmed against the box's
 * live v31.99 node). A zero-/below-floor-fee tx is still rejected with
 * "min relay fee not met"; a paying tx at >= 0.1 sat/vB is accepted.
 *
 * Reference: bitcoin-core/src/policy/policy.h:70 DEFAULT_MIN_RELAY_TX_FEE{100}
 * (sat/kvB) and the CFeeRate(minrelaytxfee) floor applied in validation.cpp's
 * fee gate.
 *
 * Previously 1 sat/vB — 10x Core's real default. That value still rejected
 * zero-fee txs (good) but over-rejected at the floor relative to default Core,
 * and it tripped a wallet cross-regression: the wallet's effective send rate
 * (~0.993 sat/vB on a 1-in/2-out P2WPKH, where the crude vsize estimate
 * undershoots the real serialized vsize) fell just below the 1 sat/vB floor and
 * sendtoaddress self-rejected with "min relay fee not met". Aligning to Core's
 * 0.1 sat/vB restores wallet-send-feerate >= min-relay-floor == Core's value.
 * (The wallet send path now also pads its effective rate to >= the floor; see
 * Wallet.createTransaction.)
 */
export const DEFAULT_MIN_FEE_RATE = 0.1;

/**
 * Default incremental relay fee rate (sat/vB).
 * Core policy.h:48: DEFAULT_INCREMENTAL_RELAY_FEE = 100 sat/kvB = 0.1 sat/vB.
 * Bug fixed: was 1 sat/vB (10× too high), causing RBF Rule #4 to demand too much.
 * Reference: bitcoin-core/src/policy/policy.h:48
 */
const DEFAULT_INCREMENTAL_RELAY_FEE = 0.1; // 100 sat/kvB

// MAX_REPLACEMENT_CANDIDATES (100) is imported from ./rbf.js.

/**
 * Package validation result types.
 */
export enum PackageValidationResult {
  /** Package validation state was not set (success). */
  PCKG_RESULT_UNSET = 0,
  /** Package policy validation failed. */
  PCKG_POLICY = 1,
  /** One or more transactions in the package failed validation. */
  PCKG_TX = 2,
  /** Internal mempool error. */
  PCKG_MEMPOOL_ERROR = 3,
}

/**
 * Result of validating/accepting a single transaction within a package.
 */
export interface PackageTxResult {
  /** Transaction ID (hex). */
  txid: string;
  /** Witness transaction ID (hex). */
  wtxid: string;
  /** Whether the transaction was accepted. */
  accepted: boolean;
  /** Error message if not accepted. */
  error?: string;
  /** Virtual size if accepted. */
  vsize?: number;
  /** Fee in satoshis if accepted. */
  fee?: bigint;
  /** Effective fee rate (package fee rate) if accepted. */
  effectiveFeeRate?: number;
  /** WTXIDs of transactions included in the effective fee rate calculation. */
  effectiveIncludes?: string[];
}

/**
 * Result of package validation/acceptance.
 */
export interface PackageResult {
  /** Overall package validation result. */
  result: PackageValidationResult;
  /** Human-readable message. */
  message: string;
  /** Per-transaction results keyed by wtxid. */
  txResults: Map<string, PackageTxResult>;
  /** Transactions that were replaced (RBF). */
  replacedTxids: string[];
}

/**
 * An entry in the mempool representing an unconfirmed transaction.
 */
export interface MempoolEntry {
  /** The transaction. */
  tx: Transaction;
  /** The transaction ID (hash of non-witness serialization). */
  txid: Buffer;
  /** Transaction fee in satoshis. */
  fee: bigint;
  /** Fee rate in satoshis per virtual byte. */
  feeRate: number;
  /** Virtual size (vsize = ceil(weight/4)). */
  vsize: number;
  /** Transaction weight (BIP-141). */
  weight: number;
  /** Unix timestamp when added to mempool. */
  addedTime: number;
  /** Chain height when the transaction was added. */
  height: number;
  /** Set of txids (hex) that spend outputs of this transaction (children). */
  spentBy: Set<string>;
  /** Set of txids (hex) that this transaction depends on (parents in mempool). */
  dependsOn: Set<string>;
  /** Cached ancestor count (including self). */
  ancestorCount: number;
  /** Cached total ancestor size in vbytes (including self). */
  ancestorSize: number;
  /** Cached descendant count (including self). */
  descendantCount: number;
  /** Cached total descendant size in vbytes (including self). */
  descendantSize: number;
  /** Cluster ID this transaction belongs to. */
  clusterId: string;
  /** Mining score (effective fee rate as sat/vB from chunk). */
  miningScore: number;
  /** Set of ephemeral dust parent txids (hex) that this tx spends from. */
  ephemeralDustParents: Set<string>;
  /** True if this transaction has ephemeral dust outputs. */
  hasEphemeralDust: boolean;
  /**
   * Weighted sigop cost for this transaction.
   * legacy sigops × WITNESS_SCALE_FACTOR + P2SH sigops × WITNESS_SCALE_FACTOR
   * + witness sigops × 1.
   * Reference: Bitcoin Core GetTransactionSigOpCost()
   */
  sigOpCost: number;
}

/**
 * UTXO entry from mempool (not yet confirmed).
 */
interface MempoolUTXO {
  amount: bigint;
  scriptPubKey: Buffer;
  txid: Buffer;
  vout: number;
}

// ============================================================================
// Ephemeral Anchor Policy Functions
// ============================================================================

/** Maximum script size (script/script.h MAX_SCRIPT_SIZE). */
const MAX_SCRIPT_SIZE = 10000;

/**
 * Get the dust threshold (in satoshis) for an output with the given
 * scriptPubKey at the given dust relay fee rate (sat/kvB).
 *
 * Faithful to Core `GetDustThreshold` (policy/policy.cpp:27-63):
 *
 *   nSize = GetSerializeSize(txout) + spending_cost
 *         = (8 + CompactSize(scriptlen) + scriptlen) + spending_cost
 * where the spending cost estimates the CTxIn needed to spend it:
 *   * witness program: 32 + 4 + 1 + (107 / 4) + 4 = 67  (WITNESS_SCALE_FACTOR=4)
 *   * non-witness:     32 + 4 + 1 + 107 + 4                          = 148
 * The witness branch is Core's `IsWitnessProgram` test — uniform across all
 * witness versions/sizes (P2WPKH, P2WSH, P2TR, unknown-witness all take the
 * segwit-discounted 67), NOT a per-script-type table.
 *
 * threshold = dustRelayFee.GetFee(nSize) = CeilDiv(nSize * fee, 1000)
 * (Core `CFeeRate::GetFee` → `FeePerVSize::EvaluateFeeUp` → `CeilDiv`,
 * util/feefrac.h:212). Unspendable scripts (OP_RETURN, oversize) return 0.
 *
 * Default dust relay fee 3000 sat/kvB yields the canonical Core thresholds:
 * P2PKH 546, P2SH 540, P2WPKH 294, P2WSH 330, P2TR 330.
 *
 * NON-consensus: mempool RELAY policy (IsStandardTx / ephemeral-anchor),
 * never block/tx validation.
 */
export function getDustThreshold(
  scriptPubKey: Buffer,
  dustRelayFee: number = DUST_RELAY_FEE,
): bigint {
  // Core: txout.scriptPubKey.IsUnspendable() ⇒ 0.
  // IsUnspendable() = (size > 0 && first == OP_RETURN) || size > MAX_SCRIPT_SIZE.
  if (
    (scriptPubKey.length > 0 && scriptPubKey[0] === 0x6a) ||
    scriptPubKey.length > MAX_SCRIPT_SIZE
  ) {
    return 0n;
  }

  // GetSerializeSize(txout) = 8 (value) + CompactSize(scriptlen) + scriptlen.
  const scriptLen = scriptPubKey.length;
  let prefix: bigint;
  if (scriptLen < 0xfd) prefix = 1n;
  else if (scriptLen <= 0xffff) prefix = 3n;
  else prefix = 5n;
  let nSize = 8n + prefix + BigInt(scriptLen);

  // Core: CScript::IsWitnessProgram — size in [4,42], first byte OP_0 or
  // OP_1..OP_16, and program-length-byte + 2 == size.
  const isWitness =
    scriptLen >= 4 &&
    scriptLen <= 42 &&
    (scriptPubKey[0] === 0x00 ||
      (scriptPubKey[0] >= 0x51 && scriptPubKey[0] <= 0x60)) &&
    scriptPubKey[1] + 2 === scriptLen;

  if (isWitness) {
    // 107 / WITNESS_SCALE_FACTOR (=4) = 26 (BigInt floor), segwit-discounted.
    nSize += 32n + 4n + 1n + 107n / 4n + 4n; // 67
  } else {
    nSize += 32n + 4n + 1n + 107n + 4n; // 148
  }

  // CFeeRate::GetFee(nSize) = CeilDiv(nSize * dustRelayFee, 1000).
  const fee = BigInt(dustRelayFee);
  return (nSize * fee + 999n) / 1000n;
}

/**
 * Check if an output is dust (value below dust threshold).
 */
export function isDust(value: bigint, scriptPubKey: Buffer): boolean {
  return value < getDustThreshold(scriptPubKey);
}

/**
 * Check if an output is ephemeral dust (0-value dust output).
 * Ephemeral dust is a 0-value output that would normally be considered dust.
 */
export function isEphemeralDust(value: bigint, scriptPubKey: Buffer): boolean {
  return value === 0n && isDust(value, scriptPubKey);
}

/**
 * Get all dust output indices for a transaction.
 */
export function getDustOutputs(tx: Transaction): number[] {
  const dustOutputs: number[] = [];
  for (let i = 0; i < tx.outputs.length; i++) {
    const output = tx.outputs[i];
    if (isDust(output.value, output.scriptPubKey)) {
      dustOutputs.push(i);
    }
  }
  return dustOutputs;
}

/**
 * Get all ephemeral dust output indices for a transaction.
 * Ephemeral dust must be 0-value.
 */
export function getEphemeralDustOutputs(tx: Transaction): number[] {
  const ephemeralOutputs: number[] = [];
  for (let i = 0; i < tx.outputs.length; i++) {
    const output = tx.outputs[i];
    if (output.value === 0n && isDust(output.value, output.scriptPubKey)) {
      ephemeralOutputs.push(i);
    }
  }
  return ephemeralOutputs;
}

/**
 * Check if a transaction has ephemeral dust outputs.
 */
export function hasEphemeralDust(tx: Transaction): boolean {
  return getEphemeralDustOutputs(tx).length > 0;
}

/**
 * Pre-check ephemeral transaction: a tx with dust must have 0 fee.
 * This ensures we never give incentive to mine a dust-creating tx alone.
 */
export function preCheckEphemeralTx(tx: Transaction, fee: bigint): { valid: boolean; error?: string } {
  const dustOutputs = getDustOutputs(tx);

  // If there's no dust, the transaction passes
  if (dustOutputs.length === 0) {
    return { valid: true };
  }

  // A transaction with dust outputs must have 0 fee
  if (fee !== 0n) {
    return {
      valid: false,
      error: "tx with dust output must be 0-fee"
    };
  }

  // Only one dust output allowed per tx
  if (dustOutputs.length > MAX_DUST_OUTPUTS_PER_TX) {
    return {
      valid: false,
      error: `too many dust outputs: ${dustOutputs.length} > ${MAX_DUST_OUTPUTS_PER_TX}`
    };
  }

  return { valid: true };
}

/**
 * Result of ephemeral spend check.
 */
export interface EphemeralSpendResult {
  valid: boolean;
  /** If invalid, the txid of the transaction that failed the check. */
  failedTxid?: string;
  /** If invalid, the wtxid of the transaction that failed the check. */
  failedWtxid?: string;
  /** Error message if invalid. */
  error?: string;
}

/**
 * Check that all ephemeral dust outputs from parents are spent by children.
 *
 * For each transaction in the package:
 * 1. Find all in-package and in-mempool parents
 * 2. Collect all dust outputs from those parents
 * 3. Verify the child spends ALL parent dust outputs
 */
export function checkEphemeralSpends(
  packageTxs: Transaction[],
  mempoolEntries: Map<string, MempoolEntry>
): EphemeralSpendResult {
  // Build txid -> Transaction map for package lookups
  const packageTxMap = new Map<string, Transaction>();
  for (const tx of packageTxs) {
    packageTxMap.set(getTxId(tx).toString("hex"), tx);
  }

  // For each transaction, check that it spends all parent dust
  for (const tx of packageTxs) {
    const processedParents = new Set<string>();
    const unspentParentDust = new Set<string>(); // "txid:vout" format

    // Collect dust from all parents (both in-package and in-mempool)
    for (const input of tx.inputs) {
      const parentTxid = input.prevOut.txid.toString("hex");

      // Skip already processed parents
      if (processedParents.has(parentTxid)) {
        continue;
      }

      // Look for parent in package or mempool
      let parentTx: Transaction | undefined;

      // Check package first
      if (packageTxMap.has(parentTxid)) {
        parentTx = packageTxMap.get(parentTxid);
      } else {
        // Check mempool
        const mempoolEntry = mempoolEntries.get(parentTxid);
        if (mempoolEntry) {
          parentTx = mempoolEntry.tx;
        }
      }

      // If we found the parent, collect its dust outputs
      if (parentTx) {
        for (let i = 0; i < parentTx.outputs.length; i++) {
          const output = parentTx.outputs[i];
          if (isDust(output.value, output.scriptPubKey)) {
            unspentParentDust.add(`${parentTxid}:${i}`);
          }
        }
      }

      processedParents.add(parentTxid);
    }

    // If no parent dust, this tx passes
    if (unspentParentDust.size === 0) {
      continue;
    }

    // Mark dust outputs as spent by this transaction's inputs
    for (const input of tx.inputs) {
      const outpointKey = `${input.prevOut.txid.toString("hex")}:${input.prevOut.vout}`;
      unspentParentDust.delete(outpointKey);
    }

    // If there's still unspent parent dust, the check fails
    if (unspentParentDust.size > 0) {
      const txid = getTxId(tx).toString("hex");
      const wtxid = getWTxId(tx).toString("hex");
      return {
        valid: false,
        failedTxid: txid,
        failedWtxid: wtxid,
        error: `tx ${txid.slice(0, 16)}... did not spend parent's ephemeral dust`,
      };
    }
  }

  return { valid: true };
}

// ============================================================================
// Cluster Mempool Data Structures
// ============================================================================

/**
 * Union-Find (Disjoint Set Union) data structure for efficient cluster identification.
 * Uses weighted union with path compression for near-constant time operations.
 */
export class UnionFind {
  /** Parent pointers. Maps txid hex -> parent txid hex. */
  private parent: Map<string, string>;
  /** Rank (tree depth) for each root. */
  private rank: Map<string, number>;
  /** Size of each set (number of elements). */
  private size: Map<string, number>;

  constructor() {
    this.parent = new Map();
    this.rank = new Map();
    this.size = new Map();
  }

  /**
   * Add a new element to the union-find structure.
   */
  makeSet(id: string): void {
    if (this.parent.has(id)) return;
    this.parent.set(id, id);
    this.rank.set(id, 0);
    this.size.set(id, 1);
  }

  /**
   * Find the root of the set containing the given element.
   * Uses path compression for efficiency.
   */
  find(id: string): string {
    if (!this.parent.has(id)) {
      this.makeSet(id);
    }
    let root = id;
    // Find root
    while (this.parent.get(root) !== root) {
      root = this.parent.get(root)!;
    }
    // Path compression
    let current = id;
    while (current !== root) {
      const next = this.parent.get(current)!;
      this.parent.set(current, root);
      current = next;
    }
    return root;
  }

  /**
   * Union two sets. Returns the root of the merged set.
   * Uses union by rank.
   */
  union(a: string, b: string): string {
    const rootA = this.find(a);
    const rootB = this.find(b);

    if (rootA === rootB) return rootA;

    const rankA = this.rank.get(rootA)!;
    const rankB = this.rank.get(rootB)!;
    const sizeA = this.size.get(rootA)!;
    const sizeB = this.size.get(rootB)!;

    // Union by rank
    if (rankA < rankB) {
      this.parent.set(rootA, rootB);
      this.size.set(rootB, sizeA + sizeB);
      return rootB;
    } else if (rankA > rankB) {
      this.parent.set(rootB, rootA);
      this.size.set(rootA, sizeA + sizeB);
      return rootA;
    } else {
      this.parent.set(rootB, rootA);
      this.rank.set(rootA, rankA + 1);
      this.size.set(rootA, sizeA + sizeB);
      return rootA;
    }
  }

  /**
   * Get the size of the set containing the given element.
   */
  getSize(id: string): number {
    const root = this.find(id);
    return this.size.get(root) ?? 0;
  }

  /**
   * Check if two elements are in the same set.
   */
  connected(a: string, b: string): boolean {
    return this.find(a) === this.find(b);
  }

  /**
   * Remove an element from the structure.
   * Note: This is expensive - requires rebuilding affected sets.
   */
  remove(id: string): void {
    this.parent.delete(id);
    this.rank.delete(id);
    this.size.delete(id);
  }

  /**
   * Clear the entire structure.
   */
  clear(): void {
    this.parent.clear();
    this.rank.clear();
    this.size.clear();
  }

  /**
   * Get all unique root IDs (cluster IDs).
   */
  getAllRoots(): Set<string> {
    const roots = new Set<string>();
    for (const id of this.parent.keys()) {
      roots.add(this.find(id));
    }
    return roots;
  }
}

/**
 * A chunk in the linearization: a set of transactions with aggregate fee rate.
 * Chunks are contiguous prefixes of the linearization that form valid topological orderings.
 */
export interface Chunk {
  /** Transaction IDs (hex) in this chunk. */
  txids: Set<string>;
  /** Total fee (satoshis). */
  totalFee: bigint;
  /** Total vsize (vbytes). */
  totalVsize: number;
  /** Aggregate fee rate (sat/vB). */
  feeRate: number;
}

/**
 * A linearization of a cluster: an ordered list of chunks.
 */
export interface Linearization {
  /** Ordered list of chunks from highest to lowest fee rate. */
  chunks: Chunk[];
  /** Map from txid hex -> chunk index in the linearization. */
  txToChunk: Map<string, number>;
}

/**
 * A cluster: a connected component of transactions in the mempool.
 */
export interface Cluster {
  /** Cluster ID (typically the root txid in union-find). */
  id: string;
  /** All transaction IDs in this cluster. */
  txids: Set<string>;
  /** Total fee. */
  totalFee: bigint;
  /** Total vsize. */
  totalVsize: number;
  /** Current linearization of the cluster. */
  linearization: Linearization;
}

/**
 * Caller-provided options for AcceptToMemoryPool / addTransaction.
 *
 * Mirrors a subset of Bitcoin Core's `ATMPArgs` (validation.cpp:451-489) that is
 * meaningful for the single-tx path:
 *
 *  - `maxFeeRateSatPerVB`: caller-defined max fee rate in sat/vB. If the
 *    transaction's effective feerate exceeds this, the tx is rejected inline
 *    with error `max-fee-exceeded`. Mirrors `args.m_client_maxfeerate` and
 *    its check at validation.cpp:1367-1371. Pass 0 / undefined to disable.
 *
 *    The previous hotbuns sendrawtransaction handler enforced this AFTER
 *    addTransaction returned, then removed the tx — which fired the
 *    txAccepted notification and bumped mempoolSequence even for txs that
 *    ultimately ended up rejected. Threading the option through here lets
 *    the gate fire BEFORE the tx is committed to the pool.
 */
export interface AcceptToMemoryPoolOptions {
  /** Caller-defined max fee rate (sat/vB). Reject if the tx exceeds this. */
  maxFeeRateSatPerVB?: number;
  /**
   * Dry-run mode: run all validation but do NOT commit the transaction to the
   * pool (skip entries.set, outpointIndex.set, cluster wiring, and ZMQ emit).
   * Mirrors Bitcoin Core's test_accept path in AcceptToMemoryPool
   * (validation.cpp — ATMPArgs::m_test_accept).
   */
  testAccept?: boolean;
}

/**
 * Transaction memory pool.
 *
 * Validates and stores unconfirmed transactions. When full, evicts transactions
 * with the lowest fee rate. Tracks dependencies between mempool transactions
 * to handle chained unconfirmed transactions.
 *
 * Uses cluster mempool architecture where transactions are organized into
 * clusters (connected components) and linearized for optimal mining.
 */
export class Mempool {
  /** Map of txid hex -> entry. */
  private entries: Map<string, MempoolEntry>;

  /** Map of "txid_hex:vout" -> spending txid hex. */
  private outpointIndex: Map<string, string>;

  /**
   * User-created fee-priority deltas keyed by internal-order txid hex.
   * Mirrors Core's CTxMemPool::mapDeltas (txmempool.h:330). A delta may name
   * a txid that is not (yet) in the mempool — it is kept so the tx is
   * prioritised if it later arrives. Deltas accumulate (saturating int64 add)
   * and an entry whose net delta returns to 0 is erased.
   * Reference: bitcoin-core/src/txmempool.cpp PrioritiseTransaction.
   */
  private mapDeltas: Map<string, bigint>;

  /** Maximum mempool size in vbytes. */
  private maxSize: number;

  /** Current total vsize of all entries. */
  private currentSize: number;

  /** UTXO manager for checking confirmed outputs. */
  private utxo: UTXOManager;

  /** Consensus parameters. */
  private params: ConsensusParams;

  /** Minimum fee rate to accept (sat/vB). Dynamic based on eviction. */
  private minFeeRate: number;

  /** Current chain tip height. */
  private tipHeight: number;

  /** Median Time Past of the current chain tip (BIP-113 / BIP-68). */
  private tipMTP: number;

  /** Incremental relay fee rate (sat/vB). Replacement must pay this per vbyte over replaced fees. */
  private incrementalRelayFee: number;

  /** Union-Find structure for cluster identification. */
  private clusters: UnionFind;

  /** Map of cluster ID -> Cluster object with linearization. */
  private clusterCache: Map<string, Cluster>;

  /** Whether cluster cache needs to be rebuilt. */
  private clusterCacheDirty: boolean;

  /** Optional event emitter for ZMQ notifications. */
  private notificationEmitter: EventEmitter | null;

  /** Monotonically increasing sequence number for mempool events. */
  private mempoolSequence: bigint;

  // ============================================================================
  // Rolling minimum fee state (GetMinFee / TrimToSize / trackPackageRemoved)
  // Reference: bitcoin-core/src/txmempool.h:195-197, txmempool.cpp:829-859
  // ============================================================================

  /**
   * Current rolling minimum fee rate (sat/kvB, floating-point double).
   * Starts at 0 and rises when TrimToSize evicts transactions.
   * Decays exponentially toward 0 with ROLLING_FEE_HALFLIFE (12h).
   * Reference: bitcoin-core/src/txmempool.h:197
   */
  private rollingMinimumFeeRate: number;

  /**
   * Whether a block has been received since the last rolling fee rate bump.
   * When true, decay is applied in GetMinFee(). When false (bump just happened),
   * the rate is returned as-is until the next decay interval.
   * Reference: bitcoin-core/src/txmempool.h:196
   */
  private blockSinceLastRollingFeeBump: boolean;

  /**
   * Unix timestamp (seconds) of the last rolling fee rate decay computation.
   * Reference: bitcoin-core/src/txmempool.h:195
   */
  private lastRollingFeeUpdate: number;

  /**
   * Optional header sync for assumevalid ancestor checks.
   * When set, the script-verification skip gate is evaluated before each
   * script check. For mempool transactions (always above the assumevalid
   * height), the decision will always be "verify scripts" — the gate is
   * provided here so that it fires automatically once the IBD path gains
   * script verification (P2-OPT-ROUND-2).
   */
  private headerSync: import("../sync/headers.js").HeaderSync | null = null;

  constructor(
    utxo: UTXOManager,
    params: ConsensusParams,
    maxSize: number = DEFAULT_MAX_SIZE,
    notificationEmitter: EventEmitter | null = null
  ) {
    this.entries = new Map();
    this.outpointIndex = new Map();
    this.mapDeltas = new Map();
    this.maxSize = maxSize;
    this.currentSize = 0;
    this.utxo = utxo;
    this.params = params;
    this.minFeeRate = DEFAULT_MIN_FEE_RATE;
    this.incrementalRelayFee = DEFAULT_INCREMENTAL_RELAY_FEE;
    this.tipHeight = 0;
    this.tipMTP = 0;
    this.clusters = new UnionFind();
    this.clusterCache = new Map();
    this.clusterCacheDirty = false;
    this.notificationEmitter = notificationEmitter;
    this.mempoolSequence = 0n;
    // Rolling fee state (txmempool.h:195-197)
    this.rollingMinimumFeeRate = 0;
    this.blockSinceLastRollingFeeBump = false;
    this.lastRollingFeeUpdate = Math.floor(Date.now() / 1000);
  }

  /**
   * Set the notification event emitter for ZMQ.
   */
  setNotificationEmitter(emitter: EventEmitter): void {
    this.notificationEmitter = emitter;
  }

  /**
   * Set the header sync reference for assumevalid ancestor checks.
   *
   * Once set, the script-verification skip gate (shouldSkipScripts) is
   * evaluated before each per-input verifyScript call in addTransaction.
   * For unconfirmed mempool txns the check will always return "verify
   * scripts" since they are above the assumevalid height. This wiring
   * exists so the canonical gate is in place for the IBD path once
   * script verification is added there (P2-OPT-ROUND-2).
   */
  setHeaderSync(headerSync: import("../sync/headers.js").HeaderSync): void {
    this.headerSync = headerSync;
  }

  /**
   * Get the current mempool sequence number.
   */
  getMempoolSequence(): bigint {
    return this.mempoolSequence;
  }

  /**
   * Set the current chain tip height.
   */
  setTipHeight(height: number): void {
    this.tipHeight = height;
  }

  /**
   * Get the current chain tip height.
   */
  getTipHeight(): number {
    return this.tipHeight;
  }

  /**
   * Set the Median Time Past of the current chain tip.
   * Used for BIP-113 IsFinalTx and BIP-68 SequenceLocks checks.
   *
   * @param mtp - MTP in Unix timestamp seconds
   */
  setTipMTP(mtp: number): void {
    this.tipMTP = mtp;
  }

  /**
   * Get the current chain tip MTP.
   */
  getTipMTP(): number {
    return this.tipMTP;
  }

  /**
   * AcceptToMemoryPool validates and adds a transaction to the mempool.
   * This is the canonical entry point matching Bitcoin Core's naming convention.
   * Performs all policy checks including BIP125 RBF, fee-rate validation,
   * script verification, and cluster mempool limits.
   */
  async acceptToMemoryPool(
    tx: Transaction,
    options?: AcceptToMemoryPoolOptions,
  ): Promise<{ accepted: boolean; error?: string }> {
    return this.addTransaction(tx, options);
  }

  /**
   * Validate and add a transaction to the mempool.
   *
   * Validation steps:
   * 1. Basic structural validation (validateTxBasic)
   * 2. Not already in mempool or confirmed
   * 3. No double-spend conflicts with existing mempool entries
   * 4. All inputs exist (in UTXO set or mempool)
   * 5. Input values >= output values (positive fee)
   * 6. Fee rate >= minFeeRate
   * 7. Script validation for all inputs
   * 8. Weight <= MAX_BLOCK_WEIGHT
   * 9. Ancestor/descendant limits
   */
  async addTransaction(
    tx: Transaction,
    options?: AcceptToMemoryPoolOptions,
  ): Promise<{ accepted: boolean; error?: string }> {
    // 1. Basic structural validation
    const basicResult = validateTxBasic(tx);
    if (!basicResult.valid) {
      return { accepted: false, error: basicResult.error };
    }

    // Coinbase transactions cannot be in mempool
    if (isCoinbase(tx)) {
      return { accepted: false, error: "Coinbase transaction not allowed in mempool" };
    }

    const txid = getTxId(tx);
    const txidHex = txid.toString("hex");
    const wtxidHex = getWTxId(tx).toString("hex");

    // 2. Mempool duplicate detection: Core checks both (a) exact wtxid match
    //    → "txn-already-in-mempool", and (b) same nonwitness data (= same txid)
    //    but DIFFERENT witness → "txn-same-nonwitness-data-in-mempool".
    //    Reference: bitcoin-core/src/validation.cpp:823-830.
    //
    //    hotbuns keys entries by txid only, so we recover (a) vs (b) by comparing
    //    the wtxid of the existing entry against the incoming tx's wtxid.
    //    Returning the correct error matters for the p2p layer: case (a) is a
    //    legitimate "we already have it" signal; case (b) means a peer relayed
    //    a malleated witness that we should not re-relay.
    {
      const existing = this.entries.get(txidHex);
      if (existing) {
        const existingWtxidHex = getWTxId(existing.tx).toString("hex");
        if (existingWtxidHex === wtxidHex) {
          return { accepted: false, error: "txn-already-in-mempool" };
        } else {
          return { accepted: false, error: "txn-same-nonwitness-data-in-mempool" };
        }
      }
    }

    // 2a. IsStandardTx: version range [TX_MIN_STANDARD_VERSION, TX_MAX_STANDARD_VERSION]
    //     Mirrors Bitcoin Core IsStandardTx (policy/policy.cpp:102-105,
    //     policy.h TX_MIN_STANDARD_VERSION=1, TX_MAX_STANDARD_VERSION=3).
    //     Rejects version 0 and any version > 3 as non-standard.
    if (tx.version < TX_MIN_STANDARD_VERSION || tx.version > TX_MAX_STANDARD_VERSION) {
      return {
        accepted: false,
        error: `version: tx version ${tx.version} out of standard range [${TX_MIN_STANDARD_VERSION},${TX_MAX_STANDARD_VERSION}]`,
      };
    }

    // 2b. IsStandardTx: weight gate (MAX_STANDARD_TX_WEIGHT = 400_000 WU).
    //     Mirrors Bitcoin Core IsStandardTx (policy/policy.cpp:111-115).
    //     Checked before the input/output loops — matches Core's order and ensures
    //     we reject the tx-size reason before scriptpubkey/datacarrier reasons.
    {
      const earlyWeight = getTxWeight(tx);
      if (BigInt(earlyWeight) > MAX_STANDARD_TX_WEIGHT) {
        return {
          accepted: false,
          error: `tx-size: weight ${earlyWeight} exceeds standard limit ${MAX_STANDARD_TX_WEIGHT}`,
        };
      }
      // Consensus block-weight ceiling (4 MWU). Defence-in-depth.
      if (earlyWeight > this.params.maxBlockWeight) {
        return {
          accepted: false,
          error: `Transaction weight ${earlyWeight} exceeds max ${this.params.maxBlockWeight}`,
        };
      }
    }

    // 2b2. IsStandardTx: minimum non-witness size (65 bytes).
    //      Mitigates CVE-2017-12842 (64-byte transaction / merkle-branch confusion).
    //      Mirrors Bitcoin Core MIN_STANDARD_TX_NONWITNESS_SIZE = 65 (validation.cpp:813).
    {
      const nonWitnessSize = serializeTx(tx, false).length;
      if (nonWitnessSize < MIN_STANDARD_TX_NONWITNESS_SIZE) {
        return {
          accepted: false,
          error: `tx-size-small: non-witness size ${nonWitnessSize} < ${MIN_STANDARD_TX_NONWITNESS_SIZE} bytes`,
        };
      }
    }

    // 2c. IsStandardTx: per-input scriptSig checks
    //     (policy/policy.cpp:117-135, MAX_STANDARD_SCRIPTSIG_SIZE = 1650).
    //     1. scriptSig must not exceed 1650 bytes.
    //     2. scriptSig must be push-only (IsPushOnly).
    //     Both mitigate CPU-exhaustion DoS from oversized / non-push scriptSigs.
    for (let i = 0; i < tx.inputs.length; i++) {
      const scriptSig = tx.inputs[i].scriptSig;
      if (scriptSig.length > MAX_STANDARD_SCRIPTSIG_SIZE) {
        return {
          accepted: false,
          error: `scriptsig-size: input ${i} scriptSig ${scriptSig.length} > ${MAX_STANDARD_SCRIPTSIG_SIZE} bytes`,
        };
      }
      if (scriptSig.length > 0 && !isPushOnly(scriptSig)) {
        return {
          accepted: false,
          error: `scriptsig-not-pushonly: input ${i} scriptSig contains non-push opcodes`,
        };
      }
    }

    // 2d. IsStandardTx: per-output scriptPubKey standardness + datacarrier budget.
    //     (policy/policy.cpp:139-156).
    //     - Each output must be a known standard type: p2pkh, p2sh, p2wpkh, p2wsh,
    //       p2tr, anchor, nulldata, p2pk, or multisig (x-of-3 max, n ≤ 3).
    //       "nonstandard" and "witness_unknown" outputs are rejected.
    //     - Cumulative nulldata (OP_RETURN) payload capped at MAX_OP_RETURN_RELAY
    //       (100_000 bytes) per transaction.
    //     - Core default permit_bare_multisig = true, so bare multisig up to
    //       x-of-3 is accepted. n > 3 → reject (IsStandard multisig check,
    //       policy.cpp:91-94).
    {
      let datacarrierBytesUsed = 0;
      for (let i = 0; i < tx.outputs.length; i++) {
        const spk = tx.outputs[i].scriptPubKey;
        const scriptType = getScriptType(spk);

        if (scriptType === "nonstandard") {
          return {
            accepted: false,
            error: `scriptpubkey: output ${i} uses non-standard script type`,
          };
        }

        if (scriptType === "witness_unknown") {
          return {
            accepted: false,
            error: `scriptpubkey: output ${i} uses undefined witness program version`,
          };
        }

        if (scriptType === "multisig") {
          // IsStandard() additional check: bare multisig n must be ≤ 3.
          // Core policy.cpp:88-94: n ∈ [1,3], m ∈ [1,n].
          const params = getBareMultisigParams(spk);
          if (params === null || params.n > 3 || params.n < 1 || params.m < 1 || params.m > params.n) {
            return {
              accepted: false,
              error: `scriptpubkey: output ${i} bare multisig exceeds x-of-3 standard limit`,
            };
          }
        }

        if (scriptType === "nulldata") {
          // Track cumulative OP_RETURN script bytes for MAX_OP_RETURN_RELAY budget.
          // Core policy.cpp:147: size = txout.scriptPubKey.size() (the whole script).
          datacarrierBytesUsed += spk.length;
          if (datacarrierBytesUsed > MAX_OP_RETURN_RELAY) {
            return {
              accepted: false,
              error: `datacarrier: cumulative OP_RETURN data ${datacarrierBytesUsed} > ${MAX_OP_RETURN_RELAY} bytes`,
            };
          }
        }
      }
    }

    // 3. Check for double-spend conflicts - with RBF support
    const conflicts = this.checkConflicts(tx);
    let isReplacement = false;
    let conflictsToEvict: MempoolEntry[] = [];
    let totalConflictingFee = 0n;
    let totalConflictingVsize = 0;

    if (conflicts.length > 0) {
      // Mark this as a potential RBF replacement - we'll validate the fees later
      isReplacement = true;

      // Gather all conflicts and their descendants
      const allConflictTxids = new Set<string>();
      for (const conflict of conflicts) {
        allConflictTxids.add(conflict.txid.toString("hex"));
        const descendants = this.getDescendantSet(conflict.txid.toString("hex"));
        for (const desc of descendants) {
          allConflictTxids.add(desc);
        }
      }

      // Check eviction limit (Rule #5: max 100 transactions)
      if (allConflictTxids.size > MAX_REPLACEMENT_CANDIDATES) {
        return {
          accepted: false,
          error: `RBF would evict too many transactions: ${allConflictTxids.size} > ${MAX_REPLACEMENT_CANDIDATES}`,
        };
      }

      // Collect all entries to be evicted
      for (const txidHex of allConflictTxids) {
        const entry = this.entries.get(txidHex);
        if (entry) {
          conflictsToEvict.push(entry);
          totalConflictingFee += entry.fee;
          totalConflictingVsize += entry.vsize;
        }
      }
    }

    // 4. Check all inputs exist and calculate fee
    let totalInput = 0n;
    const parentTxids: Set<string> = new Set();
    const inputUtxos: Array<{
      utxo: UTXOEntry | MempoolUTXO;
      input: (typeof tx.inputs)[0];
      isMempool: boolean;
    }> = [];

    // MAX_MONEY = 21_000_000 * 100_000_000 satoshis. Defined here locally so
    // we can run the per-input MoneyRange check below without importing a new
    // constant. Mirrors Bitcoin Core consensus/amount.h:MAX_MONEY.
    const MAX_MONEY_SATS = 2_100_000_000_000_000n;
    const moneyInRange = (v: bigint): boolean => v >= 0n && v <= MAX_MONEY_SATS;

    for (const input of tx.inputs) {
      const outpointKey = `${input.prevOut.txid.toString("hex")}:${input.prevOut.vout}`;
      const parentTxidHex = input.prevOut.txid.toString("hex");

      // Check if input is from mempool
      const mempoolParent = this.entries.get(parentTxidHex);
      if (mempoolParent) {
        if (input.prevOut.vout >= mempoolParent.tx.outputs.length) {
          return {
            accepted: false,
            error: `Invalid mempool input: ${outpointKey}`,
          };
        }

        const output = mempoolParent.tx.outputs[input.prevOut.vout];
        // bad-txns-inputvalues-outofrange: per-input + accumulated MoneyRange.
        // Reference: bitcoin-core/src/consensus/tx_verify.cpp:184-188.
        // Defense-in-depth: a mempool parent should already be value-range-clean,
        // but a confirmed-coin path could be corrupted (DB read error, etc.),
        // and accumulated overflow is its own gate.
        if (!moneyInRange(output.value)) {
          return { accepted: false, error: "bad-txns-inputvalues-outofrange" };
        }
        totalInput += output.value;
        if (!moneyInRange(totalInput)) {
          return { accepted: false, error: "bad-txns-inputvalues-outofrange" };
        }
        parentTxids.add(parentTxidHex);
        inputUtxos.push({
          utxo: {
            amount: output.value,
            scriptPubKey: output.scriptPubKey,
            txid: input.prevOut.txid,
            vout: input.prevOut.vout,
          },
          input,
          isMempool: true,
        });
      } else {
        // Check UTXO set
        const utxo = await this.utxo.getUTXOAsync(input.prevOut);
        if (!utxo) {
          // Inputs missing: Core distinguishes "we already have this tx (it's
          // confirmed)" from "we don't have the parent yet (orphan)" by checking
          // whether any of this tx's OWN outputs are present in the coins cache.
          // If yes → `txn-already-known`; if no → `bad-txns-inputs-missingorspent`.
          //
          // Reference: bitcoin-core/src/validation.cpp:857-867 — this distinction
          // drives different downstream behavior at the p2p layer (already-known
          // is silent dedup; missingorspent enters the orphan-tx flow).
          for (let outIdx = 0; outIdx < tx.outputs.length; outIdx++) {
            const ownOutpoint = { txid, vout: outIdx };
            const ownCoin = await this.utxo.getUTXOAsync(ownOutpoint);
            if (ownCoin) {
              return { accepted: false, error: "txn-already-known" };
            }
          }
          return {
            accepted: false,
            error: `bad-txns-inputs-missingorspent: ${outpointKey}`,
          };
        }

        // Check coinbase maturity
        if (utxo.coinbase) {
          const confirmations = this.tipHeight - utxo.height;
          if (confirmations < this.params.coinbaseMaturity) {
            return {
              accepted: false,
              error: `bad-txns-premature-spend-of-coinbase: depth ${confirmations} < ${this.params.coinbaseMaturity}`,
            };
          }
        }

        // bad-txns-inputvalues-outofrange: per-input + accumulated MoneyRange
        // for the confirmed-UTXO path. Reference: tx_verify.cpp:184-188.
        if (!moneyInRange(utxo.amount)) {
          return { accepted: false, error: "bad-txns-inputvalues-outofrange" };
        }
        totalInput += utxo.amount;
        if (!moneyInRange(totalInput)) {
          return { accepted: false, error: "bad-txns-inputvalues-outofrange" };
        }
        inputUtxos.push({ utxo, input, isMempool: false });
      }
    }

    // 5. Calculate fee
    let totalOutput = 0n;
    for (const output of tx.outputs) {
      totalOutput += output.value;
    }

    if (totalInput < totalOutput) {
      // Reference: bitcoin-core/src/consensus/tx_verify.cpp:196-199 —
      // `bad-txns-in-belowout` is the canonical consensus error name.
      return {
        accepted: false,
        error: `bad-txns-in-belowout: value in ${totalInput} < value out ${totalOutput}`,
      };
    }

    const fee = totalInput - totalOutput;

    // bad-txns-fee-outofrange: defense-in-depth on the computed fee.
    // Core's tx_verify.cpp:203-210 notes this is unreachable given the
    // preconditions, but checks anyway. We mirror that.
    if (!moneyInRange(fee)) {
      return { accepted: false, error: "bad-txns-fee-outofrange" };
    }

    // Calculate weight and sigop cost; derive sigop-adjusted vsize.
    //
    // Bitcoin Core computes GetTransactionSigOpCost() immediately after all
    // inputs are fetched (validation.cpp:908), then:
    //  1. Enforces MAX_STANDARD_TX_SIGOPS_COST = 16_000 (policy.h:44, validation.cpp:941).
    //  2. Uses sigop-adjusted vsize for fee-rate math (mempool_entry.h:110-112):
    //       adjWeight = max(weight, sigOpCost * DEFAULT_BYTES_PER_SIGOP)
    //       vsize = ceil(adjWeight / WITNESS_SCALE_FACTOR)
    const weight = getTxWeight(tx);
    const prevOutputsForSigOps: Buffer[] = tx.inputs.map((inp) => {
      const utxoEntry = inputUtxos.find((u) => u.input === inp);
      return utxoEntry ? Buffer.from(utxoEntry.utxo.scriptPubKey) : Buffer.alloc(0);
    });
    const sigOpCost = getTransactionSigOpCost(
      tx,
      prevOutputsForSigOps,
      /* verifyP2SH */ true,
      /* verifyWitness */ true
    );

    // Policy gate: reject txs with excessive sigops (validation.cpp:941).
    // MAX_STANDARD_TX_SIGOPS_COST = MAX_BLOCK_SIGOPS_COST / 5 = 80_000 / 5 = 16_000.
    if (sigOpCost > MAX_STANDARD_TX_SIGOPS_COST) {
      return {
        accepted: false,
        error: `bad-txns-too-many-sigops: sigop cost ${sigOpCost} exceeds maximum ${MAX_STANDARD_TX_SIGOPS_COST}`,
      };
    }

    // Sigop-adjusted vsize: mirrors GetVirtualTransactionSize(weight, sigOpCost, bytes_per_sigop)
    // in bitcoin-core/src/policy/policy.cpp:395-397.
    // If sigops are expensive (sigOpCost * 20 > weight), vsize inflates to reflect that cost.
    const adjWeight = Math.max(weight, sigOpCost * DEFAULT_BYTES_PER_SIGOP);
    const vsize = Math.ceil(adjWeight / WITNESS_SCALE_FACTOR);

    // 8a. PreCheckEphemeralTx: a tx with dust outputs must have 0 fee
    //     so that no miner has an incentive to mine it alone.
    //     Reference: bitcoin-core/src/policy/ephemeral_policy.cpp:23-31
    //     and validation.cpp:935-939 (called in single-tx ATMP after vsize is
    //     known, before the sigop-cost gate).
    //
    //     Previously this gate was only run from the package-validation path
    //     (validatePackage in mempool.ts), so a single-tx submission with a dust
    //     output and a non-zero fee bypassed the dust-relay-fee gate.
    {
      const ephemeralPreCheck = preCheckEphemeralTx(tx, fee);
      if (!ephemeralPreCheck.valid) {
        return { accepted: false, error: ephemeralPreCheck.error };
      }
    }

    // 8c. BIP-113 IsFinalTx: nLockTime must be satisfied at the next block.
    //     Reference: Bitcoin Core CheckFinalTxAtTip() (validation.cpp).
    //     nextHeight = tipHeight + 1; lockTimeCutoff = MTP (BIP-113 MTP rule).
    //     If headerSync is available, compute MTP from the best header; otherwise
    //     fall back to the cached tipMTP value (set via setTipMTP).
    const nextHeight = this.tipHeight + 1;
    let currentMTP = this.tipMTP;
    if (this.headerSync) {
      const bestHdr = this.headerSync.getBestHeader();
      if (bestHdr) {
        currentMTP = this.headerSync.getMedianTimePast(bestHdr);
      }
    }
    if (!isFinalTx(tx, nextHeight, currentMTP)) {
      return {
        accepted: false,
        error: "non-final: bad-txns-nonfinal",
      };
    }

    // 8d. BIP-68 SequenceLocks: per-input relative locktimes (CSV).
    //     Reference: Bitcoin Core CheckSequenceLocksAtTip() (validation.cpp).
    //     For confirmed UTXOs: use tipMTP conservatively as coin MTP (may
    //     false-reject time-locked txs near the boundary but never false-admits).
    //     For mempool parents: synthetic height = tipHeight + 1 (Core convention).
    const enforceBIP68 =
      tx.version >= 2 &&
      this.tipHeight >= (this.params.csvHeight ?? 0);
    if (enforceBIP68) {
      const utxoConfirmations: UTXOConfirmation[] = inputUtxos.map(({ utxo, isMempool: isMp }) => {
        if (isMp) {
          // Unconfirmed parent: treat as mined at tipHeight + 1 with currentMTP.
          return { height: nextHeight, medianTimePast: currentMTP };
        } else {
          // Confirmed UTXO: height from DB; use currentMTP conservatively for MTP.
          const confirmedUtxo = utxo as UTXOEntry;
          return { height: confirmedUtxo.height, medianTimePast: currentMTP };
        }
      });
      if (!checkSequenceLocks(tx, enforceBIP68, nextHeight, currentMTP, utxoConfirmations)) {
        return {
          accepted: false,
          error: "non-BIP68-final: bad-txns-nonfinal",
        };
      }
    }

    // 6. Check fee rate.
    //
    //    Bitcoin Core's CheckFeeRate (validation.cpp:699-713) enforces two
    //    distinct gates with distinct error strings:
    //
    //      (a) Rolling minimum fee (`mempool min fee not met`):
    //          m_pool.GetMinFee().GetFee(package_size) — the dynamic floor
    //          set by the most recently evicted chunk, decayed exponentially
    //          with ROLLING_FEE_HALFLIFE. Returns sat/kvB.
    //
    //      (b) Static min-relay fee (`min relay fee not met`):
    //          m_pool.m_opts.min_relay_feerate.GetFee(package_size).
    //
    //    Previously hotbuns only enforced (b) via `this.minFeeRate`, and
    //    `getMinFee()` (the rolling rate) only got reflected into
    //    `this.minFeeRate` during eviction — between eviction events the
    //    rolling rate could decay back below `this.minFeeRate` (correct) but
    //    could ALSO stay above without being checked here against the
    //    current decayed value. We now query getMinFee() inline so the
    //    rolling-min decay path is enforced at admission time as well.
    const feeRate = Number(fee) / vsize;
    // getMinFee() returns sat/kvB; convert to sat/vB for the gate.
    const rollingMinSatPerVB = this.getMinFee() / 1000;
    if (rollingMinSatPerVB > 0 && feeRate < rollingMinSatPerVB) {
      return {
        accepted: false,
        error: `mempool min fee not met: ${feeRate.toFixed(8)} sat/vB < ${rollingMinSatPerVB.toFixed(8)} sat/vB`,
      };
    }
    if (feeRate < this.minFeeRate) {
      return {
        accepted: false,
        error: `min relay fee not met: ${feeRate.toFixed(8)} sat/vB < ${this.minFeeRate} sat/vB`,
      };
    }

    // 6a. Caller-defined max fee rate (matches Bitcoin Core ATMPArgs.m_client_maxfeerate
    //     at validation.cpp:1367-1371). RPC callers (e.g. sendrawtransaction) use
    //     this to refuse to broadcast obviously-overpaying txs. Checking here, before
    //     conflict-eviction or notification emit, avoids the prior-pattern "accept,
    //     emit notification, then remove" race.
    if (
      options?.maxFeeRateSatPerVB !== undefined &&
      options.maxFeeRateSatPerVB > 0 &&
      feeRate > options.maxFeeRateSatPerVB
    ) {
      return {
        accepted: false,
        error: `max-fee-exceeded: ${feeRate.toFixed(8)} sat/vB > ${options.maxFeeRateSatPerVB} sat/vB`,
      };
    }

    // RBF replacement checks (BIP 125 Rule #2, #3, #4)
    if (isReplacement) {
      // Rule #2 (BIP-125, ref bitcoin-core/src/policy/rbf.cpp::HasNoNewUnconfirmed
      //         pre-removal era): the replacement may only spend an
      //         unconfirmed input if that input was already known —
      //         either an in-mempool ancestor of one of the conflicts
      //         being replaced, or one of the conflicts themselves.
      //         Any new unconfirmed input → reject.
      //
      // Build the set of "already-known" mempool txids: union of conflicts
      // plus all mempool ancestors of the conflicts. Then walk the
      // replacement's inputs; any input whose prev-out points at a mempool
      // tx outside this set is a new unconfirmed input.
      // Build the direct-conflicts set (by txid-hex) and the ancestor sets.
      const conflictTxids = new Set<string>();
      const conflictParents = new Set<string>();
      for (const conflict of conflictsToEvict) {
        conflictTxids.add(conflict.txid.toString("hex"));
        for (const p of conflict.dependsOn) conflictParents.add(p);
      }
      const conflictAncestors = this.getAncestorSet(conflictParents);

      // Rule #2 / HasNoNewUnconfirmed
      // (bitcoin-core/src/policy/rbf.cpp, pre-removal HasNoNewUnconfirmed):
      // The replacement may only spend an unconfirmed input if that input was
      // already known — either an in-mempool ancestor of one of the conflicts
      // being replaced, or one of the conflicts themselves.
      // The "already-known" set is conflicts ∪ ancestors-of-conflicts.
      const allowedUnconfirmed = new Set<string>([
        ...conflictTxids,
        ...conflictAncestors,
      ]);
      for (const input of tx.inputs) {
        const parentHex = input.prevOut.txid.toString("hex");
        // Only inputs that reference an in-mempool tx need to be checked;
        // confirmed (chainstate) inputs are always allowed by Rule 2.
        if (this.entries.has(parentHex) && !allowedUnconfirmed.has(parentHex)) {
          return {
            accepted: false,
            error: `RBF replacement adds new unconfirmed input ${parentHex.slice(0, 16)}...:${input.prevOut.vout} (BIP-125 Rule 2)`,
          };
        }
      }

      // Gate #5 / EntriesAndTxidsDisjoint
      // (bitcoin-core/src/policy/rbf.cpp:EntriesAndTxidsDisjoint)
      // Verify that no ancestor of the *replacement* transaction appears in
      // the direct-conflicts set. If an ancestor is being evicted, the
      // replacement would spend an output of a transaction that no longer
      // exists, which is topologically impossible.
      const replacementAncestors = this.getAncestorSet(parentTxids);
      const disjointErr = entriesAndTxidsDisjoint(
        replacementAncestors,
        conflictTxids,
        txid.toString("hex")
      );
      if (disjointErr !== null) {
        return { accepted: false, error: disjointErr };
      }

      // Rule #3: Replacement fees must be >= original fees.
      // (bitcoin-core/src/policy/rbf.cpp:PaysForRBF, line 109: `replacement_fees < original_fees`)
      // Core accepts equal fees here; Rule #4 rejects zero-increment cases.
      if (fee < totalConflictingFee) {
        return {
          accepted: false,
          error: `RBF replacement fee ${fee} must be >= conflicting fees ${totalConflictingFee} (BIP-125 Rule 3)`,
        };
      }

      // Rule #4: Additional fee must cover the replacement's own bandwidth.
      // newFee - sumOldFees >= incrementalRelayFee * newVsize
      // (bitcoin-core/src/policy/rbf.cpp:PaysForRBF, line 118)
      const additionalFee = fee - totalConflictingFee;
      const requiredIncrementalFee = BigInt(Math.ceil(this.incrementalRelayFee * vsize));
      if (additionalFee < requiredIncrementalFee) {
        return {
          accepted: false,
          error: `RBF incremental fee ${additionalFee} < required ${requiredIncrementalFee} (${this.incrementalRelayFee} sat/vB * ${vsize} vB) (BIP-125 Rule 4)`,
        };
      }

      // NOTE: No per-conflict fee-rate comparison. Bitcoin Core (policy/rbf.cpp)
      // does NOT require the replacement's fee rate to exceed every individual
      // conflicting tx's fee rate — only the absolute and incremental fee gates
      // above apply.

      // Gate #8 / ImprovesFeerateDiagram (Core 27+ cluster mempool).
      // Reference: bitcoin-core/src/policy/rbf.cpp:127-138 (ImprovesFeerateDiagram),
      //            bitcoin-core/src/util/feefrac.cpp:10-73 (CompareChunks).
      //
      // The replacement must strictly improve the mempool's feerate diagram.
      // "Before" = linearize(affected cluster); "After" = same cluster minus
      // conflicts plus replacement.  After must dominate Before at every
      // cumulative-vsize boundary (CompareChunks(after, before) > 0).
      {
        const diagramErr = this.improvesFeerateDiagram(
          txid.toString("hex"),
          fee,
          vsize,
          parentTxids,
          conflictsToEvict,
        );
        if (diagramErr !== null) {
          return { accepted: false, error: diagramErr };
        }
      }
    }

    // 9a. Check TRUC (v3) policy rules
    const trucResult = this.checkTRUCPolicy(
      tx,
      vsize,
      parentTxids,
      conflicts,
      isReplacement
    );
    if (!trucResult.valid) {
      // If sibling eviction is possible, add the sibling to conflicts
      if (trucResult.siblingToEvict) {
        // Sibling eviction: v3 child can replace existing v3 child
        const siblingEntry = this.entries.get(trucResult.siblingToEvict);
        if (siblingEntry) {
          // For sibling eviction, we allow replacement without normal RBF fee-rate rules
          // Just need to pay higher absolute fee
          if (fee <= siblingEntry.fee) {
            return {
              accepted: false,
              error: `TRUC sibling eviction requires higher fee: ${fee} <= ${siblingEntry.fee}`,
            };
          }

          // Add sibling to eviction list
          if (!conflictsToEvict.some((e) => e.txid.toString("hex") === trucResult.siblingToEvict)) {
            conflictsToEvict.push(siblingEntry);
            totalConflictingFee += siblingEntry.fee;
            totalConflictingVsize += siblingEntry.vsize;
            isReplacement = true;
          }
        }
      } else {
        return { accepted: false, error: trucResult.error };
      }
    }

    // 9b. Check cluster size limit (replaces ancestor/descendant limits)
    //
    // For RBF, evaluate against the POST-eviction state: the conflicts (and
    // their descendants gathered above into `conflictsToEvict`) will be
    // removed before the new tx is added, so they must not count toward the
    // cluster's count/vbytes when checking the limit. Mirrors
    // `m_subpackage.m_changeset->CheckMemPoolPolicyLimits()` in
    // bitcoin-core/src/validation.cpp:1023 (ReplacementChecks).
    //
    // For non-RBF the excluded set is empty and this reduces to the prior
    // behavior. For TRUC, checkTRUCPolicy has already applied its own (stricter)
    // limits with the same eviction semantics.
    const evictedTxidSet = new Set<string>();
    if (isReplacement) {
      for (const e of conflictsToEvict) {
        evictedTxidSet.add(e.txid.toString("hex"));
      }
    }
    const clusterResult = this.checkClusterSizeLimit(parentTxids, vsize, evictedTxidSet);
    if (!clusterResult.valid) {
      return { accepted: false, error: clusterResult.error };
    }

    // Also check legacy ancestor/descendant limits for backward compatibility
    const ancestorResult = this.checkAncestorLimits(parentTxids, vsize);
    if (!ancestorResult.valid) {
      return { accepted: false, error: ancestorResult.error };
    }

    // 2e1. ValidateInputsStandardness: per-input prevScript policy checks.
    //      Mirrors Bitcoin Core's ValidateInputsStandardness() (policy/policy.cpp:214-263),
    //      called from PreChecks (validation.cpp:896-901) after CheckTxInputs.
    //      Three rejections:
    //        - nonstandard prevScript → "bad-txns-nonstandard-inputs"
    //        - witness_unknown prevScript (witness v2-v16) → undefined witness program
    //        - P2SH redeemScript with > MAX_P2SH_SIGOPS (=15) sigops in accurate mode
    {
      const inputsStdResult = validateInputsStandardness(tx, inputUtxos);
      if (!inputsStdResult.ok) {
        return { accepted: false, error: inputsStdResult.reason };
      }
    }

    // 2e. IsWitnessStandard: per-input witness policy checks.
    //     Mirrors Bitcoin Core's IsWitnessStandard() (policy/policy.cpp:265-352).
    //     Called here (after inputUtxos is fully resolved) because we need the
    //     prevout scriptPubKey for each input to classify the witness spend type.
    //     6 gates (Core order):
    //       1. P2A prevScript + any witness → reject
    //       2. P2SH-wrapped: eval scriptSig → get redeemScript; fail/empty → reject
    //       3. Non-witness prevScript + non-empty witness → reject
    //       4. P2WSH v0 32B: witnessScript ≤ 3600; ≤ 100 stack items; each ≤ 80B
    //       5. P2TR v1 32B (!p2sh): annex 0x50 → reject; tapscript leaf 0xc0 → items ≤ 80B; empty stack → reject
    //       6. Coinbase: exempt (checked before addTransaction is called)
    {
      const witnessResult = isWitnessStandard(tx, inputUtxos);
      if (!witnessResult.ok) {
        return { accepted: false, error: witnessResult.reason };
      }
    }

    // 9c. CheckEphemeralSpends (single-tx ATMP path).
    //     Mirrors Bitcoin Core's CheckEphemeralSpends() (policy/ephemeral_policy.cpp:33-95),
    //     called in single-tx ATMP at validation.cpp:1373-1378 with the singleton
    //     package {ptx}.
    //
    //     For every mempool parent with ephemeral dust outputs, the child must
    //     spend all of those dust outpoints. Without this gate in the single-tx
    //     path, a CPFP child that doesn't actually pay for the dust gets in,
    //     and the dust parent becomes unprunable.
    {
      const ephemeralSpendResult = checkEphemeralSpends([tx], this.entries);
      if (!ephemeralSpendResult.valid) {
        return { accepted: false, error: ephemeralSpendResult.error };
      }
    }

    // 7. Script validation
    //
    // Evaluate the assumevalid skip gate before the per-input script loop.
    // For mempool transactions (unconfirmed, at tip height) the ancestor
    // check will always fail (the tx isn't in any confirmed block), so the
    // gate always returns "verify scripts" here. The gate is wired here so
    // that when the IBD path gains script verification (P2-OPT-ROUND-2),
    // the canonical shouldSkipScripts() function fires automatically.
    //
    // NOTE: hotbuns's IBD path (BlockSync.connectBlock) does not currently
    // invoke script verification — this is the separate P2-OPT-ROUND-2 gap
    // "hotbuns has verifyAllInputsParallel defined but never imported; script
    // verification absent from IBD path". Once that is fixed, the assumevalid
    // decision function will fire in the IBD path automatically.
    let skipScripts = false;
    if (this.headerSync && this.params.assumedValid) {
      // Build a pseudo-pindex for the mempool context.
      // Mempool txns are unconfirmed so height is tipHeight+1; hash is
      // unknown — we use an empty hex which will fail the ancestor check,
      // ensuring skipScripts=false for all mempool txns as expected.
      const pindexEntry: AssumeValidBlockEntry = {
        hash: "",
        height: this.tipHeight + 1,
        chainWork: 0n,
      };
      const bestHeader = this.headerSync.getBestHeader();
      const skipResult = shouldSkipScripts({
        pindex: pindexEntry,
        assumedValidHash: this.params.assumedValid,
        getBlockByHash: (hashHex) => {
          const entry = this.headerSync!.getHeader(Buffer.from(hashHex, "hex"));
          if (!entry) return null;
          return { hash: entry.hash.toString("hex"), height: entry.height, chainWork: entry.chainWork };
        },
        getBlockAtHeight: (height) => {
          const entry = this.headerSync!.getHeaderByHeight(height);
          if (!entry) return null;
          return { hash: entry.hash.toString("hex"), height: entry.height, chainWork: entry.chainWork };
        },
        bestHeader: bestHeader
          ? { hash: bestHeader.hash.toString("hex"), height: bestHeader.height, chainWork: bestHeader.chainWork }
          : null,
        minimumChainWork: this.params.nMinimumChainWork,
        pindexTimestamp: Math.floor(Date.now() / 1000),
        bestHeaderTimestamp: bestHeader ? bestHeader.header.timestamp : 0,
      });
      skipScripts = skipResult.skip;
    }

    // Mempool uses standard (policy) flags — stricter than consensus block flags.
    const flags = getStandardFlags(this.tipHeight);

    // Helper to verify all inputs under a given flag set. Used twice: once
    // for PolicyScriptChecks (standard flags) and once for
    // ConsensusScriptChecks (consensus block flags).
    const verifyAllInputs = (flagSet: ScriptFlags): { ok: true } | { ok: false; reason: string } => {
      for (let i = 0; i < tx.inputs.length; i++) {
        const { utxo, input } = inputUtxos[i];
        const sigHasher = (subscript: Buffer, hashType: number): Buffer => {
          const witnessProgram = utxo.scriptPubKey;
          const isSegwit =
            (witnessProgram.length === 22 &&
              witnessProgram[0] === 0x00 &&
              witnessProgram[1] === 20) ||
            (witnessProgram.length === 34 &&
              witnessProgram[0] === 0x00 &&
              witnessProgram[1] === 32);
          if (isSegwit || input.witness.length > 0) {
            return sigHashWitnessV0(tx, i, subscript, utxo.amount, hashType);
          } else {
            return sigHashLegacy(tx, i, subscript, hashType);
          }
        };
        const valid = verifyScript(
          input.scriptSig,
          utxo.scriptPubKey,
          input.witness,
          flagSet,
          sigHasher,
          undefined,
          { txVersion: tx.version, txLockTime: tx.lockTime, txSequence: input.sequence }
        );
        if (!valid) {
          return { ok: false, reason: `Script validation failed for input ${i}` };
        }
      }
      return { ok: true };
    };

    if (!skipScripts) {
      // PolicyScriptChecks: verify with STANDARD (policy) flags.
      // Mirrors bitcoin-core/src/validation.cpp:1135-1156 — uses
      // STANDARD_SCRIPT_VERIFY_FLAGS, the strictest set, and is the
      // "expensive checks last" gate of ATMP.
      const policyResult = verifyAllInputs(flags);
      if (!policyResult.ok) {
        return { accepted: false, error: policyResult.reason };
      }

      // ConsensusScriptChecks: re-verify with current-block CONSENSUS flags.
      // Mirrors bitcoin-core/src/validation.cpp:1158-1189. This is a defense-
      // in-depth check that catches bugs where STANDARD_SCRIPT_VERIFY_FLAGS
      // would *accept* a script that the looser MANDATORY/consensus flags would
      // *reject* — historically the STRICTENC flag was incorrectly allowing
      // certain CHECKSIG NOT scripts to pass even though they were invalid.
      // If policy passed but consensus rejects, we still reject (better safe).
      // Cheap to run since the sig cache (when wired) would already have
      // cached the signature verifications.
      const consensusFlags = getConsensusFlags(this.tipHeight);
      const consensusResult = verifyAllInputs(consensusFlags);
      if (!consensusResult.ok) {
        return {
          accepted: false,
          error: `ConsensusScriptChecks: ${consensusResult.reason}`,
        };
      }
    }

    // If this is an RBF replacement, remove all conflicting transactions first
    if (isReplacement) {
      for (const conflictEntry of conflictsToEvict) {
        // Remove without removing dependents since we're removing all of them
        this.removeTransactionInternal(conflictEntry.txid);
      }
    }

    // Calculate ancestor stats before creating entry
    const { ancestorCount, ancestorSize } = this.calculateAncestorStats(parentTxids, vsize);

    // Track ephemeral dust relationships
    const ephemeralDustParents = new Set<string>();
    for (const parentTxidHex of parentTxids) {
      const parent = this.entries.get(parentTxidHex);
      if (parent && parent.hasEphemeralDust) {
        ephemeralDustParents.add(parentTxidHex);
      }
    }

    // Check if this tx has ephemeral dust outputs
    const txHasEphemeralDust = hasEphemeralDust(tx);

    // Create the mempool entry
    // (sigOpCost and vsize are computed early above, after inputs are gathered)
    const entry: MempoolEntry = {
      tx,
      txid,
      fee,
      feeRate,
      vsize,
      weight,
      addedTime: Math.floor(Date.now() / 1000),
      height: this.tipHeight,
      spentBy: new Set(),
      dependsOn: parentTxids,
      ancestorCount,
      ancestorSize,
      descendantCount: 1, // Only self initially
      descendantSize: vsize,
      clusterId: txidHex, // Will be updated by addToCluster
      miningScore: feeRate, // Will be updated by linearization
      ephemeralDustParents,
      hasEphemeralDust: txHasEphemeralDust,
      sigOpCost,
    };

    // Dry-run path: validation passed but caller only wants a yes/no answer.
    // Do NOT commit anything to the pool (mirrors Core's test_accept=true path).
    if (options?.testAccept) {
      return { accepted: true };
    }

    // Add to mempool
    this.entries.set(txidHex, entry);
    this.currentSize += vsize;

    // Update parent entries' spentBy and descendant stats
    for (const parentTxidHex of parentTxids) {
      const parent = this.entries.get(parentTxidHex);
      if (parent) {
        parent.spentBy.add(txidHex);
      }
    }

    // Update all ancestors' descendant counts
    this.updateAncestorDescendantStats(txidHex, vsize);

    // Add to cluster structure
    this.addToCluster(txidHex, parentTxids);

    // Index the spent outpoints
    for (const input of tx.inputs) {
      const outpointKey = `${input.prevOut.txid.toString("hex")}:${input.prevOut.vout}`;
      this.outpointIndex.set(outpointKey, txidHex);
    }

    // Evict if over size limit
    if (this.currentSize > this.maxSize) {
      this.evict();
    }

    // Emit notification for ZMQ
    if (this.notificationEmitter) {
      const seq = this.mempoolSequence;
      this.mempoolSequence += 1n;
      this.notificationEmitter.emit("txAccepted", tx, seq);
    }

    return { accepted: true };
  }

  /**
   * Remove a transaction from the mempool.
   *
   * @param txid - The transaction ID to remove
   * @param removeDependents - If true, also remove all dependent transactions (default: true)
   */
  removeTransaction(txid: Buffer, removeDependents: boolean = true): void {
    const txidHex = txid.toString("hex");
    const entry = this.entries.get(txidHex);

    if (!entry) {
      return;
    }

    // If removing dependents, recursively remove children first
    if (removeDependents) {
      for (const childTxidHex of entry.spentBy) {
        const childTxid = Buffer.from(childTxidHex, "hex");
        this.removeTransaction(childTxid, true);
      }
    }

    // Ephemeral anchor cascade: if this tx spends ephemeral dust from a parent,
    // and this is the only child spending that parent's dust, the parent must
    // also be removed (it can't exist in mempool without its dust being spent).
    const ephemeralParentsToRemove: string[] = [];
    for (const parentTxidHex of entry.ephemeralDustParents) {
      const parent = this.entries.get(parentTxidHex);
      if (parent && parent.hasEphemeralDust) {
        // Check if any other child still spends this parent's dust
        let hasOtherChild = false;
        for (const otherChildHex of parent.spentBy) {
          if (otherChildHex !== txidHex && this.entries.has(otherChildHex)) {
            const otherChild = this.entries.get(otherChildHex)!;
            if (otherChild.ephemeralDustParents.has(parentTxidHex)) {
              hasOtherChild = true;
              break;
            }
          }
        }
        if (!hasOtherChild) {
          ephemeralParentsToRemove.push(parentTxidHex);
        }
      }
    }

    // Update ancestors' descendant stats before removing
    const ancestors = this.getAncestorSet(entry.dependsOn);
    for (const ancestorTxidHex of ancestors) {
      const ancestor = this.entries.get(ancestorTxidHex);
      if (ancestor) {
        ancestor.descendantCount -= 1;
        ancestor.descendantSize -= entry.vsize;
      }
    }

    // Remove from parent's spentBy
    for (const parentTxidHex of entry.dependsOn) {
      const parent = this.entries.get(parentTxidHex);
      if (parent) {
        parent.spentBy.delete(txidHex);
      }
    }

    // Remove outpoint index entries
    for (const input of entry.tx.inputs) {
      const outpointKey = `${input.prevOut.txid.toString("hex")}:${input.prevOut.vout}`;
      this.outpointIndex.delete(outpointKey);
    }

    // Remove from entries
    this.entries.delete(txidHex);
    this.currentSize -= entry.vsize;

    // Mark cluster cache as dirty
    this.clusterCacheDirty = true;

    // Emit notification for ZMQ
    if (this.notificationEmitter) {
      const seq = this.mempoolSequence;
      this.mempoolSequence += 1n;
      this.notificationEmitter.emit("txRemoved", txid, seq);
    }

    // Cascade removal of ephemeral dust parents that no longer have their dust spent
    for (const parentTxidHex of ephemeralParentsToRemove) {
      const parentTxid = Buffer.from(parentTxidHex, "hex");
      this.removeTransaction(parentTxid, true);
    }
  }

  /**
   * Remove all transactions confirmed in a block.
   *
   * Also removes any transactions that conflict with the block
   * (double-spends that weren't included).
   */
  removeForBlock(block: Block): void {
    const confirmedTxids = new Set<string>();

    // First, collect all confirmed txids and remove them
    for (const tx of block.transactions) {
      if (isCoinbase(tx)) continue;

      const txid = getTxId(tx);
      const txidHex = txid.toString("hex");
      confirmedTxids.add(txidHex);

      // A confirmed tx's prioritisation delta is cleared (Core removeForBlock
      // -> ClearPrioritisation, txmempool.cpp:420) so it cannot leak onto a
      // future unrelated tx reusing this txid. Done regardless of whether the
      // tx was actually in our mempool, matching Core.
      this.mapDeltas.delete(txidHex);

      // Remove the transaction (but not its dependents yet - they may also be confirmed)
      const entry = this.entries.get(txidHex);
      if (entry) {
        // Remove outpoint index entries
        for (const input of entry.tx.inputs) {
          const outpointKey = `${input.prevOut.txid.toString("hex")}:${input.prevOut.vout}`;
          this.outpointIndex.delete(outpointKey);
        }

        // Remove from entries
        this.entries.delete(txidHex);
        this.currentSize -= entry.vsize;
      }
    }

    // Now check for conflicts (mempool txs that spend inputs used by block txs)
    const conflictingTxids: string[] = [];

    for (const tx of block.transactions) {
      if (isCoinbase(tx)) continue;

      for (const input of tx.inputs) {
        const outpointKey = `${input.prevOut.txid.toString("hex")}:${input.prevOut.vout}`;
        const spendingTxid = this.outpointIndex.get(outpointKey);

        if (spendingTxid && !confirmedTxids.has(spendingTxid)) {
          conflictingTxids.push(spendingTxid);
        }
      }
    }

    // Remove conflicting transactions (with their dependents)
    for (const txidHex of conflictingTxids) {
      const txid = Buffer.from(txidHex, "hex");
      // Conflicted-out txs also drop their delta (Core removeConflicts ->
      // ClearPrioritisation). Other removal reasons (RBF replace, size-limit
      // eviction, expiry, reorg) preserve the delta so a re-entering tx stays
      // prioritised — hence this is done here and not in removeTransaction.
      this.mapDeltas.delete(txidHex);
      this.removeTransaction(txid, true);
    }

    // Update dependency tracking for remaining transactions
    for (const [txidHex, entry] of this.entries) {
      // Remove confirmed parents from dependsOn
      for (const parentTxidHex of entry.dependsOn) {
        if (confirmedTxids.has(parentTxidHex)) {
          entry.dependsOn.delete(parentTxidHex);
        }
      }

      // Remove confirmed children from spentBy
      for (const childTxidHex of entry.spentBy) {
        if (confirmedTxids.has(childTxidHex)) {
          entry.spentBy.delete(childTxidHex);
        }
      }
    }

    // Recalculate cached stats for all remaining entries
    this.recalculateAllStats();

    // Rebuild cluster structure from scratch
    this.rebuildClusters();

    // After a block is connected, reset rolling fee decay timer and set the
    // blockSinceLastRollingFeeBump flag so that GetMinFee() will apply decay
    // going forward.
    // Reference: bitcoin-core/src/txmempool.cpp:426-427
    this.lastRollingFeeUpdate = Math.floor(Date.now() / 1000);
    this.blockSinceLastRollingFeeBump = true;
  }

  /**
   * Rebuild the cluster union-find structure from scratch.
   * Called after bulk operations like removeForBlock.
   */
  private rebuildClusters(): void {
    this.clusters.clear();
    this.clusterCache.clear();

    // Create singleton sets for all remaining transactions
    for (const txidHex of this.entries.keys()) {
      this.clusters.makeSet(txidHex);
    }

    // Union based on dependencies
    for (const [txidHex, entry] of this.entries) {
      for (const parentTxidHex of entry.dependsOn) {
        if (this.entries.has(parentTxidHex)) {
          this.clusters.union(txidHex, parentTxidHex);
        }
      }
    }

    this.clusterCacheDirty = true;
  }

  /**
   * Recalculate all cached ancestor/descendant stats.
   * Called after bulk operations like removeForBlock.
   */
  private recalculateAllStats(): void {
    // Reset all stats
    for (const entry of this.entries.values()) {
      entry.ancestorCount = 1; // Self
      entry.ancestorSize = entry.vsize;
      entry.descendantCount = 1; // Self
      entry.descendantSize = entry.vsize;
    }

    // Recalculate ancestors for each entry
    for (const [txidHex, entry] of this.entries) {
      const ancestors = this.getAncestorSet(entry.dependsOn);
      let ancestorSize = entry.vsize;
      for (const ancestorTxidHex of ancestors) {
        const ancestor = this.entries.get(ancestorTxidHex);
        if (ancestor) {
          ancestorSize += ancestor.vsize;
        }
      }
      entry.ancestorCount = ancestors.size + 1;
      entry.ancestorSize = ancestorSize;
    }

    // Recalculate descendants: for each entry, increment all its ancestors' descendant counts
    for (const [txidHex, entry] of this.entries) {
      const ancestors = this.getAncestorSet(entry.dependsOn);
      for (const ancestorTxidHex of ancestors) {
        const ancestor = this.entries.get(ancestorTxidHex);
        if (ancestor) {
          ancestor.descendantCount += 1;
          ancestor.descendantSize += entry.vsize;
        }
      }
    }
  }

  /**
   * Re-add transactions after a block disconnect (reorg).
   *
   * Attempts to re-add transactions that were previously confirmed
   * but are now unconfirmed due to a chain reorganization.
   *
   * Per-tx accept/reject is logged so the reorg dispatcher can
   * surface partial-refill conditions (Pattern B2) in operator logs
   * without trying to re-thread the result back through the caller
   * chain.
   */
  async readdTransactions(txs: Transaction[]): Promise<void> {
    for (const tx of txs) {
      // Skip coinbase
      if (isCoinbase(tx)) continue;

      // Try to add back to mempool — log failure reason.  Reorg refill
      // is best-effort (Bitcoin Core's MaybeUpdateMempoolForReorg
      // semantics: drop txs that are no longer policy-valid against
      // the new tip).  Surfacing the error helps diagnose Pattern B2
      // partial-refill bugs vs. transient policy mismatches.
      const result = await this.addTransaction(tx);
      if (!result.accepted) {
        const txid = getTxId(tx).toString("hex");
        console.warn(
          `[mempool-readd] tx ${txid.slice(0, 16)}... rejected during reorg refill: ${result.error}`
        );
      }
    }
  }

  /**
   * Re-admit transactions disconnected by a chain reorg WITHOUT
   * re-running input UTXO / script / standardness checks.  Used by
   * the reorg-refill code path (BlockSync.connectBlock detects a
   * tip-prev mismatch and feeds disconnected txs here to mirror
   * Bitcoin Core's MaybeUpdateMempoolForReorg, validation.cpp).
   *
   * Why an unchecked path is needed in hotbuns specifically:
   *
   *   1. hotbuns's IBD-time block connect (BlockSync.connectBlock)
   *      does NOT persist undo data — coreConnectBlockChecks returns
   *      `spentOutputs` but BlockSync drops it (only the chain/state.ts
   *      path persists undo data, and that path is unwired during IBD).
   *      Without persisted undo data, a true UTXO disconnect is
   *      impossible: the inputs that the disconnected txs consumed
   *      cannot be restored to the UTXO set.
   *   2. The full validation that addTransaction runs (input lookup,
   *      script, BIP-68/113, fee) would therefore reject every refill
   *      candidate with "Missing input" because the input UTXOs were
   *      consumed by the now-disconnected blocks but never restored.
   *
   * This unchecked admission is policy-correct for the refill case
   * because the txs WERE valid against the chain that included them
   * (the disconnected blocks) — Core's MaybeUpdateMempoolForReorg
   * makes the same trust assumption (it does run a re-validation but
   * only because Core HAS a proper UTXO disconnect; with that prereq
   * met, all checks pass).  The ancestor/descendant + cluster
   * accounting and indexes are still maintained for getrawmempool /
   * RBF / fee-rate ordering correctness.
   *
   * Cross-impl audit:
   * CORE-PARITY-AUDIT/_mempool-refill-on-reorg-fleet-result-2026-05-05.md
   * Reference: camlcoin lib/sync.ml:2354-2363 (uses checked path
   * because OCaml's reorg has full UTXO disconnect first).
   *
   * Side effect: emits a [mempool-reorg-refill] log line per
   * admission so the corpus harness diagnosis (Pattern B1
   * vs B2 vs ordering) can be cross-referenced against per-impl logs.
   */
  reorgRefillUnchecked(txs: Transaction[]): void {
    for (const tx of txs) {
      if (isCoinbase(tx)) continue;
      const txid = getTxId(tx);
      const txidHex = txid.toString("hex");

      // Idempotency: if already in mempool (e.g. user broadcast
      // arrived between disconnect and refill), skip.  Mirrors
      // addTransaction's "already in mempool" guard.
      if (this.entries.has(txidHex)) continue;

      const weight = getTxWeight(tx);
      const vsize = getTxVSize(tx);
      // Fee + feeRate cannot be computed without the input UTXO set.
      // Use 0 (sentinel) — getrawmempool returns the txid which is
      // what the corpus harness checks; ordering uses miningScore
      // which we set to 0 too, so refill txs sort to the end (mining
      // selection prefers paying txs).
      const fee = 0n;
      const feeRate = 0;

      const entry: MempoolEntry = {
        tx,
        txid,
        fee,
        feeRate,
        vsize,
        weight,
        addedTime: Math.floor(Date.now() / 1000),
        height: this.tipHeight,
        spentBy: new Set<string>(),
        dependsOn: new Set<string>(), // unchecked path: no parent tracking
        ancestorCount: 1,
        ancestorSize: vsize,
        descendantCount: 1,
        descendantSize: vsize,
        clusterId: txidHex,
        miningScore: 0,
        ephemeralDustParents: new Set<string>(),
        hasEphemeralDust: false,
        sigOpCost: 0,
      };

      this.entries.set(txidHex, entry);
      this.currentSize += vsize;

      // Index spent outpoints so a later RBF / double-spend would
      // surface this entry as a conflict (defence-in-depth).
      for (const input of tx.inputs) {
        const outpointKey = `${input.prevOut.txid.toString("hex")}:${input.prevOut.vout}`;
        this.outpointIndex.set(outpointKey, txidHex);
      }

      console.log(
        `[mempool-reorg-refill] re-admitted disconnected tx ${txidHex.slice(0, 16)}... (vsize=${vsize})`
      );
    }
  }

  /**
   * Get transactions sorted by fee rate (descending) for block template.
   */
  getTransactionsByFeeRate(): MempoolEntry[] {
    const entries = Array.from(this.entries.values());

    // FIX-72: rank by MODIFIED fee rate (base + prioritisetransaction delta),
    // not the raw base fee rate. This is the entry's own single-entry mining
    // rank — an operator-prioritised low-base-fee tx now surfaces ahead of a
    // higher-base-fee peer, matching Core (txmempool.cpp:636-643 drives mining
    // off GetModifiedFee). Un-prioritised txs (delta 0) compare on entry.feeRate
    // exactly, so their relative order is unchanged. Multi-ancestor delta
    // folding is the W106 G8 separate follow-up.
    entries.sort((a, b) => this.getEntryModifiedFeeRate(b) - this.getEntryModifiedFeeRate(a));

    return entries;
  }

  /**
   * Get a transaction from the mempool by txid.
   */
  getTransaction(txid: Buffer): MempoolEntry | null {
    const txidHex = txid.toString("hex");
    return this.entries.get(txidHex) ?? null;
  }

  /**
   * Check if a transaction exists in the mempool.
   */
  hasTransaction(txid: Buffer): boolean {
    return this.entries.has(txid.toString("hex"));
  }

  /**
   * Get all transaction IDs in the mempool.
   */
  getAllTxids(): Buffer[] {
    return Array.from(this.entries.keys()).map((hex) => Buffer.from(hex, "hex"));
  }

  // ==========================================================================
  // Prioritisation (PrioritiseTransaction / mapDeltas / GetModifiedFee)
  // Reference: bitcoin-core/src/txmempool.cpp:630 (PrioritiseTransaction),
  //   :657 (ApplyDelta), :673 (GetPrioritisedTransactions), and
  //   kernel/mempool_entry.h GetModifiedFee/UpdateModifiedFee.
  // ==========================================================================

  /**
   * int64 saturating add — Core uses SaturatingAdd on CAmount (int64) so that
   * extreme stacked deltas clamp instead of overflowing. fee_delta is a signed
   * 64-bit satoshi value.
   */
  private static saturatingAddI64(a: bigint, b: bigint): bigint {
    const I64_MAX = 9_223_372_036_854_775_807n;
    const I64_MIN = -9_223_372_036_854_775_808n;
    const sum = a + b;
    if (sum > I64_MAX) return I64_MAX;
    if (sum < I64_MIN) return I64_MIN;
    return sum;
  }

  /**
   * Apply a fee-priority delta for *txid* (Core: PrioritiseTransaction).
   *
   * Accumulates onto any existing delta (saturating int64 add). The txid may
   * name a transaction not currently in the mempool: Core stores the delta
   * anyway so a later-arriving tx is prioritised. When the net delta returns
   * to 0 the entry is erased from the map (Core txmempool.cpp:644-653).
   *
   * @param txid internal-order txid bytes (the mempool's keying order).
   * @param deltaSats satoshis to add (negative subtracts). Signed int64.
   */
  prioritiseTransaction(txid: Buffer, deltaSats: bigint): void {
    const txidHex = txid.toString("hex");
    const current = this.mapDeltas.get(txidHex) ?? 0n;
    const newDelta = Mempool.saturatingAddI64(current, deltaSats);
    if (newDelta === 0n) {
      this.mapDeltas.delete(txidHex);
    } else {
      this.mapDeltas.set(txidHex, newDelta);
    }
    // The delta feeds the modified-fee mining rank + eviction via the cluster
    // cache; invalidate so getMiningScore()/linearizeCluster() recompute. Core
    // UpdateModifiedFee likewise re-sorts the entry in-place (txmempool.cpp:636).
    this.clusterCacheDirty = true;
  }

  /**
   * Modified fee for *txid* = base fee + stored delta (Core GetModifiedFee).
   * Returns the base fee unchanged when no delta is set. If the tx is not in
   * the mempool the base is 0, so the result is just the stored delta.
   *
   * @param txid internal-order txid bytes.
   */
  getModifiedFee(txid: Buffer): bigint {
    const txidHex = txid.toString("hex");
    const entry = this.entries.get(txidHex);
    const base = entry ? entry.fee : 0n;
    const delta = this.mapDeltas.get(txidHex) ?? 0n;
    return base + delta;
  }

  /**
   * Modified fee for an in-mempool *entry* = base fee + stored delta, clamped
   * at 0 on net-negative (Core GetModifiedFee never goes negative in the
   * mining/eviction comparators — kernel/mempool_entry.h). Takes the entry by
   * reference so callers in the hot linearization/sort paths avoid a second
   * map lookup. When no delta is set this returns `entry.fee` unchanged, which
   * keeps un-prioritised txs byte-identical to the pre-delta behaviour.
   *
   * FIX-72 (mirrors rustoshi get_modified_fee, mempool.rs:3372): the entry's
   * OWN single-entry mining rank + eviction pick consult this. Multi-ancestor
   * delta folding (an ancestor's delta propagating into a descendant's
   * cluster/ancestor score) is the W106 G8 separate follow-up and is NOT done
   * here — chunk merges still aggregate raw `entry.fee`.
   */
  private getEntryModifiedFee(entry: MempoolEntry): bigint {
    const delta = this.mapDeltas.get(entry.txid.toString("hex")) ?? 0n;
    if (delta === 0n) return entry.fee;
    const modified = entry.fee + delta;
    return modified > 0n ? modified : 0n;
  }

  /**
   * Modified fee *rate* (sat/vB) for an in-mempool *entry* = modified fee /
   * vsize. This is the per-entry rank used by the block-template selection sort
   * and by each transaction's seed chunk in cluster linearization (which in
   * turn drives both `miningScore` and the eviction tail-chunk pick). For an
   * un-prioritised tx this equals `entry.feeRate` exactly.
   */
  private getEntryModifiedFeeRate(entry: MempoolEntry): number {
    const delta = this.mapDeltas.get(entry.txid.toString("hex")) ?? 0n;
    if (delta === 0n) return entry.feeRate;
    if (entry.vsize <= 0) return entry.feeRate;
    return Number(this.getEntryModifiedFee(entry)) / entry.vsize;
  }

  /**
   * Return the full mapDeltas snapshot (internal-order txid hex -> delta) for
   * persistence (mempool.dat). Caller owns the copy.
   */
  getFeeDeltas(): Map<string, bigint> {
    return new Map(this.mapDeltas);
  }

  /**
   * Restore a single fee delta on load from mempool.dat. Unlike
   * prioritiseTransaction this is an absolute set (the persisted value is
   * already the accumulated net delta), and a 0 value is ignored.
   *
   * @param txid internal-order txid bytes.
   */
  loadFeeDelta(txid: Buffer, deltaSats: bigint): void {
    if (deltaSats === 0n) return;
    this.mapDeltas.set(txid.toString("hex"), deltaSats);
    this.clusterCacheDirty = true;
  }

  /**
   * Per-tx delta info for the getprioritisedtransactions RPC. Mirrors Core
   * CTxMemPool::GetPrioritisedTransactions (txmempool.cpp:673): one record per
   * mapDeltas entry, with modified_fee present only when the tx is in mempool.
   * Returned txids are in internal byte order; the RPC layer reverses to
   * display order for the JSON keys.
   */
  getPrioritisedTransactions(): Array<{
    txid: Buffer;
    feeDelta: bigint;
    inMempool: boolean;
    modifiedFee: bigint | null;
  }> {
    const result: Array<{
      txid: Buffer;
      feeDelta: bigint;
      inMempool: boolean;
      modifiedFee: bigint | null;
    }> = [];
    for (const [txidHex, delta] of this.mapDeltas) {
      const entry = this.entries.get(txidHex);
      const inMempool = entry !== undefined;
      result.push({
        txid: Buffer.from(txidHex, "hex"),
        feeDelta: delta,
        inMempool,
        modifiedFee: inMempool ? entry!.fee + delta : null,
      });
    }
    return result;
  }

  /**
   * Drop *txid*'s prioritisation delta (Core ClearPrioritisation). Called when
   * a tx confirms in a block so its delta does not leak onto a future
   * unrelated tx that happens to reuse the txid. Other removal reasons
   * (RBF replace, size-limit eviction, expiry, reorg) preserve the delta.
   *
   * @param txid internal-order txid bytes.
   */
  clearPrioritisation(txid: Buffer): void {
    if (this.mapDeltas.delete(txid.toString("hex"))) {
      this.clusterCacheDirty = true;
    }
  }

  /**
   * Check if a transaction is already confirmed in the blockchain.
   *
   * A transaction is considered confirmed if at least one of its outputs
   * exists in the UTXO set (or was spent after being confirmed).
   * We check output 0 as a heuristic - if the tx was confirmed, at least
   * one output must have been created.
   *
   * @param txid The transaction ID to check
   * @returns true if the transaction appears to be confirmed
   */
  async isTransactionConfirmed(txid: Buffer): Promise<boolean> {
    // Check if output 0 exists in the UTXO set
    // If it does, the transaction is confirmed (output exists)
    const utxoExists = await this.utxo.hasUTXOAsync({ txid, vout: 0 });
    return utxoExists;
  }

  /**
   * Check if a transaction conflicts with existing mempool entries.
   *
   * A conflict occurs when the transaction spends an output that is
   * already spent by another mempool transaction (double-spend).
   */
  private checkConflicts(tx: Transaction): MempoolEntry[] {
    const conflicts: MempoolEntry[] = [];

    for (const input of tx.inputs) {
      const outpointKey = `${input.prevOut.txid.toString("hex")}:${input.prevOut.vout}`;
      const spendingTxid = this.outpointIndex.get(outpointKey);

      if (spendingTxid) {
        const entry = this.entries.get(spendingTxid);
        if (entry && !conflicts.includes(entry)) {
          conflicts.push(entry);
        }
      }
    }

    return conflicts;
  }

  /**
   * Check ancestor limits for a new transaction.
   */
  /**
   * Check ancestor and descendant limits for a new transaction.
   *
   * Enforces 4 gates from Bitcoin Core (policy/policy.h + kernel/mempool_limits.h):
   *   Gate A — ancestor count:   new tx's ancestor set (incl. self) ≤ MAX_ANCESTORS (25).
   *             Reference: bitcoin-core/src/policy/policy.h:76
   *   Gate B — ancestor size:    total vsize of ancestors (incl. self) ≤ MAX_ANCESTOR_SIZE (101,000 vB).
   *             Reference: bitcoin-core/src/policy/policy.h:74 (DEFAULT_CLUSTER_SIZE_LIMIT_KVB = 101)
   *   Gate C — descendant count: each in-mempool ancestor's descendant count (incl. existing + new) ≤ MAX_DESCENDANTS (25).
   *             Reference: bitcoin-core/src/policy/policy.h:78
   *   Gate D — descendant size:  each in-mempool ancestor's descendant vsize (incl. existing + new) ≤ MAX_DESCENDANT_SIZE (101,000 vB).
   *             Reference: bitcoin-core/src/policy/policy.h:74 (DEFAULT_CLUSTER_SIZE_LIMIT_KVB = 101)
   *             Previously enforced via -limitdescendantsize in legacy Core.
   */
  private checkAncestorLimits(
    parentTxids: Set<string>,
    newTxVsize: number
  ): { valid: boolean; error?: string } {
    // Calculate ancestor stats
    const { ancestorCount, ancestorSize } = this.calculateAncestorStats(parentTxids, newTxVsize);

    // Gate A: ancestor count limit (includes self).
    // Bitcoin Core: kernel/mempool_limits.h MemPoolLimits::ancestor_count = DEFAULT_ANCESTOR_LIMIT = 25.
    if (ancestorCount > MAX_ANCESTORS) {
      return {
        valid: false,
        error: `too-long-mempool-chain: ${ancestorCount} ancestors exceeds limit of ${MAX_ANCESTORS}`,
      };
    }

    // Gate B: ancestor size limit in vbytes (includes self).
    // Bitcoin Core: DEFAULT_CLUSTER_SIZE_LIMIT_KVB = 101 kvB → 101,000 vB.
    if (ancestorSize > MAX_ANCESTOR_SIZE) {
      return {
        valid: false,
        error: `too-long-mempool-chain: ancestor vsize ${ancestorSize} exceeds limit of ${MAX_ANCESTOR_SIZE} vB`,
      };
    }

    // Gates C + D: descendant limits for all in-mempool ancestors.
    // Adding this tx would increase each ancestor's descendant count by 1 and
    // descendant size by newTxVsize. Check both before admission.
    const allAncestors = this.getAncestorSet(parentTxids);
    for (const ancestorTxidHex of allAncestors) {
      const ancestor = this.entries.get(ancestorTxidHex);
      if (ancestor) {
        // Gate C: descendant count.
        // Bitcoin Core: kernel/mempool_limits.h MemPoolLimits::descendant_count = DEFAULT_DESCENDANT_LIMIT = 25.
        const newDescendantCount = ancestor.descendantCount + 1;
        if (newDescendantCount > MAX_DESCENDANTS) {
          return {
            valid: false,
            error: `too-long-mempool-chain: ancestor ${ancestorTxidHex.slice(0, 16)}... would have ${newDescendantCount} descendants (limit ${MAX_DESCENDANTS})`,
          };
        }

        // Gate D: descendant size in vbytes.
        // Bitcoin Core: DEFAULT_CLUSTER_SIZE_LIMIT_KVB = 101 kvB → 101,000 vB.
        // Previously -limitdescendantsize in legacy Core before cluster mempool.
        const newDescendantSize = ancestor.descendantSize + newTxVsize;
        if (newDescendantSize > MAX_DESCENDANT_SIZE) {
          return {
            valid: false,
            error: `too-long-mempool-chain: ancestor ${ancestorTxidHex.slice(0, 16)}... descendant vsize would be ${newDescendantSize} (limit ${MAX_DESCENDANT_SIZE} vB)`,
          };
        }
      }
    }

    return { valid: true };
  }

  /**
   * Check TRUC (v3) policy rules for a transaction.
   *
   * Rules for nVersion === 3 transactions:
   * 1. A v3 tx can have at most 1 unconfirmed ancestor (parent) in the mempool.
   * 2. A v3 tx can have at most 1 unconfirmed descendant (child).
   * 3. A v3 child tx must be at most 1000 vbytes.
   * 4. A v3 parent can be up to standard size (TRUC_MAX_VSIZE = 10000).
   * 5. v3 transactions are always replaceable (implicit RBF signaling).
   * 6. A v3 child can replace an existing v3 child of the same parent without
   *    the normal RBF fee-rate rule (sibling eviction).
   * 7. Non-v3 transactions cannot spend unconfirmed v3 outputs;
   *    v3 transactions cannot spend unconfirmed non-v3 outputs.
   *
   * @returns Result with optional siblingToEvict txid for sibling eviction
   */
  private checkTRUCPolicy(
    tx: Transaction,
    vsize: number,
    parentTxids: Set<string>,
    conflicts: MempoolEntry[],
    isReplacement: boolean
  ): { valid: boolean; error?: string; siblingToEvict?: string } {
    const isV3 = tx.version === TRUC_VERSION;

    // Get mempool parents (those that are in the mempool)
    const mempoolParents: MempoolEntry[] = [];
    for (const parentTxidHex of parentTxids) {
      const parent = this.entries.get(parentTxidHex);
      if (parent) {
        mempoolParents.push(parent);
      }
    }

    // Rule 7: Check version inheritance between this tx and its mempool parents
    for (const parent of mempoolParents) {
      const parentIsV3 = parent.tx.version === TRUC_VERSION;

      if (isV3 && !parentIsV3) {
        // v3 tx cannot spend unconfirmed non-v3 outputs
        return {
          valid: false,
          error: `version=3 tx cannot spend from non-version=3 unconfirmed tx ${parent.txid.toString("hex").slice(0, 16)}...`,
        };
      }

      if (!isV3 && parentIsV3) {
        // non-v3 tx cannot spend unconfirmed v3 outputs
        return {
          valid: false,
          error: `non-version=3 tx cannot spend from version=3 unconfirmed tx ${parent.txid.toString("hex").slice(0, 16)}...`,
        };
      }
    }

    // The rest of the rules only apply to v3 transactions
    if (!isV3) {
      return { valid: true };
    }

    // Rule 4: v3 tx must be within TRUC_MAX_VSIZE
    if (vsize > TRUC_MAX_VSIZE) {
      return {
        valid: false,
        error: `version=3 tx is too big: ${vsize} > ${TRUC_MAX_VSIZE} vbytes`,
      };
    }

    // Rule 1: v3 tx can have at most 1 unconfirmed ancestor (parent) in mempool
    // With TRUC_ANCESTOR_LIMIT = 2, that means parent + self
    if (mempoolParents.length > 1) {
      return {
        valid: false,
        error: `version=3 tx would have too many ancestors: ${mempoolParents.length + 1} > ${TRUC_ANCESTOR_LIMIT}`,
      };
    }

    // If there's a mempool parent, ensure it doesn't also have an ancestor.
    // Mirrors Bitcoin Core SingleTRUCChecks: GetAncestorCount(parent) + 1 > TRUC_ANCESTOR_LIMIT.
    // ancestorCount includes the parent itself, so ancestorCount >= 2 means parent has an ancestor.
    if (mempoolParents.length === 1) {
      const parent = mempoolParents[0];
      // ancestorCount includes the parent itself; > 1 means parent itself has an unconfirmed ancestor.
      // Equivalent to Core's GetAncestorCount(mempool_parents[0]) + 1 > TRUC_ANCESTOR_LIMIT (= 2).
      if (parent.ancestorCount > 1) {
        return {
          valid: false,
          error: `version=3 tx would have too many ancestors`,
        };
      }

      // Rule 3: If this is a child (has unconfirmed parent), it must be small
      if (vsize > TRUC_CHILD_MAX_VSIZE) {
        return {
          valid: false,
          error: `version=3 child tx is too big: ${vsize} > ${TRUC_CHILD_MAX_VSIZE} vbytes`,
        };
      }

      // Rule 2: Check descendant limit for the parent.
      // Mirrors Bitcoin Core SingleTRUCChecks:
      //   if (pool.GetDescendantCount(parent_entry) + 1 > TRUC_DESCENDANT_LIMIT && !child_will_be_replaced)
      // GetDescendantCount includes the entry itself, so GetDescendantCount = 1 means no children.
      // We use parent.descendantCount (cached, transitive) as the primary count, and scan spentBy
      // only to identify the sibling candidate for eviction.
      const parentTxidHex = parent.txid.toString("hex");

      // Collect conflict txids so we can credit replacements.
      const conflictTxids = new Set(conflicts.map((c) => c.txid.toString("hex")));

      // Count conflicts that are direct children of the parent (will be removed).
      let conflictedChildCount = 0;
      let existingChild: MempoolEntry | undefined;
      for (const childTxidHex of parent.spentBy) {
        const child = this.entries.get(childTxidHex);
        if (conflictTxids.has(childTxidHex)) {
          conflictedChildCount++;
        } else if (child) {
          // Track the non-conflict child as a sibling candidate.
          existingChild = child;
        }
      }

      // parent.descendantCount includes the parent itself. Subtract 1 (self) to get
      // number of existing descendants. Subtract conflicted children that will be evicted.
      // If after accounting for replacements the count is >= 1, we already have a child.
      const currentDescendants = (parent.descendantCount - 1) - conflictedChildCount;

      // If parent already has a descendant that isn't being replaced
      if (currentDescendants >= 1) {
        // Sibling eviction: if there's exactly one existing v3 child, we can evict it.
        // Mirrors Bitcoin Core SingleTRUCChecks (policy/truc_policy.cpp):
        //   consider_sibling_eviction = (GetDescendantCount(parent) == 2)
        //                            && (GetAncestorCount(sibling) == 2)
        // The ancestor count guard (ancestorCount === 2) rejects sibling eviction
        // when the sibling itself has extra ancestors (e.g. after a reorg), which
        // Core also refuses in that case.
        if (
          currentDescendants === 1 &&
          existingChild &&
          existingChild.descendantCount === 1 && // sibling has no grandchildren
          existingChild.ancestorCount === 2       // sibling has exactly 1 mempool ancestor (the shared parent)
        ) {
          // Allow sibling eviction - return the sibling to be evicted
          return {
            valid: false,
            error: `version=3 tx would exceed descendant limit`,
            siblingToEvict: existingChild.txid.toString("hex"),
          };
        }

        return {
          valid: false,
          error: `version=3 tx would exceed descendant limit: parent ${parentTxidHex.slice(0, 16)}... already has ${currentDescendants} descendant(s)`,
        };
      }
    }

    return { valid: true };
  }

  /**
   * Calculate ancestor count and size for a new transaction.
   */
  private calculateAncestorStats(
    parentTxids: Set<string>,
    newTxVsize: number
  ): { ancestorCount: number; ancestorSize: number } {
    const ancestors = this.getAncestorSet(parentTxids);

    let ancestorSize = newTxVsize; // Include self
    for (const txidHex of ancestors) {
      const entry = this.entries.get(txidHex);
      if (entry) {
        ancestorSize += entry.vsize;
      }
    }

    return {
      ancestorCount: ancestors.size + 1, // +1 for self
      ancestorSize,
    };
  }

  /**
   * Get the set of all ancestor txids (not including self).
   */
  private getAncestorSet(parentTxids: Set<string>): Set<string> {
    const ancestors = new Set<string>();
    const queue = Array.from(parentTxids);

    while (queue.length > 0) {
      const txidHex = queue.shift()!;

      if (ancestors.has(txidHex)) continue;
      ancestors.add(txidHex);

      const entry = this.entries.get(txidHex);
      if (entry) {
        for (const parentTxidHex of entry.dependsOn) {
          if (!ancestors.has(parentTxidHex)) {
            queue.push(parentTxidHex);
          }
        }
      }
    }

    return ancestors;
  }

  /**
   * Update all ancestors' descendant counts when a new tx is added.
   */
  private updateAncestorDescendantStats(newTxidHex: string, newTxVsize: number): void {
    const entry = this.entries.get(newTxidHex);
    if (!entry) return;

    const ancestors = this.getAncestorSet(entry.dependsOn);
    for (const ancestorTxidHex of ancestors) {
      const ancestor = this.entries.get(ancestorTxidHex);
      if (ancestor) {
        ancestor.descendantCount += 1;
        ancestor.descendantSize += newTxVsize;
      }
    }
  }

  /**
   * Count the number of descendants for a transaction (using BFS, not cache).
   * This is used for verification/debugging.
   */
  private countDescendants(txidHex: string): number {
    const descendants = new Set<string>();
    const queue: string[] = [];

    const entry = this.entries.get(txidHex);
    if (!entry) return 0;

    for (const childTxidHex of entry.spentBy) {
      queue.push(childTxidHex);
    }

    while (queue.length > 0) {
      const childTxidHex = queue.shift()!;

      if (descendants.has(childTxidHex)) continue;
      descendants.add(childTxidHex);

      const childEntry = this.entries.get(childTxidHex);
      if (childEntry) {
        for (const grandchildTxidHex of childEntry.spentBy) {
          if (!descendants.has(grandchildTxidHex)) {
            queue.push(grandchildTxidHex);
          }
        }
      }
    }

    return descendants.size;
  }

  /**
   * Get the set of all descendant txids (not including self).
   * Used for RBF to calculate total eviction count.
   */
  private getDescendantSet(txidHex: string): Set<string> {
    const descendants = new Set<string>();
    const queue: string[] = [];

    const entry = this.entries.get(txidHex);
    if (!entry) return descendants;

    for (const childTxidHex of entry.spentBy) {
      queue.push(childTxidHex);
    }

    while (queue.length > 0) {
      const childTxidHex = queue.shift()!;

      if (descendants.has(childTxidHex)) continue;
      descendants.add(childTxidHex);

      const childEntry = this.entries.get(childTxidHex);
      if (childEntry) {
        for (const grandchildTxidHex of childEntry.spentBy) {
          if (!descendants.has(grandchildTxidHex)) {
            queue.push(grandchildTxidHex);
          }
        }
      }
    }

    return descendants;
  }

  /**
   * Remove a transaction from the mempool without removing dependents.
   * Used internally by RBF when we're removing all conflicts at once.
   */
  private removeTransactionInternal(txid: Buffer): void {
    const txidHex = txid.toString("hex");
    const entry = this.entries.get(txidHex);

    if (!entry) {
      return;
    }

    // Update ancestors' descendant stats before removing
    const ancestors = this.getAncestorSet(entry.dependsOn);
    for (const ancestorTxidHex of ancestors) {
      const ancestor = this.entries.get(ancestorTxidHex);
      if (ancestor) {
        ancestor.descendantCount -= 1;
        ancestor.descendantSize -= entry.vsize;
      }
    }

    // Remove from parent's spentBy
    for (const parentTxidHex of entry.dependsOn) {
      const parent = this.entries.get(parentTxidHex);
      if (parent) {
        parent.spentBy.delete(txidHex);
      }
    }

    // Remove outpoint index entries
    for (const input of entry.tx.inputs) {
      const outpointKey = `${input.prevOut.txid.toString("hex")}:${input.prevOut.vout}`;
      this.outpointIndex.delete(outpointKey);
    }

    // Remove from entries
    this.entries.delete(txidHex);
    this.currentSize -= entry.vsize;
  }

  /**
   * Return the BIP-125 RBF opt-in state for a mempool transaction.
   *
   * Reports "yes" if the transaction itself or any of its mempool ancestors
   * signals opt-in RBF via nSequence <= MAX_BIP125_RBF_SEQUENCE (0xfffffffd).
   * Reports "no" if neither the tx nor any ancestor signals.
   * Reports "unknown" if the txid is not in the mempool.
   *
   * Used for the "bip125-replaceable" field in getmempoolentry / getrawmempool.
   * Mirrors bitcoin-core/src/policy/rbf.cpp:IsRBFOptIn.
   *
   * Note: hotbuns runs full-RBF (all mempool transactions are practically
   * replaceable regardless of this signal), but we report the BIP-125 signal
   * status faithfully for RPC compatibility with Bitcoin Core.
   */
  getRBFOptInState(txid: Buffer): RBFTransactionState {
    const txidHex = txid.toString("hex");
    const entry = this.entries.get(txidHex);
    if (!entry) {
      return RBFTransactionState.UNKNOWN;
    }

    // Build the ancestor Transaction iterable (lazy: just walk dependsOn).
    const self = this;
    function* ancestorTxs(): Iterable<import("../validation/tx.js").Transaction> {
      const visited = new Set<string>();
      const queue = Array.from(entry!.dependsOn);
      while (queue.length > 0) {
        const parentHex = queue.shift()!;
        if (visited.has(parentHex)) continue;
        visited.add(parentHex);
        const parentEntry = self.entries.get(parentHex);
        if (parentEntry) {
          yield parentEntry.tx;
          for (const grandparentHex of parentEntry.dependsOn) {
            if (!visited.has(grandparentHex)) queue.push(grandparentHex);
          }
        }
      }
    }

    return isRBFOptIn(entry.tx, true, ancestorTxs());
  }

  /**
   * Check if a transaction is replaceable.
   *
   * In full-RBF mode (hotbuns default) every mempool transaction is
   * replaceable regardless of BIP-125 sequence signaling.  Returns true for
   * any known txid, false for unknown (not in mempool).
   *
   * For the BIP-125 signal status (used in "bip125-replaceable" RPC field),
   * use getRBFOptInState() instead.
   */
  isReplaceable(txid: Buffer): boolean {
    // Full RBF: every known mempool transaction is replaceable.
    return this.entries.has(txid.toString("hex"));
  }

  /**
   * Check whether a transaction signals opt-in RBF via BIP-125.
   * Mirrors bitcoin-core/src/util/rbf.cpp:SignalsOptInRBF.
   * Does NOT walk ancestors — use getRBFOptInState() for the full check.
   */
  static signalsOptInRBF(tx: import("../validation/tx.js").Transaction): boolean {
    return signalsOptInRBF(tx);
  }

  /**
   * Expire transactions that have been in the mempool too long.
   *
   * Removes all transactions whose addedTime is older than `time` (Unix seconds),
   * including all descendants of each expired transaction.
   *
   * Reference: bitcoin-core/src/txmempool.cpp:811-827 (CTxMemPool::Expire)
   * Core signature: int CTxMemPool::Expire(std::chrono::seconds time)
   *
   * @param time - Expiry cutoff in Unix seconds. Transactions added before this
   *               time are removed. Defaults to (now - MEMPOOL_EXPIRY_SECONDS).
   * @returns Number of transactions removed.
   */
  expire(time?: number): number {
    const cutoff = time ?? (Math.floor(Date.now() / 1000) - MEMPOOL_EXPIRY_SECONDS);

    // Collect all txids whose addedTime is before the cutoff, in insertion order.
    // We remove in topological order (parents first) to avoid removing children
    // of entries we haven't yet removed; removeTransaction(removeDependents=true)
    // handles cascading cleanly regardless, but collecting the set first mirrors
    // Core's approach.
    const toRemove = new Set<string>();
    for (const [txidHex, entry] of this.entries) {
      if (entry.addedTime < cutoff) {
        toRemove.add(txidHex);
      }
    }

    // Expand to include all descendants (mirrors Core's CalculateDescendants +
    // RemoveStaged).
    const stage = new Set<string>(toRemove);
    for (const txidHex of toRemove) {
      const descendants = this.getDescendantSet(txidHex);
      for (const d of descendants) {
        stage.add(d);
      }
    }

    for (const txidHex of stage) {
      if (this.entries.has(txidHex)) {
        const entry = this.entries.get(txidHex)!;
        this.removeTransactionInternal(entry.txid);
      }
    }

    return stage.size;
  }

  /**
   * Update the rolling minimum fee rate when a chunk is evicted.
   *
   * Called by trimToSize() for each evicted chunk. If the chunk's fee rate
   * exceeds the current rolling minimum, the rolling minimum is updated and
   * blockSinceLastRollingFeeBump is cleared (rate just bumped, no decay yet).
   *
   * Reference: bitcoin-core/src/txmempool.cpp:853-859 (CTxMemPool::trackPackageRemoved)
   */
  private trackPackageRemoved(rateSatPerKvB: number): void {
    if (rateSatPerKvB > this.rollingMinimumFeeRate) {
      this.rollingMinimumFeeRate = rateSatPerKvB;
      this.blockSinceLastRollingFeeBump = false;
    }
  }

  /**
   * Get the dynamic minimum fee rate for mempool admission.
   *
   * When the mempool is full and transactions are being evicted, this returns
   * the fee rate of the last-evicted chunk (plus incrementalRelayFee) so that
   * new transactions must pay at least that much to enter.
   *
   * The rate decays exponentially with ROLLING_FEE_HALFLIFE (12 hours):
   *   - If pool usage < sizelimit/4: halflife is quartered (faster decay)
   *   - If pool usage < sizelimit/2: halflife is halved (faster decay)
   *   - Otherwise: full 12h halflife
   *
   * Returns 0 once the rate decays below incrementalRelayFee/2. The floor
   * when non-zero is max(rollingMinimumFeeRate, incrementalRelayFee).
   *
   * Reference: bitcoin-core/src/txmempool.cpp:829-851 (CTxMemPool::GetMinFee)
   *
   * @returns Minimum fee rate in sat/kvB.
   */
  getMinFee(): number {
    if (!this.blockSinceLastRollingFeeBump || this.rollingMinimumFeeRate === 0) {
      return this.rollingMinimumFeeRate;
    }

    const now = Math.floor(Date.now() / 1000);
    if (now > this.lastRollingFeeUpdate + 10) {
      // Choose halflife based on how full the pool is.
      // Reference: txmempool.cpp:836-841
      let halflife = ROLLING_FEE_HALFLIFE;
      if (this.currentSize < this.maxSize / 4) {
        halflife /= 4;
      } else if (this.currentSize < this.maxSize / 2) {
        halflife /= 2;
      }

      // Exponential decay: rate /= 2^(Δt / halflife)
      // Reference: txmempool.cpp:842
      this.rollingMinimumFeeRate =
        this.rollingMinimumFeeRate / Math.pow(2.0, (now - this.lastRollingFeeUpdate) / halflife);
      this.lastRollingFeeUpdate = now;

      // Floor: once rate < incrementalRelayFee/2, zero it out entirely.
      // Reference: txmempool.cpp:845-848
      const incrementalRelayKvB = this.incrementalRelayFee * 1000; // sat/vB → sat/kvB
      if (this.rollingMinimumFeeRate < incrementalRelayKvB / 2) {
        this.rollingMinimumFeeRate = 0;
        return 0;
      }
    }

    // Return the greater of the rolling rate and the incremental relay fee.
    // Reference: txmempool.cpp:850
    const incrementalRelayKvB = this.incrementalRelayFee * 1000;
    return Math.max(this.rollingMinimumFeeRate, incrementalRelayKvB);
  }

  /**
   * Trim the mempool to `sizelimit` bytes by evicting the lowest-feerate chunks.
   *
   * Core eviction algorithm (TrimToSize, txmempool.cpp:861-911):
   *  1. While DynamicMemoryUsage() > sizelimit:
   *     a. Get the worst chunk from the cluster linearization (lowest fee-rate chunk
   *        in the worst-ordered cluster).
   *     b. Compute removed_feerate = chunk_feerate + incrementalRelayFee.
   *     c. Call trackPackageRemoved(removed_feerate) to bump the rolling minimum.
   *     d. Remove all transactions in the chunk.
   *  2. Log the max fee rate removed.
   *
   * The crucial difference from the old evict(): Core evicts an entire *chunk*
   * atomically (which may be multiple transactions), not just the single
   * worst-scoring individual transaction. This ensures the CPFP cluster is
   * evicted together.
   *
   * Reference: bitcoin-core/src/txmempool.cpp:861-911
   */
  private evict(): void {
    this.rebuildClusterCache();

    let nTxnRemoved = 0;
    let maxFeeRateRemovedKvB = 0;

    while (this.currentSize > this.maxSize && this.entries.size > 0) {
      // Find the worst chunk across all clusters.
      // "Worst" = lowest chunk fee rate in the last (tail) position of some
      // cluster's linearization, since linearizations are sorted best-first.
      // We scan all cluster linearizations and pick the lowest tail-chunk.
      let worstChunkTxids: string[] = [];
      let worstChunkFeeRate = Infinity;
      let worstChunkTotalVsize = 0;
      let worstChunkTotalFee = 0n;

      for (const [, cluster] of this.clusterCache) {
        const lin = cluster.linearization;
        if (lin.chunks.length === 0) continue;
        // The last chunk in the linearization has the lowest fee rate.
        const tailChunk = lin.chunks[lin.chunks.length - 1];
        if (tailChunk.feeRate < worstChunkFeeRate) {
          worstChunkFeeRate = tailChunk.feeRate;
          worstChunkTxids = Array.from(tailChunk.txids);
          worstChunkTotalVsize = tailChunk.totalVsize;
          worstChunkTotalFee = tailChunk.totalFee;
        }
      }

      if (worstChunkTxids.length === 0) break;

      // Compute the evicted fee rate in sat/kvB and add incrementalRelayFee.
      // Reference: txmempool.cpp:870-878
      // removed = chunk_feerate_sat_per_kvB + incrementalRelayFee_sat_per_kvB
      const chunkFeeRateKvB =
        worstChunkTotalVsize > 0
          ? (Number(worstChunkTotalFee) / worstChunkTotalVsize) * 1000
          : 0;
      const incrementalRelayKvB = this.incrementalRelayFee * 1000;
      const removedKvB = chunkFeeRateKvB + incrementalRelayKvB;

      this.trackPackageRemoved(removedKvB);
      if (removedKvB > maxFeeRateRemovedKvB) {
        maxFeeRateRemovedKvB = removedKvB;
      }

      nTxnRemoved += worstChunkTxids.length;

      // Remove all transactions in the chunk.
      // removeTransactionInternal handles descendant stats + index cleanup.
      for (const txidHex of worstChunkTxids) {
        if (this.entries.has(txidHex)) {
          const entry = this.entries.get(txidHex)!;
          this.removeTransactionInternal(entry.txid);
        }
      }

      // Rebuild cluster cache after removals to get the next worst chunk.
      this.clusterCacheDirty = true;
      this.rebuildClusterCache();
    }

    // Sync the admission minFeeRate from the rolling rate (sat/vB).
    // This ensures that new transactions must pay at least the rate of what
    // was just evicted.
    if (maxFeeRateRemovedKvB > 0) {
      // Convert sat/kvB → sat/vB for the admission gate comparison.
      const newMinSatPerVB = maxFeeRateRemovedKvB / 1000;
      this.minFeeRate = Math.max(this.minFeeRate, newMinSatPerVB);
    }
  }

  /**
   * Get mempool statistics.
   */
  getInfo(): { size: number; bytes: number; minFeeRate: number } {
    // Expose the dynamic minimum (rolling + static floor) as sat/vB.
    const dynamicMinSatPerVB = Math.max(this.minFeeRate, this.getMinFee() / 1000);
    return {
      size: this.entries.size,
      bytes: this.currentSize,
      minFeeRate: dynamicMinSatPerVB,
    };
  }

  /**
   * Set the static admission min-relay fee rate (sat/vB). Mirrors the
   * `-minrelaytxfee` configuration knob in Bitcoin Core. The dynamic
   * rolling-min always supersedes this when higher.
   */
  setMinFeeRate(satPerVB: number): void {
    this.minFeeRate = satPerVB;
  }

  /**
   * Get the minimum fee rate in sat/kvB (for BIP133 feefilter).
   *
   * Returns the rolling dynamic minimum (with decay), floored by the static
   * admission minFeeRate, converted to sat/kvB as an integer.
   *
   * Reference: bitcoin-core/src/txmempool.cpp:829-851 (GetMinFee),
   *            net_processing.cpp BIP133 feefilter message construction.
   */
  getMinFeeRateKvB(): bigint {
    // getMinFee() returns sat/kvB (rolling minimum with decay).
    // Convert the static admission floor (sat/vB) to sat/kvB for comparison.
    const rollingKvB = this.getMinFee();
    const admissionKvB = this.minFeeRate * 1000;
    return BigInt(Math.floor(Math.max(rollingKvB, admissionKvB)));
  }

  /**
   * Set the incremental relay fee rate (sat/vB).
   * For RBF, replacement must pay at least this * newVsize more than replaced fees.
   */
  setIncrementalRelayFee(rate: number): void {
    this.incrementalRelayFee = rate;
  }

  /**
   * Get the incremental relay fee rate (sat/vB).
   */
  getIncrementalRelayFee(): number {
    return this.incrementalRelayFee;
  }

  /**
   * Get mempool entry count.
   */
  getSize(): number {
    return this.entries.size;
  }

  /**
   * Clear all mempool entries.
   */
  clear(): void {
    this.entries.clear();
    this.outpointIndex.clear();
    this.currentSize = 0;
    this.minFeeRate = DEFAULT_MIN_FEE_RATE;
    this.clusters.clear();
    this.clusterCache.clear();
    this.clusterCacheDirty = false;
    // Reset rolling fee state.
    this.rollingMinimumFeeRate = 0;
    this.blockSinceLastRollingFeeBump = false;
    this.lastRollingFeeUpdate = Math.floor(Date.now() / 1000);
  }

  /**
   * Check if an outpoint is spent by a mempool transaction.
   */
  isOutpointSpent(txid: Buffer, vout: number): boolean {
    const outpointKey = `${txid.toString("hex")}:${vout}`;
    return this.outpointIndex.has(outpointKey);
  }

  /**
   * Return the txid (hex, internal byte order) of the mempool transaction that
   * spends `(txid, vout)`, or null when no mempool tx spends it. The mempool
   * reverse-index (`outpointIndex`) analog of Bitcoin Core's
   * `CTxMemPool::GetConflictTx` — used by `gettxspendingprevout` to resolve the
   * MEMPOOL-spend path before consulting the on-chain txospenderindex.
   *
   * `txid` is internal/wire byte order (matching `input.prevOut.txid`).
   * Reference: bitcoin-core/src/txmempool.h::GetConflictTx.
   */
  getSpendingTxid(txid: Buffer, vout: number): string | null {
    const outpointKey = `${txid.toString("hex")}:${vout}`;
    return this.outpointIndex.get(outpointKey) ?? null;
  }

  // ============================================================================
  // Cluster Mempool Methods
  // ============================================================================

  /**
   * Get the cluster ID for a transaction.
   */
  getClusterId(txidHex: string): string {
    return this.clusters.find(txidHex);
  }

  /**
   * Get the size of a cluster (number of transactions).
   */
  getClusterSize(txidHex: string): number {
    return this.clusters.getSize(txidHex);
  }

  /**
   * Check if adding a transaction would exceed the cluster limits.
   *
   * Enforces two gates from Bitcoin Core (policy/policy.h + kernel/mempool_limits.h):
   *   Gate 1 — cluster count: merged cluster tx count must not exceed MAX_CLUSTER_COUNT (64).
   *             Core: DEFAULT_CLUSTER_LIMIT = 64; CheckMemPoolPolicyLimits() via TxGraph::IsOversized.
   *             Reference: bitcoin-core/src/policy/policy.h:72, src/txmempool.cpp:1072-1079
   *   Gate 2 — cluster vbytes: merged cluster total vsize must not exceed MAX_CLUSTER_SIZE_VBYTES (101,000).
   *             Core: cluster_size_vbytes = DEFAULT_CLUSTER_SIZE_LIMIT_KVB * 1000 = 101,000 vB.
   *             Reference: bitcoin-core/src/policy/policy.h:74, src/kernel/mempool_limits.h:22
   *
   * A new transaction may merge multiple existing clusters together when it spends
   * outputs from transactions in different clusters.
   */
  private checkClusterSizeLimit(
    parentTxids: Set<string>,
    newTxVsize: number,
    excludeTxids?: Set<string>,
  ): { valid: boolean; error?: string } {
    // `excludeTxids` is the set of txids that will be removed by this admission
    // (e.g. RBF conflicts and their descendants). They contribute zero to the
    // post-eviction cluster — mirrors Bitcoin Core's
    // `m_subpackage.m_changeset->CheckMemPoolPolicyLimits()` (validation.cpp:1023)
    // which evaluates limits against the staged-changeset state, not the
    // pre-eviction state. Without this, an RBF replacement is falsely rejected
    // when the conflicts it evicts inflate the cluster past MAX_CLUSTER_COUNT
    // or MAX_CLUSTER_SIZE_VBYTES.
    const excluded = excludeTxids ?? new Set<string>();

    // Find all unique cluster roots that would be merged by adding this tx.
    const clusterRoots = new Set<string>();
    for (const parentTxidHex of parentTxids) {
      // Treat a parent that's being evicted as "not in the mempool" for cluster
      // purposes — its outputs come from chainstate post-eviction.
      if (excluded.has(parentTxidHex)) continue;
      if (this.entries.has(parentTxidHex)) {
        clusterRoots.add(this.clusters.find(parentTxidHex));
      }
    }

    // Gate 1: cluster count.
    // Sum entries in each merged cluster, subtracting any entries being evicted.
    let mergedCount = 1; // +1 for the new tx
    let mergedVsize = newTxVsize;
    for (const [txidHex, entry] of this.entries) {
      const root = this.clusters.find(txidHex);
      if (!clusterRoots.has(root)) continue;
      if (excluded.has(txidHex)) continue;
      mergedCount += 1;
      mergedVsize += entry.vsize;
    }

    if (mergedCount > MAX_CLUSTER_COUNT) {
      return {
        valid: false,
        error: `too-large-cluster: cluster would exceed maximum count ${MAX_CLUSTER_COUNT} (would be ${mergedCount})`,
      };
    }

    if (mergedVsize > MAX_CLUSTER_SIZE_VBYTES) {
      return {
        valid: false,
        error: `too-large-cluster: cluster would exceed maximum vsize ${MAX_CLUSTER_SIZE_VBYTES} vB (would be ${mergedVsize})`,
      };
    }

    return { valid: true };
  }

  /**
   * Add a transaction to the cluster structure.
   * Updates union-find and marks cluster cache as dirty.
   */
  private addToCluster(txidHex: string, parentTxids: Set<string>): void {
    // Create a new singleton cluster for this tx
    this.clusters.makeSet(txidHex);

    // Union with all parent clusters
    for (const parentTxidHex of parentTxids) {
      if (this.entries.has(parentTxidHex)) {
        this.clusters.union(txidHex, parentTxidHex);
      }
    }

    // Mark cache as dirty since cluster structure changed
    this.clusterCacheDirty = true;
  }

  /**
   * Rebuild the cluster cache from scratch.
   * Called lazily when cluster information is needed.
   */
  private rebuildClusterCache(): void {
    if (!this.clusterCacheDirty) return;

    this.clusterCache.clear();

    // Group transactions by cluster ID
    const clusterTxids = new Map<string, Set<string>>();
    for (const txidHex of this.entries.keys()) {
      const clusterId = this.clusters.find(txidHex);
      if (!clusterTxids.has(clusterId)) {
        clusterTxids.set(clusterId, new Set());
      }
      clusterTxids.get(clusterId)!.add(txidHex);
    }

    // Build cluster objects with linearization
    for (const [clusterId, txids] of clusterTxids) {
      const linearization = this.linearizeCluster(txids);

      let totalFee = 0n;
      let totalVsize = 0;
      for (const txidHex of txids) {
        const entry = this.entries.get(txidHex)!;
        totalFee += entry.fee;
        totalVsize += entry.vsize;
      }

      const cluster: Cluster = {
        id: clusterId,
        txids,
        totalFee,
        totalVsize,
        linearization,
      };

      this.clusterCache.set(clusterId, cluster);

      // Update mining scores for all transactions in this cluster
      for (let chunkIdx = 0; chunkIdx < linearization.chunks.length; chunkIdx++) {
        const chunk = linearization.chunks[chunkIdx];
        for (const txidHex of chunk.txids) {
          const entry = this.entries.get(txidHex);
          if (entry) {
            entry.clusterId = clusterId;
            entry.miningScore = chunk.feeRate;
          }
        }
      }
    }

    this.clusterCacheDirty = false;
  }

  /**
   * Linearize a cluster: order transactions by optimal fee-rate chunks.
   *
   * This implements the greedy algorithm from Bitcoin Core's cluster_linearize.h:
   * 1. Start with the linearization in topological order
   * 2. Compute chunks by absorbing higher-feerate transactions into earlier chunks
   *
   * A chunk is a contiguous prefix of the linearization that forms a valid
   * topological ordering. Transactions in the same chunk get the same mining score
   * (the chunk's aggregate fee rate).
   */
  linearizeCluster(txids: Set<string>): Linearization {
    if (txids.size === 0) {
      return { chunks: [], txToChunk: new Map() };
    }

    // Build a topological ordering of the cluster
    const topoOrder = this.topologicalSort(txids);

    // Compute chunks using the greedy algorithm from Bitcoin Core
    // Each tx starts as its own chunk, then absorb higher-feerate chunks
    const chunks: Chunk[] = [];

    for (const txidHex of topoOrder) {
      const entry = this.entries.get(txidHex)!;

      // FIX-72: seed each tx's chunk with its MODIFIED fee (base +
      // prioritisetransaction delta), not the raw base fee. This single seed
      // feeds BOTH the mining score (entry.miningScore = chunk.feeRate at
      // rebuildClusterCache) AND the eviction pick (evict() scans the lowest
      // tail chunk of each cluster linearization), so the delta now drives
      // mining + eviction in-place — matching Core's UpdateModifiedFee +
      // SetTransactionFee (txmempool.cpp:636-643). For an un-prioritised tx
      // (delta 0) these equal entry.fee / entry.feeRate, so the chunk geometry
      // is byte-identical to before. NOTE: chunk merges below still aggregate
      // raw lastChunk.totalFee — multi-ancestor delta folding is W106 G8, a
      // deliberately separate follow-up.
      const seedFee = this.getEntryModifiedFee(entry);
      const newChunk: Chunk = {
        txids: new Set([txidHex]),
        totalFee: seedFee,
        totalVsize: entry.vsize,
        feeRate: this.getEntryModifiedFeeRate(entry),
      };

      // While the new chunk has a higher feerate than the last chunk, absorb it
      // This implements: while (!ret.empty() && new_chunk.feerate >> ret.back().feerate)
      while (chunks.length > 0 && this.compareFeeRate(newChunk, chunks[chunks.length - 1]) > 0) {
        const lastChunk = chunks.pop()!;
        // Merge lastChunk into newChunk
        for (const txid of lastChunk.txids) {
          newChunk.txids.add(txid);
        }
        newChunk.totalFee += lastChunk.totalFee;
        newChunk.totalVsize += lastChunk.totalVsize;
        newChunk.feeRate = Number(newChunk.totalFee) / newChunk.totalVsize;
      }

      chunks.push(newChunk);
    }

    // Build txToChunk map
    const txToChunk = new Map<string, number>();
    for (let i = 0; i < chunks.length; i++) {
      for (const txidHex of chunks[i].txids) {
        txToChunk.set(txidHex, i);
      }
    }

    return { chunks, txToChunk };
  }

  /**
   * Compare two chunks by fee rate.
   * Returns > 0 if a has higher feerate, < 0 if b has higher, 0 if equal.
   * Uses cross-multiplication to avoid floating point issues.
   */
  private compareFeeRate(a: Chunk, b: Chunk): number {
    // a.feeRate > b.feeRate iff a.fee * b.size > b.fee * a.size
    const lhs = a.totalFee * BigInt(b.totalVsize);
    const rhs = b.totalFee * BigInt(a.totalVsize);
    if (lhs > rhs) return 1;
    if (lhs < rhs) return -1;
    return 0;
  }

  // ─── ImprovesFeerateDiagram helpers ────────────────────────────────────────

  /**
   * Produce the cumulative feerate diagram (list of {totalFee, totalVsize}
   * points in ascending vsize order) from a linearized cluster.
   *
   * Each element is the *cumulative* fee and vsize at the end of that chunk
   * (i.e. the diagram is the staircase of chunk endpoints).
   *
   * Reference: bitcoin-core/src/util/feefrac.h / cluster_linearize.h —
   * FeeFrac-based cumulative diagram used by CompareChunks.
   */
  private linearizeVirtualCluster(
    virtualEntries: Map<string, { fee: bigint; vsize: number; dependsOn: Set<string> }>,
  ): Array<{ cumFee: bigint; cumVsize: number }> {
    if (virtualEntries.size === 0) return [];

    // Topological sort using Kahn's algorithm over the virtual entries.
    const inDegree = new Map<string, number>();
    const children = new Map<string, Set<string>>();
    for (const txidHex of virtualEntries.keys()) {
      inDegree.set(txidHex, 0);
      children.set(txidHex, new Set());
    }
    for (const [txidHex, e] of virtualEntries) {
      for (const parentHex of e.dependsOn) {
        if (virtualEntries.has(parentHex)) {
          inDegree.set(txidHex, (inDegree.get(txidHex) ?? 0) + 1);
          children.get(parentHex)!.add(txidHex);
        }
      }
    }
    const queue: string[] = [];
    for (const [txidHex, deg] of inDegree) {
      if (deg === 0) queue.push(txidHex);
    }
    // Deterministic order: sort by feerate desc so high-feerate roots come first
    queue.sort((a, b) => {
      const ea = virtualEntries.get(a)!;
      const eb = virtualEntries.get(b)!;
      const lhs = ea.fee * BigInt(eb.vsize);
      const rhs = eb.fee * BigInt(ea.vsize);
      return lhs > rhs ? -1 : lhs < rhs ? 1 : 0;
    });
    const topoOrder: string[] = [];
    while (queue.length > 0) {
      const cur = queue.shift()!;
      topoOrder.push(cur);
      const sortedKids = Array.from(children.get(cur)!);
      for (const child of sortedKids) {
        const nd = (inDegree.get(child) ?? 0) - 1;
        inDegree.set(child, nd);
        if (nd === 0) queue.push(child);
      }
      queue.sort((a, b) => {
        const ea = virtualEntries.get(a)!;
        const eb = virtualEntries.get(b)!;
        const lhs = ea.fee * BigInt(eb.vsize);
        const rhs = eb.fee * BigInt(ea.vsize);
        return lhs > rhs ? -1 : lhs < rhs ? 1 : 0;
      });
    }

    // Greedy chunk-merging (same algorithm as linearizeCluster).
    interface VChunk { fee: bigint; vsize: number }
    const chunks: VChunk[] = [];
    const chunkMergeable = (a: VChunk, b: VChunk): boolean => {
      // a has higher feerate than b iff a.fee * b.vsize > b.fee * a.vsize
      return a.fee * BigInt(b.vsize) > b.fee * BigInt(a.vsize);
    };
    for (const txidHex of topoOrder) {
      const e = virtualEntries.get(txidHex)!;
      let cur: VChunk = { fee: e.fee, vsize: e.vsize };
      while (chunks.length > 0 && chunkMergeable(cur, chunks[chunks.length - 1])) {
        const last = chunks.pop()!;
        cur = { fee: cur.fee + last.fee, vsize: cur.vsize + last.vsize };
      }
      chunks.push(cur);
    }

    // Build cumulative diagram points (staircase endpoints).
    const diagram: Array<{ cumFee: bigint; cumVsize: number }> = [];
    let cumFee = 0n;
    let cumVsize = 0;
    for (const chunk of chunks) {
      cumFee += chunk.fee;
      cumVsize += chunk.vsize;
      diagram.push({ cumFee, cumVsize });
    }
    return diagram;
  }

  /**
   * Compare two feerate diagrams.
   *
   * Returns "better" if `after` strictly dominates `before` at every vsize
   * point, "worse" if `before` strictly dominates `after`, "equal" if they
   * are identical, or "incomparable" if neither dominates.
   *
   * Implements bitcoin-core/src/util/feefrac.cpp:10-73 (CompareChunks) in
   * terms of cumulative {cumFee, cumVsize} staircase diagrams.
   *
   * The interpolation rule: given consecutive staircase endpoints A and B on
   * one side, the value at a vsize v ∈ (A.cumVsize, B.cumVsize) is linearly
   * interpolated along the line from A to B.  This is equivalent to checking
   * that each chunk-endpoint of one diagram lies above/on/below the piecewise-
   * linear "other" diagram.
   *
   * For the RBF gate we only need to know whether `after` strictly beats
   * `before` (i.e. the result is "better").
   */
  private compareFeeDiagrams(
    before: Array<{ cumFee: bigint; cumVsize: number }>,
    after: Array<{ cumFee: bigint; cumVsize: number }>,
  ): "better" | "worse" | "equal" | "incomparable" {
    // Walk both diagrams in tandem.  At each vsize boundary we interpolate the
    // value of the *other* diagram and compare.  Mirrors feefrac.cpp CompareChunks.

    let afterBetterSomewhere = false;
    let beforeBetterSomewhere = false;

    // Evaluate fee of `diag` at cumulative vsize `v` (linear interp).
    const feeAt = (
      diag: Array<{ cumFee: bigint; cumVsize: number }>,
      v: number,
    ): bigint => {
      if (diag.length === 0) return 0n;
      // v beyond the last point → use the last fee (tail slope = 0)
      if (v >= diag[diag.length - 1].cumVsize) return diag[diag.length - 1].cumFee;
      // v before the first point → interpolate from origin (0,0)
      if (v <= 0) return 0n;

      let prevFee = 0n;
      let prevVsize = 0;
      for (const pt of diag) {
        if (pt.cumVsize >= v) {
          // Interpolate: fee = prevFee + (v - prevVsize) * (pt.cumFee - prevFee) / (pt.cumVsize - prevVsize)
          const dv = pt.cumVsize - prevVsize;
          if (dv === 0) return pt.cumFee;
          const df = pt.cumFee - prevFee;
          // Use BigInt arithmetic: multiply then divide to avoid fractions.
          return prevFee + (BigInt(v - prevVsize) * df) / BigInt(dv);
        }
        prevFee = pt.cumFee;
        prevVsize = pt.cumVsize;
      }
      return diag[diag.length - 1].cumFee;
    };

    // Collect all unique vsize boundaries from both diagrams.
    const vsizes = new Set<number>();
    for (const pt of before) vsizes.add(pt.cumVsize);
    for (const pt of after) vsizes.add(pt.cumVsize);

    for (const v of vsizes) {
      const bFee = feeAt(before, v);
      const aFee = feeAt(after, v);
      if (aFee > bFee) afterBetterSomewhere = true;
      if (bFee > aFee) beforeBetterSomewhere = true;
      if (afterBetterSomewhere && beforeBetterSomewhere) return "incomparable";
    }

    if (afterBetterSomewhere && !beforeBetterSomewhere) return "better";
    if (beforeBetterSomewhere && !afterBetterSomewhere) return "worse";
    return "equal";
  }

  /**
   * Gate #8: ImprovesFeerateDiagram.
   *
   * Returns null if the replacement improves (or ties) the feerate diagram,
   * or an error string if it does not.
   *
   * Algorithm:
   *   1. Find all cluster txids that are in any cluster touched by a conflict.
   *   2. Build a "before" virtual-entries map from those txids.
   *   3. Build an "after" virtual-entries map: same minus conflicts, plus the
   *      replacement transaction (with the correct dependsOn set).
   *   4. Linearize both and compare diagrams.
   *
   * Reference: bitcoin-core/src/policy/rbf.cpp:127-138.
   */
  private improvesFeerateDiagram(
    replacementTxidHex: string,
    replacementFee: bigint,
    replacementVsize: number,
    replacementParents: Set<string>,   // in-mempool parent txids (hex)
    conflictsToEvict: MempoolEntry[],
  ): string | null {
    // Collect all cluster roots touched by any conflict.
    const touchedClusterRoots = new Set<string>();
    for (const conflict of conflictsToEvict) {
      const conflictHex = conflict.txid.toString("hex");
      if (this.entries.has(conflictHex)) {
        touchedClusterRoots.add(this.clusters.find(conflictHex));
      }
    }

    // Gather all txids in those clusters.
    const clusterTxids = new Set<string>();
    for (const [txidHex] of this.entries) {
      const root = this.clusters.find(txidHex);
      if (touchedClusterRoots.has(root)) {
        clusterTxids.add(txidHex);
      }
    }

    if (clusterTxids.size === 0) return null; // nothing to compare

    const conflictSet = new Set<string>(conflictsToEvict.map((e) => e.txid.toString("hex")));

    // Build "before" virtual-entries from clusterTxids.
    type VEntry = { fee: bigint; vsize: number; dependsOn: Set<string> };
    const beforeMap = new Map<string, VEntry>();
    for (const txidHex of clusterTxids) {
      const entry = this.entries.get(txidHex)!;
      // dependsOn restricted to the cluster
      const deps = new Set<string>();
      for (const dep of entry.dependsOn) {
        if (clusterTxids.has(dep)) deps.add(dep);
      }
      beforeMap.set(txidHex, { fee: entry.fee, vsize: entry.vsize, dependsOn: deps });
    }

    // Build "after" virtual-entries: remove conflicts, add replacement.
    const afterMap = new Map<string, VEntry>();
    for (const [txidHex, e] of beforeMap) {
      if (!conflictSet.has(txidHex)) {
        afterMap.set(txidHex, e);
      }
    }
    // Replacement's dependsOn = parents that survive into afterMap.
    const replacementDeps = new Set<string>();
    for (const parentHex of replacementParents) {
      if (afterMap.has(parentHex)) replacementDeps.add(parentHex);
    }
    afterMap.set(replacementTxidHex, {
      fee: replacementFee,
      vsize: replacementVsize,
      dependsOn: replacementDeps,
    });

    const beforeDiagram = this.linearizeVirtualCluster(beforeMap);
    const afterDiagram = this.linearizeVirtualCluster(afterMap);

    const cmp = this.compareFeeDiagrams(beforeDiagram, afterDiagram);
    if (cmp === "better" || cmp === "equal") {
      // "equal" is technically a non-improvement, but Core accepts ties
      // (std::is_gt — strictly greater is required).  We mirror that.
      if (cmp === "equal") {
        return "insufficient feerate: does not improve feerate diagram";
      }
      return null; // "better" → OK
    }
    return "insufficient feerate: does not improve feerate diagram";
  }

  /**
   * Topologically sort a set of transactions (parents before children).
   * Uses Kahn's algorithm.
   */
  private topologicalSort(txids: Set<string>): string[] {
    // Build in-degree counts and adjacency for the subset
    const inDegree = new Map<string, number>();
    const children = new Map<string, Set<string>>();

    for (const txidHex of txids) {
      inDegree.set(txidHex, 0);
      children.set(txidHex, new Set());
    }

    // Count in-degree (number of parents within the cluster)
    for (const txidHex of txids) {
      const entry = this.entries.get(txidHex)!;
      for (const parentTxidHex of entry.dependsOn) {
        if (txids.has(parentTxidHex)) {
          inDegree.set(txidHex, (inDegree.get(txidHex) || 0) + 1);
          children.get(parentTxidHex)!.add(txidHex);
        }
      }
    }

    // Start with nodes that have no in-cluster parents
    // Sort by ancestor count for deterministic ordering
    const queue: string[] = [];
    for (const [txidHex, degree] of inDegree) {
      if (degree === 0) {
        queue.push(txidHex);
      }
    }
    // Sort queue by ancestor count for consistent ordering
    queue.sort((a, b) => {
      const entryA = this.entries.get(a)!;
      const entryB = this.entries.get(b)!;
      return entryA.ancestorCount - entryB.ancestorCount;
    });

    const result: string[] = [];
    while (queue.length > 0) {
      const txidHex = queue.shift()!;
      result.push(txidHex);

      // Decrease in-degree for all children
      for (const childTxidHex of children.get(txidHex)!) {
        const newDegree = inDegree.get(childTxidHex)! - 1;
        inDegree.set(childTxidHex, newDegree);
        if (newDegree === 0) {
          queue.push(childTxidHex);
          // Re-sort to maintain consistent ordering
          queue.sort((a, b) => {
            const entryA = this.entries.get(a)!;
            const entryB = this.entries.get(b)!;
            return entryA.ancestorCount - entryB.ancestorCount;
          });
        }
      }
    }

    return result;
  }

  /**
   * Get the cluster containing a transaction.
   */
  getCluster(txidHex: string): Cluster | null {
    this.rebuildClusterCache();
    const clusterId = this.clusters.find(txidHex);
    return this.clusterCache.get(clusterId) || null;
  }

  /**
   * Get all clusters in the mempool.
   */
  getAllClusters(): Cluster[] {
    this.rebuildClusterCache();
    return Array.from(this.clusterCache.values());
  }

  /**
   * Get the mining score (chunk fee rate) for a transaction.
   * Returns the fee rate of the chunk this transaction belongs to in its cluster's linearization.
   */
  getMiningScore(txidHex: string): number {
    this.rebuildClusterCache();
    const entry = this.entries.get(txidHex);
    if (!entry) return 0;
    return entry.miningScore;
  }

  /**
   * Get transactions sorted by mining score (descending) for block template.
   * This respects chunk boundaries and topological ordering within clusters.
   */
  getTransactionsByMiningScore(): MempoolEntry[] {
    this.rebuildClusterCache();

    // Collect all chunks from all clusters
    const allChunks: { chunk: Chunk; clusterId: string }[] = [];
    for (const cluster of this.clusterCache.values()) {
      for (const chunk of cluster.linearization.chunks) {
        allChunks.push({ chunk, clusterId: cluster.id });
      }
    }

    // Sort chunks by fee rate descending
    allChunks.sort((a, b) => b.chunk.feeRate - a.chunk.feeRate);

    // Flatten into transaction entries, respecting topological order within chunks
    const result: MempoolEntry[] = [];
    for (const { chunk, clusterId } of allChunks) {
      // Get transactions in this chunk in topological order
      const chunkTxids = this.topologicalSort(chunk.txids);
      for (const txidHex of chunkTxids) {
        const entry = this.entries.get(txidHex);
        if (entry) {
          result.push(entry);
        }
      }
    }

    return result;
  }

  /**
   * Submit a package of transactions for validation and acceptance.
   *
   * Package validation allows related transactions to be validated together,
   * enabling CPFP (Child-Pays-For-Parent) fee bumping. A parent transaction
   * with a low fee rate can be accepted if its child pays enough fees to
   * bring the combined package fee rate above the mempool minimum.
   *
   * @param transactions - Array of transactions in topological order (parents before children)
   * @returns Package validation result with per-transaction results
   */
  async submitPackage(transactions: Transaction[]): Promise<PackageResult> {
    // Initialize result
    const txResults = new Map<string, PackageTxResult>();
    const replacedTxids: string[] = [];

    // Empty package
    if (transactions.length === 0) {
      return {
        result: PackageValidationResult.PCKG_POLICY,
        message: "package-empty",
        txResults,
        replacedTxids,
      };
    }

    // Single transaction - just use regular acceptance
    if (transactions.length === 1) {
      const tx = transactions[0];
      const txid = getTxId(tx).toString("hex");
      const wtxid = getWTxId(tx).toString("hex");

      // Single transaction with ephemeral dust cannot be accepted alone
      // It requires a child in the same package to spend the dust
      if (hasEphemeralDust(tx)) {
        txResults.set(wtxid, {
          txid,
          wtxid,
          accepted: false,
          error: "tx has ephemeral dust but no child spending it",
        });

        return {
          result: PackageValidationResult.PCKG_POLICY,
          message: "ephemeral-dust-no-child",
          txResults,
          replacedTxids,
        };
      }

      const result = await this.addTransaction(tx);

      txResults.set(wtxid, {
        txid,
        wtxid,
        accepted: result.accepted,
        error: result.error,
        vsize: result.accepted ? getTxVSize(tx) : undefined,
      });

      return {
        result: result.accepted
          ? PackageValidationResult.PCKG_RESULT_UNSET
          : PackageValidationResult.PCKG_TX,
        message: result.accepted ? "success" : result.error || "transaction-rejected",
        txResults,
        replacedTxids,
      };
    }

    // Validate package structure
    const packageValidation = validatePackage(transactions);
    if (!packageValidation.valid) {
      // Create error results for all transactions
      for (const tx of transactions) {
        const txid = getTxId(tx).toString("hex");
        const wtxid = getWTxId(tx).toString("hex");
        txResults.set(wtxid, {
          txid,
          wtxid,
          accepted: false,
          error: "package-not-validated",
        });
      }

      return {
        result: PackageValidationResult.PCKG_POLICY,
        message: packageValidation.error!,
        txResults,
        replacedTxids,
      };
    }

    // BUG-4 (W116): enforce child-with-parents-tree topology.
    // Core's submitpackage RPC (mempool.cpp:1395) rejects multi-tx packages that are not
    // IsChildWithParentsTree — i.e. chains (gp→p→c) or packages where parents depend on each other.
    // validatePackage only checks topo-sort and consistency; this is the additional topology guard.
    if (!isChildWithParentsTree(transactions)) {
      for (const tx of transactions) {
        const txid = getTxId(tx).toString("hex");
        const wtxid = getWTxId(tx).toString("hex");
        txResults.set(wtxid, {
          txid,
          wtxid,
          accepted: false,
          error: "package-not-validated",
        });
      }

      return {
        result: PackageValidationResult.PCKG_POLICY,
        message: "package topology disallowed. not child-with-parents or parents depend on each other.",
        txResults,
        replacedTxids,
      };
    }

    // Build a map of pending transactions for fee calculation
    // This allows us to look up outputs from package members that aren't in mempool yet
    const pendingTxs = new Map<string, Transaction>();
    for (const tx of transactions) {
      pendingTxs.set(getTxId(tx).toString("hex"), tx);
    }

    // First pass: calculate fees for all transactions using the pending map
    const txFees = new Map<string, bigint>();
    const txVsizes = new Map<string, number>();

    for (const tx of transactions) {
      const txid = getTxId(tx).toString("hex");
      const wtxid = getWTxId(tx).toString("hex");

      // Check if already in mempool
      if (this.entries.has(txid)) {
        const entry = this.entries.get(txid)!;
        txFees.set(txid, entry.fee);
        txVsizes.set(txid, entry.vsize);
        txResults.set(wtxid, {
          txid,
          wtxid,
          accepted: true,
          vsize: entry.vsize,
          fee: entry.fee,
        });
        continue;
      }

      // Calculate fee for this transaction
      const feeResult = await this.calculateTxFee(tx, pendingTxs);
      if (!feeResult.valid) {
        // Transaction is invalid
        txResults.set(wtxid, {
          txid,
          wtxid,
          accepted: false,
          error: feeResult.error,
        });

        return {
          result: PackageValidationResult.PCKG_TX,
          message: feeResult.error || "transaction-invalid",
          txResults,
          replacedTxids,
        };
      }

      txFees.set(txid, feeResult.fee!);
      txVsizes.set(txid, getTxVSize(tx));

      // Pre-check ephemeral tx: dust outputs require 0-fee
      const ephemeralPreCheck = preCheckEphemeralTx(tx, feeResult.fee!);
      if (!ephemeralPreCheck.valid) {
        txResults.set(wtxid, {
          txid,
          wtxid,
          accepted: false,
          error: ephemeralPreCheck.error,
        });

        return {
          result: PackageValidationResult.PCKG_POLICY,
          message: ephemeralPreCheck.error || "ephemeral-policy-violation",
          txResults,
          replacedTxids,
        };
      }
    }

    // Check ephemeral spends: all dust from parents must be spent by children
    const ephemeralCheck = checkEphemeralSpends(transactions, this.entries);
    if (!ephemeralCheck.valid) {
      // Find the failing transaction
      for (const tx of transactions) {
        const txid = getTxId(tx).toString("hex");
        const wtxid = getWTxId(tx).toString("hex");

        if (this.entries.has(txid)) {
          continue; // Already in mempool, not the issue
        }

        if (wtxid === ephemeralCheck.failedWtxid) {
          txResults.set(wtxid, {
            txid,
            wtxid,
            accepted: false,
            error: ephemeralCheck.error,
          });
        } else {
          txResults.set(wtxid, {
            txid,
            wtxid,
            accepted: false,
            error: "missing-ephemeral-spends",
          });
        }
      }

      return {
        result: PackageValidationResult.PCKG_POLICY,
        message: ephemeralCheck.error || "missing-ephemeral-spends",
        txResults,
        replacedTxids,
      };
    }

    // Calculate total package fee and vsize
    let totalPackageFee = 0n;
    let totalPackageVsize = 0;
    const packageWtxids: string[] = [];

    for (const tx of transactions) {
      const txid = getTxId(tx).toString("hex");
      const wtxid = getWTxId(tx).toString("hex");

      // Skip transactions already in mempool (they're already accounted for)
      if (this.entries.has(txid)) {
        continue;
      }

      totalPackageFee += txFees.get(txid)!;
      totalPackageVsize += txVsizes.get(txid)!;
      packageWtxids.push(wtxid);
    }

    // Calculate package fee rate
    const packageFeeRate = totalPackageVsize > 0
      ? Number(totalPackageFee) / totalPackageVsize
      : 0;

    // Check if package fee rate meets minimum
    if (totalPackageVsize > 0 && packageFeeRate < this.minFeeRate) {
      // Package fee rate too low
      for (const tx of transactions) {
        const txid = getTxId(tx).toString("hex");
        const wtxid = getWTxId(tx).toString("hex");

        if (this.entries.has(txid)) {
          continue; // Already in mempool
        }

        txResults.set(wtxid, {
          txid,
          wtxid,
          accepted: false,
          error: `Package fee rate ${packageFeeRate.toFixed(2)} sat/vB below minimum ${this.minFeeRate}`,
        });
      }

      return {
        result: PackageValidationResult.PCKG_POLICY,
        message: "package-fee-too-low",
        txResults,
        replacedTxids,
      };
    }

    // Now add all transactions to mempool in order
    // Bypass individual fee checks since we've validated package fee rate
    const acceptedTxs: Transaction[] = [];

    for (const tx of transactions) {
      const txid = getTxId(tx).toString("hex");
      const wtxid = getWTxId(tx).toString("hex");

      // Skip if already in mempool
      if (this.entries.has(txid)) {
        continue;
      }

      // Add with bypassed fee check
      const result = await this.addTransactionBypassFeeCheck(tx);

      if (result.accepted) {
        acceptedTxs.push(tx);
        const entry = this.entries.get(txid)!;
        txResults.set(wtxid, {
          txid,
          wtxid,
          accepted: true,
          vsize: entry.vsize,
          fee: entry.fee,
          effectiveFeeRate: packageFeeRate,
          effectiveIncludes: packageWtxids,
        });
      } else {
        txResults.set(wtxid, {
          txid,
          wtxid,
          accepted: false,
          error: result.error,
        });

        // Remove already accepted transactions from this package
        for (const acceptedTx of acceptedTxs) {
          this.removeTransaction(getTxId(acceptedTx), true);
        }

        return {
          result: PackageValidationResult.PCKG_TX,
          message: result.error || "transaction-rejected",
          txResults,
          replacedTxids,
        };
      }
    }

    return {
      result: PackageValidationResult.PCKG_RESULT_UNSET,
      message: "success",
      txResults,
      replacedTxids,
    };
  }

  /**
   * Calculate the fee for a transaction without adding it to mempool.
   * Used for CPFP package fee rate calculation.
   *
   * @param tx - Transaction to calculate fee for
   * @param pendingTxs - Optional map of txid -> Transaction for transactions
   *                     in the package that haven't been added to mempool yet.
   */
  private async calculateTxFee(
    tx: Transaction,
    pendingTxs?: Map<string, Transaction>
  ): Promise<{ valid: boolean; fee?: bigint; error?: string }> {
    // Basic validation
    const basicResult = validateTxBasic(tx);
    if (!basicResult.valid) {
      return { valid: false, error: basicResult.error };
    }

    if (isCoinbase(tx)) {
      return { valid: false, error: "Coinbase transaction not allowed" };
    }

    // Calculate input values
    let totalInput = 0n;

    for (const input of tx.inputs) {
      const parentTxidHex = input.prevOut.txid.toString("hex");

      // Check pending transactions first (package members not yet in mempool)
      if (pendingTxs && pendingTxs.has(parentTxidHex)) {
        const pendingTx = pendingTxs.get(parentTxidHex)!;
        if (input.prevOut.vout >= pendingTx.outputs.length) {
          return { valid: false, error: `Invalid pending input` };
        }
        totalInput += pendingTx.outputs[input.prevOut.vout].value;
        continue;
      }

      // Check mempool
      const mempoolParent = this.entries.get(parentTxidHex);
      if (mempoolParent) {
        if (input.prevOut.vout >= mempoolParent.tx.outputs.length) {
          return { valid: false, error: `Invalid mempool input` };
        }
        totalInput += mempoolParent.tx.outputs[input.prevOut.vout].value;
        continue;
      }

      // Check UTXO set
      const utxo = await this.utxo.getUTXOAsync(input.prevOut);
      if (!utxo) {
        return { valid: false, error: `Missing input` };
      }
      totalInput += utxo.amount;
    }

    // Calculate output values
    let totalOutput = 0n;
    for (const output of tx.outputs) {
      totalOutput += output.value;
    }

    if (totalInput < totalOutput) {
      return { valid: false, error: `Insufficient input value` };
    }

    return { valid: true, fee: totalInput - totalOutput };
  }

  /**
   * Add a transaction bypassing the fee rate check.
   * Used for CPFP where the package fee rate has already been validated.
   */
  private async addTransactionBypassFeeCheck(
    tx: Transaction
  ): Promise<{ accepted: boolean; error?: string }> {
    // Save current minFeeRate
    const savedMinFeeRate = this.minFeeRate;

    // Temporarily set minFeeRate to 0 to bypass the check
    this.minFeeRate = 0;

    try {
      const result = await this.addTransaction(tx);
      return result;
    } finally {
      // Restore minFeeRate
      this.minFeeRate = savedMinFeeRate;
    }
  }
}

// ============================================================================
// Package Validation Functions
// ============================================================================

/**
 * Check if transactions are topologically sorted (parents before children).
 *
 * @param transactions - Array of transactions to check
 * @returns true if topologically sorted
 */
export function isTopoSortedPackage(transactions: Transaction[]): boolean {
  // Build a set of txids we've seen so far
  const seenTxids = new Set<string>();

  for (const tx of transactions) {
    const txid = getTxId(tx).toString("hex");

    // Check if any input spends a transaction that comes later
    for (const input of tx.inputs) {
      const parentTxid = input.prevOut.txid.toString("hex");
      // If the parent txid is in our set of txids for this package but not yet seen,
      // it means a parent appears after its child
      if (!seenTxids.has(parentTxid)) {
        // Check if this parent is in the package at all
        const parentInPackage = transactions.some(
          (t) => getTxId(t).toString("hex") === parentTxid
        );
        if (parentInPackage) {
          // Parent is in package but hasn't been processed yet = not topo sorted
          return false;
        }
      }
    }

    seenTxids.add(txid);
  }

  return true;
}

/**
 * Check if package has no conflicting transactions (no double-spends within package).
 *
 * @param transactions - Array of transactions to check
 * @returns true if consistent (no conflicts)
 */
export function isConsistentPackage(transactions: Transaction[]): boolean {
  const inputsSeen = new Set<string>();

  for (const tx of transactions) {
    // Empty inputs are not allowed for non-coinbase transactions
    if (tx.inputs.length === 0) {
      return false;
    }

    // Check for duplicate inputs within package
    for (const input of tx.inputs) {
      const outpointKey = `${input.prevOut.txid.toString("hex")}:${input.prevOut.vout}`;
      if (inputsSeen.has(outpointKey)) {
        // This input is spent by another transaction in the package
        return false;
      }
    }

    // Add all inputs from this transaction
    for (const input of tx.inputs) {
      const outpointKey = `${input.prevOut.txid.toString("hex")}:${input.prevOut.vout}`;
      inputsSeen.add(outpointKey);
    }
  }

  return true;
}

/**
 * Check if package is a child-with-parents structure.
 * The last transaction must be the child, and all other transactions must be parents of that child.
 *
 * @param transactions - Array of transactions to check
 * @returns true if child-with-parents structure
 */
export function isChildWithParents(transactions: Transaction[]): boolean {
  if (transactions.length < 2) {
    return false;
  }

  const child = transactions[transactions.length - 1];

  // Get all input txids of the child
  const childInputTxids = new Set<string>();
  for (const input of child.inputs) {
    childInputTxids.add(input.prevOut.txid.toString("hex"));
  }

  // Every other transaction must be a parent of the child
  for (let i = 0; i < transactions.length - 1; i++) {
    const txid = getTxId(transactions[i]).toString("hex");
    if (!childInputTxids.has(txid)) {
      return false;
    }
  }

  return true;
}

/**
 * Check if package is a child-with-parents tree structure.
 * Child-with-parents, plus parents don't depend on each other.
 *
 * @param transactions - Array of transactions to check
 * @returns true if child-with-parents tree structure
 */
export function isChildWithParentsTree(transactions: Transaction[]): boolean {
  if (!isChildWithParents(transactions)) {
    return false;
  }

  // Get set of parent txids
  const parentTxids = new Set<string>();
  for (let i = 0; i < transactions.length - 1; i++) {
    parentTxids.add(getTxId(transactions[i]).toString("hex"));
  }

  // Each parent must not have an input that is one of the other parents
  for (let i = 0; i < transactions.length - 1; i++) {
    const tx = transactions[i];
    for (const input of tx.inputs) {
      if (parentTxids.has(input.prevOut.txid.toString("hex"))) {
        return false;
      }
    }
  }

  return true;
}

/**
 * Validate a package of transactions.
 *
 * Checks:
 * 1. Package size limits (max 25 transactions, max 404,000 WU)
 * 2. No duplicate transactions
 * 3. Topological ordering (parents before children)
 * 4. No conflicting transactions (double-spends within package)
 *
 * @param transactions - Array of transactions to validate
 * @returns Validation result
 */
export function validatePackage(
  transactions: Transaction[]
): { valid: boolean; error?: string } {
  // Check transaction count
  if (transactions.length > MAX_PACKAGE_COUNT) {
    return {
      valid: false,
      error: "package-too-many-transactions",
    };
  }

  // Calculate total weight
  let totalWeight = 0;
  for (const tx of transactions) {
    totalWeight += getTxWeight(tx);
  }

  // Single transaction packages skip the weight check (reported on individual tx)
  if (transactions.length > 1 && totalWeight > MAX_PACKAGE_WEIGHT) {
    return {
      valid: false,
      error: "package-too-large",
    };
  }

  // Check for duplicate transactions
  const txids = new Set<string>();
  for (const tx of transactions) {
    const txid = getTxId(tx).toString("hex");
    if (txids.has(txid)) {
      return {
        valid: false,
        error: "package-contains-duplicates",
      };
    }
    txids.add(txid);
  }

  // Check topological ordering
  if (!isTopoSortedPackage(transactions)) {
    return {
      valid: false,
      error: "package-not-sorted",
    };
  }

  // Check for conflicts
  if (!isConsistentPackage(transactions)) {
    return {
      valid: false,
      error: "conflict-in-package",
    };
  }

  return { valid: true };
}

/**
 * Compute the package hash (for P2P relay).
 *
 * The package hash is SHA256 of the sorted wtxids concatenated together.
 *
 * @param transactions - Array of transactions
 * @returns 32-byte package hash
 */
export function getPackageHash(transactions: Transaction[]): Buffer {
  // Get all wtxids
  const wtxids = transactions.map((tx) => getWTxId(tx));

  // Sort wtxids lexicographically (comparing as byte arrays)
  wtxids.sort((a, b) => Buffer.compare(a, b));

  // Concatenate and hash
  const concat = Buffer.concat(wtxids);
  return sha256Hash(concat);
}
