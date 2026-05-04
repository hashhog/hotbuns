/**
 * coreConnectBlockChecks — shared consensus validation + UTXO mutation kernel.
 *
 * Consolidates the duplicate ConnectBlock logic that previously lived in
 * both chain/state.ts (throw-on-error, rollback/reorg/mine path) and
 * sync/blocks.ts (return-false, IBD/submitblock path).
 *
 * Background
 * ----------
 * Wave-1 (c48c6d0) added BIP-30 to chain/state.ts::connectBlock.  Wave-30b
 * (0ce6d9e) added it again to sync/blocks.ts::connectBlock because wave-1 had
 * targeted the wrong symbol.  Wave-33b confirmed both are live (not dead code)
 * but flagged the structural duplication.  This file closes that finding by
 * extracting the shared consensus-check + UTXO-mutation sequence into a single
 * authoritative function that both callers delegate to.
 *
 * Design
 * ------
 * This function contains the complete per-block consensus checks and UTXO
 * mutations that belong to EVERY ConnectBlock call regardless of caller context:
 *
 *   1. BIP-30 duplicate-UTXO check (UTXO-integrity; runs even under assumevalid)
 *   2. IsFinalTx for every transaction (BIP-113 lock-time; runs even under assumevalid)
 *   3. Bulk UTXO preload (parallel LevelDB reads)
 *   4a. Assumevalid fast path: spend + addTransaction, skip maturity/BIP68/scripts
 *   4b. Full validation path: maturity + BIP-68/CSV + script verify + spend + addTransaction
 *   5. Sigops cost ceiling (MAX_BLOCK_SIGOPS_COST)  [full path only]
 *   6. Coinbase value ≤ subsidy + fees (consensus-critical; runs even under assumevalid)
 *
 * UTXO mutations (spendOutput / addTransaction) are performed inside this
 * function so that block-internal transaction chaining works correctly:
 * a transaction at index N can create a UTXO that transaction N+1 spends.
 *
 * DB writes (undo data, block store, chain state, block index) are LEFT TO
 * THE CALLER — they differ between the two call sites.
 *
 * Reference: Bitcoin Core validation.cpp::ConnectBlock
 */

import type { ConsensusParams } from "./params.js";
import { getBlockSubsidy } from "./params.js";
import type { Block } from "../validation/block.js";
import {
  getTransactionSigOpCost,
  MAX_BLOCK_SIGOPS_COST,
} from "../validation/block.js";
import type { Transaction, UTXOConfirmation } from "../validation/tx.js";
import {
  getTxId,
  isCoinbase,
  checkSequenceLocks,
  verifyAllInputsParallel,
  verifyAllInputsSequential,
  ScriptFlags,
} from "../validation/tx.js";
import type { UTXOEntry } from "../storage/database.js";
import { UTXOManager, type SpentUTXO } from "../chain/utxo.js";
import { isFinalTx } from "../mining/template.js";

// ─── Public types ─────────────────────────────────────────────────────────────

/**
 * Successful result from coreConnectBlockChecks.
 *
 * By the time this is returned, the UTXOManager has already had all inputs
 * spent (spendOutput) and all outputs added (addTransaction).  The caller is
 * responsible only for:
 *   - Serialising spentOutputs into undo data and persisting it
 *   - Flushing the UTXOManager to disk (timing is caller-controlled)
 *   - Updating chain state / DB (block index, height mapping, chainwork, etc.)
 */
export interface ConnectBlockOk {
  ok: true;
  /** Spent UTXOs for undo-data serialisation. */
  spentOutputs: SpentUTXO[];
  /** Sum of all non-coinbase input values (sats). */
  totalInputValue: bigint;
  /** Sum of all output values across all txns (sats). */
  totalOutputValue: bigint;
  /** Sum of coinbase tx outputs (sats). */
  coinbaseOutputValue: bigint;
}

export interface ConnectBlockErr {
  ok: false;
  /** Human-readable error string (maps to BIP-22 token at the call site). */
  error: string;
}

export type ConnectBlockResult = ConnectBlockOk | ConnectBlockErr;

/**
 * Options that vary between the two call sites.
 */
export interface ConnectBlockOpts {
  /**
   * Skip expensive script/witness/maturity/BIP-68 checks (assume-valid fast
   * path).  Coinbase-value check still runs (consensus-critical, never skipped
   * in Core).  IsFinalTx still runs (ContextualCheckBlock, not gated by
   * assumevalid).  BIP-30 still runs (UTXO-integrity, not gated by assumevalid).
   */
  assumeValid?: boolean;

  /**
   * Whether to skip script execution on the full-validation path.
   * Separate from assumeValid — used by the P2-OPT assumevalid gate in
   * sync/blocks.ts that performs a 6-condition shouldSkipScripts() check.
   */
  skipScripts?: boolean;

  /**
   * Previous block's Median Time Past.  Required for:
   *   - IsFinalTx lock-time cutoff when CSV/BIP-113 is active (height ≥ csvHeight)
   *   - BIP-68 sequence-lock evaluation (height ≥ csvHeight)
   * Pass 0 on heights where CSV/BIP-113 is not yet active.
   */
  prevMTP?: number;

  /**
   * Whether to enforce BIP-68 checkSequenceLocks.
   * True when !assumeValid && height >= params.csvHeight.
   */
  enforceBIP68?: boolean;

  /**
   * Number of parallel script-verification workers.
   * 1  = sequential (verifyAllInputsSequential — benchmark baseline).
   * >1 = parallel   (verifyAllInputsParallel  — production default).
   * Defaults to 4 if not supplied.
   */
  scriptThreads?: number;

  /**
   * Whether to verify P2SH redeem scripts (BIP-16).
   * True when height >= params.bip16Height.
   */
  verifyP2SH?: boolean;

  /**
   * Whether to verify witness scripts (BIP-141/143).
   * True when height >= params.segwitHeight.
   */
  verifyWitness?: boolean;

  /**
   * Optional per-coin MTP provider for BIP-68 time-based sequence locks.
   *
   * Called with the block height at which a UTXO was created; should return
   * the Median Time Past of the block at (utxoHeight - 1).
   *
   * If not supplied, the helper defaults to 0 for all coins.  This is
   * conservative: block-height-based sequence locks are still checked
   * correctly; time-based ones may be slightly loose.  Only supply this
   * when HeaderSync is available (sync/blocks.ts path).
   */
  getUTXOMTP?: (utxoHeight: number) => number;
}

// ─── Main helper ──────────────────────────────────────────────────────────────

/**
 * Core ConnectBlock consensus checks + UTXO mutations.
 *
 * Runs BIP-30, IsFinalTx, per-tx maturity/BIP-68/scripts/sigops, coinbase-value
 * check, and performs spendOutput + addTransaction for every transaction.
 *
 * On return (ok=true) the UTXOManager reflects the post-block state; the caller
 * must persist it (flush) and update the chain-state DB.
 *
 * On return (ok=false) the UTXOManager may be partially mutated — the caller
 * should discard any in-progress UTXO cache changes (e.g. by not flushing).
 *
 * @param block       - Fully-deserialized block to validate.
 * @param height      - Block height on the chain.
 * @param utxoManager - UTXO cache/DB reader-writer.
 * @param params      - Network consensus parameters.
 * @param opts        - Per-call-site options (see ConnectBlockOpts).
 */
export async function coreConnectBlockChecks(
  block: Block,
  height: number,
  utxoManager: UTXOManager,
  params: ConsensusParams,
  opts: ConnectBlockOpts = {}
): Promise<ConnectBlockResult> {
  const {
    assumeValid = false,
    skipScripts = false,
    prevMTP = 0,
    enforceBIP68 = false,
    scriptThreads = 4,
    verifyP2SH = height >= params.bip16Height,
    verifyWitness = height >= params.segwitHeight,
    getUTXOMTP,
  } = opts;

  // ── 1. BIP-30: reject blocks that would overwrite an existing unspent output.
  //
  // Two mainnet blocks (h=91842, h=91880) are permanently exempt; they predate
  // BIP-30 and intentionally duplicate earlier coinbase txids.
  // After BIP-34 activation (h≥bip34Height) coinbase-height uniqueness makes
  // duplicates practically impossible, so skip up to h=1,983,702. After that
  // BIP-34 modular arithmetic begins to repeat pre-BIP34 heights, so re-enable.
  //
  // Consensus-critical: runs even under assumevalid.
  // Reference: Bitcoin Core validation.cpp ConnectBlock / IsBIP30Repeat().
  {
    const BIP34_IMPLIES_BIP30_LIMIT = 1_983_702;
    const isExemptHeight = params.bip30ExceptionHeights.includes(height);
    const bip34Active = height >= params.bip34Height;
    const belowReenableLimit = height < BIP34_IMPLIES_BIP30_LIMIT;
    const enforceBip30 = !isExemptHeight && !(bip34Active && belowReenableLimit);

    if (enforceBip30) {
      for (const tx of block.transactions) {
        const txid = getTxId(tx);
        for (let vout = 0; vout < tx.outputs.length; vout++) {
          const exists = await utxoManager.hasUTXOAsync({ txid, vout });
          if (exists) {
            return {
              ok: false,
              error: `bad-txns-BIP30: tried to overwrite transaction ${txid.toString("hex")}:${vout} at height ${height}`,
            };
          }
        }
      }
    }
  }

  // ── 2. IsFinalTx: ContextualCheckBlock lock-time enforcement.
  //
  // Bitcoin Core validation.cpp:4146. Runs for every transaction.
  // Consensus rule that runs even under assumevalid — assumevalid only skips
  // script verification, not lock-time rules.
  // lock_time_cutoff = MTP when CSV/BIP-113 is active, block timestamp otherwise.
  {
    const csvActive = height >= params.csvHeight;
    const lockTimeCutoff = csvActive ? prevMTP : block.header.timestamp;
    for (const tx of block.transactions) {
      if (!isFinalTx(tx, height, lockTimeCutoff)) {
        return {
          ok: false,
          error: `Block at height ${height} contains non-final transaction (bad-txns-nonfinal)`,
        };
      }
    }
  }

  // ── 3. Pre-load all UTXOs needed by this block in one parallel batch.
  //
  // Turns N sequential LevelDB reads into N parallel reads, avoiding the
  // per-input serial-read pattern that dominated IBD wall time.
  {
    const allOutpoints: import("../validation/tx.js").OutPoint[] = [];
    for (const tx of block.transactions) {
      if (!isCoinbase(tx)) {
        for (const input of tx.inputs) {
          allOutpoints.push(input.prevOut);
        }
      }
    }
    if (allOutpoints.length > 0) {
      await utxoManager.preloadUTXOs(allOutpoints);
    }
  }

  // ── 4a. Assume-valid fast path ────────────────────────────────────────────
  // Skip: maturity checks, BIP-68, sigops counting, script verification.
  // Always run: coinbase-value check (consensus-critical, never skipped in Core).
  // Reference: Bitcoin Core validation.cpp::ConnectBlock —
  //   fScriptChecks only gates signature/script checking, not arithmetic checks.
  if (assumeValid) {
    let avTotalInputValue = 0n;
    let avTotalOutputValue = 0n;

    for (const tx of block.transactions) {
      const txid = getTxId(tx);
      const isCoinbaseTx = isCoinbase(tx);

      if (!isCoinbaseTx) {
        for (const input of tx.inputs) {
          // Ensure input is loaded (may not be in the bulk-preload cache if
          // it was created by an earlier tx in this same block).
          if (!utxoManager.hasUTXO(input.prevOut)) {
            const loaded = await utxoManager.preloadUTXO(input.prevOut);
            if (!loaded) {
              return {
                ok: false,
                error: `Missing UTXO at height ${height}: ${input.prevOut.txid.toString("hex").slice(0, 16)}:${input.prevOut.vout}`,
              };
            }
          }
          const spentEntry = utxoManager.spendOutput(input.prevOut);
          avTotalInputValue += spentEntry.amount;
        }
      }

      for (const output of tx.outputs) {
        avTotalOutputValue += output.value;
      }

      // addTransaction MUST be called here (not after the loop) so that a tx
      // at index N can create a UTXO immediately spendable by tx at index N+1
      // within the same block (block-internal chaining).
      utxoManager.addTransaction(txid, tx, height, isCoinbaseTx);
    }

    // Coinbase-value check: consensus-critical, runs even under assumevalid.
    // Matches full-validation path below and Bitcoin Core ConnectBlock
    // (validation.cpp:2610-2614).
    const avCoinbaseTx = block.transactions[0];
    let avCoinbaseOutputValue = 0n;
    for (const output of avCoinbaseTx.outputs) {
      avCoinbaseOutputValue += output.value;
    }
    const avSubsidy = getBlockSubsidy(height, params);
    const avFees = avTotalInputValue - (avTotalOutputValue - avCoinbaseOutputValue);
    const avMaxCoinbaseValue = avSubsidy + avFees;
    if (avCoinbaseOutputValue > avMaxCoinbaseValue) {
      return {
        ok: false,
        error: `Coinbase value ${avCoinbaseOutputValue} exceeds maximum ${avMaxCoinbaseValue} at height ${height}`,
      };
    }

    return {
      ok: true,
      spentOutputs: [], // assume-valid path: no undo data needed
      totalInputValue: avTotalInputValue,
      totalOutputValue: avTotalOutputValue,
      coinbaseOutputValue: avCoinbaseOutputValue,
    };
  }

  // ── 4b. Full validation path ──────────────────────────────────────────────
  let totalSigOpsCost = 0;
  const spentOutputs: SpentUTXO[] = [];
  let totalInputValue = 0n;
  let totalOutputValue = 0n;

  for (let txIndex = 0; txIndex < block.transactions.length; txIndex++) {
    const tx = block.transactions[txIndex];
    const txid = getTxId(tx);
    const txidHex = txid.toString("hex");
    const isCoinbaseTx = isCoinbase(tx);

    const prevOutputs: Buffer[] = [];

    if (!isCoinbaseTx) {
      // Ensure all inputs are in cache (may need individual load for intra-block
      // chaining where a tx spends outputs of an earlier tx in the same block).
      for (const input of tx.inputs) {
        if (!utxoManager.hasUTXO(input.prevOut)) {
          const loaded = await utxoManager.preloadUTXO(input.prevOut);
          if (!loaded) {
            return {
              ok: false,
              error: `Missing UTXO for input ${input.prevOut.vout} of tx ${txidHex.slice(0, 16)}: ${input.prevOut.txid.toString("hex").slice(0, 16)}:${input.prevOut.vout} at height ${height}`,
            };
          }
        }
      }

      const utxoConfirmations: UTXOConfirmation[] = [];
      const inputUTXOs: UTXOEntry[] = [];

      for (const input of tx.inputs) {
        const utxo = utxoManager.getUTXO(input.prevOut);
        if (utxo) {
          prevOutputs.push(utxo.scriptPubKey);
          inputUTXOs.push(utxo);

          // ── Coinbase maturity (COINBASE_MATURITY = 100 confirmations).
          if (utxo.coinbase) {
            const maturity = height - utxo.height;
            if (maturity < params.coinbaseMaturity) {
              return {
                ok: false,
                error: `Immature coinbase spend in tx ${txidHex.slice(0, 16)}: maturity ${maturity} < ${params.coinbaseMaturity}`,
              };
            }
          }

          // Collect (height, medianTimePast) for BIP-68.
          // getUTXOMTP provides the MTP of the block at (utxoHeight - 1) when
          // available (sync/blocks.ts wires HeaderSync here).  Without it we
          // default to 0, which makes block-height-based locks work correctly
          // and time-based locks conservative (never spuriously fails, may miss
          // a time-lock violation at the exact MTP boundary).
          const coinMTP = getUTXOMTP ? getUTXOMTP(utxo.height) : 0;
          utxoConfirmations.push({ height: utxo.height, medianTimePast: coinMTP });
        }
      }

      // ── BIP-68 / CSV sequence locks.
      if (enforceBIP68 && tx.version >= 2) {
        const seqLockValid = checkSequenceLocks(
          tx,
          enforceBIP68,
          height,
          prevMTP,
          utxoConfirmations
        );
        if (!seqLockValid) {
          return {
            ok: false,
            error: `Sequence locks not satisfied for tx ${txidHex.slice(0, 16)} at height ${height}`,
          };
        }
      }

      // ── Script verification (skipped when skipScripts=true).
      if (!skipScripts) {
        const scriptFlags =
          (verifyP2SH ? ScriptFlags.VERIFY_P2SH : ScriptFlags.VERIFY_NONE) |
          (verifyWitness ? ScriptFlags.VERIFY_WITNESS : ScriptFlags.VERIFY_NONE);

        let scriptResult;
        if (scriptThreads === 1) {
          // Sequential path: benchmark baseline.
          scriptResult = verifyAllInputsSequential(tx, inputUTXOs, scriptFlags);
        } else {
          // Parallel path: production default.
          scriptResult = await verifyAllInputsParallel(tx, inputUTXOs, scriptFlags);
        }

        if (!scriptResult.valid) {
          const errSuffix =
            (scriptResult.failedInput !== undefined
              ? ` (input ${scriptResult.failedInput})`
              : "") +
            (scriptResult.error ? `: ${scriptResult.error}` : "");
          return {
            ok: false,
            error: `Script verification failed in tx ${txidHex.slice(0, 16)} at height ${height}${errSuffix}`,
          };
        }
      }

      // ── Spend inputs; collect undo data.
      for (const input of tx.inputs) {
        const spentEntry = utxoManager.spendOutput(input.prevOut);
        totalInputValue += spentEntry.amount;
        spentOutputs.push({
          txid: input.prevOut.txid,
          vout: input.prevOut.vout,
          entry: spentEntry,
        });
      }
    }

    // ── Sigops cost (P2SH and witness sigop counting).
    const txSigOpsCost = getTransactionSigOpCost(
      tx,
      prevOutputs,
      verifyP2SH,
      verifyWitness
    );
    totalSigOpsCost += txSigOpsCost;

    // ── Add outputs as new UTXOs BEFORE processing subsequent transactions
    //    so that block-internal chaining works correctly.
    utxoManager.addTransaction(txid, tx, height, isCoinbaseTx);

    // ── Sum output values.
    for (const output of tx.outputs) {
      totalOutputValue += output.value;
    }
  }

  // ── 5. Sigops ceiling.
  if (totalSigOpsCost > MAX_BLOCK_SIGOPS_COST) {
    return {
      ok: false,
      error: `Block sigops cost ${totalSigOpsCost} exceeds maximum ${MAX_BLOCK_SIGOPS_COST}`,
    };
  }

  // ── 6. Coinbase value ≤ subsidy + fees (consensus-critical).
  //
  // Reference: Bitcoin Core validation.cpp ConnectBlock block_reward check.
  // Never skipped by assumevalid — fScriptChecks only gates signature verification.
  const coinbaseTx = block.transactions[0];
  let coinbaseOutputValue = 0n;
  for (const output of coinbaseTx.outputs) {
    coinbaseOutputValue += output.value;
  }
  const subsidy = getBlockSubsidy(height, params);
  const fees = totalInputValue - (totalOutputValue - coinbaseOutputValue);
  const maxCoinbaseValue = subsidy + fees;
  if (coinbaseOutputValue > maxCoinbaseValue) {
    return {
      ok: false,
      error: `Coinbase value ${coinbaseOutputValue} exceeds maximum ${maxCoinbaseValue} at height ${height}`,
    };
  }

  return {
    ok: true,
    spentOutputs,
    totalInputValue,
    totalOutputValue,
    coinbaseOutputValue,
  };
}
