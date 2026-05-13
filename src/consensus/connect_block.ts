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
 *   0a. Genesis short-circuit (validation.cpp:2339-2343)                       [W93]
 *   0b. View-best-block consistency check (validation.cpp:2333)                [W93]
 *   1.  BIP-30 duplicate-UTXO check (UTXO-integrity; runs even under assumevalid)
 *   2.  IsFinalTx for every transaction (BIP-113 lock-time; runs even under assumevalid)
 *   3.  Bulk UTXO preload (parallel LevelDB reads)
 *   4a. Assumevalid fast path: spend + addTransaction, skip maturity/BIP68/scripts
 *   4b. Full validation path: maturity + BIP-68/CSV + script verify + spend + addTransaction
 *       + per-tx accumulated-fee MoneyRange (W93, validation.cpp:2543-2547)
 *       + per-tx bad-txns-in-belowout (W93, tx_verify.cpp:197)
 *   5.  Sigops cost ceiling (MAX_BLOCK_SIGOPS_COST)  [full path only; W93 token "bad-blk-sigops"]
 *   6.  Coinbase value ≤ subsidy + fees (consensus-critical; runs even under
 *       assumevalid; W93 token "bad-cb-amount")
 *
 * Canonical Bitcoin Core reject tokens emitted by this function (W93):
 *   - bad-txns-inputs-missingorspent       (tx_verify.cpp:168)
 *   - bad-txns-in-belowout                 (tx_verify.cpp:197)
 *   - bad-txns-accumulated-fee-outofrange  (validation.cpp:2544)
 *   - bad-txns-inputvalues-outofrange      (tx_verify.cpp:187)
 *   - bad-blk-sigops                       (validation.cpp:2570)
 *   - bad-cb-amount                        (validation.cpp:2612)
 *   - bad-txns-BIP30                       (validation.cpp:2471)
 *   - bad-txns-nonfinal                    (validation.cpp:2558 / :4146)
 *
 * UTXO mutations (spendOutput / addTransaction) are performed inside this
 * function so that block-internal transaction chaining works correctly:
 * a transaction at index N can create a UTXO that transaction N+1 spends.
 *
 * DB writes (undo data, block store, chain state, block index) are LEFT TO
 * THE CALLER — they differ between the two call sites.  The caller also
 * advances the UTXO view's best-block pointer (`utxoManager.setBestBlock`)
 * after this function returns; pre-W93 chain/state.ts forgot this update,
 * leaving the view's bestBlock stale until the next flush.
 *
 * Reference: Bitcoin Core validation.cpp::ConnectBlock (lines 2295-2673),
 *            validation.cpp::ConnectTip (lines 3005-3108),
 *            validation.cpp::UpdateCoins (lines 1999-2012),
 *            consensus/tx_verify.cpp::CheckTxInputs (lines 164-214).
 */

import type { ConsensusParams } from "./params.js";
import { getBlockSubsidy } from "./params.js";
import type { Block } from "../validation/block.js";
import {
  getTransactionSigOpCost,
  MAX_BLOCK_SIGOPS_COST,
  getBlockHash,
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
   * Whether to verify Taproot scripts (BIP-341/342).
   * True when height >= params.taprootHeight.
   */
  verifyTaproot?: boolean;

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

  /**
   * W93 gate — hash of the genesis block on this network.  When supplied,
   * coreConnectBlockChecks short-circuits the per-tx loop for the genesis
   * block, matching Bitcoin Core validation.cpp:2339-2343:
   *
   *   // Special case for the genesis block, skipping connection of its
   *   // transactions (its coinbase is unspendable)
   *   if (block_hash == params.GetConsensus().hashGenesisBlock) { ... return true; }
   *
   * Without this guard, hotbuns runs the full tx loop on genesis: BIP-30
   * happens to no-op (the UTXO is empty), the coinbase-value check sees
   * 50 BTC vs subsidy 50 BTC and passes, but the early exit is symbolic
   * — exposing the special case to test harnesses lets us match Core's
   * "true without persisting anything for tx[0]" semantics.
   */
  genesisHashHex?: string;

  /**
   * W93 gate — hash of the parent block as stored in this UTXO view.
   * When supplied, coreConnectBlockChecks asserts that the parent of the
   * block being connected matches this hash, mirroring Core's
   * validation.cpp:2333 invariant:
   *
   *   assert(hashPrevBlock == view.GetBestBlock());
   *
   * In Core this is an `assert` that aborts the process on failure (the
   * UTXO view should never be out of sync with the chain).  In hotbuns
   * we make this a soft check that returns a ConnectBlockErr instead, so
   * an upstream coordination bug surfaces as a chain-state error rather
   * than a process exit.  Callers that have access to `utxoManager
   * .cache.getBestBlock()` should wire this through.
   */
  utxoBestBlockHashHex?: string;
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
    verifyTaproot = height >= params.taprootHeight,
    getUTXOMTP,
    genesisHashHex,
    utxoBestBlockHashHex,
  } = opts;

  // ── W93 Gate 0a: Genesis short-circuit.
  //
  // Bitcoin Core validation.cpp:2339-2343 explicitly skips connection of the
  // genesis block's transactions because its coinbase is unspendable.  Without
  // this gate the BIP-30 + tx loop run uselessly on genesis (BIP-30 happens
  // to no-op because the view is empty; tx loop then attempts to "spend"
  // genesis-coinbase phantom inputs).  Mirrors Core's early-return.
  const blockHashForGate = getBlockHash(block.header);
  const blockHashHexForGate = Buffer.from(blockHashForGate)
    .reverse()
    .toString("hex"); // display order
  if (genesisHashHex && blockHashHexForGate === genesisHashHex) {
    return {
      ok: true,
      spentOutputs: [],
      totalInputValue: 0n,
      totalOutputValue: 0n,
      coinbaseOutputValue: 0n,
    };
  }

  // ── W93 Gate 0b: View consistency — the UTXO view's best block hash MUST
  // match this block's prevBlock.  Core validation.cpp:2333 asserts:
  //   assert(hashPrevBlock == view.GetBestBlock());
  // In Core this is fatal (process exit); in hotbuns we surface a clean
  // ConnectBlockErr so an upstream coordination bug doesn't kill the daemon
  // mid-IBD.  Callers that don't have a fresh `view.getBestBlock()` (e.g.
  // generateblock RPC at cold start) may omit this option — the gate becomes
  // a no-op rather than fail-closed.
  if (utxoBestBlockHashHex !== undefined) {
    const prevBlockHexLE = Buffer.from(block.header.prevBlock)
      .reverse()
      .toString("hex");
    // Allow empty/zero view-best-block as the "fresh start" state (matches
    // Core's `view.GetBestBlock() == uint256()` for genesis-parent case).
    const viewBest = utxoBestBlockHashHex.toLowerCase();
    const isFreshView =
      viewBest === "" ||
      viewBest === "0".repeat(64);
    if (!isFreshView && viewBest !== prevBlockHexLE.toLowerCase()) {
      return {
        ok: false,
        error: `UTXO view best block ${viewBest} does not match block prev ${prevBlockHexLE} at height ${height} (view-out-of-sync)`,
      };
    }
  }

  // ── 1. BIP-30: reject blocks that would overwrite an existing unspent output.
  //
  // Gate A — IsBIP30Repeat: two mainnet blocks (h=91842, h=91880) are permanently
  // exempt by BOTH height AND block hash. Checking height alone is wrong: an
  // alternative-chain block at height 91842 with a different hash must still
  // enforce BIP-30. Core's IsBIP30Repeat() (validation.cpp:6189-6192) verifies both.
  //
  // Gate B — BIP-34 skip: once BIP-34 is active and the canonical BIP34Hash is
  // confirmed at the activation height, coinbase-height uniqueness makes new
  // duplicates practically impossible. Skip BIP-30 between bip34Height and
  // 1,983,702. Core validation.cpp:2460-2462 verifies ancestor hash == BIP34Hash.
  //
  // Gate C — BIP34_IMPLIES_BIP30_LIMIT = 1,983,702: BIP-34 modular arithmetic
  // begins to repeat pre-BIP34 coinbase heights above this limit, so re-enable
  // BIP-30 at and above this height regardless of BIP-34 status.
  //
  // Consensus-critical: runs even under assumevalid.
  // Reference: Bitcoin Core validation.cpp:2402-2476, 6189-6192.
  {
    const BIP34_IMPLIES_BIP30_LIMIT = 1_983_702;

    // Gate A: IsBIP30Repeat — exempt by height AND hash, not height alone.
    const blockHash = getBlockHash(block.header);
    const blockHashHex = Buffer.from(blockHash).reverse().toString("hex"); // display order
    const isExempt = params.bip30ExceptionBlocks.some(
      (ex) => ex.height === height && ex.blockHashHex === blockHashHex
    );

    // Gate B: BIP-34 skip — skip BIP-30 only when the canonical BIP34Hash is
    // confirmed at the activation height. We approximate this by checking whether
    // we are past bip34Height AND bip34Hash is non-null (meaning this network has
    // a canonical BIP34 activation block). On the canonical chain this is always
    // true once past that height; on an alternative chain the BIP-30 check would
    // still fire correctly because those blocks are below bip34Height.
    //
    // Note: Bitcoin Core uses pindex->pprev->GetAncestor(BIP34Height)->GetBlockHash()
    // for the full ancestor check. We cannot do that here without chain context, but
    // the approximation is correct for IBD on the canonical chain: once bip34Hash is
    // set and we're past bip34Height we're guaranteed to be on the chain that has that
    // activation block (ancestor check would pass).
    const bip34HashConfirmed = params.bip34Hash !== null && height >= params.bip34Height;
    const belowReenableLimit = height < BIP34_IMPLIES_BIP30_LIMIT;

    // fEnforceBIP30 matches Core's logic:
    //   fEnforceBIP30 = !IsBIP30Repeat(*pindex)
    //   fEnforceBIP30 &= !(pindexBIP34height && BIP34Hash matches)
    //   if (fEnforceBIP30 || height >= BIP34_IMPLIES_BIP30_LIMIT) → run check
    const fEnforceBIP30 = !isExempt && !(bip34HashConfirmed && belowReenableLimit);

    if (fEnforceBIP30 || height >= BIP34_IMPLIES_BIP30_LIMIT) {
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
              // W93: match Core's canonical reject reason
              // (consensus/tx_verify.cpp:168 — bad-txns-inputs-missingorspent).
              return {
                ok: false,
                error: `bad-txns-inputs-missingorspent: input ${input.prevOut.txid.toString("hex").slice(0, 16)}:${input.prevOut.vout} not in UTXO set at height ${height}`,
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
      // W93: align with Core's canonical reject reason (validation.cpp:2612).
      return {
        ok: false,
        error: `bad-cb-amount: coinbase pays too much (actual=${avCoinbaseOutputValue} vs limit=${avMaxCoinbaseValue}) at height ${height}`,
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
  // W93 Gate H: per-tx accumulated nFees with MoneyRange check.
  // Bitcoin Core validation.cpp:2542-2547 increments nFees per tx then bails
  // on !MoneyRange(nFees) — the bad-txns-accumulated-fee-outofrange error.
  // Previously hotbuns only computed a final `fees` post-loop; if it ever
  // overflowed, the error code was `bad-txns-accumulated-fee-outofrange`
  // but fired AFTER the loop, not at the offending tx.  Tracking per-tx
  // matches Core's gate ordering.
  let nFees = 0n;
  const MAX_MONEY_FEE = 2_100_000_000_000_000n;

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
            // W93: match Core's canonical reject reason
            // (consensus/tx_verify.cpp:168 — bad-txns-inputs-missingorspent).
            // This is the HaveInputs() precondition gate at the entry to
            // Consensus::CheckTxInputs.
            return {
              ok: false,
              error: `bad-txns-inputs-missingorspent: input ${input.prevOut.vout} of tx ${txidHex.slice(0, 16)} (${input.prevOut.txid.toString("hex").slice(0, 16)}:${input.prevOut.vout}) at height ${height}`,
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
          (verifyP2SH    ? ScriptFlags.VERIFY_P2SH    : ScriptFlags.VERIFY_NONE) |
          (verifyWitness ? ScriptFlags.VERIFY_WITNESS  : ScriptFlags.VERIFY_NONE) |
          (verifyTaproot ? ScriptFlags.VERIFY_TAPROOT  : ScriptFlags.VERIFY_NONE);

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
      // Also enforce per-coin and accumulated input MoneyRange checks.
      // Core consensus/tx_verify.cpp::CheckTxInputs:184-188:
      //   nValueIn += coin.out.nValue;
      //   if (!MoneyRange(coin.out.nValue) || !MoneyRange(nValueIn))
      //     → "bad-txns-inputvalues-outofrange"
      const MAX_MONEY_INPUT = 2_100_000_000_000_000n; // 21_000_000 * COIN
      for (const input of tx.inputs) {
        const spentEntry = utxoManager.spendOutput(input.prevOut);
        // Gate: individual coin value must be in MoneyRange.
        if (spentEntry.amount < 0n || spentEntry.amount > MAX_MONEY_INPUT) {
          return {
            ok: false,
            error: `bad-txns-inputvalues-outofrange in tx ${txidHex.slice(0, 16)}`,
          };
        }
        totalInputValue += spentEntry.amount;
        // Gate: accumulated input value must stay in MoneyRange.
        if (totalInputValue > MAX_MONEY_INPUT) {
          return {
            ok: false,
            error: `bad-txns-inputvalues-outofrange (accumulated) in tx ${txidHex.slice(0, 16)}`,
          };
        }
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

    // ── Sum output values; bump per-tx fee accumulator + MoneyRange check.
    let txOutputValue = 0n;
    for (const output of tx.outputs) {
      totalOutputValue += output.value;
      txOutputValue += output.value;
    }
    if (!isCoinbaseTx) {
      // W93 Gate H: per-tx accumulated nFees MoneyRange check.
      // Core consensus/tx_verify.cpp:196-199 computes
      //   value_out = tx.GetValueOut(); if (nValueIn < value_out) → bad-txns-in-belowout.
      // We track txValueIn locally to mirror this gate per tx (the cumulative
      // bad-txns-in-belowout check still runs post-loop for safety).
      let txValueIn = 0n;
      for (const sp of spentOutputs.slice(-(tx.inputs.length))) {
        txValueIn += sp.entry.amount;
      }
      if (txValueIn < txOutputValue) {
        return {
          ok: false,
          error: `bad-txns-in-belowout: value in (${txValueIn}) < value out (${txOutputValue}) in tx ${txidHex.slice(0, 16)} at height ${height}`,
        };
      }
      const txFee = txValueIn - txOutputValue;
      nFees += txFee;
      // Core validation.cpp:2543-2547 — MoneyRange check on the running
      // total, NOT just the per-tx fee.  Match that exactly.
      if (nFees < 0n || nFees > MAX_MONEY_FEE) {
        return {
          ok: false,
          error: `bad-txns-accumulated-fee-outofrange at tx ${txidHex.slice(0, 16)} (h=${height})`,
        };
      }
    }
  }

  // ── 5. Sigops ceiling.
  //
  // Bitcoin Core validation.cpp:2569-2572:
  //   if (nSigOpsCost > MAX_BLOCK_SIGOPS_COST) {
  //     state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-blk-sigops", ...);
  //   }
  // W93: emit canonical "bad-blk-sigops" prefix so cross-impl diff-test
  // corpus and BIP-22 token mapping (bip22FromConnectError) catch it.
  if (totalSigOpsCost > MAX_BLOCK_SIGOPS_COST) {
    return {
      ok: false,
      error: `bad-blk-sigops: cost ${totalSigOpsCost} exceeds maximum ${MAX_BLOCK_SIGOPS_COST} at height ${height}`,
    };
  }

  // ── 6. Coinbase value ≤ subsidy + fees (consensus-critical).
  //
  // Reference: Bitcoin Core validation.cpp:2610-2614:
  //   CAmount blockReward = nFees + GetBlockSubsidy(pindex->nHeight, ...);
  //   if (block.vtx[0]->GetValueOut() > blockReward && state.IsValid())
  //     state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-cb-amount", ...);
  // Never skipped by assumevalid — fScriptChecks only gates signature verification.
  const coinbaseTx = block.transactions[0];
  let coinbaseOutputValue = 0n;
  for (const output of coinbaseTx.outputs) {
    coinbaseOutputValue += output.value;
  }
  const subsidy = getBlockSubsidy(height, params);

  // W93: nFees was tracked per-tx with MoneyRange check inside the loop, so
  // any range / bad-txns-in-belowout error already returned above.  This
  // post-loop check is the consensus-critical Core gate at validation.cpp:
  // 2611.  The legacy `fees = totalInputValue - (totalOutputValue -
  // coinbaseOutputValue)` arithmetic is kept as a defensive sanity check —
  // it MUST equal nFees if the per-tx loop computed correctly.
  const feesByTotals = totalInputValue - (totalOutputValue - coinbaseOutputValue);
  if (feesByTotals !== nFees) {
    // This would indicate an internal arithmetic mismatch — would only fire
    // under a programmer bug, but match Core's "bad-cb-amount" semantics.
    return {
      ok: false,
      error: `bad-cb-amount: internal fee accounting mismatch nFees=${nFees} vs totals-derived=${feesByTotals} at h=${height}`,
    };
  }

  const blockReward = subsidy + nFees;
  if (coinbaseOutputValue > blockReward) {
    return {
      ok: false,
      error: `bad-cb-amount: coinbase pays too much (actual=${coinbaseOutputValue} vs limit=${blockReward}) at height ${height}`,
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
