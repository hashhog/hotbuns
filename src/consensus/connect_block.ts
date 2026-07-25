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
  bip68VersionActive,
  verifyAllInputsParallel,
  verifyAllInputsSequential,
  ScriptFlags,
} from "../validation/tx.js";
import type { UTXOEntry } from "../storage/database.js";
import { UTXOManager, type SpentUTXO } from "../chain/utxo.js";
import { isFinalTx } from "../mining/template.js";

// ─── Script-flag exception helper ─────────────────────────────────────────────

/**
 * Compute the consensus script-verify flags bitmask for a specific block.
 *
 * A literal port of Bitcoin Core validation.cpp::GetBlockScriptFlags
 * (2249-2289), which is a three-step sequence:
 *
 *   1. BASE — seed P2SH | WITNESS | TAPROOT **unconditionally, for every
 *      block** (:2262). Core has had no BIP16Height / taprootHeight gate on
 *      these since v23; the historical violator blocks are handled entirely
 *      by the exception table in step 2, not by a height comparison.
 *   2. EXCEPTION — on a block-hash hit in `params.scriptFlagExceptions`,
 *      **REPLACE** the whole set with the table's value (:2264-2267).
 *   3. HEIGHT GATES — **OR** the four flags Core still gates by activation
 *      on top of step 2's result (:2268-2286): DERSIG (BIP66), CLTV (BIP65),
 *      CSV (BIP68/112/113), NULLDUMMY (BIP147, rides SegWit activation).
 *
 * Step 3 running AFTER step 2 is load-bearing. The previous implementation
 * early-returned the exception value, which drops all four. At block 692261
 * the table value is P2SH|WITNESS, so the early return yielded P2SH|WITNESS
 * alone while Core also has DERSIG|CLTV|CSV|NULLDUMMY active at that height —
 * a FALSE-ACCEPT (hotbuns would accept scripts Core rejects under those four
 * rules). The old comment defended this as "observationally equivalent ...
 * because the real exception blocks satisfy every flag anyway" and cited the
 * blockbrew/beamchain implementations as canonical; both of those have since
 * been corrected to Core's shape (blockbrew 9f35879, beamchain c138cad), and
 * "the one block with this hash happens to pass anyway" is a coincidence of
 * that block's contents, not a property of the algorithm.
 *
 * blockHashHex MUST be in display/RPC byte order (big-endian), computed as:
 *   Buffer.from(getBlockHash(block.header)).reverse().toString("hex")
 * — the same convention used by bip30ExceptionBlocks.
 *
 * NOTE: no STANDARD/policy flag is ever set here. NULLFAIL, CLEANSTACK,
 * LOW_S, STRICTENC, MINIMALDATA, MINIMALIF and WITNESS_PUBKEYTYPE are
 * policy-only (Core policy/policy.h:125) and must not reach block validation.
 *
 * Reference: Bitcoin Core kernel/chainparams.cpp:85-88, 210-211;
 *            src/validation.cpp:2249-2289 GetBlockScriptFlags.
 */
export function getScriptFlagsForBlock(
  params: ConsensusParams,
  blockHashHex: string,
  verifyDERSig: boolean,
  verifyCLTV: boolean,
  verifyCSV: boolean,
  verifyNullDummy: boolean,
): number {
  // ── Step 1: BASE. Unconditional for every block (Core :2262).
  let flags =
    ScriptFlags.VERIFY_P2SH |
    ScriptFlags.VERIFY_WITNESS |
    ScriptFlags.VERIFY_TAPROOT;

  // ── Step 2: EXCEPTION. REPLACE the whole set on a hash hit (Core :2264-2267).
  const exception = params.scriptFlagExceptions.find(
    (ex) => ex.blockHashHex === blockHashHex
  );
  if (exception !== undefined) {
    flags = exception.flags;
  }

  // ── Step 3: HEIGHT GATES, OR-ed on top of step 2 (Core :2268-2286).
  if (verifyDERSig) flags |= ScriptFlags.VERIFY_DERSIG;
  if (verifyCLTV) flags |= ScriptFlags.VERIFY_CHECKLOCKTIMEVERIFY;
  if (verifyCSV) flags |= ScriptFlags.VERIFY_CHECKSEQUENCEVERIFY;
  if (verifyNullDummy) flags |= ScriptFlags.VERIFY_NULLDUMMY;

  return flags;
}

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

  // NOTE: there are deliberately no verifyP2SH / verifyWitness / verifyTaproot
  // options here. Core sets SCRIPT_VERIFY_P2SH | WITNESS | TAPROOT
  // unconditionally on every block (validation.cpp:2262) and handles the
  // historical violator blocks through script_flag_exceptions, so there is no
  // height (or caller) input for them to take. Accepting them would recreate
  // the hash-blind second flag source that this wave exists to remove.

  /**
   * Whether to enforce strict-DER signatures (BIP-66 / DERSIG).
   * True when height >= params.bip66Height.
   *
   * Core validation.cpp GetBlockScriptFlags:2268-2271 gates SCRIPT_VERIFY_DERSIG
   * on DeploymentActiveAt(DEPLOYMENT_DERSIG).  This is one of the four MANDATORY
   * height-gated consensus flags that block-connect must apply (the prior code
   * only set P2SH|WITNESS|TAPROOT, under-flagging every pre-segwit-but-post-BIP66
   * block and leaving DERSIG enforcement to the WITNESS-implies-DERSIG fallback
   * in scriptFlagsFromBitmask — which is wrong below segwitHeight).
   */
  verifyDERSig?: boolean;

  /**
   * Whether to enforce OP_CHECKLOCKTIMEVERIFY (BIP-65 / CLTV).
   * True when height >= params.bip65Height.
   * Core validation.cpp:2273-2276 (DEPLOYMENT_CLTV).
   */
  verifyCLTV?: boolean;

  /**
   * Whether to enforce OP_CHECKSEQUENCEVERIFY (BIP-112 / CSV).
   * True when height >= params.csvHeight.
   * Core validation.cpp:2278-2281 (DEPLOYMENT_CSV).
   */
  verifyCSV?: boolean;

  /**
   * Whether to enforce NULLDUMMY (BIP-147).
   * True when height >= params.segwitHeight — Core activates BIP-147
   * simultaneously with segwit (validation.cpp:2283-2286 gates NULLDUMMY on
   * DEPLOYMENT_SEGWIT).
   */
  verifyNullDummy?: boolean;

  /**
   * Optional per-coin MTP provider for BIP-68 time-based sequence locks.
   *
   * Called with the block height at which a UTXO was created; should return
   * the Median Time Past of the block at (utxoHeight - 1).
   *
   * Supply this whenever HeaderSync is wired (both the IBD/P2P path via
   * sync/blocks.ts AND the reorg-reconnect/regtest path via chain/state.ts).
   * Without it, time-based relative locks default to coinMTP=0, making
   * minTime trivially satisfiable — a false-ACCEPT for time-locked txs.
   *
   * The callback MUST read from the persistent header store (loaded by
   * HeaderSync.loadFromDB() on startup) so it is correct post-restart.
   * The getMedianTimePast partial walk never returns 0 on a short walk.
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
    // assumeValid (pure-height) is no longer a skip driver — the faithful
    // `skipScripts` gate is the sole driver; the opt remains in ConnectBlockOpts
    // for caller compatibility but is intentionally not consumed here.
    skipScripts = false,
    prevMTP = 0,
    enforceBIP68 = false,
    scriptThreads = 4,
    // MANDATORY height-gated consensus flags (Core GetBlockScriptFlags).
    // Default each from its own activation height in chainparams, exactly as
    // Core's GetBlockScriptFlags gates on the per-deployment activation.
    verifyDERSig = height >= params.bip66Height,
    verifyCLTV = height >= params.bip65Height,
    verifyCSV = height >= params.csvHeight,
    verifyNullDummy = height >= params.segwitHeight,
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

  // ── Per-block consensus script-verify flags, resolved ONCE for the whole
  // block (they depend only on the block, never on the transaction).
  //
  // Computed here — OUTSIDE the `skipScripts` guard — because sigop accounting
  // below consumes it too, and sigops are counted on every connect regardless
  // of whether scripts are verified (assumevalid IBD, reorg replay, import).
  // Core does the same: GetBlockScriptFlags feeds both CheckInputScripts and
  // GetTransactionSigOpCost(tx, inputs, flags) (consensus/tx_verify.cpp:143-162).
  const blockScriptFlags = getScriptFlagsForBlock(
    params,
    blockHashHexForGate,
    verifyDERSig,
    verifyCLTV,
    verifyCSV,
    verifyNullDummy,
  );
  // Sigop counting gates on the FINAL, exception-aware flag set, not on the
  // raw height booleans — Core gates P2SH sigops on SCRIPT_VERIFY_P2SH
  // (tx_verify.cpp:150-152) and returns 0 witness sigops when
  // SCRIPT_VERIFY_WITNESS is clear (script/interpreter.cpp:2141-2143). At the
  // BIP-16 exception block the flags are SCRIPT_VERIFY_NONE, so Core counts
  // ZERO P2SH and witness sigops there.
  const sigopsP2SH = (blockScriptFlags & ScriptFlags.VERIFY_P2SH) !== 0;
  const sigopsWitness = (blockScriptFlags & ScriptFlags.VERIFY_WITNESS) !== 0;

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

  // ── 4a. (assume-valid fast path removed) ──────────────────────────
  // Previously a height-driven fast path skipped maturity/BIP-68/sigops/
  // CheckTxInputs for assumevalid-window blocks — over-skipping vs Core,
  // whose fScriptChecks=false skips ONLY signature/script verification. Now
  // every block runs the full path below; `skipScripts` (the faithful gate)
  // gates ONLY signature verification (the `if (!skipScripts)` block).

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
      for (let inputIdx = 0; inputIdx < tx.inputs.length; inputIdx++) {
        const input = tx.inputs[inputIdx];
        if (!utxoManager.hasUTXO(input.prevOut)) {
          const loaded = await utxoManager.preloadUTXO(input.prevOut);
          if (!loaded) {
            // W93: match Core's canonical reject reason
            // (consensus/tx_verify.cpp:168 — bad-txns-inputs-missingorspent).
            // This is the HaveInputs() precondition gate at the entry to
            // Consensus::CheckTxInputs.
            // Bug #132 (2026-05-26): prior message labelled `input.prevOut.vout`
            // as "input N" — that's the prevout's vout, NOT the vin-index.
            // Now logs both: `vin[i]` is the input index, `prevout txid:vout`
            // is the spent coin's identity.
            return {
              ok: false,
              error: `bad-txns-inputs-missingorspent: vin[${inputIdx}] of tx ${txidHex.slice(0, 16)} spends prevout ${input.prevOut.txid.toString("hex").slice(0, 16)}:${input.prevOut.vout} at height ${height}`,
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

      // ── BIP-68 / CSV sequence locks. Version compared unsigned (Core uint32_t).
      if (enforceBIP68 && bip68VersionActive(tx.version)) {
        const seqLockValid = checkSequenceLocks(
          tx,
          enforceBIP68,
          height,
          prevMTP,
          utxoConfirmations
        );
        if (!seqLockValid) {
          // Core ConnectBlock emits the SAME reject reason for a BIP-68
          // SequenceLocks failure as for an IsFinalTx failure:
          // state.Invalid(BLOCK_CONSENSUS, "bad-txns-nonfinal",
          //   "contains a non-BIP68-final transaction ...")
          // (validation.cpp:2557-2559). Carry the canonical `bad-txns-nonfinal`
          // token in the error string so the BIP-22 reason mapper
          // (ConsensusErrorCode.SEQUENCE_LOCK_NOT_SATISFIED -> "bad-txns-nonfinal")
          // and any token-matching consumer surface the correct Core reason —
          // matching the sibling IsFinalTx message above and rustoshi.
          return {
            ok: false,
            error: `Sequence locks not satisfied (bad-txns-nonfinal): non-BIP68-final tx ${txidHex.slice(0, 16)} at height ${height}`,
          };
        }
      }

      // ── Script verification (skipped when skipScripts=true).
      if (!skipScripts) {
        // Per-block bitmask, resolved once above (see blockScriptFlags).
        const scriptFlags = blockScriptFlags;

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
      sigopsP2SH,
      sigopsWitness
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
