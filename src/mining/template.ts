/**
 * Block template construction for mining.
 *
 * Selects transactions from the mempool to maximize fees while respecting
 * weight limits and dependency ordering. Constructs coinbase transaction
 * with proper BIP34 height encoding and witness commitment.
 */

import type { ConsensusParams } from "../consensus/params.js";
import { getBlockSubsidy, compactToBigInt, bigIntToCompact } from "../consensus/params.js";
import type { ChainStateManager } from "../chain/state.js";
import type { Mempool, MempoolEntry } from "../mempool/mempool.js";
import {
  VersionBitsCache,
  buildBlockIndex,
  VERSIONBITS_TOP_BITS,
  type DeploymentParams,
  type HeaderInfo,
} from "../consensus/versionbits.js";
import type {
  Transaction,
  TxIn,
  TxOut,
} from "../validation/tx.js";
import {
  getTxId,
  getWTxId,
  getTxWeight,
  serializeTx,
} from "../validation/tx.js";
import type { BlockHeader, Block } from "../validation/block.js";
import {
  computeMerkleRoot,
  computeWitnessMerkleRoot,
} from "../validation/block.js";
import { hash256 } from "../crypto/primitives.js";
import { BufferWriter, varIntSize } from "../wire/serialization.js";

/**
 * Locktime threshold: values below this are block heights, above are Unix timestamps.
 * Per BIP-113 and consensus rules.
 */
const LOCKTIME_THRESHOLD = 500_000_000;

/**
 * Check if a transaction is final for inclusion in a block at the given height and time.
 *
 * A transaction is final if:
 * - nLockTime == 0, OR
 * - nLockTime < threshold (block height or time depending on LOCKTIME_THRESHOLD), OR
 * - All inputs have nSequence == 0xFFFFFFFF
 *
 * Reference: Bitcoin Core's IsFinalTx() in consensus/tx_verify.cpp
 *
 * @param tx - The transaction to check
 * @param blockHeight - The height of the block being assembled
 * @param blockTime - The median time past (MTP) of the previous block
 * @returns true if the transaction is final
 */
export function isFinalTx(tx: Transaction, blockHeight: number, blockTime: number): boolean {
  // nLockTime == 0 means always final
  if (tx.lockTime === 0) {
    return true;
  }

  // Determine if locktime is height-based or time-based
  const lockTimeThreshold = tx.lockTime < LOCKTIME_THRESHOLD ? blockHeight : blockTime;

  // If nLockTime is less than the threshold, the tx is final
  if (tx.lockTime < lockTimeThreshold) {
    return true;
  }

  // Even if nLockTime isn't satisfied, a transaction is still final if all
  // inputs have nSequence == 0xFFFFFFFF (SEQUENCE_FINAL)
  for (const input of tx.inputs) {
    if (input.sequence !== 0xffffffff) {
      return false;
    }
  }

  return true;
}

/**
 * A complete block template ready for mining.
 */
export interface BlockTemplate {
  /** Block header (nonce set to 0, ready for mining). */
  header: BlockHeader;
  /** The coinbase transaction. */
  coinbaseTx: Transaction;
  /** Selected mempool transactions (ordered by inclusion order). */
  transactions: Transaction[];
  /** Total fees from all selected transactions. */
  totalFees: bigint;
  /** Total weight of the block (including header). */
  totalWeight: number;
  /** Total sigops cost of the block. */
  totalSigOps: number;
  /** Block height. */
  height: number;
  /** Target value for proof of work. */
  target: bigint;
}

/**
 * Reserved weight for block header, var_int tx count and coinbase transaction.
 * Core default: DEFAULT_BLOCK_RESERVED_WEIGHT = 8000 (policy/policy.h:27).
 * This is the value passed to resetBlock() as nBlockWeight and must match Core.
 */
const BLOCK_RESERVED_WEIGHT = 8000;

/**
 * Minimum sigops budget reserved for coinbase transaction outputs.
 * Core default: DEFAULT_COINBASE_OUTPUT_MAX_ADDITIONAL_SIGOPS = 400 (policy/policy.h:29).
 * Applied in resetBlock() analog: nBlockSigOpsCost starts at this value.
 */
const COINBASE_OUTPUT_MAX_ADDITIONAL_SIGOPS = 400;

/**
 * Maximum consecutive failed chunk additions before early exit when block is nearly full.
 * Core: MAX_CONSECUTIVE_FAILURES = 1000 (node/miner.cpp:284).
 */
const MAX_CONSECUTIVE_FAILURES = 1000;

/**
 * Weight delta used with MAX_CONSECUTIVE_FAILURES: if block weight is within
 * BLOCK_FULL_ENOUGH_WEIGHT_DELTA of the maximum AND we've hit MAX_CONSECUTIVE_FAILURES,
 * give up early. Core: BLOCK_FULL_ENOUGH_WEIGHT_DELTA = 4000 (node/miner.cpp:285).
 */
const BLOCK_FULL_ENOUGH_WEIGHT_DELTA = 4000;

/**
 * Coinbase input sequence value. Core uses MAX_SEQUENCE_NONFINAL (= SEQUENCE_FINAL - 1 =
 * 0xFFFFFFFE) so that the coinbase's nLockTime = nHeight-1 is actually enforced.
 * Using SEQUENCE_FINAL (0xFFFFFFFF) would make IsFinalTx ignore nLockTime entirely.
 * Reference: node/miner.cpp:171 "Make sure timelock is enforced."
 */
const MAX_SEQUENCE_NONFINAL = 0xfffffffe;

/**
 * Witness commitment header: OP_RETURN (0x6a) + push 36 bytes (0x24) + commitment marker (0xaa21a9ed)
 */
const WITNESS_COMMITMENT_HEADER = Buffer.from([0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed]);

/**
 * Encode a number as a minimal CScript number (little-endian with sign handling).
 *
 * Exported standalone so `generateblock` (which builds blocks with arbitrary
 * user-supplied transactions, not mempool selection, and therefore cannot use
 * `BlockTemplateBuilder.createTemplate` directly) can reuse the same encoding
 * as the canonical helper.
 */
export function encodeScriptNum(n: number): Buffer {
  if (n === 0) {
    return Buffer.alloc(0);
  }

  const negative = n < 0;
  let absValue = Math.abs(n);
  const result: number[] = [];

  while (absValue > 0) {
    result.push(absValue & 0xff);
    absValue >>= 8;
  }

  // If the most significant byte has the high bit set and the number is positive,
  // add a 0x00 byte to avoid it being interpreted as negative
  if (result[result.length - 1] & 0x80) {
    result.push(negative ? 0x80 : 0x00);
  } else if (negative) {
    result[result.length - 1] |= 0x80;
  }

  return Buffer.from(result);
}

/**
 * Encode height as BIP34 push data for coinbase scriptSig.
 *
 * BIP34 requires the height to be pushed using minimal CScript encoding:
 * - Heights 0: OP_0 (0x00)
 * - Heights 1-16: OP_1 to OP_16 (0x51-0x60)
 * - Heights 17+: [length byte] [height in little-endian]
 *
 * Exported alongside {@link encodeScriptNum} so `generateblock` and the
 * production RPC layer can share the canonical encoder used by
 * {@link BlockTemplateBuilder.createTemplate}.
 */
export function encodeBIP34Height(height: number): Buffer {
  if (height < 0) {
    throw new Error("Height cannot be negative");
  }

  if (height === 0) {
    return Buffer.from([0x00]); // OP_0
  }

  if (height >= 1 && height <= 16) {
    return Buffer.from([0x50 + height]); // OP_1 to OP_16
  }

  // For heights >= 17, use minimal push encoding
  const heightBytes = encodeScriptNum(height);
  return Buffer.concat([
    Buffer.from([heightBytes.length]),
    heightBytes,
  ]);
}

/**
 * Build a coinbase transaction outside the BlockTemplateBuilder instance.
 *
 * Mirrors the private `BlockTemplateBuilder.buildCoinbase` method byte-for-byte
 * so the `generateblock` RPC (which selects user-supplied transactions instead
 * of mempool-greedy selection) emits a coinbase that is consensus-identical to
 * the one BlockTemplateBuilder produces — fixing W123 BUG-5 (sequence) and
 * BUG-6 (lockTime) on the explicit-tx mining path without requiring a full
 * BlockTemplateBuilder call.
 *
 * Reference: Bitcoin Core `node/miner.cpp::CreateNewBlock` (lines 162-199):
 *   - `vin[0].nSequence = CTxIn::MAX_SEQUENCE_NONFINAL` (L171)
 *   - `vin[0].scriptSig = CScript() << nHeight` + optional extranonce
 *   - `vout[0].nValue = nFees + GetBlockSubsidy(nHeight, params)`
 *   - `nLockTime = static_cast<uint32_t>(nHeight - 1)` (L196)
 *
 * @param height - Height of the block being assembled (parent.height + 1)
 * @param fees - Total fees collected from selected transactions
 * @param params - Consensus params (drives `getBlockSubsidy`)
 * @param coinbaseScript - scriptPubKey for the miner's reward output
 * @param extraNonce - Optional bytes appended to scriptSig after the height push
 * @param witnessCommitment - 32-byte witness commitment (segwit); pass `Buffer.alloc(0)` pre-segwit
 */
export function buildCoinbaseTransaction(
  height: number,
  fees: bigint,
  params: ConsensusParams,
  coinbaseScript: Buffer,
  extraNonce: Buffer = Buffer.alloc(0),
  witnessCommitment: Buffer = Buffer.alloc(0)
): Transaction {
  const subsidy = getBlockSubsidy(height, params);
  const totalReward = subsidy + fees;

  const heightPush = encodeBIP34Height(height);
  const scriptSig = Buffer.concat([heightPush, extraNonce]);

  const inputs: TxIn[] = [
    {
      prevOut: {
        txid: Buffer.alloc(32, 0),
        vout: 0xffffffff,
      },
      scriptSig,
      sequence: MAX_SEQUENCE_NONFINAL,
      witness: witnessCommitment.length > 0 ? [Buffer.alloc(32, 0)] : [],
    },
  ];

  const outputs: TxOut[] = [
    {
      value: totalReward,
      scriptPubKey: coinbaseScript,
    },
  ];

  if (witnessCommitment.length === 32) {
    const commitmentScript = Buffer.concat([
      WITNESS_COMMITMENT_HEADER,
      witnessCommitment,
    ]);
    outputs.push({
      value: 0n,
      scriptPubKey: commitmentScript,
    });
  }

  return {
    version: 2,
    inputs,
    outputs,
    lockTime: height > 0 ? height - 1 : 0,
  };
}

/**
 * Compute the BIP-141 witness commitment for a list of non-coinbase transactions.
 *
 * commitment = hash256(witness_merkle_root || witness_nonce)
 *
 * The witness merkle root uses wtxids, with the coinbase wtxid forced to 32
 * zero bytes per BIP-141. The witness nonce in the coinbase input witness is
 * always 32 zero bytes — Core supports operator-chosen nonces but the
 * canonical empty-nonce form is what every other production miner emits.
 *
 * Exported alongside {@link buildCoinbaseTransaction} so the production RPC
 * layer can compute the commitment exactly the way BlockTemplateBuilder does.
 */
export function computeWitnessCommitmentHash(txs: Transaction[]): Buffer {
  const wtxids: Buffer[] = [Buffer.alloc(32, 0)]; // Coinbase wtxid placeholder
  for (const tx of txs) {
    wtxids.push(getWTxId(tx));
  }
  const witnessMerkleRoot = computeWitnessMerkleRoot(wtxids);
  const witnessNonce = Buffer.alloc(32, 0);
  return hash256(Buffer.concat([witnessMerkleRoot, witnessNonce]));
}

/**
 * Block template builder.
 *
 * Constructs valid block templates by selecting transactions from the mempool,
 * ordering them correctly (respecting dependencies), and creating the coinbase
 * transaction with proper height encoding and witness commitment.
 */
export class BlockTemplateBuilder {
  private mempool: Mempool;
  private chainState: ChainStateManager;
  private params: ConsensusParams;
  /** Optional header lookup for BIP9 computeBlockVersion. */
  private getHeaderByHeight?: (height: number) => HeaderInfo | undefined;
  /** Optional per-deployment params for BIP9 version bits signalling. */
  private deployments?: Map<string, DeploymentParams>;
  /** Per-deployment state cache (reused across template builds). */
  private versionBitsCache: VersionBitsCache = new VersionBitsCache();

  /**
   * Median time past for locktime validation.
   * Set via setMedianTimePast() or automatically calculated if available.
   */
  private medianTimePast: number = 0;

  constructor(
    mempool: Mempool,
    chainState: ChainStateManager,
    params: ConsensusParams,
    opts?: {
      /**
       * Header lookup by height for BIP9 computeBlockVersion.
       * Without this, block version defaults to VERSIONBITS_TOP_BITS (0x20000000).
       */
      getHeaderByHeight?: (height: number) => HeaderInfo | undefined;
      /** Active deployments to signal in block version. */
      deployments?: Map<string, DeploymentParams>;
    }
  ) {
    this.mempool = mempool;
    this.chainState = chainState;
    this.params = params;
    this.getHeaderByHeight = opts?.getHeaderByHeight;
    this.deployments = opts?.deployments;
  }

  /**
   * Set the median time past for locktime validation.
   * This should be the MTP of the previous block (the block we're building on top of).
   *
   * @param mtp - The median time past in Unix timestamp seconds
   */
  setMedianTimePast(mtp: number): void {
    this.medianTimePast = mtp;
  }

  /**
   * Get the current median time past.
   */
  getMedianTimePast(): number {
    return this.medianTimePast;
  }

  /**
   * Build a block template for the given coinbase output script.
   *
   * @param coinbaseScript - The scriptPubKey for the coinbase output (miner's reward address)
   * @param extraNonce - Extra data for the coinbase to expand nonce search space
   * @returns A complete block template ready for mining
   */
  createTemplate(coinbaseScript: Buffer, extraNonce: Buffer = Buffer.alloc(0)): BlockTemplate {
    const bestBlock = this.chainState.getBestBlock();
    const height = bestBlock.height + 1;

    // Select transactions from mempool
    // totalWeight from selectTransactions() is nBlockWeight (starts at BLOCK_RESERVED_WEIGHT,
    // grows with each selected tx). This matches Core's m_last_block_weight semantics.
    const { txs: selectedEntries, totalFees, totalWeight, totalSigOps } = this.selectTransactions();

    // Get the selected transactions
    const transactions = selectedEntries.map(entry => entry.tx);

    // Get next block target
    const target = this.getNextTarget();

    // Build coinbase transaction (needs witness commitment if segwit active)
    const segwitActive = height >= this.params.segwitHeight;

    // Compute witness commitment if segwit is active
    let witnessCommitment: Buffer = Buffer.alloc(32, 0);
    if (segwitActive) {
      // We need the coinbase wtxid as 32 zero bytes for the commitment
      const wtxids: Buffer[] = [Buffer.alloc(32, 0)]; // Coinbase wtxid placeholder
      for (const tx of transactions) {
        wtxids.push(getWTxId(tx));
      }
      const witnessMerkleRoot = computeWitnessMerkleRoot(wtxids);
      // Witness nonce is 32 zero bytes
      const witnessNonce: Buffer = Buffer.alloc(32, 0);
      witnessCommitment = hash256(Buffer.concat([witnessMerkleRoot, witnessNonce]));
    }

    const coinbaseTx = this.buildCoinbase(
      height,
      totalFees,
      coinbaseScript,
      extraNonce,
      segwitActive ? witnessCommitment : Buffer.alloc(0)
    );

    // Compute merkle root with coinbase first
    const allTxs = [coinbaseTx, ...transactions];
    const txids = allTxs.map(tx => getTxId(tx));
    const merkleRoot = computeMerkleRoot(txids);

    // Bug fix 7: block timestamp must be >= MTP+1 (GetMinimumTime in Core miner.cpp:36-47).
    // Core's UpdateTime() does max(GetMinimumTime(pindexPrev,...), now).
    // GetMinimumTime returns max(MTP+1, ...). So: timestamp = max(now, MTP+1).
    // Reference: node/miner.cpp:52-53.
    const nowSecs = Math.floor(Date.now() / 1000);
    const minTime = this.medianTimePast + 1;
    const timestamp = Math.max(nowSecs, minTime);

    // Compute block version using BIP9 state machine when header data is available.
    // Without header data, fall back to VERSIONBITS_TOP_BITS (0x20000000).
    // Bug fix: previously always hardcoded 0x20000000, never signalled for any deployment
    // in STARTED or LOCKED_IN states.
    // Core: versionbits.cpp ComputeBlockVersion (line 265-279).
    let blockVersion = VERSIONBITS_TOP_BITS;
    if (this.getHeaderByHeight && this.deployments && this.deployments.size > 0) {
      const parentEntry = this.getHeaderByHeight(height - 1);
      if (parentEntry) {
        const pindexPrev = buildBlockIndex(parentEntry, this.getHeaderByHeight);
        blockVersion = this.versionBitsCache.computeBlockVersion(pindexPrev, this.deployments);
      }
    }

    // Build block header
    const header: BlockHeader = {
      version: blockVersion,
      prevBlock: bestBlock.hash,
      merkleRoot,
      timestamp,
      bits: bigIntToCompact(target),
      nonce: 0, // Miner will increment this
    };

    // Bug fix 2: totalWeight is already fully accumulated by selectTransactions()
    // (it starts at BLOCK_RESERVED_WEIGHT which covers header+coinbase overhead).
    // Do NOT add headerWeight (320) or coinbaseWeight separately here — that was
    // the old double-counting bug that made blocks appear heavier than maxBlockWeight.
    // The coinbase weight is already accounted for by the BLOCK_RESERVED_WEIGHT reservation.

    return {
      header,
      coinbaseTx,
      transactions,
      totalFees,
      totalWeight,
      totalSigOps,
      height,
      target,
    };
  }

  /**
   * Select transactions from the mempool greedily by fee rate.
   *
   * Respects:
   * - Maximum block weight (nBlockMaxWeight = maxBlockWeight; initial nBlockWeight = BLOCK_RESERVED_WEIGHT)
   * - Maximum sigops cost (initial nBlockSigOpsCost = COINBASE_OUTPUT_MAX_ADDITIONAL_SIGOPS)
   * - Parent-child dependencies (parent must be included before child)
   * - Transaction locktime (must be final at the target block height/time)
   * - MAX_CONSECUTIVE_FAILURES early-exit when block is nearly full
   *
   * Mirrors Core BlockAssembler::addChunks() + TestChunkBlockLimits() in node/miner.cpp.
   */
  private selectTransactions(): { txs: MempoolEntry[]; totalFees: bigint; totalWeight: number; totalSigOps: number } {
    // Bug fix 1+2: weight budget starts at BLOCK_RESERVED_WEIGHT (which already
    // accounts for header + coinbase overhead), not zero. The block header weight
    // (320 WU) is NOT separately subtracted here; it is already baked into
    // BLOCK_RESERVED_WEIGHT. Subtracting it again caused the txWeight budget to
    // be too small AND made totalWeight report more than the actual block weight.
    // Core: resetBlock() sets nBlockWeight = *block_reserved_weight (8000).
    // createTemplate's totalWeight below will be nBlockWeight (which starts at
    // BLOCK_RESERVED_WEIGHT and grows with each selected tx), matching Core exactly.
    const maxBlockWeight = this.params.maxBlockWeight;

    // Bug fix 8: sigops budget starts at COINBASE_OUTPUT_MAX_ADDITIONAL_SIGOPS (400),
    // reserving room for the coinbase's own outputs. Core: resetBlock() sets
    // nBlockSigOpsCost = coinbase_output_max_additional_sigops.
    const maxSigOps = this.params.maxBlockSigOpsCost;

    // Get target block height for locktime validation
    const bestBlock = this.chainState.getBestBlock();
    const targetHeight = bestBlock.height + 1;

    // Get all mempool entries sorted by fee rate (descending)
    const entries = this.mempool.getTransactionsByFeeRate();

    const selected: MempoolEntry[] = [];
    const selectedTxids = new Set<string>();
    let totalFees = 0n;
    // Bug fix 1: start at BLOCK_RESERVED_WEIGHT, not 0. This tracks nBlockWeight.
    let totalWeight = BLOCK_RESERVED_WEIGHT;
    // Bug fix 8: start at reserved coinbase sigops budget.
    let totalSigOps = COINBASE_OUTPUT_MAX_ADDITIONAL_SIGOPS;

    // Track which entries we've processed to avoid re-checking
    const processed = new Set<string>();

    // Track entries that are not final (for skipping)
    const notFinal = new Set<string>();

    // Bug fix 4: track consecutive failures for MAX_CONSECUTIVE_FAILURES early-exit.
    let nConsecutiveFailed = 0;

    // Helper to add an entry and its ancestors
    const addWithAncestors = (entry: MempoolEntry): boolean => {
      const txidHex = entry.txid.toString("hex");

      if (selectedTxids.has(txidHex)) {
        return true; // Already selected
      }

      // Check if this transaction is final
      if (notFinal.has(txidHex)) {
        return false;
      }

      if (!isFinalTx(entry.tx, targetHeight, this.medianTimePast)) {
        notFinal.add(txidHex);
        return false;
      }

      // First, recursively add all ancestors
      for (const parentTxidHex of entry.dependsOn) {
        if (!selectedTxids.has(parentTxidHex)) {
          // Find the parent entry
          const parentTxid = Buffer.from(parentTxidHex, "hex");
          const parentEntry = this.mempool.getTransaction(parentTxid);
          if (!parentEntry) {
            // Parent not in mempool anymore, can't include this tx
            return false;
          }
          if (!addWithAncestors(parentEntry)) {
            return false;
          }
        }
      }

      // Bug fix 3: use >= (not >) to match Core's TestChunkBlockLimits gate:
      //   if (nBlockWeight + chunk_feerate.size >= m_options.nBlockMaxWeight) return false;
      // Reference: node/miner.cpp:241.
      if (totalWeight + entry.weight >= maxBlockWeight) {
        return false;
      }

      // Bug fix 9: use >= for sigops gate, matching Core's TestChunkBlockLimits:
      //   if (nBlockSigOpsCost + chunk_sigops_cost >= MAX_BLOCK_SIGOPS_COST) return false;
      // Reference: node/miner.cpp:244.
      const txSigOpCost = entry.sigOpCost ?? 0;
      if (totalSigOps + txSigOpCost >= maxSigOps) {
        return false;
      }

      selected.push(entry);
      selectedTxids.add(txidHex);
      totalFees += entry.fee;
      totalWeight += entry.weight;
      totalSigOps += txSigOpCost;

      return true;
    };

    // Process entries by fee rate
    for (const entry of entries) {
      const txidHex = entry.txid.toString("hex");

      if (processed.has(txidHex) || selectedTxids.has(txidHex)) {
        continue;
      }

      processed.add(txidHex);

      // Try to add this entry (with its ancestors if needed)
      const added = addWithAncestors(entry);

      if (!added) {
        // Bug fix 4: MAX_CONSECUTIVE_FAILURES early-exit when block is nearly full.
        // Core: addChunks() gives up if nConsecutiveFailed > 1000 AND
        //   nBlockWeight + BLOCK_FULL_ENOUGH_WEIGHT_DELTA > nBlockMaxWeight.
        // Reference: node/miner.cpp:314-317.
        nConsecutiveFailed++;
        if (
          nConsecutiveFailed > MAX_CONSECUTIVE_FAILURES &&
          totalWeight + BLOCK_FULL_ENOUGH_WEIGHT_DELTA > maxBlockWeight
        ) {
          break;
        }
      } else {
        nConsecutiveFailed = 0;
      }
    }

    return { txs: selected, totalFees, totalWeight, totalSigOps };
  }

  /**
   * Build the coinbase transaction.
   *
   * Structure:
   * - Input: prevOut = {txid: 32 zero bytes, vout: 0xFFFFFFFF},
   *          scriptSig = [BIP34 height] + extraNonce,
   *          sequence = MAX_SEQUENCE_NONFINAL (0xFFFFFFFE) — timelock enforced
   * - Output 0: value = subsidy + fees, scriptPubKey = coinbaseScript
   * - Output 1 (if segwit): OP_RETURN witness commitment
   * - Witness (if segwit): 32 zero bytes (witness nonce)
   * - lockTime = height - 1 (BIP34 requirement; enforced because sequence != SEQUENCE_FINAL)
   *
   * Reference: Bitcoin Core node/miner.cpp CreateNewBlock():
   *   coinbaseTx.vin[0].nSequence = CTxIn::MAX_SEQUENCE_NONFINAL  (line 171)
   *   coinbaseTx.nLockTime = static_cast<uint32_t>(nHeight - 1)   (line 196)
   */
  private buildCoinbase(
    height: number,
    fees: bigint,
    coinbaseScript: Buffer,
    extraNonce: Buffer,
    witnessCommitment: Buffer
  ): Transaction {
    // Delegates to the top-level {@link buildCoinbaseTransaction} so the
    // standalone export (used by `generateblock` and other RPC entry points)
    // and this instance method stay byte-identical. Keeps a one-pipeline
    // contract for sequence / lockTime / subsidy / commitment output.
    return buildCoinbaseTransaction(
      height,
      fees,
      this.params,
      coinbaseScript,
      extraNonce,
      witnessCommitment
    );
  }

  /**
   * Compute the witness commitment for the block.
   *
   * commitment = hash256(witness_merkle_root || witness_nonce)
   *
   * The witness merkle root uses wtxids, with the coinbase wtxid as 32 zero bytes.
   */
  private computeWitnessCommitment(txs: Transaction[], coinbaseWtxid: Buffer): Buffer {
    // Build list of wtxids with coinbase as zeros
    const wtxids: Buffer[] = [Buffer.alloc(32, 0)]; // Coinbase wtxid is always zeros
    for (const tx of txs) {
      wtxids.push(getWTxId(tx));
    }

    const witnessMerkleRoot = computeWitnessMerkleRoot(wtxids);

    // Witness nonce is 32 zero bytes
    const witnessNonce = Buffer.alloc(32, 0);

    return hash256(Buffer.concat([witnessMerkleRoot, witnessNonce]));
  }

  /**
   * Calculate the next block's target from the current chain state.
   *
   * This is a simplified version. In production, this would need to
   * properly implement difficulty adjustment based on the last 2016 blocks.
   */
  private getNextTarget(): bigint {
    const bestBlock = this.chainState.getBestBlock();

    // For now, return a simple target based on current chain state
    // A full implementation would calculate difficulty adjustment
    // This would typically come from the HeaderSync module

    // Default to max target (easiest difficulty) for simplicity
    // In production, this should calculate proper difficulty adjustment
    return this.params.powLimit;
  }
}

/**
 * Create a coinbase output script for a P2PKH address.
 * Format: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
 */
export function createP2PKHCoinbaseScript(pubKeyHash: Buffer): Buffer {
  if (pubKeyHash.length !== 20) {
    throw new Error("pubKeyHash must be 20 bytes");
  }
  return Buffer.concat([
    Buffer.from([0x76, 0xa9, 0x14]), // OP_DUP OP_HASH160 PUSH20
    pubKeyHash,
    Buffer.from([0x88, 0xac]), // OP_EQUALVERIFY OP_CHECKSIG
  ]);
}

/**
 * Create a coinbase output script for a P2WPKH address (native segwit).
 * Format: OP_0 <20 bytes>
 */
export function createP2WPKHCoinbaseScript(pubKeyHash: Buffer): Buffer {
  if (pubKeyHash.length !== 20) {
    throw new Error("pubKeyHash must be 20 bytes");
  }
  return Buffer.concat([
    Buffer.from([0x00, 0x14]), // OP_0 PUSH20
    pubKeyHash,
  ]);
}

/**
 * Create a coinbase output script for a P2WSH address.
 * Format: OP_0 <32 bytes>
 */
export function createP2WSHCoinbaseScript(scriptHash: Buffer): Buffer {
  if (scriptHash.length !== 32) {
    throw new Error("scriptHash must be 32 bytes");
  }
  return Buffer.concat([
    Buffer.from([0x00, 0x20]), // OP_0 PUSH32
    scriptHash,
  ]);
}
