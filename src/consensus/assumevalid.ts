/**
 * Assumevalid policy — Bitcoin Core v28.0 compatible ancestor-check semantics.
 *
 * POLICY SUMMARY (Core validation.cpp:2346-2382):
 * Script verification is SKIPPED if and only if ALL five conditions hold:
 *  1. assumed_valid hash is configured (non-zero / non-empty).
 *  2. The assumed-valid block hash IS in the local block-header index.
 *  3. The block being connected is an ancestor of the assumed-valid block on
 *     the ACTIVE chain (ancestor check — NOT a height check):
 *       active_chain.hash_at(pindex.height) == pindex.hash
 *       AND pindex.height <= av_height
 *       AND active_chain.hash_at(av_height)  == av_hash
 *     A fork block at height <= av_height fails this test.
 *  4. best_header.chainWork >= minimum_chain_work (eclipse / eclipse-split defense).
 *  5. GetBlockProofEquivalentTime(best_header, pindex, best_header, params) > 2 weeks
 *     (DoS defense):
 *       equiv_time = (best_header.chainWork − pindex.chainWork)
 *                    × powTargetSpacing / GetBlockProof(best_header.bits)
 *     Uses exact 256-bit chainwork; NOT a float, NOT a timestamp approximation.
 *
 * What assumevalid does NOT skip: PoW, merkle root, coinbase, BIP30, block
 * size/weight, UTXO application — only script/signature verification is skipped.
 *
 * Regtest has no assumevalid; every regtest block verifies every script.
 *
 * IMPLEMENTATION NOTE — IBD path caveat (P2-OPT-ROUND-2):
 * hotbuns's IBD path (BlockSync.connectBlock) does not currently invoke script
 * verification — signature checking only fires via the mempool/RPC path
 * (validateTxInputsAsync / verifyAllInputsParallel). This is an existing gap
 * tracked as open item P2-OPT-ROUND-2 "hotbuns has verifyAllInputsParallel
 * defined but never imported; script verification absent from IBD path".
 *
 * For this implementation, the shouldSkipScripts() decision function is wired
 * into wherever script verification IS called today (validateTxInputsAsync and
 * verifyAllInputsParallel). Once script verification is wired into the IBD path,
 * this assumevalid decision function will fire there automatically since it is
 * the canonical gate.
 */

/** Two weeks in seconds — the equivalent-work delay safety guard. */
const TWO_WEEKS_IN_SECONDS_BIGINT = 1_209_600n; // 60 * 60 * 24 * 14

/**
 * Fleet-standard assumevalid hashes from Bitcoin Core v28.0.
 * Source: git show v28.0:src/kernel/chainparams.cpp
 *
 * All values are in internal byte order (little-endian, as stored in the
 * block index). These match the wire-format reversed hashes exactly.
 *
 * Regtest has NO assumevalid hash — every script is verified on regtest.
 * This is intentional for test determinism.
 */
export const ASSUMED_VALID_HASHES = {
  /** Mainnet: block 938343 */
  mainnet: "00000000000000000000ccebd6d74d9194d8dcdc1d177c478e094bfad51ba5ac",
  /** Testnet3: block 4842348 (Core CTestNetParams) */
  testnet3: "000000007a61e4230b28ac5cb6b5e5a0130de37ac1faf2f8987d2fa6505b67f4",
  /** Testnet4: block 123613 (Core CTestNet4Params) */
  testnet4: "0000000002368b1e4ee27e2e85676ae6f9f9e69579b29093e9a82c170bf7cf8a",
  /** Signet: block 293175 */
  signet: "00000008414aab61092ef93f1aacc54cf9e9f16af29ddad493b908a01ff5c329",
} as const;

/**
 * Block index entry interface for assumevalid decisions.
 *
 * This is intentionally minimal — only the fields needed for the 6-condition
 * check. It is compatible with HeaderChainEntry from headers.ts.
 */
export interface AssumeValidBlockEntry {
  /** Block hash (hex string) */
  readonly hash: string;
  /** Block height */
  readonly height: number;
  /** Cumulative chain work */
  readonly chainWork: bigint;
}

/**
 * Context passed to shouldSkipScripts for the 5-condition evaluation.
 */
export interface AssumeValidContext {
  /**
   * The block being connected (pindex in Bitcoin Core parlance).
   * Needs: hash (hex), height, chainWork.
   */
  pindex: AssumeValidBlockEntry;

  /**
   * The assumevalid hash configured for this network (hex string).
   * Absent / undefined / empty means "no assumevalid" — verify everything.
   */
  assumedValidHash: string | undefined;

  /**
   * Callback to look up a block index entry by its hash (hex).
   * Returns null if the hash is not in the local header index.
   *
   * Implements condition 2: "the assumed-valid block is in the local block index".
   */
  getBlockByHash: (hashHex: string) => AssumeValidBlockEntry | null;

  /**
   * Callback to look up the active-chain (best-header-chain) block at a given height.
   * Returns null if no block/header is known at that height.
   *
   * Used for condition 3:
   *   getBlockAtHeight(pindex.height).hash === pindex.hash  (pindex on active chain)
   *   getBlockAtHeight(av_height).hash    === av_hash       (av block on active chain)
   */
  getBlockAtHeight: (height: number) => AssumeValidBlockEntry | null;

  /**
   * The best known header (most chainwork).
   * Used for conditions 4 and 5.
   */
  bestHeader: AssumeValidBlockEntry | null;

  /**
   * Minimum chain work required for the network (condition 4).
   */
  minimumChainWork: bigint;

  /**
   * Compact nBits encoding of the best known header.
   *
   * Used for condition 5 (DoS defense): GetBlockProofEquivalentTime requires
   * GetBlockProof(best_header) = 2^256 / (target+1) where target is decoded
   * from bestHeaderBits.  This is the "tip" parameter in Core's
   * GetBlockProofEquivalentTime(bestHeader, pindex, bestHeader, params).
   *
   * Sourced from headerSync.getBestHeader().header.bits in blocks.ts.
   */
  bestHeaderBits: number;

  /**
   * Proof-of-work target spacing in seconds (nPowTargetSpacing).
   *
   * Bitcoin mainnet: 600 s (10 minutes).  Used in condition 5:
   *   equiv_time = workDiff * powTargetSpacing / GetBlockProof(bestHeaderBits)
   * Sourced from params.targetSpacing.
   */
  powTargetSpacing: number;
}

/**
 * Compute block proof from compact bits encoding.
 *
 * Mirrors Bitcoin Core GetBitsProof (src/chain.cpp:121-134).
 * Returns 2^256 / (target + 1) using the identity
 *   (~target / (target+1)) + 1 = 2^256 / (target+1).
 * Returns 0n for zero, negative, or overflow targets.
 */
function getBitsProof(bits: number): bigint {
  const exponent = bits >>> 24;
  const isNegative = (bits & 0x800000) !== 0;
  const mantissa = bits & 0x7fffff;

  let target: bigint;
  if (exponent <= 3) {
    target = BigInt(mantissa) >> BigInt(8 * (3 - exponent));
  } else {
    target = BigInt(mantissa) << BigInt(8 * (exponent - 3));
  }

  if (isNegative && target !== 0n) return 0n;
  if (target === 0n) return 0n;

  // 2^256 / (target + 1)
  return (1n << 256n) / (target + 1n);
}

/**
 * Compute equivalent time between bestHeader and pindex.
 *
 * Mirrors Bitcoin Core GetBlockProofEquivalentTime (src/chain.cpp:136-151)
 * called as:
 *   GetBlockProofEquivalentTime(bestHeader, pindex, bestHeader, params)
 *
 * Formula:
 *   r = (bestHeader.chainWork − pindex.chainWork) × powTargetSpacing
 *       / GetBlockProof(bestHeader.bits)
 *
 * Returns 0n if bestHeaderChainWork ≤ pindexChainWork or if bestHeaderBits
 * decodes to a zero/overflow target (neither should occur under normal operation).
 * Returns INT64_MAX (9_223_372_036_854_775_807n) if the result would overflow
 * int64, mirroring Core's r.bits() > 63 guard.
 */
function getBlockProofEquivalentTime(
  bestHeaderChainWork: bigint,
  pindexChainWork: bigint,
  bestHeaderBits: number,
  powTargetSpacing: number,
): bigint {
  if (bestHeaderChainWork <= pindexChainWork) return 0n;
  const tipProof = getBitsProof(bestHeaderBits);
  if (tipProof === 0n) return 0n;
  const r =
    ((bestHeaderChainWork - pindexChainWork) * BigInt(powTargetSpacing)) /
    tipProof;
  // Mirror Core: if r.bits() > 63 → return INT64_MAX
  const INT64_MAX = 9_223_372_036_854_775_807n;
  return r > INT64_MAX ? INT64_MAX : r;
}

/**
 * Result of the shouldSkipScripts decision with a reason for logging.
 */
export interface SkipScriptsResult {
  /** True = skip script verification for this block. */
  skip: boolean;
  /** Human-readable reason (mirrors Bitcoin Core's script_check_reason). */
  reason: string;
}

/**
 * Decide whether to skip script verification for the block being connected.
 *
 * This is the canonical assumevalid gate. It must be called at every point
 * where script verification would be invoked. Currently in hotbuns that is:
 *  - validateTxInputsAsync (mempool/RPC path)
 *  - verifyAllInputsParallel (exported utility, wired via the above)
 *
 * Once script verification is added to the IBD path (P2-OPT-ROUND-2), this
 * function will fire there automatically — no changes needed here.
 *
 * @returns SkipScriptsResult with skip=true iff ALL five conditions hold.
 */
export function shouldSkipScripts(ctx: AssumeValidContext): SkipScriptsResult {
  // Condition 1: assumedValid hash must be configured (non-null/empty).
  // Core: m_chainman.AssumedValidBlock().IsNull()
  if (!ctx.assumedValidHash) {
    return { skip: false, reason: "assumevalid=0 (always verify)" };
  }

  // Condition 2: The assumed-valid block must be in the local header index.
  // Core: it == m_blockman.m_block_index.end()
  const assumedValidEntry = ctx.getBlockByHash(ctx.assumedValidHash);
  if (!assumedValidEntry) {
    return { skip: false, reason: "assumevalid hash not in headers" };
  }

  // Condition 3: The block being connected must be an ancestor of the
  // assumed-valid block on the ACTIVE chain.
  //
  // Core checks two things (validation.cpp:2358-2361):
  //   (a) it->second.GetAncestor(pindex->nHeight) == pindex
  //       — pindex is on AV's chain
  //   (b) m_chainman.m_best_header->GetAncestor(pindex->nHeight) == pindex
  //       — pindex is also on the best-header chain
  //
  // In hotbuns, getBlockAtHeight(h) returns the active/best-header-chain
  // block at height h. We check:
  //   (a) active_chain.hash_at(pindex.height) == pindex.hash
  //       — pindex is on the active chain (covers Core's check (b))
  //   (b) pindex.height <= av_height
  //       — pindex is not above AV
  //   (c) active_chain.hash_at(av_height) == av_hash
  //       — AV itself is on the active chain (ensures (a) implies ancestorship)
  //
  // A fork block at height <= av_height fails check (a) because the active
  // chain at that height has a DIFFERENT hash.
  if (ctx.pindex.height > assumedValidEntry.height) {
    return { skip: false, reason: "block height above assumevalid height" };
  }

  const ancestorAtPindexHeight = ctx.getBlockAtHeight(ctx.pindex.height);
  if (!ancestorAtPindexHeight || ancestorAtPindexHeight.hash !== ctx.pindex.hash) {
    return { skip: false, reason: "block not in assumevalid chain" };
  }

  // Check that AV is itself on the active chain (condition 3c above).
  // Without this check a stale AV entry from a discarded fork could cause
  // an active-chain block to skip scripts incorrectly.
  const avAtItsHeight = ctx.getBlockAtHeight(assumedValidEntry.height);
  if (!avAtItsHeight || avAtItsHeight.hash !== ctx.assumedValidHash) {
    return { skip: false, reason: "assumevalid block not on active chain" };
  }

  // Conditions 4 and 5 require a valid best header.
  if (!ctx.bestHeader) {
    return { skip: false, reason: "no best header available" };
  }

  // Condition 4: Best-known-header chainwork >= minimum chainwork (eclipse defense).
  // Core: m_chainman.m_best_header->nChainWork < m_chainman.MinimumChainWork()
  if (ctx.bestHeader.chainWork < ctx.minimumChainWork) {
    return { skip: false, reason: "best header chainwork below minimumchainwork" };
  }

  // Condition 5: Equivalent work time from pindex to best header > 2 weeks (DoS defense).
  //
  // Core (validation.cpp:2364):
  //   GetBlockProofEquivalentTime(bestHeader, pindex, bestHeader, params) > TWO_WEEKS
  //
  // Formula (chain.cpp:136-151):
  //   equiv_time = (bestHeader.chainWork − pindex.chainWork)
  //                × nPowTargetSpacing / GetBlockProof(bestHeader.nBits)
  //
  // We use exact 256-bit BigInt chainwork — no float, no timestamp approximation.
  // The DoS defense: if a chain of ~two weeks of PoW cannot be shown, verify scripts.
  const equivTime = getBlockProofEquivalentTime(
    ctx.bestHeader.chainWork,
    ctx.pindex.chainWork,
    ctx.bestHeaderBits,
    ctx.powTargetSpacing,
  );
  if (equivTime <= TWO_WEEKS_IN_SECONDS_BIGINT) {
    return { skip: false, reason: "block too recent relative to best header" };
  }

  // All five conditions satisfied: skip script verification.
  return {
    skip: true,
    reason:
      "block is ancestor of assumevalid and all safety conditions met — SKIP scripts",
  };
}
