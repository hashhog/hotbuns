/**
 * Accept one block read from an external block file (`--import-blocks`).
 *
 * Bitcoin Core: ChainstateManager::LoadExternalBlockFile (validation.cpp)
 * hands every block to AcceptBlock (AcceptBlockHeader -> CheckBlockHeader /
 * ContextualCheckBlockHeader, then CheckBlock + ContextualCheckBlock) and
 * only then lets ActivateBestChain connect it. A block from a file is no more
 * trusted than one from a peer.
 *
 * ChainStateManager.connectBlock takes an already-validated block and runs
 * only ConnectBlock's UTXO / script / coinbase-value checks, so the importer
 * must run the header and CheckBlock stages itself, in Core's order:
 *
 *   1. the block extends the active tip (an import connects in order);
 *   2. AcceptBlockHeader: HeaderSync.validateHeader (bad-diffbits, time,
 *      version, high-hash, checkpoints) and the header enters the index;
 *   3. CheckBlock + ContextualCheckBlock: validateBlock (merkle root and
 *      mutation, coinbase, size/weight, BIP34, witness commitment,
 *      CheckTransaction) at the height the header index gives it;
 *   4. ConnectBlock: ChainStateManager.connectBlock.
 *
 * min_pow_checked is true, as LoadExternalBlockFile passes it: the operator
 * chose the file, so the anti-DoS low-work header gate does not apply (an
 * import from genesis would otherwise be refused below nMinimumChainWork).
 *
 * A block whose body fails is not marked invalid in the header index: a
 * corrupted body (bad merkle root) has the same hash as the real block, and
 * Core does not mark a mutated block failed either. The importer stops at the
 * first failure and the tip stays where it was.
 */

import type { Block } from "../validation/block.js";
import { getBlockHash, validateBlock } from "../validation/block.js";
import type { ConsensusParams } from "../consensus/params.js";
import type { HeaderSync } from "../sync/headers.js";
import type { ChainStateManager } from "./state.js";

export type ImportBlockResult =
  | { ok: true; height: number }
  | { ok: false; reason: string };

/**
 * @param claimedHeight height the input format claims for the block (the
 *   stdin frame header), or null when the format carries none (blk*.dat).
 *   A claim that disagrees with the header index is refused.
 */
export async function acceptImportedBlock(
  block: Block,
  claimedHeight: number | null,
  headerSync: HeaderSync,
  chainState: ChainStateManager,
  params: ConsensusParams
): Promise<ImportBlockResult> {
  const hash = getBlockHash(block.header);
  const tip = chainState.getBestBlock();

  // 1. Connect in order: the block's parent must be the active tip.
  if (!block.header.prevBlock.equals(tip.hash)) {
    return {
      ok: false,
      reason: `prev-blk-not-tip: parent ${Buffer.from(block.header.prevBlock).reverse().toString("hex")} is not the active tip`,
    };
  }

  // 2. AcceptBlockHeader.
  let entry = headerSync.getHeader(hash);
  if (entry && entry.status === "invalid") {
    return { ok: false, reason: "duplicate-invalid" };
  }
  if (!entry) {
    const parent = headerSync.getHeader(block.header.prevBlock);
    if (!parent) {
      return { ok: false, reason: "prev-blk-not-found: active tip missing from the header index" };
    }
    if (parent.status === "invalid") {
      return { ok: false, reason: "bad-prevblk" };
    }
    const hv = headerSync.validateHeader(block.header, parent);
    if (!hv.valid) {
      return { ok: false, reason: hv.error ?? "invalid header" };
    }
    await headerSync.processHeaders([block.header], null, true);
    entry = headerSync.getHeader(hash);
    if (!entry) {
      return { ok: false, reason: "header not accepted into the header index" };
    }
  }

  const height = entry.height;
  if (height !== tip.height + 1) {
    return { ok: false, reason: `header index height ${height} does not extend tip ${tip.height}` };
  }
  if (claimedHeight !== null && claimedHeight !== height) {
    return {
      ok: false,
      reason: `height mismatch: input claims height ${claimedHeight}, header index has ${height}`,
    };
  }

  // 3. CheckBlock + ContextualCheckBlock.
  const bv = validateBlock(block, height, params);
  if (!bv.valid) {
    return { ok: false, reason: bv.error ?? "invalid block" };
  }

  // 4. ConnectBlock.
  try {
    await chainState.connectBlock(block, height);
  } catch (e) {
    return { ok: false, reason: e instanceof Error ? e.message : String(e) };
  }
  return { ok: true, height };
}
