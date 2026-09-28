/**
 * Startup reconcile of the block index's nTx field against this node's OWN
 * state (R3: no answer is borrowed from another node).
 *
 * Why this exists: until 2026-09-28 a startup migration (`migrateNTxBackfill`,
 * cli.ts) read the live Bitcoin Core's cookie and WROTE Core's `nTx` into
 * hotbuns' block index for every entry whose body hotbuns did not hold. The
 * live mainnet log records 1,066 + a handful of such writes. Those values are
 * indistinguishable from locally-derived ones after the fact, so this pass
 * re-derives every entry it cannot vouch for.
 *
 * Core semantics (chain.h CBlockIndex::nTx; validation.cpp:3768
 * ReceivedBlockTransactions sets it when the block's transactions are
 * received; CheckBlockIndex 5240-5257): nTx > 0 iff the block's transactions
 * were received and validated by THIS node ("VALID_TRANSACTIONS is equivalent
 * to nTx > 0 ... whether or not pruning has occurred"). A header-only entry,
 * and an assumeutxo snapshot base (validation.cpp:5949 seeds only
 * m_chain_tx_count), has nTx = 0.
 *
 * Per entry:
 *  - body held locally            -> nTx = tx count read from the body.
 *  - no body, validated by this node's own connect path (TXS_VALID set by a
 *    connect writer, i.e. not a snapshot-base-shaped entry)
 *                                 -> kept. hotbuns keeps bodies only inside
 *    the reorg-retention window, so this is the pruned-block case, where Core
 *    too retains nTx. (The count is a property of the validated block itself.)
 *  - no body, not validated here  -> 0 (Core: block data not available).
 *
 * Idempotent (a second run changes nothing), never fatal, one log line.
 */
import { BlockStatus, type ChainDB } from "./database.js";
import { BufferReader } from "../wire/serialization.js";

export interface NTxReconcileResult {
  scanned: number;
  /** nTx>0 kept without a body: validated by this node, body not retained. */
  keptValidated: number;
  /** Entries whose nTx was checked against a locally held body. */
  recounted: number;
  /** ...of which the stored value differed and was rewritten. */
  corrected: number;
  /** nTx was 0 but the body is held: filled from the body. */
  filled: number;
  /** nTx>0, no local body, not validated here: reset to 0. */
  reset: number;
  /** Bodies that could not be parsed (value left as is). */
  unreadable: number;
}

/** Tx count of a serialized block: the CompactSize right after the header. */
export function txCountFromRawBlock(raw: Buffer): number {
  if (raw.length < 81) throw new Error("block body shorter than header+count");
  return new BufferReader(raw.subarray(80)).readVarInt();
}

/**
 * True for an entry whose TXS_VALID bit was NOT earned by connecting the block
 * here: an assumeutxo snapshot base. The snapshot loaders write
 * HEADER_VALID|TXS_VALID|HAVE_DATA with dataPos 0 and no body; every connect
 * writer also sets TXS_KNOWN (sync/blocks.ts) or HAVE_UNDO (chain/state.ts).
 */
function isSnapshotBaseShaped(
  hashHex: string,
  status: number,
  height: number,
  assumeutxoBases: ReadonlySet<string>,
): boolean {
  if (assumeutxoBases.has(hashHex)) return true;
  if (height === 0) return false;
  return (
    (status & BlockStatus.TXS_VALID) !== 0 &&
    (status & BlockStatus.TXS_KNOWN) === 0 &&
    (status & BlockStatus.HAVE_UNDO) === 0
  );
}

export async function reconcileNTxProvenance(
  db: ChainDB,
  assumeutxoBases: ReadonlySet<string> = new Set(),
): Promise<NTxReconcileResult> {
  const r: NTxReconcileResult = {
    scanned: 0, keptValidated: 0, recounted: 0, corrected: 0,
    filled: 0, reset: 0, unreadable: 0,
  };
  // Classify while iterating (no writes with the iterator open); only the
  // entries that need a body lookup are kept in memory.
  const writes: Array<[Buffer, number]> = [];
  const lookups: Array<[Buffer, number, boolean]> = [];
  for await (const [hash, rec] of db.iterateBlockIndexEntries()) {
    r.scanned++;
    const validatedHere =
      (rec.status & BlockStatus.TXS_VALID) !== 0 &&
      !isSnapshotBaseShaped(hash.toString("hex"), rec.status, rec.height, assumeutxoBases);
    // A validated entry without HAVE_DATA has no retained body: keep it
    // without a lookup (this is almost the whole connected chain).
    if (rec.nTx > 0 && validatedHere && (rec.status & BlockStatus.HAVE_DATA) === 0) {
      r.keptValidated++;
      continue;
    }
    lookups.push([hash, rec.nTx, validatedHere]);
  }
  for (const [hash, nTx, validatedHere] of lookups) {
    if (!(await db.hasBlock(hash))) {
      if (nTx > 0) {
        if (validatedHere) {
          r.keptValidated++;
        } else {
          writes.push([hash, 0]);
          r.reset++;
        }
      }
      continue;
    }
    const raw = await db.getBlock(hash);
    if (raw === null) continue;
    let count: number;
    try {
      count = txCountFromRawBlock(raw);
    } catch {
      r.unreadable++;
      continue;
    }
    if (count <= 0) {
      r.unreadable++;
      continue;
    }
    if (nTx === 0) {
      writes.push([hash, count]);
      r.filled++;
    } else {
      r.recounted++;
      if (nTx !== count) {
        writes.push([hash, count]);
        r.corrected++;
      }
    }
  }
  for (const [hash, n] of writes) {
    await db.setBlockIndexNTx(hash, n);
  }
  return r;
}
