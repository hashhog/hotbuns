/**
 * Does this node lack the block bodies below a UTXO snapshot base?
 *
 * A node started from an assumeutxo snapshot (`--load-snapshot` or the
 * `loadtxoutset` RPC) never downloads the bodies of blocks at or below the
 * snapshot base: hotbuns has no background download of that history. Bitcoin
 * Core in the same state:
 *   - clears NODE_NETWORK and keeps NODE_NETWORK_LIMITED in its local services
 *     (rpc/blockchain.cpp loadtxoutset: RemoveLocalServices(NODE_NETWORK);
 *     init.cpp: NODE_NETWORK only when there is no unfinished historical
 *     chainstate, so it stays off across a restart, and comes back when the
 *     background download completes and the node is not pruning);
 *   - reports the snapshot chainstate in getchainstates with
 *     snapshot_blockhash and validated:false.
 *
 * The snapshot base is recorded in the MARKER keyspace when a snapshot is
 * loaded. Datadirs loaded before that record existed are recognised from what
 * the loader left behind: a known assumeutxo base on the active chain with
 * nTx 0, no body, and none of the status bits a block connected from its
 * parent gets (TXS_KNOWN / HAVE_UNDO).
 */
import { BlockStatus, type ChainDB } from "../storage/database.js";
import type { ConsensusParams } from "../consensus/params.js";

export const SNAPSHOT_ORIGIN_MARKER = "snapshot_origin_v1";

/** NODE_NETWORK (Core protocol.h). Kept local to avoid a chain->p2p import. */
const NODE_NETWORK = 1n;

export interface SnapshotOrigin {
  /** Snapshot base block hash, internal byte order. */
  baseHash: Buffer;
  baseHeight: number;
}

/** Anything that owns the node's local service bits (PeerManager). */
export interface LocalServicesOwner {
  removeLocalServices(bits: bigint): void;
  addLocalServices(bits: bigint): void;
}

/** Record that this datadir's chainstate was started from a snapshot. */
export async function recordSnapshotOrigin(
  db: ChainDB,
  baseHash: Buffer,
  baseHeight: number,
): Promise<void> {
  const rec = Buffer.alloc(36);
  Buffer.from(baseHash).copy(rec, 0, 0, 32);
  rec.writeUInt32LE(baseHeight >>> 0, 32);
  await db.putMarker(SNAPSHOT_ORIGIN_MARKER, rec);
}

/**
 * The snapshot this datadir was started from, or null for a node that
 * connected its chain from genesis.
 */
export async function readSnapshotOrigin(
  db: ChainDB,
  params: ConsensusParams,
): Promise<SnapshotOrigin | null> {
  const rec = await db.getMarker(SNAPSHOT_ORIGIN_MARKER);
  if (rec !== null && rec.length >= 36) {
    return { baseHash: Buffer.from(rec.subarray(0, 32)), baseHeight: rec.readUInt32LE(32) };
  }
  if (!params.assumeutxo) return null;
  for (const au of params.assumeutxo.values()) {
    const onChain = await db.getBlockHashByHeight(au.height);
    if (!onChain || !onChain.equals(au.blockHash)) continue;
    const idx = await db.getBlockIndex(au.blockHash);
    if (!idx || idx.nTx !== 0) continue;
    if ((idx.status & (BlockStatus.TXS_KNOWN | BlockStatus.HAVE_UNDO)) !== 0) continue;
    if (await db.hasBlock(au.blockHash)) continue;
    return { baseHash: Buffer.from(au.blockHash), baseHeight: au.height };
  }
  return null;
}

/**
 * True while the node cannot serve the history below its snapshot base: the
 * base body or the height-1 body is missing. hotbuns never backfills those, so
 * for a snapshot-started node this stays true unless every body was already
 * present when the snapshot was loaded (the loadtxoutset case Core's
 * background validation completes).
 */
export async function isHistoryIncomplete(db: ChainDB, origin: SnapshotOrigin): Promise<boolean> {
  if (!(await db.hasBlock(origin.baseHash))) return true;
  if (origin.baseHeight <= 1) return false;
  const first = await db.getBlockHashByHeight(1);
  return !first || !(await db.hasBlock(first));
}

/** The snapshot origin, only while its history is still missing. */
export async function snapshotOriginWithoutHistory(
  db: ChainDB,
  params: ConsensusParams,
): Promise<SnapshotOrigin | null> {
  const origin = await readSnapshotOrigin(db, params);
  if (!origin) return null;
  return (await isHistoryIncomplete(db, origin)) ? origin : null;
}

/**
 * Boot-time service bits: clear NODE_NETWORK while the history below the
 * snapshot base is missing (Core init.cpp). Returns the origin it acted on.
 */
export async function applySnapshotHistoryServices(
  db: ChainDB,
  params: ConsensusParams,
  services: LocalServicesOwner,
): Promise<SnapshotOrigin | null> {
  const origin = await snapshotOriginWithoutHistory(db, params);
  if (origin) services.removeLocalServices(NODE_NETWORK);
  return origin;
}
