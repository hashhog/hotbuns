/**
 * BIP-157 compact block filter P2P handlers.
 *
 * Implements three incoming-message arms:
 *   - getcfilters  → 0 .. N cfilter responses
 *   - getcfheaders → 1 cfheaders response
 *   - getcfcheckpt → 1 cfcheckpt response
 *
 * Mirrors Bitcoin Core's PeerManagerImpl in
 * bitcoin-core/src/net_processing.cpp:
 *   - PrepareBlockFilterRequest (lines 3262-3313): shared validation.
 *   - ProcessGetCFilters         (lines 3315-3342)
 *   - ProcessGetCFHeaders        (lines 3344-3384)
 *   - ProcessGetCFCheckPt        (lines 3386-3422)
 *
 * Wire layout / constants:
 *   - MAX_GETCFILTERS_SIZE   = 1000 (Core net_processing.cpp:184)
 *   - MAX_GETCFHEADERS_SIZE  = 2000 (Core net_processing.cpp:186)
 *   - CFCHECKPT_INTERVAL     = 1000 (Core blockfilterindex.h:31)
 *   - NODE_COMPACT_FILTERS   = 1<<6 (Core protocol.h:323)
 *
 * Validation invariants (all five trigger peer.misbehaving(100) +
 * disconnect, matching Core node.fDisconnect = true):
 *   1. filter_type != BASIC (0)            → unsupported
 *   2. NODE_COMPACT_FILTERS not advertised → unsupported
 *   3. stop_hash not in our chain          → invalid hash
 *   4. start_height > stop_height          → invalid range
 *   5. stop_height - start_height + 1 > max → too many requested
 *
 * Stop-hash anchor pattern: when serving cfilters/cfheaders, walk the
 * peer's stop_hash backward via getBlockHashByHeight (the active chain
 * oracle) — same shape as the REST handler in src/rpc/rest.ts:1063-1086.
 * Hotbuns uses height-keyed walk against the active chain rather than
 * GetAncestor(h) because the height→hash DB index IS the active chain
 * snapshot; stale-fork stop_hash queries fall out because the lookup at
 * the peer's stop_hash will fail entirely (block index miss → reject) or
 * succeed only if the peer's stop_hash matches the active chain at that
 * height. Mirrors FIX-74 (blockbrew) + FIX-79 (ouroboros) + FIX-84
 * (clearbit) — the canonical fleet pattern.
 *
 * Defensive return-on-miss: when prev_filter_header or any per-height
 * filter is missing from the index (e.g. backfill still in progress),
 * we return without sending a partial response. Mirrors Core's
 * `if (!filter_index->LookupFilterHashRange(...)) return;` (lines
 * 3334, 3365, 3373) and the FIX-79 ouroboros early-return pattern.
 */

import type { Peer } from "./peer.js";
import {
  type GetCFiltersPayload,
  type GetCFHeadersPayload,
  type GetCFCheckPtPayload,
  MAX_GETCFILTERS_SIZE,
  MAX_GETCFHEADERS_SIZE,
  CFCHECKPT_INTERVAL,
  NODE_COMPACT_FILTERS_BIT,
} from "./messages.js";
import {
  GCSFilter,
  computeFilterHeader,
  type BlockFilterIndex,
} from "../storage/indexes.js";
import type { ChainDB } from "../storage/database.js";

/**
 * Filter type byte for "basic" filters per BIP-157
 * (Core BlockFilterType::BASIC = 0).  Hotbuns ships only this type
 * — anything else MUST be rejected.
 */
export const FILTER_TYPE_BASIC = 0;

/**
 * Shared dependencies for the three BIP-157 handlers.
 */
export interface CFilterHandlerDeps {
  /** Block index lookup (height ↔ hash on the active chain). */
  db: Pick<ChainDB, "getBlockIndex" | "getBlockHashByHeight">;
  /** BIP-157/158 filter index (may be undefined if --blockfilterindex=0). */
  filterIndex: BlockFilterIndex | undefined;
  /**
   * Our advertised services bitmask.  When NODE_COMPACT_FILTERS is NOT
   * set, every incoming getcf* message is misbehavior — Core gates
   * service via `peer.m_our_services & NODE_COMPACT_FILTERS`.
   * Sourced from `peerManager.getAdvertisedServices()` so the same
   * value drives version-handshake + cf-handler gating.
   */
  ourServices: bigint;
}

/**
 * Outcome of PrepareBlockFilterRequest: either disconnect (and the peer
 * handler caller should return early) or proceed with the validated
 * `stopBlockIndex` (height + hash on the active chain).
 */
type PrepareResult =
  | { ok: false }
  | { ok: true; stopHeight: number; stopHash: Buffer };

/**
 * Shared validation for all three BIP-157 incoming-message handlers.
 *
 * Mirrors Core's PrepareBlockFilterRequest (net_processing.cpp:3262).
 * Returns { ok: false } when validation fails AND the peer has been
 * disconnected; returns { ok: true, stopHeight, stopHash } when the
 * request is well-formed.
 *
 * NOTE: this is the single source-of-truth for the five validation
 * invariants — every getcf* handler funnels through here.  Adding a
 * sixth rule (e.g. -peerblockfilters operator gate) goes here, not in
 * the per-handler bodies.
 */
async function prepareBlockFilterRequest(
  peer: Peer,
  deps: CFilterHandlerDeps,
  filterType: number,
  startHeight: number,
  stopHash: Buffer,
  maxHeightDiff: number
): Promise<PrepareResult> {
  // Rule 1: filter_type must be BASIC (0).
  // Rule 2: we must have advertised NODE_COMPACT_FILTERS.
  // Core combines these into one check (m_our_services & NODE_COMPACT_FILTERS
  // implies BASIC is supported); hotbuns splits for clarity so the log
  // distinguishes "operator disabled the index" from "peer asked for an
  // unknown filter type".
  const supportsBasic =
    filterType === FILTER_TYPE_BASIC &&
    (deps.ourServices & NODE_COMPACT_FILTERS_BIT) !== 0n;
  if (!supportsBasic) {
    peer.misbehaving(
      100,
      `getcf*: unsupported filter type ${filterType} (NODE_COMPACT_FILTERS not advertised or type not BASIC)`
    );
    return { ok: false };
  }

  // Rule 3: stop_hash must be a block known to our chain.
  const stopBlockIndex = await deps.db.getBlockIndex(stopHash);
  if (!stopBlockIndex) {
    peer.misbehaving(
      100,
      `getcf*: peer requested invalid stop_hash ${stopHash
        .toString("hex")
        .slice(0, 16)} (block not found)`
    );
    return { ok: false };
  }

  const stopHeight = stopBlockIndex.height;

  // Rule 4: start_height must not exceed stop_height (uint32 compare).
  // start_height in the wire payload is uint32 LE; negative is impossible
  // post-deserialize.  Defensive >= 0 anyway.
  if (startHeight > stopHeight || startHeight < 0) {
    peer.misbehaving(
      100,
      `getcf*: peer sent invalid range start=${startHeight} > stop=${stopHeight}`
    );
    return { ok: false };
  }

  // Rule 5: the requested range must not exceed the per-message cap.
  // Core uses `stop_height - start_height >= max_height_diff` (strict
  // inequality on the COUNT-MINUS-ONE form) — we mirror exactly.
  // Equivalent to "count <= max" where count = stop - start + 1.
  if (stopHeight - startHeight >= maxHeightDiff) {
    peer.misbehaving(
      100,
      `getcf*: peer requested too many cf entries: ` +
        `${stopHeight - startHeight + 1} > ${maxHeightDiff}`
    );
    return { ok: false };
  }

  // Filter-index presence is a node-side configuration concern, not a
  // misbehavior. Core checks `if (!filter_index) return;` here without
  // disconnect — we mirror the same shape: silent return when the
  // operator did not enable --blockfilterindex (we already advertised
  // NODE_COMPACT_FILTERS, so the peer's expectation is reasonable;
  // disconnecting them would punish a peer for our config change).
  if (!deps.filterIndex || !deps.filterIndex.isEnabled()) {
    return { ok: false };
  }

  return { ok: true, stopHeight, stopHash };
}

/**
 * Handle an incoming `getcfilters` message.
 *
 * Mirrors ProcessGetCFilters (net_processing.cpp:3315).  Sends 0..N
 * `cfilter` messages, one per block in [start_height, stop_height]
 * along the active chain.
 *
 * On any validation failure the handler returns silently after the
 * shared `prepareBlockFilterRequest` has already disconnected the
 * peer.  On index-miss the handler returns without sending a partial
 * series — matches Core's `if (!filter_index->LookupFilterRange(...))
 * return;` shape.
 */
export async function processGetCFilters(
  peer: Peer,
  payload: GetCFiltersPayload,
  deps: CFilterHandlerDeps,
  sendCFilter: (peer: Peer, response: {
    filterType: number;
    blockHash: Buffer;
    filterBytes: Buffer;
  }) => void
): Promise<void> {
  const prepared = await prepareBlockFilterRequest(
    peer,
    deps,
    payload.filterType,
    payload.startHeight,
    payload.stopHash,
    MAX_GETCFILTERS_SIZE
  );
  if (!prepared.ok) return;

  // Defensive: prepareBlockFilterRequest already returns ok=false on
  // missing index, so this branch is unreachable; keeping the assert
  // for type-narrowing.
  if (!deps.filterIndex) return;

  // Walk the active chain forward from start_height to stop_height,
  // looking up the filter at each height. Same pattern as the REST
  // handler in src/rpc/rest.ts handleBlockFilterHeaders.
  const filters: Array<{ blockHash: Buffer; filterBytes: Buffer }> = [];
  for (let h = payload.startHeight; h <= prepared.stopHeight; h++) {
    const hash = await deps.db.getBlockHashByHeight(h);
    if (!hash) {
      // Active chain missing at this height — should be impossible inside
      // [0, stopHeight] when stopHash was successfully resolved to
      // stopHeight, but treat defensively.
      return;
    }
    const filterBytes = await deps.filterIndex.getFilter(hash);
    if (!filterBytes) {
      // Index lag / backfill in progress — Core returns silently in this
      // case (line 3334-3336). Don't send a partial series.
      return;
    }
    filters.push({ blockHash: hash, filterBytes });
  }

  // Emit one cfilter message per block. Core uses MakeAndPushMessage in
  // a loop (line 3339-3341).
  for (const { blockHash, filterBytes } of filters) {
    sendCFilter(peer, {
      filterType: payload.filterType,
      blockHash,
      filterBytes,
    });
  }
}

/**
 * Handle an incoming `getcfheaders` message.
 *
 * Mirrors ProcessGetCFHeaders (net_processing.cpp:3344).  Sends one
 * `cfheaders` response containing all filter hashes for blocks
 * [start_height, stop_height] plus the filter header for the block
 * at (start_height - 1) as `previous_filter_header`.
 *
 * Index-miss behavior: defensive return-on-miss for prev_filter_header
 * (the FIX-79 ouroboros pattern) — we never send a cfheaders message
 * with a zeroed prev_filter_header when the predecessor's filter
 * header isn't available, because a SPV client would silently accept
 * the lie. When start_height === 0 there is no predecessor and Core
 * defaults to the all-zeros header (BIP-157 §3).
 */
export async function processGetCFHeaders(
  peer: Peer,
  payload: GetCFHeadersPayload,
  deps: CFilterHandlerDeps,
  sendCFHeaders: (peer: Peer, response: {
    filterType: number;
    stopHash: Buffer;
    previousFilterHeader: Buffer;
    filterHashes: Buffer[];
  }) => void
): Promise<void> {
  const prepared = await prepareBlockFilterRequest(
    peer,
    deps,
    payload.filterType,
    payload.startHeight,
    payload.stopHash,
    MAX_GETCFHEADERS_SIZE
  );
  if (!prepared.ok) return;
  if (!deps.filterIndex) return;

  // Resolve the previous filter header. For start_height === 0, the
  // BIP-157 convention is the all-zeros header (genesis predecessor).
  let previousFilterHeader: Buffer = Buffer.alloc(32, 0);
  if (payload.startHeight > 0) {
    const prevHash = await deps.db.getBlockHashByHeight(payload.startHeight - 1);
    if (!prevHash) {
      // Active chain missing at start_height-1: defensive return rather
      // than send a misleading zero header.
      return;
    }
    const prev = await deps.filterIndex.getFilterHeader(prevHash);
    if (!prev) {
      // Index lag at the previous block — FIX-79 ouroboros pattern:
      // never advertise a zero predecessor as if it were genesis.
      return;
    }
    previousFilterHeader = prev;
  }

  // Walk the chain forward gathering filter HASHES (not headers).
  // Core uses LookupFilterHashRange which returns the per-block filter
  // hash; hotbuns derives the hash from the encoded filter via
  // GCSFilter.fromEncoded(...).getHash() because the index does not
  // store the filter hash separately. The cost is one GCS decode per
  // block in the range; the per-message cap of 2000 keeps this bounded.
  const filterHashes: Buffer[] = [];
  for (let h = payload.startHeight; h <= prepared.stopHeight; h++) {
    const hash = await deps.db.getBlockHashByHeight(h);
    if (!hash) return;
    const filterBytes = await deps.filterIndex.getFilter(hash);
    if (!filterBytes) {
      // Index lag — same defensive return as Core line 3375.
      return;
    }
    const decoded = GCSFilter.fromEncoded(filterBytes, hash);
    filterHashes.push(decoded.getHash());
  }

  sendCFHeaders(peer, {
    filterType: payload.filterType,
    stopHash: prepared.stopHash,
    previousFilterHeader,
    filterHashes,
  });
}

/**
 * Handle an incoming `getcfcheckpt` message.
 *
 * Mirrors ProcessGetCFCheckPt (net_processing.cpp:3386). Returns a
 * single `cfcheckpt` response with the filter header for every
 * CFCHECKPT_INTERVAL (1000)-th block from height 1000 up to
 * floor(stop_height / 1000) * 1000.
 *
 * No range cap on this message — Core uses `numeric_limits<uint32>::max()`
 * because the response size is bounded by stop_height / 1000.
 *
 * CRITICAL: heights walked are `(i+1) * CFCHECKPT_INTERVAL` for
 * i ∈ [0, headers.size()-1], NOT off-by-one (1000, 2000, ..., not
 * 999, 1999, ...).  W121 BUG-7 on blockbrew was exactly this — keep
 * the FIX-74 closure shape.
 */
export async function processGetCFCheckPt(
  peer: Peer,
  payload: GetCFCheckPtPayload,
  deps: CFilterHandlerDeps,
  sendCFCheckPt: (peer: Peer, response: {
    filterType: number;
    stopHash: Buffer;
    filterHeaders: Buffer[];
  }) => void
): Promise<void> {
  const prepared = await prepareBlockFilterRequest(
    peer,
    deps,
    payload.filterType,
    0, // start_height = 0 per Core (line 3397)
    payload.stopHash,
    Number.MAX_SAFE_INTEGER // no per-message cap — Core uses uint32 max
  );
  if (!prepared.ok) return;
  if (!deps.filterIndex) return;

  const numCheckpoints = Math.floor(prepared.stopHeight / CFCHECKPT_INTERVAL);
  const filterHeaders: Buffer[] = new Array(numCheckpoints);

  // Core walks BACKWARDS from stop_index via GetAncestor(height), filling
  // headers[i] in reverse so the output is in ascending-height order.
  // Hotbuns walks ascending — same final ordering, simpler code, and the
  // active-chain oracle (getBlockHashByHeight) returns the same result
  // regardless of walk direction because stop_hash MUST be on the active
  // chain (validated by getBlockIndex above).
  for (let i = 0; i < numCheckpoints; i++) {
    const height = (i + 1) * CFCHECKPT_INTERVAL;
    const hash = await deps.db.getBlockHashByHeight(height);
    if (!hash) {
      // Active chain missing: should never trigger for height <= stop_height.
      return;
    }
    const filterHeader = await deps.filterIndex.getFilterHeader(hash);
    if (!filterHeader) {
      // Index lag — Core returns silently (line 3411-3415).
      return;
    }
    filterHeaders[i] = filterHeader;
  }

  sendCFCheckPt(peer, {
    filterType: payload.filterType,
    stopHash: prepared.stopHash,
    filterHeaders,
  });
}

/**
 * Re-exports for downstream code that wants the BIP-157 constants
 * alongside the handlers.
 */
export {
  MAX_GETCFILTERS_SIZE,
  MAX_GETCFHEADERS_SIZE,
  CFCHECKPT_INTERVAL,
  NODE_COMPACT_FILTERS_BIT,
  computeFilterHeader,
};
