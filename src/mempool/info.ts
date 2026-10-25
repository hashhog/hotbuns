/**
 * Shared mempool-info object.
 *
 * Core builds the `getmempoolinfo` RPC result and `/rest/mempool/info.json`
 * from one function, MempoolInfoToJSON (rpc/mempool.cpp). This is the same
 * single source for hotbuns' RPC and REST servers, so the two cannot drift.
 */

import type { Mempool } from "./mempool.js";

export function mempoolInfoToJSON(
  mempool: Pick<Mempool, "getInfo" | "getAllTxids" | "getTransaction" | "getUnbroadcastTxs">
): Record<string, unknown> {
  const info = mempool.getInfo();

  // Calculate total fees
  let totalFee = 0;
  for (const txid of mempool.getAllTxids()) {
    const entry = mempool.getTransaction(txid);
    if (entry) totalFee += Number(entry.fee);
  }

  return {
    loaded: true,
    size: info.size,
    bytes: info.bytes,
    usage: info.usage, // Estimated real heap retention (Core: DynamicMemoryUsage)
    total_fee: totalFee / 100_000_000, // BTC
    maxmempool: info.maxmempool,
    mempoolminfee: info.minFeeRate / 100_000, // Convert sat/vB to BTC/kvB
    minrelaytxfee: 0.000001, // 0.1 sat/vB = Core's minrelaytxfee default (0.00000100 BTC/kvB)
    incrementalrelayfee: 0.000001, // 0.1 sat/vB = Core's DEFAULT_INCREMENTAL_RELAY_FEE{100} (0.00000100 BTC/kvB)
    unbroadcastcount: mempool.getUnbroadcastTxs().size,
    fullrbf: true,
    // Core v31.99 MempoolInfoToJSON appends these 5 fields after fullrbf
    // (rpc/mempool.cpp). Values are the policy defaults (policy.h):
    //   permit_bare_multisig (DEFAULT_PERMIT_BAREMULTISIG=true),
    //   max_datacarrier_bytes (MAX_OP_RETURN_RELAY=100000),
    //   limits.cluster_count (DEFAULT_CLUSTER_LIMIT=64),
    //   limits.cluster_size_vbytes (DEFAULT_CLUSTER_SIZE_LIMIT_KVB*1000=101000),
    //   optimal (txgraph quick optimality check — true for an empty/clean pool).
    permitbaremultisig: true,
    maxdatacarriersize: 100_000,
    limitclustercount: 64,
    limitclustersize: 101_000,
    optimal: true,
  };
}
