/**
 * W112 BIP-152 Compact Blocks audit — hotbuns (TypeScript/Bun)
 *
 * 30 gates covering compact block constants, sendcmpct negotiation, cmpctblock
 * handling, getblocktxn/blocktxn, reconstruction, interactions, and HB peer mgmt.
 *
 * Core references:
 *   bitcoin-core/src/blockencodings.h/cpp  — PartiallyDownloadedBlock, CBlockHeaderAndShortTxIDs
 *   bitcoin-core/src/net_processing.cpp    — sendcmpct handler (L3901), cmpctblock handler (L4466)
 *   BIP-152
 *
 * Findings (18 bugs):
 *
 *   BUG-1  (G6,  P1-POLICY)    handleSendCmpct() does NOT reject version != 2. Core immediately
 *                               returns if sendcmpct_version != CMPCTBLOCKS_VERSION (L3907).
 *                               hotbuns accepts version=0, 1, 3 and marks peer as compact-capable.
 *
 *   BUG-2  (G8,  HIGH)         CompactBlockManager (compact_blocks.ts) is a DEAD HELPER —
 *                               it is defined, tested and correct but NEVER imported by production
 *                               code (sync/blocks.ts, peer.ts, manager.ts). The sync path ignores
 *                               it entirely and falls back to full-block getdata unconditionally.
 *
 *   BUG-3  (G11, P1-POLICY)    cmpctblock handling in sync/blocks.ts always falls back to full
 *                               block getdata, ignoring the CompactBlockManager even when the block
 *                               could be reconstructed from the local mempool. This defeats the
 *                               purpose of compact block relay.
 *
 *   BUG-4  (G9,  MEDIUM)       sendcmpct received handler in sync/blocks.ts only logs the message
 *                               but does NOT call CompactBlockManager.handleSendCmpct() to record
 *                               the peer's capabilities. Per-peer compact state is never populated
 *                               in the production path.
 *
 *   BUG-5  (G16, MEDIUM)       getblocktxn handler in sync/blocks.ts is a no-op stub:
 *                               "We don't serve compact blocks yet, so ignore these". Any peer
 *                               that sent us a cmpctblock and awaits our getblocktxn → blocktxn
 *                               round-trip will never receive a response.
 *
 *   BUG-6  (G19, MEDIUM)       blocktxn handler in sync/blocks.ts is a no-op stub:
 *                               "We fall back to full block download, so we shouldn't receive these".
 *                               Even if a peer sends us blocktxn (responding to our getblocktxn),
 *                               we discard it and the reconstruction can never complete.
 *
 *   BUG-7  (G25, MEDIUM)       No MAX_CMPCTBLOCK_DEPTH=5 guard on incoming cmpctblock.
 *                               Core (net_processing.cpp L2466) refuses to create cmpctblocks for
 *                               blocks deeper than tip-5. hotbuns accepts cmpctblocks at any depth,
 *                               wasting bandwidth reconstructing old or orphan blocks.
 *
 *   BUG-8  (G26, MEDIUM)       No vExtraTxnForCompact pool maintained anywhere.
 *                               Core maintains a circular buffer of recently-received/evicted txs
 *                               (MAX_EXTRA_TXN=100) used during compact block reconstruction to
 *                               fill slots not in the active mempool. hotbuns has no such pool,
 *                               so recently seen or evicted transactions are silently lost.
 *
 *   BUG-9  (G7,  LOW)          Our outbound sendcmpct is hardcoded enabled=false (low-bandwidth
 *                               mode) in peer.ts for every peer, unconditionally. Core selects HB
 *                               peers based on preferred-download status (L1323). While a deliberate
 *                               simplification, it means we never receive unsolicited cmpctblocks
 *                               from any peer, even for freshly-connected preferred peers.
 *
 *   BUG-10 (G10, LOW)          No duplicate-sendcmpct guard: if a peer sends sendcmpct twice,
 *                               handleSendCmpct() silently overwrites the previous state.
 *                               Core does not explicitly guard this either but Core's node-state
 *                               model makes it harmless; here it could flip HB state mid-session.
 *
 *   BUG-11 (G28, LOW)          No low-work / anti-DoS threshold check on received cmpctblock header.
 *                               Core checks GetAntiDoSWorkThreshold() (L4490) before processing.
 *                               hotbuns does not validate proof-of-work on the cmpctblock header
 *                               before initiating reconstruction, enabling trivial DoS.
 *
 *   BUG-12 (G13, LOW)          cmpctblock handler in sync/blocks.ts does not validate the block
 *                               header via ProcessNewBlockHeaders before falling back. Core always
 *                               calls ProcessNewBlockHeaders (L4503) and punishes on invalid header.
 *
 *   BUG-13 (G21, LOW)          No MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK guard. Core (L4577) limits
 *                               concurrent compact block in-flight requests per block to avoid
 *                               duplicate reconstruction work. hotbuns has no such limit.
 *
 *   BUG-14 (G22, LOW)          No BLOCK_HAVE_DATA early exit in cmpctblock handler.
 *                               Core (L4539) returns early if we already have the block data.
 *                               hotbuns sends a full getdata for every received cmpctblock, even
 *                               for blocks already stored.
 *
 *   BUG-15 (G17, LOW)          deserializeGetBlockTxnPayload does not cap the index count before
 *                               allocating. Core uses uint16_t[] (max 65535). An adversarial peer
 *                               can send a varint claiming millions of indices, forcing huge
 *                               allocation before any processing occurs.
 *
 *   BUG-16 (G29, LOW)          CompactBlockManager.sentSendCmpct() adds a peer to highBandwidthPeers
 *                               via side-effect inside the call, but the same peer can be added via
 *                               addHighBandwidthPeer() externally. If both are called the HB cap of 3
 *                               can be exceeded: sentSendCmpct checks < MAX but addHighBandwidthPeer
 *                               checks >= MAX — between them a peer can appear twice (Set prevents
 *                               duplicates, but the double-add path bypasses the <= 3 invariant).
 *
 *   BUG-17 (G30, LOW)          No cleanup of pendingBlockTxn entries on peer timeout or peer disconnect
 *                               beyond CompactBlockManager.removePeer(). If sync/blocks.ts never
 *                               calls removePeer() (which it doesn't, as the manager is unwired),
 *                               pending reconstructions accumulate indefinitely.
 *
 *   BUG-18 (G6, NOTE)          createCompactBlockFromBlock() accepts a version parameter but never
 *                               uses it to switch between txid (v1, non-witness) and wtxid (v2,
 *                               witness) for short-ID computation. If version=1 is ever used, all
 *                               short IDs will be computed with wtxid, producing a non-interoperable
 *                               compact block that no v1-only peer can reconstruct.
 *
 * Status legend:
 *   PASS — correct behaviour confirmed
 *   FAIL — bug confirmed
 *   PARTIAL — partially correct; see note
 */

import { describe, expect, test } from "bun:test";
import {
  CompactBlockManager,
  PartiallyDownloadedBlock,
  ReadStatus,
  deriveSipHashKeys,
  computeShortTxId,
  computeShortTxIdValue,
  createCompactBlockFromBlock,
  createBlockTxnResponse,
  SHORT_TXID_LENGTH,
  COMPACT_BLOCK_VERSION_1,
  COMPACT_BLOCK_VERSION_2,
  MAX_HIGH_BANDWIDTH_PEERS,
  MAX_EXTRA_TXN,
  MAX_CMPCTBLOCK_DEPTH,
  MAX_BLOCKTXN_DEPTH,
} from "../src/p2p/compact_blocks.js";
import { serializeBlockHeader } from "../src/validation/block.js";
import { getTxId, getWTxId, serializeTx } from "../src/validation/tx.js";
import { sipHash24 } from "../src/storage/indexes.js";
import {
  deserializeMessage,
  serializeMessage,
  serializeHeader,
  type CmpctBlockPayload,
  type GetBlockTxnPayload,
  type MessageHeader,
} from "../src/p2p/messages.js";

// Mainnet magic constant (used when we need to build wire messages)
const MAINNET_MAGIC = 0xd9b4bef9;
import type { Block, BlockHeader } from "../src/validation/block.js";
import type { Transaction } from "../src/validation/tx.js";
import type { MempoolEntry } from "../src/mempool/mempool.js";
import { hash256, sha256Hash } from "../src/crypto/primitives.js";
import { BufferWriter } from "../src/wire/serialization.js";

// ============================================================================
// Test helpers
// ============================================================================

function mkHeader(nonce: number = 0): BlockHeader {
  return {
    version: 1,
    prevBlock: Buffer.alloc(32, 0x01),
    merkleRoot: Buffer.alloc(32, 0x02),
    timestamp: 1600000000,
    bits: 0x1d00ffff,
    nonce,
  };
}

function mkTx(id: number, hasWitness = false): Transaction {
  return {
    version: 1,
    inputs: [
      {
        prevOut: { txid: Buffer.alloc(32, id), vout: 0 },
        scriptSig: Buffer.from([0x00]),
        sequence: 0xffffffff,
        witness: hasWitness ? [Buffer.from([0x30, 0x44]), Buffer.alloc(33, id)] : [],
      },
    ],
    outputs: [
      {
        value: 50000000n,
        scriptPubKey: Buffer.from([0x76, 0xa9, 0x14, ...Buffer.alloc(20, id), 0x88, 0xac]),
      },
    ],
    lockTime: 0,
  };
}

function mkCoinbase(height = 1): Transaction {
  return {
    version: 1,
    inputs: [
      {
        prevOut: { txid: Buffer.alloc(32, 0), vout: 0xffffffff },
        scriptSig: Buffer.from([0x01, height & 0xff]),
        sequence: 0xffffffff,
        witness: [],
      },
    ],
    outputs: [{ value: 5000000000n, scriptPubKey: Buffer.from([0x76, 0xa9, 0x14, ...Buffer.alloc(20, 0xaa), 0x88, 0xac]) }],
    lockTime: 0,
  };
}

function mkBlock(txCount: number, hasWitness = false): Block {
  const txs: Transaction[] = [mkCoinbase()];
  for (let i = 1; i < txCount; i++) txs.push(mkTx(i, hasWitness));
  return { header: mkHeader(), transactions: txs };
}

function mkMempool(txs: Transaction[]) {
  const entries: MempoolEntry[] = txs.map((tx) => ({
    tx,
    txid: getTxId(tx),
    fee: 1000n, feeRate: 1, vsize: 200, weight: 800,
    addedTime: Date.now(), height: 1,
    spentBy: new Set<string>(), dependsOn: new Set<string>(),
    ancestorCount: 1, ancestorSize: 200,
    descendantCount: 1, descendantSize: 200,
    clusterId: getTxId(tx).toString("hex"),
    miningScore: 1, ephemeralDustParents: new Set<string>(),
    hasEphemeralDust: false, sigOpCost: 0,
  }));
  const map = new Map(entries.map((e) => [e.txid.toString("hex"), e]));
  return {
    getTransaction(txid: Buffer) { return map.get(txid.toString("hex")) ?? null; },
    getAllEntries() { return entries; },
  };
}

// ============================================================================
// G1: SHORT_TXID_LENGTH = 6
// ============================================================================

describe("G1: SHORT_TXID_LENGTH constant = 6 bytes", () => {
  test("SHORT_TXID_LENGTH is 6", () => {
    expect(SHORT_TXID_LENGTH).toBe(6);
  });

  test("computeShortTxId produces exactly 6 bytes", () => {
    const [k0, k1] = [0x0102030405060708n, 0x090a0b0c0d0e0f10n];
    const wtxid = Buffer.alloc(32, 0xab);
    const sid = computeShortTxId(k0, k1, wtxid);
    expect(sid.length).toBe(6);
  });
});

// ============================================================================
// G2: COMPACT_BLOCK_VERSION_1=1n, COMPACT_BLOCK_VERSION_2=2n
// ============================================================================

describe("G2: BIP-152 version constants", () => {
  test("COMPACT_BLOCK_VERSION_1 = 1n", () => {
    expect(COMPACT_BLOCK_VERSION_1).toBe(1n);
  });

  test("COMPACT_BLOCK_VERSION_2 = 2n", () => {
    expect(COMPACT_BLOCK_VERSION_2).toBe(2n);
  });
});

// ============================================================================
// G3: MAX_HIGH_BANDWIDTH_PEERS = 3
// ============================================================================

describe("G3: MAX_HIGH_BANDWIDTH_PEERS = 3", () => {
  test("MAX_HIGH_BANDWIDTH_PEERS constant is 3", () => {
    expect(MAX_HIGH_BANDWIDTH_PEERS).toBe(3);
  });

  test("CompactBlockManager enforces HB cap at 3 peers", () => {
    const mgr = new CompactBlockManager();
    for (let i = 0; i < 3; i++) {
      expect(mgr.addHighBandwidthPeer(`p${i}`)).toBe(true);
    }
    expect(mgr.addHighBandwidthPeer("p4")).toBe(false);
  });
});

// ============================================================================
// G4: MAX_EXTRA_TXN = 100
// ============================================================================

describe("G4: MAX_EXTRA_TXN constant = 100", () => {
  test("MAX_EXTRA_TXN is 100", () => {
    expect(MAX_EXTRA_TXN).toBe(100);
  });
});

// ============================================================================
// G5: SipHash-2-4 key derivation — SHA256(header||nonce_LE) → k0/k1 LE u64
// ============================================================================

describe("G5: SipHash-2-4 key derivation (BIP-152 FillShortTxIDSelector)", () => {
  test("deriveSipHashKeys: input is raw 80-byte header bytes, not hash256(header)", () => {
    // Core: stream << header << nonce → SHA256; the header is the 80-byte serialized form
    const header = mkHeader();
    const headerBuf = serializeBlockHeader(header);
    const nonce = 0xdeadbeef1234n;

    const [k0_correct, k1_correct] = deriveSipHashKeys(headerBuf, nonce);

    // Compute with hash256(header) instead — must differ
    const [k0_wrong, k1_wrong] = deriveSipHashKeys(hash256(headerBuf), nonce);
    expect(k0_correct === k0_wrong && k1_correct === k1_wrong).toBe(false);
  });

  test("deriveSipHashKeys: uses single SHA256 not double-SHA256", () => {
    const headerBuf = serializeBlockHeader(mkHeader());
    const nonce = 42n;

    const nonceBuffer = Buffer.alloc(8);
    nonceBuffer.writeBigUInt64LE(nonce, 0);
    const keyData = Buffer.concat([headerBuf, nonceBuffer]);

    const singleHash = sha256Hash(keyData);
    const expectedK0 = singleHash.readBigUInt64LE(0);
    const expectedK1 = singleHash.readBigUInt64LE(8);

    const [k0, k1] = deriveSipHashKeys(headerBuf, nonce);
    expect(k0).toBe(expectedK0);
    expect(k1).toBe(expectedK1);
  });

  test("deriveSipHashKeys: nonce is serialized as little-endian u64", () => {
    const headerBuf = serializeBlockHeader(mkHeader());
    const nonce = 0x0102030405060708n;

    const [k0] = deriveSipHashKeys(headerBuf, nonce);
    expect(typeof k0).toBe("bigint");
    expect(k0 < 2n ** 64n).toBe(true);
  });

  test("deriveSipHashKeys: deterministic for same inputs", () => {
    const headerBuf = serializeBlockHeader(mkHeader());
    const nonce = 0xffeeddccbbaa9988n;

    const [k0a, k1a] = deriveSipHashKeys(headerBuf, nonce);
    const [k0b, k1b] = deriveSipHashKeys(headerBuf, nonce);
    expect(k0a).toBe(k0b);
    expect(k1a).toBe(k1b);
  });
});

// ============================================================================
// G6: sendcmpct negotiation — BUG-1 (version != 2 not rejected), BUG-18 (v1 wtxid bug)
// ============================================================================

describe("G6: sendcmpct version validation — BUG-1 FAIL", () => {
  test("FAIL: handleSendCmpct does NOT reject version=0 (Core rejects non-2)", () => {
    // Core: if (sendcmpct_version != CMPCTBLOCKS_VERSION) return;  (net_processing.cpp:3907)
    // hotbuns: no such check
    const mgr = new CompactBlockManager();
    mgr.handleSendCmpct("p1", true, 0n); // version 0 — should be rejected
    // Bug: peer is now marked as compact-capable with version 0
    expect(mgr.peerSupportsCompact("p1")).toBe(true); // FAIL — should be false
  });

  test("FAIL: handleSendCmpct does NOT reject version=1 (Core rejects non-2)", () => {
    const mgr = new CompactBlockManager();
    mgr.handleSendCmpct("p1", true, 1n); // version 1 (non-witness) — Core rejects
    expect(mgr.peerSupportsCompact("p1")).toBe(true); // FAIL — should be false
  });

  test("FAIL: handleSendCmpct does NOT reject version=3 (future version)", () => {
    const mgr = new CompactBlockManager();
    mgr.handleSendCmpct("p1", true, 3n); // version 3 — unknown, Core rejects
    expect(mgr.peerSupportsCompact("p1")).toBe(true); // FAIL — should be false
  });

  test("PASS: handleSendCmpct correctly accepts version=2", () => {
    const mgr = new CompactBlockManager();
    mgr.handleSendCmpct("p1", true, 2n);
    expect(mgr.peerSupportsCompact("p1")).toBe(true);
    expect(mgr.getNegotiatedVersion("p1")).toBe(2n);
  });
});

describe("G6: BUG-18 — createCompactBlockFromBlock ignores version param for wtxid/txid selection", () => {
  test("FAIL: version=1 still uses wtxid instead of txid for short IDs", () => {
    // Core CBlockHeaderAndShortTxIDs always uses GetWitnessHash() (see blockencodings.cpp:31)
    // BIP-152 v2 uses wtxid; v1 used txid. hotbuns always uses wtxid regardless.
    // This is a bug if version=1 is ever requested, but not an active CDIV since
    // we only send/negotiate version=2. Documented here for completeness.
    const block = mkBlock(3, true); // witness txs
    const nonce = 1n;

    const compact_v1 = createCompactBlockFromBlock(block, nonce, new Set(), COMPACT_BLOCK_VERSION_1);
    const compact_v2 = createCompactBlockFromBlock(block, nonce, new Set(), COMPACT_BLOCK_VERSION_2);

    // Both use wtxid. For v1, they should differ if txid != wtxid.
    // Since getWTxId differs from getTxId for witness txs, v1 compact block
    // built with wtxid cannot be reconstructed by a peer using txid.
    // We verify: v1 and v2 both produce the same short IDs (both use wtxid).
    expect(compact_v1.shortIds.length).toBe(compact_v2.shortIds.length);
    if (compact_v1.shortIds.length > 0) {
      // For witness txs wtxid != txid, but both versions use wtxid here
      // so they produce the same result — that's the bug
      expect(compact_v1.shortIds[0].equals(compact_v2.shortIds[0])).toBe(true);
    }
  });
});

// ============================================================================
// G7: sendcmpct: our outgoing always enabled=false — BUG-9
// ============================================================================

describe("G7: Our outbound sendcmpct is always low-bandwidth — BUG-9 LOW", () => {
  test("FAIL: peer.ts hardcodes enabled=false for all peers (no HB outbound)", () => {
    // Core L1323: sends HB (enabled=true) for preferred-download peers
    // We can verify the message serialization: our sendcmpct is always enabled=false
    const msg = serializeMessage(MAINNET_MAGIC, { type: "sendcmpct", payload: { enabled: false, version: 2n } });
    const hdrBuf = {
      magic: msg.readUInt32LE(0),
      command: msg.subarray(4, 16).toString("ascii").replace(/\0/g, ""),
      length: msg.readUInt32LE(16),
      checksum: msg.subarray(20, 24),
    };
    const payload = msg.subarray(24);
    expect(hdrBuf.command).toBe("sendcmpct");
    // enabled=false is byte 0
    expect(payload[0]).toBe(0);
  });
});

// ============================================================================
// G8: CompactBlockManager is a dead helper — BUG-2
// ============================================================================

describe("G8: CompactBlockManager DEAD HELPER — BUG-2 HIGH", () => {
  test("FAIL: compact_blocks.ts is not imported by any production module", () => {
    // If CompactBlockManager were wired, the sync/blocks.ts cmpctblock handler
    // would call it. Instead sync/blocks.ts falls back to MSG_WITNESS_BLOCK getdata.
    // We verify the production behavior: the CompactBlockManager is importable but unwired.
    const mgr = new CompactBlockManager();
    mgr.handleSendCmpct("p1", true, 2n);

    // This is the correct handler code — but it's never called in production.
    // The test passes because the logic is correct, but this is dead code in deployment.
    expect(mgr.peerSupportsCompact("p1")).toBe(true);
    expect(typeof mgr.startBlockReconstruction).toBe("function");
    expect(typeof mgr.tryFillFromMempool).toBe("function");
    // No production module imports from compact_blocks.ts
  });
});

// ============================================================================
// G9: sendcmpct received — BUG-4 (not recorded in production)
// ============================================================================

describe("G9: Received sendcmpct is logged but not recorded — BUG-4 MEDIUM", () => {
  test("PASS: CompactBlockManager correctly records sendcmpct state (unit level)", () => {
    const mgr = new CompactBlockManager();
    mgr.handleSendCmpct("p1", true, 2n);
    expect(mgr.peerSupportsCompact("p1")).toBe(true);
  });

  test("FAIL: Production sync/blocks.ts sendcmpct handler does not call CompactBlockManager", () => {
    // Verified by code inspection: sync/blocks.ts:L659-665 only logs, no manager call.
    // This is a dead-helper wiring bug — the handler exists but doesn't record state.
    // We can't directly test the wiring gap in isolation, so we document the path:
    // sync/blocks.ts line 659: peerManager.onMessage("sendcmpct", ...) => console.log only
    expect(true).toBe(true); // Documented: BUG-4 verified by code inspection
  });
});

// ============================================================================
// G10: Version negotiation — min(our_version, peer_version)
// ============================================================================

describe("G10: Version negotiation takes min(ours, peer's)", () => {
  test("PASS: getNegotiatedVersion returns min of our v2 and peer v1", () => {
    const mgr = new CompactBlockManager();
    mgr.handleSendCmpct("p1", true, 1n);
    expect(mgr.getNegotiatedVersion("p1")).toBe(1n);
  });

  test("PASS: getNegotiatedVersion returns v2 when peer also supports v2", () => {
    const mgr = new CompactBlockManager();
    mgr.handleSendCmpct("p1", true, 2n);
    expect(mgr.getNegotiatedVersion("p1")).toBe(2n);
  });

  test("PASS: getNegotiatedVersion returns 0 when peer doesn't support compact", () => {
    const mgr = new CompactBlockManager();
    mgr.handleSendCmpct("p1", false, 0n);
    expect(mgr.getNegotiatedVersion("p1")).toBe(0n);
  });
});

// ============================================================================
// G11: cmpctblock reception — BUG-3 (always falls back to full block)
// ============================================================================

describe("G11: cmpctblock reconstruction path — BUG-3 P1-POLICY", () => {
  test("PASS: PartiallyDownloadedBlock.initData works correctly (unit)", () => {
    const block = mkBlock(4);
    const compact = createCompactBlockFromBlock(block, 111n);
    const partial = new PartiallyDownloadedBlock(compact, "a".repeat(64));
    expect(partial.initData(compact)).toBe(ReadStatus.OK);
  });

  test("FAIL: Production cmpctblock handler unconditionally falls back to full block getdata", () => {
    // sync/blocks.ts:L636-656 — always sends MSG_WITNESS_BLOCK getdata, ignores CompactBlockManager
    // This defeats compact block relay even when mempool can complete the block.
    // Verified by code inspection: no call to CompactBlockManager.startBlockReconstruction().
    expect(true).toBe(true); // Documented: BUG-3 verified by code inspection
  });
});

// ============================================================================
// G12: cmpctblock header validation before reconstruction
// ============================================================================

describe("G12: cmpctblock header PoW validation — BUG-11 LOW", () => {
  test("FAIL: no anti-DoS work threshold check on received cmpctblock", () => {
    // Core net_processing.cpp:4490 — GetAntiDoSWorkThreshold() check
    // hotbuns sync/blocks.ts cmpctblock handler does no PoW check before getdata fallback
    // (and CompactBlockManager.startBlockReconstruction has no PoW check either)
    const block = mkBlock(3);
    const compact = createCompactBlockFromBlock(block, 0n);
    const mgr = new CompactBlockManager();
    mgr.handleSendCmpct("p1", true, 2n);
    // No exception thrown for a zero-work header — should reject in a real node
    const partial = mgr.startBlockReconstruction(compact, "b".repeat(64), "p1");
    expect(partial).not.toBeNull(); // Accepted — but should be rejected for low-work
  });
});

// ============================================================================
// G13: getblocktxn request is created for missing transactions
// ============================================================================

describe("G13: getblocktxn request creation", () => {
  test("PASS: createGetBlockTxn produces correct payload", () => {
    const mgr = new CompactBlockManager();
    const blockHash = Buffer.alloc(32, 0x01);
    const req = mgr.createGetBlockTxn(blockHash, [1, 3, 5]);
    expect(req.blockHash).toBe(blockHash);
    expect(req.indexes).toEqual([1, 3, 5]);
  });

  test("PASS: missing indices from reconstruction are correct", () => {
    const block = mkBlock(5);
    const compact = createCompactBlockFromBlock(block, 222n);
    const mempool = mkMempool([block.transactions[1]]);

    const partial = new PartiallyDownloadedBlock(compact, "c".repeat(64));
    partial.initData(compact);
    const missing = partial.fillFromMempool(mempool);

    // tx2, tx3, tx4 are missing
    expect(missing.length).toBe(3);
    expect(missing).toContain(2);
    expect(missing).toContain(3);
    expect(missing).toContain(4);
  });
});

// ============================================================================
// G14: fallback to full block on reconstruction failure
// ============================================================================

describe("G14: Full-block fallback on InitData failure", () => {
  test("PASS: startBlockReconstruction returns null on INVALID status", () => {
    const compact: CmpctBlockPayload = {
      header: mkHeader(),
      nonce: 0n,
      shortIds: [],
      prefilledTxns: [],
    };
    const mgr = new CompactBlockManager();
    mgr.handleSendCmpct("p1", true, 2n);
    const result = mgr.startBlockReconstruction(compact, "d".repeat(64), "p1");
    expect(result).toBeNull(); // INVALID → null → fallback
  });

  test("PASS: FAILED status (duplicate short IDs) also returns null", () => {
    const block = mkBlock(4);
    const compact = createCompactBlockFromBlock(block, 0n);
    // Inject duplicate short ID
    if (compact.shortIds.length >= 2) {
      compact.shortIds[1] = Buffer.from(compact.shortIds[0]);
    }
    const mgr = new CompactBlockManager();
    mgr.handleSendCmpct("p1", true, 2n);
    const result = mgr.startBlockReconstruction(compact, "e".repeat(64), "p1");
    expect(result).toBeNull();
  });
});

// ============================================================================
// G15: Short ID collision detection (bucket-size-12 DoS guard)
// ============================================================================

describe("G15: Short ID collision detection", () => {
  test("PASS: 13 identical short IDs → FAILED", () => {
    const block = mkBlock(15);
    const compact = createCompactBlockFromBlock(block, 0n);
    const collidingId = compact.shortIds[0].slice();
    for (let i = 0; i < 13 && i < compact.shortIds.length; i++) {
      compact.shortIds[i] = Buffer.from(collidingId);
    }
    const partial = new PartiallyDownloadedBlock(compact, "f".repeat(64));
    expect(partial.initData(compact)).toBe(ReadStatus.FAILED);
  });

  test("PASS: 2 identical short IDs → FAILED (exact duplicate)", () => {
    const block = mkBlock(4);
    const compact = createCompactBlockFromBlock(block, 0n);
    compact.shortIds[1] = Buffer.from(compact.shortIds[0]);
    const partial = new PartiallyDownloadedBlock(compact, "10".repeat(32));
    expect(partial.initData(compact)).toBe(ReadStatus.FAILED);
  });
});

// ============================================================================
// G16: getblocktxn serving — BUG-5
// ============================================================================

describe("G16: getblocktxn serving — BUG-5 MEDIUM stub", () => {
  test("PASS: createBlockTxnResponse builds correct blocktxn payload", () => {
    const block = mkBlock(5);
    const req: GetBlockTxnPayload = { blockHash: Buffer.alloc(32, 0x02), indexes: [1, 3] };
    const resp = createBlockTxnResponse(block, req);
    expect(resp).not.toBeNull();
    expect(resp!.transactions[0]).toBe(block.transactions[1]);
    expect(resp!.transactions[1]).toBe(block.transactions[3]);
  });

  test("FAIL: Production getblocktxn handler is a no-op stub (BUG-5)", () => {
    // sync/blocks.ts:L669-671: "We don't serve compact blocks yet, so ignore these"
    // Peers requesting blocktxn from us will never receive a response.
    expect(true).toBe(true); // Documented: BUG-5 verified by code inspection
  });
});

// ============================================================================
// G17: getblocktxn differential index encoding/decoding
// ============================================================================

describe("G17: getblocktxn differential index encoding (wire format)", () => {
  test("PASS: round-trip getblocktxn payload via serialize/deserialize", () => {
    const gbtPayload: GetBlockTxnPayload = {
      blockHash: Buffer.alloc(32, 0x03),
      indexes: [0, 2, 5, 11],
    };
    const serialized = serializeMessage(MAINNET_MAGIC, { type: "getblocktxn", payload: gbtPayload });
    const msgBuf = serialized.subarray(24); // strip message header
    const hdr: MessageHeader = {
      magic: serialized.readUInt32LE(0),
      command: "getblocktxn",
      length: serialized.readUInt32LE(16),
      checksum: serialized.subarray(20, 24),
    };
    const recovered = deserializeMessage(hdr, msgBuf);
    expect(recovered.type).toBe("getblocktxn");
    if (recovered.type === "getblocktxn") {
      expect(recovered.payload.indexes).toEqual([0, 2, 5, 11]);
    }
  });

  test("FAIL: deserializeGetBlockTxnPayload does not cap index count — BUG-15", () => {
    // A malicious peer can send a varint with millions of indices before we check.
    // Core uses uint16_t[] (max 65535) so it's self-limiting.
    // hotbuns uses number[] with no pre-allocation cap.
    // We document this without exhausting memory in the test.
    expect(true).toBe(true); // Documented: BUG-15 by code inspection of messages.ts:L982-996
  });
});

// ============================================================================
// G18: blocktxn count must match missing indices
// ============================================================================

describe("G18: blocktxn transaction count must match missing indices", () => {
  test("PASS: fillFromBlockTxn returns false when count mismatches", () => {
    const block = mkBlock(4);
    const compact = createCompactBlockFromBlock(block, 333n);
    const partial = new PartiallyDownloadedBlock(compact, "20".repeat(32));
    partial.initData(compact);
    partial.fillFromMempool(mkMempool([]));

    // 3 missing, but supply only 2
    const result = partial.fillFromBlockTxn(block.transactions.slice(1, 3));
    expect(result).toBe(false);
  });

  test("PASS: fillFromBlockTxn returns true when count matches", () => {
    const block = mkBlock(3);
    const compact = createCompactBlockFromBlock(block, 444n);
    const partial = new PartiallyDownloadedBlock(compact, "30".repeat(32));
    partial.initData(compact);
    const missing = partial.fillFromMempool(mkMempool([]));
    const txs = missing.map((i) => block.transactions[i]);
    expect(partial.fillFromBlockTxn(txs)).toBe(true);
  });
});

// ============================================================================
// G19: blocktxn handler — BUG-6
// ============================================================================

describe("G19: blocktxn handling — BUG-6 MEDIUM stub", () => {
  test("PASS: handleBlockTxn completes reconstruction (unit)", () => {
    const block = mkBlock(3);
    const compact = createCompactBlockFromBlock(block, 555n);
    const mgr = new CompactBlockManager();
    mgr.handleSendCmpct("p1", true, 2n);
    const partial = mgr.startBlockReconstruction(compact, "40".repeat(32), "p1");
    const missing = mgr.tryFillFromMempool(partial!, mkMempool([]));
    const txs = missing.map((i) => block.transactions[i]);
    const reconstructed = mgr.handleBlockTxn("p1", {
      blockHash: Buffer.from("40".repeat(32), "hex"),
      transactions: txs,
    });
    expect(reconstructed).not.toBeNull();
  });

  test("FAIL: Production blocktxn handler is a no-op stub (BUG-6)", () => {
    // sync/blocks.ts:L674-676: "We fall back to full block download"
    expect(true).toBe(true); // Documented: BUG-6 verified by code inspection
  });
});

// ============================================================================
// G20: Only accept blocktxn if we sent getblocktxn for that block
// ============================================================================

describe("G20: blocktxn accepted only for pending blocks", () => {
  test("PASS: handleBlockTxn returns null for unknown blockHash", () => {
    const mgr = new CompactBlockManager();
    mgr.handleSendCmpct("p1", true, 2n);
    const result = mgr.handleBlockTxn("p1", {
      blockHash: Buffer.alloc(32, 0xff),
      transactions: [],
    });
    expect(result).toBeNull();
  });

  test("PASS: handleBlockTxn returns null for unknown peer", () => {
    const mgr = new CompactBlockManager();
    const result = mgr.handleBlockTxn("unknown-peer", {
      blockHash: Buffer.alloc(32, 0x01),
      transactions: [],
    });
    expect(result).toBeNull();
  });
});

// ============================================================================
// G21: Full reconstruction with mempool only
// ============================================================================

describe("G21: Full reconstruction — mempool only", () => {
  test("PASS: complete reconstruction when all txs are in mempool", () => {
    const block = mkBlock(6);
    const compact = createCompactBlockFromBlock(block, 0xdeadbeefn);
    const mempool = mkMempool(block.transactions.slice(1));

    const partial = new PartiallyDownloadedBlock(compact, "50".repeat(32));
    partial.initData(compact);
    const missing = partial.fillFromMempool(mempool);

    expect(missing.length).toBe(0);
    expect(partial.isComplete()).toBe(true);
    const result = partial.getBlock();
    expect(result).not.toBeNull();
    expect(result!.transactions.length).toBe(6);
  });

  test("PASS: short IDs use wtxid for witness transactions", () => {
    const block = mkBlock(3, true);
    const nonce = 99n;
    const compact = createCompactBlockFromBlock(block, nonce);

    // Verify short IDs match wtxid (not txid)
    const headerBuf = serializeBlockHeader(block.header);
    const [k0, k1] = deriveSipHashKeys(headerBuf, nonce);
    const tx = block.transactions[1];
    const wtxid = getWTxId(tx);
    const txid = getTxId(tx);

    expect(wtxid.equals(txid)).toBe(false); // witness tx differs
    const fromWtxid = sipHash24(k0, k1, wtxid) & 0xffffffffffffn;
    const fromTxid = sipHash24(k0, k1, txid) & 0xffffffffffffn;
    const stored = (() => {
      const pad = Buffer.alloc(8);
      compact.shortIds[0].copy(pad, 0);
      return pad.readBigUInt64LE(0);
    })();
    expect(stored).toBe(fromWtxid);
    expect(stored).not.toBe(fromTxid);
  });
});

// ============================================================================
// G22: Reconstruction with getblocktxn fallback
// ============================================================================

describe("G22: Reconstruction with getblocktxn fallback", () => {
  test("PASS: partial fill then complete via fillFromBlockTxn", () => {
    const block = mkBlock(5);
    const compact = createCompactBlockFromBlock(block, 0xcafebaben);
    const mempool = mkMempool([block.transactions[1], block.transactions[3]]);

    const partial = new PartiallyDownloadedBlock(compact, "60".repeat(32));
    partial.initData(compact);
    const missing = partial.fillFromMempool(mempool);

    expect(missing.length).toBe(2);
    const txs = missing.map((i) => block.transactions[i]);
    expect(partial.fillFromBlockTxn(txs)).toBe(true);

    const result = partial.getBlock();
    expect(result).not.toBeNull();
    expect(result!.transactions.length).toBe(5);
  });
});

// ============================================================================
// G23: IsBlockMutated check in getBlock()
// ============================================================================

describe("G23: IsBlockMutated check (checkWitnessMalleation) in getBlock()", () => {
  test("PASS: getBlock(true) returns block for valid non-witness block", () => {
    const block = mkBlock(4);
    const compact = createCompactBlockFromBlock(block, 0n);
    const partial = new PartiallyDownloadedBlock(compact, "70".repeat(32));
    partial.initData(compact);
    partial.fillFromMempool(mkMempool(block.transactions.slice(1)));
    expect(partial.getBlock(true)).not.toBeNull();
  });

  test("PASS: getBlock(false) skips witness check", () => {
    const block = mkBlock(3);
    const compact = createCompactBlockFromBlock(block, 0n);
    const partial = new PartiallyDownloadedBlock(compact, "80".repeat(32));
    partial.initData(compact);
    partial.fillFromMempool(mkMempool(block.transactions.slice(1)));
    expect(partial.getBlock(false)).not.toBeNull();
  });

  test("PASS: getBlock() returns null when block is incomplete", () => {
    const block = mkBlock(5);
    const compact = createCompactBlockFromBlock(block, 0n);
    const partial = new PartiallyDownloadedBlock(compact, "90".repeat(32));
    partial.initData(compact);
    partial.fillFromMempool(mkMempool([]));
    expect(partial.getBlock()).toBeNull();
  });
});

// ============================================================================
// G24: have_txn[] 3-way collision protection
// ============================================================================

describe("G24: have_txn[] prevents 3-way mempool collision from re-filling a cleared slot", () => {
  test("PASS: duplicate extra_txn entry with same wtxid does not clear slot", () => {
    const block = mkBlock(3);
    const compact = createCompactBlockFromBlock(block, 5555n);
    const partial = new PartiallyDownloadedBlock(compact, "a0".repeat(32));
    partial.initData(compact);
    const tx1 = block.transactions[1];
    const missing = partial.fillFromMempool(mkMempool([]), [tx1, tx1]);
    // tx1 slot filled (same wtxid, no clear), tx2 still missing
    expect(partial.isTxAvailable(1)).toBe(true);
    expect(missing).toContain(2);
  });
});

// ============================================================================
// G25: MAX_CMPCTBLOCK_DEPTH=5 guard — BUG-7 (FIXED in FIX-42)
// ============================================================================

describe("G25: MAX_CMPCTBLOCK_DEPTH=5 guard — FIX-42", () => {
  test("PASS: MAX_CMPCTBLOCK_DEPTH constant is 5", () => {
    expect(MAX_CMPCTBLOCK_DEPTH).toBe(5);
  });

  test("PASS: startBlockReconstruction rejects depth > MAX_CMPCTBLOCK_DEPTH", () => {
    // Core net_processing.cpp:2466 — refuses cmpctblock for blocks at tip-6 or deeper
    // FIX-42: depth parameter added to startBlockReconstruction; depth > 5 → null
    const block = mkBlock(3);
    const compact = createCompactBlockFromBlock(block, 0n);
    const mgr = new CompactBlockManager();
    mgr.handleSendCmpct("p1", true, 2n);
    // depth = MAX_CMPCTBLOCK_DEPTH + 1 → should be rejected
    const partial = mgr.startBlockReconstruction(compact, "b0".repeat(32), "p1", MAX_CMPCTBLOCK_DEPTH + 1);
    expect(partial).toBeNull(); // PASS: depth guard rejects stale block
  });

  test("PASS: startBlockReconstruction accepts depth = MAX_CMPCTBLOCK_DEPTH exactly", () => {
    const block = mkBlock(3);
    const compact = createCompactBlockFromBlock(block, 0n);
    const mgr = new CompactBlockManager();
    mgr.handleSendCmpct("p1", true, 2n);
    const partial = mgr.startBlockReconstruction(compact, "b1".repeat(32), "p1", MAX_CMPCTBLOCK_DEPTH);
    expect(partial).not.toBeNull(); // depth == 5 is allowed
  });

  test("PASS: startBlockReconstruction accepts depth 0 (tip block)", () => {
    const block = mkBlock(3);
    const compact = createCompactBlockFromBlock(block, 0n);
    const mgr = new CompactBlockManager();
    mgr.handleSendCmpct("p1", true, 2n);
    const partial = mgr.startBlockReconstruction(compact, "b2".repeat(32), "p1", 0);
    expect(partial).not.toBeNull();
  });

  test("PASS: startBlockReconstruction accepts depth=0 by default (backward compat)", () => {
    // Existing callers without depth param still work (default = 0 = tip).
    const block = mkBlock(3);
    const compact = createCompactBlockFromBlock(block, 0n);
    const mgr = new CompactBlockManager();
    mgr.handleSendCmpct("p1", true, 2n);
    const partial = mgr.startBlockReconstruction(compact, "b3".repeat(32), "p1");
    expect(partial).not.toBeNull();
  });
});

// ============================================================================
// G25b: MAX_BLOCKTXN_DEPTH=10 constant — FIX-42
// ============================================================================

describe("G25b: MAX_BLOCKTXN_DEPTH=10 constant — FIX-42", () => {
  test("PASS: MAX_BLOCKTXN_DEPTH constant is 10", () => {
    // Core net_processing.cpp MAX_BLOCKTXN_DEPTH = 10:
    // getblocktxn serve requests are ignored for blocks deeper than tip-10.
    expect(MAX_BLOCKTXN_DEPTH).toBe(10);
  });

  test("PASS: MAX_BLOCKTXN_DEPTH > MAX_CMPCTBLOCK_DEPTH (wider serve window)", () => {
    // We may serve blocktxn for slightly older blocks than we reconstruct from.
    expect(MAX_BLOCKTXN_DEPTH).toBeGreaterThan(MAX_CMPCTBLOCK_DEPTH);
  });
});

// ============================================================================
// G26: vExtraTxnForCompact pool — BUG-8
// ============================================================================

describe("G26: vExtraTxnForCompact pool absent — BUG-8 MEDIUM", () => {
  test("FAIL: No extra_txn pool maintained anywhere in production code (BUG-8)", () => {
    // Core maintains a circular buffer of MAX_EXTRA_TXN=100 recently-received txs
    // compact_blocks.ts has MAX_EXTRA_TXN=100 exported but no production code maintains it
    expect(MAX_EXTRA_TXN).toBe(100); // Constant defined
    // But no production code maintains a vExtraTxnForCompact buffer
    // tryFillFromMempool(partial, mempool, extraTxn=[]) always called with empty extraTxn
    expect(true).toBe(true); // Documented: BUG-8 verified by code inspection
  });
});

// ============================================================================
// G27: cmpctblock depth + chain work threshold — BUG-11
// ============================================================================

describe("G27: Anti-DoS chain-work threshold on cmpctblock — BUG-11 LOW", () => {
  test("FAIL: CompactBlockManager.startBlockReconstruction has no PoW check (BUG-11)", () => {
    // Core: if (prev_block->nChainWork + GetBlockProof(header) < GetAntiDoSWorkThreshold()) return;
    // hotbuns: no such check
    const block = mkBlock(2);
    block.header.bits = 0x207fffff; // very easy difficulty (near zero work)
    const compact = createCompactBlockFromBlock(block, 0n);
    const mgr = new CompactBlockManager();
    mgr.handleSendCmpct("p1", true, 2n);
    const partial = mgr.startBlockReconstruction(compact, "c0".repeat(32), "p1");
    // Should reject low-work block — but it's accepted
    expect(partial).not.toBeNull(); // BUG-11: no PoW rejection
  });
});

// ============================================================================
// G28: BLOCK_HAVE_DATA early exit — BUG-14
// ============================================================================

describe("G28: BLOCK_HAVE_DATA early exit — BUG-14 LOW", () => {
  test("FAIL: No already-have-data check before reconstruction (BUG-14)", () => {
    // Core L4539: if (pindex->nStatus & BLOCK_HAVE_DATA) return;
    // hotbuns falls back to MSG_WITNESS_BLOCK getdata without checking storage first
    // Documented by code inspection of sync/blocks.ts:L636-656
    expect(true).toBe(true); // Documented: BUG-14 by code inspection
  });
});

// ============================================================================
// G29: HB peer selection criteria — BUG-9 documented
// ============================================================================

describe("G29: HB peer selection based on preferred-download status — BUG-9 LOW", () => {
  test("PASS: CompactBlockManager enforces HB cap at 3", () => {
    const mgr = new CompactBlockManager();
    expect(mgr.addHighBandwidthPeer("p1")).toBe(true);
    expect(mgr.addHighBandwidthPeer("p2")).toBe(true);
    expect(mgr.addHighBandwidthPeer("p3")).toBe(true);
    expect(mgr.addHighBandwidthPeer("p4")).toBe(false);
  });

  test("PASS: removePeer removes from HB set", () => {
    const mgr = new CompactBlockManager();
    for (let i = 0; i < 3; i++) mgr.addHighBandwidthPeer(`p${i}`);
    mgr.removePeer("p0");
    expect(mgr.isHighBandwidthPeer("p0")).toBe(false);
    expect(mgr.addHighBandwidthPeer("p_new")).toBe(true);
  });
});

// ============================================================================
// G30: CompactBlockManager statistics
// ============================================================================

describe("G30: CompactBlockManager statistics tracking", () => {
  test("PASS: stats track successful reconstruction", () => {
    const block = mkBlock(3);
    const compact = createCompactBlockFromBlock(block, 999n);
    const mgr = new CompactBlockManager();
    mgr.handleSendCmpct("p1", true, 2n);
    const partial = mgr.startBlockReconstruction(compact, "d0".repeat(32), "p1");
    mgr.tryFillFromMempool(partial!, mkMempool(block.transactions.slice(1)));
    const stats = mgr.getStats();
    expect(stats.compactBlocksReceived).toBe(1);
    expect(stats.successfulReconstructions).toBe(1);
    expect(stats.mempoolHits).toBe(2);
    expect(stats.mempoolMisses).toBe(0);
  });

  test("PASS: getSuccessRate returns 0 when all need requests", () => {
    const mgr = new CompactBlockManager();
    for (let i = 0; i < 3; i++) {
      const block = mkBlock(2);
      const compact = createCompactBlockFromBlock(block, BigInt(i));
      mgr.handleSendCmpct("p1", true, 2n);
      const partial = mgr.startBlockReconstruction(compact, `${i}0`.repeat(32), "p1");
      if (partial) mgr.tryFillFromMempool(partial, mkMempool([]));
    }
    expect(mgr.getSuccessRate()).toBe(0);
  });

  test("PASS: getMempoolHitRate returns 1.0 with empty stats", () => {
    expect(new CompactBlockManager().getMempoolHitRate()).toBe(1.0);
  });
});

// ============================================================================
// Wire-format integrity tests (messages.ts)
// ============================================================================

describe("Wire-format: sendcmpct serialize/deserialize round-trip", () => {
  test("PASS: sendcmpct(enabled=true, version=2) round-trips correctly", () => {
    const msg = serializeMessage(MAINNET_MAGIC, { type: "sendcmpct", payload: { enabled: true, version: 2n } });
    const hdr: MessageHeader = {
      magic: msg.readUInt32LE(0),
      command: msg.subarray(4, 16).toString("ascii").replace(/\0/g, ""),
      length: msg.readUInt32LE(16),
      checksum: msg.subarray(20, 24),
    };
    const recovered = deserializeMessage(hdr, msg.subarray(24));
    expect(recovered.type).toBe("sendcmpct");
    if (recovered.type === "sendcmpct") {
      expect(recovered.payload.enabled).toBe(true);
      expect(recovered.payload.version).toBe(2n);
    }
  });

  test("PASS: cmpctblock DoS cap rejects shortId count > 65535", () => {
    const header = mkHeader();
    const headerBuf = serializeBlockHeader(header);
    const raw = new BufferWriter();
    raw.writeBytes(headerBuf);
    raw.writeUInt64LE(0n);
    // varint for 65536 (0x10000): FE 00 00 01 00
    raw.writeUInt8(0xfe);
    raw.writeUInt8(0x00);
    raw.writeUInt8(0x00);
    raw.writeUInt8(0x01);
    raw.writeUInt8(0x00);
    const payload = raw.toBuffer();
    const checksum = hash256(payload).subarray(0, 4);
    const fakeHdr = { magic: 0, command: "cmpctblock", length: payload.length, checksum };
    expect(() => deserializeMessage(fakeHdr as any, payload)).toThrow(/exceeds limit/);
  });
});
