/**
 * W126 — BIP-152 Compact Blocks parity audit (hotbuns).
 *
 * Reference:
 *   - bitcoin-core/src/blockencodings.cpp + .h
 *   - bitcoin-core/src/net_processing.cpp (SENDCMPCT / CMPCTBLOCK /
 *     GETBLOCKTXN / BLOCKTXN handlers, MaybeSetPeerAsAnnouncingHeaderAndIDs,
 *     NewPoWValidBlock, SendBlockTransactions, vExtraTxnForCompact).
 *   - bitcoin-core/src/node/protocol_version.h
 *     (SHORT_IDS_BLOCKS_VERSION = 70014, INVALID_CB_NO_BAN_VERSION = 70015).
 *   - bitcoin-core/src/consensus/validation.cpp (IsBlockMutated).
 *   - BIP-152.
 *
 * 30 audit gates, classified PRESENT / PARTIAL / MISSING.
 *
 * Audit summary (see audit/w126_bip152_compact_blocks.md):
 *   8 PRESENT / 6 PARTIAL / 16 MISSING / 21 bugs.
 *   P0-CDIV  = 5 (BIP-152 protocol not running end-to-end)
 *   P0       = 3 (wrong default / wrong invariant)
 *   P0-WIRE  = 3 (decoder hardening)
 *   P1       = 7 (DoS scoring + protocol-version gates)
 *   P2       = 3 (internal-inconsistency / dead-helper / comment-as-confession)
 *
 * KEY FINDING (BUG-1, 34th-streak dead-helper-at-call-site):
 *   CompactBlockManager + PartiallyDownloadedBlock + createCompactBlockFromBlock
 *   + createBlockTxnResponse + deriveSipHashKeys are all wholly unreferenced
 *   from any code path that actually runs at runtime.  src/sync/blocks.ts
 *   handles every incoming `cmpctblock` by falling back to a full-block
 *   `getdata`, defeating the BIP-152 bandwidth-savings entirely.  The
 *   comment at sync/blocks.ts:669 literally names CompactBlockManager as
 *   a "dead helper" — canonical "test-comment-as-confession" pattern.
 *
 * No production code changes in this wave.
 *
 * Running: bun test src/__tests__/w126_bip152_compact_blocks.test.ts
 */

import { describe, it, test, expect } from "bun:test";
import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

import {
  SHORT_TXID_LENGTH,
  COMPACT_BLOCK_VERSION_1,
  COMPACT_BLOCK_VERSION_2,
  MAX_HIGH_BANDWIDTH_PEERS,
  MAX_EXTRA_TXN,
  MAX_CMPCTBLOCK_DEPTH,
  MAX_BLOCKTXN_DEPTH,
  CompactBlockManager,
  PartiallyDownloadedBlock,
  ReadStatus,
  createCompactBlockFromBlock,
  createBlockTxnResponse,
  deriveSipHashKeys,
  computeShortTxId,
} from "../p2p/compact_blocks.js";

// ---------------------------------------------------------------------------
// Source-level fixtures (audit framework reads the source files to verify
// presence / absence of identifiers and call-site patterns).
// ---------------------------------------------------------------------------

const __dirname = dirname(fileURLToPath(import.meta.url));
const SRC = resolve(__dirname, "..");
const COMPACT_BLOCKS_SRC = readFileSync(
  resolve(SRC, "p2p", "compact_blocks.ts"),
  "utf8"
);
const SYNC_BLOCKS_SRC = readFileSync(resolve(SRC, "sync", "blocks.ts"), "utf8");
const PEER_SRC = readFileSync(resolve(SRC, "p2p", "peer.ts"), "utf8");
const MANAGER_SRC = readFileSync(resolve(SRC, "p2p", "manager.ts"), "utf8");
const MESSAGES_SRC = readFileSync(resolve(SRC, "p2p", "messages.ts"), "utf8");

// =============================================================================
// G1 — SipHash-2-4 short-id derivation present (PRESENT)
// =============================================================================
describe("W126-G1: SipHash-2-4 short-id derivation — PRESENT", () => {
  it("compact_blocks.ts exports SHORT_TXID_LENGTH = 6 (Core blockencodings.h:103)", () => {
    expect(SHORT_TXID_LENGTH).toBe(6);
  });
  it("deriveSipHashKeys + computeShortTxId both exported", () => {
    expect(typeof deriveSipHashKeys).toBe("function");
    expect(typeof computeShortTxId).toBe("function");
  });
  it("deriveSipHashKeys returns two 64-bit bigint keys", () => {
    const header = Buffer.alloc(80, 0xaa);
    const [k0, k1] = deriveSipHashKeys(header, 0xdeadn);
    expect(typeof k0).toBe("bigint");
    expect(typeof k1).toBe("bigint");
  });
  it("computeShortTxId emits 6-byte buffer", () => {
    const wtxid = Buffer.alloc(32, 0xab);
    const shortId = computeShortTxId(0n, 0n, wtxid);
    expect(shortId.length).toBe(6);
  });
});

// =============================================================================
// G2 — uint16_t cap on PrefilledTx absolute index (PARTIAL — BUG-10)
// =============================================================================
describe("W126-G2: uint16_t cap on PrefilledTx absolute index — PARTIAL (BUG-10)", () => {
  it("compact_blocks.ts:425 enforces absoluteIndex > 0xffff → INVALID", () => {
    expect(COMPACT_BLOCKS_SRC).toMatch(/absoluteIndex\s*>\s*0xffff/);
  });
  it.skip("BUG-10: PrefilledTx.index docstring mis-describes the field as 'differentially encoded' but the deserialiser stores absolute index — TODO rename", () => {
    // Documentation drift: messages.ts:253-256 says "differentially encoded
    // index" but after deserialisation the field is absolute.  Cosmetic but
    // misleading to readers.
    expect(MESSAGES_SRC).not.toMatch(/differentially encoded index/);
  });
});

// =============================================================================
// G3 — Multi-tx prefilling beyond coinbase (PARTIAL — BUG-8)
// =============================================================================
describe("W126-G3: multi-tx prefilling beyond coinbase — PARTIAL (BUG-8)", () => {
  it("createCompactBlockFromBlock accepts a peerMempoolTxids param", () => {
    expect(COMPACT_BLOCKS_SRC).toContain(
      "peerMempoolTxids: Set<string>"
    );
  });
  it.skip("BUG-8: hotbuns does not track per-peer mempool reception, so peerMempoolTxids is always empty in practice — TODO wire peer-mempool tracker", () => {
    // Per Core blockencodings.cpp:27 TODO comment, predictive prefilling is
    // a known optimization opportunity.  Hotbuns has the parameter but no
    // caller passes a real set.
    const callSites = COMPACT_BLOCKS_SRC.match(
      /createCompactBlockFromBlock\([^)]*peerMempoolTxids/g
    );
    expect(callSites && callSites.length).toBeGreaterThan(0);
  });
});

// =============================================================================
// G4 — cmpctblock message types defined / serialised (PRESENT)
// =============================================================================
describe("W126-G4: cmpctblock message types defined / serialised — PRESENT", () => {
  it("messages.ts defines CmpctBlockPayload / GetBlockTxnPayload / BlockTxnPayload / SendCmpctPayload", () => {
    expect(MESSAGES_SRC).toContain("interface CmpctBlockPayload");
    expect(MESSAGES_SRC).toContain("interface GetBlockTxnPayload");
    expect(MESSAGES_SRC).toContain("interface BlockTxnPayload");
    expect(MESSAGES_SRC).toContain("interface SendCmpctPayload");
  });
  it("all four commands appear in the dispatch table (serialise + deserialise)", () => {
    for (const cmd of ["sendcmpct", "cmpctblock", "getblocktxn", "blocktxn"]) {
      expect(MESSAGES_SRC).toContain(`case "${cmd}":`);
    }
  });
});

// =============================================================================
// G5 — Differential encoding of prefilled indices on the wire (PARTIAL — BUG-9)
// =============================================================================
describe("W126-G5: differential encoding of prefilled indices — PARTIAL (BUG-9)", () => {
  it("serializer at messages.ts:746 emits diff = index - lastIndex - 1", () => {
    expect(MESSAGES_SRC).toMatch(
      /diff\s*=\s*prefilled\.index\s*-\s*lastIndex\s*-\s*1/
    );
  });
  it("deserializer at messages.ts:1215 reconstructs absolute index", () => {
    expect(MESSAGES_SRC).toMatch(
      /const\s+index\s*=\s*lastIndex\s*\+\s*diff\s*\+\s*1/
    );
  });
  it.skip("BUG-9: deserializer accepts unbounded diff without uint16_t enforcement at the wire layer — TODO add hard cap", () => {
    // Core's DifferenceFormatter throws on uint64 overflow + extends to a
    // uint16 absolute-index check in InitData.  Hotbuns only checks absolute
    // index at InitData time; the wire-level decoder accepts any varint.
    expect(MESSAGES_SRC).toMatch(
      /if\s*\(index\s*>\s*0xffff\).*throw/s
    );
  });
});

// =============================================================================
// G6 — Outgoing sendcmpct gated by SHORT_IDS_BLOCKS_VERSION (MISSING — BUG-17)
// =============================================================================
describe("W126-G6: outgoing sendcmpct gated by SHORT_IDS_BLOCKS_VERSION — MISSING (BUG-17)", () => {
  it.skip("BUG-17: peer.ts sends sendcmpct unconditionally without checking peer.commonVersion >= 70014 — TODO add gate", () => {
    // Core: net_processing.cpp:3864-3870
    expect(PEER_SRC).toMatch(
      /(commonVersion|protocolVersion|GetCommonVersion).*>=.*70014/
    );
  });
});

// =============================================================================
// G7 — Fast-announce gated by INVALID_CB_NO_BAN_VERSION (MISSING — BUG-18)
// =============================================================================
describe("W126-G7: fast-announce gated by INVALID_CB_NO_BAN_VERSION — MISSING (BUG-18)", () => {
  it.skip("BUG-18: no fast-announce path exists, so no version gate exists — TODO add NewPoWValidBlock + gate", () => {
    // Core: net_processing.cpp:2103-2152 + 2136 (the version gate inside the loop).
    expect(SYNC_BLOCKS_SRC).toMatch(/70015|INVALID_CB_NO_BAN_VERSION/);
  });
});

// =============================================================================
// G8 — Only CMPCTBLOCKS_VERSION = 2 accepted on the wire (PRESENT)
// =============================================================================
describe("W126-G8: only version 2 accepted on receipt — PRESENT", () => {
  it("compact_blocks.ts:756 drops sendcmpct for any version != COMPACT_BLOCK_VERSION_2", () => {
    expect(COMPACT_BLOCKS_SRC).toMatch(
      /if\s*\(version\s*!==\s*COMPACT_BLOCK_VERSION_2\)/
    );
  });
  test("CompactBlockManager.handleSendCmpct drops v1 silently", () => {
    const mgr = new CompactBlockManager();
    mgr.handleSendCmpct("peer-A", true, COMPACT_BLOCK_VERSION_1);
    expect(mgr.peerSupportsCompact("peer-A")).toBe(false);
  });
  test("CompactBlockManager.handleSendCmpct accepts v2", () => {
    const mgr = new CompactBlockManager();
    mgr.handleSendCmpct("peer-A", true, COMPACT_BLOCK_VERSION_2);
    expect(mgr.peerSupportsCompact("peer-A")).toBe(true);
  });
});

// =============================================================================
// G9 — MAX_CMPCTBLOCK_DEPTH = 5 depth guard on receive (PRESENT)
// =============================================================================
describe("W126-G9: MAX_CMPCTBLOCK_DEPTH=5 depth guard on receive — PRESENT", () => {
  it("constant matches Core net_processing.cpp:138 (MAX_CMPCTBLOCK_DEPTH = 5)", () => {
    expect(MAX_CMPCTBLOCK_DEPTH).toBe(5);
  });
  it("sync/blocks.ts:655 checks depth > MAX_CMPCTBLOCK_DEPTH before reconstruction", () => {
    expect(SYNC_BLOCKS_SRC).toMatch(
      /depth\s*>\s*MAX_CMPCTBLOCK_DEPTH/
    );
  });
});

// =============================================================================
// G10 — MAX_BLOCKTXN_DEPTH = 10 depth guard on serve (PRESENT)
// =============================================================================
describe("W126-G10: MAX_BLOCKTXN_DEPTH=10 depth guard on serve — PRESENT", () => {
  it("constant matches Core net_processing.cpp:140 (MAX_BLOCKTXN_DEPTH = 10)", () => {
    expect(MAX_BLOCKTXN_DEPTH).toBe(10);
  });
  it("sync/blocks.ts:708 checks depth > MAX_BLOCKTXN_DEPTH before serving", () => {
    expect(SYNC_BLOCKS_SRC).toMatch(/depth\s*>\s*MAX_BLOCKTXN_DEPTH/);
  });
});

// =============================================================================
// G11 — MAX_HIGH_BANDWIDTH_PEERS = 3 LRU limit (PARTIAL — BUG-21)
// =============================================================================
describe("W126-G11: MAX_HIGH_BANDWIDTH_PEERS=3 LRU limit — PARTIAL (BUG-21)", () => {
  it("constant matches BIP-152 §High Bandwidth Mode (max 3 outbound HB peers)", () => {
    expect(MAX_HIGH_BANDWIDTH_PEERS).toBe(3);
  });
  test("addHighBandwidthPeer refuses a 4th peer", () => {
    const mgr = new CompactBlockManager();
    expect(mgr.addHighBandwidthPeer("a")).toBe(true);
    expect(mgr.addHighBandwidthPeer("b")).toBe(true);
    expect(mgr.addHighBandwidthPeer("c")).toBe(true);
    expect(mgr.addHighBandwidthPeer("d")).toBe(false);
  });
  it.skip("BUG-21: removePeer is never called from peer-disconnect dispatch — memory leak under churn — TODO wire", () => {
    // CompactBlockManager.removePeer at compact_blocks.ts:971-975 cleans
    // up peerStates + highBandwidthPeers but nothing in manager.ts /
    // peer.ts / sync/blocks.ts invokes it on disconnect.
    expect(MANAGER_SRC + PEER_SRC + SYNC_BLOCKS_SRC).toMatch(
      /\.removePeer\s*\(/
    );
  });
});

// =============================================================================
// G12 — IsBlockMutated check in FillBlock (PRESENT)
// =============================================================================
describe("W126-G12: IsBlockMutated check in FillBlock — PRESENT", () => {
  it("PartiallyDownloadedBlock.getBlock invokes checkWitnessMalleation before returning a Block", () => {
    expect(COMPACT_BLOCKS_SRC).toContain("checkWitnessMalleation(block");
  });
  it("getBlock returns null on malleation (Core: READ_STATUS_FAILED Possible Short ID collision)", () => {
    expect(COMPACT_BLOCKS_SRC).toMatch(
      /if\s*\(!malleation\.valid\)[\s\S]*?return\s+null/
    );
  });
});

// =============================================================================
// G13 — Bucket-size-12 DoS guard in InitData (PRESENT)
// =============================================================================
describe("W126-G13: bucket-size-12 DoS guard in InitData — PRESENT", () => {
  it("compact_blocks.ts:475 enforces bucket-size >= 12 → READ_STATUS_FAILED", () => {
    expect(COMPACT_BLOCKS_SRC).toMatch(
      /if\s*\(prev\s*>=\s*12\)[\s\S]*?return\s+ReadStatus\.FAILED/
    );
  });
});

// =============================================================================
// G14 — blocktxn dispatch handler (MISSING — BUG-3)
// =============================================================================
describe("W126-G14: blocktxn dispatch handler — MISSING (BUG-3)", () => {
  it("BUG-3: the blocktxn handler is an empty stub", () => {
    // The current handler is exactly the no-op body:
    //   (_peer, _msg) => { /* we fall back to full block download */ }
    expect(SYNC_BLOCKS_SRC).toMatch(
      /onMessage\("blocktxn",[\s\S]*?We fall back to full block download/
    );
  });
  it.skip("BUG-3: blocktxn handler should call CompactBlockManager.handleBlockTxn — TODO wire", () => {
    expect(SYNC_BLOCKS_SRC).toMatch(
      /onMessage\("blocktxn"[\s\S]{0,800}?handleBlockTxn/
    );
  });
});

// =============================================================================
// G15 — cmpctblock dispatch handler calls CompactBlockManager (MISSING — BUG-1)
// =============================================================================
describe("W126-G15: cmpctblock dispatch handler calls CompactBlockManager — MISSING (BUG-1, 34th-streak dead-helper)", () => {
  it("BUG-1: cmpctblock dispatch path falls back to full-block getdata", () => {
    // Existing code at sync/blocks.ts:643-680 logs and then issues
    // MSG_WITNESS_BLOCK getdata.  This is the smoking gun.
    expect(SYNC_BLOCKS_SRC).toMatch(
      /onMessage\("cmpctblock",[\s\S]*?falling back to full block request/
    );
  });
  it("BUG-1: CompactBlockManager is unreferenced from sync/blocks.ts EXCEPT in the comment-as-confession", () => {
    // The only occurrence of "CompactBlockManager" in sync/blocks.ts is the
    // comment at line 669 explicitly naming it as a dead helper.  There is
    // no import, no instantiation, no method invocation.
    const occurrences = SYNC_BLOCKS_SRC.match(/CompactBlockManager/g) || [];
    expect(occurrences.length).toBe(1);
    expect(SYNC_BLOCKS_SRC).not.toMatch(/new\s+CompactBlockManager/);
    expect(SYNC_BLOCKS_SRC).not.toContain("new PartiallyDownloadedBlock");
    expect(SYNC_BLOCKS_SRC).not.toContain("startBlockReconstruction");
  });
  it("BUG-1: CompactBlockManager is unreferenced from p2p/manager.ts and p2p/peer.ts as well", () => {
    expect(MANAGER_SRC).not.toContain("CompactBlockManager");
    expect(PEER_SRC).not.toContain("CompactBlockManager");
  });
  it.skip("BUG-1: cmpctblock dispatch SHOULD call manager.startBlockReconstruction — TODO wire", () => {
    expect(SYNC_BLOCKS_SRC).toMatch(
      /onMessage\("cmpctblock"[\s\S]{0,1500}?startBlockReconstruction/
    );
  });
});

// =============================================================================
// G16 — sendcmpct dispatch handler updates peer state (MISSING — BUG-4)
// =============================================================================
describe("W126-G16: sendcmpct dispatch handler updates peer state — MISSING (BUG-4)", () => {
  it("BUG-4: sendcmpct handler is log-only — never stores peer's HB / version state", () => {
    // sync/blocks.ts:683-690 — only console.log; no state mutation
    expect(SYNC_BLOCKS_SRC).toMatch(
      /onMessage\("sendcmpct",[\s\S]*?supports compact blocks/
    );
    // Confirm the handler body does NOT mutate any per-peer state structure
    const idx = SYNC_BLOCKS_SRC.indexOf('onMessage("sendcmpct"');
    const window = SYNC_BLOCKS_SRC.slice(idx, idx + 400);
    expect(window).not.toContain("handleSendCmpct");
    expect(window).not.toContain("setPeerSupportsCompact");
  });
  it.skip("BUG-4: handler SHOULD call CompactBlockManager.handleSendCmpct — TODO wire", () => {
    expect(SYNC_BLOCKS_SRC).toMatch(
      /onMessage\("sendcmpct"[\s\S]{0,400}?handleSendCmpct/
    );
  });
});

// =============================================================================
// G17 — MaybeSetPeerAsAnnouncingHeaderAndIDs equivalent (MISSING — BUG-7)
// =============================================================================
describe("W126-G17: MaybeSetPeerAsAnnouncingHeaderAndIDs equivalent — MISSING (BUG-7)", () => {
  it.skip("BUG-7: no chain-validation hook promotes peers to HB after their last block validated cleanly — TODO add BlockChecked equivalent", () => {
    // Core: net_processing.cpp:1272-1329 — promotion logic + the 3-slot LRU.
    expect(MANAGER_SRC + SYNC_BLOCKS_SRC).toMatch(
      /MaybeSetPeerAsAnnouncing|maybeSetPeerAsAnnouncing|promoteToHighBandwidth/
    );
  });
});

// =============================================================================
// G18 — getblocktxn serve path calls createBlockTxnResponse (MISSING — BUG-2)
// =============================================================================
describe("W126-G18: getblocktxn serve path — MISSING (BUG-2)", () => {
  it("BUG-2: the getblocktxn handler is a stub that returns without responding", () => {
    expect(SYNC_BLOCKS_SRC).toMatch(
      /onMessage\("getblocktxn"[\s\S]*?We don't serve compact blocks yet/
    );
  });
  it("BUG-2: createBlockTxnResponse exists but is never called from any non-test code path", () => {
    expect(COMPACT_BLOCKS_SRC).toContain("export function createBlockTxnResponse");
    expect(SYNC_BLOCKS_SRC).not.toContain("createBlockTxnResponse");
    expect(MANAGER_SRC).not.toContain("createBlockTxnResponse");
    expect(PEER_SRC).not.toContain("createBlockTxnResponse");
  });
  it.skip("BUG-2: getblocktxn handler SHOULD call createBlockTxnResponse + send blocktxn — TODO wire", () => {
    expect(SYNC_BLOCKS_SRC).toMatch(
      /onMessage\("getblocktxn"[\s\S]{0,800}?createBlockTxnResponse/
    );
  });
});

// =============================================================================
// G19 — HB-peer outgoing sendcmpct(true, 2) after promotion (MISSING — BUG-6)
// =============================================================================
describe("W126-G19: HB-peer outgoing sendcmpct(true, 2) after promotion — MISSING (BUG-6)", () => {
  it("peer.ts:1326-1329 announces sendcmpct(enabled=false, version=2)", () => {
    expect(PEER_SRC).toMatch(
      /sendcmpct[\s\S]*?enabled:\s*false[\s\S]*?version:\s*2n/
    );
  });
  it.skip("BUG-6: no code path resends sendcmpct(true, 2) after promoting a peer to HB — TODO add promotion send", () => {
    // Core: net_processing.cpp:1323 — MakeAndPushMessage(*pfrom, NetMsgType::SENDCMPCT, /*high_bandwidth=*/true, /*version=*/CMPCTBLOCKS_VERSION)
    const promotionSends = (PEER_SRC + MANAGER_SRC + SYNC_BLOCKS_SRC).match(
      /sendcmpct[\s\S]{0,80}enabled:\s*true/g
    );
    expect(promotionSends && promotionSends.length).toBeGreaterThan(0);
  });
});

// =============================================================================
// G20 — BlockChecked → HB-peer selection hook (MISSING — BUG-7 follow-on)
// =============================================================================
describe("W126-G20: BlockChecked → HB-peer selection hook — MISSING (BUG-7)", () => {
  it.skip("BUG-7: no equivalent of Core's BlockChecked callback that calls MaybeSetPeerAsAnnouncing on cleanly-validated source peer — TODO wire", () => {
    // Core: net_processing.cpp:2196-2225 (BlockChecked) calls
    // MaybeSetPeerAsAnnouncingHeaderAndIDs(it->second.first) after a block
    // from peer X validates cleanly and we are not in IBD.
    expect(SYNC_BLOCKS_SRC + MANAGER_SRC).toMatch(
      /BlockChecked|blockChecked|onBlockChecked|maybeSetPeerAsAnnouncing/
    );
  });
});

// =============================================================================
// G21 — removePeer called on peer disconnect (MISSING — BUG-21)
// =============================================================================
describe("W126-G21: removePeer called on peer disconnect — MISSING (BUG-21)", () => {
  it.skip("BUG-21: nothing in manager.ts / peer.ts / sync/blocks.ts calls CompactBlockManager.removePeer — TODO wire on disconnect", () => {
    // CompactBlockManager.peerStates and highBandwidthPeers will grow
    // unboundedly under peer churn once BUG-1 is fixed.
    expect(MANAGER_SRC + PEER_SRC + SYNC_BLOCKS_SRC).toMatch(
      /CompactBlockManager[\s\S]{0,200}\.removePeer/
    );
  });
});

// =============================================================================
// G22 — Misbehaving(peer, "invalid compact block") on INVALID (MISSING — BUG-12)
// =============================================================================
describe("W126-G22: Misbehaving on INVALID compact block — MISSING (BUG-12)", () => {
  it.skip("BUG-12: startBlockReconstruction returns null but never invokes peer.misbehaving on INVALID — TODO add scoring callback", () => {
    // Core: net_processing.cpp:4594 — Misbehaving(peer, "invalid compact block")
    // The helper at compact_blocks.ts:860-894 has no peer misbehaving callback parameter.
    expect(COMPACT_BLOCKS_SRC).toMatch(
      /startBlockReconstruction[\s\S]{0,400}?misbehaving/
    );
  });
});

// =============================================================================
// G23 — Misbehaving on out-of-bounds getblocktxn indices (MISSING — BUG-13)
// =============================================================================
describe("W126-G23: Misbehaving on out-of-bounds getblocktxn indices — MISSING (BUG-13)", () => {
  it.skip("BUG-13: createBlockTxnResponse returns null silently on idx >= tx count — should signal misbehaving to call site — TODO redesign return shape", () => {
    // Core: net_processing.cpp:2603 — Misbehaving(peer, "getblocktxn with out-of-bounds tx indices")
    expect(COMPACT_BLOCKS_SRC).toMatch(
      /createBlockTxnResponse[\s\S]{0,400}?misbehav/i
    );
  });
});

// =============================================================================
// G24 — NewPoWValidBlock fast-announce path (MISSING — BUG-5)
// =============================================================================
describe("W126-G24: NewPoWValidBlock fast-announce path — MISSING (BUG-5)", () => {
  it.skip("BUG-5: no fast-announce of new-tip compact block to HB peers — TODO wire NewPoWValidBlock equivalent", () => {
    // Core: net_processing.cpp:2103-2152.  createCompactBlockFromBlock is
    // the helper that would do the encoding but is unused outside tests.
    expect(SYNC_BLOCKS_SRC + MANAGER_SRC).toMatch(
      /NewPoWValidBlock|newPoWValidBlock|fastAnnounceCompactBlock/
    );
  });
});

// =============================================================================
// G25 — compact_blocks.ts referenced by chain/sync code path (MISSING — BUG-19)
// =============================================================================
describe("W126-G25: compact_blocks.ts referenced by runtime code — MISSING (BUG-19 comment-as-confession)", () => {
  it("BUG-19: sync/blocks.ts imports MAX_CMPCTBLOCK_DEPTH + MAX_BLOCKTXN_DEPTH only — never the class", () => {
    // The only thing sync/blocks.ts imports from compact_blocks.ts is two
    // constants for the depth guards.  The class, the PartiallyDownloadedBlock,
    // and all helpers are unimported.
    expect(SYNC_BLOCKS_SRC).toMatch(
      /import\s*\{\s*MAX_CMPCTBLOCK_DEPTH[\s\S]{0,80}?MAX_BLOCKTXN_DEPTH[\s\S]{0,40}?\}\s*from\s*"\.\.\/p2p\/compact_blocks/
    );
  });
  it("BUG-19: production code prose names the dead helper outright (canonical comment-as-confession)", () => {
    // From sync/blocks.ts:669:
    //   "BUG-2/BUG-3 — CompactBlockManager dead helper; wiring it is out of scope for FIX-42"
    expect(SYNC_BLOCKS_SRC).toContain("CompactBlockManager");
    expect(SYNC_BLOCKS_SRC).toContain("dead helper");
    expect(SYNC_BLOCKS_SRC).toContain("FIX-42");
  });
  it("BUG-19: a second comment-as-confession at the getblocktxn handler", () => {
    expect(SYNC_BLOCKS_SRC).toContain("getblocktxn serve path is a stub");
  });
});

// =============================================================================
// G26 — weWantHighBandwidth state field read after write (MISSING — BUG-20)
// =============================================================================
describe("W126-G26: weWantHighBandwidth state field is read after write — MISSING (BUG-20)", () => {
  it("BUG-20: sentSendCmpct writes weWantHighBandwidth but no code path reads it", () => {
    const writes = COMPACT_BLOCKS_SRC.match(/weWantHighBandwidth\s*=/g);
    expect(writes && writes.length).toBeGreaterThan(0);
  });
  it.skip("BUG-20: no code reads state.weWantHighBandwidth to decide HB-peer behaviour — TODO consult the flag", () => {
    // Field exists, is set, never consulted.  Field-policy mismatch.
    const reads = COMPACT_BLOCKS_SRC.match(
      /(state|this)\.weWantHighBandwidth(?!\s*=)/g
    );
    expect(reads && reads.length).toBeGreaterThan(0);
  });
});

// =============================================================================
// G27 — Strict-increasing decoder check on getblocktxn indices (MISSING — BUG-11)
// =============================================================================
describe("W126-G27: strict-increasing decoder check on getblocktxn indices — MISSING (BUG-11)", () => {
  it("deserializeGetBlockTxnPayload accumulates diff + 1 (matches Core DifferenceFormatter shape)", () => {
    expect(MESSAGES_SRC).toMatch(
      /deserializeGetBlockTxnPayload[\s\S]{0,400}?diff\s*\+\s*1/
    );
  });
  it.skip("BUG-11: no overflow / strict-increasing assertion — Core Assume(req.indexes[i] > req.indexes[i-1]) at net_processing.cpp:4250-4252 — TODO add assertion", () => {
    expect(MESSAGES_SRC).toMatch(
      /deserializeGetBlockTxnPayload[\s\S]{0,400}?(strict|increasing|>\s*lastIndex)/
    );
  });
});

// =============================================================================
// G28 — Misbehaving on "previous reconstruction attempt failed" (MISSING — BUG-14)
// =============================================================================
describe("W126-G28: Misbehaving on previous-reconstruction-attempt-failed — MISSING (BUG-14)", () => {
  it.skip("BUG-14: empty blocktxn handler can't detect replay — TODO add header.IsNull() check + Misbehaving", () => {
    // Core: net_processing.cpp:3476 — Misbehaving(peer, "previous compact
    // block reconstruction attempt failed") when partialBlock.header.IsNull()
    expect(SYNC_BLOCKS_SRC).toMatch(
      /onMessage\("blocktxn"[\s\S]{0,800}?misbehav/i
    );
  });
});

// =============================================================================
// G29 — Misbehaving on blocktxn with non-matching txs (MISSING — BUG-15)
// =============================================================================
describe("W126-G29: Misbehaving on blocktxn with non-matching txs — MISSING (BUG-15)", () => {
  it.skip("BUG-15: empty blocktxn handler doesn't validate response shape — TODO add FillBlock + Misbehaving on READ_STATUS_INVALID", () => {
    // Core: net_processing.cpp:3487 — Misbehaving(peer, "invalid compact
    // block/non-matching block transactions") on READ_STATUS_INVALID.
    expect(SYNC_BLOCKS_SRC).toMatch(
      /onMessage\("blocktxn"[\s\S]{0,800}?non-matching block transactions/
    );
  });
});

// =============================================================================
// G30 — vExtraTxnForCompact ring buffer maintained (MISSING — BUG-16)
// =============================================================================
describe("W126-G30: vExtraTxnForCompact ring buffer maintained — MISSING (BUG-16)", () => {
  it("MAX_EXTRA_TXN constant is exported (matches Core m_opts.max_extra_txs default 100)", () => {
    expect(MAX_EXTRA_TXN).toBe(100);
  });
  it("fillFromMempool accepts an extraTxn parameter (Core blockencodings.cpp:147-176)", () => {
    expect(COMPACT_BLOCKS_SRC).toContain("extraTxn: Transaction[]");
  });
  it.skip("BUG-16: no chain-event source maintains a ring buffer of recently-rejected / orphan / replaced txs — TODO wire", () => {
    // Core: net_processing.cpp:997-999 (vector field) + 1887-1890 (insertion).
    // Nothing in hotbuns populates this from mempool / orphan / reconsider events.
    expect(MANAGER_SRC + SYNC_BLOCKS_SRC).toMatch(
      /(vExtraTxnForCompact|extraTxnRingBuffer|recordRecentlyRejected)/
    );
  });
});

// =============================================================================
// Status summary (informational; assertion is the cumulative pass/fail above).
// =============================================================================
describe("W126 status summary", () => {
  it("audit document exists at audit/w126_bip152_compact_blocks.md", () => {
    const audit = readFileSync(
      resolve(SRC, "..", "audit", "w126_bip152_compact_blocks.md"),
      "utf8"
    );
    expect(audit).toContain("W126 — BIP-152 Compact Blocks parity audit");
    expect(audit).toContain("21 BUGS / 30 gates");
  });
  it("audit lists the dead-helper finding as BUG-1 (the 34th-streak signature finding)", () => {
    const audit = readFileSync(
      resolve(SRC, "..", "audit", "w126_bip152_compact_blocks.md"),
      "utf8"
    );
    expect(audit).toContain("CompactBlockManager` is never wired");
    expect(audit).toContain("dead-helper");
  });
  it("audit catalogues exactly four message-handler stub bugs (cmpctblock, sendcmpct, getblocktxn, blocktxn)", () => {
    const audit = readFileSync(
      resolve(SRC, "..", "audit", "w126_bip152_compact_blocks.md"),
      "utf8"
    );
    expect(audit).toContain("BUG-1");
    expect(audit).toContain("BUG-2");
    expect(audit).toContain("BUG-3");
    expect(audit).toContain("BUG-4");
  });
});
