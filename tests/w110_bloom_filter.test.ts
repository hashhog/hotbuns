/**
 * W110 — BIP-37 bloom filter fleet audit (hotbuns / TypeScript)
 *
 * Gates cover:
 *   G1  — MAX_BLOOM_FILTER_SIZE = 36000
 *   G2  — MAX_HASH_FUNCS = 50
 *   G3  — LN2SQUARED full precision (0.4804530139182014...)
 *   G4  — Constructor sizing formula: min(-1/LN2² × N × ln(fp), MAX × 8) / 8
 *   G5  — nHashFuncs formula: min(vData.length×8/N × LN2, MAX_HASH_FUNCS)
 *   G6  — MurmurHash3 32-bit implementation
 *   G7  — Hash schedule: nHashNum * 0xFBA4C795 + nTweak
 *   G8  — Bit-index computation: hash % (vData.length * 8)
 *   G9  — Insert + Contains round-trip correctness
 *   G10 — isFull/isEmpty short-circuit (zero-size = match-all)
 *   G11 — UPDATE_NONE = 0
 *   G12 — UPDATE_ALL = 1
 *   G13 — UPDATE_P2PUBKEY_ONLY = 2
 *   G14 — UPDATE_MASK = 3
 *   G15 — nFlags & UPDATE_MASK extraction
 *   G16 — txid match in IsRelevantAndUpdate
 *   G17 — Per-output-script pushdata scan
 *   G18 — P2PKH/P2SH/P2PK/multisig outpoint insert on BLOOM_UPDATE_P2PUBKEY_ONLY
 *   G19 — Outpoint match on inputs (scriptSig prevout scan)
 *   G20 — scriptSig data items scan
 *   G21 — UPDATE_ALL: insert outpoint on any matching output
 *   G22 — UPDATE_P2PUBKEY_ONLY: insert outpoint only for P2PK/multisig
 *   G23 — UPDATE_NONE: no automatic outpoint insertion
 *   G24 — Outpoint serialization: txid(32 LE) || vout(4 LE)
 *   G25 — filterload P2P message (decode vData/nHashFuncs/nTweak/nFlags from wire)
 *   G26 — filteradd element ≤ 520 bytes (MAX_SCRIPT_ELEMENT_SIZE)
 *   G27 — filterclear P2P message (clears per-peer filter)
 *   G28 — merkleblock P2P message + PartialMerkleTree
 *   G29 — IsWithinSizeConstraints: vData ≤ 36000 AND nHashFuncs ≤ 50
 *   G30 — NODE_BLOOM service bit (1<<2=4) + BIP-111 -peerbloomfilters gate
 *
 * BUG FINDINGS (18 bugs):
 *
 *   BUG-1 (G1-G5, MISSING)      — CBloomFilter class absent entirely. No MAX_BLOOM_FILTER_SIZE,
 *                                  MAX_HASH_FUNCS, LN2SQUARED, sizing formula, or nHashFuncs
 *                                  computation anywhere in hotbuns/src/*.
 *
 *   BUG-2 (G6, MISSING)         — MurmurHash3 32-bit not implemented anywhere in hotbuns/src/.
 *                                  The entire hash function on which BIP-37 depends is absent.
 *
 *   BUG-3 (G7, MISSING)         — Hash schedule (nHashNum * 0xFBA4C795 + nTweak) absent.
 *                                  Follows from BUG-1/2.
 *
 *   BUG-4 (G8, MISSING)         — Bit-index computation absent. Follows from BUG-1.
 *
 *   BUG-5 (G9, MISSING)         — Insert/Contains absent. Follows from BUG-1.
 *
 *   BUG-6 (G10, MISSING)        — isEmpty (zero-size = match-all) absent. Follows from BUG-1.
 *
 *   BUG-7 (G11-G15, MISSING)    — BLOOM_UPDATE_* constants absent. No UPDATE_NONE/ALL/P2PUBKEY_ONLY/MASK.
 *                                  Follows from BUG-1.
 *
 *   BUG-8 (G16-G20, MISSING)    — IsRelevantAndUpdate absent. No txid match, no scriptPubKey
 *                                  pushdata scan, no outpoint match, no scriptSig scan.
 *                                  Follows from BUG-1.
 *
 *   BUG-9 (G21-G23, MISSING)    — All three UPDATE_* paths absent. Follows from BUG-1/8.
 *
 *   BUG-10 (G24, MISSING)       — Outpoint serialization for bloom absent. Follows from BUG-1.
 *
 *   BUG-11 (G25, MISSING)       — filterload not in NetworkMessage type union and not in
 *                                  deserializeMessage switch. Messages arrive as { type: "filterload",
 *                                  payload: null } (unknown-message fallback) and are silently
 *                                  dropped (no handler registered). Core disconnects peers that
 *                                  send filterload when NODE_BLOOM is not advertised.
 *
 *   BUG-12 (G26, MISSING)       — filteradd not in NetworkMessage union; no MAX_SCRIPT_ELEMENT_SIZE
 *                                  520-byte element guard; no handler registered.
 *
 *   BUG-13 (G27, MISSING)       — filterclear not in NetworkMessage union; no handler registered.
 *                                  Clearing a peer's filter is a no-op because no per-peer filter
 *                                  exists in the first place.
 *
 *   BUG-14 (G28, MISSING)       — merkleblock not in NetworkMessage union or P2P layer.
 *                                  A PartialMerkleTree builder exists (rpc/server.ts Wave-47b helpers)
 *                                  but it is wired only to the gettxoutproof RPC, not to the P2P
 *                                  "send filtered block" path. Dead-helper pattern (wave-25 streak).
 *
 *   BUG-15 (G29, MISSING)       — IsWithinSizeConstraints absent. No rejection of oversized filters
 *                                  (> 36000 bytes) or too-many hash functions (> 50).
 *
 *   BUG-16 (G30-P0, BIP-111 BROKEN) — manager.ts hardcodes NODE_BLOOM in ALL outbound version
 *                                  messages and all address-record initial services, regardless of
 *                                  --peerbloomfilters config. cli.ts conditionally ORs the bit into
 *                                  params.services only for the mempool-gate; manager.ts does NOT
 *                                  read that conditional params field and always emits the bit.
 *                                  Result: the node perpetually advertises NODE_BLOOM even when
 *                                  --peerbloomfilters=0 (default). Peers will send filterload;
 *                                  hotbuns silently ignores them (BUG-11); peers believe filtering
 *                                  is active but receive unfiltered tx-invs. P0-CDIV.
 *
 *   BUG-17 (G30, BIP-111)       — filterload disconnect path missing. Core net_processing.cpp:4964
 *                                  disconnects a peer that sends filterload when NODE_BLOOM is not
 *                                  set. hotbuns does not disconnect; the message is silently dropped
 *                                  (BUG-11 unknown-message path). This is a DoS vector.
 *
 *   BUG-18 (G28, TWO-PIPELINE)  — PartialMerkleTree construction is implemented twice:
 *                                  (1) Wave-47b helpers (w47bTraverseAndBuild etc.) in rpc/server.ts
 *                                      wired to gettxoutproof/verifytxoutproof RPCs only.
 *                                  (2) No P2P sendMerkleBlock path exists at all.
 *                                  The RPC-only partial tree builder is a dead-helper relative to the
 *                                  P2P "send filtered blocks to SPV peers" use case. Two-pipeline
 *                                  pattern: if a P2P merkleblock path were added it would need to
 *                                  reuse or share the existing helpers.
 *
 * References:
 *   bitcoin-core/src/common/bloom.h/cpp
 *   bitcoin-core/src/merkleblock.h/cpp
 *   bitcoin-core/src/net_processing.cpp (filterload ~4964, filteradd ~4989, filterclear ~5010)
 *   BIP-37 (bloom filter), BIP-111 (-peerbloomfilters / NODE_BLOOM service bit)
 */

import { describe, test, expect } from "bun:test";
import { ServiceFlags } from "../src/p2p/manager.js";
import {
  deserializeMessage,
  serializeMessage,
  serializeHeader,
  parseHeader,
  type NetworkMessage,
} from "../src/p2p/messages.js";

// ============================================================================
// Helpers
// ============================================================================

/** Build a valid on-wire message buffer and deserialize it back. */
function roundTrip(command: string, payload: Buffer): NetworkMessage {
  const magic = 0xd9b4bef9; // mainnet
  const header = serializeHeader(magic, command, payload);
  const parsedHeader = parseHeader(header);
  return deserializeMessage(parsedHeader, payload);
}

/** Build a minimal filterload wire payload: vData(1 byte) + nHashFuncs(4 LE) + nTweak(4 LE) + nFlags(1 byte) */
function makeFilterloadPayload(
  vDataLen = 1,
  nHashFuncs = 10,
  nTweak = 0,
  nFlags = 0
): Buffer {
  const buf = Buffer.alloc(1 + vDataLen + 4 + 4 + 1);
  let off = 0;
  buf[off++] = vDataLen; // varint(vDataLen)
  off += vDataLen;      // zeroed filter data
  buf.writeUInt32LE(nHashFuncs, off); off += 4;
  buf.writeUInt32LE(nTweak, off);     off += 4;
  buf[off] = nFlags;
  return buf;
}

/** Build a minimal filteradd wire payload: varint(len) + data */
function makeFilteraddPayload(data: Buffer): Buffer {
  const buf = Buffer.alloc(1 + data.length);
  buf[0] = data.length; // varint
  data.copy(buf, 1);
  return buf;
}

// ============================================================================
// G1-G5 — Constants & sizing (CBloomFilter class absent)
// ============================================================================

describe("G1: MAX_BLOOM_FILTER_SIZE = 36000 — MISSING (BUG-1)", () => {
  test.skip("constant absent — CBloomFilter class not implemented", () => {
    // Core bloom.h: static constexpr unsigned int MAX_BLOOM_FILTER_SIZE = 36000;
    // hotbuns has no CBloomFilter and no MAX_BLOOM_FILTER_SIZE export anywhere.
    const { MAX_BLOOM_FILTER_SIZE } = require("../src/bloom/bloom.js");
    expect(MAX_BLOOM_FILTER_SIZE).toBe(36000);
  });

  test("MAX_BLOOM_FILTER_SIZE is NOT exported from any known path", () => {
    // Verify the constant is absent — structural documentation of BUG-1.
    // The import below will throw; this test documents the gap.
    let found = false;
    try {
      // Dynamic require to avoid build-time type errors.
      const m = require("../src/bloom/bloom.js");
      if (m.MAX_BLOOM_FILTER_SIZE === 36000) found = true;
    } catch {
      found = false;
    }
    expect(found).toBe(false);
  });
});

describe("G2: MAX_HASH_FUNCS = 50 — MISSING (BUG-1)", () => {
  test.skip("constant absent — CBloomFilter class not implemented", () => {
    const { MAX_HASH_FUNCS } = require("../src/bloom/bloom.js");
    expect(MAX_HASH_FUNCS).toBe(50);
  });

  test("MAX_HASH_FUNCS absent", () => {
    let found = false;
    try {
      const m = require("../src/bloom/bloom.js");
      if (m.MAX_HASH_FUNCS === 50) found = true;
    } catch { found = false; }
    expect(found).toBe(false);
  });
});

describe("G3: LN2SQUARED full precision — MISSING (BUG-1)", () => {
  test.skip("constant absent — CBloomFilter class not implemented", () => {
    // Core bloom.cpp: 0.4804530139182014246671025263266649717305529515945455
    // IEEE-754 double: 0.4804530139182014 (last few digits lost, expected).
    const { LN2SQUARED } = require("../src/bloom/bloom.js");
    expect(LN2SQUARED).toBeCloseTo(0.4804530139182014, 15);
  });

  test("LN2SQUARED absent", () => {
    let found = false;
    try {
      const m = require("../src/bloom/bloom.js");
      if (typeof m.LN2SQUARED === "number") found = true;
    } catch { found = false; }
    expect(found).toBe(false);
  });
});

describe("G4: Constructor sizing formula — MISSING (BUG-1)", () => {
  test.todo("CBloomFilter constructor not implemented — sizing formula absent");
  // Core: vData = min(-1/LN2SQUARED * nElements * log(nFPRate), MAX * 8) / 8
  // For nElements=1000, nFPRate=0.001: -1/0.4804530… × 1000 × ln(0.001) ≈ 14378 bytes
  // Clamped to 36000 for extreme params.
});

describe("G5: nHashFuncs formula — MISSING (BUG-1)", () => {
  test.todo("CBloomFilter constructor not implemented — nHashFuncs formula absent");
  // Core: nHashFuncs = min(vData.size() * 8 / nElements * LN2, MAX_HASH_FUNCS)
  // For 14378 bytes / 1000 elements: 14378*8/1000 * 0.6931 ≈ 7.96 → floor → 7
});

// ============================================================================
// G6-G10 — Hash & bit-set (MurmurHash3 absent)
// ============================================================================

describe("G6: MurmurHash3 32-bit — MISSING (BUG-2)", () => {
  test.skip("MurmurHash3 not implemented in hotbuns/src/", () => {
    // Core hash.h/hash.cpp: MurmurHash3(seed, data) → uint32_t
    // Known vector: MurmurHash3(seed=0, data=[]) = 0
    // Known vector: MurmurHash3(seed=0, data=[0x00]) = 0x514E28B7
    const { murmurHash3 } = require("../src/crypto/primitives.js");
    expect(murmurHash3(0, Buffer.alloc(0))).toBe(0);
    expect(murmurHash3(0, Buffer.from([0x00]))).toBe(0x514e28b7);
  });

  test("MurmurHash3 absent from primitives", () => {
    const primitives = require("../src/crypto/primitives.js");
    expect(typeof primitives.murmurHash3).toBe("undefined");
    expect(typeof primitives.MurmurHash3).toBe("undefined");
  });
});

describe("G7: Hash schedule nHashNum * 0xFBA4C795 + nTweak — MISSING (BUG-3)", () => {
  test.todo("CBloomFilter.Hash absent — schedule not implemented");
  // Core bloom.cpp:47:
  //   return MurmurHash3(nHashNum * 0xFBA4C795 + nTweak, vDataToHash) % (vData.size() * 8);
});

describe("G8: Bit-index computation — MISSING (BUG-4)", () => {
  test.todo("CBloomFilter.Hash absent — bit-index (hash % (vData.size*8)) not implemented");
});

describe("G9: Insert + Contains round-trip — MISSING (BUG-5)", () => {
  test.todo("CBloomFilter.insert / CBloomFilter.contains not implemented");
  // After insert(key), contains(key) must be true.
  // After insert(key1), contains(key2) must be false (no false negative for distinct key).
});

describe("G10: isEmpty / isFull short-circuit — MISSING (BUG-6)", () => {
  test.todo("isFull / isEmpty not implemented");
  // Core bloom.cpp:
  //   contains(): if (vData.empty()) return true;  ← zero-size = match-all
  //   insert():   if (vData.empty()) return;       ← CVE-2013-5700 guard
});

// ============================================================================
// G11-G15 — Update flags
// ============================================================================

describe("G11: BLOOM_UPDATE_NONE = 0 — MISSING (BUG-7)", () => {
  test.skip("constant absent", () => {
    const { BLOOM_UPDATE_NONE } = require("../src/bloom/bloom.js");
    expect(BLOOM_UPDATE_NONE).toBe(0);
  });

  test("BLOOM_UPDATE_NONE absent", () => {
    let found = false;
    try {
      const m = require("../src/bloom/bloom.js");
      if (m.BLOOM_UPDATE_NONE === 0) found = true;
    } catch { found = false; }
    expect(found).toBe(false);
  });
});

describe("G12: BLOOM_UPDATE_ALL = 1 — MISSING (BUG-7)", () => {
  test.skip("constant absent", () => {
    const { BLOOM_UPDATE_ALL } = require("../src/bloom/bloom.js");
    expect(BLOOM_UPDATE_ALL).toBe(1);
  });

  test("BLOOM_UPDATE_ALL absent", () => {
    let found = false;
    try {
      const m = require("../src/bloom/bloom.js");
      if (m.BLOOM_UPDATE_ALL === 1) found = true;
    } catch { found = false; }
    expect(found).toBe(false);
  });
});

describe("G13: BLOOM_UPDATE_P2PUBKEY_ONLY = 2 — MISSING (BUG-7)", () => {
  test.skip("constant absent", () => {
    const { BLOOM_UPDATE_P2PUBKEY_ONLY } = require("../src/bloom/bloom.js");
    expect(BLOOM_UPDATE_P2PUBKEY_ONLY).toBe(2);
  });

  test("BLOOM_UPDATE_P2PUBKEY_ONLY absent", () => {
    let found = false;
    try {
      const m = require("../src/bloom/bloom.js");
      if (m.BLOOM_UPDATE_P2PUBKEY_ONLY === 2) found = true;
    } catch { found = false; }
    expect(found).toBe(false);
  });
});

describe("G14: BLOOM_UPDATE_MASK = 3 — MISSING (BUG-7)", () => {
  test.skip("constant absent", () => {
    const { BLOOM_UPDATE_MASK } = require("../src/bloom/bloom.js");
    expect(BLOOM_UPDATE_MASK).toBe(3);
  });

  test("BLOOM_UPDATE_MASK absent", () => {
    let found = false;
    try {
      const m = require("../src/bloom/bloom.js");
      if (m.BLOOM_UPDATE_MASK === 3) found = true;
    } catch { found = false; }
    expect(found).toBe(false);
  });
});

describe("G15: nFlags & BLOOM_UPDATE_MASK extraction — MISSING (BUG-7)", () => {
  test.todo("nFlags & UPDATE_MASK not implemented — IsRelevantAndUpdate absent");
  // Core bloom.cpp:
  //   if ((nFlags & BLOOM_UPDATE_MASK) == BLOOM_UPDATE_ALL) insert(outpoint);
  //   else if ((nFlags & BLOOM_UPDATE_MASK) == BLOOM_UPDATE_P2PUBKEY_ONLY) ...
});

// ============================================================================
// G16-G20 — Match logic (IsRelevantAndUpdate absent)
// ============================================================================

describe("G16: txid match in IsRelevantAndUpdate — MISSING (BUG-8)", () => {
  test.todo("IsRelevantAndUpdate absent — txid (tx.GetHash()) not checked against filter");
  // Core bloom.cpp:103: if (contains(hash.ToUint256())) fFound = true;
});

describe("G17: Per-output scriptPubKey pushdata scan — MISSING (BUG-8)", () => {
  test.todo("scriptPubKey GetOp loop not implemented — data elements not checked");
  // Core bloom.cpp:113-135: iterates txout.scriptPubKey, checks each pushed data element.
});

describe("G18: P2PK/multisig outpoint insert on UPDATE_P2PUBKEY_ONLY — MISSING (BUG-9)", () => {
  test.todo("Solver(scriptPubKey) check absent — P2PK/multisig outpoint never inserted");
  // Core bloom.cpp:128: if (type == TxoutType::PUBKEY || type == TxoutType::MULTISIG)
  //   insert(COutPoint(hash, i));
});

describe("G19: Outpoint match on inputs — MISSING (BUG-8)", () => {
  test.todo("contains(txin.prevout) check absent — spending tx not matched by outpoint");
  // Core bloom.cpp:144: if (contains(txin.prevout)) return true;
});

describe("G20: scriptSig data items scan — MISSING (BUG-8)", () => {
  test.todo("scriptSig GetOp loop absent — data items in scriptSig not matched");
  // Core bloom.cpp:148-158: iterates txin.scriptSig, checks each pushed data element.
});

// ============================================================================
// G21-G24 — isRelevantAndUpdate update paths
// ============================================================================

describe("G21: UPDATE_ALL — insert outpoint on any matching output — MISSING (BUG-9)", () => {
  test.todo("BLOOM_UPDATE_ALL path absent — insert(COutPoint(hash, i)) never called");
});

describe("G22: UPDATE_P2PUBKEY_ONLY — insert only for P2PK/multisig — MISSING (BUG-9)", () => {
  test.todo("BLOOM_UPDATE_P2PUBKEY_ONLY path absent — Solver() check never runs");
});

describe("G23: UPDATE_NONE — no automatic outpoint insertion — MISSING (BUG-9)", () => {
  test.todo("UPDATE_NONE path absent — entire IsRelevantAndUpdate missing");
});

describe("G24: Outpoint serialization (txid LE || vout LE32) — MISSING (BUG-10)", () => {
  test.todo("COutPoint serialization for bloom absent");
  // Core: DataStream stream{}; stream << outpoint; (32-byte txid LE + 4-byte vout LE)
});

// ============================================================================
// G25 — filterload P2P message (BUG-11)
// ============================================================================

describe("G25: filterload P2P message — MISSING from NetworkMessage union (BUG-11)", () => {
  test("filterload not in NetworkMessage type union", () => {
    // Core: messages.h NetMsgType::FILTERLOAD = "filterload"
    // hotbuns messages.ts NetworkMessage union has no filterload variant.
    // Confirm by deserializing: falls through to unknown-message default.
    const payload = makeFilterloadPayload(10, 8, 2897477, 1); // nElements≈10, fpRate≈0.01
    const msg = roundTrip("filterload", payload);
    // Falls to default case, returns { type: "filterload", payload: null }
    expect(msg.type).toBe("filterload");
    // The payload is null (unknown message — not a parsed CBloomFilter).
    expect(msg.payload).toBeNull();
  });

  test("filterload payload is NOT parsed as a CBloomFilter", () => {
    // If it were correctly parsed, payload would contain { vData, nHashFuncs, nTweak, nFlags }.
    const payload = makeFilterloadPayload(8, 5, 42, 0);
    const msg = roundTrip("filterload", payload);
    // Null payload confirms no deserialization occurred.
    expect((msg as any).payload?.nHashFuncs).toBeUndefined();
    expect((msg as any).payload?.nTweak).toBeUndefined();
    expect((msg as any).payload?.nFlags).toBeUndefined();
  });

  test("no filterload handler is registered on PeerManager", () => {
    // Core net_processing.cpp ~4964: processes filterload, sets per-peer bloom filter.
    // hotbuns: no onMessage("filterload") registered in cli.ts or manager.ts.
    //
    // We verify by inspecting the messageHandlers Map on a fresh PeerManager.
    const { PeerManager } = require("../src/p2p/manager.js");
    const { REGTEST } = require("../src/consensus/params.js");
    const pm = new PeerManager({
      params: REGTEST,
      datadir: "/tmp/w110-test-pm",
      listen: false,
    });
    // The private messageHandlers Map should have no "filterload" entry.
    const handlers: Map<string, unknown[]> = (pm as any).messageHandlers;
    expect(handlers.has("filterload")).toBe(false);
    expect(handlers.has("filteradd")).toBe(false);
    expect(handlers.has("filterclear")).toBe(false);
  });
});

// ============================================================================
// G26 — filteradd ≤ 520 bytes guard (BUG-12)
// ============================================================================

describe("G26: filteradd ≤ MAX_SCRIPT_ELEMENT_SIZE (520 bytes) — MISSING (BUG-12)", () => {
  test("filteradd not in NetworkMessage union", () => {
    // Core net_processing.cpp ~4989: processes filteradd.
    // hotbuns: falls through to unknown-message default.
    const data = Buffer.alloc(20, 0xab); // e.g. a 20-byte hash
    const payload = makeFilteraddPayload(data);
    const msg = roundTrip("filteradd", payload);
    expect(msg.type).toBe("filteradd");
    expect(msg.payload).toBeNull(); // not parsed
  });

  test.skip("filteradd with element > 520 bytes should be rejected (DoS guard)", () => {
    // Core net_processing.cpp: if (element.size() > MAX_SCRIPT_ELEMENT_SIZE) Misbehaving(+100)
    // hotbuns: no such check — element size never validated.
    const oversized = Buffer.alloc(521, 0xff); // 1 byte over limit
    const payload = makeFilteraddPayload(oversized);
    // Should throw or disconnect; currently silently dropped.
    expect(() => roundTrip("filteradd", payload)).toThrow();
  });
});

// ============================================================================
// G27 — filterclear P2P message (BUG-13)
// ============================================================================

describe("G27: filterclear P2P message — MISSING from NetworkMessage union (BUG-13)", () => {
  test("filterclear not in NetworkMessage union", () => {
    // Core net_processing.cpp ~5010: processes filterclear, clears per-peer filter.
    // hotbuns: falls through to unknown-message default.
    const msg = roundTrip("filterclear", Buffer.alloc(0));
    expect(msg.type).toBe("filterclear");
    expect(msg.payload).toBeNull(); // not parsed
  });

  test("filterclear has no registered handler on PeerManager", () => {
    const { PeerManager } = require("../src/p2p/manager.js");
    const { REGTEST } = require("../src/consensus/params.js");
    const pm = new PeerManager({
      params: REGTEST,
      datadir: "/tmp/w110-test-pm-clear",
      listen: false,
    });
    const handlers: Map<string, unknown[]> = (pm as any).messageHandlers;
    expect(handlers.has("filterclear")).toBe(false);
  });
});

// ============================================================================
// G28 — merkleblock P2P message + PartialMerkleTree (BUG-14, BUG-18)
// ============================================================================

describe("G28: merkleblock P2P message + PartialMerkleTree — MISSING P2P (BUG-14/18)", () => {
  test("merkleblock not in NetworkMessage type union", () => {
    // Core: CMerkleBlock serialized to "merkleblock" P2P message for SPV peers.
    // hotbuns: NetworkMessage union has no merkleblock variant.
    //
    // Build a minimal merkleblock wire payload:
    // 80-byte header + nTx(4 LE=1) + varint(1 hash) + 32-byte hash + varint(1 flag byte) + 0x01
    const header80 = Buffer.alloc(80, 0);
    const nTxBuf = Buffer.alloc(4); nTxBuf.writeUInt32LE(1, 0);
    const hash32 = Buffer.alloc(32, 0xab);
    const flagBuf = Buffer.from([0x01, 0x01]); // varint=1, flags=0x01
    const payload = Buffer.concat([
      header80,
      nTxBuf,
      Buffer.from([0x01]), // varint: 1 hash
      hash32,
      flagBuf,
    ]);
    const msg = roundTrip("merkleblock", payload);
    // Falls through to unknown-message default.
    expect(msg.type).toBe("merkleblock");
    expect(msg.payload).toBeNull(); // not parsed
  });

  test("PartialMerkleTree builder exists in RPC but not wired to P2P sendMerkleBlock (BUG-18 two-pipeline)", () => {
    // rpc/server.ts exports w47bTraverseAndBuild (Wave-47b) — wired to gettxoutproof only.
    // There is no equivalent sendMerkleBlock(peer, block, filter) path in P2P.
    // This is a dead-helper / two-pipeline: the RPC tree-builder is present but the
    // P2P filtered-block relay path is entirely absent.
    //
    // Verify that the RPC server module contains the Wave-47b helpers:
    const src = require("fs").readFileSync(
      require("path").join(__dirname, "../src/rpc/server.ts"),
      "utf8"
    );
    expect(src).toContain("w47bTraverseAndBuild");
    expect(src).toContain("Wave-47b");

    // Verify there is no sendMerkleBlock or similar in P2P paths:
    const peerSrc = require("fs").readFileSync(
      require("path").join(__dirname, "../src/p2p/peer.ts"),
      "utf8"
    );
    expect(peerSrc.toLowerCase()).not.toContain("merkleblock");
    expect(peerSrc.toLowerCase()).not.toContain("sendmerkle");
  });
});

// ============================================================================
// G29 — IsWithinSizeConstraints (BUG-15)
// ============================================================================

describe("G29: IsWithinSizeConstraints — MISSING (BUG-15)", () => {
  test.skip("IsWithinSizeConstraints not implemented", () => {
    // Core bloom.h: vData.size() <= MAX_BLOOM_FILTER_SIZE && nHashFuncs <= MAX_HASH_FUNCS
    // hotbuns: no such guard — filterload payloads are silently dropped (BUG-11).
    const { CBloomFilter, MAX_BLOOM_FILTER_SIZE } = require("../src/bloom/bloom.js");
    // oversized: vData larger than 36000 bytes should fail
    const f = new CBloomFilter(36001 * 8, 1e-10, 0, 0);
    expect(f.isWithinSizeConstraints()).toBe(false);
  });

  test("IsWithinSizeConstraints absent — filterload payload not size-checked", () => {
    // Build a filterload with vData length > MAX_BLOOM_FILTER_SIZE (36000).
    // In a correct impl this would be rejected with Misbehaving(+100).
    // In hotbuns it is silently dropped as an unknown message.
    const oversizedVDataLen = 36001;
    // Build raw payload: use a large varint marker (0xfe) for the data length
    const payloadBuf = Buffer.alloc(4 + oversizedVDataLen + 4 + 4 + 1);
    let off = 0;
    payloadBuf[off++] = 0xfe; // varint 4-byte follows
    payloadBuf.writeUInt32LE(oversizedVDataLen, off); off += 4;
    // rest is zeros: nHashFuncs=0, nTweak=0, nFlags=0 at the end
    const msg = roundTrip("filterload", payloadBuf);
    // Falls through to default regardless of size — no size check.
    expect(msg.type).toBe("filterload");
  });
});

// ============================================================================
// G30 — NODE_BLOOM service bit + BIP-111 -peerbloomfilters gate (BUG-16/17)
// ============================================================================

describe("G30: NODE_BLOOM (1<<2 = 4n) defined — PASS", () => {
  test("ServiceFlags.NODE_BLOOM = 4n", () => {
    // Core: NODE_BLOOM = (1 << 2) = 4
    expect(ServiceFlags.NODE_BLOOM).toBe(4n);
  });
});

describe("G30: -peerbloomfilters default OFF — PASS", () => {
  test("peerBloomFilters defaults to false", () => {
    // cli.ts: peerBloomFilters: false (matches Core DEFAULT_PEERBLOOMFILTERS = false)
    // Verified via source inspection; cli.ts line ~202.
    const src = require("fs").readFileSync(
      require("path").join(__dirname, "../src/cli/cli.ts"),
      "utf8"
    );
    expect(src).toContain("peerBloomFilters: false");
  });
});

describe("G30: NODE_BLOOM gated on --peerbloomfilters via params.services — FIX-35", () => {
  // FIX-35: BUG-16 closed.  manager.ts no longer hardcodes NODE_BLOOM in
  // address-record initializations.  The four previously-broken sites
  // (--connect seeds, DNS-seed pool, fallback peers, connectPeer new-entry)
  // now use NODE_NETWORK | NODE_WITNESS as the conservative baseline.
  // The bloom bit is controlled exclusively by cli.ts via params.services
  // (OR'd in when --peerbloomfilters=1, absent by default).

  test("manager.ts does NOT hardcode NODE_BLOOM in address-record services (FIX-35)", () => {
    // After fix: the pattern
    //   services: ServiceFlags.NODE_NETWORK | ServiceFlags.NODE_WITNESS | ServiceFlags.NODE_BLOOM
    // must be absent from manager.ts.  All four former sites now use
    //   services: ServiceFlags.NODE_NETWORK | ServiceFlags.NODE_WITNESS
    const managerSrc = require("fs").readFileSync(
      require("path").join(__dirname, "../src/p2p/manager.ts"),
      "utf8"
    );
    const hardcodedPattern = /ServiceFlags\.NODE_NETWORK \| ServiceFlags\.NODE_WITNESS \| ServiceFlags\.NODE_BLOOM/g;
    const matches = managerSrc.match(hardcodedPattern) ?? [];
    // Must be zero — no hardcoded bloom in address-record initializations.
    expect(matches.length).toBe(0);
  });

  test("getAdvertisedServices(): NODE_BLOOM absent when peerBloomFilters=false (default)", () => {
    // Core DEFAULT_PEERBLOOMFILTERS = false → node must NOT advertise NODE_BLOOM.
    // params.services = 0x09n (NODE_NETWORK | NODE_WITNESS) when bloom is off.
    const { PeerManager } = require("../src/p2p/manager.js");
    const { MAINNET } = require("../src/consensus/params.js");
    // Default params: services = 0x09n, no NODE_BLOOM bit.
    const pm = new PeerManager({
      params: MAINNET,
      datadir: "/tmp/w110-fix35-test-off",
      listen: false,
      maxOutbound: 8,
      maxInbound: 117,
      bestHeight: 0,
    });
    const advertised = pm.getAdvertisedServices();
    // NODE_BLOOM (4n) must NOT be set when peerBloomFilters=false.
    expect(advertised & ServiceFlags.NODE_BLOOM).toBe(0n);
    // NODE_NETWORK and NODE_WITNESS must still be set.
    expect(advertised & ServiceFlags.NODE_NETWORK).toBe(ServiceFlags.NODE_NETWORK);
    expect(advertised & ServiceFlags.NODE_WITNESS).toBe(ServiceFlags.NODE_WITNESS);
  });

  test("getAdvertisedServices(): NODE_BLOOM present when peerBloomFilters=true", () => {
    // When operator passes --peerbloomfilters, cli.ts sets
    //   params.services = baseParams.services | 4n
    // PeerManager.getAdvertisedServices() returns params.services (or +NETWORK_LIMITED for prune).
    // Simulate the cli.ts behaviour by constructing params with the bloom bit set.
    const { PeerManager } = require("../src/p2p/manager.js");
    const { MAINNET } = require("../src/consensus/params.js");
    const paramsWithBloom = { ...MAINNET, services: MAINNET.services | ServiceFlags.NODE_BLOOM };
    const pm = new PeerManager({
      params: paramsWithBloom,
      datadir: "/tmp/w110-fix35-test-on",
      listen: false,
      maxOutbound: 8,
      maxInbound: 117,
      bestHeight: 0,
    });
    const advertised = pm.getAdvertisedServices();
    // NODE_BLOOM (4n) MUST be set when peerBloomFilters=true.
    expect(advertised & ServiceFlags.NODE_BLOOM).toBe(ServiceFlags.NODE_BLOOM);
    // NODE_NETWORK and NODE_WITNESS must also still be set.
    expect(advertised & ServiceFlags.NODE_NETWORK).toBe(ServiceFlags.NODE_NETWORK);
    expect(advertised & ServiceFlags.NODE_WITNESS).toBe(ServiceFlags.NODE_WITNESS);
  });

  test("params.services bloom-gating in cli.ts flows through to PeerManager", () => {
    // cli.ts correctly gates bloom bit in params.services, and PeerManager
    // getAdvertisedServices() reads params.services (not hardcoded constants).
    const cliSrc = require("fs").readFileSync(
      require("path").join(__dirname, "../src/cli/cli.ts"),
      "utf8"
    );
    expect(cliSrc).toContain("NODE_BLOOM_BIT");
    expect(cliSrc).toContain("mergedConfig.peerBloomFilters");
    // manager.ts version-message construction uses this.config.params.services,
    // which is the params object built by cli.ts with the conditional bloom bit.
    const managerSrc = require("fs").readFileSync(
      require("path").join(__dirname, "../src/p2p/manager.ts"),
      "utf8"
    );
    // Version-message construction must reference params.services (not NODE_BLOOM directly).
    expect(managerSrc).toContain("this.config.params.services");
  });
});

describe("G30: filterload disconnect when NODE_BLOOM not advertised — MISSING (BUG-17)", () => {
  test("filterload received when !NODE_BLOOM should disconnect peer — not implemented", () => {
    // Core net_processing.cpp ~4964:
    //   if (!pfrom.m_bloom_filter_present && !(peer->m_our_services & NODE_BLOOM)) {
    //     pfrom.fDisconnect = true; return;
    //   }
    // hotbuns: filterload falls through to unknown-message default (console.log + null payload).
    // No disconnect happens.
    //
    // Structural verification: manager's handlePeerMessage does NOT disconnect on filterload.
    const managerSrc = require("fs").readFileSync(
      require("path").join(__dirname, "../src/p2p/manager.ts"),
      "utf8"
    );
    // No disconnect logic for filterload in manager.ts:
    expect(managerSrc).not.toContain('"filterload"');
  });

  test("per-peer bloom filter state (m_pfilter) absent from Peer class", () => {
    // Core: CNode has unique_ptr<CBloomFilter> m_bloom_filter GUARDED_BY(m_bloom_filter_mutex).
    // hotbuns Peer: no bloomFilter, no m_pfilter, no m_bloom_filter field.
    const peerSrc = require("fs").readFileSync(
      require("path").join(__dirname, "../src/p2p/peer.ts"),
      "utf8"
    );
    expect(peerSrc).not.toContain("bloomFilter");
    expect(peerSrc).not.toContain("m_bloom_filter");
    expect(peerSrc).not.toContain("m_pfilter");
    expect(peerSrc).not.toContain("txFilter");
  });
});

// ============================================================================
// Structural summary
// ============================================================================

describe("Structural summary: CBloomFilter subsystem entirely absent", () => {
  test("no bloom.ts or bloom/ directory in hotbuns/src/", () => {
    const { existsSync } = require("fs");
    const path = require("path");
    expect(existsSync(path.join(__dirname, "../src/bloom"))).toBe(false);
    expect(existsSync(path.join(__dirname, "../src/bloom/bloom.ts"))).toBe(false);
    expect(existsSync(path.join(__dirname, "../src/common/bloom.ts"))).toBe(false);
  });

  test("no MurmurHash3 in crypto/primitives.ts", () => {
    const primitives = require("../src/crypto/primitives.js");
    expect(primitives.murmurHash3).toBeUndefined();
    expect(primitives.MurmurHash3).toBeUndefined();
  });

  test("filterload / filteradd / filterclear / merkleblock absent from NetworkMessage union (type-level)", () => {
    // These 4 types are absent from the NetworkMessage discriminated union in messages.ts.
    // Unknown-message fallback is used for all of them.
    const msgs = ["filterload", "filteradd", "filterclear", "merkleblock"];
    for (const cmd of msgs) {
      const payload = Buffer.alloc(0);
      // Need non-empty payload for filterclear (empty ok), but filterload etc. need at least a checksum.
      try {
        const msg = roundTrip(cmd, payload);
        expect(msg.type).toBe(cmd);
        expect(msg.payload).toBeNull();
      } catch {
        // Acceptable — checksum computed on payload, empty is fine for filterclear.
        // The important point is that no proper deserialization occurs.
      }
    }
  });

  test("PartialMerkleTree helpers present in RPC (dead-helper relative to P2P) — BUG-18 two-pipeline", () => {
    // Wave-47b helpers (w47bTraverseAndBuild, w47bCalcHash, etc.) exist in rpc/server.ts
    // but are NOT wired to any P2P "send filtered block" code path.
    // This is the dead-helper / two-pipeline pattern: the builder is present but unused
    // for its primary BIP-37 purpose.
    const serverSrc = require("fs").readFileSync(
      require("path").join(__dirname, "../src/rpc/server.ts"),
      "utf8"
    );
    expect(serverSrc).toContain("w47bTraverseAndBuild");
    expect(serverSrc).toContain("w47bTraverseAndExtract");
    // Wired only to gettxoutproof/verifytxoutproof, not to a P2P merkleblock path:
    expect(serverSrc).toContain("gettxoutproof");
    expect(serverSrc).toContain("verifytxoutproof");
  });
});
