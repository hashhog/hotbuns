/**
 * W138 — assumeUTXO snapshots (loadtxoutset / dumptxoutset / dual chainstate) — hotbuns
 *
 * Discovery audit. Each test either
 *   (a) PASSes today, documenting a Core-parity behavior to keep, OR
 *   (b) DOCUMENTS a bug by asserting the CURRENT divergent behavior
 *       and including a `// BUG-N` comment so a future fix wave can
 *       grep this file and invert the assertions.
 *
 * Reference:
 *   - bitcoin-core/src/node/utxo_snapshot.{h,cpp}
 *   - bitcoin-core/src/validation.cpp
 *     (ActivateSnapshot 5588, PopulateAndValidateSnapshot 5754,
 *      MaybeValidateSnapshot 5967, LoadAssumeutxoChainstate 6151,
 *      MaybeRebalanceCaches 6085)
 *   - bitcoin-core/src/rpc/blockchain.cpp
 *     (dumptxoutset 3074, loadtxoutset 3368, getchainstates 3462)
 *
 * Companion document: audit/w138_assumeutxo.md.
 *
 * Run: bun test src/__tests__/w138_assumeutxo.test.ts
 */

import { describe, it, expect, beforeEach, afterEach } from "bun:test";
import { rmSync, mkdirSync } from "node:fs";
import { promises as fsp } from "node:fs";
import { join } from "node:path";
import { readFileSync } from "node:fs";

import {
  ChainstateManager,
  Chainstate,
  ChainstateStatus,
  SnapshotValidationResult,
  SNAPSHOT_MAGIC,
  SNAPSHOT_VERSION,
  serializeSnapshotMetadata,
  deserializeSnapshotMetadata,
  computeUTXOSetHash,
  getAssumeutxoData,
  getAssumeutxoDataByHeight,
  getAvailableSnapshotHeights,
  getLatestSnapshotHeightForRollback,
  type SnapshotMetadata,
} from "../chain/snapshot.js";
import { ChainDB, DBPrefix } from "../storage/database.js";
import { REGTEST, MAINNET, type ConsensusParams } from "../consensus/params.js";
import { BufferReader, BufferWriter } from "../wire/serialization.js";

// =============================================================================
// Test scaffolding
// =============================================================================

const REPO_ROOT = join(import.meta.dirname, "..", "..");
const SRC_ROOT = join(REPO_ROOT, "src");
const SNAPSHOT_TS = readFileSync(join(SRC_ROOT, "chain", "snapshot.ts"), "utf8");
const RPC_SERVER_TS = readFileSync(join(SRC_ROOT, "rpc", "server.ts"), "utf8");
const CLI_TS = readFileSync(join(SRC_ROOT, "cli", "cli.ts"), "utf8");

const TEST_ROOT = "/tmp/hotbuns-w138-" + Date.now() + "-" + Math.random().toString(36).slice(2);

beforeEach(() => {
  try { rmSync(TEST_ROOT, { recursive: true, force: true }); } catch {}
  mkdirSync(TEST_ROOT, { recursive: true });
});

afterEach(() => {
  try { rmSync(TEST_ROOT, { recursive: true, force: true }); } catch {}
});

async function freshDB(label: string): Promise<ChainDB> {
  const path = join(TEST_ROOT, label + "-" + Math.random().toString(36).slice(2));
  const db = new ChainDB(path);
  await db.open();
  return db;
}

// =============================================================================
// G1 — SNAPSHOT_MAGIC_BYTES = 'utxo' || 0xff
// =============================================================================

describe("W138-G1: SNAPSHOT_MAGIC_BYTES = 'utxo' || 0xff", () => {
  it("PRESENT: hotbuns SNAPSHOT_MAGIC equals Core's {'u','t','x','o',0xff}", () => {
    // Core utxo_snapshot.h:28:
    //   static constexpr std::array<uint8_t, 5> SNAPSHOT_MAGIC_BYTES = {'u','t','x','o',0xff};
    expect(SNAPSHOT_MAGIC.equals(Buffer.from([0x75, 0x74, 0x78, 0x6f, 0xff]))).toBe(true);
    expect(SNAPSHOT_MAGIC.length).toBe(5);
    expect(String.fromCharCode(SNAPSHOT_MAGIC[0]!)).toBe("u");
    expect(String.fromCharCode(SNAPSHOT_MAGIC[1]!)).toBe("t");
    expect(String.fromCharCode(SNAPSHOT_MAGIC[2]!)).toBe("x");
    expect(String.fromCharCode(SNAPSHOT_MAGIC[3]!)).toBe("o");
    expect(SNAPSHOT_MAGIC[4]).toBe(0xff);
  });

  it("PRESENT: deserializer rejects wrong magic", () => {
    const bad = Buffer.concat([
      Buffer.from([0x00, 0x00, 0x00, 0x00, 0x00]),
      Buffer.alloc(46),
    ]);
    expect(() =>
      deserializeSnapshotMetadata(new BufferReader(bad), 0xdab5bffa),
    ).toThrow(/Invalid snapshot magic/);
  });
});

// =============================================================================
// G2 — SNAPSHOT_VERSION = 2
// =============================================================================

describe("W138-G2: SNAPSHOT_VERSION = 2", () => {
  it("PRESENT: hotbuns SNAPSHOT_VERSION matches Core's VERSION = 2", () => {
    // Core utxo_snapshot.h:39 — inline static const uint16_t VERSION{2};
    expect(SNAPSHOT_VERSION).toBe(2);
  });

  it("PRESENT: deserializer rejects other versions", () => {
    // Build a header with version=1 (legal magic, wrong version).
    const buf = Buffer.alloc(51);
    SNAPSHOT_MAGIC.copy(buf, 0);
    buf.writeUInt16LE(1, 5);
    expect(() =>
      deserializeSnapshotMetadata(new BufferReader(buf), 0xdab5bffa),
    ).toThrow(/Unsupported snapshot version/);
  });

  it("PARITY GAP: hotbuns checks `!==` against literal 2 (Core uses std::set, would accept multiple versions)", () => {
    // Minor — future-proofing parity gap, not a current bug. Core
    // utxo_snapshot.h:40 declares `const std::set<uint16_t> m_supported_versions{VERSION}`.
    // Hotbuns snapshot.ts:185-187 compares against the literal.
    expect(SNAPSHOT_TS).toContain("if (version !== SNAPSHOT_VERSION)");
    expect(SNAPSHOT_TS).not.toContain("m_supported_versions");
  });
});

// =============================================================================
// G3 — SNAPSHOT_BLOCKHASH_FILENAME = "base_blockhash" + chainstate_snapshot dir
// =============================================================================

describe("W138-G3: SNAPSHOT_BLOCKHASH_FILENAME + chainstate_snapshot/ dir (BUG-1)", () => {
  it("BUG-1: no `base_blockhash` file is written by loadSnapshot / no chainstate_snapshot/ dir", () => {
    // Core utxo_snapshot.cpp:22 WriteSnapshotBaseBlockhash, called from
    // validation.cpp:5712 inside ActivateSnapshot. Hotbuns has no analog —
    // grep the codebase for the filename and the chainstate dir suffix.
    expect(SNAPSHOT_TS).not.toMatch(/base_blockhash/);
    expect(SNAPSHOT_TS).not.toMatch(/SNAPSHOT_BLOCKHASH_FILENAME/);
    expect(SNAPSHOT_TS).not.toMatch(/chainstate_snapshot/);
    expect(SNAPSHOT_TS).not.toMatch(/_snapshot[\b'"\)]/);
    expect(SNAPSHOT_TS).not.toMatch(/WriteSnapshotBaseBlockhash/);
    expect(SNAPSHOT_TS).not.toMatch(/ReadSnapshotBaseBlockhash/);
    expect(SNAPSHOT_TS).not.toMatch(/FindAssumeutxoChainstateDir/);
  });

  it("BUG-1: snapshotBaseBlockHash lives only in memory on the Chainstate object", async () => {
    // The flag is set at snapshot.ts:561 in the constructor. There is no
    // persistence call anywhere.
    const db = await freshDB("g3");
    try {
      const baseHash = Buffer.alloc(32, 0xab);
      const cs = new Chainstate(db, REGTEST, {
        snapshotBaseBlockHash: baseHash,
        status: ChainstateStatus.UNVALIDATED,
      });
      expect(cs.snapshotBaseBlockHash?.equals(baseHash)).toBe(true);

      // A second Chainstate over the SAME db has no memory of the snapshot
      // state — confirming there is no on-disk persistence layer.
      const cs2 = new Chainstate(db, REGTEST);
      expect(cs2.snapshotBaseBlockHash).toBeNull();
      expect(cs2.isSnapshot()).toBe(false);
    } finally {
      await db.close();
    }
  });
});

// =============================================================================
// G4 — 51-byte metadata header layout
// =============================================================================

describe("W138-G4: 51-byte metadata header layout", () => {
  it("PRESENT: header is exactly 5+2+4+32+8 = 51 bytes", () => {
    const meta: SnapshotMetadata = {
      networkMagic: 0xd9b4bef9, // mainnet
      baseBlockHash: Buffer.alloc(32, 0xab),
      coinsCount: 12345678n,
    };
    const bytes = serializeSnapshotMetadata(meta);
    expect(bytes.length).toBe(51);
    // Magic
    expect(bytes.subarray(0, 5).equals(SNAPSHOT_MAGIC)).toBe(true);
    // Version uint16 LE
    expect(bytes.readUInt16LE(5)).toBe(SNAPSHOT_VERSION);
    // Network magic in pchMessageStart byte order (mainnet → f9 be b4 d9)
    expect(bytes.subarray(7, 11)).toEqual(Buffer.from([0xf9, 0xbe, 0xb4, 0xd9]));
    // Base blockhash
    expect(bytes.subarray(11, 43).equals(meta.baseBlockHash)).toBe(true);
    // Coins count uint64 LE
    expect(bytes.readBigUInt64LE(43)).toBe(meta.coinsCount);
  });
});

// =============================================================================
// G5 — Per-coin layout: VARINT(code) || TxOutCompression
// =============================================================================

describe("W138-G5: per-coin layout = VARINT(code) || TxOutCompression", () => {
  it("PRESENT: serializeCoinForSnapshot emits Pieter's VARINT for height*2+coinbase", async () => {
    // Already pinned by assumeutxo.test.ts; we lightly cross-reference here.
    // code = (height<<1) | fCoinBase encoded with Pieter's per-byte VARINT.
    // The companion assumeutxo.test.ts:167-199 verifies the exact byte layout.
    expect(SNAPSHOT_TS).toContain("writeVarIntCore");
    expect(SNAPSHOT_TS).toContain("serializeTxOutCompressed");
    expect(SNAPSHOT_TS).toMatch(/code = BigInt\(coin\.height\) \* 2n \+/);
  });
});

// =============================================================================
// G6 — Per-txid group layout (txid || CompactSize n || (CompactSize vout || Coin)+)
// =============================================================================

describe("W138-G6: per-txid group layout + numeric-vout sort", () => {
  it("PRESENT: dumpSnapshot sorts vouts numerically per txid (Core std::map<uint32_t, Coin>)", () => {
    // Pinned by assumeutxo.test.ts:1928-2033; here we just confirm the
    // critical sort step exists in source.
    expect(SNAPSHOT_TS).toContain("currentCoins.sort((a, b) => a.vout - b.vout)");
  });
});

// =============================================================================
// G7 — Headers-chain ancestor check on snapshot base block (BUG-2)
// =============================================================================

describe("W138-G7: headers-chain ancestor check (BUG-2, P0-CDIV)", () => {
  it("BUG-2: loadSnapshot does NOT verify base block appears in the headers chain", () => {
    // Core validation.cpp:5611-5614:
    //   snapshot_start_block = m_blockman.LookupBlockIndex(base_blockhash);
    //   if (!snapshot_start_block) { return Error("The base block header
    //     (%s) must appear in the headers chain. ..."); }
    // And :5622-5624:
    //   if (!m_best_header || m_best_header->GetAncestor(snapshot_start_block->nHeight)
    //       != snapshot_start_block) { return Error("A forked headers-chain ..."); }
    // Hotbuns: the only lookup is getAssumeutxoData (chainparams), there
    // is no header-chain ancestor walk in loadSnapshot.
    expect(SNAPSHOT_TS).not.toMatch(/headers.*chain/i);
    expect(SNAPSHOT_TS).not.toMatch(/m_best_header/);
    expect(SNAPSHOT_TS).not.toMatch(/getAncestor/i);
    expect(SNAPSHOT_TS).not.toMatch(/must appear in the headers chain/);

    // The only base-block lookup in loadSnapshot is the chainparams
    // assumeutxo Map — NOT the header chain.
    const loadSnapshotStart = SNAPSHOT_TS.indexOf("async loadSnapshot(");
    const loadSnapshotEnd = SNAPSHOT_TS.indexOf("\n  }", loadSnapshotStart) + 4;
    const fn = SNAPSHOT_TS.slice(loadSnapshotStart, loadSnapshotEnd);
    expect(fn).toContain("getAssumeutxoData(this.params");
    // Critically, the function does NOT consult db.getBlockIndex on the
    // base block hash to verify the header chain knows about it.
    expect(fn).not.toContain("getBlockIndex");
  });
});

// =============================================================================
// G8 — BLOCK_FAILED_VALID start-block rejection (BUG-3)
// =============================================================================

describe("W138-G8: BLOCK_FAILED_VALID start-block rejection (BUG-3, P1-API)", () => {
  it("BUG-3: loadSnapshot does NOT check BlockStatus.FAILED_VALID on the base block", () => {
    // Core validation.cpp:5617-5620:
    //   bool start_block_invalid = snapshot_start_block->nStatus & BLOCK_FAILED_VALID;
    //   if (start_block_invalid) { return Error("The base block header (%s) is
    //     part of an invalid chain"); }
    // Hotbuns: no BlockStatus inspection on the base block hash anywhere in
    // loadSnapshot.
    expect(SNAPSHOT_TS).not.toMatch(/FAILED_VALID/);
    expect(SNAPSHOT_TS).not.toMatch(/BLOCK_FAILED/);
    expect(SNAPSHOT_TS).not.toMatch(/part of an invalid chain/);
  });
});

// =============================================================================
// G9 — Mempool-empty precondition (BUG-4)
// =============================================================================

describe("W138-G9: mempool-empty precondition (BUG-4, P1-API)", () => {
  it("BUG-4: loadSnapshot does NOT consult the mempool size", () => {
    // Core validation.cpp:5626-5629:
    //   auto mempool{CurrentChainstate().GetMempool()};
    //   if (mempool && mempool->size() > 0) {
    //       return Error("Can't activate a snapshot when mempool not empty");
    //   }
    expect(SNAPSHOT_TS).not.toMatch(/mempool/i);
    expect(SNAPSHOT_TS).not.toMatch(/mempool.*size/i);
    expect(SNAPSHOT_TS).not.toMatch(/Can't activate a snapshot when mempool not empty/);
  });

  it("BUG-4: ChainstateManager constructor takes (db, params, maxCacheBytes) — no mempool reference", () => {
    // Verify the structural API: there's no place to thread a mempool
    // through, so the check is impossible without an API change.
    const ctorIdx = SNAPSHOT_TS.indexOf("constructor(db: ChainDB, params: ConsensusParams");
    expect(ctorIdx).toBeGreaterThan(0);
    const ctorEnd = SNAPSHOT_TS.indexOf("\n  }", ctorIdx);
    const ctor = SNAPSHOT_TS.slice(ctorIdx, ctorEnd);
    expect(ctor).not.toMatch(/mempool/i);
  });
});

// =============================================================================
// G10 — Transient IBD_CACHE_PERC / SNAPSHOT_CACHE_PERC resize (BUG-5)
// =============================================================================

describe("W138-G10: transient 1%/99% cache resize during load (BUG-5, P1-API)", () => {
  it("BUG-5: no IBD_CACHE_PERC / SNAPSHOT_CACHE_PERC constants in hotbuns", () => {
    // Core validation.cpp:5641-5642:
    //   static constexpr double IBD_CACHE_PERC = 0.01;
    //   static constexpr double SNAPSHOT_CACHE_PERC = 0.99;
    expect(SNAPSHOT_TS).not.toMatch(/IBD_CACHE_PERC/);
    expect(SNAPSHOT_TS).not.toMatch(/SNAPSHOT_CACHE_PERC/);
    expect(SNAPSHOT_TS).not.toMatch(/ResizeCoinsCaches/);
  });
});

// =============================================================================
// G11 — Per-txid overflow guard (PRESENT)
// =============================================================================

describe("W138-G11: per-txid overflow guard", () => {
  it("PRESENT: source documents the validation.cpp:5804-5806 mirror", () => {
    expect(SNAPSHOT_TS).toContain(
      "Mismatch in coins count in snapshot metadata and actual snapshot data",
    );
    // Also pinned end-to-end in assumeutxo.test.ts BUG-1 case.
    expect(SNAPSHOT_TS).toContain("BUG-1: per-txid overflow guard");
  });
});

// =============================================================================
// G12 — Trailing-bytes EOF check (PRESENT)
// =============================================================================

describe("W138-G12: trailing-bytes EOF check", () => {
  it("PRESENT: source documents the validation.cpp:5872-5883 mirror", () => {
    expect(SNAPSHOT_TS).toContain("Bad snapshot - coins left over after deserializing");
    expect(SNAPSHOT_TS).toContain("BUG-2: trailing-bytes EOF check");
  });
});

// =============================================================================
// G13 — Per-coin MoneyRange + height check (PRESENT)
// =============================================================================

describe("W138-G13: per-coin MoneyRange + height check", () => {
  it("PRESENT: MAX_MONEY constant = 21M BTC in sat", () => {
    // Match Core consensus/amount.h: MAX_MONEY = 21_000_000 * COIN.
    expect(SNAPSHOT_TS).toContain("2_100_000_000_000_000n");
    expect(SNAPSHOT_TS).toContain("bad tx out value");
    // Pinned end-to-end by assumeutxo.test.ts BUG-3 case.
  });

  it("PRESENT: MAX_VOUT constant = 0xFFFFFFFF (Core: outpoint.n >= UINT32_MAX)", () => {
    expect(SNAPSHOT_TS).toContain("const MAX_VOUT = 0xffff_ffff");
    expect(SNAPSHOT_TS).toContain("if (vout >= MAX_VOUT)");
    // Pinned end-to-end by assumeutxo.test.ts BUG-4 case.
  });

  it("PRESENT: coin height > base_height is rejected", () => {
    expect(SNAPSHOT_TS).toContain("Invalid coin height");
    expect(SNAPSHOT_TS).toContain("> snapshot height");
  });
});

// =============================================================================
// G14 — Per-120 000-coin partial flush + CRITICAL state machine (BUG-6)
// =============================================================================

describe("W138-G14: 120 000-coin partial flush + CRITICAL check (BUG-6, P1-WIRE)", () => {
  it("BUG-6: COINS_LOAD_BATCH_SIZE = 120 000 matches Core's flush cadence", () => {
    // Core validation.cpp:5840 uses coins_processed % 120000 == 0.
    expect(SNAPSHOT_TS).toContain("const COINS_LOAD_BATCH_SIZE = 120_000");
  });

  it("BUG-6: but there's no CoinsCacheSizeState::CRITICAL check / no sentinel SetBestBlock", () => {
    // Core conditionally flushes ONLY if the cache is CRITICAL and sets
    // a random sentinel best-block (validation.cpp:5848-5856) before the
    // flush so a crash mid-load leaves the leveldb logically unreadable
    // (rather than partially-readable at a wrong tip).
    expect(SNAPSHOT_TS).not.toMatch(/CoinsCacheSizeState/);
    // "CRITICAL ORDERING" exists in a comment about vout sort order
    // (snapshot.ts:346/1153). The bug-relevant Core string is the
    // size-state machine "CRITICAL" — match that specifically.
    expect(SNAPSHOT_TS).not.toMatch(/CRITICAL\b(?!\s*ORDERING)/);
    expect(SNAPSHOT_TS).not.toMatch(/GetRandHash/);
    expect(SNAPSHOT_TS).not.toMatch(/SetBestBlock/);
    expect(SNAPSHOT_TS).not.toMatch(/FlushSnapshotToDisk/);
  });
});

// =============================================================================
// G15 — Snapshot chainstate isolation (BUG-7, P0-CDIV)
// =============================================================================

describe("W138-G15: snapshot chainstate isolation (BUG-7, P0-CDIV)", () => {
  it("BUG-7: ChainstateManager stores ONE db reference and shares it between active + background", () => {
    // Verify structural divergence from Core's separate-leveldb model.
    // snapshot.ts:557 — Chainstate ctor takes a db parameter.
    // snapshot.ts:806/892/1051 — both active and background chainstates
    // are constructed with `this.db`, the SAME ChainDB instance.
    expect(SNAPSHOT_TS).toMatch(/new Chainstate\(this\.db, this\.params/);
    expect(SNAPSHOT_TS).toMatch(
      /this\.backgroundChainstate = new Chainstate\(this\.db, this\.params/,
    );
    // There is no second ChainDB construction in loadSnapshot.
    const loadStart = SNAPSHOT_TS.indexOf("async loadSnapshot(");
    const loadEnd = SNAPSHOT_TS.indexOf("\n  }", loadStart) + 4;
    const fn = SNAPSHOT_TS.slice(loadStart, loadEnd);
    expect(fn).not.toMatch(/new ChainDB/);
  });

  it("BUG-7: strict gate computeUTXOSetHash(this.db) iterates whole db, not snapshot-only subset", async () => {
    // Demonstrate the contamination empirically: pre-populate a UTXO,
    // then compute the hash — it includes the pre-existing entry.
    // Under Core's separate-leveldb model the snapshot-side hash would
    // be deterministic on the snapshot bytes only.
    const db = await freshDB("g15");
    try {
      // Pre-existing UTXO (simulating partial IBD).
      await db.putUTXO(Buffer.alloc(32, 0xaa), 0, {
        height: 5,
        coinbase: false,
        amount: 1_00000000n,
        scriptPubKey: Buffer.from([0x6a, 0x01]),
      });
      const { hash: hashWithPre, coinsCount: countWithPre } = await computeUTXOSetHash(db);
      expect(countWithPre).toBe(1n);

      // Now add a second "snapshot" UTXO — the hash MUST differ from
      // the empty-pre case, confirming the strict gate sees BOTH.
      await db.putUTXO(Buffer.alloc(32, 0xbb), 0, {
        height: 6,
        coinbase: false,
        amount: 2_00000000n,
        scriptPubKey: Buffer.from([0x6a, 0x02]),
      });
      const { hash: hashWithBoth, coinsCount: countBoth } = await computeUTXOSetHash(db);
      expect(countBoth).toBe(2n);

      // Different content → different digest. This is the proof: the
      // strict gate is NOT computed over a snapshot-isolated coins view.
      expect(hashWithBoth.equals(hashWithPre)).toBe(false);
    } finally {
      await db.close();
    }
  });
});

// =============================================================================
// G16 — coins_cache.SetBestBlock(base_blockhash) after load (BUG-8)
// =============================================================================

describe("W138-G16: best-block persistence after coin load (BUG-8, P0-CDIV)", () => {
  it("BUG-8: loadSnapshot mutates only in-memory tipHash, NOT db chain state", () => {
    // Core validation.cpp:5870 calls coins_cache.SetBestBlock(base_blockhash)
    // BEFORE the trailing-byte check + hash gate. In hotbuns the in-memory
    // tipHash is set at snapshot.ts:896-897 but the db's chain state is
    // NEVER written — that lives in the CLI wrapper runSnapshotLoad.
    const loadStart = SNAPSHOT_TS.indexOf("async loadSnapshot(");
    const loadEnd = SNAPSHOT_TS.indexOf("\n  }", loadStart) + 4;
    const fn = SNAPSHOT_TS.slice(loadStart, loadEnd);
    expect(fn).not.toMatch(/putChainState/);
    expect(fn).not.toMatch(/bestBlockHash/);
    // CLI does the persist:
    expect(CLI_TS).toMatch(/await db\.putChainState/);
    expect(CLI_TS).toMatch(/bestBlockHash: result\.baseBlockHash/);
  });

  it("BUG-8 CLOSED: loadtxoutset RPC is now wired (drives the background validator), no longer refused", async () => {
    // The loadtxoutset RPC used to be refused ("disabled in this build"). It is
    // now wired: it loads the snapshot into an isolated store and drives the
    // background validator (startBackgroundValidation) genesis->base, surfacing
    // the verdict via getchainstates rather than promoting the snapshot into the
    // live chainstate. Confirm the refusal string is gone and the bg driver wired.
    expect(RPC_SERVER_TS).not.toContain("loadtxoutset RPC is disabled in this build");
    expect(RPC_SERVER_TS).toContain("startBackgroundValidation");
  });
});

// =============================================================================
// G17 — Final work-vs-active-tip recheck (PRESENT)
// =============================================================================

describe("W138-G17: work-vs-active-tip recheck (height-approx)", () => {
  it("PRESENT: snapshot.ts rejects with 'Work does not exceed active chainstate'", () => {
    expect(SNAPSHOT_TS).toContain("Work does not exceed active chainstate");
    expect(SNAPSHOT_TS).toContain("auData.height <= activeTipHeight");
  });

  it("PARITY GAP: hotbuns uses height comparison; Core uses CBlockIndexWorkComparator", () => {
    // For mainnet at the four hardcoded assumeutxo heights, chained-work
    // is monotonic in height so this is a safe approximation. Documented
    // explicitly in source.
    expect(SNAPSHOT_TS).toMatch(/approximate.*height/i);
  });
});

// =============================================================================
// G18 — m_chain_tx_count = au_data.m_chain_tx_count fake (BUG-9)
// =============================================================================

describe("W138-G18: m_chain_tx_count fake on snapshot tip (BUG-9, P0-CDIV)", () => {
  it("BUG-9: dumpSnapshot returns nChainTx: 0n with a TODO comment", () => {
    expect(SNAPSHOT_TS).toContain("nChainTx: 0n, // Would need to be computed from block index");
  });

  it("BUG-9: AssumeutxoData.nChainTx is in the interface but never consulted from loadSnapshot", () => {
    // The field exists in the AssumeutxoData interface (snapshot.ts:72)
    // and is populated for the four mainnet entries in
    // consensus/params.ts (e.g. 840000 → 991_032_194n). But loadSnapshot
    // never reads auData.nChainTx to populate any block index entry.
    expect(SNAPSHOT_TS).toMatch(/nChainTx:\s*bigint/);
    const loadStart = SNAPSHOT_TS.indexOf("async loadSnapshot(");
    const loadEnd = SNAPSHOT_TS.indexOf("\n  }", loadStart) + 4;
    const fn = SNAPSHOT_TS.slice(loadStart, loadEnd);
    expect(fn).not.toMatch(/auData\.nChainTx/);
    expect(fn).not.toMatch(/m_chain_tx_count/);
  });

  it("BUG-9: CLI wrapper runSnapshotLoad writes nTx: 0 into the block index for the snapshot tip", () => {
    // The CLI is the only path that puts a block index entry for the
    // snapshot's base block. It uses nTx: 0 — not auData.nChainTx.
    expect(CLI_TS).toMatch(/await db\.putBlockIndex\(result\.baseBlockHash,\s*\{/);
    expect(CLI_TS).toMatch(/nTx: 0,/);
  });

  it("BUG-9: mainnet 840 000 entry registers nChainTx = 991 032 194 (would be the correct fake)", () => {
    // Cross-check the params data exists; the fix would be to write
    // this into the block index at load time.
    const e840 = MAINNET.assumeutxo!.get(
      "a583da1c3ff29b687248ff737822f8ce4827033a282003000000000000000000",
    );
    expect(e840).toBeDefined();
    expect(e840!.nChainTx).toBe(991_032_194n);
    expect(e840!.height).toBe(840000);
  });
});

// =============================================================================
// G19 — BLOCK_OPT_WITNESS fake walk (BUG-10)
// =============================================================================

describe("W138-G19: BLOCK_OPT_WITNESS fake walk over snapshot range (BUG-10, P1-API)", () => {
  it("BUG-10: snapshot.ts never references BLOCK_OPT_WITNESS / OPT_WITNESS", () => {
    // Core validation.cpp:5935 (inside PopulateAndValidateSnapshot, after
    // the strict hash check passes):
    //   if (DeploymentActiveAt(*index, *this, Consensus::DEPLOYMENT_SEGWIT)) {
    //       index->nStatus |= BLOCK_OPT_WITNESS;
    //   }
    // The constant exists in hotbuns at storage/database.ts:48
    // (BlockStatus.OPT_WITNESS = 128) but snapshot.ts does not import or
    // mutate it.
    expect(SNAPSHOT_TS).not.toMatch(/OPT_WITNESS/);
    expect(SNAPSHOT_TS).not.toMatch(/BLOCK_OPT_WITNESS/);
    expect(SNAPSHOT_TS).not.toMatch(/DeploymentActiveAt/);
    expect(SNAPSHOT_TS).not.toMatch(/DEPLOYMENT_SEGWIT/);
  });
});

// =============================================================================
// G20 — cleanup_bad_snapshot lambda (BUG-11)
// =============================================================================

describe("W138-G20: cleanup_bad_snapshot on error path (BUG-11, P2)", () => {
  it("BUG-11: no error-path cleanup wipes partially-loaded UTXOs from the shared db", () => {
    // Core validation.cpp:5677-5694 — cleanup_bad_snapshot:
    //   1. MaybeRebalanceCaches()  (back to IBD allocation)
    //   2. DeleteCoinsDBFromDisk(*snapshot_datadir, /*is_snapshot=*/true)
    // Hotbuns has neither — no rebalance, no UTXO wipe.
    expect(SNAPSHOT_TS).not.toMatch(/cleanup_bad_snapshot/);
    expect(SNAPSHOT_TS).not.toMatch(/cleanupBadSnapshot/);
    expect(SNAPSHOT_TS).not.toMatch(/DeleteCoinsDBFromDisk/);
    expect(SNAPSHOT_TS).not.toMatch(/deleteCoinsDBFromDisk/);

    // The loadSnapshot try/finally only closes the file handle. A throw
    // mid-batch leaves partial UTXOs in the leveldb.
    const loadStart = SNAPSHOT_TS.indexOf("async loadSnapshot(");
    const loadEnd = SNAPSHOT_TS.indexOf("\n  }", loadStart) + 4;
    const fn = SNAPSHOT_TS.slice(loadStart, loadEnd);
    expect(fn).toMatch(/await fh\.close\(\)\.catch\(/);
    expect(fn).not.toMatch(/await this\.db\.batch\(\s*delKeys/);
  });
});

// =============================================================================
// G21 — InvalidateCoinsDBOnDisk rename to _INVALID on bg fail (BUG-12)
// =============================================================================

describe("W138-G21: rename to _INVALID on background validation failure (BUG-12, P2)", () => {
  it("BUG-12 (partial fix): mismatch flips the snapshot to INVALID + surfaces a fatal error; on-disk _INVALID rename still a follow-up", () => {
    // FLIPPED (2026-06-13): with the dual-chainstate pass landed, a hash
    // mismatch now flips the snapshot chainstate to INVALID (via
    // finishSnapshotActivation) AND surfaces a fatal error to the caller
    // (Core handle_invalid_snapshot → AbortNode). The bg store's own ChainDB
    // is closed/discarded. What is STILL a follow-up (kept as documented gap):
    // Core's InvalidateCoinsDBOnDisk renames the bg coins dir to `<dir>_INVALID`
    // on disk and the node calls a GLOBAL fatalError; hotbuns surfaces the error
    // to the loadtxoutset caller instead of renaming + global-aborting.
    expect(SNAPSHOT_TS).not.toMatch(/InvalidateCoinsDBOnDisk/);
    expect(SNAPSHOT_TS).not.toMatch(/invalidateCoinsDBOnDisk/);
    // The bg dir-rename-to-_INVALID is NOT implemented (the only `_INVALID`
    // mention would be this absent feature).
    expect(SNAPSHOT_TS).not.toMatch(/db_path \+ ['"]_INVALID/);

    // What IS there now: the INVALID flip on the active/snapshot chainstate
    // (finishSnapshotActivation) and a surfaced fatal-error log.
    expect(SNAPSHOT_TS).toMatch(
      /activation\.snapshot\.status = ChainstateStatus\.INVALID/,
    );
    expect(SNAPSHOT_TS).toMatch(
      /AssumeUTXO background validation FAILED/,
    );
  });
});

// =============================================================================
// G22 — getchainstates RPC (BUG-13)
// =============================================================================

describe("W138-G22: getchainstates RPC (BUG-13, P1-API)", () => {
  it("BUG-13 FIXED: getchainstates RPC is registered + reports snapshot_blockhash/validated", () => {
    // Core rpc/blockchain.cpp:3462-3517 registers getchainstates returning
    // { headers, chainstates: [{ blocks, bestblockhash, bits, target,
    //   difficulty, verificationprogress, snapshot_blockhash?, validated,
    //   coins_db_cache_bytes, coins_tip_cache_bytes }] }. hotbuns now registers
    // it (7125559 emitted bits+target; the loadtxoutset wiring added the
    // snapshot_blockhash/validated branch — camlcoin 3140ab9 / lunarblock
    // a39dd42 parity).
    expect(RPC_SERVER_TS).toMatch(/registerMethod\("getchainstates"/);
    expect(RPC_SERVER_TS).toContain("snapshot_blockhash");
  });

  it("BUG-13: closest hotbuns equivalent is the non-Core getutxosetsnapshot (no dual-chainstate info)", () => {
    // Hotbuns has getutxosetsnapshot at server.ts:7361-7384 which only
    // returns the SINGLE active chainstate's UTXO stats — no headers,
    // no "validated" boolean, no per-chainstate breakdown.
    expect(RPC_SERVER_TS).toContain('registerMethod("getutxosetsnapshot"');
    expect(RPC_SERVER_TS).toContain("txoutset_hash");
    expect(RPC_SERVER_TS).toContain("coins_count");
  });

  it("BUG-13 FIXED: loadtxoutset RPC is registered + WIRED to the real background validator", () => {
    // The refusal ("loadtxoutset RPC is disabled in this build") is GONE: the
    // live handler now loads the snapshot + drives the real dual-chainstate
    // background validation (ChainstateManager.startBackgroundValidation) so a
    // mismatch can never silently validate. Core async AbortNode model:
    // loadtxoutset returns success; getchainstates surfaces the verdict.
    expect(RPC_SERVER_TS).toContain('registerMethod("loadtxoutset"');
    expect(RPC_SERVER_TS).not.toContain(
      "loadtxoutset RPC is disabled in this build",
    );
    expect(RPC_SERVER_TS).toContain("startBackgroundValidation");
  });

  it("BUG-13: dumptxoutset RPC is registered (functional)", () => {
    expect(RPC_SERVER_TS).toContain('registerMethod("dumptxoutset"');
  });
});

// =============================================================================
// G23 — MaybeRebalanceCaches (BUG-14)
// =============================================================================

describe("W138-G23: MaybeRebalanceCaches (BUG-14, P1-API)", () => {
  it("BUG-14: snapshot.ts has no MaybeRebalanceCaches analog", () => {
    // Core validation.cpp:6085 — re-allocates m_total_coinstip_cache /
    // m_total_coinsdb_cache between snapshot and IBD chainstates after
    // every load + after background validation completes.
    expect(SNAPSHOT_TS).not.toMatch(/MaybeRebalanceCaches/);
    expect(SNAPSHOT_TS).not.toMatch(/maybeRebalanceCaches/);
    expect(SNAPSHOT_TS).not.toMatch(/rebalanceCaches/i);
  });

  it("BUG-14: cache budget is constructor-only (maxCacheBytes) — no mutator", () => {
    expect(SNAPSHOT_TS).toMatch(/private maxCacheBytes\?: number/);
    // No `this.maxCacheBytes =` reassignment outside the constructor.
    const reassign = SNAPSHOT_TS.match(/this\.maxCacheBytes\s*=/g) ?? [];
    expect(reassign.length).toBe(1); // only the ctor line
  });
});

// =============================================================================
// G24 — NetworkDisable analog on loadSnapshot (BUG-15)
// =============================================================================

describe("W138-G24: NetworkDisable on loadSnapshot (BUG-15, P2)", () => {
  it("BUG-15: blockSubmissionPaused is toggled by dumpTxoutset rollback but NOT by loadtxoutset / loadSnapshot", () => {
    // dumpTxoutset rollback flips the pause flag at server.ts:7162-7165.
    expect(RPC_SERVER_TS).toMatch(
      /networkPauseActive = targetHeight < tip\.height/,
    );
    expect(RPC_SERVER_TS).toContain("this.blockSubmissionPaused = true");
    // loadSnapshot has no analog — snapshot.ts never touches submission
    // gates because they live in the RPC layer.
    expect(SNAPSHOT_TS).not.toMatch(/blockSubmissionPaused/);
    expect(SNAPSHOT_TS).not.toMatch(/NetworkDisable/);
    expect(SNAPSHOT_TS).not.toMatch(/disable.*network/i);
  });
});

// =============================================================================
// G25 — LoadAssumeutxoChainstate boot-time pickup (BUG-16)
// =============================================================================

describe("W138-G25: LoadAssumeutxoChainstate boot-time pickup (BUG-16, P1-API)", () => {
  it("BUG-16: no LoadAssumeutxoChainstate equivalent in snapshot.ts or cli.ts", () => {
    // Core validation.cpp:6151:
    //   Chainstate* LoadAssumeutxoChainstate() {
    //     ... FindAssumeutxoChainstateDir(m_options.datadir) ...
    //     ... ReadSnapshotBaseBlockhash(*path) ...
    //   }
    expect(SNAPSHOT_TS).not.toMatch(/LoadAssumeutxoChainstate/);
    expect(SNAPSHOT_TS).not.toMatch(/loadAssumeutxoChainstate/);
    expect(CLI_TS).not.toMatch(/LoadAssumeutxoChainstate/);
    expect(CLI_TS).not.toMatch(/loadAssumeutxoChainstate/);
  });

  it("BUG-16: ChainstateManager constructor doesn't probe for in-progress snapshot state", () => {
    // The ctor body has no fsp.access / fs.statSync calls for a
    // chainstate_snapshot/ directory.
    const ctorIdx = SNAPSHOT_TS.indexOf("constructor(db: ChainDB, params: ConsensusParams");
    expect(ctorIdx).toBeGreaterThan(0);
    const ctorEnd = SNAPSHOT_TS.indexOf("\n  }", ctorIdx);
    const ctor = SNAPSHOT_TS.slice(ctorIdx, ctorEnd);
    expect(ctor).not.toMatch(/fs\.access/);
    expect(ctor).not.toMatch(/fsp\.access/);
    expect(ctor).not.toMatch(/fs\.statSync/);
    expect(ctor).not.toMatch(/exists/i);
  });
});

// =============================================================================
// G26 — dumptxoutset latest / rollback / rollback=<h|hash>
// =============================================================================

describe("W138-G26: dumptxoutset types + rollback option", () => {
  it("PRESENT: dumpTxoutset accepts type ∈ {'', 'latest', 'rollback'}", () => {
    expect(RPC_SERVER_TS).toContain('snapshotType !== ""');
    expect(RPC_SERVER_TS).toContain('snapshotType !== "latest"');
    expect(RPC_SERVER_TS).toContain('snapshotType !== "rollback"');
    expect(RPC_SERVER_TS).toMatch(
      /Invalid snapshot type ".*" specified\. Please specify "rollback" or "latest"/,
    );
  });

  it("PRESENT: dumpTxoutset accepts rollback=<height|hash> named option", () => {
    expect(RPC_SERVER_TS).toContain('hasRollbackOption');
    expect(RPC_SERVER_TS).toContain('options.rollback');
    expect(RPC_SERVER_TS).toMatch(/resolveRollbackTarget/);
  });

  it("PRESENT: type='rollback' (no explicit height) uses getLatestSnapshotHeightForRollback", () => {
    expect(RPC_SERVER_TS).toMatch(
      /getLatestSnapshotHeightForRollback\(this\.params,\s*tip\.height\)/,
    );
  });

  it("PRESENT: pruned-mode pre-check refuses if target < firstUnprunedHeight", () => {
    expect(RPC_SERVER_TS).toContain("isPruneMode()");
    expect(RPC_SERVER_TS).toContain("getFirstUnprunedHeight()");
    expect(RPC_SERVER_TS).toMatch(/not available \(pruned data\)/);
  });

  it("PRESENT: getAvailableSnapshotHeights returns sorted heights from params", () => {
    const heights = getAvailableSnapshotHeights(MAINNET);
    expect(heights.length).toBeGreaterThan(0);
    // Should be sorted ascending.
    for (let i = 1; i < heights.length; i++) {
      expect(heights[i]).toBeGreaterThan(heights[i - 1]);
    }
    // Must include the four Core hardcoded heights.
    expect(heights).toContain(840000);
    expect(heights).toContain(880000);
    expect(heights).toContain(910000);
    expect(heights).toContain(935000);
  });

  it("PRESENT: getLatestSnapshotHeightForRollback picks the highest height ≤ tip", () => {
    expect(getLatestSnapshotHeightForRollback(MAINNET, 839_999)).toBeNull();
    expect(getLatestSnapshotHeightForRollback(MAINNET, 840_000)).toBe(840_000);
    expect(getLatestSnapshotHeightForRollback(MAINNET, 879_999)).toBe(840_000);
    expect(getLatestSnapshotHeightForRollback(MAINNET, 880_000)).toBe(880_000);
    expect(getLatestSnapshotHeightForRollback(MAINNET, 1_000_000)).toBeGreaterThanOrEqual(935_000);
  });
});

// =============================================================================
// G27 — MaybeValidateSnapshot tautology (BUG-17)
// =============================================================================

describe("W138-G27: MaybeValidateSnapshot tautology FIXED — bg validator hashes its OWN store (BUG-17, P0-CDIV)", () => {
  it("BUG-17 FIXED: the background pass recomputes HASH_SERIALIZED over its OWN separate store, NOT this.db", async () => {
    // FLIPPED (2026-06-13): the dual-chainstate pass landed. The strict-load
    // gate still computes over the active db:
    //   const { hash } = await computeUTXOSetHash(this.db, interruptCheck)
    // but the BACKGROUND validator now computes over its OWN ChainDB
    // (BackgroundValidator.finalizeAtBase → computeUTXOSetHash(this.bgDB)),
    // which is a genuinely independent genesis->base replay — no longer the
    // tautological hash-of-self over this.db.
    expect(SNAPSHOT_TS).toMatch(
      /await computeUTXOSetHash\(this\.db, interruptCheck\)/,
    );
    // The old tautological `computeUTXOSetHash(this.db)` in
    // finalizeBackgroundValidation is GONE.
    expect(SNAPSHOT_TS).not.toMatch(
      /const \{ hash \} = await computeUTXOSetHash\(this\.db\)/,
    );
    // The bg validator hashes its OWN store.
    expect(SNAPSHOT_TS).toMatch(/computeUTXOSetHash\(this\.bgDB\)/);
    // And the bg store is constructed as a separate ChainDB, refusing to alias.
    expect(SNAPSHOT_TS).toContain("background coins store must be separate");
  });

  it("BUG-17: empirical proof — running the gate twice on the same db gives identical hashes", async () => {
    const db = await freshDB("g27");
    try {
      await db.putUTXO(Buffer.alloc(32, 0x11), 0, {
        height: 1,
        coinbase: false,
        amount: 5n,
        scriptPubKey: Buffer.from([0x6a]),
      });
      await db.putUTXO(Buffer.alloc(32, 0x12), 0, {
        height: 2,
        coinbase: false,
        amount: 7n,
        scriptPubKey: Buffer.from([0x6a]),
      });

      const a = await computeUTXOSetHash(db);
      const b = await computeUTXOSetHash(db);
      expect(a.hash.equals(b.hash)).toBe(true);
      expect(a.coinsCount).toBe(b.coinsCount);
      // The "load gate" and "background gate" comparing identical
      // inputs is exactly what makes G27 tautological.
    } finally {
      await db.close();
    }
  });
});

// =============================================================================
// G28 — startBackgroundValidation has no callers (BUG-17 continuation)
// =============================================================================

describe("W138-G28: startBackgroundValidation has no callers (BUG-17 sister)", () => {
  it("BUG-17 FIXED: startBackgroundValidation is now CALLED by the live loadtxoutset RPC handler", () => {
    expect(SNAPSHOT_TS).toContain("startBackgroundValidation(");
    // The live loadtxoutset RPC handler now drives the real background
    // validator (camlcoin 3140ab9 / lunarblock a39dd42 parity). The CLI path
    // still does not call it directly (it loads the snapshot before P2P/sync
    // components start); the RPC path is the live driver.
    expect(CLI_TS).not.toMatch(/startBackgroundValidation/);
    expect(RPC_SERVER_TS).toMatch(/startBackgroundValidation/);
  });

  it("BUG-17: SnapshotValidationResult enum exists but its values are returned only to the void caller", () => {
    expect(SNAPSHOT_TS).toContain("export enum SnapshotValidationResult");
    expect(SNAPSHOT_TS).toContain("SUCCESS");
    expect(SNAPSHOT_TS).toContain("HASH_MISMATCH");
    expect(SNAPSHOT_TS).toContain("STATS_FAILED");
    // The enum is exported but no external consumer destructures the
    // result anywhere outside of snapshot.ts itself.
    expect(CLI_TS).not.toMatch(/SnapshotValidationResult/);
    expect(RPC_SERVER_TS).not.toMatch(/SnapshotValidationResult/);
    expect(SnapshotValidationResult.SUCCESS).toBe("success");
    expect(SnapshotValidationResult.HASH_MISMATCH).toBe("hash_mismatch");
  });
});

// =============================================================================
// G29 — RemoveLocalServices(NODE_NETWORK) + AddLocalServices(NODE_NETWORK_LIMITED)
// =============================================================================

describe("W138-G29: service-flag toggle on snapshot load (folded into G15)", () => {
  it("documented gap: snapshot.ts never touches p2p service flags", () => {
    // Core rpc/blockchain.cpp:3432-3435 (inside loadtxoutset RPC):
    //   node.connman->RemoveLocalServices(NODE_NETWORK);
    //   node.connman->AddLocalServices(NODE_NETWORK_LIMITED);
    // Hotbuns: no equivalent wiring; the p2p service flags are decided
    // once at PeerManager construction (manager.ts:759-765) based on
    // the --prune flag (BIP-159), not on whether a snapshot was loaded.
    expect(SNAPSHOT_TS).not.toMatch(/NODE_NETWORK_LIMITED/);
    expect(SNAPSHOT_TS).not.toMatch(/RemoveLocalServices/);
    expect(SNAPSHOT_TS).not.toMatch(/AddLocalServices/);
    expect(RPC_SERVER_TS).not.toMatch(/NODE_NETWORK_LIMITED.*loadtxoutset/);
  });
});

// =============================================================================
// G30 — Atomic .incomplete -> <path> rename on dumpSnapshot (PRESENT)
// =============================================================================

describe("W138-G30: atomic .incomplete + sync + rename on dumpSnapshot", () => {
  it("PRESENT: snapshot.ts writes to tempPath then renames atomically", () => {
    expect(SNAPSHOT_TS).toContain('const tempPath = `${filePath}.incomplete`');
    expect(SNAPSHOT_TS).toContain("await fh.sync()");
    expect(SNAPSHOT_TS).toContain("await fsp.rename(tempPath, filePath)");
  });

  it("PRESENT: refuses to overwrite an existing destination (Core's 'already exists' guard)", () => {
    expect(SNAPSHOT_TS).toMatch(
      /already exists\. If you are sure this is what you want, move it out of the way first/,
    );
  });

  it("PRESENT: empirical — dumpSnapshot does NOT leave a .incomplete on success", async () => {
    const db = await freshDB("g30");
    try {
      const tip = Buffer.alloc(32, 0xee);
      await db.putBlockIndex(tip, {
        height: 1,
        header: Buffer.alloc(80, 0),
        nTx: 1,
        status: 0x1f,
        dataPos: 0,
      });
      await db.putChainState({
        bestBlockHash: tip,
        bestHeight: 1,
        totalWork: 1n,
      });

      const snapPath = join(TEST_ROOT, "g30-dump.dat");
      const mgr = new ChainstateManager(db, REGTEST);
      await mgr.dumpSnapshot(snapPath);

      // <path>.incomplete must NOT exist after a successful dump.
      let tempExists = false;
      try {
        await fsp.access(snapPath + ".incomplete");
        tempExists = true;
      } catch {
        tempExists = false;
      }
      expect(tempExists).toBe(false);

      // <path> must exist.
      let pathExists = false;
      try {
        await fsp.access(snapPath);
        pathExists = true;
      } catch {
        pathExists = false;
      }
      expect(pathExists).toBe(true);
    } finally {
      await db.close();
    }
  });
});

// =============================================================================
// Cross-cutting: mainnet assumeutxo entries (cross-reference) + chainparams
// =============================================================================

describe("W138 cross-cutting: hardcoded assumeutxo entries (chainparams parity)", () => {
  it("PRESENT: mainnet entries 840k / 880k / 910k / 935k match Core's m_assumeutxo_data", () => {
    expect(MAINNET.assumeutxo).toBeDefined();
    const entries = Array.from(MAINNET.assumeutxo!.entries());
    expect(entries.length).toBeGreaterThanOrEqual(4);

    const e840 = MAINNET.assumeutxo!.get(
      "a583da1c3ff29b687248ff737822f8ce4827033a282003000000000000000000",
    );
    expect(e840).toBeDefined();
    expect(e840!.height).toBe(840000);
    expect(e840!.hashSerialized.toString("hex")).toBe(
      "a2a5521b1b5ab65f67818e5e8eccabb7171a517f9e2382208f77687310768f96",
    );
    expect(e840!.nChainTx).toBe(991_032_194n);

    const e880 = MAINNET.assumeutxo!.get(
      "8028ca5cec8220cf1dfd2a9c9a960705403c3c28170b01000000000000000000",
    );
    expect(e880!.hashSerialized.toString("hex")).toBe(
      "dbd190983eaf433ef7c15f78a278ae42c00ef52e0fd2a54953782175fbadcea9",
    );

    const e910 = MAINNET.assumeutxo!.get(
      "21a894914616bdb1dccd7ae1ea16d5ff2295cb0a970801000000000000000000",
    );
    expect(e910!.hashSerialized.toString("hex")).toBe(
      "4daf8a17b4902498c5787966a2b51c613acdab5df5db73f196fa59a4da2f1568",
    );

    const e935 = MAINNET.assumeutxo!.get(
      "eeb50f6fa5725eccea7b60ba1bb9b25216af5849034701000000000000000000",
    );
    expect(e935!.hashSerialized.toString("hex")).toBe(
      "e4b90ef9eae834f56c4b64d2d50143cee10ad87994c614d7d04125e2a6025050",
    );
  });

  it("PRESENT: hashhog-local 944183 entry — recovery snapshot for hotbuns + lunarblock", () => {
    // Non-Core entry but byte-identical format.
    const e944 = MAINNET.assumeutxo!.get(
      "17d8ce98333245aba5170dc0c69a0e9d8303160a184601000000000000000000",
    );
    expect(e944).toBeDefined();
    expect(e944!.height).toBe(944183);
    expect(e944!.hashSerialized.toString("hex")).toBe(
      "a888bcbc200384747c0813c8e7f4650d9bc0847b5147791c3ca869567271af2e",
    );
  });

  it("PRESENT: getAssumeutxoData looks up by internal-LE hex (not display-order)", () => {
    // Use the same key as the params entry.
    const internalLE = Buffer.from(
      "a583da1c3ff29b687248ff737822f8ce4827033a282003000000000000000000",
      "hex",
    );
    const lookup = getAssumeutxoData(MAINNET, internalLE);
    expect(lookup).not.toBeNull();
    expect(lookup!.height).toBe(840000);

    // Display-order (block-explorer) hex must NOT resolve — confirming
    // the byte-order discipline documented in consensus/params.ts:608-621.
    const displayOrder = Buffer.from(
      "0000000000000000000320283a032748cef8227873ff4872689bf23f1cda83a5",
      "hex",
    );
    const lookupDisplay = getAssumeutxoData(MAINNET, displayOrder);
    expect(lookupDisplay).toBeNull();
  });

  it("PRESENT: getAssumeutxoDataByHeight resolves all five mainnet snapshot heights", () => {
    expect(getAssumeutxoDataByHeight(MAINNET, 840000)).not.toBeNull();
    expect(getAssumeutxoDataByHeight(MAINNET, 880000)).not.toBeNull();
    expect(getAssumeutxoDataByHeight(MAINNET, 910000)).not.toBeNull();
    expect(getAssumeutxoDataByHeight(MAINNET, 935000)).not.toBeNull();
    expect(getAssumeutxoDataByHeight(MAINNET, 944183)).not.toBeNull();
    // Negative cases — heights between the Core entries.
    expect(getAssumeutxoDataByHeight(MAINNET, 850000)).toBeNull();
    expect(getAssumeutxoDataByHeight(MAINNET, 900000)).toBeNull();
  });
});

// =============================================================================
// Cross-cutting: REGTEST has no assumeutxo entries (correct)
// =============================================================================

describe("W138 cross-cutting: REGTEST has no assumeutxo entries", () => {
  it("PRESENT: REGTEST.assumeutxo is an empty Map (no hardcoded snapshots on regtest)", () => {
    expect(REGTEST.assumeutxo).toBeDefined();
    expect(REGTEST.assumeutxo!.size).toBe(0);
    expect(getAvailableSnapshotHeights(REGTEST)).toEqual([]);
    expect(getLatestSnapshotHeightForRollback(REGTEST, 1_000_000)).toBeNull();
  });
});
