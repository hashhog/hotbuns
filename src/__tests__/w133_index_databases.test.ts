/**
 * W133 — Index databases (txindex + coinstatsindex) — hotbuns
 *
 * Discovery audit (no production code changes).  Each test below
 * either:
 *   (a) PASSes today, documenting a Core-parity behavior we want to
 *       keep, OR
 *   (b) DOCUMENTS a bug by asserting the CURRENT divergent behavior
 *       and including a `// BUG-N` comment so a future fix wave can
 *       grep this file and invert the assertions.
 *
 * Reference:
 *   - bitcoin-core/src/index/base.{h,cpp}
 *   - bitcoin-core/src/index/txindex.{h,cpp}
 *   - bitcoin-core/src/index/coinstatsindex.{h,cpp}
 *   - bitcoin-core/src/index/disktxpos.h
 *   - bitcoin-core/src/index/db_key.h
 *   - bitcoin-core/src/kernel/coinstats.cpp  (GetBogoSize, ApplyCoinHash)
 *   - bitcoin-core/src/script/script.h        (IsUnspendable)
 *   - bitcoin-core/src/crypto/muhash.h        (MuHash3072 spec)
 *
 * Companion document: audit/w133_index_databases.md.
 *
 * Run: bun test src/__tests__/w133_index_databases.test.ts
 */

import { describe, it, expect } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  MuHash,
  CoinStatsIndex,
  TxIndexManager,
  BlockFilterIndex,
  IndexManager,
} from "../storage/indexes.js";

// =============================================================================
// Helpers
// =============================================================================

/** Path-relative repo root for source-level audits. */
const REPO_ROOT = join(import.meta.dirname, "..", "..");
const SRC_ROOT = join(REPO_ROOT, "src");

function readSrc(rel: string): string {
  return readFileSync(join(SRC_ROOT, rel), "utf8");
}

/** Build a Buffer of the specified length filled with a tag byte. */
function tagBuf(len: number, tag: number): Buffer {
  return Buffer.alloc(len, tag);
}

// =============================================================================
// G01 — TxIndex production path indexes genesis (BUG-1)
// =============================================================================

describe("W133-G01: TxIndex skip-genesis (Core txindex.cpp:77)", () => {
  it("TxIndexManager.indexBlock correctly skips genesis (the dead path)", async () => {
    // Reference: bitcoin-core/src/index/txindex.cpp:77
    //   if (block.height == 0) return true;
    //
    // hotbuns's TxIndexManager (storage/indexes.ts:1361-1364) matches Core.
    // This test exists to pin the BEHAVIOR of the helper that is NOT wired.
    const calls: any[] = [];
    const fakeDB: any = {
      batchWrite: async (ops: any[]) => calls.push(...ops),
      batch: async (ops: any[]) => calls.push(...ops),
      getTxIndex: async () => null,
    };
    const mgr = new TxIndexManager(fakeDB, true);
    const block = {
      header: {
        version: 1,
        prevBlock: Buffer.alloc(32),
        merkleRoot: Buffer.alloc(32),
        timestamp: 1231006505,
        bits: 0x1d00ffff,
        nonce: 0,
      },
      transactions: [
        {
          version: 1,
          inputs: [
            {
              prevOut: { txid: Buffer.alloc(32), vout: 0xffffffff },
              scriptSig: Buffer.from([0x04, 0xff, 0xff, 0x00, 0x1d]),
              sequence: 0xffffffff,
              witness: [],
            },
          ],
          outputs: [{ value: 5000000000n, scriptPubKey: Buffer.from([0x00]) }],
          lockTime: 0,
        },
      ],
    };

    await mgr.indexBlock(block as any, 0, Buffer.alloc(32, 1), 0);
    expect(calls.length).toBe(0); // genesis skipped, no ops emitted
  });

  it("BUG-1: production path (sync/blocks.ts) does NOT skip genesis", () => {
    // Static-source audit: sync/blocks.ts::writeTxIndexForBlock loops
    // `block.transactions` unconditionally with no height guard.  If a
    // future wave moves the production path to call TxIndexManager
    // instead, this test will need to be inverted.
    const src = readSrc("sync/blocks.ts");
    const helperBody = src
      .split("private async writeTxIndexForBlock")[1]
      ?.split("private async deleteTxIndexForBlock")[0] ?? "";

    // No `height === 0` guard exists in the helper body.
    expect(helperBody).not.toContain("height === 0");
    expect(helperBody).not.toContain("height == 0");
    // The chain/state.ts mirror also skips no genesis.
    const stateSrc = readSrc("chain/state.ts");
    // The connect block's txindex loop sits between these two markers.
    const connectIdx = stateSrc.indexOf("Pattern C0: write txindex on connect");
    expect(connectIdx).toBeGreaterThan(0);
    const window = stateSrc.slice(connectIdx, connectIdx + 1200);
    expect(window).not.toMatch(/\bheight\s*={2,3}\s*0\b/);
  });
});

// =============================================================================
// G02 — TxIndex disk-pos shape (BUG-2)
// =============================================================================

describe("W133-G02: TxIndex on-disk format vs CDiskTxPos", () => {
  it("BUG-2: TxIndexEntry is fixed 40B (blockHash:32 + offset:u32 + length:u32)", () => {
    // Reference: bitcoin-core/src/index/disktxpos.h:17 —
    //   READWRITE(AsBase<FlatFilePos>(obj), VARINT(obj.nTxOffset));
    // i.e. (file:i32 + pos:u32 + VARINT(nTxOffset)) ≈ 8-12 bytes
    //
    // hotbuns: serializeTxIndex in database.ts writes 40 bytes.
    // Also: offset and length are ALWAYS zero in the wired paths
    // (chain/state.ts:408-411, sync/blocks.ts:1693-1699).
    const dbSrc = readSrc("storage/database.ts");
    expect(dbSrc).toContain("blockHash"); // entry shape exposes blockHash
    // 40 = 32(hash) + 4(offset LE) + 4(length LE)
    expect(dbSrc).toMatch(/Buffer\.alloc(?:Unsafe)?\(\s*40\s*\)/);
  });
});

// =============================================================================
// G03 — TxIndex key shape (PASS)
// =============================================================================

describe("W133-G03: TxIndex key shape (prefix + txid32) — PASS", () => {
  it("DBPrefix.TX_INDEX is 0x74 'b' / one-byte prefix matches Core's DB_TXINDEX", () => {
    // Core txindex.cpp:31: constexpr uint8_t DB_TXINDEX{'t'};  → 0x74
    // hotbuns database.ts:25:  TX_INDEX = 0x74, // 't'
    const dbSrc = readSrc("storage/database.ts");
    expect(dbSrc).toMatch(/TX_INDEX\s*=\s*0x74,?\s*\/\/\s*'t'/);
  });
});

// =============================================================================
// G04 — Separate DB path (BUG-3)
// =============================================================================

describe("W133-G04: TxIndex lives in indexes/txindex/ subdir (BUG-3)", () => {
  it("BUG-3: hotbuns has no indexes/txindex/ subdir — shares main chainstate LevelDB", () => {
    // Core: txindex.cpp:51 — DataDirNet() / "indexes" / "txindex"
    // hotbuns: chain DB hosts TX_INDEX under prefix 0x74; no separate path.
    const dbSrc = readSrc("storage/database.ts");
    expect(dbSrc).not.toContain("indexes/txindex");
    // The whole hotbuns codebase has no reference to indexes/txindex or
    // indexes/coinstatsindex (W121 used `indexes` only in comments).
  });
});

// =============================================================================
// G05 — Obfuscation key (BUG-4)
// =============================================================================

describe("W133-G05: Index DB obfuscation key (BUG-4)", () => {
  it("BUG-4: no f_obfuscate equivalent on hotbuns index DB", () => {
    // Core BaseIndex::DB takes f_obfuscate; hotbuns uses ClassicLevel
    // without any obfuscation.  classic-level is referenced from
    // database.ts; grep for any obfuscation-key write or seed.
    const dbSrc = readSrc("storage/database.ts");
    expect(dbSrc.toLowerCase()).not.toContain("obfuscat");
  });
});

// =============================================================================
// G06 — AllowPrune == false for TxIndex (BUG-5)
// =============================================================================

describe("W133-G06: TxIndex AllowPrune=false / prune-lock registration (BUG-5)", () => {
  it("BUG-5: no prune-lock coupling between txindex height and pruner", () => {
    // Core txindex.h:34: bool AllowPrune() const override { return false; }
    // base.cpp:487: SetBestBlockIndex updates m_blockman.UpdatePruneLock.
    //
    // hotbuns storage/pruning.ts has no reference to txindex height.
    const pruningSrc = readSrc("storage/pruning.ts");
    expect(pruningSrc.toLowerCase()).not.toContain("txindex");
    expect(pruningSrc.toLowerCase()).not.toContain("tx_index");
  });
});

// =============================================================================
// G07 — -txindex CLI flag (BUG-6)
// =============================================================================

describe("W133-G07: -txindex user-facing flag (BUG-6)", () => {
  it("BUG-6: no -txindex CLI flag; production unconditionally writes index entries", () => {
    // Core: txindex.h:19 constexpr bool DEFAULT_TXINDEX{false}.
    // hotbuns: cli.ts:2080 explicitly admits no -txindex flag exists.
    const cliSrc = readSrc("cli/cli.ts");
    expect(cliSrc).toContain("hotbuns has no `-txindex` user-facing flag");
    // Conversely, --blockfilterindex IS exposed (W121 work).
    expect(cliSrc).toContain("--blockfilterindex");
  });
});

// =============================================================================
// G08 — FindTx txid cross-check (BUG-7)
// =============================================================================

describe("W133-G08: FindTx txid re-verification (BUG-7)", () => {
  it("BUG-7: rpc/server.ts::findTxInBlock never re-verifies txid after decode", () => {
    // Core txindex.cpp:114: if (tx->GetHash() != tx_hash) { LogError(...) }
    // hotbuns: rpc/server.ts::findTxInBlock returns the first matching tx.
    const rpcSrc = readSrc("rpc/server.ts");
    const fnIdx = rpcSrc.indexOf("private async findTxInBlock");
    expect(fnIdx).toBeGreaterThan(0);
    // The fn body has no explicit re-hash + compare step.
    const fnBody = rpcSrc.slice(fnIdx, fnIdx + 4000);
    // Look for either "GetHash()" or a hash256(...) compare wired to the
    // input txid.  Neither exists in current code.
    expect(fnBody).not.toMatch(/getTxId\([^)]+\)\.equals\(\s*txid\b/);
  });
});

// =============================================================================
// G09 — TxIndex revert on disconnect (PASS)
// =============================================================================

describe("W133-G09: TxIndex revert on disconnect — PASS", () => {
  it("disconnectBlock + reorg delete the txindex entries (sync/blocks.ts:1943 + chain/state.ts:710-713)", () => {
    // Core: BaseIndex::BlockDisconnected via CustomRemove on TxIndex —
    // implicit via the locator/best-block update.  hotbuns wires explicit
    // batched deletes from both sync/blocks.ts and chain/state.ts.
    const syncSrc = readSrc("sync/blocks.ts");
    const stateSrc = readSrc("chain/state.ts");
    expect(syncSrc).toContain("buildTxIndexDeleteOp");
    expect(stateSrc).toContain("buildTxIndexDeleteOp");
  });
});

// =============================================================================
// G10 — prev-hash chain check in CoinStatsIndex (BUG-8)
// =============================================================================

describe("W133-G10: CoinStatsIndex prev-hash chain check (BUG-8)", () => {
  it("BUG-8: indexBlock does not validate header.prevBlock vs currentHash", () => {
    // Core coinstatsindex.cpp:115-120 errors on mismatch and aborts append.
    const src = readSrc("storage/indexes.ts");
    const csiStart = src.indexOf("class CoinStatsIndex");
    expect(csiStart).toBeGreaterThan(0);
    const csi = src.slice(csiStart, csiStart + 8000);
    // The block.header.prevBlock is never compared against this.currentHash.
    expect(csi).not.toMatch(/header\.prevBlock\s*[!=]==?.*currentHash/);
    expect(csi).not.toMatch(/currentHash\.\s*equals\(\s*block\.header\.prevBlock/);
  });
});

// =============================================================================
// G11 — MuHash = MuHash3072 (BUG-9, P0)
// =============================================================================

describe("W133-G11: MuHash3072 cryptographic parity (BUG-9, P0)", () => {
  it("BUG-9a: MuHash class self-documents simplification (NOT real MuHash3072)", () => {
    const src = readSrc("storage/indexes.ts");
    expect(src).toContain("Simplified");
    expect(src).toContain("For full MuHash3072");
  });

  it("BUG-9b: serialized state is 64B (Core MuHash3072 is 768B = 2 * Num3072)", () => {
    const m = new MuHash();
    expect(m.serialize().length).toBe(64); // 32+32; Core: 384+384 = 768
  });

  it("BUG-9c: insert+remove of same UTXO does NOT return to identity", () => {
    // Core: MuHash3072.Insert(x) * MuHash3072.Remove(x) = identity
    //       (multiplication is commutative + Remove is modular inverse)
    // hotbuns: insert(x) multiplies numerator; remove(x) multiplies
    // denominator.  These are different sides of a SHA256-chain; their
    // sha256 concat with the constant identity does NOT cancel.
    const fresh = new MuHash().finalize();

    const m = new MuHash();
    const txid = tagBuf(32, 0x11);
    const script = Buffer.from([0x76, 0xa9, 0x14, ...tagBuf(20, 0x22), 0x88, 0xac]);
    m.insert(txid, 0, 100, false, 50000000n, script);
    m.remove(txid, 0, 100, false, 50000000n, script);
    const after = m.finalize();

    // Document the divergence: after != fresh (Core: would be ==).
    expect(after.equals(fresh)).toBe(false);
  });

  it("BUG-9d: MuHash is order-DEPENDENT (Core MuHash3072 is order-independent)", () => {
    // Two UTXOs inserted in different orders should produce equal hashes
    // under Core's MuHash3072 (multiplicative, commutative).  Under
    // hotbuns's SHA256-chain, the hashes differ because hash(a||b) !=
    // hash(b||a).
    const txid1 = tagBuf(32, 0x01);
    const txid2 = tagBuf(32, 0x02);
    const script = Buffer.from([0x6a, 0x00]); // OP_RETURN — but MuHash doesn't filter

    const m1 = new MuHash();
    m1.insert(txid1, 0, 1, false, 100n, script);
    m1.insert(txid2, 0, 1, false, 200n, script);

    const m2 = new MuHash();
    m2.insert(txid2, 0, 1, false, 200n, script);
    m2.insert(txid1, 0, 1, false, 100n, script);

    // Core: equal.  hotbuns: divergent.  Documents the current behavior.
    expect(m1.finalize().equals(m2.finalize())).toBe(false);
  });
});

// =============================================================================
// G12 — BIP-30 unspendable coinbase (BUG-10)
// =============================================================================

describe("W133-G12: BIP-30 unspendable coinbase exemption (BUG-10)", () => {
  it("BUG-10: CoinStatsIndex.indexBlock has no BIP-30 awareness", () => {
    const src = readSrc("storage/indexes.ts");
    const csiStart = src.indexOf("class CoinStatsIndex");
    const csi = src.slice(csiStart, csiStart + 8000);
    expect(csi.toLowerCase()).not.toContain("bip30");
    expect(csi.toLowerCase()).not.toContain("bip-30");
    expect(csi.toLowerCase()).not.toContain("isbip30unspendable");
  });
});

// =============================================================================
// G13 — IsUnspendable definition (BUG-11)
// =============================================================================

describe("W133-G13: IsUnspendable scope (BUG-11 — FIXED)", () => {
  it("coinStatsIsUnspendable checks OP_RETURN at offset 0 AND size > MAX_SCRIPT_SIZE (=10000)", () => {
    // Core script.h:565: (size>0 && first==OP_RETURN) || size > MAX_SCRIPT_SIZE (=10000).
    // hotbuns implements this as the module-level helper coinStatsIsUnspendable,
    // applied in indexBlock's created-outputs loop (the CustomAppend mirror).
    const src = readSrc("storage/indexes.ts");
    const fnStart = src.indexOf("function coinStatsIsUnspendable");
    expect(fnStart).toBeGreaterThan(0);
    const fn = src.slice(fnStart, fnStart + 400);
    // OP_RETURN-at-offset-0 check…
    expect(fn).toMatch(/0x6a/);
    // …AND the MAX_SCRIPT_SIZE (10000) threshold, strict `>` (not `>=`).
    expect(fn).toMatch(/length > 10000/);
    expect(fn).not.toMatch(/length >= 10000/);
  });
});

// =============================================================================
// G14 — bogo_size formula (BUG-12)
// =============================================================================

describe("W133-G14: bogo_size formula = 50 + script_len (BUG-12)", () => {
  it("BUG-12: hotbuns's getBogoSize is 32 + script_len, missing the 18-byte constant", () => {
    // Core kernel/coinstats.cpp:35-43:
    //   32 + 4 + 4 + 8 + 2 + script_len  → 50 + script_len
    const src = readSrc("storage/indexes.ts");
    const fn = src.split("function getBogoSize")[1]?.split("function ")[0] ?? "";
    expect(fn).toContain("32");
    // The other constants (4, 4, 8, 2) totaling 18 bytes are NOT present.
    expect(fn).not.toMatch(/\b50\b/);
    expect(fn).not.toMatch(/\b32\s*\+\s*4\s*\+\s*4\s*\+\s*8\s*\+\s*2\b/);
  });
});

// =============================================================================
// G15 — CoinStatsIndex CustomRemove (BUG-13, P0)
// =============================================================================

describe("W133-G15: CoinStatsIndex.removeBlock (BUG-13, P0)", () => {
  it("BUG-13: CoinStatsIndex class has no removeBlock method", () => {
    // Core coinstatsindex.cpp:216-234 — CustomRemove drives a per-block
    // muhash rollback + counter restore.  hotbuns: absent.
    const csi = new CoinStatsIndex({} as any, true);
    expect((csi as any).removeBlock).toBeUndefined();
  });

  it("BUG-13b: storage/indexes.ts contains no CoinStatsIndex.removeBlock", () => {
    const src = readSrc("storage/indexes.ts");
    const csiStart = src.indexOf("class CoinStatsIndex");
    const csiEnd = src.indexOf("\n}\n", csiStart);
    expect(csiStart).toBeGreaterThan(0);
    expect(csiEnd).toBeGreaterThan(csiStart);
    const csi = src.slice(csiStart, csiEnd);
    expect(csi).not.toContain("removeBlock");
    expect(csi).not.toContain("revertBlock");
    expect(csi).not.toContain("customRemove");
  });
});

// =============================================================================
// G16 — connect_undo_data NotifyOptions (BUG-14)
// =============================================================================

describe("W133-G16: NotifyOptions for CoinStatsIndex (BUG-14)", () => {
  it("BUG-14: indexBlock signature takes spentOutputs arg with no NotifyOptions equivalent", () => {
    // Core coinstatsindex.cpp:316 returns
    //   options.{connect_undo_data, disconnect_data, disconnect_undo_data}
    // so BaseIndex auto-reads undo on the index's behalf.  hotbuns requires
    // callers to remember to pass spentOutputs.
    const src = readSrc("storage/indexes.ts");
    expect(src).toContain("spentOutputs: SpentUTXO[]");
    expect(src.toLowerCase()).not.toContain("notifyoptions");
  });
});

// =============================================================================
// G17 — MuHash atomic with best-block (BUG-15)
// =============================================================================

describe("W133-G17: MuHash committed atomically with locator (BUG-15)", () => {
  it("BUG-15: no `CustomCommit`-style batching of muhash with a locator", () => {
    // Core base.cpp:270-288 commits CustomCommit + WriteBestBlock in one
    // CDBBatch atomically.  hotbuns batches the per-height row + muhash +
    // tip pointer, but there is no equivalent of Core's periodic Commit
    // cadence and no muhash-vs-stats reconciliation on Init.
    const src = readSrc("storage/indexes.ts");
    const csiStart = src.indexOf("class CoinStatsIndex");
    const csi = src.slice(csiStart, csiStart + 12000);
    expect(csi).not.toContain("CustomCommit");
    // No reconciliation on init either:
    expect(csi).not.toContain("entry.muhash != out");
    expect(csi).not.toContain("muhash mismatch");
  });
});

// =============================================================================
// G18 — AllowPrune (BUG-16)
// =============================================================================

describe("W133-G18: CoinStatsIndex AllowPrune (BUG-16)", () => {
  it("BUG-16: no AllowPrune coupling; pruner is unaware of coinstatsindex", () => {
    const pruningSrc = readSrc("storage/pruning.ts");
    expect(pruningSrc.toLowerCase()).not.toContain("coinstats");
  });
});

// =============================================================================
// G19/20/21/22 — Missing accumulator fields (BUG-17 / 18 / 19 / 20)
// =============================================================================

describe("W133-G19+G20+G21+G22: Missing per-block accumulators (BUG-17..20)", () => {
  it("BUG-17/18/19/20: CoinStats interface omits Core's six extra accumulators", () => {
    // Core DBVal (coinstatsindex.cpp:46-58):
    //   total_prevout_spent_amount        (arith_uint256)
    //   total_new_outputs_ex_coinbase_amount
    //   total_coinbase_amount
    //   total_unspendables_genesis_block
    //   total_unspendables_bip30
    //   total_unspendables_scripts
    //   total_unspendables_unclaimed_rewards
    const src = readSrc("storage/indexes.ts");
    const ifaceStart = src.indexOf("export interface CoinStats");
    const iface = src.slice(ifaceStart, ifaceStart + 800);
    expect(ifaceStart).toBeGreaterThan(0);
    // None of Core's extra fields exist:
    expect(iface).not.toMatch(/total_?[Pp]revout/);
    expect(iface).not.toMatch(/total_?[Nn]ew_?[Oo]utputs/);
    expect(iface).not.toMatch(/total_?[Cc]oinbase_?[Aa]mount/);
    expect(iface).not.toMatch(/total_?[Uu]nspendables/);
    expect(iface).not.toMatch(/total_?[Uu]nclaimed/);
  });
});

// =============================================================================
// G23 — LookUpStats RPC primitive (BUG-21)
// =============================================================================

describe("W133-G23: LookUpStats height-or-hash lookup (BUG-21)", () => {
  it("BUG-21: getStats is height-only; no hash fallback for reorged blocks", () => {
    const src = readSrc("storage/indexes.ts");
    const fnStart = src.indexOf("async getStats(height: number)");
    expect(fnStart).toBeGreaterThan(0);
    const fn = src.slice(fnStart, fnStart + 1500);
    // Only height-keyed lookup, no hash fallback.
    expect(fn).toContain("heightKey");
    expect(fn).not.toContain("hashKey");
    expect(fn).not.toContain("DBHashKey");
  });
});

// =============================================================================
// G24 — CopyHeightIndexToHashIndex (BUG-22, P0)
// =============================================================================

describe("W133-G24: CopyHeightIndexToHashIndex on reorg (BUG-22, P0)", () => {
  it("BUG-22: no hash-keyed storage for CoinStatsIndex entries", () => {
    // Core db_key.h:71-93 — copy height entry to hash key on reorg so
    // queries against the disconnected block hash still resolve.
    const src = readSrc("storage/indexes.ts");
    const csiStart = src.indexOf("class CoinStatsIndex");
    const csi = src.slice(csiStart, csiStart + 12000);
    expect(csi).not.toContain("DBHashKey");
    expect(csi).not.toContain("CopyHeightIndexToHashIndex");
    expect(csi).not.toMatch(/COIN_STATS_HASH/);
  });
});

// =============================================================================
// G25 — m_synced latch (BUG-23)
// =============================================================================

describe("W133-G25: m_synced sync-then-stream latch (BUG-23)", () => {
  it("BUG-23: no m_synced equivalent on any of the three index classes", () => {
    const src = readSrc("storage/indexes.ts");
    expect(src.toLowerCase()).not.toContain("m_synced");
    expect(src.toLowerCase()).not.toContain("issynced");
    expect(src.toLowerCase()).not.toContain("synced latch");
  });
});

// =============================================================================
// G26 — BlockUntilSyncedToCurrentChain (BUG-24)
// =============================================================================

describe("W133-G26: BlockUntilSyncedToCurrentChain RPC primitive (BUG-24)", () => {
  it("BUG-24: no BlockUntilSyncedToCurrentChain helper exists in hotbuns", () => {
    const src = readSrc("storage/indexes.ts");
    expect(src.toLowerCase()).not.toContain("blockuntilsynced");
    expect(src.toLowerCase()).not.toContain("block_until_synced");
  });
});

// =============================================================================
// G27 — Single-batch atomic write (PASS via db.batch)
// =============================================================================

describe("W133-G27: indexBlock batches operations atomically — PASS", () => {
  it("CoinStatsIndex.indexBlock writes COIN_STATS + MUHASH + TIP via one db.batch", () => {
    // Source-level audit: the three puts in indexBlock all go through a
    // single `await this.db.batch(ops)` call.
    const src = readSrc("storage/indexes.ts");
    const csiIdx = src.indexOf("class CoinStatsIndex");
    const indexBlockIdx = src.indexOf("async indexBlock(", csiIdx);
    expect(indexBlockIdx).toBeGreaterThan(csiIdx);
    const fn = src.slice(indexBlockIdx, indexBlockIdx + 4000);
    // One batch call:
    const batchCount = (fn.match(/await\s+this\.db\.batch\(/g) ?? []).length;
    expect(batchCount).toBe(1);
  });
});

// =============================================================================
// G28 — Unclaimed-reward accounting (BUG-25)
// =============================================================================

describe("W133-G28: total_unspendables_unclaimed_rewards (BUG-25)", () => {
  it("BUG-25: no shortfall reconciliation between subsidy + prevouts vs new + coinbase", () => {
    const src = readSrc("storage/indexes.ts");
    const csiStart = src.indexOf("class CoinStatsIndex");
    const csi = src.slice(csiStart, csiStart + 12000);
    expect(csi.toLowerCase()).not.toContain("unclaimed_rewards");
    expect(csi.toLowerCase()).not.toContain("unclaimedrewards");
    expect(csi.toLowerCase()).not.toContain("unclaimed reward");
  });
});

// =============================================================================
// G29 — -coinstatsindex flag + getindexinfo RPC (BUG-26)
// =============================================================================

describe("W133-G29: -coinstatsindex flag + getindexinfo RPC (BUG-26 — FIXED)", () => {
  it("BUG-26a: --coinstatsindex flag is declared, defaults off (Core DEFAULT_COINSTATSINDEX=false), parsed, and wired", () => {
    const cliSrc = readSrc("cli/cli.ts");
    // Config field declared + defaulted false.
    expect(cliSrc).toContain("coinstatsindex: boolean");
    expect(cliSrc).toContain("coinstatsindex: false");
    // CLI arg parsed and actually used to construct/enable the index.
    expect(cliSrc).toContain('case "coinstatsindex":');
    expect(cliSrc).toContain("mergedConfig.coinstatsindex");
  });

  it("BUG-26b: getindexinfo RPC method is registered", () => {
    const rpcSrc = readSrc("rpc/server.ts");
    expect(rpcSrc).toMatch(/registerMethod\(\s*["']getindexinfo["']/);
  });
});

// =============================================================================
// G30 — Separate indexes/ directory tree (BUG-27)
// =============================================================================

describe("W133-G30: indexes/ subdir per index (BUG-27)", () => {
  it("BUG-27: no `indexes` subdirectory pathing in hotbuns datadir layout", () => {
    // Core: <datadir>/indexes/{txindex, coinstatsindex, blockfilterindex/<type>}
    // hotbuns: chain DB stores all index data under one LevelDB.
    const dbSrc = readSrc("storage/database.ts");
    expect(dbSrc).not.toContain("indexes/");
    expect(dbSrc).not.toContain("indexes/txindex");
    expect(dbSrc).not.toContain("indexes/coinstatsindex");
  });
});

// =============================================================================
// Headline meta-finding: the IndexManager class is never wired
// =============================================================================

describe("W133-META: TxIndexManager/CoinStatsIndex/IndexManager wiring", () => {
  it("META: IndexManager is exported but not instantiated outside tests", () => {
    // Grep equivalent: ensure no `new IndexManager(` appears in src/
    // except in src/__tests__/*.test.ts.
    const stateSrc = readSrc("chain/state.ts");
    const syncSrc = readSrc("sync/blocks.ts");
    const indexSrc = readSrc("index.ts");
    expect(stateSrc).not.toContain("new IndexManager");
    expect(syncSrc).not.toContain("new IndexManager");
    expect(indexSrc).not.toContain("new IndexManager");

    // And no `new TxIndexManager` or `new CoinStatsIndex` outside the
    // wrapper file + tests.
    expect(stateSrc).not.toContain("new TxIndexManager");
    expect(syncSrc).not.toContain("new TxIndexManager");
    expect(stateSrc).not.toContain("new CoinStatsIndex");
    expect(syncSrc).not.toContain("new CoinStatsIndex");
  });

  it("META: production tx-index write path is db.buildTxIndexPutOp / db.putTxIndex", () => {
    // Documents the discovered fork-in-the-road: the OOP wrapper is dead,
    // the flat `db.put*` path is live.
    const stateSrc = readSrc("chain/state.ts");
    const syncSrc = readSrc("sync/blocks.ts");
    expect(stateSrc).toContain("db.putTxIndex");
    expect(syncSrc).toContain("db.buildTxIndexPutOp");
  });
});

// =============================================================================
// Cross-check: GCSFilter wiring (W121-adjacent regression guard)
// =============================================================================

describe("W133-XCHECK: BlockFilterIndex IS wired (W121 closure regression guard)", () => {
  it("BlockFilterIndex is instantiated in cli.ts when --blockfilterindex=1", () => {
    // Pin the W121 wiring so a future W133 fix wave that touches
    // storage/indexes.ts doesn't accidentally un-wire the only wired
    // index.
    const cliSrc = readSrc("cli/cli.ts");
    expect(cliSrc).toContain("BIP-157/158 basic filter index enabled");
    // The reference to BlockFilterIndex setup lives near the boot path:
    expect(cliSrc).toContain("blockfilterindex");
  });
});

// =============================================================================
// Status note (read in CI logs)
// =============================================================================
//
// As of W133 commit, the expected outcome per gate:
//
//   G03, G09, G27, META (1 of 2), XCHECK: PASS
//   G01 / G02 / G04 / G05 / G06 / G07 / G08 / G10..G26 / G28..G30 + META(2):
//     PASS as written, BUT each assertion documents the CURRENT (buggy)
//     state.  A future fix wave that closes a BUG must INVERT the
//     assertion at the cited gate.
//
// Cross-fleet: this audit's META finding (production-vs-wrapper fork)
// is the W133 universal-pattern candidate.  See audit/w133_index_databases.md
// section "Universal patterns".
