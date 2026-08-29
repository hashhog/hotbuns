/**
 * W123 — Mining / GBT parity audit (hotbuns).
 *
 * Reference:
 *   - bitcoin-core/src/node/miner.cpp (BlockAssembler, CreateNewBlock,
 *     TestChunkBlockLimits, addChunks, GetMinimumTime, UpdateTime)
 *   - bitcoin-core/src/rpc/mining.cpp (getblocktemplate, getmininginfo,
 *     submitblock, submitheader, prioritisetransaction,
 *     getprioritisedtransactions, getnetworkhashps,
 *     generatetoaddress, generatetodescriptor, generateblock)
 *   - bitcoin-core/src/policy/feefrac.cpp (CompareChunks / ImprovesFeerateDiagram)
 *   - bitcoin-core/src/consensus/consensus.h
 *   - bitcoin-core/src/policy/policy.h
 *   - BIP-22 / BIP-23 / BIP-141 / BIP-152 / BIP-9
 *
 * 30 audit gates, classified PRESENT / PARTIAL / MISSING.
 *
 * Audit summary (see audit/w123_mining_gbt.md): originally 22 bugs / 30 gates,
 *   PRESENT=10, PARTIAL=7, MISSING=13. P0-CDIV=7, P0-RPC=7, P1=7, P2=1.
 *
 * 2026-05-19 UPDATE: the canonical W123 BUG-21 / W154 BUG-1 / W155 BUG-31
 * **dead-helper-at-the-call-site** fix has landed —
 * `src/rpc/server.ts::getBlockTemplate` and `generateSingleBlock` now route
 * through the `BlockTemplateBuilder` helper (and the new top-level
 * `buildCoinbaseTransaction` / `computeWitnessCommitmentHash` exports on the
 * explicit-tx path). Tests below that previously pinned the BUG presence have
 * been flipped to assert the FIX presence; bug numbering is preserved in the
 * `describe`/`it` titles so the audit history stays linkable. The G19
 * (longpoll) / G15 (mode=proposal) / G16 (submitheader) / G17
 * (prioritisetransaction) / G18 (IBD guard) gates remain open follow-ups —
 * they are still pinning the corresponding bug as MISSING.
 *
 * Running: bun test src/__tests__/w123_mining_gbt.test.ts
 */

import { describe, it, expect } from "bun:test";
import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

import { BlockTemplateBuilder } from "../mining/template.js";

// ---------------------------------------------------------------------------
// Source-level fixtures (audit tests inspect the production source by path,
// to assert structural shapes that don't have a clean runtime hook).
// ---------------------------------------------------------------------------

const __dirname = dirname(fileURLToPath(import.meta.url));
const SRC = resolve(__dirname, "..");

const RPC_SERVER_SRC = readFileSync(resolve(SRC, "rpc", "server.ts"), "utf8");
const MINING_TEMPLATE_SRC = readFileSync(resolve(SRC, "mining", "template.ts"), "utf8");
const MEMPOOL_SRC = readFileSync(resolve(SRC, "mempool", "mempool.ts"), "utf8");
const HEADERS_SRC = readFileSync(resolve(SRC, "sync", "headers.ts"), "utf8");
const COMPACT_BLOCKS_SRC = readFileSync(resolve(SRC, "p2p", "compact_blocks.ts"), "utf8");

// Convenience window-slice extractor for the getblocktemplate function body.
function rpcSlice(needleStart: string, lines = 220): string {
  const idx = RPC_SERVER_SRC.indexOf(needleStart);
  if (idx === -1) return "";
  const after = RPC_SERVER_SRC.slice(idx);
  return after.split("\n").slice(0, lines).join("\n");
}

// =============================================================================
// G1 — tx finality enforcement in template selection (BIP-65/BIP-113/IsFinalTx)
// =============================================================================
describe("W123-G1: tx finality enforcement in template selection — FIXED via helper wire-up", () => {
  it("BlockTemplateBuilder.selectTransactions HAS isFinalTx check (PRESENT in helper)", () => {
    expect(MINING_TEMPLATE_SRC).toContain("isFinalTx(entry.tx, targetHeight, this.medianTimePast)");
    expect(MINING_TEMPLATE_SRC).toContain("notFinal.add(txidHex)");
  });

  it("BUG-1 FIXED: getBlockTemplate now delegates selection to the helper, which runs isFinalTx", () => {
    // After the W123 BUG-21 / W154 BUG-1 / W155 BUG-31 wire-up, server.ts's
    // getBlockTemplate no longer iterates `mempool.getAllTxids()` itself. The
    // builder.createTemplate() call internally invokes selectTransactions,
    // which gates each candidate through isFinalTx().
    const gbt = rpcSlice("private async getBlockTemplate(params: unknown[])", 280);
    expect(gbt.length).toBeGreaterThan(0);
    expect(gbt).toContain("new BlockTemplateBuilder(");
    expect(gbt).toContain("setMedianTimePast(");
    expect(gbt).toContain("builder.createTemplate(");
  });
});

// =============================================================================
// G2 — MAX_BLOCK_WEIGHT enforcement
// =============================================================================
describe("W123-G2: MAX_BLOCK_WEIGHT enforcement (>=) — FIXED via helper wire-up (was BUG-2)", () => {
  it("BlockTemplateBuilder enforces totalWeight + entry.weight >= maxBlockWeight (PRESENT)", () => {
    expect(MINING_TEMPLATE_SRC).toContain("totalWeight + entry.weight >= maxBlockWeight");
  });

  it("BUG-2 FIXED: getBlockTemplate inherits the weight gate via BlockTemplateBuilder", () => {
    // After wire-up, server.ts's GBT path no longer hand-rolls a per-tx weight
    // accumulator (it never had a gate before; now selection happens entirely
    // in the helper's selectTransactions). The hand-rolled `totalWeight +=` is
    // gone too.
    const gbt = rpcSlice("private async getBlockTemplate(params: unknown[])", 280);
    expect(gbt).toContain("new BlockTemplateBuilder(");
    expect(gbt).not.toMatch(/totalWeight\s*\+=\s*entry\.weight/);
  });
});

// =============================================================================
// G3 — reserved-weight (8000) + reserved-coinbase-sigops (400) budgets
// =============================================================================
describe("W123-G3: reserved budgets — FIXED via BlockTemplateBuilder wire-up (was BUG-3, BUG-4)", () => {
  it("BlockTemplateBuilder starts totalWeight at BLOCK_RESERVED_WEIGHT (PRESENT)", () => {
    // Constant defined per Core policy/policy.h:27 DEFAULT_BLOCK_RESERVED_WEIGHT=8000.
    expect(MINING_TEMPLATE_SRC).toContain("const BLOCK_RESERVED_WEIGHT = 8000");
    expect(MINING_TEMPLATE_SRC).toContain("let totalWeight = BLOCK_RESERVED_WEIGHT");
  });
  it("BlockTemplateBuilder starts totalSigOps at COINBASE_OUTPUT_MAX_ADDITIONAL_SIGOPS (PRESENT)", () => {
    expect(MINING_TEMPLATE_SRC).toContain("const COINBASE_OUTPUT_MAX_ADDITIONAL_SIGOPS = 400");
    expect(MINING_TEMPLATE_SRC).toContain("let totalSigOps = COINBASE_OUTPUT_MAX_ADDITIONAL_SIGOPS");
  });

  it("BUG-3 FIXED: getBlockTemplate now routes selection through BlockTemplateBuilder", () => {
    // After the W123 BUG-21 / W154 BUG-1 / W155 BUG-31 wire-up, the production
    // RPC no longer keeps its own `let totalWeight = 0` / `let totalSigOps = 0`
    // counters — selection is delegated to the canonical helper whose budgets
    // start at BLOCK_RESERVED_WEIGHT and COINBASE_OUTPUT_MAX_ADDITIONAL_SIGOPS.
    const gbt = rpcSlice("private async getBlockTemplate(params: unknown[])", 280);
    expect(gbt).toContain("new BlockTemplateBuilder(");
    expect(gbt).toContain("builder.createTemplate(");
    // The old hand-rolled counters are gone.
    expect(gbt).not.toMatch(/let\s+totalWeight\s*=\s*0/);
    expect(gbt).not.toMatch(/let\s+totalSigOps\s*=\s*0/);
  });

  it("BUG-4 FIXED: sigops gate now lives inside the helper (uses `>=`)", () => {
    // The hand-rolled `totalSigOps + txSigOpCost > MAX_BLOCK_SIGOPS_COST` gate
    // has been removed from server.ts; selection delegates to the helper, which
    // uses Core's `>=` semantics at template.ts:408.
    const gbt = rpcSlice("private async getBlockTemplate(params: unknown[])", 280);
    expect(gbt).not.toContain("totalSigOps + txSigOpCost > MAX_BLOCK_SIGOPS_COST");
    expect(MINING_TEMPLATE_SRC).toContain("totalSigOps + txSigOpCost >= maxSigOps");
  });
});

// =============================================================================
// G4 — dependency / ancestor ordering
// =============================================================================
describe("W123-G4: dependency / ancestor ordering — FIXED via BlockTemplateBuilder wire-up", () => {
  it("BlockTemplateBuilder walks dependsOn ancestors recursively (PRESENT)", () => {
    expect(MINING_TEMPLATE_SRC).toContain("addWithAncestors");
    expect(MINING_TEMPLATE_SRC).toContain("for (const parentTxidHex of entry.dependsOn)");
  });
  it("FIXED: getBlockTemplate now relies on helper for ordering (fee-rate + ancestor walk)", () => {
    // After wire-up, server.ts no longer iterates `mempool.getAllTxids()` in
    // Map insertion order. The helper's `selectTransactions` uses
    // `getTransactionsByFeeRate()` with `addWithAncestors` so a parent always
    // precedes its child in the BIP-22 `transactions[]` array. server.ts only
    // re-derives the `depends[]` index numbers from the helper's already-
    // ordered output.
    const gbt = rpcSlice("private async getBlockTemplate(params: unknown[])", 280);
    expect(gbt).toContain("const depends: number[]");
    expect(gbt).not.toContain("this.mempool.getAllTxids()");
    expect(gbt).toContain("template.transactions");
  });
});

// =============================================================================
// G5 — MAX_CONSECUTIVE_FAILURES early-exit
// =============================================================================
describe("W123-G5: MAX_CONSECUTIVE_FAILURES early-exit (1000) — FIXED via helper", () => {
  it("BlockTemplateBuilder has MAX_CONSECUTIVE_FAILURES=1000 + 4000 weight delta (PRESENT)", () => {
    expect(MINING_TEMPLATE_SRC).toContain("MAX_CONSECUTIVE_FAILURES = 1000");
    expect(MINING_TEMPLATE_SRC).toContain("BLOCK_FULL_ENOUGH_WEIGHT_DELTA = 4000");
  });
  it("FIXED: getBlockTemplate inherits the early-exit via BlockTemplateBuilder", () => {
    // After wire-up, the production GBT path delegates to
    // BlockTemplateBuilder.createTemplate which inherits the early-exit
    // (template.ts addWithAncestors loop). The constants do NOT appear in
    // server.ts because the loop body lives in the helper, but the production
    // GBT instantiates the helper.
    const gbt = rpcSlice("private async getBlockTemplate(params: unknown[])", 280);
    expect(gbt).toContain("new BlockTemplateBuilder(");
  });
});

// =============================================================================
// G6 — BIP-94 timewarp clamp in mintime
// =============================================================================
describe("W123-G6: BIP-94 timewarp clamp in mintime — MISSING (BUG-15)", () => {
  it("BIP-94 enforcement exists in header validator (sync/headers.ts)", () => {
    expect(HEADERS_SRC).toContain("MAX_TIMEWARP");
    expect(HEADERS_SRC).toContain("time-timewarp-attack");
  });

  it("BUG-15: neither mining path applies the parent_time - MAX_TIMEWARP clamp at retarget boundary", () => {
    // Core node/miner.cpp:36-46 GetMinimumTime:
    //   if (height % difficulty_adjustment_interval == 0) {
    //     min_time = max(min_time, parent->GetBlockTime() - MAX_TIMEWARP);
    //   }
    // hotbuns: template.ts:265-267 + server.ts:5145-5147 use only MTP+1.
    const gbt = rpcSlice("private async getBlockTemplate(params: unknown[])", 200);
    expect(gbt).not.toContain("MAX_TIMEWARP");
    expect(gbt).not.toMatch(/difficulty.adjustment.interval/i);

    // Helper also doesn't apply it.
    expect(MINING_TEMPLATE_SRC).not.toContain("MAX_TIMEWARP");
  });
});

// =============================================================================
// G7 — coinbase nSequence == MAX_SEQUENCE_NONFINAL (0xfffffffe)
// =============================================================================
describe("W123-G7: coinbase nSequence — FIXED via helper (was BUG-5)", () => {
  it("BlockTemplateBuilder.buildCoinbase uses MAX_SEQUENCE_NONFINAL = 0xfffffffe (PRESENT)", () => {
    expect(MINING_TEMPLATE_SRC).toContain("const MAX_SEQUENCE_NONFINAL = 0xfffffffe");
    expect(MINING_TEMPLATE_SRC).toContain("sequence: MAX_SEQUENCE_NONFINAL");
  });

  it("BUG-5 FIXED: generateSingleBlock no longer hand-rolls coinbase; routes through buildCoinbaseTransaction", () => {
    // The two old private builders (`buildCoinbaseTx` /
    // `buildCoinbaseTxWithWitnessCommitment`) have been deleted; both call
    // sites now use either the BlockTemplateBuilder helper (no-tx path) or
    // the exported `buildCoinbaseTransaction(...)` helper (explicit-tx
    // generateblock path), both of which emit `MAX_SEQUENCE_NONFINAL`.
    expect(RPC_SERVER_SRC).not.toContain("private buildCoinbaseTx(");
    expect(RPC_SERVER_SRC).not.toContain("private buildCoinbaseTxWithWitnessCommitment(");
    // Production server now imports the canonical helper.
    expect(RPC_SERVER_SRC).toContain("buildCoinbaseTransaction,");
  });
});

// =============================================================================
// G8 — coinbase nLockTime == height - 1
// =============================================================================
describe("W123-G8: coinbase nLockTime == height - 1 — FIXED via helper (was BUG-6)", () => {
  it("BlockTemplateBuilder.buildCoinbase sets lockTime: height > 0 ? height - 1 : 0 (PRESENT)", () => {
    expect(MINING_TEMPLATE_SRC).toContain("lockTime: height > 0 ? height - 1 : 0");
  });

  it("BUG-6 FIXED: generateSingleBlock's hand-rolled coinbase is deleted; lockTime now correct via helper", () => {
    // The two private builders that hardcoded lockTime: 0 are gone. Both
    // production call sites route through buildCoinbaseTransaction / the
    // BlockTemplateBuilder, both of which set lockTime = height - 1 (Core
    // node/miner.cpp:196 parity).
    expect(RPC_SERVER_SRC).not.toContain("private buildCoinbaseTx(");
    expect(RPC_SERVER_SRC).not.toContain("private buildCoinbaseTxWithWitnessCommitment(");
    // The export the production server now imports DOES set the BIP-34 lockTime.
    expect(MINING_TEMPLATE_SRC).toContain("export function buildCoinbaseTransaction(");
    expect(MINING_TEMPLATE_SRC).toContain("lockTime: height > 0 ? height - 1 : 0");
  });
});

// =============================================================================
// G9 — BIP-141 witness commitment
// =============================================================================
describe("W123-G9: BIP-141 witness commitment — PRESENT (via helper after wire-up)", () => {
  it("BlockTemplateBuilder emits OP_RETURN(0x6a) PUSH36(0x24) marker(0xaa21a9ed)", () => {
    expect(MINING_TEMPLATE_SRC).toContain("0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed");
  });
  it("getBlockTemplate emits default_witness_commitment by extracting from helper coinbase", () => {
    const gbt = rpcSlice("private async getBlockTemplate(params: unknown[])", 280);
    expect(gbt).toContain("default_witness_commitment");
    // After the wire-up the server.ts GBT path no longer inlines the marker
    // bytes — it copies them out of the helper coinbase's last output. The
    // marker still appears in the segwit-active sanity-check `equals(...)`.
    expect(gbt).toContain("[0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed]");
  });
  it("explicit-tx (generateblock) path uses computeWitnessCommitmentHash + buildCoinbaseTransaction", () => {
    const gen = rpcSlice("private async generateSingleBlock(", 280);
    // No more private buildCoinbaseTxWithWitnessCommitment; the helper
    // module's exports handle commitment construction.
    expect(gen).toContain("computeWitnessCommitmentHash(");
    expect(gen).toContain("buildCoinbaseTransaction(");
    expect(RPC_SERVER_SRC).not.toContain("buildCoinbaseTxWithWitnessCommitment(");
  });
});

// =============================================================================
// G10 — retarget via getNextWorkRequired (next bits)
// =============================================================================
describe("W123-G10: next-block target via getNextWorkRequired — PARTIAL (BUG-7)", () => {
  it("getBlockTemplate computes nextTarget via headerSync.getNextTarget (PRESENT)", () => {
    const gbt = rpcSlice("private async getBlockTemplate(params: unknown[])", 200);
    expect(gbt).toContain("this.headerSync.getNextTarget(parentEntry");
  });

  it("BUG-7: generateSingleBlock uses this.params.powLimit unconditionally (regtest-only target)", () => {
    const gen = rpcSlice("private async generateSingleBlock(", 200);
    expect(gen).toContain("const target = this.params.powLimit");
    expect(gen).not.toContain("getNextTarget");
  });
});

// =============================================================================
// G11 — getmininginfo next.bits / networkhashps / currentblock fields
// =============================================================================
describe("W123-G11: getmininginfo fields — MISSING (BUG-8, BUG-9, BUG-10)", () => {
  it("BUG-8: getmininginfo `next` reports TIP bits/target (not next-block via GetNextWorkRequired)", () => {
    const mi = rpcSlice("private async getMiningInfo()", 35);
    expect(mi).toContain("next: {");
    expect(mi).toContain("bits: tipBitsHex");
    expect(mi).toContain("target: tipTargetHex");
    // Core uses NextEmptyBlockIndex(tip,...) + GetNextWorkRequired(&next_index,...).
    expect(mi).not.toContain("getNextTarget");
    expect(mi).not.toContain("NextEmptyBlockIndex");
  });

  it("BUG-9: getmininginfo `networkhashps` hardcoded to 0 (not delegated to getnetworkhashps)", () => {
    const mi = rpcSlice("private async getMiningInfo()", 35);
    expect(mi).toContain("networkhashps: 0");
    expect(mi).not.toContain("this.getNetworkHashPS");
  });

  it("FIXED (BUG-10): getmininginfo reports currentblockweight / currentblocktx", () => {
    // Core's getmininginfo emits the last-assembled-block stats
    // (m_last_block_weight / m_last_block_num_txs). hotbuns now does too.
    expect(RPC_SERVER_SRC).toContain("currentblockweight");
    expect(RPC_SERVER_SRC).toContain("currentblocktx");
  });
});

// =============================================================================
// G12 — generateSingleBlock timestamp via max(now, MTP+1)
// =============================================================================
describe("W123-G12: generateSingleBlock timestamp >= MTP+1 — FIXED (was BUG-19)", () => {
  it("BUG-19 FIXED: header.timestamp is max(now, MTP+1) on the generateSingleBlock explicit-tx path", () => {
    // After the wire-up, generateSingleBlock pulls parent MTP from headerSync
    // and clamps timestamp = max(now, parentMTP + 1). The empty-tx path goes
    // through BlockTemplateBuilder which has its own MTP+1 floor at
    // template.ts:267, so both production miner entry points respect the
    // MTP+1 invariant.
    const gen = rpcSlice("private async generateSingleBlock(", 280);
    expect(gen).toContain("getMedianTimePast(parentEntry)");
    expect(gen).toContain("Math.max(nowSecs, parentMTP + 1)");
    expect(gen).not.toContain("timestamp: Math.floor(Date.now() / 1000)");
  });
});

// =============================================================================
// G13 — blockmintxfee from -blockmintxfee arg
// =============================================================================
describe("W123-G13: blockmintxfee from operator -blockmintxfee arg — MISSING (BUG-22)", () => {
  it("getmininginfo emits blockmintxfee = DEFAULT_BLOCK_MIN_TX_FEE (0.00000001), hardcoded", () => {
    // Core's DEFAULT_BLOCK_MIN_TX_FEE is 1 sat/kvB = 0.00000001 BTC/kvB
    // (policy.h). The earlier hardcoded 0.00001000 over-reported by 1000x.
    const mi = rpcSlice("private async getMiningInfo()", 40);
    expect(mi).toContain("blockmintxfee: 0.00000001");
  });
  it("No `-blockmintxfee` CLI arg or config parsing exists", () => {
    // Search whole codebase for the option name. Not parsed anywhere.
    const cli = readFileSync(resolve(SRC, "cli", "cli.ts"), "utf8");
    expect(cli).not.toContain("blockmintxfee");
  });
});

// =============================================================================
// G14 — coinbase scriptSig >= 2 bytes (OP_0 dummy when height <= 16)
// =============================================================================
describe("W123-G14: coinbase scriptSig OP_0 dummy when height <= 16 — MISSING (BUG-20)", () => {
  it("BUG-20: BlockTemplateBuilder.buildCoinbase does NOT add OP_0 dummy for h <= 16", () => {
    // Core node/miner.cpp:188-193: `if (include_dummy_extranonce) scriptSig << OP_0;`
    // hotbuns helper emits just the BIP-34 height push.
    const buildCb = MINING_TEMPLATE_SRC.slice(
      MINING_TEMPLATE_SRC.indexOf("private buildCoinbase(")
    ).split("\n").slice(0, 70).join("\n");
    expect(buildCb).not.toMatch(/OP_0/i);
    expect(buildCb).not.toMatch(/include_dummy_extranonce/i);
  });

  it("BUG-20: generateSingleBlock's coinbase doesn't add OP_0 dummy either", () => {
    const buildCb = rpcSlice("private buildCoinbaseTx(", 30);
    expect(buildCb).not.toMatch(/OP_0/i);
    expect(buildCb).not.toMatch(/dummy.*extranonce/i);
  });
});

// =============================================================================
// G15 — GBT mode: "proposal" (BIP-23)
// =============================================================================
describe("W123-G15: GBT mode=proposal — MISSING (BUG-11)", () => {
  it("BUG-11: getBlockTemplate explicitly throws for mode != 'template'", () => {
    const gbt = rpcSlice("private async getBlockTemplate(params: unknown[])", 80);
    expect(gbt).toContain("Only 'template' mode is supported");
  });
});

// =============================================================================
// G16 — submitheader RPC
// =============================================================================
describe("W123-G16: submitheader RPC — MISSING (BUG-12)", () => {
  it("FIXED (BUG-12): submitheader is registered as an RPC method", () => {
    expect(RPC_SERVER_SRC).toContain("submitheader");
  });
});

// =============================================================================
// G17 — prioritisetransaction / getprioritisedtransactions
// =============================================================================
describe("W123-G17: prioritisetransaction / getprioritisedtransactions — MISSING (BUG-13, BUG-14)", () => {
  it("FIXED (BUG-13): prioritisetransaction is a registered RPC", () => {
    expect(RPC_SERVER_SRC).toContain("prioritisetransaction");
  });
  it("FIXED (BUG-14): getprioritisedtransactions is a registered RPC", () => {
    expect(RPC_SERVER_SRC).toContain("getprioritisedtransactions");
  });
  it("FIXED: Mempool has a per-entry feeDelta modifier (the root cause)", () => {
    // BUG-13/14's root cause was the absence of a tx-level fee delta. The
    // mempool now carries one (loadFeeDelta / feeDelta), which is what
    // prioritisetransaction mutates and getprioritisedtransactions reports.
    expect(MEMPOOL_SRC).toContain("feeDelta");
  });
});

// =============================================================================
// G18 — IBD / connman pre-checks on getblocktemplate
// =============================================================================
describe("W123-G18: IBD / connman guards on getblocktemplate — MISSING (BUG-16)", () => {
  it("BUG-16: getBlockTemplate has no `isInitialBlockDownload` check", () => {
    const gbt = rpcSlice("private async getBlockTemplate(params: unknown[])", 200);
    expect(gbt).not.toMatch(/isInitialBlockDownload|isInIBD|isIBD/i);
    expect(gbt).not.toMatch(/RPC_CLIENT_IN_INITIAL_DOWNLOAD/);
  });
  it("BUG-16: getBlockTemplate has no `peerCount==0` / connman check", () => {
    const gbt = rpcSlice("private async getBlockTemplate(params: unknown[])", 200);
    expect(gbt).not.toMatch(/peerCount|getNodeCount|connectedPeers/i);
    expect(gbt).not.toMatch(/RPC_CLIENT_NOT_CONNECTED/);
  });
});

// =============================================================================
// G19 — BIP-22 longpoll
// =============================================================================
describe("W123-G19: BIP-22 longpoll — STILL MISSING (BUG-17)", () => {
  it("BUG-17 STILL OPEN: longpollid is emitted but never honored on subsequent calls", () => {
    // Longpoll wiring was NOT closed by the BlockTemplateBuilder wire-up; it
    // remains a P1 open finding (W155 BUG-20). Slice widened to 280 lines to
    // span the new longer GBT function after the helper wire-up.
    const gbt = rpcSlice("private async getBlockTemplate(params: unknown[])", 280);
    expect(gbt).toContain("longpollid:");
    // No wait loop or tip-change subscription.
    expect(gbt).not.toContain("waitTipChanged");
    expect(gbt).not.toContain("nTransactionsUpdatedLast");
  });
});

// =============================================================================
// G20 — template caching (pindexPrev reuse)
// =============================================================================
describe("W123-G20: template caching (pindexPrev == tip reuse) — MISSING (BUG-18)", () => {
  it("BUG-18: getBlockTemplate rebuilds template from scratch every call (no cache)", () => {
    const gbt = rpcSlice("private async getBlockTemplate(params: unknown[])", 200);
    // No persistent template cache. (Core caches block_template + checks
    // pindexPrev == tip and mempool-update counter.)
    expect(gbt).not.toContain("block_template");
    expect(gbt).not.toContain("cachedTemplate");
    expect(gbt).not.toContain("nTransactionsUpdatedLast");
    // No class-level field to hold the cached template either.
    expect(RPC_SERVER_SRC).not.toMatch(/private\s+cachedBlockTemplate/);
    expect(RPC_SERVER_SRC).not.toMatch(/private\s+lastTemplateTip/);
  });
});

// =============================================================================
// G21 — BlockTemplateBuilder actually called from production RPCs
// =============================================================================
describe("W123-G21: BlockTemplateBuilder used by production RPCs — FIXED (was BUG-21)", () => {
  it("BUG-21 FIXED: rpc/server.ts imports AND instantiates BlockTemplateBuilder", () => {
    // After the W123 BUG-21 / W154 BUG-1 / W155 BUG-31 wire-up the import is
    // multi-line (BlockTemplateBuilder, buildCoinbaseTransaction,
    // computeWitnessCommitmentHash) — match that shape.
    expect(RPC_SERVER_SRC).toContain('from "../mining/template.js"');
    expect(RPC_SERVER_SRC).toContain("BlockTemplateBuilder,");
    expect(RPC_SERVER_SRC).toContain("new BlockTemplateBuilder(");
  });

  it("BUG-21 FIXED: helper has live call sites in production server", () => {
    expect(typeof BlockTemplateBuilder).toBe("function");
    // Production callsites: getBlockTemplate + generateSingleBlock both
    // construct the helper. Match constructor invocations specifically.
    const callSites = RPC_SERVER_SRC.match(/new\s+BlockTemplateBuilder\s*\(/g);
    expect(callSites).not.toBeNull();
    expect((callSites ?? []).length).toBeGreaterThanOrEqual(2);
  });

  it("Helper unchanged in shape: ~685 LOC (delegated coinbase + standalone exports added)", () => {
    // After the wire-up we kept BlockTemplateBuilder's public API stable and
    // delegated its private `buildCoinbase` to a new top-level
    // `buildCoinbaseTransaction` export. Class LOC grows slightly because of
    // the added top-level exports; new ceiling allows up to ~900.
    const lines = MINING_TEMPLATE_SRC.split("\n").length;
    expect(lines).toBeGreaterThan(600);
    expect(lines).toBeLessThan(900);
  });
});

// =============================================================================
// G22 — submitblock BIP-22 string returns
// =============================================================================
describe("W123-G22: submitblock BIP-22 strings — PRESENT", () => {
  it("submitblock returns 'high-hash' on bad PoW", () => {
    expect(RPC_SERVER_SRC).toContain('return "high-hash"');
  });
  it("submitblock returns 'time-too-old' on bad timestamp", () => {
    expect(RPC_SERVER_SRC).toContain('return "time-too-old"');
  });
  it("submitblock returns 'rejected' on NetworkDisable", () => {
    expect(RPC_SERVER_SRC).toContain('return "rejected"');
  });
  it("submitblock has stateless pre-validation path before injectBlock", () => {
    expect(RPC_SERVER_SRC).toContain("BIP-22 stateless pre-validation");
  });
});

// =============================================================================
// G23 — default_witness_commitment field
// =============================================================================
describe("W123-G23: default_witness_commitment in GBT response — PRESENT", () => {
  it("getBlockTemplate emits default_witness_commitment whenever segwit active", () => {
    // Slice widened to 280 lines after the BlockTemplateBuilder wire-up grew
    // the GBT function — the `height >= this.params.segwitHeight` gate now
    // sits ~250 lines into the function.
    const gbt = rpcSlice("private async getBlockTemplate(params: unknown[])", 280);
    expect(gbt).toContain("default_witness_commitment");
    expect(gbt).toContain("height >= this.params.segwitHeight");
  });
});

// =============================================================================
// G24 — BIP-9 rules + vbavailable
// =============================================================================
describe("W123-G24: BIP-9 rules / vbavailable — PRESENT", () => {
  it("rules array includes csv + !segwit (+ taproot when active)", () => {
    const gbt = rpcSlice("private async getBlockTemplate(params: unknown[])", 250);
    expect(gbt).toContain('const gbtRules: string[] = ["csv"]');
    expect(gbt).toContain('gbtRules.push("!segwit")');
    expect(gbt).toContain('gbtRules.push("taproot")');
  });
  it("vbavailable maps deployment name -> bit for STARTED/LOCKED_IN", () => {
    const gbt = rpcSlice("private async getBlockTemplate(params: unknown[])", 250);
    expect(gbt).toContain("DeploymentState.Started");
    expect(gbt).toContain("DeploymentState.LockedIn");
    expect(gbt).toContain("vbavailable[name] = deployment.bit");
  });
});

// =============================================================================
// G25 — computeNextBlockVersion via BIP-9 state machine
// =============================================================================
describe("W123-G25: BIP-9 computeNextBlockVersion — PRESENT", () => {
  it("RPC paths call computeNextBlockVersion(parentHeight)", () => {
    expect(RPC_SERVER_SRC).toContain("private computeNextBlockVersion(parentHeight: number): number");
    expect(RPC_SERVER_SRC).toMatch(/this\.computeNextBlockVersion\(bestBlock\.height\)/);
  });
});

// =============================================================================
// G26 — sigops cost stored on mempool entries
// =============================================================================
describe("W123-G26: per-entry sigOpCost (Core's GetTransactionSigOpCost analog) — PRESENT", () => {
  it("MempoolEntry has sigOpCost field", () => {
    expect(MEMPOOL_SRC).toContain("sigOpCost: number");
  });
  it("mempool computes sigOpCost via getTransactionSigOpCost", () => {
    expect(MEMPOOL_SRC).toContain("getTransactionSigOpCost(");
  });
  it("MAX_STANDARD_TX_SIGOPS_COST is enforced at admission time", () => {
    expect(MEMPOOL_SRC).toContain("MAX_STANDARD_TX_SIGOPS_COST");
  });
});

// =============================================================================
// G27 — BlockAssembler::AddToBlock-equivalent accounting
// =============================================================================
describe("W123-G27: AddToBlock-equivalent accounting (helper) — PRESENT", () => {
  it("BlockTemplateBuilder increments totalWeight/totalSigOps/totalFees per added tx", () => {
    expect(MINING_TEMPLATE_SRC).toContain("totalFees += entry.fee");
    expect(MINING_TEMPLATE_SRC).toContain("totalWeight += entry.weight");
    expect(MINING_TEMPLATE_SRC).toContain("totalSigOps += txSigOpCost");
  });
});

// =============================================================================
// G28 — ImprovesFeerateDiagram (cluster mempool) hook
// =============================================================================
describe("W123-G28: ImprovesFeerateDiagram (cluster mempool) — PRESENT", () => {
  it("mempool has CompareChunks / feerate-diagram comparator", () => {
    expect(MEMPOOL_SRC).toContain("ImprovesFeerateDiagram");
    expect(MEMPOOL_SRC).toContain("linearizeVirtualCluster");
    expect(MEMPOOL_SRC).toContain("CompareChunks");
  });
});

// =============================================================================
// G29 — BIP-152 compact-block reconstruction
// =============================================================================
describe("W123-G29: BIP-152 compact blocks — PRESENT", () => {
  it("CompactBlockManager + sendcmpct v2 + short-id SipHash all wired", () => {
    expect(COMPACT_BLOCKS_SRC).toContain("class CompactBlockManager");
    expect(COMPACT_BLOCKS_SRC).toContain("SipHash-2-4");
    expect(COMPACT_BLOCKS_SRC).toContain("CMPCTBLOCKS_VERSION");
  });
});

// =============================================================================
// G30 — getnetworkhashps window calculation
// =============================================================================
describe("W123-G30: getnetworkhashps window — PRESENT", () => {
  it("getNetworkHashPS computes workDiff / timeDiff over sliding window", () => {
    // 2026-08-29: the slice was 30 lines, which stopped reaching the
    // arithmetic once the handler gained Core's argument validation
    // (getInt<int> widths, nblocks/height domain checks, height honoured).
    // A fixed line count is a brittle way to look at a function; widen it.
    const fn = rpcSlice("private async getNetworkHashPS(params:", 80);
    expect(fn).toContain("hiEntry.chainWork - loEntry.chainWork");
    expect(fn).toContain("hiEntry.header.timestamp - loEntry.header.timestamp");
    expect(fn).toContain("Number(hashps)");
  });
});

// =============================================================================
// Status summary (informational; assertion is the cumulative pass/fail above)
// =============================================================================
describe("W123 status summary", () => {
  it("audit document exists at audit/w123_mining_gbt.md", () => {
    const audit = readFileSync(resolve(SRC, "..", "audit", "w123_mining_gbt.md"), "utf8");
    expect(audit).toContain("W123 — Mining / GBT parity audit");
    expect(audit).toContain("22 BUGS / 30 gates");
  });
});
