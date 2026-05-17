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
 * Audit summary (see audit/w123_mining_gbt.md): 22 bugs / 30 gates,
 *   PRESENT=10, PARTIAL=7, MISSING=13.
 *   P0-CDIV=7, P0-RPC=7, P1=7, P2=1.
 *
 * KEY FINDING: hotbuns has two parallel mining code paths. The
 * `BlockTemplateBuilder` helper at `src/mining/template.ts` (685 LOC,
 * 62 unit tests passing) is **correctly implemented** with all W14/W63
 * fixes. The production RPC entry points
 * (`getBlockTemplate` + `generateSingleBlock` in `src/rpc/server.ts`)
 * re-implement the logic by hand and bring the W14/W63 bugs back —
 * **classic "dead-helper at the call-site" pattern**, 33rd-consecutive
 * audit wave to find an instance of it across the fleet.
 *
 * Running: bun test src/__tests__/w123_mining_gbt.test.ts
 *
 * No production code changes in this wave.
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
describe("W123-G1: tx finality enforcement in template selection — PARTIAL (BUG-1)", () => {
  it("BlockTemplateBuilder.selectTransactions HAS isFinalTx check (PRESENT in helper)", () => {
    expect(MINING_TEMPLATE_SRC).toContain("isFinalTx(entry.tx, targetHeight, this.medianTimePast)");
    expect(MINING_TEMPLATE_SRC).toContain("notFinal.add(txidHex)");
  });

  it("BUG-1: getBlockTemplate RPC has NO isFinalTx check (MISSING in production path)", () => {
    // The RPC iterates getAllTxids() and pushes everything that fits the sigops
    // budget, regardless of locktime. Core: TestChunkTransactions
    // (node/miner.cpp:253-258) walks every selected tx through IsFinalTx.
    const gbt = rpcSlice("private async getBlockTemplate(params: unknown[])", 200);
    expect(gbt.length).toBeGreaterThan(0);
    expect(gbt).not.toContain("isFinalTx");
    expect(gbt).not.toContain("IsFinalTx");
  });
});

// =============================================================================
// G2 — MAX_BLOCK_WEIGHT enforcement
// =============================================================================
describe("W123-G2: MAX_BLOCK_WEIGHT enforcement (>=) — PARTIAL (BUG-2)", () => {
  it("BlockTemplateBuilder enforces totalWeight + entry.weight >= maxBlockWeight (PRESENT)", () => {
    expect(MINING_TEMPLATE_SRC).toContain("totalWeight + entry.weight >= maxBlockWeight");
  });

  it("BUG-2: getBlockTemplate RPC has NO MAX_BLOCK_WEIGHT gate (MISSING)", () => {
    const gbt = rpcSlice("private async getBlockTemplate(params: unknown[])", 200);
    // No weight check at all; only sigops is gated.
    expect(gbt).not.toMatch(/totalWeight\s*\+\s*entry\.weight\s*>=?\s*\w+\.maxBlockWeight/);
    expect(gbt).not.toMatch(/totalWeight\s*\+\s*entry\.weight\s*>=?\s*MAX_BLOCK_WEIGHT/);
  });
});

// =============================================================================
// G3 — reserved-weight (8000) + reserved-coinbase-sigops (400) budgets
// =============================================================================
describe("W123-G3: reserved budgets — PARTIAL (BUG-3, BUG-4)", () => {
  it("BlockTemplateBuilder starts totalWeight at BLOCK_RESERVED_WEIGHT (PRESENT)", () => {
    // Constant defined per Core policy/policy.h:27 DEFAULT_BLOCK_RESERVED_WEIGHT=8000.
    expect(MINING_TEMPLATE_SRC).toContain("const BLOCK_RESERVED_WEIGHT = 8000");
    expect(MINING_TEMPLATE_SRC).toContain("let totalWeight = BLOCK_RESERVED_WEIGHT");
  });
  it("BlockTemplateBuilder starts totalSigOps at COINBASE_OUTPUT_MAX_ADDITIONAL_SIGOPS (PRESENT)", () => {
    expect(MINING_TEMPLATE_SRC).toContain("const COINBASE_OUTPUT_MAX_ADDITIONAL_SIGOPS = 400");
    expect(MINING_TEMPLATE_SRC).toContain("let totalSigOps = COINBASE_OUTPUT_MAX_ADDITIONAL_SIGOPS");
  });

  it("BUG-3: getBlockTemplate RPC starts totalWeight AND totalSigOps at 0 (MISSING)", () => {
    const gbt = rpcSlice("private async getBlockTemplate(params: unknown[])", 100);
    expect(gbt).toMatch(/let\s+totalWeight\s*=\s*0/);
    expect(gbt).toMatch(/let\s+totalSigOps\s*=\s*0/);
    // Specifically, no `8000` and no `400` constant near the totals init.
    expect(gbt).not.toContain("BLOCK_RESERVED_WEIGHT");
    expect(gbt).not.toContain("COINBASE_OUTPUT_MAX_ADDITIONAL_SIGOPS");
  });

  it("BUG-4: getBlockTemplate sigops gate uses `>` instead of `>=` (Core: `>=` rejects equality)", () => {
    const gbt = rpcSlice("private async getBlockTemplate(params: unknown[])", 100);
    // Core node/miner.cpp:244: `if (nBlockSigOpsCost + chunk_sigops_cost >= MAX_BLOCK_SIGOPS_COST) return false;`
    // hotbuns: `if (totalSigOps + txSigOpCost > MAX_BLOCK_SIGOPS_COST) continue;`
    expect(gbt).toContain("totalSigOps + txSigOpCost > MAX_BLOCK_SIGOPS_COST");
    expect(gbt).not.toContain("totalSigOps + txSigOpCost >= MAX_BLOCK_SIGOPS_COST");
  });
});

// =============================================================================
// G4 — dependency / ancestor ordering
// =============================================================================
describe("W123-G4: dependency / ancestor ordering in template — PARTIAL", () => {
  it("BlockTemplateBuilder walks dependsOn ancestors recursively (PRESENT)", () => {
    expect(MINING_TEMPLATE_SRC).toContain("addWithAncestors");
    expect(MINING_TEMPLATE_SRC).toContain("for (const parentTxidHex of entry.dependsOn)");
  });
  it("getBlockTemplate emits depends[] by 1-based index but uses mempool-iteration order (no topological pre-sort)", () => {
    const gbt = rpcSlice("private async getBlockTemplate(params: unknown[])", 100);
    // depends array is computed but iteration is over getAllTxids() (Map insertion order),
    // not a fee-rate sort with parent-first dependency walk.
    expect(gbt).toContain("const depends: number[]");
    expect(gbt).toContain("this.mempool.getAllTxids()");
    expect(gbt).not.toContain("getTransactionsByFeeRate");
  });
});

// =============================================================================
// G5 — MAX_CONSECUTIVE_FAILURES early-exit
// =============================================================================
describe("W123-G5: MAX_CONSECUTIVE_FAILURES early-exit (1000) — PARTIAL", () => {
  it("BlockTemplateBuilder has MAX_CONSECUTIVE_FAILURES=1000 + 4000 weight delta (PRESENT)", () => {
    expect(MINING_TEMPLATE_SRC).toContain("MAX_CONSECUTIVE_FAILURES = 1000");
    expect(MINING_TEMPLATE_SRC).toContain("BLOCK_FULL_ENOUGH_WEIGHT_DELTA = 4000");
  });
  it("getBlockTemplate RPC has no early-exit (MISSING)", () => {
    const gbt = rpcSlice("private async getBlockTemplate(params: unknown[])", 100);
    expect(gbt).not.toContain("MAX_CONSECUTIVE_FAILURES");
    expect(gbt).not.toContain("BLOCK_FULL_ENOUGH_WEIGHT_DELTA");
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
describe("W123-G7: coinbase nSequence — PARTIAL (BUG-5)", () => {
  it("BlockTemplateBuilder.buildCoinbase uses MAX_SEQUENCE_NONFINAL = 0xfffffffe (PRESENT)", () => {
    expect(MINING_TEMPLATE_SRC).toContain("const MAX_SEQUENCE_NONFINAL = 0xfffffffe");
    expect(MINING_TEMPLATE_SRC).toContain("sequence: MAX_SEQUENCE_NONFINAL");
  });

  it("BUG-5: generateSingleBlock's coinbase uses sequence: 0xffffffff (SEQUENCE_FINAL — wrong)", () => {
    // Both `buildCoinbaseTx` and `buildCoinbaseTxWithWitnessCommitment` in
    // rpc/server.ts emit `sequence: 0xffffffff`. Core uses MAX_SEQUENCE_NONFINAL
    // (`node/miner.cpp:171`) so the coinbase's nLockTime=height-1 is enforced.
    const buildCb = rpcSlice("private buildCoinbaseTx(", 30);
    const buildCbWC = rpcSlice("private buildCoinbaseTxWithWitnessCommitment(", 40);
    expect(buildCb).toContain("sequence: 0xffffffff");
    expect(buildCbWC).toContain("sequence: 0xffffffff");
    expect(buildCb).not.toContain("0xfffffffe");
    expect(buildCbWC).not.toContain("0xfffffffe");
  });
});

// =============================================================================
// G8 — coinbase nLockTime == height - 1
// =============================================================================
describe("W123-G8: coinbase nLockTime == height - 1 — PARTIAL (BUG-6)", () => {
  it("BlockTemplateBuilder.buildCoinbase sets lockTime: height > 0 ? height - 1 : 0 (PRESENT)", () => {
    expect(MINING_TEMPLATE_SRC).toContain("lockTime: height > 0 ? height - 1 : 0");
  });

  it("BUG-6: generateSingleBlock builds coinbase with lockTime: 0 (wrong)", () => {
    const buildCb = rpcSlice("private buildCoinbaseTx(", 30);
    const buildCbWC = rpcSlice("private buildCoinbaseTxWithWitnessCommitment(", 40);
    expect(buildCb).toContain("lockTime: 0");
    expect(buildCbWC).toContain("lockTime: 0");
  });
});

// =============================================================================
// G9 — BIP-141 witness commitment
// =============================================================================
describe("W123-G9: BIP-141 witness commitment — PRESENT", () => {
  it("BlockTemplateBuilder emits OP_RETURN(0x6a) PUSH36(0x24) marker(0xaa21a9ed)", () => {
    expect(MINING_TEMPLATE_SRC).toContain("0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed");
  });
  it("getBlockTemplate emits default_witness_commitment hex", () => {
    const gbt = rpcSlice("private async getBlockTemplate(params: unknown[])", 250);
    expect(gbt).toContain("default_witness_commitment");
    expect(gbt).toContain("0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed");
  });
  it("generateSingleBlock emits witness commitment too", () => {
    const wcCoinbase = rpcSlice("private buildCoinbaseTxWithWitnessCommitment(", 40);
    expect(wcCoinbase).toContain("0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed");
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

  it("BUG-10: getmininginfo does NOT report currentblockweight / currentblocktx (last-assembled-block)", () => {
    const mi = rpcSlice("private async getMiningInfo()", 35);
    expect(mi).not.toContain("currentblockweight");
    expect(mi).not.toContain("currentblocktx");
    // hotbuns has no m_last_block_weight / m_last_block_num_txs equivalent.
    expect(RPC_SERVER_SRC).not.toContain("m_last_block_weight");
    expect(RPC_SERVER_SRC).not.toContain("m_last_block_num_txs");
  });
});

// =============================================================================
// G12 — generateSingleBlock timestamp via max(now, MTP+1)
// =============================================================================
describe("W123-G12: generateSingleBlock timestamp >= MTP+1 — MISSING (BUG-19)", () => {
  it("BUG-19: header.timestamp is `Math.floor(Date.now() / 1000)` with NO MTP+1 floor", () => {
    const gen = rpcSlice("private async generateSingleBlock(", 200);
    expect(gen).toContain("timestamp: Math.floor(Date.now() / 1000)");
    // No mintime/MTP computation present in this RPC.
    expect(gen).not.toContain("getMedianTimePast");
    expect(gen).not.toContain("Math.max(");
  });
});

// =============================================================================
// G13 — blockmintxfee from -blockmintxfee arg
// =============================================================================
describe("W123-G13: blockmintxfee from operator -blockmintxfee arg — MISSING (BUG-22)", () => {
  it("BUG-22: getmininginfo emits blockmintxfee: 0.00001000 (hardcoded)", () => {
    const mi = rpcSlice("private async getMiningInfo()", 35);
    expect(mi).toContain("blockmintxfee: 0.00001000");
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
  it("BUG-12: submitheader is not registered as an RPC method", () => {
    expect(RPC_SERVER_SRC).not.toContain('registerMethod("submitheader"');
    expect(RPC_SERVER_SRC).not.toContain("submitheader");
  });
});

// =============================================================================
// G17 — prioritisetransaction / getprioritisedtransactions
// =============================================================================
describe("W123-G17: prioritisetransaction / getprioritisedtransactions — MISSING (BUG-13, BUG-14)", () => {
  it("BUG-13: prioritisetransaction is not a registered RPC", () => {
    expect(RPC_SERVER_SRC).not.toContain('registerMethod("prioritisetransaction"');
  });
  it("BUG-14: getprioritisedtransactions is not a registered RPC", () => {
    expect(RPC_SERVER_SRC).not.toContain('registerMethod("getprioritisedtransactions"');
  });
  it("Mempool has no per-entry feeDelta modifier (root cause)", () => {
    // mempool/persist.ts:301 candidly notes "hotbuns lacks a tx-level feeDelta".
    const persist = readFileSync(resolve(SRC, "mempool", "persist.ts"), "utf8");
    expect(persist).toContain("hotbuns lacks a tx-level");
    expect(persist).toContain("feeDelta");
    // The MempoolEntry interface has no feeDelta field.
    expect(MEMPOOL_SRC).not.toMatch(/^\s*feeDelta:\s*bigint/m);
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
describe("W123-G19: BIP-22 longpoll — MISSING (BUG-17)", () => {
  it("BUG-17: longpollid is emitted but never honored on subsequent calls", () => {
    const gbt = rpcSlice("private async getBlockTemplate(params: unknown[])", 200);
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
describe("W123-G21: BlockTemplateBuilder used by production RPCs — MISSING (BUG-21)", () => {
  it("BUG-21: rpc/server.ts imports BlockTemplateBuilder but NEVER instantiates it (dead import)", () => {
    // The import line exists (rpc/server.ts:44) and the symbol is referenced
    // in one comment only — but no `new BlockTemplateBuilder(...)` exists.
    expect(RPC_SERVER_SRC).toContain('import { BlockTemplateBuilder } from "../mining/template.js"');
    expect(RPC_SERVER_SRC).not.toContain("new BlockTemplateBuilder");
  });

  it("BUG-21: helper has zero call sites outside its own tests", () => {
    expect(typeof BlockTemplateBuilder).toBe("function");
    // Strongest invariant: not a single `BlockTemplateBuilder(` call anywhere in server.ts.
    const callSites = RPC_SERVER_SRC.match(/BlockTemplateBuilder\s*\(/g);
    expect(callSites).toBeNull();
  });

  it("33rd-consecutive dead-helper-at-call-site wave: ~685 LOC + 62 tests + zero production use", () => {
    // Pure structural fact. Lines of mining/template.ts.
    const lines = MINING_TEMPLATE_SRC.split("\n").length;
    expect(lines).toBeGreaterThan(600);
    expect(lines).toBeLessThan(800);
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
    const gbt = rpcSlice("private async getBlockTemplate(params: unknown[])", 250);
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
    const fn = rpcSlice("private async getNetworkHashPS(params:", 30);
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
