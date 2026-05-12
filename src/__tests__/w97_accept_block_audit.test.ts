/**
 * W97 — AcceptBlockHeader + AcceptBlock + ProcessNewBlockHeaders audit
 *
 * Discovery-wave audit of hotbuns' equivalents of Bitcoin Core's
 *
 *   - AcceptBlockHeader        (validation.cpp:4186-4239)
 *   - ProcessNewBlockHeaders   (validation.cpp:4242-4270)
 *   - AcceptBlock              (validation.cpp:4298-4396)
 *   - CheckBlock               (validation.cpp:3918)
 *
 * Hotbuns maps these onto:
 *
 *   - HeaderSync.validateHeader / processHeaders   — src/sync/headers.ts
 *   - BlockSync.connectBlock                       — src/sync/blocks.ts
 *   - validateBlock                                — src/validation/block.ts
 *
 * Most tests are static (source-text inspection or signature inspection) so
 * they pin down divergences without needing to mine PoW.  The few end-to-end
 * tests stub the PoW path by injecting headers via a controlled flow.
 *
 * No fixes are applied in this wave — this is the gate-by-gate spec only.
 *
 * Reference:
 *   bitcoin-core/src/validation.cpp:3918, 4080-4121, 4186-4396
 *   bitcoin-core/src/consensus/validation.h (BLOCK_FAILED_VALID, BLOCK_HAVE_DATA, BlockValidationResult)
 */

import { describe, test, expect } from "bun:test";
import * as fs from "node:fs";
import * as path from "node:path";

import { BlockStatus } from "../storage/database.js";
import { REGTEST } from "../consensus/params.js";
import { HeaderSync } from "../sync/headers.js";
import {
  validateBlock,
  type Block,
  type BlockHeader,
  computeMerkleRoot,
  getBlockHash,
} from "../validation/block.js";
import { getTxId, type Transaction } from "../validation/tx.js";

// ─── Helpers ─────────────────────────────────────────────────────────────────

function makeCoinbase(height: number, value: bigint): Transaction {
  return {
    version: 1,
    inputs: [
      {
        prevOut: { txid: Buffer.alloc(32, 0), vout: 0xffffffff },
        scriptSig: Buffer.concat([Buffer.from([0x03]), Buffer.alloc(3, height)]),
        sequence: 0xffffffff,
        witness: [],
      },
    ],
    outputs: [
      {
        value,
        scriptPubKey: Buffer.from([
          0x76, 0xa9, 0x14, ...Array(20).fill(0x01), 0x88, 0xac,
        ]),
      },
    ],
    lockTime: 0,
  };
}

function makeBlock(
  prevBlock: Buffer,
  txs: Transaction[],
  opts: Partial<BlockHeader> = {}
): Block {
  const txids = txs.map(getTxId);
  const merkle = computeMerkleRoot(txids);
  return {
    header: {
      version: opts.version ?? 0x20000000,
      prevBlock,
      merkleRoot: merkle,
      timestamp: opts.timestamp ?? Math.floor(Date.now() / 1000),
      bits: opts.bits ?? REGTEST.powLimitBits,
      nonce: opts.nonce ?? 0,
    },
    transactions: txs,
  };
}

const BLOCKS_SRC = fs.readFileSync(
  path.join(__dirname, "..", "sync", "blocks.ts"),
  "utf8"
);

const HEADERS_SRC = fs.readFileSync(
  path.join(__dirname, "..", "sync", "headers.ts"),
  "utf8"
);

// ─── G1-G16: HeaderSync / ProcessNewBlockHeaders gates ───────────────────────

describe("W97 AcceptBlockHeader — duplicate, prev-blk, contextual gates", () => {
  // ── G1: duplicate-hash short-circuit ──
  // Encoded as static check: processHeaders short-circuits on
  // `headerChain.has(hashHex)` with a plain `continue` (no separate
  // "already known" return-true path).
  test("G1 — processHeaders short-circuits on already-known hash via continue", () => {
    // Find the relevant block in processHeaders().
    const idx = HEADERS_SRC.indexOf("async processHeaders(");
    expect(idx).toBeGreaterThan(-1);
    const slice = HEADERS_SRC.slice(idx, idx + 4000);
    // The short-circuit pattern:
    expect(slice).toContain("if (this.headerChain.has(hashHex)) {");
    expect(slice).toContain("continue;");
  });

  // ── G3: BLOCK_FAILED_VALID → duplicate-invalid / BLOCK_CACHED_INVALID ──
  test("G3 — there is no in-memory cache of previously-failed header hashes", () => {
    // BUG B02: hotbuns has no equivalent of pindex->nStatus & BLOCK_FAILED_VALID
    // at the AcceptBlockHeader level.  The `status: "invalid"` field on
    // HeaderChainEntry is set ONLY by loadFromDB (line 1045).
    //
    // Confirm absence: validateHeader returns `{valid: false, error}` but the
    // caller (processHeaders) only logs + continues — it never stores the
    // failure.
    const idx = HEADERS_SRC.indexOf("async processHeaders(");
    const slice = HEADERS_SRC.slice(idx, idx + 4000);
    // Pre-validation `headerChain.has` check is present (handles previously-
    // ACCEPTED duplicates).  But there is no second branch for
    // previously-REJECTED hashes.
    expect(slice).not.toContain("invalidHeaders");
    expect(slice).not.toContain("rejectedHeaders");
    expect(slice).not.toContain("duplicate-invalid");
  });

  // ── G5: orphan handling has no canonical "prev-blk-not-found" path ──
  test("G5 — orphan-header path logs warn + continues silently (no canonical reject token)", () => {
    const idx = HEADERS_SRC.indexOf("async processHeaders(");
    const slice = HEADERS_SRC.slice(idx, idx + 4000);
    // Orphan handling block:
    expect(slice).toContain("Orphan header received:");
    // Core's canonical token:
    expect(slice).not.toContain("prev-blk-not-found");
    // No peer.misbehaving for orphan flood:
    expect(slice).not.toContain(".misbehaving(");
  });

  // ── G6: parent BLOCK_FAILED_VALID → bad-prevblk ──
  test("G6 — child of an invalidated parent is NOT rejected (no parent.status check)", () => {
    const idx = HEADERS_SRC.indexOf("async processHeaders(");
    const slice = HEADERS_SRC.slice(idx, idx + 4000);
    // BUG B04: processHeaders fetches `parent = this.headerChain.get(...)` but
    // never checks `parent.status === "invalid"` before adding the child.
    // Confirm: no parent.status check appears in the slice.
    expect(slice).not.toMatch(/parent\.status\s*===\s*"invalid"/);
    expect(slice).not.toContain("bad-prevblk");
    expect(slice).not.toContain("BLOCK_INVALID_PREV");
  });

  // ── G4 + G7: CheckBlockHeader + ContextualCheckBlockHeader are inlined ──
  test("G4/G7 — CheckBlockHeader and ContextualCheckBlockHeader are fused into validateHeader", () => {
    // Hotbuns has one combined validateHeader; Core separates pure-PoW
    // CheckBlockHeader from ContextualCheckBlockHeader.
    // BUG B29: tests that probe pure-PoW correctness in isolation have to
    // call validateBlockHeader (a different function in validation/block.ts).
    expect(HEADERS_SRC).toContain("validateHeader(");
    expect(HEADERS_SRC).not.toContain("CheckBlockHeader(");
    // The validation/block.ts function is the closest analogue:
    const valSrc = fs.readFileSync(
      path.join(__dirname, "..", "validation", "block.ts"),
      "utf8"
    );
    expect(valSrc).toContain("export function validateBlockHeader(");
  });

  // ── G8: min_pow_checked / too-little-chainwork at AcceptBlockHeader level ──
  test("G8 — processHeaders has no min_pow_checked parameter (anti-DoS gate is orthogonal)", () => {
    // BUG B05: hotbuns separates anti-DoS into PRESYNC/REDOWNLOAD
    // (HeadersSyncState) rather than threading min_pow_checked through the
    // accept-header call.  The direct path (used by submitblock-injected
    // headers at blocks.ts:749) has NO low-chainwork rejection.
    const sig = (HeaderSync.prototype as any).processHeaders;
    expect(typeof sig).toBe("function");
    // Signature has ≤2 params (headers, fromPeer).
    expect(sig.length).toBeLessThanOrEqual(2);
    // Core has a 3rd param `min_pow_checked`.
    // Spec target: flip this assertion to >= 3 once B05 is closed.
  });

  // ── G13: early return on first failed header in batch ──
  test("G13 — processHeaders 'continues' on validateHeader failure instead of returning", () => {
    const idx = HEADERS_SRC.indexOf("async processHeaders(");
    const slice = HEADERS_SRC.slice(idx, idx + 4000);
    // BUG B07: Core's ProcessNewBlockHeaders does `if (!accepted) return false;`
    // (validation.cpp:4259-4261).  Hotbuns continues on each failure.
    //
    // We confirm by locating the `if (!validation.valid) {` block and
    // verifying the next "control-flow keyword" we encounter is `continue;`
    // and not `return` or `break`.
    const vIdx = slice.indexOf("if (!validation.valid) {");
    expect(vIdx).toBeGreaterThan(-1);
    const block = slice.slice(vIdx, vIdx + 400);
    expect(block).toContain("continue;");
    expect(block).not.toContain("return false;");
    expect(block).not.toContain("return state");
    // Also confirm Core's strings are absent (no canonical reject token):
    expect(block).not.toContain("MarkBlockAsInvalid");
  });

  // ── G16: IBD progress log uses PowTargetSpacing ──
  test("G16 — processHeaders has no IBD-progress log derived from targetSpacing", () => {
    // BUG B09: hotbuns has no equivalent of Core's
    //   LogInfo("Synchronizing blockheaders, height: %d (~%.2f%%)\n", ...)
    // using PowTargetSpacing() to estimate blocks-left.
    const idx = HEADERS_SRC.indexOf("async processHeaders(");
    const slice = HEADERS_SRC.slice(idx, idx + 4000);
    expect(slice).not.toContain("targetSpacing");
    expect(slice).not.toContain("blocks_left");
    expect(slice).not.toContain("Synchronizing blockheaders");
  });

  // ── G15: NotifyHeaderTip fires INSIDE async function (no cs_main analog) ──
  test("G15 — headersProcessedCallbacks fire inside the same async pass, after the loop", () => {
    const idx = HEADERS_SRC.indexOf("async processHeaders(");
    const slice = HEADERS_SRC.slice(idx, idx + 4000);
    // Confirm callbacks are invoked after the for-loop completes (Core
    // invokes NotifyHeaderTip OUTSIDE cs_main):
    expect(slice).toContain("for (const cb of this.headersProcessedCallbacks)");
    // Hotbuns has no lock; the placement is correct in spirit.  We document
    // the re-entrancy footgun (callback may mutate header state).
    // BUG B08 is structural and re-entrant — flagged for follow-up.
  });

  // ── G11+G12: CheckBlockIndex invariant after each AcceptBlockHeader ──
  test("G11/G12 — no per-header CheckBlockIndex / invariant check inside the loop", () => {
    // BUG B06: Core invokes CheckBlockIndex() after every AcceptBlockHeader
    // (validation.cpp:4253).  Hotbuns has none.
    expect(HEADERS_SRC).not.toContain("CheckBlockIndex");
    expect(HEADERS_SRC).not.toContain("checkBlockIndex");
  });
});

// ─── G17-G30: AcceptBlock / connectBlock gates ───────────────────────────────

describe("W97 AcceptBlock — fAlreadyHave, fTooFarAhead, MinimumChainWork, CheckBlock, fNewBlock", () => {
  // ── G19c: MIN_BLOCKS_TO_KEEP = 288 fTooFarAhead cap ──
  test("G19c — Core constant MIN_BLOCKS_TO_KEEP (288) is not referenced in sync/blocks.ts", () => {
    // BUG B14: hotbuns gates on MAX_DOWNLOADED_BUFFER (200) for the inject
    // path only — there is no peer-driven equivalent of the +288 cap on
    // pindex->nHeight > ActiveHeight() + MIN_BLOCKS_TO_KEEP.
    const has288 = /\b288\b/.test(BLOCKS_SRC);
    expect(has288).toBe(false); // marker: gate is structurally absent.
  });

  // ── G19b: !fHasMoreOrSameWork early-return on unrequested ──
  test("G19b — connectBlock has no fHasMoreOrSameWork early-return", () => {
    // Core: bool fHasMoreOrSameWork = ActiveTip() ?
    //         pindex->nChainWork >= ActiveTip()->nChainWork : true;
    //       if (!fRequested) { if (!fHasMoreOrSameWork) return true; }
    // BUG B13: connectBlock has no such gate.
    const idx = BLOCKS_SRC.indexOf("async connectBlock(");
    const slice = BLOCKS_SRC.slice(idx, idx + 8000);
    expect(slice).not.toContain("fHasMoreOrSameWork");
    expect(slice).not.toMatch(/chainWork\s*>=\s*\w+chainWork/i);
  });

  // ── G19d: nChainWork < MinimumChainWork early-return on unrequested ──
  test("G19d — connectBlock has no MinimumChainWork early-return (low-work block DoS gate)", () => {
    // BUG B15: minimumChainWork is referenced only inside the AssumeValidContext
    // for skip-script eligibility — NOT as an accept-block gate.
    const idx = BLOCKS_SRC.indexOf("async connectBlock(");
    const slice = BLOCKS_SRC.slice(idx, idx + 8000);
    // The string `minimumChainWork` may appear inside the avCtx; assert it
    // is NOT in an early-return position.
    expect(slice).not.toMatch(
      /if[^{}]+chainWork\s*<\s*[^{}]*MinimumChainWork[^{}]+return/i
    );
  });

  // ── G18: fAlreadyHave bit-mask is HAVE_DATA, not TXS_VALID ──
  test("G18 — handleInv 'already have' check uses TXS_VALID (4), not HAVE_DATA (8)", () => {
    // BUG B11: line ~870 reads `(existing.status & 4) !== 0` — TXS_VALID.
    // Core uses BLOCK_HAVE_DATA (= 8).
    expect(BLOCKS_SRC).toContain("(existing.status & 4) !== 0");
    // Spec target: flip to `& 8`.
    // Confirm BlockStatus values for clarity:
    expect(BlockStatus.TXS_VALID).toBe(4);
    expect(BlockStatus.HAVE_DATA).toBe(8);
  });

  // ── G19a: nTx != 0 early-return (pruned block) ──
  test("G19a — connectBlock has no nTx != 0 / pruned early-return", () => {
    // BUG B12: Core's `if (pindex->nTx != 0) return true;` (validation.cpp:4337)
    // is absent.  Hotbuns would re-validate a pruned block from scratch.
    const idx = BLOCKS_SRC.indexOf("async connectBlock(");
    const slice = BLOCKS_SRC.slice(idx, idx + 8000);
    expect(slice).not.toMatch(/pindex\.nTx\s*!=?\s*0/);
    expect(slice).not.toMatch(/nTx\s*!==?\s*0[^{}]+return/);
  });

  // ── G20: validateBlock (structural CheckBlock) must run unconditionally ──
  test("G20 — validateBlock is NOT gated on !assumeValid (structural checks always run)", () => {
    // FIX B16: Core's assumevalid skips ONLY per-input script verification.
    // Structural checks — merkle root, witness commitment, BIP-34, block weight,
    // tx-structure — must run even inside the assumevalid range.
    // Reference: Bitcoin Core validation.cpp::CheckBlock (line 3918+) always
    // runs; only ConnectBlock's fScriptChecks is gated on !fAssumeValid.
    const idx = BLOCKS_SRC.indexOf("async connectBlock(");
    const slice = BLOCKS_SRC.slice(idx, idx + 8000);
    // The old buggy gate must be absent.
    expect(slice).not.toMatch(/if \(!assumeValid\) {[^}]*validation = validateBlock\(/s);
    // validateBlock must be called unconditionally (before the assumeValid variable).
    const validateCallIdx = slice.indexOf("validateBlock(block, height");
    const assumeVarIdx = slice.indexOf("const assumeValid =");
    expect(validateCallIdx).toBeGreaterThan(-1);
    expect(assumeVarIdx).toBeGreaterThan(-1);
    expect(validateCallIdx).toBeLessThan(assumeVarIdx);
  });

  // ── G21: ContextualCheckBlock invocation independent of validateBlock ──
  test("G21 — there is no separate ContextualCheckBlock invocation outside validateBlock", () => {
    // BUG B17: ContextualCheckBlock-equivalent checks (block-level MTP gates,
    // BIP-34 height, weight) are folded into validateBlock.  Under assumevalid
    // they're skipped along with the structural checks (see G20).
    const idx = BLOCKS_SRC.indexOf("async connectBlock(");
    const slice = BLOCKS_SRC.slice(idx, idx + 8000);
    expect(slice).not.toContain("ContextualCheckBlock");
    expect(slice).not.toContain("contextualCheckBlock");
  });

  // ── G22: InvalidBlockFound persists BLOCK_FAILED_VALID ──
  test("G22 — connectBlock failure does NOT persist BLOCK_FAILED_VALID", () => {
    // BUG B18: Core's InvalidBlockFound sets pindex->nStatus |= BLOCK_FAILED_VALID
    // (validation.cpp:1999-2012).  Hotbuns logs + returns false only.
    const idx = BLOCKS_SRC.indexOf("async connectBlock(");
    const slice = BLOCKS_SRC.slice(idx, idx + 8000);
    expect(slice).not.toContain("FAILED_VALID");
    expect(slice).not.toContain("BlockStatus.FAILED_VALID");
  });

  // ── G23: NewPoWValidBlock relay gated on !IBD && ActiveTip == pprev ──
  test("G23 — relay (broadcast inv) is gated on atTip, not on the Core condition", () => {
    // BUG B19: Core's NewPoWValidBlock signal fires when:
    //   !IsInitialBlockDownload() && ActiveTip() == pindex->pprev
    // Hotbuns gates on `atTip && this.peerManager` where atTip uses the
    // HEADER chain tip, not the ACTIVE chain tip.
    expect(BLOCKS_SRC).toContain("atTip && this.peerManager");
    expect(BLOCKS_SRC).not.toContain("NewPoWValidBlock");
    expect(BLOCKS_SRC).not.toContain("isInitialBlockDownload(");
  });

  // ── G24+G25: WriteBlock + HAVE_DATA bit deep-IBD divergence ──
  test("G24/G25 — body persistence (putBlock) and HAVE_DATA bit are gated on atTip", () => {
    // BUG B20: db.putBlock is gated on `if (atTip) { ... }` — deep-IBD
    // blocks have NO body persisted.
    // BUG B21: status bit 8 (HAVE_DATA) is conditional on atTip:
    //   status: 1 | 2 | 4 | (atTip ? 8 : 0) | haveUndo
    expect(BLOCKS_SRC).toContain("(atTip ? 8 : 0)");
  });

  // ── G26: FlushStateToDisk(NONE) unconditional ──
  test("G26 — flushDirty is gated on shouldFlush, not unconditional", () => {
    // BUG B22: Core calls FlushStateToDisk after every accepted block
    // (validation.cpp:4393).  Hotbuns gates on
    // `shouldFlush = atTip || height % FLUSH_INTERVAL === 0` (documented
    // perf optimization, flagged for parity).
    expect(BLOCKS_SRC).toContain("const shouldFlush = atTip");
    expect(BLOCKS_SRC).toContain("FLUSH_INTERVAL");
  });

  // ── G27: CheckBlockIndex post-condition ──
  test("G27 — no CheckBlockIndex post-condition after connectBlock", () => {
    // BUG B23: Core's CheckBlockIndex() runs after every AcceptBlock
    // (validation.cpp:4395).  Hotbuns has none.
    expect(BLOCKS_SRC).not.toContain("CheckBlockIndex");
    expect(BLOCKS_SRC).not.toContain("checkBlockIndex");
  });

  // ── G28: fNewBlock output parameter ──
  test("G28 — connectBlock returns boolean only; no fNewBlock output", () => {
    // BUG B24: Core's AcceptBlock writes through *fNewBlock = true/false.
    // Hotbuns connectBlock returns a bare boolean.
    expect(BLOCKS_SRC).toContain(
      "async connectBlock(block: Block, height: number): Promise<boolean>"
    );
    expect(BLOCKS_SRC).not.toContain("fNewBlock");
  });

  // ── G29: try/catch around disk writes ──
  test("G29 — db.putBlock + flushDirty are not individually wrapped in try/catch", () => {
    // BUG B25: a runtime ENOSPC / EIO error propagates as an unhandled
    // rejection.  Core wraps WriteBlock in try/catch and calls FatalError.
    const idx = BLOCKS_SRC.indexOf("async connectBlock(");
    const slice = BLOCKS_SRC.slice(idx, idx + 40000);
    // Locate the connectBlock-internal putBlock (skip the first one inside
    // injectBlock, which appears earlier in the file).
    const putIdx = slice.indexOf("await this.db.putBlock(blockHash, rawBlock)");
    expect(putIdx).toBeGreaterThan(-1);
    // Walk backward looking for a `try {` in close proximity — Core wraps
    // the WriteBlock + ReceivedBlockTransactions call in a `try { } catch`.
    const window = slice.slice(Math.max(0, putIdx - 200), putIdx);
    expect(window).not.toContain("try {");
  });

  // ── G30: HAVE_DATA bit-set ordering vs. ReceivedBlockTransactions ──
  test("G30 — db.putBlock fires BEFORE the chain-state batch that sets HAVE_DATA", () => {
    // BUG B26: hotbuns writes the body via db.putBlock BEFORE the batched
    // flush that sets HAVE_DATA in the block-index record.  A crash window
    // between the body write and the chain-state batch leaves an orphan
    // body on disk with no chain-state pointer; there is no restart-scan
    // path that rebuilds block-index entries from blk*.dat.
    const idx = BLOCKS_SRC.indexOf("async connectBlock(");
    const slice = BLOCKS_SRC.slice(idx, idx + 40000);
    const putIdx = slice.indexOf("await this.db.putBlock(blockHash, rawBlock)");
    const flushIdx = slice.indexOf("await this.utxoManager.flushDirty(");
    expect(putIdx).toBeGreaterThan(-1);
    expect(flushIdx).toBeGreaterThan(-1);
    expect(putIdx).toBeLessThan(flushIdx);
  });

  // ── G2: Genesis-block bypass of CheckBlockHeader + prev lookup ──
  test("G2 — genesis is initialized with non-zero chainWork via getHeaderWork(genesisBits)", () => {
    // initGenesis does NOT run validateHeader (no prev to validate against).
    // It seeds chainWork from the genesis bits — Core's CBlockIndex::nChainWork
    // for genesis is GetBlockProof(genesis), same shape.
    expect(HEADERS_SRC).toContain("initGenesis()");
    expect(HEADERS_SRC).toContain("this.getHeaderWork(genesisHeader.bits)");
  });

  // ── G17: AcceptBlockHeader inner call inside AcceptBlock ──
  test("G17 — connectBlock relies on prior processHeaders, no in-line AcceptBlockHeader equivalent", () => {
    // BUG B10: Core's AcceptBlock calls AcceptBlockHeader internally before
    // structural checks (validation.cpp:4307-4311).  Hotbuns expects the
    // header to already be in the in-memory chain (it asserts equality at
    // 2329 against headerSync.getHeaderByHeight(height)) — if a peer sends
    // a block whose header was never processed (e.g. via cmpctblock direct
    // injection), the assertion fires but no contextual re-check happens.
    const idx = BLOCKS_SRC.indexOf("async connectBlock(");
    const slice = BLOCKS_SRC.slice(idx, idx + 8000);
    expect(slice).toMatch(/headerSync\.getHeaderByHeight\(height\)/);
    expect(slice).not.toContain("acceptBlockHeader(");
  });
});

// ─── Sanity: validateBlock-direct gates (CheckBlock side) ────────────────────

describe("W97 CheckBlock — validateBlock direct exercises", () => {
  test("validateBlock rejects empty blocks (Core CheckBlock 3922)", () => {
    const empty: Block = {
      header: {
        version: 1,
        prevBlock: Buffer.alloc(32, 0),
        merkleRoot: Buffer.alloc(32, 0),
        timestamp: Math.floor(Date.now() / 1000),
        bits: REGTEST.powLimitBits,
        nonce: 0,
      },
      transactions: [],
    };
    const r = validateBlock(empty, 1, REGTEST);
    expect(r.valid).toBe(false);
    expect(r.error).toContain("transactions");
  });

  test("validateBlock rejects blocks where first tx is not coinbase", () => {
    const nonCoinbase: Transaction = {
      version: 1,
      inputs: [
        {
          prevOut: { txid: Buffer.alloc(32, 0x11), vout: 0 },
          scriptSig: Buffer.alloc(0),
          sequence: 0xffffffff,
          witness: [],
        },
      ],
      outputs: [{ value: 50n, scriptPubKey: Buffer.from([0x51]) }],
      lockTime: 0,
    };
    const block = makeBlock(Buffer.alloc(32, 0), [nonCoinbase]);
    const r = validateBlock(block, 1, REGTEST);
    expect(r.valid).toBe(false);
    expect(r.error).toContain("coinbase");
  });

  test("validateBlock rejects merkle root mismatch", () => {
    const block = makeBlock(Buffer.alloc(32, 0), [makeCoinbase(1, 50n)]);
    block.header.merkleRoot = Buffer.alloc(32, 0xee); // wrong
    const r = validateBlock(block, 1, REGTEST);
    expect(r.valid).toBe(false);
    expect(r.error).toContain("Merkle");
  });

  test("validateBlock rejects a block whose coinbase scriptSig is too short (<2 bytes)", () => {
    const cb: Transaction = {
      version: 1,
      inputs: [
        {
          prevOut: { txid: Buffer.alloc(32, 0), vout: 0xffffffff },
          scriptSig: Buffer.from([0x01]), // 1 byte (too short)
          sequence: 0xffffffff,
          witness: [],
        },
      ],
      outputs: [
        {
          value: 50n * 100_000_000n,
          scriptPubKey: Buffer.from([0x51]),
        },
      ],
      lockTime: 0,
    };
    const block = makeBlock(Buffer.alloc(32, 0), [cb]);
    const r = validateBlock(block, 1, REGTEST);
    expect(r.valid).toBe(false);
    expect(r.error).toContain("bad-cb-length");
  });
});
