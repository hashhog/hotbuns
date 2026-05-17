/**
 * FIX-85 — BIP-157 P2P handler behavioral tests.
 *
 * Reference: bitcoin-core/src/net_processing.cpp ProcessGetCFilters /
 * ProcessGetCFHeaders / ProcessGetCFCheckPt + PrepareBlockFilterRequest
 * (lines 3262-3422).  Cross-impl FIX-74 (blockbrew) + FIX-79 (ouroboros) +
 * FIX-81 (lunarblock) + FIX-82 (rustoshi) + FIX-84 (clearbit).
 *
 * Covers:
 *   - Happy path: getcfilters / getcfheaders / getcfcheckpt produce the
 *     expected response shape.
 *   - Validation invariants: each of the five disconnect paths triggers
 *     peer.misbehaving(100) (i.e. node.fDisconnect = true parity).
 *   - Defensive return-on-miss for prev_filter_header (FIX-79 pattern).
 *   - Index-disabled / not-advertised path closes the gate.
 *
 * No real network — uses a hand-rolled MockPeer + in-memory db/filterIndex
 * stand-ins so the handler exercises every validation arm without
 * spinning up TCP listeners.
 */

import { describe, expect, it } from "bun:test";
import {
  processGetCFilters,
  processGetCFHeaders,
  processGetCFCheckPt,
  FILTER_TYPE_BASIC,
  computeFilterHeader,
} from "../p2p/cfilter_handlers.js";
import {
  MAX_GETCFILTERS_SIZE,
  MAX_GETCFHEADERS_SIZE,
  CFCHECKPT_INTERVAL,
  NODE_COMPACT_FILTERS_BIT,
} from "../p2p/messages.js";
import type { CFilterHandlerDeps } from "../p2p/cfilter_handlers.js";
import type { Peer } from "../p2p/peer.js";
import { GCSFilter } from "../storage/indexes.js";

// ============================================================================
// MockPeer — minimal stand-in for the Peer interface the handlers touch.
//
// The handlers only call peer.misbehaving(score, message); we capture
// those into a list and assert against it in the test bodies. Cast to
// `unknown as Peer` so TypeScript trusts the surface.
// ============================================================================
function makeMockPeer(): {
  peer: Peer;
  misbehaviors: Array<{ score: number; message: string }>;
} {
  const misbehaviors: Array<{ score: number; message: string }> = [];
  const peer = {
    host: "203.0.113.1",
    port: 12345,
    misbehaving(score: number, message: string) {
      misbehaviors.push({ score, message });
    },
    send() {
      // unused in handler-direct tests; we pass a sendCFilter callback
    },
  } as unknown as Peer;
  return { peer, misbehaviors };
}

// ============================================================================
// Mock filter index — minimal surface (isEnabled / getFilter / getFilterHeader).
// ============================================================================
type MockFilterIndex = NonNullable<CFilterHandlerDeps["filterIndex"]>;
function makeFilterIndex(
  filters: Map<string, Buffer>,
  headers: Map<string, Buffer>,
  enabled = true
): MockFilterIndex {
  return {
    isEnabled: () => enabled,
    getFilter: async (hash: Buffer) => filters.get(hash.toString("hex")) ?? null,
    getFilterHeader: async (hash: Buffer) =>
      headers.get(hash.toString("hex")) ?? null,
  } as unknown as MockFilterIndex;
}

// ============================================================================
// Mock chain DB — a height-keyed map of (height ↔ hash). Mirrors the
// active-chain oracle handlers walk via getBlockHashByHeight + the
// hash-keyed getBlockIndex lookup for stop_hash → height.
// ============================================================================
function makeMockDb(blocks: Array<{ height: number; hash: Buffer }>) {
  const byHash = new Map<string, { height: number; hash: Buffer }>();
  const byHeight = new Map<number, Buffer>();
  for (const b of blocks) {
    byHash.set(b.hash.toString("hex"), b);
    byHeight.set(b.height, b.hash);
  }
  return {
    getBlockIndex: async (hash: Buffer) => {
      const b = byHash.get(hash.toString("hex"));
      return b ? { height: b.height, header: Buffer.alloc(80), nTx: 0, status: 0, dataPos: 0 } : null;
    },
    getBlockHashByHeight: async (height: number) => byHeight.get(height) ?? null,
  };
}

// ============================================================================
// Fixture: 5-block chain (heights 0..4) with a basic filter on each.
// ============================================================================
function makeChainFixture() {
  const blocks: Array<{ height: number; hash: Buffer; filterBytes: Buffer; filterHeader: Buffer }> = [];
  let prevFilterHeader: Buffer = Buffer.alloc(32, 0);
  for (let h = 0; h <= 4; h++) {
    const hash = Buffer.alloc(32, h + 1);
    const script = Buffer.from([0x76, 0xa9, 0x14, ...Buffer.alloc(20, h), 0x88, 0xac]);
    const filter = new GCSFilter([script], hash);
    const filterBytes = filter.getEncodedFilter();
    // Compute the filter HEADER (rolling hash256(filter_hash || prev_header))
    const filterHeader: Buffer = Buffer.from(computeFilterHeader(filter.getHash(), prevFilterHeader));
    blocks.push({ height: h, hash, filterBytes, filterHeader });
    prevFilterHeader = filterHeader;
  }
  const filters = new Map(blocks.map((b) => [b.hash.toString("hex"), b.filterBytes]));
  const headers = new Map(blocks.map((b) => [b.hash.toString("hex"), b.filterHeader]));
  const db = makeMockDb(blocks);
  const filterIndex = makeFilterIndex(filters, headers);
  return { blocks, db, filterIndex };
}

// ============================================================================
// processGetCFilters
// ============================================================================
describe("FIX-85: processGetCFilters", () => {
  it("happy path: returns one cfilter per block in range", async () => {
    const { blocks, db, filterIndex } = makeChainFixture();
    const { peer, misbehaviors } = makeMockPeer();
    const sent: Array<{ blockHash: Buffer; filterBytes: Buffer }> = [];
    await processGetCFilters(
      peer,
      { filterType: FILTER_TYPE_BASIC, startHeight: 1, stopHash: blocks[3].hash },
      { db, filterIndex, ourServices: NODE_COMPACT_FILTERS_BIT },
      (_p, resp) => sent.push({ blockHash: resp.blockHash, filterBytes: resp.filterBytes })
    );
    expect(sent.length).toBe(3); // heights 1, 2, 3
    expect(sent[0].blockHash.equals(blocks[1].hash)).toBe(true);
    expect(sent[2].blockHash.equals(blocks[3].hash)).toBe(true);
    expect(misbehaviors.length).toBe(0);
  });

  it("disconnects on unknown filter type", async () => {
    const { blocks, db, filterIndex } = makeChainFixture();
    const { peer, misbehaviors } = makeMockPeer();
    const sent: Array<unknown> = [];
    await processGetCFilters(
      peer,
      { filterType: 7 /* unknown */, startHeight: 0, stopHash: blocks[3].hash },
      { db, filterIndex, ourServices: NODE_COMPACT_FILTERS_BIT },
      (_p, resp) => sent.push(resp)
    );
    expect(sent.length).toBe(0);
    expect(misbehaviors.length).toBe(1);
    expect(misbehaviors[0].score).toBe(100);
    expect(misbehaviors[0].message).toContain("unsupported filter type");
  });

  it("disconnects when NODE_COMPACT_FILTERS not advertised", async () => {
    const { blocks, db, filterIndex } = makeChainFixture();
    const { peer, misbehaviors } = makeMockPeer();
    const sent: Array<unknown> = [];
    await processGetCFilters(
      peer,
      { filterType: 0, startHeight: 0, stopHash: blocks[3].hash },
      { db, filterIndex, ourServices: 0n /* no bits set */ },
      (_p, resp) => sent.push(resp)
    );
    expect(sent.length).toBe(0);
    expect(misbehaviors.length).toBe(1);
    expect(misbehaviors[0].score).toBe(100);
  });

  it("disconnects on unknown stop_hash", async () => {
    const { db, filterIndex } = makeChainFixture();
    const { peer, misbehaviors } = makeMockPeer();
    const unknownHash = Buffer.alloc(32, 0xff);
    const sent: Array<unknown> = [];
    await processGetCFilters(
      peer,
      { filterType: 0, startHeight: 0, stopHash: unknownHash },
      { db, filterIndex, ourServices: NODE_COMPACT_FILTERS_BIT },
      (_p, resp) => sent.push(resp)
    );
    expect(sent.length).toBe(0);
    expect(misbehaviors.length).toBe(1);
    expect(misbehaviors[0].message).toContain("invalid stop_hash");
  });

  it("disconnects on start_height > stop_height", async () => {
    const { blocks, db, filterIndex } = makeChainFixture();
    const { peer, misbehaviors } = makeMockPeer();
    const sent: Array<unknown> = [];
    await processGetCFilters(
      peer,
      { filterType: 0, startHeight: 4, stopHash: blocks[2].hash /* h=2 */ },
      { db, filterIndex, ourServices: NODE_COMPACT_FILTERS_BIT },
      (_p, resp) => sent.push(resp)
    );
    expect(sent.length).toBe(0);
    expect(misbehaviors.length).toBe(1);
    expect(misbehaviors[0].message).toContain("invalid range");
  });

  it("disconnects when range exceeds MAX_GETCFILTERS_SIZE (1000)", async () => {
    // Need a large chain. Simulate stop_height = 1000 + 1 with start = 0.
    const blocks: Array<{ height: number; hash: Buffer }> = [];
    for (let h = 0; h <= MAX_GETCFILTERS_SIZE; h++) {
      blocks.push({ height: h, hash: Buffer.from([h >> 8, h & 0xff, ...Buffer.alloc(30)]) });
    }
    const filters = new Map<string, Buffer>();
    const headers = new Map<string, Buffer>();
    const stopHash = blocks[MAX_GETCFILTERS_SIZE].hash;
    const { peer, misbehaviors } = makeMockPeer();
    const sent: Array<unknown> = [];
    await processGetCFilters(
      peer,
      { filterType: 0, startHeight: 0, stopHash },
      {
        db: makeMockDb(blocks),
        filterIndex: makeFilterIndex(filters, headers),
        ourServices: NODE_COMPACT_FILTERS_BIT,
      },
      (_p, resp) => sent.push(resp)
    );
    expect(sent.length).toBe(0);
    expect(misbehaviors.length).toBe(1);
    expect(misbehaviors[0].message).toContain("too many cf entries");
  });

  it("does not disconnect when --blockfilterindex disabled (silent return)", async () => {
    const { blocks, db } = makeChainFixture();
    // Filter index disabled — handler should silently return without
    // misbehaving (Core line 3306-3310 parity).
    const disabledFi = makeFilterIndex(new Map(), new Map(), false);
    const { peer, misbehaviors } = makeMockPeer();
    const sent: Array<unknown> = [];
    await processGetCFilters(
      peer,
      { filterType: 0, startHeight: 0, stopHash: blocks[3].hash },
      { db, filterIndex: disabledFi, ourServices: NODE_COMPACT_FILTERS_BIT },
      (_p, resp) => sent.push(resp)
    );
    expect(sent.length).toBe(0);
    expect(misbehaviors.length).toBe(0);
  });
});

// ============================================================================
// processGetCFHeaders
// ============================================================================
describe("FIX-85: processGetCFHeaders", () => {
  it("happy path: returns single cfheaders with filter hashes + prev header", async () => {
    const { blocks, db, filterIndex } = makeChainFixture();
    const { peer, misbehaviors } = makeMockPeer();
    const sent: Array<{
      filterType: number;
      stopHash: Buffer;
      previousFilterHeader: Buffer;
      filterHashes: Buffer[];
    }> = [];
    await processGetCFHeaders(
      peer,
      { filterType: 0, startHeight: 1, stopHash: blocks[3].hash },
      { db, filterIndex, ourServices: NODE_COMPACT_FILTERS_BIT },
      (_p, resp) => sent.push(resp)
    );
    expect(sent.length).toBe(1);
    expect(sent[0].filterHashes.length).toBe(3); // h=1,2,3
    expect(sent[0].previousFilterHeader.equals(blocks[0].filterHeader)).toBe(true);
    expect(misbehaviors.length).toBe(0);
  });

  it("start_height === 0: previousFilterHeader is all zeros (BIP-157 §3)", async () => {
    const { blocks, db, filterIndex } = makeChainFixture();
    const { peer } = makeMockPeer();
    const sent: Array<{ previousFilterHeader: Buffer; filterHashes: Buffer[] }> = [];
    await processGetCFHeaders(
      peer,
      { filterType: 0, startHeight: 0, stopHash: blocks[2].hash },
      { db, filterIndex, ourServices: NODE_COMPACT_FILTERS_BIT },
      (_p, resp) => sent.push(resp)
    );
    expect(sent.length).toBe(1);
    expect(sent[0].previousFilterHeader.equals(Buffer.alloc(32, 0))).toBe(true);
    expect(sent[0].filterHashes.length).toBe(3);
  });

  it("defensive return on missing prev_filter_header (FIX-79 pattern)", async () => {
    // Construct a chain where height 0's filter header is missing — the
    // handler must NOT send a partial response with a zero predecessor,
    // because a SPV peer would silently trust the lie. Mirrors ouroboros
    // FIX-79.
    const { blocks, db } = makeChainFixture();
    const filters = new Map(blocks.map((b) => [b.hash.toString("hex"), b.filterBytes]));
    const headers = new Map(blocks.slice(1).map((b) => [b.hash.toString("hex"), b.filterHeader]));
    // height 0 deliberately omitted
    const filterIndex = makeFilterIndex(filters, headers);
    const { peer } = makeMockPeer();
    const sent: Array<unknown> = [];
    await processGetCFHeaders(
      peer,
      { filterType: 0, startHeight: 1, stopHash: blocks[3].hash },
      { db, filterIndex, ourServices: NODE_COMPACT_FILTERS_BIT },
      (_p, resp) => sent.push(resp)
    );
    expect(sent.length).toBe(0); // defensive return; no partial answer
  });

  it("disconnects when range exceeds MAX_GETCFHEADERS_SIZE (2000)", async () => {
    const blocks: Array<{ height: number; hash: Buffer }> = [];
    for (let h = 0; h <= MAX_GETCFHEADERS_SIZE; h++) {
      blocks.push({
        height: h,
        hash: Buffer.from([h >> 8, h & 0xff, ...Buffer.alloc(30)]),
      });
    }
    const stopHash = blocks[MAX_GETCFHEADERS_SIZE].hash;
    const { peer, misbehaviors } = makeMockPeer();
    const sent: Array<unknown> = [];
    await processGetCFHeaders(
      peer,
      { filterType: 0, startHeight: 0, stopHash },
      {
        db: makeMockDb(blocks),
        filterIndex: makeFilterIndex(new Map(), new Map()),
        ourServices: NODE_COMPACT_FILTERS_BIT,
      },
      (_p, resp) => sent.push(resp)
    );
    expect(sent.length).toBe(0);
    expect(misbehaviors.length).toBe(1);
    expect(misbehaviors[0].message).toContain("too many cf entries");
  });
});

// ============================================================================
// processGetCFCheckPt
// ============================================================================
describe("FIX-85: processGetCFCheckPt", () => {
  it("happy path: emits filter header at every CFCHECKPT_INTERVAL", async () => {
    // Build a 2500-block chain. Checkpoints expected at heights 1000, 2000.
    const blocks: Array<{ height: number; hash: Buffer; filterHeader: Buffer }> = [];
    for (let h = 0; h <= 2500; h++) {
      blocks.push({
        height: h,
        hash: Buffer.from([h >> 8, h & 0xff, ...Buffer.alloc(30)]),
        filterHeader: Buffer.alloc(32, h % 256),
      });
    }
    const headers = new Map(blocks.map((b) => [b.hash.toString("hex"), b.filterHeader]));
    const stopHash = blocks[2500].hash;
    const { peer, misbehaviors } = makeMockPeer();
    const sent: Array<{ filterHeaders: Buffer[]; stopHash: Buffer }> = [];
    await processGetCFCheckPt(
      peer,
      { filterType: 0, stopHash },
      {
        db: makeMockDb(blocks),
        filterIndex: makeFilterIndex(new Map(), headers),
        ourServices: NODE_COMPACT_FILTERS_BIT,
      },
      (_p, resp) => sent.push(resp)
    );
    expect(sent.length).toBe(1);
    // floor(2500 / 1000) = 2 checkpoints at h=1000, 2000
    expect(sent[0].filterHeaders.length).toBe(2);
    // Verify Core-parity heights (1000, 2000) NOT (999, 1999) — W121 BUG-7
    expect(sent[0].filterHeaders[0].equals(blocks[1000].filterHeader)).toBe(true);
    expect(sent[0].filterHeaders[1].equals(blocks[2000].filterHeader)).toBe(true);
    expect(misbehaviors.length).toBe(0);
  });

  it("stop_height < CFCHECKPT_INTERVAL: zero checkpoints (no response wire-truncated)", async () => {
    // For a 100-block chain, floor(100/1000) = 0 — Core still sends a
    // cfcheckpt with an empty headers array (the response shape is
    // mandatory). Verify our handler emits the empty-array response.
    const blocks: Array<{ height: number; hash: Buffer; filterHeader: Buffer }> = [];
    for (let h = 0; h <= 100; h++) {
      blocks.push({
        height: h,
        hash: Buffer.from([h >> 8, h & 0xff, ...Buffer.alloc(30)]),
        filterHeader: Buffer.alloc(32, h % 256),
      });
    }
    const headers = new Map(blocks.map((b) => [b.hash.toString("hex"), b.filterHeader]));
    const stopHash = blocks[100].hash;
    const { peer } = makeMockPeer();
    const sent: Array<{ filterHeaders: Buffer[] }> = [];
    await processGetCFCheckPt(
      peer,
      { filterType: 0, stopHash },
      {
        db: makeMockDb(blocks),
        filterIndex: makeFilterIndex(new Map(), headers),
        ourServices: NODE_COMPACT_FILTERS_BIT,
      },
      (_p, resp) => sent.push(resp)
    );
    expect(sent.length).toBe(1);
    expect(sent[0].filterHeaders.length).toBe(0);
  });

  it("disconnects on unknown stop_hash", async () => {
    const blocks = [{ height: 0, hash: Buffer.alloc(32, 1), filterHeader: Buffer.alloc(32, 2) }];
    const headers = new Map(blocks.map((b) => [b.hash.toString("hex"), b.filterHeader]));
    const { peer, misbehaviors } = makeMockPeer();
    const sent: Array<unknown> = [];
    await processGetCFCheckPt(
      peer,
      { filterType: 0, stopHash: Buffer.alloc(32, 0xff) },
      {
        db: makeMockDb(blocks),
        filterIndex: makeFilterIndex(new Map(), headers),
        ourServices: NODE_COMPACT_FILTERS_BIT,
      },
      (_p, resp) => sent.push(resp)
    );
    expect(sent.length).toBe(0);
    expect(misbehaviors.length).toBe(1);
  });
});

// ============================================================================
// Wire codec round-trips (constants verified separately in w121 tests).
// ============================================================================
describe("FIX-85: wire constants", () => {
  it("MAX_GETCFILTERS_SIZE === 1000 (Core net_processing.cpp:184)", () => {
    expect(MAX_GETCFILTERS_SIZE).toBe(1000);
  });
  it("MAX_GETCFHEADERS_SIZE === 2000 (Core net_processing.cpp:186)", () => {
    expect(MAX_GETCFHEADERS_SIZE).toBe(2000);
  });
  it("CFCHECKPT_INTERVAL === 1000 (Core blockfilterindex.h:31)", () => {
    expect(CFCHECKPT_INTERVAL).toBe(1000);
  });
  it("NODE_COMPACT_FILTERS_BIT === 64n (= 1<<6, Core protocol.h:323)", () => {
    expect(NODE_COMPACT_FILTERS_BIT).toBe(64n);
  });
});
