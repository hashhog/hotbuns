/**
 * Invalid block over P2P, reorg-INTERMEDIATE shape (Core InvalidBlockFound /
 * SetBlockFailureFlags / MaybePunishNodeForBlock parity).
 *
 *      genesis ── A1 ── A2            (active chain; A2 arrives last)
 *              \
 *               B1(invalid: bad-cb-amount) ── B2x   (heavier competing tip)
 *
 * A1 is the tip. B1 ties A1 on work, so it is stored as a side-branch body
 * without being validated. B2x (on B1) is heavier, so connecting it drives a
 * reorg whose INTERMEDIATE B1 fails a consensus rule.
 *
 * Bitcoin Core: ConnectTip(B1) fails -> InvalidBlockFound marks B1
 * BLOCK_FAILED_VALID, B2x becomes BLOCK_FAILED_CHILD, best header is
 * recalculated off the invalid branch, BlockChecked punishes the peer that
 * delivered B1, the active chain stays on A1, and neither block is ever
 * requested again. A2 (valid, ties B2x on work) then activates.
 *
 * PRE-FIX (hotbuns 088f392): the intermediate's consensus failure was
 * swallowed; the fork-tip connect then failed the secondary
 * `view-out-of-sync` gate, which is not a verdict, so nothing was marked,
 * nobody was punished, B2x stayed the best header and was re-requested in a
 * hot loop (167,882 getdata in the p2p-invalid-block-feed `after` scenario),
 * with a "wipe + re-sync" corruption banner every 3rd attempt.
 */

import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { mkdtemp, rm } from "fs/promises";
import { tmpdir } from "os";
import { join } from "path";
import { ChainDB } from "../storage/database.js";
import { REGTEST, compactToBigInt } from "../consensus/params.js";
import { MissingAncestorHeaderError } from "../consensus/pow.js";
import {
  Block,
  BlockHeader,
  getBlockHash,
  computeMerkleRoot,
  encodeBip34Height,
} from "../validation/block.js";
import { Transaction, getTxId } from "../validation/tx.js";
import { InvType } from "../p2p/messages.js";
import { HeaderSync } from "./headers.js";
import {
  BlockSync,
  isBlockMutationError,
  isInvalidBlockVerdict,
} from "./blocks.js";
import { ChainStateManager } from "../chain/state.js";

const REGTEST_SUBSIDY = 5_000_000_000n;

function coinbaseTx(height: number, extraNonce: number, value: bigint): Transaction {
  return {
    version: 1,
    inputs: [
      {
        prevOut: { txid: Buffer.alloc(32, 0), vout: 0xffffffff },
        scriptSig: Buffer.concat([
          encodeBip34Height(height),
          Buffer.from([0xff, extraNonce & 0xff]),
        ]),
        sequence: 0xffffffff,
        witness: [],
      },
    ],
    outputs: [
      {
        value,
        scriptPubKey: Buffer.from([0x76, 0xa9, 0x14, ...Buffer.alloc(20, 0x11), 0x88, 0xac]),
      },
    ],
    lockTime: 0,
  };
}

function mineBlock(
  prevBlock: Buffer,
  timestamp: number,
  height: number,
  extraNonce: number,
  coinbaseValue: bigint = REGTEST_SUBSIDY
): Block {
  const cb = coinbaseTx(height, extraNonce, coinbaseValue);
  const base: BlockHeader = {
    version: 4,
    prevBlock,
    merkleRoot: computeMerkleRoot([getTxId(cb)]),
    timestamp,
    bits: REGTEST.powLimitBits,
    nonce: 0,
  };
  const target = compactToBigInt(REGTEST.powLimitBits);
  for (let nonce = 0; nonce < 10_000_000; nonce++) {
    const header = { ...base, nonce };
    const h = Buffer.from(getBlockHash(header)).reverse();
    if (BigInt("0x" + h.toString("hex")) <= target) {
      return { header, transactions: [cb] };
    }
  }
  throw new Error("failed to mine regtest block");
}

/** Minimal stand-in for a connected Peer: records getdata + misbehaving. */
function fakePeer(host: string, port: number) {
  const sent: any[] = [];
  const misbehaved: Array<{ score: number; reason: string }> = [];
  return {
    host,
    port,
    sent,
    misbehaved,
    versionPayload: undefined,
    send(msg: any) {
      sent.push(msg);
      return true;
    },
    misbehaving(score: number, reason: string) {
      misbehaved.push({ score, reason });
    },
    addBlockInFlight() {},
    removeBlockInFlight() {},
    updateSyncedHeaders() {},
    updateSyncedBlocks() {},
  };
}

function fakeManager(peers: any[]) {
  return {
    getConnectedPeers: () => peers,
    updateBestHeight() {},
    broadcast() {},
    increaseBanScore() {},
  };
}

function blockGetdatas(peer: ReturnType<typeof fakePeer>, hash: Buffer): number {
  let n = 0;
  for (const m of peer.sent) {
    if (m.type !== "getdata") continue;
    for (const inv of m.payload.inventory) {
      if (Buffer.from(inv.hash).equals(hash)) n++;
    }
  }
  return n;
}

describe("BlockSync reorg intermediate fails consensus (Core InvalidBlockFound parity)", () => {
  let dbPath: string;
  let db: ChainDB;
  let headerSync: HeaderSync;
  let chainState: ChainStateManager;
  let blockSync: BlockSync;

  beforeEach(async () => {
    dbPath = await mkdtemp(join(tmpdir(), "hotbuns-reorg-invalid-interm-"));
    db = new ChainDB(dbPath);
    await db.open();
    headerSync = new HeaderSync(db, REGTEST);
    headerSync.initGenesis();
    chainState = new ChainStateManager(db, REGTEST);
    blockSync = new BlockSync(db, REGTEST, headerSync, undefined, chainState);
  });

  afterEach(async () => {
    await blockSync.stop();
    await db.close();
    await rm(dbPath, { recursive: true, force: true });
  });

  async function setup() {
    const genesis = headerSync.getBestHeader()!;
    const t0 = genesis.header.timestamp;
    const A1 = mineBlock(genesis.hash, t0 + 600, 1, 1);
    expect(await blockSync.injectBlock(A1)).toBeNull();
    const A1Hash = getBlockHash(A1.header);
    const B1 = mineBlock(genesis.hash, t0 + 600, 1, 2, REGTEST_SUBSIDY + 1n);
    const B1Hash = getBlockHash(B1.header);
    const B2x = mineBlock(B1Hash, t0 + 1200, 2, 2);
    const B2xHash = getBlockHash(B2x.header);
    const A2 = mineBlock(A1Hash, t0 + 1200, 2, 1);
    return { A1, A1Hash, B1, B1Hash, B2x, B2xHash, A2, A2Hash: getBlockHash(A2.header) };
  }

  test(
    "B1 marked invalid, B2x failed-child, B1's deliverer punished, tip kept, A2 activates, no refetch",
    async () => {
      const { A1Hash, B1, B1Hash, B2x, B2xHash, A2, A2Hash } = await setup();

      // X delivered B1 (equal work -> stored as a side branch, unvalidated).
      const X = fakePeer("127.0.0.2", 50001);
      const H = fakePeer("127.0.0.3", 50002);
      (blockSync as any).peerManager = fakeManager([X, H]);
      expect(await blockSync.injectBlock(B1)).toBe("duplicate");
      (blockSync as any).forkBodySource.set(B1Hash.toString("hex"), "127.0.0.2:50001");
      expect(chainState.getBestBlock().hash.equals(A1Hash)).toBe(true);

      // B2x (heavier, on B1) drives the reorg; B1 fails bad-cb-amount.
      const r = await blockSync.injectBlock(B2x);
      expect(r).not.toBeNull();

      // Active chain untouched.
      expect(chainState.getBestBlock().height).toBe(1);
      expect(chainState.getBestBlock().hash.equals(A1Hash)).toBe(true);

      // Core BLOCK_FAILED_VALID on B1, BLOCK_FAILED_CHILD on B2x.
      expect(headerSync.getHeader(B1Hash)!.status).toBe("invalid");
      expect(headerSync.getHeader(B2xHash)!.status).toBe("invalid");
      // Best header recalculated off the invalid branch.
      expect(headerSync.getBestHeader()!.hash.equals(A1Hash)).toBe(true);
      expect(headerSync.getHeaderByHeight(2)).toBeUndefined();

      // BlockChecked for B1 -> its deliverer (X) punished with the real rule;
      // the honest peer is not.
      expect(X.misbehaved.length).toBe(1);
      expect(X.misbehaved[0].reason).toBe("bad-cb-amount");
      expect(H.misbehaved.length).toBe(0);

      // The failure is remembered: a re-announcement (X redialled) fetches
      // neither block.
      (blockSync as any).ibdComplete = true;
      const X2 = fakePeer("127.0.0.2", 50003);
      await (blockSync as any).handleInv(X2, [
        { type: InvType.MSG_BLOCK, hash: B1Hash },
        { type: InvType.MSG_BLOCK, hash: B2xHash },
      ]);
      expect(blockGetdatas(X2, B1Hash)).toBe(0);
      expect(blockGetdatas(X2, B2xHash)).toBe(0);
      // Re-delivered headers do not resurrect the branch.
      await headerSync.processHeaders([B1.header, B2x.header], null);
      expect(headerSync.getBestHeader()!.hash.equals(A1Hash)).toBe(true);
      expect(headerSync.getHeader(B2xHash)!.status).toBe("invalid");

      // A valid competitor (ties B2x on work) activates.
      expect(await blockSync.injectBlock(A2)).toBeNull();
      expect(chainState.getBestBlock().height).toBe(2);
      expect(chainState.getBestBlock().hash.equals(A2Hash)).toBe(true);
      expect(blockGetdatas(X, B2xHash) + blockGetdatas(H, B2xHash)).toBe(0);
    },
    30_000
  );

  test(
    "non-verdict: intermediate that cannot be decided (missing ancestor header) is NOT marked",
    async () => {
      const { A1Hash, B1, B1Hash, B2x, B2xHash } = await setup();
      const X = fakePeer("127.0.0.2", 50001);
      (blockSync as any).peerManager = fakeManager([X]);
      expect(await blockSync.injectBlock(B1)).toBe("duplicate");
      (blockSync as any).forkBodySource.set(B1Hash.toString("hex"), "127.0.0.2:50001");

      // Snapshot-style partial header window: the intermediate's BIP-113 MTP
      // cannot be computed -> refusal, not a verdict.
      const orig = headerSync.getMedianTimePastAtHeight.bind(headerSync);
      (headerSync as any).getMedianTimePastAtHeight = (h: number, what: string) => {
        if (h === 0) throw new MissingAncestorHeaderError(what, 1, 0);
        return orig(h, what);
      };
      const r = await blockSync.injectBlock(B2x);
      expect(r).not.toBeNull();
      (headerSync as any).getMedianTimePastAtHeight = orig;

      expect(chainState.getBestBlock().hash.equals(A1Hash)).toBe(true);
      expect(headerSync.getHeader(B1Hash)!.status).not.toBe("invalid");
      expect(headerSync.getHeader(B2xHash)!.status).not.toBe("invalid");
      // Still the best header: it is retried later, not abandoned.
      expect(headerSync.getBestHeader()!.hash.equals(B2xHash)).toBe(true);
      expect(X.misbehaved.length).toBe(0);
    },
    30_000
  );

  test(
    "download: a block is requested only from a peer that announced its height (no NOTFOUND detour)",
    async () => {
      const { A2, A2Hash } = await setup();
      // H (honest, listed first) only knows height 1; X announced height 2.
      const H = { ...fakePeer("127.0.0.3", 50002), bestKnownHeight: 1 };
      const X = { ...fakePeer("127.0.0.2", 50001), bestKnownHeight: 2 };
      (blockSync as any).peerManager = fakeManager([H, X]);
      await headerSync.processHeaders([A2.header], null);
      expect(headerSync.getBestHeader()!.hash.equals(A2Hash)).toBe(true);
      (blockSync as any).running = true;
      (blockSync as any).state.nextHeightToRequest = 2;
      (blockSync as any).requestBlocks();
      (blockSync as any).running = false;
      expect(blockGetdatas(H as any, A2Hash)).toBe(0);
      expect(blockGetdatas(X as any, A2Hash)).toBe(1);
    },
    30_000
  );

  test("verdict classifier: mutation and cannot-decide errors are not verdicts", () => {
    // BLOCK_MUTATED class (Core never marks these BLOCK_FAILED_VALID).
    for (const e of [
      "Block abcd... at height 5 failed validation: Merkle root mismatch",
      "Block abcd... at height 5 failed validation: bad-txns-duplicate",
      "bad-witness-merkle-match",
      "bad-witness-nonce-size",
      "unexpected-witness",
    ]) {
      expect(isBlockMutationError(e)).toBe(true);
      expect(isInvalidBlockVerdict(e)).toBe(false);
    }
    // Cannot-decide / coordination / I-O.
    expect(
      isInvalidBlockVerdict(
        new MissingAncestorHeaderError("BIP-113 prev-block median-time-past", 9, 3).message
      )
    ).toBe(false);
    expect(isInvalidBlockVerdict("UTXO view best block aa does not match block prev bb at height 22 (view-out-of-sync)")).toBe(false);
    expect(isInvalidBlockVerdict("LEVEL_DATABASE_NOT_OPEN")).toBe(false);
    expect(isInvalidBlockVerdict("undo data missing for block")).toBe(false);
    // Genuine verdicts.
    expect(isInvalidBlockVerdict("bad-cb-amount: coinbase pays too much")).toBe(true);
    expect(isInvalidBlockVerdict("bad-txns-nonfinal")).toBe(true);
    expect(
      isInvalidBlockVerdict(
        "Block x... at height 2 not connected: reorg intermediate y at height 1 is invalid: bad-cb-amount: coinbase pays too much"
      )
    ).toBe(true);
  });
});
