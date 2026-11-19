/**
 * Reorg intermediates must pass CheckBlock + ContextualCheckBlock
 * (Core AcceptBlock / ConnectBlock parity).
 *
 *   genesis ── A1 ── A2                       (active chain)
 *          \
 *           B1 ── B2 ── B3                    (heavier fork, B3 delivered last)
 *
 * B1 and B2 tie A1/A2 on work, so hotbuns stores them as side-branch bodies
 * after only the receipt mutation check. B3 drives the reorg, and
 * handleReorgUtxoAndCollect connects B1 and B2 from disk.
 *
 * Bitcoin Core: AcceptBlock runs CheckBlock + ContextualCheckBlock before any
 * body is stored, and ConnectBlock re-runs CheckBlock, so every block connected
 * in ActivateBestChainStep -> ConnectTip has passed both. A fork whose middle
 * block breaks one of those rules (BIP34 coinbase height, duplicate inputs,
 * weight, coinbase placement, CheckTransaction) never becomes active, and the
 * bad block is marked BLOCK_FAILED_VALID.
 *
 * Pre-fix hotbuns ran only coreConnectBlockChecks (ConnectBlock's UTXO/script
 * part) on intermediates, so such a fork was accepted.
 */

import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { mkdtemp, rm } from "fs/promises";
import { tmpdir } from "os";
import { join } from "path";
import { ChainDB } from "../storage/database.js";
import { REGTEST, compactToBigInt } from "../consensus/params.js";
import {
  Block,
  BlockHeader,
  getBlockHash,
  computeMerkleRoot,
  encodeBip34Height,
} from "../validation/block.js";
import { Transaction, getTxId } from "../validation/tx.js";
import { HeaderSync } from "../sync/headers.js";
import { BlockSync } from "../sync/blocks.js";
import { ChainStateManager } from "../chain/state.js";

const SUBSIDY = 5_000_000_000n;
// OP_TRUE: anyone can spend, so a fixture tx needs no signature.
const OP_TRUE = Buffer.from([0x51]);

function coinbaseTx(height: number, tag: number, bip34 = true): Transaction {
  return {
    version: 1,
    inputs: [
      {
        prevOut: { txid: Buffer.alloc(32, 0), vout: 0xffffffff },
        scriptSig: bip34
          ? Buffer.concat([encodeBip34Height(height), Buffer.from([0xff, tag & 0xff])])
          : // 2..100 bytes (passes bad-cb-length) but no height push.
            Buffer.from([0xff, tag & 0xff, 0xee]),
        sequence: 0xffffffff,
        witness: [],
      },
    ],
    outputs: [{ value: SUBSIDY, scriptPubKey: OP_TRUE }],
    lockTime: 0,
  };
}

function mine(
  prevBlock: Buffer,
  timestamp: number,
  height: number,
  tag: number,
  opts: { bip34?: boolean; extraTxs?: Transaction[] } = {}
): Block {
  const txs = [coinbaseTx(height, tag, opts.bip34 ?? true), ...(opts.extraTxs ?? [])];
  const base: BlockHeader = {
    version: 4,
    prevBlock,
    merkleRoot: computeMerkleRoot(txs.map((t) => getTxId(t))),
    timestamp,
    bits: REGTEST.powLimitBits,
    nonce: 0,
  };
  const target = compactToBigInt(REGTEST.powLimitBits);
  for (let nonce = 0; nonce < 10_000_000; nonce++) {
    const header = { ...base, nonce };
    const h = Buffer.from(getBlockHash(header)).reverse();
    if (BigInt("0x" + h.toString("hex")) <= target) {
      return { header, transactions: txs };
    }
  }
  throw new Error("failed to mine regtest block");
}

describe("reorg intermediates pass CheckBlock + ContextualCheckBlock", () => {
  let dbPath: string;
  let db: ChainDB;
  let headerSync: HeaderSync;
  let chainState: ChainStateManager;
  let blockSync: BlockSync;

  beforeEach(async () => {
    dbPath = await mkdtemp(join(tmpdir(), "hotbuns-cffix-reorg-checkblock-"));
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

  /**
   * Build the active chain `base` (already connected) + A(n+1), A(n+2), and a
   * competing fork B(n+1), B(n+2), B(n+3) from the same fork point. B(n+1)
   * is built by `badB1` (defaults to a valid block).
   */
  async function forkFixture(
    forkHash: Buffer,
    forkHeight: number,
    forkTime: number,
    badB1?: (prev: Buffer, time: number, height: number) => Block
  ) {
    const h = forkHeight;
    const A1 = mine(forkHash, forkTime + 600, h + 1, 1);
    expect(await blockSync.injectBlock(A1)).toBeNull();
    const A2 = mine(getBlockHash(A1.header), forkTime + 1200, h + 2, 1);
    expect(await blockSync.injectBlock(A2)).toBeNull();
    const A2Hash = getBlockHash(A2.header);
    expect(chainState.getBestBlock().hash.equals(A2Hash)).toBe(true);

    const B1 = badB1
      ? badB1(forkHash, forkTime + 601, h + 1)
      : mine(forkHash, forkTime + 601, h + 1, 2);
    const B1Hash = getBlockHash(B1.header);
    const B2 = mine(B1Hash, forkTime + 1201, h + 2, 2);
    const B2Hash = getBlockHash(B2.header);
    const B3 = mine(B2Hash, forkTime + 1801, h + 3, 2);
    const B3Hash = getBlockHash(B3.header);

    // Equal work to the active chain: stored as side-branch bodies.
    expect(await blockSync.injectBlock(B1)).toBe("inconclusive");
    expect(await blockSync.injectBlock(B2)).toBe("inconclusive");
    expect(chainState.getBestBlock().hash.equals(A2Hash)).toBe(true);

    return { A2Hash, B1, B1Hash, B2Hash, B3, B3Hash };
  }

  async function expectRejectedFork(
    f: Awaited<ReturnType<typeof forkFixture>>,
    activeHeight: number,
    reason: string
  ) {
    // B3 is heavier: connecting it drives the reorg through B1, B2.
    const r = await blockSync.injectBlock(f.B3);
    expect(r).not.toBeNull();

    // Active chain stays on A.
    expect(chainState.getBestBlock().height).toBe(activeHeight);
    expect(chainState.getBestBlock().hash.equals(f.A2Hash)).toBe(true);

    // B1 BLOCK_FAILED_VALID, its descendants BLOCK_FAILED_CHILD.
    expect(headerSync.getHeader(f.B1Hash)!.status).toBe("invalid");
    expect(headerSync.getHeader(f.B2Hash)!.status).toBe("invalid");
    expect(headerSync.getHeader(f.B3Hash)!.status).toBe("invalid");
    expect(headerSync.getBestHeader()!.hash.equals(f.A2Hash)).toBe(true);

    // The verdict names B1's rule.
    expect(String((blockSync as any).lastConnectError)).toContain(reason);
  }

  /** 100 connected blocks, so the height-1 coinbase (OP_TRUE) is mature for
   *  a block at height 101 (COINBASE_MATURITY = 100). */
  async function matureChain() {
    const genesis = headerSync.getBestHeader()!;
    let prev = genesis.hash;
    let t = genesis.header.timestamp;
    let firstCoinbase: Transaction | null = null;
    for (let h = 1; h <= 100; h++) {
      t += 600;
      const b = mine(prev, t, h, 0);
      expect(await blockSync.injectBlock(b)).toBeNull();
      if (h === 1) firstCoinbase = b.transactions[0];
      prev = getBlockHash(b.header);
    }
    return { prev, t, firstCoinbase: firstCoinbase! };
  }

  function spendTx(txid: Buffer, vouts: number[]): Transaction {
    return {
      version: 2,
      inputs: vouts.map((vout) => ({
        prevOut: { txid, vout },
        scriptSig: Buffer.alloc(0),
        sequence: 0xffffffff,
        witness: [],
      })),
      outputs: [{ value: 1_000n, scriptPubKey: OP_TRUE }],
      lockTime: 0,
    };
  }

  test(
    "intermediate whose coinbase lacks the BIP34 height is rejected bad-cb-height; tip stays on A",
    async () => {
      const genesis = headerSync.getBestHeader()!;
      const f = await forkFixture(genesis.hash, 0, genesis.header.timestamp, (prev, t, h) =>
        mine(prev, t, h, 2, { bip34: false })
      );
      await expectRejectedFork(f, 2, "bad-cb-height");
    },
    30_000
  );

  test(
    "intermediate with a duplicate-input tx is rejected bad-txns-inputs-duplicate, not an exception",
    async () => {
      const { prev, t, firstCoinbase } = await matureChain();
      const cbTxid = getTxId(firstCoinbase);
      // The same outpoint spent twice in one tx (CVE-2018-17144 shape).
      const dupTx = spendTx(cbTxid, [0, 0]);
      const f = await forkFixture(prev, 100, t, (p, bt, h) =>
        mine(p, bt, h, 2, { extraTxs: [dupTx] })
      );
      await expectRejectedFork(f, 102, "bad-txns-inputs-duplicate");
    },
    120_000
  );

  test(
    "control: a valid fork with valid intermediates still reorgs",
    async () => {
      const genesis = headerSync.getBestHeader()!;
      const f = await forkFixture(genesis.hash, 0, genesis.header.timestamp);
      expect(await blockSync.injectBlock(f.B3)).toBeNull();
      expect(chainState.getBestBlock().height).toBe(3);
      expect(chainState.getBestBlock().hash.equals(f.B3Hash)).toBe(true);
      expect(headerSync.getHeader(f.B1Hash)!.status).not.toBe("invalid");
    },
    30_000
  );

  test(
    "control: a valid fork whose intermediate spends a mature coin still reorgs",
    async () => {
      const { prev, t, firstCoinbase } = await matureChain();
      const okTx = spendTx(getTxId(firstCoinbase), [0]);
      const f = await forkFixture(prev, 100, t, (p, bt, h) =>
        mine(p, bt, h, 2, { extraTxs: [okTx] })
      );
      expect(await blockSync.injectBlock(f.B3)).toBeNull();
      expect(chainState.getBestBlock().height).toBe(103);
      expect(chainState.getBestBlock().hash.equals(f.B3Hash)).toBe(true);
      expect(headerSync.getHeader(f.B1Hash)!.status).not.toBe("invalid");
    },
    120_000
  );
});
