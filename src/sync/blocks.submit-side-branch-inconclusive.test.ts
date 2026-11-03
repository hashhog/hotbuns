/**
 * submitblock of a block below the processing frontier: "duplicate" only when
 * the body is already held, "inconclusive" for a side-branch block seen for
 * the first time.
 *
 *      genesis ── A1 ── A2      (active chain)
 *              \
 *               B1 ── B2 ── B3  (side branch; B3 out-works A2)
 *
 * Bitcoin Core rpc/mining.cpp submitblock:
 *     accepted = ProcessNewBlock(..., &new_block);
 *     if (!new_block && accepted) return "duplicate";
 *     if (!sc->found) return "inconclusive";
 * new_block is false only when AcceptBlock finds BLOCK_HAVE_DATA already set
 * (validation.cpp AcceptBlock, `if (fAlreadyHave) return true;`). A new
 * side-branch block with no more work than the tip is written to disk
 * (new_block=true) but never connected, so BlockChecked does not fire for it
 * and submitblock answers "inconclusive".
 *
 * PRE-FIX (hotbuns f0b6c4a): injectBlock answered "duplicate" for every block
 * whose header height was below the frontier, new or not (Core regtest rows
 * chain/submit/side-branch, failed_reorg/{a..e}/*s, *invalidated_submit/submit/
 * {inconclusive,failed-connect-sibling}).
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
import { HeaderSync } from "./headers.js";
import { BlockSync } from "./blocks.js";
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

describe("submitblock below the frontier: duplicate vs inconclusive (Core new_block parity)", () => {
  let dbPath: string;
  let db: ChainDB;
  let headerSync: HeaderSync;
  let chainState: ChainStateManager;
  let blockSync: BlockSync;

  beforeEach(async () => {
    dbPath = await mkdtemp(join(tmpdir(), "hotbuns-submit-side-inconclusive-"));
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
    const A1Hash = getBlockHash(A1.header);
    const A2 = mineBlock(A1Hash, t0 + 1200, 2, 1);
    const A2Hash = getBlockHash(A2.header);
    expect(await blockSync.injectBlock(A1)).toBeNull();
    expect(await blockSync.injectBlock(A2)).toBeNull();
    expect(chainState.getBestBlock().hash.equals(A2Hash)).toBe(true);
    const B1 = mineBlock(genesis.hash, t0 + 601, 1, 2);
    const B1Hash = getBlockHash(B1.header);
    const B2 = mineBlock(B1Hash, t0 + 1201, 2, 2);
    const B2Hash = getBlockHash(B2.header);
    return { A1, A1Hash, A2, A2Hash, B1, B1Hash, B2, B2Hash, t0 };
  }

  test("side-branch block submitted for the first time answers inconclusive and is stored", async () => {
    const { A2Hash, B1, B1Hash } = await setup();
    expect(await db.hasBlock(B1Hash)).toBe(false);
    expect(await blockSync.injectBlock(B1)).toBe("inconclusive");
    // Stored (Core: WriteBlock + BLOCK_HAVE_DATA), not connected.
    expect(await db.hasBlock(B1Hash)).toBe(true);
    expect(chainState.getBestBlock().hash.equals(A2Hash)).toBe(true);
  });

  test("equal-work side-branch tip submitted for the first time answers inconclusive", async () => {
    const { A2Hash, B1, B2 } = await setup();
    expect(await blockSync.injectBlock(B1)).toBe("inconclusive");
    // B2 ties A2 on work: Core keeps the first-seen tip and never checks B2.
    expect(await blockSync.injectBlock(B2)).toBe("inconclusive");
    expect(chainState.getBestBlock().hash.equals(A2Hash)).toBe(true);
  });

  test("the same side-branch block submitted again answers duplicate", async () => {
    const { B1 } = await setup();
    expect(await blockSync.injectBlock(B1)).toBe("inconclusive");
    expect(await blockSync.injectBlock(B1)).toBe("duplicate");
  });

  test("an active-chain block submitted again answers duplicate", async () => {
    const { A1, A2 } = await setup();
    expect(await blockSync.injectBlock(A1)).toBe("duplicate");
    expect(await blockSync.injectBlock(A2)).toBe("duplicate");
  });

  test("an inconclusive side-branch body is used when a heavier child arrives (reorg to B3)", async () => {
    const { A2Hash, B1, B2, B2Hash, t0 } = await setup();
    expect(await blockSync.injectBlock(B1)).toBe("inconclusive");
    expect(await blockSync.injectBlock(B2)).toBe("inconclusive");
    const B3 = mineBlock(B2Hash, t0 + 1801, 3, 2);
    const B3Hash = getBlockHash(B3.header);
    expect(await blockSync.injectBlock(B3)).toBeNull();
    expect(chainState.getBestBlock().hash.equals(B3Hash)).toBe(true);
    expect(chainState.getBestBlock().hash.equals(A2Hash)).toBe(false);
  });

  test("an invalid side-branch body stored as inconclusive is still rejected when a heavier child drives the reorg", async () => {
    const { A2Hash, B1, B1Hash, t0 } = await setup();
    // B2bad overpays the coinbase: not caught until ConnectBlock.
    const B2bad = mineBlock(B1Hash, t0 + 1202, 2, 3, REGTEST_SUBSIDY * 2n);
    const B2badHash = getBlockHash(B2bad.header);
    expect(await blockSync.injectBlock(B1)).toBe("inconclusive");
    expect(await blockSync.injectBlock(B2bad)).toBe("inconclusive");
    const B3 = mineBlock(B2badHash, t0 + 1802, 3, 3);
    const r = await blockSync.injectBlock(B3);
    expect(r).not.toBeNull();
    expect(chainState.getBestBlock().hash.equals(A2Hash)).toBe(true);
  });
});
