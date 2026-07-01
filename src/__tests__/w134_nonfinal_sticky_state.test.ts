/**
 * W134 — sticky `bad-txns-nonfinal` state contamination across submitblock calls.
 *
 * TRUE-differential-fuzz finding (regtest bitcoind oracle vs hotbuns, driven via
 * the submitblock RPC): after a non-final-locktime block is rejected, hotbuns
 * retained the nonfinal reject reason in the BlockSync-instance scratchpad
 * `lastConnectError` and mis-reported it for a subsequent, unrelated block — one
 * poisoned block wedged every future submitblock with "bad-txns-nonfinal".
 *
 * Root cause: `injectBlock` (the submitblock intake) reads `lastConnectError`
 * back through its BIP-22 result classifier. `connectBlock` clears that field at
 * its own start, so the *connect decision* is always per-block — but when a
 * submitted block never reaches `connectBlock` (its header is a competing
 * sibling that is not the active header at its height, so
 * `processOrderedBlocksInner` cannot find its body and breaks without
 * connecting), the classifier read the STALE reason from the previous rejected
 * block.
 *
 * Finality is a pure per-tx property in Bitcoin Core (IsFinalTx,
 * consensus/tx_verify.cpp — never persisted). The fix scopes the scratchpad
 * per submission by resetting `lastConnectError` at the start of `injectBlock`,
 * mirroring the per-block reset `connectBlock` already performs.
 *
 * Reachability: submitblock-only. The P2P intake (`handleBlock`) returns void
 * and never maps `lastConnectError` into a per-block verdict; only the
 * submitblock classifier does. Both paths share `connectBlock`, whose per-block
 * reset keeps the actual connect decision correct.
 *
 * EFFECTIVE test: submit a non-final block (reject) then a valid block ->
 *   pre-fix: the valid block is wrongly reported "bad-txns-nonfinal".
 *   post-fix: the valid block is NOT reported "bad-txns-nonfinal".
 *
 * Reference:
 *   - bitcoin-core/src/consensus/tx_verify.cpp (IsFinalTx — pure, per-tx)
 *   - bitcoin-core/src/validation.cpp:4146 (ContextualCheckBlock IsFinalTx loop)
 *
 * Running: bun test src/__tests__/w134_nonfinal_sticky_state.test.ts
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

/** BIP34-height coinbase, parameterised by lockTime/sequence so we can build a
 *  non-final variant (unmet height lock + non-SEQUENCE_FINAL input). */
function makeCoinbase(
  height: number,
  lockTime: number,
  sequence: number,
  value: bigint = 5000000000n,
): Transaction {
  // Canonical BIP34 height encoding (byte-exact prefix Core requires), padded
  // to satisfy the 2-byte minimum coinbase-scriptSig length.
  const scriptSig = Buffer.concat([encodeBip34Height(height), Buffer.from([0x00])]);
  return {
    version: 1,
    inputs: [
      {
        prevOut: { txid: Buffer.alloc(32, 0), vout: 0xffffffff },
        scriptSig,
        sequence,
        witness: [],
      },
    ],
    outputs: [
      {
        value,
        scriptPubKey: Buffer.from([
          0x76, 0xa9, 0x14, ...Buffer.alloc(20, 0x11), 0x88, 0xac,
        ]),
      },
    ],
    lockTime,
  };
}

/** Mine a regtest block containing exactly `coinbaseTx`. */
function mineBlock(prevBlock: Buffer, timestamp: number, coinbaseTx: Transaction): Block {
  const merkleRoot = computeMerkleRoot([getTxId(coinbaseTx)]);
  const base: BlockHeader = {
    version: 4,
    prevBlock,
    merkleRoot,
    timestamp,
    bits: REGTEST.powLimitBits,
    nonce: 0,
  };
  const target = compactToBigInt(REGTEST.powLimitBits);
  for (let nonce = 0; nonce < 10_000_000; nonce++) {
    const header = { ...base, nonce };
    const hv = BigInt("0x" + Buffer.from(getBlockHash(header)).reverse().toString("hex"));
    if (hv <= target) return { header, transactions: [coinbaseTx] };
  }
  throw new Error("could not mine regtest block");
}

describe("W134: sticky bad-txns-nonfinal contamination (submitblock)", () => {
  let dbPath: string;
  let db: ChainDB;
  let headerSync: HeaderSync;
  let blockSync: BlockSync;

  beforeEach(async () => {
    dbPath = await mkdtemp(join(tmpdir(), "hotbuns-w134-"));
    db = new ChainDB(dbPath);
    await db.open();
    headerSync = new HeaderSync(db, REGTEST);
    headerSync.initGenesis();
    blockSync = new BlockSync(db, REGTEST, headerSync);
  });

  afterEach(async () => {
    await blockSync.stop();
    await db.close();
    await rm(dbPath, { recursive: true, force: true });
  });

  test("a non-final block reject must not poison a later block's submitblock verdict", async () => {
    const genesis = headerSync.getBestHeader()!;
    const ts = genesis.header.timestamp + 600;

    // --- Block A: non-final coinbase (unmet height lock + non-SEQUENCE_FINAL
    //     input) => ContextualCheckBlock IsFinalTx rejects "bad-txns-nonfinal". ---
    const nonFinalBlock = mineBlock(
      genesis.hash,
      ts,
      makeCoinbase(1, /*lockTime=*/ 500_000, /*sequence=*/ 0xfffffffe),
    );

    // --- Block B: an ordinary, fully-final competing block at the same height
    //     (SEQUENCE_FINAL coinbase, lockTime 0). Different txid => different
    //     merkle root => different block hash than A. ---
    const validBlock = mineBlock(
      genesis.hash,
      ts,
      makeCoinbase(1, /*lockTime=*/ 0, /*sequence=*/ 0xffffffff),
    );

    // Sanity: the two blocks really are distinct.
    expect(getBlockHash(nonFinalBlock.header).equals(getBlockHash(validBlock.header))).toBe(false);

    // 1) Submit the non-final block: must be rejected as bad-txns-nonfinal.
    const r1 = await blockSync.injectBlock(nonFinalBlock);
    expect(r1).toBe("bad-txns-nonfinal");

    // 2) Submit the valid block. Pre-fix, `injectBlock` read the stale
    //    `lastConnectError` (still "…bad-txns-nonfinal…" from block A, because
    //    block B's body never reaches connectBlock — A's header stays active at
    //    height 1) and wrongly returned "bad-txns-nonfinal". Post-fix, the
    //    per-submission reset clears it, so B is never mis-tagged non-final.
    const r2 = await blockSync.injectBlock(validBlock);
    expect(r2).not.toBe("bad-txns-nonfinal");
  });
});
