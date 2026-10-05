/**
 * In-process tests for the active-chain time context (2026-10-05).
 *
 * Core references:
 *   validation.cpp CheckFinalTxAtTip         — IsFinalTx(tx, tip+1, tip MTP)
 *   validation.cpp CalculateLockPointsAtTip  — mempool coin -> height tip+1
 *   consensus/tx_verify.cpp CalculateSequenceLocks
 *       nCoinTime = block.GetAncestor(max(nCoinHeight-1, 0))->GetMedianTimePast()
 *   validation.cpp ContextualCheckBlock      — lock_time_cutoff = pprev MTP
 *
 * The end-to-end discriminator against the real binary is
 * src/__tests__/mtp_wiring_e2e.test.ts; this file pins the pieces:
 * ChainStateManager's block-index fallback (no HeaderSync), the
 * active-tip-not-best-header rule, and that the mempool's provider follows
 * a disconnect without any update hook.
 */
import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ChainDB } from "../storage/database.js";
import { REGTEST } from "../consensus/params.js";
import { ChainStateManager } from "./state.js";
import { HeaderSync } from "../sync/headers.js";
import { Mempool } from "../mempool/mempool.js";
import { getBlockHash, deserializeBlock } from "../validation/block.js";
import { getTxId } from "../validation/tx.js";
import { BufferReader } from "../wire/serialization.js";
import {
  buildBaseChain,
  mineBlock,
  spendOpTrue,
  timeLock,
  tsAt,
  mtpAt,
  BASE_TIP,
  FUND_HEIGHT,
  FUND_OUT_VALUE,
  type BaseChain,
} from "../test/mtp_chain_fixture.js";

const GENESIS_TS = deserializeBlock(new BufferReader(REGTEST.genesisBlock)).header.timestamp;
const TIP_MTP = mtpAt(BASE_TIP, GENESIS_TS);
const COIN_MTP = mtpAt(FUND_HEIGHT - 1, GENESIS_TS);

let chain: BaseChain;
let dir: string;
let db: ChainDB;
let cs: ChainStateManager;

beforeEach(async () => {
  chain ??= buildBaseChain();
  dir = await mkdtemp(join(tmpdir(), "hb-mtp-unit-"));
  db = new ChainDB(dir);
  await db.open();
  cs = new ChainStateManager(db, REGTEST);
  await cs.load();
});

afterEach(async () => {
  await db.close();
  await rm(dir, { recursive: true, force: true });
});

async function connectBase(): Promise<void> {
  for (let i = 0; i < chain.blocks.length; i++) {
    await cs.connectBlock(chain.blocks[i], i + 1);
  }
}

const fundTxid = () => getTxId(chain.fundTx);
const next = (txs: ReturnType<typeof spendOpTrue>[]) =>
  mineBlock(chain.tipHash, BASE_TIP + 1, tsAt(BASE_TIP + 1), txs);

async function connectErr(block: ReturnType<typeof next>): Promise<string | null> {
  try {
    await cs.connectBlock(block, BASE_TIP + 1);
    return null;
  } catch (e) {
    return (e as Error).message;
  }
}

describe("ChainStateManager.connectBlock without HeaderSync (block-index fallback)", () => {
  test("nLockTime = prevMTP rejected; prevMTP-1 accepted (control)", async () => {
    await connectBase();
    const bad = spendOpTrue(fundTxid(), 0, FUND_OUT_VALUE, { lockTime: TIP_MTP, sequence: 0xfffffffe });
    expect(await connectErr(next([bad]))).toContain("bad-txns-nonfinal");
    expect(cs.getBestBlock().height).toBe(BASE_TIP);
    const ok = spendOpTrue(fundTxid(), 0, FUND_OUT_VALUE, { lockTime: TIP_MTP - 1, sequence: 0xfffffffe });
    expect(await connectErr(next([ok]))).toBeNull();
    expect(cs.getBestBlock().height).toBe(BASE_TIP + 1);
  });

  test("time-type relative lock: 12 units rejected, 11 units accepted (control)", async () => {
    await connectBase();
    const bad = spendOpTrue(fundTxid(), 1, FUND_OUT_VALUE, { sequence: timeLock(12) });
    expect(await connectErr(next([bad]))).toContain("bad-txns-nonfinal");
    const ok = spendOpTrue(fundTxid(), 1, FUND_OUT_VALUE, { sequence: timeLock(11) });
    expect(await connectErr(next([ok]))).toBeNull();
  });

  test("an unresolvable coin ancestor refuses the block (never coin MTP 0)", async () => {
    await connectBase();
    // Coin at 102 -> ancestor 101 via the active-chain height index.
    await db.deleteBlockHashByHeight(FUND_HEIGHT - 1);
    expect(await db.getBlockHashByHeight(FUND_HEIGHT - 1)).toBeNull();
    const tx = spendOpTrue(fundTxid(), 1, FUND_OUT_VALUE, { sequence: timeLock(11) });
    expect(await connectErr(next([tx]))).toContain("missing-ancestor-header");
    expect(cs.getBestBlock().height).toBe(BASE_TIP);
  });
});

describe("active-chain MTP provider (HeaderSync wired)", () => {
  async function wired(): Promise<HeaderSync> {
    const hs = new HeaderSync(db, REGTEST);
    hs.initGenesis();
    await hs.processHeaders(chain.blocks.map((b) => b.header), null);
    cs.setHeaderSync(hs);
    await connectBase();
    return hs;
  }

  test("tip MTP and coin MTP equal Core's values at tip 120", async () => {
    await wired();
    expect(cs.getTipMedianTimePast()).toBe(TIP_MTP);
    expect(cs.getCoinMedianTimePastAtTip(FUND_HEIGHT)).toBe(COIN_MTP);
  });

  test("tip MTP follows the ACTIVE tip, not a heavier best-header fork", async () => {
    const hs = await wired();
    // Fork from height 110 with 15 headers (best header 125), timestamps +7 s.
    let prev = getBlockHash(chain.blocks[109].header);
    const fork = [];
    for (let h = 111; h <= 125; h++) {
      const b = mineBlock(prev, h, tsAt(h) + 7, []);
      fork.push(b.header);
      prev = getBlockHash(b.header);
    }
    await hs.processHeaders(fork, null);
    expect(hs.getBestHeader()!.height).toBe(125);
    expect(cs.getBestBlock().height).toBe(BASE_TIP);
    expect(cs.getTipMedianTimePast()).toBe(TIP_MTP);
    // Coin at 118 -> ancestor 117 of the ACTIVE chain (fork would be +7).
    expect(cs.getCoinMedianTimePastAtTip(118)).toBe(mtpAt(117, GENESIS_TS));
  });

  test("mempool provider follows a disconnect with no update hook", async () => {
    await wired();
    const mp = new Mempool(cs.getUTXOManager(), REGTEST);
    mp.setTipHeight(BASE_TIP);
    mp.setChainMTPProvider({
      tipMTP: () => cs.getTipMedianTimePast(),
      coinMTP: (h: number) => cs.getCoinMedianTimePastAtTip(h),
    });
    const lt = spendOpTrue(fundTxid(), 2, FUND_OUT_VALUE, { lockTime: TIP_MTP - 1, sequence: 0xfffffffe });
    expect((await mp.addTransaction(lt, { testAccept: true } as never)).error).toBeUndefined();
    const rel = spendOpTrue(fundTxid(), 3, FUND_OUT_VALUE, { sequence: timeLock(11) });
    expect((await mp.addTransaction(rel, { testAccept: true } as never)).error).toBeUndefined();
    // Disconnect the tip: active MTP becomes MTP(119) = ts(114) < TIP_MTP - 1.
    await cs.disconnectBlock(chain.blocks[BASE_TIP - 1], BASE_TIP);
    mp.setTipHeight(BASE_TIP - 1);
    expect(cs.getTipMedianTimePast()).toBe(mtpAt(BASE_TIP - 1, GENESIS_TS));
    const r = await mp.addTransaction(lt, { testAccept: true } as never);
    expect(r.accepted).toBe(false);
    expect(String(r.error)).toContain("non-final");
  });
});
