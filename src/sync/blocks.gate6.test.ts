/**
 * Gate 6 — a resource failure is never a consensus verdict.
 *
 * docs/RELEASE-CHECKLIST.md gate 6; audit receipts/gate6-resource-limit-audit-2026-10-04.md
 * (hotbuns: F11 blocks.ts:4886 torn cache, F10 script-layer catch-alls,
 * mempool/submitblock system errors).
 *
 * Core: CCoinsViewCache is discarded on a failed ConnectBlock; a fault it
 * cannot retry past is FatalError -> AbortNode (validation.cpp:2136): stop
 * connecting, mark nothing, punish nobody, skip the shutdown flush, exit
 * non-zero. Script checks report only ScriptError values; bad_alloc
 * terminates.
 *
 * Every fault here is injected the same way on the deployed tree (7df1efe +
 * the test-only scriptFaultInjection hook + the inert chain/fatal.ts module)
 * and on the fix, so each test is a real fail-before / pass-after. The
 * controls (genuinely invalid blocks keep their verdicts) pass on both.
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
import { Transaction, getTxId, scriptFaultInjection } from "../validation/tx.js";
import { HeaderSync } from "./headers.js";
import { BlockSync, classifyCallbackError, isInvalidBlockVerdict } from "./blocks.js";
import { ChainStateManager } from "../chain/state.js";
import { isFatal, resetFatalForTest, abortNode } from "../chain/fatal.js";
import { ecdsaVerifyLaxFFI, FFI_AVAILABLE } from "../crypto/secp256k1_ffi.js";

const OP_TRUE = Buffer.from([0x51]);
const MATURE = 101; // blocks 1..101 coinbase-only; 102 spends cb1 + cb2
const SUBSIDY = 5_000_000_000n;

function coinbaseTx(height: number, value: bigint = SUBSIDY, tag = 0x07): Transaction {
  return {
    version: 1,
    inputs: [
      {
        prevOut: { txid: Buffer.alloc(32, 0), vout: 0xffffffff },
        scriptSig: Buffer.concat([encodeBip34Height(height), Buffer.from([0xff, tag])]),
        sequence: 0xffffffff,
        witness: [],
      },
    ],
    outputs: [{ value, scriptPubKey: OP_TRUE }],
    lockTime: 0,
  };
}

function spend(src: Transaction, value: bigint, scriptSig: Buffer = Buffer.alloc(0)): Transaction {
  return {
    version: 2,
    inputs: [
      {
        prevOut: { txid: getTxId(src), vout: 0 },
        scriptSig,
        sequence: 0xffffffff,
        witness: [],
      },
    ],
    outputs: [{ value, scriptPubKey: OP_TRUE }],
    lockTime: 0,
  };
}

function mine(prev: Buffer, ts: number, txs: Transaction[]): Block {
  const target = compactToBigInt(REGTEST.powLimitBits);
  const base: BlockHeader = {
    version: 4,
    prevBlock: prev,
    merkleRoot: computeMerkleRoot(txs.map((t) => getTxId(t))),
    timestamp: ts,
    bits: REGTEST.powLimitBits,
    nonce: 0,
  };
  for (let nonce = 0; nonce < 10_000_000; nonce++) {
    const header = { ...base, nonce };
    if (BigInt("0x" + Buffer.from(getBlockHash(header)).reverse().toString("hex")) <= target) {
      return { header, transactions: txs };
    }
  }
  throw new Error("failed to mine regtest block");
}

type Fixture = {
  dbPath: string;
  db: ChainDB;
  headerSync: HeaderSync;
  bs: BlockSync;
  chain: Block[]; // chain[i] is height i+1
  punished: string[];
  peerKey: string;
};

function mockPeer(punished: string[]): any {
  return {
    host: "127.0.0.1",
    port: 18444,
    state: "connected",
    versionPayload: { startHeight: MATURE + 1, services: 0x409n },
    send: () => true,
    addBlockInFlight: () => {},
    removeBlockInFlight: () => {},
    misbehaving: (score: number, reason: string) => {
      punished.push(`${score}:${reason}`);
    },
  };
}

function mockPeerManager(peers: any[]): any {
  return {
    getConnectedPeers: () => peers,
    onMessage: () => {},
    broadcast: () => {},
    increaseBanScore: () => {},
    updateBestHeight: () => {},
  };
}

/** Build a node at height 101 and a header chain whose block 102 is `tip`. */
async function setup(makeTip: (chain: Block[]) => Block): Promise<Fixture> {
  const dbPath = await mkdtemp(join(tmpdir(), "hotbuns-gate6-"));
  const db = new ChainDB(dbPath);
  await db.open();
  const headerSync = new HeaderSync(db, REGTEST);
  headerSync.initGenesis();
  const genesis = headerSync.getBestHeader()!;
  const chain: Block[] = [];
  let prev = genesis.hash;
  let ts = genesis.header.timestamp;
  for (let h = 1; h <= MATURE; h++) {
    ts += 600;
    const b = mine(prev, ts, [coinbaseTx(h)]);
    chain.push(b);
    prev = getBlockHash(b.header);
  }
  chain.push(makeTip(chain));
  const punished: string[] = [];
  const peer = mockPeer(punished);
  await headerSync.processHeaders(chain.map((b) => b.header), peer);
  expect(headerSync.getBestHeader()!.height).toBe(MATURE + 1);

  const csm = new ChainStateManager(db, REGTEST);
  await csm.load();
  const bs = new BlockSync(db, REGTEST, headerSync, mockPeerManager([peer]), csm);
  (bs as any).running = true; // as after start(), without timers / P2P
  bs.getState().nextHeightToProcess = 1;
  bs.getState().nextHeightToRequest = MATURE + 2;
  for (let i = 0; i < MATURE; i++) {
    bs.getState().downloadedBlocks.set(getBlockHash(chain[i].header).toString("hex"), chain[i]);
  }
  await (bs as any).processOrderedBlocks();
  expect(bs.getState().nextHeightToProcess).toBe(MATURE + 1);
  return { dbPath, db, headerSync, bs, chain, punished, peerKey: `${peer.host}:${peer.port}` };
}

function deliverTip(f: Fixture): void {
  const tip = f.chain[MATURE];
  const hex = getBlockHash(tip.header).toString("hex");
  f.bs.getState().downloadedBlocks.set(hex, tip);
  (f.bs as any).downloadedBlockPeers.set(hex, f.peerKey);
}

function tipStatus(f: Fixture): string | undefined {
  return f.headerSync.getHeader(getBlockHash(f.chain[MATURE].header))?.status;
}

/** Run processOrderedBlocks; report whether it threw (the deployed shape). */
async function process(f: Fixture): Promise<boolean> {
  try {
    await (f.bs as any).processOrderedBlocks();
    return false;
  } catch {
    return true;
  }
}

// Every test spends with a different fee so the spending txids differ: the
// process-wide signature cache would otherwise answer a later test's script
// checks from an earlier test's successful run (and skip the injected fault).
let feeSalt = 0n;
function validTip(chain: Block[]): Block {
  const cb1 = chain[0].transactions[0];
  const cb2 = chain[1].transactions[0];
  const prev = getBlockHash(chain[MATURE - 1].header);
  const fee = 1000n + feeSalt++;
  return mine(prev, chain[MATURE - 1].header.timestamp + 600, [
    coinbaseTx(MATURE + 1),
    spend(cb1, SUBSIDY - fee),
    spend(cb2, SUBSIDY - fee),
  ]);
}

/**
 * Make the SECOND getMaxCacheBytes() call of a connect throw — that call is
 * coreConnectBlockChecks' verifyScriptChecks argument, which runs AFTER the
 * block's spends and creates were applied to the in-memory view: an OOM at
 * the worst point of the connect.
 */
function armOomAfterApply(f: Fixture, times: number): () => number {
  const um = (f.bs as any).utxoManager;
  const orig = um.getMaxCacheBytes.bind(um);
  let calls = 0;
  let fired = 0;
  um.getMaxCacheBytes = () => {
    calls++;
    if (fired < times && calls % 2 === 0) {
      fired++;
      throw new RangeError("Out of memory");
    }
    return orig();
  };
  return () => fired;
}

describe("gate 6: a fault mid-connect is never a verdict (blocks.ts:4886 class)", () => {
  let f: Fixture;
  beforeEach(() => {
    resetFatalForTest();
    scriptFaultInjection.hook = null;
  });
  afterEach(async () => {
    scriptFaultInjection.hook = null;
    resetFatalForTest();
    try {
      await f.db.close();
    } catch {}
    await rm(f.dbPath, { recursive: true, force: true });
  });

  test(
    "OOM after the UTXO apply: the redelivered valid block connects, nothing marked, nobody punished",
    async () => {
      f = await setup(validTip);
      armOomAfterApply(f, 1);
      deliverTip(f);
      await process(f);
      // Nothing about the block was decided.
      expect(tipStatus(f)).not.toBe("invalid");
      expect(f.punished).toEqual([]);
      // Redelivery of the same valid block (the deployed tree kept it
      // buffered with the torn cache; the fix rewound and re-requested it).
      deliverTip(f);
      await process(f);
      // PRE-FIX: its own inputs read as spent -> bad-txns-inputs-missingorspent
      // -> header invalidated + misbehaving(100) for a VALID block.
      expect(tipStatus(f)).not.toBe("invalid");
      expect(f.punished).toEqual([]);
      expect(f.bs.getState().nextHeightToProcess).toBe(MATURE + 2);
      expect(isFatal()).toBe(false);
    },
    120_000
  );

  test(
    "a shutdown after the fault does not persist the torn view",
    async () => {
      f = await setup(validTip);
      armOomAfterApply(f, 1);
      deliverTip(f);
      await process(f);
      await f.bs.stop();
      // PRE-FIX: stop() flushed the half-applied block: cb1/cb2 deleted on disk
      // under CHAIN_STATE 101, i.e. coins destroyed with no block spending them.
      const cs = await f.db.getChainState();
      expect(cs!.bestHeight).toBe(MATURE);
      expect(await f.db.getUTXO(getTxId(f.chain[0].transactions[0]), 0)).not.toBeNull();
      expect(await f.db.getUTXO(getTxId(f.chain[1].transactions[0]), 0)).not.toBeNull();
    },
    120_000
  );

  test(
    "the fault recurs at the same height: AbortNode, no verdict, no punishment, no shutdown flush",
    async () => {
      f = await setup(validTip);
      armOomAfterApply(f, 1_000_000);
      deliverTip(f);
      await process(f);
      deliverTip(f);
      await process(f);
      expect(isFatal()).toBe(true); // pre: retried forever, never halts
      expect(tipStatus(f)).not.toBe("invalid");
      expect(f.punished).toEqual([]);
      await f.bs.stop();
      const cs = await f.db.getChainState();
      expect(cs!.bestHeight).toBe(MATURE);
      expect(await f.db.getUTXO(getTxId(f.chain[0].transactions[0]), 0)).not.toBeNull();
    },
    120_000
  );
});

describe("gate 6: a script check with no result (three outcomes)", () => {
  let f: Fixture;
  beforeEach(() => {
    resetFatalForTest();
    scriptFaultInjection.hook = null;
  });
  afterEach(async () => {
    scriptFaultInjection.hook = null;
    resetFatalForTest();
    try {
      await f.db.close();
    } catch {}
    await rm(f.dbPath, { recursive: true, force: true });
  });

  test(
    "a RangeError inside the interpreter is not 'Script verify failed': no mark, no ban; the retry connects",
    async () => {
      f = await setup(validTip);
      let fired = 0;
      scriptFaultInjection.hook = () => {
        if (fired++ === 0) throw new RangeError("Out of memory");
      };
      deliverTip(f);
      await process(f);
      // PRE-FIX: "Script verification failed ... RangeError: Out of memory"
      // -> consensus class -> header invalidated + misbehaving(100).
      expect(tipStatus(f)).not.toBe("invalid");
      expect(f.punished).toEqual([]);
      deliverTip(f);
      await process(f);
      expect(f.bs.getState().nextHeightToProcess).toBe(MATURE + 2);
      expect(isFatal()).toBe(false);
    },
    120_000
  );

  test(
    "a persistent interpreter fault latches AbortNode and is never a verdict",
    async () => {
      f = await setup(validTip);
      scriptFaultInjection.hook = () => {
        throw new TypeError("Unable to convert TypeError to a pointer");
      };
      deliverTip(f);
      await process(f);
      deliverTip(f);
      await process(f);
      expect(tipStatus(f)).not.toBe("invalid");
      expect(f.punished).toEqual([]);
      expect(isFatal()).toBe(true);
    },
    120_000
  );
});

describe("gate 6: the latch", () => {
  let f: Fixture;
  afterEach(async () => {
    resetFatalForTest();
    try {
      await f.db.close();
    } catch {}
    await rm(f.dbPath, { recursive: true, force: true });
  });

  test(
    "after AbortNode the valid tip is not connected, not judged, and submitblock gets the fatal token",
    async () => {
      f = await setup(validTip);
      resetFatalForTest();
      abortNode("test: injected fatal");
      deliverTip(f);
      await process(f);
      expect(f.bs.getState().nextHeightToProcess).toBe(MATURE + 1); // pre: connects
      expect(tipStatus(f)).not.toBe("invalid");
      expect(f.punished).toEqual([]);
      const r = await f.bs.injectBlock(f.chain[MATURE]);
      expect(r).toBe("fatal-error");
    },
    120_000
  );
});

describe("gate 6: classifier — a system fault is never a verdict", () => {
  test("fault strings are not consensus", () => {
    const faults = [
      "Script verification failed in tx 00aa at height 102 (input 0): Script verify failed: Out of memory",
      "fatal-error: system fault connecting block: RangeError: Out of memory",
      "bad-txns-inputs-missingorspent after LEVEL_IO_ERROR: IO error: No space left on device",
      "Missing UTXO: 00aa:0 (SystemFaultError: buffer is detached)",
    ];
    for (const m of faults) {
      expect(classifyCallbackError(m)).not.toBe("consensus");
      expect(isInvalidBlockVerdict(m)).toBe(false);
    }
  });
  test("controls: consensus failures keep their verdicts", () => {
    const verdicts = [
      "bad-cb-amount: coinbase pays too much (actual=5000000001 vs limit=5000000000) at height 102",
      "bad-txns-inputs-missingorspent: vin[0] of tx 00aa spends prevout 00bb:0 at height 102",
      "Script verification failed in tx 00aa at height 102 (input 0): Script verify returned false",
      "Script verification failed in tx 00aa at height 102 (input 0): Script verify failed: SCRIPT_ERR_OP_RETURN",
    ];
    for (const m of verdicts) {
      expect(classifyCallbackError(m)).toBe("consensus");
      expect(isInvalidBlockVerdict(m)).toBe(true);
    }
  });
});

describe("gate 6: secp FFI — a lost buffer is not an invalid signature", () => {
  test("a detached pubkey buffer raises instead of returning false", () => {
    if (!FFI_AVAILABLE) return; // FFI-only path
    const ab = new ArrayBuffer(33);
    const pk = new Uint8Array(ab);
    pk[0] = 0x02;
    structuredClone(ab, { transfer: [ab] }); // detach
    const sig = Buffer.from(
      "3044022000000000000000000000000000000000000000000000000000000000000000010220" +
        "0000000000000000000000000000000000000000000000000000000000000001",
      "hex"
    );
    let threw = false;
    let res: boolean | undefined;
    try {
      res = ecdsaVerifyLaxFFI(sig, Buffer.alloc(32, 1), pk);
    } catch {
      threw = true;
    }
    // PRE-FIX: false -> a NOT'd CHECKSIG would pass.
    expect(threw).toBe(true);
    expect(res).toBeUndefined();
  });
});

describe("gate 6 controls: genuinely invalid blocks keep their verdicts", () => {
  let f: Fixture;
  afterEach(async () => {
    resetFatalForTest();
    try {
      await f.db.close();
    } catch {}
    await rm(f.dbPath, { recursive: true, force: true });
  });

  test(
    "coinbase overpay: invalidated and the deliverer punished",
    async () => {
      f = await setup((chain) =>
        mine(getBlockHash(chain[MATURE - 1].header), chain[MATURE - 1].header.timestamp + 600, [
          coinbaseTx(MATURE + 1, SUBSIDY + 1n),
        ])
      );
      deliverTip(f);
      await process(f);
      expect(tipStatus(f)).toBe("invalid");
      expect(f.punished.length).toBe(1);
      expect(isFatal()).toBe(false);
    },
    120_000
  );

  test(
    "an invalid script (OP_RETURN scriptSig): invalidated and the deliverer punished",
    async () => {
      f = await setup((chain) =>
        mine(getBlockHash(chain[MATURE - 1].header), chain[MATURE - 1].header.timestamp + 600, [
          coinbaseTx(MATURE + 1),
          spend(chain[0].transactions[0], SUBSIDY - 1000n, Buffer.from([0x6a])),
        ])
      );
      deliverTip(f);
      await process(f);
      expect(tipStatus(f)).toBe("invalid");
      expect(f.punished.length).toBe(1);
      expect(isFatal()).toBe(false);
    },
    120_000
  );
});
