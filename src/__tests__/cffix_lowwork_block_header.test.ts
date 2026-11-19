/**
 * cffix-hotbuns-lowwork-block-header: an UNREQUESTED block whose parent is
 * known, but whose claimed chain work is below the anti-DoS threshold, must not
 * leave a header entry or a stored body behind.
 *
 * Core net_processing.cpp ProcessMessage "block" sets
 *   min_pow_checked = prev_block->nChainWork + GetBlockProof(*pblock)
 *                     >= GetAntiDoSWorkThreshold()
 * and validation.cpp ChainstateManager::AcceptBlockHeader answers
 *   if (!min_pow_checked) return state.Invalid(BLOCK_HEADER_LOW_WORK,
 *                                               "too-little-chainwork");
 * UNCONDITIONALLY: the header never enters the block index and AcceptBlock
 * never writes the body. The sender is not punished (LOW_WORK is not a
 * misbehaviour in MaybePunishNodeForBlock).
 *
 * hotbuns' handleBlock computed min_pow_checked correctly, but processHeaders
 * only used `minPowChecked=false` to compare against nMinimumChainWork. Once
 * the node was past nMinimumChainWork the low-work header was stored, and
 * maybeStoreForkBody then wrote the fork body to disk: a cheap disk-fill on
 * testnet4 (20-minute min-difficulty blocks).
 *
 * Fixture: regtest-difficulty headers (so the test can mine them) with
 * nMinimumChainWork raised above zero, i.e. a network that HAS a minimum chain
 * work and a node that is past it — the testnet4/mainnet condition the finding
 * needs. The active chain is 300 blocks; the anti-DoS threshold is therefore
 * tip work - 144 blocks of work.
 */

import { describe, test, expect, beforeEach, afterEach, mock } from "bun:test";
import { mkdtemp, rm } from "fs/promises";
import { tmpdir } from "os";
import { join } from "path";
import { ChainDB } from "../storage/database.js";
import { REGTEST, compactToBigInt, type ConsensusParams } from "../consensus/params.js";
import {
  type Block,
  type BlockHeader,
  getBlockHash,
  computeMerkleRoot,
  encodeBip34Height,
  validateBlock,
} from "../validation/block.js";
import { type Transaction, getTxId } from "../validation/tx.js";
import { HeaderSync } from "../sync/headers.js";
import { BlockSync } from "../sync/blocks.js";

// A network with a real (non-zero) minimum chain work that the 300-block
// active chain clears after its first block (regtest work per block is 2).
const PARAMS: ConsensusParams = { ...REGTEST, nMinimumChainWork: 4n };

function mockPeer(): any {
  return {
    host: "10.0.0.9",
    port: 8333,
    state: "connected",
    versionPayload: { startHeight: 300, services: 0x409n },
    send: mock(() => true),
    addBlockInFlight: mock(() => {}),
    removeBlockInFlight: mock(() => {}),
    misbehaving: mock((_score: number, _reason: string) => {}),
    updateSyncedBlocks: mock(() => {}),
    updateSyncedHeaders: mock(() => {}),
  };
}

function mockPeerManager(peers: any[]): any {
  return {
    getConnectedPeers: () => peers,
    onMessage: () => {},
    broadcast: mock(() => {}),
    increaseBanScore: mock(() => {}),
    updateBestHeight: mock(() => {}),
  };
}

function coinbase(height: number, tag: number): Transaction {
  // Canonical BIP34 height push (Core: CScript() << nHeight), so every fixture
  // block is consensus-valid, not just its header.
  return {
    version: 1,
    inputs: [
      {
        prevOut: { txid: Buffer.alloc(32, 0), vout: 0xffffffff },
        scriptSig: Buffer.concat([encodeBip34Height(height), Buffer.from([0x01, tag & 0xff])]),
        sequence: 0xffffffff,
        witness: [],
      },
    ],
    outputs: [{ value: 5000000000n, scriptPubKey: Buffer.from([0x51]) }],
    lockTime: 0,
  };
}

function mineBlock(prev: Buffer, ts: number, height: number, tag: number): Block {
  const cb = coinbase(height, tag);
  const base: BlockHeader = {
    version: 4,
    prevBlock: prev,
    merkleRoot: computeMerkleRoot([getTxId(cb)]),
    timestamp: ts,
    bits: PARAMS.powLimitBits,
    nonce: 0,
  };
  const target = compactToBigInt(PARAMS.powLimitBits);
  for (let nonce = 0; nonce < 1_000_000; nonce++) {
    const header = { ...base, nonce };
    if (BigInt("0x" + Buffer.from(getBlockHash(header)).reverse().toString("hex")) <= target) {
      return { header, transactions: [cb] };
    }
  }
  throw new Error("could not mine block");
}

describe("cffix-hotbuns-lowwork-block-header: unrequested low-work block", () => {
  let dbPath: string;
  let db: ChainDB;
  let headerSync: HeaderSync;
  let active: Block[];
  let bs: BlockSync;

  beforeEach(async () => {
    dbPath = await mkdtemp(join(tmpdir(), "hotbuns-cffix-lowwork-"));
    db = new ChainDB(dbPath);
    await db.open();
    headerSync = new HeaderSync(db, PARAMS);
    headerSync.initGenesis();
    const genesis = headerSync.getBestHeader()!;

    // Active chain: genesis -> 1..300.
    active = [];
    let prev = genesis.hash;
    let ts = genesis.header.timestamp;
    for (let h = 1; h <= 300; h++) {
      ts += 600;
      const b = mineBlock(prev, ts, h, 1);
      active.push(b);
      prev = getBlockHash(b.header);
    }
    await headerSync.processHeaders(active.map((b) => b.header), null);
    const tip = headerSync.getBestHeader()!;
    expect(tip.height).toBe(300);
    // Past nMinimumChainWork: the old nMinimumChainWork-only gate is a no-op.
    expect(tip.chainWork > PARAMS.nMinimumChainWork).toBe(true);

    const peer = mockPeer();
    bs = new BlockSync(db, PARAMS, headerSync, mockPeerManager([peer]), {
      getBestBlock: () => ({ hash: tip.hash, height: tip.height, chainWork: tip.chainWork }),
    } as any);
    bs.getState().nextHeightToProcess = 301;
    bs.getState().nextHeightToRequest = 301;
    (bs as any).running = true;
    (bs as any).ibdComplete = true;
    (bs as any).hasCompletedInitialSync = true;
  });

  afterEach(async () => {
    await db.close();
    await rm(dbPath, { recursive: true, force: true });
  });

  test("parent 200 deep, claimed work below the anti-DoS threshold: no header, no body, no punishment", async () => {
    const parent = active[99]; // height 100, 200 below the tip
    const fork = mineBlock(getBlockHash(parent.header), parent.header.timestamp + 1, 101, 7);
    const forkHash = getBlockHash(fork.header);

    const parentEntry = headerSync.getHeader(fork.header.prevBlock)!;
    const claimed = parentEntry.chainWork + headerSync.getHeaderWork(fork.header.bits);
    const threshold = headerSync.getAntiDoSWorkThreshold();
    expect(claimed < threshold).toBe(true); // below the anti-DoS threshold
    expect(claimed >= PARAMS.nMinimumChainWork).toBe(true); // but above min chain work

    const peer = mockPeer();
    await bs.handleBlock(peer, fork);

    // Core AcceptBlockHeader: too-little-chainwork, header never indexed.
    expect(headerSync.getHeader(forkHash)).toBeUndefined();
    // AcceptBlock never reached: the body is not on disk.
    expect(await db.getBlock(forkHash)).toBeNull();
    expect((bs as any).forkBodiesOnDisk.has(forkHash.toString("hex"))).toBe(false);
    // BLOCK_HEADER_LOW_WORK is not a misbehaviour.
    expect(peer.misbehaving).not.toHaveBeenCalled();
  });

  test("control: parent inside the 144-block buffer clears the threshold and the fork body is stored", async () => {
    const parent = active[249]; // height 250, 50 below the tip
    const fork = mineBlock(getBlockHash(parent.header), parent.header.timestamp + 1, 251, 8);
    const forkHash = getBlockHash(fork.header);

    const parentEntry = headerSync.getHeader(fork.header.prevBlock)!;
    const claimed = parentEntry.chainWork + headerSync.getHeaderWork(fork.header.bits);
    expect(claimed >= headerSync.getAntiDoSWorkThreshold()).toBe(true);

    const peer = mockPeer();
    await bs.handleBlock(peer, fork);

    expect(headerSync.getHeader(forkHash)).toBeDefined();
    expect(await db.getBlock(forkHash)).not.toBeNull();
    expect(peer.misbehaving).not.toHaveBeenCalled();
  });

  test("control: an unrequested block extending the active tip is still accepted (valid block not refused)", async () => {
    const tipBlock = active[299];
    const next = mineBlock(getBlockHash(tipBlock.header), tipBlock.header.timestamp + 600, 301, 11);
    // The block itself is consensus-valid (CheckBlock + contextual checks,
    // BIP34 height included), so refusing it would be a real regression.
    const v = validateBlock(next, 301, PARAMS);
    expect(v.error).toBeUndefined();
    expect(v.valid).toBe(true);

    // The fixture has headers only (no UTXO set for the 300-block chain), so
    // spy connectBlock and assert the block reaches it, as
    // blocks.reorg-p2p.test.ts does; the UTXO connect itself is covered there.
    const connectCalls: Array<{ hashHex: string; height: number }> = [];
    (bs as any).connectBlock = async (block: Block, height: number) => {
      connectCalls.push({ hashHex: getBlockHash(block.header).toString("hex"), height });
      return true;
    };

    const peer = mockPeer();
    await bs.handleBlock(peer, next);
    const nextHex = getBlockHash(next.header).toString("hex");
    const entry = headerSync.getHeader(getBlockHash(next.header));
    expect(entry).toBeDefined();
    expect(entry!.height).toBe(301);
    expect(entry!.status).not.toBe("invalid");
    expect(connectCalls).toEqual([{ hashHex: nextHex, height: 301 }]);
    expect(bs.getState().nextHeightToProcess).toBe(302);
    expect(peer.misbehaving).not.toHaveBeenCalled();
  });

  test("processHeaders(minPowChecked=false) refuses even when chain work is above nMinimumChainWork", async () => {
    const parent = active[199];
    const fork = mineBlock(getBlockHash(parent.header), parent.header.timestamp + 1, 201, 9);
    const accepted = await headerSync.processHeaders([fork.header], null, false);
    expect(accepted).toBe(0);
    expect(headerSync.getHeader(getBlockHash(fork.header))).toBeUndefined();
  });

  test("submitblock (injectBlock) of a deep low-work fork still indexes the header: Core passes min_pow_checked=true", async () => {
    const parent = active[99];
    const fork = mineBlock(getBlockHash(parent.header), parent.header.timestamp + 1, 101, 10);
    await bs.injectBlock(fork);
    expect(headerSync.getHeader(getBlockHash(fork.header))).toBeDefined();
  });
});
