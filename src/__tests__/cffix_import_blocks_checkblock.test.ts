/**
 * `--import-blocks` must run the same header + CheckBlock + connect pipeline
 * as a block from a peer (Core LoadExternalBlockFile -> AcceptBlock ->
 * ActivateBestChain).
 *
 * Bitcoin Core: ChainstateManager::LoadExternalBlockFile (validation.cpp)
 * hands every block read from an external file to AcceptBlock, which runs
 * AcceptBlockHeader (CheckBlockHeader PoW, ContextualCheckBlockHeader
 * bad-diffbits / time / version), CheckBlock (merkle root, mutation,
 * coinbase, CheckTransaction) and ContextualCheckBlock (BIP34, witness
 * commitment, weight) before the block is stored, and only then
 * ActivateBestChain connects it.
 *
 * Before this fix hotbuns' runBlockImport deserialized each block and called
 * ChainStateManager.connectBlock directly. connectBlock is documented as
 * taking an already-validated block and runs none of those checks, so a block
 * file with a corrupted merkle root, a hash above its target, or the wrong
 * nBits advanced the tip.
 *
 * The tests drive the real CLI (`bun run src/index.ts --import-blocks=...`)
 * in a subprocess against a scratch regtest datadir, then reopen the datadir
 * and read the tip.
 */

import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { mkdtemp, rm, mkdir, writeFile } from "fs/promises";
import { tmpdir } from "os";
import { join, resolve } from "path";
import { ChainDB } from "../storage/database.js";
import { REGTEST, compactToBigInt } from "../consensus/params.js";
import {
  Block,
  BlockHeader,
  getBlockHash,
  computeMerkleRoot,
  encodeBip34Height,
  serializeBlock,
  deserializeBlock,
} from "../validation/block.js";
import { Transaction, getTxId } from "../validation/tx.js";
import { ChainStateManager } from "../chain/state.js";
import { BufferReader } from "../wire/serialization.js";

const SUBSIDY = 5_000_000_000n;
const OP_TRUE = Buffer.from([0x51]);
const ENTRY = resolve(import.meta.dir, "..", "index.ts");
const GENESIS = deserializeBlock(new BufferReader(REGTEST.genesisBlock));
const GENESIS_HASH = getBlockHash(GENESIS.header);

function coinbaseTx(height: number, tag: number): Transaction {
  return {
    version: 1,
    inputs: [
      {
        prevOut: { txid: Buffer.alloc(32, 0), vout: 0xffffffff },
        scriptSig: Buffer.concat([encodeBip34Height(height), Buffer.from([0xff, tag & 0xff])]),
        sequence: 0xffffffff,
        witness: [],
      },
    ],
    outputs: [{ value: SUBSIDY, scriptPubKey: OP_TRUE }],
    lockTime: 0,
  };
}

function hashValue(header: BlockHeader): bigint {
  return BigInt("0x" + Buffer.from(getBlockHash(header)).reverse().toString("hex"));
}

/**
 * Build a block at `height` on `prev`. `merkleRoot` overrides the header's
 * merkle root (a corrupted one), `bits` the compact target, and `badPow`
 * picks a nonce whose hash is ABOVE the target instead of below it.
 */
function mine(
  prev: Buffer,
  timestamp: number,
  height: number,
  opts: { merkleRoot?: Buffer; bits?: number; badPow?: boolean; tag?: number } = {}
): Block {
  const txs = [coinbaseTx(height, opts.tag ?? 0)];
  const bits = opts.bits ?? REGTEST.powLimitBits;
  const base: BlockHeader = {
    version: 4,
    prevBlock: prev,
    merkleRoot: opts.merkleRoot ?? computeMerkleRoot(txs.map((t) => getTxId(t))),
    timestamp,
    bits,
    nonce: 0,
  };
  const target = compactToBigInt(bits);
  for (let nonce = 0; nonce < 10_000_000; nonce++) {
    const header = { ...base, nonce };
    const ok = hashValue(header) <= target;
    if (ok !== (opts.badPow ?? false)) {
      return { header, transactions: txs };
    }
  }
  throw new Error("failed to mine regtest block");
}

/** stdin import frame: [4B height LE][4B size LE][block]. */
function frame(height: number, block: Block): Buffer {
  const raw = serializeBlock(block);
  const hdr = Buffer.alloc(8);
  hdr.writeUInt32LE(height, 0);
  hdr.writeUInt32LE(raw.length, 4);
  return Buffer.concat([hdr, raw]);
}

/** blk*.dat record: [4B magic LE][4B size LE][block]. */
function blkRecord(block: Block): Buffer {
  const raw = serializeBlock(block);
  const hdr = Buffer.alloc(8);
  hdr.writeUInt32LE(REGTEST.networkMagic, 0);
  hdr.writeUInt32LE(raw.length, 4);
  return Buffer.concat([hdr, raw]);
}

describe("--import-blocks runs header + CheckBlock + connect", () => {
  let dir: string;
  let datadir: string;

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "hotbuns-cffix-import-checkblock-"));
    datadir = join(dir, "data");
    await mkdir(datadir, { recursive: true });
  });

  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  async function runImport(importArg: string, stdin?: Buffer): Promise<string> {
    const proc = Bun.spawn(
      [
        process.execPath,
        "run",
        ENTRY,
        "--network=regtest",
        `--datadir=${datadir}`,
        `--import-blocks=${importArg}`,
      ],
      {
        stdin: stdin ? new Blob([new Uint8Array(stdin)]) : "ignore",
        stdout: "pipe",
        stderr: "pipe",
        env: { ...process.env, HOTBUNS_SUPERVISE: "0" },
      }
    );
    const timer = setTimeout(() => proc.kill(), 60_000);
    const [out, err] = await Promise.all([
      new Response(proc.stdout).text(),
      new Response(proc.stderr).text(),
    ]);
    await proc.exited;
    clearTimeout(timer);
    const log = out + err;
    // Instrument check: the import ran at all (otherwise "tip unchanged"
    // would pass vacuously).
    expect(log).toContain("Block import mode");
    return log;
  }

  async function tip(): Promise<{ height: number; hash: Buffer }> {
    const db = new ChainDB(join(datadir, "blocks.db"));
    await db.open();
    try {
      const cs = new ChainStateManager(db, REGTEST);
      await cs.load();
      const b = cs.getBestBlock();
      return { height: b.height, hash: Buffer.from(b.hash) };
    } finally {
      await db.close();
    }
  }

  const t0 = GENESIS.header.timestamp;

  test("stdin: block 1 with a corrupted merkle root is rejected, tip stays at genesis", async () => {
    const bad = mine(GENESIS_HASH, t0 + 600, 1, { merkleRoot: Buffer.alloc(32, 0xab) });
    const log = await runImport("-", frame(1, bad));
    expect((await tip()).height).toBe(0);
    expect(log).toContain("Merkle root mismatch");
  }, 90_000);

  test("stdin: block 1 whose hash is above its target is rejected high-hash, tip stays at genesis", async () => {
    const bad = mine(GENESIS_HASH, t0 + 600, 1, { badPow: true });
    const log = await runImport("-", frame(1, bad));
    expect((await tip()).height).toBe(0);
    expect(log).toContain("high-hash");
  }, 90_000);

  test("stdin: block 1 with nBits other than the required work is rejected bad-diffbits", async () => {
    // Valid PoW for its own (slightly harder) target, but regtest requires
    // powLimitBits (GetNextWorkRequired with fPowNoRetargeting).
    const bad = mine(GENESIS_HASH, t0 + 600, 1, { bits: 0x207ffffe });
    const log = await runImport("-", frame(1, bad));
    expect((await tip()).height).toBe(0);
    expect(log).toContain("bad-diffbits");
  }, 90_000);

  test("stdin: a valid block 1 framed as height 2 is refused, not connected at the wrong height", async () => {
    const b1 = mine(GENESIS_HASH, t0 + 600, 1);
    const log = await runImport("-", frame(2, b1));
    expect((await tip()).height).toBe(0);
    expect(log).toContain("height mismatch");
  }, 90_000);

  test("blk file: block 1 with a corrupted merkle root is rejected, tip stays at genesis", async () => {
    const bad = mine(GENESIS_HASH, t0 + 600, 1, { merkleRoot: Buffer.alloc(32, 0xcd) });
    const blocksDir = join(dir, "blk");
    await mkdir(blocksDir, { recursive: true });
    await writeFile(join(blocksDir, "blk00000.dat"), blkRecord(bad));
    const log = await runImport(blocksDir);
    const t = await tip();
    expect(t.height).toBe(0);
    expect(t.hash.equals(GENESIS_HASH)).toBe(true);
    expect(log).toContain("Merkle root mismatch");
  }, 90_000);

  test("control: valid blocks 1 and 2 from stdin are imported", async () => {
    const b1 = mine(GENESIS_HASH, t0 + 600, 1, { tag: 1 });
    const b2 = mine(getBlockHash(b1.header), t0 + 1200, 2, { tag: 2 });
    await runImport("-", Buffer.concat([frame(1, b1), frame(2, b2)]));
    const t = await tip();
    expect(t.height).toBe(2);
    expect(t.hash.equals(getBlockHash(b2.header))).toBe(true);
  }, 90_000);

  test("control: a valid block 1 from a blk file is imported", async () => {
    const b1 = mine(GENESIS_HASH, t0 + 600, 1, { tag: 3 });
    const blocksDir = join(dir, "blk");
    await mkdir(blocksDir, { recursive: true });
    await writeFile(join(blocksDir, "blk00000.dat"), blkRecord(b1));
    await runImport(blocksDir);
    const t = await tip();
    expect(t.height).toBe(1);
    expect(t.hash.equals(getBlockHash(b1.header))).toBe(true);
  }, 90_000);

  test("blk file: a bad-PoW block 1 is skipped and its valid sibling, then block 2, are imported", async () => {
    const bad = mine(GENESIS_HASH, t0 + 600, 1, { badPow: true, tag: 4 });
    const b1 = mine(GENESIS_HASH, t0 + 601, 1, { tag: 5 });
    const b2 = mine(getBlockHash(b1.header), t0 + 1200, 2, { tag: 6 });
    const blocksDir = join(dir, "blk");
    await mkdir(blocksDir, { recursive: true });
    // File order: the bad sibling first, and block 2 before its parent
    // (Core places out-of-order blocks by parent, not by file position).
    await writeFile(
      join(blocksDir, "blk00000.dat"),
      Buffer.concat([blkRecord(bad), blkRecord(b2), blkRecord(b1)])
    );
    const log = await runImport(blocksDir);
    expect(log).toContain("high-hash");
    const t = await tip();
    expect(t.height).toBe(2);
    expect(t.hash.equals(getBlockHash(b2.header))).toBe(true);
  }, 90_000);
});
