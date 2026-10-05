/**
 * Deterministic regtest chain for the BIP-113 / BIP-68 time-context tests
 * (mtp_wiring.test.ts, __tests__/mtp_wiring_e2e.test.ts).
 *
 * Every block pays its coinbase to P2WSH(OP_TRUE), so spends need no keys:
 * witness = [0x51]. Timestamps are T0 + 300*h, so every MTP is computable by
 * hand: MTP(h) = timestamp(h-5) for h >= 10 (median of h-10..h).
 *
 *   heights 1..101   coinbase-only
 *   height  102      FUND: spends coinbase(1) into 10 x 4.9 BTC P2WSH(OP_TRUE)
 *                    (coin height 102 -> BIP-68 coin time = MTP(101))
 *   heights 103..120 coinbase-only
 *
 * At tip 120: tipMTP = ts(115), coinMTP(FUND) = MTP(101) = ts(96);
 * difference 19*300 = 5700 s. A time-type relative lock of 11 units (5632 s)
 * is matured (Core: coinMTP + 5632 - 1 < tipMTP); 12 units (6144 s) is not.
 */
import type { Block, BlockHeader } from "../validation/block.js";
import {
  getBlockHash,
  computeMerkleRoot,
  serializeBlock,
} from "../validation/block.js";
import type { Transaction } from "../validation/tx.js";
import { getTxId, serializeTx, SEQUENCE_LOCKTIME_TYPE_FLAG } from "../validation/tx.js";
import { sha256Hash } from "../crypto/primitives.js";
import {
  buildCoinbaseTransaction,
  computeWitnessCommitmentHash,
} from "../mining/template.js";
import { checkProofOfWork } from "../consensus/pow.js";
import { REGTEST } from "../consensus/params.js";

export const OP_TRUE_SCRIPT = Buffer.from([0x51]);
export const P2WSH_OP_TRUE = Buffer.concat([
  Buffer.from([0x00, 0x20]),
  sha256Hash(OP_TRUE_SCRIPT),
]);
export const T0 = 1_700_000_000;
export const STEP = 300;
export const FUND_HEIGHT = 102;
export const BASE_TIP = 120;
export const FUND_OUT_VALUE = 490_000_000n;
export const FUND_OUTPUTS = 10;

export const tsAt = (h: number): number => T0 + STEP * h;
/** MTP of the block at height h on this chain (genesis timestamp is far lower). */
export function mtpAt(h: number, genesisTs: number): number {
  const ts: number[] = [];
  for (let i = h; i >= 0 && ts.length < 11; i--) ts.push(i === 0 ? genesisTs : tsAt(i));
  ts.sort((a, b) => a - b);
  return ts[Math.floor(ts.length / 2)];
}

export function mineBlock(
  prev: Buffer,
  height: number,
  timestamp: number,
  txs: Transaction[],
): Block {
  const hasWit = txs.some((t) => t.inputs.some((i) => i.witness.length > 0));
  const commitment = hasWit || txs.length > 0
    ? computeWitnessCommitmentHash(txs)
    : Buffer.alloc(0);
  const cb = buildCoinbaseTransaction(height, 0n, REGTEST, P2WSH_OP_TRUE, Buffer.alloc(0), commitment);
  // Fees are ignored by consensus as long as coinbase <= subsidy + fees.
  const all = [cb, ...txs];
  const header: BlockHeader = {
    version: 0x20000000,
    prevBlock: prev,
    merkleRoot: computeMerkleRoot(all.map((t) => getTxId(t))),
    timestamp,
    bits: REGTEST.powLimitBits,
    nonce: 0,
  };
  for (;;) {
    if (checkProofOfWork(getBlockHash(header), header.bits, REGTEST)) break;
    header.nonce++;
  }
  return { header, transactions: all };
}

/** Spend `prevout` (a P2WSH(OP_TRUE) coin worth `value`) to one output. */
export function spendOpTrue(
  prevTxid: Buffer,
  vout: number,
  value: bigint,
  opts: { version?: number; sequence?: number; lockTime?: number; fee?: bigint } = {},
): Transaction {
  return {
    version: opts.version ?? 2,
    inputs: [{
      prevOut: { txid: prevTxid, vout },
      scriptSig: Buffer.alloc(0),
      sequence: opts.sequence ?? 0xffffffff,
      witness: [OP_TRUE_SCRIPT],
    }],
    outputs: [{ value: value - (opts.fee ?? 10_000n), scriptPubKey: P2WSH_OP_TRUE }],
    lockTime: opts.lockTime ?? 0,
  };
}

export interface BaseChain {
  blocks: Block[]; // index i = height i+1
  fundTx: Transaction;
  tipHash: Buffer;
}

export function buildBaseChain(): BaseChain {
  const blocks: Block[] = [];
  let prev = REGTEST.genesisBlockHash;
  let fundTx: Transaction | null = null;
  for (let h = 1; h <= BASE_TIP; h++) {
    let txs: Transaction[] = [];
    if (h === FUND_HEIGHT) {
      const cb1 = blocks[0].transactions[0];
      fundTx = {
        version: 2,
        inputs: [{
          prevOut: { txid: getTxId(cb1), vout: 0 },
          scriptSig: Buffer.alloc(0),
          sequence: 0xffffffff,
          witness: [OP_TRUE_SCRIPT],
        }],
        outputs: Array.from({ length: FUND_OUTPUTS }, () => ({
          value: FUND_OUT_VALUE,
          scriptPubKey: P2WSH_OP_TRUE,
        })),
        lockTime: 0,
      };
      txs = [fundTx];
    }
    const b = mineBlock(prev, h, tsAt(h), txs);
    blocks.push(b);
    prev = getBlockHash(b.header);
  }
  return { blocks, fundTx: fundTx!, tipHash: prev };
}

/** Time-type relative lock of `units` x 512 s. */
export const timeLock = (units: number): number => (SEQUENCE_LOCKTIME_TYPE_FLAG | units) >>> 0;

/** Frame for `--import-blocks=-`: [height LE32][size LE32][block]. */
export function importFrame(height: number, block: Block): Buffer {
  const raw = serializeBlock(block);
  const hdr = Buffer.alloc(8);
  hdr.writeUInt32LE(height, 0);
  hdr.writeUInt32LE(raw.length, 4);
  return Buffer.concat([hdr, raw]);
}

export const txHex = (tx: Transaction): string => serializeTx(tx, true).toString("hex");
