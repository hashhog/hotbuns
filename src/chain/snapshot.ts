/**
 * assumeUTXO: Fast startup by loading a serialized UTXO set snapshot.
 *
 * Implements:
 * - Snapshot format: serialized UTXO set at a specific block height with content hash
 * - Dual chainstate: snapshot chainstate (active) + background chainstate (validating from genesis)
 * - Background validation: gradually syncs from genesis using cooperative scheduling
 * - loadtxoutset/dumptxoutset RPCs
 *
 * Reference: Bitcoin Core validation.cpp (ActivateSnapshot, PopulateAndValidateSnapshot)
 * and node/utxo_snapshot.cpp
 */

import { promises as fsp } from "node:fs";
import type { FileHandle } from "node:fs/promises";
import { sha256Hash } from "../crypto/primitives.js";
import { BufferWriter, BufferReader, varIntSize } from "../wire/serialization.js";
import {
  serializeTxOutCompressed,
  deserializeTxOutCompressed,
  writeVarIntCore,
  readVarIntCore,
  decompressAmount,
  decompressScript,
  getSpecialScriptSize,
  NUM_SPECIAL_SCRIPTS,
  MAX_SCRIPT_SIZE,
} from "../wire/compressor.js";
import { MuHash3072 } from "../wire/muhash.js";
import type { UTXOEntry, BatchOperation } from "../storage/database.js";
import { ChainDB, DBPrefix } from "../storage/database.js";
import type { ConsensusParams } from "../consensus/params.js";
import type { Coin, CoinsViewCache, CoinsViewDB } from "./utxo.js";
import { UTXOManager } from "./utxo.js";
import type { Block } from "../validation/block.js";
import { isCoinbase, getTxId } from "../validation/tx.js";

/**
 * Snapshot file magic bytes: 'utxo\xff'
 */
export const SNAPSHOT_MAGIC = Buffer.from([0x75, 0x74, 0x78, 0x6f, 0xff]);

/**
 * Current snapshot format version.
 */
export const SNAPSHOT_VERSION = 2;

/**
 * Batch size for loading coins (flush DB periodically to avoid OOM).
 */
const COINS_LOAD_BATCH_SIZE = 120_000;

/**
 * Maximum valid coin value (21M BTC in satoshis).
 * Mirrors Bitcoin Core's MAX_MONEY = 21_000_000 * COIN.
 */
const MAX_MONEY = 2_100_000_000_000_000n;

/**
 * Maximum valid vout index (uint32 max − 1).
 * Core's PopulateAndValidateSnapshot rejects outpoint.n >= UINT32_MAX to
 * avoid integer wrap-around in coinstats.cpp ApplyHash.
 */
const MAX_VOUT = 0xffff_ffff;

/**
 * assumeUTXO data hardcoded in chain parameters.
 */
export interface AssumeutxoData {
  /** Block height of the snapshot. */
  height: number;
  /** SHA256 hash of the serialized UTXO set (HASH_SERIALIZED). */
  hashSerialized: Buffer;
  /** Cumulative transaction count up to and including this block. */
  nChainTx: bigint;
  /** Block hash at this height. */
  blockHash: Buffer;
}

/**
 * Snapshot metadata header.
 */
export interface SnapshotMetadata {
  /** Network magic bytes (4 bytes). */
  networkMagic: number;
  /** Base block hash (32 bytes). */
  baseBlockHash: Buffer;
  /** Number of coins in the snapshot. */
  coinsCount: bigint;
}

/**
 * Result of loading a snapshot.
 */
export interface LoadSnapshotResult {
  /** Number of coins loaded. */
  coinsLoaded: bigint;
  /** Base block hash. */
  baseBlockHash: Buffer;
  /** Base block height. */
  baseHeight: number;
  /** Path to the snapshot file. */
  path: string;
}

/**
 * Result of dumping a snapshot.
 */
export interface DumpSnapshotResult {
  /** Number of coins written. */
  coinsWritten: bigint;
  /** Base block hash. */
  baseHash: string;
  /** Base block height. */
  baseHeight: number;
  /** Path to the snapshot file. */
  path: string;
  /** UTXO set hash (for verification). */
  txoutsetHash: string;
  /** Cumulative transaction count. */
  nChainTx: bigint;
}

/**
 * Chainstate status for assumeUTXO.
 */
export enum ChainstateStatus {
  /** All blocks validated from genesis (normal IBD completion). */
  VALIDATED = "validated",
  /** Snapshot-based, not yet verified by background validation. */
  UNVALIDATED = "unvalidated",
  /** Snapshot validation failed (hash mismatch). */
  INVALID = "invalid",
}

/**
 * Result of background snapshot validation.
 */
export enum SnapshotValidationResult {
  /** Snapshot validation succeeded. */
  SUCCESS = "success",
  /** Validation conditions not met yet (still syncing). */
  SKIPPED = "skipped",
  /** No assumeutxo data for height. */
  MISSING_CHAINPARAMS = "missing_chainparams",
  /** Computing UTXO hash failed. */
  STATS_FAILED = "stats_failed",
  /** Computed hash != expected hash. */
  HASH_MISMATCH = "hash_mismatch",
}

/**
 * Serialize snapshot metadata header.
 */
export function serializeSnapshotMetadata(metadata: SnapshotMetadata): Buffer {
  const writer = new BufferWriter();

  // Magic bytes
  writer.writeBytes(SNAPSHOT_MAGIC);

  // Version (uint16)
  writer.writeUInt16LE(SNAPSHOT_VERSION);

  // Network magic (4 bytes)
  writer.writeUInt32LE(metadata.networkMagic);

  // Base block hash (32 bytes)
  writer.writeHash(metadata.baseBlockHash);

  // Coins count (uint64)
  writer.writeUInt64LE(metadata.coinsCount);

  return writer.toBuffer();
}

/**
 * Deserialize snapshot metadata header.
 */
export function deserializeSnapshotMetadata(reader: BufferReader, expectedMagic: number): SnapshotMetadata {
  // Magic bytes
  const magic = reader.readBytes(5);
  if (!magic.equals(SNAPSHOT_MAGIC)) {
    throw new Error(`Invalid snapshot magic: expected ${SNAPSHOT_MAGIC.toString("hex")}, got ${magic.toString("hex")}`);
  }

  // Version
  const version = reader.readUInt16LE();
  if (version !== SNAPSHOT_VERSION) {
    throw new Error(`Unsupported snapshot version: expected ${SNAPSHOT_VERSION}, got ${version}`);
  }

  // Network magic
  const networkMagic = reader.readUInt32LE();
  if (networkMagic !== expectedMagic) {
    throw new Error(`Network magic mismatch: expected ${expectedMagic.toString(16)}, got ${networkMagic.toString(16)}`);
  }

  // Base block hash
  const baseBlockHash = reader.readHash();

  // Coins count
  const coinsCount = reader.readUInt64LE();

  return {
    networkMagic,
    baseBlockHash,
    coinsCount,
  };
}

/**
 * Serialize a coin for snapshot storage in Bitcoin Core's wire-compatible
 * format (Coin::Serialize from src/coins.h):
 *
 *   VARINT(nHeight * 2 + fCoinBase) || TxOutCompression
 *
 * Where TxOutCompression =
 *   VARINT(CompressAmount(value)) || ScriptCompression(scriptPubKey)
 *
 * VARINT here is Pieter's variable-length encoding (NOT wire-protocol
 * CompactSize). See src/wire/compressor.ts.
 */
export function serializeCoinForSnapshot(coin: Coin): Buffer {
  const writer = new BufferWriter();

  // VARINT(code): height * 2 + fCoinBase.
  const code = BigInt(coin.height) * 2n + (coin.isCoinbase ? 1n : 0n);
  writeVarIntCore(writer, code);

  // TxOutCompression: compressed value + compressed script.
  serializeTxOutCompressed(writer, coin.txOut.value, coin.txOut.scriptPubKey);

  return writer.toBuffer();
}

/**
 * Serialize a coin into an existing BufferWriter (avoids allocating an
 * intermediate Buffer per coin during the dump fast-path).
 */
export function serializeCoinIntoWriter(writer: BufferWriter, coin: Coin): void {
  const code = BigInt(coin.height) * 2n + (coin.isCoinbase ? 1n : 0n);
  writeVarIntCore(writer, code);
  serializeTxOutCompressed(writer, coin.txOut.value, coin.txOut.scriptPubKey);
}

/**
 * Deserialize a coin from snapshot storage (Coin::Unserialize equivalent).
 *
 * Reads VARINT(code) || TxOutCompression and reconstructs height,
 * isCoinbase, and the original (decompressed) txOut.
 */
export function deserializeCoinFromSnapshot(reader: BufferReader): Coin {
  const codeBig = readVarIntCore(reader);
  // Height fits in 31 bits in Core; safe as a JS number.
  const height = Number(codeBig >> 1n);
  const isCoinbase = (codeBig & 1n) === 1n;

  const { value, scriptPubKey } = deserializeTxOutCompressed(reader);

  return {
    txOut: { value, scriptPubKey },
    height,
    isCoinbase,
  };
}

/**
 * Build the per-coin TxOutSer bytes that feed the UTXO-set hash.
 *
 * Layout, mirroring kernel/coinstats.cpp `TxOutSer`:
 *
 *   COutPoint  = txid (32 LE) || vout (uint32 LE)
 *   uint32     = (height << 1) + coinbase
 *   CTxOut     = int64 nValue (LE) || CScript (CompactSize len || bytes)
 *
 * Shared by `computeUTXOSetHash` (HASH_SERIALIZED, SHA256d via HashWriter)
 * and `computeUTXOSetMuHash` (MUHASH, used by gettxoutsetinfo only); both
 * hash types ingest the same canonical per-coin bytes — the difference is
 * only how the bytes are folded into a digest.
 */
function txOutSerBytes(
  txid: Buffer,
  vout: number,
  height: number,
  coinbase: boolean,
  amount: bigint,
  scriptPubKey: Buffer
): Buffer {
  const writer = new BufferWriter();
  writer.writeHash(txid);
  writer.writeUInt32LE(vout);
  writer.writeUInt32LE(((height << 1) + (coinbase ? 1 : 0)) >>> 0);
  writer.writeUInt64LE(amount);
  writer.writeVarBytes(scriptPubKey);
  return writer.toBuffer();
}

/**
 * Compute the UTXO set hash (HASH_SERIALIZED), Bitcoin Core compatible.
 *
 * Mirrors `kernel/coinstats.cpp::ApplyCoinHash(HashWriter&, ...)` +
 * `ComputeUTXOStats(... CoinStatsHashType::HASH_SERIALIZED ...)` at
 * `kernel/coinstats.cpp:161-163`:
 *
 *   HashWriter ss{};
 *   for each (outpoint, coin) in db iteration order:
 *     ss << outpoint                              // 32-byte txid + uint32 vout
 *     ss << uint32((coin.nHeight << 1) + coin.fCoinBase)
 *     ss << coin.out                              // int64 nValue + CScript
 *   return ss.GetHash();                          // double-SHA256
 *
 * Note: Core's `HashWriter::GetHash()` finalizes a SHA-256 then re-hashes
 * the digest (double-SHA256, see `hash.h`). The streaming `Bun.CryptoHasher`
 * below already produces the inner SHA-256 of the byte stream, so we apply
 * exactly ONE more SHA-256 (`sha256Hash`) — NOT `hash256()`, which would
 * cascade two more SHA-256s and yield triple-SHA256.
 *
 * **This is the function that backs the assumeutxo strict gate**
 * (`validation.cpp:5902-5914` calls `ComputeUTXOStats` with
 * `CoinStatsHashType::HASH_SERIALIZED`, then compares against
 * `m_assumeutxo_data.hash_serialized`). The four hardcoded mainnet hex
 * strings (`a2a5521b...` at 840k, `dbd19098...` at 880k, `4daf8a17...` at
 * 910k, `e4b90ef9...` at 935k) in `consensus/params.ts` are HASH_SERIALIZED
 * (SHA256d-via-HashWriter) outputs, NOT MuHash3072 outputs.
 *
 * MuHash3072 is reserved for `gettxoutsetinfo hash_type=muhash` (see
 * `computeUTXOSetMuHash`); it is NOT what assumeutxo commits to.
 *
 * Warning (verbatim from kernel/coinstats.cpp): "be very careful when
 * changing this!" — the assumeutxo commitment depends on this exact
 * byte layout (see `txOutSerBytes`).
 */
export async function computeUTXOSetHash(
  db: ChainDB,
  interruptCheck?: () => boolean
): Promise<{ hash: Buffer; coinsCount: bigint }> {
  // Single-SHA256 streaming; finalize once, then hash the digest a second
  // time to match Core's HashWriter::GetHash (double-SHA256).
  const hasher = new Bun.CryptoHasher("sha256");

  let coinsCount = 0n;

  const utxoPrefix = Buffer.from([DBPrefix.UTXO]);
  const iterator = (db as any).db.iterator({
    gte: utxoPrefix,
    lt: Buffer.concat([Buffer.from([DBPrefix.UTXO + 1])]),
  });

  // CRITICAL ORDERING FIX: Core uses `std::map<uint32_t, Coin>`
  // (kernel/coinstats.cpp:122-128) which iterates vouts in NUMERIC order
  // for each txid. LevelDB iterates by byte-lex on the
  // [prefix=0x75][txid 32B][vout uint32_LE] key, so within a txid the
  // vouts come out in LE-byte order, which differs from numeric order
  // for any vout >= 256 (e.g. numeric [0,1,256,257] arrives as
  // [0,1,0,0,0,0,0,1,0,0,0,1,0,0,0,1,1,0,0,0]). On mainnet at h=940k,
  // 183,859 of 114M txids have at least one vout >= 256 (max 13,106),
  // and the resulting digest diverges from Core's HASH_SERIALIZED by
  // exactly the per-txid permutation. Fix: buffer all coins for a txid
  // group, sort numerically by vout, then ingest.
  let prevTxid: Buffer | null = null;
  let group: Array<{
    vout: number;
    height: number;
    coinbase: boolean;
    amount: bigint;
    scriptPubKey: Buffer;
  }> = [];

  const flush = () => {
    if (!prevTxid || group.length === 0) return;
    if (group.length > 1) {
      group.sort((a, b) => a.vout - b.vout);
    }
    for (const c of group) {
      hasher.update(
        txOutSerBytes(prevTxid, c.vout, c.height, c.coinbase, c.amount, c.scriptPubKey),
      );
    }
    group = [];
  };

  try {
    for await (const [key, value] of iterator) {
      if (interruptCheck?.()) {
        throw new Error("Interrupted");
      }

      // Key format: prefix (1 byte) + txid (32 bytes) + vout (4 bytes LE).
      if (key.length !== 37) continue;

      const txid = key.subarray(1, 33);
      const vout = key.readUInt32LE(33);

      // Deserialize the UTXO entry stored locally.
      const reader = new BufferReader(value);
      const height = reader.readUInt32LE();
      const coinbase = reader.readUInt8() === 1;
      const amount = reader.readUInt64LE();
      const scriptPubKey = reader.readVarBytes();

      if (!prevTxid || !txid.equals(prevTxid)) {
        flush();
        // The iterator key buffer may be reused on the next iteration —
        // copy the txid so the group stays valid until we flush.
        prevTxid = Buffer.from(txid);
      }
      group.push({ vout, height, coinbase, amount, scriptPubKey });
      coinsCount++;
    }
    flush();
  } finally {
    await iterator.close();
  }

  // Core's HashWriter::GetHash() = SHA256(SHA256(stream)). The streaming
  // hasher above produces the inner SHA256(stream); apply ONE more SHA256
  // to get the full double-SHA256 — using `hash256()` here would chain
  // two more SHA256s for a triple-SHA256, which is what previously made
  // computeUTXOSetHash diverge from `compute-snapshot-hash.py` and Core's
  // chainparams hash_serialized constants on the full mainnet UTXO set.
  // Empirically: SHA256(<correct double-SHA256 a888bcbc...>)
  // = 2075205e71f087f76533a3f108b66e22e2de42cdc8a44f5b1601c7b314c66097,
  // exactly the wrong digest hotbuns produced before this line was fixed.
  const inner = Buffer.from(hasher.digest());
  const hash = sha256Hash(inner);

  return { hash, coinsCount };
}

/**
 * Compute the UTXO set hash using MuHash3072 (CoinStatsHashType::MUHASH).
 *
 * Mirrors `kernel/coinstats.cpp::ApplyCoinHash(MuHash3072&, ...)` +
 * `ComputeUTXOStats(... CoinStatsHashType::MUHASH ...)`:
 *
 *   MuHash3072 muhash;
 *   for each (outpoint, coin) in db iteration order:
 *     DataStream ss; TxOutSer(ss, outpoint, coin); muhash.Insert(ss);
 *   muhash.Finalize(out);                         // SHA256(LE_384(num/den))
 *
 * MuHash is order-independent (multiset hash over a 3072-bit prime field).
 *
 * Used by `gettxoutsetinfo hash_type=muhash` ONLY. The assumeutxo strict
 * gate uses `computeUTXOSetHash` (HASH_SERIALIZED) instead — see
 * `validation.cpp:5902` (`CoinStatsHashType::HASH_SERIALIZED`).
 */
export async function computeUTXOSetMuHash(
  db: ChainDB,
  interruptCheck?: () => boolean
): Promise<{ hash: Buffer; coinsCount: bigint }> {
  const acc = new MuHash3072();

  let coinsCount = 0n;

  const utxoPrefix = Buffer.from([DBPrefix.UTXO]);
  const iterator = (db as any).db.iterator({
    gte: utxoPrefix,
    lt: Buffer.concat([Buffer.from([DBPrefix.UTXO + 1])]),
  });

  // MuHash is order-invariant by math (multiset hash over a 3072-bit prime
  // field), so this grouping is not strictly required for digest equality.
  // We apply it anyway for parity with Core's `gettxoutsetinfo
  // hash_type=muhash` ingestion order — same per-txid sort as
  // `computeUTXOSetHash`, since both functions consume the same DB iterator.
  let prevTxid: Buffer | null = null;
  let group: Array<{
    vout: number;
    height: number;
    coinbase: boolean;
    amount: bigint;
    scriptPubKey: Buffer;
  }> = [];

  const flush = () => {
    if (!prevTxid || group.length === 0) return;
    if (group.length > 1) {
      group.sort((a, b) => a.vout - b.vout);
    }
    for (const c of group) {
      acc.add(
        txOutSerBytes(prevTxid, c.vout, c.height, c.coinbase, c.amount, c.scriptPubKey),
      );
    }
    group = [];
  };

  try {
    for await (const [key, value] of iterator) {
      if (interruptCheck?.()) {
        throw new Error("Interrupted");
      }

      // Key format: prefix (1 byte) + txid (32 bytes) + vout (4 bytes LE).
      if (key.length !== 37) continue;

      const txid = key.subarray(1, 33);
      const vout = key.readUInt32LE(33);

      const reader = new BufferReader(value);
      const height = reader.readUInt32LE();
      const coinbase = reader.readUInt8() === 1;
      const amount = reader.readUInt64LE();
      const scriptPubKey = reader.readVarBytes();

      if (!prevTxid || !txid.equals(prevTxid)) {
        flush();
        prevTxid = Buffer.from(txid);
      }
      group.push({ vout, height, coinbase, amount, scriptPubKey });
      coinsCount++;
    }
    flush();
  } finally {
    await iterator.close();
  }

  // SHA256(LE_384(num/den)) -> 32-byte digest.
  const hash = acc.finalize();

  return { hash, coinsCount };
}

/**
 * Database-independent UTXO "bogosize" of one coin, byte-for-byte mirroring
 * `kernel/coinstats.cpp::GetBogoSize`:
 *
 *   32  txid
 * +  4  vout index
 * +  4  height + coinbase
 * +  8  amount
 * +  2  scriptPubKey length field (Core uses a fixed 2, NOT the CompactSize len)
 * +  scriptPubKey.size()
 *
 * The metric is intentionally "meaningless" (Core's own wording) — it is a
 * database-independent proxy for UTXO-set size, so it must be computed with
 * Core's exact constants to match `gettxoutsetinfo`'s `bogosize` field.
 */
function getBogoSize(scriptPubKeyLen: number): bigint {
  return 32n + 4n + 4n + 8n + 2n + BigInt(scriptPubKeyLen);
}

/**
 * Full `gettxoutsetinfo` statistics over the chainstate UTXO set in ONE pass.
 *
 * Mirrors `kernel/coinstats.cpp::ComputeUTXOStats` +
 * `ApplyStats` (coinstats.cpp:96-107): a single coin-cursor walk that
 * simultaneously accumulates
 *
 *   - nTransactionOutputs (`txouts`)  — one per coin,
 *   - nTransactions (`transactions`)  — one per distinct txid group,
 *   - nBogoSize (`bogosize`)          — sum of per-coin `GetBogoSize`,
 *   - total_amount                    — sum of all unspent output values,
 *   - the set hash for `hash_type`    — HASH_SERIALIZED (default), MUHASH,
 *                                       or NONE (no hash).
 *
 * Coin-cursor order parity: Core iterates `std::map<uint32_t, Coin>` so within
 * a txid the vouts are numerically ordered; LevelDB hands them back in
 * LE-byte order on the [prefix][txid][vout-u32-LE] key, which differs for any
 * vout >= 256. We buffer each txid group and sort numerically before ingest —
 * identical to the fix already proven in `computeUTXOSetHash`. The grouping is
 * also what lets us count distinct-txid `transactions` correctly.
 *
 * For HASH_SERIALIZED the digest is `HashWriter::GetHash()` = SHA256(SHA256(
 * stream)); the streaming hasher produces the inner SHA256, so ONE more SHA256
 * finalizes the double-SHA256 (see `computeUTXOSetHash` for the cautionary
 * note about not using `hash256()` here). For MUHASH the digest is the
 * order-independent MuHash3072 finalize.
 */
export type UTXOSetHashType = "hash_serialized_3" | "muhash" | "none";

export interface UTXOSetStats {
  /** Number of unspent transaction outputs (`txouts`). */
  txouts: bigint;
  /** Number of distinct txids with at least one unspent output (`transactions`). */
  transactions: bigint;
  /** Database-independent UTXO-set-size proxy (`bogosize`). */
  bogosize: bigint;
  /** Sum of all unspent output values, in satoshis. */
  totalAmount: bigint;
  /**
   * 32-byte set hash for the requested `hashType`, or null when
   * `hashType === "none"`. Returned in INTERNAL byte order (the caller
   * reverses for hex display, matching Core's `uint256::GetHex`).
   */
  hash: Buffer | null;
}

export async function computeUTXOSetStats(
  db: ChainDB,
  hashType: UTXOSetHashType,
  interruptCheck?: () => boolean,
): Promise<UTXOSetStats> {
  // Hash accumulators — only the one for `hashType` is fed.
  const hasher =
    hashType === "hash_serialized_3" ? new Bun.CryptoHasher("sha256") : null;
  const muhash = hashType === "muhash" ? new MuHash3072() : null;

  let txouts = 0n;
  let transactions = 0n;
  let bogosize = 0n;
  let totalAmount = 0n;

  const utxoPrefix = Buffer.from([DBPrefix.UTXO]);
  const iterator = (db as any).db.iterator({
    gte: utxoPrefix,
    lt: Buffer.concat([Buffer.from([DBPrefix.UTXO + 1])]),
  });

  let prevTxid: Buffer | null = null;
  let group: Array<{
    vout: number;
    height: number;
    coinbase: boolean;
    amount: bigint;
    scriptPubKey: Buffer;
  }> = [];

  // Ingest one finished txid group: count it as one transaction, and for each
  // coin (vouts sorted numerically) update stats + feed the chosen hash.
  const flush = () => {
    if (!prevTxid || group.length === 0) return;
    transactions++;
    if (group.length > 1) {
      group.sort((a, b) => a.vout - b.vout);
    }
    for (const c of group) {
      txouts++;
      totalAmount += c.amount;
      bogosize += getBogoSize(c.scriptPubKey.length);
      if (hasher || muhash) {
        const bytes = txOutSerBytes(
          prevTxid,
          c.vout,
          c.height,
          c.coinbase,
          c.amount,
          c.scriptPubKey,
        );
        if (hasher) hasher.update(bytes);
        if (muhash) muhash.add(bytes);
      }
    }
    group = [];
  };

  try {
    for await (const [key, value] of iterator) {
      if (interruptCheck?.()) {
        throw new Error("Interrupted");
      }
      // Key format: prefix (1) + txid (32) + vout (4 LE).
      if (key.length !== 37) continue;

      const txid = key.subarray(1, 33);
      const vout = key.readUInt32LE(33);

      const reader = new BufferReader(value);
      const height = reader.readUInt32LE();
      const coinbase = reader.readUInt8() === 1;
      const amount = reader.readUInt64LE();
      const scriptPubKey = reader.readVarBytes();

      if (!prevTxid || !txid.equals(prevTxid)) {
        flush();
        // The iterator key buffer may be reused — copy the txid.
        prevTxid = Buffer.from(txid);
      }
      group.push({ vout, height, coinbase, amount, scriptPubKey });
    }
    flush();
  } finally {
    await iterator.close();
  }

  let hash: Buffer | null = null;
  if (hasher) {
    // SHA256(SHA256(stream)) — one more SHA256 over the streamed inner digest.
    hash = sha256Hash(Buffer.from(hasher.digest()));
  } else if (muhash) {
    hash = muhash.finalize();
  }

  return { txouts, transactions, bogosize, totalAmount, hash };
}

/**
 * Chainstate wrapper for assumeUTXO.
 *
 * Manages the dual chainstate model:
 * - Snapshot chainstate: validates from snapshot forward
 * - Background chainstate: validates from genesis to snapshot
 */
export class Chainstate {
  readonly db: ChainDB;
  readonly params: ConsensusParams;
  readonly utxoManager: UTXOManager;

  /** Status of this chainstate. */
  status: ChainstateStatus;

  /** If this is a snapshot chainstate, the base block hash. */
  snapshotBaseBlockHash: Buffer | null;

  /** Current chain tip hash. */
  tipHash: Buffer;

  /** Current chain tip height. */
  tipHeight: number;

  /** If this is a background chainstate, the target block hash. */
  targetBlockHash: Buffer | null;

  constructor(
    db: ChainDB,
    params: ConsensusParams,
    options?: {
      snapshotBaseBlockHash?: Buffer;
      status?: ChainstateStatus;
      maxCacheBytes?: number;
    }
  ) {
    this.db = db;
    this.params = params;
    this.utxoManager = new UTXOManager(db, options?.maxCacheBytes);
    this.status = options?.status ?? ChainstateStatus.VALIDATED;
    this.snapshotBaseBlockHash = options?.snapshotBaseBlockHash ?? null;
    this.tipHash = params.genesisBlockHash;
    this.tipHeight = 0;
    this.targetBlockHash = null;
  }

  /**
   * Check if this chainstate is based on a snapshot.
   */
  isSnapshot(): boolean {
    return this.snapshotBaseBlockHash !== null;
  }

  /**
   * Check if this is the background validation chainstate.
   */
  isBackground(): boolean {
    return this.targetBlockHash !== null;
  }

  /**
   * Check if background validation has reached the target.
   */
  hasReachedTarget(): boolean {
    if (!this.targetBlockHash) return false;
    return this.tipHash.equals(this.targetBlockHash);
  }

  /**
   * Flush UTXO changes to database.
   */
  async flush(): Promise<void> {
    await this.utxoManager.flush();
  }
}

/**
 * Streaming snapshot file reader.
 *
 * Reason for existing: V8 / Bun's `Buffer.alloc` and `arrayBuffer()` are
 * capped at 4 GiB (TypedArray-spec limit on `Buffer`/`Uint8Array`), so the
 * old `Buffer.from(await Bun.file(p).arrayBuffer())` path silently dies on
 * any mainnet `dumptxoutset` ≥ 4 GiB. Mainnet UTXO snapshots are ~9 GiB
 * (165M coins post-h=940k), so loading the whole file at once is no
 * longer viable on this runtime.
 *
 * This class holds a sliding 8 MiB window backed by a `node:fs` FileHandle
 * and exposes the subset of `BufferReader`'s API that loadSnapshot uses
 * (`readBytes`, `readUInt8/16/32LE`, `readUInt64LE`, `readVarInt`,
 * `readVarIntBig`, `readVarBytes`, `readHash`). Reads are advanced by
 * sliding the window forward; refill happens lazily when the next read
 * would underrun. `readBytes` always returns an owned copy so callers
 * cannot retain views into a buffer that the next refill will overwrite.
 *
 * Not exported: only loadSnapshot needs this codepath. Other consumers of
 * snapshot.ts call deserializeSnapshotMetadata with a small in-memory
 * Buffer and are unaffected.
 */
class StreamingBufferReader {
  private fh: FileHandle;
  private fileSize: number;
  private filePos: number;       // next byte in file to read into the window
  private window: Buffer;        // refill buffer
  private windowEnd: number;     // valid bytes [0, windowEnd) inside window
  private windowOff: number;     // next read offset within window
  private bytesConsumed: number; // total bytes returned to caller (== file pos of windowOff)
  private static readonly WINDOW_BYTES = 8 * 1024 * 1024;

  constructor(fh: FileHandle, fileSize: number) {
    this.fh = fh;
    this.fileSize = fileSize;
    this.filePos = 0;
    this.window = Buffer.alloc(StreamingBufferReader.WINDOW_BYTES);
    this.windowEnd = 0;
    this.windowOff = 0;
    this.bytesConsumed = 0;
  }

  get position(): number {
    return this.bytesConsumed;
  }

  /**
   * Returns true when the entire file has been consumed (no trailing bytes).
   */
  isEOF(): boolean {
    return (
      this.filePos >= this.fileSize &&
      this.windowOff >= this.windowEnd
    );
  }

  /**
   * Ensure at least `n` bytes are available starting at windowOff. Compacts
   * the unread tail to position 0 then refills from disk.
   */
  async ensure(n: number): Promise<void> {
    if (n > this.window.length) {
      // A single coin entry is bounded (script ≤ ~10kB, etc.); 8 MiB is
      // plenty. If n grows beyond the window, that's a malformed snapshot.
      throw new Error(
        `StreamingBufferReader: requested ${n} bytes exceeds window ${this.window.length}`
      );
    }
    if (this.windowEnd - this.windowOff >= n) return;
    // Compact remaining tail to start of window.
    const tailLen = this.windowEnd - this.windowOff;
    if (tailLen > 0 && this.windowOff > 0) {
      this.window.copy(this.window, 0, this.windowOff, this.windowEnd);
    }
    this.windowEnd = tailLen;
    this.windowOff = 0;
    // Fill from file.
    while (this.windowEnd < n && this.filePos < this.fileSize) {
      const want = Math.min(
        this.window.length - this.windowEnd,
        this.fileSize - this.filePos,
      );
      const { bytesRead } = await this.fh.read(
        this.window,
        this.windowEnd,
        want,
        this.filePos,
      );
      if (bytesRead === 0) break;
      this.windowEnd += bytesRead;
      this.filePos += bytesRead;
    }
    if (this.windowEnd - this.windowOff < n) {
      throw new Error(
        `StreamingBufferReader: underrun — wanted ${n} bytes but only ` +
          `${this.windowEnd - this.windowOff} available (file pos ` +
          `${this.bytesConsumed + this.windowOff}, file size ${this.fileSize})`
      );
    }
  }

  async readUInt8(): Promise<number> {
    await this.ensure(1);
    const v = this.window.readUInt8(this.windowOff);
    this.windowOff += 1;
    this.bytesConsumed += 1;
    return v;
  }

  async readUInt16LE(): Promise<number> {
    await this.ensure(2);
    const v = this.window.readUInt16LE(this.windowOff);
    this.windowOff += 2;
    this.bytesConsumed += 2;
    return v;
  }

  async readUInt32LE(): Promise<number> {
    await this.ensure(4);
    const v = this.window.readUInt32LE(this.windowOff);
    this.windowOff += 4;
    this.bytesConsumed += 4;
    return v;
  }

  async readUInt64LE(): Promise<bigint> {
    await this.ensure(8);
    const v = this.window.readBigUInt64LE(this.windowOff);
    this.windowOff += 8;
    this.bytesConsumed += 8;
    return v;
  }

  async readBytes(n: number): Promise<Buffer> {
    await this.ensure(n);
    // Copy: caller may retain references across subsequent reads which slide
    // the window and overwrite the underlying memory.
    const out = Buffer.from(this.window.subarray(this.windowOff, this.windowOff + n));
    this.windowOff += n;
    this.bytesConsumed += n;
    return out;
  }

  async readHash(): Promise<Buffer> {
    return this.readBytes(32);
  }

  async readVarIntBig(): Promise<bigint> {
    const first = await this.readUInt8();
    if (first <= 0xfc) return BigInt(first);
    if (first === 0xfd) return BigInt(await this.readUInt16LE());
    if (first === 0xfe) return BigInt(await this.readUInt32LE());
    return await this.readUInt64LE();
  }

  async readVarInt(): Promise<number> {
    const v = await this.readVarIntBig();
    if (v > BigInt(Number.MAX_SAFE_INTEGER)) {
      throw new Error("readVarInt: value exceeds Number.MAX_SAFE_INTEGER");
    }
    return Number(v);
  }

  async readVarBytes(): Promise<Buffer> {
    const len = await this.readVarInt();
    return this.readBytes(len);
  }

  /**
   * Read Bitcoin Core's per-byte VARINT (NOT CompactSize). Mirrors
   * wire/compressor.ts:readVarIntCore but driven by this stream.
   */
  async readVarIntCore(): Promise<bigint> {
    let n = 0n;
    while (true) {
      const ch = await this.readUInt8();
      n = (n << 7n) | BigInt(ch & 0x7f);
      if ((ch & 0x80) === 0) return n;
      n += 1n;
    }
  }
}

/**
 * ChainstateManager manages dual chainstates for assumeUTXO.
 */
export class ChainstateManager {
  private params: ConsensusParams;
  private db: ChainDB;

  /** The active chainstate (either IBD or snapshot). */
  private activeChainstate: Chainstate;

  /** The background chainstate (validates from genesis). */
  private backgroundChainstate: Chainstate | null = null;

  /**
   * The REAL background validator (owns a SEPARATE ChainDB) wired up at snapshot
   * activation. Distinct from `backgroundChainstate` (a lightweight marker kept
   * for the legacy progress fields). This is the genesis->base re-validation
   * with its own coins store — Core's background chainstate from AddChainstate.
   */
  private backgroundValidator: BackgroundValidator | null = null;

  /** Cached terminal verdict of the background pass (drives getStatus). */
  private backgroundVerdict: SnapshotValidationResult | null = null;

  /** Whether background validation is running. */
  private backgroundValidationRunning = false;

  /** Callback for background validation progress. */
  onBackgroundProgress?: (height: number, targetHeight: number) => void;

  /** Cache budget propagated to every Chainstate this manager creates. */
  private maxCacheBytes?: number;

  /**
   * Filesystem path where the background chainstate's SEPARATE coins store is
   * opened. Must be a DIFFERENT path than the active `db`'s. Defaults under
   * `<active-db-path>-bgvalidate` when not given explicitly.
   */
  private bgDataDir?: string;

  constructor(db: ChainDB, params: ConsensusParams, maxCacheBytes?: number, bgDataDir?: string) {
    this.db = db;
    this.params = params;
    this.maxCacheBytes = maxCacheBytes;
    this.bgDataDir = bgDataDir;
    this.activeChainstate = new Chainstate(db, params, { maxCacheBytes });
  }

  /**
   * Set the on-disk directory for the background chainstate's SEPARATE coins
   * store (used by {@link startBackgroundValidation}). Must NOT be the active
   * db's path.
   */
  setBackgroundDataDir(dir: string): void {
    this.bgDataDir = dir;
  }

  /**
   * Get the current active chainstate.
   */
  current(): Chainstate {
    return this.activeChainstate;
  }

  /**
   * Get the background chainstate (if any).
   */
  background(): Chainstate | null {
    return this.backgroundChainstate;
  }

  /**
   * Load a UTXO snapshot from a file and activate it.
   */
  async loadSnapshot(
    filePath: string,
    interruptCheck?: () => boolean
  ): Promise<LoadSnapshotResult> {
    // BUG-5: double-activation guard.
    // Mirrors validation.cpp:5600 — "Can't activate a snapshot-based
    // chainstate more than once".
    if (this.activeChainstate.isSnapshot()) {
      throw new Error("Can't activate a snapshot-based chainstate more than once");
    }

    // BUG-6: work-vs-active-tip check.
    // Mirrors validation.cpp:5787-5789 — "Work does not exceed active
    // chainstate". We approximate chained-work comparison using height: the
    // snapshot height must be strictly greater than the current active tip
    // height so loading a stale snapshot is rejected.
    // Note: Core performs this check again at activation time inside
    // ActivateSnapshot() after PopulateAndValidateSnapshot succeeds.
    const activeTipHeight = this.activeChainstate.tipHeight;

    let stat;
    try {
      stat = await fsp.stat(filePath);
    } catch {
      throw new Error(`Snapshot file not found: ${filePath}`);
    }

    // Stream the file via node:fs FileHandle. The previous implementation
    // tried `Buffer.from(await Bun.file(p).arrayBuffer())`, but `Buffer`
    // (and the underlying TypedArray) caps at 4 GiB on V8/Bun, so any
    // mainnet snapshot ≥4 GiB silently killed the process. Mainnet UTXO
    // dumps are ~9 GiB at h ≥940k, so we must stream.
    const fh = await fsp.open(filePath, "r");
    let coinsLoaded = 0n;
    let metadata: SnapshotMetadata;
    // null only on the HASHHOG_UNSAFE_SNAPSHOT_HEIGHT development bypass below,
    // where there is no chainparams entry (and so no hardcoded commitment).
    let auData: AssumeutxoData | null;
    let baseHeight: number;
    let snapshotChainstate: Chainstate;
    try {
      const stream = new StreamingBufferReader(fh, stat.size);

      // Parse metadata (51 bytes).
      const headerLen = SNAPSHOT_MAGIC.length + 2 + 4 + 32 + 8;
      const headerBuf = await stream.readBytes(headerLen);
      metadata = deserializeSnapshotMetadata(
        new BufferReader(headerBuf),
        this.params.networkMagic,
      );

      // Validate against assumeutxo parameters.
      //
      // HASHHOG_UNSAFE_SNAPSHOT_HEIGHT: development-only escape from the
      // chainparams assumeutxo whitelist. Core (and this node by default)
      // only accepts snapshots whose base blockhash is a hardcoded trust
      // anchor, because loadtxoutset is a trust shortcut for end users.
      // Setting this variable to the snapshot's base height accepts ANY
      // snapshot and takes that height on faith -- it exists so the fleet can
      // validate arbitrary block ranges in parallel from a locally generated
      // snapshot ladder, where correctness is established by checking the
      // range's OUTPUT utxo hash against an independent commitment, not by
      // trusting the input. ONLY whitelist membership and the associated
      // hardcoded hash_serialized comparison are bypassed; every other check
      // (magic, version, network, coin count, per-coin parse, MoneyRange,
      // vout/height bounds, trailing bytes) still runs.
      // Unset (the default, and what ships) = unchanged Core-equivalent
      // behaviour. Read through `process.env` at call time so it works under
      // both `bun run src/index.ts` and the bundled `node src/index.js`.
      const unsafeHeightEnv = process.env.HASHHOG_UNSAFE_SNAPSHOT_HEIGHT;
      const lookup = getAssumeutxoData(this.params, metadata.baseBlockHash);
      if (!lookup && !unsafeHeightEnv) {
        throw new Error(
          `No assumeutxo data for block ${metadata.baseBlockHash.toString("hex")}`,
        );
      }
      if (lookup) {
        auData = lookup;
        baseHeight = lookup.height;
      } else {
        const parsedHeight = Number(unsafeHeightEnv);
        if (!Number.isInteger(parsedHeight) || parsedHeight < 0) {
          throw new Error(
            `HASHHOG_UNSAFE_SNAPSHOT_HEIGHT=${unsafeHeightEnv} is not a valid block height`,
          );
        }
        auData = null;
        baseHeight = parsedHeight;
        console.warn(
          `WARNING: HASHHOG_UNSAFE_SNAPSHOT_HEIGHT=${parsedHeight} -- accepting an ` +
            `UNVERIFIED snapshot whose base blockhash ` +
            `${Buffer.from(metadata.baseBlockHash).reverse().toString("hex")} is NOT a ` +
            `chainparams trust anchor. The hardcoded hash_serialized comparison is ` +
            `SKIPPED and the base height is taken from the environment on faith. ` +
            `Development use only; never enable this in production.`,
        );
      }

      // BUG-6: work-vs-active-tip height guard (continued from precondition
      // above). Reject if the snapshot base height does not strictly exceed
      // the current active tip; a stale snapshot would regress the chain.
      if (baseHeight <= activeTipHeight) {
        throw new Error("Work does not exceed active chainstate");
      }

      // Create snapshot chainstate.
      snapshotChainstate = new Chainstate(this.db, this.params, {
        snapshotBaseBlockHash: metadata.baseBlockHash,
        status: ChainstateStatus.UNVALIDATED,
        maxCacheBytes: this.maxCacheBytes,
      });
      snapshotChainstate.tipHash = metadata.baseBlockHash;
      snapshotChainstate.tipHeight = baseHeight;

      const batchOps: BatchOperation[] = [];

      while (coinsLoaded < metadata.coinsCount) {
        if (interruptCheck?.()) {
          throw new Error("Interrupted");
        }

        // Read transaction ID.
        const txid = await stream.readHash();

        // Read number of outputs for this transaction (CompactSize).
        const numOutputs = await stream.readVarInt();

        // BUG-1: per-txid overflow guard.
        // Mirrors validation.cpp:5804-5806 — coins_per_txid > coins_left
        // means the file claims more coins for this txid than the header
        // declared in total, which indicates corrupt snapshot data.
        if (BigInt(numOutputs) > metadata.coinsCount - coinsLoaded) {
          throw new Error(
            "Mismatch in coins count in snapshot metadata and actual snapshot data",
          );
        }

        for (let i = 0; i < numOutputs; i++) {
          // vout index — CompactSize.
          const vout = await stream.readVarInt();

          // BUG-4: vout upper-bound check.
          // Mirrors validation.cpp:5815-5818 — outpoint.n >= UINT32_MAX is
          // rejected to avoid integer wrap-around in coinstats.cpp ApplyHash.
          // The CompactSize-encoded vout is read as a JS number, so we
          // compare against MAX_VOUT (0xFFFFFFFF = uint32_max).
          if (vout >= MAX_VOUT) {
            throw new Error(
              `Bad snapshot data after deserializing ${coinsLoaded} coins`,
            );
          }

          // Coin payload: VARINT(code) + VARINT(CompressAmount(value)) +
          // ScriptCompression(scriptPubKey). Mirrors
          // deserializeCoinFromSnapshot/deserializeTxOutCompressed but
          // driven by the streaming reader so we never allocate the full
          // 9 GiB file in memory.
          const codeBig = await stream.readVarIntCore();
          const height = Number(codeBig >> 1n);
          const isCoinbase = (codeBig & 1n) === 1n;

          const compAmount = await stream.readVarIntCore();
          const value = decompressAmount(compAmount);

          // BUG-3: per-coin MoneyRange check.
          // Mirrors validation.cpp:5820-5823 — !MoneyRange(coin.out.nValue).
          // MoneyRange: 0 ≤ value ≤ MAX_MONEY (2_100_000_000_000_000n sat).
          if (value < 0n || value > MAX_MONEY) {
            throw new Error(
              `Bad snapshot data after deserializing ${coinsLoaded} coins - bad tx out value`,
            );
          }

          const nSizeBig = await stream.readVarIntCore();
          const nSize = Number(nSizeBig);
          let scriptPubKey: Buffer;
          if (nSize < NUM_SPECIAL_SCRIPTS) {
            const payloadLen = getSpecialScriptSize(nSize);
            const payload = await stream.readBytes(payloadLen);
            scriptPubKey = decompressScript(nSize, payload);
          } else {
            const rawSize = nSize - NUM_SPECIAL_SCRIPTS;
            if (rawSize > MAX_SCRIPT_SIZE) {
              // Overly long script: replace with OP_RETURN and consume the bytes,
              // mirroring compressor.h:ScriptCompression::Unser (lines 87-90).
              await stream.readBytes(rawSize);
              scriptPubKey = Buffer.from([0x6a]);
            } else {
              scriptPubKey = await stream.readBytes(rawSize);
            }
          }

          // Validate coin height (must be ≤ snapshot height).
          if (height > baseHeight) {
            throw new Error(
              `Invalid coin height ${height} > snapshot height ${baseHeight}`,
            );
          }

          // Add to batch.
          const key = Buffer.alloc(36);
          txid.copy(key, 0);
          key.writeUInt32LE(vout, 32);

          const writer = new BufferWriter();
          writer.writeUInt32LE(height);
          writer.writeUInt8(isCoinbase ? 1 : 0);
          writer.writeUInt64LE(value);
          writer.writeVarBytes(scriptPubKey);

          batchOps.push({
            type: "put",
            prefix: DBPrefix.UTXO,
            key,
            value: writer.toBuffer(),
          });

          coinsLoaded++;

          if (batchOps.length >= COINS_LOAD_BATCH_SIZE) {
            await this.db.batch(batchOps);
            batchOps.length = 0;
          }
        }
      }

      if (batchOps.length > 0) {
        await this.db.batch(batchOps);
      }

      // BUG-2: trailing-bytes EOF check.
      // Mirrors validation.cpp:5872-5883 — after all declared coins are
      // read, attempt to read one more byte: if it succeeds the file has
      // extra data beyond what the header claimed, which indicates a
      // malformed or corrupted snapshot.
      if (!stream.isEOF()) {
        throw new Error(
          `Bad snapshot - coins left over after deserializing ${coinsLoaded} coins`,
        );
      }
    } finally {
      await fh.close().catch(() => { /* close-on-error best-effort */ });
    }

    // Strict snapshot content-hash check.
    //
    // Mirrors Bitcoin Core validation.cpp:5902-5914
    // (PopulateAndValidateSnapshot):
    //
    //   maybe_stats = ComputeUTXOStats(
    //       CoinStatsHashType::HASH_SERIALIZED, ..., interruption_point);
    //   ...
    //   if (AssumeutxoHash{maybe_stats->hashSerialized} != au_data.hash_serialized) {
    //       return util::Error{Untranslated(strprintf(
    //           "Bad snapshot content hash: expected %s, got %s", ...))};
    //   }
    //
    // Core uses HASH_SERIALIZED (SHA256d via HashWriter, see
    // `kernel/coinstats.cpp:161-163`) for the strict gate, NOT MuHash3072.
    // MuHash is for `gettxoutsetinfo hash_type=muhash` only; the
    // `m_assumeutxo_data.hash_serialized` constants in chainparams.cpp are
    // SHA256d-via-HashWriter outputs. Refusing on mismatch is what makes
    // `loadtxoutset` strict — a malformed or out-of-band snapshot cannot
    // poison the chainstate.
    const { hash: computedHash, coinsCount } = await computeUTXOSetHash(this.db, interruptCheck);

    // `auData === null` ONLY under the HASHHOG_UNSAFE_SNAPSHOT_HEIGHT bypass
    // above, where no chainparams entry exists and therefore no hardcoded
    // hash_serialized to compare against. That is the one and only check the
    // bypass drops (the loud warning above already said so); with the variable
    // unset this is byte-for-byte the previous strict gate.
    if (auData && !computedHash.equals(auData.hashSerialized)) {
      throw new Error(
        `Bad snapshot content hash: expected ${auData.hashSerialized.toString("hex")}, got ${computedHash.toString("hex")}`
      );
    }

    // Create background chainstate for validation from genesis
    this.backgroundChainstate = new Chainstate(this.db, this.params, {
      status: ChainstateStatus.VALIDATED,
      maxCacheBytes: this.maxCacheBytes,
    });
    this.backgroundChainstate.targetBlockHash = metadata.baseBlockHash;

    // Activate snapshot chainstate
    this.activeChainstate = snapshotChainstate;

    return {
      coinsLoaded,
      baseBlockHash: metadata.baseBlockHash,
      baseHeight,
      path: filePath,
    };
  }

  /**
   * Dump the current UTXO set to a snapshot file.
   */
  async dumpSnapshot(
    filePath: string,
    interruptCheck?: () => boolean
  ): Promise<DumpSnapshotResult> {
    const chainstate = await this.db.getChainState();
    if (!chainstate) {
      throw new Error("No chain state available");
    }

    // Refuse to overwrite an existing destination — matches Bitcoin Core's
    // "<path> already exists. If you are sure this is what you want, move
    // it out of the way first." guard in rpc/blockchain.cpp::dumptxoutset.
    // The .incomplete temp is fine to overwrite (left over from a previous
    // crashed dump).
    try {
      await fsp.access(filePath);
      throw new Error(
        `${filePath} already exists. If you are sure this is what you want, move it out of the way first.`
      );
    } catch (e: any) {
      if (e?.code !== "ENOENT") throw e;
    }

    // Compute UTXO set hash and count
    const { hash, coinsCount } = await computeUTXOSetHash(this.db, interruptCheck);

    // Get block index for tip
    const blockIndex = await this.db.getBlockIndex(chainstate.bestBlockHash);
    if (!blockIndex) {
      throw new Error("Block index not found for chain tip");
    }

    // Create metadata
    const metadata: SnapshotMetadata = {
      networkMagic: this.params.networkMagic,
      baseBlockHash: chainstate.bestBlockHash,
      coinsCount,
    };

    // Atomic-write protocol: write to "<path>.incomplete", fsync the fd,
    // then atomically rename to <path>. Mirrors Bitcoin Core's flow in
    // rpc/blockchain.cpp::dumptxoutset (temppath = path + ".incomplete";
    // write; fsync; rename(temppath, path)). Until rename completes, the
    // final path doesn't exist on disk so an operator copying it never
    // sees a torn file.
    const tempPath = `${filePath}.incomplete`;
    let renamed = false;
    let fh: FileHandle | null = null;

    const cleanupTemp = async () => {
      try {
        await fsp.unlink(tempPath);
      } catch {
        // Best-effort: missing temp is fine, surface nothing.
      }
    };

    try {
      fh = await fsp.open(tempPath, "w");

      // Write header
      const header = serializeSnapshotMetadata(metadata);
      await fh.write(header);

      // Group coins by txid and write
      const utxoPrefix = Buffer.from([DBPrefix.UTXO]);
      const iterator = (this.db as any).db.iterator({
        gte: utxoPrefix,
        lt: Buffer.concat([Buffer.from([DBPrefix.UTXO + 1])]),
      });

      let currentTxid: Buffer | null = null;
      let currentCoins: Array<{ vout: number; coin: Coin }> = [];
      let coinsWritten = 0n;

      // Mirrors Bitcoin Core's write_coins_to_file lambda in
      // rpc/blockchain.cpp WriteUTXOSnapshot. The outer txid-group
      // framing (txid, count, [vout, coin]...) uses wire-protocol
      // CompactSize for count and vout, while each Coin uses Pieter's
      // VARINT and TxOutCompression internally (see
      // serializeCoinIntoWriter).
      //
      // CRITICAL ORDERING: Core's WriteUTXOSnapshot reads from a
      // `std::map<uint32_t, Coin>` keyed by vout, so per-txid the
      // vouts are emitted in NUMERIC order. LevelDB iterates this DB
      // in byte-lex order on the [prefix=0x75][txid 32B][vout
      // uint32_LE] key, which sorts vouts in LE-byte order — distinct
      // from numeric order for any vout >= 256. Sorting
      // `currentCoins` by `vout` numerically before flush restores
      // byte-identity with Core's dumptxoutset on chains that contain
      // high-vout txids (mainnet has 183,859 such txids at h=940k,
      // max vout 13,106).
      const flushTx = async () => {
        if (!currentTxid || currentCoins.length === 0) return;

        if (currentCoins.length > 1) {
          currentCoins.sort((a, b) => a.vout - b.vout);
        }

        const groupWriter = new BufferWriter();
        // txid (32 bytes, raw).
        groupWriter.writeBytes(currentTxid);
        // CompactSize: number of outputs in this group.
        groupWriter.writeVarInt(currentCoins.length);
        for (const { vout, coin } of currentCoins) {
          // CompactSize: vout index.
          groupWriter.writeVarInt(vout);
          // Coin: VARINT(code) || TxOutCompression.
          serializeCoinIntoWriter(groupWriter, coin);
        }
        await fh!.write(groupWriter.toBuffer());

        currentCoins = [];
      };

      try {
        for await (const [key, value] of iterator) {
          if (interruptCheck?.()) {
            throw new Error("Interrupted");
          }

          if (key.length !== 37) continue;

          const txid = key.subarray(1, 33);
          const vout = key.readUInt32LE(33);

          // Deserialize UTXO entry stored in the local DB
          // (uncompressed, matches UTXOManager.serializeUTXO format).
          const entryReader = new BufferReader(value);
          const height = entryReader.readUInt32LE();
          const coinbase = entryReader.readUInt8() === 1;
          const amount = entryReader.readUInt64LE();
          const scriptPubKey = entryReader.readVarBytes();

          const coin: Coin = {
            txOut: { value: amount, scriptPubKey },
            height,
            isCoinbase: coinbase,
          };

          // Check if new transaction
          if (!currentTxid || !txid.equals(currentTxid)) {
            await flushTx();
            currentTxid = Buffer.from(txid);
          }

          currentCoins.push({ vout, coin });
          coinsWritten++;
        }

        // Flush last transaction
        await flushTx();
      } finally {
        await iterator.close();
      }

      // Durability barrier: fsync the fd before the atomic rename.
      // Without this, a power loss between rename and dirty-page
      // flush could leave <path> visible with zero-length / torn
      // contents.
      await fh.sync();
      await fh.close();
      fh = null;

      // Atomic rename: temp -> final. After this point the snapshot
      // file is visible to any concurrent reader.
      await fsp.rename(tempPath, filePath);
      renamed = true;

      return {
        coinsWritten,
        baseHash: chainstate.bestBlockHash.toString("hex"),
        baseHeight: chainstate.bestHeight,
        path: filePath,
        txoutsetHash: hash.toString("hex"),
        nChainTx: 0n, // Would need to be computed from block index
      };
    } finally {
      // If we never made it to the rename, ensure the fd is closed
      // and the .incomplete temp is removed so a SIGKILL or thrown
      // exception leaves at most one orphan artifact (the temp,
      // which can be cleaned up out-of-band) — never a torn <path>.
      if (fh) {
        try {
          await fh.close();
        } catch {
          // Best-effort.
        }
      }
      if (!renamed) {
        await cleanupTemp();
      }
    }
  }

  /**
   * Start background validation — the REAL dual-chainstate pass.
   *
   * Builds a {@link BackgroundValidator} over a SEPARATE {@link ChainDB} (a
   * distinct LevelDB at `bgDataDir`, defaulting to `<active-db-path>-bgvalidate`)
   * and re-connects every block genesis -> base into that store via REAL block
   * connection (spend inputs / add outputs), then recomputes the bg store's
   * HASH_SERIALIZED and compares it to the assumeutxo commitment. MATCH ->
   * snapshot VALIDATED + bg retired; MISMATCH -> snapshot INVALID (never
   * silently accepted).
   *
   * This replaces the old counter loop that walked heights over the SAME `this.db`
   * with no real connection. Mirrors Core ActivateSnapshot/AddChainstate/
   * MaybeCompleteSnapshotValidation (validation.cpp) and the cross-impl pilots
   * (blockbrew bfd429a, lunarblock a39dd42, camlcoin 2675b31).
   *
   * @param getBlock      fn(height) -> canonical block for genesis+1..base
   *                      (shared block store; bg chainstate owns only its coins)
   * @param onComplete    optional callback fired with the terminal result
   * @returns the {@link SnapshotActivation} (snapshot chainstate + background
   *          validator) so a caller can inspect / drive it; null if not
   *          activatable (no snapshot loaded / no assumeutxo data).
   */
  async startBackgroundValidation(
    getBlock: (height: number) => Promise<Block | null>,
    onComplete?: (result: SnapshotValidationResult) => void,
  ): Promise<SnapshotActivation | null> {
    if (this.backgroundValidationRunning) {
      return null;
    }
    // Require an active snapshot with a known base + assumeutxo data.
    const baseHash = this.backgroundChainstate?.targetBlockHash
      ?? this.activeChainstate.snapshotBaseBlockHash;
    if (!baseHash) {
      return null;
    }
    const auData = getAssumeutxoData(this.params, baseHash);
    if (!auData) {
      // Also the terminal state for a snapshot accepted through the
      // HASHHOG_UNSAFE_SNAPSHOT_HEIGHT bypass: with no chainparams trust
      // anchor there is no commitment for the background pass to re-derive
      // and compare against, so it does not run and the snapshot stays
      // UNVALIDATED (getchainstates validated=false). Unchanged for every
      // whitelisted snapshot.
      this.backgroundVerdict = SnapshotValidationResult.MISSING_CHAINPARAMS;
      return null;
    }

    // Open the SEPARATE background coins store. MUST be a different path/object
    // than the active db.
    const bgDir = this.bgDataDir ?? `${this.db.path()}-bgvalidate`;
    const bgDB = new ChainDB(bgDir);
    await bgDB.open();

    let activation: SnapshotActivation;
    try {
      activation = activateSnapshotWithBackground(
        this.activeChainstate,
        bgDB,
        auData,
        getBlock,
        this.maxCacheBytes,
      );
    } catch (e) {
      await bgDB.close().catch(() => { /* best-effort */ });
      throw e;
    }

    this.backgroundValidator = activation.background;
    this.backgroundValidationRunning = true;
    this.backgroundVerdict = null;

    // Drive the real genesis->base connection + hash compare.
    const result = await activation.background.runToBase();

    if (this.onBackgroundProgress) {
      this.onBackgroundProgress(activation.background.currentHeight(), auData.height);
    }

    // Apply the verdict to the (active) snapshot chainstate.
    const { validated, error } = finishSnapshotActivation(activation);

    let verdict: SnapshotValidationResult;
    if (validated) {
      verdict = SnapshotValidationResult.SUCCESS;
      // Retire the bg chainstate (Core ValidatedSnapshotCleanup).
      this.backgroundChainstate = null;
    } else if (result === BackgroundValidationResult.INVALID) {
      verdict = SnapshotValidationResult.HASH_MISMATCH;
      if (error) {
        console.error(`AssumeUTXO background validation FAILED: ${error.message}`);
      }
    } else {
      verdict = SnapshotValidationResult.SKIPPED;
    }

    this.backgroundVerdict = verdict;
    this.backgroundValidationRunning = false;

    // Close the bg store regardless of verdict (Core retires the bg chainstate
    // on completion; on failure the node aborts so the store is discarded).
    await activation.background.close();
    this.backgroundValidator = null;

    onComplete?.(verdict);
    return activation;
  }

  /**
   * Stop background validation.
   */
  stopBackgroundValidation(): void {
    this.backgroundValidationRunning = false;
  }

  /**
   * Get status of assumeUTXO validation.
   */
  getStatus(): {
    hasSnapshot: boolean;
    snapshotValidated: boolean;
    backgroundRunning: boolean;
    backgroundProgress: number | null;
    backgroundTarget: number | null;
  } {
    const hasSnapshot = this.activeChainstate.isSnapshot();
    // A from-snapshot chainstate is `validated` (getchainstates) only AFTER the
    // background pass matches: false while UNVALIDATED / running, true once the
    // bg hash compare succeeds (Core's m_assumeutxo == VALIDATED).
    const snapshotValidated = this.activeChainstate.status === ChainstateStatus.VALIDATED;

    let backgroundProgress: number | null = null;
    let backgroundTarget: number | null = null;

    if (this.backgroundValidator) {
      // Live progress from the real validator.
      backgroundProgress = this.backgroundValidator.currentHeight();
      const baseHash = this.activeChainstate.snapshotBaseBlockHash;
      if (baseHash) {
        const auData = getAssumeutxoData(this.params, baseHash);
        if (auData) backgroundTarget = auData.height;
      }
    } else if (this.backgroundChainstate && this.backgroundChainstate.targetBlockHash) {
      backgroundProgress = this.backgroundChainstate.tipHeight;
      const auData = getAssumeutxoData(this.params, this.backgroundChainstate.targetBlockHash);
      if (auData) backgroundTarget = auData.height;
    }

    return {
      hasSnapshot,
      snapshotValidated,
      backgroundRunning: this.backgroundValidationRunning,
      backgroundProgress,
      backgroundTarget,
    };
  }

  /** The active background validator, if a real pass is wired up. */
  backgroundValidatorRef(): BackgroundValidator | null {
    return this.backgroundValidator;
  }

  /** Last terminal verdict of the background pass (null if never run). */
  backgroundValidationVerdict(): SnapshotValidationResult | null {
    return this.backgroundVerdict;
  }
}

/**
 * Get assumeUTXO data for a block hash from chain parameters.
 */
export function getAssumeutxoData(
  params: ConsensusParams,
  blockHash: Buffer
): AssumeutxoData | null {
  const assumeutxo = (params as any).assumeutxo as Map<string, AssumeutxoData> | undefined;
  if (!assumeutxo) return null;

  const key = blockHash.toString("hex");
  return assumeutxo.get(key) ?? null;
}

/** Regtest network magic (REGTEST.networkMagic in consensus/params.ts). */
const REGTEST_NETWORK_MAGIC = 0xdab5bffa;

/**
 * Register a regtest AssumeUTXO whitelist entry at runtime.
 *
 * Core's regtest chainparams DOES carry `m_assumeutxo_data` entries (heights
 * 110 / 200 / 299 in `bitcoin-core/src/kernel/chainparams.cpp`, explicitly
 * "for use by test/functional/feature_assumeutxo.py" and the snapshot fuzz
 * target). Those Core values are pinned to Core's deterministic regtest mining
 * chain; hotbuns's snapshot tests build their own short regtest chains, so the
 * regtest table is REGISTERABLE at runtime — exactly mirroring how Core's
 * regtest is a mockable chain whose assumeutxo data is purpose-built for the
 * snapshot tests rather than a permanent network commitment (camlcoin 3140ab9
 * `register_regtest_assumeutxo`, lunarblock a39dd42).
 *
 * REGTEST ONLY: refuses any non-regtest params so a mainnet/testnet4 whitelist
 * can never be mutated at runtime — those remain the hardcoded, immutable Core
 * values. Idempotent on the base block hash (re-registering replaces the prior
 * entry). The entry is keyed by `au.blockHash.toString("hex")`, the same key
 * {@link getAssumeutxoData} reads.
 */
export function registerRegtestAssumeutxo(
  params: ConsensusParams,
  au: AssumeutxoData,
): void {
  if (params.networkMagic !== REGTEST_NETWORK_MAGIC) {
    throw new Error(
      "registerRegtestAssumeutxo: refusing to mutate a non-regtest assumeutxo " +
        "whitelist (mainnet/testnet4 entries are immutable Core values)",
    );
  }
  let assumeutxo = (params as any).assumeutxo as Map<string, AssumeutxoData> | undefined;
  if (!assumeutxo) {
    assumeutxo = new Map<string, AssumeutxoData>();
    (params as any).assumeutxo = assumeutxo;
  }
  assumeutxo.set(au.blockHash.toString("hex"), au);
}

/**
 * Empty the regtest AssumeUTXO whitelist (test teardown hygiene so
 * registrations never leak across test cases). REGTEST ONLY.
 */
export function clearRegtestAssumeutxo(params: ConsensusParams): void {
  if (params.networkMagic !== REGTEST_NETWORK_MAGIC) {
    throw new Error(
      "clearRegtestAssumeutxo: refusing to clear a non-regtest assumeutxo whitelist",
    );
  }
  const assumeutxo = (params as any).assumeutxo as Map<string, AssumeutxoData> | undefined;
  if (assumeutxo) assumeutxo.clear();
}

/**
 * One entry of a campaign-assumeutxo fixture file (DISPLAY-order hex, as
 * printed by Bitcoin Core / `dumptxoutset`). See
 * `receipts/CAMPAIGN-SNAPSHOT-TABLE-SPEC.md` for the shared cross-impl
 * schema. `base_mtp` / `base_header` / `chainwork` are accepted (other
 * impls need them for post-snapshot connect) but hotbuns's
 * {@link AssumeutxoData} shape does not carry them yet, so they are
 * validated-if-present and otherwise ignored here.
 */
interface CampaignAssumeutxoEntry {
  height: number;
  blockhash: string;
  hash_serialized: string;
  m_chain_tx_count: number;
  base_mtp?: number;
  base_header?: string;
  chainwork?: string;
}

const HASH_HEX_RE = /^[0-9a-fA-F]{64}$/;

/**
 * Load `HASHHOG_CAMPAIGN_ASSUMEUTXO=<abs-path.json>` (read ONCE, here) and
 * append its entries to the RUNNING network's assumeutxo allowlist.
 *
 * Design: `receipts/CAMPAIGN-SNAPSHOT-TABLE-SPEC.md`. Unset (the common
 * case, including every production launch today) does exactly one
 * `process.env` read and returns — bit-identical to before this function
 * existed. When set, the campaign entries are APPEND-ONLY: any collision
 * with an existing entry (same internal-order block hash OR same height,
 * built-in or previously-loaded-campaign) is refused with a thrown Error,
 * which aborts startup (`main().catch` in index.ts logs "Fatal error" and
 * exits 1) — campaign data may never override a production hash. Callable
 * against ANY network's params (mainnet included: the M2 campaign boots
 * "mainnet params" by design), unlike {@link registerRegtestAssumeutxo},
 * which stays regtest-only and untouched by this function.
 *
 * Fixture hex is DISPLAY order (Core convention); converted to hotbuns's
 * INTERNAL (byte-reversed) convention on load, mirroring every hardcoded
 * entry in consensus/params.ts.
 */
export async function loadCampaignAssumeutxo(params: ConsensusParams): Promise<void> {
  const fixturePath = process.env.HASHHOG_CAMPAIGN_ASSUMEUTXO;
  if (!fixturePath) return;

  let raw: string;
  try {
    raw = await fsp.readFile(fixturePath, "utf8");
  } catch (err) {
    throw new Error(
      `loadCampaignAssumeutxo: failed to read HASHHOG_CAMPAIGN_ASSUMEUTXO=${fixturePath}: ${
        (err as Error).message
      }`,
    );
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    throw new Error(
      `loadCampaignAssumeutxo: invalid JSON in ${fixturePath}: ${(err as Error).message}`,
    );
  }
  if (!Array.isArray(parsed)) {
    throw new Error(
      `loadCampaignAssumeutxo: ${fixturePath} must contain a top-level JSON array`,
    );
  }

  let assumeutxo = (params as any).assumeutxo as Map<string, AssumeutxoData> | undefined;
  if (!assumeutxo) {
    assumeutxo = new Map<string, AssumeutxoData>();
    (params as any).assumeutxo = assumeutxo;
  }

  const loadedHeights: number[] = [];
  for (const [i, entry] of (parsed as CampaignAssumeutxoEntry[]).entries()) {
    if (typeof entry !== "object" || entry === null) {
      throw new Error(`loadCampaignAssumeutxo: entry ${i} in ${fixturePath} is not an object`);
    }
    if (typeof entry.height !== "number" || !Number.isInteger(entry.height) || entry.height <= 0) {
      throw new Error(
        `loadCampaignAssumeutxo: entry ${i} has invalid height ${JSON.stringify(entry.height)}`,
      );
    }
    if (typeof entry.blockhash !== "string" || !HASH_HEX_RE.test(entry.blockhash)) {
      throw new Error(
        `loadCampaignAssumeutxo: entry ${i} (height ${entry.height}) has invalid blockhash`,
      );
    }
    if (typeof entry.hash_serialized !== "string" || !HASH_HEX_RE.test(entry.hash_serialized)) {
      throw new Error(
        `loadCampaignAssumeutxo: entry ${i} (height ${entry.height}) has invalid hash_serialized`,
      );
    }
    if (
      (typeof entry.m_chain_tx_count !== "number" && typeof entry.m_chain_tx_count !== "string") ||
      BigInt(entry.m_chain_tx_count) <= 0n
    ) {
      throw new Error(
        `loadCampaignAssumeutxo: entry ${i} (height ${entry.height}) has invalid m_chain_tx_count`,
      );
    }
    if (entry.base_header !== undefined && !/^[0-9a-fA-F]+$/.test(entry.base_header)) {
      throw new Error(
        `loadCampaignAssumeutxo: entry ${i} (height ${entry.height}) has non-hex base_header`,
      );
    }

    const blockHash = Buffer.from(entry.blockhash, "hex").reverse();
    const hashSerialized = Buffer.from(entry.hash_serialized, "hex").reverse();
    const key = blockHash.toString("hex");

    if (assumeutxo.has(key)) {
      throw new Error(
        `loadCampaignAssumeutxo: entry ${i} blockhash ${entry.blockhash} collides with an ` +
          `existing assumeutxo entry — refusing to override a production/loaded hash`,
      );
    }
    for (const existing of assumeutxo.values()) {
      if (existing.height === entry.height) {
        throw new Error(
          `loadCampaignAssumeutxo: entry ${i} height ${entry.height} collides with an ` +
            `existing assumeutxo entry — refusing to override a production/loaded hash`,
        );
      }
    }

    assumeutxo.set(key, {
      height: entry.height,
      hashSerialized,
      nChainTx: BigInt(entry.m_chain_tx_count),
      blockHash,
    });
    loadedHeights.push(entry.height);
  }

  console.log(
    `[CAMPAIGN-ASSUMEUTXO] loaded ${loadedHeights.length} entries from ${fixturePath} ` +
      `heights=[${loadedHeights.join(",")}]`,
  );
}

/**
 * Get assumeUTXO data for a height from chain parameters.
 */
export function getAssumeutxoDataByHeight(
  params: ConsensusParams,
  height: number
): AssumeutxoData | null {
  const assumeutxo = (params as any).assumeutxo as Map<string, AssumeutxoData> | undefined;
  if (!assumeutxo) return null;

  for (const data of assumeutxo.values()) {
    if (data.height === height) {
      return data;
    }
  }

  return null;
}

/**
 * Get all assumeUTXO snapshot heights from chain parameters, sorted ascending.
 *
 * Mirrors `ChainParams::GetAvailableSnapshotHeights()` from
 * `bitcoin-core/src/kernel/chainparams.cpp` — returns the heights at which
 * a hardcoded assumeutxo entry exists, used by `dumptxoutset rollback`
 * (no explicit height) to pick the latest snapshot height that
 * `loadtxoutset` could currently consume.
 */
export function getAvailableSnapshotHeights(params: ConsensusParams): number[] {
  const assumeutxo = (params as any).assumeutxo as Map<string, AssumeutxoData> | undefined;
  if (!assumeutxo) return [];

  const heights: number[] = [];
  for (const data of assumeutxo.values()) {
    heights.push(data.height);
  }
  heights.sort((a, b) => a - b);
  return heights;
}

/**
 * Get the latest assumeUTXO snapshot height ≤ the given current tip height.
 *
 * Used by `dumptxoutset` with `type="rollback"` and no explicit height —
 * matches Core's `dumptxoutset` behavior in `rpc/blockchain.cpp` (snapshot
 * type "rollback" picks `max(GetAvailableSnapshotHeights())`, with the
 * implicit constraint that the chosen height is reachable from the current
 * tip).
 */
export function getLatestSnapshotHeightForRollback(
  params: ConsensusParams,
  currentTipHeight: number
): number | null {
  const heights = getAvailableSnapshotHeights(params);
  let chosen: number | null = null;
  for (const h of heights) {
    if (h <= currentTipHeight) {
      chosen = h;
    }
  }
  return chosen;
}

// ─────────────────────────────────────────────────────────────────────────────
// AssumeUTXO dual-chainstate (REAL background 2nd chainstate)
//
// Core reference: bitcoin-core/src/validation.cpp.
//   * ActivateSnapshot (5588) loads the snapshot coins into a NEW chainstate
//     which becomes the active/tip-serving chainstate (m_assumeutxo =
//     UNVALIDATED).
//   * AddChainstate (6170) DEMOTES the original genesis-validated chainstate to
//     a BACKGROUND chainstate by setting its m_target_blockhash to the snapshot
//     base. The background chainstate keeps its OWN coins DB
//     (`prev_chainstate.m_coins_views`) and re-connects blocks genesis -> base
//     independently of the loaded snapshot coins.
//   * MaybeCompleteSnapshotValidation (5967) runs once the background chainstate
//     reaches the base: it computes the HASH_SERIALIZED of the BACKGROUND
//     chainstate's OWN coins (ComputeUTXOStats / kernel/coinstats.cpp) and
//     compares it to au_data.hash_serialized. MATCH -> the snapshot chainstate's
//     m_assumeutxo flips to VALIDATED and the background chainstate is retired
//     (ValidatedSnapshotCleanup, 6280). MISMATCH -> snapshot marked INVALID and
//     AbortNode (the handle-invalid-snapshot path) — NEVER silently accepted.
//
// The load-time HASH_SERIALIZED gate (loadSnapshot, the `computedHash !==
// auData.hashSerialized` check above) already authenticates the snapshot bytes.
// This background pass is the trustless re-verification by INDEPENDENT
// re-computation: it never trusts the loaded coins, it rebuilds the UTXO set
// from genesis in a SEPARATE coins store and checks that an honest replay
// arrives at the same committed hash.
//
// Replaces the old `ChainstateManager.startBackgroundValidation` counter loop
// (which had no callers, walked heights with no real block connection, and
// operated over the SAME `this.db` as the active store). The machinery below is
// a genuinely separate background chainstate with its OWN ChainDB.
//
// Cross-impl references for the same machinery: blockbrew bfd429a
// (BackgroundValidator / ActivateSnapshotWithBackground,
// internal/consensus/assumeutxo.go), lunarblock a39dd42
// (BackgroundValidator over new_memory_storage, src/utxo.lua), and camlcoin
// 2675b31 (make_background_chainstate / run_background_to_completion,
// lib/assume_utxo.ml).
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Terminal verdict of the background validation pass.
 */
export enum BackgroundValidationResult {
  /** The background pass has not yet reached the base height. */
  PENDING = "pending",
  /** Background-recomputed HASH_SERIALIZED MATCHED the assumeutxo commitment. */
  VALIDATED = "validated",
  /** Mismatch, or a block failed to connect — snapshot is INVALID / abort. */
  INVALID = "invalid",
}

/**
 * BackgroundValidator owns the SECOND (background) chainstate for AssumeUTXO
 * validation: a genesis-rooted chainstate with its OWN separate coins store.
 *
 * The store is a distinct {@link ChainDB} (a distinct LevelDB instance at a
 * distinct on-disk path / keyspace) wrapped in its own {@link UTXOManager} — it
 * is NOT the active snapshot chainstate's `db`, and a write to the active store
 * is INVISIBLE here (proven by the dual-chainstate aliasing falsification test).
 *
 * It re-connects every block genesis -> base into that store via REAL block
 * connection (`connectNext`: spend every non-coinbase input out of the bg store,
 * add every new output into the bg store — NOT a height counter), then
 * recomputes the HASH_SERIALIZED of its OWN coins ({@link computeUTXOSetHash}
 * over the bg ChainDB — the SAME kernel the load-time gate uses) and compares it
 * to the assumeutxo commitment.
 *
 * This is Core's background (validated, genesis-rooted) chainstate from
 * AddChainstate: it keeps its own m_coins_views and replays forward to
 * m_target_blockhash (the snapshot base).
 */
export class BackgroundValidator {
  /**
   * The background chainstate's OWN coins store — a genuinely separate
   * {@link ChainDB} from the active (snapshot) chainstate's `db`. Owned by this
   * validator; closed by {@link close}.
   */
  private readonly bgDB: ChainDB;

  /** Layered UTXO view over {@link bgDB} (spend/add/flush). */
  private readonly bgUTXO: UTXOManager;

  /** Snapshot base height (Core m_target_blockhash height). */
  private readonly targetHeight: number;

  /**
   * The assumeutxo HASH_SERIALIZED commitment (au_data.hash_serialized) the
   * recomputed bg hash is compared against.
   */
  private readonly targetHash: Buffer;

  /**
   * Reads canonical blocks for heights 1..base from the node's block store. The
   * bg chainstate only owns its coins, not block bodies (Core shares
   * BlockManager across chainstates), so blocks come from the shared store.
   */
  private readonly getBlock: (height: number) => Promise<Block | null>;

  private currentHeightVal = 0; // genesis-seeded: empty coins at height 0
  private resultVal: BackgroundValidationResult = BackgroundValidationResult.PENDING;
  private errVal: Error | null = null;
  private closed = false;

  /**
   * @param bgDB         the SEPARATE background coins store (a distinct ChainDB;
   *                     MUST NOT be the active snapshot store's db)
   * @param targetHeight snapshot base height to validate up to
   * @param targetHash   assumeutxo HASH_SERIALIZED commitment at the base
   * @param getBlock     fn(height) -> block for heights 1..targetHeight
   * @param maxCacheBytes optional cache budget for the bg UTXO view
   */
  constructor(
    bgDB: ChainDB,
    targetHeight: number,
    targetHash: Buffer,
    getBlock: (height: number) => Promise<Block | null>,
    maxCacheBytes?: number,
  ) {
    this.bgDB = bgDB;
    this.bgUTXO = new UTXOManager(bgDB, maxCacheBytes);
    this.targetHeight = targetHeight;
    this.targetHash = targetHash;
    this.getBlock = getBlock;
  }

  /** Background chainstate's current tip height. */
  currentHeight(): number {
    return this.currentHeightVal;
  }

  /** Terminal verdict (PENDING until {@link runToBase} completes). */
  result(): BackgroundValidationResult {
    return this.resultVal;
  }

  /** The connection / mismatch error, if any. */
  error(): Error | null {
    return this.errVal;
  }

  /**
   * The background chainstate's OWN coins ChainDB. Exposed so tests can prove
   * the store is genuinely separate from the active one (an active-store write
   * is NOT visible here).
   */
  backgroundDB(): ChainDB {
    return this.bgDB;
  }

  /** The layered UTXO view over the background store. */
  backgroundUTXO(): UTXOManager {
    return this.bgUTXO;
  }

  /**
   * Connect exactly one block (currentHeight+1) into the background
   * chainstate's OWN coins via REAL block connection. This is NOT a counter
   * bump: it spends every non-coinbase input out of the bg store and adds every
   * (spendable) new output into the bg store, mutating the independent coins
   * set.
   *
   * Mirrors the coins-layer half of Core's Chainstate::ConnectBlock
   * (validation.cpp): for each tx, `view.SpendCoin(prevout)` for every input
   * (coinbase excepted) then `AddCoins(tx, height)` for the outputs. An aliasing
   * bug (reading the active store) or a missing parent coin surfaces here as a
   * spend of a coin absent from THIS store.
   */
  private async connectNext(): Promise<void> {
    const next = this.currentHeightVal + 1;
    const block = await this.getBlock(next);
    if (!block) {
      throw new Error(`background validation: missing block at height ${next}`);
    }

    const cache = this.bgUTXO.getCoinsViewCache();

    for (const tx of block.transactions) {
      const coinbase = isCoinbase(tx);

      // Spend inputs (coinbase has no real prevouts).
      if (!coinbase) {
        for (const input of tx.inputs) {
          const spent = await cache.spendCoin(input.prevOut);
          if (!spent) {
            throw new Error(
              `background validation: block ${next} spends a coin absent from the ` +
                `background store (${input.prevOut.txid.toString("hex")}:${input.prevOut.vout}); ` +
                `connection is not real or the store is aliased`,
            );
          }
        }
      }

      // Add this tx's outputs (CoinsViewCache.addCoin skips unspendable
      // scripts, matching Core's AddCoins).
      const txid = getTxId(tx);
      for (let vout = 0; vout < tx.outputs.length; vout++) {
        const out = tx.outputs[vout];
        const coin: Coin = {
          txOut: { value: out.value, scriptPubKey: out.scriptPubKey },
          height: next,
          isCoinbase: coinbase,
        };
        // possibleOverwrite=coinbase mirrors Core's `AddCoins(tx, ..., overwrite)`
        // where overwrite is set for BIP-30 duplicate-coinbase handling.
        cache.addCoin({ txid, vout }, coin, coinbase);
      }
    }

    this.currentHeightVal = next;
  }

  /**
   * Recompute the background chainstate's HASH_SERIALIZED at the base and apply
   * the verdict (Core MaybeCompleteSnapshotValidation).
   *
   * Flushes the bg coins cache to the bg ChainDB, then runs
   * {@link computeUTXOSetHash} over THAT db — the same HASH_SERIALIZED kernel
   * the load-time gate uses (validation.cpp ComputeUTXOStats over the chainstate
   * cursor). Correct even if the cache has spilled to disk.
   */
  private async finalizeAtBase(): Promise<void> {
    let computed: Buffer;
    try {
      await this.bgUTXO.flush();
      const res = await computeUTXOSetHash(this.bgDB);
      computed = res.hash;
    } catch (e) {
      this.errVal = e instanceof Error ? e : new Error(String(e));
      this.resultVal = BackgroundValidationResult.INVALID;
      return;
    }

    if (computed.equals(this.targetHash)) {
      // MATCH: Core flips the snapshot chainstate to VALIDATED and retires bg.
      this.resultVal = BackgroundValidationResult.VALIDATED;
      return;
    }

    // MISMATCH: Core marks the snapshot INVALID and AbortNodes. Surface a hard
    // error; never silently accept. ("mismatch" kept in the message so external
    // tooling scraping it keeps working — cross-impl convention.)
    this.errVal = new Error(
      `background validation hash mismatch: background-recomputed HASH_SERIALIZED ` +
        `${computed.toString("hex")} != assumeutxo ${this.targetHash.toString("hex")}`,
    );
    this.resultVal = BackgroundValidationResult.INVALID;
  }

  /**
   * Synchronously drive the background validation to its terminal state:
   * connect every block genesis+1..base into the bg coins store, then recompute
   * the HASH_SERIALIZED and compare to the assumeutxo commitment. Returns the
   * terminal result. A live node could instead tick {@link connectNext} from a
   * maintenance loop and call finalize on reaching the base; this in-process
   * driver mirrors Core's validation-queue work synchronously.
   */
  async runToBase(): Promise<BackgroundValidationResult> {
    if (this.resultVal !== BackgroundValidationResult.PENDING) {
      return this.resultVal;
    }
    try {
      while (this.currentHeightVal < this.targetHeight) {
        await this.connectNext();
      }
    } catch (e) {
      this.errVal = e instanceof Error ? e : new Error(String(e));
      this.resultVal = BackgroundValidationResult.INVALID;
      return this.resultVal;
    }
    await this.finalizeAtBase();
    return this.resultVal;
  }

  /**
   * Close the background chainstate's OWN ChainDB. Called after the verdict is
   * applied (Core's ValidatedSnapshotCleanup retires the bg chainstate). Safe to
   * call more than once.
   */
  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    await this.bgDB.close().catch(() => { /* best-effort */ });
  }
}

/**
 * Pairs the active (snapshot) chainstate with the background validator that
 * re-derives its UTXO hash. Mirrors Core's triple through ActivateSnapshot /
 * AddChainstate: the UNVALIDATED snapshot chainstate, and the VALIDATED
 * background chainstate targeting the snapshot base.
 */
export interface SnapshotActivation {
  /**
   * The ACTIVE chainstate (snapshot-loaded). Starts UNVALIDATED (Core
   * Assumeutxo::UNVALIDATED); the background pass flips its `status` to
   * VALIDATED (match) or INVALID (mismatch) via {@link finishSnapshotActivation}.
   */
  snapshot: Chainstate;
  /** The genesis-rooted validator with its OWN separate coins store. */
  background: BackgroundValidator;
}

/**
 * Wire up a real dual-chainstate validation for an already-loaded snapshot
 * chainstate (Core ActivateSnapshot + AddChainstate).
 *
 * Performs NO block connection itself — exactly like Core's ActivateSnapshot,
 * which returns after demoting the prior chainstate and lets the validation
 * queue do the background work. Drive it with `background.runToBase()` and then
 * call {@link finishSnapshotActivation}.
 *
 * @param snapshotCS the ACTIVE chainstate produced by loading the snapshot (its
 *                   coins live in its OWN `db`). Forced to UNVALIDATED here.
 * @param bgDB       the BACKGROUND chainstate's OWN coins store — MUST be a
 *                   genuinely separate {@link ChainDB} from the snapshot
 *                   chainstate's `db`. Refuses to proceed if it is the same
 *                   object (aliasing guard, mirroring blockbrew's
 *                   "background coins store must be separate" check).
 * @param au         the assumeutxo entry for the base (its hashSerialized is the
 *                   commitment the background pass re-derives and checks).
 * @param getBlock   fn(height) -> block for genesis+1..base (shared block store).
 * @param maxCacheBytes optional cache budget for the bg UTXO view.
 */
export function activateSnapshotWithBackground(
  snapshotCS: Chainstate,
  bgDB: ChainDB,
  au: AssumeutxoData,
  getBlock: (height: number) => Promise<Block | null>,
  maxCacheBytes?: number,
): SnapshotActivation {
  if (!snapshotCS) {
    throw new Error("activateSnapshotWithBackground: nil snapshot chainstate");
  }
  if (!au) {
    throw new Error("activateSnapshotWithBackground: nil assumeutxo data");
  }
  if (!bgDB) {
    throw new Error("activateSnapshotWithBackground: nil background coins store");
  }
  // Aliasing guard: the bg coins store MUST be a different object from the
  // active store (Core's background chainstate keeps its OWN m_coins_views).
  if (bgDB === snapshotCS.db) {
    throw new Error(
      "activateSnapshotWithBackground: background coins store must be separate from " +
        "the active (snapshot) chainstate store",
    );
  }

  // The snapshot chainstate is the active, not-yet-validated one
  // (Core Assumeutxo::UNVALIDATED).
  snapshotCS.status = ChainstateStatus.UNVALIDATED;

  const background = new BackgroundValidator(bgDB, au.height, au.hashSerialized, getBlock, maxCacheBytes);
  return { snapshot: snapshotCS, background };
}

/**
 * Apply the background verdict to the snapshot chainstate (Core's flip of
 * unvalidated_cs.m_assumeutxo).
 *
 *   - VALIDATED match -> snapshot.status = VALIDATED, returns { validated: true }.
 *   - INVALID mismatch -> snapshot.status = INVALID, returns
 *     { validated: false, error } — the snapshot is NEVER silently accepted on a
 *     mismatch; the caller should treat the error as fatal (Core AbortNode).
 *   - still PENDING -> leaves the snapshot unchanged, returns
 *     { validated: false }.
 */
export function finishSnapshotActivation(
  activation: SnapshotActivation,
): { validated: boolean; error?: Error } {
  const bg = activation.background;
  switch (bg.result()) {
    case BackgroundValidationResult.VALIDATED:
      activation.snapshot.status = ChainstateStatus.VALIDATED;
      return { validated: true };
    case BackgroundValidationResult.INVALID:
      activation.snapshot.status = ChainstateStatus.INVALID;
      return {
        validated: false,
        error: bg.error() ?? new Error("background validation failed"),
      };
    default:
      // Still pending: not terminal. Do not flip the snapshot's status.
      return { validated: false };
  }
}
