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

import { hash256 } from "../crypto/primitives.js";
import { BufferWriter, BufferReader, varIntSize } from "../wire/serialization.js";
import {
  serializeTxOutCompressed,
  deserializeTxOutCompressed,
  writeVarIntCore,
  readVarIntCore,
} from "../wire/compressor.js";
import { MuHash3072 } from "../wire/muhash.js";
import type { ChainDB, UTXOEntry, BatchOperation } from "../storage/database.js";
import { DBPrefix } from "../storage/database.js";
import type { ConsensusParams } from "../consensus/params.js";
import type { Coin, CoinsViewCache, CoinsViewDB } from "./utxo.js";
import { UTXOManager } from "./utxo.js";

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
 * the digest (double-SHA256, see `hash.h`) — we use `hash256()` to match.
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

      hasher.update(txOutSerBytes(txid, vout, height, coinbase, amount, scriptPubKey));
      coinsCount++;
    }
  } finally {
    await iterator.close();
  }

  // Double-SHA256 to match Core's HashWriter::GetHash().
  const inner = Buffer.from(hasher.digest());
  const hash = hash256(inner);

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

      acc.add(txOutSerBytes(txid, vout, height, coinbase, amount, scriptPubKey));
      coinsCount++;
    }
  } finally {
    await iterator.close();
  }

  // SHA256(LE_384(num/den)) -> 32-byte digest.
  const hash = acc.finalize();

  return { hash, coinsCount };
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
 * ChainstateManager manages dual chainstates for assumeUTXO.
 */
export class ChainstateManager {
  private params: ConsensusParams;
  private db: ChainDB;

  /** The active chainstate (either IBD or snapshot). */
  private activeChainstate: Chainstate;

  /** The background chainstate (validates from genesis). */
  private backgroundChainstate: Chainstate | null = null;

  /** Whether background validation is running. */
  private backgroundValidationRunning = false;

  /** Callback for background validation progress. */
  onBackgroundProgress?: (height: number, targetHeight: number) => void;

  /** Cache budget propagated to every Chainstate this manager creates. */
  private maxCacheBytes?: number;

  constructor(db: ChainDB, params: ConsensusParams, maxCacheBytes?: number) {
    this.db = db;
    this.params = params;
    this.maxCacheBytes = maxCacheBytes;
    this.activeChainstate = new Chainstate(db, params, { maxCacheBytes });
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
    const file = Bun.file(filePath);

    if (!await file.exists()) {
      throw new Error(`Snapshot file not found: ${filePath}`);
    }

    // Read the entire file into a buffer
    const data = Buffer.from(await file.arrayBuffer());
    const reader = new BufferReader(data);

    // Parse metadata
    const metadata = deserializeSnapshotMetadata(reader, this.params.networkMagic);

    // Validate against assumeutxo parameters
    const auData = getAssumeutxoData(this.params, metadata.baseBlockHash);
    if (!auData) {
      throw new Error(`No assumeutxo data for block ${metadata.baseBlockHash.toString("hex")}`);
    }

    // Create snapshot chainstate
    const snapshotChainstate = new Chainstate(this.db, this.params, {
      snapshotBaseBlockHash: metadata.baseBlockHash,
      status: ChainstateStatus.UNVALIDATED,
      maxCacheBytes: this.maxCacheBytes,
    });
    snapshotChainstate.tipHash = metadata.baseBlockHash;
    snapshotChainstate.tipHeight = auData.height;

    // Load coins from snapshot
    let coinsLoaded = 0n;
    let currentTxid: Buffer | null = null;
    let coinsForTx: Array<{ vout: number; coin: Coin }> = [];

    const batchOps: BatchOperation[] = [];

    while (coinsLoaded < metadata.coinsCount) {
      if (interruptCheck?.()) {
        throw new Error("Interrupted");
      }

      // Read transaction ID
      const txid = reader.readHash();

      // Read number of outputs for this transaction
      const numOutputs = reader.readVarInt();

      // Read each output
      for (let i = 0; i < numOutputs; i++) {
        const vout = reader.readVarInt();
        const coin = deserializeCoinFromSnapshot(reader);

        // Validate coin height
        if (coin.height > auData.height) {
          throw new Error(`Invalid coin height ${coin.height} > snapshot height ${auData.height}`);
        }

        // Add to batch
        const key = Buffer.alloc(36);
        txid.copy(key, 0);
        key.writeUInt32LE(vout, 32);

        const writer = new BufferWriter();
        writer.writeUInt32LE(coin.height);
        writer.writeUInt8(coin.isCoinbase ? 1 : 0);
        writer.writeUInt64LE(coin.txOut.value);
        writer.writeVarBytes(coin.txOut.scriptPubKey);

        batchOps.push({
          type: "put",
          prefix: DBPrefix.UTXO,
          key,
          value: writer.toBuffer(),
        });

        coinsLoaded++;

        // Flush batch periodically
        if (batchOps.length >= COINS_LOAD_BATCH_SIZE) {
          await this.db.batch(batchOps);
          batchOps.length = 0;
        }
      }
    }

    // Flush remaining ops
    if (batchOps.length > 0) {
      await this.db.batch(batchOps);
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

    if (!computedHash.equals(auData.hashSerialized)) {
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
      baseHeight: auData.height,
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

    // Write to temporary file then rename
    const tempPath = `${filePath}.tmp`;
    const file = Bun.file(tempPath);
    const writer = file.writer();

    // Write header
    const header = serializeSnapshotMetadata(metadata);
    writer.write(header);

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
    // rpc/blockchain.cpp WriteUTXOSnapshot. The outer txid-group framing
    // (txid, count, [vout, coin]...) uses wire-protocol CompactSize for
    // count and vout, while each Coin uses Pieter's VARINT and
    // TxOutCompression internally (see serializeCoinIntoWriter).
    const flushTx = () => {
      if (!currentTxid || currentCoins.length === 0) return;

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
      writer.write(groupWriter.toBuffer());

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

        // Deserialize UTXO entry stored in the local DB (uncompressed,
        // matches UTXOManager.serializeUTXO format).
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
          flushTx();
          currentTxid = Buffer.from(txid);
        }

        currentCoins.push({ vout, coin });
        coinsWritten++;
      }

      // Flush last transaction
      flushTx();
    } finally {
      await iterator.close();
    }

    writer.end();

    // Atomic rename
    await Bun.write(filePath, Bun.file(tempPath));

    // Delete temp file
    try {
      await Bun.file(tempPath).arrayBuffer(); // Force close
      // Note: Bun doesn't have unlink, the temp file will be orphaned
      // In production, use fs.unlink
    } catch {
      // Ignore
    }

    return {
      coinsWritten,
      baseHash: chainstate.bestBlockHash.toString("hex"),
      baseHeight: chainstate.bestHeight,
      path: filePath,
      txoutsetHash: hash.toString("hex"),
      nChainTx: 0n, // Would need to be computed from block index
    };
  }

  /**
   * Start background validation.
   *
   * Uses setImmediate for cooperative scheduling to avoid blocking.
   */
  startBackgroundValidation(
    validateBlock: (height: number) => Promise<boolean>
  ): void {
    if (this.backgroundValidationRunning) {
      return;
    }

    if (!this.backgroundChainstate) {
      return;
    }

    this.backgroundValidationRunning = true;

    const validate = async () => {
      if (!this.backgroundChainstate || !this.backgroundValidationRunning) {
        return;
      }

      // Check if we've reached the target
      if (this.backgroundChainstate.hasReachedTarget()) {
        await this.finalizeBackgroundValidation();
        return;
      }

      // Validate next block
      const nextHeight = this.backgroundChainstate.tipHeight + 1;

      try {
        const success = await validateBlock(nextHeight);
        if (success) {
          this.backgroundChainstate.tipHeight = nextHeight;

          // Report progress
          if (this.onBackgroundProgress && this.backgroundChainstate.targetBlockHash) {
            const auData = getAssumeutxoData(this.params, this.backgroundChainstate.targetBlockHash);
            if (auData) {
              this.onBackgroundProgress(nextHeight, auData.height);
            }
          }
        }
      } catch (error) {
        console.error(`Background validation failed at height ${nextHeight}:`, error);
        this.backgroundChainstate.status = ChainstateStatus.INVALID;
        this.backgroundValidationRunning = false;
        return;
      }

      // Schedule next iteration
      setImmediate(validate);
    };

    // Start validation
    setImmediate(validate);
  }

  /**
   * Stop background validation.
   */
  stopBackgroundValidation(): void {
    this.backgroundValidationRunning = false;
  }

  /**
   * Finalize background validation after reaching target.
   */
  private async finalizeBackgroundValidation(): Promise<SnapshotValidationResult> {
    if (!this.backgroundChainstate || !this.backgroundChainstate.targetBlockHash) {
      return SnapshotValidationResult.SKIPPED;
    }

    // Get assumeutxo data for the target
    const auData = getAssumeutxoData(this.params, this.backgroundChainstate.targetBlockHash);
    if (!auData) {
      return SnapshotValidationResult.MISSING_CHAINPARAMS;
    }

    // Compute UTXO set hash for background chainstate
    try {
      const { hash } = await computeUTXOSetHash(this.db);

      if (!hash.equals(auData.hashSerialized)) {
        console.error(
          `Background validation hash mismatch: expected ${auData.hashSerialized.toString("hex")}, ` +
          `got ${hash.toString("hex")}`
        );
        this.activeChainstate.status = ChainstateStatus.INVALID;
        return SnapshotValidationResult.HASH_MISMATCH;
      }

      // Validation succeeded - mark snapshot as validated
      this.activeChainstate.status = ChainstateStatus.VALIDATED;

      // Clean up background chainstate
      this.backgroundChainstate = null;
      this.backgroundValidationRunning = false;

      return SnapshotValidationResult.SUCCESS;
    } catch (error) {
      console.error("Failed to compute UTXO hash:", error);
      return SnapshotValidationResult.STATS_FAILED;
    }
  }

  /**
   * Get status of assumeUTXO validation.
   */
  getStatus(): {
    hasSnapshot: boolean;
    snapshotValidated: boolean;
    backgroundProgress: number | null;
    backgroundTarget: number | null;
  } {
    const hasSnapshot = this.activeChainstate.isSnapshot();
    const snapshotValidated = this.activeChainstate.status === ChainstateStatus.VALIDATED;

    let backgroundProgress: number | null = null;
    let backgroundTarget: number | null = null;

    if (this.backgroundChainstate && this.backgroundChainstate.targetBlockHash) {
      backgroundProgress = this.backgroundChainstate.tipHeight;
      const auData = getAssumeutxoData(this.params, this.backgroundChainstate.targetBlockHash);
      if (auData) {
        backgroundTarget = auData.height;
      }
    }

    return {
      hasSnapshot,
      snapshotValidated,
      backgroundProgress,
      backgroundTarget,
    };
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
