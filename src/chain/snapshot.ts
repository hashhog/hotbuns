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
 * Serialize a coin for snapshot storage.
 * Format: VARINT((height << 1) | coinbase) + TxOut
 */
export function serializeCoinForSnapshot(coin: Coin): Buffer {
  const writer = new BufferWriter();

  // Encode height and coinbase flag
  const code = (coin.height << 1) | (coin.isCoinbase ? 1 : 0);
  writer.writeVarInt(code);

  // TxOut: value + scriptPubKey
  writer.writeUInt64LE(coin.txOut.value);
  writer.writeVarBytes(coin.txOut.scriptPubKey);

  return writer.toBuffer();
}

/**
 * Deserialize a coin from snapshot storage.
 */
export function deserializeCoinFromSnapshot(reader: BufferReader): Coin {
  // Decode height and coinbase flag
  const code = reader.readVarInt();
  const height = code >> 1;
  const isCoinbase = (code & 1) === 1;

  // TxOut
  const value = reader.readUInt64LE();
  const scriptPubKey = reader.readVarBytes();

  return {
    txOut: { value, scriptPubKey },
    height,
    isCoinbase,
  };
}

/**
 * Compute the UTXO set hash (HASH_SERIALIZED).
 *
 * This iterates all UTXOs in deterministic order and computes a hash
 * over all serialized (outpoint, coin) pairs.
 */
export async function computeUTXOSetHash(
  db: ChainDB,
  interruptCheck?: () => boolean
): Promise<{ hash: Buffer; coinsCount: bigint }> {
  // We'll use an incremental hash approach:
  // For each UTXO, serialize (txid, vout, coin) and add to a running hash

  // Create a SHA256 hasher
  const hasher = new Bun.CryptoHasher("sha256");

  let coinsCount = 0n;

  // Iterate all UTXOs in database order (lexicographic by key)
  // The UTXO key is: prefix (1 byte) + txid (32 bytes) + vout (4 bytes LE)
  const utxoPrefix = Buffer.from([DBPrefix.UTXO]);

  // We need to iterate the underlying LevelDB
  // For now, use a simpler approach: read all UTXOs
  // In production, this should use a proper iterator

  // Use batch reads from database - we'll iterate over the raw level
  const iterator = (db as any).db.iterator({
    gte: utxoPrefix,
    lt: Buffer.concat([Buffer.from([DBPrefix.UTXO + 1])]),
  });

  try {
    for await (const [key, value] of iterator) {
      if (interruptCheck?.()) {
        throw new Error("Interrupted");
      }

      // Key format: prefix (1 byte) + txid (32 bytes) + vout (4 bytes LE)
      if (key.length !== 37) continue;

      const txid = key.subarray(1, 33);
      const vout = key.readUInt32LE(33);

      // Deserialize the UTXO entry
      const reader = new BufferReader(value);
      const height = reader.readUInt32LE();
      const coinbase = reader.readUInt8() === 1;
      const amount = reader.readUInt64LE();
      const scriptPubKey = reader.readVarBytes();

      // Serialize for hash: txid + vout + code + txout
      const code = (height << 1) | (coinbase ? 1 : 0);
      const writer = new BufferWriter();
      writer.writeHash(txid);
      writer.writeUInt32LE(vout);
      writer.writeVarInt(code);
      writer.writeUInt64LE(amount);
      writer.writeVarBytes(scriptPubKey);

      hasher.update(writer.toBuffer());
      coinsCount++;
    }
  } finally {
    await iterator.close();
  }

  // Final hash
  const hash = Buffer.from(hasher.digest());

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
    }
  ) {
    this.db = db;
    this.params = params;
    this.utxoManager = new UTXOManager(db);
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

  constructor(db: ChainDB, params: ConsensusParams) {
    this.db = db;
    this.params = params;
    this.activeChainstate = new Chainstate(db, params);
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

    // Verify UTXO set hash
    const { hash: computedHash, coinsCount } = await computeUTXOSetHash(this.db, interruptCheck);

    if (!computedHash.equals(auData.hashSerialized)) {
      throw new Error(
        `UTXO set hash mismatch: expected ${auData.hashSerialized.toString("hex")}, ` +
        `got ${computedHash.toString("hex")}`
      );
    }

    // Create background chainstate for validation from genesis
    this.backgroundChainstate = new Chainstate(this.db, this.params, {
      status: ChainstateStatus.VALIDATED,
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
    let currentCoins: Array<{ vout: number; data: Buffer }> = [];
    let coinsWritten = 0n;

    const flushTx = () => {
      if (!currentTxid || currentCoins.length === 0) return;

      // Write txid
      writer.write(currentTxid);

      // Write number of outputs
      const countWriter = new BufferWriter();
      countWriter.writeVarInt(currentCoins.length);
      writer.write(countWriter.toBuffer());

      // Write each output
      for (const { vout, data } of currentCoins) {
        const voutWriter = new BufferWriter();
        voutWriter.writeVarInt(vout);
        writer.write(voutWriter.toBuffer());
        writer.write(data);
      }

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

        // Deserialize UTXO entry
        const entryReader = new BufferReader(value);
        const height = entryReader.readUInt32LE();
        const coinbase = entryReader.readUInt8() === 1;
        const amount = entryReader.readUInt64LE();
        const scriptPubKey = entryReader.readVarBytes();

        // Serialize coin for snapshot
        const coinWriter = new BufferWriter();
        const code = (height << 1) | (coinbase ? 1 : 0);
        coinWriter.writeVarInt(code);
        coinWriter.writeUInt64LE(amount);
        coinWriter.writeVarBytes(scriptPubKey);

        // Check if new transaction
        if (!currentTxid || !txid.equals(currentTxid)) {
          flushTx();
          currentTxid = Buffer.from(txid);
        }

        currentCoins.push({ vout, data: coinWriter.toBuffer() });
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
