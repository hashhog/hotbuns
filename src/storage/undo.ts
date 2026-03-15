/**
 * Undo data storage for block disconnect during reorganizations.
 *
 * Stores the UTXOs consumed by each block's transactions so blocks can be
 * disconnected without re-validating the entire chain. Follows Bitcoin Core's
 * undo data format from undo.h and blockstorage.cpp.
 *
 * Structure:
 * - TxUndo: Undo data for a single transaction (one entry per spent input)
 * - BlockUndo: Undo data for a block (one TxUndo per non-coinbase transaction)
 *
 * Storage:
 * - rev{nnnnn}.dat files alongside blk{nnnnn}.dat
 * - Checksum: SHA256(prevBlockHash || undoData) for corruption detection
 */

import { BufferWriter, BufferReader } from "../wire/serialization.js";
import { hash256 } from "../crypto/primitives.js";
import { mkdir } from "node:fs/promises";
import { join } from "node:path";

/** Maximum size of a single rev file (128 MB). */
const MAX_REV_FILE_SIZE = 128 * 1024 * 1024;

/**
 * A single spent output's undo information.
 * Corresponds to Bitcoin Core's Coin structure in undo context.
 */
export interface TxOut {
  /** Satoshi value of the output. */
  value: bigint;
  /** scriptPubKey of the output. */
  scriptPubKey: Buffer;
}

/**
 * Undo data for a single spent input.
 * Contains the TxOut that was consumed plus metadata.
 */
export interface TxInUndo {
  /** Height at which the output was created. */
  height: number;
  /** Whether the output was from a coinbase transaction. */
  isCoinbase: boolean;
  /** The spent output (value + scriptPubKey). */
  output: TxOut;
}

/**
 * Undo data for a single transaction.
 * One entry per input (prevout) that was spent.
 */
export interface TxUndo {
  /** Spent outputs in order of inputs. */
  prevOutputs: TxInUndo[];
}

/**
 * Undo data for an entire block.
 * One TxUndo per non-coinbase transaction (coinbase has no inputs to spend).
 */
export interface BlockUndo {
  /** Transaction undo data (excludes coinbase). */
  txUndo: TxUndo[];
}

/**
 * Serialize a TxInUndo to bytes.
 * Format matches Bitcoin Core: packed height/coinbase, dummy version, compressed output.
 */
export function serializeTxInUndo(undo: TxInUndo): Buffer {
  const writer = new BufferWriter();

  // Encode height * 2 + coinbase as varint (Bitcoin Core format)
  const code = undo.height * 2 + (undo.isCoinbase ? 1 : 0);
  writer.writeVarInt(code);

  // For heights > 0, write dummy version byte (backward compatibility)
  if (undo.height > 0) {
    writer.writeUInt8(0);
  }

  // Write the output (value + scriptPubKey)
  writer.writeUInt64LE(undo.output.value);
  writer.writeVarBytes(undo.output.scriptPubKey);

  return writer.toBuffer();
}

/**
 * Deserialize a TxInUndo from bytes.
 */
export function deserializeTxInUndo(reader: BufferReader): TxInUndo {
  const code = reader.readVarInt();
  const height = code >>> 1;
  const isCoinbase = (code & 1) === 1;

  // For heights > 0, read and discard dummy version byte
  if (height > 0) {
    reader.readUInt8();
  }

  // Read the output
  const value = reader.readUInt64LE();
  const scriptPubKey = reader.readVarBytes();

  return {
    height,
    isCoinbase,
    output: { value, scriptPubKey },
  };
}

/**
 * Serialize a TxUndo to bytes.
 */
export function serializeTxUndo(undo: TxUndo): Buffer {
  const writer = new BufferWriter();
  writer.writeVarInt(undo.prevOutputs.length);

  for (const prevOutput of undo.prevOutputs) {
    writer.writeBytes(serializeTxInUndo(prevOutput));
  }

  return writer.toBuffer();
}

/**
 * Deserialize a TxUndo from bytes.
 */
export function deserializeTxUndo(reader: BufferReader): TxUndo {
  const count = reader.readVarInt();
  const prevOutputs: TxInUndo[] = [];

  for (let i = 0; i < count; i++) {
    prevOutputs.push(deserializeTxInUndo(reader));
  }

  return { prevOutputs };
}

/**
 * Serialize a BlockUndo to bytes.
 */
export function serializeBlockUndo(undo: BlockUndo): Buffer {
  const writer = new BufferWriter();
  writer.writeVarInt(undo.txUndo.length);

  for (const txUndo of undo.txUndo) {
    writer.writeBytes(serializeTxUndo(txUndo));
  }

  return writer.toBuffer();
}

/**
 * Deserialize a BlockUndo from bytes.
 */
export function deserializeBlockUndo(data: Buffer): BlockUndo {
  const reader = new BufferReader(data);
  const count = reader.readVarInt();
  const txUndo: TxUndo[] = [];

  for (let i = 0; i < count; i++) {
    txUndo.push(deserializeTxUndo(reader));
  }

  return { txUndo };
}

/**
 * Calculate checksum for undo data.
 * Checksum = SHA256d(prevBlockHash || undoData)
 * This allows detecting corruption and wrong file positions.
 */
export function calculateUndoChecksum(
  prevBlockHash: Buffer,
  undoData: Buffer
): Buffer {
  const combined = Buffer.concat([prevBlockHash, undoData]);
  return hash256(combined);
}

/**
 * Verify undo data checksum.
 */
export function verifyUndoChecksum(
  prevBlockHash: Buffer,
  undoData: Buffer,
  checksum: Buffer
): boolean {
  const expected = calculateUndoChecksum(prevBlockHash, undoData);
  return expected.equals(checksum);
}

/**
 * Serialize undo data with checksum for storage.
 * Format: [undoData] [checksum (32 bytes)]
 */
export function serializeUndoDataWithChecksum(
  prevBlockHash: Buffer,
  blockUndo: BlockUndo
): Buffer {
  const undoData = serializeBlockUndo(blockUndo);
  const checksum = calculateUndoChecksum(prevBlockHash, undoData);
  return Buffer.concat([undoData, checksum]);
}

/**
 * Deserialize and verify undo data with checksum.
 * Throws if checksum verification fails.
 */
export function deserializeUndoDataWithChecksum(
  prevBlockHash: Buffer,
  data: Buffer
): BlockUndo {
  if (data.length < 32) {
    throw new Error("Undo data too short to contain checksum");
  }

  const undoData = data.subarray(0, data.length - 32);
  const checksum = data.subarray(data.length - 32);

  if (!verifyUndoChecksum(prevBlockHash, undoData, checksum)) {
    throw new Error("Undo data checksum verification failed");
  }

  return deserializeBlockUndo(undoData);
}

/**
 * Format file number as 5-digit string (e.g., "00001").
 */
function formatFileNumber(fileNum: number): string {
  return fileNum.toString().padStart(5, "0");
}

/**
 * Undo data file manager.
 * Handles reading and writing rev*.dat files.
 */
export class UndoFileManager {
  private dataDir: string;
  private currentFileNum: number;
  private currentFilePos: number;
  private initialized: boolean;

  constructor(dataDir: string) {
    this.dataDir = dataDir;
    this.currentFileNum = 0;
    this.currentFilePos = 0;
    this.initialized = false;
  }

  /**
   * Initialize the undo file manager.
   * Creates the blocks directory if it doesn't exist.
   */
  async init(): Promise<void> {
    if (this.initialized) return;

    const blocksDir = join(this.dataDir, "blocks");
    await mkdir(blocksDir, { recursive: true });

    // Scan existing rev files to find current position
    await this.scanExistingFiles();

    this.initialized = true;
  }

  /**
   * Scan existing rev files to determine current file number and position.
   */
  private async scanExistingFiles(): Promise<void> {
    const blocksDir = join(this.dataDir, "blocks");

    try {
      const files = await Bun.file(blocksDir).exists()
        ? []
        : []; // Will be populated if dir exists

      // Use glob to find rev files
      const glob = new Bun.Glob("rev*.dat");
      for await (const file of glob.scan(blocksDir)) {
        const match = file.match(/rev(\d{5})\.dat/);
        if (match) {
          const fileNum = parseInt(match[1], 10);
          if (fileNum >= this.currentFileNum) {
            this.currentFileNum = fileNum;
            // Get file size to determine position
            const filePath = join(blocksDir, file);
            const stat = Bun.file(filePath);
            const size = stat.size;
            this.currentFilePos = size;
          }
        }
      }
    } catch {
      // Directory doesn't exist yet or empty, use defaults
      this.currentFileNum = 0;
      this.currentFilePos = 0;
    }
  }

  /**
   * Get the path to a rev file.
   */
  private getRevFilePath(fileNum: number): string {
    return join(this.dataDir, "blocks", `rev${formatFileNumber(fileNum)}.dat`);
  }

  /**
   * Write undo data for a block.
   * Returns the file position where the data was written.
   */
  async writeBlockUndo(
    blockHash: Buffer,
    prevBlockHash: Buffer,
    blockUndo: BlockUndo
  ): Promise<{ fileNum: number; filePos: number }> {
    await this.init();

    const dataWithChecksum = serializeUndoDataWithChecksum(
      prevBlockHash,
      blockUndo
    );

    // Check if we need to start a new file
    if (this.currentFilePos + dataWithChecksum.length > MAX_REV_FILE_SIZE) {
      this.currentFileNum++;
      this.currentFilePos = 0;
    }

    const filePath = this.getRevFilePath(this.currentFileNum);
    const filePos = this.currentFilePos;

    // Write header: [data length (4 bytes)] [data]
    const header = Buffer.alloc(4);
    header.writeUInt32LE(dataWithChecksum.length, 0);

    // Append to file
    const file = Bun.file(filePath);
    let existingData = Buffer.alloc(0);

    if (await file.exists()) {
      existingData = Buffer.from(await file.arrayBuffer());
    }

    const newData = Buffer.concat([existingData, header, dataWithChecksum]);
    await Bun.write(filePath, newData);

    this.currentFilePos = newData.length;

    return { fileNum: this.currentFileNum, filePos };
  }

  /**
   * Read undo data for a block.
   */
  async readBlockUndo(
    prevBlockHash: Buffer,
    fileNum: number,
    filePos: number
  ): Promise<BlockUndo> {
    const filePath = this.getRevFilePath(fileNum);
    const file = Bun.file(filePath);

    if (!(await file.exists())) {
      throw new Error(`Undo file not found: ${filePath}`);
    }

    const fileData = Buffer.from(await file.arrayBuffer());

    if (filePos + 4 > fileData.length) {
      throw new Error("Invalid undo file position");
    }

    // Read header
    const dataLength = fileData.readUInt32LE(filePos);

    if (filePos + 4 + dataLength > fileData.length) {
      throw new Error("Undo data extends beyond file");
    }

    const data = fileData.subarray(filePos + 4, filePos + 4 + dataLength);

    return deserializeUndoDataWithChecksum(prevBlockHash, data);
  }

  /**
   * Get current file number and position.
   */
  getCurrentPosition(): { fileNum: number; filePos: number } {
    return {
      fileNum: this.currentFileNum,
      filePos: this.currentFilePos,
    };
  }
}

/**
 * Undo data manager that integrates file storage with database index.
 * Coordinates between rev*.dat files and the database for block->undo lookup.
 */
export class UndoManager {
  private fileManager: UndoFileManager;

  constructor(dataDir: string) {
    this.fileManager = new UndoFileManager(dataDir);
  }

  /**
   * Initialize the undo manager.
   */
  async init(): Promise<void> {
    await this.fileManager.init();
  }

  /**
   * Store undo data for a block.
   * Returns position info to store in block index.
   */
  async storeBlockUndo(
    blockHash: Buffer,
    prevBlockHash: Buffer,
    blockUndo: BlockUndo
  ): Promise<{ fileNum: number; filePos: number }> {
    return this.fileManager.writeBlockUndo(blockHash, prevBlockHash, blockUndo);
  }

  /**
   * Load undo data for a block.
   */
  async loadBlockUndo(
    prevBlockHash: Buffer,
    fileNum: number,
    filePos: number
  ): Promise<BlockUndo> {
    return this.fileManager.readBlockUndo(prevBlockHash, fileNum, filePos);
  }

  /**
   * Create a BlockUndo from spent UTXO information.
   * Groups spent outputs by transaction (excluding coinbase).
   *
   * @param spentByTx Map of transaction index -> spent outputs for that tx
   * @param txCount Total number of transactions in the block
   */
  static createBlockUndo(
    spentByTx: Map<number, TxInUndo[]>,
    txCount: number
  ): BlockUndo {
    const txUndo: TxUndo[] = [];

    // Start from index 1 to skip coinbase
    for (let txIndex = 1; txIndex < txCount; txIndex++) {
      const spent = spentByTx.get(txIndex) || [];
      txUndo.push({ prevOutputs: spent });
    }

    return { txUndo };
  }
}

// Re-export for backward compatibility with existing code that uses simpler format
export type { SpentUTXO } from "../chain/utxo.js";
