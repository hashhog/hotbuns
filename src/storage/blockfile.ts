/**
 * Flat file block storage (blk{nnnnn}.dat).
 *
 * Stores blocks in flat files matching Bitcoin Core's format:
 * - Each block is prefixed with [4-byte magic][4-byte size LE]
 * - Files are capped at MAX_BLOCKFILE_SIZE (128 MiB)
 * - Pre-allocation in BLOCKFILE_CHUNK_SIZE (16 MiB) chunks for performance
 *
 * Reference: Bitcoin Core's blockstorage.cpp and flatfile.cpp
 */

import { mkdir, stat } from "node:fs/promises";
import { join } from "node:path";
import { BufferWriter, BufferReader } from "../wire/serialization.js";

/** Maximum size of a single block file (128 MiB). */
export const MAX_BLOCKFILE_SIZE = 0x8000000; // 128 * 1024 * 1024

/** Pre-allocation chunk size (16 MiB). */
export const BLOCKFILE_CHUNK_SIZE = 0x1000000; // 16 * 1024 * 1024

/** Size of storage header: 4-byte magic + 4-byte size. */
export const STORAGE_HEADER_BYTES = 8;

/**
 * Position in a flat file.
 */
export interface FlatFilePos {
  /** File number (0-indexed). */
  fileNum: number;
  /** Byte position within file (after header). */
  pos: number;
}

/**
 * Metadata about a single block file.
 * Tracks blocks stored, sizes, and height/time ranges.
 */
export interface BlockFileInfo {
  /** Number of blocks stored in this file. */
  nBlocks: number;
  /** Number of used bytes in the block file. */
  nSize: number;
  /** Number of used bytes in the corresponding undo file. */
  nUndoSize: number;
  /** Lowest block height stored in this file. */
  nHeightFirst: number;
  /** Highest block height stored in this file. */
  nHeightLast: number;
  /** Earliest block timestamp in this file (unix time). */
  nTimeFirst: number;
  /** Latest block timestamp in this file (unix time). */
  nTimeLast: number;
}

/**
 * Create an empty BlockFileInfo.
 */
export function createEmptyBlockFileInfo(): BlockFileInfo {
  return {
    nBlocks: 0,
    nSize: 0,
    nUndoSize: 0,
    nHeightFirst: 0,
    nHeightLast: 0,
    nTimeFirst: 0,
    nTimeLast: 0,
  };
}

/**
 * Update BlockFileInfo with a new block.
 * Does NOT update nSize (caller must do that separately).
 */
export function updateBlockFileInfo(
  info: BlockFileInfo,
  height: number,
  timestamp: number
): void {
  if (info.nBlocks === 0 || height < info.nHeightFirst) {
    info.nHeightFirst = height;
  }
  if (info.nBlocks === 0 || timestamp < info.nTimeFirst) {
    info.nTimeFirst = timestamp;
  }
  info.nBlocks++;
  if (height > info.nHeightLast) {
    info.nHeightLast = height;
  }
  if (timestamp > info.nTimeLast) {
    info.nTimeLast = timestamp;
  }
}

/**
 * Serialize BlockFileInfo to bytes.
 */
export function serializeBlockFileInfo(info: BlockFileInfo): Buffer {
  const writer = new BufferWriter();
  writer.writeVarInt(info.nBlocks);
  writer.writeVarInt(info.nSize);
  writer.writeVarInt(info.nUndoSize);
  writer.writeVarInt(info.nHeightFirst);
  writer.writeVarInt(info.nHeightLast);
  writer.writeVarInt(info.nTimeFirst);
  writer.writeVarInt(info.nTimeLast);
  return writer.toBuffer();
}

/**
 * Deserialize BlockFileInfo from bytes.
 */
export function deserializeBlockFileInfo(data: Buffer): BlockFileInfo {
  const reader = new BufferReader(data);
  return {
    nBlocks: reader.readVarInt(),
    nSize: reader.readVarInt(),
    nUndoSize: reader.readVarInt(),
    nHeightFirst: reader.readVarInt(),
    nHeightLast: reader.readVarInt(),
    nTimeFirst: reader.readVarInt(),
    nTimeLast: reader.readVarInt(),
  };
}

/**
 * Block position index entry.
 * Maps block hash to its location in flat files.
 */
export interface BlockPosRecord {
  /** File number containing the block data. */
  fileNum: number;
  /** Byte offset within file (points to start of block data, after header). */
  dataPos: number;
  /** File number containing undo data (-1 if none). */
  undoFileNum: number;
  /** Byte offset of undo data (-1 if none). */
  undoPos: number;
}

/**
 * Serialize BlockPosRecord to bytes.
 */
export function serializeBlockPosRecord(record: BlockPosRecord): Buffer {
  const writer = new BufferWriter();
  writer.writeUInt32LE(record.fileNum);
  writer.writeUInt32LE(record.dataPos);
  writer.writeInt32LE(record.undoFileNum);
  writer.writeInt32LE(record.undoPos);
  return writer.toBuffer();
}

/**
 * Deserialize BlockPosRecord from bytes.
 */
export function deserializeBlockPosRecord(data: Buffer): BlockPosRecord {
  const reader = new BufferReader(data);
  return {
    fileNum: reader.readUInt32LE(),
    dataPos: reader.readUInt32LE(),
    undoFileNum: reader.readInt32LE(),
    undoPos: reader.readInt32LE(),
  };
}

/**
 * Format file number as 5-digit zero-padded string.
 */
function formatFileNumber(fileNum: number): string {
  return String(fileNum).padStart(5, "0");
}

/**
 * Encode network magic as 4-byte little-endian buffer.
 */
function encodeMagic(magic: number): Buffer {
  const buf = Buffer.alloc(4);
  buf.writeUInt32LE(magic, 0);
  return buf;
}

/**
 * Block file manager.
 * Handles reading and writing block data to blk{nnnnn}.dat files.
 */
export class BlockFileManager {
  private dataDir: string;
  private networkMagic: number;
  private currentFileNum: number;
  private currentFileSize: number;
  private blockFileInfo: Map<number, BlockFileInfo>;
  private initialized: boolean;
  private preAllocatedSize: Map<number, number>; // Track pre-allocated space

  constructor(dataDir: string, networkMagic: number) {
    this.dataDir = dataDir;
    this.networkMagic = networkMagic;
    this.currentFileNum = 0;
    this.currentFileSize = 0;
    this.blockFileInfo = new Map();
    this.initialized = false;
    this.preAllocatedSize = new Map();
  }

  /**
   * Initialize the block file manager.
   * Creates the blocks directory and scans existing files.
   */
  async init(): Promise<void> {
    if (this.initialized) return;

    const blocksDir = join(this.dataDir, "blocks");
    await mkdir(blocksDir, { recursive: true });

    await this.scanExistingFiles();

    this.initialized = true;
  }

  /**
   * Scan existing block files to determine current state.
   */
  private async scanExistingFiles(): Promise<void> {
    const blocksDir = join(this.dataDir, "blocks");

    try {
      const glob = new Bun.Glob("blk*.dat");
      const files: string[] = [];

      for await (const file of glob.scan(blocksDir)) {
        files.push(file);
      }

      // Sort files to process in order
      files.sort();

      for (const file of files) {
        const match = file.match(/blk(\d{5})\.dat/);
        if (match) {
          const fileNum = parseInt(match[1], 10);
          const filePath = join(blocksDir, file);

          try {
            const fileStat = await stat(filePath);
            const fileSize = fileStat.size;

            if (fileNum >= this.currentFileNum) {
              this.currentFileNum = fileNum;
              this.currentFileSize = fileSize;
            }

            // Initialize BlockFileInfo if not already loaded from DB
            if (!this.blockFileInfo.has(fileNum)) {
              // We'll need to scan the file or load from DB
              // For now, create empty info (actual loading from DB happens separately)
              this.blockFileInfo.set(fileNum, {
                ...createEmptyBlockFileInfo(),
                nSize: fileSize,
              });
            }
          } catch {
            // File doesn't exist or can't be read
          }
        }
      }
    } catch {
      // Directory doesn't exist yet, use defaults
      this.currentFileNum = 0;
      this.currentFileSize = 0;
    }
  }

  /**
   * Get the path to a block file.
   */
  getBlockFilePath(fileNum: number): string {
    return join(
      this.dataDir,
      "blocks",
      `blk${formatFileNumber(fileNum)}.dat`
    );
  }

  /**
   * Find the next position to write a block.
   * Handles file rotation when current file is full.
   */
  async findNextBlockPos(
    blockSize: number,
    height: number,
    timestamp: number
  ): Promise<FlatFilePos> {
    await this.init();

    const totalSize = blockSize + STORAGE_HEADER_BYTES;

    // Check if we need a new file
    if (this.currentFileSize + totalSize > MAX_BLOCKFILE_SIZE) {
      // Finalize current file before moving to next
      this.currentFileNum++;
      this.currentFileSize = 0;
    }

    // Ensure we have BlockFileInfo for this file
    if (!this.blockFileInfo.has(this.currentFileNum)) {
      this.blockFileInfo.set(this.currentFileNum, createEmptyBlockFileInfo());
    }

    // Pre-allocate space if needed
    await this.maybePreAllocate(this.currentFileNum, totalSize);

    const pos: FlatFilePos = {
      fileNum: this.currentFileNum,
      pos: this.currentFileSize + STORAGE_HEADER_BYTES, // Position after the header
    };

    // Update file info
    const info = this.blockFileInfo.get(this.currentFileNum)!;
    updateBlockFileInfo(info, height, timestamp);
    info.nSize += totalSize;

    // Update tracking
    this.currentFileSize += totalSize;

    return pos;
  }

  /**
   * Pre-allocate file space in chunks for better write performance.
   */
  private async maybePreAllocate(
    fileNum: number,
    addSize: number
  ): Promise<void> {
    const currentPreAlloc = this.preAllocatedSize.get(fileNum) ?? 0;
    const targetSize = this.currentFileSize + addSize;

    // Check if we need more pre-allocated space
    if (targetSize <= currentPreAlloc) {
      return;
    }

    // Calculate new pre-allocation size
    const oldChunks = Math.floor(currentPreAlloc / BLOCKFILE_CHUNK_SIZE);
    const newChunks = Math.ceil(targetSize / BLOCKFILE_CHUNK_SIZE);

    if (newChunks > oldChunks) {
      const newPreAllocSize = newChunks * BLOCKFILE_CHUNK_SIZE;
      const filePath = this.getBlockFilePath(fileNum);

      try {
        const file = Bun.file(filePath);
        let existingSize = 0;

        if (await file.exists()) {
          existingSize = file.size;
        }

        // Only pre-allocate if we need more space
        if (newPreAllocSize > existingSize) {
          // Create a sparse file or extend the existing one
          // Bun doesn't have truncate, so we append zeros
          const allocSize = newPreAllocSize - existingSize;
          if (allocSize > 0) {
            // Read existing content and extend
            let existing = Buffer.alloc(0);
            if (await file.exists()) {
              existing = Buffer.from(await file.arrayBuffer());
            }
            const newData = Buffer.concat([
              existing,
              Buffer.alloc(allocSize, 0),
            ]);
            await Bun.write(filePath, newData);
          }
        }

        this.preAllocatedSize.set(fileNum, newPreAllocSize);
      } catch {
        // Pre-allocation failed, not fatal - writes will still work
      }
    }
  }

  /**
   * Write a block to disk.
   * Returns the position where the block was written.
   */
  async writeBlock(
    rawBlock: Buffer,
    height: number,
    timestamp: number
  ): Promise<FlatFilePos> {
    await this.init();

    const pos = await this.findNextBlockPos(rawBlock.length, height, timestamp);

    const filePath = this.getBlockFilePath(pos.fileNum);

    // Prepare header: [magic (4 bytes)][size (4 bytes LE)]
    const header = Buffer.alloc(STORAGE_HEADER_BYTES);
    header.writeUInt32LE(this.networkMagic, 0);
    header.writeUInt32LE(rawBlock.length, 4);

    // Read existing file content
    const file = Bun.file(filePath);
    let existingData = Buffer.alloc(0);

    if (await file.exists()) {
      const arrayBuffer = await file.arrayBuffer();
      existingData = Buffer.from(arrayBuffer);
    }

    // Calculate write position (header + data)
    const headerPos = pos.pos - STORAGE_HEADER_BYTES;

    // Ensure buffer is large enough
    const requiredSize = headerPos + STORAGE_HEADER_BYTES + rawBlock.length;
    let newData: Buffer;

    if (existingData.length >= requiredSize) {
      newData = existingData;
    } else {
      newData = Buffer.alloc(requiredSize);
      existingData.copy(newData, 0);
    }

    // Write header and block data
    header.copy(newData, headerPos);
    rawBlock.copy(newData, headerPos + STORAGE_HEADER_BYTES);

    await Bun.write(filePath, newData);

    return pos;
  }

  /**
   * Read a block from disk.
   * Validates magic number and size before returning data.
   */
  async readBlock(pos: FlatFilePos): Promise<Buffer> {
    await this.init();

    const filePath = this.getBlockFilePath(pos.fileNum);
    const file = Bun.file(filePath);

    if (!(await file.exists())) {
      throw new Error(`Block file not found: ${filePath}`);
    }

    const fileData = Buffer.from(await file.arrayBuffer());
    const headerPos = pos.pos - STORAGE_HEADER_BYTES;

    if (headerPos < 0) {
      throw new Error(`Invalid block position: header position ${headerPos} < 0`);
    }

    if (headerPos + STORAGE_HEADER_BYTES > fileData.length) {
      throw new Error(
        `Block position ${pos.pos} exceeds file size ${fileData.length}`
      );
    }

    // Read and validate header
    const magic = fileData.readUInt32LE(headerPos);
    const blockSize = fileData.readUInt32LE(headerPos + 4);

    if (magic !== this.networkMagic) {
      throw new Error(
        `Block magic mismatch: got 0x${magic.toString(16)}, expected 0x${this.networkMagic.toString(16)}`
      );
    }

    if (blockSize > MAX_BLOCKFILE_SIZE) {
      throw new Error(`Block size ${blockSize} exceeds maximum`);
    }

    const blockEnd = pos.pos + blockSize;
    if (blockEnd > fileData.length) {
      throw new Error(
        `Block data extends beyond file: ${blockEnd} > ${fileData.length}`
      );
    }

    // Return block data
    return fileData.subarray(pos.pos, blockEnd);
  }

  /**
   * Get BlockFileInfo for a file.
   */
  getBlockFileInfo(fileNum: number): BlockFileInfo | undefined {
    return this.blockFileInfo.get(fileNum);
  }

  /**
   * Set BlockFileInfo for a file (used when loading from DB).
   */
  setBlockFileInfo(fileNum: number, info: BlockFileInfo): void {
    this.blockFileInfo.set(fileNum, info);
  }

  /**
   * Get all BlockFileInfo entries.
   */
  getAllBlockFileInfo(): Map<number, BlockFileInfo> {
    return new Map(this.blockFileInfo);
  }

  /**
   * Get the current file number.
   */
  getCurrentFileNum(): number {
    return this.currentFileNum;
  }

  /**
   * Get the current file size.
   */
  getCurrentFileSize(): number {
    return this.currentFileSize;
  }

  /**
   * Update undo size for a file.
   */
  updateUndoSize(fileNum: number, undoSize: number): void {
    const info = this.blockFileInfo.get(fileNum);
    if (info) {
      info.nUndoSize = undoSize;
    }
  }

  /**
   * Check if a block file exists.
   */
  async blockFileExists(fileNum: number): Promise<boolean> {
    const filePath = this.getBlockFilePath(fileNum);
    const file = Bun.file(filePath);
    return file.exists();
  }
}

/**
 * Combined block storage manager.
 * Integrates flat file storage with database index.
 */
export class BlockStore {
  private fileManager: BlockFileManager;

  constructor(dataDir: string, networkMagic: number) {
    this.fileManager = new BlockFileManager(dataDir, networkMagic);
  }

  /**
   * Initialize the block store.
   */
  async init(): Promise<void> {
    await this.fileManager.init();
  }

  /**
   * Save a block to disk.
   * Returns the position where the block was written.
   */
  async saveBlockToDisk(
    rawBlock: Buffer,
    height: number,
    timestamp: number
  ): Promise<FlatFilePos> {
    return this.fileManager.writeBlock(rawBlock, height, timestamp);
  }

  /**
   * Read a block from disk.
   */
  async readBlockFromDisk(pos: FlatFilePos): Promise<Buffer> {
    return this.fileManager.readBlock(pos);
  }

  /**
   * Get BlockFileInfo for a file number.
   */
  getBlockFileInfo(fileNum: number): BlockFileInfo | undefined {
    return this.fileManager.getBlockFileInfo(fileNum);
  }

  /**
   * Set BlockFileInfo for a file (when loading from database).
   */
  setBlockFileInfo(fileNum: number, info: BlockFileInfo): void {
    this.fileManager.setBlockFileInfo(fileNum, info);
  }

  /**
   * Get all BlockFileInfo entries.
   */
  getAllBlockFileInfo(): Map<number, BlockFileInfo> {
    return this.fileManager.getAllBlockFileInfo();
  }

  /**
   * Get the current file number and size.
   */
  getCurrentPosition(): { fileNum: number; size: number } {
    return {
      fileNum: this.fileManager.getCurrentFileNum(),
      size: this.fileManager.getCurrentFileSize(),
    };
  }

  /**
   * Get the underlying file manager (for advanced operations).
   */
  getFileManager(): BlockFileManager {
    return this.fileManager;
  }
}
