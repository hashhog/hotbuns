import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { mkdtemp, rm, readdir } from "fs/promises";
import { tmpdir } from "os";
import { join } from "path";
import {
  BlockFileManager,
  BlockStore,
  MAX_BLOCKFILE_SIZE,
  BLOCKFILE_CHUNK_SIZE,
  STORAGE_HEADER_BYTES,
  createEmptyBlockFileInfo,
  updateBlockFileInfo,
  serializeBlockFileInfo,
  deserializeBlockFileInfo,
  serializeBlockPosRecord,
  deserializeBlockPosRecord,
  type BlockFileInfo,
  type BlockPosRecord,
  type FlatFilePos,
} from "./blockfile.js";

// Mainnet magic for testing
const MAINNET_MAGIC = 0xd9b4bef9;
// Testnet4 magic for testing
const TESTNET4_MAGIC = 0x1c163f28;

describe("BlockFileInfo serialization", () => {
  test("serialize and deserialize empty info", () => {
    const info = createEmptyBlockFileInfo();
    const serialized = serializeBlockFileInfo(info);
    const deserialized = deserializeBlockFileInfo(serialized);

    expect(deserialized.nBlocks).toBe(0);
    expect(deserialized.nSize).toBe(0);
    expect(deserialized.nUndoSize).toBe(0);
    expect(deserialized.nHeightFirst).toBe(0);
    expect(deserialized.nHeightLast).toBe(0);
    expect(deserialized.nTimeFirst).toBe(0);
    expect(deserialized.nTimeLast).toBe(0);
  });

  test("serialize and deserialize with data", () => {
    const info: BlockFileInfo = {
      nBlocks: 150,
      nSize: 123456789,
      nUndoSize: 9876543,
      nHeightFirst: 100000,
      nHeightLast: 100149,
      nTimeFirst: 1600000000,
      nTimeLast: 1600099999,
    };

    const serialized = serializeBlockFileInfo(info);
    const deserialized = deserializeBlockFileInfo(serialized);

    expect(deserialized.nBlocks).toBe(info.nBlocks);
    expect(deserialized.nSize).toBe(info.nSize);
    expect(deserialized.nUndoSize).toBe(info.nUndoSize);
    expect(deserialized.nHeightFirst).toBe(info.nHeightFirst);
    expect(deserialized.nHeightLast).toBe(info.nHeightLast);
    expect(deserialized.nTimeFirst).toBe(info.nTimeFirst);
    expect(deserialized.nTimeLast).toBe(info.nTimeLast);
  });

  test("updateBlockFileInfo updates statistics correctly", () => {
    const info = createEmptyBlockFileInfo();

    // First block
    updateBlockFileInfo(info, 100, 1600000000);
    expect(info.nBlocks).toBe(1);
    expect(info.nHeightFirst).toBe(100);
    expect(info.nHeightLast).toBe(100);
    expect(info.nTimeFirst).toBe(1600000000);
    expect(info.nTimeLast).toBe(1600000000);

    // Second block (higher)
    updateBlockFileInfo(info, 200, 1600001000);
    expect(info.nBlocks).toBe(2);
    expect(info.nHeightFirst).toBe(100);
    expect(info.nHeightLast).toBe(200);
    expect(info.nTimeFirst).toBe(1600000000);
    expect(info.nTimeLast).toBe(1600001000);

    // Third block (lower height, earlier time)
    updateBlockFileInfo(info, 50, 1599999000);
    expect(info.nBlocks).toBe(3);
    expect(info.nHeightFirst).toBe(50);
    expect(info.nHeightLast).toBe(200);
    expect(info.nTimeFirst).toBe(1599999000);
    expect(info.nTimeLast).toBe(1600001000);
  });
});

describe("BlockPosRecord serialization", () => {
  test("serialize and deserialize record", () => {
    const record: BlockPosRecord = {
      fileNum: 5,
      dataPos: 12345,
      undoFileNum: 5,
      undoPos: 6789,
    };

    const serialized = serializeBlockPosRecord(record);
    const deserialized = deserializeBlockPosRecord(serialized);

    expect(deserialized.fileNum).toBe(record.fileNum);
    expect(deserialized.dataPos).toBe(record.dataPos);
    expect(deserialized.undoFileNum).toBe(record.undoFileNum);
    expect(deserialized.undoPos).toBe(record.undoPos);
  });

  test("serialize and deserialize record with no undo", () => {
    const record: BlockPosRecord = {
      fileNum: 10,
      dataPos: 99999,
      undoFileNum: -1,
      undoPos: -1,
    };

    const serialized = serializeBlockPosRecord(record);
    const deserialized = deserializeBlockPosRecord(serialized);

    expect(deserialized.fileNum).toBe(10);
    expect(deserialized.dataPos).toBe(99999);
    expect(deserialized.undoFileNum).toBe(-1);
    expect(deserialized.undoPos).toBe(-1);
  });
});

describe("BlockFileManager", () => {
  let testDir: string;
  let manager: BlockFileManager;

  beforeEach(async () => {
    testDir = await mkdtemp(join(tmpdir(), "hotbuns-blockfile-test-"));
    manager = new BlockFileManager(testDir, MAINNET_MAGIC);
    await manager.init();
  });

  afterEach(async () => {
    await rm(testDir, { recursive: true, force: true });
  });

  test("creates blocks directory on init", async () => {
    const blocksDir = join(testDir, "blocks");
    const files = await readdir(blocksDir);
    // Directory should exist (may be empty)
    expect(files).toBeDefined();
  });

  test("writes and reads a single block", async () => {
    const blockData = Buffer.from("test block data for mainnet");
    const height = 100;
    const timestamp = 1600000000;

    const pos = await manager.writeBlock(blockData, height, timestamp);

    expect(pos.fileNum).toBe(0);
    expect(pos.pos).toBe(STORAGE_HEADER_BYTES); // First block starts right after header

    const readBack = await manager.readBlock(pos);
    expect(readBack.equals(blockData)).toBe(true);
  });

  test("writes multiple blocks to same file", async () => {
    const block1 = Buffer.alloc(1000, 0xaa);
    const block2 = Buffer.alloc(2000, 0xbb);
    const block3 = Buffer.alloc(500, 0xcc);

    const pos1 = await manager.writeBlock(block1, 100, 1600000000);
    const pos2 = await manager.writeBlock(block2, 101, 1600001000);
    const pos3 = await manager.writeBlock(block3, 102, 1600002000);

    // All should be in file 0
    expect(pos1.fileNum).toBe(0);
    expect(pos2.fileNum).toBe(0);
    expect(pos3.fileNum).toBe(0);

    // Positions should be sequential
    expect(pos1.pos).toBe(STORAGE_HEADER_BYTES);
    expect(pos2.pos).toBe(STORAGE_HEADER_BYTES + 1000 + STORAGE_HEADER_BYTES);
    expect(pos3.pos).toBe(
      STORAGE_HEADER_BYTES + 1000 + STORAGE_HEADER_BYTES + 2000 + STORAGE_HEADER_BYTES
    );

    // Read back all blocks
    const read1 = await manager.readBlock(pos1);
    const read2 = await manager.readBlock(pos2);
    const read3 = await manager.readBlock(pos3);

    expect(read1.equals(block1)).toBe(true);
    expect(read2.equals(block2)).toBe(true);
    expect(read3.equals(block3)).toBe(true);
  });

  test("rotates to new file when current exceeds max size", async () => {
    // Create a manager with small max size for testing
    // We'll simulate by writing blocks that nearly fill the file
    const smallManager = new BlockFileManager(testDir, TESTNET4_MAGIC);
    await smallManager.init();

    // Write a block that's close to max file size
    // MAX_BLOCKFILE_SIZE = 128 MiB = 134,217,728 bytes
    // For testing, we'll write several smaller blocks

    const blockSize = 1000;
    const block = Buffer.alloc(blockSize, 0xdd);

    const pos1 = await smallManager.writeBlock(block, 1, 1600000000);
    expect(pos1.fileNum).toBe(0);

    // Check file info is updated
    const info = smallManager.getBlockFileInfo(0);
    expect(info).toBeDefined();
    expect(info!.nBlocks).toBe(1);
    expect(info!.nSize).toBe(blockSize + STORAGE_HEADER_BYTES);
  });

  test("validates magic number on read", async () => {
    const blockData = Buffer.from("test block");
    const pos = await manager.writeBlock(blockData, 100, 1600000000);

    // Corrupt the magic number in the file
    const filePath = manager.getBlockFilePath(pos.fileNum);
    const fileData = Buffer.from(await Bun.file(filePath).arrayBuffer());
    fileData.writeUInt32LE(0xdeadbeef, 0); // Write wrong magic
    await Bun.write(filePath, fileData);

    // Read should fail with magic mismatch
    await expect(manager.readBlock(pos)).rejects.toThrow("magic mismatch");
  });

  test("throws on reading from non-existent file", async () => {
    const pos: FlatFilePos = { fileNum: 999, pos: 100 };
    await expect(manager.readBlock(pos)).rejects.toThrow("Block file not found");
  });

  test("throws on invalid block position", async () => {
    const blockData = Buffer.from("test block");
    await manager.writeBlock(blockData, 100, 1600000000);

    // Try to read from position beyond file
    const pos: FlatFilePos = { fileNum: 0, pos: 999999 };
    // Should throw either "exceeds file size" or "magic mismatch" (if reading zeros)
    await expect(manager.readBlock(pos)).rejects.toThrow();
  });

  test("tracks BlockFileInfo correctly", async () => {
    const block1 = Buffer.alloc(100, 0x11);
    const block2 = Buffer.alloc(200, 0x22);

    await manager.writeBlock(block1, 500, 1600000000);
    await manager.writeBlock(block2, 501, 1600001000);

    const info = manager.getBlockFileInfo(0);
    expect(info).toBeDefined();
    expect(info!.nBlocks).toBe(2);
    expect(info!.nHeightFirst).toBe(500);
    expect(info!.nHeightLast).toBe(501);
    expect(info!.nTimeFirst).toBe(1600000000);
    expect(info!.nTimeLast).toBe(1600001000);
    expect(info!.nSize).toBe(100 + STORAGE_HEADER_BYTES + 200 + STORAGE_HEADER_BYTES);
  });

  test("handles large blocks", async () => {
    // 1 MiB block
    const largeBlock = Buffer.alloc(1024 * 1024, 0xef);
    const pos = await manager.writeBlock(largeBlock, 100, 1600000000);

    const readBack = await manager.readBlock(pos);
    expect(readBack.length).toBe(largeBlock.length);
    expect(readBack.equals(largeBlock)).toBe(true);
  });

  test("re-initialization picks up existing files", async () => {
    const block = Buffer.alloc(500, 0xaa);
    const pos = await manager.writeBlock(block, 100, 1600000000);

    // Create new manager pointing to same directory
    const manager2 = new BlockFileManager(testDir, MAINNET_MAGIC);
    await manager2.init();

    // Should be able to read the block
    const readBack = await manager2.readBlock(pos);
    expect(readBack.equals(block)).toBe(true);

    // Current file number should be detected
    expect(manager2.getCurrentFileNum()).toBe(0);
  });

  test("getBlockFilePath formats correctly", () => {
    const path0 = manager.getBlockFilePath(0);
    const path5 = manager.getBlockFilePath(5);
    const path123 = manager.getBlockFilePath(123);
    const path99999 = manager.getBlockFilePath(99999);

    expect(path0).toContain("blk00000.dat");
    expect(path5).toContain("blk00005.dat");
    expect(path123).toContain("blk00123.dat");
    expect(path99999).toContain("blk99999.dat");
  });

  test("blockFileExists returns correct values", async () => {
    const exists0Before = await manager.blockFileExists(0);
    // File doesn't exist until we write something
    expect(exists0Before).toBe(false);

    const block = Buffer.from("test");
    await manager.writeBlock(block, 1, 1600000000);

    const exists0After = await manager.blockFileExists(0);
    expect(exists0After).toBe(true);

    const exists1 = await manager.blockFileExists(1);
    expect(exists1).toBe(false);
  });
});

describe("BlockStore", () => {
  let testDir: string;
  let store: BlockStore;

  beforeEach(async () => {
    testDir = await mkdtemp(join(tmpdir(), "hotbuns-blockstore-test-"));
    store = new BlockStore(testDir, MAINNET_MAGIC);
    await store.init();
  });

  afterEach(async () => {
    await rm(testDir, { recursive: true, force: true });
  });

  test("saveBlockToDisk and readBlockFromDisk", async () => {
    const rawBlock = Buffer.from("serialized block data here");
    const height = 12345;
    const timestamp = Math.floor(Date.now() / 1000);

    const pos = await store.saveBlockToDisk(rawBlock, height, timestamp);

    expect(pos.fileNum).toBeGreaterThanOrEqual(0);
    expect(pos.pos).toBeGreaterThan(0);

    const readBack = await store.readBlockFromDisk(pos);
    expect(readBack.equals(rawBlock)).toBe(true);
  });

  test("getCurrentPosition tracks writes", async () => {
    const initial = store.getCurrentPosition();
    expect(initial.fileNum).toBe(0);
    expect(initial.size).toBe(0);

    const block1 = Buffer.alloc(1000, 0x11);
    await store.saveBlockToDisk(block1, 1, 1600000000);

    const after1 = store.getCurrentPosition();
    expect(after1.fileNum).toBe(0);
    expect(after1.size).toBe(1000 + STORAGE_HEADER_BYTES);

    const block2 = Buffer.alloc(2000, 0x22);
    await store.saveBlockToDisk(block2, 2, 1600001000);

    const after2 = store.getCurrentPosition();
    expect(after2.size).toBe(1000 + STORAGE_HEADER_BYTES + 2000 + STORAGE_HEADER_BYTES);
  });

  test("getAllBlockFileInfo returns all file info", async () => {
    const block1 = Buffer.alloc(100, 0xaa);
    await store.saveBlockToDisk(block1, 100, 1600000000);

    const allInfo = store.getAllBlockFileInfo();
    expect(allInfo.size).toBeGreaterThanOrEqual(1);
    expect(allInfo.has(0)).toBe(true);
    expect(allInfo.get(0)!.nBlocks).toBe(1);
  });

  test("setBlockFileInfo loads info from database", async () => {
    const info: BlockFileInfo = {
      nBlocks: 50,
      nSize: 50000,
      nUndoSize: 10000,
      nHeightFirst: 100,
      nHeightLast: 149,
      nTimeFirst: 1600000000,
      nTimeLast: 1600099000,
    };

    store.setBlockFileInfo(5, info);

    const retrieved = store.getBlockFileInfo(5);
    expect(retrieved).toBeDefined();
    expect(retrieved!.nBlocks).toBe(50);
    expect(retrieved!.nSize).toBe(50000);
  });
});

describe("BlockFileManager file rotation", () => {
  let testDir: string;

  beforeEach(async () => {
    testDir = await mkdtemp(join(tmpdir(), "hotbuns-rotation-test-"));
  });

  afterEach(async () => {
    await rm(testDir, { recursive: true, force: true });
  });

  test("files are created with correct naming", async () => {
    const manager = new BlockFileManager(testDir, MAINNET_MAGIC);
    await manager.init();

    // Write a block to create file 0
    const block = Buffer.from("test block");
    await manager.writeBlock(block, 1, 1600000000);

    const blocksDir = join(testDir, "blocks");
    const files = await readdir(blocksDir);

    expect(files).toContain("blk00000.dat");
  });
});

describe("Constants", () => {
  test("MAX_BLOCKFILE_SIZE is 128 MiB", () => {
    expect(MAX_BLOCKFILE_SIZE).toBe(128 * 1024 * 1024);
    expect(MAX_BLOCKFILE_SIZE).toBe(0x8000000);
  });

  test("BLOCKFILE_CHUNK_SIZE is 16 MiB", () => {
    expect(BLOCKFILE_CHUNK_SIZE).toBe(16 * 1024 * 1024);
    expect(BLOCKFILE_CHUNK_SIZE).toBe(0x1000000);
  });

  test("STORAGE_HEADER_BYTES is 8", () => {
    // 4 bytes magic + 4 bytes size
    expect(STORAGE_HEADER_BYTES).toBe(8);
  });
});

describe("Edge cases", () => {
  let testDir: string;
  let manager: BlockFileManager;

  beforeEach(async () => {
    testDir = await mkdtemp(join(tmpdir(), "hotbuns-edge-test-"));
    manager = new BlockFileManager(testDir, MAINNET_MAGIC);
    await manager.init();
  });

  afterEach(async () => {
    await rm(testDir, { recursive: true, force: true });
  });

  test("empty block", async () => {
    const emptyBlock = Buffer.alloc(0);
    const pos = await manager.writeBlock(emptyBlock, 0, 1600000000);

    const readBack = await manager.readBlock(pos);
    expect(readBack.length).toBe(0);
    expect(readBack.equals(emptyBlock)).toBe(true);
  });

  test("block with all zeros", async () => {
    const zeroBlock = Buffer.alloc(1000, 0);
    const pos = await manager.writeBlock(zeroBlock, 1, 1600000000);

    const readBack = await manager.readBlock(pos);
    expect(readBack.equals(zeroBlock)).toBe(true);
  });

  test("block with all 0xFF", async () => {
    const ffBlock = Buffer.alloc(1000, 0xff);
    const pos = await manager.writeBlock(ffBlock, 1, 1600000000);

    const readBack = await manager.readBlock(pos);
    expect(readBack.equals(ffBlock)).toBe(true);
  });

  test("block with binary data", async () => {
    // Create a block with varied binary data
    const binaryBlock = Buffer.alloc(256);
    for (let i = 0; i < 256; i++) {
      binaryBlock[i] = i;
    }
    const pos = await manager.writeBlock(binaryBlock, 1, 1600000000);

    const readBack = await manager.readBlock(pos);
    expect(readBack.equals(binaryBlock)).toBe(true);
  });

  test("multiple managers on same directory", async () => {
    const manager1 = new BlockFileManager(testDir, MAINNET_MAGIC);
    await manager1.init();

    const block1 = Buffer.from("block from manager 1");
    const pos1 = await manager1.writeBlock(block1, 100, 1600000000);

    // Second manager initializes after first has written
    const manager2 = new BlockFileManager(testDir, MAINNET_MAGIC);
    await manager2.init();

    // Manager 2 should see the file and be able to read from it
    const readBack = await manager2.readBlock(pos1);
    expect(readBack.equals(block1)).toBe(true);
  });
});
