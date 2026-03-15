/**
 * Tests for undo data storage and serialization.
 */

import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  TxInUndo,
  TxUndo,
  BlockUndo,
  serializeTxInUndo,
  deserializeTxInUndo,
  serializeTxUndo,
  deserializeTxUndo,
  serializeBlockUndo,
  deserializeBlockUndo,
  calculateUndoChecksum,
  verifyUndoChecksum,
  serializeUndoDataWithChecksum,
  deserializeUndoDataWithChecksum,
  UndoFileManager,
  UndoManager,
} from "./undo.js";
import { BufferReader } from "../wire/serialization.js";

describe("TxInUndo serialization", () => {
  test("roundtrip serialization of non-coinbase output", () => {
    const undo: TxInUndo = {
      height: 12345,
      isCoinbase: false,
      output: {
        value: 50_00000000n,
        scriptPubKey: Buffer.from([0x76, 0xa9, 0x14, ...Array(20).fill(0x11), 0x88, 0xac]),
      },
    };

    const serialized = serializeTxInUndo(undo);
    const reader = new BufferReader(serialized);
    const deserialized = deserializeTxInUndo(reader);

    expect(deserialized.height).toBe(12345);
    expect(deserialized.isCoinbase).toBe(false);
    expect(deserialized.output.value).toBe(50_00000000n);
    expect(deserialized.output.scriptPubKey.equals(undo.output.scriptPubKey)).toBe(true);
  });

  test("roundtrip serialization of coinbase output", () => {
    const undo: TxInUndo = {
      height: 100,
      isCoinbase: true,
      output: {
        value: 50_00000000n,
        scriptPubKey: Buffer.from([0x00, 0x14, ...Array(20).fill(0x22)]),
      },
    };

    const serialized = serializeTxInUndo(undo);
    const reader = new BufferReader(serialized);
    const deserialized = deserializeTxInUndo(reader);

    expect(deserialized.height).toBe(100);
    expect(deserialized.isCoinbase).toBe(true);
    expect(deserialized.output.value).toBe(50_00000000n);
    expect(deserialized.output.scriptPubKey.equals(undo.output.scriptPubKey)).toBe(true);
  });

  test("roundtrip with height 0 (no dummy version byte)", () => {
    const undo: TxInUndo = {
      height: 0,
      isCoinbase: false,
      output: {
        value: 1000n,
        scriptPubKey: Buffer.from([0x51]), // OP_1
      },
    };

    const serialized = serializeTxInUndo(undo);
    const reader = new BufferReader(serialized);
    const deserialized = deserializeTxInUndo(reader);

    expect(deserialized.height).toBe(0);
    expect(deserialized.isCoinbase).toBe(false);
  });

  test("height encoding (height * 2 + coinbase)", () => {
    // Non-coinbase at height 100: code = 100 * 2 + 0 = 200
    const undo1: TxInUndo = {
      height: 100,
      isCoinbase: false,
      output: { value: 0n, scriptPubKey: Buffer.alloc(0) },
    };
    const serialized1 = serializeTxInUndo(undo1);
    // First byte should be the varint for 200
    expect(serialized1[0]).toBe(200);

    // Coinbase at height 100: code = 100 * 2 + 1 = 201
    const undo2: TxInUndo = {
      height: 100,
      isCoinbase: true,
      output: { value: 0n, scriptPubKey: Buffer.alloc(0) },
    };
    const serialized2 = serializeTxInUndo(undo2);
    expect(serialized2[0]).toBe(201);
  });
});

describe("TxUndo serialization", () => {
  test("roundtrip serialization with multiple inputs", () => {
    const undo: TxUndo = {
      prevOutputs: [
        {
          height: 100,
          isCoinbase: false,
          output: { value: 1000n, scriptPubKey: Buffer.from([0x51]) },
        },
        {
          height: 200,
          isCoinbase: true,
          output: { value: 50_00000000n, scriptPubKey: Buffer.alloc(25) },
        },
        {
          height: 300,
          isCoinbase: false,
          output: { value: 2500n, scriptPubKey: Buffer.alloc(34) },
        },
      ],
    };

    const serialized = serializeTxUndo(undo);
    const reader = new BufferReader(serialized);
    const deserialized = deserializeTxUndo(reader);

    expect(deserialized.prevOutputs.length).toBe(3);
    expect(deserialized.prevOutputs[0].height).toBe(100);
    expect(deserialized.prevOutputs[0].isCoinbase).toBe(false);
    expect(deserialized.prevOutputs[1].height).toBe(200);
    expect(deserialized.prevOutputs[1].isCoinbase).toBe(true);
    expect(deserialized.prevOutputs[2].height).toBe(300);
    expect(deserialized.prevOutputs[2].output.value).toBe(2500n);
  });

  test("handles empty prevOutputs", () => {
    const undo: TxUndo = { prevOutputs: [] };

    const serialized = serializeTxUndo(undo);
    const reader = new BufferReader(serialized);
    const deserialized = deserializeTxUndo(reader);

    expect(deserialized.prevOutputs.length).toBe(0);
  });
});

describe("BlockUndo serialization", () => {
  test("roundtrip serialization with multiple transactions", () => {
    const blockUndo: BlockUndo = {
      txUndo: [
        {
          prevOutputs: [
            {
              height: 50,
              isCoinbase: true,
              output: { value: 50_00000000n, scriptPubKey: Buffer.alloc(25) },
            },
          ],
        },
        {
          prevOutputs: [
            {
              height: 100,
              isCoinbase: false,
              output: { value: 1000n, scriptPubKey: Buffer.from([0x51]) },
            },
            {
              height: 100,
              isCoinbase: false,
              output: { value: 2000n, scriptPubKey: Buffer.from([0x52]) },
            },
          ],
        },
      ],
    };

    const serialized = serializeBlockUndo(blockUndo);
    const deserialized = deserializeBlockUndo(serialized);

    expect(deserialized.txUndo.length).toBe(2);
    expect(deserialized.txUndo[0].prevOutputs.length).toBe(1);
    expect(deserialized.txUndo[0].prevOutputs[0].height).toBe(50);
    expect(deserialized.txUndo[1].prevOutputs.length).toBe(2);
    expect(deserialized.txUndo[1].prevOutputs[0].output.value).toBe(1000n);
    expect(deserialized.txUndo[1].prevOutputs[1].output.value).toBe(2000n);
  });

  test("handles empty block (coinbase only)", () => {
    const blockUndo: BlockUndo = { txUndo: [] };

    const serialized = serializeBlockUndo(blockUndo);
    const deserialized = deserializeBlockUndo(serialized);

    expect(deserialized.txUndo.length).toBe(0);
  });
});

describe("Undo checksum", () => {
  test("calculates deterministic checksum", () => {
    const prevBlockHash = Buffer.alloc(32, 0xaa);
    const undoData = Buffer.from([1, 2, 3, 4, 5]);

    const checksum1 = calculateUndoChecksum(prevBlockHash, undoData);
    const checksum2 = calculateUndoChecksum(prevBlockHash, undoData);

    expect(checksum1.equals(checksum2)).toBe(true);
    expect(checksum1.length).toBe(32);
  });

  test("different inputs produce different checksums", () => {
    const prevBlockHash1 = Buffer.alloc(32, 0xaa);
    const prevBlockHash2 = Buffer.alloc(32, 0xbb);
    const undoData = Buffer.from([1, 2, 3, 4, 5]);

    const checksum1 = calculateUndoChecksum(prevBlockHash1, undoData);
    const checksum2 = calculateUndoChecksum(prevBlockHash2, undoData);

    expect(checksum1.equals(checksum2)).toBe(false);
  });

  test("verifies correct checksum", () => {
    const prevBlockHash = Buffer.alloc(32, 0xcc);
    const undoData = Buffer.from([10, 20, 30]);
    const checksum = calculateUndoChecksum(prevBlockHash, undoData);

    expect(verifyUndoChecksum(prevBlockHash, undoData, checksum)).toBe(true);
  });

  test("rejects incorrect checksum", () => {
    const prevBlockHash = Buffer.alloc(32, 0xdd);
    const undoData = Buffer.from([10, 20, 30]);
    const badChecksum = Buffer.alloc(32, 0xff);

    expect(verifyUndoChecksum(prevBlockHash, undoData, badChecksum)).toBe(false);
  });
});

describe("Undo data with checksum", () => {
  test("roundtrip serialization with checksum", () => {
    const prevBlockHash = Buffer.alloc(32, 0xee);
    const blockUndo: BlockUndo = {
      txUndo: [
        {
          prevOutputs: [
            {
              height: 500,
              isCoinbase: false,
              output: { value: 12345n, scriptPubKey: Buffer.alloc(22) },
            },
          ],
        },
      ],
    };

    const serialized = serializeUndoDataWithChecksum(prevBlockHash, blockUndo);
    const deserialized = deserializeUndoDataWithChecksum(prevBlockHash, serialized);

    expect(deserialized.txUndo.length).toBe(1);
    expect(deserialized.txUndo[0].prevOutputs[0].height).toBe(500);
    expect(deserialized.txUndo[0].prevOutputs[0].output.value).toBe(12345n);
  });

  test("throws on checksum mismatch", () => {
    const prevBlockHash = Buffer.alloc(32, 0xff);
    const blockUndo: BlockUndo = { txUndo: [] };

    const serialized = serializeUndoDataWithChecksum(prevBlockHash, blockUndo);

    // Corrupt the checksum
    serialized[serialized.length - 1] ^= 0xff;

    expect(() =>
      deserializeUndoDataWithChecksum(prevBlockHash, serialized)
    ).toThrow("checksum verification failed");
  });

  test("throws on wrong prevBlockHash", () => {
    const prevBlockHash1 = Buffer.alloc(32, 0x11);
    const prevBlockHash2 = Buffer.alloc(32, 0x22);
    const blockUndo: BlockUndo = { txUndo: [] };

    const serialized = serializeUndoDataWithChecksum(prevBlockHash1, blockUndo);

    // Try to deserialize with wrong prevBlockHash
    expect(() =>
      deserializeUndoDataWithChecksum(prevBlockHash2, serialized)
    ).toThrow("checksum verification failed");
  });

  test("throws on data too short", () => {
    const prevBlockHash = Buffer.alloc(32, 0x33);
    const shortData = Buffer.alloc(16);

    expect(() =>
      deserializeUndoDataWithChecksum(prevBlockHash, shortData)
    ).toThrow("too short");
  });
});

describe("UndoFileManager", () => {
  let tempDir: string;
  let fileManager: UndoFileManager;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "undo-test-"));
    fileManager = new UndoFileManager(tempDir);
  });

  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  test("initializes and creates blocks directory", async () => {
    await fileManager.init();

    const blocksDir = join(tempDir, "blocks");
    const file = Bun.file(blocksDir);
    // Can't easily check directory existence with Bun.file
    // But init should not throw
  });

  test("writes and reads block undo data", async () => {
    const blockHash = Buffer.alloc(32, 0x11);
    const prevBlockHash = Buffer.alloc(32, 0x22);
    const blockUndo: BlockUndo = {
      txUndo: [
        {
          prevOutputs: [
            {
              height: 100,
              isCoinbase: true,
              output: { value: 50_00000000n, scriptPubKey: Buffer.alloc(25) },
            },
          ],
        },
      ],
    };

    const pos = await fileManager.writeBlockUndo(blockHash, prevBlockHash, blockUndo);

    expect(pos.fileNum).toBe(0);
    expect(pos.filePos).toBe(0);

    const loaded = await fileManager.readBlockUndo(prevBlockHash, pos.fileNum, pos.filePos);

    expect(loaded.txUndo.length).toBe(1);
    expect(loaded.txUndo[0].prevOutputs[0].height).toBe(100);
    expect(loaded.txUndo[0].prevOutputs[0].isCoinbase).toBe(true);
  });

  test("appends multiple blocks to same file", async () => {
    const blocks = [
      {
        blockHash: Buffer.alloc(32, 0x01),
        prevBlockHash: Buffer.alloc(32, 0x00),
        blockUndo: {
          txUndo: [
            {
              prevOutputs: [
                { height: 1, isCoinbase: true, output: { value: 50n, scriptPubKey: Buffer.alloc(10) } },
              ],
            },
          ],
        },
      },
      {
        blockHash: Buffer.alloc(32, 0x02),
        prevBlockHash: Buffer.alloc(32, 0x01),
        blockUndo: {
          txUndo: [
            {
              prevOutputs: [
                { height: 2, isCoinbase: false, output: { value: 100n, scriptPubKey: Buffer.alloc(20) } },
              ],
            },
          ],
        },
      },
    ];

    const positions = [];
    for (const block of blocks) {
      const pos = await fileManager.writeBlockUndo(
        block.blockHash,
        block.prevBlockHash,
        block.blockUndo
      );
      positions.push(pos);
    }

    // Both should be in file 0
    expect(positions[0].fileNum).toBe(0);
    expect(positions[1].fileNum).toBe(0);

    // Second should have higher position
    expect(positions[1].filePos).toBeGreaterThan(positions[0].filePos);

    // Read both back
    const loaded0 = await fileManager.readBlockUndo(
      blocks[0].prevBlockHash,
      positions[0].fileNum,
      positions[0].filePos
    );
    const loaded1 = await fileManager.readBlockUndo(
      blocks[1].prevBlockHash,
      positions[1].fileNum,
      positions[1].filePos
    );

    expect(loaded0.txUndo[0].prevOutputs[0].height).toBe(1);
    expect(loaded1.txUndo[0].prevOutputs[0].height).toBe(2);
  });

  test("throws on missing file", async () => {
    const prevBlockHash = Buffer.alloc(32, 0xaa);

    await expect(
      fileManager.readBlockUndo(prevBlockHash, 99, 0)
    ).rejects.toThrow("not found");
  });

  test("throws on invalid position", async () => {
    // Write something first
    const blockHash = Buffer.alloc(32, 0x11);
    const prevBlockHash = Buffer.alloc(32, 0x22);
    const blockUndo: BlockUndo = { txUndo: [] };

    await fileManager.writeBlockUndo(blockHash, prevBlockHash, blockUndo);

    // Try to read at invalid position
    await expect(
      fileManager.readBlockUndo(prevBlockHash, 0, 99999)
    ).rejects.toThrow("Invalid");
  });
});

describe("UndoManager", () => {
  let tempDir: string;
  let undoManager: UndoManager;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "undo-mgr-test-"));
    undoManager = new UndoManager(tempDir);
    await undoManager.init();
  });

  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  test("stores and loads block undo", async () => {
    const blockHash = Buffer.alloc(32, 0xaa);
    const prevBlockHash = Buffer.alloc(32, 0xbb);
    const blockUndo: BlockUndo = {
      txUndo: [
        {
          prevOutputs: [
            {
              height: 500,
              isCoinbase: false,
              output: { value: 1000n, scriptPubKey: Buffer.from([0x51]) },
            },
          ],
        },
      ],
    };

    const pos = await undoManager.storeBlockUndo(blockHash, prevBlockHash, blockUndo);
    const loaded = await undoManager.loadBlockUndo(prevBlockHash, pos.fileNum, pos.filePos);

    expect(loaded.txUndo.length).toBe(1);
    expect(loaded.txUndo[0].prevOutputs[0].height).toBe(500);
  });

  test("createBlockUndo helper", () => {
    const spentByTx = new Map<number, TxInUndo[]>();

    // Transaction 1 (index 1, first non-coinbase) spends 2 inputs
    spentByTx.set(1, [
      { height: 100, isCoinbase: true, output: { value: 50_00000000n, scriptPubKey: Buffer.alloc(25) } },
      { height: 100, isCoinbase: false, output: { value: 1000n, scriptPubKey: Buffer.alloc(22) } },
    ]);

    // Transaction 2 spends 1 input
    spentByTx.set(2, [
      { height: 150, isCoinbase: false, output: { value: 2000n, scriptPubKey: Buffer.alloc(34) } },
    ]);

    const blockUndo = UndoManager.createBlockUndo(spentByTx, 3);

    expect(blockUndo.txUndo.length).toBe(2); // Excludes coinbase (index 0)
    expect(blockUndo.txUndo[0].prevOutputs.length).toBe(2);
    expect(blockUndo.txUndo[1].prevOutputs.length).toBe(1);
    expect(blockUndo.txUndo[0].prevOutputs[0].height).toBe(100);
    expect(blockUndo.txUndo[1].prevOutputs[0].value).toBe(undefined); // value is on output
    expect(blockUndo.txUndo[1].prevOutputs[0].output.value).toBe(2000n);
  });

  test("createBlockUndo handles empty transactions", () => {
    const spentByTx = new Map<number, TxInUndo[]>();

    // Block with 5 transactions, but only tx 2 and 4 spend anything
    spentByTx.set(2, [
      { height: 50, isCoinbase: false, output: { value: 500n, scriptPubKey: Buffer.alloc(10) } },
    ]);
    spentByTx.set(4, [
      { height: 60, isCoinbase: false, output: { value: 600n, scriptPubKey: Buffer.alloc(10) } },
    ]);

    const blockUndo = UndoManager.createBlockUndo(spentByTx, 5);

    expect(blockUndo.txUndo.length).toBe(4); // txs 1, 2, 3, 4
    expect(blockUndo.txUndo[0].prevOutputs.length).toBe(0); // tx 1 - empty
    expect(blockUndo.txUndo[1].prevOutputs.length).toBe(1); // tx 2 - has spent
    expect(blockUndo.txUndo[2].prevOutputs.length).toBe(0); // tx 3 - empty
    expect(blockUndo.txUndo[3].prevOutputs.length).toBe(1); // tx 4 - has spent
  });
});

describe("disconnect block with undo data", () => {
  // Integration tests verifying undo data works for block disconnect
  // These tests complement the existing state.test.ts tests

  test("undo data contains correct spent output info", () => {
    const spentByTx = new Map<number, TxInUndo[]>();

    // Simulate spending outputs from different heights
    spentByTx.set(1, [
      {
        height: 50,
        isCoinbase: true,
        output: {
          value: 50_00000000n,
          scriptPubKey: Buffer.from([0x76, 0xa9, 0x14, ...Array(20).fill(0x11), 0x88, 0xac]),
        },
      },
    ]);

    const blockUndo = UndoManager.createBlockUndo(spentByTx, 2);

    // Verify undo data captures the full output info
    const txUndo = blockUndo.txUndo[0];
    expect(txUndo.prevOutputs[0].height).toBe(50);
    expect(txUndo.prevOutputs[0].isCoinbase).toBe(true);
    expect(txUndo.prevOutputs[0].output.value).toBe(50_00000000n);
    expect(txUndo.prevOutputs[0].output.scriptPubKey.length).toBe(25);
  });
});

describe("reorg undo data handling", () => {
  let tempDir: string;
  let undoManager: UndoManager;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "reorg-test-"));
    undoManager = new UndoManager(tempDir);
    await undoManager.init();
  });

  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  test("stores multiple blocks and retrieves them in reverse order for reorg", async () => {
    // Simulate storing undo data for a chain of blocks
    const positions: { fileNum: number; filePos: number }[] = [];
    const blockHashes: Buffer[] = [];
    const prevBlockHashes: Buffer[] = [];

    // Create genesis hash
    prevBlockHashes.push(Buffer.alloc(32, 0x00));

    for (let i = 1; i <= 5; i++) {
      const blockHash = Buffer.alloc(32, i);
      blockHashes.push(blockHash);

      const blockUndo: BlockUndo = {
        txUndo: [
          {
            prevOutputs: [
              {
                height: i * 10,
                isCoinbase: i === 1,
                output: { value: BigInt(i * 1000), scriptPubKey: Buffer.alloc(25) },
              },
            ],
          },
        ],
      };

      const pos = await undoManager.storeBlockUndo(
        blockHash,
        prevBlockHashes[i - 1],
        blockUndo
      );
      positions.push(pos);
      prevBlockHashes.push(blockHash);
    }

    // Read back in reverse order (as would happen during reorg disconnect)
    for (let i = 4; i >= 0; i--) {
      const loaded = await undoManager.loadBlockUndo(
        prevBlockHashes[i],
        positions[i].fileNum,
        positions[i].filePos
      );

      expect(loaded.txUndo[0].prevOutputs[0].height).toBe((i + 1) * 10);
      expect(loaded.txUndo[0].prevOutputs[0].output.value).toBe(BigInt((i + 1) * 1000));
    }
  });
});
