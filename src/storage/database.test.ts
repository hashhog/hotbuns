import { describe, test, expect, beforeEach, afterEach } from 'bun:test';
import { mkdtemp, rm } from 'fs/promises';
import { tmpdir } from 'os';
import { join } from 'path';
import {
  ChainDB,
  DBPrefix,
  type BlockIndexRecord,
  type UTXOEntry,
  type ChainState,
  type BatchOperation,
  type TxIndexEntry,
} from './database.js';

describe('ChainDB', () => {
  let dbPath: string;
  let db: ChainDB;

  beforeEach(async () => {
    dbPath = await mkdtemp(join(tmpdir(), 'hotbuns-test-'));
    db = new ChainDB(dbPath);
    await db.open();
  });

  afterEach(async () => {
    await db.close();
    await rm(dbPath, { recursive: true, force: true });
  });

  describe('BlockIndex operations', () => {
    test('put and get block index record', async () => {
      const hash = Buffer.alloc(32, 0xab);
      const header = Buffer.alloc(80, 0xcd);
      const record: BlockIndexRecord = {
        height: 12345,
        header,
        nTx: 100,
        status: 7, // header-valid | txs-known | txs-valid
        dataPos: 999,
      };

      await db.putBlockIndex(hash, record);
      const retrieved = await db.getBlockIndex(hash);

      expect(retrieved).not.toBeNull();
      expect(retrieved!.height).toBe(12345);
      expect(retrieved!.header.equals(header)).toBe(true);
      expect(retrieved!.nTx).toBe(100);
      expect(retrieved!.status).toBe(7);
      expect(retrieved!.dataPos).toBe(999);
    });

    test('get non-existent block index returns null', async () => {
      const hash = Buffer.alloc(32, 0xff);
      const result = await db.getBlockIndex(hash);
      expect(result).toBeNull();
    });

    test('get block hash by height', async () => {
      const hash1 = Buffer.alloc(32, 0x11);
      const hash2 = Buffer.alloc(32, 0x22);
      const hash3 = Buffer.alloc(32, 0x33);

      await db.putBlockIndex(hash1, {
        height: 0,
        header: Buffer.alloc(80, 0x01),
        nTx: 1,
        status: 7,
        dataPos: 0,
      });
      await db.putBlockIndex(hash2, {
        height: 1,
        header: Buffer.alloc(80, 0x02),
        nTx: 2,
        status: 7,
        dataPos: 1,
      });
      await db.putBlockIndex(hash3, {
        height: 100,
        header: Buffer.alloc(80, 0x03),
        nTx: 3,
        status: 7,
        dataPos: 100,
      });

      const retrieved0 = await db.getBlockHashByHeight(0);
      const retrieved1 = await db.getBlockHashByHeight(1);
      const retrieved100 = await db.getBlockHashByHeight(100);
      const retrievedNone = await db.getBlockHashByHeight(50);

      expect(retrieved0).not.toBeNull();
      expect(retrieved0!.equals(hash1)).toBe(true);
      expect(retrieved1).not.toBeNull();
      expect(retrieved1!.equals(hash2)).toBe(true);
      expect(retrieved100).not.toBeNull();
      expect(retrieved100!.equals(hash3)).toBe(true);
      expect(retrievedNone).toBeNull();
    });
  });

  describe('Block data operations', () => {
    test('put and get raw block', async () => {
      const hash = Buffer.alloc(32, 0xde);
      const rawBlock = Buffer.from('This is a fake block for testing purposes');

      await db.putBlock(hash, rawBlock);
      const retrieved = await db.getBlock(hash);

      expect(retrieved).not.toBeNull();
      expect(retrieved!.equals(rawBlock)).toBe(true);
    });

    test('get non-existent block returns null', async () => {
      const hash = Buffer.alloc(32, 0xee);
      const result = await db.getBlock(hash);
      expect(result).toBeNull();
    });
  });

  describe('UTXO operations', () => {
    test('put and get UTXO entry', async () => {
      const txid = Buffer.alloc(32, 0xaa);
      const vout = 0;
      const entry: UTXOEntry = {
        height: 500000,
        coinbase: false,
        amount: 50_000_000n, // 0.5 BTC
        scriptPubKey: Buffer.from('76a914abcd...88ac', 'hex'),
      };

      await db.putUTXO(txid, vout, entry);
      const retrieved = await db.getUTXO(txid, vout);

      expect(retrieved).not.toBeNull();
      expect(retrieved!.height).toBe(500000);
      expect(retrieved!.coinbase).toBe(false);
      expect(retrieved!.amount).toBe(50_000_000n);
      expect(retrieved!.scriptPubKey.equals(entry.scriptPubKey)).toBe(true);
    });

    test('put and get coinbase UTXO entry', async () => {
      const txid = Buffer.alloc(32, 0xbb);
      const vout = 0;
      const entry: UTXOEntry = {
        height: 100,
        coinbase: true,
        amount: 5_000_000_000n, // 50 BTC (block reward)
        scriptPubKey: Buffer.from('6a', 'hex'), // OP_RETURN
      };

      await db.putUTXO(txid, vout, entry);
      const retrieved = await db.getUTXO(txid, vout);

      expect(retrieved).not.toBeNull();
      expect(retrieved!.coinbase).toBe(true);
      expect(retrieved!.amount).toBe(5_000_000_000n);
    });

    test('get non-existent UTXO returns null', async () => {
      const txid = Buffer.alloc(32, 0xcc);
      const result = await db.getUTXO(txid, 0);
      expect(result).toBeNull();
    });

    test('delete UTXO', async () => {
      const txid = Buffer.alloc(32, 0xdd);
      const vout = 1;
      const entry: UTXOEntry = {
        height: 1000,
        coinbase: false,
        amount: 100_000n,
        scriptPubKey: Buffer.from('00', 'hex'),
      };

      await db.putUTXO(txid, vout, entry);
      let retrieved = await db.getUTXO(txid, vout);
      expect(retrieved).not.toBeNull();

      await db.deleteUTXO(txid, vout);
      retrieved = await db.getUTXO(txid, vout);
      expect(retrieved).toBeNull();
    });

    test('multiple outputs for same txid', async () => {
      const txid = Buffer.alloc(32, 0xee);

      const entry0: UTXOEntry = {
        height: 200,
        coinbase: false,
        amount: 100n,
        scriptPubKey: Buffer.from('00', 'hex'),
      };
      const entry1: UTXOEntry = {
        height: 200,
        coinbase: false,
        amount: 200n,
        scriptPubKey: Buffer.from('01', 'hex'),
      };
      const entry2: UTXOEntry = {
        height: 200,
        coinbase: false,
        amount: 300n,
        scriptPubKey: Buffer.from('02', 'hex'),
      };

      await db.putUTXO(txid, 0, entry0);
      await db.putUTXO(txid, 1, entry1);
      await db.putUTXO(txid, 2, entry2);

      const retrieved0 = await db.getUTXO(txid, 0);
      const retrieved1 = await db.getUTXO(txid, 1);
      const retrieved2 = await db.getUTXO(txid, 2);

      expect(retrieved0!.amount).toBe(100n);
      expect(retrieved1!.amount).toBe(200n);
      expect(retrieved2!.amount).toBe(300n);
    });
  });

  describe('ChainState operations', () => {
    test('put and get chain state', async () => {
      const state: ChainState = {
        bestBlockHash: Buffer.alloc(32, 0xff),
        bestHeight: 700000,
        totalWork: 123456789012345678901234567890n,
      };

      await db.putChainState(state);
      const retrieved = await db.getChainState();

      expect(retrieved).not.toBeNull();
      expect(retrieved!.bestBlockHash.equals(state.bestBlockHash)).toBe(true);
      expect(retrieved!.bestHeight).toBe(700000);
      expect(retrieved!.totalWork).toBe(123456789012345678901234567890n);
    });

    test('get chain state when none exists returns null', async () => {
      const result = await db.getChainState();
      expect(result).toBeNull();
    });

    test('chain state with zero total work', async () => {
      const state: ChainState = {
        bestBlockHash: Buffer.alloc(32, 0x00),
        bestHeight: 0,
        totalWork: 0n,
      };

      await db.putChainState(state);
      const retrieved = await db.getChainState();

      expect(retrieved).not.toBeNull();
      expect(retrieved!.totalWork).toBe(0n);
    });

    test('update chain state', async () => {
      const state1: ChainState = {
        bestBlockHash: Buffer.alloc(32, 0x11),
        bestHeight: 100,
        totalWork: 1000n,
      };
      const state2: ChainState = {
        bestBlockHash: Buffer.alloc(32, 0x22),
        bestHeight: 200,
        totalWork: 2000n,
      };

      await db.putChainState(state1);
      let retrieved = await db.getChainState();
      expect(retrieved!.bestHeight).toBe(100);

      await db.putChainState(state2);
      retrieved = await db.getChainState();
      expect(retrieved!.bestHeight).toBe(200);
      expect(retrieved!.totalWork).toBe(2000n);
    });
  });

  describe('Transaction index operations', () => {
    test('put and get tx index entry', async () => {
      const txid = Buffer.alloc(32, 0xab);
      const blockHash = Buffer.alloc(32, 0xcd);
      const entry = {
        blockHash,
        offset: 1234,
        length: 567,
      };

      await db.putTxIndex(txid, entry);
      const retrieved = await db.getTxIndex(txid);

      expect(retrieved).not.toBeNull();
      expect(retrieved!.blockHash.equals(blockHash)).toBe(true);
      expect(retrieved!.offset).toBe(1234);
      expect(retrieved!.length).toBe(567);
    });

    test('get non-existent tx index returns null', async () => {
      const txid = Buffer.alloc(32, 0xff);
      const result = await db.getTxIndex(txid);
      expect(result).toBeNull();
    });

    test('delete tx index', async () => {
      const txid = Buffer.alloc(32, 0xee);
      const entry = {
        blockHash: Buffer.alloc(32, 0xdd),
        offset: 100,
        length: 200,
      };

      await db.putTxIndex(txid, entry);
      let retrieved = await db.getTxIndex(txid);
      expect(retrieved).not.toBeNull();

      await db.deleteTxIndex(txid);
      retrieved = await db.getTxIndex(txid);
      expect(retrieved).toBeNull();
    });

    test('update tx index entry', async () => {
      const txid = Buffer.alloc(32, 0x11);
      const entry1 = {
        blockHash: Buffer.alloc(32, 0x22),
        offset: 100,
        length: 200,
      };
      const entry2 = {
        blockHash: Buffer.alloc(32, 0x33),
        offset: 300,
        length: 400,
      };

      await db.putTxIndex(txid, entry1);
      let retrieved = await db.getTxIndex(txid);
      expect(retrieved!.offset).toBe(100);

      await db.putTxIndex(txid, entry2);
      retrieved = await db.getTxIndex(txid);
      expect(retrieved!.offset).toBe(300);
      expect(retrieved!.blockHash.equals(entry2.blockHash)).toBe(true);
    });
  });

  describe('Undo data operations', () => {
    test('put and get undo data', async () => {
      const hash = Buffer.alloc(32, 0xab);
      const undoData = Buffer.from('serialized undo information');

      await db.putUndoData(hash, undoData);
      const retrieved = await db.getUndoData(hash);

      expect(retrieved).not.toBeNull();
      expect(retrieved!.equals(undoData)).toBe(true);
    });

    test('get non-existent undo data returns null', async () => {
      const hash = Buffer.alloc(32, 0xcd);
      const result = await db.getUndoData(hash);
      expect(result).toBeNull();
    });
  });

  describe('Batch operations', () => {
    test('batch put multiple UTXOs atomically', async () => {
      const txid1 = Buffer.alloc(32, 0x11);
      const txid2 = Buffer.alloc(32, 0x22);

      const entry1: UTXOEntry = {
        height: 100,
        coinbase: false,
        amount: 1000n,
        scriptPubKey: Buffer.from('01', 'hex'),
      };
      const entry2: UTXOEntry = {
        height: 100,
        coinbase: false,
        amount: 2000n,
        scriptPubKey: Buffer.from('02', 'hex'),
      };

      // Manually serialize for batch operations
      const { BufferWriter } = await import('../wire/serialization.js');

      function serializeUTXO(entry: UTXOEntry): Buffer {
        const writer = new BufferWriter();
        writer.writeUInt32LE(entry.height);
        writer.writeUInt8(entry.coinbase ? 1 : 0);
        writer.writeUInt64LE(entry.amount);
        writer.writeVarBytes(entry.scriptPubKey);
        return writer.toBuffer();
      }

      function encodeUTXOKey(txid: Buffer, vout: number): Buffer {
        const buf = Buffer.alloc(36);
        txid.copy(buf, 0);
        buf.writeUInt32LE(vout, 32);
        return buf;
      }

      const ops: BatchOperation[] = [
        {
          type: 'put',
          prefix: DBPrefix.UTXO,
          key: encodeUTXOKey(txid1, 0),
          value: serializeUTXO(entry1),
        },
        {
          type: 'put',
          prefix: DBPrefix.UTXO,
          key: encodeUTXOKey(txid2, 0),
          value: serializeUTXO(entry2),
        },
      ];

      await db.batch(ops);

      const retrieved1 = await db.getUTXO(txid1, 0);
      const retrieved2 = await db.getUTXO(txid2, 0);

      expect(retrieved1).not.toBeNull();
      expect(retrieved1!.amount).toBe(1000n);
      expect(retrieved2).not.toBeNull();
      expect(retrieved2!.amount).toBe(2000n);
    });

    test('batch delete UTXOs atomically', async () => {
      const txid = Buffer.alloc(32, 0x33);
      const entry: UTXOEntry = {
        height: 100,
        coinbase: false,
        amount: 5000n,
        scriptPubKey: Buffer.from('03', 'hex'),
      };

      // First add the UTXO
      await db.putUTXO(txid, 0, entry);
      let retrieved = await db.getUTXO(txid, 0);
      expect(retrieved).not.toBeNull();

      function encodeUTXOKey(txid: Buffer, vout: number): Buffer {
        const buf = Buffer.alloc(36);
        txid.copy(buf, 0);
        buf.writeUInt32LE(vout, 32);
        return buf;
      }

      // Delete via batch
      const ops: BatchOperation[] = [
        {
          type: 'del',
          prefix: DBPrefix.UTXO,
          key: encodeUTXOKey(txid, 0),
        },
      ];

      await db.batch(ops);
      retrieved = await db.getUTXO(txid, 0);
      expect(retrieved).toBeNull();
    });

    test('batch mixed put and delete operations', async () => {
      const txid1 = Buffer.alloc(32, 0x44);
      const txid2 = Buffer.alloc(32, 0x55);

      const entry1: UTXOEntry = {
        height: 100,
        coinbase: false,
        amount: 1000n,
        scriptPubKey: Buffer.from('04', 'hex'),
      };
      const entry2: UTXOEntry = {
        height: 101,
        coinbase: false,
        amount: 2000n,
        scriptPubKey: Buffer.from('05', 'hex'),
      };

      // Add first UTXO
      await db.putUTXO(txid1, 0, entry1);

      const { BufferWriter } = await import('../wire/serialization.js');

      function serializeUTXO(entry: UTXOEntry): Buffer {
        const writer = new BufferWriter();
        writer.writeUInt32LE(entry.height);
        writer.writeUInt8(entry.coinbase ? 1 : 0);
        writer.writeUInt64LE(entry.amount);
        writer.writeVarBytes(entry.scriptPubKey);
        return writer.toBuffer();
      }

      function encodeUTXOKey(txid: Buffer, vout: number): Buffer {
        const buf = Buffer.alloc(36);
        txid.copy(buf, 0);
        buf.writeUInt32LE(vout, 32);
        return buf;
      }

      // Atomically delete first and add second (simulating spending)
      const ops: BatchOperation[] = [
        {
          type: 'del',
          prefix: DBPrefix.UTXO,
          key: encodeUTXOKey(txid1, 0),
        },
        {
          type: 'put',
          prefix: DBPrefix.UTXO,
          key: encodeUTXOKey(txid2, 0),
          value: serializeUTXO(entry2),
        },
      ];

      await db.batch(ops);

      const retrieved1 = await db.getUTXO(txid1, 0);
      const retrieved2 = await db.getUTXO(txid2, 0);

      expect(retrieved1).toBeNull();
      expect(retrieved2).not.toBeNull();
      expect(retrieved2!.amount).toBe(2000n);
    });
  });

  describe('Edge cases', () => {
    test('large totalWork value in chain state', async () => {
      // Bitcoin's actual total work is a very large number
      const state: ChainState = {
        bestBlockHash: Buffer.alloc(32, 0xff),
        bestHeight: 800000,
        // Approximate real Bitcoin network total work (2^90 range)
        totalWork: BigInt('0x' + 'ff'.repeat(32)),
      };

      await db.putChainState(state);
      const retrieved = await db.getChainState();

      expect(retrieved).not.toBeNull();
      expect(retrieved!.totalWork).toBe(state.totalWork);
    });

    test('empty batch operation', async () => {
      // Should not throw
      await db.batch([]);
    });

    test('UTXO with maximum vout', async () => {
      const txid = Buffer.alloc(32, 0x99);
      const vout = 0xffffffff; // Max uint32
      const entry: UTXOEntry = {
        height: 1,
        coinbase: false,
        amount: 1n,
        scriptPubKey: Buffer.alloc(0),
      };

      await db.putUTXO(txid, vout, entry);
      const retrieved = await db.getUTXO(txid, vout);

      expect(retrieved).not.toBeNull();
      expect(retrieved!.amount).toBe(1n);
    });

    test('block at height 0 (genesis)', async () => {
      const genesisHash = Buffer.alloc(32, 0x00);
      const record: BlockIndexRecord = {
        height: 0,
        header: Buffer.alloc(80, 0x01),
        nTx: 1,
        status: 7,
        dataPos: 0,
      };

      await db.putBlockIndex(genesisHash, record);

      const retrievedByHash = await db.getBlockIndex(genesisHash);
      const retrievedByHeight = await db.getBlockHashByHeight(0);

      expect(retrievedByHash).not.toBeNull();
      expect(retrievedByHash!.height).toBe(0);
      expect(retrievedByHeight).not.toBeNull();
      expect(retrievedByHeight!.equals(genesisHash)).toBe(true);
    });

    test('UTXO with empty scriptPubKey', async () => {
      const txid = Buffer.alloc(32, 0xaa);
      const entry: UTXOEntry = {
        height: 500,
        coinbase: false,
        amount: 0n,
        scriptPubKey: Buffer.alloc(0),
      };

      await db.putUTXO(txid, 0, entry);
      const retrieved = await db.getUTXO(txid, 0);

      expect(retrieved).not.toBeNull();
      expect(retrieved!.scriptPubKey.length).toBe(0);
      expect(retrieved!.amount).toBe(0n);
    });
  });
});
