/**
 * Persistent storage for blocks, headers, and chain state using LevelDB.
 *
 * Uses prefix-based key namespacing and batch write support for atomic operations.
 */

import { ClassicLevel } from 'classic-level';
import { BufferReader, BufferWriter } from '../wire/serialization.js';

/** Key prefixes for database namespaces. */
export const enum DBPrefix {
  BLOCK_INDEX = 0x62, // 'b' - block hash -> block index record
  BLOCK_DATA = 0x64, // 'd' - block hash -> raw block bytes
  TX_INDEX = 0x74, // 't' - txid -> { blockHash, offset, length }
  UTXO = 0x75, // 'u' - outpoint (txid+vout) -> UTXO entry
  CHAIN_STATE = 0x73, // 's' - chain state metadata
  HEADER = 0x68, // 'h' - height (4 bytes BE) -> block hash
  UNDO = 0x72, // 'r' - block hash -> undo data for disconnect
}

/** Block index record stored in the database. */
export interface BlockIndexRecord {
  height: number;
  header: Buffer; // 80-byte block header
  nTx: number;
  status: number; // bitmask: 1=header-valid, 2=txs-known, 4=txs-valid
  dataPos: number; // position/flag for block data existence
}

/** UTXO entry stored in the database. */
export interface UTXOEntry {
  height: number;
  coinbase: boolean;
  amount: bigint;
  scriptPubKey: Buffer;
}

/** Chain state metadata. */
export interface ChainState {
  bestBlockHash: Buffer;
  bestHeight: number;
  totalWork: bigint;
}

/** Batch operation for atomic writes. */
export interface BatchOperation {
  type: 'put' | 'del';
  prefix: DBPrefix;
  key: Buffer;
  value?: Buffer;
}

/**
 * Construct a prefixed key for database storage.
 */
function makeKey(prefix: DBPrefix, key: Buffer): Buffer {
  return Buffer.concat([Buffer.from([prefix]), key]);
}

/**
 * Encode a height as 4-byte big-endian for lexicographic ordering.
 */
function encodeHeight(height: number): Buffer {
  const buf = Buffer.alloc(4);
  buf.writeUInt32BE(height, 0);
  return buf;
}

/**
 * Encode a UTXO key: txid (32 bytes) || vout (4 bytes LE).
 */
function encodeUTXOKey(txid: Buffer, vout: number): Buffer {
  const buf = Buffer.alloc(36);
  txid.copy(buf, 0);
  buf.writeUInt32LE(vout, 32);
  return buf;
}

/**
 * Serialize a BlockIndexRecord to bytes.
 */
function serializeBlockIndex(record: BlockIndexRecord): Buffer {
  const writer = new BufferWriter();
  writer.writeUInt32LE(record.height);
  writer.writeBytes(record.header);
  writer.writeUInt32LE(record.nTx);
  writer.writeUInt32LE(record.status);
  writer.writeUInt32LE(record.dataPos);
  return writer.toBuffer();
}

/**
 * Deserialize a BlockIndexRecord from bytes.
 */
function deserializeBlockIndex(data: Buffer): BlockIndexRecord {
  const reader = new BufferReader(data);
  const height = reader.readUInt32LE();
  const header = reader.readBytes(80);
  const nTx = reader.readUInt32LE();
  const status = reader.readUInt32LE();
  const dataPos = reader.readUInt32LE();
  return { height, header, nTx, status, dataPos };
}

/**
 * Serialize a UTXOEntry to bytes.
 */
function serializeUTXO(entry: UTXOEntry): Buffer {
  const writer = new BufferWriter();
  writer.writeUInt32LE(entry.height);
  writer.writeUInt8(entry.coinbase ? 1 : 0);
  writer.writeUInt64LE(entry.amount);
  writer.writeVarBytes(entry.scriptPubKey);
  return writer.toBuffer();
}

/**
 * Deserialize a UTXOEntry from bytes.
 */
function deserializeUTXO(data: Buffer): UTXOEntry {
  const reader = new BufferReader(data);
  const height = reader.readUInt32LE();
  const coinbase = reader.readUInt8() === 1;
  const amount = reader.readUInt64LE();
  const scriptPubKey = reader.readVarBytes();
  return { height, coinbase, amount, scriptPubKey };
}

/**
 * Serialize ChainState to bytes.
 */
function serializeChainState(state: ChainState): Buffer {
  const writer = new BufferWriter();
  writer.writeHash(state.bestBlockHash);
  writer.writeUInt32LE(state.bestHeight);
  // Serialize totalWork as a variable-length big integer
  // We store it as a byte array with length prefix
  const workBytes = bigIntToBuffer(state.totalWork);
  writer.writeVarBytes(workBytes);
  return writer.toBuffer();
}

/**
 * Deserialize ChainState from bytes.
 */
function deserializeChainState(data: Buffer): ChainState {
  const reader = new BufferReader(data);
  const bestBlockHash = reader.readHash();
  const bestHeight = reader.readUInt32LE();
  const workBytes = reader.readVarBytes();
  const totalWork = bufferToBigInt(workBytes);
  return { bestBlockHash, bestHeight, totalWork };
}

/**
 * Convert a bigint to a Buffer (big-endian, variable length).
 */
function bigIntToBuffer(n: bigint): Buffer {
  if (n === 0n) {
    return Buffer.alloc(0);
  }
  let hex = n.toString(16);
  if (hex.length % 2 !== 0) {
    hex = '0' + hex;
  }
  return Buffer.from(hex, 'hex');
}

/**
 * Convert a Buffer to a bigint (big-endian).
 */
function bufferToBigInt(buf: Buffer): bigint {
  if (buf.length === 0) {
    return 0n;
  }
  return BigInt('0x' + buf.toString('hex'));
}

/**
 * LevelDB-backed storage for Bitcoin blockchain data.
 *
 * Provides storage for:
 * - Block index records (block metadata)
 * - Raw block data
 * - UTXO set
 * - Chain state
 * - Undo data for reorgs
 */
export class ChainDB {
  private db: ClassicLevel<Buffer, Buffer>;

  constructor(dbPath: string) {
    this.db = new ClassicLevel<Buffer, Buffer>(dbPath, {
      keyEncoding: 'buffer',
      valueEncoding: 'buffer',
    });
  }

  async open(): Promise<void> {
    await this.db.open();
  }

  async close(): Promise<void> {
    await this.db.close();
  }

  // Block index operations

  async putBlockIndex(hash: Buffer, record: BlockIndexRecord): Promise<void> {
    const key = makeKey(DBPrefix.BLOCK_INDEX, hash);
    const value = serializeBlockIndex(record);
    await this.db.put(key, value);

    // Also store height -> hash mapping
    const heightKey = makeKey(DBPrefix.HEADER, encodeHeight(record.height));
    await this.db.put(heightKey, hash);
  }

  async getBlockIndex(hash: Buffer): Promise<BlockIndexRecord | null> {
    const key = makeKey(DBPrefix.BLOCK_INDEX, hash);
    const value = await this.db.get(key);
    if (value === undefined) {
      return null;
    }
    return deserializeBlockIndex(value);
  }

  async getBlockHashByHeight(height: number): Promise<Buffer | null> {
    const key = makeKey(DBPrefix.HEADER, encodeHeight(height));
    const value = await this.db.get(key);
    if (value === undefined) {
      return null;
    }
    return value;
  }

  // Raw block data operations

  async putBlock(hash: Buffer, rawBlock: Buffer): Promise<void> {
    const key = makeKey(DBPrefix.BLOCK_DATA, hash);
    await this.db.put(key, rawBlock);
  }

  async getBlock(hash: Buffer): Promise<Buffer | null> {
    const key = makeKey(DBPrefix.BLOCK_DATA, hash);
    const value = await this.db.get(key);
    if (value === undefined) {
      return null;
    }
    return value;
  }

  // UTXO set operations

  async putUTXO(txid: Buffer, vout: number, entry: UTXOEntry): Promise<void> {
    const key = makeKey(DBPrefix.UTXO, encodeUTXOKey(txid, vout));
    const value = serializeUTXO(entry);
    await this.db.put(key, value);
  }

  async getUTXO(txid: Buffer, vout: number): Promise<UTXOEntry | null> {
    const key = makeKey(DBPrefix.UTXO, encodeUTXOKey(txid, vout));
    const value = await this.db.get(key);
    if (value === undefined) {
      return null;
    }
    return deserializeUTXO(value);
  }

  async deleteUTXO(txid: Buffer, vout: number): Promise<void> {
    const key = makeKey(DBPrefix.UTXO, encodeUTXOKey(txid, vout));
    await this.db.del(key);
  }

  // Chain state operations

  async putChainState(state: ChainState): Promise<void> {
    const key = makeKey(DBPrefix.CHAIN_STATE, Buffer.alloc(0));
    const value = serializeChainState(state);
    await this.db.put(key, value);
  }

  async getChainState(): Promise<ChainState | null> {
    const key = makeKey(DBPrefix.CHAIN_STATE, Buffer.alloc(0));
    const value = await this.db.get(key);
    if (value === undefined) {
      return null;
    }
    return deserializeChainState(value);
  }

  // Batch operations for atomic writes

  async batch(ops: BatchOperation[]): Promise<void> {
    const batch = this.db.batch();
    for (const op of ops) {
      const key = makeKey(op.prefix, op.key);
      if (op.type === 'put') {
        if (!op.value) {
          throw new Error('batch put operation requires a value');
        }
        batch.put(key, op.value);
      } else {
        batch.del(key);
      }
    }
    await batch.write();
  }

  // Undo data operations (for block disconnect / reorgs)

  async putUndoData(hash: Buffer, data: Buffer): Promise<void> {
    const key = makeKey(DBPrefix.UNDO, hash);
    await this.db.put(key, data);
  }

  async getUndoData(hash: Buffer): Promise<Buffer | null> {
    const key = makeKey(DBPrefix.UNDO, hash);
    const value = await this.db.get(key);
    if (value === undefined) {
      return null;
    }
    return value;
  }
}
