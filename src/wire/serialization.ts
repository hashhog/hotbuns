/**
 * Bitcoin protocol binary serialization and deserialization.
 *
 * Implements CompactSize (varint) encoding and primitive type serialization
 * used throughout the Bitcoin wire protocol.
 */

/**
 * Calculate the byte size of a CompactSize (varint) encoded value.
 */
export function varIntSize(value: number | bigint): number {
  const n = typeof value === "bigint" ? value : BigInt(value);
  if (n < 0n) {
    throw new Error("varIntSize: value must be non-negative");
  }
  if (n <= 0xfcn) return 1;
  if (n <= 0xffffn) return 3;
  if (n <= 0xffffffffn) return 5;
  return 9;
}

/**
 * BufferWriter accumulates binary data for Bitcoin protocol serialization.
 * Data is written in little-endian format as required by the Bitcoin protocol.
 */
export class BufferWriter {
  private buffers: Buffer[];
  private length: number;

  constructor() {
    this.buffers = [];
    this.length = 0;
  }

  writeUInt8(value: number): void {
    const buf = Buffer.alloc(1);
    buf.writeUInt8(value, 0);
    this.buffers.push(buf);
    this.length += 1;
  }

  writeUInt16LE(value: number): void {
    const buf = Buffer.alloc(2);
    buf.writeUInt16LE(value, 0);
    this.buffers.push(buf);
    this.length += 2;
  }

  writeUInt32LE(value: number): void {
    const buf = Buffer.alloc(4);
    buf.writeUInt32LE(value, 0);
    this.buffers.push(buf);
    this.length += 4;
  }

  writeInt32LE(value: number): void {
    const buf = Buffer.alloc(4);
    buf.writeInt32LE(value, 0);
    this.buffers.push(buf);
    this.length += 4;
  }

  writeUInt64LE(value: bigint): void {
    const buf = Buffer.alloc(8);
    buf.writeBigUInt64LE(value, 0);
    this.buffers.push(buf);
    this.length += 8;
  }

  /**
   * Write a CompactSize (varint) encoded value.
   * Uses canonical (smallest) encoding.
   */
  writeVarInt(value: number | bigint): void {
    const n = typeof value === "bigint" ? value : BigInt(value);
    if (n < 0n) {
      throw new Error("writeVarInt: value must be non-negative");
    }

    if (n <= 0xfcn) {
      this.writeUInt8(Number(n));
    } else if (n <= 0xffffn) {
      this.writeUInt8(0xfd);
      this.writeUInt16LE(Number(n));
    } else if (n <= 0xffffffffn) {
      this.writeUInt8(0xfe);
      this.writeUInt32LE(Number(n));
    } else {
      this.writeUInt8(0xff);
      this.writeUInt64LE(n);
    }
  }

  /**
   * Write a varint length prefix followed by the data bytes.
   */
  writeVarBytes(data: Buffer): void {
    this.writeVarInt(data.length);
    this.writeBytes(data);
  }

  /**
   * Write a varint length prefix followed by UTF-8 encoded string bytes.
   */
  writeVarString(str: string): void {
    const data = Buffer.from(str, "utf-8");
    this.writeVarBytes(data);
  }

  /**
   * Write raw bytes without any prefix.
   */
  writeBytes(data: Buffer): void {
    this.buffers.push(data);
    this.length += data.length;
  }

  /**
   * Write exactly 32 bytes (a hash value).
   * Bitcoin hashes are stored as little-endian in memory.
   */
  writeHash(hash: Buffer): void {
    if (hash.length !== 32) {
      throw new Error(`writeHash: expected 32 bytes, got ${hash.length}`);
    }
    this.writeBytes(hash);
  }

  /**
   * Concatenate all accumulated buffers into a single Buffer.
   */
  toBuffer(): Buffer {
    return Buffer.concat(this.buffers, this.length);
  }
}

/**
 * BufferReader reads binary data from a Buffer for Bitcoin protocol deserialization.
 * Data is read in little-endian format as required by the Bitcoin protocol.
 */
export class BufferReader {
  private buffer: Buffer;
  private offset: number;

  constructor(buffer: Buffer) {
    this.buffer = buffer;
    this.offset = 0;
  }

  readUInt8(): number {
    this.ensureAvailable(1);
    const value = this.buffer.readUInt8(this.offset);
    this.offset += 1;
    return value;
  }

  readUInt16LE(): number {
    this.ensureAvailable(2);
    const value = this.buffer.readUInt16LE(this.offset);
    this.offset += 2;
    return value;
  }

  readUInt32LE(): number {
    this.ensureAvailable(4);
    const value = this.buffer.readUInt32LE(this.offset);
    this.offset += 4;
    return value;
  }

  readInt32LE(): number {
    this.ensureAvailable(4);
    const value = this.buffer.readInt32LE(this.offset);
    this.offset += 4;
    return value;
  }

  readUInt64LE(): bigint {
    this.ensureAvailable(8);
    const value = this.buffer.readBigUInt64LE(this.offset);
    this.offset += 8;
    return value;
  }

  /**
   * Read a CompactSize (varint) encoded value.
   * Returns a number (safe for values up to Number.MAX_SAFE_INTEGER).
   */
  readVarInt(): number {
    const value = this.readVarIntBig();
    if (value > BigInt(Number.MAX_SAFE_INTEGER)) {
      throw new Error("readVarInt: value exceeds Number.MAX_SAFE_INTEGER");
    }
    return Number(value);
  }

  /**
   * Read a CompactSize (varint) encoded value as bigint.
   * Use this for values that may exceed Number.MAX_SAFE_INTEGER.
   */
  readVarIntBig(): bigint {
    const first = this.readUInt8();
    if (first <= 0xfc) {
      return BigInt(first);
    } else if (first === 0xfd) {
      return BigInt(this.readUInt16LE());
    } else if (first === 0xfe) {
      return BigInt(this.readUInt32LE());
    } else {
      return this.readUInt64LE();
    }
  }

  /**
   * Read a varint length prefix followed by that many bytes.
   */
  readVarBytes(): Buffer {
    const length = this.readVarInt();
    return this.readBytes(length);
  }

  /**
   * Read a varint length prefix followed by UTF-8 string bytes.
   */
  readVarString(): string {
    const data = this.readVarBytes();
    return data.toString("utf-8");
  }

  /**
   * Read a fixed number of raw bytes.
   */
  readBytes(length: number): Buffer {
    this.ensureAvailable(length);
    const data = this.buffer.subarray(this.offset, this.offset + length);
    this.offset += length;
    return data;
  }

  /**
   * Read exactly 32 bytes (a hash value).
   */
  readHash(): Buffer {
    return this.readBytes(32);
  }

  /**
   * Current read position in the buffer.
   */
  get position(): number {
    return this.offset;
  }

  /**
   * Number of bytes remaining to be read.
   */
  get remaining(): number {
    return this.buffer.length - this.offset;
  }

  /**
   * True if all bytes have been read.
   */
  get eof(): boolean {
    return this.offset >= this.buffer.length;
  }

  private ensureAvailable(bytes: number): void {
    if (this.offset + bytes > this.buffer.length) {
      throw new Error(
        `BufferReader: attempted to read ${bytes} bytes at offset ${this.offset}, ` +
          `but only ${this.remaining} bytes remaining`
      );
    }
  }
}
