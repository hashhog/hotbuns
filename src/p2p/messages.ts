/**
 * Bitcoin P2P protocol message framing and serialization.
 *
 * Implements the 24-byte message header, all message type serialization/deserialization,
 * and the message envelope for network communication.
 *
 * Message header format (24 bytes):
 * - magic: 4 bytes LE (network magic)
 * - command: 12 bytes (null-padded ASCII)
 * - length: 4 bytes LE (payload length)
 * - checksum: 4 bytes (first 4 bytes of hash256(payload))
 */

import { BufferReader, BufferWriter } from "../wire/serialization.js";
import { hash256 } from "../crypto/primitives.js";
import {
  BlockHeader,
  Block,
  deserializeBlockHeader,
  deserializeBlock,
  serializeBlockHeader,
  serializeBlock,
} from "../validation/block.js";
import {
  Transaction,
  deserializeTx,
  serializeTx,
} from "../validation/tx.js";

/** Maximum message payload size: 32 MiB */
export const MAX_MESSAGE_SIZE = 32 * 1024 * 1024;

/** Message header size in bytes */
export const MESSAGE_HEADER_SIZE = 24;

/**
 * Bitcoin P2P message header (24 bytes).
 */
export interface MessageHeader {
  magic: number;
  command: string;
  length: number;
  checksum: Buffer;
}

/**
 * Discriminated union for all Bitcoin P2P message types.
 */
export type NetworkMessage =
  | { type: "version"; payload: VersionPayload }
  | { type: "verack"; payload: null }
  | { type: "ping"; payload: PingPayload }
  | { type: "pong"; payload: PongPayload }
  | { type: "inv"; payload: InvPayload }
  | { type: "getdata"; payload: GetDataPayload }
  | { type: "getblocks"; payload: GetBlocksPayload }
  | { type: "getheaders"; payload: GetHeadersPayload }
  | { type: "headers"; payload: HeadersPayload }
  | { type: "block"; payload: BlockPayload }
  | { type: "tx"; payload: TxPayload }
  | { type: "addr"; payload: AddrPayload }
  | { type: "getaddr"; payload: null }
  | { type: "reject"; payload: RejectPayload }
  | { type: "sendheaders"; payload: null }
  | { type: "sendcmpct"; payload: SendCmpctPayload }
  | { type: "feefilter"; payload: FeeFilterPayload }
  | { type: "wtxidrelay"; payload: null }
  | { type: "sendaddrv2"; payload: null }
  | { type: "cmpctblock"; payload: CmpctBlockPayload }
  | { type: "getblocktxn"; payload: GetBlockTxnPayload }
  | { type: "blocktxn"; payload: BlockTxnPayload };

/**
 * Network address (without timestamp, used in version message).
 * Port is big-endian, unlike everything else in Bitcoin!
 */
export interface NetworkAddress {
  services: bigint;
  ip: Buffer;     // 16 bytes (IPv4-mapped IPv6)
  port: number;   // uint16 BE
}

/**
 * Version message payload (first message after connection).
 */
export interface VersionPayload {
  version: number;         // int32 — protocol version (70016)
  services: bigint;        // uint64 — service flags
  timestamp: bigint;       // int64 — unix timestamp
  addrRecv: NetworkAddress;
  addrFrom: NetworkAddress;
  nonce: bigint;           // uint64 — random nonce
  userAgent: string;       // var_str
  startHeight: number;     // int32
  relay: boolean;          // bool (1 byte)
}

/**
 * Inventory vector types.
 */
export const enum InvType {
  ERROR = 0,
  MSG_TX = 1,
  MSG_BLOCK = 2,
  MSG_FILTERED_BLOCK = 3,
  MSG_CMPCT_BLOCK = 4,
  MSG_WITNESS_TX = 0x40000001,
  MSG_WITNESS_BLOCK = 0x40000002,
}

/**
 * Inventory vector (type + hash).
 */
export interface InvVector {
  type: InvType;
  hash: Buffer;   // 32 bytes
}

export interface PingPayload { nonce: bigint; }
export interface PongPayload { nonce: bigint; }
export interface InvPayload { inventory: InvVector[]; }
export interface GetDataPayload { inventory: InvVector[]; }
export interface GetBlocksPayload { version: number; locatorHashes: Buffer[]; hashStop: Buffer; }
export interface GetHeadersPayload { version: number; locatorHashes: Buffer[]; hashStop: Buffer; }
export interface HeadersPayload { headers: BlockHeader[]; }
export interface BlockPayload { block: Block; }
export interface TxPayload { tx: Transaction; }

/**
 * Address with timestamp (used in addr message).
 */
export interface AddrPayload {
  addrs: { timestamp: number; addr: NetworkAddress }[];
}

/**
 * Reject message payload.
 */
export interface RejectPayload {
  message: string;
  ccode: number;
  reason: string;
  data?: Buffer;
}

/**
 * SendCmpct message payload (BIP 152).
 */
export interface SendCmpctPayload {
  enabled: boolean;
  version: bigint;
}

/**
 * FeeFilter message payload (BIP 133).
 */
export interface FeeFilterPayload {
  feeRate: bigint;
}

// ============================================================================
// BIP-152 Compact Block Relay
// ============================================================================

/**
 * Short transaction ID for compact blocks (6 bytes).
 * Computed as: SHA256(SHA256(nonce || txid))[0:6]
 */
export interface ShortTxId {
  shortId: Buffer;  // 6 bytes
}

/**
 * Prefilled transaction in a compact block.
 * Used for coinbase and any transactions not expected to be in mempool.
 */
export interface PrefilledTx {
  index: number;    // differentially encoded index
  tx: Transaction;
}

/**
 * Compact block message payload (BIP 152).
 *
 * Contains block header + short transaction IDs + prefilled transactions.
 * Allows reconstruction of the full block using transactions from mempool.
 */
export interface CmpctBlockPayload {
  header: BlockHeader;
  nonce: bigint;              // 64-bit nonce for short ID calculation
  shortIds: Buffer[];         // Array of 6-byte short transaction IDs
  prefilledTxns: PrefilledTx[];
}

/**
 * Request for block transactions not found in mempool.
 */
export interface GetBlockTxnPayload {
  blockHash: Buffer;          // 32 bytes
  indexes: number[];          // differentially encoded tx indices
}

/**
 * Response with requested transactions.
 */
export interface BlockTxnPayload {
  blockHash: Buffer;          // 32 bytes
  transactions: Transaction[];
}

// ============================================================================
// Header serialization
// ============================================================================

/**
 * Serialize a message header.
 *
 * @param magic - Network magic bytes (4 bytes LE)
 * @param command - Command name (max 12 chars, null-padded)
 * @param payload - Message payload (used to compute checksum)
 */
export function serializeHeader(magic: number, command: string, payload: Buffer): Buffer {
  if (command.length > 12) {
    throw new Error(`Command name too long: ${command}`);
  }
  if (payload.length > MAX_MESSAGE_SIZE) {
    throw new Error(`Payload too large: ${payload.length} > ${MAX_MESSAGE_SIZE}`);
  }

  const writer = new BufferWriter();

  // Magic (4 bytes LE)
  writer.writeUInt32LE(magic);

  // Command (12 bytes, null-padded)
  const cmdBuf = Buffer.alloc(12, 0);
  cmdBuf.write(command, 0, "ascii");
  writer.writeBytes(cmdBuf);

  // Payload length (4 bytes LE)
  writer.writeUInt32LE(payload.length);

  // Checksum (first 4 bytes of hash256(payload))
  const checksum = hash256(payload).subarray(0, 4);
  writer.writeBytes(checksum);

  return writer.toBuffer();
}

/**
 * Parse a message header from raw bytes.
 *
 * @param data - 24 bytes of header data
 * @returns Parsed header or null if insufficient data
 */
export function parseHeader(data: Buffer): MessageHeader | null {
  if (data.length < MESSAGE_HEADER_SIZE) {
    return null;
  }

  const reader = new BufferReader(data);

  const magic = reader.readUInt32LE();
  const cmdBuf = reader.readBytes(12);
  const length = reader.readUInt32LE();
  const checksum = reader.readBytes(4);

  // Extract command name (up to first null byte)
  let commandEnd = cmdBuf.indexOf(0);
  if (commandEnd === -1) {
    commandEnd = 12;
  }
  const command = cmdBuf.toString("ascii", 0, commandEnd);

  // Validate payload length
  if (length > MAX_MESSAGE_SIZE) {
    throw new Error(`Payload length exceeds maximum: ${length} > ${MAX_MESSAGE_SIZE}`);
  }

  return { magic, command, length, checksum };
}

// ============================================================================
// Network address serialization
// ============================================================================

/**
 * Convert an IPv4 address string to a 16-byte IPv4-mapped IPv6 buffer.
 *
 * IPv4-mapped IPv6 format: 00000000 00000000 0000FFFF + 4 IPv4 bytes
 */
export function ipv4ToBuffer(ip: string): Buffer {
  const parts = ip.split(".");
  if (parts.length !== 4) {
    throw new Error(`Invalid IPv4 address: ${ip}`);
  }

  const buf = Buffer.alloc(16, 0);

  // IPv4-mapped IPv6 prefix: ::ffff:
  buf[10] = 0xff;
  buf[11] = 0xff;

  // IPv4 bytes
  for (let i = 0; i < 4; i++) {
    const octet = parseInt(parts[i], 10);
    if (isNaN(octet) || octet < 0 || octet > 255) {
      throw new Error(`Invalid IPv4 octet: ${parts[i]}`);
    }
    buf[12 + i] = octet;
  }

  return buf;
}

function serializeNetworkAddress(writer: BufferWriter, addr: NetworkAddress): void {
  writer.writeUInt64LE(addr.services);
  if (addr.ip.length !== 16) {
    throw new Error(`Invalid IP buffer length: ${addr.ip.length}, expected 16`);
  }
  writer.writeBytes(addr.ip);
  // Port is big-endian!
  const portBuf = Buffer.alloc(2);
  portBuf.writeUInt16BE(addr.port, 0);
  writer.writeBytes(portBuf);
}

function deserializeNetworkAddress(reader: BufferReader): NetworkAddress {
  const services = reader.readUInt64LE();
  const ip = reader.readBytes(16);
  // Port is big-endian!
  const portBuf = reader.readBytes(2);
  const port = portBuf.readUInt16BE(0);
  return { services, ip, port };
}

// ============================================================================
// Payload serializers
// ============================================================================

function serializeVersionPayload(payload: VersionPayload): Buffer {
  const writer = new BufferWriter();

  writer.writeInt32LE(payload.version);
  writer.writeUInt64LE(payload.services);

  // Timestamp as int64 (signed, but always positive)
  const timestampBuf = Buffer.alloc(8);
  timestampBuf.writeBigInt64LE(payload.timestamp, 0);
  writer.writeBytes(timestampBuf);

  // Address receiving (no timestamp prefix in version message)
  serializeNetworkAddress(writer, payload.addrRecv);

  // Address from (no timestamp prefix in version message)
  serializeNetworkAddress(writer, payload.addrFrom);

  writer.writeUInt64LE(payload.nonce);
  writer.writeVarString(payload.userAgent);
  writer.writeInt32LE(payload.startHeight);
  writer.writeUInt8(payload.relay ? 1 : 0);

  return writer.toBuffer();
}

function serializePingPongPayload(nonce: bigint): Buffer {
  const writer = new BufferWriter();
  writer.writeUInt64LE(nonce);
  return writer.toBuffer();
}

function serializeInvVector(writer: BufferWriter, inv: InvVector): void {
  writer.writeUInt32LE(inv.type);
  if (inv.hash.length !== 32) {
    throw new Error(`Invalid inv hash length: ${inv.hash.length}, expected 32`);
  }
  writer.writeHash(inv.hash);
}

function serializeInvPayload(inventory: InvVector[]): Buffer {
  const writer = new BufferWriter();
  writer.writeVarInt(inventory.length);
  for (const inv of inventory) {
    serializeInvVector(writer, inv);
  }
  return writer.toBuffer();
}

function serializeBlockLocator(version: number, locatorHashes: Buffer[], hashStop: Buffer): Buffer {
  const writer = new BufferWriter();
  writer.writeUInt32LE(version);
  writer.writeVarInt(locatorHashes.length);
  for (const hash of locatorHashes) {
    if (hash.length !== 32) {
      throw new Error(`Invalid locator hash length: ${hash.length}, expected 32`);
    }
    writer.writeHash(hash);
  }
  if (hashStop.length !== 32) {
    throw new Error(`Invalid hashStop length: ${hashStop.length}, expected 32`);
  }
  writer.writeHash(hashStop);
  return writer.toBuffer();
}

function serializeHeadersPayload(headers: BlockHeader[]): Buffer {
  const writer = new BufferWriter();
  writer.writeVarInt(headers.length);
  for (const header of headers) {
    writer.writeBytes(serializeBlockHeader(header));
    // Each header is followed by a varint txn_count (always 0 in headers message)
    writer.writeVarInt(0);
  }
  return writer.toBuffer();
}

function serializeAddrPayload(addrs: { timestamp: number; addr: NetworkAddress }[]): Buffer {
  const writer = new BufferWriter();
  writer.writeVarInt(addrs.length);
  for (const entry of addrs) {
    writer.writeUInt32LE(entry.timestamp);
    serializeNetworkAddress(writer, entry.addr);
  }
  return writer.toBuffer();
}

function serializeRejectPayload(payload: RejectPayload): Buffer {
  const writer = new BufferWriter();
  writer.writeVarString(payload.message);
  writer.writeUInt8(payload.ccode);
  writer.writeVarString(payload.reason);
  if (payload.data) {
    writer.writeBytes(payload.data);
  }
  return writer.toBuffer();
}

function serializeSendCmpctPayload(payload: SendCmpctPayload): Buffer {
  const writer = new BufferWriter();
  writer.writeUInt8(payload.enabled ? 1 : 0);
  writer.writeUInt64LE(payload.version);
  return writer.toBuffer();
}

function serializeFeeFilterPayload(payload: FeeFilterPayload): Buffer {
  const writer = new BufferWriter();
  writer.writeUInt64LE(payload.feeRate);
  return writer.toBuffer();
}

function serializeCmpctBlockPayload(payload: CmpctBlockPayload): Buffer {
  const writer = new BufferWriter();

  // Header (80 bytes)
  writer.writeBytes(serializeBlockHeader(payload.header));

  // Nonce (8 bytes)
  writer.writeUInt64LE(payload.nonce);

  // Short IDs count and data
  writer.writeVarInt(payload.shortIds.length);
  for (const shortId of payload.shortIds) {
    if (shortId.length !== 6) {
      throw new Error(`Invalid short ID length: ${shortId.length}, expected 6`);
    }
    writer.writeBytes(shortId);
  }

  // Prefilled transactions (differentially encoded indices)
  writer.writeVarInt(payload.prefilledTxns.length);
  let lastIndex = -1;
  for (const prefilled of payload.prefilledTxns) {
    // Differential encoding: store difference from last index - 1
    const diff = prefilled.index - lastIndex - 1;
    writer.writeVarInt(diff);
    writer.writeBytes(serializeTx(prefilled.tx, true));
    lastIndex = prefilled.index;
  }

  return writer.toBuffer();
}

function serializeGetBlockTxnPayload(payload: GetBlockTxnPayload): Buffer {
  const writer = new BufferWriter();

  writer.writeHash(payload.blockHash);

  // Differentially encoded indices
  writer.writeVarInt(payload.indexes.length);
  let lastIndex = -1;
  for (const index of payload.indexes) {
    const diff = index - lastIndex - 1;
    writer.writeVarInt(diff);
    lastIndex = index;
  }

  return writer.toBuffer();
}

function serializeBlockTxnPayload(payload: BlockTxnPayload): Buffer {
  const writer = new BufferWriter();

  writer.writeHash(payload.blockHash);
  writer.writeVarInt(payload.transactions.length);
  for (const tx of payload.transactions) {
    writer.writeBytes(serializeTx(tx, true));
  }

  return writer.toBuffer();
}

// ============================================================================
// Payload deserializers
// ============================================================================

function deserializeVersionPayload(reader: BufferReader): VersionPayload {
  const version = reader.readInt32LE();
  const services = reader.readUInt64LE();

  // Timestamp as int64
  const timestampBuf = reader.readBytes(8);
  const timestamp = timestampBuf.readBigInt64LE(0);

  const addrRecv = deserializeNetworkAddress(reader);
  const addrFrom = deserializeNetworkAddress(reader);
  const nonce = reader.readUInt64LE();
  const userAgent = reader.readVarString();
  const startHeight = reader.readInt32LE();

  // relay is optional (BIP 37), default to true
  let relay = true;
  if (reader.remaining > 0) {
    relay = reader.readUInt8() !== 0;
  }

  return {
    version,
    services,
    timestamp,
    addrRecv,
    addrFrom,
    nonce,
    userAgent,
    startHeight,
    relay,
  };
}

function deserializePingPongPayload(reader: BufferReader): { nonce: bigint } {
  const nonce = reader.readUInt64LE();
  return { nonce };
}

function deserializeInvVector(reader: BufferReader): InvVector {
  const type = reader.readUInt32LE() as InvType;
  const hash = reader.readHash();
  return { type, hash };
}

function deserializeInvPayload(reader: BufferReader): InvPayload {
  const count = reader.readVarInt();
  const inventory: InvVector[] = [];
  for (let i = 0; i < count; i++) {
    inventory.push(deserializeInvVector(reader));
  }
  return { inventory };
}

function deserializeBlockLocator(reader: BufferReader): { version: number; locatorHashes: Buffer[]; hashStop: Buffer } {
  const version = reader.readUInt32LE();
  const count = reader.readVarInt();
  const locatorHashes: Buffer[] = [];
  for (let i = 0; i < count; i++) {
    locatorHashes.push(reader.readHash());
  }
  const hashStop = reader.readHash();
  return { version, locatorHashes, hashStop };
}

function deserializeHeadersPayload(reader: BufferReader): HeadersPayload {
  const count = reader.readVarInt();
  const headers: BlockHeader[] = [];
  for (let i = 0; i < count; i++) {
    const header = deserializeBlockHeader(reader);
    // Read and discard txn_count (always 0 in headers message)
    reader.readVarInt();
    headers.push(header);
  }
  return { headers };
}

function deserializeAddrPayload(reader: BufferReader): AddrPayload {
  const count = reader.readVarInt();
  const addrs: { timestamp: number; addr: NetworkAddress }[] = [];
  for (let i = 0; i < count; i++) {
    const timestamp = reader.readUInt32LE();
    const addr = deserializeNetworkAddress(reader);
    addrs.push({ timestamp, addr });
  }
  return { addrs };
}

function deserializeRejectPayload(reader: BufferReader): RejectPayload {
  const message = reader.readVarString();
  const ccode = reader.readUInt8();
  const reason = reader.readVarString();

  // data is optional (32 bytes for block/tx hash)
  let data: Buffer | undefined;
  if (reader.remaining > 0) {
    data = reader.readBytes(reader.remaining);
  }

  return { message, ccode, reason, data };
}

function deserializeSendCmpctPayload(reader: BufferReader): SendCmpctPayload {
  const enabled = reader.readUInt8() !== 0;
  const version = reader.readUInt64LE();
  return { enabled, version };
}

function deserializeFeeFilterPayload(reader: BufferReader): FeeFilterPayload {
  const feeRate = reader.readUInt64LE();
  return { feeRate };
}

function deserializeCmpctBlockPayload(reader: BufferReader): CmpctBlockPayload {
  const header = deserializeBlockHeader(reader);
  const nonce = reader.readUInt64LE();

  // Short IDs
  const shortIdCount = reader.readVarInt();
  const shortIds: Buffer[] = [];
  for (let i = 0; i < shortIdCount; i++) {
    shortIds.push(reader.readBytes(6));
  }

  // Prefilled transactions (differentially encoded)
  const prefilledCount = reader.readVarInt();
  const prefilledTxns: PrefilledTx[] = [];
  let lastIndex = -1;
  for (let i = 0; i < prefilledCount; i++) {
    const diff = reader.readVarInt();
    const index = lastIndex + diff + 1;
    const tx = deserializeTx(reader);
    prefilledTxns.push({ index, tx });
    lastIndex = index;
  }

  return { header, nonce, shortIds, prefilledTxns };
}

function deserializeGetBlockTxnPayload(reader: BufferReader): GetBlockTxnPayload {
  const blockHash = reader.readHash();

  // Differentially encoded indices
  const count = reader.readVarInt();
  const indexes: number[] = [];
  let lastIndex = -1;
  for (let i = 0; i < count; i++) {
    const diff = reader.readVarInt();
    const index = lastIndex + diff + 1;
    indexes.push(index);
    lastIndex = index;
  }

  return { blockHash, indexes };
}

function deserializeBlockTxnPayload(reader: BufferReader): BlockTxnPayload {
  const blockHash = reader.readHash();
  const count = reader.readVarInt();
  const transactions: Transaction[] = [];
  for (let i = 0; i < count; i++) {
    transactions.push(deserializeTx(reader));
  }
  return { blockHash, transactions };
}

// ============================================================================
// Main serialization/deserialization functions
// ============================================================================

/**
 * Serialize a complete network message (header + payload).
 *
 * @param magic - Network magic bytes
 * @param msg - Network message to serialize
 * @returns Complete message buffer (header + payload)
 */
export function serializeMessage(magic: number, msg: NetworkMessage): Buffer {
  let payload: Buffer;
  let command: string;

  switch (msg.type) {
    case "version":
      command = "version";
      payload = serializeVersionPayload(msg.payload);
      break;
    case "verack":
      command = "verack";
      payload = Buffer.alloc(0);
      break;
    case "ping":
      command = "ping";
      payload = serializePingPongPayload(msg.payload.nonce);
      break;
    case "pong":
      command = "pong";
      payload = serializePingPongPayload(msg.payload.nonce);
      break;
    case "inv":
      command = "inv";
      payload = serializeInvPayload(msg.payload.inventory);
      break;
    case "getdata":
      command = "getdata";
      payload = serializeInvPayload(msg.payload.inventory);
      break;
    case "getblocks":
      command = "getblocks";
      payload = serializeBlockLocator(
        msg.payload.version,
        msg.payload.locatorHashes,
        msg.payload.hashStop
      );
      break;
    case "getheaders":
      command = "getheaders";
      payload = serializeBlockLocator(
        msg.payload.version,
        msg.payload.locatorHashes,
        msg.payload.hashStop
      );
      break;
    case "headers":
      command = "headers";
      payload = serializeHeadersPayload(msg.payload.headers);
      break;
    case "block":
      command = "block";
      payload = serializeBlock(msg.payload.block);
      break;
    case "tx":
      command = "tx";
      payload = serializeTx(msg.payload.tx, true);
      break;
    case "addr":
      command = "addr";
      payload = serializeAddrPayload(msg.payload.addrs);
      break;
    case "getaddr":
      command = "getaddr";
      payload = Buffer.alloc(0);
      break;
    case "reject":
      command = "reject";
      payload = serializeRejectPayload(msg.payload);
      break;
    case "sendheaders":
      command = "sendheaders";
      payload = Buffer.alloc(0);
      break;
    case "sendcmpct":
      command = "sendcmpct";
      payload = serializeSendCmpctPayload(msg.payload);
      break;
    case "feefilter":
      command = "feefilter";
      payload = serializeFeeFilterPayload(msg.payload);
      break;
    case "wtxidrelay":
      command = "wtxidrelay";
      payload = Buffer.alloc(0);
      break;
    case "sendaddrv2":
      command = "sendaddrv2";
      payload = Buffer.alloc(0);
      break;
    case "cmpctblock":
      command = "cmpctblock";
      payload = serializeCmpctBlockPayload(msg.payload);
      break;
    case "getblocktxn":
      command = "getblocktxn";
      payload = serializeGetBlockTxnPayload(msg.payload);
      break;
    case "blocktxn":
      command = "blocktxn";
      payload = serializeBlockTxnPayload(msg.payload);
      break;
    default:
      throw new Error(`Unknown message type: ${(msg as NetworkMessage).type}`);
  }

  const header = serializeHeader(magic, command, payload);
  return Buffer.concat([header, payload]);
}

/**
 * Deserialize a message payload given the parsed header.
 *
 * @param header - Parsed message header
 * @param payload - Raw payload bytes
 * @returns Deserialized network message
 */
export function deserializeMessage(header: MessageHeader, payload: Buffer): NetworkMessage {
  // Verify checksum
  const expectedChecksum = hash256(payload).subarray(0, 4);
  if (!header.checksum.equals(expectedChecksum)) {
    throw new Error(
      `Checksum mismatch: expected ${expectedChecksum.toString("hex")}, got ${header.checksum.toString("hex")}`
    );
  }

  const reader = new BufferReader(payload);

  switch (header.command) {
    case "version":
      return { type: "version", payload: deserializeVersionPayload(reader) };
    case "verack":
      return { type: "verack", payload: null };
    case "ping":
      return { type: "ping", payload: deserializePingPongPayload(reader) };
    case "pong":
      return { type: "pong", payload: deserializePingPongPayload(reader) };
    case "inv":
      return { type: "inv", payload: deserializeInvPayload(reader) };
    case "getdata":
      return { type: "getdata", payload: deserializeInvPayload(reader) };
    case "getblocks": {
      const locator = deserializeBlockLocator(reader);
      return { type: "getblocks", payload: locator };
    }
    case "getheaders": {
      const locator = deserializeBlockLocator(reader);
      return { type: "getheaders", payload: locator };
    }
    case "headers":
      return { type: "headers", payload: deserializeHeadersPayload(reader) };
    case "block":
      return { type: "block", payload: { block: deserializeBlock(reader) } };
    case "tx":
      return { type: "tx", payload: { tx: deserializeTx(reader) } };
    case "addr":
      return { type: "addr", payload: deserializeAddrPayload(reader) };
    case "getaddr":
      return { type: "getaddr", payload: null };
    case "reject":
      return { type: "reject", payload: deserializeRejectPayload(reader) };
    case "sendheaders":
      return { type: "sendheaders", payload: null };
    case "sendcmpct":
      return { type: "sendcmpct", payload: deserializeSendCmpctPayload(reader) };
    case "feefilter":
      return { type: "feefilter", payload: deserializeFeeFilterPayload(reader) };
    case "wtxidrelay":
      return { type: "wtxidrelay", payload: null };
    case "sendaddrv2":
      return { type: "sendaddrv2", payload: null };
    case "cmpctblock":
      return { type: "cmpctblock", payload: deserializeCmpctBlockPayload(reader) };
    case "getblocktxn":
      return { type: "getblocktxn", payload: deserializeGetBlockTxnPayload(reader) };
    case "blocktxn":
      return { type: "blocktxn", payload: deserializeBlockTxnPayload(reader) };
    default:
      throw new Error(`Unknown command: ${header.command}`);
  }
}

// ============================================================================
// BIP-152 Compact Block Helper Functions
// ============================================================================

import { sha256Hash } from "../crypto/primitives.js";

/**
 * Compute short transaction ID for compact blocks (BIP 152).
 *
 * shortid = SipHash-2-4(k0, k1, txid)[0:6]
 * where k0, k1 are derived from SHA256(header || nonce)
 *
 * For simplicity, we use SHA256 truncated (not SipHash) as an approximation.
 * Full BIP-152 implementation would use SipHash.
 */
export function computeShortTxId(
  headerHash: Buffer,
  nonce: bigint,
  txid: Buffer
): Buffer {
  // Compute key = SHA256(header || nonce)
  const nonceBuffer = Buffer.alloc(8);
  nonceBuffer.writeBigUInt64LE(nonce, 0);
  const keyData = Buffer.concat([headerHash, nonceBuffer]);
  const key = sha256Hash(keyData);

  // Compute short ID = SHA256(key || txid)[0:6]
  const shortIdData = Buffer.concat([key, txid]);
  const fullHash = sha256Hash(shortIdData);

  return fullHash.subarray(0, 6);
}

/**
 * Create a compact block from a full block.
 *
 * @param block - Full block to compact
 * @param nonce - Random nonce for short ID calculation
 * @param mempoolTxIds - Set of txids known to be in peer's mempool
 */
export function createCompactBlock(
  block: Block,
  nonce: bigint,
  mempoolTxIds: Set<string> = new Set()
): CmpctBlockPayload {
  const headerHash = hash256(serializeBlockHeader(block.header));
  const shortIds: Buffer[] = [];
  const prefilledTxns: PrefilledTx[] = [];

  for (let i = 0; i < block.transactions.length; i++) {
    const tx = block.transactions[i];
    const txid = getTxId(tx);

    // Always include coinbase in prefilled
    if (i === 0) {
      prefilledTxns.push({ index: i, tx });
      continue;
    }

    // If not in mempool, include in prefilled
    const txidHex = txid.toString("hex");
    if (!mempoolTxIds.has(txidHex)) {
      prefilledTxns.push({ index: i, tx });
    } else {
      // Add short ID
      shortIds.push(computeShortTxId(headerHash, nonce, txid));
    }
  }

  return {
    header: block.header,
    nonce,
    shortIds,
    prefilledTxns,
  };
}

/**
 * Reconstruct a full block from a compact block and mempool transactions.
 *
 * @param compact - Compact block
 * @param txLookup - Map from short ID (hex) to full transaction
 * @returns Reconstructed block or null if transactions are missing
 */
export function reconstructBlockFromCompact(
  compact: CmpctBlockPayload,
  txLookup: Map<string, Transaction>
): Block | null {
  // Total transaction count = shortIds + prefilledTxns
  const txCount = compact.shortIds.length + compact.prefilledTxns.length;
  const transactions: (Transaction | undefined)[] = new Array(txCount);

  // Place prefilled transactions
  for (const prefilled of compact.prefilledTxns) {
    if (prefilled.index >= txCount) {
      return null; // Invalid index
    }
    transactions[prefilled.index] = prefilled.tx;
  }

  // Fill remaining from lookup
  let shortIdIndex = 0;
  for (let i = 0; i < txCount; i++) {
    if (transactions[i] === undefined) {
      if (shortIdIndex >= compact.shortIds.length) {
        return null; // Not enough short IDs
      }
      const shortIdHex = compact.shortIds[shortIdIndex].toString("hex");
      const tx = txLookup.get(shortIdHex);
      if (!tx) {
        return null; // Transaction not found
      }
      transactions[i] = tx;
      shortIdIndex++;
    }
  }

  // Verify all slots are filled
  for (const tx of transactions) {
    if (tx === undefined) {
      return null;
    }
  }

  return {
    header: compact.header,
    transactions: transactions as Transaction[],
  };
}

import { getTxId } from "../validation/tx.js";
