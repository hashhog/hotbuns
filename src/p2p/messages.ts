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
import {
  type AddrV2Payload,
  serializeAddrV2Payload,
  deserializeAddrV2Payload,
} from "./addrv2.js";
import { parseIPv4, parseIPv6 } from "./asmap.js";

// Re-export addrv2 types for convenience
export type { AddrV2Payload, NetworkAddressV2, AddrV2Entry } from "./addrv2.js";
export {
  BIP155Network,
  isValidNetworkAddressV2,
  isAddrV1Compatible,
  legacyAddressToNetworkAddressV2,
  networkAddressV2ToLegacy,
  ipv4ToNetworkAddressV2,
  networkAddressV2ToIPv4String,
  formatNetworkAddressV2,
  getNetworkName,
} from "./addrv2.js";

/** Maximum message payload size: 4 MB (matches Core MAX_PROTOCOL_MESSAGE_LENGTH) */
export const MAX_MESSAGE_SIZE = 4 * 1000 * 1000;

/** Message header size in bytes */
export const MESSAGE_HEADER_SIZE = 24;

// ============================================================================
// Wire-decode caps (DoS protection)
//
// Adversarial peers may craft a varint count larger than the protocol bounds
// to force gigabyte-scale allocation before the loop fails to find more wire
// bytes. Each peer-supplied count MUST be checked against the corresponding
// Core protocol limit BEFORE allocating / looping. Values mirror Bitcoin Core
// `src/net_processing.cpp` / `src/net_processing.h`.
// ============================================================================

/** Maximum entries in an inv / getdata / notfound message (Core MAX_INV_SZ). */
export const MAX_INV_SZ = 50_000;

/** Maximum headers per `headers` message (Core MAX_HEADERS_RESULTS). */
export const MAX_HEADERS_RESULTS = 2_000;

/** Maximum addresses per `addr` / `addrv2` message (Core MAX_ADDR_TO_SEND). */
export const MAX_ADDR_TO_SEND = 1_000;

/**
 * Maximum hashes in a `getblocks` / `getheaders` block locator.
 *
 * Core `chain.h:MAX_LOCATOR_SZ = 101` (log2(maxHeight)+10). We cap at 101 to
 * mirror Core; honest peers send well under this.
 */
export const MAX_LOCATOR_SZ = 101;

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
  | { type: "addrv2"; payload: AddrV2Payload }
  | { type: "getaddr"; payload: null }
  | { type: "reject"; payload: RejectPayload }
  | { type: "sendheaders"; payload: null }
  | { type: "sendcmpct"; payload: SendCmpctPayload }
  | { type: "feefilter"; payload: FeeFilterPayload }
  | { type: "wtxidrelay"; payload: null }
  | { type: "sendaddrv2"; payload: null }
  | { type: "mempool"; payload: null }
  | { type: "cmpctblock"; payload: CmpctBlockPayload }
  | { type: "getblocktxn"; payload: GetBlockTxnPayload }
  | { type: "blocktxn"; payload: BlockTxnPayload }
  // Package relay messages
  | { type: "sendpackages"; payload: SendPackagesPayload }
  | { type: "ancpkginfo"; payload: AncPkgInfoPayload }
  | { type: "getpkgtxns"; payload: GetPkgTxnsPayload }
  | { type: "pkgtxns"; payload: PkgTxnsPayload }
  // BIP-330 Erlay transaction reconciliation
  | { type: "sendtxrcncl"; payload: SendTxRcnclPayload }
  | { type: "reqrecon"; payload: ReqReconPayload }
  | { type: "sketch"; payload: SketchPayload }
  | { type: "reqsketchext"; payload: ReqSketchExtPayload }
  | { type: "reconcildiff"; payload: ReconcilDiffPayload }
  | { type: "invtx"; payload: InvTxPayload }
  | { type: "notfound"; payload: InvPayload }
  // BIP-157 compact block filter messages
  | { type: "getcfilters"; payload: GetCFiltersPayload }
  | { type: "cfilter"; payload: CFilterPayload }
  | { type: "getcfheaders"; payload: GetCFHeadersPayload }
  | { type: "cfheaders"; payload: CFHeadersPayload }
  | { type: "getcfcheckpt"; payload: GetCFCheckPtPayload }
  | { type: "cfcheckpt"; payload: CFCheckPtPayload };

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
  /**
   * BIP-339 / Bitcoin Core protocol.h: MSG_WTX = 5.
   * Used in inv messages to announce a transaction by wtxid to a
   * wtxid-relay peer.  This is the correct inv type for wtxid-relay peers.
   * Note: MSG_WITNESS_TX (0x40000001) is a BIP-144 *getdata flag*, not a
   * valid inv type — Core peers silently discard inv entries with that type.
   */
  MSG_WTX = 5,
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
// Package Relay Messages (BIP 331-style)
// ============================================================================

/**
 * SendPackages message payload.
 * Announces support for package relay. Sent during version handshake.
 */
export interface SendPackagesPayload {
  version: number;  // Package relay protocol version
}

/**
 * AncPkgInfo message payload.
 * Announces an available package to a peer.
 */
export interface AncPkgInfoPayload {
  packageHash: Buffer;        // 32 bytes - SHA256 of sorted wtxids
  packageFeeRate: bigint;     // Fee rate in satoshis per kvB
  packageWeight: number;      // Total weight of the package
  txCount: number;            // Number of transactions in the package
}

/**
 * GetPkgTxns message payload.
 * Request specific transactions from an announced package.
 */
export interface GetPkgTxnsPayload {
  packageHash: Buffer;        // 32 bytes - identifies the package
  wtxids: Buffer[];           // wtxids of requested transactions
}

/**
 * PkgTxns message payload.
 * Response with requested package transactions.
 */
export interface PkgTxnsPayload {
  packageHash: Buffer;        // 32 bytes - identifies the package
  transactions: Transaction[];  // The requested transactions
}

// ============================================================================
// BIP-330 Erlay Transaction Reconciliation Messages
// ============================================================================

/**
 * SendTxRcncl message payload (BIP-330).
 * Sent during handshake to negotiate Erlay support.
 */
export interface SendTxRcnclPayload {
  version: number;            // uint32 - protocol version (currently 1)
  salt: bigint;               // uint64 - random salt for short ID computation
}

/**
 * ReqRecon message payload (BIP-330).
 * Initiator requests reconciliation with a peer.
 */
export interface ReqReconPayload {
  setSize: number;            // uint16 - size of local reconciliation set
  q: number;                  // uint16 - estimated difference coefficient
}

/**
 * Sketch message payload (BIP-330).
 * Responder sends their sketch for set reconciliation.
 */
export interface SketchPayload {
  sketchData: Buffer;         // Serialized Minisketch data
}

/**
 * ReqSketchExt message payload (BIP-330).
 * Request sketch extension when initial reconciliation fails.
 */
export interface ReqSketchExtPayload {
  // Empty payload - just signals need for extension
}

/**
 * ReconcilDiff message payload (BIP-330).
 * Announce reconciliation result with missing/extra short IDs.
 */
export interface ReconcilDiffPayload {
  success: boolean;           // Whether reconciliation succeeded
  localMissing: number[];     // Short IDs of txs we're missing (32-bit each)
  remoteMissing: number[];    // Short IDs of txs peer is missing
}

/**
 * InvTx message payload (BIP-330).
 * Announce transactions by wtxid after reconciliation.
 */
export interface InvTxPayload {
  wtxids: Buffer[];           // Array of 32-byte wtxids
}

// ============================================================================
// BIP-157 Compact Block Filter P2P Messages
// ============================================================================

/**
 * BIP-157 protocol constants.
 *
 * Reference:
 *   - bitcoin-core/src/net_processing.cpp:184-186 — MAX_GETCF{ILTERS,HEADERS}_SIZE
 *   - bitcoin-core/src/index/blockfilterindex.h:31 — CFCHECKPT_INTERVAL
 *   - bitcoin-core/src/protocol.h:323 — NODE_COMPACT_FILTERS = (1 << 6)
 */
/** Max blocks per `getcfilters` request (BIP-157). */
export const MAX_GETCFILTERS_SIZE = 1000;
/** Max blocks per `getcfheaders` request (BIP-157). */
export const MAX_GETCFHEADERS_SIZE = 2000;
/** Cfcheckpoint interval per Core (every 1000th block from genesis). */
export const CFCHECKPT_INTERVAL = 1000;
/** BIP-157 NODE_COMPACT_FILTERS service-flag bit (Core protocol.h:323). */
export const NODE_COMPACT_FILTERS_BIT = 64n; // 1 << 6

/**
 * BIP-157 `getcfilters` message payload.
 *
 *   filter_type:  uint8 (0 = BASIC)
 *   start_height: uint32 LE
 *   stop_hash:    uint256 (32 bytes LE, the block hash to walk back from)
 */
export interface GetCFiltersPayload {
  filterType: number;     // uint8
  startHeight: number;    // uint32
  stopHash: Buffer;       // 32 bytes
}

/**
 * BIP-157 `cfilter` message payload.
 *
 *   filter_type: uint8
 *   block_hash:  uint256
 *   filter_bytes: varlen byte string (GCS-encoded basic filter)
 */
export interface CFilterPayload {
  filterType: number;
  blockHash: Buffer;
  filterBytes: Buffer;
}

/**
 * BIP-157 `getcfheaders` message payload.
 *
 *   filter_type:  uint8
 *   start_height: uint32 LE
 *   stop_hash:    uint256
 */
export interface GetCFHeadersPayload {
  filterType: number;
  startHeight: number;
  stopHash: Buffer;
}

/**
 * BIP-157 `cfheaders` message payload.
 *
 *   filter_type:        uint8
 *   stop_hash:          uint256
 *   previous_filter_header: uint256 (filter header for block `start_height - 1`)
 *   filter_hashes:      varint count + count * uint256
 */
export interface CFHeadersPayload {
  filterType: number;
  stopHash: Buffer;
  previousFilterHeader: Buffer;
  filterHashes: Buffer[];
}

/**
 * BIP-157 `getcfcheckpt` message payload.
 *
 *   filter_type: uint8
 *   stop_hash:   uint256
 */
export interface GetCFCheckPtPayload {
  filterType: number;
  stopHash: Buffer;
}

/**
 * BIP-157 `cfcheckpt` message payload.
 *
 *   filter_type:    uint8
 *   stop_hash:      uint256
 *   filter_headers: varint count + count * uint256 (every CFCHECKPT_INTERVAL block)
 */
export interface CFCheckPtPayload {
  filterType: number;
  stopHash: Buffer;
  filterHeaders: Buffer[];
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

/**
 * Convert a peer host string to the 16-byte legacy network-address buffer used
 * in the VERSION message's addrRecv/addrFrom fields.
 *
 * Unlike {@link ipv4ToBuffer}, this accepts BOTH IPv4 and IPv6 literals:
 *   - IPv4 ("1.2.3.4")        → IPv4-mapped IPv6 (::ffff:1.2.3.4)
 *   - IPv6 ("2001:db8::1", "[::1]") → the 16-byte address as-is
 *   - anything else (onion/i2p/cjdns hostnames, unresolved names) → the
 *     unspecified address (16 zero bytes), which Core treats as "no addr".
 *
 * This never throws on a parseable-or-not host, so an IPv6 peer no longer
 * surfaces "processRecvBuffer failed: Invalid IPv4 address: <ipv6>" when we
 * build our VERSION reply. The legacy addr field is informational only (Core
 * does not validate the peer-reported addrRecv against the socket), so a
 * best-effort encoding with a zero-addr fallback preserves wire semantics.
 */
export function hostToBuffer(host: string): Buffer {
  // IPv6 literals contain ':' (IPv4 dotted-decimal never does).
  if (host.includes(":")) {
    const v6 = parseIPv6(host);
    if (v6) {
      return Buffer.from(v6);
    }
    // Unparseable v6-looking host (shouldn't happen for a connected peer) —
    // fall through to the zero-addr fallback rather than throwing.
    return Buffer.alloc(16, 0);
  }

  const v4 = parseIPv4(host);
  if (v4) {
    const buf = Buffer.alloc(16, 0);
    // IPv4-mapped IPv6 prefix: ::ffff:
    buf[10] = 0xff;
    buf[11] = 0xff;
    buf.set(v4, 12);
    return buf;
  }

  // Non-IP host (onion/i2p/cjdns/hostname): encode as the unspecified address.
  // These networks ride the addrv2 path; the legacy addr field is unused.
  return Buffer.alloc(16, 0);
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
// Package Relay Payload Serializers
// ============================================================================

function serializeSendPackagesPayload(payload: SendPackagesPayload): Buffer {
  const writer = new BufferWriter();
  writer.writeUInt32LE(payload.version);
  return writer.toBuffer();
}

function serializeAncPkgInfoPayload(payload: AncPkgInfoPayload): Buffer {
  const writer = new BufferWriter();

  if (payload.packageHash.length !== 32) {
    throw new Error(`Invalid package hash length: ${payload.packageHash.length}, expected 32`);
  }
  writer.writeHash(payload.packageHash);
  writer.writeUInt64LE(payload.packageFeeRate);
  writer.writeUInt32LE(payload.packageWeight);
  writer.writeVarInt(payload.txCount);

  return writer.toBuffer();
}

function serializeGetPkgTxnsPayload(payload: GetPkgTxnsPayload): Buffer {
  const writer = new BufferWriter();

  if (payload.packageHash.length !== 32) {
    throw new Error(`Invalid package hash length: ${payload.packageHash.length}, expected 32`);
  }
  writer.writeHash(payload.packageHash);

  writer.writeVarInt(payload.wtxids.length);
  for (const wtxid of payload.wtxids) {
    if (wtxid.length !== 32) {
      throw new Error(`Invalid wtxid length: ${wtxid.length}, expected 32`);
    }
    writer.writeHash(wtxid);
  }

  return writer.toBuffer();
}

function serializePkgTxnsPayload(payload: PkgTxnsPayload): Buffer {
  const writer = new BufferWriter();

  if (payload.packageHash.length !== 32) {
    throw new Error(`Invalid package hash length: ${payload.packageHash.length}, expected 32`);
  }
  writer.writeHash(payload.packageHash);

  writer.writeVarInt(payload.transactions.length);
  for (const tx of payload.transactions) {
    writer.writeBytes(serializeTx(tx, true));
  }

  return writer.toBuffer();
}

// ============================================================================
// BIP-330 Erlay Payload Serializers
// ============================================================================

function serializeSendTxRcnclPayload(payload: SendTxRcnclPayload): Buffer {
  const writer = new BufferWriter();
  writer.writeUInt32LE(payload.version);
  writer.writeUInt64LE(payload.salt);
  return writer.toBuffer();
}

function serializeReqReconPayload(payload: ReqReconPayload): Buffer {
  const writer = new BufferWriter();
  writer.writeUInt16LE(payload.setSize);
  writer.writeUInt16LE(payload.q);
  return writer.toBuffer();
}

function serializeSketchPayload(payload: SketchPayload): Buffer {
  const writer = new BufferWriter();
  writer.writeVarBytes(payload.sketchData);
  return writer.toBuffer();
}

function serializeReqSketchExtPayload(_payload: ReqSketchExtPayload): Buffer {
  // Empty payload
  return Buffer.alloc(0);
}

function serializeReconcilDiffPayload(payload: ReconcilDiffPayload): Buffer {
  const writer = new BufferWriter();

  // Success flag as uint8
  writer.writeUInt8(payload.success ? 1 : 0);

  // Local missing short IDs
  writer.writeVarInt(payload.localMissing.length);
  for (const shortId of payload.localMissing) {
    writer.writeUInt32LE(shortId);
  }

  // Remote missing short IDs
  writer.writeVarInt(payload.remoteMissing.length);
  for (const shortId of payload.remoteMissing) {
    writer.writeUInt32LE(shortId);
  }

  return writer.toBuffer();
}

function serializeInvTxPayload(payload: InvTxPayload): Buffer {
  const writer = new BufferWriter();

  writer.writeVarInt(payload.wtxids.length);
  for (const wtxid of payload.wtxids) {
    if (wtxid.length !== 32) {
      throw new Error(`Invalid wtxid length: ${wtxid.length}, expected 32`);
    }
    writer.writeHash(wtxid);
  }

  return writer.toBuffer();
}

// ============================================================================
// BIP-157 Compact Block Filter Payload Serializers / Deserializers
// ============================================================================
//
// Wire format mirrors bitcoin-core/src/net_processing.cpp ProcessGetCFilters /
// ProcessGetCFHeaders / ProcessGetCFCheckPt and the matching response sites.
// Filter and header hashes are 32 bytes little-endian (Core's internal
// uint256 ordering, identical to how block hashes are framed on the wire).

function serializeGetCFiltersPayload(payload: GetCFiltersPayload): Buffer {
  const writer = new BufferWriter();
  writer.writeUInt8(payload.filterType);
  writer.writeUInt32LE(payload.startHeight);
  writer.writeHash(payload.stopHash);
  return writer.toBuffer();
}

function deserializeGetCFiltersPayload(reader: BufferReader): GetCFiltersPayload {
  const filterType = reader.readUInt8();
  const startHeight = reader.readUInt32LE();
  const stopHash = reader.readHash();
  return { filterType, startHeight, stopHash };
}

function serializeCFilterPayload(payload: CFilterPayload): Buffer {
  const writer = new BufferWriter();
  writer.writeUInt8(payload.filterType);
  writer.writeHash(payload.blockHash);
  writer.writeVarBytes(payload.filterBytes);
  return writer.toBuffer();
}

function deserializeCFilterPayload(reader: BufferReader): CFilterPayload {
  const filterType = reader.readUInt8();
  const blockHash = reader.readHash();
  const filterBytes = reader.readVarBytes();
  return { filterType, blockHash, filterBytes };
}

function serializeGetCFHeadersPayload(payload: GetCFHeadersPayload): Buffer {
  const writer = new BufferWriter();
  writer.writeUInt8(payload.filterType);
  writer.writeUInt32LE(payload.startHeight);
  writer.writeHash(payload.stopHash);
  return writer.toBuffer();
}

function deserializeGetCFHeadersPayload(reader: BufferReader): GetCFHeadersPayload {
  const filterType = reader.readUInt8();
  const startHeight = reader.readUInt32LE();
  const stopHash = reader.readHash();
  return { filterType, startHeight, stopHash };
}

function serializeCFHeadersPayload(payload: CFHeadersPayload): Buffer {
  const writer = new BufferWriter();
  writer.writeUInt8(payload.filterType);
  writer.writeHash(payload.stopHash);
  writer.writeHash(payload.previousFilterHeader);
  writer.writeVarInt(payload.filterHashes.length);
  for (const h of payload.filterHashes) {
    if (h.length !== 32) {
      throw new Error(`Invalid filter hash length: ${h.length}, expected 32`);
    }
    writer.writeHash(h);
  }
  return writer.toBuffer();
}

function deserializeCFHeadersPayload(reader: BufferReader): CFHeadersPayload {
  const filterType = reader.readUInt8();
  const stopHash = reader.readHash();
  const previousFilterHeader = reader.readHash();
  const count = reader.readVarInt();
  // DoS cap: filter_hashes count must be <= MAX_GETCFHEADERS_SIZE on the wire.
  // Core caps via the request side (start..=stop range bounded). Decoder side
  // mirrors the same bound to prevent giant allocations from adversarial peers.
  if (count > MAX_GETCFHEADERS_SIZE) {
    throw new Error(
      `cfheaders.filter_hashes count exceeds MAX_GETCFHEADERS_SIZE: ` +
        `${count} > ${MAX_GETCFHEADERS_SIZE}`
    );
  }
  const filterHashes: Buffer[] = [];
  for (let i = 0; i < count; i++) {
    filterHashes.push(reader.readHash());
  }
  return { filterType, stopHash, previousFilterHeader, filterHashes };
}

function serializeGetCFCheckPtPayload(payload: GetCFCheckPtPayload): Buffer {
  const writer = new BufferWriter();
  writer.writeUInt8(payload.filterType);
  writer.writeHash(payload.stopHash);
  return writer.toBuffer();
}

function deserializeGetCFCheckPtPayload(reader: BufferReader): GetCFCheckPtPayload {
  const filterType = reader.readUInt8();
  const stopHash = reader.readHash();
  return { filterType, stopHash };
}

function serializeCFCheckPtPayload(payload: CFCheckPtPayload): Buffer {
  const writer = new BufferWriter();
  writer.writeUInt8(payload.filterType);
  writer.writeHash(payload.stopHash);
  writer.writeVarInt(payload.filterHeaders.length);
  for (const h of payload.filterHeaders) {
    if (h.length !== 32) {
      throw new Error(`Invalid filter header length: ${h.length}, expected 32`);
    }
    writer.writeHash(h);
  }
  return writer.toBuffer();
}

function deserializeCFCheckPtPayload(reader: BufferReader): CFCheckPtPayload {
  const filterType = reader.readUInt8();
  const stopHash = reader.readHash();
  const count = reader.readVarInt();
  // Defensive upper bound: a single getcfcheckpt covers every 1000th block from
  // genesis to stop_hash; for foreseeable mainnet heights this stays well under
  // ~1e5. Cap at 1e6 to bound adversarial allocations.
  if (count > 1_000_000) {
    throw new Error(
      `cfcheckpt.filter_headers count exceeds defensive cap: ${count} > 1000000`
    );
  }
  const filterHeaders: Buffer[] = [];
  for (let i = 0; i < count; i++) {
    filterHeaders.push(reader.readHash());
  }
  return { filterType, stopHash, filterHeaders };
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
  // DoS cap: reject before allocating (Core MAX_INV_SZ = 50000).
  if (count > MAX_INV_SZ) {
    throw new Error(`inv/getdata/notfound count exceeds MAX_INV_SZ: ${count} > ${MAX_INV_SZ}`);
  }
  const inventory: InvVector[] = [];
  for (let i = 0; i < count; i++) {
    inventory.push(deserializeInvVector(reader));
  }
  return { inventory };
}

function deserializeBlockLocator(reader: BufferReader): { version: number; locatorHashes: Buffer[]; hashStop: Buffer } {
  const version = reader.readUInt32LE();
  const count = reader.readVarInt();
  // DoS cap: reject before allocating (Core MAX_LOCATOR_SZ = 101).
  if (count > MAX_LOCATOR_SZ) {
    throw new Error(`block locator count exceeds MAX_LOCATOR_SZ: ${count} > ${MAX_LOCATOR_SZ}`);
  }
  const locatorHashes: Buffer[] = [];
  for (let i = 0; i < count; i++) {
    locatorHashes.push(reader.readHash());
  }
  const hashStop = reader.readHash();
  return { version, locatorHashes, hashStop };
}

function deserializeHeadersPayload(reader: BufferReader): HeadersPayload {
  const count = reader.readVarInt();
  // DoS cap: reject before allocating (Core MAX_HEADERS_RESULTS = 2000).
  if (count > MAX_HEADERS_RESULTS) {
    throw new Error(`headers count exceeds MAX_HEADERS_RESULTS: ${count} > ${MAX_HEADERS_RESULTS}`);
  }
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
  // DoS cap: reject before allocating (Core MAX_ADDR_TO_SEND = 1000).
  if (count > MAX_ADDR_TO_SEND) {
    throw new Error(`addr count exceeds MAX_ADDR_TO_SEND: ${count} > ${MAX_ADDR_TO_SEND}`);
  }
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

/**
 * Maximum total tx count in a cmpctblock message.
 *
 * Core: blockencodings.h serializer gate:
 *   BlockTxCount() > std::numeric_limits<uint16_t>::max() → throw
 * Combined shortIds + prefilledTxns must be ≤ 65535 (uint16_t max).
 * We also enforce the weight-based ceiling:
 *   MAX_BLOCK_WEIGHT (4_000_000) / MIN_SERIALIZABLE_TRANSACTION_WEIGHT (40) = 100_000
 * The tighter uint16_t bound (65535) dominates.
 */
const MAX_CMPCT_TOTAL_TX = 0xffff;

function deserializeCmpctBlockPayload(reader: BufferReader): CmpctBlockPayload {
  const header = deserializeBlockHeader(reader);
  const nonce = reader.readUInt64LE();

  // Short IDs — DoS cap before allocation.
  // Core: blockencodings.h:125-128 (uint16_t overflow gate on BlockTxCount).
  const shortIdCount = reader.readVarInt();
  if (shortIdCount > MAX_CMPCT_TOTAL_TX) {
    throw new Error(`cmpctblock shortId count exceeds limit: ${shortIdCount} > ${MAX_CMPCT_TOTAL_TX}`);
  }
  const shortIds: Buffer[] = [];
  for (let i = 0; i < shortIdCount; i++) {
    shortIds.push(reader.readBytes(6));
  }

  // Prefilled transactions (differentially encoded) — cap before allocation.
  const prefilledCount = reader.readVarInt();
  if (prefilledCount > MAX_CMPCT_TOTAL_TX) {
    throw new Error(`cmpctblock prefilled count exceeds limit: ${prefilledCount} > ${MAX_CMPCT_TOTAL_TX}`);
  }
  // Combined count must also fit.
  if (shortIdCount + prefilledCount > MAX_CMPCT_TOTAL_TX) {
    throw new Error(`cmpctblock total tx count exceeds limit: ${shortIdCount + prefilledCount} > ${MAX_CMPCT_TOTAL_TX}`);
  }
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
// Package Relay Payload Deserializers
// ============================================================================

function deserializeSendPackagesPayload(reader: BufferReader): SendPackagesPayload {
  const version = reader.readUInt32LE();
  return { version };
}

function deserializeAncPkgInfoPayload(reader: BufferReader): AncPkgInfoPayload {
  const packageHash = reader.readHash();
  const packageFeeRate = reader.readUInt64LE();
  const packageWeight = reader.readUInt32LE();
  const txCount = reader.readVarInt();

  return { packageHash, packageFeeRate, packageWeight, txCount };
}

function deserializeGetPkgTxnsPayload(reader: BufferReader): GetPkgTxnsPayload {
  const packageHash = reader.readHash();
  const count = reader.readVarInt();
  const wtxids: Buffer[] = [];

  for (let i = 0; i < count; i++) {
    wtxids.push(reader.readHash());
  }

  return { packageHash, wtxids };
}

function deserializePkgTxnsPayload(reader: BufferReader): PkgTxnsPayload {
  const packageHash = reader.readHash();
  const count = reader.readVarInt();
  const transactions: Transaction[] = [];

  for (let i = 0; i < count; i++) {
    transactions.push(deserializeTx(reader));
  }

  return { packageHash, transactions };
}

// ============================================================================
// BIP-330 Erlay Payload Deserializers
// ============================================================================

function deserializeSendTxRcnclPayload(reader: BufferReader): SendTxRcnclPayload {
  const version = reader.readUInt32LE();
  const salt = reader.readUInt64LE();
  return { version, salt };
}

function deserializeReqReconPayload(reader: BufferReader): ReqReconPayload {
  const setSize = reader.readUInt16LE();
  const q = reader.readUInt16LE();
  return { setSize, q };
}

function deserializeSketchPayload(reader: BufferReader): SketchPayload {
  const sketchData = reader.readVarBytes();
  return { sketchData };
}

function deserializeReqSketchExtPayload(_reader: BufferReader): ReqSketchExtPayload {
  // Empty payload
  return {};
}

function deserializeReconcilDiffPayload(reader: BufferReader): ReconcilDiffPayload {
  const success = reader.readUInt8() !== 0;

  const localMissingCount = reader.readVarInt();
  const localMissing: number[] = [];
  for (let i = 0; i < localMissingCount; i++) {
    localMissing.push(reader.readUInt32LE());
  }

  const remoteMissingCount = reader.readVarInt();
  const remoteMissing: number[] = [];
  for (let i = 0; i < remoteMissingCount; i++) {
    remoteMissing.push(reader.readUInt32LE());
  }

  return { success, localMissing, remoteMissing };
}

function deserializeInvTxPayload(reader: BufferReader): InvTxPayload {
  const count = reader.readVarInt();
  const wtxids: Buffer[] = [];

  for (let i = 0; i < count; i++) {
    wtxids.push(reader.readHash());
  }

  return { wtxids };
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
    case "addrv2":
      command = "addrv2";
      payload = serializeAddrV2Payload(msg.payload.addrs);
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
    case "mempool":
      // BIP-35: Request peer to send invs of all mempool transactions.
      command = "mempool";
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
    // Package relay messages
    case "sendpackages":
      command = "sendpackages";
      payload = serializeSendPackagesPayload(msg.payload);
      break;
    case "ancpkginfo":
      command = "ancpkginfo";
      payload = serializeAncPkgInfoPayload(msg.payload);
      break;
    case "getpkgtxns":
      command = "getpkgtxns";
      payload = serializeGetPkgTxnsPayload(msg.payload);
      break;
    case "pkgtxns":
      command = "pkgtxns";
      payload = serializePkgTxnsPayload(msg.payload);
      break;
    // BIP-330 Erlay messages
    case "sendtxrcncl":
      command = "sendtxrcncl";
      payload = serializeSendTxRcnclPayload(msg.payload);
      break;
    case "reqrecon":
      command = "reqrecon";
      payload = serializeReqReconPayload(msg.payload);
      break;
    case "sketch":
      command = "sketch";
      payload = serializeSketchPayload(msg.payload);
      break;
    case "reqsketchext":
      command = "reqsketchext";
      payload = serializeReqSketchExtPayload(msg.payload);
      break;
    case "reconcildiff":
      command = "reconcildiff";
      payload = serializeReconcilDiffPayload(msg.payload);
      break;
    case "invtx":
      command = "invtx";
      payload = serializeInvTxPayload(msg.payload);
      break;
    // BIP-157 compact block filter messages
    case "getcfilters":
      command = "getcfilters";
      payload = serializeGetCFiltersPayload(msg.payload);
      break;
    case "cfilter":
      command = "cfilter";
      payload = serializeCFilterPayload(msg.payload);
      break;
    case "getcfheaders":
      command = "getcfheaders";
      payload = serializeGetCFHeadersPayload(msg.payload);
      break;
    case "cfheaders":
      command = "cfheaders";
      payload = serializeCFHeadersPayload(msg.payload);
      break;
    case "getcfcheckpt":
      command = "getcfcheckpt";
      payload = serializeGetCFCheckPtPayload(msg.payload);
      break;
    case "cfcheckpt":
      command = "cfcheckpt";
      payload = serializeCFCheckPtPayload(msg.payload);
      break;
    default:
      throw new Error(`Unknown message type: ${(msg as NetworkMessage).type}`);
  }

  const header = serializeHeader(magic, command, payload);
  return Buffer.concat([header, payload]);
}

/**
 * Serialize a message into its (command, payload) parts only — no v1 header.
 *
 * Used by the BIP-324 v2 path, which carries the command name in the
 * encrypted contents (short ID or 12-byte long encoding) and authenticates
 * the payload via Poly1305 instead of a 4-byte hash256 checksum.
 *
 * Re-uses {@link serializeMessage} by parsing back out the command + payload
 * so we have a single source of truth for payload encoding.  Cheaper than
 * re-implementing the giant switch.
 */
export function extractCommandAndPayload(
  magic: number,
  msg: NetworkMessage
): { command: string; payload: Buffer } {
  const full = serializeMessage(magic, msg);
  const header = parseHeader(full);
  if (!header) {
    throw new Error("extractCommandAndPayload: parseHeader returned null");
  }
  return {
    command: header.command,
    payload: full.subarray(MESSAGE_HEADER_SIZE),
  };
}

/**
 * Deserialize a v2-decrypted message given its command name + payload.
 *
 * The BIP-324 transport authenticates each packet via Poly1305, so there
 * is no v1 header / checksum to verify here.  We synthesize a fake header
 * (with a correctly-recomputed checksum) and dispatch through the
 * existing {@link deserializeMessage} switch to keep a single source of
 * truth for payload parsing.
 */
export function deserializeV2Message(
  command: string,
  payload: Buffer
): NetworkMessage {
  const fakeHeader: MessageHeader = {
    magic: 0,
    command,
    length: payload.length,
    checksum: hash256(payload).subarray(0, 4),
  };
  return deserializeMessage(fakeHeader, payload);
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
    case "addrv2":
      return { type: "addrv2", payload: deserializeAddrV2Payload(reader) };
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
    case "mempool":
      // BIP-35: peer is requesting our mempool contents. Empty payload.
      return { type: "mempool", payload: null };
    case "cmpctblock":
      return { type: "cmpctblock", payload: deserializeCmpctBlockPayload(reader) };
    case "getblocktxn":
      return { type: "getblocktxn", payload: deserializeGetBlockTxnPayload(reader) };
    case "blocktxn":
      return { type: "blocktxn", payload: deserializeBlockTxnPayload(reader) };
    // Package relay messages
    case "sendpackages":
      return { type: "sendpackages", payload: deserializeSendPackagesPayload(reader) };
    case "ancpkginfo":
      return { type: "ancpkginfo", payload: deserializeAncPkgInfoPayload(reader) };
    case "getpkgtxns":
      return { type: "getpkgtxns", payload: deserializeGetPkgTxnsPayload(reader) };
    case "pkgtxns":
      return { type: "pkgtxns", payload: deserializePkgTxnsPayload(reader) };
    // BIP-330 Erlay messages
    case "sendtxrcncl":
      return { type: "sendtxrcncl", payload: deserializeSendTxRcnclPayload(reader) };
    case "reqrecon":
      return { type: "reqrecon", payload: deserializeReqReconPayload(reader) };
    case "sketch":
      return { type: "sketch", payload: deserializeSketchPayload(reader) };
    case "reqsketchext":
      return { type: "reqsketchext", payload: deserializeReqSketchExtPayload(reader) };
    case "reconcildiff":
      return { type: "reconcildiff", payload: deserializeReconcilDiffPayload(reader) };
    case "invtx":
      return { type: "invtx", payload: deserializeInvTxPayload(reader) };
    case "notfound":
      return { type: "notfound", payload: deserializeInvPayload(reader) };
    // BIP-157 compact block filter messages
    case "getcfilters":
      return { type: "getcfilters", payload: deserializeGetCFiltersPayload(reader) };
    case "cfilter":
      return { type: "cfilter", payload: deserializeCFilterPayload(reader) };
    case "getcfheaders":
      return { type: "getcfheaders", payload: deserializeGetCFHeadersPayload(reader) };
    case "cfheaders":
      return { type: "cfheaders", payload: deserializeCFHeadersPayload(reader) };
    case "getcfcheckpt":
      return { type: "getcfcheckpt", payload: deserializeGetCFCheckPtPayload(reader) };
    case "cfcheckpt":
      return { type: "cfcheckpt", payload: deserializeCFCheckPtPayload(reader) };
    default:
      // Unknown messages should be ignored, not crash the connection.
      // Bitcoin Core regularly adds new message types and peers may send
      // messages we don't understand yet.
      console.log(`P2P: ignoring unknown message type "${header.command}" (${payload.length} bytes)`);
      return { type: header.command as any, payload: null };
  }
}

import { sha256Hash } from "../crypto/primitives.js";
import { getTxId } from "../validation/tx.js";
