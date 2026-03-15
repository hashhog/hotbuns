/**
 * BIP155 ADDRv2 Protocol Implementation
 *
 * Implements the addrv2 message format to support Tor v3 (.onion), I2P,
 * and CJDNS addresses which don't fit in the legacy 16-byte addr format.
 *
 * Reference: https://github.com/bitcoin/bips/blob/master/bip-0155.mediawiki
 * Bitcoin Core: src/netaddress.cpp, src/net_processing.cpp
 */

import { BufferReader, BufferWriter } from "../wire/serialization.js";

/**
 * BIP155 network IDs.
 *
 * These identify the address type in addrv2 messages.
 */
export const enum BIP155Network {
  IPV4 = 1,   // 4 bytes
  IPV6 = 2,   // 16 bytes
  TORV2 = 3,  // 10 bytes (deprecated, not supported)
  TORV3 = 4,  // 32 bytes (ed25519 public key)
  I2P = 5,    // 32 bytes (SHA256 of destination)
  CJDNS = 6,  // 16 bytes
}

/**
 * Expected address sizes for each network type.
 */
export const BIP155AddressSizes: Record<BIP155Network, number> = {
  [BIP155Network.IPV4]: 4,
  [BIP155Network.IPV6]: 16,
  [BIP155Network.TORV2]: 10,
  [BIP155Network.TORV3]: 32,
  [BIP155Network.I2P]: 32,
  [BIP155Network.CJDNS]: 16,
};

/**
 * Maximum address size in BIP155 (512 bytes).
 * Unknown network types up to this size are tolerated but ignored.
 */
export const MAX_ADDRV2_SIZE = 512;

/**
 * Network address in BIP155 format (addrv2).
 *
 * Unlike the legacy NetworkAddress which stores all addresses as IPv4-mapped IPv6,
 * this stores the raw address bytes with an explicit network type.
 */
export interface NetworkAddressV2 {
  /** BIP155 network type (1=IPv4, 2=IPv6, 4=TorV3, 5=I2P, 6=CJDNS) */
  networkId: BIP155Network | number;
  /** Raw address bytes (variable length depending on network type) */
  addr: Buffer;
  /** Port number (big-endian on wire) */
  port: number;
  /** Service flags (compactSize encoded in addrv2) */
  services: bigint;
}

/**
 * Address entry in addrv2 message with timestamp.
 */
export interface AddrV2Entry {
  /** Unix timestamp (seconds) */
  timestamp: number;
  /** Network address */
  addr: NetworkAddressV2;
}

/**
 * Payload for addrv2 message.
 */
export interface AddrV2Payload {
  addrs: AddrV2Entry[];
}

/**
 * Check if a network ID is known (has a defined address size).
 */
export function isKnownNetwork(networkId: number): networkId is BIP155Network {
  return networkId >= BIP155Network.IPV4 && networkId <= BIP155Network.CJDNS;
}

/**
 * Get the expected address size for a known network ID.
 * Returns undefined for unknown network IDs.
 */
export function getNetworkAddressSize(networkId: number): number | undefined {
  if (isKnownNetwork(networkId)) {
    return BIP155AddressSizes[networkId];
  }
  return undefined;
}

/**
 * Validate that a TorV3 address is a valid ed25519 public key.
 *
 * TorV3 addresses are 32-byte ed25519 public keys. Basic validation
 * ensures the bytes could represent a valid point on the curve.
 *
 * Note: Full validation would require checking if the point is on the curve,
 * but we do basic validation here to reject obviously invalid addresses.
 *
 * @param addr - 32-byte TorV3 address
 * @returns true if the address passes basic validation
 */
export function isValidTorV3Address(addr: Buffer): boolean {
  if (addr.length !== 32) {
    return false;
  }

  // ed25519 public keys are 32 bytes representing a compressed point.
  // The high bit of the last byte is used for the sign.
  // Basic check: ensure it's not all zeros (invalid point)
  let allZero = true;
  for (let i = 0; i < addr.length; i++) {
    if (addr[i] !== 0) {
      allZero = false;
      break;
    }
  }
  if (allZero) {
    return false;
  }

  // Additional check: the last byte's high 7 bits encode the y-coordinate's
  // most significant bits. There's no simple invalid pattern we can check
  // without full curve arithmetic, so we accept any non-zero value.
  return true;
}

/**
 * Validate that a CJDNS address has the correct prefix.
 *
 * All CJDNS addresses start with 0xFC.
 * Reference: https://github.com/cjdelisle/cjdns/blob/master/doc/Whitepaper.md
 *
 * @param addr - 16-byte CJDNS address
 * @returns true if the address has a valid CJDNS prefix
 */
export function isValidCJDNSAddress(addr: Buffer): boolean {
  if (addr.length !== 16) {
    return false;
  }
  return addr[0] === 0xfc;
}

/**
 * Validate an I2P address.
 *
 * I2P addresses are 32-byte SHA256 hashes of the destination.
 * Any 32-byte value is technically valid.
 *
 * @param addr - 32-byte I2P address
 * @returns true if the address length is correct
 */
export function isValidI2PAddress(addr: Buffer): boolean {
  return addr.length === 32;
}

/**
 * Validate a NetworkAddressV2 for a known network type.
 *
 * @param addr - Network address to validate
 * @returns true if the address is valid for its network type
 */
export function isValidNetworkAddressV2(addr: NetworkAddressV2): boolean {
  const expectedSize = getNetworkAddressSize(addr.networkId);

  // For known networks, validate size
  if (expectedSize !== undefined) {
    if (addr.addr.length !== expectedSize) {
      return false;
    }
  } else {
    // Unknown network: validate size is within bounds
    if (addr.addr.length > MAX_ADDRV2_SIZE) {
      return false;
    }
  }

  // Network-specific validation
  switch (addr.networkId) {
    case BIP155Network.TORV3:
      return isValidTorV3Address(addr.addr);
    case BIP155Network.CJDNS:
      return isValidCJDNSAddress(addr.addr);
    case BIP155Network.I2P:
      return isValidI2PAddress(addr.addr);
    case BIP155Network.TORV2:
      // TorV2 is deprecated and should be rejected
      return false;
    default:
      return true;
  }
}

/**
 * Serialize an addrv2 message payload.
 *
 * Format per address:
 * - time: uint32 LE (seconds since epoch)
 * - services: compactSize
 * - networkID: uint8
 * - addr: compactSize length + bytes
 * - port: uint16 BE (!)
 *
 * @param addrs - Array of address entries
 * @returns Serialized payload
 */
export function serializeAddrV2Payload(addrs: AddrV2Entry[]): Buffer {
  const writer = new BufferWriter();

  // Count
  writer.writeVarInt(addrs.length);

  for (const entry of addrs) {
    // Timestamp (uint32 LE)
    writer.writeUInt32LE(entry.timestamp);

    // Services (compactSize - different from addr v1 which uses uint64!)
    writer.writeVarInt(entry.addr.services);

    // Network ID (uint8)
    writer.writeUInt8(entry.addr.networkId);

    // Address length (compactSize) + address bytes
    writer.writeVarInt(entry.addr.addr.length);
    writer.writeBytes(entry.addr.addr);

    // Port (uint16 BE - same as addr v1)
    const portBuf = Buffer.alloc(2);
    portBuf.writeUInt16BE(entry.addr.port, 0);
    writer.writeBytes(portBuf);
  }

  return writer.toBuffer();
}

/**
 * Deserialize an addrv2 message payload.
 *
 * @param reader - Buffer reader positioned at payload start
 * @returns Parsed addrv2 payload
 * @throws Error if payload is malformed
 */
export function deserializeAddrV2Payload(reader: BufferReader): AddrV2Payload {
  const count = reader.readVarInt();

  // Sanity check: max 1000 addresses per message (same as addr v1)
  if (count > 1000) {
    throw new Error(`Too many addresses in addrv2 message: ${count}`);
  }

  const addrs: AddrV2Entry[] = [];

  for (let i = 0; i < count; i++) {
    // Timestamp (uint32 LE)
    const timestamp = reader.readUInt32LE();

    // Services (compactSize)
    const services = reader.readVarIntBig();

    // Network ID (uint8)
    const networkId = reader.readUInt8();

    // Address length (compactSize) + address bytes
    const addrLen = reader.readVarInt();

    // Validate address length
    if (addrLen > MAX_ADDRV2_SIZE) {
      throw new Error(`Address too large: ${addrLen} > ${MAX_ADDRV2_SIZE}`);
    }

    // For known networks, validate expected size
    const expectedSize = getNetworkAddressSize(networkId);
    if (expectedSize !== undefined && addrLen !== expectedSize) {
      throw new Error(
        `Invalid address size for network ${networkId}: got ${addrLen}, expected ${expectedSize}`
      );
    }

    const addr = reader.readBytes(addrLen);

    // Port (uint16 BE)
    const portBuf = reader.readBytes(2);
    const port = portBuf.readUInt16BE(0);

    addrs.push({
      timestamp,
      addr: {
        networkId,
        addr,
        port,
        services,
      },
    });
  }

  return { addrs };
}

/**
 * Convert an IPv4 address string to a NetworkAddressV2.
 *
 * @param ip - IPv4 address string (e.g., "192.168.1.1")
 * @param port - Port number
 * @param services - Service flags
 * @returns NetworkAddressV2 for IPv4
 */
export function ipv4ToNetworkAddressV2(
  ip: string,
  port: number,
  services: bigint = 0n
): NetworkAddressV2 {
  const parts = ip.split(".");
  if (parts.length !== 4) {
    throw new Error(`Invalid IPv4 address: ${ip}`);
  }

  const addr = Buffer.alloc(4);
  for (let i = 0; i < 4; i++) {
    const octet = parseInt(parts[i], 10);
    if (isNaN(octet) || octet < 0 || octet > 255) {
      throw new Error(`Invalid IPv4 octet: ${parts[i]}`);
    }
    addr[i] = octet;
  }

  return {
    networkId: BIP155Network.IPV4,
    addr,
    port,
    services,
  };
}

/**
 * Convert a NetworkAddressV2 IPv4 address to string.
 *
 * @param addr - NetworkAddressV2 with IPv4 network type
 * @returns IPv4 address string or null if not IPv4
 */
export function networkAddressV2ToIPv4String(addr: NetworkAddressV2): string | null {
  if (addr.networkId !== BIP155Network.IPV4 || addr.addr.length !== 4) {
    return null;
  }
  return `${addr.addr[0]}.${addr.addr[1]}.${addr.addr[2]}.${addr.addr[3]}`;
}

/**
 * Convert an IPv6 address buffer to a NetworkAddressV2.
 *
 * @param ip - 16-byte IPv6 address buffer
 * @param port - Port number
 * @param services - Service flags
 * @returns NetworkAddressV2 for IPv6
 */
export function ipv6ToNetworkAddressV2(
  ip: Buffer,
  port: number,
  services: bigint = 0n
): NetworkAddressV2 {
  if (ip.length !== 16) {
    throw new Error(`Invalid IPv6 address length: ${ip.length}`);
  }

  return {
    networkId: BIP155Network.IPV6,
    addr: Buffer.from(ip),
    port,
    services,
  };
}

/**
 * Convert legacy NetworkAddress (IPv4-mapped IPv6) to NetworkAddressV2.
 *
 * Detects if the address is IPv4-mapped and converts appropriately.
 *
 * @param ip - 16-byte IPv4-mapped IPv6 buffer
 * @param port - Port number
 * @param services - Service flags
 * @returns NetworkAddressV2 for IPv4 or IPv6
 */
export function legacyAddressToNetworkAddressV2(
  ip: Buffer,
  port: number,
  services: bigint
): NetworkAddressV2 {
  if (ip.length !== 16) {
    throw new Error(`Invalid IP buffer length: ${ip.length}`);
  }

  // Check for IPv4-mapped IPv6 prefix: ::ffff:
  const isIPv4Mapped =
    ip[0] === 0 && ip[1] === 0 &&
    ip[2] === 0 && ip[3] === 0 &&
    ip[4] === 0 && ip[5] === 0 &&
    ip[6] === 0 && ip[7] === 0 &&
    ip[8] === 0 && ip[9] === 0 &&
    ip[10] === 0xff && ip[11] === 0xff;

  if (isIPv4Mapped) {
    // Extract IPv4 bytes
    return {
      networkId: BIP155Network.IPV4,
      addr: Buffer.from(ip.subarray(12, 16)),
      port,
      services,
    };
  }

  // It's a true IPv6 address
  return {
    networkId: BIP155Network.IPV6,
    addr: Buffer.from(ip),
    port,
    services,
  };
}

/**
 * Convert NetworkAddressV2 to legacy 16-byte IPv4-mapped IPv6 format.
 *
 * Only works for IPv4 and IPv6 addresses.
 *
 * @param addr - NetworkAddressV2 to convert
 * @returns 16-byte IPv4-mapped IPv6 buffer or null for non-IP addresses
 */
export function networkAddressV2ToLegacy(addr: NetworkAddressV2): Buffer | null {
  switch (addr.networkId) {
    case BIP155Network.IPV4: {
      // IPv4 -> IPv4-mapped IPv6
      const buf = Buffer.alloc(16, 0);
      buf[10] = 0xff;
      buf[11] = 0xff;
      addr.addr.copy(buf, 12);
      return buf;
    }
    case BIP155Network.IPV6:
      // IPv6 stays as-is
      return Buffer.from(addr.addr);
    default:
      // Tor, I2P, CJDNS cannot be converted to legacy format
      return null;
  }
}

/**
 * Check if a NetworkAddressV2 is compatible with legacy addr format.
 *
 * Only IPv4 and IPv6 addresses can be sent in legacy addr messages.
 *
 * @param addr - Address to check
 * @returns true if can be serialized as addr v1
 */
export function isAddrV1Compatible(addr: NetworkAddressV2): boolean {
  return addr.networkId === BIP155Network.IPV4 || addr.networkId === BIP155Network.IPV6;
}

/**
 * Get human-readable network name.
 */
export function getNetworkName(networkId: number): string {
  switch (networkId) {
    case BIP155Network.IPV4:
      return "IPv4";
    case BIP155Network.IPV6:
      return "IPv6";
    case BIP155Network.TORV2:
      return "TorV2";
    case BIP155Network.TORV3:
      return "TorV3";
    case BIP155Network.I2P:
      return "I2P";
    case BIP155Network.CJDNS:
      return "CJDNS";
    default:
      return `Unknown(${networkId})`;
  }
}

/**
 * Format a NetworkAddressV2 as a human-readable string.
 */
export function formatNetworkAddressV2(addr: NetworkAddressV2): string {
  let addrStr: string;

  switch (addr.networkId) {
    case BIP155Network.IPV4:
      addrStr = networkAddressV2ToIPv4String(addr) ?? addr.addr.toString("hex");
      break;
    case BIP155Network.IPV6:
      // Format as IPv6 with brackets
      addrStr = formatIPv6(addr.addr);
      break;
    case BIP155Network.TORV3:
      // Tor v3 addresses are base32 encoded with .onion suffix
      addrStr = formatTorV3(addr.addr);
      break;
    case BIP155Network.I2P:
      // I2P addresses are base32 encoded with .b32.i2p suffix
      addrStr = formatI2P(addr.addr);
      break;
    case BIP155Network.CJDNS:
      // CJDNS uses IPv6 format (starts with fc)
      addrStr = formatIPv6(addr.addr);
      break;
    default:
      addrStr = addr.addr.toString("hex");
  }

  return `${addrStr}:${addr.port}`;
}

/**
 * Format IPv6 address bytes as string.
 */
function formatIPv6(addr: Buffer): string {
  if (addr.length !== 16) {
    return addr.toString("hex");
  }

  // Convert to colon-separated hex groups
  const groups: string[] = [];
  for (let i = 0; i < 16; i += 2) {
    const value = (addr[i] << 8) | addr[i + 1];
    groups.push(value.toString(16));
  }

  return `[${groups.join(":")}]`;
}

/**
 * Format TorV3 address bytes as .onion address.
 *
 * TorV3 onion addresses are base32-encoded: pubkey + checksum + version
 */
function formatTorV3(pubkey: Buffer): string {
  if (pubkey.length !== 32) {
    return pubkey.toString("hex") + ".onion";
  }

  // The onion address is base32(pubkey || checksum || version)
  // checksum = first 2 bytes of SHA3-256(".onion checksum" || pubkey || version)
  // version = 0x03
  // For display, we just show the hex for now (full encoding requires sha3)
  return pubkey.toString("hex").substring(0, 16) + "...onion";
}

/**
 * Format I2P address bytes as .b32.i2p address.
 *
 * I2P addresses are base32-encoded 32-byte hashes.
 */
function formatI2P(hash: Buffer): string {
  if (hash.length !== 32) {
    return hash.toString("hex") + ".b32.i2p";
  }

  // Full encoding requires base32, show truncated hex for now
  return hash.toString("hex").substring(0, 16) + "...b32.i2p";
}
