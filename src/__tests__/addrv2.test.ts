/**
 * BIP155 ADDRv2 Protocol Tests
 *
 * Tests for addrv2 message serialization, deserialization, and validation.
 */

import { describe, expect, it } from "bun:test";
import { BufferReader, BufferWriter } from "../wire/serialization.js";
import {
  BIP155Network,
  type NetworkAddressV2,
  type AddrV2Entry,
  serializeAddrV2Payload,
  deserializeAddrV2Payload,
  isValidNetworkAddressV2,
  isValidTorV3Address,
  isValidCJDNSAddress,
  isValidI2PAddress,
  ipv4ToNetworkAddressV2,
  networkAddressV2ToIPv4String,
  legacyAddressToNetworkAddressV2,
  networkAddressV2ToLegacy,
  isAddrV1Compatible,
  formatNetworkAddressV2,
  getNetworkName,
} from "../p2p/addrv2.js";

describe("BIP155 Network Types", () => {
  it("defines correct network IDs", () => {
    expect(BIP155Network.IPV4).toBe(1);
    expect(BIP155Network.IPV6).toBe(2);
    expect(BIP155Network.TORV2).toBe(3);
    expect(BIP155Network.TORV3).toBe(4);
    expect(BIP155Network.I2P).toBe(5);
    expect(BIP155Network.CJDNS).toBe(6);
  });

  it("returns correct network names", () => {
    expect(getNetworkName(BIP155Network.IPV4)).toBe("IPv4");
    expect(getNetworkName(BIP155Network.IPV6)).toBe("IPv6");
    expect(getNetworkName(BIP155Network.TORV3)).toBe("TorV3");
    expect(getNetworkName(BIP155Network.I2P)).toBe("I2P");
    expect(getNetworkName(BIP155Network.CJDNS)).toBe("CJDNS");
    expect(getNetworkName(99)).toBe("Unknown(99)");
  });
});

describe("IPv4 Address Handling", () => {
  it("converts IPv4 string to NetworkAddressV2", () => {
    const addr = ipv4ToNetworkAddressV2("192.168.1.1", 8333, 1n);

    expect(addr.networkId).toBe(BIP155Network.IPV4);
    expect(addr.addr.length).toBe(4);
    expect(addr.addr[0]).toBe(192);
    expect(addr.addr[1]).toBe(168);
    expect(addr.addr[2]).toBe(1);
    expect(addr.addr[3]).toBe(1);
    expect(addr.port).toBe(8333);
    expect(addr.services).toBe(1n);
  });

  it("converts NetworkAddressV2 back to IPv4 string", () => {
    const addr = ipv4ToNetworkAddressV2("10.0.0.1", 8333);
    const str = networkAddressV2ToIPv4String(addr);
    expect(str).toBe("10.0.0.1");
  });

  it("returns null for non-IPv4 addresses", () => {
    const addr: NetworkAddressV2 = {
      networkId: BIP155Network.IPV6,
      addr: Buffer.alloc(16),
      port: 8333,
      services: 0n,
    };
    expect(networkAddressV2ToIPv4String(addr)).toBeNull();
  });

  it("throws on invalid IPv4 string", () => {
    expect(() => ipv4ToNetworkAddressV2("invalid", 8333)).toThrow();
    expect(() => ipv4ToNetworkAddressV2("192.168.1", 8333)).toThrow();
    expect(() => ipv4ToNetworkAddressV2("192.168.1.256", 8333)).toThrow();
  });
});

describe("Legacy Address Conversion", () => {
  it("converts IPv4-mapped IPv6 to NetworkAddressV2 IPv4", () => {
    // IPv4-mapped IPv6: ::ffff:192.168.1.1
    const legacy = Buffer.from([
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 168, 1, 1,
    ]);

    const addr = legacyAddressToNetworkAddressV2(legacy, 8333, 1n);

    expect(addr.networkId).toBe(BIP155Network.IPV4);
    expect(addr.addr.length).toBe(4);
    expect(networkAddressV2ToIPv4String(addr)).toBe("192.168.1.1");
  });

  it("keeps true IPv6 addresses as IPv6", () => {
    // A real IPv6 address (2001:db8::1)
    const legacy = Buffer.from([
      0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
    ]);

    const addr = legacyAddressToNetworkAddressV2(legacy, 8333, 1n);

    expect(addr.networkId).toBe(BIP155Network.IPV6);
    expect(addr.addr.length).toBe(16);
  });

  it("converts NetworkAddressV2 IPv4 back to legacy format", () => {
    const addr = ipv4ToNetworkAddressV2("192.168.1.1", 8333);
    const legacy = networkAddressV2ToLegacy(addr);

    expect(legacy).not.toBeNull();
    expect(legacy!.length).toBe(16);
    // Check IPv4-mapped IPv6 prefix
    expect(legacy![10]).toBe(0xff);
    expect(legacy![11]).toBe(0xff);
    expect(legacy![12]).toBe(192);
    expect(legacy![13]).toBe(168);
    expect(legacy![14]).toBe(1);
    expect(legacy![15]).toBe(1);
  });

  it("returns null for non-IP addresses", () => {
    const torAddr: NetworkAddressV2 = {
      networkId: BIP155Network.TORV3,
      addr: Buffer.alloc(32),
      port: 8333,
      services: 0n,
    };
    expect(networkAddressV2ToLegacy(torAddr)).toBeNull();
  });
});

describe("TorV3 Address Validation", () => {
  it("accepts valid 32-byte TorV3 address", () => {
    const pubkey = Buffer.alloc(32, 0x01); // Non-zero 32 bytes
    expect(isValidTorV3Address(pubkey)).toBe(true);
  });

  it("rejects all-zero TorV3 address (invalid point)", () => {
    const pubkey = Buffer.alloc(32, 0);
    expect(isValidTorV3Address(pubkey)).toBe(false);
  });

  it("rejects wrong-sized TorV3 address", () => {
    expect(isValidTorV3Address(Buffer.alloc(31))).toBe(false);
    expect(isValidTorV3Address(Buffer.alloc(33))).toBe(false);
  });

  it("validates TorV3 address in NetworkAddressV2", () => {
    const validTor: NetworkAddressV2 = {
      networkId: BIP155Network.TORV3,
      addr: Buffer.alloc(32, 0xab),
      port: 8333,
      services: 1n,
    };
    expect(isValidNetworkAddressV2(validTor)).toBe(true);

    const invalidTor: NetworkAddressV2 = {
      networkId: BIP155Network.TORV3,
      addr: Buffer.alloc(32, 0), // All zeros
      port: 8333,
      services: 1n,
    };
    expect(isValidNetworkAddressV2(invalidTor)).toBe(false);
  });
});

describe("CJDNS Address Validation", () => {
  it("accepts valid CJDNS address with fc prefix", () => {
    const addr = Buffer.alloc(16);
    addr[0] = 0xfc;
    expect(isValidCJDNSAddress(addr)).toBe(true);
  });

  it("rejects CJDNS address without fc prefix", () => {
    const addr = Buffer.alloc(16);
    addr[0] = 0xfe; // Wrong prefix
    expect(isValidCJDNSAddress(addr)).toBe(false);
  });

  it("rejects wrong-sized CJDNS address", () => {
    const addr = Buffer.alloc(15);
    addr[0] = 0xfc;
    expect(isValidCJDNSAddress(addr)).toBe(false);
  });
});

describe("I2P Address Validation", () => {
  it("accepts valid 32-byte I2P address", () => {
    const hash = Buffer.alloc(32, 0xcd);
    expect(isValidI2PAddress(hash)).toBe(true);
  });

  it("rejects wrong-sized I2P address", () => {
    expect(isValidI2PAddress(Buffer.alloc(31))).toBe(false);
    expect(isValidI2PAddress(Buffer.alloc(33))).toBe(false);
  });
});

describe("TorV2 (Deprecated) Rejection", () => {
  it("rejects TorV2 addresses as invalid", () => {
    const torv2: NetworkAddressV2 = {
      networkId: BIP155Network.TORV2,
      addr: Buffer.alloc(10),
      port: 8333,
      services: 1n,
    };
    expect(isValidNetworkAddressV2(torv2)).toBe(false);
  });
});

describe("Address V1 Compatibility", () => {
  it("marks IPv4 addresses as V1 compatible", () => {
    const addr = ipv4ToNetworkAddressV2("1.2.3.4", 8333);
    expect(isAddrV1Compatible(addr)).toBe(true);
  });

  it("marks IPv6 addresses as V1 compatible", () => {
    const addr: NetworkAddressV2 = {
      networkId: BIP155Network.IPV6,
      addr: Buffer.alloc(16, 0x20),
      port: 8333,
      services: 0n,
    };
    expect(isAddrV1Compatible(addr)).toBe(true);
  });

  it("marks TorV3 addresses as NOT V1 compatible", () => {
    const addr: NetworkAddressV2 = {
      networkId: BIP155Network.TORV3,
      addr: Buffer.alloc(32, 0xab),
      port: 8333,
      services: 0n,
    };
    expect(isAddrV1Compatible(addr)).toBe(false);
  });

  it("marks I2P addresses as NOT V1 compatible", () => {
    const addr: NetworkAddressV2 = {
      networkId: BIP155Network.I2P,
      addr: Buffer.alloc(32, 0xcd),
      port: 8333,
      services: 0n,
    };
    expect(isAddrV1Compatible(addr)).toBe(false);
  });
});

describe("ADDRv2 Message Serialization", () => {
  it("serializes and deserializes empty addrv2 message", () => {
    const original: AddrV2Entry[] = [];
    const serialized = serializeAddrV2Payload(original);
    const reader = new BufferReader(serialized);
    const deserialized = deserializeAddrV2Payload(reader);

    expect(deserialized.addrs.length).toBe(0);
  });

  it("serializes and deserializes IPv4 address", () => {
    const timestamp = Math.floor(Date.now() / 1000);
    const original: AddrV2Entry[] = [
      {
        timestamp,
        addr: ipv4ToNetworkAddressV2("192.168.1.1", 8333, 9n), // NODE_NETWORK | NODE_WITNESS
      },
    ];

    const serialized = serializeAddrV2Payload(original);
    const reader = new BufferReader(serialized);
    const deserialized = deserializeAddrV2Payload(reader);

    expect(deserialized.addrs.length).toBe(1);
    expect(deserialized.addrs[0].timestamp).toBe(timestamp);
    expect(deserialized.addrs[0].addr.networkId).toBe(BIP155Network.IPV4);
    expect(deserialized.addrs[0].addr.port).toBe(8333);
    expect(deserialized.addrs[0].addr.services).toBe(9n);
    expect(networkAddressV2ToIPv4String(deserialized.addrs[0].addr)).toBe(
      "192.168.1.1"
    );
  });

  it("serializes and deserializes TorV3 address", () => {
    const timestamp = 1700000000;
    const torPubkey = Buffer.alloc(32);
    for (let i = 0; i < 32; i++) {
      torPubkey[i] = i + 1;
    }

    const original: AddrV2Entry[] = [
      {
        timestamp,
        addr: {
          networkId: BIP155Network.TORV3,
          addr: torPubkey,
          port: 8333,
          services: 8n, // NODE_WITNESS
        },
      },
    ];

    const serialized = serializeAddrV2Payload(original);
    const reader = new BufferReader(serialized);
    const deserialized = deserializeAddrV2Payload(reader);

    expect(deserialized.addrs.length).toBe(1);
    expect(deserialized.addrs[0].addr.networkId).toBe(BIP155Network.TORV3);
    expect(deserialized.addrs[0].addr.addr.length).toBe(32);
    expect(deserialized.addrs[0].addr.addr.equals(torPubkey)).toBe(true);
    expect(deserialized.addrs[0].addr.port).toBe(8333);
    expect(deserialized.addrs[0].addr.services).toBe(8n);
  });

  it("serializes and deserializes I2P address", () => {
    const timestamp = 1700000000;
    const i2pHash = Buffer.alloc(32, 0xde);

    const original: AddrV2Entry[] = [
      {
        timestamp,
        addr: {
          networkId: BIP155Network.I2P,
          addr: i2pHash,
          port: 0, // I2P port is typically 0
          services: 1n,
        },
      },
    ];

    const serialized = serializeAddrV2Payload(original);
    const reader = new BufferReader(serialized);
    const deserialized = deserializeAddrV2Payload(reader);

    expect(deserialized.addrs.length).toBe(1);
    expect(deserialized.addrs[0].addr.networkId).toBe(BIP155Network.I2P);
    expect(deserialized.addrs[0].addr.addr.length).toBe(32);
    expect(deserialized.addrs[0].addr.port).toBe(0);
  });

  it("serializes and deserializes CJDNS address", () => {
    const timestamp = 1700000000;
    const cjdnsAddr = Buffer.alloc(16);
    cjdnsAddr[0] = 0xfc;
    for (let i = 1; i < 16; i++) {
      cjdnsAddr[i] = i;
    }

    const original: AddrV2Entry[] = [
      {
        timestamp,
        addr: {
          networkId: BIP155Network.CJDNS,
          addr: cjdnsAddr,
          port: 8333,
          services: 9n,
        },
      },
    ];

    const serialized = serializeAddrV2Payload(original);
    const reader = new BufferReader(serialized);
    const deserialized = deserializeAddrV2Payload(reader);

    expect(deserialized.addrs.length).toBe(1);
    expect(deserialized.addrs[0].addr.networkId).toBe(BIP155Network.CJDNS);
    expect(deserialized.addrs[0].addr.addr[0]).toBe(0xfc);
    expect(deserialized.addrs[0].addr.port).toBe(8333);
  });

  it("serializes and deserializes multiple mixed addresses", () => {
    const timestamp = 1700000000;

    const original: AddrV2Entry[] = [
      {
        timestamp,
        addr: ipv4ToNetworkAddressV2("10.0.0.1", 8333, 1n),
      },
      {
        timestamp: timestamp + 100,
        addr: {
          networkId: BIP155Network.TORV3,
          addr: Buffer.alloc(32, 0xab),
          port: 8333,
          services: 8n,
        },
      },
      {
        timestamp: timestamp + 200,
        addr: {
          networkId: BIP155Network.I2P,
          addr: Buffer.alloc(32, 0xcd),
          port: 0,
          services: 1n,
        },
      },
    ];

    const serialized = serializeAddrV2Payload(original);
    const reader = new BufferReader(serialized);
    const deserialized = deserializeAddrV2Payload(reader);

    expect(deserialized.addrs.length).toBe(3);

    // IPv4
    expect(deserialized.addrs[0].addr.networkId).toBe(BIP155Network.IPV4);
    expect(networkAddressV2ToIPv4String(deserialized.addrs[0].addr)).toBe("10.0.0.1");

    // TorV3
    expect(deserialized.addrs[1].addr.networkId).toBe(BIP155Network.TORV3);
    expect(deserialized.addrs[1].addr.addr.length).toBe(32);

    // I2P
    expect(deserialized.addrs[2].addr.networkId).toBe(BIP155Network.I2P);
    expect(deserialized.addrs[2].addr.addr.length).toBe(32);
  });

  it("uses compactSize encoding for services", () => {
    const timestamp = 1700000000;

    // Test large services value that requires 3-byte encoding
    const largeServices = 0x0400n; // NODE_NETWORK_LIMITED = 1024

    const original: AddrV2Entry[] = [
      {
        timestamp,
        addr: ipv4ToNetworkAddressV2("1.2.3.4", 8333, largeServices),
      },
    ];

    const serialized = serializeAddrV2Payload(original);
    const reader = new BufferReader(serialized);
    const deserialized = deserializeAddrV2Payload(reader);

    expect(deserialized.addrs[0].addr.services).toBe(largeServices);
  });
});

describe("ADDRv2 Deserialization Error Handling", () => {
  it("throws on too many addresses", () => {
    // Create a buffer that claims to have more than 1000 addresses
    const writer = new BufferWriter();
    writer.writeVarInt(1001); // More than max

    const reader = new BufferReader(writer.toBuffer());
    expect(() => deserializeAddrV2Payload(reader)).toThrow("Too many addresses");
  });

  it("throws on address size exceeding max", () => {
    const writer = new BufferWriter();
    writer.writeVarInt(1); // 1 address
    writer.writeUInt32LE(1700000000); // timestamp
    writer.writeVarInt(1); // services
    writer.writeUInt8(99); // unknown network ID
    writer.writeVarInt(513); // address length > 512

    const reader = new BufferReader(writer.toBuffer());
    expect(() => deserializeAddrV2Payload(reader)).toThrow("Address too large");
  });

  it("throws on invalid address size for known network", () => {
    const writer = new BufferWriter();
    writer.writeVarInt(1); // 1 address
    writer.writeUInt32LE(1700000000); // timestamp
    writer.writeVarInt(1); // services
    writer.writeUInt8(BIP155Network.IPV4); // IPv4
    writer.writeVarInt(5); // Wrong size (should be 4)
    writer.writeBytes(Buffer.alloc(5));
    // port would follow but we'll hit the error first

    const reader = new BufferReader(writer.toBuffer());
    expect(() => deserializeAddrV2Payload(reader)).toThrow(
      "Invalid address size"
    );
  });
});

describe("Address Formatting", () => {
  it("formats IPv4 address", () => {
    const addr = ipv4ToNetworkAddressV2("192.168.1.1", 8333);
    expect(formatNetworkAddressV2(addr)).toBe("192.168.1.1:8333");
  });

  it("formats TorV3 address (truncated)", () => {
    const addr: NetworkAddressV2 = {
      networkId: BIP155Network.TORV3,
      addr: Buffer.alloc(32, 0xab),
      port: 8333,
      services: 0n,
    };
    const formatted = formatNetworkAddressV2(addr);
    expect(formatted).toContain("onion");
    expect(formatted).toContain(":8333");
  });

  it("formats I2P address (truncated)", () => {
    const addr: NetworkAddressV2 = {
      networkId: BIP155Network.I2P,
      addr: Buffer.alloc(32, 0xcd),
      port: 0,
      services: 0n,
    };
    const formatted = formatNetworkAddressV2(addr);
    expect(formatted).toContain("b32.i2p");
    expect(formatted).toContain(":0");
  });
});

describe("Wire Format Compatibility", () => {
  it("encodes port in big-endian", () => {
    const original: AddrV2Entry[] = [
      {
        timestamp: 1700000000,
        addr: ipv4ToNetworkAddressV2("1.2.3.4", 0x1234, 1n),
      },
    ];

    const serialized = serializeAddrV2Payload(original);

    // Find the port bytes at the end of the address entry
    // Format: count(1) + timestamp(4) + services(1) + netId(1) + addrLen(1) + addr(4) + port(2)
    const portOffset = 1 + 4 + 1 + 1 + 1 + 4;
    expect(serialized[portOffset]).toBe(0x12); // High byte first (big-endian)
    expect(serialized[portOffset + 1]).toBe(0x34); // Low byte second
  });
});
