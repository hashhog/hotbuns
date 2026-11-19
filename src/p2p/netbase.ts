/**
 * Address classification shared by the address store and the dialer.
 *
 * A leaf module (no imports from manager.ts / addrman.ts) so both the
 * bucketed AddrMan and PeerManager can use one routability rule without an
 * import cycle.
 *
 * Core refs:
 *   netaddress.cpp CNetAddr::IsRoutable / IsValid / IsLocal / IsRFC*
 *   netbase.cpp    IsBadPort
 */

/**
 * Core CNetAddr::IsRoutable for an IP address in its 16-byte form
 * (IPv4 as ::ffff:a.b.c.d, the form `hostTo16` / BIP155 IPv6 use).
 *
 * IsRoutable = IsValid() && !(RFC1918 || RFC2544 || RFC3927 || RFC4862 ||
 *   RFC6598 || RFC5737 || RFC4193 || RFC4843 || RFC7343 || IsLocal() ||
 *   IsInternal()).
 */
export function isRoutableIP16(b: Uint8Array): boolean {
  if (b.length !== 16) return false;

  const isMappedV4 = b.subarray(0, 10).every((x) => x === 0) && b[10] === 0xff && b[11] === 0xff;
  if (isMappedV4) {
    const a = b[12]!;
    const c = b[13]!;
    const d = b[14]!;
    // IsValid: 0.0.0.0 (INADDR_ANY) and 255.255.255.255 (INADDR_NONE).
    if (b.subarray(12).every((x) => x === 0)) return false;
    if (b.subarray(12).every((x) => x === 0xff)) return false;
    if (a === 127 || a === 0) return false; // IsLocal
    if (a === 10) return false; // RFC1918
    if (a === 172 && c >= 16 && c <= 31) return false; // RFC1918
    if (a === 192 && c === 168) return false; // RFC1918
    if (a === 198 && (c === 18 || c === 19)) return false; // RFC2544
    if (a === 169 && c === 254) return false; // RFC3927
    if (a === 100 && c >= 64 && c <= 127) return false; // RFC6598
    if (a === 192 && c === 0 && d === 2) return false; // RFC5737
    if (a === 198 && c === 51 && d === 100) return false; // RFC5737
    if (a === 203 && c === 0 && d === 113) return false; // RFC5737
    return true;
  }

  // IPv6.
  if (b.every((x) => x === 0)) return false; // IsValid: unspecified ::
  if (b.subarray(0, 15).every((x) => x === 0) && b[15] === 1) return false; // IsLocal: ::1
  if (b[0] === 0x20 && b[1] === 0x01 && b[2] === 0x0d && b[3] === 0xb8) return false; // RFC3849 (IsValid)
  if (b[0] === 0xfe && b[1] === 0x80 && b.subarray(2, 8).every((x) => x === 0)) return false; // RFC4862 fe80::/64
  if ((b[0]! & 0xfe) === 0xfc) return false; // RFC4193 fc00::/7
  if (b[0] === 0x20 && b[1] === 0x01 && b[2] === 0x00 && (b[3]! & 0xf0) === 0x10) return false; // RFC4843
  if (b[0] === 0x20 && b[1] === 0x01 && b[2] === 0x00 && (b[3]! & 0xf0) === 0x20) return false; // RFC7343
  // IsInternal: fd6b:88c0:8724::/48 (Core's internal-name prefix) is inside
  // fc00::/7 and already rejected above.
  return true;
}

/**
 * Core netbase.cpp IsBadPort: ports of well-known services an automatic
 * outbound connection must not target, so gossip cannot turn the node into
 * a scanner/spammer of other people's SMTP, SSH, databases, etc.
 */
const BAD_PORTS: ReadonlySet<number> = new Set([
  1, 7, 9, 11, 13, 15, 17, 19, 20, 21, 22, 23, 25, 37, 42, 43, 53, 69, 77, 79,
  87, 95, 101, 102, 103, 104, 109, 110, 111, 113, 115, 117, 119, 123, 135, 137,
  139, 143, 161, 179, 389, 427, 465, 512, 513, 514, 515, 526, 530, 531, 532,
  540, 548, 554, 556, 563, 587, 601, 636, 989, 990, 993, 995, 1719, 1720, 1723,
  2049, 3306, 3389, 3659, 4045, 5060, 5061, 5432, 5900, 6000, 6566, 6665, 6666,
  6667, 6668, 6669, 6697, 10080, 27017,
]);

/** Core netbase.cpp IsBadPort. */
export function isBadPort(port: number): boolean {
  return BAD_PORTS.has(port);
}
