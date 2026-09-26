/**
 * Self-address advertisement (Bitcoin Core parity).
 *
 * A listening node must tell the network where it can be reached, or nobody
 * ever dials it: peers only learn addresses from addr/addrv2 gossip, and the
 * only gossip source for OUR address is us. Core does this in three parts;
 * this module holds the first and the pure helpers for the other two (the
 * wiring lives in PeerManager):
 *
 *  1. A table of local addresses (Core net.cpp mapLocalHost / AddLocal /
 *     SeenLocal). Entries come from `--externalip` (score LOCAL_MANUAL) and
 *     from discovery: an OUTBOUND peer's VERSION carries addr_recv, the
 *     address it sees us at. A discovered entry's score is the number of
 *     DISTINCT peer netgroups that confirmed it, so one peer (or one /16)
 *     cannot talk us into advertising an address; it must be confirmed by
 *     MIN_DISCOVERED_LOCAL_SCORE groups before it is used, and it ages out
 *     after DISCOVERED_LOCAL_ADDR_TTL_MS without a fresh confirmation, so a
 *     changed public IP replaces the old one. Inbound peers only score an
 *     entry we already have (Core SeenLocal).
 *  2. The per-peer choice (Core net.cpp GetLocalAddrForPeer, 240-268).
 *  3. The send (Core net_processing.cpp MaybeSendAddr, 5445-5479): only when
 *     listening and out of IBD, one addr/addrv2 carrying just our address
 *     right after the handshake, then again on a Poisson timer averaging 24h
 *     (AVG_LOCAL_ADDRESS_BROADCAST_INTERVAL). Never to block-relay-only or
 *     feeler connections.
 *
 * Reference design: blockbrew internal/p2p/localaddr.go (a255986).
 */

import { isRoutable } from "./manager.js";
import { parseIPv4, parseIPv6 } from "./asmap.js";

/** Local address scores (Core net.h enum LOCAL_NONE..LOCAL_MANUAL). */
export const LOCAL_NONE = 0; // unknown / discovered
export const LOCAL_IF = 1; // address a local interface listens on
export const LOCAL_BIND = 2; // address explicitly bound to
export const LOCAL_MAPPED = 3; // address reported by PCP/NAT-PMP
export const LOCAL_MANUAL = 4; // address explicitly specified (--externalip)

/** Mean delay between self-announcements to one peer (Core net_processing.cpp:158). */
export const AVG_LOCAL_ADDRESS_BROADCAST_INTERVAL_MS = 24 * 60 * 60 * 1000;

/**
 * How often the timer loop looks for peers whose next self-announcement is
 * due. Coarse is fine against a 24h mean; it also bounds how late the first
 * announcement goes out after IBD ends (the IBD gate leaves the slot unset).
 */
export const LOCAL_ADDR_CHECK_INTERVAL_MS = 60 * 1000;

/**
 * A discovered (non-manual) entry not confirmed by any peer for this long is
 * dropped. Outbound churn (feelers every ~2 min) re-confirms a stable address
 * many times per hour, so this only bites after the public IP changes.
 */
export const DISCOVERED_LOCAL_ADDR_TTL_MS = 3 * 60 * 60 * 1000;

/** Distinct peer netgroups needed before a discovered address is advertised. */
export const MIN_DISCOVERED_LOCAL_SCORE = 2;

/** Cap on discovered entries; the weakest is evicted to make room. */
export const MAX_DISCOVERED_LOCAL_ADDRS = 8;

/** Cap on the per-entry confirmer set (score ceiling). */
export const MAX_LOCAL_ADDR_CONFIRMERS = 64;

/** One row of getnetworkinfo.localaddresses. */
export interface LocalAddress {
  address: string;
  port: number;
  score: number;
}

/**
 * Strict IPv6 literal parse: every group must be 1-4 hex digits (asmap's
 * parseIPv6 uses a lax parseInt), and an embedded dotted IPv4 tail
 * (`::ffff:1.2.3.4`) is converted to its two hex groups first.
 */
function parseV6Strict(host: string): Uint8Array | null {
  let h = host.replace(/^\[|\]$/g, "");
  const m = /^(.*:)(\d+\.\d+\.\d+\.\d+)$/.exec(h);
  if (m) {
    const v4 = parseIPv4(m[2]);
    if (!v4) return null;
    h = `${m[1]}${((v4[0] << 8) | v4[1]).toString(16)}:${((v4[2] << 8) | v4[3]).toString(16)}`;
  }
  const groups = h.split(":").filter((g) => g !== "");
  if (!groups.every((g) => /^[0-9a-fA-F]{1,4}$/.test(g))) return null;
  return parseIPv6(h);
}

/**
 * Canonical text form of a host: brackets stripped, IPv4-mapped IPv6
 * (`::ffff:1.2.3.4`, which Bun reports for inbound peers on a dual-stack
 * listener) folded to dotted IPv4, IPv6 in RFC 5952 compressed form.
 * Non-IP hosts are returned unchanged.
 */
export function normalizeHost(host: string): string {
  const h = host.replace(/^\[|\]$/g, "");
  if (!h.includes(":")) return h;
  const v6 = parseV6Strict(h);
  if (!v6) return h;
  return ipBytesToString(Buffer.from(v6)) ?? h;
}

function isV4Mapped(b: Uint8Array): boolean {
  for (let i = 0; i < 10; i++) if (b[i] !== 0) return false;
  return b[10] === 0xff && b[11] === 0xff;
}

/**
 * Render a 16-byte legacy network address (VERSION addr_recv, addr entries).
 * Returns null for the unspecified address (all zero, or ::ffff:0.0.0.0) —
 * Core's `CService::IsValid()` is false for those and getpeerinfo omits
 * `addrlocal`.
 */
export function ipBytesToString(buf: Uint8Array): string | null {
  if (buf.length !== 16) return null;
  if (isV4Mapped(buf)) {
    if (buf[12] === 0 && buf[13] === 0 && buf[14] === 0 && buf[15] === 0) return null;
    return `${buf[12]}.${buf[13]}.${buf[14]}.${buf[15]}`;
  }
  if (buf.every((x) => x === 0)) return null;
  const groups: number[] = [];
  for (let i = 0; i < 16; i += 2) groups.push((buf[i] << 8) | buf[i + 1]);
  // RFC 5952: compress the longest run (>= 2) of zero groups.
  let bestStart = -1;
  let bestLen = 0;
  for (let i = 0; i < 8; ) {
    if (groups[i] !== 0) {
      i++;
      continue;
    }
    let j = i;
    while (j < 8 && groups[j] === 0) j++;
    if (j - i > bestLen) {
      bestStart = i;
      bestLen = j - i;
    }
    i = j;
  }
  const hex = groups.map((g) => g.toString(16));
  if (bestLen < 2) return hex.join(":");
  const left = hex.slice(0, bestStart).join(":");
  const right = hex.slice(bestStart + bestLen).join(":");
  return `${left}::${right}`;
}

/**
 * Publicly routable check for local-address purposes (Core
 * CNetAddr::IsRoutable). IPv4 reuses the node's existing {@link isRoutable}
 * (manager.ts). That function is IPv4-only, so the IPv6 half is added here
 * with Core's non-routable ranges: unspecified, loopback, RFC3849
 * (2001:db8::/32), RFC4193 (fc00::/7), RFC4843 (2001:10::/28), RFC7343
 * (2001:20::/28), RFC4862 link-local (fe80::/64 — Core checks /64; we reject
 * all of fe80::/10). IPv4-mapped IPv6 is judged as its IPv4 address.
 */
export function isRoutableAddr(host: string): boolean {
  const h = normalizeHost(host);
  if (!h.includes(":")) {
    return parseIPv4(h) !== null && isRoutable(h);
  }
  const b = parseV6Strict(h);
  if (!b) return false;
  if (b.every((x) => x === 0)) return false; // ::
  if (b.slice(0, 15).every((x) => x === 0) && b[15] === 1) return false; // ::1
  if (b[0] === 0x20 && b[1] === 0x01 && b[2] === 0x0d && b[3] === 0xb8) return false; // 2001:db8::/32
  if ((b[0] & 0xfe) === 0xfc) return false; // fc00::/7
  if (b[0] === 0x20 && b[1] === 0x01 && b[2] === 0x00 && (b[3] & 0xf0) === 0x10) return false; // 2001:10::/28
  if (b[0] === 0x20 && b[1] === 0x01 && b[2] === 0x00 && (b[3] & 0xf0) === 0x20) return false; // 2001:20::/28
  if (b[0] === 0xfe && (b[1] & 0xc0) === 0x80) return false; // fe80::/10
  return true;
}

/**
 * The address a peer says it sees us at: the addr_recv field of ITS VERSION
 * message (Core CNode::GetAddrLocal / m_addr_local). null before VERSION, or
 * when the peer sent the unspecified address (Core CService::IsValid() false
 * -> getpeerinfo omits `addrlocal`).
 */
export function peerAddrLocal(peer: {
  versionPayload: { addrRecv: { ip: Uint8Array; port: number } } | null;
}): { host: string; port: number } | null {
  const recv = peer.versionPayload?.addrRecv;
  if (!recv) return null;
  const host = ipBytesToString(recv.ip);
  if (host === null) return null;
  return { host, port: recv.port };
}

/** True for an IPv4 host (after normalization). */
export function isIPv4Host(host: string): boolean {
  return !normalizeHost(host).includes(":");
}

/**
 * Parse one `--externalip` value: `<ip>`, `<ipv4>:<port>`, `[<ipv6>]` or
 * `[<ipv6>]:<port>` (a bare IPv6 literal is also accepted). Port 0 means
 * "use the P2P listen port". Throws on anything else.
 */
export function parseExternalIP(value: string): { host: string; port: number } {
  const v = value.trim();
  // Bare IPv4 or bare/bracketed IPv6.
  const bare = v.replace(/^\[|\]$/g, "");
  if (parseIPv4(bare) || (bare.includes(":") && parseV6Strict(bare))) {
    return { host: normalizeHost(bare), port: 0 };
  }
  let host: string;
  let portStr: string;
  const m6 = /^\[([^\]]+)\]:(\d+)$/.exec(v);
  if (m6) {
    host = m6[1];
    portStr = m6[2];
  } else {
    const idx = v.lastIndexOf(":");
    if (idx <= 0) throw new Error(`invalid address "${value}"`);
    host = v.slice(0, idx);
    portStr = v.slice(idx + 1);
  }
  if (!(parseIPv4(host) || (host.includes(":") && parseV6Strict(host)))) {
    throw new Error(`invalid IP "${host}"`);
  }
  if (!/^\d+$/.test(portStr)) throw new Error(`invalid port "${portStr}"`);
  const port = parseInt(portStr, 10);
  if (port <= 0 || port > 65535) throw new Error(`invalid port "${portStr}"`);
  return { host: normalizeHost(host), port };
}

/** Poisson inter-announcement delay (Core rand_exp_duration). */
export function nextLocalAddrDelayMs(rand: () => number = Math.random): number {
  return -Math.log(1 - rand()) * AVG_LOCAL_ADDRESS_BROADCAST_INTERVAL_MS;
}

interface LocalAddrEntry {
  host: string;
  /** 0 = "the listen port", resolved by the caller at use time. */
  port: number;
  manual: boolean;
  baseScore: number;
  confirmers: Set<string>;
  lastSeen: number;
}

function entryScore(e: LocalAddrEntry): number {
  return e.baseScore + e.confirmers.size;
}

function entryUsable(e: LocalAddrEntry): boolean {
  return e.manual || e.confirmers.size >= MIN_DISCOVERED_LOCAL_SCORE;
}

/**
 * The node's known local addresses (Core mapLocalHost). Keyed by IP only,
 * like Core (map<CNetAddr, LocalServiceInfo>).
 */
export class LocalAddrTable {
  private entries = new Map<string, LocalAddrEntry>();

  /**
   * Record an operator-specified address (--externalip). Returns false for a
   * non-routable address, which Core's AddLocal also refuses.
   */
  addManual(host: string, port: number): boolean {
    const h = normalizeHost(host);
    if (!isRoutableAddr(h)) return false;
    let e = this.entries.get(h);
    if (!e) {
      e = { host: h, port, manual: true, baseScore: LOCAL_MANUAL, confirmers: new Set(), lastSeen: 0 };
      this.entries.set(h, e);
    }
    e.manual = true;
    e.baseScore = LOCAL_MANUAL;
    e.port = port;
    return true;
  }

  /**
   * Record that a peer in netgroup `group` sees us at `host`. With
   * `create` false (inbound peers, Core SeenLocal) only an existing entry is
   * scored; with `create` true (outbound addr_recv discovery) a new entry is
   * created with `port` (our listen port).
   */
  confirm(host: string, port: number, group: string, create: boolean, now: number): boolean {
    const h = normalizeHost(host);
    if (!isRoutableAddr(h)) return false;
    this.expire(now);
    let e = this.entries.get(h);
    if (!e) {
      if (!create) return false;
      this.makeRoom();
      e = { host: h, port, manual: false, baseScore: LOCAL_NONE, confirmers: new Set(), lastSeen: now };
      this.entries.set(h, e);
    }
    if (e.confirmers.size < MAX_LOCAL_ADDR_CONFIRMERS) e.confirmers.add(group);
    e.lastSeen = now;
    return true;
  }

  private expire(now: number): void {
    for (const [k, e] of this.entries) {
      if (!e.manual && now - e.lastSeen > DISCOVERED_LOCAL_ADDR_TTL_MS) {
        this.entries.delete(k);
      }
    }
  }

  /** Evict the weakest (lowest score, then oldest) discovered entry when full. */
  private makeRoom(): void {
    let n = 0;
    let worstKey: string | null = null;
    let worst: LocalAddrEntry | null = null;
    for (const [k, e] of this.entries) {
      if (e.manual) continue;
      n++;
      if (
        worst === null ||
        entryScore(e) < entryScore(worst) ||
        (entryScore(e) === entryScore(worst) && e.lastSeen < worst.lastSeen)
      ) {
        worst = e;
        worstKey = k;
      }
    }
    if (n >= MAX_DISCOVERED_LOCAL_ADDRS && worstKey !== null) {
      this.entries.delete(worstKey);
    }
  }

  /**
   * Best usable address for a peer (Core GetLocal): same address family as
   * the peer first, then the highest score, then the most recently
   * confirmed. `peerHost` may be null (no family preference).
   */
  best(peerHost: string | null, now: number): LocalAddress | null {
    this.expire(now);
    const peerV4 = peerHost !== null ? isIPv4Host(peerHost) : null;
    const reach = (e: LocalAddrEntry): number =>
      peerV4 === null ? 0 : isIPv4Host(e.host) === peerV4 ? 1 : 0;
    let b: LocalAddrEntry | null = null;
    for (const e of this.entries.values()) {
      if (!entryUsable(e)) continue;
      if (
        b === null ||
        reach(e) > reach(b) ||
        (reach(e) === reach(b) &&
          (entryScore(e) > entryScore(b) ||
            (entryScore(e) === entryScore(b) && e.lastSeen > b.lastSeen)))
      ) {
        b = e;
      }
    }
    return b ? { address: b.host, port: b.port, score: entryScore(b) } : null;
  }

  /** Every entry, highest score first (getnetworkinfo.localaddresses). */
  list(now: number): LocalAddress[] {
    this.expire(now);
    const out = [...this.entries.values()].map((e) => ({
      address: e.host,
      port: e.port,
      score: entryScore(e),
    }));
    out.sort((a, b) => (b.score - a.score) || (a.address < b.address ? -1 : a.address > b.address ? 1 : 0));
    return out;
  }

  /** Number of entries (tests / diagnostics). */
  get size(): number {
    return this.entries.size;
  }
}
