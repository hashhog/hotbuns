/**
 * Peer discovery, connection management, and message routing.
 *
 * Handles DNS seed resolution, maintains configurable outbound connections,
 * tracks peer quality via ban scores, and routes messages to handlers.
 */

import {
  Peer,
  type PeerConfig,
  type PeerEvents,
  type PeerState,
  type OnBanCallback,
  PING_INTERVAL_MS,
  PING_TIMEOUT_MS,
  STALE_TIP_THRESHOLD_MS,
  STALE_CHECK_INTERVAL_MS,
  MINIMUM_CONNECT_TIME_MS,
  MAX_OUTBOUND_PEERS_TO_PROTECT,
} from "./peer.js";
import type { NetworkMessage, AddrPayload, NetworkAddress, AddrV2Payload, FeeFilterPayload } from "./messages.js";
import type { ConsensusParams } from "../consensus/params.js";
import { BufferReader, BufferWriter } from "../wire/serialization.js";
import { BanManager, DEFAULT_BAN_TIME, type BanEntry } from "./banman.js";
import {
  BIP155Network,
  type NetworkAddressV2,
  isValidNetworkAddressV2,
  networkAddressV2ToIPv4String,
  legacyAddressToNetworkAddressV2,
  isAddrV1Compatible,
  formatNetworkAddressV2,
  formatTorV3,
  formatI2P,
} from "./addrv2.js";
import {
  FeeFilterManager,
  meetsFeeFilter,
  MAX_MONEY,
  FEEFILTER_VERSION,
} from "./feefilter.js";
import { randomBytes } from "node:crypto";
import {
  loadAsmap,
  getMappedAS as asmapGetMappedAS,
  getAsnGroup,
  asmapVersion,
} from "./asmap.js";
import type { ProxyManager, NetworkType } from "./proxy.js";

/**
 * Maximum number of addresses retained in the v1-only fallback cache.
 * Mirrors clearbit's V2_FALLBACK_CACHE_MAX (256) — bounded so we don't
 * hold long-tail v1 hosts forever during DNS-seed churn.
 */
export const V1_ONLY_CACHE_MAX = 256;

/**
 * Hard cap on the number of entries retained in {@link PeerManager.knownAddresses}
 * (the addrman). Mirrors Bitcoin Core's ADDRMAN ceiling
 * (`ADDRMAN_NEW_BUCKET_COUNT * ADDRMAN_TRIED_BUCKET_COUNT * ...`,
 * addrman_impl.h:26-33 → ~81,920 addresses). Without this, every routable
 * address gossiped in an `addr`/`addrv2` flood is retained forever (zero
 * delete/clear) and re-persisted/reloaded across restarts, so peers.dat — and
 * RSS — grow monotonically. On overflow we evict the oldest-`lastSeen` entry
 * (a faithful approximation of Core's bucket-collision eviction; addr gossip is
 * advisory, so dropping the stalest address changes no consensus behaviour).
 */
export const KNOWN_ADDRESSES_MAX = 81920;

/**
 * Time-to-live (ms) for v1-only fallback cache entries.  After this
 * window we re-probe the address for v2 — a peer that was v1-only at
 * t=0 may have been upgraded.  1h matches the order of magnitude of
 * Bitcoin Core's v2 reconnect heuristic.
 */
export const V1_ONLY_CACHE_TTL_MS = 60 * 60 * 1000;

/**
 * Interval (ms) for periodic ASMap health-check log.
 * 3600 s = 1 hour, matching Bitcoin Core's AddrMan periodic maintenance cadence.
 */
const ASMAP_HEALTH_CHECK_INTERVAL_MS = 60 * 60 * 1000;

/** Service bit flags for peer capabilities. */
export const ServiceFlags = {
  NODE_NETWORK: 1n,          // Full node, can serve full blocks
  NODE_BLOOM: 4n,            // SPV bloom filter support (BIP 111)
  NODE_WITNESS: 8n,          // Segregated Witness support (BIP 144)
  NODE_COMPACT_FILTERS: 64n, // BIP-157 compact block filter serving (1<<6)
  NODE_NETWORK_LIMITED: 1024n, // Pruned node (BIP 159)
} as const;

/** Configuration for the peer manager. */
export interface PeerManagerConfig {
  maxOutbound: number;       // default 8 full-relay + 2 block-relay
  maxInbound: number;        // default 117
  params: ConsensusParams;
  bestHeight: number;
  datadir: string;
  /** Maximum full-relay outbound connections (default: 8) */
  maxOutboundFullRelay?: number;
  /** Maximum block-relay-only outbound connections (default: 2) */
  maxOutboundBlockRelay?: number;
  /**
   * Explicit peer addresses to connect to (from `-connect` flag).
   *
   * Bitcoin Core semantics (net.cpp `CConnman::ThreadOpenConnections`):
   * when non-empty the node connects to ONLY these peers and disables
   * DNS-seed resolution + addrman/auto-outbound dialing (Core also implies
   * `-dnsseed=0` and turns `-listen` off). hotbuns mirrors the connect-only
   * gate (no DNS, no fallbacks, no candidate fill) but leaves `-listen`
   * under operator control. See {@link isConnectOnly}.
   */
  connect?: string[];
  /**
   * Mirrors Bitcoin Core's `-dnsseed` (default on). When false
   * (`-nodnsseed` / `-dnsseed=0`) DNS-seed resolution is skipped at
   * startup; addrman/anchors/auto-outbound dialing are unaffected. This is
   * independent of {@link connect}: a connect-only run skips DNS regardless
   * of this flag, but `-nodnsseed` alone suppresses just the DNS lookups.
   * Mirrors clearbit `config.dns_seed` (main.zig:52, set false by
   * `--nodnsseed` / `dnsseed=0`).
   */
  dnsSeed?: boolean;
  /** Whether to listen for inbound connections (default: true) */
  listen?: boolean;
  /** P2P port to listen on (default: network default port) */
  port?: number;
  /**
   * Whether prune mode is enabled (--prune > 0).  Note: this does NOT gate
   * NODE_NETWORK_LIMITED advertisement.  Core advertises NODE_NETWORK_LIMITED
   * UNCONDITIONALLY for full nodes (init.cpp:863 base g_local_services =
   * NODE_NETWORK_LIMITED | NODE_WITNESS), so the bit lives in
   * `params.services` (0x409) and is always sent.  Peers seeing it must not
   * request blocks below the recent-`MIN_BLOCKS_TO_KEEP` (288) keep window.
   */
  pruneMode?: boolean;
  /**
   * Path to an asmap binary file for ASN-aware outbound peer grouping.
   * Mirrors Bitcoin Core's `-asmap=<file>` (init.cpp:540).
   * When set, the bytecode is loaded and validated at construction time;
   * startup throws if the file is missing or fails sanity checking.
   * Relative paths are resolved against the network-specific datadir.
   * When null/undefined, falls back to the legacy /16 (IPv4) or /32 (IPv6)
   * prefix-based bucketing.
   */
  asmapPath?: string | null;
  /**
   * Optional multi-network proxy manager.  When non-null and initialized,
   * outbound connects to `.onion` / `.b32.i2p` addresses route through
   * the configured SOCKS5 / I2P SAM proxies; clearnet routes through the
   * default proxy if one is set (otherwise direct).
   *
   * Constructed in cli.ts from --proxy / --onion / --i2psam flags and
   * passed in here so PeerManager can dispatch on PeerInfo.networkId.
   * When null, all outbound goes through Bun.connect directly and the
   * candidate set is filtered to clearnet-only.
   */
  proxyManager?: ProxyManager | null;
  /**
   * Mirrors Bitcoin Core's `-cjdnsreachable`. When true, CJDNS peers
   * (fc00::/8 IPv6, BIP155 network id 6) are eligible for outbound
   * connects (direct, no SOCKS5). When false (default), CJDNS peers
   * are filtered out of {@link getCandidateAddresses}.
   */
  cjdnsReachable?: boolean;
}

/** Stored information about a known peer address. */
export interface PeerInfo {
  host: string;
  port: number;
  services: bigint;
  lastSeen: number;          // Unix timestamp
  banScore: number;
  lastConnected: number;     // Unix timestamp
  /** Connection type when connected */
  connectionType?: ConnectionType;
  /** Time when peer was connected (for eviction) */
  connectedTime?: number;
  /** Minimum ping latency observed */
  minPingTime?: number;
  /** Last time peer sent us a block */
  lastBlockTime?: number;
  /** Last time peer sent us a transaction */
  lastTxTime?: number;
  /**
   * BIP155 network type (1=IPv4, 2=IPv6, 4=TorV3, 5=I2P, 6=CJDNS).
   * If not set, assumes IPv4 (for legacy addresses).
   */
  networkId?: number;
  /**
   * Raw address bytes for non-IPv4/IPv6 addresses (Tor, I2P, CJDNS).
   * For IPv4/IPv6, we use the host field.
   */
  rawAddr?: Buffer;
  /**
   * Internal provenance tag for the address. "fixedseeds" mirrors Core's
   * CNetAddr::SetInternal("fixedseeds") used as the source when injecting the
   * hardcoded last-resort seeds (net.cpp:2642). Unset for normally-learned
   * addresses.
   */
  source?: string;
}

/**
 * Ban score penalties for various infractions.
 * Reference: Bitcoin Core net_processing.cpp Misbehaving() calls.
 */
export const BanScores = {
  INVALID_MESSAGE: 20,
  INVALID_BLOCK_HEADER: 100, // Instant ban
  INVALID_BLOCK: 100,        // Instant ban
  INVALID_TRANSACTION: 10,
  UNSOLICITED_MESSAGE: 20,
  PROTOCOL_VIOLATION: 10,
  SLOW_RESPONSE: 2,
  UNREQUESTED_DATA: 5,
  HEADERS_DONT_CONNECT: 20,
  BLOCK_DOWNLOAD_STALL: 50,
} as const;

/** Fallback peer addresses when DNS seeds fail (testnet4 is unreliable). */
const FALLBACK_PEERS: Record<number, Array<{ host: string; port: number }>> = {
  // Mainnet (networkMagic: 0xd9b4bef9)
  0xd9b4bef9: [
    { host: "seed.bitcoin.sipa.be", port: 8333 },
    { host: "dnsseed.bluematt.me", port: 8333 },
  ],
  // Testnet (networkMagic: 0x0709110b)
  0x0709110b: [
    { host: "testnet-seed.bitcoin.jonasschnelli.ch", port: 18333 },
    { host: "seed.tbtc.petertodd.net", port: 18333 },
  ],
  // Testnet4 (networkMagic: 0x283f161c)
  0x283f161c: [
    { host: "seed.testnet4.bitcoin.sprovoost.nl", port: 48333 },
    { host: "seed.testnet4.wiz.biz", port: 48333 },
  ],
  // Regtest (networkMagic: 0xdab5bffa) - no fallbacks, local only
  0xdab5bffa: [],
};

/**
 * Curated, hardcoded fixed-seed IPs — the LAST-RESORT bootstrap fallback,
 * keyed by networkMagic. These are Core-vetted IPv4 peer addresses (NOT DNS
 * hostnames) injected into the known-address pool only when DNS seeding has
 * yielded nothing and the book is empty. They are layered AFTER the normal
 * DNS bootstrap; they never replace nor bypass it.
 *
 * Reference: Bitcoin Core net.cpp:2607-2643 ThreadOpenConnections fixed-seed
 * trigger (add_fixed_seeds one-shot) + chainparams.cpp m_params.FixedSeeds().
 * Core clears vFixedSeeds for non-mainnet, so only mainnet carries entries;
 * testnet/testnet4/regtest are empty.
 */
export const FIXED_SEEDS: Record<number, Array<{ host: string; port: number }>> = {
  // Mainnet (networkMagic: 0xd9b4bef9) — 40 curated IPv4:8333 fixed seeds.
  0xd9b4bef9: [
    { host: "2.121.116.198", port: 8333 },
    { host: "3.86.179.235", port: 8333 },
    { host: "4.2.51.251", port: 8333 },
    { host: "5.2.23.226", port: 8333 },
    { host: "12.11.29.34", port: 8333 },
    { host: "14.49.142.41", port: 8333 },
    { host: "18.27.125.103", port: 8333 },
    { host: "23.93.18.82", port: 8333 },
    { host: "24.16.202.74", port: 8333 },
    { host: "27.83.109.113", port: 8333 },
    { host: "31.41.23.249", port: 8333 },
    { host: "34.65.45.157", port: 8333 },
    { host: "35.78.97.86", port: 8333 },
    { host: "37.15.61.236", port: 8333 },
    { host: "38.52.3.192", port: 8333 },
    { host: "40.160.1.232", port: 8333 },
    { host: "44.223.26.178", port: 8333 },
    { host: "45.19.130.200", port: 8333 },
    { host: "46.126.216.3", port: 8333 },
    { host: "47.90.137.13", port: 8333 },
    { host: "50.4.123.66", port: 8333 },
    { host: "51.154.0.142", port: 8333 },
    { host: "52.182.185.242", port: 8333 },
    { host: "60.241.1.72", port: 8333 },
    { host: "62.34.57.141", port: 8333 },
    { host: "63.247.147.166", port: 8333 },
    { host: "64.23.97.128", port: 8333 },
    { host: "65.94.134.253", port: 8333 },
    { host: "66.35.84.14", port: 8333 },
    { host: "67.4.139.122", port: 8333 },
    { host: "68.61.69.53", port: 8333 },
    { host: "69.4.94.226", port: 8333 },
    { host: "70.44.20.24", port: 8333 },
    { host: "71.56.178.136", port: 8333 },
    { host: "72.88.192.74", port: 8333 },
    { host: "73.42.33.255", port: 8333 },
    { host: "74.48.195.218", port: 8333 },
    { host: "75.80.3.4", port: 8333 },
    { host: "76.124.35.108", port: 8333 },
    { host: "77.38.72.37", port: 8333 },
  ],
  // Testnet (networkMagic: 0x0709110b) — Core clears vFixedSeeds: none.
  0x0709110b: [],
  // Testnet4 (networkMagic: 0x283f161c) — none.
  0x283f161c: [],
  // Regtest (networkMagic: 0xdab5bffa) — none.
  0xdab5bffa: [],
};

/** Database prefix for peer addresses. */
export const DB_PREFIX_PEERS = 0x70; // 'p'

/** Maximum outbound full-relay connections. */
export const MAX_OUTBOUND_FULL_RELAY = 8;

/** Maximum outbound block-relay-only connections. */
export const MAX_OUTBOUND_BLOCK_RELAY = 2;

/** Maximum anchor connections to persist. */
export const MAX_BLOCK_RELAY_ONLY_ANCHORS = 2;

/** Protection counts for inbound eviction (per category). */
export const EVICTION_PROTECT_NETGROUP = 4;
export const EVICTION_PROTECT_PING = 8;
export const EVICTION_PROTECT_TX = 4;
export const EVICTION_PROTECT_BLOCKS = 4;
export const EVICTION_PROTECT_BLOCK_RELAY = 8;

/** Connection type for outbound connections. */
export type ConnectionType = "full_relay" | "block_relay" | "inbound";

/**
 * Compute the network group for an IP address.
 *
 * For IPv4: uses /16 prefix (first two octets)
 * For IPv6: uses /32 prefix (first four bytes)
 *
 * This ensures outbound connections are distributed across different
 * network groups, making eclipse attacks much harder.
 *
 * Reference: Bitcoin Core netgroup.cpp GetGroup()
 */
export function getNetGroup(addr: string): string {
  // Check if IPv6
  if (addr.includes(":")) {
    // IPv6 address - use /32 prefix
    const parts = addr.split(":");
    if (parts.length >= 2) {
      // Expand :: notation if present
      const fullParts: string[] = [];
      let seenDoubleColon = false;
      for (const part of parts) {
        if (part === "" && !seenDoubleColon) {
          seenDoubleColon = true;
          // Fill in zeros for the missing parts
          const missing = 8 - parts.filter((p) => p !== "").length;
          for (let i = 0; i < missing + 1; i++) {
            fullParts.push("0000");
          }
        } else if (part !== "") {
          fullParts.push(part.padStart(4, "0"));
        }
      }
      // /32 = first 2 groups (4 bytes)
      return `ipv6:${fullParts[0]}:${fullParts[1]}`;
    }
    return `ipv6:${addr}`;
  }

  // Check if it looks like an IPv4 address (all numeric octets)
  const parts = addr.split(".");
  if (parts.length === 4) {
    const isIPv4 = parts.every((p) => {
      const num = parseInt(p, 10);
      return !isNaN(num) && num >= 0 && num <= 255 && String(num) === p;
    });
    if (isIPv4) {
      // /16 = first two octets
      return `ipv4:${parts[0]}.${parts[1]}`;
    }
  }

  // Fallback: use full address as group (e.g., hostnames)
  return `other:${addr}`;
}

/**
 * Check if an address is a localhost/loopback address.
 */
export function isLocalAddress(addr: string): boolean {
  return (
    addr === "127.0.0.1" ||
    addr === "localhost" ||
    addr === "::1" ||
    addr.startsWith("127.")
  );
}

/**
 * Check if an IPv4 address string is publicly routable on the global internet.
 *
 * Mirrors Bitcoin Core CNetAddr::IsRoutable() / netaddress.cpp.
 * Rejects:
 *   RFC1918  — 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
 *   RFC2544  — 198.18.0.0/15  (benchmarking)
 *   RFC3927  — 169.254.0.0/16 (link-local / APIPA)
 *   RFC6598  — 100.64.0.0/10  (shared address space)
 *   RFC5737  — 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 (documentation)
 *   Loopback — 0.0.0.0/8, 127.0.0.0/8
 *
 * Core ref: addrman.cpp AddSingle() `if (!addr.IsRoutable()) return false;`
 *           netaddress.cpp CNetAddr::IsRoutable()
 */
export function isRoutable(addr: string): boolean {
  const parts = addr.split(".");
  if (parts.length !== 4) return false; // Only IPv4 handled here

  const [a, b, c] = parts.map(Number);
  if (parts.some((p) => isNaN(Number(p)) || Number(p) < 0 || Number(p) > 255)) {
    return false;
  }

  // Loopback / unspecified (IsLocal): 127.0.0.0/8 and 0.0.0.0/8
  if (a === 127 || a === 0) return false;

  // RFC1918 — private ranges
  if (a === 10) return false;
  if (a === 172 && b >= 16 && b <= 31) return false;
  if (a === 192 && b === 168) return false;

  // RFC2544 — benchmarking: 198.18.0.0/15
  if (a === 198 && (b === 18 || b === 19)) return false;

  // RFC3927 — link-local: 169.254.0.0/16
  if (a === 169 && b === 254) return false;

  // RFC6598 — shared address space: 100.64.0.0/10
  if (a === 100 && b >= 64 && b <= 127) return false;

  // RFC5737 — documentation ranges
  if (a === 192 && b === 0 && c === 2) return false;
  if (a === 198 && b === 51 && c === 100) return false;
  if (a === 203 && b === 0 && c === 113) return false;

  return true;
}

/**
 * Candidate for eviction from inbound slots.
 * Contains metadata needed for the eviction algorithm.
 */
export interface EvictionCandidate {
  id: string; // peer key (host:port)
  connectedTime: number; // Unix timestamp when connected
  minPingTime: number; // Minimum observed ping latency
  lastBlockTime: number; // Time of last block received
  lastTxTime: number; // Time of last tx received
  keyedNetGroup: string; // Network group (hashed for determinism)
  isBlockRelayOnly: boolean; // Block-relay-only connection
  isLocal: boolean; // Localhost connection
}

/**
 * Manages peer connections, discovery, and message routing.
 *
 * Responsibilities:
 * - Resolve DNS seeds to discover peers
 * - Maintain up to maxOutbound outbound connections
 * - Track peer quality and ban misbehaving peers
 * - Route received messages to registered handlers
 * - Persist known addresses for faster restarts
 */
export class PeerManager {
  private peers: Map<string, Peer>;
  private knownAddresses: Map<string, PeerInfo>;
  private config: PeerManagerConfig;
  private messageHandlers: Map<string, Array<(peer: Peer, msg: NetworkMessage) => void>>;
  private maintainInterval: ReturnType<typeof setInterval> | null;
  private running: boolean;
  private lastActivity: Map<string, number>;
  private connectingPeers: Set<string>;
  private banManager: BanManager;

  /** Track connection type for each peer */
  private peerConnectionType: Map<string, ConnectionType>;
  /** Track network groups of outbound peers (for diversity) */
  private outboundNetGroups: Set<string>;
  /** Anchor connections to reconnect on startup */
  private anchors: Array<{ host: string; port: number }>;
  /** Track inbound peers for eviction */
  private inboundPeers: Set<string>;

  /**
   * Set true once {@link stop} has been entered.  Independent of
   * {@link running} because tests (and the mainnet `connectPeer` path)
   * exercise the manager without first calling {@link start}, so
   * `running === false` does not imply "shutdown in progress".
   * Used by {@link handlePeerMessage} to drop messages that arrive after
   * shutdown begins, preventing P2P-driven async DB writes from racing
   * `db.close()` and surfacing as `LEVEL_DATABASE_NOT_OPEN` log spam.
   */
  private shuttingDown: boolean;

  /** Interval for periodic ping checks (2 minutes). */
  private pingInterval: ReturnType<typeof setInterval> | null;
  /** Interval for stale tip checks (45 seconds). */
  private staleCheckInterval: ReturnType<typeof setInterval> | null;
  /** Track protected outbound peers (have good chain). */
  private protectedPeers: Set<string>;
  /** Last time we updated our tip. */
  private lastTipUpdateTime: number;
  /** BIP133 feefilter manager. */
  private feeFilterManager: FeeFilterManager;
  /** Interval for periodic feefilter checks. */
  private feeFilterInterval: ReturnType<typeof setInterval> | null;
  /** Interval for periodic ASMap health-check log (every 3600 s). */
  private asmapHealthCheckInterval: ReturnType<typeof setInterval> | null;
  /** TCP listener for inbound P2P connections (Bun.listen). */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private tcpListener: any;

  /**
   * Per-address v1-only cache.  After a failed BIP-324 v2 outbound
   * negotiation we record the address here so subsequent reconnect
   * attempts skip the v2 probe and go straight to v1.  Map value is
   * the time (ms since epoch) when the entry was added; entries older
   * than {@link V1_ONLY_CACHE_TTL_MS} are evicted lazily on lookup.
   *
   * Reference: clearbit PeerManager.v2_fallback_set / markV1Only /
   * isV1Only (clearbit src/peer.zig:1942-1958), but we use a
   * timestamped Map for TTL-based eviction rather than a fixed-size
   * AutoHashMap.
   */
  private v1OnlyCache: Map<string, number>;

  /**
   * Loaded ASMap bytecode, or null when no --asmap flag was supplied.
   * When non-null, getMappedAS() and getNetGroup() use ASN-based bucketing
   * instead of the legacy /16 (IPv4) or /32 (IPv6) prefix scheme.
   *
   * Reference: Bitcoin Core NetGroupManager::m_asmap (netgroup.h)
   */
  private asmapData: Uint8Array | null;

  /**
   * Multi-network proxy manager (Tor SOCKS5 + I2P SAM + clearnet SOCKS5).
   * Constructed by cli.ts from --proxy / --onion / --i2psam flags and
   * passed in via {@link PeerManagerConfig.proxyManager}.  Null when no
   * proxy flag was supplied; in that case only IPv4/IPv6 candidates are
   * returned by {@link getCandidateAddresses}.
   *
   * Reference: bitcoin-core/src/init.cpp `-proxy`/`-onion`/`-i2psam`,
   *            netbase.cpp SetProxy(NET_*).
   */
  private proxyManager: ProxyManager | null;

  /** Mirrors `-cjdnsreachable`. See {@link PeerManagerConfig.cjdnsReachable}. */
  private cjdnsReachable: boolean;

  /**
   * Mirrors `-dnsseed` (default true). When false, DNS-seed resolution is
   * skipped at startup. See {@link PeerManagerConfig.dnsSeed}.
   */
  private dnsSeed: boolean;

  /**
   * One-shot guard for the fixed-seed last-resort injection. Set true after
   * {@link maybeAddFixedSeeds} fires once so subsequent ticks are no-ops.
   * Mirrors Core's `add_fixed_seeds = false` (net.cpp:2641).
   */
  private fixedSeedsAdded: boolean;

  /**
   * Wall-clock ms timestamp anchored at the top of {@link start}. Used by
   * {@link maybeAddFixedSeeds} for the 60s grace period before falling back to
   * fixed seeds. Mirrors Core's `start` anchor in ThreadOpenConnections
   * (net.cpp `GetTime() > start + 1min`).
   */
  private loopStartTs: number;

  /**
   * Parsed, pinned `-connect` peers (host + port). Non-empty iff the
   * operator passed one or more `-connect=<ip:port>` flags. When non-empty
   * the node is in connect-only mode: DNS seeding, fallback peers, anchors,
   * and addrman candidate fill are all suppressed; the maintenance loop
   * only (re)dials these addresses. Mirrors clearbit `connect_address`
   * (peer.zig:7009 / 7050) but supports a list rather than a single peer.
   */
  private readonly connectPeers: ReadonlyArray<{ host: string; port: number }>;

  constructor(config: PeerManagerConfig) {
    this.config = {
      maxOutbound: config.maxOutbound ?? MAX_OUTBOUND_FULL_RELAY + MAX_OUTBOUND_BLOCK_RELAY,
      maxInbound: config.maxInbound ?? 117,
      params: config.params,
      bestHeight: config.bestHeight ?? 0,
      datadir: config.datadir,
      maxOutboundFullRelay: config.maxOutboundFullRelay ?? MAX_OUTBOUND_FULL_RELAY,
      maxOutboundBlockRelay: config.maxOutboundBlockRelay ?? MAX_OUTBOUND_BLOCK_RELAY,
      connect: config.connect,
      listen: config.listen ?? true,
      port: config.port ?? config.params.defaultPort,
      // Retained for prune-mode behavior generally; it no longer gates the
      // NODE_NETWORK_LIMITED service bit (advertised unconditionally for this
      // full node via params.services = 0x409, per Core init.cpp:863/1950).
      pruneMode: config.pruneMode ?? false,
    };
    this.peers = new Map();
    this.knownAddresses = new Map();
    this.messageHandlers = new Map();
    this.maintainInterval = null;
    this.running = false;
    this.shuttingDown = false;
    this.lastActivity = new Map();
    this.connectingPeers = new Set();
    this.banManager = new BanManager(config.datadir);
    this.peerConnectionType = new Map();
    this.outboundNetGroups = new Set();
    this.anchors = [];
    this.inboundPeers = new Set();
    this.pingInterval = null;
    this.staleCheckInterval = null;
    this.protectedPeers = new Set();
    this.lastTipUpdateTime = Date.now();
    // Initialize feefilter manager with send callback
    this.feeFilterManager = new FeeFilterManager((peer, feeRate) => {
      peer.send({ type: "feefilter", payload: { feeRate } });
    });
    this.feeFilterInterval = null;
    this.asmapHealthCheckInterval = null;
    this.tcpListener = null;
    this.v1OnlyCache = new Map();

    // Load asmap if --asmap path was supplied.
    // Mirrors Bitcoin Core init.cpp:1590-1605: resolve path, load, validate.
    // Throws on load/sanity failure (startup must fail loudly on bad asmap).
    if (config.asmapPath) {
      const data = loadAsmap(config.asmapPath);
      if (!data) {
        throw new Error(
          `Failed to load or validate asmap file: ${config.asmapPath}. ` +
          `File may be missing, too large (>8 MiB), or contain invalid bytecode.`
        );
      }
      this.asmapData = data;
    } else {
      this.asmapData = null;
    }

    // Wire in the proxy manager and CJDNS reachability flag from cli.ts.
    // Both default to "off" (null / false); existing call sites that
    // construct PeerManager without these fields keep the historical
    // clearnet-only behavior.
    this.proxyManager = config.proxyManager ?? null;
    this.cjdnsReachable = config.cjdnsReachable ?? false;
    this.dnsSeed = config.dnsSeed ?? true;
    this.fixedSeedsAdded = false;
    // Anchored properly at the top of start(); initialized here so the field
    // is always defined even for tests that exercise the manager without
    // calling start().
    this.loopStartTs = Date.now();

    // Parse the pinned -connect addresses once. host:port split mirrors the
    // start()-path parsing below (lastIndexOf(":") so IPv6 literals survive),
    // defaulting to the network's default P2P port when no port is given.
    const parsedConnect: Array<{ host: string; port: number }> = [];
    for (const addr of config.connect ?? []) {
      const [host, portStr] = addr.includes(":")
        ? [addr.slice(0, addr.lastIndexOf(":")), addr.slice(addr.lastIndexOf(":") + 1)]
        : [addr, String(this.config.params.defaultPort)];
      const port = parseInt(portStr, 10);
      if (host && !Number.isNaN(port)) {
        parsedConnect.push({ host, port });
      }
    }
    this.connectPeers = parsedConnect;
  }

  /**
   * Returns true iff the node is in Bitcoin Core `-connect` mode: one or
   * more `-connect=<ip:port>` peers were pinned. In this mode the node
   * connects to ONLY those peers and suppresses DNS seeding, fallback
   * peers, anchors, and addrman candidate fill.
   *
   * Reference: bitcoin-core/src/net.cpp `CConnman::ThreadOpenConnections`
   * (the `connect.size()` branch); clearbit peer.zig:7009/7050
   * (`connect_address` gate).
   */
  isConnectOnly(): boolean {
    return this.connectPeers.length > 0;
  }

  /**
   * Returns the proxy manager, or null when none is configured.
   * Exposed for {@link Peer.connect} routing and unit tests.
   */
  getProxyManager(): ProxyManager | null {
    return this.proxyManager;
  }

  /**
   * Returns true iff CJDNS outbound is enabled (`--cjdnsreachable`).
   */
  isCJDNSReachable(): boolean {
    return this.cjdnsReachable;
  }

  /**
   * Resolve a {@link PeerInfo} entry into the dialable network type +
   * host string used for outbound connects. Returns null when the peer
   * cannot be reached given the current proxy configuration.
   *
   * For IPv4/IPv6 the host string is used directly (Bun.connect or
   * SOCKS5 over the default proxy).  For TorV3, the 32-byte pubkey is
   * encoded as the proper `.onion` address (base32 of pubkey || checksum
   * || version).  For I2P the 32-byte hash is encoded as `.b32.i2p`.
   * For CJDNS the 16-byte address is formatted as IPv6.
   *
   * Returns null when:
   *   - networkId is TorV3 and no SOCKS5 proxy is configured,
   *   - networkId is I2P and no SAM bridge is configured,
   *   - networkId is CJDNS and `--cjdnsreachable` was not set,
   *   - networkId is unknown (BIP-155 forward compatibility).
   *
   * Used by {@link getCandidateAddresses} (BUG-5 filter) and
   * {@link connectPeerInfo} to route outbound connects through the
   * appropriate transport.
   */
  resolveDialable(info: PeerInfo): { host: string; networkType: NetworkType } | null {
    const networkId = info.networkId ?? BIP155Network.IPV4;
    switch (networkId) {
      case BIP155Network.IPV4:
        return { host: info.host, networkType: "ipv4" };
      case BIP155Network.IPV6: {
        // Older code stored the raw 32-char hex in info.host; if rawAddr
        // is present we re-derive the canonical IPv6 string. If only the
        // legacy hex string is present, accept it as-is — Bun.connect
        // tolerates either form for in-fleet round-trips.
        if (info.rawAddr && info.rawAddr.length === 16) {
          const groups: string[] = [];
          for (let i = 0; i < 16; i += 2) {
            const v = (info.rawAddr[i] << 8) | info.rawAddr[i + 1];
            groups.push(v.toString(16));
          }
          return { host: groups.join(":"), networkType: "ipv6" };
        }
        return { host: info.host, networkType: "ipv6" };
      }
      case BIP155Network.TORV3: {
        if (!this.proxyManager) return null;
        if (!info.rawAddr || info.rawAddr.length !== 32) return null;
        return {
          host: formatTorV3(info.rawAddr),
          networkType: "onion",
        };
      }
      case BIP155Network.I2P: {
        if (!this.proxyManager) return null;
        if (!info.rawAddr || info.rawAddr.length !== 32) return null;
        return {
          host: formatI2P(info.rawAddr),
          networkType: "i2p",
        };
      }
      case BIP155Network.CJDNS: {
        if (!this.cjdnsReachable) return null;
        if (!info.rawAddr || info.rawAddr.length !== 16) return null;
        const groups: string[] = [];
        for (let i = 0; i < 16; i += 2) {
          const v = (info.rawAddr[i] << 8) | info.rawAddr[i + 1];
          groups.push(v.toString(16));
        }
        return { host: groups.join(":"), networkType: "cjdns" };
      }
      default:
        return null;
    }
  }

  /**
   * Return a cryptographically secure random integer in [0, n).
   *
   * Uses crypto.randomBytes() (CSPRNG) rather than Math.random().
   * Reference: Bitcoin Core FastRandomContext (random.h).
   *
   * This is the equivalent of Core's insecure_rand() used throughout
   * AddrMan for shuffling, peer selection, and bucket assignment.
   */
  secureRandInt(n: number): number {
    if (n <= 0) return 0;
    // Draw 4 bytes from the OS CSPRNG and interpret as unsigned 32-bit BE.
    const val = randomBytes(4).readUInt32BE(0);
    // Modulo bias is negligible for small n relative to 2^32.
    return val % n;
  }

  // ---------------------------------------------------------------------------
  // ASMap API — mirrors Bitcoin Core's NetGroupManager public interface
  // ---------------------------------------------------------------------------

  /**
   * Return the network group string for `addr`, using ASN-based bucketing
   * when an asmap is loaded, otherwise falling back to the /16 (IPv4) or
   * /32 (IPv6) prefix string.
   *
   * Used internally for all outbound diversity checks and eviction logic.
   * The public standalone `getNetGroup()` (no-asmap) is retained for callers
   * that do not have access to the PeerManager instance.
   */
  private getNetGroupForAddr(addr: string): string {
    if (this.asmapData && this.asmapData.length > 0) {
      const asn = asmapGetMappedAS(this.asmapData, addr);
      if (asn !== 0) {
        return `asn:${asn}`;
      }
    }
    return getNetGroup(addr);
  }

  /**
   * Returns true iff an asmap file was loaded successfully at startup.
   * Mirrors Bitcoin Core's NetGroupManager::UsingASMap().
   */
  usingASMap(): boolean {
    return this.asmapData !== null && this.asmapData.length > 0;
  }

  /**
   * Look up the ASN for a peer address string (IPv4 or IPv6).
   * Returns 0 if asmap is not loaded, the address is not IP-based
   * (Tor, I2P, hostname), or the prefix has no ASN mapping.
   * AS0 is reserved by RFC 7607 — always means "no mapping".
   *
   * Mirrors Bitcoin Core's NetGroupManager::GetMappedAS().
   *
   * @param addr  Peer address string (dotted-decimal IPv4 or bracketed/bare IPv6).
   */
  getMappedAS(addr: string): number {
    return asmapGetMappedAS(this.asmapData, addr);
  }

  /**
   * Return the SHA-256 checksum of the loaded asmap data as a hex string,
   * or null when no asmap is loaded.  Used to detect asmap file changes
   * and trigger re-bucketing of addrman entries.
   *
   * Mirrors Bitcoin Core's NetGroupManager::GetAsmapVersion() + AsmapVersion().
   */
  getAsmapVersion(): string | null {
    if (!this.asmapData || this.asmapData.length === 0) return null;
    return asmapVersion(this.asmapData);
  }

  /**
   * Log a summary of how well the loaded asmap covers the current peer set.
   * Mirrors Bitcoin Core's NetGroupManager::ASMapHealthCheck(clearnet_addrs).
   *
   * Returns an object with { total, mapped, unmapped, distinctASNs } — also
   * logs a one-line summary at info level.
   *
   * Reference: bitcoin-core/src/net.cpp:4188 post-addrman construction call.
   */
  asmapHealthCheck(): { total: number; mapped: number; unmapped: number; distinctASNs: number } {
    const asnSet = new Set<number>();
    let mapped = 0;
    let total = 0;
    for (const info of this.knownAddresses.values()) {
      // Only count clearnet (IPv4/IPv6) peers
      if (info.host.includes(":") || /^\d+\.\d+\.\d+\.\d+$/.test(info.host)) {
        total++;
        const asn = asmapGetMappedAS(this.asmapData, info.host);
        if (asn !== 0) {
          mapped++;
          asnSet.add(asn);
        }
      }
    }
    const result = { total, mapped, unmapped: total - mapped, distinctASNs: asnSet.size };
    console.log(
      `ASMap Health Check: ${total} clearnet peers, ` +
      `${mapped} mapped to ${asnSet.size} ASNs, ${result.unmapped} unmapped.`
    );
    return result;
  }

  /**
   * Mark `addr` (host:port key) as v1-only — future outbound attempts
   * skip the v2 probe and go straight to v1.  Bounded at
   * {@link V1_ONLY_CACHE_MAX} entries; oldest insertion is dropped on
   * overflow.
   */
  markV1Only(addr: string): void {
    if (this.v1OnlyCache.size >= V1_ONLY_CACHE_MAX) {
      // Drop oldest entry by insertion order (Maps preserve insertion order).
      const firstKey = this.v1OnlyCache.keys().next().value;
      if (firstKey !== undefined) {
        this.v1OnlyCache.delete(firstKey);
      }
    }
    this.v1OnlyCache.set(addr, Date.now());
  }

  /**
   * Returns true iff `addr` is in the v1-only cache and the entry has
   * not expired.  Lazily evicts stale entries on lookup.
   */
  isV1Only(addr: string): boolean {
    const ts = this.v1OnlyCache.get(addr);
    if (ts === undefined) return false;
    if (Date.now() - ts > V1_ONLY_CACHE_TTL_MS) {
      this.v1OnlyCache.delete(addr);
      return false;
    }
    return true;
  }

  /**
   * Drop all entries from the v1-only cache (for testing).
   */
  clearV1OnlyCache(): void {
    this.v1OnlyCache.clear();
  }

  /**
   * Resolved service-bit field advertised in outbound + inbound version
   * handshakes, identical to the value computed at the connect/listen sites.
   * For a full node this is NODE_NETWORK | NODE_WITNESS | NODE_NETWORK_LIMITED
   * (0x409): Core advertises NODE_NETWORK_LIMITED UNCONDITIONALLY for full
   * nodes (init.cpp:863 base g_local_services = NODE_NETWORK_LIMITED |
   * NODE_WITNESS; NODE_NETWORK added for non-prune at init.cpp:1950).  The
   * bit lives in `params.services`, so no prune gate is needed here.
   * NODE_P2P_V2 is NOT advertised (BIP-324 v2 is default-off for hotbuns).
   * Exposed primarily so tests can pin the advertised bitset without poking
   * at private state.
   */
  getAdvertisedServices(): bigint {
    return this.config.params.services;
  }

  /**
   * Start the peer manager: resolve DNS seeds, begin connecting.
   */
  async start(): Promise<void> {
    this.running = true;
    // Anchor the connection-loop start timestamp for the fixed-seed 60s grace
    // period (Core net.cpp ThreadOpenConnections `start`).
    this.loopStartTs = Date.now();

    // Start TCP listener for inbound connections
    if (this.config.listen && this.config.port) {
      this.startListener(this.config.port);
    }

    // Load ban list and persisted addresses
    await this.banManager.load();
    await this.loadAddresses();

    // Load anchor connections for fast re-entry into the network
    await this.loadAnchors();

    // Add explicit --connect addresses first (highest priority)
    if (this.config.connect && this.config.connect.length > 0) {
      const now = Date.now();
      for (const addr of this.config.connect) {
        const [host, portStr] = addr.includes(":")
          ? [addr.slice(0, addr.lastIndexOf(":")), addr.slice(addr.lastIndexOf(":") + 1)]
          : [addr, String(this.config.params.defaultPort)];
        const port = parseInt(portStr, 10);
        const key = `${host}:${port}`;
        if (!this.knownAddresses.has(key)) {
          this.knownAddresses.set(key, {
            host,
            port,
            // Conservative baseline: assume full-node + segwit only.  We learn
            // the real services during the version handshake and update
            // info.services (see handleHandshakeComplete).  NODE_BLOOM is NOT
            // assumed here — advertising or honoring it is controlled by the
            // --peerbloomfilters flag via params.services, not hardcoded.
            services: ServiceFlags.NODE_NETWORK | ServiceFlags.NODE_WITNESS,
            lastSeen: now,
            banScore: 0,
            lastConnected: 0,
          });
        }
      }
    }

    // Connect-only (`-connect`) and `-nodnsseed`/`-dnsseed=0` gates.
    //
    // Bitcoin Core: when `-connect` is set the node connects to ONLY those
    // peers and does NOT resolve DNS seeds nor auto-dial via addrman
    // (net.cpp ThreadOpenConnections); `-connect` also implies `-dnsseed=0`.
    // `-nodnsseed` independently suppresses just the DNS lookups.
    // clearbit mirrors this: peer.zig:7009 takes a dedicated connect branch
    // that skips dnsSeeds(), and the outbound-fill loop is gated on
    // connect_address==null (peer.zig:7050).
    //
    // So we resolve DNS + seed the known-address pool only when NOT in
    // connect-only mode AND DNS seeding is enabled. In connect-only mode the
    // only known addresses are the pinned `-connect` peers added above.
    if (!this.isConnectOnly() && this.dnsSeed) {
      // Resolve DNS seeds
      const addresses = await this.resolveDNSSeeds();
      const now = Date.now();

      // Add discovered addresses to known pool
      for (const ip of addresses) {
        const key = `${ip}:${this.config.params.defaultPort}`;
        if (!this.knownAddresses.has(key)) {
          this.knownAddresses.set(key, {
            host: ip,
            port: this.config.params.defaultPort,
            // Conservative baseline: assume full-node + segwit only.
            // Real services are learned during version handshake.
            services: ServiceFlags.NODE_NETWORK | ServiceFlags.NODE_WITNESS,
            lastSeen: now,
            banScore: 0,
            lastConnected: 0,
          });
        }
      }

      // Add fallback peers if we don't have enough addresses
      const fallbacks = FALLBACK_PEERS[this.config.params.networkMagic] ?? [];
      for (const { host, port } of fallbacks) {
        const key = `${host}:${port}`;
        if (!this.knownAddresses.has(key)) {
          this.knownAddresses.set(key, {
            host,
            port,
            // Conservative baseline: assume full-node + segwit only.
            // Real services are learned during version handshake.
            services: ServiceFlags.NODE_NETWORK | ServiceFlags.NODE_WITNESS,
            lastSeen: now,
            banScore: 0,
            lastConnected: 0,
          });
        }
      }
    } else if (this.isConnectOnly()) {
      console.log(
        `P2P: -connect mode — pinned to ${this.connectPeers.length} peer(s); ` +
        `DNS seeding, fallback peers, anchors, and auto-outbound fill disabled`
      );
    } else {
      console.log("P2P: -nodnsseed — skipping DNS seed resolution");
    }

    // Last-resort fixed-seed fallback. Layered AFTER the normal DNS / fallback
    // bootstrap above — it never replaces nor bypasses DNS. Fires immediately
    // here only for the DNS-disabled / connect-disabled-but-still-empty case
    // (Core's cheap `!dnsseed && !use_seednodes` shortcut, net.cpp:2620); the
    // 60s-grace empty-book case is handled in the maintain() loop.
    this.maybeAddFixedSeeds();

    // Fill initial connections
    await this.fillConnections();

    // Startup ASMap health-check log (once, after addresses are populated).
    // Mirrors Bitcoin Core net.cpp:4188 — called immediately after addrman
    // construction so the operator sees coverage statistics at launch.
    if (this.usingASMap()) {
      this.asmapHealthCheck();
    }

    // Start maintenance loop (every 30 seconds)
    this.maintainInterval = setInterval(() => {
      this.maintain().catch((err) => {
        console.error("Maintenance error:", err);
      });
    }, 30_000);

    // Start ping interval (every 2 minutes)
    this.pingInterval = setInterval(() => {
      this.checkPings();
    }, PING_INTERVAL_MS);

    // Start stale peer check interval (every 45 seconds)
    this.staleCheckInterval = setInterval(() => {
      this.checkForStaleTipAndEvictPeers();
    }, STALE_CHECK_INTERVAL_MS);

    // Start ASMap health-check periodic log (every 3600 s).
    // Mirrors Bitcoin Core's periodic per-hour AddrMan maintenance.
    if (this.usingASMap()) {
      this.asmapHealthCheckInterval = setInterval(() => {
        this.asmapHealthCheck();
      }, ASMAP_HEALTH_CHECK_INTERVAL_MS);
    }
  }

  /**
   * Stop all peer connections and the maintenance loop.
   */
  async stop(): Promise<void> {
    // Flip shuttingDown *before* running=false so any in-flight async
    // dispatch sees the gate immediately.
    this.shuttingDown = true;
    this.running = false;

    // Stop TCP listener
    if (this.tcpListener) {
      this.tcpListener.stop(true);
      this.tcpListener = null;
    }

    // Stop maintenance loop
    if (this.maintainInterval) {
      clearInterval(this.maintainInterval);
      this.maintainInterval = null;
    }

    // Stop ping interval
    if (this.pingInterval) {
      clearInterval(this.pingInterval);
      this.pingInterval = null;
    }

    // Stop stale check interval
    if (this.staleCheckInterval) {
      clearInterval(this.staleCheckInterval);
      this.staleCheckInterval = null;
    }

    // Stop ASMap health-check interval
    if (this.asmapHealthCheckInterval) {
      clearInterval(this.asmapHealthCheckInterval);
      this.asmapHealthCheckInterval = null;
    }

    // Clear protected peers
    this.protectedPeers.clear();

    // Save anchor connections before disconnecting (block-relay-only outbound)
    await this.saveAnchors();

    // Disconnect all peers
    for (const [key, peer] of this.peers) {
      peer.disconnect("shutdown");
      this.peers.delete(key);
    }

    // Clear connection tracking
    this.peerConnectionType.clear();
    this.outboundNetGroups.clear();
    this.inboundPeers.clear();

    // Save addresses and ban list before shutdown
    await this.saveAddresses();
    await this.banManager.save();
  }

  /**
   * Resolve DNS seed hostnames to IP addresses.
   * Shuffles results for randomized peer selection.
   */
  private async resolveDNSSeeds(): Promise<string[]> {
    const seeds = this.config.params.dnsSeed;
    const addresses: string[] = [];

    for (const seed of seeds) {
      try {
        // Use Bun's built-in DNS resolution
        // @ts-expect-error Bun.dns.resolve typing is incomplete
        const results = await Bun.dns.resolve(seed, "A") as Array<{ address: string; ttl: number }>;
        for (const record of results) {
          if (record && typeof record.address === "string") {
            addresses.push(record.address);
          }
        }
      } catch {
        // DNS resolution failed for this seed, continue with others
      }
    }

    // Shuffle addresses using Fisher-Yates (CSPRNG — Core: FastRandomContext)
    for (let i = addresses.length - 1; i > 0; i--) {
      const j = this.secureRandInt(i + 1);
      [addresses[i], addresses[j]] = [addresses[j], addresses[i]];
    }

    return addresses;
  }

  /**
   * Connect to a specific peer by host and port.
   * Returns the connected Peer instance.
   *
   * @param host - Peer hostname or IP
   * @param port - Peer port
   * @param connectionType - Type of outbound connection (default: full_relay)
   */
  async connectPeer(
    host: string,
    port: number,
    connectionType: ConnectionType = "full_relay",
    networkType: NetworkType = "ipv4"
  ): Promise<Peer> {
    const key = `${host}:${port}`;

    // Check if banned
    if (this.banManager.isBanned(host)) {
      throw new Error(`Peer ${host} is banned`);
    }

    // Check if already connected or connecting
    if (this.peers.has(key)) {
      return this.peers.get(key)!;
    }

    if (this.connectingPeers.has(key)) {
      throw new Error(`Already connecting to ${key}`);
    }

    // Network group diversity check for outbound connections
    // Skip for localhost (allows testing with multiple connections)
    if (connectionType !== "inbound" && !isLocalAddress(host)) {
      const netGroup = this.getNetGroupForAddr(host);
      if (this.outboundNetGroups.has(netGroup)) {
        throw new Error(`Already have outbound connection in netgroup ${netGroup}`);
      }
    }

    this.connectingPeers.add(key);

    // NODE_NETWORK_LIMITED (1<<10 = 0x400) is advertised UNCONDITIONALLY for
    // this full node — it is already part of `params.services` (0x409), per
    // Core (init.cpp:863 base g_local_services includes NODE_NETWORK_LIMITED;
    // NODE_NETWORK added for non-prune at init.cpp:1950).  No prune gate here.
    const advertisedServices = this.config.params.services;

    const config: PeerConfig = {
      host,
      port,
      magic: this.config.params.networkMagic,
      protocolVersion: this.config.params.protocolVersion,
      services: advertisedServices,
      userAgent: this.config.params.userAgent,
      bestHeight: this.config.bestHeight,
      relay: connectionType !== "block_relay", // Block-relay-only connections don't relay txs,
      // FIX-56 W117: plumb the proxy manager + network type into the Peer
      // so non-clearnet outbound (.onion, .b32.i2p) routes through SOCKS5
      // or I2P SAM rather than the direct Bun.connect path.  CJDNS is
      // direct-IPv6 from the node's perspective (no proxy hop).
      proxyManager: this.proxyManager ?? undefined,
      networkType,
    };

    const events: PeerEvents = {
      onConnect: (peer) => this.handlePeerConnect(peer),
      onDisconnect: (peer, error) => this.handlePeerDisconnect(peer, error),
      onMessage: (peer, msg) => this.handlePeerMessage(peer, msg),
      onHandshakeComplete: (peer) => this.handleHandshakeComplete(peer),
    };

    // Callback when peer reaches ban threshold
    const onBan: OnBanCallback = (peer, reason) => {
      this.banManager.ban(peer.host, DEFAULT_BAN_TIME, reason);
    };

    // Decide whether to attempt BIP-324 v2 first.  If outbound v2 is
    // gated off globally (HOTBUNS_BIP324_V2 env var) or this address
    // is in the v1-only cache, go straight to v1.  Otherwise try v2;
    // on failure mark v1-only and reconnect on a fresh socket — sending
    // v2 garbage to a v1 peer is destructive so the same socket cannot
    // be reused (mirrors clearbit's connectOutboundNegotiated).
    const tryV2 =
      connectionType !== "inbound" &&
      Peer.bip324V2Enabled() &&
      !this.isV1Only(key);

    let peer = new Peer(config, events, onBan);

    try {
      if (tryV2) {
        try {
          await peer.connect(/* useV2 */ true);
        } catch (v2Err) {
          // Cipher-handshake failure (timeout, decrypt error, peer is v1).
          // Mark v1-only and retry with a fresh Peer + fresh socket.
          this.markV1Only(key);
          try {
            peer.disconnect("v2 handshake failed; falling back to v1");
          } catch {
            // ignore — disconnect is idempotent
          }
          peer = new Peer(config, events, onBan);
          await peer.connect(/* useV2 */ false);
          // We expose the v2 failure as a debug-level signal but do not
          // throw — v1 succeeded.
          const reason = v2Err instanceof Error ? v2Err.message : String(v2Err);
          console.log(`P2P: BIP-324 v2 outbound failed peer=${key}: ${reason}; using v1`);
        }
      } else {
        await peer.connect(/* useV2 */ false);
      }

      this.peers.set(key, peer);
      this.lastActivity.set(key, Date.now());

      // Track connection type
      this.peerConnectionType.set(key, connectionType);

      // Track network group for outbound connections
      if (connectionType !== "inbound") {
        const netGroup = this.getNetGroupForAddr(host);
        this.outboundNetGroups.add(netGroup);
      } else {
        this.inboundPeers.add(key);
      }

      // Add or update known address
      const now = Date.now();
      if (!this.knownAddresses.has(key)) {
        this.knownAddresses.set(key, {
          host,
          port,
          // Conservative baseline: assume full-node + segwit only.
          // Real services are learned during version handshake and
          // updated via info.services = peer.versionPayload.services.
          services: ServiceFlags.NODE_NETWORK | ServiceFlags.NODE_WITNESS,
          lastSeen: now,
          banScore: 0,
          lastConnected: now,
          connectionType,
          connectedTime: now,
        });
      } else {
        const info = this.knownAddresses.get(key)!;
        info.lastConnected = now;
        info.connectionType = connectionType;
        info.connectedTime = now;
      }

      return peer;
    } catch (error) {
      // Connection failed - increase ban score slightly
      const info = this.knownAddresses.get(key);
      if (info) {
        info.banScore += 1;
      }
      throw error;
    } finally {
      this.connectingPeers.delete(key);
    }
  }

  /**
   * Disconnect a peer by key, optionally banning them.
   */
  disconnectPeer(key: string, ban?: boolean, reason?: string): void {
    const peer = this.peers.get(key);
    if (peer) {
      peer.disconnect(ban ? "banned" : "disconnect");
      this.peers.delete(key);
      this.lastActivity.delete(key);

      // Clean up connection tracking
      const connType = this.peerConnectionType.get(key);
      this.peerConnectionType.delete(key);

      if (connType !== "inbound") {
        const netGroup = this.getNetGroupForAddr(peer.host);
        this.outboundNetGroups.delete(netGroup);
      } else {
        this.inboundPeers.delete(key);
      }

      if (ban) {
        // Add to ban manager with 24-hour ban
        this.banManager.ban(peer.host, DEFAULT_BAN_TIME, reason || "disconnected with ban");
      }
    }

    if (ban) {
      const info = this.knownAddresses.get(key);
      if (info) {
        info.banScore = 100; // Mark as banned in known addresses too
      }
    }
  }

  /**
   * Register a handler for a specific message type.
   * Multiple handlers can be registered for the same type.
   */
  onMessage(type: string, handler: (peer: Peer, msg: NetworkMessage) => void): void {
    const handlers = this.messageHandlers.get(type) ?? [];
    handlers.push(handler);
    this.messageHandlers.set(type, handlers);
  }

  /**
   * Broadcast a message to all connected peers.
   */
  broadcast(msg: NetworkMessage): void {
    for (const peer of this.peers.values()) {
      if (peer.state === "connected") {
        peer.send(msg);
      }
    }
  }

  /**
   * Get a list of all connected peers.
   */
  getConnectedPeers(): Peer[] {
    return Array.from(this.peers.values()).filter(
      (peer) => peer.state === "connected"
    );
  }

  /**
   * Get the number of outbound connections.
   */
  getOutboundCount(): number {
    return this.peers.size;
  }

  /**
   * Increase ban score for a misbehaving peer.
   * Disconnects and bans if score reaches 100.
   *
   * This is a convenience method that delegates to peer.misbehaving().
   */
  increaseBanScore(peer: Peer, score: number, reason: string): void {
    const key = `${peer.host}:${peer.port}`;
    const info = this.knownAddresses.get(key);

    // Update known address ban score
    if (info) {
      info.banScore += score;
    }

    // Use the peer's misbehaving method which handles the actual banning
    peer.misbehaving(score, reason);
  }

  /**
   * Get the ban manager for RPC access.
   */
  getBanManager(): BanManager {
    return this.banManager;
  }

  /**
   * Check if an IP address is currently banned.
   */
  isBanned(address: string): boolean {
    return this.banManager.isBanned(address);
  }

  /**
   * Ban an IP address manually (via RPC).
   */
  banAddress(address: string, banTime: number = DEFAULT_BAN_TIME, reason: string = ""): void {
    this.banManager.ban(address, banTime, reason);

    // Disconnect any connected peers from this address
    for (const [key, peer] of this.peers) {
      if (peer.host === address) {
        this.disconnectPeer(key, false, reason);
      }
    }
  }

  /**
   * Unban an IP address manually (via RPC).
   */
  unbanAddress(address: string): boolean {
    return this.banManager.unban(address);
  }

  /**
   * Get list of all banned addresses.
   */
  listBanned(): BanEntry[] {
    return this.banManager.getBanned();
  }

  /**
   * Clear all bans.
   */
  clearBanned(): void {
    this.banManager.clearBanned();
  }

  /**
   * Update the best height (called when chain tip advances).
   */
  updateBestHeight(height: number): void {
    this.config.bestHeight = height;
  }

  /**
   * Get all known peer addresses.
   */
  getKnownAddresses(): Map<string, PeerInfo> {
    return new Map(this.knownAddresses);
  }

  /**
   * Map a {@link PeerInfo}'s {@link PeerInfo.networkId} (BIP-155 id) to the
   * Bitcoin Core network NAME string emitted by `getnodeaddresses`
   * (Core: netbase.cpp GetNetworkName, via CAddress::GetNetClass()).
   *
   * Returns one of `ipv4 | ipv6 | onion | i2p | cjdns`. Entries with a
   * missing / legacy networkId default to `ipv4` (matching the addr-handler
   * fallback that stamps legacy 16-byte addresses as IPV4). Unknown BIP-155
   * ids (forward-compat) map to `not_publicly_routable` — the same string
   * Core renders for NET_UNROUTABLE.
   */
  static networkIdToCoreName(networkId: number | undefined): string {
    switch (networkId ?? BIP155Network.IPV4) {
      case BIP155Network.IPV4:
        return "ipv4";
      case BIP155Network.IPV6:
        return "ipv6";
      case BIP155Network.TORV3:
        return "onion";
      case BIP155Network.I2P:
        return "i2p";
      case BIP155Network.CJDNS:
        return "cjdns";
      default:
        return "not_publicly_routable";
    }
  }

  /**
   * Dump the addrman (known-address pool) for the `getnodeaddresses` RPC,
   * already shaped EXACTLY as Bitcoin Core emits each entry (rpc/net.cpp:
   * 959-965): five keys in this order — `time` (UNIX seconds, INTEGER),
   * `services` (raw bitfield, INTEGER), `address` (host literal, no port),
   * `port` (INTEGER), `network` (Core network NAME string).
   *
   * Mirrors Core's `CConnman::GetAddressesUnsafe(count, max_pct=0, network)`
   * (rpc/net.cpp:955): returns a SHUFFLED snapshot, optionally filtered to a
   * single network, then truncated to at most `count` entries (`count == 0`
   * → no cap / return all). The shuffle uses the same CSPRNG Fisher–Yates as
   * the rest of this manager, so order is intentionally non-deterministic
   * (callers / tests must match by content, never by index).
   *
   * `services` is returned as a `number` so the RPC layer emits a JSON
   * INTEGER (not a hex string, unlike `getpeerinfo`). The internal
   * `lastSeen` is stored in milliseconds; we convert to integer seconds.
   *
   * @param count   max entries to return; `0` means "all known".
   * @param network optional Core network NAME filter
   *                (`ipv4|ipv6|onion|i2p|cjdns`); when set, only addresses
   *                whose {@link networkIdToCoreName} equals it are returned.
   */
  dumpAddrmanForRpc(
    count: number,
    network?: string,
  ): Array<{
    time: number;
    services: number;
    address: string;
    port: number;
    network: string;
  }> {
    const selected: PeerInfo[] = [];
    for (const info of this.knownAddresses.values()) {
      if (
        network !== undefined &&
        PeerManager.networkIdToCoreName(info.networkId) !== network
      ) {
        continue;
      }
      selected.push(info);
    }

    // Shuffle (Fisher–Yates, CSPRNG) — Core returns a shuffled vector so the
    // order leaks nothing about addrman bucket layout.
    for (let i = selected.length - 1; i > 0; i--) {
      const j = this.secureRandInt(i + 1);
      [selected[i], selected[j]] = [selected[j], selected[i]];
    }

    const capped =
      count > 0 && selected.length > count
        ? selected.slice(0, count)
        : selected;

    return capped.map((info) => ({
      time: Math.floor(info.lastSeen / 1000),
      services: Number(info.services),
      address: info.host,
      port: info.port,
      network: PeerManager.networkIdToCoreName(info.networkId),
    }));
  }

  /**
   * Insert (or refresh) a single address into the addrman — the substrate for
   * the `addpeeraddress` test-only RPC (Core: rpc/net.cpp:972).
   *
   * Validation mirrors Core's path loosely: only routable IPv4 literals are
   * accepted here (the only network the legacy `knownAddresses` map keys by
   * `ip:port`). Non-routable / malformed inputs return `false` (Core returns
   * `{success:false}`); a valid insert returns `true`. An existing key is
   * refreshed in place (services + lastSeen) rather than duplicated.
   *
   * @param host     IPv4 literal.
   * @param port     TCP port.
   * @param services raw services bitfield.
   * @param timeSecs last-seen UNIX time in SECONDS (stored internally as ms,
   *                 matching the rest of {@link PeerInfo.lastSeen}).
   */
  injectKnownAddress(
    host: string,
    port: number,
    services: bigint,
    timeSecs: number,
  ): boolean {
    if (!isRoutable(host)) return false;
    if (!Number.isInteger(port) || port <= 0 || port > 0xffff) return false;

    const key = `${host}:${port}`;
    const lastSeenMs = timeSecs * 1000;
    const existing = this.knownAddresses.get(key);
    if (existing) {
      existing.services = services;
      if (lastSeenMs > existing.lastSeen) existing.lastSeen = lastSeenMs;
      return true;
    }
    this.addKnownAddress(key, {
      host,
      port,
      services,
      lastSeen: lastSeenMs,
      banScore: 0,
      lastConnected: 0,
      networkId: BIP155Network.IPV4,
    });
    return true;
  }

  /**
   * Periodic maintenance: evict bad peers, refill connections.
   */
  private async maintain(): Promise<void> {
    if (!this.running) return;

    // Last-resort fixed-seed fallback (60s-grace empty-book case). The DNS /
    // fallback bootstrap in start() ran first; if it produced nothing and the
    // book is still empty 60s in, fall through to the curated fixed seeds.
    // Falls THROUGH after DNS — never replaces it (Core net.cpp:2616-2643).
    this.maybeAddFixedSeeds();

    // Evict peers with high ban scores
    for (const [key, info] of this.knownAddresses) {
      if (info.banScore >= 100) {
        const peer = this.peers.get(key);
        if (peer) {
          this.disconnectPeer(key, true);
        }
      }
    }

    // Periodically ask connected peers for more addresses
    const connectedPeers = this.getConnectedPeers();
    if (connectedPeers.length > 0 && this.knownAddresses.size < 1000) {
      // Ask a random peer for addresses (CSPRNG — Core: FastRandomContext)
      const randomPeer = connectedPeers[this.secureRandInt(connectedPeers.length)];
      randomPeer.send({ type: "getaddr", payload: null });
    }

    // Fill connections up to maxOutbound
    await this.fillConnections();

    // Save addresses periodically
    await this.saveAddresses();
  }

  /**
   * Last-resort fixed-seed fallback (Core net.cpp:2607-2643,
   * ThreadOpenConnections fixed-seed trigger).
   *
   * Fires the one-shot curated fixed-seed injection ONLY when ALL hold:
   *  (1) ENABLED: fixed seeds are on (default; off under `-connect`) AND the
   *      per-network {@link FIXED_SEEDS} list is non-empty (mainnet only —
   *      empty for testnet/signet/regtest, matching Core clearing vFixedSeeds).
   *  (2) BOOK EMPTY: {@link knownAddresses} is empty — our impl-local proxy
   *      for Core's `!GetReachableEmptyNetworks().empty()` over this
   *      IPv4-only set (addrman has no addresses for a reachable network).
   *  (3) EITHER (a) >60s elapsed since {@link loopStartTs} (gives DNS /
   *      addnode / seednode time to populate the book first), OR (b) DNS
   *      seeding is disabled and there is no pinned source to wait for
   *      (Core's cheap `!dnsseed && !use_seednodes` shortcut at net.cpp:2620 —
   *      fire immediately).
   *
   * After firing, sets the one-shot guard ({@link fixedSeedsAdded}, Core's
   * `add_fixed_seeds = false`) so subsequent ticks are no-ops. Injected addrs
   * carry the "fixedseeds" internal source tag (Core CNetAddr::SetInternal)
   * and pass the normal routable / dedup / ban filter on add.
   *
   * This is a LAST-RESORT fallback layered AFTER the untouched normal DNS
   * bootstrap — it never replaces DNS, never bypasses it, and only adds
   * IPv4-routable curated entries.
   */
  private maybeAddFixedSeeds(): void {
    // One-shot guard (Core: add_fixed_seeds already false).
    if (this.fixedSeedsAdded) return;

    const seeds = FIXED_SEEDS[this.config.params.networkMagic] ?? [];

    // (1) ENABLED: fixed seeds present (mainnet only) and not in connect-only
    // mode. Core folds -connect into "fixed-seed path off".
    if (seeds.length === 0) return;
    if (this.isConnectOnly()) return;

    // (2) BOOK EMPTY: no known addresses for any reachable network.
    if (this.knownAddresses.size !== 0) return;

    // (3) Timing gate: either >60s since the loop start, OR DNS seeding is
    // disabled (nothing to wait for) ⇒ fire immediately. We have no
    // -addnode/-seednode source other than -connect (already excluded above),
    // so the DNS-off branch mirrors Core's `!dnsseed && !use_seednodes`.
    const graceElapsed = Date.now() - this.loopStartTs > 60_000;
    if (!graceElapsed && this.dnsSeed) return;

    // Mark the one-shot guard before adding so a re-entrant tick is a no-op.
    this.fixedSeedsAdded = true;

    const now = Date.now();
    const services = ServiceFlags.NODE_NETWORK | ServiceFlags.NODE_WITNESS;
    let added = 0;
    for (const { host, port } of seeds) {
      // Pass the normal routable + dedup + ban filter, exactly as a learned
      // address would (Core: addrman.Add drops non-routable; we also honor the
      // ban list so a banned fixed seed is not injected).
      if (!isRoutable(host)) continue;
      if (this.banManager.isBanned(host)) continue;
      const key = `${host}:${port}`;
      if (this.knownAddresses.has(key)) continue;
      this.addKnownAddress(key, {
        host,
        port,
        services,
        lastSeen: now,
        banScore: 0,
        lastConnected: 0,
        source: "fixedseeds",
      });
      added++;
    }

    console.log(
      `P2P: added ${added} fixed seed(s) as a last-resort fallback ` +
      `(DNS bootstrap produced no addresses${this.dnsSeed ? " within 60s" : "; -nodnsseed"})`
    );
  }

  /**
   * Check pings and send keepalives, disconnect timed-out peers.
   *
   * Called every PING_INTERVAL_MS (2 minutes).
   * Reference: Bitcoin Core net_processing.cpp MaybeSendPing()
   */
  private checkPings(): void {
    if (!this.running) return;

    const now = Date.now();

    for (const [key, peer] of this.peers) {
      if (peer.state !== "connected") continue;

      // Check for ping timeout (20 minutes without pong)
      if (peer.hasPingTimedOut()) {
        console.log(`Ping timeout: disconnecting peer ${key}`);
        this.disconnectPeer(key, false, "ping timeout");
        continue;
      }

      // Send ping if peer needs it (idle for PING_INTERVAL_MS)
      const lastActivity = this.lastActivity.get(key) ?? now;
      if (peer.needsPing(lastActivity)) {
        peer.sendPing();
      }
    }
  }

  /**
   * Check for stale tip and evict underperforming peers.
   *
   * Called every STALE_CHECK_INTERVAL_MS (45 seconds).
   * Reference: Bitcoin Core net_processing.cpp CheckForStaleTipAndEvictPeers()
   */
  private checkForStaleTipAndEvictPeers(): void {
    if (!this.running) return;

    const now = Date.now();

    // Check headers timeouts
    this.checkHeadersTimeouts();

    // Check block download timeouts
    this.checkBlockDownloadTimeouts();

    // Evict extra outbound peers
    this.evictExtraOutboundPeers(now);

    // Check for stale outbound peers
    this.evictStaleTipPeers(now);
  }

  /**
   * Check for peers with headers request timeouts.
   * Mark as misbehaving if no response within 2 minutes.
   */
  private checkHeadersTimeouts(): void {
    for (const [key, peer] of this.peers) {
      if (peer.state !== "connected") continue;

      if (peer.hasHeadersTimedOut()) {
        console.log(`Headers timeout: peer ${key} not responding`);
        peer.misbehaving(20, "headers timeout");
        peer.markHeadersReceived(); // Clear the timeout to avoid repeated scoring
      }
    }
  }

  /**
   * Check for peers with block download timeouts.
   * Disconnect if a block hasn't arrived within timeout.
   */
  private checkBlockDownloadTimeouts(): void {
    const peerCount = this.peers.size;

    for (const [key, peer] of this.peers) {
      if (peer.state !== "connected") continue;

      const timedOutBlock = peer.getTimedOutBlock(peerCount);
      if (timedOutBlock) {
        console.log(`Block download timeout: disconnecting peer ${key} (block ${timedOutBlock.slice(0, 16)}...)`);
        this.disconnectPeer(key, false, "block download timeout");
      }
    }
  }

  /**
   * Evict stale tip peers that are behind our chain.
   *
   * Only evicts one peer per check cycle to avoid mass disconnections.
   * Protects up to MAX_OUTBOUND_PEERS_TO_PROTECT peers.
   *
   * Reference: Bitcoin Core net_processing.cpp ConsiderEviction()
   */
  private evictStaleTipPeers(now: number): void {
    // Find outbound peers with stale tips
    const stalePeers: Array<{ key: string; peer: Peer }> = [];
    const ourBestHeight = this.config.bestHeight;

    // First, update protection status for peers with good chains
    this.updateProtectedPeers();

    for (const [key, peer] of this.peers) {
      if (peer.state !== "connected") continue;

      // Only consider outbound peers
      const connType = this.peerConnectionType.get(key);
      if (connType === "inbound") continue;

      // Skip protected peers
      if (this.protectedPeers.has(key)) continue;

      // Skip peers connected too recently
      if (now - peer.connectedTime < MINIMUM_CONNECT_TIME_MS) continue;

      // Skip peers with blocks in flight
      if (peer.hasBlocksInFlight()) continue;

      // Check if peer's best known height is behind ours by threshold
      const peerHeight = peer.bestKnownHeight;
      const heightDiff = ourBestHeight - peerHeight;

      // Never evict peers that are ahead of us — we need them for sync!
      if (peerHeight >= ourBestHeight) continue;

      // Check if peer's tip is stale (30 minutes worth of blocks behind)
      const timeSinceBlock = peer.lastBlockTime > 0 ? now - peer.lastBlockTime : Infinity;

      // Peer is stale if their best known height is significantly behind ours
      // AND they haven't given us a block recently
      if (heightDiff >= 3 && timeSinceBlock > STALE_TIP_THRESHOLD_MS) {
        stalePeers.push({ key, peer });
      }
    }

    // Only evict if we have better peers available
    const goodPeers = this.countPeersWithGoodChain();

    if (stalePeers.length > 0 && goodPeers > 0) {
      // Evict only one stale peer per cycle
      const { key, peer: stalePeer } = stalePeers[0];
      console.log(
        `Evicting stale outbound peer ${key} (height: ${stalePeer.bestKnownHeight}, ours: ${ourBestHeight})`
      );
      this.disconnectPeer(key, false, "stale tip");
    }
  }

  /**
   * Evict extra outbound peers when we have too many.
   *
   * Reference: Bitcoin Core net_processing.cpp EvictExtraOutboundPeers()
   */
  private evictExtraOutboundPeers(now: number): void {
    const maxFullRelay = this.config.maxOutboundFullRelay ?? MAX_OUTBOUND_FULL_RELAY;
    const maxBlockRelay = this.config.maxOutboundBlockRelay ?? MAX_OUTBOUND_BLOCK_RELAY;

    // Count current outbound connections by type
    let fullRelayCount = 0;
    let blockRelayCount = 0;
    const fullRelayPeers: Array<{ key: string; peer: Peer }> = [];
    const blockRelayPeers: Array<{ key: string; peer: Peer }> = [];

    for (const [key, connType] of this.peerConnectionType) {
      const peer = this.peers.get(key);
      if (!peer || peer.state !== "connected") continue;

      if (connType === "full_relay") {
        fullRelayCount++;
        fullRelayPeers.push({ key, peer });
      } else if (connType === "block_relay") {
        blockRelayCount++;
        blockRelayPeers.push({ key, peer });
      }
    }

    // Evict extra block-relay-only peers first
    if (blockRelayCount > maxBlockRelay) {
      // Find the youngest block-relay peer that hasn't given us a block recently
      const candidates = blockRelayPeers
        .filter((p) => now - p.peer.connectedTime >= MINIMUM_CONNECT_TIME_MS)
        .filter((p) => !p.peer.hasBlocksInFlight())
        .sort((a, b) => b.peer.connectedTime - a.peer.connectedTime); // Youngest first

      if (candidates.length > 0) {
        // Find peer with oldest block time
        let evictCandidate = candidates[0];
        for (const c of candidates) {
          if (c.peer.lastBlockTime < evictCandidate.peer.lastBlockTime) {
            evictCandidate = c;
          }
        }
        console.log(`Evicting extra block-relay peer ${evictCandidate.key}`);
        this.disconnectPeer(evictCandidate.key, false, "extra block-relay peer");
        return;
      }
    }

    // Evict extra full-relay peers
    if (fullRelayCount > maxFullRelay) {
      // Find the full-relay peer that least recently announced a block
      const candidates = fullRelayPeers
        .filter((p) => now - p.peer.connectedTime >= MINIMUM_CONNECT_TIME_MS)
        .filter((p) => !p.peer.hasBlocksInFlight())
        .filter((p) => !this.protectedPeers.has(p.key))
        .sort((a, b) => a.peer.lastBlockTime - b.peer.lastBlockTime); // Oldest block time first

      if (candidates.length > 0) {
        const evictCandidate = candidates[0];
        console.log(`Evicting extra full-relay peer ${evictCandidate.key}`);
        this.disconnectPeer(evictCandidate.key, false, "extra full-relay peer");
      }
    }
  }

  /**
   * Update the set of protected outbound peers.
   * Peers with good chain tips are protected from eviction.
   */
  private updateProtectedPeers(): void {
    const ourBestHeight = this.config.bestHeight;
    const candidates: Array<{ key: string; peer: Peer }> = [];

    for (const [key, peer] of this.peers) {
      if (peer.state !== "connected") continue;

      // Only protect outbound full-relay peers
      const connType = this.peerConnectionType.get(key);
      if (connType !== "full_relay") continue;

      // Peer has chain at least as good as ours
      if (peer.bestKnownHeight >= ourBestHeight) {
        candidates.push({ key, peer });
      }
    }

    // Clear and rebuild protected set
    this.protectedPeers.clear();

    // Sort by earliest connected time (reward long connections)
    candidates.sort((a, b) => a.peer.connectedTime - b.peer.connectedTime);

    // Protect up to MAX_OUTBOUND_PEERS_TO_PROTECT
    for (let i = 0; i < Math.min(candidates.length, MAX_OUTBOUND_PEERS_TO_PROTECT); i++) {
      this.protectedPeers.add(candidates[i].key);
    }
  }

  /**
   * Count outbound peers that have a chain at least as good as ours.
   */
  private countPeersWithGoodChain(): number {
    const ourBestHeight = this.config.bestHeight;
    let count = 0;

    for (const [key, peer] of this.peers) {
      if (peer.state !== "connected") continue;

      // Only count outbound peers
      const connType = this.peerConnectionType.get(key);
      if (connType === "inbound") continue;

      if (peer.bestKnownHeight >= ourBestHeight) {
        count++;
      }
    }

    return count;
  }

  /**
   * Notify manager that our tip was updated.
   * Call this when a new block is connected.
   */
  notifyTipUpdated(): void {
    this.lastTipUpdateTime = Date.now();
  }

  /**
   * Fill outbound connections up to maxOutbound.
   *
   * Connection priority:
   * 1. Anchor connections (block-relay-only peers from last session)
   * 2. Full-relay outbound connections (up to maxOutboundFullRelay)
   * 3. Block-relay-only outbound connections (up to maxOutboundBlockRelay)
   *
   * Enforces network group diversity: no two outbound peers share the same /16 (IPv4) or /32 (IPv6).
   */
  private async fillConnections(): Promise<void> {
    if (!this.running) return;

    // Connect-only mode (`-connect`): dial ONLY the pinned peers and never
    // touch anchors / addrman candidates / DNS-derived addresses. Mirrors
    // clearbit peer.zig:7050 (maintainOutbound gated on connect_address==null)
    // and Core net.cpp ThreadOpenConnections's connect.size() branch.
    // connectPeer() already no-ops when the peer is connected or connecting,
    // so this naturally (re)dials only dropped pins each maintenance tick.
    if (this.isConnectOnly()) {
      for (const { host, port } of this.connectPeers) {
        const key = `${host}:${port}`;
        if (this.peers.has(key) || this.connectingPeers.has(key)) continue;
        try {
          await this.connectPeer(host, port, "full_relay");
        } catch {
          // Pinned peer unreachable this tick; retry on the next maintenance
          // pass. We do NOT fall back to DNS / addrman peers.
        }
      }
      return;
    }

    // Count current outbound connections by type
    let fullRelayCount = 0;
    let blockRelayCount = 0;
    for (const [key, connType] of this.peerConnectionType) {
      if (connType === "full_relay") fullRelayCount++;
      else if (connType === "block_relay") blockRelayCount++;
    }

    // Also count pending connections (assume they're full-relay unless specified)
    const pendingCount = this.connectingPeers.size;

    const maxFullRelay = this.config.maxOutboundFullRelay ?? MAX_OUTBOUND_FULL_RELAY;
    const maxBlockRelay = this.config.maxOutboundBlockRelay ?? MAX_OUTBOUND_BLOCK_RELAY;

    // First priority: Connect to anchor peers if we have slots
    while (
      this.anchors.length > 0 &&
      blockRelayCount < maxBlockRelay
    ) {
      const anchor = this.anchors.shift()!;
      const key = `${anchor.host}:${anchor.port}`;

      // Skip if already connected
      if (this.peers.has(key) || this.connectingPeers.has(key)) {
        continue;
      }

      // Skip if banned
      if (this.banManager.isBanned(anchor.host)) {
        continue;
      }

      // Check network group diversity
      const netGroup = this.getNetGroupForAddr(anchor.host);
      if (this.outboundNetGroups.has(netGroup)) {
        continue;
      }

      try {
        await this.connectPeer(anchor.host, anchor.port, "block_relay");
        blockRelayCount++;
      } catch {
        // Anchor connection failed, continue to next
      }
    }

    // Second priority: Fill full-relay slots
    const neededFullRelay = maxFullRelay - fullRelayCount - pendingCount;
    if (neededFullRelay > 0) {
      const candidates = this.getCandidateAddresses(neededFullRelay * 3); // Get extra in case some fail diversity check
      let connected = 0;

      for (const info of candidates) {
        if (connected >= neededFullRelay) break;

        // BUG-5: resolve into a dialable string + network type.  Already
        // gated by getCandidateAddresses, but keep this explicit so future
        // refactors can't bypass the proxy dispatch.
        const dialable = this.resolveDialable(info);
        if (!dialable) continue;

        // Check network group diversity (use original host so legacy
        // /16 + ASN bucketing keep their semantics).
        const netGroup = this.getNetGroupForAddr(info.host);
        if (this.outboundNetGroups.has(netGroup)) {
          continue;
        }

        try {
          await this.connectPeer(
            dialable.host,
            info.port,
            "full_relay",
            dialable.networkType
          );
          connected++;
        } catch {
          // Connection failed, try next
        }
      }
    }

    // Third priority: Fill block-relay slots
    const neededBlockRelay = maxBlockRelay - blockRelayCount;
    if (neededBlockRelay > 0) {
      const candidates = this.getCandidateAddresses(neededBlockRelay * 3);
      let connected = 0;

      for (const info of candidates) {
        if (connected >= neededBlockRelay) break;

        const dialable = this.resolveDialable(info);
        if (!dialable) continue;

        // Check network group diversity
        const netGroup = this.getNetGroupForAddr(info.host);
        if (this.outboundNetGroups.has(netGroup)) {
          continue;
        }

        try {
          await this.connectPeer(
            dialable.host,
            info.port,
            "block_relay",
            dialable.networkType
          );
          connected++;
        } catch {
          // Connection failed, try next
        }
      }
    }
  }

  /**
   * Get candidate addresses for connection, sorted by preference.
   * Prefers peers with NODE_WITNESS, recently seen, low ban scores.
   *
   * BUG-5 (W117): filters out peers whose network is unreachable in the
   * current configuration so we never hand a hex-encoded TorV3 / I2P /
   * CJDNS string to `Bun.connect`.  Reachability is determined by:
   *
   *   - IPv4 / IPv6        — always reachable (clearnet or `--proxy`)
   *   - TorV3 (.onion)     — only when `--onion` or `--proxy` is set
   *                          (i.e. {@link proxyManager} non-null)
   *   - I2P (.b32.i2p)     — only when `--i2psam` is set
   *   - CJDNS (fc00::/8)   — only when `--cjdnsreachable`
   *   - unknown networkId  — never reachable (BIP-155 forward compat)
   *
   * Reference: Bitcoin Core net.cpp `CConnman::ConnectNode` /
   * `IsReachable(Network)`.
   */
  private getCandidateAddresses(limit: number): PeerInfo[] {
    const now = Date.now();
    const candidates: PeerInfo[] = [];

    for (const [key, info] of this.knownAddresses) {
      // Skip already connected or connecting
      if (this.peers.has(key) || this.connectingPeers.has(key)) {
        continue;
      }

      // Skip banned peers (check both local score and ban manager)
      if (info.banScore >= 100 || this.banManager.isBanned(info.host)) {
        continue;
      }

      // Skip recently failed connections (wait at least 5 minutes)
      if (info.lastConnected > 0 && now - info.lastConnected < 300_000) {
        const peer = this.peers.get(key);
        if (!peer) {
          // Recently tried but not connected - skip
          continue;
        }
      }

      // BUG-5: Network reachability filter.  Without it,
      // getCandidateAddresses would happily return TorV3 / I2P / CJDNS
      // entries whose `host` is a 32-char hex blob, and connectPeer would
      // then pass that string straight to Bun.connect → instant failure.
      if (this.resolveDialable(info) === null) {
        continue;
      }

      candidates.push(info);
    }

    // Sort by preference: NODE_WITNESS > recent lastSeen > low banScore
    candidates.sort((a, b) => {
      // Prefer NODE_WITNESS
      const aWitness = (a.services & ServiceFlags.NODE_WITNESS) !== 0n;
      const bWitness = (b.services & ServiceFlags.NODE_WITNESS) !== 0n;
      if (aWitness && !bWitness) return -1;
      if (!aWitness && bWitness) return 1;

      // Prefer NODE_NETWORK
      const aNetwork = (a.services & ServiceFlags.NODE_NETWORK) !== 0n;
      const bNetwork = (b.services & ServiceFlags.NODE_NETWORK) !== 0n;
      if (aNetwork && !bNetwork) return -1;
      if (!aNetwork && bNetwork) return 1;

      // Prefer lower ban score
      if (a.banScore !== b.banScore) {
        return a.banScore - b.banScore;
      }

      // Prefer more recently seen
      return b.lastSeen - a.lastSeen;
    });

    return candidates.slice(0, limit);
  }

  /**
   * Handle peer connection event.
   */
  private handlePeerConnect(_peer: Peer): void {
    // Connection established, waiting for handshake
  }

  /**
   * Handle peer disconnection.
   */
  private handlePeerDisconnect(peer: Peer, _error?: Error): void {
    const key = `${peer.host}:${peer.port}`;
    this.peers.delete(key);
    this.lastActivity.delete(key);

    // Clean up connection tracking
    const connType = this.peerConnectionType.get(key);
    this.peerConnectionType.delete(key);

    if (connType !== "inbound") {
      // FIX-51: use getNetGroupForAddr (ASN-aware when asmap loaded) so the
      // key matches what was inserted in connectPeer().  The old getNetGroup()
      // call returned an ipv4:/16 string even when the outboundNetGroups entry
      // was keyed as "asn:N", causing stale entries that permanently blocked
      // new connections to any peer in the same AS.
      const netGroup = this.getNetGroupForAddr(peer.host);
      this.outboundNetGroups.delete(netGroup);
    } else {
      this.inboundPeers.delete(key);
    }

    // Emit disconnect event to handlers
    const handlers = this.messageHandlers.get("__disconnect__") ?? [];
    for (const handler of handlers) {
      try {
        handler(peer, { type: "verack", payload: null }); // Dummy message
      } catch {
        // Handler error
      }
    }
  }

  /**
   * Handle handshake completion.
   */
  private handleHandshakeComplete(peer: Peer): void {
    const key = `${peer.host}:${peer.port}`;
    this.lastActivity.set(key, Date.now());

    // Update known address with peer's services
    const info = this.knownAddresses.get(key);
    if (info && peer.versionPayload) {
      info.services = peer.versionPayload.services;
      info.lastSeen = Date.now();
    }

    // Send initial feefilter if this isn't a block-relay-only peer
    // BIP133: peers supporting feefilter (>= 70013) receive our min fee rate
    const connType = this.peerConnectionType.get(key);
    if (connType !== "block_relay" && peer.versionPayload) {
      if (peer.versionPayload.version >= FEEFILTER_VERSION) {
        this.feeFilterManager.sendInitialFeeFilter(peer);
      }
    }

    // Emit connect event to handlers
    const handlers = this.messageHandlers.get("__connect__") ?? [];
    for (const handler of handlers) {
      try {
        handler(peer, { type: "verack", payload: null }); // Dummy message
      } catch {
        // Handler error
      }
    }
  }

  /**
   * Handle incoming message from a peer.
   */
  private handlePeerMessage(peer: Peer, msg: NetworkMessage): void {
    // Drop any messages that arrive after stop() began.  Buffered socket
    // data (a peer's pending headers/inv/etc.) can still flow through Bun's
    // parser briefly after we begin shutdown; without this gate those
    // messages would dispatch to handlers (e.g. headers → DB write) that
    // race against db.close() and surface as LEVEL_DATABASE_NOT_OPEN.
    // Approach A: stop dispatching as soon as the manager is shutting down.
    if (this.shuttingDown) {
      return;
    }

    const key = `${peer.host}:${peer.port}`;
    this.lastActivity.set(key, Date.now());

    // Respond to ping with pong (required by Bitcoin protocol)
    if (msg.type === "ping") {
      peer.send({ type: "pong", payload: { nonce: msg.payload.nonce } });
    }

    // Handle addr messages to learn new peers
    if (msg.type === "addr") {
      this.handleAddrMessage(peer, msg.payload);
      // BIP155: Relay to up to 2 random peers
      this.relayAddrToRandomPeers(peer, msg);
    } else if (msg.type === "addrv2") {
      this.handleAddrV2Message(peer, msg.payload);
      // BIP155: Relay addrv2 to up to 2 random peers
      this.relayAddrToRandomPeers(peer, msg);
    } else if (msg.type === "feefilter") {
      // BIP133: Handle received feefilter
      this.handleFeeFilterMessage(peer, msg.payload);
    }

    // Dispatch to registered handlers
    const handlers = this.messageHandlers.get(msg.type) ?? [];
    for (const handler of handlers) {
      try {
        handler(peer, msg);
      } catch (error) {
        console.error(`Handler error for ${msg.type}:`, error);
      }
    }
  }

  /**
   * Insert a freshly-learned address into {@link knownAddresses}, enforcing
   * the {@link KNOWN_ADDRESSES_MAX} cap. When the map is already at the cap we
   * evict the entry with the oldest `lastSeen` before inserting, so the working
   * set tracks the most-recently-advertised addresses (Core addrman bucket
   * eviction analogue). Callers must only pass NEW keys — existing entries are
   * updated in place by the addr handlers, so they never grow the map.
   *
   * Mirrors the {@link markV1Only} cap pattern (drop-on-overflow) already used
   * for `v1OnlyCache`.
   */
  private addKnownAddress(key: string, info: PeerInfo): void {
    if (this.knownAddresses.size >= KNOWN_ADDRESSES_MAX) {
      this.evictOldestKnownAddress();
    }
    this.knownAddresses.set(key, info);
  }

  /**
   * Evict the single known address with the oldest `lastSeen` timestamp.
   * Linear scan — only runs on the rare overflow path (once the addrman is
   * already saturated at {@link KNOWN_ADDRESSES_MAX}), so the cost is bounded
   * and amortised. No-op if the map is empty.
   */
  private evictOldestKnownAddress(): void {
    let oldestKey: string | undefined;
    let oldestSeen = Infinity;
    for (const [k, v] of this.knownAddresses) {
      if (v.lastSeen < oldestSeen) {
        oldestSeen = v.lastSeen;
        oldestKey = k;
      }
    }
    if (oldestKey !== undefined) {
      this.knownAddresses.delete(oldestKey);
    }
  }

  /**
   * Process addr message and add new addresses to known pool.
   */
  private handleAddrMessage(_peer: Peer, payload: AddrPayload): void {
    const now = Math.floor(Date.now() / 1000);

    for (const entry of payload.addrs) {
      // Skip addresses that are too old (more than 3 hours)
      if (now - entry.timestamp > 3 * 60 * 60) {
        continue;
      }

      const ip = bufferToIPv4(entry.addr.ip);
      if (!ip) continue; // Skip non-IPv4 addresses

      // Reject non-routable addresses (RFC1918, loopback, link-local, etc.)
      // Core: addrman.cpp AddSingle() `if (!addr.IsRoutable()) return false;`
      if (!isRoutable(ip)) continue;

      const key = `${ip}:${entry.addr.port}`;

      // Add or update address
      const existing = this.knownAddresses.get(key);
      if (existing) {
        // Update if more recent
        if (entry.timestamp > existing.lastSeen) {
          existing.lastSeen = entry.timestamp * 1000;
          existing.services = entry.addr.services;
        }
      } else {
        this.addKnownAddress(key, {
          host: ip,
          port: entry.addr.port,
          services: entry.addr.services,
          lastSeen: entry.timestamp * 1000,
          banScore: 0,
          lastConnected: 0,
          networkId: BIP155Network.IPV4,
        });
      }
    }
  }

  /**
   * Process addrv2 message (BIP155) and add new addresses to known pool.
   *
   * ADDRv2 supports Tor v3, I2P, CJDNS, and native IPv4/IPv6 addresses.
   * Reference: Bitcoin Core net_processing.cpp ProcessMessage() for "addrv2"
   */
  private handleAddrV2Message(_peer: Peer, payload: AddrV2Payload): void {
    const now = Math.floor(Date.now() / 1000);

    for (const entry of payload.addrs) {
      // Skip addresses that are too old (more than 3 hours)
      if (now - entry.timestamp > 3 * 60 * 60) {
        continue;
      }

      // Validate the address for known network types
      if (!isValidNetworkAddressV2(entry.addr)) {
        continue;
      }

      // Generate unique key for this address
      const key = this.getAddrV2Key(entry.addr);
      if (!key) continue;

      // Add or update address
      const existing = this.knownAddresses.get(key);
      if (existing) {
        // Update if more recent
        if (entry.timestamp > existing.lastSeen) {
          existing.lastSeen = entry.timestamp * 1000;
          existing.services = entry.addr.services;
        }
      } else {
        const peerInfo = this.addrV2ToPeerInfo(entry.addr, entry.timestamp);
        if (peerInfo) {
          this.addKnownAddress(key, peerInfo);
        }
      }
    }
  }

  /**
   * Generate a unique key for a NetworkAddressV2.
   */
  private getAddrV2Key(addr: NetworkAddressV2): string | null {
    switch (addr.networkId) {
      case BIP155Network.IPV4: {
        const ip = networkAddressV2ToIPv4String(addr);
        return ip ? `${ip}:${addr.port}` : null;
      }
      case BIP155Network.IPV6:
        // IPv6: use hex representation of address
        return `[${addr.addr.toString("hex")}]:${addr.port}`;
      case BIP155Network.TORV3:
        // TorV3: use hex of pubkey (32 bytes)
        return `torv3:${addr.addr.toString("hex")}:${addr.port}`;
      case BIP155Network.I2P:
        // I2P: use hex of hash (32 bytes)
        return `i2p:${addr.addr.toString("hex")}:${addr.port}`;
      case BIP155Network.CJDNS:
        // CJDNS: use hex of address (16 bytes)
        return `cjdns:${addr.addr.toString("hex")}:${addr.port}`;
      default:
        // Unknown network type - skip
        return null;
    }
  }

  /**
   * Convert a NetworkAddressV2 to PeerInfo.
   */
  private addrV2ToPeerInfo(
    addr: NetworkAddressV2,
    timestamp: number
  ): PeerInfo | null {
    switch (addr.networkId) {
      case BIP155Network.IPV4: {
        const ip = networkAddressV2ToIPv4String(addr);
        if (!ip) return null;
        return {
          host: ip,
          port: addr.port,
          services: addr.services,
          lastSeen: timestamp * 1000,
          banScore: 0,
          lastConnected: 0,
          networkId: BIP155Network.IPV4,
        };
      }
      case BIP155Network.IPV6:
        // For IPv6, store the hex representation as "host" for now
        return {
          host: addr.addr.toString("hex"),
          port: addr.port,
          services: addr.services,
          lastSeen: timestamp * 1000,
          banScore: 0,
          lastConnected: 0,
          networkId: BIP155Network.IPV6,
          rawAddr: Buffer.from(addr.addr),
        };
      case BIP155Network.TORV3:
        // Store TorV3 address (we can't connect yet, but we can relay)
        return {
          host: addr.addr.toString("hex"),
          port: addr.port,
          services: addr.services,
          lastSeen: timestamp * 1000,
          banScore: 0,
          lastConnected: 0,
          networkId: BIP155Network.TORV3,
          rawAddr: Buffer.from(addr.addr),
        };
      case BIP155Network.I2P:
        // Store I2P address
        return {
          host: addr.addr.toString("hex"),
          port: addr.port,
          services: addr.services,
          lastSeen: timestamp * 1000,
          banScore: 0,
          lastConnected: 0,
          networkId: BIP155Network.I2P,
          rawAddr: Buffer.from(addr.addr),
        };
      case BIP155Network.CJDNS:
        // Store CJDNS address
        return {
          host: addr.addr.toString("hex"),
          port: addr.port,
          services: addr.services,
          lastSeen: timestamp * 1000,
          banScore: 0,
          lastConnected: 0,
          networkId: BIP155Network.CJDNS,
          rawAddr: Buffer.from(addr.addr),
        };
      default:
        return null;
    }
  }

  /**
   * Convert PeerInfo to NetworkAddressV2 for sending in addrv2 messages.
   */
  peerInfoToAddrV2(info: PeerInfo): NetworkAddressV2 | null {
    const networkId = info.networkId ?? BIP155Network.IPV4;

    switch (networkId) {
      case BIP155Network.IPV4: {
        // Parse IPv4 from host string
        const parts = info.host.split(".");
        if (parts.length !== 4) return null;
        const addr = Buffer.alloc(4);
        for (let i = 0; i < 4; i++) {
          const octet = parseInt(parts[i], 10);
          if (isNaN(octet) || octet < 0 || octet > 255) return null;
          addr[i] = octet;
        }
        return {
          networkId: BIP155Network.IPV4,
          addr,
          port: info.port,
          services: info.services,
        };
      }
      case BIP155Network.IPV6:
      case BIP155Network.TORV3:
      case BIP155Network.I2P:
      case BIP155Network.CJDNS:
        // Use stored raw address
        if (!info.rawAddr) return null;
        return {
          networkId,
          addr: info.rawAddr,
          port: info.port,
          services: info.services,
        };
      default:
        return null;
    }
  }

  /**
   * Check if a PeerInfo can be sent in legacy addr messages.
   */
  isAddrV1CompatiblePeer(info: PeerInfo): boolean {
    const networkId = info.networkId ?? BIP155Network.IPV4;
    return networkId === BIP155Network.IPV4 || networkId === BIP155Network.IPV6;
  }

  /**
   * Load persisted addresses from disk.
   */
  private async loadAddresses(): Promise<void> {
    const path = `${this.config.datadir}/peers.dat`;
    try {
      const file = Bun.file(path);
      if (await file.exists()) {
        const data = await file.arrayBuffer();
        const buffer = Buffer.from(data);
        const addresses = deserializePeerAddresses(buffer);
        // A peers.dat written before the cap existed (or by an older build)
        // may hold more than KNOWN_ADDRESSES_MAX entries. Keep the newest by
        // lastSeen so a stale oversized file can't reload the map uncapped.
        addresses.sort((a, b) => b.lastSeen - a.lastSeen);
        for (const info of addresses) {
          if (this.knownAddresses.size >= KNOWN_ADDRESSES_MAX) break;
          const key = `${info.host}:${info.port}`;
          this.knownAddresses.set(key, info);
        }
      }
    } catch {
      // No saved addresses or read error
    }
  }

  /**
   * Save known addresses to disk.
   */
  private async saveAddresses(): Promise<void> {
    const path = `${this.config.datadir}/peers.dat`;
    try {
      let addresses = Array.from(this.knownAddresses.values());
      // Hard-cap what we persist so peers.dat can't grow monotonically across
      // restarts. The in-memory map is already capped at KNOWN_ADDRESSES_MAX,
      // so this is a belt-and-braces ceiling: keep the freshest by lastSeen.
      if (addresses.length > KNOWN_ADDRESSES_MAX) {
        addresses.sort((a, b) => b.lastSeen - a.lastSeen);
        addresses = addresses.slice(0, KNOWN_ADDRESSES_MAX);
      }
      const buffer = serializePeerAddresses(addresses);
      await Bun.write(path, buffer);
    } catch {
      // Write error
    }
  }

  /**
   * Load anchor connections from disk.
   *
   * Anchors are block-relay-only peers that we reconnect to on startup
   * to prevent eclipse attacks after restart.
   *
   * Reference: Bitcoin Core addrdb.cpp ReadAnchors()
   */
  private async loadAnchors(): Promise<void> {
    const path = `${this.config.datadir}/anchors.dat`;
    try {
      const file = Bun.file(path);
      if (await file.exists()) {
        const data = await file.arrayBuffer();
        const buffer = Buffer.from(data);
        const reader = new BufferReader(buffer);

        // Version byte
        const version = reader.readUInt8();
        if (version !== 1) {
          return;
        }

        // Anchor count
        const count = reader.readVarInt();
        for (let i = 0; i < count && i < MAX_BLOCK_RELAY_ONLY_ANCHORS; i++) {
          const host = reader.readVarString();
          const port = reader.readUInt16LE();
          this.anchors.push({ host, port });
        }

        // Delete anchors file after reading (Bitcoin Core behavior)
        // The file is recreated on clean shutdown
        try {
          const fs = await import("node:fs/promises");
          await fs.unlink(path);
        } catch {
          // Ignore unlink errors
        }
      }
    } catch {
      // No anchors file or read error
    }
  }

  /**
   * Save anchor connections to disk.
   *
   * Persists up to MAX_BLOCK_RELAY_ONLY_ANCHORS block-relay-only
   * outbound connections for reconnection on next startup.
   *
   * Reference: Bitcoin Core addrdb.cpp DumpAnchors()
   */
  private async saveAnchors(): Promise<void> {
    const path = `${this.config.datadir}/anchors.dat`;
    try {
      // Collect current block-relay-only connections
      const anchors: Array<{ host: string; port: number }> = [];
      for (const [key, connType] of this.peerConnectionType) {
        if (connType === "block_relay" && anchors.length < MAX_BLOCK_RELAY_ONLY_ANCHORS) {
          const peer = this.peers.get(key);
          if (peer && peer.state === "connected") {
            anchors.push({ host: peer.host, port: peer.port });
          }
        }
      }

      if (anchors.length === 0) {
        // No anchors to save
        return;
      }

      const writer = new BufferWriter();

      // Version byte
      writer.writeUInt8(1);

      // Anchor count
      writer.writeVarInt(anchors.length);

      for (const anchor of anchors) {
        writer.writeVarString(anchor.host);
        writer.writeUInt16LE(anchor.port);
      }

      await Bun.write(path, writer.toBuffer());
    } catch {
      // Write error
    }
  }

  /**
   * Start the TCP listener for inbound P2P connections using Bun.listen.
   */
  private startListener(port: number): void {
    try {
      const manager = this;
      this.tcpListener = Bun.listen<{ peer: Peer | null }>({
        hostname: "0.0.0.0",
        port,
        socket: {
          open(socket) {
            const host = socket.remoteAddress;
            // Check if banned
            if (manager.banManager.isBanned(host)) {
              socket.end();
              return;
            }
            // Check inbound capacity
            if (manager.inboundPeers.size >= manager.config.maxInbound) {
              const evicted = manager.selectPeerToEvict();
              if (!evicted) {
                socket.end();
                return;
              }
              manager.disconnectPeer(evicted);
            }

            // NODE_NETWORK_LIMITED is advertised UNCONDITIONALLY for this full
            // node — already part of `params.services` (0x409), same as the
            // outbound site.  No prune gate (Core init.cpp:863/1950).
            const inAdvertisedServices = manager.config.params.services;

            // Create a Peer for this inbound connection
            const peerConfig: PeerConfig = {
              host,
              port: 0, // remote ephemeral port; not meaningful for inbound
              magic: manager.config.params.networkMagic,
              protocolVersion: manager.config.params.protocolVersion,
              services: inAdvertisedServices,
              userAgent: manager.config.params.userAgent,
              bestHeight: manager.config.bestHeight,
              relay: true,
            };
            const events: PeerEvents = {
              onConnect: (peer) => manager.handlePeerConnect(peer),
              onDisconnect: (peer, error) => manager.handlePeerDisconnect(peer, error),
              onMessage: (peer, msg) => manager.handlePeerMessage(peer, msg),
              onHandshakeComplete: (peer) => manager.handleHandshakeComplete(peer),
            };
            const onBan: OnBanCallback = (peer, reason) => {
              manager.banManager.ban(peer.host, DEFAULT_BAN_TIME, reason);
            };

            const peer = new Peer(peerConfig, events, onBan);
            socket.data = { peer };
            const key = `${host}:${0}`;
            manager.peers.set(key, peer);
            manager.lastActivity.set(key, Date.now());
            manager.peerConnectionType.set(key, "inbound");
            manager.inboundPeers.add(key);

            // Accept the already-connected socket
            peer.acceptSocket(socket);
          },
          data(socket, data) {
            const peer = socket.data?.peer;
            if (peer) {
              peer.feedData(Buffer.from(data));
            }
          },
          close(socket) {
            // Peer.disconnect will be triggered by the socket close handler
            // that was set up in acceptSocket — but Bun.listen uses its own
            // close callback, so we need to notify the peer here.
            const peer = socket.data?.peer;
            if (peer && peer.state !== "disconnected") {
              peer.disconnect("remote closed");
            }
          },
          error(socket, err) {
            const peer = socket.data?.peer;
            if (peer && peer.state !== "disconnected") {
              peer.disconnect("socket error");
            }
          },
        },
      });
      console.log(`P2P listening on port ${port}`);
    } catch (err) {
      console.error(`Failed to start P2P listener on port ${port}:`, err);
    }
  }

  /**
   * Accept an inbound connection.
   *
   * When inbound slots are full, uses eviction algorithm to decide
   * whether to accept the new connection by evicting an existing one.
   *
   * @param host - Remote peer's IP address
   * @param port - Remote peer's port
   * @returns The accepted Peer, or null if rejected
   */
  async acceptInbound(host: string, port: number): Promise<Peer | null> {
    // Check if banned
    if (this.banManager.isBanned(host)) {
      return null;
    }

    // Check inbound capacity
    const inboundCount = this.inboundPeers.size;
    if (inboundCount >= this.config.maxInbound) {
      // Try to evict a peer
      const evicted = this.selectPeerToEvict();
      if (!evicted) {
        // Cannot evict anyone, reject connection
        return null;
      }

      // Disconnect the evicted peer
      this.disconnectPeer(evicted);
    }

    // Accept the connection
    return this.connectPeer(host, port, "inbound");
  }

  /**
   * Select a peer to evict when inbound slots are full.
   *
   * Implements Bitcoin Core's eviction algorithm which protects
   * peers across multiple categories to ensure diversity.
   *
   * Reference: Bitcoin Core node/eviction.cpp SelectNodeToEvict()
   */
  selectPeerToEvict(): string | null {
    // Build list of eviction candidates (inbound peers only)
    const candidates: EvictionCandidate[] = [];
    const now = Date.now();

    for (const key of this.inboundPeers) {
      const peer = this.peers.get(key);
      if (!peer) continue;

      const info = this.knownAddresses.get(key);
      const connType = this.peerConnectionType.get(key);

      candidates.push({
        id: key,
        connectedTime: info?.connectedTime ?? now,
        minPingTime: info?.minPingTime ?? (peer.latency || Infinity),
        lastBlockTime: info?.lastBlockTime ?? 0,
        lastTxTime: info?.lastTxTime ?? 0,
        keyedNetGroup: this.getNetGroupForAddr(peer.host),
        isBlockRelayOnly: connType === "block_relay",
        isLocal: isLocalAddress(peer.host),
      });
    }

    if (candidates.length === 0) {
      return null;
    }

    // Apply protection filters (each removes candidates from consideration)
    let remaining = [...candidates];

    // 1. Protect by distinct network groups (4 peers)
    remaining = this.protectByNetGroup(remaining, EVICTION_PROTECT_NETGROUP);

    // 2. Protect by lowest ping time (8 peers)
    remaining = this.protectByLowestPing(remaining, EVICTION_PROTECT_PING);

    // 3. Protect by recent transaction relay (4 peers)
    remaining = this.protectByRecentTx(remaining, EVICTION_PROTECT_TX);

    // 4. Protect block-relay-only peers (8 peers)
    remaining = this.protectBlockRelayOnly(remaining, EVICTION_PROTECT_BLOCK_RELAY);

    // 5. Protect by recent block relay (4 peers)
    remaining = this.protectByRecentBlocks(remaining, EVICTION_PROTECT_BLOCKS);

    // 6. Protect local/localhost connections
    remaining = remaining.filter((c) => !c.isLocal);

    if (remaining.length === 0) {
      return null;
    }

    // Select victim from remaining: pick from largest network group
    // (attacker most likely controls the largest group)
    const groupCounts = new Map<string, EvictionCandidate[]>();
    for (const c of remaining) {
      const group = groupCounts.get(c.keyedNetGroup) ?? [];
      group.push(c);
      groupCounts.set(c.keyedNetGroup, group);
    }

    // Find largest group
    let largestGroup: EvictionCandidate[] = [];
    let largestGroupAge = Infinity; // Tiebreaker: newest first

    for (const group of groupCounts.values()) {
      const newestInGroup = Math.max(...group.map((c) => c.connectedTime));

      if (
        group.length > largestGroup.length ||
        (group.length === largestGroup.length && newestInGroup > largestGroupAge)
      ) {
        largestGroup = group;
        largestGroupAge = newestInGroup;
      }
    }

    if (largestGroup.length === 0) {
      return null;
    }

    // Evict oldest peer in the largest group
    largestGroup.sort((a, b) => a.connectedTime - b.connectedTime);
    return largestGroup[0].id;
  }

  /**
   * Protect peers with distinct network groups.
   */
  private protectByNetGroup(
    candidates: EvictionCandidate[],
    count: number
  ): EvictionCandidate[] {
    // Group by netgroup, keep one from each distinct group
    const seenGroups = new Set<string>();
    const protected_: Set<string> = new Set();

    // Sort by connected time (oldest first - reward long connections)
    const sorted = [...candidates].sort(
      (a, b) => a.connectedTime - b.connectedTime
    );

    for (const c of sorted) {
      if (!seenGroups.has(c.keyedNetGroup) && protected_.size < count) {
        seenGroups.add(c.keyedNetGroup);
        protected_.add(c.id);
      }
    }

    return candidates.filter((c) => !protected_.has(c.id));
  }

  /**
   * Protect peers with lowest ping times.
   */
  private protectByLowestPing(
    candidates: EvictionCandidate[],
    count: number
  ): EvictionCandidate[] {
    const sorted = [...candidates].sort(
      (a, b) => a.minPingTime - b.minPingTime
    );
    const protected_ = new Set(sorted.slice(0, count).map((c) => c.id));
    return candidates.filter((c) => !protected_.has(c.id));
  }

  /**
   * Protect peers that recently relayed transactions.
   */
  private protectByRecentTx(
    candidates: EvictionCandidate[],
    count: number
  ): EvictionCandidate[] {
    // Filter to those that have relayed txs, sort by most recent
    const withTx = candidates
      .filter((c) => c.lastTxTime > 0)
      .sort((a, b) => b.lastTxTime - a.lastTxTime);
    const protected_ = new Set(withTx.slice(0, count).map((c) => c.id));
    return candidates.filter((c) => !protected_.has(c.id));
  }

  /**
   * Protect block-relay-only connections.
   */
  private protectBlockRelayOnly(
    candidates: EvictionCandidate[],
    count: number
  ): EvictionCandidate[] {
    // Protect block-relay peers that have relayed blocks
    const blockRelay = candidates
      .filter((c) => c.isBlockRelayOnly && c.lastBlockTime > 0)
      .sort((a, b) => b.lastBlockTime - a.lastBlockTime);
    const protected_ = new Set(blockRelay.slice(0, count).map((c) => c.id));
    return candidates.filter((c) => !protected_.has(c.id));
  }

  /**
   * Protect peers that recently relayed blocks.
   */
  private protectByRecentBlocks(
    candidates: EvictionCandidate[],
    count: number
  ): EvictionCandidate[] {
    const withBlocks = candidates
      .filter((c) => c.lastBlockTime > 0)
      .sort((a, b) => b.lastBlockTime - a.lastBlockTime);
    const protected_ = new Set(withBlocks.slice(0, count).map((c) => c.id));
    return candidates.filter((c) => !protected_.has(c.id));
  }

  /**
   * Update peer's last block time (called when peer sends us a block).
   */
  recordBlockFromPeer(key: string): void {
    const info = this.knownAddresses.get(key);
    if (info) {
      info.lastBlockTime = Date.now();
    }
  }

  /**
   * Update peer's last tx time (called when peer sends us a transaction).
   */
  recordTxFromPeer(key: string): void {
    const info = this.knownAddresses.get(key);
    if (info) {
      info.lastTxTime = Date.now();
    }
  }

  /**
   * Update peer's minimum ping time.
   */
  recordPingFromPeer(key: string, latency: number): void {
    const info = this.knownAddresses.get(key);
    if (info) {
      if (!info.minPingTime || latency < info.minPingTime) {
        info.minPingTime = latency;
      }
    }
  }

  /**
   * Get the connection type for a peer.
   */
  getConnectionType(key: string): ConnectionType | undefined {
    return this.peerConnectionType.get(key);
  }

  /**
   * Get the set of network groups used by outbound peers.
   */
  getOutboundNetGroups(): Set<string> {
    return new Set(this.outboundNetGroups);
  }

  /**
   * Get the current anchor connection addresses.
   */
  getAnchors(): Array<{ host: string; port: number }> {
    return [...this.anchors];
  }

  /**
   * Get count of inbound peers.
   */
  getInboundCount(): number {
    return this.inboundPeers.size;
  }

  /**
   * Get count of full-relay outbound peers.
   */
  getFullRelayCount(): number {
    let count = 0;
    for (const connType of this.peerConnectionType.values()) {
      if (connType === "full_relay") count++;
    }
    return count;
  }

  /**
   * Get count of block-relay-only outbound peers.
   */
  getBlockRelayCount(): number {
    let count = 0;
    for (const connType of this.peerConnectionType.values()) {
      if (connType === "block_relay") count++;
    }
    return count;
  }

  // ============================================================================
  // BIP133 FeeFilter
  // ============================================================================

  /**
   * Handle received feefilter message from a peer.
   * Reference: Bitcoin Core net_processing.cpp ProcessMessage() for "feefilter"
   */
  private handleFeeFilterMessage(peer: Peer, payload: FeeFilterPayload): void {
    this.feeFilterManager.handleFeeFilter(peer, payload.feeRate);
  }

  /**
   * Relay an addr or addrv2 message to up to 2 random connected peers,
   * excluding the source peer. Implements Bitcoin Core's RelayAddress behavior.
   */
  private relayAddrToRandomPeers(source: Peer, msg: any): void {
    const candidates: Peer[] = [];
    for (const [_key, p] of this.peers) {
      if (p !== source && p.state === "connected") {
        candidates.push(p);
      }
    }
    if (candidates.length === 0) return;

    // Shuffle and pick up to 2 (CSPRNG — Core: FastRandomContext)
    for (let i = candidates.length - 1; i > 0; i--) {
      const j = this.secureRandInt(i + 1);
      [candidates[i], candidates[j]] = [candidates[j], candidates[i]];
    }
    const targets = candidates.slice(0, Math.min(2, candidates.length));
    for (const target of targets) {
      try {
        target.send(msg);
      } catch (_e) {
        // Ignore send errors during relay
      }
    }
  }

  /**
   * Update the minimum fee rate for feefilter broadcasts.
   * Called when mempool minimum fee changes.
   * @param feeRate - Fee rate in sat/kvB (NOT sat/vB)
   */
  setMinFeeRate(feeRate: bigint): void {
    this.feeFilterManager.setMinFeeRate(feeRate);
  }

  /**
   * Set whether we're in initial block download.
   * During IBD, we send MAX_MONEY as feefilter to suppress tx relay.
   */
  setInIBD(inIBD: boolean): void {
    this.feeFilterManager.setInIBD(inIBD);
  }

  /**
   * Check if a transaction's fee rate meets a peer's feefilter threshold.
   * @param peer - The peer to check against
   * @param txFeeRate - Transaction fee rate in sat/vB
   * @returns true if the transaction should be relayed to this peer
   */
  passesFeeFilter(peer: Peer, txFeeRate: number): boolean {
    return meetsFeeFilter(txFeeRate, peer.feeFilterReceived);
  }

  /**
   * Get the fee filter manager (for testing).
   */
  getFeeFilterManager(): FeeFilterManager {
    return this.feeFilterManager;
  }
}

/**
 * Convert an IPv4-mapped IPv6 buffer to IPv4 string.
 * Returns null for non-IPv4 addresses.
 */
function bufferToIPv4(buf: Buffer): string | null {
  if (buf.length !== 16) return null;

  // Check for IPv4-mapped IPv6 prefix: ::ffff:
  const isIPv4Mapped =
    buf[0] === 0 && buf[1] === 0 &&
    buf[2] === 0 && buf[3] === 0 &&
    buf[4] === 0 && buf[5] === 0 &&
    buf[6] === 0 && buf[7] === 0 &&
    buf[8] === 0 && buf[9] === 0 &&
    buf[10] === 0xff && buf[11] === 0xff;

  if (!isIPv4Mapped) return null;

  return `${buf[12]}.${buf[13]}.${buf[14]}.${buf[15]}`;
}

/**
 * Serialize peer addresses for persistence.
 */
function serializePeerAddresses(addresses: PeerInfo[]): Buffer {
  const writer = new BufferWriter();

  // Version byte
  writer.writeUInt8(1);

  // Address count
  writer.writeVarInt(addresses.length);

  for (const info of addresses) {
    // Host as variable-length string
    writer.writeVarString(info.host);
    // Port
    writer.writeUInt16LE(info.port);
    // Services
    writer.writeUInt64LE(info.services);
    // Last seen
    writer.writeUInt64LE(BigInt(info.lastSeen));
    // Ban score
    writer.writeUInt32LE(info.banScore);
    // Last connected
    writer.writeUInt64LE(BigInt(info.lastConnected));
  }

  return writer.toBuffer();
}

/**
 * Deserialize peer addresses from persistence.
 */
function deserializePeerAddresses(data: Buffer): PeerInfo[] {
  const reader = new BufferReader(data);
  const addresses: PeerInfo[] = [];

  // Version byte
  const version = reader.readUInt8();
  if (version !== 1) {
    throw new Error(`Unsupported peer data version: ${version}`);
  }

  // Address count
  const count = reader.readVarInt();

  for (let i = 0; i < count; i++) {
    const host = reader.readVarString();
    const port = reader.readUInt16LE();
    const services = reader.readUInt64LE();
    const lastSeen = Number(reader.readUInt64LE());
    const banScore = reader.readUInt32LE();
    const lastConnected = Number(reader.readUInt64LE());

    addresses.push({
      host,
      port,
      services,
      lastSeen,
      banScore,
      lastConnected,
    });
  }

  return addresses;
}
