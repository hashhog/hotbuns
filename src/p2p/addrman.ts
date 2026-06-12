/**
 * addrman.ts — full Bitcoin Core CAddrMan NEW/TRIED bucketed address manager.
 *
 * Northstar axis #2 (persistent bucketed addrman). hotbuns previously stored
 * heard-about addresses in a flat `Map<string, PeerInfo>` keyed by `host:port`
 * (manager.ts `knownAddresses`) with a deterministic-sort candidate selection
 * and a bounded peers.dat — but no real buckets, no per-manager salt, and no
 * new-vs-tried split. The W128 characterization suite documents the gap
 * (BUG-1..BUG-13: "no bucket structure / no AddrInfo lifecycle").
 *
 * This module adds the Core data structure as a standalone, in-memory manager
 * layered ON TOP of the existing peers.dat persistence and the 81920 cap:
 *   NEW[1024][64] + TRIED[256][64] id-tables + mapInfo/mapAddr + a 256-bit nKey
 *   salt, with Core-exact deterministic placement, Add (new-bucket placement +
 *   IsTerrible/refcount collision), Good (promote new->tried, tried-collision
 *   evicts the occupant back to its new bucket), Select (50/50 new/tried bias),
 *   and a versioned, corrupt-safe, bounded peers.dat round-trip that preserves
 *   placement across restart by re-bucketing from the persisted nKey.
 *
 * Mirrors blockbrew internal/p2p/addrman_core.go (6c5a463) and rustoshi
 * crates/network/src/peer_manager.rs (361d81b) — the proven flat-map fan-out
 * pilots. The existing manager.ts `knownAddresses` / serializePeerAddresses
 * path and the public addr API (relay / getnodeaddresses / connect) are left
 * untouched; this manager can be driven alongside or used to back them.
 *
 * Reference: bitcoin-core/src/addrman.cpp + addrman_impl.h
 *   GetTriedBucket    = H(nKey, GetKey()) then H(nKey, group(addr), h1%8) % 256
 *   GetNewBucket      = H(nKey, group(addr), group(src)) then
 *                       H(nKey, group(src), h1%64) % 1024
 *   GetBucketPosition = H(nKey, 'N'|'K', bucket, GetKey()) % 64
 * Like rustoshi/blockbrew, Core's HashWriter::GetCheapHash (SipHash over a
 * serialised stream) is replaced with a single SHA-256 cheap-hash of the
 * concatenated parts (low 8 bytes, little-endian). hotbuns is a from-scratch
 * impl; the placement only needs to be deterministic and Core-shaped (the
 * 1024/256/64/64/8 geometry + group-keyed, salted, anti-Sybil bucketing), not
 * a wire-level match of Core's on-disk peers.dat.
 */

import { createHash, randomBytes } from "node:crypto";

import { getNetGroup } from "./manager.js";

// ---------------------------------------------------------------------------
// Core ADDRMAN_ geometry constants (addrman_impl.h / addrman.h).
// ---------------------------------------------------------------------------

/** ADDRMAN_NEW_BUCKET_COUNT = 1 << 10. */
export const ADDRMAN_NEW_BUCKET_COUNT = 1024;
/** ADDRMAN_TRIED_BUCKET_COUNT = 1 << 8. */
export const ADDRMAN_TRIED_BUCKET_COUNT = 256;
/** ADDRMAN_BUCKET_SIZE = 1 << 6. Positions per bucket. */
export const ADDRMAN_BUCKET_SIZE = 64;
/** A single source group reaches only this many new buckets (anti-Sybil). */
export const ADDRMAN_NEW_BUCKETS_PER_SOURCE_GROUP = 64;
/** A single group reaches only this many tried buckets (anti-Sybil). */
export const ADDRMAN_TRIED_BUCKETS_PER_GROUP = 8;
/** Max multiplicity of one address in the new table. */
export const ADDRMAN_NEW_BUCKETS_PER_ADDRESS = 8;
/** ADDRMAN_HORIZON (30 days, seconds): older entries are terrible. */
export const ADDRMAN_HORIZON_SECS = 30 * 24 * 60 * 60;
/** ADDRMAN_RETRIES — never-succeeded entry is terrible past this many tries. */
export const ADDRMAN_RETRIES = 3;
/** ADDRMAN_MAX_FAILURES — successive-failure terrible gate. */
export const ADDRMAN_MAX_FAILURES = 10;
/** ADDRMAN_MIN_FAIL (7 days, seconds). */
export const ADDRMAN_MIN_FAIL_SECS = 7 * 24 * 60 * 60;

/**
 * Total bounded slot ceiling: 1024*64 + 256*64 = 81920. Matches the existing
 * KNOWN_ADDRESSES_MAX cap in manager.ts (manager.ts:69).
 */
export const ADDRMAN_CEILING =
  ADDRMAN_NEW_BUCKET_COUNT * ADDRMAN_BUCKET_SIZE +
  ADDRMAN_TRIED_BUCKET_COUNT * ADDRMAN_BUCKET_SIZE;

/** peers.dat (bucketed) format version. */
export const ADDRMAN_DAT_VERSION = 1;
/** Magic header tag for the bucketed serialization. */
export const ADDRMAN_DAT_MAGIC = "ADDRMANV2";

/** Internal entry id (Core nid_type). -1 means "empty slot". */
const EMPTY = -1;

/**
 * AddrInfo (Core): a stored address plus connection bookkeeping.
 */
export interface AddrInfo {
  /** Network address host string (IPv4 dotted / IPv6 / Tor / I2P / CJDNS). */
  host: string;
  /** Port. */
  port: number;
  /** Service flags (NODE_*). */
  services: bigint;
  /** Source host that advertised this address (for group(src)). */
  source: string;
  /** nTime — last advertised (unix seconds). */
  nTime: number;
  /** m_last_success (unix seconds; 0 = never). */
  lastSuccess: number;
  /** m_last_try (unix seconds; 0 = never). */
  lastTry: number;
  /** nAttempts. */
  attempts: number;
  /** nRefCount — number of new buckets referencing this entry. */
  refCount: number;
  /** fInTried. */
  inTried: boolean;
  /**
   * Raw address bytes for non-IPv4/IPv6 networks (Tor/I2P/CJDNS). When set, it
   * is used in place of the parsed IP for the GetKey() bucket-hash input.
   */
  rawAddr?: Buffer;
}

/** Position of an address in the manager (Core AddressPosition). */
export interface AddressPosition {
  tried: boolean;
  multiplicity: number;
  bucket: number;
  position: number;
}

// ---------------------------------------------------------------------------
// Hashing primitives (Core HashWriter::GetCheapHash analogue).
// ---------------------------------------------------------------------------

/**
 * cheapHash — single SHA-256 of the concatenated parts, low 8 bytes
 * interpreted little-endian (Core GetCheapHash analogue, matching the rustoshi
 * / blockbrew pilots). Returns a BigInt so we keep all 64 bits.
 */
export function cheapHash(...parts: Buffer[]): bigint {
  const h = createHash("sha256");
  for (const p of parts) h.update(p);
  const sum = h.digest();
  return sum.readBigUInt64LE(0);
}

/** Encode a non-negative integer little-endian into 8 bytes. */
function le8(v: bigint): Buffer {
  const b = Buffer.alloc(8);
  b.writeBigUInt64LE(v & 0xffffffffffffffffn, 0);
  return b;
}

/** Encode a uint32 little-endian into 4 bytes (bucket-index feed). */
function le4(v: number): Buffer {
  const b = Buffer.alloc(4);
  b.writeUInt32LE(v >>> 0, 0);
  return b;
}

/**
 * Map an IPv4/IPv6 host string to its 16-byte representation (Core
 * CNetAddr 16-byte form). IPv4 -> ::ffff:a.b.c.d mapped. Returns null when the
 * host is not a parseable IP (Tor/I2P/CJDNS use rawAddr instead).
 */
export function hostTo16(host: string): Buffer | null {
  // IPv4 dotted-decimal
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
    const octets = host.split(".").map((o) => parseInt(o, 10));
    if (octets.some((o) => o < 0 || o > 255)) return null;
    const b = Buffer.alloc(16);
    // ::ffff:a.b.c.d
    b[10] = 0xff;
    b[11] = 0xff;
    b[12] = octets[0]!;
    b[13] = octets[1]!;
    b[14] = octets[2]!;
    b[15] = octets[3]!;
    return b;
  }
  // IPv6 (possibly bracketed)
  let h = host;
  if (h.startsWith("[") && h.endsWith("]")) h = h.slice(1, -1);
  if (!h.includes(":")) return null;
  // strip zone id
  const pct = h.indexOf("%");
  if (pct !== -1) h = h.slice(0, pct);
  // Expand :: notation.
  const dc = h.indexOf("::");
  let groups: string[];
  if (dc !== -1) {
    const left = h.slice(0, dc).split(":").filter((s) => s !== "");
    const right = h.slice(dc + 2).split(":").filter((s) => s !== "");
    const missing = 8 - left.length - right.length;
    if (missing < 0) return null;
    groups = [...left, ...Array(missing).fill("0"), ...right];
  } else {
    groups = h.split(":");
  }
  if (groups.length !== 8) return null;
  const b = Buffer.alloc(16);
  for (let i = 0; i < 8; i++) {
    const g = groups[i]!;
    if (!/^[0-9a-fA-F]{1,4}$/.test(g)) return null;
    const v = parseInt(g, 16);
    b[i * 2] = (v >> 8) & 0xff;
    b[i * 2 + 1] = v & 0xff;
  }
  return b;
}

/**
 * addrKey — Core CService::GetKey analogue: 16-byte network address + 2-byte
 * big-endian port. For Tor/I2P/CJDNS we use the rawAddr bytes (left-padded /
 * truncated to 16 only for the IP path; raw networks use their own bytes which
 * are already unique). Non-parseable hosts fall back to a hash of the host
 * string so the key is always deterministic.
 */
export function addrKey(info: { host: string; port: number; rawAddr?: Buffer }): Buffer {
  let addrBytes: Buffer;
  if (info.rawAddr && info.rawAddr.length > 0) {
    addrBytes = info.rawAddr;
  } else {
    const ip16 = hostTo16(info.host);
    if (ip16) {
      addrBytes = ip16;
    } else {
      // Non-IP, non-raw host (e.g. a hostname) — derive a stable 16-byte key.
      addrBytes = createHash("sha256").update(info.host).digest().subarray(0, 16);
    }
  }
  const port = Buffer.alloc(2);
  port.writeUInt16BE(info.port & 0xffff, 0);
  return Buffer.concat([addrBytes, port]);
}

// ---------------------------------------------------------------------------
// IsTerrible (Core AddrInfo::IsTerrible, addrman.cpp:49).
// ---------------------------------------------------------------------------

/** isTerrible mirrors Core AddrInfo::IsTerrible. now is unix seconds. */
export function isTerrible(e: AddrInfo, now: number): boolean {
  if (now - e.lastTry <= 60) return false; // tried in the last minute
  if (e.nTime > now + 10 * 60) return true; // came in a flying DeLorean
  if (now - e.nTime > ADDRMAN_HORIZON_SECS) return true; // not seen recently
  if (e.lastSuccess === 0 && e.attempts >= ADDRMAN_RETRIES) return true;
  if (now - e.lastSuccess > ADDRMAN_MIN_FAIL_SECS && e.attempts >= ADDRMAN_MAX_FAILURES) {
    return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
// AddrMan — the full Core CAddrMan: NEW/TRIED id-tables + maps + salt.
// ---------------------------------------------------------------------------

/** A simple xorshift128+-ish deterministic RNG (test reproducibility). */
class Rng {
  private s: bigint;
  constructor(seed: bigint) {
    this.s = seed === 0n ? 0x9e3779b97f4a7c15n : seed;
  }
  /** next() in [0, 2^32). */
  next(): number {
    // splitmix64 step
    this.s = (this.s + 0x9e3779b97f4a7c15n) & 0xffffffffffffffffn;
    let z = this.s;
    z = ((z ^ (z >> 30n)) * 0xbf58476d1ce4e5b9n) & 0xffffffffffffffffn;
    z = ((z ^ (z >> 27n)) * 0x94d049bb133111ebn) & 0xffffffffffffffffn;
    z = z ^ (z >> 31n);
    return Number(z & 0xffffffffn);
  }
  /** randrange(n) in [0, n). */
  range(n: number): number {
    if (n <= 1) return 0;
    return this.next() % n;
  }
}

export class AddrMan {
  /** per-manager 256-bit salt (Core nKey). */
  private nKey: Buffer;
  /** vvNew[bucket][pos] = id | -1. */
  private vvNew: Int32Array[];
  /** vvTried[bucket][pos] = id | -1. */
  private vvTried: Int32Array[];
  /** id -> AddrInfo. */
  private mapInfo = new Map<number, AddrInfo>();
  /** "host:port" -> id. */
  private mapAddr = new Map<string, number>();
  /** next id to allocate. */
  private idCount = 0;
  /** ids referenced in the new table. */
  private nNew = 0;
  /** ids in the tried table. */
  private nTried = 0;
  /** optional asmap-aware group resolver (injected from the manager). */
  private groupFn: (host: string) => string;
  private rng: Rng;

  constructor(opts?: {
    nKey?: Buffer;
    /** Inject the manager's asmap-aware group resolver; falls back to /16. */
    groupFn?: (host: string) => string;
    /** Deterministic RNG seed (tests). */
    rngSeed?: bigint;
  }) {
    this.nKey = opts?.nKey ?? randomBytes(32);
    if (this.nKey.length !== 32) {
      throw new Error("addrman nKey must be 32 bytes");
    }
    this.groupFn = opts?.groupFn ?? getNetGroup;
    this.rng = new Rng(opts?.rngSeed ?? this.nKey.readBigUInt64LE(0));
    this.vvNew = AddrMan.allocTable(ADDRMAN_NEW_BUCKET_COUNT);
    this.vvTried = AddrMan.allocTable(ADDRMAN_TRIED_BUCKET_COUNT);
  }

  private static allocTable(buckets: number): Int32Array[] {
    const t: Int32Array[] = new Array(buckets);
    for (let b = 0; b < buckets; b++) {
      const row = new Int32Array(ADDRMAN_BUCKET_SIZE);
      row.fill(EMPTY);
      t[b] = row;
    }
    return t;
  }

  /** Get the manager salt (test / persistence helper). */
  getNKey(): Buffer {
    return Buffer.from(this.nKey);
  }

  /** group(host) — bytes of the network group string (asmap-aware). */
  private group(host: string): Buffer {
    return Buffer.from(this.groupFn(host), "utf8");
  }

  // --- Core placement functions -------------------------------------------

  /** Core AddrInfo::GetNewBucket. */
  getNewBucket(addrGroup: Buffer, srcGroup: Buffer): number {
    const hash1 = cheapHash(this.nKey, addrGroup, srcGroup);
    const hash2 = cheapHash(
      this.nKey,
      srcGroup,
      le8(hash1 % BigInt(ADDRMAN_NEW_BUCKETS_PER_SOURCE_GROUP)),
    );
    return Number(hash2 % BigInt(ADDRMAN_NEW_BUCKET_COUNT));
  }

  /** Core AddrInfo::GetTriedBucket. */
  getTriedBucket(info: { host: string; port: number; rawAddr?: Buffer }, addrGroup: Buffer): number {
    const hash1 = cheapHash(this.nKey, addrKey(info));
    const hash2 = cheapHash(
      this.nKey,
      addrGroup,
      le8(hash1 % BigInt(ADDRMAN_TRIED_BUCKETS_PER_GROUP)),
    );
    return Number(hash2 % BigInt(ADDRMAN_TRIED_BUCKET_COUNT));
  }

  /** Core AddrInfo::GetBucketPosition. */
  getBucketPosition(fNew: boolean, bucket: number, info: { host: string; port: number; rawAddr?: Buffer }): number {
    const tag = Buffer.from([fNew ? 0x4e /* 'N' */ : 0x4b /* 'K' */]);
    const hash1 = cheapHash(this.nKey, tag, le4(bucket), addrKey(info));
    return Number(hash1 % BigInt(ADDRMAN_BUCKET_SIZE));
  }

  private groupsOf(info: AddrInfo): { addrGroup: Buffer; srcGroup: Buffer } {
    return { addrGroup: this.group(info.host), srcGroup: this.group(info.source) };
  }

  // --- Internal map helpers (Core Find / Create / Delete / ClearNew) -------

  private static mkKey(host: string, port: number): string {
    return `${host}:${port}`;
  }

  private find(host: string, port: number): number {
    const id = this.mapAddr.get(AddrMan.mkKey(host, port));
    return id === undefined ? EMPTY : id;
  }

  private create(
    host: string,
    port: number,
    source: string,
    services: bigint,
    nTime: number,
    rawAddr?: Buffer,
  ): number {
    const id = this.idCount++;
    const info: AddrInfo = {
      host,
      port,
      services,
      source,
      nTime,
      lastSuccess: 0,
      lastTry: 0,
      attempts: 0,
      refCount: 0,
      inTried: false,
      rawAddr,
    };
    this.mapInfo.set(id, info);
    this.mapAddr.set(AddrMan.mkKey(host, port), id);
    return id;
  }

  /** Core Delete: drop a refcount-0, non-tried id entirely. */
  private deleteIfFloating(id: number): void {
    const info = this.mapInfo.get(id);
    if (info && info.refCount === 0 && !info.inTried) {
      this.mapAddr.delete(AddrMan.mkKey(info.host, info.port));
      this.mapInfo.delete(id);
    }
  }

  /** Core ClearNew: clear a new-table slot, decrementing the occupant. */
  private clearNew(bucket: number, pos: number): void {
    const id = this.vvNew[bucket]![pos]!;
    if (id === EMPTY) return;
    this.vvNew[bucket]![pos] = EMPTY;
    const info = this.mapInfo.get(id);
    if (!info) return;
    if (info.refCount > 0) info.refCount--;
    if (info.refCount === 0) {
      if (this.nNew > 0) this.nNew--;
      this.deleteIfFloating(id);
    }
  }

  // --- Public counts / probes ----------------------------------------------

  /** Number of unique addresses referenced in the new table. */
  newCount(): number {
    return this.nNew;
  }
  /** Number of addresses in the tried table. */
  triedCount(): number {
    return this.nTried;
  }
  /** Number of distinct ids tracked (bounded by ceiling). */
  size(): number {
    return this.mapInfo.size;
  }
  /** Whether addr is in the tried table. */
  isInTried(host: string, port: number): boolean {
    const id = this.find(host, port);
    if (id === EMPTY) return false;
    return this.mapInfo.get(id)?.inTried ?? false;
  }

  /** Find the (bucket, pos) addr occupies in NEW, or null. */
  newSlotOf(host: string, port: number): { bucket: number; position: number } | null {
    const id = this.find(host, port);
    if (id === EMPTY) return null;
    const info = this.mapInfo.get(id)!;
    if (info.inTried) return null;
    const { addrGroup, srcGroup } = this.groupsOf(info);
    const start = this.getNewBucket(addrGroup, srcGroup);
    for (let n = 0; n < ADDRMAN_NEW_BUCKET_COUNT; n++) {
      const b = (start + n) % ADDRMAN_NEW_BUCKET_COUNT;
      const p = this.getBucketPosition(true, b, info);
      if (this.vvNew[b]![p] === id) return { bucket: b, position: p };
    }
    return null;
  }

  /** Find the (bucket, pos) addr occupies in TRIED, or null. */
  triedSlotOf(host: string, port: number): { bucket: number; position: number } | null {
    const id = this.find(host, port);
    if (id === EMPTY) return null;
    const info = this.mapInfo.get(id)!;
    if (!info.inTried) return null;
    const { addrGroup } = this.groupsOf(info);
    const kb = this.getTriedBucket(info, addrGroup);
    const kp = this.getBucketPosition(false, kb, info);
    return { bucket: kb, position: kp };
  }

  /**
   * Test-only: full position info for an address (Core FindAddressEntry).
   */
  findAddressEntry(host: string, port: number): AddressPosition | null {
    const id = this.find(host, port);
    if (id === EMPTY) return null;
    const info = this.mapInfo.get(id)!;
    if (info.inTried) {
      const slot = this.triedSlotOf(host, port)!;
      return { tried: true, multiplicity: 1, bucket: slot.bucket, position: slot.position };
    }
    const slot = this.newSlotOf(host, port);
    return {
      tried: false,
      multiplicity: info.refCount,
      bucket: slot?.bucket ?? -1,
      position: slot?.position ?? -1,
    };
  }

  // --- Add (Core Add_/AddSingle) -------------------------------------------

  /**
   * Add places a heard-about address in the NEW table.
   * @returns true iff a fresh slot insertion occurred.
   */
  add(
    host: string,
    port: number,
    source: string,
    services: bigint,
    nTime: number,
    now: number = Math.floor(Date.now() / 1000),
    rawAddr?: Buffer,
  ): boolean {
    let id = this.find(host, port);
    if (id !== EMPTY) {
      const info = this.mapInfo.get(id)!;
      if (nTime > info.nTime) info.nTime = nTime;
      info.services |= services;
      if (info.inTried) return false;
      if (info.refCount >= ADDRMAN_NEW_BUCKETS_PER_ADDRESS) return false;
      // Stochastic multiplicity gate: 2^refCount harder each time.
      if (info.refCount > 0) {
        const factor = 1 << info.refCount;
        if (this.rng.range(factor) !== 0) return false;
      }
    } else {
      if (this.mapInfo.size >= ADDRMAN_CEILING) return false; // bounded ceiling
      id = this.create(host, port, source, services, nTime, rawAddr);
    }

    const info = this.mapInfo.get(id)!;
    // Core AddSingle (addrman.cpp:579) places using the CURRENT advertiser's
    // source group, NOT info.source, so one address heard from many distinct
    // source groups spreads into up to ADDRMAN_NEW_BUCKETS_PER_ADDRESS buckets.
    const addrGroup = this.group(info.host);
    const srcGroup = this.group(source);
    const bucket = this.getNewBucket(addrGroup, srcGroup);
    const pos = this.getBucketPosition(true, bucket, info);

    const occupant = this.vvNew[bucket]![pos]!;
    let insert = occupant === EMPTY;
    if (occupant !== id) {
      if (!insert) {
        const occ = this.mapInfo.get(occupant);
        if (!occ || isTerrible(occ, now) || (occ.refCount > 1 && info.refCount === 0)) {
          insert = true;
        }
      }
      if (insert) {
        this.clearNew(bucket, pos);
        info.refCount++;
        this.vvNew[bucket]![pos] = id;
        this.nNew++;
      } else if (info.refCount === 0) {
        this.deleteIfFloating(id);
      }
    }
    return insert;
  }

  // --- Good (Core Good_/MakeTried) -----------------------------------------

  /**
   * Good promotes an address from NEW to TRIED, evicting an existing tried
   * occupant back to its NEW bucket on collision.
   * @returns true iff the address was moved into tried.
   */
  good(host: string, port: number, now: number = Math.floor(Date.now() / 1000)): boolean {
    const id = this.find(host, port);
    if (id === EMPTY) return false;
    const info = this.mapInfo.get(id)!;
    info.lastSuccess = now;
    info.lastTry = now;
    info.attempts = 0;
    if (info.inTried) return false;
    if (info.refCount === 0) return false; // not in new — something bad

    // Remove the id from ALL its new buckets (Core MakeTried loop).
    const { addrGroup, srcGroup } = this.groupsOf(info);
    const start = this.getNewBucket(addrGroup, srcGroup);
    for (let n = 0; n < ADDRMAN_NEW_BUCKET_COUNT; n++) {
      const b = (start + n) % ADDRMAN_NEW_BUCKET_COUNT;
      const p = this.getBucketPosition(true, b, info);
      if (this.vvNew[b]![p] === id) {
        this.vvNew[b]![p] = EMPTY;
        if (info.refCount > 0) info.refCount--;
        if (info.refCount === 0) break;
      }
    }
    if (this.nNew > 0) this.nNew--;
    info.refCount = 0;

    // Compute the tried slot.
    const kBucket = this.getTriedBucket(info, addrGroup);
    const kPos = this.getBucketPosition(false, kBucket, info);

    // On collision, evict the existing tried occupant back to NEW.
    const evict = this.vvTried[kBucket]![kPos]!;
    if (evict !== EMPTY) {
      this.vvTried[kBucket]![kPos] = EMPTY;
      if (this.nTried > 0) this.nTried--;
      const old = this.mapInfo.get(evict);
      if (old) {
        old.inTried = false;
        const og = this.groupsOf(old);
        const ob = this.getNewBucket(og.addrGroup, og.srcGroup);
        const op = this.getBucketPosition(true, ob, old);
        this.clearNew(ob, op);
        old.refCount = 1;
        this.vvNew[ob]![op] = evict;
        this.nNew++;
      }
    }

    // Place the promoted id into tried.
    this.vvTried[kBucket]![kPos] = id;
    this.nTried++;
    info.inTried = true;
    return true;
  }

  /** Attempt records a (possibly-failed) connection attempt (Core Attempt_). */
  attempt(host: string, port: number, now: number = Math.floor(Date.now() / 1000)): void {
    const id = this.find(host, port);
    if (id === EMPTY) return;
    const info = this.mapInfo.get(id)!;
    info.lastTry = now;
    info.attempts++;
  }

  // --- Select (Core Select_, liveness-safe bounded scan) -------------------

  /**
   * Select chooses an address with the Core 50/50 new-vs-tried bias. When
   * newOnly is true, only the new table is searched. Returns the AddrInfo or
   * null when empty. Bounded scan (never loops forever).
   */
  select(newOnly = false): AddrInfo | null {
    if (this.mapInfo.size === 0) return null;
    if (newOnly && this.nNew === 0) return null;
    if (this.nNew + this.nTried === 0) return null;

    let searchTried: boolean;
    if (newOnly || this.nTried === 0) {
      searchTried = false;
    } else if (this.nNew === 0) {
      searchTried = true;
    } else {
      searchTried = this.rng.range(2) === 0; // 50/50
    }

    const table = searchTried ? this.vvTried : this.vvNew;
    const bucketCount = searchTried ? ADDRMAN_TRIED_BUCKET_COUNT : ADDRMAN_NEW_BUCKET_COUNT;

    const startBucket = this.rng.range(bucketCount);
    const initialPos = this.rng.range(ADDRMAN_BUCKET_SIZE);
    for (let nb = 0; nb < bucketCount; nb++) {
      const bucket = (startBucket + nb) % bucketCount;
      for (let i = 0; i < ADDRMAN_BUCKET_SIZE; i++) {
        const pos = (initialPos + i) % ADDRMAN_BUCKET_SIZE;
        const id = table[bucket]![pos]!;
        if (id !== EMPTY) {
          const info = this.mapInfo.get(id);
          if (info) return info;
        }
      }
    }
    return null;
  }

  /**
   * getEntries returns all AddrInfo in one table (Core GetEntries). Used by
   * getnodeaddresses / getaddr-equivalent paths and by tests.
   */
  getEntries(fromTried: boolean): AddrInfo[] {
    const out: AddrInfo[] = [];
    for (const info of this.mapInfo.values()) {
      if (info.inTried === fromTried) out.push(info);
    }
    return out;
  }

  // --- Persistence (peers.dat-equivalent, bucketed) ------------------------

  /**
   * serialize writes the versioned, line-oriented bucketed form. Format:
   *   line 0: "ADDRMANV2 <version> <nkey-hex>"
   *   then one record per id:
   *     "<n|t> <host> <port> <services> <source> <nTime> <lastSuccess>
   *      <lastTry> <attempts> <refCount> <rawAddrHex|->"
   * New records are restored via add() (new-bucket placement recomputed); tried
   * records are re-promoted via good() so placement is recomputed from the same
   * nKey on load.
   */
  serialize(): string {
    const lines: string[] = [];
    lines.push(`${ADDRMAN_DAT_MAGIC} ${ADDRMAN_DAT_VERSION} ${this.nKey.toString("hex")}`);
    for (const info of this.mapInfo.values()) {
      const tag = info.inTried ? "t" : "n";
      const raw = info.rawAddr && info.rawAddr.length > 0 ? info.rawAddr.toString("hex") : "-";
      lines.push(
        [
          tag,
          info.host,
          info.port,
          info.services.toString(),
          info.source,
          info.nTime,
          info.lastSuccess,
          info.lastTry,
          info.attempts,
          info.refCount,
          raw,
        ].join(" "),
      );
    }
    return lines.join("\n") + "\n";
  }

  /**
   * deserialize re-bucketing via add()/good() so placement is recomputed from
   * the persisted nKey. Corrupt / truncated / wrong-version / empty input
   * yields null so the caller can cold-start. Bounded by the ceiling.
   */
  static deserialize(
    text: string,
    opts?: { groupFn?: (host: string) => string; rngSeed?: bigint },
  ): AddrMan | null {
    const rawLines = text.split("\n");
    if (rawLines.length === 0) return null;
    const header = rawLines[0]!.trim().split(/\s+/);
    if (header.length !== 3 || header[0] !== ADDRMAN_DAT_MAGIC) return null;
    const version = parseInt(header[1]!, 10);
    if (!Number.isInteger(version) || version !== ADDRMAN_DAT_VERSION) return null;
    if (!/^[0-9a-fA-F]{64}$/.test(header[2]!)) return null;
    const nKey = Buffer.from(header[2]!, "hex");

    const am = new AddrMan({ nKey, groupFn: opts?.groupFn, rngSeed: opts?.rngSeed });

    const triedRecs: Array<{ host: string; port: number }> = [];
    const now = Math.floor(Date.now() / 1000);
    for (let i = 1; i < rawLines.length; i++) {
      const line = rawLines[i]!.trim();
      if (line === "") continue;
      if (am.mapInfo.size >= ADDRMAN_CEILING) break; // bounded
      const f = line.split(/\s+/);
      if (f.length !== 11) return null; // structural problem -> cold start
      const tag = f[0]!;
      const host = f[1]!;
      const port = parseInt(f[2]!, 10);
      if (!Number.isInteger(port) || port < 0 || port > 65535) return null;
      let services: bigint;
      try {
        services = BigInt(f[3]!);
      } catch {
        return null;
      }
      const source = f[4]!;
      const nTime = parseInt(f[5]!, 10);
      const lastSuccess = parseInt(f[6]!, 10);
      const lastTry = parseInt(f[7]!, 10);
      const attempts = parseInt(f[8]!, 10);
      // f[9] (refCount) is recomputed by add(); validated for structure.
      const refCountParsed = parseInt(f[9]!, 10);
      if (
        [nTime, lastSuccess, lastTry, attempts, refCountParsed].some(
          (v) => !Number.isInteger(v),
        )
      ) {
        return null;
      }
      const rawHex = f[10]!;
      let rawAddr: Buffer | undefined;
      if (rawHex !== "-") {
        if (!/^[0-9a-fA-F]+$/.test(rawHex) || rawHex.length % 2 !== 0) return null;
        rawAddr = Buffer.from(rawHex, "hex");
      }

      // Re-create via add() so new-bucket placement is recomputed from nKey.
      am.add(host, port, source, services, nTime, now, rawAddr);
      const id = am.find(host, port);
      if (id !== EMPTY) {
        const info = am.mapInfo.get(id)!;
        info.lastSuccess = lastSuccess;
        info.lastTry = lastTry;
        info.attempts = attempts;
      }
      if (tag === "t") triedRecs.push({ host, port });
    }

    // Second pass: promote the tried records (placement recomputed from nKey).
    for (const r of triedRecs) {
      am.good(r.host, r.port, now);
    }
    return am;
  }
}
