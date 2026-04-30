/**
 * Mempool persistence (Bitcoin Core mempool.dat compatibility).
 *
 * Reference: bitcoin-core/src/node/mempool_persist.cpp
 *
 * On-disk format (MEMPOOL_DUMP_VERSION = 2):
 *
 *   uint64 LE          version (== 2)
 *   compactsize=8      Obfuscation key length
 *   8 bytes            Obfuscation key (raw)
 *   --- everything below is XOR-obfuscated by repeating the 8-byte key ---
 *   uint64 LE          number of transactions
 *   per tx:
 *     CTransaction     serialized WITH witness (BIP-141 segwit format)
 *     int64 LE         time (seconds since UNIX epoch)
 *     int64 LE         nFeeDelta (PrioritiseTransaction modifier; 0 if unused)
 *   compactsize        mapDeltas count
 *   per mapDeltas:
 *     32 bytes         txid (internal little-endian)
 *     int64 LE         nFeeDelta
 *   compactsize        unbroadcast_txids count
 *   per unbroadcast:
 *     32 bytes         txid
 *
 * The obfuscation XOR is applied at absolute file offsets — the version
 * and the obfuscation key itself are NOT obfuscated, but every byte after
 * file offset 17 is XORed against `key[file_offset % 8]`.  This matches
 * the AutoFile semantics in `bitcoin-core/src/streams.cpp`.
 *
 * Operator policy: "all 10 impls byte-for-byte Core-compatible".  Round-
 * tripping through Core 28.x must produce an identical file modulo the
 * random obfuscation key, and any Core-written mempool.dat must load
 * cleanly here.
 */

import { promises as fsp } from "node:fs";
import * as path from "node:path";
import { BufferWriter, BufferReader } from "../wire/serialization.js";
import {
  serializeTx,
  deserializeTx,
  getTxId,
  type Transaction,
} from "../validation/tx.js";
import { Mempool } from "./mempool.js";

/**
 * Mempool dump format with XOR obfuscation (Core 28.0+).
 */
export const MEMPOOL_DUMP_VERSION = 2n;

/**
 * Legacy mempool dump format without an obfuscation key (Core <= 27.x).
 * Still readable on the load path for backwards compatibility.
 */
export const MEMPOOL_DUMP_VERSION_NO_XOR_KEY = 1n;

/**
 * Obfuscation key length in bytes (uint64).
 */
export const OBFUSCATION_KEY_SIZE = 8;

/**
 * Default mempool.dat filename (matches Core default).
 */
export const MEMPOOL_DAT_FILENAME = "mempool.dat";

/**
 * Result of a load operation.
 */
export interface LoadResult {
  /** Number of transactions successfully accepted into the mempool. */
  succeeded: number;
  /** Number of transactions whose deserialization or accept-to-mempool failed. */
  failed: number;
  /** Number of transactions skipped because they were past the expiry window. */
  expired: number;
  /** Number of unbroadcast txids restored. */
  unbroadcast: number;
}

/**
 * Result of a dump operation.
 */
export interface DumpResult {
  /** Number of transactions written. */
  count: number;
  /** Total bytes written to disk. */
  bytes: number;
  /** Final dump path (always `<datadir>/mempool.dat`). */
  path: string;
}

/**
 * Obfuscate `data` IN PLACE by XORing each byte against the repeating key.
 * `fileOffset` is the absolute byte position of `data[0]` in the file —
 * this matches the Core `AutoFile` behaviour where the position counter
 * is incremented across every read/write regardless of whether obfuscation
 * was active when those bytes were first written.
 */
export function applyObfuscation(
  data: Buffer,
  fileOffset: number,
  key: Buffer
): void {
  if (key.length !== OBFUSCATION_KEY_SIZE) {
    throw new Error(
      `applyObfuscation: key must be exactly ${OBFUSCATION_KEY_SIZE} bytes`
    );
  }
  // All-zero key is a no-op (Core treats key=0 the same as v1, no-XOR).
  let allZero = true;
  for (const b of key) {
    if (b !== 0) {
      allZero = false;
      break;
    }
  }
  if (allZero) return;

  for (let i = 0; i < data.length; i++) {
    data[i] ^= key[(fileOffset + i) % OBFUSCATION_KEY_SIZE];
  }
}

/**
 * Pack a mempool snapshot into a single Buffer in MEMPOOL_DUMP_VERSION=2
 * format. Used by `dumpMempool` and exposed for unit tests so the byte
 * layout can be asserted independently of any filesystem.
 *
 * @param entries - One per mempool transaction.
 * @param mapDeltas - PrioritiseTransaction map (txid -> int64 satoshi modifier).
 * @param unbroadcast - Unbroadcast txid set.
 * @param obfuscationKey - 8-byte XOR key. Pass an all-zero key for the v1
 *   format equivalent (no obfuscation).  Tests typically pass deterministic
 *   bytes; production callers should pass crypto-grade randomness.
 */
export function encodeMempoolDump(
  entries: Array<{ tx: Transaction; time: bigint; feeDelta: bigint }>,
  mapDeltas: Map<string, bigint>,
  unbroadcast: Set<string>,
  obfuscationKey: Buffer
): Buffer {
  if (obfuscationKey.length !== OBFUSCATION_KEY_SIZE) {
    throw new Error(
      `encodeMempoolDump: key must be exactly ${OBFUSCATION_KEY_SIZE} bytes`
    );
  }

  // Header: version(8) + compactsize(=8, 1 byte) + key(8) = 17 bytes,
  // none of which are XOR-obfuscated.
  const header = new BufferWriter(17);
  header.writeUInt64LE(MEMPOOL_DUMP_VERSION);
  header.writeVarInt(OBFUSCATION_KEY_SIZE); // compactsize prefix on the key vector
  header.writeBytes(obfuscationKey);
  const headerBuf = header.toBuffer();

  // Body: everything after byte 17, fully XOR-obfuscated in-place.
  const body = new BufferWriter();
  body.writeUInt64LE(BigInt(entries.length));
  for (const { tx, time, feeDelta } of entries) {
    body.writeBytes(serializeTx(tx, true)); // TX_WITH_WITNESS
    body.writeUInt64LE(time);                // int64 LE
    body.writeUInt64LE(feeDelta);            // int64 LE
  }
  // mapDeltas: compactsize count, then (txid 32 bytes + int64 LE) per entry.
  // std::map iteration is sorted by key — we sort the txid hex strings to
  // mirror that behaviour for byte-for-byte round-trip determinism.
  const sortedDeltas = Array.from(mapDeltas.entries()).sort((a, b) =>
    a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0
  );
  body.writeVarInt(sortedDeltas.length);
  for (const [txidHex, delta] of sortedDeltas) {
    body.writeBytes(Buffer.from(txidHex, "hex"));
    body.writeUInt64LE(delta);
  }
  // unbroadcast_txids: compactsize count, then 32-byte txid per entry,
  // again sorted to match std::set iteration order.
  const sortedUnbroadcast = Array.from(unbroadcast).sort();
  body.writeVarInt(sortedUnbroadcast.length);
  for (const txidHex of sortedUnbroadcast) {
    body.writeBytes(Buffer.from(txidHex, "hex"));
  }
  const bodyBuf = body.toBuffer();

  // Apply XOR obfuscation in-place at the correct absolute offset.
  applyObfuscation(bodyBuf, headerBuf.length, obfuscationKey);

  return Buffer.concat([headerBuf, bodyBuf]);
}

/**
 * Parse a mempool.dat buffer.  Returns one entry per transaction plus the
 * priority deltas and unbroadcast set.  Caller decides what to do with each
 * entry (typical: feed to `mempool.acceptToMemoryPool`).
 *
 * Throws on structural failure — versions other than 1/2, malformed
 * compactsize fields, or truncated data.  Per-tx deserialization errors
 * are NOT caught here: a bad file is bad data, not a load-time decision.
 */
export function decodeMempoolDump(buf: Buffer): {
  entries: Array<{ tx: Transaction; time: bigint; feeDelta: bigint }>;
  mapDeltas: Map<string, bigint>;
  unbroadcast: Set<string>;
} {
  if (buf.length < 8) {
    throw new Error("decodeMempoolDump: file too short for version header");
  }

  // Version is unobfuscated (Core writes it before SetObfuscation).
  const versionReader = new BufferReader(buf);
  const version = versionReader.readUInt64LE();

  let payloadStart: number;
  let key: Buffer;

  if (version === MEMPOOL_DUMP_VERSION_NO_XOR_KEY) {
    // v1: no key block, body starts immediately after version.
    payloadStart = 8;
    key = Buffer.alloc(OBFUSCATION_KEY_SIZE, 0);
  } else if (version === MEMPOOL_DUMP_VERSION) {
    // v2: read compactsize length + 8-byte key (still unobfuscated).
    const keyReader = new BufferReader(buf.subarray(8));
    const keyLen = keyReader.readVarInt();
    if (keyLen !== OBFUSCATION_KEY_SIZE) {
      throw new Error(
        `decodeMempoolDump: obfuscation key length ${keyLen} != ${OBFUSCATION_KEY_SIZE}`
      );
    }
    key = keyReader.readBytes(OBFUSCATION_KEY_SIZE);
    payloadStart = 8 + keyReader.position;
  } else {
    throw new Error(
      `decodeMempoolDump: unsupported version ${version} (expected 1 or 2)`
    );
  }

  // Copy the body, then de-obfuscate at the correct absolute offset.  The
  // copy is necessary because applyObfuscation mutates in place and we
  // don't want to corrupt the caller's buffer.
  const body = Buffer.from(buf.subarray(payloadStart));
  applyObfuscation(body, payloadStart, key);

  const reader = new BufferReader(body);
  const totalCount = reader.readUInt64LE();
  if (totalCount > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new Error("decodeMempoolDump: tx count exceeds safe integer range");
  }
  const txCount = Number(totalCount);

  const entries: Array<{ tx: Transaction; time: bigint; feeDelta: bigint }> = [];
  for (let i = 0; i < txCount; i++) {
    const tx = deserializeTx(reader);
    const time = reader.readUInt64LE();
    const feeDelta = reader.readUInt64LE();
    entries.push({ tx, time, feeDelta });
  }

  const mapCount = reader.readVarInt();
  const mapDeltas = new Map<string, bigint>();
  for (let i = 0; i < mapCount; i++) {
    const txid = reader.readBytes(32);
    const delta = reader.readUInt64LE();
    mapDeltas.set(txid.toString("hex"), delta);
  }

  const unbroadcastCount = reader.readVarInt();
  const unbroadcast = new Set<string>();
  for (let i = 0; i < unbroadcastCount; i++) {
    const txid = reader.readBytes(32);
    unbroadcast.add(txid.toString("hex"));
  }

  return { entries, mapDeltas, unbroadcast };
}

/**
 * Dump the mempool to `<datadir>/mempool.dat`.  Writes to a `.new`
 * sibling file first then renames over the target — same crash-safe
 * pattern as Core's `DumpMempool()`.
 *
 * Currently writes empty mapDeltas and unbroadcast sets because hotbuns
 * does not implement PrioritiseTransaction or an unbroadcast tracker.
 * The fields are still present in the file (with count=0) so byte-format
 * compatibility is preserved.
 */
export async function dumpMempool(
  mempool: Mempool,
  datadir: string,
  randomKey?: Buffer
): Promise<DumpResult> {
  const dumpPath = path.join(datadir, MEMPOOL_DAT_FILENAME);
  const newPath = `${dumpPath}.new`;

  // Use a crypto-grade random key by default; tests can pin a deterministic
  // key.  An all-zero key would fall back to "no obfuscation" semantics
  // (and Core would write version=1 in that case) — we always emit v2.
  const key = randomKey ?? Buffer.from(crypto.getRandomValues(new Uint8Array(OBFUSCATION_KEY_SIZE)));

  // Snapshot every entry into the format expected by encodeMempoolDump.
  // hotbuns lacks a tx-level "feeDelta" prioritisation modifier, so 0n.
  const entries: Array<{ tx: Transaction; time: bigint; feeDelta: bigint }> = [];
  for (const txid of mempool.getAllTxids()) {
    const entry = mempool.getTransaction(txid);
    if (!entry) continue;
    entries.push({
      tx: entry.tx,
      time: BigInt(entry.addedTime),
      feeDelta: 0n,
    });
  }

  const buf = encodeMempoolDump(entries, new Map(), new Set(), key);

  await fsp.mkdir(datadir, { recursive: true });
  await fsp.writeFile(newPath, buf);
  await fsp.rename(newPath, dumpPath);

  return { count: entries.length, bytes: buf.length, path: dumpPath };
}

/**
 * Load the mempool from `<datadir>/mempool.dat`.  Missing or unreadable
 * file is treated as a no-op success (`succeeded: 0`) — same lenient
 * policy as Core's `LoadMempool()`.  A malformed file logs and returns
 * zeroes rather than crashing the node.
 *
 * Each tx is re-validated through `mempool.acceptToMemoryPool` so all
 * the policy rules (weight, fee rate, RBF, …) are re-applied: a stale
 * dump never bypasses a tightened relay rule.
 *
 * @param expirySeconds - Maximum age of a tx (in seconds) past which it
 *   is dropped on load.  Mirrors `pool.m_opts.expiry` in Core (default
 *   336h = 1_209_600s).
 */
export async function loadMempool(
  mempool: Mempool,
  datadir: string,
  expirySeconds: number = 336 * 60 * 60
): Promise<LoadResult> {
  const result: LoadResult = { succeeded: 0, failed: 0, expired: 0, unbroadcast: 0 };
  const dumpPath = path.join(datadir, MEMPOOL_DAT_FILENAME);

  let buf: Buffer;
  try {
    buf = await fsp.readFile(dumpPath);
  } catch {
    // No dump file is the common bootstrap case — silent no-op.
    return result;
  }

  let decoded: ReturnType<typeof decodeMempoolDump>;
  try {
    decoded = decodeMempoolDump(buf);
  } catch (err) {
    console.error(
      `[mempool] Failed to decode ${dumpPath}: ${(err as Error).message}. Continuing anyway.`
    );
    return result;
  }

  const nowSec = Math.floor(Date.now() / 1000);
  for (const { tx, time } of decoded.entries) {
    if (Number(time) < nowSec - expirySeconds) {
      result.expired++;
      continue;
    }
    const accept = await mempool.acceptToMemoryPool(tx);
    if (accept.accepted) {
      result.succeeded++;
    } else {
      result.failed++;
    }
  }

  // hotbuns does not yet expose PrioritiseTransaction or an unbroadcast
  // tracker, but we still report the count so operators can see when a
  // future load brings priority data through unchanged.
  result.unbroadcast = decoded.unbroadcast.size;
  // Touch mapDeltas reference so an unused-var lint doesn't fire on
  // future strict configs; the data is intentionally dropped today.
  void decoded.mapDeltas;

  return result;
}

/**
 * Check whether `<datadir>/mempool.dat` exists.  Tiny helper used by the
 * `loadmempool` RPC so it can return INVALID_PARAMETER instead of a
 * silent no-op when the operator points at a wrong directory.
 */
export async function mempoolDumpExists(datadir: string): Promise<boolean> {
  try {
    await fsp.access(path.join(datadir, MEMPOOL_DAT_FILENAME));
    return true;
  } catch {
    return false;
  }
}

/**
 * Re-export to satisfy callers that import getTxId off this module without
 * having to thread the validation/tx import through.
 */
export { getTxId };
