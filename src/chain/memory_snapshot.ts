/**
 * Process + UTXO-cache memory snapshot for IBD logs.
 *
 * Peak RSS at 900k is not the JS heap: live samples had heap 1–7 GB against
 * RSS 12–25 GB. This module attributes that remainder (worker isolates,
 * bun:ffi / ArrayBuffer external, LevelDB SST mmap) so a --dbcache bound
 * can be checked instead of guessed.
 */

import { readFileSync } from "node:fs";

export interface UtxoMemoryView {
	getMemoryUsage(): number;
	getCacheSize(): number;
	getDirtyCount(): number;
	getMaxCacheBytes(): number;
}

export interface MemorySnapshot {
	rss: number;
	heapUsed: number;
	heapTotal: number;
	external: number;
	arrayBuffers: number;
	/** VmRSS anonymous pages from /proc/self/status, or null. */
	rssAnon: number | null;
	/** VmRSS file-backed pages from /proc/self/status, or null. */
	rssFile: number | null;
	utxoBytes: number;
	utxoEntries: number;
	utxoDirty: number;
	utxoMaxBytes: number;
	workers: number;
	/** rss - heapUsed: native, file mmap, worker isolates, external. */
	nonHeap: number;
	/**
	 * Best-effort per-worker native estimate:
	 * (rssAnon - heapUsed) / workers. Null if we cannot see anon RSS.
	 */
	perWorkerNative: number | null;
}

/** Anonymous RSS above this multiple of --dbcache is treated as pressure. */
export const RSS_PRESSURE_MULTIPLE = 4;

export function readProcRss(): { anon: number; file: number } | null {
	try {
		const text = readFileSync("/proc/self/status", "utf8");
		let anon: number | null = null;
		let file: number | null = null;
		for (const line of text.split("\n")) {
			if (line.startsWith("RssAnon:")) {
				anon = parseInt(line.split(/\s+/)[1]!, 10) * 1024;
			} else if (line.startsWith("RssFile:")) {
				file = parseInt(line.split(/\s+/)[1]!, 10) * 1024;
			}
		}
		if (anon === null || file === null) return null;
		return { anon, file };
	} catch {
		return null;
	}
}

export function snapshotMemory(
	utxo?: UtxoMemoryView,
	workers = 0,
): MemorySnapshot {
	const mem = process.memoryUsage();
	const proc = readProcRss();
	const heapUsed = mem.heapUsed;
	const rssAnon = proc?.anon ?? null;
	let perWorkerNative: number | null = null;
	if (rssAnon !== null && workers > 0) {
		perWorkerNative = Math.max(0, Math.floor((rssAnon - heapUsed) / workers));
	}
	return {
		rss: mem.rss,
		heapUsed,
		heapTotal: mem.heapTotal,
		external: mem.external,
		arrayBuffers: mem.arrayBuffers,
		rssAnon,
		rssFile: proc?.file ?? null,
		utxoBytes: utxo?.getMemoryUsage() ?? 0,
		utxoEntries: utxo?.getCacheSize() ?? 0,
		utxoDirty: utxo?.getDirtyCount() ?? 0,
		utxoMaxBytes: utxo?.getMaxCacheBytes() ?? 0,
		workers,
		nonHeap: Math.max(0, mem.rss - heapUsed),
		perWorkerNative,
	};
}

function mb(n: number): string {
	return (n / (1024 * 1024)).toFixed(0);
}

/**
 * One IBD log fragment. Example:
 *   RSS=15089MB heap=1134MB ext=40MB ab=80MB | anon=4908MB file=6596MB nonheap=13955MB | utxo=563899/2560MB used=1690MB dirty=400000 | workers=15 × ~220MB
 */
export function formatMemoryBreakdown(s: MemorySnapshot): string {
	const anon = s.rssAnon !== null ? `${mb(s.rssAnon)}MB` : "?";
	const file = s.rssFile !== null ? `${mb(s.rssFile)}MB` : "?";
	const utxoMaxMB = s.utxoMaxBytes > 0 ? mb(s.utxoMaxBytes) : "?";
	const per =
		s.perWorkerNative !== null ? ` × ~${mb(s.perWorkerNative)}MB` : "";
	return (
		`RSS=${mb(s.rss)}MB heap=${mb(s.heapUsed)}MB ext=${mb(s.external)}MB ab=${mb(s.arrayBuffers)}MB` +
		` | anon=${anon} file=${file} nonheap=${mb(s.nonHeap)}MB` +
		` | utxo=${s.utxoEntries}/${utxoMaxMB}MB used=${mb(s.utxoBytes)}MB dirty=${s.utxoDirty}` +
		` | workers=${s.workers}${per}`
	);
}

/**
 * True when anonymous RSS (or non-heap if /proc is missing) exceeds
 * RSS_PRESSURE_MULTIPLE × dbcache. File-backed LevelDB mmap is excluded
 * so a 14 GB chainstate does not look like a cache leak.
 */
export function exceedsRssBudget(
	snap: MemorySnapshot,
	cacheBytes: number,
): boolean {
	if (!(cacheBytes > 0)) return false;
	return rssPressure(snap) > RSS_PRESSURE_MULTIPLE * cacheBytes;
}

function rssPressure(snap: MemorySnapshot): number {
	return snap.rssAnon ?? snap.nonHeap;
}

/** Smallest growth that re-arms the RSS trigger after it has fired. */
export const RSS_REARM_MIN_BYTES = 256 * 1024 * 1024;

/**
 * Stateful RSS flush trigger for the IBD connect loop.
 *
 * {@link exceedsRssBudget} alone is a level trigger, and a UTXO sync under
 * the coins-cache budget evicts nothing (CoinsViewCache.sync). When memory a
 * flush cannot free holds anon RSS over the line, the level trigger fires on
 * every block with dirty coins. The pre-base header backfill (088f392) does
 * exactly that: ~940k HeaderChainEntry objects lift anon to 4.1–4.7 GB
 * against 4 × --dbcache=1024, and the 852000/930000 slices flushed 5,920
 * times in 12,235 blocks and 2,903 in 10,000 (0–1 before the backfill).
 *
 * After an RSS flush the gate re-arms only once pressure has grown by
 * max(cacheBytes, RSS_REARM_MIN_BYTES) above the lowest pressure seen since
 * that flush. A flat baseline (header index, worker isolates) fires once;
 * memory that keeps growing still forces a flush per re-arm step. Core's
 * FlushStateToDisk has no RSS trigger at all; the coins-cache trigger
 * (shouldFlush) is unaffected by this gate.
 */
export class RssFlushGate {
	private floor: number | null = null;
	private fired = 0;

	shouldFlush(snap: MemorySnapshot, cacheBytes: number): boolean {
		if (!(cacheBytes > 0)) return false;
		const pressure = rssPressure(snap);
		if (this.floor !== null && pressure < this.floor) this.floor = pressure;
		if (pressure <= RSS_PRESSURE_MULTIPLE * cacheBytes) return false;
		if (this.floor === null) return true;
		return pressure - this.floor >= Math.max(cacheBytes, RSS_REARM_MIN_BYTES);
	}

	/** Record an RSS-triggered flush; `snap` is the pressure it fired at. */
	recordFlush(snap: MemorySnapshot): void {
		this.floor = rssPressure(snap);
		this.fired++;
	}

	get flushes(): number {
		return this.fired;
	}
}
