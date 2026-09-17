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
	const pressure = snap.rssAnon ?? snap.nonHeap;
	return pressure > RSS_PRESSURE_MULTIPLE * cacheBytes;
}
