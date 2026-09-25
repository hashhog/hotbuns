/**
 * SigCache FIFO eviction must evict exactly what the old
 * `cache.keys().next()` Map-order eviction evicted. The ring replaced it
 * because JSC's iterator walks delete tombstones (O(n) per eviction under
 * churn); membership after every operation must be unchanged.
 *
 * Control: HOTBUNS_UNIT_CHILD=1 bun test ./src/validation/sig_cache.fifo.test.ts
 */
import { describe, expect, it } from "bun:test";
import { SigCache } from "./sig_cache.js";

/** The pre-change algorithm, verbatim, as the reference model. */
class RefFifo {
	m = new Map<string, true>();
	constructor(private max: number) {}
	insert(k: string) {
		if (this.m.has(k)) return;
		if (this.m.size >= this.max) {
			const o = this.m.keys().next().value;
			if (o !== undefined) this.m.delete(o);
		}
		this.m.set(k, true);
	}
}

describe("SigCache FIFO ring", () => {
	for (const max of [1, 2, 7, 100]) {
		it(`matches Map-order eviction exactly (max=${max})`, () => {
			const c = new SigCache(max, Buffer.alloc(32, 9));
			let ref = new RefFifo(max);
			let seed = 12345 + max;
			const rnd = () => {
				seed = (seed * 1103515245 + 12345) & 0x7fffffff;
				return seed;
			};
			for (let i = 0; i < 20_000; i++) {
				const r = rnd();
				if (r % 997 === 0) {
					c.clear();
					ref = new RefFifo(max);
					continue;
				}
				// small key space => many duplicate inserts
				const k = (r % (max * 3 + 5)).toString(16).padStart(16, "0");
				c.insert({ entryHex: k });
				ref.insert(k);
				expect(c.size).toBe(ref.m.size);
				if (i % 50 === 0) {
					for (let j = 0; j < max * 3 + 5; j++) {
						const kk = j.toString(16).padStart(16, "0");
						expect(c.lookup({ entryHex: kk })).toBe(ref.m.has(kk));
					}
				}
			}
		});
	}
});
