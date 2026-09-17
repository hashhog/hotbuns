/**
 * Native-memory lifetime class around the 340890 IBD crash window.
 *
 * Receipt: receipts/hotbuns-bun-segfault-340890-2026-09-17.md
 * Proof:   proof/r4/segfault-340890.txt (UNEXPLAINED — do not claim this
 *          file closed the SIGSEGV).
 *
 * The crash was non-deterministic at that height. The same commit
 * `280c6f02ebe5` later CLOSED 340000→363708 with zero crashes, so the
 * FRESH-spend / empty-ptr work here is a real footgun class, not a
 * demonstrated SIGSEGV root cause. Two cooperating bugs this file
 * actually controls:
 *
 *   1. Spending a FRESH coin deletes the cache entry but leaves
 *      CACHE_ENTRY_OVERHEAD (3000) in cachedCoinsUsage. After ~850k such
 *      spends the counter is permanently >= dbcache, so every subsequent
 *      block does a full UTXO flush + Bun.gc(true) with 15 FFI workers live.
 *      That is the 2.7× RSS overshoot and the crash-log flush spiral.
 *   2. bun:ffi ptr() on an empty ArrayBufferView does not throw — it RETURNS
 *      a TypeError object. Passing that to a dlopen() libsecp256k1 symbol
 *      throws "Unable to convert TypeError to a pointer". Worker fromU8
 *      also aliased the structured-clone ArrayBuffer. Neither path has
 *      been observed to SIGSEGV (15×5000 worker trials: 75,000 throws,
 *      0 SIGSEGV). nativePtr() still must not hand the TypeError to C.
 *
 * Control: HOTBUNS_UNIT_CHILD=1 bun test ./src/validation/bun-native-lifetime.test.ts
 */
import { afterEach, describe, expect, test } from "bun:test";
import { dlopen, FFIType, ptr as ffiPtr } from "bun:ffi";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CoinsViewCache, CoinsViewDB, type Coin } from "../chain/utxo.js";
import {
	FFI_AVAILABLE,
	ecdsaVerifyFFI,
	ecdsaVerifyLaxFFI,
	parseSignatureDER_FFI,
} from "../crypto/secp256k1_ffi.js";
import {
	ecdsaSign,
	privateKeyToPublicKey,
	sha256Hash,
} from "../crypto/primitives.js";
import { ChainDB } from "../storage/database.js";
import type { OutPoint } from "./tx.js";
import { fromU8, toU8 } from "./script_check_wire.js";

function makeCoin(): Coin {
	return {
		txOut: {
			value: 50_000n,
			scriptPubKey: Buffer.from([
				0x76, 0xa9, 0x14, ...Array(20).fill(0xab), 0x88, 0xac,
			]),
		},
		height: 100,
		isCoinbase: false,
	};
}

function makeOutpoint(n: number): OutPoint {
	const txid = Buffer.alloc(32, 0);
	txid.writeUInt32LE(n + 1, 0);
	return { txid, vout: 0 };
}

describe("FRESH-spend cache usage (dbcache overshoot / GC storm)", () => {
	let tempDir: string;
	let db: ChainDB;
	let cache: CoinsViewCache;

	afterEach(async () => {
		await db.close();
		await rm(tempDir, { recursive: true, force: true });
	});

	async function setup(maxBytes: number): Promise<void> {
		tempDir = await mkdtemp(join(tmpdir(), "hotbuns-fresh-usage-"));
		db = new ChainDB(tempDir);
		await db.open();
		cache = new CoinsViewCache(new CoinsViewDB(db), maxBytes);
	}

	test("spend of a FRESH coin drops usage to 0 (does not leak entry overhead)", async () => {
		await setup(512 * 1024 * 1024);
		const op = makeOutpoint(1);
		cache.addCoin(op, makeCoin(), false);
		expect(cache.getCacheSize()).toBe(1);
		expect(cache.getMemoryUsage()).toBeGreaterThan(0);
		const ok = cache.spendCoinSync(op);
		expect(ok).toBe(true);
		expect(cache.getCacheSize()).toBe(0);
		expect(cache.getMemoryUsage()).toBe(0);
		expect(cache.shouldFlush()).toBe(false);
	});

	test("async spend of a FRESH coin also drops usage to 0", async () => {
		await setup(512 * 1024 * 1024);
		const op = makeOutpoint(2);
		cache.addCoin(op, makeCoin(), false);
		expect(await cache.spendCoin(op)).toBe(true);
		expect(cache.getCacheSize()).toBe(0);
		expect(cache.getMemoryUsage()).toBe(0);
	});

	test("many FRESH add+spend cycles do not trip shouldFlush on an empty cache", async () => {
		// 50_000 bytes ≈ 16 × CACHE_ENTRY_OVERHEAD. 200 leaked spends would
		// push the counter to 600_000 and shouldFlush() would fire forever
		// with cache.size === 0 — the 340k IBD flush-every-block spiral.
		await setup(50_000);
		for (let i = 0; i < 200; i++) {
			const op = makeOutpoint(i);
			cache.addCoin(op, makeCoin(), false);
			expect(cache.spendCoinSync(op)).toBe(true);
		}
		expect(cache.getCacheSize()).toBe(0);
		expect(cache.getMemoryUsage()).toBe(0);
		expect(cache.shouldFlush()).toBe(false);
	});
});

describe("FFI ptr() lifetime (empty / detached must not reach libsecp)", () => {
	test("libsecp256k1 FFI is available", () => {
		expect(FFI_AVAILABLE).toBe(true);
	});

	test("bun:ffi ptr(empty) returns TypeError; dlopen FFI throws, does not SIGSEGV", () => {
		// Evidence that the 340890 SIGSEGV is not "TypeError used as a pointer"
		// on the dlopen() path hotbuns actually uses. See proof/r4/segfault-340890.txt.
		const empty = new Uint8Array(0);
		const emptyView = new Uint8Array(64).subarray(10, 10);
		let emptyPtr: unknown;
		expect(() => {
			emptyPtr = ffiPtr(empty);
		}).not.toThrow();
		expect(emptyPtr instanceof Error).toBe(true);
		expect(String(emptyPtr)).toMatch(/length > 0/);
		expect(() => {
			ffiPtr(emptyView);
		}).not.toThrow();
		const lib = dlopen("libsecp256k1.so.2", {
			secp256k1_context_create: { args: [FFIType.u32], returns: FFIType.u64 },
			secp256k1_ecdsa_signature_parse_der: {
				args: [FFIType.u64, FFIType.ptr, FFIType.ptr, FFIType.u64],
				returns: FFIType.i32,
			},
		});
		const ctx = lib.symbols.secp256k1_context_create(1);
		const out = new Uint8Array(64);
		const outPtr = ffiPtr(out) as number;
		expect(typeof outPtr).toBe("number");
		expect(() =>
			lib.symbols.secp256k1_ecdsa_signature_parse_der(ctx, outPtr, emptyPtr as number, 0),
		).toThrow(/Unable to convert TypeError/);
	});

	test("empty signature returns false and does not throw", () => {
		const priv = Buffer.alloc(32, 1);
		const pub = privateKeyToPublicKey(priv, true);
		const msg = sha256Hash(Buffer.from("lifetime"));
		const empty = Buffer.alloc(0);
		const emptyView = new Uint8Array(64).subarray(10, 10);
		expect(() => ecdsaVerifyFFI(empty, msg, pub)).not.toThrow();
		expect(ecdsaVerifyFFI(empty, msg, pub)).toBe(false);
		expect(() => ecdsaVerifyFFI(emptyView, msg, pub)).not.toThrow();
		expect(ecdsaVerifyFFI(emptyView, msg, pub)).toBe(false);
		expect(() => parseSignatureDER_FFI(empty)).not.toThrow();
		expect(parseSignatureDER_FFI(empty)).toBe(false);
		expect(() => ecdsaVerifyLaxFFI(empty, msg, pub)).not.toThrow();
		expect(ecdsaVerifyLaxFFI(empty, msg, pub)).toBe(false);
		// Valid sig still verifies so the guard did not break the happy path.
		const der = ecdsaSign(msg, priv);
		expect(ecdsaVerifyFFI(der, msg, pub)).toBe(true);
	});
});

describe("worker wire copies (no aliased ArrayBuffer for FFI)", () => {
	test("fromU8 does not alias the source ArrayBuffer", () => {
		const src = toU8(Buffer.from([1, 2, 3, 4, 5]));
		const copy = fromU8(src);
		expect(copy.equals(Buffer.from(src))).toBe(true);
		expect(copy.buffer).not.toBe(src.buffer);
		src[0] = 0xff;
		expect(copy[0]).toBe(1);
	});

	test("fromU8 of an empty view is a detached-safe empty Buffer", () => {
		const emptyView = new Uint8Array(32).subarray(4, 4);
		const copy = fromU8(emptyView);
		expect(copy.byteLength).toBe(0);
		expect(Buffer.isBuffer(copy)).toBe(true);
	});
});
