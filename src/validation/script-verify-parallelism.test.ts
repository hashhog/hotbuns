/**
 * Script-verification parallelism / sigcache control.
 *
 * The validator is the long pole for this node. `verifyAllInputsParallel`
 * was Promise.all over synchronous ECDSA on one JS thread, and
 * coreConnectBlockChecks waited per transaction, so a block of 1-input
 * txs (the common case) never used more than one core.
 *
 * Bar: connecting a 768-input P2PKH block with scriptThreads=8 must be
 * at least 1.5× faster than scriptThreads=1. That fails on the
 * single-thread Promise.all path (~1.15×) and passes once a Bun Worker
 * pool runs the block's script checks concurrently. Sigcache is cleared
 * between timed runs so the number is ECDSA work, not a cache hit.
 *
 * Control: `bun test src/validation/script-verify-parallelism.test.ts`
 */
import { afterEach, describe, expect, it } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { UTXOManager } from "../chain/utxo.js";
import { coreConnectBlockChecks } from "../consensus/connect_block.js";
import { getBlockSubsidy, REGTEST } from "../consensus/params.js";
import {
	ecdsaSign,
	hash160,
	privateKeyToPublicKey,
} from "../crypto/primitives.js";
import { ChainDB } from "../storage/database.js";
import type { Block, BlockHeader } from "./block.js";
import {
	clampScriptThreads,
	MAX_SCRIPTCHECK_THREADS,
	scriptCheckPoolSize,
} from "./script_check_queue.js";
import { globalSigCache } from "./sig_cache.js";
import {
	ScriptFlags,
	SIGHASH_ALL,
	sigHashLegacy,
	type Transaction,
} from "./tx.js";

const N = 768;
const HEIGHT = 200;
const AMOUNT = 50_000n;
const FEE = 1_000n;
const BAR_SPEEDUP = 1.5;
const THREADS =
	typeof navigator !== "undefined" && navigator.hardwareConcurrency > 1
		? Math.min(8, navigator.hardwareConcurrency)
		: 8;

const PRIV = Buffer.from(
	"0101010101010101010101010101010101010101010101010101010101010101",
	"hex",
);
const PUB = privateKeyToPublicKey(PRIV, true);
const PKH = hash160(PUB);

function p2pkhScript(pkh: Buffer): Buffer {
	return Buffer.concat([
		Buffer.from([0x76, 0xa9, 0x14]),
		pkh,
		Buffer.from([0x88, 0xac]),
	]);
}

function prevTxid(i: number): Buffer {
	const b = Buffer.alloc(32, 0);
	b.writeUInt32LE(i + 1, 0);
	return b;
}

function heightScriptSig(height: number): Buffer {
	const bytes: number[] = [];
	let h = height;
	while (h > 0) {
		bytes.push(h & 0xff);
		h >>= 8;
	}
	if (bytes.length === 0) bytes.push(0);
	if (bytes[bytes.length - 1]! & 0x80) bytes.push(0);
	return Buffer.from([bytes.length, ...bytes]);
}

function coinbaseTx(height: number, value: bigint): Transaction {
	return {
		version: 1,
		inputs: [
			{
				prevOut: { txid: Buffer.alloc(32, 0), vout: 0xffffffff },
				scriptSig: heightScriptSig(height),
				sequence: 0xffffffff,
				witness: [],
			},
		],
		outputs: [{ value, scriptPubKey: p2pkhScript(PKH) }],
		lockTime: 0,
	};
}

function signP2PKH(
	tx: Transaction,
	inputIndex: number,
	scriptPubKey: Buffer,
): void {
	const sighash = sigHashLegacy(tx, inputIndex, scriptPubKey, SIGHASH_ALL);
	const der = ecdsaSign(sighash, PRIV);
	const sig = Buffer.concat([der, Buffer.from([SIGHASH_ALL])]);
	tx.inputs[inputIndex]!.scriptSig = Buffer.concat([
		Buffer.from([sig.length]),
		sig,
		Buffer.from([PUB.length]),
		PUB,
	]);
}

function spendTx(i: number): Transaction {
	const scriptPubKey = p2pkhScript(PKH);
	const tx: Transaction = {
		version: 2,
		inputs: [
			{
				prevOut: { txid: prevTxid(i), vout: 0 },
				scriptSig: Buffer.alloc(0),
				sequence: 0xffffffff,
				witness: [],
			},
		],
		outputs: [{ value: AMOUNT - FEE, scriptPubKey }],
		lockTime: 0,
	};
	signP2PKH(tx, 0, scriptPubKey);
	return tx;
}

function dummyHeader(): BlockHeader {
	return {
		version: 0x20000000,
		prevBlock: Buffer.alloc(32, 0x11),
		merkleRoot: Buffer.alloc(32, 0x22),
		timestamp: 1_700_000_000,
		bits: REGTEST.powLimitBits,
		nonce: 0,
	};
}

function seedUtxos(utxo: UTXOManager): void {
	const scriptPubKey = p2pkhScript(PKH);
	for (let i = 0; i < N; i++) {
		const prev: Transaction = {
			version: 1,
			inputs: [
				{
					prevOut: { txid: Buffer.alloc(32, 0), vout: 0 },
					scriptSig: Buffer.alloc(0),
					sequence: 0xffffffff,
					witness: [],
				},
			],
			outputs: [{ value: AMOUNT, scriptPubKey }],
			lockTime: 0,
		};
		utxo.addTransaction(prevTxid(i), prev, 1, false);
	}
}

function consensusFlags() {
	return {
		verifyDERSig: true,
		verifyCLTV: true,
		verifyCSV: true,
		verifyNullDummy: true,
	};
}

const CONSENSUS_FLAGS =
	ScriptFlags.VERIFY_P2SH |
	ScriptFlags.VERIFY_WITNESS |
	ScriptFlags.VERIFY_TAPROOT |
	ScriptFlags.VERIFY_DERSIG |
	ScriptFlags.VERIFY_NULLDUMMY |
	ScriptFlags.VERIFY_CHECKLOCKTIMEVERIFY |
	ScriptFlags.VERIFY_CHECKSEQUENCEVERIFY;

async function connectOnce(
	db: ChainDB,
	block: Block,
	scriptThreads: number,
): Promise<{ ok: boolean; error?: string; spent: number; elapsedMs: number }> {
	const utxo = new UTXOManager(db);
	seedUtxos(utxo);
	globalSigCache.clear();
	const t0 = performance.now();
	const result = await coreConnectBlockChecks(block, HEIGHT, utxo, REGTEST, {
		skipScripts: false,
		scriptThreads,
		...consensusFlags(),
	});
	const elapsedMs = performance.now() - t0;
	return {
		ok: result.ok,
		error: result.ok ? undefined : result.error,
		spent: result.ok ? result.spentOutputs.length : 0,
		elapsedMs,
	};
}

describe("script-verification parallelism / sigcache", () => {
	let dir: string;
	let db: ChainDB;
	let spends: Transaction[];
	let block: Block;

	async function setup(): Promise<void> {
		dir = await mkdtemp(join(tmpdir(), "hotbuns-script-par-"));
		db = new ChainDB(dir);
		await db.open();
		spends = Array.from({ length: N }, (_, i) => spendTx(i));
		const subsidy = getBlockSubsidy(HEIGHT, REGTEST);
		const cb = coinbaseTx(HEIGHT, subsidy + BigInt(N) * FEE);
		block = { header: dummyHeader(), transactions: [cb, ...spends] };
	}

	afterEach(async () => {
		globalSigCache.clear();
		if (db) await db.close();
		if (dir) {
			try {
				await rm(dir, { recursive: true, force: true });
			} catch {
				// best-effort
			}
		}
	});

	it(
		`connects ${N} P2PKH inputs ≥${BAR_SPEEDUP}× faster with ${THREADS} threads than 1`,
		async () => {
			await setup();

			// Warm the interpreter / FFI / worker pool so spawn and JIT are
			// not the measured delta.
			await connectOnce(db, block, 1);
			await connectOnce(db, block, THREADS);

			const serial = await connectOnce(db, block, 1);
			const parallel = await connectOnce(db, block, THREADS);

			expect(serial.ok).toBe(true);
			expect(parallel.ok).toBe(true);
			expect(serial.spent).toBe(N);
			expect(parallel.spent).toBe(N);

			const speedup = serial.elapsedMs / parallel.elapsedMs;
			console.log(
				`[script-verify parallelism] 1-thread: ${serial.elapsedMs.toFixed(1)}ms | ` +
					`${THREADS}-thread: ${parallel.elapsedMs.toFixed(1)}ms | ` +
					`speedup: ${speedup.toFixed(2)}x (bar ${BAR_SPEEDUP}x)`,
			);

			expect(scriptCheckPoolSize()).toBeGreaterThanOrEqual(2);
			expect(speedup).toBeGreaterThanOrEqual(BAR_SPEEDUP);
		},
		{ timeout: 60_000 },
	);

	it("N-thread path rejects a tampered signature the serial path also rejects", async () => {
		await setup();
		const bad = spends[0]!;
		bad.inputs[0]!.scriptSig[1] ^= 0x01;

		const serial = await connectOnce(db, block, 1);
		const parallel = await connectOnce(db, block, THREADS);

		expect(serial.ok).toBe(false);
		expect(parallel.ok).toBe(false);
		expect(serial.error).toContain("Script verification failed");
		expect(parallel.error).toContain("Script verification failed");
	});

	it("clamps scriptThreads to Core MAX_SCRIPTCHECK_THREADS=15 (0 = auto)", () => {
		expect(MAX_SCRIPTCHECK_THREADS).toBe(15);
		expect(clampScriptThreads(1)).toBe(1);
		expect(clampScriptThreads(15)).toBe(15);
		expect(clampScriptThreads(16)).toBe(15);
		expect(clampScriptThreads(1000)).toBe(15);
		expect(clampScriptThreads(0)).toBeGreaterThanOrEqual(1);
		expect(clampScriptThreads(0)).toBeLessThanOrEqual(15);
		expect(clampScriptThreads(undefined)).toBeGreaterThanOrEqual(1);
		expect(clampScriptThreads(undefined)).toBeLessThanOrEqual(15);
	});

	it("sigcache hit skips a second verify of the same input (mempool→block)", async () => {
		await setup();
		globalSigCache.clear();
		expect(globalSigCache.size).toBe(0);

		const { verifyInputSignature } = await import("./tx.js");
		const utxoEntry = {
			height: 1,
			coinbase: false,
			amount: AMOUNT,
			scriptPubKey: p2pkhScript(PKH),
		};
		const tx = spends[0]!;
		const first = verifyInputSignature(
			tx,
			0,
			utxoEntry,
			{},
			[utxoEntry],
			undefined,
			CONSENSUS_FLAGS,
		);
		expect(first.valid).toBe(true);
		expect(globalSigCache.size).toBe(1);

		const sizeAfter = globalSigCache.size;
		const second = verifyInputSignature(
			tx,
			0,
			utxoEntry,
			{},
			[utxoEntry],
			undefined,
			CONSENSUS_FLAGS,
		);
		expect(second.valid).toBe(true);
		expect(globalSigCache.size).toBe(sizeAfter);
	});
});
