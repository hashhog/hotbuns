/**
 * ConnectBlock feeds the script-check workers during its tx loop (ARCH-2.5).
 *
 * The time split at 900k had script wait at 31% of block time with the
 * workers ~50% used: coreConnectBlockChecks collected every input check of
 * the block and handed the list to the pool only after the tx loop, the
 * sigops ceiling and the coinbase check. Core's CCheckQueueControl::Add
 * gives the threads each tx's checks as the loop produces them and Wait()s
 * after the loop (validation.cpp ConnectBlock).
 *
 * Now beginScriptChecks().add() posts full SCRIPTCHECK_BATCH_SIZE batches to
 * idle workers from inside the loop. What must NOT change: the verdict is
 * read only at Wait(), so a block with both a non-script failure and a bad
 * script still reports the non-script reason, and the earliest-index script
 * failure wins whatever the split.
 *
 * Control: HOTBUNS_UNIT_CHILD=1 bun test ./src/validation/script-check-stream.test.ts
 */
import { afterAll, afterEach, beforeAll, describe, expect, it } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { UTXOManager } from "../chain/utxo.js";
import { coreConnectBlockChecks } from "../consensus/connect_block.js";
import { getBlockSubsidy, REGTEST } from "../consensus/params.js";
import { ChainDB } from "../storage/database.js";
import type { Block } from "./block.js";
import {
	SCRIPTCHECK_BATCH_SIZE,
	scriptCheckPeakInFlightJobs,
	scriptCheckResetStats,
	shutdownScriptCheckPool,
	verifyScriptChecks,
} from "./script_check_queue.js";
import { globalSigCache } from "./sig_cache.js";
import {
	getTxId,
	SEQUENCE_LOCKTIME_TYPE_FLAG,
	type Transaction,
} from "./tx.js";

const HEIGHT = 1_000; // past regtest CSV / segwit activation
const OP_TRUE = Buffer.from([0x51]);
const OP_FALSE = Buffer.from([0x00]);
const AMOUNT = 10_000n;
const THREADS = 4;
const WIDE = 2 * SCRIPTCHECK_BATCH_SIZE; // inputs of the first spend

let dir: string;
let db: ChainDB;
let uniq = 0;

beforeAll(async () => {
	dir = await mkdtemp(join(tmpdir(), "hotbuns-script-check-stream-"));
	db = new ChainDB(dir);
	await db.open();
});
afterAll(async () => {
	await db.close();
	await rm(dir, { recursive: true, force: true });
});
afterEach(async () => {
	globalSigCache.clear();
	await shutdownScriptCheckPool();
});

function coinbase(value: bigint): Transaction {
	return {
		version: 1,
		inputs: [
			{
				prevOut: { txid: Buffer.alloc(32, 0), vout: 0xffffffff },
				scriptSig: Buffer.from([0x02, HEIGHT & 0xff, (HEIGHT >> 8) & 0xff, 0x51]),
				sequence: 0xffffffff,
				witness: [],
			},
		],
		outputs: [{ value, scriptPubKey: OP_TRUE }],
		lockTime: 0,
	};
}

/** A fresh coin in `utxo`'s cache, locked by `spk`. */
function fund(utxo: UTXOManager, spk: Buffer, coinHeight = 1): { txid: Buffer; vout: number } {
	const txid = Buffer.alloc(32, 0);
	txid.writeUInt32LE(++uniq, 0);
	txid.writeUInt32LE(0x5eed, 28);
	utxo.getCoinsViewCache().addCoin(
		{ txid, vout: 0 },
		{ txOut: { value: AMOUNT, scriptPubKey: spk }, height: coinHeight, isCoinbase: false },
		false,
	);
	return { txid, vout: 0 };
}

function spend(
	prevOuts: { txid: Buffer; vout: number }[],
	outValue: bigint,
	sequence = 0xffffffff,
): Transaction {
	return {
		version: 2,
		inputs: prevOuts.map((prevOut) => ({
			prevOut,
			scriptSig: Buffer.alloc(0),
			sequence,
			witness: [],
		})),
		outputs: [{ value: outValue, scriptPubKey: OP_TRUE }],
		lockTime: 0,
	};
}

function block(txs: Transaction[]): Block {
	return {
		header: {
			version: 0x20000000,
			prevBlock: Buffer.alloc(32, 0xcd),
			merkleRoot: getTxId(txs[0]!),
			timestamp: 1_700_000_000,
			bits: REGTEST.powLimitBits,
			nonce: 0,
		},
		transactions: txs,
	};
}

/** Start the pool and wait until every worker is up (production steady state). */
async function warmPool(): Promise<void> {
	const utxo = new UTXOManager(db);
	const jobs = [];
	for (let i = 0; i < 16; i++) {
		const tx = spend([fund(utxo, OP_TRUE)], AMOUNT);
		jobs.push({
			tx,
			inputIndex: 0,
			utxos: [{ height: 1, coinbase: false, amount: AMOUNT, scriptPubKey: OP_TRUE }],
			flags: 0,
			txidHex: `warm${i}`,
		});
	}
	const r = await verifyScriptChecks(jobs, THREADS);
	expect(r.valid).toBe(true);
	globalSigCache.clear();
}

describe("script checks are fed to the workers during the tx loop", () => {
	it(
		"the workers hold checks of an earlier tx while the loop is still on a later tx",
		async () => {
			await warmPool();
			const utxo = new UTXOManager(db);
			const wide = spend(
				Array.from({ length: WIDE }, () => fund(utxo, OP_TRUE)),
				AMOUNT * BigInt(WIDE),
			);
			// One input with a time-based relative lock (1 x 512 s): the loop
			// asks getUTXOMTP for its coin, which is our probe inside the loop.
			const probeCoinHeight = 7;
			const late = spend(
				[fund(utxo, OP_TRUE, probeCoinHeight)],
				AMOUNT,
				SEQUENCE_LOCKTIME_TYPE_FLAG | 1,
			);
			const cb = coinbase(getBlockSubsidy(HEIGHT, REGTEST));
			let inFlightAtProbe = -1;
			scriptCheckResetStats();
			const res = await coreConnectBlockChecks(block([cb, wide, late]), HEIGHT, utxo, REGTEST, {
				scriptThreads: THREADS,
				enforceBIP68: true,
				prevMTP: 1_700_000_000,
				getUTXOMTP: (h: number) => {
					if (h === probeCoinHeight) inFlightAtProbe = scriptCheckPeakInFlightJobs();
					return 0;
				},
			});
			expect(res.ok).toBe(true);
			// master: 0, nothing reaches a worker until after the loop.
			expect(inFlightAtProbe).toBeGreaterThan(0);
		},
		{ timeout: 60_000 },
	);

	it(
		"a non-script failure still wins over a bad script that was already dispatched",
		async () => {
			await warmPool();
			const utxo = new UTXOManager(db);
			const prevOuts = Array.from({ length: WIDE }, (_, i) =>
				fund(utxo, i === 5 ? OP_FALSE : OP_TRUE),
			);
			const wide = spend(prevOuts, AMOUNT * BigInt(WIDE));
			// Coinbase pays 1 sat too much: Core rejects bad-cb-amount before
			// it Wait()s for the script threads.
			const cb = coinbase(getBlockSubsidy(HEIGHT, REGTEST) + 1n);
			const res = await coreConnectBlockChecks(block([cb, wide]), HEIGHT, utxo, REGTEST, {
				scriptThreads: THREADS,
			});
			expect(res.ok).toBe(false);
			expect(res.ok ? "" : res.error).toMatch(/^bad-cb-amount/);
			// The abandoned stream left the pool usable for the next block.
			await expect(verifyScriptChecks([], THREADS)).resolves.toEqual({ valid: true });
		},
		{ timeout: 60_000 },
	);

	it(
		"streamed and serial connects report the same earliest script failure",
		async () => {
			const errors: string[] = [];
			for (const threads of [1, THREADS]) {
				if (threads > 1) await warmPool();
				const utxo = new UTXOManager(db);
				const prevOuts = Array.from({ length: 3 * SCRIPTCHECK_BATCH_SIZE }, (_, i) =>
					fund(utxo, i === 140 || i === 300 ? OP_FALSE : OP_TRUE),
				);
				const txs = [coinbase(getBlockSubsidy(HEIGHT, REGTEST))];
				// One input per tx so the failing tx id says which index failed.
				for (const p of prevOuts) txs.push(spend([p], AMOUNT));
				const res = await coreConnectBlockChecks(block(txs), HEIGHT, utxo, REGTEST, {
					scriptThreads: threads,
				});
				expect(res.ok).toBe(false);
				const err = res.ok ? "" : res.error;
				// prevOuts[140] is spent by txs[141]; the txids differ per run.
				const first = getTxId(txs[141]!).toString("hex").slice(0, 16);
				expect(err).toContain(first);
				errors.push(err.replace(first, "<txs[141]>"));
				globalSigCache.clear();
			}
			expect(errors[1]).toBe(errors[0]);
		},
		{ timeout: 60_000 },
	);
});
