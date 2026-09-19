/**
 * Structured-clone wire format for script-check worker jobs.
 * Side-effect free — safe to import from both the main thread and workers.
 */

import type { UTXOEntry } from "../storage/database.js";
import type { Transaction } from "./tx.js";

export interface WireTxIn {
	prevOut: { txid: Uint8Array; vout: number };
	scriptSig: Uint8Array;
	sequence: number;
	witness: Uint8Array[];
}

export interface WireTxOut {
	value: bigint;
	scriptPubKey: Uint8Array;
}

export interface WireTx {
	version: number;
	inputs: WireTxIn[];
	outputs: WireTxOut[];
	lockTime: number;
}

export interface WireUtxo {
	height: number;
	coinbase: boolean;
	amount: bigint;
	scriptPubKey: Uint8Array;
}

export interface WireJob {
	txi: number;
	inputIndex: number;
	flags: number;
}

export interface WireBatch {
	kind: "batch";
	id: number;
	txs: WireTx[];
	/** UTXO vectors once per tx, not once per input (O(inputs) not O(inputs²)). */
	txUtxos: WireUtxo[][];
	jobs: WireJob[];
}

/** Jobs the main thread hands to {@link buildWireBatch}. */
export interface WireableJob {
	tx: Transaction;
	inputIndex: number;
	utxos: UTXOEntry[];
	flags: number;
}

/** Hard cap on one structured-clone payload. Also the default when no dbcache. */
export const MAX_SCRIPTCHECK_WIRE_BYTES = 8 * 1024 * 1024;

export interface WireStop {
	kind: "stop";
}

export interface WireResultItem {
	jobIndex: number;
	valid: boolean;
	inputIndex: number;
	error?: string;
}

export type WorkerIn = WireBatch | WireStop;
export type WorkerOut =
	| { kind: "ready" }
	| { kind: "result"; id: number; results: WireResultItem[] }
	| { kind: "crash"; id: number; error: string };

export function toU8(b: Buffer): Uint8Array {
	// Copy into a tight ArrayBuffer. Node/Bun Buffers often view an 8 KiB
	// pool slab; cloning the view's underlying buffer would ship the slab.
	const out = new Uint8Array(b.byteLength);
	out.set(b);
	return out;
}

export function fromU8(u: Uint8Array): Buffer {
	// Copy. Buffer.from(u.buffer, offset, len) is a VIEW of the structured-
	// clone ArrayBuffer the worker just received. FFI ptr() of that view is
	// dangling if the message backing store is recycled — the 340890 SIGSEGV
	// class. A tight copy severs the alias the same way toU8 does on send.
	const out = Buffer.allocUnsafe(u.byteLength);
	if (u.byteLength > 0) out.set(u);
	return out;
}

export function toWireTx(tx: Transaction): WireTx {
	return {
		version: tx.version,
		inputs: tx.inputs.map((inp) => ({
			prevOut: { txid: toU8(inp.prevOut.txid), vout: inp.prevOut.vout },
			scriptSig: toU8(inp.scriptSig),
			sequence: inp.sequence,
			witness: inp.witness.map(toU8),
		})),
		outputs: tx.outputs.map((out) => ({
			value: out.value,
			scriptPubKey: toU8(out.scriptPubKey),
		})),
		lockTime: tx.lockTime,
	};
}

export function toWireUtxo(u: UTXOEntry): WireUtxo {
	return {
		height: u.height,
		coinbase: u.coinbase,
		amount: u.amount,
		scriptPubKey: toU8(u.scriptPubKey),
	};
}

export function fromWireTx(w: WireTx): Transaction {
	return {
		version: w.version,
		inputs: w.inputs.map((inp) => ({
			prevOut: { txid: fromU8(inp.prevOut.txid), vout: inp.prevOut.vout },
			scriptSig: fromU8(inp.scriptSig),
			sequence: inp.sequence,
			witness: inp.witness.map(fromU8),
		})),
		outputs: w.outputs.map((out) => ({
			value: out.value,
			scriptPubKey: fromU8(out.scriptPubKey),
		})),
		lockTime: w.lockTime,
	};
}

export function fromWireUtxo(w: WireUtxo): UTXOEntry {
	return {
		height: w.height,
		coinbase: w.coinbase,
		amount: w.amount,
		scriptPubKey: fromU8(w.scriptPubKey),
	};
}

/**
 * Build a worker batch that stores each tx's UTXO vector once.
 * The previous per-job `utxos: job.utxos.map(toWireUtxo)` copied the full
 * prevout vector once per input — a 128-input tx became 16 384 UTXO clones
 * before structured-clone duplicated them into every worker isolate.
 */
export function buildWireBatch(id: number, chunk: WireableJob[]): WireBatch {
	const txMap = new Map<Transaction, number>();
	const txs: WireTx[] = [];
	const txUtxos: WireUtxo[][] = [];
	const jobs: WireJob[] = [];
	for (const job of chunk) {
		let txi = txMap.get(job.tx);
		if (txi === undefined) {
			txi = txs.length;
			txMap.set(job.tx, txi);
			txs.push(toWireTx(job.tx));
			txUtxos.push(job.utxos.map(toWireUtxo));
		}
		jobs.push({
			txi,
			inputIndex: job.inputIndex,
			flags: job.flags,
		});
	}
	return { kind: "batch", id, txs, txUtxos, jobs };
}

export function countWireUtxos(batch: WireBatch): number {
	let n = 0;
	for (const arr of batch.txUtxos) n += arr.length;
	return n;
}

export function estimateWireBatchBytes(batch: WireBatch): number {
	let n = 64;
	for (const tx of batch.txs) {
		n += 24;
		for (const inp of tx.inputs) {
			n += 40 + inp.scriptSig.byteLength;
			for (const w of inp.witness) n += w.byteLength;
		}
		for (const o of tx.outputs) n += 16 + o.scriptPubKey.byteLength;
	}
	for (const arr of batch.txUtxos) {
		for (const u of arr) n += 24 + u.scriptPubKey.byteLength;
	}
	n += batch.jobs.length * 16;
	return n;
}

/**
 * Split jobs so each structured-clone payload stays ≤ budget. Whole
 * transactions stay together when a single tx already fits.
 */
export function splitJobsByWireBudget(
	jobs: WireableJob[],
	budget: number,
): WireableJob[][] {
	if (jobs.length === 0) return [];
	const est = estimateWireBatchBytes(buildWireBatch(0, jobs));
	if (est <= budget || jobs.length === 1) return [jobs];
	const mid = Math.ceil(jobs.length / 2);
	return [
		...splitJobsByWireBudget(jobs.slice(0, mid), budget),
		...splitJobsByWireBudget(jobs.slice(mid), budget),
	];
}

const PACKED_MAGIC = 0x48425343; // 'HBSC'

function packedSize(batch: WireBatch): number {
	// Generous: encodePackedBatch slices to the bytes actually written.
	return estimateWireBatchBytes(batch) + 256;
}

/**
 * Pack a WireBatch into one ArrayBuffer so postMessage can transfer it
 * instead of structured-cloning the object graph (the clone was matching
 * P2PKH ECDSA wall time and hiding worker speedup).
 */
export function encodePackedBatch(batch: WireBatch): ArrayBuffer {
	const buf = new ArrayBuffer(packedSize(batch));
	const v = new DataView(buf);
	const u8 = new Uint8Array(buf);
	let o = 0;
	const wU32 = (x: number) => {
		v.setUint32(o, x >>> 0, true);
		o += 4;
	};
	const wI32 = (x: number) => {
		v.setInt32(o, x, true);
		o += 4;
	};
	const wU8 = (x: number) => {
		v.setUint8(o, x);
		o += 1;
	};
	const wU64 = (x: bigint) => {
		v.setBigUint64(o, x, true);
		o += 8;
	};
	const wBytes = (b: Uint8Array) => {
		wU32(b.byteLength);
		if (b.byteLength > 0) {
			u8.set(b, o);
			o += b.byteLength;
		}
	};

	wU32(PACKED_MAGIC);
	wU32(batch.id);
	wU32(batch.txs.length);
	for (const tx of batch.txs) {
		wI32(tx.version);
		wU32(tx.inputs.length);
		wU32(tx.outputs.length);
		wU32(tx.lockTime);
		for (const inp of tx.inputs) {
			if (inp.prevOut.txid.byteLength !== 32) {
				throw new Error("packed wire: txid must be 32 bytes");
			}
			u8.set(inp.prevOut.txid, o);
			o += 32;
			wU32(inp.prevOut.vout);
			wBytes(inp.scriptSig);
			wU32(inp.sequence);
			wU32(inp.witness.length);
			for (const w of inp.witness) wBytes(w);
		}
		for (const out of tx.outputs) {
			wU64(out.value);
			wBytes(out.scriptPubKey);
		}
	}
	wU32(batch.txUtxos.length);
	for (const arr of batch.txUtxos) {
		wU32(arr.length);
		for (const u of arr) {
			wU32(u.height);
			wU8(u.coinbase ? 1 : 0);
			wU64(u.amount);
			wBytes(u.scriptPubKey);
		}
	}
	wU32(batch.jobs.length);
	for (const job of batch.jobs) {
		wU32(job.txi);
		wU32(job.inputIndex);
		wU32(job.flags);
	}
	if (o !== buf.byteLength) {
		return buf.slice(0, o);
	}
	return buf;
}

export function decodePackedBatch(buf: ArrayBuffer): WireBatch {
	const v = new DataView(buf);
	const u8 = new Uint8Array(buf);
	let o = 0;
	const need = (n: number) => {
		if (o + n > buf.byteLength) {
			throw new Error("packed wire: truncated");
		}
	};
	const rU32 = () => {
		need(4);
		const x = v.getUint32(o, true);
		o += 4;
		return x;
	};
	const rI32 = () => {
		need(4);
		const x = v.getInt32(o, true);
		o += 4;
		return x;
	};
	const rU8 = () => {
		need(1);
		const x = v.getUint8(o);
		o += 1;
		return x;
	};
	const rU64 = () => {
		need(8);
		const x = v.getBigUint64(o, true);
		o += 8;
		return x;
	};
	const rBytes = (): Uint8Array => {
		const n = rU32();
		need(n);
		const out = u8.subarray(o, o + n);
		o += n;
		return out;
	};
	const rTxid = (): Uint8Array => {
		need(32);
		const out = u8.subarray(o, o + 32);
		o += 32;
		return out;
	};

	if (rU32() !== PACKED_MAGIC) {
		throw new Error("packed wire: bad magic");
	}
	const id = rU32();
	const nTx = rU32();
	const txs: WireTx[] = [];
	for (let i = 0; i < nTx; i++) {
		const version = rI32();
		const nIn = rU32();
		const nOut = rU32();
		const lockTime = rU32();
		const inputs: WireTxIn[] = [];
		for (let j = 0; j < nIn; j++) {
			const txid = rTxid();
			const vout = rU32();
			const scriptSig = rBytes();
			const sequence = rU32();
			const nWit = rU32();
			const witness: Uint8Array[] = [];
			for (let k = 0; k < nWit; k++) witness.push(rBytes());
			inputs.push({ prevOut: { txid, vout }, scriptSig, sequence, witness });
		}
		const outputs: WireTxOut[] = [];
		for (let j = 0; j < nOut; j++) {
			outputs.push({ value: rU64(), scriptPubKey: rBytes() });
		}
		txs.push({ version, inputs, outputs, lockTime });
	}
	const nGroups = rU32();
	const txUtxos: WireUtxo[][] = [];
	for (let i = 0; i < nGroups; i++) {
		const n = rU32();
		const arr: WireUtxo[] = [];
		for (let j = 0; j < n; j++) {
			arr.push({
				height: rU32(),
				coinbase: rU8() !== 0,
				amount: rU64(),
				scriptPubKey: rBytes(),
			});
		}
		txUtxos.push(arr);
	}
	const nJobs = rU32();
	const jobs: WireJob[] = [];
	for (let i = 0; i < nJobs; i++) {
		jobs.push({ txi: rU32(), inputIndex: rU32(), flags: rU32() });
	}
	return { kind: "batch", id, txs, txUtxos, jobs };
}

/** In-flight wire budget: 1–8 MiB, and never more than a quarter of dbcache. */
export function scriptCheckWireBudget(cacheBytes?: number): number {
	if (typeof cacheBytes === "number" && cacheBytes > 0) {
		return Math.max(
			1024 * 1024,
			Math.min(MAX_SCRIPTCHECK_WIRE_BYTES, Math.floor(cacheBytes / 4)),
		);
	}
	return MAX_SCRIPTCHECK_WIRE_BYTES;
}
