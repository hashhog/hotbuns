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

/**
 * Exact byte length of {@link encodePackedBatch}'s output.
 *
 * This used to be an estimate (40 B/input, witness items without their
 * 4-byte length prefix) padded by a fixed 256 B. A tx with more than ~50
 * two-item witness inputs overran the padding, so encodePackedBatch threw
 * "Out of bounds access" / "Range consisting of offset and length are out of
 * bounds" and the WHOLE block fell back to serial verification on the main
 * thread — observed on 23,914 of ~34,000 blocks in the 515000 R4 slice.
 * The size is now computed field-for-field against the encoder below.
 */
export const PACKED_HEADER_BYTES = 20; // magic + id + nTx + nGroups + nJobs
export const PACKED_JOB_BYTES = 12; // txi + inputIndex + flags

/** Packed bytes for one tx (Transaction or WireTx — same field shapes). */
export function packedTxBytes(tx: {
	inputs: ReadonlyArray<{ scriptSig: Uint8Array; witness: ReadonlyArray<Uint8Array> }>;
	outputs: ReadonlyArray<{ scriptPubKey: Uint8Array }>;
}): number {
	let n = 16; // version + nIn + nOut + lockTime
	for (const inp of tx.inputs) {
		// txid 32 + vout 4 + scriptSig len 4 + sequence 4 + nWit 4
		n += 48 + inp.scriptSig.byteLength;
		for (const w of inp.witness) n += 4 + w.byteLength;
	}
	for (const o of tx.outputs) n += 12 + o.scriptPubKey.byteLength;
	return n;
}

/** Packed bytes for one tx's UTXO vector (UTXOEntry or WireUtxo). */
export function packedUtxosBytes(
	utxos: ReadonlyArray<{ scriptPubKey: Uint8Array }>,
): number {
	let n = 4; // group length
	for (const u of utxos) n += 17 + u.scriptPubKey.byteLength; // h4 cb1 amt8 len4
	return n;
}

export function estimateWireBatchBytes(batch: WireBatch): number {
	let n = PACKED_HEADER_BYTES;
	for (const tx of batch.txs) n += packedTxBytes(tx);
	for (const arr of batch.txUtxos) n += packedUtxosBytes(arr);
	n += batch.jobs.length * PACKED_JOB_BYTES;
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
	return estimateWireBatchBytes(batch);
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
		// packedSize is exact; a mismatch means the encoder and the sizer
		// drifted apart. Throw (the queue falls back to serial) rather than
		// ship a buffer with trailing garbage.
		throw new Error(`packed wire: wrote ${o} of ${buf.byteLength} bytes`);
	}
	return buf;
}

/**
 * Encode jobs straight to the packed format, byte-identical to
 * `encodePackedBatch(buildWireBatch(id, chunk))`.
 *
 * The two-step path first copied every input's txid/scriptSig/witness item
 * and every prevout script into fresh Uint8Arrays (toWireTx/toWireUtxo), only
 * to copy them again into the ArrayBuffer — 11-14% of main-thread time in the
 * 515000 R4 slice profile once the pool was reached. Buffers are Uint8Arrays,
 * so they are written into the transfer buffer directly. The transfer buffer
 * is a fresh ArrayBuffer either way: nothing the worker sees aliases a
 * main-thread Buffer (the property toU8 existed to guarantee).
 */
export function encodePackedJobs(id: number, chunk: WireableJob[]): ArrayBuffer {
	const txIndex = new Map<Transaction, number>();
	const txs: Transaction[] = [];
	const txUtxos: UTXOEntry[][] = [];
	let size = PACKED_HEADER_BYTES + chunk.length * PACKED_JOB_BYTES;
	for (const job of chunk) {
		if (!txIndex.has(job.tx)) {
			txIndex.set(job.tx, txs.length);
			txs.push(job.tx);
			txUtxos.push(job.utxos);
			size += packedTxBytes(job.tx) + packedUtxosBytes(job.utxos);
		}
	}
	const buf = new ArrayBuffer(size);
	const v = new DataView(buf);
	const u8 = new Uint8Array(buf);
	let o = 0;
	const wU32 = (x: number) => {
		v.setUint32(o, x >>> 0, true);
		o += 4;
	};
	const wBytes = (b: Uint8Array) => {
		v.setUint32(o, b.byteLength, true);
		o += 4;
		if (b.byteLength > 0) {
			u8.set(b, o);
			o += b.byteLength;
		}
	};
	wU32(PACKED_MAGIC);
	wU32(id);
	wU32(txs.length);
	for (const tx of txs) {
		v.setInt32(o, tx.version, true);
		o += 4;
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
			v.setBigUint64(o, out.value, true);
			o += 8;
			wBytes(out.scriptPubKey);
		}
	}
	wU32(txUtxos.length);
	for (const arr of txUtxos) {
		wU32(arr.length);
		for (const u of arr) {
			wU32(u.height);
			v.setUint8(o, u.coinbase ? 1 : 0);
			o += 1;
			v.setBigUint64(o, u.amount, true);
			o += 8;
			wBytes(u.scriptPubKey);
		}
	}
	wU32(chunk.length);
	for (const job of chunk) {
		wU32(txIndex.get(job.tx)!);
		wU32(job.inputIndex);
		wU32(job.flags);
	}
	if (o !== size) {
		throw new Error(`packed wire: wrote ${o} of ${size} bytes`);
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
