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
	utxos: WireUtxo[];
	flags: number;
}

export interface WireBatch {
	kind: "batch";
	id: number;
	txs: WireTx[];
	jobs: WireJob[];
}

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
	return Buffer.isBuffer(u)
		? u
		: Buffer.from(u.buffer, u.byteOffset, u.byteLength);
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
