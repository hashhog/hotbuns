/**
 * Arithmetic tx/block sizes must equal the serialized lengths they replace.
 *
 * validateBlock's weight check (Core CheckBlock: GetBlockWeight >
 * MAX_BLOCK_WEIGHT) and validateTxBasic's bad-txns-oversize gate
 * (Core CheckTransaction) now use getTxBaseSize/getTxTotalSize instead of
 * serializing. This pins them to serializeTx/serializeBlock byte-for-byte,
 * including CompactSize boundaries (252/253, 65535/65536), witness present,
 * absent, and present-but-all-empty (which serializes WITHOUT marker/flag).
 *
 * Control: HOTBUNS_UNIT_CHILD=1 bun test ./src/validation/size-arith.test.ts
 */
import { describe, expect, it } from "bun:test";
import {
	getBlockBaseSize,
	getBlockTotalSize,
	getBlockWeight,
	serializeBlock,
	type Block,
} from "./block.js";
import {
	getTxBaseSize,
	getTxTotalSize,
	serializeTx,
	type Transaction,
} from "./tx.js";

let seed = 20260925;
const rnd = (n: number) => {
	seed = (seed * 1103515245 + 12345) & 0x7fffffff;
	return (seed >>> 8) % n;
};
const LENS = [0, 1, 20, 72, 252, 253, 254, 300, 65535, 65536, 70000];
let bigLens = true;
const len = () => (bigLens && rnd(4) === 0 ? LENS[rnd(LENS.length)]! : rnd(120));

function randTx(big = true): Transaction {
	const nIn = big && rnd(5) === 0 ? 253 + rnd(3) : 1 + rnd(6);
	const nOut = big && rnd(7) === 0 ? 252 + rnd(3) : 1 + rnd(4);
	const witnessMode = rnd(3); // 0 none, 1 some, 2 all-empty stacks
	return {
		version: rnd(2) ? 2 : -1,
		inputs: Array.from({ length: nIn }, () => ({
			prevOut: { txid: Buffer.alloc(32, rnd(256)), vout: rnd(1 << 30) },
			scriptSig: Buffer.alloc(len(), 1),
			sequence: 0xffffffff,
			witness:
				witnessMode === 1 && rnd(2)
					? Array.from({ length: rnd(4) }, () => Buffer.alloc(len(), 2))
					: [],
		})),
		outputs: Array.from({ length: nOut }, () => ({
			value: BigInt(rnd(1e9)),
			scriptPubKey: Buffer.alloc(len(), 3),
		})),
		lockTime: rnd(1 << 30),
	};
}

describe("arithmetic sizes == serialized lengths", () => {
	it("per tx, 600 random txs", () => {
		let withWitness = 0;
		let emptyStacksOnly = 0;
		for (let i = 0; i < 600; i++) {
			const tx = randTx();
			if (tx.inputs.some((x) => x.witness.length > 0)) withWitness++;
			else emptyStacksOnly++;
			expect(getTxBaseSize(tx)).toBe(serializeTx(tx, false).length);
			expect(getTxTotalSize(tx)).toBe(serializeTx(tx, true).length);
		}
		// Denominator: both serializations must actually be exercised.
		expect(withWitness).toBeGreaterThan(50);
		expect(emptyStacksOnly).toBeGreaterThan(50);
	});

	it("per block incl. CompactSize tx-count boundaries", () => {
		for (const nTx of [1, 3, 252, 253, 254]) {
			const block: Block = {
				header: {
					version: 0x20000000,
					prevBlock: Buffer.alloc(32),
					merkleRoot: Buffer.alloc(32),
					timestamp: 1,
					bits: 0x1d00ffff,
					nonce: 0,
				},
				transactions: Array.from({ length: nTx }, (_, i) => {
					bigLens = i < 3;
					return randTx(i < 3);
				}),
			};
			const full = serializeBlock(block).length;
			const stripped =
				80 +
				(nTx <= 0xfc ? 1 : 3) +
				block.transactions.reduce((a, t) => a + serializeTx(t, false).length, 0);
			expect(getBlockTotalSize(block)).toBe(full);
			expect(getBlockBaseSize(block)).toBe(stripped);
			expect(getBlockWeight(block)).toBe(stripped * 3 + full);
		}
	});
});
