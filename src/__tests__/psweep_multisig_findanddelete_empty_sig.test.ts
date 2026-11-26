/**
 * Legacy (SigVersion::BASE) OP_CHECKMULTISIG / OP_CHECKSIG must run
 * FindAndDelete for an EMPTY signature too.
 *
 * Core v31.1 src/script/interpreter.cpp, OP_CHECKMULTISIG:
 *
 *     for (int k = 0; k < nSigsCount; k++) {
 *         valtype& vchSig = stacktop(-isig-k);
 *         if (sigversion == SigVersion::BASE) {
 *             int found = FindAndDelete(scriptCode, CScript() << vchSig);
 *             if (found > 0 && (flags & SCRIPT_VERIFY_CONST_SCRIPTCODE))
 *                 return set_error(serror, SCRIPT_ERR_SIG_FINDANDDELETE);
 *         }
 *     }
 *
 * and the same in EvalChecksigPreTapscript. `CScript() << vchSig` for an
 * empty vchSig is the one byte 0x00 (OP_0), so an empty sig removes every
 * opcode-aligned OP_0 from scriptCode before any signature is checked. That
 * changes the legacy sighash of every OTHER signature in the same multisig.
 *
 * hotbuns' findAndDelete returned `found: 0` at once for an empty sig, so it
 * hashed a scriptCode that still held the OP_0. Two consensus splits follow
 * (block flags, nothing policy):
 *
 *   forward: Core rejects (SIG_DER), hotbuns accepted.
 *   reverse: Core accepts, hotbuns rejected (SIG_DER).
 *
 * Control: HOTBUNS_UNIT_CHILD=1 bun test ./src/__tests__/psweep_multisig_findanddelete_empty_sig.test.ts
 */
import { describe, expect, test } from "bun:test";
import { ecdsaSign, privateKeyToPublicKey, sha256Hash } from "../crypto/primitives.js";
import {
	executeScript,
	parseScript,
	ScriptError,
	SigVersion,
	type ExecutionContext,
	type ScriptFlags as InterpFlags,
} from "../script/interpreter.js";
import {
	ScriptFlags,
	SIGHASH_ALL,
	setInputSigCacheEnabled,
	sigHashLegacy,
	sigHashWitnessV0,
	type Transaction,
	verifyInputSignature,
} from "../validation/tx.js";

// Block (consensus) flags, as getScriptFlagsForBlock sets them on a modern
// regtest/mainnet block. No policy bit (NULLFAIL, CONST_SCRIPTCODE, ...).
const BLOCK_FLAGS =
	ScriptFlags.VERIFY_P2SH |
	ScriptFlags.VERIFY_WITNESS |
	ScriptFlags.VERIFY_TAPROOT |
	ScriptFlags.VERIFY_DERSIG |
	ScriptFlags.VERIFY_NULLDUMMY |
	ScriptFlags.VERIFY_CHECKLOCKTIMEVERIFY |
	ScriptFlags.VERIFY_CHECKSEQUENCEVERIFY;

const PRIVS = [1, 2, 3, 4].map((b) => Buffer.alloc(32, b));
const PUBS = PRIVS.map((p) => privateKeyToPublicKey(p, true));

const h = (s: string) => Buffer.from(s, "hex");
const push = (b: Buffer) => {
	if (b.length >= 76) throw new Error("test helper only does direct pushes");
	return Buffer.concat([Buffer.from([b.length]), b]);
};
const pushKeys = (keys: Buffer[]) => Buffer.concat(keys.map(push));

/** Opcode-aligned removal of every OP_0 — what Core's FindAndDelete(scriptCode, CScript() << {}) does. */
function coreDropOp0(script: Buffer): Buffer {
	const out: number[] = [];
	let i = 0;
	while (i < script.length) {
		const op = script[i]!;
		if (op === 0x00) {
			i += 1;
			continue;
		}
		const end = op >= 0x01 && op <= 0x4b ? i + 1 + op : i + 1; // test scripts use only direct pushes
		for (let j = i; j < end; j++) out.push(script[j]!);
		i = end;
	}
	return Buffer.from(out);
}

function spendTx(scriptSig: Buffer): Transaction {
	return {
		version: 1,
		inputs: [
			{
				prevOut: { txid: Buffer.alloc(32, 0x5a), vout: 0 },
				scriptSig,
				sequence: 0xffffffff,
				witness: [],
			},
		],
		outputs: [{ value: 49_000n, scriptPubKey: h("51") }],
		lockTime: 0,
	};
}

/** Sign input 0 of a tx whose scriptSig is not yet known (legacy sighash ignores it). */
function sign(scriptCode: Buffer, priv: Buffer): Buffer {
	const sighash = sigHashLegacy(spendTx(Buffer.alloc(0)), 0, scriptCode, SIGHASH_ALL);
	return Buffer.concat([ecdsaSign(sighash, priv), Buffer.from([SIGHASH_ALL])]);
}

function verifyBlock(scriptPubKey: Buffer, scriptSig: Buffer) {
	setInputSigCacheEnabled(false);
	const tx = spendTx(scriptSig);
	const utxo = { height: 1, coinbase: false, amount: 50_000n, scriptPubKey };
	return verifyInputSignature(tx, 0, utxo, {}, [utxo], {}, BLOCK_FLAGS);
}

// scriptPubKey 00 75 53 <pk1> <pk2> <pk3> <pk4> 54 ae 91 (the item's input)
const FWD_SPK = Buffer.concat([
	h("007553"),
	pushKeys(PUBS),
	h("54ae91"),
]);
// scriptPubKey 00 75 53 <pk1> <pk2> <pk3> 53 ae 91 (3-of-3, reverse case)
const REV_SPK = Buffer.concat([
	h("007553"),
	pushKeys(PUBS.slice(0, 3)),
	h("53ae91"),
]);

describe("legacy CHECKMULTISIG FindAndDelete of an empty sig (block flags)", () => {
	test("forward: S valid over Core's scriptCode, then sig 01 -> SIG_DER (Core rejects the block)", () => {
		// Core: sigs (top first) = S, 01, <empty>. FindAndDelete(<empty>)
		// drops the leading OP_0, S verifies against pk4, the next sig 01
		// reaches CheckSignatureEncoding -> SCRIPT_ERR_SIG_DER.
		const S = sign(coreDropOp0(FWD_SPK), PRIVS[3]!);
		const scriptSig = Buffer.concat([h("00" + "00" + "0101"), push(S)]);
		const r = verifyBlock(FWD_SPK, scriptSig);
		expect(r.valid).toBe(false);
		expect(r.error ?? "").toContain("SIG_DER");
	});

	test("reverse: S valid only over the OP_0-bearing scriptCode -> CHECKMULTISIG false, OP_NOT -> true (Core accepts)", () => {
		// Core hashes the scriptCode WITHOUT the OP_0, so S (signed over the
		// full script) fails against pk3; 3 sigs are then left for 2 keys,
		// the multisig is false, OP_NOT makes it true. The sig 01 is never
		// reached, so its bad DER is never checked.
		const S = sign(REV_SPK, PRIVS[2]!);
		const scriptSig = Buffer.concat([h("00" + "00" + "0101"), push(S)]);
		const r = verifyBlock(REV_SPK, scriptSig);
		expect(r.error).toBeUndefined();
		expect(r.valid).toBe(true);
	});

	test("every opcode-aligned OP_0 goes, not only the first", () => {
		// Two OP_0 DROP pairs. Core's scriptCode has both removed.
		const spk = Buffer.concat([h("0075"), FWD_SPK.subarray(0, FWD_SPK.length - 1), h("0075"), h("91")]);
		const S = sign(coreDropOp0(spk), PRIVS[3]!);
		const scriptSig = Buffer.concat([h("00" + "00" + "0101"), push(S)]);
		const r = verifyBlock(spk, scriptSig);
		expect(r.valid).toBe(false);
		expect(r.error ?? "").toContain("SIG_DER");
	});

	test("control: 00 bytes inside a push payload are NOT deleted (opcode-aligned scan)", () => {
		// 02 0000 75: the zero bytes are push data, not OP_0. Core keeps them,
		// so S must be signed over the full script; it verifies against pk4
		// and the 01 sig then fails DER, on master and on the fix alike.
		const spk = Buffer.concat([h("02000075"), FWD_SPK.subarray(2)]);
		const S = sign(spk, PRIVS[3]!);
		const scriptSig = Buffer.concat([h("00" + "00" + "0101"), push(S)]);
		const r = verifyBlock(spk, scriptSig);
		expect(r.valid).toBe(false);
		expect(r.error ?? "").toContain("SIG_DER");
	});

	test("control: witness v0 (P2WSH) does no FindAndDelete, so the OP_0 stays in the BIP143 scriptCode", () => {
		// Same script as the forward case, as a witnessScript. S is signed
		// over the FULL witnessScript (BIP143 has no FindAndDelete), so it
		// verifies against pk4 and the 01 sig then fails DER. If the empty-sig
		// deletion leaked into witness v0, S would fail, the multisig would
		// be false and OP_NOT would turn a Core-invalid spend valid.
		setInputSigCacheEnabled(false);
		const ws = FWD_SPK;
		const spk = Buffer.concat([h("0020"), sha256Hash(ws)]);
		const amount = 50_000n;
		const tx = spendTx(Buffer.alloc(0));
		const S = Buffer.concat([
			ecdsaSign(sigHashWitnessV0(tx, 0, ws, amount, SIGHASH_ALL), PRIVS[3]!),
			Buffer.from([SIGHASH_ALL]),
		]);
		tx.inputs[0]!.witness = [Buffer.alloc(0), Buffer.alloc(0), h("01"), S, ws];
		const utxo = { height: 1, coinbase: false, amount, scriptPubKey: spk };
		const r = verifyInputSignature(tx, 0, utxo, {}, [utxo], {}, BLOCK_FLAGS);
		expect(r.valid).toBe(false);
		expect(r.error ?? "").toContain("SIG_DER");
	});

	test("control: an ordinary 2-of-2 bare multisig with no OP_0 in scriptCode is unchanged", () => {
		const spk = Buffer.concat([h("52"), pushKeys(PUBS.slice(0, 2)), h("52ae")]);
		const s1 = sign(spk, PRIVS[0]!);
		const s2 = sign(spk, PRIVS[1]!);
		expect(verifyBlock(spk, Buffer.concat([h("00"), push(s1), push(s2)])).valid).toBe(true);
		// Wrong order (s2 before s1 on the stack) still fails, as in Core.
		expect(verifyBlock(spk, Buffer.concat([h("00"), push(s2), push(s1)])).valid).toBe(false);
	});
});

// ---------------------------------------------------------------------------
// SCRIPT_VERIFY_CONST_SCRIPTCODE (policy): the deletion of an OP_0 by an empty
// sig counts as found > 0, in CHECKSIG and in CHECKMULTISIG.
// ---------------------------------------------------------------------------

function policyFlags(constScriptCode: boolean): InterpFlags {
	return {
		verifyP2SH: true,
		verifyWitness: true,
		verifyTaproot: true,
		verifyStrictEncoding: true,
		verifyDERSignatures: true,
		verifyLowS: true,
		verifyNullDummy: true,
		verifyNullFail: true,
		verifyCheckLockTimeVerify: true,
		verifyCheckSequenceVerify: true,
		verifyWitnessPubkeyType: true,
		verifyConstScriptCode: constScriptCode,
	};
}

function runBase(script: Buffer, stack: Buffer[], constScriptCode: boolean): { ok?: boolean; err?: string } {
	const ctx: ExecutionContext = {
		stack,
		altStack: [],
		flags: policyFlags(constScriptCode),
		sigHasher: () => Buffer.alloc(32, 0x11),
		sigVersion: SigVersion.BASE,
	};
	try {
		return { ok: executeScript(parseScript(script), ctx) };
	} catch (e) {
		if (e instanceof ScriptError) return { err: e.code };
		throw e;
	}
}

describe("CONST_SCRIPTCODE counts an empty sig's OP_0 deletion", () => {
	test("CHECKSIG: empty sig over scriptCode holding OP_0 -> SIG_FINDANDDELETE", () => {
		// Script: OP_0 OP_DROP <pk> CHECKSIG, stack [<empty sig>]
		const script = Buffer.concat([h("0075"), push(PUBS[0]!), h("ac")]);
		expect(runBase(script, [Buffer.alloc(0)], true).err).toBe("SIG_FINDANDDELETE");
	});

	test("CHECKMULTISIG: empty sig over scriptCode holding OP_0 -> SIG_FINDANDDELETE", () => {
		// Script: OP_0 OP_DROP 1 <pk> 1 CHECKMULTISIG, stack [<dummy>, <empty sig>]
		const script = Buffer.concat([h("007551"), push(PUBS[0]!), h("51ae")]);
		expect(runBase(script, [Buffer.alloc(0), Buffer.alloc(0)], true).err).toBe("SIG_FINDANDDELETE");
	});

	test("control: no OP_0 in scriptCode -> no SIG_FINDANDDELETE for an empty sig", () => {
		const cs = Buffer.concat([push(PUBS[0]!), h("ac")]);
		expect(runBase(cs, [Buffer.alloc(0)], true)).toEqual({ ok: true });
		const cms = Buffer.concat([h("51"), push(PUBS[0]!), h("51ae")]);
		expect(runBase(cms, [Buffer.alloc(0), Buffer.alloc(0)], true)).toEqual({ ok: true });
	});

	test("control: without CONST_SCRIPTCODE the empty sig is just a failed check", () => {
		const script = Buffer.concat([h("0075"), push(PUBS[0]!), h("ac")]);
		expect(runBase(script, [Buffer.alloc(0)], false)).toEqual({ ok: true });
	});
});
