/**
 * BIP-342 OP_SUCCESSx pre-scan must parse the leaf with GetOp semantics.
 *
 * Core (src/script/interpreter.cpp, ExecuteWitnessScript, tapscript branch):
 *
 *   while (pc < script.end()) {
 *     if (!script.GetOp(pc, opcode)) return set_error(serror, SCRIPT_ERR_BAD_OPCODE);
 *     if (IsOpSuccess(opcode)) { ... return set_success(serror); }
 *   }
 *
 * GetScriptOp (src/script/script.cpp) reads PUSHDATA1/2/4 lengths as
 * UNSIGNED and fails when the length field or the payload runs past the end
 * of the script. A truncated push therefore ends the scan with BAD_OPCODE
 * before any later byte is looked at.
 *
 * hotbuns' `containsOpSuccess` used to fall through when a PUSHDATA length
 * field was incomplete and scan the length bytes as opcodes, so leaf `4d 50`
 * (PUSHDATA2 with one length byte, 0x50 = OP_RESERVED = OP_SUCCESS80)
 * returned OP_SUCCESS and the spend was VALID where Core says BAD_OPCODE.
 * It also read the PUSHDATA4 length as a signed int32 with no bounds check:
 * leaf `4e fb ff ff ff` gives len = -5 and `i += 4 + len` puts i back at 0,
 * an infinite loop in block validation.
 *
 * Fingerprint: hotbuns:script/interpreter.ts:containsOpSuccess:malformed-push-scan
 */

import { describe, expect, test } from "bun:test";
import { resolve } from "node:path";
import {
  verifyTaproot,
  type ScriptFlags,
  type TaprootContext,
} from "../script/interpreter.js";
import {
  taggedHash,
  privateKeyToXOnlyPubKey,
  tweakPublicKey,
} from "../crypto/primitives.js";

const TAPROOT_LEAF_TAPSCRIPT = 0xc0;

function consensusTaprootFlags(): ScriptFlags {
  return {
    verifyP2SH: true,
    verifyWitness: true,
    verifyTaproot: true,
    verifyStrictEncoding: false,
    verifyDERSignatures: true,
    verifyLowS: false,
    verifyNullDummy: true,
    verifyNullFail: true,
    verifyCheckLockTimeVerify: true,
    verifyCheckSequenceVerify: true,
    verifyWitnessPubkeyType: true,
  };
}

const dummyTaprootCtx = (): TaprootContext => ({
  keyPathSigHasher: () => Buffer.alloc(32),
  scriptPathSigHasher: () => Buffer.alloc(32),
});

/**
 * Verify a single-leaf P2TR script-path spend of `leafHex` with an empty
 * witness argument stack (witness = [leaf, controlBlock]). Returns the
 * verifyTaproot result for the committed parity, or rethrows its error.
 */
function verifyLeaf(leafHex: string): boolean {
  const leaf = Buffer.from(leafHex, "hex");
  const internalPriv = Buffer.alloc(32, 0);
  internalPriv[31] = 0x23;
  const internalPub = privateKeyToXOnlyPubKey(internalPriv);
  if (leaf.length >= 0xfd) throw new Error("fixture: leaf too long");
  const leafHash = taggedHash(
    "TapLeaf",
    Buffer.concat([Buffer.from([TAPROOT_LEAF_TAPSCRIPT, leaf.length]), leaf])
  );
  const tweak = taggedHash("TapTweak", Buffer.concat([internalPub, leafHash]));
  const spk = Buffer.concat([Buffer.from([0x51, 0x20]), tweakPublicKey(internalPub, tweak)]);

  let committedErr: unknown;
  for (const parity of [0, 1]) {
    const witness = [
      leaf,
      Buffer.concat([Buffer.from([TAPROOT_LEAF_TAPSCRIPT | parity]), internalPub]),
    ];
    try {
      return verifyTaproot(spk, witness, consensusTaprootFlags(), dummyTaprootCtx());
    } catch (e) {
      if ((e as Error).message.includes("WITNESS_PROGRAM_MISMATCH")) continue;
      committedErr = e;
    }
  }
  if (committedErr) throw committedErr;
  throw new Error("fixture broken: neither parity committed to the leaf");
}

/** "ok:<bool>" or "err:<message>" — the verdict as a comparable string. */
function verdict(leafHex: string): string {
  try {
    return `ok:${verifyLeaf(leafHex)}`;
  } catch (e) {
    return `err:${(e as Error).message}`;
  }
}

// When run as a child process (see the hang test), print the verdict and exit.
if (process.env.CFFIX_PRESCAN_CHILD_LEAF) {
  console.log(`VERDICT ${verdict(process.env.CFFIX_PRESCAN_CHILD_LEAF)}`);
  process.exit(0);
}

describe("BIP-342 OP_SUCCESS pre-scan uses GetOp parsing (cffix-hotbuns-tapscript-opsuccess-prescan)", () => {
  test("leaf 4d 50 (truncated PUSHDATA2 length, then 0x50) fails with BAD_OPCODE", () => {
    expect(verdict("4d50")).toBe("err:SCRIPT_ERR_BAD_OPCODE");
  });

  test("leaf 4e fb ff ff ff (PUSHDATA4 len 0xfffffffb) fails with BAD_OPCODE within 2 s", () => {
    // A synchronous infinite loop cannot be preempted by bun's test timeout,
    // so run the verification in a child process with a hard 2 s kill.
    const child = Bun.spawnSync({
      cmd: [process.execPath, resolve(import.meta.path)],
      env: { ...process.env, CFFIX_PRESCAN_CHILD_LEAF: "4efbffffff" },
      stdout: "pipe",
      stderr: "pipe",
      timeout: 2000,
    });
    const out = child.stdout.toString();
    const line = out.split("\n").find((l) => l.startsWith("VERDICT ")) ?? "<no verdict: child hung or crashed>";
    expect(line).toBe("VERDICT err:SCRIPT_ERR_BAD_OPCODE");
  });

  // Controls — well-formed OP_SUCCESS must still succeed.
  test("control: leaf 50 (OP_SUCCESS80) succeeds", () => {
    expect(verdict("50")).toBe("ok:true");
  });

  test("control: leaf 4d 00 00 50 (zero-length PUSHDATA2, then OP_SUCCESS80) succeeds", () => {
    expect(verdict("4d000050")).toBe("ok:true");
  });

  test("control: OP_SUCCESS before a truncated push still succeeds (Core scans in order)", () => {
    // 50 4d — GetOp reaches 0x50 first and returns success before the bad push.
    expect(verdict("504d")).toBe("ok:true");
  });

  test("control: well-formed PUSHDATA1/2/4 pushes whose payload bytes look like OP_SUCCESS are skipped", () => {
    // PUSHDATA1 len 1 [0x50], PUSHDATA2 len 1 [0x50], PUSHDATA4 len 1 [0x50],
    // then OP_DROP x3 OP_1: no OP_SUCCESS opcode, clean true.
    expect(verdict("4c0150" + "4d010050" + "4e0100000050" + "757575" + "51")).toBe("ok:true");
  });

  test("truncated direct push (03 aa) fails with BAD_OPCODE (was a bare false: invalid either way, error code now Core's)", () => {
    expect(verdict("03aa")).toBe("err:SCRIPT_ERR_BAD_OPCODE");
  });
});
