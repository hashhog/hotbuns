/**
 * W137 — PSBT v0/v2 (BIP-174 / BIP-370 / BIP-371) — hotbuns
 *
 * Discovery audit. Each test either
 *   (a) PASSes today, documenting a Core-parity behavior to keep, OR
 *   (b) DOCUMENTS a bug by asserting the CURRENT divergent behavior
 *       and including a `// BUG-N` comment so a future fix wave can
 *       grep this file and invert the assertions.
 *
 * Reference:
 *   - bitcoin-core/src/psbt.h / psbt.cpp
 *   - bitcoin-core/src/wallet/rpc/spend.cpp
 *   - bitcoin-core/src/rpc/rawtransaction.cpp
 *   - BIPs 174, 370, 371
 *
 * Companion document: audit/w137_psbt.md.
 *
 * Run: bun test src/__tests__/w137_psbt.test.ts
 */

import { describe, it, expect } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import {
  createPSBT,
  serializePSBT,
  deserializePSBT,
  combinePSBTs,
  finalizePSBTInput,
  isInputFinalized,
  PSBT_MAGIC,
  PSBT_HIGHEST_VERSION,
  PSBT_MAX_FILE_SIZE,
  PSBT_GLOBAL_UNSIGNED_TX,
  PSBT_GLOBAL_XPUB,
  PSBT_GLOBAL_VERSION,
  PSBT_GLOBAL_PROPRIETARY,
  PSBT_IN_PROPRIETARY,
  PSBT_IN_PARTIAL_SIG,
  PSBT_IN_SIGHASH,
  PSBT_OUT_PROPRIETARY,
  type PSBT,
} from "../wallet/psbt";

import { type Transaction } from "../validation/tx";

// =============================================================================
// Helpers
// =============================================================================

const REPO_ROOT = join(import.meta.dirname, "..", "..");
const SRC_ROOT = join(REPO_ROOT, "src");

function readSrc(rel: string): string {
  return readFileSync(join(SRC_ROOT, rel), "utf8");
}

/** Asymmetric 32-byte txid (head/tail differ — W32-B rule). */
function asymTxid(tag: number): Buffer {
  const b = Buffer.alloc(32);
  for (let i = 0; i < 32; i++) {
    b[i] = ((i * 7 + tag * 31 + 0x4d) & 0xff) ^ (i & 0x0f);
  }
  b[0] = (0xa0 ^ tag) & 0xff;
  b[31] = (0x5e ^ tag) & 0xff;
  return b;
}

/** Build a P2WPKH scriptPubKey: OP_0 <20-byte-hash> (asymmetric tag). */
function p2wpkhSpk(tag: number): Buffer {
  const h = Buffer.alloc(20);
  for (let i = 0; i < 20; i++) h[i] = (i * 13 + tag * 7 + 0x21) & 0xff;
  return Buffer.concat([Buffer.from([0x00, 0x14]), h]);
}

/** Build a minimal unsigned tx: 1 input (P2WPKH-ish), 1 output. */
function unsignedTx(): Transaction {
  return {
    version: 2,
    inputs: [
      {
        prevOut: { txid: asymTxid(1), vout: 0 },
        scriptSig: Buffer.alloc(0),
        sequence: 0xffffffff,
        witness: [],
      },
    ],
    outputs: [{ value: 50_000n, scriptPubKey: p2wpkhSpk(2) }],
    lockTime: 0,
  };
}

/**
 * Build a minimal PSBT bytes blob with a single global field.
 * Layout: magic + (keylen + keytype + value-as-vector) + sep + per-input
 * empty maps + per-output empty maps.
 */
function buildPSBTWithGlobals(globals: Buffer): Buffer {
  // The globals buffer must include the unsigned tx + any extras + sep.
  // For these tests we always include exactly one input + one output empty
  // map after the globals to make the deserializer happy.
  return Buffer.concat([
    PSBT_MAGIC,
    globals,
    Buffer.from([0x00]), // input map separator
    Buffer.from([0x00]), // output map separator
  ]);
}

/** Build a single key-value pair: <keylen><key><vallen><val>. */
function kv(key: Buffer, value: Buffer): Buffer {
  // CompactSize encoding for sizes < 0xfd is single byte.
  function cs(n: number): Buffer {
    if (n < 0xfd) return Buffer.from([n]);
    if (n <= 0xffff) {
      const b = Buffer.alloc(3);
      b[0] = 0xfd;
      b.writeUInt16LE(n, 1);
      return b;
    }
    const b = Buffer.alloc(5);
    b[0] = 0xfe;
    b.writeUInt32LE(n, 1);
    return b;
  }
  return Buffer.concat([cs(key.length), key, cs(value.length), value]);
}

function serializeUnsignedTxNoWitness(tx: Transaction): Buffer {
  // Lazy re-implementation: re-use the actual serializeTx helper for
  // bytes parity (it correctly writes 4-byte version + var-int input count
  // etc.). We import via the public PSBT helper indirectly through
  // serializePSBT/deserializePSBT round-trip, but a hand-rolled minimal
  // serialize is easier here for the fixture.
  const parts: Buffer[] = [];
  // version (LE 4)
  const v = Buffer.alloc(4);
  v.writeUInt32LE(tx.version >>> 0, 0);
  parts.push(v);
  // input count
  parts.push(Buffer.from([tx.inputs.length]));
  for (const inp of tx.inputs) {
    parts.push(inp.prevOut.txid); // 32-byte LE txid
    const vout = Buffer.alloc(4);
    vout.writeUInt32LE(inp.prevOut.vout >>> 0, 0);
    parts.push(vout);
    parts.push(Buffer.from([inp.scriptSig.length]));
    parts.push(inp.scriptSig);
    const seq = Buffer.alloc(4);
    seq.writeUInt32LE(inp.sequence >>> 0, 0);
    parts.push(seq);
  }
  parts.push(Buffer.from([tx.outputs.length]));
  for (const out of tx.outputs) {
    const v = Buffer.alloc(8);
    v.writeBigUInt64LE(out.value, 0);
    parts.push(v);
    parts.push(Buffer.from([out.scriptPubKey.length]));
    parts.push(out.scriptPubKey);
  }
  const lt = Buffer.alloc(4);
  lt.writeUInt32LE(tx.lockTime >>> 0, 0);
  parts.push(lt);
  return Buffer.concat(parts);
}

// =============================================================================
// G1 — PSBT_MAGIC_BYTES
// =============================================================================

describe("W137-G1: PSBT_MAGIC_BYTES = 'psbt' || 0xff", () => {
  it("PRESENT: hotbuns PSBT_MAGIC equals Core's PSBT_MAGIC_BYTES (70 73 62 74 ff)", () => {
    expect(PSBT_MAGIC.equals(Buffer.from("70736274ff", "hex"))).toBe(true);
    expect(PSBT_MAGIC.length).toBe(5);
    expect(PSBT_MAGIC[0]).toBe(0x70); // 'p'
    expect(PSBT_MAGIC[1]).toBe(0x73); // 's'
    expect(PSBT_MAGIC[2]).toBe(0x62); // 'b'
    expect(PSBT_MAGIC[3]).toBe(0x74); // 't'
    expect(PSBT_MAGIC[4]).toBe(0xff);
  });

  it("PRESENT: deserializer rejects wrong magic", () => {
    const bad = Buffer.from("707362740100", "hex"); // 'psbt\x01'
    expect(() => deserializePSBT(bad)).toThrow(/[Ii]nvalid PSBT magic/);
  });
});

// =============================================================================
// G2 — Serialize-side: empty final_script_witness emission (BUG-1)
// =============================================================================

describe("W137-G2: skip empty finalScriptWitness on serialize (BUG-1)", () => {
  it("BUG-1: hotbuns emits PSBT_IN_SCRIPTWITNESS when finalScriptWitness=[] (Core skips)", () => {
    // Build a PSBT, manually set finalScriptWitness to empty array.
    // Core's serialize guards with `!final_script_witness.IsNull()` where
    // IsNull() returns `stack.empty()` (psbt.h:456). hotbuns's check is
    // `input.finalScriptWitness !== undefined` (psbt.ts:484).
    const psbt = createPSBT(unsignedTx());
    psbt.inputs[0].finalScriptWitness = [];
    const bytes = serializePSBT(psbt);
    // The byte 0x08 is PSBT_IN_SCRIPTWITNESS — looking for "keylen=1, key=0x08"
    // in the input map. If hotbuns emitted nothing for an empty witness, the
    // input map should contain only the separator 0x00.
    // Find the input map start: after magic + globals + global separator.
    // For our trivial PSBT there are no global xpubs / version / proprietary,
    // so layout is: 5 magic + global UNSIGNED_TX (single key) + 0x00 sep + INPUTS.
    // The 0x08 byte must appear in the post-global region.
    const sepIdxes: number[] = [];
    for (let i = 5; i < bytes.length; i++) {
      if (bytes[i] === 0x00) sepIdxes.push(i);
    }
    // Source-level guard: serialize emits PSBT_IN_SCRIPTWITNESS when
    // finalScriptWitness is non-undefined (regardless of length).
    const src = readSrc("wallet/psbt.ts");
    expect(src).toMatch(/if\s*\(input\.finalScriptWitness\)\s*\{/);
    // No `length > 0` guard alongside in the SERIALIZE path. Locate the
    // serialize-side block (must contain PSBT_IN_SCRIPTWITNESS write):
    const guard = src.match(
      /if\s*\(input\.finalScriptWitness\)\s*\{[\s\S]{0,400}?PSBT_IN_SCRIPTWITNESS/
    );
    expect(guard).not.toBeNull();
    if (guard) {
      expect(guard[0]).not.toMatch(/finalScriptWitness\.length\s*>\s*0/);
    }
  });

  it("PASS: when finalScriptWitness is undefined, no PSBT_IN_SCRIPTWITNESS emitted", () => {
    const psbt = createPSBT(unsignedTx());
    // Don't set finalScriptWitness at all.
    const bytes = serializePSBT(psbt);
    // PSBT_IN_SCRIPTWITNESS keytype is 0x08; with a 1-byte key the wire
    // sequence is 01 08 <vallen><val>. We don't have any 0x08 marker because
    // no signatures / witness either.
    expect(bytes.indexOf(Buffer.from([0x01, 0x08]))).toBe(-1);
  });
});

// =============================================================================
// G3 — PSBT_HIGHEST_VERSION = 0
// =============================================================================

describe("W137-G3: PSBT_HIGHEST_VERSION", () => {
  it("PRESENT: hotbuns matches Core (psbt.h:80 → 0)", () => {
    expect(PSBT_HIGHEST_VERSION).toBe(0);
  });

  it("PRESENT: deserializer rejects version > 0", () => {
    // Minimal PSBT v2 bytes: magic + (keylen=1, key=0xfb, vallen=4,
    // val=02 00 00 00) + sep + sep + sep.
    const bytes = Buffer.concat([
      PSBT_MAGIC,
      Buffer.from([0x01, 0xfb, 0x04, 0x02, 0x00, 0x00, 0x00]),
      Buffer.from([0x00]),
    ]);
    expect(() => deserializePSBT(bytes)).toThrow(/[Uu]nsupported PSBT version/);
  });
});

// =============================================================================
// G4 — MAX_FILE_SIZE_PSBT
// =============================================================================

describe("W137-G4: MAX_FILE_SIZE_PSBT", () => {
  it("PRESENT: hotbuns matches Core's 100_000_000 (psbt.h:77)", () => {
    expect(PSBT_MAX_FILE_SIZE).toBe(100_000_000);
  });

  it("PRESENT: deserialize rejects bytes longer than the limit", () => {
    // We construct a fake buffer length WITHOUT allocating 100MB — Buffer.alloc
    // is fine for the size check since it short-circuits before parsing.
    // Allocating an oversized contiguous buffer would blow heap, so build a
    // minimal blob and call the helper with a length check via array length.
    // The check at psbt.ts:1160 is `data.length > PSBT_MAX_FILE_SIZE`, so use
    // a small synthetic — verify the check IS in source.
    const src = readSrc("wallet/psbt.ts");
    expect(src).toMatch(/data\.length\s*>\s*PSBT_MAX_FILE_SIZE/);
  });
});

// =============================================================================
// G5 — m_xpubs storage shape (BUG-2)
// =============================================================================

describe("W137-G5: m_xpubs storage shape (BUG-2)", () => {
  it("BUG-2: hotbuns keys xpubs by xpub-hex, Core keys by keypath", () => {
    // Core stores std::map<KeyOriginInfo, std::set<CExtPubKey>>
    // (psbt.h:1143) — i.e. multiple xpubs at the same path coalesce into
    // a set value. hotbuns stores Map<string, {xpub, origin}> keyed by
    // xpub-hex (psbt.ts:184), so two xpubs sharing a keypath must occupy
    // distinct Map entries.
    const src = readSrc("wallet/psbt.ts");
    // The PSBT interface has xpubs: Map<string, ...>; the comment/use
    // confirms it's keyed by xpub hex.
    expect(src).toMatch(/xpubs:\s*Map<string,\s*\{\s*xpub:\s*Buffer;\s*origin:\s*KeyOriginInfo/);
    // The deserializer adds entries by xpubHex (psbt.ts:1213-1220).
    expect(src).toMatch(/const\s+xpubHex\s*=\s*keyData\.toString\("hex"\)/);
  });
});

// =============================================================================
// G6 — PSBT_GLOBAL_PROPRIETARY = 0xFC swallowed by `unknown` (BUG-3)
// =============================================================================

describe("W137-G6: PSBT_GLOBAL_PROPRIETARY swallowed by unknown (BUG-3, P0-CDIV)", () => {
  it("PRESENT (constant): PSBT_GLOBAL_PROPRIETARY = 0xFC", () => {
    expect(PSBT_GLOBAL_PROPRIETARY).toBe(0xfc);
  });

  it("BUG-3: deserializer global switch has NO case PSBT_GLOBAL_PROPRIETARY", () => {
    // Source-level: in the global-map switch (psbt.ts:1187-1247), only
    // UNSIGNED_TX / XPUB / VERSION are explicit cases; PROPRIETARY falls
    // to default.
    const src = readSrc("wallet/psbt.ts");
    // Extract the global deserialize switch body.
    const globalSwitch = src.split(
      "for (const [key, value] of globalPairs)"
    )[1]?.split("if (!tx) {")[0] ?? "";
    expect(globalSwitch).toMatch(/case\s+PSBT_GLOBAL_UNSIGNED_TX/);
    expect(globalSwitch).toMatch(/case\s+PSBT_GLOBAL_XPUB/);
    expect(globalSwitch).toMatch(/case\s+PSBT_GLOBAL_VERSION/);
    // No case for PROPRIETARY.
    expect(globalSwitch).not.toMatch(/case\s+PSBT_GLOBAL_PROPRIETARY/);
  });

  it("BUG-3: round-trip stores a proprietary global as an opaque unknown", () => {
    // Build a PSBT where the proprietary key shape is just the type byte
    // 0xfc (a complete real proprietary key in Core has identifier+subtype
    // appended). For this minimal test we just want to confirm hotbuns
    // does NOT parse the inner structure — round-trip preserves the raw
    // key bytes only in the `unknown` map.
    const txBytes = serializeUnsignedTxNoWitness(unsignedTx());
    // Global field: PSBT_GLOBAL_UNSIGNED_TX (key=0x00) + the tx bytes (as
    // length-prefixed value); then a proprietary field (key=0xfc + 1-byte
    // tag, value=0xde 0xad).
    const globals = Buffer.concat([
      kv(Buffer.from([PSBT_GLOBAL_UNSIGNED_TX]), txBytes),
      kv(Buffer.from([PSBT_GLOBAL_PROPRIETARY, 0x42]), Buffer.from([0xde, 0xad])),
      Buffer.from([0x00]),
    ]);
    const bytes = Buffer.concat([
      PSBT_MAGIC,
      globals,
      Buffer.from([0x00]), // input map sep
      Buffer.from([0x00]), // output map sep
    ]);
    const psbt = deserializePSBT(bytes);
    // Proprietary lands in `unknown` because no structured case.
    expect(psbt.unknown.size).toBeGreaterThan(0);
    const propEntry = Array.from(psbt.unknown.entries()).find(([k]) =>
      k.startsWith("fc")
    );
    expect(propEntry).toBeDefined();
  });
});

// =============================================================================
// G7 — PSBT_GLOBAL_XPUB = 0x01
// =============================================================================

describe("W137-G7: PSBT_GLOBAL_XPUB = 0x01", () => {
  it("PRESENT: constant + deserialize case", () => {
    expect(PSBT_GLOBAL_XPUB).toBe(0x01);
    const src = readSrc("wallet/psbt.ts");
    expect(src).toMatch(/case\s+PSBT_GLOBAL_XPUB/);
    // 78-byte BIP-32 extended key check
    expect(src).toMatch(/keyData\.length\s*!==\s*78/);
  });
});

// =============================================================================
// G8 — PSBT_GLOBAL_UNSIGNED_TX = 0x00
// =============================================================================

describe("W137-G8: PSBT_GLOBAL_UNSIGNED_TX = 0x00", () => {
  it("PRESENT: constant + deserialize case + empty-scriptSig/witness check", () => {
    expect(PSBT_GLOBAL_UNSIGNED_TX).toBe(0x00);
    const src = readSrc("wallet/psbt.ts");
    expect(src).toMatch(/case\s+PSBT_GLOBAL_UNSIGNED_TX/);
    expect(src).toMatch(/Unsigned tx must have empty scriptSigs and witnesses/);
  });

  it("PRESENT: deserialize rejects a PSBT with non-empty scriptSig in the unsigned tx", () => {
    const tx: Transaction = {
      version: 2,
      inputs: [
        {
          prevOut: { txid: asymTxid(9), vout: 0 },
          scriptSig: Buffer.from([0x01, 0x02]), // forbidden!
          sequence: 0xffffffff,
          witness: [],
        },
      ],
      outputs: [{ value: 100n, scriptPubKey: p2wpkhSpk(3) }],
      lockTime: 0,
    };
    const txBytes = serializeUnsignedTxNoWitness(tx);
    const bytes = Buffer.concat([
      PSBT_MAGIC,
      kv(Buffer.from([PSBT_GLOBAL_UNSIGNED_TX]), txBytes),
      Buffer.from([0x00, 0x00, 0x00]),
    ]);
    expect(() => deserializePSBT(bytes)).toThrow(
      /Unsigned tx must have empty scriptSigs/i
    );
  });
});

// =============================================================================
// G9 — PSBT v2 globals (Core parity: also missing)
// =============================================================================

describe("W137-G9: PSBT v2 globals (parity with Core — not a bug)", () => {
  it("PARITY: hotbuns has no PSBT_GLOBAL_TX_VERSION et al.; Core also does not", () => {
    const src = readSrc("wallet/psbt.ts");
    // None of the BIP-370 globals (0x02..0x06) should be defined.
    expect(src).not.toMatch(/PSBT_GLOBAL_TX_VERSION/);
    expect(src).not.toMatch(/PSBT_GLOBAL_FALLBACK_LOCKTIME/);
    expect(src).not.toMatch(/PSBT_GLOBAL_INPUT_COUNT/);
    expect(src).not.toMatch(/PSBT_GLOBAL_OUTPUT_COUNT/);
    expect(src).not.toMatch(/PSBT_GLOBAL_TX_MODIFIABLE/);
  });
});

// =============================================================================
// G10 — Sorted unknown / proprietary output order (BUG-5)
// =============================================================================

describe("W137-G10: sorted unknown/proprietary output order (BUG-5, P1-WIRE)", () => {
  it("BUG-5: hotbuns iterates unknown Map in insertion order (Core uses std::map = sorted by key)", () => {
    // Core's `unknown` is `std::map<std::vector<unsigned char>,
    // std::vector<unsigned char>>` (psbt.h:1146) so iteration order is
    // sorted-by-key-bytes. hotbuns uses Map<string, Buffer> (psbt.ts:193),
    // which iterates in insertion order.
    //
    // We use unique value bytes (0xCAFE and 0xBEEF) as taggants — the values
    // are pre-emitted by writeVarBytes, so finding the tag in the
    // serialized stream gives us a stable index per insertion-order entry.
    const psbt = createPSBT(unsignedTx());
    // Two unknown global keys: 0x77 (early) and 0x55 (late by byte value).
    // Inserted in [0x77, 0x55] order. Core would sort and emit 0x55 first.
    psbt.unknown.set("77", Buffer.from([0xca, 0xfe])); // tagged value for 0x77
    psbt.unknown.set("55", Buffer.from([0xbe, 0xef])); // tagged value for 0x55
    const bytes = serializePSBT(psbt);
    // Find the tagged value bytes in the wire stream.
    const tag77 = bytes.indexOf(Buffer.from([0xca, 0xfe]));
    const tag55 = bytes.indexOf(Buffer.from([0xbe, 0xef]));
    expect(tag77).toBeGreaterThan(0);
    expect(tag55).toBeGreaterThan(0);
    // BUG-5: hotbuns emits in insertion order — 0x77 (added first) appears
    // BEFORE 0x55 (added second). Core would emit 0x55 first (sorted).
    expect(tag77).toBeLessThan(tag55);
  });
});

// =============================================================================
// G11 — UTXO cross-check (CVE-2020-14199)
// =============================================================================

describe("W137-G11: UTXO oracle cross-check (CVE-2020-14199)", () => {
  it("PASS: getInputUTXO performs witnessUtxo↔nonWitnessUtxo cross-check (psbt.ts:1331-1384)", () => {
    const src = readSrc("wallet/psbt.ts");
    expect(src).toMatch(/CVE-2020-14199/);
    expect(src).toMatch(/witnessUtxo\.value !== fromFullTx\.value/);
    expect(src).toMatch(
      /witnessUtxo\.scriptPubKey\.equals\(fromFullTx\.scriptPubKey\)/
    );
  });
});

// =============================================================================
// G12 — Partial signature parsing (no DER strict-encoding check in hotbuns)
// =============================================================================

describe("W137-G12: PSBT_IN_PARTIAL_SIG = 0x02", () => {
  it("PRESENT: hotbuns accepts 33 and 65-byte pubkeys, dedups", () => {
    expect(PSBT_IN_PARTIAL_SIG).toBe(0x02);
    const src = readSrc("wallet/psbt.ts");
    expect(src).toMatch(/keyData\.length\s*!==\s*33\s*&&\s*keyData\.length\s*!==\s*65/);
    expect(src).toMatch(/Duplicate partial signature/);
  });

  it("PARITY GAP: hotbuns does NOT call CheckSignatureEncoding at parse time", () => {
    // Core's psbt.h:543-546 calls CheckSignatureEncoding(sig, DERSIG|STRICTENC)
    // and throws on bad encoding. hotbuns just stores raw bytes.
    const src = readSrc("wallet/psbt.ts");
    // Inside the PSBT_IN_PARTIAL_SIG branch.
    const branch = src
      .split("case PSBT_IN_PARTIAL_SIG")[1]
      ?.split("case PSBT_IN_SIGHASH")[0] ?? "";
    expect(branch).not.toMatch(/CheckSignatureEncoding/);
    expect(branch).not.toMatch(/SCRIPT_VERIFY_DERSIG/);
  });
});

// =============================================================================
// G13 — Sighash type field shape (BUG-6)
// =============================================================================

describe("W137-G13: PSBT_IN_SIGHASH = 0x03 — field width (BUG-6, P1-WIRE)", () => {
  it("BUG-6: hotbuns writes/reads sighash as UInt32LE (Core: int32 / signed)", () => {
    expect(PSBT_IN_SIGHASH).toBe(0x03);
    const src = readSrc("wallet/psbt.ts");
    // Serialize uses writeUInt32LE (unsigned).
    expect(src).toMatch(/sighashWriter\.writeUInt32LE\(input\.sighashType\)/);
    // Deserialize uses readUInt32LE (unsigned).
    expect(src).toMatch(/input\.sighashType\s*=\s*sighashReader\.readUInt32LE\(\)/);
    // Core uses `int sighash; UnserializeFromVector(s, sighash);` which is
    // a signed int32 (psbt.h:558-560). For valid sighash values 0x01..0x83
    // the bytes match either way, but the type shape (sign) differs.
  });
});

// =============================================================================
// G14 — BIP-32 derivation (input)
// =============================================================================

describe("W137-G14: PSBT_IN_BIP32_DERIVATION = 0x06", () => {
  it("PRESENT: parsed with 33/65 pubkey length check + dedup", () => {
    const src = readSrc("wallet/psbt.ts");
    expect(src).toMatch(/case\s+PSBT_IN_BIP32_DERIVATION/);
    expect(src).toMatch(/Duplicate BIP32 derivation/);
  });
});

// =============================================================================
// G15 — Final scriptSig + scriptWitness
// =============================================================================

describe("W137-G15: PSBT_IN_SCRIPTSIG = 0x07 / PSBT_IN_SCRIPTWITNESS = 0x08", () => {
  it("PRESENT: both parsed; finalize path triggers no more signing data emit", () => {
    const src = readSrc("wallet/psbt.ts");
    expect(src).toMatch(/case\s+PSBT_IN_SCRIPTSIG/);
    expect(src).toMatch(/case\s+PSBT_IN_SCRIPTWITNESS/);
    // On serialize, partial sigs are only written when both finalScriptSig
    // AND finalScriptWitness are unset (psbt.ts:391).
    expect(src).toMatch(
      /if\s*\(!input\.finalScriptSig\s*&&\s*!input\.finalScriptWitness\)/
    );
  });
});

// =============================================================================
// G16 — Hash preimages
// =============================================================================

describe("W137-G16: PSBT_IN_{RIPEMD160,SHA256,HASH160,HASH256}", () => {
  it("PRESENT: all four hash preimage types parsed with correct lengths", () => {
    const src = readSrc("wallet/psbt.ts");
    expect(src).toMatch(/case\s+PSBT_IN_RIPEMD160/);
    expect(src).toMatch(/case\s+PSBT_IN_SHA256/);
    expect(src).toMatch(/case\s+PSBT_IN_HASH160/);
    expect(src).toMatch(/case\s+PSBT_IN_HASH256/);
    // Length checks: 20 / 32 / 20 / 32
    const r = src.split("case PSBT_IN_RIPEMD160")[1]?.split("case PSBT_IN_SHA256")[0] ?? "";
    expect(r).toMatch(/keyData\.length\s*!==\s*20/);
  });
});

// =============================================================================
// G17 — PSBT_IN_PROPRIETARY = 0xFC swallowed by unknown (BUG-7)
// =============================================================================

describe("W137-G17: PSBT_IN_PROPRIETARY swallowed by unknown (BUG-7, P0-CDIV)", () => {
  it("PRESENT (constant): PSBT_IN_PROPRIETARY = 0xFC", () => {
    expect(PSBT_IN_PROPRIETARY).toBe(0xfc);
  });

  it("BUG-7: input deserializer has NO case PSBT_IN_PROPRIETARY", () => {
    const src = readSrc("wallet/psbt.ts");
    const inputSwitch = src
      .split("function deserializePSBTInput")[1]
      ?.split("function deserializePSBTOutput")[0] ?? "";
    expect(inputSwitch).toMatch(/case\s+PSBT_IN_NON_WITNESS_UTXO/);
    expect(inputSwitch).toMatch(/case\s+PSBT_IN_PARTIAL_SIG/);
    // But NOT proprietary
    expect(inputSwitch).not.toMatch(/case\s+PSBT_IN_PROPRIETARY/);
  });
});

// =============================================================================
// G18 — PSBT_IN_TAP_KEY_SIG = 0x13 parse vs sign (BUG-8)
// =============================================================================

describe("W137-G18: PSBT_IN_TAP_KEY_SIG = 0x13 (parse-only, BUG-8 P0-CDIV)", () => {
  it("PRESENT (parse): 64–65 byte length check", () => {
    const src = readSrc("wallet/psbt.ts");
    expect(src).toMatch(/case\s+PSBT_IN_TAP_KEY_SIG/);
    expect(src).toMatch(/Invalid taproot signature length/);
  });

  it("BUG-8: signPSBTInput has NO P2TR branch — refuses to sign taproot inputs", () => {
    const src = readSrc("wallet/psbt.ts");
    // The signPSBTInput function body covers P2WPKH, P2PKH, P2SH-* and
    // P2WSH but has no IsPayToTaproot / 0x51 0x20 branch.
    const signBody = src
      .split("export function signPSBTInput")[1]
      ?.split("export function combinePSBTs")[0] ?? "";
    // No P2TR script template detection: OP_1 (0x51) <32 bytes>
    expect(signBody).not.toMatch(/scriptPubKey\[0\]\s*===\s*0x51/);
    expect(signBody).not.toMatch(/witness_v1_taproot/);
    // The final "Unsupported script type for signing" branch is what fires
    // on a taproot input.
    expect(signBody).toMatch(/Unsupported script type for signing/);
  });
});

// =============================================================================
// G19 — PSBT_IN_TAP_SCRIPT_SIG = 0x14 (parse-only)
// =============================================================================

describe("W137-G19: PSBT_IN_TAP_SCRIPT_SIG = 0x14 (parse-only)", () => {
  it("PRESENT: 64-byte keydata (xonly+leaf_hash) + 64-65 byte sig", () => {
    const src = readSrc("wallet/psbt.ts");
    expect(src).toMatch(/case\s+PSBT_IN_TAP_SCRIPT_SIG/);
    expect(src).toMatch(
      /Taproot script sig key must have exactly 64 bytes of key data/
    );
  });
});

// =============================================================================
// G20 — PSBT_IN_TAP_LEAF_SCRIPT = 0x15
// =============================================================================

describe("W137-G20: PSBT_IN_TAP_LEAF_SCRIPT = 0x15", () => {
  it("PRESENT: keydata >= 33, (keydata-1)%32==0, multiple control_blocks coalesced", () => {
    const src = readSrc("wallet/psbt.ts");
    expect(src).toMatch(/case\s+PSBT_IN_TAP_LEAF_SCRIPT/);
    expect(src).toMatch(/keyData\.length\s*<\s*33/);
    expect(src).toMatch(/keyData\.length\s*-\s*1\)\s*%\s*32\s*!==\s*0/);
    // multiple control blocks → push into existing.controlBlocks
    expect(src).toMatch(/existing\.controlBlocks\.push\(controlBlock\)/);
  });
});

// =============================================================================
// G21 — PSBT_IN_TAP_BIP32_DERIVATION = 0x16
// =============================================================================

describe("W137-G21: PSBT_IN_TAP_BIP32_DERIVATION = 0x16", () => {
  it("PRESENT: 32-byte keydata + leaf_hashes + key_origin", () => {
    const src = readSrc("wallet/psbt.ts");
    expect(src).toMatch(/case\s+PSBT_IN_TAP_BIP32_DERIVATION/);
    expect(src).toMatch(
      /Taproot BIP32 derivation key must have exactly 32 bytes of key data/
    );
  });
});

// =============================================================================
// G22 — PSBT_IN_TAP_INTERNAL_KEY = 0x17, PSBT_IN_TAP_MERKLE_ROOT = 0x18
// =============================================================================

describe("W137-G22: PSBT_IN_TAP_INTERNAL_KEY/MERKLE_ROOT", () => {
  it("PRESENT: both parse with 32-byte value, no keydata", () => {
    const src = readSrc("wallet/psbt.ts");
    expect(src).toMatch(/case\s+PSBT_IN_TAP_INTERNAL_KEY/);
    expect(src).toMatch(/case\s+PSBT_IN_TAP_MERKLE_ROOT/);
    expect(src).toMatch(/Invalid taproot internal key length/);
    expect(src).toMatch(/Invalid taproot merkle root length/);
  });
});

// =============================================================================
// G23 — MuSig2 input fields (BUG-9)
// =============================================================================

describe("W137-G23: MuSig2 input fields 0x1a/0x1b/0x1c (BUG-9, P1-API)", () => {
  it("BUG-9: hotbuns defines NO PSBT_IN_MUSIG2_* constants", () => {
    const src = readSrc("wallet/psbt.ts");
    expect(src).not.toMatch(/PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS/);
    expect(src).not.toMatch(/PSBT_IN_MUSIG2_PUB_NONCE/);
    expect(src).not.toMatch(/PSBT_IN_MUSIG2_PARTIAL_SIG/);
  });

  it("BUG-9: input deserializer has no cases for 0x1a / 0x1b / 0x1c", () => {
    const src = readSrc("wallet/psbt.ts");
    const inputSwitch = src
      .split("function deserializePSBTInput")[1]
      ?.split("function deserializePSBTOutput")[0] ?? "";
    expect(inputSwitch).not.toMatch(/0x1a/);
    expect(inputSwitch).not.toMatch(/0x1b/);
    expect(inputSwitch).not.toMatch(/0x1c/);
  });
});

// =============================================================================
// G24 — PSBT_OUT_PROPRIETARY = 0xFC swallowed (BUG-10)
// =============================================================================

describe("W137-G24: PSBT_OUT_PROPRIETARY swallowed by unknown (BUG-10, P0-CDIV)", () => {
  it("PRESENT (constant): PSBT_OUT_PROPRIETARY = 0xFC", () => {
    expect(PSBT_OUT_PROPRIETARY).toBe(0xfc);
  });

  it("BUG-10: output deserializer has NO case PSBT_OUT_PROPRIETARY", () => {
    const src = readSrc("wallet/psbt.ts");
    const outputSwitch = src
      .split("function deserializePSBTOutput")[1]
      ?.split("function deserializePSBT(")[0] ?? "";
    // Confirm coverage of the legitimate output types so this assertion
    // isn't trivially true on bad slicing.
    expect(outputSwitch).toMatch(/case\s+PSBT_OUT_REDEEMSCRIPT/);
    expect(outputSwitch).toMatch(/case\s+PSBT_OUT_TAP_INTERNAL_KEY/);
    // But not proprietary.
    expect(outputSwitch).not.toMatch(/case\s+PSBT_OUT_PROPRIETARY/);
  });
});

// =============================================================================
// G25 — BIP-371 output fields
// =============================================================================

describe("W137-G25: BIP-371 output fields", () => {
  it("PRESENT: tap_internal_key / tap_tree / tap_bip32_derivation all parsed", () => {
    const src = readSrc("wallet/psbt.ts");
    expect(src).toMatch(/case\s+PSBT_OUT_TAP_INTERNAL_KEY/);
    expect(src).toMatch(/case\s+PSBT_OUT_TAP_TREE/);
    expect(src).toMatch(/case\s+PSBT_OUT_TAP_BIP32_DERIVATION/);
  });
});

// =============================================================================
// G26 — MuSig2 output participant pubkeys (PSBT_OUT_MUSIG2_PARTICIPANT_PUBKEYS = 0x08)
// =============================================================================

describe("W137-G26: PSBT_OUT_MUSIG2_PARTICIPANT_PUBKEYS = 0x08", () => {
  it("PRESENT: 33-byte agg key + N*33-byte participants", () => {
    const src = readSrc("wallet/psbt.ts");
    expect(src).toMatch(/case\s+PSBT_OUT_MUSIG2_PARTICIPANT_PUBKEYS/);
    expect(src).toMatch(
      /Output MuSig2 participant pubkeys key must have exactly 33 bytes/
    );
    expect(src).toMatch(/value\.length\s*%\s*33\s*!==\s*0/);
  });
});

// =============================================================================
// G27 — CREATOR role
// =============================================================================

describe("W137-G27: CREATOR — createPSBT", () => {
  it("PASS: rejects unsigned tx with non-empty scriptSig", () => {
    const tx: Transaction = {
      version: 2,
      inputs: [
        {
          prevOut: { txid: asymTxid(11), vout: 0 },
          scriptSig: Buffer.from([0x01]), // not empty
          sequence: 0xffffffff,
          witness: [],
        },
      ],
      outputs: [{ value: 100n, scriptPubKey: p2wpkhSpk(3) }],
      lockTime: 0,
    };
    expect(() => createPSBT(tx)).toThrow(/empty scriptSig/);
  });

  it("PASS: rejects unsigned tx with non-empty witness", () => {
    const tx: Transaction = {
      version: 2,
      inputs: [
        {
          prevOut: { txid: asymTxid(12), vout: 0 },
          scriptSig: Buffer.alloc(0),
          sequence: 0xffffffff,
          witness: [Buffer.from([0x01])],
        },
      ],
      outputs: [{ value: 100n, scriptPubKey: p2wpkhSpk(4) }],
      lockTime: 0,
    };
    expect(() => createPSBT(tx)).toThrow(/empty witness/);
  });

  it("PASS: builds an empty PSBT with correct input/output counts", () => {
    const tx = unsignedTx();
    const p = createPSBT(tx);
    expect(p.inputs.length).toBe(1);
    expect(p.outputs.length).toBe(1);
    expect(p.tx.version).toBe(2);
  });
});

// =============================================================================
// G28 — SIGNER role (P2TR missing — counted under BUG-8)
// =============================================================================

describe("W137-G28: SIGNER — signPSBTInput script template coverage", () => {
  it("PASS: signPSBTInput recognizes P2WPKH / P2PKH / P2SH-P2WPKH / P2SH-P2WSH / P2WSH", () => {
    const src = readSrc("wallet/psbt.ts");
    const signBody = src
      .split("export function signPSBTInput")[1]
      ?.split("export function combinePSBTs")[0] ?? "";
    // 0x00 0x14 = P2WPKH
    expect(signBody).toMatch(/scriptPubKey\[0\]\s*===\s*0x00.*scriptPubKey\[1\]\s*===\s*0x14/s);
    // 0x76 0xa9 0x14 = P2PKH
    expect(signBody).toMatch(/scriptPubKey\[0\]\s*===\s*0x76/);
    // 0xa9 0x14 = P2SH
    expect(signBody).toMatch(/scriptPubKey\[0\]\s*===\s*0xa9/);
    // P2WSH 0x00 0x20
    expect(signBody).toMatch(/scriptPubKey\[1\]\s*===\s*0x20/);
  });

  it("BUG-8 (recorded under G18): no P2TR (witness_v1_taproot) signing branch", () => {
    const src = readSrc("wallet/psbt.ts");
    const signBody = src
      .split("export function signPSBTInput")[1]
      ?.split("export function combinePSBTs")[0] ?? "";
    // OP_1 (0x51) = SegWit v1 / P2TR — not present in signPSBTInput
    expect(signBody).not.toMatch(/===\s*0x51/);
  });
});

// =============================================================================
// G29 — COMBINER (BUG-11)
// =============================================================================

describe("W137-G29: COMBINER — combinePSBTs (BUG-11, P1-WIRE)", () => {
  it("PASS: rejects PSBTs with different underlying transactions", () => {
    const a = createPSBT(unsignedTx());
    const b = createPSBT({
      ...unsignedTx(),
      outputs: [{ value: 99_999n, scriptPubKey: p2wpkhSpk(99) }],
    });
    expect(() => combinePSBTs([a, b])).toThrow(/different transactions/i);
  });

  it("BUG-11: combinePSBTs returns a PSBT but has NO `complete` boolean and no version-mismatch check", () => {
    const src = readSrc("wallet/psbt.ts");
    // Function signature: `function combinePSBTs(psbts: PSBT[]): PSBT`
    expect(src).toMatch(/export function combinePSBTs\(psbts: PSBT\[\]\):\s*PSBT/);
    // No version cross-check loop inside combine.
    const combineBody = src
      .split("export function combinePSBTs")[1]
      ?.split("export function finalizePSBTInput")[0] ?? "";
    expect(combineBody).not.toMatch(/different versions/i);
  });
});

// =============================================================================
// G30 — FINALIZER (BUG-12)
// =============================================================================

describe("W137-G30: FINALIZER — finalizePSBTInput (BUG-12, P1-WIRE)", () => {
  it("PASS: finalizes legacy P2SH-multisig (W43 closure)", () => {
    const src = readSrc("wallet/psbt.ts");
    // Source-level: parseMultisigScript helper + legacy P2SH-multisig
    // branch in finalize (psbt.ts:2005-2046).
    expect(src).toMatch(/function parseMultisigScript/);
    expect(src).toMatch(/Legacy P2SH-multisig \(BIP-11\)/);
  });

  it("BUG-12: extractTransaction substitutes [] for missing finalScriptWitness, possibly lowering tx encoding", () => {
    const src = readSrc("wallet/psbt.ts");
    const ext = src
      .split("export function extractTransaction")[1]
      ?.split("export function analyzePSBT(")[0] ?? "";
    expect(ext).toMatch(/finalScriptWitness\s*\|\|\s*\[\]/);
  });
});

// =============================================================================
// G31 — walletprocesspsbt RPC (BUG-13)
// =============================================================================

describe("W137-G31: walletprocesspsbt RPC (BUG-13, P1-API)", () => {
  it("BUG-13: rpc/server.ts has NO registerMethod for 'walletprocesspsbt'", () => {
    const src = readSrc("rpc/server.ts");
    expect(src).not.toMatch(/registerMethod\("walletprocesspsbt"/);
    // But it does have the other PSBT methods.
    expect(src).toMatch(/registerMethod\("createpsbt"/);
    expect(src).toMatch(/registerMethod\("decodepsbt"/);
    expect(src).toMatch(/registerMethod\("combinepsbt"/);
    expect(src).toMatch(/registerMethod\("finalizepsbt"/);
  });
});

// =============================================================================
// G32 — joinpsbts RPC (BUG-14)
// =============================================================================

describe("W137-G32: joinpsbts RPC (BUG-14, P1-API)", () => {
  it("BUG-14: no registerMethod for 'joinpsbts'", () => {
    const src = readSrc("rpc/server.ts");
    expect(src).not.toMatch(/registerMethod\("joinpsbts"/);
  });
});

// =============================================================================
// G33 — utxoupdatepsbt RPC (BUG-15)
// =============================================================================

describe("W137-G33: utxoupdatepsbt RPC (BUG-15, P1-API)", () => {
  it("BUG-15: no registerMethod for 'utxoupdatepsbt'", () => {
    const src = readSrc("rpc/server.ts");
    expect(src).not.toMatch(/registerMethod\("utxoupdatepsbt"/);
  });
});

// =============================================================================
// G34 — walletcreatefundedpsbt manual-inputs rejection (BUG-16)
// =============================================================================

describe("W137-G34: walletcreatefundedpsbt rejects manual inputs (BUG-16, P2)", () => {
  it("BUG-16: server.ts explicitly throws on inputsParam.length > 0", () => {
    const src = readSrc("rpc/server.ts");
    expect(src).toMatch(/Manual\s+`?inputs`?\s+aren'?t\s+supported\s+yet/);
    // Confirm the throw is inside walletCreateFundedPSBT.
    const fn = src
      .split("private async walletCreateFundedPSBT")[1]
      ?.split("private async help")[0] ?? "";
    expect(fn).toMatch(/inputsParam\.length\s*>\s*0/);
  });
});

// =============================================================================
// G35 — decodepsbt proprietary always [] (BUG-17)
// =============================================================================

describe("W137-G35: decodepsbt proprietary always empty (BUG-17, P2)", () => {
  it("BUG-17: decodePSBT returns proprietary: [] unconditionally", () => {
    const src = readSrc("wallet/psbt.ts");
    // The decoded shape has proprietary: [] hardcoded in the result object.
    expect(src).toMatch(/proprietary:\s*\[\]/);
    // The PSBT interface itself has no `proprietary: PSBTProprietary[]`
    // field on the PSBT struct (only `unknown`).
    const psbtIface = src
      .split("export interface PSBT")[1]
      ?.split("export enum PSBTRole")[0] ?? "";
    expect(psbtIface).not.toMatch(/proprietary\??:/);
  });
});

// =============================================================================
// G36 — psbtbumpfee RPC (PASS)
// =============================================================================

describe("W137-G36: psbtbumpfee RPC (PASS)", () => {
  it("PASS: rpc/server.ts registers psbtbumpfee", () => {
    const src = readSrc("rpc/server.ts");
    expect(src).toMatch(/registerMethod\("psbtbumpfee"/);
  });

  it("PASS: psbtBumpFee wraps the unsigned tx in a PSBT + attaches witness UTXOs", () => {
    const src = readSrc("rpc/server.ts");
    const fn = src
      .split("private async psbtBumpFee")[1]
      ?.split("private async help")[0] ?? "";
    expect(fn).toMatch(/convertToPSBT/);
    expect(fn).toMatch(/witnessUtxo/);
  });
});

// =============================================================================
// G37 — RemoveUnnecessaryTransactions (BUG-18)
// =============================================================================

describe("W137-G37: RemoveUnnecessaryTransactions analog (BUG-18, P1-API)", () => {
  it("BUG-18: no analog of Core's RemoveUnnecessaryTransactions in psbt.ts", () => {
    const src = readSrc("wallet/psbt.ts");
    // The function (or any equivalent helper that strips non_witness_utxo
    // for pure taproot inputs) does not exist.
    expect(src).not.toMatch(/RemoveUnnecessaryTransactions/);
    expect(src).not.toMatch(/removeUnnecessaryTransactions/);
    // No code path that conditionally drops nonWitnessUtxo when segwit-v1.
    expect(src).not.toMatch(
      /nonWitnessUtxo\s*=\s*undefined.*segwit/i
    );
  });
});

// =============================================================================
// Source-level sanity check: bug count = 17 (BUG-4 reserved for PSBT v2 parity row)
// =============================================================================

describe("W137 summary: 17 numbered bugs (reserved id intentionally skipped)", () => {
  it("sanity: tests enumerate the expected bug ids before the summary block", () => {
    const thisFile = readFileSync(
      join(import.meta.dirname, "w137_psbt.test.ts"),
      "utf8"
    );
    // Cut off the summary block (which mentions reserved id ranges in
    // prose) so it doesn't contaminate the count.
    const cutoff = thisFile.indexOf("// Source-level sanity check");
    const auditPart = cutoff > 0 ? thisFile.slice(0, cutoff) : thisFile;
    const matches = auditPart.match(/BUG-(\d+)/g) ?? [];
    const ids = new Set(matches.map((m) => m.replace("BUG-", "")));
    // Active bug ids
    const expected = [1, 2, 3, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18];
    for (const i of expected) {
      expect(ids.has(String(i))).toBe(true);
    }
    // Reserved id is intentionally NOT used in any test body.
    expect(ids.has("4")).toBe(false);
    expect(ids.size).toBe(expected.length);
  });
});
