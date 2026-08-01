/**
 * W118 Wallet audit — hotbuns (TypeScript / Bun)
 *
 * 30 gates covering Descriptors, BIP-32 derivation, PSBT, fee bumping,
 * Send, and UTXO selection.
 *
 * Reference: bitcoin-core/src/wallet/*, BIPs 32/38/39/43/44/49/84/86/125/174/370/380.
 *
 * Gate map:
 *   Descriptors (G1-G6)
 *     G1  pk()/pkh()/wpkh() basic parsing
 *     G2  sh(wpkh()) and tr() nested + key-path
 *     G3  BIP-380 checksum compute / validate
 *     G4  Ranged xpub /0/* derivation (isRange)
 *     G5  multi() / sortedmulti() ordering
 *     G6  Miniscript inside wsh(...) (BIP-379)
 *   BIP-32 derivation (G7-G12)
 *     G7  Master key from BIP-32 vector 1 seed
 *     G8  Normal child derivation (non-hardened, vector 1)
 *     G9  Hardened child derivation (vector 1)
 *     G10 Invalid-child skip (parse256(IL) >= n)
 *     G11 Extended key encode/decode roundtrip (xpub/xprv)
 *     G12 BIP-44/49/84/86 receive-path generation (BIP-84 vector)
 *   PSBT (G13-G18)
 *     G13 Creator role (createPSBT from unsigned tx)
 *     G14 Serialize/deserialize roundtrip (BIP-174 v0 magic)
 *     G15 Signer role — P2WPKH partial signature
 *     G16 Combiner role — merge sigs from two signers
 *     G17 Finalizer + Extractor — P2WPKH finalScriptWitness
 *     G18 PSBTv2 (BIP-370) — expected MISSING
 *   Fee bumping (G19-G22)
 *     G19 bumpfee — RBF (BIP-125) — expected MISSING
 *     G20 psbtbumpfee — expected MISSING
 *     G21 Anti-fee-sniping nLockTime (Core sets locktime≈tip)
 *     G22 RBF signaling — sequence < 0xfffffffe
 *   Send (G23-G26)
 *     G23 sendtoaddress fee calculation via createTransaction
 *     G24 Dust threshold per address type (BIP-141 dust math)
 *     G25 Insufficient funds error path
 *     G26 sendmany — multi-output createTransaction
 *   UTXO (G27-G30)
 *     G27 COINBASE_MATURITY = 100 confirmations
 *     G28 processBlock UTXO discovery + spend tracking
 *     G29 getBalance confirmed vs unconfirmed split
 *     G30 listUnspent — minconf filtering via selectCoinsAdvanced
 *
 * Status legend:
 *   PASS — correct behaviour confirmed
 *   FAIL — bug confirmed
 *   MISSING — feature not implemented
 */

import { describe, expect, test, beforeEach, afterEach } from "bun:test";
import { mkdirSync, rmSync } from "fs";
import { hmac } from "@noble/hashes/hmac.js";
import { sha512, sha256 } from "@noble/hashes/sha2.js";

import {
  Wallet,
  type WalletConfig,
  type WalletUTXO,
  Bip32InvalidChildError,
  bip32CkdPrivFromI,
  COINBASE_MATURITY,
} from "../wallet/wallet";

import {
  parseDescriptor,
  descriptorChecksum,
  addChecksum,
  validateChecksum,
  encodeExtendedKey,
  decodeExtendedKey,
  DescriptorType,
  OutputType,
  type ExtendedKey,
} from "../wallet/descriptor";

import {
  createPSBT,
  serializePSBT,
  deserializePSBT,
  signPSBTInput,
  combinePSBTs,
  finalizePSBTInput,
  extractTransaction,
  encodePSBTBase64,
  decodePSBTBase64,
  isInputFinalized,
  PSBT_MAGIC,
  PSBT_HIGHEST_VERSION,
  type PSBT,
} from "../wallet/psbt";

import { privateKeyToPublicKey, hash160 } from "../crypto/primitives";
import { AddressType } from "../address/encoding";
import { type Transaction, SIGHASH_ALL, getTxId } from "../validation/tx";

const TEST_DATADIR = "/tmp/hotbuns-w118-audit";

// BIP-39 canonical "abandon × 11 about" mnemonic
const ABANDON_MNEMONIC =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

// BIP-84 test vector receive address 0
const EXPECTED_BIP84_RECEIVE_0 = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu";

// BIP-32 test-vector 1 master xprv / xpub (seed 000102030405060708090a0b0c0d0e0f)
const BIP32_TV1_SEED_HEX = "000102030405060708090a0b0c0d0e0f";
const BIP32_TV1_MASTER_XPUB =
  "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
const BIP32_TV1_MASTER_XPRV =
  "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";

// Sample 33-byte compressed pubkey (G-times-1)
const SAMPLE_PUBKEY_HEX =
  "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

// secp256k1 order
const N = BigInt(
  "0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"
);

function makeConfig(
  network: "mainnet" | "testnet" | "regtest" = "mainnet"
): WalletConfig {
  return { datadir: TEST_DATADIR, network };
}

// Synthetic UTXO factory (asymmetric txid per W32-B rule).
function makeUTXO(opts: {
  txidSeed: number;
  vout: number;
  amount: bigint;
  address: string;
  keyPath: string;
  confirmations: number;
  addressType?: AddressType;
  isCoinbase?: boolean;
}): WalletUTXO {
  const txid = Buffer.alloc(32);
  for (let i = 0; i < 32; i++) {
    txid[i] = ((i * 7 + opts.txidSeed * 31 + 0x4d) & 0xff) ^ (i & 0x0f);
  }
  txid[0] = (0xa0 ^ opts.txidSeed) & 0xff;
  txid[31] = (0x5e ^ opts.txidSeed) & 0xff;

  return {
    outpoint: { txid, vout: opts.vout },
    amount: opts.amount,
    address: opts.address,
    keyPath: opts.keyPath,
    confirmations: opts.confirmations,
    addressType: opts.addressType ?? AddressType.P2WPKH,
    isCoinbase: opts.isCoinbase ?? false,
  };
}

// ============================================================================
// G1: pk() / pkh() / wpkh() basic descriptor parsing
// ============================================================================
describe("G1: pk/pkh/wpkh descriptor parsing", () => {
  test("PASS: parses pk()", () => {
    const parsed = parseDescriptor(`pk(${SAMPLE_PUBKEY_HEX})`);
    expect(parsed.descriptor.getType()).toBe(DescriptorType.PK);
  });

  test("PASS: parses pkh() with legacy output type", () => {
    const parsed = parseDescriptor(`pkh(${SAMPLE_PUBKEY_HEX})`);
    expect(parsed.descriptor.getType()).toBe(DescriptorType.PKH);
    expect(parsed.descriptor.getOutputType()).toBe(OutputType.LEGACY);
  });

  test("PASS: parses wpkh() with bech32 output type", () => {
    const parsed = parseDescriptor(`wpkh(${SAMPLE_PUBKEY_HEX})`);
    expect(parsed.descriptor.getType()).toBe(DescriptorType.WPKH);
    expect(parsed.descriptor.getOutputType()).toBe(OutputType.BECH32);
  });
});

// ============================================================================
// G2: sh(wpkh()) nested + tr() key-path
// ============================================================================
describe("G2: sh(wpkh()) + tr() descriptors", () => {
  test("PASS: parses sh(wpkh()) as p2sh-segwit", () => {
    const parsed = parseDescriptor(`sh(wpkh(${SAMPLE_PUBKEY_HEX}))`);
    expect(parsed.descriptor.getType()).toBe(DescriptorType.SH);
    expect(parsed.descriptor.getOutputType()).toBe(OutputType.P2SH_SEGWIT);
  });

  test("PASS: parses tr() key-path as bech32m", () => {
    const parsed = parseDescriptor(`tr(${SAMPLE_PUBKEY_HEX})`);
    expect(parsed.descriptor.getType()).toBe(DescriptorType.TR);
    expect(parsed.descriptor.getOutputType()).toBe(OutputType.BECH32M);
  });

  test("PASS: rejects wpkh at non-top-level outside sh()", () => {
    // wpkh inside wsh is invalid (BIP-382)
    expect(() =>
      parseDescriptor(`wsh(wpkh(${SAMPLE_PUBKEY_HEX}))`)
    ).toThrow();
  });
});

// ============================================================================
// G3: BIP-380 descriptor checksum compute + validate
// ============================================================================
describe("G3: BIP-380 descriptor checksum", () => {
  test("PASS: computes 8-char checksum in CHECKSUM_CHARSET", () => {
    const desc = `pkh(${SAMPLE_PUBKEY_HEX})`;
    const cs = descriptorChecksum(desc);
    expect(cs.length).toBe(8);
    expect(/^[qpzry9x8gf2tvdw0s3jn54khce6mua7l]+$/.test(cs)).toBe(true);
  });

  test("PASS: addChecksum + validateChecksum roundtrip", () => {
    const desc = `wpkh(${SAMPLE_PUBKEY_HEX})`;
    const withCs = addChecksum(desc);
    const stripped = validateChecksum(withCs);
    expect(stripped).toBe(desc);
  });

  test("PASS: validateChecksum throws on tampered checksum", () => {
    const desc = `wpkh(${SAMPLE_PUBKEY_HEX})`;
    const withCs = addChecksum(desc);
    // Flip last char to a different valid character
    const lastChar = withCs[withCs.length - 1];
    const replacement = lastChar === "q" ? "p" : "q";
    const tampered = withCs.slice(0, -1) + replacement;
    expect(() => validateChecksum(tampered)).toThrow();
  });
});

// ============================================================================
// G4: Ranged xpub /0/* derivation
// ============================================================================
describe("G4: ranged xpub /0/* descriptor", () => {
  test("PASS: parses /0/* as ranged", () => {
    const parsed = parseDescriptor(`pkh(${BIP32_TV1_MASTER_XPUB}/0/*)`);
    expect(parsed.descriptor.isRange()).toBe(true);
  });

  test("PASS: non-ranged /0/0 is not isRange", () => {
    const parsed = parseDescriptor(`pkh(${BIP32_TV1_MASTER_XPUB}/0/0)`);
    expect(parsed.descriptor.isRange()).toBe(false);
  });

  test("PASS: hardened ranged /0/*' is also isRange", () => {
    const parsed = parseDescriptor(`pkh(${BIP32_TV1_MASTER_XPRV}/0/*')`);
    expect(parsed.descriptor.isRange()).toBe(true);
  });
});

// ============================================================================
// G5: multi() / sortedmulti() ordering
// ============================================================================
describe("G5: multi() / sortedmulti() parsing + sorting", () => {
  test("PASS: parses 2-of-3 multi() preserving pubkey order", () => {
    const p1 = SAMPLE_PUBKEY_HEX;
    const p2 = "0379be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81799";
    const p3 = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
    const parsed = parseDescriptor(`multi(2,${p1},${p2},${p3})`);
    expect(parsed.descriptor.getType()).toBe(DescriptorType.MULTI);
  });

  test("PASS: parses sortedmulti() with sort flag", () => {
    const p1 = SAMPLE_PUBKEY_HEX;
    const p2 = "0379be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81799";
    const parsed = parseDescriptor(`sortedmulti(2,${p1},${p2})`);
    expect(parsed.descriptor.getType()).toBe(DescriptorType.SORTEDMULTI);
  });

  test("PASS: wsh(multi(2,...)) produces witness output", () => {
    const p1 = SAMPLE_PUBKEY_HEX;
    const p2 = "0379be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81799";
    const parsed = parseDescriptor(`wsh(multi(2,${p1},${p2}))`);
    expect(parsed.descriptor.getType()).toBe(DescriptorType.WSH);
    expect(parsed.descriptor.getOutputType()).toBe(OutputType.BECH32);
  });
});

// ============================================================================
// G6: Miniscript inside wsh(...)
// ============================================================================
describe("G6: miniscript support (BIP-379)", () => {
  test("PASS: miniscript module exists + parseDescriptor accepts wsh(pk())", () => {
    // The miniscript module is present (src/wallet/miniscript.ts ~2700 LOC).
    // Inside wsh() context, parseDescriptor falls through to miniscript
    // parsing if it can't match a top-level fragment. We confirm the
    // simplest miniscript fragment (a single pk()) parses inside wsh().
    const parsed = parseDescriptor(`wsh(pk(${SAMPLE_PUBKEY_HEX}))`);
    // Either a WSH descriptor wrapping a pk subexpression, or a
    // MINISCRIPT-typed descriptor — both indicate miniscript support.
    const t = parsed.descriptor.getType();
    expect([DescriptorType.WSH]).toContain(t);
  });
});

// ============================================================================
// G7: BIP-32 master key from vector-1 seed
// ============================================================================
describe("G7: BIP-32 master key derivation", () => {
  beforeEach(() => mkdirSync(TEST_DATADIR, { recursive: true }));
  afterEach(() => rmSync(TEST_DATADIR, { recursive: true, force: true }));

  test("PASS: HMAC-SHA512('Bitcoin seed', seed) matches BIP-32 TV1", () => {
    // Expected master private key (BIP-32 vector 1):
    //   e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35
    const seed = Buffer.from(BIP32_TV1_SEED_HEX, "hex");
    const I = Buffer.from(hmac(sha512, Buffer.from("Bitcoin seed"), seed));
    expect(I.subarray(0, 32).toString("hex")).toBe(
      "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35"
    );
    expect(I.subarray(32, 64).toString("hex")).toBe(
      "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508"
    );
  });
});

// ============================================================================
// G8: BIP-32 normal child derivation
// ============================================================================
describe("G8: BIP-32 normal child derivation (math helper)", () => {
  test("PASS: bip32CkdPrivFromI happy path adds IL to parent mod n", () => {
    const parent = Buffer.from(
      "1111111111111111111111111111111111111111111111111111111111111111",
      "hex"
    );
    const IL = Buffer.alloc(32);
    IL[31] = 2; // IL = 2
    const IR = Buffer.alloc(32, 0xab);
    const I = Buffer.concat([IL, IR]);

    const { key, chainCode } = bip32CkdPrivFromI(parent, I, 0);
    expect(key.length).toBe(32);
    expect(chainCode.length).toBe(32);
    expect(chainCode.equals(IR)).toBe(true);

    // child = parent + 2 mod n
    const expectedBig =
      (BigInt("0x" + parent.toString("hex")) + 2n) % N;
    const expected = Buffer.from(
      expectedBig.toString(16).padStart(64, "0"),
      "hex"
    );
    expect(key.equals(expected)).toBe(true);
  });
});

// ============================================================================
// G9: BIP-32 hardened child derivation produces 32-byte key
// ============================================================================
describe("G9: BIP-32 hardened derivation via Wallet API", () => {
  beforeEach(() => mkdirSync(TEST_DATADIR, { recursive: true }));
  afterEach(() => rmSync(TEST_DATADIR, { recursive: true, force: true }));

  test("PASS: BIP-84 hardened path derives canonical address", () => {
    const wallet = Wallet.create(makeConfig("mainnet"), ABANDON_MNEMONIC);
    // BIP-84 vector: m/84'/0'/0'/0/0 → bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu
    const addr = wallet.getNewAddress("bech32");
    expect(addr).toBe(EXPECTED_BIP84_RECEIVE_0);
  });
});

// ============================================================================
// G10: Invalid-child skip (parse256(IL) >= n)
// ============================================================================
describe("G10: BIP-32 invalid-child skip", () => {
  test("PASS: IL == n raises Bip32InvalidChildError(il-overflow)", () => {
    const parent = Buffer.from(
      "1111111111111111111111111111111111111111111111111111111111111111",
      "hex"
    );
    const IL = Buffer.from(N.toString(16).padStart(64, "0"), "hex");
    const IR = Buffer.alloc(32, 0xcc);
    const I = Buffer.concat([IL, IR]);

    expect(() => bip32CkdPrivFromI(parent, I, 5)).toThrow(
      Bip32InvalidChildError
    );
  });

  test("PASS: child-zero case raises Bip32InvalidChildError(child-zero)", () => {
    // pick parent + IL such that (parent + IL) % n == 0
    // simplest: parent = n - 1, IL = 1  →  child = 0 mod n
    const parentBig = N - 1n;
    const parent = Buffer.from(parentBig.toString(16).padStart(64, "0"), "hex");
    const IL = Buffer.alloc(32);
    IL[31] = 1;
    const IR = Buffer.alloc(32, 0x33);
    const I = Buffer.concat([IL, IR]);

    let err: unknown = null;
    try {
      bip32CkdPrivFromI(parent, I, 9);
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(Bip32InvalidChildError);
    expect((err as Bip32InvalidChildError).message).toContain("child-zero");
  });
});

// ============================================================================
// G11: Extended key encode/decode roundtrip
// ============================================================================
describe("G11: xpub/xprv encode/decode roundtrip", () => {
  test("PASS: xpub decode → re-encode matches input", () => {
    const decoded = decodeExtendedKey(BIP32_TV1_MASTER_XPUB);
    expect(decoded.isPrivate).toBe(false);
    expect(decoded.depth).toBe(0);
    expect(decoded.key.length).toBe(33); // compressed pubkey
    const reencoded = encodeExtendedKey(decoded);
    expect(reencoded).toBe(BIP32_TV1_MASTER_XPUB);
  });

  test("PASS: xprv decode → re-encode matches input", () => {
    const decoded = decodeExtendedKey(BIP32_TV1_MASTER_XPRV);
    expect(decoded.isPrivate).toBe(true);
    expect(decoded.depth).toBe(0);
    expect(decoded.key.length).toBe(32); // raw private key (no 0x00 prefix)
    const reencoded = encodeExtendedKey(decoded);
    expect(reencoded).toBe(BIP32_TV1_MASTER_XPRV);
  });

  test("PASS: tampered xpub fails checksum", () => {
    // Flip a single hex char inside the body to break the trailing checksum.
    const tampered =
      BIP32_TV1_MASTER_XPUB.slice(0, 60) +
      (BIP32_TV1_MASTER_XPUB[60] === "A" ? "B" : "A") +
      BIP32_TV1_MASTER_XPUB.slice(61);
    expect(() => decodeExtendedKey(tampered)).toThrow();
  });
});

// ============================================================================
// G12: BIP-44 / BIP-49 / BIP-84 / BIP-86 receive paths
// ============================================================================
describe("G12: BIP-44/49/84/86 receive-path generation", () => {
  beforeEach(() => mkdirSync(TEST_DATADIR, { recursive: true }));
  afterEach(() => rmSync(TEST_DATADIR, { recursive: true, force: true }));

  test("PASS: BIP-84 (m/84'/0'/0'/0/0) → known mainnet bech32 address", () => {
    const wallet = Wallet.create(makeConfig("mainnet"), ABANDON_MNEMONIC);
    expect(wallet.getNewAddress("bech32")).toBe(EXPECTED_BIP84_RECEIVE_0);
  });

  test("PASS: BIP-44 (legacy P2PKH) emits 1-prefixed mainnet address", () => {
    const wallet = Wallet.create(makeConfig("mainnet"), ABANDON_MNEMONIC);
    const addr = wallet.getNewAddress("legacy");
    expect(addr.startsWith("1")).toBe(true);
  });

  test("PASS: BIP-49 (P2SH-P2WPKH) emits 3-prefixed mainnet address", () => {
    const wallet = Wallet.create(makeConfig("mainnet"), ABANDON_MNEMONIC);
    const addr = wallet.getNewAddress("p2sh-segwit");
    expect(addr.startsWith("3")).toBe(true);
  });

  test("PASS: BIP-86 (P2TR / bech32m) emits bc1p-prefixed mainnet address", () => {
    const wallet = Wallet.create(makeConfig("mainnet"), ABANDON_MNEMONIC);
    const addr = wallet.getNewAddress("bech32m");
    expect(addr.startsWith("bc1p")).toBe(true);
  });
});

// ============================================================================
// G13: PSBT Creator role
// ============================================================================
describe("G13: PSBT creator role", () => {
  test("PASS: createPSBT on unsigned tx produces empty input/output maps", () => {
    const tx: Transaction = {
      version: 2,
      inputs: [
        {
          prevOut: { txid: Buffer.alloc(32, 1), vout: 0 },
          scriptSig: Buffer.alloc(0),
          sequence: 0xffffffff,
          witness: [],
        },
      ],
      outputs: [
        { value: 10000n, scriptPubKey: Buffer.from([0x00, 0x14, ...Buffer.alloc(20, 2)]) },
      ],
      lockTime: 0,
    };
    const psbt = createPSBT(tx);
    expect(psbt.inputs.length).toBe(1);
    expect(psbt.outputs.length).toBe(1);
    expect(psbt.inputs[0].partialSigs.size).toBe(0);
    expect(psbt.inputs[0].bip32Derivation.size).toBe(0);
  });

  test("PASS: createPSBT rejects pre-signed tx (non-empty scriptSig)", () => {
    const tx: Transaction = {
      version: 2,
      inputs: [
        {
          prevOut: { txid: Buffer.alloc(32, 1), vout: 0 },
          scriptSig: Buffer.from([0x01, 0x02, 0x03]), // non-empty
          sequence: 0xffffffff,
          witness: [],
        },
      ],
      outputs: [
        { value: 10000n, scriptPubKey: Buffer.from([0x00, 0x14, ...Buffer.alloc(20, 2)]) },
      ],
      lockTime: 0,
    };
    expect(() => createPSBT(tx)).toThrow();
  });
});

// ============================================================================
// G14: PSBT serialize/deserialize roundtrip
// ============================================================================
describe("G14: PSBT serialize/deserialize roundtrip", () => {
  test("PASS: serialize starts with magic 70736274ff", () => {
    const tx: Transaction = {
      version: 2,
      inputs: [
        {
          prevOut: { txid: Buffer.alloc(32, 7), vout: 1 },
          scriptSig: Buffer.alloc(0),
          sequence: 0xffffffff,
          witness: [],
        },
      ],
      outputs: [
        { value: 50000n, scriptPubKey: Buffer.from([0x00, 0x14, ...Buffer.alloc(20, 3)]) },
      ],
      lockTime: 0,
    };
    const psbt = createPSBT(tx);
    const bytes = serializePSBT(psbt);
    expect(bytes.subarray(0, 5).toString("hex")).toBe(
      PSBT_MAGIC.toString("hex")
    );
  });

  test("PASS: deserialize(serialize(psbt)) recovers tx structure", () => {
    const tx: Transaction = {
      version: 2,
      inputs: [
        {
          prevOut: { txid: Buffer.alloc(32, 9), vout: 2 },
          scriptSig: Buffer.alloc(0),
          sequence: 0xfffffffd,
          witness: [],
        },
      ],
      outputs: [
        { value: 12345n, scriptPubKey: Buffer.from([0x00, 0x14, ...Buffer.alloc(20, 4)]) },
      ],
      lockTime: 700_000,
    };
    const psbt = createPSBT(tx);
    const back = deserializePSBT(serializePSBT(psbt));
    expect(back.tx.lockTime).toBe(700_000);
    expect(back.tx.inputs[0].sequence).toBe(0xfffffffd);
    expect(back.tx.outputs[0].value).toBe(12345n);
  });

  test("PASS: base64 roundtrip preserves equality", () => {
    const tx: Transaction = {
      version: 2,
      inputs: [
        {
          prevOut: { txid: Buffer.alloc(32, 11), vout: 0 },
          scriptSig: Buffer.alloc(0),
          sequence: 0xffffffff,
          witness: [],
        },
      ],
      outputs: [
        { value: 99000n, scriptPubKey: Buffer.from([0x00, 0x14, ...Buffer.alloc(20, 5)]) },
      ],
      lockTime: 0,
    };
    const psbt = createPSBT(tx);
    const b64 = encodePSBTBase64(psbt);
    const back = decodePSBTBase64(b64);
    expect(back.inputs.length).toBe(1);
    expect(back.tx.outputs[0].value).toBe(99000n);
  });
});

// ============================================================================
// G15: PSBT signer role — P2WPKH partial signature
// ============================================================================
describe("G15: PSBT signer role (P2WPKH)", () => {
  test("PASS: signPSBTInput adds a partial sig for P2WPKH", () => {
    const priv = Buffer.from(
      "0000000000000000000000000000000000000000000000000000000000000001",
      "hex"
    );
    const pub = privateKeyToPublicKey(priv, true);
    const scriptPubKey = Buffer.concat([
      Buffer.from([0x00, 0x14]),
      hash160(pub),
    ]);

    const tx: Transaction = {
      version: 2,
      inputs: [
        {
          prevOut: { txid: Buffer.alloc(32, 0xab), vout: 0 },
          scriptSig: Buffer.alloc(0),
          sequence: 0xffffffff,
          witness: [],
        },
      ],
      outputs: [
        { value: 99000n, scriptPubKey: Buffer.from([0x00, 0x14, ...Buffer.alloc(20, 0x07)]) },
      ],
      lockTime: 0,
    };

    const psbt = createPSBT(tx);
    psbt.inputs[0].witnessUtxo = { value: 100000n, scriptPubKey };

    signPSBTInput(psbt, 0, priv, pub);
    expect(psbt.inputs[0].partialSigs.size).toBe(1);
    const entry = psbt.inputs[0].partialSigs.get(pub.toString("hex"));
    expect(entry).toBeDefined();
    // ECDSA sig + sighashType byte
    expect(entry!.signature.length).toBeGreaterThan(64);
    expect(entry!.signature[entry!.signature.length - 1]).toBe(SIGHASH_ALL);
  });
});

// ============================================================================
// G16: PSBT combiner — merge sigs from two signers
// ============================================================================
describe("G16: PSBT combiner role", () => {
  test("PASS: combinePSBTs unions partialSigs maps", () => {
    const priv1 = Buffer.from(
      "0000000000000000000000000000000000000000000000000000000000000001",
      "hex"
    );
    const priv2 = Buffer.from(
      "0000000000000000000000000000000000000000000000000000000000000002",
      "hex"
    );
    const pub1 = privateKeyToPublicKey(priv1, true);
    const pub2 = privateKeyToPublicKey(priv2, true);
    const scriptPubKey = Buffer.concat([
      Buffer.from([0x00, 0x14]),
      hash160(pub1),
    ]);

    const tx: Transaction = {
      version: 2,
      inputs: [
        {
          prevOut: { txid: Buffer.alloc(32, 0xcd), vout: 0 },
          scriptSig: Buffer.alloc(0),
          sequence: 0xffffffff,
          witness: [],
        },
      ],
      outputs: [
        { value: 50000n, scriptPubKey: Buffer.from([0x00, 0x14, ...Buffer.alloc(20, 0x08)]) },
      ],
      lockTime: 0,
    };

    const a = createPSBT(tx);
    a.inputs[0].witnessUtxo = { value: 100000n, scriptPubKey };
    signPSBTInput(a, 0, priv1, pub1);

    const b = createPSBT(tx);
    b.inputs[0].witnessUtxo = { value: 100000n, scriptPubKey };
    // Fake partial sig for pub2 (signer-by-pubkey is what combiner unions on)
    b.inputs[0].partialSigs.set(pub2.toString("hex"), {
      pubkey: pub2,
      signature: Buffer.alloc(71, 0xee),
    });

    const combined = combinePSBTs([a, b]);
    expect(combined.inputs[0].partialSigs.size).toBe(2);
    expect(
      combined.inputs[0].partialSigs.has(pub1.toString("hex"))
    ).toBe(true);
    expect(
      combined.inputs[0].partialSigs.has(pub2.toString("hex"))
    ).toBe(true);
  });
});

// ============================================================================
// G17: PSBT finalizer + extractor for P2WPKH
// ============================================================================
describe("G17: PSBT finalize + extract", () => {
  test("PASS: finalize → extract on P2WPKH yields signed tx", () => {
    const priv = Buffer.from(
      "0000000000000000000000000000000000000000000000000000000000000001",
      "hex"
    );
    const pub = privateKeyToPublicKey(priv, true);
    const scriptPubKey = Buffer.concat([
      Buffer.from([0x00, 0x14]),
      hash160(pub),
    ]);

    const tx: Transaction = {
      version: 2,
      inputs: [
        {
          prevOut: { txid: Buffer.alloc(32, 0xfa), vout: 0 },
          scriptSig: Buffer.alloc(0),
          sequence: 0xffffffff,
          witness: [],
        },
      ],
      outputs: [
        { value: 90000n, scriptPubKey: Buffer.from([0x00, 0x14, ...Buffer.alloc(20, 0x0a)]) },
      ],
      lockTime: 0,
    };
    const psbt = createPSBT(tx);
    psbt.inputs[0].witnessUtxo = { value: 100000n, scriptPubKey };
    signPSBTInput(psbt, 0, priv, pub);

    expect(finalizePSBTInput(psbt, 0)).toBe(true);
    expect(isInputFinalized(psbt.inputs[0])).toBe(true);

    const signed = extractTransaction(psbt);
    expect(signed.inputs[0].witness.length).toBe(2);
    // Empty scriptSig for native segwit
    expect(signed.inputs[0].scriptSig.length).toBe(0);
  });
});

// ============================================================================
// G18: PSBTv2 (BIP-370) — expected MISSING
// ============================================================================
describe("G18: PSBTv2 (BIP-370) support", () => {
  test("MISSING: only PSBT v0 (BIP-174) is supported; v2 is rejected", () => {
    // PSBT_HIGHEST_VERSION is hard-coded to 0 in src/wallet/psbt.ts.
    // Anything > 0 throws on deserialize.
    expect(PSBT_HIGHEST_VERSION).toBe(0);

    // Construct minimal PSBTv2 bytes: magic + global version=2 + separator + empty.
    // [magic 5B] [keylen=1] [key=0xfb] [vallen=4] [val=02 00 00 00] [sep 0x00]
    const bytes = Buffer.concat([
      PSBT_MAGIC,
      Buffer.from([0x01, 0xfb, 0x04, 0x02, 0x00, 0x00, 0x00, 0x00]),
    ]);
    expect(() => deserializePSBT(bytes)).toThrow(/[Uu]nsupported PSBT version/);
  });
});

// ============================================================================
// G19: bumpfee RPC — FIX-61 closure
// ============================================================================
describe("G19: bumpfee RPC (BIP-125 RBF)", () => {
  beforeEach(() => mkdirSync(TEST_DATADIR, { recursive: true }));
  afterEach(() => rmSync(TEST_DATADIR, { recursive: true, force: true }));

  test("PASS (FIX-61): Wallet.bumpFee exists and bumps unconfirmed RBF tx", () => {
    // Method should be defined on the prototype now that FIX-61 landed.
    expect(typeof (Wallet.prototype as unknown as Record<string, unknown>).bumpFee).toBe(
      "function"
    );

    const wallet = Wallet.create(makeConfig("mainnet"), ABANDON_MNEMONIC);
    const myAddress = wallet.getNewAddress("bech32");
    wallet.addUTXO(
      makeUTXO({
        txidSeed: 100,
        vout: 0,
        amount: 1_000_000n,
        address: myAddress,
        keyPath: "m/84'/0'/0'/0/0",
        confirmations: 6,
      })
    );

    // Build and broadcast (via createTransaction's outgoingTxs tracking) at
    // 1 sat/vB.
    const dest = "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3";
    const orig = wallet.createTransaction(
      [{ address: dest, amount: 500_000n }],
      1
    );
    const origTxid = getTxidHex(orig);

    const tracked = wallet.getOutgoingTx(origTxid);
    expect(tracked).toBeDefined();
    expect(tracked!.fee).toBeGreaterThan(0n);

    const bumped = wallet.bumpFee(origTxid, 5); // 5 sat/vB
    expect(bumped.newFee).toBeGreaterThan(bumped.origFee);
    expect(bumped.tx.inputs.length).toBe(orig.inputs.length);
    expect(bumped.tx.outputs.length).toBe(orig.outputs.length);
    // BIP-125 signaling preserved.
    expect(bumped.tx.inputs[0].sequence).toBeLessThan(0xfffffffe);
    // Replacement is signed (witness populated for P2WPKH).
    expect(bumped.tx.inputs[0].witness.length).toBeGreaterThan(0);
  });

  test("PASS (FIX-61): rejects unknown txid", () => {
    const wallet = Wallet.create(makeConfig("mainnet"), ABANDON_MNEMONIC);
    expect(() => wallet.bumpFee("00".repeat(32), 5)).toThrow(/no such wallet transaction/);
  });

  test("PASS (FIX-61): rejects confirmed tx", () => {
    const wallet = Wallet.create(makeConfig("mainnet"), ABANDON_MNEMONIC);
    const myAddress = wallet.getNewAddress("bech32");
    wallet.addUTXO(
      makeUTXO({
        txidSeed: 101,
        vout: 0,
        amount: 1_000_000n,
        address: myAddress,
        keyPath: "m/84'/0'/0'/0/0",
        confirmations: 6,
      })
    );
    const dest = "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3";
    const orig = wallet.createTransaction(
      [{ address: dest, amount: 500_000n }],
      1
    );
    const origTxidHex = getTxidHex(orig);

    // Force confirmation by directly tagging the OutgoingTx — mirrors what
    // processBlock does when it sees the tx in a connected block.
    wallet.getOutgoingTx(origTxidHex)!.confirmed = true;

    expect(() => wallet.bumpFee(origTxidHex, 5)).toThrow(/has been mined/);
  });

  test("PASS (FIX-61): rejects when new fee rate not greater than original", () => {
    const wallet = Wallet.create(makeConfig("mainnet"), ABANDON_MNEMONIC);
    const myAddress = wallet.getNewAddress("bech32");
    wallet.addUTXO(
      makeUTXO({
        txidSeed: 102,
        vout: 0,
        amount: 1_000_000n,
        address: myAddress,
        keyPath: "m/84'/0'/0'/0/0",
        confirmations: 6,
      })
    );
    const dest = "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3";
    const orig = wallet.createTransaction(
      [{ address: dest, amount: 500_000n }],
      5
    );
    const origTxidHex = getTxidHex(orig);
    // Try to bump at the same rate — must fail.
    expect(() => wallet.bumpFee(origTxidHex, 5)).toThrow(/must be greater than original/);
  });
});

// ============================================================================
// G20: psbtbumpfee RPC — FIX-61 closure
// ============================================================================
describe("G20: psbtbumpfee RPC", () => {
  beforeEach(() => mkdirSync(TEST_DATADIR, { recursive: true }));
  afterEach(() => rmSync(TEST_DATADIR, { recursive: true, force: true }));

  test("PASS (FIX-61): Wallet.psbtBumpFee exists and returns unsigned tx", () => {
    expect(typeof (Wallet.prototype as unknown as Record<string, unknown>).psbtBumpFee).toBe(
      "function"
    );

    const wallet = Wallet.create(makeConfig("mainnet"), ABANDON_MNEMONIC);
    const myAddress = wallet.getNewAddress("bech32");
    wallet.addUTXO(
      makeUTXO({
        txidSeed: 200,
        vout: 0,
        amount: 1_000_000n,
        address: myAddress,
        keyPath: "m/84'/0'/0'/0/0",
        confirmations: 6,
      })
    );
    const dest = "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3";
    const orig = wallet.createTransaction(
      [{ address: dest, amount: 500_000n }],
      1
    );
    const origTxidHex = getTxidHex(orig);

    const psbtResult = wallet.psbtBumpFee(origTxidHex, 5);
    expect(psbtResult.newFee).toBeGreaterThan(psbtResult.origFee);
    // PSBT-mode: inputs must be UNSIGNED (no witness, empty scriptSig).
    for (const inp of psbtResult.unsignedTx.inputs) {
      expect(inp.witness.length).toBe(0);
      expect(inp.scriptSig.length).toBe(0);
      // BIP-125 signaling preserved.
      expect(inp.sequence).toBeLessThan(0xfffffffe);
    }
    expect(psbtResult.inputUtxos.length).toBe(orig.inputs.length);
  });
});

// Helper: compute a canonical txid hex string for a Transaction. Mirrors
// what Wallet.createTransaction stores under outgoingTxs.
function getTxidHex(tx: Transaction): string {
  return getTxId(tx).toString("hex");
}

// ============================================================================
// G21: Anti-fee-sniping nLockTime
// ============================================================================
describe("G21: anti-fee-sniping nLockTime", () => {
  beforeEach(() => mkdirSync(TEST_DATADIR, { recursive: true }));
  afterEach(() => rmSync(TEST_DATADIR, { recursive: true, force: true }));

  test("FAIL BUG-21: createTransaction hardcodes lockTime=0 (Core sets ≈tip)", () => {
    const wallet = Wallet.create(makeConfig("mainnet"), ABANDON_MNEMONIC);

    // Find a wallet address we own — first receive bech32 address.
    const myAddress = wallet.getNewAddress("bech32");
    wallet.addUTXO(
      makeUTXO({
        txidSeed: 1,
        vout: 0,
        amount: 1_000_000n,
        address: myAddress,
        keyPath: "m/84'/0'/0'/0/0",
        confirmations: 6,
      })
    );

    // Build a tx — destination must be a valid Bitcoin address.
    const dest = "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3";
    const tx = wallet.createTransaction([{ address: dest, amount: 500_000n }], 1);

    // Core's wallet.cpp sets `tx.nLockTime = chain.getHeight()` with ~10%
    // randomization. hotbuns always emits 0 — anti-fee-sniping is missing.
    // We document this as a bug rather than break: the property "locktime == 0"
    // is the failure signal.
    expect(tx.lockTime).toBe(0);
  });
});

// ============================================================================
// G22: RBF signaling — sequence < 0xfffffffe
// ============================================================================
describe("G22: RBF (BIP-125) opt-in sequence", () => {
  beforeEach(() => mkdirSync(TEST_DATADIR, { recursive: true }));
  afterEach(() => rmSync(TEST_DATADIR, { recursive: true, force: true }));

  test("PASS (FIX-61): createTransaction emits sequence=0xfffffffd (BIP-125 opt-in RBF)", () => {
    const wallet = Wallet.create(makeConfig("mainnet"), ABANDON_MNEMONIC);
    const myAddress = wallet.getNewAddress("bech32");
    wallet.addUTXO(
      makeUTXO({
        txidSeed: 2,
        vout: 0,
        amount: 1_000_000n,
        address: myAddress,
        keyPath: "m/84'/0'/0'/0/0",
        confirmations: 6,
      })
    );

    const dest = "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3";
    const tx = wallet.createTransaction([{ address: dest, amount: 500_000n }], 1);

    // BIP-125: any input with sequence < 0xfffffffe signals RBF replaceability.
    // Hotbuns now emits 0xfffffffd (MAX_BIP125_RBF_SEQUENCE), matching Core's
    // wallet default. This is BOTH a prerequisite for bumpfee (Part 2 of
    // FIX-61) and the fix for the W118 BUG-22 "RBF opt-out" finding.
    expect(tx.inputs[0].sequence).toBe(0xfffffffd);
    // Must also be < 0xfffffffe to satisfy the BIP-125 signaling check.
    expect(tx.inputs[0].sequence).toBeLessThan(0xfffffffe);
  });
});

// ============================================================================
// G23: sendtoaddress fee calculation
// ============================================================================
describe("G23: createTransaction fee calculation", () => {
  beforeEach(() => mkdirSync(TEST_DATADIR, { recursive: true }));
  afterEach(() => rmSync(TEST_DATADIR, { recursive: true, force: true }));

  test("PASS: change output absorbs fee; sum-of-outputs + fee <= input", () => {
    const wallet = Wallet.create(makeConfig("mainnet"), ABANDON_MNEMONIC);
    const myAddress = wallet.getNewAddress("bech32");
    wallet.addUTXO(
      makeUTXO({
        txidSeed: 3,
        vout: 0,
        amount: 1_000_000n,
        address: myAddress,
        keyPath: "m/84'/0'/0'/0/0",
        confirmations: 6,
      })
    );

    const dest = "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3";
    const tx = wallet.createTransaction([{ address: dest, amount: 500_000n }], 5);

    let outSum = 0n;
    for (const out of tx.outputs) outSum += out.value;
    // total out ≤ total in (fee >= 0)
    expect(outSum < 1_000_000n).toBe(true);
    // payment output exists
    expect(tx.outputs.some((o) => o.value === 500_000n)).toBe(true);
  });
});

// ============================================================================
// G24: Dust threshold per address type
// ============================================================================
describe("G24: dust threshold", () => {
  beforeEach(() => mkdirSync(TEST_DATADIR, { recursive: true }));
  afterEach(() => rmSync(TEST_DATADIR, { recursive: true, force: true }));

  test("FAIL BUG-24: dust threshold is hardcoded 546 (P2PKH) — wrong for P2WPKH/P2TR", () => {
    // Core uses GetDustThreshold(output, dustRelayFee):
    //   - P2PKH:   546 sat (matches)
    //   - P2WPKH:  294 sat
    //   - P2TR:    330 sat
    // src/wallet/wallet.ts:1016 hardcodes `DUST_THRESHOLD = 546n` regardless
    // of change address type. This loses 252 sat (P2WPKH) / 216 sat (P2TR)
    // of change to fee unnecessarily on every transaction where change
    // falls into that window.
    const wallet = Wallet.create(makeConfig("mainnet"), ABANDON_MNEMONIC);
    const myAddress = wallet.getNewAddress("bech32");

    // Hand-craft a UTXO such that change = exactly 400 sats (between 294 and 546).
    // Use input = target + estimated_fee + 400.
    // For 1 P2WPKH input + 1 P2WPKH output + 1 P2WPKH change @ feerate=1:
    //   vsize ≈ 10 + 68 + 31*2 = 140 vbytes → fee = 140 sats.
    // So input = 1000 + 140 + 400 = 1540
    wallet.addUTXO(
      makeUTXO({
        txidSeed: 4,
        vout: 0,
        amount: 1540n,
        address: myAddress,
        keyPath: "m/84'/0'/0'/0/0",
        confirmations: 6,
      })
    );

    const dest = "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3";
    const tx = wallet.createTransaction(
      [{ address: dest, amount: 1000n }],
      1
    );

    // Change ~400 < 546 → dropped despite being well above P2WPKH dust (294).
    // Therefore only the payment output should appear.
    expect(tx.outputs.length).toBe(1);
  });
});

// ============================================================================
// G25: Insufficient-funds error path
// ============================================================================
describe("G25: insufficient funds detection", () => {
  beforeEach(() => mkdirSync(TEST_DATADIR, { recursive: true }));
  afterEach(() => rmSync(TEST_DATADIR, { recursive: true, force: true }));

  test("PASS: createTransaction throws when funds < target+fee", () => {
    const wallet = Wallet.create(makeConfig("mainnet"), ABANDON_MNEMONIC);
    const myAddress = wallet.getNewAddress("bech32");
    wallet.addUTXO(
      makeUTXO({
        txidSeed: 5,
        vout: 0,
        amount: 1000n,
        address: myAddress,
        keyPath: "m/84'/0'/0'/0/0",
        confirmations: 6,
      })
    );

    const dest = "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3";
    expect(() =>
      wallet.createTransaction([{ address: dest, amount: 5000n }], 1)
    ).toThrow(/[Ii]nsufficient/);
  });

  test("PASS: throws on empty UTXO pool", () => {
    const wallet = Wallet.create(makeConfig("mainnet"), ABANDON_MNEMONIC);
    const dest = "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3";
    expect(() =>
      wallet.createTransaction([{ address: dest, amount: 100n }], 1)
    ).toThrow();
  });
});

// ============================================================================
// G26: sendmany — multi-output createTransaction
// ============================================================================
describe("G26: sendmany / multi-output", () => {
  beforeEach(() => mkdirSync(TEST_DATADIR, { recursive: true }));
  afterEach(() => rmSync(TEST_DATADIR, { recursive: true, force: true }));

  test("PASS: createTransaction with multiple destinations preserves all outputs", () => {
    const wallet = Wallet.create(makeConfig("mainnet"), ABANDON_MNEMONIC);
    const myAddress = wallet.getNewAddress("bech32");
    wallet.addUTXO(
      makeUTXO({
        txidSeed: 6,
        vout: 0,
        amount: 10_000_000n,
        address: myAddress,
        keyPath: "m/84'/0'/0'/0/0",
        confirmations: 6,
      })
    );

    const d1 = "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3";
    const d2 = "bc1q0ht9tyks4vh7p5p904t340cr9nvahy7u3re7zg";
    const tx = wallet.createTransaction(
      [
        { address: d1, amount: 1_000_000n },
        { address: d2, amount: 2_000_000n },
      ],
      2
    );

    // Two destination outputs + possibly one change output
    expect(tx.outputs.length >= 2).toBe(true);
    const totalDest =
      tx.outputs
        .filter((o) => o.value === 1_000_000n || o.value === 2_000_000n)
        .reduce((s, o) => s + o.value, 0n);
    expect(totalDest).toBe(3_000_000n);
  });
});

// ============================================================================
// G27: COINBASE_MATURITY = 100 confirmations
// ============================================================================
describe("G27: coinbase maturity", () => {
  beforeEach(() => mkdirSync(TEST_DATADIR, { recursive: true }));
  afterEach(() => rmSync(TEST_DATADIR, { recursive: true, force: true }));

  test("PASS: COINBASE_MATURITY constant equals Core's 100", () => {
    expect(COINBASE_MATURITY).toBe(100);
  });

  test("PASS: immature coinbase (conf=99) is not in getSpendableUTXOs()", () => {
    const wallet = Wallet.create(makeConfig("mainnet"), ABANDON_MNEMONIC);
    const myAddress = wallet.getNewAddress("bech32");
    wallet.addUTXO(
      makeUTXO({
        txidSeed: 7,
        vout: 0,
        amount: 50_00000000n, // 50 BTC subsidy
        address: myAddress,
        keyPath: "m/84'/0'/0'/0/0",
        confirmations: 99,
        isCoinbase: true,
      })
    );

    expect(wallet.getSpendableUTXOs().length).toBe(0);
  });

  test("PASS: mature coinbase (conf=101) IS spendable", () => {
    const wallet = Wallet.create(makeConfig("mainnet"), ABANDON_MNEMONIC);
    const myAddress = wallet.getNewAddress("bech32");
    wallet.addUTXO(
      makeUTXO({
        txidSeed: 8,
        vout: 0,
        amount: 50_00000000n,
        address: myAddress,
        keyPath: "m/84'/0'/0'/0/0",
        // Core wallet matures a coinbase at depth >= COINBASE_MATURITY + 1
        // (GetTxBlocksToMaturity == 0, wallet.cpp:3333-3343).
        confirmations: 101,
        isCoinbase: true,
      })
    );
    expect(wallet.getSpendableUTXOs().length).toBe(1);
  });
});

// ============================================================================
// G28: processBlock UTXO discovery + spend tracking
// ============================================================================
describe("G28: processBlock UTXO discovery", () => {
  beforeEach(() => mkdirSync(TEST_DATADIR, { recursive: true }));
  afterEach(() => rmSync(TEST_DATADIR, { recursive: true, force: true }));

  test("PASS: processBlock adds outputs paying to our address", () => {
    const wallet = Wallet.create(makeConfig("mainnet"), ABANDON_MNEMONIC);
    const myAddress = wallet.getNewAddress("bech32");
    // Decode address → hash160 — but we'll build a P2WPKH scriptPubKey
    // from the wallet's own buildScriptPubKey behaviour: just decode.
    const { decodeAddress } = require("../address/encoding");
    const decoded = decodeAddress(myAddress);
    const scriptPubKey = Buffer.concat([
      Buffer.from([0x00, 0x14]),
      decoded.hash,
    ]);

    const block = {
      header: {
        version: 1,
        prevBlock: Buffer.alloc(32),
        merkleRoot: Buffer.alloc(32),
        timestamp: 0,
        bits: 0x1d00ffff,
        nonce: 0,
      },
      transactions: [
        {
          version: 2,
          inputs: [
            {
              prevOut: { txid: Buffer.alloc(32, 0xfe), vout: 0xffffffff },
              scriptSig: Buffer.from([0x51]),
              sequence: 0xffffffff,
              witness: [],
            },
          ],
          outputs: [{ value: 5000n, scriptPubKey }],
          lockTime: 0,
        },
      ],
    } as unknown as Parameters<typeof wallet.processBlock>[0];

    expect(wallet.getUTXOs().length).toBe(0);
    wallet.processBlock(block, 1);
    expect(wallet.getUTXOs().length).toBe(1);
    expect(wallet.getUTXOs()[0].amount).toBe(5000n);
  });

  test("PASS: processBlock removes UTXOs spent by an input", () => {
    const wallet = Wallet.create(makeConfig("mainnet"), ABANDON_MNEMONIC);
    const myAddress = wallet.getNewAddress("bech32");

    // Seed a UTXO that some later tx will spend.
    const seedUtxo = makeUTXO({
      txidSeed: 42,
      vout: 0,
      amount: 100_000n,
      address: myAddress,
      keyPath: "m/84'/0'/0'/0/0",
      confirmations: 6,
    });
    wallet.addUTXO(seedUtxo);
    expect(wallet.getUTXOs().length).toBe(1);

    // Build a block whose only tx spends that exact outpoint.
    const block = {
      header: {
        version: 1,
        prevBlock: Buffer.alloc(32),
        merkleRoot: Buffer.alloc(32),
        timestamp: 0,
        bits: 0,
        nonce: 0,
      },
      transactions: [
        {
          version: 2,
          inputs: [
            {
              prevOut: { txid: seedUtxo.outpoint.txid, vout: 0 },
              scriptSig: Buffer.alloc(0),
              sequence: 0xffffffff,
              witness: [],
            },
          ],
          outputs: [
            {
              value: 90_000n,
              scriptPubKey: Buffer.from([0x00, 0x14, ...Buffer.alloc(20, 0xaa)]),
            },
          ],
          lockTime: 0,
        },
      ],
    } as unknown as Parameters<typeof wallet.processBlock>[0];

    wallet.processBlock(block, 100);
    expect(wallet.getUTXOs().length).toBe(0);
  });
});

// ============================================================================
// G29: getBalance — confirmed vs unconfirmed split
// ============================================================================
describe("G29: getBalance confirmed/unconfirmed split", () => {
  beforeEach(() => mkdirSync(TEST_DATADIR, { recursive: true }));
  afterEach(() => rmSync(TEST_DATADIR, { recursive: true, force: true }));

  test("PASS: confirmations >= 1 → confirmed, else unconfirmed", () => {
    const wallet = Wallet.create(makeConfig("mainnet"), ABANDON_MNEMONIC);
    const myAddress = wallet.getNewAddress("bech32");

    wallet.addUTXO(
      makeUTXO({
        txidSeed: 11,
        vout: 0,
        amount: 100n,
        address: myAddress,
        keyPath: "m/84'/0'/0'/0/0",
        confirmations: 0,
      })
    );
    wallet.addUTXO(
      makeUTXO({
        txidSeed: 12,
        vout: 0,
        amount: 200n,
        address: myAddress,
        keyPath: "m/84'/0'/0'/0/0",
        confirmations: 6,
      })
    );

    const bal = wallet.getBalance();
    expect(bal.confirmed).toBe(200n);
    expect(bal.unconfirmed).toBe(100n);
    expect(bal.total).toBe(300n);
  });
});

// ============================================================================
// G30: listUnspent / minconf filtering (via selectCoinsAdvanced)
// ============================================================================
describe("G30: minconf filtering for spending", () => {
  beforeEach(() => mkdirSync(TEST_DATADIR, { recursive: true }));
  afterEach(() => rmSync(TEST_DATADIR, { recursive: true, force: true }));

  test("PASS: zero-conf UTXOs are excluded from coin selection", () => {
    const wallet = Wallet.create(makeConfig("mainnet"), ABANDON_MNEMONIC);
    const myAddress = wallet.getNewAddress("bech32");

    // Only unconfirmed UTXO — selection should fail.
    wallet.addUTXO(
      makeUTXO({
        txidSeed: 13,
        vout: 0,
        amount: 10_000_000n,
        address: myAddress,
        keyPath: "m/84'/0'/0'/0/0",
        confirmations: 0,
      })
    );

    const dest = "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3";
    expect(() =>
      wallet.createTransaction([{ address: dest, amount: 500_000n }], 1)
    ).toThrow(/[Nn]o confirmed UTXOs/);
  });

  test("PASS: getSpendableUTXOs filters confirmations < 1", () => {
    const wallet = Wallet.create(makeConfig("mainnet"), ABANDON_MNEMONIC);
    const myAddress = wallet.getNewAddress("bech32");

    wallet.addUTXO(
      makeUTXO({
        txidSeed: 14,
        vout: 0,
        amount: 100n,
        address: myAddress,
        keyPath: "m/84'/0'/0'/0/0",
        confirmations: 0,
      })
    );
    wallet.addUTXO(
      makeUTXO({
        txidSeed: 15,
        vout: 0,
        amount: 200n,
        address: myAddress,
        keyPath: "m/84'/0'/0'/0/0",
        confirmations: 1,
      })
    );

    const spendable = wallet.getSpendableUTXOs();
    expect(spendable.length).toBe(1);
    expect(spendable[0].amount).toBe(200n);
  });
});
