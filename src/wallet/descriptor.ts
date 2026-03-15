/**
 * Output Descriptors (BIP380-386)
 *
 * A language for describing sets of output scripts, enabling wallet import/export
 * and watch-only wallets.
 *
 * Supported descriptor types:
 * - pk(KEY)      - P2PK: pay to public key
 * - pkh(KEY)     - P2PKH: pay to public key hash
 * - wpkh(KEY)    - P2WPKH: pay to witness public key hash
 * - sh(SCRIPT)   - P2SH: pay to script hash
 * - wsh(SCRIPT)  - P2WSH: pay to witness script hash
 * - tr(KEY)      - P2TR: pay to taproot (key-path only)
 * - tr(KEY,TREE) - P2TR with script tree
 * - multi(K,...)  - K-of-N multisig
 * - sortedmulti(K,...) - K-of-N sorted multisig
 * - addr(ADDR)   - Raw address
 * - raw(HEX)     - Raw script
 * - combo(KEY)   - P2PK + P2PKH + P2WPKH + P2SH-P2WPKH (if compressed)
 *
 * Key expressions:
 * - Hex pubkeys (33 or 65 bytes)
 * - WIF private keys
 * - xpub/xprv with derivation paths ([fingerprint/path]xpub.../0/*)
 *
 * References:
 * - BIP 380: https://github.com/bitcoin/bips/blob/master/bip-0380.mediawiki
 * - BIP 381: https://github.com/bitcoin/bips/blob/master/bip-0381.mediawiki
 * - BIP 382: https://github.com/bitcoin/bips/blob/master/bip-0382.mediawiki
 * - BIP 383: https://github.com/bitcoin/bips/blob/master/bip-0383.mediawiki
 * - BIP 384: https://github.com/bitcoin/bips/blob/master/bip-0384.mediawiki
 * - BIP 385: https://github.com/bitcoin/bips/blob/master/bip-0385.mediawiki
 * - BIP 386: https://github.com/bitcoin/bips/blob/master/bip-0386.mediawiki
 * - Bitcoin Core: /src/script/descriptor.cpp
 */

import { hmac } from "@noble/hashes/hmac.js";
import { sha512, sha256 as sha256Noble } from "@noble/hashes/sha2.js";
import { schnorr, secp256k1 } from "@noble/curves/secp256k1.js";
import {
  hash160,
  hash256,
  privateKeyToPublicKey,
  taggedHash,
  sha256Hash,
} from "../crypto/primitives.js";
import {
  AddressType,
  decodeAddress,
  encodeAddress,
  base58CheckDecode,
  base58CheckEncode,
  bech32Encode,
} from "../address/encoding.js";
import { Opcode } from "../script/interpreter.js";
import type { KeyOriginInfo } from "./psbt.js";

// =============================================================================
// Constants
// =============================================================================

/** BIP-32 hardened offset */
const HARDENED_OFFSET = 0x80000000;

/** secp256k1 curve order */
const CURVE_ORDER = BigInt(
  "0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"
);

/** Taproot tweak tag */
const TAPTWEAK_TAG = "TapTweak";

/**
 * Input character set for descriptor checksum (95 characters).
 * Arranged so uppercase/lowercase pairs share groups for error detection.
 */
const INPUT_CHARSET =
  "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ ";

/**
 * Checksum character set (32 characters, same as bech32).
 */
const CHECKSUM_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

// Base58 alphabet
const BASE58_ALPHABET =
  "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

// =============================================================================
// Checksum Algorithm (BIP380)
// =============================================================================

/**
 * Polynomial modular reduction in GF(32).
 *
 * Generator polynomial:
 * G(x) = x^8 + {30}x^7 + {23}x^6 + {15}x^5 + {14}x^4 + {10}x^3 + {6}x^2 + {12}x + {9}
 */
function polyMod(c: bigint, val: number): bigint {
  const c0 = Number(c >> 35n);
  c = ((c & 0x7ffffffffn) << 5n) ^ BigInt(val);

  // XOR with generator constants based on bits of c0
  if (c0 & 1) c ^= 0xf5dee51989n;
  if (c0 & 2) c ^= 0xa9fdca3312n;
  if (c0 & 4) c ^= 0x1bab10e32dn;
  if (c0 & 8) c ^= 0x3706b1677an;
  if (c0 & 16) c ^= 0x644d626ffdn;

  return c;
}

/**
 * Compute the 8-character checksum for a descriptor string.
 * Returns only the checksum portion (without the '#' prefix).
 */
export function descriptorChecksum(desc: string): string {
  let c = 1n;
  let cls = 0;
  let clscount = 0;

  for (const ch of desc) {
    const pos = INPUT_CHARSET.indexOf(ch);
    if (pos === -1) {
      throw new Error(`Invalid character '${ch}' in descriptor`);
    }

    // Emit the low 5 bits of position
    c = polyMod(c, pos & 31);

    // Group characters into triplets
    cls = cls * 3 + (pos >> 5);
    clscount++;
    if (clscount === 3) {
      c = polyMod(c, cls);
      cls = 0;
      clscount = 0;
    }
  }

  // Flush remaining class bits
  if (clscount > 0) c = polyMod(c, cls);

  // Finalize: 8 more iterations with 0
  for (let i = 0; i < 8; i++) {
    c = polyMod(c, 0);
  }

  // XOR with 1 to prevent appending zeros affecting checksum
  c ^= 1n;

  // Extract 8 5-bit values
  let result = "";
  for (let i = 0; i < 8; i++) {
    result = CHECKSUM_CHARSET[Number((c >> (5n * BigInt(i))) & 31n)] + result;
  }

  return result;
}

/**
 * Add checksum to descriptor string.
 */
export function addChecksum(desc: string): string {
  // Strip existing checksum if present
  const hashIdx = desc.indexOf("#");
  if (hashIdx !== -1) {
    desc = desc.slice(0, hashIdx);
  }
  return `${desc}#${descriptorChecksum(desc)}`;
}

/**
 * Validate descriptor checksum. Returns the descriptor without checksum if valid.
 */
export function validateChecksum(desc: string): string {
  const hashIdx = desc.indexOf("#");
  if (hashIdx === -1) {
    // No checksum present, return as-is
    return desc;
  }

  const base = desc.slice(0, hashIdx);
  const checksum = desc.slice(hashIdx + 1);

  if (checksum.length !== 8) {
    throw new Error("Invalid checksum length");
  }

  const expected = descriptorChecksum(base);
  if (checksum !== expected) {
    throw new Error(`Invalid checksum: expected ${expected}, got ${checksum}`);
  }

  return base;
}

// =============================================================================
// Key Types
// =============================================================================

/**
 * Type of key derivation.
 */
export enum DeriveType {
  /** Single key, no range */
  NO_RANGE = "no_range",
  /** Range with unhardened derivation (xpub.../0/*) */
  UNHARDENED = "unhardened",
  /** Range with hardened derivation (xpub.../0/*') */
  HARDENED = "hardened",
}

/**
 * Extended key data (xpub/xprv).
 */
export interface ExtendedKey {
  /** Version bytes (4 bytes) */
  version: number;
  /** Depth in derivation tree */
  depth: number;
  /** Parent fingerprint (4 bytes) */
  parentFingerprint: Buffer;
  /** Child index */
  childIndex: number;
  /** Chain code (32 bytes) */
  chainCode: Buffer;
  /** Key data (33 bytes for pubkey, 33 bytes with 0x00 prefix for privkey) */
  key: Buffer;
  /** Whether this is a private key */
  isPrivate: boolean;
}

/**
 * Abstract base class for public key providers.
 */
export interface PubkeyProvider {
  /** Get the public key at the given derivation index */
  getPubKey(index: number): Buffer;
  /** Whether this provider supports range derivation */
  isRange(): boolean;
  /** Get the size of the public key (33 or 65 bytes) */
  getSize(): number;
  /** Whether the key is x-only (32 bytes, for Taproot) */
  isXOnly(): boolean;
  /** Convert to descriptor string form */
  toString(): string;
  /** Convert to private string form (includes private key if available) */
  toPrivateString(): string;
  /** Get the origin info ([fingerprint/path]) if present */
  getOrigin(): KeyOriginInfo | undefined;
  /** Get the private key if available */
  getPrivKey(): Buffer | undefined;
}

/**
 * Constant (non-extended) public key provider.
 */
export class ConstPubkeyProvider implements PubkeyProvider {
  private pubkey: Buffer;
  private privkey: Buffer | undefined;
  private xonly: boolean;
  private origin: KeyOriginInfo | undefined;

  constructor(
    pubkey: Buffer,
    privkey?: Buffer,
    xonly: boolean = false,
    origin?: KeyOriginInfo
  ) {
    this.pubkey = pubkey;
    this.privkey = privkey;
    this.xonly = xonly;
    this.origin = origin;
  }

  getPubKey(_index: number): Buffer {
    return this.pubkey;
  }

  isRange(): boolean {
    return false;
  }

  getSize(): number {
    return this.xonly ? 32 : this.pubkey.length;
  }

  isXOnly(): boolean {
    return this.xonly;
  }

  toString(): string {
    const originStr = this.origin
      ? `[${this.origin.fingerprint.toString("hex")}/${formatPath(this.origin.path)}]`
      : "";
    return `${originStr}${this.pubkey.toString("hex")}`;
  }

  toPrivateString(): string {
    if (this.privkey) {
      const originStr = this.origin
        ? `[${this.origin.fingerprint.toString("hex")}/${formatPath(this.origin.path)}]`
        : "";
      // TODO: Convert to WIF
      return `${originStr}${this.privkey.toString("hex")}`;
    }
    return this.toString();
  }

  getOrigin(): KeyOriginInfo | undefined {
    return this.origin;
  }

  getPrivKey(): Buffer | undefined {
    return this.privkey;
  }
}

/**
 * BIP-32 extended key provider with derivation path.
 */
export class BIP32PubkeyProvider implements PubkeyProvider {
  private extkey: ExtendedKey;
  private path: number[];
  private deriveType: DeriveType;
  private origin: KeyOriginInfo | undefined;
  private useApostrophe: boolean;

  constructor(
    extkey: ExtendedKey,
    path: number[],
    deriveType: DeriveType,
    origin?: KeyOriginInfo,
    useApostrophe: boolean = true
  ) {
    this.extkey = extkey;
    this.path = path;
    this.deriveType = deriveType;
    this.origin = origin;
    this.useApostrophe = useApostrophe;
  }

  getPubKey(index: number): Buffer {
    // Start from the extended key
    let currentKey = this.extkey.key;
    let currentChainCode = this.extkey.chainCode;
    let isPrivate = this.extkey.isPrivate;

    // Derive along the fixed path
    for (const childIndex of this.path) {
      const derived = this.deriveChild(
        currentKey,
        currentChainCode,
        childIndex,
        isPrivate
      );
      currentKey = derived.key;
      currentChainCode = derived.chainCode;
    }

    // If range, derive the final index
    if (this.deriveType !== DeriveType.NO_RANGE) {
      const childIndex =
        this.deriveType === DeriveType.HARDENED
          ? index + HARDENED_OFFSET
          : index;
      const derived = this.deriveChild(
        currentKey,
        currentChainCode,
        childIndex,
        isPrivate
      );
      currentKey = derived.key;
    }

    // If we have a private key, convert to public
    if (isPrivate) {
      currentKey = privateKeyToPublicKey(currentKey, true);
    }

    return currentKey;
  }

  private deriveChild(
    parentKey: Buffer,
    parentChainCode: Buffer,
    index: number,
    isPrivate: boolean
  ): { key: Buffer; chainCode: Buffer } {
    const isHardened = index >= HARDENED_OFFSET;

    if (isHardened && !isPrivate) {
      throw new Error("Cannot derive hardened child from public key");
    }

    let data: Buffer;
    if (isHardened) {
      // Hardened: 0x00 || private key || index
      data = Buffer.alloc(37);
      data[0] = 0x00;
      parentKey.copy(data, 1);
      data.writeUInt32BE(index, 33);
    } else {
      // Normal: public key || index
      const parentPubKey = isPrivate
        ? privateKeyToPublicKey(parentKey, true)
        : parentKey;
      data = Buffer.alloc(37);
      parentPubKey.copy(data, 0);
      data.writeUInt32BE(index, 33);
    }

    const I = Buffer.from(hmac(sha512, parentChainCode, data));
    const IL = I.subarray(0, 32);
    const IR = I.subarray(32, 64);

    let childKey: Buffer;
    if (isPrivate) {
      // Child private key = IL + parent key (mod curve order)
      const parentKeyBigInt = BigInt("0x" + parentKey.toString("hex"));
      const ILBigInt = BigInt("0x" + IL.toString("hex"));
      const childKeyBigInt = (parentKeyBigInt + ILBigInt) % CURVE_ORDER;
      let childKeyHex = childKeyBigInt.toString(16);
      childKeyHex = childKeyHex.padStart(64, "0");
      childKey = Buffer.from(childKeyHex, "hex");
    } else {
      // Child public key = IL * G + parent key
      const ILBigInt = BigInt("0x" + IL.toString("hex"));
      const parentPoint = secp256k1.Point.fromHex(parentKey.toString("hex"));
      const ILPoint = secp256k1.Point.BASE.multiply(ILBigInt);
      const childPoint = parentPoint.add(ILPoint);
      childKey = Buffer.from(childPoint.toBytes(true));
    }

    return {
      key: childKey,
      chainCode: Buffer.from(IR),
    };
  }

  isRange(): boolean {
    return this.deriveType !== DeriveType.NO_RANGE;
  }

  getSize(): number {
    return 33; // Compressed pubkey
  }

  isXOnly(): boolean {
    return false;
  }

  toString(): string {
    const originStr = this.origin
      ? `[${this.origin.fingerprint.toString("hex")}/${formatPath(this.origin.path, this.useApostrophe)}]`
      : "";
    const extkeyStr = encodeExtendedKey(this.extkey);
    const pathStr =
      this.path.length > 0
        ? "/" + formatPath(this.path, this.useApostrophe)
        : "";
    const rangeStr =
      this.deriveType === DeriveType.HARDENED
        ? "/*'"
        : this.deriveType === DeriveType.UNHARDENED
          ? "/*"
          : "";
    return `${originStr}${extkeyStr}${pathStr}${rangeStr}`;
  }

  toPrivateString(): string {
    if (this.extkey.isPrivate) {
      return this.toString();
    }
    return this.toString();
  }

  getOrigin(): KeyOriginInfo | undefined {
    return this.origin;
  }

  getPrivKey(): Buffer | undefined {
    return this.extkey.isPrivate ? this.extkey.key : undefined;
  }

  getExtendedKey(): ExtendedKey {
    return this.extkey;
  }

  getPath(): number[] {
    return this.path;
  }

  getDeriveType(): DeriveType {
    return this.deriveType;
  }
}

// =============================================================================
// Descriptor Types
// =============================================================================

/**
 * Type of descriptor.
 */
export enum DescriptorType {
  PK = "pk",
  PKH = "pkh",
  WPKH = "wpkh",
  SH = "sh",
  WSH = "wsh",
  TR = "tr",
  MULTI = "multi",
  SORTEDMULTI = "sortedmulti",
  ADDR = "addr",
  RAW = "raw",
  COMBO = "combo",
}

/**
 * Output type for a descriptor.
 */
export enum OutputType {
  LEGACY = "legacy",
  P2SH_SEGWIT = "p2sh_segwit",
  BECH32 = "bech32",
  BECH32M = "bech32m",
}

/**
 * Expanded descriptor output.
 */
export interface ExpandedOutput {
  /** scriptPubKey */
  scriptPubKey: Buffer;
  /** Address (if applicable) */
  address?: string;
  /** Output type */
  outputType: OutputType;
  /** Redeem script (for P2SH) */
  redeemScript?: Buffer;
  /** Witness script (for P2WSH) */
  witnessScript?: Buffer;
  /** Public keys used */
  pubkeys: Buffer[];
  /** Origin info for each pubkey */
  origins: Map<string, KeyOriginInfo>;
}

/**
 * Abstract descriptor interface.
 */
export interface Descriptor {
  /** Get the descriptor type */
  getType(): DescriptorType;
  /** Whether this is a ranged descriptor */
  isRange(): boolean;
  /** Whether this descriptor expands to a single script type */
  isSingleType(): boolean;
  /** Get the output type(s) */
  getOutputType(): OutputType | undefined;
  /** Expand the descriptor at the given index */
  expand(index: number, network: NetworkType): ExpandedOutput[];
  /** Convert to canonical descriptor string */
  toString(): string;
  /** Convert to string with private keys */
  toPrivateString(): string;
}

// Network type for address encoding
export type NetworkType = "mainnet" | "testnet" | "regtest";

// =============================================================================
// Descriptor Implementations
// =============================================================================

/**
 * pk(KEY) - Pay to public key
 */
export class PKDescriptor implements Descriptor {
  private pubkeyProvider: PubkeyProvider;

  constructor(pubkeyProvider: PubkeyProvider) {
    this.pubkeyProvider = pubkeyProvider;
  }

  getType(): DescriptorType {
    return DescriptorType.PK;
  }

  isRange(): boolean {
    return this.pubkeyProvider.isRange();
  }

  isSingleType(): boolean {
    return true;
  }

  getOutputType(): OutputType {
    return OutputType.LEGACY;
  }

  expand(index: number, _network: NetworkType): ExpandedOutput[] {
    const pubkey = this.pubkeyProvider.getPubKey(index);
    const script = buildP2PKScript(pubkey);
    const origins = new Map<string, KeyOriginInfo>();
    const origin = this.pubkeyProvider.getOrigin();
    if (origin) {
      origins.set(pubkey.toString("hex"), origin);
    }

    return [
      {
        scriptPubKey: script,
        outputType: OutputType.LEGACY,
        pubkeys: [pubkey],
        origins,
      },
    ];
  }

  toString(): string {
    return `pk(${this.pubkeyProvider.toString()})`;
  }

  toPrivateString(): string {
    return `pk(${this.pubkeyProvider.toPrivateString()})`;
  }
}

/**
 * pkh(KEY) - Pay to public key hash
 */
export class PKHDescriptor implements Descriptor {
  private pubkeyProvider: PubkeyProvider;

  constructor(pubkeyProvider: PubkeyProvider) {
    this.pubkeyProvider = pubkeyProvider;
  }

  getType(): DescriptorType {
    return DescriptorType.PKH;
  }

  isRange(): boolean {
    return this.pubkeyProvider.isRange();
  }

  isSingleType(): boolean {
    return true;
  }

  getOutputType(): OutputType {
    return OutputType.LEGACY;
  }

  expand(index: number, network: NetworkType): ExpandedOutput[] {
    const pubkey = this.pubkeyProvider.getPubKey(index);
    const pubkeyHash = hash160(pubkey);
    const script = buildP2PKHScript(pubkeyHash);
    const address = encodeAddress({
      type: AddressType.P2PKH,
      hash: pubkeyHash,
      network,
    });
    const origins = new Map<string, KeyOriginInfo>();
    const origin = this.pubkeyProvider.getOrigin();
    if (origin) {
      origins.set(pubkey.toString("hex"), origin);
    }

    return [
      {
        scriptPubKey: script,
        address,
        outputType: OutputType.LEGACY,
        pubkeys: [pubkey],
        origins,
      },
    ];
  }

  toString(): string {
    return `pkh(${this.pubkeyProvider.toString()})`;
  }

  toPrivateString(): string {
    return `pkh(${this.pubkeyProvider.toPrivateString()})`;
  }
}

/**
 * wpkh(KEY) - Pay to witness public key hash
 */
export class WPKHDescriptor implements Descriptor {
  private pubkeyProvider: PubkeyProvider;

  constructor(pubkeyProvider: PubkeyProvider) {
    this.pubkeyProvider = pubkeyProvider;
  }

  getType(): DescriptorType {
    return DescriptorType.WPKH;
  }

  isRange(): boolean {
    return this.pubkeyProvider.isRange();
  }

  isSingleType(): boolean {
    return true;
  }

  getOutputType(): OutputType {
    return OutputType.BECH32;
  }

  expand(index: number, network: NetworkType): ExpandedOutput[] {
    const pubkey = this.pubkeyProvider.getPubKey(index);

    // wpkh requires compressed pubkey
    if (pubkey.length !== 33) {
      throw new Error("wpkh requires compressed public key");
    }

    const pubkeyHash = hash160(pubkey);
    const script = buildP2WPKHScript(pubkeyHash);
    const hrp = getHrp(network);
    const address = bech32Encode(hrp, 0, pubkeyHash);
    const origins = new Map<string, KeyOriginInfo>();
    const origin = this.pubkeyProvider.getOrigin();
    if (origin) {
      origins.set(pubkey.toString("hex"), origin);
    }

    return [
      {
        scriptPubKey: script,
        address,
        outputType: OutputType.BECH32,
        pubkeys: [pubkey],
        origins,
      },
    ];
  }

  toString(): string {
    return `wpkh(${this.pubkeyProvider.toString()})`;
  }

  toPrivateString(): string {
    return `wpkh(${this.pubkeyProvider.toPrivateString()})`;
  }
}

/**
 * sh(SCRIPT) - Pay to script hash
 */
export class SHDescriptor implements Descriptor {
  private subdescriptor: Descriptor;

  constructor(subdescriptor: Descriptor) {
    this.subdescriptor = subdescriptor;
  }

  getType(): DescriptorType {
    return DescriptorType.SH;
  }

  isRange(): boolean {
    return this.subdescriptor.isRange();
  }

  isSingleType(): boolean {
    return this.subdescriptor.isSingleType();
  }

  getOutputType(): OutputType {
    // If subdescriptor is segwit, this is P2SH-segwit
    const subType = this.subdescriptor.getOutputType();
    if (subType === OutputType.BECH32 || subType === OutputType.BECH32M) {
      return OutputType.P2SH_SEGWIT;
    }
    return OutputType.LEGACY;
  }

  expand(index: number, network: NetworkType): ExpandedOutput[] {
    const subOutputs = this.subdescriptor.expand(index, network);
    const results: ExpandedOutput[] = [];

    for (const subOutput of subOutputs) {
      const redeemScript = subOutput.scriptPubKey;
      const scriptHash = hash160(redeemScript);
      const script = buildP2SHScript(scriptHash);
      const address = encodeAddress({
        type: AddressType.P2SH,
        hash: scriptHash,
        network,
      });

      results.push({
        scriptPubKey: script,
        address,
        outputType: this.getOutputType(),
        redeemScript,
        witnessScript: subOutput.witnessScript,
        pubkeys: subOutput.pubkeys,
        origins: subOutput.origins,
      });
    }

    return results;
  }

  toString(): string {
    return `sh(${this.subdescriptor.toString()})`;
  }

  toPrivateString(): string {
    return `sh(${this.subdescriptor.toPrivateString()})`;
  }
}

/**
 * wsh(SCRIPT) - Pay to witness script hash
 */
export class WSHDescriptor implements Descriptor {
  private subdescriptor: Descriptor;

  constructor(subdescriptor: Descriptor) {
    this.subdescriptor = subdescriptor;
  }

  getType(): DescriptorType {
    return DescriptorType.WSH;
  }

  isRange(): boolean {
    return this.subdescriptor.isRange();
  }

  isSingleType(): boolean {
    return this.subdescriptor.isSingleType();
  }

  getOutputType(): OutputType {
    return OutputType.BECH32;
  }

  expand(index: number, network: NetworkType): ExpandedOutput[] {
    const subOutputs = this.subdescriptor.expand(index, network);
    const results: ExpandedOutput[] = [];

    for (const subOutput of subOutputs) {
      const witnessScript = subOutput.scriptPubKey;
      const scriptHash = sha256Hash(witnessScript);
      const script = buildP2WSHScript(scriptHash);
      const hrp = getHrp(network);
      const address = bech32Encode(hrp, 0, scriptHash);

      results.push({
        scriptPubKey: script,
        address,
        outputType: OutputType.BECH32,
        witnessScript,
        pubkeys: subOutput.pubkeys,
        origins: subOutput.origins,
      });
    }

    return results;
  }

  toString(): string {
    return `wsh(${this.subdescriptor.toString()})`;
  }

  toPrivateString(): string {
    return `wsh(${this.subdescriptor.toPrivateString()})`;
  }
}

/**
 * tr(KEY) or tr(KEY,TREE) - Pay to taproot
 */
export class TRDescriptor implements Descriptor {
  private internalKey: PubkeyProvider;
  private scriptTree?: TaprootTree;

  constructor(internalKey: PubkeyProvider, scriptTree?: TaprootTree) {
    this.internalKey = internalKey;
    this.scriptTree = scriptTree;
  }

  getType(): DescriptorType {
    return DescriptorType.TR;
  }

  isRange(): boolean {
    if (this.internalKey.isRange()) return true;
    if (this.scriptTree) {
      return treeIsRange(this.scriptTree);
    }
    return false;
  }

  isSingleType(): boolean {
    return true;
  }

  getOutputType(): OutputType {
    return OutputType.BECH32M;
  }

  expand(index: number, network: NetworkType): ExpandedOutput[] {
    const pubkey = this.internalKey.getPubKey(index);
    // Get x-only pubkey (32 bytes)
    const xOnlyPubkey = pubkey.length === 33 ? pubkey.subarray(1, 33) : pubkey;

    let tweak: Buffer;
    if (this.scriptTree) {
      // Build Merkle root from script tree and tweak
      const merkleRoot = buildTaprootMerkleRoot(this.scriptTree, index);
      tweak = taggedHash(
        TAPTWEAK_TAG,
        Buffer.concat([xOnlyPubkey, merkleRoot])
      );
    } else {
      // Key-path only: tweak with just the pubkey
      tweak = taggedHash(TAPTWEAK_TAG, xOnlyPubkey);
    }

    const tweakedPubkey = tweakPublicKey(xOnlyPubkey, tweak);
    const script = buildP2TRScript(tweakedPubkey);
    const hrp = getHrp(network);
    const address = bech32Encode(hrp, 1, tweakedPubkey);

    const origins = new Map<string, KeyOriginInfo>();
    const origin = this.internalKey.getOrigin();
    if (origin) {
      origins.set(pubkey.toString("hex"), origin);
    }

    return [
      {
        scriptPubKey: script,
        address,
        outputType: OutputType.BECH32M,
        pubkeys: [pubkey],
        origins,
      },
    ];
  }

  toString(): string {
    if (this.scriptTree) {
      return `tr(${this.internalKey.toString()},${treeToString(this.scriptTree)})`;
    }
    return `tr(${this.internalKey.toString()})`;
  }

  toPrivateString(): string {
    if (this.scriptTree) {
      return `tr(${this.internalKey.toPrivateString()},${treeToPrivateString(this.scriptTree)})`;
    }
    return `tr(${this.internalKey.toPrivateString()})`;
  }
}

/**
 * multi(K,KEY,...) - K-of-N multisig
 */
export class MultiDescriptor implements Descriptor {
  private threshold: number;
  private pubkeyProviders: PubkeyProvider[];
  private sorted: boolean;

  constructor(
    threshold: number,
    pubkeyProviders: PubkeyProvider[],
    sorted: boolean = false
  ) {
    this.threshold = threshold;
    this.pubkeyProviders = pubkeyProviders;
    this.sorted = sorted;
  }

  getType(): DescriptorType {
    return this.sorted ? DescriptorType.SORTEDMULTI : DescriptorType.MULTI;
  }

  isRange(): boolean {
    return this.pubkeyProviders.some((p) => p.isRange());
  }

  isSingleType(): boolean {
    return true;
  }

  getOutputType(): OutputType {
    return OutputType.LEGACY;
  }

  expand(index: number, _network: NetworkType): ExpandedOutput[] {
    let pubkeys = this.pubkeyProviders.map((p) => p.getPubKey(index));

    if (this.sorted) {
      pubkeys = [...pubkeys].sort((a, b) => a.compare(b));
    }

    const script = buildMultisigScript(this.threshold, pubkeys);
    const origins = new Map<string, KeyOriginInfo>();
    for (let i = 0; i < this.pubkeyProviders.length; i++) {
      const origin = this.pubkeyProviders[i].getOrigin();
      if (origin) {
        origins.set(pubkeys[i].toString("hex"), origin);
      }
    }

    return [
      {
        scriptPubKey: script,
        outputType: OutputType.LEGACY,
        pubkeys,
        origins,
      },
    ];
  }

  toString(): string {
    const name = this.sorted ? "sortedmulti" : "multi";
    const keys = this.pubkeyProviders.map((p) => p.toString()).join(",");
    return `${name}(${this.threshold},${keys})`;
  }

  toPrivateString(): string {
    const name = this.sorted ? "sortedmulti" : "multi";
    const keys = this.pubkeyProviders.map((p) => p.toPrivateString()).join(",");
    return `${name}(${this.threshold},${keys})`;
  }
}

/**
 * addr(ADDR) - Raw address
 */
export class AddrDescriptor implements Descriptor {
  private address: string;
  private addressType: AddressType;
  private hash: Buffer;
  private network: NetworkType;

  constructor(address: string) {
    this.address = address;
    const decoded = decodeAddress(address);
    this.addressType = decoded.type;
    this.hash = decoded.hash;
    this.network = decoded.network;
  }

  getType(): DescriptorType {
    return DescriptorType.ADDR;
  }

  isRange(): boolean {
    return false;
  }

  isSingleType(): boolean {
    return true;
  }

  getOutputType(): OutputType {
    switch (this.addressType) {
      case AddressType.P2PKH:
      case AddressType.P2SH:
        return OutputType.LEGACY;
      case AddressType.P2WPKH:
      case AddressType.P2WSH:
        return OutputType.BECH32;
      case AddressType.P2TR:
        return OutputType.BECH32M;
    }
  }

  expand(_index: number, _network: NetworkType): ExpandedOutput[] {
    let scriptPubKey: Buffer;

    switch (this.addressType) {
      case AddressType.P2PKH:
        scriptPubKey = buildP2PKHScript(this.hash);
        break;
      case AddressType.P2SH:
        scriptPubKey = buildP2SHScript(this.hash);
        break;
      case AddressType.P2WPKH:
        scriptPubKey = buildP2WPKHScript(this.hash);
        break;
      case AddressType.P2WSH:
        scriptPubKey = buildP2WSHScript(this.hash);
        break;
      case AddressType.P2TR:
        scriptPubKey = buildP2TRScript(this.hash);
        break;
    }

    return [
      {
        scriptPubKey,
        address: this.address,
        outputType: this.getOutputType(),
        pubkeys: [],
        origins: new Map(),
      },
    ];
  }

  toString(): string {
    return `addr(${this.address})`;
  }

  toPrivateString(): string {
    return this.toString();
  }
}

/**
 * raw(HEX) - Raw script
 */
export class RawDescriptor implements Descriptor {
  private script: Buffer;

  constructor(script: Buffer) {
    this.script = script;
  }

  getType(): DescriptorType {
    return DescriptorType.RAW;
  }

  isRange(): boolean {
    return false;
  }

  isSingleType(): boolean {
    return true;
  }

  getOutputType(): OutputType | undefined {
    return undefined;
  }

  expand(_index: number, _network: NetworkType): ExpandedOutput[] {
    return [
      {
        scriptPubKey: this.script,
        outputType: OutputType.LEGACY,
        pubkeys: [],
        origins: new Map(),
      },
    ];
  }

  toString(): string {
    return `raw(${this.script.toString("hex")})`;
  }

  toPrivateString(): string {
    return this.toString();
  }
}

/**
 * combo(KEY) - P2PK + P2PKH + P2WPKH + P2SH-P2WPKH (if compressed)
 */
export class ComboDescriptor implements Descriptor {
  private pubkeyProvider: PubkeyProvider;

  constructor(pubkeyProvider: PubkeyProvider) {
    this.pubkeyProvider = pubkeyProvider;
  }

  getType(): DescriptorType {
    return DescriptorType.COMBO;
  }

  isRange(): boolean {
    return this.pubkeyProvider.isRange();
  }

  isSingleType(): boolean {
    return false; // combo expands to multiple types
  }

  getOutputType(): OutputType | undefined {
    return undefined; // multiple types
  }

  expand(index: number, network: NetworkType): ExpandedOutput[] {
    const pubkey = this.pubkeyProvider.getPubKey(index);
    const results: ExpandedOutput[] = [];
    const origin = this.pubkeyProvider.getOrigin();

    const makeOrigins = () => {
      const origins = new Map<string, KeyOriginInfo>();
      if (origin) {
        origins.set(pubkey.toString("hex"), origin);
      }
      return origins;
    };

    // P2PK
    results.push({
      scriptPubKey: buildP2PKScript(pubkey),
      outputType: OutputType.LEGACY,
      pubkeys: [pubkey],
      origins: makeOrigins(),
    });

    // P2PKH
    const pubkeyHash = hash160(pubkey);
    results.push({
      scriptPubKey: buildP2PKHScript(pubkeyHash),
      address: encodeAddress({
        type: AddressType.P2PKH,
        hash: pubkeyHash,
        network,
      }),
      outputType: OutputType.LEGACY,
      pubkeys: [pubkey],
      origins: makeOrigins(),
    });

    // If compressed, also add segwit outputs
    if (pubkey.length === 33) {
      // P2WPKH
      const wpkhScript = buildP2WPKHScript(pubkeyHash);
      const hrp = getHrp(network);
      results.push({
        scriptPubKey: wpkhScript,
        address: bech32Encode(hrp, 0, pubkeyHash),
        outputType: OutputType.BECH32,
        pubkeys: [pubkey],
        origins: makeOrigins(),
      });

      // P2SH-P2WPKH
      const redeemScript = wpkhScript;
      const scriptHash = hash160(redeemScript);
      results.push({
        scriptPubKey: buildP2SHScript(scriptHash),
        address: encodeAddress({
          type: AddressType.P2SH,
          hash: scriptHash,
          network,
        }),
        outputType: OutputType.P2SH_SEGWIT,
        redeemScript,
        pubkeys: [pubkey],
        origins: makeOrigins(),
      });
    }

    return results;
  }

  toString(): string {
    return `combo(${this.pubkeyProvider.toString()})`;
  }

  toPrivateString(): string {
    return `combo(${this.pubkeyProvider.toPrivateString()})`;
  }
}

// =============================================================================
// Taproot Tree
// =============================================================================

/**
 * Taproot script tree node.
 */
export type TaprootTree =
  | { type: "leaf"; script: Descriptor; leafVersion?: number }
  | { type: "branch"; left: TaprootTree; right: TaprootTree };

function treeIsRange(tree: TaprootTree): boolean {
  if (tree.type === "leaf") {
    return tree.script.isRange();
  }
  return treeIsRange(tree.left) || treeIsRange(tree.right);
}

function treeToString(tree: TaprootTree): string {
  if (tree.type === "leaf") {
    return tree.script.toString();
  }
  return `{${treeToString(tree.left)},${treeToString(tree.right)}}`;
}

function treeToPrivateString(tree: TaprootTree): string {
  if (tree.type === "leaf") {
    return tree.script.toPrivateString();
  }
  return `{${treeToPrivateString(tree.left)},${treeToPrivateString(tree.right)}}`;
}

function buildTaprootMerkleRoot(tree: TaprootTree, index: number): Buffer {
  if (tree.type === "leaf") {
    const outputs = tree.script.expand(index, "mainnet");
    const script = outputs[0].scriptPubKey;
    const leafVersion = tree.leafVersion ?? 0xc0;
    // TapLeaf = TaggedHash("TapLeaf", leafVersion || script_length || script)
    const leafData = Buffer.concat([
      Buffer.from([leafVersion]),
      encodeVarInt(script.length),
      script,
    ]);
    return taggedHash("TapLeaf", leafData);
  }

  const leftHash = buildTaprootMerkleRoot(tree.left, index);
  const rightHash = buildTaprootMerkleRoot(tree.right, index);

  // Sort lexicographically
  const [first, second] =
    leftHash.compare(rightHash) < 0
      ? [leftHash, rightHash]
      : [rightHash, leftHash];

  return taggedHash("TapBranch", Buffer.concat([first, second]));
}

// =============================================================================
// Script Building Helpers
// =============================================================================

function buildP2PKScript(pubkey: Buffer): Buffer {
  // <pubkey> OP_CHECKSIG
  const len = pubkey.length;
  return Buffer.concat([Buffer.from([len]), pubkey, Buffer.from([Opcode.OP_CHECKSIG])]);
}

function buildP2PKHScript(pubkeyHash: Buffer): Buffer {
  // OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
  return Buffer.concat([
    Buffer.from([
      Opcode.OP_DUP,
      Opcode.OP_HASH160,
      0x14, // Push 20 bytes
    ]),
    pubkeyHash,
    Buffer.from([Opcode.OP_EQUALVERIFY, Opcode.OP_CHECKSIG]),
  ]);
}

function buildP2WPKHScript(pubkeyHash: Buffer): Buffer {
  // OP_0 <20 bytes>
  return Buffer.concat([Buffer.from([Opcode.OP_0, 0x14]), pubkeyHash]);
}

function buildP2SHScript(scriptHash: Buffer): Buffer {
  // OP_HASH160 <20 bytes> OP_EQUAL
  return Buffer.concat([
    Buffer.from([Opcode.OP_HASH160, 0x14]),
    scriptHash,
    Buffer.from([Opcode.OP_EQUAL]),
  ]);
}

function buildP2WSHScript(scriptHash: Buffer): Buffer {
  // OP_0 <32 bytes>
  return Buffer.concat([Buffer.from([Opcode.OP_0, 0x20]), scriptHash]);
}

function buildP2TRScript(xOnlyPubkey: Buffer): Buffer {
  // OP_1 <32 bytes>
  return Buffer.concat([Buffer.from([Opcode.OP_1, 0x20]), xOnlyPubkey]);
}

function buildMultisigScript(threshold: number, pubkeys: Buffer[]): Buffer {
  const n = pubkeys.length;
  if (threshold < 1 || threshold > n) {
    throw new Error(`Invalid threshold ${threshold} for ${n} keys`);
  }
  if (n > 20) {
    throw new Error(`Too many keys for multisig: ${n} > 20`);
  }

  // OP_M <pubkey1> ... <pubkeyN> OP_N OP_CHECKMULTISIG
  const parts: Buffer[] = [
    Buffer.from([Opcode.OP_1 - 1 + threshold]), // OP_M
  ];
  for (const pubkey of pubkeys) {
    parts.push(Buffer.from([pubkey.length]));
    parts.push(pubkey);
  }
  parts.push(Buffer.from([Opcode.OP_1 - 1 + n])); // OP_N
  parts.push(Buffer.from([Opcode.OP_CHECKMULTISIG]));

  return Buffer.concat(parts);
}

function encodeVarInt(n: number): Buffer {
  if (n < 0xfd) {
    return Buffer.from([n]);
  } else if (n <= 0xffff) {
    const buf = Buffer.alloc(3);
    buf[0] = 0xfd;
    buf.writeUInt16LE(n, 1);
    return buf;
  } else if (n <= 0xffffffff) {
    const buf = Buffer.alloc(5);
    buf[0] = 0xfe;
    buf.writeUInt32LE(n, 1);
    return buf;
  } else {
    const buf = Buffer.alloc(9);
    buf[0] = 0xff;
    buf.writeBigUInt64LE(BigInt(n), 1);
    return buf;
  }
}

// =============================================================================
// Taproot Key Tweaking
// =============================================================================

function tweakPublicKey(xOnlyPubkey: Buffer, tweak: Buffer): Buffer {
  // Use lift_x to convert x-only pubkey to point
  const xBigInt = BigInt("0x" + xOnlyPubkey.toString("hex"));
  const point = schnorr.utils.lift_x(xBigInt);

  // Get the tweak as a scalar
  const tweakScalar = BigInt("0x" + tweak.toString("hex"));

  // Check if tweak is valid (must be < curve order)
  if (tweakScalar >= CURVE_ORDER) {
    throw new Error("Invalid tweak - exceeds curve order");
  }

  // Compute tweaked point: P' = P + t*G
  const tweakPoint = schnorr.Point.BASE.multiply(tweakScalar);
  const tweakedPoint = point.add(tweakPoint);

  // Get the x-only coordinate (32 bytes)
  const tweakedBytes = schnorr.utils.pointToBytes(tweakedPoint);
  return Buffer.from(tweakedBytes);
}

// =============================================================================
// Extended Key Encoding/Decoding
// =============================================================================

// Version bytes for extended keys
const XPUB_VERSION = 0x0488b21e; // mainnet
const XPRV_VERSION = 0x0488ade4;
const TPUB_VERSION = 0x043587cf; // testnet
const TPRV_VERSION = 0x04358394;

/**
 * Decode a base58-encoded string to raw bytes (with checksum verification).
 */
function base58DecodeRaw(str: string): Buffer {
  // Count leading '1's (they represent leading zero bytes)
  let leadingOnes = 0;
  for (const char of str) {
    if (char === "1") {
      leadingOnes++;
    } else {
      break;
    }
  }

  // Convert Base58 string to bytes
  const bytes: number[] = [];

  for (const char of str) {
    const value = BASE58_ALPHABET.indexOf(char);
    if (value === -1) {
      throw new Error(`Invalid Base58 character: ${char}`);
    }

    let carry = value;
    for (let i = 0; i < bytes.length; i++) {
      carry += bytes[i] * 58;
      bytes[i] = carry % 256;
      carry = Math.floor(carry / 256);
    }
    while (carry > 0) {
      bytes.push(carry % 256);
      carry = Math.floor(carry / 256);
    }
  }

  // Add leading zeros and reverse
  const result = Buffer.alloc(leadingOnes + bytes.length);
  for (let i = 0; i < bytes.length; i++) {
    result[leadingOnes + bytes.length - 1 - i] = bytes[i];
  }

  return result;
}

/**
 * Decode a base58check-encoded extended key (xpub/xprv/tpub/tprv).
 */
export function decodeExtendedKey(str: string): ExtendedKey {
  // Base58 decode the full string
  const data = base58DecodeRaw(str);

  // Extended key is 78 bytes + 4 bytes checksum = 82 bytes
  if (data.length !== 82) {
    throw new Error(`Invalid extended key length: ${data.length}`);
  }

  // Verify checksum
  const payload = data.subarray(0, 78);
  const checksum = data.subarray(78, 82);
  const expectedChecksum = hash256(payload).subarray(0, 4);
  if (!checksum.equals(expectedChecksum)) {
    throw new Error("Invalid extended key checksum");
  }

  const version = payload.readUInt32BE(0);
  const depth = payload[4];
  const parentFingerprint = payload.subarray(5, 9);
  const childIndex = payload.readUInt32BE(9);
  const chainCode = payload.subarray(13, 45);
  const keyData = payload.subarray(45, 78);

  const isPrivate = keyData[0] === 0x00;
  const key = isPrivate ? keyData.subarray(1) : keyData;

  return {
    version,
    depth,
    parentFingerprint: Buffer.from(parentFingerprint),
    childIndex,
    chainCode: Buffer.from(chainCode),
    key: Buffer.from(key),
    isPrivate,
  };
}

/**
 * Encode raw bytes to base58 string.
 */
function base58EncodeRaw(data: Buffer): string {
  // Count leading zeros
  let leadingZeros = 0;
  for (const byte of data) {
    if (byte === 0) {
      leadingZeros++;
    } else {
      break;
    }
  }

  // Convert bytes to a big integer using repeated base conversion
  const digits: number[] = [];

  for (const byte of data) {
    let carry = byte;
    for (let i = 0; i < digits.length; i++) {
      carry += digits[i] * 256;
      digits[i] = carry % 58;
      carry = Math.floor(carry / 58);
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = Math.floor(carry / 58);
    }
  }

  // Build the result string (digits are in reverse order)
  let result = "1".repeat(leadingZeros);
  for (let i = digits.length - 1; i >= 0; i--) {
    result += BASE58_ALPHABET[digits[i]];
  }

  return result;
}

/**
 * Encode an extended key to base58check string.
 */
export function encodeExtendedKey(extkey: ExtendedKey): string {
  const data = Buffer.alloc(78);
  data.writeUInt32BE(extkey.version, 0);
  data[4] = extkey.depth;
  extkey.parentFingerprint.copy(data, 5);
  data.writeUInt32BE(extkey.childIndex, 9);
  extkey.chainCode.copy(data, 13);

  if (extkey.isPrivate) {
    data[45] = 0x00;
    extkey.key.copy(data, 46);
  } else {
    extkey.key.copy(data, 45);
  }

  // Add checksum
  const checksum = hash256(data).subarray(0, 4);
  const fullData = Buffer.concat([data, checksum]);

  return base58EncodeRaw(fullData);
}

// =============================================================================
// Path Formatting
// =============================================================================

function formatPath(path: number[], useApostrophe: boolean = true): string {
  return path
    .map((idx) => {
      if (idx >= HARDENED_OFFSET) {
        return `${idx - HARDENED_OFFSET}${useApostrophe ? "'" : "h"}`;
      }
      return `${idx}`;
    })
    .join("/");
}

function getHrp(network: NetworkType): string {
  switch (network) {
    case "mainnet":
      return "bc";
    case "testnet":
      return "tb";
    case "regtest":
      return "bcrt";
  }
}

// =============================================================================
// Descriptor Parsing
// =============================================================================

/**
 * Parse context for descriptor parsing.
 */
enum ParseContext {
  TOP = "top",
  P2SH = "p2sh",
  P2WSH = "p2wsh",
  P2TR = "p2tr",
}

/**
 * Result of parsing a descriptor.
 */
export interface ParsedDescriptor {
  descriptor: Descriptor;
  checksum?: string;
}

/**
 * Parse a descriptor string.
 */
export function parseDescriptor(
  desc: string,
  network: NetworkType = "mainnet"
): ParsedDescriptor {
  // Validate and strip checksum
  let checksum: string | undefined;
  const hashIdx = desc.indexOf("#");
  if (hashIdx !== -1) {
    checksum = desc.slice(hashIdx + 1);
    desc = validateChecksum(desc);
  }

  // Parse the descriptor
  const result = parseDescriptorInner(desc, 0, ParseContext.TOP, network);
  if (result.pos !== desc.length) {
    throw new Error(
      `Unexpected characters at position ${result.pos}: ${desc.slice(result.pos)}`
    );
  }

  return {
    descriptor: result.descriptor,
    checksum,
  };
}

interface ParseResult {
  descriptor: Descriptor;
  pos: number;
}

function parseDescriptorInner(
  desc: string,
  pos: number,
  context: ParseContext,
  network: NetworkType
): ParseResult {
  // Try each descriptor type
  const types = [
    "pk(",
    "pkh(",
    "wpkh(",
    "sh(",
    "wsh(",
    "tr(",
    "multi(",
    "sortedmulti(",
    "addr(",
    "raw(",
    "combo(",
  ];

  for (const type of types) {
    if (desc.slice(pos).startsWith(type)) {
      const funcName = type.slice(0, -1);
      return parseFunction(
        desc,
        pos + type.length,
        funcName,
        context,
        network
      );
    }
  }

  throw new Error(`Unknown descriptor at position ${pos}: ${desc.slice(pos)}`);
}

function parseFunction(
  desc: string,
  pos: number,
  funcName: string,
  context: ParseContext,
  network: NetworkType
): ParseResult {
  switch (funcName) {
    case "pk":
      return parsePK(desc, pos, context, network);
    case "pkh":
      return parsePKH(desc, pos, context, network);
    case "wpkh":
      return parseWPKH(desc, pos, context, network);
    case "sh":
      return parseSH(desc, pos, context, network);
    case "wsh":
      return parseWSH(desc, pos, context, network);
    case "tr":
      return parseTR(desc, pos, context, network);
    case "multi":
      return parseMulti(desc, pos, false, context, network);
    case "sortedmulti":
      return parseMulti(desc, pos, true, context, network);
    case "addr":
      return parseAddr(desc, pos, context, network);
    case "raw":
      return parseRaw(desc, pos, context, network);
    case "combo":
      return parseCombo(desc, pos, context, network);
    default:
      throw new Error(`Unknown function: ${funcName}`);
  }
}

function parsePK(
  desc: string,
  pos: number,
  _context: ParseContext,
  network: NetworkType
): ParseResult {
  const keyResult = parseKey(desc, pos, network);
  pos = keyResult.pos;

  if (desc[pos] !== ")") {
    throw new Error(`Expected ')' at position ${pos}`);
  }

  return {
    descriptor: new PKDescriptor(keyResult.provider),
    pos: pos + 1,
  };
}

function parsePKH(
  desc: string,
  pos: number,
  context: ParseContext,
  network: NetworkType
): ParseResult {
  if (context === ParseContext.P2TR) {
    throw new Error("pkh() cannot be used inside tr()");
  }

  const keyResult = parseKey(desc, pos, network);
  pos = keyResult.pos;

  if (desc[pos] !== ")") {
    throw new Error(`Expected ')' at position ${pos}`);
  }

  return {
    descriptor: new PKHDescriptor(keyResult.provider),
    pos: pos + 1,
  };
}

function parseWPKH(
  desc: string,
  pos: number,
  context: ParseContext,
  network: NetworkType
): ParseResult {
  if (context === ParseContext.P2WSH) {
    throw new Error("wpkh() cannot be used inside wsh()");
  }
  if (context === ParseContext.P2TR) {
    throw new Error("wpkh() cannot be used inside tr()");
  }

  const keyResult = parseKey(desc, pos, network);
  pos = keyResult.pos;

  if (desc[pos] !== ")") {
    throw new Error(`Expected ')' at position ${pos}`);
  }

  return {
    descriptor: new WPKHDescriptor(keyResult.provider),
    pos: pos + 1,
  };
}

function parseSH(
  desc: string,
  pos: number,
  context: ParseContext,
  network: NetworkType
): ParseResult {
  if (context !== ParseContext.TOP) {
    throw new Error("sh() can only be used at top level");
  }

  const inner = parseDescriptorInner(desc, pos, ParseContext.P2SH, network);
  pos = inner.pos;

  if (desc[pos] !== ")") {
    throw new Error(`Expected ')' at position ${pos}`);
  }

  return {
    descriptor: new SHDescriptor(inner.descriptor),
    pos: pos + 1,
  };
}

function parseWSH(
  desc: string,
  pos: number,
  context: ParseContext,
  network: NetworkType
): ParseResult {
  if (context === ParseContext.P2WSH) {
    throw new Error("wsh() cannot be nested");
  }
  if (context === ParseContext.P2TR) {
    throw new Error("wsh() cannot be used inside tr()");
  }

  const inner = parseDescriptorInner(desc, pos, ParseContext.P2WSH, network);
  pos = inner.pos;

  if (desc[pos] !== ")") {
    throw new Error(`Expected ')' at position ${pos}`);
  }

  return {
    descriptor: new WSHDescriptor(inner.descriptor),
    pos: pos + 1,
  };
}

function parseTR(
  desc: string,
  pos: number,
  context: ParseContext,
  network: NetworkType
): ParseResult {
  if (context !== ParseContext.TOP) {
    throw new Error("tr() can only be used at top level");
  }

  const keyResult = parseKey(desc, pos, network);
  pos = keyResult.pos;

  let scriptTree: TaprootTree | undefined;

  if (desc[pos] === ",") {
    pos++; // skip comma
    const treeResult = parseTaprootTree(desc, pos, network);
    scriptTree = treeResult.tree;
    pos = treeResult.pos;
  }

  if (desc[pos] !== ")") {
    throw new Error(`Expected ')' at position ${pos}`);
  }

  return {
    descriptor: new TRDescriptor(keyResult.provider, scriptTree),
    pos: pos + 1,
  };
}

function parseTaprootTree(
  desc: string,
  pos: number,
  network: NetworkType
): { tree: TaprootTree; pos: number } {
  if (desc[pos] === "{") {
    // Branch: {left,right}
    pos++; // skip '{'

    const leftResult = parseTaprootTree(desc, pos, network);
    pos = leftResult.pos;

    if (desc[pos] !== ",") {
      throw new Error(`Expected ',' at position ${pos}`);
    }
    pos++; // skip ','

    const rightResult = parseTaprootTree(desc, pos, network);
    pos = rightResult.pos;

    if (desc[pos] !== "}") {
      throw new Error(`Expected '}' at position ${pos}`);
    }
    pos++; // skip '}'

    return {
      tree: { type: "branch", left: leftResult.tree, right: rightResult.tree },
      pos,
    };
  } else {
    // Leaf: a script descriptor
    const inner = parseDescriptorInner(desc, pos, ParseContext.P2TR, network);
    return {
      tree: { type: "leaf", script: inner.descriptor },
      pos: inner.pos,
    };
  }
}

function parseMulti(
  desc: string,
  pos: number,
  sorted: boolean,
  context: ParseContext,
  network: NetworkType
): ParseResult {
  if (context === ParseContext.P2TR) {
    throw new Error("multi() cannot be used inside tr()");
  }

  // Parse threshold
  const thresholdMatch = desc.slice(pos).match(/^(\d+),/);
  if (!thresholdMatch) {
    throw new Error(`Expected threshold at position ${pos}`);
  }
  const threshold = parseInt(thresholdMatch[1], 10);
  pos += thresholdMatch[0].length;

  // Parse keys
  const providers: PubkeyProvider[] = [];
  while (true) {
    const keyResult = parseKey(desc, pos, network);
    providers.push(keyResult.provider);
    pos = keyResult.pos;

    if (desc[pos] === ",") {
      pos++; // skip comma
    } else if (desc[pos] === ")") {
      break;
    } else {
      throw new Error(`Expected ',' or ')' at position ${pos}`);
    }
  }

  if (desc[pos] !== ")") {
    throw new Error(`Expected ')' at position ${pos}`);
  }

  if (threshold > providers.length) {
    throw new Error(
      `Threshold ${threshold} exceeds number of keys ${providers.length}`
    );
  }

  return {
    descriptor: new MultiDescriptor(threshold, providers, sorted),
    pos: pos + 1,
  };
}

function parseAddr(
  desc: string,
  pos: number,
  context: ParseContext,
  _network: NetworkType
): ParseResult {
  if (context !== ParseContext.TOP) {
    throw new Error("addr() can only be used at top level");
  }

  // Find the closing paren
  const closePos = desc.indexOf(")", pos);
  if (closePos === -1) {
    throw new Error(`Expected ')' for addr()`);
  }

  const address = desc.slice(pos, closePos);

  return {
    descriptor: new AddrDescriptor(address),
    pos: closePos + 1,
  };
}

function parseRaw(
  desc: string,
  pos: number,
  context: ParseContext,
  _network: NetworkType
): ParseResult {
  if (context !== ParseContext.TOP) {
    throw new Error("raw() can only be used at top level");
  }

  // Find the closing paren
  const closePos = desc.indexOf(")", pos);
  if (closePos === -1) {
    throw new Error(`Expected ')' for raw()`);
  }

  const hex = desc.slice(pos, closePos);
  if (!/^[0-9a-fA-F]*$/.test(hex)) {
    throw new Error("Invalid hex in raw()");
  }

  return {
    descriptor: new RawDescriptor(Buffer.from(hex, "hex")),
    pos: closePos + 1,
  };
}

function parseCombo(
  desc: string,
  pos: number,
  context: ParseContext,
  network: NetworkType
): ParseResult {
  if (context !== ParseContext.TOP) {
    throw new Error("combo() can only be used at top level");
  }

  const keyResult = parseKey(desc, pos, network);
  pos = keyResult.pos;

  if (desc[pos] !== ")") {
    throw new Error(`Expected ')' at position ${pos}`);
  }

  return {
    descriptor: new ComboDescriptor(keyResult.provider),
    pos: pos + 1,
  };
}

interface KeyParseResult {
  provider: PubkeyProvider;
  pos: number;
}

function parseKey(
  desc: string,
  pos: number,
  network: NetworkType
): KeyParseResult {
  let origin: KeyOriginInfo | undefined;

  // Check for origin info [fingerprint/path]
  if (desc[pos] === "[") {
    pos++; // skip '['
    const closeBracket = desc.indexOf("]", pos);
    if (closeBracket === -1) {
      throw new Error("Unclosed origin bracket");
    }

    const originStr = desc.slice(pos, closeBracket);
    origin = parseOrigin(originStr);
    pos = closeBracket + 1;
  }

  // Determine key type
  const remaining = desc.slice(pos);

  // Check for xpub/xprv/tpub/tprv
  if (
    remaining.startsWith("xpub") ||
    remaining.startsWith("xprv") ||
    remaining.startsWith("tpub") ||
    remaining.startsWith("tprv")
  ) {
    return parseExtendedKey(desc, pos, origin, network);
  }

  // Check for hex pubkey
  if (/^[0-9a-fA-F]/.test(remaining)) {
    return parseHexKey(desc, pos, origin);
  }

  // Check for WIF private key (starts with 5, K, L, c, or 9)
  if (/^[5KLc9]/.test(remaining)) {
    return parseWIFKey(desc, pos, origin, network);
  }

  throw new Error(`Unknown key format at position ${pos}`);
}

function parseOrigin(originStr: string): KeyOriginInfo {
  const parts = originStr.split("/");
  if (parts.length < 1) {
    throw new Error("Invalid origin format");
  }

  const fingerprint = Buffer.from(parts[0], "hex");
  if (fingerprint.length !== 4) {
    throw new Error("Fingerprint must be 4 bytes");
  }

  const path: number[] = [];
  for (let i = 1; i < parts.length; i++) {
    const part = parts[i];
    const isHardened = part.endsWith("'") || part.endsWith("h");
    const indexStr = isHardened ? part.slice(0, -1) : part;
    let index = parseInt(indexStr, 10);
    if (isNaN(index)) {
      throw new Error(`Invalid path component: ${part}`);
    }
    if (isHardened) {
      index += HARDENED_OFFSET;
    }
    path.push(index);
  }

  return { fingerprint, path };
}

function parseExtendedKey(
  desc: string,
  pos: number,
  origin: KeyOriginInfo | undefined,
  _network: NetworkType
): KeyParseResult {
  // Find the end of the extended key (look for special characters)
  let endPos = pos;
  while (
    endPos < desc.length &&
    (BASE58_ALPHABET.includes(desc[endPos]) || /[0-9]/.test(desc[endPos]))
  ) {
    endPos++;
  }

  const extkeyStr = desc.slice(pos, endPos);
  pos = endPos;

  // Decode the extended key
  const extkey = decodeExtendedKey(extkeyStr);

  // Parse derivation path
  const path: number[] = [];
  let deriveType = DeriveType.NO_RANGE;
  let useApostrophe = true;

  while (desc[pos] === "/") {
    pos++; // skip '/'

    if (desc[pos] === "*") {
      pos++; // skip '*'
      if (desc[pos] === "'" || desc[pos] === "h") {
        deriveType = DeriveType.HARDENED;
        useApostrophe = desc[pos] === "'";
        pos++;
      } else {
        deriveType = DeriveType.UNHARDENED;
      }
      break; // * is always the last component
    }

    // Parse numeric index
    const indexMatch = desc.slice(pos).match(/^(\d+)(['h])?/);
    if (!indexMatch) {
      throw new Error(`Invalid path component at position ${pos}`);
    }

    let index = parseInt(indexMatch[1], 10);
    if (indexMatch[2]) {
      index += HARDENED_OFFSET;
      useApostrophe = indexMatch[2] === "'";
    }
    path.push(index);
    pos += indexMatch[0].length;
  }

  return {
    provider: new BIP32PubkeyProvider(
      extkey,
      path,
      deriveType,
      origin,
      useApostrophe
    ),
    pos,
  };
}

function parseHexKey(
  desc: string,
  pos: number,
  origin: KeyOriginInfo | undefined
): KeyParseResult {
  // Find the end of the hex string
  let endPos = pos;
  while (endPos < desc.length && /[0-9a-fA-F]/.test(desc[endPos])) {
    endPos++;
  }

  const hex = desc.slice(pos, endPos);
  const pubkey = Buffer.from(hex, "hex");

  // Validate pubkey length
  if (pubkey.length !== 33 && pubkey.length !== 65 && pubkey.length !== 32) {
    throw new Error(`Invalid pubkey length: ${pubkey.length}`);
  }

  const xonly = pubkey.length === 32;

  return {
    provider: new ConstPubkeyProvider(pubkey, undefined, xonly, origin),
    pos: endPos,
  };
}

function parseWIFKey(
  desc: string,
  pos: number,
  origin: KeyOriginInfo | undefined,
  network: NetworkType
): KeyParseResult {
  // Find the end of the WIF string
  let endPos = pos;
  while (endPos < desc.length && BASE58_ALPHABET.includes(desc[endPos])) {
    endPos++;
  }

  const wif = desc.slice(pos, endPos);
  const decoded = base58CheckDecode(wif);

  // Check version byte
  const isTestnet = network === "testnet" || network === "regtest";
  const expectedVersion = isTestnet ? 0xef : 0x80;
  if (decoded.version !== expectedVersion) {
    throw new Error(`Invalid WIF version byte: ${decoded.version}`);
  }

  let privkey: Buffer;
  let compressed: boolean;

  if (decoded.hash.length === 33 && decoded.hash[32] === 0x01) {
    // Compressed
    privkey = decoded.hash.subarray(0, 32);
    compressed = true;
  } else if (decoded.hash.length === 32) {
    // Uncompressed
    privkey = decoded.hash;
    compressed = false;
  } else {
    throw new Error("Invalid WIF private key length");
  }

  const pubkey = privateKeyToPublicKey(privkey, compressed);

  return {
    provider: new ConstPubkeyProvider(pubkey, privkey, false, origin),
    pos: endPos,
  };
}

// =============================================================================
// Descriptor Info & Derivation
// =============================================================================

/**
 * Descriptor info result (for getdescriptorinfo RPC).
 */
export interface DescriptorInfo {
  /** Canonical descriptor with checksum */
  descriptor: string;
  /** The 8-character checksum */
  checksum: string;
  /** Whether the descriptor is ranged */
  isRange: boolean;
  /** Whether the descriptor is solvable (has all key info) */
  isSolvable: boolean;
  /** Whether the descriptor has private keys */
  hasPrivateKeys: boolean;
}

/**
 * Get information about a descriptor.
 */
export function getDescriptorInfo(descStr: string): DescriptorInfo {
  const parsed = parseDescriptor(descStr);
  const descriptor = parsed.descriptor;
  const canonicalStr = descriptor.toString();
  const checksum = descriptorChecksum(canonicalStr);

  // Check if solvable and has private keys
  let isSolvable = true;
  let hasPrivateKeys = false;

  // addr() and raw() are not solvable
  if (
    descriptor.getType() === DescriptorType.ADDR ||
    descriptor.getType() === DescriptorType.RAW
  ) {
    isSolvable = false;
  }

  // TODO: Check for private keys in providers

  return {
    descriptor: `${canonicalStr}#${checksum}`,
    checksum,
    isRange: descriptor.isRange(),
    isSolvable,
    hasPrivateKeys,
  };
}

/**
 * Derive addresses from a descriptor.
 */
export function deriveAddresses(
  descStr: string,
  network: NetworkType = "mainnet",
  range?: [number, number]
): string[] {
  const parsed = parseDescriptor(descStr, network);
  const descriptor = parsed.descriptor;

  const addresses: string[] = [];

  if (descriptor.isRange()) {
    if (!range) {
      throw new Error("Range required for ranged descriptor");
    }
    const [start, end] = range;
    for (let i = start; i <= end; i++) {
      const outputs = descriptor.expand(i, network);
      for (const output of outputs) {
        if (output.address) {
          addresses.push(output.address);
        }
      }
    }
  } else {
    const outputs = descriptor.expand(0, network);
    for (const output of outputs) {
      if (output.address) {
        addresses.push(output.address);
      }
    }
  }

  return addresses;
}
