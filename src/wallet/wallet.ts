/**
 * HD Wallet: BIP-32/BIP-44/BIP-49/BIP-84/BIP-86 key derivation, address generation,
 * UTXO tracking, and transaction creation/signing.
 *
 * Supports all major address types:
 * - P2PKH (legacy) - BIP-44 derivation paths (m/44'/...)
 * - P2SH-P2WPKH (nested segwit) - BIP-49 derivation paths (m/49'/...)
 * - P2WPKH (native segwit) - BIP-84 derivation paths (m/84'/...)
 * - P2TR (taproot) - BIP-86 derivation paths (m/86'/...)
 *
 * Implements Branch-and-Bound (BnB) and Knapsack coin selection algorithms.
 */

import { hmac } from "@noble/hashes/hmac.js";
import { sha512, sha256 } from "@noble/hashes/sha2.js";
import { pbkdf2 } from "@noble/hashes/pbkdf2.js";
import { gcm } from "@noble/ciphers/aes.js";
import { randomBytes } from "@noble/ciphers/utils.js";
import * as crypto from "node:crypto";

import {
  hash160,
  privateKeyToPublicKey,
  ecdsaSign,
  taggedHash,
} from "../crypto/primitives.js";
import {
  AddressType,
  decodeAddress,
  pubkeyToP2WPKH,
  pubkeyToP2PKH,
  bech32Encode,
  encodeAddress,
  base58CheckEncode,
} from "../address/encoding.js";
import { BufferWriter } from "../wire/serialization.js";
import type { ChainDB, UTXOEntry } from "../storage/database.js";
import {
  type Transaction,
  type TxIn,
  type TxOut,
  type OutPoint,
  serializeTx,
  getTxId,
  sigHashWitnessV0,
  SIGHASH_ALL,
  isCoinbase,
} from "../validation/tx.js";
import type { Block } from "../validation/block.js";

// Import secp256k1 for Taproot key tweaking
import { secp256k1, schnorr } from "@noble/curves/secp256k1.js";

// BIP-32 constants
const HARDENED_OFFSET = 0x80000000;

// secp256k1 curve order (n)
const CURVE_ORDER = BigInt(
  "0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"
);

// BIP-86 Taproot internal key tweak (hash of "TapTweak" tag for key-path spending)
const TAPTWEAK_TAG = "TapTweak";

// Coin selection constants (from Bitcoin Core)
const TOTAL_TRIES = 100000; // Max iterations for BnB
const KNAPSACK_ITERATIONS = 1000; // Max iterations for Knapsack approximation
const CHANGE_LOWER = 50000n; // Lower bound for random change target
const CHANGE_UPPER = 1000000n; // Upper bound for random change target

// Input weight estimates (vbytes * 4 for weight)
const INPUT_WEIGHT = {
  P2PKH: 148 * 4, // ~148 vbytes for P2PKH input
  P2SH_P2WPKH: 91 * 4, // ~91 vbytes for nested segwit
  P2WPKH: 68 * 4, // ~68 vbytes for native segwit
  P2TR: 57.5 * 4, // ~57.5 vbytes for taproot (Schnorr sig)
};

// Output weight estimates
const OUTPUT_WEIGHT = {
  P2PKH: 34 * 4,
  P2SH: 32 * 4,
  P2WPKH: 31 * 4,
  P2WSH: 43 * 4,
  P2TR: 43 * 4,
};

export interface WalletConfig {
  datadir: string;
  network: "mainnet" | "testnet" | "regtest";
}

// Wallet address type for getnewaddress
export type WalletAddressType = "legacy" | "p2sh-segwit" | "bech32" | "bech32m";

export interface WalletKey {
  privateKey: Buffer;
  publicKey: Buffer;
  address: string;
  path: string; // e.g., "m/84'/0'/0'/0/0"
  addressType: AddressType;
}

export interface WalletUTXO {
  outpoint: OutPoint;
  amount: bigint;
  address: string;
  keyPath: string;
  confirmations: number;
  addressType: AddressType;
  isCoinbase: boolean;
}

// Consensus constant: coinbase outputs require 100 confirmations before spending
export const COINBASE_MATURITY = 100;

// Coin selection result
export interface CoinSelectionResult {
  inputs: WalletUTXO[];
  totalInput: bigint;
  fee: bigint;
  change: bigint;
  algorithm: "bnb" | "knapsack" | "largest_first";
}

/**
 * Encrypted wallet file format.
 */
interface EncryptedWalletFile {
  version: number;
  salt: string; // hex
  iv: string; // hex
  ciphertext: string; // hex
}

/**
 * Serializable wallet data for encryption.
 */
interface WalletData {
  seed: string; // hex
  // Per-address-type indices
  nextReceiveIndices: Record<string, number>;
  nextChangeIndices: Record<string, number>;
  // Legacy fields for backwards compatibility
  nextReceiveIndex?: number;
  nextChangeIndex?: number;
  utxos: SerializedUTXO[];
  // Address labels (address -> label)
  labels?: Record<string, string>;
  // Wallet encryption state (for encrypted wallets)
  encryption?: {
    isEncrypted: boolean;
    encryptedSeed: string | null;
    encryptionSalt: string | null;
    encryptionIV: string | null;
  };
}

interface SerializedUTXO {
  txid: string;
  vout: number;
  amount: string;
  address: string;
  keyPath: string;
  confirmations: number;
  addressType: string;
  isCoinbase: boolean;
}

/**
 * Wallet encryption state for AES-256-CBC encrypted wallets.
 */
export interface WalletEncryptionState {
  isEncrypted: boolean;
  isLocked: boolean;
  encryptedSeed: Buffer | null; // Encrypted seed (when locked)
  encryptionSalt: Buffer | null; // Scrypt salt
  encryptionIV: Buffer | null; // AES IV
  unlockTimeout: ReturnType<typeof setTimeout> | null;
}

/**
 * HD Wallet implementing BIP-32/BIP-44/BIP-49/BIP-84/BIP-86.
 */
export class Wallet {
  private seed: Buffer;
  private masterKey: { key: Buffer; chainCode: Buffer };
  private keys: Map<string, WalletKey>; // address -> key info
  private utxos: Map<string, WalletUTXO>; // outpoint string -> utxo
  private config: WalletConfig;

  // Per-address-type indices for receive and change
  private nextReceiveIndex: Map<AddressType, number>;
  private nextChangeIndex: Map<AddressType, number>;

  // Pre-generated address gap
  private readonly ADDRESS_GAP = 20;

  // Wallet encryption state
  private encryption: WalletEncryptionState;

  // Address labels (address -> label)
  private labels: Map<string, string>;

  constructor(config: WalletConfig) {
    this.config = config;
    this.keys = new Map();
    this.utxos = new Map();
    this.seed = Buffer.alloc(0);
    this.masterKey = { key: Buffer.alloc(0), chainCode: Buffer.alloc(0) };
    this.labels = new Map();

    // Initialize encryption state
    this.encryption = {
      isEncrypted: false,
      isLocked: false,
      encryptedSeed: null,
      encryptionSalt: null,
      encryptionIV: null,
      unlockTimeout: null,
    };

    // Initialize per-type indices
    this.nextReceiveIndex = new Map([
      [AddressType.P2PKH, 0],
      [AddressType.P2SH, 0], // P2SH-P2WPKH
      [AddressType.P2WPKH, 0],
      [AddressType.P2TR, 0],
    ]);
    this.nextChangeIndex = new Map([
      [AddressType.P2PKH, 0],
      [AddressType.P2SH, 0],
      [AddressType.P2WPKH, 0],
      [AddressType.P2TR, 0],
    ]);
  }

  /**
   * Create a new wallet from a BIP-39 mnemonic or random seed.
   * If no mnemonic is provided, generates a random 32-byte seed.
   */
  static create(config: WalletConfig, mnemonic?: string): Wallet {
    const wallet = new Wallet(config);

    if (mnemonic) {
      // BIP-39: Convert mnemonic to seed using PBKDF2
      // Password is "mnemonic" + optional passphrase (empty here)
      const mnemonicBuffer = Buffer.from(mnemonic.normalize("NFKD"), "utf-8");
      const salt = Buffer.from("mnemonic", "utf-8");
      wallet.seed = Buffer.from(
        pbkdf2(sha512, mnemonicBuffer, salt, { c: 2048, dkLen: 64 })
      );
    } else {
      // Generate random 64-byte seed
      wallet.seed = Buffer.from(randomBytes(64));
    }

    // Derive master key from seed using HMAC-SHA512
    wallet.masterKey = wallet.deriveMasterKey(wallet.seed);

    // Pre-generate addresses for all address types
    wallet.pregenerateAddresses();

    return wallet;
  }

  /**
   * Map wallet address type string to AddressType enum.
   */
  private static walletAddressTypeToEnum(type: WalletAddressType): AddressType {
    switch (type) {
      case "legacy":
        return AddressType.P2PKH;
      case "p2sh-segwit":
        return AddressType.P2SH;
      case "bech32":
        return AddressType.P2WPKH;
      case "bech32m":
        return AddressType.P2TR;
    }
  }

  /**
   * Load wallet from encrypted file.
   */
  static async load(config: WalletConfig, password: string): Promise<Wallet> {
    const walletPath = `${config.datadir}/wallet.dat`;
    const file = Bun.file(walletPath);

    if (!(await file.exists())) {
      throw new Error(`Wallet file not found: ${walletPath}`);
    }

    const content = await file.text();
    const encrypted: EncryptedWalletFile = JSON.parse(content);

    if (encrypted.version !== 1) {
      throw new Error(`Unsupported wallet version: ${encrypted.version}`);
    }

    // Derive encryption key from password using PBKDF2
    const salt = Buffer.from(encrypted.salt, "hex");
    const key = Buffer.from(
      pbkdf2(sha256, Buffer.from(password, "utf-8"), salt, {
        c: 100000,
        dkLen: 32,
      })
    );

    // Decrypt using AES-256-GCM
    const iv = Buffer.from(encrypted.iv, "hex");
    const ciphertext = Buffer.from(encrypted.ciphertext, "hex");

    const aes = gcm(key, iv);
    let plaintext: Uint8Array;
    try {
      plaintext = aes.decrypt(ciphertext);
    } catch {
      throw new Error("Failed to decrypt wallet - incorrect password?");
    }

    const data: WalletData = JSON.parse(Buffer.from(plaintext).toString("utf-8"));

    // Reconstruct wallet
    const wallet = new Wallet(config);
    wallet.seed = Buffer.from(data.seed, "hex");
    wallet.masterKey = wallet.deriveMasterKey(wallet.seed);

    // Restore indices - support both new per-type and legacy format
    if (data.nextReceiveIndices) {
      for (const [typeStr, index] of Object.entries(data.nextReceiveIndices)) {
        wallet.nextReceiveIndex.set(typeStr as AddressType, index);
      }
      for (const [typeStr, index] of Object.entries(data.nextChangeIndices)) {
        wallet.nextChangeIndex.set(typeStr as AddressType, index);
      }
    } else if (data.nextReceiveIndex !== undefined) {
      // Legacy format - only P2WPKH was supported
      wallet.nextReceiveIndex.set(AddressType.P2WPKH, data.nextReceiveIndex);
      wallet.nextChangeIndex.set(AddressType.P2WPKH, data.nextChangeIndex ?? 0);
    }

    // Restore UTXOs
    for (const utxo of data.utxos) {
      const utxoKey = `${utxo.txid}:${utxo.vout}`;
      wallet.utxos.set(utxoKey, {
        outpoint: {
          txid: Buffer.from(utxo.txid, "hex"),
          vout: utxo.vout,
        },
        amount: BigInt(utxo.amount),
        address: utxo.address,
        keyPath: utxo.keyPath,
        confirmations: utxo.confirmations,
        addressType: (utxo.addressType as AddressType) || AddressType.P2WPKH,
        isCoinbase: utxo.isCoinbase ?? false,
      });
    }

    // Restore labels
    if (data.labels) {
      wallet.setLabelsFromObject(data.labels);
    }

    // Restore encryption state
    if (data.encryption) {
      wallet.setEncryptionState(data.encryption);
    }

    // Regenerate keys (only if not encrypted, or if we have the seed)
    if (!wallet.encryption.isEncrypted || wallet.seed.length > 0) {
      wallet.pregenerateAddresses();
    }

    return wallet;
  }

  /**
   * Save wallet to encrypted file.
   */
  async save(password: string): Promise<void> {
    const walletPath = `${this.config.datadir}/wallet.dat`;

    // Serialize wallet data
    const utxos: SerializedUTXO[] = [];
    for (const utxo of this.utxos.values()) {
      utxos.push({
        txid: utxo.outpoint.txid.toString("hex"),
        vout: utxo.outpoint.vout,
        amount: utxo.amount.toString(),
        address: utxo.address,
        keyPath: utxo.keyPath,
        confirmations: utxo.confirmations,
        addressType: utxo.addressType,
        isCoinbase: utxo.isCoinbase ?? false,
      });
    }

    // Convert indices maps to objects
    const nextReceiveIndices: Record<string, number> = {};
    for (const [type, index] of this.nextReceiveIndex.entries()) {
      nextReceiveIndices[type] = index;
    }
    const nextChangeIndices: Record<string, number> = {};
    for (const [type, index] of this.nextChangeIndex.entries()) {
      nextChangeIndices[type] = index;
    }

    const data: WalletData = {
      seed: this.encryption.isEncrypted
        ? "" // Don't store plaintext seed if wallet is encrypted
        : this.seed.toString("hex"),
      nextReceiveIndices,
      nextChangeIndices,
      utxos,
      labels: this.getLabelsObject(),
      encryption: this.getEncryptionState(),
    };

    const plaintext = Buffer.from(JSON.stringify(data), "utf-8");

    // Derive encryption key using PBKDF2
    const salt = Buffer.from(randomBytes(16));
    const key = Buffer.from(
      pbkdf2(sha256, Buffer.from(password, "utf-8"), salt, {
        c: 100000,
        dkLen: 32,
      })
    );

    // Encrypt using AES-256-GCM
    const iv = Buffer.from(randomBytes(12));
    const aes = gcm(key, iv);
    const ciphertext = aes.encrypt(plaintext);

    const encrypted: EncryptedWalletFile = {
      version: 1,
      salt: salt.toString("hex"),
      iv: iv.toString("hex"),
      ciphertext: Buffer.from(ciphertext).toString("hex"),
    };

    await Bun.write(walletPath, JSON.stringify(encrypted, null, 2));
  }

  /**
   * Derive master key from seed using HMAC-SHA512 with key "Bitcoin seed".
   */
  private deriveMasterKey(seed: Buffer): { key: Buffer; chainCode: Buffer } {
    const I = Buffer.from(hmac(sha512, Buffer.from("Bitcoin seed"), seed));
    return {
      key: I.subarray(0, 32),
      chainCode: I.subarray(32, 64),
    };
  }

  /**
   * BIP-32 key derivation: derive child key from parent.
   *
   * For hardened derivation (index >= 0x80000000):
   *   HMAC-SHA512(chainCode, 0x00 || parentKey || index)
   *
   * For normal derivation:
   *   HMAC-SHA512(chainCode, parentPubKey || index)
   */
  private deriveChild(
    parentKey: Buffer,
    parentChainCode: Buffer,
    index: number
  ): { key: Buffer; chainCode: Buffer } {
    const isHardened = index >= HARDENED_OFFSET;

    let data: Buffer;
    if (isHardened) {
      // Hardened: 0x00 || private key || index
      data = Buffer.alloc(37);
      data[0] = 0x00;
      parentKey.copy(data, 1);
      data.writeUInt32BE(index, 33);
    } else {
      // Normal: compressed public key || index
      const parentPubKey = privateKeyToPublicKey(parentKey, true);
      data = Buffer.alloc(37);
      parentPubKey.copy(data, 0);
      data.writeUInt32BE(index, 33);
    }

    const I = Buffer.from(hmac(sha512, parentChainCode, data));
    const IL = I.subarray(0, 32);
    const IR = I.subarray(32, 64);

    // Child key = IL + parent key (mod curve order)
    const parentKeyBigInt = BigInt("0x" + parentKey.toString("hex"));
    const ILBigInt = BigInt("0x" + IL.toString("hex"));

    const childKeyBigInt = (parentKeyBigInt + ILBigInt) % CURVE_ORDER;

    // Convert back to 32-byte buffer
    let childKeyHex = childKeyBigInt.toString(16);
    childKeyHex = childKeyHex.padStart(64, "0");
    const childKey = Buffer.from(childKeyHex, "hex");

    return {
      key: childKey,
      chainCode: IR,
    };
  }

  /**
   * Derive a key at a specific BIP path.
   * Paths:
   *   BIP-44 (P2PKH):      m/44'/coin'/account'/change/index
   *   BIP-49 (P2SH-P2WPKH): m/49'/coin'/account'/change/index
   *   BIP-84 (P2WPKH):     m/84'/coin'/account'/change/index
   *   BIP-86 (P2TR):       m/86'/coin'/account'/change/index
   */
  private deriveKey(path: string, addressType: AddressType): WalletKey {
    if (!path.startsWith("m/")) {
      throw new Error(`Invalid path format: ${path}`);
    }

    const parts = path.slice(2).split("/");
    let currentKey = this.masterKey.key;
    let currentChainCode = this.masterKey.chainCode;

    for (const part of parts) {
      const isHardened = part.endsWith("'");
      const indexStr = isHardened ? part.slice(0, -1) : part;
      let index = parseInt(indexStr, 10);

      if (isNaN(index)) {
        throw new Error(`Invalid path component: ${part}`);
      }

      if (isHardened) {
        index += HARDENED_OFFSET;
      }

      const derived = this.deriveChild(currentKey, currentChainCode, index);
      currentKey = derived.key;
      currentChainCode = derived.chainCode;
    }

    const privateKey = currentKey;
    const publicKey = privateKeyToPublicKey(privateKey, true);

    // Generate address based on type
    const address = this.pubkeyToAddress(publicKey, addressType);

    return {
      privateKey,
      publicKey,
      address,
      path,
      addressType,
    };
  }

  /**
   * Convert a public key to an address of the given type.
   */
  private pubkeyToAddress(publicKey: Buffer, addressType: AddressType): string {
    const network = this.config.network;

    switch (addressType) {
      case AddressType.P2PKH:
        // Legacy P2PKH: HASH160(pubkey)
        return pubkeyToP2PKH(publicKey, network);

      case AddressType.P2SH:
        // P2SH-P2WPKH (nested segwit)
        // redeemScript = OP_0 <20-byte-key-hash>
        // address = Base58Check(version || HASH160(redeemScript))
        return this.pubkeyToP2SHP2WPKH(publicKey);

      case AddressType.P2WPKH:
        // Native segwit P2WPKH
        return pubkeyToP2WPKH(publicKey, network);

      case AddressType.P2TR:
        // Taproot P2TR (BIP-86 key-path only)
        return this.pubkeyToP2TR(publicKey);

      default:
        throw new Error(`Unsupported address type: ${addressType}`);
    }
  }

  /**
   * Generate P2SH-P2WPKH address (nested segwit).
   * BIP-49: redeemScript = OP_0 <HASH160(pubkey)>
   */
  private pubkeyToP2SHP2WPKH(publicKey: Buffer): string {
    const pubKeyHash = hash160(publicKey);
    // redeemScript: OP_0 PUSH20 <20-byte-hash>
    const redeemScript = Buffer.concat([Buffer.from([0x00, 0x14]), pubKeyHash]);
    const scriptHash = hash160(redeemScript);

    const version =
      this.config.network === "mainnet" ? 0x05 : 0xc4; // P2SH version byte
    return base58CheckEncode(version, scriptHash);
  }

  /**
   * Generate P2TR address (taproot) using BIP-86 key-path spending.
   * The internal key is tweaked with the empty script tree hash.
   */
  private pubkeyToP2TR(publicKey: Buffer): string {
    // Get the x-only public key (32 bytes, drop the prefix)
    const xOnlyPubkey = publicKey.subarray(1, 33);

    // BIP-86: tweak = SHA256(taggedHash("TapTweak", pubkey))
    // For key-path only (no scripts), we tweak with just the pubkey
    const tweak = taggedHash(TAPTWEAK_TAG, xOnlyPubkey);

    // Tweak the public key
    const tweakedPubkey = this.tweakPublicKey(xOnlyPubkey, tweak);

    // Encode as bech32m address (witness version 1)
    const hrp = this.getHrp();
    return bech32Encode(hrp, 1, tweakedPubkey);
  }

  /**
   * Tweak a public key for Taproot.
   * P' = P + tweak * G
   */
  private tweakPublicKey(xOnlyPubkey: Buffer, tweak: Buffer): Buffer {
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

    // Get the x-only coordinate (32 bytes) using the schnorr utils
    const tweakedBytes = schnorr.utils.pointToBytes(tweakedPoint);
    return Buffer.from(tweakedBytes);
  }

  /**
   * Get HRP for bech32/bech32m addresses.
   */
  private getHrp(): string {
    switch (this.config.network) {
      case "mainnet":
        return "bc";
      case "testnet":
        return "tb";
      case "regtest":
        return "bcrt";
    }
  }

  /**
   * Pre-generate addresses for all address types on both receive and change chains.
   * Maintains a gap of ADDRESS_GAP addresses ahead of the last used.
   */
  private pregenerateAddresses(): void {
    const addressTypes = [
      AddressType.P2PKH,
      AddressType.P2SH,
      AddressType.P2WPKH,
      AddressType.P2TR,
    ];

    for (const addressType of addressTypes) {
      const receiveIndex = this.nextReceiveIndex.get(addressType) ?? 0;
      const changeIndex = this.nextChangeIndex.get(addressType) ?? 0;

      // Generate receive addresses
      const receiveTarget = receiveIndex + this.ADDRESS_GAP;
      for (let i = 0; i < receiveTarget; i++) {
        const path = this.getReceivePath(i, addressType);
        if (!this.hasKeyForPath(path)) {
          const key = this.deriveKey(path, addressType);
          this.keys.set(key.address, key);
        }
      }

      // Generate change addresses
      const changeTarget = changeIndex + this.ADDRESS_GAP;
      for (let i = 0; i < changeTarget; i++) {
        const path = this.getChangePath(i, addressType);
        if (!this.hasKeyForPath(path)) {
          const key = this.deriveKey(path, addressType);
          this.keys.set(key.address, key);
        }
      }
    }
  }

  /**
   * Check if we have a key for a given path.
   */
  private hasKeyForPath(path: string): boolean {
    for (const key of this.keys.values()) {
      if (key.path === path) {
        return true;
      }
    }
    return false;
  }

  /**
   * Get the BIP purpose number for an address type.
   */
  private getBipPurpose(addressType: AddressType): number {
    switch (addressType) {
      case AddressType.P2PKH:
        return 44;
      case AddressType.P2SH:
        return 49;
      case AddressType.P2WPKH:
        return 84;
      case AddressType.P2TR:
        return 86;
      default:
        throw new Error(`Unsupported address type: ${addressType}`);
    }
  }

  /**
   * Get receive path for a given index and address type.
   * m/purpose'/coin'/account'/0/index
   */
  private getReceivePath(index: number, addressType: AddressType): string {
    const purpose = this.getBipPurpose(addressType);
    const coinType = this.config.network === "mainnet" ? 0 : 1;
    return `m/${purpose}'/${coinType}'/0'/0/${index}`;
  }

  /**
   * Get change path for a given index and address type.
   * m/purpose'/coin'/account'/1/index
   */
  private getChangePath(index: number, addressType: AddressType): string {
    const purpose = this.getBipPurpose(addressType);
    const coinType = this.config.network === "mainnet" ? 0 : 1;
    return `m/${purpose}'/${coinType}'/0'/1/${index}`;
  }

  /**
   * Generate the next receive address of the specified type.
   * @param type - Address type: "legacy", "p2sh-segwit", "bech32", or "bech32m"
   * Default is "bech32" (P2WPKH) for backwards compatibility.
   */
  getNewAddress(type: WalletAddressType = "bech32"): string {
    const addressType = Wallet.walletAddressTypeToEnum(type);
    const index = this.nextReceiveIndex.get(addressType) ?? 0;
    const path = this.getReceivePath(index, addressType);
    const key = this.deriveKey(path, addressType);
    this.keys.set(key.address, key);
    this.nextReceiveIndex.set(addressType, index + 1);

    // Ensure gap is maintained
    this.pregenerateAddresses();

    return key.address;
  }

  /**
   * Generate a change address of the specified type.
   * Default is "bech32" (P2WPKH) for backwards compatibility.
   */
  getChangeAddress(type: WalletAddressType = "bech32"): string {
    const addressType = Wallet.walletAddressTypeToEnum(type);
    const index = this.nextChangeIndex.get(addressType) ?? 0;
    const path = this.getChangePath(index, addressType);
    const key = this.deriveKey(path, addressType);
    this.keys.set(key.address, key);
    this.nextChangeIndex.set(addressType, index + 1);

    // Ensure gap is maintained
    this.pregenerateAddresses();

    return key.address;
  }

  /**
   * Get wallet balance.
   */
  getBalance(): { confirmed: bigint; unconfirmed: bigint; total: bigint } {
    let confirmed = 0n;
    let unconfirmed = 0n;

    for (const utxo of this.utxos.values()) {
      if (utxo.confirmations >= 1) {
        confirmed += utxo.amount;
      } else {
        unconfirmed += utxo.amount;
      }
    }

    return {
      confirmed,
      unconfirmed,
      total: confirmed + unconfirmed,
    };
  }

  /**
   * Scan the UTXO set for outputs matching our addresses.
   */
  async scanUTXOs(db: ChainDB): Promise<void> {
    // Get current chain state for confirmation count
    const chainState = await db.getChainState();
    const currentHeight = chainState?.bestHeight ?? 0;

    // Clear existing UTXOs for rescan
    this.utxos.clear();

    // For each address we control, scan for UTXOs
    // In a real implementation, we'd iterate the UTXO set
    // Here we'd need to iterate all UTXOs and check if they match our addresses

    // Get all our addresses
    const ourAddresses = new Set<string>();
    for (const key of this.keys.values()) {
      ourAddresses.add(key.address);
    }

    // Note: This is a simplified implementation.
    // In practice, we'd iterate the UTXO database and match scriptPubKeys.
    // LevelDB iteration would look something like:
    //
    // for await (const [key, value] of db.iterator({ prefix: UTXO_PREFIX })) {
    //   const utxo = deserializeUTXO(value);
    //   const address = scriptPubKeyToAddress(utxo.scriptPubKey);
    //   if (ourAddresses.has(address)) {
    //     // Add to wallet UTXOs
    //   }
    // }
    //
    // For now, wallet UTXOs are tracked by processBlock() as blocks come in.

    // Update confirmation counts for existing UTXOs
    for (const utxo of this.utxos.values()) {
      const dbUtxo = await db.getUTXO(utxo.outpoint.txid, utxo.outpoint.vout);
      if (dbUtxo) {
        utxo.confirmations = currentHeight - dbUtxo.height + 1;
      } else {
        // UTXO was spent, remove it
        const key = `${utxo.outpoint.txid.toString("hex")}:${utxo.outpoint.vout}`;
        this.utxos.delete(key);
      }
    }
  }

  /**
   * Create and sign a transaction.
   */
  createTransaction(
    outputs: { address: string; amount: bigint }[],
    feeRate: number
  ): Transaction {
    // Calculate total output amount
    let totalOutput = 0n;
    for (const output of outputs) {
      if (output.amount <= 0n) {
        throw new Error("Output amount must be positive");
      }
      totalOutput += output.amount;
    }

    // Select coins
    const selectedUtxos = this.selectCoins(totalOutput, feeRate);

    // Calculate total input amount
    let totalInput = 0n;
    for (const utxo of selectedUtxos) {
      totalInput += utxo.amount;
    }

    // Estimate transaction size for fee calculation
    // P2WPKH: ~10 + 68*inputs + 31*outputs vbytes (approximate)
    const numOutputs = outputs.length + 1; // +1 for potential change
    const estimatedVSize =
      10 + 68 * selectedUtxos.length + 31 * numOutputs;
    const estimatedFee = BigInt(Math.ceil(estimatedVSize * feeRate));

    // Calculate change
    const change = totalInput - totalOutput - estimatedFee;

    if (change < 0n) {
      throw new Error(
        `Insufficient funds: need ${totalOutput + estimatedFee}, have ${totalInput}`
      );
    }

    // Build transaction inputs
    const txInputs: TxIn[] = selectedUtxos.map((utxo) => ({
      prevOut: utxo.outpoint,
      scriptSig: Buffer.alloc(0), // Empty for P2WPKH
      sequence: 0xffffffff,
      witness: [], // Will be filled by signInput
    }));

    // Build transaction outputs
    const txOutputs: TxOut[] = outputs.map((output) => {
      const decoded = decodeAddress(output.address);
      return {
        value: output.amount,
        scriptPubKey: this.buildScriptPubKey(decoded.type, decoded.hash),
      };
    });

    // Add change output if significant (> dust threshold of 546 sats)
    const DUST_THRESHOLD = 546n;
    if (change > DUST_THRESHOLD) {
      const changeAddress = this.getChangeAddress();
      const decoded = decodeAddress(changeAddress);
      txOutputs.push({
        value: change,
        scriptPubKey: this.buildScriptPubKey(decoded.type, decoded.hash),
      });
    }

    // Create transaction
    const tx: Transaction = {
      version: 2,
      inputs: txInputs,
      outputs: txOutputs,
      lockTime: 0,
    };

    // Sign all inputs
    for (let i = 0; i < txInputs.length; i++) {
      const utxo = selectedUtxos[i];
      const key = this.keys.get(utxo.address);
      if (!key) {
        throw new Error(`No key found for address: ${utxo.address}`);
      }
      this.signInput(tx, i, key, utxo);
    }

    return tx;
  }

  /**
   * Build scriptPubKey for an address type and hash.
   */
  private buildScriptPubKey(type: AddressType, hash: Buffer): Buffer {
    switch (type) {
      case AddressType.P2WPKH:
        // OP_0 <20-byte hash>
        return Buffer.concat([Buffer.from([0x00, 0x14]), hash]);
      case AddressType.P2WSH:
        // OP_0 <32-byte hash>
        return Buffer.concat([Buffer.from([0x00, 0x20]), hash]);
      case AddressType.P2PKH:
        // OP_DUP OP_HASH160 <20-byte hash> OP_EQUALVERIFY OP_CHECKSIG
        return Buffer.concat([
          Buffer.from([0x76, 0xa9, 0x14]),
          hash,
          Buffer.from([0x88, 0xac]),
        ]);
      case AddressType.P2SH:
        // OP_HASH160 <20-byte hash> OP_EQUAL
        return Buffer.concat([
          Buffer.from([0xa9, 0x14]),
          hash,
          Buffer.from([0x87]),
        ]);
      case AddressType.P2TR:
        // OP_1 <32-byte key>
        return Buffer.concat([Buffer.from([0x51, 0x20]), hash]);
      default:
        throw new Error(`Unsupported address type: ${type}`);
    }
  }

  /**
   * Sign a transaction input based on address type.
   */
  private signInput(
    tx: Transaction,
    inputIndex: number,
    key: WalletKey,
    utxo: WalletUTXO
  ): void {
    switch (key.addressType) {
      case AddressType.P2PKH:
        this.signP2PKHInput(tx, inputIndex, key, utxo);
        break;
      case AddressType.P2SH:
        this.signP2SHP2WPKHInput(tx, inputIndex, key, utxo);
        break;
      case AddressType.P2WPKH:
        this.signP2WPKHInput(tx, inputIndex, key, utxo);
        break;
      case AddressType.P2TR:
        this.signP2TRInput(tx, inputIndex, key, utxo);
        break;
      default:
        throw new Error(`Unsupported address type for signing: ${key.addressType}`);
    }
  }

  /**
   * Sign a P2PKH input (legacy).
   */
  private signP2PKHInput(
    tx: Transaction,
    inputIndex: number,
    key: WalletKey,
    utxo: WalletUTXO
  ): void {
    // For P2PKH, we need to compute legacy sighash
    // scriptPubKey is: OP_DUP OP_HASH160 <pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG
    const pubKeyHash = hash160(key.publicKey);
    const scriptPubKey = Buffer.concat([
      Buffer.from([0x76, 0xa9, 0x14]),
      pubKeyHash,
      Buffer.from([0x88, 0xac]),
    ]);

    // Compute legacy sighash
    const sighash = this.sigHashLegacy(tx, inputIndex, scriptPubKey, SIGHASH_ALL);

    // Sign with ECDSA
    const signature = ecdsaSign(sighash, key.privateKey);
    const sigWithType = Buffer.concat([signature, Buffer.from([SIGHASH_ALL])]);

    // scriptSig: <sig> <pubkey>
    const sigPush = this.pushData(sigWithType);
    const pubkeyPush = this.pushData(key.publicKey);
    tx.inputs[inputIndex].scriptSig = Buffer.concat([sigPush, pubkeyPush]);
    tx.inputs[inputIndex].witness = [];
  }

  /**
   * Sign a P2SH-P2WPKH input (nested segwit).
   */
  private signP2SHP2WPKHInput(
    tx: Transaction,
    inputIndex: number,
    key: WalletKey,
    utxo: WalletUTXO
  ): void {
    // Create the P2WPKH scriptCode
    const pubKeyHash = hash160(key.publicKey);
    const scriptCode = Buffer.concat([
      Buffer.from([0x76, 0xa9, 0x14]),
      pubKeyHash,
      Buffer.from([0x88, 0xac]),
    ]);

    // Compute BIP-143 sighash
    const sighash = sigHashWitnessV0(
      tx,
      inputIndex,
      scriptCode,
      utxo.amount,
      SIGHASH_ALL
    );

    // Sign with ECDSA
    const signature = ecdsaSign(sighash, key.privateKey);
    const sigWithType = Buffer.concat([signature, Buffer.from([SIGHASH_ALL])]);

    // redeemScript: OP_0 <pubKeyHash>
    const redeemScript = Buffer.concat([Buffer.from([0x00, 0x14]), pubKeyHash]);

    // scriptSig: <redeemScript>
    tx.inputs[inputIndex].scriptSig = this.pushData(redeemScript);

    // Witness: [signature, pubkey]
    tx.inputs[inputIndex].witness = [sigWithType, key.publicKey];
  }

  /**
   * Sign a P2WPKH input (native segwit).
   */
  private signP2WPKHInput(
    tx: Transaction,
    inputIndex: number,
    key: WalletKey,
    utxo: WalletUTXO
  ): void {
    // For P2WPKH, the scriptCode is OP_DUP OP_HASH160 <pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG
    const pubKeyHash = hash160(key.publicKey);
    const scriptCode = Buffer.concat([
      Buffer.from([0x76, 0xa9, 0x14]),
      pubKeyHash,
      Buffer.from([0x88, 0xac]),
    ]);

    // Compute BIP-143 sighash
    const sighash = sigHashWitnessV0(
      tx,
      inputIndex,
      scriptCode,
      utxo.amount,
      SIGHASH_ALL
    );

    // Sign with private key
    const signature = ecdsaSign(sighash, key.privateKey);

    // Append sighash type
    const sigWithType = Buffer.concat([signature, Buffer.from([SIGHASH_ALL])]);

    // Set witness: [signature, pubkey]
    tx.inputs[inputIndex].scriptSig = Buffer.alloc(0);
    tx.inputs[inputIndex].witness = [sigWithType, key.publicKey];
  }

  /**
   * Sign a P2TR input (taproot key-path).
   */
  private signP2TRInput(
    tx: Transaction,
    inputIndex: number,
    key: WalletKey,
    utxo: WalletUTXO
  ): void {
    // BIP-341 taproot key-path spending
    // We need to tweak the private key just like we tweaked the public key

    // Get x-only public key
    const xOnlyPubkey = key.publicKey.subarray(1, 33);

    // Compute tweak
    const tweak = taggedHash(TAPTWEAK_TAG, xOnlyPubkey);

    // Tweak the private key: d' = d + t (mod n)
    const privateKeyBigInt = BigInt("0x" + key.privateKey.toString("hex"));
    const tweakBigInt = BigInt("0x" + tweak.toString("hex"));
    const tweakedKeyBigInt = (privateKeyBigInt + tweakBigInt) % CURVE_ORDER;

    let tweakedKeyHex = tweakedKeyBigInt.toString(16);
    tweakedKeyHex = tweakedKeyHex.padStart(64, "0");
    const tweakedPrivateKey = Buffer.from(tweakedKeyHex, "hex");

    // Compute BIP-341 sighash (simplified - uses SIGHASH_DEFAULT = 0x00)
    const sighash = this.sigHashTaproot(tx, inputIndex, utxo.amount, 0x00);

    // Sign with Schnorr (64-byte signature)
    const signature = this.schnorrSign(sighash, tweakedPrivateKey);

    // For SIGHASH_DEFAULT, we use a 64-byte signature (no sighash byte appended)
    tx.inputs[inputIndex].scriptSig = Buffer.alloc(0);
    tx.inputs[inputIndex].witness = [signature];
  }

  /**
   * Legacy sighash computation for P2PKH.
   */
  private sigHashLegacy(
    tx: Transaction,
    inputIndex: number,
    scriptCode: Buffer,
    hashType: number
  ): Buffer {
    // Create a copy of the transaction for signing
    const txCopy: Transaction = {
      version: tx.version,
      inputs: tx.inputs.map((input, i) => ({
        prevOut: input.prevOut,
        scriptSig: i === inputIndex ? scriptCode : Buffer.alloc(0),
        sequence: input.sequence,
        witness: [],
      })),
      outputs: tx.outputs.map((output) => ({
        value: output.value,
        scriptPubKey: output.scriptPubKey,
      })),
      lockTime: tx.lockTime,
    };

    // Serialize and hash
    const serialized = serializeTx(txCopy, false); // without witness
    const hashTypeBytes = Buffer.alloc(4);
    hashTypeBytes.writeUInt32LE(hashType);

    const { hash256 } = require("../crypto/primitives.js");
    return hash256(Buffer.concat([serialized, hashTypeBytes]));
  }

  /**
   * BIP-341 Taproot sighash computation.
   */
  private sigHashTaproot(
    tx: Transaction,
    inputIndex: number,
    amount: bigint,
    hashType: number
  ): Buffer {
    // Simplified BIP-341 sighash for key-path spending
    // This is a basic implementation; full BIP-341 is more complex

    const writer = new BufferWriter();

    // Epoch byte
    writer.writeUInt8(0x00);

    // Hash type
    const effectiveHashType = hashType === 0x00 ? SIGHASH_ALL : hashType;
    writer.writeUInt8(hashType);

    // Version
    writer.writeInt32LE(tx.version);

    // Lock time
    writer.writeUInt32LE(tx.lockTime);

    // Hash of prevouts
    const prevoutsWriter = new BufferWriter();
    for (const input of tx.inputs) {
      prevoutsWriter.writeBuffer(input.prevOut.txid);
      prevoutsWriter.writeUInt32LE(input.prevOut.vout);
    }
    const { sha256Hash } = require("../crypto/primitives.js");
    writer.writeBuffer(sha256Hash(prevoutsWriter.toBuffer()));

    // Hash of amounts
    const amountsWriter = new BufferWriter();
    // For proper implementation, we'd need all input amounts
    // For now, use a placeholder
    amountsWriter.writeInt64LE(amount);
    for (let i = 1; i < tx.inputs.length; i++) {
      amountsWriter.writeInt64LE(0n); // Would need actual amounts
    }
    writer.writeBuffer(sha256Hash(amountsWriter.toBuffer()));

    // Hash of scriptPubKeys
    const scriptsWriter = new BufferWriter();
    // For key-path, this would be the witness program
    const pubKeyHash = Buffer.alloc(32); // placeholder
    scriptsWriter.writeVarSlice(pubKeyHash);
    writer.writeBuffer(sha256Hash(scriptsWriter.toBuffer()));

    // Hash of sequences
    const seqWriter = new BufferWriter();
    for (const input of tx.inputs) {
      seqWriter.writeUInt32LE(input.sequence);
    }
    writer.writeBuffer(sha256Hash(seqWriter.toBuffer()));

    // Hash of outputs
    const outputsWriter = new BufferWriter();
    for (const output of tx.outputs) {
      outputsWriter.writeInt64LE(output.value);
      outputsWriter.writeVarSlice(output.scriptPubKey);
    }
    writer.writeBuffer(sha256Hash(outputsWriter.toBuffer()));

    // Spend type (key-path, no annex)
    writer.writeUInt8(0x00);

    // Input index
    writer.writeUInt32LE(inputIndex);

    return taggedHash("TapSighash", writer.toBuffer());
  }

  /**
   * Schnorr signature for Taproot.
   */
  private schnorrSign(msgHash: Buffer, privateKey: Buffer): Buffer {
    // Use schnorr signing from @noble/curves
    const signature = schnorr.sign(msgHash, privateKey);
    return Buffer.from(signature);
  }

  /**
   * Push data with appropriate opcode.
   */
  private pushData(data: Buffer): Buffer {
    if (data.length < 0x4c) {
      // Single byte push
      return Buffer.concat([Buffer.from([data.length]), data]);
    } else if (data.length <= 0xff) {
      // OP_PUSHDATA1
      return Buffer.concat([Buffer.from([0x4c, data.length]), data]);
    } else if (data.length <= 0xffff) {
      // OP_PUSHDATA2
      const lenBuf = Buffer.alloc(2);
      lenBuf.writeUInt16LE(data.length);
      return Buffer.concat([Buffer.from([0x4d]), lenBuf, data]);
    } else {
      // OP_PUSHDATA4
      const lenBuf = Buffer.alloc(4);
      lenBuf.writeUInt32LE(data.length);
      return Buffer.concat([Buffer.from([0x4e]), lenBuf, data]);
    }
  }

  /**
   * Select UTXOs using best available algorithm.
   * Tries BnB first (exact match without change), then Knapsack, then largest-first.
   */
  private selectCoins(target: bigint, feeRate: number): WalletUTXO[] {
    const result = this.selectCoinsAdvanced(target, feeRate);
    return result.inputs;
  }

  /**
   * Advanced coin selection with algorithm choice.
   * Tries BnB first (exact match without change), then Knapsack, then largest-first.
   */
  selectCoinsAdvanced(
    target: bigint,
    feeRate: number,
    changeType: AddressType = AddressType.P2WPKH
  ): CoinSelectionResult {
    // Get all available UTXOs (confirmed only for safety)
    // Skip coinbase UTXOs that haven't reached maturity (100 confirmations)
    const available: WalletUTXO[] = [];
    for (const utxo of this.utxos.values()) {
      if (utxo.confirmations < 1) {
        continue; // Unconfirmed
      }
      // Coinbase outputs require COINBASE_MATURITY (100) confirmations
      if (utxo.isCoinbase && utxo.confirmations < COINBASE_MATURITY) {
        continue; // Immature coinbase
      }
      available.push(utxo);
    }

    if (available.length === 0) {
      throw new Error("No confirmed UTXOs available");
    }

    // Calculate cost of change (creating + spending later)
    const changeOutputWeight = this.getOutputWeight(changeType);
    const changeInputWeight = this.getInputWeight(changeType);
    const changeFee = BigInt(Math.ceil((changeOutputWeight / 4) * feeRate));
    const costOfChange = changeFee + BigInt(Math.ceil((changeInputWeight / 4) * feeRate));

    // Try BnB first (exact match without change output)
    const bnbResult = this.selectCoinsBnB(
      available,
      target,
      feeRate,
      costOfChange
    );
    if (bnbResult) {
      return bnbResult;
    }

    // Try Knapsack (with change output)
    const knapsackResult = this.selectCoinsKnapsack(
      available,
      target,
      feeRate,
      changeType
    );
    if (knapsackResult) {
      return knapsackResult;
    }

    // Fallback to largest-first
    return this.selectCoinsLargestFirst(available, target, feeRate, changeType);
  }

  /**
   * Get the input weight for an address type.
   */
  private getInputWeight(addressType: AddressType): number {
    switch (addressType) {
      case AddressType.P2PKH:
        return INPUT_WEIGHT.P2PKH;
      case AddressType.P2SH:
        return INPUT_WEIGHT.P2SH_P2WPKH;
      case AddressType.P2WPKH:
        return INPUT_WEIGHT.P2WPKH;
      case AddressType.P2TR:
        return INPUT_WEIGHT.P2TR;
      default:
        return INPUT_WEIGHT.P2WPKH;
    }
  }

  /**
   * Get the output weight for an address type.
   */
  private getOutputWeight(addressType: AddressType): number {
    switch (addressType) {
      case AddressType.P2PKH:
        return OUTPUT_WEIGHT.P2PKH;
      case AddressType.P2SH:
        return OUTPUT_WEIGHT.P2SH;
      case AddressType.P2WPKH:
        return OUTPUT_WEIGHT.P2WPKH;
      case AddressType.P2TR:
        return OUTPUT_WEIGHT.P2TR;
      default:
        return OUTPUT_WEIGHT.P2WPKH;
    }
  }

  /**
   * Calculate effective value of a UTXO after spending fee.
   */
  private getEffectiveValue(utxo: WalletUTXO, feeRate: number): bigint {
    const inputWeight = this.getInputWeight(utxo.addressType);
    const inputFee = BigInt(Math.ceil((inputWeight / 4) * feeRate));
    return utxo.amount - inputFee;
  }

  /**
   * Branch-and-Bound coin selection algorithm.
   * Searches for an exact match (no change output needed).
   *
   * Based on Bitcoin Core's SelectCoinsBnB from coinselection.cpp.
   */
  selectCoinsBnB(
    utxos: WalletUTXO[],
    target: bigint,
    feeRate: number,
    costOfChange: bigint
  ): CoinSelectionResult | null {
    // Filter UTXOs with positive effective value and calculate effective values
    const utxoData: Array<{ utxo: WalletUTXO; effectiveValue: bigint }> = [];
    let totalAvailable = 0n;

    for (const utxo of utxos) {
      const effectiveValue = this.getEffectiveValue(utxo, feeRate);
      if (effectiveValue > 0n) {
        utxoData.push({ utxo, effectiveValue });
        totalAvailable += effectiveValue;
      }
    }

    if (totalAvailable < target) {
      return null;
    }

    // Sort by effective value descending
    utxoData.sort((a, b) => {
      if (b.effectiveValue > a.effectiveValue) return 1;
      if (b.effectiveValue < a.effectiveValue) return -1;
      return 0;
    });

    // BnB depth-first search
    let currentValue = 0n;
    let currentAvailable = totalAvailable;
    const currentSelection: number[] = [];
    let bestSelection: number[] = [];
    let bestValue = BigInt("0x7fffffffffffffffffffffffffffffff"); // Max value sentinel

    for (let tries = 0, index = 0; tries < TOTAL_TRIES; tries++, index++) {
      let backtrack = false;

      // Check if we need to backtrack
      if (currentValue + currentAvailable < target) {
        // Cannot reach target with remaining UTXOs
        backtrack = true;
      } else if (currentValue > target + costOfChange) {
        // Exceeded target + cost of change (would need change output)
        backtrack = true;
      } else if (currentValue >= target) {
        // Found a valid selection!
        if (currentValue < bestValue) {
          bestSelection = [...currentSelection];
          bestValue = currentValue;
        }
        backtrack = true;
      }

      if (backtrack) {
        if (currentSelection.length === 0) {
          break; // Searched all possibilities
        }

        // Backtrack: restore available value for skipped UTXOs
        while (index > currentSelection[currentSelection.length - 1] + 1) {
          index--;
          currentAvailable += utxoData[index].effectiveValue;
        }

        // Deselect the last selected UTXO
        index = currentSelection[currentSelection.length - 1];
        currentValue -= utxoData[index].effectiveValue;
        currentSelection.pop();
      } else if (index < utxoData.length) {
        // Include this UTXO
        currentAvailable -= utxoData[index].effectiveValue;

        // Skip duplicate effective values (optimization)
        if (
          currentSelection.length === 0 ||
          index - 1 === currentSelection[currentSelection.length - 1] ||
          utxoData[index].effectiveValue !== utxoData[index - 1].effectiveValue
        ) {
          currentSelection.push(index);
          currentValue += utxoData[index].effectiveValue;
        }
      } else {
        // Reached end of UTXO pool, backtrack
        if (currentSelection.length === 0) {
          break;
        }
        index = currentSelection[currentSelection.length - 1];
        currentValue -= utxoData[index].effectiveValue;
        currentSelection.pop();
      }
    }

    if (bestSelection.length === 0) {
      return null;
    }

    // Build result
    const selectedInputs = bestSelection.map((i) => utxoData[i].utxo);
    let totalInput = 0n;
    let totalInputFee = 0n;

    for (const input of selectedInputs) {
      totalInput += input.amount;
      const inputWeight = this.getInputWeight(input.addressType);
      totalInputFee += BigInt(Math.ceil((inputWeight / 4) * feeRate));
    }

    return {
      inputs: selectedInputs,
      totalInput,
      fee: totalInputFee,
      change: 0n, // BnB produces no change
      algorithm: "bnb",
    };
  }

  /**
   * Knapsack coin selection algorithm.
   * Uses stochastic approximation to find a good subset sum.
   *
   * Based on Bitcoin Core's KnapsackSolver from coinselection.cpp.
   */
  selectCoinsKnapsack(
    utxos: WalletUTXO[],
    target: bigint,
    feeRate: number,
    changeType: AddressType
  ): CoinSelectionResult | null {
    // Calculate change target (minimum change we want to produce)
    const changeOutputWeight = this.getOutputWeight(changeType);
    const changeFee = BigInt(Math.ceil((changeOutputWeight / 4) * feeRate));
    const minChange = CHANGE_LOWER + changeFee;

    // Calculate effective values
    const utxoData: Array<{ utxo: WalletUTXO; effectiveValue: bigint }> = [];
    let totalLower = 0n;
    let lowestLarger: { utxo: WalletUTXO; effectiveValue: bigint } | null = null;

    for (const utxo of utxos) {
      const effectiveValue = this.getEffectiveValue(utxo, feeRate);
      if (effectiveValue <= 0n) continue;

      if (effectiveValue === target) {
        // Exact match!
        const inputWeight = this.getInputWeight(utxo.addressType);
        const fee = BigInt(Math.ceil((inputWeight / 4) * feeRate));
        return {
          inputs: [utxo],
          totalInput: utxo.amount,
          fee,
          change: 0n,
          algorithm: "knapsack",
        };
      } else if (effectiveValue < target + minChange) {
        utxoData.push({ utxo, effectiveValue });
        totalLower += effectiveValue;
      } else if (!lowestLarger || effectiveValue < lowestLarger.effectiveValue) {
        lowestLarger = { utxo, effectiveValue };
      }
    }

    // If sum of smaller coins exactly matches target
    if (totalLower === target) {
      return this.buildKnapsackResult(
        utxoData.map((d) => d.utxo),
        feeRate,
        0n
      );
    }

    // If sum of smaller coins is insufficient, use the smallest larger coin
    if (totalLower < target) {
      if (lowestLarger) {
        const inputWeight = this.getInputWeight(lowestLarger.utxo.addressType);
        const fee = BigInt(Math.ceil((inputWeight / 4) * feeRate));
        return {
          inputs: [lowestLarger.utxo],
          totalInput: lowestLarger.utxo.amount,
          fee,
          change: lowestLarger.utxo.amount - target - fee,
          algorithm: "knapsack",
        };
      }
      return null;
    }

    // Shuffle and sort by effective value descending
    this.shuffleArray(utxoData);
    utxoData.sort((a, b) => {
      if (b.effectiveValue > a.effectiveValue) return 1;
      if (b.effectiveValue < a.effectiveValue) return -1;
      return 0;
    });

    // Approximate best subset
    let bestSelection: boolean[] = new Array(utxoData.length).fill(true);
    let bestValue = totalLower;

    // Try to find exact match first, then match with min change
    const targets = [target, target + minChange];

    for (const targetValue of targets) {
      for (let rep = 0; rep < KNAPSACK_ITERATIONS && bestValue !== targetValue; rep++) {
        const included = new Array(utxoData.length).fill(false);
        let total = 0n;
        let reachedTarget = false;

        for (let pass = 0; pass < 2 && !reachedTarget; pass++) {
          for (let i = 0; i < utxoData.length; i++) {
            // First pass: random selection, second pass: fill in missing
            if (pass === 0 ? Math.random() < 0.5 : !included[i]) {
              total += utxoData[i].effectiveValue;
              included[i] = true;

              if (total >= targetValue) {
                reachedTarget = true;
                if (total < bestValue) {
                  bestValue = total;
                  bestSelection = [...included];
                }
                total -= utxoData[i].effectiveValue;
                included[i] = false;
              }
            }
          }
        }
      }
    }

    // If lowestLarger is closer to target, use it instead
    if (
      lowestLarger &&
      (bestValue < target + minChange ||
        lowestLarger.effectiveValue <= bestValue)
    ) {
      const inputWeight = this.getInputWeight(lowestLarger.utxo.addressType);
      const fee = BigInt(Math.ceil((inputWeight / 4) * feeRate));
      return {
        inputs: [lowestLarger.utxo],
        totalInput: lowestLarger.utxo.amount,
        fee,
        change: lowestLarger.utxo.amount - target - fee,
        algorithm: "knapsack",
      };
    }

    // Build result from best selection
    const selectedUtxos: WalletUTXO[] = [];
    for (let i = 0; i < utxoData.length; i++) {
      if (bestSelection[i]) {
        selectedUtxos.push(utxoData[i].utxo);
      }
    }

    if (selectedUtxos.length === 0) {
      return null;
    }

    return this.buildKnapsackResult(selectedUtxos, feeRate, target);
  }

  /**
   * Build a CoinSelectionResult from selected UTXOs.
   */
  private buildKnapsackResult(
    inputs: WalletUTXO[],
    feeRate: number,
    target: bigint
  ): CoinSelectionResult {
    let totalInput = 0n;
    let totalFee = 0n;

    for (const input of inputs) {
      totalInput += input.amount;
      const inputWeight = this.getInputWeight(input.addressType);
      totalFee += BigInt(Math.ceil((inputWeight / 4) * feeRate));
    }

    const change = target === 0n ? 0n : totalInput - target - totalFee;

    return {
      inputs,
      totalInput,
      fee: totalFee,
      change: change > 0n ? change : 0n,
      algorithm: "knapsack",
    };
  }

  /**
   * Largest-first coin selection (fallback).
   */
  private selectCoinsLargestFirst(
    utxos: WalletUTXO[],
    target: bigint,
    feeRate: number,
    changeType: AddressType
  ): CoinSelectionResult {
    // Sort by amount descending
    const sorted = [...utxos].sort((a, b) => {
      if (b.amount > a.amount) return 1;
      if (b.amount < a.amount) return -1;
      return 0;
    });

    const selected: WalletUTXO[] = [];
    let totalSelected = 0n;
    let totalFee = 0n;

    // Base tx weight (version + locktime + input/output count)
    const baseTxWeight = 10 * 4;
    // Assuming 1 output for payment + potential change
    const outputWeight =
      this.getOutputWeight(AddressType.P2WPKH) +
      this.getOutputWeight(changeType);

    for (const utxo of sorted) {
      selected.push(utxo);
      totalSelected += utxo.amount;

      // Calculate current fee
      let inputsWeight = 0;
      for (const sel of selected) {
        inputsWeight += this.getInputWeight(sel.addressType);
      }

      const totalWeight = baseTxWeight + inputsWeight + outputWeight;
      totalFee = BigInt(Math.ceil((totalWeight / 4) * feeRate));

      if (totalSelected >= target + totalFee) {
        const change = totalSelected - target - totalFee;
        return {
          inputs: selected,
          totalInput: totalSelected,
          fee: totalFee,
          change,
          algorithm: "largest_first",
        };
      }
    }

    throw new Error(
      `Insufficient funds: need ${target}, only have ${totalSelected}`
    );
  }

  /**
   * Fisher-Yates shuffle.
   */
  private shuffleArray<T>(array: T[]): void {
    for (let i = array.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [array[i], array[j]] = [array[j], array[i]];
    }
  }

  /**
   * List all wallet addresses.
   */
  listAddresses(): WalletKey[] {
    return Array.from(this.keys.values());
  }

  /**
   * Update UTXOs when a new block is connected.
   */
  processBlock(block: Block, height: number): void {
    // Get our addresses and their types
    const ourAddresses = new Set<string>();
    const addressToPath = new Map<string, string>();
    const addressToType = new Map<string, AddressType>();

    for (const key of this.keys.values()) {
      ourAddresses.add(key.address);
      addressToPath.set(key.address, key.path);
      addressToType.set(key.address, key.addressType);
    }

    // Process each transaction
    for (const tx of block.transactions) {
      const txid = getTxId(tx);
      const txIsCoinbase = isCoinbase(tx);

      // Check outputs for incoming payments
      for (let vout = 0; vout < tx.outputs.length; vout++) {
        const output = tx.outputs[vout];
        const addressInfo = this.scriptPubKeyToAddressInfo(output.scriptPubKey);

        if (addressInfo && ourAddresses.has(addressInfo.address)) {
          const outpointKey = `${txid.toString("hex")}:${vout}`;
          const keyPath = addressToPath.get(addressInfo.address) ?? "";
          const addrType = addressToType.get(addressInfo.address) ?? addressInfo.type;

          this.utxos.set(outpointKey, {
            outpoint: { txid, vout },
            amount: output.value,
            address: addressInfo.address,
            keyPath,
            confirmations: 1,
            addressType: addrType,
            isCoinbase: txIsCoinbase,
          });
        }
      }

      // Check inputs for outgoing spends
      for (const input of tx.inputs) {
        const spentKey = `${input.prevOut.txid.toString("hex")}:${input.prevOut.vout}`;
        if (this.utxos.has(spentKey)) {
          this.utxos.delete(spentKey);
        }
      }
    }

    // Increment confirmation count for all UTXOs
    for (const utxo of this.utxos.values()) {
      utxo.confirmations++;
    }
  }

  /**
   * Convert a scriptPubKey to an address string (legacy compatibility).
   */
  private scriptPubKeyToAddress(scriptPubKey: Buffer): string | null {
    const info = this.scriptPubKeyToAddressInfo(scriptPubKey);
    return info ? info.address : null;
  }

  /**
   * Convert a scriptPubKey to an address with type info.
   */
  private scriptPubKeyToAddressInfo(
    scriptPubKey: Buffer
  ): { address: string; type: AddressType } | null {
    // P2WPKH: OP_0 <20-byte hash>
    if (
      scriptPubKey.length === 22 &&
      scriptPubKey[0] === 0x00 &&
      scriptPubKey[1] === 0x14
    ) {
      const pubKeyHash = scriptPubKey.subarray(2);
      return {
        address: encodeAddress({
          type: AddressType.P2WPKH,
          hash: pubKeyHash,
          network: this.config.network,
        }),
        type: AddressType.P2WPKH,
      };
    }

    // P2WSH: OP_0 <32-byte hash>
    if (
      scriptPubKey.length === 34 &&
      scriptPubKey[0] === 0x00 &&
      scriptPubKey[1] === 0x20
    ) {
      const scriptHash = scriptPubKey.subarray(2);
      return {
        address: encodeAddress({
          type: AddressType.P2WSH,
          hash: scriptHash,
          network: this.config.network,
        }),
        type: AddressType.P2WSH,
      };
    }

    // P2TR: OP_1 <32-byte key>
    if (
      scriptPubKey.length === 34 &&
      scriptPubKey[0] === 0x51 &&
      scriptPubKey[1] === 0x20
    ) {
      const tweakedPubkey = scriptPubKey.subarray(2);
      return {
        address: encodeAddress({
          type: AddressType.P2TR,
          hash: tweakedPubkey,
          network: this.config.network,
        }),
        type: AddressType.P2TR,
      };
    }

    // P2PKH: OP_DUP OP_HASH160 <20-byte hash> OP_EQUALVERIFY OP_CHECKSIG
    if (
      scriptPubKey.length === 25 &&
      scriptPubKey[0] === 0x76 &&
      scriptPubKey[1] === 0xa9 &&
      scriptPubKey[2] === 0x14 &&
      scriptPubKey[23] === 0x88 &&
      scriptPubKey[24] === 0xac
    ) {
      const pubKeyHash = scriptPubKey.subarray(3, 23);
      return {
        address: encodeAddress({
          type: AddressType.P2PKH,
          hash: pubKeyHash,
          network: this.config.network,
        }),
        type: AddressType.P2PKH,
      };
    }

    // P2SH: OP_HASH160 <20-byte hash> OP_EQUAL
    if (
      scriptPubKey.length === 23 &&
      scriptPubKey[0] === 0xa9 &&
      scriptPubKey[1] === 0x14 &&
      scriptPubKey[22] === 0x87
    ) {
      const scriptHash = scriptPubKey.subarray(2, 22);
      return {
        address: encodeAddress({
          type: AddressType.P2SH,
          hash: scriptHash,
          network: this.config.network,
        }),
        type: AddressType.P2SH,
      };
    }

    return null;
  }

  /**
   * Get a key by address.
   */
  getKey(address: string): WalletKey | undefined {
    return this.keys.get(address);
  }

  /**
   * Check if wallet contains an address.
   */
  hasAddress(address: string): boolean {
    return this.keys.has(address);
  }

  /**
   * Get all UTXOs.
   */
  getUTXOs(): WalletUTXO[] {
    return Array.from(this.utxos.values());
  }

  /**
   * Get only spendable UTXOs (confirmed and mature coinbase).
   */
  getSpendableUTXOs(): WalletUTXO[] {
    const spendable: WalletUTXO[] = [];
    for (const utxo of this.utxos.values()) {
      if (utxo.confirmations < 1) {
        continue; // Unconfirmed
      }
      if (utxo.isCoinbase && utxo.confirmations < COINBASE_MATURITY) {
        continue; // Immature coinbase
      }
      spendable.push(utxo);
    }
    return spendable;
  }

  /**
   * Check if a UTXO is spendable (confirmed and mature if coinbase).
   */
  isUTXOSpendable(utxo: WalletUTXO): boolean {
    if (utxo.confirmations < 1) {
      return false;
    }
    if (utxo.isCoinbase && utxo.confirmations < COINBASE_MATURITY) {
      return false;
    }
    return true;
  }

  /**
   * Manually add a UTXO (for testing or importing).
   */
  addUTXO(utxo: WalletUTXO): void {
    const key = `${utxo.outpoint.txid.toString("hex")}:${utxo.outpoint.vout}`;
    this.utxos.set(key, utxo);
  }

  /**
   * Get the seed (for backup).
   * WARNING: This exposes the master secret!
   */
  getSeed(): Buffer {
    if (this.encryption.isEncrypted && this.encryption.isLocked) {
      throw new Error("Wallet is locked. Please unlock with walletpassphrase first.");
    }
    return this.seed;
  }

  // ============================================================================
  // Wallet Encryption Methods (AES-256-CBC with scrypt key derivation)
  // ============================================================================

  /**
   * Check if the wallet is encrypted.
   */
  isEncrypted(): boolean {
    return this.encryption.isEncrypted;
  }

  /**
   * Check if the wallet is locked (encrypted and not unlocked).
   */
  isLocked(): boolean {
    return this.encryption.isEncrypted && this.encryption.isLocked;
  }

  /**
   * Derive encryption key from passphrase using scrypt.
   * Uses secure parameters: N=2^14, r=8, p=1
   * (Bitcoin Core uses N=2^14 for wallet encryption)
   */
  private async deriveEncryptionKey(passphrase: string, salt: Buffer): Promise<Buffer> {
    return new Promise((resolve, reject) => {
      crypto.scrypt(passphrase, salt, 32, { N: 16384, r: 8, p: 1 }, (err, key) => {
        if (err) {
          reject(err);
        } else {
          resolve(key);
        }
      });
    });
  }

  /**
   * Encrypt data using AES-256-CBC.
   */
  private encryptAES256CBC(plaintext: Buffer, key: Buffer, iv: Buffer): Buffer {
    const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);
    const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    return encrypted;
  }

  /**
   * Decrypt data using AES-256-CBC.
   */
  private decryptAES256CBC(ciphertext: Buffer, key: Buffer, iv: Buffer): Buffer {
    const decipher = crypto.createDecipheriv("aes-256-cbc", key, iv);
    const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return decrypted;
  }

  /**
   * Encrypt the wallet with a passphrase (encryptwallet RPC).
   *
   * This encrypts the seed with AES-256-CBC and locks the wallet.
   * After encryption, the wallet file will be re-saved with encrypted keys.
   *
   * @param passphrase - The encryption passphrase
   * @throws If wallet is already encrypted
   */
  async encryptWallet(passphrase: string): Promise<void> {
    if (this.encryption.isEncrypted) {
      throw new Error("Wallet is already encrypted. Use walletpassphrasechange to change the passphrase.");
    }

    if (!passphrase || passphrase.length < 1) {
      throw new Error("Passphrase cannot be empty.");
    }

    // Generate salt and IV
    const salt = crypto.randomBytes(32);
    const iv = crypto.randomBytes(16);

    // Derive encryption key
    const key = await this.deriveEncryptionKey(passphrase, salt);

    // Encrypt the seed
    const encryptedSeed = this.encryptAES256CBC(this.seed, key, iv);

    // Update encryption state
    this.encryption = {
      isEncrypted: true,
      isLocked: true,
      encryptedSeed,
      encryptionSalt: salt,
      encryptionIV: iv,
      unlockTimeout: null,
    };

    // Clear the plaintext seed from memory
    this.seed.fill(0);
    this.seed = Buffer.alloc(0);

    // Clear master key
    this.masterKey.key.fill(0);
    this.masterKey.chainCode.fill(0);

    // Note: Private keys are derived on-demand from the seed, so they're not in memory
    // when the wallet is locked. The key map contains public info only when locked.
  }

  /**
   * Unlock the wallet temporarily (walletpassphrase RPC).
   *
   * @param passphrase - The encryption passphrase
   * @param timeout - Seconds to keep the wallet unlocked (0 = until lock or shutdown)
   * @throws If passphrase is incorrect or wallet is not encrypted
   */
  async unlockWallet(passphrase: string, timeout: number): Promise<void> {
    if (!this.encryption.isEncrypted) {
      throw new Error("Wallet is not encrypted.");
    }

    if (!this.encryption.isLocked) {
      // Already unlocked - just reset the timeout
      if (this.encryption.unlockTimeout) {
        clearTimeout(this.encryption.unlockTimeout);
        this.encryption.unlockTimeout = null;
      }

      if (timeout > 0) {
        this.encryption.unlockTimeout = setTimeout(() => {
          this.lockWallet();
        }, timeout * 1000);
      }
      return;
    }

    if (!this.encryption.encryptedSeed || !this.encryption.encryptionSalt || !this.encryption.encryptionIV) {
      throw new Error("Wallet encryption state is invalid.");
    }

    // Derive encryption key
    const key = await this.deriveEncryptionKey(passphrase, this.encryption.encryptionSalt);

    // Try to decrypt the seed
    let decryptedSeed: Buffer;
    try {
      decryptedSeed = this.decryptAES256CBC(this.encryption.encryptedSeed, key, this.encryption.encryptionIV);
    } catch {
      throw new Error("Incorrect passphrase.");
    }

    // Verify the seed is valid (64 bytes for BIP-39)
    if (decryptedSeed.length !== 64) {
      throw new Error("Incorrect passphrase.");
    }

    // Restore the seed
    this.seed = decryptedSeed;
    this.masterKey = this.deriveMasterKey(this.seed);

    // Regenerate addresses now that we have the seed
    this.pregenerateAddresses();

    // Mark as unlocked
    this.encryption.isLocked = false;

    // Set auto-lock timeout
    if (timeout > 0) {
      this.encryption.unlockTimeout = setTimeout(() => {
        this.lockWallet();
      }, timeout * 1000);
    }
  }

  /**
   * Lock the wallet (walletlock RPC).
   *
   * Clears the decrypted seed from memory.
   */
  lockWallet(): void {
    if (!this.encryption.isEncrypted) {
      throw new Error("Wallet is not encrypted.");
    }

    if (this.encryption.isLocked) {
      return; // Already locked
    }

    // Clear timeout if set
    if (this.encryption.unlockTimeout) {
      clearTimeout(this.encryption.unlockTimeout);
      this.encryption.unlockTimeout = null;
    }

    // Clear the plaintext seed from memory
    this.seed.fill(0);
    this.seed = Buffer.alloc(0);

    // Clear master key
    this.masterKey.key.fill(0);
    this.masterKey.chainCode.fill(0);

    // Mark as locked
    this.encryption.isLocked = true;
  }

  /**
   * Change the wallet passphrase (walletpassphrasechange RPC).
   *
   * @param oldPassphrase - Current passphrase
   * @param newPassphrase - New passphrase
   * @throws If old passphrase is incorrect or wallet is not encrypted
   */
  async changePassphrase(oldPassphrase: string, newPassphrase: string): Promise<void> {
    if (!this.encryption.isEncrypted) {
      throw new Error("Wallet is not encrypted.");
    }

    if (!newPassphrase || newPassphrase.length < 1) {
      throw new Error("New passphrase cannot be empty.");
    }

    // If locked, unlock first to get the seed
    const wasLocked = this.encryption.isLocked;
    if (wasLocked) {
      await this.unlockWallet(oldPassphrase, 0);
    }

    // Generate new salt and IV
    const newSalt = crypto.randomBytes(32);
    const newIV = crypto.randomBytes(16);

    // Derive new encryption key
    const newKey = await this.deriveEncryptionKey(newPassphrase, newSalt);

    // Re-encrypt the seed
    const encryptedSeed = this.encryptAES256CBC(this.seed, newKey, newIV);

    // Update encryption state
    this.encryption.encryptedSeed = encryptedSeed;
    this.encryption.encryptionSalt = newSalt;
    this.encryption.encryptionIV = newIV;

    // If was locked, lock again
    if (wasLocked) {
      this.lockWallet();
    }
  }

  /**
   * Get encryption state for serialization.
   */
  getEncryptionState(): {
    isEncrypted: boolean;
    encryptedSeed: string | null;
    encryptionSalt: string | null;
    encryptionIV: string | null;
  } {
    return {
      isEncrypted: this.encryption.isEncrypted,
      encryptedSeed: this.encryption.encryptedSeed?.toString("hex") ?? null,
      encryptionSalt: this.encryption.encryptionSalt?.toString("hex") ?? null,
      encryptionIV: this.encryption.encryptionIV?.toString("hex") ?? null,
    };
  }

  /**
   * Restore encryption state from serialization.
   */
  setEncryptionState(state: {
    isEncrypted: boolean;
    encryptedSeed: string | null;
    encryptionSalt: string | null;
    encryptionIV: string | null;
  }): void {
    this.encryption = {
      isEncrypted: state.isEncrypted,
      isLocked: state.isEncrypted, // Start locked if encrypted
      encryptedSeed: state.encryptedSeed ? Buffer.from(state.encryptedSeed, "hex") : null,
      encryptionSalt: state.encryptionSalt ? Buffer.from(state.encryptionSalt, "hex") : null,
      encryptionIV: state.encryptionIV ? Buffer.from(state.encryptionIV, "hex") : null,
      unlockTimeout: null,
    };
  }

  // ============================================================================
  // Address Label Methods
  // ============================================================================

  /**
   * Set a label for an address.
   *
   * @param address - The address to label
   * @param label - The label to assign (empty string removes the label)
   */
  setLabel(address: string, label: string): void {
    if (!this.hasAddress(address)) {
      throw new Error(`Address not found in wallet: ${address}`);
    }

    if (label === "") {
      this.labels.delete(address);
    } else {
      this.labels.set(address, label);
    }
  }

  /**
   * Get the label for an address.
   *
   * @param address - The address to look up
   * @returns The label, or empty string if not labeled
   */
  getLabel(address: string): string {
    return this.labels.get(address) ?? "";
  }

  /**
   * Get all addresses with a specific label.
   *
   * @param label - The label to search for
   * @returns Array of addresses with that label
   */
  getAddressesByLabel(label: string): string[] {
    const addresses: string[] = [];
    for (const [address, addressLabel] of this.labels) {
      if (addressLabel === label) {
        addresses.push(address);
      }
    }
    return addresses;
  }

  /**
   * Get all labels with their addresses.
   *
   * @returns Map of label -> addresses
   */
  listLabels(): Map<string, string[]> {
    const labelMap = new Map<string, string[]>();
    for (const [address, label] of this.labels) {
      const addresses = labelMap.get(label) ?? [];
      addresses.push(address);
      labelMap.set(label, addresses);
    }
    return labelMap;
  }

  /**
   * Get all labels as an object (for serialization).
   */
  getLabelsObject(): Record<string, string> {
    const obj: Record<string, string> = {};
    for (const [address, label] of this.labels) {
      obj[address] = label;
    }
    return obj;
  }

  /**
   * Restore labels from an object.
   */
  setLabelsFromObject(obj: Record<string, string>): void {
    this.labels.clear();
    for (const [address, label] of Object.entries(obj)) {
      this.labels.set(address, label);
    }
  }

  /**
   * List received by address with labels.
   *
   * @returns Array of { address, label, amount, confirmations }
   */
  listReceivedByAddress(): Array<{
    address: string;
    label: string;
    amount: bigint;
    confirmations: number;
  }> {
    const received = new Map<string, { amount: bigint; confirmations: number }>();

    // Aggregate UTXOs by address
    for (const utxo of this.utxos.values()) {
      const existing = received.get(utxo.address);
      if (existing) {
        existing.amount += utxo.amount;
        existing.confirmations = Math.min(existing.confirmations, utxo.confirmations);
      } else {
        received.set(utxo.address, {
          amount: utxo.amount,
          confirmations: utxo.confirmations,
        });
      }
    }

    // Build result with labels
    const result: Array<{
      address: string;
      label: string;
      amount: bigint;
      confirmations: number;
    }> = [];

    for (const [address, { amount, confirmations }] of received) {
      result.push({
        address,
        label: this.getLabel(address),
        amount,
        confirmations,
      });
    }

    return result;
  }
}

/**
 * Options for creating a new wallet.
 */
export interface CreateWalletOptions {
  /** Disable private keys (watch-only wallet). */
  disablePrivateKeys?: boolean;
  /** Create a blank wallet with no keys. */
  blank?: boolean;
  /** Encrypt the wallet with this passphrase. */
  passphrase?: string;
  /** Track clean/dirty coins to avoid address reuse. */
  avoidReuse?: boolean;
  /** Use output descriptors (always true for new wallets). */
  descriptors?: boolean;
  /** Save wallet name to settings for auto-load on startup. */
  loadOnStartup?: boolean;
}

/**
 * Result of createwallet RPC.
 */
export interface CreateWalletResult {
  name: string;
  warnings: string[];
}

/**
 * Result of loadwallet RPC.
 */
export interface LoadWalletResult {
  name: string;
  warnings: string[];
}

/**
 * Entry in listwalletdir result.
 */
export interface WalletDirEntry {
  name: string;
}

/**
 * Multi-wallet manager: maintains multiple wallets loaded simultaneously.
 *
 * Reference: Bitcoin Core's WalletContext in wallet/context.h
 *
 * Wallet storage layout:
 *   <datadir>/wallets/<name>/wallet.dat
 *
 * The default wallet (empty name "") is stored at:
 *   <datadir>/wallets/wallet.dat
 */
export class WalletManager {
  private wallets: Map<string, Wallet> = new Map();
  private datadir: string;
  private network: "mainnet" | "testnet" | "regtest";
  private settingsPath: string;

  constructor(datadir: string, network: "mainnet" | "testnet" | "regtest") {
    this.datadir = datadir;
    this.network = network;
    this.settingsPath = `${datadir}/settings.json`;
  }

  /**
   * Get the wallets directory path.
   */
  getWalletsDir(): string {
    return `${this.datadir}/wallets`;
  }

  /**
   * Get the path to a wallet's directory.
   */
  getWalletPath(name: string): string {
    if (name === "") {
      // Default wallet is stored directly in wallets dir
      return `${this.getWalletsDir()}/wallet.dat`;
    }
    return `${this.getWalletsDir()}/${name}`;
  }

  /**
   * Get the path to a wallet's data file.
   */
  getWalletFilePath(name: string): string {
    if (name === "") {
      return `${this.getWalletsDir()}/wallet.dat`;
    }
    return `${this.getWalletsDir()}/${name}/wallet.dat`;
  }

  /**
   * Create a new wallet.
   *
   * Reference: Bitcoin Core's CreateWallet in wallet/wallet.cpp
   */
  async createWallet(
    name: string,
    options: CreateWalletOptions = {},
    password: string = ""
  ): Promise<CreateWalletResult> {
    const warnings: string[] = [];

    // Wallet must have a non-empty name (Bitcoin Core behavior)
    // Note: we allow empty name for default wallet unlike Core
    if (name.includes("/") || name.includes("\\")) {
      throw new Error("Wallet name cannot contain path separators");
    }

    // Check if wallet is already loaded
    if (this.wallets.has(name)) {
      throw new Error(`Wallet "${name}" is already loaded`);
    }

    // Check if wallet file already exists
    const walletFile = this.getWalletFilePath(name);
    const file = Bun.file(walletFile);
    if (await file.exists()) {
      throw new Error(
        `Wallet "${name}" already exists. Use loadwallet to load it.`
      );
    }

    // Create wallet directory if needed
    const walletDir = name === "" ? this.getWalletsDir() : `${this.getWalletsDir()}/${name}`;
    const { mkdirSync, existsSync } = await import("fs");
    if (!existsSync(walletDir)) {
      mkdirSync(walletDir, { recursive: true });
    }

    // Handle passphrase for encryption
    // Only encrypt if options.passphrase is explicitly provided (not the storage password)
    const encryptionPassphrase = options.passphrase;
    if (encryptionPassphrase === "" && options.passphrase !== undefined) {
      warnings.push(
        "Empty string given as passphrase, wallet will not be encrypted."
      );
    }

    // Use storage password (for file encryption, not wallet encryption)
    const storagePassword = password || "hotbuns";

    // Blank wallet: no keys generated
    // disablePrivateKeys: watch-only wallet
    // For now, we create a standard HD wallet

    const config: WalletConfig = {
      datadir: name === "" ? this.getWalletsDir() : walletDir,
      network: this.network,
    };

    const wallet = Wallet.create(config);

    // If passphrase provided in options, encrypt the wallet
    if (encryptionPassphrase) {
      await wallet.encryptWallet(encryptionPassphrase);
    }

    // Save the wallet
    await wallet.save(storagePassword);

    // Add to loaded wallets
    this.wallets.set(name, wallet);

    // Update settings if loadOnStartup is true
    if (options.loadOnStartup === true) {
      await this.addWalletToSettings(name);
    } else if (options.loadOnStartup === false) {
      await this.removeWalletFromSettings(name);
    }

    return { name, warnings };
  }

  /**
   * Load an existing wallet from disk.
   *
   * Reference: Bitcoin Core's LoadWallet in wallet/wallet.cpp
   */
  async loadWallet(
    name: string,
    password: string,
    loadOnStartup?: boolean
  ): Promise<LoadWalletResult> {
    const warnings: string[] = [];

    // Check if already loaded
    if (this.wallets.has(name)) {
      throw new Error(`Wallet "${name}" is already loaded`);
    }

    // Check if wallet file exists
    const walletFile = this.getWalletFilePath(name);
    const file = Bun.file(walletFile);
    if (!(await file.exists())) {
      throw new Error(`Wallet "${name}" not found`);
    }

    const config: WalletConfig = {
      datadir: name === "" ? this.getWalletsDir() : `${this.getWalletsDir()}/${name}`,
      network: this.network,
    };

    const wallet = await Wallet.load(config, password);
    this.wallets.set(name, wallet);

    // Update settings
    if (loadOnStartup === true) {
      await this.addWalletToSettings(name);
    } else if (loadOnStartup === false) {
      await this.removeWalletFromSettings(name);
    }

    return { name, warnings };
  }

  /**
   * Unload a wallet from memory.
   *
   * Reference: Bitcoin Core's RemoveWallet in wallet/wallet.cpp
   */
  async unloadWallet(
    name: string,
    loadOnStartup?: boolean
  ): Promise<{ warnings: string[] }> {
    const warnings: string[] = [];

    if (!this.wallets.has(name)) {
      throw new Error(`Wallet "${name}" is not loaded`);
    }

    this.wallets.delete(name);

    // Update settings
    if (loadOnStartup === true) {
      await this.addWalletToSettings(name);
    } else if (loadOnStartup === false) {
      await this.removeWalletFromSettings(name);
    }

    return { warnings };
  }

  /**
   * Get a loaded wallet by name.
   */
  getWallet(name: string): Wallet | undefined {
    return this.wallets.get(name);
  }

  /**
   * Get the default wallet if exactly one wallet is loaded.
   *
   * Reference: Bitcoin Core's GetDefaultWallet in wallet/wallet.cpp
   */
  getDefaultWallet(): Wallet | undefined {
    if (this.wallets.size === 1) {
      return this.wallets.values().next().value;
    }
    return undefined;
  }

  /**
   * Get all loaded wallet names.
   */
  listWallets(): string[] {
    return Array.from(this.wallets.keys());
  }

  /**
   * List available wallet directories.
   *
   * Reference: Bitcoin Core's ListDatabases in wallet/walletutil.cpp
   */
  async listWalletDir(): Promise<WalletDirEntry[]> {
    const walletsDir = this.getWalletsDir();
    const entries: WalletDirEntry[] = [];

    const { readdirSync, statSync, existsSync } = await import("fs");

    if (!existsSync(walletsDir)) {
      return entries;
    }

    // Check for default wallet (wallet.dat directly in wallets dir)
    const defaultWalletFile = `${walletsDir}/wallet.dat`;
    if (existsSync(defaultWalletFile)) {
      entries.push({ name: "" });
    }

    // Check subdirectories for wallet.dat files
    const files = readdirSync(walletsDir);
    for (const file of files) {
      const filePath = `${walletsDir}/${file}`;
      const stat = statSync(filePath);
      if (stat.isDirectory()) {
        const walletFile = `${filePath}/wallet.dat`;
        if (existsSync(walletFile)) {
          entries.push({ name: file });
        }
      }
    }

    return entries;
  }

  /**
   * Get wallet count.
   */
  getWalletCount(): number {
    return this.wallets.size;
  }

  /**
   * Check if a wallet is loaded.
   */
  hasWallet(name: string): boolean {
    return this.wallets.has(name);
  }

  /**
   * Load settings from settings.json.
   */
  private async loadSettings(): Promise<{ wallet?: string[] }> {
    try {
      const file = Bun.file(this.settingsPath);
      if (await file.exists()) {
        const content = await file.text();
        return JSON.parse(content);
      }
    } catch {
      // Ignore errors
    }
    return {};
  }

  /**
   * Save settings to settings.json.
   */
  private async saveSettings(settings: { wallet?: string[] }): Promise<void> {
    await Bun.write(this.settingsPath, JSON.stringify(settings, null, 2));
  }

  /**
   * Add a wallet to the startup list in settings.json.
   */
  private async addWalletToSettings(name: string): Promise<void> {
    const settings = await this.loadSettings();
    if (!settings.wallet) {
      settings.wallet = [];
    }
    if (!settings.wallet.includes(name)) {
      settings.wallet.push(name);
      await this.saveSettings(settings);
    }
  }

  /**
   * Remove a wallet from the startup list in settings.json.
   */
  private async removeWalletFromSettings(name: string): Promise<void> {
    const settings = await this.loadSettings();
    if (settings.wallet) {
      settings.wallet = settings.wallet.filter((w) => w !== name);
      await this.saveSettings(settings);
    }
  }

  /**
   * Get wallets that should be loaded on startup.
   */
  async getStartupWallets(): Promise<string[]> {
    const settings = await this.loadSettings();
    return settings.wallet || [];
  }

  /**
   * Load all wallets configured for startup.
   */
  async loadStartupWallets(password: string): Promise<void> {
    const walletNames = await this.getStartupWallets();
    for (const name of walletNames) {
      try {
        await this.loadWallet(name, password);
      } catch (error) {
        // Log error but continue loading other wallets
        console.error(`Failed to load wallet "${name}":`, error);
      }
    }
  }

  /**
   * Process a new block for all loaded wallets.
   */
  processBlock(block: Block, height: number): void {
    for (const wallet of this.wallets.values()) {
      wallet.processBlock(block, height);
    }
  }
}
