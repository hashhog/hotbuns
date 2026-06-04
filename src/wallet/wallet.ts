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
  validateMnemonic as bip39ValidateMnemonic,
  parseMnemonicString as bip39ParseMnemonicString,
} from "./bip39.js";

import {
  hash160,
  privateKeyToPublicKey,
  ecdsaSign,
  taggedHash,
  tweakPrivateKey,
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
  type TaprootSigHashCache,
  serializeTx,
  getTxId,
  sigHashWitnessV0,
  sigHashTaproot,
  SIGHASH_ALL,
  isCoinbase,
} from "../validation/tx.js";
import type { Block } from "../validation/block.js";

// Import secp256k1 for Taproot key tweaking
import { secp256k1, schnorr } from "@noble/curves/secp256k1.js";

// BIP-32 constants
const HARDENED_OFFSET = 0x80000000;
const BIP32_MAX_INDEX = 0xffffffff;

// secp256k1 curve order (n)
const CURVE_ORDER = BigInt(
  "0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"
);

/**
 * BIP-125 opt-in RBF sequence value.
 *
 * Per BIP-125 / bitcoin-core/src/util/rbf.h::MAX_BIP125_RBF_SEQUENCE,
 * a transaction signals replaceability when at least one input's nSequence
 * is < 0xfffffffe (SEQUENCE_FINAL - 1). Core's wallet defaults to
 * 0xfffffffd (SEQUENCE_FINAL - 2): RBF-replaceable AND nLockTime-honoring.
 *
 * Hotbuns previously hardcoded 0xffffffff (SEQUENCE_FINAL), which:
 *   1. opts out of RBF — bumpfee would have had nothing to bump.
 *   2. disables nLockTime — even when set, Core treats final-sequence inputs
 *      as ignoring locktime (anti-fee-sniping does not apply).
 *
 * This is the worst-case BIP-125 violation in the W118 fleet audit.
 */
export const BIP125_RBF_SEQUENCE = 0xfffffffd;

/**
 * Recoverable error signalling that BIP-32 CKD landed on the spec-mandated
 * skip case: parse256(IL) >= n  OR  k_i == 0. Both conditions are extremely
 * rare (~2^-127) but the spec REQUIRES the caller to bump the child index
 * by 1 and retry rather than emit the invalid key.
 *
 * BIP-32: "In case parse256(IL) >= n or k_i = 0, the resulting key is
 *          invalid, and one should proceed with the next value for i."
 *
 * Also matches Bitcoin Core's CKey::Derive: libsecp256k1's seckey_tweak_add
 * returns 0 in exactly these two cases, and Core propagates that as failure.
 */
export class Bip32InvalidChildError extends Error {
  readonly index: number;
  constructor(index: number, reason: "il-overflow" | "child-zero") {
    super(
      `BIP-32 invalid child at index ${index} (${reason}); caller must retry with index+1`
    );
    this.name = "Bip32InvalidChildError";
    this.index = index;
  }
}

/**
 * Pure BIP-32 CKD-priv math given a precomputed HMAC-SHA512 output `I`
 * (64 bytes). Throws `Bip32InvalidChildError` on the spec-mandated skip cases
 * (parse256(IL) >= n  OR  k_i == 0). Exported for unit testing the retry
 * detection without recomputing the HMAC.
 */
export function bip32CkdPrivFromI(
  parentKey: Buffer,
  I: Buffer,
  index: number
): { key: Buffer; chainCode: Buffer } {
  if (I.length !== 64) {
    throw new Error(`bip32CkdPrivFromI: I must be 64 bytes, got ${I.length}`);
  }
  const IL = I.subarray(0, 32);
  const IR = I.subarray(32, 64);

  const parentKeyBigInt = BigInt("0x" + parentKey.toString("hex"));
  const ILBigInt = BigInt("0x" + IL.toString("hex"));

  if (ILBigInt >= CURVE_ORDER) {
    throw new Bip32InvalidChildError(index, "il-overflow");
  }

  const childKeyBigInt = (parentKeyBigInt + ILBigInt) % CURVE_ORDER;
  if (childKeyBigInt === 0n) {
    throw new Bip32InvalidChildError(index, "child-zero");
  }

  const childKeyHex = childKeyBigInt.toString(16).padStart(64, "0");
  return {
    key: Buffer.from(childKeyHex, "hex"),
    chainCode: Buffer.from(IR),
  };
}

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

// Consensus constant: coinbase outputs require 100 blocks to be buried beneath
// them before spending (bitcoin-core/src/consensus/consensus.h:19).
export const COINBASE_MATURITY = 100;

// Wallet-layer spendability threshold for a coinbase, expressed in *wallet
// confirmations* (depth = tipHeight - txHeight + 1, so a coin in the tip block
// has 1 confirmation). Core's wallet matures a coinbase when
// GetBlocksToMaturity() == 0, i.e. chain_depth >= COINBASE_MATURITY + 1
// (bitcoin-core/src/wallet/wallet.cpp:3342). This is exactly one greater than
// the bare COINBASE_MATURITY so the wallet never coin-selects a coinbase the
// mempool would then reject with bad-txns-premature-spend-of-coinbase (the
// mempool uses depth = tipHeight - utxoHeight, one less than wallet depth — see
// src/mempool/mempool.ts coinbase-maturity gate). At tip 101 only the height-1
// coinbase (101 confirmations) is mature; the height-2 coinbase (100) is not.
export const COINBASE_SPENDABLE_DEPTH = COINBASE_MATURITY + 1;

// Coin selection result
export interface CoinSelectionResult {
  inputs: WalletUTXO[];
  totalInput: bigint;
  fee: bigint;
  change: bigint;
  algorithm: "bnb" | "knapsack" | "largest_first";
}

/**
 * Tracked outgoing wallet transaction, retained until confirmed so that
 * bumpfee / psbtbumpfee can re-sign a replacement. Records both the tx
 * itself and the per-input UTXO metadata (which we lose once the originals
 * are deleted from `utxos`).
 */
export interface OutgoingTx {
  /** The signed transaction we broadcast. */
  tx: Transaction;
  /** Per-input UTXOs that funded the original tx, in input order. */
  inputUtxos: WalletUTXO[];
  /** Index of the change output in tx.outputs, or -1 if no change. */
  changeIndex: number;
  /** Original fee paid (sat). */
  fee: bigint;
  /** Original effective fee rate (sat/vB). */
  feeRate: number;
  /** Whether the tx has been confirmed (set in processBlock). */
  confirmed: boolean;
}

/**
 * Result of a bumpfee operation — mirrors Core's bumpfee RPC result.
 */
export interface BumpFeeResult {
  /** New signed replacement transaction. */
  tx: Transaction;
  /** Original tx fee in sat. */
  origFee: bigint;
  /** New replacement tx fee in sat. */
  newFee: bigint;
  /** New effective fee rate in sat/vB. */
  newFeeRate: number;
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

  // Outgoing wallet transactions, keyed by txid (hex). Populated by
  // createTransaction() so bumpfee/psbtbumpfee can locate the original tx
  // along with the per-input UTXO metadata required to re-sign. Entries are
  // removed in processBlock() once the tx is confirmed (we only need to
  // bump unconfirmed txs).
  private outgoingTxs: Map<string, OutgoingTx>;

  constructor(config: WalletConfig) {
    this.config = config;
    this.keys = new Map();
    this.utxos = new Map();
    this.seed = Buffer.alloc(0);
    this.masterKey = { key: Buffer.alloc(0), chainCode: Buffer.alloc(0) };
    this.labels = new Map();
    this.outgoingTxs = new Map();

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
   *
   * The optional BIP-39 `passphrase` is the "25th word" / plausible-deniability
   * passphrase: a different passphrase against the same mnemonic yields a
   * different but equally-valid wallet. This restores parity with
   * Trezor / Ledger / Coldcard and the rest of the hashhog fleet (W161 BUG-12).
   *
   * NOTE: Per BIP-39 spec, `mnemonicToSeed` (the PBKDF2-SHA512 call below)
   * does NOT validate — any UTF-8 string produces *some* seed. The checksum
   * gate must be applied at the user-input boundary so that a typo'd
   * mnemonic fails loudly here instead of silently producing a different
   * but plausible-looking wallet. (Same UX hazard the W21 ouroboros agent
   * flagged for `WalletManager.create_wallet`.)
   */
  static create(
    config: WalletConfig,
    mnemonic?: string,
    passphrase: string = ""
  ): Wallet {
    const wallet = new Wallet(config);

    if (mnemonic) {
      // Validate the mnemonic at the boundary: word count, wordlist
      // membership, and checksum. Throws with a clear error on failure.
      const words = bip39ParseMnemonicString(mnemonic);
      bip39ValidateMnemonic(words);

      // BIP-39 §"From mnemonic to seed": PBKDF2-HMAC-SHA512 with
      //   Password = NFKD(mnemonic sentence)
      //   Salt     = NFKD("mnemonic" + passphrase)
      //   c = 2048, dkLen = 64
      // The salt MUST be NFKD-normalised (BUG-13 fix): a passphrase
      // containing NFK-decomposable characters (Hangul jamo, diacritics)
      // would otherwise produce a different seed than every other BIP-39
      // wallet on earth. ASCII passphrases are NFKD-invariant.
      const mnemonicBuffer = Buffer.from(words.join(" ").normalize("NFKD"), "utf-8");
      const salt = Buffer.from(("mnemonic" + passphrase).normalize("NFKD"), "utf-8");
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
    return bip32CkdPrivFromI(parentKey, I, index);
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

      // BIP-32 spec: on parse256(IL) >= n or k_i == 0, skip to next index.
      // Single retry suffices with overwhelming probability (~2^-127);
      // bound the loop anyway so a pathological mocked-HMAC test cannot
      // burn forever, and so we never cross the hardened/non-hardened
      // boundary (the spec says "next value for i" — same flag).
      const maxIndex = isHardened ? BIP32_MAX_INDEX : HARDENED_OFFSET - 1;
      let derived: { key: Buffer; chainCode: Buffer } | undefined;
      for (let attempt = 0; attempt < 256; attempt++) {
        try {
          derived = this.deriveChild(currentKey, currentChainCode, index);
          break;
        } catch (e) {
          if (!(e instanceof Bip32InvalidChildError)) throw e;
          if (index >= maxIndex) {
            throw new Error(
              `BIP-32 derivation exhausted index space at ${part} (no valid child)`
            );
          }
          index += 1;
        }
      }
      if (!derived) {
        throw new Error(
          `BIP-32 derivation failed after 256 retries at ${part}`
        );
      }
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

    // BIP-341 step 2: t must be a valid scalar (t < n). Otherwise the
    // tweaked output key disagrees with libsecp256k1.
    if (tweakScalar >= CURVE_ORDER) {
      throw new Error("Invalid tweak - exceeds curve order");
    }

    // Compute tweaked point: P' = P + t*G
    const tweakPoint = schnorr.Point.BASE.multiply(tweakScalar);
    const tweakedPoint = point.add(tweakPoint);

    // BIP-341 step 4: reject infinity. noble's pointToBytes(infinity)
    // calls toBytes(true)→assertValidity() which throws (FpIsValidNot0),
    // so this guard mostly matches what noble would surface anyway, but
    // we want a stable error string for the caller.
    if (tweakedPoint.is0()) {
      throw new Error("Invalid tweak - tweaked point is at infinity");
    }

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

    // Build transaction inputs.
    //
    // BIP-125: default to OPTIN RBF (sequence == 0xfffffffd) so a later
    // bumpfee can replace this tx. Setting 0xffffffff opts out of RBF
    // entirely AND disables nLockTime. This mirrors Core's wallet default
    // (see CWallet::CreateTransactionInternal).
    const txInputs: TxIn[] = selectedUtxos.map((utxo) => ({
      prevOut: utxo.outpoint,
      scriptSig: Buffer.alloc(0), // Empty for P2WPKH
      sequence: BIP125_RBF_SEQUENCE,
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

    // Add change output if significant (> dust threshold of 546 sats).
    // Track changeIndex (-1 if no change) so bumpfee can locate it.
    const DUST_THRESHOLD = 546n;
    let changeIndex = -1;
    if (change > DUST_THRESHOLD) {
      const changeAddress = this.getChangeAddress();
      const decoded = decodeAddress(changeAddress);
      changeIndex = txOutputs.length;
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

    // Sign all inputs. Taproot signing requires the prevOut (scriptPubKey +
    // amount) of EVERY input — not just the input being signed — so build the
    // full prevOuts vector once and thread it through.
    const prevOuts = selectedUtxos.map((u) => {
      const decoded = decodeAddress(u.address);
      return {
        scriptPubKey: this.buildScriptPubKey(decoded.type, decoded.hash),
        value: u.amount,
      };
    });
    for (let i = 0; i < txInputs.length; i++) {
      const utxo = selectedUtxos[i];
      const key = this.keys.get(utxo.address);
      if (!key) {
        throw new Error(`No key found for address: ${utxo.address}`);
      }
      this.signInput(tx, i, key, utxo, prevOuts);
    }

    // Compute the actual fee (which may differ from estimatedFee since the
    // size estimate is approximate). totalInput - sum(outputs) = fee.
    let totalOut = 0n;
    for (const out of tx.outputs) totalOut += out.value;
    const actualFee = totalInput - totalOut;

    // Record the outgoing tx so bumpfee/psbtbumpfee can find it later.
    // Use the same effective vsize estimator we use for fee calc so the
    // recorded feeRate is internally consistent.
    const txid = getTxId(tx).toString("hex");
    const actualVSize = 10 + 68 * selectedUtxos.length + 31 * tx.outputs.length;
    this.outgoingTxs.set(txid, {
      tx,
      inputUtxos: [...selectedUtxos],
      changeIndex,
      fee: actualFee,
      feeRate: Number(actualFee) / actualVSize,
      confirmed: false,
    });

    return tx;
  }

  /**
   * Get an outgoing wallet transaction by txid. Returns undefined if not
   * tracked (either never sent by this wallet, or pruned). Exposed so
   * the RPC layer can introspect for bumpfee.
   */
  getOutgoingTx(txid: string): OutgoingTx | undefined {
    return this.outgoingTxs.get(txid);
  }

  /**
   * List all currently tracked outgoing wallet txids (hex).
   */
  listOutgoingTxs(): string[] {
    return Array.from(this.outgoingTxs.keys());
  }

  /**
   * Build a fee-bumped replacement for `txid` and return the new signed
   * transaction. Mirrors bitcoin-core feebumper::CreateRateBumpTransaction
   * + CommitTransaction — minimal viable shape:
   *
   *   1. Locate the original outgoing tx (must be unconfirmed + tracked).
   *   2. Verify BIP-125 signaling (all inputs nSequence < 0xfffffffe).
   *   3. Verify we have keys for every input (AllInputsMine).
   *   4. Compute new fee: max(user-supplied fee_rate, oldFee/vsize + 1 sat/vB).
   *   5. Reduce change output by the delta. Reject if change < dust.
   *   6. Re-sign every input. Stage the new tx into outgoingTxs for chained
   *      bumps.
   *
   * Reference: bitcoin-core/src/wallet/feebumper.cpp.
   *
   * @param txid hex-encoded txid of the original outgoing tx.
   * @param newFeeRate optional explicit replacement fee rate (sat/vB). If
   *   omitted, uses oldFeeRate + 1 sat/vB (Core's bumpfee default).
   */
  bumpFee(txid: string, newFeeRate?: number): BumpFeeResult {
    const out = this.outgoingTxs.get(txid);
    if (!out) {
      throw new Error(`bumpfee: no such wallet transaction: ${txid}`);
    }
    if (out.confirmed) {
      throw new Error(
        "bumpfee: transaction has been mined, or is conflicted with a mined transaction"
      );
    }

    // BIP-125 signaling: Core's PreconditionChecks indirectly requires this
    // via SignalsOptInRBF — at least one input nSequence < 0xfffffffe.
    const anyRbf = out.tx.inputs.some((i) => i.sequence < 0xfffffffe);
    if (!anyRbf) {
      throw new Error(
        "bumpfee: transaction is not BIP-125 replaceable (no input has sequence < 0xfffffffe)"
      );
    }

    // AllInputsMine: every input must be funded by a UTXO we have the key
    // for. createTransaction guarantees this for wallet-originated txs,
    // but check anyway in case the wallet was re-loaded after restart.
    for (const u of out.inputUtxos) {
      if (!this.keys.has(u.address)) {
        throw new Error(
          `bumpfee: transaction contains inputs that don't belong to this wallet (${u.address})`
        );
      }
    }

    if (out.changeIndex < 0) {
      throw new Error(
        "bumpfee: cannot bump transaction without a change output (would need to drop a payment output)"
      );
    }

    // Compute target fee. The replacement tx will have the same input/output
    // shape as the original, so its vsize estimate matches.
    const oldVSize =
      10 + 68 * out.tx.inputs.length + 31 * out.tx.outputs.length;
    const oldFeeRate = Number(out.fee) / oldVSize;
    const targetRate = newFeeRate ?? oldFeeRate + 1;

    // BIP-125 Rule 4 / Core CheckFeeRate: replacement fee must be strictly
    // greater than the original.
    if (targetRate <= oldFeeRate) {
      throw new Error(
        `bumpfee: new fee rate (${targetRate.toFixed(3)} sat/vB) must be greater than original (${oldFeeRate.toFixed(3)} sat/vB)`
      );
    }

    const newFee = BigInt(Math.ceil(oldVSize * targetRate));
    if (newFee <= out.fee) {
      throw new Error(
        `bumpfee: new fee (${newFee}) must exceed original fee (${out.fee})`
      );
    }

    // Build replacement outputs: copy originals, then reduce change by the
    // fee delta. If change would drop below dust, refuse.
    const DUST_THRESHOLD = 546n;
    const feeDelta = newFee - out.fee;
    const origChange = out.tx.outputs[out.changeIndex].value;
    const newChange = origChange - feeDelta;
    if (newChange <= DUST_THRESHOLD) {
      throw new Error(
        `bumpfee: change output would drop below dust (${newChange} <= ${DUST_THRESHOLD})`
      );
    }

    const newOutputs: TxOut[] = out.tx.outputs.map((o, i) =>
      i === out.changeIndex
        ? { value: newChange, scriptPubKey: o.scriptPubKey }
        : { value: o.value, scriptPubKey: o.scriptPubKey }
    );

    // Build replacement inputs: same prevOuts/sequence, empty signatures
    // to be re-filled.
    const newInputs: TxIn[] = out.tx.inputs.map((i) => ({
      prevOut: i.prevOut,
      scriptSig: Buffer.alloc(0),
      sequence: i.sequence < 0xfffffffe ? i.sequence : BIP125_RBF_SEQUENCE,
      witness: [],
    }));

    const newTx: Transaction = {
      version: out.tx.version,
      inputs: newInputs,
      outputs: newOutputs,
      lockTime: out.tx.lockTime,
    };

    // Re-sign every input. Use the recorded inputUtxos for amount/scriptPubKey.
    const prevOuts = out.inputUtxos.map((u) => {
      const decoded = decodeAddress(u.address);
      return {
        scriptPubKey: this.buildScriptPubKey(decoded.type, decoded.hash),
        value: u.amount,
      };
    });
    for (let i = 0; i < newInputs.length; i++) {
      const u = out.inputUtxos[i];
      const key = this.keys.get(u.address);
      if (!key) {
        throw new Error(`bumpfee: missing key for input ${i} (${u.address})`);
      }
      this.signInput(newTx, i, key, u, prevOuts);
    }

    // Track the replacement for further chained bumps.
    const newTxid = getTxId(newTx).toString("hex");
    this.outgoingTxs.set(newTxid, {
      tx: newTx,
      inputUtxos: [...out.inputUtxos],
      changeIndex: out.changeIndex,
      fee: newFee,
      feeRate: Number(newFee) / oldVSize,
      confirmed: false,
    });

    return {
      tx: newTx,
      origFee: out.fee,
      newFee,
      newFeeRate: Number(newFee) / oldVSize,
    };
  }

  /**
   * Build a fee-bumped replacement and return it as an unsigned PSBT instead
   * of a signed tx — the PSBT-mode variant of bumpfee. Mirrors Core's
   * psbtbumpfee RPC: same precondition checks, same fee math, same change
   * reduction; but signatures are STRIPPED so external signers can re-sign.
   *
   * Returned PSBT is in the BIP-174 v0 shape (unsigned tx + per-input UTXO
   * witness_utxo). The replacement is NOT recorded in outgoingTxs (since
   * it's not signed and won't go to the mempool from this wallet).
   *
   * Reference: bitcoin-core/src/wallet/rpc/spend.cpp::psbtbumpfee.
   *
   * @param txid hex-encoded txid of the original outgoing tx.
   * @param newFeeRate optional explicit replacement fee rate (sat/vB).
   * @returns an unsigned Transaction + per-input witness_utxo metadata.
   *   The caller passes this to convertToPSBT() / signPSBTInput().
   */
  psbtBumpFee(
    txid: string,
    newFeeRate?: number
  ): {
    unsignedTx: Transaction;
    inputUtxos: WalletUTXO[];
    origFee: bigint;
    newFee: bigint;
    newFeeRate: number;
  } {
    // Reuse bumpFee's precondition + math by building the replacement, then
    // strip signatures. Cheaper than duplicating ~80 LOC of validation.
    const bumped = this.bumpFee(txid, newFeeRate);

    // Strip signatures from inputs — PSBT consumers will re-sign.
    const unsignedTx: Transaction = {
      version: bumped.tx.version,
      inputs: bumped.tx.inputs.map((i) => ({
        prevOut: i.prevOut,
        scriptSig: Buffer.alloc(0),
        sequence: i.sequence,
        witness: [],
      })),
      outputs: bumped.tx.outputs.map((o) => ({
        value: o.value,
        scriptPubKey: o.scriptPubKey,
      })),
      lockTime: bumped.tx.lockTime,
    };

    // Remove the signed replacement from outgoingTxs — only signed txs that
    // we actually broadcast should be tracked (otherwise we'd offer to bump
    // a PSBT that's still in the signer's hands).
    const signedTxid = getTxId(bumped.tx).toString("hex");
    this.outgoingTxs.delete(signedTxid);

    // Refetch the original to return its inputUtxos for the caller.
    const orig = this.outgoingTxs.get(txid);
    const inputUtxos = orig ? [...orig.inputUtxos] : [];

    return {
      unsignedTx,
      inputUtxos,
      origFee: bumped.origFee,
      newFee: bumped.newFee,
      newFeeRate: bumped.newFeeRate,
    };
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
   *
   * @param prevOuts - scriptPubKey + value for ALL inputs of `tx`. Required for
   *   BIP-341 taproot key-path signing (sha_amounts + sha_scriptPubKeys commit
   *   to every input). Optional for legacy/segwit-v0 paths, which only need
   *   the active input's amount.
   */
  private signInput(
    tx: Transaction,
    inputIndex: number,
    key: WalletKey,
    utxo: WalletUTXO,
    prevOuts?: { scriptPubKey: Buffer; value: bigint }[]
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
      case AddressType.P2TR: {
        // Build the prevOuts vector lazily if the caller didn't pre-compute it
        // (e.g. callers that sign single-input txs). We can recover the
        // scriptPubKey for the *active* input from `utxo.address`; the other
        // inputs' addresses are unknown from here alone, so we require the
        // caller to pass `prevOuts` for multi-input taproot txs. Throw a clear
        // error rather than silently signing with zeros.
        let resolved = prevOuts;
        if (!resolved) {
          if (tx.inputs.length !== 1) {
            throw new Error(
              "signInput(P2TR): multi-input transactions require prevOuts " +
                "(scriptPubKey + value for every input) per BIP-341"
            );
          }
          const decoded = decodeAddress(utxo.address);
          resolved = [
            {
              scriptPubKey: this.buildScriptPubKey(decoded.type, decoded.hash),
              value: utxo.amount,
            },
          ];
        }
        this.signP2TRInput(tx, inputIndex, key, utxo, resolved);
        break;
      }
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
   * Sign a P2TR input (BIP-341 taproot key-path, BIP-86 derivation).
   *
   * Uses the canonical `sigHashTaproot` from validation/tx.ts (the same code
   * path that validates incoming blocks) to produce the BIP-341 sighash, and
   * `tweakPrivateKey` to apply BIP-341's even-y negation + key tweak.
   *
   * Defaults to SIGHASH_DEFAULT (0x00) which produces a 64-byte witness
   * (no sighash byte appended), matching the canonical BIP-86 wallet output.
   */
  private signP2TRInput(
    tx: Transaction,
    inputIndex: number,
    key: WalletKey,
    utxo: WalletUTXO,
    prevOuts: { scriptPubKey: Buffer; value: bigint }[],
    hashType: number = 0x00 // SIGHASH_DEFAULT
  ): void {
    // Internal x-only pubkey P (32 bytes). key.publicKey is the 33-byte
    // compressed form: [parity_byte || x].
    const xOnlyPubkey = key.publicKey.subarray(1, 33);

    // BIP-86: tweak = TaggedHash("TapTweak", x(P)) — no merkle root for
    // single-key BIP-86 derivation. (For BIP-341 script-path wallets, this
    // would be TaggedHash("TapTweak", x(P) || merkle_root).)
    const tweak = taggedHash(TAPTWEAK_TAG, xOnlyPubkey);

    // Tweak the private key with BIP-341 even-y negation. Without the
    // negation step (which was missing pre-W20), ~50% of internal keys
    // produce a tweaked secret that does NOT correspond to the on-chain
    // x-only output key, and Schnorr verify fails.
    const tweakedPrivateKey = tweakPrivateKey(key.privateKey, tweak);

    // Canonical BIP-341 sighash. Commits to ALL inputs' amounts and
    // scriptPubKeys via sha_amounts / sha_scriptPubKeys.
    const cache: TaprootSigHashCache = {};
    const sighash = sigHashTaproot(
      tx,
      inputIndex,
      prevOuts,
      hashType,
      0,         // ext_flag = 0 for key-path
      undefined, // no annex
      undefined, // no tap leaf hash (key-path)
      undefined, // no key version (key-path)
      0xffffffff, // codeSepPos unused for key-path
      cache
    );

    // Schnorr-sign with the tweaked secret. Note that BIP-340's sign() will
    // *not* re-negate the secret: by construction `tweakedPrivateKey * G == Q`
    // where Q is the even-Y output key, so the inner has_even_y(P) check
    // inside Noble's signer is already satisfied.
    const signature = Buffer.from(schnorr.sign(sighash, tweakedPrivateKey));

    // Witness encoding (BIP-341 §"Constructing and spending Taproot outputs"):
    //   - SIGHASH_DEFAULT (0x00): 64-byte signature, no trailing hash-type byte
    //   - any other hashType:    65 bytes — signature || [hashType]
    let witnessSig: Buffer;
    if (hashType === 0x00) {
      witnessSig = signature;
    } else {
      witnessSig = Buffer.concat([signature, Buffer.from([hashType])]);
    }

    tx.inputs[inputIndex].scriptSig = Buffer.alloc(0);
    tx.inputs[inputIndex].witness = [witnessSig];
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
      // Coinbase outputs are spendable only once buried COINBASE_MATURITY deep
      // (wallet depth >= COINBASE_MATURITY + 1); see COINBASE_SPENDABLE_DEPTH.
      if (utxo.isCoinbase && utxo.confirmations < COINBASE_SPENDABLE_DEPTH) {
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
            if (pass === 0 ? (crypto.randomBytes(4).readUInt32BE(0) < 0x80000000) : !included[i]) {
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
      const j = crypto.randomBytes(4).readUInt32BE(0) % (i + 1);
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

    // Track the outpoints credited in THIS block so the per-block confirmation
    // bump below does not double-count their creating block. A coin included in
    // the current tip block has exactly 1 confirmation (Core: GetDepthInMainChain
    // == 1 for a tx in the tip), so a freshly-credited UTXO must stay at 1 — it
    // is the increment loop's job to age only the coins that existed BEFORE this
    // block. (Pre-fix the new UTXO was created at conf=1 and then immediately
    // bumped in the same call, leaving it at conf=2 and over-stating depth by 1,
    // which prematurely matured coinbase by one block.)
    const createdThisBlock = new Set<string>();

    // Process each transaction
    for (const tx of block.transactions) {
      const txid = getTxId(tx);
      const txIsCoinbase = isCoinbase(tx);
      const txidHex = txid.toString("hex");

      // If this is one of our tracked outgoing txs, mark it confirmed so
      // bumpfee no longer offers to bump it. (Bumpfee only operates on
      // unconfirmed txs — see PreconditionChecks GetTxDepthInMainChain != 0.)
      const out = this.outgoingTxs.get(txidHex);
      if (out) {
        out.confirmed = true;
      }

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
          createdThisBlock.add(outpointKey);
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

    // Age every UTXO that existed before this block by one confirmation. Coins
    // credited in this block keep confirmations == 1 (they were just set above).
    for (const [outpointKey, utxo] of this.utxos.entries()) {
      if (!createdThisBlock.has(outpointKey)) {
        utxo.confirmations++;
      }
    }
  }

  /**
   * Reverse the wallet-ledger effects of a block being disconnected from the
   * active tip (reorg). Conservative + lossless: remove only the UTXOs this
   * block *created* for our addresses (those outpoints no longer exist on the
   * active chain) and roll back the per-block confirmation increment. We do
   * NOT attempt to restore coins this block *spent*, because the wallet retains
   * no undo data for the prior coin amounts; that rare case is reconcilable via
   * a future rescan. Symmetric to `processBlock`'s credit half.
   *
   * Reference: bitcoin-core/src/wallet/wallet.cpp CWallet::blockDisconnected.
   */
  disconnectBlock(block: Block): void {
    // Remove outputs this block created that we had credited.
    for (const tx of block.transactions) {
      const txid = getTxId(tx);
      const txidHex = txid.toString("hex");
      for (let vout = 0; vout < tx.outputs.length; vout++) {
        const outpointKey = `${txidHex}:${vout}`;
        if (this.utxos.has(outpointKey)) {
          this.utxos.delete(outpointKey);
        }
      }
      // An outgoing tx that was confirmed in this block is unconfirmed again.
      const out = this.outgoingTxs.get(txidHex);
      if (out) {
        out.confirmed = false;
      }
    }

    // Roll back the per-block confirmation increment applied in processBlock.
    for (const utxo of this.utxos.values()) {
      if (utxo.confirmations > 0) {
        utxo.confirmations--;
      }
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
      if (utxo.isCoinbase && utxo.confirmations < COINBASE_SPENDABLE_DEPTH) {
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
    if (utxo.isCoinbase && utxo.confirmations < COINBASE_SPENDABLE_DEPTH) {
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
  /**
   * BIP-39 mnemonic to deterministically restore an existing wallet's keys.
   * When omitted, a fresh random 64-byte seed is generated (Core default).
   * When supplied, the same mnemonic always re-derives byte-identical
   * addresses — this is hotbuns' seed-only wallet-recovery path.
   */
  mnemonic?: string;
  /** Optional BIP-39 "25th word" passphrase paired with `mnemonic`. */
  mnemonicPassphrase?: string;
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

    // Seed-only restore: when a BIP-39 mnemonic is supplied, derive the seed
    // deterministically so the SAME mnemonic re-creates byte-identical keys
    // (wallet recovery after disk loss). Otherwise generate a random seed.
    const wallet = options.mnemonic
      ? Wallet.create(config, options.mnemonic, options.mnemonicPassphrase ?? "")
      : Wallet.create(config);

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

  /**
   * Reverse a disconnected block's wallet-ledger effects across all loaded
   * wallets (reorg). Mirrors `processBlock` on the disconnect side.
   */
  disconnectBlock(block: Block): void {
    for (const wallet of this.wallets.values()) {
      wallet.disconnectBlock(block);
    }
  }
}
