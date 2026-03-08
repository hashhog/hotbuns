/**
 * HD Wallet: BIP-32/BIP-44/BIP-84 key derivation, address generation,
 * UTXO tracking, and transaction creation/signing.
 *
 * Supports P2WPKH (native segwit) addresses using BIP-84 derivation paths.
 */

import { hmac } from "@noble/hashes/hmac.js";
import { sha512, sha256 } from "@noble/hashes/sha2.js";
import { pbkdf2 } from "@noble/hashes/pbkdf2.js";
import { gcm } from "@noble/ciphers/aes.js";
import { randomBytes } from "@noble/ciphers/utils.js";

import {
  hash160,
  privateKeyToPublicKey,
  ecdsaSign,
} from "../crypto/primitives.js";
import {
  AddressType,
  decodeAddress,
  pubkeyToP2WPKH,
  bech32Encode,
  encodeAddress,
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
} from "../validation/tx.js";
import type { Block } from "../validation/block.js";

// BIP-32 constants
const HARDENED_OFFSET = 0x80000000;

// secp256k1 curve order (n)
const CURVE_ORDER = BigInt(
  "0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"
);

export interface WalletConfig {
  datadir: string;
  network: "mainnet" | "testnet" | "regtest";
}

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
  nextReceiveIndex: number;
  nextChangeIndex: number;
  utxos: SerializedUTXO[];
}

interface SerializedUTXO {
  txid: string;
  vout: number;
  amount: string;
  address: string;
  keyPath: string;
  confirmations: number;
}

/**
 * HD Wallet implementing BIP-32/BIP-84.
 */
export class Wallet {
  private seed: Buffer;
  private masterKey: { key: Buffer; chainCode: Buffer };
  private keys: Map<string, WalletKey>; // address -> key info
  private utxos: Map<string, WalletUTXO>; // outpoint string -> utxo
  private config: WalletConfig;
  private nextReceiveIndex: number;
  private nextChangeIndex: number;

  // Pre-generated address gap
  private readonly ADDRESS_GAP = 20;

  constructor(config: WalletConfig) {
    this.config = config;
    this.keys = new Map();
    this.utxos = new Map();
    this.nextReceiveIndex = 0;
    this.nextChangeIndex = 0;
    this.seed = Buffer.alloc(0);
    this.masterKey = { key: Buffer.alloc(0), chainCode: Buffer.alloc(0) };
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

    // Pre-generate addresses
    wallet.pregenerateAddresses();

    return wallet;
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
    wallet.nextReceiveIndex = data.nextReceiveIndex;
    wallet.nextChangeIndex = data.nextChangeIndex;

    // Restore UTXOs
    for (const utxo of data.utxos) {
      const key = `${utxo.txid}:${utxo.vout}`;
      wallet.utxos.set(key, {
        outpoint: {
          txid: Buffer.from(utxo.txid, "hex"),
          vout: utxo.vout,
        },
        amount: BigInt(utxo.amount),
        address: utxo.address,
        keyPath: utxo.keyPath,
        confirmations: utxo.confirmations,
      });
    }

    // Regenerate keys
    wallet.pregenerateAddresses();

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
      });
    }

    const data: WalletData = {
      seed: this.seed.toString("hex"),
      nextReceiveIndex: this.nextReceiveIndex,
      nextChangeIndex: this.nextChangeIndex,
      utxos,
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
   * Derive a key at a specific BIP-44/BIP-84 path.
   * Path format: "m/84'/0'/0'/0/0"
   */
  private deriveKey(path: string): WalletKey {
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
    const address = pubkeyToP2WPKH(publicKey, this.config.network);

    return {
      privateKey,
      publicKey,
      address,
      path,
      addressType: AddressType.P2WPKH,
    };
  }

  /**
   * Pre-generate addresses for both receive and change chains.
   * Maintains a gap of ADDRESS_GAP addresses ahead of the last used.
   */
  private pregenerateAddresses(): void {
    // Generate receive addresses
    const receiveTarget = this.nextReceiveIndex + this.ADDRESS_GAP;
    for (let i = 0; i < receiveTarget; i++) {
      const path = this.getReceivePath(i);
      if (!this.hasKeyForPath(path)) {
        const key = this.deriveKey(path);
        this.keys.set(key.address, key);
      }
    }

    // Generate change addresses
    const changeTarget = this.nextChangeIndex + this.ADDRESS_GAP;
    for (let i = 0; i < changeTarget; i++) {
      const path = this.getChangePath(i);
      if (!this.hasKeyForPath(path)) {
        const key = this.deriveKey(path);
        this.keys.set(key.address, key);
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
   * Get BIP-84 receive path for index.
   * m/84'/coin'/account'/0/index
   */
  private getReceivePath(index: number): string {
    const coinType = this.config.network === "mainnet" ? 0 : 1;
    return `m/84'/${coinType}'/0'/0/${index}`;
  }

  /**
   * Get BIP-84 change path for index.
   * m/84'/coin'/account'/1/index
   */
  private getChangePath(index: number): string {
    const coinType = this.config.network === "mainnet" ? 0 : 1;
    return `m/84'/${coinType}'/0'/1/${index}`;
  }

  /**
   * Generate the next receive address (BIP-84 P2WPKH).
   */
  getNewAddress(): string {
    const path = this.getReceivePath(this.nextReceiveIndex);
    const key = this.deriveKey(path);
    this.keys.set(key.address, key);
    this.nextReceiveIndex++;

    // Ensure gap is maintained
    this.pregenerateAddresses();

    return key.address;
  }

  /**
   * Generate a change address.
   */
  getChangeAddress(): string {
    const path = this.getChangePath(this.nextChangeIndex);
    const key = this.deriveKey(path);
    this.keys.set(key.address, key);
    this.nextChangeIndex++;

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
   * Sign a transaction input using BIP-143 sighash for P2WPKH.
   */
  private signInput(
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
    tx.inputs[inputIndex].witness = [sigWithType, key.publicKey];
  }

  /**
   * Select UTXOs for a target amount using "largest first" strategy.
   * Selects UTXOs by descending value until target + estimated fee is covered.
   */
  private selectCoins(target: bigint, feeRate: number): WalletUTXO[] {
    // Get all available UTXOs (confirmed only for safety)
    const available: WalletUTXO[] = [];
    for (const utxo of this.utxos.values()) {
      if (utxo.confirmations >= 1) {
        available.push(utxo);
      }
    }

    // Sort by amount descending (largest first)
    available.sort((a, b) => {
      if (b.amount > a.amount) return 1;
      if (b.amount < a.amount) return -1;
      return 0;
    });

    const selected: WalletUTXO[] = [];
    let totalSelected = 0n;

    for (const utxo of available) {
      selected.push(utxo);
      totalSelected += utxo.amount;

      // Estimate fee with current selection
      // P2WPKH vsize estimate: 10 + 68*inputs + 31*outputs
      const estimatedVSize = 10 + 68 * selected.length + 31 * 2; // 2 outputs (payment + change)
      const estimatedFee = BigInt(Math.ceil(estimatedVSize * feeRate));

      if (totalSelected >= target + estimatedFee) {
        return selected;
      }
    }

    // Not enough funds
    throw new Error(
      `Insufficient funds: need ${target}, only have ${totalSelected}`
    );
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
    // Get our addresses
    const ourAddresses = new Set<string>();
    const addressToPath = new Map<string, string>();

    for (const key of this.keys.values()) {
      ourAddresses.add(key.address);
      addressToPath.set(key.address, key.path);
    }

    // Process each transaction
    for (const tx of block.transactions) {
      const txid = getTxId(tx);

      // Check outputs for incoming payments
      for (let vout = 0; vout < tx.outputs.length; vout++) {
        const output = tx.outputs[vout];
        const address = this.scriptPubKeyToAddress(output.scriptPubKey);

        if (address && ourAddresses.has(address)) {
          const outpointKey = `${txid.toString("hex")}:${vout}`;
          const keyPath = addressToPath.get(address) ?? "";

          this.utxos.set(outpointKey, {
            outpoint: { txid, vout },
            amount: output.value,
            address,
            keyPath,
            confirmations: 1,
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
   * Convert a scriptPubKey to an address.
   */
  private scriptPubKeyToAddress(scriptPubKey: Buffer): string | null {
    // P2WPKH: OP_0 <20-byte hash>
    if (
      scriptPubKey.length === 22 &&
      scriptPubKey[0] === 0x00 &&
      scriptPubKey[1] === 0x14
    ) {
      const pubKeyHash = scriptPubKey.subarray(2);
      return encodeAddress({
        type: AddressType.P2WPKH,
        hash: pubKeyHash,
        network: this.config.network,
      });
    }

    // P2WSH: OP_0 <32-byte hash>
    if (
      scriptPubKey.length === 34 &&
      scriptPubKey[0] === 0x00 &&
      scriptPubKey[1] === 0x20
    ) {
      const scriptHash = scriptPubKey.subarray(2);
      return encodeAddress({
        type: AddressType.P2WSH,
        hash: scriptHash,
        network: this.config.network,
      });
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
      return encodeAddress({
        type: AddressType.P2PKH,
        hash: pubKeyHash,
        network: this.config.network,
      });
    }

    // For now, only handle P2WPKH, P2WSH, P2PKH
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
    return this.seed;
  }
}
