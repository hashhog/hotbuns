/**
 * BIP324 packet cipher.
 *
 * Encapsulates key derivation, stream cipher for length encryption,
 * and AEAD for packet encryption/decryption.
 *
 * Reference: Bitcoin Core src/bip324.h, bip324.cpp
 */

import { randomBytes, createHash } from "crypto";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { FSChaCha20 } from "./chacha20.js";
import { FSChaCha20Poly1305, POLY1305_TAG_LEN } from "./chacha20poly1305.js";
import { deriveBIP324Keys, type BIP324SessionKeys } from "./hkdf.js";
import {
  EllSwiftPubKey,
  ellswiftCreate,
  ellswiftECDH,
  ELLSWIFT_PUBLIC_KEY_SIZE,
} from "./elligator_swift.js";

/** Session ID length in bytes */
export const SESSION_ID_LEN = 32;

/** Garbage terminator length in bytes */
export const GARBAGE_TERMINATOR_LEN = 16;

/** Default rekey interval */
export const REKEY_INTERVAL = 224;

/** Length field size in bytes */
export const LENGTH_LEN = 3;

/** Header byte size */
export const HEADER_LEN = 1;

/** Total expansion when encrypting: length + header + poly1305 tag */
export const EXPANSION = LENGTH_LEN + HEADER_LEN + POLY1305_TAG_LEN;

/** Maximum garbage length (2^12 - 1 = 4095 bytes) */
export const MAX_GARBAGE_LEN = 4095;

/** Ignore bit in header byte */
export const IGNORE_BIT = 0x80;

/**
 * BIP324 packet cipher.
 *
 * Provides encryption and decryption of BIP324 v2 transport packets.
 */
export class BIP324Cipher {
  private privateKey: Buffer;
  private ourPubKey: EllSwiftPubKey;
  private sendLCipher: FSChaCha20 | null = null;
  private recvLCipher: FSChaCha20 | null = null;
  private sendPCipher: FSChaCha20Poly1305 | null = null;
  private recvPCipher: FSChaCha20Poly1305 | null = null;
  private _sessionId: Buffer | null = null;
  private _sendGarbageTerminator: Buffer | null = null;
  private _recvGarbageTerminator: Buffer | null = null;
  private networkMagic: Buffer;

  /**
   * Create a BIP324 cipher with a new random key.
   *
   * @param networkMagic - 4-byte network magic
   */
  constructor(networkMagic: Buffer) {
    if (networkMagic.length !== 4) {
      throw new Error(`Invalid network magic length: ${networkMagic.length}`);
    }
    this.networkMagic = networkMagic;

    // Generate a new random private key
    this.privateKey = randomBytes(32);

    // Ensure it's a valid secp256k1 scalar
    while (!secp256k1.utils.isValidSecretKey(this.privateKey)) {
      this.privateKey = randomBytes(32);
    }

    // Generate ElligatorSwift encoding with random entropy
    const entropy = randomBytes(32);
    this.ourPubKey = EllSwiftPubKey.create(this.privateKey, entropy);
  }

  /**
   * Create a BIP324 cipher with specified key and entropy (for testing).
   *
   * @param privateKey - 32-byte private key
   * @param entropy - 32-byte entropy for ElligatorSwift encoding
   * @param networkMagic - 4-byte network magic
   */
  static withKey(privateKey: Buffer, entropy: Buffer, networkMagic: Buffer): BIP324Cipher {
    const cipher = Object.create(BIP324Cipher.prototype) as BIP324Cipher;
    cipher.networkMagic = networkMagic;
    cipher.privateKey = privateKey;
    cipher.ourPubKey = EllSwiftPubKey.create(privateKey, entropy);
    return cipher;
  }

  /**
   * Create a BIP324 cipher with specified key and pre-computed public key (for testing).
   *
   * @param privateKey - 32-byte private key
   * @param pubKey - Pre-computed ElligatorSwift public key
   * @param networkMagic - 4-byte network magic
   */
  static withPubKey(
    privateKey: Buffer,
    pubKey: EllSwiftPubKey,
    networkMagic: Buffer
  ): BIP324Cipher {
    const cipher = Object.create(BIP324Cipher.prototype) as BIP324Cipher;
    cipher.networkMagic = networkMagic;
    cipher.privateKey = privateKey;
    cipher.ourPubKey = pubKey;
    return cipher;
  }

  /**
   * Get our ElligatorSwift-encoded public key.
   */
  getOurPubKey(): EllSwiftPubKey {
    return this.ourPubKey;
  }

  /**
   * Check if the cipher is initialized.
   */
  isInitialized(): boolean {
    return this.sendLCipher !== null;
  }

  /**
   * Initialize the cipher after receiving the other party's public key.
   *
   * Performs ECDH key exchange and derives all session keys.
   *
   * @param theirPubKey - Other party's ElligatorSwift-encoded public key
   * @param initiator - Whether we are the connection initiator
   * @param selfDecrypt - For testing: swap send/recv keys to decrypt our own messages
   */
  initialize(
    theirPubKey: EllSwiftPubKey,
    initiator: boolean,
    selfDecrypt: boolean = false
  ): void {
    // Perform ECDH to compute shared secret
    const ecdhSecret = this.computeECDHSecret(theirPubKey, initiator);

    // Derive all session keys - deriveBIP324Keys handles send/recv based on initiator
    // For selfDecrypt mode (testing), we swap send/recv to decrypt our own messages
    const deriveSide = initiator !== selfDecrypt;
    const keys = deriveBIP324Keys(ecdhSecret, this.networkMagic, deriveSide);

    // Initialize ciphers with derived keys
    // deriveBIP324Keys already assigns send/recv keys based on initiator role
    if (selfDecrypt) {
      // Self-decrypt mode: swap send/recv to decrypt our own messages
      this.sendLCipher = new FSChaCha20(keys.recvLKey);
      this.sendPCipher = new FSChaCha20Poly1305(keys.recvPKey);
      this.recvLCipher = new FSChaCha20(keys.sendLKey);
      this.recvPCipher = new FSChaCha20Poly1305(keys.sendPKey);
    } else {
      // Normal mode: use keys as derived
      this.sendLCipher = new FSChaCha20(keys.sendLKey);
      this.sendPCipher = new FSChaCha20Poly1305(keys.sendPKey);
      this.recvLCipher = new FSChaCha20(keys.recvLKey);
      this.recvPCipher = new FSChaCha20Poly1305(keys.recvPKey);
    }

    // Store garbage terminators (already assigned correctly by deriveBIP324Keys based on initiator role)
    this._sendGarbageTerminator = keys.sendGarbageTerminator;
    this._recvGarbageTerminator = keys.recvGarbageTerminator;

    this._sessionId = keys.sessionId;

    // Clear sensitive data
    ecdhSecret.fill(0);
    this.privateKey.fill(0);
  }

  /**
   * Compute ECDH shared secret.
   */
  private computeECDHSecret(theirPubKey: EllSwiftPubKey, initiator: boolean): Buffer {
    return ellswiftECDH(
      this.privateKey,
      theirPubKey.data,
      this.ourPubKey.data,
      initiator
    );
  }

  /**
   * Encrypt a packet.
   *
   * @param contents - Message contents
   * @param aad - Additional authenticated data (garbage for first packet, empty otherwise)
   * @param ignore - Whether to set the IGNORE bit
   * @returns Encrypted packet (length + ciphertext with tag)
   */
  encrypt(contents: Buffer, aad: Buffer, ignore: boolean): Buffer {
    if (!this.isInitialized()) {
      throw new Error("Cipher not initialized");
    }

    const output = Buffer.alloc(contents.length + EXPANSION);

    // Encrypt length (3 bytes, little-endian)
    const lenBytes = Buffer.alloc(LENGTH_LEN);
    lenBytes[0] = contents.length & 0xff;
    lenBytes[1] = (contents.length >> 8) & 0xff;
    lenBytes[2] = (contents.length >> 16) & 0xff;
    const encryptedLen = this.sendLCipher!.crypt(lenBytes);
    encryptedLen.copy(output, 0);

    // Create header byte
    const header = Buffer.alloc(HEADER_LEN);
    header[0] = ignore ? IGNORE_BIT : 0;

    // Encrypt header + contents with AEAD
    const ciphertext = this.sendPCipher!.encryptSplit(header, contents, aad);
    ciphertext.copy(output, LENGTH_LEN);

    return output;
  }

  /**
   * Decrypt the length field of a packet.
   *
   * @param input - 3 bytes of encrypted length
   * @returns Decrypted length value
   */
  decryptLength(input: Buffer): number {
    if (!this.isInitialized()) {
      throw new Error("Cipher not initialized");
    }
    if (input.length !== LENGTH_LEN) {
      throw new Error(`Invalid length field size: ${input.length}`);
    }

    const decrypted = this.recvLCipher!.crypt(input);
    return decrypted[0] | (decrypted[1] << 8) | (decrypted[2] << 16);
  }

  /**
   * Decrypt a packet (after length has been decrypted).
   *
   * @param input - Encrypted payload (header + contents + tag)
   * @param aad - Additional authenticated data
   * @returns { ignore, contents } or null if authentication fails
   */
  decrypt(
    input: Buffer,
    aad: Buffer
  ): { ignore: boolean; contents: Buffer } | null {
    if (!this.isInitialized()) {
      throw new Error("Cipher not initialized");
    }

    const result = this.recvPCipher!.decryptSplit(input, aad);
    if (result === null) {
      return null;
    }

    const [header, contents] = result;
    const ignore = (header[0] & IGNORE_BIT) === IGNORE_BIT;

    return { ignore, contents };
  }

  /**
   * Get the session ID (only after initialization).
   */
  get sessionId(): Buffer {
    if (!this._sessionId) {
      throw new Error("Cipher not initialized");
    }
    return this._sessionId;
  }

  /**
   * Get the garbage terminator to send (only after initialization).
   */
  get sendGarbageTerminator(): Buffer {
    if (!this._sendGarbageTerminator) {
      throw new Error("Cipher not initialized");
    }
    return this._sendGarbageTerminator;
  }

  /**
   * Get the expected garbage terminator to receive (only after initialization).
   */
  get recvGarbageTerminator(): Buffer {
    if (!this._recvGarbageTerminator) {
      throw new Error("Cipher not initialized");
    }
    return this._recvGarbageTerminator;
  }
}

/**
 * Generate random garbage data for BIP324 handshake.
 *
 * @param maxLen - Maximum length (default: MAX_GARBAGE_LEN)
 * @returns Random garbage bytes (0 to maxLen bytes)
 */
export function generateGarbage(maxLen: number = MAX_GARBAGE_LEN): Buffer {
  const len = Math.floor(Math.random() * (maxLen + 1));
  return randomBytes(len);
}
