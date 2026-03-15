/**
 * ChaCha20-Poly1305 AEAD and FSChaCha20Poly1305 for BIP324.
 *
 * Implements RFC 8439 AEAD_CHACHA20_POLY1305 and the forward-secure variant
 * used in BIP324 for packet encryption.
 *
 * Reference: Bitcoin Core src/crypto/chacha20poly1305.h
 */

import { chacha20poly1305 } from "@noble/ciphers/chacha.js";
import { chacha20 } from "@noble/ciphers/chacha.js";
import { CHACHA20_KEY_LEN, CHACHA20_BLOCK_LEN, REKEY_INTERVAL } from "./chacha20.js";

/** Poly1305 authentication tag length in bytes */
export const POLY1305_TAG_LEN = 16;

/** ChaCha20-Poly1305 expansion (just the tag) */
export const AEAD_EXPANSION = POLY1305_TAG_LEN;

/**
 * ChaCha20-Poly1305 AEAD cipher.
 *
 * Provides authenticated encryption with associated data.
 * Reference: RFC 8439 Section 2.8
 */
export class AEADChaCha20Poly1305 {
  private key: Uint8Array;

  constructor(key: Buffer) {
    if (key.length !== CHACHA20_KEY_LEN) {
      throw new Error(`Invalid AEAD key length: ${key.length}`);
    }
    this.key = new Uint8Array(key);
  }

  /**
   * Set a new key.
   */
  setKey(key: Buffer): void {
    if (key.length !== CHACHA20_KEY_LEN) {
      throw new Error(`Invalid AEAD key length: ${key.length}`);
    }
    this.key = new Uint8Array(key);
  }

  /**
   * Encrypt plaintext with AEAD.
   *
   * @param nonce - 96-bit nonce as [uint32, uint64]
   * @param plaintext - Data to encrypt
   * @param aad - Additional authenticated data
   * @returns Ciphertext with 16-byte auth tag appended
   */
  encrypt(nonce: [number, bigint], plaintext: Buffer, aad: Buffer): Buffer {
    const nonceBuf = this.buildNonce(nonce);
    const cipher = chacha20poly1305(this.key, nonceBuf, aad);
    return Buffer.from(cipher.encrypt(plaintext));
  }

  /**
   * Encrypt two plaintext parts with AEAD.
   *
   * Used by BIP324 to encrypt header + contents in one operation.
   *
   * @param nonce - 96-bit nonce
   * @param plain1 - First part of plaintext (header)
   * @param plain2 - Second part of plaintext (contents)
   * @param aad - Additional authenticated data
   * @returns Ciphertext with auth tag
   */
  encryptSplit(
    nonce: [number, bigint],
    plain1: Buffer,
    plain2: Buffer,
    aad: Buffer
  ): Buffer {
    const combined = Buffer.concat([plain1, plain2]);
    return this.encrypt(nonce, combined, aad);
  }

  /**
   * Decrypt ciphertext with AEAD.
   *
   * @param nonce - 96-bit nonce
   * @param ciphertext - Encrypted data with auth tag
   * @param aad - Additional authenticated data
   * @returns Plaintext or null if authentication fails
   */
  decrypt(nonce: [number, bigint], ciphertext: Buffer, aad: Buffer): Buffer | null {
    if (ciphertext.length < POLY1305_TAG_LEN) {
      return null;
    }

    const nonceBuf = this.buildNonce(nonce);
    const cipher = chacha20poly1305(this.key, nonceBuf, aad);

    try {
      return Buffer.from(cipher.decrypt(ciphertext));
    } catch {
      // Authentication failed
      return null;
    }
  }

  /**
   * Decrypt ciphertext and split the result.
   *
   * @param nonce - 96-bit nonce
   * @param ciphertext - Encrypted data with auth tag
   * @param aad - Additional authenticated data
   * @param split - Number of bytes in first part
   * @returns [plain1, plain2] or null if authentication fails
   */
  decryptSplit(
    nonce: [number, bigint],
    ciphertext: Buffer,
    aad: Buffer,
    split: number
  ): [Buffer, Buffer] | null {
    const plaintext = this.decrypt(nonce, ciphertext, aad);
    if (plaintext === null) {
      return null;
    }

    return [plaintext.subarray(0, split), plaintext.subarray(split)];
  }

  /**
   * Generate keystream bytes (for rekeying).
   *
   * Skips block 0 (which is used for Poly1305 key derivation in AEAD)
   * and starts from block 1.
   *
   * @param nonce - 96-bit nonce
   * @param length - Number of bytes to generate
   * @returns Keystream bytes
   */
  keystream(nonce: [number, bigint], length: number): Buffer {
    const nonceBuf = this.buildNonce(nonce);
    const zeros = new Uint8Array(length);
    // Start at block 1, not 0 - block 0 is reserved for Poly1305 key in AEAD
    const output = chacha20(this.key, nonceBuf, zeros, undefined, 1);
    return Buffer.from(output);
  }

  /**
   * Build a 12-byte nonce from the structured format.
   */
  private buildNonce(nonce: [number, bigint]): Uint8Array {
    const buf = Buffer.alloc(12);
    buf.writeUInt32LE(nonce[0], 0);
    buf.writeBigUInt64LE(nonce[1], 4);
    return new Uint8Array(buf);
  }
}

/**
 * Forward-secure ChaCha20-Poly1305 AEAD.
 *
 * Automatically increments nonce on every encryption/decryption
 * and rekeys after a fixed number of operations.
 *
 * Reference: Bitcoin Core FSChaCha20Poly1305
 */
export class FSChaCha20Poly1305 {
  private aead: AEADChaCha20Poly1305;
  private readonly rekeyInterval: number;
  private packetCounter: number;
  private rekeyCounter: bigint;

  /** Expansion when encrypting (16-byte tag) */
  static readonly EXPANSION = POLY1305_TAG_LEN;

  constructor(key: Buffer, rekeyInterval: number = REKEY_INTERVAL) {
    this.aead = new AEADChaCha20Poly1305(key);
    this.rekeyInterval = rekeyInterval;
    this.packetCounter = 0;
    this.rekeyCounter = 0n;
  }

  /**
   * Encrypt plaintext with AEAD.
   *
   * @param plaintext - Data to encrypt
   * @param aad - Additional authenticated data
   * @returns Ciphertext with auth tag
   */
  encrypt(plaintext: Buffer, aad: Buffer): Buffer {
    const nonce: [number, bigint] = [this.packetCounter, this.rekeyCounter];
    const ciphertext = this.aead.encrypt(nonce, plaintext, aad);
    this.nextPacket();
    return ciphertext;
  }

  /**
   * Encrypt header and contents with AEAD.
   *
   * @param header - Header byte(s)
   * @param contents - Message contents
   * @param aad - Additional authenticated data
   * @returns Ciphertext with auth tag
   */
  encryptSplit(header: Buffer, contents: Buffer, aad: Buffer): Buffer {
    const nonce: [number, bigint] = [this.packetCounter, this.rekeyCounter];
    const ciphertext = this.aead.encryptSplit(nonce, header, contents, aad);
    this.nextPacket();
    return ciphertext;
  }

  /**
   * Decrypt ciphertext with AEAD.
   *
   * @param ciphertext - Encrypted data with auth tag
   * @param aad - Additional authenticated data
   * @returns Plaintext or null if authentication fails
   */
  decrypt(ciphertext: Buffer, aad: Buffer): Buffer | null {
    const nonce: [number, bigint] = [this.packetCounter, this.rekeyCounter];
    const plaintext = this.aead.decrypt(nonce, ciphertext, aad);
    if (plaintext !== null) {
      this.nextPacket();
    }
    return plaintext;
  }

  /**
   * Decrypt ciphertext and split into header + contents.
   *
   * @param ciphertext - Encrypted data with auth tag
   * @param aad - Additional authenticated data
   * @returns [header, contents] or null if authentication fails
   */
  decryptSplit(ciphertext: Buffer, aad: Buffer): [Buffer, Buffer] | null {
    const nonce: [number, bigint] = [this.packetCounter, this.rekeyCounter];
    const result = this.aead.decryptSplit(nonce, ciphertext, aad, 1);
    if (result !== null) {
      this.nextPacket();
    }
    return result;
  }

  /**
   * Update counters and rekey if needed.
   */
  private nextPacket(): void {
    this.packetCounter++;

    if (this.packetCounter === this.rekeyInterval) {
      // Generate keystream for rekeying using sentinel nonce
      const rekeyNonce: [number, bigint] = [0xffffffff, this.rekeyCounter];
      const keystream = this.aead.keystream(rekeyNonce, CHACHA20_BLOCK_LEN);

      // Use first 32 bytes as new key
      const newKey = keystream.subarray(0, CHACHA20_KEY_LEN);
      this.aead.setKey(newKey);

      // Reset packet counter and increment rekey counter
      this.packetCounter = 0;
      this.rekeyCounter++;

      // Clear keystream from memory
      keystream.fill(0);
    }
  }
}
