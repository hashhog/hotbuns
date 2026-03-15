/**
 * ChaCha20 and FSChaCha20 (forward-secure ChaCha20) for BIP324.
 *
 * ChaCha20 is a 256-bit stream cipher used for length encryption.
 * FSChaCha20 wraps it with automatic rekeying for forward secrecy.
 *
 * Reference: Bitcoin Core src/crypto/chacha20.h, chacha20.cpp
 */

import { chacha20 } from "@noble/ciphers/chacha.js";

/** ChaCha20 key length in bytes */
export const CHACHA20_KEY_LEN = 32;

/** ChaCha20 nonce length in bytes */
export const CHACHA20_NONCE_LEN = 12;

/** ChaCha20 block size in bytes */
export const CHACHA20_BLOCK_LEN = 64;

/** Default rekey interval for BIP324 */
export const REKEY_INTERVAL = 224;

/**
 * ChaCha20 stream cipher.
 *
 * Provides encryption/decryption (XOR with keystream) for arbitrary-length data.
 */
export class ChaCha20 {
  private key: Uint8Array;

  constructor(key: Buffer) {
    if (key.length !== CHACHA20_KEY_LEN) {
      throw new Error(`Invalid ChaCha20 key length: ${key.length}`);
    }
    this.key = new Uint8Array(key);
  }

  /**
   * Set a new key.
   */
  setKey(key: Buffer): void {
    if (key.length !== CHACHA20_KEY_LEN) {
      throw new Error(`Invalid ChaCha20 key length: ${key.length}`);
    }
    this.key = new Uint8Array(key);
  }

  /**
   * Encrypt/decrypt data using ChaCha20.
   *
   * @param nonce - 96-bit nonce as [uint32, uint64]
   * @param blockCounter - Starting block counter
   * @param input - Data to encrypt/decrypt
   * @returns Encrypted/decrypted output
   */
  crypt(nonce: [number, bigint], blockCounter: number, input: Buffer): Buffer {
    // Construct the 12-byte nonce
    // Format: nonce[0] (4 bytes LE) || nonce[1] (8 bytes LE)
    const nonceBuf = Buffer.alloc(CHACHA20_NONCE_LEN);
    nonceBuf.writeUInt32LE(nonce[0], 0);
    nonceBuf.writeBigUInt64LE(nonce[1], 4);

    // Use @noble/ciphers chacha20: (key, nonce, data, output?, counter?)
    const output = chacha20(this.key, nonceBuf, input, undefined, blockCounter);
    return Buffer.from(output);
  }

  /**
   * Generate keystream bytes.
   *
   * @param nonce - 96-bit nonce
   * @param length - Number of keystream bytes to generate
   * @returns Keystream bytes
   */
  keystream(nonce: [number, bigint], length: number): Buffer {
    const zeros = Buffer.alloc(length, 0);
    return this.crypt(nonce, 0, zeros);
  }
}

/**
 * Forward-secure ChaCha20.
 *
 * Uses a continuous keystream and rekeys after a fixed number of operations.
 * Unlike the basic ChaCha20, this maintains buffered keystream bytes between
 * calls for short messages.
 *
 * Reference: Bitcoin Core FSChaCha20
 */
export class FSChaCha20 {
  private key: Uint8Array;
  private readonly rekeyInterval: number;
  private chunkCounter: number;
  private rekeyCounter: bigint;
  // Buffered keystream for reusing partial blocks
  private keystreamBuffer: Buffer;
  private bufferLeft: number;
  // Current position in keystream (block counter * 64 + offset)
  private blockCounter: number;

  constructor(key: Buffer, rekeyInterval: number = REKEY_INTERVAL) {
    if (key.length !== CHACHA20_KEY_LEN) {
      throw new Error(`Invalid ChaCha20 key length: ${key.length}`);
    }
    this.key = new Uint8Array(key);
    this.rekeyInterval = rekeyInterval;
    this.chunkCounter = 0;
    this.rekeyCounter = 0n;
    this.keystreamBuffer = Buffer.alloc(CHACHA20_BLOCK_LEN);
    this.bufferLeft = 0;
    this.blockCounter = 0;
  }

  /**
   * Build the 12-byte nonce for the current state.
   */
  private buildNonce(): Uint8Array {
    // Nonce format: (0, rekeyCounter) for normal operation
    const buf = Buffer.alloc(CHACHA20_NONCE_LEN);
    buf.writeUInt32LE(0, 0); // first 4 bytes
    buf.writeBigUInt64LE(this.rekeyCounter, 4); // last 8 bytes
    return new Uint8Array(buf);
  }

  /**
   * Generate more keystream bytes into the buffer.
   */
  private generateKeystream(): void {
    const nonce = this.buildNonce();
    const zeros = new Uint8Array(CHACHA20_BLOCK_LEN);
    const output = chacha20(this.key, nonce, zeros, undefined, this.blockCounter);
    this.keystreamBuffer = Buffer.from(output);
    this.bufferLeft = CHACHA20_BLOCK_LEN;
    this.blockCounter++;
  }

  /**
   * Encrypt/decrypt a chunk of data.
   *
   * Uses a continuous keystream. Automatically rekeys after rekeyInterval operations.
   *
   * @param input - Data to encrypt/decrypt
   * @returns Encrypted/decrypted output
   */
  crypt(input: Buffer): Buffer {
    const output = Buffer.alloc(input.length);
    let inputOffset = 0;
    let outputOffset = 0;

    // First, use any leftover bytes from the buffer
    if (this.bufferLeft > 0) {
      const reuse = Math.min(this.bufferLeft, input.length);
      const bufferStart = CHACHA20_BLOCK_LEN - this.bufferLeft;
      for (let i = 0; i < reuse; i++) {
        output[outputOffset++] = input[inputOffset++] ^ this.keystreamBuffer[bufferStart + i];
      }
      this.bufferLeft -= reuse;
    }

    // Process remaining input
    while (inputOffset < input.length) {
      this.generateKeystream();
      const remaining = input.length - inputOffset;
      const toProcess = Math.min(remaining, CHACHA20_BLOCK_LEN);

      for (let i = 0; i < toProcess; i++) {
        output[outputOffset++] = input[inputOffset++] ^ this.keystreamBuffer[i];
      }
      this.bufferLeft = CHACHA20_BLOCK_LEN - toProcess;
    }

    // Advance to next chunk and check for rekey
    this.nextChunk();

    return output;
  }

  /**
   * Update counters and rekey if needed.
   */
  private nextChunk(): void {
    this.chunkCounter++;

    if (this.chunkCounter === this.rekeyInterval) {
      // Generate 32 bytes of keystream for the new key
      // Use the current keystream position to get bytes for the new key
      const newKey = Buffer.alloc(CHACHA20_KEY_LEN);
      let offset = 0;

      // Use leftover buffer bytes first
      while (offset < CHACHA20_KEY_LEN && this.bufferLeft > 0) {
        const bufferStart = CHACHA20_BLOCK_LEN - this.bufferLeft;
        const toCopy = Math.min(this.bufferLeft, CHACHA20_KEY_LEN - offset);
        this.keystreamBuffer.copy(newKey, offset, bufferStart, bufferStart + toCopy);
        offset += toCopy;
        this.bufferLeft -= toCopy;
      }

      // Generate more keystream if needed
      while (offset < CHACHA20_KEY_LEN) {
        this.generateKeystream();
        const toCopy = Math.min(CHACHA20_BLOCK_LEN, CHACHA20_KEY_LEN - offset);
        this.keystreamBuffer.copy(newKey, offset, 0, toCopy);
        offset += toCopy;
        this.bufferLeft = CHACHA20_BLOCK_LEN - toCopy;
      }

      // Set the new key
      this.key = new Uint8Array(newKey);

      // Reset counters for new key epoch
      this.chunkCounter = 0;
      this.rekeyCounter++;
      this.blockCounter = 0;
      this.bufferLeft = 0;

      // Clear the new key buffer
      newKey.fill(0);
    }
  }
}
