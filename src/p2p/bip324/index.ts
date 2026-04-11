/**
 * BIP324 v2 transport module.
 *
 * Provides encrypted and authenticated P2P communication using:
 * - ElligatorSwift key exchange
 * - ChaCha20-Poly1305 AEAD
 * - Forward secrecy through automatic rekeying
 */

export * from "./elligator_swift.js";
export * from "./hkdf.js";
// Export chacha20 symbols except REKEY_INTERVAL which is also defined in cipher.ts
export {
  CHACHA20_KEY_LEN,
  CHACHA20_NONCE_LEN,
  CHACHA20_BLOCK_LEN,
  ChaCha20,
  FSChaCha20,
} from "./chacha20.js";
export * from "./chacha20poly1305.js";
export * from "./cipher.js";
export * from "./message_ids.js";
