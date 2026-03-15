/**
 * HKDF-SHA256 key derivation for BIP324.
 *
 * Implements RFC 5869 HKDF with HMAC-SHA256 and fixed output length of 32 bytes.
 * Reference: Bitcoin Core src/crypto/hkdf_sha256_32.h
 */

import { createHmac } from "crypto";

/**
 * HKDF-SHA256 with L=32 (fixed 32-byte output).
 *
 * This class implements the HKDF extract-then-expand paradigm from RFC 5869,
 * specialized for BIP324's needs.
 */
export class HKDF_SHA256_L32 {
  private readonly prk: Buffer;
  private static readonly OUTPUT_SIZE = 32;

  /**
   * Create an HKDF instance.
   *
   * Extract phase: PRK = HMAC-SHA256(salt, IKM)
   *
   * @param ikm - Input keying material
   * @param salt - Salt value as Buffer (for BIP324: "bitcoin_v2_shared_secret" + network magic bytes)
   */
  constructor(ikm: Buffer, salt: Buffer) {
    // HKDF-Extract: PRK = HMAC-SHA256(salt, IKM)
    const hmac = createHmac("sha256", salt);
    hmac.update(ikm);
    this.prk = hmac.digest();
  }

  /**
   * Expand the PRK to derive a 32-byte key.
   *
   * Expand phase: OKM = HMAC-SHA256(PRK, info || 0x01)
   *
   * Since L=32 and HMAC-SHA256 outputs 32 bytes, we only need one round.
   *
   * @param info - Application-specific info string
   * @returns 32-byte output keying material
   */
  expand32(info: string): Buffer {
    // For L=32 (single block), output = HMAC(PRK, info || 0x01)
    const hmac = createHmac("sha256", this.prk);
    hmac.update(Buffer.from(info, "utf-8"));
    hmac.update(Buffer.from([0x01]));
    return hmac.digest();
  }
}

/**
 * BIP324 key labels for HKDF expansion.
 */
export const BIP324_KEY_LABELS = {
  INITIATOR_L: "initiator_L",
  INITIATOR_P: "initiator_P",
  RESPONDER_L: "responder_L",
  RESPONDER_P: "responder_P",
  GARBAGE_TERMINATORS: "garbage_terminators",
  SESSION_ID: "session_id",
} as const;

/**
 * Derive all BIP324 session keys from the ECDH shared secret.
 *
 * @param ecdhSecret - 32-byte ECDH shared secret
 * @param networkMagic - 4-byte network magic
 * @param initiator - Whether we are the connection initiator
 * @returns Object containing all derived keys
 */
export function deriveBIP324Keys(
  ecdhSecret: Buffer,
  networkMagic: Buffer,
  initiator: boolean
): BIP324SessionKeys {
  // Salt = "bitcoin_v2_shared_secret" + network magic bytes (as raw bytes)
  const saltString = Buffer.from("bitcoin_v2_shared_secret", "utf-8");
  const salt = Buffer.concat([saltString, networkMagic]);
  const hkdf = new HKDF_SHA256_L32(ecdhSecret, salt);

  // Derive all keys
  const initiatorL = hkdf.expand32(BIP324_KEY_LABELS.INITIATOR_L);
  const initiatorP = hkdf.expand32(BIP324_KEY_LABELS.INITIATOR_P);
  const responderL = hkdf.expand32(BIP324_KEY_LABELS.RESPONDER_L);
  const responderP = hkdf.expand32(BIP324_KEY_LABELS.RESPONDER_P);
  const garbageTerminators = hkdf.expand32(BIP324_KEY_LABELS.GARBAGE_TERMINATORS);
  const sessionId = hkdf.expand32(BIP324_KEY_LABELS.SESSION_ID);

  // Assign send/receive keys based on initiator role
  let sendLKey: Buffer;
  let recvLKey: Buffer;
  let sendPKey: Buffer;
  let recvPKey: Buffer;
  let sendGarbageTerminator: Buffer;
  let recvGarbageTerminator: Buffer;

  if (initiator) {
    sendLKey = initiatorL;
    sendPKey = initiatorP;
    recvLKey = responderL;
    recvPKey = responderP;
    sendGarbageTerminator = garbageTerminators.subarray(0, 16);
    recvGarbageTerminator = garbageTerminators.subarray(16, 32);
  } else {
    sendLKey = responderL;
    sendPKey = responderP;
    recvLKey = initiatorL;
    recvPKey = initiatorP;
    sendGarbageTerminator = garbageTerminators.subarray(16, 32);
    recvGarbageTerminator = garbageTerminators.subarray(0, 16);
  }

  return {
    sendLKey,
    recvLKey,
    sendPKey,
    recvPKey,
    sendGarbageTerminator,
    recvGarbageTerminator,
    sessionId,
  };
}

/**
 * All BIP324 session keys derived from HKDF.
 */
export interface BIP324SessionKeys {
  /** Key for encrypting message lengths (send direction) */
  sendLKey: Buffer;
  /** Key for decrypting message lengths (receive direction) */
  recvLKey: Buffer;
  /** Key for AEAD encryption (send direction) */
  sendPKey: Buffer;
  /** Key for AEAD decryption (receive direction) */
  recvPKey: Buffer;
  /** 16-byte garbage terminator we send */
  sendGarbageTerminator: Buffer;
  /** 16-byte garbage terminator we expect to receive */
  recvGarbageTerminator: Buffer;
  /** 32-byte session identifier */
  sessionId: Buffer;
}
