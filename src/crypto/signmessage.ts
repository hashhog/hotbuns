/**
 * BIP-137 / Bitcoin Core message signing & verification.
 *
 * Mirrors `bitcoin-core/src/common/signmessage.cpp`:
 *
 *   MESSAGE_MAGIC = "Bitcoin Signed Message:\n"
 *   hash = SHA256d(varstr(MESSAGE_MAGIC) || varstr(message))
 *   signature = compact ECDSA signature with recovery id, base64-encoded
 *
 * The compact signature layout (65 bytes) is:
 *
 *   [ header_byte (1) ] [ R (32) ] [ S (32) ]
 *
 * where header_byte = 27 + recovery_id + (compressed ? 4 : 0).
 *
 * Verification recovers the public key from the signature and the message
 * hash, derives the corresponding P2PKH address, and compares it against
 * the address provided by the caller.
 */

import { secp256k1 } from "@noble/curves/secp256k1.js";
import { hash256, hash160, privateKeyToPublicKey } from "./primitives.js";
import { BufferWriter } from "../wire/serialization.js";
import {
  base58CheckDecode,
  base58CheckEncode,
} from "../address/encoding.js";

/**
 * Magic prefix used so `signmessage` can never be confused with a
 * transaction signature. Identical to Bitcoin Core.
 */
export const MESSAGE_MAGIC = "Bitcoin Signed Message:\n";

/**
 * Result of verifying a signed message. Mirrors Bitcoin Core's
 * `MessageVerificationResult` enum so callers can map directly to the
 * Core RPC error codes without translation tables.
 */
export enum MessageVerificationResult {
  OK = "OK",
  ERR_INVALID_ADDRESS = "ERR_INVALID_ADDRESS",
  ERR_ADDRESS_NO_KEY = "ERR_ADDRESS_NO_KEY",
  ERR_MALFORMED_SIGNATURE = "ERR_MALFORMED_SIGNATURE",
  ERR_PUBKEY_NOT_RECOVERED = "ERR_PUBKEY_NOT_RECOVERED",
  ERR_NOT_SIGNED = "ERR_NOT_SIGNED",
}

/** P2PKH version bytes per network (mainnet vs testnet/regtest). */
const P2PKH_VERSIONS = {
  mainnet: 0x00,
  testnet: 0x6f,
  regtest: 0x6f,
} as const;

/**
 * Compute the message hash that is signed: SHA256d(varstr(MAGIC) || varstr(msg)).
 * `varstr(s)` = compactSize(len) || utf8 bytes, matching Bitcoin Core's
 * `HashWriter << s` for `std::string`.
 */
export function messageHash(message: string): Buffer {
  const w = new BufferWriter(64 + message.length);
  w.writeVarString(MESSAGE_MAGIC);
  w.writeVarString(message);
  return hash256(w.toBuffer());
}

/**
 * Sign `message` with the 32-byte `privateKey`. Returns a 65-byte compact
 * signature {header, R, S} encoded as base64. Compatible with Bitcoin
 * Core's `signmessage` / `signmessagewithprivkey`.
 *
 * @param privateKey 32-byte secret key.
 * @param message    Message to sign (UTF-8 string).
 * @param compressed Whether the message is signed against a compressed
 *                   pubkey (default true). The header byte encodes this.
 */
export function messageSign(
  privateKey: Buffer,
  message: string,
  compressed: boolean = true
): string {
  if (privateKey.length !== 32) {
    throw new Error(`messageSign: privateKey must be 32 bytes, got ${privateKey.length}`);
  }

  const h = messageHash(message);
  const sigBytes = secp256k1.sign(h, privateKey, {
    prehash: false,
    format: "recovered",
  });
  // noble v3 'recovered' format is recovery(1) || R(32) || S(32).
  if (sigBytes.length !== 65) {
    throw new Error(`messageSign: unexpected signature length ${sigBytes.length}`);
  }
  const recovery = sigBytes[0];
  const r = sigBytes.subarray(1, 33);
  const s = sigBytes.subarray(33, 65);
  // Bitcoin compact format: header || R || S, with header = 27 + rec + (compressed ? 4 : 0).
  const header = 27 + recovery + (compressed ? 4 : 0);

  const out = Buffer.alloc(65);
  out[0] = header;
  out.set(r, 1);
  out.set(s, 33);
  return out.toString("base64");
}

/**
 * Verify a base64-encoded compact signature against an address and message.
 *
 * Only P2PKH addresses are supported (Core has the same limitation —
 * `MessageVerify` returns `ERR_ADDRESS_NO_KEY` for P2SH/bech32). A future
 * extension to BIP-322 would unblock those.
 *
 * @returns `MessageVerificationResult.OK` on success, otherwise an error code.
 */
export function messageVerify(
  address: string,
  signatureBase64: string,
  message: string
): MessageVerificationResult {
  // Decode address — must be a P2PKH (legacy) Base58Check address.
  let decoded: { version: number; hash: Buffer };
  try {
    decoded = base58CheckDecode(address);
  } catch {
    return MessageVerificationResult.ERR_INVALID_ADDRESS;
  }

  // Reject anything but P2PKH (mainnet / testnet / regtest).
  if (
    decoded.version !== P2PKH_VERSIONS.mainnet &&
    decoded.version !== P2PKH_VERSIONS.testnet
  ) {
    return MessageVerificationResult.ERR_ADDRESS_NO_KEY;
  }
  if (decoded.hash.length !== 20) {
    return MessageVerificationResult.ERR_INVALID_ADDRESS;
  }

  // Decode the base64 signature.
  let sigBytes: Buffer;
  try {
    sigBytes = Buffer.from(signatureBase64, "base64");
  } catch {
    return MessageVerificationResult.ERR_MALFORMED_SIGNATURE;
  }
  if (sigBytes.length !== 65) {
    return MessageVerificationResult.ERR_MALFORMED_SIGNATURE;
  }

  const header = sigBytes[0];
  if (header < 27 || header > 34) {
    return MessageVerificationResult.ERR_MALFORMED_SIGNATURE;
  }
  const compressed = header >= 31;
  const recovery = (header - 27) & 0x03;

  // Build the noble 'recovered' format: rec || R || S.
  const recoveredSig = Buffer.alloc(65);
  recoveredSig[0] = recovery;
  sigBytes.copy(recoveredSig, 1, 1, 65); // R || S

  const h = messageHash(message);

  // Recover the public key. noble's `recoverPublicKey` always parses the
  // signature in 'recovered' format (recovery byte || R || S). The
  // returned key is 33-byte compressed.
  let recoveredPubkey: Uint8Array;
  try {
    recoveredPubkey = secp256k1.recoverPublicKey(recoveredSig, h, {
      prehash: false,
    });
  } catch {
    return MessageVerificationResult.ERR_PUBKEY_NOT_RECOVERED;
  }

  // noble returns a 33-byte compressed pubkey. If the signer claimed an
  // uncompressed key (header < 31) we must HASH160 the uncompressed
  // encoding, otherwise the address-comparison path will never agree
  // with a Core-produced uncompressed signature.
  let pubkeyForAddr: Buffer;
  if (compressed) {
    pubkeyForAddr = Buffer.from(recoveredPubkey);
  } else {
    // Re-encode the recovered point as 65-byte uncompressed (0x04 || X || Y).
    const point = secp256k1.Point.fromBytes(recoveredPubkey);
    pubkeyForAddr = Buffer.from(point.toBytes(false));
  }

  const recoveredHash = hash160(pubkeyForAddr);
  if (!recoveredHash.equals(decoded.hash)) {
    return MessageVerificationResult.ERR_NOT_SIGNED;
  }

  return MessageVerificationResult.OK;
}

/**
 * Convenience: derive the P2PKH address (legacy Base58Check) for a given
 * private key and network. Used by tests and by the wallet path of the
 * `signmessage` RPC.
 */
export function privateKeyToP2PKHAddress(
  privateKey: Buffer,
  network: "mainnet" | "testnet" | "regtest",
  compressed: boolean = true
): string {
  const pubkey = privateKeyToPublicKey(privateKey, compressed);
  const h = hash160(pubkey);
  return base58CheckEncode(P2PKH_VERSIONS[network], h);
}
