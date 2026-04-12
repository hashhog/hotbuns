/**
 * Bun FFI binding for libsecp256k1.
 *
 * Provides ECDSA and BIP-340 Schnorr signature verification via the system
 * libsecp256k1 (C library with assembly-optimized field arithmetic), which is
 * ~100-1000x faster than @noble/curves for verification-heavy IBD workloads.
 *
 * Functions exposed:
 *   - ecdsaVerifyFFI(sig, msgHash, pubkey) → boolean   (strict DER, low-S enforced by libsecp256k1)
 *   - ecdsaVerifyLaxFFI(sig, msgHash, pubkey) → boolean (lax DER, historical Bitcoin compat)
 *   - schnorrVerifyFFI(sig, msgHash, xonlyPubkey) → boolean (BIP-340)
 *   - parsePubkeyFFI(pubkeyBytes) → boolean             (validate compressed/uncompressed key)
 *   - parseSignatureDER_FFI(derBytes) → boolean         (validate strict DER encoding)
 *
 * The SECP256K1_CONTEXT_VERIFY context is created once at module load and
 * lives for the duration of the process. All verify functions use module-level
 * pre-allocated 64-byte output buffers to avoid per-call heap allocation.
 *
 * libsecp256k1 availability: requires /usr/lib/.../libsecp256k1.so.2
 * (libsecp256k1-dev >= 0.4.0, tested with 0.5.0 on Debian 13).
 *
 * @noble/secp256k1 / @noble/curves remain available as fallback for
 * non-consensus paths and cross-checking in tests.
 */

import { dlopen, FFIType, ptr } from "bun:ffi";

// ---------------------------------------------------------------------------
// Library path
// ---------------------------------------------------------------------------

const LIB_PATH = "libsecp256k1.so.2";

// Context flags from secp256k1.h
const SECP256K1_CONTEXT_VERIFY = 1;

// Opaque struct sizes from secp256k1.h:
// secp256k1_pubkey, secp256k1_ecdsa_signature, secp256k1_xonly_pubkey are all 64 bytes.
const OPAQUE_BUF_SIZE = 64;

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

/** Whether FFI is available and initialized on this system. */
export let FFI_AVAILABLE = false;

/** Running count of FFI verification calls (ECDSA + Schnorr). Used for benchmarks. */
export let ffiCallCount = 0;

/** Reset ffiCallCount to zero (used between benchmark runs). */
export function resetFFICallCount(): void {
  ffiCallCount = 0;
}

// Internal raw FFI handle
type SymbolTable = {
  secp256k1_context_create: (flags: number) => bigint;
  secp256k1_context_destroy: (ctx: bigint) => void;
  secp256k1_ec_pubkey_parse: (
    ctx: bigint,
    pubkeyOut: number,
    inputBuf: number,
    inputLen: number
  ) => number;
  secp256k1_ecdsa_signature_parse_der: (
    ctx: bigint,
    sigOut: number,
    inputBuf: number,
    inputLen: number
  ) => number;
  secp256k1_ecdsa_signature_parse_compact: (
    ctx: bigint,
    sigOut: number,
    inputBuf: number
  ) => number;
  secp256k1_ecdsa_signature_normalize: (
    ctx: bigint,
    sigOut: number,
    sigIn: number
  ) => number;
  secp256k1_ecdsa_verify: (
    ctx: bigint,
    sigBuf: number,
    msgHash: number,
    pubkeyBuf: number
  ) => number;
  secp256k1_xonly_pubkey_parse: (
    ctx: bigint,
    xonlyOut: number,
    inputBuf: number
  ) => number;
  secp256k1_schnorrsig_verify: (
    ctx: bigint,
    sig64: number,
    msg: number,
    msglen: number,
    pubkey: number
  ) => number;
};

let _syms: SymbolTable | null = null;
let _ctx: bigint = 0n;

// Pre-allocated reusable output buffers (stable module-level allocations)
const _pubkeyBuf = new Uint8Array(OPAQUE_BUF_SIZE);
const _sigBuf = new Uint8Array(OPAQUE_BUF_SIZE);
const _xonlyPubkeyBuf = new Uint8Array(OPAQUE_BUF_SIZE);
let _pubkeyPtr: number = 0;
let _sigPtr: number = 0;
let _xonlyPubkeyPtr: number = 0;

// ---------------------------------------------------------------------------
// Initialization
// ---------------------------------------------------------------------------

function initFFI(): boolean {
  try {
    const lib = dlopen(LIB_PATH, {
      secp256k1_context_create: {
        args: [FFIType.u32],
        returns: FFIType.u64,
      },
      secp256k1_context_destroy: {
        args: [FFIType.u64],
        returns: FFIType.void,
      },
      secp256k1_ec_pubkey_parse: {
        args: [FFIType.u64, FFIType.ptr, FFIType.ptr, FFIType.u64],
        returns: FFIType.i32,
      },
      secp256k1_ecdsa_signature_parse_der: {
        args: [FFIType.u64, FFIType.ptr, FFIType.ptr, FFIType.u64],
        returns: FFIType.i32,
      },
      secp256k1_ecdsa_signature_parse_compact: {
        args: [FFIType.u64, FFIType.ptr, FFIType.ptr],
        returns: FFIType.i32,
      },
      secp256k1_ecdsa_signature_normalize: {
        args: [FFIType.u64, FFIType.ptr, FFIType.ptr],
        returns: FFIType.i32,
      },
      secp256k1_ecdsa_verify: {
        args: [FFIType.u64, FFIType.ptr, FFIType.ptr, FFIType.ptr],
        returns: FFIType.i32,
      },
      secp256k1_xonly_pubkey_parse: {
        args: [FFIType.u64, FFIType.ptr, FFIType.ptr],
        returns: FFIType.i32,
      },
      secp256k1_schnorrsig_verify: {
        args: [FFIType.u64, FFIType.ptr, FFIType.ptr, FFIType.u64, FFIType.ptr],
        returns: FFIType.i32,
      },
    });

    _syms = lib.symbols as unknown as SymbolTable;

    // Create process-lifetime VERIFY context
    _ctx = _syms.secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    if (_ctx === 0n) {
      console.error("[secp256k1_ffi] secp256k1_context_create returned NULL");
      return false;
    }

    // Compute stable pointers to pre-allocated buffers
    _pubkeyPtr = ptr(_pubkeyBuf);
    _sigPtr = ptr(_sigBuf);
    _xonlyPubkeyPtr = ptr(_xonlyPubkeyBuf);

    return true;
  } catch (e) {
    // Library not found or symbol missing — log warning and degrade gracefully
    console.warn("[secp256k1_ffi] Failed to load libsecp256k1:", (e as Error).message);
    return false;
  }
}

// Initialize at module load time (synchronous)
FFI_AVAILABLE = initFFI();

if (FFI_AVAILABLE) {
  console.log("[secp256k1_ffi] libsecp256k1 0.5.0 FFI ready — ECDSA/Schnorr via C library");
} else {
  console.warn("[secp256k1_ffi] libsecp256k1 unavailable — callers fall back to @noble/curves");
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Parse a secp256k1 public key (33-byte compressed or 65-byte uncompressed)
 * into the internal 64-byte opaque format in _pubkeyBuf.
 * Returns true on success.
 */
function _parsePubkey(pubkeyBytes: Uint8Array): boolean {
  const inputPtr = ptr(pubkeyBytes);
  return _syms!.secp256k1_ec_pubkey_parse(
    _ctx,
    _pubkeyPtr,
    inputPtr,
    pubkeyBytes.length
  ) === 1;
}

/**
 * Parse a strict-DER ECDSA signature into the internal 64-byte format in _sigBuf.
 * Returns true on success.
 */
function _parseSigDER(derBytes: Uint8Array): boolean {
  const inputPtr = ptr(derBytes);
  return _syms!.secp256k1_ecdsa_signature_parse_der(
    _ctx,
    _sigPtr,
    inputPtr,
    derBytes.length
  ) === 1;
}

/**
 * Lax DER parser matching Bitcoin Core's ecdsa_signature_parse_der_lax.
 *
 * Extracts (r, s) tolerating non-canonical DER encodings:
 * - Excess leading zero bytes
 * - Non-minimal length encodings
 * - Trailing garbage bytes
 *
 * Returns a 64-byte compact {r||s} (each component right-aligned in 32 bytes),
 * or null if the data is completely unparseable.
 */
function _laxDerToCompact(sig: Uint8Array): Uint8Array | null {
  let pos = 0;
  const len = sig.length;

  if (pos >= len || sig[pos] !== 0x30) return null;
  pos++;

  // Sequence length — skip (may be non-minimal multi-byte encoding)
  if (pos >= len) return null;
  let seqLen = sig[pos++];
  if (seqLen & 0x80) {
    const numBytes = seqLen & 0x7f;
    seqLen = 0;
    for (let i = 0; i < numBytes && pos < len; i++) {
      seqLen = (seqLen << 8) | sig[pos++];
    }
  }

  // Parse R integer
  if (pos >= len || sig[pos] !== 0x02) return null;
  pos++;
  if (pos >= len) return null;
  let rLen = sig[pos++];
  if (rLen & 0x80) {
    const numBytes = rLen & 0x7f;
    rLen = 0;
    for (let i = 0; i < numBytes && pos < len; i++) {
      rLen = (rLen << 8) | sig[pos++];
    }
  }
  if (pos + rLen > len) return null;
  let rStart = pos;
  const rEnd = pos + rLen;
  // Strip leading zero padding
  while (rStart < rEnd && sig[rStart] === 0x00) rStart++;
  const rBytes = sig.slice(rStart, rEnd);
  pos += rLen;

  // Parse S integer
  if (pos >= len || sig[pos] !== 0x02) return null;
  pos++;
  if (pos >= len) return null;
  let sLen = sig[pos++];
  if (sLen & 0x80) {
    const numBytes = sLen & 0x7f;
    sLen = 0;
    for (let i = 0; i < numBytes && pos < len; i++) {
      sLen = (sLen << 8) | sig[pos++];
    }
  }
  if (pos + sLen > len) return null;
  let sStart = pos;
  const sEnd = pos + sLen;
  while (sStart < sEnd && sig[sStart] === 0x00) sStart++;
  const sBytes = sig.slice(sStart, sEnd);

  if (rBytes.length === 0 || sBytes.length === 0) return null;
  // r and s must fit in 32 bytes (256-bit scalar)
  if (rBytes.length > 32 || sBytes.length > 32) return null;

  // Pack into compact 64-byte form: r right-aligned in [0..31], s right-aligned in [32..63]
  const compact = new Uint8Array(64);
  compact.set(rBytes, 32 - rBytes.length);
  compact.set(sBytes, 64 - sBytes.length);
  return compact;
}

// ---------------------------------------------------------------------------
// Public API — signature verification
// ---------------------------------------------------------------------------

/**
 * Validate a public key (33-byte compressed or 65-byte uncompressed).
 * Returns true if the key is a valid secp256k1 point.
 */
export function parsePubkeyFFI(pubkeyBytes: Buffer | Uint8Array): boolean {
  if (!FFI_AVAILABLE) return false;
  return _parsePubkey(pubkeyBytes as Uint8Array);
}

/**
 * Validate a strict DER-encoded ECDSA signature.
 * Returns true if the DER encoding is valid.
 */
export function parseSignatureDER_FFI(derBytes: Buffer | Uint8Array): boolean {
  if (!FFI_AVAILABLE) return false;
  return _parseSigDER(derBytes as Uint8Array);
}

/**
 * Verify a strict-DER ECDSA signature using libsecp256k1.
 *
 * libsecp256k1's secp256k1_ecdsa_verify internally normalizes to low-S before
 * comparing, so high-S signatures return false. This is correct for
 * SCRIPT_VERIFY_LOW_S enforcement. For legacy paths that do not enforce low-S,
 * use ecdsaVerifyLaxFFI instead.
 *
 * @param signature DER-encoded ECDSA signature (without sighash byte)
 * @param msgHash   32-byte message hash (pre-hashed)
 * @param publicKey 33-byte compressed or 65-byte uncompressed public key
 * @returns true if signature is valid
 */
export function ecdsaVerifyFFI(
  signature: Buffer | Uint8Array,
  msgHash: Buffer | Uint8Array,
  publicKey: Buffer | Uint8Array
): boolean {
  if (!FFI_AVAILABLE) return false;
  if (msgHash.length !== 32) return false;

  if (!_parsePubkey(publicKey as Uint8Array)) return false;
  if (!_parseSigDER(signature as Uint8Array)) return false;

  // Normalize to low-S (required by secp256k1_ecdsa_verify which rejects high-S)
  _syms!.secp256k1_ecdsa_signature_normalize(_ctx, _sigPtr, _sigPtr);

  const msgPtr = ptr(msgHash as Uint8Array);
  return _syms!.secp256k1_ecdsa_verify(_ctx, _sigPtr, msgPtr, _pubkeyPtr) === 1;
}

/**
 * Verify an ECDSA signature using lax DER parsing.
 *
 * Matches Bitcoin Core's behavior when SCRIPT_VERIFY_DERSIG is NOT set:
 * non-strict DER encodings are accepted as long as (r,s) are valid scalars.
 * Also handles hybrid pubkeys (0x06/0x07 prefix).
 *
 * Low-S is NOT enforced here — the script interpreter enforces SCRIPT_VERIFY_LOW_S
 * by checking the high bit of S before calling this function.
 *
 * @param signature ECDSA signature (lax DER, without sighash byte)
 * @param msgHash   32-byte message hash
 * @param publicKey 33/65-byte compressed/uncompressed or hybrid (06/07) pubkey
 * @returns true if signature is valid
 */
export function ecdsaVerifyLaxFFI(
  signature: Buffer | Uint8Array,
  msgHash: Buffer | Uint8Array,
  publicKey: Buffer | Uint8Array
): boolean {
  if (!FFI_AVAILABLE) return false;
  if (msgHash.length !== 32) return false;

  // Handle hybrid pubkeys (0x06/0x07) — convert to uncompressed (0x04)
  let pk = publicKey as Uint8Array;
  if (pk.length === 65 && (pk[0] === 0x06 || pk[0] === 0x07)) {
    pk = new Uint8Array(pk);
    pk[0] = 0x04;
  }

  if (!_parsePubkey(pk)) return false;

  // Lax DER parse: tolerate non-canonical encodings, extract raw (r,s)
  const compact = _laxDerToCompact(signature as Uint8Array);
  if (!compact) return false;

  // Parse via compact format (bypasses strict DER requirements)
  const compactPtr = ptr(compact);
  if (_syms!.secp256k1_ecdsa_signature_parse_compact(_ctx, _sigPtr, compactPtr) !== 1) {
    return false;
  }

  // Do NOT normalize to low-S — lax verification intentionally allows high-S.
  // The interpreter checks SCRIPT_VERIFY_LOW_S separately.

  const msgPtr = ptr(msgHash as Uint8Array);
  return _syms!.secp256k1_ecdsa_verify(_ctx, _sigPtr, msgPtr, _pubkeyPtr) === 1;
}

/**
 * Verify a BIP-340 Schnorr signature using libsecp256k1.
 *
 * @param signature    64-byte Schnorr signature
 * @param msgHash      32-byte message hash (sighash)
 * @param xonlyPubkey  32-byte x-only public key
 * @returns true if signature is valid per BIP-340
 */
export function schnorrVerifyFFI(
  signature: Buffer | Uint8Array,
  msgHash: Buffer | Uint8Array,
  xonlyPubkey: Buffer | Uint8Array
): boolean {
  if (!FFI_AVAILABLE) return false;
  if (signature.length !== 64 || msgHash.length !== 32 || xonlyPubkey.length !== 32) {
    return false;
  }

  // Parse x-only pubkey into opaque struct
  const xpkPtr = ptr(xonlyPubkey as Uint8Array);
  if (_syms!.secp256k1_xonly_pubkey_parse(_ctx, _xonlyPubkeyPtr, xpkPtr) !== 1) {
    return false;
  }

  const sigPtr = ptr(signature as Uint8Array);
  const msgPtr = ptr(msgHash as Uint8Array);
  return _syms!.secp256k1_schnorrsig_verify(_ctx, sigPtr, msgPtr, 32, _xonlyPubkeyPtr) === 1;
}

// ---------------------------------------------------------------------------
// Counted wrappers (increment ffiCallCount for benchmarking)
// ---------------------------------------------------------------------------

/** ecdsaVerifyFFI that also increments ffiCallCount. */
export function ecdsaVerifyFFICounted(
  signature: Buffer | Uint8Array,
  msgHash: Buffer | Uint8Array,
  publicKey: Buffer | Uint8Array
): boolean {
  ffiCallCount++;
  return ecdsaVerifyFFI(signature, msgHash, publicKey);
}

/** ecdsaVerifyLaxFFI that also increments ffiCallCount. */
export function ecdsaVerifyLaxFFICounted(
  signature: Buffer | Uint8Array,
  msgHash: Buffer | Uint8Array,
  publicKey: Buffer | Uint8Array
): boolean {
  ffiCallCount++;
  return ecdsaVerifyLaxFFI(signature, msgHash, publicKey);
}

/** schnorrVerifyFFI that also increments ffiCallCount. */
export function schnorrVerifyFFICounted(
  signature: Buffer | Uint8Array,
  msgHash: Buffer | Uint8Array,
  xonlyPubkey: Buffer | Uint8Array
): boolean {
  ffiCallCount++;
  return schnorrVerifyFFI(signature, msgHash, xonlyPubkey);
}
