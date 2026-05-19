# W160 — ECDSA + Schnorr signing primitives + RFC 6979 deterministic nonce + sighash construction (hotbuns)

**Wave:** W160 — `secp256k1_ecdsa_sign` / `secp256k1_ecdsa_sign_recoverable`,
RFC 6979 deterministic nonce (HMAC-DRBG with SHA-256),
`secp256k1_schnorrsig_sign32` / `_sign_custom`, BIP-340 `aux_rand32`
(NEVER NULL on production sign path), `secp256k1_ecdsa_signature_normalize`
low-S enforcement (BIP-62 rule 5), `secp256k1_ecdsa_signature_serialize_der`
strict-DER (BIP-66), BIP-143 segwit-v0 sighash (`hashPrevouts` / `hashSequence`
/ `hashOutputs` per-tx midstate caching), BIP-341 Taproot sighash
(`epoch=0x00`, `sha_prevouts` / `sha_amounts` / `sha_scriptpubkeys` /
`sha_sequences` / `sha_outputs`, `ext_flag * 2 | hasAnnex` spend_type,
`tap_leaf_hash || key_version || codesep_pos` for script-path), SIGHASH_DEFAULT
(0x00 → 64-byte sig, no trailing byte), SIGHASH_SINGLE preserve-the-bug
(`uint256::ONE` when nIn >= vout.size() in legacy/segwit-v0),
`secp256k1_keypair_create` + `_keypair_xonly_pub` parity output + `_keypair_xonly_tweak_add`
(BIP-341 even-Y negation inside libsecp256k1 — not the caller's BigInt),
`CKey::Sign(..., grind=true)` low-R grinding (saves 1 byte/sig avg),
`secp256k1_ec_seckey_tweak_add` (BIP-32 priv-side scalar add),
`memory_cleanse` zeroize on every CKey scope exit, FindAndDelete walking
at opcode boundaries, sigcache key SHA256(nonce || 'E' || zeros || sighash ||
pubkey || sig) — sighash REQUIRED for cache safety, `secp256k1_ecdsa_recover`
recovery byte for compact-recoverable sigs (BIP-137).

**Scope:** discovery only — no production code changes.

**Bitcoin Core references**
- `bitcoin-core/src/secp256k1/src/modules/recovery/main_impl.h` — `secp256k1_ecdsa_sign_recoverable`
  (RFC 6979 nonce via `nonce_function_rfc6979`, recovery byte encoded
  into the 65-byte compact form via
  `secp256k1_ecdsa_recoverable_signature_serialize_compact`).
- `bitcoin-core/src/secp256k1/src/modules/schnorrsig/main_impl.h` —
  `secp256k1_schnorrsig_sign32(ctx, sig64, msg32, keypair, aux_rand32)`:
  `aux_rand32` MUST be 32-byte random (BIP-340 §"Default Signing"
  RECOMMENDS fresh random per signature). When `aux_rand32 == NULL`,
  the spec's "default signing" still works but provides only the
  deterministic component `t = bytes(d) XOR H(...)` — strictly weaker
  against fault attacks.
- `bitcoin-core/src/secp256k1/src/ecdsa_impl.h` — `secp256k1_ecdsa_sig_sign`
  with deterministic `k` derived via `nonce_function_rfc6979` (HMAC-SHA-256
  DRBG over `seckey || msg32 || algo16 || data32(extra_entropy)`); produces
  canonical low-S sig (s ≤ n/2).
- `bitcoin-core/src/script/sign.cpp` — `CreateSig`, `SignStep`,
  `ProduceSignature`; sigversion plumbing; `MutableTransactionSignatureCreator`.
- `bitcoin-core/src/script/interpreter.cpp:1483-1599` —
  `SignatureHashSchnorr`: BIP-341 sigmsg construction with `epoch=0x00`,
  `sha_prevouts/amounts/scriptpubkeys/sequences/outputs`, spend_type
  `(ext_flag << 1) | hasAnnex`, `sha_single_output` when SIGHASH_SINGLE,
  per-leaf `tap_leaf_hash || key_version || codesep_pos` when
  ext_flag=1 (BIP-342 tapscript).
- `bitcoin-core/src/script/interpreter.cpp:1600-1677` — legacy +
  BIP-143 `SignatureHash` (single API, sigversion dispatch); BIP-143 cache
  via `m_bip143_segwit_ready`; SIGHASH_SINGLE bug: `nIn >= txTo.vout.size()`
  → `return uint256::ONE` (which is `0x010000…00` LE, 32 bytes with
  byte[0]=0x01).
- `bitcoin-core/src/script/interpreter.cpp:1265-1292` — legacy
  `CTransactionSignatureSerializer::SerializeScriptCode`: strips ALL
  `OP_CODESEPARATOR` bytes (regardless of position) before emitting
  the script bytes. Segwit-v0 path (`else if` branch around line 1623)
  does NOT strip — scriptCode is emitted as-is.
- `bitcoin-core/src/script/interpreter.cpp:229-255` — `FindAndDelete`:
  walks at **opcode boundaries** via `script.GetOp(pc, opcode)`. Inner
  `while` loop re-checks `std::equal` repeatedly at the SAME opcode
  start so adjacent occurrences are all stripped in one pass.
- `bitcoin-core/src/script/interpreter.cpp:212-216` — `CheckECDSASignature`:
  calls `secp256k1_ecdsa_signature_normalize` (low-S enforcement) before
  `secp256k1_ecdsa_verify`.
- `bitcoin-core/src/key.cpp:209-234` — `CKey::Sign`: deterministic
  ECDSA, optional **low-R grinding** (`grind=true` default; saves 1
  byte/sig on average via `SigHasLowR()` retry with incrementing
  `extra_entropy`), **paranoia re-verify**: after `secp256k1_ecdsa_sign`
  Core RE-VERIFIES via `secp256k1_ec_pubkey_create` + `secp256k1_ecdsa_verify`
  and asserts. Same paranoia at `key.cpp:262-269` for
  `SignCompact` (recoverable) and `key.cpp:555-562` for
  `KeyPair::SignSchnorr` (with `memory_cleanse` on failure).
- `bitcoin-core/src/key.cpp:528-547` — `KeyPair::KeyPair(merkle_root)`:
  BIP-341 even-Y negation is done INSIDE libsecp256k1 via
  `secp256k1_keypair_create` → `_keypair_xonly_pub` (parity output)
  → `_keypair_xonly_tweak_add`. Caller never touches BigInt math.
- `bitcoin-core/src/key.cpp::CKey::Derive` — BIP-32 priv-side scalar add
  via `secp256k1_ec_seckey_tweak_add` (NOT BigInt) — constant-time +
  scalar-range gate inside libsecp256k1.
- `bitcoin-core/src/script/sigcache.cpp:41-43` — `CSignatureCache::ComputeEntry`:
  cache key = `CSHA256(nonce || 'E' || 31_zeros || sighash || pubkey || sig)`.
  **The sighash MUST be in the key** because the same `(sig, pubkey)` can
  appear in different transactions verifying different sighashes —
  omitting sighash from the key creates a false-positive when an
  identical witness rides on a different spending tx.
- `bitcoin-core/src/script/sign.cpp` (BIP-32) — `CKey::Sign(..., grind=true,
  test_case=0)`: low-R grinding loops `extra_entropy = test_case+1, +2, …`
  until `SigHasLowR()`; default `grind=true` from
  `CKey::Sign` invocations.
- `bitcoin-core/src/secp256k1/src/scratch.h` — `secp256k1_scratch` for
  precomp tables in batch verify (not used by hotbuns).
- `bitcoin-core/src/support/lockedpool.cpp::LockedPool` + `secure_allocator`
  — `mlock`/`memory_cleanse` backing `CPrivKey` and `keydata`. seckey
  bytes never page to swap.

**Files audited**
- `src/crypto/primitives.ts` (905 LOC) — `ecdsaSign` (267-278) via
  `@noble/curves` `secp256k1.sign({prehash:false, format:"der"})` —
  NO FFI sign path, NO re-verify, NO low-R grinding;
  `ecdsaVerify` (287-302) FFI-then-fallback;
  `ecdsaVerifyLax` (422-453) FFI-then-fallback with lax DER reparse;
  `ecdsaVerifyBatch` (462-486) sequential loop with `*Batch` name;
  `schnorrSign` (500-517) via `@noble` `schnorr.sign(msg, sk, auxRand)`
  with `auxRand` defaulted to noble's `randomBytes(32)` if undefined;
  `schnorrVerify` (536-554); `schnorrVerifyBatch` (563-586) sequential;
  `privateKeyToPublicKey` (598-608) via noble;
  `privateKeyToXOnlyPubKey` (617-625) via `schnorr.getPublicKey` (noble);
  `tweakPrivateKey` (692-745) pure-JS BigInt even-Y negation +
  scalar add `(d + t) mod n` + return `hex(...).padStart(64,"0")`;
  `tweakPublicKey` (755-798) pure-JS BigInt point add via noble.
- `src/crypto/secp256k1_ffi.ts` (489 LOC) — VERIFY-only FFI:
  `_context_create(VERIFY)` + `_ec_pubkey_parse` + `_ecdsa_signature_parse_der`
  + `_parse_compact` + `_normalize` + `_ecdsa_verify` + `_xonly_pubkey_parse`
  + `_schnorrsig_verify`. **NO** `_ecdsa_sign`, **NO** `_ecdsa_sign_recoverable`,
  **NO** `_schnorrsig_sign32`, **NO** `_ecdsa_recover`, **NO** `_keypair_*`,
  **NO** `_ec_seckey_tweak_add`, **NO** `_xonly_pubkey_tweak_add_check`.
- `src/crypto/signmessage.ts` (213 LOC) — `messageSign` (78-107)
  via `@noble` `secp256k1.sign({prehash:false, format:"recovered"})`;
  recovery byte at `sigBytes[0]`, `R || S` at `[1..65]`; manually rebuilds
  Bitcoin compact header `27 + rec + (compressed ? 4 : 0)`; NO re-recover/
  re-cmp paranoia; NO FFI. `messageVerify` (118-198) via `@noble`
  `secp256k1.recoverPublicKey`; NO FFI.
- `src/validation/tx.ts` (1948 LOC) — `sigHashLegacy` (778-875),
  `sigHashLegacyWithSig` (890-900), `sigHashLegacyRaw` (907-1001);
  `sigHashWitnessV0` (393-482) BIP-143 (no per-tx cache, only single-input
  cache via `sigHashWitnessV0Cached` 1146-1245);
  `sigMsgTaproot` (1287-1411) BIP-341 sigmsg with full cache;
  `sigHashTaproot` (1413-1430) = `taggedHash("TapSighash", sigMsgTaproot(...))`;
  `sigHashTaprootKeyPath` (1436-1456), `sigHashTaprootScriptPath` (1462-1484);
  `verifyInputSignature` (1499-1691) per-input verify with `SigHashCache`
  + `TaprootSigHashCache` + script-interpreter dispatch;
  `verifyAllInputsParallel` (1698-1740) `Promise.all` of
  `Promise.resolve(syncFn())` → single-threaded.
- `src/validation/sig_cache.ts` (172 LOC) — `SigCache.computeKey`
  (94-111): key = `SHA256(nonce || scriptSig || witnessConcat || flagsLE4)[0..8]`;
  **sighash NOT included**. `globalSigCache` (172) at module load.
- `src/script/interpreter.ts` (3092 LOC) — `isValidSignatureEncoding`
  (466-495) strict DER; `isLowDERSignature` (519-530); `checkSignatureEncoding`
  (551-574) gate order DERSIG → LOW_S → STRICTENC; `verifySchnorrSig`
  (703-775) BIP-342 tapscript Schnorr; `findAndDelete` (941-974)
  byte-by-byte search (NOT opcode-aware — divergence vs Core);
  OP_CHECKSIG legacy path (1666-1678) calls local `findAndDelete`;
  OP_CHECKSIG segwit-v0 path (1671-1673) uses `serializeScript(slice(codeSepPos+1))`
  with no `OP_CODESEPARATOR`-stripping when BIP-143 path NEVER strips
  (correct! match with Core);
  `verifyTaprootKeyPath` (2469-2516); `verifyTaprootScriptPath` (2531-2625)
  with pure-JS BigInt `tweakPublicKeyWithParity` (2675-2729).
- `src/wallet/wallet.ts` (3235 LOC) — `bip32CkdPrivFromI` (117-145)
  **pure-JS BigInt** `(parent + IL) mod n` — NOT FFI;
  `signP2PKHInput` (1466-1493) `ecdsaSign` + concat `[SIGHASH_ALL]`;
  `signP2SHP2WPKHInput` (1498-1533); `signP2WPKHInput` (1538-1570);
  `signP2TRInput` (1582-1639) `tweakPrivateKey` + `schnorr.sign` (noble,
  not FFI) + conditional 64/65-byte witness encoding by SIGHASH_DEFAULT
  vs non-default. **No `signP2TRInput` re-verify.** No
  `tweakedPrivateKey.fill(0)` after sign.
- `src/wallet/psbt.ts` (3833 LOC) — `signPSBTInput` (1486-1638)
  enumerates P2WPKH / P2PKH / P2SH-P2WPKH / P2SH-P2WSH / P2WSH and
  throws `"Unsupported script type for signing"` for **anything else**
  including P2TR. PSBT cannot sign Taproot inputs.

---

## Gate matrix (28 sub-gates / 9 behaviours)

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 1 | RFC 6979 deterministic nonce | G1: ECDSA sign uses RFC 6979 HMAC-DRBG over (seckey, msg32, algo, extra_entropy) | PASS — `@noble/curves` `secp256k1.sign` defaults to RFC 6979 (`hmac` option uses HMAC-SHA-256 DRBG, documented in `_shortw_utils.d.ts`) |
| 1 | … | G2: low-R grinding (`grind=true`) to save 1 byte/sig avg | **BUG-1 (P2)** — `ecdsaSign` (primitives.ts:267-278) calls noble with no `extraEntropy` parameter, no retry loop on high-R. Bytes per signature average ~73 instead of Core's ~72. Default Core `CKey::Sign(grind=true)` saves ~1B per p2pkh / p2wpkh signature; over millions of mainnet outputs the size delta is real |
| 1 | … | G3: sign-then-verify paranoia (re-verify against derived pubkey, assert) | **BUG-2 (P1)** — `ecdsaSign` (primitives.ts:267-278) returns the noble sig directly. No `secp256k1_ec_pubkey_create` + `secp256k1_ecdsa_verify` round-trip. Carry-forward of W159 BUG-5 |
| 2 | aux_rand32 (BIP-340 default-signing) | G4: Schnorr sign receives FRESH 32-byte aux_rand per call | PASS (noble defaults to `randomBytes(32)` when `auxRand` is undefined — `node_modules/@noble/curves/secp256k1.js:148`) |
| 2 | … | G5: Schnorr sign-then-verify + `memory_cleanse` on failure | **BUG-3 (P1)** — `schnorrSign` (primitives.ts:500-517) + `signP2TRInput` (wallet.ts:1582-1639) return noble sig with no re-verify, no `memory_cleanse` on partial-output failure. Carry-forward of W159 BUG-7 |
| 2 | … | G6: caller cannot pass `auxRand = Buffer.alloc(32, 0)` and get a valid-but-weaker sig with no warning | **BUG-4 (P2)** — `schnorrSign` accepts any 32-byte `auxRand` including all-zeros, no warning. The wallet path `signP2TRInput` (wallet.ts:1625) calls `schnorr.sign(sighash, tweakedPrivateKey)` with no `auxRand` argument → noble produces fresh randomness, so end-to-end this is safe — but a future caller that accidentally passes a zero buffer or a stale random gets silently weaker sigs |
| 3 | Low-S enforcement (BIP-62 rule 5) | G7: ECDSA verify normalizes sig to low-S before secp256k1 verify | PASS (`secp256k1_ffi.ts:347, 404` — calls `_ecdsa_signature_normalize` on both ecdsaVerifyFFI and ecdsaVerifyLaxFFI paths) |
| 3 | … | G8: ECDSA sign emits low-S by default (matches default `lowS:true` of @noble) | PASS — `ecdsaSign` calls noble with no `lowS:false` override, noble defaults to `lowS:true` (`weierstrass.d.ts:82`) |
| 4 | DER strict (BIP-66) | G9: `isValidSignatureEncoding` enforces strict DER | PASS (`interpreter.ts:466-495`) |
| 4 | … | G10: `checkSignatureEncoding` gates DER on DERSIG / LOW_S / STRICTENC | PASS (`interpreter.ts:558` — gates on `verifyDERSignatures || verifyLowS || verifyStrictEncoding`) |
| 5 | Sighash construction — legacy | G11: `SIGHASH_SINGLE` bug preserved (return `uint256::ONE` when `inputIndex >= outputs.length`) | PASS (`tx.ts:793-797, 921-926` — returns 32-byte buf with `[0]=1`) |
| 5 | … | G12: `SIGHASH_SINGLE` bug only fires for non-segwit (sigversion != WITNESS_V0) | PASS — BIP-143 sigHashWitnessV0 falls through to `hashOutputs = Buffer.alloc(32, 0)` (line 444-445) instead |
| 5 | … | G13: legacy sighash strips ALL `OP_CODESEPARATOR` from scriptCode (mirror Core `SerializeScriptCode`) | PASS (`tx.ts:800 removeCodeSeparators(subscript)` before serialize; `interpreter.ts:1668-1670` does FindAndDelete then sigHasher) |
| 5 | … | G14: `FindAndDelete` walks at OPCODE BOUNDARIES (mirror Core `script.GetOp(pc, opcode)`) | **BUG-5 (P0-CDIV)** — `interpreter.ts:941-974` `findAndDelete` advances ONE byte at a time on no-match (line 968-969), NOT at opcode boundaries. Core walks via `script.GetOp(pc, opcode)`. A crafted scriptCode whose embedded push-bytes happen to contain the encoded-sig prefix could be stripped mid-push-data by hotbuns where Core wouldn't strip. Note: hotbuns has a SECOND, opcode-aware `findAndDelete` in `tx.ts:658-739` (the public one) that is NEVER called from the interpreter — only `prepareSubscriptForSigning` uses it. **Two implementations of the same primitive, one consensus-critical path calling the wrong one** |
| 6 | Sighash construction — BIP-143 segwit-v0 | G15: `hashPrevouts` / `hashSequence` / `hashOutputs` per-tx midstate cache | PARTIAL — `sigHashWitnessV0Cached` (tx.ts:1146-1245) caches per-input via `SigHashCache`, but `verifyAllInputsSequential` creates a fresh `cache: SigHashCache = {}` per tx (line 1763), so cross-input reuse works. **BUG-6 (P1)** — there is NO cross-tx cache (no equivalent of Core's `PrecomputedTransactionData` keyed by txid). Re-validating the same tx during block-connect after mempool acceptance recomputes the three hashes |
| 6 | … | G16: hashType written as 4-byte LE int (matches Core `ss << nHashType`) | PASS (`tx.ts:479 writeUInt32LE(hashType)`, `tx.ts:1242 writeUInt32LE(hashType)`) |
| 6 | … | G17: scriptCode for OP_CHECKSIG in WITNESS_V0 is `serializeScript(slice(codeSepPos+1))` — NOT `removeCodeSeparators`-stripped | PASS (`interpreter.ts:1672-1673` — segwit branch does NOT strip; matches Core `EvalChecksigPreTapscript` which passes raw `pbegincodehash..pend` to `SignatureHash` for WITNESS_V0) |
| 7 | Sighash construction — BIP-341 Taproot | G18: epoch byte = 0x00 | PASS (`tx.ts:1315 writer.writeUInt8(0x00)`) |
| 7 | … | G19: original `hashType` (not effective) emitted in sigmsg | PASS (`tx.ts:1316 writeUInt8(hashType)` — uses ORIGINAL, not effective; SIGHASH_DEFAULT=0x00 commits to 0x00 byte) |
| 7 | … | G20: spend_type = `(ext_flag << 1) | hasAnnex` | PASS (`tx.ts:1373 spendType = (extFlag * 2) | (hasAnnex ? 1 : 0)`) |
| 7 | … | G21: annex hash = SHA256(compactsize(annex_len) || annex), with the `0x50` prefix INCLUDED in annex bytes | PASS (`tx.ts:1567-1569, 1641-1645` — annex bytes include the 0x50 lead byte; `BufferWriter.writeVarBytes` emits compactsize prefix) |
| 7 | … | G22: script-path emits `tap_leaf_hash (32) || key_version (1) || codesep_pos (4 LE)` after annex | PASS (`tx.ts:1401-1408`) |
| 7 | … | G23: SIGHASH_DEFAULT (0x00) → 64-byte sig; explicit 0x01 (ALL) → 65 bytes — distinct path | PASS — `verifySchnorrSig` (interpreter.ts:743-753) errors on `sig.length===65 && hashType===0x00` (SCHNORR_SIG_HASHTYPE); same in `verifyTaprootKeyPath` (interpreter.ts:2489-2495). Wallet `signP2TRInput` (wallet.ts:1631-1635) encodes 64 vs 65 bytes |
| 8 | Sig-cache key includes sighash | G24: cache key = SHA256(nonce \|\| 'E' \|\| zeros \|\| sighash \|\| pubkey \|\| sig) | **BUG-7 (P0-SEC)** — `sig_cache.ts:94-111` `SigCache.computeKey` = `SHA256(nonce \|\| scriptSig \|\| witnessConcat \|\| flagsLE4)`. **sighash NOT in key.** Identical witness on different spending tx → cache hit → script verify SKIPPED → invalid tx accepted. **Concrete attack:** anyone who broadcasts a tx with a P2WPKH/P2WSH/P2SH-P2WPKH `<sig, pubkey>` witness reveals it; an attacker who knows another UTXO sent to the same pubkey can build a tx2 spending UTXO2 with the **identical** witness `[sig, pubkey]`. After tx1 is verified successfully, the cache has `(scriptSig, [sig, pubkey], flags)` → success. tx2 has the same `(scriptSig, [sig, pubkey], flags)` → CACHE HIT → marked valid without running the interpreter. The sig is RFC-6979-deterministic against tx1's sighash and DOES NOT verify against tx2's sighash, so without the cache this would correctly fail. **Comment-as-confession at sig_cache.ts:85-88**: `"We use scriptSig+witness as a proxy for the individual sig material because… (b) any change to sig bytes produces a different key"` — but the same sig bytes on a DIFFERENT tx is exactly the missed case |
| 9 | Taproot keypair seckey-flip on odd-y | G25: `tweakPrivateKey` uses libsecp256k1's `secp256k1_keypair_create + _xonly_tweak_add` (not BigInt) | **BUG-8 (P0-CDIV)** — `primitives.ts:692-745` pure-JS BigInt. Carry-forward of W159 BUG-18 (escalates with this audit's BUG-12 sig-cache-on-script-path) |
| 9 | … | G26: BIP-32 priv-side scalar add via `secp256k1_ec_seckey_tweak_add` (not BigInt) | **BUG-9 (P1)** — `wallet.ts:117-145` `bip32CkdPrivFromI` does `(parent + IL) % n` in pure-JS BigInt — non-constant-time. Carry-forward of W159 BUG-18; same shape, different call site (CKD vs TapTweak) |
| 10 | Signing surface coverage | G27: PSBT can sign all Bitcoin script types including P2TR | **BUG-10 (P1)** — `psbt.ts:1486-1638` `signPSBTInput` enumerates P2WPKH / P2PKH / P2SH-P2WPKH / P2SH-P2WSH / P2WSH but throws `"Unsupported script type for signing"` for everything else, including P2TR. PSBT is unusable for Taproot signing — `signP2TRInput` exists only on the `Wallet` class internal flow. Worse: PSBT parsing AT psbt.ts:866-900 DOES parse `PSBT_IN_TAP_KEY_SIG`, `PSBT_IN_TAP_INTERNAL_KEY`, `PSBT_IN_TAP_MERKLE_ROOT` (BIP-371), so the file format claims to support Taproot but the SIGNER role rejects it |
| 10 | … | G28: ECDSA recovery (compact sig recovery) routes through FFI (`secp256k1_ecdsa_recover`) on the BIP-137 messageVerify path | **BUG-11 (P1)** — `signmessage.ts:172` calls `secp256k1.recoverPublicKey` (noble); FFI module doesn't bind `secp256k1_ecdsa_recover`. Carry-forward of W159 BUG-15 |

---

## BUG-1 (P2) — `ecdsaSign` does not implement low-R grinding (`grind=true` default)

**Severity:** P2 (size optimization / mainnet-block-bloat policy parity).

Bitcoin Core's `CKey::Sign` at `bitcoin-core/src/key.cpp:209-227` runs:

```c
unsigned char extra_entropy[32] = {0};
ret = secp256k1_ecdsa_sign(secp256k1_context_sign, &sig, hash.data(), UCharCast(begin()), nullptr, nullptr);
assert(ret);
if (grind) {
    while (ret && !SigHasLowR(&sig)) {
        WriteLE32(extra_entropy, ++counter);
        ret = secp256k1_ecdsa_sign(secp256k1_context_sign, &sig, hash.data(), UCharCast(begin()), nullptr, extra_entropy);
    }
    assert(ret);
}
```

`grind=true` is the default. The retry loop tweaks `extra_entropy` until
`SigHasLowR()` returns true (the resulting `r` value fits in 31 bytes,
not 32). This saves 1 byte per DER signature on average (32 → 31 byte
`r` happens ~50% of the time, so the geometric retry costs ~2 attempts
amortized).

Over the full mainnet history this is on the order of millions of
saved bytes, and the deterministic-but-padded `extra_entropy` keeps the
sig fully RFC-6979 (still no fresh secret randomness).

hotbuns `ecdsaSign` at `src/crypto/primitives.ts:267-278`:

```typescript
export function ecdsaSign(msgHash: Buffer, privateKey: Buffer): Buffer {
  if (msgHash.length !== 32) { throw new Error(...); }
  if (privateKey.length !== 32) { throw new Error(...); }
  const signature = secp256k1.sign(msgHash, privateKey, { prehash: false, format: "der" });
  return Buffer.from(signature);
}
```

No `extraEntropy`, no retry loop. Every sig hotbuns emits is ~1 byte
larger than the canonical Core sig for the same key/msg pair.

**File:** `src/crypto/primitives.ts:267-278`.

**Core ref:** `bitcoin-core/src/key.cpp:209-227`.

**Impact:** wallet outputs are marginally larger than Core's. Not a
consensus difference (high-R sigs are valid), but block-template bytes
spent on hotbuns wallet sigs are non-canonical. Mempool acceptance is
fine. The optimisation is the closest thing to "free bytes" Core has
on the wire.

---

## BUG-2 (P1) — `ecdsaSign` lacks `secp256k1_ecdsa_verify` re-check paranoia

**Severity:** P1 (carry-forward of W159 BUG-5; documented here for the
W160 sign-side completeness).

Core's `CKey::Sign` at `key.cpp:228-234`:

```c
// Additional verification step to prevent using a potentially corrupted signature
secp256k1_pubkey pk;
ret = secp256k1_ec_pubkey_create(secp256k1_context_sign, &pk, UCharCast(begin()));
assert(ret);
ret = secp256k1_ecdsa_verify(secp256k1_context_static, &sig, hash.begin(), &pk);
assert(ret);
return true;
```

Rationale per the comment: "prevent using a potentially corrupted
signature" — guard against memory corruption, transient hardware
faults, or library bugs. Defense-in-depth specifically for the
sign-path.

hotbuns: no equivalent on `ecdsaSign`, `signP2PKHInput`,
`signP2SHP2WPKHInput`, `signP2WPKHInput`, or `signPSBTInput` (PSBT
caller-loaded ECDSA path).

**File:** `src/crypto/primitives.ts:267-278`; downstream callers:
`src/wallet/wallet.ts:1485, 1522, 1562`; `src/wallet/psbt.ts:1628`.

**Core ref:** `bitcoin-core/src/key.cpp:228-234`.

**Impact:** a single corrupted sig (hardware fault, library bug)
would emit a tx that fails verification at the receiving end. The
wallet has no detection. **W159 BUG-5 carry-forward — 2nd-consecutive
audit of the same gap.** Hotbuns is the 5th-of-10 fleet impl with the
sign-then-verify-paranoia-absent pattern.

---

## BUG-3 (P1) — `schnorrSign` / `signP2TRInput` lack sign-then-verify + `memory_cleanse`

**Severity:** P1 (carry-forward of W159 BUG-7).

Core's `KeyPair::SignSchnorr` at `key.cpp:549-563`:

```c
bool ret = secp256k1_schnorrsig_sign32(secp256k1_context_sign, sig.data(), hash.data(), keypair, aux.data());
if (ret) {
    secp256k1_xonly_pubkey pubkey_verify;
    ret = secp256k1_keypair_xonly_pub(secp256k1_context_static, &pubkey_verify, nullptr, keypair);
    ret &= secp256k1_schnorrsig_verify(secp256k1_context_static, sig.data(), hash.begin(), 32, &pubkey_verify);
}
if (!ret) memory_cleanse(sig.data(), sig.size());
return ret;
```

Three paranoia elements:
1. Re-derive pubkey from the keypair via `secp256k1_keypair_xonly_pub`.
2. Re-verify the signature via `secp256k1_schnorrsig_verify`.
3. **On failure**, `memory_cleanse` the (potentially-partial) signature
   buffer — sig may have leaked partial secret-derived state.

hotbuns `primitives.ts:500-517`:

```typescript
export function schnorrSign(msgHash, privateKey, auxRand): Buffer {
  if (msgHash.length !== 32) { throw ... }
  if (privateKey.length !== 32) { throw ... }
  if (auxRand && auxRand.length !== 32) { throw ... }
  const sig = schnorr.sign(msgHash, privateKey, auxRand);
  return Buffer.from(sig);
}
```

And `wallet.ts:1625`:

```typescript
const signature = Buffer.from(schnorr.sign(sighash, tweakedPrivateKey));
```

No re-verify, no `memory_cleanse`. The `tweakedPrivateKey` is itself
the BIP-86 spending key; if the noble sign path produces a corrupted
output, hotbuns happily broadcasts.

**File:** `src/crypto/primitives.ts:500-517`; `src/wallet/wallet.ts:1625`.

**Core ref:** `bitcoin-core/src/key.cpp:549-563`.

**Impact:** same shape as BUG-2 but for the Taproot path.
**W159 BUG-7 carry-forward.**

---

## BUG-4 (P2) — `schnorrSign` accepts `auxRand = Buffer.alloc(32, 0)` silently

**Severity:** P2 (footgun, not exploitable today).

BIP-340 §"Default Signing" specifies that `aux_rand32` SHOULD be 32
bytes of fresh CSPRNG output. Passing all-zeros is permitted by the
algorithm (the deterministic component still depends on `d` and `msg`)
but disables the auxiliary defense against fault attacks.

Core never passes all-zeros — `KeyPair::SignSchnorr` always reads from
`GetStrongRandBytes(aux)`. The library deliberately does NOT make this
caller-controllable except in test mode.

hotbuns `primitives.ts:500-517`:

```typescript
if (auxRand && auxRand.length !== 32) { throw new Error(...); }
const sig = schnorr.sign(msgHash, privateKey, auxRand);
```

The only check is length; an all-zero 32-byte buffer is accepted.
Today the only production caller is `signP2TRInput` (wallet.ts:1625)
which passes NO `auxRand` argument → noble defaults to
`randomBytes(32)` (noble source at
`node_modules/@noble/curves/secp256k1.js:148`). End-to-end safe.

**But:** the public API surface `schnorrSign(msgHash, privateKey, Buffer.alloc(32, 0))`
is callable by any future consumer that wants "deterministic test
sigs" — a test fixture that uses zero `auxRand` and gets copy-pasted
into production code is a real-world bug class.

**File:** `src/crypto/primitives.ts:500-517`.

**Core ref:** `bitcoin-core/src/secp256k1/src/modules/schnorrsig/main_impl.h`
+ `bitcoin-core/src/key.cpp:549-563`.

**Impact:** latent; depends on future caller behavior. Mitigation
would be either a runtime warning when `auxRand` is all-zero or a
production guard that rejects deterministic `auxRand` outside test
mode.

---

## BUG-5 (P0-CDIV) — `findAndDelete` in interpreter walks byte-by-byte instead of opcode boundaries

**Severity:** P0-CDIV (consensus-critical).

Bitcoin Core's `FindAndDelete` at `bitcoin-core/src/script/interpreter.cpp:229-255`:

```c
int FindAndDelete(CScript& script, const CScript& b)
{
    int nFound = 0;
    if (b.empty()) return nFound;
    CScript result;
    CScript::const_iterator pc = script.begin(), pc2 = script.begin(), end = script.end();
    opcodetype opcode;
    do {
        result.insert(result.end(), pc2, pc);
        while (static_cast<size_t>(end - pc) >= b.size() && std::equal(b.begin(), b.end(), pc)) {
            pc = pc + b.size();
            ++nFound;
        }
        pc2 = pc;
    } while (script.GetOp(pc, opcode));
    ...
}
```

The outer loop advances `pc` at **opcode boundaries** via
`script.GetOp(pc, opcode)`. This means the match-check at each
iteration starts at a position that begins a NEW opcode (not in the
middle of push-data). The inner `while` loop allows MULTIPLE adjacent
occurrences to be stripped per iteration.

This is consensus-critical because BIP-66 / BIP-62 sigs embedded in
script push-data are stripped ONLY when they appear at an opcode
boundary. If hotbuns strips them mid-push-data, hotbuns will compute
a different sighash than Core.

hotbuns `src/script/interpreter.ts:941-974`:

```typescript
function findAndDelete(script: Buffer, sig: Buffer): Buffer {
  if (sig.length === 0) return script;
  let pushSig: Buffer;
  if (sig.length < 76)      { pushSig = Buffer.concat([Buffer.from([sig.length]), sig]); }
  else if (sig.length < 256){ pushSig = Buffer.concat([Buffer.from([OP_PUSHDATA1, sig.length]), sig]); }
  else                      { pushSig = Buffer.concat([Buffer.from([OP_PUSHDATA2, sig.length & 0xff, (sig.length >> 8) & 0xff]), sig]); }

  const parts: Buffer[] = [];
  let i = 0;
  while (i < script.length) {
    if (i + pushSig.length <= script.length && script.subarray(i, i + pushSig.length).equals(pushSig)) {
      i += pushSig.length;          // skip match
    } else {
      parts.push(script.subarray(i, i + 1));
      i++;                           // ← advances ONE BYTE, not one OPCODE
    }
  }
  return Buffer.concat(parts);
}
```

The fallback `i++` advances ONE BYTE, not one opcode. A scripthash that
embeds the push-encoded form of a signature inside a longer push (e.g.
`OP_PUSHDATA1 0xFF <... bytes that happen to contain the encoded sig
prefix ...>`) would be stripped mid-push by hotbuns whereas Core would
skip the entire push opcode and only match at the next opcode start.

**Crucial additional observation:** hotbuns has a **SECOND** `findAndDelete`
implementation in `src/validation/tx.ts:658-739` (the public, exported
one) that **DOES** walk at opcode boundaries via the same kind of
`while (pos < script.length) { ... ; let nextPos: number; if (opcode <= 0x4b)
{ nextPos = pos + 1 + opcode; } ... ; pos = nextPos; }` structure as
Core. This second implementation is invoked by `prepareSubscriptForSigning`
(tx.ts:749-763) which is intended for legacy sighash. The
interpreter, however, calls the BYTE-LEVEL version (line 1670 of
interpreter.ts) instead of the opcode-aware one.

**Two implementations of the same primitive, the consensus-critical
path calling the wrong one.** Pattern fleet-wide for hotbuns: "wiring-
look-but-no-wire" + new variant "two-implementations-same-name-wrong-
one-called".

**File:** `src/script/interpreter.ts:941-974` (the byte-by-byte
version); `src/validation/tx.ts:658-739` (the opcode-aware version,
NOT called by the interpreter).

**Core ref:** `bitcoin-core/src/script/interpreter.cpp:229-255` +
`bitcoin-core/src/script/interpreter.cpp:330, 1146` (callsites that
use it for legacy CHECKSIG / CHECKMULTISIG via `FindAndDelete(scriptCode,
CScript() << vchSig)`).

**Impact:** consensus divergence on the legacy CHECKSIG /
CHECKMULTISIG path for a crafted script containing a push of the
sig-prefix bytes inside another opcode. The crafted-script class is
hostile-by-construction but real: any block from Core could include
such a tx, hotbuns would compute a different sighash and reject the
block. **Most concerning fix priority of this audit.**

---

## BUG-6 (P1) — no `PrecomputedTransactionData` cache; per-tx midstate cache is per-input only

**Severity:** P1.

Bitcoin Core's `PrecomputedTransactionData` (`primitives/transaction.h`)
is a per-tx struct that caches `hashPrevouts`, `hashSequence`,
`hashOutputs` (and the Taproot-flavor `sha_prevouts/amounts/scriptpubkeys/
sequences/outputs`) once per tx, then reuses across mempool acceptance
AND block-connect verification of the SAME tx. The cache is keyed
implicitly by the `CTransaction` object identity.

hotbuns has `SigHashCache` (tx.ts:1136-1140) and `TaprootSigHashCache`
(tx.ts:1255-1262), but they are constructed at the call-site:

```typescript
// verifyAllInputsSequential (tx.ts:1763)
const cache: SigHashCache = {};
const taprootCache: TaprootSigHashCache = {};
```

Each `verifyAllInputsSequential` invocation creates fresh caches.
Mempool acceptance and block-connect of the same tx run independent
cache instances → BIP-143's two SHA-256 + Taproot's five SHA-256 are
recomputed.

**File:** `src/validation/tx.ts:1716-1718, 1763-1765` (cache
construction sites). No persistent `txid → cache` map anywhere in
`src/validation/` or `src/mempool/`.

**Core ref:** `bitcoin-core/src/primitives/transaction.h::PrecomputedTransactionData`.

**Impact:** mempool-accepted tx re-validated during block-connect
recomputes 2 hashes (BIP-143) or 5 hashes (BIP-341) per input.
At ~5M sat-bytes of mainnet block weight the overhead is small but
real. Larger problem: a tx with 100 inputs verifies the 5 Taproot
midstates 100 times during a single block-connect pass because they
are shared per-tx but not per-block, and they ARE re-computed if
the same tx is checked again for any reason (e.g. CPFP descendant
scoring).

---

## BUG-7 (P0-SEC) — sigcache key omits sighash: cross-tx replay false-positive

**Severity:** P0-SEC (security / consensus-bypass).

Bitcoin Core's `CSignatureCache::ComputeEntry` at
`bitcoin-core/src/script/sigcache.cpp:41-43`:

```c
static uint256 ComputeEntry(
    const ChaCha20::Key& nonce_key,
    const std::vector<unsigned char>& vchSig,
    const std::vector<unsigned char>& vchPubKey,
    const uint256& sighash) {
    CSHA256()
        .Write(nonce_key.data(), nonce_key.size())
        .Write(vchSig.data(), vchSig.size())
        .Write(vchPubKey.data(), vchPubKey.size())
        .Write(sighash.begin(), sighash.size())   // ← sighash IS in key
        .Finalize(out.begin());
    return out;
}
```

The **sighash is part of the key**. Two transactions that happen to
have the SAME `(sig, pubkey)` but DIFFERENT sighashes (because they
spend different prev-outputs) produce DIFFERENT cache keys. Cache
hits only when the EXACT same (sig, pubkey, sighash) triple has been
verified successfully before.

hotbuns `src/validation/sig_cache.ts:94-111`:

```typescript
computeKey(scriptSig: Buffer, witness: Buffer[], flags: number): CacheKey {
  const flagsBuf = Buffer.allocUnsafe(4);
  flagsBuf.writeUInt32LE(flags, 0);
  const witnessParts: Buffer[] = [];
  for (const item of witness) {
    const lenBuf = Buffer.allocUnsafe(4);
    lenBuf.writeUInt32LE(item.length, 0);
    witnessParts.push(lenBuf, item);
  }
  const material = Buffer.concat([this.nonce, scriptSig, ...witnessParts, flagsBuf]);
  const digest = createHash("sha256").update(material).digest();
  const entryHex = digest.subarray(0, 8).toString("hex");
  return { entryHex };
}
```

`(scriptSig, witness, flags)` only — **no sighash, no spending-tx
context, no input-index**.

**Attack:**
1. Alice's wallet broadcasts tx1 spending UTXO_A. The P2WPKH witness
   for input 0 is `[sig_A, pubkey_A]` where `sig_A` is RFC-6979-derived
   from `(pubkey_A.priv, sighash_A)` and `sighash_A` commits to UTXO_A
   (via `hashPrevouts`).
2. hotbuns mempool-accepts tx1 → `verifyInputSignature` succeeds → cache
   entry `SHA256(nonce || "" || [sig_A_len, sig_A, pubkey_A_len, pubkey_A]
   || witnessFlagsLE)` is inserted.
3. Attacker observes tx1 on the wire and extracts `[sig_A, pubkey_A]`.
4. Attacker constructs tx2 spending UTXO_B (different prev-out, same
   destination pubkey `pubkey_A`). tx2's input 0 carries the SAME
   witness `[sig_A, pubkey_A]` (copy-paste, no resigning).
5. tx2's sighash is `sighash_B != sighash_A` because `hashPrevouts`
   commits to UTXO_B.
6. hotbuns `verifyInputSignature(tx2, 0, UTXO_B, ...)` computes the
   cache key. `scriptSig = ""`, `witness = [sig_A, pubkey_A]`,
   `flags = witnessFlags` — **IDENTICAL to tx1's cache entry**.
7. `globalSigCache.lookup(cacheKey)` returns `true`. `verifyInputSignature`
   returns `{valid: true, inputIndex: 0}` **WITHOUT running the
   interpreter**.
8. tx2 is admitted. The actual `ecdsaVerifyLax(sig_A, sighash_B,
   pubkey_A)` would have returned `false` (RFC-6979 sig binds to one
   sighash), but the cache hit skipped it.

**This is exploitable on mainnet today.** Any address-reuse pattern
where pubkey_A receives at multiple UTXOs is fodder. The attacker
doesn't need the private key — just the broadcast witness.

**Mitigating factor:** the cache `nonce` is per-process random
(line 75), so the attack must operate within a single hotbuns process
lifetime — restarting the node clears the cache. But: 1) most nodes
run for weeks; 2) the cache holds 50,000 entries (`maxEntries`
default at line 71); 3) any address-reuse pattern will eventually
exercise the bug.

**Comment-as-confession at sig_cache.ts:84-88:**

```
   * Mirrors Core: SHA256(nonce || 'E'||zeros || sighash || pubkey || sig)
   * (sigcache.cpp:41-43).  We use scriptSig+witness as a proxy for the
   * individual sig material because (a) it is available at the
   * verifyInputSignature call site without threading into the interpreter,
   * and (b) any change to sig bytes produces a different key.
```

The comment EXPLICITLY references Core including `sighash` in the
key, then justifies omitting it on the grounds "any change to sig
bytes produces a different key" — true, but the converse "same sig
bytes on a DIFFERENT tx" is the missed case. **Comment-as-confession
19th distinct hotbuns instance**, and the most exploit-direct.

**File:** `src/validation/sig_cache.ts:94-111`; `src/validation/sig_cache.ts:84-88`
(the comment-as-confession).

**Core ref:** `bitcoin-core/src/script/sigcache.cpp:41-43`
(`CSignatureCache::ComputeEntry`); `bitcoin-core/src/script/sigcache.h:42-44`
(per-process nonce + entry encoding).

**Impact:** consensus bypass via cache poisoning. The exact severity
class is **P0-SEC** (security-level critical) rather than P0-CDIV
(consensus-divergent) because hotbuns and Core both REJECT tx2 if the
interpreter actually runs — the bug is that hotbuns skips the
interpreter. A miner who wants to confuse hotbuns into accepting
invalid blocks could exploit this for double-spend confusion.

---

## BUG-8 (P0-CDIV) — Taproot keypair seckey-flip in pure-JS BigInt (W159 carry-forward, escalated)

**Severity:** P0-CDIV (consensus-critical when combined with BUG-7).

Carry-forward of W159 BUG-18. Documented here because the W160 lens
adds two new dimensions:

1. **The tweaked seckey IS the actual signing key for production
   BIP-86 wallets.** Every `signP2TRInput` call (wallet.ts:1582-1639)
   runs `tweakPrivateKey` in pure-JS BigInt then hands the result to
   noble `schnorr.sign`. The tweaked seckey lives in a regular
   `Buffer` (`Buffer.from(hex, "hex")` at primitives.ts:744). No
   `mlock`, no `memory_cleanse` after sign.

2. **The output of `tweakPrivateKey` is used to sign a sighash that
   may be cached via BUG-7.** A bug in the BigInt code path (e.g.
   an off-by-one in `.padStart(64, "0")` for keys that happen to be
   ≤ 32 bytes) would produce a sig that NEVER verifies against the
   on-chain output key — but if the same `[sig, pubkey]` is reused
   (cache poisoning) the sig-cache bypass would accept it
   nonetheless. The combination of pure-JS even-Y negation + sig-
   cache without sighash is materially worse than either alone.

**File:** `src/crypto/primitives.ts:692-745`.

**Core ref:** `bitcoin-core/src/key.cpp:528-547`.

**Impact:** P0 fault-tolerance on the wallet signing path + amplifies
BUG-7's blast radius for any Taproot tx that gets cache-poisoned.

---

## BUG-9 (P1) — BIP-32 priv-side scalar add in pure-JS BigInt

**Severity:** P1 (side-channel surface, performance, consensus-clean).

Bitcoin Core's `CKey::Derive` derives a child secret via
`secp256k1_ec_seckey_tweak_add(ctx, child.data(), IL_bytes)`. The
scalar add `(parent + IL) mod n` runs inside libsecp256k1 with the
randomized sign-context, in constant time, with the scalar-range
gate built-in.

hotbuns `src/wallet/wallet.ts:117-145` `bip32CkdPrivFromI`:

```typescript
export function bip32CkdPrivFromI(parentKey, I, index) {
  const IL = I.subarray(0, 32);
  const IR = I.subarray(32, 64);
  const parentKeyBigInt = BigInt("0x" + parentKey.toString("hex"));
  const ILBigInt = BigInt("0x" + IL.toString("hex"));
  if (ILBigInt >= CURVE_ORDER) { throw new Bip32InvalidChildError(...); }
  const childKeyBigInt = (parentKeyBigInt + ILBigInt) % CURVE_ORDER;
  if (childKeyBigInt === 0n) { throw new Bip32InvalidChildError(...); }
  const childKeyHex = childKeyBigInt.toString(16).padStart(64, "0");
  return { key: Buffer.from(childKeyHex, "hex"), chainCode: Buffer.from(IR) };
}
```

Pure-JS BigInt. Every BIP-32 derivation (master → m/84'/0'/0'/0/0 is
5 derivations on first use) flows through this. The intermediate
BigInts are allocated on the JS GC heap and `.toString(16)` /
`Buffer.from(hex, "hex")` round-trips leave hex-string traces in
memory.

**Note on scope:** the master seed itself comes from `deriveMasterKey`
which uses `hmac(sha512, "Bitcoin seed", seed)` — this lives in
Buffer space, but the FIRST priv-side scalar add (which converts
HMAC output to a valid scalar) is the BigInt path above.

**File:** `src/wallet/wallet.ts:117-145`.

**Core ref:** `bitcoin-core/src/key.cpp::CKey::Derive` +
`bitcoin-core/src/secp256k1/include/secp256k1.h::secp256k1_ec_seckey_tweak_add`.

**Impact:** non-constant-time wallet derivation; secrets leak into
hex-string interner. **W159 BUG-17 sibling on the BIP-32 path**.
The FFI module has the requisite primitive on disk; binding it would
close both this and W159 BUG-17.

---

## BUG-10 (P1) — PSBT signer rejects P2TR: parses BIP-371 fields but cannot sign Taproot

**Severity:** P1.

PSBT (`src/wallet/psbt.ts`) has full BIP-371 PARSER support:
`psbt.ts:866-987` parses `PSBT_IN_TAP_KEY_SIG`,
`PSBT_IN_TAP_SCRIPT_SIG`, `PSBT_IN_TAP_LEAF_SCRIPT`,
`PSBT_IN_TAP_BIP32_DERIVATION`, `PSBT_IN_TAP_INTERNAL_KEY`,
`PSBT_IN_TAP_MERKLE_ROOT`, and parses out the structures
correctly into the typed `PSBTInput` (line 132-150). The COMBINER and
EXTRACTOR roles also handle Taproot fields.

But the **SIGNER role** at `psbt.ts:1486-1638` (`signPSBTInput`)
enumerates script types and at line 1623-1624:

```typescript
} else {
  throw new Error("Unsupported script type for signing");
}
```

The enumerated types are P2WPKH, P2PKH, P2SH-P2WPKH, P2SH-P2WSH,
P2WSH. P2TR (OP_1 <32 bytes>) is NOT in the enum and falls into the
else branch. The thrown error string mirrors a "permanent unsupported"
posture, not a "TODO".

**The wallet has** `signP2TRInput` (wallet.ts:1582-1639) which DOES
sign Taproot, but the PSBT module does not call into it. PSBT-driven
hardware-wallet flows (which are the dominant production path) cannot
sign Taproot via hotbuns.

**File:** `src/wallet/psbt.ts:1486-1638` (signer enum);
`src/wallet/wallet.ts:1582-1639` (the existing signer that PSBT
doesn't call).

**Core ref:** `bitcoin-core/src/wallet/scriptpubkeyman.cpp::FillPSBT` +
`bitcoin-core/src/wallet/walletutil.cpp` (Core's PSBT signer dispatches
to Taproot key-path + script-path).

**Impact:** **PSBT-Taproot is a no-op fleet pattern** — fleet pattern
"feature-half-finished-parser-vs-signer". A hardware wallet that hands
hotbuns a Taproot PSBT gets back the PSBT unchanged with no error
indication to the GUI level (well — it throws, so the call fails, but
not silently). Practical impact: users with a Trezor/Ledger setup who
own Taproot funds CANNOT spend them through hotbuns.

---

## BUG-11 (P1) — `secp256k1_ecdsa_recover` not wired for BIP-137 messageVerify

**Severity:** P1 (carry-forward of W159 BUG-15, documented here for the
W160 sign-side completeness).

`secp256k1_ffi.ts:56-100` (the `SymbolTable` type and the `initFFI`
`dlopen` table) lists 9 symbols: `_context_create`, `_destroy`,
`_ec_pubkey_parse`, `_ecdsa_signature_parse_der`, `_parse_compact`,
`_normalize`, `_ecdsa_verify`, `_xonly_pubkey_parse`, `_schnorrsig_verify`.

**Missing:** `secp256k1_ecdsa_recover` (the public-key recovery
primitive) and its support functions `secp256k1_ecdsa_recoverable_
signature_parse_compact` / `_serialize_compact`. The recovery module is
a separate compile-time feature in libsecp256k1 — most distros build
it in (`--enable-module-recovery`), and the Debian 13 `libsecp256k1.so.2`
that hotbuns dlopen's at line 32 DOES include it.

`messageVerify` at `signmessage.ts:172` calls
`secp256k1.recoverPublicKey(recoveredSig, h, { prehash: false })` via
noble — pure JS, no FFI. On every BIP-137 signed-message verify,
that's a noble round-trip.

**File:** `src/crypto/secp256k1_ffi.ts:56-100` (missing symbol bindings);
`src/crypto/signmessage.ts:172` (the consumer).

**Core ref:** `bitcoin-core/src/secp256k1/src/modules/recovery/main_impl.h`.

**Impact:** `messageVerify` is 30-100× slower than the FFI equivalent.
Not on the consensus hot path so not P0-SEC. **W159 BUG-15 carry-forward
— 2nd-consecutive audit of the same dead-symbol gap.**

---

## Fleet-pattern cross-cites (W160 lens)

**Side-channel-blinding-disabled (universal 10/10):** W160 confirms
hotbuns is also affected via the FFI context (W159 BUG-4); no new
W160 evidence beyond W159.

**Sign-then-verify-paranoia-absent (5+ impls):** W160 BUG-2 + BUG-3
re-confirm the W159 sign-side. Hotbuns is the 5th-of-10 fleet impl
with this gap (clearbit, lunarblock, rustoshi, nimrod, hotbuns =
saturating-on-the-pattern).

**SegWit malleability sigcache (3+ impls):** W160 BUG-7 is a NEW
hotbuns instance of the broader "sigcache key omits enough material"
fleet pattern. camlcoin / haskoin / nimrod (3 prior hits) had related
cache keying gaps; hotbuns now joins as the 4th — but with a stronger
class of bug (omits SIGHASH itself, not just a flag). **NEW fleet
pattern variant: "sigcache-key-omits-sighash" — hotbuns origin**.

**BIP-32 priv-side BigInt asymmetry:** W160 BUG-9 = W159 BUG-17.

**BIP-340 nonce=0 fallback:** PARTIAL — W160 BUG-4 documents the
risk but the production path doesn't trigger it.

**Asymmetric Schnorr surface:** W159 BUG-15 / W160 BUG-11 carry-forward.

**Cipher-as-scalar:** confirmed in W159 (BIP-324 uses noble
`isValidSecretKey` for the per-handshake key, not FFI). No new W160
evidence.

**Two-curve-library on consensus path (hotbuns origin):** W160 confirms
+ extends. The Taproot key-path tweak in `tweakPublicKeyWithParity`
(interpreter.ts:2675-2729) and the BIP-86 wallet seckey tweak in
`tweakPrivateKey` (primitives.ts:692-745) are both pure-JS noble
BigInt math. The FFI module does NOT handle production signing OR
production Taproot tweaks. **Two-curve-library expands from "Taproot
script-path output-key verify" (W159 finding) to ALSO include
"wallet Taproot key-path SIGN"** — broader scope than W159 admitted.

**Wiring-look-but-no-wire — TWO-IMPLEMENTATIONS-SAME-NAME-WRONG-ONE-
CALLED (NEW VARIANT, hotbuns origin):** W160 BUG-5 is a new variant.
hotbuns has two `findAndDelete` implementations on disk: the
byte-by-byte one in `interpreter.ts:941` (called from OP_CHECKSIG /
OP_CHECKMULTISIG) and the opcode-aware one in `tx.ts:658` (called
from `prepareSubscriptForSigning`, which is exported but never
invoked from the interpreter hot path). The consensus-critical path
calls the WRONG implementation. **New pattern: "twin-impl,
consensus-path picks the wrong twin".**

**Comment-as-confession:** W160 BUG-7 is the **19th distinct hotbuns
instance** and the most exploit-direct: the cache code EXPLICITLY
references Core including `sighash` in the key, then JUSTIFIES
omitting it on grounds that turn out to be incomplete.

**Test-pins-bug:** no new W160 evidence (the existing tests
on `sig_cache.test.ts:302-311` exercise nonce-override determinism
but don't probe the cross-tx replay class).

**Dead-but-public-returns-true:** no new W160 evidence.

**Drift-converged-on-wrong-default:** PARTIAL — W160 BUG-4 (`auxRand`
all-zero footgun) is adjacent.

---

## Severity rollup

| Severity | Count | Bugs |
|----------|-------|------|
| P0-SEC   | 1     | BUG-7 (sigcache cross-tx replay) |
| P0-CDIV  | 2     | BUG-5 (FindAndDelete byte-level), BUG-8 (Taproot tweak BigInt — escalated by BUG-7) |
| P1       | 7     | BUG-2, BUG-3, BUG-6, BUG-9, BUG-10, BUG-11, (and BUG-9 BIP-32) |
| P2       | 2     | BUG-1, BUG-4 |
| **Total**| **11**| |

(Note: BUG-8 and BUG-9 both partially overlap W159 carry-forwards but
are documented here for the W160 lens — they EXPAND W159's findings.)

---

## Recommended priority

1. **BUG-7 (P0-SEC, ~10 LOC fix)** — add `sighash: Buffer` to
   `SigCache.computeKey` signature; thread it from
   `verifyInputSignature` (which already computes sighashes inline).
   Single highest-priority fix in this wave; closes a consensus-bypass
   class.
2. **BUG-5 (P0-CDIV, ~5 LOC fix)** — replace the `interpreter.ts:941`
   `findAndDelete` body with a call to the existing opcode-aware
   `tx.ts:658` version (resolve the circular import via the same
   `require()` pattern already used for taproot at `tx.ts:1592`).
3. **BUG-10 (P1, ~30 LOC fix)** — add P2TR branch to `signPSBTInput`
   that calls into `Wallet.signP2TRInput` (or directly invokes
   `tweakPrivateKey + schnorr.sign + sigHashTaproot`). Enables
   PSBT-Taproot for hardware wallets.
4. **BUG-2 + BUG-3 (P1 each, ~3 LOC each)** — wrap `ecdsaSign` +
   `schnorrSign` in re-verify-then-`fill(0)` paranoia. Closes 2 of the
   5-of-10 fleet sign-then-verify-paranoia-absent pattern instances.
5. **BUG-6 (P1, ~15 LOC)** — add a `txid → PrecomputedTransactionData`
   cache at the validation layer (or thread an existing one through
   `verifyAllInputsSequential`).
6. **BUG-9 + BUG-8 (P1+P0-CDIV, ~20 LOC)** — bind `secp256k1_ec_seckey_tweak_add`
   + `secp256k1_keypair_xonly_tweak_add` in the FFI module; route
   `bip32CkdPrivFromI` + `tweakPrivateKey` through them. Closes
   W159 BUG-17/18 + W160 BUG-8/9 in one PR.
7. **BUG-11 (P1, ~10 LOC)** — bind `secp256k1_ecdsa_recover` + the
   recoverable-sig serializer; route `messageVerify` through FFI.
8. **BUG-1 (P2, ~15 LOC)** — implement low-R grinding on `ecdsaSign`
   with `extra_entropy` retry loop. Optional but cheap mainnet-bloat
   reduction.
9. **BUG-4 (P2, ~3 LOC)** — add a runtime warning when `auxRand` is
   all-zero in `schnorrSign`.
