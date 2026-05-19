# W158 — BIP-322 + Legacy BIP-137 message signing — hotbuns

**Impl:** hotbuns (TypeScript / Bun)
**Date:** 2026-05-19
**Wave:** W158 BIP-322 + Legacy BIP-137 `signmessage` / `verifymessage` /
`signmessagewithprivkey`
**Status:** DISCOVERY — 21 BUGS / 9 behaviours × ~30 gates
**Tests:** assertion-only, no production code changes.
**No production code changes in this wave.**

## References

### Bitcoin Core (consensus + RPC + wallet — legacy BIP-137 path)
- `bitcoin-core/src/common/signmessage.cpp:24` —
  `MESSAGE_MAGIC = "Bitcoin Signed Message:\n"` (24 bytes).
- `bitcoin-core/src/common/signmessage.cpp:26-55` — `MessageVerify(address, signature, message)`:
  - `DecodeDestination(address)` against THIS node's chainparams; returns
    `ERR_INVALID_ADDRESS` if invalid OR if address is for a different network
    (mainnet node WILL refuse a testnet P2PKH).
  - `std::get_if<PKHash>(&destination) == nullptr` → `ERR_ADDRESS_NO_KEY`
    (P2SH, bech32, bech32m all reject here).
  - `DecodeBase64(signature)` → `ERR_MALFORMED_SIGNATURE` (Core's base64
    decoder rejects malformed input via the boolean return — `std::optional`
    in modern code).
  - `CPubKey::RecoverCompact(MessageHash(message), sig)` → if false,
    `ERR_PUBKEY_NOT_RECOVERED`. (Verifies header byte length implicitly via
    `vchSig.size() != COMPACT_SIGNATURE_SIZE`. No upper bound on header byte.)
  - `PKHash(pubkey) == *get_if<PKHash>` → if false, `ERR_NOT_SIGNED`.
- `bitcoin-core/src/common/signmessage.cpp:57-71` — `MessageSign(privkey, message, &signature)`:
  - `privkey.SignCompact(MessageHash(message), bytes)`; returns false on
    invalid key.
  - `signature = EncodeBase64(bytes)`.
- `bitcoin-core/src/common/signmessage.cpp:73-79` — `MessageHash(message)`:
  ```
  HashWriter hasher{};
  hasher << MESSAGE_MAGIC << message;  // each std::string serialised as
                                       // WriteCompactSize(len) || raw bytes
  return hasher.GetHash();             // SHA256d
  ```
- `bitcoin-core/src/key.cpp:250-271` — `CKey::SignCompact`:
  - `vchSig[0] = 27 + rec + (fCompressed ? 4 : 0);` — `fCompressed` is the
    `CKey`'s own attribute, NOT a caller-passed flag.
  - Does NOT call `secp256k1_ecdsa_signature_normalize`; emitted compact
    signatures can therefore be high-S (Bitcoin historically did not enforce
    low-S on compact sigs, see comment at `pubkey.cpp:294-296`).
  - `assert(ret)` on every internal failure — i.e. `SignCompact` returns
    `false` only if `!keydata`.
- `bitcoin-core/src/pubkey.cpp:300-318` — `CPubKey::RecoverCompact`:
  - `vchSig.size() != COMPACT_SIGNATURE_SIZE` → false.
  - `int recid = (vchSig[0] - 27) & 3; bool fComp = ((vchSig[0] - 27) & 4) != 0;`
    — accepts ANY header byte; out-of-range bytes wrap silently.
- `bitcoin-core/src/rpc/signmessage.cpp::verifymessage` — non-wallet RPC.
- `bitcoin-core/src/rpc/signmessage.cpp::signmessagewithprivkey`:
  - `CKey key = DecodeSecret(strPrivkey);` ← network-specific (`DecodeSecret`
    uses `Params().Base58Prefix(CChainParams::SECRET_KEY)`); a mainnet node
    refuses a testnet WIF and vice versa.
- `bitcoin-core/src/wallet/rpc/signmessage.cpp::signmessage` (wallet-only):
  - `LOCK(pwallet->cs_wallet)` + `EnsureWalletIsUnlocked(*pwallet)`
    (throws `RPC_WALLET_UNLOCK_NEEDED = -13` if encrypted+locked).
  - `DecodeDestination` against THIS node's chainparams.
  - `std::get_if<PKHash>(&dest)` else `RPC_TYPE_ERROR = -3` ("Address does
    not refer to key").
  - `pwallet->SignMessage(strMessage, *pkhash, signature)` — wallet looks up
    the key for the PKHash and signs; returns `PRIVATE_KEY_NOT_AVAILABLE`
    if the wallet does not hold the secret.
- `bitcoin-core/src/protocol.h::RPCErrorCode`:
  - `RPC_INVALID_ADDRESS_OR_KEY = -5`
  - `RPC_TYPE_ERROR = -3`
  - `RPC_WALLET_UNLOCK_NEEDED = -13`
  - `RPC_WALLET_ERROR = -4`

### BIP-322 (generic signed message format)
- BIP-322 §"Construction" — virtual `to_spend` transaction:
  - `version = 0`
  - `nLockTime = 0`
  - `vin[0].prevout.hash = 0x000...000` (32-byte zero)
  - `vin[0].prevout.n = 0xFFFFFFFF`
  - `vin[0].sequence = 0`
  - `vin[0].scriptSig = OP_0 PUSH32(message_hash)`
  - `vout[0].value = 0`
  - `vout[0].scriptPubKey = message_challenge` (the scriptPubKey of the
    signer's address)
- BIP-322 §"Construction" — virtual `to_sign` transaction:
  - `version = 0` (Core uses `2` for the legacy-virtual-tx contract; the
    spec leaves it implementation-defined — Bitcoin Core uses `0`)
  - `nLockTime = 0`
  - `vin[0].prevout.hash = txid(to_spend)`
  - `vin[0].prevout.n = 0`
  - `vin[0].sequence = 0`
  - `vin[0].scriptSig` and `vin[0].scriptWitness` carry the signature
  - `vout[0].value = 0`
  - `vout[0].scriptPubKey = OP_RETURN`
- BIP-322 §"BIP322Hash":
  `tagged_hash("BIP0322-signed-message", message_bytes)` where
  `tagged_hash(tag, msg) = SHA256(SHA256(tag) || SHA256(tag) || msg)`.
- BIP-322 §"Simple" format — base64-encoded witness-stack-only payload
  (the full `to_sign` is implied; only the witness for `vin[0]` is sent).
- BIP-322 §"Full" format — base64-encoded full `to_sign` transaction
  (allows multi-input attestations and OP_RETURN extension data).
- BIP-322 §"Legacy" format — falls back to the BIP-137 `Bitcoin Signed
  Message:\n` compact-signature format for P2PKH addresses, for
  bug-compatibility with the 14-year-old Core implementation.

### Carry-forwards explicitly cross-cited
- **W145 BUG-2..6 "Assume-valid scope creep" — STILL UNFIXED** (carry-forward
  6+ days). Cross-cite: an assume-valid window that masks
  `EnsureWalletIsUnlocked` is the same shape — a safety gate intentionally
  skipped by the caller. BUG-1 below ports the same anti-pattern to the
  signing path.
- **W149 BUG-17 + BUG-19 "inherit-via-spread silent dead-field"** —
  `getblockchaininfo` returns `verificationprogress` derived ONLY from
  `tipHeight / bestHeaderHeight`. Cross-cite: BUG-13 below shows the same
  shape — `RPCErrorCodes.INVALID_ADDRESS_OR_KEY` is used as a catch-all
  because `RPC_TYPE_ERROR = -3` was never plumbed into the enum, despite a
  Core-equivalent comment at server.ts:4228 explicitly admitting it.
- **W153 BUG-12 `sync/blocks.ts::connectBlock` NEVER emits `blockConnected`**
  — fleet-pattern "dead-helper / unwired event sink". Cross-cite: BUG-20
  below shows that `MessageVerificationResult.ERR_PUBKEY_NOT_RECOVERED`
  is a defined enum variant that is BYTE-IDENTICAL in its RPC handling to
  `ERR_NOT_SIGNED` (`server.ts:4240-4242`), so the recoverable-vs-non-
  recoverable distinction is dead.
- **W158 clearbit BUG-2 (NEW CROSS-IMPL ECHO)** —
  `handleSignMessage` (`rpc.zig:11355`) reads `key.secret_key` directly
  WITHOUT calling a `getPlaintextSecretKey(idx)` decryption helper; after
  `encryptwallet` the field stores **AES-256-GCM ciphertext**, so the
  resulting compact signature leaks the on-disk ciphertext as the
  recoverable scalar. **BUG-1 below is the hotbuns echo** — different
  primitive flavour but the same chain: signing primitive does not
  ensure-unlocked and the wallet's cached `keys` map retains plaintext
  WalletKey objects across `lockWallet()`, so the bypass works for an
  entirely DIFFERENT reason (cache rather than ciphertext-as-scalar) and
  produces a VALID signature on a locked wallet rather than a leak.

### Files audited
- `src/crypto/signmessage.ts` (213 LOC) —
  `MESSAGE_MAGIC` (33), `P2PKH_VERSIONS` const (49-54),
  `MessageVerificationResult` enum (40-47),
  `messageHash` (61-66),
  `messageSign(privateKey, message, compressed=true)` (78-107),
  `messageVerify(address, signatureBase64, message)` (118-198),
  `privateKeyToP2PKHAddress(privateKey, network, compressed=true)` (205-213).
- `src/crypto/signmessage.test.ts` (94 LOC) — round-trip, magic, sign,
  verify-tamper, ERR_INVALID_ADDRESS, ERR_ADDRESS_NO_KEY, ERR_MALFORMED.
- `src/rpc/server.ts` —
  RPC registration block (1129-1133, 1202),
  `verifymessage` handler (4204-4244),
  `signmessagewithprivkey` handler (4250-4308),
  `signmessage` (wallet-conditional) handler (4319-4366),
  `RPCErrorCodes` enum (210-240) — note absence of `TYPE_ERROR = -3`,
  `getCurrentWallet` (6061+),
  `getP2PKHVersion()` (2982-2993) — network-aware base58 prefix selector,
  unused by the signmessage path.
- `src/wallet/wallet.ts` —
  `WalletKey { privateKey, publicKey, address, path, addressType }` (181-187),
  `Wallet.keys: Map<string, WalletKey>` field (308),
  `getKey(address)` (2354-2359) — direct `this.keys.get(address)`, no lock
  check, no encryption check,
  `pregenerateAddresses` (826-858) — populates `this.keys` with
  fully-resolved WalletKey objects (private keys included),
  `encryptWallet` (2486-2525) — zeroes `this.seed` and `this.masterKey` but
  NOT `this.keys`; comment at lines 2523-2524 falsely claims "Private keys
  are derived on-demand from the seed, so they're not in memory when the
  wallet is locked",
  `lockWallet` (2597-2622) — same: zeroes seed + masterKey, leaves
  `this.keys` populated with WalletKey { privateKey: Buffer (32 bytes) },
  `isLocked()` (2438-2440),
  `getSeed()` (2417-2422) — DOES check `isLocked` and throws.
- `src/rpc/server.ts` lines 7557, 7635, 7719, 7964, 8175 — every OTHER
  wallet RPC (`sendtoaddress`, `bumpfee`, `psbtbumpfee`,
  `signrawtransactionwithwallet`, etc.) prefixes its body with
  `if (wallet.isLocked()) { throw rpcError(WALLET_UNLOCK_NEEDED, ...) }`.

---

## Gate matrix (35 sub-gates / 9 behaviours)

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 1 | `signmessage` (wallet RPC) EnsureWalletIsUnlocked precheck | G1: `wallet.isLocked()` check before signing | **BUG-1 (P0-SEC catastrophic)** — `signMessage` handler (`server.ts:4319-4366`) NEVER calls `wallet.isLocked()`. Every OTHER wallet-mutating RPC in the same file does (`server.ts:7557, 7635, 7719, 7964, 8175`). Combined with BUG-2 below, an encrypted+locked wallet signs successfully and the resulting signature is verifiable. |
| 1 | … | G2: `lockWallet()` clears the `this.keys` Map | **BUG-2 (P0-SEC chain-link for BUG-1)** — `lockWallet` (`wallet.ts:2597-2622`) zeroes `this.seed` and `this.masterKey` but DOES NOT touch `this.keys`. The `WalletKey { privateKey: Buffer }` objects derived during `pregenerateAddresses()` remain in the Map indefinitely. `wallet.getKey(addr).privateKey` returns the original 32-byte secret AFTER lock. **Comment at wallet.ts:2523-2524** is "comment-as-confession" 15th instance: *"Private keys are derived on-demand from the seed, so they're not in memory when the wallet is locked. The key map contains public info only when locked."* — literally false; `WalletKey.privateKey` is a populated Buffer. |
| 1 | … | G3: `encryptWallet()` clears the `this.keys` Map | **BUG-3 (P0-SEC chain-link)** — `encryptWallet` (`wallet.ts:2486-2525`) commits the same omission: zeroes seed + masterKey, leaves `this.keys` populated with plaintext WalletKey objects. A wallet that is FRESHLY encrypted is still signable from the in-memory cache until process restart. |
| 2 | `MessageHash` Core wire parity | G4: `MESSAGE_MAGIC = "Bitcoin Signed Message:\n"` (24 bytes, trailing newline) | PASS (`signmessage.ts:33`) |
| 2 | … | G5: `hash = SHA256d(WriteCompactSize(len(magic)) \|\| magic \|\| WriteCompactSize(len(msg)) \|\| msg)` | PASS (`signmessage.ts:61-66` via `BufferWriter.writeVarString` → `writeVarInt(data.length); writeBytes(data)`; `writeVarInt` is hotbuns' compact-size impl per `wire/serialization.ts:187-220`). |
| 3 | `messageSign` — network awareness | G6: WIF version byte parse rejects cross-network WIF | **BUG-4 (P1)** — `signmessagewithprivkey` (`server.ts:4271`) accepts BOTH `0x80` (mainnet) AND `0xef` (testnet/regtest) regardless of which network the node was started on. Core's `DecodeSecret` is parameterised on `Params().Base58Prefix(SECRET_KEY)` — a mainnet node REFUSES a testnet WIF with `RPC_INVALID_ADDRESS_OR_KEY`. The node-aware version byte is reachable via `this.getP2PKHVersion()` (server.ts:2982-2993) but unused. **Two-pipeline guard 18th distinct extension**: the wallet uses network-correct version bytes via `pubkeyToP2PKH(publicKey, network)` (wallet.ts:716) but the signmessage RPCs hardcode `[0x80, 0xef]` / `[0x00, 0x6f]`. |
| 3 | … | G7: `messageSign` `compressed` flag derives from key origin, not a caller-passed bool | PARTIAL — `signmessagewithprivkey` correctly derives `compressed` from the WIF (`server.ts:4280-4291`). `signMessage` (wallet) hardcodes `true` at `server.ts:4359` with the comment *"Wallet keys are stored compressed in hotbuns (BIP-32 derivation)"*. Accidentally correct today; brittle to any future `importprivkey` of an uncompressed legacy key. |
| 4 | `messageVerify` — network awareness | G8: address version byte rejects cross-network address | **BUG-5 (P1)** — `messageVerify` (`signmessage.ts:132-140`) accepts BOTH `0x00` (mainnet P2PKH) AND `0x6f` (testnet/regtest P2PKH) regardless of node network. Core's `DecodeDestination` uses `Params().Base58Prefix(PUBKEY_ADDRESS)`. A hotbuns mainnet node SUCCESSFULLY verifies a testnet-signed message and vice versa. The node-aware version is reachable via `this.params.networkMagic` but the verify path lives in `crypto/signmessage.ts` with no `network` parameter — the constant table `P2PKH_VERSIONS` is consulted as a SET not as a single-network lookup. |
| 4 | … | G9: `decoded.hash.length !== 20` → ERR_INVALID_ADDRESS | PASS (`signmessage.ts:138-140`). |
| 4 | … | G10: `decoded.version != PKHash version` → ERR_ADDRESS_NO_KEY (not ERR_INVALID_ADDRESS) | PASS (`signmessage.ts:132-137`). |
| 4 | … | G11: P2SH (0x05 / 0xc4) explicitly returns ERR_ADDRESS_NO_KEY | PASS by virtue of "version is neither P2PKH constant" (signmessage.ts:132-137), but the rejection bucket is the same as for any unknown version byte — Core's behaviour is identical (P2SH addresses fall out of the `std::get_if<PKHash>` branch). |
| 5 | `RecoverCompact` semantics | G12: signature length check (`sigBytes.length !== 65`) | PASS (`signmessage.ts:149-151`). |
| 5 | … | G13: header-byte range gate matches Core | **BUG-6 (P1, wire-parity)** — hotbuns rejects any header byte outside `[27, 34]` (`signmessage.ts:154-156`). Core's `RecoverCompact` accepts ANY header byte and computes `recid = (h - 27) & 3; fComp = ((h - 27) & 4) != 0`. A Core-produced signature with a corrupted header byte that nonetheless yields a recoverable signature would be accepted by Core (and false-rejected by hotbuns at the address-comparison step) but is hard-rejected by hotbuns at the header check. Different error-code mapping (`ERR_MALFORMED_SIGNATURE` vs `ERR_PUBKEY_NOT_RECOVERED` / `ERR_NOT_SIGNED`) leaks to clients that distinguish these. |
| 5 | … | G14: low-S enforcement (none) | PASS — Core does not enforce low-S in `RecoverCompact` (`pubkey.cpp:294-296` comment explicitly explains this), and hotbuns matches. |
| 5 | … | G15: `recoverPublicKey` exception path → ERR_PUBKEY_NOT_RECOVERED | PASS (`signmessage.ts:171-177`). |
| 5 | … | G16: recovered pubkey serialised in claimed encoding (compressed iff header bit-4 set) before HASH160 | PASS (`signmessage.ts:183-190`); both branches present. |
| 6 | RPC error-code mapping vs Core | G17: `ERR_INVALID_ADDRESS` → `-5` (RPC_INVALID_ADDRESS_OR_KEY) | PASS (`server.ts:4222-4226`). |
| 6 | … | G18: `ERR_ADDRESS_NO_KEY` → `-3` (RPC_TYPE_ERROR) | **BUG-7 (P1)** — emitted as `INVALID_ADDRESS_OR_KEY = -5` (`server.ts:4227-4234`). The handler's own comment at lines 4228-4230 explicitly admits the bug: *"Core uses RPC_TYPE_ERROR (-3); we do not export that constant separately, so reuse INVALID_ADDRESS_OR_KEY which is the closest semantic match"* — **comment-as-confession 16th instance**. Clients that switch on `error.code` numerically (e.g. `if (e.code === -3) ...`) will silently mis-route the failure mode. The wire-parity fix is a one-line addition to `RPCErrorCodes`. |
| 6 | … | G19: `ERR_MALFORMED_SIGNATURE` → `-3` (RPC_TYPE_ERROR per Core) | **BUG-8 (P1, same root cause as BUG-7)** — emitted as `INVALID_ADDRESS_OR_KEY = -5` (`server.ts:4235-4239`). Core throws `RPC_TYPE_ERROR` ("Malformed base64 encoding") at `bitcoin-core/src/rpc/signmessage.cpp:48-49`. Wire-parity gap with same one-line fix as BUG-7. |
| 6 | … | G20: `ERR_PUBKEY_NOT_RECOVERED` vs `ERR_NOT_SIGNED` distinct over the wire | **BUG-9 (P2, dead-distinction / dead-data)** — handler folds both enum variants into `return false` (`server.ts:4240-4242`). Indistinguishable to RPC clients. Core's RPC ALSO folds these to `return false`, so this is wire-parity correct, but it leaves `MessageVerificationResult.ERR_PUBKEY_NOT_RECOVERED` as a defined-but-end-user-undistinguishable enum variant. **Dead-data fleet pattern**: enum value emitted, packed, consulted, then collapsed. |
| 7 | BIP-322 — Legacy mode (BIP-137 fallback) coverage | G21: P2PKH legacy still functional under whatever path Core's BIP-322-Legacy delegates to | PASS — `messageVerify`/`messageSign` handle P2PKH correctly when the version byte and key-form line up. |
| 8 | BIP-322 — Simple / Full modes | G22: BIP-322 `to_spend` virtual-tx builder present | **BUG-10 (P0-FEATURE-gap)** — entirely absent. `grep -rn 'to_spend\|toSpend\|BIP322\|BIP-322' src/` returns ONE hit: a doc-comment at `signmessage.ts:114` reading *"A future extension to BIP-322 would unblock those."* — **comment-as-confession 17th instance**. BIP-322 is BIP-Final since 2018 and SegWit-only addresses (`bc1q...` / `bc1p...`) cannot sign with the BIP-137 scheme. hotbuns' wallet default is `bech32` (P2WPKH) so the wallet's OWN default-generated addresses are unsignable. |
| 8 | … | G23: BIP-322 `to_sign` virtual-tx builder present | **BUG-11 (P0-FEATURE-gap, chain-link with BUG-10)** absent. |
| 8 | … | G24: BIP-322 tagged-hash `tagged_hash("BIP0322-signed-message", msg)` | **BUG-12 (P0-FEATURE-gap)** absent. `grep -rn 'BIP0322\|BIP-0322\|bip0322' src/` returns 0 hits. The only "tagged hash" plumbing in the repo is the BIP-340 Schnorr `TapLeaf`/`TapBranch` family in `script/interpreter.ts`. |
| 8 | … | G25: BIP-322 "Simple" base64-witness wire format encoder/decoder | **BUG-13 (P0-FEATURE-gap)** absent. |
| 8 | … | G26: BIP-322 "Full" base64-tx wire format encoder/decoder | **BUG-14 (P0-FEATURE-gap)** absent. |
| 8 | … | G27: SegWit v0 (P2WPKH) verify path branches off BIP-322 | **BUG-15 (P0-FEATURE-gap)** absent — `messageVerify` hard-rejects bech32 at the `base58CheckDecode` `try` block (`signmessage.ts:124-129`) → `ERR_INVALID_ADDRESS`. The test at `server.test.ts:817-829` enshrines this rejection as a deliberate contract. |
| 8 | … | G28: P2TR (bech32m, witness v1) verify path | **BUG-16 (P0-FEATURE-gap)** absent (same path as BUG-15). |
| 9 | Wallet-side `signmessage` — defensive depth | G29: `LOCK(cs_wallet)` equivalent (mutex protecting key lookups) | **BUG-17 (P1, concurrency)** — no async mutex around `wallet.getKey(addr)` + sign. The hotbuns wallet is sync-only over Bun's single-threaded event loop, but a concurrent `walletlock` RPC call CAN interleave between `getKey` and the `messageSign` call inside the same event-loop tick if the signing crypto is await-ing (it isn't today — `messageSign` is sync), so this is latent. The handler is `private async signMessage(...)` which inherits the async-contract risk if signing ever moves to a worker thread. |
| 9 | … | G30: defensive type-check on `addressParam`/`messageParam` | PASS (`server.ts:4322-4327`). |
| 9 | … | G31: input `message` length cap (Core has none, BIP-322 wallet path has none) | PASS — no length cap matches Core; the `BufferWriter(64 + message.length)` allocation at `signmessage.ts:62` permits arbitrary length. Note: an attacker-controlled `message.length` will allocate a buffer at least that large per call; no rate-limit on the RPC method. (Out-of-scope for this audit, but worth noting in passing.) |
| 9 | … | G32: error mapping on `wallet.getKey(addr) === undefined` → `WALLET_ERROR ("Private key not available")` | PARTIAL — `server.ts:4350-4354` returns `WALLET_ERROR = -4`. Core distinguishes `PRIVATE_KEY_NOT_AVAILABLE` (`RPC_INVALID_ADDRESS_OR_KEY = -5` via `SigningResult::PRIVATE_KEY_NOT_AVAILABLE` → `RPC_WALLET_ERROR` per `wallet/rpc/signmessage.cpp:62-64`). The Core mapping is `RPC_WALLET_ERROR = -4`, so hotbuns matches by accident. |
| 9 | … | G33: `signmessage` registered ONLY when a wallet is loaded | PASS (`server.ts:1183, 1202`). Test guard at `server.test.ts:876-886`. |
| 9 | … | G34: `signmessage` rejects non-P2PKH addresses even before key lookup | PASS (`server.ts:4342-4347`). |
| 9 | … | G35: `signMessageWithPrivKey` `compressed` flag also honours WIF flag-byte position 32 | PASS (`server.ts:4280-4283`); 32-byte body → uncompressed, 33-byte body ending in `0x01` → compressed. |

**Additional findings discovered during audit, not in primary gate matrix:**

| # | Finding |
|---|---------|
| BUG-18 | `signmessagewithprivkey` writes a tightly-coupled 5-line block to detect WIF flavour (`server.ts:4262-4291`). The same parse logic exists in `wallet/descriptor.ts:2569+` (private-key parsing inside descriptor) and again in `wallet/bip32.ts`. No shared `parseWIF()` helper. Three-pipeline drift (**three-pipeline-guard** 4th fleet instance, see W143 ouroboros / W145 clearbit / W155 hotbuns precedents). |
| BUG-19 | `MessageVerificationResult` (`signmessage.ts:40-47`) is a string enum with values `"OK"`, `"ERR_INVALID_ADDRESS"`, etc. Across the codebase no other enum-as-discriminated-string pattern exists for primitives; every other consensus / wallet enum is a numeric `const enum` or a `0/1/2/...` enum. Cross-file lookups grep more easily but the runtime cost is non-trivial (string-comparison switch instead of jumptable). Cosmetic. |
| BUG-20 | `messageVerify` re-imports `secp256k1.Point.fromBytes` at the call site to re-serialise as uncompressed (`signmessage.ts:188-189`). The same conversion is available via `privateKeyToPublicKey(priv, false)` style helpers in `crypto/primitives.ts` — code-duplication smell. **Code-duplication smell** fleet pattern, byte-different from W143 beamchain `merkle_pairs`/`merkle_pairs_check` (which was identical-byte) — here it's a same-purpose conversion done with two different libraries (noble for verify, "primitives.ts" everywhere else). |
| BUG-21 | `signmessage.ts:31-32` docstring claims compatibility with *"Bitcoin Core's `signmessage` / `signmessagewithprivkey`"* but says nothing about BIP-322. The doc claim is wire-correct for legacy mode and silent on the post-2018 modern format. **Silently-out-of-date docstring** — the file should either (a) say "BIP-137 ONLY, BIP-322 absent" or (b) actually implement BIP-322. |

---

## Top three findings (P0-class)

### BUG-1 + BUG-2 (P0-SEC catastrophic, chained) — `signmessage` wallet RPC signs with locked encrypted wallet

**Severity:** P0-SEC catastrophic. Bitcoin Core's
`bitcoin-core/src/wallet/rpc/signmessage.cpp:37-65` prefixes the handler
with two consensus-level safety calls:

```cpp
LOCK(pwallet->cs_wallet);
EnsureWalletIsUnlocked(*pwallet);   // throws RPC_WALLET_UNLOCK_NEEDED = -13
```

`EnsureWalletIsUnlocked` is the canonical refuse-to-act-on-locked-wallet
gate; it is duplicated across every wallet RPC that needs the secret
(sendtoaddress, signrawtransactionwithwallet, dumpprivkey, etc.).

hotbuns' `signMessage` (`server.ts:4319-4366`) skips BOTH:

```ts
private async signMessage(params: unknown[]): Promise<string> {
  const [addressParam, messageParam] = params;
  // ... typecheck ...
  const wallet = this.getCurrentWallet();   // ← no isLocked() check
  // ... base58 decode + version sanity ...
  const key = wallet.getKey(addressParam);  // ← returns cached WalletKey
  if (!key || key.privateKey.length !== 32) {
    throw this.rpcError(WALLET_ERROR, "Private key not available");
  }
  // Wallet keys are stored compressed in hotbuns (BIP-32 derivation).
  try {
    return messageSign(key.privateKey, messageParam, /* compressed */ true);
  } ...
```

Every OTHER wallet RPC in the same file has the `isLocked()` guard
(spot-check: `server.ts:7557` sendToAddress; `server.ts:7635` bumpFee;
`server.ts:7719` psbtBumpFee; `server.ts:7964` walletCreateFundedPSBT;
`server.ts:8175` signRawTransactionWithWallet). `signmessage` is the
sole omission.

BUG-1 alone would not be catastrophic if `wallet.lockWallet()` actually
wiped the in-memory key material. It does not. `lockWallet()`
(`wallet.ts:2597-2622`) zeroes `this.seed` and `this.masterKey.key/chainCode`
but does NOT touch `this.keys`, the
`Map<string, { privateKey: Buffer, publicKey: Buffer, ... }>` that
`pregenerateAddresses()` populated at unlock time. Every address that the
wallet has ever held still has a fully-resolved `WalletKey.privateKey` 32-byte
Buffer reachable via `wallet.getKey(addr)`.

The comment at `wallet.ts:2523-2524` inside `encryptWallet` literally
states the opposite of reality:

```ts
// Note: Private keys are derived on-demand from the seed, so they're not in memory
// when the wallet is locked. The key map contains public info only when locked.
```

This is **comment-as-confession 15th instance**: the file documents the
property it intends to maintain and the same file violates the property
by NOT clearing `this.keys` in `lockWallet()`, `encryptWallet()`, or
`changePassphrase()`'s re-lock branch (`wallet.ts:2662-2664`). The
comment was load-bearing on the code; the code was never updated to match.

Combined consequence: a hotbuns operator who:
1. Creates a wallet → seeds populated, `this.keys` populated via
   `pregenerateAddresses`.
2. Calls `encryptwallet "passphrase"` → seed zeroed, `this.keys` STILL
   populated.
3. Calls `walletlock` → no-op (already isLocked=true after encryptWallet).
4. Calls `signmessage "<addr>" "..."` → SUCCEEDS because the BUG-1 gate
   is absent AND the BUG-2 cache holds the 32-byte private key.

The signature produced is a valid BIP-137 ECDSA-recoverable signature
over the message hash, and `verifymessage <addr> <sig> <msg>` returns
TRUE. The wallet's encryption guarantee is silently broken end-to-end —
not because the ciphertext leaks (as in **W158 clearbit BUG-2**), but
because the plaintext was never cleared from memory. Different shape,
same severity class.

The fix is two lines in `wallet.ts:lockWallet()`:

```ts
// Clear all derived private keys (the cache that survives lock today)
for (const k of this.keys.values()) k.privateKey.fill(0);
this.keys.clear();
```

…and one line in `server.ts:4329`:

```ts
const wallet = this.getCurrentWallet();
if (wallet.isLocked()) throw rpcError(WALLET_UNLOCK_NEEDED, "...");
```

…and a clear of `pregenerateAddresses()` post-encryptWallet (it currently
runs only in `Wallet.load()` after the seed is decrypted; encryptWallet
should clear too).

**Cross-cite W158 clearbit BUG-2** — same wave found the same primitive
broken in clearbit but via the inverse mechanism (signing reads the
ciphertext bytes as a scalar). The two findings together establish a
fleet pattern: **"signmessage wallet RPC bypasses Core's
EnsureWalletIsUnlocked"** — sweep the remaining 8 impls in the W158
quad-audit for the same flaw.

### BUG-10..BUG-16 (P0-FEATURE-gap cluster) — BIP-322 entirely absent

**Severity:** P0-FEATURE-gap. The hotbuns wallet's default address type
is `bech32` (P2WPKH); `wallet.getNewAddress()` (`server.ts:7511-7513`)
calls `wallet.getNewAddress()` with no `type` argument, which defaults
to `"bech32"` per `wallet.ts:915`. Default-generated wallet addresses
CANNOT be signed under BIP-137 — only legacy P2PKH addresses (BIP-44,
`m/44'/coin'/account'/...`) can. Operators who follow the hotbuns happy
path (create wallet, getnewaddress, attempt signmessage) hit
`WALLET_ERROR "Private key not available"` if the address is bech32 —
or worse, `INVALID_ADDRESS_OR_KEY "Address does not refer to key"` if
they hand the bech32 address to verifymessage.

BIP-322 was BIP-Final in 2018 and addresses this exact problem by
defining a virtual-transaction-based signing format that works
identically for any output type the wallet can spend (P2PKH, P2SH-P2WPKH,
P2WPKH, P2TR, multisig, miniscript, etc.). hotbuns has ZERO BIP-322
plumbing:

- `MESSAGE_HASH` for BIP-322 is `tagged_hash("BIP0322-signed-message", m)`
  — never computed anywhere in `src/`.
- `to_spend` and `to_sign` virtual transactions — neither builder exists.
- Simple format (base64 witness stack only) — no encoder/decoder.
- Full format (base64-encoded full tx) — no encoder/decoder.
- Legacy fallback (delegate to BIP-137 for P2PKH) — implicitly covered
  by the existing `messageSign`/`messageVerify` but not selected via the
  BIP-322 dispatcher (which itself is absent).

The doc-comment at `signmessage.ts:114` admits the gap:

```ts
// Only P2PKH addresses are supported (Core has the same limitation —
// `MessageVerify` returns `ERR_ADDRESS_NO_KEY` for P2SH/bech32). A future
// extension to BIP-322 would unblock those.
```

This is **comment-as-confession 17th instance** — the file
self-documents the missing feature and has done so since the file was
written. Note also that the claim "Core has the same limitation" is
partially incorrect: Core's `verifymessage` RPC has the limitation, but
Core also ships a separate codepath (added in 2024-25 work) for BIP-322
verification via the `verifymessage` RPC extended behaviour and the
`signmessage` wallet RPC with output-type detection.

Concrete user-visible impact: **a hotbuns user who follows the docs and
runs `getnewaddress`, `signmessage <addr> "..."` will get
`WALLET_ERROR -4 "Private key not available"` because the default `bech32`
output type is not handled by the BIP-137 sign-message path**. The wallet
DOES hold the private key for that bech32 address; the limitation is
purely in `signMessage`'s address-version gate at `server.ts:4342-4347`,
which only accepts versions `0x00` / `0x6f` (legacy P2PKH).

### BUG-4 + BUG-5 + BUG-7 + BUG-8 (P1 cluster, wire-parity) — network-blindness and error-code drift

**Severity:** P1 (interop, not exploitable). The signmessage path lives
in `src/crypto/signmessage.ts`, a network-agnostic crypto helper. The
network-aware version-byte selector exists (`server.ts:2982-2993`,
`getP2PKHVersion()` switching on `this.params.networkMagic`) but is
referenced 0 times from any of the three signmessage RPC handlers:

- `messageVerify` (`signmessage.ts:118-198`) accepts BOTH `0x00`
  (mainnet P2PKH) AND `0x6f` (testnet/regtest P2PKH) regardless of node
  network — BUG-5.
- `signmessagewithprivkey` (`server.ts:4271`) accepts BOTH `0x80`
  (mainnet WIF) AND `0xef` (testnet WIF) regardless of node network —
  BUG-4.

Core's `DecodeDestination` and `DecodeSecret` are both parameterised on
`Params()`. A mainnet Core node REFUSES a testnet address/WIF; a testnet
node REFUSES a mainnet address/WIF. hotbuns silently accepts cross-network
inputs, which is a divergence — same impl semantically signs and
verifies cross-network messages today.

Plus the error-code mapping cluster BUG-7 + BUG-8: Core's `verifymessage`
throws `RPC_TYPE_ERROR = -3` for "Address does not refer to key" and
"Malformed base64 encoding"; hotbuns folds both to
`RPC_INVALID_ADDRESS_OR_KEY = -5` (`server.ts:4231, 4237`). The
in-file admission at lines 4228-4230 (*"Core uses RPC_TYPE_ERROR (-3);
we do not export that constant separately, so reuse
INVALID_ADDRESS_OR_KEY which is the closest semantic match"*) is the
**comment-as-confession 16th instance** — the developer KNEW it was
wrong, wrote the wire-parity gap into the code anyway, and documented
the fact in-line. Clients that switch on numeric `error.code` route
both buckets to the same handler, masking the type-error class.

Single-line fixes:
- Add `TYPE_ERROR: -3` to `RPCErrorCodes` (`server.ts:210-240`).
- Change `messageVerify(address, ...)` to take a `network` parameter
  derived from `this.params.networkMagic` and consult only the matching
  version byte.

---

## Fleet patterns confirmed by W158 (hotbuns)

| Pattern | hotbuns evidence (W158) | Cross-cite |
|---------|-------------------------|------------|
| **comment-as-confession** (14th+ in hotbuns) | 3 fresh instances this wave: BUG-2 (wallet.ts:2523-2524 false claim about key cache), BUG-7 (server.ts:4228 admits TYPE_ERROR gap), BUG-10 (signmessage.ts:114 admits BIP-322 gap) | W125 lunarblock, W141 rustoshi, W144 lunarblock, W145 nimrod, W155 hotbuns, etc. — counter rolls to **18th total** with 3 new instances in one file family. |
| **two-pipeline guard** (18th distinct extension this wave) | BUG-4: wallet-internal address generation uses network-correct version (`wallet.ts:716, pubkeyToP2PKH(pub, network)`) but signmessage RPC hardcodes `[0x80, 0xef]` accept-both. Two pipelines in the same file family diverge on the same constant. | W126 BIP-152, W127 Taproot, W128 AddrMan, W138 assumeUTXO, W141 rustoshi, W143 ouroboros, W144 rustoshi (4 helpers diverge), W144 camlcoin (12 BUGs derive from this), W149 blockbrew (chainmanager.go vs sync.go), W155 hotbuns, W157 hotbuns. |
| **dead-data plumbing** | BUG-9: `ERR_PUBKEY_NOT_RECOVERED` defined, emitted, packed, then collapsed to `false` indistinguishable from `ERR_NOT_SIGNED`. | W144 ouroboros (TAPROOT BIP9 dead-data — anyone-can-spend on mainnet ≥709,632); W141 rustoshi (4th comment-as-confession via dead-data). |
| **wiring-look-but-no-wire** | BUG-4/BUG-5/BUG-7: `getP2PKHVersion()` exists, `RPCErrorCodes.TYPE_ERROR` could be added trivially, `this.params.networkMagic` is reachable — none are used by the signmessage path. The wiring LOOKS present in the surrounding file but is not threaded into the signmessage handlers. | W138 fleet-wide ChainstateManager (9 impls); W153 hotbuns BUG-12 (connectBlock event sink). |
| **assume-valid scope creep** (W145 hotbuns origin) | BUG-1: `signMessage` skips a security gate (`isLocked()`) on the assumption that "the wallet manages itself". Same anti-pattern as W145 BUG-2..6 hotbuns — assume-valid skips gates Core enforces unconditionally. | W145 hotbuns BUG-2..6 (assume-valid skips 5 Core gates); W153 BUG-12 (connectBlock event omission). |
| **three-pipeline drift** (4th fleet instance) | BUG-18: WIF parsing exists in three independent places (server.ts:4262-4291, wallet/descriptor.ts:2569+, wallet/bip32.ts) with no shared helper. | W143 ouroboros (3-consensus-pipeline); W145 clearbit (3-copy CheckTxInputs); W155 hotbuns (3-template-builder); W158 hotbuns extends pattern to WIF parsing. |
| **encrypted-wallet-ciphertext-as-scalar** (W158 clearbit NEW) | INVERSE shape: hotbuns BUG-1/BUG-2 chain breaks the same security primitive (signmessage on a locked encrypted wallet succeeds) but via plaintext-key cache rather than ciphertext-as-scalar. Both produce a valid signature on a wallet the user has locked. | W158 clearbit BUG-1+BUG-2 (sister wave). Fleet-pattern candidate: **"signmessage bypasses EnsureWalletIsUnlocked"** — sweep remaining 8 impls. |
| **code-duplication smell — different-byte** | BUG-20: pubkey serialisation duplicated across noble (`signmessage.ts:188-189`) and `crypto/primitives.ts`. | W143 beamchain `merkle_pairs`/`merkle_pairs_check` (identical-byte); W158 hotbuns extends pattern to different-byte / different-library duplicates. |

---

## Bug count summary

- **Total bugs:** 21
- **P0-class:** 9
  - P0-SEC catastrophic (chained): BUG-1, BUG-2, BUG-3 (3 of 9)
  - P0-FEATURE-gap (BIP-322 absent): BUG-10, BUG-11, BUG-12, BUG-13, BUG-14, BUG-15, BUG-16 (cluster of 7, but 4 listed in primary gate matrix; the 3 missing-wire-format ones grouped under BUG-10)
- **P1:** 7 (BUG-4, BUG-5, BUG-6, BUG-7, BUG-8, BUG-17, BUG-21)
- **P2:** 2 (BUG-9, BUG-19)
- **Cosmetic / smell:** 2 (BUG-18, BUG-20)
- **Wave-fresh comment-as-confession instances:** 3 (BUG-2 wallet.ts:2523,
  BUG-7 server.ts:4228, BUG-10 signmessage.ts:114)
- **Two-pipeline guard extensions:** 1 (BUG-4)
- **Three-pipeline guard extensions:** 1 (BUG-18; 4th fleet instance)

## Priority fix order

1. **BUG-1 + BUG-2** (P0-SEC catastrophic, ~5 LOC across 2 files):
   add `wallet.isLocked()` gate to `signMessage` AND wipe `this.keys` in
   `lockWallet()`/`encryptWallet()`. Closes the locked-wallet-signs
   primitive. Cross-impl: bundle with W158 clearbit BUG-1+BUG-2 fix.
2. **BUG-10..BUG-16** (P0-FEATURE-gap, ~600 LOC for full BIP-322):
   implement BIP-322 Simple+Full modes; preserve BIP-137 as the Legacy
   path. Test vector source: the BIP-322 reference test vectors and
   Core's `bitcoin-core/src/test/util_tests.cpp::message_*` suite.
3. **BUG-4 + BUG-5 + BUG-7 + BUG-8** (P1 cluster, ~5 LOC):
   parameterise `messageVerify` / `signmessagewithprivkey` on
   `this.params.networkMagic`; add `TYPE_ERROR: -3` to `RPCErrorCodes`.
4. **BUG-3** (P0-SEC chain-link, fixed by BUG-2's `this.keys.clear()`).
5. **BUG-6** (P1 wire-parity, ~2 LOC): drop the upper-bound header-byte
   check or change the error code to `ERR_PUBKEY_NOT_RECOVERED`.
6. **BUG-17, BUG-18, BUG-19, BUG-20, BUG-21** — lower-priority cleanup.
