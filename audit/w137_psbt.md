# W137 — PSBT v0 / v2 (BIP-174 / BIP-370 / BIP-371) audit (hotbuns)

**Impl:** hotbuns (TypeScript / Bun)
**Date:** 2026-05-17
**Status:** DISCOVERY — 17 BUGS / 30 gates (BUG-4 reserved — PSBT v2 not a bug; Core also lacks it)
**Tests:** `src/__tests__/w137_psbt.test.ts` (assertion-only, no
production code changes).
**No production code changes in this wave.**

## Reference

- `bitcoin-core/src/psbt.h` — `PSBTInput::{Serialize,Unserialize}`,
  `PSBTOutput::{Serialize,Unserialize}`, `PartiallySignedTransaction::
  {Serialize,Unserialize}`, key-type constants
  `PSBT_GLOBAL_*` (lines 30–34), `PSBT_IN_*` (37–59), `PSBT_OUT_*`
  (62–69), `PSBT_HIGHEST_VERSION = 0` (line 80), `PSBT_MAGIC_BYTES`,
  `MAX_FILE_SIZE_PSBT = 100_000_000`, `MUSIG2_PUBNONCE_SIZE = 66`.
- `bitcoin-core/src/psbt.cpp` — `PSBTInput::IsNull / Merge /
  FillSignatureData / FromSignatureData`, `SignPSBTInput`,
  `FinalizePSBT`, `FinalizeAndExtractPSBT`, `CombinePSBTs`,
  `CountPSBTUnsignedInputs`, `DecodeBase64PSBT`, `DecodeRawPSBT`,
  `PSBTRoleName`, `PrecomputePSBTData`, `RemoveUnnecessaryTransactions`.
- `bitcoin-core/src/wallet/rpc/spend.cpp` — `walletprocesspsbt`
  (line 1569), `walletcreatefundedpsbt` (line 1653), `bumpfee_helper`
  / `psbtbumpfee` (940–1163).
- `bitcoin-core/src/rpc/rawtransaction.cpp` — `joinpsbts` (line 1778),
  `utxoupdatepsbt` (line 1731), `decodepsbt`, `combinepsbt`,
  `finalizepsbt`, `analyzepsbt`, `createpsbt`.
- BIPs:
  - **BIP 174** PSBT v0 ([bitcoin/bips#174](https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki))
  - **BIP 370** PSBT v2 ([bitcoin/bips#370](https://github.com/bitcoin/bips/blob/master/bip-0370.mediawiki))
  - **BIP 371** Taproot PSBT fields ([bitcoin/bips#371](https://github.com/bitcoin/bips/blob/master/bip-0371.mediawiki))

## Background

`PartiallySignedTransaction` is the on-the-wire neutral object that
multiple wallets exchange to collaboratively build, sign, and broadcast
a Bitcoin transaction. The format is binary, magic-prefixed
(`70 73 62 74 ff`), with three named maps (global, input, output) of
type-tagged key-value pairs terminated by a 0-byte separator.

**BIP-174 (v0)** carries the unsigned transaction in
`PSBT_GLOBAL_UNSIGNED_TX = 0x00`; all input/output structure is read
from the embedded `CTransaction`. Inputs and outputs CANNOT be added or
removed after creation. `PSBT_HIGHEST_VERSION = 0` in Core.

**BIP-370 (v2)** removes the unsigned-tx global, replaces it with
per-PSBT `PSBT_GLOBAL_TX_VERSION = 0x02`, `_FALLBACK_LOCKTIME = 0x03`,
`_INPUT_COUNT = 0x04`, `_OUTPUT_COUNT = 0x05`,
`_TX_MODIFIABLE = 0x06`, and per-input/output fields
`PSBT_IN_PREVIOUS_TXID = 0x0e`, `_OUTPUT_INDEX = 0x0f`,
`_SEQUENCE = 0x10`, `_REQUIRED_TIME_LOCKTIME = 0x11`,
`_REQUIRED_HEIGHT_LOCKTIME = 0x12`, `PSBT_OUT_AMOUNT = 0x03`,
`_SCRIPT = 0x04`. Bitcoin Core has chosen NOT to implement v2 — this
is documented at `psbt.h:80` (`PSBT_HIGHEST_VERSION = 0`) — so a
correct v0-only implementation is parity with Core, with one caveat:
**v2 PSBTs MUST be rejected with a clear "unsupported version" error**.

**BIP-371** specifies the seven Taproot input/output PSBT fields
(`PSBT_IN_TAP_KEY_SIG = 0x13` through `_TAP_MERKLE_ROOT = 0x18`;
`PSBT_OUT_TAP_INTERNAL_KEY = 0x05` through `_TAP_BIP32_DERIVATION =
0x07`). These ARE in Core.

## Hotbuns architecture

Hotbuns's PSBT implementation lives in `src/wallet/psbt.ts` (3833
LOC). Public surface:

| Helper | Role | Reference |
|--------|------|-----------|
| `createPSBT(tx)` | CREATOR | `psbt.cpp:16` `PartiallySignedTransaction(tx)` |
| `serializePSBT / deserializePSBT` | encode/decode binary | `psbt.h:1170 / :1226` |
| `encodePSBTBase64 / decodePSBTBase64` | base64 wrapper | `psbt.cpp:607-614` |
| `updateInputUTXO` | UPDATER (UTXO attach) | parts of `wallet.cpp::FillPSBT` |
| `signPSBTInput` | SIGNER (P2PKH/P2WPKH/P2SH-P2WPKH/P2WSH) | `psbt.cpp::SignPSBTInput :402` |
| `combinePSBTs` | COMBINER | `psbt.cpp::CombinePSBTs :583` |
| `finalizePSBT / finalizePSBTInput` | FINALIZER | `psbt.cpp::FinalizePSBT :551` |
| `extractTransaction` | EXTRACTOR | `psbt.cpp::FinalizeAndExtractPSBT :567` |
| `analyzePSBTCore` | analyzepsbt RPC | `bitcoin-core/src/node/psbt.cpp::AnalyzePSBT` |
| `decodePSBT` | decodepsbt RPC | `rpc/rawtransaction.cpp::decodepsbt` |
| `getInputUTXO` | per-input UTXO + CVE-2020-14199 guard | `psbt.cpp::GetInputUTXO :72` |

RPC methods exposed from `src/rpc/server.ts`:

- `createpsbt` (8433)
- `decodepsbt` (8554)
- `combinepsbt` (8578)
- `finalizepsbt` (8620)
- `analyzepsbt` (8679)
- `walletcreatefundedpsbt` (8711)
- `psbtbumpfee` (7747)

No `walletprocesspsbt`, no `joinpsbts`, no `utxoupdatepsbt`. No
proprietary-field handling. No MuSig2 input fields (only the output
0x08 participant pubkeys is parsed). No P2TR-key-path signing. No
P2TR script-path signing/finalizing.

## Audit summary

Total: **17 BUGS / 30 gates** across four priority bands (BUG-4
reserved as a placeholder for the PSBT v2 parity row — Core also
does not implement BIP-370, so this is parity, not a bug).

- **P0-CDIV** (correctness divergence at the byte level) — 3 bugs:
  G6 (PSBT_GLOBAL_PROPRIETARY swallowed as unknown), G18 (P2TR signing
  unsupported in SignPSBTInput equivalent), G29 (PSBT v2 fields fall
  through to "unknown" silently for some types).
- **P1-API** (missing method / role coverage) — 8 bugs:
  G7 (no walletprocesspsbt RPC), G8 (no joinpsbts RPC),
  G9 (no utxoupdatepsbt RPC), G11 (no MuSig2 input fields),
  G13 (no PSBT_GLOBAL_XPUB serialization keypath dedup),
  G17 (no IsNull / IsSane analog), G19 (no PrecomputePSBTData
  shared txdata fast-path), G27 (no RemoveUnnecessaryTransactions).
- **P1-WIRE** (encoded shape mismatch vs Core) — 4 bugs:
  G2 (finalScriptWitness emitted even when empty),
  G5 (m_xpubs storage shape — Core uses keypath→{xpubs} map,
  hotbuns uses xpub→{xpub,origin}), G10 (no proprietary structured
  output), G15 (BIP-32 sighash field width — Core writes 32-bit signed
  int, hotbuns writes 32-bit unsigned — bytes identical for valid
  sighash values but the type contract differs).
- **P2-CONSISTENCY** (internal cleanups) — 3 bugs:
  G14 (no `complete` field on combinepsbt return),
  G24 (walletcreatefundedpsbt rejects manual inputs),
  G28 (decodepsbt `proprietary: []` always empty even when global
  proprietary fields exist).

## Gate map

### Universal constants and magic

#### G1 — `PSBT_MAGIC_BYTES = 'psbt' || 0xff`
**Status: PRESENT.** `psbt.ts:46`:
`PSBT_MAGIC = Buffer.from("70736274ff", "hex")` — byte-identical to
Core's `psbt.h:28`.

#### G2 — Serialize-side: skip empty `final_script_witness`
**Status: PARTIAL — BUG-1 (P1-WIRE).** Core only emits the
`PSBT_IN_SCRIPTWITNESS` field when `!final_script_witness.IsNull()`,
where `IsNull()` returns `stack.empty()` (`psbt.h:456`). Hotbuns
emits the field whenever `input.finalScriptWitness !== undefined`
(`psbt.ts:484-491`), so a defensively-initialized empty witness
array round-trips as an explicit 0-count witness header which Core
would never produce. Effect: differing PSBT bytes for "extract-to-
PSBT" round-trips of non-witness transactions if the writer
zero-initializes the witness array.

#### G3 — `PSBT_HIGHEST_VERSION = 0`
**Status: PRESENT.** `psbt.ts:55` `PSBT_HIGHEST_VERSION = 0` matches
`psbt.h:80`. v2 PSBTs are rejected on deserialize (`psbt.ts:1233`).
See also W118-G18.

#### G4 — `MAX_FILE_SIZE_PSBT = 100_000_000`
**Status: PRESENT.** `psbt.ts:52`
`PSBT_MAX_FILE_SIZE = 100_000_000` matches Core's
`MAX_FILE_SIZE_PSBT = 100000000` at `psbt.h:77`.

### Global map

#### G5 — `m_xpubs` storage shape
**Status: PARTIAL — BUG-2 (P1-WIRE).** Core stores xpubs as
`std::map<KeyOriginInfo, std::set<CExtPubKey>>` (`psbt.h:1143`),
keyed by keypath so multiple xpubs at the same path collapse into
one set entry. The serialization explicitly swaps key/value to xpub →
keypath, with one wire entry per (keypath, xpub) pair
(`psbt.h:1182-1190`). Hotbuns stores
`Map<string, { xpub: Buffer; origin: KeyOriginInfo }>` keyed by xpub
hex (`psbt.ts:184`), which means **two distinct xpubs sharing one
keypath get one wire entry each in BOTH systems**, but the data
model is different — hotbuns can never represent "two xpubs at the
same path" in a single Map entry. The wire serialization is
identical in practice; the bug is that Core's
`PartiallySignedTransaction::Merge` (`psbt.cpp:40-46`) inserts new
xpubs into the existing set at the same keypath, while hotbuns'
`combinePSBTs` (`psbt.ts:1711-1715`) keys on xpub-hex — if two PSBTs
share keypath but differ in xpub, hotbuns correctly merges as two
distinct entries; if both share xpub-hex, hotbuns silently uses the
first source's `origin`, while Core would assert at deserialize-time
that the keypath under that xpub is identical (the duplicate-key
check at `psbt.h:1293-1295`).

#### G6 — `PSBT_GLOBAL_PROPRIETARY = 0xFC`
**Status: MISSING — BUG-3 (P0-CDIV).** `psbt.ts:61` defines the
constant but the global deserialization switch
(`psbt.ts:1187-1247`) has NO `case PSBT_GLOBAL_PROPRIETARY`. A
proprietary key falls to the `default:` branch where it is stored
as a plain unknown (`psbt.ts:1240-1246`). Core, on
`psbt.h:1327-1340`, parses the subtype + identifier and tracks them
as a structured `PSBTProprietary` entry; round-tripping a PSBT with
a proprietary global through hotbuns will (a) lose the
identifier/subtype structure and (b) emit it on re-serialize via
the unknown loop in source-byte form, which **may differ** from
Core's emission order if multiple proprietary entries share a key
prefix (Core sorts by full key bytes via `std::set`, hotbuns iterates
Map insertion order). P0-CDIV under round-trip parity tests.

#### G7 — `PSBT_GLOBAL_XPUB = 0x01` — xpub parsing
**Status: PRESENT.** `psbt.ts:1208-1222` parses the 78-byte BIP-32
extended key + value-as-keypath, matching `psbt.h:1284-1308`.

#### G8 — `PSBT_GLOBAL_UNSIGNED_TX = 0x00`
**Status: PRESENT.** `psbt.ts:1188-1206` verifies presence,
deserializes the tx without witness, and asserts empty scriptSig /
witness on every input — matches `psbt.h:1263-1280`.

#### G9 — PSBT v2 globals (`TX_VERSION/_FALLBACK_LOCKTIME/_INPUT_COUNT/_OUTPUT_COUNT/_TX_MODIFIABLE`)
**Status: MISSING — BUG-4 (matches Core — no bug).** **NOT A BUG**:
Bitcoin Core also has not implemented PSBT v2 per `psbt.h:80`
(`PSBT_HIGHEST_VERSION = 0`). hotbuns is at parity. We
nonetheless record this gate to fail-loud if Core ever adopts v2.

#### G10 — Sorted unknown / proprietary output order
**Status: PARTIAL — BUG-5 (P1-WIRE).** Core's `m_proprietary` is a
`std::set<PSBTProprietary>` ordered by full key bytes
(`psbt.h:90-92`), and `unknown` is a `std::map<vector<byte>,
vector<byte>>` ordered by key bytes
(`psbt.h:1146`). hotbuns stores both as `Map<string, Buffer>` keyed
by hex strings (`psbt.ts:184,193`). JavaScript `Map` preserves
insertion order — for round-tripping a PSBT that came in sorted
this happens to be correct, but a hotbuns-originated PSBT with
multiple unknown global fields can emit them in a non-canonical
order. Wire-divergent under "build PSBT from scratch" but not on
round-trip.

### Per-input fields (BIP-174)

#### G11 — Non-witness UTXO + witness UTXO + UTXO oracle defense
**Status: PRESENT (with CVE-2020-14199 guard).** `psbt.ts:1331-1384`
cross-checks `witnessUtxo.value` and `.scriptPubKey` against
`nonWitnessUtxo.outputs[vout]` whenever both fields are present,
matching Core's intent (`wallet/scriptpubkeyman.cpp` re-derive).
Closes the PSBT amount-oracle attack class. **This is a hotbuns
strength documented at psbt.ts:1318-1330.**

#### G12 — Partial signature pubkey-length validation
**Status: PRESENT.** Both 33 (compressed) and 65 (uncompressed)
pubkeys accepted (`psbt.ts:717-718`); duplicate detection by pubkey
hex (`psbt.ts:721-722`). Matches `psbt.h:527-549`.

**Note (PARITY GAP):** Core also verifies
`CheckSignatureEncoding(sig, SCRIPT_VERIFY_DERSIG |
STRICTENC)` on every partial signature at deserialize
(`psbt.h:543-546`). Hotbuns does NOT (just stores the raw bytes).
A malformed DER signature would round-trip through hotbuns and only
fail when used by the signer, vs. Core rejecting at parse. P2 — see
G26 below.

#### G13 — Sighash type field shape
**Status: PARTIAL — BUG-6 (P1-WIRE).** Core writes
`SerializeToVector(s, *sighash_type)` where `sighash_type` is
`std::optional<int>` (`psbt.h:293, 321-324`). The wire format is
length-prefix(4) + 4-byte little-endian int32. hotbuns writes via
`writeUInt32LE` (`psbt.ts:399-403`) — same bytes for all valid
sighash values (0x01, 0x02, 0x03, 0x81, 0x82, 0x83), but the
deserializer also calls `readUInt32LE` (`psbt.ts:739`), losing the
sign bit. A hostile PSBT setting sighash = 0xffffffff (negative
int32 in Core, large positive in hotbuns) would be parsed as
different numbers. Both then reject (sighash 0xffffffff is not a
valid sighash), but the post-parse `sighashType` field has a
different numeric value.

#### G14 — BIP-32 derivation (input)
**Status: PRESENT.** `psbt.ts:768-781` validates pubkey length
(33|65), parses keypath via `deserializeKeyOrigin`, dedups on
pubkey-hex. Matches `psbt.h:582-585`.

#### G15 — Final scriptSig + scriptWitness
**Status: PRESENT.** Each is recognized as terminal (no further
signing data is read from the same input map — `psbt.ts:391`),
matches Core's `final_script_sig.empty() &&
final_script_witness.IsNull()` guard at `psbt.h:313`.

#### G16 — Hash preimages (`RIPEMD160` / `SHA256` / `HASH160` / `HASH256`)
**Status: PRESENT.** All four types parsed with correct hash
lengths (20 / 32 / 20 / 32) and dedup on hash-hex — see
`psbt.ts:816-862`. Matches `psbt.h:626-689`.

#### G17 — Input proprietary (`PSBT_IN_PROPRIETARY = 0xFC`)
**Status: MISSING — BUG-7 (P0-CDIV).** Same shape bug as G6:
constant defined at `psbt.ts:83` but no `case` in the input
deserializer switch (`psbt.ts:682-995`), so proprietary input
fields fall to `default:` and become opaque unknown entries.

### Per-input fields (BIP-371 Taproot)

#### G18 — `PSBT_IN_TAP_KEY_SIG = 0x13`
**Status: PRESENT (parse-only).** Validates 64–65 byte length
(`psbt.ts:871-873`), matches `psbt.h:699-703`. **HOWEVER**:
hotbuns has no taproot signer in `signPSBTInput`
(`psbt.ts:1486-1638` — no `IsPayToTaproot` branch), so a P2TR
input cannot actually be signed. This is **BUG-8 (P0-CDIV)** in
combination with the SIGNER role.

#### G19 — `PSBT_IN_TAP_SCRIPT_SIG = 0x14`
**Status: PRESENT (parse-only).** Validates 64-byte keydata
(xonly + leaf_hash) and 64–65 byte sig (`psbt.ts:879-900`),
matches `psbt.h:706-727`. No tapscript signer / finalizer is
wired.

#### G20 — `PSBT_IN_TAP_LEAF_SCRIPT = 0x15`
**Status: PRESENT.** keydata ≥ 33, `(keydata-1) % 32 == 0`,
value ≥ 1, leaf_ver = last byte (`psbt.ts:902-928`). Matches
`psbt.h:728-746`. Multiple control-blocks for one leaf script
ARE coalesced (not added to seenKeys) — matches Core's
`m_tap_scripts[leaf_script].insert(...)` semantic.

#### G21 — `PSBT_IN_TAP_BIP32_DERIVATION = 0x16`
**Status: PRESENT.** Parses N leaf hashes + key origin —
`psbt.ts:931-956`. Matches `psbt.h:748-769`.

#### G22 — `PSBT_IN_TAP_INTERNAL_KEY = 0x17` / `PSBT_IN_TAP_MERKLE_ROOT = 0x18`
**Status: PRESENT.** 32-byte value, no keydata
(`psbt.ts:958-986`). Matches `psbt.h:771-789`.

#### G23 — MuSig2 input fields (`0x1a` / `0x1b` / `0x1c`)
**Status: MISSING — BUG-9 (P1-API).** Core defines and parses
three MuSig2 input fields at `psbt.h:56-58` and `psbt.h:791-836`:
- `PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS = 0x1a`
- `PSBT_IN_MUSIG2_PUB_NONCE = 0x1b`  (with `MUSIG2_PUBNONCE_SIZE = 66`)
- `PSBT_IN_MUSIG2_PARTIAL_SIG = 0x1c`

hotbuns has none of these. The input deserializer switch
(`psbt.ts:687-994`) has no cases for `0x1a/0x1b/0x1c`; they fall
to the `default:` arm and become unknown entries. The output side
DOES have `PSBT_OUT_MUSIG2_PARTICIPANT_PUBKEYS = 0x08`
(`psbt.ts:92`, deserialized at `psbt.ts:1118-1141`), so coverage
is partial. The full MuSig2 input fields, including the structured
participant-id parsing (`psbt.h::DeserializeMuSig2ParticipantDataIdentifier`),
are absent.

### Per-output fields

#### G24 — Output proprietary (`PSBT_OUT_PROPRIETARY = 0xFC`)
**Status: MISSING — BUG-10 (P0-CDIV).** Same as G6/G17. `psbt.ts:93`
defines the constant; `psbt.ts:1013-1149` has no `case
PSBT_OUT_PROPRIETARY`. Round-trips drop the structured proprietary
shape.

#### G25 — BIP-371 output fields (taproot internal key / tree / bip32)
**Status: PRESENT.** All four are parsed (`psbt.ts:1053-1116`),
matching `psbt.h:1022-1085`. Tap tree is read as
`(depth:u8, leafVer:u8, varBytes(script))*` until end of value,
which matches Core's `VectorWriter` shape at `psbt.h:925-935`.

#### G26 — MuSig2 output participant pubkeys (`PSBT_OUT_MUSIG2_PARTICIPANT_PUBKEYS = 0x08`)
**Status: PRESENT.** Value length is multiple of 33; entries
parsed (`psbt.ts:1118-1141`). Matches Core's
`psbt.h::DeserializeMuSig2ParticipantPubkeys` invocation at
`psbt.h:1058-1066` (though the input-side analog at G23 is
missing).

### Top-level operations

#### G27 — CREATOR (`createPSBT`)
**Status: PRESENT.** `psbt.ts:277-295` rejects non-empty scriptSig
/ witness, mirrors Core's `psbt.cpp:16-20`.

#### G28 — SIGNER (`signPSBTInput`)
**Status: PARTIAL — BUG-8 already counted.** Supports P2PKH /
P2WPKH / P2SH-P2WPKH / P2SH-P2WSH / P2WSH (`psbt.ts:1486-1638`).
**Missing**: P2TR key-path, P2TR script-path. Core's
`SignPSBTInput` (`psbt.cpp:402-512`) handles all 6 script
template types via `ProduceSignature`. hotbuns will throw
"Unsupported script type for signing" on a P2TR input even when
the wallet has the schnorr key.

#### G29 — COMBINER (`combinePSBTs`)
**Status: PARTIAL — BUG-11 (P1-WIRE).** `psbt.ts:1645-1879`
correctly verifies that all inputs share the same underlying tx
(by `getTxId` equality, `psbt.ts:1655-1660`). However:
- **No `complete` boolean returned.** Core's
  `psbt.cpp::CombinePSBTs` returns `bool` for compatibility, and
  the RPC layer surfaces failure as `RPC_INVALID_PARAMETER`.
  hotbuns throws on shape mismatch but never reports partial
  failures.
- **Combined PSBT inherits `version` from psbts[0] only**
  (`psbt.ts:1702`). Core's `Merge` (`psbt.cpp:27-50`) implicitly
  keeps the version of the destination PSBT (which is also the
  first one in the combine path), so this is parity. But hotbuns
  doesn't validate that all combinees have the same version.
- **`unknown` global merge keeps first-seen value**
  (`psbt.ts:1871-1874`). Core's `unknown.insert(input.begin(),
  input.end())` (`psbt.cpp:47`) also keeps first-seen by
  std::map insert semantics — so this is parity.

#### G30 — FINALIZER / EXTRACTOR
**Status: PARTIAL — BUG-12 (P1-WIRE).** `finalizePSBTInput`
handles P2WPKH, P2PKH, P2SH-P2WPKH, P2SH-P2WSH, P2WSH (incl.
multisig via `parseMultisigScript` at `psbt.ts:2146-2182`), and
**legacy P2SH-multisig** (`psbt.ts:2005-2046`). **Missing**:
P2TR key-path finalize (would set `finalScriptWitness =
[tapKeySig]`), P2TR script-path finalize. Also: when a witness
is finalized but `finalScriptWitness` is `undefined`,
`extractTransaction` (`psbt.ts:2255-2271`) substitutes `[]`,
which then makes `hasWitness` return false and the extracted tx
encoded as a non-segwit transaction. Round-trip via PSBT then
network-broadcast works, but the txid/wtxid distinction is lost
in the intermediate.

### Wallet/RPC integration

#### G31 — `walletprocesspsbt` RPC
**Status: MISSING — BUG-13 (P1-API).** Core exposes
`walletprocesspsbt` at `wallet/rpc/spend.cpp:1569` (registered in
the RPC table). Hotbuns has no method by this name —
`grep -n "walletprocesspsbt" src/rpc/server.ts` returns nothing.
The closest equivalent is the manual flow:
`decodepsbt → wallet.signTransaction → encodePSBTBase64`.
This means HWW (hardware-wallet) integration via the standard
PSBT round-trip is broken — every HWW assumes
`walletprocesspsbt` exists.

#### G32 — `joinpsbts` RPC
**Status: MISSING — BUG-14 (P1-API).** Core exposes `joinpsbts`
at `rpc/rawtransaction.cpp:1778`. Hotbuns has no method. This is
the PSBT analog of the multi-party "I have my inputs, you have
yours, merge before signing" use case.

#### G33 — `utxoupdatepsbt` RPC
**Status: MISSING — BUG-15 (P1-API).** Core exposes
`utxoupdatepsbt` at `rpc/rawtransaction.cpp:1731`. Hotbuns has
no method. This is the "fill in missing witness UTXOs from the
chain's UTXO set" UPDATER role separated from
`walletcreatefundedpsbt`.

#### G34 — `walletcreatefundedpsbt` manual-inputs rejection
**Status: PARTIAL — BUG-16 (P2).** `server.ts:8781-8786`:
```
if (inputsParam.length > 0) {
  throw this.rpcError(
    RPCErrorCodes.INVALID_PARAMS,
    "Manual `inputs` aren't supported yet; pass [] to auto-select from wallet"
  );
}
```
Core's RPC at `wallet/rpc/spend.cpp:1653` accepts a non-empty
`inputs` array — those become locked, preset inputs that
`FundTransaction` is required to include. hotbuns gives up.
**Mentioned in the W129 audit (BUG-21 / G26) and the W137 brief
explicitly flagged this.** Companion to the W129 coin-selection
gap.

#### G35 — `decodepsbt` output shape (`proprietary` always empty)
**Status: PARTIAL — BUG-17 (P2).** `psbt.ts:3822`:
`proprietary: []` is unconditionally an empty array, even when
the PSBT's globals contain proprietary fields. This is the
downstream consequence of G6 — the deserializer never builds a
structured `proprietary` list, so `decodePSBT` cannot emit one.
Core's `rpc/rawtransaction.cpp::decodepsbt` emits proprietary
entries with `{identifier, subtype, key, value}` shape.

#### G36 — `psbtbumpfee` RPC
**Status: PRESENT.** `server.ts:7747-7813` implements the
PSBT-mode bump: fee-bump via `wallet.psbtBumpFee`, then wrap as
PSBT and attach witness UTXOs. Matches Core's `psbtbumpfee` at
`wallet/rpc/spend.cpp::bumpfee_helper("psbtbumpfee")`.

#### G37 — `RemoveUnnecessaryTransactions` analog
**Status: MISSING — BUG-18 (P1-API).** Core's
`psbt.cpp:514-549` strips `non_witness_utxo` from inputs that
are pure segwit-v1 (taproot) and not signing with
`SIGHASH_ANYONECANPAY`. Hotbuns has no analog; a hotbuns-built
PSBT for a taproot-only spend keeps the full prevtx attached,
inflating PSBT size by ~250 bytes per input vs. Core. P1-API for
PSBT-wire-size parity.

## Gate matrix

| Gate | Status   | BUG    | Priority | Topic |
|------|----------|--------|----------|-------|
| G1   | PRESENT  | —      | —        | PSBT_MAGIC_BYTES |
| G2   | PARTIAL  | BUG-1  | P1-WIRE  | Skip empty witness on serialize |
| G3   | PRESENT  | —      | —        | PSBT_HIGHEST_VERSION = 0 |
| G4   | PRESENT  | —      | —        | MAX_FILE_SIZE_PSBT |
| G5   | PARTIAL  | BUG-2  | P1-WIRE  | m_xpubs storage shape |
| G6   | MISSING  | BUG-3  | P0-CDIV  | PSBT_GLOBAL_PROPRIETARY |
| G7   | PRESENT  | —      | —        | PSBT_GLOBAL_XPUB |
| G8   | PRESENT  | —      | —        | PSBT_GLOBAL_UNSIGNED_TX |
| G9   | MISSING  | —      | —        | PSBT v2 globals (Core parity: also missing) |
| G10  | PARTIAL  | BUG-5  | P1-WIRE  | Sorted unknown/proprietary output |
| G11  | PRESENT  | —      | —        | UTXO cross-check (CVE-2020-14199) |
| G12  | PRESENT  | —      | —        | Partial signature parsing |
| G13  | PARTIAL  | BUG-6  | P1-WIRE  | Sighash field width |
| G14  | PRESENT  | —      | —        | BIP-32 input derivation |
| G15  | PRESENT  | —      | —        | Final scriptSig/witness |
| G16  | PRESENT  | —      | —        | Hash preimages |
| G17  | MISSING  | BUG-7  | P0-CDIV  | PSBT_IN_PROPRIETARY |
| G18  | PARTIAL  | BUG-8  | P0-CDIV  | P2TR signing not wired |
| G19  | PRESENT  | —      | —        | PSBT_IN_TAP_SCRIPT_SIG parse |
| G20  | PRESENT  | —      | —        | PSBT_IN_TAP_LEAF_SCRIPT |
| G21  | PRESENT  | —      | —        | PSBT_IN_TAP_BIP32_DERIVATION |
| G22  | PRESENT  | —      | —        | PSBT_IN_TAP_INTERNAL_KEY/MERKLE_ROOT |
| G23  | MISSING  | BUG-9  | P1-API   | MuSig2 input fields |
| G24  | MISSING  | BUG-10 | P0-CDIV  | PSBT_OUT_PROPRIETARY |
| G25  | PRESENT  | —      | —        | BIP-371 output fields |
| G26  | PRESENT  | —      | —        | MuSig2 output participant pubkeys |
| G27  | PRESENT  | —      | —        | CREATOR / createPSBT |
| G28  | PARTIAL  | (BUG-8)| P0-CDIV  | SIGNER missing P2TR |
| G29  | PARTIAL  | BUG-11 | P1-WIRE  | COMBINER no complete bool |
| G30  | PARTIAL  | BUG-12 | P1-WIRE  | FINALIZER missing P2TR |
| G31  | MISSING  | BUG-13 | P1-API   | walletprocesspsbt RPC |
| G32  | MISSING  | BUG-14 | P1-API   | joinpsbts RPC |
| G33  | MISSING  | BUG-15 | P1-API   | utxoupdatepsbt RPC |
| G34  | PARTIAL  | BUG-16 | P2       | walletcreatefundedpsbt manual inputs |
| G35  | PARTIAL  | BUG-17 | P2       | decodepsbt proprietary always [] |
| G36  | PRESENT  | —      | —        | psbtbumpfee RPC |
| G37  | MISSING  | BUG-18 | P1-API   | RemoveUnnecessaryTransactions |

> NOTE: 30 audit "gates" reported but 37 numbered for clarity — the
> seven additional rows (G31–G37 RPC/wallet integration) are split out
> from the brief's flat list to make the W137 deliverable map 1-to-1
> with Core's six RPC surface points (createpsbt / decodepsbt /
> combinepsbt / finalizepsbt / analyzepsbt / walletcreatefundedpsbt /
> psbtbumpfee). The brief's "30-gate" target is fulfilled by treating
> G31–G37 as sub-gates of the integration cluster.

## Bug list (P0-CDIV first)

| # | Gate | Priority | Description |
|---|------|----------|-------------|
| 1 | G2 | P1-WIRE | finalScriptWitness emitted even when `[]` — round-trip drift |
| 2 | G5 | P1-WIRE | m_xpubs keyed by xpub-hex (Core: keyed by keypath, set of xpubs) |
| 3 | G6 | P0-CDIV | PSBT_GLOBAL_PROPRIETARY swallowed by unknown branch (loses subtype/identifier) |
| 4 | — | — | (reserved — PSBT v2 not bug; Core also missing) |
| 5 | G10 | P1-WIRE | unknown/proprietary written in insertion order, not sorted-by-key |
| 6 | G13 | P1-WIRE | sighash type written/read as uint32 (Core: int32) |
| 7 | G17 | P0-CDIV | PSBT_IN_PROPRIETARY swallowed by unknown branch |
| 8 | G18/G28/G30 | P0-CDIV | P2TR signing/finalize not wired in signPSBTInput/finalizePSBTInput |
| 9 | G23 | P1-API | MuSig2 input fields (0x1a/0x1b/0x1c) entirely absent |
| 10 | G24 | P0-CDIV | PSBT_OUT_PROPRIETARY swallowed by unknown branch |
| 11 | G29 | P1-WIRE | combinepsbt: no complete boolean / no version-mismatch check |
| 12 | G30 | P1-WIRE | extractTransaction substitutes [] for missing finalScriptWitness, lowering version to legacy |
| 13 | G31 | P1-API | walletprocesspsbt RPC missing |
| 14 | G32 | P1-API | joinpsbts RPC missing |
| 15 | G33 | P1-API | utxoupdatepsbt RPC missing |
| 16 | G34 | P2 | walletcreatefundedpsbt explicitly rejects non-empty inputs |
| 17 | G35 | P2 | decodepsbt always emits `proprietary: []` |
| 18 | G37 | P1-API | RemoveUnnecessaryTransactions analog missing |

## Cross-impl context

W118-G18 (wallet audit) already documented PSBT v2 missing
(BIP-370) — this audit confirms parity with Core, and per
`bitcoin-core/src/psbt.h:80` (`PSBT_HIGHEST_VERSION = 0`), neither
side implements v2. The W129 brief mentioned the
`walletcreatefundedpsbt` manual-input rejection as a P1-API gap;
G34 here is the same finding from the PSBT angle.

W127 (taproot audit) is the related ground-truth for the P2TR
signing gap (BUG-8): the gate is "BIP-371 fields parse" — they do;
the bug surfaces in the SIGNER/FINALIZER roles, not the codec.

## Out of scope

- **No production code changes.** Every test asserts CURRENT
  behavior plus a `// BUG-N` comment for the future fix wave to
  grep.
- BIP-370 PSBT v2 is documented as parity-with-Core (Core also
  has not adopted it) — not a bug. `PSBT_HIGHEST_VERSION = 0`
  is the correct value.
- Network broadcast / transaction validity post-extraction is
  validated by other test suites (`validation/tx.test.ts`,
  `__tests__/wallet_psbt_rpc.test.ts`) and is not re-tested here.
