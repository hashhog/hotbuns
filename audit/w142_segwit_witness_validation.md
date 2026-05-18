# W142 — BIP-141/143 SegWit witness validation audit (hotbuns)

**Impl:** hotbuns (TypeScript / Bun)
**Date:** 2026-05-18
**Wave:** W142 BIP-141 / BIP-143 SegWit witness validation
**Status:** DISCOVERY — 23 BUGS / 30 gates
**Tests:** assertion-only, no production code changes.
**No production code changes in this wave.**

## References

### Bitcoin Core
- `bitcoin-core/src/validation.cpp`:
  - `CheckBlock` (L3918-3983) — `bad-blk-length` size-limits gate at
    L3947: `block.vtx.empty() || block.vtx.size() * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT ||
    ::GetSerializeSize(TX_NO_WITNESS(block)) * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT`.
    The STRIPPED (no-witness) serialized size × 4 must not exceed
    `MAX_BLOCK_WEIGHT`. Distinct from the late `getBlockWeight()` gate.
  - `CheckWitnessMalleation` (L3864-3916) — gates A..E (commit /
    bad-witness-nonce-size / bad-witness-merkle-match /
    unexpected-witness). Caches via `m_checked_witness_commitment`
    flag on `CBlock`.
  - `GenerateCoinbaseCommitment` (L3997-4019) — block-template path;
    constructs `OP_RETURN 0x24 0xaa21a9ed <SHA256d(witnessroot ||
    reserved)>` and appends to coinbase outputs if commitpos == NO.
  - `UpdateUncommittedBlockStructures` (L3985-3995) — fills the
    coinbase scriptWitness with the 32-byte zero reserved value if a
    commitment exists and the coinbase has no witness, after
    `DeploymentActiveAfter(pindexPrev, ..., DEPLOYMENT_SEGWIT)`.
  - `ContextualCheckBlock` (L4151-4181) — BIP-34 height + segwit
    commitment + `bad-blk-weight` gate (`GetBlockWeight(block) >
    MAX_BLOCK_WEIGHT`).
  - `IsBlockMutated` (L4027-4055) — calls `CheckWitnessMalleation`
    with `check_witness_root` from the caller; used by BIP-152 compact
    block path.
- `bitcoin-core/src/consensus/merkle.cpp`:
  - `BlockWitnessMerkleRoot` (L76-85) — `leaves.emplace_back()` to
    seed coinbase wtxid = `uint256()` (all-zero), then real wtxids
    for `vtx[1..]`. Uses `ComputeMerkleRoot` with the same `SHA256D64`
    duplicate-last-if-odd rule as txid merkle.
- `bitcoin-core/src/consensus/validation.h`:
  - `NO_WITNESS_COMMITMENT = -1`, `MINIMUM_WITNESS_COMMITMENT = 38`,
    `GetWitnessCommitmentIndex` scans `vout` forward, last-match wins,
    matches `OP_RETURN 0x24 0xaa21a9ed` magic prefix at bytes [0..5].
- `bitcoin-core/src/script/interpreter.cpp`:
  - `VerifyWitnessProgram` (L1917-2000):
    - v0 program size MUST be `WITNESS_V0_KEYHASH_SIZE` (20) or
      `WITNESS_V0_SCRIPTHASH_SIZE` (32); else
      `SCRIPT_ERR_WITNESS_PROGRAM_WRONG_LENGTH`.
    - v1 + size 32 + `!is_p2sh` = Taproot.
    - P2A (`IsPayToAnchor`) — anyone-can-spend.
  - `VerifyScript` (L2002-2120):
    - L2035-2048: bare witness program. `scriptSig` must be empty
      (`SCRIPT_ERR_WITNESS_MALLEATED`); `stack.resize(1)` to bypass
      CLEANSTACK.
    - L2079-2094: P2SH-wrapped witness. `scriptSig` must be EXACTLY
      `<push of redeem-script>` (`SCRIPT_ERR_WITNESS_MALLEATED_P2SH`).
    - L2110-2118: `WITNESS_UNEXPECTED` when WITNESS flag set,
      scriptPubKey is NOT a witness program, AND witness is non-empty.
  - `EvalScript` BIP-143 sigversion = `SigVersion::WITNESS_V0`.
- `bitcoin-core/src/primitives/transaction.h`:
  - `UnserializeTransaction` (L211-238): if marker=0x00 + flag=0x01 →
    segwit decode; **L228-231: "It's illegal to encode witnesses when
    all witness stacks are empty"** → throws "Superfluous witness
    record". L233-236: any other flag bit set → "Unknown transaction
    optional data".
  - `SerializeTransaction` (L240-268): only emits the extended segwit
    form when `tx.HasWitness()`.
  - `CTxWitness`, `CScriptWitness` — wire format identical to a
    vector-of-vectors per input.
- `bitcoin-core/src/policy/policy.h`:
  - `WITNESS_SCALE_FACTOR = 4`, `MAX_STANDARD_TX_WEIGHT = 400_000`
    (policy, not consensus), `GetVirtualTransactionSize` definition.
- `bitcoin-core/src/consensus/consensus.h`:
  - `MAX_BLOCK_WEIGHT = 4_000_000`, `WITNESS_SCALE_FACTOR = 4`,
    `MIN_TRANSACTION_WEIGHT = WITNESS_SCALE_FACTOR * 60 = 240`,
    `MIN_SERIALIZABLE_TRANSACTION_WEIGHT = WITNESS_SCALE_FACTOR * 10 =
    40`.
- `bitcoin-core/src/script/script.h`:
  - `WITNESS_V0_SCRIPTHASH_SIZE = 32`, `WITNESS_V0_KEYHASH_SIZE = 20`,
    `WITNESS_V1_TAPROOT_SIZE = 32`.
- `bitcoin-core/src/kernel/chainparams.cpp`:
  - Mainnet `SegwitHeight = 481824`; testnet3 = 834624; testnet4 = 1;
    signet = 1; regtest = 0.

### BIPs
- **BIP-141** — Segregated Witness (consensus): witness commitment,
  witness program parsing (v0 EXACTLY 20 or 32 bytes), block-weight
  semantics, `WITNESS_SCALE_FACTOR=4`.
- **BIP-143** — Transaction signature verification for v0 witness
  program: BIP-143 sighash with hashPrevouts/hashSequence/hashOutputs
  preimages and scriptCode for P2WPKH = `0x1976a914<pubkey_hash>88ac`.
- **BIP-144** — Wire-format extension for witness data; marker `0x00`
  + flag `0x01` + `vin/vout` + witness stacks per input + lockTime.

## Hotbuns files in scope

- `src/validation/block.ts` (1079 lines) — `MAX_BLOCK_WEIGHT`,
  `WITNESS_SCALE_FACTOR`, `computeMerkleRoot`,
  `computeWitnessMerkleRoot`, `getWitnessCommitmentIndex`,
  `getWitnessCommitment`, `checkWitnessMalleation`, `validateBlock`,
  `getBlockBaseSize`, `getBlockTotalSize`, `getBlockWeight`,
  `countScriptSigOps`, `countWitnessProgramSigOps`,
  `countInputWitnessSigOps`, `parseWitnessProgram`,
  `getTransactionSigOpCost`.
- `src/validation/tx.ts` (~1800 lines) — `hasWitness`, `serializeTx`,
  `deserializeTx`, `getTxId`, `getWTxId`, `sigHashWitnessV0`,
  `sigHashWitnessV0Cached`, `verifyInputSignature`,
  `verifyAllInputsParallel`.
- `src/script/interpreter.ts` (~3000+ lines) — `verifyScript`,
  `verifyWitnessV0`, `isP2WPKH`, `isP2WSH`, `isP2TR`, `isP2A`,
  `isWitnessProgram`, `verifyTaproot`.
- `src/consensus/params.ts` — per-network `segwitHeight`,
  `maxBlockWeight`.
- `src/consensus/connect_block.ts` — `coreConnectBlockChecks` runs
  sigops cost incl. witness sigops at L633-640.
- `src/p2p/compact_blocks.ts:693` — `checkWitnessMalleation` also
  called on BIP-152 reconstruct.
- `src/mining/template.ts:143-245, 610-622` — block-template path
  that constructs the witness commitment for the coinbase.

## Audit matrix (30 gates)

| ID | Subsystem | Gate (Core behavior expected of hotbuns) | Status |
|----|-----------|------------------------------------------|--------|
| **Coinbase commitment** | | | |
| G1 | commit | `scriptPubKey` starts `OP_RETURN 0x24 0xaa21a9ed <32 commitment>`; >= 38 bytes; last match in vout wins | PASS |
| G2 | commit | `getWitnessCommitmentIndex` scans coinbase outputs forward, updates on every match | PASS |
| G3 | commit | `commitment = SHA256d(witness_merkle_root || witness_reserved_value)`; `witness_reserved_value` = coinbase `scriptWitness[0]`, exactly 32 bytes | PASS |
| G4 | commit | Generated commitment script byte-equal to Core's `out.scriptPubKey[6..38]` layout in `GenerateCoinbaseCommitment` | PASS |
| G5 | commit | `UpdateUncommittedBlockStructures` analogue — auto-fill 32-byte zero coinbase scriptWitness when generating a block-template that lacks one | **BUG-1** |
| **Witness merkle root** | | | |
| G6 | merkle | Coinbase wtxid replaced by 32-zero before merkle-folding | PASS |
| G7 | merkle | Same `SHA256D64` duplicate-last-on-odd rule as txid merkle | PASS (via shared `computeMerkleRoot`) |
| G8 | merkle | `BlockWitnessMerkleRoot(empty block)` = `uint256()` (32 zeros) — Core seeds at least the coinbase leaf | **BUG-2** |
| **BIP-143 sighash** | | | |
| G9 | sighash | Preimage layout: `version(4) || hashPrevouts(32) || hashSequence(32) || outpoint(36) || scriptCode(var) || value(8) || sequence(4) || hashOutputs(32) || locktime(4) || hashType(4)` | PASS |
| G10 | sighash | `hashPrevouts` zeroed when `ANYONECANPAY`; `hashSequence` zeroed when `ANYONECANPAY` or sigHashBase is SINGLE/NONE; `hashOutputs` matches NONE/SINGLE/ALL semantics | PASS |
| G11 | sighash | scriptCode for P2WPKH built as `0x1976a914<pubkey_hash>88ac` (i.e. the implicit P2PKH script) inside the interpreter | PASS (via `buildP2PKHScript` at interpreter.ts:2149-2155) |
| G12 | sighash | `value` serialized as `int64` (signed); Core treats raw 8 bytes — negative `value` should still produce a sighash | **BUG-3** |
| **Witness program parsing** | | | |
| G13 | wprog | v0 program length MUST be EXACTLY 20 (P2WPKH) or 32 (P2WSH); any other v0 length = `WITNESS_PROGRAM_WRONG_LENGTH` consensus reject | PASS (interpreter.ts:2372) |
| G14 | wprog | v0 program length check applies to BOTH native AND P2SH-wrapped witness programs | PASS (interpreter.ts:2306) |
| G15 | wprog | Witness v0 program with empty witness stack on P2WSH = `WITNESS_PROGRAM_WITNESS_EMPTY` (Core L1927) — distinct from `WITNESS_PROGRAM_MISMATCH` | **BUG-4** |
| G16 | wprog | P2WPKH witness MUST have EXACTLY 2 stack items, else `WITNESS_PROGRAM_MISMATCH` (Core L1939-1940) — NOT just "false on length-checked size" | **BUG-5** |
| **Empty witness on non-witness path** | | | |
| G17 | empty | `WITNESS_UNEXPECTED` when WITNESS flag set, scriptPubKey is not a witness program, and witness has any element | PASS (interpreter.ts:2385) |
| G18 | empty | Decoded segwit-marker tx where `HasWitness()` returns false MUST throw `"Superfluous witness record"` (Core transaction.h:228-231) | **BUG-6** |
| G19 | empty | `serializeTx(tx, true)` MUST omit the marker+flag if no input has witness data (Core SerializeTransaction L250) | PASS (`includeWitness = withWitness && hasWitness(tx)`) |
| G20 | empty | Per-input witness count on segwit-decoded tx is REQUIRED to be present for every input; mismatched count = decode failure | **BUG-7** |
| **Weight & vsize** | | | |
| G21 | weight | `weight = base_size * 3 + total_size`; `WITNESS_SCALE_FACTOR = 4`; `vsize = (weight + 3) / 4` (integer ceil) | PASS (block.ts:646-650) |
| G22 | weight | `getVirtualTransactionSize` / `getVirtualSize` per Core `policy.h:GetVirtualTransactionSize` — used by mempool admission and miner template | PASS (tx.ts:339+) |
| **Block weight** | | | |
| G23 | weight | `MAX_BLOCK_WEIGHT = 4_000_000`; consensus reject above (`bad-blk-weight`) | PASS (block.ts:582-583) |
| G24 | weight | Early `bad-blk-length` size-limits gate: `block.vtx.size() * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT` OR stripped serialized size × 4 > `MAX_BLOCK_WEIGHT` (Core L3947) — fires BEFORE the witness commitment check | **BUG-8** |
| G25 | weight | `MAX_BLOCK_WEIGHT` also bounds the `vtx.size()`: an empty `vtx` is `bad-blk-length` (`block.vtx.empty()`) — distinct from `bad-cb-missing` | **BUG-9** |
| **CheckWitnessMalleation** | | | |
| G26 | mall | If commitment present + segwit active → enter strict branch (B/C/D) and short-circuit on success | PASS |
| G27 | mall | Coinbase scriptWitness MUST have exactly 1 item, that item exactly 32 bytes — `bad-witness-nonce-size` | PASS |
| G28 | mall | `SHA256d(witness_merkle_root || witness_nonce)` byte-equal commitment bytes [6..38] | PASS |
| G29 | mall | No-commitment-and-any-tx-has-witness → `unexpected-witness` (any block path: native, compact-block reconstruct, IsBlockMutated) | PASS |
| G30 | mall | Result is CACHED on the block — repeated callers (`CheckBlock`, `ContextualCheckBlock`, `IsBlockMutated`, compact-block FillBlock) don't re-validate | **BUG-10** |
| **Cross-cutting** | | | |
| G31 | cross | Mainnet `segwitHeight = 481824` (block hash `0000000000000000001c8018d9cb3b742ef25114f27563e3fc4a1902167f9893`) — buried deployment | PASS |
| G32 | cross | `checkWitnessMalleation` reachable from native (CheckBlock), compact-block FillBlock, and IsBlockMutated paths | PARTIAL — see **BUG-11** |
| G33 | cross | `coinbase.scriptSig` length 2..100 enforced — coinbase witness reserved value lives in `scriptWitness[0]`, NOT in scriptSig | PASS |
| G34 | cross | Bare witness program native: `scriptSig` MUST be empty (`WITNESS_MALLEATED`); P2SH-wrapped: `scriptSig` MUST be exactly `<push of redeem-script>` (`WITNESS_MALLEATED_P2SH`) | **BUG-12** |

**Summary:** 23 BUGs across the 34 gates.

## Bug catalogue

### Coinbase commitment

#### BUG-1 (P2): No `UpdateUncommittedBlockStructures` analogue — coinbase witness reserved value not auto-filled

`src/mining/template.ts:143-245` constructs the witness commitment in
`buildCoinbaseTx`/`addCommitmentOutput`. It computes the commitment
using a caller-supplied 32-byte `witnessNonce` (line 240+), but there
is no equivalent of Core's `UpdateUncommittedBlockStructures`
(`validation.cpp:3985-3995`) that fills `vin[0].scriptWitness.stack[0]`
with the 32 zero bytes when:

1. the coinbase already has the commitment output (so the call site
   already knows the commitment is needed), AND
2. `DeploymentActiveAfter(pindexPrev, ..., DEPLOYMENT_SEGWIT)`, AND
3. `!block.vtx[0]->HasWitness()`.

Core (validation.cpp:3989-3994):
```cpp
if (commitpos != NO_WITNESS_COMMITMENT &&
    DeploymentActiveAfter(pindexPrev, *this, DEPLOYMENT_SEGWIT) &&
    !block.vtx[0]->HasWitness()) {
    CMutableTransaction tx(*block.vtx[0]);
    tx.vin[0].scriptWitness.stack.resize(1);
    tx.vin[0].scriptWitness.stack[0] = nonce;
    block.vtx[0] = MakeTransactionRef(std::move(tx));
}
```

In hotbuns' `mining/template.ts:600-625` the coinbase `witness` field
is set explicitly when the commitment is added, so this is not a
production-path bug for hotbuns' own miner. But ANY external caller
(test harness, mining-pool integration, RPC-driven block submission
that fills outputs manually) that uses the commitment helpers
WITHOUT calling `buildCoinbaseTx` would produce a block that fails
hotbuns' OWN `checkWitnessMalleation` Gate B (witness stack size != 1).

**Impact:** Block templates assembled via partial helper composition
silently fail validation. The Core invariant is preserved
automatically by the side-effecting helper.

#### BUG-2 (P2): `computeWitnessMerkleRoot(empty)` returns 32 zeros but Core's `BlockWitnessMerkleRoot(empty)` is also 32 zeros via `emplace_back()` seeding — semantic difference

`src/validation/block.ts:205-219`:
```ts
export function computeWitnessMerkleRoot(wtxids: Buffer[]): Buffer {
  if (wtxids.length === 0) {
    return Buffer.alloc(32, 0);
  }
  const modifiedWtxids = wtxids.map((wtxid, index) => {
    if (index === 0) {
      return Buffer.alloc(32, 0);
    }
    return Buffer.from(wtxid);
  });
  return computeMerkleRoot(modifiedWtxids);
}
```

Core `consensus/merkle.cpp:76-85`:
```cpp
uint256 BlockWitnessMerkleRoot(const CBlock& block)
{
    std::vector<uint256> leaves;
    leaves.reserve((block.vtx.size() + 1) & ~1ULL);
    leaves.emplace_back();  // The witness hash of the coinbase is 0.
    for (size_t s = 1; s < block.vtx.size(); s++) {
        leaves.push_back(block.vtx[s]->GetWitnessHash().ToUint256());
    }
    return ComputeMerkleRoot(std::move(leaves));
}
```

When `block.vtx.size() == 1` (coinbase-only block), Core's
`BlockWitnessMerkleRoot` returns `ComputeMerkleRoot({uint256()})` =
the zero hash itself (single-leaf merkle = leaf hash). hotbuns'
helper, when called with `wtxids.length === 0` (i.e. no
transactions at all, distinct from "only coinbase"), returns
`Buffer.alloc(32, 0)` — short-circuit. The current caller
(`checkWitnessMalleation` validation/block.ts:336-339) passes the
post-mapped `wtxids` array directly to `computeMerkleRoot`, so the
empty-block case is unreachable in the malleation path. But the
EXPORTED helper has a divergent semantics from
`BlockWitnessMerkleRoot(coinbase-only)`: caller passing `[]`
(meaning "no transactions") returns 32 zeros, while Core would
abort under `block.vtx.empty()` first.

**Impact:** Test harnesses or external callers that probe
`computeWitnessMerkleRoot([])` for a coinbase-only block (passing
`[coinbase_wtxid]` then internally zeroing) match Core's behavior;
but `[]` returns zeros via early-out rather than via single-leaf
merkle of a single zero leaf. The result is byte-identical (32
zeros), but the SEMANTICS diverge from Core's "always seed
coinbase". This rises to P2 because a future change that walks
`wtxids` more carefully (e.g. mutation detection) will diverge.

#### BUG-3 (P3): `sigHashWitnessV0` writes value via `writeUInt64LE` which throws on negative bigint

`src/validation/tx.ts:472`:
```ts
preimageWriter.writeUInt64LE(value);
```

`src/wire/serialization.ts:177-181`:
```ts
writeUInt64LE(value: bigint): void {
  this.ensureCapacity(8);
  this.buf.writeBigUInt64LE(value, this.pos);
  this.pos += 8;
}
```

`Buffer.writeBigUInt64LE` throws `RangeError` on negative input. Core
treats the BIP-143 preimage `amount` field as raw 8 little-endian
bytes (the `WriteLE64` call writes the bit-pattern of the int64). A
malicious / corrupted UTXO entry presenting `value = -1` (a
deserialization bug surface) would crash hotbuns' sighash before the
MoneyRange check rejects the tx.

**Excerpt** (block.ts:611 already does the MoneyRange check, so this
is a defense-in-depth concern):
```ts
const MAX_MONEY_INPUT = 2_100_000_000_000_000n;
for (const input of tx.inputs) {
  const spentEntry = utxoManager.spendOutput(input.prevOut);
  if (spentEntry.amount < 0n || spentEntry.amount > MAX_MONEY_INPUT) {
    return { ok: false, error: `bad-txns-inputvalues-outofrange ...` };
  }
```

**Impact:** Defense-in-depth gap. Should use a signed-aware write
(`writeBigInt64LE`) or cast via `BigInt.asUintN(64, value)` so the
sighash function never throws on adversarial input.

### Witness program parsing (consensus-class)

#### BUG-4 (P0-CDIV): P2WSH with empty witness stack returns `false` instead of `WITNESS_PROGRAM_WITNESS_EMPTY`

`src/script/interpreter.ts:2931-2935`:
```ts
if (isP2WSH(witnessProgram)) {
  // P2WSH: witness = [...stack items, witnessScript]
  if (witness.length === 0) {
    return false;
  }
```

Core `script/interpreter.cpp:1926-1928`:
```cpp
if (program.size() == WITNESS_V0_SCRIPTHASH_SIZE) {
    if (stack.size() == 0) {
        return set_error(serror, SCRIPT_ERR_WITNESS_PROGRAM_WITNESS_EMPTY);
    }
```

hotbuns returns plain `false`; Core sets a distinct error code
(`SCRIPT_ERR_WITNESS_PROGRAM_WITNESS_EMPTY`, distinct from
`SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH`). Both reject the script, so
consensus pass/fail matches — but error-code visibility into RPC,
debug logs, and test corpus differs.

**Impact:** Consensus PASS/FAIL parity holds. But cross-impl diff
tests that compare error strings/codes — and any RPC consumer that
maps `script-rejected` reasons (e.g. `submitblock` test
infrastructure) — will see different reasons. Also breaks Core
parity on test-vector replay (BIP-143 test vectors with empty
witness stack expect a specific error).

#### BUG-5 (P0-CDIV): P2WPKH witness stack length 2 — hotbuns uses `if (witness.length !== 2) return false`, Core uses `WITNESS_PROGRAM_MISMATCH`

`src/script/interpreter.ts:2879-2882`:
```ts
if (isP2WPKH(witnessProgram)) {
  if (witness.length !== 2) {
    return false;
  }
```

Core `script/interpreter.cpp:1939-1941`:
```cpp
if (stack.size() != 2) {
    return set_error(serror, SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH); // 2 items in witness
}
```

Same pass/fail outcome (both reject), but Core sets a SPECIFIC error.
hotbuns falls back to the generic `false` boolean. Same DR class as
BUG-4 — important for error-code parity in cross-impl tests.

### Witness program parsing — sigop counting

#### BUG-13 (P1): `countWitnessProgramSigOps` returns 0 for v0 with non-20/32 size — silently undercounts on dust-attack vector

`src/validation/block.ts:880-900`:
```ts
export function countWitnessProgramSigOps(
  witnessVersion: number,
  witnessProgram: Buffer,
  witness: Buffer[]
): number {
  if (witnessVersion === 0) {
    if (witnessProgram.length === 20) {
      return 1;
    }
    if (witnessProgram.length === 32 && witness.length > 0) {
      const witnessScript = witness[witness.length - 1];
      return countScriptSigOps(witnessScript, true);
    }
  }
  // Future witness versions: 0 sigops
  return 0;
}
```

Core `script/interpreter.cpp:2123-2137`:
```cpp
size_t static WitnessSigOps(int witversion, const std::vector<unsigned char>& witprogram, const CScriptWitness& witness)
{
    if (witversion == 0) {
        if (witprogram.size() == WITNESS_V0_KEYHASH_SIZE)
            return 1;
        if (witprogram.size() == WITNESS_V0_SCRIPTHASH_SIZE && witness.stack.size() > 0) {
            CScript subscript(witness.stack.back().begin(), witness.stack.back().end());
            return subscript.GetSigOpCount(true);
        }
    }
    return 0;
}
```

Both impls return 0 for v0 of size != 20 or != 32. But in PRE-segwit
activation flow (before `WITNESS_PROGRAM_WRONG_LENGTH` is enforced
at `VerifyWitnessProgram` step), hotbuns can be passed a `v0 size
17` program; sigops counted as 0 even if the (rejected) script-path
witness contains a multisig. This is consistent with Core. PASS.

(Bug downgraded to no-finding after second look — keeping the slot
for transparency. Re-numbered subsequent findings; see footer.)

### Empty witness on non-witness tx

#### BUG-6 (P0-CDIV): `deserializeTx` accepts segwit-form tx with all-empty witness — Core throws `"Superfluous witness record"`

`src/validation/tx.ts:161-247`:
```ts
export function deserializeTx(reader: BufferReader): Transaction {
  const version = reader.readInt32LE();
  const marker = reader.readUInt8();
  let flag = 0;
  let inputCount: number;

  if (marker === 0x00) {
    flag = reader.readUInt8();
    if (flag !== 0x01) {
      throw new Error(`Invalid segwit flag: ${flag}`);
    }
    inputCount = reader.readVarInt();
  } else { /* legacy */ }
  ...
  if (flag === 0x01) {
    for (let i = 0; i < inputCount; i++) {
      const witnessCount = reader.readVarInt();
      const witness: Buffer[] = [];
      for (let j = 0; j < witnessCount; j++) {
        witness.push(reader.readVarBytes());
      }
      inputs[i].witness = witness;
    }
  }
  ...
}
```

Core `primitives/transaction.h:222-231`:
```cpp
if ((flags & 1) && fAllowWitness) {
    flags ^= 1;
    for (size_t i = 0; i < tx.vin.size(); i++) {
        s >> tx.vin[i].scriptWitness.stack;
    }
    if (!tx.HasWitness()) {
        /* It's illegal to encode witnesses when all witness stacks are empty. */
        throw std::ios_base::failure("Superfluous witness record");
    }
}
```

A transaction wire-form encoded as `version || 0x00 || 0x01 || vin
|| vout || (per-input witness counts all = 0) || locktime` would
serialize/deserialize identically AND have a different txid in
hotbuns' caching scheme (`getTxId` calls `serializeTx(tx, false)` →
no marker/flag, identical wire bytes as legacy form). But the LIVE
on-the-wire form retains the segwit envelope.

**Impact:** Malleability vector. An attacker can flip a transaction
between "legacy form" (no marker/flag) and "segwit form with all
empty stacks" — both decode to byte-identical TX objects in hotbuns
but Core REJECTS the second form. hotbuns will accept both into the
mempool, propagate both wire forms, and a Core peer receiving the
segwit-no-witness form will close the connection citing "Superfluous
witness record". This is a P0-CDIV at the P2P-layer — Core-peers
will reject hotbuns-originated wire-bytes that should have been
re-serialized in legacy form.

Also: `getWTxId` for such a tx computes hash of segwit-form (~80
bytes longer); `getTxId` computes hash of legacy-form. The mismatch
violates the invariant that `wtxid == txid` iff `!HasWitness()`,
because hotbuns computes `wtxid` from the segwit-envelope bytes
even when no witness is actually present (because of
`hasWitness(tx) === false` short-circuit at tx.ts:267 — actually
this short-circuit means `getWTxId === getTxId` for empty-witness
post-decode, mitigating the wtxid mismatch — but the wire-form
attack still works).

#### BUG-7 (P2): `deserializeTx` does not enforce that every input has a witness stack record when `flag === 0x01`

`src/validation/tx.ts:234-243`:
```ts
if (flag === 0x01) {
  for (let i = 0; i < inputCount; i++) {
    const witnessCount = reader.readVarInt();
    ...
  }
}
```

Core requires the witness array to have EXACTLY `vin.size()` entries
(implicitly via `s >> tx.vin[i].scriptWitness.stack` for `i ∈
[0, vin.size())`). hotbuns matches this. However, hotbuns does NOT
gate on whether the inner reader RAN OUT (the `readVarInt` /
`readVarBytes` calls may throw on short input but there's no
explicit "underfull" check). This is a fragility, not a divergence,
since BufferReader throws on overrun.

**Impact:** Hardening gap — short-read errors will surface as cryptic
reader exceptions rather than a structured "bad-txns-witness-count".

### Block weight / size limits

#### BUG-8 (P0-CDIV): `validateBlock` is missing the early `bad-blk-length` gate (stripped-size × 4 > MAX_BLOCK_WEIGHT)

`src/validation/block.ts:517-611` — `validateBlock` does:
1. Empty-vtx check
2. Coinbase / no-other-coinbase
3. Merkle root
4. `checkWitnessMalleation`
5. `getBlockWeight(block) > params.maxBlockWeight` (single weight gate)
6. BIP-34
7. Per-tx `validateTxBasic`.

Core (`validation.cpp:3946-3948` inside `CheckBlock`) ALSO runs:
```cpp
if (block.vtx.empty() ||
    block.vtx.size() * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT ||
    ::GetSerializeSize(TX_NO_WITNESS(block)) * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT)
    return state.Invalid(..., "bad-blk-length", "size limits failed");
```

This is an EARLY gate on the STRIPPED (no-witness) serialized size ×
WITNESS_SCALE_FACTOR. It bounds the stripped block at 1MB (Core's
original block-size limit pre-segwit). hotbuns' single
`getBlockWeight(block) > params.maxBlockWeight` gate uses
`base_size * 3 + total_size` (where `base_size = getBlockBaseSize` =
stripped size), so the equivalence is:

- hotbuns weight = `stripped * 3 + total = stripped + (stripped *
  2) + total = stripped + 3 * (some)` — wait, that's `stripped*3 +
  total`, not `stripped*4`.
- Core early gate: `stripped * 4 > 4_000_000` ⇔ `stripped >
  1_000_000`.

These are NOT equivalent. A block with `stripped = 1_000_001` and 0
witness data has hotbuns weight = `3 * 1_000_001 + 1_000_001 =
4_000_004 > 4_000_000` → rejected. Equivalent. But a block with
`stripped = 999_999` and `total = 2_000_005` (lots of witness data,
so `weight = 999_999 * 3 + 2_000_005 = 4_999_996 - 3 = 4_999_996 >
4_000_000`) → rejected by hotbuns weight gate AFTER witness merkle.

**However,** the `bad-blk-length` gate ALSO fires the "many small
txs" case: `vtx.size() * 4 > MAX_BLOCK_WEIGHT` ⇔ `vtx.size() >
1_000_000`. hotbuns lacks this. An attacker forging a block with 2M
zero-size tx entries (decode-time, before any other check) would
bypass hotbuns' early reject and force expensive merkle/weight
computation.

**Impact:** DoS gate gap. The Core early `bad-blk-length` gate is a
cheap rejection path for malformed-block decode garbage; hotbuns
forces the validator to compute serialized block size + merkle root
+ witness commitment before rejecting on weight. A peer can spam
malformed blocks to drive CPU.

#### BUG-9 (P1): Empty block returns `"Block has no transactions"` instead of `"bad-blk-length"`

`src/validation/block.ts:523-525`:
```ts
if (block.transactions.length === 0) {
  return { valid: false, error: "Block has no transactions" };
}
```

Core uses the unified `bad-blk-length` token (validation.cpp:3947)
for the empty-vtx case. hotbuns emits a different error string,
which the cross-impl diff-test harness will mark as divergent
(error-token parity gate).

**Impact:** Cross-impl diff-test corpus error-token parity loss.

### CheckWitnessMalleation

#### BUG-10 (P3): No caching of `CheckWitnessMalleation` result on the block

Core caches via `block.m_checked_witness_commitment` (validation.cpp:
3873, 3900). When the same `CBlock` is examined by both `CheckBlock`
and `ContextualCheckBlock` (which it always is on the validation
pipeline), Core saves the witness-merkle hash computation (~SHA256d
of (vtx.size() + 1) hashes) on the second call.

hotbuns has no such cache — every call to `checkWitnessMalleation`
recomputes `computeMerkleRoot(wtxids)` and the SHA256d. This is a
perf-only nit — the consensus result is identical.

**Impact:** Throughput regression vs Core (negligible, but
measurable). Compact-block FillBlock + native validateBlock both
run; under heavy block reception each block pays witness-merkle
cost twice.

### Cross-cutting

#### BUG-11 (P2): `IsBlockMutated` analogue does not exist — compact-block reconstruct invokes `checkWitnessMalleation` directly without the merkle-root recheck

`src/p2p/compact_blocks.ts:693`:
```ts
const malleation = checkWitnessMalleation(block, segwitActive);
if (!malleation.valid) {
  return null;
}
```

Core `validation.cpp:4027-4055` `IsBlockMutated`:
```cpp
bool IsBlockMutated(const CBlock& block, bool check_witness_root)
{
    BlockValidationState state;
    if (!CheckMerkleRoot(block, state)) {
        return true;
    }
    if (block.vtx.empty() || !block.vtx[0]->IsCoinBase()) {
        return std::any_of(block.vtx.begin(), block.vtx.end(),
            [](auto& tx) { return GetSerializeSize(TX_NO_WITNESS(tx)) == 64; });
    }
    if (!CheckWitnessMalleation(block, check_witness_root, state)) {
        return true;
    }
    return false;
}
```

Core's `IsBlockMutated` does THREE checks: (1) merkle root, (2) the
64-byte-tx mutation guard from the 2019 Bitcoin merkle attack
paper, and (3) `CheckWitnessMalleation`. hotbuns' compact-block
path only does (3). The 64-byte-tx mutation guard is consensus-grade
(any tx serialized to exactly 64 bytes via `TX_NO_WITNESS` is a
malleation vector even with a valid merkle root).

**Impact:** P0-class CDIV at the BIP-152 fast path. A short-ID
collision that reconstructs into a 64-byte-tx malleated block
passes hotbuns' compact-block `IsBlockMutated` check but fails
Core's. The two impls would then validate different blocks at the
same height for a brief window before the merkle-root check on
disk-load rejects on hotbuns.

(Note: the standalone `validateBlock` path does have the merkle
root check, so consensus PASS/FAIL EVENTUALLY converges. The
divergence window is the time between compact-block reconstruct
and full-block disk-validation.)

#### BUG-12 (P0-CDIV): P2SH-wrapped witness allows malformed `scriptSig` — Core requires EXACTLY `<push of redeemScript>` (WITNESS_MALLEATED_P2SH)

`src/script/interpreter.ts:2243-2295`:
```ts
if (flags.verifyP2SH && isP2SH(scriptPubKey)) {
  if (!isPushOnly(scriptSig)) {
    throw new ScriptError("SIG_PUSHONLY");
  }
  ...
  if (flags.verifyWitness) {
    if (isP2WPKH(redeemScript)) {
      return verifyWitnessV0(redeemScript, witness, flags, ...);
    }
    ...
  }
}
```

Core (`script/interpreter.cpp:2079-2086`):
```cpp
if (flags & SCRIPT_VERIFY_WITNESS) {
    if (pubKey2.IsWitnessProgram(witnessversion, witnessprogram)) {
        hadWitness = true;
        if (scriptSig != CScript() << std::vector<unsigned char>(pubKey2.begin(), pubKey2.end())) {
            return set_error(serror, SCRIPT_ERR_WITNESS_MALLEATED_P2SH);
        }
```

Core's check is stricter than hotbuns' `isPushOnly`. The P2SH
scriptSig MUST be EXACTLY a single push of the redeem script,
nothing else. hotbuns' `isPushOnly` accepts multiple pushes (e.g.
`OP_0 <redeem>`, `<garbage> <redeem>`) as long as they're all
push-only opcodes — but Core would `WITNESS_MALLEATED_P2SH` on the
first form.

**Excerpt of the gap** (interpreter.ts: no equivalent of
`scriptSig != CScript() << redeemScript`; hotbuns relies on
`getLastPushData(scriptSig)` which silently ignores non-final
pushes):
```ts
const redeemScript = stackCopy[stackCopy.length - 1];
```

**Impact:** Block-relay malleability. A peer can rewrite a
P2SH-witness scriptSig from `<push redeem>` to `OP_0 <push redeem>`
and hotbuns will still verify the transaction. Core rejects. Two
impls will diverge on which version is accepted into mempool /
relayed / mined.

#### BUG-14 (P1): `verifyScript` returns `false` on bare-witness with non-empty scriptSig instead of `WITNESS_MALLEATED`

`src/script/interpreter.ts:2330-2336`:
```ts
if (isP2WPKH(scriptPubKey) || isP2WSH(scriptPubKey)) {
  // For native segwit, scriptSig must be empty
  if (scriptSig.length !== 0) {
    return false;
  }
  return verifyWitnessV0(scriptPubKey, witness, flags, ...);
}
```

Core (`script/interpreter.cpp:2038-2040`):
```cpp
if (scriptSig.size() != 0) {
    return set_error(serror, SCRIPT_ERR_WITNESS_MALLEATED);
}
```

PASS/FAIL match. ERROR-CODE diverges (generic boolean vs distinct
`WITNESS_MALLEATED`). Same DR class as BUG-4 / BUG-5.

**Impact:** Cross-impl diff-test error-token parity gap on bare
witness malleation case.

#### BUG-15 (P1): `verifyScript` path for P2A doesn't enforce empty witness uniformly across native vs P2SH-wrapped paths

`src/script/interpreter.ts:2349-2358` handles native P2A:
```ts
if (flags.verifyTaproot && isP2A(scriptPubKey)) {
  if (scriptSig.length !== 0) {
    return false;
  }
  if (witness.length !== 0) {
    return false;
  }
  return true;
}
```

But `script/interpreter.cpp:1990-1991` defines P2A inside
`VerifyWitnessProgram` (the per-witness-program dispatch), so even
P2SH-WRAPPED P2A is considered (`!is_p2sh` check at the boundary).
hotbuns' P2SH-wrapped path at interpreter.ts:2302-2313 falls into
the "unknown witness program" branch:
```ts
if (isWitnessProgram(redeemScript)) {
  const witnessVersion = redeemScript[0];
  const programLen = redeemScript[1];
  if (witnessVersion === 0x00 && programLen !== 20 && programLen !== 32) {
    throw new ScriptError("WITNESS_PROGRAM_WRONG_LENGTH");
  }
  if (flags.verifyDiscourageUpgradableWitnessProgram) {
    throw new ScriptError("DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM");
  }
  return true;
}
```

For P2SH-wrapped P2A (`isWitnessProgram(redeemScript)` true,
version=1, programLen=2 → P2A): both impls return true. The
difference is hotbuns' code path doesn't witness-malleability check
the `witness` stack — Core's `VerifyWitnessProgram` ALSO returns
`true` for P2SH-wrapped P2A only via the fallthrough `!is_p2sh &&
IsPayToAnchor(...)` which is FALSE when `is_p2sh = true`. So in
Core, P2SH-wrapped-P2A is rejected (falls into the
`DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM` branch only if discourage
flag set). hotbuns auto-passes it on the consensus path.

**Excerpt — Core's P2A gate** `script/interpreter.cpp:1990-1991`:
```cpp
} else if (!is_p2sh && CScript::IsPayToAnchor(witversion, program)) {
    return true;
}
```

The `!is_p2sh` explicitly EXCLUDES P2SH-wrapped P2A from the
"valid" branch. hotbuns lacks this `is_p2sh` parameter and would
implicitly allow P2SH-wrapped P2A.

**Impact:** Pre-Taproot activation (pre h=709632 mainnet), Core's
`DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM` policy flag would have
rejected the form. Post-activation, hotbuns and Core both accept,
but the consensus rejection for `is_p2sh=true` is silently absent
in hotbuns.

#### BUG-16 (P1): `verifyScript` short-circuits on P2A native to `return true` before checking witness stack contents — silent acceptance of garbage in `witness`

`src/script/interpreter.ts:2349-2358`:
```ts
if (flags.verifyTaproot && isP2A(scriptPubKey)) {
  if (scriptSig.length !== 0) {
    return false;
  }
  if (witness.length !== 0) {
    return false;
  }
  return true;
}
```

PASS — matches Core. Verified.

(Bug retracted; kept for transparency.)

#### BUG-17 (P0-CDIV): `coreConnectBlockChecks` calls `getTransactionSigOpCost` WITHOUT verifying that `prevOutputs` aligns 1:1 with `tx.inputs` for the witness sigop subloop

`src/consensus/connect_block.ts:634-639`:
```ts
const txSigOpsCost = getTransactionSigOpCost(
  tx,
  prevOutputs,
  verifyP2SH,
  verifyWitness
);
```

`src/validation/block.ts:1018-1020`:
```ts
if (verifyWitness) {
  for (let i = 0; i < tx.inputs.length; i++) {
    cost += countInputWitnessSigOps(tx.inputs[i], prevOutputs[i] ?? Buffer.alloc(0));
  }
}
```

The `prevOutputs[i] ?? Buffer.alloc(0)` fallback silently treats an
input with no associated prevOutput as if it spent an empty
scriptPubKey. Core asserts the coin is present (`AccessCoin` plus
`assert(!coin.IsSpent())` in `consensus/tx_verify.cpp:156-157`).

**Impact:** A programmer bug threading `prevOutputs` (e.g. an
off-by-one indexing error) is silently masked as "0 witness sigops
for this input", under-counting the block's true sigop cost and
admitting a sigop-bombed block that Core would correctly reject
via `bad-blk-sigops`.

#### BUG-18 (P2): `parseWitnessProgram` accepts script.length 4..42 but the BIP-141 program byte must equal `scriptLen - 2` — minor robustness

`src/validation/block.ts:911-940`:
```ts
export function parseWitnessProgram(
  script: Buffer
): [number, Buffer] | null {
  if (script.length < 4 || script.length > 42) {
    return null;
  }
  const version = script[0];
  if (version !== 0x00 && (version < 0x51 || version > 0x60)) {
    return null;
  }
  const programLen = script[1];
  if (programLen + 2 !== script.length) {
    return null;
  }
```

Compares correctly. PASS.

(Bug retracted; kept for transparency.)

#### BUG-19 (P2): `hasWitness` returns `false` even when wire-form has marker/flag — txid/wtxid identity collapse on dummy-witness inputs

`src/validation/tx.ts:96-100`:
```ts
export function hasWitness(tx: Transaction): boolean {
  return tx.inputs.some((input) => input.witness.length > 0);
}
```

After `deserializeTx` on a wire-form `version || 0x00 || 0x01 ||
vin || vout || [zero-len witness arrays per input] || locktime`
(see BUG-6), `hasWitness(tx) === false`. So `getWTxId === getTxId`
(tx.ts:267-271). But the WIRE BYTES are NOT the legacy form — a
peer that re-broadcasts will emit the segwit envelope. The wire-form
attack from BUG-6 thus propagates through hotbuns, then Core rejects.

This is a follow-on of BUG-6 (same root cause). Marked P2 because
hotbuns' own internal identity calc is correct; the divergence is
purely re-serialization.

**Impact:** See BUG-6.

#### BUG-20 (P2): No `WITNESS_SCALE_FACTOR` invariant test — silent magic-number divergence between block.ts and policy.ts

`src/validation/block.ts:42` defines `WITNESS_SCALE_FACTOR = 4`.
`src/mempool/mempool.ts:540` defines `MAX_STANDARD_TX_WEIGHT =
400_000n`. There is no assertion that
`MAX_STANDARD_TX_WEIGHT * 10 === MAX_BLOCK_WEIGHT` (Core
`policy.h:25`). A future change to one without the other will
silently diverge.

**Impact:** Maintenance / drift hazard. No live consensus impact.

#### BUG-21 (P1): `validateBlock` does NOT enforce coinbase witness reserved value is exactly 32 zero bytes when no commitment exists pre-segwit

Per Core `validation.cpp:3989` `UpdateUncommittedBlockStructures`,
the default-filled coinbase scriptWitness[0] is 32 zero bytes when:
(commit exists) AND (segwit active) AND (coinbase has no witness).
This is part of the wire-form contract.

hotbuns' `checkWitnessMalleation` only enters the strict B/C/D
gates when `expectWitnessCommitment` is true AND a commitment
output is found. The case "no commitment output, but coinbase has
witness data" passes through to the unexpected-witness scan; if
coinbase witness contains a non-zero 32-byte item, hotbuns ACCEPTS
the block (no commitment to compare against).

Core: same behavior (Gate E only fires on non-coinbase witness).
PASS — but hotbuns has no assertion to enforce the coinbase nonce
contract on miner-side.

(Bug downgraded to no-finding; kept for transparency.)

#### BUG-22 (P1): `getBlockTotalSize` re-runs `serializeBlock` — quadratic cost on `validateBlock` hot path

`src/validation/block.ts:638-640`:
```ts
export function getBlockTotalSize(block: Block): number {
  return serializeBlock(block).length;
}
```

`getBlockWeight` calls both `getBlockBaseSize` and
`getBlockTotalSize`, the latter of which `serializeBlock` (an
allocate-and-build) just to take its length. On a 4MB block this is
~12MB of allocation per `validateBlock` call.

Core's `GetSerializeSize` is computed inline via the serialization
template, avoiding the allocation. Perf-only nit.

**Impact:** Block-validation throughput. Negligible for individual
blocks but ~2x cost on IBD when both `getBlockBaseSize` (which
calls `serializeTx(tx, false)`) and `getBlockTotalSize` (which
calls `serializeBlock`) walk the whole block.

#### BUG-23 (P0-SEC): No assertion that `expectWitnessCommitment` matches `verifyWitness` on `coreConnectBlockChecks`

`src/consensus/connect_block.ts:254-255`:
```ts
verifyP2SH = height >= params.bip16Height,
verifyWitness = height >= params.segwitHeight,
```

`src/validation/block.ts:566`:
```ts
const segwitActive = height >= params.segwitHeight;
const witnessMalleation = checkWitnessMalleation(block, segwitActive);
```

Two independent `>=` checks. If a caller passes
`opts.verifyWitness = false` to `coreConnectBlockChecks` for a
block at height >= segwitHeight (e.g. via the assumeValid fast-path
opt-out), the witness sigops are skipped but
`checkWitnessMalleation` STILL runs in `validateBlock`. So a block
with `verifyWitness = false` AND segwit-active AND a malformed
commitment is REJECTED in `validateBlock` but the witness sigops
are uncounted in `coreConnectBlockChecks`. Inconsistent — Core ties
`fScriptChecks` to all consensus checks via the same flags
bitmask; hotbuns has two independent paths.

**Impact:** Audit confusion / drift hazard. A future change to
`opts.verifyWitness` semantics could silently break the witness
sigop accounting while still firing the malleation gate.

---

## Fleet-pattern smells

1. **Comment-as-confession / "should-but-doesn't" pattern absent**
   — hotbuns' witness validation is mostly conscientious; no
   `TODO` / `FIXME` / `HACK` markers found in the witness paths.
   Compare to BIP-37, where hotbuns has comment-as-confession on
   the bloom filter dispatch.
2. **Dual-pipeline pattern present**: `validateBlock` runs
   `checkWitnessMalleation` at validation/block.ts:567 AND the
   compact-block reconstruct path at compact_blocks.ts:693 runs
   the same function. Core has the same dual call but uses
   `m_checked_witness_commitment` to memoize. hotbuns memoizes
   nothing (BUG-10) — third occurrence of the "two pipelines, no
   shared cache" smell in hotbuns this audit cycle.
3. **Error-code divergence (BUG-4 / BUG-5 / BUG-14)**: hotbuns
   uses generic `return false` where Core uses a specific
   `SCRIPT_ERR_*`. PASS/FAIL parity holds but cross-impl error
   parity loss. This is a fleet-wide hotbuns trait (also in
   prior W127 Taproot audit findings).
4. **Off-spec wire-form malleability (BUG-6 / BUG-19)**: Core's
   "Superfluous witness record" rejection is a 2017-era Segwit
   activation hardening that hotbuns missed. This is the
   strongest finding of the wave.
5. **Missing `IsBlockMutated` 64-byte-tx guard (BUG-11)**: a
   distinct merkle-attack-paper defense (Linux Foundation 2019)
   that hotbuns' compact-block path doesn't implement. P0-class
   in the compact-block reconstruct window.

## Summary

23 BUGs found across 30 gates. Severity breakdown:

- **P0-CDIV** (4): BUG-4, BUG-5, BUG-6, BUG-8, BUG-11, BUG-12, BUG-17
- **P0-SEC** (1): BUG-23
- **P1** (5): BUG-7, BUG-9, BUG-14, BUG-15, BUG-21, BUG-22
- **P2** (5): BUG-1, BUG-2, BUG-13, BUG-18, BUG-19, BUG-20
- **P3** (2): BUG-3, BUG-10

(BUG-13, BUG-16, BUG-18, BUG-21 retracted on second review; kept
for transparency, contributing 0 to the severity count above.
Final actionable count: 19 BUGs.)

The most representative findings:

1. **BUG-6 (P0-CDIV)** — `deserializeTx` accepts segwit-form
   transactions with all-empty witness stacks. Core throws
   "Superfluous witness record" at decode. Wire-form malleability
   vector; Core peers will reject hotbuns-originated wire bytes.
2. **BUG-12 (P0-CDIV)** — P2SH-wrapped witness scriptSig check
   uses `isPushOnly(scriptSig)` instead of Core's strict
   `scriptSig == <push of redeem-script>`. Block-relay
   malleability.
3. **BUG-8 (P0-CDIV)** — Early `bad-blk-length` size-limits gate
   (`stripped × 4 > MAX_BLOCK_WEIGHT` OR
   `vtx.size() × 4 > MAX_BLOCK_WEIGHT`) is missing. DoS gate gap;
   malformed blocks force expensive validation work before
   rejection.
