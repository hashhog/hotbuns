# W134 — BIP-37 Bloom Filter (legacy SPV) — hotbuns

**Impl:** hotbuns (TypeScript / Bun)
**Date:** 2026-05-17
**Status:** DISCOVERY — 27 BUGS / 30 gates (1 PRESENT, 2 PARTIAL non-bug, 27 BUGs of which 2 are PARTIAL-with-deviation: BUG-21, BUG-29)
**Tests:** `src/__tests__/w134_bip37_bloom_filter.test.ts`
**No production code changes in this wave.**

## Scope

- BIP-37 `CBloomFilter` (insertion / containment / IsRelevantAndUpdate /
  IsWithinSizeConstraints / nFlags / nTweak / MurmurHash3).
- BIP-37 P2P wire: `filterload`, `filteradd`, `filterclear`, `merkleblock`,
  `MSG_FILTERED_BLOCK` getdata vector, `inv` filtering.
- BIP-111 `NODE_BLOOM` service bit gate + `-peerbloomfilters` flag.
- `CMerkleBlock` / `CPartialMerkleTree` for filtered-block delivery
  (independent of the gettxoutproof use of the same data structure).
- VERSION-message `fRelay` flag interaction with BIP-37.

**Out of scope:** BIP-157/158 compact filters (W121/W122), BIP-152 compact
blocks (W126), BIP-339 wtxid relay (W103-class), `gettxoutproof` /
`verifytxoutproof` RPCs (already-wired in W47b — only consulted here for
their MerkleBlock encoding shared with BIP-37).

## Reference (Bitcoin Core)

- `bitcoin-core/src/common/bloom.h` — `CBloomFilter`, `MAX_BLOOM_FILTER_SIZE`
  (36000 bytes), `MAX_HASH_FUNCS` (50), `bloomflags` enum
  (BLOOM_UPDATE_NONE / BLOOM_UPDATE_ALL / BLOOM_UPDATE_P2PUBKEY_ONLY).
- `bitcoin-core/src/common/bloom.cpp` — sizing formulas (`vData.size() =
  min(-1/ln(2)^2 * nElements * log(nFPRate), 36000*8) / 8`,
  `nHashFuncs = min(vData.size()*8/nElements * ln(2), 50)`), MurmurHash3
  with seed `nHashNum * 0xFBA4C795 + nTweak`, CVE-2013-5700 zero-size
  guard (return early on insert, return true on contains), `insert`,
  `contains`, `IsWithinSizeConstraints`, `IsRelevantAndUpdate` with the
  BLOOM_UPDATE_MASK = 3 outpoint-injection logic.
- `bitcoin-core/src/merkleblock.h` / `.cpp` — `CPartialMerkleTree`,
  `CMerkleBlock(block, filter)` constructor (calls
  IsRelevantAndUpdate per tx + populates `vMatchedTxn`),
  `BitsToBytes` / `BytesToBits` little-endian packing,
  `TraverseAndBuild` / `TraverseAndExtract` with the `fBad` flag,
  `ExtractMatches` reorg/size guards
  (`nTransactions > MAX_BLOCK_WEIGHT / MIN_TRANSACTION_WEIGHT`,
  `vHash.size() > nTransactions`, `vBits.size() < vHash.size()`,
  identical-left/right-child detection at line 124).
- `bitcoin-core/src/net_processing.cpp:4963-5033` — `filterload`,
  `filteradd`, `filterclear` handlers (NODE_BLOOM gate +
  IsWithinSizeConstraints + `MAX_SCRIPT_ELEMENT_SIZE=520` filteradd cap
  + Misbehaving on violation).
- `bitcoin-core/src/net_processing.cpp:2439-2470` — `MSG_FILTERED_BLOCK`
  getdata branch (sends merkleblock + the matched txs that the filter
  asked us to inject).
- `bitcoin-core/src/net_processing.cpp:3676-3688` — VERSION `fRelay`
  flag initialization of `Peer::TxRelay::m_relay_txs` (off if
  `fRelay==false` AND NODE_BLOOM is not offered).
- `bitcoin-core/src/net_processing.cpp:5992-6080` — bloom-filter gate on
  outbound inv/tx (`if (tx_relay->m_bloom_filter) { if
  (!m_bloom_filter->IsRelevantAndUpdate(*txinfo.tx)) continue; }`).
- `bitcoin-core/src/net_processing.cpp:4855-4861` — `mempool` message
  NODE_BLOOM gate, with `pfrom.fDisconnect = true` on violation when
  the peer lacks NoBan permission.
- `bitcoin-core/src/net_processing.h:44` — `DEFAULT_PEERBLOOMFILTERS = false`.
- `bitcoin-core/src/init.cpp:1104-1105` — `g_local_services |= NODE_BLOOM`
  when `-peerbloomfilters=1`.
- `bitcoin-core/src/script/script.h:28` — `MAX_SCRIPT_ELEMENT_SIZE = 520`.

BIPs:
- **BIP-37** — Bloom-filtered connections (`filterload` / `filteradd` /
  `filterclear` / `merkleblock`, MSG_FILTERED_BLOCK, fRelay flag).
- **BIP-111** — `NODE_BLOOM` service flag (bit 2 = `0x04`).

## hotbuns architecture (or lack thereof)

The summary, with severity: **hotbuns has zero BIP-37 P2P implementation.**
What it has:

- `ServiceFlags.NODE_BLOOM = 4n` constant declared in `src/p2p/manager.ts:75`.
- `config.peerBloomFilters` CLI flag at `src/cli/cli.ts:128-136` and parsed
  at `:419-431` / `:719-720`.
- The flag is OR'd into `params.services` at `src/cli/cli.ts:1477-1479` —
  hotbuns will **advertise** NODE_BLOOM when the flag is set.
- BIP-324 short message IDs for `filteradd` / `filterclear` / `filterload`
  / `merkleblock` (`src/p2p/bip324/message_ids.ts:23-33`) — purely a
  table lookup; no handler is wired.
- `VersionPayload.relay: boolean` is parsed at `src/p2p/messages.ts:163`
  and surfaced in `getpeerinfo.relaytxes` at `src/rpc/server.ts:4388`,
  but no downstream code consults it.
- `gettxoutproof` / `verifytxoutproof` RPC builds a CMerkleBlock proof in
  `src/rpc/server.ts:315-438` (the `w47b…` helpers from wave-47b). This
  is reused for our W134 G19 / G20 / G24 / G25 gates because the
  PartialMerkleTree wire format is identical — but the BIP-37
  *delivery path* over the `merkleblock` message is missing.

What it does **not** have:

- Any `CBloomFilter` / bloom filter data structure (insert / contains /
  IsRelevantAndUpdate).
- Any handler for `filterload`, `filteradd`, `filterclear`, or
  `MSG_FILTERED_BLOCK`.
- Any `merkleblock` sender (Core's `sendMerkleBlock` branch in the block
  announce path at net_processing.cpp:2443).
- Any per-peer `m_bloom_filter` / `m_relay_txs` field on `Peer`.
- Any consultation of `peer.versionPayload.relay` when announcing
  transactions to the peer.
- Any MurmurHash3 implementation.
- Any `MAX_BLOOM_FILTER_SIZE` / `MAX_HASH_FUNCS` constant.
- Any rolling-bloom data structure (CRollingBloomFilter) — Core uses this
  for `m_addr_known` and `m_tx_inventory_known_filter`; hotbuns uses
  plain `Set` and lacks the privacy-bounded "recently seen" semantics.

Net effect: hotbuns will **advertise NODE_BLOOM if the operator sets
`-peerbloomfilters=1`**, but any SPV client (BitcoinJ, Wasabi pre-BIP-157,
older Electrum servers) that connects expecting filterload to work will
silently fail — its filter is dropped, every inv is sent regardless of
the filter, and no merkleblocks are returned. This is a **liveness +
correctness divergence on the SPV serving role**.

The mirror direction (hotbuns acting as an SPV *client*, sending
filterload to a peer to scan a blockchain it can't store locally) is also
missing — but hotbuns is a full node and doesn't need this; it's flagged
in the matrix for completeness.

---

## Audit matrix — 30 gates

Severity legend:
- **P0-CDIV** — consensus-divergent (could fork, or break wire shape in
  a way that other nodes can detect).
- **P1-WIRE** — wire / advertisement mismatch (advertise a service we
  don't implement, or reject valid traffic).
- **P1-BIP** — BIP feature missing (legitimate clients can't use us).
- **P1-DOS** — missing DoS guard from Core (rate-limit, size-limit, Misbehaving).
- **P2-EFF** — performance / efficiency.
- **P3-COS** — cosmetic / documentation.

Status legend: **PRESENT** / **PARTIAL** / **MISSING** / **BUG-N**.

| Gate | Subject | Status | Severity |
|------|---------|--------|----------|
| G01 | `MAX_BLOOM_FILTER_SIZE = 36000` bytes constant | **BUG-1** MISSING | P1-DOS |
| G02 | `MAX_HASH_FUNCS = 50` constant | **BUG-2** MISSING | P1-DOS |
| G03 | `BLOOM_UPDATE_NONE/ALL/P2PUBKEY_ONLY` flag enum | **BUG-3** MISSING | P1-BIP |
| G04 | `CBloomFilter` data structure (vData / nHashFuncs / nTweak / nFlags) | **BUG-4** MISSING | P1-BIP |
| G05 | MurmurHash3 with seed `n*0xFBA4C795 + nTweak` | **BUG-5** MISSING | P0-CDIV |
| G06 | `CBloomFilter::insert(key)` zero-size guard (CVE-2013-5700) | **BUG-6** MISSING | P0-CDIV |
| G07 | `CBloomFilter::contains(key)` zero-size guard returns true | **BUG-7** MISSING | P0-CDIV |
| G08 | `CBloomFilter::insert(COutPoint)` (outpoint serialization round-trip) | **BUG-8** MISSING | P1-BIP |
| G09 | `IsWithinSizeConstraints()` (vData ≤ 36000 && nHashFuncs ≤ 50) | **BUG-9** MISSING | P1-DOS |
| G10 | `IsRelevantAndUpdate(tx)` — txid + scriptPubKey-data + outpoint + scriptSig matches | **BUG-10** MISSING | P0-CDIV |
| G11 | `BLOOM_UPDATE_ALL` injects matching outpoints into filter | **BUG-11** MISSING | P0-CDIV |
| G12 | `BLOOM_UPDATE_P2PUBKEY_ONLY` injects outpoint only for P2PK/multisig | **BUG-12** MISSING | P0-CDIV |
| G13 | `filterload` wire deserialization (vData/nHashFuncs/nTweak/nFlags) | **BUG-13** MISSING | P1-BIP |
| G14 | `filterload` handler — NODE_BLOOM gate + Misbehaving on oversize | **BUG-14** MISSING | P1-DOS |
| G15 | `filteradd` handler — NODE_BLOOM gate + MAX_SCRIPT_ELEMENT_SIZE (520) cap | **BUG-15** MISSING | P1-DOS |
| G16 | `filterclear` handler — NODE_BLOOM gate, resets filter + m_relay_txs=true | **BUG-16** MISSING | P1-BIP |
| G17 | `peer.m_bloom_filter` / `m_relay_txs` per-peer state | **BUG-17** MISSING | P1-BIP |
| G18 | `merkleblock` send on `MSG_FILTERED_BLOCK` getdata | **BUG-18** MISSING | P1-BIP |
| G19 | `CMerkleBlock(block, filter)` constructor — IsRelevantAndUpdate per tx | **BUG-19** MISSING | P1-BIP |
| G20 | `CPartialMerkleTree` `TraverseAndBuild` recursion (PRESENT via gettxoutproof) | PARTIAL | P3-COS |
| G21 | `CPartialMerkleTree` `TraverseAndExtract` overflow guards (`fBad`) | **BUG-21** PARTIAL | P0-CDIV |
| G22 | `ExtractMatches` size guards (MAX_BLOCK_WEIGHT/MIN_TX_WEIGHT, vHash≤nTx, vBits≥vHash) | **BUG-22** MISSING | P0-CDIV |
| G23 | `ExtractMatches` identical-left-right-child rejection | **BUG-23** MISSING | P0-CDIV |
| G24 | `BitsToBytes` / `BytesToBits` LSB-first packing — PRESENT | PRESENT | (matches Core) |
| G25 | `CalcTreeWidth(nTx, height) = (nTx + (1<<h)-1) >> h` — PRESENT | PARTIAL | P3-COS |
| G26 | `verifytxoutproof` cross-checks extracted root vs. header merkleRoot | **BUG-26** MISSING | P0-CDIV |
| G27 | Outbound `inv`/`tx` filtered by per-peer bloom filter (m_bloom_filter gate) | **BUG-27** MISSING | P1-BIP |
| G28 | `peer.versionPayload.relay==false` suppresses tx inv (no-filter path) | **BUG-28** MISSING | P1-BIP |
| G29 | `mempool` NODE_BLOOM gate disconnects offending peer (Core net_processing.cpp:4860) | **BUG-29** PARTIAL | P1-DOS |
| G30 | `-peerbloomfilters` flag honored — NODE_BLOOM advertised iff we serve | **BUG-30** | P1-WIRE |

**Tally: 27 BUGs / 30 gates** (1 PRESENT [G24], 2 PARTIAL non-bug [G20, G25],
25 MISSING, 2 PARTIAL-with-deviation [G21, G29]).

---

## Bug detail

### BUG-1 P1-DOS — `MAX_BLOOM_FILTER_SIZE = 36000` constant missing
Core `common/bloom.h:17`:
```cpp
static constexpr unsigned int MAX_BLOOM_FILTER_SIZE = 36000; // bytes
```
hotbuns has no analog. The constant has no use today because there is
no filter implementation, but if a future agent ports `filterload`
without adding this constant, oversized filters will be accepted with
no Misbehaving — letting a peer pin ~unbounded memory per connection
(`vData` of 1 MB is wire-legal under varint).

### BUG-2 P1-DOS — `MAX_HASH_FUNCS = 50` constant missing
Core `common/bloom.h:18`. Same risk shape as BUG-1: ungated `nHashFuncs`
would let a peer force O(n) hashing on every IsRelevantAndUpdate call
(each tx output runs `vKey ⨉ nHashFuncs` murmur hashes). Trivial DoS
amplifier without the constant + bound check.

### BUG-3 P1-BIP — `bloomflags` enum missing
Core `common/bloom.h:24-31`:
```cpp
BLOOM_UPDATE_NONE = 0,
BLOOM_UPDATE_ALL = 1,
BLOOM_UPDATE_P2PUBKEY_ONLY = 2,
BLOOM_UPDATE_MASK = 3,
```
Wire-visible bits — used by IsRelevantAndUpdate to decide whether to
inject matched outpoints back into the filter (so the client doesn't
have to round-trip a filteradd). Absence is structurally part of
BUG-10 / 11 / 12 but is its own discoverable gap.

### BUG-4 P1-BIP — `CBloomFilter` data structure absent
The legacy SPV API surface — no file in `src/` declares a class with
`vData: Buffer`, `nHashFuncs: number`, `nTweak: number`, `nFlags:
number`. Static-grep gate in the test asserts the literal absence so
that landing a partial impl in another wave is detectable.

### BUG-5 P0-CDIV — MurmurHash3 with seed `n*0xFBA4C795 + nTweak` absent
Core `common/bloom.cpp:47`:
```cpp
return MurmurHash3(nHashNum * 0xFBA4C795 + nTweak, vDataToHash)
    % (vData.size() * 8);
```
hotbuns has no MurmurHash3 implementation at all (`grep -r MurmurHash`
returns zero). Even the BIP-158 path uses SipHash, and BIP-152 uses
SipHash too — Murmur3 with the 0xFBA4C795 magic and the
`% (vData.size() * 8)` reduction is BIP-37–specific. P0-CDIV because
*any* divergence in the hash function or reduction step produces
filters that disagree with Core peers byte-for-byte; an SPV client
would either over-match or under-match relative to Core's filter for
the same tx.

### BUG-6 P0-CDIV — `insert` zero-size guard (CVE-2013-5700) absent
Core `common/bloom.cpp:50-53`:
```cpp
if (vData.empty()) return;
```
Comment in Core's source: "Avoid divide-by-zero (CVE-2013-5700)".
Without this guard, an empty filter would trigger `nIndex % 0` → div by
zero → SIGFPE → node crash. Pre-2013 Bitcoind was vulnerable. Hotbuns
needs the analog guard the moment it adds a CBloomFilter. Severity
P0-CDIV because a crash on filterload is a remote-DoS vector that
Core peers know about and exploit defenses against.

### BUG-7 P0-CDIV — `contains` zero-size guard returns *true*
Core `common/bloom.cpp:69-72`:
```cpp
if (vData.empty()) return true;
```
A zero-size filter means "match-all" per Core's semantics. This is the
*opposite* of the natural "empty → no match" intuition — an
implementation bug that returned false on empty would silently filter
out every tx, breaking SPV. P0-CDIV because semantic divergence from
Core changes which txs reach the SPV peer.

### BUG-8 P1-BIP — `insert(COutPoint)` overload missing
Core `common/bloom.cpp:62-67`:
```cpp
void CBloomFilter::insert(const COutPoint& outpoint) {
  DataStream stream{};
  stream << outpoint;
  insert(MakeUCharSpan(stream));
}
```
Serializes `(uint256 hash, uint32 n)` = 36 bytes little-endian. The
BLOOM_UPDATE outpoint-injection path (BUG-11/12) calls this. Without
it, even if the keyed insert/contains works, the BLOOM_UPDATE_ALL
behavior won't.

### BUG-9 P1-DOS — `IsWithinSizeConstraints()` absent
Core `common/bloom.cpp:90-93`:
```cpp
return vData.size() <= MAX_BLOOM_FILTER_SIZE
    && nHashFuncs <= MAX_HASH_FUNCS;
```
Called by net_processing.cpp:4972 on filterload deserialize. Without
this check, the wire-deserializer accepts arbitrary filter sizes
(constrained only by `MAX_MESSAGE_SIZE = 32 MiB` for the whole frame).
A 5MB filter is wire-legal but would pin 5MB per peer for the
connection duration.

### BUG-10 P0-CDIV — `IsRelevantAndUpdate(tx)` algorithm absent
Core `common/bloom.cpp:95-161`. Matches against:
1. The transaction hash (`tx.GetHash()`).
2. Any non-empty data element pushed onto the stack by the scriptPubKey
   of any output (matching keys, addresses, hashes).
3. Each prevout (`COutPoint` serialization) of each input.
4. Any non-empty data element in any input's scriptSig (matching keys,
   redeem-script hashes pushed by signatures, etc.).

Without this method, even with a working CBloomFilter, the filtered-block
constructor can't decide which txs match the filter. P0-CDIV because
this is the canonical "is this tx for the SPV client?" decision; any
divergence produces a different set of matched txs than Core would
build, which the client would notice when the merkle proof's matched
set doesn't include their expected txs.

### BUG-11 P0-CDIV — `BLOOM_UPDATE_ALL` outpoint-injection absent
Core `common/bloom.cpp:123-124`:
```cpp
if ((nFlags & BLOOM_UPDATE_MASK) == BLOOM_UPDATE_ALL)
    insert(COutPoint(hash, i));
```
When a scriptPubKey data element matches AND nFlags is BLOOM_UPDATE_ALL,
Core injects the matching outpoint into the filter so that when the
client later sees a tx *spending* that outpoint, it auto-matches without
the client needing a round-trip filteradd. Without this, the SPV
client misses "outgoing" spends of UTXOs we delivered them.

### BUG-12 P0-CDIV — `BLOOM_UPDATE_P2PUBKEY_ONLY` Solver gating absent
Core `common/bloom.cpp:125-132`:
```cpp
else if ((nFlags & BLOOM_UPDATE_MASK) == BLOOM_UPDATE_P2PUBKEY_ONLY) {
    std::vector<std::vector<unsigned char>> vSolutions;
    TxoutType type = Solver(txout.scriptPubKey, vSolutions);
    if (type == TxoutType::PUBKEY || type == TxoutType::MULTISIG)
        insert(COutPoint(hash, i));
}
```
The narrower update mode: only inject outpoints for P2PK / multisig
outputs (the privacy rationale is that those don't reveal an address
hash on the wire). Requires the script Solver which hotbuns has
internally — but the wiring is absent.

### BUG-13 P1-BIP — `filterload` wire deserialization absent
Core SERIALIZE_METHODS at `common/bloom.h:67`:
```cpp
SERIALIZE_METHODS(CBloomFilter, obj) {
  READWRITE(obj.vData, obj.nHashFuncs, obj.nTweak, obj.nFlags);
}
```
Wire order is `vector<uint8> vData (varint length) | uint32 nHashFuncs
| uint32 nTweak | uint8 nFlags`. The hotbuns `messages.ts` discriminated
union lacks `{ type: "filterload"; payload: FilterLoadPayload }`, the
`parseMessage` switch has no `case "filterload"` arm, and the
serializeMessage path likewise has no entry — every filterload received
falls through to the default unknown-message logger.

### BUG-14 P1-DOS — `filterload` handler / Misbehaving absent
Core `net_processing.cpp:4963-4986`:
```cpp
if (msg_type == NetMsgType::FILTERLOAD) {
    if (!(peer.m_our_services & NODE_BLOOM)) {
        pfrom.fDisconnect = true;  // disconnect on filter msg without bloom service
        return;
    }
    CBloomFilter filter;
    vRecv >> filter;
    if (!filter.IsWithinSizeConstraints()) {
        Misbehaving(peer, "too-large bloom filter");  // 100-point ban
    } else if (auto tx_relay = peer.GetTxRelay(); tx_relay != nullptr) {
        ...m_bloom_filter.reset(new CBloomFilter(filter)); m_relay_txs = true;
        pfrom.m_bloom_filter_loaded = true;
    }
}
```
hotbuns: no `peerManager.onMessage("filterload", ...)` registration in
`cli.ts`. Test asserts `(mgr as any).messageHandlers.has("filterload")
=== false`. Net effect: malicious peer can send any filterload payload
(including malformed ones) without consequence — and well-behaved SPV
clients are silently broken.

### BUG-15 P1-DOS — `filteradd` handler + 520-byte cap absent
Core `net_processing.cpp:4988-5014`:
```cpp
if (vData.size() > MAX_SCRIPT_ELEMENT_SIZE) {
    bad = true;
} else if (tx_relay->m_bloom_filter) {
    tx_relay->m_bloom_filter->insert(vData);
} else {
    bad = true;  // filteradd before filterload
}
if (bad) Misbehaving(peer, "bad filteradd message");
```
`MAX_SCRIPT_ELEMENT_SIZE = 520` from `script/script.h:28`. hotbuns: no
handler, no cap, no Misbehaving. Even the constant 520 is not in the
codebase under that name.

### BUG-16 P1-BIP — `filterclear` handler absent
Core `net_processing.cpp:5016-5033`. Resets `m_bloom_filter` and (critically)
re-sets `m_relay_txs = true` — so a peer that connected with
`fRelay=false` (version), loaded a filter, then sent filterclear, gets
returned to "full-relay" mode.

### BUG-17 P1-BIP — `peer.m_bloom_filter` / `m_relay_txs` fields absent
Core `net_processing.cpp:293-303`. The `Peer::TxRelay` struct holds
the per-peer filter under `m_bloom_filter_mutex` plus the `m_relay_txs`
flag. hotbuns's `Peer` class (`src/p2p/peer.ts:159-279`) has fields
for wtxidRelay / feeFilterReceived / supportsErlay / erlayLocalSalt
etc. but no `bloomFilter`, no `relayTxs`, no `bloomFilterLoaded`. Test
asserts these are all `undefined`.

### BUG-18 P1-BIP — `MSG_FILTERED_BLOCK` getdata branch absent
Core `net_processing.cpp:2439-2470`:
```cpp
bool sendMerkleBlock = false;
CMerkleBlock merkleBlock;
{
    LOCK(tx_relay->m_bloom_filter_mutex);
    if (tx_relay->m_bloom_filter) {
        sendMerkleBlock = true;
        merkleBlock = CMerkleBlock(*pblock, *tx_relay->m_bloom_filter);
    }
}
if (sendMerkleBlock) {
    m_connman.PushMessage(&pfrom,
        msgMaker.Make(NetMsgType::MERKLEBLOCK, merkleBlock));
    // ...push matched txs the client did not see ...
}
```
hotbuns has `InvType.MSG_FILTERED_BLOCK = 3` declared in
`p2p/messages.ts:173` but no incoming-getdata handler at all (we
checked `cli.ts` + `manager.ts` for any `onMessage("getdata", ...)` —
nothing). So even MSG_BLOCK / MSG_TX getdatas aren't served either; the
MSG_FILTERED_BLOCK branch is doubly absent.

### BUG-19 P1-BIP — `CMerkleBlock(block, filter)` constructor absent
Core `merkleblock.cpp:31-56`. Iterates `block.vtx`, calls
`filter.IsRelevantAndUpdate(*block.vtx[i])` per tx (also mutates the
filter via BLOOM_UPDATE_ALL injection), pushes match-bool into vMatch,
hash into vHashes. hotbuns has the matched-set version
(`gettxoutproof` style) at `rpc/server.ts:8919` but no
filter-driven version that calls IsRelevantAndUpdate.

### BUG-20 PARTIAL P3-COS — `CPartialMerkleTree::TraverseAndBuild` PRESENT (w47b)
hotbuns has `w47bTraverseAndBuild` at `src/rpc/server.ts:336-368`,
algorithmically equivalent to Core. Used only by `gettxoutproof`.
PARTIAL because (a) the algorithm is locked inside an RPC helper
function in `rpc/server.ts` rather than exposed as a `merkleblock.ts`
module that BIP-37 can import; (b) it has no exports / tests outside
the gettxoutproof path. If the BIP-37 wave adds a separate module, the
two implementations will diverge over time. Recommendation: extract
to `src/p2p/merkleblock.ts` (consensus-touching code) when wiring
BIP-37.

### BUG-21 P0-CDIV PARTIAL — `TraverseAndExtract` overflow guards weak
Core `merkleblock.cpp:99-135` sets `fBad = true` on:
- bits-array overflow (`nBitsUsed >= vBits.size()`)
- hash-array overflow (`nHashUsed >= vHash.size()`)
- identical left/right child (line 124, indicates duplicated txid attack
  attempt — see BUG-23).

hotbuns `w47bTraverseAndExtract` at `rpc/server.ts:407-438`:
```ts
function extract(height, pos): Buffer {
  const flag = bits[bitPos++] ?? false;  // overflow → `?? false` returns false, NO fBad
  if (height === 0 || !flag) {
    const h = hashes[hashPos++]!;        // ! asserts non-null, undefined at runtime
    ...
  }
  ...
}
```
The `bits[bitPos++] ?? false` silently substitutes `false` on overflow
instead of failing; the non-null assertion on `hashes[hashPos++]!`
ignores the bounds. P0-CDIV because a malformed proof can yield a
wrong-but-undetected merkle root and `verifytxoutproof` will return
matched txids that don't actually appear in the block.

### BUG-22 P0-CDIV — `ExtractMatches` outer guards absent
Core `merkleblock.cpp:153-184` ExtractMatches:
```cpp
if (nTransactions > MAX_BLOCK_WEIGHT / MIN_TRANSACTION_WEIGHT)
    return uint256();      // ~10k tx cap
if (vHash.size() > nTransactions) return uint256();
if (vBits.size() < vHash.size()) return uint256();
// post-traversal:
if (fBad) return uint256();
if (CeilDiv(nBitsUsed, 8u) != CeilDiv(vBits.size(), 8u))
    return uint256();
if (nHashUsed != vHash.size()) return uint256();
```
hotbuns `verifyTxOutProof` at `rpc/server.ts:9031-9063` skips all of
these. A peer (in a future BIP-37 wire path) or a malicious RPC caller
can pass a proof with arbitrarily inflated `nTx` to force O(n) tree-
height computation; or pass `vBits.size() < vHash.size()` to force
out-of-bounds reads. P0-CDIV via the `verifytxoutproof` surface today;
will also fail BIP-37 merkleblock-receive in a future wave.

### BUG-23 P0-CDIV — identical left/right child detection absent
Core `merkleblock.cpp:124-127`:
```cpp
if (right == left) {
    // The left and right branches should never be identical, as the
    // transaction hashes covered by them must each be unique.
    fBad = true;
}
```
This blocks the 2017 "duplicate-txid" SPV attack (CVE-2017-12842):
attacker pairs two identical txids to forge a merkle proof for a fake
tx with the same hash as a real one. hotbuns's TraverseAndExtract
does not perform this check. P0-CDIV: `verifytxoutproof` can be tricked
into "verifying" a fabricated tx is in a block.

### BUG-24 PRESENT — `BitsToBytes`/`BytesToBits` LSB-first packing
Core `merkleblock.cpp:13-29` packs bit `p` into `bytes[p/8] |= bit <<
(p%8)`. hotbuns `w47bBitsToBytes` / `w47bBytesToBits` at
`rpc/server.ts:371-384` does the same LSB-first packing
(`buf[i >> 3] |= 1 << (i & 7)` and reverse). **Only PRESENT gate in
this wave.**

### BUG-25 PARTIAL — `CalcTreeWidth` formula
hotbuns `w47bTreeWidth` at `rpc/server.ts:320-322`:
```ts
return (nTx + (1 << height) - 1) >> height;
```
Matches Core exactly. PARTIAL because (a) `1 << height` is sign-extended
in JavaScript for `height ≥ 31`; (b) `nTx + (1 << height) - 1` overflows
`Number.MAX_SAFE_INTEGER` only at astronomical nTx (>2^53), so
practically safe but theoretically not bit-exact for an
adversarial-crafted maximum-block proof.

### BUG-26 P0-CDIV — `verifytxoutproof` skips merkle-root check
Core's `verifytxoutproof` in `rpc/blockchain.cpp` (not in the files we
read here but in its RPC handler) calls `pmt.ExtractMatches(matches,
indices)` and then asserts the returned uint256 *equals* the block
header's hashMerkleRoot. hotbuns `verifyTxOutProof` at
`src/rpc/server.ts:9031-9063` parses the proof and runs
`w47bTraverseAndExtract` — but **never** computes the resulting root,
**never** compares it to the embedded header's `merkleRoot`, **never**
checks the header is in our chain. Returns matched txids unconditionally.
A caller can hand it a proof with any header (even one we've never
seen) and get back the embedded txids. P0-CDIV via RPC.

### BUG-27 P1-BIP — outbound inv/tx not filtered by bloom filter
Core `net_processing.cpp:5992-6080`:
```cpp
if (tx_relay->m_bloom_filter) {
    if (!tx_relay->m_bloom_filter->IsRelevantAndUpdate(*txinfo.tx))
        continue;
}
```
hotbuns `relay.ts:144-176`:
```ts
queueTxFiltered(peer: Peer, txid: string, txFeeRate: number): boolean {
    if (!meetsFeeFilter(txFeeRate, peer.feeFilterReceived)) return false;
    // ... no bloom check ...
    queue.pendingTxs.add(txid);
    return true;
}
```
Only feefilter is consulted; no peer-bloom-filter gate. Even if a BIP-37
client successfully filterloads, we'd flood them with every tx — which
defeats the entire BIP-37 bandwidth-savings motivation. (This is the
counterpart of BUG-17 — the per-peer bloom field is absent so we
*can't* consult it even if we wanted to.)

### BUG-28 P1-BIP — `version.relay==false` ignored on tx announce
Core `net_processing.cpp:3676-3688` initializes
`tx_relay->m_relay_txs = fRelay` from the version message. When
fRelay==false AND we don't offer NODE_BLOOM, `tx_relay` is left
nullptr, gating outbound tx inv (`net_processing.cpp:3980, 5993,
6044`). hotbuns parses `versionPayload.relay` (`messages.ts:163`) and
surfaces it via `getpeerinfo.relaytxes`, but no relay-loop code path
consults it. A peer that asked us NOT to send tx inv (`relay=false`,
no filter loaded) still gets every tx announcement.

### BUG-29 PARTIAL P1-DOS — `mempool` NODE_BLOOM gate silent-drops
Core `net_processing.cpp:4855-4860`:
```cpp
if (!(peer.m_our_services & NODE_BLOOM) && !pfrom.HasPermission(...Mempool)) {
    if (!pfrom.HasPermission(NetPermissionFlags::NoBan)) {
        LogDebug(...);
        pfrom.fDisconnect = true;   // <-- disconnect, not just drop
    }
    return;
}
```
hotbuns `cli.ts:1947-1953`:
```ts
peerManager.onMessage("mempool", (peer, _msg) => {
    if (!advertisingNodeBloom) {
        // ... drop and return ...
        return;
    }
    ...
});
```
PARTIAL: the gate works (don't honor mempool requests when NODE_BLOOM
is off) but Core *also* disconnects the peer on the violation. hotbuns
silently drops. Comment at `cli.ts:1939-1943` acknowledges this is
intentional ("a sloppy disconnect on every spurious mempool ping
would churn the fleet"), but this is a Core-divergence; SPV-style
clients that learn "mempool isn't honored" by getting disconnected
will instead loop on hotbuns. Severity P1-DOS not P0 because Core's
own behavior is gated on NoBan permission absence, which hotbuns
doesn't model.

### BUG-30 P1-WIRE — `-peerbloomfilters` advertises a service we don't serve
The most visible operator-facing footgun in this wave.
`cli.ts:1477-1479`:
```ts
if (mergedConfig.peerBloomFilters) {
    paramsServices |= NODE_BLOOM_BIT;
}
```
hotbuns will set bit 2 of its advertised services word when the flag
is `true`. Any peer that sees NODE_BLOOM in our version message will
believe we honor BIP-37 — and send `filterload`. We'll silently drop
it (no handler — BUG-14), then they'll send `MSG_FILTERED_BLOCK`
getdatas (BUG-18), get no response, time out, and disconnect. The
peer's address-manager will mark hotbuns as "unreliable" instead of
"doesn't implement BIP-37" — which is worse for the AddrMan signal.

Compounds with BUG-17 / 27: even the BIP-35 `mempool` handler that
*is* gated on this bit (`cli.ts:1944, 1948`) will run when we advertise
NODE_BLOOM but our outbound inv flood will be unfiltered (BUG-27), so
the SPV client will receive a flood of inv anyway.

The simple defensive option, until BIP-37 lands, is to **refuse to
advertise NODE_BLOOM unless filterload is wired** — same shape as
W121's FIX-71-style "plumb-gate-then-flip" pattern.

---

## Universal patterns visible in this audit

1. **"Advertise-but-don't-serve"** — BUG-30 is the canonical shape. We've
   seen the same dynamic in W121 for NODE_COMPACT_FILTERS (the
   FIX-71 / FIX-74 / FIX-81 / FIX-82 chain). Recommendation: hotbuns
   should adopt a hard rule that every service-flag advertisement is
   gated by a feature-detect that fails closed when the dispatch arm
   is not present — same as the rustoshi
   `BIP157_P2P_HANDLERS_REGISTERED` gate FIX-82 added.

2. **"Audit framework requires byte-exact against Core"** — BUG-5 and
   the merkle-root check gap (BUG-26) are exactly the W122-finding
   pattern: a self-consistent implementation can pass SHA-256d
   tautology tests yet diverge from Core. Even hotbuns's
   `w47bTraverseAndBuild` *output* would need to be cross-checked
   against Core's serialization to detect bit-order or padding
   divergence — and it has no such test today (the only consumer is
   gettxoutproof's own round-trip test, which is self-comparing).
   A future BIP-37 fix wave must include byte-exact assertions against
   Core merkleblock fixtures.

3. **"Misbehaving / Disconnect parity is fleet-wide gap"** — BUG-14 /
   15 / 29 echo the W121-#5 pattern (cfilters-misbehaving missing
   across the fleet — closed in FIX-78). hotbuns has only one
   misbehaving call site in `peer.ts` (BIP-339 handshake violation,
   `peer.ts:1267`); BIP-37 will need three more. The recurring
   shape: "we receive the message but don't sanction the
   protocol violation it represents".

4. **"Algorithm exists, wiring missing"** — BUG-20 / 24 / 25 are the
   "PartialMerkleTree algorithm is implemented (in rpc/server.ts) but
   only wired for an RPC, not for the P2P merkleblock send path." Same
   shape as the FIX-79 nimrod "dead-helper-at-call-site" closure.
   When BIP-37 lands, the partial-merkle-tree code should be hoisted
   from `rpc/server.ts` into a shared `src/p2p/merkleblock.ts` and
   shared with both call sites — otherwise drift is inevitable.

5. **"Source-level guards on absence"** — most W134 BUGs are
   "this symbol does not exist anywhere in src/". The tests use
   regex-grep on the source tree to assert absence (`expect(SRC).not
   .toMatch(/MurmurHash3|CBloomFilter/)`) so that landing a partial
   implementation flips the test from PASS to FAIL — same defensive
   pattern as the wave-48c "test fixtures hard-code all fields" lesson.

---

## Recommendation

Before the FIX wave that lands BIP-37, hotbuns should land a
**one-line BUG-30 hotfix**: refuse to OR `NODE_BLOOM_BIT` into the
advertised services word until handler registration is complete — same
shape as cli.ts's existing `mergedConfig.blockfilterindex` gate for
NODE_COMPACT_FILTERS. This closes the observable wire-divergence with
minimal code surface and matches the FIX-71-class "plumb-gate-then-flip"
pattern that's worked across the fleet five times now.

Full BIP-37 implementation is a larger surface (~600 LOC including
CBloomFilter, MurmurHash3, three new message types, three new
handlers, the per-peer `m_bloom_filter` field, the MSG_FILTERED_BLOCK
getdata branch, the relay-loop bloom gate, and the
`CMerkleBlock(block, filter)` constructor). Recommended as a single
single-impl wave — hotbuns only.

## Test summary

`src/__tests__/w134_bip37_bloom_filter.test.ts` — 30 gates / 27 BUGs
documented via assertions (66 tests, 147 expect() calls, all pass). All
MISSING-gate tests assert the absence of the relevant symbol or handler
so they will flip to FAIL the moment a future wave lands the
implementation. PRESENT/PARTIAL tests assert algorithmic equivalence to
Core for the merkle-tree helpers shared with `gettxoutproof`.
Assertion-only, no production code changes.
