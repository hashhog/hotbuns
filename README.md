# hotbuns

A Bitcoin full node implementation in TypeScript, running on [Bun](https://bun.sh).

## Status — v1.0.0

**Label: "Replay-verified"**
(`receipts/RELEASE-v1.0-SCORECARD.md`, §What each label means). That label is
deliberately weaker than "Validated", and the scorecard spells out why: it means
hotbuns agreed with Core on every block the nightly instruments showed it — 169
distilled real mainnet blocks, 10 block-context corpus entries, and its row in the
nightly corpus sweep — and that the 26,067-height stateless replay has since
COMPLETED: 26,067 distinct heights, `accept` on every one, 0 disagreements, 0
harness-limit rows, against 51,512 rejected control twins (scorecard footnote
[1], which also records that the first run silently compared only 65% of its
input and had to be re-run).
> **What that does and does not mean.** It is a *stateless* re-check of each block
> against Core's rules with scripts on. It is **not** a from-genesis reproduction of
> Core's UTXO set. hotbuns' only from-genesis evidence remains the partial
> genesis→250,000 ledger below, and that ledger has a committed disconfirmation
> inside its own range, described there. The other three nodes that carried this
> label have no from-genesis artifact at all; hotbuns' is partial and contested,
> which is not the same thing as absent. The git tag `v0.1.0-beta1`
(`receipts/RELEASE-v1.0-FREEZE.md`) says the same thing from the other side: `rc`
is reserved for an independent from-genesis `--assumevalid=0` reproduction of
Core's UTXO-set commitment, and `beta` means that receipt does not exist
(`receipts/beta1-tag-drafts-2026-08-20.md:23-27`). Neither label certifies wallet
or fund-custody readiness — see `SECURITY.md`.

## Known limitation — memory

**hotbuns leaks memory and will wedge if left running.** On 2026-09-02 it reached
its 16 GiB memory ceiling after about 1 day 16 hours of mainnet uptime and stopped
answering RPC entirely for 35 minutes. The process stayed alive and kept accepting
mempool transactions the whole time, so nothing restarted it automatically and a
process-liveness check would have called it healthy. It reaches roughly 7.5 GiB
within an hour of a cold start and about 12 GiB by two hours, then oscillates in
that band rather than climbing steadily — six samples over six minutes at the
two-hour mark ran 11.90–12.23 GiB and trended *down*. So a high reading is not by
itself a sign of imminent failure, and the shape of the curve between two hours
and the ceiling has not been characterised: the only evidence for the far end is
the single observed wedge. Recovery needed a manual stop, and it did not respond
to SIGTERM — it took SIGKILL after a 30-second grace.

Expect this roughly every other day until the leak is fixed. Run it under a
memory cap with automatic restart, and alert on RPC latency rather than on
process liveness, because the failure mode is a live process that has stopped
answering.

A separate fault on 2026-08-31 killed it with `SIGILL` (illegal instruction).
That cause has not been established, and it is not the same problem.

**hotbuns has no from-genesis UTXO-set reproduction.** There is no hotbuns row in
the reproduction ledger (`receipts/TRUST-ANCHOR.md:140-145`). What does exist is
weaker than it looks, in two directions:

- An offline replay ledger records genesis → 250000 byte-identical to Core under
  `assumevalid=0` on 2026-07-02
  (`CORE-PARITY-AUDIT/replay-ledgers/hotbuns-av0-danger-ledger.txt`,
  `overall=ALL-PASS`). But a later `assumevalid=0` rig rejected *real mainnet
  block 124276* with `SCRIPT_ERR_SIG_DER`, because `scriptFlagsFromBitmask`
  inferred DERSIG/CLTV/CSV/NULLDUMMY from the WITNESS flag and so enforced BIP-66
  from genesis. Fixed in `66f3926` on 2026-08-20
  (`receipts/beta1-tag-drafts-2026-08-20.md:60-70`). A ledger that passed a
  height range is not a proof that the interpreter was right there.
- `receipts/TRUST-ANCHOR.md:187-198` (correction, 2026-09-01) retracts every
  pre-2026-09-01 M2 boundary-campaign PASS row for hotbuns as script evidence:
  those runs used hotbuns' *default* assumevalid, so the window blocks were
  connected with scripts **skipped**. Those rows are chain-selection evidence
  only.

The release scorecard adds a third caveat about that 2026-07-02 ledger: the
`assumevalid=0 full-script` line in its header is the harness's own assertion, and
no launch-flag acknowledgement from the node was recorded
(`receipts/RELEASE-v1.0-SCORECARD.md`, hotbuns row). A reader of this repository
alone should not conclude that hotbuns has validated the chain from genesis.

**Operator RPC parity: 56 of Bitcoin Core's 85.** From the 103-method R5
operator probe run 2026-09-01
(`tools/diff-test-artifacts/r5-probe/20260901T182642Z.json`): hotbuns 56 PASS /
29 FAIL, Bitcoin Core 85 PASS on the same probe, 18 methods unmeasured
(`SKIP-REGTEST`) for every node including Core.

**Known gaps in this repo** (`receipts/UNIT-BASELINE-v1.0.md`, 2026-09-01): the
unit suite went 8 failing → 0, with **3 gaps carried as explicit skips whose IDs
were not recorded** in the day-1 data — the baseline marks them NOT VERIFIED, so
this README cannot name them. `bun install` crashes on the ZeroMQ NIF; run via
`bun run`. Node.js is not supported.

**Fleet-wide comparison:** `receipts/RELEASE-v1.0-SCORECARD.md` in the hashhog
meta-repo, which is **not public** — see the note below.

> **The cited paths are NOT publicly readable — do not treat them as evidence.**
> Paths beginning `receipts/`, `tools/`, `docs/` and `CORE-PARITY-AUDIT/` refer to
> the hashhog meta-repo, which is a **private** repository, not to this one. They
> are provenance for the maintainers. From outside, any claim resting only on such
> a path is **unverified**, and you should read it as such.
>
> Two of those paths are unreadable even with the meta-repo in hand: the R5 probe
> JSON is gitignored (`.gitignore:60  tools/diff-test-artifacts/`) and so are the
> nightly `diffguard-*.log` files (`.gitignore:43  *.log`). Regenerate the probe
> JSON with `python3 tools/r5_probe.py` against a running fleet.
>
> **What you can check from this repository alone:** build it, run its own test
> suite, and reproduce its behaviour against Bitcoin Core yourself. That is the
> evidence this repo actually ships.

## Quick Start

### Docker

```bash
docker build -t hotbuns .
docker run -v hotbuns-data:/data -p 48349:48349 -p 48339:48339 hotbuns
```

### From Source

Requires Bun 1.2+ (Dockerfile pins `oven/bun:1.2`; fleet builds run Bun 1.3.11 — Node.js is NOT supported) and the system `libsecp256k1` >= 0.4.0 (`apt install libsecp256k1-dev`, see Cryptography below).

```bash
bun install
bun run src/index.ts start --network=testnet4
bun run src/index.ts --help
```

## Features

- Full block and transaction validation (SegWit, Taproot, BIP68 sequence locks, sigop counting with witness discount)
- Script interpreter (P2PKH, P2SH, P2WPKH, P2WSH, P2TR, P2A anchors, NULLFAIL, WITNESS_PUBKEYTYPE, MINIMALIF, FindAndDelete, OP_CODESEPARATOR)
- Header-first sync with anti-DoS (PRESYNC/REDOWNLOAD strategy, PoW verification, checkpoint enforcement)
- Parallel block download with stall detection
- UTXO set with layered CoinsView cache (dirty/fresh flags, batch flush, undo data)
- Cluster mempool (union-find clustering, linearization, mining scores, cluster-based eviction, full RBF, package relay, CPFP, v3/TRUC policy, ephemeral anchors)
- BIP-324 v2 encrypted transport (ElligatorSwift ECDH, ChaCha20-Poly1305 AEAD)
- BIP-152 compact blocks (SipHash short IDs, mempool reconstruction, high/low bandwidth modes)
- BIP-330 Erlay transaction reconciliation (Minisketch set reconciliation)
- BIP-133 feefilter with Poisson-delayed broadcasts
- BIP-155 ADDRv2 (TorV3, I2P, CJDNS address support)
- Eclipse attack protections (netgroup diversity, anchor connections, eviction protection)
- Stale peer eviction (ping timeout, headers timeout, block download timeout)
- Inventory trickling (Poisson tx batching, immediate block relay, Fisher-Yates shuffle)
- HD wallet (BIP-32/44/49/84/86, BnB+Knapsack coin selection, encrypted storage)
- Multi-wallet support (createwallet/loadwallet/unloadwallet/listwallets RPCs)
- PSBT (BIP-174/370, partial signing, multi-party workflows)
- Output descriptors (BIP380-386, pk/pkh/wpkh/sh/wsh/tr/multi/sortedmulti/addr/raw/combo)
- Miniscript (type system, recursive descent parser, script compilation, witness satisfaction)
- assumeUTXO (snapshot serialization, dual chainstate, background validation)
- Block pruning (automatic disk management, pruneblockchain RPC, MIN_BLOCKS_TO_KEEP)
- Block indexes (txindex, BIP-157/158 blockfilterindex with GCS filters, coinstatsindex with MuHash)
- Fee estimation (confirmation buckets, historical data)
- Block template construction (tx selection, coinbase, witness commitment)
- ZMQ notifications (hashblock, hashtx, rawblock, rawtx, sequence topics)
- REST API (block, headers, blockhashbyheight, tx, utxos, mempool; JSON/bin/hex formats)
- Tor/I2P proxy (SOCKS5 client, Tor hidden services, I2P SAM protocol)
- Regtest mode (generatetoaddress, generateblock, generatetodescriptor RPCs)
- Chain management (invalidateblock, reconsiderblock, preciousblock RPCs)

## Configuration

### CLI Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--datadir=DIR` | `~/.hotbuns` | Data directory |
| `--network=NET` | `mainnet` | Network: mainnet, testnet, testnet4, regtest |
| `--rpcport=PORT` | per-network | RPC server port |
| `--rpc-user=USER` | `user` | RPC username |
| `--rpc-password=PASS` | `pass` | RPC password |
| `--port=PORT` | per-network | P2P listen port |
| `--max-outbound=N` | `8` | Maximum outbound peers |
| `--listen=BOOL` | `true` | Accept inbound P2P connections |
| `--connect=ADDR` | none | Connect to specific peer (repeatable) |
| `--addnode=ADDR` | none | Add peer to address manager (repeatable) |
| `--log-level=LVL` | `info` | Log level: debug, info, warn, error |
| `--prune=N` | `0` | Prune target in MiB (0=disabled, min 550) |
| `--import-blocks=PATH` | none | Import blocks from blk*.dat directory or `-` for stdin |
| `--import-utxo=PATH` | none | Import UTXO snapshot from HDOG file |

### Config File

`hotbuns.conf` in the data directory (key=value format):

```ini
# hotbuns configuration file
network=testnet4
rpcport=48349
rpcuser=myuser
rpcpassword=mypass
maxoutbound=10
listen=1
port=48339
loglevel=info
prune=550
```

## RPC API

JSON-RPC 2.0 modelled on Bitcoin Core's, with batch request support. Not behaviourally compatible: on the 2026-09-01 operator probe hotbuns answers 56 of the 103 probed methods correctly against Core's 85, with 29 failures (`tools/diff-test-artifacts/r5-probe/20260901T182642Z.json`).

| Category | Methods |
|----------|---------|
| Blockchain | `getblockchaininfo`, `getblock`, `getblockhash`, `getblockheader`, `getblockcount`, `getbestblockhash`, `getchaintips`, `getdifficulty` |
| Transactions | `getrawtransaction`, `sendrawtransaction`, `decoderawtransaction`, `decodescript`, `createrawtransaction`, `submitpackage` |
| Mempool | `getmempoolinfo`, `getrawmempool`, `getmempoolentry`, `getmempoolancestors` |
| Mining | `getblocktemplate`, `submitblock`, `getmininginfo`, `generatetoaddress`, `generateblock`, `generatetodescriptor` |
| Network | `getpeerinfo`, `getnetworkinfo`, `getconnectioncount`, `listbanned` |
| Wallet | `createwallet`, `loadwallet`, `unloadwallet`, `listwallets`, `listwalletdir`, `getnewaddress`, `getbalance`, `sendtoaddress`, `listunspent`, `getwalletinfo`, `listreceivedbyaddress`, `listtransactions` |
| Wallet Security | `encryptwallet`, `walletpassphrase`, `walletlock`, `walletpassphrasechange` |
| Descriptors | `getdescriptorinfo`, `deriveaddresses`, `importdescriptors` |
| PSBT | `createpsbt`, `decodepsbt`, `combinepsbt`, `finalizepsbt` |
| Util | `validateaddress`, `estimatesmartfee` |
| Chain Mgmt | `invalidateblock`, `reconsiderblock`, `preciousblock`, `pruneblockchain` |
| assumeUTXO | `loadtxoutset`, `dumptxoutset`, `getutxosetsnapshot` |
| ZMQ | `getzmqnotifications` |
| Control | `stop`, `help` |

REST API available at `/rest/` (block, headers, blockhashbyheight, tx, getutxos, mempool).

## Monitoring

No built-in Prometheus exporter. Monitor via RPC calls to `getblockchaininfo`, `getpeerinfo`, `getmempoolinfo`, and `getnetworkinfo`.

## Architecture

hotbuns leverages the Bun runtime for its native performance characteristics, including hardware-accelerated SHA256 and direct FFI access to libsecp256k1 via the `@noble/curves` and `@noble/hashes` libraries. The TypeScript type system provides strong guarantees around protocol message formats, script stack operations, and UTXO state transitions while remaining readable. LevelDB handles persistent storage for the block index and UTXO set, with flat file block storage in Bitcoin Core-compatible blk*.dat format.

The P2P layer implements the full Bitcoin protocol including BIP-324 v2 encrypted transport with ElligatorSwift key exchange. Peer management includes DNS seed discovery, misbehavior scoring, netgroup-diversified bucket assignment for eclipse attack resistance, and anchor connections for restart resilience. Inventory relay uses Poisson-timed batching for privacy, and BIP-330 Erlay reduces bandwidth through set reconciliation.

The validation pipeline processes blocks through parallel signature verification with a signature cache to avoid redundant work. The UTXO set uses a layered CoinsView architecture with dirty/fresh flag tracking and periodic batch flushing to LevelDB, matching Bitcoin Core's cache design. The cluster mempool implementation uses union-find clustering with linearization for optimal fee-rate ordering and mining score-based eviction.

The wallet subsystem supports BIP-32/44/49/84/86 HD key derivation across all address types (P2PKH, P2SH-P2WPKH, P2WPKH, P2TR), with Branch-and-Bound and Knapsack coin selection algorithms. PSBT support enables multi-party signing workflows, and output descriptors with miniscript provide flexible script policy composition.

## Cryptography

### libsecp256k1 FFI (ECDSA/Schnorr verification)

hotbuns uses a Bun FFI binding to the system `libsecp256k1` C library for all
consensus-path ECDSA and BIP-340 Schnorr signature verification. This replaces
the pure-JavaScript `@noble/curves` implementation on the verification hot path.
The FFI path is expected to be substantially faster there, but **no
benchmark artifact in this project measures it** — earlier revisions of this file
quoted "~30x" and "~30,000 vs ~1,000 ECDSA ops/sec"; those figures are not traceable
to any committed run and have been removed rather than repeated.

**Install the system library before running hotbuns:**

```bash
# Debian / Ubuntu
sudo apt install libsecp256k1-dev

# Verify version (requires >= 0.4.0)
pkg-config --modversion libsecp256k1
```

**FFI module:** `src/crypto/secp256k1_ffi.ts`

Functions:
- `ecdsaVerifyFFI` — strict DER ECDSA, low-S enforced (used by `ecdsaVerify`)
- `ecdsaVerifyLaxFFI` — lax DER ECDSA, historical Bitcoin compat (used by `ecdsaVerifyLax`)
- `schnorrVerifyFFI` — BIP-340 Schnorr (used by `schnorrVerify`)

**Graceful fallback (untested):** If `libsecp256k1.so.2` is not found at startup,
hotbuns is intended to fall back to `@noble/curves` automatically with a warning log,
remaining functional but slower during IBD. No committed test artifact in this project
exercises that fallback path, so treat it as unverified — install the system library
rather than relying on it.

**@noble fallback:** `@noble/secp256k1` and `@noble/curves` are intentionally
kept in `package.json`. They remain the implementation for:
- Signing operations (wallet, test helpers) — not on the IBD hot path
- BIP-324 ECDH / ElligatorSwift (P2P transport)
- Taproot key tweaking (key derivation math)
- Cross-checking FFI results in `src/crypto/secp256k1_ffi.test.ts`

## License

MIT
