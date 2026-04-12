# hotbuns

A Bitcoin full node implementation in TypeScript, running on [Bun](https://bun.sh).

## Quick Start

### Docker

```bash
docker build -t hotbuns .
docker run -v hotbuns-data:/data -p 48349:48349 -p 48339:48339 hotbuns
```

### From Source

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

Bitcoin Core-compatible JSON-RPC 2.0 with batch request support.

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
the pure-JavaScript `@noble/curves` implementation on the verification hot path,
achieving ~30x throughput improvement during IBD (~30,000 ECDSA ops/sec vs
~1,000 ops/sec with `@noble/curves`).

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

**Graceful fallback:** If `libsecp256k1.so.2` is not found at startup, hotbuns
falls back to `@noble/curves` automatically with a warning log. The node
remains fully functional; IBD will be slower without the C library.

**@noble fallback:** `@noble/secp256k1` and `@noble/curves` are intentionally
kept in `package.json`. They remain the implementation for:
- Signing operations (wallet, test helpers) — not on the IBD hot path
- BIP-324 ECDH / ElligatorSwift (P2P transport)
- Taproot key tweaking (key derivation math)
- Cross-checking FFI results in `src/crypto/secp256k1_ffi.test.ts`

## License

MIT
