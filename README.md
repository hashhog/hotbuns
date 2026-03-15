# hotbuns

A Bitcoin full node implementation in TypeScript, running on Bun.

## What is it?

Maybe you've wondered what it takes to validate a Bitcoin transaction from scratch.
hotbuns is a from-scratch Bitcoin full node written in TypeScript (Bun) that does exactly that.

## Current status

- [x] Wire serialization (varint, BufferReader/BufferWriter, buffer pooling)
- [x] Cryptographic primitives (SHA256d, HASH160, secp256k1 ECDSA)
- [x] Address encoding (Base58Check, Bech32, Bech32m)
- [x] Script interpreter (P2PKH, P2SH, P2WPKH, P2WSH, P2TR, P2A anchors, NULLFAIL, WITNESS_PUBKEYTYPE, witness cleanstack, P2SH push-only, FindAndDelete, OP_CODESEPARATOR, MINIMALIF)
- [x] Consensus parameters (mainnet, testnet3, testnet4/BIP94, signet, regtest)
- [x] Difficulty adjustment (2016-block retargeting, testnet 20-minute rule, BIP94)
- [x] BIP9 versionbits (soft fork state machine, deployment signaling)
- [x] Database storage (LevelDB, block index, UTXO set, batch optimization, flat file block storage)
- [x] Transaction and block validation (parallel sig verification, BIP68 sequence locks, sigop counting with witness discount)
- [x] P2P networking (TCP, version handshake, message framing, pre-handshake rejection)
- [x] BIP-324 v2 transport (ElligatorSwift ECDH, ChaCha20-Poly1305 AEAD, forward secrecy)
- [x] BIP-152 compact blocks (SipHash short IDs, mempool reconstruction, getblocktxn/blocktxn, high/low bandwidth modes)
- [x] Peer manager (DNS discovery, connection pool, misbehavior scoring, ban management)
- [x] Stale peer eviction (ping timeout, headers timeout, block download timeout, stale tip)
- [x] Eclipse attack protections (netgroup diversity, anchor connections, eviction protection)
- [x] Inventory trickling (Poisson tx batching, immediate block relay, Fisher-Yates shuffle)
- [x] BIP-133 feefilter (min fee rate announcement, relay filtering, Poisson-delayed broadcasts, incremental relay fee)
- [x] BIP-155 ADDRv2 (TorV3, I2P, CJDNS address support, sendaddrv2 negotiation)
- [x] BIP-330 Erlay (set reconciliation via Minisketch, short ID computation, periodic recon timers)
- [x] Header sync (block locator, MTP, PoW verification, PRESYNC/REDOWNLOAD anti-DoS, checkpoint verification)
- [x] Block sync (IBD, parallel download, stall detection)
- [x] UTXO/chain state (layered CoinsView cache, dirty/fresh flags, batch flush, undo data, checkpoint verification)
- [x] Mempool (cluster mempool, union-find clustering, linearization, mining scores, cluster-based eviction, full RBF, package relay, CPFP, v3/TRUC policy)
- [x] Fee estimation (confirmation buckets, historical data)
- [x] Block template (tx selection, locktime finality, coinbase, witness commitment)
- [x] RPC server (JSON-RPC 2.0, batch requests, Bitcoin Core-compatible: getblockchaininfo, getblock, getblockheader, getblockhash, getrawtransaction, sendrawtransaction, submitpackage, getmempoolinfo, getrawmempool, getmempoolentry, estimatesmartfee, getpeerinfo, getnetworkinfo, validateaddress, getblocktemplate, getdescriptorinfo, deriveaddresses)
- [x] HD wallet (BIP-32/44/49/84/86, P2PKH/P2SH-P2WPKH/P2WPKH/P2TR, BnB+Knapsack coin selection, encrypted storage)
- [x] PSBT (BIP-174/370, partial signing, multi-party workflows, base64 encoding)
- [x] Coinbase maturity (100-block delay for coinbase UTXO spending)
- [x] Wallet encryption (AES-256-CBC with scrypt key derivation, encryptwallet/walletpassphrase/walletlock/walletpassphrasechange RPCs)
- [x] Address labels (setlabel RPC, labels in listreceivedbyaddress and listtransactions)
- [x] Block pruning (automatic disk management, pruneblockchain RPC, MIN_BLOCKS_TO_KEEP)
- [x] Block indexes (txindex, BIP157/158 blockfilterindex with GCS filters, coinstatsindex with MuHash)
- [x] Output descriptors (BIP380-386, pk/pkh/wpkh/sh/wsh/tr/multi/sortedmulti/addr/raw/combo, xpub/xprv paths, range derivation, checksums)
- [x] Miniscript (type system, recursive descent parser, script compilation, witness satisfaction, wsh/tr integration)
- [x] assumeUTXO (snapshot serialization, dual chainstate, background validation, loadtxoutset/dumptxoutset RPCs)
- [x] CLI (start/stop, RPC client, wallet commands, --prune flag, --txindex flag)
- [x] Test suite (unit, integration, e2e with regtest)
- [x] Performance benchmarks (block deser, UTXO cache, sig verify)

## Quick start

```bash
bun install
bun run src/index.ts start --network=testnet
```

Or use the CLI for wallet and RPC operations:

```bash
bun run src/index.ts wallet create --password=secret
bun run src/index.ts getinfo --rpc-port=18332
```

## Project structure

```
src/
  index.ts          # entry point
  cli/              # command-line interface
  wire/             # protocol serialization
  crypto/           # SHA256, RIPEMD160, secp256k1
  address/          # Base58Check, Bech32
  script/           # Script interpreter
  consensus/        # network parameters, proof-of-work, BIP9 versionbits
  storage/          # persistent storage, block files (blk*.dat), undo data (rev*.dat), indexes
  validation/       # block and tx validation
  p2p/              # peer connections, message framing, relay
  sync/             # header and block sync
  chain/            # UTXO set, chain state
  mempool/          # unconfirmed transactions
  fees/             # fee estimation
  mining/           # block templates
  rpc/              # JSON-RPC server
  wallet/           # HD wallet, transaction signing, output descriptors
  test/             # integration and e2e tests
```

## Running tests

```bash
bun test
bun test --coverage
```

## Performance benchmarks

```bash
bun run bench
```
