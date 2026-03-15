# hotbuns

A Bitcoin full node implementation in TypeScript, running on Bun.

## What is it?

Maybe you've wondered what it takes to validate a Bitcoin transaction from scratch.
hotbuns is a from-scratch Bitcoin full node written in TypeScript (Bun) that does exactly that.

## Current status

- [x] Wire serialization (varint, BufferReader/BufferWriter, buffer pooling)
- [x] Cryptographic primitives (SHA256d, HASH160, secp256k1 ECDSA)
- [x] Address encoding (Base58Check, Bech32, Bech32m)
- [x] Script interpreter (P2PKH, P2SH, P2WPKH, P2WSH, P2TR, NULLFAIL, WITNESS_PUBKEYTYPE, witness cleanstack, P2SH push-only, FindAndDelete, OP_CODESEPARATOR, MINIMALIF)
- [x] Consensus parameters (mainnet, testnet3, testnet4/BIP94, signet, regtest)
- [x] Difficulty adjustment (2016-block retargeting, testnet 20-minute rule, BIP94)
- [x] BIP9 versionbits (soft fork state machine, deployment signaling)
- [x] Database storage (LevelDB, block index, UTXO set, batch optimization)
- [x] Transaction and block validation (parallel sig verification, BIP68 sequence locks, sigop counting with witness discount)
- [x] P2P networking (TCP, version handshake, message framing, BIP-152, pre-handshake rejection)
- [x] Peer manager (DNS discovery, connection pool, misbehavior scoring, ban management)
- [x] Stale peer eviction (ping timeout, headers timeout, block download timeout, stale tip)
- [x] Eclipse attack protections (netgroup diversity, anchor connections, eviction protection)
- [x] Inventory trickling (Poisson tx batching, immediate block relay, Fisher-Yates shuffle)
- [x] Header sync (block locator, MTP, PoW verification, PRESYNC/REDOWNLOAD anti-DoS, checkpoint verification)
- [x] Block sync (IBD, parallel download, stall detection)
- [x] UTXO/chain state (LRU cache, dirty tracking, connect/disconnect, undo data, checkpoint verification)
- [x] Mempool (fee-rate ordering, eviction, dependency tracking, ancestor/descendant limits)
- [x] Fee estimation (confirmation buckets, historical data)
- [x] Block template (tx selection, locktime finality, coinbase, witness commitment)
- [x] RPC server (JSON-RPC 2.0, Bitcoin Core-compatible)
- [x] HD wallet (BIP-32/BIP-84, P2WPKH, encrypted storage)
- [x] CLI (start/stop, RPC client, wallet commands)
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
  storage/          # persistent storage, undo data (rev*.dat)
  validation/       # block and tx validation
  p2p/              # peer connections, message framing, relay
  sync/             # header and block sync
  chain/            # UTXO set, chain state
  mempool/          # unconfirmed transactions
  fees/             # fee estimation
  mining/           # block templates
  rpc/              # JSON-RPC server
  wallet/           # HD wallet, transaction signing
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
