# hotbuns

A Bitcoin full node implementation in TypeScript, running on Bun.

## What is it?

Maybe you've wondered what it takes to validate a Bitcoin transaction from scratch.
hotbuns is a from-scratch Bitcoin full node written in TypeScript (Bun) that does exactly that.

## Current status

- [x] Wire serialization (varint, BufferReader/BufferWriter)
- [x] Cryptographic primitives (SHA256d, HASH160, secp256k1 ECDSA)
- [x] Address encoding (Base58Check, Bech32, Bech32m)
- [x] Script interpreter (P2PKH, P2SH, P2WPKH, P2WSH, P2TR)
- [x] Consensus parameters (mainnet, testnet, regtest)
- [x] Database storage (LevelDB, block index, UTXO set)
- [x] Transaction and block validation
- [x] P2P networking (TCP, version handshake, message framing)
- [x] Peer manager (DNS discovery, connection pool, ban scoring)
- [x] Header sync (block locator, MTP, PoW, difficulty adjustment)
- [x] Block sync (IBD, parallel download, stall detection)
- [x] UTXO/chain state (connect/disconnect blocks, reorg handling)
- [x] Mempool (fee-rate ordering, eviction, dependency tracking)
- [x] Fee estimation (confirmation buckets, historical data)
- [x] Block template (tx selection, coinbase, witness commitment)
- [x] RPC server (JSON-RPC 2.0, Bitcoin Core-compatible)
- [x] HD wallet (BIP-32/BIP-84, P2WPKH, encrypted storage)
- [x] CLI (start/stop, RPC client, wallet commands)

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
  consensus/        # network parameters
  storage/          # persistent storage
  validation/       # block and tx validation
  p2p/              # peer connections, message framing
  sync/             # header and block sync
  chain/            # UTXO set, chain state
  mempool/          # unconfirmed transactions
  fees/             # fee estimation
  mining/           # block templates
  rpc/              # JSON-RPC server
  wallet/           # HD wallet, transaction signing
```

## Running tests

```bash
bun test
```
