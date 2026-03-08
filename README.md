# hotbuns

A Bitcoin full node implementation in TypeScript, running on Bun.

## What is it?

Maybe you've wondered what it takes to validate a Bitcoin transaction from scratch.
hotbuns is a from-scratch Bitcoin full node written in TypeScript (Bun) that does exactly that.

## Current status

- [x] Project scaffold and module layout
- [x] Wire serialization (varint, BufferReader/BufferWriter)
- [x] Cryptographic primitives (SHA256d, HASH160, secp256k1 ECDSA)
- [x] Address encoding (Base58Check, Bech32, Bech32m)
- [x] Script interpreter (P2PKH, P2SH, P2WPKH, P2WSH, P2TR)
- [x] Consensus parameters (mainnet, testnet, regtest)
- [x] Database storage (LevelDB, block index, UTXO set, chain state)
- [x] Transaction validation (sighash, weight, serialization)
- [x] Block validation (merkle root, PoW, witness commitment)
- [x] P2P message serialization (header, version, inv, headers, block, tx)
- [x] P2P peer connection (TCP via Bun.connect, version handshake, ping/pong)
- [x] Peer manager (DNS discovery, connection pool, ban scoring, message routing)
- [x] Header sync (block locator, MTP, PoW validation, difficulty adjustment)
- [ ] Block sync
- [ ] Mempool
- [ ] RPC server

## Quick start

```bash
bun install
bun run src/index.ts --datadir ~/.hotbuns
```

## Project structure

```
src/
  index.ts          # entry point
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
  wallet/           # key management
  cli/              # command-line parsing
```

## Running tests

```bash
bun test
```
