# Architecture

hotbuns is a single Bun process. `src/index.ts` calls `main()` in `src/cli/cli.ts`, which parses flags, reads the config file, opens the database and starts each subsystem in turn (`startNode`). Most work runs on Bun's single JavaScript event loop; script verification runs on a pool of Bun workers.

## Storage — `src/storage/`, `src/chain/`

- `storage/database.ts` (`ChainDB`) wraps one LevelDB database (`<datadir>/blocks.db`, through `classic-level`). Keys are prefixed by type: block index records, raw block bytes, undo data, UTXO entries, height-to-hash entries, chain work and chain-state metadata.
- `chain/utxo.ts` (`UTXOManager`) is a layered coins cache in the style of Core's `CCoinsViewCache`: entries carry dirty and fresh flags and are flushed to LevelDB in batches, with the chain-state record written in the same batch. `--dbcache` sets its size.
- `storage/undo.ts` keeps per-block undo data for disconnecting blocks during a reorganisation.
- `storage/pruning.ts` deletes old block data when `--prune` is set.
- `storage/indexes.ts` holds the optional indexes: BIP-158 block filters, coin statistics (MuHash, `wire/muhash.ts`) and the spent-output index.
- `chain/snapshot.ts` loads and writes Core-format UTXO snapshots (`loadtxoutset`, `dumptxoutset`) and runs the snapshot chainstate next to a background chainstate, as in Core's assumeUTXO.

## Validation — `src/validation/`, `src/script/`, `src/consensus/`

- `consensus/params.ts` defines the networks (genesis blocks, ports, deployment heights, checkpoints, assumevalid and assumeUTXO data). `consensus/pow.ts` computes difficulty targets; `consensus/versionbits.ts` tracks BIP-9 deployments.
- `validation/tx.ts` and `validation/block.ts` hold the context-free and contextual checks for transactions and blocks (sizes, sigop counts, BIP-30/34, BIP-68 sequence locks, witness commitment).
- `consensus/connect_block.ts` and `chain/state.ts` connect and disconnect blocks against the UTXO set and choose the most-work chain.
- `script/interpreter.ts` is the script interpreter: legacy, P2SH, SegWit v0 and Taproot/Tapscript, with Core's verification flags. Signature hashes are computed there; ECDSA and Schnorr verification call libsecp256k1 through `crypto/secp256k1_ffi.ts`.
- `validation/script_check_queue.ts` is the equivalent of Core's `CCheckQueue`: the inputs of a block are verified on a pool of Bun workers (`script_check_worker.ts`), with a signature cache (`sig_cache.ts`) consulted first.
- `consensus/assumevalid.ts` decides which blocks may skip script checks; `--noassumevalid` turns that off.

## P2P and sync — `src/p2p/`, `src/sync/`

- `p2p/peer.ts` is one connection: version handshake, message framing, and BIP-324 v2 encrypted transport (`p2p/bip324/`, `p2p/v2_transport.ts`).
- `p2p/manager.ts` (`PeerManager`) owns the connections: DNS and fixed seeds, outbound slots, inbound limits, eviction, anchors and feeler connections. Addresses live in `p2p/addrman.ts` (with BIP-155 addrv2 in `addrv2.ts` and ASMap grouping in `asmap.ts`); bans in `banman.ts`; SOCKS5, Tor and I2P in `proxy.ts`.
- `p2p/relay.ts` relays transactions and blocks with trickled inventory; `compact_blocks.ts` implements BIP-152, `erlay.ts` and `minisketch.ts` BIP-330, `feefilter.ts` BIP-133, and `cfilter_handlers.ts` serves BIP-157 filters.
- `sync/headers.ts` runs headers-first sync with Core's presync and redownload protection against low-work header chains. `sync/blocks.ts` schedules parallel block downloads from several peers, detects stalls and hands blocks to validation in order.

## Mempool and mining — `src/mempool/`, `src/mining/`, `src/fees/`

- `mempool/mempool.ts` accepts transactions under Core's standardness policy, groups them into clusters for eviction and mining order, and handles replacement (`rbf.ts`), package acceptance, TRUC (v3) and ephemeral anchors. Orphans wait in `orphan_pool.ts`; `persist.ts` reads and writes `mempool.dat`.
- `mining/template.ts` builds block templates for `getblocktemplate` and the `generate*` RPCs.
- `fees/estimator.ts` estimates fees from confirmation times, as Core's `estimatesmartfee` does.

## RPC — `src/rpc/`

- `rpc/server.ts` is the JSON-RPC server (`Bun.serve`), with authentication, batching and the dispatch table of all methods.
- `rpc/rest.ts` is the optional REST server; `rpc/zmq.ts` the ZMQ publisher.

## Wallet — `src/wallet/`, `src/payjoin/`

- `wallet/wallet.ts` is a descriptor-based HD wallet (BIP-32, BIP-39, BIP-44/49/84/86) with coin selection, labels, encryption and multi-wallet management.
- `wallet/descriptor.ts` and `wallet/miniscript.ts` parse output descriptors and miniscript; `wallet/psbt.ts` implements PSBT (BIP-174).
- `payjoin/` implements BIP-78 sender and receiver.

## Supporting code

- `wire/serialization.ts` reads and writes Bitcoin's binary encodings; `wire/compressor.ts` is Core's coin compression, used by snapshots.
- `address/encoding.ts` handles Base58Check and Bech32/Bech32m addresses.
- `logger/` provides the logger with Core-style debug categories and an event-loop lag monitor.
- `cli/supervisor.ts` implements `--supervise`.

## Tests

Unit tests sit next to the code (`src/**/*.test.ts`). Broader tests are in `src/__tests__/`, `tests/` and `__tests__/`. `tests/script_vectors.ts` and `tests/sighash_vectors.ts` run Bitcoin Core's test vectors. `bunfig.toml` runs each test file in its own process (`scripts/unit-isolate-preload.ts`) and lists the files excluded from `bun test`.
