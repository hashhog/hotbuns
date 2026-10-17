# hotbuns

A Bitcoin full node written from scratch in TypeScript, running on [Bun](https://bun.sh). One of the ten [hashhog](https://github.com/hashhog) nodes.

> **Experimental.** hashhog nodes are independent re-implementations of Bitcoin Core for research and testing. Do not use them with real funds.

## Status

| Area | State |
|---|---|
| Script interpreter | Passes all 1,222 of Bitcoin Core v31.1's `script_tests.json` vectors and all 500 `sighash.json` vectors (`bun tests/script_vectors.ts`, see [docs/status.md](docs/status.md)). |
| UTXO set vs Core | On regtest, after syncing a chain from Bitcoin Core v31.1 over P2P, `gettxoutsetinfo` `hash_serialized_3` matches Core's. hotbuns has not yet completed a from-genesis mainnet sync with script checks on that reproduces Core's hash. See [docs/status.md](docs/status.md). |
| RPC | 139 JSON-RPC methods with Core's names and result shapes; some error codes and messages differ. See [docs/rpc.md](docs/rpc.md). |
| P2P | Headers-first sync, BIP-324 v2 transport, BIP-152 compact blocks, BIP-155 addrv2, Erlay, Tor/I2P proxies. Tests in `src/p2p/` and `src/__tests__/`. |
| Test suite | `bun test`: 6,736 tests in 247 files; 6,668 pass, 2 fail, 47 skipped, 19 todo. See [docs/status.md](docs/status.md#test-suite). |
| Wallet | Descriptor HD wallet, PSBT and coin selection work on regtest. Not reviewed for custody: see [SECURITY.md](SECURITY.md). |

Last updated: 2026-10-17.

## Quick start

Tested on Debian 13 with Bun 1.3.11 and libsecp256k1 0.5.0. Node.js does not run this tree; it needs Bun.

```bash
sudo apt-get install -y libsecp256k1-dev curl git unzip
curl -fsSL https://bun.sh/install | bash -s "bun-v1.3.11"   # then open a new shell, or: export PATH=$HOME/.bun/bin:$PATH
git clone https://github.com/hashhog/hotbuns.git && cd hotbuns
bun install
DATADIR=$(mktemp -d)
bun run src/index.ts start --network=regtest --datadir="$DATADIR" --metrics-port=0 &
sleep 5
curl -s --user "$(cat "$DATADIR/.cookie")" -d '{"method":"getblockchaininfo","params":[]}' http://127.0.0.1:18443/
curl -s --user "$(cat "$DATADIR/.cookie")" -d '{"method":"stop","params":[]}' http://127.0.0.1:18443/
```

The first `curl` prints the regtest genesis state (`"chain":"regtest","blocks":0`). `--metrics-port=0` turns off the Prometheus endpoint, which otherwise listens on all interfaces on port 9332. There is no compile step: Bun runs the TypeScript directly.

## Running

The default network is mainnet. Select another with `--network=testnet4`, `--network=testnet` (testnet3) or `--network=regtest`. Signet is not supported.

| Network | Flag | P2P port | RPC port |
|---|---|---|---|
| mainnet | (none) | 8333 | 8332 |
| testnet4 | `--network=testnet4` | 48333 | 48332 |
| testnet3 | `--network=testnet` | 18333 | 18332 |
| regtest | `--network=regtest` | 18444 | 18443 |

Data goes directly into `--datadir` (default `~/.hotbuns`), with no per-network subdirectory, so give each network its own datadir. Blocks, the block index and the UTXO set all live in one LevelDB database, `<datadir>/blocks.db`. For mainnet, plan for the disk of an unpruned Bitcoin Core node (several hundred GB), or pass `--prune=<MiB>` (at least 550). `--dbcache=<MiB>` (default 512) sets the UTXO cache; the node needs a few GB of RAM on top of it.

Flags take the form `--name=value`. Every flag, the config file, environment variables and the datadir layout are in [docs/running.md](docs/running.md).

## RPC

hotbuns serves a JSON-RPC interface modelled on Bitcoin Core's on the RPC port above. On startup it writes a cookie to `<datadir>/.cookie`; `--rpc-user` / `--rpc-password` also work. With the quick-start node running (before the final `stop`):

```bash
curl -s --user "$(cat "$DATADIR/.cookie")" -d '{"method":"createwallet","params":["demo"]}' http://127.0.0.1:18443/
curl -s --user "$(cat "$DATADIR/.cookie")" -d '{"method":"getnewaddress","params":[]}' http://127.0.0.1:18443/wallet/demo
```

As in Core, wallet calls go to a named wallet through the `/wallet/<name>` URL path. Responses always carry `"jsonrpc":"2.0"`, even for 1.0-style requests. A read-only REST interface is available with `--rest`. The method list and known differences from Core are in [docs/rpc.md](docs/rpc.md).

## Development

```bash
bun test                         # unit and integration tests (about 6,700; three minutes)
```

```
src/cli/          command line, config file, node startup and shutdown
src/consensus/    chain parameters, proof of work, BIP-9 deployments, assumevalid
src/script/       script interpreter
src/validation/   block and transaction checks, parallel script verification
src/chain/        chain state, UTXO cache, assumeUTXO snapshots
src/storage/      LevelDB database, undo data, pruning, indexes
src/p2p/, sync/   P2P messages, peers, address manager, header and block sync
src/mempool/      mempool, RBF, package relay, orphans
src/rpc/          JSON-RPC, REST and ZMQ
src/wallet/       descriptor wallet, PSBT, miniscript
```

[docs/architecture.md](docs/architecture.md) describes how the parts fit together, [docs/building.md](docs/building.md) covers the toolchain and dependencies, and [CONTRIBUTING.md](CONTRIBUTING.md) explains how to send changes.

## Security

Please report vulnerabilities privately, as described in [SECURITY.md](SECURITY.md).

## License

MIT. See [LICENSE](LICENSE).
