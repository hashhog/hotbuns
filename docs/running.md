# Running hotbuns

```
bun run src/index.ts [command] [--flag=value ...]
```

The command defaults to `start`, which runs the node in the foreground. Flags are written `--name=value`; boolean flags also accept the bare form (`--rest`) and `=0` / `=1`. Unknown flags are ignored without a warning, so check spelling. `bun run src/index.ts --help` prints a summary; this page is the full list, taken from `parseArgs` and `loadConfig` in `src/cli/cli.ts`.

## Networks and ports

| Network | Flag | P2P port | RPC port |
|---|---|---|---|
| mainnet (default) | `--network=mainnet` | 8333 | 8332 |
| testnet4 | `--network=testnet4` | 48333 | 48332 |
| testnet3 | `--network=testnet` | 18333 | 18332 |
| regtest | `--network=regtest` | 18444 | 18443 |

Signet is not supported. The RPC server binds to `127.0.0.1` only. The P2P listener binds all interfaces (`0.0.0.0` and `[::]`) unless `--bind` or `--listen=0` is given.

## Data directory

All files go directly into `--datadir` (default `~/.hotbuns`). There is no per-network subdirectory, so use a separate datadir for each network.

| Path | Contents |
|---|---|
| `blocks.db/` | LevelDB: block index, block data, undo data, UTXO set, optional indexes |
| `.cookie` | RPC cookie, rewritten on every start |
| `hotbuns.pid` | PID of the running node (see `--pid`) |
| `hotbuns.conf` | Optional config file (see below) |
| `wallets/` | Wallets created with `createwallet` |
| `mempool.dat` | Mempool saved at shutdown and reloaded at start |
| `fee_estimates.json` | Fee estimator state |
| `peers.dat` | Known peer addresses |

## Resources

For mainnet, plan for the disk of an unpruned Bitcoin Core node (several hundred GB), or prune with `--prune`. Memory use is mostly the UTXO cache (`--dbcache`, default 512 MiB) plus the Bun runtime, typically a few GB in total. Initial sync is slower than Bitcoin Core's; `--script-threads` controls how many worker threads verify scripts.

## Flags

### General

| Flag | Default | Meaning |
|---|---|---|
| `--datadir=<dir>` | `~/.hotbuns` | Data directory |
| `--conf=<file>` | `<datadir>/hotbuns.conf` | Config file; a relative path is taken from the datadir |
| `--network=<net>` | `mainnet` | `mainnet`, `testnet`, `testnet4` or `regtest` |
| `--daemon` | off | Re-launch in the background and return |
| `--pid=<file>` | `<datadir>/hotbuns.pid` | PID file; `--pid=` disables it |
| `--supervise` | off | Run the node as a child process and restart it after a crash signal (SIGSEGV, SIGILL) |
| `--supervise-restarts=<n>` | `3` | Restart limit for `--supervise` |
| `--ready-fd=<n>` | none | Write `ready` to this file descriptor once startup completes |
| `--help` | | Print usage |

### Chain and validation

| Flag | Default | Meaning |
|---|---|---|
| `--noassumevalid`, `--assumevalid=0` | off | Verify scripts in all blocks. Other `--assumevalid` values are ignored; the built-in value is used. |
| `--dbcache=<MiB>` | `512` | UTXO cache size |
| `--prune=<MiB>` | `0` | `0` off, `1` manual (`pruneblockchain` only), 550 or more: automatic target |
| `--script-threads=<n>` | `0` (auto) | Script-verification workers, at most 15; `1` verifies on the main thread |
| `--import-blocks=<path>` | none | Import blocks from a directory of `blk*.dat` files, or `-` for framed blocks on stdin |
| `--load-snapshot=<file>` | none | Load a Bitcoin Core `dumptxoutset` snapshot (assumeUTXO). The base block must be one of the built-in assumeUTXO heights. |
| `--blockfilterindex[=basic]` | off | Build BIP-158 block filters and serve BIP-157 to peers |
| `--coinstatsindex` | off | Keep per-height UTXO statistics, so `gettxoutsetinfo` can answer for past blocks |
| `--txospenderindex` | off | Record which transaction spent each output, for `gettxspendingprevout` |

### P2P

| Flag | Default | Meaning |
|---|---|---|
| `--port=<port>`, `--p2p-port=<port>` | per network | P2P listen port |
| `--bind=<addr>[:port]` | all interfaces | P2P listen address; repeatable |
| `--listen=<0\|1>` | `1` | Accept inbound connections |
| `--max-outbound=<n>` | `8` | Outbound connection target |
| `--maxconnections=<n>` | `125` | Total connection limit; inbound slots are this minus outbound |
| `--connect=<host:port>` | none | Connect only to these peers (repeatable); disables DNS seeds and automatic outbound |
| `--addnode=<host:port>` | none | Add a peer to try (repeatable) |
| `--dnsseed=<0\|1>`, `--nodnsseed` | on | Look up DNS seeds at start |
| `--externalip=<ip>[:port]` | none | Address to advertise to peers (repeatable or comma-separated) |
| `--discover=<0\|1>`, `--nodiscover` | on, off with `--externalip` | Learn our address from what peers report |
| `--peerbloomfilters` | off | Advertise NODE_BLOOM and answer BIP-35 `mempool` requests |
| `--asmap=<file>` | none | ASMap file for grouping peers by AS; relative to the datadir |
| `--proxy=<host:port>` | none | SOCKS5 proxy for outbound connections |
| `--onion=<host:port>` | none | SOCKS5 proxy for `.onion` addresses |
| `--i2psam=<host:port>` | none | I2P SAM bridge |
| `--cjdnsreachable` | off | Allow outbound CJDNS (`fc00::/8`) connections |

### RPC, REST and metrics

| Flag | Default | Meaning |
|---|---|---|
| `--rpcport=<port>`, `--rpc-port=<port>` | per network | JSON-RPC port |
| `--rpc-user=<user>` | `user` | RPC user name, accepted in addition to the cookie |
| `--rpc-password=<pass>` | `pass` | RPC password |
| `--rpc-tls-cert=<file>`, `--rpc-tls-key=<file>` | none | Serve RPC over HTTPS with this PEM certificate and key; both or neither |
| `--rest` | off | Serve the read-only REST API |
| `--rest-port=<port>` | RPC port + 1 | REST listen port (`127.0.0.1`) |
| `--metrics-port=<port>` | `9332` | Prometheus metrics on all interfaces; `0` disables |

The default `user` / `pass` credentials are accepted unless you change them, so anyone who can reach the RPC port can use them. The port binds to `127.0.0.1`, but on a shared host set `--rpc-password` (or `rpcpassword=` in the config file).

### Logging

| Flag | Default | Meaning |
|---|---|---|
| `--log-level=<level>` | `info` | `debug`, `info`, `warn` or `error` |
| `--debug=<category>` | none | Extra logging for a category (repeatable); `all` or `1` for every category, `none` or `0` for none |
| `--printtoconsole` | on | Log to stdout and stderr |

Logs go to stdout and stderr; redirect them to a file if you want to keep them. Categories follow Core's names (`net`, `mempool`, `rpc`, `validation`, `cmpctblock`, `zmq`, ...), plus `sync`, `headers` and `blocks`.

### Wallet commands

The `wallet` subcommands (`wallet create`, `wallet getaddress`, `wallet getbalance`, `wallet send <addr> <amount>`) work on a single `<datadir>/wallet.dat` file and take `--password=<pass>` and `--fee-rate=<sat/vB>`. They are separate from the RPC wallets under `wallets/`; use the RPC wallet methods instead.

## Config file

`<datadir>/hotbuns.conf` (or `--conf`) holds `key=value` lines; `#` starts a comment. The node does not create it. Values in the file override command-line flags. Recognised keys:

`network`, `rpcport`, `rpcuser`, `rpcpassword`, `rpctlscert`, `rpctlskey`, `port`, `bind`, `listen`, `maxoutbound`, `maxconnections`, `dnsseed`, `externalip`, `discover`, `peerbloomfilters`, `prune`, `dbcache`, `blockfilterindex`, `coinstatsindex`, `txospenderindex`, `rest`, `restport`, `metricsport`, `loglevel`, `debug`, `printtoconsole`, `daemon`, `pid`.

Booleans are `1` / `true` or `0` / `false`. Any other key is ignored. `config.example.toml` in the repository root uses a sectioned TOML layout that this parser does not read.

Example, run on regtest:

```bash
DATADIR=$(mktemp -d)
printf 'rpcport=18600\nport=18602\nmetricsport=0\nrest=1\n' > "$DATADIR/hotbuns.conf"
bun run src/index.ts --network=regtest --datadir="$DATADIR" &
sleep 5
curl -s --user "$(cat "$DATADIR/.cookie")" -d '{"method":"getblockcount","params":[]}' http://127.0.0.1:18600/
curl -s http://127.0.0.1:18601/rest/chaininfo.json
curl -s --user user:pass -d '{"method":"stop","params":[]}' http://127.0.0.1:18600/
```

## Environment variables

| Variable | Effect |
|---|---|
| `HOTBUNS_ASSUMEVALID=0` | Same as `--noassumevalid` |
| `HOTBUNS_SUPERVISE=1` | Same as `--supervise` |
| `HOTBUNS_BIP324_V2=0` | Turn off BIP-324 v2 transport (on by default) |
| `HASHHOG_UNSAFE_SNAPSHOT_HEIGHT=<height>` | Testing only: accept a `--load-snapshot` / `loadtxoutset` file whose base block is not built in, and take its height on trust |

## Monitoring

With `--metrics-port` set (default 9332), `GET /metrics` returns Prometheus text (`bitcoin_blocks_total`, `bitcoin_peers_connected`, `bitcoin_mempool_size` and memory gauges) and `GET /health` returns a liveness probe. Both have no authentication and listen on all interfaces, so firewall the port or set `--metrics-port=0`.

```bash
DATADIR=$(mktemp -d)
bun run src/index.ts --network=regtest --datadir="$DATADIR" --metrics-port=19332 &
sleep 5
curl -s http://127.0.0.1:19332/metrics | grep bitcoin_blocks_total
curl -s http://127.0.0.1:19332/health
curl -s --user "$(cat "$DATADIR/.cookie")" -d '{"method":"stop","params":[]}' http://127.0.0.1:18443/
```

For sync progress use the RPCs `getblockchaininfo` (`blocks`, `headers`, `verificationprogress`) and `getpeerinfo`. A periodic `IBD:` log line reports height, block rate, peer count and memory.

## Stopping

Call the `stop` RPC, or send SIGINT or SIGTERM. The node flushes the UTXO cache, saves the mempool and fee estimates, and removes the PID file before it exits.
