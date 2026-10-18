# Status and how to check it

Each row of the status table in the [README](../README.md) can be checked with the commands on this page. Last updated 2026-10-17, against the `master` commit of that date, with Bun 1.3.11 on Debian 13. Commands run from the repository root after `bun install`.

## Test suite

```bash
bun test
```

On 2026-10-17 this ran 6,736 tests in 247 files: 6,668 passed, 2 failed, 47 were skipped and 19 are marked todo. It takes about three minutes. The last lines give the totals:

```
 6668 pass
 2 fail
 47 skip
 19 todo
Ran 6736 tests across 247 files.
```

The two failures are in `src/__tests__/w125_error_parity.test.ts`, which checks that the wallet error codes -35 and -36 exist; they do not yet. Because of them, `bun test` exits with status 1 on `master`. `src/validation/script-verify-parallelism.test.ts` measures a speed-up from worker threads and can also fail on a heavily loaded machine.

`bunfig.toml` runs every test file in its own process and excludes 21 files (`pathIgnorePatterns`) that are known to fail or need a live node. To run a single file in-process:

```bash
HOTBUNS_UNIT_CHILD=1 bun test ./src/script/interpreter.test.ts
```

On 2026-10-17 this file ran 113 tests: 113 passed, 0 failed.

## Script interpreter against Core's vectors

`tests/script_vectors.ts` and `tests/sighash_vectors.ts` run Bitcoin Core's `script_tests.json` and `sighash.json`. They look for a Bitcoin Core checkout at `bitcoin-core/` inside this repository or next to it (`../bitcoin-core`):

```bash
git clone --depth 1 --branch v31.1 https://github.com/bitcoin/bitcoin.git ../bitcoin-core
bun tests/script_vectors.ts
bun tests/sighash_vectors.ts
```

Results on 2026-10-17:

```
script_tests.json results: 1222 passed, 0 failed, 51 skipped, 0 parse errors
Sighash test vectors: 500 passed, 0 failed, 1 skipped (header)
```

The 51 skipped script rows are comments, and the skipped sighash row is the header.

## UTXO set against Core, on regtest

This builds a chain on Bitcoin Core, lets hotbuns sync it over P2P, and compares the two UTXO-set hashes. `hash_serialized_3` covers every coin, so one wrong coin, amount or script changes it. You need Bitcoin Core's `bitcoind` and `bitcoin-cli` on your `PATH`; this was run with Core v31.1.

```bash
CORE=$(mktemp -d); NODE=$(mktemp -d)
bitcoind -regtest -datadir="$CORE" -port=18544 -rpcport=18543 -listen=1 -daemon
sleep 3
bitcoin-cli -regtest -datadir="$CORE" -rpcport=18543 generatetoaddress 200 bcrt1qlfglp2xalgefyyy8hdh3h6wg8ceqn006jdyp89
bun run src/index.ts start --network=regtest --datadir="$NODE" --metrics-port=0 --connect=127.0.0.1:18544 &
sleep 20
bitcoin-cli -regtest -datadir="$CORE" -rpcport=18543 gettxoutsetinfo
curl -s --user "$(cat "$NODE/.cookie")" -d '{"method":"gettxoutsetinfo","params":[]}' http://127.0.0.1:18443/
curl -s --user "$(cat "$NODE/.cookie")" -d '{"method":"stop","params":[]}' http://127.0.0.1:18443/
bitcoin-cli -regtest -datadir="$CORE" -rpcport=18543 stop
```

Both report `"height": 200`, the same `bestblock`, `"txouts": 200` and `"hash_serialized_3": "55a904f0ebf65d38b61e674ea2c411e0241cd7d311ad8c5f35c24c9eafbfe44f"`. The block hashes change from run to run because block times differ, but this UTXO hash does not: the chain holds only coinbase outputs to a fixed address, and their txids do not depend on the time.

## UTXO set against Core, on mainnet

The same comparison works on mainnet but needs a full sync of both nodes. Run hotbuns with `--noassumevalid` so every script is verified, wait until both nodes report the same `bestblock` in `gettxoutsetinfo`, and compare `hash_serialized_3`.

Bitcoin Core can also produce the hash for a past height, so you do not have to catch both nodes at the same tip: `bitcoin-cli -named dumptxoutset path=<file> rollback=<height>` returns it as `txoutset_hash`. For height 958,794 Core's value is `29692050559b8f064a03af9cd605040e71d1d978fa22947c079cc7e5546e7af0` over 166,180,925 coins.

hotbuns has not completed such a from-genesis mainnet sync yet. A full sync with script checks on takes much longer than Core's.

## RPC coverage

Start a regtest node as in the README's quick start, then list the methods:

```bash
curl -s --user "$(cat "$DATADIR/.cookie")" -d '{"method":"help","params":[]}' http://127.0.0.1:18443/
```

[rpc.md](rpc.md) lists all 139 and the known differences from Core.

## Known limitations

- No signet support.
- ZMQ publishers cannot be configured from the command line.
- The `wallet` CLI subcommands use a separate, older wallet file; use the RPC wallet.
- `bun run typecheck` reports type errors in test files.
- Initial sync with script verification is CPU-bound and slower than Bitcoin Core's.
