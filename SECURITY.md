# Security policy

hotbuns is an experimental, independent implementation of a Bitcoin full node. It is meant for research and testing. Do not use it to hold or move real funds.

## Supported versions

Only the latest `master` receives fixes. There are no long-term support releases and no response-time guarantee.

## Reporting a vulnerability

Please do not open a public GitHub issue for a problem in consensus, P2P or wallet code. A public report can put other nodes at risk before a fix exists.

Email the maintainer at `max@dockyard.navy` with:

- the affected component and commit,
- a reproduction: a regtest script, a block or transaction in hex, or a malformed P2P message,
- what happens and what you expected (ideally what Bitcoin Core does with the same input),
- a suggested fix, if you have one.

You will get an acknowledgement, a fix and disclosure timeline agreed with you, and credit if you want it.

## In scope

- Consensus divergence: hotbuns accepting a block or transaction that Bitcoin Core rejects, or rejecting one Core accepts.
- Remotely triggerable crashes, hangs, memory exhaustion or disk exhaustion through P2P messages, or through RPC on a port reachable beyond localhost.
- Chainstate corruption after a crash or power loss.
- Wallet bugs that sign with the wrong key, produce a transaction the network rejects, compute a wrong fee, or lose keys.

## Out of scope

- Sync speed and resource use that is merely high.
- Attacks that need an already compromised host or access to the datadir.
- Exposing the RPC, REST or metrics port to an untrusted network. REST and metrics have no authentication, and the metrics port (9332) listens on all interfaces by default; turn it off with `--metrics-port=0` or firewall it.

## Configuration to check

- The RPC server accepts the user name `user` and password `pass` unless you set `--rpc-user` / `--rpc-password`. It binds to `127.0.0.1`, so this matters on shared hosts; set your own password or rely on the cookie.
- The P2P port listens on all interfaces by default. Use `--bind=127.0.0.1` or `--listen=0` to restrict it.

## Wallet caveats

The wallet has not been reviewed for custody. Wallet files live under `<datadir>/wallets/` and include the HD seed. They are not encrypted unless you call `encryptwallet`; protect the datadir accordingly.
