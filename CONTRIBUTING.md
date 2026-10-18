# Contributing to hotbuns

Thank you for helping. hotbuns is a from-scratch Bitcoin node, so correctness matters more than features or speed.

## Build and test

See [docs/building.md](docs/building.md) for Bun 1.3.11 and libsecp256k1. Then:

```bash
bun install
bun test
```

Before opening a pull request, run the suite and check that your change adds no failures; [docs/status.md](docs/status.md#test-suite) lists the failures already on `master`. For a change to the script interpreter, also run Core's vectors with `bun tests/script_vectors.ts` and `bun tests/sighash_vectors.ts`.

## Pull requests

- Every behaviour change comes with a test that fails before the change and passes after it. Name the test in the pull request description.
- Put tests next to the code they test (`src/<area>/<name>.test.ts`) or in `src/__tests__/`. A file listed in `pathIgnorePatterns` in `bunfig.toml` does not run under `bun test`, so check that your test appears in the output.
- Keep each pull request to one change. Refactors go in their own pull request.
- Do not disable, skip or delete a test without explaining why in the pull request.
- Branch from and target `master`.

## Commit messages

Use a conventional prefix and explain why the change is needed, not only what it does:

```
fix(rpc): return -8 for an out-of-range height in getblockhash

Core returns RPC_INVALID_PARAMETER (-8) here; we returned -1, which broke
clients that match on the code.
```

Common prefixes: `fix`, `feat`, `perf`, `refactor`, `test`, `docs`, `chore`. A scope in parentheses (`consensus`, `p2p`, `rpc`, `storage`, `wallet`) helps reviewers.

## Consensus changes

Anything that can change whether a block or transaction is accepted (script, validation, UTXO handling, chain selection, reorganisations) needs evidence that hotbuns behaves like Bitcoin Core afterwards. Point to the Core source that defines the behaviour, add a test with the concrete input (Core's test vectors where they exist), and describe how the change could make a valid block invalid or an invalid block valid, and which test covers that. Where possible, show the same input on Core and on hotbuns giving the same result, for example on regtest as in [docs/status.md](docs/status.md).
