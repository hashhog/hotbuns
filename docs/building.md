# Building hotbuns

hotbuns is TypeScript run directly by [Bun](https://bun.sh). There is no compile or bundle step: installing the dependencies is the build.

## Toolchain

- **Bun 1.3.11.** This is the version the tree is tested with. hotbuns uses Bun-specific APIs (`Bun.serve`, `Bun.file`, `bun:ffi`, Bun workers) and does not run under Node.js.
- **libsecp256k1** (shared library `libsecp256k1.so.2`). Signature verification calls it through Bun's FFI. Tested with 0.5.0.
- **git**, **curl**, and **unzip** (the Bun installer needs `unzip`).

On Debian or Ubuntu:

```bash
sudo apt-get install -y libsecp256k1-dev curl git unzip
pkg-config --modversion libsecp256k1
curl -fsSL https://bun.sh/install | bash -s "bun-v1.3.11"
export PATH=$HOME/.bun/bin:$PATH
bun --version
```

`pkg-config` prints the library version (`0.5.0` on Debian 13) and `bun --version` prints `1.3.11`. The installer puts Bun in `~/.bun` and adds it to your shell profile. Set `BUN_INSTALL=<dir>` before running it to install somewhere else.

## Dependencies

```bash
git clone https://github.com/hashhog/hotbuns.git && cd hotbuns
bun install
```

`bun install` reads `package.json` and `bun.lock`. The runtime dependencies are the `@noble` cryptography libraries (used for signing, BIP-324 key exchange and Taproot tweaks), `classic-level` (LevelDB bindings, prebuilt for common platforms) and `zeromq` (native module for ZMQ notifications). To install exactly the locked versions, use `bun install --frozen-lockfile`.

Check that the node starts:

```bash
bun run src/index.ts --help
```

The first line of output says whether the libsecp256k1 FFI loaded: `[secp256k1_ffi] ... FFI ready` when it did, `libsecp256k1 unavailable` when it did not.

## Cryptography backends

Consensus-path ECDSA and BIP-340 Schnorr verification go through libsecp256k1 (`src/crypto/secp256k1_ffi.ts`). If the library cannot be loaded, hotbuns logs a warning and falls back to the pure-JavaScript `@noble/curves` code, which is much slower during initial sync. Install the system library rather than relying on the fallback. `src/crypto/secp256k1_ffi.test.ts` cross-checks the two backends.

## Tests

`bun test` runs the test suite; see [status.md](status.md#test-suite) for what it covers and the current result.

## Reproducibility

Because the source is what runs, a build is reproducible when the commit and `bun.lock` match and the same Bun version is used. `bun install --frozen-lockfile` refuses to change the lock file.
