# Security Policy — hotbuns

hotbuns is a from-scratch Bitcoin full-node implementation in TypeScript on the Bun
runtime, part of the [hashhog](https://github.com/hashhog) fleet of ten independent
nodes that cross-validate each other and Bitcoin Core.

## Project maturity — read this first

hotbuns is a pre-release, best-effort node. It has NOT completed an
`--assumevalid=0` genesis-to-tip validation on this fleet's hardware, and its unit
test suite is not fully green. It is intended to be run *beside* Bitcoin Core with
`consensus-diff` as a live divergence alarm, not as a sole source of truth.

**It is NOT fund-capable.** Do not custody funds on it. There are no fund-grade
guarantees. Run from a pinned commit.

## Supported versions

| Version | Supported |
|---------|-----------|
| `v0.1.0-beta1` | Beta — best-effort; no security SLA |
| pre-release (`master`) | Best-effort |

Release-signing key fingerprint: to be published with v1.0.0.

## Reporting a vulnerability

**Please do NOT open a public GitHub issue** for anything in the consensus, P2P, or
wallet paths — a public report could put real Bitcoin nodes or funds at risk.

Report privately to the maintainer:

- **Email:** `max@dockyard.navy`  <!-- TODO(max): confirm or replace with a dedicated security alias -->

Include the affected path, a deterministic reproduction (a diff-test corpus entry,
regtest script, or malformed message), impact, and any suggested fix. We coordinate
a fix + disclosure timeline and credit you if you wish.

## In scope (highest priority)

- **Consensus divergence** — hotbuns accepting a block/tx Core rejects, or vice-versa.
  This is the core concern (see `../CORE-PARITY-AUDIT/`).
- **Remotely-triggerable crashes / OOM / resource exhaustion** in the P2P or block/tx
  decode paths.
- **Wallet funds-safety** — silent wrong-key signing, a spend the node reports valid
  that the network rejects, un-recoverable backups, fee miscalculation stranding funds.
- **Chainstate corruption on crash.**

## Custody caveats

hotbuns' wallet is experimental; nothing in it should be treated as fund-safe. Any
wallet path issue is in scope but no custody use is supported.

## Out of scope

- IBD/sync performance characteristics.
- Issues requiring an already-compromised host.

## Disclosure

Coordinated disclosure. Consensus fixes are verified with `../tools/verify-fix.sh` and
gated through the differential corpus before they are considered landed.
