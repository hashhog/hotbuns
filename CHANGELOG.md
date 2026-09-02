# Changelog

## v1.0.0 (unreleased)

Changes since `v0.1.0-beta1`:

- 3479813 test: three tests left stale by the 2026-08-27..31 RPC fixes
- d577cde test(rpc): server.test.ts -- 8 expectations stale against Core behaviour
- 1c1fa8d fix(rpc): arity error carries Core's help signature, not a generic phrase
- 3adafbb docs: LICENSE, SECURITY.md, toolchain versions (release hygiene)
- d30ea9d fix(rpc): validate argument COUNT centrally, as Core does (#103)
- 463dbf7 fix(test): consensus vector suite could not find its vectors
- 50081a9 fix(rpc): the integer conversion runs before the lookup, and setban/disconnectnode match Core
- 200908a fix(rpc): read integer arguments at Core's width, and honour the ones we read
- 3d79e43 fix(rpc): createrawtransaction and createpsbt ignored the `version` argument
- 5dc2004 fix(rpc): submitblock decode failure reports Core's token, not the decoder's own text
- 9470e5e fix(rpc): createrawtransaction contradiction check uses Core's -8, not -32602
- b47f39a fix(rpc): createrawtransaction argument domains match Core; no Node error escapes to the wire
- a14f84d fix(rpc): verifytxoutproof stops blessing forged proofs — full ExtractMatches parity (w134 BUG-21/22/23/26)
- f24e0fc test(sync): work-vs-length header-selection pins via loadFromDB (#47)
- d6a17f8 fix(p2p): send() reports drops + revert; partial writes buffered through drain — the silent-send class (#74)
- 0e5e25c fix(p2p): HSS locator appends real chain-start LocatorEntries, not the bare hash

