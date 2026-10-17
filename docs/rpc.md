# RPC reference

hotbuns serves a JSON-RPC interface over HTTP on the RPC port (8332 mainnet, 48332 testnet4, 18332 testnet3, 18443 regtest), bound to `127.0.0.1`. Method names, parameter order and result fields follow Bitcoin Core, so most clients written for `bitcoind` work.

## Calling it

Authenticate with HTTP Basic auth, either with the cookie the node writes to `<datadir>/.cookie` (user `__cookie__`) or with `--rpc-user` / `--rpc-password` (default `user` / `pass`). A request is a JSON object, or a JSON array of objects for a batch. A request without an `id` gets a response without one. Wallet methods take the wallet from the URL path `/wallet/<name>`, as in Core.

With a regtest node running as in the README quick start:

```bash
COOKIE="$(cat "$DATADIR/.cookie")"
curl -s --user "$COOKIE" -d '{"jsonrpc":"2.0","id":1,"method":"getblockhash","params":[0]}' http://127.0.0.1:18443/
curl -s --user "$COOKIE" -d '[{"method":"getblockcount","id":1},{"method":"getbestblockhash","id":2}]' http://127.0.0.1:18443/
curl -s --user "$COOKIE" -d '{"method":"help","params":[]}' http://127.0.0.1:18443/
```

The first call returns the regtest genesis hash, `0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206`, with `"id":1`. The batch returns an array with one response per request, in request order: block count 0, then the same genesis hash. `help` returns every method name, one per line. The table below is the dispatch table in `src/rpc/server.ts` (`registerMethod` calls): 139 methods.

## REST

`--rest` starts a read-only REST server on `127.0.0.1`, on the RPC port plus one unless `--rest-port` is set. It has no authentication. Endpoints follow Core's: `chaininfo.json`, `mempool/info.json`, `mempool/contents.json`, `block/<hash>`, `block/notxdetails/<hash>`, `tx/<txid>`, `headers/<count>/<hash>`, `blockhashbyheight/<height>`, `getutxos[/checkmempool]/<txid>-<n>/...`, `blockfilter/basic/<hash>`, `blockfilterheaders/basic/<count>/<hash>`, each with a `.json`, `.bin` or `.hex` suffix.

On regtest the default REST port, 18444, is also the P2P port, so give REST its own port:

```bash
DATADIR=$(mktemp -d)
bun run src/index.ts --network=regtest --datadir="$DATADIR" --metrics-port=0 --rest --rest-port=18450 &
sleep 5
curl -s http://127.0.0.1:18450/rest/chaininfo.json
curl -s http://127.0.0.1:18450/rest/blockhashbyheight/0.hex
curl -s --user "$(cat "$DATADIR/.cookie")" -d '{"method":"stop","params":[]}' http://127.0.0.1:18443/
```

`chaininfo.json` starts `{"chain":"regtest","blocks":0,"headers":0,"bestblockhash":"0f9188f1...`, and `blockhashbyheight/0.hex` prints the genesis hash on its own. Some `chaininfo.json` fields differ from Core's; see [Known differences from Core](#known-differences-from-core).

## ZMQ

`getzmqnotifications` exists, but there are no command-line flags to configure ZMQ publishers, so it returns an empty list.

## Methods

Marks: † not in Bitcoin Core v31.1; ‡ in Core but hidden from Core's `help`.

| Group | Methods |
|---|---|
| Blockchain | `getbestblockhash`, `getblock`, `getblockchaininfo`, `getblockcount`, `getblockfilter`, `getblockhash`, `getblockheader`, `getblockstats`, `getchainstates`, `getchaintips`, `getchaintxstats`, `getdeploymentinfo`, `getdifficulty`, `getmempoolancestors`, `getmempooldescendants`, `getmempoolentry`, `getmempoolinfo`, `getrawmempool`, `gettxout`, `gettxoutproof`, `gettxoutsetinfo`, `gettxspendingprevout`, `importmempool`, `loadtxoutset`, `dumptxoutset`, `preciousblock`, `pruneblockchain`, `savemempool`, `scanblocks`, `scantxoutset`, `verifychain`, `verifytxoutproof`, `waitforblock`, `waitforblockheight`, `waitfornewblock`, `invalidateblock`‡, `reconsiderblock`‡, `getsyncstate`†, `getutxosetsnapshot`†, `dumpmempool`†, `loadmempool`† |
| Control | `getmemoryinfo`, `getrpcinfo`, `help`, `logging`, `stop`, `uptime` |
| Mining | `getblocktemplate`, `getmininginfo`, `getnetworkhashps`, `getprioritisedtransactions`, `prioritisetransaction`, `submitblock`, `submitheader`, `generateblock`‡, `generatetoaddress`‡, `generatetodescriptor`‡ |
| Network | `addnode`, `clearbanned`, `disconnectnode`, `getaddednodeinfo`, `getaddrmaninfo`, `getblockfrompeer`, `getconnectioncount`, `getnettotals`, `getnetworkinfo`, `getnodeaddresses`, `getpeerinfo`, `listbanned`, `ping`, `setban`, `setnetworkactive`, `addpeeraddress`‡, `getorphantxs`‡ |
| Raw transactions | `analyzepsbt`, `combinepsbt`, `combinerawtransaction`, `converttopsbt`, `createpsbt`, `createrawtransaction`, `decodepsbt`, `decoderawtransaction`, `decodescript`, `descriptorprocesspsbt`, `finalizepsbt`, `getrawtransaction`, `joinpsbts`, `sendrawtransaction`, `signrawtransactionwithkey`, `submitpackage`, `testmempoolaccept`, `utxoupdatepsbt` |
| Util | `createmultisig`, `deriveaddresses`, `estimatesmartfee`, `getdescriptorinfo`, `getindexinfo`, `signmessagewithprivkey`, `validateaddress`, `verifymessage`, `estimaterawfee`‡ |
| Wallet | `backupwallet`, `bumpfee`, `createwallet`, `encryptwallet`, `fundrawtransaction`, `getaddressinfo`, `getbalance`, `getbalances`, `getnewaddress`, `gettransaction`, `getwalletinfo`, `importdescriptors`, `listdescriptors`, `listreceivedbyaddress`, `listtransactions`, `listunspent`, `listwalletdir`, `listwallets`, `loadwallet`, `psbtbumpfee`, `rescanblockchain`, `restorewallet`, `send`, `sendtoaddress`, `setlabel`, `signmessage`, `signrawtransactionwithwallet`, `unloadwallet`, `walletcreatefundedpsbt`, `walletlock`, `walletpassphrase`, `walletpassphrasechange`, `walletprocesspsbt`, `dumpprivkey`†, `importprivkey`†, `getpayjoinrequest`†, `sendpayjoinrequest`† |
| ZMQ | `getzmqnotifications` |

`dumpprivkey` and `importprivkey` belonged to Core's legacy wallet, which Core no longer has. `getpayjoinrequest` / `sendpayjoinrequest` implement BIP-78 PayJoin.

Core v31.1 wallet methods hotbuns does not implement include `abandontransaction`, `getrawchangeaddress`, `getreceivedbyaddress`, `listsinceblock`, `listlabels`, `lockunspent`, `listlockunspent`, `sendall`, `sendmany` and `walletdisplayaddress`. Core's `getmempoolcluster` is also missing.

## Known differences from Core

- Every response carries `"jsonrpc":"2.0"`, including replies to JSON-RPC 1.0 requests, where Core omits it and includes `"error":null`.
- Some error codes and messages differ from Core's for invalid or missing parameters. The wallet "already loaded" (-35) and "already exists" (-36) codes are not defined yet; `src/__tests__/w125_error_parity.test.ts` tracks this.
- `help` returns a flat list of names rather than Core's grouped listing, and ignores a method-name argument: `help getblockhash` also returns the full list.
- `--rpc-tls-cert` / `--rpc-tls-key` serve RPC over HTTPS directly. Core has no built-in TLS.
- REST `chaininfo.json` is a reduced object, not the `getblockchaininfo` result that Core's REST returns: `mediantime` is always 0, `pruned` is always `false`, `softforks` is an empty object (Core's `getblockchaininfo` has not returned that field since v24), and `difficulty` never goes below 1. At the regtest genesis it reports `"difficulty":1,"mediantime":0`, where the `getblockchaininfo` RPC reports `"difficulty":4.656542373906925e-10,"mediantime":1296688602`. Use the RPC for these fields.
