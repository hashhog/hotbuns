/**
 * R5 error-code parity -- every answer below was CAPTURED from Bitcoin Core
 * (bitcoin-core/build-wallet bitcoind, mainnet params, 2026-09-27) with the
 * exact same method + params, and this suite asserts hotbuns returns the SAME
 * code AND message (or the same result) over the real JSON-RPC socket.
 *
 * Two rows record the live, synced Core's answer instead of the scratch
 * (genesis, peerless) Core's: getblocktemplate and importmempool, because a
 * Core in IBD / with no peers answers -9 / -10 before reaching the checked
 * branch. Those two run on a REGTEST rig (Core's IsTestChain skips the -9/-10
 * gate for getblocktemplate; the mock tip is out of IBD on regtest).
 *
 * Before this change hotbuns answered these with the JSON-RPC TRANSPORT code
 * -32602 (or -32603 / -26 / -1 / -5), with no `importmempool`,
 * `utxoupdatepsbt` or `descriptorprocesspsbt` at all (-32601), and could not
 * decode a PSBT with zero inputs (joinpsbts). Core's rules reproduced:
 *   - central argument TYPE check (rpc/util.cpp:647-657): -3 "Wrong type
 *     passed:\n{...}" before any handler runs (pruneblockchain, getindexinfo,
 *     setnetworkactive, getblockhash);
 *   - ParseHashV / ParseHexV (-8), DecodeHexTx (-22), DecodeBase64PSBT (-22
 *     "TX decode failed invalid base64"), unknown action (-8), addnode's
 *     help-text -1, createmultisig's key-before-bounds ORDER.
 *
 * Regenerate the fixture by re-running the same calls against a Core; never
 * edit an expected value by hand to make a test pass.
 */
import { describe, it, expect, beforeAll, afterAll } from "bun:test";
import { RPCServer, RPCServerConfig, RPCServerDeps } from "../rpc/server.js";
import { MAINNET, REGTEST, type ConsensusParams } from "../consensus/params.js";

type Row = {
  method: string;
  params: unknown[];
  core: { error?: { code: number; message: string }; result?: unknown };
  note?: string;
};

const CORE_ROWS: Row[] = [
 {
  "method": "decoderawtransaction",
  "params": [
   "zz"
  ],
  "core": {
   "error": {
    "code": -22,
    "message": "TX decode failed"
   }
  }
 },
 {
  "method": "sendrawtransaction",
  "params": [
   "deadbeef"
  ],
  "core": {
   "error": {
    "code": -22,
    "message": "TX decode failed. Make sure the tx has at least one input."
   }
  }
 },
 {
  "method": "submitpackage",
  "params": [
   []
  ],
  "core": {
   "error": {
    "code": -8,
    "message": "Array must contain between 1 and 25 transactions."
   }
  }
 },
 {
  "method": "submitpackage",
  "params": [
   [
    "zz"
   ]
  ],
  "core": {
   "error": {
    "code": -22,
    "message": "TX decode failed: zz Make sure the tx has at least one input."
   }
  }
 },
 {
  "method": "prioritisetransaction",
  "params": [
   "zz",
   0,
   1000
  ],
  "core": {
   "error": {
    "code": -8,
    "message": "txid must be of length 64 (not 2, for 'zz')"
   }
  }
 },
 {
  "method": "scantxoutset",
  "params": [
   "bogus"
  ],
  "core": {
   "error": {
    "code": -8,
    "message": "Invalid action 'bogus'"
   }
  }
 },
 {
  "method": "pruneblockchain",
  "params": [
   "zz"
  ],
  "core": {
   "error": {
    "code": -3,
    "message": "Wrong type passed:\n{\n    \"Position 1 (height)\": \"JSON value of type string is not of expected type number\"\n}"
   }
  }
 },
 {
  "method": "getindexinfo",
  "params": [
   123
  ],
  "core": {
   "error": {
    "code": -3,
    "message": "Wrong type passed:\n{\n    \"Position 1 (index_name)\": \"JSON value of type number is not of expected type string\"\n}"
   }
  }
 },
 {
  "method": "setnetworkactive",
  "params": [
   "x"
  ],
  "core": {
   "error": {
    "code": -3,
    "message": "Wrong type passed:\n{\n    \"Position 1 (state)\": \"JSON value of type string is not of expected type bool\"\n}"
   }
  }
 },
 {
  "method": "addnode",
  "params": [
   "192.0.2.1:8333",
   "notacommand"
  ],
  "core": {
   "error": {
    "code": -1,
    "message": "addnode \"node\" \"command\" ( v2transport )\n\nAttempts to add or remove a node from the addnode list.\nOr try a connection to a node once.\nNodes added using addnode (or -connect) are protected from DoS disconnection and are not required to be\nfull nodes/support SegWit as other outbound peers are (though such peers will not be synced from).\nAddnode connections are limited to 8 at a time and are counted separately from the -maxconnections limit.\n\nArguments:\n1. node           (string, required) The IP address/hostname optionally followed by :port of the peer to connect to\n2. command        (string, required) 'add' to add a node to the list, 'remove' to remove a node from the list, 'onetry' to try a connection to the node once\n3. v2transport    (boolean, optional, default=set by -v2transport) Attempt to connect using BIP324 v2 transport protocol (ignored for 'remove' command)\n\nResult:\nnull    (json null)\n\nExamples:\n> bitcoin-cli addnode \"192.168.0.6:8333\" \"onetry\" true\n> curl --user myusername --data-binary '{\"jsonrpc\": \"2.0\", \"id\": \"curltest\", \"method\": \"addnode\", \"params\": [\"192.168.0.6:8333\", \"onetry\" true]}' -H 'content-type: application/json' http://127.0.0.1:8332/\n"
   }
  }
 },
 {
  "method": "createpsbt",
  "params": [
   [
    {
     "txid": "zz",
     "vout": 0
    }
   ],
   {
    "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4": 0.001
   }
  ],
  "core": {
   "error": {
    "code": -8,
    "message": "txid must be of length 64 (not 2, for 'zz')"
   }
  }
 },
 {
  "method": "decodepsbt",
  "params": [
   "notbase64!!"
  ],
  "core": {
   "error": {
    "code": -22,
    "message": "TX decode failed invalid base64"
   }
  }
 },
 {
  "method": "analyzepsbt",
  "params": [
   "notbase64!!"
  ],
  "core": {
   "error": {
    "code": -22,
    "message": "TX decode failed invalid base64"
   }
  }
 },
 {
  "method": "finalizepsbt",
  "params": [
   "notbase64!!"
  ],
  "core": {
   "error": {
    "code": -22,
    "message": "TX decode failed invalid base64"
   }
  }
 },
 {
  "method": "utxoupdatepsbt",
  "params": [
   "notbase64!!"
  ],
  "core": {
   "error": {
    "code": -22,
    "message": "TX decode failed invalid base64"
   }
  }
 },
 {
  "method": "combinepsbt",
  "params": [
   []
  ],
  "core": {
   "error": {
    "code": -8,
    "message": "Parameter 'txs' cannot be empty"
   }
  }
 },
 {
  "method": "descriptorprocesspsbt",
  "params": [
   "cHNidP8BAFICAAAAAaqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqAAAAAAD9////AaCGAQAAAAAAFgAUdR526BmRltRUlBxF0bOjI/FDO9YAAAAAAAAA",
   [
    "nonsense(desc)"
   ]
  ],
  "core": {
   "error": {
    "code": -5,
    "message": "'nonsense(desc)' is not a valid descriptor function"
   }
  }
 },
 {
  "method": "createmultisig",
  "params": [
   1,
   [
    "deadbeef"
   ]
  ],
  "core": {
   "error": {
    "code": -5,
    "message": "Pubkey \"deadbeef\" must have a length of either 33 or 65 bytes"
   }
  }
 },
 {
  "method": "createmultisig",
  "params": [
   3,
   [
    "03789ed0bb717d88f7d321a368d905e7430207ebbd82bd342cf11ae157a7ace5fd",
    "03dbc6764b8884a92e871274b87583e6d5c2a58819473e17e107ef3f6aa5a61626"
   ]
  ],
  "core": {
   "error": {
    "code": -8,
    "message": "not enough keys supplied (got 2 keys, but need at least 3 to redeem)"
   }
  }
 },
 {
  "method": "createmultisig",
  "params": [
   3,
   [
    "deadbeef",
    "deadbeef"
   ]
  ],
  "core": {
   "error": {
    "code": -5,
    "message": "Pubkey \"deadbeef\" must have a length of either 33 or 65 bytes"
   }
  }
 },
 {
  "method": "createmultisig",
  "params": [
   0,
   [
    "03789ed0bb717d88f7d321a368d905e7430207ebbd82bd342cf11ae157a7ace5fd"
   ]
  ],
  "core": {
   "error": {
    "code": -8,
    "message": "a multisignature address must require at least one key to redeem"
   }
  }
 },
 {
  "method": "createmultisig",
  "params": [
   1,
   [
    "zz"
   ]
  ],
  "core": {
   "error": {
    "code": -5,
    "message": "Pubkey \"zz\" must be a hex string"
   }
  }
 },
 {
  "method": "createmultisig",
  "params": [
   1,
   [
    "03789ed0bb717d88f7d321a368d905e7430207ebbd82bd342cf11ae157a7ace5fd"
   ],
   "bech32m"
  ],
  "core": {
   "error": {
    "code": -5,
    "message": "createmultisig cannot create bech32m multisig addresses"
   }
  }
 },
 {
  "method": "createmultisig",
  "params": [
   1,
   [
    "03789ed0bb717d88f7d321a368d905e7430207ebbd82bd342cf11ae157a7ace5fd"
   ],
   "bogus"
  ],
  "core": {
   "error": {
    "code": -5,
    "message": "Unknown address type 'bogus'"
   }
  }
 },
 {
  "method": "verifymessage",
  "params": [
   "1GAehh7TsJAHuUAeKZcXf5CnwuGuGgyX2S",
   "not-base64!!",
   "hashhog r5 probe"
  ],
  "core": {
   "error": {
    "code": -3,
    "message": "Malformed base64 encoding"
   }
  }
 },
 {
  "method": "verifymessage",
  "params": [
   "1GAehh7TsJAHuUAeKZcXf5CnwuGuGgyX2S",
   "AAAA",
   "hashhog r5 probe"
  ],
  "core": {
   "result": false
  }
 },
 {
  "method": "verifytxoutproof",
  "params": [
   "zz"
  ],
  "core": {
   "error": {
    "code": -8,
    "message": "proof must be hexadecimal string (not 'zz')"
   }
  }
 },
 {
  "method": "gettxoutproof",
  "params": [
   [
    "0000000000000000000000000000000000000000000000000000000000000000"
   ]
  ],
  "core": {
   "error": {
    "code": -5,
    "message": "Transaction not yet in block"
   }
  }
 },
 {
  "method": "gettxoutproof",
  "params": [
   []
  ],
  "core": {
   "error": {
    "code": -8,
    "message": "Parameter 'txids' cannot be empty"
   }
  }
 },
 {
  "method": "gettxspendingprevout",
  "params": [
   [
    {
     "txid": "0000000000000000000000000000000000000000000000000000000000000000"
    }
   ]
  ],
  "core": {
   "error": {
    "code": -3,
    "message": "Missing vout"
   }
  }
 },
 {
  "method": "getrawtransaction",
  "params": [
   "zz"
  ],
  "core": {
   "error": {
    "code": -8,
    "message": "parameter 1 must be of length 64 (not 2, for 'zz')"
   }
  }
 },
 {
  "method": "getblockhash",
  "params": [
   "zz"
  ],
  "core": {
   "error": {
    "code": -3,
    "message": "Wrong type passed:\n{\n    \"Position 1 (height)\": \"JSON value of type string is not of expected type number\"\n}"
   }
  }
 },
 {
  "method": "getdescriptorinfo",
  "params": [
   "notadescriptor"
  ],
  "core": {
   "error": {
    "code": -5,
    "message": "'notadescriptor' is not a valid descriptor function"
   }
  }
 },
 {
  "method": "getblocktemplate",
  "params": [
   {}
  ],
  "core": {
   "error": {
    "code": -8,
    "message": "getblocktemplate must be called with the segwit rule set (call with {\"rules\": [\"segwit\"]})"
   }
  },
  "note": "live Core (connected, synced) answer; the genesis scratch Core answers -9 first"
 },
 {
  "method": "importmempool",
  "params": [
   "/nonexistent/r5-probe-no-such-file.dat"
  ],
  "core": {
   "error": {
    "code": -1,
    "message": "Unable to import mempool file, see debug log for details."
   }
  },
  "note": "live Core (synced) answer; a Core in IBD answers -10 first"
 },
 {
  "method": "validateaddress",
  "params": [
   "notanaddress"
  ],
  "core": {
   "result": {
    "isvalid": false,
    "error_locations": [],
    "error": "Invalid checksum or length of Base58 address (P2PKH or P2SH)"
   }
  }
 },
 {
  "method": "joinpsbts",
  "params": [
   [
    "cHNidP8BAFICAAAAAaqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqAAAAAAD9////AaCGAQAAAAAAFgAUdR526BmRltRUlBxF0bOjI/FDO9YAAAAAAAAA",
    "cHNidP8BACkCAAAAAAGghgEAAAAAABYAFHUedugZkZbUVJQcRdGzoyPxQzvWAAAAAAAA"
   ]
  ],
  "core": {
   "result": "cHNidP8BAHECAAAAAaqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqAAAAAAD9////AqCGAQAAAAAAFgAUdR526BmRltRUlBxF0bOjI/FDO9aghgEAAAAAABYAFHUedugZkZbUVJQcRdGzoyPxQzvWAAAAAAAAAAA="
  }
 },
 {
  "method": "utxoupdatepsbt",
  "params": [
   "cHNidP8BAFICAAAAAaqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqAAAAAAD9////AaCGAQAAAAAAFgAUdR526BmRltRUlBxF0bOjI/FDO9YAAAAAAAAA"
  ],
  "core": {
   "result": "cHNidP8BAFICAAAAAaqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqAAAAAAD9////AaCGAQAAAAAAFgAUdR526BmRltRUlBxF0bOjI/FDO9YAAAAAAAAA"
  }
 },
 {
  "method": "descriptorprocesspsbt",
  "params": [
   "cHNidP8BAFICAAAAAaqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqAAAAAAD9////AaCGAQAAAAAAFgAUdR526BmRltRUlBxF0bOjI/FDO9YAAAAAAAAA",
   [
    "wpkh(KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn)"
   ]
  ],
  "core": {
   "result": {
    "psbt": "cHNidP8BAFICAAAAAaqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqAAAAAAD9////AaCGAQAAAAAAFgAUdR526BmRltRUlBxF0bOjI/FDO9YAAAAAAAAiAgJ5vmZ++dy7rFWgYpXOhwsHApv82y3OKNlZ8oFbFvgXmAR1HnboAA==",
    "complete": false
   }
  }
 },
 {"method": "verifytxoutproof", "params": ["0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000111111111111111111111111111111111111111111111111111111111111111110101"], "core": {"result": []}, "note": "merkle root != header root: Core returns [] (never throws)"},
 {"method": "verifytxoutproof", "params": ["0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"], "core": {"error": {"code": -1, "message": "SpanReader::read(): end of data: iostream error"}}, "note": "truncated proof"}
];

const REGTEST_METHODS = new Set(["getblocktemplate", "importmempool"]);

let portCounter = 29761;

class MockChainStateManager {
  getBestBlock() {
    return { hash: Buffer.alloc(32, 0), height: 100, chainWork: 1000n };
  }
  getUTXOManager() {
    return { async getUTXOAsync() { return null; }, getUTXO() { return null; } };
  }
}
class MockMempool {
  getInfo() { return { size: 0, bytes: 0, minFeeRate: 1 }; }
  getAllTxids() { return []; }
  getTransaction() { return null; }
  hasTransaction() { return false; }
  getSize() { return 0; }
  async isTransactionConfirmed() { return false; }
}
class MockPeerManager {
  getConnectedPeers() { return []; }
  broadcast() {}
}
class MockFeeEstimator {
  estimateSmartFee() { return { feeRate: 10, blocks: 6 }; }
  getBuckets() { return []; }
}
class MockHeaderSync {
  getBestHeader() {
    return { hash: Buffer.alloc(32, 0), height: 100, chainWork: 1000n };
  }
  getHeader() { return undefined; }
  getMedianTimePast() { return 0; }
  isOnBestHeaderChain() { return false; }
}
class MockChainDB {
  async getBlock() { return null; }
  async getBlockIndex() { return null; }
  async getBlockHashByHeight() { return null; }
  async getChainWork(): Promise<bigint | null> { return null; }
  async getChainState() {
    return { bestBlockHash: Buffer.alloc(32, 0), bestHeight: 100 };
  }
  async getUTXO() { return null; }
  async getTxIndex() { return null; }
}

function makeServer(params: ConsensusParams): { server: RPCServer; port: number } {
  const port = portCounter++;
  const config: RPCServerConfig = { port, host: "127.0.0.1", noAuth: true };
  const deps: RPCServerDeps = {
    chainState: new MockChainStateManager() as any,
    mempool: new MockMempool() as any,
    peerManager: new MockPeerManager() as any,
    feeEstimator: new MockFeeEstimator() as any,
    headerSync: new MockHeaderSync() as any,
    db: new MockChainDB() as any,
    params,
  };
  const server = new RPCServer(config, deps);
  server.start();
  return { server, port };
}

async function call(port: number, method: string, params: unknown[]): Promise<any> {
  const r = await fetch(`http://127.0.0.1:${port}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ jsonrpc: "1.0", id: 1, method, params }),
  });
  return r.json();
}

describe("R5 error-code parity: hotbuns answers exactly as Core", () => {
  let main: { server: RPCServer; port: number };
  let reg: { server: RPCServer; port: number };

  beforeAll(() => {
    main = makeServer(MAINNET);
    reg = makeServer(REGTEST);
  });
  afterAll(() => {
    main.server.stop();
    reg.server.stop();
  });

  for (const row of CORE_ROWS) {
    const label = `${row.method} ${JSON.stringify(row.params).slice(0, 70)}`;
    it(label, async () => {
      const port = REGTEST_METHODS.has(row.method) ? reg.port : main.port;
      const resp = await call(port, row.method, row.params);
      if (row.core.error) {
        expect(resp.error ?? null).not.toBeNull();
        expect(resp.error.code).toBe(row.core.error.code);
        expect(resp.error.message).toBe(row.core.error.message);
      } else {
        expect(resp.error ?? null).toBeNull();
        expect(resp.result).toEqual(row.core.result);
      }
    });
  }

  // CONTROLS: the central type check must not reject what Core accepts.
  it("control: optional args may be null / omitted (no type error)", async () => {
    const resp = await call(main.port, "getblockhash", [0]);
    expect(resp.error?.code === -3).toBe(false);
  });
  it("control: skip_type_check args are not type-checked (getblock verbosity bool)", async () => {
    const resp = await call(main.port, "getblock", ["00".repeat(32), true]);
    expect(resp.error?.code === -3).toBe(false);
  });
  it("control: several mismatches are reported together, in position order", async () => {
    const resp = await call(main.port, "getblockheader", [1, "x"]);
    expect(resp.error.code).toBe(-3);
    expect(resp.error.message).toBe(
      'Wrong type passed:\n{\n    "Position 1 (blockhash)": "JSON value of type number is not of expected type string",\n    "Position 2 (verbose)": "JSON value of type string is not of expected type bool"\n}'
    );
  });
});
