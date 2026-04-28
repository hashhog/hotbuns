#!/usr/bin/env bun
// BIP-341 vector-runner shim for hotbuns. Drives sigMsgTaproot +
// sigHashTaproot through the stdin/stdout JSON protocol described in
// tools/bip341-vector-runner/README.md.
//
// Input (one JSON object per line on stdin):
//   { "tx_hex": "...", "input_index": 0,
//     "spent_amounts": [12345, ...],
//     "spent_scripts": ["hex...", ...],
//     "hash_type": 0,
//     "annex_hex": null }
//
// Output (one JSON object per line on stdout):
//   { "sig_msg": "hex...", "sig_hash": "hex..." }

import {
  deserializeTx,
  sigMsgTaproot,
  sigHashTaproot,
  type Transaction,
  type TaprootSigHashCache,
} from "../../src/validation/tx";
import { BufferReader } from "../../src/wire/serialization";

interface Request {
  tx_hex: string;
  input_index: number;
  spent_amounts: number[];
  spent_scripts: string[];
  hash_type: number;
  annex_hex: string | null;
}

function processRequest(req: Request): { sig_msg: string; sig_hash: string } {
  const txBytes = Buffer.from(req.tx_hex, "hex");
  const tx: Transaction = deserializeTx(new BufferReader(txBytes));

  const prevOuts = req.spent_amounts.map((amt, i) => ({
    value: BigInt(amt),
    scriptPubKey: Buffer.from(req.spent_scripts[i], "hex"),
  }));

  const annexHash =
    req.annex_hex != null ? Buffer.from(req.annex_hex, "hex") : undefined;

  const cache: TaprootSigHashCache = {};

  // BIP-341 wallet vectors only exercise key-path (ext_flag=0).
  const sigMsg = sigMsgTaproot(
    tx, req.input_index, prevOuts, req.hash_type, 0,
    annexHash, undefined, undefined, 0xffffffff, cache,
  );
  const sigHash = sigHashTaproot(
    tx, req.input_index, prevOuts, req.hash_type, 0,
    annexHash, undefined, undefined, 0xffffffff, cache,
  );

  return {
    sig_msg: sigMsg.toString("hex"),
    sig_hash: sigHash.toString("hex"),
  };
}

// Read JSON lines from stdin, write JSON lines to stdout.
const decoder = new TextDecoder();
let buffer = "";

for await (const chunk of Bun.stdin.stream()) {
  buffer += decoder.decode(chunk);
  let nl: number;
  while ((nl = buffer.indexOf("\n")) >= 0) {
    const line = buffer.slice(0, nl).trim();
    buffer = buffer.slice(nl + 1);
    if (!line) continue;
    try {
      const req = JSON.parse(line) as Request;
      const resp = processRequest(req);
      process.stdout.write(JSON.stringify(resp) + "\n");
    } catch (e) {
      const msg = (e as Error).message.replace(/"/g, '\\"');
      process.stdout.write(`{"error":"${msg}"}\n`);
    }
  }
}
