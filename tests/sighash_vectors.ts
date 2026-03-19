/**
 * Sighash test harness for hotbuns Bitcoin implementation.
 *
 * Loads Bitcoin Core's sighash.json test vectors and verifies
 * the legacy sighash computation against each expected result.
 *
 * Format: [raw_transaction_hex, script_hex, input_index, hash_type, expected_sighash_hex]
 */

import { readFileSync } from "fs";
import { BufferReader } from "../src/wire/serialization";
import { deserializeTx, sigHashLegacy } from "../src/validation/tx";

const VECTOR_PATH = "/home/max/hashhog/ouroboros/bitcoin/src/test/data/sighash.json";

const raw = readFileSync(VECTOR_PATH, "utf-8");
const vectors: any[] = JSON.parse(raw);

let pass = 0;
let fail = 0;
let skip = 0;

for (let i = 0; i < vectors.length; i++) {
  const entry = vectors[i];

  // First entry is a header comment (single-element array of string)
  if (entry.length === 1 && typeof entry[0] === "string") {
    skip++;
    continue;
  }

  const [rawTxHex, scriptHex, inputIndex, hashType, expectedHashHex] = entry as [
    string,
    string,
    number,
    number,
    string,
  ];

  try {
    // Deserialize the raw transaction
    const rawTx = Buffer.from(rawTxHex, "hex");
    const reader = new BufferReader(rawTx);
    const tx = deserializeTx(reader);

    // Parse the subscript
    const subscript = scriptHex.length > 0 ? Buffer.from(scriptHex, "hex") : Buffer.alloc(0);

    // Compute the sighash
    const sighash = sigHashLegacy(tx, inputIndex, subscript, hashType);

    // The test vectors store the hash in display (big-endian / reversed) order.
    // sigHashLegacy returns internal (little-endian) byte order, so reverse for comparison.
    const sighashDisplay = Buffer.from(sighash).reverse().toString("hex");

    if (sighashDisplay === expectedHashHex) {
      pass++;
    } else {
      fail++;
      console.log(
        `FAIL vector ${i}: input=${inputIndex} hashType=${hashType}\n` +
          `  expected: ${expectedHashHex}\n` +
          `  got:      ${sighashDisplay}`
      );
    }
  } catch (err: any) {
    fail++;
    console.log(`ERROR vector ${i}: ${err.message}`);
  }
}

console.log(`\nSighash test vectors: ${pass} passed, ${fail} failed, ${skip} skipped (header)`);
console.log(`Total vectors processed: ${pass + fail}`);

if (fail > 0) {
  process.exit(1);
}
