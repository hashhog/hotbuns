/**
 * createrawtransaction — vout/sequence/locktime must be validated Core's way.
 *
 * THE DEFECT (regression pinned by this suite)
 * --------------------------------------------
 * The input parser only asked "is vout negative?". It never asked "is vout too
 * big?", and it never used Core's error CODES:
 *
 *   vout 2147483648 (2^31)  ->  ACCEPTED, written as outpoint index 0x80000000.
 *                               Bitcoin Core REJECTS this value outright.
 *   vout 4294967296 (2^32)  ->  code "ERR_OUT_OF_RANGE", message "The value of
 *                               \"value\" is out of range. It must be >= 0 and
 *                               <= 4294967295. Received 4294967296"
 *   vout -1 / missing vout / sequence out of range / locktime -1
 *                           ->  -32602, where Core says -8.
 *
 * The 2^32 case is a PROTOCOL violation on top of a parity one: that is Node's
 * own `ERR_OUT_OF_RANGE` from `Buffer.writeUInt32LE` escaping onto the wire,
 * and JSON-RPC requires `error.code` to be an INTEGER. A client that switches
 * on the numeric code gets a string. This suite therefore asserts
 * `typeof code === "number"` explicitly, not just the value.
 *
 * The 2^31 case is the quiet one and the worse one: a silent ACCEPT of an
 * input Core refuses, producing a transaction Core's own
 * createrawtransaction would never build.
 *
 * WHAT BITCOIN CORE DOES
 * ----------------------
 * `AddInputs` (bitcoin-core/src/rpc/rawtransaction_util.cpp:36-45) reads the
 * field with `find_value(o, "vout").getInt<int>()` — `int`, i.e. THIRTY-TWO
 * bits. `UniValue::getInt<Int>` (src/univalue/include/univalue.h:139-150)
 * converts with `std::from_chars` into the destination width and throws
 * `std::runtime_error("JSON integer out of range")` when the token does not
 * fit; rpc/server.cpp:514-515 turns that into RPC_MISC_ERROR (-1).
 *
 * THE ORDERING IS UNIVALUE'S, NOT THE HANDLER'S: the width check lives inside
 * the *conversion*, so it runs BEFORE `if (nOutput < 0) throw ... "vout cannot
 * be negative"`. That is why -1 gets the vout-specific -8 message while
 * 2147483648 — equally "not a valid vout" to a human — gets the generic -1
 * "JSON integer out of range". `vout -2147483649` is the case that pins the
 * order: negative AND out of int32 range, and Core answers -1, not -8.
 *
 * TEETH
 * -----
 * Every case above is a rejection, and a handler that rejected EVERY input
 * would satisfy all of them. The two CONTROL tests make that impossible: they
 * drive the real handler to success and then DECODE the returned hex with the
 * node's own `deserializeTx`, asserting the outpoint index that actually
 * reached the wire bytes. The int32-MAX control (2147483647) fails loudly if
 * the new bound is off by one in the tight direction. Both controls pass
 * BEFORE the fix as well as after — that is what makes them controls.
 *
 * The suite drives the REAL RPC server over a real HTTP socket (same rig as
 * fundrawtransaction_rpc.test.ts), so the assertions cover the on-the-wire
 * JSON-RPC envelope, not just an internal throw.
 *
 * References:
 *   bitcoin-core/src/rpc/rawtransaction_util.cpp:36-45   AddInputs
 *   bitcoin-core/src/rpc/rawtransaction_util.cpp:151-156 ConstructTransaction
 *   bitcoin-core/src/univalue/include/univalue.h:139-150 getInt<Int>
 *   bitcoin-core/src/rpc/util.cpp:117-125                ParseHashV
 *   bitcoin-core/src/rpc/protocol.h                      RPC_MISC_ERROR = -1
 *                                                        RPC_INVALID_PARAMETER = -8
 */

import { describe, it, expect, beforeEach, afterEach } from "bun:test";
import { RPCServer, RPCServerConfig, RPCServerDeps } from "../rpc/server.js";
import { REGTEST } from "../consensus/params.js";
import { deserializeTx } from "../validation/tx.js";
import { BufferReader } from "../wire/serialization.js";

// Well-formed 64-hex txid. Its content is irrelevant: createrawtransaction
// builds an UNSIGNED transaction from its arguments alone and never looks the
// outpoint up, so no chainstate is involved.
const TXID =
  "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b";

const INT32_MAX = 2147483647;
const INT32_MAX_PLUS_1 = 2147483648;
const INT32_MIN_MINUS_1 = -2147483649;
const TWO_POW_32 = 4294967296;
const TWO_POW_33 = 8589934592;

// A single OP_RETURN output. Deliberately data-only so the test never touches
// address encoding or the network params — a failure here can only mean the
// INPUT parser, never the output parser.
const OUTPUTS = { data: "deadbeef" };

let portCounter = 29661;

class MockChainStateManager {
  getBestBlock() {
    return { hash: Buffer.alloc(32, 0), height: 100, chainWork: 1000n };
  }
  getUTXOManager() {
    return { async getUTXOAsync() { return null; } };
  }
}
class MockMempool {
  getInfo() { return { size: 0, bytes: 0, minFeeRate: 1 }; }
  getAllTxids() { return []; }
  getTransaction() { return null; }
  hasTransaction() { return false; }
  getSize() { return 0; }
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
}

function makeServer(): { server: RPCServer; port: number } {
  const port = portCounter++;
  const config: RPCServerConfig = { port, host: "127.0.0.1", noAuth: true };
  const deps: RPCServerDeps = {
    chainState: new MockChainStateManager() as any,
    mempool: new MockMempool() as any,
    peerManager: new MockPeerManager() as any,
    feeEstimator: new MockFeeEstimator() as any,
    headerSync: new MockHeaderSync() as any,
    db: new MockChainDB() as any,
    params: REGTEST,
  };
  const server = new RPCServer(config, deps);
  server.start();
  return { server, port };
}

describe("createrawtransaction vout/sequence/locktime range — REGRESSION", () => {
  let server: RPCServer;
  let port: number;

  beforeEach(() => {
    const out = makeServer();
    server = out.server;
    port = out.port;
  });

  afterEach(() => {
    server.stop();
  });

  /** POST a real JSON-RPC request at the real server and return the envelope. */
  async function call(params: any[]): Promise<any> {
    const r = await fetch(`http://127.0.0.1:${port}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      // NOTE: hand-built JSON so the huge integers reach the server exactly as
      // written, without any client-side coercion.
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "createrawtransaction",
        params,
      }),
    });
    return r.json();
  }

  async function createRaw(inputs: any[], ...rest: any[]): Promise<any> {
    return call([inputs, OUTPUTS, ...rest]);
  }

  /**
   * Assert a Core-shaped JSON-RPC error. `code` is checked to be a NUMBER
   * first: the pre-fix 2^32 path returned the string "ERR_OUT_OF_RANGE", which
   * is not a legal JSON-RPC code at all.
   */
  function expectError(resp: any, code: number, message: string): void {
    expect(resp.result ?? null).toBeNull();
    expect(resp.error).toBeDefined();
    expect(typeof resp.error.code).toBe("number");
    expect(resp.error.code).toBe(code);
    expect(resp.error.message).toBe(message);
  }

  /**
   * Decode the returned hex with the node's own deserializer and report the
   * outpoint index that actually landed in the transaction bytes.
   */
  function firstInputVout(hex: string): number {
    const tx = deserializeTx(new BufferReader(Buffer.from(hex, "hex")));
    expect(tx.inputs.length).toBe(1);
    return tx.inputs[0].prevOut.vout;
  }

  // ---- THE REGRESSION: vout is an int32, and RANGE beats SIGN -------------

  const outOfInt32: Array<[string, number]> = [
    ["4294967296 (2^32)", TWO_POW_32],
    ["8589934592 (2^33)", TWO_POW_33],
    // The exact boundary: one past what Core's getInt<int> can hold. This
    // value was ACCEPTED before the fix and written as 0x80000000.
    ["2147483648 (int32 MAX + 1)", INT32_MAX_PLUS_1],
    // Negative AND out of int32 range. Core's range check lives inside the
    // conversion, so it wins over the "cannot be negative" message. This is
    // the ORDERING assertion.
    ["-2147483649 (int32 MIN - 1, range beats sign)", INT32_MIN_MINUS_1],
  ];

  for (const [label, vout] of outOfInt32) {
    it(`vout ${label} -> -1 JSON integer out of range`, async () => {
      const r = await createRaw([{ txid: TXID, vout }]);
      expectError(r, -1, "JSON integer out of range");
    });
  }

  // ---- Neighbouring guards must report Core's own codes and wording -------

  it("vout -1 -> -8 Invalid parameter, vout cannot be negative", async () => {
    // -1 fits in an int32, so the range check passes and the sign test speaks.
    const r = await createRaw([{ txid: TXID, vout: -1 }]);
    expectError(r, -8, "Invalid parameter, vout cannot be negative");
  });

  it("missing vout -> -8 Invalid parameter, missing vout key", async () => {
    const r = await createRaw([{ txid: TXID }]);
    expectError(r, -8, "Invalid parameter, missing vout key");
  });

  it("sequence 4294967296 -> -8 sequence number is out of range", async () => {
    const r = await createRaw([{ txid: TXID, vout: 0, sequence: TWO_POW_32 }]);
    expectError(r, -8, "Invalid parameter, sequence number is out of range");
  });

  it("sequence -1 -> -8 sequence number is out of range", async () => {
    const r = await createRaw([{ txid: TXID, vout: 0, sequence: -1 }]);
    expectError(r, -8, "Invalid parameter, sequence number is out of range");
  });

  it("locktime -1 -> -8 Invalid parameter, locktime out of range", async () => {
    const r = await createRaw([{ txid: TXID, vout: 0 }], -1);
    expectError(r, -8, "Invalid parameter, locktime out of range");
  });

  it("malformed txid 'abc' -> -8 with ParseHashV wording", async () => {
    // Core runs ParseHashO BEFORE it looks at vout, so a malformed txid is
    // reported as a txid problem with ParseHashV's exact message.
    const r = await createRaw([{ txid: "abc", vout: 0 }]);
    expectError(r, -8, "txid must be of length 64 (not 3, for 'abc')");
  });

  it("a present but NON-numeric sequence is ignored, not an error", async () => {
    // Core guards the read with `if (sequenceObj.isNum())`, so the default
    // applies (replaceable defaults true -> MAX_BIP125_RBF_SEQUENCE).
    const r = await createRaw([{ txid: TXID, vout: 0, sequence: "nope" }]);
    expect(r.error).toBeUndefined();
    const tx = deserializeTx(new BufferReader(Buffer.from(r.result, "hex")));
    expect(tx.inputs[0].sequence).toBe(0xfffffffd);
  });

  // ---- CONTROLS — must pass BOTH before and after the fix -----------------

  it("CONTROL: vout 2147483647 (int32 MAX) is ACCEPTED and lands in the bytes", async () => {
    // Proves the new upper bound is `> INT32_MAX`, not `>=` or some smaller
    // cap. Fails loudly if the guard is over-tight by even one.
    const r = await createRaw([{ txid: TXID, vout: INT32_MAX }]);
    expect(r.error).toBeUndefined();
    expect(typeof r.result).toBe("string");
    expect(firstInputVout(r.result)).toBe(INT32_MAX);
  });

  it("CONTROL: an ordinary vout 7 is ACCEPTED and lands in the bytes", async () => {
    // Proves the handler still does its normal job, so the rejection tests
    // above cannot be satisfied by a reject-everything stub.
    const r = await createRaw([{ txid: TXID, vout: 7 }]);
    expect(r.error).toBeUndefined();
    expect(typeof r.result).toBe("string");
    expect(firstInputVout(r.result)).toBe(7);
  });
  // ---- THE SECOND REGRESSION: `replaceable=true` vs. the sequences --------
  //
  // Core's ConstructTransaction ends with (rawtransaction_util.cpp:166-168):
  //
  //   if (rbf.has_value() && rbf.value() && rawTx.vin.size() > 0 &&
  //       !SignalsOptInRBF(CTransaction(rawTx)))
  //       throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter
  //           combination: Sequence number(s) contradict replaceable option");
  //
  // with SignalsOptInRBF (util/rbf.cpp) true as soon as ANY input carries
  // nSequence <= MAX_BIP125_RBF_SEQUENCE (0xfffffffd).
  //
  // hotbuns HAD this check but answered -32602 where Core answers -8. The code
  // is the whole point of the row: -32602 ("Invalid params") says the request
  // envelope was malformed, while -8 says two well-formed arguments disagree.
  // A client switching on the numeric code to decide whether to retry, or to
  // decide whether to surface the message to a human, gets the wrong answer.
  //
  // THE SUBTLE PART is that rbf keeps its OPTIONAL-NESS: `absent` and
  // `explicitly true` pick the SAME default sequence but behave DIFFERENTLY
  // here (has_value() vs. value_or(true)). The ABSENT and NULL controls below
  // are what stop the check from breaking ordinary calls.

  const MAX_BIP125_RBF_SEQUENCE = 0xfffffffd;
  const MAX_SEQUENCE_NONFINAL = 0xfffffffe;
  const SEQUENCE_FINAL = 0xffffffff;
  const CONTRADICTION_MSG =
    "Invalid parameter combination: Sequence number(s) contradict replaceable option";

  /** Decode the returned hex and report every input's nSequence, in order. */
  function sequencesOf(hex: string): number[] {
    const tx = deserializeTx(new BufferReader(Buffer.from(hex, "hex")));
    return tx.inputs.map((i) => i.sequence);
  }

  for (const [label, seq] of [
    ["0xffffffff (SEQUENCE_FINAL)", SEQUENCE_FINAL],
    ["0xfffffffe (MAX_SEQUENCE_NONFINAL)", MAX_SEQUENCE_NONFINAL],
  ] as Array<[string, number]>) {
    it(`replaceable=true + sequence ${label} -> -8 contradiction`, async () => {
      const r = await createRaw([{ txid: TXID, vout: 0, sequence: seq }], 0, true);
      expectError(r, -8, CONTRADICTION_MSG);
    });
  }

  it("CONTROL: replaceable ABSENT + SEQUENCE_FINAL is ACCEPTED", async () => {
    // rbf.has_value() is false when the argument is omitted, so the check
    // cannot fire — and the explicit sequence still reaches the bytes. This is
    // the row a plain-bool implementation gets wrong.
    const r = await createRaw([{ txid: TXID, vout: 0, sequence: SEQUENCE_FINAL }]);
    expect(r.error).toBeUndefined();
    expect(sequencesOf(r.result)).toEqual([SEQUENCE_FINAL]);
  });

  it("CONTROL: replaceable NULL + SEQUENCE_FINAL is ACCEPTED", async () => {
    // Core's isNull() is true for an explicit JSON null exactly as for an
    // omitted argument, so null must behave like ABSENT, not like `false`.
    const r = await createRaw([{ txid: TXID, vout: 0, sequence: SEQUENCE_FINAL }], 0, null);
    expect(r.error).toBeUndefined();
    expect(sequencesOf(r.result)).toEqual([SEQUENCE_FINAL]);
  });

  it("CONTROL: replaceable=true + sequence 0xfffffffd is ACCEPTED", async () => {
    // 0xfffffffd IS the BIP-125 signal, so there is no contradiction.
    const r = await createRaw(
      [{ txid: TXID, vout: 0, sequence: MAX_BIP125_RBF_SEQUENCE }], 0, true);
    expect(r.error).toBeUndefined();
    expect(sequencesOf(r.result)).toEqual([MAX_BIP125_RBF_SEQUENCE]);
  });

  it("CONTROL: replaceable=false + SEQUENCE_FINAL is ACCEPTED", async () => {
    // rbf.value() is false, so the check is inert however final the sequence.
    const r = await createRaw([{ txid: TXID, vout: 0, sequence: SEQUENCE_FINAL }], 0, false);
    expect(r.error).toBeUndefined();
    expect(sequencesOf(r.result)).toEqual([SEQUENCE_FINAL]);
  });

  it("CONTROL: replaceable=true + NO inputs is ACCEPTED", async () => {
    // Core guards on rawTx.vin.size() > 0: an input-less transaction cannot
    // contradict anything.
    //
    // Asserted on the RAW BYTES rather than through deserializeTx on purpose.
    // A zero-input transaction serializes as version || 0x00 || <vout count>,
    // and 0x00 is also the BIP-144 witness MARKER, so a witness-aware
    // deserializer re-reads the following output count as the witness FLAG and
    // walks off into nonsense. That ambiguity is inherent to the encoding (Core
    // resolves it in core_read.cpp by trying both and keeping the one that
    // round-trips), and it is NOT what this row is about — so read the input
    // count straight out of the hex: byte 4, immediately after the 4-byte
    // version, is the CompactSize input count and must be 0.
    const r = await createRaw([], 0, true);
    expect(r.error).toBeUndefined();
    expect(typeof r.result).toBe("string");
    expect(r.result.slice(8, 10)).toBe("00");
  });

  it("CONTROL: replaceable=true + one of TWO inputs signals is ACCEPTED", async () => {
    // SignalsOptInRBF is ANY, not ALL: one signalling input is enough, which
    // is BIP-125's multi-party rule — no single co-signer may opt the whole
    // transaction out of replacement. A check written with `every` rejects
    // this row.
    const r = await createRaw([
      { txid: TXID, vout: 0, sequence: SEQUENCE_FINAL },
      { txid: TXID, vout: 1, sequence: 0 },
    ], 0, true);
    expect(r.error).toBeUndefined();
    expect(sequencesOf(r.result)).toEqual([SEQUENCE_FINAL, 0]);
  });

  it("CONTROL: replaceable=true + no explicit sequence emits 0xfffffffd", async () => {
    // The default sequence under replaceable=true IS the RBF one, so the
    // ordinary RBF call must keep working — and must EMIT 0xfffffffd, not
    // merely succeed.
    const r = await createRaw([{ txid: TXID, vout: 0 }], 0, true);
    expect(r.error).toBeUndefined();
    expect(sequencesOf(r.result)).toEqual([MAX_BIP125_RBF_SEQUENCE]);
  });
});

/**
 * createrawtransaction must HONOUR the `version` argument, not ignore it.
 *
 * THE DEFECT.  Core's createrawtransaction takes a 5th argument, `version`
 * (bitcoin-core/src/rpc/rawtransaction.cpp:122).  It reads it as
 * `self.Arg<uint32_t>("version")`, bounds it to
 * [TX_MIN_STANDARD_VERSION, TX_MAX_STANDARD_VERSION] = [1, 3]
 * (src/policy/policy.h:152-153) and EMITS it
 * (src/rpc/rawtransaction_util.cpp:158-161).
 *
 * hotbuns hardcoded `version: 2` and ignored the argument.  Asked for version
 * 1, 2 or 3 it returned 02000000 every time, and version 4 — which Core
 * rejects — was accepted.  A success reply for a request that was not
 * honoured, and not cosmetic: version 3 is TRUC (BIP 431), so a caller who
 * asked for v3 and received v2 holds a transaction with different relay
 * behaviour from the one they requested, with nothing in the reply saying so.
 *
 * Measured 2026-08-29 by tools/rpc-arg-differential.py against a real regtest
 * Core: seven of the ten implementations behaved identically here.
 *
 * THE UNSIGNED WIDTH DECIDES WHICH ERROR YOU GET.  `version` is read as uint32,
 * unlike the int32 used for `vout`, so 2147483648 SURVIVES the conversion and
 * reaches the DOMAIN error (-8), while -1 and 4294967296 fail the CONVERSION
 * first (-1).  Those two are asserted separately; collapsing them would look
 * close enough and be wrong in both directions.
 *
 * THE ASSERTIONS DECODE THE VERSION BYTES off the returned transaction with the
 * node's own deserializer.  Checking only that the call was accepted is exactly
 * the pre-fix behaviour.
 */
describe("createrawtransaction version — REGRESSION (was hardcoded 2)", () => {
  let server: RPCServer;
  let port: number;

  beforeEach(() => {
    const out = makeServer();
    server = out.server;
    port = out.port;
  });

  afterEach(() => {
    server.stop();
  });

  async function callVersion(version?: unknown): Promise<any> {
    const params: any[] = [[{ txid: TXID, vout: 0 }], OUTPUTS, 0, false];
    if (version !== undefined) params.push(version);
    const r = await fetch(`http://127.0.0.1:${port}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "createrawtransaction", params }),
    });
    return r.json();
  }

  /** The transaction version, decoded with the node's own deserializer. */
  function versionOf(resp: any): number {
    expect(resp.error ?? null).toBeNull();
    expect(typeof resp.result).toBe("string");
    const tx = deserializeTx(new BufferReader(Buffer.from(resp.result, "hex")));
    return tx.version;
  }

  function expectVersionError(resp: any, code: number, message: string): void {
    expect(resp.result ?? null).toBeNull();
    expect(resp.error).toBeDefined();
    expect(typeof resp.error.code).toBe("number");
    expect(resp.error.code).toBe(code);
    expect(resp.error.message).toBe(message);
  }

  it("versions 1, 2 and 3 are emitted, not forced to 2", async () => {
    for (const want of [1, 2, 3]) {
      expect(versionOf(await callVersion(want))).toBe(want);
    }
  });

  it("version 0 and 4 are rejected with Core's domain error", async () => {
    for (const bad of [0, 4]) {
      expectVersionError(await callVersion(bad), -8,
        "Invalid parameter, version out of range(1~3)");
    }
  });

  it("2147483648 fits uint32 so it reaches the DOMAIN error (-8), not -1", async () => {
    expectVersionError(await callVersion(2147483648), -8,
      "Invalid parameter, version out of range(1~3)");
  });

  it("4294967296 and -1 are outside uint32 so CONVERSION fails first (-1)", async () => {
    for (const bad of [4294967296, -1, -2147483649]) {
      expectVersionError(await callVersion(bad), -1, "JSON integer out of range");
    }
  });

  // CONTROLS. Without these a handler that rejected every version would
  // satisfy every rejection assertion above.
  it("CONTROL absent version defaults to 2 (Core DEFAULT_RAWTX_VERSION)", async () => {
    expect(versionOf(await callVersion(undefined))).toBe(2);
  });

  it("CONTROL explicit null version defaults to 2", async () => {
    expect(versionOf(await callVersion(null))).toBe(2);
  });
});
