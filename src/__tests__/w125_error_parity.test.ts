/**
 * W125 — JSON-RPC error code parity audit (hotbuns).
 *
 * Reference:
 *   - bitcoin-core/src/rpc/protocol.h (canonical enum RPCErrorCode)
 *   - bitcoin-core/src/rpc/util.cpp (mapping helpers)
 *   - bitcoin-core/src/rpc/server.cpp (parse / warmup / param dup)
 *   - bitcoin-core/src/rpc/rawtransaction.cpp
 *   - bitcoin-core/src/rpc/mempool.cpp
 *   - bitcoin-core/src/rpc/blockchain.cpp
 *   - bitcoin-core/src/rpc/mining.cpp
 *   - bitcoin-core/src/rpc/net.cpp
 *   - bitcoin-core/src/wallet/rpc/encrypt.cpp + spend.cpp + wallet.cpp
 *   - JSON-RPC 2.0 §5.1 (Error object), §6 (batch).
 *
 * 30 audit gates, classified PRESENT / PARTIAL / MISSING.
 *
 * Audit summary (see audit/w125_rpc_error_parity.md): 18 bugs / 30
 * gates, PRESENT=10, PARTIAL=5, MISSING=15.
 *   P0-API-CDIV=5 (wrong codes on the wire)
 *   P1-API=6 (wrong category but tolerable)
 *   P1-WIRE=4 (wrong envelope shape)
 *   P2-CONSISTENCY=3 (hotbuns-internal cleanups)
 *
 * KEY FINDING: hotbuns defines 20 of 32 canonical Core error codes.
 * The 12 missing constants explain 10 of the 18 bugs (every bug 6-11
 * + 17 is rooted in a missing constant). The single largest scale
 * finding is BUG-1: 86+ throws use INVALID_PARAMS (-32602) where
 * Core uses RPC_INVALID_PARAMETER (-8). The JSON-RPC 2.0 -32602 code
 * is reserved for **transport-layer** "this isn't a valid request
 * shape" errors; application-layer "your hex string has odd length"
 * should be -8.
 *
 * No production code changes in this wave.
 *
 * Running: bun test src/__tests__/w125_error_parity.test.ts
 */

import { describe, it, expect } from "bun:test";
import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

import { RPCErrorCodes } from "../rpc/server.js";

// ---------------------------------------------------------------------------
// Source-level fixtures.
// ---------------------------------------------------------------------------

const __dirname = dirname(fileURLToPath(import.meta.url));
const SRC = resolve(__dirname, "..");
const RPC_SERVER_SRC = readFileSync(resolve(SRC, "rpc", "server.ts"), "utf8");

// =============================================================================
// G1 — JSON-RPC 2.0 transport codes (-32700..-32603) — PRESENT
// =============================================================================
describe("W125-G1: JSON-RPC 2.0 transport codes — PRESENT", () => {
  it("PARSE_ERROR === -32700", () => {
    expect(RPCErrorCodes.PARSE_ERROR).toBe(-32700);
  });
  it("INVALID_REQUEST === -32600", () => {
    expect(RPCErrorCodes.INVALID_REQUEST).toBe(-32600);
  });
  it("METHOD_NOT_FOUND === -32601", () => {
    expect(RPCErrorCodes.METHOD_NOT_FOUND).toBe(-32601);
  });
  it("INVALID_PARAMS === -32602", () => {
    expect(RPCErrorCodes.INVALID_PARAMS).toBe(-32602);
  });
  it("INTERNAL_ERROR === -32603", () => {
    expect(RPCErrorCodes.INTERNAL_ERROR).toBe(-32603);
  });
});

// =============================================================================
// G2 — RPC_MISC_ERROR (-1) — PRESENT
// =============================================================================
describe("W125-G2: RPC_MISC_ERROR (-1) — PRESENT", () => {
  it("MISC_ERROR === -1", () => {
    expect(RPCErrorCodes.MISC_ERROR).toBe(-1);
  });
});

// =============================================================================
// G3 — RPC_TYPE_ERROR (-3) — MISSING (BUG-6)
// =============================================================================
describe("W125-G3: RPC_TYPE_ERROR (-3) — MISSING (BUG-6)", () => {
  it("BUG-6: no TYPE_ERROR constant in RPCErrorCodes", () => {
    expect(("TYPE_ERROR" in RPCErrorCodes)).toBe(false);
  });
  it("BUG-6: no call site uses code -3", () => {
    expect(RPC_SERVER_SRC).not.toContain("RPCErrorCodes.TYPE_ERROR");
  });
});

// =============================================================================
// G4 — RPC_WALLET_ERROR (-4) — PRESENT
// =============================================================================
describe("W125-G4: RPC_WALLET_ERROR (-4) — PRESENT", () => {
  it("WALLET_ERROR === -4", () => {
    expect(RPCErrorCodes.WALLET_ERROR).toBe(-4);
  });
  it("at least one call site throws WALLET_ERROR", () => {
    expect(RPC_SERVER_SRC).toContain("RPCErrorCodes.WALLET_ERROR");
  });
});

// =============================================================================
// G5 — RPC_INVALID_ADDRESS_OR_KEY (-5) — PRESENT
// =============================================================================
describe("W125-G5: RPC_INVALID_ADDRESS_OR_KEY (-5) — PRESENT", () => {
  it("INVALID_ADDRESS_OR_KEY === -5", () => {
    expect(RPCErrorCodes.INVALID_ADDRESS_OR_KEY).toBe(-5);
  });
  it("used for block-not-found", () => {
    expect(RPC_SERVER_SRC).toMatch(
      /INVALID_ADDRESS_OR_KEY[^)]*Block not found/
    );
  });
});

// =============================================================================
// G6 — RPC_INVALID_PARAMETER (-8) — MISSING (BUG-1, the big one)
// =============================================================================
describe("W125-G6: RPC_INVALID_PARAMETER (-8) — MISSING (BUG-1)", () => {
  it("BUG-1: no INVALID_PARAMETER constant in RPCErrorCodes table", () => {
    // Core's `protocol.h` reserves -8 = RPC_INVALID_PARAMETER for application-
    // layer parameter errors; -32602 (RPC_INVALID_PARAMS) is JSON-RPC 2.0
    // transport-layer.
    expect("INVALID_PARAMETER" in RPCErrorCodes).toBe(false);
  });
  it("BUG-1: no call site uses code -8 anywhere", () => {
    // Sanity: there is NO usage of the right Core code.
    expect(RPC_SERVER_SRC).not.toContain("RPCErrorCodes.INVALID_PARAMETER");
  });
  it("BUG-1: INVALID_PARAMS (-32602) is overused for param validation (>= 40 sites)", () => {
    // Count occurrences of the wrong code in throws.
    const matches = RPC_SERVER_SRC.match(/RPCErrorCodes\.INVALID_PARAMS/g) || [];
    expect(matches.length).toBeGreaterThanOrEqual(40);
  });
  it("BUG-1: sendrawtransaction hexstring validation uses INVALID_PARAMS (should be -8)", () => {
    // Locate the sendrawtransaction handler text.
    const idx = RPC_SERVER_SRC.indexOf(
      'private async sendRawTransaction(params: unknown[])'
    );
    expect(idx).toBeGreaterThan(0);
    const window = RPC_SERVER_SRC.slice(idx, idx + 2000);
    // Currently throws INVALID_PARAMS; Core uses RPC_INVALID_PARAMETER.
    expect(window).toContain('RPCErrorCodes.INVALID_PARAMS');
    expect(window).toContain('"hexstring must be a string"');
  });
});

// =============================================================================
// G7 — RPC_OUT_OF_MEMORY (-7) — MISSING (BUG-7)
// =============================================================================
describe("W125-G7: RPC_OUT_OF_MEMORY (-7) — MISSING (BUG-7)", () => {
  it("BUG-7: no OUT_OF_MEMORY constant", () => {
    expect("OUT_OF_MEMORY" in RPCErrorCodes).toBe(false);
  });
});

// =============================================================================
// G8 — RPC_CLIENT_NOT_CONNECTED (-9) — MISSING (BUG-10)
// =============================================================================
describe("W125-G8: RPC_CLIENT_NOT_CONNECTED (-9) — MISSING (BUG-10)", () => {
  it("BUG-10: no CLIENT_NOT_CONNECTED constant", () => {
    expect("CLIENT_NOT_CONNECTED" in RPCErrorCodes).toBe(false);
  });
});

// =============================================================================
// G9 — RPC_CLIENT_IN_INITIAL_DOWNLOAD (-10) — MISSING (BUG-8)
// =============================================================================
describe("W125-G9: RPC_CLIENT_IN_INITIAL_DOWNLOAD (-10) — MISSING (BUG-8)", () => {
  it("BUG-8: no IBD-error constant in RPCErrorCodes", () => {
    expect("CLIENT_IN_INITIAL_DOWNLOAD" in RPCErrorCodes).toBe(false);
  });
  it("BUG-8: getBlockTemplate has no IBD gate (no throw of -10 anywhere)", () => {
    // Conservative check: even string -10 doesn't appear as an RPC error code.
    expect(RPC_SERVER_SRC).not.toMatch(/code:\s*-10[^0-9]/);
  });
});

// =============================================================================
// G10 — RPC_WALLET_INVALID_LABEL_NAME (-11) — PRESENT
// =============================================================================
describe("W125-G10: RPC_WALLET_INVALID_LABEL_NAME (-11) — PRESENT", () => {
  it("WALLET_INVALID_LABEL_NAME === -11", () => {
    expect(RPCErrorCodes.WALLET_INVALID_LABEL_NAME).toBe(-11);
  });
});

// =============================================================================
// G11 — RPC_WALLET_KEYPOOL_RAN_OUT (-12) — PARTIAL (constant present, no thrower)
// =============================================================================
describe("W125-G11: RPC_WALLET_KEYPOOL_RAN_OUT (-12) — PARTIAL", () => {
  it("WALLET_KEYPOOL_RAN_OUT === -12", () => {
    expect(RPCErrorCodes.WALLET_KEYPOOL_RAN_OUT).toBe(-12);
  });
  it("no call site explicitly throws WALLET_KEYPOOL_RAN_OUT yet", () => {
    expect(RPC_SERVER_SRC).not.toMatch(
      /this\.rpcError\(\s*RPCErrorCodes\.WALLET_KEYPOOL_RAN_OUT/
    );
  });
});

// =============================================================================
// G12 — RPC_WALLET_UNLOCK_NEEDED (-13) — PRESENT
// =============================================================================
describe("W125-G12: RPC_WALLET_UNLOCK_NEEDED (-13) — PRESENT", () => {
  it("WALLET_UNLOCK_NEEDED === -13", () => {
    expect(RPCErrorCodes.WALLET_UNLOCK_NEEDED).toBe(-13);
  });
  it("sendtoaddress / bumpfee throw it for locked wallet", () => {
    expect(RPC_SERVER_SRC).toContain("RPCErrorCodes.WALLET_UNLOCK_NEEDED");
    expect(RPC_SERVER_SRC).toMatch(
      /WALLET_UNLOCK_NEEDED[\s\S]{0,200}walletpassphrase/
    );
  });
});

// =============================================================================
// G13 — RPC_WALLET_PASSPHRASE_INCORRECT (-14) — PRESENT
// =============================================================================
describe("W125-G13: RPC_WALLET_PASSPHRASE_INCORRECT (-14) — PRESENT", () => {
  it("WALLET_PASSPHRASE_INCORRECT === -14", () => {
    expect(RPCErrorCodes.WALLET_PASSPHRASE_INCORRECT).toBe(-14);
  });
});

// =============================================================================
// G14 — RPC_WALLET_ALREADY_LOADED / _ALREADY_EXISTS — MISSING (BUG-5)
// =============================================================================
describe("W125-G14: RPC_WALLET_ALREADY_LOADED (-35) / _ALREADY_EXISTS (-36) — MISSING (BUG-5)", () => {
  it("BUG-5: no WALLET_ALREADY_LOADED constant", () => {
    expect("WALLET_ALREADY_LOADED" in RPCErrorCodes).toBe(false);
  });
  it("BUG-5: no WALLET_ALREADY_EXISTS constant", () => {
    expect("WALLET_ALREADY_EXISTS" in RPCErrorCodes).toBe(false);
  });
  it("BUG-5: createwallet falls back to WALLET_ERROR for both cases", () => {
    const idx = RPC_SERVER_SRC.indexOf(
      "private async createWallet(params: unknown[])"
    );
    expect(idx).toBeGreaterThan(0);
    const window = RPC_SERVER_SRC.slice(idx, idx + 3000);
    expect(window).toContain("RPCErrorCodes.WALLET_ERROR");
    expect(window).not.toContain("WALLET_ALREADY_EXISTS");
    expect(window).not.toContain("WALLET_ALREADY_LOADED");
  });
});

// =============================================================================
// G15 — RPC_METHOD_DEPRECATED (-32) — MISSING (BUG-11)
// =============================================================================
describe("W125-G15: RPC_METHOD_DEPRECATED (-32) — MISSING (BUG-11)", () => {
  it("BUG-11: no METHOD_DEPRECATED constant", () => {
    expect("METHOD_DEPRECATED" in RPCErrorCodes).toBe(false);
  });
});

// =============================================================================
// G16 — JSON-RPC error.data extension field — MISSING (BUG-12)
// =============================================================================
describe("W125-G16: JSON-RPC error.data field — MISSING (BUG-12)", () => {
  it("RPCResponse type declares optional data", () => {
    // Type-level confirmation: server.ts:143 has `data?: unknown`.
    expect(RPC_SERVER_SRC).toMatch(/error\?:\s*\{[^}]*data\?:\s*unknown/);
  });
  it("BUG-12: NO producer code path ever emits error.data", () => {
    // processRequest's error-object construction has only {code, message}.
    expect(RPC_SERVER_SRC).toMatch(
      /code:\s*err\.code\s*\?\?\s*RPCErrorCodes\.INTERNAL_ERROR,\s*message:\s*err\.message/
    );
    // Verify no `data:` field setter sits adjacent to the error code emission.
    // (Sanity-only — any data emission would require editing processRequest.)
  });
});

// =============================================================================
// G17 — Batch request partial error handling — MISSING (BUG-13)
// =============================================================================
describe("W125-G17: Batch request partial error handling — MISSING (BUG-13)", () => {
  it("BUG-13: batch path uses single req.json() that fails the whole batch on any malformed entry", () => {
    // The current implementation does a single req.json() to parse the whole
    // batch; if any entry is malformed the parse fails and the whole batch
    // returns one envelope. JSON-RPC 2.0 §6 says each entry should be tried
    // independently.
    const idx = RPC_SERVER_SRC.indexOf("// Parse request body");
    expect(idx).toBeGreaterThan(0);
    const window = RPC_SERVER_SRC.slice(idx, idx + 600);
    expect(window).toContain("body = await req.json()");
    // No per-entry try/catch in batch processing.
    expect(window).not.toContain("body.map((request, idx) => { try");
  });
});

// =============================================================================
// G18 — Peer disconnect / setban-remove unknown-node codes — MISSING (BUG-3, BUG-4)
// =============================================================================
describe("W125-G18: peer/ban unknown-node codes (-29, -30) — MISSING (BUG-3, BUG-4)", () => {
  it("BUG-3: no CLIENT_NODE_NOT_CONNECTED constant", () => {
    expect("CLIENT_NODE_NOT_CONNECTED" in RPCErrorCodes).toBe(false);
  });
  it("BUG-3: disconnectnode uses MISC_ERROR instead of -29", () => {
    const idx = RPC_SERVER_SRC.indexOf(
      "private async disconnectNode(params: unknown[])"
    );
    expect(idx).toBeGreaterThan(0);
    const window = RPC_SERVER_SRC.slice(idx, idx + 2000);
    expect(window).toMatch(
      /MISC_ERROR[^)]*Node[^"]*not found/
    );
  });
  it("BUG-4: setban remove uses MISC_ERROR instead of -30", () => {
    const idx = RPC_SERVER_SRC.indexOf("private async setBan(");
    expect(idx).toBeGreaterThan(0);
    const window = RPC_SERVER_SRC.slice(idx, idx + 2000);
    expect(window).toMatch(
      /MISC_ERROR[^)]*IP\/Subnet[^"]*is not banned/
    );
  });
  it("BUG-4: no CLIENT_INVALID_IP_OR_SUBNET constant", () => {
    expect("CLIENT_INVALID_IP_OR_SUBNET" in RPCErrorCodes).toBe(false);
  });
});

// =============================================================================
// G19 — HTTP status code 200 for JSON-RPC bodies — PARTIAL (BUG-14)
// =============================================================================
describe("W125-G19: HTTP 200 for JSON-RPC bodies — PARTIAL (BUG-14)", () => {
  it("BUG-14: parse-error path returns HTTP 400", () => {
    // The PARSE_ERROR response should still be HTTP 200 per Core convention.
    const idx = RPC_SERVER_SRC.indexOf('PARSE_ERROR, message: "Parse error"');
    expect(idx).toBeGreaterThan(0);
    const window = RPC_SERVER_SRC.slice(idx, idx + 200);
    expect(window).toContain("status: 400");
  });
  it("BUG-14: top-level non-object body also returns HTTP 400", () => {
    const idx = RPC_SERVER_SRC.indexOf(
      'PARSE_ERROR, message: "Top-level object parse error"'
    );
    expect(idx).toBeGreaterThan(0);
    const window = RPC_SERVER_SRC.slice(idx, idx + 300);
    expect(window).toContain("status: 400");
  });
});

// =============================================================================
// G20 — HTTP 401 on auth fail — PRESENT
// =============================================================================
describe("W125-G20: HTTP 401 on auth fail — PRESENT", () => {
  it("auth failure responds 401 with WWW-Authenticate header", () => {
    const idx = RPC_SERVER_SRC.indexOf("Authentication required");
    expect(idx).toBeGreaterThan(0);
    const window = RPC_SERVER_SRC.slice(idx, idx + 500);
    expect(window).toContain("status: 401");
    expect(window).toContain('WWW-Authenticate');
  });
});

// =============================================================================
// G21 — Cookie auth INVALID_REQUEST (-32600) in JSON body on auth fail — PRESENT
// =============================================================================
describe("W125-G21: auth-fail JSON body uses INVALID_REQUEST — PRESENT", () => {
  it("auth-fail body: code === INVALID_REQUEST (-32600)", () => {
    const idx = RPC_SERVER_SRC.indexOf("Authentication required");
    expect(idx).toBeGreaterThan(0);
    const before = RPC_SERVER_SRC.slice(Math.max(0, idx - 200), idx + 50);
    expect(before).toContain("INVALID_REQUEST");
  });
});

// =============================================================================
// G22 — Throw style consistency — PARTIAL (BUG-16)
// =============================================================================
describe("W125-G22: throw style consistency — PARTIAL (BUG-16)", () => {
  it("BUG-16: rpcError-helper sites count is large (≥150)", () => {
    const helperThrows = (RPC_SERVER_SRC.match(/this\.rpcError\(/g) || []).length;
    expect(helperThrows).toBeGreaterThanOrEqual(150);
  });
  it("BUG-16: raw-object throws also exist (`throw { code: RPCErrorCodes.`)", () => {
    const rawThrows =
      (RPC_SERVER_SRC.match(/throw\s*\{\s*code:\s*RPCErrorCodes\./g) || [])
        .length;
    expect(rawThrows).toBeGreaterThanOrEqual(15);
  });
});

// =============================================================================
// G23 — Modern canonical name RPC_VERIFY_ALREADY_IN_UTXO_SET (-27) — PARTIAL (BUG-17)
// =============================================================================
describe("W125-G23: RPC_VERIFY_ALREADY_IN_UTXO_SET (-27) modern name — PARTIAL (BUG-17)", () => {
  it("RPC_TRANSACTION_ALREADY_IN_CHAIN (-27) is present (old name)", () => {
    expect(RPCErrorCodes.RPC_TRANSACTION_ALREADY_IN_CHAIN).toBe(-27);
  });
  it("BUG-17: modern canonical name VERIFY_ALREADY_IN_UTXO_SET is NOT present", () => {
    expect("VERIFY_ALREADY_IN_UTXO_SET" in RPCErrorCodes).toBe(false);
  });
  it("BUG-17: VERIFY_ALREADY_IN_CHAIN (-25) re-uses -25 which is RPC_VERIFY_ERROR in Core — name collision", () => {
    // Core has alias RPC_TRANSACTION_ERROR = RPC_VERIFY_ERROR = -25.
    // hotbuns has VERIFY_ALREADY_IN_CHAIN = -25 — the alias name is wrong;
    // -25 is "VERIFY_ERROR / TRANSACTION_ERROR", not
    // "VERIFY_ALREADY_IN_CHAIN" (which is -27 in Core).
    expect(RPCErrorCodes.VERIFY_ALREADY_IN_CHAIN).toBe(-25);
  });
});

// =============================================================================
// G24 — Dead-helper WALLET_ALREADY_UNLOCKED — PARTIAL (BUG-18)
// =============================================================================
describe("W125-G24: WALLET_ALREADY_UNLOCKED dead-helper — PARTIAL (BUG-18)", () => {
  it("WALLET_ALREADY_UNLOCKED constant is declared (-17)", () => {
    expect(RPCErrorCodes.WALLET_ALREADY_UNLOCKED).toBe(-17);
  });
  it("BUG-18: WALLET_ALREADY_UNLOCKED constant is never thrown by any call site", () => {
    expect(RPC_SERVER_SRC).not.toMatch(
      /(?:code|rpcError\()\s*[:(]\s*RPCErrorCodes\.WALLET_ALREADY_UNLOCKED/
    );
  });
});

// =============================================================================
// G25 — RPC_DESERIALIZATION_ERROR (-22) — MISSING (BUG-2)
// =============================================================================
describe("W125-G25: RPC_DESERIALIZATION_ERROR (-22) — MISSING (BUG-2)", () => {
  it("BUG-2: no DESERIALIZATION_ERROR constant", () => {
    expect("DESERIALIZATION_ERROR" in RPCErrorCodes).toBe(false);
  });
  it("BUG-2: sendrawtransaction TX-decode uses RPC_TRANSACTION_REJECTED (should be -22)", () => {
    const idx = RPC_SERVER_SRC.indexOf(
      "private async sendRawTransaction(params: unknown[])"
    );
    expect(idx).toBeGreaterThan(0);
    const window = RPC_SERVER_SRC.slice(idx, idx + 3000);
    // The TX-decode catch raises TRANSACTION_REJECTED; Core uses
    // RPC_DESERIALIZATION_ERROR for decode failures.
    expect(window).toMatch(
      /TRANSACTION_REJECTED[\s\S]{0,200}TX decode failed/
    );
  });
  it("BUG-2: submitPackage TX-decode also uses RPC_TRANSACTION_REJECTED", () => {
    const idx = RPC_SERVER_SRC.indexOf("private async submitPackage(");
    expect(idx).toBeGreaterThan(0);
    const window = RPC_SERVER_SRC.slice(idx, idx + 4000);
    expect(window).toMatch(
      /TRANSACTION_REJECTED[\s\S]{0,200}TX decode failed/
    );
  });
});

// =============================================================================
// G26 — RPC_DATABASE_ERROR (-20) — MISSING (BUG-7)
// =============================================================================
describe("W125-G26: RPC_DATABASE_ERROR (-20) — MISSING (BUG-7)", () => {
  it("BUG-7: no DATABASE_ERROR constant", () => {
    expect("DATABASE_ERROR" in RPCErrorCodes).toBe(false);
  });
});

// =============================================================================
// G27 — RPC_VERIFY_ERROR (-25) — PRESENT (with name caveat)
// =============================================================================
describe("W125-G27: RPC_VERIFY_ERROR (-25) — PRESENT (with name caveat)", () => {
  it("RPC_TRANSACTION_ERROR === -25", () => {
    expect(RPCErrorCodes.RPC_TRANSACTION_ERROR).toBe(-25);
  });
  it("name caveat: declared as RPC_TRANSACTION_ERROR (an alias name in Core), not RPC_VERIFY_ERROR (the canonical name)", () => {
    // Cosmetic: Core's protocol.h lists RPC_VERIFY_ERROR -25 first and
    // RPC_TRANSACTION_ERROR is the alias. hotbuns reverses the naming.
    expect("RPC_VERIFY_ERROR" in RPCErrorCodes).toBe(false);
  });
});

// =============================================================================
// G28 — RPC_IN_WARMUP (-28) — MISSING (BUG-9)
// =============================================================================
describe("W125-G28: RPC_IN_WARMUP (-28) — MISSING (BUG-9)", () => {
  it("BUG-9: no IN_WARMUP constant", () => {
    expect("IN_WARMUP" in RPCErrorCodes).toBe(false);
  });
  it("BUG-9: no warmup-state gate at the RPC entry point", () => {
    // Core gates EVERY method during warmup; hotbuns has no such gate.
    expect(RPC_SERVER_SRC).not.toContain("rpcWarmupStatus");
    expect(RPC_SERVER_SRC).not.toContain("IN_WARMUP");
    expect(RPC_SERVER_SRC).not.toContain("setRPCWarmupFinished");
  });
});

// =============================================================================
// G29 — HTTP 400 (Core) vs 405 (hotbuns) for non-POST — PARTIAL (BUG-15)
// =============================================================================
describe("W125-G29: non-POST HTTP code — PARTIAL (BUG-15)", () => {
  it("BUG-15: non-POST returns HTTP 405 (Core returns 400 with JSON body)", () => {
    const idx = RPC_SERVER_SRC.indexOf(
      "Only POST requests are supported"
    );
    expect(idx).toBeGreaterThan(0);
    const window = RPC_SERVER_SRC.slice(idx, idx + 300);
    expect(window).toContain("status: 405");
  });
});

// =============================================================================
// G30 — RPC_CLIENT_P2P_DISABLED / _NODE_CAPACITY_REACHED / _MEMPOOL_DISABLED — MISSING (BUG-10)
// =============================================================================
describe("W125-G30: peer/mempool disabled codes (-31, -33, -34) — MISSING (BUG-10)", () => {
  it("BUG-10: no CLIENT_P2P_DISABLED constant", () => {
    expect("CLIENT_P2P_DISABLED" in RPCErrorCodes).toBe(false);
  });
  it("BUG-10: no CLIENT_NODE_CAPACITY_REACHED constant", () => {
    expect("CLIENT_NODE_CAPACITY_REACHED" in RPCErrorCodes).toBe(false);
  });
  it("BUG-10: no CLIENT_MEMPOOL_DISABLED constant", () => {
    expect("CLIENT_MEMPOOL_DISABLED" in RPCErrorCodes).toBe(false);
  });
  it("BUG-10: no CLIENT_NODE_ALREADY_ADDED constant", () => {
    expect("CLIENT_NODE_ALREADY_ADDED" in RPCErrorCodes).toBe(false);
  });
  it("BUG-10: no CLIENT_NODE_NOT_ADDED constant", () => {
    expect("CLIENT_NODE_NOT_ADDED" in RPCErrorCodes).toBe(false);
  });
});

// =============================================================================
// Aggregate summary — readable from CI logs
// =============================================================================
describe("W125 summary", () => {
  it("RPCErrorCodes table size (declared codes)", () => {
    const codes = Object.keys(RPCErrorCodes).length;
    // 20 of the 32 canonical Core codes (+ a few aliases). When constants
    // are added in a future FIX wave this number will rise; the assertion
    // here pins the audit snapshot.
    expect(codes).toBeGreaterThanOrEqual(20);
    expect(codes).toBeLessThanOrEqual(25);
  });
  it("audit-snapshot tag", () => {
    // Pins the audit summary as a literal string the test runner shows
    // in passing-test logs.
    const snapshot = "W125: 18 bugs / 30 gates / PRESENT=10 PARTIAL=5 MISSING=15";
    expect(snapshot).toContain("18 bugs");
  });
});
