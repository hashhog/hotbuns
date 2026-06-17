/**
 * Tests for the Core-faithful dust threshold (getDustThreshold / isDust).
 *
 * Mirrors bitcoin-core/src/policy/policy.cpp GetDustThreshold + IsDust.
 * NON-consensus: mempool RELAY policy (IsStandardTx / ephemeral-anchor),
 * never block/tx validation.
 *
 * These tests fail against the pre-fix implementation, which dropped the
 * CompactSize prefix term (hardcoded +1) and used truncating division
 * instead of Core's CeilDiv.
 */

import { describe, test, expect } from "bun:test";
import { getDustThreshold, isDust } from "./mempool.js";

const WITNESS_SCALE_FACTOR = 4n;
const DUST_RELAY_FEE = 3000;

/**
 * Independent Core reference for GetDustThreshold, used to cross-check the
 * implementation rather than asserting it against itself.
 *
 *   nSize = GetSerializeSize(txout) + spending_cost
 *         = (8 + CompactSize(len) + len) + (witness ? 67 : 148)
 *   threshold = CeilDiv(nSize * dustRelayFee, 1000)
 */
function coreDustThreshold(
  scriptPubKey: Buffer,
  dustRelayFee = DUST_RELAY_FEE,
): bigint {
  // IsUnspendable() ⇒ 0
  if (
    (scriptPubKey.length > 0 && scriptPubKey[0] === 0x6a) ||
    scriptPubKey.length > 10000
  ) {
    return 0n;
  }
  const len = scriptPubKey.length;
  let prefix: bigint;
  if (len < 0xfd) prefix = 1n;
  else if (len <= 0xffff) prefix = 3n;
  else prefix = 5n;
  let nSize = 8n + prefix + BigInt(len);
  const isWitness =
    len >= 4 &&
    len <= 42 &&
    (scriptPubKey[0] === 0x00 ||
      (scriptPubKey[0] >= 0x51 && scriptPubKey[0] <= 0x60)) &&
    scriptPubKey[1] + 2 === len;
  if (isWitness) {
    nSize += 32n + 4n + 1n + 107n / WITNESS_SCALE_FACTOR + 4n;
  } else {
    nSize += 32n + 4n + 1n + 107n + 4n;
  }
  return (nSize * BigInt(dustRelayFee) + 999n) / 1000n;
}

// Canonical scriptPubKey shapes for the five standard output types.
const P2PKH = Buffer.concat([
  Buffer.from([0x76, 0xa9, 0x14]),
  Buffer.alloc(20),
  Buffer.from([0x88, 0xac]),
]); // 25 bytes
const P2SH = Buffer.concat([
  Buffer.from([0xa9, 0x14]),
  Buffer.alloc(20),
  Buffer.from([0x87]),
]); // 23 bytes
const P2WPKH = Buffer.concat([Buffer.from([0x00, 0x14]), Buffer.alloc(20)]); // 22 bytes
const P2WSH = Buffer.concat([Buffer.from([0x00, 0x20]), Buffer.alloc(32)]); // 34 bytes
const P2TR = Buffer.concat([Buffer.from([0x51, 0x20]), Buffer.alloc(32)]); // 34 bytes

describe("getDustThreshold — Core parity", () => {
  test("canonical Core thresholds at default 3000 sat/kvB dust relay fee", () => {
    // bitcoin-core/src/policy/policy.cpp comments: 546 / 540 / 294 / 330 / 330.
    expect(getDustThreshold(P2PKH)).toBe(546n);
    expect(getDustThreshold(P2SH)).toBe(540n);
    expect(getDustThreshold(P2WPKH)).toBe(294n);
    expect(getDustThreshold(P2WSH)).toBe(330n);
    expect(getDustThreshold(P2TR)).toBe(330n);
  });

  test("matches independent Core reference across shapes", () => {
    for (const spk of [P2PKH, P2SH, P2WPKH, P2WSH, P2TR]) {
      expect(getDustThreshold(spk)).toBe(coreDustThreshold(spk));
    }
  });

  test("OP_RETURN and oversize scripts are never dust (threshold 0)", () => {
    const opReturn = Buffer.from([0x6a, 0x04, 0xde, 0xad, 0xbe, 0xef]);
    expect(getDustThreshold(opReturn)).toBe(0n);
    const oversize = Buffer.alloc(10001, 0xab);
    expect(getDustThreshold(oversize)).toBe(0n);
  });

  test("CeilDiv: non-default fee rate rounds up like Core (not truncate)", () => {
    // At 3001 sat/kvB a P2WPKH output: nSize=98, 98*3001=294098,
    // CeilDiv(294098,1000) = 295 (Core), truncating div would give 294.
    expect(getDustThreshold(P2WPKH, 3001)).toBe(295n);
    expect(getDustThreshold(P2WPKH, 3001)).toBe(coreDustThreshold(P2WPKH, 3001));
  });

  test("CompactSize prefix: large (>=253-byte) script uses 3-byte prefix", () => {
    // A 300-byte bare (non-witness) script: GetSerializeSize prefix is 3, not 1.
    // nSize = 8 + 3 + 300 + 148 = 459; 459*3000/1000 = 1377 (Core).
    // Pre-fix hardcoded +1 prefix gives 1371.
    const big = Buffer.alloc(300, 0xab);
    expect(getDustThreshold(big)).toBe(1377n);
    expect(getDustThreshold(big)).toBe(coreDustThreshold(big));
  });

  test("isDust uses the 546/294 boundaries for P2PKH/P2WPKH", () => {
    expect(isDust(545n, P2PKH)).toBe(true);
    expect(isDust(546n, P2PKH)).toBe(false);
    expect(isDust(293n, P2WPKH)).toBe(true);
    expect(isDust(294n, P2WPKH)).toBe(false);
  });
});
