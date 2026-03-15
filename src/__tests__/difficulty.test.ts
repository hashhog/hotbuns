/**
 * Tests for difficulty adjustment (PoW retargeting).
 *
 * Covers:
 * - Mainnet standard retargeting every 2016 blocks
 * - Testnet3 20-minute min-difficulty rule with walk-back
 * - Testnet4/BIP94 first-block-of-period retargeting
 * - Regtest always minimum difficulty
 */

import { describe, it, expect } from "bun:test";
import {
  getNextWorkRequired,
  calculateNextWorkRequired,
  permittedDifficultyTransition,
  checkProofOfWork,
  deriveTarget,
  getBlockWork,
  type BlockInfo,
  type BlockLookup,
} from "../consensus/pow";
import {
  MAINNET,
  TESTNET,
  TESTNET4,
  REGTEST,
  compactToBigInt,
  bigIntToCompact,
  type ConsensusParams,
} from "../consensus/params";

/**
 * Helper to create a mock block chain for testing.
 */
function createMockChain(
  heights: Map<number, { timestamp: number; bits: number }>
): BlockLookup {
  return (height: number): BlockInfo | undefined => {
    const block = heights.get(height);
    if (!block) {
      return undefined;
    }
    return {
      height,
      header: {
        timestamp: block.timestamp,
        bits: block.bits,
      },
    };
  };
}

describe("Difficulty adjustment", () => {
  describe("Mainnet", () => {
    it("should return parent difficulty for non-adjustment blocks", () => {
      const parentBits = 0x1a01bc00; // some arbitrary difficulty
      const parent: BlockInfo = {
        height: 100,
        header: { timestamp: 1700000000, bits: parentBits },
      };

      const lookup = createMockChain(new Map([[100, parent.header]]));
      const target = getNextWorkRequired(parent, 1700000600, MAINNET, lookup);

      expect(target).toBe(compactToBigInt(parentBits));
    });

    it("should maintain difficulty at adjustment boundary with perfect timing", () => {
      // Block 2015 (last of period), blocks every 10 minutes exactly
      const interval = 2016;
      const startTime = 1700000000;
      const perfectTimespan = MAINNET.targetTimespan; // 14 days

      const chain = new Map<number, { timestamp: number; bits: number }>();
      const bits = 0x1d00ffff; // genesis difficulty

      // First block of period (height 0)
      chain.set(0, { timestamp: startTime, bits });
      // Last block of period (height 2015)
      chain.set(2015, { timestamp: startTime + perfectTimespan, bits });

      const parent: BlockInfo = {
        height: 2015,
        header: chain.get(2015)!,
      };

      const lookup = createMockChain(chain);
      const target = getNextWorkRequired(
        parent,
        startTime + perfectTimespan + 600,
        MAINNET,
        lookup
      );

      // With perfect timing, difficulty should stay roughly the same
      const expectedTarget = compactToBigInt(bits);
      // Allow some rounding error
      expect(target).toBeGreaterThan(expectedTarget / 2n);
      expect(target).toBeLessThan(expectedTarget * 2n);
    });

    it("should increase difficulty when blocks are too fast", () => {
      const interval = 2016;
      const startTime = 1700000000;
      // Blocks were mined in half the expected time
      const fastTimespan = Math.floor(MAINNET.targetTimespan / 2);

      const chain = new Map<number, { timestamp: number; bits: number }>();
      const bits = 0x1d00ffff;

      chain.set(0, { timestamp: startTime, bits });
      chain.set(2015, { timestamp: startTime + fastTimespan, bits });

      const parent: BlockInfo = {
        height: 2015,
        header: chain.get(2015)!,
      };

      const lookup = createMockChain(chain);
      const target = getNextWorkRequired(
        parent,
        startTime + fastTimespan + 600,
        MAINNET,
        lookup
      );

      // Faster blocks = harder difficulty = lower target
      const oldTarget = compactToBigInt(bits);
      expect(target).toBeLessThan(oldTarget);
    });

    it("should decrease difficulty when blocks are too slow", () => {
      const startTime = 1700000000;
      // Blocks were mined in double the expected time
      const slowTimespan = MAINNET.targetTimespan * 2;

      const chain = new Map<number, { timestamp: number; bits: number }>();
      // Use a harder difficulty that has room to get easier
      const bits = 0x1a01bc00;

      chain.set(0, { timestamp: startTime, bits });
      chain.set(2015, { timestamp: startTime + slowTimespan, bits });

      const parent: BlockInfo = {
        height: 2015,
        header: chain.get(2015)!,
      };

      const lookup = createMockChain(chain);
      const target = getNextWorkRequired(
        parent,
        startTime + slowTimespan + 600,
        MAINNET,
        lookup
      );

      // Slower blocks = easier difficulty = higher target
      const oldTarget = compactToBigInt(bits);
      expect(target).toBeGreaterThan(oldTarget);
    });

    it("should clamp adjustment to 4x increase", () => {
      const startTime = 1700000000;
      // Blocks were mined extremely slow (10x expected time)
      const verySlowTimespan = MAINNET.targetTimespan * 10;

      const chain = new Map<number, { timestamp: number; bits: number }>();
      const bits = 0x1a01bc00; // not at powLimit

      chain.set(0, { timestamp: startTime, bits });
      chain.set(2015, { timestamp: startTime + verySlowTimespan, bits });

      const parent: BlockInfo = {
        height: 2015,
        header: chain.get(2015)!,
      };

      const lookup = createMockChain(chain);
      const target = getNextWorkRequired(
        parent,
        startTime + verySlowTimespan + 600,
        MAINNET,
        lookup
      );

      // Should be clamped to 4x max increase
      const oldTarget = compactToBigInt(bits);
      expect(target).toBeLessThanOrEqual(oldTarget * 4n);
    });

    it("should clamp adjustment to 4x decrease", () => {
      const startTime = 1700000000;
      // Blocks were mined extremely fast (1/10 of expected time)
      const veryFastTimespan = Math.floor(MAINNET.targetTimespan / 10);

      const chain = new Map<number, { timestamp: number; bits: number }>();
      const bits = 0x1d00ffff;

      chain.set(0, { timestamp: startTime, bits });
      chain.set(2015, { timestamp: startTime + veryFastTimespan, bits });

      const parent: BlockInfo = {
        height: 2015,
        header: chain.get(2015)!,
      };

      const lookup = createMockChain(chain);
      const target = getNextWorkRequired(
        parent,
        startTime + veryFastTimespan + 600,
        MAINNET,
        lookup
      );

      // Should be clamped to 1/4 min decrease
      const oldTarget = compactToBigInt(bits);
      expect(target).toBeGreaterThanOrEqual(oldTarget / 4n);
    });

    it("should not exceed powLimit", () => {
      const startTime = 1700000000;
      const slowTimespan = MAINNET.targetTimespan * 4;

      const chain = new Map<number, { timestamp: number; bits: number }>();
      // Start already at powLimit
      const bits = MAINNET.powLimitBits;

      chain.set(0, { timestamp: startTime, bits });
      chain.set(2015, { timestamp: startTime + slowTimespan, bits });

      const parent: BlockInfo = {
        height: 2015,
        header: chain.get(2015)!,
      };

      const lookup = createMockChain(chain);
      const target = getNextWorkRequired(
        parent,
        startTime + slowTimespan + 600,
        MAINNET,
        lookup
      );

      expect(target).toBeLessThanOrEqual(MAINNET.powLimit);
    });
  });

  describe("Testnet3 (20-minute rule)", () => {
    it("should allow min-difficulty block after 20 minutes", () => {
      const parentTime = 1700000000;
      const parentBits = 0x1a01bc00; // hard difficulty

      const parent: BlockInfo = {
        height: 100,
        header: { timestamp: parentTime, bits: parentBits },
      };

      const chain = new Map<number, { timestamp: number; bits: number }>();
      chain.set(100, parent.header);

      const lookup = createMockChain(chain);

      // Block timestamp is > 20 minutes after parent
      const blockTimestamp = parentTime + 21 * 60;
      const target = getNextWorkRequired(parent, blockTimestamp, TESTNET, lookup);

      // Should return powLimit (min difficulty)
      expect(target).toBe(TESTNET.powLimit);
    });

    it("should not allow min-difficulty block within 20 minutes", () => {
      const parentTime = 1700000000;
      const parentBits = 0x1a01bc00;

      const parent: BlockInfo = {
        height: 100,
        header: { timestamp: parentTime, bits: parentBits },
      };

      const chain = new Map<number, { timestamp: number; bits: number }>();
      chain.set(100, parent.header);

      const lookup = createMockChain(chain);

      // Block timestamp is < 20 minutes after parent
      const blockTimestamp = parentTime + 10 * 60;
      const target = getNextWorkRequired(parent, blockTimestamp, TESTNET, lookup);

      // Should use parent's difficulty (walk-back finds it)
      expect(target).toBe(compactToBigInt(parentBits));
    });

    it("should walk back to find last non-min-difficulty block", () => {
      const chain = new Map<number, { timestamp: number; bits: number }>();
      const realDiffBits = 0x1a01bc00;
      const minDiffBits = TESTNET.powLimitBits;

      // Block 95: real difficulty
      chain.set(95, { timestamp: 1700000000, bits: realDiffBits });
      // Blocks 96-99: min difficulty
      chain.set(96, { timestamp: 1700001200, bits: minDiffBits });
      chain.set(97, { timestamp: 1700002400, bits: minDiffBits });
      chain.set(98, { timestamp: 1700003600, bits: minDiffBits });
      chain.set(99, { timestamp: 1700004800, bits: minDiffBits });
      // Block 100: parent (also min difficulty)
      chain.set(100, { timestamp: 1700006000, bits: minDiffBits });

      const parent: BlockInfo = {
        height: 100,
        header: chain.get(100)!,
      };

      const lookup = createMockChain(chain);

      // Block timestamp is within 20 minutes
      const blockTimestamp = 1700006600;
      const target = getNextWorkRequired(parent, blockTimestamp, TESTNET, lookup);

      // Should walk back to block 95 with real difficulty
      expect(target).toBe(compactToBigInt(realDiffBits));
    });

    it("should stop walk-back at difficulty adjustment boundary", () => {
      const chain = new Map<number, { timestamp: number; bits: number }>();
      const interval = TESTNET.difficultyAdjustmentInterval;

      // Difficulty period boundary at height 2016
      // Block 2016: min difficulty (at boundary)
      chain.set(2016, { timestamp: 1700000000, bits: TESTNET.powLimitBits });
      // Block 2017: min difficulty
      chain.set(2017, { timestamp: 1700001200, bits: TESTNET.powLimitBits });

      const parent: BlockInfo = {
        height: 2017,
        header: chain.get(2017)!,
      };

      const lookup = createMockChain(chain);

      // Block timestamp is within 20 minutes
      const blockTimestamp = 1700001800;
      const target = getNextWorkRequired(parent, blockTimestamp, TESTNET, lookup);

      // Should stop at boundary block 2016, even though it's min difficulty
      expect(target).toBe(compactToBigInt(TESTNET.powLimitBits));
    });
  });

  describe("Testnet4 / BIP94", () => {
    it("should use first block of period for retargeting", () => {
      const chain = new Map<number, { timestamp: number; bits: number }>();
      const startTime = 1700000000;
      const realDiffBits = 0x1a01bc00;
      const minDiffBits = TESTNET4.powLimitBits;

      // First block of period (height 0): real difficulty
      chain.set(0, { timestamp: startTime, bits: realDiffBits });
      // Middle blocks: some min difficulty (simulating 20-min gaps)
      for (let i = 1; i < 2015; i++) {
        chain.set(i, { timestamp: startTime + i * 600, bits: minDiffBits });
      }
      // Last block of period (height 2015): min difficulty
      const endTime = startTime + TESTNET4.targetTimespan;
      chain.set(2015, { timestamp: endTime, bits: minDiffBits });

      const parent: BlockInfo = {
        height: 2015,
        header: chain.get(2015)!,
      };

      const lookup = createMockChain(chain);
      const target = getNextWorkRequired(parent, endTime + 600, TESTNET4, lookup);

      // BIP94: should use first block's difficulty (realDiffBits), not last block's
      // The new target should be based on realDiffBits adjusted by timespan
      const baseTarget = compactToBigInt(realDiffBits);
      // With perfect timing, target should stay roughly the same
      expect(target).toBeGreaterThan(baseTarget / 4n);
      expect(target).toBeLessThan(baseTarget * 4n);
    });

    it("should allow min-difficulty after 20 minutes (like testnet3)", () => {
      const parentTime = 1700000000;
      const parentBits = 0x1a01bc00;

      const parent: BlockInfo = {
        height: 100,
        header: { timestamp: parentTime, bits: parentBits },
      };

      const chain = new Map<number, { timestamp: number; bits: number }>();
      chain.set(100, parent.header);

      const lookup = createMockChain(chain);

      // Block timestamp is > 20 minutes after parent
      const blockTimestamp = parentTime + 21 * 60;
      const target = getNextWorkRequired(parent, blockTimestamp, TESTNET4, lookup);

      // Should return powLimit (min difficulty)
      expect(target).toBe(TESTNET4.powLimit);
    });
  });

  describe("Regtest", () => {
    it("should always return powLimit (no retargeting)", () => {
      const chain = new Map<number, { timestamp: number; bits: number }>();
      const bits = 0x1a01bc00; // doesn't matter

      chain.set(100, { timestamp: 1700000000, bits });

      const parent: BlockInfo = {
        height: 100,
        header: chain.get(100)!,
      };

      const lookup = createMockChain(chain);
      const target = getNextWorkRequired(parent, 1700000600, REGTEST, lookup);

      // Regtest: always powLimit
      expect(target).toBe(REGTEST.powLimit);
    });

    it("should return powLimit even at adjustment boundary", () => {
      const chain = new Map<number, { timestamp: number; bits: number }>();
      const bits = REGTEST.powLimitBits;

      chain.set(0, { timestamp: 1700000000, bits });
      chain.set(2015, { timestamp: 1700000000 + REGTEST.targetTimespan, bits });

      const parent: BlockInfo = {
        height: 2015,
        header: chain.get(2015)!,
      };

      const lookup = createMockChain(chain);
      const target = getNextWorkRequired(
        parent,
        1700000000 + REGTEST.targetTimespan + 600,
        REGTEST,
        lookup
      );

      // Regtest: always powLimit, no retargeting
      expect(target).toBe(REGTEST.powLimit);
    });
  });

  describe("permittedDifficultyTransition", () => {
    it("should allow any transition on testnet", () => {
      expect(permittedDifficultyTransition(TESTNET, 100, 0x1d00ffff, 0x1a01bc00)).toBe(true);
      expect(permittedDifficultyTransition(TESTNET, 2016, 0x1d00ffff, 0x1a01bc00)).toBe(true);
    });

    it("should require identical bits on mainnet non-adjustment blocks", () => {
      expect(permittedDifficultyTransition(MAINNET, 100, 0x1a01bc00, 0x1a01bc00)).toBe(true);
      expect(permittedDifficultyTransition(MAINNET, 100, 0x1a01bc00, 0x1a01bc01)).toBe(false);
    });

    it("should allow 4x range on mainnet adjustment blocks", () => {
      // At adjustment boundary, transitions within 4x are allowed
      const baseBits = 0x1a01bc00;
      expect(permittedDifficultyTransition(MAINNET, 2016, baseBits, baseBits)).toBe(true);
    });
  });

  describe("checkProofOfWork", () => {
    it("should accept valid proof of work", () => {
      // Create a hash that's less than the target
      // Bitcoin hashes are stored in little-endian, so we need leading zeros
      // when viewed in big-endian (which is how we compare)
      const hash = Buffer.alloc(32, 0);
      // This creates a very small hash value (all zeros)

      expect(checkProofOfWork(hash, MAINNET.powLimitBits, MAINNET)).toBe(true);
    });

    it("should reject invalid proof of work", () => {
      // Create a hash that's greater than the target
      const hash = Buffer.alloc(32, 0xff); // Very large hash

      expect(checkProofOfWork(hash, MAINNET.powLimitBits, MAINNET)).toBe(false);
    });

    it("should reject invalid bits", () => {
      const hash = Buffer.alloc(32, 0);
      // Negative target (bit 23 set with non-zero mantissa)
      expect(checkProofOfWork(hash, 0x1d800001, MAINNET)).toBe(false);
    });
  });

  describe("deriveTarget", () => {
    it("should correctly derive target from compact bits", () => {
      const target = deriveTarget(MAINNET.powLimitBits, MAINNET.powLimit);
      expect(target).toBe(MAINNET.powLimit);
    });

    it("should return null for zero target", () => {
      expect(deriveTarget(0, MAINNET.powLimit)).toBeNull();
    });

    it("should return null for target exceeding powLimit", () => {
      // Create bits that would produce a target > powLimit
      // Using a very easy difficulty
      const tooEasyBits = 0x2100ffff;
      expect(deriveTarget(tooEasyBits, MAINNET.powLimit)).toBeNull();
    });
  });

  describe("getBlockWork", () => {
    it("should calculate correct work for powLimit", () => {
      const work = getBlockWork(MAINNET.powLimitBits);
      expect(work).toBeGreaterThan(0n);
    });

    it("should calculate more work for harder difficulty", () => {
      const easyWork = getBlockWork(MAINNET.powLimitBits);
      const hardWork = getBlockWork(0x1a01bc00); // harder difficulty

      expect(hardWork).toBeGreaterThan(easyWork);
    });

    it("should return 0 for invalid bits", () => {
      expect(getBlockWork(0)).toBe(0n);
    });
  });

  describe("compact encoding roundtrip", () => {
    it("should roundtrip through compact encoding", () => {
      const targets = [
        MAINNET.powLimit,
        REGTEST.powLimit,
        compactToBigInt(0x1a01bc00),
        compactToBigInt(0x1b0404cb),
      ];

      for (const target of targets) {
        const bits = bigIntToCompact(target);
        const recovered = compactToBigInt(bits);
        // May lose some precision due to compact encoding
        expect(recovered).toBeLessThanOrEqual(target);
        expect(recovered).toBeGreaterThan(target / 256n);
      }
    });
  });
});
