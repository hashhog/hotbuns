/**
 * Tests for checkpoint verification.
 *
 * Covers:
 * - Checkpoint hash verification at known heights
 * - Fork rejection below the last checkpoint
 * - Network-specific checkpoint validation
 * - IBD checkpoint requirements
 */

import { describe, it, expect } from "bun:test";
import {
  MAINNET,
  TESTNET,
  TESTNET4,
  SIGNET,
  REGTEST,
  type ConsensusParams,
} from "../consensus/params";
import {
  verifyCheckpoint,
  checkForkBelowCheckpoint,
  getLastCheckpointHeight,
  type CheckpointResult,
} from "../chain/state";

describe("Checkpoint verification", () => {
  describe("getLastCheckpointHeight", () => {
    it("should return highest checkpoint height for mainnet", () => {
      const lastCp = getLastCheckpointHeight(MAINNET);
      // Should be 530000 based on our checkpoints
      expect(lastCp).toBe(530000);
    });

    it("should return genesis height for testnet3", () => {
      const lastCp = getLastCheckpointHeight(TESTNET);
      // Has genesis and one more checkpoint
      expect(lastCp).toBeGreaterThanOrEqual(0);
    });

    it("should return -1 for regtest (no checkpoints)", () => {
      const lastCp = getLastCheckpointHeight(REGTEST);
      expect(lastCp).toBe(-1);
    });

    it("should return correct height for signet", () => {
      const lastCp = getLastCheckpointHeight(SIGNET);
      expect(lastCp).toBeGreaterThanOrEqual(0);
    });
  });

  describe("verifyCheckpoint", () => {
    it("should pass for non-checkpoint heights", () => {
      // Height 12345 is not a checkpoint
      const fakeHash = Buffer.alloc(32, 0x42);
      const result = verifyCheckpoint(fakeHash, 12345, MAINNET);
      expect(result.valid).toBe(true);
    });

    it("should pass for correct checkpoint hash", () => {
      // Height 0 is the genesis checkpoint
      const genesisHash = MAINNET.checkpoints.get(0)!;
      const result = verifyCheckpoint(genesisHash, 0, MAINNET);
      expect(result.valid).toBe(true);
    });

    it("should fail for incorrect checkpoint hash", () => {
      // Height 0 with wrong hash
      const wrongHash = Buffer.alloc(32, 0x00);
      const result = verifyCheckpoint(wrongHash, 0, MAINNET);
      expect(result.valid).toBe(false);
      expect(result.error).toContain("Checkpoint mismatch");
      expect(result.error).toContain("height 0");
    });

    it("should verify mainnet checkpoint at height 11111", () => {
      const checkpointHash = MAINNET.checkpoints.get(11111)!;
      expect(checkpointHash).toBeDefined();

      const result = verifyCheckpoint(checkpointHash, 11111, MAINNET);
      expect(result.valid).toBe(true);
    });

    it("should verify mainnet checkpoint at height 210000", () => {
      const checkpointHash = MAINNET.checkpoints.get(210000)!;
      expect(checkpointHash).toBeDefined();

      const result = verifyCheckpoint(checkpointHash, 210000, MAINNET);
      expect(result.valid).toBe(true);
    });

    it("should pass any hash on regtest (no checkpoints)", () => {
      const anyHash = Buffer.alloc(32, 0xff);
      const result = verifyCheckpoint(anyHash, 0, REGTEST);
      expect(result.valid).toBe(true);
    });

    it("should verify testnet genesis checkpoint", () => {
      const genesisHash = TESTNET.checkpoints.get(0)!;
      expect(genesisHash).toBeDefined();

      const result = verifyCheckpoint(genesisHash, 0, TESTNET);
      expect(result.valid).toBe(true);
    });

    it("should verify testnet4 genesis checkpoint", () => {
      const genesisHash = TESTNET4.checkpoints.get(0)!;
      expect(genesisHash).toBeDefined();

      const result = verifyCheckpoint(genesisHash, 0, TESTNET4);
      expect(result.valid).toBe(true);
    });
  });

  describe("checkForkBelowCheckpoint", () => {
    // Helper to create a mock ancestor lookup
    function createMockAncestorLookup(
      ancestors: Map<number, Buffer>
    ): (height: number) => Buffer | undefined {
      return (height: number) => ancestors.get(height);
    }

    it("should pass when no checkpoints exist", () => {
      const hash = Buffer.alloc(32, 0x42);
      const parentHash = Buffer.alloc(32, 0x41);
      const ancestors = new Map<number, Buffer>();

      const result = checkForkBelowCheckpoint(
        100,
        hash,
        parentHash,
        REGTEST,
        createMockAncestorLookup(ancestors)
      );

      expect(result.valid).toBe(true);
    });

    it("should pass when header matches checkpoint exactly", () => {
      const checkpointHash = MAINNET.checkpoints.get(11111)!;
      const parentHash = Buffer.alloc(32, 0x00);
      const ancestors = new Map<number, Buffer>();

      const result = checkForkBelowCheckpoint(
        11111,
        checkpointHash,
        parentHash,
        MAINNET,
        createMockAncestorLookup(ancestors)
      );

      expect(result.valid).toBe(true);
    });

    it("should reject header at checkpoint height with wrong hash", () => {
      const wrongHash = Buffer.alloc(32, 0xff);
      const parentHash = Buffer.alloc(32, 0x00);
      const ancestors = new Map<number, Buffer>();

      const result = checkForkBelowCheckpoint(
        11111,
        wrongHash,
        parentHash,
        MAINNET,
        createMockAncestorLookup(ancestors)
      );

      expect(result.valid).toBe(false);
      expect(result.error).toContain("does not match");
      expect(result.error).toContain("11111");
    });

    it("should pass when ancestry matches all checkpoints", () => {
      const hash = Buffer.alloc(32, 0x99);
      const parentHash = Buffer.alloc(32, 0x98);

      // Build ancestors that match all checkpoints
      const ancestors = new Map<number, Buffer>();
      for (const [height, cpHash] of MAINNET.checkpoints) {
        ancestors.set(height, cpHash);
      }

      const result = checkForkBelowCheckpoint(
        600000, // Above all checkpoints
        hash,
        parentHash,
        MAINNET,
        createMockAncestorLookup(ancestors)
      );

      expect(result.valid).toBe(true);
    });

    it("should reject fork below checkpoint with wrong ancestor", () => {
      const hash = Buffer.alloc(32, 0x99);
      const parentHash = Buffer.alloc(32, 0x98);

      // Build ancestors with one wrong checkpoint
      const ancestors = new Map<number, Buffer>();
      for (const [height, cpHash] of MAINNET.checkpoints) {
        if (height === 11111) {
          // Wrong hash at checkpoint
          ancestors.set(height, Buffer.alloc(32, 0xaa));
        } else {
          ancestors.set(height, cpHash);
        }
      }

      const result = checkForkBelowCheckpoint(
        600000, // Above all checkpoints
        hash,
        parentHash,
        MAINNET,
        createMockAncestorLookup(ancestors)
      );

      expect(result.valid).toBe(false);
      expect(result.error).toContain("Fork detected");
      expect(result.error).toContain("11111");
    });

    it("should pass when header is below last checkpoint but matches", () => {
      // Header at height 100, which is below the last checkpoint
      const hash = Buffer.alloc(32, 0x42);
      const parentHash = Buffer.alloc(32, 0x41);
      const ancestors = new Map<number, Buffer>();
      // Genesis matches
      ancestors.set(0, MAINNET.checkpoints.get(0)!);

      const result = checkForkBelowCheckpoint(
        100,
        hash,
        parentHash,
        MAINNET,
        createMockAncestorLookup(ancestors)
      );

      expect(result.valid).toBe(true);
    });
  });

  describe("Checkpoint data integrity", () => {
    it("mainnet genesis checkpoint matches genesis hash", () => {
      const checkpoint = MAINNET.checkpoints.get(0);
      expect(checkpoint).toBeDefined();
      expect(checkpoint!.equals(MAINNET.genesisBlockHash)).toBe(true);
    });

    it("testnet3 genesis checkpoint matches genesis hash", () => {
      const checkpoint = TESTNET.checkpoints.get(0);
      expect(checkpoint).toBeDefined();
      expect(checkpoint!.equals(TESTNET.genesisBlockHash)).toBe(true);
    });

    it("testnet4 genesis checkpoint matches genesis hash", () => {
      const checkpoint = TESTNET4.checkpoints.get(0);
      expect(checkpoint).toBeDefined();
      expect(checkpoint!.equals(TESTNET4.genesisBlockHash)).toBe(true);
    });

    it("signet genesis checkpoint matches genesis hash", () => {
      const checkpoint = SIGNET.checkpoints.get(0);
      expect(checkpoint).toBeDefined();
      expect(checkpoint!.equals(SIGNET.genesisBlockHash)).toBe(true);
    });

    it("regtest has no checkpoints", () => {
      expect(REGTEST.checkpoints.size).toBe(0);
    });

    it("mainnet has at least 10 checkpoints", () => {
      expect(MAINNET.checkpoints.size).toBeGreaterThanOrEqual(10);
    });

    it("checkpoint heights are in ascending order", () => {
      const heights = Array.from(MAINNET.checkpoints.keys()).sort(
        (a, b) => a - b
      );
      for (let i = 1; i < heights.length; i++) {
        expect(heights[i]).toBeGreaterThan(heights[i - 1]);
      }
    });

    it("checkpoint hashes are 32 bytes", () => {
      for (const [height, hash] of MAINNET.checkpoints) {
        expect(hash.length).toBe(32);
      }
    });

    it("checkpoint hashes are valid little-endian (internal format)", () => {
      // All mainnet checkpoint hashes should start with zeros when
      // displayed in big-endian (standard Bitcoin format)
      for (const [height, hash] of MAINNET.checkpoints) {
        // In little-endian internal format, the last bytes should be zeros
        // for valid Bitcoin block hashes
        const lastBytes = hash.subarray(28, 32);
        const hasLeadingZeros = lastBytes[3] === 0;
        expect(hasLeadingZeros).toBe(true);
      }
    });
  });

  describe("nMinimumChainWork", () => {
    it("mainnet has non-zero minimum chain work", () => {
      expect(MAINNET.nMinimumChainWork).toBeGreaterThan(0n);
    });

    it("testnet3 has non-zero minimum chain work", () => {
      expect(TESTNET.nMinimumChainWork).toBeGreaterThan(0n);
    });

    it("testnet4 has non-zero minimum chain work", () => {
      expect(TESTNET4.nMinimumChainWork).toBeGreaterThan(0n);
    });

    it("signet has non-zero minimum chain work", () => {
      expect(SIGNET.nMinimumChainWork).toBeGreaterThan(0n);
    });

    it("regtest has zero minimum chain work", () => {
      expect(REGTEST.nMinimumChainWork).toBe(0n);
    });

    it("mainnet minimum chain work is greater than testnet", () => {
      expect(MAINNET.nMinimumChainWork).toBeGreaterThan(
        TESTNET.nMinimumChainWork
      );
    });
  });

  describe("Fork rejection scenarios", () => {
    it("should reject attempt to fork at genesis on mainnet", () => {
      // Try to create an alternative genesis block
      const fakeGenesis = Buffer.alloc(32, 0xaa);
      const result = verifyCheckpoint(fakeGenesis, 0, MAINNET);

      expect(result.valid).toBe(false);
      expect(result.error).toContain("height 0");
    });

    it("should reject attempt to fork at halving checkpoint", () => {
      // Height 210000 is the first halving checkpoint
      const fakeHash = Buffer.alloc(32, 0xbb);
      const result = verifyCheckpoint(fakeHash, 210000, MAINNET);

      expect(result.valid).toBe(false);
    });

    it("should accept valid chain extending past checkpoints", () => {
      const hash = Buffer.alloc(32, 0x99);
      const parentHash = Buffer.alloc(32, 0x98);

      // All ancestors match checkpoints
      const ancestors = new Map<number, Buffer>();
      for (const [height, cpHash] of MAINNET.checkpoints) {
        ancestors.set(height, cpHash);
      }

      // Create function to look up ancestors
      const getAncestor = (h: number) => ancestors.get(h);

      // Header at height 1000000 (well above all checkpoints)
      const result = checkForkBelowCheckpoint(
        1000000,
        hash,
        parentHash,
        MAINNET,
        getAncestor
      );

      expect(result.valid).toBe(true);
    });
  });
});
