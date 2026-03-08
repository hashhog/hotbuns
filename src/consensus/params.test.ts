import { describe, expect, test } from "bun:test";
import {
  MAINNET,
  TESTNET,
  REGTEST,
  getBlockSubsidy,
  compactToBigInt,
  bigIntToCompact,
  getGenesisBlock,
} from "./params";

describe("network constants", () => {
  test("mainnet network magic", () => {
    expect(MAINNET.networkMagic).toBe(0xd9b4bef9);
  });

  test("testnet network magic", () => {
    expect(TESTNET.networkMagic).toBe(0x0709110b);
  });

  test("regtest network magic", () => {
    expect(REGTEST.networkMagic).toBe(0xdab5bffa);
  });

  test("mainnet default port", () => {
    expect(MAINNET.defaultPort).toBe(8333);
  });

  test("testnet default port", () => {
    expect(TESTNET.defaultPort).toBe(18333);
  });

  test("regtest default port", () => {
    expect(REGTEST.defaultPort).toBe(18444);
  });

  test("mainnet max coins is 21M BTC in satoshis", () => {
    expect(MAINNET.maxCoins).toBe(2_100_000_000_000_000n);
  });

  test("services field has correct flags", () => {
    // NODE_NETWORK (1) | NODE_WITNESS (8) | NODE_NETWORK_LIMITED (1024)
    expect(MAINNET.services).toBe(0x0409n);
    expect(MAINNET.services).toBe(1n | 8n | 1024n);
  });

  test("difficulty adjustment interval is 2016 blocks", () => {
    expect(MAINNET.difficultyAdjustmentInterval).toBe(2016);
    // targetTimespan / targetSpacing = 1209600 / 600 = 2016
    expect(MAINNET.targetTimespan / MAINNET.targetSpacing).toBe(2016);
  });
});

describe("getBlockSubsidy", () => {
  test("block 0 subsidy is 50 BTC", () => {
    const subsidy = getBlockSubsidy(0, MAINNET);
    expect(subsidy).toBe(50_00000000n);
  });

  test("block 209999 subsidy is still 50 BTC", () => {
    const subsidy = getBlockSubsidy(209999, MAINNET);
    expect(subsidy).toBe(50_00000000n);
  });

  test("block 210000 subsidy is 25 BTC (first halving)", () => {
    const subsidy = getBlockSubsidy(210000, MAINNET);
    expect(subsidy).toBe(25_00000000n);
  });

  test("block 420000 subsidy is 12.5 BTC (second halving)", () => {
    const subsidy = getBlockSubsidy(420000, MAINNET);
    expect(subsidy).toBe(12_50000000n);
  });

  test("block 630000 subsidy is 6.25 BTC (third halving)", () => {
    const subsidy = getBlockSubsidy(630000, MAINNET);
    expect(subsidy).toBe(6_25000000n);
  });

  test("block 840000 subsidy is 3.125 BTC (fourth halving)", () => {
    const subsidy = getBlockSubsidy(840000, MAINNET);
    expect(subsidy).toBe(3_12500000n);
  });

  test("block 6930000 subsidy is 0 (after 33 halvings)", () => {
    // 33 halvings * 210000 = 6930000
    // 50 BTC >> 33 = 0 (subsidy rounds to 0)
    const subsidy = getBlockSubsidy(6930000, MAINNET);
    expect(subsidy).toBe(0n);
  });

  test("after 64 halvings subsidy is 0", () => {
    // 64 * 210000 = 13,440,000
    const subsidy = getBlockSubsidy(13_440_000, MAINNET);
    expect(subsidy).toBe(0n);
  });

  test("regtest halving interval is 150 blocks", () => {
    expect(getBlockSubsidy(0, REGTEST)).toBe(50_00000000n);
    expect(getBlockSubsidy(149, REGTEST)).toBe(50_00000000n);
    expect(getBlockSubsidy(150, REGTEST)).toBe(25_00000000n);
    expect(getBlockSubsidy(300, REGTEST)).toBe(12_50000000n);
  });
});

describe("compactToBigInt", () => {
  test("converts mainnet powLimitBits correctly", () => {
    const target = compactToBigInt(0x1d00ffff);
    expect(target).toBe(MAINNET.powLimit);
  });

  test("converts regtest powLimitBits correctly", () => {
    const target = compactToBigInt(0x207fffff);
    expect(target).toBe(REGTEST.powLimit);
  });

  test("handles small exponents", () => {
    // 0x03000001 = exponent 3, mantissa 1
    // target = 1 * 2^(8*(3-3)) = 1
    const target = compactToBigInt(0x03000001);
    expect(target).toBe(1n);
  });

  test("handles zero mantissa", () => {
    const target = compactToBigInt(0x1d000000);
    expect(target).toBe(0n);
  });

  test("negative flag returns zero", () => {
    // 0x1d800000 has the negative bit set
    const target = compactToBigInt(0x1d800001);
    expect(target).toBe(0n);
  });
});

describe("bigIntToCompact", () => {
  test("converts mainnet powLimit correctly", () => {
    const bits = bigIntToCompact(MAINNET.powLimit);
    expect(bits).toBe(0x1d00ffff);
  });

  test("converts regtest powLimit correctly", () => {
    const bits = bigIntToCompact(REGTEST.powLimit);
    expect(bits).toBe(0x207fffff);
  });

  test("handles zero", () => {
    const bits = bigIntToCompact(0n);
    expect(bits).toBe(0);
  });

  test("handles small values", () => {
    const bits = bigIntToCompact(1n);
    const roundTrip = compactToBigInt(bits);
    expect(roundTrip).toBe(1n);
  });

  test("round-trip conversion preserves value", () => {
    // Test with actual targets derived from compact values
    const compactValues = [
      0x1d00ffff, // mainnet initial difficulty
      0x1c00ffff,
      0x1b00ffff,
      0x1a00ffff,
      0x207fffff, // regtest
      0x1903a30c, // a real difficulty value
    ];

    for (const bits of compactValues) {
      const target = compactToBigInt(bits);
      const roundTrip = bigIntToCompact(target);
      const targetAgain = compactToBigInt(roundTrip);
      // The round-trip target should match
      expect(targetAgain).toBe(target);
    }
  });
});

describe("genesis block", () => {
  test("mainnet genesis block hash matches expected", () => {
    // The famous genesis block hash (reversed for internal byte order)
    const expectedHash = Buffer.from(
      "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
      "hex"
    ).reverse();
    expect(MAINNET.genesisBlockHash.equals(expectedHash)).toBe(true);
  });

  test("mainnet genesis block can be parsed", () => {
    const block = getGenesisBlock(MAINNET);

    expect(block.header.version).toBe(1);
    expect(block.header.prevBlockHash.equals(Buffer.alloc(32, 0))).toBe(true);
    expect(block.header.timestamp).toBe(1231006505);
    expect(block.header.bits).toBe(0x1d00ffff);
    expect(block.header.nonce).toBe(2083236893);
    expect(block.transactions.length).toBe(1);
  });

  test("mainnet genesis coinbase contains Times headline", () => {
    const block = getGenesisBlock(MAINNET);
    const coinbase = block.transactions[0];

    expect(coinbase.inputs.length).toBe(1);
    expect(coinbase.outputs.length).toBe(1);
    expect(coinbase.outputs[0].value).toBe(50_00000000n);

    // The scriptSig should contain the famous headline
    const scriptSig = coinbase.inputs[0].scriptSig;
    const scriptStr = scriptSig.toString("ascii");
    expect(scriptStr).toContain("The Times 03/Jan/2009");
    expect(scriptStr).toContain("Chancellor on brink of second bailout for banks");
  });

  test("testnet genesis block has correct timestamp", () => {
    const block = getGenesisBlock(TESTNET);
    expect(block.header.timestamp).toBe(1296688602);
  });

  test("regtest genesis block has minimum difficulty", () => {
    const block = getGenesisBlock(REGTEST);
    expect(block.header.bits).toBe(0x207fffff);
    expect(block.header.nonce).toBe(2);
  });

  test("genesis coinbase output is not spendable", () => {
    // This is a reminder that the genesis coinbase is NOT in the UTXO set
    // (a known Bitcoin quirk). The implementation should handle this.
    const block = getGenesisBlock(MAINNET);
    const coinbase = block.transactions[0];
    // The output exists but should never be added to UTXO set
    expect(coinbase.outputs[0].value).toBe(50_00000000n);
    // Note: Actual UTXO handling is done elsewhere, this just documents the quirk
  });
});

describe("checkpoint validation", () => {
  test("mainnet has checkpoints", () => {
    expect(MAINNET.checkpoints.size).toBeGreaterThan(0);
  });

  test("mainnet genesis checkpoint matches genesis hash", () => {
    const checkpoint = MAINNET.checkpoints.get(0);
    expect(checkpoint).toBeDefined();
    expect(checkpoint!.equals(MAINNET.genesisBlockHash)).toBe(true);
  });

  test("testnet has genesis checkpoint", () => {
    const checkpoint = TESTNET.checkpoints.get(0);
    expect(checkpoint).toBeDefined();
    expect(checkpoint!.equals(TESTNET.genesisBlockHash)).toBe(true);
  });

  test("regtest has no checkpoints", () => {
    expect(REGTEST.checkpoints.size).toBe(0);
  });
});

describe("BIP activation heights", () => {
  test("mainnet BIP activation heights are set", () => {
    expect(MAINNET.bip34Height).toBe(227931);
    expect(MAINNET.bip65Height).toBe(388381);
    expect(MAINNET.bip66Height).toBe(363725);
    expect(MAINNET.segwitHeight).toBe(481824);
    expect(MAINNET.taprootHeight).toBe(709632);
  });

  test("regtest has early activation for all BIPs", () => {
    expect(REGTEST.segwitHeight).toBe(0);
    expect(REGTEST.taprootHeight).toBe(0);
  });
});
