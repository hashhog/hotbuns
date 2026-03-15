/**
 * Tests for coinbase maturity enforcement.
 *
 * Coinbase outputs require 100 confirmations before they can be spent.
 * This prevents miners from spending their rewards before the chain has
 * sufficient depth to prevent reorganization attacks.
 */

import { describe, expect, test, beforeEach, afterEach } from "bun:test";
import { rmSync, mkdirSync } from "fs";
import { Wallet, type WalletConfig, type WalletUTXO, COINBASE_MATURITY } from "../wallet/wallet";
import { AddressType } from "../address/encoding";

const TEST_DATADIR = "/tmp/hotbuns-maturity-test";

const TEST_MNEMONIC =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

function createTestConfig(): WalletConfig {
  return {
    datadir: TEST_DATADIR,
    network: "regtest",
  };
}

describe("Coinbase Maturity", () => {
  beforeEach(() => {
    mkdirSync(TEST_DATADIR, { recursive: true });
  });

  afterEach(() => {
    rmSync(TEST_DATADIR, { recursive: true, force: true });
  });

  test("COINBASE_MATURITY constant is 100", () => {
    expect(COINBASE_MATURITY).toBe(100);
  });

  test("immature coinbase UTXOs are not spendable", () => {
    const config = createTestConfig();
    const wallet = Wallet.create(config, TEST_MNEMONIC);
    const address = wallet.getNewAddress();

    // Add an immature coinbase UTXO (only 50 confirmations)
    const immatureCoinbase: WalletUTXO = {
      outpoint: {
        txid: Buffer.alloc(32, 1),
        vout: 0,
      },
      amount: 5000000000n, // 50 BTC coinbase reward
      address,
      keyPath: "m/84'/0'/0'/0/0",
      confirmations: 50, // Less than 100
      addressType: AddressType.P2WPKH,
      isCoinbase: true,
    };

    wallet.addUTXO(immatureCoinbase);

    // Check that it's not spendable
    expect(wallet.isUTXOSpendable(immatureCoinbase)).toBe(false);

    // Check that getSpendableUTXOs excludes it
    const spendable = wallet.getSpendableUTXOs();
    expect(spendable.length).toBe(0);

    // Total UTXOs should still include it
    const allUTXOs = wallet.getUTXOs();
    expect(allUTXOs.length).toBe(1);
  });

  test("mature coinbase UTXOs are spendable", () => {
    const config = createTestConfig();
    const wallet = Wallet.create(config, TEST_MNEMONIC);
    const address = wallet.getNewAddress();

    // Add a mature coinbase UTXO (100+ confirmations)
    const matureCoinbase: WalletUTXO = {
      outpoint: {
        txid: Buffer.alloc(32, 2),
        vout: 0,
      },
      amount: 5000000000n,
      address,
      keyPath: "m/84'/0'/0'/0/0",
      confirmations: 100, // Exactly 100
      addressType: AddressType.P2WPKH,
      isCoinbase: true,
    };

    wallet.addUTXO(matureCoinbase);

    // Check that it's spendable
    expect(wallet.isUTXOSpendable(matureCoinbase)).toBe(true);

    // Check that getSpendableUTXOs includes it
    const spendable = wallet.getSpendableUTXOs();
    expect(spendable.length).toBe(1);
  });

  test("coinbase at exactly 99 confirmations is not spendable", () => {
    const config = createTestConfig();
    const wallet = Wallet.create(config, TEST_MNEMONIC);
    const address = wallet.getNewAddress();

    const coinbase: WalletUTXO = {
      outpoint: {
        txid: Buffer.alloc(32, 3),
        vout: 0,
      },
      amount: 5000000000n,
      address,
      keyPath: "m/84'/0'/0'/0/0",
      confirmations: 99, // One less than required
      addressType: AddressType.P2WPKH,
      isCoinbase: true,
    };

    wallet.addUTXO(coinbase);
    expect(wallet.isUTXOSpendable(coinbase)).toBe(false);
  });

  test("non-coinbase UTXOs are spendable with 1 confirmation", () => {
    const config = createTestConfig();
    const wallet = Wallet.create(config, TEST_MNEMONIC);
    const address = wallet.getNewAddress();

    // Regular UTXO (not coinbase)
    const regularUTXO: WalletUTXO = {
      outpoint: {
        txid: Buffer.alloc(32, 4),
        vout: 0,
      },
      amount: 1000000n,
      address,
      keyPath: "m/84'/0'/0'/0/0",
      confirmations: 1,
      addressType: AddressType.P2WPKH,
      isCoinbase: false,
    };

    wallet.addUTXO(regularUTXO);

    // Should be spendable with just 1 confirmation
    expect(wallet.isUTXOSpendable(regularUTXO)).toBe(true);
    expect(wallet.getSpendableUTXOs().length).toBe(1);
  });

  test("unconfirmed UTXOs are not spendable", () => {
    const config = createTestConfig();
    const wallet = Wallet.create(config, TEST_MNEMONIC);
    const address = wallet.getNewAddress();

    const unconfirmed: WalletUTXO = {
      outpoint: {
        txid: Buffer.alloc(32, 5),
        vout: 0,
      },
      amount: 1000000n,
      address,
      keyPath: "m/84'/0'/0'/0/0",
      confirmations: 0, // Unconfirmed
      addressType: AddressType.P2WPKH,
      isCoinbase: false,
    };

    wallet.addUTXO(unconfirmed);

    expect(wallet.isUTXOSpendable(unconfirmed)).toBe(false);
  });

  test("coin selection excludes immature coinbase", () => {
    const config = createTestConfig();
    const wallet = Wallet.create(config, TEST_MNEMONIC);
    const address = wallet.getNewAddress();

    // Add an immature coinbase with large amount
    wallet.addUTXO({
      outpoint: { txid: Buffer.alloc(32, 1), vout: 0 },
      amount: 5000000000n, // 50 BTC
      address,
      keyPath: "m/84'/0'/0'/0/0",
      confirmations: 50,
      addressType: AddressType.P2WPKH,
      isCoinbase: true,
    });

    // Add a small regular UTXO
    wallet.addUTXO({
      outpoint: { txid: Buffer.alloc(32, 2), vout: 0 },
      amount: 10000n, // 0.0001 BTC
      address,
      keyPath: "m/84'/0'/0'/0/0",
      confirmations: 6,
      addressType: AddressType.P2WPKH,
      isCoinbase: false,
    });

    // Try to spend more than the small UTXO but less than coinbase
    // Should fail because coinbase is immature
    expect(() => {
      wallet.createTransaction(
        [{ address: "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080", amount: 100000n }],
        1
      );
    }).toThrow("Insufficient funds");
  });

  test("coin selection includes mature coinbase", () => {
    const config = createTestConfig();
    const wallet = Wallet.create(config, TEST_MNEMONIC);
    const address = wallet.getNewAddress();

    // Add a mature coinbase
    wallet.addUTXO({
      outpoint: { txid: Buffer.alloc(32, 1), vout: 0 },
      amount: 5000000000n, // 50 BTC
      address,
      keyPath: "m/84'/0'/0'/0/0",
      confirmations: 100,
      addressType: AddressType.P2WPKH,
      isCoinbase: true,
    });

    // Should be able to spend from mature coinbase
    const tx = wallet.createTransaction(
      [{ address: "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080", amount: 100000n }],
      1
    );

    expect(tx.inputs.length).toBeGreaterThanOrEqual(1);
  });

  test("balance includes immature coinbase in total", () => {
    const config = createTestConfig();
    const wallet = Wallet.create(config, TEST_MNEMONIC);
    const address = wallet.getNewAddress();

    // Add mature UTXO
    wallet.addUTXO({
      outpoint: { txid: Buffer.alloc(32, 1), vout: 0 },
      amount: 1000000n,
      address,
      keyPath: "m/84'/0'/0'/0/0",
      confirmations: 100,
      addressType: AddressType.P2WPKH,
      isCoinbase: false,
    });

    // Add immature coinbase
    wallet.addUTXO({
      outpoint: { txid: Buffer.alloc(32, 2), vout: 0 },
      amount: 5000000000n,
      address,
      keyPath: "m/84'/0'/0'/0/0",
      confirmations: 50,
      addressType: AddressType.P2WPKH,
      isCoinbase: true,
    });

    const balance = wallet.getBalance();

    // Total should include both
    expect(balance.total).toBe(5001000000n);

    // Confirmed should include both (they're both confirmed)
    expect(balance.confirmed).toBe(5001000000n);

    // But only the regular UTXO is spendable
    const spendable = wallet.getSpendableUTXOs();
    const spendableAmount = spendable.reduce((sum, u) => sum + u.amount, 0n);
    expect(spendableAmount).toBe(1000000n);
  });
});

describe("Coinbase Maturity Consensus", () => {
  test("ConsensusError PREMATURE_COINBASE_SPEND is defined", async () => {
    const { ConsensusError, ConsensusErrorCode } = await import("../validation/errors");

    const error = new ConsensusError(ConsensusErrorCode.PREMATURE_COINBASE_SPEND, "test");
    expect(error.code).toBe(ConsensusErrorCode.PREMATURE_COINBASE_SPEND);
    expect(error.name).toBe("ConsensusError");
  });
});
