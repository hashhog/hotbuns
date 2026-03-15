/**
 * Tests for address labels.
 *
 * Labels allow users to associate human-readable names with addresses,
 * useful for organizing funds and tracking transaction purposes.
 */

import { describe, expect, test, beforeEach, afterEach } from "bun:test";
import { rmSync, mkdirSync } from "fs";
import { Wallet, type WalletConfig, type WalletUTXO } from "../wallet/wallet";
import { AddressType } from "../address/encoding";

const TEST_DATADIR = "/tmp/hotbuns-label-test";

const TEST_MNEMONIC =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

function createTestConfig(): WalletConfig {
  return {
    datadir: TEST_DATADIR,
    network: "regtest",
  };
}

describe("Address Labels", () => {
  beforeEach(() => {
    mkdirSync(TEST_DATADIR, { recursive: true });
  });

  afterEach(() => {
    rmSync(TEST_DATADIR, { recursive: true, force: true });
  });

  test("new address has no label", () => {
    const config = createTestConfig();
    const wallet = Wallet.create(config, TEST_MNEMONIC);
    const address = wallet.getNewAddress();

    expect(wallet.getLabel(address)).toBe("");
  });

  test("setLabel assigns a label to an address", () => {
    const config = createTestConfig();
    const wallet = Wallet.create(config, TEST_MNEMONIC);
    const address = wallet.getNewAddress();

    wallet.setLabel(address, "savings");
    expect(wallet.getLabel(address)).toBe("savings");
  });

  test("setLabel with empty string removes the label", () => {
    const config = createTestConfig();
    const wallet = Wallet.create(config, TEST_MNEMONIC);
    const address = wallet.getNewAddress();

    wallet.setLabel(address, "savings");
    expect(wallet.getLabel(address)).toBe("savings");

    wallet.setLabel(address, "");
    expect(wallet.getLabel(address)).toBe("");
  });

  test("setLabel throws for unknown address", () => {
    const config = createTestConfig();
    const wallet = Wallet.create(config, TEST_MNEMONIC);

    expect(() => {
      wallet.setLabel("bcrt1qnotinwallet", "label");
    }).toThrow("not found");
  });

  test("getAddressesByLabel returns addresses with that label", () => {
    const config = createTestConfig();
    const wallet = Wallet.create(config, TEST_MNEMONIC);

    const addr1 = wallet.getNewAddress();
    const addr2 = wallet.getNewAddress();
    const addr3 = wallet.getNewAddress();

    wallet.setLabel(addr1, "savings");
    wallet.setLabel(addr2, "savings");
    wallet.setLabel(addr3, "checking");

    const savingsAddresses = wallet.getAddressesByLabel("savings");
    expect(savingsAddresses).toContain(addr1);
    expect(savingsAddresses).toContain(addr2);
    expect(savingsAddresses).not.toContain(addr3);
    expect(savingsAddresses.length).toBe(2);
  });

  test("listLabels returns all labels with their addresses", () => {
    const config = createTestConfig();
    const wallet = Wallet.create(config, TEST_MNEMONIC);

    const addr1 = wallet.getNewAddress();
    const addr2 = wallet.getNewAddress();
    const addr3 = wallet.getNewAddress();

    wallet.setLabel(addr1, "savings");
    wallet.setLabel(addr2, "savings");
    wallet.setLabel(addr3, "checking");

    const labels = wallet.listLabels();
    expect(labels.size).toBe(2);
    expect(labels.get("savings")?.length).toBe(2);
    expect(labels.get("checking")?.length).toBe(1);
  });

  test("labels are included in listReceivedByAddress", () => {
    const config = createTestConfig();
    const wallet = Wallet.create(config, TEST_MNEMONIC);
    const address = wallet.getNewAddress();

    wallet.setLabel(address, "donations");

    // Add a UTXO
    wallet.addUTXO({
      outpoint: { txid: Buffer.alloc(32, 1), vout: 0 },
      amount: 1000000n,
      address,
      keyPath: "m/84'/0'/0'/0/0",
      confirmations: 6,
      addressType: AddressType.P2WPKH,
      isCoinbase: false,
    });

    const received = wallet.listReceivedByAddress();
    const entry = received.find((r) => r.address === address);

    expect(entry).toBeDefined();
    expect(entry?.label).toBe("donations");
    expect(entry?.amount).toBe(1000000n);
  });

  test("labels persist with getLabelsObject/setLabelsFromObject", () => {
    const config = createTestConfig();
    const wallet1 = Wallet.create(config, TEST_MNEMONIC);

    const addr1 = wallet1.getNewAddress();
    const addr2 = wallet1.getNewAddress();

    wallet1.setLabel(addr1, "savings");
    wallet1.setLabel(addr2, "checking");

    const labelsObj = wallet1.getLabelsObject();
    expect(labelsObj[addr1]).toBe("savings");
    expect(labelsObj[addr2]).toBe("checking");

    // Create another wallet and restore labels
    const wallet2 = Wallet.create(config, TEST_MNEMONIC);
    wallet2.setLabelsFromObject(labelsObj);

    expect(wallet2.getLabel(addr1)).toBe("savings");
    expect(wallet2.getLabel(addr2)).toBe("checking");
  });
});

describe("Label Persistence", () => {
  beforeEach(() => {
    mkdirSync(TEST_DATADIR, { recursive: true });
  });

  afterEach(() => {
    rmSync(TEST_DATADIR, { recursive: true, force: true });
  });

  test("labels persist across save/load", async () => {
    const config = createTestConfig();
    const password = "test-password";

    // Create wallet with labels
    const wallet1 = Wallet.create(config, TEST_MNEMONIC);
    const addr1 = wallet1.getNewAddress();
    const addr2 = wallet1.getNewAddress();

    wallet1.setLabel(addr1, "work");
    wallet1.setLabel(addr2, "personal");

    await wallet1.save(password);

    // Load wallet
    const wallet2 = await Wallet.load(config, password);

    expect(wallet2.getLabel(addr1)).toBe("work");
    expect(wallet2.getLabel(addr2)).toBe("personal");
  });
});

describe("listReceivedByAddress with Labels", () => {
  beforeEach(() => {
    mkdirSync(TEST_DATADIR, { recursive: true });
  });

  afterEach(() => {
    rmSync(TEST_DATADIR, { recursive: true, force: true });
  });

  test("aggregates amounts by address", () => {
    const config = createTestConfig();
    const wallet = Wallet.create(config, TEST_MNEMONIC);
    const address = wallet.getNewAddress();

    // Add multiple UTXOs to the same address
    wallet.addUTXO({
      outpoint: { txid: Buffer.alloc(32, 1), vout: 0 },
      amount: 1000000n,
      address,
      keyPath: "m/84'/0'/0'/0/0",
      confirmations: 6,
      addressType: AddressType.P2WPKH,
      isCoinbase: false,
    });

    wallet.addUTXO({
      outpoint: { txid: Buffer.alloc(32, 2), vout: 0 },
      amount: 2000000n,
      address,
      keyPath: "m/84'/0'/0'/0/0",
      confirmations: 10,
      addressType: AddressType.P2WPKH,
      isCoinbase: false,
    });

    const received = wallet.listReceivedByAddress();
    const entry = received.find((r) => r.address === address);

    expect(entry).toBeDefined();
    expect(entry?.amount).toBe(3000000n); // Sum of both UTXOs
    expect(entry?.confirmations).toBe(6); // Minimum confirmations
  });

  test("includes addresses with labels but no balance", () => {
    const config = createTestConfig();
    const wallet = Wallet.create(config, TEST_MNEMONIC);

    const addr1 = wallet.getNewAddress();
    const addr2 = wallet.getNewAddress();

    wallet.setLabel(addr1, "labeled-no-funds");
    wallet.setLabel(addr2, "labeled-with-funds");

    // Only add funds to addr2
    wallet.addUTXO({
      outpoint: { txid: Buffer.alloc(32, 1), vout: 0 },
      amount: 1000000n,
      address: addr2,
      keyPath: "m/84'/0'/0'/0/1",
      confirmations: 6,
      addressType: AddressType.P2WPKH,
      isCoinbase: false,
    });

    const received = wallet.listReceivedByAddress();

    // Only addr2 should appear (has UTXOs)
    const entry1 = received.find((r) => r.address === addr1);
    const entry2 = received.find((r) => r.address === addr2);

    expect(entry1).toBeUndefined(); // No UTXOs
    expect(entry2).toBeDefined();
    expect(entry2?.label).toBe("labeled-with-funds");
  });
});
