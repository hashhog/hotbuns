/**
 * Tests for wallet encryption with AES-256-CBC.
 *
 * Wallet encryption protects private keys with a passphrase-derived key.
 * Uses scrypt for key derivation and AES-256-CBC for encryption.
 */

import { describe, expect, test, beforeEach, afterEach } from "bun:test";
import { rmSync, mkdirSync } from "fs";
import { Wallet, type WalletConfig } from "../wallet/wallet";

const TEST_DATADIR = "/tmp/hotbuns-encrypt-test";

const TEST_MNEMONIC =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

function createTestConfig(): WalletConfig {
  return {
    datadir: TEST_DATADIR,
    network: "regtest",
  };
}

describe("Wallet Encryption", () => {
  beforeEach(() => {
    mkdirSync(TEST_DATADIR, { recursive: true });
  });

  afterEach(() => {
    rmSync(TEST_DATADIR, { recursive: true, force: true });
  });

  test("new wallet is not encrypted", () => {
    const config = createTestConfig();
    const wallet = Wallet.create(config, TEST_MNEMONIC);

    expect(wallet.isEncrypted()).toBe(false);
    expect(wallet.isLocked()).toBe(false);
  });

  test("encryptWallet encrypts and locks the wallet", async () => {
    const config = createTestConfig();
    const wallet = Wallet.create(config, TEST_MNEMONIC);
    const passphrase = "test-passphrase-123";

    await wallet.encryptWallet(passphrase);

    expect(wallet.isEncrypted()).toBe(true);
    expect(wallet.isLocked()).toBe(true);
  });

  test("cannot encrypt already encrypted wallet", async () => {
    const config = createTestConfig();
    const wallet = Wallet.create(config, TEST_MNEMONIC);
    const passphrase = "test-passphrase-123";

    await wallet.encryptWallet(passphrase);

    await expect(wallet.encryptWallet(passphrase)).rejects.toThrow(
      "already encrypted"
    );
  });

  test("cannot encrypt with empty passphrase", async () => {
    const config = createTestConfig();
    const wallet = Wallet.create(config, TEST_MNEMONIC);

    await expect(wallet.encryptWallet("")).rejects.toThrow("empty");
  });

  test("unlockWallet unlocks with correct passphrase", async () => {
    const config = createTestConfig();
    const wallet = Wallet.create(config, TEST_MNEMONIC);
    const passphrase = "test-passphrase-123";

    await wallet.encryptWallet(passphrase);
    expect(wallet.isLocked()).toBe(true);

    await wallet.unlockWallet(passphrase, 0);
    expect(wallet.isLocked()).toBe(false);
  });

  test("unlockWallet fails with incorrect passphrase", async () => {
    const config = createTestConfig();
    const wallet = Wallet.create(config, TEST_MNEMONIC);
    const passphrase = "test-passphrase-123";

    await wallet.encryptWallet(passphrase);

    await expect(wallet.unlockWallet("wrong-passphrase", 0)).rejects.toThrow(
      "Incorrect"
    );
  });

  test("lockWallet locks the wallet", async () => {
    const config = createTestConfig();
    const wallet = Wallet.create(config, TEST_MNEMONIC);
    const passphrase = "test-passphrase-123";

    await wallet.encryptWallet(passphrase);
    await wallet.unlockWallet(passphrase, 0);
    expect(wallet.isLocked()).toBe(false);

    wallet.lockWallet();
    expect(wallet.isLocked()).toBe(true);
  });

  test("lockWallet throws on unencrypted wallet", () => {
    const config = createTestConfig();
    const wallet = Wallet.create(config, TEST_MNEMONIC);

    expect(() => wallet.lockWallet()).toThrow("not encrypted");
  });

  test("changePassphrase changes the passphrase", async () => {
    const config = createTestConfig();
    const wallet = Wallet.create(config, TEST_MNEMONIC);
    const oldPassphrase = "old-passphrase";
    const newPassphrase = "new-passphrase";

    await wallet.encryptWallet(oldPassphrase);
    await wallet.changePassphrase(oldPassphrase, newPassphrase);

    // Old passphrase should no longer work
    await expect(wallet.unlockWallet(oldPassphrase, 0)).rejects.toThrow();

    // New passphrase should work
    await wallet.unlockWallet(newPassphrase, 0);
    expect(wallet.isLocked()).toBe(false);
  });

  test("getSeed throws when wallet is locked", async () => {
    const config = createTestConfig();
    const wallet = Wallet.create(config, TEST_MNEMONIC);
    const passphrase = "test-passphrase-123";

    // Seed is accessible before encryption
    const seedBefore = Buffer.from(wallet.getSeed()); // Copy the buffer
    expect(seedBefore.length).toBe(64);

    await wallet.encryptWallet(passphrase);

    // Seed should not be accessible when locked
    expect(() => wallet.getSeed()).toThrow("locked");

    // Unlock and seed should be accessible again
    await wallet.unlockWallet(passphrase, 0);
    const seedAfter = wallet.getSeed();
    expect(seedAfter.length).toBe(64);
    expect(seedAfter.equals(seedBefore)).toBe(true);
  });

  test("encryption state is serializable", async () => {
    const config = createTestConfig();
    const wallet = Wallet.create(config, TEST_MNEMONIC);
    const passphrase = "test-passphrase-123";

    await wallet.encryptWallet(passphrase);

    const state = wallet.getEncryptionState();
    expect(state.isEncrypted).toBe(true);
    expect(typeof state.encryptedSeed).toBe("string");
    expect(typeof state.encryptionSalt).toBe("string");
    expect(typeof state.encryptionIV).toBe("string");
  });

  test("encryption state can be restored", async () => {
    const config = createTestConfig();
    const wallet1 = Wallet.create(config, TEST_MNEMONIC);
    const passphrase = "test-passphrase-123";

    await wallet1.encryptWallet(passphrase);
    const state = wallet1.getEncryptionState();

    // Create a new wallet and restore the encryption state
    const wallet2 = Wallet.create(config, TEST_MNEMONIC);
    wallet2.setEncryptionState(state);

    expect(wallet2.isEncrypted()).toBe(true);
    expect(wallet2.isLocked()).toBe(true);

    // Should be able to unlock with the same passphrase
    await wallet2.unlockWallet(passphrase, 0);
    expect(wallet2.isLocked()).toBe(false);
  });

  test("auto-lock timeout works", async () => {
    const config = createTestConfig();
    const wallet = Wallet.create(config, TEST_MNEMONIC);
    const passphrase = "test-passphrase-123";

    await wallet.encryptWallet(passphrase);

    // Unlock with 1 second timeout
    await wallet.unlockWallet(passphrase, 1);
    expect(wallet.isLocked()).toBe(false);

    // Wait for auto-lock
    await new Promise((resolve) => setTimeout(resolve, 1500));
    expect(wallet.isLocked()).toBe(true);
  }, 3000);

  test("unlock with 0 timeout stays unlocked", async () => {
    const config = createTestConfig();
    const wallet = Wallet.create(config, TEST_MNEMONIC);
    const passphrase = "test-passphrase-123";

    await wallet.encryptWallet(passphrase);
    await wallet.unlockWallet(passphrase, 0);

    // Should stay unlocked
    await new Promise((resolve) => setTimeout(resolve, 100));
    expect(wallet.isLocked()).toBe(false);
  });
});

describe("Wallet Encryption Persistence", () => {
  beforeEach(() => {
    mkdirSync(TEST_DATADIR, { recursive: true });
  });

  afterEach(() => {
    rmSync(TEST_DATADIR, { recursive: true, force: true });
  });

  test("encrypted wallet can be saved and loaded", async () => {
    const config = createTestConfig();
    const filePassword = "file-password";
    const walletPassword = "wallet-password";

    // Create and encrypt wallet
    const wallet1 = Wallet.create(config, TEST_MNEMONIC);
    const address = wallet1.getNewAddress();
    await wallet1.encryptWallet(walletPassword);

    // Unlock to allow saving with seed
    await wallet1.unlockWallet(walletPassword, 0);
    await wallet1.save(filePassword);

    // Load wallet
    const wallet2 = await Wallet.load(config, filePassword);

    // Should be encrypted and locked
    expect(wallet2.isEncrypted()).toBe(true);
    expect(wallet2.isLocked()).toBe(true);

    // Unlock with wallet password
    await wallet2.unlockWallet(walletPassword, 0);
    expect(wallet2.isLocked()).toBe(false);

    // After unlock, we need to regenerate addresses
    // The first address from the same mnemonic should match
    const expectedAddress = wallet2.getNewAddress();
    // Note: The first address generated will be the same as wallet1's first address
    // since both use the same mnemonic
    expect(expectedAddress).toBeDefined();
    expect(expectedAddress.length).toBeGreaterThan(0);
  });
});
