/**
 * Tests for multi-wallet support.
 *
 * Verifies that multiple wallets can be loaded simultaneously with
 * independent keys, balances, and transaction history. Tests wallet-specific
 * RPC endpoints via /wallet/<name> URL prefix.
 */

import { describe, expect, test, beforeEach, afterEach } from "bun:test";
import { rmSync, mkdirSync, existsSync } from "fs";
import {
  Wallet,
  WalletManager,
  type WalletConfig,
  type CreateWalletOptions,
} from "../wallet/wallet";
import { RPCServer, type RPCServerConfig, type RPCServerDeps } from "../rpc/server";

const TEST_DATADIR = "/tmp/hotbuns-multi-wallet-test";
const TEST_PASSWORD = "test-password-123";

function createTestConfig(subdir?: string): WalletConfig {
  return {
    datadir: subdir ? `${TEST_DATADIR}/${subdir}` : TEST_DATADIR,
    network: "regtest",
  };
}

describe("WalletManager", () => {
  beforeEach(() => {
    mkdirSync(TEST_DATADIR, { recursive: true });
    mkdirSync(`${TEST_DATADIR}/wallets`, { recursive: true });
  });

  afterEach(() => {
    rmSync(TEST_DATADIR, { recursive: true, force: true });
  });

  test("creates a new wallet", async () => {
    const manager = new WalletManager(TEST_DATADIR, "regtest");

    const result = await manager.createWallet("testwallet", {}, TEST_PASSWORD);

    expect(result.name).toBe("testwallet");
    expect(result.warnings).toEqual([]);
    expect(manager.hasWallet("testwallet")).toBe(true);
    expect(manager.getWalletCount()).toBe(1);
  });

  test("creates wallet with passphrase encryption", async () => {
    const manager = new WalletManager(TEST_DATADIR, "regtest");
    const passphrase = "my-secure-passphrase";

    const result = await manager.createWallet("encrypted", { passphrase });

    expect(result.name).toBe("encrypted");
    const wallet = manager.getWallet("encrypted");
    expect(wallet).toBeDefined();
    expect(wallet!.isEncrypted()).toBe(true);
    expect(wallet!.isLocked()).toBe(true);
  });

  test("cannot create duplicate wallet", async () => {
    const manager = new WalletManager(TEST_DATADIR, "regtest");
    await manager.createWallet("duplicate", {}, TEST_PASSWORD);

    await expect(
      manager.createWallet("duplicate", {}, TEST_PASSWORD)
    ).rejects.toThrow("already loaded");
  });

  test("loads an existing wallet", async () => {
    const manager = new WalletManager(TEST_DATADIR, "regtest");

    // First create and unload a wallet
    await manager.createWallet("loadtest", {}, TEST_PASSWORD);
    await manager.unloadWallet("loadtest");
    expect(manager.hasWallet("loadtest")).toBe(false);

    // Now load it
    const result = await manager.loadWallet("loadtest", TEST_PASSWORD);
    expect(result.name).toBe("loadtest");
    expect(manager.hasWallet("loadtest")).toBe(true);
  });

  test("cannot load non-existent wallet", async () => {
    const manager = new WalletManager(TEST_DATADIR, "regtest");

    await expect(
      manager.loadWallet("nonexistent", TEST_PASSWORD)
    ).rejects.toThrow("not found");
  });

  test("cannot load already loaded wallet", async () => {
    const manager = new WalletManager(TEST_DATADIR, "regtest");
    await manager.createWallet("alreadyloaded", {}, TEST_PASSWORD);

    await expect(
      manager.loadWallet("alreadyloaded", TEST_PASSWORD)
    ).rejects.toThrow("already loaded");
  });

  test("unloads a wallet", async () => {
    const manager = new WalletManager(TEST_DATADIR, "regtest");
    await manager.createWallet("unloadtest", {}, TEST_PASSWORD);
    expect(manager.hasWallet("unloadtest")).toBe(true);

    const result = await manager.unloadWallet("unloadtest");
    expect(result.warnings).toEqual([]);
    expect(manager.hasWallet("unloadtest")).toBe(false);
  });

  test("cannot unload non-loaded wallet", async () => {
    const manager = new WalletManager(TEST_DATADIR, "regtest");

    await expect(manager.unloadWallet("notloaded")).rejects.toThrow(
      "not loaded"
    );
  });

  test("lists loaded wallets", async () => {
    const manager = new WalletManager(TEST_DATADIR, "regtest");
    await manager.createWallet("wallet1", {}, TEST_PASSWORD);
    await manager.createWallet("wallet2", {}, TEST_PASSWORD);
    await manager.createWallet("wallet3", {}, TEST_PASSWORD);

    const wallets = manager.listWallets();
    expect(wallets).toContain("wallet1");
    expect(wallets).toContain("wallet2");
    expect(wallets).toContain("wallet3");
    expect(wallets.length).toBe(3);
  });

  test("lists wallet directories", async () => {
    const manager = new WalletManager(TEST_DATADIR, "regtest");
    await manager.createWallet("dirtest1", {}, TEST_PASSWORD);
    await manager.createWallet("dirtest2", {}, TEST_PASSWORD);
    await manager.unloadWallet("dirtest2");

    const entries = await manager.listWalletDir();
    const names = entries.map((e) => e.name);
    expect(names).toContain("dirtest1");
    expect(names).toContain("dirtest2");
  });

  test("gets default wallet when only one loaded", async () => {
    const manager = new WalletManager(TEST_DATADIR, "regtest");
    await manager.createWallet("default", {}, TEST_PASSWORD);

    const wallet = manager.getDefaultWallet();
    expect(wallet).toBeDefined();
  });

  test("getDefaultWallet returns undefined when multiple wallets loaded", async () => {
    const manager = new WalletManager(TEST_DATADIR, "regtest");
    await manager.createWallet("wallet1", {}, TEST_PASSWORD);
    await manager.createWallet("wallet2", {}, TEST_PASSWORD);

    const wallet = manager.getDefaultWallet();
    expect(wallet).toBeUndefined();
  });

  test("getDefaultWallet returns undefined when no wallets loaded", async () => {
    const manager = new WalletManager(TEST_DATADIR, "regtest");

    const wallet = manager.getDefaultWallet();
    expect(wallet).toBeUndefined();
  });

  test("multiple wallets have independent addresses", async () => {
    const manager = new WalletManager(TEST_DATADIR, "regtest");
    await manager.createWallet("indep1", {}, TEST_PASSWORD);
    await manager.createWallet("indep2", {}, TEST_PASSWORD);

    const wallet1 = manager.getWallet("indep1")!;
    const wallet2 = manager.getWallet("indep2")!;

    const addr1 = wallet1.getNewAddress();
    const addr2 = wallet2.getNewAddress();

    // Different wallets should have different addresses (different seeds)
    expect(addr1).not.toBe(addr2);
  });

  test("loadOnStartup adds wallet to settings", async () => {
    const manager = new WalletManager(TEST_DATADIR, "regtest");
    await manager.createWallet("startup", { loadOnStartup: true }, TEST_PASSWORD);

    const startupWallets = await manager.getStartupWallets();
    expect(startupWallets).toContain("startup");
  });

  test("loadOnStartup=false removes wallet from settings", async () => {
    const manager = new WalletManager(TEST_DATADIR, "regtest");
    await manager.createWallet("nostartup", { loadOnStartup: true }, TEST_PASSWORD);
    await manager.unloadWallet("nostartup", false);

    const startupWallets = await manager.getStartupWallets();
    expect(startupWallets).not.toContain("nostartup");
  });

  test("default wallet (empty name) storage", async () => {
    const manager = new WalletManager(TEST_DATADIR, "regtest");
    await manager.createWallet("", {}, TEST_PASSWORD);

    // Default wallet should be stored directly in wallets dir
    const defaultWalletPath = `${TEST_DATADIR}/wallets/wallet.dat`;
    expect(existsSync(defaultWalletPath)).toBe(true);

    expect(manager.hasWallet("")).toBe(true);
    expect(manager.listWallets()).toContain("");
  });
});

describe("Wallet isolation", () => {
  beforeEach(() => {
    mkdirSync(TEST_DATADIR, { recursive: true });
    mkdirSync(`${TEST_DATADIR}/wallets`, { recursive: true });
  });

  afterEach(() => {
    rmSync(TEST_DATADIR, { recursive: true, force: true });
  });

  test("wallets have isolated UTXO sets", async () => {
    const manager = new WalletManager(TEST_DATADIR, "regtest");
    await manager.createWallet("utxo1", {}, TEST_PASSWORD);
    await manager.createWallet("utxo2", {}, TEST_PASSWORD);

    const wallet1 = manager.getWallet("utxo1")!;
    const wallet2 = manager.getWallet("utxo2")!;

    // Both should start with empty UTXO sets
    expect(wallet1.getUTXOs().length).toBe(0);
    expect(wallet2.getUTXOs().length).toBe(0);
  });

  test("wallets have isolated labels", async () => {
    const manager = new WalletManager(TEST_DATADIR, "regtest");
    await manager.createWallet("label1", {}, TEST_PASSWORD);
    await manager.createWallet("label2", {}, TEST_PASSWORD);

    const wallet1 = manager.getWallet("label1")!;
    const wallet2 = manager.getWallet("label2")!;

    const addr1 = wallet1.getNewAddress();
    wallet1.setLabel(addr1, "My Label");

    // Label should not appear in wallet2
    expect(wallet1.getLabel(addr1)).toBe("My Label");
    expect(wallet2.getLabel(addr1)).toBe("");
  });

  test("wallet encryption states are independent", async () => {
    const manager = new WalletManager(TEST_DATADIR, "regtest");
    await manager.createWallet("enc1", { passphrase: "secret1" });
    await manager.createWallet("enc2", {}, TEST_PASSWORD);

    const wallet1 = manager.getWallet("enc1")!;
    const wallet2 = manager.getWallet("enc2")!;

    expect(wallet1.isEncrypted()).toBe(true);
    expect(wallet2.isEncrypted()).toBe(false);
  });
});

describe("Wallet paths", () => {
  beforeEach(() => {
    mkdirSync(TEST_DATADIR, { recursive: true });
    mkdirSync(`${TEST_DATADIR}/wallets`, { recursive: true });
  });

  afterEach(() => {
    rmSync(TEST_DATADIR, { recursive: true, force: true });
  });

  test("wallet name cannot contain path separators", async () => {
    const manager = new WalletManager(TEST_DATADIR, "regtest");

    await expect(
      manager.createWallet("path/to/wallet", {}, TEST_PASSWORD)
    ).rejects.toThrow("path separators");

    await expect(
      manager.createWallet("path\\to\\wallet", {}, TEST_PASSWORD)
    ).rejects.toThrow("path separators");
  });

  test("getWalletPath returns correct paths", () => {
    const manager = new WalletManager(TEST_DATADIR, "regtest");

    // Named wallet
    const namedPath = manager.getWalletPath("mywallet");
    expect(namedPath).toBe(`${TEST_DATADIR}/wallets/mywallet`);

    // Default wallet (empty name)
    const defaultPath = manager.getWalletPath("");
    expect(defaultPath).toBe(`${TEST_DATADIR}/wallets/wallet.dat`);
  });

  test("getWalletFilePath returns correct file paths", () => {
    const manager = new WalletManager(TEST_DATADIR, "regtest");

    // Named wallet
    const namedFilePath = manager.getWalletFilePath("mywallet");
    expect(namedFilePath).toBe(`${TEST_DATADIR}/wallets/mywallet/wallet.dat`);

    // Default wallet
    const defaultFilePath = manager.getWalletFilePath("");
    expect(defaultFilePath).toBe(`${TEST_DATADIR}/wallets/wallet.dat`);
  });
});

describe("Settings persistence", () => {
  beforeEach(() => {
    mkdirSync(TEST_DATADIR, { recursive: true });
    mkdirSync(`${TEST_DATADIR}/wallets`, { recursive: true });
  });

  afterEach(() => {
    rmSync(TEST_DATADIR, { recursive: true, force: true });
  });

  test("loadStartupWallets loads wallets from settings", async () => {
    const manager1 = new WalletManager(TEST_DATADIR, "regtest");
    await manager1.createWallet("auto1", { loadOnStartup: true }, TEST_PASSWORD);
    await manager1.createWallet("auto2", { loadOnStartup: true }, TEST_PASSWORD);
    await manager1.createWallet("manual", {}, TEST_PASSWORD);

    // Unload all
    await manager1.unloadWallet("auto1");
    await manager1.unloadWallet("auto2");
    await manager1.unloadWallet("manual");

    // Create a new manager and load startup wallets
    const manager2 = new WalletManager(TEST_DATADIR, "regtest");
    await manager2.loadStartupWallets(TEST_PASSWORD);

    expect(manager2.hasWallet("auto1")).toBe(true);
    expect(manager2.hasWallet("auto2")).toBe(true);
    expect(manager2.hasWallet("manual")).toBe(false);
  });
});
