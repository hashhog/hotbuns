/**
 * Locking a wallet must leave no plaintext private keys in memory, and the
 * key-using RPCs (dumpprivkey, signmessage) must require an unlocked wallet.
 *
 * lockWallet() / encryptWallet() used to clear only the seed and the master
 * key. Every derived key (pregenerateAddresses, rotateSeed's retired keys)
 * and every imported key (restoreImportedKeys) kept its plaintext
 * `privateKey` in the keyring, and dumpprivkey / signmessage read it there
 * with no lock check, so both worked on a locked wallet.
 *
 * Core: CWallet::Lock (wallet/wallet.cpp) clears vMasterKey and keys exist
 * only encrypted while locked; dumpprivkey and signmessage call
 * EnsureWalletIsUnlocked, which fails with RPC_WALLET_UNLOCK_NEEDED (-13)
 * "Error: Please enter the wallet passphrase with walletpassphrase first."
 */

import { describe, expect, test, beforeEach, afterEach } from "bun:test";
import { rmSync, mkdirSync, mkdtempSync } from "fs";
import * as os from "os";
import * as nodePath from "path";
import { Wallet, WalletManager, type WalletKey } from "../wallet/wallet";
import { AddressType } from "../address/encoding";
import { RPCServer, type RPCServerDeps, RPCErrorCodes } from "../rpc/server.js";
import { startTestRpc } from "../test/rpc-listen.js";
import { REGTEST } from "../consensus/params.js";
import { privateKeyToPublicKey } from "../crypto/primitives.js";
import { base58CheckDecode } from "../address/encoding";

const UNLOCK_MSG = "Error: Please enter the wallet passphrase with walletpassphrase first.";
const IMPORTED_PRIV = Buffer.from(
  "0b5a1c3d2e4f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9",
  "hex"
);

const isZero = (b: Buffer) => b.every((x) => x === 0);
/** Keys whose private key is still present (non-empty and not all zero). */
const plaintextKeys = (w: Wallet): WalletKey[] =>
  w.listAddresses().filter((k) => k.privateKey.length > 0 && !isZero(k.privateKey));

describe("cffix: locked wallet holds no plaintext private keys", () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(nodePath.join(os.tmpdir(), "hotbuns-cffix-lock-wipe-"));
  });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  test("encryptWallet wipes derived, retired and imported keys in place", async () => {
    const w = Wallet.create({ datadir: dir, network: "regtest" });
    w.getNewAddress("legacy");
    w.addImportedKey(IMPORTED_PRIV, AddressType.P2WPKH);
    // Hold references to the buffers that existed before encryption.
    const before = w.listAddresses().map((k) => k.privateKey);
    expect(before.length).toBeGreaterThan(0);
    expect(before.some((b) => !isZero(b))).toBe(true);

    await w.encryptWallet("pw");
    expect(w.isLocked()).toBe(true);
    expect(plaintextKeys(w).map((k) => k.address)).toEqual([]);
    // The old buffers are zeroed, not just dropped.
    for (const b of before) expect(isZero(b)).toBe(true);
  });

  test("walletlock wipes every key restored by unlock; unlock brings them back", async () => {
    const w = Wallet.create({ datadir: dir, network: "regtest" });
    w.getNewAddress("legacy"); // becomes a retired key after rotation
    w.addImportedKey(IMPORTED_PRIV, AddressType.P2WPKH);
    await w.encryptWallet("pw");
    await w.unlockWallet("pw", 0);

    const unlocked = plaintextKeys(w);
    expect(unlocked.some((k) => k.retired)).toBe(true);
    expect(unlocked.some((k) => k.path === "imported")).toBe(true);
    expect(unlocked.some((k) => k.path !== "imported" && !k.retired)).toBe(true);
    const buffers = unlocked.map((k) => k.privateKey);
    const addresses = w.listAddresses().map((k) => k.address).sort();

    w.lockWallet();
    expect(plaintextKeys(w).map((k) => k.address)).toEqual([]);
    for (const b of buffers) expect(isZero(b)).toBe(true);
    // Addresses stay known (ownership/balance tracking needs them).
    expect(w.listAddresses().map((k) => k.address).sort()).toEqual(addresses);

    // Unlock again: every key is back and matches its public key.
    await w.unlockWallet("pw", 0);
    const again = w.listAddresses();
    expect(again.map((k) => k.address).sort()).toEqual(addresses);
    for (const k of again) {
      expect(k.privateKey.length).toBe(32);
      expect(privateKeyToPublicKey(k.privateKey, true).equals(k.publicKey)).toBe(true);
    }
  });
});

describe("cffix: dumpprivkey / signmessage require an unlocked wallet (-13)", () => {
  let server: RPCServer;
  let port: number;
  let caseDir: string;
  let wallet: Wallet;

  beforeEach(async () => {
    caseDir = mkdtempSync(nodePath.join(os.tmpdir(), "hotbuns-cffix-lock-wipe-rpc-"));
    mkdirSync(`${caseDir}/wallets`, { recursive: true });
    const manager = new WalletManager(caseDir, "regtest");
    await manager.createWallet("default", {});
    wallet = manager.getWallet("default")!;
    await wallet.encryptWallet("pw");
    const chain = {
      getBestBlock: () => ({ hash: Buffer.alloc(32, 0), height: 0, chainWork: 0n }),
      getUTXOManager: () => ({ async getUTXOAsync() { return null; } }),
    };
    const deps: RPCServerDeps = {
      chainState: chain as any,
      mempool: {} as any,
      peerManager: { getConnectedPeers: () => [], broadcast() {} } as any,
      feeEstimator: {} as any,
      headerSync: {} as any,
      db: {} as any,
      params: REGTEST,
      walletManager: manager,
    };
    const started = startTestRpc(deps);
    server = started.server;
    port = started.port;
  });

  afterEach(() => {
    server.stop();
    try {
      rmSync(caseDir, { recursive: true, force: true });
    } catch {
      /* persist may still be flushing */
    }
  });

  async function rpc(method: string, params: unknown[] = []): Promise<any> {
    const r = await fetch(`http://127.0.0.1:${port}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
    });
    return r.json();
  }

  test("locked: both fail with -13; unlocked: both work (control)", async () => {
    expect((await rpc("walletpassphrase", ["pw", 600])).error ?? null).toBeNull();
    const addr = (await rpc("getnewaddress", ["", "legacy"])).result as string;
    expect(typeof addr).toBe("string");

    // Control: unlocked, both RPCs work and the WIF is the address's key.
    const wif = await rpc("dumpprivkey", [addr]);
    expect(wif.error ?? null).toBeNull();
    const decoded = base58CheckDecode(wif.result);
    const priv = decoded.hash.subarray(0, 32) as Buffer;
    expect(privateKeyToPublicKey(priv, true).equals(wallet.getKey(addr)!.publicKey)).toBe(true);
    const sig = await rpc("signmessage", [addr, "hello"]);
    expect(sig.error ?? null).toBeNull();
    expect(typeof sig.result).toBe("string");

    expect((await rpc("walletlock", [])).error ?? null).toBeNull();
    expect(wallet.isLocked()).toBe(true);

    const d = await rpc("dumpprivkey", [addr]);
    expect(d.result ?? null).toBeNull();
    expect(d.error?.code).toBe(RPCErrorCodes.WALLET_UNLOCK_NEEDED);
    expect(d.error?.message).toBe(UNLOCK_MSG);

    const s = await rpc("signmessage", [addr, "hello"]);
    expect(s.result ?? null).toBeNull();
    expect(s.error?.code).toBe(RPCErrorCodes.WALLET_UNLOCK_NEEDED);
    expect(s.error?.message).toBe(UNLOCK_MSG);

    // Unlock again: the same WIF comes back.
    expect((await rpc("walletpassphrase", ["pw", 600])).error ?? null).toBeNull();
    expect((await rpc("dumpprivkey", [addr])).result).toBe(wif.result);
  });

  test("freshly encrypted (never unlocked): both fail with -13", async () => {
    const addr = (await rpc("getnewaddress", ["", "legacy"])).result as string;
    expect(typeof addr).toBe("string");
    const d = await rpc("dumpprivkey", [addr]);
    expect(d.error?.code).toBe(RPCErrorCodes.WALLET_UNLOCK_NEEDED);
    const s = await rpc("signmessage", [addr, "hello"]);
    expect(s.error?.code).toBe(RPCErrorCodes.WALLET_UNLOCK_NEEDED);
  });
});
