/**
 * walletpassphrase / walletpassphrasechange must check the passphrase even
 * when the wallet is already unlocked.
 *
 * unlockWallet() used to return early on an unlocked wallet (only resetting
 * the timeout), and changePassphrase() only checked the old passphrase when
 * the wallet was locked. So on an unlocked wallet, walletpassphrase accepted
 * any passphrase, and walletpassphrasechange let anyone with RPC access
 * replace the passphrase without knowing it.
 *
 * Core: CWallet::Unlock always decrypts a master key with the given
 * passphrase and fails on mismatch; CWallet::ChangeWalletPassphrase checks
 * the old passphrase the same way whatever the lock state. Both RPCs then
 * report RPC_WALLET_PASSPHRASE_INCORRECT (-14)
 * (wallet/wallet.cpp, wallet/rpc/encrypt.cpp).
 */

import { describe, expect, test, beforeEach, afterEach } from "bun:test";
import { rmSync, mkdirSync, mkdtempSync } from "fs";
import * as os from "os";
import * as nodePath from "path";
import { WalletManager, type Wallet } from "../wallet/wallet";
import { RPCServer, type RPCServerDeps, RPCErrorCodes } from "../rpc/server.js";
import { startTestRpc } from "../test/rpc-listen.js";
import { REGTEST } from "../consensus/params.js";

describe("cffix: passphrase checked on an unlocked wallet", () => {
  let server: RPCServer;
  let port: number;
  let caseDir: string;
  let wallet: Wallet;

  beforeEach(async () => {
    caseDir = mkdtempSync(nodePath.join(os.tmpdir(), "hotbuns-cffix-walletpassphrase-"));
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
    try {
      wallet.lockWallet();
    } catch {
      /* not encrypted */
    }
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

  test("walletpassphrase with a wrong passphrase on an unlocked wallet is -14", async () => {
    const ok = await rpc("walletpassphrase", ["pw", 60]);
    expect(ok.error ?? null).toBeNull();
    expect(wallet.isLocked()).toBe(false);

    const r = await rpc("walletpassphrase", ["wrong", 60]);
    expect(r.error?.code).toBe(RPCErrorCodes.WALLET_PASSPHRASE_INCORRECT);
    // A failed check does not lock the wallet (Core leaves it as it was).
    expect(wallet.isLocked()).toBe(false);

    // The right passphrase still works on an unlocked wallet.
    const again = await rpc("walletpassphrase", ["pw", 60]);
    expect(again.error ?? null).toBeNull();
  });

  test("walletpassphrasechange with a wrong old passphrase on an unlocked wallet is -14 and changes nothing", async () => {
    const ok = await rpc("walletpassphrase", ["pw", 60]);
    expect(ok.error ?? null).toBeNull();

    const r = await rpc("walletpassphrasechange", ["wrong", "new"]);
    expect(r.error?.code).toBe(RPCErrorCodes.WALLET_PASSPHRASE_INCORRECT);
    expect(wallet.isLocked()).toBe(false);

    // The passphrase was not replaced: "pw" still unlocks, "new" does not.
    wallet.lockWallet();
    const bad = await rpc("walletpassphrase", ["new", 60]);
    expect(bad.error?.code).toBe(RPCErrorCodes.WALLET_PASSPHRASE_INCORRECT);
    expect(wallet.isLocked()).toBe(true);
    const good = await rpc("walletpassphrase", ["pw", 60]);
    expect(good.error ?? null).toBeNull();
  });

  test("walletpassphrasechange with the right old passphrase on an unlocked wallet works and keeps it unlocked", async () => {
    expect((await rpc("walletpassphrase", ["pw", 60])).error ?? null).toBeNull();

    const r = await rpc("walletpassphrasechange", ["pw", "new"]);
    expect(r.error ?? null).toBeNull();
    expect(wallet.isLocked()).toBe(false);

    wallet.lockWallet();
    expect((await rpc("walletpassphrase", ["pw", 60])).error?.code).toBe(
      RPCErrorCodes.WALLET_PASSPHRASE_INCORRECT
    );
    expect((await rpc("walletpassphrase", ["new", 60])).error ?? null).toBeNull();
  });

  test("walletpassphrasechange on a locked wallet: wrong old is -14, right old works and leaves it locked", async () => {
    expect(wallet.isLocked()).toBe(true);
    const bad = await rpc("walletpassphrasechange", ["wrong", "new"]);
    expect(bad.error?.code).toBe(RPCErrorCodes.WALLET_PASSPHRASE_INCORRECT);
    expect(wallet.isLocked()).toBe(true);

    const good = await rpc("walletpassphrasechange", ["pw", "new"]);
    expect(good.error ?? null).toBeNull();
    expect(wallet.isLocked()).toBe(true);
    expect((await rpc("walletpassphrase", ["new", 60])).error ?? null).toBeNull();
  });
});
