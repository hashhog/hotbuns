/**
 * A locked wallet must never derive keys from its cleared master key.
 *
 * lockWallet() / encryptWallet() zero masterKey.key and masterKey.chainCode in
 * place. getNewAddress() / getChangeAddress() used to call deriveKey() with that
 * zeroed master once the pre-derived pool ran out, handing out addresses whose
 * private keys anyone can compute (BIP-32 from key=0, chaincode=0).
 *
 * Core: DescriptorScriptPubKeyMan::TopUp cannot derive hardened keys while
 * locked, so GetNewDestination fails with "Keypool ran out"
 * (RPC_WALLET_KEYPOOL_RAN_OUT, -12) once the pool is used up
 * (wallet/scriptpubkeyman.cpp, wallet/rpc/addresses.cpp).
 *
 * The all-zero-master address is computed here independently of the wallet's
 * own derivation code.
 */

import { describe, expect, test, beforeEach, afterEach } from "bun:test";
import { rmSync, mkdirSync, mkdtempSync } from "fs";
import * as os from "os";
import * as nodePath from "path";
import { hmac } from "@noble/hashes/hmac.js";
import { sha512 } from "@noble/hashes/sha2.js";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { Wallet, WalletManager, type WalletConfig } from "../wallet/wallet";
import { RPCServer, type RPCServerDeps, RPCErrorCodes } from "../rpc/server.js";
import { startTestRpc } from "../test/rpc-listen.js";
import { REGTEST } from "../consensus/params.js";
import { pubkeyToP2WPKH } from "../address/encoding";

const TEST_DATADIR = "/tmp/hotbuns-cffix-locked-zero-master-test";
const TEST_MNEMONIC =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const GAP = 20; // Wallet.ADDRESS_GAP
const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;

function config(): WalletConfig {
  return { datadir: TEST_DATADIR, network: "regtest" };
}

function be32(k: bigint): Buffer {
  return Buffer.from(k.toString(16).padStart(64, "0"), "hex");
}

/** Independent BIP-32 CKDpriv from key=0, chaincode=0 along `path`. */
function zeroMasterP2WPKH(path: string): string {
  let k = 0n;
  let c = Buffer.alloc(32);
  for (const part of path.slice(2).split("/")) {
    const hardened = part.endsWith("'");
    let index = parseInt(hardened ? part.slice(0, -1) : part, 10);
    if (hardened) index += 0x80000000;
    const data = Buffer.alloc(37);
    if (hardened) {
      data[0] = 0;
      be32(k).copy(data, 1);
    } else {
      Buffer.from(secp256k1.getPublicKey(be32(k), true)).copy(data, 0);
    }
    data.writeUInt32BE(index, 33);
    const I = Buffer.from(hmac(sha512, c, data));
    k = (BigInt("0x" + I.subarray(0, 32).toString("hex")) + k) % N;
    c = I.subarray(32);
  }
  return pubkeyToP2WPKH(Buffer.from(secp256k1.getPublicKey(be32(k), true)), "regtest");
}

/** Next address, or the error it raised. */
function next(fn: () => string): { address?: string; error?: Error } {
  try {
    return { address: fn() };
  } catch (e) {
    return { error: e as Error };
  }
}

describe("cffix: locked wallet never derives from the zeroed master", () => {
  beforeEach(() => mkdirSync(TEST_DATADIR, { recursive: true }));
  afterEach(() => rmSync(TEST_DATADIR, { recursive: true, force: true }));

  test("getNewAddress past the pool while locked does not use the zero master", async () => {
    const wallet = Wallet.create(config(), TEST_MNEMONIC);
    await wallet.encryptWallet("pw");
    expect(wallet.isLocked()).toBe(true);

    const pooled: string[] = [];
    for (let i = 0; i < GAP; i++) pooled.push(wallet.getNewAddress("bech32"));

    const zero = zeroMasterP2WPKH(`m/84'/1'/0'/0/${GAP}`);
    const r = next(() => wallet.getNewAddress("bech32"));
    expect(r.address).not.toBe(zero);
    if (r.error) {
      expect(r.error.message).toContain("Keypool ran out");
    }

    // The pool keys handed out while locked are the wallet's real keys.
    await wallet.unlockWallet("pw", 0);
    const seen = new Set(pooled);
    expect(seen.size).toBe(GAP);
    for (const a of pooled) {
      expect(wallet.hasAddress(a)).toBe(true);
      expect(a).not.toBe(zeroMasterP2WPKH(`m/84'/1'/0'/0/${pooled.indexOf(a)}`));
    }
    if (r.address) {
      // If an address was handed out, it is the one the unlocked wallet owns.
      expect(wallet.hasAddress(r.address)).toBe(true);
    } else {
      // Locked failure did not consume an index: unlocked, the next address
      // is index GAP from the real seed, not from the zero master.
      const a = wallet.getNewAddress("bech32");
      expect(a).not.toBe(zero);
      expect(seen.has(a)).toBe(false);
    }
  });

  test("getChangeAddress past the pool while locked does not use the zero master", async () => {
    const wallet = Wallet.create(config(), TEST_MNEMONIC);
    await wallet.encryptWallet("pw");
    for (let i = 0; i < GAP; i++) wallet.getChangeAddress("bech32");

    const zero = zeroMasterP2WPKH(`m/84'/1'/0'/1/${GAP}`);
    const r = next(() => wallet.getChangeAddress("bech32"));
    expect(r.address).not.toBe(zero);
    if (r.error) {
      expect(r.error.message).toContain("Keypool ran out");
    }
  });

  test("relocked wallet (walletlock) does not use the zero master either", async () => {
    const wallet = Wallet.create(config(), TEST_MNEMONIC);
    await wallet.encryptWallet("pw");
    await wallet.unlockWallet("pw", 0);
    wallet.lockWallet();
    for (let i = 0; i < GAP; i++) wallet.getNewAddress("bech32");
    const zero = zeroMasterP2WPKH(`m/84'/1'/0'/0/${GAP}`);
    const r = next(() => wallet.getNewAddress("bech32"));
    expect(r.address).not.toBe(zero);
    if (r.error) {
      expect(r.error.message).toContain("Keypool ran out");
    }
  });

  test("independent zero-master derivation is the instrument the test claims", () => {
    // Negative control for the oracle: it differs from a real seed's address
    // at the same path, and is deterministic.
    const wallet = Wallet.create(config(), TEST_MNEMONIC);
    const real = wallet.getNewAddress("bech32");
    expect(real).not.toBe(zeroMasterP2WPKH("m/84'/1'/0'/0/0"));
    expect(zeroMasterP2WPKH("m/84'/1'/0'/0/0")).toBe(zeroMasterP2WPKH("m/84'/1'/0'/0/0"));
    expect(zeroMasterP2WPKH("m/84'/1'/0'/0/0").startsWith("bcrt1q")).toBe(true);
  });
});

// RPC: getnewaddress past the pool on a locked wallet is Core's -12.
describe("cffix: getnewaddress RPC on a locked wallet", () => {
  let server: RPCServer;
  let port: number;
  let caseDir: string;

  beforeEach(async () => {
    caseDir = mkdtempSync(nodePath.join(os.tmpdir(), "hotbuns-cffix-locked-rpc-"));
    mkdirSync(`${caseDir}/wallets`, { recursive: true });
    const manager = new WalletManager(caseDir, "regtest");
    await manager.createWallet("default", {});
    const wallet = manager.getWallet("default")!;
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

  test("pool addresses are served, then -12 Keypool ran out, never the zero-master address", async () => {
    for (let i = 0; i < GAP; i++) {
      const r = await rpc("getnewaddress", []);
      expect(r.error ?? null).toBeNull();
      expect(r.result).not.toBe(zeroMasterP2WPKH(`m/84'/1'/0'/0/${i}`));
    }
    const r = await rpc("getnewaddress", []);
    expect(r.result ?? null).not.toBe(zeroMasterP2WPKH(`m/84'/1'/0'/0/${GAP}`));
    expect(r.error?.code).toBe(RPCErrorCodes.WALLET_KEYPOOL_RAN_OUT);
    expect(r.error?.message).toBe("Error: Keypool ran out, please call keypoolrefill first");
  });
});
