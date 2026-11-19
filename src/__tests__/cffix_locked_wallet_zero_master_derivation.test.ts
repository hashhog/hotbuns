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
import { pbkdf2 } from "@noble/hashes/pbkdf2.js";
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

/** Independent BIP-32 CKDpriv from (k, c) along `path`, as a P2WPKH address. */
function ckdP2WPKH(k: bigint, c: Buffer, path: string): string {
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

/** Address from the all-zero master (key=0, chaincode=0): what a cleared master gives. */
function zeroMasterP2WPKH(path: string): string {
  return ckdP2WPKH(0n, Buffer.alloc(32), path);
}

/** BIP-32 master from a seed: HMAC-SHA512("Bitcoin seed", seed). */
function seedP2WPKH(seed: Buffer, path: string): string {
  const I = Buffer.from(hmac(sha512, Buffer.from("Bitcoin seed"), seed));
  return ckdP2WPKH(BigInt("0x" + I.subarray(0, 32).toString("hex")), I.subarray(32), path);
}

/** The wallet's real key at `path`: BIP-39 seed of TEST_MNEMONIC, no passphrase. */
function realP2WPKH(path: string): string {
  const seed = Buffer.from(
    pbkdf2(sha512, Buffer.from(TEST_MNEMONIC), Buffer.from("mnemonic"), { c: 2048, dkLen: 64 })
  );
  return seedP2WPKH(seed, path);
}

const recv = (i: number) => `m/84'/1'/0'/0/${i}`;
const chg = (i: number) => `m/84'/1'/0'/1/${i}`;

/** Next address, or the error it raised. */
function next(fn: () => string): { address?: string; error?: Error } {
  try {
    return { address: fn() };
  } catch (e) {
    return { error: e as Error };
  }
}

/**
 * Each locked call must either fail like Core ("Keypool ran out") or return
 * the wallet's real key for that index. Checked for the pool and one past it.
 */
function expectOnlyRealOrRanOut(fn: () => string, path: (i: number) => string): number {
  let served = 0;
  for (let i = 0; i <= GAP; i++) {
    const r = next(fn);
    if (r.error) {
      expect(r.error.message).toContain("Keypool ran out");
      break;
    }
    expect(r.address).not.toBe(zeroMasterP2WPKH(path(i)));
    expect(r.address).toBe(realP2WPKH(path(i)));
    served++;
  }
  return served;
}

/** A wallet on TEST_MNEMONIC's seed, encrypted (and so locked) with "pw". */
async function lockedWallet(): Promise<Wallet> {
  const wallet = Wallet.create(config(), TEST_MNEMONIC);
  // Keep the mnemonic seed (as WalletManager.createWallet with a passphrase
  // does) so the real keys can be computed independently.
  await wallet.encryptWallet("pw", { rotateSeed: false });
  expect(wallet.isLocked()).toBe(true);
  return wallet;
}

describe("cffix: locked wallet never derives from the zeroed master", () => {
  beforeEach(() => mkdirSync(TEST_DATADIR, { recursive: true }));
  afterEach(() => rmSync(TEST_DATADIR, { recursive: true, force: true }));

  test("getNewAddress past the pool while locked does not use the zero master", async () => {
    const wallet = await lockedWallet();
    const served = expectOnlyRealOrRanOut(() => wallet.getNewAddress("bech32"), recv);
    // The pre-derived pool is served while locked; past it, Core fails.
    expect(served).toBe(GAP);

    // The failure did not consume an index: unlocked, the next address is
    // the real key at index GAP.
    await wallet.unlockWallet("pw", 0);
    expect(wallet.getNewAddress("bech32")).toBe(realP2WPKH(recv(GAP)));
  });

  test("getChangeAddress past the pool while locked does not use the zero master", async () => {
    const wallet = await lockedWallet();
    const served = expectOnlyRealOrRanOut(() => wallet.getChangeAddress("bech32"), chg);
    expect(served).toBe(GAP);
  });

  test("relocked wallet (walletlock) does not use the zero master either", async () => {
    const wallet = await lockedWallet();
    await wallet.unlockWallet("pw", 0);
    wallet.lockWallet();
    expect(wallet.isLocked()).toBe(true);
    const served = expectOnlyRealOrRanOut(() => wallet.getNewAddress("bech32"), recv);
    expect(served).toBe(GAP);
  });

  test("encrypted wallet reloaded from disk (locked) does not derive from an empty seed", async () => {
    const wallet = await lockedWallet();
    await wallet.save("filepw");
    const loaded = await Wallet.load(config(), "filepw");
    expect(loaded.isLocked()).toBe(true);
    // Base derived a master from the empty on-disk seed: HMAC("Bitcoin seed", "").
    const emptySeed = seedP2WPKH(Buffer.alloc(0), recv(0));
    const r = next(() => loaded.getNewAddress("bech32"));
    expect(r.address).not.toBe(emptySeed);
    expectOnlyRealOrRanOut(() => loaded.getChangeAddress("bech32"), chg);
    if (r.error) {
      expect(r.error.message).toContain("Keypool ran out");
    } else {
      expect(r.address).toBe(realP2WPKH(recv(0)));
    }
    // Unlocking restores derivation from the real seed.
    await loaded.unlockWallet("pw", 0);
    expect(loaded.getNewAddress("bech32")).toBe(realP2WPKH(recv(0)));
  });

  test("independent oracles are the instruments the tests claim (control)", () => {
    // The real-seed oracle reproduces an unlocked wallet's addresses; the
    // zero- and empty-seed oracles do not.
    const wallet = Wallet.create(config(), TEST_MNEMONIC);
    const a0 = wallet.getNewAddress("bech32");
    const c0 = wallet.getChangeAddress("bech32");
    expect(a0).toBe(realP2WPKH(recv(0)));
    expect(c0).toBe(realP2WPKH(chg(0)));
    expect(a0).not.toBe(zeroMasterP2WPKH(recv(0)));
    expect(a0).not.toBe(seedP2WPKH(Buffer.alloc(0), recv(0)));
    expect(zeroMasterP2WPKH(recv(0)).startsWith("bcrt1q")).toBe(true);
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
