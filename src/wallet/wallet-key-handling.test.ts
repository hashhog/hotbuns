/**
 * Security audit 2026-10-29 (audits/security/hotbuns-2026-10-29.md), H6 + H7.
 *
 * H6: every wallet.dat is wrapped with the fixed storage key "hotbuns", so for
 *     an unencrypted wallet the seed is plaintext to anyone who can read the
 *     file -- and the file was created 0644. Core keeps unencrypted wallets
 *     honestly unencrypted and relies on file mode 0600. `encryptwallet` and
 *     `walletpassphrasechange` changed memory only: wallet.dat kept the
 *     plaintext seed (or the old passphrase) until an unrelated flush, so a
 *     crash after "Wallet encrypted" silently reverted the wallet. Core writes
 *     the encrypted keys before EncryptWallet returns (wallet/wallet.cpp:818-886).
 *
 * H7: `importprivkey` keys lived only in memory; save() had no field for them
 *     and load() rebuilt keys from the seed alone, so after any restart the
 *     imported key's coins were unspendable. Core writes imported keys to the
 *     wallet DB, encrypted when the wallet is encrypted.
 *
 * Everything here runs on regtest / fresh temp datadirs.
 */
import { describe, it, expect, beforeAll, afterAll } from "bun:test";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { Wallet, type WalletConfig } from "./wallet.js";
import { AddressType, base58CheckEncode } from "../address/encoding.js";

const STORAGE_PW = "hotbuns";
const REPO = path.resolve(import.meta.dir, "../..");
let nextPort = 43000 + (process.pid % 1500) * 4;

// A fixed, valid secp256k1 scalar (well below the curve order).
const IMPORT_PRIV = Buffer.from(
  "1e99423a4ed27608a15a2616a2b0e9e52ced330ac530edcc32c8ffc6a526aedd",
  "hex",
);

function tmpDir(tag: string): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), `hotbuns-h6h7-${tag}-`));
}

function cfg(datadir: string): WalletConfig {
  return { datadir, network: "regtest" };
}

/** Decrypt the fixed-key outer layer of wallet.dat and return its JSON body. */
async function rawWalletJson(datadir: string): Promise<string> {
  const { pbkdf2 } = await import("@noble/hashes/pbkdf2.js");
  const { sha256 } = await import("@noble/hashes/sha2.js");
  const { gcm } = await import("@noble/ciphers/aes.js");
  const f = JSON.parse(fs.readFileSync(path.join(datadir, "wallet.dat"), "utf8"));
  const key = pbkdf2(sha256, Buffer.from(STORAGE_PW), Buffer.from(f.salt, "hex"), {
    c: 100000,
    dkLen: 32,
  });
  const pt = gcm(key, Buffer.from(f.iv, "hex")).decrypt(Buffer.from(f.ciphertext, "hex"));
  return Buffer.from(pt).toString("utf8");
}

// ---------------------------------------------------------------------------
// H6 -- file mode
// ---------------------------------------------------------------------------

describe("H6: wallet.dat is owner-only", () => {
  it("save() creates wallet.dat with mode 0600", async () => {
    const dir = tmpDir("mode");
    try {
      const w = Wallet.create(cfg(dir));
      await w.save(STORAGE_PW);
      const mode = fs.statSync(path.join(dir, "wallet.dat")).mode & 0o777;
      expect(mode.toString(8)).toBe("600");
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("a re-save over an existing 0644 file also ends 0600", async () => {
    const dir = tmpDir("mode2");
    try {
      const w = Wallet.create(cfg(dir));
      await w.save(STORAGE_PW);
      fs.chmodSync(path.join(dir, "wallet.dat"), 0o644);
      await w.save(STORAGE_PW);
      const mode = fs.statSync(path.join(dir, "wallet.dat")).mode & 0o777;
      expect(mode.toString(8)).toBe("600");
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

// ---------------------------------------------------------------------------
// H7 -- imported keys survive save -> load
// ---------------------------------------------------------------------------

describe("H7: imported private keys are persisted", () => {
  it("unencrypted wallet: importprivkey key round-trips through save/load", async () => {
    const dir = tmpDir("imp");
    try {
      const w = Wallet.create(cfg(dir));
      const addr = w.addImportedKey(IMPORT_PRIV, AddressType.P2WPKH, "lbl");
      await w.save(STORAGE_PW);

      const loaded = await Wallet.load(cfg(dir), STORAGE_PW);
      const key = loaded.getKey(addr);
      expect(key).toBeDefined();
      expect(key!.path).toBe("imported");
      expect(key!.privateKey.toString("hex")).toBe(IMPORT_PRIV.toString("hex"));
      expect(loaded.hasAddress(addr)).toBe(true);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("encrypted wallet: the key is on disk only in encrypted form and comes back on unlock", async () => {
    const dir = tmpDir("impenc");
    try {
      const w = Wallet.create(cfg(dir));
      await w.encryptWallet("bob");
      await w.unlockWallet("bob", 0);
      const addr = w.addImportedKey(IMPORT_PRIV, AddressType.P2WPKH);
      w.lockWallet();
      await w.save(STORAGE_PW);

      // The fixed-key layer must not expose the imported secret.
      const raw = await rawWalletJson(dir);
      expect(raw.includes(IMPORT_PRIV.toString("hex"))).toBe(false);

      const loaded = await Wallet.load(cfg(dir), STORAGE_PW);
      expect(loaded.isLocked()).toBe(true);
      expect(loaded.getKey(addr)?.privateKey).toBeUndefined();

      await expect(loaded.unlockWallet("wrong", 0)).rejects.toThrow();
      await loaded.unlockWallet("bob", 0);
      expect(loaded.getKey(addr)?.privateKey.toString("hex")).toBe(IMPORT_PRIV.toString("hex"));
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("encrypting a wallet that already holds an imported key encrypts that key too", async () => {
    const dir = tmpDir("impthenenc");
    try {
      const w = Wallet.create(cfg(dir));
      const addr = w.addImportedKey(IMPORT_PRIV, AddressType.P2WPKH);
      await w.encryptWallet("bob");
      await w.save(STORAGE_PW);
      expect((await rawWalletJson(dir)).includes(IMPORT_PRIV.toString("hex"))).toBe(false);

      // ... and still survives a passphrase change.
      await w.changePassphrase("bob", "carol");
      await w.save(STORAGE_PW);
      const loaded = await Wallet.load(cfg(dir), STORAGE_PW);
      await loaded.unlockWallet("carol", 0);
      expect(loaded.getKey(addr)?.privateKey.toString("hex")).toBe(IMPORT_PRIV.toString("hex"));
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("importing into a locked encrypted wallet is refused (Core: EnsureWalletIsUnlocked)", async () => {
    const dir = tmpDir("implocked");
    try {
      const w = Wallet.create(cfg(dir));
      await w.encryptWallet("bob");
      expect(() => w.addImportedKey(IMPORT_PRIV, AddressType.P2WPKH)).toThrow(/walletpassphrase/);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

// ---------------------------------------------------------------------------
// End to end on a regtest node: the RPC must have written the file before it
// replies. Each check reads wallet.dat immediately after the reply, or after
// SIGKILL -- never after a clean shutdown, which would flush anyway.
// ---------------------------------------------------------------------------

type Node = { proc: ReturnType<typeof Bun.spawn>; datadir: string; rpcPort: number; auth: string };

async function startRegtestNode(): Promise<Node> {
  const datadir = tmpDir("node");
  const rpcPort = nextPort++;
  const p2pPort = nextPort++;
  const proc = Bun.spawn(
    [
      process.execPath,
      "run",
      path.join(REPO, "src/index.ts"),
      "--network=regtest",
      `--datadir=${datadir}`,
      `--rpcport=${rpcPort}`,
      `--port=${p2pPort}`,
      "--metrics-port=0",
      "--nodnsseed",
      "--nodiscover",
      "--connect=127.0.0.1:1",
      "--listen=0",
    ],
    { cwd: REPO, stdout: "ignore", stderr: "ignore" },
  );
  const cookie = path.join(datadir, ".cookie");
  const deadline = Date.now() + 90_000;
  while (Date.now() < deadline) {
    if (fs.existsSync(cookie) && fs.readFileSync(cookie, "utf8").startsWith("__cookie__:")) {
      const auth = "Basic " + Buffer.from(fs.readFileSync(cookie, "utf8").trim()).toString("base64");
      try {
        const r = await fetch(`http://127.0.0.1:${rpcPort}/`, {
          method: "POST",
          headers: { Authorization: auth },
          body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "getblockcount", params: [] }),
        });
        await r.text();
        return { proc, datadir, rpcPort, auth };
      } catch {
        // listener not up yet
      }
    }
    await Bun.sleep(100);
  }
  proc.kill();
  throw new Error("regtest node did not come up within 90s");
}

async function rpc(node: Node, pathname: string, method: string, params: unknown[]): Promise<any> {
  const r = await fetch(`http://127.0.0.1:${node.rpcPort}${pathname}`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: node.auth },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  const body: any = await r.json();
  if (body.error) throw new Error(`${method}: ${JSON.stringify(body.error)}`);
  return body.result;
}

describe("H6/H7 end to end on a regtest node", () => {
  let node: Node;
  beforeAll(async () => {
    node = await startRegtestNode();
  }, 120_000);
  afterAll(async () => {
    if (!node) return;
    node.proc.kill("SIGKILL");
    await node.proc.exited;
    fs.rmSync(node.datadir, { recursive: true, force: true });
  });

  const walletDir = (name: string) => path.join(node.datadir, "wallets", name);

  it("encryptwallet has written the encrypted wallet to disk before it replies", async () => {
    await rpc(node, "/", "createwallet", ["enc"]);
    await rpc(node, "/wallet/enc", "encryptwallet", ["bob"]);

    const onDisk = await Wallet.load(cfg(walletDir("enc")), STORAGE_PW);
    expect(onDisk.isEncrypted()).toBe(true);
    expect(JSON.parse(await rawWalletJson(walletDir("enc"))).seed).toBe("");
  }, 60_000);

  it("walletpassphrasechange has written the new passphrase to disk before it replies", async () => {
    await rpc(node, "/", "createwallet", ["chg", false, false, "bob"]);
    await rpc(node, "/wallet/chg", "walletpassphrasechange", ["bob", "carol"]);

    const onDisk = await Wallet.load(cfg(walletDir("chg")), STORAGE_PW);
    await expect(onDisk.unlockWallet("bob", 0)).rejects.toThrow();
    await onDisk.unlockWallet("carol", 0);
    expect(onDisk.isLocked()).toBe(false);
  }, 60_000);

  it("an importprivkey key survives SIGKILL right after the reply", async () => {
    await rpc(node, "/", "createwallet", ["imp"]);
    const wif = base58CheckEncode(0xef, Buffer.concat([IMPORT_PRIV, Buffer.from([0x01])]));
    await rpc(node, "/wallet/imp", "importprivkey", [wif, "", false]);

    node.proc.kill("SIGKILL");
    await node.proc.exited;

    const scratch = tmpDir("addr");
    const addr = Wallet.create(cfg(scratch)).addImportedKey(IMPORT_PRIV, AddressType.P2WPKH);
    fs.rmSync(scratch, { recursive: true, force: true });
    const onDisk = await Wallet.load(cfg(walletDir("imp")), STORAGE_PW);
    expect(onDisk.getKey(addr)?.privateKey.toString("hex")).toBe(IMPORT_PRIV.toString("hex"));
  }, 60_000);
});
