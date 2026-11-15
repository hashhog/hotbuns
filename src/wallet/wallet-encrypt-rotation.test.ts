/**
 * Security audit H6: encryptwallet kept the old HD seed.
 *
 * Every wallet.dat is wrapped with the fixed storage key "hotbuns", so the
 * seed of an unencrypted wallet is plaintext to anyone holding the file -- and
 * that includes every backup taken before `encryptwallet`. hotbuns#41 made
 * encryptwallet persist before replying, but Wallet.encryptWallet still kept
 * the same seed, so a pre-encryption copy derives every address the wallet
 * hands out after encryption: encrypting protected nothing that wasn't already
 * leaked.
 *
 * Core: CWallet::EncryptWallet (wallet/wallet.cpp:818-886) generates a fresh
 * seed and fresh descriptors inside the encryption transaction ("if we are
 * using descriptors, make new descriptors with a new seed"), keeps the old
 * descriptors (now encrypted) so their coins stay spendable, then Rewrite()s
 * the database so no plaintext record of the old keys remains.
 *
 * Everything here runs on regtest with fresh temp datadirs.
 */
import { describe, it, expect } from "bun:test";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { Wallet, WalletManager, type WalletConfig } from "./wallet.js";
import { decodeAddress } from "../address/encoding.js";
import { verifyInputSignature } from "../validation/tx.js";

const STORAGE_PW = "hotbuns";
const PASS = "correct horse battery staple";
const TYPES = ["legacy", "p2sh-segwit", "bech32", "bech32m"] as const;
const MNEMONIC =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

function tmpDir(tag: string): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), `hotbuns-h6rot-${tag}-`));
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

/**
 * Everything an attacker holding a pre-encryption copy can derive: every
 * address the copy's seed yields for the first `depth` receive and change
 * indices of every address type.
 */
function derivableFrom(stolen: Wallet, depth: number): Set<string> {
  const out = new Set<string>();
  for (const t of TYPES) {
    for (let i = 0; i < depth; i++) {
      out.add(stolen.getNewAddress(t));
      out.add(stolen.getChangeAddress(t));
    }
  }
  for (const k of stolen.listAddresses()) out.add(k.address);
  return out;
}

function p2wpkhSpk(address: string): Buffer {
  const d = decodeAddress(address);
  return Buffer.concat([Buffer.from([0x00, 0x14]), d.hash]);
}

/** Fund `address` with one confirmed, mature UTXO of `amount` sat. */
function fund(w: Wallet, address: string, amount: bigint, txidByte: number): void {
  w.addUTXO({
    outpoint: { txid: Buffer.alloc(32, txidByte), vout: 0 },
    amount,
    address,
    keyPath: w.getKey(address)!.path,
    confirmations: 10,
    addressType: w.getKey(address)!.addressType,
    isCoinbase: false,
    height: 1,
  });
}

/** Encrypt `datadir`'s wallet after copying the pre-encryption file aside. */
async function encryptKeepingBackup(
  w: Wallet,
  dir: string,
  backupDir: string,
): Promise<void> {
  await w.save(STORAGE_PW);
  fs.copyFileSync(path.join(dir, "wallet.dat"), path.join(backupDir, "wallet.dat"));
  await w.encryptWallet(PASS);
  await w.save(STORAGE_PW);
}

describe("H6: encryptwallet rotates the HD seed (Core EncryptWallet)", () => {
  it("addresses issued after encryptwallet are not derivable from a pre-encryption copy", async () => {
    const dir = tmpDir("rot");
    const backup = tmpDir("rot-bak");
    try {
      const w = Wallet.create(cfg(dir));
      const s0 = Buffer.from(w.getSeed()).toString("hex");
      const a0 = w.getNewAddress("bech32");
      await encryptKeepingBackup(w, dir, backup);

      const live = await Wallet.load(cfg(dir), STORAGE_PW);
      await live.unlockWallet(PASS, 0);
      expect(Buffer.from(live.getSeed()).toString("hex")).not.toBe(s0);
      const issued = TYPES.flatMap((t) => [live.getNewAddress(t), live.getChangeAddress(t)]);

      // The attacker opens the stolen pre-encryption copy with the public key.
      const stolen = await Wallet.load(cfg(backup), STORAGE_PW);
      expect(Buffer.from(stolen.getSeed()).toString("hex")).toBe(s0);
      expect(stolen.hasAddress(a0)).toBe(true); // the copy is the real wallet
      const reach = derivableFrom(stolen, 100);
      for (const addr of issued) {
        expect(reach.has(addr)).toBe(false);
      }
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
      fs.rmSync(backup, { recursive: true, force: true });
    }
  });

  it("the encrypted wallet.dat holds no plaintext copy of the old or new seed", async () => {
    const dir = tmpDir("noplain");
    const backup = tmpDir("noplain-bak");
    try {
      const w = Wallet.create(cfg(dir));
      const s0 = Buffer.from(w.getSeed()).toString("hex");
      await encryptKeepingBackup(w, dir, backup);
      await w.unlockWallet(PASS, 0);
      const s1 = Buffer.from(w.getSeed()).toString("hex");

      const raw = await rawWalletJson(dir);
      expect(raw.includes(s0)).toBe(false);
      expect(raw.includes(s1)).toBe(false);
      // Control: the instrument sees a plaintext seed when one is there.
      expect((await rawWalletJson(backup)).includes(s0)).toBe(true);
      // The encrypted file is a fresh write, not the old bytes reused.
      const before = fs.readFileSync(path.join(backup, "wallet.dat"));
      const after = fs.readFileSync(path.join(dir, "wallet.dat"));
      expect(after.equals(before)).toBe(false);
      expect(JSON.parse(after.toString()).salt).not.toBe(JSON.parse(before.toString()).salt);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
      fs.rmSync(backup, { recursive: true, force: true });
    }
  });
});

describe("H6 controls: coins at old-seed key paths survive the rotation", () => {
  it("a coin paid to a pre-encryption address is spendable after encrypt + reload + unlock", async () => {
    const dir = tmpDir("spend");
    const backup = tmpDir("spend-bak");
    try {
      const w = Wallet.create(cfg(dir));
      const a0 = w.getNewAddress("bech32");
      const k0 = Buffer.from(w.getKey(a0)!.privateKey);
      fund(w, a0, 100_000_000n, 0x11);
      await encryptKeepingBackup(w, dir, backup);

      const live = await Wallet.load(cfg(dir), STORAGE_PW);
      await live.unlockWallet(PASS, 0);
      expect(live.getKey(a0)?.privateKey.toString("hex")).toBe(k0.toString("hex"));

      const dest = live.getNewAddress("bech32");
      const tx = live.createTransaction([{ address: dest, amount: 50_000_000n }], 2);
      expect(tx.inputs.length).toBe(1);
      const prev = { height: 1, coinbase: false, amount: 100_000_000n, scriptPubKey: p2wpkhSpk(a0) };
      expect(verifyInputSignature(tx, 0, prev, {}, [prev], {}).valid).toBe(true);

      // Negative control: the check rejects a signature over the wrong amount.
      const wrong = { ...prev, amount: 99_999_999n };
      expect(verifyInputSignature(tx, 0, wrong, {}, [wrong], {}).valid).toBe(false);

      // Change goes to the NEW seed, not back to the leaked one.
      const stolen = await Wallet.load(cfg(backup), STORAGE_PW);
      const reach = derivableFrom(stolen, 30);
      for (const out of tx.outputs) {
        const isOurs = [dest, ...live.listAddresses().map((k) => k.address)].find(
          (a) => p2wpkhSpk(a).equals(out.scriptPubKey),
        );
        expect(isOurs).toBeDefined();
        expect(reach.has(isOurs!)).toBe(false);
      }
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
      fs.rmSync(backup, { recursive: true, force: true });
    }
  });

  it("old-seed gap addresses stay owned, and survive walletpassphrasechange", async () => {
    const dir = tmpDir("gap");
    const backup = tmpDir("gap-bak");
    try {
      const w = Wallet.create(cfg(dir));
      const handedOut = TYPES.map((t) => w.getNewAddress(t));
      // An address in the old keypool gap that was never handed out but a
      // payer could still have (Core keeps the old descriptor's range).
      const before = new Set(w.listAddresses().map((k) => k.address));
      await encryptKeepingBackup(w, dir, backup);

      await w.changePassphrase(PASS, "new pass");
      await w.save(STORAGE_PW);
      const live = await Wallet.load(cfg(dir), STORAGE_PW);
      await expect(live.unlockWallet(PASS, 0)).rejects.toThrow();
      await live.unlockWallet("new pass", 0);
      for (const a of before) {
        expect(live.hasAddress(a)).toBe(true);
        expect(live.getKey(a)?.privateKey.length).toBe(32);
      }
      for (const a of handedOut) expect(live.hasAddress(a)).toBe(true);
      // A further reload keeps both generations.
      await live.save(STORAGE_PW);
      const again = await Wallet.load(cfg(dir), STORAGE_PW);
      await again.unlockWallet("new pass", 0);
      for (const a of before) expect(again.hasAddress(a)).toBe(true);
      expect(again.listAddresses().length).toBeGreaterThan(before.size);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
      fs.rmSync(backup, { recursive: true, force: true });
    }
  });

  it("an imported key added before encryptwallet stays spendable after rotation", async () => {
    const dir = tmpDir("imp");
    const backup = tmpDir("imp-bak");
    try {
      const priv = Buffer.from(
        "1e99423a4ed27608a15a2616a2b0e9e52ced330ac530edcc32c8ffc6a526aedd",
        "hex",
      );
      const w = Wallet.create(cfg(dir));
      const { AddressType } = await import("../address/encoding.js");
      const addr = w.addImportedKey(priv, AddressType.P2WPKH);
      await encryptKeepingBackup(w, dir, backup);
      const live = await Wallet.load(cfg(dir), STORAGE_PW);
      await live.unlockWallet(PASS, 0);
      expect(live.getKey(addr)?.privateKey.toString("hex")).toBe(priv.toString("hex"));
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
      fs.rmSync(backup, { recursive: true, force: true });
    }
  });

  it("createwallet with a mnemonic and a passphrase keeps the mnemonic's keys (seed-only recovery)", async () => {
    const root = tmpDir("mnem");
    try {
      const mgr = new WalletManager(root, "regtest");
      await mgr.createWallet("m", { mnemonic: MNEMONIC, passphrase: PASS });
      const enc = mgr.getWallet("m")!;
      await enc.unlockWallet(PASS, 0);
      const plain = Wallet.create(cfg(root), MNEMONIC);
      expect(enc.getNewAddress("bech32")).toBe(plain.getNewAddress("bech32"));
      expect(Buffer.from(enc.getSeed()).equals(plain.getSeed())).toBe(true);
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });
});
