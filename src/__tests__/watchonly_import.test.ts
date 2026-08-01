/**
 * Watch-only import contract tests (Core v31.99 parity).
 *
 * Covers the five watch-only fixes:
 *   1. importdescriptors REQUIRES the BIP-380 checksum (Core Parse with
 *      require_checksum=true, wallet/rpc/backup.cpp:158) with CheckChecksum's
 *      exact error strings (script/descriptor.cpp:2838-2869), embedded
 *      PER-ENTRY with code -5 — never thrown top-level.
 *   2. Imported descriptors register real wallet ownership and a numeric-
 *      timestamp import rescans synchronously, crediting PRE-IMPORT funds
 *      (wallet-level rescan test below; end-to-end on regtest is covered by
 *      test-suite/watchonly/hotbuns_watchonly.sh).
 *   3. Privkey polarity: privkey material into a disable_private_keys wallet
 *      -> per-entry -4 (backup.cpp:224-226); pubkey-only into a privkey-
 *      ENABLED wallet -> per-entry -4 (backup.cpp:259-262).
 *   4. getaddressinfo with Core's shape (addresses.cpp:423-511).
 *   5. createwallet disable_private_keys honored: persisted flag,
 *      private_keys_enabled in getwalletinfo, -4 guards on key-using ops.
 */

import { describe, it, expect, beforeEach, afterEach, beforeAll } from "bun:test";
import { rmSync, mkdirSync } from "fs";
import { RPCServer, RPCServerConfig, RPCServerDeps, RPCErrorCodes } from "../rpc/server.js";
import { REGTEST } from "../consensus/params.js";
import { Wallet, WalletManager, type WalletConfig } from "../wallet/wallet.js";
import { deriveAddresses, addChecksum } from "../wallet/descriptor.js";
import { base58CheckEncode, decodeAddress } from "../address/encoding.js";
import type { Block } from "../validation/block.js";

const TEST_DATADIR = "/tmp/hotbuns-watchonly-import-test";

// Randomised per-run base. A FIXED base collides with long-running processes on
// the dev box: 28601-28610 are held by the phaseb python harnesses and a regtest
// bitcoind, which made these tests fail with "Failed to start server. Is port
// 28601 in use?" and masked the real assertion failures underneath.
let portCounter = 23000 + Math.floor(Math.random() * 2000);
function getTestPort(): number {
  return portCounter++;
}

// A fixed, valid secp256k1 keypair (same scalar family the watch-only
// regtest harness uses).
const PUB_HEX =
  "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798".toLowerCase();
const PRIV_HEX =
  "00112233445566778899aabbccddeeff00112233445566778899aabbccdd4d04";

/** Regtest compressed-key WIF (0xef version + 0x01 compression flag). */
function regtestWIF(privHex: string): string {
  return base58CheckEncode(
    0xef,
    Buffer.concat([Buffer.from(privHex, "hex"), Buffer.from([0x01])])
  );
}

class MockChainStateManager {
  private bestBlock = { hash: Buffer.alloc(32, 0), height: 100, chainWork: 1000n };
  getBestBlock() {
    return { ...this.bestBlock };
  }
  getUTXOManager() {
    return { getUTXOAsync: async () => null };
  }
}
class MockMempool {
  getInfo() { return { size: 0, bytes: 0, minFeeRate: 1 }; }
  getAllTxids() { return []; }
  getTransaction(_txid: Buffer) { return null; }
  hasTransaction(_txid: Buffer) { return false; }
  async addTransaction(_tx: any) { return { accepted: true }; }
  removeTransaction(_txid: Buffer) {}
  async isTransactionConfirmed(_txid: Buffer): Promise<boolean> { return false; }
  isReplaceable(_txid: Buffer): boolean { return true; }
  getSize() { return 0; }
}
class MockPeerManager {
  getConnectedPeers() { return []; }
  broadcast(_msg: any) {}
}
class MockFeeEstimator {
  estimateSmartFee() { return { feeRate: 10, blocks: 6 }; }
  getBuckets() { return []; }
}
class MockHeaderSync {
  getBestHeader() { return { hash: Buffer.alloc(32, 0), height: 100, chainWork: 1000n }; }
  getHeader(_h: Buffer) { return undefined; }
  getMedianTimePast() { return 0; }
}
class MockChainDB {
  async getBlock() { return null; }
  async getBlockIndex() { return null; }
  async getBlockHashByHeight() { return null; }
  async getChainWork(): Promise<bigint | null> { return null; }
  async getChainState() { return { bestBlockHash: Buffer.alloc(32, 0), bestHeight: 100 }; }
  async getUTXO() { return null; }
}

async function rpc(port: number, method: string, params: any[] = []): Promise<any> {
  const r = await fetch(`http://127.0.0.1:${port}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  return r.json();
}

async function rpcWallet(
  port: number,
  wallet: string,
  method: string,
  params: any[] = []
): Promise<any> {
  const r = await fetch(`http://127.0.0.1:${port}/wallet/${wallet}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  return r.json();
}

describe("watch-only import contract", () => {
  beforeAll(() => {
    rmSync(TEST_DATADIR, { recursive: true, force: true });
    mkdirSync(TEST_DATADIR, { recursive: true });
  });

  let server: RPCServer;
  let port: number;
  let manager: WalletManager;
  // Unique per-test datadir: the WalletManager's debounced save-on-mutation
  // flush can land AFTER the test ends; sharing one datadir lets a previous
  // test's late flush collide with the next test's createwallet.
  let caseDir: string;
  let caseCounter = 0;

  // The watch wallet's pubkey descriptor + addr() descriptor, checksummed.
  const wpkhDesc = addChecksum(`wpkh(${PUB_HEX})`);
  const watchAddr = deriveAddresses(`wpkh(${PUB_HEX})`, "regtest")[0];
  const addrDesc = addChecksum(`addr(${watchAddr})`);

  beforeEach(async () => {
    caseDir = `${TEST_DATADIR}/case-${caseCounter++}`;
    mkdirSync(`${caseDir}/wallets`, { recursive: true });
    manager = new WalletManager(caseDir, "regtest");
    await manager.createWallet("default", {});
    await manager.createWallet("wo", { disablePrivateKeys: true, blank: true });

    port = getTestPort();
    const config: RPCServerConfig = { port, host: "127.0.0.1", noAuth: true };
    const deps: RPCServerDeps = {
      chainState: new MockChainStateManager() as any,
      mempool: new MockMempool() as any,
      peerManager: new MockPeerManager() as any,
      feeEstimator: new MockFeeEstimator() as any,
      headerSync: new MockHeaderSync() as any,
      db: new MockChainDB() as any,
      params: REGTEST,
      walletManager: manager,
    };
    server = new RPCServer(config, deps);
    server.start();
  });

  afterEach(async () => {
    server.stop();
    // Drain any debounced wallet flush before the next case's WalletManager
    // starts (same 250ms-debounce race class as wallet_psbt_rpc).
    await manager.flushAll();
  });

  // -----------------------------------------------------------------------
  // (5) createwallet disable_private_keys contract
  // -----------------------------------------------------------------------

  describe("disable_private_keys wallet", () => {
    it("getwalletinfo reports private_keys_enabled:false and keypoolsize:0", async () => {
      const r = await rpcWallet(port, "wo", "getwalletinfo");
      expect(r.error).toBeUndefined();
      expect(r.result.private_keys_enabled).toBe(false);
      expect(r.result.keypoolsize).toBe(0);
    });

    it("the default wallet still reports private_keys_enabled:true", async () => {
      const r = await rpcWallet(port, "default", "getwalletinfo");
      expect(r.error).toBeUndefined();
      expect(r.result.private_keys_enabled).toBe(true);
      expect(r.result.keypoolsize).toBe(20);
    });

    it("is born keyless (no pre-generated addresses)", () => {
      const wo = manager.getWallet("wo")!;
      expect(wo.listAddresses().length).toBe(0);
      expect(wo.isPrivateKeysDisabled()).toBe(true);
    });

    it("createwallet rejects passphrase + disable_private_keys (Core wallet.cpp:409-413)", async () => {
      const r = await rpc(port, "createwallet", ["badcombo", true, true, "secret"]);
      expect(r.error).toBeDefined();
      expect(r.error.code).toBe(RPCErrorCodes.WALLET_ERROR);
      expect(r.error.message).toBe(
        "Passphrase provided but private keys are disabled. A passphrase is only used to encrypt private keys, so cannot be used for wallets with private keys disabled."
      );
    });

    it("getnewaddress -> -4 'Error: This wallet has no available keys'", async () => {
      const r = await rpcWallet(port, "wo", "getnewaddress");
      expect(r.error.code).toBe(RPCErrorCodes.WALLET_ERROR);
      expect(r.error.message).toBe("Error: This wallet has no available keys");
    });

    it("sendtoaddress -> -4 'Error: Private keys are disabled for this wallet'", async () => {
      const r = await rpcWallet(port, "wo", "sendtoaddress", [watchAddr, 1.0]);
      expect(r.error.code).toBe(RPCErrorCodes.WALLET_ERROR);
      expect(r.error.message).toBe("Error: Private keys are disabled for this wallet");
    });

    it("importprivkey -> -4 'Cannot import private keys ...'", async () => {
      const r = await rpcWallet(port, "wo", "importprivkey", [regtestWIF(PRIV_HEX)]);
      expect(r.error.code).toBe(RPCErrorCodes.WALLET_ERROR);
      expect(r.error.message).toBe(
        "Cannot import private keys to a wallet with private keys disabled"
      );
    });

    it("encryptwallet -> -16 'nothing to encrypt' (Core encrypt.cpp:255-256)", async () => {
      const r = await rpcWallet(port, "wo", "encryptwallet", ["pass"]);
      expect(r.error.code).toBe(RPCErrorCodes.WALLET_ENCRYPTION_FAILED);
      expect(r.error.message).toBe(
        "Error: wallet does not contain private keys, nothing to encrypt."
      );
    });
  });

  // -----------------------------------------------------------------------
  // (1) checksum enforcement: per-entry -5, Core-exact strings
  // -----------------------------------------------------------------------

  describe("importdescriptors checksum enforcement", () => {
    async function importOne(desc: string): Promise<any> {
      return rpcWallet(port, "wo", "importdescriptors", [
        [{ desc, timestamp: "now" }],
      ]);
    }

    it("missing checksum -> per-entry -5 'Missing checksum' (call still succeeds)", async () => {
      const noChk = wpkhDesc.split("#")[0];
      const r = await importOne(noChk);
      expect(r.error).toBeUndefined(); // NOT a top-level error
      expect(r.result.length).toBe(1);
      expect(r.result[0].success).toBe(false);
      expect(r.result[0].error.code).toBe(RPCErrorCodes.INVALID_ADDRESS_OR_KEY);
      expect(r.result[0].error.message).toBe("Missing checksum");
    });

    it("multiple '#' -> -5 \"Multiple '#' symbols\"", async () => {
      const r = await importOne(`${wpkhDesc}#extra`);
      expect(r.result[0].error.code).toBe(RPCErrorCodes.INVALID_ADDRESS_OR_KEY);
      expect(r.result[0].error.message).toBe("Multiple '#' symbols");
    });

    it("wrong checksum length -> -5 'Expected 8 character checksum, not N characters'", async () => {
      const r = await importOne(`${wpkhDesc.split("#")[0]}#abc`);
      expect(r.result[0].error.code).toBe(RPCErrorCodes.INVALID_ADDRESS_OR_KEY);
      expect(r.result[0].error.message).toBe(
        "Expected 8 character checksum, not 3 characters"
      );
    });

    it("checksum mismatch -> -5 with provided + computed checksums", async () => {
      const [payload, chk] = wpkhDesc.split("#");
      // Flip the last checksum character to a different charset member.
      const bad = chk.slice(0, 7) + (chk[7] === "q" ? "p" : "q");
      const r = await importOne(`${payload}#${bad}`);
      expect(r.result[0].error.code).toBe(RPCErrorCodes.INVALID_ADDRESS_OR_KEY);
      expect(r.result[0].error.message).toBe(
        `Provided checksum '${bad}' does not match computed checksum '${chk}'`
      );
    });

    it("a bad entry does not poison later entries (per-entry embedding)", async () => {
      const r = await rpcWallet(port, "wo", "importdescriptors", [
        [
          { desc: wpkhDesc.split("#")[0], timestamp: "now" },
          { desc: addrDesc, timestamp: "now" },
        ],
      ]);
      expect(r.error).toBeUndefined();
      expect(r.result.length).toBe(2);
      expect(r.result[0].success).toBe(false);
      expect(r.result[1].success).toBe(true);
    });
  });

  // -----------------------------------------------------------------------
  // (2-timestamp) timestamp semantics: top-level -3 (Core GetImportTimestamp)
  // -----------------------------------------------------------------------

  describe("importdescriptors timestamp semantics", () => {
    it("missing timestamp -> TOP-LEVEL -3 (aborts the whole call)", async () => {
      const r = await rpcWallet(port, "wo", "importdescriptors", [
        [{ desc: addrDesc }],
      ]);
      expect(r.result).toBeFalsy();
      expect(r.error.code).toBe(RPCErrorCodes.TYPE_ERROR);
      expect(r.error.message).toBe("Missing required timestamp field for key");
    });

    it("wrong-type timestamp -> TOP-LEVEL -3", async () => {
      const r = await rpcWallet(port, "wo", "importdescriptors", [
        [{ desc: addrDesc, timestamp: true }],
      ]);
      expect(r.error.code).toBe(RPCErrorCodes.TYPE_ERROR);
      expect(r.error.message).toContain('Expected number or "now" timestamp value for key');
    });

    it("string timestamps other than 'now' -> TOP-LEVEL -3", async () => {
      const r = await rpcWallet(port, "wo", "importdescriptors", [
        [{ desc: addrDesc, timestamp: "later" }],
      ]);
      expect(r.error.code).toBe(RPCErrorCodes.TYPE_ERROR);
    });
  });

  // -----------------------------------------------------------------------
  // (3) privkey polarity
  // -----------------------------------------------------------------------

  describe("importdescriptors privkey polarity", () => {
    it("privkey descriptor into dpk wallet -> per-entry -4 (Core backup.cpp:224-226)", async () => {
      const privDesc = addChecksum(`wpkh(${regtestWIF(PRIV_HEX)})`);
      const r = await rpcWallet(port, "wo", "importdescriptors", [
        [{ desc: privDesc, timestamp: 0 }],
      ]);
      expect(r.error).toBeUndefined();
      expect(r.result[0].success).toBe(false);
      expect(r.result[0].error.code).toBe(RPCErrorCodes.WALLET_ERROR);
      expect(r.result[0].error.message).toBe(
        "Cannot import private keys to a wallet with private keys disabled"
      );
    });

    it("pubkey-only descriptor into privkey-enabled wallet -> per-entry -4 (backup.cpp:259-262)", async () => {
      const r = await rpcWallet(port, "default", "importdescriptors", [
        [{ desc: wpkhDesc, timestamp: "now" }],
      ]);
      expect(r.error).toBeUndefined();
      expect(r.result[0].success).toBe(false);
      expect(r.result[0].error.code).toBe(RPCErrorCodes.WALLET_ERROR);
      expect(r.result[0].error.message).toBe(
        "Cannot import descriptor without private keys to a wallet with private keys enabled"
      );
    });

    it("getdescriptorinfo reports hasprivatekeys for WIF descriptors", async () => {
      const r = await rpc(port, "getdescriptorinfo", [
        `wpkh(${regtestWIF(PRIV_HEX)})`,
      ]);
      expect(r.error).toBeUndefined();
      expect(r.result.hasprivatekeys).toBe(true);

      const r2 = await rpc(port, "getdescriptorinfo", [`wpkh(${PUB_HEX})`]);
      expect(r2.result.hasprivatekeys).toBe(false);
    });
  });

  // -----------------------------------------------------------------------
  // (4) getaddressinfo shape
  // -----------------------------------------------------------------------

  describe("getaddressinfo", () => {
    it("imported addr() watch address: ismine:true, solvable:false, parent_desc, labels", async () => {
      const imp = await rpcWallet(port, "wo", "importdescriptors", [
        [{ desc: addrDesc, timestamp: "now", label: "wo-label" }],
      ]);
      expect(imp.result[0].success).toBe(true);

      const r = await rpcWallet(port, "wo", "getaddressinfo", [watchAddr]);
      expect(r.error).toBeUndefined();
      const info = r.result;
      expect(info.address).toBe(watchAddr);
      expect(typeof info.scriptPubKey).toBe("string");
      expect(info.ismine).toBe(true);
      expect(info.solvable).toBe(false); // addr() carries no key knowledge
      expect(info.desc).toBeUndefined(); // desc emitted ONLY when solvable
      expect(info.parent_desc).toBe(addrDesc);
      expect(info.iswatchonly).toBe(false); // DEPRECATED — Core hardcodes false
      expect(info.iswitness).toBe(true);
      expect(info.witness_version).toBe(0);
      expect(info.labels).toEqual(["wo-label"]);
    });

    it("imported wpkh(PUB): ismine:true, solvable:true, desc + parent_desc", async () => {
      const imp = await rpcWallet(port, "wo", "importdescriptors", [
        [{ desc: wpkhDesc, timestamp: "now" }],
      ]);
      expect(imp.result[0].success).toBe(true);

      const r = await rpcWallet(port, "wo", "getaddressinfo", [watchAddr]);
      const info = r.result;
      expect(info.ismine).toBe(true);
      expect(info.solvable).toBe(true);
      expect(info.desc).toBe(wpkhDesc);
      expect(info.parent_desc).toBe(wpkhDesc);
      expect(info.pubkey).toBe(PUB_HEX);
      expect(info.labels).toEqual([]);
    });

    it("non-wallet address: ismine:false; invalid address: top-level -5", async () => {
      const r = await rpcWallet(port, "wo", "getaddressinfo", [watchAddr]);
      expect(r.result.ismine).toBe(false);

      const bad = await rpcWallet(port, "wo", "getaddressinfo", ["notanaddress"]);
      expect(bad.error.code).toBe(RPCErrorCodes.INVALID_ADDRESS_OR_KEY);
    });
  });

  // -----------------------------------------------------------------------
  // (2) ownership registration + rescan crediting (wallet level)
  // -----------------------------------------------------------------------

  describe("watch ownership + rescan crediting (wallet level)", () => {
    function walletConfig(): WalletConfig {
      return { datadir: `${caseDir}/wallets/unit`, network: "regtest" };
    }

    /** A minimal regular (non-coinbase) block paying `script` `value` sats. */
    function blockPaying(script: Buffer, value: bigint): Block {
      return {
        header: {
          version: 1,
          prevBlock: Buffer.alloc(32, 0),
          merkleRoot: Buffer.alloc(32, 0),
          timestamp: Math.floor(Date.now() / 1000),
          bits: 0x207fffff,
          nonce: 0,
        },
        transactions: [
          {
            version: 1,
            inputs: [
              {
                prevOut: { txid: Buffer.alloc(32, 0x42), vout: 0 },
                scriptSig: Buffer.alloc(0),
                sequence: 0xffffffff,
                witness: [],
              },
            ],
            outputs: [{ value, scriptPubKey: script }],
            lockTime: 0,
          },
        ],
      } as unknown as Block;
    }

    it("rescan credits PRE-IMPORT funds paid to a watch descriptor (the ts=0 contract)", async () => {
      const wallet = Wallet.create(walletConfig(), undefined, "", {
        disablePrivateKeys: true,
        blank: true,
      });

      const decoded = decodeAddress(watchAddr);
      const script = Buffer.concat([Buffer.from([0x00, 0x14]), decoded.hash]);

      // The funding block EXISTS BEFORE the import (pre-import funding).
      const funding = blockPaying(script, 150_000_000n);

      // Import, then rescan from genesis — exactly what importdescriptors
      // with timestamp 0 drives.
      const addrs = wallet.addWatchDescriptor(addrDesc, 1);
      expect(addrs).toEqual([watchAddr]);

      const chain: Record<number, Block> = { 0: funding };
      const res = await wallet.rescan(async (h) => chain[h] ?? null, 0, 0);
      expect(res.stopHeight).toBe(0);

      const utxos = wallet.getUTXOs();
      expect(utxos.length).toBe(1);
      expect(utxos[0].address).toBe(watchAddr);
      expect(utxos[0].amount).toBe(150_000_000n);
      expect(utxos[0].keyPath).toBe("watch");
      expect(wallet.getBalance().total).toBe(150_000_000n);
    });

    it("watch state + dpk flag survive a save/load round-trip", async () => {
      const config = walletConfig();
      mkdirSync(config.datadir, { recursive: true });
      const wallet = Wallet.create(config, undefined, "", {
        disablePrivateKeys: true,
        blank: true,
      });
      wallet.addWatchDescriptor(wpkhDesc, 1, undefined, "roundtrip");
      await wallet.save("pw");

      const reloaded = await Wallet.load(config, "pw");
      expect(reloaded.isPrivateKeysDisabled()).toBe(true);
      expect(reloaded.isWatchAddress(watchAddr)).toBe(true);
      expect(reloaded.getWatchAddressInfo(watchAddr)?.parentDesc).toBe(wpkhDesc);
      expect(reloaded.getLabel(watchAddr)).toBe("roundtrip");
      // Still keyless after reload (no pregeneration for dpk wallets).
      expect(reloaded.listAddresses().length).toBe(0);
    });
  });
});
