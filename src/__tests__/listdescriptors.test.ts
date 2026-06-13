/**
 * listdescriptors RPC contract tests (Core v31.99 parity).
 *
 * Core: bitcoin-core/src/wallet/rpc/backup.cpp::listdescriptors.
 *
 * Verified shape (private=false default):
 *   { wallet_name, descriptors: [ { desc (WITH #checksum), timestamp, active,
 *     internal? (active only), range? + next?/next_index? (ranged only) } ] }
 *   - descriptors sorted by descriptor string
 *   - private=true on a watch-only wallet -> -4
 *     "Can't get private descriptor string for watch-only wallets"
 *
 * Populates the descriptor store IN-PROCESS via importdescriptors (no full
 * node / regtest bind), then asserts the listdescriptors output shape and a
 * correct BIP-380 checksum.
 */

import { describe, it, expect, beforeEach, afterEach, beforeAll } from "bun:test";
import { rmSync, mkdirSync } from "fs";
import { RPCServer, RPCServerConfig, RPCServerDeps, RPCErrorCodes } from "../rpc/server.js";
import { REGTEST } from "../consensus/params.js";
import { WalletManager } from "../wallet/wallet.js";
import { addChecksum, descriptorChecksum } from "../wallet/descriptor.js";

const TEST_DATADIR = "/tmp/hotbuns-listdescriptors-test";

let portCounter = 28900;
function getTestPort(): number {
  return portCounter++;
}

// A fixed, valid secp256k1 compressed pubkey (the generator point G).
const PUB_HEX =
  "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798".toLowerCase();
// A second valid compressed pubkey (sorts after PUB_HEX as a desc string so we
// can assert deterministic ordering).
const PUB_HEX_2 =
  "02C6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5".toLowerCase();

// A real BIP-32 extended public key (the BIP-32 spec test vector, chain m),
// usable in a ranged wildcard descriptor.
const XPUB =
  "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";

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

describe("listdescriptors RPC contract", () => {
  beforeAll(() => {
    rmSync(TEST_DATADIR, { recursive: true, force: true });
    mkdirSync(TEST_DATADIR, { recursive: true });
  });

  let server: RPCServer;
  let port: number;
  let manager: WalletManager;
  let caseDir: string;
  let caseCounter = 0;

  // The watch wallet's two single-key pubkey descriptors, checksummed.
  const wpkhDesc = addChecksum(`wpkh(${PUB_HEX})`);
  const pkhDesc2 = addChecksum(`pkh(${PUB_HEX_2})`);

  beforeEach(async () => {
    caseDir = `${TEST_DATADIR}/case-${caseCounter++}`;
    mkdirSync(`${caseDir}/wallets`, { recursive: true });
    manager = new WalletManager(caseDir, "regtest");
    // Watch-only wallet: private keys disabled, blank — the only wallet kind
    // that accepts pubkey-only descriptors via importdescriptors.
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

  afterEach(() => {
    server.stop();
  });

  it("returns wallet_name + empty descriptors before any import", async () => {
    const r = await rpcWallet(port, "wo", "listdescriptors");
    expect(r.error).toBeUndefined();
    expect(r.result.wallet_name).toBe("wo");
    expect(Array.isArray(r.result.descriptors)).toBe(true);
    expect(r.result.descriptors.length).toBe(0);
  });

  it("emits an imported descriptor in Core shape with the trailing #checksum", async () => {
    const imp = await rpcWallet(port, "wo", "importdescriptors", [
      [{ desc: wpkhDesc, timestamp: 1700000000 }],
    ]);
    expect(imp.error).toBeUndefined();
    expect(imp.result[0].success).toBe(true);

    const r = await rpcWallet(port, "wo", "listdescriptors");
    expect(r.error).toBeUndefined();
    expect(r.result.wallet_name).toBe("wo");
    expect(r.result.descriptors.length).toBe(1);

    const d = r.result.descriptors[0];
    // desc carries the trailing #<8-char checksum> and it is CORRECT.
    expect(d.desc).toBe(wpkhDesc);
    expect(d.desc).toMatch(/#[0-9a-z]{8}$/);
    const [base, csum] = (d.desc as string).split("#");
    expect(csum.length).toBe(8);
    expect(csum).toBe(descriptorChecksum(base));

    expect(d.timestamp).toBe(1700000000);
    expect(d.active).toBe(false);
    // internal is omitted for inactive (imported watch-only) descriptors.
    expect("internal" in d).toBe(false);
    // Un-ranged single-key descriptor: no range / next / next_index.
    expect("range" in d).toBe(false);
    expect("next" in d).toBe(false);
    expect("next_index" in d).toBe(false);
  });

  it("sorts descriptors by descriptor string (Core backup.cpp:541-543)", async () => {
    // Import in the order [pkh(...) , wpkh(...)]. As desc strings, "pkh(" < "wpkh("
    // so pkhDesc2 must come first regardless of import order.
    await rpcWallet(port, "wo", "importdescriptors", [
      [
        { desc: wpkhDesc, timestamp: 1700000000 },
        { desc: pkhDesc2, timestamp: 1700000001 },
      ],
    ]);

    const r = await rpcWallet(port, "wo", "listdescriptors");
    expect(r.error).toBeUndefined();
    const descs = r.result.descriptors.map((x: any) => x.desc);
    expect(descs.length).toBe(2);
    // Output is sorted ascending by descriptor string.
    expect(descs).toEqual([...descs].sort());
    expect(descs[0]).toBe(pkhDesc2); // "pkh(" sorts before "wpkh("
    expect(descs[1]).toBe(wpkhDesc);
  });

  it("emits range + next/next_index for a ranged descriptor", async () => {
    const rangedDesc = addChecksum(`pkh(${XPUB}/0/*)`);
    const imp = await rpcWallet(port, "wo", "importdescriptors", [
      [{ desc: rangedDesc, timestamp: 1700000000, range: [0, 4] }],
    ]);
    expect(imp.error).toBeUndefined();
    expect(imp.result[0].success).toBe(true);

    const r = await rpcWallet(port, "wo", "listdescriptors");
    expect(r.error).toBeUndefined();
    expect(r.result.descriptors.length).toBe(1);

    const d = r.result.descriptors[0];
    expect(d.desc).toMatch(/#[0-9a-z]{8}$/);
    expect(d.active).toBe(false);
    // Ranged descriptors carry the inclusive [begin,end] range and a next index.
    expect(d.range).toEqual([0, 4]);
    expect(d.next).toBe(0);
    expect(d.next_index).toBe(0);
  });

  it("private=true on a watch-only wallet -> -4 (Core backup.cpp:500-502)", async () => {
    await rpcWallet(port, "wo", "importdescriptors", [
      [{ desc: wpkhDesc, timestamp: 1700000000 }],
    ]);
    const r = await rpcWallet(port, "wo", "listdescriptors", [true]);
    expect(r.error).toBeDefined();
    expect(r.error.code).toBe(RPCErrorCodes.WALLET_ERROR);
    expect(r.error.message).toBe(
      "Can't get private descriptor string for watch-only wallets"
    );
  });

  it("non-boolean private argument -> -3 type error", async () => {
    const r = await rpcWallet(port, "wo", "listdescriptors", ["yes"]);
    expect(r.error).toBeDefined();
    expect(r.error.code).toBe(RPCErrorCodes.TYPE_ERROR);
  });
});
