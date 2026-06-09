/**
 * Unit tests for the `getblockfrompeer` RPC.
 *
 * Core contract (rpc/blockchain.cpp:514 getblockfrompeer +
 * net_processing.cpp:1960 FetchBlock):
 *   (a) unknown header              -> RPC_MISC_ERROR (-1) "Block header missing"
 *   (b) unresolvable peer_id        -> RPC_MISC_ERROR (-1) "Peer does not exist"
 *   (c) body already on disk        -> RPC_MISC_ERROR (-1) "Block already downloaded"
 *   (d) success                     -> sends a block getdata
 *                                      (MSG_BLOCK | MSG_WITNESS_FLAG, the hash)
 *                                      to the resolved peer and returns {}.
 *
 * Peer-id convention: hotbuns' getpeerinfo assigns each peer an `id` equal to
 * its index in getConnectedPeers(). getblockfrompeer resolves peer_id the same
 * way (getConnectedPeers()[peer_id]).
 *
 * In-process only: a real RPCServer is started on loopback with mock deps; the
 * getdata send is captured via a mock peer whose .send() records the outbound
 * NetworkMessage. No multi-node regtest, no chain sync — OOM-free.
 */

import { describe, it, expect, beforeEach, afterEach } from "bun:test";
import { RPCServer, RPCServerConfig, RPCServerDeps, RPCErrorCodes } from "../rpc/server.js";
import { REGTEST } from "../consensus/params.js";
import { InvType, NetworkMessage } from "../p2p/messages.js";

// ── Minimal mock substrate (mirrors src/rpc/server.test.ts) ───────────────

class MockChainStateManager {
  private bestBlock = { hash: Buffer.alloc(32, 0), height: 100, chainWork: 1000n };
  getBestBlock() {
    return { ...this.bestBlock };
  }
}

class MockHeaderSync {
  private unknownHashes = new Set<string>();
  getHeader(hash: Buffer) {
    if (this.unknownHashes.has(hash.toString("hex"))) {
      return undefined;
    }
    return {
      hash: Buffer.from(hash),
      header: {
        version: 1,
        prevBlock: Buffer.alloc(32, 0),
        merkleRoot: Buffer.alloc(32, 0),
        timestamp: 1234567890,
        bits: 0x1d00ffff,
        nonce: 0,
      },
      height: 100,
      chainWork: 1000n,
      status: "valid-header" as const,
    };
  }
  /** Make getHeader return undefined for a specific internal-order hash. */
  setUnknown(hash: Buffer) {
    this.unknownHashes.add(hash.toString("hex"));
  }
}

class MockChainDB {
  private blocks = new Map<string, Buffer>();
  async getBlock(hash: Buffer) {
    return this.blocks.get(hash.toString("hex")) ?? null;
  }
  setBlock(hash: Buffer, data: Buffer) {
    this.blocks.set(hash.toString("hex"), data);
  }
}

/** A peer that records every NetworkMessage passed to .send(). */
class CapturePeer {
  public host: string;
  public port: number;
  public sent: NetworkMessage[] = [];
  constructor(host: string, port: number) {
    this.host = host;
    this.port = port;
  }
  send(msg: NetworkMessage) {
    this.sent.push(msg);
  }
}

class MockPeerManager {
  private peers: any[] = [];
  getConnectedPeers() {
    return this.peers;
  }
  addPeer(peer: any) {
    this.peers.push(peer);
  }
  usingASMap(): boolean {
    return false;
  }
  getMappedAS(_addr: string): number {
    return 0;
  }
}

// ── HTTP roundtrip helper (exercises the real dispatch) ───────────────────

async function rpcRequest(port: number, method: string, params: any[] = []): Promise<any> {
  const response = await fetch(`http://127.0.0.1:${port}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  return response.json();
}

let portCounter = 19443;
function getTestPort(): number {
  return portCounter++;
}

describe("getblockfrompeer", () => {
  let server: RPCServer;
  let mockChainState: MockChainStateManager;
  let mockHeaderSync: MockHeaderSync;
  let mockDB: MockChainDB;
  let mockPeerManager: MockPeerManager;
  let testPort: number;

  // A canonical 32-byte hash. RPC hashes are display-order; the handler
  // reverses to internal order. We assert capture in internal order.
  const displayHashHex = "00".repeat(31) + "ab"; // display-order hex string
  const internalHash = Buffer.from(displayHashHex, "hex").reverse(); // = 0xab,0x00*31

  beforeEach(() => {
    testPort = getTestPort();
    mockChainState = new MockChainStateManager();
    mockHeaderSync = new MockHeaderSync();
    mockDB = new MockChainDB();
    mockPeerManager = new MockPeerManager();

    const config: RPCServerConfig = { port: testPort, host: "127.0.0.1", noAuth: true };
    const deps: RPCServerDeps = {
      chainState: mockChainState as any,
      mempool: {} as any,
      peerManager: mockPeerManager as any,
      feeEstimator: {} as any,
      headerSync: mockHeaderSync as any,
      db: mockDB as any,
      params: REGTEST,
    };

    server = new RPCServer(config, deps);
    server.start();
  });

  afterEach(() => {
    server.stop();
  });

  // (a) unknown header -> "Block header missing"
  it("rejects with -1 'Block header missing' when the header is unknown", async () => {
    mockHeaderSync.setUnknown(internalHash);
    // Even with a valid peer present, the header check must fire first.
    mockPeerManager.addPeer(new CapturePeer("10.0.0.1", 8333));

    const result = await rpcRequest(testPort, "getblockfrompeer", [displayHashHex, 0]);

    expect(result.error).toBeDefined();
    expect(result.error.code).toBe(RPCErrorCodes.MISC_ERROR); // -1
    expect(result.error.code).toBe(-1);
    expect(result.error.message).toBe("Block header missing");
  });

  // (b) bad peer_id -> "Peer does not exist"
  it("rejects with -1 'Peer does not exist' when peer_id is out of range", async () => {
    // No peers connected; header is known (default mock behavior).
    const result = await rpcRequest(testPort, "getblockfrompeer", [displayHashHex, 0]);

    expect(result.error).toBeDefined();
    expect(result.error.code).toBe(RPCErrorCodes.MISC_ERROR); // -1
    expect(result.error.code).toBe(-1);
    expect(result.error.message).toBe("Peer does not exist");
  });

  it("rejects with -1 'Peer does not exist' for a negative peer_id", async () => {
    mockPeerManager.addPeer(new CapturePeer("10.0.0.1", 8333));

    const result = await rpcRequest(testPort, "getblockfrompeer", [displayHashHex, -1]);

    expect(result.error).toBeDefined();
    expect(result.error.code).toBe(-1);
    expect(result.error.message).toBe("Peer does not exist");
  });

  // (c) success -> sends getdata for the hash to the resolved peer, returns {}
  it("sends a witness-block getdata to the resolved peer and returns {} on success", async () => {
    const peer0 = new CapturePeer("10.0.0.1", 8333);
    const peer1 = new CapturePeer("10.0.0.2", 8334); // the target (index 1)
    mockPeerManager.addPeer(peer0);
    mockPeerManager.addPeer(peer1);

    const result = await rpcRequest(testPort, "getblockfrompeer", [displayHashHex, 1]);

    // returns {} (empty object) on success
    expect(result.error).toBeUndefined();
    expect(result.result).toEqual({});

    // getdata went to peer index 1 (matches getpeerinfo id convention), not 0
    expect(peer0.sent.length).toBe(0);
    expect(peer1.sent.length).toBe(1);

    const msg = peer1.sent[0];
    expect(msg.type).toBe("getdata");
    if (msg.type === "getdata") {
      expect(msg.payload.inventory.length).toBe(1);
      const inv = msg.payload.inventory[0];
      // MSG_BLOCK | MSG_WITNESS_FLAG == InvType.MSG_WITNESS_BLOCK (0x40000002)
      expect(inv.type).toBe(InvType.MSG_WITNESS_BLOCK);
      // Hash carried in internal byte order (the reversed display hash)
      expect(inv.hash.equals(internalHash)).toBe(true);
    }
  });

  // (extra) body already on disk -> "Block already downloaded"
  it("rejects with -1 'Block already downloaded' when the body is present", async () => {
    mockPeerManager.addPeer(new CapturePeer("10.0.0.1", 8333));
    mockDB.setBlock(internalHash, Buffer.from([0x01, 0x02, 0x03]));

    const result = await rpcRequest(testPort, "getblockfrompeer", [displayHashHex, 0]);

    expect(result.error).toBeDefined();
    expect(result.error.code).toBe(-1);
    expect(result.error.message).toBe("Block already downloaded");
  });

  // (extra) bad arg types are rejected before any send
  it("rejects a non-integer peer_id with -32602", async () => {
    mockPeerManager.addPeer(new CapturePeer("10.0.0.1", 8333));

    const result = await rpcRequest(testPort, "getblockfrompeer", [displayHashHex, "zero"]);

    expect(result.error).toBeDefined();
    expect(result.error.code).toBe(RPCErrorCodes.INVALID_PARAMS); // -32602
  });
});
