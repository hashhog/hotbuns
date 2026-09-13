import { describe, expect, it } from "bun:test";
import { REGTEST } from "../consensus/params.js";
import type { RPCServerDeps } from "../rpc/server.js";
import { startTestRpc } from "./rpc-listen.js";

function stubDeps(): RPCServerDeps {
  return {
    chainState: {
      getBestBlock: () => ({ hash: Buffer.alloc(32, 0), height: 0, chainWork: 0n }),
    } as RPCServerDeps["chainState"],
    mempool: { getInfo: () => ({ size: 0, bytes: 0, minFeeRate: 1 }) } as RPCServerDeps["mempool"],
    peerManager: { getConnectedPeers: () => [] } as RPCServerDeps["peerManager"],
    feeEstimator: { estimateSmartFee: () => ({ feeRate: 1, blocks: 1 }) } as RPCServerDeps["feeEstimator"],
    headerSync: {
      getBestHeader: () => ({ hash: Buffer.alloc(32, 0), height: 0, chainWork: 0n }),
    } as RPCServerDeps["headerSync"],
    db: {} as RPCServerDeps["db"],
    params: REGTEST,
  };
}

describe("startTestRpc", () => {
  it("binds an OS-assigned port (not a guessed ephemeral)", async () => {
    const { server, port } = startTestRpc(stubDeps());
    try {
      expect(port).toBeGreaterThan(0);
      const r = await fetch(`http://127.0.0.1:${port}/`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ jsonrpc: "1.0", id: "t", method: "getblockcount", params: [] }),
      });
      expect(r.status).toBeGreaterThanOrEqual(200);
    } finally {
      server.stop();
    }
  });

  it("retries when the requested port is already bound", async () => {
    const blocker = Bun.serve({
      port: 0,
      hostname: "127.0.0.1",
      fetch: () => new Response("held"),
    });
    try {
      const occupied = blocker.port;
      expect(occupied).toBeGreaterThan(0);
      const { server, port } = startTestRpc(stubDeps(), { port: occupied });
      try {
        expect(port).not.toBe(occupied);
        expect(port).toBeGreaterThan(0);
      } finally {
        server.stop();
      }
    } finally {
      blocker.stop();
    }
  });
});
