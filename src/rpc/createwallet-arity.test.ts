/**
 * createwallet vs the central argument-count gate (hotbuns-wallet-arity).
 *
 * The gate enforces Core's 1..8 positional limit. hotbuns' BIP-39 restore
 * extension sends mnemonic and mnemonic_passphrase at positions 8 and 9, which
 * the gate rejected with -1 + help text, so every wallet arm
 * (recovery/spend/history/import) failed at `createwallet w1`.
 */
import { describe, it, expect, beforeEach, afterEach } from "bun:test";
import { RPCServer, RPCServerConfig, RPCServerDeps } from "./server.js";
import { REGTEST } from "../consensus/params.js";

let nextPort = 39100 + (process.pid % 500);
const created: Array<{ name: string; options: any }> = [];

function makeServer(port: number): RPCServer {
  const walletManager = {
    createWallet: async (name: string, options: any) => {
      created.push({ name, options });
      return { name, warnings: [] };
    },
    listWallets: () => [],
  };
  const deps = {
    chainState: { getBestBlock: () => ({ height: 0, hash: Buffer.alloc(32), chainWork: 0n }) },
    mempool: {},
    peerManager: { getConnectedPeers: () => [] },
    feeEstimator: {},
    headerSync: {},
    db: {},
    params: REGTEST,
    walletManager,
  } as unknown as RPCServerDeps;
  const config: RPCServerConfig = { port, host: "127.0.0.1", noAuth: true };
  return new RPCServer(config, deps);
}

async function rpc(port: number, method: string, params: unknown[]): Promise<any> {
  const r = await fetch(`http://127.0.0.1:${port}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  return r.json();
}

const MNEMONIC =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

describe("createwallet arity gate", () => {
  let server: RPCServer;
  let port: number;
  beforeEach(() => {
    created.length = 0;
    port = nextPort++;
    server = makeServer(port);
    server.start();
  });
  afterEach(() => server.stop());

  it("accepts the mnemonic at position 8 (8 args, as the recovery arms send)", async () => {
    const res = await rpc(port, "createwallet", ["w1", false, false, "", false, true, false, MNEMONIC]);
    expect(res.error).toBeUndefined();
    expect(res.result.name).toBe("w1");
    expect(created[0].options.mnemonic).toBe(MNEMONIC);
  });

  it("accepts mnemonic + mnemonic_passphrase (9 args)", async () => {
    const res = await rpc(port, "createwallet", ["w1", false, false, "", false, true, false, MNEMONIC, "pp"]);
    expect(res.error).toBeUndefined();
    expect(created[0].options.mnemonic).toBe(MNEMONIC);
    expect(created[0].options.mnemonicPassphrase).toBe("pp");
  });

  it("CONTROL: Core-shaped calls with 1 and 7 args still work", async () => {
    expect((await rpc(port, "createwallet", ["a"])).result.name).toBe("a");
    const r7 = await rpc(port, "createwallet", ["b", false, false, "", false, true, false]);
    expect(r7.result.name).toBe("b");
  });

  it("CONTROL: 10 args is still Core's -1 help error", async () => {
    const res = await rpc(port, "createwallet", ["w", false, false, "", false, true, false, MNEMONIC, "", "x"]);
    expect(res.error.code).toBe(-1);
    expect(res.error.message).toContain("createwallet");
    expect(created.length).toBe(0);
  });

  it("CONTROL: 9 args with a boolean external_signer is still -1 (Core max is 8)", async () => {
    const res = await rpc(port, "createwallet", ["w", false, false, "", false, true, false, false, "x"]);
    expect(res.error.code).toBe(-1);
  });

  it("CONTROL: type check still applies to the Core prefix with a mnemonic", async () => {
    const res = await rpc(port, "createwallet", ["w", "notabool", false, "", false, true, false, MNEMONIC]);
    expect(res.error.code).toBe(-3);
    expect(created.length).toBe(0);
  });
});
