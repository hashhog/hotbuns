/**
 * getnetworkhashps VALUE parity with Bitcoin Core (rpc/mining.cpp
 * GetNetworkHashPS, :65-104).
 *
 * Chain: a deterministic 110-block regtest chain.  Block h has
 *   time = 1296688602 + 600*h + (h*7919 mod 300)
 * and every block (genesis included) has bits 0x207fffff, so
 * chainwork(h) = 2*(h+1).  The expected values were read from a scratch
 * regtest Core v31.99 that mined exactly this chain under setmocktime
 * (2026-10-04).
 *
 * Before the fix every row came back 0: the handler divided BigInt work by
 * BigInt seconds, truncating the ~3.3e-3 H/s rate, and it took only the two
 * endpoint timestamps instead of Core's min/max over the window.
 */
import { describe, it, expect } from "bun:test";
import { RPCServer, arithGetDouble } from "../rpc/server.js";
import { REGTEST } from "../consensus/params.js";

const TIP = 110;
const timeAt = (h: number) => 1296688602 + 600 * h + ((h * 7919) % 300);
const entryAt = (h: number) => ({
  hash: Buffer.alloc(32, h & 0xff),
  height: h,
  chainWork: BigInt(2 * (h + 1)),
  header: { timestamp: timeAt(h) },
});

function makeServer(): RPCServer {
  const deps: any = {
    chainState: { getBestBlock: () => ({ hash: Buffer.alloc(32), height: TIP, chainWork: 222n }) },
    mempool: {},
    peerManager: {},
    feeEstimator: {},
    headerSync: {
      getHeaderByHeight: (h: number) => (h >= 0 && h <= TIP ? entryAt(h) : undefined),
    },
    db: {},
    params: REGTEST,
  };
  // Not started: the handler is called directly, no port is bound.
  return new RPCServer({ port: 1, host: "127.0.0.1", noAuth: true } as any, deps);
}

// [nblocks, height, Core's answer]
const CORE: Array<[number, number, number]> = [
  [120, -1, 0.00332376491917208], // lookup clamps to 110: walks to genesis
  [120, 50, 0.003305785123966942], // the R5 probe shape: nblocks >= height
  [50, 50, 0.003305785123966942],
  [49, 50, 0.003318546612034811],
  [10, 50, 0.00333889816360601],
  [1, 1, 0.002781641168289291],
  [-1, -1, 0.00332376491917208],
  [-1, 30, 0.003284072249589491],
  [1000, 110, 0.00332376491917208],
  [110, 110, 0.00332376491917208],
  [109, 110, 0.003329718501321196],
  [3, 100, 0.003231017770597738],
];

describe("getnetworkhashps value == Core on a regtest chain", () => {
  const server = makeServer() as any;
  for (const [nb, ht, want] of CORE) {
    it(`getnetworkhashps ${nb} ${ht} == ${want}`, async () => {
      const got = await server.getNetworkHashPS([nb, ht]);
      expect(typeof got).toBe("number");
      expect(Math.abs(got - want)).toBeLessThanOrEqual(1e-15 * want);
    });
  }
  it("height 0 returns 0 (Core: !pb->nHeight)", async () => {
    expect(await server.getNetworkHashPS([120, 0])).toBe(0);
  });
});

describe("arithGetDouble == Core arith_uint256::getdouble", () => {
  it("small and limb-crossing values", () => {
    expect(arithGetDouble(0n)).toBe(0);
    expect(arithGetDouble(222n)).toBe(222);
    expect(arithGetDouble(1n << 32n)).toBe(4294967296);
    expect(arithGetDouble((1n << 200n) + 12345n)).toBe(2 ** 200);
  });
});
