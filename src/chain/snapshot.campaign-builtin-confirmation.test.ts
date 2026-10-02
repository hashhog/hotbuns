/**
 * HASHHOG_CAMPAIGN_ASSUMEUTXO: an entry IDENTICAL to a built-in row is a
 * confirmation, not a collision (R4 slice 910000-920000 was BLOCKED on it).
 *
 * The soak-910000 fixture was minted by dumping a Core clone at 910,000 and
 * carries exactly the commitment Core hardcodes there (kernel/chainparams.cpp
 * m_assumeutxo_data, mirrored in consensus/params.ts MAINNET.assumeutxo).
 * Identical (height, blockhash, hash_serialized, m_chain_tx_count) is
 * accepted and only fills gaps in the row; anything else at a built-in
 * height or blockhash is still refused.
 */

import { describe, test, expect, afterEach } from "bun:test";
import { mkdtemp, writeFile, rm } from "fs/promises";
import { tmpdir } from "os";
import { join } from "path";
import { loadCampaignAssumeutxo } from "./snapshot.js";
import { MAINNET, type ConsensusParams } from "../consensus/params.js";

// The real soak-910000 commitment (tools/boundary-blocks/soak-910000/campaign-entry.json).
const H = 910000;
const BLOCKHASH = "0000000000000000000108970acb9522ffd516eae17acddcb1bd16469194a821";
const HASH_SERIALIZED = "4daf8a17b4902498c5787966a2b51c613acdab5df5db73f196fa59a4da2f1568";
const NCHAINTX = 1226586151;
const BASE_HEADER =
  "00a0572be06d4f01a2ed2228dec965539cc8b96512ccde7d2824010000000000000000006f28c30dc748f6b1430fb2b9a5a94b5b34a5df6e318c6cc5c310a1a35b432b59a3ab9d68b32c021719d103e9";
const CHAINWORK = "0000000000000000000000000000000000000000da15bcbf68ad7fed795c504f";
const KEY = Buffer.from(BLOCKHASH, "hex").reverse().toString("hex");

function cloneMainnet(): ConsensusParams {
  return { ...MAINNET, assumeutxo: new Map(MAINNET.assumeutxo) };
}

function entry(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    height: H,
    blockhash: BLOCKHASH,
    hash_serialized: HASH_SERIALIZED,
    m_chain_tx_count: NCHAINTX,
    base_header: BASE_HEADER,
    chainwork: CHAINWORK,
    ...over,
  };
}

describe("loadCampaignAssumeutxo: built-in confirmation vs collision", () => {
  const prevEnv = process.env.HASHHOG_CAMPAIGN_ASSUMEUTXO;
  const dirs: string[] = [];

  afterEach(async () => {
    if (prevEnv === undefined) delete process.env.HASHHOG_CAMPAIGN_ASSUMEUTXO;
    else process.env.HASHHOG_CAMPAIGN_ASSUMEUTXO = prevEnv;
    for (const d of dirs.splice(0)) await rm(d, { recursive: true, force: true });
  });

  async function useFixture(body: unknown): Promise<void> {
    const dir = await mkdtemp(join(tmpdir(), "hotbuns-campaign-confirm-"));
    dirs.push(dir);
    const path = join(dir, "campaign-entry.json");
    await writeFile(path, JSON.stringify(body));
    process.env.HASHHOG_CAMPAIGN_ASSUMEUTXO = path;
  }

  test("built-in table really has the 910000 row this suite relies on", () => {
    const row = MAINNET.assumeutxo!.get(KEY);
    expect(row).toBeDefined();
    expect(row!.height).toBe(H);
    expect(row!.baseHeader).toBeUndefined();
  });

  test("identical entry is accepted; commitment kept, gaps filled, built-in not mutated", async () => {
    await useFixture([entry()]);
    const params = cloneMainnet();
    const builtin = MAINNET.assumeutxo!.get(KEY)!;
    const sizeBefore = params.assumeutxo!.size;
    await loadCampaignAssumeutxo(params);
    expect(params.assumeutxo!.size).toBe(sizeBefore);
    const row = params.assumeutxo!.get(KEY)!;
    expect(row.height).toBe(H);
    expect(row.hashSerialized.equals(builtin.hashSerialized)).toBe(true);
    expect(row.nChainTx).toBe(builtin.nChainTx);
    expect(row.baseHeader!.toString("hex")).toBe(BASE_HEADER);
    expect(row.chainWork).toBe(BigInt("0x" + CHAINWORK));
    // The shared MAINNET row object is untouched.
    expect(builtin.baseHeader).toBeUndefined();
    expect(MAINNET.assumeutxo!.get(KEY)).toBe(builtin);
  });

  test("the real soak-910000 fixture file is accepted against MAINNET", async () => {
    const abs = "/home/work/hashhog/tools/boundary-blocks/soak-910000/campaign-entry.json";
    const file = Bun.file(abs);
    if (!(await file.exists())) {
      console.warn(`skip: ${abs} not on this machine`);
      return;
    }
    process.env.HASHHOG_CAMPAIGN_ASSUMEUTXO = abs;
    const params = cloneMainnet();
    await loadCampaignAssumeutxo(params);
    const row = params.assumeutxo!.get(KEY)!;
    expect(row.baseTailHeaders!.length).toBeGreaterThan(0);
    expect(row.baseHeader!.toString("hex")).toBe(BASE_HEADER);
  });

  test("uppercase hex in the identical entry is still a confirmation", async () => {
    await useFixture([
      entry({ blockhash: BLOCKHASH.toUpperCase(), hash_serialized: HASH_SERIALIZED.toUpperCase() }),
    ]);
    const params = cloneMainnet();
    await loadCampaignAssumeutxo(params);
    expect(params.assumeutxo!.get(KEY)!.baseHeader).toBeDefined();
  });

  test("different hash_serialized at the built-in height is refused", async () => {
    await useFixture([entry({ hash_serialized: "22".repeat(32) })]);
    await expect(loadCampaignAssumeutxo(cloneMainnet())).rejects.toThrow(/collides/);
  });

  test("different m_chain_tx_count at the built-in height is refused", async () => {
    await useFixture([entry({ m_chain_tx_count: NCHAINTX + 1 })]);
    await expect(loadCampaignAssumeutxo(cloneMainnet())).rejects.toThrow(/collides/);
  });

  test("different blockhash at the built-in height is refused", async () => {
    await useFixture([
      entry({ blockhash: "11".repeat(32), base_header: undefined, chainwork: undefined }),
    ]);
    await expect(loadCampaignAssumeutxo(cloneMainnet())).rejects.toThrow(/collides/);
  });

  test("built-in blockhash at a different height is refused", async () => {
    await useFixture([entry({ height: H + 1, base_header: undefined, chainwork: undefined })]);
    await expect(loadCampaignAssumeutxo(cloneMainnet())).rejects.toThrow(/collides/);
  });

  test("identical commitment with a base_header that does not hash to it is refused", async () => {
    const bad = BASE_HEADER.slice(0, -2) + "00";
    await useFixture([entry({ base_header: bad })]);
    await expect(loadCampaignAssumeutxo(cloneMainnet())).rejects.toThrow(/hashes to/);
  });

  test("a duplicated identical entry within the file is refused", async () => {
    await useFixture([entry(), entry()]);
    await expect(loadCampaignAssumeutxo(cloneMainnet())).rejects.toThrow(/duplicates/);
  });
});
