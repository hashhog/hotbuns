/**
 * Campaign `base_tail_headers` parse + load (receipt 2026-09-11).
 *
 * Snapshot-boot used to seed only genesis + the base (`hdrs=2`). The first
 * retarget whose period-start sits below the base (60,480 needs 58,464 for
 * base 60,000) then failed. This pins that HASHHOG_CAMPAIGN_ASSUMEUTXO
 * consumes the 80-byte band and rejects a broken chain.
 */

import { describe, test, expect, afterEach } from "bun:test";
import { mkdtemp, writeFile, rm } from "fs/promises";
import { tmpdir } from "os";
import { join } from "path";
import {
  loadCampaignAssumeutxo,
  parseBaseTailHeaders,
} from "./snapshot.js";
import { REGTEST, type ConsensusParams } from "../consensus/params.js";
import { serializeBlockHeader, getBlockHash, type BlockHeader } from "../validation/block.js";

function displayHex(internal: Buffer): string {
  return Buffer.from(internal).reverse().toString("hex");
}

function linkedRaw(n: number, bits = 0x1d00ffff, startTime = 1_230_000_000): Buffer[] {
  const raw: Buffer[] = [];
  let prev = Buffer.alloc(32, 0);
  for (let i = 0; i < n; i++) {
    const header: BlockHeader = {
      version: 1,
      prevBlock: prev,
      merkleRoot: Buffer.alloc(32, i + 1),
      timestamp: startTime + i * 600,
      bits,
      nonce: i,
    };
    const buf = serializeBlockHeader(header);
    raw.push(buf);
    prev = getBlockHash(header);
  }
  return raw;
}

function cloneParams(): ConsensusParams {
  return { ...REGTEST, assumeutxo: new Map(REGTEST.assumeutxo) };
}

describe("parseBaseTailHeaders", () => {
  test("empty list is a no-op", () => {
    expect(parseBaseTailHeaders([], Buffer.alloc(32, 1), 100, 0)).toEqual([]);
  });

  test("valid chain ending at expected base hash", () => {
    const raw = linkedRaw(3);
    const lastHash = getBlockHash({
      version: 1,
      prevBlock: raw[2].subarray(4, 36),
      merkleRoot: raw[2].subarray(36, 68),
      timestamp: raw[2].readUInt32LE(68),
      bits: raw[2].readUInt32LE(72),
      nonce: raw[2].readUInt32LE(76),
    });
    // getBlockHash of the deserialized last header
    const last = raw[2];
    const lastHeader: BlockHeader = {
      version: last.readInt32LE(0),
      prevBlock: Buffer.from(last.subarray(4, 36)),
      merkleRoot: Buffer.from(last.subarray(36, 68)),
      timestamp: last.readUInt32LE(68),
      bits: last.readUInt32LE(72),
      nonce: last.readUInt32LE(76),
    };
    const expected = getBlockHash(lastHeader);
    const got = parseBaseTailHeaders(
      raw.map((b) => b.toString("hex")),
      expected,
      100,
      0,
    );
    expect(got.length).toBe(3);
    expect(got[2].equals(raw[2])).toBe(true);
    expect(expected.equals(lastHash)).toBe(true);
  });

  test("broken prev-link is rejected", () => {
    const raw = linkedRaw(3);
    raw[2] = Buffer.from(raw[2]);
    raw[2][4] ^= 0xff;
    const lastHeader: BlockHeader = {
      version: raw[2].readInt32LE(0),
      prevBlock: Buffer.from(raw[2].subarray(4, 36)),
      merkleRoot: Buffer.from(raw[2].subarray(36, 68)),
      timestamp: raw[2].readUInt32LE(68),
      bits: raw[2].readUInt32LE(72),
      nonce: raw[2].readUInt32LE(76),
    };
    expect(() =>
      parseBaseTailHeaders(
        raw.map((b) => b.toString("hex")),
        getBlockHash(lastHeader),
        100,
        0,
      ),
    ).toThrow(/does not chain/);
  });

  test("last header must hash to the entry blockhash", () => {
    const raw = linkedRaw(2);
    expect(() =>
      parseBaseTailHeaders(
        raw.map((b) => b.toString("hex")),
        Buffer.alloc(32, 0xab),
        100,
        0,
      ),
    ).toThrow(/last header hashes to/);
  });

  test("band longer than base height is rejected", () => {
    const raw = linkedRaw(3);
    const last = raw[2];
    const lastHeader: BlockHeader = {
      version: last.readInt32LE(0),
      prevBlock: Buffer.from(last.subarray(4, 36)),
      merkleRoot: Buffer.from(last.subarray(36, 68)),
      timestamp: last.readUInt32LE(68),
      bits: last.readUInt32LE(72),
      nonce: last.readUInt32LE(76),
    };
    expect(() =>
      parseBaseTailHeaders(raw.map((b) => b.toString("hex")), getBlockHash(lastHeader), 1, 0),
    ).toThrow(/below genesis/);
  });
});

describe("loadCampaignAssumeutxo base_tail_headers", () => {
  const prevEnv = process.env.HASHHOG_CAMPAIGN_ASSUMEUTXO;
  const dirs: string[] = [];

  afterEach(async () => {
    if (prevEnv === undefined) delete process.env.HASHHOG_CAMPAIGN_ASSUMEUTXO;
    else process.env.HASHHOG_CAMPAIGN_ASSUMEUTXO = prevEnv;
    for (const d of dirs.splice(0)) {
      await rm(d, { recursive: true, force: true });
    }
  });

  async function writeFixture(body: unknown): Promise<string> {
    const dir = await mkdtemp(join(tmpdir(), "hotbuns-campaign-tail-"));
    dirs.push(dir);
    const path = join(dir, "campaign-entry.json");
    await writeFile(path, JSON.stringify(body));
    return path;
  }

  test("missing key leaves baseTailHeaders unset (pre-tail behaviour)", async () => {
    const path = await writeFixture([
      {
        height: 50000,
        blockhash: "11".repeat(32),
        hash_serialized: "22".repeat(32),
        m_chain_tx_count: 1,
      },
    ]);
    process.env.HASHHOG_CAMPAIGN_ASSUMEUTXO = path;
    const params = cloneParams();
    await loadCampaignAssumeutxo(params);
    const au = [...params.assumeutxo!.values()].find((e) => e.height === 50000);
    expect(au).toBeDefined();
    expect(au!.baseTailHeaders).toBeUndefined();
  });

  test("valid band is stored and last header is the base", async () => {
    const raw = linkedRaw(5);
    const last = raw[4];
    const lastHeader: BlockHeader = {
      version: last.readInt32LE(0),
      prevBlock: Buffer.from(last.subarray(4, 36)),
      merkleRoot: Buffer.from(last.subarray(36, 68)),
      timestamp: last.readUInt32LE(68),
      bits: last.readUInt32LE(72),
      nonce: last.readUInt32LE(76),
    };
    const baseHash = getBlockHash(lastHeader);
    const path = await writeFixture([
      {
        height: 50000,
        blockhash: displayHex(baseHash),
        hash_serialized: "22".repeat(32),
        m_chain_tx_count: 1,
        base_tail_headers: raw.map((b) => b.toString("hex")),
      },
    ]);
    process.env.HASHHOG_CAMPAIGN_ASSUMEUTXO = path;
    const params = cloneParams();
    await loadCampaignAssumeutxo(params);
    const au = [...params.assumeutxo!.values()].find((e) => e.height === 50000);
    expect(au).toBeDefined();
    expect(au!.baseTailHeaders).toBeDefined();
    expect(au!.baseTailHeaders!.length).toBe(5);
    expect(au!.baseHeader!.equals(raw[4])).toBe(true);
    expect(au!.blockHash.equals(baseHash)).toBe(true);
  });
});
