/**
 * cffix-hotbuns-outbound-addr-selection — an addr sender must not be able to
 * steer every outbound slot.
 *
 * Bug (fingerprint hotbuns-p2p-outbound-select-deterministic-lastseen):
 * `getCandidateAddresses` sorted the flat `knownAddresses` map by NODE_WITNESS,
 * then NODE_NETWORK, then banScore, then `lastSeen` (newest first) and returned
 * the top N. `lastSeen` is peer-supplied (accepted up to now+600 s), so one peer
 * advertising its own addresses stamped now+500 s with NODE_NETWORK|NODE_WITNESS
 * took every outbound slot, every time.
 *
 * Core: ThreadOpenConnections draws each candidate with addrman.Select()
 * (addrman.cpp AddrManImpl::Select_): new or tried table at random, then a
 * random bucket and position, accepted with a GetChance() quality factor. A new
 * table entry's bucket is keyed by the SOURCE group (GetNewBucket), so one
 * source reaches at most ADDRMAN_NEW_BUCKETS_PER_SOURCE_GROUP (64) of the 1024
 * new buckets however many addresses it sends.
 *
 * The test drives the real addr ingestion path (handleAddrMessage) from 50
 * honest sources and one attacker source, then samples outbound candidate
 * selection for 8 slots 200 times.
 */

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { PeerManager, ServiceFlags, type PeerManagerConfig } from "../p2p/manager.js";
import { AddrMan } from "../p2p/addrman.js";
import { REGTEST } from "../consensus/params.js";

let dir: string;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "hotbuns-cffix-outbound-"));
});

afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

function makeManager(): any {
  const config: PeerManagerConfig = {
    maxOutbound: 8,
    maxInbound: 117,
    params: REGTEST,
    bestHeight: 0,
    datadir: dir,
  };
  return new PeerManager(config) as any;
}

function mapped(ip: string): Buffer {
  const b = Buffer.alloc(16);
  b[10] = 0xff;
  b[11] = 0xff;
  ip.split(".").forEach((o, i) => (b[12 + i] = Number(o)));
  return b;
}

function stubPeer(host: string): any {
  return { host, port: 8333, state: "connected", wantsAddrV2: false, send: () => true };
}

const WITNESS_NETWORK = ServiceFlags.NODE_NETWORK | ServiceFlags.NODE_WITNESS;

/**
 * Feed `ips` to the manager as one addr message from `source`. The source is
 * given a full token bucket (as after our getaddr, which grants 1000 tokens) so
 * the rate limiter does not mask the selection behaviour under test.
 */
function feedAddrs(pm: any, source: string, ips: string[], timestamp: (i: number) => number): void {
  const peer = stubPeer(source);
  pm.addrTokenBucket.set(`${peer.host}:${peer.port}`, { tokens: 1e6, ts: Date.now() });
  const addrs = ips.map((ip, i) => ({
    timestamp: timestamp(i),
    addr: { services: WITNESS_NETWORK, ip: mapped(ip), port: 8333 },
  }));
  pm.handleAddrMessage(peer, { addrs });
}

/** Honest address i (unique, one /16 each) inside 11.0.0.0/8 .. 60.0.0.0/8. */
function honestIp(i: number): string {
  return `${11 + (i % 50)}.${Math.floor(i / 50)}.${(i % 7) + 1}.1`;
}

/** Attacker address i (unique, one /16 each: the worst case) in 61-110/8. */
function attackerIp(i: number): string {
  return `${61 + (i % 50)}.${Math.floor(i / 50)}.3.4`;
}

function seed(pm: any): Set<string> {
  const now = Math.floor(Date.now() / 1000);
  // 1,000 honest addresses from 50 distinct sources (distinct /16s), 20 each,
  // stamped a few minutes to a few hours in the past.
  for (let s = 0; s < 50; s++) {
    const ips: string[] = [];
    for (let j = 0; j < 20; j++) ips.push(honestIp(s * 20 + j));
    feedAddrs(pm, `200.${s}.1.1`, ips, (j) => now - 300 - ((s * 20 + j) % 10_000));
  }
  // 1,000 attacker addresses from ONE source, all stamped now+500 s (inside
  // the accepted now+600 s window) with NODE_WITNESS|NODE_NETWORK.
  const attacker: string[] = [];
  for (let i = 0; i < 1000; i++) attacker.push(attackerIp(i));
  feedAddrs(pm, "203.0.113.7", attacker, () => now + 500);
  return new Set(attacker.map((ip) => `${ip}:8333`));
}

describe("cffix: outbound address selection is not steerable by one addr sender", () => {
  test("sanity: both populations were stored", () => {
    const pm = makeManager();
    const attacker = seed(pm);
    let honest = 0;
    let bad = 0;
    for (const key of pm.knownAddresses.keys()) {
      if (attacker.has(key)) bad++;
      else honest++;
    }
    expect(honest).toBe(1000);
    expect(bad).toBe(1000);
  });

  test("attacker share of 8 outbound candidates over 200 draws is below 50%", () => {
    const pm = makeManager();
    const attacker = seed(pm);
    let picked = 0;
    let fromAttacker = 0;
    for (let iter = 0; iter < 200; iter++) {
      const cands = pm.getCandidateAddresses(8);
      for (const c of cands) {
        picked++;
        if (attacker.has(`${c.host}:${c.port}`)) fromAttacker++;
      }
    }
    // The denominator must be real: every iteration filled all 8 slots.
    expect(picked).toBe(200 * 8);
    const share = fromAttacker / picked;
    expect(share).toBeLessThan(0.5);
  });

  test("selection is random: 200 draws do not return the same 8 addresses", () => {
    const pm = makeManager();
    seed(pm);
    const distinct = new Set<string>();
    for (let iter = 0; iter < 200; iter++) {
      for (const c of pm.getCandidateAddresses(8)) distinct.add(`${c.host}:${c.port}`);
    }
    expect(distinct.size).toBeGreaterThan(8);
  });

  test("addr ingestion buckets a learned address by the advertising peer's group", () => {
    // Core GetNewBucket is keyed by group(source). The relaying peer, not the
    // address itself, must be the source, or a single sender spreads over all
    // 1024 new buckets.
    const pm = makeManager();
    const now = Math.floor(Date.now() / 1000);
    feedAddrs(pm, "203.0.113.7", ["100.1.2.3"], () => now);
    const entry = pm.addrMan.getEntries(false).find((e: any) => e.host === "100.1.2.3");
    expect(entry).toBeDefined();
    expect(entry.source).toBe("203.0.113.7");
  });

  test("one source reaches at most 64 new buckets however many addresses it sends", () => {
    const pm = makeManager();
    const attacker = seed(pm);
    const am: AddrMan = pm.addrMan;
    const buckets = new Set<number>();
    for (const key of attacker) {
      const [host, port] = key.split(":");
      const slot = am.newSlotOf(host!, Number(port));
      if (slot) buckets.add(slot.bucket);
    }
    expect(buckets.size).toBeGreaterThan(0);
    expect(buckets.size).toBeLessThanOrEqual(64);
  });

  test("DNS-seed results are drawn too: one later addr sender cannot crowd them out", async () => {
    // Core ThreadDNSAddressSeed adds seed results to addrman
    // (addrman.Add(vAdd, resolveSource)), so Select() weighs them with every
    // other entry. If they bypass the addrman, a cold-started node's outbound
    // draw is filled entirely by the first addr sender. 200 seed addresses
    // (several seeds of ~25 each, as on mainnet) occupy ~180 new buckets
    // against the sender's 64, so its share should be about a quarter.
    const pm = makeManager();
    const seeds: string[] = [];
    for (let i = 0; i < 200; i++) seeds.push(`${11 + (i % 50)}.${200 + Math.floor(i / 50)}.${i + 1}.9`);
    pm.resolveDNSSeeds = async () => seeds;
    pm.fillConnections = async () => {};
    await pm.start();
    try {
      // A few may lose a new-bucket slot collision (Core AddSingle drops those
      // too); before the fix none were held.
      const held = seeds.filter((ip) => pm.addrMan.findAddressEntry(ip, 18444) !== null).length;
      expect(held).toBeGreaterThan(seeds.length * 0.9);
      const now = Math.floor(Date.now() / 1000);
      const attacker: string[] = [];
      for (let i = 0; i < 1000; i++) attacker.push(attackerIp(i));
      feedAddrs(pm, "203.0.113.7", attacker, () => now + 500);
      const bad = new Set(attacker.map((ip) => `${ip}:8333`));
      let picked = 0;
      let fromAttacker = 0;
      for (let iter = 0; iter < 200; iter++) {
        for (const c of pm.getCandidateAddresses(8)) {
          picked++;
          if (bad.has(`${c.host}:${c.port}`)) fromAttacker++;
        }
      }
      expect(picked).toBe(200 * 8);
      expect(fromAttacker / picked).toBeLessThan(0.5);
    } finally {
      await pm.stop();
    }
  });

  test("candidate selection still skips connected and recently failed addresses", () => {
    const pm = makeManager();
    const now = Math.floor(Date.now() / 1000);
    feedAddrs(pm, "203.0.113.7", ["100.1.2.3", "100.2.2.3", "100.3.2.3"], () => now);
    pm.peers.set("100.1.2.3:8333", stubPeer("100.1.2.3"));
    pm.knownAddresses.get("100.2.2.3:8333").lastConnected = Date.now();
    for (let iter = 0; iter < 20; iter++) {
      const keys = pm.getCandidateAddresses(8).map((c: any) => `${c.host}:${c.port}`);
      expect(keys).toEqual(["100.3.2.3:8333"]);
    }
  });
});
