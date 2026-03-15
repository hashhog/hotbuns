/**
 * Tests for misbehavior scoring and ban management.
 *
 * Tests cover:
 * - Peer misbehavior score accumulation
 * - Automatic banning at threshold
 * - BanManager persistence
 * - RPC commands: listbanned, setban, clearbanned
 */

import { describe, expect, test, beforeEach, afterEach } from "bun:test";
import { Peer, type PeerConfig, type PeerEvents, type OnBanCallback } from "../p2p/peer.js";
import { BanManager, DEFAULT_BAN_TIME, type BanEntry } from "../p2p/banman.js";
import { BanScores } from "../p2p/manager.js";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

describe("Peer misbehavior scoring", () => {
  const createMockPeerConfig = (): PeerConfig => ({
    host: "127.0.0.1",
    port: 8333,
    magic: 0xd9b4bef9,
    protocolVersion: 70016,
    services: 1n,
    userAgent: "/test:0.0.1/",
    bestHeight: 0,
    relay: true,
  });

  const createMockEvents = (): PeerEvents => ({
    onMessage: () => {},
    onConnect: () => {},
    onDisconnect: () => {},
    onHandshakeComplete: () => {},
  });

  test("initial misbehavior score is 0", () => {
    const peer = new Peer(createMockPeerConfig(), createMockEvents());
    expect(peer.misbehaviorScore).toBe(0);
    expect(peer.shouldDisconnect).toBe(false);
  });

  test("misbehaving adds to score", () => {
    const peer = new Peer(createMockPeerConfig(), createMockEvents());

    peer.misbehaving(10, "test violation");
    expect(peer.misbehaviorScore).toBe(10);
    expect(peer.shouldDisconnect).toBe(false);

    peer.misbehaving(20, "another violation");
    expect(peer.misbehaviorScore).toBe(30);
    expect(peer.shouldDisconnect).toBe(false);
  });

  test("score reaching 100 triggers shouldDisconnect", () => {
    const peer = new Peer(createMockPeerConfig(), createMockEvents());

    peer.misbehaving(50, "first");
    expect(peer.shouldDisconnect).toBe(false);

    peer.misbehaving(50, "second");
    expect(peer.misbehaviorScore).toBe(100);
    expect(peer.shouldDisconnect).toBe(true);
  });

  test("score exceeding 100 triggers shouldDisconnect", () => {
    const peer = new Peer(createMockPeerConfig(), createMockEvents());

    peer.misbehaving(150, "instant ban");
    expect(peer.misbehaviorScore).toBe(150);
    expect(peer.shouldDisconnect).toBe(true);
  });

  test("onBan callback is invoked when threshold reached", () => {
    let banCallbackInvoked = false;
    let bannedPeer: Peer | null = null;
    let banReason = "";

    const onBan: OnBanCallback = (peer, reason) => {
      banCallbackInvoked = true;
      bannedPeer = peer;
      banReason = reason;
    };

    const peer = new Peer(createMockPeerConfig(), createMockEvents(), onBan);
    peer.misbehaving(100, "invalid block header");

    expect(banCallbackInvoked).toBe(true);
    expect(bannedPeer).toBe(peer);
    expect(banReason).toBe("invalid block header");
  });

  test("BanScores constants have expected values", () => {
    expect(BanScores.INVALID_BLOCK_HEADER).toBe(100);
    expect(BanScores.INVALID_BLOCK).toBe(100);
    expect(BanScores.INVALID_TRANSACTION).toBe(10);
    expect(BanScores.UNSOLICITED_MESSAGE).toBe(20);
    expect(BanScores.PROTOCOL_VIOLATION).toBe(10);
  });

  test("invalid block header causes instant ban", () => {
    const peer = new Peer(createMockPeerConfig(), createMockEvents());

    peer.misbehaving(BanScores.INVALID_BLOCK_HEADER, "header with invalid proof of work");

    expect(peer.misbehaviorScore).toBe(100);
    expect(peer.shouldDisconnect).toBe(true);
  });

  test("multiple small violations accumulate to ban", () => {
    const peer = new Peer(createMockPeerConfig(), createMockEvents());

    // 10 invalid transaction reports
    for (let i = 0; i < 10; i++) {
      peer.misbehaving(BanScores.INVALID_TRANSACTION, `invalid tx ${i}`);
    }

    expect(peer.misbehaviorScore).toBe(100);
    expect(peer.shouldDisconnect).toBe(true);
  });
});

describe("BanManager", () => {
  let tempDir: string;
  let banManager: BanManager;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "hotbuns-test-"));
    banManager = new BanManager(tempDir);
  });

  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  test("initially no addresses are banned", () => {
    expect(banManager.isBanned("192.168.1.1")).toBe(false);
    expect(banManager.getBanned().length).toBe(0);
  });

  test("ban adds address to banned list", () => {
    banManager.ban("192.168.1.1", DEFAULT_BAN_TIME, "test ban");

    expect(banManager.isBanned("192.168.1.1")).toBe(true);
    expect(banManager.isBanned("192.168.1.2")).toBe(false);

    const banned = banManager.getBanned();
    expect(banned.length).toBe(1);
    expect(banned[0].address).toBe("192.168.1.1");
    expect(banned[0].reason).toBe("test ban");
  });

  test("unban removes address from banned list", () => {
    banManager.ban("192.168.1.1", DEFAULT_BAN_TIME, "test ban");
    expect(banManager.isBanned("192.168.1.1")).toBe(true);

    const removed = banManager.unban("192.168.1.1");
    expect(removed).toBe(true);
    expect(banManager.isBanned("192.168.1.1")).toBe(false);
  });

  test("unban returns false for non-banned address", () => {
    const removed = banManager.unban("192.168.1.1");
    expect(removed).toBe(false);
  });

  test("clearBanned removes all bans", () => {
    banManager.ban("192.168.1.1", DEFAULT_BAN_TIME, "test1");
    banManager.ban("192.168.1.2", DEFAULT_BAN_TIME, "test2");
    banManager.ban("192.168.1.3", DEFAULT_BAN_TIME, "test3");

    expect(banManager.getBanned().length).toBe(3);

    banManager.clearBanned();

    expect(banManager.getBanned().length).toBe(0);
    expect(banManager.isBanned("192.168.1.1")).toBe(false);
  });

  test("expired bans are not reported", async () => {
    // Ban for 1 second
    banManager.ban("192.168.1.1", 1, "short ban");
    expect(banManager.isBanned("192.168.1.1")).toBe(true);

    // Wait for expiration
    await new Promise((resolve) => setTimeout(resolve, 1100));

    expect(banManager.isBanned("192.168.1.1")).toBe(false);
    expect(banManager.getBanned().length).toBe(0);
  });

  test("persistence: save and load", async () => {
    banManager.ban("192.168.1.1", DEFAULT_BAN_TIME, "reason1");
    banManager.ban("10.0.0.1", DEFAULT_BAN_TIME, "reason2");

    await banManager.save();

    // Create new manager and load
    const newManager = new BanManager(tempDir);
    await newManager.load();

    expect(newManager.isBanned("192.168.1.1")).toBe(true);
    expect(newManager.isBanned("10.0.0.1")).toBe(true);
    expect(newManager.isBanned("172.16.0.1")).toBe(false);

    const banned = newManager.getBanned();
    expect(banned.length).toBe(2);
  });

  test("default ban time is 24 hours", () => {
    expect(DEFAULT_BAN_TIME).toBe(24 * 60 * 60);
  });

  test("ban with absolute timestamp", () => {
    const futureTimestamp = Math.floor(Date.now() / 1000) + 3600; // 1 hour from now
    banManager.ban("192.168.1.1", futureTimestamp, "absolute ban", true);

    expect(banManager.isBanned("192.168.1.1")).toBe(true);

    const banned = banManager.getBanned();
    expect(banned[0].banUntil).toBe(futureTimestamp);
  });

  test("longer ban replaces shorter ban", () => {
    const now = Math.floor(Date.now() / 1000);

    banManager.ban("192.168.1.1", 3600, "short ban"); // 1 hour
    const banned1 = banManager.getBanned();
    const firstBanUntil = banned1[0].banUntil;

    banManager.ban("192.168.1.1", 7200, "longer ban"); // 2 hours
    const banned2 = banManager.getBanned();
    const secondBanUntil = banned2[0].banUntil;

    expect(secondBanUntil).toBeGreaterThan(firstBanUntil);
    expect(banned2[0].reason).toBe("longer ban");
  });

  test("shorter ban does not replace longer ban", () => {
    banManager.ban("192.168.1.1", 7200, "longer ban"); // 2 hours
    const banned1 = banManager.getBanned();
    const firstBanUntil = banned1[0].banUntil;

    banManager.ban("192.168.1.1", 3600, "shorter ban"); // 1 hour
    const banned2 = banManager.getBanned();
    const secondBanUntil = banned2[0].banUntil;

    // Should keep the longer ban
    expect(secondBanUntil).toBe(firstBanUntil);
    expect(banned2[0].reason).toBe("longer ban");
  });

  test("sweepBanned removes expired entries", async () => {
    // Ban one for 1 second, another for 1 hour
    banManager.ban("192.168.1.1", 1, "short");
    banManager.ban("192.168.1.2", 3600, "long");

    expect(banManager.getBanned().length).toBe(2);

    // Wait for first to expire
    await new Promise((resolve) => setTimeout(resolve, 1100));

    banManager.sweepBanned();

    const remaining = banManager.getBanned();
    expect(remaining.length).toBe(1);
    expect(remaining[0].address).toBe("192.168.1.2");
  });
});

describe("BanManager file format", () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "hotbuns-test-"));
  });

  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  test("banlist.json has correct structure", async () => {
    const banManager = new BanManager(tempDir);
    banManager.ban("192.168.1.1", DEFAULT_BAN_TIME, "test reason");
    await banManager.save();

    const file = Bun.file(join(tempDir, "banlist.json"));
    const content = await file.text();
    const data = JSON.parse(content);

    expect(data.version).toBe(1);
    expect(Array.isArray(data.bans)).toBe(true);
    expect(data.bans.length).toBe(1);
    expect(data.bans[0].address).toBe("192.168.1.1");
    expect(data.bans[0].reason).toBe("test reason");
    expect(typeof data.bans[0].banCreated).toBe("number");
    expect(typeof data.bans[0].banUntil).toBe("number");
  });

  test("handles missing banlist.json gracefully", async () => {
    const banManager = new BanManager(tempDir);
    await banManager.load(); // Should not throw

    expect(banManager.getBanned().length).toBe(0);
  });

  test("handles corrupted banlist.json gracefully", async () => {
    // Write invalid JSON
    await Bun.write(join(tempDir, "banlist.json"), "{ invalid json }}}");

    const banManager = new BanManager(tempDir);
    await banManager.load(); // Should not throw

    expect(banManager.getBanned().length).toBe(0);
  });

  test("handles unknown version gracefully", async () => {
    // Write with unknown version
    await Bun.write(
      join(tempDir, "banlist.json"),
      JSON.stringify({ version: 999, bans: [] })
    );

    const banManager = new BanManager(tempDir);
    await banManager.load(); // Should not throw

    expect(banManager.getBanned().length).toBe(0);
  });
});
