/**
 * Regression tests for the block-download-timeout DISCONNECT CASCADE.
 *
 * Bug (observed live on mainnet 2026-06-19): hotbuns dropped to 2 peers because
 * a single slow block was disconnecting EVERY peer that held it. Root cause:
 * BlockSync.requestBlocks (sync/blocks.ts) races a slow critical block by
 * blasting its getdata to every connected peer ("parallel critical block
 * request"), which — via sendGetData → peer.addBlockInFlight — registers that
 * one block in every peer's in-flight set. PeerManager.checkBlockDownloadTimeouts
 * then looped all peers and disconnected each that had the (raced) block past
 * the timeout, collapsing the whole peer set for one slow block.
 *
 * Fix (manager.ts checkBlockDownloadTimeouts):
 *   - A block held by >1 connected peer is a raced block; clear the stale
 *     in-flight marker on each holder but DO NOT disconnect.
 *   - Only a block in-flight from a single peer is a genuine single-source
 *     stall; disconnect at most ONE such peer per cycle (the most stalled),
 *     mirroring Bitcoin Core's single-staller disconnect + evictStaleTipPeers.
 */

import { describe, expect, test, beforeEach, afterEach, spyOn } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PeerManager, type PeerManagerConfig } from "../p2p/manager.js";
import {
  Peer,
  type PeerConfig,
  type PeerEvents,
  BLOCK_DOWNLOAD_TIMEOUT_BASE_MS,
  BLOCK_DOWNLOAD_TIMEOUT_PER_PEER_MS,
} from "../p2p/peer.js";
import { REGTEST } from "../consensus/params.js";

const HASH_A = "00000000000000000000000000000000000000000000000000000000aaaaaaaa";
const HASH_B = "00000000000000000000000000000000000000000000000000000000bbbbbbbb";
const HASH_C = "00000000000000000000000000000000000000000000000000000000cccccccc";

function peerConfig(port: number): PeerConfig {
  return {
    host: "127.0.0.1",
    port,
    magic: REGTEST.networkMagic,
    protocolVersion: 70016,
    services: 0n,
    userAgent: "/test:0.0.1/",
    bestHeight: 0,
    relay: true,
  };
}

const NOOP_EVENTS: PeerEvents = {
  onConnect: () => {},
  onDisconnect: () => {},
  onMessage: () => {},
  onHandshakeComplete: () => {},
};

/** Build a real (un-connected) Peer in the "connected" state with the given
 *  blocks in-flight, each requested `ageMs` milliseconds ago. */
function connectedPeer(port: number, blocks: string[], ageMs: number): Peer {
  const p = new Peer(peerConfig(port), NOOP_EVENTS);
  p.state = "connected";
  const requestedAt = Date.now() - ageMs;
  for (const h of blocks) {
    p.addBlockInFlight(h);
    p.blocksInFlight.set(h, requestedAt); // backdate so getTimedOutBlock fires
  }
  return p;
}

describe("checkBlockDownloadTimeouts — no mass-disconnect cascade", () => {
  let manager: PeerManager;
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "hotbuns-dlcascade-"));
    const config: PeerManagerConfig = {
      maxOutbound: 10,
      maxInbound: 117,
      params: REGTEST,
      bestHeight: 0,
      datadir: tempDir,
    };
    manager = new PeerManager(config);
  });

  // `peers` and checkBlockDownloadTimeouts are private; reach them for the unit
  // test through an `any` view, the same way the rest of the suite pokes at
  // PeerManager internals.
  const internals = () => manager as any;

  afterEach(async () => {
    await manager.stop();
    await rm(tempDir, { recursive: true, force: true });
  });

  // Timeout for 3 peers = base + 3*per_peer; backdate well past it.
  const wayPastTimeout = () =>
    BLOCK_DOWNLOAD_TIMEOUT_BASE_MS + BLOCK_DOWNLOAD_TIMEOUT_PER_PEER_MS * 10 + 60_000;

  test("a raced block (held by 3 peers) disconnects NONE of them", () => {
    // All three peers hold the SAME block past the timeout — exactly the
    // parallel-critical-request situation that caused the live cascade.
    const pA = connectedPeer(18001, [HASH_A], wayPastTimeout());
    const pB = connectedPeer(18002, [HASH_A], wayPastTimeout());
    const pC = connectedPeer(18003, [HASH_A], wayPastTimeout());
    internals().peers.set("127.0.0.1:18001", pA);
    internals().peers.set("127.0.0.1:18002", pB);
    internals().peers.set("127.0.0.1:18003", pC);

    const disc = spyOn(manager, "disconnectPeer").mockImplementation(() => {});
    (manager as any).checkBlockDownloadTimeouts();

    // Pre-fix: 3 disconnects. Post-fix: 0 — the raced block is cleared instead.
    expect(disc).toHaveBeenCalledTimes(0);
    expect(pA.blocksInFlight.has(HASH_A)).toBe(false);
    expect(pB.blocksInFlight.has(HASH_A)).toBe(false);
    expect(pC.blocksInFlight.has(HASH_A)).toBe(false);
    // All three peers remain in the set.
    expect(internals().peers.size).toBe(3);
  });

  test("a genuine single-source stall disconnects exactly that one peer", () => {
    const pA = connectedPeer(18001, [HASH_A], wayPastTimeout());
    internals().peers.set("127.0.0.1:18001", pA);

    const disc = spyOn(manager, "disconnectPeer").mockImplementation(() => {});
    (manager as any).checkBlockDownloadTimeouts();

    expect(disc).toHaveBeenCalledTimes(1);
    expect(disc).toHaveBeenCalledWith("127.0.0.1:18001", false, "block download timeout");
  });

  test("multiple DISTINCT single-source stalls disconnect at most one per cycle", () => {
    // Two peers each stalling on their own distinct block — both are genuine
    // single-source stalls, but we cap to one disconnect per 45s cycle.
    const pA = connectedPeer(18001, [HASH_B], wayPastTimeout());
    const pC = connectedPeer(18003, [HASH_C], wayPastTimeout() + 5_000); // older → most stalled
    internals().peers.set("127.0.0.1:18001", pA);
    internals().peers.set("127.0.0.1:18003", pC);

    const disc = spyOn(manager, "disconnectPeer").mockImplementation(() => {});
    (manager as any).checkBlockDownloadTimeouts();

    expect(disc).toHaveBeenCalledTimes(1);
    // The most-stalled (oldest outstanding request) is chosen.
    expect(disc).toHaveBeenCalledWith("127.0.0.1:18003", false, "block download timeout");
  });

  test("no timed-out blocks → no disconnects", () => {
    const pA = connectedPeer(18001, [HASH_A], 1_000); // fresh request
    internals().peers.set("127.0.0.1:18001", pA);

    const disc = spyOn(manager, "disconnectPeer").mockImplementation(() => {});
    (manager as any).checkBlockDownloadTimeouts();

    expect(disc).toHaveBeenCalledTimes(0);
    expect(pA.blocksInFlight.has(HASH_A)).toBe(true);
  });
});
