/**
 * W141 — ZMQ + REST + Notification scripts audit (hotbuns).
 *
 * Discovery-only: NO production code changes. Tests pin existing
 * behavior so a follow-up FIX wave can flip the assertions. Where a
 * test ASSERTS on a BUGGY value, the inline comment cites the Core
 * line number that defines the expected correct behavior.
 *
 * References:
 *   bitcoin-core/src/zmq/zmqnotificationinterface.cpp
 *   bitcoin-core/src/zmq/zmqpublishnotifier.cpp
 *   bitcoin-core/src/zmq/zmqabstractnotifier.h
 *   bitcoin-core/src/rest.cpp
 *   bitcoin-core/src/init.cpp
 *   bitcoin-core/src/common/system.cpp
 *
 * No BIPs (operator-facing surface).
 */

import { describe, expect, test } from "bun:test";
import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import {
  parseZMQArgs,
  ZMQNotificationInterface,
  wireZMQNotifications,
  type ZMQTopic,
} from "../rpc/zmq.js";
import { EventEmitter } from "events";
import {
  getBlockHash,
  type Block,
  type BlockHeader,
} from "../validation/block.js";
import { getTxId, type Transaction } from "../validation/tx.js";

// Repo paths used by source-grep gates.
const REPO_ROOT = join(import.meta.dir, "..", "..");
const CLI_TS = join(REPO_ROOT, "src", "cli", "cli.ts");
const ZMQ_TS = join(REPO_ROOT, "src", "rpc", "zmq.ts");
const REST_TS = join(REPO_ROOT, "src", "rpc", "rest.ts");

function readSource(path: string): string {
  return readFileSync(path, "utf8");
}

// =============================================================================
// Test fixtures
// =============================================================================

function mockHeader(): BlockHeader {
  return {
    version: 1,
    prevBlock: Buffer.alloc(32, 0x01),
    merkleRoot: Buffer.alloc(32, 0x02),
    timestamp: 1700000000,
    bits: 0x1d00ffff,
    nonce: 7,
  };
}

function mockCoinbase(): Transaction {
  return {
    version: 1,
    inputs: [
      {
        prevOut: { txid: Buffer.alloc(32, 0x00), vout: 0xffffffff },
        scriptSig: Buffer.from([0x01, 0x01]),
        sequence: 0xffffffff,
        witness: [],
      },
    ],
    outputs: [
      {
        value: 5000000000n,
        scriptPubKey: Buffer.from([0x6a]), // OP_RETURN
      },
    ],
    lockTime: 0,
  };
}

function mockBlock(): Block {
  return { header: mockHeader(), transactions: [mockCoinbase()] };
}

// =============================================================================
// ZMQ — wire format
// =============================================================================

describe("W141 G1 (PASS): ZMQ multipart frame is [topic, body, LE-u32 seq]", () => {
  test("publish path builds a 4-byte LE sequence buffer", () => {
    // Inspect zmq.ts source — the private `publish` method
    // documents and builds Buffer.alloc(4) + writeUInt32LE.
    const src = readSource(ZMQ_TS);
    expect(src).toContain('Buffer.alloc(4)');
    expect(src).toContain('seqBuf.writeUInt32LE(pub.sequence)');
    // Send order is [topic, body, sequence] — Core's
    // zmq_send_multipart(psocket, command, ..., data, ..., msgseq, ...)
    expect(src).toContain('Buffer.from(topic), body, seqBuf');
  });
});

describe("W141 G2 / G4 (BUG-1, P0-CDIV): hash bytes NOT reversed to display order before publish", () => {
  test("notifyBlock publishes the internal-LE block hash directly (Core reverses)", () => {
    // Core (zmqpublishnotifier.cpp:214-218):
    //     uint8_t data[32];
    //     for (unsigned int i = 0; i < 32; i++) {
    //         data[31 - i] = hash.begin()[i];   // REVERSE
    //     }
    // Hotbuns hands `blockHash` straight to publish() without
    // .reverse(). Pin the BUGGY behavior; a fix wave flips this.
    const src = readSource(ZMQ_TS);
    // The would-be correct line would read:
    //   await this.publish("hashblock", Buffer.from(blockHash).reverse());
    // The actual current line:
    expect(src).toContain('await this.publish("hashblock", blockHash);');
    expect(src).not.toContain('Buffer.from(blockHash).reverse()');
    // Same defect for hashtx (per-tx loop in notifyBlock and in
    // notifyTransactionAcceptance):
    expect(src).toContain('await this.publish("hashtx", txid);');
    expect(src).not.toContain('Buffer.from(txid).reverse()');
  });

  test("publishSequence body uses raw LE hash for bytes 0..32 (Core reverses these too)", () => {
    // Core's SendSequenceMsg (zmqpublishnotifier.cpp:259-261)
    // reverses the hash into bytes 0..32 of `data` before writing
    // the label / sequence. Hotbuns uses `hash.copy(body, 0)`.
    const src = readSource(ZMQ_TS);
    expect(src).toContain('hash.copy(body, 0)');
    // No reverse-call sequence in the publishSequence path.
    expect(src).not.toContain('Buffer.from(hash).reverse()');
  });
});

describe("W141 G3 (PASS): rawblock/rawtx use TX_WITH_WITNESS-equivalent serialization", () => {
  test("notifyTransactionAcceptance serializes with witness", () => {
    const src = readSource(ZMQ_TS);
    expect(src).toContain('serializeTx(tx, true)');
  });
});

describe("W141 G5 (PASS): sequence number is monotonic per-topic and wraps as u32", () => {
  test("publish increments and masks to u32", () => {
    const src = readSource(ZMQ_TS);
    expect(src).toContain('pub.sequence = (pub.sequence + 1) >>> 0;');
  });
});

// =============================================================================
// ZMQ — lifecycle
// =============================================================================

describe("W141 G6 (BUG-2, P1-NEAR): per-topic HWM args not supported", () => {
  test("parseZMQArgs has no path to set HWM; getNotifications hardcodes 1000", () => {
    const src = readSource(ZMQ_TS);
    // No `hwm` parse:
    expect(src).not.toMatch(/zmqpub.*hwm/i);
    // getNotifications always reports hwm=1000:
    expect(src).toContain('hwm: 1000,');
  });

  test("parseZMQArgs ignores any --zmqpubhashblockhwm operator override", () => {
    const cfg = parseZMQArgs([
      "--zmqpubhashblock=tcp://127.0.0.1:28332",
      "--zmqpubhashblockhwm=10000",
    ]);
    // The hwm flag is silently dropped (treated as an unknown topic).
    // No way to inspect a per-notifier hwm because the parser doesn't
    // model one.
    expect(cfg.notifiers.length).toBe(1);
    expect(cfg.notifiers[0].topic).toBe("hashblock");
  });
});

describe("W141 G7 (BUG-3, P1-NEAR): only double-dash --zmqpub* is parsed; Core uses single dash", () => {
  test("parseZMQArgs ignores single-dash Core-style args", () => {
    const cfg = parseZMQArgs(["-zmqpubhashblock=tcp://127.0.0.1:28332"]);
    // Buggy: silently dropped because regex requires `^--`.
    expect(cfg.notifiers.length).toBe(0);
  });
});

describe("W141 G8 (BUG-4, P0-DEAD-CODE): ZMQ never wired in production cli.ts", () => {
  test("cli.ts does not import the zmq module", () => {
    const src = readSource(CLI_TS);
    expect(src).not.toMatch(/from\s+["']\.\.\/rpc\/zmq(\.js)?["']/);
    expect(src).not.toMatch(/from\s+["']\.\/rpc\/zmq(\.js)?["']/);
  });

  test("cli.ts never instantiates ZMQNotificationInterface", () => {
    const src = readSource(CLI_TS);
    expect(src).not.toContain('new ZMQNotificationInterface');
    expect(src).not.toContain('parseZMQArgs(');
    expect(src).not.toContain('wireZMQNotifications(');
  });

  test("only mention of zmq in cli.ts is a stale comment, not actual wiring", () => {
    const src = readSource(CLI_TS);
    const zmqMatches = [...src.matchAll(/zmq/gi)].map((m) => m.index ?? -1);
    // We expect at most a handful of comment-only references. Lock
    // exact count so a future production wiring intentionally trips
    // this assertion and forces re-audit.
    expect(zmqMatches.length).toBeLessThanOrEqual(2);
  });
});

describe("W141 G9 (BUG-5, P2-MED): unix:// -> ipc:// rewrite missing", () => {
  test("ZMQNotificationInterface.start does not translate unix:// addresses", () => {
    // Core (zmqnotificationinterface.cpp:61-64):
    //   if (address.starts_with(ADDR_PREFIX_UNIX)) {
    //     address.replace(0, ADDR_PREFIX_UNIX.length(), ADDR_PREFIX_IPC);
    //   }
    const src = readSource(ZMQ_TS);
    expect(src).not.toMatch(/unix:\/\//);
    expect(src).not.toMatch(/ipc:\/\//);
    expect(src).not.toMatch(/ADDR_PREFIX/);
  });
});

describe("W141 G10 (PASS): multiple topics share a single socket per address", () => {
  test("start() groups notifiers by address before constructing sockets", () => {
    const src = readSource(ZMQ_TS);
    expect(src).toContain('addressToTopics');
    expect(src).toContain('addressToSocket');
    // Confirm the de-dupe (one socket per unique address):
    expect(src).toContain('if (!socket) {');
  });
});

describe("W141 G11 (BUG-6, P1-NEAR): ZMQ_LINGER=0 not set before close", () => {
  test("stop() closes the socket without setting linger to 0", () => {
    // Core (zmqpublishnotifier.cpp:185-187):
    //   int linger = 0;
    //   zmq_setsockopt(psocket, ZMQ_LINGER, &linger, sizeof(linger));
    //   zmq_close(psocket);
    const src = readSource(ZMQ_TS);
    expect(src).not.toMatch(/LINGER/i);
    expect(src).not.toMatch(/setsockopt/i);
    expect(src).toContain('pub.socket.close();');
  });
});

// =============================================================================
// ZMQ — semantics
// =============================================================================

describe("W141 G12 (BUG-7, P1-NEAR): notifyBlock does not skip during IBD", () => {
  test("ZMQNotificationInterface API has no IBD parameter", () => {
    // Core (zmqnotificationinterface.cpp:151-154):
    //   void UpdatedBlockTip(... bool fInitialDownload)
    //   { if (fInitialDownload || pindexNew == pindexFork) return; }
    const src = readSource(ZMQ_TS);
    // notifyBlock signature is `(block: Block): Promise<void>` —
    // no IBD flag is passed in.
    expect(src).toContain('async notifyBlock(block: Block): Promise<void>');
    expect(src).not.toMatch(/fInitialDownload|initialDownload|isIBD/);
  });
});

describe("W141 G13 (BUG-8, P1-NEAR): notifyBlock fires hashtx only, not rawtx, per block tx", () => {
  test("the block-iteration loop only publishes hashtx", () => {
    const src = readSource(ZMQ_TS);
    // Buggy loop: only publishes hashtx, missing rawtx companion.
    const block = "// hashtx for each transaction in block";
    expect(src).toContain(block);
    // Locate the loop body and check it does NOT publish rawtx for
    // each tx; the only rawtx publish is in
    // notifyTransactionAcceptance (mempool entry path), not the
    // block-connect path. Core's BlockConnected fires both via
    // NotifyTransaction (zmqnotificationinterface.cpp:185-189).
    const blockLoopMatch = src.match(
      /\/\/ hashtx for each transaction in block[\s\S]*?\}\s*\n/
    );
    expect(blockLoopMatch).not.toBeNull();
    if (blockLoopMatch) {
      expect(blockLoopMatch[0]).not.toContain('"rawtx"');
    }
  });
});

describe("W141 G14 (BUG-9, P1-NEAR): notifyBlockDisconnect has no per-tx hashtx/rawtx loop", () => {
  test("notifyBlockDisconnect only publishes sequence 'D', no per-tx fan-out", () => {
    // Core BlockDisconnected (zmqnotificationinterface.cpp:198-211)
    // iterates pblock->vtx and fires NotifyTransaction first, then
    // NotifyBlockDisconnect.
    const src = readSource(ZMQ_TS);
    const match = src.match(
      /async notifyBlockDisconnect\(block: Block\): Promise<void>[\s\S]*?\n\s{0,4}\}/
    );
    expect(match).not.toBeNull();
    if (match) {
      expect(match[0]).not.toContain('block.transactions');
      expect(match[0]).toContain('publishSequence(blockHash, "D")');
    }
  });
});

describe("W141 G15 (BUG-10, P2-MED): failed publish does not evict notifier", () => {
  test("publish() catches no error, returns void, never removes a notifier", () => {
    // Core (zmqnotificationinterface.cpp:136-147):
    //   void TryForEachAndRemoveFailed(... func) {
    //     if (func(notifier)) ++i;
    //     else { notifier->Shutdown(); i = notifiers.erase(i); }
    //   }
    const src = readSource(ZMQ_TS);
    // No erase/remove from this.publishers on send failure.
    expect(src).not.toMatch(/this\.publishers\.delete/);
    // wireZMQNotifications uses `.catch(err => console.error(...))`
    // — i.e. logs and swallows. The notifier stays in the map.
    expect(src).toContain('console.error("ZMQ notifyBlock error:", err);');
  });
});

describe("W141 G16 (PASS for source): mempool A/R wiring exists in the helper", () => {
  test("wireZMQNotifications listens for txAccepted -> notifyTransactionAcceptance", async () => {
    const zmq = new ZMQNotificationInterface();
    const emitter = new EventEmitter();
    let called = false;
    let receivedSeq: bigint | undefined;
    zmq.notifyTransactionAcceptance = async (tx, seq) => {
      called = true;
      receivedSeq = seq;
    };
    wireZMQNotifications(zmq, emitter);
    emitter.emit("txAccepted", mockCoinbase(), 7n);
    await new Promise((r) => setTimeout(r, 10));
    expect(called).toBe(true);
    expect(receivedSeq).toBe(7n);
    // Caveat: in production, nothing constructs `zmq` — see BUG-4.
  });
});

// =============================================================================
// REST — routing + framing
// =============================================================================

describe("W141 G17 (BUG-11, P2-MED): no warmup gate on REST routes", () => {
  test("handleRequest has no CheckWarmup / IsInWarmup analog", () => {
    // Core (rest.cpp:171): every route starts with `if (!CheckWarmup(req)) return false;`
    const src = readSource(REST_TS);
    expect(src).not.toMatch(/CheckWarmup|IsInWarmup|isWarmedUp|warmup/i);
  });
});

describe("W141 G18 (BUG-12, P2-MED): unknown extension silently falls back to JSON", () => {
  test("parseFormat returns format='json' for unrecognized extensions", () => {
    const src = readSource(REST_TS);
    // Buggy fallback line (rest.ts:245):
    expect(src).toContain('return { path: param, format: "json" };');
    // Core's ParseDataFormat returns UNDEF for unknown extensions
    // (rest.cpp:151), and every route's default: case emits
    // HTTP_NOT_FOUND with "output format not found".
  });
});

describe("W141 G19 (BUG-13, P2-MED): missing REST endpoints (blockpart, spenttxouts, deploymentinfo)", () => {
  test("REST handler dispatches do not include blockpart/", () => {
    const src = readSource(REST_TS);
    expect(src).not.toContain('"blockpart/"');
    expect(src).not.toMatch(/handleBlockPart|rest_block_part/);
  });

  test("REST handler dispatches do not include spenttxouts/", () => {
    const src = readSource(REST_TS);
    expect(src).not.toContain('"spenttxouts/"');
    expect(src).not.toContain('rest_spent_txouts');
  });

  test("REST handler dispatches do not include deploymentinfo/", () => {
    const src = readSource(REST_TS);
    expect(src).not.toContain('"deploymentinfo"');
    expect(src).not.toContain('"deploymentinfo/"');
    expect(src).not.toMatch(/handleDeploymentInfo|rest_deploymentinfo/);
  });
});

describe("W141 G20 (BUG-14, P2-MED): getutxos rejects POST; Core accepts POST body", () => {
  test("handleRequest rejects any non-GET method with HTTP 405", () => {
    // Core (rest.cpp:912): `strRequestMutable = req->ReadBody();`
    // explicitly supports POST bodies for getutxos with BIN/HEX
    // serialized vOutPoints.
    const src = readSource(REST_TS);
    expect(src).toMatch(
      /if\s*\(\s*req\.method\s*!==\s*"GET"\s*\)/
    );
    expect(src).toContain('Only GET requests are supported');
  });
});

describe("W141 G21 (PASS): -rest defaults OFF, opt-in via --rest=1", () => {
  test("CLI default for rest is false, matching Core DEFAULT_REST_ENABLE", () => {
    const src = readSource(CLI_TS);
    // The config-default block (cli.ts:276) sets `rest: false`.
    expect(src).toMatch(/rest:\s*false,/);
    // The opt-in branch:
    expect(src).toMatch(/config\.rest\s*=\s*true/);
  });
});

describe("W141 G22 (PASS w/ caveat): REST binds on rpcPort+1 by default; Core embeds REST in same server", () => {
  test("RESTServer config defaults port to rpcPort+1 in cli.ts wiring", () => {
    const src = readSource(CLI_TS);
    // The cli.ts default:
    expect(src).toContain('mergedConfig.restPort ?? mergedConfig.rpcPort + 1');
  });
});

// =============================================================================
// REST — data accuracy
// =============================================================================

describe("W141 G23 (BUG-15, P2-MED): confirmations is not -1 for orphaned blocks", () => {
  test("formatBlockJson uses unconditional `bestBlock.height - height + 1`", () => {
    const src = readSource(REST_TS);
    // Buggy line (rest.ts:369):
    expect(src).toContain(
      'confirmations: height >= 0 ? bestBlock.height - height + 1 : 0,'
    );
    // Core returns -1 for any block not on the active chain
    // (rpc/blockchain.cpp:614 help text + ComputeNextBlockAndDepth).
    expect(src).not.toMatch(/activeChain.*contains|isOnActiveChain/);
  });
});

describe("W141 G24 (BUG-16, P2-MED): chaininfo.mediantime is hardcoded 0", () => {
  test("handleChainInfo emits mediantime: 0", () => {
    const src = readSource(REST_TS);
    expect(src).toMatch(/mediantime:\s*0,\s*\/\/\s*Would need MTP calculation/);
  });
});

describe("W141 G25 (BUG-17, P2-MED): chaininfo.softforks always empty", () => {
  test("handleChainInfo emits softforks: {}", () => {
    const src = readSource(REST_TS);
    expect(src).toMatch(/softforks:\s*\{\}/);
  });
});

describe("W141 G26 (BUG-18, P2-MED): rest_tx does not wait for txindex sync", () => {
  test("handleTx does not call BlockUntilSyncedToCurrentChain on txIndex", () => {
    // Core (rest.cpp:850-852):
    //   if (g_txindex) g_txindex->BlockUntilSyncedToCurrentChain();
    const src = readSource(REST_TS);
    expect(src).not.toMatch(/BlockUntilSyncedToCurrentChain|waitForSync/);
  });
});

describe("W141 G27 (BUG-19, P2-MED): block 404 doesn't distinguish pruned vs not-downloaded", () => {
  test("handleBlock emits a single 'not found' error on db miss", () => {
    const src = readSource(REST_TS);
    expect(src).toContain('hashStr + " not found"');
    // Core distinguishes "not available (pruned data)" vs
    // "not available (not fully downloaded)" (rest.cpp:418-422).
    expect(src).not.toMatch(/not available \(pruned data\)/);
    expect(src).not.toMatch(/not available \(not fully downloaded\)/);
  });
});

describe("W141 G28 (BUG-20, P2-MED): blockfilter routes don't wait for index sync nor distinguish corruption", () => {
  test("handleBlockFilter never calls a sync-wait nor a corruption distinguisher", () => {
    const src = readSource(REST_TS);
    // No call to wait for index sync.
    expect(src).not.toMatch(/BlockUntilSynced|waitForSync|isSynced/);
    // The error string is unconditional:
    expect(src).toContain(
      'Filter not found. Block filters are still in the process of being indexed.'
    );
    // No "indicates index corruption" branch.
    expect(src).not.toMatch(/indicates index corruption/);
  });
});

// =============================================================================
// Notification scripts
// =============================================================================

describe("W141 G29 (BUG-21, P0-FEATURE-MISSING): no -blocknotify / -alertnotify / -startupnotify / -shutdownnotify / -walletnotify support", () => {
  test("cli.ts does not reference any notify-hook flag", () => {
    const src = readSource(CLI_TS);
    expect(src).not.toMatch(/blocknotify/i);
    expect(src).not.toMatch(/alertnotify/i);
    expect(src).not.toMatch(/startupnotify/i);
    expect(src).not.toMatch(/shutdownnotify/i);
    expect(src).not.toMatch(/walletnotify/i);
  });

  test("the source tree has no notify-hook module wired anywhere", () => {
    // The notify hooks would naturally land in something like
    // src/notify/runner.ts or src/util/run-command.ts. Confirm
    // those don't exist yet (so the FIX wave can land them without
    // colliding with stale skeletons).
    expect(existsSync(join(REPO_ROOT, "src", "notify"))).toBe(false);
    expect(existsSync(join(REPO_ROOT, "src", "util", "run-command.ts"))).toBe(
      false
    );
  });
});

describe("W141 G30 (BUG-22, P0-PRE-EMPTIVE): no shell-injection-safe runner exists yet", () => {
  test("no production code calls child_process.exec with operator-supplied templates", () => {
    // Pre-emptive: we want to assert that BEFORE the notify FIX
    // wave lands, no naive `exec(template)` snippet exists. After
    // the FIX wave this gate should still pass because the safe
    // pattern uses `Bun.spawn([...argv])` or `Bun.spawn(["sh", "-c", cmd])`
    // with explicit `ShellEscape` on `%s` substitutions.
    const src = readSource(CLI_TS);
    expect(src).not.toMatch(/child_process/);
    expect(src).not.toMatch(/require\(["']child_process["']\)/);
    expect(src).not.toMatch(/\bexec\s*\(/);
  });

  test("Bun.spawn use in cli.ts is daemonization only (no operator-supplied command line)", () => {
    const src = readSource(CLI_TS);
    // The only EXECUTING Bun.spawn in cli.ts is the daemon re-exec at
    // line ~1248 which uses [bunExe, "run", scriptPath, ...] — an
    // argv array controlled by the process itself, not by an
    // operator template. Other `Bun.spawn` mentions are docstrings
    // (`/^\s*\*.*Bun\.spawn/`) — count only call sites.
    const callMatches = src
      .split("\n")
      .filter((line) => /Bun\.spawn\(/.test(line) && !/^\s*\*/.test(line));
    expect(callMatches.length).toBeLessThanOrEqual(1);
    // And the one call site assembles an argv array, not a shell
    // string: pin that the first arg starts with `[`.
    if (callMatches.length === 1) {
      expect(callMatches[0]).toMatch(/Bun\.spawn\(\[/);
    }
  });
});

// =============================================================================
// Cross-cutting: emit-event wiring sanity
// =============================================================================

describe("W141 cross-cut: chain/mempool emit the events ZMQ would consume", () => {
  test("chain/state.ts emits blockConnected and blockDisconnected on the shared emitter", () => {
    const stateSrc = readFileSync(
      join(REPO_ROOT, "src", "chain", "state.ts"),
      "utf8"
    );
    expect(stateSrc).toContain('this.notificationEmitter.emit("blockConnected", block)');
    expect(stateSrc).toContain('this.notificationEmitter.emit("blockDisconnected", block)');
  });

  test("mempool/mempool.ts emits txAccepted and txRemoved on the shared emitter", () => {
    const mpSrc = readFileSync(
      join(REPO_ROOT, "src", "mempool", "mempool.ts"),
      "utf8"
    );
    expect(mpSrc).toContain('this.notificationEmitter.emit("txAccepted", tx, seq)');
    expect(mpSrc).toContain('this.notificationEmitter.emit("txRemoved", txid, seq)');
  });

  test("cli.ts plumbs a single shared EventEmitter into chainState + mempool", () => {
    // The seam is present. Only the ZMQ subscriber is missing.
    const src = readSource(CLI_TS);
    expect(src).toContain('chainState.setNotificationEmitter(chainEvents);');
    expect(src).toContain('mempool.setNotificationEmitter(chainEvents);');
  });
});

// =============================================================================
// Cross-cutting: byte-order audit confirms the BUG-1 finding end-to-end
// =============================================================================

describe("W141 cross-cut: getBlockHash and getTxId return internal-LE bytes", () => {
  test("getBlockHash documents LE return", () => {
    const blockSrc = readFileSync(
      join(REPO_ROOT, "src", "validation", "block.ts"),
      "utf8"
    );
    expect(blockSrc).toContain('Returns in little-endian (internal) format.');
  });

  test("getTxId documents LE return", () => {
    const txSrc = readFileSync(
      join(REPO_ROOT, "src", "validation", "tx.ts"),
      "utf8"
    );
    expect(txSrc).toContain(
      'The txid is stored in little-endian (internal) format.'
    );
  });

  test("computed block hash matches itself across calls (idempotent)", () => {
    const b = mockBlock();
    const h1 = getBlockHash(b.header);
    const h2 = getBlockHash(b.header);
    expect(h1.equals(h2)).toBe(true);
    expect(h1.length).toBe(32);
  });

  test("computed txid for coinbase fixture has length 32", () => {
    const tx = mockCoinbase();
    const t = getTxId(tx);
    expect(t.length).toBe(32);
  });
});
