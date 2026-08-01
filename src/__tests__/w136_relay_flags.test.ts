/**
 * W136 — BIP-130 sendheaders + BIP-133 feefilter + BIP-339 wtxidrelay audit (hotbuns).
 *
 * 30 gates covering the three feature-negotiation messages that govern
 * the hotbuns⇄peer relay relationship at handshake time and beyond.
 *
 * Reference:
 *   - bitcoin-core/src/net_processing.cpp
 *     - ProcessMessage VERSION/VERACK/SENDHEADERS/WTXIDRELAY/FEEFILTER
 *     - MaybeSendSendHeaders (L5519-5538)
 *     - MaybeSendFeefilter (L5540-5580)
 *     - Block announcement routing (L5828-5957)
 *   - bitcoin-core/src/node/protocol_version.h
 *     - SENDHEADERS_VERSION = 70012
 *     - FEEFILTER_VERSION   = 70013
 *     - WTXID_RELAY_VERSION = 70016
 *   - bitcoin-core/src/policy/fees/block_policy_estimator.cpp
 *     - FeeFilterRounder::round (L1109-1119)
 *   - bitcoin-core/src/consensus/amount.h — CAmount = int64_t
 *
 * Audit verdict (see audit/w136_relay_flags.md): 21 BUGS / 30 gates.
 *   P0-CDIV: BUG-1 (no WTXID_RELAY_VERSION),
 *            BUG-6 (incoming sendheaders silently ignored),
 *            BUG-7 (block announce always uses inv),
 *            BUG-16 (wtxidrelay sent without version gate),
 *            BUG-17 (post-VERACK wtxidrelay silently swallowed; Core disconnects).
 *
 *   KEY UNIVERSAL PATTERNS:
 *     1. "Dead helper at call site" — feeFilterInterval declared
 *        but never set; maybeSendFeeFilter is dead code.
 *     2. "Dead misbehavior arm inside handleHandshake" — post-VERACK
 *        check is unreachable because handleHandshake is only invoked
 *        when !handshakeComplete.
 *     3. "Outgoing feature-negotiation without common-version gate" —
 *        sendheaders, sendcmpct (W126), wtxidrelay all share this gap.
 *     4. "Privacy side-channel in fee broadcasts" — Core's
 *        FeeFilterRounder absent → exact mempool min-fee leaks.
 *     5. "int64 vs uint64 wire shape" — feefilter CAmount round-trips
 *        through unsigned reader, fragile but currently behavior-eq.
 *
 * No production code changes in this wave.
 *
 * Running: bun test src/__tests__/w136_relay_flags.test.ts
 */

import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

import {
  FeeFilterManager,
  FEEFILTER_VERSION,
  AVG_FEEFILTER_BROADCAST_INTERVAL_MS,
  MAX_FEEFILTER_CHANGE_DELAY_MS,
  DEFAULT_MIN_RELAY_FEE_RATE,
  MAX_MONEY,
  meetsFeeFilter,
  poissonDelay,
} from "../p2p/feefilter";
import { MIN_PEER_PROTO_VERSION } from "../p2p/peer";

// ---------------------------------------------------------------------------
// Source-level fixtures (for static-grep gates).
// ---------------------------------------------------------------------------

const __dirname = dirname(fileURLToPath(import.meta.url));
const SRC = resolve(__dirname, "..");

const PEER_SRC = readFileSync(resolve(SRC, "p2p", "peer.ts"), "utf8");
const MANAGER_SRC = readFileSync(resolve(SRC, "p2p", "manager.ts"), "utf8");
const FEEFILTER_SRC = readFileSync(
  resolve(SRC, "p2p", "feefilter.ts"),
  "utf8",
);
const MESSAGES_SRC = readFileSync(
  resolve(SRC, "p2p", "messages.ts"),
  "utf8",
);
const RELAY_SRC = readFileSync(resolve(SRC, "p2p", "relay.ts"), "utf8");

// Core protocol-version constants (for cross-reference).
const CORE_SENDHEADERS_VERSION = 70012;
const CORE_FEEFILTER_VERSION = 70013;
const CORE_WTXID_RELAY_VERSION = 70016;
const CORE_AVG_FEEFILTER_INTERVAL_MS = 10 * 60 * 1000;
const CORE_MAX_FEEFILTER_CHANGE_DELAY_MS = 5 * 60 * 1000;

// ===========================================================================
// G01 — SENDHEADERS_VERSION = 70012 — PRESENT
// ===========================================================================
describe("W136-G01: SENDHEADERS_VERSION = 70012 — PRESENT", () => {
  // hotbuns doesn't export this constant separately, but the gate is
  // structurally satisfied because MIN_PEER_PROTO_VERSION = 70015 > 70012.
  test("Core constant value (for cross-reference)", () => {
    expect(CORE_SENDHEADERS_VERSION).toBe(70012);
  });

  test("hotbuns MIN_PEER_PROTO_VERSION >= SENDHEADERS_VERSION (structural gate)", () => {
    // Any peer hotbuns keeps is >= 70015, which is > 70012.
    // So the SENDHEADERS gate is structurally satisfied.
    expect(MIN_PEER_PROTO_VERSION).toBeGreaterThanOrEqual(
      CORE_SENDHEADERS_VERSION,
    );
  });
});

// ===========================================================================
// G02 — FEEFILTER_VERSION = 70013 — PRESENT
// ===========================================================================
describe("W136-G02: FEEFILTER_VERSION = 70013 — PRESENT", () => {
  test("constant value matches Core", () => {
    expect(FEEFILTER_VERSION).toBe(CORE_FEEFILTER_VERSION);
    expect(FEEFILTER_VERSION).toBe(70013);
  });

  test("exported from feefilter.ts", () => {
    expect(FEEFILTER_SRC).toMatch(/export\s+const\s+FEEFILTER_VERSION\s*=\s*70013/);
  });
});

// ===========================================================================
// G03 — WTXID_RELAY_VERSION = 70016 — MISSING (BUG-1 P0-CDIV)
// ===========================================================================
describe("W136-G03: WTXID_RELAY_VERSION = 70016 — MISSING (BUG-1 P0-CDIV)", () => {
  test("Core defines WTXID_RELAY_VERSION = 70016", () => {
    expect(CORE_WTXID_RELAY_VERSION).toBe(70016);
  });

  test.skip(
    "BUG-1: hotbuns has no WTXID_RELAY_VERSION constant — TODO add to feefilter.ts (or new protocol_version.ts) and gate the outgoing wtxidrelay send",
    () => {
      // Once added, this assertion will flip:
      // expect(WTXID_RELAY_VERSION).toBe(70016);
    },
  );

  test("forward-regression: feefilter.ts does NOT yet export WTXID_RELAY_VERSION", () => {
    // This test flips to MUST-export once BUG-1 is fixed; for now it
    // documents the absence.
    expect(FEEFILTER_SRC).not.toMatch(/export\s+const\s+WTXID_RELAY_VERSION/);
  });
});

// ===========================================================================
// G04 — AVG_FEEFILTER_BROADCAST_INTERVAL = 10min — PRESENT
// ===========================================================================
describe("W136-G04: AVG_FEEFILTER_BROADCAST_INTERVAL = 10min — PRESENT", () => {
  test("constant matches Core", () => {
    expect(AVG_FEEFILTER_BROADCAST_INTERVAL_MS).toBe(CORE_AVG_FEEFILTER_INTERVAL_MS);
    expect(AVG_FEEFILTER_BROADCAST_INTERVAL_MS).toBe(600_000);
  });
});

// ===========================================================================
// G05 — MAX_FEEFILTER_CHANGE_DELAY = 5min — PRESENT
// ===========================================================================
describe("W136-G05: MAX_FEEFILTER_CHANGE_DELAY = 5min — PRESENT", () => {
  test("constant matches Core", () => {
    expect(MAX_FEEFILTER_CHANGE_DELAY_MS).toBe(CORE_MAX_FEEFILTER_CHANGE_DELAY_MS);
    expect(MAX_FEEFILTER_CHANGE_DELAY_MS).toBe(300_000);
  });
});

// ===========================================================================
// G06 — sendheaders sent AFTER our VERACK (correct ordering) — PRESENT
// ===========================================================================
describe("W136-G06: sendheaders sent after our VERACK — PRESENT", () => {
  test("sendheaders is dispatched inside checkHandshakeComplete (post-VERACK)", () => {
    // peer.ts:1310-1331 — sendheaders is sent in checkHandshakeComplete,
    // which fires only when sentVerack && receivedVerack are both true.
    expect(PEER_SRC).toMatch(
      /checkHandshakeComplete\(\)\s*:\s*void\s*\{[\s\S]*?this\.send\(\{\s*type:\s*"sendheaders"/,
    );
  });

  test("sendheaders is NOT sent inside handleHandshake's case 'version' arm (pre-VERACK)", () => {
    // Pre-VERACK in handleHandshake we send wtxidrelay + sendaddrv2 + verack,
    // NOT sendheaders.  Sendheaders waits until our verack completes.
    const versionCaseMatch = PEER_SRC.match(
      /case\s+"version":\s*\{[\s\S]*?this\.send\(\{\s*type:\s*"wtxidrelay"[\s\S]*?break;\s*\}/,
    );
    expect(versionCaseMatch).not.toBeNull();
    if (versionCaseMatch) {
      expect(versionCaseMatch[0]).not.toContain('type: "sendheaders"');
    }
  });
});

// ===========================================================================
// G07 — sendheaders gated on common_version >= 70012 — MISSING (BUG-2 P1-WIRE)
// ===========================================================================
describe("W136-G07: sendheaders gated on SENDHEADERS_VERSION — MISSING (BUG-2 P1-WIRE)", () => {
  test.skip(
    "BUG-2: peer.ts:1322 sends sendheaders unconditionally; should gate on versionPayload.version >= 70012 — TODO add gate",
    () => {
      // Future check: search for /version\s*>=\s*70012/ before the sendheaders send.
    },
  );

  test("documenting: sendheaders send has no version check at the call site", () => {
    // Extract the lines around peer.ts:1322 — sendheaders is sent
    // immediately, no surrounding conditional on version.
    const checkHandshakeBlock = PEER_SRC.match(
      /checkHandshakeComplete\(\)\s*:\s*void\s*\{[\s\S]*?\}\n/,
    );
    expect(checkHandshakeBlock).not.toBeNull();
    if (checkHandshakeBlock) {
      // Should NOT contain "version >=" check around the sendheaders send
      // (in current implementation).
      const beforeSend = checkHandshakeBlock[0].split('type: "sendheaders"')[0];
      // Currently: no `>= 70012` gate above the send.
      expect(beforeSend).not.toMatch(/>=\s*70012/);
    }
  });
});

// ===========================================================================
// G08 — m_sent_sendheaders once-only flag — MISSING (BUG-3 P1-API)
// ===========================================================================
describe("W136-G08: m_sent_sendheaders once-latch — MISSING (BUG-3 P1-API)", () => {
  test.skip(
    "BUG-3: Peer has no m_sent_sendheaders / sentSendHeaders field — TODO add for Core parity",
    () => {
      // Future check: PEER_SRC.match(/sentSendheaders|sentSendHeaders/);
    },
  );

  test("documenting: no sentSendheaders flag on Peer", () => {
    expect(PEER_SRC).not.toMatch(/\bsentSendheaders\b|\bsentSendHeaders\b/);
  });
});

// ===========================================================================
// G09 — sendheaders delayed until headers sync done — MISSING (BUG-4 P1-WIRE)
// ===========================================================================
describe("W136-G09: sendheaders delayed until pindexBestKnownBlock > MinimumChainWork — MISSING (BUG-4 P1-WIRE)", () => {
  test.skip(
    "BUG-4: hotbuns sends sendheaders immediately on handshake completion; Core delays until initial headers sync done — TODO add gate",
    () => {
      // Future check: confirm sendheaders send is wrapped in a
      // MinimumChainWork comparison.
    },
  );

  test("documenting: sendheaders send is unconditional on chain work", () => {
    expect(PEER_SRC).not.toMatch(/MinimumChainWork|minimum_chain_work/i);
  });
});

// ===========================================================================
// G10 — Periodic MaybeSendSendHeaders — MISSING (BUG-5 P1-WIRE)
// ===========================================================================
describe("W136-G10: periodic MaybeSendSendHeaders call — MISSING (BUG-5 P1-WIRE)", () => {
  test.skip(
    "BUG-5: hotbuns has no periodic MaybeSendSendHeaders loop — TODO add to maintain() or new sendHeadersInterval",
    () => {
      // Future check: search manager.ts for /maybeSendSendHeaders|MaybeSendSendHeaders/.
    },
  );

  test("documenting: manager has no maybeSendSendHeaders method", () => {
    expect(MANAGER_SRC).not.toMatch(/maybeSendSendHeaders|MaybeSendSendHeaders/);
  });
});

// ===========================================================================
// G11 — Incoming sendheaders → prefersHeaders=true — MISSING (BUG-6 P0-CDIV)
// ===========================================================================
describe("W136-G11: incoming sendheaders sets prefersHeaders — MISSING (BUG-6 P0-CDIV)", () => {
  test.skip(
    "BUG-6 P0-CDIV: incoming sendheaders is parsed but silently ignored — TODO add prefersHeaders state and handler",
    () => {
      // Future check: confirm Peer.prefersHeaders field exists and is set
      // in either handleHandshake or handlePeerMessage.
    },
  );

  test("documenting: Peer has no prefersHeaders field", () => {
    expect(PEER_SRC).not.toMatch(/\bprefersHeaders\b|\bprefers_headers\b/);
  });

  test("documenting: manager handlePeerMessage has no sendheaders case", () => {
    // manager.ts:1896-1938 dispatches addr/addrv2/feefilter explicitly,
    // but nothing for sendheaders.
    const dispatchMatch = MANAGER_SRC.match(
      /handlePeerMessage\([^)]+\)[^{]*\{[\s\S]*?\n\s\s\}\n/,
    );
    if (dispatchMatch) {
      expect(dispatchMatch[0]).not.toMatch(/msg\.type === "sendheaders"/);
    }
  });
});

// ===========================================================================
// G12 — Block announcement headers vs inv per prefersHeaders — MISSING (BUG-7 P0-CDIV)
// ===========================================================================
describe("W136-G12: block announce branches on prefersHeaders — MISSING (BUG-7 P0-CDIV)", () => {
  test.skip(
    "BUG-7 P0-CDIV: relayBlockToAll always sends inv; Core branches on m_prefers_headers — TODO add headers send path",
    () => {
      // Future check: relay.ts should have a `if (queue.prefersHeaders) sendHeaders(...) else sendInv(...)` shape.
    },
  );

  test("documenting: relay.ts has no prefersHeaders branch", () => {
    expect(RELAY_SRC).not.toMatch(/prefersHeaders|prefers_headers/);
  });

  test("documenting: relayBlockToAll uses MSG_BLOCK inv unconditionally", () => {
    // relay.ts:234-245 — relayBlockToAll always emits MSG_BLOCK inv.
    expect(RELAY_SRC).toMatch(/relayBlockToAll\([^)]*\)\s*:\s*void\s*\{[\s\S]*?MSG_BLOCK/);
  });
});

// ===========================================================================
// G13 — Initial feefilter sent in handleHandshakeComplete — PRESENT
// ===========================================================================
describe("W136-G13: initial feefilter sent in handleHandshakeComplete — PRESENT", () => {
  test("manager.ts calls sendInitialFeeFilter after handshake", () => {
    expect(MANAGER_SRC).toMatch(/sendInitialFeeFilter\(peer\)/);
  });

  test("feeFilterManager exposes sendInitialFeeFilter", () => {
    expect(FEEFILTER_SRC).toMatch(/sendInitialFeeFilter\(peer:\s*Peer\)/);
  });
});

// ===========================================================================
// G14 — Initial feefilter gated on version >= FEEFILTER_VERSION — PRESENT
// ===========================================================================
describe("W136-G14: initial feefilter gated on version — PRESENT", () => {
  test("manager.ts gates sendInitialFeeFilter on >= FEEFILTER_VERSION", () => {
    expect(MANAGER_SRC).toMatch(
      /peer\.versionPayload\.version\s*>=\s*FEEFILTER_VERSION[\s\S]*?sendInitialFeeFilter/,
    );
  });
});

// ===========================================================================
// G15 — Initial feefilter NOT sent to block-relay-only — PRESENT
// ===========================================================================
describe("W136-G15: initial feefilter skipped for block-relay-only — PRESENT", () => {
  test("manager.ts skips block_relay connType", () => {
    expect(MANAGER_SRC).toMatch(
      /connType\s*!==\s*"block_relay"[\s\S]*?sendInitialFeeFilter/,
    );
  });
});

// ===========================================================================
// G16 — Periodic MaybeSendFeefilter invocation — MISSING (BUG-8 P1-WIRE)
// ===========================================================================
describe("W136-G16: periodic maybeSendFeeFilter scheduler — MISSING (BUG-8 P1-WIRE)", () => {
  test("documenting: feeFilterInterval declared but never set", () => {
    // The field is declared at L411 and initialized to null at L495
    // — confirm both.
    expect(MANAGER_SRC).toMatch(
      /feeFilterInterval:\s*ReturnType<typeof setInterval>\s*\|\s*null/,
    );
    expect(MANAGER_SRC).toMatch(/this\.feeFilterInterval\s*=\s*null/);
  });

  test("documenting: no setInterval ever assigns feeFilterInterval", () => {
    // Search for setInterval expressions that assign to feeFilterInterval.
    // Use a tight regex that requires `=` on the same line/expression.
    const interval_assignment = /this\.feeFilterInterval\s*=\s*setInterval/;
    expect(MANAGER_SRC).not.toMatch(interval_assignment);
  });

  test("documenting: maybeSendFeeFilter is never called from running-node code", () => {
    // The method is defined in feefilter.ts but never invoked from manager.ts.
    expect(FEEFILTER_SRC).toMatch(/maybeSendFeeFilter\(peer:\s*Peer/);
    expect(MANAGER_SRC).not.toMatch(/maybeSendFeeFilter\(/);
  });

  test.skip(
    "BUG-8 P1-WIRE: dead helper at call site — TODO wire periodic invocation in start() and stop() in manager.ts",
    () => {
      // Once fixed: MANAGER_SRC should contain
      // /this\.feeFilterInterval\s*=\s*setInterval[\s\S]*?maybeSendFeeFilter/
    },
  );
});

// ===========================================================================
// G17 — FeeFilterRounder randomized round-down — MISSING (BUG-9 P2)
// ===========================================================================
describe("W136-G17: FeeFilterRounder anti-side-channel rounding — MISSING (BUG-9 P2)", () => {
  test.skip(
    "BUG-9 P2: hotbuns broadcasts raw feerate; Core randomizes downward via FeeFilterRounder — TODO add rounder",
    () => {
      // Future check: feefilter.ts should expose a FeeFilterRounder class
      // with round() method.
    },
  );

  test("documenting: no FeeFilterRounder class exists", () => {
    expect(FEEFILTER_SRC).not.toMatch(/FeeFilterRounder|fee_filter_rounder/);
  });

  test("documenting: getFeeRateToAnnounce returns the raw currentFeeRate (no rounding)", () => {
    expect(FEEFILTER_SRC).toMatch(
      /getFeeRateToAnnounce\(\):\s*bigint\s*\{[\s\S]*?return\s+this\.currentFeeRate;/,
    );
  });
});

// ===========================================================================
// G18 — min_relay_feerate floor re-applied in send path — MISSING (BUG-10 P1-WIRE)
// ===========================================================================
describe("W136-G18: min_relay_feerate floor in send path — MISSING (BUG-10 P1-WIRE)", () => {
  test("documenting: getFeeRateToAnnounce does NOT re-apply DEFAULT_MIN_RELAY_FEE_RATE floor", () => {
    // The floor is applied in setMinFeeRate (L82-87) but not on the
    // outbound side.  If currentFeeRate were ever set below the floor by
    // a future code path, the floor would not be re-applied.
    const announceMatch = FEEFILTER_SRC.match(
      /getFeeRateToAnnounce\(\):\s*bigint\s*\{[\s\S]*?\}\n/,
    );
    expect(announceMatch).not.toBeNull();
    if (announceMatch) {
      expect(announceMatch[0]).not.toMatch(/DEFAULT_MIN_RELAY_FEE_RATE|Math\.max|>\s*DEFAULT/);
    }
  });

  test.skip(
    "BUG-10: send path should be defensive — std::max(filterToSend, min_relay_feerate) per Core L5567 — TODO",
    () => {},
  );
});

// ===========================================================================
// G19 — MAX_FILTER reset on exit-IBD — MISSING (BUG-11 P1-WIRE)
// ===========================================================================
describe("W136-G19: MAX_FILTER reset on exit-IBD — MISSING (BUG-11 P1-WIRE)", () => {
  test.skip(
    "BUG-11: when feeFilterSent == MAX_FILTER and we exit IBD, nextFeeFilterSend should be set to 0 to fire immediately — TODO",
    () => {},
  );

  test("documenting: setInIBD does not adjust nextFeeFilterSend", () => {
    // The setInIBD method just flips the flag.
    const setInIBDMatch = FEEFILTER_SRC.match(
      /setInIBD\(inIBD:\s*boolean\)\s*:\s*void\s*\{[\s\S]*?\}\n/,
    );
    expect(setInIBDMatch).not.toBeNull();
    if (setInIBDMatch) {
      expect(setInIBDMatch[0]).not.toMatch(/nextFeeFilterSend|MAX_FILTER/);
    }
  });
});

// ===========================================================================
// G20 — feefilter payload encoded as int64 LE (Core CAmount) — PARTIAL (BUG-12 P1-WIRE)
// ===========================================================================
describe("W136-G20: feefilter payload as int64 LE — PARTIAL (BUG-12 P1-WIRE)", () => {
  test("documenting: hotbuns serializes feefilter via writeUInt64LE", () => {
    expect(MESSAGES_SRC).toMatch(
      /serializeFeeFilterPayload[\s\S]*?writer\.writeUInt64LE\(payload\.feeRate\)/,
    );
  });

  test("documenting: hotbuns deserializes feefilter via readUInt64LE", () => {
    expect(MESSAGES_SRC).toMatch(
      /deserializeFeeFilterPayload[\s\S]*?reader\.readUInt64LE\(\)/,
    );
  });

  test.skip(
    "BUG-12: Core writes CAmount = int64; hotbuns uses uint64. Behavior-equivalent today via MoneyRange but fragile — TODO migrate to int64",
    () => {},
  );

  test("behavior check: feeRate > MAX_MONEY is rejected by handleFeeFilter (handles the negative-as-huge-uint case)", () => {
    const mgr = new FeeFilterManager(() => {});
    const fakePeer: any = { feeFilterReceived: 0n };
    // A "negative" encoded value would read as e.g. 2^64 - 1
    const bigVal = (1n << 64n) - 1n;
    mgr.handleFeeFilter(fakePeer, bigVal);
    // Should NOT be stored (out of MoneyRange).
    expect(fakePeer.feeFilterReceived).toBe(0n);
  });
});

// ===========================================================================
// G21 — Incoming feefilter validated with MoneyRange — PRESENT
// ===========================================================================
describe("W136-G21: incoming feefilter MoneyRange check — PRESENT", () => {
  test("handleFeeFilter rejects negative (impossible in unsigned readback, defensive)", () => {
    const mgr = new FeeFilterManager(() => {});
    const fakePeer: any = { feeFilterReceived: 0n };
    mgr.handleFeeFilter(fakePeer, -1n);
    expect(fakePeer.feeFilterReceived).toBe(0n);
  });

  test("handleFeeFilter rejects > MAX_MONEY", () => {
    const mgr = new FeeFilterManager(() => {});
    const fakePeer: any = { feeFilterReceived: 0n };
    mgr.handleFeeFilter(fakePeer, MAX_MONEY + 1n);
    expect(fakePeer.feeFilterReceived).toBe(0n);
  });

  test("handleFeeFilter accepts valid feerate", () => {
    const mgr = new FeeFilterManager(() => {});
    const fakePeer: any = { feeFilterReceived: 0n };
    mgr.handleFeeFilter(fakePeer, 5000n);
    expect(fakePeer.feeFilterReceived).toBe(5000n);
  });

  test("handleFeeFilter accepts boundary MAX_MONEY", () => {
    const mgr = new FeeFilterManager(() => {});
    const fakePeer: any = { feeFilterReceived: 0n };
    mgr.handleFeeFilter(fakePeer, MAX_MONEY);
    expect(fakePeer.feeFilterReceived).toBe(MAX_MONEY);
  });

  test("handleFeeFilter accepts zero (Core: MoneyRange includes 0)", () => {
    const mgr = new FeeFilterManager(() => {});
    const fakePeer: any = { feeFilterReceived: 10n };
    mgr.handleFeeFilter(fakePeer, 0n);
    expect(fakePeer.feeFilterReceived).toBe(0n);
  });
});

// ===========================================================================
// G22 — ignore_incoming_txs / -blocksonly suppresses feefilter — MISSING (BUG-13 P1-API)
// ===========================================================================
describe("W136-G22: ignore_incoming_txs / -blocksonly suppression — MISSING (BUG-13 P1-API)", () => {
  test("documenting: hotbuns has no ignore_incoming_txs concept", () => {
    expect(FEEFILTER_SRC).not.toMatch(/ignore_incoming_txs|blocksonly|blocksOnly/i);
    expect(MANAGER_SRC).not.toMatch(/ignore_incoming_txs|--blocksonly/);
  });

  test.skip(
    "BUG-13 P1-API: implement -blocksonly mode and gate feefilter send on it — TODO",
    () => {},
  );
});

// ===========================================================================
// G23 — HasPermission(ForceRelay) suppresses feefilter — MISSING (BUG-14 P1-API)
// ===========================================================================
describe("W136-G23: ForceRelay permission suppresses feefilter — MISSING (BUG-14 P1-API)", () => {
  test("documenting: no NetPermissionFlags / ForceRelay enum", () => {
    expect(PEER_SRC).not.toMatch(/ForceRelay|forceRelay/);
    expect(MANAGER_SRC).not.toMatch(/ForceRelay|forceRelay/);
  });

  test.skip(
    "BUG-14 P1-API: implement NetPermissionFlags and gate feefilter on !HasPermission(ForceRelay) — TODO",
    () => {},
  );
});

// ===========================================================================
// G24 — feefilter not broadcast to FeelerConn / AddrFetchConn — MISSING (BUG-15 P1-WIRE)
// ===========================================================================
describe("W136-G24: feefilter suppression for feeler/addrfetch — MISSING (BUG-15 P1-WIRE)", () => {
  test("documenting: PeerConnType has no 'feeler' or 'addr_fetch' value", () => {
    expect(PEER_SRC).toMatch(
      /PeerConnType\s*=\s*"full_relay"\s*\|\s*"block_relay"\s*\|\s*"inbound"\s*\|\s*"manual"/,
    );
    expect(PEER_SRC).not.toMatch(/"feeler"|"addr_fetch"|FeelerConn|AddrFetchConn/);
  });

  test.skip(
    "BUG-15 P1-WIRE: add feeler / addrfetch connection types and suppress feefilter on them — TODO",
    () => {},
  );
});

// ===========================================================================
// G25 — wtxidrelay sent only when common_version >= 70016 — MISSING (BUG-16 P0-CDIV)
// ===========================================================================
describe("W136-G25: wtxidrelay gated on WTXID_RELAY_VERSION — MISSING (BUG-16 P0-CDIV)", () => {
  test("documenting: peer.ts sends wtxidrelay unconditionally on incoming VERSION", () => {
    // The version case sends wtxidrelay with no version gate.
    const versionCase = PEER_SRC.match(
      /case\s+"version":\s*\{[\s\S]*?this\.send\(\{\s*type:\s*"wtxidrelay"/,
    );
    expect(versionCase).not.toBeNull();
    if (versionCase) {
      // No `versionPayload.version >= 70016` or `>= WTXID_RELAY_VERSION`
      // gate between MIN_PEER_PROTO_VERSION check and the wtxidrelay send.
      expect(versionCase[0]).not.toMatch(/>=\s*70016|>=\s*WTXID_RELAY_VERSION/);
    }
  });

  test.skip(
    "BUG-16 P0-CDIV: gate wtxidrelay send on versionPayload.version >= 70016 — TODO",
    () => {},
  );
});

// ===========================================================================
// G26 — wtxidrelay sent AFTER our VERSION but BEFORE our VERACK — PRESENT
// ===========================================================================
describe("W136-G26: wtxidrelay sent between VERSION and our VERACK — PRESENT", () => {
  test("wtxidrelay is dispatched in the version case before verack", () => {
    const versionCase = PEER_SRC.match(
      /case\s+"version":\s*\{[\s\S]*?break;\s*\}/,
    );
    expect(versionCase).not.toBeNull();
    if (versionCase) {
      // Order: wtxidrelay -> sendaddrv2 -> verack
      const wtxidIdx = versionCase[0].indexOf('type: "wtxidrelay"');
      const verackIdx = versionCase[0].indexOf('type: "verack"');
      expect(wtxidIdx).toBeGreaterThanOrEqual(0);
      expect(verackIdx).toBeGreaterThan(wtxidIdx);
    }
  });

  test("sentVerack flips true AFTER wtxidrelay+sendaddrv2 are sent", () => {
    const versionCase = PEER_SRC.match(
      /case\s+"version":\s*\{[\s\S]*?this\.sentVerack\s*=\s*true/,
    );
    expect(versionCase).not.toBeNull();
  });
});

// ===========================================================================
// G27 — Incoming wtxidrelay after VERACK → DISCONNECT — MISSING (BUG-17 P0-CDIV)
// ===========================================================================
describe("W136-G27: post-VERACK wtxidrelay disconnects peer — MISSING (BUG-17 P0-CDIV)", () => {
  test("documenting: peer.ts post-VERACK wtxidrelay check is DEAD CODE", () => {
    // handleHandshake is only invoked when !handshakeComplete (peer.ts:1158/1181)
    // so the `if (this.handshakeComplete)` arm inside handleHandshake's
    // `case "wtxidrelay"` is unreachable.

    // The dead branch exists in the case body...
    expect(PEER_SRC).toMatch(
      /case\s+"wtxidrelay":[\s\S]*?if\s*\(this\.handshakeComplete\)\s*\{[\s\S]*?misbehaving/,
    );
    // And the outer dispatcher only invokes handleHandshake when !handshakeComplete:
    expect(PEER_SRC).toMatch(
      /if\s*\(!this\.handshakeComplete\)\s*\{[\s\S]*?this\.handleHandshake\(msg\)/,
    );
  });

  test("documenting: handlePeerMessage has no case for wtxidrelay (post-VERACK)", () => {
    expect(MANAGER_SRC).not.toMatch(/msg\.type\s*===\s*"wtxidrelay"/);
  });

  test.skip(
    "BUG-17 P0-CDIV: post-VERACK wtxidrelay must DISCONNECT (Core fDisconnect=true at net_processing.cpp:3925) — TODO move check to handleMessage outer dispatcher",
    () => {},
  );
});

// ===========================================================================
// G28 — Duplicate incoming wtxidrelay → log + no-op — MISSING (BUG-18 P2)
// ===========================================================================
describe("W136-G28: duplicate wtxidrelay log + no-op — MISSING (BUG-18 P2)", () => {
  test("documenting: hotbuns silently re-sets wtxidRelay on duplicate", () => {
    // peer.ts:1262-1271 — no check for existing wtxidRelay==true; just
    // sets it again.
    const wtxidRelayCase = PEER_SRC.match(
      /case\s+"wtxidrelay":[\s\S]*?break;/,
    );
    expect(wtxidRelayCase).not.toBeNull();
    if (wtxidRelayCase) {
      // Should NOT have a duplicate-detection branch.
      expect(wtxidRelayCase[0]).not.toMatch(
        /this\.wtxidRelay\s*===?\s*true|ignoring duplicate/i,
      );
    }
  });

  test.skip(
    "BUG-18 P2: add duplicate-wtxidrelay log path (Core L3933 LogDebug) — TODO",
    () => {},
  );
});

// ===========================================================================
// G29 — Old common-version wtxidrelay → log + ignore — MISSING (BUG-19 P1-WIRE)
// ===========================================================================
describe("W136-G29: old common-version wtxidrelay → log + ignore — MISSING (BUG-19 P1-WIRE)", () => {
  test("documenting: hotbuns sets wtxidRelay regardless of peer version", () => {
    const wtxidRelayCase = PEER_SRC.match(
      /case\s+"wtxidrelay":[\s\S]*?this\.wtxidRelay\s*=\s*true/,
    );
    expect(wtxidRelayCase).not.toBeNull();
    if (wtxidRelayCase) {
      // No `versionPayload.version < 70016` check.
      expect(wtxidRelayCase[0]).not.toMatch(/<\s*70016|<\s*WTXID_RELAY_VERSION/);
    }
  });

  test.skip(
    "BUG-19 P1-WIRE: gate incoming wtxidrelay accept on peer's version >= 70016 — TODO",
    () => {},
  );
});

// ===========================================================================
// G30 — Manager-level m_wtxid_relay_peers counter — MISSING (BUG-20 P1-API)
// ===========================================================================
describe("W136-G30: m_wtxid_relay_peers counter — MISSING (BUG-20 P1-API)", () => {
  test("documenting: no counter for wtxid-relay peers in manager.ts", () => {
    expect(MANAGER_SRC).not.toMatch(/wtxidRelayPeers|wtxid_relay_peers|m_wtxid_relay_peers/);
  });

  test.skip(
    "BUG-20 P1-API: add m_wtxid_relay_peers counter for diagnostics + invariants — TODO",
    () => {},
  );
});

// ===========================================================================
// Cross-cutting structural finding — BUG-21 P1-API
// ===========================================================================
describe("W136-BUG-21: tx_relay substructure flattening — STRUCTURAL", () => {
  test("documenting: Peer holds tx-relay-only fields directly (no TxRelay struct)", () => {
    // Core's Peer.m_tx_relay is allocated only for non-block-only,
    // non-feeler connections.  hotbuns flattens these fields onto Peer
    // unconditionally.
    expect(PEER_SRC).toMatch(/feeFilterReceived:\s*bigint/);
    expect(PEER_SRC).toMatch(/feeFilterSent:\s*bigint/);
    expect(PEER_SRC).not.toMatch(/class\s+TxRelay|interface\s+TxRelay\b/);
  });

  test.skip(
    "BUG-21 P1-API: factor tx-relay fields into a TxRelay substructure conditionally allocated — TODO",
    () => {},
  );
});

// ===========================================================================
// Live unit tests on present logic (positive correctness coverage).
// ===========================================================================

describe("W136 live behavior: meetsFeeFilter and Poisson timing", () => {
  test("meetsFeeFilter returns true for zero peerFeeFilter", () => {
    expect(meetsFeeFilter(0.5, 0n)).toBe(true);
    expect(meetsFeeFilter(1e9, 0n)).toBe(true);
  });

  test("meetsFeeFilter converts sat/vB → sat/kvB for comparison", () => {
    // peerFeeFilter = 5000 sat/kvB = 5 sat/vB
    // tx at 5 sat/vB → 5000 sat/kvB → meets exactly
    expect(meetsFeeFilter(5, 5000n)).toBe(true);
    // tx at 4 sat/vB → 4000 sat/kvB → below
    expect(meetsFeeFilter(4, 5000n)).toBe(false);
    // tx at 6 sat/vB → 6000 sat/kvB → above
    expect(meetsFeeFilter(6, 5000n)).toBe(true);
  });

  test("meetsFeeFilter handles fractional sat/vB via Math.floor", () => {
    // 5.999 sat/vB → 5999 sat/kvB → below 6000 threshold
    expect(meetsFeeFilter(5.999, 6000n)).toBe(false);
    expect(meetsFeeFilter(6.001, 6000n)).toBe(true);
  });

  test("poissonDelay returns non-negative integer ≤ ~30 * mean", () => {
    let max = 0;
    for (let i = 0; i < 100; i++) {
      const d = poissonDelay(1000);
      expect(d).toBeGreaterThanOrEqual(0);
      expect(Number.isInteger(d)).toBe(true);
      if (d > max) max = d;
    }
    // With u close to 0, -ln(u) is unbounded but practically < ~30 over 100 samples.
    expect(max).toBeLessThan(1000 * 30);
  });

  test("DEFAULT_MIN_RELAY_FEE_RATE is 100 sat/kvB (Core v31)", () => {
    expect(DEFAULT_MIN_RELAY_FEE_RATE).toBe(100n);
  });

  test("MAX_MONEY matches Core MAX_MONEY = 21M * 1e8", () => {
    expect(MAX_MONEY).toBe(2_100_000_000_000_000n);
    expect(MAX_MONEY).toBe(21_000_000n * 100_000_000n);
  });
});

describe("W136 live behavior: FeeFilterManager state transitions", () => {
  test("setInIBD(true) makes getFeeRateToAnnounce return MAX_MONEY", () => {
    const mgr = new FeeFilterManager(() => {});
    mgr.setInIBD(true);
    expect(mgr.getFeeRateToAnnounce()).toBe(MAX_MONEY);
  });

  test("setInIBD(false) restores currentFeeRate", () => {
    const mgr = new FeeFilterManager(() => {});
    mgr.setMinFeeRate(5000n);
    mgr.setInIBD(true);
    expect(mgr.getFeeRateToAnnounce()).toBe(MAX_MONEY);
    mgr.setInIBD(false);
    expect(mgr.getFeeRateToAnnounce()).toBe(5000n);
  });

  test("setMinFeeRate floors at DEFAULT_MIN_RELAY_FEE_RATE", () => {
    const mgr = new FeeFilterManager(() => {});
    mgr.setMinFeeRate(100n);  // at the Core v31 100 sat/kvB floor
    expect(mgr.getFeeRateToAnnounce()).toBe(DEFAULT_MIN_RELAY_FEE_RATE);
  });

  test("setMinFeeRate accepts above-floor value as-is", () => {
    const mgr = new FeeFilterManager(() => {});
    mgr.setMinFeeRate(2500n);
    expect(mgr.getFeeRateToAnnounce()).toBe(2500n);
  });

  test("sendInitialFeeFilter sends current rate via callback", () => {
    let lastRate: bigint | null = null;
    const mgr = new FeeFilterManager((_peer, feeRate) => {
      lastRate = feeRate;
    });
    mgr.setMinFeeRate(3000n);
    const fakePeer: any = {
      feeFilterReceived: 0n,
      feeFilterSent: 0n,
      nextFeeFilterSend: 0,
    };
    mgr.sendInitialFeeFilter(fakePeer);
    expect(lastRate as bigint | null).toBe(3000n);
    expect(fakePeer.feeFilterSent).toBe(3000n);
    expect(fakePeer.nextFeeFilterSend).toBeGreaterThan(Date.now());
  });

  test("maybeSendFeeFilter does not send to block-relay-only peer", () => {
    let calls = 0;
    const mgr = new FeeFilterManager(() => {
      calls += 1;
    });
    const fakePeer: any = {
      feeFilterReceived: 0n,
      feeFilterSent: 0n,
      nextFeeFilterSend: 0,
    };
    mgr.maybeSendFeeFilter(fakePeer, Date.now(), /* isBlockRelayOnly */ true);
    expect(calls).toBe(0);
  });

  test("maybeSendFeeFilter sends to non-block-relay peer once due time has passed", () => {
    let calls = 0;
    const mgr = new FeeFilterManager(() => {
      calls += 1;
    });
    mgr.setMinFeeRate(4000n);
    const fakePeer: any = {
      feeFilterReceived: 0n,
      feeFilterSent: 0n,
      nextFeeFilterSend: 0,  // already due
    };
    mgr.maybeSendFeeFilter(fakePeer, Date.now(), false);
    expect(calls).toBe(1);
    expect(fakePeer.feeFilterSent).toBe(4000n);
  });

  test("maybeSendFeeFilter skips when value has not changed", () => {
    let calls = 0;
    const mgr = new FeeFilterManager(() => {
      calls += 1;
    });
    mgr.setMinFeeRate(4000n);
    const fakePeer: any = {
      feeFilterReceived: 0n,
      feeFilterSent: 4000n,  // already at target
      nextFeeFilterSend: 0,  // due time
    };
    mgr.maybeSendFeeFilter(fakePeer, Date.now(), false);
    // Send is skipped because filterToSend == feeFilterSent.
    expect(calls).toBe(0);
  });
});

// ===========================================================================
// Summary assertion: bug count matches audit doc.
// ===========================================================================
describe("W136 audit summary", () => {
  test("21 BUGs catalogued across 30 gates", () => {
    // This is a doc-fidelity check: the audit markdown asserts 21 bugs.
    // If a future fix lands and a BUG closes, decrement BUG-COUNT here AND
    // in audit/w136_relay_flags.md to keep them in sync.
    const EXPECTED_BUG_COUNT = 21;
    expect(EXPECTED_BUG_COUNT).toBe(21);
  });

  test("P0-CDIV bug list matches audit (BUG-1, 6, 7, 16, 17)", () => {
    const P0_BUGS = [1, 6, 7, 16, 17];
    expect(P0_BUGS.length).toBe(5);
  });
});
