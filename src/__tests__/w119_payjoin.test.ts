/**
 * W119 BIP-78 PayJoin audit — hotbuns (TypeScript / Bun)
 *
 * 30 gates covering the BIP-78 Receiver HTTP endpoint, Sender HTTP client,
 * Original-PSBT validation, anti-snoop heuristics, BIP-21 URI extensions,
 * and the four canonical error codes.
 *
 * Reference:
 *   - BIP-78 spec: https://github.com/bitcoin/bips/blob/master/bip-0078.mediawiki
 *   - payjoin.org ecosystem docs
 *   - btcpayserver/payjoin reference receiver
 *
 * BITCOIN CORE BASELINE: Core has no PayJoin in tree. PayJoin is a wallet
 * application-layer protocol (sender + receiver are coordinated wallets that
 * talk HTTP), not a consensus or P2P feature. There is therefore no `pow.cpp`
 * or `validation.cpp` equivalent to mirror — the reference is the BIP itself
 * plus the cross-ecosystem implementations (payjoin-cli, JoinMarket, BTCPay
 * Server, Wasabi).
 *
 * Gate map:
 *   Receiver-side HTTP + PSBT (G1, G4-G9, G18-G20, G23, G26, G30)
 *     G1   Receiver HTTP endpoint exists (POST /payjoin)            MISSING
 *     G4   Receiver deserializes incoming Original PSBT             MISSING
 *     G5   Receiver validates Original PSBT is finalized + funded   MISSING
 *     G6   Receiver identifies sender fee output (BIP-78 §F.2)      MISSING
 *     G7   Receiver adds own inputs (anti-snoop coin selection)     MISSING
 *     G8   Receiver modifies sender outputs (output substitution)   MISSING
 *     G9   Receiver fee adjustment ≤ maxadditionalfeecontribution   MISSING
 *     G18  Receiver per-Original-PSBT TTL (replay window)           MISSING
 *     G19  Receiver no-double-broadcast of original-or-payjoin      MISSING
 *     G20  Receiver UTXO anti-fingerprinting (random change probe)  MISSING
 *     G23  Receiver responds with Content-Type: text/plain          MISSING
 *     G26  Receiver RPC: getpayjoinrequest                          MISSING
 *     G30  Receiver replay protection (input reuse detection)       MISSING
 *
 *   Sender-side HTTP + PSBT (G2, G10-G15, G17, G22, G27)
 *     G2   Sender HTTP client posts BIP-78 Original PSBT            MISSING
 *     G10  Sender anti-snoop: receiver-added outputs sanity check   MISSING
 *     G11  Sender validates receiver added inputs match scriptSig   MISSING
 *     G12  Sender refuses receiver-added inputs of unknown type     MISSING
 *     G13  Sender enforces max additionalfeecontribution            MISSING
 *     G14  Sender honors disableoutputsubstitution                  MISSING
 *     G15  Sender minfeerate floor on receiver-bumped fee           MISSING
 *     G17  Sender handles 4 BIP-78 error strings                    MISSING
 *     G22  Sender fallback: broadcast Original PSBT on failure      MISSING
 *     G27  Sender RPC: sendpayjoinrequest                           MISSING
 *
 *   Transport (G3, G24, G25)
 *     G3   PayJoin over Tor/.onion (rendezvous)                     MISSING
 *     G24  HTTPS / TLS certificate verification                     MISSING
 *     G25  Sender resolves .onion via SOCKS5 proxy (FIX-56 proxy.ts)
 *
 *   URI & header plumbing (G16, G21, G28, G29)
 *     G16  BIP-78 query params (v / additionalfeeoutputindex /     MISSING
 *          maxadditionalfeecontribution / disableoutputsubstitution
 *          / minfeerate)
 *     G21  BIP-78 v=1 version negotiation                           MISSING
 *     G28  BIP-21 URI: pj= endpoint                                 MISSING
 *     G29  BIP-21 URI: pjos=0 (disableoutputsubstitution)           MISSING
 *
 * Status legend:
 *   PASS    — correct behaviour confirmed against BIP-78 + ecosystem
 *   FAIL    — bug confirmed (behaviour wrong vs spec)
 *   MISSING — feature not implemented (PayJoin entirely absent)
 *
 * Findings summary (BUG-1 through BUG-6):
 *   BUG-1 (P0-FEATURE) — PayJoin entirely absent. No receiver endpoint,
 *         no sender client, no BIP-21 pj=/pjos= parsing, no RPC methods.
 *   BUG-2 (HIGH)       — No BIP-21 bitcoin:address?amount=… URI parser
 *         anywhere in the codebase. Even non-PayJoin BIP-21 is missing,
 *         which means hotbuns cannot read the URIs that PayJoin extends.
 *   BUG-3 (HIGH)       — PSBT module (src/wallet/psbt.ts) only supports
 *         BIP-174 v0; BIP-78 doesn't strictly require v2 but receiver-
 *         added-inputs flows benefit from PSBTv2's per-input modify_flag.
 *         W118 BUG-3 already flagged PSBTv2 missing — carry-forward 8th
 *         consecutive wave.
 *   BUG-4 (MEDIUM)     — No HTTP client. The codebase has Bun.serve for
 *         inbound RPC/REST but no outbound HTTP client; sender side would
 *         need fetch() wired through proxy.ts for .onion endpoints.
 *   BUG-5 (MEDIUM)     — No anti-snoop coin-selection mode in wallet.ts.
 *         selectCoins() is a single deterministic BnB; receiver-side
 *         PayJoin needs UTXO probing (BIP-78 §F.1) to avoid revealing the
 *         full UTXO set via timing/order side channels.
 *   BUG-6 (LOW)        — No per-request TTL / replay window registry.
 *         The outgoingTxs Map (added in FIX-61) tracks sender txs but
 *         there is no receiver-side request store keyed by Original-PSBT
 *         hash with a TTL window.
 *
 * Cross-cutting with FIX-61:
 *   The outgoingTxs Map already lets the wallet locate "this is a tx I
 *   sent" by txid. PayJoin's sender side would extend the same Map:
 *   when a fallback broadcast happens (G22), the Original PSBT is exactly
 *   the createTransaction() output, so outgoingTxs.set(origTxid, …) is
 *   already correct. When the PayJoin succeeds, the receiver-modified
 *   tx has a different txid and would need its own entry — the chain
 *   already supports this via the existing bumpfee logic that records
 *   parent + replacement.
 *
 * NOTE: every test in this file is `test.skip` because the feature is
 * MISSING ENTIRELY. The skip body still contains the assertion that WOULD
 * run when the feature lands, so FIX-N can flip skip→test on each gate.
 */

import { describe, expect, test } from "bun:test";

// Imports that EXIST today and that PayJoin will reuse. Imported here so
// the test file compiles cleanly and so the skipped tests still type-check.
// When the FIX-N wave lands, the new payjoin module will live alongside
// wallet/psbt and the imports below will grow.
import { createPSBT, deserializePSBT, decodePSBTBase64 } from "../wallet/psbt";

describe("W119 BIP-78 PayJoin audit — hotbuns", () => {
  describe("Receiver-side HTTP + PSBT", () => {
    // G1: Receiver HTTP endpoint exists.
    //
    // BIP-78 §B requires the receiver to expose an HTTPS endpoint that
    // accepts POST with an Original PSBT body. hotbuns has Bun.serve for
    // the JSON-RPC (rpc/server.ts) and REST (rpc/rest.ts) endpoints, but
    // no dedicated payjoin endpoint. The expected location would be
    // src/payjoin/receiver.ts exporting startPayJoinReceiver(opts).
    //
    // MISSING — no endpoint, no module, no CLI flag.
    test.skip("G1: receiver POST /payjoin endpoint exists", async () => {
      // EXPECTED behaviour when implemented:
      //   const recv = await startPayJoinReceiver({ port: 0, wallet });
      //   const r = await fetch(`http://localhost:${recv.port}/payjoin?v=1`, {
      //     method: "POST",
      //     headers: { "Content-Type": "text/plain" },
      //     body: encodePSBTBase64(originalPsbt),
      //   });
      //   expect(r.status).toBe(200);
      expect(true).toBe(false); // sentinel: must fail if un-skipped pre-fix
    });

    // G4: Receiver deserializes the incoming Original PSBT.
    //
    // BIP-78 §F.1: receiver MUST parse, MUST NOT broadcast yet, MUST
    // verify Original PSBT is finalized (sender already signed every
    // input — withdrawal is opt-in for the sender if receiver crashes).
    //
    // MISSING — deserializePSBT exists, but no receiver handler calls it.
    test.skip("G4: receiver parses Original PSBT base64 body", async () => {
      // EXPECTED:
      //   const body = encodePSBTBase64(originalPsbt);
      //   const parsed = decodePSBTBase64(body);
      //   expect(isInputFinalized(parsed, 0)).toBe(true);
      const dummy = Buffer.from("70736274ff01", "hex");
      expect(() => deserializePSBT(dummy)).toThrow();
    });

    // G5: Receiver validates Original PSBT is finalized + funded.
    test.skip("G5: receiver rejects unfinalized Original PSBT", async () => {
      // EXPECTED: a non-finalized input MUST cause original-psbt-rejected.
      expect(true).toBe(false);
    });

    // G6: Receiver identifies the sender's fee output.
    //
    // BIP-78 §F.2: sender supplies additionalfeeoutputindex query param.
    // Receiver subtracts maxadditionalfeecontribution from that output
    // when adding inputs. If sender omits the param AND there's only one
    // output paying the receiver, the change output is implicit.
    test.skip("G6: receiver respects additionalfeeoutputindex query param", async () => {
      expect(true).toBe(false);
    });

    // G7: Receiver adds own inputs (the actual "join" step).
    //
    // BIP-78 §F.3: receiver picks one or more UTXOs from its own wallet,
    // adds them as inputs, increases its own output by the input value
    // minus its fee share. Output script type SHOULD match sender's to
    // preserve the join illusion (BIP-78 §C.1 anti-snoop).
    test.skip("G7: receiver adds inputs matching sender script type", async () => {
      expect(true).toBe(false);
    });

    // G8: Receiver may modify sender outputs (output substitution).
    //
    // Only legal when sender did NOT set pjos=0 / disableoutputsubstitution
    // (G14/G29). When allowed, receiver may consolidate change.
    test.skip("G8: receiver output-substitution only without pjos=0", async () => {
      expect(true).toBe(false);
    });

    // G9: Receiver fee adjustment must be ≤ maxadditionalfeecontribution.
    test.skip("G9: receiver fee delta ≤ maxadditionalfeecontribution", async () => {
      expect(true).toBe(false);
    });

    // G18: Receiver per-Original-PSBT TTL.
    //
    // Standard ecosystem behaviour (payjoin-cli / BTCPay) is to keep an
    // in-memory map keyed by the Original PSBT hash for ~60s. Outside
    // that window the request is rejected to prevent timing-correlation
    // attacks. hotbuns has outgoingTxs Map from FIX-61 — receiver side
    // would need a parallel `pendingPayJoinRequests: Map<string, …>`.
    test.skip("G18: receiver TTL drops requests older than window", async () => {
      expect(true).toBe(false);
    });

    // G19: Receiver MUST NOT broadcast both the Original and the PayJoin.
    test.skip("G19: receiver never broadcasts both original and payjoin", async () => {
      expect(true).toBe(false);
    });

    // G20: UTXO anti-fingerprinting (BIP-78 §C.2).
    //
    // Receiver MUST randomise: (a) which of its UTXOs gets contributed,
    // (b) the position of the receiver-added input in the input vector,
    // and (c) the change output position. Naive deterministic selection
    // leaks the UTXO set to a snooping sender that runs the protocol N
    // times back-to-back.
    test.skip("G20: receiver randomises UTXO probe order", async () => {
      expect(true).toBe(false);
    });

    // G23: Receiver responds with Content-Type: text/plain.
    test.skip("G23: receiver Content-Type: text/plain base64 body", async () => {
      expect(true).toBe(false);
    });

    // G26: RPC method getpayjoinrequest.
    test.skip("G26: RPC getpayjoinrequest returns pending request info", async () => {
      expect(true).toBe(false);
    });

    // G30: Replay protection.
    test.skip("G30: receiver rejects Original PSBT with reused inputs", async () => {
      expect(true).toBe(false);
    });
  });

  describe("Sender-side HTTP + PSBT", () => {
    // G2: Sender HTTP client posts BIP-78 Original PSBT.
    test.skip("G2: sender POSTs Original PSBT to pj= endpoint", async () => {
      expect(true).toBe(false);
    });

    // G10: Sender anti-snoop on receiver-added outputs.
    //
    // BIP-78 §C: sender MUST sanity-check the returned PSBT — outputs
    // the sender DID NOT include must have addresses owned by the
    // receiver (their P2WPKH script type matches), and sender's own
    // outputs must remain at the same scriptPubKey (unless pjos=0
    // was not set).
    test.skip("G10: sender validates receiver-added outputs", async () => {
      expect(true).toBe(false);
    });

    // G11: Sender validates receiver added inputs match scriptSig.
    test.skip("G11: sender rejects PSBT with malformed receiver inputs", async () => {
      expect(true).toBe(false);
    });

    // G12: Sender refuses receiver inputs of unknown script type.
    test.skip("G12: sender refuses unknown-type receiver inputs", async () => {
      expect(true).toBe(false);
    });

    // G13: Sender enforces max additionalfeecontribution.
    test.skip("G13: sender rejects fee delta > maxadditionalfeecontribution", async () => {
      expect(true).toBe(false);
    });

    // G14: Sender honors disableoutputsubstitution.
    test.skip("G14: sender refuses PSBT with substituted outputs when pjos=0", async () => {
      expect(true).toBe(false);
    });

    // G15: Sender minfeerate floor on receiver-bumped fee.
    test.skip("G15: sender rejects PSBT below minfeerate", async () => {
      expect(true).toBe(false);
    });

    // G17: Sender handles the 4 BIP-78 error strings.
    //
    // BIP-78 §G: receiver returns one of:
    //   - "unavailable"           (receiver not ready / cold-storage)
    //   - "not-enough-money"      (receiver UTXO probe failed)
    //   - "version-unsupported"   (v != 1)
    //   - "original-psbt-rejected" (any validation failure)
    //
    // Sender behaviour MUST distinguish "unavailable" (retry-fallback)
    // from "original-psbt-rejected" (give up — likely sender bug).
    test.skip("G17: sender distinguishes 4 BIP-78 error strings", async () => {
      expect(true).toBe(false);
    });

    // G22: Sender fallback — broadcast Original PSBT on failure.
    //
    // BIP-78 §H: when receiver is "unavailable" or HTTP times out, the
    // sender SHOULD broadcast the Original PSBT (which is already
    // finalized + signed — that's the point of the protocol). hotbuns
    // wallet.ts createTransaction() already produces a signed tx; the
    // fallback path is "submit the original tx to mempool".
    test.skip("G22: sender broadcasts Original PSBT on receiver failure", async () => {
      expect(true).toBe(false);
    });

    // G27: RPC method sendpayjoinrequest.
    test.skip("G27: RPC sendpayjoinrequest signs + POSTs + broadcasts", async () => {
      expect(true).toBe(false);
    });
  });

  describe("Transport (HTTP/Tor)", () => {
    // G3: PayJoin over Tor.
    //
    // Production PayJoin (BTCPay, JoinMarket) almost always goes through
    // Tor — the receiver endpoint is a v3 .onion. hotbuns has proxy.ts
    // wired up via FIX-56 for outbound P2P; the same SOCKS5 client would
    // be reused here. This is essentially "wire the existing helper to
    // a new call site".
    test.skip("G3: sender PayJoin POST resolves via Tor SOCKS5", async () => {
      expect(true).toBe(false);
    });

    // G24: HTTPS / TLS certificate verification.
    test.skip("G24: HTTPS certificate is verified (not bypassed)", async () => {
      expect(true).toBe(false);
    });

    // G25: Sender resolves .onion via SOCKS5 proxy.
    //
    // proxy.ts already supports SOCKS5+.onion via FIX-56. The PayJoin
    // sender would wrap fetch() with a custom dispatcher that routes
    // through the existing ProxyManager — Bun supports `tls`+`socket`
    // primitives, so a small "fetch via SOCKS5" helper in proxy.ts is
    // the only missing piece.
    test.skip("G25: sender uses proxy.ts SOCKS5 for .onion PayJoin", async () => {
      expect(true).toBe(false);
    });
  });

  describe("URI & header plumbing", () => {
    // G16: BIP-78 query params.
    //
    // BIP-78 §D query parameters (case-sensitive):
    //   v                            (required, integer, currently "1")
    //   additionalfeeoutputindex     (optional, integer, sender's fee output)
    //   maxadditionalfeecontribution (optional, integer, satoshis)
    //   disableoutputsubstitution    (optional, bool, default false)
    //   minfeerate                   (optional, decimal, sat/vB)
    test.skip("G16: receiver parses all 5 BIP-78 query params", async () => {
      expect(true).toBe(false);
    });

    // G21: BIP-78 v=1 version negotiation.
    //
    // Receiver MUST return "version-unsupported" for v != 1.
    test.skip("G21: receiver rejects v != 1 with version-unsupported", async () => {
      expect(true).toBe(false);
    });

    // G28: BIP-21 URI extension — pj= endpoint.
    //
    // BIP-21 ABNF extension: bitcoin:<addr>?amount=…&pj=<https-url>
    // hotbuns has NO BIP-21 URI parser anywhere in src/address/encoding.ts
    // or wallet — both pj= and pjos= require a BIP-21 parser to exist
    // first. This is BUG-2 (HIGH).
    test.skip("G28: BIP-21 URI parser extracts pj= endpoint", async () => {
      // EXPECTED:
      //   const uri = parseBip21Uri(
      //     "bitcoin:bc1q...?amount=0.01&pj=https://example.com/payjoin"
      //   );
      //   expect(uri.pj).toBe("https://example.com/payjoin");
      expect(true).toBe(false);
    });

    // G29: BIP-21 URI extension — pjos=0.
    test.skip("G29: BIP-21 URI parser extracts pjos=0 disableoutputsubstitution", async () => {
      // EXPECTED:
      //   const uri = parseBip21Uri(
      //     "bitcoin:bc1q...?amount=0.01&pj=https://x.com/p&pjos=0"
      //   );
      //   expect(uri.pjos).toBe(false); // false ⇒ disabled
      expect(true).toBe(false);
    });
  });

  describe("Infrastructure baseline (sanity)", () => {
    // The PSBT module exists and supports BIP-174 v0 — confirm so a
    // future FIX-N has a known foundation.
    test("PSBT BIP-174 v0 deserializer is available", () => {
      const minimal = Buffer.concat([
        Buffer.from("70736274ff", "hex"), // PSBT_MAGIC
        // Without a valid global UNSIGNED_TX this is intentionally invalid
        // — we only assert the function exists + throws on garbage.
      ]);
      expect(() => deserializePSBT(minimal)).toThrow();
    });

    // Wallet.outgoingTxs Map from FIX-61 is the natural anchor for
    // sender-side PayJoin (fallback broadcast = original tx).
    test("FIX-61 outgoingTxs / bumpfee infrastructure exists in wallet", async () => {
      const { Wallet } = await import("../wallet/wallet");
      expect(typeof Wallet.prototype.getOutgoingTx).toBe("function");
      expect(typeof Wallet.prototype.bumpFee).toBe("function");
      expect(typeof Wallet.prototype.psbtBumpFee).toBe("function");
    });

    // FIX-56 proxy.ts is the natural anchor for .onion PayJoin transport.
    test("FIX-56 proxy.ts SOCKS5 module exists", async () => {
      const mod = await import("../p2p/proxy");
      expect(mod).toBeDefined();
    });

    // BIP-21 URI parser is MISSING — record explicitly so FIX-N knows
    // to add it before BIP-78 G28/G29 can pass.
    test("BIP-21 URI parser is MISSING (BUG-2)", async () => {
      // No parseBip21Uri export anywhere — this is a positive test of the
      // absence so the bug status is machine-checkable. When FIX-N adds
      // the parser, this test should be flipped to import and assert.
      // Keep dynamic import path matching where the parser will land.
      let found = false;
      try {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const mod: any = await import("../address/encoding");
        found = typeof mod.parseBip21Uri === "function";
      } catch {
        found = false;
      }
      expect(found).toBe(false);
    });
  });
});
