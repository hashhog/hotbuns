/**
 * FIX-62 — BIP-21 URI parser for hotbuns.
 *
 * Closes W119 BUG-2 (HIGH): "No BIP-21 bitcoin:address?amount=… URI
 * parser anywhere in the codebase. Even non-PayJoin BIP-21 is missing."
 *
 * Also satisfies the prereq for W119 G28 (pj= endpoint) and
 * G29 (pjos=0) — the BIP-78 PayJoin gates assume a working BIP-21
 * parser sitting on a sane address validator.
 *
 * Reference: https://github.com/bitcoin/bips/blob/master/bip-0021.mediawiki
 * BIP-78 §6:  https://github.com/bitcoin/bips/blob/master/bip-0078.mediawiki
 */

import { describe, expect, test } from "bun:test";
import { parseBip21Uri, type Bip21Uri } from "../address/encoding.js";

// Known-good test addresses from the existing encoding tests so we
// avoid coupling to BIP-21 logic by reusing literals that already round-
// trip via decodeAddress in encoding.test.ts.
const P2PKH_MAINNET = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
const P2SH_MAINNET = "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy";
const P2WPKH_MAINNET = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";

function ok(r: ReturnType<typeof parseBip21Uri>): Bip21Uri {
  if (!r.ok) throw new Error(`expected ok=true, got ${r.kind}: ${r.message}`);
  return r;
}

describe("BIP-21 URI parser (FIX-62)", () => {
  describe("standard parses", () => {
    test("bitcoin:<addr> with no query parses", () => {
      const r = parseBip21Uri(`bitcoin:${P2PKH_MAINNET}`, "mainnet");
      const u = ok(r);
      expect(u.address).toBe(P2PKH_MAINNET);
      expect(u.amount).toBeUndefined();
      expect(u.label).toBeUndefined();
      expect(u.message).toBeUndefined();
      expect(u.extras).toBeUndefined();
    });

    test("bitcoin:<bech32-addr> with no query parses", () => {
      const u = ok(parseBip21Uri(`bitcoin:${P2WPKH_MAINNET}`, "mainnet"));
      expect(u.address).toBe(P2WPKH_MAINNET);
    });

    test("amount=1.0 → 100_000_000 sat", () => {
      const u = ok(parseBip21Uri(`bitcoin:${P2PKH_MAINNET}?amount=1.0`, "mainnet"));
      expect(u.amount).toBe(100_000_000n);
    });

    test("amount=0.00000001 → 1 sat (8 dp precision)", () => {
      const u = ok(parseBip21Uri(`bitcoin:${P2PKH_MAINNET}?amount=0.00000001`, "mainnet"));
      expect(u.amount).toBe(1n);
    });

    test("amount=21000000 → 21M BTC in sat", () => {
      const u = ok(parseBip21Uri(`bitcoin:${P2PKH_MAINNET}?amount=21000000`, "mainnet"));
      expect(u.amount).toBe(21_000_000n * 100_000_000n);
    });

    test("amount=.5 (no integer part) parses to 50_000_000 sat", () => {
      const u = ok(parseBip21Uri(`bitcoin:${P2PKH_MAINNET}?amount=.5`, "mainnet"));
      expect(u.amount).toBe(50_000_000n);
    });

    test("amount=5. (no frac part) parses to 5 BTC sat", () => {
      const u = ok(parseBip21Uri(`bitcoin:${P2PKH_MAINNET}?amount=5.`, "mainnet"));
      expect(u.amount).toBe(500_000_000n);
    });

    test("label, message round-trip without percent-encoding", () => {
      const u = ok(
        parseBip21Uri(`bitcoin:${P2PKH_MAINNET}?label=Luke-Jr&message=Donation`, "mainnet")
      );
      expect(u.label).toBe("Luke-Jr");
      expect(u.message).toBe("Donation");
    });

    test("multiple recognized params combine", () => {
      const u = ok(
        parseBip21Uri(
          `bitcoin:${P2PKH_MAINNET}?amount=20.30&label=Luke-Jr&message=Donation`,
          "mainnet"
        )
      );
      expect(u.amount).toBe(20_30_000_000n); // 20.30 BTC = 2_030_000_000 sat
      expect(u.amount).toBe(2_030_000_000n);
      expect(u.label).toBe("Luke-Jr");
      expect(u.message).toBe("Donation");
    });

    test("unknown non-req params go into extras (lower-cased)", () => {
      const u = ok(
        parseBip21Uri(`bitcoin:${P2PKH_MAINNET}?foo=bar&BAZ=qux`, "mainnet")
      );
      expect(u.extras?.foo).toBe("bar");
      expect(u.extras?.baz).toBe("qux");
      // recognized fields stay unset
      expect(u.amount).toBeUndefined();
      expect(u.label).toBeUndefined();
    });

    test("trailing/extra & separators are tolerated", () => {
      const u = ok(parseBip21Uri(`bitcoin:${P2PKH_MAINNET}?amount=1.0&`, "mainnet"));
      expect(u.amount).toBe(100_000_000n);
    });

    test("fragment after query is ignored", () => {
      const u = ok(parseBip21Uri(`bitcoin:${P2PKH_MAINNET}?amount=1.0#anchor`, "mainnet"));
      expect(u.amount).toBe(100_000_000n);
    });
  });

  describe("percent-decoding", () => {
    test("label with %20 decodes to space", () => {
      const u = ok(parseBip21Uri(`bitcoin:${P2PKH_MAINNET}?label=Hello%20World`, "mainnet"));
      expect(u.label).toBe("Hello World");
    });

    test("message with %C3%A9 decodes to é (UTF-8)", () => {
      const u = ok(parseBip21Uri(`bitcoin:${P2PKH_MAINNET}?message=caf%C3%A9`, "mainnet"));
      expect(u.message).toBe("café");
    });

    test("ampersand inside label percent-encoded as %26", () => {
      const u = ok(parseBip21Uri(`bitcoin:${P2PKH_MAINNET}?label=A%26B`, "mainnet"));
      expect(u.label).toBe("A&B");
    });

    test("does NOT treat + as space (RFC-3986, not form-urlencoded)", () => {
      const u = ok(parseBip21Uri(`bitcoin:${P2PKH_MAINNET}?label=Hello+World`, "mainnet"));
      expect(u.label).toBe("Hello+World");
    });

    test("malformed percent-encoding rejected", () => {
      const r = parseBip21Uri(`bitcoin:${P2PKH_MAINNET}?label=bad%2Z`, "mainnet");
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.kind).toBe("pct");
    });

    test("truncated percent-encoding rejected", () => {
      const r = parseBip21Uri(`bitcoin:${P2PKH_MAINNET}?label=bad%2`, "mainnet");
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.kind).toBe("pct");
    });
  });

  describe("req- rejection (BIP-21 MUST)", () => {
    test("req-foo unknown rejects the URI", () => {
      const r = parseBip21Uri(`bitcoin:${P2PKH_MAINNET}?req-foo=bar`, "mainnet");
      expect(r.ok).toBe(false);
      if (!r.ok) {
        expect(r.kind).toBe("req-unknown");
        if (r.kind === "req-unknown") expect(r.param).toBe("req-foo");
      }
    });

    test("REQ-FOO (case-insensitive) also rejects", () => {
      const r = parseBip21Uri(`bitcoin:${P2PKH_MAINNET}?REQ-FOO=bar`, "mainnet");
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.kind).toBe("req-unknown");
    });

    test("regular foo without req- prefix is fine (goes into extras)", () => {
      const u = ok(parseBip21Uri(`bitcoin:${P2PKH_MAINNET}?foo=bar`, "mainnet"));
      expect(u.extras?.foo).toBe("bar");
    });
  });

  describe("BIP-78 PayJoin (G28 + G29)", () => {
    // G28 — pj= endpoint extraction.
    test("G28: pj= endpoint is extracted", () => {
      const u = ok(
        parseBip21Uri(
          `bitcoin:${P2PKH_MAINNET}?amount=0.01&pj=https://example.com/payjoin`,
          "mainnet"
        )
      );
      expect(u.pj).toBe("https://example.com/payjoin");
      expect(u.amount).toBe(1_000_000n);
    });

    test("G28: pj= URL with percent-encoded reserved chars decodes", () => {
      const u = ok(
        parseBip21Uri(
          `bitcoin:${P2PKH_MAINNET}?pj=https%3A%2F%2Fhost%2Fpath%3Fa%3Db`,
          "mainnet"
        )
      );
      expect(u.pj).toBe("https://host/path?a=b");
    });

    // G29 — pjos=0 / pjos=1.
    test("G29: pjos=0 → output substitution DISABLED (false)", () => {
      const u = ok(
        parseBip21Uri(
          `bitcoin:${P2PKH_MAINNET}?amount=0.01&pj=https://x.com/p&pjos=0`,
          "mainnet"
        )
      );
      expect(u.pjos).toBe(false);
    });

    test("G29: pjos=1 → substitution ENABLED (true)", () => {
      const u = ok(
        parseBip21Uri(`bitcoin:${P2PKH_MAINNET}?pj=https://x.com/p&pjos=1`, "mainnet")
      );
      expect(u.pjos).toBe(true);
    });

    test("G29: pjos=2 → rejected (must be 0 or 1)", () => {
      const r = parseBip21Uri(`bitcoin:${P2PKH_MAINNET}?pj=https://x/p&pjos=2`, "mainnet");
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.kind).toBe("pjos");
    });

    test("G29: pjos absent → undefined (default = substitution enabled)", () => {
      const u = ok(parseBip21Uri(`bitcoin:${P2PKH_MAINNET}?pj=https://x/p`, "mainnet"));
      expect(u.pjos).toBeUndefined();
    });

    test("lightning= invoice fallback string captured verbatim", () => {
      const ln =
        "lnbc1pjlmnopqr1234567890abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnop";
      const u = ok(
        parseBip21Uri(`bitcoin:${P2PKH_MAINNET}?lightning=${ln}`, "mainnet")
      );
      expect(u.lightning).toBe(ln);
    });
  });

  describe("case-insensitive keys + scheme", () => {
    test("scheme BITCOIN: is accepted", () => {
      const u = ok(parseBip21Uri(`BITCOIN:${P2PKH_MAINNET}`, "mainnet"));
      expect(u.address).toBe(P2PKH_MAINNET);
    });

    test("scheme Bitcoin: is accepted", () => {
      const u = ok(parseBip21Uri(`Bitcoin:${P2PKH_MAINNET}`, "mainnet"));
      expect(u.address).toBe(P2PKH_MAINNET);
    });

    test("AMOUNT=, Label=, MESSAGE= are recognized", () => {
      const u = ok(
        parseBip21Uri(
          `bitcoin:${P2PKH_MAINNET}?AMOUNT=2.5&Label=L&MESSAGE=M`,
          "mainnet"
        )
      );
      expect(u.amount).toBe(2_5000_0000n);
      expect(u.label).toBe("L");
      expect(u.message).toBe("M");
    });

    test("Pj=, PJOS= recognized", () => {
      const u = ok(
        parseBip21Uri(
          `bitcoin:${P2PKH_MAINNET}?Pj=https://x/p&PJOS=0`,
          "mainnet"
        )
      );
      expect(u.pj).toBe("https://x/p");
      expect(u.pjos).toBe(false);
    });

    test("duplicate of same recognized key (case-folded) is rejected", () => {
      const r = parseBip21Uri(
        `bitcoin:${P2PKH_MAINNET}?amount=1.0&AMOUNT=2.0`,
        "mainnet"
      );
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.kind).toBe("duplicate");
    });
  });

  describe("validation errors", () => {
    test("missing scheme rejected", () => {
      const r = parseBip21Uri(P2PKH_MAINNET, "mainnet");
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.kind).toBe("scheme");
    });

    test("wrong scheme (ethereum:) rejected", () => {
      const r = parseBip21Uri(`ethereum:${P2PKH_MAINNET}`, "mainnet");
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.kind).toBe("scheme");
    });

    test("empty address (just bitcoin:) rejected", () => {
      const r = parseBip21Uri("bitcoin:", "mainnet");
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.kind).toBe("empty");
    });

    test("empty address with query (bitcoin:?amount=1) rejected", () => {
      const r = parseBip21Uri("bitcoin:?amount=1", "mainnet");
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.kind).toBe("empty");
    });

    test("garbage address rejected with address error", () => {
      const r = parseBip21Uri("bitcoin:notanaddress!!!", "mainnet");
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.kind).toBe("address");
    });

    test("network mismatch: mainnet addr against testnet requested", () => {
      const r = parseBip21Uri(`bitcoin:${P2PKH_MAINNET}`, "testnet");
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.kind).toBe("network");
    });

    test("amount with two dots rejected", () => {
      const r = parseBip21Uri(`bitcoin:${P2PKH_MAINNET}?amount=1.0.0`, "mainnet");
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.kind).toBe("amount");
    });

    test("amount with 9 fractional digits rejected (overflow precision)", () => {
      const r = parseBip21Uri(`bitcoin:${P2PKH_MAINNET}?amount=0.000000001`, "mainnet");
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.kind).toBe("amount");
    });

    test("amount with negative sign rejected", () => {
      const r = parseBip21Uri(`bitcoin:${P2PKH_MAINNET}?amount=-1.0`, "mainnet");
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.kind).toBe("amount");
    });

    test("amount with exponential rejected", () => {
      const r = parseBip21Uri(`bitcoin:${P2PKH_MAINNET}?amount=1e8`, "mainnet");
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.kind).toBe("amount");
    });

    test("bare dot amount rejected", () => {
      const r = parseBip21Uri(`bitcoin:${P2PKH_MAINNET}?amount=.`, "mainnet");
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.kind).toBe("amount");
    });

    test("empty query key rejected", () => {
      const r = parseBip21Uri(`bitcoin:${P2PKH_MAINNET}?=val`, "mainnet");
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.kind).toBe("query");
    });

    test("duplicate of unknown key (extras) is also rejected", () => {
      const r = parseBip21Uri(`bitcoin:${P2PKH_MAINNET}?foo=1&FOO=2`, "mainnet");
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.kind).toBe("duplicate");
    });

    test("non-string input rejected at scheme gate", () => {
      // intentionally bypass TS to mimic a runtime caller.
      const r = parseBip21Uri(123 as unknown as string, "mainnet");
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.kind).toBe("scheme");
    });
  });

  describe("address types", () => {
    test("P2SH address parses", () => {
      const u = ok(parseBip21Uri(`bitcoin:${P2SH_MAINNET}`, "mainnet"));
      expect(u.address).toBe(P2SH_MAINNET);
    });

    test("P2WPKH (bech32) address parses with amount", () => {
      const u = ok(
        parseBip21Uri(`bitcoin:${P2WPKH_MAINNET}?amount=0.1`, "mainnet")
      );
      expect(u.address).toBe(P2WPKH_MAINNET);
      expect(u.amount).toBe(10_000_000n);
    });
  });

  describe("BIP-21 mediawiki spec vectors", () => {
    // From https://github.com/bitcoin/bips/blob/master/bip-0021.mediawiki §Examples
    // (addresses substituted with checksummed equivalents on the same network
    // so decodeAddress accepts them; the BIP examples use 175tWpb8 which is
    // an unchecksummed placeholder.)

    test("vector: just an address", () => {
      const u = ok(parseBip21Uri(`bitcoin:${P2PKH_MAINNET}`, "mainnet"));
      expect(u.address).toBe(P2PKH_MAINNET);
    });

    test("vector: address with name", () => {
      const u = ok(
        parseBip21Uri(`bitcoin:${P2PKH_MAINNET}?label=Luke-Jr`, "mainnet")
      );
      expect(u.label).toBe("Luke-Jr");
    });

    test("vector: request 20.30 BTC to address with name", () => {
      const u = ok(
        parseBip21Uri(
          `bitcoin:${P2PKH_MAINNET}?amount=20.30&label=Luke-Jr`,
          "mainnet"
        )
      );
      expect(u.amount).toBe(2_030_000_000n);
      expect(u.label).toBe("Luke-Jr");
    });

    test("vector: request 50 BTC with message", () => {
      const u = ok(
        parseBip21Uri(
          `bitcoin:${P2PKH_MAINNET}?amount=50&label=Luke-Jr&message=Donation%20for%20project%20xyz`,
          "mainnet"
        )
      );
      expect(u.amount).toBe(5_000_000_000n);
      expect(u.label).toBe("Luke-Jr");
      expect(u.message).toBe("Donation for project xyz");
    });

    test("vector: required not-understood req- rejects", () => {
      const r = parseBip21Uri(
        `bitcoin:${P2PKH_MAINNET}?req-somethingyoudontunderstand=50&req-somethingelseyoudontget=999`,
        "mainnet"
      );
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.kind).toBe("req-unknown");
    });

    test("vector: optional somethingyoudontunderstand goes to extras", () => {
      const u = ok(
        parseBip21Uri(
          `bitcoin:${P2PKH_MAINNET}?somethingyoudontunderstand=50&somethingelseyoudontget=999`,
          "mainnet"
        )
      );
      expect(u.extras?.somethingyoudontunderstand).toBe("50");
      expect(u.extras?.somethingelseyoudontget).toBe("999");
    });
  });

  // ============================================================
  // W119 audit assertion flips (BUG-2 / G28 / G29)
  // ============================================================
  //
  // The audit recorded the parser's absence via:
  //   src/__tests__/w119_payjoin.test.ts:410-424
  //     "BIP-21 URI parser is MISSING (BUG-2)"
  //     → expect(found).toBe(false);
  // and G28/G29 as `test.skip(...)`.
  //
  // We don't edit those files (audit history stays intact). Instead we
  // re-prove the inverse here: parseBip21Uri exists and produces the
  // expected results for G28 and G29.

  describe("W119 audit assertions (flipped)", () => {
    test("BUG-2: parseBip21Uri is present in src/address/encoding", async () => {
      const mod: { parseBip21Uri?: unknown } = await import("../address/encoding.js");
      expect(typeof mod.parseBip21Uri).toBe("function");
    });

    test("G28 (flipped): parseBip21Uri extracts pj= endpoint", () => {
      const u = ok(
        parseBip21Uri(
          `bitcoin:${P2WPKH_MAINNET}?amount=0.01&pj=https://example.com/payjoin`,
          "mainnet"
        )
      );
      expect(u.pj).toBe("https://example.com/payjoin");
    });

    test("G29 (flipped): parseBip21Uri extracts pjos=0 → false", () => {
      const u = ok(
        parseBip21Uri(
          `bitcoin:${P2WPKH_MAINNET}?amount=0.01&pj=https://x.com/p&pjos=0`,
          "mainnet"
        )
      );
      expect(u.pjos).toBe(false);
    });
  });
});
