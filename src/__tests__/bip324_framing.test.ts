/**
 * BIP-324 v2 transport framing-correctness tests.
 *
 * These tests target three framing bugs found vs Bitcoin Core net.cpp and
 * are written to FAIL on the pre-fix hotbuns behavior (non-vacuous):
 *
 *  - G19: a DECOY (ignore-bit set) packet received in the VERSION state must
 *         be skipped WITHOUT advancing to APP.  Core net.cpp:1249-1264 only
 *         transitions VERSION->APP on a non-decoy.  The pre-fix code advanced
 *         on ANY first packet, so a leading decoy desynced the responder and
 *         the real version packet was mis-parsed as an APP message.
 *
 *  - G16: the GARB_GARBTERM abort threshold is `==` MAX_GARBAGE_LEN +
 *         GARBAGE_TERMINATOR_LEN (4111) in Core net.cpp:1192; the pre-fix
 *         code only aborted when strictly ABOVE 4111 (i.e. at 4112).
 *
 *  - G25: generateGarbage draws the garbage LENGTH from a CSPRNG
 *         (crypto.randomBytes), matching Core GenerateRandomGarbage
 *         (FastRandomContext).  The pre-fix code used the non-crypto global
 *         Math.random().
 *
 * Reference: Bitcoin Core src/net.cpp V2Transport.
 */

import { afterEach, describe, expect, test } from "bun:test";
import {
  V2Transport,
  RecvState,
  GARBAGE_TERMINATOR_LEN,
  MAX_GARBAGE_LEN,
} from "../p2p/v2_transport.js";
import {
  BIP324Cipher,
  generateGarbage,
} from "../p2p/bip324/cipher.js";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { randomBytes } from "crypto";

const MAINNET_MAGIC = Buffer.from([0xf9, 0xbe, 0xb4, 0xd9]);

/** A random valid secp256k1 private key. */
function randPriv(): Buffer {
  let k = randomBytes(32);
  while (!secp256k1.utils.isValidSecretKey(k)) {
    k = randomBytes(32);
  }
  return k;
}

/**
 * Build a paired initiator/responder using fixed (per-call random) keys via
 * withParams so the transports are deterministic for the lifetime of a test,
 * plus a MIRROR of the initiator's send cipher so we can hand-encrypt the
 * initiator->responder version-phase stream (decoys + real version) in the
 * correct FSChaCha20 packet order.
 */
function makePairWithMirror() {
  const initPriv = randPriv();
  const initEntropy = randomBytes(32);
  const respPriv = randPriv();
  const respEntropy = randomBytes(32);
  // Zero-length garbage on both sides keeps the wire deterministic and avoids
  // the (astronomically unlikely) garbage-terminator-in-garbage collision.
  const initGarbage = Buffer.alloc(0);
  const respGarbage = Buffer.alloc(0);

  // NOTE: BIP324Cipher.initialize() zeroes its private key in place, and
  // withParams stores the passed Buffer BY REFERENCE. So we hand withParams a
  // COPY and keep the pristine initPriv for the mirror cipher.
  const initiator = V2Transport.withParams(
    MAINNET_MAGIC,
    true,
    Buffer.from(initPriv),
    Buffer.from(initEntropy),
    initGarbage
  );
  const responder = V2Transport.withParams(
    MAINNET_MAGIC,
    false,
    respPriv,
    respEntropy,
    respGarbage
  );

  return { initiator, responder, initPriv, initEntropy };
}

describe("G19: decoy version packets must not advance VERSION->APP", () => {
  test("a decoy sent first leaves the responder in VERSION; real version then decodes", () => {
    const { initiator, responder, initPriv, initEntropy } = makePairWithMirror();

    // Step 1: initiator -> responder (key + empty garbage).
    const initKey = initiator.consumeSendBuffer();
    responder.receiveBytes(initKey);
    // Responder derived its cipher and is now waiting for the initiator's
    // garbage terminator (GARB_GARBTERM).
    expect(responder.getRecvState()).toBe(RecvState.GARB_GARBTERM);

    // Step 2: responder -> initiator. Drive the initiator far enough to learn
    // the responder's pubkey so our MIRROR cipher can be initialized with the
    // exact same key the responder expects to receive from.
    const respReply = responder.consumeSendBuffer();
    initiator.receiveBytes(respReply);

    // Build a MIRROR of the initiator's send cipher.  withParams() built the
    // initiator's internal cipher via BIP324Cipher.withKey(priv, entropy,
    // magic); we reconstruct the identical cipher and initialize it as the
    // initiator against the responder's pubkey, giving byte-identical
    // send-side keystreams.  We use this to encrypt the version-phase stream
    // in a controlled order (decoys first).
    const mirror = BIP324Cipher.withKey(initPriv, initEntropy, MAINNET_MAGIC);
    // theirKey (the responder's ellswift pubkey) is set on the initiator
    // during processKey; pull it back out to initialize the mirror with the
    // exact same DH inputs the real initiator cipher used.
    const theirKey = (initiator as unknown as { theirKey: { data: Buffer } }).theirKey;
    expect(theirKey).not.toBeNull();
    mirror.initialize({ data: theirKey.data } as never, true);

    // The initiator's garbage was empty, so AAD on the first packet is empty
    // garbage on the responder side too (responder saw our empty garbage).
    const aad = Buffer.alloc(0);

    // Encrypt, IN CIPHER ORDER: two decoys (ignore=true) then the real
    // version packet (empty contents, ignore=false).  This mirrors a peer
    // that pads its handshake with leading decoy version packets.
    const decoy1 = mirror.encrypt(Buffer.alloc(0), aad, true);
    const decoy2 = mirror.encrypt(Buffer.alloc(0), Buffer.alloc(0), true);
    const realVersion = mirror.encrypt(Buffer.alloc(0), Buffer.alloc(0), false);

    // Step 3a: feed the responder ONLY the initiator's garbage terminator.
    // sendGarbageTerminator on the mirror == the terminator the responder
    // expects to receive (recvGarbageTerminator on the responder).
    const initTerminator = mirror.sendGarbageTerminator;
    let r = responder.receiveBytes(initTerminator);
    expect(r.error).toBeUndefined();
    // Now the responder is parsing version-phase packets.
    expect(responder.getRecvState()).toBe(RecvState.VERSION);

    // Step 3b: feed the first decoy.  Pre-fix: the responder would flip to
    // APP after this packet (BUG).  Post-fix: it stays in VERSION.
    r = responder.receiveBytes(decoy1);
    expect(r.error).toBeUndefined();
    expect(responder.getRecvState()).toBe(RecvState.VERSION);
    expect(responder.isVersionReceived()).toBe(false);
    // A decoy emits no application message.
    expect(responder.getReceivedMessages().length).toBe(0);

    // Second decoy: still in VERSION.
    r = responder.receiveBytes(decoy2);
    expect(r.error).toBeUndefined();
    expect(responder.getRecvState()).toBe(RecvState.VERSION);
    expect(responder.isVersionReceived()).toBe(false);

    // The real (non-decoy) version packet: NOW we advance to APP.
    r = responder.receiveBytes(realVersion);
    expect(r.error).toBeUndefined();
    expect(responder.isVersionReceived()).toBe(true);
    expect(responder.getRecvState()).toBe(RecvState.APP);

    // And a subsequent APP message decodes correctly through the now-aligned
    // packet cipher.  Pre-fix this would be off-by-one in the keystream
    // because the real version packet had been consumed as an APP message.
    const pingPayload = Buffer.from([0xaa, 0xbb, 0xcc]);
    const pingCt = mirror.encrypt(
      Buffer.concat([Buffer.from([18]), pingPayload]), // 18 == "ping" short id
      Buffer.alloc(0),
      false
    );
    r = responder.receiveBytes(pingCt);
    expect(r.error).toBeUndefined();
    const msgs = responder.getReceivedMessages();
    expect(msgs.length).toBe(1);
    expect(msgs[0].type).toBe("ping");
    expect(msgs[0].payload.equals(pingPayload)).toBe(true);
  });
});

describe("G16: GARB_GARBTERM abort threshold matches Core (== 4111)", () => {
  test("4095 garbage bytes with no terminator does not yet error; the byte taking the buffer to 4111 errors", () => {
    const { initiator, responder } = makePairWithMirror();

    // Drive the responder into GARB_GARBTERM.
    responder.receiveBytes(initiator.consumeSendBuffer());
    expect(responder.getRecvState()).toBe(RecvState.GARB_GARBTERM);

    // The responder is now scanning for ITS recvGarbageTerminator. Feed
    // garbage that deliberately never contains the terminator. We feed up to
    // MAX_GARBAGE_LEN (4095) bytes first; that is the maximum permitted
    // garbage, so it must NOT error yet (terminator could still arrive).
    const garbage4095 = randomBytes(MAX_GARBAGE_LEN);
    let r = responder.receiveBytes(garbage4095);
    expect(r.error).toBeUndefined();
    expect(responder.getRecvState()).toBe(RecvState.GARB_GARBTERM);

    // Now feed exactly enough additional non-terminator bytes to bring the
    // buffer to MAX_GARBAGE_LEN + GARBAGE_TERMINATOR_LEN (4111). Core aborts
    // AT this size with no terminator match. Pre-fix hotbuns only aborted
    // strictly above 4111 (at 4112), so this 4111th-boundary feed passed.
    const fill = randomBytes(GARBAGE_TERMINATOR_LEN); // brings 4095 -> 4111
    r = responder.receiveBytes(fill);
    expect(r.error).toBeDefined();
    expect(r.error).toContain("Garbage too long");
  });

  test("terminator at the MAX legal offset (4095 garbage) is accepted with 4095 AAD bytes", () => {
    const { initiator, responder } = makePairWithMirror();

    responder.receiveBytes(initiator.consumeSendBuffer());
    expect(responder.getRecvState()).toBe(RecvState.GARB_GARBTERM);

    const term = (responder as unknown as {
      cipher: { recvGarbageTerminator: Buffer };
    }).cipher.recvGarbageTerminator;
    // Exactly MAX_GARBAGE_LEN (4095) garbage bytes is the maximum Core permits
    // before the terminator (Core net.cpp:1185-1191 accepts a trailing-window
    // match at buffer size up to and including 4111).  The all-zero garbage
    // cannot collide with the (cryptographically non-zero) terminator.
    expect(term.equals(Buffer.alloc(GARBAGE_TERMINATOR_LEN, 0x00))).toBe(false);
    const garbage = Buffer.alloc(MAX_GARBAGE_LEN, 0x00);
    const r = responder.receiveBytes(Buffer.concat([garbage, term]));
    expect(r.error).toBeUndefined();
    expect(responder.getRecvState()).toBe(RecvState.VERSION);
    const recvAad = (responder as unknown as { recvAad: Buffer }).recvAad;
    expect(recvAad.length).toBe(MAX_GARBAGE_LEN);
  });

  test("terminator split across two receiveBytes chunks is found at the seam", () => {
    // Exercises the incremental trailing-16B scan across a delivery boundary:
    // the terminator straddles two chunks, with garbage before it.  Core feeds
    // bytes one at a time, so the seam is irrelevant; the port must match.
    const { initiator, responder } = makePairWithMirror();

    responder.receiveBytes(initiator.consumeSendBuffer());
    expect(responder.getRecvState()).toBe(RecvState.GARB_GARBTERM);

    const term = (responder as unknown as {
      cipher: { recvGarbageTerminator: Buffer };
    }).cipher.recvGarbageTerminator;
    const L = 50;
    const garbage = Buffer.alloc(L, 0x00);
    expect(term.equals(Buffer.alloc(GARBAGE_TERMINATOR_LEN, 0x00))).toBe(false);

    // First chunk: all garbage + first 7 terminator bytes. The trailing-16
    // window does NOT yet equal the terminator, so we stay in GARB_GARBTERM.
    const firstChunk = Buffer.concat([garbage, term.subarray(0, 7)]);
    let r = responder.receiveBytes(firstChunk);
    expect(r.error).toBeUndefined();
    expect(responder.getRecvState()).toBe(RecvState.GARB_GARBTERM);

    // Second chunk: the remaining 9 terminator bytes complete the window.
    r = responder.receiveBytes(term.subarray(7));
    expect(r.error).toBeUndefined();
    expect(responder.getRecvState()).toBe(RecvState.VERSION);
    const recvAad = (responder as unknown as { recvAad: Buffer }).recvAad;
    expect(recvAad.length).toBe(L);
    expect(recvAad.equals(garbage)).toBe(true);
  });

  test("garbage terminator at offset L stashes exactly L AAD bytes and advances to VERSION", () => {
    const { initiator, responder } = makePairWithMirror();

    responder.receiveBytes(initiator.consumeSendBuffer());
    expect(responder.getRecvState()).toBe(RecvState.GARB_GARBTERM);

    // The responder expects its recvGarbageTerminator. Build a stream of L
    // garbage bytes followed by that terminator. We must avoid the garbage
    // accidentally containing the terminator, so derive garbage from a value
    // that cannot equal the 16-byte terminator (all 0x00 is fine unless the
    // terminator itself is all-zero, which is cryptographically impossible).
    const term = (responder as unknown as {
      cipher: { recvGarbageTerminator: Buffer };
    }).cipher.recvGarbageTerminator;
    const L = 100;
    const garbage = Buffer.alloc(L, 0x00);
    // Sanity: ensure no 16-byte window of all-zero garbage matches the
    // terminator (true unless the terminator is all-zero).
    expect(term.equals(Buffer.alloc(GARBAGE_TERMINATOR_LEN, 0x00))).toBe(false);

    const r = responder.receiveBytes(Buffer.concat([garbage, term]));
    expect(r.error).toBeUndefined();
    expect(responder.getRecvState()).toBe(RecvState.VERSION);

    // The stashed AAD (recvGarbage / recvAad) must be exactly the L garbage
    // bytes preceding the terminator.
    const recvAad = (responder as unknown as { recvAad: Buffer }).recvAad;
    expect(recvAad.length).toBe(L);
    expect(recvAad.equals(garbage)).toBe(true);
  });
});

describe("G25: generateGarbage draws its length from a CSPRNG, not Math.random", () => {
  const realMathRandom = Math.random;
  afterEach(() => {
    Math.random = realMathRandom;
  });

  test("generateGarbage does not call Math.random for the length", () => {
    let called = false;
    Math.random = () => {
      called = true;
      return 0;
    };
    // Many draws — if the length used Math.random even once, `called` flips.
    for (let i = 0; i < 256; i++) {
      const g = generateGarbage();
      expect(g.length).toBeGreaterThanOrEqual(0);
      expect(g.length).toBeLessThanOrEqual(MAX_GARBAGE_LEN);
    }
    expect(called).toBe(false);
  });

  test("lengths span a wide range across many draws (not a degenerate constant)", () => {
    const lengths = new Set<number>();
    for (let i = 0; i < 200; i++) {
      lengths.add(generateGarbage().length);
    }
    // A real CSPRNG over [0,4095] will produce many distinct lengths; a
    // constant-zero stub (the Math.random=()=>0 failure mode) would yield {0}.
    expect(lengths.size).toBeGreaterThan(20);
  });
});
