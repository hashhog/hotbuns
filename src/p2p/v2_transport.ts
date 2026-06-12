/**
 * BIP324 v2 encrypted P2P transport.
 *
 * Implements the encrypted and authenticated transport protocol that replaces
 * the plaintext v1 protocol. Features:
 * - ElligatorSwift key exchange (indistinguishable from random)
 * - ChaCha20-Poly1305 authenticated encryption
 * - Forward secrecy through regular rekeying
 * - 1-byte short message IDs for common messages
 * - Garbage data for censorship resistance
 *
 * Reference: BIP324, Bitcoin Core src/net.cpp V2Transport
 */
import {
  BIP324Cipher,
  generateGarbage,
  LENGTH_LEN,
  EXPANSION,
  MAX_GARBAGE_LEN,
  GARBAGE_TERMINATOR_LEN,
} from "./bip324/cipher.js";
import { EllSwiftPubKey, ELLSWIFT_PUBLIC_KEY_SIZE } from "./bip324/elligator_swift.js";
import { encodeMessageType, decodeMessageType } from "./bip324/message_ids.js";

/** Maximum v2 protocol message payload size (matches Core MAX_PROTOCOL_MESSAGE_LENGTH) */
export const MAX_V2_MESSAGE_SIZE = 4 * 1000 * 1000;

/** Version byte for v2 transport (used for future upgrades) */
export const V2_VERSION = 0;

/** Length of the v1 VERSION-message prefix (4 magic + 12-byte command). */
export const V1_PREFIX_LEN = 16;

/** v1 VERSION command: 12 bytes "version\0\0\0\0\0". */
export const V1_VERSION_COMMAND: Buffer = Buffer.from([
  0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0, 0, 0, 0, 0,
]);

/**
 * V2 transport receive states.
 */
export enum RecvState {
  /** Responder: waiting for the first bytes to detect v1 vs v2 */
  KEY_MAYBE_V1 = "KEY_MAYBE_V1",
  /** Initiator: waiting for the peer's 64-byte ellswift pubkey */
  KEY = "KEY",
  /** Reading garbage until terminator is found */
  GARB_GARBTERM = "GARB_GARBTERM",
  /** Receiving the peer's first encrypted (version) packet */
  VERSION = "VERSION",
  /** Receiving subsequent application packets */
  APP = "APP",
  /** Fell back to v1 transport */
  V1 = "V1",
}

/**
 * V2 transport send states.
 */
export enum SendState {
  /** Responder: waiting to receive peer's key before we can send our key */
  MAYBE_V1 = "MAYBE_V1",
  /** Initiator: pubkey + garbage already queued; waiting for cipher init */
  AWAITING_KEY = "AWAITING_KEY",
  /** Cipher initialized; garbage terminator + version packet queued; ready for app */
  READY = "READY",
  /** Fell back to v1 transport */
  V1 = "V1",
}

/**
 * Result of receiving bytes.
 */
export interface RecvResult {
  /** Whether more data can be processed */
  continue: boolean;
  /** Whether the transport should fall back to v1 */
  fallbackV1: boolean;
  /** Error message if processing failed */
  error?: string;
}

/**
 * A received v2 message.
 */
export interface V2Message {
  /** Message type (e.g., "version", "ping") */
  type: string;
  /** Message payload */
  payload: Buffer;
  /** Whether the IGNORE bit was set */
  ignore: boolean;
}

/**
 * Classify the first 16 bytes of an inbound TCP stream.
 *
 * Returns true iff the bytes look like the leading bytes of a v1 VERSION
 * message (network magic followed by the 12-byte "version" command).
 *
 * Caller is responsible for ensuring `bytes.length >= V1_PREFIX_LEN` and for
 * passing the network magic in little-endian form (matching the wire layout).
 *
 * Reference: clearbit src/v2_transport.zig looksLikeV1Version (bip324
 * disambiguation between v1 and v2 inbound).
 */
export function looksLikeV1Version(bytes: Buffer, networkMagicLE: Buffer): boolean {
  if (bytes.length < V1_PREFIX_LEN) return false;
  if (!bytes.subarray(0, 4).equals(networkMagicLE)) return false;
  return bytes.subarray(4, 16).equals(V1_VERSION_COMMAND);
}

/**
 * V2 Transport state machine.
 *
 * Handles the BIP324 encrypted transport protocol, including:
 * - Key exchange handshake
 * - Garbage handling for censorship resistance
 * - Encrypted packet framing
 * - Automatic v1 fallback detection
 *
 * The send-side state machine queues outbound bytes into an internal buffer.
 * Callers drain via {@link consumeSendBuffer} after each {@link receiveBytes}
 * (and also right after construction for the initiator).  This mirrors the
 * "send_buffer" pattern in clearbit src/v2_transport.zig and ouroboros's
 * V2Transport, where cipher-handshake bytes are emitted by the state machine
 * itself rather than synthesized at the call site.
 */
export class V2Transport {
  private cipher: BIP324Cipher;
  private recvState: RecvState;
  private sendState: SendState;
  private initiator: boolean;
  private networkMagic: Buffer;

  // Receive buffers
  private recvBuffer: Buffer = Buffer.alloc(0);
  private recvGarbage: Buffer = Buffer.alloc(0);
  /** End offset of the trailing-16B garbage windows already compared against
   *  the terminator (Core scans one byte at a time, so each window is checked
   *  exactly once as it completes; this is the cursor that makes our batched
   *  receive equivalent to Core's per-byte GARB_GARBTERM loop). */
  private garbageScanned: number = 0;
  private currentPacketLen: number = -1;
  private theirKey: EllSwiftPubKey | null = null;
  private receivedMessages: V2Message[] = [];
  /** AAD for the next inbound packet to authenticate (recv_garbage on the
   *  first inbound application packet, empty thereafter). */
  private recvAad: Buffer = Buffer.alloc(0);
  /** Whether we have observed (and successfully decrypted) the peer's
   *  first encrypted packet (the "version" packet).  Toggle is the
   *  responder/initiator equivalent of clearbit's isVersionReceived. */
  private versionReceived: boolean = false;

  // Send buffers
  /** Bytes pending socket write (handshake + garbage + terminator + app messages). */
  private sendBuffer: Buffer = Buffer.alloc(0);
  /** Random garbage we send after our pubkey (BIP-324 censorship resistance). */
  private sendGarbage: Buffer;
  /** Whether we have queued our outbound version-packet (empty contents,
   *  AAD = our_garbage). */
  private versionPacketSent: boolean = false;

  // V1 fallback
  private v1Fallback: boolean = false;

  /**
   * Create a new V2 transport.
   *
   * For initiators, the pubkey + garbage are queued into the send buffer
   * immediately (drain via {@link consumeSendBuffer}).  Responders wait
   * until they receive the initiator's pubkey before queueing their reply.
   *
   * @param networkMagic - 4-byte network magic (LE)
   * @param initiator - Whether we are initiating the connection
   * @param skipV1Check - For responders: skip the embedded 4-byte magic
   *   check.  Set this to true if the caller has already classified the
   *   wire as v2 (e.g. by examining the first 16 bytes against the v1
   *   `<magic> || "version\0\0\0\0\0"` prefix).  Without this flag, a
   *   uniformly-random ElligatorSwift pubkey whose first 4 bytes happen
   *   to collide with the network magic (probability 2^-32) would
   *   incorrectly trigger v1 fallback.
   */
  constructor(networkMagic: Buffer, initiator: boolean, skipV1Check: boolean = false) {
    this.networkMagic = networkMagic;
    this.initiator = initiator;
    this.cipher = new BIP324Cipher(networkMagic);
    this.sendGarbage = generateGarbage();

    if (initiator) {
      this.recvState = RecvState.KEY;
      this.sendState = SendState.AWAITING_KEY;
      this.queueOurKeyAndGarbage();
    } else {
      this.recvState = skipV1Check ? RecvState.KEY : RecvState.KEY_MAYBE_V1;
      this.sendState = SendState.MAYBE_V1;
    }
  }

  /**
   * Create a V2 transport with specified key and garbage (for testing).
   */
  static withParams(
    networkMagic: Buffer,
    initiator: boolean,
    privateKey: Buffer,
    entropy: Buffer,
    garbage: Buffer
  ): V2Transport {
    const transport = Object.create(V2Transport.prototype) as V2Transport;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const t = transport as any;
    t.networkMagic = networkMagic;
    t.initiator = initiator;
    t.cipher = BIP324Cipher.withKey(privateKey, entropy, networkMagic);
    t.sendGarbage = garbage;
    t.recvBuffer = Buffer.alloc(0);
    t.recvGarbage = Buffer.alloc(0);
    t.garbageScanned = 0;
    t.currentPacketLen = -1;
    t.theirKey = null;
    t.receivedMessages = [];
    t.recvAad = Buffer.alloc(0);
    t.versionReceived = false;
    t.sendBuffer = Buffer.alloc(0);
    t.versionPacketSent = false;
    t.v1Fallback = false;

    if (initiator) {
      t.recvState = RecvState.KEY;
      t.sendState = SendState.AWAITING_KEY;
      transport.queueOurKeyAndGarbage();
    } else {
      t.recvState = RecvState.KEY_MAYBE_V1;
      t.sendState = SendState.MAYBE_V1;
    }

    return transport;
  }

  /**
   * Backwards-compat helper: returns our pubkey + garbage as a freshly
   * concatenated buffer.  Prefer {@link consumeSendBuffer}, which drains
   * everything the state machine has queued (including the responder's
   * key + garbage + terminator + version packet on the responder side).
   */
  getHandshakeBytes(): Buffer {
    // For the initiator, we already queued key + garbage in the constructor.
    // We pull from the send buffer up to that fixed prefix length so that
    // legacy callers see the same "key + garbage" output as before.
    if (this.initiator) {
      const fixedLen = ELLSWIFT_PUBLIC_KEY_SIZE + this.sendGarbage.length;
      const out = this.sendBuffer.subarray(0, Math.min(fixedLen, this.sendBuffer.length));
      this.sendBuffer = Buffer.from(this.sendBuffer.subarray(out.length));
      return Buffer.from(out);
    }
    // Responder: caller probably only has the key + garbage queued (no
    // terminator yet, since we haven't received their key).  Drain whatever
    // is currently buffered.
    return this.consumeSendBuffer();
  }

  /**
   * Drain all bytes that the state machine has queued for transmission.
   * Returns an empty buffer if nothing is pending.
   */
  consumeSendBuffer(): Buffer {
    const out = this.sendBuffer;
    this.sendBuffer = Buffer.alloc(0);
    return out;
  }

  /** Bytes currently pending in the send buffer (without consuming). */
  pendingSendBytes(): number {
    return this.sendBuffer.length;
  }

  /**
   * Queue our 64-byte ElligatorSwift pubkey + send_garbage onto the send
   * buffer.  Called from the constructor for initiators, and after we
   * observe the peer's key for responders.
   */
  private queueOurKeyAndGarbage(): void {
    const ourKey = this.cipher.getOurPubKey().data;
    this.sendBuffer = Buffer.concat([this.sendBuffer, ourKey, this.sendGarbage]);
  }

  /**
   * Queue our garbage terminator + initial (empty) version packet.  AAD on
   * the version packet is our send_garbage so the peer can authenticate the
   * entire pre-cipher prefix.  Idempotent — guarded by versionPacketSent.
   *
   * Reference: Bitcoin Core net.cpp:1163 ProcessReceivedKeyBytes.
   */
  private queueTerminatorAndVersionPacket(): void {
    if (this.versionPacketSent) return;
    if (!this.cipher.isInitialized()) {
      throw new Error("Cipher must be initialized before queueing version packet");
    }
    const terminator = this.cipher.sendGarbageTerminator;
    // Empty contents, AAD = send_garbage, ignore=false.
    const versionCt = this.cipher.encrypt(Buffer.alloc(0), this.sendGarbage, false);
    this.sendBuffer = Buffer.concat([this.sendBuffer, terminator, versionCt]);
    this.versionPacketSent = true;
  }

  /**
   * Process received bytes.
   *
   * @param data - Incoming data from socket
   * @returns Result indicating whether to continue processing
   */
  receiveBytes(data: Buffer): RecvResult {
    if (data.length > 0) {
      this.recvBuffer = Buffer.concat([this.recvBuffer, data]);
    }

    // Drive the state machine until it stalls (waiting for more bytes).
    while (true) {
      const result = this.processReceiveState();
      if (!result.continue) {
        return result;
      }
    }
  }

  /**
   * Process the current receive state.
   */
  private processReceiveState(): RecvResult {
    switch (this.recvState) {
      case RecvState.KEY_MAYBE_V1:
        return this.processKeyMaybeV1();
      case RecvState.KEY:
        return this.processKey();
      case RecvState.GARB_GARBTERM:
        return this.processGarbage();
      case RecvState.VERSION:
        return this.processVersionPacket();
      case RecvState.APP:
        return this.processAppPacket();
      case RecvState.V1:
        return { continue: false, fallbackV1: true };
      default:
        return { continue: false, fallbackV1: false, error: "Invalid state" };
    }
  }

  /**
   * Responder-only: wait for the full 16-byte v1 prefix (4-byte magic +
   * 12-byte "version\0\0\0\0\0" command field) before deciding v1 vs v2.
   *
   * Core (net.cpp V1_PREFIX_LEN=16) requires ALL 16 bytes to match before
   * falling back to v1.  Using only 4 bytes (magic) produces a false-positive
   * v1 fallback for any v2 ElligatorSwift pubkey whose first 4 bytes collide
   * with the network magic (probability 2^-32).  The fix matches Core exactly.
   */
  private processKeyMaybeV1(): RecvResult {
    // Need at least 1 byte to check for early mismatch.
    if (this.recvBuffer.length === 0) {
      return { continue: false, fallbackV1: false };
    }
    // Build the expected 16-byte prefix: networkMagic + V1_VERSION_COMMAND.
    const v1Prefix = Buffer.concat([this.networkMagic, V1_VERSION_COMMAND]);
    const received = this.recvBuffer.length;
    // Check byte-by-byte as far as we have received; any mismatch → v2.
    for (let i = 0; i < Math.min(received, V1_PREFIX_LEN); i++) {
      if (this.recvBuffer[i] !== v1Prefix[i]) {
        // Mismatch before 16 bytes — this is a v2 connection.
        this.recvState = RecvState.KEY;
        return { continue: true, fallbackV1: false };
      }
    }
    if (received < V1_PREFIX_LEN) {
      // All bytes received so far match, but we haven't seen all 16 yet.
      return { continue: false, fallbackV1: false };
    }
    // Full 16-byte match — this is a v1 connection.
    this.recvState = RecvState.V1;
    this.sendState = SendState.V1;
    this.v1Fallback = true;
    return { continue: false, fallbackV1: true };
  }

  /**
   * Process key reception (KEY state).
   */
  private processKey(): RecvResult {
    if (this.recvBuffer.length < ELLSWIFT_PUBLIC_KEY_SIZE) {
      return { continue: false, fallbackV1: false };
    }

    // Extract their pubkey.
    this.theirKey = new EllSwiftPubKey(
      this.recvBuffer.subarray(0, ELLSWIFT_PUBLIC_KEY_SIZE)
    );
    this.recvBuffer = Buffer.from(
      this.recvBuffer.subarray(ELLSWIFT_PUBLIC_KEY_SIZE)
    );

    // Initialize the cipher (computes ECDH, derives keys).
    this.cipher.initialize(this.theirKey, this.initiator);

    // Responder: queue our key + garbage now (we couldn't earlier — we
    // didn't know if the peer was v1 yet).
    if (!this.initiator) {
      this.queueOurKeyAndGarbage();
    }

    // Both sides now queue the garbage terminator + version packet.
    this.queueTerminatorAndVersionPacket();
    this.sendState = SendState.READY;
    this.recvState = RecvState.GARB_GARBTERM;
    this.recvGarbage = Buffer.alloc(0);
    this.garbageScanned = 0;

    return { continue: true, fallbackV1: false };
  }

  /**
   * Process garbage reception (GARB_GARBTERM state).
   *
   * Faithful port of Bitcoin Core V2Transport::ProcessReceivedGarbageBytes
   * (net.cpp:1180-1205).  Core feeds garbage ONE byte at a time
   * (GetMaxBytesToProcess returns 1 in GARB_GARBTERM, net.cpp:1296-1298) and,
   * after each byte, compares the TRAILING GARBAGE_TERMINATOR_LEN bytes of the
   * accumulated buffer against the receive garbage terminator.  The terminator
   * is therefore recognized at the earliest buffer length where it completes
   * as a *suffix* — i.e. the leftmost window in scan order — and the bytes
   * before it are the peer's garbage (stashed as AAD).
   *
   * We receive in batches rather than byte-by-byte, so `garbageScanned` records
   * the end offset of the trailing windows already compared; on each call we
   * only test the newly-completed windows (ending at offsets
   * garbageScanned+1 .. recvBuffer.length).  This makes the batched path
   * byte-for-byte equivalent to Core's per-byte loop, with no forward-scan that
   * could skip a terminator beyond MAX_GARBAGE_LEN or pick a non-Core offset.
   */
  private processGarbage(): RecvResult {
    const terminator = this.cipher.recvGarbageTerminator;
    const MAX = MAX_GARBAGE_LEN + GARBAGE_TERMINATOR_LEN; // 4111

    // Advance the per-byte equivalent scan over any windows completed since the
    // last call.  `end` is the (exclusive) end of the trailing window — i.e.
    // Core's m_recv_buffer.size() after appending that byte.
    for (
      let end = Math.max(this.garbageScanned, GARBAGE_TERMINATOR_LEN);
      end <= this.recvBuffer.length;
      end++
    ) {
      // Core only checks once buffer.size() >= GARBAGE_TERMINATOR_LEN
      // (net.cpp:1185); the trailing window is [end-16, end).
      if (
        this.recvBuffer
          .subarray(end - GARBAGE_TERMINATOR_LEN, end)
          .equals(terminator)
      ) {
        // Garbage terminator received.  Bytes before it are the garbage,
        // stashed as AAD for the first inbound (version) packet — Core moves
        // m_recv_buffer into m_recv_aad and trims the terminator
        // (net.cpp:1187-1191).
        const garbEnd = end - GARBAGE_TERMINATOR_LEN;
        this.recvGarbage =
          garbEnd > 0
            ? Buffer.from(this.recvBuffer.subarray(0, garbEnd))
            : Buffer.alloc(0);
        this.recvAad = this.recvGarbage;
        this.recvBuffer = Buffer.from(this.recvBuffer.subarray(end));
        this.garbageScanned = 0;
        this.recvState = RecvState.VERSION;
        this.currentPacketLen = -1;
        return { continue: true, fallbackV1: false };
      }
      // Core aborts when the buffer reaches MAX_GARBAGE_LEN +
      // GARBAGE_TERMINATOR_LEN (4111) and the trailing terminator still does
      // not match (net.cpp:1192-1196): too much garbage, terminator absent.
      if (end === MAX) {
        return { continue: false, fallbackV1: false, error: "Garbage too long" };
      }
    }

    // Remember how far we have scanned so we never re-compare a window, and
    // wait for more bytes (Core's "need to receive more" branch,
    // net.cpp:1197-1203).
    this.garbageScanned = this.recvBuffer.length;
    return { continue: false, fallbackV1: false };
  }

  /**
   * Process the peer's first encrypted (version) packet.
   *
   * AAD on this packet is recv_garbage; subsequent application packets
   * carry no AAD.  Decoy packets (IGNORE bit set) are dropped silently.
   */
  private processVersionPacket(): RecvResult {
    return this.processEncryptedPacket(true);
  }

  /**
   * Process subsequent application packets.
   */
  private processAppPacket(): RecvResult {
    return this.processEncryptedPacket(false);
  }

  /**
   * Decrypt one inbound packet.
   *
   * The FSChaCha20 length cipher advances exactly once per packet, so we
   * MUST decrypt the length only once even if we hit this branch repeatedly
   * while waiting for the rest of the ciphertext.  This is the "W56 v2
   * transport bug" clearbit guards against; we use `currentPacketLen ===
   * -1` as the "length not yet decrypted" sentinel.
   */
  private processEncryptedPacket(isVersion: boolean): RecvResult {
    if (this.currentPacketLen < 0) {
      if (this.recvBuffer.length < LENGTH_LEN) {
        return { continue: false, fallbackV1: false };
      }
      const encryptedLen = this.recvBuffer.subarray(0, LENGTH_LEN);
      this.currentPacketLen = this.cipher.decryptLength(encryptedLen);
      this.recvBuffer = Buffer.from(this.recvBuffer.subarray(LENGTH_LEN));
      if (this.currentPacketLen > MAX_V2_MESSAGE_SIZE) {
        return {
          continue: false,
          fallbackV1: false,
          error: `Packet too large: ${this.currentPacketLen}`,
        };
      }
    }

    const expectedLen = this.currentPacketLen + 1 + 16; // HEADER_LEN + POLY1305_TAG_LEN
    if (this.recvBuffer.length < expectedLen) {
      return { continue: false, fallbackV1: false };
    }

    const encryptedPayload = this.recvBuffer.subarray(0, expectedLen);
    this.recvBuffer = Buffer.from(this.recvBuffer.subarray(expectedLen));

    // AAD for the very first inbound packet is recv_garbage; thereafter it's
    // empty.  Either way, recvAad is consumed (cleared) after a successful
    // decrypt regardless of whether the packet was a decoy.
    const aad = this.recvAad;
    const result = this.cipher.decrypt(encryptedPayload, aad);
    if (result === null) {
      return {
        continue: false,
        fallbackV1: false,
        error: "Decryption failed",
      };
    }
    if (this.recvAad.length > 0) {
      this.recvAad = Buffer.alloc(0);
    }
    this.currentPacketLen = -1;

    // Decoy packets are discarded; no message emitted.
    if (!result.ignore && result.contents.length > 0) {
      const { msgType, remaining } = decodeMessageType(result.contents);
      if (msgType !== null) {
        this.receivedMessages.push({
          type: msgType,
          payload: remaining,
          ignore: result.ignore,
        });
      }
    }

    if (isVersion && !result.ignore) {
      // Only a NON-decoy (ignore-bit clear) packet is the version packet that
      // completes the handshake-version phase and transitions us to APP.  A
      // decoy (ignore=true) received in the VERSION state must be skipped
      // WITHOUT advancing — we loop over any number of leading decoys until
      // the first real version packet arrives.  Matches Bitcoin Core
      // net.cpp:1249-1264 ProcessReceivedPacketBytes (state only advances on
      // !ignore).  Advancing on a decoy desyncs the receiver: the real
      // version packet would then be mis-parsed as an APP message.
      this.versionReceived = true;
      this.recvState = RecvState.APP;
    }

    return { continue: true, fallbackV1: false };
  }

  /**
   * Get received messages and clear the queue.
   */
  getReceivedMessages(): V2Message[] {
    const messages = this.receivedMessages;
    this.receivedMessages = [];
    return messages;
  }

  /**
   * Check if there are pending received messages.
   */
  hasReceivedMessages(): boolean {
    return this.receivedMessages.length > 0;
  }

  /**
   * Encrypt and queue an application-layer message for sending.
   *
   * Application packets carry no AAD (only our version packet uses
   * sent-garbage AAD, and that one is queued automatically by the state
   * machine after cipher init).
   *
   * @param msgType - Message type (e.g., "version", "ping")
   * @param payload - Message payload
   * @param ignore - Whether to set the IGNORE bit
   * @returns Encrypted packet bytes (caller may also drain via consumeSendBuffer
   *          if they want to batch with already-queued handshake bytes).
   */
  encryptMessage(msgType: string, payload: Buffer, ignore: boolean = false): Buffer {
    if (!this.cipher.isInitialized()) {
      throw new Error("Cipher not initialized");
    }
    if (!this.versionPacketSent) {
      // Defensive — should not happen since the state machine queues the
      // version packet immediately after cipher init.
      throw new Error("Version packet not yet queued; call receiveBytes first");
    }
    const typeBytes = encodeMessageType(msgType);
    const contents = Buffer.concat([typeBytes, payload]);
    return this.cipher.encrypt(contents, Buffer.alloc(0), ignore);
  }

  /**
   * Get the garbage terminator to send after receiving their key.
   *
   * @deprecated The state machine queues this internally; prefer
   * {@link consumeSendBuffer}.  Retained for the legacy test pattern.
   */
  getGarbageTerminator(): Buffer {
    if (!this.cipher.isInitialized()) {
      throw new Error("Cipher not initialized");
    }
    return this.cipher.sendGarbageTerminator;
  }

  /**
   * Check if the cipher is ready for message encryption/decryption.
   */
  isReady(): boolean {
    return this.cipher.isInitialized();
  }

  /**
   * True iff we have observed (and decrypted) the peer's first encrypted
   * packet.  Combined with `versionPacketSent`, this means the v2 handshake
   * is fully complete and the peer can send / receive application messages.
   */
  isVersionReceived(): boolean {
    return this.versionReceived;
  }

  /**
   * True iff the cipher is initialized AND our outbound version packet has
   * been queued.  Application sendMessage() calls require this.
   */
  isHandshakeReady(): boolean {
    return this.sendState === SendState.READY && this.versionPacketSent;
  }

  /**
   * True iff this transport was constructed in initiator (outbound) mode.
   * Used by Peer to label v2-success log lines with the connection
   * direction; the cross-impl BIP-324 interop matrix harness treats the
   * "outbound|inbound" tag as the v2-success signal.
   */
  isInitiator(): boolean {
    return this.initiator;
  }

  /**
   * Check if we should fall back to v1 transport.
   */
  shouldFallbackV1(): boolean {
    return this.v1Fallback;
  }

  /**
   * Get the session ID (only after handshake completion).
   */
  getSessionId(): Buffer {
    return this.cipher.sessionId;
  }

  /**
   * Get the current receive state.
   */
  getRecvState(): RecvState {
    return this.recvState;
  }

  /**
   * Get the current send state.
   */
  getSendState(): SendState {
    return this.sendState;
  }
}

// Re-export types and constants for convenience
export {
  BIP324Cipher,
  EllSwiftPubKey,
  MAX_GARBAGE_LEN,
  GARBAGE_TERMINATOR_LEN,
  ELLSWIFT_PUBLIC_KEY_SIZE,
  LENGTH_LEN,
  EXPANSION,
};
export { encodeMessageType, decodeMessageType, V2_MESSAGE_IDS } from "./bip324/message_ids.js";
