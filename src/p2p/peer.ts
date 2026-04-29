/**
 * Individual peer connection and message handling.
 *
 * Manages TCP connection to a single Bitcoin peer using Bun.connect,
 * handles the version handshake, message framing, and ping/pong latency.
 */

import type { Socket } from "bun";
import { hash256 } from "../crypto/primitives.js";
import {
  type NetworkMessage,
  type VersionPayload,
  type MessageHeader,
  MESSAGE_HEADER_SIZE,
  parseHeader,
  serializeMessage,
  deserializeMessage,
  deserializeV2Message,
  extractCommandAndPayload,
  ipv4ToBuffer,
} from "./messages.js";
import {
  V2Transport,
  V1_PREFIX_LEN,
  looksLikeV1Version,
} from "./v2_transport.js";

/** State of a peer connection. */
export type PeerState = "connecting" | "handshaking" | "connected" | "disconnected";

/** Configuration for connecting to a peer. */
export interface PeerConfig {
  host: string;
  port: number;
  magic: number;
  protocolVersion: number;
  services: bigint;
  userAgent: string;
  bestHeight: number;
  relay: boolean;
}

/** Event handlers for peer lifecycle events. */
export interface PeerEvents {
  onMessage: (peer: Peer, msg: NetworkMessage) => void;
  onConnect: (peer: Peer) => void;
  onDisconnect: (peer: Peer, error?: Error) => void;
  onHandshakeComplete: (peer: Peer) => void;
}

/** Callback for when a peer should be banned. */
export type OnBanCallback = (peer: Peer, reason: string) => void;

/**
 * Represents a connection to a single Bitcoin peer.
 *
 * Handles TCP connection, message framing over the stream,
 * version handshake, and ping/pong latency measurement.
 */
/** Minimum protocol version for witness support. */
export const MIN_PEER_PROTO_VERSION = 70015;

/** TCP connection timeout in milliseconds. */
export const CONNECT_TIMEOUT_MS = 10_000;

/** Handshake timeout in milliseconds. */
export const HANDSHAKE_TIMEOUT_MS = 60_000;

/** Ping interval in milliseconds (2 minutes). */
export const PING_INTERVAL_MS = 2 * 60 * 1000;

/** Ping timeout in milliseconds (20 minutes). */
export const PING_TIMEOUT_MS = 20 * 60 * 1000;

/** Headers response timeout in milliseconds (2 minutes). */
export const HEADERS_RESPONSE_TIMEOUT_MS = 2 * 60 * 1000;

/** Stale tip threshold in milliseconds (30 minutes). */
export const STALE_TIP_THRESHOLD_MS = 30 * 60 * 1000;

/** Stale check interval in milliseconds (45 seconds). */
export const STALE_CHECK_INTERVAL_MS = 45 * 1000;

/** Block download timeout base in milliseconds (10 minutes - one block interval). */
export const BLOCK_DOWNLOAD_TIMEOUT_BASE_MS = 10 * 60 * 1000;

/** Block download timeout per peer scaling (5 minutes). */
export const BLOCK_DOWNLOAD_TIMEOUT_PER_PEER_MS = 5 * 60 * 1000;

/** Maximum blocks in transit per peer. */
export const MAX_BLOCKS_IN_TRANSIT_PER_PEER = 16;

/** Minimum connect time before considering eviction (30 seconds). */
export const MINIMUM_CONNECT_TIME_MS = 30 * 1000;

/** Maximum outbound peers to protect from stale tip disconnect. */
export const MAX_OUTBOUND_PEERS_TO_PROTECT = 4;

/**
 * Maximum time to wait for the BIP-324 v2 cipher handshake to complete,
 * in milliseconds.  After this we abandon the socket as v1-only and
 * reconnect (sending v2 garbage is destructive on a v1 peer so the same
 * socket cannot be reused).
 *
 * Reference: clearbit Peer.V2_HANDSHAKE_DEADLINE_MS = 30_000.
 */
export const V2_HANDSHAKE_DEADLINE_MS = 30_000;

export class Peer {
  readonly host: string;
  readonly port: number;
  state: PeerState;
  versionPayload: VersionPayload | null;
  latency: number;
  /** Accumulated misbehavior score; peer is banned at 100. */
  misbehaviorScore: number;
  /** Tracks whether this peer should be discouraged/banned. */
  shouldDisconnect: boolean;
  /** Whether the VERSION + VERACK handshake is complete. */
  handshakeComplete: boolean;

  /** Timestamp of last block received from this peer (ms). */
  lastBlockTime: number;
  /** Timestamp of last transaction received from this peer (ms). */
  lastTxTime: number;
  /** Timestamp of when ping was sent (for timeout detection). */
  pingSentTime: number;
  /** Whether we're waiting for a pong response. */
  pingOutstanding: boolean;
  /** Timestamp of when headers request was sent (ms), 0 if none pending. */
  headersRequestTime: number;
  /** Timestamp of when this peer connected (ms). */
  connectedTime: number;
  /** Total bytes sent to this peer (for getpeerinfo.bytessent). */
  bytesSent: number;
  /** Total bytes received from this peer (for getpeerinfo.bytesrecv). */
  bytesRecv: number;
  /** Timestamp of last outbound send (ms, for getpeerinfo.lastsend). */
  lastSend: number;
  /** Timestamp of last inbound recv (ms, for getpeerinfo.lastrecv). */
  lastRecv: number;
  /** Local time (ms) when peer's VERSION message was processed. 0 until received. */
  versionReceivedAt: number;
  /** Set of blocks in flight (hashes as hex strings) with request times. */
  blocksInFlight: Map<string, number>;
  /** Best known height from this peer (from version message or updates). */
  bestKnownHeight: number;
  /**
   * Whether peer has signaled support for receiving ADDRv2 (BIP155) messages.
   * Set when we receive sendaddrv2 message during handshake.
   * When true, we should send addrv2 instead of addr to this peer.
   */
  wantsAddrV2: boolean;

  /**
   * The fee rate (sat/kvB) that this peer announced via feefilter (BIP133).
   * Transactions below this rate should not be relayed to this peer.
   * 0n means no feefilter has been received.
   */
  feeFilterReceived: bigint;

  /**
   * The last fee filter we sent to this peer (sat/kvB).
   * Used to avoid sending redundant feefilter messages.
   */
  feeFilterSent: bigint;

  /**
   * Timestamp for next feefilter send (ms since epoch).
   * Used for Poisson-delayed feefilter broadcasting.
   */
  nextFeeFilterSend: number;

  // BIP-330 Erlay transaction reconciliation state
  /**
   * Whether peer has signaled support for Erlay (BIP-330).
   * Set when we receive sendtxrcncl message during handshake.
   */
  supportsErlay: boolean;

  /**
   * Our local salt for Erlay short ID computation.
   * Generated when we send sendtxrcncl, used to compute combined salt.
   */
  erlayLocalSalt: bigint;

  /**
   * Peer's salt from their sendtxrcncl message.
   * 0n means we haven't received their salt yet.
   */
  erlayRemoteSalt: bigint;

  /**
   * Whether we've sent our sendtxrcncl message to this peer.
   */
  sentSendTxRcncl: boolean;

  /**
   * Whether we've received sendtxrcncl from this peer.
   */
  receivedSendTxRcncl: boolean;

  private socket: Socket | null;
  private recvBuffer: Buffer;
  private config: PeerConfig;
  private events: PeerEvents;
  private pingNonce: bigint | null;
  private lastPingTime: number;
  private sentVerack: boolean;
  private receivedVerack: boolean;
  private receivedVersion: boolean;
  private onBan: OnBanCallback | null;
  /** Our version nonce, used for self-connection detection. */
  private ourNonce: bigint;
  /** Timer for handshake timeout. */
  private handshakeTimer: ReturnType<typeof setTimeout> | null;
  /** Set of known local nonces (for self-connection detection). */
  private static localNonces: Set<bigint> = new Set();

  /**
   * Transport mode for this peer.
   *
   * - "unknown" — inbound only, before we've classified the wire as v1 or v2.
   *   The recv buffer accumulates bytes; we peek the first 16 bytes to
   *   decide.  Outbound peers default to "v1" since this implementation
   *   does not yet initiate v2 (see outbound audit in commit message).
   * - "v1" — plaintext Bitcoin Core protocol (the historical default).
   * - "v2" — BIP-324 encrypted transport.  All sends/receives go through
   *   {@link v2Transport}.
   */
  private transportMode: "unknown" | "v1" | "v2";

  /** V2 transport state machine, populated when transportMode === "v2". */
  private v2Transport: V2Transport | null;

  /** Network magic in 4-byte little-endian form (for v1/v2 classification). */
  private magicLE: Buffer;

  /**
   * Whether we have already emitted our application-layer VERSION.
   * v1 path: sendVersionMessage is called from connect() (outbound) or
   * after the magic-bytes classification (inbound).
   * v2 path: sendVersionMessage is deferred until the cipher handshake
   * has produced symmetric keys and queued our outbound version packet
   * (so the v1-formatted VERSION rides through the encrypted channel).
   */
  private versionSent: boolean;

  constructor(config: PeerConfig, events: PeerEvents, onBan?: OnBanCallback) {
    this.config = config;
    this.events = events;
    this.host = config.host;
    this.port = config.port;
    this.state = "connecting";
    this.versionPayload = null;
    this.socket = null;
    this.recvBuffer = Buffer.alloc(0);
    this.pingNonce = null;
    this.lastPingTime = 0;
    this.latency = 0;
    this.sentVerack = false;
    this.receivedVerack = false;
    this.receivedVersion = false;
    this.misbehaviorScore = 0;
    this.shouldDisconnect = false;
    this.handshakeComplete = false;
    this.onBan = onBan ?? null;
    this.ourNonce = BigInt(Math.floor(Math.random() * Number.MAX_SAFE_INTEGER));
    this.handshakeTimer = null;
    // Stale peer tracking fields
    this.lastBlockTime = 0;
    this.lastTxTime = 0;
    this.pingSentTime = 0;
    this.pingOutstanding = false;
    this.headersRequestTime = 0;
    this.connectedTime = Date.now();
    this.bytesSent = 0;
    this.bytesRecv = 0;
    this.lastSend = 0;
    this.lastRecv = 0;
    this.versionReceivedAt = 0;
    this.blocksInFlight = new Map();
    this.bestKnownHeight = 0;
    this.wantsAddrV2 = false;
    // BIP133 feefilter state
    this.feeFilterReceived = 0n;
    this.feeFilterSent = 0n;
    this.nextFeeFilterSend = 0;
    // BIP330 Erlay state
    this.supportsErlay = false;
    this.erlayLocalSalt = 0n;
    this.erlayRemoteSalt = 0n;
    this.sentSendTxRcncl = false;
    this.receivedSendTxRcncl = false;
    // BIP-324 transport state.  Defaults to v1 — the inbound listener
    // overrides to "unknown" via {@link acceptSocket} so we can classify
    // the wire after the first 16 bytes arrive.
    this.transportMode = "v1";
    this.v2Transport = null;
    this.magicLE = Buffer.alloc(4);
    this.magicLE.writeUInt32LE(config.magic, 0);
    this.versionSent = false;
    // Register our nonce for self-connection detection
    Peer.localNonces.add(this.ourNonce);
  }

  /**
   * Initiate TCP connection using Bun.connect.
   *
   * The `useV2` flag (default: false) chooses between v1 and BIP-324 v2:
   *
   *   - v1 path (`useV2=false`): on socket open, immediately send our
   *     plaintext v1 VERSION.  Historical default.
   *   - v2 path (`useV2=true`): on socket open, write our 64-byte
   *     ElligatorSwift pubkey + 0..32-byte garbage to the wire.  The
   *     V2Transport state machine (already constructed in
   *     {@link prepareV2Outbound}) processes inbound bytes; once we
   *     observe the responder's pubkey + garbage + terminator + version
   *     packet, the encrypted application VERSION is queued and the
   *     normal handshake continues over the encrypted transport.
   *
   * On v2 cipher-handshake failure (timeout, decryption error, peer
   * abruptly disconnects), the caller is expected to:
   *   1. close this peer's socket,
   *   2. mark the address as v1-only via PeerManager.markV1Only,
   *   3. construct a fresh Peer and call connect(useV2=false).
   *
   * Sending v2 garbage is destructive on a v1 peer, so the same socket
   * cannot be reused.  This mirrors clearbit's connectOutboundNegotiated
   * pattern (clearbit src/peer.zig:1863).
   *
   * Reference: clearbit src/peer.zig:807 performV2Handshake (initiator
   * loop) and clearbit src/peer.zig:1846 connectOutboundNegotiated
   * (manager-level negotiation).
   */
  async connect(useV2: boolean = false): Promise<void> {
    if (useV2) {
      this.prepareV2Outbound();
    }
    this.state = "connecting";

    const connectPromise = Bun.connect({
      hostname: this.host,
      port: this.port,
      socket: {
        data: (_socket, data) => this.onData(Buffer.from(data)),
        open: (socket) => {
          // Store socket immediately - open callback fires before await returns
          this.socket = socket;
          this.state = "handshaking";
          this.events.onConnect(this);

          if (useV2) {
            // Drain the V2Transport's queued ellswift pubkey + garbage to
            // the wire.  Once the peer replies with their pubkey we can
            // queue + send the garbage terminator + version packet and
            // proceed with the encrypted application VERSION exchange
            // (see processRecvBufferV2).
            this.flushV2SendBuffer();
            // Tighter deadline for the cipher handshake — the manager
            // needs to know quickly whether to fall back to v1.
            this.handshakeTimer = setTimeout(() => {
              if (!this.handshakeComplete && this.state !== "disconnected") {
                this.disconnect("v2 handshake timeout");
              }
            }, V2_HANDSHAKE_DEADLINE_MS);
          } else {
            // v1: send our VERSION immediately and arm the normal
            // handshake timeout.
            this.sendVersionMessage();
            this.handshakeTimer = setTimeout(() => {
              if (!this.handshakeComplete && this.state !== "disconnected") {
                this.disconnect("handshake timeout");
              }
            }, HANDSHAKE_TIMEOUT_MS);
          }
        },
        close: (_socket) => {
          this.cleanupHandshakeTimer();
          if (this.state !== "disconnected") {
            this.state = "disconnected";
            this.events.onDisconnect(this);
          }
        },
        error: (_socket, error) => {
          this.cleanupHandshakeTimer();
          if (this.state !== "disconnected") {
            this.state = "disconnected";
            this.events.onDisconnect(this, error);
          }
        },
        connectError: (_socket, error) => {
          this.cleanupHandshakeTimer();
          this.state = "disconnected";
          this.events.onDisconnect(this, error);
        },
      },
    });

    // Race against a connection timeout to avoid blocking on unreachable hosts
    const timeoutPromise = new Promise<never>((_, reject) => {
      setTimeout(() => reject(new Error("Connection timeout")), CONNECT_TIMEOUT_MS);
    });

    try {
      this.socket = await Promise.race([connectPromise, timeoutPromise]);
    } catch (error) {
      this.state = "disconnected";
      throw error;
    }
  }

  /**
   * Construct an initiator-mode V2Transport and stash it on this peer.
   *
   * Called from {@link connect} when v2 outbound is enabled.  The
   * transport's constructor queues the 64-byte ElligatorSwift pubkey +
   * 0..32-byte garbage into its send buffer; the actual flush to the
   * socket happens in the `open` callback.
   *
   * Also flips transportMode to "v2" so subsequent {@link send}
   * invocations route through the encrypted path (no-op until the
   * cipher handshake completes — sendV2 guards via isHandshakeReady).
   *
   * Idempotent: repeated calls are no-ops if already prepared.
   */
  private prepareV2Outbound(): void {
    if (this.transportMode === "v2" && this.v2Transport) return;
    this.transportMode = "v2";
    this.v2Transport = new V2Transport(
      this.magicLE,
      /* initiator */ true
    );
  }

  /**
   * Accept an already-connected inbound socket (from Bun.listen).
   *
   * Per BIP-324 inbound flow, we DEFER sending our application-layer
   * VERSION until we have classified the wire as v1 or v2:
   *
   *   - If the first 16 bytes match `<network_magic> || "version\0\0\0\0\0"`,
   *     the peer is speaking plaintext v1.  We then send our v1 VERSION
   *     and proceed normally.
   *   - Otherwise (and assuming the peer is well-behaved), the first
   *     bytes are the peer's 64-byte ElligatorSwift pubkey, kicking off
   *     a v2 BIP-324 handshake.  We construct a {@link V2Transport} in
   *     responder mode, drive the cipher handshake, and only then emit
   *     our application-layer VERSION through the encrypted channel.
   *
   * If we send our v1 VERSION too early, a v2-only peer will see four
   * bytes of network magic where it expects an ElligatorSwift pubkey —
   * the v1 magic-byte heuristic triggers v1 fallback at best, or the
   * peer drops us at worst.
   *
   * Reference: clearbit src/peer.zig:891-930 performHandshake (inbound
   * peek-and-classify), Bitcoin Core src/net.cpp V2Transport responder.
   */
  acceptSocket(sock: Socket<unknown>): void {
    this.socket = sock as Socket;
    this.state = "handshaking";
    this.connectedTime = Date.now();
    this.transportMode = "unknown"; // classified by processRecvBuffer
    this.events.onConnect(this);

    // Start handshake timeout — covers both v1 and v2 paths.
    this.handshakeTimer = setTimeout(() => {
      if (!this.handshakeComplete && this.state !== "disconnected") {
        this.disconnect("handshake timeout");
      }
    }, HANDSHAKE_TIMEOUT_MS);
  }

  /**
   * Feed raw data into this peer's receive buffer (used by inbound listener).
   */
  feedData(data: Buffer): void {
    this.onData(data);
  }

  /**
   * Send a NetworkMessage to this peer.
   *
   * Routes through the BIP-324 v2 transport when negotiated; otherwise
   * serializes the message in the plaintext v1 framing (4-byte magic +
   * 12-byte command + length + checksum + payload).
   */
  send(msg: NetworkMessage): void {
    if (!this.socket || this.state === "disconnected") {
      return;
    }
    if (this.transportMode === "v2" && this.v2Transport) {
      this.sendV2(msg);
      return;
    }
    const data = serializeMessage(this.config.magic, msg);
    this.socket.write(data);
    this.bytesSent += data.length;
    this.lastSend = Date.now();
  }

  /**
   * Encrypt and send a message via the BIP-324 v2 transport.
   * Internal — callers use {@link send}.
   */
  private sendV2(msg: NetworkMessage): void {
    if (!this.socket || !this.v2Transport) return;
    if (!this.v2Transport.isHandshakeReady()) {
      // The cipher handshake hasn't finished queueing our version
      // packet yet.  This shouldn't happen because we only flip
      // transportMode to "v2" after the handshake is ready, but
      // guard defensively.
      return;
    }
    const { command, payload } = extractCommandAndPayload(this.config.magic, msg);
    const encrypted = this.v2Transport.encryptMessage(command, payload, false);
    this.socket.write(encrypted);
    this.bytesSent += encrypted.length;
    this.lastSend = Date.now();
  }

  /**
   * Drain any bytes the V2Transport has queued (handshake bytes during
   * negotiation; nothing during steady-state app messaging since
   * {@link sendV2} writes directly).
   */
  private flushV2SendBuffer(): void {
    if (!this.socket || !this.v2Transport) return;
    if (this.v2Transport.pendingSendBytes() === 0) return;
    const out = this.v2Transport.consumeSendBuffer();
    if (out.length === 0) return;
    this.socket.write(out);
    this.bytesSent += out.length;
    this.lastSend = Date.now();
  }

  /**
   * Gracefully disconnect from this peer.
   * @param _reason - Optional reason for disconnection (for logging)
   */
  disconnect(_reason?: string): void {
    if (this.state === "disconnected") {
      return;
    }
    this.cleanupHandshakeTimer();
    // Clean up our nonce from local nonces
    Peer.localNonces.delete(this.ourNonce);
    this.state = "disconnected";
    if (this.socket) {
      this.socket.end();
      this.socket = null;
    }
    this.events.onDisconnect(this);
  }

  /**
   * Clean up the handshake timer if it exists.
   */
  private cleanupHandshakeTimer(): void {
    if (this.handshakeTimer !== null) {
      clearTimeout(this.handshakeTimer);
      this.handshakeTimer = null;
    }
  }

  /**
   * Check if a nonce belongs to one of our local connections (self-connection detection).
   * @param nonce - The nonce from a received version message
   * @returns true if this is a self-connection
   */
  static isLocalNonce(nonce: bigint): boolean {
    return Peer.localNonces.has(nonce);
  }

  /**
   * Clear all local nonces (for testing).
   */
  static clearLocalNonces(): void {
    Peer.localNonces.clear();
  }

  /**
   * Returns true iff outbound BIP-324 v2 negotiation is enabled.
   *
   * Gated behind the `HOTBUNS_BIP324_V2` env var.  Default OFF — outbound
   * v2 is brand-new wiring (this commit is the first time hotbuns even
   * attempts an initiator-side BIP-324 handshake) and we want to soak the
   * code path in the wild before flipping the default.  Set
   * `HOTBUNS_BIP324_V2=1` (or "true") to opt into outbound v2.  Inbound
   * v2 (the responder path) is independently enabled by virtue of
   * `acceptSocket` always classifying — no env-var gate.
   *
   * Reference: clearbit Peer.bip324V2Enabled (CLEARBIT_BIP324_V2 env var,
   * but defaulted ON post-W90 once they had verified live-handshakes
   * against Bitcoin Core 28.x).
   */
  static bip324V2Enabled(): boolean {
    const v = process.env.HOTBUNS_BIP324_V2;
    if (!v) return false;
    if (v === "0" || v === "false" || v === "FALSE") return false;
    return true;
  }

  /**
   * Mark a peer as misbehaving by adding to their score.
   * If the score reaches or exceeds 100, the peer is banned.
   *
   * Modeled after Bitcoin Core's Misbehaving() in net_processing.cpp.
   *
   * @param howmuch - Score to add (common values: 10, 20, 50, 100)
   * @param message - Description of the violation
   */
  misbehaving(howmuch: number, message: string): void {
    this.misbehaviorScore += howmuch;
    const messagePrefixed = message ? `: ${message}` : "";
    console.log(
      `Misbehaving: peer=${this.host}:${this.port} score=${this.misbehaviorScore}${messagePrefixed}`
    );

    if (this.misbehaviorScore >= 100) {
      this.shouldDisconnect = true;
      if (this.onBan) {
        this.onBan(this, message);
      }
      this.disconnect(`banned: ${message}`);
    }
  }

  /**
   * Send a ping message and start latency measurement.
   * The pong response will be used to calculate round-trip latency.
   */
  sendPing(): void {
    this.pingNonce = BigInt(Math.floor(Math.random() * Number.MAX_SAFE_INTEGER));
    this.lastPingTime = Date.now();
    this.pingSentTime = this.lastPingTime;
    this.pingOutstanding = true;
    this.send({ type: "ping", payload: { nonce: this.pingNonce } });
  }

  /**
   * Send the initial version message to start the handshake.
   *
   * Idempotent: re-entry is a no-op once we've sent VERSION.  Double-calls
   * happen on the v2 path (acceptSocket vs handshake-ready transition) and
   * during v1 fallback after a v2 handshake aborted partway through.
   */
  private sendVersionMessage(): void {
    if (this.versionSent) return;
    this.versionSent = true;
    const now = BigInt(Math.floor(Date.now() / 1000));

    // Create version message using our nonce for self-connection detection
    const versionMsg: NetworkMessage = {
      type: "version",
      payload: {
        version: this.config.protocolVersion,
        services: this.config.services,
        timestamp: now,
        addrRecv: {
          services: 0n, // We don't know their services yet
          ip: ipv4ToBuffer(this.host),
          port: this.port,
        },
        addrFrom: {
          services: this.config.services,
          ip: ipv4ToBuffer("0.0.0.0"),
          port: 0,
        },
        nonce: this.ourNonce,
        userAgent: this.config.userAgent,
        startHeight: this.config.bestHeight,
        relay: this.config.relay,
      },
    };

    this.send(versionMsg);
  }

  /**
   * Called when raw data arrives on the socket.
   * Accumulates data in recvBuffer and processes complete messages.
   */
  private onData(data: Buffer): void {
    this.bytesRecv += data.length;
    this.lastRecv = Date.now();
    // Accumulate incoming data - copy into new buffer to avoid
    // retaining references to large underlying ArrayBuffers
    if (this.recvBuffer.length === 0) {
      this.recvBuffer = Buffer.from(data);
    } else {
      const newBuf = Buffer.allocUnsafe(this.recvBuffer.length + data.length);
      newBuf.set(this.recvBuffer, 0);
      newBuf.set(data, this.recvBuffer.length);
      this.recvBuffer = newBuf;
    }

    // Process any complete messages
    try {
      this.processRecvBuffer();
    } catch (error) {
      // Malformed message - disconnect
      const errMsg = error instanceof Error ? error.message : "malformed message";
      console.error(`PEER ERROR: ${this.host}:${this.port} processRecvBuffer failed: ${errMsg} (recvBuf=${this.recvBuffer.length} bytes)`);
      this.disconnect(errMsg);
    }
  }

  /**
   * Parse complete messages from recvBuffer.
   *
   * Routing layers:
   *   1. If the transport mode is "unknown" (inbound peer; pre-classification),
   *      peek the first 16 bytes.  If they match `<magic> || "version\0\0\0\0\0"`,
   *      switch to v1.  Otherwise switch to v2 and construct a responder
   *      V2Transport.  Wait for more bytes if we don't have 16 yet.
   *   2. v1: accumulate until we have header + payload, verify checksum,
   *      deserialize, and dispatch.
   *   3. v2: feed bytes into the V2Transport state machine; drain any
   *      handshake bytes back out to the socket; on handshake completion,
   *      send our application-layer VERSION through the encrypted channel;
   *      dispatch decrypted messages.
   */
  private processRecvBuffer(): void {
    // 1. Classify the wire if we're an inbound peer waiting on first bytes.
    if (this.transportMode === "unknown") {
      if (this.recvBuffer.length < V1_PREFIX_LEN) {
        // Need more bytes before we can decide.
        return;
      }
      if (looksLikeV1Version(this.recvBuffer.subarray(0, V1_PREFIX_LEN), this.magicLE)) {
        this.transportMode = "v1";
        // Send our v1 VERSION now (was previously deferred at acceptSocket
        // time so we wouldn't corrupt a v2 wire).
        this.sendVersionMessage();
      } else {
        // Construct a V2Transport in responder mode; the state machine
        // will queue our pubkey + garbage + terminator + version packet
        // automatically as it consumes the peer's bytes.  We pass
        // skipV1Check=true because we already classified the 16-byte
        // prefix as not-v1; without it, a uniformly-random ellswift
        // pubkey colliding with the magic (prob 2^-32) would trigger
        // an incorrect fallback.
        this.transportMode = "v2";
        this.v2Transport = new V2Transport(
          this.magicLE,
          /* initiator */ false,
          /* skipV1Check */ true
        );
      }
    }

    if (this.transportMode === "v2") {
      this.processRecvBufferV2();
      return;
    }

    // 2. v1 path (unchanged from pre-W76 behaviour).
    while (this.recvBuffer.length >= MESSAGE_HEADER_SIZE) {
      const header = parseHeader(this.recvBuffer);
      if (!header) {
        break;
      }

      if (header.magic !== this.config.magic) {
        throw new Error(
          `Invalid magic: expected ${this.config.magic.toString(16)}, got ${header.magic.toString(16)}`
        );
      }

      const totalLength = MESSAGE_HEADER_SIZE + header.length;
      if (this.recvBuffer.length < totalLength) {
        break;
      }

      const payload = this.recvBuffer.subarray(MESSAGE_HEADER_SIZE, totalLength);

      const expectedChecksum = hash256(payload).subarray(0, 4);
      if (!header.checksum.equals(expectedChecksum)) {
        throw new Error(
          `Checksum mismatch: expected ${expectedChecksum.toString("hex")}, got ${header.checksum.toString("hex")}`
        );
      }

      let msg;
      try {
        msg = deserializeMessage(header, payload);
      } catch (deserErr) {
        if (header.command === "block") {
          console.error(`BLOCK DESER ERROR: size=${header.length} from=${this.host}: ${deserErr instanceof Error ? deserErr.message : String(deserErr)}`);
        }
        throw deserErr;
      }

      this.recvBuffer = Buffer.from(this.recvBuffer.subarray(totalLength));
      this.handleMessage(msg);
    }
  }

  /**
   * v2 receive-side dispatch.
   *
   * Drives the {@link V2Transport} state machine, drains any pending
   * outbound handshake bytes (responder pubkey, garbage terminator,
   * version packet), and on first reaching the application phase emits
   * our v1-style VERSION over the encrypted transport.  Subsequent
   * decrypted messages are dispatched through {@link handleMessage}.
   *
   * Initiator-side fast v1 detection: the V2Transport in initiator mode
   * unconditionally reads 64 bytes as the peer's ellswift pubkey.  If
   * the peer is in fact v1, those bytes are the start of a v1 VERSION
   * message (magic + "version\0\0\0\0\0" + ...) — the cipher init would
   * succeed against the random-looking bytes and we'd waste 30s waiting
   * for the rest of a packet that never arrives.  Short-circuit by
   * checking for the v1 prefix once we have 16 inbound bytes.
   */
  private processRecvBufferV2(): void {
    if (!this.v2Transport) return;

    // Initiator-side: detect a v1 peer by looking for magic + "version"
    // command in the first 16 bytes.  Disconnect with a typed reason so
    // the manager knows to mark the address v1-only and reconnect.
    if (
      !this.v2Transport.isReady() &&
      this.recvBuffer.length >= V1_PREFIX_LEN &&
      looksLikeV1Version(this.recvBuffer.subarray(0, V1_PREFIX_LEN), this.magicLE)
    ) {
      this.disconnect("v2 outbound: peer responded with v1 VERSION");
      return;
    }

    // One-shot: drive the state machine on whatever has accumulated.
    const inbound = this.recvBuffer;
    this.recvBuffer = Buffer.alloc(0);
    const result = this.v2Transport.receiveBytes(inbound);

    // Flush whatever the state machine queued (responder pubkey + garbage
    // + terminator + version packet for the responder side; garbage
    // terminator + version packet for the initiator side once cipher init
    // completed).
    this.flushV2SendBuffer();

    if (result.fallbackV1) {
      // Either (a) responder side hit the embedded v1-magic check (should
      // not occur because acceptSocket pre-classifies with
      // skipV1Check=true), or (b) initiator side observed v1 magic (also
      // caught above, but the V2Transport could in principle re-flag it).
      // Treat as a transport-level v1 fallback signal.
      this.disconnect("v2 transport requested v1 fallback");
      return;
    }
    if (result.error) {
      this.disconnect(`v2 transport error: ${result.error}`);
      return;
    }

    // After cipher init + version-packet queueing, send our application
    // VERSION exactly once.  sendVersionMessage flips versionSent
    // internally (idempotence guard).
    if (this.v2Transport.isHandshakeReady() && !this.versionSent) {
      this.sendVersionMessage();
    }

    // Drain any decrypted messages into the v1 dispatch path.
    if (this.v2Transport.hasReceivedMessages()) {
      const messages = this.v2Transport.getReceivedMessages();
      for (const v2msg of messages) {
        let parsed: NetworkMessage;
        try {
          parsed = deserializeV2Message(v2msg.type, v2msg.payload);
        } catch (err) {
          // Unrecognized command name, malformed payload, etc.  Match
          // Bitcoin Core: log and discard rather than disconnect, since
          // BIP-324 explicitly leaves room for unknown extensions.
          console.error(
            `V2 deser error from ${this.host}:${this.port} type=${v2msg.type}: ${err instanceof Error ? err.message : String(err)}`
          );
          continue;
        }
        this.handleMessage(parsed);
      }
    }
  }

  /**
   * Route a received message to appropriate handler.
   *
   * Following Bitcoin Core's net_processing.cpp ProcessMessage():
   * - Before version received: only accept "version"
   * - After version, before verack complete: accept "version", "verack", and feature negotiation
   * - After handshake complete: accept all messages
   */
  private handleMessage(msg: NetworkMessage): void {
    // Check for pre-handshake message violations
    if (!this.handshakeComplete) {
      // Before we've received their version, only accept version messages
      if (!this.receivedVersion && msg.type !== "version") {
        // Non-version message before version handshake
        this.misbehaving(10, `non-version message before version handshake: ${msg.type}`);
        return;
      }

      // After version but before verack, only accept certain messages
      if (this.receivedVersion && !this.handshakeComplete) {
        const allowedDuringHandshake = [
          "version", // Duplicate version check handled in handleHandshake
          "verack",
          "wtxidrelay",
          "sendaddrv2",
          "sendtxrcncl",
        ];
        if (!allowedDuringHandshake.includes(msg.type)) {
          this.misbehaving(10, `unsupported message prior to verack: ${msg.type}`);
          return;
        }
      }

      this.handleHandshake(msg);
    } else if (this.state === "connected") {
      // Handle pong for latency measurement
      if (msg.type === "pong" && this.pingNonce !== null) {
        if (msg.payload.nonce === this.pingNonce) {
          this.latency = Date.now() - this.lastPingTime;
          this.pingNonce = null;
          this.pingOutstanding = false;
          this.pingSentTime = 0;
        }
      }
      // Dispatch all messages to the event handler
      this.events.onMessage(this, msg);
    }
  }

  /**
   * Handle the version handshake state machine.
   *
   * Sequence:
   * 1. On connect (open), we send version
   * 2. Receive their version - store it, send verack
   * 3. Receive their verack - handshake complete
   *
   * We transition to 'connected' once we have both sent and received verack.
   *
   * Additional checks (per Bitcoin Core net_processing.cpp):
   * - Reject duplicate version messages (misbehavior 1)
   * - Detect self-connections via nonce
   * - Enforce minimum protocol version (70015 for witness)
   */
  private handleHandshake(msg: NetworkMessage): void {
    switch (msg.type) {
      case "version": {
        // Check for duplicate version message
        if (this.receivedVersion) {
          this.misbehaving(1, "duplicate version message");
          return;
        }

        const versionPayload = msg.payload;

        // Check minimum protocol version (70015 for witness support)
        if (versionPayload.version < MIN_PEER_PROTO_VERSION) {
          this.disconnect(`peer using obsolete version ${versionPayload.version}`);
          return;
        }

        // Self-connection detection: check if the nonce matches any of our local nonces
        if (Peer.isLocalNonce(versionPayload.nonce)) {
          this.disconnect("connected to self");
          return;
        }

        // Store their version payload
        this.versionPayload = versionPayload;
        this.versionReceivedAt = Date.now();
        this.receivedVersion = true;

        // Send feature negotiation messages BEFORE verack (required by protocol)
        this.send({ type: "wtxidrelay", payload: null });
        this.send({ type: "sendaddrv2", payload: null });

        // Send verack in response
        this.send({ type: "verack", payload: null });
        this.sentVerack = true;
        this.checkHandshakeComplete();
        break;
      }

      case "verack":
        // Ignore redundant verack after handshake complete
        if (this.handshakeComplete) {
          return;
        }

        // They acknowledged our version
        this.receivedVerack = true;
        this.checkHandshakeComplete();
        break;

      case "sendaddrv2":
        // BIP155: Peer wants to receive ADDRv2 messages instead of ADDR.
        // This message must arrive between VERSION and VERACK.
        // If we receive it after handshake, it's a protocol violation.
        if (this.handshakeComplete) {
          this.misbehaving(10, "sendaddrv2 received after verack");
          return;
        }
        this.wantsAddrV2 = true;
        break;

      case "sendtxrcncl":
        // BIP330: Peer supports Erlay transaction reconciliation.
        // This message must arrive between VERSION and VERACK.
        if (this.handshakeComplete) {
          this.misbehaving(10, "sendtxrcncl received after verack");
          return;
        }
        if (this.receivedSendTxRcncl) {
          this.misbehaving(1, "duplicate sendtxrcncl message");
          return;
        }
        this.receivedSendTxRcncl = true;
        this.erlayRemoteSalt = msg.payload.salt;
        this.supportsErlay = true;
        break;

      default:
        // Ignore other messages during handshake
        // (some implementations may send wtxidrelay etc. before verack)
        break;
    }
  }

  /**
   * Check if handshake is complete and transition to connected state.
   */
  private checkHandshakeComplete(): void {
    if (this.sentVerack && this.receivedVerack && this.versionPayload) {
      // Clear handshake timeout
      this.cleanupHandshakeTimer();

      this.handshakeComplete = true;
      this.state = "connected";
      // Store the peer's best height from version message
      this.bestKnownHeight = this.versionPayload.startHeight;
      this.events.onHandshakeComplete(this);

      // Send post-handshake feature negotiation messages
      this.send({ type: "sendheaders", payload: null });

      // BIP 152: Signal compact block relay support (version 2 = segwit)
      // enabled=false means low-bandwidth mode (we receive inv/headers first)
      this.send({
        type: "sendcmpct",
        payload: { enabled: false, version: 2n },
      });
    }
  }

  /**
   * Record that we received a block from this peer.
   */
  recordBlockReceived(): void {
    this.lastBlockTime = Date.now();
  }

  /**
   * Record that we received a transaction from this peer.
   */
  recordTxReceived(): void {
    this.lastTxTime = Date.now();
  }

  /**
   * Mark that we sent a getheaders request to this peer.
   */
  markHeadersRequested(): void {
    this.headersRequestTime = Date.now();
  }

  /**
   * Mark that we received headers response.
   */
  markHeadersReceived(): void {
    this.headersRequestTime = 0;
  }

  /**
   * Add a block to in-flight tracking.
   * @param blockHash - Block hash as hex string
   */
  addBlockInFlight(blockHash: string): void {
    if (this.blocksInFlight.size >= MAX_BLOCKS_IN_TRANSIT_PER_PEER) {
      return; // Already at maximum
    }
    this.blocksInFlight.set(blockHash, Date.now());
  }

  /**
   * Remove a block from in-flight tracking (received or cancelled).
   * @param blockHash - Block hash as hex string
   */
  removeBlockInFlight(blockHash: string): void {
    this.blocksInFlight.delete(blockHash);
  }

  /**
   * Get the number of blocks currently in flight.
   */
  getBlocksInFlightCount(): number {
    return this.blocksInFlight.size;
  }

  /**
   * Check if we have any blocks in flight.
   */
  hasBlocksInFlight(): boolean {
    return this.blocksInFlight.size > 0;
  }

  /**
   * Update the peer's best known height.
   * @param height - New best known height
   */
  updateBestKnownHeight(height: number): void {
    if (height > this.bestKnownHeight) {
      this.bestKnownHeight = height;
    }
  }

  /**
   * Check if ping has timed out.
   * @returns true if a ping is outstanding and has exceeded timeout
   */
  hasPingTimedOut(): boolean {
    if (!this.pingOutstanding || this.pingSentTime === 0) {
      return false;
    }
    return Date.now() - this.pingSentTime > PING_TIMEOUT_MS;
  }

  /**
   * Check if headers request has timed out.
   * @returns true if headers request is pending and has exceeded timeout
   */
  hasHeadersTimedOut(): boolean {
    if (this.headersRequestTime === 0) {
      return false;
    }
    return Date.now() - this.headersRequestTime > HEADERS_RESPONSE_TIMEOUT_MS;
  }

  /**
   * Get the oldest block in flight that has exceeded timeout.
   * @param peerCount - Number of connected peers (used for timeout scaling)
   * @returns Block hash of timed-out block, or null if none
   */
  getTimedOutBlock(peerCount: number): string | null {
    const now = Date.now();
    // Timeout scales: base + per_peer * peerCount
    const timeout = BLOCK_DOWNLOAD_TIMEOUT_BASE_MS + BLOCK_DOWNLOAD_TIMEOUT_PER_PEER_MS * peerCount;

    for (const [hash, requestTime] of this.blocksInFlight) {
      if (now - requestTime > timeout) {
        return hash;
      }
    }
    return null;
  }

  /**
   * Check if peer should be considered for ping (needs keepalive).
   * @param lastActivity - Timestamp of last activity from this peer
   * @returns true if it's been PING_INTERVAL_MS since last activity
   */
  needsPing(lastActivity: number): boolean {
    if (!this.handshakeComplete || this.pingOutstanding) {
      return false;
    }
    return Date.now() - lastActivity >= PING_INTERVAL_MS;
  }
}
