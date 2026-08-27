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
  hostToBuffer,
} from "./messages.js";
import {
  V2Transport,
  V1_PREFIX_LEN,
  looksLikeV1Version,
} from "./v2_transport.js";
import type { ProxyManager, NetworkType } from "./proxy.js";

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
  /**
   * Optional multi-network proxy manager.  When supplied AND
   * {@link networkType} is "onion" or "i2p", outbound connects are
   * routed through `proxyManager.connect(host, port)` instead of
   * directly through `Bun.connect`.  Clearnet (ipv4/ipv6/cjdns) uses the
   * direct path unless the manager has a default clearnet proxy
   * configured — that decision is made inside ProxyManager.
   *
   * Wired in by the PeerManager from --proxy/--onion/--i2psam CLI flags.
   * Reference: bitcoin-core/src/init.cpp `-proxy`/`-onion`/`-i2psam`.
   */
  proxyManager?: ProxyManager;
  /**
   * Network type for the destination address.  Drives the dispatch in
   * {@link Peer.connect}:
   *   - "onion" / "i2p"  → route via {@link proxyManager}
   *   - "cjdns"          → direct (only reachable when --cjdnsreachable)
   *   - "ipv4" / "ipv6"  → direct (or via default proxy if configured)
   *
   * Defaults to "ipv4" when not supplied (preserves existing callers).
   */
  networkType?: NetworkType;
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
 * Connection type for this peer.
 * - "full_relay"   — outbound full-relay (tx + block announcements)
 * - "block_relay"  — outbound block-relay-only (no tx relay)
 * - "inbound"      — peer connected to us
 * - "manual"       — manually added via addnode / connect CLI
 */
export type PeerConnType = "full_relay" | "block_relay" | "inbound" | "manual";

/**
 * Optional constructor options that control ban/protection policy.
 */
export interface PeerOptions {
  /**
   * If true, the peer has the NoBan permission (e.g. whitelisted).
   * misbehaving() becomes a no-op for these peers.
   * Reference: Core NetPermissionFlags::NoBan.
   */
  noban?: boolean;
  /**
   * Connection type.  Manual connections and outbound (block_relay /
   * full_relay) are protected from outright ban; local-addr peers get
   * disconnect-only treatment.  Defaults to "inbound".
   */
  connType?: PeerConnType;
}

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
  /**
   * Running minimum observed pong round-trip in milliseconds (Core
   * CNode::m_min_ping_time). Stays null until the first pong lands, then
   * tracks the smallest latency ever seen. getpeerinfo surfaces it as the
   * optional `minping` field (rpc/net.cpp:256, emitted only when populated).
   */
  minPing: number | null;
  /**
   * Misbehavior score (kept for logging/diagnostics only — NOT used for
   * the discourage decision since Core PR #25974 removed score accumulation).
   * Any call to misbehaving() now immediately sets m_should_discourage = true.
   */
  misbehaviorScore: number;
  /** Tracks whether this peer should be discouraged/banned. */
  shouldDisconnect: boolean;
  /** Whether the VERSION + VERACK handshake is complete. */
  handshakeComplete: boolean;

  /**
   * Whether the TCP connection ever established (the socket `open` callback
   * fired). Distinguishes an unreachable host (connect refused/timed out, open
   * never fired) from a peer that connected but then dropped a BIP-324 v2
   * handshake. Only the latter is a v1-fallback candidate — mirrors Bitcoin
   * Core's `V2Transport::ShouldReconnectV1` (net.cpp:1555), which returns false
   * unless the session actually got far enough to have sent v1-header-worth of
   * bytes. See PeerManager.connectPeer.
   */
  tcpEstablished: boolean;

  /**
   * Whether this peer holds the NoBan permission (whitelisted).
   * When true, misbehaving() is a no-op.
   * Reference: Bitcoin Core NetPermissionFlags::NoBan.
   */
  noban: boolean;

  /**
   * Connection type — used to determine ban-protection policy.
   * Reference: Bitcoin Core CNode::m_conn_type.
   */
  connType: PeerConnType;

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
   * Whether this peer negotiated BIP-339 wtxid-relay.
   * Set when we receive a `wtxidrelay` message during the handshake
   * (before VERACK).  When true, tx inv announcements must use MSG_WTX (=5)
   * + wtxid; when false, use MSG_TX (=1) + txid.
   * Reference: Bitcoin Core net_processing.cpp m_wtxid_relay, protocol.h
   * MSG_WTX = 5.
   */
  wtxidRelay: boolean;

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
  /**
   * Bytes accepted by send() but not yet accepted by the kernel.
   * Bun's Socket.write() returns the byte count actually written and does
   * NOT buffer the remainder — ignoring a short write does not merely drop
   * a message, it desyncs the v1 framing / v2 AEAD stream for the rest of
   * the connection (meta #74). writeRaw() parks the tail here and
   * onDrain() (wired from the socket's drain callback) flushes it in
   * order.
   */
  private outbox: Buffer[] = [];
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

  /**
   * Outbound BIP-324 v2 cipher-handshake gate.  ONLY used on the
   * useV2=true initiator path.  connect(useV2=true) does not resolve the
   * instant the TCP socket opens — it awaits this promise, which settles
   * exactly once:
   *   - resolve: the v2 cipher handshake reached isHandshakeReady()
   *     (same instant the "[bip324] v2 outbound connected" log fires);
   *   - reject : the socket closed/errored before the handshake completed
   *     (a v1-only peer replies with a v1 VERSION then disconnects — Core
   *     logs "Wrong MessageStart"), the peer was detected as v1, the v2
   *     transport errored, or the handshake deadline elapsed.
   * The reject lets PeerManager.connectPeer run its markV1Only + fresh
   * v1 re-dial fallback (manager.ts), mirroring Bitcoin Core
   * V2Transport::ShouldReconnectV1 (net.cpp:1555) and clearbit
   * connectOutboundNegotiated (peer.zig:2888).  Left null on the v1
   * (useV2=false) path so that path is byte-for-byte unchanged.
   */
  private v2HandshakeResolve: (() => void) | null;
  private v2HandshakeReject: ((err: Error) => void) | null;
  /** One-shot guard so the v2 gate settles at most once. */
  private v2HandshakeSettled: boolean;

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

  constructor(config: PeerConfig, events: PeerEvents, onBan?: OnBanCallback, options?: PeerOptions) {
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
    this.minPing = null;
    this.sentVerack = false;
    this.receivedVerack = false;
    this.receivedVersion = false;
    this.misbehaviorScore = 0;
    this.shouldDisconnect = false;
    this.handshakeComplete = false;
    this.tcpEstablished = false;
    this.onBan = onBan ?? null;
    this.noban = options?.noban ?? false;
    this.connType = options?.connType ?? "inbound";
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
    this.wtxidRelay = false;
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
    this.v2HandshakeResolve = null;
    this.v2HandshakeReject = null;
    this.v2HandshakeSettled = false;
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

    // FIX-56 W117: dispatch on network type.  ProxyManager handles the
    // SOCKS5 / I2P SAM handshake and returns a connected Socket; we then
    // call socket.reload() to install our handlers on top of the already-
    // open transport.  Direct clearnet uses the historical Bun.connect
    // path with handlers wired up-front.
    const useProxy =
      this.config.proxyManager !== undefined &&
      (this.config.networkType === "onion" ||
        this.config.networkType === "i2p");

    if (useProxy) {
      await this.connectViaProxy(useV2);
      return;
    }

    await this.connectDirect(useV2);
  }

  /**
   * Direct Bun.connect path (historical default).  Used for IPv4, IPv6,
   * CJDNS, and clearnet-via-default-proxy (the default proxy is handled
   * by SOCKS5 transparently — but right now we only route .onion / .b32.i2p
   * through ProxyManager.connect; clearnet-with-default-proxy would
   * require a new dispatch branch above).
   */
  private async connectDirect(useV2: boolean): Promise<void> {
    // Arm the v2 cipher-handshake gate BEFORE we open the socket so the
    // socket close/error handlers (and processRecvBufferV2) can settle it.
    // Only the useV2=true path awaits this gate; the v1 path leaves the
    // resolver/rejecter null and its behaviour is unchanged.
    let v2HandshakePromise: Promise<void> | null = null;
    if (useV2) {
      this.v2HandshakeSettled = false;
      v2HandshakePromise = new Promise<void>((resolve, reject) => {
        this.v2HandshakeResolve = resolve;
        this.v2HandshakeReject = reject;
      });
      // Attach a sink handler the instant the gate exists so a rejection from
      // settleV2HandshakeFail() can never surface as an "Unhandled rejection
      // at: Promise {<rejected>} ... settleV2HandshakeFail" log line. The
      // socket close/error/connectError handlers (and the dial-timeout catch
      // below) can reject this promise BEFORE the `await v2HandshakePromise`
      // at the end of this method is ever reached — e.g. when connectError
      // fires while we're still awaiting the TCP connect race, the catch at
      // line ~565 re-throws and execution never reaches the await, leaving a
      // rejected-but-unobserved promise. A v2 handshake failure is a normal
      // dropped-peer outcome (v1-only peer / timeout), not an error; the
      // real control flow (v1 fallback) is driven by the awaited copy below
      // and by the caller's try/catch in PeerManager.connectPeer. The sink
      // only marks the rejection as observed — it does not swallow control
      // flow, since `await v2HandshakePromise` still rethrows.
      v2HandshakePromise.catch(() => {
        // intentionally empty: rejection is handled by the awaiter below /
        // the PeerManager v1-fallback catch; this just prevents the noisy
        // unhandled-rejection report on the dropped-peer path.
      });
    }

    const connectPromise = Bun.connect({
      hostname: this.host,
      port: this.port,
      socket: {
        data: (_socket, data) => this.onData(Buffer.from(data)),
        drain: () => this.onDrain(),
        open: (socket) => {
          // Store socket immediately - open callback fires before await returns
          this.socket = socket;
          // TCP is up: any failure from here on is a post-connect handshake
          // drop (a v1-fallback candidate), not an unreachable host.
          this.tcpEstablished = true;
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
          this.releaseNonce();
          // v2-only: a socket close before the cipher handshake completed
          // means the peer was v1-only and disconnected after our ellswift
          // garbage (Core logs "Wrong MessageStart").  Reject the gate so
          // the manager falls back to v1.  No-op on the v1 path.
          this.settleV2HandshakeFail("socket closed before v2 handshake");
          if (this.state !== "disconnected") {
            this.state = "disconnected";
            this.events.onDisconnect(this);
          }
        },
        error: (_socket, error) => {
          this.cleanupHandshakeTimer();
          this.releaseNonce();
          this.settleV2HandshakeFail(
            `socket error before v2 handshake: ${error instanceof Error ? error.message : String(error)}`
          );
          if (this.state !== "disconnected") {
            this.state = "disconnected";
            this.events.onDisconnect(this, error);
          }
        },
        connectError: (_socket, error) => {
          this.cleanupHandshakeTimer();
          this.releaseNonce();
          this.settleV2HandshakeFail(
            `connect error before v2 handshake: ${error instanceof Error ? error.message : String(error)}`
          );
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
      // Dial timed out / refused before any socket handler fired — release the
      // nonce here so a failed outbound dial doesn't leak one bigint.
      this.releaseNonce();
      this.state = "disconnected";
      // Settle the v2 gate as failed too so an awaiter on the useV2 path
      // does not hang (no-op on the v1 path).
      this.settleV2HandshakeFail(
        `tcp connect failed: ${error instanceof Error ? error.message : String(error)}`
      );
      throw error;
    }

    // v1 path: the connect promise already represents a usable peer at TCP
    // open (VERSION sent inline in the open handler) — return as before.
    // v2 path: do NOT resolve at TCP open.  The promise resolves only when
    // the BIP-324 cipher handshake reaches isHandshakeReady (settled in
    // processRecvBufferV2) and REJECTS on socket-close-before-handshake /
    // wrong-magic / v1-detected / transport-error / handshake timeout —
    // letting PeerManager fall back to v1.  Mirrors Core ShouldReconnectV1
    // (net.cpp:1555) and clearbit connectOutboundNegotiated (peer.zig:2888).
    if (useV2 && v2HandshakePromise) {
      await v2HandshakePromise;
    }
  }

  /**
   * Proxy path for .onion / .b32.i2p destinations.
   *
   * 1. Call `proxyManager.connect(host, port)` — this opens a TCP socket
   *    to the SOCKS5 proxy (or I2P SAM bridge), performs the SOCKS5
   *    handshake (or SAM HELLO + STREAM CONNECT), and returns the
   *    connected Socket once the proxy has wired the tunnel through.
   * 2. Reinstall our handlers on the returned Socket via
   *    `socket.reload({ socket: ... })` so subsequent data/close/error
   *    events are dispatched to {@link onData} / {@link disconnect}
   *    rather than the proxy's internal state machine.
   * 3. Emit the v1 VERSION (or queue the v2 cipher handshake) exactly as
   *    in {@link connectDirect}.
   *
   * Reference: Bitcoin Core net.cpp `CConnman::ConnectNode` connect-via-
   * proxy branch + Bun's `Socket.reload` (per-socket handler swap for
   * Bun.connect-created sockets).
   */
  private async connectViaProxy(useV2: boolean): Promise<void> {
    const proxy = this.config.proxyManager;
    if (!proxy) {
      throw new Error("connectViaProxy called without a proxy manager");
    }

    const connectPromise: Promise<Socket> = (async () => {
      const socket = await proxy.connect(this.host, this.port);
      // Reinstall our handlers.  This works for Bun.connect-derived
      // sockets per the Bun runtime docs.
      socket.reload({
        socket: {
          data: (_s, data) => this.onData(Buffer.from(data)),
          close: () => {
            this.cleanupHandshakeTimer();
            this.releaseNonce();
            if (this.state !== "disconnected") {
              this.state = "disconnected";
              this.events.onDisconnect(this);
            }
          },
          error: (_s, error) => {
            this.cleanupHandshakeTimer();
            this.releaseNonce();
            if (this.state !== "disconnected") {
              this.state = "disconnected";
              this.events.onDisconnect(this, error);
            }
          },
          // open / connectError do not fire on a reload — the socket is
          // already open by the time ProxyManager.connect resolves.
        },
      });
      return socket;
    })();

    const timeoutPromise = new Promise<never>((_, reject) => {
      setTimeout(
        () => reject(new Error("Proxy connection timeout")),
        CONNECT_TIMEOUT_MS
      );
    });

    let socket: Socket;
    try {
      socket = await Promise.race([connectPromise, timeoutPromise]);
    } catch (error) {
      // Proxy dial failed before any socket handler fired — release the nonce
      // so a failed proxied dial doesn't leak one bigint.
      this.releaseNonce();
      this.state = "disconnected";
      throw error;
    }

    this.socket = socket;
    this.state = "handshaking";
    this.events.onConnect(this);

    if (useV2) {
      // Drain the V2Transport's queued ellswift pubkey + garbage.
      this.flushV2SendBuffer();
      this.handshakeTimer = setTimeout(() => {
        if (!this.handshakeComplete && this.state !== "disconnected") {
          this.disconnect("v2 handshake timeout");
        }
      }, V2_HANDSHAKE_DEADLINE_MS);
    } else {
      this.sendVersionMessage();
      this.handshakeTimer = setTimeout(() => {
        if (!this.handshakeComplete && this.state !== "disconnected") {
          this.disconnect("handshake timeout");
        }
      }, HANDSHAKE_TIMEOUT_MS);
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
  send(msg: NetworkMessage): boolean {
    if (!this.socket || this.state === "disconnected") {
      // #74: this used to be a SILENT no-op while callers had already
      // committed in-flight state (pendingBlocks / syncingPeers) — the
      // blockbrew-wedge shape. Callers must check the return.
      console.warn(`peer ${this.host}: send(${msg.type}) dropped — socket ${this.socket ? "disconnected" : "absent"}`);
      return false;
    }
    if (this.transportMode === "v2" && this.v2Transport) {
      return this.sendV2(msg);
    }
    const data = serializeMessage(this.config.magic, msg);
    this.writeRaw(data);
    this.bytesSent += data.length;
    this.lastSend = Date.now();
    return true;
  }

  /**
   * Write bytes preserving stream order across backpressure: if the kernel
   * accepts fewer bytes than offered, the tail is parked in the outbox and
   * flushed by onDrain(). Never interleaves — anything queued goes first.
   */
  private writeRaw(data: Buffer): void {
    if (!this.socket) return;
    if (this.outbox.length > 0) {
      this.outbox.push(data);
      return;
    }
    const written = this.socket.write(data);
    if (written < data.length) {
      this.outbox.push(data.subarray(written));
      console.warn(`peer ${this.host}: backpressure — parked ${data.length - written} bytes for drain`);
    }
  }

  /** Socket drain callback: flush parked bytes in order. */
  onDrain(): void {
    while (this.outbox.length > 0 && this.socket) {
      const head = this.outbox[0];
      const written = this.socket.write(head);
      if (written < head.length) {
        this.outbox[0] = head.subarray(written);
        return; // still backpressured; next drain continues
      }
      this.outbox.shift();
    }
  }

  /**
   * Encrypt and send a message via the BIP-324 v2 transport.
   * Internal — callers use {@link send}.
   */
  private sendV2(msg: NetworkMessage): boolean {
    if (!this.socket || !this.v2Transport) return false;
    if (!this.v2Transport.isHandshakeReady()) {
      // The cipher handshake hasn't finished queueing our version
      // packet yet.  This shouldn't happen because we only flip
      // transportMode to "v2" after the handshake is ready, but
      // guard defensively.
      console.warn(`peer ${this.host}: sendV2(${msg.type}) dropped — handshake not ready`);
      return false;
    }
    const { command, payload } = extractCommandAndPayload(this.config.magic, msg);
    const encrypted = this.v2Transport.encryptMessage(command, payload, false);
    this.writeRaw(encrypted);
    this.bytesSent += encrypted.length;
    this.lastSend = Date.now();
    return true;
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
    this.writeRaw(out);
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
    this.releaseNonce();
    // If an outbound v2 handshake is still in flight, reject its gate so
    // connect(useV2=true) returns control to the manager for v1 fallback.
    // Covers the typed v2 teardown reasons set in processRecvBufferV2
    // (peer responded with v1 VERSION / v2 transport requested v1 fallback
    // / v2 transport error) and the v2 handshake-deadline timer.  No-op on
    // the v1 path and after the gate has already settled successfully.
    this.settleV2HandshakeFail(_reason ?? "disconnected during v2 handshake");
    this.state = "disconnected";
    if (this.socket) {
      this.socket.end();
      this.socket = null;
    }
    this.events.onDisconnect(this);
  }

  /**
   * Release this peer's self-connection nonce from the static
   * {@link localNonces} set. Idempotent (Set.delete is a no-op for an absent
   * key), so it is safe to call from every disconnect/teardown path. The
   * socket `close`/`error`/`connectError` handlers and the connect-failure
   * catch blocks do NOT route through {@link disconnect} — they set
   * `state="disconnected"` and emit `onDisconnect` directly — so each of those
   * paths must call this to avoid leaking one `bigint` per dropped/failed peer.
   * Mirrors the nonce cleanup Bitcoin Core does in `FinalizeNode`.
   */
  private releaseNonce(): void {
    Peer.localNonces.delete(this.ourNonce);
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
   * Resolve the outbound v2 cipher-handshake gate (success).  One-shot.
   * Called from {@link processRecvBufferV2} the instant the cipher
   * handshake reaches isHandshakeReady().  No-op on the v1 path (the
   * resolver is null there) and after the gate has already settled.
   */
  private settleV2HandshakeOk(): void {
    if (this.v2HandshakeSettled) return;
    this.v2HandshakeSettled = true;
    const resolve = this.v2HandshakeResolve;
    this.v2HandshakeResolve = null;
    this.v2HandshakeReject = null;
    if (resolve) resolve();
  }

  /**
   * Reject the outbound v2 cipher-handshake gate (failure).  One-shot.
   * Called from every path that tears the peer down before the v2 cipher
   * handshake completed: the socket close/error handlers (a v1-only peer
   * disconnects after our ellswift garbage — Core "Wrong MessageStart"),
   * the v2 handshake-deadline timer, and {@link disconnect} for the typed
   * v1-fallback / transport-error reasons.  Rejecting unblocks
   * connect(useV2=true) so PeerManager runs markV1Only + a fresh v1
   * re-dial.  No-op on the v1 path (rejecter is null) and after settle.
   */
  private settleV2HandshakeFail(reason: string): void {
    if (this.v2HandshakeSettled) return;
    this.v2HandshakeSettled = true;
    const reject = this.v2HandshakeReject;
    this.v2HandshakeResolve = null;
    this.v2HandshakeReject = null;
    if (reject) reject(new Error(reason));
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
   * Number of live self-connection nonces currently tracked (for testing /
   * the structure-size metric in the leak instrumentation plan). Each connected
   * or in-flight Peer registers exactly one nonce in its constructor and must
   * release it on every disconnect path.
   */
  static localNoncesSize(): number {
    return Peer.localNonces.size;
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
    // Default ON: env unset -> v2 enabled. Only an explicit opt-out
    // (0 / false / off, any case) disables it. Mirrors haskoin 6963b93 and
    // camlcoin bb4894f, which flipped their BIP-324 v2 default ON once the
    // initiator + responder paths were interop-proven against a real Core v2
    // peer across a rekey boundary (test-suite/v2interop). The forced-on env
    // (HOTBUNS_BIP324_V2=1) still works and is now a no-op vs the default.
    if (v === undefined) return true;
    const lc = v.toLowerCase();
    if (lc === "0" || lc === "false" || lc === "off") return false;
    return true;
  }

  /**
   * Returns true if this peer's address is a local/loopback address.
   *
   * Reference: Bitcoin Core CAddress::IsLocal() / IsLoopback().
   */
  isLocalAddr(): boolean {
    const h = this.host;
    return (
      h === "127.0.0.1" ||
      h === "localhost" ||
      h === "::1" ||
      h.startsWith("127.")
    );
  }

  /**
   * Mark a peer as misbehaving. Per Bitcoin Core PR #25974 (2022), ANY call
   * to Misbehaving() immediately sets m_should_discourage = true — there is
   * no score accumulation. The peer is discouraged and disconnected on the
   * next MaybeDiscourageAndDisconnect() pass (here: immediately, synchronously).
   *
   * Canonical Core pattern (net_processing.cpp Misbehaving + MaybeDiscourageAndDisconnect):
   *   1. Misbehaving() → m_should_discourage = true  (no howmuch, no threshold)
   *   2. MaybeDiscourageAndDisconnect():
   *      a. noban permission → no-op (log warning only)
   *      b. manual connection → no-op (log warning only)
   *      c. local address → disconnect-only (no ban entry)
   *      d. regular peer → Discourage (ban) + disconnect
   *
   * The `howmuch` parameter is accepted for API compatibility with existing
   * call sites but is IGNORED for the discourage decision; it is only used
   * for diagnostic logging.
   *
   * Reference: bitcoin-core/src/net_processing.cpp:1893 Misbehaving()
   *            bitcoin-core/src/net_processing.cpp:5083 MaybeDiscourageAndDisconnect()
   *            Bitcoin Core PR #25974 "net processing: Remove misbehavior score"
   *
   * @param howmuch - Ignored for ban decision; kept for logging only.
   * @param message - Description of the violation.
   */
  misbehaving(howmuch: number, message: string): void {
    const messagePrefixed = message ? `: ${message}` : "";

    // G2: noban permission — log warning, take no action.
    if (this.noban) {
      console.log(
        `Misbehaving (noban — no action): peer=${this.host}:${this.port}${messagePrefixed}`
      );
      return;
    }

    // G2: manual connections are never discouraged (operator explicitly added them).
    if (this.connType === "manual") {
      console.log(
        `Misbehaving (manual — no action): peer=${this.host}:${this.port}${messagePrefixed}`
      );
      return;
    }

    // G1: single-event discourage — any misbehavior immediately triggers disconnect.
    // m_should_discourage = true (Core model); we set shouldDisconnect synchronously.
    this.misbehaviorScore += howmuch; // diagnostic only
    console.log(
      `Misbehaving: peer=${this.host}:${this.port}${messagePrefixed}`
    );

    this.shouldDisconnect = true;

    if (this.isLocalAddr()) {
      // Local peers: disconnect-only, no ban entry (Core: "disconnecting but not discouraging local peer").
      console.log(
        `Misbehaving (local — disconnect only): peer=${this.host}:${this.port}`
      );
      this.disconnect(`misbehaving (local): ${message}`);
    } else {
      // Regular inbound / outbound relay peers: discourage (ban) + disconnect.
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
          // hostToBuffer (not ipv4ToBuffer) so an IPv6 peer host encodes to its
          // 16-byte address instead of throwing "Invalid IPv4 address: <ipv6>",
          // which previously bubbled up as a processRecvBuffer failure + peer
          // drop on the inbound-v1 / v2-version paths.
          ip: hostToBuffer(this.host),
          port: this.port,
        },
        addrFrom: {
          services: this.config.services,
          ip: hostToBuffer("0.0.0.0"),
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
      // Positive v2-success log so the cross-impl BIP-324 interop matrix
      // harness can classify hotbuns pairs as v2 instead of "unknown"
      // (Phase D parity fix).  Fires once per Peer because !versionSent
      // is the same one-shot guard as the sendVersionMessage call below.
      // Direction is determined by the V2Transport role (initiator =
      // outbound, responder = inbound).
      const dir = this.v2Transport.isInitiator() ? "outbound" : "inbound";
      console.log(
        `[bip324] v2 ${dir} connected (encrypted) peer=${this.host}:${this.port}`
      );
      // Outbound: the cipher handshake is complete and our version packet
      // is queued — resolve connect(useV2=true).  No-op for responder
      // (inbound) peers, where the gate was never armed.
      this.settleV2HandshakeOk();
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
          // Track the running minimum round-trip (Core m_min_ping_time):
          // getpeerinfo's `minping` reports this rather than the last sample.
          if (this.minPing === null || this.latency < this.minPing) {
            this.minPing = this.latency;
          }
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

      case "wtxidrelay":
        // BIP-339: Peer wants to receive tx inv entries as MSG_WTX (=5) + wtxid.
        // This message must arrive between VERSION and VERACK (Core enforces
        // this in net_processing.cpp ProcessMessage "wtxidrelay" handler).
        if (this.handshakeComplete) {
          this.misbehaving(10, "wtxidrelay received after verack");
          return;
        }
        this.wtxidRelay = true;
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
