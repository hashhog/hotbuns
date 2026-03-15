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
  ipv4ToBuffer,
} from "./messages.js";

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

  private socket: Socket | null;
  private recvBuffer: Buffer;
  private config: PeerConfig;
  private events: PeerEvents;
  private pingNonce: bigint | null;
  private lastPingTime: number;
  private sentVerack: boolean;
  private receivedVerack: boolean;
  private onBan: OnBanCallback | null;

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
    this.misbehaviorScore = 0;
    this.shouldDisconnect = false;
    this.onBan = onBan ?? null;
  }

  /**
   * Initiate TCP connection using Bun.connect.
   * On successful connection, immediately sends version message.
   */
  async connect(): Promise<void> {
    this.state = "connecting";

    this.socket = await Bun.connect({
      hostname: this.host,
      port: this.port,
      socket: {
        data: (_socket, data) => this.onData(Buffer.from(data)),
        open: (socket) => {
          // Store socket immediately - open callback fires before await returns
          this.socket = socket;
          this.state = "handshaking";
          this.events.onConnect(this);
          this.sendVersionMessage();
        },
        close: (_socket) => {
          if (this.state !== "disconnected") {
            this.state = "disconnected";
            this.events.onDisconnect(this);
          }
        },
        error: (_socket, error) => {
          if (this.state !== "disconnected") {
            this.state = "disconnected";
            this.events.onDisconnect(this, error);
          }
        },
        connectError: (_socket, error) => {
          this.state = "disconnected";
          this.events.onDisconnect(this, error);
        },
      },
    });
  }

  /**
   * Send a NetworkMessage to this peer.
   * Serializes the message with the network magic and writes to socket.
   */
  send(msg: NetworkMessage): void {
    if (!this.socket || this.state === "disconnected") {
      return;
    }
    const data = serializeMessage(this.config.magic, msg);
    this.socket.write(data);
  }

  /**
   * Gracefully disconnect from this peer.
   * @param _reason - Optional reason for disconnection (for logging)
   */
  disconnect(_reason?: string): void {
    if (this.state === "disconnected") {
      return;
    }
    this.state = "disconnected";
    if (this.socket) {
      this.socket.end();
      this.socket = null;
    }
    this.events.onDisconnect(this);
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
    this.send({ type: "ping", payload: { nonce: this.pingNonce } });
  }

  /**
   * Send the initial version message to start the handshake.
   */
  private sendVersionMessage(): void {
    const now = BigInt(Math.floor(Date.now() / 1000));
    const nonce = BigInt(Math.floor(Math.random() * Number.MAX_SAFE_INTEGER));

    // Create version message
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
        nonce,
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
    // Accumulate incoming data
    this.recvBuffer = Buffer.concat([this.recvBuffer, data]);

    // Process any complete messages
    try {
      this.processRecvBuffer();
    } catch (error) {
      // Malformed message - disconnect
      this.disconnect(
        error instanceof Error ? error.message : "malformed message"
      );
    }
  }

  /**
   * Parse complete messages from recvBuffer.
   * Implements message framing: accumulate until we have header + payload,
   * verify checksum, deserialize, and dispatch.
   */
  private processRecvBuffer(): void {
    // Process messages in a loop - one data event may contain multiple messages
    while (this.recvBuffer.length >= MESSAGE_HEADER_SIZE) {
      // Try to parse header
      const header = parseHeader(this.recvBuffer);
      if (!header) {
        // Shouldn't happen since we checked length, but be safe
        break;
      }

      // Validate magic
      if (header.magic !== this.config.magic) {
        throw new Error(
          `Invalid magic: expected ${this.config.magic.toString(16)}, got ${header.magic.toString(16)}`
        );
      }

      // Check if we have the complete payload
      const totalLength = MESSAGE_HEADER_SIZE + header.length;
      if (this.recvBuffer.length < totalLength) {
        // Wait for more data
        break;
      }

      // Extract payload
      const payload = this.recvBuffer.subarray(
        MESSAGE_HEADER_SIZE,
        totalLength
      );

      // Verify checksum before deserialization
      const expectedChecksum = hash256(payload).subarray(0, 4);
      if (!header.checksum.equals(expectedChecksum)) {
        throw new Error(
          `Checksum mismatch: expected ${expectedChecksum.toString("hex")}, got ${header.checksum.toString("hex")}`
        );
      }

      // Deserialize the message
      const msg = deserializeMessage(header, payload);

      // Remove consumed bytes from buffer
      this.recvBuffer = this.recvBuffer.subarray(totalLength);

      // Handle the message
      this.handleMessage(msg);
    }
  }

  /**
   * Route a received message to appropriate handler.
   */
  private handleMessage(msg: NetworkMessage): void {
    if (this.state === "handshaking") {
      this.handleHandshake(msg);
    } else if (this.state === "connected") {
      // Handle pong for latency measurement
      if (msg.type === "pong" && this.pingNonce !== null) {
        if (msg.payload.nonce === this.pingNonce) {
          this.latency = Date.now() - this.lastPingTime;
          this.pingNonce = null;
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
   */
  private handleHandshake(msg: NetworkMessage): void {
    switch (msg.type) {
      case "version":
        // Store their version payload
        this.versionPayload = msg.payload;
        // Send verack in response
        this.send({ type: "verack", payload: null });
        this.sentVerack = true;
        this.checkHandshakeComplete();
        break;

      case "verack":
        // They acknowledged our version
        this.receivedVerack = true;
        this.checkHandshakeComplete();
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
      this.state = "connected";
      this.events.onHandshakeComplete(this);

      // Send optional feature negotiation messages
      this.send({ type: "sendheaders", payload: null });
      this.send({ type: "sendaddrv2", payload: null });
      this.send({ type: "wtxidrelay", payload: null });
    }
  }
}
