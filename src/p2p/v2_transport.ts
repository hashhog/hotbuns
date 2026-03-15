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

import { randomBytes } from "crypto";
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

/** Maximum v2 protocol message payload size */
export const MAX_V2_MESSAGE_SIZE = 32 * 1024 * 1024;

/** Version byte for v2 transport (used for future upgrades) */
export const V2_VERSION = 0;

/**
 * V2 transport receive states.
 */
export enum RecvState {
  /** Waiting for the first bytes to detect v1 vs v2 */
  KEY = "KEY",
  /** Reading garbage until terminator is found */
  GARB_GARBTERM = "GARB_GARBTERM",
  /** Reading encrypted packet length (3 bytes) */
  VERSION = "VERSION",
  /** Waiting for application data length */
  APP = "APP",
  /** Waiting for application data payload */
  APP_READY = "APP_READY",
  /** Fell back to v1 transport */
  V1 = "V1",
}

/**
 * V2 transport send states.
 */
export enum SendState {
  /** Waiting to send key and garbage */
  MAYBE_V1 = "MAYBE_V1",
  /** Ready to send version packet */
  AWAITING_KEY = "AWAITING_KEY",
  /** Ready to send application messages */
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
 * V2 Transport state machine.
 *
 * Handles the BIP324 encrypted transport protocol, including:
 * - Key exchange handshake
 * - Garbage handling for censorship resistance
 * - Encrypted packet framing
 * - Automatic v1 fallback detection
 */
export class V2Transport {
  private cipher: BIP324Cipher;
  private recvState: RecvState;
  private sendState: SendState;
  private readonly initiator: boolean;
  private readonly networkMagic: Buffer;

  // Receive buffers
  private recvBuffer: Buffer = Buffer.alloc(0);
  private garbageBuffer: Buffer = Buffer.alloc(0);
  private currentPacketLen: number = 0;
  private theirKey: EllSwiftPubKey | null = null;
  private decryptBuffer: Buffer = Buffer.alloc(0);
  private receivedMessages: V2Message[] = [];

  // Send buffers
  private sendBuffer: Buffer = Buffer.alloc(0);
  private garbage: Buffer;
  private versionPacketSent: boolean = false;

  // V1 fallback
  private v1Fallback: boolean = false;

  /**
   * Create a new V2 transport.
   *
   * @param networkMagic - 4-byte network magic
   * @param initiator - Whether we are initiating the connection
   */
  constructor(networkMagic: Buffer, initiator: boolean) {
    this.networkMagic = networkMagic;
    this.initiator = initiator;
    this.cipher = new BIP324Cipher(networkMagic);
    this.garbage = generateGarbage();

    // Initial states depend on role
    if (initiator) {
      this.recvState = RecvState.KEY;
      this.sendState = SendState.AWAITING_KEY;
    } else {
      this.recvState = RecvState.KEY;
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
    transport.networkMagic = networkMagic;
    transport.initiator = initiator;
    transport.cipher = BIP324Cipher.withKey(privateKey, entropy, networkMagic);
    transport.garbage = garbage;
    transport.recvBuffer = Buffer.alloc(0);
    transport.garbageBuffer = Buffer.alloc(0);
    transport.currentPacketLen = 0;
    transport.theirKey = null;
    transport.decryptBuffer = Buffer.alloc(0);
    transport.receivedMessages = [];
    transport.sendBuffer = Buffer.alloc(0);
    transport.versionPacketSent = false;
    transport.v1Fallback = false;

    if (initiator) {
      transport.recvState = RecvState.KEY;
      transport.sendState = SendState.AWAITING_KEY;
    } else {
      transport.recvState = RecvState.KEY;
      transport.sendState = SendState.MAYBE_V1;
    }

    return transport;
  }

  /**
   * Get the bytes to send for handshake initiation.
   *
   * Returns our ElligatorSwift public key + garbage + garbage terminator.
   * Should be called after the socket connects and before any other data.
   */
  getHandshakeBytes(): Buffer {
    if (this.sendState !== SendState.AWAITING_KEY && this.sendState !== SendState.MAYBE_V1) {
      return Buffer.alloc(0);
    }

    const ourKey = this.cipher.getOurPubKey().data;

    // We'll send key + garbage now, terminator after we initialize cipher
    // For now, just return the key + garbage
    this.sendState = SendState.AWAITING_KEY;

    return Buffer.concat([ourKey, this.garbage]);
  }

  /**
   * Process received bytes.
   *
   * @param data - Incoming data from socket
   * @returns Result indicating whether to continue processing
   */
  receiveBytes(data: Buffer): RecvResult {
    this.recvBuffer = Buffer.concat([this.recvBuffer, data]);

    while (this.recvBuffer.length > 0) {
      const result = this.processReceiveState();
      if (!result.continue) {
        return result;
      }
    }

    return { continue: true, fallbackV1: false };
  }

  /**
   * Process the current receive state.
   */
  private processReceiveState(): RecvResult {
    switch (this.recvState) {
      case RecvState.KEY:
        return this.processKey();
      case RecvState.GARB_GARBTERM:
        return this.processGarbage();
      case RecvState.VERSION:
        return this.processVersion();
      case RecvState.APP:
        return this.processAppLength();
      case RecvState.APP_READY:
        return this.processAppPayload();
      case RecvState.V1:
        return { continue: false, fallbackV1: true };
      default:
        return { continue: false, fallbackV1: false, error: "Invalid state" };
    }
  }

  /**
   * Process key reception (KEY state).
   */
  private processKey(): RecvResult {
    // Check for v1 magic (responder only, first 16 bytes)
    if (!this.initiator && this.recvBuffer.length >= 4) {
      // v1 messages start with network magic
      if (this.recvBuffer.subarray(0, 4).equals(this.networkMagic)) {
        this.recvState = RecvState.V1;
        this.v1Fallback = true;
        return { continue: false, fallbackV1: true };
      }
    }

    // Need 64 bytes for ElligatorSwift key
    if (this.recvBuffer.length < ELLSWIFT_PUBLIC_KEY_SIZE) {
      return { continue: false, fallbackV1: false };
    }

    // Extract their key
    this.theirKey = new EllSwiftPubKey(this.recvBuffer.subarray(0, ELLSWIFT_PUBLIC_KEY_SIZE));
    this.recvBuffer = this.recvBuffer.subarray(ELLSWIFT_PUBLIC_KEY_SIZE);

    // Initialize cipher
    this.cipher.initialize(this.theirKey, this.initiator);

    // Transition to garbage state
    this.recvState = RecvState.GARB_GARBTERM;
    this.garbageBuffer = Buffer.alloc(0);

    // Now we can send our garbage terminator
    if (this.initiator) {
      this.sendState = SendState.READY;
    }

    return { continue: true, fallbackV1: false };
  }

  /**
   * Process garbage reception (GARB_GARBTERM state).
   */
  private processGarbage(): RecvResult {
    const terminator = this.cipher.recvGarbageTerminator;

    // Scan for garbage terminator
    while (this.recvBuffer.length > 0) {
      // Add byte to garbage buffer
      this.garbageBuffer = Buffer.concat([
        this.garbageBuffer,
        this.recvBuffer.subarray(0, 1),
      ]);
      this.recvBuffer = this.recvBuffer.subarray(1);

      // Check if garbage buffer ends with terminator
      if (this.garbageBuffer.length >= GARBAGE_TERMINATOR_LEN) {
        const possibleTerm = this.garbageBuffer.subarray(
          this.garbageBuffer.length - GARBAGE_TERMINATOR_LEN
        );
        if (possibleTerm.equals(terminator)) {
          // Found terminator! Remove it from garbage buffer
          const actualGarbage = this.garbageBuffer.subarray(
            0,
            this.garbageBuffer.length - GARBAGE_TERMINATOR_LEN
          );
          this.garbageBuffer = actualGarbage;

          // Move to VERSION state (receive first encrypted packet)
          this.recvState = RecvState.VERSION;
          return { continue: true, fallbackV1: false };
        }
      }

      // Check for too much garbage
      if (this.garbageBuffer.length > MAX_GARBAGE_LEN + GARBAGE_TERMINATOR_LEN) {
        return {
          continue: false,
          fallbackV1: false,
          error: "Garbage too long",
        };
      }
    }

    return { continue: false, fallbackV1: false };
  }

  /**
   * Process version packet (first encrypted packet after handshake).
   */
  private processVersion(): RecvResult {
    // Need at least 3 bytes for length
    if (this.recvBuffer.length < LENGTH_LEN) {
      return { continue: false, fallbackV1: false };
    }

    // Decrypt length
    const encryptedLen = this.recvBuffer.subarray(0, LENGTH_LEN);
    this.currentPacketLen = this.cipher.decryptLength(encryptedLen);
    this.recvBuffer = this.recvBuffer.subarray(LENGTH_LEN);

    // Validate length
    if (this.currentPacketLen > MAX_V2_MESSAGE_SIZE) {
      return {
        continue: false,
        fallbackV1: false,
        error: `Packet too large: ${this.currentPacketLen}`,
      };
    }

    // Move to APP state to receive payload
    this.recvState = RecvState.APP;
    this.decryptBuffer = encryptedLen; // AAD includes encrypted length

    return { continue: true, fallbackV1: false };
  }

  /**
   * Process application message length.
   */
  private processAppLength(): RecvResult {
    // Need full payload (contents + header + tag)
    const expectedLen = this.currentPacketLen + 1 + 16; // HEADER_LEN + POLY1305_TAG_LEN

    if (this.recvBuffer.length < expectedLen) {
      return { continue: false, fallbackV1: false };
    }

    // Extract encrypted payload
    const encryptedPayload = this.recvBuffer.subarray(0, expectedLen);
    this.recvBuffer = this.recvBuffer.subarray(expectedLen);

    // Decrypt with AAD (garbage for first packet after handshake, empty otherwise)
    const aad = this.receivedMessages.length === 0 ? this.garbageBuffer : Buffer.alloc(0);
    const result = this.cipher.decrypt(encryptedPayload, aad);

    if (result === null) {
      return {
        continue: false,
        fallbackV1: false,
        error: "Decryption failed",
      };
    }

    // Don't process IGNORE packets
    if (!result.ignore && result.contents.length > 0) {
      // Decode message type
      const { msgType, remaining } = decodeMessageType(result.contents);
      if (msgType !== null) {
        this.receivedMessages.push({
          type: msgType,
          payload: remaining,
          ignore: result.ignore,
        });
      }
    }

    // Clear garbage buffer after first packet
    if (this.receivedMessages.length === 1) {
      this.garbageBuffer = Buffer.alloc(0);
    }

    // Stay in APP state for more packets
    this.recvState = RecvState.APP_READY;
    return { continue: true, fallbackV1: false };
  }

  /**
   * Process application message payload.
   */
  private processAppPayload(): RecvResult {
    // Check for more packets
    if (this.recvBuffer.length < LENGTH_LEN) {
      return { continue: false, fallbackV1: false };
    }

    // Decrypt next length
    const encryptedLen = this.recvBuffer.subarray(0, LENGTH_LEN);
    this.currentPacketLen = this.cipher.decryptLength(encryptedLen);
    this.recvBuffer = this.recvBuffer.subarray(LENGTH_LEN);

    if (this.currentPacketLen > MAX_V2_MESSAGE_SIZE) {
      return {
        continue: false,
        fallbackV1: false,
        error: `Packet too large: ${this.currentPacketLen}`,
      };
    }

    this.recvState = RecvState.APP;
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
   * Encrypt and queue a message for sending.
   *
   * @param msgType - Message type (e.g., "version", "ping")
   * @param payload - Message payload
   * @param ignore - Whether to set the IGNORE bit
   * @returns Encrypted packet bytes
   */
  encryptMessage(msgType: string, payload: Buffer, ignore: boolean = false): Buffer {
    if (!this.cipher.isInitialized()) {
      throw new Error("Cipher not initialized");
    }

    // Encode message type
    const typeBytes = encodeMessageType(msgType);
    const contents = Buffer.concat([typeBytes, payload]);

    // Determine AAD (garbage for first packet, empty otherwise)
    let aad: Buffer;
    if (!this.versionPacketSent) {
      // First packet uses our garbage as AAD
      aad = this.garbage;
      this.versionPacketSent = true;
    } else {
      aad = Buffer.alloc(0);
    }

    return this.cipher.encrypt(contents, aad, ignore);
  }

  /**
   * Get the garbage terminator to send after receiving their key.
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
