/**
 * BIP-330 Erlay: efficient transaction reconciliation.
 *
 * Erlay reduces transaction relay bandwidth by using set reconciliation
 * instead of sending full inventory lists. Peers exchange sketches of their
 * transaction sets and compute the symmetric difference efficiently.
 *
 * Reference: https://github.com/bitcoin/bips/blob/master/bip-0330.mediawiki
 *            Bitcoin Core /home/max/hashhog/bitcoin/src/node/txreconciliation.cpp
 */

import type { Peer } from "./peer.js";
import type {
  NetworkMessage,
  SendTxRcnclPayload,
  ReqReconPayload,
  SketchPayload,
  ReconcilDiffPayload,
  InvTxPayload,
} from "./messages.js";
import { sipHash24 } from "../storage/indexes.js";
import { Minisketch, makeMinisketch32, chooseSketchCapacity } from "./minisketch.js";
import { hash256 } from "../crypto/primitives.js";

// ============================================================================
// Constants
// ============================================================================

/**
 * Current Erlay protocol version.
 * Reference: Bitcoin Core TXRECONCILIATION_VERSION
 */
export const ERLAY_VERSION = 1;

/**
 * Static salt used to compute short transaction IDs.
 * This matches Bitcoin Core's RECON_STATIC_SALT.
 */
const RECON_STATIC_SALT = "Tx Relay Salting";

/**
 * Reconciliation interval for outbound connections (initiator role).
 * The initiator requests reconciliation every ~2 seconds.
 */
export const OUTBOUND_RECON_INTERVAL_MS = 2000;

/**
 * Reconciliation interval for inbound connections (responder role).
 * Responders are polled less frequently (~8 seconds).
 */
export const INBOUND_RECON_INTERVAL_MS = 8000;

/**
 * Default coefficient for estimating set difference (q parameter).
 * A higher value means larger sketch capacity.
 */
export const DEFAULT_Q_COEFFICIENT = 1;

/**
 * Maximum sketch capacity (limits memory usage).
 */
export const MAX_SKETCH_CAPACITY = 2000;

/**
 * Minimum set size to trigger reconciliation.
 * Below this, regular inv flooding is more efficient.
 */
export const MIN_RECON_SET_SIZE = 10;

/**
 * Maximum set difference for successful reconciliation.
 * If exceeded, fall back to inv flooding.
 */
export const MAX_RECON_SET_DIFF = 100;

// ============================================================================
// Short ID Computation
// ============================================================================

/**
 * Compute the salt used for short ID computation between two peers.
 *
 * The salt is derived by hashing the static salt with both peer salts
 * combined in ascending order.
 *
 * @param salt1 - First peer's salt (our salt)
 * @param salt2 - Second peer's salt (remote peer's salt)
 * @returns 32-byte salt for SipHash key derivation
 */
export function computeReconSalt(salt1: bigint, salt2: bigint): Buffer {
  // Combine salts in ascending order (per BIP-330)
  const minSalt = salt1 < salt2 ? salt1 : salt2;
  const maxSalt = salt1 < salt2 ? salt2 : salt1;

  // Create tagged hash: SHA256(SHA256(tag) || SHA256(tag) || data)
  const tagHash = hash256(Buffer.from(RECON_STATIC_SALT, "utf8"));

  // Serialize salts as little-endian uint64
  const saltData = Buffer.alloc(16);
  saltData.writeBigUInt64LE(minSalt, 0);
  saltData.writeBigUInt64LE(maxSalt, 8);

  return hash256(Buffer.concat([tagHash, tagHash, saltData]));
}

/**
 * Compute the 32-bit short ID for a transaction.
 *
 * shortID = SipHash-2-4(k0, k1, wtxid) truncated to 32 bits.
 *
 * @param k0 - First SipHash key (from salt)
 * @param k1 - Second SipHash key (from salt)
 * @param wtxid - 32-byte witness transaction ID
 * @returns 32-bit short ID
 */
export function computeShortId(k0: bigint, k1: bigint, wtxid: Buffer): number {
  const hash = sipHash24(k0, k1, wtxid);
  // Truncate to 32 bits
  return Number(hash & 0xffffffffn) >>> 0;
}

/**
 * Derive SipHash keys from the combined salt.
 *
 * @param salt - 32-byte combined salt
 * @returns Tuple of [k0, k1] for SipHash
 */
export function deriveSipHashKeys(salt: Buffer): [bigint, bigint] {
  const k0 = salt.readBigUInt64LE(0);
  const k1 = salt.readBigUInt64LE(8);
  return [k0, k1];
}

// ============================================================================
// Per-Peer Reconciliation State
// ============================================================================

/**
 * Result of attempting to register a peer for reconciliation.
 */
export enum ReconciliationRegisterResult {
  /** Peer was not pre-registered. */
  NOT_FOUND = "NOT_FOUND",
  /** Registration successful. */
  SUCCESS = "SUCCESS",
  /** Peer was already registered. */
  ALREADY_REGISTERED = "ALREADY_REGISTERED",
  /** Protocol violation (invalid version, etc.). */
  PROTOCOL_VIOLATION = "PROTOCOL_VIOLATION",
}

/**
 * State of an active reconciliation round.
 */
export interface ReconciliationRound {
  /** Timestamp when round started. */
  startTime: number;
  /** Local set snapshot at round start. */
  localSet: Set<number>;
  /** Sketch sent to peer (if responder). */
  sentSketch: Minisketch | null;
  /** Whether we're waiting for a response. */
  pending: boolean;
  /** Whether extension was requested. */
  extensionRequested: boolean;
}

/**
 * Per-peer reconciliation state.
 */
export interface TxReconciliationState {
  /** Whether we are the initiator (true) or responder (false). */
  weInitiate: boolean;
  /** SipHash key k0 for short ID computation. */
  k0: bigint;
  /** SipHash key k1 for short ID computation. */
  k1: bigint;
  /** Set of short IDs for transactions to reconcile. */
  reconSet: Set<number>;
  /** Map from short ID to wtxid. */
  shortIdToWtxid: Map<number, Buffer>;
  /** Current reconciliation round (if any). */
  currentRound: ReconciliationRound | null;
  /** Timer for periodic reconciliation (initiator only). */
  reconTimer: ReturnType<typeof setInterval> | null;
}

// ============================================================================
// Transaction Reconciliation Tracker
// ============================================================================

/**
 * Callback types for reconciliation events.
 */
export interface TxReconciliationCallbacks {
  /** Send a message to a peer. */
  sendMessage: (peer: Peer, msg: NetworkMessage) => void;
  /** Request transactions by wtxid. */
  requestTransactions: (peer: Peer, wtxids: Buffer[]) => void;
  /** Announce transactions to peer (they are missing these). */
  announceTransactions: (peer: Peer, wtxids: Buffer[]) => void;
  /** Log a debug message. */
  log?: (message: string) => void;
}

/**
 * TxReconciliationTracker: manages Erlay reconciliation state for all peers.
 *
 * Following Bitcoin Core's TxReconciliationTracker pattern:
 * 1. PreRegisterPeer: generate local salt before sending sendtxrcncl
 * 2. RegisterPeer: complete registration when we receive their sendtxrcncl
 * 3. ForgetPeer: clean up when peer disconnects
 *
 * Reference: Bitcoin Core node/txreconciliation.cpp
 */
export class TxReconciliationTracker {
  /** Local protocol version. */
  private reconVersion: number;

  /**
   * Per-peer state.
   * Before full registration: stores local salt (bigint).
   * After registration: stores TxReconciliationState.
   */
  private states: Map<string, bigint | TxReconciliationState>;

  /** Callbacks for sending messages, etc. */
  private callbacks: TxReconciliationCallbacks;

  constructor(callbacks: TxReconciliationCallbacks, reconVersion: number = ERLAY_VERSION) {
    this.reconVersion = reconVersion;
    this.states = new Map();
    this.callbacks = callbacks;
  }

  /**
   * Generate a peer ID string from host:port.
   */
  private getPeerId(peer: Peer): string {
    return `${peer.host}:${peer.port}`;
  }

  /**
   * Log a message if logging callback is available.
   */
  private log(message: string): void {
    if (this.callbacks.log) {
      this.callbacks.log(`[Erlay] ${message}`);
    }
  }

  /**
   * Pre-register a peer for reconciliation.
   *
   * Generates and stores our local salt. Call this before sending sendtxrcncl.
   *
   * @param peer - The peer to pre-register
   * @returns Our local salt to include in sendtxrcncl message
   */
  preRegisterPeer(peer: Peer): bigint {
    const peerId = this.getPeerId(peer);
    this.log(`Pre-registering peer ${peerId}`);

    // Generate random 64-bit salt
    // Use two 32-bit random values combined into a 64-bit value
    const low32 = BigInt(Math.floor(Math.random() * 0xFFFFFFFF)) & 0xFFFFFFFFn;
    const high32 = BigInt(Math.floor(Math.random() * 0xFFFFFFFF)) & 0xFFFFFFFFn;
    const localSalt = low32 | (high32 << 32n);

    this.states.set(peerId, localSalt);
    return localSalt;
  }

  /**
   * Complete peer registration after receiving their sendtxrcncl.
   *
   * @param peer - The peer
   * @param isPeerInbound - Whether this is an inbound connection
   * @param peerReconVersion - Peer's reconciliation version
   * @param remoteSalt - Peer's salt from sendtxrcncl
   * @returns Registration result
   */
  registerPeer(
    peer: Peer,
    isPeerInbound: boolean,
    peerReconVersion: number,
    remoteSalt: bigint
  ): ReconciliationRegisterResult {
    const peerId = this.getPeerId(peer);
    const state = this.states.get(peerId);

    if (state === undefined) {
      this.log(`Peer ${peerId} not pre-registered`);
      return ReconciliationRegisterResult.NOT_FOUND;
    }

    if (typeof state !== "bigint") {
      this.log(`Peer ${peerId} already registered`);
      return ReconciliationRegisterResult.ALREADY_REGISTERED;
    }

    const localSalt = state;

    // Downgrade to minimum supported version
    const reconVersion = Math.min(peerReconVersion, this.reconVersion);
    if (reconVersion < 1) {
      this.log(`Peer ${peerId} version too low: ${reconVersion}`);
      return ReconciliationRegisterResult.PROTOCOL_VIOLATION;
    }

    // Compute combined salt and derive keys
    const fullSalt = computeReconSalt(localSalt, remoteSalt);
    const [k0, k1] = deriveSipHashKeys(fullSalt);

    // Initiator role: outbound connections initiate reconciliation
    const weInitiate = !isPeerInbound;

    this.log(`Registered peer ${peerId} (initiator=${weInitiate})`);

    // Create full state
    const reconState: TxReconciliationState = {
      weInitiate,
      k0,
      k1,
      reconSet: new Set(),
      shortIdToWtxid: new Map(),
      currentRound: null,
      reconTimer: null,
    };

    this.states.set(peerId, reconState);

    // Start periodic reconciliation for initiators
    if (weInitiate) {
      this.startReconciliationTimer(peer, reconState);
    }

    return ReconciliationRegisterResult.SUCCESS;
  }

  /**
   * Forget a peer and clean up state.
   *
   * @param peer - The peer to forget
   */
  forgetPeer(peer: Peer): void {
    const peerId = this.getPeerId(peer);
    const state = this.states.get(peerId);

    if (state && typeof state !== "bigint") {
      // Stop reconciliation timer if running
      if (state.reconTimer) {
        clearInterval(state.reconTimer);
      }
    }

    if (this.states.delete(peerId)) {
      this.log(`Forgot peer ${peerId}`);
    }
  }

  /**
   * Check if a peer is fully registered for reconciliation.
   *
   * @param peer - The peer to check
   * @returns true if peer is registered
   */
  isPeerRegistered(peer: Peer): boolean {
    const peerId = this.getPeerId(peer);
    const state = this.states.get(peerId);
    return state !== undefined && typeof state !== "bigint";
  }

  /**
   * Get peer state if registered.
   */
  private getPeerState(peer: Peer): TxReconciliationState | null {
    const peerId = this.getPeerId(peer);
    const state = this.states.get(peerId);
    if (state && typeof state !== "bigint") {
      return state;
    }
    return null;
  }

  /**
   * Add a transaction to a peer's reconciliation set.
   *
   * Instead of immediately announcing the transaction, we add it to the
   * set for reconciliation during the next round.
   *
   * @param peer - The peer
   * @param wtxid - Transaction wtxid
   */
  addToReconSet(peer: Peer, wtxid: Buffer): void {
    const state = this.getPeerState(peer);
    if (!state) return;

    const shortId = computeShortId(state.k0, state.k1, wtxid);
    state.reconSet.add(shortId);
    state.shortIdToWtxid.set(shortId, wtxid);
  }

  /**
   * Remove a transaction from a peer's reconciliation set.
   *
   * Call this when a transaction is confirmed or otherwise no longer needs relay.
   *
   * @param peer - The peer
   * @param wtxid - Transaction wtxid
   */
  removeFromReconSet(peer: Peer, wtxid: Buffer): void {
    const state = this.getPeerState(peer);
    if (!state) return;

    const shortId = computeShortId(state.k0, state.k1, wtxid);
    state.reconSet.delete(shortId);
    state.shortIdToWtxid.delete(shortId);
  }

  /**
   * Start periodic reconciliation timer for an initiator.
   */
  private startReconciliationTimer(peer: Peer, state: TxReconciliationState): void {
    const interval = state.weInitiate ? OUTBOUND_RECON_INTERVAL_MS : INBOUND_RECON_INTERVAL_MS;

    state.reconTimer = setInterval(() => {
      this.maybeInitiateReconciliation(peer, state);
    }, interval);
  }

  /**
   * Maybe initiate a reconciliation round.
   */
  private maybeInitiateReconciliation(peer: Peer, state: TxReconciliationState): void {
    // Don't start if we already have a round in progress
    if (state.currentRound && state.currentRound.pending) {
      return;
    }

    // Don't reconcile if set is too small
    if (state.reconSet.size < MIN_RECON_SET_SIZE) {
      return;
    }

    this.log(`Initiating reconciliation with ${this.getPeerId(peer)}, set size: ${state.reconSet.size}`);

    // Start a new round
    state.currentRound = {
      startTime: Date.now(),
      localSet: new Set(state.reconSet),
      sentSketch: null,
      pending: true,
      extensionRequested: false,
    };

    // Send reqrecon message
    const msg: NetworkMessage = {
      type: "reqrecon",
      payload: {
        setSize: state.reconSet.size,
        q: DEFAULT_Q_COEFFICIENT,
      },
    };

    this.callbacks.sendMessage(peer, msg);
  }

  /**
   * Handle received sendtxrcncl message.
   *
   * This is called during handshake when peer announces Erlay support.
   *
   * @param peer - The peer
   * @param payload - sendtxrcncl payload
   * @param isPeerInbound - Whether this is an inbound connection
   */
  handleSendTxRcncl(
    peer: Peer,
    payload: SendTxRcnclPayload,
    isPeerInbound: boolean
  ): void {
    const result = this.registerPeer(peer, isPeerInbound, payload.version, payload.salt);

    if (result !== ReconciliationRegisterResult.SUCCESS) {
      this.log(`Failed to register peer ${this.getPeerId(peer)}: ${result}`);
    }
  }

  /**
   * Handle received reqrecon message (as responder).
   *
   * Computes our sketch and sends it to the initiator.
   *
   * @param peer - The peer
   * @param payload - reqrecon payload
   */
  handleReqRecon(peer: Peer, payload: ReqReconPayload): void {
    const state = this.getPeerState(peer);
    if (!state) {
      this.log(`Received reqrecon from unregistered peer ${this.getPeerId(peer)}`);
      return;
    }

    // Calculate sketch capacity based on set sizes
    const capacity = Math.min(
      chooseSketchCapacity(state.reconSet.size, payload.setSize),
      MAX_SKETCH_CAPACITY
    );

    // Build sketch from our set
    const sketch = makeMinisketch32(capacity);
    for (const shortId of state.reconSet) {
      sketch.add(shortId);
    }

    // Store for potential extension
    state.currentRound = {
      startTime: Date.now(),
      localSet: new Set(state.reconSet),
      sentSketch: sketch.clone(),
      pending: true,
      extensionRequested: false,
    };

    // Send sketch
    const msg: NetworkMessage = {
      type: "sketch",
      payload: {
        sketchData: sketch.serialize(),
      },
    };

    this.callbacks.sendMessage(peer, msg);
  }

  /**
   * Handle received sketch message (as initiator).
   *
   * Attempts to decode the set difference using our local set.
   *
   * @param peer - The peer
   * @param payload - sketch payload
   */
  handleSketch(peer: Peer, payload: SketchPayload): void {
    const state = this.getPeerState(peer);
    if (!state || !state.currentRound) {
      this.log(`Received sketch from peer ${this.getPeerId(peer)} without active round`);
      return;
    }

    const round = state.currentRound;

    // Deserialize their sketch
    const remoteSketch = Minisketch.deserialize(payload.sketchData);

    // Build our sketch with same capacity
    const localSketch = makeMinisketch32(remoteSketch.getCapacity());
    for (const shortId of round.localSet) {
      localSketch.add(shortId);
    }

    // Merge (XOR) to get difference sketch
    localSketch.merge(remoteSketch);

    // Try to decode the difference
    const difference = localSketch.decode();

    if (difference === null) {
      // Decoding failed - need extension or fallback
      if (!round.extensionRequested) {
        this.log(`Requesting sketch extension from ${this.getPeerId(peer)}`);
        round.extensionRequested = true;

        const msg: NetworkMessage = {
          type: "reqsketchext",
          payload: {},
        };
        this.callbacks.sendMessage(peer, msg);
        return;
      }

      // Extension already tried, fall back to flooding
      this.fallbackToFlooding(peer, state, round);
      return;
    }

    // Successfully decoded - categorize elements
    const localMissing: number[] = [];
    const remoteMissing: number[] = [];

    for (const shortId of difference) {
      if (round.localSet.has(shortId)) {
        // We have it, they don't
        remoteMissing.push(shortId);
      } else {
        // They have it, we don't
        localMissing.push(shortId);
      }
    }

    this.log(`Reconciliation success: localMissing=${localMissing.length}, remoteMissing=${remoteMissing.length}`);

    // Send reconcildiff to announce result
    const msg: NetworkMessage = {
      type: "reconcildiff",
      payload: {
        success: true,
        localMissing,
        remoteMissing,
      },
    };
    this.callbacks.sendMessage(peer, msg);

    // Request missing transactions
    if (localMissing.length > 0) {
      // We need to wait for peer to announce these via invtx
      // For now, just log
      this.log(`Waiting for peer to announce ${localMissing.length} transactions`);
    }

    // Announce transactions peer is missing
    if (remoteMissing.length > 0) {
      const wtxidsToAnnounce: Buffer[] = [];
      for (const shortId of remoteMissing) {
        const wtxid = state.shortIdToWtxid.get(shortId);
        if (wtxid) {
          wtxidsToAnnounce.push(wtxid);
        }
      }
      if (wtxidsToAnnounce.length > 0) {
        this.callbacks.announceTransactions(peer, wtxidsToAnnounce);
      }
    }

    // Clean up round
    state.currentRound = null;

    // Clear reconciled items from set
    for (const shortId of remoteMissing) {
      state.reconSet.delete(shortId);
      state.shortIdToWtxid.delete(shortId);
    }
  }

  /**
   * Handle received reqsketchext message.
   *
   * Sends extended sketch data for retrying reconciliation.
   *
   * @param peer - The peer
   */
  handleReqSketchExt(peer: Peer): void {
    const state = this.getPeerState(peer);
    if (!state || !state.currentRound || !state.currentRound.sentSketch) {
      this.log(`Received reqsketchext without active round`);
      return;
    }

    // Double capacity and resend
    const oldCapacity = state.currentRound.sentSketch.getCapacity();
    const newCapacity = Math.min(oldCapacity * 2, MAX_SKETCH_CAPACITY);

    const sketch = makeMinisketch32(newCapacity);
    for (const shortId of state.currentRound.localSet) {
      sketch.add(shortId);
    }

    state.currentRound.sentSketch = sketch.clone();

    const msg: NetworkMessage = {
      type: "sketch",
      payload: {
        sketchData: sketch.serialize(),
      },
    };

    this.callbacks.sendMessage(peer, msg);
  }

  /**
   * Handle received reconcildiff message.
   *
   * Process reconciliation result from initiator.
   *
   * @param peer - The peer
   * @param payload - reconcildiff payload
   */
  handleReconcilDiff(peer: Peer, payload: ReconcilDiffPayload): void {
    const state = this.getPeerState(peer);
    if (!state) {
      return;
    }

    if (!payload.success) {
      // Reconciliation failed, they will send full inv
      this.log(`Reconciliation failed with ${this.getPeerId(peer)}, expecting inv flood`);
      return;
    }

    // Announce transactions they are missing via invtx
    if (payload.localMissing.length > 0) {
      const wtxidsToAnnounce: Buffer[] = [];
      for (const shortId of payload.localMissing) {
        const wtxid = state.shortIdToWtxid.get(shortId);
        if (wtxid) {
          wtxidsToAnnounce.push(wtxid);
        }
      }

      if (wtxidsToAnnounce.length > 0) {
        const msg: NetworkMessage = {
          type: "invtx",
          payload: { wtxids: wtxidsToAnnounce },
        };
        this.callbacks.sendMessage(peer, msg);
      }
    }

    // Request transactions we are missing
    if (payload.remoteMissing.length > 0) {
      // They will send invtx, we'll request from there
      this.log(`Waiting for invtx for ${payload.remoteMissing.length} transactions`);
    }

    // Clean up
    if (state.currentRound) {
      state.currentRound = null;
    }
  }

  /**
   * Handle received invtx message.
   *
   * Request the announced transactions.
   *
   * @param peer - The peer
   * @param payload - invtx payload
   */
  handleInvTx(peer: Peer, payload: InvTxPayload): void {
    if (payload.wtxids.length > 0) {
      this.callbacks.requestTransactions(peer, payload.wtxids);
    }
  }

  /**
   * Fall back to regular inv flooding when reconciliation fails.
   */
  private fallbackToFlooding(
    peer: Peer,
    state: TxReconciliationState,
    round: ReconciliationRound
  ): void {
    this.log(`Falling back to inv flooding with ${this.getPeerId(peer)}`);

    // Send reconcildiff with failure flag
    const msg: NetworkMessage = {
      type: "reconcildiff",
      payload: {
        success: false,
        localMissing: [],
        remoteMissing: [],
      },
    };
    this.callbacks.sendMessage(peer, msg);

    // Announce all our transactions
    const wtxids: Buffer[] = [];
    for (const shortId of round.localSet) {
      const wtxid = state.shortIdToWtxid.get(shortId);
      if (wtxid) {
        wtxids.push(wtxid);
      }
    }

    if (wtxids.length > 0) {
      this.callbacks.announceTransactions(peer, wtxids);
    }

    // Clean up round
    state.currentRound = null;
  }

  /**
   * Handle an incoming message related to Erlay.
   *
   * @param peer - The peer
   * @param msg - The message
   * @param isPeerInbound - Whether this is an inbound connection
   * @returns true if message was handled
   */
  handleMessage(peer: Peer, msg: NetworkMessage, isPeerInbound: boolean): boolean {
    switch (msg.type) {
      case "sendtxrcncl":
        this.handleSendTxRcncl(peer, msg.payload, isPeerInbound);
        return true;
      case "reqrecon":
        this.handleReqRecon(peer, msg.payload);
        return true;
      case "sketch":
        this.handleSketch(peer, msg.payload);
        return true;
      case "reqsketchext":
        this.handleReqSketchExt(peer);
        return true;
      case "reconcildiff":
        this.handleReconcilDiff(peer, msg.payload);
        return true;
      case "invtx":
        this.handleInvTx(peer, msg.payload);
        return true;
      default:
        return false;
    }
  }

  /**
   * Check if a transaction should be added to recon set or announced immediately.
   *
   * Transactions are queued for reconciliation if:
   * - Peer is registered for Erlay
   * - Set is not too large
   *
   * @param peer - The peer
   * @returns true if transaction should be queued for reconciliation
   */
  shouldQueueForReconciliation(peer: Peer): boolean {
    const state = this.getPeerState(peer);
    if (!state) return false;

    // Don't queue if set is already large
    if (state.reconSet.size >= MAX_SKETCH_CAPACITY) {
      return false;
    }

    return true;
  }

  /**
   * Get the number of registered peers.
   */
  getRegisteredPeerCount(): number {
    let count = 0;
    for (const state of this.states.values()) {
      if (typeof state !== "bigint") {
        count++;
      }
    }
    return count;
  }

  /**
   * Stop all reconciliation timers (for cleanup).
   */
  stopAll(): void {
    for (const state of this.states.values()) {
      if (typeof state !== "bigint" && state.reconTimer) {
        clearInterval(state.reconTimer);
      }
    }
  }
}

/**
 * Create a sendtxrcncl message for handshake.
 *
 * @param salt - Our local salt
 * @returns NetworkMessage
 */
export function createSendTxRcnclMessage(salt: bigint): NetworkMessage {
  return {
    type: "sendtxrcncl",
    payload: {
      version: ERLAY_VERSION,
      salt,
    },
  };
}

/**
 * Check if Erlay is supported based on protocol version.
 *
 * Erlay requires at least protocol version 70016.
 *
 * @param protocolVersion - Peer's protocol version
 * @returns true if Erlay is supported
 */
export function isErlaySupported(protocolVersion: number): boolean {
  return protocolVersion >= 70016;
}
