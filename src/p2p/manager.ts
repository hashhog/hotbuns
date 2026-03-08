/**
 * Peer discovery, connection management, and message routing.
 *
 * Handles DNS seed resolution, maintains configurable outbound connections,
 * tracks peer quality via ban scores, and routes messages to handlers.
 */

import { Peer, type PeerConfig, type PeerEvents, type PeerState } from "./peer.js";
import type { NetworkMessage, AddrPayload, NetworkAddress } from "./messages.js";
import type { ConsensusParams } from "../consensus/params.js";
import { BufferReader, BufferWriter } from "../wire/serialization.js";

/** Service bit flags for peer capabilities. */
export const ServiceFlags = {
  NODE_NETWORK: 1n,          // Full node, can serve full blocks
  NODE_BLOOM: 4n,            // SPV bloom filter support (BIP 111)
  NODE_WITNESS: 8n,          // Segregated Witness support (BIP 144)
  NODE_NETWORK_LIMITED: 1024n, // Pruned node (BIP 159)
} as const;

/** Configuration for the peer manager. */
export interface PeerManagerConfig {
  maxOutbound: number;       // default 8
  maxInbound: number;        // default 117
  params: ConsensusParams;
  bestHeight: number;
  datadir: string;
}

/** Stored information about a known peer address. */
export interface PeerInfo {
  host: string;
  port: number;
  services: bigint;
  lastSeen: number;          // Unix timestamp
  banScore: number;
  lastConnected: number;     // Unix timestamp
}

/** Ban score penalties for various infractions. */
export const BanScores = {
  INVALID_MESSAGE: 20,
  INVALID_BLOCK: 100,        // Instant ban
  SLOW_RESPONSE: 2,
  PROTOCOL_VIOLATION: 50,
  UNREQUESTED_DATA: 10,
} as const;

/** Fallback peer addresses when DNS seeds fail (testnet4 is unreliable). */
const FALLBACK_PEERS: Record<number, Array<{ host: string; port: number }>> = {
  // Mainnet (networkMagic: 0xd9b4bef9)
  0xd9b4bef9: [
    { host: "seed.bitcoin.sipa.be", port: 8333 },
    { host: "dnsseed.bluematt.me", port: 8333 },
  ],
  // Testnet (networkMagic: 0x0709110b)
  0x0709110b: [
    { host: "testnet-seed.bitcoin.jonasschnelli.ch", port: 18333 },
    { host: "seed.tbtc.petertodd.net", port: 18333 },
  ],
  // Regtest (networkMagic: 0xdab5bffa) - no fallbacks, local only
  0xdab5bffa: [],
};

/** Database prefix for peer addresses. */
export const DB_PREFIX_PEERS = 0x70; // 'p'

/**
 * Manages peer connections, discovery, and message routing.
 *
 * Responsibilities:
 * - Resolve DNS seeds to discover peers
 * - Maintain up to maxOutbound outbound connections
 * - Track peer quality and ban misbehaving peers
 * - Route received messages to registered handlers
 * - Persist known addresses for faster restarts
 */
export class PeerManager {
  private peers: Map<string, Peer>;
  private knownAddresses: Map<string, PeerInfo>;
  private config: PeerManagerConfig;
  private messageHandlers: Map<string, Array<(peer: Peer, msg: NetworkMessage) => void>>;
  private maintainInterval: ReturnType<typeof setInterval> | null;
  private running: boolean;
  private lastActivity: Map<string, number>;
  private connectingPeers: Set<string>;

  constructor(config: PeerManagerConfig) {
    this.config = {
      maxOutbound: config.maxOutbound ?? 8,
      maxInbound: config.maxInbound ?? 117,
      params: config.params,
      bestHeight: config.bestHeight ?? 0,
      datadir: config.datadir,
    };
    this.peers = new Map();
    this.knownAddresses = new Map();
    this.messageHandlers = new Map();
    this.maintainInterval = null;
    this.running = false;
    this.lastActivity = new Map();
    this.connectingPeers = new Set();
  }

  /**
   * Start the peer manager: resolve DNS seeds, begin connecting.
   */
  async start(): Promise<void> {
    this.running = true;

    // Load persisted addresses
    await this.loadAddresses();

    // Resolve DNS seeds
    const addresses = await this.resolveDNSSeeds();
    const now = Date.now();

    // Add discovered addresses to known pool
    for (const ip of addresses) {
      const key = `${ip}:${this.config.params.defaultPort}`;
      if (!this.knownAddresses.has(key)) {
        this.knownAddresses.set(key, {
          host: ip,
          port: this.config.params.defaultPort,
          services: ServiceFlags.NODE_NETWORK | ServiceFlags.NODE_WITNESS,
          lastSeen: now,
          banScore: 0,
          lastConnected: 0,
        });
      }
    }

    // Add fallback peers if we don't have enough addresses
    const fallbacks = FALLBACK_PEERS[this.config.params.networkMagic] ?? [];
    for (const { host, port } of fallbacks) {
      const key = `${host}:${port}`;
      if (!this.knownAddresses.has(key)) {
        this.knownAddresses.set(key, {
          host,
          port,
          services: ServiceFlags.NODE_NETWORK | ServiceFlags.NODE_WITNESS,
          lastSeen: now,
          banScore: 0,
          lastConnected: 0,
        });
      }
    }

    // Fill initial connections
    await this.fillConnections();

    // Start maintenance loop (every 30 seconds)
    this.maintainInterval = setInterval(() => {
      this.maintain().catch((err) => {
        console.error("Maintenance error:", err);
      });
    }, 30_000);
  }

  /**
   * Stop all peer connections and the maintenance loop.
   */
  async stop(): Promise<void> {
    this.running = false;

    // Stop maintenance loop
    if (this.maintainInterval) {
      clearInterval(this.maintainInterval);
      this.maintainInterval = null;
    }

    // Disconnect all peers
    for (const [key, peer] of this.peers) {
      peer.disconnect("shutdown");
      this.peers.delete(key);
    }

    // Save addresses before shutdown
    await this.saveAddresses();
  }

  /**
   * Resolve DNS seed hostnames to IP addresses.
   * Shuffles results for randomized peer selection.
   */
  private async resolveDNSSeeds(): Promise<string[]> {
    const seeds = this.config.params.dnsSeed;
    const addresses: string[] = [];

    for (const seed of seeds) {
      try {
        // Use Bun's built-in DNS resolution
        // @ts-expect-error Bun.dns.resolve typing is incomplete
        const results = await Bun.dns.resolve(seed, "A") as Array<{ address: string; ttl: number }>;
        for (const record of results) {
          if (record && typeof record.address === "string") {
            addresses.push(record.address);
          }
        }
      } catch {
        // DNS resolution failed for this seed, continue with others
      }
    }

    // Shuffle addresses using Fisher-Yates
    for (let i = addresses.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [addresses[i], addresses[j]] = [addresses[j], addresses[i]];
    }

    return addresses;
  }

  /**
   * Connect to a specific peer by host and port.
   * Returns the connected Peer instance.
   */
  async connectPeer(host: string, port: number): Promise<Peer> {
    const key = `${host}:${port}`;

    // Check if already connected or connecting
    if (this.peers.has(key)) {
      return this.peers.get(key)!;
    }

    if (this.connectingPeers.has(key)) {
      throw new Error(`Already connecting to ${key}`);
    }

    this.connectingPeers.add(key);

    const config: PeerConfig = {
      host,
      port,
      magic: this.config.params.networkMagic,
      protocolVersion: this.config.params.protocolVersion,
      services: this.config.params.services,
      userAgent: this.config.params.userAgent,
      bestHeight: this.config.bestHeight,
      relay: true,
    };

    const events: PeerEvents = {
      onConnect: (peer) => this.handlePeerConnect(peer),
      onDisconnect: (peer, error) => this.handlePeerDisconnect(peer, error),
      onMessage: (peer, msg) => this.handlePeerMessage(peer, msg),
      onHandshakeComplete: (peer) => this.handleHandshakeComplete(peer),
    };

    const peer = new Peer(config, events);

    try {
      await peer.connect();
      this.peers.set(key, peer);
      this.lastActivity.set(key, Date.now());

      // Add or update known address
      const now = Date.now();
      if (!this.knownAddresses.has(key)) {
        this.knownAddresses.set(key, {
          host,
          port,
          services: ServiceFlags.NODE_NETWORK | ServiceFlags.NODE_WITNESS,
          lastSeen: now,
          banScore: 0,
          lastConnected: now,
        });
      } else {
        const info = this.knownAddresses.get(key)!;
        info.lastConnected = now;
      }

      return peer;
    } catch (error) {
      // Connection failed - increase ban score slightly
      const info = this.knownAddresses.get(key);
      if (info) {
        info.banScore += 1;
      }
      throw error;
    } finally {
      this.connectingPeers.delete(key);
    }
  }

  /**
   * Disconnect a peer by key, optionally banning them.
   */
  disconnectPeer(key: string, ban?: boolean): void {
    const peer = this.peers.get(key);
    if (peer) {
      peer.disconnect(ban ? "banned" : "disconnect");
      this.peers.delete(key);
      this.lastActivity.delete(key);
    }

    if (ban) {
      const info = this.knownAddresses.get(key);
      if (info) {
        info.banScore = 100; // Instant ban
      }
    }
  }

  /**
   * Register a handler for a specific message type.
   * Multiple handlers can be registered for the same type.
   */
  onMessage(type: string, handler: (peer: Peer, msg: NetworkMessage) => void): void {
    const handlers = this.messageHandlers.get(type) ?? [];
    handlers.push(handler);
    this.messageHandlers.set(type, handlers);
  }

  /**
   * Broadcast a message to all connected peers.
   */
  broadcast(msg: NetworkMessage): void {
    for (const peer of this.peers.values()) {
      if (peer.state === "connected") {
        peer.send(msg);
      }
    }
  }

  /**
   * Get a list of all connected peers.
   */
  getConnectedPeers(): Peer[] {
    return Array.from(this.peers.values()).filter(
      (peer) => peer.state === "connected"
    );
  }

  /**
   * Get the number of outbound connections.
   */
  getOutboundCount(): number {
    return this.peers.size;
  }

  /**
   * Increase ban score for a misbehaving peer.
   * Disconnects and bans if score reaches 100.
   */
  increaseBanScore(peer: Peer, score: number, reason: string): void {
    const key = `${peer.host}:${peer.port}`;
    const info = this.knownAddresses.get(key);

    if (info) {
      info.banScore += score;

      if (info.banScore >= 100) {
        console.log(`Banning peer ${key}: ${reason} (score: ${info.banScore})`);
        this.disconnectPeer(key, true);
      }
    }
  }

  /**
   * Update the best height (called when chain tip advances).
   */
  updateBestHeight(height: number): void {
    this.config.bestHeight = height;
  }

  /**
   * Get all known peer addresses.
   */
  getKnownAddresses(): Map<string, PeerInfo> {
    return new Map(this.knownAddresses);
  }

  /**
   * Periodic maintenance: evict bad peers, refill connections, ping idle peers.
   */
  private async maintain(): Promise<void> {
    if (!this.running) return;

    const now = Date.now();

    // Check for peers that need pinging or disconnecting
    for (const [key, peer] of this.peers) {
      const lastActivity = this.lastActivity.get(key) ?? 0;
      const idleTime = now - lastActivity;

      if (idleTime > 300_000) {
        // 5 minutes without response - disconnect
        console.log(`Disconnecting unresponsive peer ${key}`);
        this.disconnectPeer(key);
      } else if (idleTime > 120_000 && peer.state === "connected") {
        // 2 minutes idle - send ping
        peer.sendPing();
      }
    }

    // Evict peers with high ban scores
    for (const [key, info] of this.knownAddresses) {
      if (info.banScore >= 100) {
        const peer = this.peers.get(key);
        if (peer) {
          this.disconnectPeer(key, true);
        }
      }
    }

    // Periodically ask connected peers for more addresses
    const connectedPeers = this.getConnectedPeers();
    if (connectedPeers.length > 0 && this.knownAddresses.size < 1000) {
      // Ask a random peer for addresses
      const randomPeer = connectedPeers[Math.floor(Math.random() * connectedPeers.length)];
      randomPeer.send({ type: "getaddr", payload: null });
    }

    // Fill connections up to maxOutbound
    await this.fillConnections();

    // Save addresses periodically
    await this.saveAddresses();
  }

  /**
   * Fill outbound connections up to maxOutbound.
   */
  private async fillConnections(): Promise<void> {
    if (!this.running) return;

    const currentCount = this.peers.size + this.connectingPeers.size;
    const needed = this.config.maxOutbound - currentCount;

    if (needed <= 0) return;

    // Get candidate addresses sorted by preference
    const candidates = this.getCandidateAddresses(needed);

    for (const info of candidates) {
      if (this.peers.size + this.connectingPeers.size >= this.config.maxOutbound) {
        break;
      }

      try {
        await this.connectPeer(info.host, info.port);
      } catch {
        // Connection failed, will be retried in next maintenance cycle
      }
    }
  }

  /**
   * Get candidate addresses for connection, sorted by preference.
   * Prefers peers with NODE_WITNESS, recently seen, low ban scores.
   */
  private getCandidateAddresses(limit: number): PeerInfo[] {
    const now = Date.now();
    const candidates: PeerInfo[] = [];

    for (const [key, info] of this.knownAddresses) {
      // Skip already connected or connecting
      if (this.peers.has(key) || this.connectingPeers.has(key)) {
        continue;
      }

      // Skip banned peers
      if (info.banScore >= 100) {
        continue;
      }

      // Skip recently failed connections (wait at least 5 minutes)
      if (info.lastConnected > 0 && now - info.lastConnected < 300_000) {
        const peer = this.peers.get(key);
        if (!peer) {
          // Recently tried but not connected - skip
          continue;
        }
      }

      candidates.push(info);
    }

    // Sort by preference: NODE_WITNESS > recent lastSeen > low banScore
    candidates.sort((a, b) => {
      // Prefer NODE_WITNESS
      const aWitness = (a.services & ServiceFlags.NODE_WITNESS) !== 0n;
      const bWitness = (b.services & ServiceFlags.NODE_WITNESS) !== 0n;
      if (aWitness && !bWitness) return -1;
      if (!aWitness && bWitness) return 1;

      // Prefer NODE_NETWORK
      const aNetwork = (a.services & ServiceFlags.NODE_NETWORK) !== 0n;
      const bNetwork = (b.services & ServiceFlags.NODE_NETWORK) !== 0n;
      if (aNetwork && !bNetwork) return -1;
      if (!aNetwork && bNetwork) return 1;

      // Prefer lower ban score
      if (a.banScore !== b.banScore) {
        return a.banScore - b.banScore;
      }

      // Prefer more recently seen
      return b.lastSeen - a.lastSeen;
    });

    return candidates.slice(0, limit);
  }

  /**
   * Handle peer connection event.
   */
  private handlePeerConnect(_peer: Peer): void {
    // Connection established, waiting for handshake
  }

  /**
   * Handle peer disconnection.
   */
  private handlePeerDisconnect(peer: Peer, _error?: Error): void {
    const key = `${peer.host}:${peer.port}`;
    this.peers.delete(key);
    this.lastActivity.delete(key);

    // Emit disconnect event to handlers
    const handlers = this.messageHandlers.get("__disconnect__") ?? [];
    for (const handler of handlers) {
      try {
        handler(peer, { type: "verack", payload: null }); // Dummy message
      } catch {
        // Handler error
      }
    }
  }

  /**
   * Handle handshake completion.
   */
  private handleHandshakeComplete(peer: Peer): void {
    const key = `${peer.host}:${peer.port}`;
    this.lastActivity.set(key, Date.now());

    // Update known address with peer's services
    const info = this.knownAddresses.get(key);
    if (info && peer.versionPayload) {
      info.services = peer.versionPayload.services;
      info.lastSeen = Date.now();
    }

    // Emit connect event to handlers
    const handlers = this.messageHandlers.get("__connect__") ?? [];
    for (const handler of handlers) {
      try {
        handler(peer, { type: "verack", payload: null }); // Dummy message
      } catch {
        // Handler error
      }
    }
  }

  /**
   * Handle incoming message from a peer.
   */
  private handlePeerMessage(peer: Peer, msg: NetworkMessage): void {
    const key = `${peer.host}:${peer.port}`;
    this.lastActivity.set(key, Date.now());

    // Handle addr messages to learn new peers
    if (msg.type === "addr") {
      this.handleAddrMessage(peer, msg.payload);
    }

    // Dispatch to registered handlers
    const handlers = this.messageHandlers.get(msg.type) ?? [];
    for (const handler of handlers) {
      try {
        handler(peer, msg);
      } catch (error) {
        console.error(`Handler error for ${msg.type}:`, error);
      }
    }
  }

  /**
   * Process addr message and add new addresses to known pool.
   */
  private handleAddrMessage(_peer: Peer, payload: AddrPayload): void {
    const now = Math.floor(Date.now() / 1000);

    for (const entry of payload.addrs) {
      // Skip addresses that are too old (more than 3 hours)
      if (now - entry.timestamp > 3 * 60 * 60) {
        continue;
      }

      const ip = bufferToIPv4(entry.addr.ip);
      if (!ip) continue; // Skip non-IPv4 addresses

      const key = `${ip}:${entry.addr.port}`;

      // Add or update address
      const existing = this.knownAddresses.get(key);
      if (existing) {
        // Update if more recent
        if (entry.timestamp > existing.lastSeen) {
          existing.lastSeen = entry.timestamp * 1000;
          existing.services = entry.addr.services;
        }
      } else {
        this.knownAddresses.set(key, {
          host: ip,
          port: entry.addr.port,
          services: entry.addr.services,
          lastSeen: entry.timestamp * 1000,
          banScore: 0,
          lastConnected: 0,
        });
      }
    }
  }

  /**
   * Load persisted addresses from disk.
   */
  private async loadAddresses(): Promise<void> {
    const path = `${this.config.datadir}/peers.dat`;
    try {
      const file = Bun.file(path);
      if (await file.exists()) {
        const data = await file.arrayBuffer();
        const buffer = Buffer.from(data);
        const addresses = deserializePeerAddresses(buffer);
        for (const info of addresses) {
          const key = `${info.host}:${info.port}`;
          this.knownAddresses.set(key, info);
        }
      }
    } catch {
      // No saved addresses or read error
    }
  }

  /**
   * Save known addresses to disk.
   */
  private async saveAddresses(): Promise<void> {
    const path = `${this.config.datadir}/peers.dat`;
    try {
      const addresses = Array.from(this.knownAddresses.values());
      const buffer = serializePeerAddresses(addresses);
      await Bun.write(path, buffer);
    } catch {
      // Write error
    }
  }
}

/**
 * Convert an IPv4-mapped IPv6 buffer to IPv4 string.
 * Returns null for non-IPv4 addresses.
 */
function bufferToIPv4(buf: Buffer): string | null {
  if (buf.length !== 16) return null;

  // Check for IPv4-mapped IPv6 prefix: ::ffff:
  const isIPv4Mapped =
    buf[0] === 0 && buf[1] === 0 &&
    buf[2] === 0 && buf[3] === 0 &&
    buf[4] === 0 && buf[5] === 0 &&
    buf[6] === 0 && buf[7] === 0 &&
    buf[8] === 0 && buf[9] === 0 &&
    buf[10] === 0xff && buf[11] === 0xff;

  if (!isIPv4Mapped) return null;

  return `${buf[12]}.${buf[13]}.${buf[14]}.${buf[15]}`;
}

/**
 * Serialize peer addresses for persistence.
 */
function serializePeerAddresses(addresses: PeerInfo[]): Buffer {
  const writer = new BufferWriter();

  // Version byte
  writer.writeUInt8(1);

  // Address count
  writer.writeVarInt(addresses.length);

  for (const info of addresses) {
    // Host as variable-length string
    writer.writeVarString(info.host);
    // Port
    writer.writeUInt16LE(info.port);
    // Services
    writer.writeUInt64LE(info.services);
    // Last seen
    writer.writeUInt64LE(BigInt(info.lastSeen));
    // Ban score
    writer.writeUInt32LE(info.banScore);
    // Last connected
    writer.writeUInt64LE(BigInt(info.lastConnected));
  }

  return writer.toBuffer();
}

/**
 * Deserialize peer addresses from persistence.
 */
function deserializePeerAddresses(data: Buffer): PeerInfo[] {
  const reader = new BufferReader(data);
  const addresses: PeerInfo[] = [];

  // Version byte
  const version = reader.readUInt8();
  if (version !== 1) {
    throw new Error(`Unsupported peer data version: ${version}`);
  }

  // Address count
  const count = reader.readVarInt();

  for (let i = 0; i < count; i++) {
    const host = reader.readVarString();
    const port = reader.readUInt16LE();
    const services = reader.readUInt64LE();
    const lastSeen = Number(reader.readUInt64LE());
    const banScore = reader.readUInt32LE();
    const lastConnected = Number(reader.readUInt64LE());

    addresses.push({
      host,
      port,
      services,
      lastSeen,
      banScore,
      lastConnected,
    });
  }

  return addresses;
}
