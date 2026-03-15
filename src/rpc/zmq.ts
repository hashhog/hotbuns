/**
 * ZeroMQ notification support: publish real-time notifications for new blocks,
 * transactions, and sequence events to ZMQ subscribers.
 *
 * Reference: Bitcoin Core zmq/zmqpublishnotifier.cpp
 */

import { EventEmitter } from "events";
import type { Publisher, Socket } from "zeromq";
import type { Block } from "../validation/block.js";
import type { Transaction } from "../validation/tx.js";
import { serializeBlock, getBlockHash } from "../validation/block.js";
import { serializeTx, getTxId } from "../validation/tx.js";

/**
 * ZMQ notification topic types.
 */
export type ZMQTopic =
  | "hashblock"
  | "hashtx"
  | "rawblock"
  | "rawtx"
  | "sequence";

/**
 * Sequence notification labels.
 * 'A' = mempool acceptance
 * 'R' = mempool removal
 * 'C' = block connected
 * 'D' = block disconnected
 */
export type SequenceLabel = "A" | "R" | "C" | "D";

/**
 * ZMQ notifier configuration for a single topic.
 */
export interface ZMQNotifierConfig {
  topic: ZMQTopic;
  address: string;
}

/**
 * ZMQ notification interface configuration.
 */
export interface ZMQConfig {
  /** Configuration for each enabled topic. */
  notifiers: ZMQNotifierConfig[];
}

/**
 * Parse ZMQ command-line arguments into configuration.
 *
 * Arguments are in the format: --zmqpub<topic>=<address>
 * Example: --zmqpubhashblock=tcp://127.0.0.1:28332
 */
export function parseZMQArgs(args: string[]): ZMQConfig {
  const notifiers: ZMQNotifierConfig[] = [];
  const topicMap: Record<string, ZMQTopic> = {
    hashblock: "hashblock",
    hashtx: "hashtx",
    rawblock: "rawblock",
    rawtx: "rawtx",
    sequence: "sequence",
  };

  for (const arg of args) {
    // Match --zmqpub<topic>=<address>
    const match = arg.match(/^--zmqpub(\w+)=(.+)$/);
    if (match) {
      const topicKey = match[1].toLowerCase();
      const address = match[2];

      if (topicKey in topicMap) {
        notifiers.push({
          topic: topicMap[topicKey],
          address,
        });
      }
    }
  }

  return { notifiers };
}

/**
 * Per-topic publisher state.
 */
interface TopicPublisher {
  topic: ZMQTopic;
  address: string;
  socket: Publisher;
  sequence: number;
}

/**
 * ZMQ notification interface.
 *
 * Manages ZMQ PUB sockets for each configured topic and publishes
 * notifications when chain/mempool events occur.
 */
export class ZMQNotificationInterface {
  private publishers: Map<ZMQTopic, TopicPublisher> = new Map();
  private eventEmitter: EventEmitter;
  private started: boolean = false;

  constructor() {
    this.eventEmitter = new EventEmitter();
  }

  /**
   * Initialize and bind all configured publishers.
   */
  async start(config: ZMQConfig): Promise<void> {
    if (this.started) {
      return;
    }

    // Dynamically import zeromq
    const zmq = await import("zeromq");

    // Group notifiers by address to share sockets
    const addressToTopics = new Map<string, ZMQTopic[]>();
    for (const notifier of config.notifiers) {
      const topics = addressToTopics.get(notifier.address) || [];
      topics.push(notifier.topic);
      addressToTopics.set(notifier.address, topics);
    }

    // Create publishers for each address
    const addressToSocket = new Map<string, Publisher>();

    for (const [address, topics] of addressToTopics) {
      let socket = addressToSocket.get(address);
      if (!socket) {
        socket = new zmq.Publisher();
        await socket.bind(address);
        addressToSocket.set(address, socket);
      }

      for (const topic of topics) {
        this.publishers.set(topic, {
          topic,
          address,
          socket,
          sequence: 0,
        });
      }
    }

    this.started = true;
  }

  /**
   * Stop all publishers and close sockets.
   */
  async stop(): Promise<void> {
    if (!this.started) {
      return;
    }

    // Close unique sockets
    const closedSockets = new Set<Publisher>();
    for (const pub of this.publishers.values()) {
      if (!closedSockets.has(pub.socket)) {
        pub.socket.close();
        closedSockets.add(pub.socket);
      }
    }

    this.publishers.clear();
    this.started = false;
  }

  /**
   * Get the event emitter for subscribing to chain/mempool events.
   */
  getEventEmitter(): EventEmitter {
    return this.eventEmitter;
  }

  /**
   * Check if a topic is enabled.
   */
  isEnabled(topic: ZMQTopic): boolean {
    return this.publishers.has(topic);
  }

  /**
   * Get all configured notifications for getzmqnotifications RPC.
   */
  getNotifications(): Array<{ type: ZMQTopic; address: string; hwm: number }> {
    const result: Array<{ type: ZMQTopic; address: string; hwm: number }> = [];
    for (const pub of this.publishers.values()) {
      result.push({
        type: pub.topic,
        address: pub.address,
        hwm: 1000, // Default high water mark
      });
    }
    return result;
  }

  /**
   * Notify of a new block being connected.
   */
  async notifyBlock(block: Block): Promise<void> {
    const blockHash = getBlockHash(block.header);

    // hashblock: 32-byte block hash
    await this.publish("hashblock", blockHash);

    // rawblock: full serialized block
    await this.publish("rawblock", serializeBlock(block));

    // sequence: block connected (C)
    await this.publishSequence(blockHash, "C");

    // hashtx for each transaction in block
    for (const tx of block.transactions) {
      const txid = getTxId(tx);
      await this.publish("hashtx", txid);
    }
  }

  /**
   * Notify of a block being disconnected (reorg).
   */
  async notifyBlockDisconnect(block: Block): Promise<void> {
    const blockHash = getBlockHash(block.header);
    await this.publishSequence(blockHash, "D");
  }

  /**
   * Notify of a transaction being added to the mempool.
   */
  async notifyTransactionAcceptance(
    tx: Transaction,
    mempoolSequence: bigint
  ): Promise<void> {
    const txid = getTxId(tx);

    // hashtx: 32-byte txid
    await this.publish("hashtx", txid);

    // rawtx: full serialized transaction (with witness)
    await this.publish("rawtx", serializeTx(tx, true));

    // sequence: mempool acceptance (A) with mempool sequence
    await this.publishSequence(txid, "A", mempoolSequence);
  }

  /**
   * Notify of a transaction being removed from the mempool.
   */
  async notifyTransactionRemoval(
    txid: Buffer,
    mempoolSequence: bigint
  ): Promise<void> {
    await this.publishSequence(txid, "R", mempoolSequence);
  }

  /**
   * Publish a message on a topic.
   *
   * Message format: [topic, body, sequence(LE u32)]
   */
  private async publish(topic: ZMQTopic, body: Buffer): Promise<void> {
    const pub = this.publishers.get(topic);
    if (!pub) {
      return;
    }

    // Build sequence number buffer (4 bytes LE)
    const seqBuf = Buffer.alloc(4);
    seqBuf.writeUInt32LE(pub.sequence);

    // Send multipart message: [topic, body, sequence]
    await pub.socket.send([Buffer.from(topic), body, seqBuf]);

    // Increment sequence
    pub.sequence = (pub.sequence + 1) >>> 0; // Keep as u32
  }

  /**
   * Publish a sequence notification.
   *
   * Body format:
   * - For mempool events (A/R): [32-byte hash][1-byte label][8-byte mempool_seq LE]
   * - For block events (C/D): [32-byte hash][1-byte label]
   */
  private async publishSequence(
    hash: Buffer,
    label: SequenceLabel,
    mempoolSequence?: bigint
  ): Promise<void> {
    const pub = this.publishers.get("sequence");
    if (!pub) {
      return;
    }

    // Build body
    let body: Buffer;
    if (mempoolSequence !== undefined) {
      // Mempool event: hash + label + mempool_sequence
      body = Buffer.alloc(41);
      hash.copy(body, 0);
      body.writeUInt8(label.charCodeAt(0), 32);
      body.writeBigUInt64LE(mempoolSequence, 33);
    } else {
      // Block event: hash + label
      body = Buffer.alloc(33);
      hash.copy(body, 0);
      body.writeUInt8(label.charCodeAt(0), 32);
    }

    // Build sequence number buffer (4 bytes LE)
    const seqBuf = Buffer.alloc(4);
    seqBuf.writeUInt32LE(pub.sequence);

    // Send multipart message: [topic, body, sequence]
    await pub.socket.send([Buffer.from("sequence"), body, seqBuf]);

    // Increment sequence
    pub.sequence = (pub.sequence + 1) >>> 0;
  }
}

/**
 * Notification events emitted by chain/mempool components.
 */
export interface NotificationEvents {
  /** Emitted when a block is connected to the chain. */
  blockConnected: (block: Block) => void;
  /** Emitted when a block is disconnected from the chain (reorg). */
  blockDisconnected: (block: Block) => void;
  /** Emitted when a transaction is accepted to the mempool. */
  txAccepted: (tx: Transaction, mempoolSequence: bigint) => void;
  /** Emitted when a transaction is removed from the mempool. */
  txRemoved: (txid: Buffer, mempoolSequence: bigint) => void;
}

/**
 * Create an event emitter for chain/mempool notifications.
 */
export function createNotificationEmitter(): EventEmitter {
  return new EventEmitter();
}

/**
 * Wire the ZMQ notification interface to an event emitter.
 *
 * Sets up event listeners to forward chain/mempool events to ZMQ publishers.
 */
export function wireZMQNotifications(
  zmq: ZMQNotificationInterface,
  emitter: EventEmitter
): void {
  emitter.on("blockConnected", (block: Block) => {
    zmq.notifyBlock(block).catch((err) => {
      console.error("ZMQ notifyBlock error:", err);
    });
  });

  emitter.on("blockDisconnected", (block: Block) => {
    zmq.notifyBlockDisconnect(block).catch((err) => {
      console.error("ZMQ notifyBlockDisconnect error:", err);
    });
  });

  emitter.on(
    "txAccepted",
    (tx: Transaction, mempoolSequence: bigint) => {
      zmq.notifyTransactionAcceptance(tx, mempoolSequence).catch((err) => {
        console.error("ZMQ notifyTransactionAcceptance error:", err);
      });
    }
  );

  emitter.on("txRemoved", (txid: Buffer, mempoolSequence: bigint) => {
    zmq.notifyTransactionRemoval(txid, mempoolSequence).catch((err) => {
      console.error("ZMQ notifyTransactionRemoval error:", err);
    });
  });
}
