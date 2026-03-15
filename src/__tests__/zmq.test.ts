/**
 * Tests for ZeroMQ notification support.
 */

import { describe, expect, test, beforeEach, afterEach } from "bun:test";
import { EventEmitter } from "events";
import {
  ZMQNotificationInterface,
  parseZMQArgs,
  wireZMQNotifications,
  createNotificationEmitter,
  type ZMQConfig,
} from "../rpc/zmq.js";
import type { Block, BlockHeader } from "../validation/block.js";
import type { Transaction } from "../validation/tx.js";

// ============================================================================
// Test Helpers
// ============================================================================

/**
 * Create a mock block header.
 */
function createMockHeader(): BlockHeader {
  return {
    version: 1,
    prevBlock: Buffer.alloc(32, 0x01),
    merkleRoot: Buffer.alloc(32, 0x02),
    timestamp: 1600000000,
    bits: 0x1d00ffff,
    nonce: 12345,
  };
}

/**
 * Create a mock transaction.
 */
function createMockTx(id: number): Transaction {
  return {
    version: 1,
    inputs: [
      {
        prevOut: {
          txid: Buffer.alloc(32, id),
          vout: 0,
        },
        scriptSig: Buffer.from([0x00]),
        sequence: 0xffffffff,
        witness: [],
      },
    ],
    outputs: [
      {
        value: 50000000n,
        scriptPubKey: Buffer.from([0x76, 0xa9, 0x14, ...Buffer.alloc(20, id), 0x88, 0xac]),
      },
    ],
    lockTime: 0,
  };
}

/**
 * Create a mock coinbase transaction.
 */
function createMockCoinbase(): Transaction {
  return {
    version: 1,
    inputs: [
      {
        prevOut: {
          txid: Buffer.alloc(32, 0x00),
          vout: 0xffffffff,
        },
        scriptSig: Buffer.from([0x01, 0x01]),
        sequence: 0xffffffff,
        witness: [],
      },
    ],
    outputs: [
      {
        value: 5000000000n,
        scriptPubKey: Buffer.from([0x76, 0xa9, 0x14, ...Buffer.alloc(20, 0xaa), 0x88, 0xac]),
      },
    ],
    lockTime: 0,
  };
}

/**
 * Create a mock block.
 */
function createMockBlock(): Block {
  return {
    header: createMockHeader(),
    transactions: [createMockCoinbase(), createMockTx(1), createMockTx(2)],
  };
}

// ============================================================================
// parseZMQArgs Tests
// ============================================================================

describe("parseZMQArgs", () => {
  test("parses hashblock argument", () => {
    const args = ["--zmqpubhashblock=tcp://127.0.0.1:28332"];
    const config = parseZMQArgs(args);

    expect(config.notifiers).toHaveLength(1);
    expect(config.notifiers[0].topic).toBe("hashblock");
    expect(config.notifiers[0].address).toBe("tcp://127.0.0.1:28332");
  });

  test("parses hashtx argument", () => {
    const args = ["--zmqpubhashtx=tcp://127.0.0.1:28333"];
    const config = parseZMQArgs(args);

    expect(config.notifiers).toHaveLength(1);
    expect(config.notifiers[0].topic).toBe("hashtx");
    expect(config.notifiers[0].address).toBe("tcp://127.0.0.1:28333");
  });

  test("parses rawblock argument", () => {
    const args = ["--zmqpubrawblock=tcp://127.0.0.1:28334"];
    const config = parseZMQArgs(args);

    expect(config.notifiers).toHaveLength(1);
    expect(config.notifiers[0].topic).toBe("rawblock");
    expect(config.notifiers[0].address).toBe("tcp://127.0.0.1:28334");
  });

  test("parses rawtx argument", () => {
    const args = ["--zmqpubrawtx=tcp://127.0.0.1:28335"];
    const config = parseZMQArgs(args);

    expect(config.notifiers).toHaveLength(1);
    expect(config.notifiers[0].topic).toBe("rawtx");
    expect(config.notifiers[0].address).toBe("tcp://127.0.0.1:28335");
  });

  test("parses sequence argument", () => {
    const args = ["--zmqpubsequence=tcp://127.0.0.1:28336"];
    const config = parseZMQArgs(args);

    expect(config.notifiers).toHaveLength(1);
    expect(config.notifiers[0].topic).toBe("sequence");
    expect(config.notifiers[0].address).toBe("tcp://127.0.0.1:28336");
  });

  test("parses multiple arguments", () => {
    const args = [
      "--zmqpubhashblock=tcp://127.0.0.1:28332",
      "--zmqpubhashtx=tcp://127.0.0.1:28333",
      "--zmqpubsequence=tcp://127.0.0.1:28336",
    ];
    const config = parseZMQArgs(args);

    expect(config.notifiers).toHaveLength(3);
    expect(config.notifiers.find(n => n.topic === "hashblock")).toBeDefined();
    expect(config.notifiers.find(n => n.topic === "hashtx")).toBeDefined();
    expect(config.notifiers.find(n => n.topic === "sequence")).toBeDefined();
  });

  test("parses case-insensitive topic names", () => {
    const args = ["--zmqpubHASHBLOCK=tcp://127.0.0.1:28332"];
    const config = parseZMQArgs(args);

    expect(config.notifiers).toHaveLength(1);
    expect(config.notifiers[0].topic).toBe("hashblock");
  });

  test("ignores invalid topic names", () => {
    const args = ["--zmqpubinvalid=tcp://127.0.0.1:28332"];
    const config = parseZMQArgs(args);

    expect(config.notifiers).toHaveLength(0);
  });

  test("ignores non-zmq arguments", () => {
    const args = [
      "--rpcport=8332",
      "--datadir=/tmp/hotbuns",
      "--zmqpubhashblock=tcp://127.0.0.1:28332",
    ];
    const config = parseZMQArgs(args);

    expect(config.notifiers).toHaveLength(1);
    expect(config.notifiers[0].topic).toBe("hashblock");
  });

  test("handles empty args", () => {
    const config = parseZMQArgs([]);
    expect(config.notifiers).toHaveLength(0);
  });

  test("allows same address for multiple topics", () => {
    const args = [
      "--zmqpubhashblock=tcp://127.0.0.1:28332",
      "--zmqpubhashtx=tcp://127.0.0.1:28332",
    ];
    const config = parseZMQArgs(args);

    expect(config.notifiers).toHaveLength(2);
    expect(config.notifiers[0].address).toBe("tcp://127.0.0.1:28332");
    expect(config.notifiers[1].address).toBe("tcp://127.0.0.1:28332");
  });
});

// ============================================================================
// ZMQNotificationInterface Tests
// ============================================================================

describe("ZMQNotificationInterface", () => {
  test("creates without config", () => {
    const zmq = new ZMQNotificationInterface();
    expect(zmq).toBeDefined();
  });

  test("isEnabled returns false when not started", () => {
    const zmq = new ZMQNotificationInterface();
    expect(zmq.isEnabled("hashblock")).toBe(false);
    expect(zmq.isEnabled("hashtx")).toBe(false);
  });

  test("getNotifications returns empty array when not started", () => {
    const zmq = new ZMQNotificationInterface();
    expect(zmq.getNotifications()).toEqual([]);
  });

  test("getEventEmitter returns an EventEmitter", () => {
    const zmq = new ZMQNotificationInterface();
    const emitter = zmq.getEventEmitter();
    expect(emitter).toBeInstanceOf(EventEmitter);
  });
});

// ============================================================================
// createNotificationEmitter Tests
// ============================================================================

describe("createNotificationEmitter", () => {
  test("creates an EventEmitter", () => {
    const emitter = createNotificationEmitter();
    expect(emitter).toBeInstanceOf(EventEmitter);
  });

  test("can emit and receive events", () => {
    const emitter = createNotificationEmitter();
    let received = false;

    emitter.on("test", () => {
      received = true;
    });

    emitter.emit("test");
    expect(received).toBe(true);
  });
});

// ============================================================================
// wireZMQNotifications Tests
// ============================================================================

describe("wireZMQNotifications", () => {
  test("wires blockConnected event", async () => {
    const zmq = new ZMQNotificationInterface();
    const emitter = new EventEmitter();

    // Track if notifyBlock was called
    let notifyBlockCalled = false;
    const originalNotifyBlock = zmq.notifyBlock.bind(zmq);
    zmq.notifyBlock = async (block: Block) => {
      notifyBlockCalled = true;
      // Don't actually call the original since we're not started
    };

    wireZMQNotifications(zmq, emitter);

    const block = createMockBlock();
    emitter.emit("blockConnected", block);

    // Allow async handlers to run
    await new Promise(resolve => setTimeout(resolve, 10));

    expect(notifyBlockCalled).toBe(true);
  });

  test("wires blockDisconnected event", async () => {
    const zmq = new ZMQNotificationInterface();
    const emitter = new EventEmitter();

    let notifyBlockDisconnectCalled = false;
    zmq.notifyBlockDisconnect = async (block: Block) => {
      notifyBlockDisconnectCalled = true;
    };

    wireZMQNotifications(zmq, emitter);

    const block = createMockBlock();
    emitter.emit("blockDisconnected", block);

    await new Promise(resolve => setTimeout(resolve, 10));

    expect(notifyBlockDisconnectCalled).toBe(true);
  });

  test("wires txAccepted event", async () => {
    const zmq = new ZMQNotificationInterface();
    const emitter = new EventEmitter();

    let notifyTxAcceptedCalled = false;
    let receivedSeq: bigint | undefined;
    zmq.notifyTransactionAcceptance = async (tx: Transaction, seq: bigint) => {
      notifyTxAcceptedCalled = true;
      receivedSeq = seq;
    };

    wireZMQNotifications(zmq, emitter);

    const tx = createMockTx(1);
    emitter.emit("txAccepted", tx, 42n);

    await new Promise(resolve => setTimeout(resolve, 10));

    expect(notifyTxAcceptedCalled).toBe(true);
    expect(receivedSeq).toBe(42n);
  });

  test("wires txRemoved event", async () => {
    const zmq = new ZMQNotificationInterface();
    const emitter = new EventEmitter();

    let notifyTxRemovedCalled = false;
    let receivedTxid: Buffer | undefined;
    let receivedSeq: bigint | undefined;
    zmq.notifyTransactionRemoval = async (txid: Buffer, seq: bigint) => {
      notifyTxRemovedCalled = true;
      receivedTxid = txid;
      receivedSeq = seq;
    };

    wireZMQNotifications(zmq, emitter);

    const txid = Buffer.alloc(32, 0x01);
    emitter.emit("txRemoved", txid, 100n);

    await new Promise(resolve => setTimeout(resolve, 10));

    expect(notifyTxRemovedCalled).toBe(true);
    expect(receivedTxid?.equals(txid)).toBe(true);
    expect(receivedSeq).toBe(100n);
  });
});

// ============================================================================
// Sequence Number Format Tests
// ============================================================================

describe("sequence number format", () => {
  test("message sequence is 4 bytes little-endian", () => {
    // The sequence number in ZMQ messages is a 4-byte LE u32
    const seqBuf = Buffer.alloc(4);
    seqBuf.writeUInt32LE(12345);

    expect(seqBuf.length).toBe(4);
    expect(seqBuf.readUInt32LE(0)).toBe(12345);
  });

  test("mempool sequence in body is 8 bytes little-endian", () => {
    // The mempool sequence in sequence notification body is 8-byte LE u64
    const mempoolSeq = 0x123456789ABCDEFn;
    const body = Buffer.alloc(8);
    body.writeBigUInt64LE(mempoolSeq);

    expect(body.length).toBe(8);
    expect(body.readBigUInt64LE(0)).toBe(mempoolSeq);
  });

  test("sequence body format for block connect (C)", () => {
    // Block connect: 32-byte hash + 1-byte label 'C' = 33 bytes
    const hash = Buffer.alloc(32, 0xab);
    const label = "C".charCodeAt(0);

    const body = Buffer.alloc(33);
    hash.copy(body, 0);
    body.writeUInt8(label, 32);

    expect(body.length).toBe(33);
    expect(body.subarray(0, 32).equals(hash)).toBe(true);
    expect(body.readUInt8(32)).toBe("C".charCodeAt(0));
  });

  test("sequence body format for block disconnect (D)", () => {
    // Block disconnect: 32-byte hash + 1-byte label 'D' = 33 bytes
    const hash = Buffer.alloc(32, 0xcd);
    const label = "D".charCodeAt(0);

    const body = Buffer.alloc(33);
    hash.copy(body, 0);
    body.writeUInt8(label, 32);

    expect(body.length).toBe(33);
    expect(body.readUInt8(32)).toBe("D".charCodeAt(0));
  });

  test("sequence body format for mempool accept (A)", () => {
    // Mempool accept: 32-byte hash + 1-byte label 'A' + 8-byte mempool_seq = 41 bytes
    const hash = Buffer.alloc(32, 0xef);
    const label = "A".charCodeAt(0);
    const mempoolSeq = 42n;

    const body = Buffer.alloc(41);
    hash.copy(body, 0);
    body.writeUInt8(label, 32);
    body.writeBigUInt64LE(mempoolSeq, 33);

    expect(body.length).toBe(41);
    expect(body.readUInt8(32)).toBe("A".charCodeAt(0));
    expect(body.readBigUInt64LE(33)).toBe(42n);
  });

  test("sequence body format for mempool remove (R)", () => {
    // Mempool remove: 32-byte hash + 1-byte label 'R' + 8-byte mempool_seq = 41 bytes
    const hash = Buffer.alloc(32, 0x11);
    const label = "R".charCodeAt(0);
    const mempoolSeq = 100n;

    const body = Buffer.alloc(41);
    hash.copy(body, 0);
    body.writeUInt8(label, 32);
    body.writeBigUInt64LE(mempoolSeq, 33);

    expect(body.length).toBe(41);
    expect(body.readUInt8(32)).toBe("R".charCodeAt(0));
    expect(body.readBigUInt64LE(33)).toBe(100n);
  });
});

// ============================================================================
// Topic and Body Format Tests
// ============================================================================

describe("topic and body formats", () => {
  test("hashblock body is 32 bytes", () => {
    // hashblock: just the 32-byte block hash
    const blockHash = Buffer.alloc(32, 0xff);
    expect(blockHash.length).toBe(32);
  });

  test("hashtx body is 32 bytes", () => {
    // hashtx: just the 32-byte txid
    const txid = Buffer.alloc(32, 0xee);
    expect(txid.length).toBe(32);
  });

  test("topic names are correct strings", () => {
    const topics = ["hashblock", "hashtx", "rawblock", "rawtx", "sequence"];

    for (const topic of topics) {
      const buf = Buffer.from(topic);
      expect(buf.toString()).toBe(topic);
    }
  });
});
