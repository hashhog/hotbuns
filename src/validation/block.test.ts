import { describe, expect, test } from "bun:test";
import { BufferReader } from "../wire/serialization";
import { MAINNET, REGTEST, getGenesisBlock } from "../consensus/params";
import { hash256 } from "../crypto/primitives";
import {
  BlockHeader,
  Block,
  serializeBlockHeader,
  deserializeBlockHeader,
  serializeBlock,
  deserializeBlock,
  getBlockHash,
  computeMerkleRoot,
  computeWitnessMerkleRoot,
  getWitnessCommitment,
  validateBlockHeader,
  validateBlock,
  getBlockWeight,
  getBlockBaseSize,
  getBlockTotalSize,
} from "./block";
import { Transaction, getTxId, serializeTx } from "./tx";

/**
 * Helper to create a valid block header.
 */
function createBlockHeader(): BlockHeader {
  return {
    version: 0x20000000,
    prevBlock: Buffer.alloc(32, 0),
    merkleRoot: Buffer.alloc(32, 0),
    timestamp: Math.floor(Date.now() / 1000),
    bits: REGTEST.powLimitBits,
    nonce: 0,
  };
}

/**
 * Helper to create a coinbase transaction.
 */
function createCoinbaseTx(height: number = 0): Transaction {
  // Encode height in scriptSig (BIP34)
  const heightScript = Buffer.from([0x01, height & 0xff]);

  return {
    version: 1,
    inputs: [
      {
        prevOut: {
          txid: Buffer.alloc(32, 0),
          vout: 0xffffffff,
        },
        scriptSig: heightScript,
        sequence: 0xffffffff,
        witness: [],
      },
    ],
    outputs: [
      {
        value: 5000000000n, // 50 BTC
        scriptPubKey: Buffer.from([0x51]), // OP_TRUE
      },
    ],
    lockTime: 0,
  };
}

/**
 * Helper to create a regular transaction.
 */
function createRegularTx(): Transaction {
  return {
    version: 1,
    inputs: [
      {
        prevOut: {
          txid: Buffer.alloc(32, 1),
          vout: 0,
        },
        scriptSig: Buffer.from([0x00]),
        sequence: 0xffffffff,
        witness: [],
      },
    ],
    outputs: [
      {
        value: 100000000n,
        scriptPubKey: Buffer.from([0x51]),
      },
    ],
    lockTime: 0,
  };
}

/**
 * Helper to create a valid block for testing.
 */
function createTestBlock(): Block {
  const coinbase = createCoinbaseTx(1);
  const txid = getTxId(coinbase);

  return {
    header: {
      version: 0x20000000,
      prevBlock: Buffer.alloc(32, 0),
      merkleRoot: txid, // Single tx = merkle root is txid
      timestamp: Math.floor(Date.now() / 1000),
      bits: REGTEST.powLimitBits,
      nonce: 0,
    },
    transactions: [coinbase],
  };
}

describe("serializeBlockHeader", () => {
  test("produces 80 bytes", () => {
    const header = createBlockHeader();
    const serialized = serializeBlockHeader(header);
    expect(serialized.length).toBe(80);
  });

  test("version is first 4 bytes", () => {
    const header = createBlockHeader();
    header.version = 0x20000002;
    const serialized = serializeBlockHeader(header);
    expect(serialized.readInt32LE(0)).toBe(0x20000002);
  });

  test("prevBlock is bytes 4-35", () => {
    const header = createBlockHeader();
    header.prevBlock = Buffer.alloc(32, 0xab);
    const serialized = serializeBlockHeader(header);
    const prevBlock = serialized.subarray(4, 36);
    expect(prevBlock.equals(header.prevBlock)).toBe(true);
  });

  test("merkleRoot is bytes 36-67", () => {
    const header = createBlockHeader();
    header.merkleRoot = Buffer.alloc(32, 0xcd);
    const serialized = serializeBlockHeader(header);
    const merkleRoot = serialized.subarray(36, 68);
    expect(merkleRoot.equals(header.merkleRoot)).toBe(true);
  });

  test("timestamp is bytes 68-71", () => {
    const header = createBlockHeader();
    header.timestamp = 1234567890;
    const serialized = serializeBlockHeader(header);
    expect(serialized.readUInt32LE(68)).toBe(1234567890);
  });

  test("bits is bytes 72-75", () => {
    const header = createBlockHeader();
    header.bits = 0x1d00ffff;
    const serialized = serializeBlockHeader(header);
    expect(serialized.readUInt32LE(72)).toBe(0x1d00ffff);
  });

  test("nonce is bytes 76-79", () => {
    const header = createBlockHeader();
    header.nonce = 2083236893;
    const serialized = serializeBlockHeader(header);
    expect(serialized.readUInt32LE(76)).toBe(2083236893);
  });
});

describe("deserializeBlockHeader", () => {
  test("round-trip serialization", () => {
    const original: BlockHeader = {
      version: 0x20000002,
      prevBlock: Buffer.alloc(32, 0xab),
      merkleRoot: Buffer.alloc(32, 0xcd),
      timestamp: 1234567890,
      bits: 0x1d00ffff,
      nonce: 2083236893,
    };

    const serialized = serializeBlockHeader(original);
    const reader = new BufferReader(serialized);
    const deserialized = deserializeBlockHeader(reader);

    expect(deserialized.version).toBe(original.version);
    expect(deserialized.prevBlock.equals(original.prevBlock)).toBe(true);
    expect(deserialized.merkleRoot.equals(original.merkleRoot)).toBe(true);
    expect(deserialized.timestamp).toBe(original.timestamp);
    expect(deserialized.bits).toBe(original.bits);
    expect(deserialized.nonce).toBe(original.nonce);
  });

  test("parses mainnet genesis header correctly", () => {
    const genesis = getGenesisBlock(MAINNET);
    const serialized = serializeBlockHeader({
      version: genesis.header.version,
      prevBlock: genesis.header.prevBlockHash,
      merkleRoot: genesis.header.merkleRoot,
      timestamp: genesis.header.timestamp,
      bits: genesis.header.bits,
      nonce: genesis.header.nonce,
    });

    const reader = new BufferReader(serialized);
    const header = deserializeBlockHeader(reader);

    expect(header.version).toBe(1);
    expect(header.timestamp).toBe(1231006505);
    expect(header.bits).toBe(0x1d00ffff);
    expect(header.nonce).toBe(2083236893);
  });
});

describe("serializeBlock and deserializeBlock", () => {
  test("round-trip block serialization", () => {
    const original = createTestBlock();
    const serialized = serializeBlock(original);
    const reader = new BufferReader(serialized);
    const deserialized = deserializeBlock(reader);

    expect(deserialized.header.version).toBe(original.header.version);
    expect(deserialized.transactions.length).toBe(original.transactions.length);
  });

  test("parses mainnet genesis block", () => {
    const reader = new BufferReader(MAINNET.genesisBlock);
    const block = deserializeBlock(reader);

    expect(block.header.version).toBe(1);
    expect(block.transactions.length).toBe(1);
    expect(block.transactions[0].outputs[0].value).toBe(5000000000n);
  });
});

describe("getBlockHash", () => {
  test("mainnet genesis block hash", () => {
    const genesis = getGenesisBlock(MAINNET);
    const header: BlockHeader = {
      version: genesis.header.version,
      prevBlock: genesis.header.prevBlockHash,
      merkleRoot: genesis.header.merkleRoot,
      timestamp: genesis.header.timestamp,
      bits: genesis.header.bits,
      nonce: genesis.header.nonce,
    };

    const blockHash = getBlockHash(header);
    expect(blockHash.equals(MAINNET.genesisBlockHash)).toBe(true);
  });

  test("regtest genesis block hash", () => {
    const genesis = getGenesisBlock(REGTEST);
    const header: BlockHeader = {
      version: genesis.header.version,
      prevBlock: genesis.header.prevBlockHash,
      merkleRoot: genesis.header.merkleRoot,
      timestamp: genesis.header.timestamp,
      bits: genesis.header.bits,
      nonce: genesis.header.nonce,
    };

    const blockHash = getBlockHash(header);
    expect(blockHash.equals(REGTEST.genesisBlockHash)).toBe(true);
  });

  test("different nonces produce different hashes", () => {
    const header1 = createBlockHeader();
    header1.nonce = 1;

    const header2 = { ...header1, nonce: 2 };

    const hash1 = getBlockHash(header1);
    const hash2 = getBlockHash(header2);

    expect(hash1.equals(hash2)).toBe(false);
  });
});

describe("computeMerkleRoot", () => {
  test("empty list returns zeros", () => {
    const root = computeMerkleRoot([]);
    expect(root.equals(Buffer.alloc(32, 0))).toBe(true);
  });

  test("single txid is the merkle root", () => {
    const txid = Buffer.alloc(32, 0xab);
    const root = computeMerkleRoot([txid]);
    expect(root.equals(txid)).toBe(true);
  });

  test("two txids are hashed together", () => {
    const txid1 = Buffer.alloc(32, 0x01);
    const txid2 = Buffer.alloc(32, 0x02);

    const root = computeMerkleRoot([txid1, txid2]);
    const expected = hash256(Buffer.concat([txid1, txid2]));

    expect(root.equals(expected)).toBe(true);
  });

  test("three txids: third is duplicated", () => {
    const txid1 = Buffer.alloc(32, 0x01);
    const txid2 = Buffer.alloc(32, 0x02);
    const txid3 = Buffer.alloc(32, 0x03);

    const root = computeMerkleRoot([txid1, txid2, txid3]);

    // Level 1: hash(1,2), hash(3,3)
    const hash12 = hash256(Buffer.concat([txid1, txid2]));
    const hash33 = hash256(Buffer.concat([txid3, txid3]));

    // Level 0: hash(hash12, hash33)
    const expected = hash256(Buffer.concat([hash12, hash33]));

    expect(root.equals(expected)).toBe(true);
  });

  test("four txids: no duplication needed", () => {
    const txids = [
      Buffer.alloc(32, 0x01),
      Buffer.alloc(32, 0x02),
      Buffer.alloc(32, 0x03),
      Buffer.alloc(32, 0x04),
    ];

    const root = computeMerkleRoot(txids);

    const hash01 = hash256(Buffer.concat([txids[0], txids[1]]));
    const hash23 = hash256(Buffer.concat([txids[2], txids[3]]));
    const expected = hash256(Buffer.concat([hash01, hash23]));

    expect(root.equals(expected)).toBe(true);
  });

  test("mainnet genesis merkle root", () => {
    const genesis = getGenesisBlock(MAINNET);
    const txid = getTxId({
      version: genesis.transactions[0].version,
      inputs: genesis.transactions[0].inputs.map((inp) => ({
        prevOut: { txid: inp.prevTxHash, vout: inp.prevTxIndex },
        scriptSig: inp.scriptSig,
        sequence: inp.sequence,
        witness: [],
      })),
      outputs: genesis.transactions[0].outputs.map((out) => ({
        value: out.value,
        scriptPubKey: out.scriptPubKey,
      })),
      lockTime: genesis.transactions[0].lockTime,
    });

    const root = computeMerkleRoot([txid]);
    expect(root.equals(genesis.header.merkleRoot)).toBe(true);
  });
});

describe("computeWitnessMerkleRoot", () => {
  test("replaces first wtxid with zeros", () => {
    const wtxid1 = Buffer.alloc(32, 0x01);
    const wtxid2 = Buffer.alloc(32, 0x02);

    const root = computeWitnessMerkleRoot([wtxid1, wtxid2]);

    // First wtxid should be replaced with zeros
    const zeros = Buffer.alloc(32, 0);
    const expected = hash256(Buffer.concat([zeros, wtxid2]));

    expect(root.equals(expected)).toBe(true);
  });

  test("single wtxid becomes zeros", () => {
    const wtxid = Buffer.alloc(32, 0xab);
    const root = computeWitnessMerkleRoot([wtxid]);

    expect(root.equals(Buffer.alloc(32, 0))).toBe(true);
  });
});

describe("getWitnessCommitment", () => {
  test("returns null for block without commitment", () => {
    const block = createTestBlock();
    const commitment = getWitnessCommitment(block);
    expect(commitment).toBeNull();
  });

  test("extracts commitment from coinbase output", () => {
    const block = createTestBlock();

    // Add witness commitment output
    const commitmentHash = Buffer.alloc(32, 0xab);
    const commitmentScript = Buffer.concat([
      Buffer.from([0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed]), // OP_RETURN + header
      commitmentHash,
    ]);

    block.transactions[0].outputs.push({
      value: 0n,
      scriptPubKey: commitmentScript,
    });

    const commitment = getWitnessCommitment(block);
    expect(commitment).not.toBeNull();
    expect(commitment!.equals(commitmentHash)).toBe(true);
  });

  test("uses last commitment if multiple exist", () => {
    const block = createTestBlock();

    // Add two commitments
    const commitment1 = Buffer.alloc(32, 0x01);
    const commitment2 = Buffer.alloc(32, 0x02);

    block.transactions[0].outputs.push({
      value: 0n,
      scriptPubKey: Buffer.concat([
        Buffer.from([0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed]),
        commitment1,
      ]),
    });

    block.transactions[0].outputs.push({
      value: 0n,
      scriptPubKey: Buffer.concat([
        Buffer.from([0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed]),
        commitment2,
      ]),
    });

    const commitment = getWitnessCommitment(block);
    expect(commitment!.equals(commitment2)).toBe(true);
  });

  test("returns null if script too short", () => {
    const block = createTestBlock();
    block.transactions[0].outputs.push({
      value: 0n,
      scriptPubKey: Buffer.from([0x6a, 0x24, 0xaa, 0x21, 0xa9]), // Only 5 bytes of header
    });

    const commitment = getWitnessCommitment(block);
    expect(commitment).toBeNull();
  });
});

describe("validateBlockHeader", () => {
  test("valid regtest genesis header passes", () => {
    const genesis = getGenesisBlock(REGTEST);
    const header: BlockHeader = {
      version: genesis.header.version,
      prevBlock: genesis.header.prevBlockHash,
      merkleRoot: genesis.header.merkleRoot,
      timestamp: genesis.header.timestamp,
      bits: genesis.header.bits,
      nonce: genesis.header.nonce,
    };

    const result = validateBlockHeader(header, null, REGTEST);
    expect(result.valid).toBe(true);
  });

  test("fails if hash > target", () => {
    // Create a header with impossible difficulty
    const header = createBlockHeader();
    header.bits = 0x03000001; // Very low target

    const result = validateBlockHeader(header, null, REGTEST);
    expect(result.valid).toBe(false);
    expect(result.error).toContain("Proof of work");
  });

  test("fails if timestamp too far in future", () => {
    // Use a known valid genesis header but modify its timestamp
    const genesis = getGenesisBlock(REGTEST);
    const header: BlockHeader = {
      version: genesis.header.version,
      prevBlock: genesis.header.prevBlockHash,
      merkleRoot: genesis.header.merkleRoot,
      timestamp: Math.floor(Date.now() / 1000) + 3 * 60 * 60, // 3 hours in future
      bits: genesis.header.bits,
      nonce: genesis.header.nonce,
    };

    const result = validateBlockHeader(header, null, REGTEST);
    expect(result.valid).toBe(false);
    expect(result.error).toContain("future");
  });

  test("fails if target exceeds powLimit", () => {
    // Use regtest genesis header (which passes regtest PoW) but validate against mainnet
    // The regtest powLimit is higher than mainnet powLimit
    const genesis = getGenesisBlock(REGTEST);
    const header: BlockHeader = {
      version: genesis.header.version,
      prevBlock: genesis.header.prevBlockHash,
      merkleRoot: genesis.header.merkleRoot,
      timestamp: genesis.header.timestamp,
      bits: genesis.header.bits, // REGTEST.powLimitBits = 0x207fffff
      nonce: genesis.header.nonce,
    };

    // This header satisfies regtest PoW but its target exceeds mainnet powLimit
    const result = validateBlockHeader(header, null, MAINNET);
    expect(result.valid).toBe(false);
    expect(result.error).toContain("powLimit");
  });

  test("validates prevBlock connection", () => {
    const genesis = getGenesisBlock(REGTEST);
    const genesisHeader: BlockHeader = {
      version: genesis.header.version,
      prevBlock: genesis.header.prevBlockHash,
      merkleRoot: genesis.header.merkleRoot,
      timestamp: genesis.header.timestamp,
      bits: genesis.header.bits,
      nonce: genesis.header.nonce,
    };

    // Use the genesis header itself but check it against itself as "prev"
    // Since genesis.prevBlock is all zeros, it won't match genesisHeader's hash
    // But we need a header that passes PoW first, so let's just use genesis
    // and validate it against itself (impossible chain link)
    const result = validateBlockHeader(genesisHeader, genesisHeader, REGTEST);
    expect(result.valid).toBe(false);
    expect(result.error).toContain("prevBlock");
  });
});

describe("validateBlock", () => {
  test("valid block passes", () => {
    const block = createTestBlock();

    // Recalculate merkle root
    const txid = getTxId(block.transactions[0]);
    block.header.merkleRoot = txid;

    const result = validateBlock(block, 1, REGTEST);
    expect(result.valid).toBe(true);
  });

  test("fails for empty block", () => {
    const block = createTestBlock();
    block.transactions = [];

    const result = validateBlock(block, 1, REGTEST);
    expect(result.valid).toBe(false);
    expect(result.error).toContain("no transactions");
  });

  test("fails if first tx is not coinbase", () => {
    const block = createTestBlock();
    block.transactions = [createRegularTx()]; // Not a coinbase

    const result = validateBlock(block, 1, REGTEST);
    expect(result.valid).toBe(false);
    expect(result.error).toContain("not coinbase");
  });

  test("fails if non-first tx is coinbase", () => {
    const block = createTestBlock();
    const secondCoinbase = createCoinbaseTx(2);
    block.transactions.push(secondCoinbase);

    // Update merkle root
    const txids = block.transactions.map((tx) => getTxId(tx));
    block.header.merkleRoot = computeMerkleRoot(txids);

    const result = validateBlock(block, 1, REGTEST);
    expect(result.valid).toBe(false);
    expect(result.error).toContain("coinbase but should not");
  });

  test("fails if merkle root mismatch", () => {
    const block = createTestBlock();
    block.header.merkleRoot = Buffer.alloc(32, 0xff); // Wrong merkle root

    const result = validateBlock(block, 1, REGTEST);
    expect(result.valid).toBe(false);
    expect(result.error).toContain("Merkle root");
  });

  test("block with multiple transactions validates merkle root", () => {
    const coinbase = createCoinbaseTx(1);
    const regularTx = createRegularTx();

    const txids = [getTxId(coinbase), getTxId(regularTx)];
    const merkleRoot = computeMerkleRoot(txids);

    const block: Block = {
      header: {
        version: 0x20000000,
        prevBlock: Buffer.alloc(32, 0),
        merkleRoot,
        timestamp: Math.floor(Date.now() / 1000),
        bits: REGTEST.powLimitBits,
        nonce: 0,
      },
      transactions: [coinbase, regularTx],
    };

    const result = validateBlock(block, 1, REGTEST);
    expect(result.valid).toBe(true);
  });
});

describe("block weight", () => {
  test("legacy block weight is 4x size", () => {
    const block = createTestBlock();
    const baseSize = getBlockBaseSize(block);
    const totalSize = getBlockTotalSize(block);
    const weight = getBlockWeight(block);

    // No witness data, so base == total
    expect(baseSize).toBe(totalSize);

    // weight = base * 3 + total = base * 4
    expect(weight).toBe(baseSize * 4);
  });

  test("segwit block has discounted witness", () => {
    const coinbase = createCoinbaseTx(1);
    // Add witness data
    coinbase.inputs[0].witness = [Buffer.alloc(32, 0)]; // 32-byte witness nonce

    const txid = getTxId(coinbase);
    const block: Block = {
      header: {
        version: 0x20000000,
        prevBlock: Buffer.alloc(32, 0),
        merkleRoot: txid,
        timestamp: Math.floor(Date.now() / 1000),
        bits: REGTEST.powLimitBits,
        nonce: 0,
      },
      transactions: [coinbase],
    };

    const baseSize = getBlockBaseSize(block);
    const totalSize = getBlockTotalSize(block);
    const weight = getBlockWeight(block);

    // With witness, total > base
    expect(totalSize).toBeGreaterThan(baseSize);

    // weight = base * 3 + total
    expect(weight).toBe(baseSize * 3 + totalSize);

    // Weight is less than 4x total (witness discount)
    expect(weight).toBeLessThan(totalSize * 4);
  });

  test("block size calculations match serialized sizes", () => {
    const block = createTestBlock();

    const serializedTotal = serializeBlock(block).length;
    const totalSize = getBlockTotalSize(block);

    expect(totalSize).toBe(serializedTotal);
  });
});

describe("genesis block validation", () => {
  test("regtest genesis passes full validation", () => {
    const reader = new BufferReader(REGTEST.genesisBlock);
    const block = deserializeBlock(reader);

    // Convert to our Block type
    const validationBlock: Block = {
      header: {
        version: block.header.version,
        prevBlock: block.header.prevBlock,
        merkleRoot: block.header.merkleRoot,
        timestamp: block.header.timestamp,
        bits: block.header.bits,
        nonce: block.header.nonce,
      },
      transactions: block.transactions,
    };

    const result = validateBlock(validationBlock, 0, REGTEST);
    expect(result.valid).toBe(true);
  });
});
