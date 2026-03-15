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
  // Sigop counting
  MAX_BLOCK_SIGOPS_COST,
  WITNESS_SCALE_FACTOR,
  MAX_PUBKEYS_PER_MULTISIG,
  countScriptSigOps,
  getLegacySigOpCount,
  getP2SHSigOpCount,
  countWitnessProgramSigOps,
  parseWitnessProgram,
  countInputWitnessSigOps,
  getTransactionSigOpCost,
  getBlockSigOpsCost,
  validateBlockSigOps,
} from "./block";
import { Transaction, getTxId, serializeTx } from "./tx";
import { Opcode } from "../script/interpreter";

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

// =============================================================================
// Sigop Counting Tests
// =============================================================================

describe("sigop constants", () => {
  test("MAX_BLOCK_SIGOPS_COST is 80000", () => {
    expect(MAX_BLOCK_SIGOPS_COST).toBe(80_000);
  });

  test("WITNESS_SCALE_FACTOR is 4", () => {
    expect(WITNESS_SCALE_FACTOR).toBe(4);
  });

  test("MAX_PUBKEYS_PER_MULTISIG is 20", () => {
    expect(MAX_PUBKEYS_PER_MULTISIG).toBe(20);
  });
});

describe("countScriptSigOps", () => {
  test("empty script has 0 sigops", () => {
    expect(countScriptSigOps(Buffer.alloc(0), false)).toBe(0);
  });

  test("OP_CHECKSIG counts as 1 sigop", () => {
    const script = Buffer.from([Opcode.OP_CHECKSIG]);
    expect(countScriptSigOps(script, false)).toBe(1);
  });

  test("OP_CHECKSIGVERIFY counts as 1 sigop", () => {
    const script = Buffer.from([Opcode.OP_CHECKSIGVERIFY]);
    expect(countScriptSigOps(script, false)).toBe(1);
  });

  test("multiple OP_CHECKSIG opcodes", () => {
    const script = Buffer.from([
      Opcode.OP_CHECKSIG,
      Opcode.OP_CHECKSIG,
      Opcode.OP_CHECKSIG,
    ]);
    expect(countScriptSigOps(script, false)).toBe(3);
  });

  test("OP_CHECKMULTISIG counts as 20 sigops in inaccurate mode", () => {
    const script = Buffer.from([Opcode.OP_CHECKMULTISIG]);
    expect(countScriptSigOps(script, false)).toBe(20);
  });

  test("OP_CHECKMULTISIGVERIFY counts as 20 sigops in inaccurate mode", () => {
    const script = Buffer.from([Opcode.OP_CHECKMULTISIGVERIFY]);
    expect(countScriptSigOps(script, false)).toBe(20);
  });

  test("OP_N OP_CHECKMULTISIG uses N sigops in accurate mode", () => {
    // OP_3 OP_CHECKMULTISIG should count as 3 sigops
    const script = Buffer.from([Opcode.OP_3, Opcode.OP_CHECKMULTISIG]);
    expect(countScriptSigOps(script, true)).toBe(3);
  });

  test("OP_16 OP_CHECKMULTISIG uses 16 sigops in accurate mode", () => {
    const script = Buffer.from([Opcode.OP_16, Opcode.OP_CHECKMULTISIG]);
    expect(countScriptSigOps(script, true)).toBe(16);
  });

  test("OP_1 OP_CHECKMULTISIG uses 1 sigop in accurate mode", () => {
    const script = Buffer.from([Opcode.OP_1, Opcode.OP_CHECKMULTISIG]);
    expect(countScriptSigOps(script, true)).toBe(1);
  });

  test("OP_CHECKMULTISIG without preceding OP_N uses 20 in accurate mode", () => {
    // Just OP_CHECKMULTISIG without a preceding OP_N
    const script = Buffer.from([Opcode.OP_DUP, Opcode.OP_CHECKMULTISIG]);
    expect(countScriptSigOps(script, true)).toBe(20);
  });

  test("P2PKH script has 1 sigop", () => {
    // OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
    const pubkeyHash = Buffer.alloc(20, 0xab);
    const script = Buffer.concat([
      Buffer.from([Opcode.OP_DUP, Opcode.OP_HASH160, 20]),
      pubkeyHash,
      Buffer.from([Opcode.OP_EQUALVERIFY, Opcode.OP_CHECKSIG]),
    ]);
    expect(countScriptSigOps(script, false)).toBe(1);
  });

  test("2-of-3 multisig script", () => {
    // OP_2 <pubkey1> <pubkey2> <pubkey3> OP_3 OP_CHECKMULTISIG
    const pubkey = Buffer.alloc(33, 0x02);
    const script = Buffer.concat([
      Buffer.from([Opcode.OP_2]),
      Buffer.from([33]), pubkey,
      Buffer.from([33]), pubkey,
      Buffer.from([33]), pubkey,
      Buffer.from([Opcode.OP_3, Opcode.OP_CHECKMULTISIG]),
    ]);
    // In accurate mode, OP_3 before OP_CHECKMULTISIG = 3 sigops
    expect(countScriptSigOps(script, true)).toBe(3);
    // In inaccurate mode = 20 sigops
    expect(countScriptSigOps(script, false)).toBe(20);
  });

  test("skips push data correctly", () => {
    // Push 32 bytes of 0xac (OP_CHECKSIG) - should NOT count as sigop
    const script = Buffer.concat([
      Buffer.from([32]), // push 32 bytes
      Buffer.alloc(32, Opcode.OP_CHECKSIG), // 32 bytes that look like OP_CHECKSIG
      Buffer.from([Opcode.OP_CHECKSIG]), // actual OP_CHECKSIG
    ]);
    expect(countScriptSigOps(script, false)).toBe(1);
  });
});

describe("getLegacySigOpCount", () => {
  test("coinbase transaction with OP_CHECKSIG output", () => {
    const coinbase = createCoinbaseTx(1);
    // Genesis-style output with OP_CHECKSIG
    coinbase.outputs[0].scriptPubKey = Buffer.concat([
      Buffer.from([65]), // push 65 bytes
      Buffer.alloc(65, 0x04), // fake uncompressed pubkey
      Buffer.from([Opcode.OP_CHECKSIG]),
    ]);

    expect(getLegacySigOpCount(coinbase)).toBe(1);
  });

  test("transaction with P2PKH output", () => {
    const tx = createRegularTx();
    // P2PKH output: OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG
    tx.outputs[0].scriptPubKey = Buffer.concat([
      Buffer.from([Opcode.OP_DUP, Opcode.OP_HASH160, 20]),
      Buffer.alloc(20, 0x00),
      Buffer.from([Opcode.OP_EQUALVERIFY, Opcode.OP_CHECKSIG]),
    ]);

    expect(getLegacySigOpCount(tx)).toBe(1);
  });

  test("counts sigops from both inputs and outputs", () => {
    const tx = createRegularTx();
    // Input with OP_CHECKSIG in scriptSig (unusual but valid)
    tx.inputs[0].scriptSig = Buffer.from([Opcode.OP_CHECKSIG]);
    // Output with OP_CHECKSIG
    tx.outputs[0].scriptPubKey = Buffer.from([Opcode.OP_CHECKSIG]);

    expect(getLegacySigOpCount(tx)).toBe(2);
  });
});

describe("parseWitnessProgram", () => {
  test("P2WPKH: OP_0 <20 bytes>", () => {
    const script = Buffer.concat([
      Buffer.from([0x00, 20]),
      Buffer.alloc(20, 0xab),
    ]);
    const result = parseWitnessProgram(script);
    expect(result).not.toBeNull();
    expect(result![0]).toBe(0); // version 0
    expect(result![1].length).toBe(20);
  });

  test("P2WSH: OP_0 <32 bytes>", () => {
    const script = Buffer.concat([
      Buffer.from([0x00, 32]),
      Buffer.alloc(32, 0xcd),
    ]);
    const result = parseWitnessProgram(script);
    expect(result).not.toBeNull();
    expect(result![0]).toBe(0);
    expect(result![1].length).toBe(32);
  });

  test("P2TR: OP_1 <32 bytes>", () => {
    const script = Buffer.concat([
      Buffer.from([0x51, 32]), // OP_1
      Buffer.alloc(32, 0xef),
    ]);
    const result = parseWitnessProgram(script);
    expect(result).not.toBeNull();
    expect(result![0]).toBe(1); // version 1
    expect(result![1].length).toBe(32);
  });

  test("non-witness program returns null", () => {
    // P2PKH is not a witness program
    const script = Buffer.concat([
      Buffer.from([Opcode.OP_DUP, Opcode.OP_HASH160, 20]),
      Buffer.alloc(20, 0x00),
      Buffer.from([Opcode.OP_EQUALVERIFY, Opcode.OP_CHECKSIG]),
    ]);
    expect(parseWitnessProgram(script)).toBeNull();
  });

  test("too short script returns null", () => {
    const script = Buffer.from([0x00, 1, 0xab]); // 1-byte program (too short)
    expect(parseWitnessProgram(script)).toBeNull();
  });

  test("too long script returns null", () => {
    const script = Buffer.concat([
      Buffer.from([0x00, 41]),
      Buffer.alloc(41, 0x00), // 41-byte program (too long)
    ]);
    expect(parseWitnessProgram(script)).toBeNull();
  });
});

describe("countWitnessProgramSigOps", () => {
  test("P2WPKH returns 1 sigop", () => {
    const program = Buffer.alloc(20, 0xab);
    const witness = [Buffer.alloc(72), Buffer.alloc(33)]; // sig + pubkey
    expect(countWitnessProgramSigOps(0, program, witness)).toBe(1);
  });

  test("P2WSH with OP_CHECKSIG returns 1 sigop", () => {
    const program = Buffer.alloc(32, 0xcd);
    const witnessScript = Buffer.from([Opcode.OP_CHECKSIG]);
    const witness = [Buffer.alloc(72), witnessScript];
    expect(countWitnessProgramSigOps(0, program, witness)).toBe(1);
  });

  test("P2WSH with 2-of-3 multisig", () => {
    const program = Buffer.alloc(32, 0xcd);
    const pubkey = Buffer.alloc(33, 0x02);
    const witnessScript = Buffer.concat([
      Buffer.from([Opcode.OP_2]),
      Buffer.from([33]), pubkey,
      Buffer.from([33]), pubkey,
      Buffer.from([33]), pubkey,
      Buffer.from([Opcode.OP_3, Opcode.OP_CHECKMULTISIG]),
    ]);
    const witness = [Buffer.alloc(0), Buffer.alloc(72), Buffer.alloc(72), witnessScript];
    // Accurate mode: OP_3 before CHECKMULTISIG = 3 sigops
    expect(countWitnessProgramSigOps(0, program, witness)).toBe(3);
  });

  test("witness version 1 (taproot) returns 0 sigops", () => {
    const program = Buffer.alloc(32, 0xef);
    const witness = [Buffer.alloc(64)]; // schnorr sig
    expect(countWitnessProgramSigOps(1, program, witness)).toBe(0);
  });

  test("empty witness returns 0 for P2WSH", () => {
    const program = Buffer.alloc(32, 0xcd);
    expect(countWitnessProgramSigOps(0, program, [])).toBe(0);
  });
});

describe("getTransactionSigOpCost", () => {
  test("legacy transaction sigops are scaled by 4", () => {
    const tx = createRegularTx();
    // Output with OP_CHECKSIG
    tx.outputs[0].scriptPubKey = Buffer.from([Opcode.OP_CHECKSIG]);
    const prevOutputs = [Buffer.from([Opcode.OP_TRUE])];

    const cost = getTransactionSigOpCost(tx, prevOutputs, false, false);
    expect(cost).toBe(1 * WITNESS_SCALE_FACTOR); // 4
  });

  test("coinbase sigops are scaled by 4", () => {
    const coinbase = createCoinbaseTx(1);
    coinbase.outputs[0].scriptPubKey = Buffer.concat([
      Buffer.from([65]),
      Buffer.alloc(65, 0x04),
      Buffer.from([Opcode.OP_CHECKSIG]),
    ]);

    const cost = getTransactionSigOpCost(coinbase, [], true, true);
    expect(cost).toBe(1 * WITNESS_SCALE_FACTOR); // 4
  });

  test("P2WPKH input has cost of 1", () => {
    const tx = createRegularTx();
    tx.inputs[0].scriptSig = Buffer.alloc(0);
    tx.inputs[0].witness = [Buffer.alloc(72), Buffer.alloc(33)];

    // P2WPKH prevOutput
    const prevOutputs = [Buffer.concat([
      Buffer.from([0x00, 20]),
      Buffer.alloc(20, 0xab),
    ])];

    const cost = getTransactionSigOpCost(tx, prevOutputs, true, true);
    // P2WPKH = 1 sigop (not scaled)
    expect(cost).toBe(1);
  });

  test("P2WSH with CHECKSIG has cost of 1", () => {
    const tx = createRegularTx();
    tx.inputs[0].scriptSig = Buffer.alloc(0);
    const witnessScript = Buffer.from([Opcode.OP_CHECKSIG]);
    tx.inputs[0].witness = [Buffer.alloc(72), witnessScript];

    // P2WSH prevOutput
    const prevOutputs = [Buffer.concat([
      Buffer.from([0x00, 32]),
      Buffer.alloc(32, 0xcd),
    ])];

    const cost = getTransactionSigOpCost(tx, prevOutputs, true, true);
    // P2WSH OP_CHECKSIG = 1 sigop (not scaled)
    expect(cost).toBe(1);
  });

  test("P2SH-P2WPKH has cost of 1", () => {
    const tx = createRegularTx();
    // P2SH-P2WPKH: scriptSig contains the P2WPKH script
    const p2wpkhScript = Buffer.concat([
      Buffer.from([0x00, 20]),
      Buffer.alloc(20, 0xab),
    ]);
    tx.inputs[0].scriptSig = Buffer.concat([
      Buffer.from([p2wpkhScript.length]),
      p2wpkhScript,
    ]);
    tx.inputs[0].witness = [Buffer.alloc(72), Buffer.alloc(33)];

    // P2SH prevOutput
    const prevOutputs = [Buffer.concat([
      Buffer.from([Opcode.OP_HASH160, 20]),
      Buffer.alloc(20, 0x00),
      Buffer.from([Opcode.OP_EQUAL]),
    ])];

    const cost = getTransactionSigOpCost(tx, prevOutputs, true, true);
    // P2SH-P2WPKH = 1 witness sigop (not scaled)
    expect(cost).toBe(1);
  });

  test("P2SH with bare multisig redeem script", () => {
    const tx = createRegularTx();
    // Build a 2-of-3 multisig redeem script
    const pubkey = Buffer.alloc(33, 0x02);
    const redeemScript = Buffer.concat([
      Buffer.from([Opcode.OP_2]),
      Buffer.from([33]), pubkey,
      Buffer.from([33]), pubkey,
      Buffer.from([33]), pubkey,
      Buffer.from([Opcode.OP_3, Opcode.OP_CHECKMULTISIG]),
    ]);
    // Push the redeem script in scriptSig (using OP_PUSHDATA1 for > 75 bytes)
    const pushRedeemScript = Buffer.concat([
      Buffer.from([Opcode.OP_PUSHDATA1, redeemScript.length]),
      redeemScript,
    ]);
    tx.inputs[0].scriptSig = Buffer.concat([
      Buffer.from([0x00]), // dummy for CHECKMULTISIG
      Buffer.from([72]), Buffer.alloc(72), // sig1
      Buffer.from([72]), Buffer.alloc(72), // sig2
      pushRedeemScript,
    ]);

    // P2SH prevOutput
    const prevOutputs = [Buffer.concat([
      Buffer.from([Opcode.OP_HASH160, 20]),
      Buffer.alloc(20, 0x00),
      Buffer.from([Opcode.OP_EQUAL]),
    ])];

    const cost = getTransactionSigOpCost(tx, prevOutputs, true, false);
    // P2SH with 3 pubkeys = 3 sigops * 4 = 12
    expect(cost).toBe(3 * WITNESS_SCALE_FACTOR);
  });
});

describe("validateBlockSigOps", () => {
  test("block within limit passes", () => {
    const block = createTestBlock();
    const prevOutputsMap = new Map<number, Buffer[]>();
    prevOutputsMap.set(0, []); // coinbase has no inputs

    const result = validateBlockSigOps(block, prevOutputsMap, true, true);
    expect(result.valid).toBe(true);
  });

  test("block exceeding limit fails", () => {
    // Create a block that would exceed sigop limit
    // Each OP_CHECKMULTISIG without OP_N = 20 sigops * 4 = 80 cost
    // Need 1001 such operations to exceed 80000
    const block = createTestBlock();
    // Add many outputs with OP_CHECKMULTISIG
    const output = { value: 0n, scriptPubKey: Buffer.from([Opcode.OP_CHECKMULTISIG]) };
    // 1001 outputs * 20 sigops * 4 = 80080 > 80000
    for (let i = 0; i < 1001; i++) {
      block.transactions[0].outputs.push(output);
    }

    const prevOutputsMap = new Map<number, Buffer[]>();
    prevOutputsMap.set(0, []);

    const result = validateBlockSigOps(block, prevOutputsMap, true, true);
    expect(result.valid).toBe(false);
    expect(result.error).toContain("exceeds maximum");
    expect(result.cost).toBeGreaterThan(MAX_BLOCK_SIGOPS_COST);
  });
});

describe("block_weight sigop integration", () => {
  test("witness discount applies to sigop counting", () => {
    // Create two transactions with same sigop pattern
    // One legacy, one segwit - segwit should have lower cost

    // Legacy P2PKH spend
    const legacyTx = createRegularTx();
    legacyTx.outputs[0].scriptPubKey = Buffer.concat([
      Buffer.from([Opcode.OP_DUP, Opcode.OP_HASH160, 20]),
      Buffer.alloc(20, 0x00),
      Buffer.from([Opcode.OP_EQUALVERIFY, Opcode.OP_CHECKSIG]),
    ]);
    const legacyPrevOutputs = [Buffer.from([Opcode.OP_TRUE])];
    const legacyCost = getTransactionSigOpCost(legacyTx, legacyPrevOutputs, true, true);
    // 1 legacy sigop * 4 = 4
    expect(legacyCost).toBe(4);

    // SegWit P2WPKH spend
    const segwitTx = createRegularTx();
    segwitTx.inputs[0].scriptSig = Buffer.alloc(0);
    segwitTx.inputs[0].witness = [Buffer.alloc(72), Buffer.alloc(33)];
    segwitTx.outputs[0].scriptPubKey = Buffer.concat([
      Buffer.from([0x00, 20]),
      Buffer.alloc(20, 0x00),
    ]);
    const segwitPrevOutputs = [Buffer.concat([
      Buffer.from([0x00, 20]),
      Buffer.alloc(20, 0xab),
    ])];
    const segwitCost = getTransactionSigOpCost(segwitTx, segwitPrevOutputs, true, true);
    // P2WPKH = 1 witness sigop (not scaled)
    expect(segwitCost).toBe(1);

    // Verify witness discount: same effective sigops, lower cost
    expect(segwitCost).toBeLessThan(legacyCost);
  });
});
