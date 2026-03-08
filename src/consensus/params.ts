/**
 * Bitcoin consensus parameters for mainnet, testnet, and regtest.
 *
 * Defines all constants governing block validation, difficulty adjustment,
 * reward schedule, and network-specific configurations.
 */

import { BufferWriter, BufferReader } from "../wire/serialization";
import { hash256 } from "../crypto/primitives";

/**
 * Network-specific consensus parameters.
 * All values are readonly to prevent accidental mutation.
 */
export interface ConsensusParams {
  readonly networkMagic: number;
  readonly defaultPort: number;
  readonly genesisBlockHash: Buffer;
  readonly genesisBlock: Buffer; // raw serialized genesis block
  readonly subsidyHalvingInterval: number;
  readonly maxCoins: bigint; // 21_000_000 * 100_000_000 satoshis
  readonly maxBlockWeight: number;
  readonly maxBlockSigOpsCost: number;
  readonly maxBlockSize: number; // legacy (pre-segwit) limit
  readonly coinbaseMaturity: number;
  readonly targetTimespan: number; // seconds
  readonly targetSpacing: number; // seconds
  readonly difficultyAdjustmentInterval: number;
  readonly powLimit: bigint;
  readonly powLimitBits: number;
  readonly bip34Height: number;
  readonly bip65Height: number;
  readonly bip66Height: number;
  readonly segwitHeight: number;
  readonly taprootHeight: number;
  readonly protocolVersion: number;
  readonly services: bigint;
  readonly userAgent: string;
  readonly dnsSeed: string[];
  readonly checkpoints: Map<number, Buffer>;
}

/**
 * Minimal block structure for genesis block parsing.
 */
export interface Block {
  readonly header: BlockHeader;
  readonly transactions: Transaction[];
}

export interface BlockHeader {
  readonly version: number;
  readonly prevBlockHash: Buffer;
  readonly merkleRoot: Buffer;
  readonly timestamp: number;
  readonly bits: number;
  readonly nonce: number;
}

export interface Transaction {
  readonly version: number;
  readonly inputs: TxInput[];
  readonly outputs: TxOutput[];
  readonly lockTime: number;
}

export interface TxInput {
  readonly prevTxHash: Buffer;
  readonly prevTxIndex: number;
  readonly scriptSig: Buffer;
  readonly sequence: number;
}

export interface TxOutput {
  readonly value: bigint;
  readonly scriptPubKey: Buffer;
}

/**
 * Build the mainnet genesis block raw bytes.
 * Satoshi's original block from January 3, 2009.
 */
function buildMainnetGenesisBlock(): Buffer {
  const writer = new BufferWriter();

  // Block header
  writer.writeInt32LE(1); // version
  writer.writeHash(Buffer.alloc(32, 0)); // prevBlockHash (all zeros)
  writer.writeHash(
    Buffer.from(
      "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a",
      "hex"
    )
  ); // merkleRoot (already in little-endian wire format)
  writer.writeUInt32LE(1231006505); // timestamp: 2009-01-03 18:15:05 UTC
  writer.writeUInt32LE(0x1d00ffff); // bits
  writer.writeUInt32LE(2083236893); // nonce

  // Transaction count
  writer.writeVarInt(1);

  // Coinbase transaction
  writer.writeInt32LE(1); // version

  // Input count
  writer.writeVarInt(1);

  // Coinbase input
  writer.writeHash(Buffer.alloc(32, 0)); // prevTxHash (null)
  writer.writeUInt32LE(0xffffffff); // prevTxIndex

  // Coinbase scriptSig containing the famous Times headline
  const coinbaseScript = Buffer.concat([
    Buffer.from([0x04, 0xff, 0xff, 0x00, 0x1d]), // push 4 bytes, then bits
    Buffer.from([0x01, 0x04]), // push 1 byte: 4
    Buffer.from([0x45]), // push 69 bytes (length of headline)
    Buffer.from(
      "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks"
    ),
  ]);
  writer.writeVarBytes(coinbaseScript);
  writer.writeUInt32LE(0xffffffff); // sequence

  // Output count
  writer.writeVarInt(1);

  // Output: 50 BTC to Satoshi's public key
  writer.writeUInt64LE(50_00000000n); // 50 BTC in satoshis

  // scriptPubKey: OP_PUSHBYTES_65 <pubkey> OP_CHECKSIG
  const satoshiPubKey = Buffer.from(
    "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f",
    "hex"
  );
  const scriptPubKey = Buffer.concat([
    Buffer.from([0x41]), // OP_PUSHBYTES_65
    satoshiPubKey,
    Buffer.from([0xac]), // OP_CHECKSIG
  ]);
  writer.writeVarBytes(scriptPubKey);

  // lockTime
  writer.writeUInt32LE(0);

  return writer.toBuffer();
}

/**
 * Build the testnet genesis block raw bytes.
 * Same as mainnet but with different nonce and timestamp.
 */
function buildTestnetGenesisBlock(): Buffer {
  const writer = new BufferWriter();

  // Block header (same merkle root as mainnet, different timestamp/nonce)
  writer.writeInt32LE(1);
  writer.writeHash(Buffer.alloc(32, 0));
  writer.writeHash(
    Buffer.from(
      "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a",
      "hex"
    )
  );
  writer.writeUInt32LE(1296688602); // timestamp: 2011-02-02
  writer.writeUInt32LE(0x1d00ffff); // bits
  writer.writeUInt32LE(414098458); // nonce

  // Same coinbase transaction as mainnet
  writer.writeVarInt(1);
  writer.writeInt32LE(1);
  writer.writeVarInt(1);
  writer.writeHash(Buffer.alloc(32, 0));
  writer.writeUInt32LE(0xffffffff);

  const coinbaseScript = Buffer.concat([
    Buffer.from([0x04, 0xff, 0xff, 0x00, 0x1d]),
    Buffer.from([0x01, 0x04]),
    Buffer.from([0x45]),
    Buffer.from(
      "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks"
    ),
  ]);
  writer.writeVarBytes(coinbaseScript);
  writer.writeUInt32LE(0xffffffff);

  writer.writeVarInt(1);
  writer.writeUInt64LE(50_00000000n);

  const satoshiPubKey = Buffer.from(
    "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f",
    "hex"
  );
  const scriptPubKey = Buffer.concat([
    Buffer.from([0x41]),
    satoshiPubKey,
    Buffer.from([0xac]),
  ]);
  writer.writeVarBytes(scriptPubKey);
  writer.writeUInt32LE(0);

  return writer.toBuffer();
}

/**
 * Build the regtest genesis block raw bytes.
 * Same structure but with minimum difficulty.
 */
function buildRegtestGenesisBlock(): Buffer {
  const writer = new BufferWriter();

  // Block header with regtest parameters
  writer.writeInt32LE(1);
  writer.writeHash(Buffer.alloc(32, 0));
  writer.writeHash(
    Buffer.from(
      "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a",
      "hex"
    )
  );
  writer.writeUInt32LE(1296688602); // timestamp
  writer.writeUInt32LE(0x207fffff); // bits (regtest minimum difficulty)
  writer.writeUInt32LE(2); // nonce

  // Same coinbase transaction
  writer.writeVarInt(1);
  writer.writeInt32LE(1);
  writer.writeVarInt(1);
  writer.writeHash(Buffer.alloc(32, 0));
  writer.writeUInt32LE(0xffffffff);

  const coinbaseScript = Buffer.concat([
    Buffer.from([0x04, 0xff, 0xff, 0x00, 0x1d]),
    Buffer.from([0x01, 0x04]),
    Buffer.from([0x45]),
    Buffer.from(
      "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks"
    ),
  ]);
  writer.writeVarBytes(coinbaseScript);
  writer.writeUInt32LE(0xffffffff);

  writer.writeVarInt(1);
  writer.writeUInt64LE(50_00000000n);

  const satoshiPubKey = Buffer.from(
    "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f",
    "hex"
  );
  const scriptPubKey = Buffer.concat([
    Buffer.from([0x41]),
    satoshiPubKey,
    Buffer.from([0xac]),
  ]);
  writer.writeVarBytes(scriptPubKey);
  writer.writeUInt32LE(0);

  return writer.toBuffer();
}

// Pre-compute genesis blocks
const mainnetGenesisBlock = buildMainnetGenesisBlock();
const testnetGenesisBlock = buildTestnetGenesisBlock();
const regtestGenesisBlock = buildRegtestGenesisBlock();

// Compute genesis block hashes (hash256 of first 80 bytes = header)
const mainnetGenesisHash = hash256(mainnetGenesisBlock.subarray(0, 80));
const testnetGenesisHash = hash256(testnetGenesisBlock.subarray(0, 80));
const regtestGenesisHash = hash256(regtestGenesisBlock.subarray(0, 80));

/**
 * Mainnet consensus parameters.
 */
export const MAINNET: ConsensusParams = {
  networkMagic: 0xd9b4bef9,
  defaultPort: 8333,
  genesisBlockHash: mainnetGenesisHash,
  genesisBlock: mainnetGenesisBlock,
  subsidyHalvingInterval: 210_000,
  maxCoins: 2_100_000_000_000_000n, // 21M BTC in satoshis
  maxBlockWeight: 4_000_000,
  maxBlockSigOpsCost: 80_000,
  maxBlockSize: 1_000_000,
  coinbaseMaturity: 100,
  targetTimespan: 14 * 24 * 60 * 60, // 2 weeks = 1,209,600 seconds
  targetSpacing: 10 * 60, // 10 minutes = 600 seconds
  difficultyAdjustmentInterval: 2016, // targetTimespan / targetSpacing
  powLimit: 0x00000000ffff0000000000000000000000000000000000000000000000000000n,
  powLimitBits: 0x1d00ffff,
  bip34Height: 227931,
  bip65Height: 388381,
  bip66Height: 363725,
  segwitHeight: 481824,
  taprootHeight: 709632,
  protocolVersion: 70016,
  services: 0x0409n, // NODE_NETWORK | NODE_WITNESS | NODE_NETWORK_LIMITED
  userAgent: "/hotbuns:0.1.0/",
  dnsSeed: [
    "seed.bitcoin.sipa.be",
    "dnsseed.bluematt.me",
    "dnsseed.bitcoin.dashjr-list-of-hierarchical-deterministic-nodes.org",
    "seed.bitcoinstats.com",
    "seed.bitcoin.jonasschnelli.ch",
    "seed.btc.petertodd.net",
    "seed.bitcoin.sprovoost.nl",
  ],
  checkpoints: new Map([
    [
      0,
      Buffer.from(
        "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
        "hex"
      ).reverse(),
    ],
    [
      11111,
      Buffer.from(
        "0000000069e244f73d78e8fd29ba2fd2ed618bd6fa2ee92559f542fdb26e7c1d",
        "hex"
      ).reverse(),
    ],
    [
      33333,
      Buffer.from(
        "000000002dd5588a74784eaa7ab0507a18ad16a236e7b1ce69f00d7ddfb5d0a6",
        "hex"
      ).reverse(),
    ],
    [
      74000,
      Buffer.from(
        "0000000000573993a3c9e41ce34471c079dcf5f52a0e824a81e7f953b8661a20",
        "hex"
      ).reverse(),
    ],
    [
      105000,
      Buffer.from(
        "00000000000291ce28027faea320c8d2b054b2e0fe44a773f3eefb151d6bdc97",
        "hex"
      ).reverse(),
    ],
    [
      134444,
      Buffer.from(
        "00000000000005b12ffd4cd315cd34ffd4a594f430ac814c91184a0d42d2b0fe",
        "hex"
      ).reverse(),
    ],
    [
      168000,
      Buffer.from(
        "000000000000099e61ea72015e79632f216fe6cb33d7899acb35b75c8303b763",
        "hex"
      ).reverse(),
    ],
    [
      193000,
      Buffer.from(
        "000000000000059f452a5f7340de6682a977387c17010ff6e6c3bd83ca8b1317",
        "hex"
      ).reverse(),
    ],
    [
      210000,
      Buffer.from(
        "000000000000048b95347e83192f69cf0366076336c639f9b7228e9ba171342e",
        "hex"
      ).reverse(),
    ],
    [
      295000,
      Buffer.from(
        "00000000000000004d9b4ef50f0f9d686fd69db2e03af35a100370c64632a983",
        "hex"
      ).reverse(),
    ],
  ]),
};

/**
 * Testnet consensus parameters (testnet3).
 */
export const TESTNET: ConsensusParams = {
  ...MAINNET,
  networkMagic: 0x0709110b,
  defaultPort: 18333,
  genesisBlockHash: testnetGenesisHash,
  genesisBlock: testnetGenesisBlock,
  powLimitBits: 0x1d00ffff,
  bip34Height: 21111,
  bip65Height: 581885,
  bip66Height: 330776,
  segwitHeight: 834624,
  taprootHeight: 0,
  dnsSeed: [
    "testnet-seed.bitcoin.jonasschnelli.ch",
    "seed.tbtc.petertodd.net",
    "testnet-seed.bluematt.me",
  ],
  checkpoints: new Map([
    [
      0,
      Buffer.from(
        "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943",
        "hex"
      ).reverse(),
    ],
  ]),
};

/**
 * Regtest consensus parameters for local development/testing.
 */
export const REGTEST: ConsensusParams = {
  ...MAINNET,
  networkMagic: 0xdab5bffa,
  defaultPort: 18444,
  genesisBlockHash: regtestGenesisHash,
  genesisBlock: regtestGenesisBlock,
  subsidyHalvingInterval: 150,
  powLimitBits: 0x207fffff,
  powLimit: 0x7fffff0000000000000000000000000000000000000000000000000000000000n,
  bip34Height: 500,
  bip65Height: 1351,
  bip66Height: 1251,
  segwitHeight: 0,
  taprootHeight: 0,
  coinbaseMaturity: 100,
  difficultyAdjustmentInterval: 2016,
  dnsSeed: [],
  checkpoints: new Map(),
};

/**
 * Calculate the block subsidy (mining reward) for a given block height.
 *
 * Initial reward is 50 BTC (5,000,000,000 satoshis).
 * Halves every subsidyHalvingInterval blocks.
 *
 * @param height - Block height
 * @param params - Network consensus parameters
 * @returns Block subsidy in satoshis
 */
export function getBlockSubsidy(
  height: number,
  params: ConsensusParams
): bigint {
  const halvings = Math.floor(height / params.subsidyHalvingInterval);

  // After 64 halvings, subsidy is effectively zero
  if (halvings >= 64) {
    return 0n;
  }

  // Initial subsidy: 50 BTC = 5,000,000,000 satoshis
  const initialSubsidy = 50_00000000n;

  // Right-shift to halve the subsidy
  return initialSubsidy >> BigInt(halvings);
}

/**
 * Convert Bitcoin's compact difficulty format (nBits) to a target value.
 *
 * Format: bits = (exponent << 24) | mantissa
 * Target = mantissa * 2^(8*(exponent-3))
 *
 * The mantissa is the lower 23 bits (bits & 0x7fffff).
 * If bit 23 is set (bits & 0x800000), the value is negative.
 *
 * @param bits - Compact difficulty encoding
 * @returns Target value as bigint
 */
export function compactToBigInt(bits: number): bigint {
  const exponent = bits >>> 24;
  let mantissa = bits & 0x7fffff;

  // Handle negative flag (bit 23)
  const isNegative = (bits & 0x800000) !== 0;

  let target: bigint;

  if (exponent <= 3) {
    // Target fits in mantissa, shift right
    target = BigInt(mantissa) >> BigInt(8 * (3 - exponent));
  } else {
    // Shift left for larger targets
    target = BigInt(mantissa) << BigInt(8 * (exponent - 3));
  }

  // Return 0 for negative targets (invalid in Bitcoin)
  if (isNegative && target !== 0n) {
    return 0n;
  }

  return target;
}

/**
 * Convert a target value to Bitcoin's compact difficulty format.
 *
 * @param target - Target value as bigint
 * @returns Compact difficulty encoding
 */
export function bigIntToCompact(target: bigint): number {
  if (target === 0n) {
    return 0;
  }

  // Count the number of bytes needed
  let size = 0;
  let temp = target;
  while (temp > 0n) {
    temp >>= 8n;
    size++;
  }

  let mantissa: number;
  let exponent = size;

  if (size <= 3) {
    // Small target: shift left to get mantissa
    mantissa = Number(target << BigInt(8 * (3 - size)));
  } else {
    // Large target: shift right and potentially round
    const shifted = target >> BigInt(8 * (size - 3));
    mantissa = Number(shifted);
  }

  // If high bit of mantissa is set, we need to increase exponent
  // to avoid the negative flag interpretation
  if (mantissa & 0x800000) {
    mantissa >>= 8;
    exponent++;
  }

  return (exponent << 24) | (mantissa & 0x7fffff);
}

/**
 * Parse a raw genesis block into a Block structure.
 *
 * @param params - Network consensus parameters
 * @returns Parsed genesis block
 */
export function getGenesisBlock(params: ConsensusParams): Block {
  const reader = new BufferReader(params.genesisBlock);

  // Parse header
  const version = reader.readInt32LE();
  const prevBlockHash = reader.readHash();
  const merkleRoot = reader.readHash();
  const timestamp = reader.readUInt32LE();
  const bits = reader.readUInt32LE();
  const nonce = reader.readUInt32LE();

  const header: BlockHeader = {
    version,
    prevBlockHash,
    merkleRoot,
    timestamp,
    bits,
    nonce,
  };

  // Parse transactions
  const txCount = reader.readVarInt();
  const transactions: Transaction[] = [];

  for (let i = 0; i < txCount; i++) {
    const txVersion = reader.readInt32LE();

    // Parse inputs
    const inputCount = reader.readVarInt();
    const inputs: TxInput[] = [];

    for (let j = 0; j < inputCount; j++) {
      const prevTxHash = reader.readHash();
      const prevTxIndex = reader.readUInt32LE();
      const scriptSig = reader.readVarBytes();
      const sequence = reader.readUInt32LE();

      inputs.push({ prevTxHash, prevTxIndex, scriptSig, sequence });
    }

    // Parse outputs
    const outputCount = reader.readVarInt();
    const outputs: TxOutput[] = [];

    for (let j = 0; j < outputCount; j++) {
      const value = reader.readUInt64LE();
      const scriptPubKey = reader.readVarBytes();

      outputs.push({ value, scriptPubKey });
    }

    const lockTime = reader.readUInt32LE();

    transactions.push({
      version: txVersion,
      inputs,
      outputs,
      lockTime,
    });
  }

  return { header, transactions };
}
