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
  // Proof-of-work flags
  readonly fPowAllowMinDifficultyBlocks: boolean; // true for testnet/regtest
  readonly fPowNoRetargeting: boolean; // true for regtest
  readonly enforce_BIP94: boolean; // true for testnet4
  readonly bip34Height: number;
  readonly bip65Height: number;
  readonly bip66Height: number;
  readonly csvHeight: number; // BIP68/112/113 (relative timelocks)
  readonly segwitHeight: number;
  readonly taprootHeight: number;
  readonly protocolVersion: number;
  readonly services: bigint;
  readonly userAgent: string;
  readonly dnsSeed: string[];
  readonly checkpoints: Map<number, Buffer>;
  /**
   * Minimum chain work required before storing headers permanently.
   * This is used by the anti-DoS PRESYNC/REDOWNLOAD mechanism.
   * Headers are only stored once the chain demonstrates this much cumulative work.
   */
  readonly nMinimumChainWork: bigint;
  /**
   * Height below which script/sigop verification is skipped during IBD.
   * Set to 0 to disable assume-valid (verify everything).
   * This is analogous to Bitcoin Core's -assumevalid flag.
   */
  readonly assumeValidHeight: number;
  /**
   * Assumed-valid block hash (hex string, display/RPC byte order).
   *
   * When set, blocks that are ancestors of this block on the active chain
   * may have their script verification skipped (subject to all six safety
   * conditions in src/consensus/assumevalid.ts).
   *
   * This is the fleet-standard Bitcoin Core v28.0 hash. Absent on regtest —
   * regtest always verifies every script for test determinism.
   *
   * Use shouldSkipScripts() from consensus/assumevalid.ts to evaluate.
   */
  readonly assumedValid?: string;
  /**
   * assumeUTXO snapshot data: maps block hash (hex) to snapshot metadata.
   * Used for fast startup by loading a pre-validated UTXO set.
   */
  readonly assumeutxo?: Map<string, AssumeutxoData>;
}

/**
 * assumeUTXO snapshot data for a specific block height.
 */
export interface AssumeutxoData {
  /** Block height of the snapshot. */
  readonly height: number;
  /** SHA256 hash of the serialized UTXO set. */
  readonly hashSerialized: Buffer;
  /** Cumulative transaction count. */
  readonly nChainTx: bigint;
  /** Block hash at this height. */
  readonly blockHash: Buffer;
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
  fPowAllowMinDifficultyBlocks: false,
  fPowNoRetargeting: false,
  enforce_BIP94: false,
  bip34Height: 227931,
  bip65Height: 388381,
  bip66Height: 363725,
  csvHeight: 419328, // BIP68/112/113
  segwitHeight: 481824,
  taprootHeight: 709632,
  assumeValidHeight: 938343, // Bitcoin Core default assumevalid (block 938343)
  // Fleet-standard assumevalid hash (Bitcoin Core v28.0, block 938343).
  // Used by shouldSkipScripts() for the proper ancestor-check semantics.
  assumedValid: "00000000000000000000ccebd6d74d9194d8dcdc1d177c478e094bfad51ba5ac",
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
      250000,
      Buffer.from(
        "000000000000003887df1f29024b06fc2200b55f8af8f35453d7be294df2d214",
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
    [
      330000,
      Buffer.from(
        "00000000000000000faabab19f17c0178c754dbed023e6c871dcaf74159c5f02",
        "hex"
      ).reverse(),
    ],
    [
      360000,
      Buffer.from(
        "00000000000000000ca6e07cf681390ff888b7f96790286a440da0f2b87c8ea6",
        "hex"
      ).reverse(),
    ],
    [
      390000,
      Buffer.from(
        "00000000000000000520000e60b56818523479ada2614806ba17ce0bbe6eaded",
        "hex"
      ).reverse(),
    ],
    [
      420000,
      Buffer.from(
        "000000000000000002cce816c0ab2c5c269cb081896b7dcb34b8422d6b74ffa1",
        "hex"
      ).reverse(),
    ],
    [
      450000,
      Buffer.from(
        "0000000000000000014083723ed311a461c648068af8cef8a19dcd620c07a20b",
        "hex"
      ).reverse(),
    ],
    [
      478559,
      Buffer.from(
        "00000000000000000019f112ec0a9982926f1258cdcc558dd7c3b7e5dc7fa148",
        "hex"
      ).reverse(),
    ],
    [
      504031,
      Buffer.from(
        "0000000000000000005ccd563c9ed7212ad591467cd3db71a17d44918b687f34",
        "hex"
      ).reverse(),
    ],
    [
      530000,
      Buffer.from(
        "000000000000000000024e9be1c7b56cab6428f07920f21ad8457221a91371ae",
        "hex"
      ).reverse(),
    ],
  ]),
  // Minimum chain work from Bitcoin Core (as of recent release)
  nMinimumChainWork: 0x0000000000000000000000000000000000000001128750f82f4c366153a3a030n,
  // assumeUTXO snapshots — Bitcoin Core mainnet, kernel/chainparams.cpp
  // m_assumeutxo_data. Map key is the block hash in display order (RPC
  // byte order, big-endian); blockHash field is the same hash in wire
  // order (little-endian). hash_serialized bytes mirror Core's
  // AssumeutxoHash::ToString() output (which is BaseHash, internal-LE).
  assumeutxo: new Map([
    [
      "0000000000000000000320283a032748cef8227873ff4872689bf23f1cda83a5",
      {
        height: 840000,
        hashSerialized: Buffer.from(
          "a2a5521b1b5ab65f67818e5e8eccabb7171a517f9e2382208f77687310768f96",
          "hex"
        ),
        nChainTx: 991_032_194n,
        blockHash: Buffer.from(
          "0000000000000000000320283a032748cef8227873ff4872689bf23f1cda83a5",
          "hex"
        ).reverse(),
      },
    ],
    [
      "000000000000000000010b17283c3c400507969a9c2afd1dcf2082ec5cca2880",
      {
        height: 880000,
        hashSerialized: Buffer.from(
          "dbd190983eaf433ef7c15f78a278ae42c00ef52e0fd2a54953782175fbadcea9",
          "hex"
        ),
        nChainTx: 1_145_604_538n,
        blockHash: Buffer.from(
          "000000000000000000010b17283c3c400507969a9c2afd1dcf2082ec5cca2880",
          "hex"
        ).reverse(),
      },
    ],
    [
      "0000000000000000000108970acb9522ffd516eae17acddcb1bd16469194a821",
      {
        height: 910000,
        hashSerialized: Buffer.from(
          "4daf8a17b4902498c5787966a2b51c613acdab5df5db73f196fa59a4da2f1568",
          "hex"
        ),
        nChainTx: 1_226_586_151n,
        blockHash: Buffer.from(
          "0000000000000000000108970acb9522ffd516eae17acddcb1bd16469194a821",
          "hex"
        ).reverse(),
      },
    ],
    [
      "0000000000000000000147034958af1652b2b91bba607beacc5e72a56f0fb5ee",
      {
        height: 935000,
        hashSerialized: Buffer.from(
          "e4b90ef9eae834f56c4b64d2d50143cee10ad87994c614d7d04125e2a6025050",
          "hex"
        ),
        nChainTx: 1_305_397_408n,
        blockHash: Buffer.from(
          "0000000000000000000147034958af1652b2b91bba607beacc5e72a56f0fb5ee",
          "hex"
        ).reverse(),
      },
    ],
  ]),
};

/**
 * Testnet3 consensus parameters.
 * Includes special 20-minute min-difficulty rule with walk-back.
 */
export const TESTNET: ConsensusParams = {
  ...MAINNET,
  networkMagic: 0x0709110b,
  defaultPort: 18333,
  genesisBlockHash: testnetGenesisHash,
  genesisBlock: testnetGenesisBlock,
  powLimitBits: 0x1d00ffff,
  fPowAllowMinDifficultyBlocks: true, // 20-minute rule enabled
  fPowNoRetargeting: false,
  enforce_BIP94: false,
  bip34Height: 21111,
  bip65Height: 581885,
  bip66Height: 330776,
  csvHeight: 770112, // BIP68/112/113
  segwitHeight: 834624,
  taprootHeight: 0,
  // Fleet-standard assumevalid hash for testnet3 (Bitcoin Core v28.0, block 123613).
  assumedValid: "0000000002368b1e4ee27e2e85676ae6f9f9e69579b29093e9a82c170bf7cf8a",
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
    [
      546,
      Buffer.from(
        "000000002a936ca763904c3c35fce2f3556c559c0214345d31b1bcebf76acb70",
        "hex"
      ).reverse(),
    ],
  ]),
  nMinimumChainWork: 0x0000000000000000000000000000000000000000000017dde1c649f3708d14b6n,
};

/**
 * Build the testnet4 genesis block raw bytes.
 * Testnet4 (BIP94) uses a different coinbase message and output script
 * than mainnet/testnet3.
 *
 * Coinbase message: "03/May/2024 000000000000000000001ebd58c244970b3aa9d783bb001011fbe8ea8e98e00e"
 * Output script: OP_PUSH33 <33 zero bytes> OP_CHECKSIG (unspendable)
 * Genesis hash: 00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043
 */
function buildTestnet4GenesisBlock(): Buffer {
  const writer = new BufferWriter();

  // Block header with testnet4 parameters
  writer.writeInt32LE(1);
  writer.writeHash(Buffer.alloc(32, 0));
  // Merkle root for testnet4 genesis (wire/LE byte order)
  writer.writeHash(
    Buffer.from(
      "4e7b2b9128fe0291db0693af2ae418b767e657cd407e80cb1434221eaea7a07a",
      "hex"
    )
  );
  writer.writeUInt32LE(1714777860); // timestamp: 2024-05-03 (BIP94 activation)
  writer.writeUInt32LE(0x1d00ffff); // bits
  writer.writeUInt32LE(393743547); // nonce

  // Coinbase transaction (different from mainnet)
  writer.writeVarInt(1);
  writer.writeInt32LE(1);
  writer.writeVarInt(1);
  writer.writeHash(Buffer.alloc(32, 0));
  writer.writeUInt32LE(0xffffffff);

  // Coinbase scriptSig with testnet4 headline (76 bytes, requires OP_PUSHDATA1)
  const testnet4Msg =
    "03/May/2024 000000000000000000001ebd58c244970b3aa9d783bb001011fbe8ea8e98e00e";
  const coinbaseScript = Buffer.concat([
    Buffer.from([0x04, 0xff, 0xff, 0x00, 0x1d]), // push 4 bytes: nBits LE
    Buffer.from([0x01, 0x04]),                     // push 1 byte: 4
    Buffer.from([0x4c, testnet4Msg.length]),        // OP_PUSHDATA1 + length
    Buffer.from(testnet4Msg),
  ]);
  writer.writeVarBytes(coinbaseScript);
  writer.writeUInt32LE(0xffffffff);

  writer.writeVarInt(1);
  writer.writeUInt64LE(50_00000000n);

  // Output script: OP_PUSH33 <33 zero bytes> OP_CHECKSIG (unspendable)
  const scriptPubKey = Buffer.concat([
    Buffer.from([0x21]),       // OP_PUSHBYTES_33
    Buffer.alloc(33, 0),      // 33 zero bytes (null compressed pubkey)
    Buffer.from([0xac]),       // OP_CHECKSIG
  ]);
  writer.writeVarBytes(scriptPubKey);
  writer.writeUInt32LE(0);

  return writer.toBuffer();
}

const testnet4GenesisBlock = buildTestnet4GenesisBlock();
const testnet4GenesisHash = hash256(testnet4GenesisBlock.subarray(0, 80));

/**
 * Testnet4 consensus parameters (BIP94).
 * Uses improved retargeting from first block of period to prevent
 * difficulty storms from min-difficulty blocks.
 */
export const TESTNET4: ConsensusParams = {
  ...MAINNET,
  networkMagic: 0x283f161c, // testnet4 magic (pchMessageStart: 1c 16 3f 28)
  defaultPort: 48333,
  genesisBlockHash: testnet4GenesisHash,
  genesisBlock: testnet4GenesisBlock,
  powLimitBits: 0x1d00ffff,
  fPowAllowMinDifficultyBlocks: true, // 20-minute rule enabled
  fPowNoRetargeting: false,
  enforce_BIP94: true, // Use first block of period for retargeting
  bip34Height: 1,
  bip65Height: 1,
  bip66Height: 1,
  csvHeight: 1,
  segwitHeight: 1,
  taprootHeight: 1,
  // Skip script/sigop verification for blocks at or below this height.
  // Testnet4 tip as of 2026-03: ~60k blocks, set conservatively.
  assumeValidHeight: 123613,
  // Fleet-standard assumevalid hash for testnet4 (Bitcoin Core v28.0, block 4842348).
  assumedValid: "000000007a61e4230b28ac5cb6b5e5a0130de37ac1faf2f8987d2fa6505b67f4",
  dnsSeed: [
    "seed.testnet4.bitcoin.sprovoost.nl",
    "seed.testnet4.wiz.biz",
  ],
  checkpoints: new Map([
    [
      0,
      testnet4GenesisHash,
    ],
    [
      50000,
      Buffer.from(
        "00000000e2c8c94ba126169a88997233f07a9769e2b009fb10cad0e893eff2cb",
        "hex"
      ).reverse(),
    ],
  ]),
  nMinimumChainWork: 0x0000000000000000000000000000000000000000000009a0fe15d0177d086304n,
};

/**
 * Build the signet genesis block raw bytes.
 * Signet uses a custom challenge script for block signing.
 */
function buildSignetGenesisBlock(): Buffer {
  const writer = new BufferWriter();

  // Block header with signet parameters
  writer.writeInt32LE(1);
  writer.writeHash(Buffer.alloc(32, 0));
  writer.writeHash(
    Buffer.from(
      "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a",
      "hex"
    )
  );
  writer.writeUInt32LE(1598918400); // timestamp: 2020-09-01
  writer.writeUInt32LE(0x1e0377ae); // bits (signet powLimit)
  writer.writeUInt32LE(52613770); // nonce

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

const signetGenesisBlock = buildSignetGenesisBlock();
const signetGenesisHash = hash256(signetGenesisBlock.subarray(0, 80));

/**
 * Signet consensus parameters.
 * Uses challenge-based block signing instead of pure PoW.
 */
export const SIGNET: ConsensusParams = {
  ...MAINNET,
  networkMagic: 0x0a03cf40, // signet magic
  defaultPort: 38333,
  genesisBlockHash: signetGenesisHash,
  genesisBlock: signetGenesisBlock,
  powLimitBits: 0x1e0377ae, // More restrictive than mainnet
  powLimit: 0x00000377ae000000000000000000000000000000000000000000000000000000n,
  fPowAllowMinDifficultyBlocks: false,
  fPowNoRetargeting: false,
  enforce_BIP94: false,
  bip34Height: 1,
  bip65Height: 1,
  bip66Height: 1,
  csvHeight: 1,
  segwitHeight: 1,
  taprootHeight: 1,
  dnsSeed: [
    "seed.signet.bitcoin.sprovoost.nl",
  ],
  checkpoints: new Map([
    [
      0,
      signetGenesisHash,
    ],
    [
      100000,
      Buffer.from(
        "0000007c7f4f77c3f2ed1ab62de7dff83f4b672753c1f08e04f9a88f1c1c2d8e",
        "hex"
      ).reverse(),
    ],
  ]),
  nMinimumChainWork: 0x00000000000000000000000000000000000000000000000000000b463ea0a4b8n,
  // Fleet-standard assumevalid hash for signet (Bitcoin Core v28.0, block 293175).
  assumedValid: "00000008414aab61092ef93f1aacc54cf9e9f16af29ddad493b908a01ff5c329",
};

/**
 * Regtest consensus parameters for local development/testing.
 * Always minimum difficulty, no retargeting.
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
  fPowAllowMinDifficultyBlocks: true,
  fPowNoRetargeting: true, // Always minimum difficulty
  enforce_BIP94: false,
  bip34Height: 500,
  bip65Height: 1351,
  bip66Height: 1251,
  csvHeight: 0, // BIP68/112/113 always active on regtest
  segwitHeight: 0,
  taprootHeight: 0,
  coinbaseMaturity: 100,
  difficultyAdjustmentInterval: 2016,
  dnsSeed: [],
  checkpoints: new Map(),
  // No minimum work for regtest (allows immediate sync)
  nMinimumChainWork: 0n,
  // Regtest has NO assumevalid: every script is verified for test determinism.
  // Explicitly override the MAINNET hash spread-in above.
  assumedValid: undefined,
  // assumeUTXO: regtest allows any snapshot for testing
  assumeutxo: new Map(),
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
