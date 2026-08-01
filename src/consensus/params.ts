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
  readonly bip16Height: number;
  readonly bip34Height: number;
  readonly bip65Height: number;
  readonly bip66Height: number;
  readonly csvHeight: number; // BIP68/112/113 (relative timelocks)
  readonly segwitHeight: number;
  readonly taprootHeight: number;
  /**
   * BIP-30 exception blocks: (height, blockHashHex) pairs that are permanently
   * exempt from the duplicate-UTXO check. Mirrors Bitcoin Core's IsBIP30Repeat()
   * which checks BOTH height AND block hash — height alone is insufficient because
   * an alternative-chain block at the same height with a different hash must still
   * enforce BIP-30.
   *
   * On mainnet the two exempt blocks are:
   *   h=91842, hash=00000000000a4d0a398161ffc163c503763b1f4360639393e0e4c8e300e0caec
   *   h=91880, hash=00000000000743f190a18c5577a3c2d2a1f610ae9601ac046a38084ccb7cd721
   *
   * blockHashHex is in display/RPC byte order (big-endian, as shown by block explorers).
   * Reference: Bitcoin Core validation.cpp:6189-6192 IsBIP30Repeat().
   */
  readonly bip30ExceptionBlocks: ReadonlyArray<{ height: number; blockHashHex: string }>;
  /**
   * BIP-30 exception blocks for the DISCONNECT walk.
   *
   * Mirrors bitcoin-core/src/validation.cpp:2201-2202 — these are the
   * heights/hashes of the blocks that were *overwritten by* the BIP-30
   * duplicate-coinbase blocks (91842 and 91880), not the duplicates
   * themselves.  DisconnectBlock unwinds in reverse, so the inconsistency
   * surfaces when the EARLIER block is being disconnected (its outputs
   * have already been re-written by the later duplicate).
   *
   * On mainnet the two heights are:
   *   h=91722, hash=00000000000271a2dc26e7667f8419f2e15416dc6955e5a6c6cdf3f2574dd08e
   *   h=91812, hash=00000000000af0aed4792b1acee3d966af36cf5def14935db8de83d6f9306f2f
   *
   * When disconnecting one of these blocks, the post-disconnect UTXO set
   * is intentionally inconsistent with the block's own outputs (because
   * the LATER block at 91842/91880 created the SAME tx-output that this
   * earlier block already created — i.e. when this earlier block is
   * disconnected, its outputs are still in the UTXO set because the
   * duplicate-coinbase block also added them).  Core marks the disconnect
   * UNCLEAN-but-allowed at these heights — we mirror by silencing the
   * output-mismatch fClean flag for these exact (height, hash) tuples.
   *
   * See https://github.com/bitcoin/bitcoin/issues/22596 for full history.
   */
  readonly bip30DisconnectExceptionBlocks: ReadonlyArray<{
    height: number;
    blockHashHex: string;
  }>;
  /**
   * @deprecated Use bip30ExceptionBlocks instead (height-only check is incorrect).
   * Kept for backward compatibility with existing tests; will be removed.
   */
  readonly bip30ExceptionHeights: readonly number[];
  /**
   * Per-block script-flag exceptions for historical blocks that violate
   * normally-active consensus rules.  Mirrors Bitcoin Core
   * `Consensus::Params::script_flag_exceptions`
   * (kernel/chainparams.cpp:85-88, 210-211; validation.cpp:2262-2266
   * GetBlockScriptFlags).
   *
   * When the block hash matches, the override flags value is returned DIRECTLY
   * and the normal height-computed flag set is NOT used (matching blockbrew /
   * beamchain canonical approach).  This is observationally equivalent to Core
   * because the real exception blocks satisfy every flag anyway.
   *
   * Override values (SCRIPT_VERIFY_* bitmask, from Core chainparams.cpp):
   *   0 = SCRIPT_VERIFY_NONE           — BIP16 violator (P2SH, WITNESS, TAPROOT OFF)
   *   3 = SCRIPT_VERIFY_P2SH | WITNESS — Taproot violator (TAPROOT OFF only)
   *
   * Mainnet: 2 exceptions (BIP16 + Taproot violators).
   * Testnet3: 1 exception (BIP16 violator).
   * Testnet4 / Signet / Regtest: empty (no exceptions).
   *
   * blockHashHex is in display/RPC byte order (big-endian), the same
   * convention as bip30ExceptionBlocks.  Mirror the BIP-30 byte-order
   * check pattern: getBlockHash() → .reverse().toString("hex") → compare.
   *
   * Reference: Bitcoin Core kernel/chainparams.cpp:85-88, 210-211;
   *            src/validation.cpp:2262-2266.
   */
  readonly scriptFlagExceptions: ReadonlyArray<{ blockHashHex: string; flags: number }>;
  /**
   * The block hash at BIP34 activation height on the canonical chain (internal
   * little-endian byte order, same as genesisBlockHash). Used by the BIP-30
   * skip optimisation: BIP-30 is skipped between bip34Height and 1,983,702
   * only when the ancestor at bip34Height has this exact hash, confirming we
   * are on the canonical chain. Matches Bitcoin Core's Consensus::Params::BIP34Hash.
   *
   * Mainnet:  000000000000024b89b42a942fe0d9fea3bb44ab7bd1b19115dd6a759c0808b8 (display)
   * Testnet3: 0000000023b3a96d3484e5abb3755c413e7d41500f8e2a5c3f0dd01299cd8ef8 (display)
   * Testnet4/regtest/signet: zero (BIP34 was always active, no skip needed)
   *
   * Set to null for networks where BIP34 was active from genesis and no skip
   * optimisation is needed (or where any BIP34Hash check would always pass/fail).
   * Reference: Bitcoin Core kernel/chainparams.cpp:89-90, validation.cpp:2462.
   */
  readonly bip34Hash: Buffer | null;
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

// BIP-324 v2 transport enablement predicate.  Kept byte-for-byte in lockstep
// with Peer.bip324V2Enabled (src/p2p/peer.ts): env unset -> ON; explicit
// 0/false/off (any case) -> OFF.  Inlined here (rather than importing Peer)
// to avoid a p2p<-consensus import cycle, and so the advertised-services
// computation below is gated on EXACTLY the same condition that decides
// whether the v2 transport is offered on the wire.  Advertising NODE_P2P_V2
// without offering v2 (or vice-versa) would mis-claim an on-wire capability.
function bip324V2EnabledForServices(): boolean {
  const v = process.env.HOTBUNS_BIP324_V2;
  if (v === undefined) return true;
  const lc = v.toLowerCase();
  if (lc === "0" || lc === "false" || lc === "off") return false;
  return true;
}

// NODE_NETWORK | NODE_WITNESS | NODE_NETWORK_LIMITED (Core protocol.h:315/320/327).
const BASE_SERVICES = 0x409n;
// NODE_P2P_V2 = 1<<11 (Core protocol.h:330): "the node supports BIP324
// transport".  Advertised iff the v2 transport is actually enabled, so the
// wire claim matches behaviour.  When enabled the resulting bitset is 0xc09.
const NODE_P2P_V2 = 0x800n;
const ADVERTISED_SERVICES = BASE_SERVICES | (bip324V2EnabledForServices() ? NODE_P2P_V2 : 0n);

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
  bip16Height: 173805,
  bip34Height: 227931,
  bip65Height: 388381,
  bip66Height: 363725,
  csvHeight: 419328, // BIP68/112/113
  segwitHeight: 481824,
  taprootHeight: 709632,
  // BIP-30: only the two historical duplicate-coinbase blocks are exempt.
  // Reference: Bitcoin Core validation.cpp:6189-6192 IsBIP30Repeat().
  bip30ExceptionBlocks: [
    {
      height: 91842,
      blockHashHex: "00000000000a4d0a398161ffc163c503763b1f4360639393e0e4c8e300e0caec",
    },
    {
      height: 91880,
      blockHashHex: "00000000000743f190a18c5577a3c2d2a1f610ae9601ac046a38084ccb7cd721",
    },
  ],
  // Disconnect-side BIP-30 exceptions — different blocks (one height
  // before each duplicate above).  Mirrors validation.cpp:2201-2202.
  bip30DisconnectExceptionBlocks: [
    {
      height: 91722,
      blockHashHex: "00000000000271a2dc26e7667f8419f2e15416dc6955e5a6c6cdf3f2574dd08e",
    },
    {
      height: 91812,
      blockHashHex: "00000000000af0aed4792b1acee3d966af36cf5def14935db8de83d6f9306f2f",
    },
  ],
  // Kept for backward compat; bip30ExceptionBlocks is the authoritative field.
  bip30ExceptionHeights: [91842, 91880],
  // Script-flag exceptions: historical mainnet blocks that violate normally-active
  // consensus rules.  Mirrors Bitcoin Core kernel/chainparams.cpp:85-88.
  // Flags are raw SCRIPT_VERIFY_* bitmask values (0 = NONE; 3 = P2SH|WITNESS).
  // Hashes in display (RPC/big-endian) order — same convention as bip30ExceptionBlocks.
  scriptFlagExceptions: [
    {
      // BIP16 violator: mined before P2SH enforcement; contains a script that
      // would fail P2SH validation.  Core override: SCRIPT_VERIFY_NONE (0).
      blockHashHex: "00000000000002dc756eebf4f49723ed8d30cc28a5f108eb94b1ba88ac4f9c22",
      flags: 0, // SCRIPT_VERIFY_NONE
    },
    {
      // Taproot violator: mined after Taproot activation but contains a script
      // that would fail TAPROOT verification.  Core override: P2SH | WITNESS (3).
      blockHashHex: "0000000000000000000f14c35b2d841e986ab5441de8c585d5ffe55ea1e395ad",
      flags: 3, // SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS
    },
  ],
  // BIP34Hash: block hash at h=227931 on mainnet canonical chain (display byte order).
  // Reference: Bitcoin Core kernel/chainparams.cpp:89-90, validation.cpp:2462.
  // Internal (LE) form stored here for direct comparison with getBlockHash() output.
  bip34Hash: Buffer.from(
    "000000000000024b89b42a942fe0d9fea3bb44ab7bd1b19115dd6a759c0808b8",
    "hex"
  ).reverse(),
  assumeValidHeight: 938343, // Bitcoin Core default assumevalid (block 938343)
  // Fleet-standard assumevalid hash (Bitcoin Core v28.0, block 938343).
  // Used by shouldSkipScripts() for the proper ancestor-check semantics.
  assumedValid: "00000000000000000000ccebd6d74d9194d8dcdc1d177c478e094bfad51ba5ac",
  protocolVersion: 70016,
  // Default-advertised services: NODE_NETWORK | NODE_WITNESS |
  // NODE_NETWORK_LIMITED = 0x409.  Core advertises NODE_NETWORK_LIMITED
  // UNCONDITIONALLY for a full node — its base g_local_services is
  // (NODE_NETWORK_LIMITED | NODE_WITNESS) at init.cpp:863, and NODE_NETWORK
  // is added for non-prune nodes at init.cpp:1950.  A full node always
  // serves at least the last 288 blocks, so it always advertises the
  // limited bit.  NODE_P2P_V2 (0x800) is added iff the BIP-324 v2 transport
  // is enabled (bip324V2EnabledForServices, the same predicate as
  // Peer.bip324V2Enabled), making the wire claim match behaviour — Core sets
  // NODE_P2P_V2 in g_local_services when v2 is on (init.cpp).  With v2 now
  // default-on the advertised bitset is 0xc09 (matching Core v31.99).
  services: ADVERTISED_SERVICES, // 0xc09 when v2 enabled, 0x409 when opted out
  userAgent: "/hotbuns:1.0.0/",
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
  // m_assumeutxo_data.
  //
  // Map key MUST be the block hash in INTERNAL byte order (the raw 32
  // bytes as serialized in the snapshot file's metadata header, the same
  // bytes that hash256() produces). getAssumeutxoData() looks up by
  // `metadata.baseBlockHash.toString("hex")`, and baseBlockHash is read
  // verbatim from the snapshot wire format via reader.readHash() —
  // that is internal LE order, not the display-order hex shown by RPC /
  // block explorers. Using display-order keys would silently prevent
  // loadtxoutset from ever resolving any mainnet snapshot.
  //
  // The block-explorer / RPC display-order hex is included as a comment
  // above each entry for human cross-reference; the live key is the
  // byte-reversed form. blockHash field stores the same 32 bytes as the
  // key (internal LE), and hashSerialized mirrors Core's
  // AssumeutxoHash::ToString() (BaseHash, internal LE).
  assumeutxo: new Map([
    // 840000 display: 0000000000000000000320283a032748cef8227873ff4872689bf23f1cda83a5
    [
      "a583da1c3ff29b687248ff737822f8ce4827033a282003000000000000000000",
      {
        height: 840000,
        // hashSerialized is the raw SHA256d-of-TxOutSer digest in INTERNAL
        // (little-endian) byte order — exactly what computeUTXOSetHash
        // produces and what the assumeutxo strict gate compares against
        // (snapshot.ts: `computedHash.equals(auData.hashSerialized)`). This is
        // Core's uint256 INTERNAL representation: validation.cpp compares
        // AssumeutxoHash uint256s by their internal bytes, and uint256{"<hex>"}
        // reverses the display hex on construction. The literal below is copied
        // verbatim from Core chainparams.cpp (DISPLAY order, as dumptxoutset
        // prints it), so it MUST be `.reverse()`d to internal order — the same
        // reversal already applied to `blockHash` in every entry. Without it,
        // loading the official Core AssumeUTXO snapshot fails with
        // "Bad snapshot content hash" against the byte-reversed digest.
        // (The h=944183 hashhog-local entry needs no `.reverse()` because its
        // literal came from compute-snapshot-hash.py, which already emits the
        // raw internal-order digest.)
        hashSerialized: Buffer.from(
          "a2a5521b1b5ab65f67818e5e8eccabb7171a517f9e2382208f77687310768f96",
          "hex"
        ).reverse(),
        nChainTx: 991_032_194n,
        blockHash: Buffer.from(
          "0000000000000000000320283a032748cef8227873ff4872689bf23f1cda83a5",
          "hex"
        ).reverse(),
      },
    ],
    // 880000 display: 000000000000000000010b17283c3c400507969a9c2afd1dcf2082ec5cca2880
    [
      "8028ca5cec8220cf1dfd2a9c9a960705403c3c28170b01000000000000000000",
      {
        height: 880000,
        // DISPLAY-order Core chainparams literal → `.reverse()` to internal
        // (see 840000 above for the full rationale).
        hashSerialized: Buffer.from(
          "dbd190983eaf433ef7c15f78a278ae42c00ef52e0fd2a54953782175fbadcea9",
          "hex"
        ).reverse(),
        nChainTx: 1_145_604_538n,
        blockHash: Buffer.from(
          "000000000000000000010b17283c3c400507969a9c2afd1dcf2082ec5cca2880",
          "hex"
        ).reverse(),
      },
    ],
    // 910000 display: 0000000000000000000108970acb9522ffd516eae17acddcb1bd16469194a821
    [
      "21a894914616bdb1dccd7ae1ea16d5ff2295cb0a970801000000000000000000",
      {
        height: 910000,
        // DISPLAY-order Core chainparams literal → `.reverse()` to internal
        // (see 840000 above for the full rationale).
        hashSerialized: Buffer.from(
          "4daf8a17b4902498c5787966a2b51c613acdab5df5db73f196fa59a4da2f1568",
          "hex"
        ).reverse(),
        nChainTx: 1_226_586_151n,
        blockHash: Buffer.from(
          "0000000000000000000108970acb9522ffd516eae17acddcb1bd16469194a821",
          "hex"
        ).reverse(),
      },
    ],
    // 935000 display: 0000000000000000000147034958af1652b2b91bba607beacc5e72a56f0fb5ee
    [
      "eeb50f6fa5725eccea7b60ba1bb9b25216af5849034701000000000000000000",
      {
        height: 935000,
        // DISPLAY-order Core chainparams literal → `.reverse()` to internal
        // (see 840000 above for the full rationale).
        hashSerialized: Buffer.from(
          "e4b90ef9eae834f56c4b64d2d50143cee10ad87994c614d7d04125e2a6025050",
          "hex"
        ).reverse(),
        nChainTx: 1_305_397_408n,
        blockHash: Buffer.from(
          "0000000000000000000147034958af1652b2b91bba607beacc5e72a56f0fb5ee",
          "hex"
        ).reverse(),
      },
    ],
    // hashhog-local snapshot at h=944183 (utxo-snapshot-raw.dat from
    // /data/nvme1/hashhog-mainnet/), used to recover hotbuns + lunarblock
    // mainnet nodes after chainstate corruption (CAMLCOIN-EBADF-LEAK
    // sister bug, see CAMLCOIN-REVIVE-FEASIBILITY.md). NOT a Bitcoin Core
    // chainparams entry — the four 840k/880k/910k/935k entries above ARE.
    // hash_serialized was computed by tools/compute-snapshot-hash.py over
    // the actual on-disk file (165,095,935 coins) and is the raw
    // SHA256d-of-TxOutSer output that computeUTXOSetHash will reproduce.
    // 944183 display: 0000000000000000000146180a1603839d0e9ac6c00d17a5ab45323398ced817
    [
      "17d8ce98333245aba5170dc0c69a0e9d8303160a184601000000000000000000",
      {
        height: 944183,
        hashSerialized: Buffer.from(
          "a888bcbc200384747c0813c8e7f4650d9bc0847b5147791c3ca869567271af2e",
          "hex"
        ),
        nChainTx: 1_334_000_000n,
        blockHash: Buffer.from(
          "0000000000000000000146180a1603839d0e9ac6c00d17a5ab45323398ced817",
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
  bip16Height: 514,
  bip34Height: 21111,
  bip65Height: 581885,
  bip66Height: 330776,
  csvHeight: 770112, // BIP68/112/113
  segwitHeight: 834624,
  taprootHeight: 0,
  bip30ExceptionBlocks: [], // No BIP-30 exceptions on testnet3
  bip30DisconnectExceptionBlocks: [], // No BIP-30 disconnect-side exceptions on testnet3
  bip30ExceptionHeights: [], // No BIP-30 exceptions on testnet3
  // Script-flag exceptions for testnet3: one BIP16 violator block.
  // Mirrors Bitcoin Core kernel/chainparams.cpp:210-211.
  scriptFlagExceptions: [
    {
      blockHashHex: "00000000dd30457c001f4095d208cc1296b0eed002427aa599874af7a432b105",
      flags: 0, // SCRIPT_VERIFY_NONE
    },
  ],
  // BIP34Hash: block hash at h=21111 on testnet3 canonical chain (display byte order, reversed to LE).
  // Reference: Bitcoin Core kernel/chainparams.cpp:213.
  bip34Hash: Buffer.from(
    "0000000023b3a96d3484e5abb3755c413e7d41500f8e2a5c3f0dd01299cd8ef8",
    "hex"
  ).reverse(),
  // Bitcoin Core CTestNetParams defaultAssumeValid — testnet3 block 4842348
  // (kernel/chainparams.cpp:233). Was the testnet4 hash (swapped); corrected.
  assumedValid: "000000007a61e4230b28ac5cb6b5e5a0130de37ac1faf2f8987d2fa6505b67f4",
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
  bip16Height: 1,
  bip34Height: 1,
  bip65Height: 1,
  bip66Height: 1,
  csvHeight: 1,
  segwitHeight: 1,
  taprootHeight: 1,
  bip30ExceptionBlocks: [], // No BIP-30 exceptions on testnet4
  bip30DisconnectExceptionBlocks: [], // No BIP-30 disconnect-side exceptions on testnet4
  bip30ExceptionHeights: [], // No BIP-30 exceptions on testnet4
  scriptFlagExceptions: [], // No script-flag exceptions on testnet4
  // BIP34 active from height 1 on testnet4; no canonical BIP34Hash needed.
  bip34Hash: null,
  // Skip script/sigop verification for blocks at or below this height.
  // Testnet4 tip as of 2026-03: ~60k blocks, set conservatively.
  assumeValidHeight: 123613,
  // Bitcoin Core CTestNet4Params defaultAssumeValid — testnet4 block 123613
  // (kernel/chainparams.cpp:333), matching assumeValidHeight above. Was the
  // testnet3 hash (swapped); corrected.
  assumedValid: "0000000002368b1e4ee27e2e85676ae6f9f9e69579b29093e9a82c170bf7cf8a",
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
  bip16Height: 1,
  bip34Height: 1,
  bip65Height: 1,
  bip66Height: 1,
  csvHeight: 1,
  segwitHeight: 1,
  taprootHeight: 1,
  bip30ExceptionBlocks: [], // No BIP-30 exceptions on signet
  bip30DisconnectExceptionBlocks: [], // No BIP-30 disconnect-side exceptions on signet
  bip30ExceptionHeights: [], // No BIP-30 exceptions on signet
  scriptFlagExceptions: [], // No script-flag exceptions on signet
  // BIP34 active from height 1 on signet; no canonical BIP34Hash needed.
  bip34Hash: null,
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
  bip16Height: 1,
  bip34Height: 1, // Bitcoin Core kernel/chainparams.cpp:536: consensus.BIP34Height = 1
  bip65Height: 1, // Bitcoin Core kernel/chainparams.cpp:538: consensus.BIP65Height = 1 (always active unless overridden)
  bip66Height: 1, // Bitcoin Core kernel/chainparams.cpp:539: consensus.BIP66Height = 1 (always active unless overridden)
  csvHeight: 0, // BIP68/112/113 always active on regtest
  segwitHeight: 0,
  taprootHeight: 0,
  bip30ExceptionBlocks: [], // No BIP-30 exceptions on regtest
  bip30DisconnectExceptionBlocks: [], // No BIP-30 disconnect-side exceptions on regtest
  bip30ExceptionHeights: [], // No BIP-30 exceptions on regtest
  scriptFlagExceptions: [], // No script-flag exceptions on regtest
  // BIP34 active from height 1 on regtest; no canonical BIP34Hash needed.
  bip34Hash: null,
  coinbaseMaturity: 100,
  difficultyAdjustmentInterval: 2016,
  dnsSeed: [],
  checkpoints: new Map(),
  // No minimum work for regtest (allows immediate sync)
  nMinimumChainWork: 0n,
  // Regtest has NO assumevalid: every script is verified for test determinism.
  // Explicitly override the MAINNET values spread-in above.
  // assumeValidHeight must be 0 (not the mainnet 938343 inherited via ...MAINNET)
  // so that assumeValid = (0 > 0 && ...) = false and all scripts run.
  assumeValidHeight: 0,
  assumedValid: undefined,
  // assumeUTXO: regtest allows any snapshot for testing.
  //
  // These 3 entries mirror Bitcoin Core's regtest m_assumeutxo_data
  // (bitcoin-core/src/kernel/chainparams.cpp CRegTestParams, heights 110 /
  // 200 / 299 — "for use by test/functional/feature_assumeutxo.py"). They are
  // Core-parity fixtures for hashhog's own deterministic regtest mining
  // chain (boot-smoke), copied verbatim from Core's DISPLAY-order literals
  // and byte-reversed to INTERNAL order for the Map key / blockHash /
  // hashSerialized fields, exactly like the MAINNET table above (see the
  // 840000 entry's comment for the full byte-order rationale). Runtime
  // registrations via registerRegtestAssumeutxo() (chain/snapshot.ts) add to
  // this map without disturbing these built-ins.
  assumeutxo: new Map([
    // 110 display: 6affe030b7965ab538f820a56ef56c8149b7dc1d1c144af57113be080db7c397
    [
      "97c3b70d08be1371f54a141c1ddcb749816cf56ea520f838b55a96b730e0ff6a",
      {
        height: 110,
        // DISPLAY-order Core chainparams literal → `.reverse()` to internal
        // (see MAINNET 840000 above for the full rationale).
        hashSerialized: Buffer.from(
          "b952555c8ab81fec46f3d4253b7af256d766ceb39fb7752b9d18cdf4a0141327",
          "hex"
        ).reverse(),
        nChainTx: 111n,
        blockHash: Buffer.from(
          "6affe030b7965ab538f820a56ef56c8149b7dc1d1c144af57113be080db7c397",
          "hex"
        ).reverse(),
      },
    ],
    // 200 display: 385901ccbd69dff6bbd00065d01fb8a9e464dede7cfe0372443884f9b1dcf6b9
    [
      "b9f6dcb1f98438447203fe7cdede64e4a9b81fd06500d0bbf6df69bdcc015938",
      {
        height: 200,
        // DISPLAY-order Core chainparams literal → `.reverse()` to internal
        // (see MAINNET 840000 above for the full rationale).
        hashSerialized: Buffer.from(
          "17dcc016d188d16068907cdeb38b75691a118d43053b8cd6a25969419381d13a",
          "hex"
        ).reverse(),
        nChainTx: 201n,
        blockHash: Buffer.from(
          "385901ccbd69dff6bbd00065d01fb8a9e464dede7cfe0372443884f9b1dcf6b9",
          "hex"
        ).reverse(),
      },
    ],
    // 299 display: 7cc695046fec709f8c9394b6f928f81e81fd3ac20977bb68760fa1faa7916ea2
    [
      "a26e91a7faa10f7668bb7709c23afd811ef828f9b694938c9f70ec6f0495c67c",
      {
        height: 299,
        // DISPLAY-order Core chainparams literal → `.reverse()` to internal
        // (see MAINNET 840000 above for the full rationale).
        hashSerialized: Buffer.from(
          "d2b051ff5e8eef46520350776f4100dd710a63447a8e01d917e92e79751a63e2",
          "hex"
        ).reverse(),
        nChainTx: 334n,
        blockHash: Buffer.from(
          "7cc695046fec709f8c9394b6f928f81e81fd3ac20977bb68760fa1faa7916ea2",
          "hex"
        ).reverse(),
      },
    ],
  ]),
};

/**
 * Return a copy of `params` with assume-valid fully DISABLED, so that every
 * script in all of history is verified (mirrors Bitcoin Core `-assumevalid=0`,
 * which sets the assumed-valid block to a null hash — see validation.cpp, where
 * a null/Nothing assumed-valid block makes the skip gate always fall through to
 * full verification).
 *
 * Concretely this zeroes `assumeValidHeight` and clears `assumedValid` (the
 * hash). The canonical gate `shouldSkipScripts()` short-circuits to
 * `skip=false, reason="assumevalid=0 (always verify)"` the moment
 * `assumedValidHash` is undefined, and the two live callers
 * (`sync/blocks.ts`, `mempool/mempool.ts`) both source it from
 * `params.assumedValid` — so clearing it here disables the skip everywhere.
 *
 * Used by the mainnet-replay harness (`--assumevalid=0` / `--noassumevalid` /
 * `HOTBUNS_ASSUMEVALID=0`).
 */
export function disableAssumeValid(params: ConsensusParams): ConsensusParams {
  return {
    ...params,
    assumeValidHeight: 0,
    assumedValid: undefined,
  };
}

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
