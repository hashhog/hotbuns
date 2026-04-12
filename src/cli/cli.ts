/**
 * Command-line interface for hotbuns Bitcoin full node.
 *
 * Handles argument parsing, node startup/shutdown, and RPC client commands.
 */

import * as os from "os";
import * as path from "path";
import * as fs from "fs";

import { ChainDB, BlockStatus, DBPrefix } from "../storage/database.js";
import { BufferWriter } from "../wire/serialization.js";
import { ChainStateManager } from "../chain/state.js";
import { UTXOManager } from "../chain/utxo.js";
import { Mempool } from "../mempool/mempool.js";
import { FeeEstimator } from "../fees/estimator.js";
import { PeerManager } from "../p2p/manager.js";
import { HeaderSync } from "../sync/headers.js";
import { BlockSync } from "../sync/blocks.js";
import { RPCServer, type RPCServerConfig, type RPCServerDeps } from "../rpc/server.js";
import { InventoryRelay } from "../p2p/relay.js";
import { getTxId, getTxVSize } from "../validation/tx.js";
import type { NetworkMessage } from "../p2p/messages.js";
import { Wallet } from "../wallet/wallet.js";
import { MAINNET, TESTNET, TESTNET4, REGTEST, type ConsensusParams } from "../consensus/params.js";

/**
 * Node configuration options.
 */
export interface NodeConfig {
  datadir: string;
  network: "mainnet" | "testnet" | "testnet4" | "regtest";
  rpcPort: number;
  rpcUser: string;
  rpcPassword: string;
  maxOutbound: number;
  listen: boolean;
  port: number;
  /** Prometheus metrics port (0 = disabled). */
  metricsPort: number;
  logLevel: "debug" | "info" | "warn" | "error";
  connect?: string[];
  addnode?: string[];
  /** Prune target in MiB (0 = disabled, minimum 550 MiB if enabled). */
  prune?: number;
  /** Path to directory with blk*.dat files, or "-" for framed stdin. */
  importBlocks?: string;
  /** Path to HDOG UTXO snapshot file for AssumeUTXO import. */
  importUtxo?: string;
  /**
   * Number of parallel script-verification workers for IBD ConnectBlock.
   * 1  = sequential (benchmark baseline).
   * >1 = parallel Promise.all path (default: hardware concurrency).
   * 0 / undefined = use hardware default.
   */
  scriptThreads?: number;
}

/**
 * Result of argument parsing.
 */
export interface ParsedArgs {
  command: string;
  config: NodeConfig;
  args: string[];
}

/**
 * Default configuration values.
 */
const DEFAULT_CONFIG: NodeConfig = {
  datadir: path.join(os.homedir(), ".hotbuns"),
  network: "mainnet",
  rpcPort: 8332,
  rpcUser: "user",
  rpcPassword: "pass",
  maxOutbound: 8,
  listen: true,
  port: 8333,
  metricsPort: 9332,
  logLevel: "info",
};

/**
 * Get default RPC port for a network.
 */
function getDefaultRpcPort(network: string): number {
  switch (network) {
    case "testnet":
      return 18332;
    case "testnet4":
      return 48332;
    case "regtest":
      return 18443;
    default:
      return 8332;
  }
}

/**
 * Get default P2P port for a network.
 */
function getDefaultP2PPort(network: string): number {
  switch (network) {
    case "testnet":
      return 18333;
    case "testnet4":
      return 48333;
    case "regtest":
      return 18444;
    default:
      return 8333;
  }
}

/**
 * Parse command-line arguments into a command and configuration.
 */
export function parseArgs(argv: string[]): ParsedArgs {
  // argv typically includes 'bun', script path, then actual arguments
  // Start from index 2 to skip those
  const args = argv.slice(2);

  const config: NodeConfig = { ...DEFAULT_CONFIG };
  const remainingArgs: string[] = [];
  let command = "start"; // Default command

  // Parse first non-flag argument as command
  let foundCommand = false;

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];

    if (arg.startsWith("--")) {
      // Parse flag
      const [key, value] = parseFlag(arg);

      switch (key) {
        case "datadir":
          if (value) config.datadir = value;
          break;
        case "network":
          if (value === "mainnet" || value === "testnet" || value === "testnet4" || value === "regtest") {
            config.network = value;
          }
          break;
        case "rpc-port":
        case "rpcport":
          if (value) config.rpcPort = parseInt(value, 10);
          break;
        case "rpc-user":
          if (value) config.rpcUser = value;
          break;
        case "rpc-password":
          if (value) config.rpcPassword = value;
          break;
        case "max-outbound":
          if (value) config.maxOutbound = parseInt(value, 10);
          break;
        case "listen":
          config.listen = value !== "0" && value !== "false";
          break;
        case "port":
        case "p2p-port":
          if (value) config.port = parseInt(value, 10);
          break;
        case "metrics-port":
        case "metricsport":
          if (value) config.metricsPort = parseInt(value, 10);
          break;
        case "log-level":
          if (
            value === "debug" ||
            value === "info" ||
            value === "warn" ||
            value === "error"
          ) {
            config.logLevel = value;
          }
          break;
        case "connect":
          if (value) {
            config.connect = config.connect || [];
            config.connect.push(value);
          }
          break;
        case "addnode":
          if (value) {
            config.addnode = config.addnode || [];
            config.addnode.push(value);
          }
          break;
        case "prune":
          if (value) {
            const pruneVal = parseInt(value, 10);
            if (!isNaN(pruneVal)) {
              // Minimum 550 MiB if pruning is enabled
              if (pruneVal > 0 && pruneVal < 550) {
                console.error("Error: --prune must be at least 550 MiB");
                process.exit(1);
              }
              config.prune = pruneVal;
            }
          }
          break;
        case "import-blocks":
          if (value) config.importBlocks = value;
          break;
        case "import-utxo":
          if (value) config.importUtxo = value;
          break;
        case "script-threads":
          if (value) {
            const n = parseInt(value, 10);
            if (!isNaN(n) && n >= 0) config.scriptThreads = n;
          }
          break;
        case "password":
          // For wallet commands
          if (value) remainingArgs.push(`--password=${value}`);
          break;
        case "fee-rate":
          // For wallet send command
          if (value) remainingArgs.push(`--fee-rate=${value}`);
          break;
        case "help":
          command = "help";
          break;
        default:
          // Unknown flag, pass through
          break;
      }
    } else if (!foundCommand) {
      // First non-flag argument is the command
      command = arg;
      foundCommand = true;
    } else {
      // Additional non-flag arguments
      remainingArgs.push(arg);
    }
  }

  // Set network-specific defaults if not explicitly set
  if (!args.some((a) => a.startsWith("--rpc-port") || a.startsWith("--rpcport"))) {
    config.rpcPort = getDefaultRpcPort(config.network);
  }
  if (!args.some((a) => a.startsWith("--port") || a.startsWith("--p2p-port"))) {
    config.port = getDefaultP2PPort(config.network);
  }

  return { command, config, args: remainingArgs };
}

/**
 * Parse a flag argument like --key=value or --key value.
 */
function parseFlag(arg: string): [string, string | undefined] {
  const withoutDashes = arg.slice(2);
  const eqIndex = withoutDashes.indexOf("=");

  if (eqIndex !== -1) {
    return [withoutDashes.slice(0, eqIndex), withoutDashes.slice(eqIndex + 1)];
  }

  return [withoutDashes, undefined];
}

/**
 * Load configuration from file, or create with defaults.
 */
export async function loadConfig(datadir: string): Promise<Partial<NodeConfig>> {
  const configPath = path.join(datadir, "hotbuns.conf");
  const config: Partial<NodeConfig> = {};

  // Ensure datadir exists
  await fs.promises.mkdir(datadir, { recursive: true });

  // Check if config file exists
  const file = Bun.file(configPath);
  if (await file.exists()) {
    const content = await file.text();
    const lines = content.split("\n");

    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith("#")) {
        continue;
      }

      const eqIndex = trimmed.indexOf("=");
      if (eqIndex === -1) {
        continue;
      }

      const key = trimmed.slice(0, eqIndex).trim();
      const value = trimmed.slice(eqIndex + 1).trim();

      switch (key) {
        case "network":
          if (value === "mainnet" || value === "testnet" || value === "testnet4" || value === "regtest") {
            config.network = value;
          }
          break;
        case "rpcport":
          config.rpcPort = parseInt(value, 10);
          break;
        case "rpcuser":
          config.rpcUser = value;
          break;
        case "rpcpassword":
          config.rpcPassword = value;
          break;
        case "maxoutbound":
          config.maxOutbound = parseInt(value, 10);
          break;
        case "listen":
          config.listen = value === "1" || value === "true";
          break;
        case "port":
          config.port = parseInt(value, 10);
          break;
        case "metricsport":
          config.metricsPort = parseInt(value, 10);
          break;
        case "loglevel":
          if (
            value === "debug" ||
            value === "info" ||
            value === "warn" ||
            value === "error"
          ) {
            config.logLevel = value;
          }
          break;
        case "prune":
          const pruneVal = parseInt(value, 10);
          if (!isNaN(pruneVal) && pruneVal >= 0) {
            config.prune = pruneVal;
          }
          break;
      }
    }
  }

  return config;
}

/**
 * Save configuration to file.
 */
export async function saveConfig(
  datadir: string,
  config: Partial<NodeConfig>
): Promise<void> {
  const configPath = path.join(datadir, "hotbuns.conf");

  const lines: string[] = [
    "# hotbuns configuration file",
    "",
  ];

  if (config.network) lines.push(`network=${config.network}`);
  if (config.rpcPort) lines.push(`rpcport=${config.rpcPort}`);
  if (config.rpcUser) lines.push(`rpcuser=${config.rpcUser}`);
  if (config.rpcPassword) lines.push(`rpcpassword=${config.rpcPassword}`);
  if (config.maxOutbound) lines.push(`maxoutbound=${config.maxOutbound}`);
  if (config.listen !== undefined) lines.push(`listen=${config.listen ? "1" : "0"}`);
  if (config.port) lines.push(`port=${config.port}`);
  if (config.logLevel) lines.push(`loglevel=${config.logLevel}`);

  await Bun.write(configPath, lines.join("\n") + "\n");
}

/**
 * Get consensus parameters for a network.
 */
function getParams(network: string): ConsensusParams {
  switch (network) {
    case "testnet":
      return TESTNET;
    case "testnet4":
      return TESTNET4;
    case "regtest":
      return REGTEST;
    default:
      return MAINNET;
  }
}

/**
 * Running node state (for shutdown).
 */
interface NodeState {
  db: ChainDB;
  chainState: ChainStateManager;
  peerManager: PeerManager;
  rpcServer: RPCServer;
  headerSync: HeaderSync;
  blockSync: BlockSync;
  feeEstimator: FeeEstimator;
  feeEstimatesPath: string;
}

let runningNode: NodeState | null = null;

/**
 * Apply XOR deobfuscation (Bitcoin Core 28.0+) to a buffer in-place.
 */
function xorDeobfuscate(data: Buffer, fileOffset: number, key: Buffer): void {
  if (key.every((b) => b === 0)) return;
  for (let i = 0; i < data.length; i++) {
    data[i] ^= key[(fileOffset + i) % 8];
  }
}

/**
 * Detect the XOR obfuscation key used by Bitcoin Core 28.0+.
 * Returns 8-byte key (all zeros if no obfuscation).
 */
async function detectXorKey(blocksDir: string, expectedMagic: Buffer): Promise<Buffer> {
  const filePath = path.join(blocksDir, "blk00000.dat");
  const file = Bun.file(filePath);
  if (!(await file.exists())) return Buffer.alloc(8);

  const headerData = Buffer.from(await file.slice(0, 16).arrayBuffer());
  if (headerData.length < 16) return Buffer.alloc(8);

  // Check if plaintext
  if (headerData.subarray(0, 4).equals(expectedMagic)) return Buffer.alloc(8);

  // Derive key[0..4] from magic
  const key = Buffer.alloc(8);
  for (let i = 0; i < 4; i++) {
    key[i] = headerData[i] ^ expectedMagic[i];
  }

  // Derive key[4..8] from bytes at offset 12..16
  // After deobfuscation, offset 8..12 should be block version (01 00 00 00)
  // offset 8 uses key[0..4], offset 12 uses key[4..8]
  // offset 12..16 after deobfuscation should be prev_block_hash[0..4] = 00 00 00 00
  for (let i = 0; i < 4; i++) {
    key[4 + i] = headerData[12 + i]; // ^ 0x00
  }

  console.log(`Detected XOR obfuscation key: ${key.toString("hex")}`);
  return key;
}

/**
 * Import blocks from blk*.dat files or framed stdin.
 *
 * blk*.dat format: [4B magic LE][4B size LE][size bytes raw block] repeated
 * stdin framed format: [4B height LE][4B size LE][size bytes raw block] repeated
 */
async function runBlockImport(
  importPath: string,
  db: ChainDB,
  chainState: ChainStateManager,
  params: ConsensusParams,
): Promise<void> {
  const { deserializeBlock, deserializeBlockHeader, getBlockHash } = await import("../validation/block.js");
  const { BufferReader } = await import("../wire/serialization.js");

  const bestBlock = chainState.getBestBlock();
  const startHeight = bestBlock.height;
  console.log(`Block import mode: starting from height ${startHeight}`);

  if (importPath === "-") {
    // Read framed format from stdin: [4B height LE][4B size LE][block data]
    await importFromStdin(startHeight, db, chainState, deserializeBlock, BufferReader);
  } else {
    // Read from blk*.dat directory
    await importFromBlkFiles(importPath, startHeight, db, chainState, params, deserializeBlock, deserializeBlockHeader, getBlockHash, BufferReader);
  }
}

/**
 * Read blocks from stdin in framed format.
 */
async function importFromStdin(
  startHeight: number,
  db: ChainDB,
  chainState: ChainStateManager,
  deserializeBlock: (reader: any) => any,
  BufferReader: any,
): Promise<void> {
  let imported = 0;
  const importStart = Date.now();
  let batchStart = Date.now();

  console.log("Reading blocks from stdin (framed format)...");

  // Read stdin as a stream
  const stdin = Bun.stdin.stream();
  const reader = stdin.getReader();

  let buffer = Buffer.alloc(0);

  const readExact = async (n: number): Promise<Buffer | null> => {
    while (buffer.length < n) {
      const { done, value } = await reader.read();
      if (done) return null;
      buffer = Buffer.concat([buffer, Buffer.from(value)]);
    }
    const result = buffer.subarray(0, n);
    buffer = buffer.subarray(n);
    return Buffer.from(result);
  };

  while (true) {
    // Read frame header
    const frameHeader = await readExact(8);
    if (!frameHeader) break;

    const frameHeight = frameHeader.readUInt32LE(0);
    const frameSize = frameHeader.readUInt32LE(4);

    if (frameSize === 0 || frameSize > 4_000_000) {
      console.error(`Invalid frame size ${frameSize} at height ${frameHeight}`);
      break;
    }

    // Skip blocks we already have
    if (frameHeight <= startHeight) {
      const skipData = await readExact(frameSize);
      if (!skipData) break;
      continue;
    }

    // Read block data
    const blockData = await readExact(frameSize);
    if (!blockData) break;

    const block = deserializeBlock(new BufferReader(blockData));

    try {
      await chainState.connectBlock(block, frameHeight);
    } catch (e: any) {
      console.error(`Block validation failed at height ${frameHeight}: ${e.message}`);
      break;
    }

    imported++;

    if (imported % 1000 === 0) {
      const elapsed = (Date.now() - batchStart) / 1000;
      const bps = 1000 / elapsed;
      const totalElapsed = (Date.now() - importStart) / 1000;
      console.log(
        `Import progress: height ${frameHeight} (${imported} blocks, ${bps.toFixed(0)} blocks/sec, ${(bps * 60).toFixed(0)} blocks/min, elapsed ${totalElapsed.toFixed(1)}s)`,
      );
      batchStart = Date.now();
    }
  }

  const totalElapsed = (Date.now() - importStart) / 1000;
  if (imported > 0) {
    const bps = imported / totalElapsed;
    console.log(
      `Import complete: ${imported} blocks in ${totalElapsed.toFixed(1)}s (${bps.toFixed(0)} blocks/sec, ${(bps * 60).toFixed(0)} blocks/min)`,
    );
  }
}

/**
 * Read blocks from blk*.dat files.
 * Scans all files to build a hash-to-location index, then processes in height order.
 */
async function importFromBlkFiles(
  blocksDir: string,
  startHeight: number,
  db: ChainDB,
  chainState: ChainStateManager,
  params: ConsensusParams,
  deserializeBlock: (reader: any) => any,
  deserializeBlockHeader: (reader: any) => any,
  getBlockHash: (header: any) => Buffer,
  BufferReader: any,
): Promise<void> {
  const magic = Buffer.alloc(4);
  magic.writeUInt32LE(params.networkMagic, 0);

  console.log(`Scanning blk*.dat files in ${blocksDir} ...`);

  // Detect XOR obfuscation key (Bitcoin Core 28.0+)
  const xorKey = await detectXorKey(blocksDir, magic);

  // Build hash -> (fileNum, offset, size) index
  const index = new Map<string, { fileNum: number; offset: number; size: number }>();
  let fileNum = 0;

  while (true) {
    const filePath = path.join(blocksDir, `blk${String(fileNum).padStart(5, "0")}.dat`);
    const file = Bun.file(filePath);
    if (!(await file.exists())) break;

    const fileData = Buffer.from(await file.arrayBuffer());
    let pos = 0;
    let blocksInFile = 0;

    while (pos + 8 <= fileData.length) {
      // Read and deobfuscate magic + size
      const hdr = Buffer.from(fileData.subarray(pos, pos + 8));
      xorDeobfuscate(hdr, pos, xorKey);

      if (hdr[0] === 0 && hdr[1] === 0 && hdr[2] === 0 && hdr[3] === 0) {
        break;
      }

      if (!hdr.subarray(0, 4).equals(magic)) {
        console.warn(`Bad magic at blk${String(fileNum).padStart(5, "0")}.dat offset ${pos}, skipping`);
        break;
      }

      const size = hdr.readUInt32LE(4);
      if (size === 0 || size > 4_000_000) {
        console.warn(`Invalid block size ${size} at blk${String(fileNum).padStart(5, "0")}.dat offset ${pos}`);
        break;
      }

      const blockOffset = pos + 8;

      // Read and deobfuscate 80-byte header to get hash
      const headerBuf = Buffer.from(fileData.subarray(blockOffset, blockOffset + 80));
      xorDeobfuscate(headerBuf, blockOffset, xorKey);
      const header = deserializeBlockHeader(new BufferReader(headerBuf));
      const hash = getBlockHash(header);
      const hashHex = hash.toString("hex");

      index.set(hashHex, { fileNum, offset: blockOffset, size });

      blocksInFile++;
      pos = blockOffset + size;
    }

    console.log(`Scanned blk${String(fileNum).padStart(5, "0")}.dat: ${blocksInFile} blocks (total: ${index.size})`);
    fileNum++;
  }

  if (fileNum === 0) {
    console.error(`No blk*.dat files found in ${blocksDir}`);
    return;
  }

  console.log(`Block index built: ${index.size} blocks from ${fileNum} files`);

  // Cache file data for reading blocks (keep last 2 files in memory)
  const fileCache = new Map<number, Buffer>();

  const readBlock = async (loc: { fileNum: number; offset: number; size: number }) => {
    let data = fileCache.get(loc.fileNum);
    if (!data) {
      const filePath = path.join(blocksDir, `blk${String(loc.fileNum).padStart(5, "0")}.dat`);
      data = Buffer.from(await Bun.file(filePath).arrayBuffer());
      // Keep cache bounded
      if (fileCache.size >= 2) {
        const firstKey = fileCache.keys().next().value;
        if (firstKey !== undefined) fileCache.delete(firstKey);
      }
      fileCache.set(loc.fileNum, data);
    }
    return data.subarray(loc.offset, loc.offset + loc.size);
  };

  // Process blocks in height order
  let height = startHeight + 1;
  let imported = 0;
  const importStart = Date.now();
  let batchStart = Date.now();

  while (true) {
    // Get expected block hash at this height from our header chain
    const hashBuf = await db.getBlockHashByHeight(height);
    if (!hashBuf) {
      console.log(`No header at height ${height} — end of header chain. Imported ${imported} blocks.`);
      break;
    }
    const hashHex = hashBuf.toString("hex");

    const loc = index.get(hashHex);
    if (!loc) {
      console.warn(`Block ${hashHex} at height ${height} not found in blk files. Stopping.`);
      break;
    }

    const blockData = Buffer.from(await readBlock(loc));
    xorDeobfuscate(blockData, loc.offset, xorKey);
    const block = deserializeBlock(new BufferReader(blockData));

    try {
      await chainState.connectBlock(block, height);
    } catch (e: any) {
      console.error(`Block validation failed at height ${height}: ${e.message}`);
      break;
    }

    imported++;
    height++;

    if (imported % 1000 === 0) {
      const elapsed = (Date.now() - batchStart) / 1000;
      const bps = 1000 / elapsed;
      const totalElapsed = (Date.now() - importStart) / 1000;
      console.log(
        `Import progress: height ${height - 1} (${imported} blocks, ${bps.toFixed(0)} blocks/sec, ${(bps * 60).toFixed(0)} blocks/min, elapsed ${totalElapsed.toFixed(1)}s)`,
      );
      batchStart = Date.now();
    }
  }

  const totalElapsed = (Date.now() - importStart) / 1000;
  if (imported > 0) {
    const bps = imported / totalElapsed;
    console.log(
      `Import complete: ${imported} blocks in ${totalElapsed.toFixed(1)}s (${bps.toFixed(0)} blocks/sec, ${(bps * 60).toFixed(0)} blocks/min)`,
    );
  }
}

/**
 * Import a UTXO snapshot in HDOG binary format.
 *
 * HDOG format:
 *   Header (52 bytes): "HDOG" (4B) + version (u32 LE) + blockHash (32B LE) + height (u32 LE) + utxoCount (u64 LE)
 *   Per UTXO: txid (32B) + vout (u32 LE) + amount (i64 LE) + heightCB (u32 LE) + scriptLen (u16 LE) + script (N B)
 *
 * Writes directly to LevelDB using the same key/value format as normal operation.
 */
async function runUtxoImport(
  snapshotPath: string,
  db: ChainDB,
  chainState: ChainStateManager,
): Promise<void> {
  const BATCH_SIZE = 50_000;
  const PROGRESS_INTERVAL = 1_000_000;

  console.log(`Opening UTXO snapshot: ${snapshotPath}`);

  const file = Bun.file(snapshotPath);
  if (!(await file.exists())) {
    throw new Error(`Snapshot file not found: ${snapshotPath}`);
  }

  const fileSize = file.size;
  console.log(`Snapshot file size: ${fileSize} bytes (${(fileSize / (1024 * 1024 * 1024)).toFixed(2)} GB)`);

  // Use Bun.file().stream() for streaming reads
  const stream = file.stream();
  const reader = stream.getReader();

  let buf = Buffer.alloc(0);
  let fileOffset = 0;

  // Read exactly N bytes from stream
  const readExact = async (n: number): Promise<Buffer> => {
    while (buf.length < n) {
      const { done, value } = await reader.read();
      if (done) {
        throw new Error(`Unexpected EOF at offset ${fileOffset + buf.length}, needed ${n} bytes, have ${buf.length}`);
      }
      buf = Buffer.concat([buf, Buffer.from(value)]);
    }
    const result = buf.subarray(0, n);
    buf = buf.subarray(n);
    fileOffset += n;
    return result;
  };

  // --- Read header (52 bytes) ---
  const header = await readExact(52);

  // Magic: "HDOG"
  const magic = header.subarray(0, 4).toString("ascii");
  if (magic !== "HDOG") {
    throw new Error(`Invalid HDOG magic: expected "HDOG", got "${magic}"`);
  }

  const version = header.readUInt32LE(4);
  if (version !== 1) {
    throw new Error(`Unsupported HDOG version: ${version}`);
  }

  const blockHash = Buffer.from(header.subarray(8, 40));
  const blockHeight = header.readUInt32LE(40);
  const utxoCount = header.readBigUInt64LE(44);

  console.log(`HDOG header:`);
  console.log(`  Version:    ${version}`);
  console.log(`  Block hash: ${Buffer.from(blockHash).reverse().toString("hex")}`);
  console.log(`  Height:     ${blockHeight}`);
  console.log(`  UTXO count: ${utxoCount.toLocaleString()}`);

  // --- Stream and write UTXOs ---
  const importStart = Date.now();
  let loaded = 0n;
  let batchOps: Array<{ type: "put"; prefix: number; key: Buffer; value: Buffer }> = [];

  for (let i = 0n; i < utxoCount; i++) {
    // Read fixed portion: txid(32) + vout(4) + amount(8) + heightCB(4) + scriptLen(2) = 50 bytes
    const fixed = await readExact(50);

    const txid = Buffer.from(fixed.subarray(0, 32));
    const vout = fixed.readUInt32LE(32);
    const amount = fixed.readBigInt64LE(36);
    const heightCB = fixed.readUInt32LE(44);
    const scriptLen = fixed.readUInt16LE(48);

    // Decode height and coinbase from packed field
    const coinHeight = heightCB >>> 1;
    const isCoinbase = (heightCB & 1) === 1;

    // Read scriptPubKey
    const script = scriptLen > 0 ? await readExact(scriptLen) : Buffer.alloc(0);

    // Build DB key: txid (32 bytes) + vout (4 bytes LE)
    const dbKey = Buffer.alloc(36);
    txid.copy(dbKey, 0);
    dbKey.writeUInt32LE(vout, 32);

    // Build DB value matching serializeUTXO format:
    // height (4B LE) + coinbase (1B) + amount (8B LE) + varint(scriptLen) + script
    const writer = new BufferWriter();
    writer.writeUInt32LE(coinHeight);
    writer.writeUInt8(isCoinbase ? 1 : 0);
    writer.writeUInt64LE(amount < 0n ? 0n : amount);
    writer.writeVarBytes(script);
    const dbValue = writer.toBuffer();

    batchOps.push({
      type: "put",
      prefix: DBPrefix.UTXO,
      key: dbKey,
      value: dbValue,
    });

    loaded++;

    // Flush batch
    if (batchOps.length >= BATCH_SIZE) {
      await db.batch(batchOps as any);
      batchOps = [];

      // Hint GC between batches
      if (typeof globalThis.gc === "function") {
        globalThis.gc();
      } else if (typeof Bun !== "undefined" && typeof (Bun as any).gc === "function") {
        (Bun as any).gc(false);
      }

      // Yield to event loop
      await new Promise<void>(resolve => setTimeout(resolve, 0));
    }

    // Progress report
    if (loaded % BigInt(PROGRESS_INTERVAL) === 0n) {
      const elapsed = (Date.now() - importStart) / 1000;
      const rate = Number(loaded) / elapsed;
      const pct = (Number(loaded) * 100 / Number(utxoCount)).toFixed(2);
      const bytesRead = fileOffset;
      const bytePct = (bytesRead * 100 / fileSize).toFixed(2);
      const eta = (Number(utxoCount) - Number(loaded)) / rate;
      console.log(
        `Progress: ${Number(loaded).toLocaleString()} / ${Number(utxoCount).toLocaleString()} UTXOs (${pct}%) | ` +
        `${(bytesRead / (1024 * 1024 * 1024)).toFixed(2)} GB read (${bytePct}%) | ` +
        `${rate.toFixed(0)} UTXOs/sec | ETA ${(eta / 60).toFixed(1)} min`
      );
    }
  }

  // Flush remaining batch
  if (batchOps.length > 0) {
    await db.batch(batchOps as any);
    batchOps = [];
  }

  // --- Set chain tip ---
  console.log(`Setting chain tip to height ${blockHeight}...`);
  await db.putChainState({
    bestBlockHash: blockHash,
    bestHeight: blockHeight,
    totalWork: 0n, // Will be recalculated on startup from headers
  });

  // Also create a minimal block index entry so the node knows about this block
  // We need a dummy 80-byte header; the node will fetch the real one from peers
  const dummyHeader = Buffer.alloc(80);
  await db.putBlockIndex(blockHash, {
    height: blockHeight,
    header: dummyHeader,
    nTx: 0,
    status: BlockStatus.HEADER_VALID | BlockStatus.TXS_VALID | BlockStatus.HAVE_DATA,
    dataPos: 0,
  });

  // Store height -> hash mapping
  const heightKey = Buffer.alloc(4);
  heightKey.writeUInt32BE(blockHeight, 0);

  const totalElapsed = (Date.now() - importStart) / 1000;
  const avgRate = Number(loaded) / totalElapsed;

  console.log(`\nUTXO snapshot import complete!`);
  console.log(`  UTXOs loaded: ${Number(loaded).toLocaleString()}`);
  console.log(`  Time: ${totalElapsed.toFixed(1)}s (${(totalElapsed / 60).toFixed(1)} min)`);
  console.log(`  Average rate: ${avgRate.toFixed(0)} UTXOs/sec`);
  console.log(`  Chain tip: height ${blockHeight}, hash ${Buffer.from(blockHash).reverse().toString("hex")}`);
}

/**
 * Start the hotbuns node.
 */
async function startNode(config: NodeConfig): Promise<void> {
  console.log("hotbuns v0.1.0 starting...");

  const params = getParams(config.network);

  // 1. Load or create config file
  const fileConfig = await loadConfig(config.datadir);
  const mergedConfig = { ...config, ...fileConfig };

  // 2. Open the database
  const dbPath = path.join(mergedConfig.datadir, "blocks.db");
  const db = new ChainDB(dbPath);
  await db.open();

  // 3. Load chain state from DB
  const chainState = new ChainStateManager(db, params);
  await chainState.load();

  // 4. Initialize UTXO manager, mempool, fee estimator
  const utxo = chainState.getUTXOManager();
  const mempool = new Mempool(utxo, params);
  const feeEstimator = new FeeEstimator(mempool);

  // Load persisted fee estimates
  const feeEstimatesPath = path.join(mergedConfig.datadir, "fee_estimates.json");
  try {
    const feeData = await Bun.file(feeEstimatesPath).arrayBuffer();
    feeEstimator.loadState(Buffer.from(feeData));
    console.log(`Loaded fee estimates from ${feeEstimatesPath}`);
  } catch {
    // No saved state or invalid data, use defaults
  }

  // Set tip height
  const bestBlock = chainState.getBestBlock();
  mempool.setTipHeight(bestBlock.height);

  // 4b. Block import mode (--import-blocks)
  if (mergedConfig.importBlocks) {
    await runBlockImport(mergedConfig.importBlocks, db, chainState, params);
    await utxo.flush();
    await db.close();
    return;
  }

  // 4c. UTXO snapshot import mode (--import-utxo)
  if (mergedConfig.importUtxo) {
    await runUtxoImport(mergedConfig.importUtxo, db, chainState);
    await db.close();
    console.log("Database closed. Import finished.");
    return;
  }

  // 5. Initialize header sync
  const headerSync = new HeaderSync(db, params);
  await headerSync.loadFromDB();

  // 6. Start peer manager (DNS seed resolution, connect to peers)
  const peerManager = new PeerManager({
    maxOutbound: mergedConfig.maxOutbound,
    maxInbound: 117,
    params,
    bestHeight: bestBlock.height,
    datadir: mergedConfig.datadir,
    connect: config.connect,
    listen: mergedConfig.listen,
    port: mergedConfig.port,
  });

  // Register header sync with peer manager
  headerSync.registerWithPeerManager(peerManager);

  // 7. Initialize block sync
  const blockSync = new BlockSync(db, params, headerSync, peerManager, chainState, mergedConfig.scriptThreads);

  // 7b. Wire mempool tx relay: accept incoming transactions via AcceptToMemoryPool
  // and relay accepted txs to peers via inventory trickling.
  const txRelay = new InventoryRelay((peer, inventory) => {
    peer.send({ type: "inv", payload: { inventory } });
  });

  // Register all connected peers for relay
  peerManager.onMessage("__connect__", (peer) => {
    txRelay.addPeer(peer, true);
  });
  peerManager.onMessage("__disconnect__", (peer) => {
    txRelay.removePeer(peer);
  });

  // Handle incoming tx messages: validate via AcceptToMemoryPool and relay
  peerManager.onMessage("tx", async (peer: import("../p2p/peer.js").Peer, msg: NetworkMessage) => {
    if (msg.type !== "tx") return;
    const tx = msg.payload.tx;
    const result = await mempool.acceptToMemoryPool(tx);
    if (result.accepted) {
      const txid = getTxId(tx);
      const txidHex = txid.toString("hex");
      const entry = mempool.getTransaction(txid);
      const feeRate = entry ? entry.feeRate : 0;
      txRelay.queueTxToAllFiltered(txidHex, feeRate);
      console.log(`[mempool] Accepted tx ${txidHex.slice(0, 16)}... from ${peer.host}`);
    }
  });

  // 8. Start RPC server
  const rpcConfig: RPCServerConfig = {
    port: mergedConfig.rpcPort,
    host: "127.0.0.1",
    rpcUser: mergedConfig.rpcUser,
    rpcPassword: mergedConfig.rpcPassword,
    datadir: mergedConfig.datadir,
  };

  const rpcDeps: RPCServerDeps = {
    chainState,
    mempool,
    peerManager,
    feeEstimator,
    headerSync,
    db,
    params,
    blockSync,
  };

  const rpcServer = new RPCServer(rpcConfig, rpcDeps);

  // Store running node state
  runningNode = {
    db,
    chainState,
    peerManager,
    rpcServer,
    headerSync,
    blockSync,
    feeEstimator,
    feeEstimatesPath,
  };

  // Set shutdown callback for RPC stop command
  rpcServer.setShutdownCallback(() => {
    gracefulShutdown();
  });

  // 9. Register signal handlers (SIGINT, SIGTERM) for graceful shutdown
  process.on("SIGINT", () => {
    console.log("\nReceived SIGINT, shutting down...");
    gracefulShutdown();
  });

  process.on("SIGTERM", () => {
    console.log("\nReceived SIGTERM, shutting down...");
    gracefulShutdown();
  });

  // Start services
  await peerManager.start();
  await blockSync.start();
  rpcServer.start();

  // Start Prometheus metrics server
  const metricsPort = mergedConfig.metricsPort;
  if (metricsPort > 0) {
    const metricsServer = Bun.serve({
      port: metricsPort,
      hostname: "0.0.0.0",
      fetch: (_req) => {
        const height = chainState.getBestBlock().height;
        const peers = peerManager.getConnectedPeers().length;
        const mempoolCount = mempool.getInfo().size;
        const body =
          `# HELP bitcoin_blocks_total Current block height\n` +
          `# TYPE bitcoin_blocks_total gauge\n` +
          `bitcoin_blocks_total ${height}\n` +
          `# HELP bitcoin_peers_connected Number of connected peers\n` +
          `# TYPE bitcoin_peers_connected gauge\n` +
          `bitcoin_peers_connected ${peers}\n` +
          `# HELP bitcoin_mempool_size Mempool transaction count\n` +
          `# TYPE bitcoin_mempool_size gauge\n` +
          `bitcoin_mempool_size ${mempoolCount}\n`;
        return new Response(body, {
          headers: {
            "Content-Type": "text/plain; version=0.0.4; charset=utf-8",
          },
        });
      },
    });
    console.log(`Prometheus metrics server listening on http://0.0.0.0:${metricsPort}`);
  }

  // 10. Log startup message
  const peerCount = peerManager.getConnectedPeers().length;
  console.log(
    `hotbuns v0.1.0 | network=${mergedConfig.network} | height=${bestBlock.height} | peers=${peerCount} | rpc=127.0.0.1:${mergedConfig.rpcPort}`
  );
}

/**
 * Graceful shutdown sequence.
 */
async function gracefulShutdown(): Promise<void> {
  if (!runningNode) {
    process.exit(0);
    return;
  }

  console.log("Stopping services...");

  // 1. Stop RPC server
  runningNode.rpcServer.stop();

  // 2. Stop block sync
  await runningNode.blockSync.stop();

  // 3. Stop peer manager
  await runningNode.peerManager.stop();

  // 4. Save fee estimates
  try {
    const serialized = runningNode.feeEstimator.serialize();
    await Bun.write(runningNode.feeEstimatesPath, serialized);
    console.log(`Fee estimates saved to ${runningNode.feeEstimatesPath}`);
  } catch (e) {
    console.error("Failed to save fee estimates:", e);
  }

  // 5. Flush UTXO cache
  const utxo = runningNode.chainState.getUTXOManager();
  await utxo.flush();

  // 6. Close database
  await runningNode.db.close();

  console.log("Shutdown complete.");
  runningNode = null;
  process.exit(0);
}

/**
 * Send an RPC request to the running node.
 */
async function rpcCall(
  config: NodeConfig,
  method: string,
  params: unknown[] = []
): Promise<unknown> {
  const url = `http://127.0.0.1:${config.rpcPort}/`;
  const auth = Buffer.from(`${config.rpcUser}:${config.rpcPassword}`).toString(
    "base64"
  );

  const body = JSON.stringify({
    jsonrpc: "2.0",
    id: 1,
    method,
    params,
  });

  const response = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Basic ${auth}`,
    },
    body,
  });

  const result = (await response.json()) as {
    result?: unknown;
    error?: { code: number; message: string };
  };

  if (result.error) {
    throw new Error(`RPC error (${result.error.code}): ${result.error.message}`);
  }

  return result.result;
}

/**
 * Format an RPC request for display (debugging).
 */
export function formatRpcRequest(
  config: NodeConfig,
  method: string,
  params: unknown[] = []
): { url: string; headers: Record<string, string>; body: string } {
  const url = `http://127.0.0.1:${config.rpcPort}/`;
  const auth = Buffer.from(`${config.rpcUser}:${config.rpcPassword}`).toString(
    "base64"
  );

  return {
    url,
    headers: {
      "Content-Type": "application/json",
      Authorization: `Basic ${auth}`,
    },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method,
      params,
    }),
  };
}

/**
 * Execute the stop command.
 */
async function cmdStop(config: NodeConfig): Promise<void> {
  try {
    const result = await rpcCall(config, "stop");
    console.log(result);
  } catch (err) {
    console.error("Failed to stop node:", (err as Error).message);
    process.exit(1);
  }
}

/**
 * Execute the getinfo command.
 */
async function cmdGetInfo(config: NodeConfig): Promise<void> {
  try {
    const result = await rpcCall(config, "getblockchaininfo");
    console.log(JSON.stringify(result, null, 2));
  } catch (err) {
    console.error("Failed to get info:", (err as Error).message);
    process.exit(1);
  }
}

/**
 * Execute the getblock command.
 */
async function cmdGetBlock(config: NodeConfig, args: string[]): Promise<void> {
  if (args.length < 1) {
    console.error("Usage: hotbuns getblock <hash> [verbosity]");
    process.exit(1);
  }

  const hash = args[0];
  const verbosity = args[1] ? parseInt(args[1], 10) : 1;

  try {
    const result = await rpcCall(config, "getblock", [hash, verbosity]);
    console.log(JSON.stringify(result, null, 2));
  } catch (err) {
    console.error("Failed to get block:", (err as Error).message);
    process.exit(1);
  }
}

/**
 * Execute the sendrawtransaction command.
 */
async function cmdSendRawTransaction(
  config: NodeConfig,
  args: string[]
): Promise<void> {
  if (args.length < 1) {
    console.error("Usage: hotbuns sendrawtransaction <hex>");
    process.exit(1);
  }

  const hex = args[0];

  try {
    const result = await rpcCall(config, "sendrawtransaction", [hex]);
    console.log(result);
  } catch (err) {
    console.error("Failed to send transaction:", (err as Error).message);
    process.exit(1);
  }
}

/**
 * Execute wallet create command.
 */
async function cmdWalletCreate(config: NodeConfig, args: string[]): Promise<void> {
  let password = "";

  // Parse --password flag
  for (const arg of args) {
    if (arg.startsWith("--password=")) {
      password = arg.slice("--password=".length);
    }
  }

  if (!password) {
    console.error("Usage: hotbuns wallet create --password=<password>");
    process.exit(1);
  }

  // Ensure datadir exists
  await fs.promises.mkdir(config.datadir, { recursive: true });

  // Check if wallet already exists
  const walletPath = path.join(config.datadir, "wallet.dat");
  const walletFile = Bun.file(walletPath);
  if (await walletFile.exists()) {
    console.error("Wallet already exists at", walletPath);
    process.exit(1);
  }

  // Create new wallet
  const walletConfig = {
    datadir: config.datadir,
    network: config.network as "mainnet" | "testnet" | "regtest",
  };

  const wallet = Wallet.create(walletConfig);

  // Save encrypted
  await wallet.save(password);

  // Get first address
  const address = wallet.getNewAddress();

  console.log("Wallet created successfully!");
  console.log("First receive address:", address);
  console.log("\nIMPORTANT: Back up your wallet file at", walletPath);
}

/**
 * Execute wallet getaddress command.
 */
async function cmdWalletGetAddress(
  config: NodeConfig,
  args: string[]
): Promise<void> {
  let password = "";

  for (const arg of args) {
    if (arg.startsWith("--password=")) {
      password = arg.slice("--password=".length);
    }
  }

  if (!password) {
    console.error("Usage: hotbuns wallet getaddress --password=<password>");
    process.exit(1);
  }

  const walletConfig = {
    datadir: config.datadir,
    network: config.network as "mainnet" | "testnet" | "regtest",
  };

  try {
    const wallet = await Wallet.load(walletConfig, password);
    const address = wallet.getNewAddress();
    await wallet.save(password);
    console.log(address);
  } catch (err) {
    console.error("Failed to get address:", (err as Error).message);
    process.exit(1);
  }
}

/**
 * Execute wallet getbalance command.
 */
async function cmdWalletGetBalance(
  config: NodeConfig,
  args: string[]
): Promise<void> {
  let password = "";

  for (const arg of args) {
    if (arg.startsWith("--password=")) {
      password = arg.slice("--password=".length);
    }
  }

  if (!password) {
    console.error("Usage: hotbuns wallet getbalance --password=<password>");
    process.exit(1);
  }

  const walletConfig = {
    datadir: config.datadir,
    network: config.network as "mainnet" | "testnet" | "regtest",
  };

  try {
    const wallet = await Wallet.load(walletConfig, password);
    const balance = wallet.getBalance();

    const formatBtc = (sats: bigint): string => {
      const btc = Number(sats) / 100_000_000;
      return btc.toFixed(8);
    };

    console.log(`Confirmed: ${formatBtc(balance.confirmed)} BTC`);
    console.log(`Unconfirmed: ${formatBtc(balance.unconfirmed)} BTC`);
    console.log(`Total: ${formatBtc(balance.total)} BTC`);
  } catch (err) {
    console.error("Failed to get balance:", (err as Error).message);
    process.exit(1);
  }
}

/**
 * Execute wallet send command.
 */
async function cmdWalletSend(config: NodeConfig, args: string[]): Promise<void> {
  let password = "";
  let feeRate = 1; // Default 1 sat/vB
  const positionalArgs: string[] = [];

  for (const arg of args) {
    if (arg.startsWith("--password=")) {
      password = arg.slice("--password=".length);
    } else if (arg.startsWith("--fee-rate=")) {
      feeRate = parseInt(arg.slice("--fee-rate=".length), 10);
    } else {
      positionalArgs.push(arg);
    }
  }

  if (!password || positionalArgs.length < 2) {
    console.error(
      "Usage: hotbuns wallet send <address> <amount> --password=<password> [--fee-rate=N]"
    );
    process.exit(1);
  }

  const address = positionalArgs[0];
  const amount = Math.round(parseFloat(positionalArgs[1]) * 100_000_000); // Convert BTC to sats

  if (isNaN(amount) || amount <= 0) {
    console.error("Invalid amount");
    process.exit(1);
  }

  const walletConfig = {
    datadir: config.datadir,
    network: config.network as "mainnet" | "testnet" | "regtest",
  };

  try {
    const wallet = await Wallet.load(walletConfig, password);

    // Create transaction
    const tx = wallet.createTransaction(
      [{ address, amount: BigInt(amount) }],
      feeRate
    );

    // Serialize transaction
    const { serializeTx, getTxId } = await import("../validation/tx.js");
    const rawTx = serializeTx(tx, true);
    const txid = getTxId(tx);

    console.log("Transaction created!");
    console.log("TXID:", txid.toString("hex"));
    console.log("Raw hex:", rawTx.toString("hex"));
    console.log("\nBroadcast with: hotbuns sendrawtransaction", rawTx.toString("hex"));

    // Save wallet (address indices updated)
    await wallet.save(password);
  } catch (err) {
    console.error("Failed to send:", (err as Error).message);
    process.exit(1);
  }
}

/**
 * Print help message.
 */
function printHelp(): void {
  console.log(`hotbuns v0.1.0 - Bitcoin full node in TypeScript (Bun)

USAGE:
  hotbuns <command> [options]

COMMANDS:
  start                 Start the node (default)
  stop                  Stop the running node
  getinfo               Get blockchain info
  getblock <hash>       Get block by hash
  sendrawtransaction <hex>  Send a raw transaction

  wallet create         Create a new wallet
  wallet getaddress     Get a new receive address
  wallet getbalance     Get wallet balance
  wallet send <addr> <amount>  Send bitcoin

OPTIONS:
  --datadir=<path>      Data directory (default: ~/.hotbuns)
  --network=<net>       Network: mainnet, testnet, testnet4, regtest (default: mainnet)
  --rpc-port=<port>     RPC port (default: 8332/18332/18443)
  --metrics-port=<port> Prometheus metrics port (default: 9332, 0 = disabled)
  --rpc-user=<user>     RPC username (default: user)
  --rpc-password=<pass> RPC password (default: pass)
  --max-outbound=<n>    Max outbound connections (default: 8)
  --log-level=<level>   Log level: debug, info, warn, error (default: info)
  --connect=<host:port> Connect to specific peer
  --prune=<n>           Prune block storage to n MiB (minimum 550, 0 = disabled)
  --import-utxo=<path>  Import UTXO snapshot from HDOG file (AssumeUTXO)
  --password=<pass>     Wallet password (for wallet commands)
  --fee-rate=<n>        Fee rate in sat/vB (for wallet send)
  --help                Show this help message

EXAMPLES:
  hotbuns start --network=testnet
  hotbuns getinfo --rpc-port=18332 --rpc-user=user --rpc-password=pass
  hotbuns wallet create --password=mysecret
  hotbuns wallet send bc1q... 0.01 --password=mysecret --fee-rate=5
`);
}

/**
 * Main entry point for the CLI.
 */
export async function main(): Promise<void> {
  const { command, config, args } = parseArgs(Bun.argv);

  // Handle help first
  if (command === "help" || command === "--help") {
    printHelp();
    return;
  }

  // Route to appropriate command handler
  switch (command) {
    case "start":
      await startNode(config);
      // Keep process running (event loop will keep it alive)
      break;

    case "stop":
      await cmdStop(config);
      break;

    case "getinfo":
      await cmdGetInfo(config);
      break;

    case "getblock":
      await cmdGetBlock(config, args);
      break;

    case "sendrawtransaction":
      await cmdSendRawTransaction(config, args);
      break;

    case "wallet":
      // Wallet subcommands
      if (args.length === 0) {
        console.error("Usage: hotbuns wallet <create|getaddress|getbalance|send>");
        process.exit(1);
      }

      const subcommand = args[0];
      const subargs = args.slice(1);

      switch (subcommand) {
        case "create":
          await cmdWalletCreate(config, subargs);
          break;
        case "getaddress":
          await cmdWalletGetAddress(config, subargs);
          break;
        case "getbalance":
          await cmdWalletGetBalance(config, subargs);
          break;
        case "send":
          await cmdWalletSend(config, subargs);
          break;
        default:
          console.error("Unknown wallet command:", subcommand);
          process.exit(1);
      }
      break;

    default:
      console.error(`Unknown command: ${command}`);
      console.error("Run 'hotbuns --help' for usage information.");
      process.exit(1);
  }
}
