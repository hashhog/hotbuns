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
import { ChainstateManager } from "../chain/snapshot.js";
import { UTXOManager } from "../chain/utxo.js";
import { Mempool } from "../mempool/mempool.js";
import { dumpMempool, loadMempool } from "../mempool/persist.js";
import { FeeEstimator } from "../fees/estimator.js";
import { PeerManager } from "../p2p/manager.js";
import { HeaderSync } from "../sync/headers.js";
import { BlockSync } from "../sync/blocks.js";
import { RPCServer, type RPCServerConfig, type RPCServerDeps } from "../rpc/server.js";
import { InventoryRelay } from "../p2p/relay.js";
import { getTxId, getTxVSize } from "../validation/tx.js";
import { InvType, type NetworkMessage, type InvVector } from "../p2p/messages.js";
import { Wallet } from "../wallet/wallet.js";
import { MAINNET, TESTNET, TESTNET4, REGTEST, type ConsensusParams } from "../consensus/params.js";
import { Logger, setLogger } from "../logger/logger.js";

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
  /**
   * Path to a Bitcoin Core-format UTXO snapshot file (assumeutxo).
   * Surfaced as `--load-snapshot=<path>`. The file MUST be a Core
   * snapshot — header is the 5-byte magic `utxo\xff` plus version 2
   * metadata, followed by per-txid groups of compressed Coins.
   *
   * (HDOG, hotbuns' previous custom format, has been retired.)
   */
   loadSnapshot?: string;
  /**
   * Daemonize the node (fork to background and detach).  Mirrors Bitcoin
   * Core's `-daemon` (init.cpp via `util::ForkDaemon`).  hotbuns is built on
   * Bun, which does not expose POSIX `daemon(3)`; instead the parent
   * re-execs itself with `Bun.spawn(..., { stdio: "ignore" })` and the
   * `--internal-daemon-child` flag, then exits.
   */
  daemon: boolean;
  /**
   * Marks the child of a `--daemon` re-exec.  Internal flag: the user
   * never sets this; the parent invocation strips `--daemon` and adds
   * this in the spawn argv.  The presence of this flag tells the child
   * "you are the detached worker, do not fork again".
   */
  internalDaemonChild: boolean;
  /**
   * Optional path to an alternate config file.  When set, overrides the
   * default `<datadir>/hotbuns.conf` lookup.  Mirrors Bitcoin Core's
   * `-conf=<file>` argument.
   */
  conf?: string;
  /**
   * PID file path.  Defaults to `<datadir>/hotbuns.pid`.  When the node
   * starts it writes its own PID to this file; on graceful shutdown the
   * file is removed.  Mirrors Bitcoin Core's `g_pidfile_path` (init.cpp
   * `CreatePidFile` / `RemovePidFile`).
   */
  pid?: string;
  /**
   * Force log output to console (stdout/stderr).  Mirrors Bitcoin Core's
   * `-printtoconsole`; default is "on when no log file is configured,
   * off otherwise".  Setting this explicitly (true) forces console-on
   * regardless of file-logging state.
   */
  printToConsole?: boolean;
  /**
   * Repeatable debug categories (`-debug=net`, `-debug=mempool`, ...).
   * `-debug=all` / `-debug=1` enables every category; `-debug=none` /
   * `-debug=0` disables them.  Plumbed into the process logger by
   * {@link startNode}.
   */
  debug?: string[];
  /**
   * Optional file descriptor that the supervisor passes via
   * `Bun.spawn({ stdio })`. When set, the node writes "ready\n" to this
   * fd once startup completes — equivalent to systemd's
   * `Type=notify` / sd_notify("READY=1") protocol, but minimal.
   */
  readyFd?: number;
  /**
   * Number of parallel script-verification workers for IBD ConnectBlock.
   * 1  = sequential (benchmark baseline).
   * >1 = parallel Promise.all path (default: hardware concurrency).
   * 0 / undefined = use hardware default.
   */
  scriptThreads?: number;
  /**
   * Whether we advertise NODE_BLOOM (service bit 4) and therefore honor
   * BIP-35 "mempool" requests.  Mirrors Bitcoin Core's `-peerbloomfilters`.
   * Default false, matching Bitcoin Core's `DEFAULT_PEERBLOOMFILTERS = false`
   * (see bitcoin-core/src/net_processing.h).
   *
   * Reference: bitcoin-core net_processing.cpp ProcessMessage() handler
   * for NetMsgType::MEMPOOL — the gate is `peer.m_our_services & NODE_BLOOM`.
   */
  peerBloomFilters: boolean;
  /**
   * UTXO database cache size in MiB. Mirrors Bitcoin Core's `-dbcache`
   * argument. Bitcoin Core defaults to `nDefaultDbCache = 450` MiB
   * (init.cpp); hotbuns keeps the historical 512 MiB default that the
   * test fixtures expect.
   *
   * Plumbed through to UTXOManager construction sites (state.ts,
   * snapshot.ts, sync/blocks.ts, test/benchmark.ts) as
   * `cacheBytes = dbcacheMB * 1024 * 1024`.
   */
  dbcacheMB: number;
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
  peerBloomFilters: false,
  dbcacheMB: 512,
  daemon: false,
  internalDaemonChild: false,
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
        case "load-snapshot":
          if (value) config.loadSnapshot = value;
          break;
        case "script-threads":
          if (value) {
            const n = parseInt(value, 10);
            if (!isNaN(n) && n >= 0) config.scriptThreads = n;
          }
          break;
        case "peerbloomfilters":
        case "peer-bloom-filters":
          // Bitcoin Core flag `-peerbloomfilters`.  Accept 0/1, true/false,
          // and the bare `--peerbloomfilters` (treated as true).
          if (value === undefined || value === "1" || value === "true") {
            config.peerBloomFilters = true;
          } else if (value === "0" || value === "false") {
            config.peerBloomFilters = false;
          }
          break;
        case "dbcache":
          // Bitcoin Core flag `-dbcache=N` — UTXO cache in MiB. Plumbed
          // through to all UTXOManager construction sites.
          if (value !== undefined) {
            const dbcacheVal = parseInt(value, 10);
            if (!isNaN(dbcacheVal) && dbcacheVal > 0) {
              config.dbcacheMB = dbcacheVal;
            }
          }
          break;
        case "daemon":
          // Bitcoin Core flag `-daemon`. Bare flag or "=1" enables; "=0"
          // disables (so a config-file `daemon=1` line can be overridden
          // on the command line).
          if (value === undefined || value === "1" || value === "true") {
            config.daemon = true;
          } else if (value === "0" || value === "false") {
            config.daemon = false;
          }
          break;
        case "internal-daemon-child":
          // Internal handoff flag set by the parent of a `--daemon`
          // re-exec.  Never set by the user.
          config.internalDaemonChild = true;
          break;
        case "conf":
          // Bitcoin Core flag `-conf=<file>`.  Promotes the config-file
          // path from the fixed `<datadir>/hotbuns.conf` to a
          // user-overridable absolute or relative path.
          if (value) config.conf = value;
          break;
        case "pid":
          // Bitcoin Core flag `-pid=<file>`. Default is
          // `<datadir>/hotbuns.pid`; an explicit value (including a
          // relative path) wins. `-pid=` (empty) disables PID-file
          // writing.
          if (value !== undefined) config.pid = value;
          break;
        case "printtoconsole":
        case "print-to-console":
          // Bitcoin Core flag `-printtoconsole`. Bare or `=1`/`=true`
          // enables; `=0`/`=false` disables.
          if (value === undefined || value === "1" || value === "true") {
            config.printToConsole = true;
          } else if (value === "0" || value === "false") {
            config.printToConsole = false;
          }
          break;
        case "debug":
          // Bitcoin Core flag `-debug=<category>`. Repeatable; `=all`/`=1`
          // enables every category, `=none`/`=0` disables.  An empty
          // value (`--debug`) is treated as "all" to match Core.
          if (value === undefined || value === "") {
            config.debug = config.debug || [];
            config.debug.push("all");
          } else {
            config.debug = config.debug || [];
            config.debug.push(value);
          }
          break;
        case "ready-fd":
        case "readyfd":
          // Optional supervisor fd for "ready\n" handoff. Mirrors a
          // minimal slice of systemd `Type=notify`.
          if (value !== undefined) {
            const fd = parseInt(value, 10);
            if (!isNaN(fd) && fd >= 0) config.readyFd = fd;
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
 *
 * @param datadir Data directory used both for default config-file lookup
 *   (`<datadir>/hotbuns.conf`) and to be created if missing.
 * @param confOverride Optional `--conf=<path>` override.  When set, the
 *   loader reads from that exact path instead of the default and ignores
 *   any `<datadir>/hotbuns.conf`.  Mirrors Bitcoin Core's `-conf` arg.
 */
export async function loadConfig(
  datadir: string,
  confOverride?: string
): Promise<Partial<NodeConfig>> {
  const configPath = confOverride
    ? path.isAbsolute(confOverride)
      ? confOverride
      : path.join(datadir, confOverride)
    : path.join(datadir, "hotbuns.conf");
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
        case "peerbloomfilters":
          config.peerBloomFilters = value === "1" || value === "true";
          break;
        case "dbcache":
          const dbcacheVal = parseInt(value, 10);
          if (!isNaN(dbcacheVal) && dbcacheVal > 0) {
            config.dbcacheMB = dbcacheVal;
          }
          break;
        case "daemon":
          config.daemon = value === "1" || value === "true";
          break;
        case "pid":
          if (value) config.pid = value;
          break;
        case "printtoconsole":
          config.printToConsole = value === "1" || value === "true";
          break;
        case "debug":
          // Comma-separated list or repeated keys; we accept either.
          config.debug = config.debug || [];
          config.debug.push(value);
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
  mempool: Mempool;
  datadir: string;
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
 * Load a Bitcoin Core-format UTXO snapshot file (assumeutxo).
 *
 * Delegates to ChainstateManager.loadSnapshot, which:
 *   - Parses the SnapshotMetadata header (5-byte magic + version + network
 *     magic + base blockhash + coins count) — see src/chain/snapshot.ts.
 *   - Iterates each per-txid group (txid + CompactSize count + per-coin
 *     compressed entries) and writes uncompressed UTXOEntry rows into the
 *     local LevelDB.
 *   - Verifies the loaded set by recomputing HASH_SERIALIZED and comparing
 *     against the consensus-hardcoded value in `params.assumeutxo`.
 *
 * After load, tip + block index are stitched up so subsequent IBD only
 * needs to download blocks above the snapshot height.
 */
async function runSnapshotLoad(
  snapshotPath: string,
  db: ChainDB,
  chainState: ChainStateManager,
  params: ConsensusParams,
): Promise<void> {
  console.log(`Loading Core-format UTXO snapshot: ${snapshotPath}`);

  const manager = new ChainstateManager(db, params);
  const result = await manager.loadSnapshot(snapshotPath);

  console.log(`Loaded ${result.coinsLoaded} coins`);
  console.log(`  Base height: ${result.baseHeight}`);
  console.log(
    `  Base block:  ${Buffer.from(result.baseBlockHash).reverse().toString("hex")}`
  );

  // Stitch chain tip + minimal block index so subsequent startup uses the
  // snapshot baseline as the active tip. The real header will arrive via
  // the network during follow-on IBD.
  await db.putChainState({
    bestBlockHash: result.baseBlockHash,
    bestHeight: result.baseHeight,
    totalWork: 0n,
  });

  const dummyHeader = Buffer.alloc(80);
  await db.putBlockIndex(result.baseBlockHash, {
    height: result.baseHeight,
    header: dummyHeader,
    nTx: 0,
    status:
      BlockStatus.HEADER_VALID | BlockStatus.TXS_VALID | BlockStatus.HAVE_DATA,
    dataPos: 0,
  });

  console.log(
    `Snapshot load complete. Chain tip: height ${result.baseHeight}, hash ` +
      Buffer.from(result.baseBlockHash).reverse().toString("hex")
  );
}

/**
 * Daemonize: re-exec self with stdio detached and `--internal-daemon-child`,
 * then exit the parent.  Bun has no POSIX `daemon(3)`; this mirrors the
 * essential behaviour (background, no controlling tty, parent returns
 * immediately) using `Bun.spawn`.
 *
 * Reference: bitcoin-core/src/init.cpp -daemon path → `util::ForkDaemon`.
 */
function daemonizeAndExit(originalArgv: string[]): never {
  // Strip out the `--daemon` token (or the `=true`/`=1` form) and add
  // `--internal-daemon-child` so the child knows not to fork again.
  const childArgs = originalArgv
    .slice(2)
    .filter((arg) => {
      if (arg === "--daemon") return false;
      if (arg.startsWith("--daemon=")) return false;
      return true;
    });
  childArgs.push("--internal-daemon-child");

  // Use the same bun executable that's running the parent.
  const bunExe = process.execPath;
  const scriptPath = originalArgv[1];

  const child = Bun.spawn([bunExe, "run", scriptPath, ...childArgs], {
    stdio: ["ignore", "ignore", "ignore"],
    // Detach so child outlives the parent.
    cwd: process.cwd(),
    env: process.env as Record<string, string>,
  });
  // Allow the parent to exit without waiting on the child.
  child.unref?.();
  console.log(`hotbuns daemonized as pid ${child.pid}`);
  process.exit(0);
}

/**
 * Write the PID of this process to `pidPath`.  Best-effort: a write
 * failure is logged but does not abort startup.  Mirrors Core's
 * `CreatePidFile` (init.cpp).
 */
async function writePidFile(pidPath: string): Promise<void> {
  try {
    await fs.promises.writeFile(pidPath, `${process.pid}\n`, { flag: "w" });
  } catch (e) {
    console.error(`Failed to write PID file ${pidPath}:`, (e as Error).message);
  }
}

/**
 * Remove the PID file written by {@link writePidFile}, if any.  Best-effort.
 */
function removePidFileSync(pidPath: string | null): void {
  if (!pidPath) return;
  try {
    fs.unlinkSync(pidPath);
  } catch {
    // file may already be gone; ignore.
  }
}

/** Track the active PID-file path for shutdown cleanup. */
let activePidPath: string | null = null;

/**
 * Start the hotbuns node.
 */
async function startNode(config: NodeConfig): Promise<void> {
  // If `--daemon` and we're not already the spawned child, fork+exit.
  if (config.daemon && !config.internalDaemonChild) {
    daemonizeAndExit(Bun.argv);
  }

  console.log("hotbuns v0.1.0 starting...");

  const baseParams = getParams(config.network);

  // 1. Load or create config file (honors --conf override).
  const fileConfig = await loadConfig(config.datadir, config.conf);
  const mergedConfig = { ...config, ...fileConfig };
  // Restore daemon-related flags from the CLI argv — file config should
  // never be allowed to silently un-set the user's intent on these.
  mergedConfig.daemon = config.daemon;
  mergedConfig.internalDaemonChild = config.internalDaemonChild;
  if (config.debug) mergedConfig.debug = config.debug;
  if (config.printToConsole !== undefined) {
    mergedConfig.printToConsole = config.printToConsole;
  }
  if (config.pid !== undefined) mergedConfig.pid = config.pid;
  if (config.readyFd !== undefined) mergedConfig.readyFd = config.readyFd;

  // 1b. Initialize the process-wide logger from the merged config.
  const logger = new Logger({
    level: mergedConfig.logLevel,
    debugCategories: mergedConfig.debug,
    printToConsole: mergedConfig.printToConsole,
  });
  setLogger(logger);

  // 1c. Write PID file (default <datadir>/hotbuns.pid).  Empty string
  // disables the PID file (matches Core's `-pid=` empty arg).
  const pidPath =
    mergedConfig.pid === ""
      ? null
      : mergedConfig.pid && path.isAbsolute(mergedConfig.pid)
        ? mergedConfig.pid
        : mergedConfig.pid
          ? path.join(mergedConfig.datadir, mergedConfig.pid)
          : path.join(mergedConfig.datadir, "hotbuns.pid");
  if (pidPath) {
    await fs.promises.mkdir(mergedConfig.datadir, { recursive: true });
    await writePidFile(pidPath);
    activePidPath = pidPath;
  }

  // 1d. SIGHUP handler — reopens the log file so external rotators can
  //     move it out of the way.  No-op when the logger is console-only.
  process.on("SIGHUP", () => {
    console.log("Received SIGHUP, reopening log file...");
    logger.reopenLog();
  });

  // BIP-35 / BIP-111: when peerBloomFilters is enabled, we OR NODE_BLOOM
  // (=4) into the advertised services word.  This is the single source of
  // truth gate that the BIP-35 mempool handler below checks before honoring
  // an inbound `mempool` request.  Mirrors Bitcoin Core net.cpp Init:
  // `nLocalServices |= NODE_BLOOM;` (gated on -peerbloomfilters, default
  // false in Core per net_processing.h DEFAULT_PEERBLOOMFILTERS).
  const NODE_BLOOM_BIT = 4n;
  const params: import("../consensus/params.js").ConsensusParams = mergedConfig.peerBloomFilters
    ? { ...baseParams, services: baseParams.services | NODE_BLOOM_BIT }
    : baseParams;

  // 2. Open the database
  const dbPath = path.join(mergedConfig.datadir, "blocks.db");
  const db = new ChainDB(dbPath);
  await db.open();

  // Resolve dbcache → bytes once for all UTXOManager construction sites.
  // Bitcoin Core init.cpp default is 450 MiB; hotbuns historical default is
  // 512 MiB (kept for test-fixture stability).
  const cacheBytes = (mergedConfig.dbcacheMB ?? 512) * 1024 * 1024;

  // 3. Load chain state from DB
  const chainState = new ChainStateManager(db, params, cacheBytes);
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

  // 4a-bis. Restore persisted mempool from <datadir>/mempool.dat (if any).
  // Mirrors Bitcoin Core's `LoadMempool` call from init.cpp's `ImportBlocks`
  // path: each tx is replayed through `acceptToMemoryPool`, so a stale
  // dump never bypasses tightened relay rules.  Skipped silently on the
  // one-shot import paths below — those exits do not run a node.
  if (!mergedConfig.importBlocks && !mergedConfig.loadSnapshot) {
    try {
      const loaded = await loadMempool(mempool, mergedConfig.datadir);
      if (loaded.succeeded + loaded.failed + loaded.expired > 0) {
        console.log(
          `[mempool] Loaded ${loaded.succeeded} txs (${loaded.failed} failed, ` +
            `${loaded.expired} expired, ${loaded.unbroadcast} unbroadcast) from mempool.dat`
        );
      }
    } catch (e) {
      console.error("[mempool] Load skipped:", (e as Error).message);
    }
  }

  // 4b. Block import mode (--import-blocks)
  if (mergedConfig.importBlocks) {
    await runBlockImport(mergedConfig.importBlocks, db, chainState, params);
    await utxo.flush();
    await db.close();
    return;
  }

  // 4c. UTXO snapshot load mode (--load-snapshot=<core-format-file>)
  if (mergedConfig.loadSnapshot) {
    await runSnapshotLoad(mergedConfig.loadSnapshot, db, chainState, params);
    await db.close();
    console.log("Database closed. Snapshot load finished.");
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
  const blockSync = new BlockSync(db, params, headerSync, peerManager, chainState, mergedConfig.scriptThreads, cacheBytes);

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

  // BIP-35: respond to "mempool" with one or more "inv" messages enumerating
  // every txid in our mempool. Reference: bitcoin-core net_processing.cpp,
  // ProcessMessage() handler for NetMsgType::MEMPOOL.
  //
  // Core's gate (net_processing.cpp ~line 4855):
  //   if (!(peer->m_our_services & NODE_BLOOM)
  //       && !pfrom.HasPermission(NetPermissionFlags::Mempool))
  //     return;
  //
  // hotbuns has no per-peer permission system, so we collapse the gate to
  // just "did *we* advertise NODE_BLOOM?" — the same boolean we used to
  // OR the bit into params.services above (mergedConfig.peerBloomFilters).
  // When the gate is closed we silently drop the message; we deliberately
  // do NOT disconnect the peer (Core's `pfrom.fDisconnect = true` branch)
  // because hotbuns lacks a NoBan permission distinction and a sloppy
  // disconnect on every spurious mempool ping would churn the fleet.
  const advertisingNodeBloom = (params.services & NODE_BLOOM_BIT) !== 0n;
  // bitcoin-core caps invs at MAX_INV_SZ = 50_000 entries per message.
  const MAX_INV_PER_MESSAGE = 50_000;
  peerManager.onMessage("mempool", (peer: import("../p2p/peer.js").Peer, _msg: NetworkMessage) => {
    if (!advertisingNodeBloom) {
      // BIP-35 gate closed: we never advertised NODE_BLOOM, so honoring
      // a mempool request would be a protocol surprise. Drop and return.
      return;
    }
    const txids = mempool.getAllTxids();
    if (txids.length === 0) return;
    // BIP-339 (wtxid relay) is negotiated per-peer with `wtxidrelay`. When
    // the peer signaled wtxidrelay we should announce by witness txid using
    // MSG_WTX (=5); otherwise BIP-144 MSG_WITNESS_TX (=0x40000001) is the
    // legacy witness-aware advertisement. hotbuns does not yet track
    // per-peer wtxidrelay state, so we conservatively advertise as
    // MSG_WITNESS_TX — matches the existing relay path and is what Core
    // emits for non-wtxidrelay peers (sans the witness flag, which we set
    // to keep witness-capable receivers happy).
    for (let i = 0; i < txids.length; i += MAX_INV_PER_MESSAGE) {
      const slice = txids.slice(i, i + MAX_INV_PER_MESSAGE);
      const inventory: InvVector[] = slice.map((hash) => ({
        type: InvType.MSG_WITNESS_TX,
        hash,
      }));
      peer.send({ type: "inv", payload: { inventory } });
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
    mempool,
    datadir: mergedConfig.datadir,
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

  // Start Prometheus metrics server (also serves /health for supervisors).
  // Bind failure is non-fatal: a busy port (e.g. another node already on
  // 9332) should not crash the daemon. Log + continue without metrics —
  // matches the nimrod fix in `f063545`.
  const metricsPort = mergedConfig.metricsPort;
  if (metricsPort > 0) {
    try {
      const metricsServer = Bun.serve({
      port: metricsPort,
      hostname: "0.0.0.0",
      fetch: (req) => {
        const url = new URL(req.url);
        // Liveness/readiness probe — minimal endpoint that supervisors
        // (systemd, docker HEALTHCHECK, k8s) can hit on the metrics port.
        if (url.pathname === "/health") {
          const height = chainState.getBestBlock().height;
          const peers = peerManager.getConnectedPeers().length;
          return new Response(
            JSON.stringify({
              status: "ok",
              network: mergedConfig.network,
              height,
              peers,
              pid: process.pid,
            }),
            {
              headers: { "Content-Type": "application/json" },
            }
          );
        }
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
    console.log(`Prometheus metrics server listening on http://0.0.0.0:${metricsPort} (/health probe enabled)`);
    } catch (err) {
      const msg = (err as Error)?.message ?? String(err);
      console.error(
        `[metrics] failed to bind port ${metricsPort}: ${msg} — continuing without metrics`
      );
    }
  }

  // Optional ready-fd handshake: write "ready\n" so a supervisor can
  // synchronize on full startup.  Best-effort; a closed fd is not fatal.
  if (typeof mergedConfig.readyFd === "number" && mergedConfig.readyFd >= 0) {
    try {
      fs.writeSync(mergedConfig.readyFd, "ready\n");
    } catch (e) {
      console.error(
        `Failed to write to --ready-fd=${mergedConfig.readyFd}:`,
        (e as Error).message
      );
    }
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

  // 4b. Persist mempool to <datadir>/mempool.dat (Core-compatible v2).
  // Best-effort: a failed dump must never block shutdown — the worst
  // case is a cold start with an empty mempool.
  try {
    const dumped = await dumpMempool(runningNode.mempool, runningNode.datadir);
    console.log(
      `Mempool persisted to ${dumped.path} (${dumped.count} txs, ${dumped.bytes} bytes)`
    );
  } catch (e) {
    console.error("Failed to dump mempool:", e);
  }

  // 5. Flush UTXO cache
  const utxo = runningNode.chainState.getUTXOManager();
  await utxo.flush();

  // 6. Close database
  await runningNode.db.close();

  // 7. Remove PID file (best-effort).
  removePidFileSync(activePidPath);
  activePidPath = null;

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
  --conf=<file>         Config file path (default: <datadir>/hotbuns.conf)
  --network=<net>       Network: mainnet, testnet, testnet4, regtest (default: mainnet)
  --rpc-port=<port>     RPC port (default: 8332/18332/18443)
  --metrics-port=<port> Prometheus metrics port (default: 9332, 0 = disabled)
  --rpc-user=<user>     RPC username (default: user)
  --rpc-password=<pass> RPC password (default: pass)
  --max-outbound=<n>    Max outbound connections (default: 8)
  --log-level=<level>   Log level: debug, info, warn, error (default: info)
  --debug=<cat>         Enable debug logging for category (repeatable; 'all'/'1' = every category, 'none'/'0' = off)
  --printtoconsole      Force log output to stdout/stderr
  --connect=<host:port> Connect to specific peer
  --prune=<n>           Prune block storage to n MiB (minimum 550, 0 = disabled)
  --dbcache=<n>         UTXO cache size in MiB (default: 512)
  --load-snapshot=<path> Load Bitcoin Core-format UTXO snapshot (assumeutxo)
  --daemon              Fork to background and detach (re-execs self under Bun)
  --pid=<file>          PID file path (default: <datadir>/hotbuns.pid; '' to disable)
  --ready-fd=<N>        Write 'ready\\n' to this fd once startup completes
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
