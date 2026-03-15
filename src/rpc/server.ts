/**
 * JSON-RPC 2.0 server using Bun.serve.
 *
 * Exposes Bitcoin Core-compatible RPC methods for querying blockchain state,
 * submitting transactions, and managing the node.
 */

import type { ChainStateManager } from "../chain/state.js";
import type { ChainDB } from "../storage/database.js";
import type { Mempool, MempoolEntry } from "../mempool/mempool.js";
import type { PeerManager } from "../p2p/manager.js";
import type { FeeEstimator } from "../fees/estimator.js";
import type { HeaderSync, HeaderChainEntry } from "../sync/headers.js";
import type { ConsensusParams } from "../consensus/params.js";
import { compactToBigInt } from "../consensus/params.js";
import type { Block, BlockHeader } from "../validation/block.js";
import {
  deserializeBlock,
  serializeBlock,
  serializeBlockHeader,
  getBlockHash,
} from "../validation/block.js";
import type { Transaction } from "../validation/tx.js";
import {
  deserializeTx,
  serializeTx,
  getTxId,
  getTxVSize,
  getTxWeight,
  hasWitness,
  isCoinbase,
} from "../validation/tx.js";
import { BufferReader } from "../wire/serialization.js";
import type { InvPayload, NetworkMessage } from "../p2p/messages.js";
import { InvType } from "../p2p/messages.js";

/**
 * JSON-RPC request format.
 */
export interface RPCRequest {
  jsonrpc: "2.0" | "1.0";
  id: string | number | null;
  method: string;
  params: unknown[];
}

/**
 * JSON-RPC response format.
 */
export interface RPCResponse {
  jsonrpc: "2.0";
  id: string | number | null;
  result?: unknown;
  error?: { code: number; message: string; data?: unknown };
}

/**
 * RPC server configuration.
 */
export interface RPCServerConfig {
  /** Port to listen on (default 8332). */
  port: number;
  /** Host to bind to (default '127.0.0.1'). */
  host: string;
  /** RPC username for authentication. */
  rpcUser?: string;
  /** RPC password for authentication. */
  rpcPassword?: string;
}

/**
 * Dependencies for the RPC server.
 */
export interface RPCServerDeps {
  chainState: ChainStateManager;
  mempool: Mempool;
  peerManager: PeerManager;
  feeEstimator: FeeEstimator;
  headerSync: HeaderSync;
  db: ChainDB;
  params: ConsensusParams;
}

/** RPC error codes. */
export const RPCErrorCodes = {
  // JSON-RPC 2.0 standard errors
  INVALID_REQUEST: -32600,
  METHOD_NOT_FOUND: -32601,
  INVALID_PARAMS: -32602,
  INTERNAL_ERROR: -32603,
  PARSE_ERROR: -32700,
  // Bitcoin-specific errors
  MISC_ERROR: -1,
  INVALID_ADDRESS_OR_KEY: -5,
  VERIFY_ALREADY_IN_CHAIN: -25,
  VERIFY_REJECTED: -26,
} as const;

/**
 * JSON-RPC 2.0 server for Bitcoin node control and queries.
 */
export class RPCServer {
  private server: ReturnType<typeof Bun.serve> | null = null;
  private config: RPCServerConfig;
  private methods: Map<string, (params: unknown[]) => Promise<unknown>>;
  private chainState: ChainStateManager;
  private mempool: Mempool;
  private peerManager: PeerManager;
  private feeEstimator: FeeEstimator;
  private headerSync: HeaderSync;
  private db: ChainDB;
  private params: ConsensusParams;
  private shutdownCallback: (() => void) | null = null;

  constructor(config: RPCServerConfig, deps: RPCServerDeps) {
    this.config = {
      port: config.port ?? 8332,
      host: config.host ?? "127.0.0.1",
      rpcUser: config.rpcUser,
      rpcPassword: config.rpcPassword,
    };
    this.chainState = deps.chainState;
    this.mempool = deps.mempool;
    this.peerManager = deps.peerManager;
    this.feeEstimator = deps.feeEstimator;
    this.headerSync = deps.headerSync;
    this.db = deps.db;
    this.params = deps.params;
    this.methods = new Map();

    this.registerBuiltinMethods();
  }

  /**
   * Set a callback to be invoked when the stop RPC is called.
   */
  setShutdownCallback(callback: () => void): void {
    this.shutdownCallback = callback;
  }

  /**
   * Start the HTTP server.
   */
  start(): void {
    this.server = Bun.serve({
      port: this.config.port,
      hostname: this.config.host,
      fetch: (req) => this.handleRequest(req),
    });

    console.log(
      `RPC server listening on http://${this.config.host}:${this.config.port}`
    );
  }

  /**
   * Stop the server.
   */
  stop(): void {
    if (this.server) {
      this.server.stop();
      this.server = null;
    }
  }

  /**
   * Register an RPC method handler.
   */
  registerMethod(
    name: string,
    handler: (params: unknown[]) => Promise<unknown>
  ): void {
    this.methods.set(name, handler);
  }

  /**
   * Handle an incoming HTTP request.
   */
  private async handleRequest(req: Request): Promise<Response> {
    // Only accept POST requests
    if (req.method !== "POST") {
      return new Response(
        JSON.stringify({
          jsonrpc: "2.0",
          id: null,
          error: { code: RPCErrorCodes.INVALID_REQUEST, message: "Only POST requests are supported" },
        }),
        {
          status: 405,
          headers: { "Content-Type": "application/json" },
        }
      );
    }

    // Authenticate
    if (!this.authenticate(req)) {
      return new Response(
        JSON.stringify({
          jsonrpc: "2.0",
          id: null,
          error: { code: RPCErrorCodes.INVALID_REQUEST, message: "Authentication required" },
        }),
        {
          status: 401,
          headers: {
            "Content-Type": "application/json",
            "WWW-Authenticate": 'Basic realm="jsonrpc"',
          },
        }
      );
    }

    // Parse request body
    let body: unknown;
    try {
      body = await req.json();
    } catch {
      return new Response(
        JSON.stringify({
          jsonrpc: "2.0",
          id: null,
          error: { code: RPCErrorCodes.PARSE_ERROR, message: "Parse error" },
        }),
        {
          status: 400,
          headers: { "Content-Type": "application/json" },
        }
      );
    }

    // Handle batched requests
    if (Array.isArray(body)) {
      const responses = await Promise.all(
        body.map((request) => this.processRequest(request))
      );
      return new Response(JSON.stringify(responses), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }

    // Handle single request
    const response = await this.processRequest(body);
    return new Response(JSON.stringify(response), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  }

  /**
   * Process a single RPC request.
   */
  private async processRequest(body: unknown): Promise<RPCResponse> {
    // Validate request structure
    if (!this.isValidRequest(body)) {
      return {
        jsonrpc: "2.0",
        id: null,
        error: { code: RPCErrorCodes.INVALID_REQUEST, message: "Invalid Request" },
      };
    }

    const request = body as RPCRequest;
    const id = request.id;

    // Look up method handler
    const handler = this.methods.get(request.method);
    if (!handler) {
      return {
        jsonrpc: "2.0",
        id,
        error: {
          code: RPCErrorCodes.METHOD_NOT_FOUND,
          message: `Method '${request.method}' not found`,
        },
      };
    }

    // Execute method
    try {
      const params = Array.isArray(request.params) ? request.params : [];
      const result = await handler(params);
      return { jsonrpc: "2.0", id, result };
    } catch (error) {
      const err = error as Error & { code?: number };
      return {
        jsonrpc: "2.0",
        id,
        error: {
          code: err.code ?? RPCErrorCodes.INTERNAL_ERROR,
          message: err.message || "Internal error",
        },
      };
    }
  }

  /**
   * Validate Basic auth credentials.
   */
  private authenticate(req: Request): boolean {
    // If no credentials configured, allow all
    if (!this.config.rpcUser || !this.config.rpcPassword) {
      return true;
    }

    const authHeader = req.headers.get("Authorization");
    if (!authHeader || !authHeader.startsWith("Basic ")) {
      return false;
    }

    const base64Credentials = authHeader.slice(6);
    let credentials: string;
    try {
      credentials = Buffer.from(base64Credentials, "base64").toString("utf-8");
    } catch {
      return false;
    }

    const [user, password] = credentials.split(":");
    return user === this.config.rpcUser && password === this.config.rpcPassword;
  }

  /**
   * Check if a request object is valid.
   */
  private isValidRequest(body: unknown): body is RPCRequest {
    if (typeof body !== "object" || body === null) {
      return false;
    }

    const obj = body as Record<string, unknown>;

    // Must have method as string
    if (typeof obj.method !== "string") {
      return false;
    }

    // params must be array or undefined
    if (obj.params !== undefined && !Array.isArray(obj.params)) {
      return false;
    }

    return true;
  }

  /**
   * Register built-in RPC methods.
   */
  private registerBuiltinMethods(): void {
    // Blockchain methods
    this.registerMethod("getblockchaininfo", () => this.getBlockchainInfo());
    this.registerMethod("getblock", (params) => this.getBlock(params));
    this.registerMethod("getblockhash", (params) => this.getBlockHash(params));
    this.registerMethod("getblockheader", (params) => this.getBlockHeader(params));

    // Transaction methods
    this.registerMethod("getrawtransaction", (params) =>
      this.getRawTransaction(params)
    );
    this.registerMethod("sendrawtransaction", (params) =>
      this.sendRawTransaction(params)
    );

    // Mempool methods
    this.registerMethod("getmempoolinfo", () => this.getMempoolInfo());
    this.registerMethod("getrawmempool", (params) => this.getRawMempool(params));

    // Fee estimation
    this.registerMethod("estimatesmartfee", (params) =>
      this.estimateSmartFee(params)
    );

    // Network methods
    this.registerMethod("getpeerinfo", () => this.getPeerInfo());
    this.registerMethod("getnetworkinfo", () => this.getNetworkInfo());

    // Ban management
    this.registerMethod("listbanned", () => this.listBanned());
    this.registerMethod("setban", (params) => this.setBan(params));
    this.registerMethod("clearbanned", () => this.clearBanned());

    // Control methods
    this.registerMethod("stop", () => this.stopNode());
  }

  // ========== Blockchain Methods ==========

  /**
   * getblockchaininfo: Returns blockchain state information.
   */
  private async getBlockchainInfo(): Promise<Record<string, unknown>> {
    const bestBlock = this.chainState.getBestBlock();
    const bestHeader = this.headerSync.getBestHeader();

    // Calculate difficulty
    const difficulty = await this.calculateDifficulty(bestBlock.hash);

    // Calculate median time past
    const headerEntry = this.headerSync.getHeader(bestBlock.hash);
    const mediantime = headerEntry
      ? this.headerSync.getMedianTimePast(headerEntry)
      : Math.floor(Date.now() / 1000);

    // Calculate verification progress
    const headers = bestHeader?.height ?? bestBlock.height;
    const blocks = bestBlock.height;
    const verificationprogress = headers > 0 ? blocks / headers : 1.0;

    // Determine chain name
    let chain: string;
    switch (this.params.networkMagic) {
      case 0xd9b4bef9:
        chain = "main";
        break;
      case 0x0709110b:
        chain = "test";
        break;
      case 0xdab5bffa:
        chain = "regtest";
        break;
      default:
        chain = "unknown";
    }

    return {
      chain,
      blocks: bestBlock.height,
      headers: headers,
      bestblockhash: bestBlock.hash.toString("hex"),
      difficulty,
      mediantime,
      verificationprogress,
      chainwork: bestBlock.chainWork.toString(16).padStart(64, "0"),
      pruned: false,
      warnings: "",
    };
  }

  /**
   * getblock: Returns block data.
   * @param params [blockhash, verbosity]
   * verbosity 0: hex-encoded block data
   * verbosity 1: JSON with txids
   * verbosity 2: JSON with full tx data
   */
  private async getBlock(params: unknown[]): Promise<unknown> {
    const [blockhashParam, verbosityParam] = params;

    if (typeof blockhashParam !== "string") {
      throw this.rpcError(RPCErrorCodes.INVALID_PARAMS, "blockhash must be a string");
    }

    const blockhash = Buffer.from(blockhashParam, "hex");
    if (blockhash.length !== 32) {
      throw this.rpcError(RPCErrorCodes.INVALID_PARAMS, "Invalid blockhash length");
    }

    const verbosity = typeof verbosityParam === "number" ? verbosityParam : 1;

    // Get block data
    const blockData = await this.db.getBlock(blockhash);
    if (!blockData) {
      throw this.rpcError(RPCErrorCodes.INVALID_ADDRESS_OR_KEY, "Block not found");
    }

    // Get block index record
    const blockIndex = await this.db.getBlockIndex(blockhash);
    if (!blockIndex) {
      throw this.rpcError(RPCErrorCodes.INVALID_ADDRESS_OR_KEY, "Block index not found");
    }

    // Verbosity 0: return hex
    if (verbosity === 0) {
      return blockData.toString("hex");
    }

    // Parse block
    const reader = new BufferReader(blockData);
    const block = deserializeBlock(reader);

    // Get header entry for chain work
    const headerEntry = this.headerSync.getHeader(blockhash);

    // Verbosity 1 or 2: return JSON
    const result: Record<string, unknown> = {
      hash: blockhashParam,
      confirmations: this.chainState.getBestBlock().height - blockIndex.height + 1,
      size: blockData.length,
      strippedsize: this.getStrippedSize(block),
      weight: this.getBlockWeight(block),
      height: blockIndex.height,
      version: block.header.version,
      versionHex: block.header.version.toString(16).padStart(8, "0"),
      merkleroot: block.header.merkleRoot.toString("hex"),
      time: block.header.timestamp,
      mediantime: headerEntry
        ? this.headerSync.getMedianTimePast(headerEntry)
        : block.header.timestamp,
      nonce: block.header.nonce,
      bits: block.header.bits.toString(16).padStart(8, "0"),
      difficulty: this.calculateDifficultyFromBits(block.header.bits),
      chainwork: headerEntry?.chainWork.toString(16).padStart(64, "0") ?? "0",
      nTx: block.transactions.length,
      previousblockhash: block.header.prevBlock.toString("hex"),
    };

    // Add next block hash if available
    const nextHash = await this.db.getBlockHashByHeight(blockIndex.height + 1);
    if (nextHash) {
      result.nextblockhash = nextHash.toString("hex");
    }

    // Add transactions
    if (verbosity === 1) {
      result.tx = block.transactions.map((tx) => getTxId(tx).toString("hex"));
    } else if (verbosity === 2) {
      result.tx = block.transactions.map((tx, index) =>
        this.formatTransaction(tx, blockhash, blockIndex.height, index)
      );
    }

    return result;
  }

  /**
   * getblockhash: Returns block hash at height.
   * @param params [height]
   */
  private async getBlockHash(params: unknown[]): Promise<string> {
    const [heightParam] = params;

    if (typeof heightParam !== "number" || !Number.isInteger(heightParam)) {
      throw this.rpcError(RPCErrorCodes.INVALID_PARAMS, "height must be an integer");
    }

    const height = heightParam;
    if (height < 0) {
      throw this.rpcError(RPCErrorCodes.INVALID_PARAMS, "height must be non-negative");
    }

    const bestBlock = this.chainState.getBestBlock();
    if (height > bestBlock.height) {
      throw this.rpcError(
        RPCErrorCodes.INVALID_PARAMS,
        "Block height out of range"
      );
    }

    const hash = await this.db.getBlockHashByHeight(height);
    if (!hash) {
      throw this.rpcError(RPCErrorCodes.INTERNAL_ERROR, "Block hash not found for height");
    }

    return hash.toString("hex");
  }

  /**
   * getblockheader: Returns header data.
   * @param params [blockhash, verbose]
   */
  private async getBlockHeader(params: unknown[]): Promise<unknown> {
    const [blockhashParam, verboseParam] = params;

    if (typeof blockhashParam !== "string") {
      throw this.rpcError(RPCErrorCodes.INVALID_PARAMS, "blockhash must be a string");
    }

    const blockhash = Buffer.from(blockhashParam, "hex");
    if (blockhash.length !== 32) {
      throw this.rpcError(RPCErrorCodes.INVALID_PARAMS, "Invalid blockhash length");
    }

    const verbose = verboseParam !== false;

    // Get block index record (contains the 80-byte header)
    const blockIndex = await this.db.getBlockIndex(blockhash);
    if (!blockIndex) {
      throw this.rpcError(RPCErrorCodes.INVALID_ADDRESS_OR_KEY, "Block header not found");
    }

    // If not verbose, return hex-encoded header
    if (!verbose) {
      return blockIndex.header.toString("hex");
    }

    // Parse header
    const headerBuf = blockIndex.header;
    const header: BlockHeader = {
      version: headerBuf.readInt32LE(0),
      prevBlock: Buffer.from(headerBuf.subarray(4, 36)),
      merkleRoot: Buffer.from(headerBuf.subarray(36, 68)),
      timestamp: headerBuf.readUInt32LE(68),
      bits: headerBuf.readUInt32LE(72),
      nonce: headerBuf.readUInt32LE(76),
    };

    // Get header entry for chain work
    const headerEntry = this.headerSync.getHeader(blockhash);

    const result: Record<string, unknown> = {
      hash: blockhashParam,
      confirmations: this.chainState.getBestBlock().height - blockIndex.height + 1,
      height: blockIndex.height,
      version: header.version,
      versionHex: header.version.toString(16).padStart(8, "0"),
      merkleroot: header.merkleRoot.toString("hex"),
      time: header.timestamp,
      mediantime: headerEntry
        ? this.headerSync.getMedianTimePast(headerEntry)
        : header.timestamp,
      nonce: header.nonce,
      bits: header.bits.toString(16).padStart(8, "0"),
      difficulty: this.calculateDifficultyFromBits(header.bits),
      chainwork: headerEntry?.chainWork.toString(16).padStart(64, "0") ?? "0",
      nTx: blockIndex.nTx,
      previousblockhash: header.prevBlock.toString("hex"),
    };

    // Add next block hash if available
    const nextHash = await this.db.getBlockHashByHeight(blockIndex.height + 1);
    if (nextHash) {
      result.nextblockhash = nextHash.toString("hex");
    }

    return result;
  }

  // ========== Transaction Methods ==========

  /**
   * getrawtransaction: Returns raw transaction data.
   * @param params [txid, verbose]
   */
  private async getRawTransaction(params: unknown[]): Promise<unknown> {
    const [txidParam, verboseParam] = params;

    if (typeof txidParam !== "string") {
      throw this.rpcError(RPCErrorCodes.INVALID_PARAMS, "txid must be a string");
    }

    const txid = Buffer.from(txidParam, "hex");
    if (txid.length !== 32) {
      throw this.rpcError(RPCErrorCodes.INVALID_PARAMS, "Invalid txid length");
    }

    const verbose = verboseParam === true || verboseParam === 1;

    // Check mempool first
    const mempoolEntry = this.mempool.getTransaction(txid);
    if (mempoolEntry) {
      const rawHex = serializeTx(mempoolEntry.tx, true).toString("hex");

      if (!verbose) {
        return rawHex;
      }

      return {
        ...this.formatTransaction(mempoolEntry.tx, null, -1, 0),
        hex: rawHex,
      };
    }

    // TODO: Implement tx index lookup for confirmed transactions
    // For now, we don't have a tx -> block index
    throw this.rpcError(
      RPCErrorCodes.INVALID_ADDRESS_OR_KEY,
      "Transaction not found in mempool. Confirmed transaction lookup not implemented."
    );
  }

  /**
   * sendrawtransaction: Decode, validate, add to mempool, broadcast to peers.
   * @param params [hexstring, maxfeerate]
   */
  private async sendRawTransaction(params: unknown[]): Promise<string> {
    const [hexstringParam] = params;

    if (typeof hexstringParam !== "string") {
      throw this.rpcError(RPCErrorCodes.INVALID_PARAMS, "hexstring must be a string");
    }

    // Parse the hex string
    let txData: Buffer;
    try {
      txData = Buffer.from(hexstringParam, "hex");
    } catch {
      throw this.rpcError(RPCErrorCodes.INVALID_PARAMS, "Invalid hex encoding");
    }

    // Deserialize the transaction
    let tx: Transaction;
    try {
      const reader = new BufferReader(txData);
      tx = deserializeTx(reader);
    } catch (e) {
      throw this.rpcError(
        RPCErrorCodes.VERIFY_REJECTED,
        `TX decode failed: ${(e as Error).message}`
      );
    }

    const txid = getTxId(tx);
    const txidHex = txid.toString("hex");

    // Check if already in mempool
    if (this.mempool.hasTransaction(txid)) {
      throw this.rpcError(
        RPCErrorCodes.VERIFY_ALREADY_IN_CHAIN,
        "Transaction already in mempool"
      );
    }

    // Add to mempool (includes validation)
    const result = await this.mempool.addTransaction(tx);
    if (!result.accepted) {
      throw this.rpcError(
        RPCErrorCodes.VERIFY_REJECTED,
        result.error || "Transaction rejected"
      );
    }

    // Broadcast to peers
    const invMsg: NetworkMessage = {
      type: "inv",
      payload: {
        inventory: [
          {
            type: InvType.MSG_WITNESS_TX,
            hash: txid,
          },
        ],
      },
    };
    this.peerManager.broadcast(invMsg);

    return txidHex;
  }

  // ========== Mempool Methods ==========

  /**
   * getmempoolinfo: Returns mempool statistics.
   */
  private async getMempoolInfo(): Promise<Record<string, unknown>> {
    const info = this.mempool.getInfo();

    return {
      loaded: true,
      size: info.size,
      bytes: info.bytes,
      usage: info.bytes, // Memory usage approximation
      maxmempool: 300_000_000, // Default max mempool size
      mempoolminfee: info.minFeeRate / 100_000, // Convert sat/vB to BTC/kvB
      minrelaytxfee: 0.00001, // 1 sat/vB
    };
  }

  /**
   * getrawmempool: Returns mempool transaction IDs.
   * @param params [verbose]
   */
  private async getRawMempool(params: unknown[]): Promise<unknown> {
    const [verboseParam] = params;
    const verbose = verboseParam === true;

    const txids = this.mempool.getAllTxids();

    if (!verbose) {
      return txids.map((txid) => txid.toString("hex"));
    }

    // Verbose: return detailed entries
    const result: Record<string, Record<string, unknown>> = {};

    for (const txid of txids) {
      const entry = this.mempool.getTransaction(txid);
      if (!entry) continue;

      const txidHex = txid.toString("hex");
      result[txidHex] = {
        vsize: entry.vsize,
        weight: entry.weight,
        fee: Number(entry.fee) / 100_000_000, // Convert to BTC
        modifiedfee: Number(entry.fee) / 100_000_000,
        time: entry.addedTime,
        height: entry.height,
        descendantcount: entry.spentBy.size + 1,
        descendantsize: entry.vsize, // Simplified
        descendantfees: Number(entry.fee),
        ancestorcount: entry.dependsOn.size + 1,
        ancestorsize: entry.vsize, // Simplified
        ancestorfees: Number(entry.fee),
        wtxid: txidHex, // Simplified (same as txid for non-witness txs)
        fees: {
          base: Number(entry.fee) / 100_000_000,
          modified: Number(entry.fee) / 100_000_000,
          ancestor: Number(entry.fee) / 100_000_000,
          descendant: Number(entry.fee) / 100_000_000,
        },
        depends: Array.from(entry.dependsOn),
        spentby: Array.from(entry.spentBy),
        "bip125-replaceable": false,
        unbroadcast: false,
      };
    }

    return result;
  }

  // ========== Fee Estimation ==========

  /**
   * estimatesmartfee: Estimates fee rate for confirmation target.
   * @param params [conf_target, estimate_mode]
   */
  private async estimateSmartFee(params: unknown[]): Promise<Record<string, unknown>> {
    const [confTargetParam] = params;

    if (typeof confTargetParam !== "number" || !Number.isInteger(confTargetParam)) {
      throw this.rpcError(RPCErrorCodes.INVALID_PARAMS, "conf_target must be an integer");
    }

    const confTarget = Math.max(1, Math.min(1008, confTargetParam));

    const estimate = this.feeEstimator.estimateSmartFee(confTarget);

    return {
      feerate: estimate.feeRate / 100_000, // Convert sat/vB to BTC/kvB
      blocks: estimate.blocks,
    };
  }

  // ========== Network Methods ==========

  /**
   * getpeerinfo: Returns information about connected peers.
   */
  private async getPeerInfo(): Promise<unknown[]> {
    const peers = this.peerManager.getConnectedPeers();

    return peers.map((peer, index) => ({
      id: index,
      addr: `${peer.host}:${peer.port}`,
      addrlocal: `127.0.0.1:${this.config.port}`,
      addrbind: `0.0.0.0:${peer.port}`,
      services: peer.versionPayload?.services.toString(16).padStart(16, "0") ?? "0000000000000000",
      servicesnames: this.getServiceNames(peer.versionPayload?.services ?? 0n),
      relaytxes: peer.versionPayload?.relay ?? true,
      lastsend: Math.floor(Date.now() / 1000),
      lastrecv: Math.floor(Date.now() / 1000),
      last_transaction: 0,
      last_block: 0,
      bytessent: 0,
      bytesrecv: 0,
      conntime: Math.floor(Date.now() / 1000),
      timeoffset: 0,
      pingtime: 0,
      minping: 0,
      version: peer.versionPayload?.version ?? 0,
      subver: peer.versionPayload?.userAgent ?? "",
      inbound: false,
      bip152_hb_to: false,
      bip152_hb_from: false,
      startingheight: peer.versionPayload?.startHeight ?? 0,
      presynced_headers: -1,
      synced_headers: -1,
      synced_blocks: -1,
      inflight: [],
      addr_relay_enabled: true,
      addr_processed: 0,
      addr_rate_limited: 0,
      permissions: [],
      minfeefilter: 0,
      bytessent_per_msg: {},
      bytesrecv_per_msg: {},
      connection_type: "outbound-full-relay",
      transport_protocol_type: "v1",
      session_id: "",
    }));
  }

  /**
   * getnetworkinfo: Returns network state information.
   */
  private async getNetworkInfo(): Promise<Record<string, unknown>> {
    const peers = this.peerManager.getConnectedPeers();

    return {
      version: this.params.protocolVersion,
      subversion: this.params.userAgent,
      protocolversion: this.params.protocolVersion,
      localservices: this.params.services.toString(16).padStart(16, "0"),
      localservicesnames: this.getServiceNames(this.params.services),
      localrelay: true,
      timeoffset: 0,
      networkactive: true,
      connections: peers.length,
      connections_in: 0,
      connections_out: peers.length,
      networks: [
        {
          name: "ipv4",
          limited: false,
          reachable: true,
          proxy: "",
          proxy_randomize_credentials: false,
        },
        {
          name: "ipv6",
          limited: false,
          reachable: true,
          proxy: "",
          proxy_randomize_credentials: false,
        },
      ],
      relayfee: 0.00001,
      incrementalfee: 0.00001,
      localaddresses: [],
      warnings: "",
    };
  }

  // ========== Ban Management ==========

  /**
   * listbanned: List all banned IPs/Subnets.
   */
  private async listBanned(): Promise<unknown[]> {
    const banned = this.peerManager.listBanned();

    return banned.map((entry) => ({
      address: entry.address,
      ban_created: entry.banCreated,
      banned_until: entry.banUntil,
      ban_reason: entry.reason,
    }));
  }

  /**
   * setban: Add or remove an IP/Subnet from the banned list.
   * @param params [ip, command, bantime, absolute]
   *   ip: IP address or subnet
   *   command: "add" or "remove"
   *   bantime: ban time in seconds (default: 24 hours), only for "add"
   *   absolute: if true, bantime is Unix timestamp (default: false)
   */
  private async setBan(params: unknown[]): Promise<null> {
    const [ipParam, commandParam, bantimeParam, absoluteParam] = params;

    if (typeof ipParam !== "string" || ipParam.length === 0) {
      throw this.rpcError(RPCErrorCodes.INVALID_PARAMS, "IP address required");
    }

    if (typeof commandParam !== "string") {
      throw this.rpcError(RPCErrorCodes.INVALID_PARAMS, "Command required (add or remove)");
    }

    const ip = ipParam;
    const command = commandParam.toLowerCase();

    if (command === "add") {
      const bantime = typeof bantimeParam === "number" ? bantimeParam : 24 * 60 * 60;
      const absolute = absoluteParam === true;

      if (bantime <= 0) {
        throw this.rpcError(RPCErrorCodes.INVALID_PARAMS, "Ban time must be positive");
      }

      this.peerManager.banAddress(ip, bantime, "manually banned via setban RPC");
      console.log(`Banned ${ip} for ${bantime} seconds`);
      return null;
    } else if (command === "remove") {
      const removed = this.peerManager.unbanAddress(ip);
      if (!removed) {
        throw this.rpcError(RPCErrorCodes.MISC_ERROR, `Error: IP/Subnet ${ip} is not banned`);
      }
      console.log(`Unbanned ${ip}`);
      return null;
    } else {
      throw this.rpcError(
        RPCErrorCodes.INVALID_PARAMS,
        "Invalid command. Use 'add' or 'remove'"
      );
    }
  }

  /**
   * clearbanned: Clear all banned IPs.
   */
  private async clearBanned(): Promise<null> {
    this.peerManager.clearBanned();
    console.log("Cleared all bans");
    return null;
  }

  // ========== Control Methods ==========

  /**
   * stop: Graceful node shutdown.
   */
  private async stopNode(): Promise<string> {
    // Schedule shutdown after response is sent
    setTimeout(() => {
      if (this.shutdownCallback) {
        this.shutdownCallback();
      }
      this.stop();
    }, 100);

    return "hotbuns stopping";
  }

  // ========== Helper Methods ==========

  /**
   * Create an RPC error with the given code and message.
   */
  private rpcError(code: number, message: string): Error & { code: number } {
    const error = new Error(message) as Error & { code: number };
    error.code = code;
    return error;
  }

  /**
   * Calculate difficulty from a block hash.
   */
  private async calculateDifficulty(blockhash: Buffer): Promise<number> {
    const blockIndex = await this.db.getBlockIndex(blockhash);
    if (!blockIndex) {
      return 1;
    }

    const bits = blockIndex.header.readUInt32LE(72);
    return this.calculateDifficultyFromBits(bits);
  }

  /**
   * Calculate difficulty from compact target (nBits).
   * difficulty = powLimit / currentTarget
   */
  private calculateDifficultyFromBits(bits: number): number {
    const target = compactToBigInt(bits);
    if (target === 0n) {
      return 1;
    }

    const powLimitTarget = compactToBigInt(this.params.powLimitBits);
    const difficulty = Number(powLimitTarget) / Number(target);

    return difficulty;
  }

  /**
   * Get stripped size of a block (without witness data).
   */
  private getStrippedSize(block: Block): number {
    let size = 80; // Header

    // varint tx count
    const txCount = block.transactions.length;
    if (txCount <= 0xfc) size += 1;
    else if (txCount <= 0xffff) size += 3;
    else if (txCount <= 0xffffffff) size += 5;
    else size += 9;

    // Transactions without witness
    for (const tx of block.transactions) {
      size += serializeTx(tx, false).length;
    }

    return size;
  }

  /**
   * Get block weight.
   */
  private getBlockWeight(block: Block): number {
    const strippedSize = this.getStrippedSize(block);
    const totalSize = serializeBlock(block).length;
    return strippedSize * 3 + totalSize;
  }

  /**
   * Format a transaction for RPC output.
   */
  private formatTransaction(
    tx: Transaction,
    blockhash: Buffer | null,
    height: number,
    txIndex: number
  ): Record<string, unknown> {
    const txid = getTxId(tx);

    const result: Record<string, unknown> = {
      txid: txid.toString("hex"),
      hash: txid.toString("hex"), // Same as txid for non-witness, different for witness
      version: tx.version,
      size: serializeTx(tx, true).length,
      vsize: getTxVSize(tx),
      weight: getTxWeight(tx),
      locktime: tx.lockTime,
      vin: tx.inputs.map((input, i) => {
        const vin: Record<string, unknown> = {
          txid: input.prevOut.txid.toString("hex"),
          vout: input.prevOut.vout,
          scriptSig: {
            asm: "", // Would need script decoder
            hex: input.scriptSig.toString("hex"),
          },
          sequence: input.sequence,
        };

        if (input.witness.length > 0) {
          vin.txinwitness = input.witness.map((w) => w.toString("hex"));
        }

        // Check if coinbase
        if (isCoinbase(tx) && i === 0) {
          vin.coinbase = input.scriptSig.toString("hex");
          delete vin.txid;
          delete vin.vout;
          delete vin.scriptSig;
        }

        return vin;
      }),
      vout: tx.outputs.map((output, i) => ({
        value: Number(output.value) / 100_000_000,
        n: i,
        scriptPubKey: {
          asm: "", // Would need script decoder
          hex: output.scriptPubKey.toString("hex"),
          type: this.getScriptType(output.scriptPubKey),
        },
      })),
    };

    if (blockhash) {
      result.blockhash = blockhash.toString("hex");
      result.confirmations = this.chainState.getBestBlock().height - height + 1;
      result.blocktime = 0; // Would need to look up block
      result.time = 0;
    }

    return result;
  }

  /**
   * Get script type name.
   */
  private getScriptType(scriptPubKey: Buffer): string {
    if (scriptPubKey.length === 25 && scriptPubKey[0] === 0x76) {
      return "pubkeyhash";
    }
    if (scriptPubKey.length === 23 && scriptPubKey[0] === 0xa9) {
      return "scripthash";
    }
    if (scriptPubKey.length === 22 && scriptPubKey[0] === 0x00 && scriptPubKey[1] === 0x14) {
      return "witness_v0_keyhash";
    }
    if (scriptPubKey.length === 34 && scriptPubKey[0] === 0x00 && scriptPubKey[1] === 0x20) {
      return "witness_v0_scripthash";
    }
    if (scriptPubKey.length === 34 && scriptPubKey[0] === 0x51 && scriptPubKey[1] === 0x20) {
      return "witness_v1_taproot";
    }
    if (scriptPubKey.length > 0 && scriptPubKey[0] === 0x6a) {
      return "nulldata";
    }
    return "nonstandard";
  }

  /**
   * Get service flag names.
   */
  private getServiceNames(services: bigint): string[] {
    const names: string[] = [];
    if (services & 1n) names.push("NETWORK");
    if (services & 4n) names.push("BLOOM");
    if (services & 8n) names.push("WITNESS");
    if (services & 1024n) names.push("NETWORK_LIMITED");
    return names;
  }
}
