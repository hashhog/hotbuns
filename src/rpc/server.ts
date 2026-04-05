/**
 * JSON-RPC 2.0 server using Bun.serve.
 *
 * Exposes Bitcoin Core-compatible RPC methods for querying blockchain state,
 * submitting transactions, and managing the node.
 */

import * as path from "path";
import type { ChainStateManager } from "../chain/state.js";
import type { ChainDB } from "../storage/database.js";
import type { Mempool, MempoolEntry } from "../mempool/mempool.js";
import { PackageValidationResult, MAX_PACKAGE_COUNT } from "../mempool/mempool.js";
import type { PeerManager } from "../p2p/manager.js";
import type { FeeEstimator } from "../fees/estimator.js";
import type { HeaderSync, HeaderChainEntry } from "../sync/headers.js";
import type { BlockSync } from "../sync/blocks.js";
import type { ConsensusParams } from "../consensus/params.js";
import { compactToBigInt, bigIntToCompact, getBlockSubsidy } from "../consensus/params.js";
import type { Block, BlockHeader } from "../validation/block.js";
import {
  deserializeBlock,
  serializeBlock,
  serializeBlockHeader,
  getBlockHash,
  computeMerkleRoot,
  computeWitnessMerkleRoot,
} from "../validation/block.js";
import { checkProofOfWork } from "../consensus/pow.js";
import { BlockTemplateBuilder } from "../mining/template.js";
import type { Transaction } from "../validation/tx.js";
import {
  deserializeTx,
  serializeTx,
  getTxId,
  getWTxId,
  getTxVSize,
  getTxWeight,
  hasWitness,
  isCoinbase,
} from "../validation/tx.js";
import { hash256 } from "../crypto/primitives.js";
import { BufferReader } from "../wire/serialization.js";
import type { InvPayload, NetworkMessage } from "../p2p/messages.js";
import { InvType } from "../p2p/messages.js";
import type { Wallet, WalletManager, CreateWalletOptions } from "../wallet/wallet.js";
import {
  parseDescriptor,
  getDescriptorInfo,
  deriveAddresses,
  addChecksum,
  type NetworkType,
} from "../wallet/descriptor.js";
import {
  ChainstateManager,
  computeUTXOSetHash,
  serializeSnapshotMetadata,
  deserializeSnapshotMetadata,
  deserializeCoinFromSnapshot,
  SNAPSHOT_MAGIC,
  SNAPSHOT_VERSION,
  type SnapshotMetadata,
  type LoadSnapshotResult,
  type DumpSnapshotResult,
} from "../chain/snapshot.js";

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
  /** Data directory for writing the .cookie file. */
  datadir?: string;
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
  pruneManager?: import("../storage/pruning.js").PruneManager;
  wallet?: Wallet;
  walletManager?: WalletManager;
  chainstateManager?: ChainstateManager;
  zmqInterface?: import("./zmq.js").ZMQNotificationInterface;
  blockSync?: BlockSync;
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
  // Transaction-related errors (sendrawtransaction)
  RPC_TRANSACTION_ERROR: -25,
  RPC_TRANSACTION_REJECTED: -26,
  RPC_TRANSACTION_ALREADY_IN_CHAIN: -27,
  // Legacy aliases for backward compatibility
  VERIFY_ALREADY_IN_CHAIN: -25,
  VERIFY_REJECTED: -26,
  // Wallet errors
  WALLET_ERROR: -4,
  WALLET_INSUFFICIENT_FUNDS: -6,
  WALLET_INVALID_LABEL_NAME: -11,
  WALLET_KEYPOOL_RAN_OUT: -12,
  WALLET_UNLOCK_NEEDED: -13,
  WALLET_PASSPHRASE_INCORRECT: -14,
  WALLET_WRONG_ENC_STATE: -15,
  WALLET_ENCRYPTION_FAILED: -16,
  WALLET_ALREADY_UNLOCKED: -17,
  WALLET_NOT_FOUND: -18,
  WALLET_NOT_SPECIFIED: -19,
} as const;

/**
 * Maximum number of requests allowed in a batch.
 * Prevents DoS via large batch requests.
 */
export const MAX_BATCH_SIZE = 1000;

/**
 * Default max fee rate for sendrawtransaction (0.10 BTC/kvB = 10000 sat/vB).
 * Transactions with fee rates higher than this are rejected to prevent
 * accidental fee overpayment.
 */
export const DEFAULT_MAX_FEE_RATE = 0.1; // BTC/kvB

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
  private pruneManager?: import("../storage/pruning.js").PruneManager;
  private wallet?: Wallet;
  private walletManager?: WalletManager;
  private chainstateManager?: ChainstateManager;
  private zmqInterface?: import("./zmq.js").ZMQNotificationInterface;
  private blockSync?: BlockSync;
  private shutdownCallback: (() => void) | null = null;
  /** Current wallet name for request context (set from URL path). */
  private currentWalletName: string | null = null;
  /** Cookie password generated on startup (hex-encoded random bytes). */
  private cookiePassword: string | null = null;
  /** Absolute path to the .cookie file written on startup. */
  private cookiePath: string | null = null;

  constructor(config: RPCServerConfig, deps: RPCServerDeps) {
    this.config = {
      port: config.port ?? 8332,
      host: config.host ?? "127.0.0.1",
      rpcUser: config.rpcUser,
      rpcPassword: config.rpcPassword,
      datadir: config.datadir,
    };
    this.chainState = deps.chainState;
    this.mempool = deps.mempool;
    this.peerManager = deps.peerManager;
    this.feeEstimator = deps.feeEstimator;
    this.headerSync = deps.headerSync;
    this.db = deps.db;
    this.params = deps.params;
    this.pruneManager = deps.pruneManager;
    this.wallet = deps.wallet;
    this.walletManager = deps.walletManager;
    this.chainstateManager = deps.chainstateManager;
    this.zmqInterface = deps.zmqInterface;
    this.blockSync = deps.blockSync;
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
   * Generates a 32-byte random cookie and writes `__cookie__:<hex>` to
   * `{datadir}/.cookie` so external tools can authenticate without a
   * configured rpcUser/rpcPassword.
   */
  start(): void {
    // Generate cookie credentials and persist them to disk.
    const cookieBytes = crypto.getRandomValues(new Uint8Array(32));
    this.cookiePassword = Buffer.from(cookieBytes).toString("hex");
    if (this.config.datadir) {
      this.cookiePath = path.join(this.config.datadir, ".cookie");
      // Bun.write is fire-and-forget here; errors are non-fatal but logged.
      Bun.write(this.cookiePath, `__cookie__:${this.cookiePassword}`).catch(
        (err) => console.error("Failed to write cookie file:", err)
      );
    }

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
   * Stop the server and remove the cookie file.
   */
  stop(): void {
    if (this.server) {
      this.server.stop();
      this.server = null;
    }
    // Remove cookie file so stale credentials cannot be reused after shutdown.
    if (this.cookiePath) {
      import("fs").then(({ promises: fsp }) =>
        fsp.unlink(this.cookiePath!).catch(() => { /* file may already be gone */ })
      );
      this.cookiePath = null;
    }
    this.cookiePassword = null;
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
          headers: { "Content-Type": "application/json", "Connection": "close" },
        }
      );
    }

    // Parse wallet name from URL path: /wallet/<name>
    // Reference: Bitcoin Core wallet-specific RPC endpoints
    const url = new URL(req.url);
    const pathParts = url.pathname.split("/").filter((p) => p !== "");
    if (pathParts.length >= 2 && pathParts[0] === "wallet") {
      // URL has /wallet/<name> prefix - use that wallet
      this.currentWalletName = decodeURIComponent(pathParts[1]);
    } else {
      // No wallet in URL - will use default if exactly one wallet loaded
      this.currentWalletName = null;
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
            "Connection": "close",
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
          headers: { "Content-Type": "application/json", "Connection": "close" },
        }
      );
    }

    // Handle batched requests
    if (Array.isArray(body)) {
      // Empty batch is an error
      if (body.length === 0) {
        return new Response(
          JSON.stringify({
            jsonrpc: "2.0",
            id: null,
            error: { code: RPCErrorCodes.INVALID_REQUEST, message: "Empty batch request" },
          }),
          {
            status: 200,
            headers: { "Content-Type": "application/json", "Connection": "close" },
          }
        );
      }

      // Limit batch size to prevent DoS
      if (body.length > MAX_BATCH_SIZE) {
        return new Response(
          JSON.stringify({
            jsonrpc: "2.0",
            id: null,
            error: {
              code: RPCErrorCodes.INVALID_REQUEST,
              message: `Batch size ${body.length} exceeds maximum of ${MAX_BATCH_SIZE}`,
            },
          }),
          {
            status: 200,
            headers: { "Content-Type": "application/json", "Connection": "close" },
          }
        );
      }

      // Process all requests in the batch (order preserved)
      const responses = await Promise.all(
        body.map((request) => this.processRequest(request))
      );
      return new Response(JSON.stringify(responses), {
        status: 200,
        headers: { "Content-Type": "application/json", "Connection": "close" },
      });
    }

    // Handle single request (must be an object)
    if (typeof body !== "object" || body === null) {
      return new Response(
        JSON.stringify({
          jsonrpc: "2.0",
          id: null,
          error: { code: RPCErrorCodes.PARSE_ERROR, message: "Top-level object parse error" },
        }),
        {
          status: 400,
          headers: { "Content-Type": "application/json", "Connection": "close" },
        }
      );
    }

    const response = await this.processRequest(body);
    return new Response(JSON.stringify(response), {
      status: 200,
      headers: { "Content-Type": "application/json", "Connection": "close" },
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
   *
   * Two credential sources are accepted (tried in order):
   *   1. Cookie auth — user `__cookie__`, password = hex cookie generated on startup.
   *   2. Configured rpcUser / rpcPassword (if both are set in config).
   *
   * If a cookie has been generated, an Authorization header is always required
   * (no unauthenticated access).  If neither a cookie nor rpcUser/rpcPassword
   * are configured the server falls back to allowing all connections (legacy
   * behaviour for development).
   */
  private authenticate(req: Request): boolean {
    const hasCookie = this.cookiePassword !== null;
    const hasConfiguredCreds =
      Boolean(this.config.rpcUser) && Boolean(this.config.rpcPassword);

    // If nothing is configured yet, allow all (shouldn't happen in practice
    // since start() always generates a cookie, but guards against edge cases).
    if (!hasCookie && !hasConfiguredCreds) {
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

    // Split on first colon only — passwords may contain colons.
    const colonIdx = credentials.indexOf(":");
    if (colonIdx === -1) {
      return false;
    }
    const user = credentials.slice(0, colonIdx);
    const password = credentials.slice(colonIdx + 1);

    // Cookie auth takes precedence.
    if (hasCookie && user === "__cookie__") {
      return password === this.cookiePassword;
    }

    // Fall back to configured rpcUser/rpcPassword.
    if (hasConfiguredCreds) {
      return user === this.config.rpcUser && password === this.config.rpcPassword;
    }

    return false;
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
    this.registerMethod("getblockcount", () => this.getBlockCount());
    this.registerMethod("getbestblockhash", () => this.getBestBlockHash());
    this.registerMethod("getchaintips", () => this.getChainTips());
    this.registerMethod("getdifficulty", () => this.getDifficulty());

    // Transaction methods
    this.registerMethod("getrawtransaction", (params) =>
      this.getRawTransaction(params)
    );
    this.registerMethod("sendrawtransaction", (params) =>
      this.sendRawTransaction(params)
    );
    this.registerMethod("submitpackage", (params) =>
      this.submitPackage(params)
    );
    this.registerMethod("decoderawtransaction", (params) =>
      this.decodeRawTransaction(params)
    );
    this.registerMethod("decodescript", (params) => this.decodeScript(params));
    this.registerMethod("createrawtransaction", (params) =>
      this.createRawTransaction(params)
    );

    // Mempool methods
    this.registerMethod("getmempoolinfo", () => this.getMempoolInfo());
    this.registerMethod("getrawmempool", (params) => this.getRawMempool(params));
    this.registerMethod("getmempoolentry", (params) => this.getMempoolEntry(params));
    this.registerMethod("testmempoolaccept", (params) => this.testMempoolAccept(params));
    this.registerMethod("getmempoolancestors", (params) => this.getMempoolAncestors(params));

    // Fee estimation
    this.registerMethod("estimatesmartfee", (params) =>
      this.estimateSmartFee(params)
    );

    // Network methods
    this.registerMethod("getpeerinfo", () => this.getPeerInfo());
    this.registerMethod("getnetworkinfo", () => this.getNetworkInfo());
    this.registerMethod("getconnectioncount", () => this.getConnectionCount());
    this.registerMethod("addnode", (params) => this.addNode(params));
    this.registerMethod("disconnectnode", (params) => this.disconnectNode(params));

    // Ban management
    this.registerMethod("listbanned", () => this.listBanned());
    this.registerMethod("setban", (params) => this.setBan(params));
    this.registerMethod("clearbanned", () => this.clearBanned());

    // Address validation
    this.registerMethod("validateaddress", (params) => this.validateAddress(params));

    // Mining methods
    this.registerMethod("getblocktemplate", (params) => this.getBlockTemplate(params));
    this.registerMethod("generatetoaddress", (params) => this.generateToAddress(params));
    this.registerMethod("generateblock", (params) => this.generateBlock(params));
    this.registerMethod("generatetodescriptor", (params) => this.generateToDescriptor(params));
    this.registerMethod("submitblock", (params) => this.submitBlock(params));
    this.registerMethod("getmininginfo", () => this.getMiningInfo());

    // Pruning methods
    this.registerMethod("pruneblockchain", (params) => this.pruneBlockchain(params));

    // Chain management methods
    this.registerMethod("invalidateblock", (params) => this.invalidateBlockRPC(params));
    this.registerMethod("reconsiderblock", (params) => this.reconsiderBlockRPC(params));
    this.registerMethod("preciousblock", (params) => this.preciousBlockRPC(params));

    // Control methods
    this.registerMethod("stop", () => this.stopNode());

    // Multi-wallet management methods (always available if walletManager is present)
    if (this.walletManager) {
      this.registerMethod("createwallet", (params) => this.createWallet(params));
      this.registerMethod("loadwallet", (params) => this.loadWallet(params));
      this.registerMethod("unloadwallet", (params) => this.unloadWallet(params));
      this.registerMethod("listwallets", () => this.listWallets());
      this.registerMethod("listwalletdir", () => this.listWalletDir());
    }

    // Wallet methods (available if wallet or walletManager is present)
    if (this.wallet || this.walletManager) {
      this.registerMethod("encryptwallet", (params) => this.encryptWallet(params));
      this.registerMethod("walletpassphrase", (params) => this.walletPassphrase(params));
      this.registerMethod("walletlock", () => this.walletLock());
      this.registerMethod("walletpassphrasechange", (params) => this.walletPassphraseChange(params));
      this.registerMethod("setlabel", (params) => this.setLabel(params));
      this.registerMethod("listreceivedbyaddress", (params) => this.listReceivedByAddress(params));
      this.registerMethod("listtransactions", (params) => this.listTransactions(params));
      this.registerMethod("getwalletinfo", () => this.getWalletInfo());
      this.registerMethod("getnewaddress", (params) => this.getNewAddress(params));
      this.registerMethod("getbalance", (params) => this.getBalance(params));
      this.registerMethod("sendtoaddress", (params) => this.sendToAddress(params));
      this.registerMethod("listunspent", (params) => this.listUnspent(params));
      this.registerMethod("signrawtransactionwithwallet", (params) =>
        this.signRawTransactionWithWallet(params)
      );
      this.registerMethod("importdescriptors", (params) =>
        this.importDescriptors(params)
      );
    }

    // Descriptor methods (work without wallet)
    this.registerMethod("getdescriptorinfo", (params) => this.getDescriptorInfo(params));
    this.registerMethod("deriveaddresses", (params) => this.deriveAddresses(params));

    // PSBT methods
    this.registerMethod("createpsbt", (params) => this.createPSBT(params));
    this.registerMethod("decodepsbt", (params) => this.decodePSBT(params));
    this.registerMethod("combinepsbt", (params) => this.combinePSBTs(params));
    this.registerMethod("finalizepsbt", (params) => this.finalizePSBT(params));

    // Utility methods
    this.registerMethod("help", (params) => this.help(params));

    // assumeUTXO methods
    this.registerMethod("loadtxoutset", (params) => this.loadTxoutset(params));
    this.registerMethod("dumptxoutset", (params) => this.dumpTxoutset(params));
    this.registerMethod("getutxosetsnapshot", () => this.getUtxoSetSnapshot());

    // ZMQ methods
    this.registerMethod("getzmqnotifications", () => this.getZMQNotifications());
  }

  // ========== Blockchain Methods ==========

  /**
   * getblockchaininfo: Returns blockchain state information.
   */
  private async getBlockchainInfo(): Promise<Record<string, unknown>> {
    // Use the in-memory best block which is updated by block sync after
    // each connected block via updateTip().  Do NOT call load() here — it
    // reads from the DB which is only written at flush boundaries (every
    // 2000 blocks), causing RPC to report a stale height.
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

    // Build softforks object
    const softforks = this.getSoftforkStatus(bestBlock.height);

    // Get pruning info
    const pruneInfo = this.pruneManager?.getPruneInfo() ?? {
      pruned: false,
      automatic_pruning: false,
    };

    const result: Record<string, unknown> = {
      chain,
      blocks: bestBlock.height,
      headers: headers,
      bestblockhash: Buffer.from(bestBlock.hash).reverse().toString("hex"),
      difficulty,
      mediantime,
      verificationprogress,
      chainwork: bestBlock.chainWork.toString(16).padStart(64, "0"),
      pruned: pruneInfo.pruned,
      softforks,
      warnings: "",
    };

    // Add pruning-specific fields if pruning is enabled
    if (pruneInfo.pruned && pruneInfo.pruneheight !== undefined) {
      result.pruneheight = pruneInfo.pruneheight;
    }
    if (pruneInfo.automatic_pruning) {
      result.automatic_pruning = true;
      if (pruneInfo.prune_target_size !== undefined) {
        result.prune_target_size = pruneInfo.prune_target_size;
      }
    }

    return result;
  }

  /**
   * Get softfork activation status for the current height.
   */
  private getSoftforkStatus(height: number): Record<string, unknown> {
    const softforks: Record<string, unknown> = {};

    // BIP34 (Height in coinbase)
    softforks.bip34 = {
      type: "buried",
      active: height >= this.params.bip34Height,
      height: this.params.bip34Height,
    };

    // BIP66 (Strict DER)
    softforks.bip66 = {
      type: "buried",
      active: height >= this.params.bip66Height,
      height: this.params.bip66Height,
    };

    // BIP65 (CLTV)
    softforks.bip65 = {
      type: "buried",
      active: height >= this.params.bip65Height,
      height: this.params.bip65Height,
    };

    // CSV (BIP68, BIP112, BIP113)
    softforks.csv = {
      type: "buried",
      active: height >= this.params.csvHeight,
      height: this.params.csvHeight,
    };

    // SegWit (BIP141, BIP143, BIP147)
    softforks.segwit = {
      type: "buried",
      active: height >= this.params.segwitHeight,
      height: this.params.segwitHeight,
    };

    // Taproot (BIP341, BIP342)
    softforks.taproot = {
      type: "buried",
      active: height >= this.params.taprootHeight,
      height: this.params.taprootHeight,
    };

    return softforks;
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

    // Get block index record first to check if pruned
    const blockIndex = await this.db.getBlockIndex(blockhash);
    if (!blockIndex) {
      throw this.rpcError(RPCErrorCodes.INVALID_ADDRESS_OR_KEY, "Block not found");
    }

    // Check if block data is pruned
    if (this.pruneManager?.isPruneMode() && this.pruneManager.isBlockPruned(blockIndex.height)) {
      throw this.rpcError(
        RPCErrorCodes.MISC_ERROR,
        "Block not available (pruned data)"
      );
    }

    // Get block data
    const blockData = await this.db.getBlock(blockhash);
    if (!blockData) {
      throw this.rpcError(RPCErrorCodes.MISC_ERROR, "Block not available (pruned data)");
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
      merkleroot: block.Buffer.from(header.merkleRoot).reverse().toString("hex"),
      time: block.header.timestamp,
      mediantime: headerEntry
        ? this.headerSync.getMedianTimePast(headerEntry)
        : block.header.timestamp,
      nonce: block.header.nonce,
      bits: block.header.bits.toString(16).padStart(8, "0"),
      difficulty: this.calculateDifficultyFromBits(block.header.bits),
      chainwork: headerEntry?.chainWork.toString(16).padStart(64, "0") ?? "0",
      nTx: block.transactions.length,
      previousblockhash: block.Buffer.from(header.prevBlock).reverse().toString("hex"),
    };

    // Add next block hash if available
    const nextHash = await this.db.getBlockHashByHeight(blockIndex.height + 1);
    if (nextHash) {
      result.nextblockhash = Buffer.from(nextHash).reverse().toString("hex");
    }

    // Add transactions
    if (verbosity === 1) {
      result.tx = block.transactions.map((tx) => Buffer.from(getTxId(tx)).reverse().toString("hex"));
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

    return Buffer.from(hash).reverse().toString("hex");
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
      merkleroot: Buffer.from(header.merkleRoot).reverse().toString("hex"),
      time: header.timestamp,
      mediantime: headerEntry
        ? this.headerSync.getMedianTimePast(headerEntry)
        : header.timestamp,
      nonce: header.nonce,
      bits: header.bits.toString(16).padStart(8, "0"),
      difficulty: this.calculateDifficultyFromBits(header.bits),
      chainwork: headerEntry?.chainWork.toString(16).padStart(64, "0") ?? "0",
      nTx: blockIndex.nTx,
      previousblockhash: Buffer.from(header.prevBlock).reverse().toString("hex"),
    };

    // Add next block hash if available
    const nextHash = await this.db.getBlockHashByHeight(blockIndex.height + 1);
    if (nextHash) {
      result.nextblockhash = Buffer.from(nextHash).reverse().toString("hex");
    }

    return result;
  }

  /**
   * getblockcount: Returns the number of blocks in the best valid chain.
   */
  private async getBlockCount(): Promise<number> {
    return this.chainState.getBestBlock().height;
  }

  /**
   * getbestblockhash: Returns the hash of the best (tip) block.
   */
  private async getBestBlockHash(): Promise<string> {
    return Buffer.from(this.chainState.getBestBlock().hash).reverse().toString("hex");
  }

  /**
   * getchaintips: Return information about all known tips in the block tree.
   * Returns an array of tips with status, height, and hash.
   */
  private async getChainTips(): Promise<Array<Record<string, unknown>>> {
    const tips: Array<Record<string, unknown>> = [];
    const bestBlock = this.chainState.getBestBlock();

    // For now, return just the active tip
    // A full implementation would track all fork tips
    tips.push({
      height: bestBlock.height,
      hash: Buffer.from(bestBlock.hash).reverse().toString("hex"),
      branchlen: 0,
      status: "active",
    });

    return tips;
  }

  /**
   * getdifficulty: Returns the current network difficulty.
   */
  private async getDifficulty(): Promise<number> {
    const bestBlock = this.chainState.getBestBlock();
    return this.calculateDifficulty(bestBlock.hash);
  }

  // ========== Transaction Methods ==========

  /**
   * getrawtransaction: Returns raw transaction data.
   *
   * @param params [txid, verbose, blockhash]
   *   - txid: The transaction id (hex string)
   *   - verbose: If false, return hex string. If true (or 1), return JSON object
   *   - blockhash: Optional block hash to look in
   *
   * Lookup priority:
   * 1. Mempool
   * 2. Specific block (if blockhash provided)
   * 3. TxIndex (if enabled)
   */
  private async getRawTransaction(params: unknown[]): Promise<unknown> {
    const [txidParam, verboseParam, blockhashParam] = params;

    if (typeof txidParam !== "string") {
      throw this.rpcError(RPCErrorCodes.INVALID_PARAMS, "txid must be a string");
    }

    const txid = Buffer.from(txidParam, "hex");
    if (txid.length !== 32) {
      throw this.rpcError(RPCErrorCodes.INVALID_PARAMS, "Invalid txid length");
    }

    // Parse verbose param: boolean or number (0/1/2 like Bitcoin Core)
    let verbose = false;
    if (verboseParam === true || verboseParam === 1 || verboseParam === 2) {
      verbose = true;
    }

    // Check mempool first (unless specific blockhash provided)
    if (blockhashParam === undefined || blockhashParam === null) {
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
    }

    // If blockhash provided, look in specific block
    if (blockhashParam !== undefined && blockhashParam !== null) {
      if (typeof blockhashParam !== "string") {
        throw this.rpcError(RPCErrorCodes.INVALID_PARAMS, "blockhash must be a string");
      }

      const blockhash = Buffer.from(blockhashParam, "hex");
      if (blockhash.length !== 32) {
        throw this.rpcError(RPCErrorCodes.INVALID_PARAMS, "Invalid blockhash length");
      }

      const result = await this.findTxInBlock(txid, blockhash, verbose);
      if (result) {
        return result;
      }

      throw this.rpcError(
        RPCErrorCodes.INVALID_ADDRESS_OR_KEY,
        "No such transaction found in the provided block"
      );
    }

    // Try txindex lookup
    const txIndexEntry = await this.db.getTxIndex(txid);
    if (txIndexEntry) {
      const result = await this.findTxInBlock(txid, txIndexEntry.blockHash, verbose);
      if (result) {
        return result;
      }
    }

    // Not found anywhere
    throw this.rpcError(
      RPCErrorCodes.INVALID_ADDRESS_OR_KEY,
      "No such mempool or blockchain transaction. Use gettransaction for wallet transactions."
    );
  }

  /**
   * Find a transaction in a specific block and format the result.
   */
  private async findTxInBlock(
    txid: Buffer,
    blockhash: Buffer,
    verbose: boolean
  ): Promise<unknown | null> {
    // Get block data
    const blockData = await this.db.getBlock(blockhash);
    if (!blockData) {
      return null;
    }

    // Get block index for height
    const blockIndex = await this.db.getBlockIndex(blockhash);
    if (!blockIndex) {
      return null;
    }

    // Parse block and find transaction
    const reader = new BufferReader(blockData);
    const block = deserializeBlock(reader);

    for (let i = 0; i < block.transactions.length; i++) {
      const tx = block.transactions[i];
      const currentTxid = getTxId(tx);

      if (currentTxid.equals(txid)) {
        const rawHex = serializeTx(tx, hasWitness(tx)).toString("hex");

        if (!verbose) {
          return rawHex;
        }

        // Get block time from header
        const blocktime = block.header.timestamp;
        const confirmations = this.chainState.getBestBlock().height - blockIndex.height + 1;

        return {
          ...this.formatTransactionVerbose(tx, blockhash, blockIndex.height, i),
          blockhash: Buffer.from(blockhash).reverse().toString("hex"),
          confirmations,
          time: blocktime,
          blocktime,
          hex: rawHex,
        };
      }
    }

    return null;
  }

  /**
   * Format a transaction for verbose RPC output with full details.
   */
  private formatTransactionVerbose(
    tx: Transaction,
    blockhash: Buffer | null,
    height: number,
    txIndex: number
  ): Record<string, unknown> {
    const txid = getTxId(tx);
    const wtxid = getWTxId(tx);
    const serializedWithWitness = serializeTx(tx, true);
    const serializedWithoutWitness = serializeTx(tx, false);
    const weight = getTxWeight(tx);
    const vsize = getTxVSize(tx);

    const result: Record<string, unknown> = {
      txid: Buffer.from(txid).reverse().toString("hex"),
      hash: wBuffer.from(txid).reverse().toString("hex"),
      version: tx.version,
      size: serializedWithWitness.length,
      vsize,
      weight,
      locktime: tx.lockTime,
      vin: tx.inputs.map((input, i) => {
        const vin: Record<string, unknown> = {};

        // Check if coinbase
        if (isCoinbase(tx) && i === 0) {
          vin.coinbase = input.scriptSig.toString("hex");
          vin.sequence = input.sequence;
        } else {
          vin.txid = input.prevOut.Buffer.from(txid).reverse().toString("hex");
          vin.vout = input.prevOut.vout;
          vin.scriptSig = {
            asm: this.disassembleScript(input.scriptSig),
            hex: input.scriptSig.toString("hex"),
          };
          vin.sequence = input.sequence;
        }

        if (input.witness.length > 0) {
          vin.txinwitness = input.witness.map((w) => w.toString("hex"));
        }

        return vin;
      }),
      vout: tx.outputs.map((output, i) => ({
        value: Number(output.value) / 100_000_000,
        n: i,
        scriptPubKey: this.formatScriptPubKey(output.scriptPubKey),
      })),
    };

    return result;
  }

  /**
   * Format scriptPubKey for RPC output.
   */
  private formatScriptPubKey(scriptPubKey: Buffer): Record<string, unknown> {
    const type = this.getScriptType(scriptPubKey);
    const result: Record<string, unknown> = {
      asm: this.disassembleScript(scriptPubKey),
      hex: scriptPubKey.toString("hex"),
      type,
    };

    // Add address if applicable
    const address = this.scriptPubKeyToAddress(scriptPubKey);
    if (address) {
      result.address = address;
    }

    return result;
  }

  /**
   * Basic script disassembly.
   */
  private disassembleScript(script: Buffer): string {
    if (script.length === 0) {
      return "";
    }

    const parts: string[] = [];
    let i = 0;

    while (i < script.length) {
      const op = script[i];

      // Push data opcodes
      if (op >= 0x01 && op <= 0x4b) {
        // OP_PUSHBYTES_N
        const len = op;
        if (i + 1 + len <= script.length) {
          const data = script.subarray(i + 1, i + 1 + len);
          parts.push(data.toString("hex"));
          i += 1 + len;
        } else {
          parts.push(`[error]`);
          break;
        }
      } else if (op === 0x4c) {
        // OP_PUSHDATA1
        if (i + 1 < script.length) {
          const len = script[i + 1];
          if (i + 2 + len <= script.length) {
            const data = script.subarray(i + 2, i + 2 + len);
            parts.push(data.toString("hex"));
            i += 2 + len;
          } else {
            parts.push(`[error]`);
            break;
          }
        } else {
          parts.push(`[error]`);
          break;
        }
      } else if (op === 0x4d) {
        // OP_PUSHDATA2
        if (i + 2 < script.length) {
          const len = script.readUInt16LE(i + 1);
          if (i + 3 + len <= script.length) {
            const data = script.subarray(i + 3, i + 3 + len);
            parts.push(data.toString("hex"));
            i += 3 + len;
          } else {
            parts.push(`[error]`);
            break;
          }
        } else {
          parts.push(`[error]`);
          break;
        }
      } else {
        // Standard opcode
        const opName = this.getOpcodeName(op);
        parts.push(opName);
        i++;
      }
    }

    return parts.join(" ");
  }

  /**
   * Get opcode name.
   */
  private getOpcodeName(op: number): string {
    const opcodes: Record<number, string> = {
      0x00: "OP_0",
      0x4f: "OP_1NEGATE",
      0x51: "OP_1",
      0x52: "OP_2",
      0x53: "OP_3",
      0x54: "OP_4",
      0x55: "OP_5",
      0x56: "OP_6",
      0x57: "OP_7",
      0x58: "OP_8",
      0x59: "OP_9",
      0x5a: "OP_10",
      0x5b: "OP_11",
      0x5c: "OP_12",
      0x5d: "OP_13",
      0x5e: "OP_14",
      0x5f: "OP_15",
      0x60: "OP_16",
      0x61: "OP_NOP",
      0x63: "OP_IF",
      0x64: "OP_NOTIF",
      0x67: "OP_ELSE",
      0x68: "OP_ENDIF",
      0x69: "OP_VERIFY",
      0x6a: "OP_RETURN",
      0x75: "OP_DROP",
      0x76: "OP_DUP",
      0x87: "OP_EQUAL",
      0x88: "OP_EQUALVERIFY",
      0x93: "OP_ADD",
      0x94: "OP_SUB",
      0xa9: "OP_HASH160",
      0xaa: "OP_HASH256",
      0xab: "OP_CODESEPARATOR",
      0xac: "OP_CHECKSIG",
      0xad: "OP_CHECKSIGVERIFY",
      0xae: "OP_CHECKMULTISIG",
      0xaf: "OP_CHECKMULTISIGVERIFY",
      0xb1: "OP_CHECKLOCKTIMEVERIFY",
      0xb2: "OP_CHECKSEQUENCEVERIFY",
    };

    return opcodes[op] || `OP_UNKNOWN[${op.toString(16)}]`;
  }

  /**
   * Convert scriptPubKey to address (basic support for standard types).
   */
  private scriptPubKeyToAddress(scriptPubKey: Buffer): string | null {
    // P2PKH: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
    if (scriptPubKey.length === 25 && scriptPubKey[0] === 0x76 && scriptPubKey[1] === 0xa9 &&
        scriptPubKey[2] === 0x14 && scriptPubKey[23] === 0x88 && scriptPubKey[24] === 0xac) {
      const hash = scriptPubKey.subarray(3, 23);
      return this.base58CheckEncode(hash, this.getP2PKHVersion());
    }

    // P2SH: OP_HASH160 <20 bytes> OP_EQUAL
    if (scriptPubKey.length === 23 && scriptPubKey[0] === 0xa9 && scriptPubKey[1] === 0x14 &&
        scriptPubKey[22] === 0x87) {
      const hash = scriptPubKey.subarray(2, 22);
      return this.base58CheckEncode(hash, this.getP2SHVersion());
    }

    // P2WPKH: OP_0 <20 bytes>
    if (scriptPubKey.length === 22 && scriptPubKey[0] === 0x00 && scriptPubKey[1] === 0x14) {
      const hash = scriptPubKey.subarray(2, 22);
      return this.bech32Encode(0, hash);
    }

    // P2WSH: OP_0 <32 bytes>
    if (scriptPubKey.length === 34 && scriptPubKey[0] === 0x00 && scriptPubKey[1] === 0x20) {
      const hash = scriptPubKey.subarray(2, 34);
      return this.bech32Encode(0, hash);
    }

    // P2TR: OP_1 <32 bytes>
    if (scriptPubKey.length === 34 && scriptPubKey[0] === 0x51 && scriptPubKey[1] === 0x20) {
      const hash = scriptPubKey.subarray(2, 34);
      return this.bech32mEncode(1, hash);
    }

    return null;
  }

  /**
   * Get P2PKH version byte based on network.
   */
  private getP2PKHVersion(): number {
    // Check network magic
    switch (this.params.networkMagic) {
      case 0xd9b4bef9: // mainnet
        return 0x00;
      case 0x0709110b: // testnet
      case 0xdab5bffa: // regtest
      case 0x1c163f28: // testnet4
      default:
        return 0x6f;
    }
  }

  /**
   * Get P2SH version byte based on network.
   */
  private getP2SHVersion(): number {
    switch (this.params.networkMagic) {
      case 0xd9b4bef9: // mainnet
        return 0x05;
      default:
        return 0xc4;
    }
  }

  /**
   * Get bech32 HRP based on network.
   */
  private getBech32HRP(): string {
    switch (this.params.networkMagic) {
      case 0xd9b4bef9: // mainnet
        return "bc";
      case 0x0709110b: // testnet
      case 0x1c163f28: // testnet4
        return "tb";
      case 0xdab5bffa: // regtest
        return "bcrt";
      default:
        return "tb";
    }
  }

  /**
   * Base58Check encode.
   */
  private base58CheckEncode(payload: Buffer, version: number): string {
    const versionBuf = Buffer.from([version]);
    const data = Buffer.concat([versionBuf, payload]);
    const checksum = hash256(data).subarray(0, 4);
    const full = Buffer.concat([data, checksum]);
    return this.base58Encode(full);
  }

  /**
   * Base58 encode.
   */
  private base58Encode(data: Buffer): string {
    const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let num = BigInt("0x" + data.toString("hex"));
    let result = "";

    while (num > 0n) {
      const mod = Number(num % 58n);
      result = ALPHABET[mod] + result;
      num = num / 58n;
    }

    // Handle leading zeros
    for (let i = 0; i < data.length && data[i] === 0; i++) {
      result = "1" + result;
    }

    return result;
  }

  /**
   * Bech32 encode (witness version 0).
   */
  private bech32Encode(witnessVersion: number, data: Buffer): string {
    const hrp = this.getBech32HRP();
    const converted = this.convertBits(data, 8, 5, true);
    if (!converted) return "";
    const values = [witnessVersion, ...converted];
    const checksum = this.createBech32Checksum(hrp, values, 1); // bech32
    const combined = [...values, ...checksum];

    const CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    let result = hrp + "1";
    for (const v of combined) {
      result += CHARSET[v];
    }
    return result;
  }

  /**
   * Bech32m encode (witness version 1+).
   */
  private bech32mEncode(witnessVersion: number, data: Buffer): string {
    const hrp = this.getBech32HRP();
    const converted = this.convertBits(data, 8, 5, true);
    if (!converted) return "";
    const values = [witnessVersion, ...converted];
    const checksum = this.createBech32Checksum(hrp, values, 0x2bc830a3); // bech32m
    const combined = [...values, ...checksum];

    const CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    let result = hrp + "1";
    for (const v of combined) {
      result += CHARSET[v];
    }
    return result;
  }

  /**
   * Convert bits between base sizes.
   */
  private convertBits(data: Buffer, fromBits: number, toBits: number, pad: boolean): number[] | null {
    let acc = 0;
    let bits = 0;
    const result: number[] = [];
    const maxV = (1 << toBits) - 1;

    for (let i = 0; i < data.length; i++) {
      acc = (acc << fromBits) | data[i];
      bits += fromBits;
      while (bits >= toBits) {
        bits -= toBits;
        result.push((acc >> bits) & maxV);
      }
    }

    if (pad) {
      if (bits > 0) {
        result.push((acc << (toBits - bits)) & maxV);
      }
    } else if (bits >= fromBits || ((acc << (toBits - bits)) & maxV)) {
      return null;
    }

    return result;
  }

  /**
   * Create bech32 checksum.
   */
  private createBech32Checksum(hrp: string, values: number[], encoding: number): number[] {
    const hrpExpanded = this.expandHRP(hrp);
    const polymod = this.polymod([...hrpExpanded, ...values, 0, 0, 0, 0, 0, 0]) ^ encoding;
    const checksum: number[] = [];
    for (let i = 0; i < 6; i++) {
      checksum.push((polymod >> (5 * (5 - i))) & 31);
    }
    return checksum;
  }

  /**
   * Expand HRP for checksum computation.
   */
  private expandHRP(hrp: string): number[] {
    const result: number[] = [];
    for (let i = 0; i < hrp.length; i++) {
      result.push(hrp.charCodeAt(i) >> 5);
    }
    result.push(0);
    for (let i = 0; i < hrp.length; i++) {
      result.push(hrp.charCodeAt(i) & 31);
    }
    return result;
  }

  /**
   * Bech32 polymod.
   */
  private polymod(values: number[]): number {
    const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    let chk = 1;
    for (const v of values) {
      const top = chk >> 25;
      chk = ((chk & 0x1ffffff) << 5) ^ v;
      for (let i = 0; i < 5; i++) {
        if ((top >> i) & 1) {
          chk ^= GEN[i];
        }
      }
    }
    return chk;
  }

  /**
   * sendrawtransaction: Decode, validate, add to mempool, broadcast to peers.
   *
   * @param params [hexstring, maxfeerate]
   *   - hexstring: The hex-encoded raw transaction
   *   - maxfeerate: (optional) Reject transactions whose fee rate is higher
   *                 than this value, in BTC/kvB. Default is 0.10 BTC/kvB.
   *                 Set to 0 to accept any fee rate.
   *
   * @returns The transaction hash (txid) in hex
   *
   * Error codes:
   *   - RPC_TRANSACTION_ERROR (-25): Generic TX error
   *   - RPC_TRANSACTION_REJECTED (-26): TX rejected by mempool policy
   *   - RPC_TRANSACTION_ALREADY_IN_CHAIN (-27): TX already confirmed in blockchain
   */
  private async sendRawTransaction(params: unknown[]): Promise<string> {
    const [hexstringParam, maxfeerateParam] = params;

    if (typeof hexstringParam !== "string") {
      throw this.rpcError(
        RPCErrorCodes.INVALID_PARAMS,
        "hexstring must be a string"
      );
    }

    // Parse maxfeerate parameter (default 0.10 BTC/kvB)
    let maxFeeRate = DEFAULT_MAX_FEE_RATE;
    if (maxfeerateParam !== undefined && maxfeerateParam !== null) {
      if (typeof maxfeerateParam !== "number") {
        throw this.rpcError(
          RPCErrorCodes.INVALID_PARAMS,
          "maxfeerate must be a number"
        );
      }
      if (maxfeerateParam < 0) {
        throw this.rpcError(
          RPCErrorCodes.INVALID_PARAMS,
          "maxfeerate cannot be negative"
        );
      }
      // Reject absurdly high fee rates (> 1 BTC/kvB)
      if (maxfeerateParam > 1) {
        throw this.rpcError(
          RPCErrorCodes.INVALID_PARAMS,
          "Fee rates larger than 1 BTC/kvB are rejected"
        );
      }
      maxFeeRate = maxfeerateParam;
    }

    // Parse the hex string
    let txData: Buffer;
    try {
      txData = Buffer.from(hexstringParam, "hex");
    } catch {
      throw this.rpcError(RPCErrorCodes.INVALID_PARAMS, "Invalid hex encoding");
    }

    // Validate hex has even length (each byte = 2 hex chars)
    if (hexstringParam.length % 2 !== 0) {
      throw this.rpcError(
        RPCErrorCodes.INVALID_PARAMS,
        "Invalid hex encoding (odd length)"
      );
    }

    // Deserialize the transaction
    let tx: Transaction;
    try {
      const reader = new BufferReader(txData);
      tx = deserializeTx(reader);
    } catch (e) {
      throw this.rpcError(
        RPCErrorCodes.RPC_TRANSACTION_REJECTED,
        `TX decode failed: ${(e as Error).message}`
      );
    }

    const txid = getTxId(tx);
    const txidHex = Buffer.from(txid).reverse().toString("hex");

    // Check if already in mempool (this is NOT an error per Bitcoin Core behavior)
    // We return the txid and consider it success - the tx is in the mempool already
    if (this.mempool.hasTransaction(txid)) {
      // Re-broadcast to peers in case they missed it
      this.broadcastTxInv(txid);
      return txidHex;
    }

    // Check if transaction is already confirmed in the blockchain
    const isConfirmed = await this.mempool.isTransactionConfirmed(txid);
    if (isConfirmed) {
      throw this.rpcError(
        RPCErrorCodes.RPC_TRANSACTION_ALREADY_IN_CHAIN,
        "Transaction already in block chain"
      );
    }

    // Calculate fee rate before adding to mempool to check maxfeerate
    // This requires knowing the fee, which we get from addTransaction
    // For now, we add to mempool first, then check fee rate
    // (mempool.addTransaction already validates minimum fee rate)

    // Add to mempool (includes validation)
    const result = await this.mempool.addTransaction(tx);
    if (!result.accepted) {
      throw this.rpcError(
        RPCErrorCodes.RPC_TRANSACTION_REJECTED,
        result.error || "Transaction rejected"
      );
    }

    // Now check maxfeerate if specified (and not 0 which means accept any rate)
    if (maxFeeRate > 0) {
      const entry = this.mempool.getTransaction(txid);
      if (entry) {
        // Convert fee rate from sat/vB to BTC/kvB for comparison
        // sat/vB * 1000 / 100_000_000 = BTC/kvB
        const feeRateBTCkvB = (entry.feeRate * 1000) / 100_000_000;
        if (feeRateBTCkvB > maxFeeRate) {
          // Remove from mempool since we're rejecting it
          this.mempool.removeTransaction(txid);
          throw this.rpcError(
            RPCErrorCodes.RPC_TRANSACTION_REJECTED,
            `Fee rate ${feeRateBTCkvB.toFixed(8)} BTC/kvB exceeds max rate ${maxFeeRate} BTC/kvB`
          );
        }
      }
    }

    // Broadcast inv to peers
    this.broadcastTxInv(txid);

    return txidHex;
  }

  /**
   * submitpackage: Submit a package of raw transactions to the mempool.
   *
   * Allows submission of related transactions together, enabling CPFP
   * (Child-Pays-For-Parent) fee bumping where a child transaction can
   * pay fees for its parent even if the parent is below minimum relay fee.
   *
   * @param params [package, maxfeerate, maxburnamount]
   *   - package: Array of hex-encoded raw transactions (topologically sorted)
   *   - maxfeerate: Optional max fee rate in BTC/kvB (default 0.10)
   *   - maxburnamount: Optional max amount for OP_RETURN outputs (default 0)
   *
   * @returns Object with:
   *   - package_msg: "success" or error message
   *   - tx-results: Object keyed by wtxid with per-tx results
   *   - replaced-transactions: Array of replaced txids (RBF)
   */
  private async submitPackage(params: unknown[]): Promise<Record<string, unknown>> {
    const [packageParam, maxfeerateParam, maxburnamountParam] = params;

    // Validate package parameter
    if (!Array.isArray(packageParam)) {
      throw this.rpcError(
        RPCErrorCodes.INVALID_PARAMS,
        "package must be an array of hex-encoded transactions"
      );
    }

    if (packageParam.length === 0 || packageParam.length > MAX_PACKAGE_COUNT) {
      throw this.rpcError(
        RPCErrorCodes.INVALID_PARAMS,
        `Array must contain between 1 and ${MAX_PACKAGE_COUNT} transactions.`
      );
    }

    // Parse maxfeerate parameter (default 0.10 BTC/kvB)
    let maxFeeRate = DEFAULT_MAX_FEE_RATE;
    if (maxfeerateParam !== undefined && maxfeerateParam !== null) {
      if (typeof maxfeerateParam !== "number") {
        throw this.rpcError(
          RPCErrorCodes.INVALID_PARAMS,
          "maxfeerate must be a number"
        );
      }
      if (maxfeerateParam < 0) {
        throw this.rpcError(
          RPCErrorCodes.INVALID_PARAMS,
          "maxfeerate cannot be negative"
        );
      }
      if (maxfeerateParam > 1) {
        throw this.rpcError(
          RPCErrorCodes.INVALID_PARAMS,
          "Fee rates larger than 1 BTC/kvB are rejected"
        );
      }
      maxFeeRate = maxfeerateParam;
    }

    // Parse maxburnamount parameter
    const maxBurnAmount = maxburnamountParam !== undefined && maxburnamountParam !== null
      ? Number(maxburnamountParam)
      : 0;

    // Deserialize all transactions
    const transactions: Transaction[] = [];
    for (let i = 0; i < packageParam.length; i++) {
      const rawtx = packageParam[i];

      if (typeof rawtx !== "string") {
        throw this.rpcError(
          RPCErrorCodes.INVALID_PARAMS,
          `Transaction at index ${i} must be a hex string`
        );
      }

      let txData: Buffer;
      try {
        txData = Buffer.from(rawtx, "hex");
      } catch {
        throw this.rpcError(
          RPCErrorCodes.INVALID_PARAMS,
          `TX decode failed at index ${i}: Invalid hex encoding`
        );
      }

      if (rawtx.length % 2 !== 0) {
        throw this.rpcError(
          RPCErrorCodes.INVALID_PARAMS,
          `TX decode failed at index ${i}: Odd hex length`
        );
      }

      let tx: Transaction;
      try {
        const reader = new BufferReader(txData);
        tx = deserializeTx(reader);
      } catch (e) {
        throw this.rpcError(
          RPCErrorCodes.RPC_TRANSACTION_REJECTED,
          `TX decode failed at index ${i}: ${(e as Error).message}`
        );
      }

      // Check max burn amount for OP_RETURN outputs
      for (const out of tx.outputs) {
        const isUnspendable = out.scriptPubKey.length > 0 &&
          (out.scriptPubKey[0] === 0x6a || // OP_RETURN
           (out.scriptPubKey.length >= 1 && out.scriptPubKey[0] === 0x00 && out.scriptPubKey.length === 1)); // OP_0 alone

        if (isUnspendable && Number(out.value) > maxBurnAmount * 100_000_000) {
          throw this.rpcError(
            RPCErrorCodes.RPC_TRANSACTION_REJECTED,
            `Transaction at index ${i} has unspendable output exceeding maxburnamount`
          );
        }
      }

      transactions.push(tx);
    }

    // Submit package to mempool
    const result = await this.mempool.submitPackage(transactions);

    // Build response
    const rpcResult: Record<string, unknown> = {
      package_msg: result.message,
    };

    // Build tx-results object keyed by wtxid
    const txResults: Record<string, Record<string, unknown>> = {};

    for (const [wtxid, txResult] of result.txResults) {
      const innerResult: Record<string, unknown> = {
        txid: txResult.txid,
      };

      if (txResult.error) {
        innerResult.error = txResult.error;
      } else {
        // Accepted
        if (txResult.vsize !== undefined) {
          innerResult.vsize = txResult.vsize;
        }

        if (txResult.fee !== undefined) {
          const fees: Record<string, unknown> = {
            base: Number(txResult.fee) / 100_000_000,
          };

          if (txResult.effectiveFeeRate !== undefined) {
            // Convert sat/vB to BTC/kvB
            fees["effective-feerate"] = (txResult.effectiveFeeRate * 1000) / 100_000_000;

            if (txResult.effectiveIncludes) {
              fees["effective-includes"] = txResult.effectiveIncludes;
            }
          }

          innerResult.fees = fees;
        }
      }

      txResults[wtxid] = innerResult;
    }

    rpcResult["tx-results"] = txResults;

    // Add replaced transactions
    rpcResult["replaced-transactions"] = result.replacedTxids;

    // Check fee rate for all accepted transactions if maxFeeRate is set
    if (maxFeeRate > 0) {
      for (const [wtxid, txResult] of result.txResults) {
        if (txResult.accepted && txResult.fee !== undefined && txResult.vsize !== undefined) {
          const feeRate = Number(txResult.fee) / txResult.vsize;
          const feeRateBTCkvB = (feeRate * 1000) / 100_000_000;

          if (feeRateBTCkvB > maxFeeRate) {
            // Remove accepted transactions from mempool
            for (const tx of transactions) {
              const txid = getTxId(tx);
              if (this.mempool.hasTransaction(txid)) {
                this.mempool.removeTransaction(txid);
              }
            }

            throw this.rpcError(
              RPCErrorCodes.RPC_TRANSACTION_REJECTED,
              `Package fee rate ${feeRateBTCkvB.toFixed(8)} BTC/kvB exceeds max rate ${maxFeeRate} BTC/kvB`
            );
          }
        }
      }
    }

    // Broadcast inv for all accepted transactions
    for (const [wtxid, txResult] of result.txResults) {
      if (txResult.accepted) {
        const txid = Buffer.from(txResult.txid, "hex");
        this.broadcastTxInv(txid);
      }
    }

    return rpcResult;
  }

  /**
   * Broadcast a transaction inventory message to all connected peers.
   */
  private broadcastTxInv(txid: Buffer): void {
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
  }

  /**
   * Broadcast a block inventory message to all connected peers.
   */
  private broadcastBlockInv(blockHash: Buffer): void {
    const invMsg: NetworkMessage = {
      type: "inv",
      payload: {
        inventory: [
          {
            type: InvType.MSG_BLOCK,
            hash: blockHash,
          },
        ],
      },
    };
    this.peerManager.broadcast(invMsg);
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
      return txids.map((txid) => Buffer.from(txid).reverse().toString("hex"));
    }

    // Verbose: return detailed entries
    const result: Record<string, Record<string, unknown>> = {};

    for (const txid of txids) {
      const entry = this.mempool.getTransaction(txid);
      if (!entry) continue;

      const txidHex = Buffer.from(txid).reverse().toString("hex");
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
        "bip125-replaceable": this.mempool.isReplaceable(txid),
        unbroadcast: false,
      };
    }

    return result;
  }

  /**
   * getmempoolentry: Returns mempool data for a given transaction.
   * @param params [txid]
   */
  private async getMempoolEntry(params: unknown[]): Promise<Record<string, unknown>> {
    const [txidParam] = params;

    if (typeof txidParam !== "string" || txidParam.length !== 64) {
      throw this.rpcError(RPCErrorCodes.INVALID_PARAMS, "txid must be a 64-character hex string");
    }

    const txid = Buffer.from(txidParam, "hex");
    const entry = this.mempool.getTransaction(txid);

    if (!entry) {
      throw this.rpcError(RPCErrorCodes.INVALID_ADDRESS_OR_KEY, "Transaction not in mempool");
    }

    // Get mining score (effective fee rate from cluster linearization)
    const miningScore = entry.miningScore;

    return {
      vsize: entry.vsize,
      weight: entry.weight,
      fee: Number(entry.fee) / 100_000_000,
      modifiedfee: Number(entry.fee) / 100_000_000,
      time: entry.addedTime,
      height: entry.height,
      descendantcount: entry.spentBy.size + 1,
      descendantsize: entry.vsize,
      descendantfees: Number(entry.fee),
      ancestorcount: entry.dependsOn.size + 1,
      ancestorsize: entry.vsize,
      ancestorfees: Number(entry.fee),
      wtxid: txidParam,
      fees: {
        base: Number(entry.fee) / 100_000_000,
        modified: Number(entry.fee) / 100_000_000,
        ancestor: Number(entry.fee) / 100_000_000,
        descendant: Number(entry.fee) / 100_000_000,
      },
      depends: Array.from(entry.dependsOn),
      spentby: Array.from(entry.spentBy),
      "bip125-replaceable": this.mempool.isReplaceable(txid),
      unbroadcast: false,
      // Cluster mempool fields
      miningScore: miningScore, // Effective fee rate (sat/vB) from chunk
    };
  }

  /**
   * testmempoolaccept: Test transaction(s) for mempool acceptance without submitting.
   * @param params [rawtxs, maxfeerate?]
   */
  private async testMempoolAccept(params: unknown[]): Promise<Array<Record<string, unknown>>> {
    const [rawtxsParam, maxfeerateParam] = params;

    if (!Array.isArray(rawtxsParam) || rawtxsParam.length === 0) {
      throw this.rpcError(
        RPCErrorCodes.INVALID_PARAMS,
        "rawtxs must be a non-empty array"
      );
    }

    if (rawtxsParam.length > 25) {
      throw this.rpcError(
        RPCErrorCodes.INVALID_PARAMS,
        "Array must contain between 1 and 25 transactions"
      );
    }

    // Parse maxfeerate (default 0.10 BTC/kvB)
    let maxFeeRate = DEFAULT_MAX_FEE_RATE;
    if (maxfeerateParam !== undefined && maxfeerateParam !== null) {
      if (typeof maxfeerateParam !== "number" || maxfeerateParam < 0) {
        throw this.rpcError(
          RPCErrorCodes.INVALID_PARAMS,
          "maxfeerate must be a non-negative number"
        );
      }
      maxFeeRate = maxfeerateParam;
    }

    const results: Array<Record<string, unknown>> = [];

    for (const rawtx of rawtxsParam) {
      if (typeof rawtx !== "string") {
        results.push({
          txid: "",
          allowed: false,
          "reject-reason": "TX decode failed: not a string",
        });
        continue;
      }

      try {
        const txData = Buffer.from(rawtx, "hex");
        const reader = new BufferReader(txData);
        const tx = deserializeTx(reader);
        const txid = getTxId(tx);
        const txidHex = Buffer.from(txid).reverse().toString("hex");

        // Check if already in mempool
        if (this.mempool.hasTransaction(txid)) {
          results.push({
            txid: txidHex,
            allowed: false,
            "reject-reason": "txn-already-in-mempool",
          });
          continue;
        }

        // Check if already confirmed
        const isConfirmed = await this.mempool.isTransactionConfirmed(txid);
        if (isConfirmed) {
          results.push({
            txid: txidHex,
            allowed: false,
            "reject-reason": "txn-already-known",
          });
          continue;
        }

        // Test mempool acceptance (dry run)
        const result = await this.mempool.addTransaction(tx, { dryRun: true });

        if (result.accepted) {
          const vsize = getTxVSize(tx);
          const feeRate = result.fee !== undefined ? Number(result.fee) / vsize : 0;
          const feeRateBTCkvB = (feeRate * 1000) / 100_000_000;

          // Check maxfeerate
          if (maxFeeRate > 0 && feeRateBTCkvB > maxFeeRate) {
            results.push({
              txid: txidHex,
              allowed: false,
              "reject-reason": `max-fee-exceeded`,
            });
          } else {
            const resultEntry: Record<string, unknown> = {
              txid: txidHex,
              wtxid: getWTxId(tx).toString("hex"),
              allowed: true,
              vsize,
              fees: {
                base: Number(result.fee ?? 0n) / 100_000_000,
              },
            };
            results.push(resultEntry);
          }
        } else {
          results.push({
            txid: txidHex,
            allowed: false,
            "reject-reason": result.error || "rejected",
          });
        }
      } catch (e) {
        const message = e instanceof Error ? e.message : String(e);
        results.push({
          txid: "",
          allowed: false,
          "reject-reason": `TX decode failed: ${message}`,
        });
      }
    }

    return results;
  }

  /**
   * getmempoolancestors: Get all in-mempool ancestors of a transaction.
   * @param params [txid, verbose?]
   */
  private async getMempoolAncestors(params: unknown[]): Promise<unknown> {
    const [txidParam, verboseParam] = params;

    if (typeof txidParam !== "string" || txidParam.length !== 64) {
      throw this.rpcError(
        RPCErrorCodes.INVALID_PARAMS,
        "txid must be a 64-character hex string"
      );
    }

    const txid = Buffer.from(txidParam, "hex");
    const entry = this.mempool.getTransaction(txid);

    if (!entry) {
      throw this.rpcError(
        RPCErrorCodes.INVALID_ADDRESS_OR_KEY,
        "Transaction not in mempool"
      );
    }

    const verbose = verboseParam === true;

    // Get all ancestors (dependsOn contains parent txids)
    const ancestors = new Set<string>(entry.dependsOn);

    // Recursively get ancestors of ancestors
    const visited = new Set<string>();
    const toVisit = [...ancestors];
    while (toVisit.length > 0) {
      const ancestorHex = toVisit.pop()!;
      if (visited.has(ancestorHex)) continue;
      visited.add(ancestorHex);

      const ancestorTxid = Buffer.from(ancestorHex, "hex");
      const ancestorEntry = this.mempool.getTransaction(ancestorTxid);
      if (ancestorEntry) {
        for (const parentHex of ancestorEntry.dependsOn) {
          if (!visited.has(parentHex)) {
            ancestors.add(parentHex);
            toVisit.push(parentHex);
          }
        }
      }
    }

    if (!verbose) {
      return Array.from(ancestors);
    }

    // Verbose mode: return detailed entries
    const result: Record<string, Record<string, unknown>> = {};
    for (const ancestorHex of ancestors) {
      const ancestorTxid = Buffer.from(ancestorHex, "hex");
      const ancestorEntry = this.mempool.getTransaction(ancestorTxid);
      if (ancestorEntry) {
        result[ancestorHex] = {
          vsize: ancestorEntry.vsize,
          weight: ancestorEntry.weight,
          fee: Number(ancestorEntry.fee) / 100_000_000,
          modifiedfee: Number(ancestorEntry.fee) / 100_000_000,
          time: ancestorEntry.addedTime,
          height: ancestorEntry.height,
          descendantcount: ancestorEntry.spentBy.size + 1,
          descendantsize: ancestorEntry.vsize,
          descendantfees: Number(ancestorEntry.fee),
          ancestorcount: ancestorEntry.dependsOn.size + 1,
          ancestorsize: ancestorEntry.vsize,
          ancestorfees: Number(ancestorEntry.fee),
          depends: Array.from(ancestorEntry.dependsOn),
          spentby: Array.from(ancestorEntry.spentBy),
          "bip125-replaceable": this.mempool.isReplaceable(ancestorTxid),
        };
      }
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

  // ========== Node Connection Management ==========

  /**
   * addnode: Add, remove, or try a connection to a node.
   * @param params [node, command] where command is "add", "remove", or "onetry"
   */
  private async addNode(params: unknown[]): Promise<null> {
    const [nodeParam, commandParam] = params;

    if (typeof nodeParam !== "string" || nodeParam.length === 0) {
      throw this.rpcError(RPCErrorCodes.INVALID_PARAMS, "Node address required");
    }
    if (typeof commandParam !== "string") {
      throw this.rpcError(RPCErrorCodes.INVALID_PARAMS, 'Command required ("add", "remove", or "onetry")');
    }

    const command = commandParam.toLowerCase();
    if (command !== "add" && command !== "remove" && command !== "onetry") {
      throw this.rpcError(RPCErrorCodes.INVALID_PARAMS, 'Command must be "add", "remove", or "onetry"');
    }

    // Parse host:port
    const lastColon = nodeParam.lastIndexOf(":");
    let host: string;
    let port: number;
    if (lastColon > 0) {
      host = nodeParam.slice(0, lastColon);
      port = parseInt(nodeParam.slice(lastColon + 1), 10);
    } else {
      host = nodeParam;
      port = this.params.defaultPort;
    }

    if (isNaN(port) || port <= 0 || port > 65535) {
      throw this.rpcError(RPCErrorCodes.INVALID_PARAMS, "Invalid port number");
    }

    if (command === "onetry" || command === "add") {
      try {
        await this.peerManager.connectPeer(host, port);
      } catch (err: unknown) {
        if (command === "add") {
          throw this.rpcError(
            RPCErrorCodes.MISC_ERROR,
            `Failed to connect: ${err instanceof Error ? err.message : String(err)}`
          );
        }
        // onetry silently ignores connection failure
      }
    } else if (command === "remove") {
      const key = `${host}:${port}`;
      this.peerManager.disconnectPeer(key);
    }

    return null;
  }

  /**
   * disconnectnode: Disconnect from a specified peer node.
   * @param params [address] or [{address: string}]
   */
  private async disconnectNode(params: unknown[]): Promise<null> {
    let address: string | undefined;

    if (typeof params[0] === "string") {
      address = params[0];
    } else if (typeof params[0] === "object" && params[0] !== null) {
      address = (params[0] as Record<string, unknown>).address as string | undefined;
    }

    if (!address || typeof address !== "string") {
      throw this.rpcError(RPCErrorCodes.INVALID_PARAMS, "Node address required");
    }

    // Parse host:port
    const lastColon = address.lastIndexOf(":");
    let host: string;
    let port: number;
    if (lastColon > 0) {
      host = address.slice(0, lastColon);
      port = parseInt(address.slice(lastColon + 1), 10);
    } else {
      host = address;
      port = this.params.defaultPort;
    }

    const key = `${host}:${port}`;
    const peers = this.peerManager.getConnectedPeers();
    const found = peers.some(p => `${p.host}:${p.port}` === key);
    if (!found) {
      throw this.rpcError(RPCErrorCodes.MISC_ERROR, `Node ${address} not found`);
    }

    this.peerManager.disconnectPeer(key);
    return null;
  }

  /**
   * getconnectioncount: Returns the number of connections to other nodes.
   */
  private getConnectionCount(): number {
    return this.peerManager.getConnectedPeers().length;
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

  // ========== Address Validation Methods ==========

  /**
   * validateaddress: Return information about the given Bitcoin address.
   * @param params [address]
   */
  private async validateAddress(params: unknown[]): Promise<Record<string, unknown>> {
    const [addressParam] = params;

    if (typeof addressParam !== "string") {
      throw this.rpcError(RPCErrorCodes.INVALID_PARAMS, "address must be a string");
    }

    const address = addressParam;
    const result: Record<string, unknown> = {};

    // Try to decode the address
    const decoded = this.decodeAddress(address);

    if (!decoded.valid) {
      result.isvalid = false;
      if (decoded.error) {
        result.error = decoded.error;
      }
      return result;
    }

    result.isvalid = true;
    result.address = address;
    result.scriptPubKey = decoded.scriptPubKey!.toString("hex");
    result.isscript = decoded.isScript;
    result.iswitness = decoded.isWitness;

    if (decoded.isWitness) {
      result.witness_version = decoded.witnessVersion;
      result.witness_program = decoded.witnessProgram!.toString("hex");
    }

    return result;
  }

  /**
   * Decode a Bitcoin address and return its components.
   */
  private decodeAddress(address: string): {
    valid: boolean;
    error?: string;
    scriptPubKey?: Buffer;
    isScript: boolean;
    isWitness: boolean;
    witnessVersion?: number;
    witnessProgram?: Buffer;
  } {
    // Try bech32/bech32m first
    if (address.startsWith("bc1") || address.startsWith("tb1") || address.startsWith("bcrt1")) {
      return this.decodeBech32Address(address);
    }

    // Try base58 (P2PKH or P2SH)
    return this.decodeBase58Address(address);
  }

  /**
   * Decode a bech32/bech32m address.
   */
  private decodeBech32Address(address: string): {
    valid: boolean;
    error?: string;
    scriptPubKey?: Buffer;
    isScript: boolean;
    isWitness: boolean;
    witnessVersion?: number;
    witnessProgram?: Buffer;
  } {
    const expectedHrp = this.getBech32HRP();

    // Find the separator
    const sepIndex = address.lastIndexOf("1");
    if (sepIndex === -1) {
      return { valid: false, error: "Invalid bech32 address: no separator", isScript: false, isWitness: false };
    }

    const hrp = address.slice(0, sepIndex).toLowerCase();
    if (hrp !== expectedHrp) {
      return { valid: false, error: `Invalid network prefix: expected ${expectedHrp}, got ${hrp}`, isScript: false, isWitness: false };
    }

    const dataStr = address.slice(sepIndex + 1).toLowerCase();
    if (dataStr.length < 7) {
      return { valid: false, error: "Invalid bech32 address: data too short", isScript: false, isWitness: false };
    }

    // Decode bech32 characters
    const CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    const values: number[] = [];
    for (const c of dataStr) {
      const idx = CHARSET.indexOf(c);
      if (idx === -1) {
        return { valid: false, error: `Invalid bech32 character: ${c}`, isScript: false, isWitness: false };
      }
      values.push(idx);
    }

    // Verify checksum (for both bech32 and bech32m)
    const hrpExpanded = this.expandHRP(hrp);
    const polymod = this.polymod([...hrpExpanded, ...values]);

    // bech32 uses constant 1, bech32m uses 0x2bc830a3
    const witnessVersion = values[0];
    const expectedConst = witnessVersion === 0 ? 1 : 0x2bc830a3;

    if (polymod !== expectedConst) {
      return { valid: false, error: "Invalid bech32 checksum", isScript: false, isWitness: false };
    }

    // Extract data (excluding checksum)
    const dataValues = values.slice(1, values.length - 6);

    // Convert from 5-bit to 8-bit
    const converted = this.convertBits(Buffer.from(dataValues), 5, 8, false);
    if (!converted) {
      return { valid: false, error: "Invalid witness program encoding", isScript: false, isWitness: false };
    }

    const witnessProgram = Buffer.from(converted);

    // Validate witness program length
    if (witnessVersion === 0) {
      if (witnessProgram.length !== 20 && witnessProgram.length !== 32) {
        return { valid: false, error: "Invalid witness v0 program length", isScript: false, isWitness: false };
      }
    } else if (witnessVersion === 1) {
      if (witnessProgram.length !== 32) {
        return { valid: false, error: "Invalid witness v1 program length", isScript: false, isWitness: false };
      }
    } else if (witnessProgram.length < 2 || witnessProgram.length > 40) {
      return { valid: false, error: "Invalid witness program length", isScript: false, isWitness: false };
    }

    // Build scriptPubKey: OP_n <program>
    const versionOpcode = witnessVersion === 0 ? 0x00 : 0x50 + witnessVersion;
    const scriptPubKey = Buffer.concat([
      Buffer.from([versionOpcode, witnessProgram.length]),
      witnessProgram,
    ]);

    return {
      valid: true,
      scriptPubKey,
      isScript: witnessVersion === 0 && witnessProgram.length === 32, // P2WSH
      isWitness: true,
      witnessVersion,
      witnessProgram,
    };
  }

  /**
   * Decode a base58check address (P2PKH or P2SH).
   */
  private decodeBase58Address(address: string): {
    valid: boolean;
    error?: string;
    scriptPubKey?: Buffer;
    isScript: boolean;
    isWitness: boolean;
  } {
    // Decode base58
    const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let num = 0n;

    for (const c of address) {
      const idx = ALPHABET.indexOf(c);
      if (idx === -1) {
        return { valid: false, error: `Invalid base58 character: ${c}`, isScript: false, isWitness: false };
      }
      num = num * 58n + BigInt(idx);
    }

    // Convert to bytes
    let hex = num.toString(16);
    if (hex.length % 2) hex = "0" + hex;
    let decoded = Buffer.from(hex, "hex");

    // Handle leading zeros (represented as '1' in base58)
    let leadingZeros = 0;
    for (const c of address) {
      if (c === "1") leadingZeros++;
      else break;
    }
    if (leadingZeros > 0) {
      decoded = Buffer.concat([Buffer.alloc(leadingZeros, 0), decoded]);
    }

    // Address must be 25 bytes (1 version + 20 hash + 4 checksum)
    if (decoded.length !== 25) {
      return { valid: false, error: "Invalid address length", isScript: false, isWitness: false };
    }

    // Verify checksum
    const payload = decoded.subarray(0, 21);
    const checksum = decoded.subarray(21, 25);
    const expectedChecksum = hash256(payload).subarray(0, 4);

    if (!checksum.equals(expectedChecksum)) {
      return { valid: false, error: "Invalid checksum", isScript: false, isWitness: false };
    }

    const version = decoded[0];
    const pubKeyHash = decoded.subarray(1, 21);

    // Determine address type based on version byte
    const p2pkhVersion = this.getP2PKHVersion();
    const p2shVersion = this.getP2SHVersion();

    if (version === p2pkhVersion) {
      // P2PKH: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
      const scriptPubKey = Buffer.concat([
        Buffer.from([0x76, 0xa9, 0x14]),
        pubKeyHash,
        Buffer.from([0x88, 0xac]),
      ]);
      return { valid: true, scriptPubKey, isScript: false, isWitness: false };
    } else if (version === p2shVersion) {
      // P2SH: OP_HASH160 <20 bytes> OP_EQUAL
      const scriptPubKey = Buffer.concat([
        Buffer.from([0xa9, 0x14]),
        pubKeyHash,
        Buffer.from([0x87]),
      ]);
      return { valid: true, scriptPubKey, isScript: true, isWitness: false };
    } else {
      return { valid: false, error: `Unknown address version: ${version}`, isScript: false, isWitness: false };
    }
  }

  // ========== Mining Methods ==========

  /**
   * submitblock: Attempts to submit a new block to the network.
   * Accepts a hex-encoded serialized block.
   *
   * @param params [hexdata] - hex-encoded serialized block
   * @returns null on success, string error message on failure
   */
  private async submitBlock(params: unknown[]): Promise<unknown> {
    const [hexdata] = params;
    if (typeof hexdata !== "string") {
      throw this.rpcError(RPCErrorCodes.INVALID_PARAMS, "hex string required");
    }

    // Deserialize the block from hex
    let block: Block;
    try {
      const buf = Buffer.from(hexdata, "hex");
      const reader = new (await import("../wire/serialization.js")).BufferReader(buf);
      block = deserializeBlock(reader);
    } catch (err) {
      throw this.rpcError(
        RPCErrorCodes.MISC_ERROR,
        `Block decode failed: ${err instanceof Error ? err.message : String(err)}`
      );
    }

    // If we have a BlockSync instance, inject the block directly
    if (this.blockSync) {
      const result = await this.blockSync.injectBlock(block);
      return result; // null = success, string = error reason
    }

    throw this.rpcError(RPCErrorCodes.MISC_ERROR, "Block sync not available");
  }

  /**
   * getblocktemplate: Returns data needed to construct a block to work on.
   * Implements BIP22/23 for mining pool compatibility.
   *
   * @param params [template_request] - object with mode, rules, capabilities, etc.
   */
  private async getBlockTemplate(params: unknown[]): Promise<Record<string, unknown>> {
    const [templateRequest] = params;

    // Parse template request
    let mode = "template";
    let clientRules: Set<string> = new Set();

    if (templateRequest && typeof templateRequest === "object") {
      const request = templateRequest as Record<string, unknown>;

      if (request.mode !== undefined) {
        if (typeof request.mode !== "string") {
          throw this.rpcError(RPCErrorCodes.INVALID_PARAMS, "Invalid mode");
        }
        mode = request.mode;
      }

      if (request.rules && Array.isArray(request.rules)) {
        for (const rule of request.rules) {
          if (typeof rule === "string") {
            clientRules.add(rule);
          }
        }
      }
    }

    // Only "template" mode is supported (proposal mode would need block validation)
    if (mode !== "template") {
      throw this.rpcError(RPCErrorCodes.INVALID_PARAMS, "Only 'template' mode is supported");
    }

    // Check that segwit rule is set
    if (!clientRules.has("segwit")) {
      throw this.rpcError(
        RPCErrorCodes.INVALID_PARAMS,
        "getblocktemplate must be called with the segwit rule set (call with {\"rules\": [\"segwit\"]})"
      );
    }

    // Get current chain state
    const bestBlock = this.chainState.getBestBlock();
    const height = bestBlock.height + 1;

    // Get mempool transactions
    const mempoolTxids = this.mempool.getAllTxids();
    const transactions: Record<string, unknown>[] = [];
    const txIndex: Map<string, number> = new Map();
    let totalFees = 0n;
    let totalWeight = 0;
    let totalSigOps = 0;

    let idx = 1; // 1-based index (coinbase is 0)
    for (const txid of mempoolTxids) {
      const entry = this.mempool.getTransaction(txid);
      if (!entry) continue;

      const txidHex = Buffer.from(txid).reverse().toString("hex");
      txIndex.set(txidHex, idx);

      // Calculate dependencies (other transactions in the template that must come before)
      const depends: number[] = [];
      for (const parentTxidHex of entry.dependsOn) {
        const parentIdx = txIndex.get(parentTxidHex);
        if (parentIdx !== undefined) {
          depends.push(parentIdx);
        }
      }

      const txData = serializeTx(entry.tx, true);

      transactions.push({
        data: txData.toString("hex"),
        txid: txidHex,
        hash: getWTxId(entry.tx).toString("hex"),
        depends,
        fee: Number(entry.fee),
        sigops: 0, // Would need proper sigop counting
        weight: entry.weight,
      });

      totalFees += entry.fee;
      totalWeight += entry.weight;
      idx++;
    }

    // Calculate coinbase value (subsidy + fees)
    const subsidy = this.getBlockSubsidy(height);
    const coinbaseValue = subsidy + totalFees;

    // Calculate target from current difficulty
    const target = compactToBigInt(this.params.powLimitBits);
    const targetHex = target.toString(16).padStart(64, "0");

    // Get previous block hash
    const previousblockhash = Buffer.from(bestBlock.hash).reverse().toString("hex");

    // Calculate current time and minimum time
    const curtime = Math.floor(Date.now() / 1000);
    const mintime = curtime; // Simplified; should be MTP + 1

    // Calculate bits (difficulty target in compact format)
    const bits = this.params.powLimitBits.toString(16).padStart(8, "0");

    // Build the result
    const result: Record<string, unknown> = {
      capabilities: ["proposal"],
      version: 0x20000000, // BIP9 version bits
      rules: ["csv", "!segwit"],
      vbavailable: {},
      vbrequired: 0,
      previousblockhash,
      transactions,
      coinbaseaux: {},
      coinbasevalue: Number(coinbaseValue),
      longpollid: `${previousblockhash}${idx}`,
      target: targetHex,
      mintime,
      mutable: ["time", "transactions", "prevblock"],
      noncerange: "00000000ffffffff",
      sigoplimit: 80000, // MAX_BLOCK_SIGOPS_COST
      sizelimit: 4000000, // MAX_BLOCK_SERIALIZED_SIZE
      weightlimit: 4000000, // MAX_BLOCK_WEIGHT
      curtime,
      bits,
      height,
    };

    // Add default witness commitment if we have transactions
    if (transactions.length > 0) {
      // The witness commitment would be calculated from the wtxids
      // For now, we just indicate that it should be included
      // In a full implementation, this would be the actual commitment script
      const witnessCommitmentHeader = "6a24aa21a9ed";
      result.default_witness_commitment = witnessCommitmentHeader + "0".repeat(64);
    }

    return result;
  }

  /**
   * generatetoaddress: Mine blocks with coinbase reward to the specified address.
   *
   * This is only available in regtest mode.
   *
   * @param params [nblocks, address, maxtries?] - Number of blocks, coinbase address, optional max nonce tries
   * @returns Array of block hashes (hex strings)
   */
  private async generateToAddress(params: unknown[]): Promise<string[]> {
    const [nblocksParam, addressParam, maxtries] = params;

    // Validate nblocks
    if (typeof nblocksParam !== "number" || !Number.isInteger(nblocksParam) || nblocksParam < 0) {
      throw this.rpcError(RPCErrorCodes.INVALID_PARAMS, "nblocks must be a non-negative integer");
    }
    const nblocks = nblocksParam;

    // Validate address
    if (typeof addressParam !== "string") {
      throw this.rpcError(RPCErrorCodes.INVALID_PARAMS, "address must be a string");
    }

    // Check this is regtest (we only allow generate RPCs on regtest)
    if (!this.params.fPowNoRetargeting) {
      throw this.rpcError(
        RPCErrorCodes.MISC_ERROR,
        "generatetoaddress is only available in regtest mode"
      );
    }

    // Decode address to get scriptPubKey
    const decoded = this.decodeAddress(addressParam);
    if (!decoded.valid || !decoded.scriptPubKey) {
      throw this.rpcError(
        RPCErrorCodes.INVALID_ADDRESS_OR_KEY,
        decoded.error || "Invalid address"
      );
    }

    const coinbaseScript = decoded.scriptPubKey;
    const maxTries = typeof maxtries === "number" ? maxtries : 1000000;

    return this.generateBlocks(nblocks, coinbaseScript, maxTries);
  }

  /**
   * generatetodescriptor: Mine blocks with coinbase reward to the specified descriptor.
   *
   * This is only available in regtest mode.
   *
   * @param params [nblocks, descriptor, maxtries?] - Number of blocks, output descriptor, optional max tries
   * @returns Array of block hashes (hex strings)
   */
  private async generateToDescriptor(params: unknown[]): Promise<string[]> {
    const [nblocksParam, descriptorParam, maxtries] = params;

    // Validate nblocks
    if (typeof nblocksParam !== "number" || !Number.isInteger(nblocksParam) || nblocksParam < 0) {
      throw this.rpcError(RPCErrorCodes.INVALID_PARAMS, "nblocks must be a non-negative integer");
    }
    const nblocks = nblocksParam;

    // Validate descriptor
    if (typeof descriptorParam !== "string") {
      throw this.rpcError(RPCErrorCodes.INVALID_PARAMS, "descriptor must be a string");
    }

    // Check this is regtest
    if (!this.params.fPowNoRetargeting) {
      throw this.rpcError(
        RPCErrorCodes.MISC_ERROR,
        "generatetodescriptor is only available in regtest mode"
      );
    }

    // Parse descriptor and derive script
    try {
      // Determine network type from params
      const networkType = this.getNetworkType();

      // Get addresses from descriptor (just need first one)
      const addresses = deriveAddresses(descriptorParam, networkType);
      if (addresses.length === 0) {
        throw this.rpcError(RPCErrorCodes.INVALID_ADDRESS_OR_KEY, "Cannot derive address from descriptor");
      }

      // Decode the first address to get scriptPubKey
      const decoded = this.decodeAddress(addresses[0]);
      if (!decoded.valid || !decoded.scriptPubKey) {
        throw this.rpcError(
          RPCErrorCodes.INVALID_ADDRESS_OR_KEY,
          decoded.error || "Cannot derive valid address from descriptor"
        );
      }

      const coinbaseScript = decoded.scriptPubKey;
      const maxTries = typeof maxtries === "number" ? maxtries : 1000000;

      return this.generateBlocks(nblocks, coinbaseScript, maxTries);
    } catch (e) {
      if (e instanceof Error && "code" in e) {
        throw e; // Re-throw RPC errors
      }
      const message = e instanceof Error ? e.message : String(e);
      throw this.rpcError(RPCErrorCodes.INVALID_ADDRESS_OR_KEY, `Invalid descriptor: ${message}`);
    }
  }

  /**
   * generateblock: Mine a block containing specific transactions.
   *
   * This is only available in regtest mode.
   *
   * @param params [output, transactions, submit?] - Output address/descriptor, array of txids or raw txs, whether to submit
   * @returns Object with hash (and hex if submit=false)
   */
  private async generateBlock(params: unknown[]): Promise<Record<string, string>> {
    const [outputParam, transactionsParam, submitParam] = params;

    // Validate output (address or descriptor)
    if (typeof outputParam !== "string") {
      throw this.rpcError(RPCErrorCodes.INVALID_PARAMS, "output must be a string (address or descriptor)");
    }

    // Validate transactions array
    if (!Array.isArray(transactionsParam)) {
      throw this.rpcError(RPCErrorCodes.INVALID_PARAMS, "transactions must be an array");
    }

    // Check this is regtest
    if (!this.params.fPowNoRetargeting) {
      throw this.rpcError(
        RPCErrorCodes.MISC_ERROR,
        "generateblock is only available in regtest mode"
      );
    }

    // Parse output to get scriptPubKey - try as address first, then as descriptor
    let coinbaseScript: Buffer;

    const decoded = this.decodeAddress(outputParam);
    if (decoded.valid && decoded.scriptPubKey) {
      coinbaseScript = decoded.scriptPubKey;
    } else {
      // Try as descriptor
      try {
        const networkType = this.getNetworkType();
        const addresses = deriveAddresses(outputParam, networkType);
        if (addresses.length === 0) {
          throw new Error("Cannot derive address from descriptor");
        }
        const descDecoded = this.decodeAddress(addresses[0]);
        if (!descDecoded.valid || !descDecoded.scriptPubKey) {
          throw new Error(descDecoded.error || "Invalid derived address");
        }
        coinbaseScript = descDecoded.scriptPubKey;
      } catch (e) {
        const message = e instanceof Error ? e.message : String(e);
        throw this.rpcError(RPCErrorCodes.INVALID_ADDRESS_OR_KEY, `Invalid output: ${message}`);
      }
    }

    const submit = submitParam !== false;

    // Collect transactions
    const txs: Transaction[] = [];
    for (const item of transactionsParam) {
      if (typeof item !== "string") {
        throw this.rpcError(RPCErrorCodes.INVALID_PARAMS, "transaction must be a hex string (txid or raw tx)");
      }

      // Check if it's a 64-char txid or a raw transaction hex
      if (item.length === 64 && /^[0-9a-fA-F]+$/.test(item)) {
        // It's a txid - look up in mempool
        const txid = Buffer.from(item, "hex");
        const entry = this.mempool.getTransaction(txid);
        if (!entry) {
          throw this.rpcError(
            RPCErrorCodes.INVALID_ADDRESS_OR_KEY,
            `Transaction ${item} not in mempool`
          );
        }
        txs.push(entry.tx);
      } else {
        // It's a raw transaction hex - decode it
        try {
          const rawTx = Buffer.from(item, "hex");
          const reader = new BufferReader(rawTx);
          const tx = deserializeTx(reader);
          txs.push(tx);
        } catch (e) {
          const message = e instanceof Error ? e.message : String(e);
          throw this.rpcError(
            RPCErrorCodes.INVALID_PARAMS,
            `Failed to decode transaction: ${message}`
          );
        }
      }
    }

    // Generate a single block with these transactions
    const result = await this.generateSingleBlock(coinbaseScript, txs, submit);

    if (submit) {
      return { hash: result.hash };
    } else {
      return { hash: result.hash, hex: result.hex! };
    }
  }

  /**
   * Generate multiple blocks with coinbase to the given script.
   */
  private async generateBlocks(
    nblocks: number,
    coinbaseScript: Buffer,
    maxTries: number
  ): Promise<string[]> {
    const blockHashes: string[] = [];

    for (let i = 0; i < nblocks; i++) {
      const result = await this.generateSingleBlock(coinbaseScript, [], true, maxTries);
      blockHashes.push(result.hash);
    }

    return blockHashes;
  }

  /**
   * Generate a single block.
   */
  private async generateSingleBlock(
    coinbaseScript: Buffer,
    transactions: Transaction[],
    submit: boolean,
    maxTries: number = 1000000
  ): Promise<{ hash: string; hex?: string }> {
    const bestBlock = this.chainState.getBestBlock();
    const height = bestBlock.height + 1;

    // Build coinbase transaction
    const subsidy = getBlockSubsidy(height, this.params);

    // Calculate fees from transactions
    let totalFees = 0n;
    for (const tx of transactions) {
      // For accurate fee calculation, we'd need to look up inputs
      // For regtest, we'll trust the mempool entries or assume 0 fees for raw txs
      const txid = getTxId(tx);
      const entry = this.mempool.getTransaction(txid);
      if (entry) {
        totalFees += entry.fee;
      }
    }

    // Build coinbase
    const coinbaseTx = this.buildCoinbaseTx(height, subsidy + totalFees, coinbaseScript);

    // All transactions for the block
    const allTxs = [coinbaseTx, ...transactions];

    // Compute merkle root
    const txids = allTxs.map(tx => getTxId(tx));
    const merkleRoot = computeMerkleRoot(txids);

    // Compute witness commitment if needed
    const segwitActive = height >= this.params.segwitHeight;
    let finalCoinbase = coinbaseTx;

    if (segwitActive) {
      // Compute witness merkle root
      const wtxids: Buffer[] = [Buffer.alloc(32, 0)]; // Coinbase wtxid is 32 zeros
      for (const tx of transactions) {
        wtxids.push(getWTxId(tx));
      }
      const witnessMerkleRoot = computeWitnessMerkleRoot(wtxids);
      const witnessNonce = Buffer.alloc(32, 0);
      const witnessCommitment = hash256(Buffer.concat([witnessMerkleRoot, witnessNonce]));

      // Rebuild coinbase with witness commitment
      finalCoinbase = this.buildCoinbaseTxWithWitnessCommitment(
        height,
        subsidy + totalFees,
        coinbaseScript,
        witnessCommitment
      );

      // Recompute txids with new coinbase
      allTxs[0] = finalCoinbase;
      txids[0] = getTxId(finalCoinbase);
    }

    // Build header
    const target = this.params.powLimit;
    const bits = bigIntToCompact(target);

    let header: BlockHeader = {
      version: 0x20000000,
      prevBlock: bestBlock.hash,
      merkleRoot: computeMerkleRoot(txids),
      timestamp: Math.floor(Date.now() / 1000),
      bits,
      nonce: 0,
    };

    // Mine the block (find valid nonce)
    let found = false;
    for (let nonce = 0; nonce < maxTries && nonce < 0xffffffff; nonce++) {
      header = { ...header, nonce };
      const blockHash = getBlockHash(header);

      if (checkProofOfWork(blockHash, bits, this.params)) {
        found = true;
        break;
      }
    }

    if (!found) {
      throw this.rpcError(RPCErrorCodes.MISC_ERROR, "Failed to find valid nonce");
    }

    // Build the block
    const block: Block = {
      header,
      transactions: allTxs,
    };

    const blockHash = getBlockHash(header);
    const blockHashHex = blockHash.toString("hex");

    if (submit) {
      // Connect the block to the chain
      await this.chainState.connectBlock(block, height);

      // Add the new header to headerSync so we can serve it to peers
      // who send getheaders after receiving our inv announcement.
      await this.headerSync.processHeaders([block.header], null);

      // Remove mined transactions from mempool
      for (const tx of transactions) {
        const txid = getTxId(tx);
        this.mempool.removeTransaction(txid);
      }

      // Announce new block to all connected peers
      this.broadcastBlockInv(blockHash);

      return { hash: blockHashHex };
    } else {
      // Return block hex without submitting
      const blockHex = serializeBlock(block).toString("hex");
      return { hash: blockHashHex, hex: blockHex };
    }
  }

  /**
   * Build a coinbase transaction.
   */
  private buildCoinbaseTx(height: number, value: bigint, scriptPubKey: Buffer): Transaction {
    // BIP34 height encoding
    const heightPush = this.encodeBIP34Height(height);

    return {
      version: 2,
      inputs: [
        {
          prevOut: {
            txid: Buffer.alloc(32, 0),
            vout: 0xffffffff,
          },
          scriptSig: heightPush,
          sequence: 0xffffffff,
          witness: [],
        },
      ],
      outputs: [
        {
          value,
          scriptPubKey,
        },
      ],
      lockTime: 0,
    };
  }

  /**
   * Build a coinbase transaction with witness commitment.
   */
  private buildCoinbaseTxWithWitnessCommitment(
    height: number,
    value: bigint,
    scriptPubKey: Buffer,
    witnessCommitment: Buffer
  ): Transaction {
    const heightPush = this.encodeBIP34Height(height);

    // Witness commitment output: OP_RETURN 0x24 0xaa21a9ed <32-byte commitment>
    const commitmentScript = Buffer.concat([
      Buffer.from([0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed]),
      witnessCommitment,
    ]);

    return {
      version: 2,
      inputs: [
        {
          prevOut: {
            txid: Buffer.alloc(32, 0),
            vout: 0xffffffff,
          },
          scriptSig: heightPush,
          sequence: 0xffffffff,
          witness: [Buffer.alloc(32, 0)], // Witness nonce
        },
      ],
      outputs: [
        {
          value,
          scriptPubKey,
        },
        {
          value: 0n,
          scriptPubKey: commitmentScript,
        },
      ],
      lockTime: 0,
    };
  }

  /**
   * Encode height for BIP34 coinbase scriptSig.
   */
  private encodeBIP34Height(height: number): Buffer {
    if (height < 0) {
      throw new Error("Height cannot be negative");
    }

    if (height === 0) {
      return Buffer.from([0x00]); // OP_0
    }

    if (height >= 1 && height <= 16) {
      return Buffer.from([0x50 + height]); // OP_1 to OP_16
    }

    // For heights >= 17, use minimal push encoding
    const heightBytes = this.encodeScriptNum(height);
    return Buffer.concat([
      Buffer.from([heightBytes.length]),
      heightBytes,
    ]);
  }

  /**
   * Encode a number as a minimal CScript number.
   */
  private encodeScriptNum(n: number): Buffer {
    if (n === 0) {
      return Buffer.alloc(0);
    }

    const negative = n < 0;
    let absValue = Math.abs(n);
    const result: number[] = [];

    while (absValue > 0) {
      result.push(absValue & 0xff);
      absValue >>= 8;
    }

    // If MSB has high bit set and number is positive, add 0x00
    if (result[result.length - 1] & 0x80) {
      result.push(negative ? 0x80 : 0x00);
    } else if (negative) {
      result[result.length - 1] |= 0x80;
    }

    return Buffer.from(result);
  }

  // ========== Pruning Methods ==========

  /**
   * pruneblockchain: Manually prune blocks up to specified height.
   *
   * @param params [height] - Height up to which to prune (exclusive)
   * @returns Height of the first block that is not pruned
   */
  private async pruneBlockchain(params: unknown[]): Promise<number> {
    const [heightParam] = params;

    if (!this.pruneManager) {
      throw this.rpcError(
        RPCErrorCodes.MISC_ERROR,
        "Cannot prune blocks because node is not in prune mode"
      );
    }

    if (typeof heightParam !== "number" || !Number.isInteger(heightParam)) {
      throw this.rpcError(RPCErrorCodes.INVALID_PARAMS, "height must be an integer");
    }

    if (heightParam < 0) {
      throw this.rpcError(RPCErrorCodes.INVALID_PARAMS, "Negative block height");
    }

    const bestBlock = this.chainState.getBestBlock();

    if (heightParam > bestBlock.height) {
      throw this.rpcError(
        RPCErrorCodes.INVALID_PARAMS,
        `Blockchain is shorter than the attempted prune height (${bestBlock.height})`
      );
    }

    const result = await this.pruneManager.pruneBlockchain(heightParam, bestBlock.height);

    return result.firstUnprunedHeight;
  }

  /**
   * Calculate block subsidy for a given height.
   */
  private getBlockSubsidy(height: number): bigint {
    const INITIAL_SUBSIDY = 5_000_000_000n; // 50 BTC in satoshis
    const HALVING_INTERVAL = 210_000;

    const halvings = Math.floor(height / HALVING_INTERVAL);
    if (halvings >= 64) {
      return 0n;
    }

    return INITIAL_SUBSIDY >> BigInt(halvings);
  }

  // ========== Chain Management Methods ==========

  /**
   * invalidateblock: Manually invalidate a block and its descendants.
   *
   * @param params [blockhash] - Hash of the block to invalidate (hex string)
   * @returns null on success
   */
  private async invalidateBlockRPC(params: unknown[]): Promise<null> {
    const [blockhashParam] = params;

    if (typeof blockhashParam !== "string") {
      throw this.rpcError(RPCErrorCodes.INVALID_PARAMS, "blockhash must be a string");
    }

    // Parse and validate hex
    if (!/^[0-9a-fA-F]{64}$/.test(blockhashParam)) {
      throw this.rpcError(
        RPCErrorCodes.INVALID_ADDRESS_OR_KEY,
        "Invalid block hash format"
      );
    }

    // Convert to internal byte order (reversed)
    const blockHash = Buffer.from(blockhashParam, "hex").reverse();

    const result = await this.chainState.invalidateBlock(blockHash);

    if (!result.success) {
      throw this.rpcError(RPCErrorCodes.MISC_ERROR, result.error || "Block invalidation failed");
    }

    return null;
  }

  /**
   * reconsiderblock: Remove invalidity status from a block and its ancestors.
   *
   * @param params [blockhash] - Hash of the block to reconsider (hex string)
   * @returns null on success
   */
  private async reconsiderBlockRPC(params: unknown[]): Promise<null> {
    const [blockhashParam] = params;

    if (typeof blockhashParam !== "string") {
      throw this.rpcError(RPCErrorCodes.INVALID_PARAMS, "blockhash must be a string");
    }

    // Parse and validate hex
    if (!/^[0-9a-fA-F]{64}$/.test(blockhashParam)) {
      throw this.rpcError(
        RPCErrorCodes.INVALID_ADDRESS_OR_KEY,
        "Invalid block hash format"
      );
    }

    // Convert to internal byte order (reversed)
    const blockHash = Buffer.from(blockhashParam, "hex").reverse();

    const result = await this.chainState.reconsiderBlock(blockHash);

    if (!result.success) {
      throw this.rpcError(RPCErrorCodes.MISC_ERROR, result.error || "Block reconsideration failed");
    }

    return null;
  }

  /**
   * preciousblock: Mark a block as precious for tie-breaking in chain selection.
   *
   * @param params [blockhash] - Hash of the block to mark precious (hex string)
   * @returns null on success
   */
  private async preciousBlockRPC(params: unknown[]): Promise<null> {
    const [blockhashParam] = params;

    if (typeof blockhashParam !== "string") {
      throw this.rpcError(RPCErrorCodes.INVALID_PARAMS, "blockhash must be a string");
    }

    // Parse and validate hex
    if (!/^[0-9a-fA-F]{64}$/.test(blockhashParam)) {
      throw this.rpcError(
        RPCErrorCodes.INVALID_ADDRESS_OR_KEY,
        "Invalid block hash format"
      );
    }

    // Convert to internal byte order (reversed)
    const blockHash = Buffer.from(blockhashParam, "hex").reverse();

    const result = await this.chainState.preciousBlock(blockHash);

    if (!result.success) {
      throw this.rpcError(RPCErrorCodes.MISC_ERROR, result.error || "Block marking failed");
    }

    return null;
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
    const wtxid = getWTxId(tx);

    const result: Record<string, unknown> = {
      txid: Buffer.from(txid).reverse().toString("hex"),
      hash: wBuffer.from(txid).reverse().toString("hex"),
      version: tx.version,
      size: serializeTx(tx, true).length,
      vsize: getTxVSize(tx),
      weight: getTxWeight(tx),
      locktime: tx.lockTime,
      vin: tx.inputs.map((input, i) => {
        const vin: Record<string, unknown> = {};

        // Check if coinbase
        if (isCoinbase(tx) && i === 0) {
          vin.coinbase = input.scriptSig.toString("hex");
          vin.sequence = input.sequence;
        } else {
          vin.txid = input.prevOut.Buffer.from(txid).reverse().toString("hex");
          vin.vout = input.prevOut.vout;
          vin.scriptSig = {
            asm: this.disassembleScript(input.scriptSig),
            hex: input.scriptSig.toString("hex"),
          };
          vin.sequence = input.sequence;
        }

        if (input.witness.length > 0) {
          vin.txinwitness = input.witness.map((w) => w.toString("hex"));
        }

        return vin;
      }),
      vout: tx.outputs.map((output, i) => ({
        value: Number(output.value) / 100_000_000,
        n: i,
        scriptPubKey: this.formatScriptPubKey(output.scriptPubKey),
      })),
    };

    if (blockhash) {
      result.blockhash = Buffer.from(blockhash).reverse().toString("hex");
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

  // ========== Multi-Wallet Methods ==========

  /**
   * Get the wallet for the current RPC request.
   *
   * If a wallet name was specified in the URL (/wallet/<name>), use that wallet.
   * Otherwise, if exactly one wallet is loaded, use it as the default.
   * If multiple wallets are loaded and no name specified, throw an error.
   *
   * Reference: Bitcoin Core's GetWalletForJSONRPCRequest in wallet/rpc/util.cpp
   */
  private getCurrentWallet(): Wallet {
    // First check legacy single wallet
    if (this.wallet && !this.walletManager) {
      return this.wallet;
    }

    if (!this.walletManager) {
      throw {
        code: RPCErrorCodes.WALLET_NOT_FOUND,
        message: "No wallet support configured",
      };
    }

    // If wallet name specified in URL
    if (this.currentWalletName !== null) {
      const wallet = this.walletManager.getWallet(this.currentWalletName);
      if (!wallet) {
        throw {
          code: RPCErrorCodes.WALLET_NOT_FOUND,
          message: `Wallet "${this.currentWalletName}" not found`,
        };
      }
      return wallet;
    }

    // No wallet in URL - try to use default
    const walletCount = this.walletManager.getWalletCount();
    if (walletCount === 0) {
      throw {
        code: RPCErrorCodes.WALLET_NOT_FOUND,
        message: "No wallet loaded. Use loadwallet or createwallet to load one.",
      };
    }

    if (walletCount > 1) {
      throw {
        code: RPCErrorCodes.WALLET_NOT_SPECIFIED,
        message: `Multiple wallets are loaded. Use /wallet/<name> endpoint to specify which wallet to use. Loaded wallets: ${this.walletManager.listWallets().join(", ")}`,
      };
    }

    // Exactly one wallet - use it as default
    const defaultWallet = this.walletManager.getDefaultWallet();
    if (!defaultWallet) {
      throw {
        code: RPCErrorCodes.WALLET_NOT_FOUND,
        message: "No wallet loaded",
      };
    }

    return defaultWallet;
  }

  /**
   * Get the name of the current wallet for RPC response.
   */
  private getCurrentWalletName(): string {
    if (this.currentWalletName !== null) {
      return this.currentWalletName;
    }
    if (this.walletManager && this.walletManager.getWalletCount() === 1) {
      return this.walletManager.listWallets()[0];
    }
    return "default";
  }

  /**
   * createwallet: Create a new wallet.
   *
   * Reference: Bitcoin Core's createwallet in wallet/rpc/wallet.cpp
   *
   * @param params [wallet_name, disable_private_keys, blank, passphrase, avoid_reuse, descriptors, load_on_startup]
   */
  private async createWallet(params: unknown[]): Promise<Record<string, unknown>> {
    if (!this.walletManager) {
      throw {
        code: RPCErrorCodes.WALLET_NOT_FOUND,
        message: "Wallet manager not available",
      };
    }

    const [
      walletName,
      disablePrivateKeys,
      blank,
      passphrase,
      avoidReuse,
      descriptors,
      loadOnStartup,
    ] = params;

    if (typeof walletName !== "string") {
      throw {
        code: RPCErrorCodes.INVALID_PARAMS,
        message: "wallet_name must be a string",
      };
    }

    // Validate optional parameters
    const options: CreateWalletOptions = {};
    if (disablePrivateKeys !== undefined && disablePrivateKeys !== null) {
      if (typeof disablePrivateKeys !== "boolean") {
        throw {
          code: RPCErrorCodes.INVALID_PARAMS,
          message: "disable_private_keys must be a boolean",
        };
      }
      options.disablePrivateKeys = disablePrivateKeys;
    }
    if (blank !== undefined && blank !== null) {
      if (typeof blank !== "boolean") {
        throw {
          code: RPCErrorCodes.INVALID_PARAMS,
          message: "blank must be a boolean",
        };
      }
      options.blank = blank;
    }
    if (passphrase !== undefined && passphrase !== null) {
      if (typeof passphrase !== "string") {
        throw {
          code: RPCErrorCodes.INVALID_PARAMS,
          message: "passphrase must be a string",
        };
      }
      options.passphrase = passphrase;
    }
    if (avoidReuse !== undefined && avoidReuse !== null) {
      if (typeof avoidReuse !== "boolean") {
        throw {
          code: RPCErrorCodes.INVALID_PARAMS,
          message: "avoid_reuse must be a boolean",
        };
      }
      options.avoidReuse = avoidReuse;
    }
    if (descriptors !== undefined && descriptors !== null) {
      if (typeof descriptors !== "boolean") {
        throw {
          code: RPCErrorCodes.INVALID_PARAMS,
          message: "descriptors must be a boolean",
        };
      }
      // We only support descriptor wallets
      if (descriptors === false) {
        throw {
          code: RPCErrorCodes.WALLET_ERROR,
          message: "Only descriptor wallets are supported (descriptors must be true or omitted)",
        };
      }
      options.descriptors = descriptors;
    }
    if (loadOnStartup !== undefined && loadOnStartup !== null) {
      if (typeof loadOnStartup !== "boolean") {
        throw {
          code: RPCErrorCodes.INVALID_PARAMS,
          message: "load_on_startup must be a boolean",
        };
      }
      options.loadOnStartup = loadOnStartup;
    }

    try {
      const result = await this.walletManager.createWallet(walletName, options);
      const response: Record<string, unknown> = {
        name: result.name,
      };
      if (result.warnings.length > 0) {
        response.warnings = result.warnings;
      }
      return response;
    } catch (err) {
      throw {
        code: RPCErrorCodes.WALLET_ERROR,
        message: err instanceof Error ? err.message : "Failed to create wallet",
      };
    }
  }

  /**
   * loadwallet: Load a wallet from disk.
   *
   * Reference: Bitcoin Core's loadwallet in wallet/rpc/wallet.cpp
   *
   * @param params [filename, load_on_startup]
   */
  private async loadWallet(params: unknown[]): Promise<Record<string, unknown>> {
    if (!this.walletManager) {
      throw {
        code: RPCErrorCodes.WALLET_NOT_FOUND,
        message: "Wallet manager not available",
      };
    }

    const [filename, loadOnStartup] = params;

    if (typeof filename !== "string") {
      throw {
        code: RPCErrorCodes.INVALID_PARAMS,
        message: "filename must be a string",
      };
    }

    let loadOnStartupValue: boolean | undefined;
    if (loadOnStartup !== undefined && loadOnStartup !== null) {
      if (typeof loadOnStartup !== "boolean") {
        throw {
          code: RPCErrorCodes.INVALID_PARAMS,
          message: "load_on_startup must be a boolean",
        };
      }
      loadOnStartupValue = loadOnStartup;
    }

    try {
      // For loadwallet, we need a password. Use a default or require it.
      // In Bitcoin Core, wallets can be unencrypted. For simplicity, we use a default.
      const result = await this.walletManager.loadWallet(
        filename,
        "hotbuns", // Default password for unencrypted wallets
        loadOnStartupValue
      );
      const response: Record<string, unknown> = {
        name: result.name,
      };
      if (result.warnings.length > 0) {
        response.warnings = result.warnings;
      }
      return response;
    } catch (err) {
      throw {
        code: RPCErrorCodes.WALLET_ERROR,
        message: err instanceof Error ? err.message : "Failed to load wallet",
      };
    }
  }

  /**
   * unloadwallet: Unload a wallet.
   *
   * Reference: Bitcoin Core's unloadwallet in wallet/rpc/wallet.cpp
   *
   * @param params [wallet_name, load_on_startup]
   */
  private async unloadWallet(params: unknown[]): Promise<Record<string, unknown>> {
    if (!this.walletManager) {
      throw {
        code: RPCErrorCodes.WALLET_NOT_FOUND,
        message: "Wallet manager not available",
      };
    }

    const [walletNameParam, loadOnStartup] = params;

    // Determine wallet name: from param or from URL
    let walletName: string;
    if (walletNameParam !== undefined && walletNameParam !== null) {
      if (typeof walletNameParam !== "string") {
        throw {
          code: RPCErrorCodes.INVALID_PARAMS,
          message: "wallet_name must be a string",
        };
      }
      walletName = walletNameParam;
    } else if (this.currentWalletName !== null) {
      walletName = this.currentWalletName;
    } else if (this.walletManager.getWalletCount() === 1) {
      walletName = this.walletManager.listWallets()[0];
    } else {
      throw {
        code: RPCErrorCodes.WALLET_NOT_SPECIFIED,
        message: "Wallet name must be specified when multiple wallets are loaded",
      };
    }

    // If both URL and param specify wallet, they must match
    if (this.currentWalletName !== null && walletNameParam !== undefined && walletNameParam !== null) {
      if (this.currentWalletName !== walletNameParam) {
        throw {
          code: RPCErrorCodes.INVALID_PARAMS,
          message: `Wallet name from URL (${this.currentWalletName}) does not match parameter (${walletNameParam})`,
        };
      }
    }

    let loadOnStartupValue: boolean | undefined;
    if (loadOnStartup !== undefined && loadOnStartup !== null) {
      if (typeof loadOnStartup !== "boolean") {
        throw {
          code: RPCErrorCodes.INVALID_PARAMS,
          message: "load_on_startup must be a boolean",
        };
      }
      loadOnStartupValue = loadOnStartup;
    }

    try {
      const result = await this.walletManager.unloadWallet(walletName, loadOnStartupValue);
      const response: Record<string, unknown> = {};
      if (result.warnings.length > 0) {
        response.warnings = result.warnings;
      }
      return response;
    } catch (err) {
      throw {
        code: RPCErrorCodes.WALLET_ERROR,
        message: err instanceof Error ? err.message : "Failed to unload wallet",
      };
    }
  }

  /**
   * listwallets: List currently loaded wallets.
   *
   * Reference: Bitcoin Core's listwallets in wallet/rpc/wallet.cpp
   */
  private async listWallets(): Promise<string[]> {
    if (!this.walletManager) {
      // Fallback for legacy single wallet
      if (this.wallet) {
        return ["default"];
      }
      throw {
        code: RPCErrorCodes.WALLET_NOT_FOUND,
        message: "Wallet manager not available",
      };
    }

    return this.walletManager.listWallets();
  }

  /**
   * listwalletdir: List available wallet directories.
   *
   * Reference: Bitcoin Core's listwalletdir in wallet/rpc/wallet.cpp
   */
  private async listWalletDir(): Promise<Record<string, unknown>> {
    if (!this.walletManager) {
      throw {
        code: RPCErrorCodes.WALLET_NOT_FOUND,
        message: "Wallet manager not available",
      };
    }

    const entries = await this.walletManager.listWalletDir();
    return {
      wallets: entries.map((e) => ({ name: e.name })),
    };
  }

  // ========== Wallet Methods ==========

  /**
   * encryptwallet: Encrypt the wallet with a passphrase.
   * After encryption, the wallet will need to be unlocked for signing operations.
   *
   * @param params [passphrase]
   */
  private async encryptWallet(params: unknown[]): Promise<string> {
    const wallet = this.getCurrentWallet();

    const [passphrase] = params;
    if (typeof passphrase !== "string" || passphrase.length === 0) {
      throw {
        code: RPCErrorCodes.INVALID_PARAMS,
        message: "Missing or invalid passphrase",
      };
    }

    if (wallet.isEncrypted()) {
      throw {
        code: RPCErrorCodes.WALLET_WRONG_ENC_STATE,
        message: "Wallet is already encrypted. Use walletpassphrasechange to change the passphrase.",
      };
    }

    try {
      await wallet.encryptWallet(passphrase);
      return "Wallet encrypted. The wallet is now locked. You need to call walletpassphrase before signing transactions.";
    } catch (err) {
      throw {
        code: RPCErrorCodes.WALLET_ENCRYPTION_FAILED,
        message: err instanceof Error ? err.message : "Encryption failed",
      };
    }
  }

  /**
   * walletpassphrase: Unlock the wallet for a specified time.
   *
   * @param params [passphrase, timeout]
   */
  private async walletPassphrase(params: unknown[]): Promise<null> {
    const wallet = this.getCurrentWallet();

    const [passphrase, timeout] = params;
    if (typeof passphrase !== "string" || passphrase.length === 0) {
      throw {
        code: RPCErrorCodes.INVALID_PARAMS,
        message: "Missing or invalid passphrase",
      };
    }
    if (typeof timeout !== "number" || timeout < 0) {
      throw {
        code: RPCErrorCodes.INVALID_PARAMS,
        message: "Missing or invalid timeout (must be non-negative number)",
      };
    }

    if (!wallet.isEncrypted()) {
      throw {
        code: RPCErrorCodes.WALLET_WRONG_ENC_STATE,
        message: "Wallet is not encrypted",
      };
    }

    try {
      await wallet.unlockWallet(passphrase, timeout);
      return null;
    } catch (err) {
      throw {
        code: RPCErrorCodes.WALLET_PASSPHRASE_INCORRECT,
        message: err instanceof Error ? err.message : "Incorrect passphrase",
      };
    }
  }

  /**
   * walletlock: Lock the wallet.
   */
  private async walletLock(): Promise<null> {
    const wallet = this.getCurrentWallet();

    if (!wallet.isEncrypted()) {
      throw {
        code: RPCErrorCodes.WALLET_WRONG_ENC_STATE,
        message: "Wallet is not encrypted",
      };
    }

    wallet.lockWallet();
    return null;
  }

  /**
   * walletpassphrasechange: Change the wallet passphrase.
   *
   * @param params [oldpassphrase, newpassphrase]
   */
  private async walletPassphraseChange(params: unknown[]): Promise<null> {
    const wallet = this.getCurrentWallet();

    const [oldPassphrase, newPassphrase] = params;
    if (typeof oldPassphrase !== "string" || oldPassphrase.length === 0) {
      throw {
        code: RPCErrorCodes.INVALID_PARAMS,
        message: "Missing or invalid old passphrase",
      };
    }
    if (typeof newPassphrase !== "string" || newPassphrase.length === 0) {
      throw {
        code: RPCErrorCodes.INVALID_PARAMS,
        message: "Missing or invalid new passphrase",
      };
    }

    if (!wallet.isEncrypted()) {
      throw {
        code: RPCErrorCodes.WALLET_WRONG_ENC_STATE,
        message: "Wallet is not encrypted",
      };
    }

    try {
      await wallet.changePassphrase(oldPassphrase, newPassphrase);
      return null;
    } catch (err) {
      throw {
        code: RPCErrorCodes.WALLET_PASSPHRASE_INCORRECT,
        message: err instanceof Error ? err.message : "Error changing passphrase",
      };
    }
  }

  /**
   * setlabel: Assign a label to an address.
   *
   * @param params [address, label]
   */
  private async setLabel(params: unknown[]): Promise<null> {
    const wallet = this.getCurrentWallet();

    const [address, label] = params;
    if (typeof address !== "string" || address.length === 0) {
      throw {
        code: RPCErrorCodes.INVALID_PARAMS,
        message: "Missing or invalid address",
      };
    }
    if (typeof label !== "string") {
      throw {
        code: RPCErrorCodes.INVALID_PARAMS,
        message: "Missing or invalid label",
      };
    }

    try {
      wallet.setLabel(address, label);
      return null;
    } catch (err) {
      throw {
        code: RPCErrorCodes.INVALID_ADDRESS_OR_KEY,
        message: err instanceof Error ? err.message : "Error setting label",
      };
    }
  }

  /**
   * listreceivedbyaddress: List balances by receiving address.
   *
   * @param params [minconf, include_empty, include_watchonly, address_filter]
   */
  private async listReceivedByAddress(params: unknown[]): Promise<unknown[]> {
    const wallet = this.getCurrentWallet();

    const [minconfParam, includeEmptyParam] = params;
    const minconf = typeof minconfParam === "number" ? minconfParam : 1;
    const includeEmpty = includeEmptyParam === true;

    const received = wallet.listReceivedByAddress();

    return received
      .filter((entry) => {
        if (entry.confirmations < minconf) return false;
        if (!includeEmpty && entry.amount === 0n) return false;
        return true;
      })
      .map((entry) => ({
        address: entry.address,
        label: entry.label,
        amount: Number(entry.amount) / 100_000_000, // Convert to BTC
        confirmations: entry.confirmations,
      }));
  }

  /**
   * listtransactions: List transactions for the wallet.
   *
   * Note: This is a simplified version that returns UTXO-based entries.
   * A full implementation would track spent transactions separately.
   *
   * @param params [label, count, skip, include_watchonly]
   */
  private async listTransactions(params: unknown[]): Promise<unknown[]> {
    const wallet = this.getCurrentWallet();

    const [labelParam, countParam, skipParam] = params;
    const labelFilter = typeof labelParam === "string" ? labelParam : "*";
    const count = typeof countParam === "number" ? Math.min(countParam, 1000) : 10;
    const skip = typeof skipParam === "number" ? skipParam : 0;

    const utxos = wallet.getUTXOs();
    const transactions: Array<{
      address: string;
      category: string;
      amount: number;
      label: string;
      confirmations: number;
    }> = [];

    for (const utxo of utxos) {
      const label = wallet.getLabel(utxo.address);

      // Filter by label if specified
      if (labelFilter !== "*" && label !== labelFilter) {
        continue;
      }

      transactions.push({
        address: utxo.address,
        category: "receive",
        amount: Number(utxo.amount) / 100_000_000,
        label,
        confirmations: utxo.confirmations,
      });
    }

    // Sort by confirmations (newest first)
    transactions.sort((a, b) => a.confirmations - b.confirmations);

    // Apply skip and count
    return transactions.slice(skip, skip + count);
  }

  /**
   * getwalletinfo: Returns wallet state information.
   */
  private async getWalletInfo(): Promise<Record<string, unknown>> {
    const wallet = this.getCurrentWallet();

    const balance = wallet.getBalance();
    const utxos = wallet.getUTXOs();

    return {
      walletname: this.getCurrentWalletName(),
      walletversion: 1,
      balance: Number(balance.confirmed) / 100_000_000,
      unconfirmed_balance: Number(balance.unconfirmed) / 100_000_000,
      immature_balance: 0, // Would need to track immature coinbase separately
      txcount: utxos.length,
      keypoolsize: 20, // Address gap
      unlocked_until: wallet.isLocked() ? 0 : undefined,
      paytxfee: 0,
      hdseedid: undefined,
      private_keys_enabled: true,
      avoid_reuse: false,
      scanning: false,
      descriptors: true,
      encrypted: wallet.isEncrypted(),
      locked: wallet.isLocked(),
    };
  }

  // ========== Descriptor Methods ==========

  /**
   * getdescriptorinfo: Analyzes a descriptor and returns information about it.
   * @param params [descriptor]
   */
  private async getDescriptorInfo(params: unknown[]): Promise<Record<string, unknown>> {
    const [descriptorParam] = params;

    if (typeof descriptorParam !== "string") {
      throw this.rpcError(RPCErrorCodes.INVALID_PARAMS, "descriptor must be a string");
    }

    try {
      const info = getDescriptorInfo(descriptorParam);
      return {
        descriptor: info.descriptor,
        checksum: info.checksum,
        isrange: info.isRange,
        issolvable: info.isSolvable,
        hasprivatekeys: info.hasPrivateKeys,
      };
    } catch (e) {
      const message = e instanceof Error ? e.message : String(e);
      throw this.rpcError(RPCErrorCodes.INVALID_ADDRESS_OR_KEY, message);
    }
  }

  /**
   * deriveaddresses: Derives addresses from a descriptor.
   * @param params [descriptor, range?]
   * range is [start, end] inclusive, or just end (implies start=0)
   */
  private async deriveAddresses(params: unknown[]): Promise<string[]> {
    const [descriptorParam, rangeParam] = params;

    if (typeof descriptorParam !== "string") {
      throw this.rpcError(RPCErrorCodes.INVALID_PARAMS, "descriptor must be a string");
    }

    // Determine network from params
    const network = this.getNetworkType();

    // Parse range parameter
    let range: [number, number] | undefined;
    if (rangeParam !== undefined) {
      if (typeof rangeParam === "number") {
        // Single number means [0, rangeParam]
        range = [0, rangeParam];
      } else if (Array.isArray(rangeParam) && rangeParam.length === 2) {
        const [start, end] = rangeParam;
        if (typeof start !== "number" || typeof end !== "number") {
          throw this.rpcError(RPCErrorCodes.INVALID_PARAMS, "range must be [start, end] numbers");
        }
        range = [start, end];
      } else {
        throw this.rpcError(RPCErrorCodes.INVALID_PARAMS, "range must be a number or [start, end]");
      }

      // Validate range
      if (range[0] < 0 || range[1] < range[0]) {
        throw this.rpcError(RPCErrorCodes.INVALID_PARAMS, "invalid range");
      }
      if (range[1] - range[0] > 10000) {
        throw this.rpcError(RPCErrorCodes.INVALID_PARAMS, "range too large (max 10000)");
      }
    }

    try {
      const addresses = deriveAddresses(descriptorParam, network, range);
      return addresses;
    } catch (e) {
      const message = e instanceof Error ? e.message : String(e);
      throw this.rpcError(RPCErrorCodes.INVALID_ADDRESS_OR_KEY, message);
    }
  }

  /**
   * Get the network type for address encoding.
   */
  private getNetworkType(): NetworkType {
    switch (this.params.networkMagic) {
      case 0xd9b4bef9:
        return "mainnet";
      case 0x0709110b:
        return "testnet";
      case 0xdab5bffa:
        return "regtest";
      default:
        return "mainnet";
    }
  }

  // ========== assumeUTXO Methods ==========

  /**
   * loadtxoutset: Load a UTXO snapshot from a file.
   *
   * @param params - [path] Path to the snapshot file
   * @returns Load result with coins loaded, base hash, height, and path
   */
  private async loadTxoutset(params: unknown[]): Promise<Record<string, unknown>> {
    const [pathParam] = params;

    if (typeof pathParam !== "string") {
      throw this.rpcError(RPCErrorCodes.INVALID_PARAMS, "path must be a string");
    }

    // Create or get chainstate manager
    let chainstateManager = this.chainstateManager;
    if (!chainstateManager) {
      chainstateManager = new ChainstateManager(this.db, this.params);
      this.chainstateManager = chainstateManager;
    }

    try {
      const result = await chainstateManager.loadSnapshot(pathParam);

      return {
        coins_loaded: Number(result.coinsLoaded),
        tip_hash: result.baseBlockHash.toString("hex"),
        base_height: result.baseHeight,
        path: result.path,
      };
    } catch (e) {
      const message = e instanceof Error ? e.message : String(e);
      throw this.rpcError(RPCErrorCodes.INTERNAL_ERROR, `Failed to load snapshot: ${message}`);
    }
  }

  /**
   * dumptxoutset: Dump the current UTXO set to a snapshot file.
   *
   * @param params - [path] Path for the output file
   * @returns Dump result with coins written, base hash, height, path, and txoutset hash
   */
  private async dumpTxoutset(params: unknown[]): Promise<Record<string, unknown>> {
    const [pathParam] = params;

    if (typeof pathParam !== "string") {
      throw this.rpcError(RPCErrorCodes.INVALID_PARAMS, "path must be a string");
    }

    // Create or get chainstate manager
    let chainstateManager = this.chainstateManager;
    if (!chainstateManager) {
      chainstateManager = new ChainstateManager(this.db, this.params);
      this.chainstateManager = chainstateManager;
    }

    try {
      const result = await chainstateManager.dumpSnapshot(pathParam);

      return {
        coins_written: Number(result.coinsWritten),
        base_hash: result.baseHash,
        base_height: result.baseHeight,
        path: result.path,
        txoutset_hash: result.txoutsetHash,
        nchaintx: Number(result.nChainTx),
      };
    } catch (e) {
      const message = e instanceof Error ? e.message : String(e);
      throw this.rpcError(RPCErrorCodes.INTERNAL_ERROR, `Failed to dump snapshot: ${message}`);
    }
  }

  /**
   * getutxosetsnapshot: Get information about the current UTXO set.
   *
   * @returns UTXO set statistics including hash and coin count
   */
  private async getUtxoSetSnapshot(): Promise<Record<string, unknown>> {
    try {
      const chainState = await this.db.getChainState();
      if (!chainState) {
        throw new Error("No chain state available");
      }

      const { hash, coinsCount } = await computeUTXOSetHash(this.db);

      return {
        height: chainState.bestHeight,
        bestblock: chainState.bestBlockHash.toString("hex"),
        txoutset_hash: hash.toString("hex"),
        coins_count: Number(coinsCount),
      };
    } catch (e) {
      const message = e instanceof Error ? e.message : String(e);
      throw this.rpcError(RPCErrorCodes.INTERNAL_ERROR, `Failed to compute UTXO set info: ${message}`);
    }
  }

  // ========== ZMQ Methods ==========

  /**
   * getzmqnotifications: Returns information about active ZMQ notifications.
   *
   * Returns an array of objects with:
   * - type: notification type (hashblock, hashtx, rawblock, rawtx, sequence)
   * - address: ZMQ socket address
   * - hwm: high water mark
   */
  private async getZMQNotifications(): Promise<Array<{
    type: string;
    address: string;
    hwm: number;
  }>> {
    if (!this.zmqInterface) {
      return [];
    }
    return this.zmqInterface.getNotifications();
  }
}
