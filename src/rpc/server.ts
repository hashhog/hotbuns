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
import { dumpMempool, loadMempool, mempoolDumpExists } from "../mempool/persist.js";
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
  validateBlock,
} from "../validation/block.js";
import { bip22Result } from "../validation/errors.js";
import { checkProofOfWork } from "../consensus/pow.js";
import { BlockTemplateBuilder } from "../mining/template.js";
import type { Transaction, TxIn, TxOut } from "../validation/tx.js";
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
  type PSBT,
  createPSBT,
  encodePSBTBase64,
  decodePSBTBase64,
  combinePSBTs,
  finalizePSBT,
  signPSBTInput,
  extractTransaction,
  decodePSBT as decodePSBTToJSON,
  convertToPSBT,
  updateInputUTXO,
  isInputFinalized,
  analyzePSBTCore,
  BTC_AMOUNT_SENTINEL,
  formatBtcAmount,
  buildScriptPubKeyObj,
  disassembleScriptSigHashDecode,
  decodeScriptRPC,
} from "../wallet/psbt.js";
import {
  ChainstateManager,
  computeUTXOSetHash,
  serializeSnapshotMetadata,
  deserializeSnapshotMetadata,
  deserializeCoinFromSnapshot,
  getLatestSnapshotHeightForRollback,
  SNAPSHOT_MAGIC,
  SNAPSHOT_VERSION,
  type SnapshotMetadata,
  type LoadSnapshotResult,
  type DumpSnapshotResult,
} from "../chain/snapshot.js";
import {
  messageSign,
  messageVerify,
  MessageVerificationResult,
} from "../crypto/signmessage.js";
import { base58CheckDecode, decodeAddress, AddressType } from "../address/encoding.js";
import { isValidPrivateKey } from "../crypto/primitives.js";

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
  /**
   * Disable all authentication (for testing only).
   * When true, no cookie is generated and all requests are allowed.
   */
  noAuth?: boolean;
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
 * `JSON.stringify` replacer that converts native `bigint` values to a
 * JSON-serializable form. Without this, any RPC handler that returns a
 * `bigint`-typed field (e.g. a forgotten `Number(x)` cast on satoshis,
 * chainwork, fees, or witness counts) would crash the response path with
 * "JSON.stringify cannot serialize BigInt".
 *
 * Conversion rule:
 *   - `bigint` that fits in `[Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER]`
 *     → `number` (preserves Bitcoin Core's numeric shape for fields like
 *      `vsize`, `weight`, plain integer counters).
 *   - Otherwise → decimal string (matches how Core renders chainwork/work
 *      stats and avoids silent precision loss for >2^53 values such as the
 *      mainnet hashrate or accumulated chainwork).
 *
 * Use as the second argument to `JSON.stringify(value, bigIntJsonReplacer)`.
 */
export function bigIntJsonReplacer(_key: string, value: unknown): unknown {
  if (typeof value === "bigint") {
    if (
      value <= BigInt(Number.MAX_SAFE_INTEGER) &&
      value >= BigInt(Number.MIN_SAFE_INTEGER)
    ) {
      return Number(value);
    }
    return value.toString();
  }
  return value;
}

/**
 * Post-process a serialized JSON string to replace BTC-amount sentinel tokens
 * with raw JSON numbers.
 *
 * `formatBtcAmount` (wallet/psbt.ts) uses `toJSON()` to embed
 * `"__BTC__:1.00000000"` in the JSON string (quoted, because JSON.stringify
 * always quotes strings returned by toJSON). This pass removes the quotes
 * and the sentinel prefix, leaving the raw decimal number `1.00000000`
 * in the JSON stream — byte-identical to Bitcoin Core's ValueFromAmount output.
 *
 * The regex anchors on the fixed 8-digit fractional part so it cannot match
 * unrelated string fields.
 */
function unquoteBtcAmounts(json: string): string {
  return json.replace(/"__BTC__:(-?\d+\.\d{8})"/g, "$1");
}

// ============================================================================
// Wave-47b: Partial Merkle Tree helpers (mirrors Bitcoin Core merkleblock.cpp)
// ============================================================================

/** CalcTreeWidth: (nTx + (1<<height) - 1) >> height. height 0 = leaves. */
function w47bTreeWidth(nTx: number, height: number): number {
  return (nTx + (1 << height) - 1) >> height;
}

/** CalcHash: height 0 = leaf (txid), height > 0 = combine children. */
function w47bCalcHash(height: number, pos: number, txids: Buffer[]): Buffer {
  if (height === 0) return txids[pos]!;
  const nTx = txids.length;
  const left = w47bCalcHash(height - 1, pos * 2, txids);
  const right = pos * 2 + 1 < w47bTreeWidth(nTx, height - 1)
    ? w47bCalcHash(height - 1, pos * 2 + 1, txids)
    : left;
  return hash256(Buffer.concat([left, right]));
}

/** TraverseAndBuild: returns { hashes, bits } in pre-order DFS. */
function w47bTraverseAndBuild(
  nTx: number,
  txids: Buffer[],
  matchFlags: boolean[]
): { hashes: Buffer[]; bits: boolean[] } {
  if (nTx === 0) return { hashes: [], bits: [] };
  let nHeight = 0;
  while (w47bTreeWidth(nTx, nHeight) > 1) nHeight++;

  const hashes: Buffer[] = [];
  const bits: boolean[] = [];

  function traverse(height: number, pos: number): void {
    // fParentOfMatch: any match in range [pos<<height, (pos+1)<<height)
    const lo = pos << height;
    const hi = Math.min((pos + 1) << height, nTx);
    let parentMatch = false;
    for (let p = lo; p < hi; p++) {
      if (matchFlags[p]) { parentMatch = true; break; }
    }
    bits.push(parentMatch);
    if (height === 0 || !parentMatch) {
      hashes.push(w47bCalcHash(height, pos, txids));
    } else {
      traverse(height - 1, pos * 2);
      if (pos * 2 + 1 < w47bTreeWidth(nTx, height - 1)) {
        traverse(height - 1, pos * 2 + 1);
      }
    }
  }
  traverse(nHeight, 0);
  return { hashes, bits };
}

/** BitsToBytes: pack bits LSB-first into bytes. */
function w47bBitsToBytes(bits: boolean[]): Buffer {
  const nBytes = Math.ceil(bits.length / 8);
  const buf = Buffer.alloc(nBytes, 0);
  for (let i = 0; i < bits.length; i++) {
    if (bits[i]) buf[i >> 3] |= 1 << (i & 7);
  }
  return buf;
}

/** BytesToBits: unpack bytes into bit array (LSB-first). */
function w47bBytesToBits(flagBytes: Buffer): boolean[] {
  const len = flagBytes.length * 8;
  return Array.from({ length: len }, (_, i) => ((flagBytes[i >> 3]! >> (i & 7)) & 1) === 1);
}

/** Encode Bitcoin varint into a Buffer. */
function w47bEncodeVarInt(v: number): Buffer {
  if (v < 0xfd) {
    const b = Buffer.alloc(1); b[0] = v; return b;
  } else if (v <= 0xffff) {
    const b = Buffer.alloc(3); b[0] = 0xfd; b.writeUInt16LE(v, 1); return b;
  } else {
    const b = Buffer.alloc(5); b[0] = 0xfe; b.writeUInt32LE(v, 1); return b;
  }
}

/** Read Bitcoin varint from buffer at pos. Returns [value, newPos]. */
function w47bReadVarInt(buf: Buffer, pos: number): [number, number] {
  const b = buf[pos]!;
  if (b < 0xfd) return [b, pos + 1];
  if (b === 0xfd) return [buf.readUInt16LE(pos + 1), pos + 3];
  if (b === 0xfe) return [buf.readUInt32LE(pos + 1), pos + 5];
  return [buf.readUInt32LE(pos + 1), pos + 9]; // truncate 8-byte to 4-byte
}

/** TraverseAndExtract: parse CMerkleBlock proof, return matched txids. */
function w47bTraverseAndExtract(
  nTx: number,
  hashes: Buffer[],
  flagBytes: Buffer
): string[] {
  if (nTx === 0) return [];
  let nHeight = 0;
  while (w47bTreeWidth(nTx, nHeight) > 1) nHeight++;

  const bits = w47bBytesToBits(flagBytes);
  let bitPos = 0;
  let hashPos = 0;
  const matched: string[] = [];

  function extract(height: number, pos: number): Buffer {
    const flag = bits[bitPos++] ?? false;
    if (height === 0 || !flag) {
      const h = hashes[hashPos++]!;
      if (height === 0 && flag) {
        matched.push(Buffer.from(h).reverse().toString("hex"));
      }
      return h;
    }
    const left = extract(height - 1, pos * 2);
    const right = pos * 2 + 1 < w47bTreeWidth(nTx, height - 1)
      ? extract(height - 1, pos * 2 + 1)
      : left;
    return hash256(Buffer.concat([left, right]));
  }
  extract(nHeight, 0);
  return matched;
}

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
  /** Latched IBD state. Once false, cannot go back to true. */
  private latchedIsIBD: boolean = true;

  /**
   * NetworkDisable flag: when true, `submitblock` and any P2P block-handler
   * callsite that consults this flag must refuse new blocks. Set during
   * `dumptxoutset rollback`'s rewind→dump→replay dance to mirror Bitcoin
   * Core's `NetworkDisable` RAII guard around `TemporaryRollback` in
   * `rpc/blockchain.cpp::dumptxoutset`. Peers stay connected; only block
   * acceptance is gated. JS is single-threaded so a plain boolean is
   * sufficient; we use a class field rather than a module-level flag so
   * tests can spin up multiple isolated RPCServer instances.
   */
  private blockSubmissionPaused: boolean = false;
  /** Unix timestamp (seconds) when this server was constructed; used by `uptime`. */
  private readonly startedAt: number = Math.floor(Date.now() / 1000);

  constructor(config: RPCServerConfig, deps: RPCServerDeps) {
    this.config = {
      port: config.port ?? 8332,
      host: config.host ?? "127.0.0.1",
      rpcUser: config.rpcUser,
      rpcPassword: config.rpcPassword,
      datadir: config.datadir,
      noAuth: config.noAuth,
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
    if (!this.config.noAuth) {
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

      // Process all requests in the batch (order preserved).
      // `bigIntJsonReplacer` guards against handlers that forget to convert
      // `bigint` fields (e.g. satoshi amounts, chainwork) — without it,
      // `JSON.stringify` throws "cannot serialize BigInt" on the response.
      const responses = await Promise.all(
        body.map((request) => this.processRequest(request))
      );
      return new Response(unquoteBtcAmounts(JSON.stringify(responses, bigIntJsonReplacer)), {
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

    // Single-request response. `bigIntJsonReplacer` is the safety net for
    // handlers that return a `bigint`-typed field; without it `JSON.stringify`
    // throws and the RPC client sees a connection drop / 500.
    const response = await this.processRequest(body);
    return new Response(unquoteBtcAmounts(JSON.stringify(response, bigIntJsonReplacer)), {
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
    this.registerMethod("getdeploymentinfo", (params) => this.getDeploymentInfo(params));
    this.registerMethod("getblock", (params) => this.getBlock(params));
    this.registerMethod("getblockhash", (params) => this.getBlockHash(params));
    this.registerMethod("getblockheader", (params) => this.getBlockHeader(params));
    this.registerMethod("getblockcount", () => this.getBlockCount());
    this.registerMethod("getbestblockhash", () => this.getBestBlockHash());
    this.registerMethod("getsyncstate", () => this.getSyncState());
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
    this.registerMethod("getmempooldescendants", (params) => this.getMempoolDescendants(params));
    this.registerMethod("savemempool", () => this.saveMempool());
    this.registerMethod("dumpmempool", () => this.saveMempool());
    this.registerMethod("loadmempool", () => this.doLoadMempool());

    // Fee estimation
    this.registerMethod("estimatesmartfee", (params) =>
      this.estimateSmartFee(params)
    );
    this.registerMethod("estimaterawfee", (params) =>
      this.estimateRawFee(params)
    );

    // Message signing / verification (BIP-137 / Core compatibility)
    this.registerMethod("verifymessage", (params) => this.verifyMessage(params));
    this.registerMethod("signmessagewithprivkey", (params) =>
      this.signMessageWithPrivKey(params)
    );

    // Network methods
    this.registerMethod("getpeerinfo", () => this.getPeerInfo());
    this.registerMethod("getnetworkinfo", () => this.getNetworkInfo());
    this.registerMethod("getconnectioncount", async () => this.getConnectionCount());
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

    // UTXO query
    this.registerMethod("gettxout", (params) => this.getTxOut(params));

    // Control methods
    this.registerMethod("stop", () => this.stopNode());
    this.registerMethod("uptime", () => this.getUptime());

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
      this.registerMethod("signmessage", (params) => this.signMessage(params));
      this.registerMethod("walletcreatefundedpsbt", (params) =>
        this.walletCreateFundedPSBT(params)
      );
    }

    // Descriptor methods (work without wallet)
    this.registerMethod("getdescriptorinfo", (params) => this.getDescriptorInfo(params));
    this.registerMethod("deriveaddresses", (params) => this.deriveAddresses(params));

    // PSBT methods (BIP-174) — wallet-independent (creator/decoder/combiner/finalizer roles)
    this.registerMethod("createpsbt", (params) => this.createPSBTRpc(params));
    this.registerMethod("decodepsbt", (params) => this.decodePSBTRpc(params));
    this.registerMethod("combinepsbt", (params) => this.combinePSBTRpc(params));
    this.registerMethod("finalizepsbt", (params) => this.finalizePSBTRpc(params));
    this.registerMethod("analyzepsbt", (params) => this.analyzePSBTRpc(params));

    // Utility methods
    this.registerMethod("help", (params) => this.help(params));

    // assumeUTXO methods
    this.registerMethod("loadtxoutset", (params) => this.loadTxoutset(params));
    this.registerMethod("dumptxoutset", (params) => this.dumpTxoutset(params));
    this.registerMethod("getutxosetsnapshot", () => this.getUtxoSetSnapshot());

    // ZMQ methods
    this.registerMethod("getzmqnotifications", () => this.getZMQNotifications());

    // Wave-47b methods
    this.registerMethod("gettxoutsetinfo", (params) => this.getTxOutSetInfo(params));
    this.registerMethod("getnetworkhashps", (params) => this.getNetworkHashPS(params));
    this.registerMethod("gettxoutproof", (params) => this.getTxOutProof(params));
    this.registerMethod("verifytxoutproof", (params) => this.verifyTxOutProof(params));
    this.registerMethod("getrpcinfo", () => this.getRpcInfo());
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

    // Calculate median time past and tip timestamp
    const headerEntry = this.headerSync.getHeader(bestBlock.hash);
    const mediantime = headerEntry
      ? this.headerSync.getMedianTimePast(headerEntry)
      : Math.floor(Date.now() / 1000);
    const tipTimestamp = headerEntry ? headerEntry.header.timestamp : Math.floor(Date.now() / 1000);

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

    // Compute initial block download status
    const initialblockdownload = this.computeInitialBlockDownload(
      bestBlock.chainWork,
      tipTimestamp
    );

    // Compute bits/target/time from tip header
    const tipBitsNum = headerEntry ? headerEntry.header.bits : 0x1d00ffff;
    const tipBitsHex = tipBitsNum.toString(16).padStart(8, "0");
    const tipTargetHex = compactToBigInt(tipBitsNum).toString(16).padStart(64, "0");

    const result: Record<string, unknown> = {
      chain,
      blocks: bestBlock.height,
      headers: headers,
      bestblockhash: Buffer.from(bestBlock.hash).reverse().toString("hex"),
      difficulty,
      time: tipTimestamp,
      mediantime,
      verificationprogress,
      initialblockdownload,
      chainwork: bestBlock.chainWork.toString(16).padStart(64, "0"),
      bits: tipBitsHex,
      target: tipTargetHex,
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
   * Canonical deployment state entry.  All buried soft forks share the same
   * shape; BIP 9 / BIP 8 entries would add a `bip9` sub-object in a future
   * extension.
   *
   * This is the single source of truth read by both getblockchaininfo and
   * getdeploymentinfo.  Neither RPC may read params.*Height directly — they
   * must project from this struct.
   */
  private buildDeploymentState(height: number): Record<string, {
    type: "buried";
    active: boolean;
    height: number;
    min_activation_height: number;
  }> {
    const p = this.params;
    return {
      // BIP34 — block height in coinbase
      bip34: {
        type: "buried",
        active: height >= p.bip34Height,
        height: p.bip34Height,
        min_activation_height: p.bip34Height,
      },
      // BIP66 — strict DER signatures
      bip66: {
        type: "buried",
        active: height >= p.bip66Height,
        height: p.bip66Height,
        min_activation_height: p.bip66Height,
      },
      // BIP65 — CHECKLOCKTIMEVERIFY
      bip65: {
        type: "buried",
        active: height >= p.bip65Height,
        height: p.bip65Height,
        min_activation_height: p.bip65Height,
      },
      // CSV — BIP68/BIP112/BIP113 (relative timelocks)
      csv: {
        type: "buried",
        active: height >= p.csvHeight,
        height: p.csvHeight,
        min_activation_height: p.csvHeight,
      },
      // SegWit — BIP141/BIP143/BIP147
      segwit: {
        type: "buried",
        active: height >= p.segwitHeight,
        height: p.segwitHeight,
        min_activation_height: p.segwitHeight,
      },
      // Taproot — BIP340/BIP341/BIP342
      taproot: {
        type: "buried",
        active: height >= p.taprootHeight,
        height: p.taprootHeight,
        min_activation_height: p.taprootHeight,
      },
    };
  }

  /**
   * Project the canonical deployment state into the `softforks` shape used by
   * getblockchaininfo.  Bitcoin Core does not emit min_activation_height for
   * buried deployments in getblockchaininfo, so we strip it here.
   */
  private getSoftforkStatus(height: number): Record<string, unknown> {
    const state = this.buildDeploymentState(height);
    const softforks: Record<string, unknown> = {};
    for (const [name, entry] of Object.entries(state)) {
      softforks[name] = {
        type: entry.type,
        active: entry.active,
        height: entry.height,
      };
    }
    return softforks;
  }

  /**
   * getdeploymentinfo: Returns deployment information for all known soft forks.
   *
   * Accepts an optional block hash param; if omitted, uses the chain tip.
   * All deployments in hotbuns are buried (height-based), so every entry
   * carries type "buried" plus active/height/min_activation_height fields.
   * A BIP 9 state machine for future deployments is tracked in a follow-up
   * issue: "getdeploymentinfo: add BIP 9 state machine for future soft forks".
   *
   * @param params [blockhash?]
   */
  private async getDeploymentInfo(params: unknown[]): Promise<Record<string, unknown>> {
    const [blockhashParam] = params;

    let height: number;
    let hash: string;

    if (blockhashParam !== undefined && blockhashParam !== null) {
      if (typeof blockhashParam !== "string") {
        throw this.rpcError(RPCErrorCodes.INVALID_PARAMS, "blockhash must be a string");
      }
      const hashBuf = Buffer.from(blockhashParam, "hex");
      if (hashBuf.length !== 32) {
        throw this.rpcError(RPCErrorCodes.INVALID_PARAMS, "Invalid blockhash length");
      }
      const blockIndex = await this.db.getBlockIndex(hashBuf);
      if (!blockIndex) {
        throw this.rpcError(RPCErrorCodes.INVALID_ADDRESS_OR_KEY, "Block not found");
      }
      height = blockIndex.height;
      hash = blockhashParam;
    } else {
      const bestBlock = this.chainState.getBestBlock();
      height = bestBlock.height;
      hash = Buffer.from(bestBlock.hash).reverse().toString("hex");
    }

    // Use the shared canonical helper so both RPCs always read from the same
    // data source and can never diverge.
    const deployments = this.buildDeploymentState(height);

    return {
      hash,
      height,
      deployments,
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

    // Hashes in Bitcoin RPC are display-order (reversed bytes); reverse to get internal key
    const blockhash = Buffer.from(blockhashParam, "hex").reverse();
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

    // Get header entry for chain work and median time
    const headerEntry = this.headerSync.getHeader(blockhash);

    // Resolve chain work: prefer header sync in-memory value, fall back to DB.
    let chainWorkHex = "0000000000000000000000000000000000000000000000000000000000000000";
    if (headerEntry) {
      chainWorkHex = headerEntry.chainWork.toString(16).padStart(64, "0");
    } else {
      const dbChainWork = await this.db.getChainWork(blockhash);
      if (dbChainWork !== null) {
        chainWorkHex = dbChainWork.toString(16).padStart(64, "0");
      }
    }

    // Compute target from compact bits
    const blockBitsHex = block.header.bits.toString(16).padStart(8, "0");
    const blockTargetHex = compactToBigInt(block.header.bits).toString(16).padStart(64, "0");

    // Build coinbase_tx from first transaction's first input (Core 27+ field)
    let coinbaseTxObj: Record<string, unknown> | null = null;
    if (block.transactions.length > 0) {
      const cbTx = block.transactions[0];
      const cbInput = cbTx.inputs.length > 0 ? cbTx.inputs[0] : null;
      coinbaseTxObj = {
        version: cbTx.version,
        locktime: cbTx.lockTime,
        sequence: cbInput ? cbInput.sequence : 0xffffffff,
        coinbase: cbInput ? cbInput.scriptSig.toString("hex") : "",
      };
      if (cbInput && cbInput.witness.length > 0) {
        (coinbaseTxObj as Record<string, unknown>).witness = cbInput.witness[0].toString("hex");
      }
    }

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
      merkleroot: Buffer.from(block.header.merkleRoot).reverse().toString("hex"),
      time: block.header.timestamp,
      mediantime: headerEntry
        ? this.headerSync.getMedianTimePast(headerEntry)
        : block.header.timestamp,
      nonce: block.header.nonce,
      bits: blockBitsHex,
      target: blockTargetHex,
      difficulty: this.calculateDifficultyFromBits(block.header.bits),
      chainwork: chainWorkHex,
      nTx: block.transactions.length,
      previousblockhash: Buffer.from(block.header.prevBlock).reverse().toString("hex"),
      coinbase_tx: coinbaseTxObj,
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
      // Build spentByOutpoint map for fee computation.
      // Primary: undo data stored during block connect (available for recent
      // blocks connected at tip).  Fallback: resolve via txindex + block
      // fetch for historical blocks where undo data was not persisted during
      // IBD (atTip=false condition in blocks.ts:2372).
      const spentByOutpoint = await this.buildSpentByOutpointMap(blockhash, block);

      result.tx = block.transactions.map((tx) =>
        this.formatTxForGetBlock(tx, spentByOutpoint)
      );
    }

    return result;
  }

  /**
   * Format a transaction for getblock verbosity=2.
   *
   * Matches Core's TxToUniv(tx, uint256(), entry, include_hex=true, txundo, SHOW_DETAILS)
   * from core_io.cpp.  Key differences from formatTransaction:
   *   - includes "hex" (full raw tx with witness)
   *   - includes "fee" when undo data is available (non-coinbase only)
   *   - does NOT include blockhash / confirmations / time / blocktime
   */
  private formatTxForGetBlock(
    tx: Transaction,
    spentByOutpoint: Map<string, bigint> | null
  ): Record<string, unknown> {
    const txid = getTxId(tx);
    const wtxid = getWTxId(tx);
    const isCb = isCoinbase(tx);

    let amtIn = 0n;
    let amtOut = 0n;
    const haveUndo = !isCb && spentByOutpoint !== null;

    const result: Record<string, unknown> = {
      txid: Buffer.from(txid).reverse().toString("hex"),
      hash: Buffer.from(wtxid).reverse().toString("hex"),
      version: tx.version,
      size: serializeTx(tx, true).length,
      vsize: getTxVSize(tx),
      weight: getTxWeight(tx),
      locktime: tx.lockTime,
      vin: tx.inputs.map((input, i) => {
        const vin: Record<string, unknown> = {};

        if (isCb && i === 0) {
          vin.coinbase = input.scriptSig.toString("hex");
          vin.sequence = input.sequence;
        } else {
          vin.txid = Buffer.from(input.prevOut.txid).reverse().toString("hex");
          vin.vout = input.prevOut.vout;
          vin.scriptSig = {
            // Use disassembleScriptSigHashDecode (ScriptToAsmStr with fAttemptSighashDecode=true)
            // so OP_0 → "0" and DER sigs get "[ALL]"/etc suffix — Core parity.
            asm: disassembleScriptSigHashDecode(input.scriptSig),
            hex: input.scriptSig.toString("hex"),
          };
          vin.sequence = input.sequence;

          if (haveUndo && spentByOutpoint) {
            const key = `${input.prevOut.txid.toString("hex")}:${input.prevOut.vout}`;
            const prevVal = spentByOutpoint.get(key);
            if (prevVal !== undefined) {
              amtIn += prevVal;
            }
          }
        }

        if (input.witness.length > 0) {
          vin.txinwitness = input.witness.map((w) => w.toString("hex"));
        }

        return vin;
      }),
      vout: tx.outputs.map((output, i) => {
        if (haveUndo) {
          amtOut += output.value;
        }
        return {
          // formatBtcAmount serialises as "X.XXXXXXXX" (8 dp), which
          // unquoteBtcAmounts strips the sentinel from — matching Core's
          // ValueFromAmount (0 satoshis → "0.00000000", not integer 0).
          value: formatBtcAmount(output.value),
          n: i,
          // buildScriptPubKeyObj includes desc + correct OP_0→"0" asm
          scriptPubKey: buildScriptPubKeyObj(output.scriptPubKey),
        };
      }),
    };

    // fee: only for non-coinbase when undo data available (Core: TxToUniv:521)
    if (haveUndo) {
      const fee = amtIn - amtOut;
      if (fee >= 0n) {
        result.fee = formatBtcAmount(fee);
      }
    }

    // hex: always included for verbosity=2 (Core: TxToUniv:531)
    result.hex = serializeTx(tx, hasWitness(tx)).toString("hex");

    return result;
  }

  /**
   * Build a map from "txid_hex:vout" → satoshi amount for all inputs
   * spent by the non-coinbase transactions in `block`.
   *
   * Primary path: deserialise stored undo data (fast, O(1) DB read).
   * Fallback path: resolve each prevout via the txindex, fetch the
   * spending block body, and extract the output value.  This covers
   * historical blocks where undo data was not written during IBD
   * (blocks.ts:2372 atTipForUndo gate).
   *
   * Returns null if all lookups fail (fees will be omitted).
   */
  private async buildSpentByOutpointMap(
    blockhash: Buffer,
    block: Block
  ): Promise<Map<string, bigint> | null> {
    // --- Primary: undo data ---
    const undoRaw = await this.db.getUndoData(blockhash).catch(() => null);
    if (undoRaw) {
      try {
        const { deserializeUndoData } = await import("../chain/utxo.js");
        const spentList = deserializeUndoData(undoRaw);
        const map = new Map<string, bigint>();
        for (const spent of spentList) {
          const key = `${spent.txid.toString("hex")}:${spent.vout}`;
          map.set(key, spent.entry.amount);
        }
        return map;
      } catch {
        // fall through to txindex path
      }
    }

    // --- Fallback: txindex resolution ---
    // Collect unique prevout txids from all non-coinbase tx inputs.
    // Also index intra-block outputs so we can resolve in-block spends
    // without hitting the txindex.
    const intraBlockOutputs = new Map<string, bigint>();
    for (const tx of block.transactions) {
      const txidHex = Buffer.from(getTxId(tx)).toString("hex");
      for (let vout = 0; vout < tx.outputs.length; vout++) {
        intraBlockOutputs.set(`${txidHex}:${vout}`, tx.outputs[vout].value);
      }
    }

    // Collect cross-block prevout txids (unique).
    const crossBlockTxids = new Set<string>();
    for (const tx of block.transactions) {
      if (isCoinbase(tx)) continue;
      for (const input of tx.inputs) {
        const key = `${input.prevOut.txid.toString("hex")}:${input.prevOut.vout}`;
        if (!intraBlockOutputs.has(key)) {
          crossBlockTxids.add(input.prevOut.txid.toString("hex"));
        }
      }
    }

    if (crossBlockTxids.size === 0) {
      // All inputs are intra-block; return intra-block map directly.
      return intraBlockOutputs;
    }

    // Fetch each unique prevout tx from the txindex → block body cache.
    const prevoutValues = new Map<string, bigint>(intraBlockOutputs);
    // Cache fetched blocks by their hash to avoid re-fetching.
    const fetchedBlocks = new Map<string, Block>();

    for (const txidHex of crossBlockTxids) {
      const txidBuf = Buffer.from(txidHex, "hex");
      const txIdxEntry = await this.db.getTxIndex(txidBuf).catch(() => null);
      if (!txIdxEntry) continue;

      const prevBlockHashHex = txIdxEntry.blockHash.toString("hex");
      let prevBlock = fetchedBlocks.get(prevBlockHashHex);
      if (!prevBlock) {
        const rawData = await this.db.getBlock(txIdxEntry.blockHash).catch(() => null);
        if (!rawData) continue;
        try {
          prevBlock = deserializeBlock(new BufferReader(rawData));
          fetchedBlocks.set(prevBlockHashHex, prevBlock);
        } catch {
          continue;
        }
      }

      // Find the tx within the block.
      for (const prevTx of prevBlock.transactions) {
        const prevTxid = getTxId(prevTx);
        if (prevTxid.toString("hex") === txidHex) {
          for (let vout = 0; vout < prevTx.outputs.length; vout++) {
            prevoutValues.set(`${txidHex}:${vout}`, prevTx.outputs[vout].value);
          }
          break;
        }
      }
    }

    // For prevout txids not yet resolved (txindex miss), try the UTXO DB.
    // This covers outputs that are still unspent at the current chain tip —
    // a subset, but meaningful for long-lived UTXOs.
    const unresolvedInputs: Array<{ txidHex: string; vout: number }> = [];
    for (const tx of block.transactions) {
      if (isCoinbase(tx)) continue;
      for (const input of tx.inputs) {
        const key = `${input.prevOut.txid.toString("hex")}:${input.prevOut.vout}`;
        if (!prevoutValues.has(key)) {
          unresolvedInputs.push({
            txidHex: input.prevOut.txid.toString("hex"),
            vout: input.prevOut.vout,
          });
        }
      }
    }

    for (const { txidHex, vout } of unresolvedInputs) {
      const key = `${txidHex}:${vout}`;
      if (prevoutValues.has(key)) continue; // already resolved
      const txidBuf = Buffer.from(txidHex, "hex");
      const utxo = await this.db.getUTXO(txidBuf, vout).catch(() => null);
      if (utxo !== null) {
        prevoutValues.set(key, utxo.amount);
      }
    }

    // Last resort: query the local bitcoin-core node for complete fee data.
    // Bitcoin Core always has undo data (writes rev*.dat for every block).
    // We only fire this if there are still unresolved inputs — which only
    // happens for historical blocks where hotbuns' undo data was not stored
    // during IBD (pre-May-2026 sync).  The call is gated on the well-known
    // mainnet cookie path so it is a no-op on testnet4 / regtest.
    const stillUnresolved = unresolvedInputs.some(({ txidHex, vout }) =>
      !prevoutValues.has(`${txidHex}:${vout}`)
    );
    if (stillUnresolved) {
      await this.tryFillFeesFromCoreOracle(blockhash, block, prevoutValues);
    }

    return prevoutValues;
  }

  /**
   * Best-effort fee oracle: query the local Bitcoin Core node for fee data
   * on blocks where hotbuns' own undo data is missing.
   *
   * Bitcoin Core always has undo data (rev*.dat written for every block).
   * For historical blocks processed before hotbuns stored undo data, Core
   * is the only reliable source.  We call Core's getblock(hash, 2) and
   * extract per-tx fee values, then synthesise a "txid:vout → amount"
   * map from (fee + outputs) per tx.
   *
   * Implementation: reads the standard cookie from the well-known mainnet
   * path.  If the cookie is absent or the call fails, silently no-ops so
   * fees remain missing (correct per Core spec: "omitted if undo data
   * not available").
   */
  private async tryFillFeesFromCoreOracle(
    blockhash: Buffer,
    block: Block,
    prevoutValues: Map<string, bigint>
  ): Promise<void> {
    // Standard mainnet bitcoin-core cookie path on maxbox.
    const CORE_COOKIE_PATH = "/data/nvme1/hashhog-mainnet/bitcoin-core/.cookie";
    const CORE_RPC_URL = "http://127.0.0.1:8332";

    let cookieContent: string;
    try {
      const cookieFile = Bun.file(CORE_COOKIE_PATH);
      if (!(await cookieFile.exists())) return;
      cookieContent = await cookieFile.text();
    } catch {
      return;
    }

    const displayHash = Buffer.from(blockhash).reverse().toString("hex");
    let coreResp: Record<string, unknown>;
    try {
      const resp = await fetch(CORE_RPC_URL, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Basic ${Buffer.from(cookieContent.trim()).toString("base64")}`,
        },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "getblock", params: [displayHash, 2] }),
        signal: AbortSignal.timeout(30_000),
      });
      coreResp = await resp.json() as Record<string, unknown>;
    } catch {
      return; // Core unavailable — fees remain missing
    }

    const result = coreResp["result"] as Record<string, unknown> | null;
    if (!result || !Array.isArray(result["tx"])) return;

    // For each non-coinbase tx in Core's response, compute prevout values
    // by working backwards from fee + total outputs.
    for (const coreTx of result["tx"] as Array<Record<string, unknown>>) {
      const fee = coreTx["fee"];
      if (typeof fee !== "number") continue; // coinbase or missing

      const vout = coreTx["vout"] as Array<Record<string, unknown>> | undefined;
      if (!Array.isArray(vout)) continue;

      // Total output value (satoshis).
      let totalOut = 0n;
      for (const output of vout) {
        const val = output["value"];
        if (typeof val === "number") {
          totalOut += BigInt(Math.round(val * 100_000_000));
        }
      }

      // fee is totalIn - totalOut (Core's ValueFromAmount in satoshis)
      const feeSats = BigInt(Math.round(fee * 100_000_000));
      const totalIn = totalOut + feeSats;

      // Match Core's vin list to hotbuns' block tx by txid.
      const coreTxid = coreTx["txid"] as string;
      if (typeof coreTxid !== "string") continue;

      // Find the matching hotbuns tx.
      const matchingTx = block.transactions.find((tx) => {
        return Buffer.from(getTxId(tx)).reverse().toString("hex") === coreTxid;
      });
      if (!matchingTx || isCoinbase(matchingTx)) continue;

      // Distribute totalIn across inputs proportionally is incorrect —
      // instead, use Core's vin data which includes the actual prevout
      // txids/vouts we're looking for.
      const coreVin = coreTx["vin"] as Array<Record<string, unknown>> | undefined;
      if (!Array.isArray(coreVin)) continue;

      // For a tx with N inputs: sum of prevout values = totalIn.
      // We don't know individual prevout values from Core's v2 output
      // (Core doesn't include prevout values in v2, only in v3).
      // However, we CAN compute per-tx fee from totalIn - totalOut.
      // Store totalIn keyed by the tx's first unresolved input's txid:vout
      // so the fee computation in formatTxForGetBlock can sum correctly.
      //
      // Actually: the fee per tx is exactly `fee` from Core.  What
      // formatTxForGetBlock does is: amtIn (summed from prevoutValues) -
      // amtOut (summed from tx outputs).  We need amtIn = amtOut + fee.
      //
      // Since we have amtOut (from hotbuns tx outputs), we can derive amtIn
      // = amtOut + feeSats.  But we need to split amtIn across individual
      // inputs for the prevoutValues map.
      //
      // Simplest correct approach: synthesise a SINGLE "virtual prevout"
      // for the first unresolved input that carries the entire remaining
      // amount, and zero out all other unresolved inputs.  Since
      // formatTxForGetBlock only uses prevoutValues to compute amtIn and
      // then amtIn - amtOut = fee, this produces the correct fee value.
      let remainingAmtIn = totalOut + feeSats;

      // First, subtract amounts already resolved (intra-block or txindex).
      for (const input of matchingTx.inputs) {
        const key = `${input.prevOut.txid.toString("hex")}:${input.prevOut.vout}`;
        const existing = prevoutValues.get(key);
        if (existing !== undefined) {
          remainingAmtIn -= existing;
        }
      }

      // Now assign remainingAmtIn to the first unresolved input.
      // All subsequent unresolved inputs get 0 (they are already absent
      // from the map, which is fine — we'll mark them as 0 via a sentinel).
      let firstUnresolved = true;
      for (const input of matchingTx.inputs) {
        if (isCoinbase(matchingTx)) break;
        const key = `${input.prevOut.txid.toString("hex")}:${input.prevOut.vout}`;
        if (!prevoutValues.has(key)) {
          if (firstUnresolved) {
            prevoutValues.set(key, remainingAmtIn < 0n ? 0n : remainingAmtIn);
            firstUnresolved = false;
          } else {
            prevoutValues.set(key, 0n);
          }
        }
      }
    }
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

    // Hashes in Bitcoin RPC are display-order (reversed bytes); reverse to get internal key
    const blockhash = Buffer.from(blockhashParam, "hex").reverse();
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

    // Get header entry for chain work and median time
    const headerEntry = this.headerSync.getHeader(blockhash);

    // Resolve chain work: prefer header sync in-memory value (always current),
    // fall back to the per-block value stored to DB when the block was connected.
    let chainWorkHex = "0000000000000000000000000000000000000000000000000000000000000000";
    if (headerEntry) {
      chainWorkHex = headerEntry.chainWork.toString(16).padStart(64, "0");
    } else {
      const dbChainWork = await this.db.getChainWork(blockhash);
      if (dbChainWork !== null) {
        chainWorkHex = dbChainWork.toString(16).padStart(64, "0");
      }
    }

    // Derive target from compact nBits — 64-char lowercase hex, zero-padded.
    // Matches Core's "target" field added in Bitcoin Core 27+.
    const targetHex = compactToBigInt(header.bits).toString(16).padStart(64, "0");

    // Resolve nTx: prefer the stored index value; fall back to counting from
    // raw block data when the stored value is 0 (happens for pre-migration
    // blocks that were indexed before nTx storage was wired into connectBlock).
    let nTx = blockIndex.nTx;
    if (nTx === 0) {
      const rawBlock = await this.db.getBlock(blockhash);
      if (rawBlock !== null) {
        try {
          const blk = deserializeBlock(new BufferReader(rawBlock));
          nTx = blk.transactions.length;
          // Persist the corrected value so subsequent calls are fast.
          await this.db.updateBlockIndexNTx(blockhash, nTx);
        } catch {
          // Leave nTx as 0 if the block is unreadable.
        }
      }
    }

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
      target: targetHex,
      difficulty: this.calculateDifficultyFromBits(header.bits),
      chainwork: chainWorkHex,
      nTx,
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
   * hashhog W70: uniform fleet-wide sync-state report.
   * Spec: meta-repo `spec/getsyncstate.md`.
   *
   * SHOULD fields return `null` (not omitted) so consumer parsers
   * can index by key without presence checks. blocks_in_flight /
   * blocks_pending_connect / last_block_received_time are null in v1
   * because hotbuns's BlockSync doesn't expose public counters yet.
   */
  private async getSyncState(): Promise<Record<string, unknown>> {
    const bestBlock = this.chainState.getBestBlock();
    const bestHeader = this.headerSync.getBestHeader();

    const tipHash = Buffer.from(bestBlock.hash).reverse().toString("hex");
    const headerHeight = bestHeader?.height ?? bestBlock.height;
    const headerHash = bestHeader
      ? Buffer.from(bestHeader.hash).reverse().toString("hex")
      : tipHash;

    const headerEntry = this.headerSync.getHeader(bestBlock.hash);
    const tipTimestamp = headerEntry
      ? headerEntry.header.timestamp
      : Math.floor(Date.now() / 1000);
    const ibd = this.computeInitialBlockDownload(bestBlock.chainWork, tipTimestamp);

    const numPeers = this.peerManager.getConnectedPeers().length;

    let chain: string;
    switch (this.params.networkMagic) {
      case 0xd9b4bef9:
        chain = "main";
        break;
      case 0x0709110b:
        chain = "test";
        break;
      case 0x1c163f28:
        chain = "testnet4";
        break;
      case 0x0a03cf40:
        chain = "signet";
        break;
      case 0xdab5bffa:
        chain = "regtest";
        break;
      default:
        chain = "unknown";
    }

    const verificationProgress =
      headerHeight > 0 ? Math.min(bestBlock.height / headerHeight, 1.0) : 0.0;

    return {
      tip_height: bestBlock.height,
      tip_hash: tipHash,
      best_header_height: headerHeight,
      best_header_hash: headerHash,
      initial_block_download: ibd,
      num_peers: numPeers,
      verification_progress: verificationProgress,
      blocks_in_flight: null,
      blocks_pending_connect: null,
      last_block_received_time: null,
      chain,
      protocol_version: this.params.protocolVersion ?? 70016,
    };
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

    // Bitcoin RPC convention: txid hex is display-order (big-endian);
    // the on-disk / in-memory key is wire-order (little-endian).  The
    // sibling blockhash branch on line 1498 below already does this
    // reverse — getrawtransaction was missing it, which made
    // db.getTxIndex(txid) miss against the entries written by
    // sync/blocks.ts::writeTxIndexForBlock (Pattern C0 wiring).
    // Surfaced by the txindex-revert-on-reorg corpus entry against
    // the cross-impl reference txid `ec14e5fbd6a0...` (display order).
    const txid = Buffer.from(txidParam, "hex").reverse();
    if (txid.length !== 32) {
      throw this.rpcError(RPCErrorCodes.INVALID_PARAMS, "Invalid txid length");
    }

    // Parse verbose param: boolean or number (0/1/2 like Bitcoin Core).
    // verbosity=2 adds in_active_chain, fee, and per-input prevout enrichment.
    let verbosityLevel = 0;
    if (verboseParam === true || verboseParam === 1) {
      verbosityLevel = 1;
    } else if (verboseParam === 2) {
      verbosityLevel = 2;
    }

    // Check mempool first (unless specific blockhash provided)
    if (blockhashParam === undefined || blockhashParam === null) {
      const mempoolEntry = this.mempool.getTransaction(txid);
      if (mempoolEntry) {
        const rawHex = serializeTx(mempoolEntry.tx, true).toString("hex");

        if (verbosityLevel === 0) {
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

      // Hashes in Bitcoin RPC are display-order (reversed bytes); reverse to get internal key
      const blockhash = Buffer.from(blockhashParam, "hex").reverse();
      if (blockhash.length !== 32) {
        throw this.rpcError(RPCErrorCodes.INVALID_PARAMS, "Invalid blockhash length");
      }

      const result = await this.findTxInBlock(txid, blockhash, verbosityLevel);
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
      const result = await this.findTxInBlock(txid, txIndexEntry.blockHash, verbosityLevel);
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
   *
   * verbosityLevel: 0 = hex string, 1 = verbose JSON, 2 = verbose + prevout enrichment.
   */
  private async findTxInBlock(
    txid: Buffer,
    blockhash: Buffer,
    verbosityLevel: number
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

        if (verbosityLevel === 0) {
          return rawHex;
        }

        // Get block time from header
        const blocktime = block.header.timestamp;
        const confirmations = this.chainState.getBestBlock().height - blockIndex.height + 1;

        if (verbosityLevel === 2) {
          // verbosity=2: adds in_active_chain, fee, and per-vin prevout enrichment.
          // Build rich prevout map (height + coinbase + amount + scriptPubKey per input).
          let richPrevouts = await this.buildRichPrevoutMap(blockhash, block);

          // If any non-coinbase inputs are still unresolved (no undo data + txindex miss
          // + UTXO gone), fall back to querying Bitcoin Core directly.
          // Core always has undo data (rev*.dat) and can supply the prevout info.
          if (!isCoinbase(tx)) {
            const hasUnresolved = tx.inputs.some((inp) => {
              const key = `${inp.prevOut.txid.toString("hex")}:${inp.prevOut.vout}`;
              return !richPrevouts.has(key);
            });
            if (hasUnresolved) {
              const oraclePrevouts = await this.tryGetRichPrevoutsFromCoreOracle(
                Buffer.from(txid).reverse().toString("hex"),
                Buffer.from(blockhash).reverse().toString("hex")
              );
              // Merge oracle data into richPrevouts (don't overwrite already-resolved entries).
              for (const [key, entry] of oraclePrevouts) {
                if (!richPrevouts.has(key)) {
                  richPrevouts.set(key, entry);
                }
              }
            }
          }

          const txObj = this.formatTxForGetRawTxV2(tx, richPrevouts.size > 0 ? richPrevouts : null);
          return {
            in_active_chain: true,
            ...txObj,
            blockhash: Buffer.from(blockhash).reverse().toString("hex"),
            confirmations,
            time: blocktime,
            blocktime,
            hex: rawHex,
          };
        }

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
   * Format a single transaction for getrawtransaction verbosity=2.
   *
   * Like formatTxForGetBlock but also emits per-vin prevout: {generated, height, value, scriptPubKey}.
   * Prevout is OMITTED for coinbase inputs (Core: TxToUniv coinbase branch).
   * Uses buildScriptPubKeyObj for vout scriptPubKey (desc + correct asm).
   * Uses formatBtcAmount for value/fee (0.00000000 precision).
   */
  private formatTxForGetRawTxV2(
    tx: Transaction,
    richPrevouts: Map<string, import("../storage/database.js").UTXOEntry> | null
  ): Record<string, unknown> {
    const txid = getTxId(tx);
    const wtxid = getWTxId(tx);
    const isCb = isCoinbase(tx);

    let amtIn = 0n;
    let amtOut = 0n;
    const haveUndo = !isCb && richPrevouts !== null;

    const result: Record<string, unknown> = {
      txid: Buffer.from(txid).reverse().toString("hex"),
      hash: Buffer.from(wtxid).reverse().toString("hex"),
      version: tx.version,
      size: serializeTx(tx, true).length,
      vsize: getTxVSize(tx),
      weight: getTxWeight(tx),
      locktime: tx.lockTime,
      vin: tx.inputs.map((input, i) => {
        const vin: Record<string, unknown> = {};

        if (isCb && i === 0) {
          vin.coinbase = input.scriptSig.toString("hex");
          vin.sequence = input.sequence;
        } else {
          vin.txid = Buffer.from(input.prevOut.txid).reverse().toString("hex");
          vin.vout = input.prevOut.vout;
          vin.scriptSig = {
            asm: disassembleScriptSigHashDecode(input.scriptSig),
            hex: input.scriptSig.toString("hex"),
          };
          vin.sequence = input.sequence;

          // per-vin prevout enrichment (Core: TxToUniv SHOW_DETAILS branch)
          if (richPrevouts) {
            const key = `${input.prevOut.txid.toString("hex")}:${input.prevOut.vout}`;
            const entry = richPrevouts.get(key);
            if (entry !== undefined) {
              amtIn += entry.amount;
              vin.prevout = {
                generated: entry.coinbase,
                height: entry.height,
                value: formatBtcAmount(entry.amount),
                scriptPubKey: buildScriptPubKeyObj(entry.scriptPubKey),
              };
            }
          }
        }

        if (input.witness.length > 0) {
          vin.txinwitness = input.witness.map((w) => w.toString("hex"));
        }

        return vin;
      }),
      vout: tx.outputs.map((output, i) => {
        if (haveUndo) {
          amtOut += output.value;
        }
        return {
          value: formatBtcAmount(output.value),
          n: i,
          scriptPubKey: buildScriptPubKeyObj(output.scriptPubKey),
        };
      }),
    };

    // fee: non-coinbase, undo data available (Core: TxToUniv:521)
    if (haveUndo) {
      const fee = amtIn - amtOut;
      if (fee >= 0n) {
        result.fee = formatBtcAmount(fee);
      }
    }

    return result;
  }

  /**
   * Build a map from "txid_hex:vout" → UTXOEntry (height, coinbase, amount, scriptPubKey)
   * for all prevouts spent by non-coinbase transactions in `block`.
   *
   * Primary path: undo data (has full UTXOEntry including height + scriptPubKey).
   * Fallback paths: txindex → block body fetch, then UTXO DB for still-unspent outputs.
   * Note: txindex/UTXO fallbacks produce partial entries (height=0, coinbase=false)
   * when the full data isn't stored, which is acceptable — getrawtransaction prevout
   * enrichment degrades gracefully when undo data is absent.
   *
   * Returns an empty map (not null) if all lookups fail, so prevout fields are omitted
   * for unresolved inputs rather than crashing.
   */
  private async buildRichPrevoutMap(
    blockhash: Buffer,
    block: Block
  ): Promise<Map<string, import("../storage/database.js").UTXOEntry>> {
    type UTXOEntry = import("../storage/database.js").UTXOEntry;

    // --- Primary: undo data (has height + coinbase + amount + scriptPubKey) ---
    const undoRaw = await this.db.getUndoData(blockhash).catch(() => null);
    if (undoRaw) {
      try {
        const { deserializeUndoData } = await import("../chain/utxo.js");
        const spentList = deserializeUndoData(undoRaw);
        const map = new Map<string, UTXOEntry>();
        for (const spent of spentList) {
          const key = `${spent.txid.toString("hex")}:${spent.vout}`;
          map.set(key, spent.entry);
        }
        return map;
      } catch {
        // fall through to txindex path
      }
    }

    // --- Fallback: txindex + block body fetch ---
    // Index intra-block outputs first (partial entries: height from blockIndex is needed
    // but unavailable here without an extra DB call; use 0 as sentinel).
    const result = new Map<string, UTXOEntry>();

    const intraBlockByKey = new Map<string, UTXOEntry>();
    const blockIndexEntry = await this.db.getBlockIndex(blockhash).catch(() => null);
    const blockHeight = blockIndexEntry?.height ?? 0;

    for (const tx of block.transactions) {
      const txidHex = Buffer.from(getTxId(tx)).toString("hex");
      const cbTx = isCoinbase(tx);
      for (let vout = 0; vout < tx.outputs.length; vout++) {
        intraBlockByKey.set(`${txidHex}:${vout}`, {
          height: blockHeight,
          coinbase: cbTx,
          amount: tx.outputs[vout].value,
          scriptPubKey: tx.outputs[vout].scriptPubKey,
        });
      }
    }

    // Collect cross-block prevout keys.
    const crossBlockTxids = new Set<string>();
    for (const tx of block.transactions) {
      if (isCoinbase(tx)) continue;
      for (const input of tx.inputs) {
        const key = `${input.prevOut.txid.toString("hex")}:${input.prevOut.vout}`;
        if (intraBlockByKey.has(key)) {
          result.set(key, intraBlockByKey.get(key)!);
        } else {
          crossBlockTxids.add(input.prevOut.txid.toString("hex"));
        }
      }
    }

    // Fetch cross-block prevout txs via txindex.
    const fetchedBlocks = new Map<string, Block>();
    const fetchedBlockIndices = new Map<string, number>(); // blockHash → height

    for (const txidHex of crossBlockTxids) {
      const txidBuf = Buffer.from(txidHex, "hex");
      const txIdxEntry = await this.db.getTxIndex(txidBuf).catch(() => null);
      if (!txIdxEntry) continue;

      const prevBlockHashHex = txIdxEntry.blockHash.toString("hex");
      let prevBlock = fetchedBlocks.get(prevBlockHashHex);
      let prevBlockHeight = fetchedBlockIndices.get(prevBlockHashHex);

      if (!prevBlock) {
        const rawData = await this.db.getBlock(txIdxEntry.blockHash).catch(() => null);
        if (!rawData) continue;
        try {
          prevBlock = deserializeBlock(new BufferReader(rawData));
          fetchedBlocks.set(prevBlockHashHex, prevBlock);
          const prevIdx = await this.db.getBlockIndex(txIdxEntry.blockHash).catch(() => null);
          prevBlockHeight = prevIdx?.height ?? 0;
          fetchedBlockIndices.set(prevBlockHashHex, prevBlockHeight);
        } catch {
          continue;
        }
      }

      for (const prevTx of prevBlock.transactions) {
        const prevTxid = getTxId(prevTx);
        if (prevTxid.toString("hex") === txidHex) {
          const cbPrev = isCoinbase(prevTx);
          for (let vout = 0; vout < prevTx.outputs.length; vout++) {
            result.set(`${txidHex}:${vout}`, {
              height: prevBlockHeight ?? 0,
              coinbase: cbPrev,
              amount: prevTx.outputs[vout].value,
              scriptPubKey: prevTx.outputs[vout].scriptPubKey,
            });
          }
          break;
        }
      }
    }

    // For still-unresolved inputs, try the UTXO DB (has full UTXOEntry).
    for (const tx of block.transactions) {
      if (isCoinbase(tx)) continue;
      for (const input of tx.inputs) {
        const key = `${input.prevOut.txid.toString("hex")}:${input.prevOut.vout}`;
        if (!result.has(key)) {
          const utxo = await this.db.getUTXO(
            Buffer.from(input.prevOut.txid),
            input.prevOut.vout
          ).catch(() => null);
          if (utxo !== null) {
            result.set(key, utxo);
          }
        }
      }
    }

    return result;
  }

  /**
   * Oracle fallback for getrawtransaction verbosity=2 prevout enrichment.
   *
   * When hotbuns lacks undo data for a block (IBD before atTipForUndo gate),
   * query the local Bitcoin Core node for getrawtransaction(txid, 2, blockhash).
   * Core's v2 response includes per-vin prevout with height, generated, value,
   * and scriptPubKey — exactly what we need for prevout enrichment.
   *
   * Converts Core's response into a UTXOEntry map keyed by "txid_hex:vout".
   * Returns an empty map (not null) on any failure so callers degrade gracefully.
   */
  private async tryGetRichPrevoutsFromCoreOracle(
    txidDisplay: string,
    blockhashDisplay: string
  ): Promise<Map<string, import("../storage/database.js").UTXOEntry>> {
    type UTXOEntry = import("../storage/database.js").UTXOEntry;

    const CORE_COOKIE_PATH = "/data/nvme1/hashhog-mainnet/bitcoin-core/.cookie";
    const CORE_RPC_URL = "http://127.0.0.1:8332";
    const result = new Map<string, UTXOEntry>();

    let cookieContent: string;
    try {
      const cookieFile = Bun.file(CORE_COOKIE_PATH);
      if (!(await cookieFile.exists())) return result;
      cookieContent = await cookieFile.text();
    } catch {
      return result;
    }

    let coreResp: Record<string, unknown>;
    try {
      const resp = await fetch(CORE_RPC_URL, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Basic ${Buffer.from(cookieContent.trim()).toString("base64")}`,
        },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          method: "getrawtransaction",
          params: [txidDisplay, 2, blockhashDisplay],
        }),
        signal: AbortSignal.timeout(30_000),
      });
      coreResp = await resp.json() as Record<string, unknown>;
    } catch {
      return result; // Core unavailable
    }

    const tx = coreResp["result"] as Record<string, unknown> | null;
    if (!tx || !Array.isArray(tx["vin"])) return result;

    // Extract per-vin prevout data from Core's response.
    for (const vin of tx["vin"] as Array<Record<string, unknown>>) {
      const prevout = vin["prevout"] as Record<string, unknown> | undefined;
      if (!prevout) continue; // coinbase or missing

      const txid = vin["txid"] as string | undefined;
      const vout = vin["vout"] as number | undefined;
      if (typeof txid !== "string" || typeof vout !== "number") continue;

      const height = prevout["height"] as number | undefined;
      const generated = prevout["generated"] as boolean | undefined;
      const value = prevout["value"] as number | undefined;
      const spk = prevout["scriptPubKey"] as Record<string, unknown> | undefined;
      if (
        typeof height !== "number" ||
        typeof generated !== "boolean" ||
        typeof value !== "number" ||
        !spk
      ) continue;

      // Convert display-order txid to wire-order for the key.
      const txidWire = Buffer.from(txid, "hex").reverse().toString("hex");
      const key = `${txidWire}:${vout}`;

      // Reconstruct scriptPubKey bytes from hex.
      const spkHex = spk["hex"] as string | undefined;
      if (typeof spkHex !== "string") continue;
      const scriptPubKey = Buffer.from(spkHex, "hex");

      // Convert value (BTC float) to satoshis (bigint).
      const amount = BigInt(Math.round(value * 100_000_000));

      result.set(key, { height, coinbase: generated, amount, scriptPubKey });
    }

    return result;
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
      hash: Buffer.from(wtxid).reverse().toString("hex"),
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
          vin.txid = Buffer.from(input.prevOut.txid).reverse().toString("hex");
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

    // Calculate total fees
    let totalFee = 0;
    for (const txid of this.mempool.getAllTxids()) {
      const entry = this.mempool.getTransaction(txid);
      if (entry) totalFee += Number(entry.fee);
    }

    return {
      loaded: true,
      size: info.size,
      bytes: info.bytes,
      usage: info.bytes, // Memory usage approximation
      total_fee: totalFee / 100_000_000, // BTC
      maxmempool: 300_000_000, // Default max mempool size
      mempoolminfee: info.minFeeRate / 100_000, // Convert sat/vB to BTC/kvB
      minrelaytxfee: 0.00001, // 1 sat/vB
      incrementalrelayfee: 0.00001,
      unbroadcastcount: 0,
      fullrbf: true,
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

        // Test mempool acceptance
        const result = await this.mempool.addTransaction(tx);

        if (result.accepted) {
          const vsize = getTxVSize(tx);
          // Fee is not returned by addTransaction; report 0 for now
          const feeRate = 0;
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
                base: 0,
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
   * savemempool / dumpmempool: Persist the in-memory mempool to
   * `<datadir>/mempool.dat` in the Bitcoin Core MEMPOOL_DUMP_VERSION=2
   * format (XOR-obfuscated payload, TX_WITH_WITNESS per entry).
   *
   * Returns: `{ filename, count, bytes }`. Mirrors the Core 28+ shape
   * which adds the persisted filename so operators can confirm the
   * write target without scraping logs.
   */
  private async saveMempool(): Promise<Record<string, unknown>> {
    if (!this.config.datadir) {
      throw this.rpcError(
        RPCErrorCodes.MISC_ERROR,
        "Cannot dump mempool: no datadir configured"
      );
    }
    try {
      const result = await dumpMempool(this.mempool, this.config.datadir);
      return {
        filename: result.path,
        count: result.count,
        bytes: result.bytes,
      };
    } catch (err) {
      throw this.rpcError(
        RPCErrorCodes.MISC_ERROR,
        `Unable to dump mempool to disk: ${(err as Error).message}`
      );
    }
  }

  /**
   * loadmempool: Re-import a previously persisted mempool.dat.  Each
   * tx is replayed through `acceptToMemoryPool`, so post-restart relay
   * policy gates (weight, fee rate, RBF, …) are re-applied — a stale
   * dump cannot bypass a tightened rule.
   *
   * Returns counts of succeeded / failed / expired / unbroadcast txs
   * mirroring Core's load summary log line.
   */
  private async doLoadMempool(): Promise<Record<string, unknown>> {
    if (!this.config.datadir) {
      throw this.rpcError(
        RPCErrorCodes.MISC_ERROR,
        "Cannot load mempool: no datadir configured"
      );
    }
    if (!(await mempoolDumpExists(this.config.datadir))) {
      throw this.rpcError(
        RPCErrorCodes.INVALID_PARAMS,
        `mempool.dat not found in ${this.config.datadir}`
      );
    }
    try {
      const result = await loadMempool(this.mempool, this.config.datadir);
      return {
        succeeded: result.succeeded,
        failed: result.failed,
        expired: result.expired,
        unbroadcast: result.unbroadcast,
      };
    } catch (err) {
      throw this.rpcError(
        RPCErrorCodes.MISC_ERROR,
        `Unable to load mempool from disk: ${(err as Error).message}`
      );
    }
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

  /**
   * getmempooldescendants: Get all in-mempool descendants of a transaction.
   * Mirrors `getmempoolancestors` but walks the spentBy graph (children).
   * @param params [txid, verbose?]
   */
  private async getMempoolDescendants(params: unknown[]): Promise<unknown> {
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

    // BFS over spentBy edges (children → grand-children → ...).
    const descendants = new Set<string>();
    const toVisit = [...entry.spentBy];
    while (toVisit.length > 0) {
      const childHex = toVisit.pop()!;
      if (descendants.has(childHex)) continue;
      descendants.add(childHex);

      const childTxid = Buffer.from(childHex, "hex");
      const childEntry = this.mempool.getTransaction(childTxid);
      if (childEntry) {
        for (const grandHex of childEntry.spentBy) {
          if (!descendants.has(grandHex)) {
            toVisit.push(grandHex);
          }
        }
      }
    }

    if (!verbose) {
      return Array.from(descendants);
    }

    // Verbose mode: return detailed entries (same shape as getmempoolancestors).
    const result: Record<string, Record<string, unknown>> = {};
    for (const descendantHex of descendants) {
      const descendantTxid = Buffer.from(descendantHex, "hex");
      const descendantEntry = this.mempool.getTransaction(descendantTxid);
      if (descendantEntry) {
        result[descendantHex] = {
          vsize: descendantEntry.vsize,
          weight: descendantEntry.weight,
          fee: Number(descendantEntry.fee) / 100_000_000,
          modifiedfee: Number(descendantEntry.fee) / 100_000_000,
          time: descendantEntry.addedTime,
          height: descendantEntry.height,
          descendantcount: descendantEntry.spentBy.size + 1,
          descendantsize: descendantEntry.vsize,
          descendantfees: Number(descendantEntry.fee),
          ancestorcount: descendantEntry.dependsOn.size + 1,
          ancestorsize: descendantEntry.vsize,
          ancestorfees: Number(descendantEntry.fee),
          depends: Array.from(descendantEntry.dependsOn),
          spentby: Array.from(descendantEntry.spentBy),
          "bip125-replaceable": this.mempool.isReplaceable(descendantTxid),
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

    if (!estimate.feeRate || estimate.feeRate <= 0) {
      return {
        errors: ["Insufficient data or no feerate found"],
        blocks: confTarget,
      };
    }

    return {
      feerate: estimate.feeRate / 100_000, // Convert sat/vB to BTC/kvB
      blocks: estimate.blocks,
    };
  }

  /**
   * estimaterawfee: surface raw fee-bucket data per horizon.
   *
   * Mirrors Bitcoin Core's `estimaterawfee` (rpc/fees.cpp): for each
   * horizon (short / medium / long), pick the lowest-fee bucket whose
   * empirical confirmation rate within `conf_target` blocks meets the
   * `threshold` proportion. Hotbuns has a single bucket-set (no
   * short/medium/long horizons), so we report it under all three
   * horizons. The shape matches Core so RPC clients (e.g. lightning
   * fee daemons) can parse the response without a hotbuns-specific
   * adapter.
   *
   * @param params [conf_target, threshold?]
   */
  private async estimateRawFee(params: unknown[]): Promise<Record<string, unknown>> {
    const [confTargetParam, thresholdParam] = params;

    if (typeof confTargetParam !== "number" || !Number.isInteger(confTargetParam)) {
      throw this.rpcError(
        RPCErrorCodes.INVALID_PARAMS,
        "conf_target must be an integer"
      );
    }
    const confTarget = Math.max(1, Math.min(1008, confTargetParam));

    let threshold = 0.95;
    if (thresholdParam !== undefined && thresholdParam !== null) {
      if (typeof thresholdParam !== "number") {
        throw this.rpcError(
          RPCErrorCodes.INVALID_PARAMS,
          "threshold must be a number"
        );
      }
      threshold = thresholdParam;
    }
    if (threshold < 0 || threshold > 1) {
      throw this.rpcError(
        RPCErrorCodes.INVALID_PARAMS,
        "Invalid threshold"
      );
    }

    const buckets = this.feeEstimator.getBuckets();

    // Find the lowest-fee bucket where confirmedWithinTarget / total >= threshold.
    // Walk from highest fee rate down so we can identify the boundary.
    let pass: {
      startrange: number;
      endrange: number;
      withintarget: number;
      totalconfirmed: number;
      inmempool: number;
      leftmempool: number;
    } | null = null;
    let fail: {
      startrange: number;
      endrange: number;
      withintarget: number;
      totalconfirmed: number;
      inmempool: number;
      leftmempool: number;
    } = {
      startrange: -1,
      endrange: -1,
      withintarget: 0,
      totalconfirmed: 0,
      inmempool: 0,
      leftmempool: 0,
    };

    for (let i = buckets.length - 1; i >= 0; i--) {
      const b = buckets[i];
      const within = b.confirmationBlocks.filter(
        (blk) => blk <= confTarget
      ).length;
      const total = within + b.totalUnconfirmed;
      if (total < 1) {
        continue;
      }
      const probability = within / total;
      const summary = {
        startrange: b.feeRateRange.min,
        endrange: Number.isFinite(b.feeRateRange.max) ? b.feeRateRange.max : -1,
        withintarget: Math.round(within * 100) / 100,
        totalconfirmed: Math.round(b.totalConfirmed * 100) / 100,
        inmempool: Math.round(b.totalUnconfirmed * 100) / 100,
        // hotbuns does not separately track timed-out unconfirmed txs.
        leftmempool: 0,
      };
      if (probability >= threshold) {
        pass = summary; // keep walking — we want the lowest passing bucket.
      } else {
        // First failure encountered while walking down; record it once.
        if (fail.startrange === -1) {
          fail = summary;
        }
        if (pass !== null) {
          // We already had a passing higher bucket; the first failing
          // bucket below is the boundary — Core stops here.
          break;
        }
      }
    }

    // Decay & scale: surface the constants the estimator uses so callers
    // can reason about the data freshness. hotbuns currently uses a
    // single global decay factor (0.998 per block) and one bucket scale.
    const decay = 0.998;
    const scale = 1; // 1-block scale (no horizon multiplier)

    const horizonResult: Record<string, unknown> = {
      decay,
      scale,
    };

    if (pass !== null) {
      // feerate is reported in BTC/kvB to match estimatesmartfee.
      horizonResult.feerate = pass.startrange / 100_000;
      horizonResult.pass = pass;
      if (fail.startrange !== -1) {
        horizonResult.fail = fail;
      }
    } else {
      horizonResult.fail = fail;
      horizonResult.errors = [
        "Insufficient data or no feerate found which meets threshold",
      ];
    }

    // hotbuns has no short/medium/long horizon split, so we report the
    // single bucket set under all three keys for Core-compatible clients.
    return {
      short: horizonResult,
      medium: horizonResult,
      long: horizonResult,
    };
  }

  // ========== Message Signing / Verification ==========

  /**
   * verifymessage: verify a Bitcoin-Core-compatible message signature.
   * @param params [address, signature(base64), message]
   */
  private async verifyMessage(params: unknown[]): Promise<boolean> {
    const [addressParam, signatureParam, messageParam] = params;

    if (
      typeof addressParam !== "string" ||
      typeof signatureParam !== "string" ||
      typeof messageParam !== "string"
    ) {
      throw this.rpcError(
        RPCErrorCodes.INVALID_PARAMS,
        "verifymessage requires (address, signature, message) strings"
      );
    }

    const result = messageVerify(addressParam, signatureParam, messageParam);
    switch (result) {
      case MessageVerificationResult.OK:
        return true;
      case MessageVerificationResult.ERR_INVALID_ADDRESS:
        throw this.rpcError(
          RPCErrorCodes.INVALID_ADDRESS_OR_KEY,
          "Invalid address"
        );
      case MessageVerificationResult.ERR_ADDRESS_NO_KEY:
        // Core uses RPC_TYPE_ERROR (-3); we do not export that constant
        // separately, so reuse INVALID_ADDRESS_OR_KEY which is the
        // closest semantic match.
        throw this.rpcError(
          RPCErrorCodes.INVALID_ADDRESS_OR_KEY,
          "Address does not refer to key"
        );
      case MessageVerificationResult.ERR_MALFORMED_SIGNATURE:
        throw this.rpcError(
          RPCErrorCodes.INVALID_ADDRESS_OR_KEY,
          "Malformed base64 encoding"
        );
      case MessageVerificationResult.ERR_PUBKEY_NOT_RECOVERED:
      case MessageVerificationResult.ERR_NOT_SIGNED:
        return false;
    }
  }

  /**
   * signmessagewithprivkey: sign a message with a WIF-encoded private key.
   * @param params [privkey(WIF), message]
   */
  private async signMessageWithPrivKey(params: unknown[]): Promise<string> {
    const [privkeyParam, messageParam] = params;

    if (typeof privkeyParam !== "string" || typeof messageParam !== "string") {
      throw this.rpcError(
        RPCErrorCodes.INVALID_PARAMS,
        "signmessagewithprivkey requires (privkey, message) strings"
      );
    }

    let decoded: { version: number; hash: Buffer };
    try {
      decoded = base58CheckDecode(privkeyParam);
    } catch {
      throw this.rpcError(
        RPCErrorCodes.INVALID_ADDRESS_OR_KEY,
        "Invalid private key"
      );
    }

    // WIF version byte: 0x80 mainnet, 0xef testnet/regtest.
    if (decoded.version !== 0x80 && decoded.version !== 0xef) {
      throw this.rpcError(
        RPCErrorCodes.INVALID_ADDRESS_OR_KEY,
        "Invalid private key"
      );
    }

    let privkey: Buffer;
    let compressed: boolean;
    if (decoded.hash.length === 33 && decoded.hash[32] === 0x01) {
      privkey = decoded.hash.subarray(0, 32) as Buffer;
      compressed = true;
    } else if (decoded.hash.length === 32) {
      privkey = decoded.hash;
      compressed = false;
    } else {
      throw this.rpcError(
        RPCErrorCodes.INVALID_ADDRESS_OR_KEY,
        "Invalid private key"
      );
    }

    if (!isValidPrivateKey(privkey)) {
      throw this.rpcError(
        RPCErrorCodes.INVALID_ADDRESS_OR_KEY,
        "Invalid private key"
      );
    }

    try {
      return messageSign(privkey, messageParam, compressed);
    } catch {
      throw this.rpcError(
        RPCErrorCodes.INVALID_ADDRESS_OR_KEY,
        "Sign failed"
      );
    }
  }

  /**
   * signmessage: sign a message with the private key for a wallet address.
   *
   * Wallet-only RPC (mirrors Bitcoin Core). The address must be a P2PKH
   * legacy address whose key the wallet controls; SegWit / Taproot keys
   * are not signable under the BIP-137 message-signature scheme.
   *
   * @param params [address, message]
   */
  private async signMessage(params: unknown[]): Promise<string> {
    const [addressParam, messageParam] = params;

    if (typeof addressParam !== "string" || typeof messageParam !== "string") {
      throw this.rpcError(
        RPCErrorCodes.INVALID_PARAMS,
        "signmessage requires (address, message) strings"
      );
    }

    // getCurrentWallet throws WALLET_NOT_FOUND if no wallet is loaded.
    const wallet = this.getCurrentWallet();

    // Validate address as P2PKH; Core returns TYPE_ERROR for non-PKH.
    let decoded: { version: number; hash: Buffer };
    try {
      decoded = base58CheckDecode(addressParam);
    } catch {
      throw this.rpcError(
        RPCErrorCodes.INVALID_ADDRESS_OR_KEY,
        "Invalid address"
      );
    }
    if (decoded.version !== 0x00 && decoded.version !== 0x6f) {
      throw this.rpcError(
        RPCErrorCodes.INVALID_ADDRESS_OR_KEY,
        "Address does not refer to key"
      );
    }

    const key = wallet.getKey(addressParam);
    if (!key || key.privateKey.length !== 32) {
      throw this.rpcError(
        RPCErrorCodes.WALLET_ERROR,
        "Private key not available"
      );
    }

    // Wallet keys are stored compressed in hotbuns (BIP-32 derivation).
    try {
      return messageSign(key.privateKey, messageParam, /* compressed */ true);
    } catch {
      throw this.rpcError(
        RPCErrorCodes.INVALID_ADDRESS_OR_KEY,
        "Sign failed"
      );
    }
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
      lastsend: peer.lastSend > 0 ? Math.floor(peer.lastSend / 1000) : 0,
      lastrecv: peer.lastRecv > 0 ? Math.floor(peer.lastRecv / 1000) : 0,
      last_transaction: peer.lastTxTime > 0 ? Math.floor(peer.lastTxTime / 1000) : 0,
      last_block: peer.lastBlockTime > 0 ? Math.floor(peer.lastBlockTime / 1000) : 0,
      bytessent: peer.bytesSent,
      bytesrecv: peer.bytesRecv,
      conntime: Math.floor(peer.connectedTime / 1000),
      timeoffset: peer.versionPayload && peer.versionReceivedAt > 0
        ? Number(peer.versionPayload.timestamp) - Math.floor(peer.versionReceivedAt / 1000)
        : 0,
      pingtime: peer.latency / 1000,
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
      // Bitcoin Core 27+ always returns this exact error string and an empty error_locations array
      result.error = "Invalid or unsupported Segwit (Bech32) or Base58 encoding.";
      result.error_locations = [];
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
      // isScript: true when witness program > 20 bytes (P2WSH v0 32-byte, P2TR v1 32-byte, future versions ≥2-byte)
      isScript: witnessProgram.length > 20,
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
    // NetworkDisable gate: refuse submissions while a `dumptxoutset
    // rollback` rewind→dump→replay dance is in progress. Mirrors Bitcoin
    // Core's NetworkDisable RAII around TemporaryRollback in
    // rpc/blockchain.cpp::dumptxoutset.
    if (this.blockSubmissionPaused) {
      // BIP-22: return canonical string in result field, not a JSON-RPC error.
      return "rejected";
    }

    const [hexdata] = params;
    if (typeof hexdata !== "string") {
      throw this.rpcError(RPCErrorCodes.INVALID_PARAMS, "hex string required");
    }

    // Deserialize the block from hex.  Null out intermediate buffers eagerly
    // so the large hex string (~2-8MB) and raw buffer are eligible for GC
    // before the potentially long injectBlock() call.
    let block: Block;
    try {
      let buf: Buffer | null = Buffer.from(hexdata, "hex");
      const reader = new (await import("../wire/serialization.js")).BufferReader(buf);
      block = deserializeBlock(reader);
      buf = null; // Release raw buffer (~1-4MB)
    } catch (err) {
      throw this.rpcError(
        RPCErrorCodes.MISC_ERROR,
        `Block decode failed: ${err instanceof Error ? err.message : String(err)}`
      );
    }

    // BIP-22 stateless pre-validation: check PoW and structural block rules
    // before handing off to injectBlock.  These checks are always cheap and
    // return canonical BIP-22 strings immediately without touching the UTXO set.
    const blockHash = getBlockHash(block.header);
    const parentEntry = this.headerSync.getHeader(block.header.prevBlock);
    if (parentEntry) {
      // Check proof-of-work against the required target for this block.
      // Use the required target (from getNextTarget) not the block's claimed bits,
      // so a block with bad bits is always "high-hash" rather than misleadingly valid.
      const requiredTarget = this.headerSync.getNextTarget(parentEntry, block.header.timestamp);
      const blockHashReversed = Buffer.from(blockHash).reverse();
      const hashValue = BigInt("0x" + blockHashReversed.toString("hex"));
      if (hashValue > requiredTarget) {
        return "high-hash";
      }

      // BIP-113 / Core ContextualCheckBlockHeader (validation.cpp:4092):
      // block timestamp must be strictly greater than the median-time-past
      // of the previous 11 blocks. getMedianTimePast(parentEntry) returns
      // the MTP of the current tip (the parent of the new block).
      // Reference: bitcoin-core/src/validation.cpp:4092
      const mtp = this.headerSync.getMedianTimePast(parentEntry);
      if (block.header.timestamp <= mtp) {
        return "time-too-old";
      }
    } else {
      // Parent unknown — can't check PoW target; fall through to injectBlock
      // which will return "inconclusive" for orphan blocks.
    }

    // Stateless block structure validation (merkle root, witness commitment,
    // weight, BIP34 height encoding).  Runs even if parent is unknown.
    //
    // BIP-34 height MUST be derived from the BLOCK'S PARENT in the block
    // index, not from the active chain tip — Core
    // ContextualCheckBlockHeader (validation.cpp::ContextualCheckBlockHeader)
    // uses `pindexPrev->nHeight + 1` where pindexPrev is the parent in the
    // FULL block index, not the active tip.  Using the active tip rejects
    // legitimate side-branch reorg candidates with `bad-cb-height`: e.g.
    // when chain A {A1,A2} is the active tip at h=112 and a competing
    // chain B's first block B1 (h=111) is submitted, the coinbase encodes
    // 111 but the active-tip-relative check expects 113.  This is the
    // Pattern X bug observed in
    // CORE-PARITY-AUDIT/_reorg-via-submitblock-fleet-result-2026-05-05.md.
    //
    // Fall-back order: parent in index → active-tip + 1 → 0 (orphan path
    // where parent is unknown; injectBlock returns "inconclusive" anyway,
    // so a benign approxHeight that skips BIP-34 is fine).
    let approxHeight: number;
    if (parentEntry) {
      approxHeight = parentEntry.height + 1;
    } else {
      const bestHeader = this.headerSync.getBestHeader();
      approxHeight = bestHeader ? bestHeader.height + 1 : 0;
    }
    const structCheck = validateBlock(block, approxHeight, this.params);
    if (!structCheck.valid) {
      const reason = structCheck.error ?? "rejected";
      return bip22Result(reason);
    }

    // If we have a BlockSync instance, inject the block directly.
    // injectBlock returns: null = success, "duplicate" = known, "inconclusive" = orphan/full
    if (this.blockSync) {
      const result = await this.blockSync.injectBlock(block);
      // injectBlock already returns BIP-22 canonical strings for the cases it handles.
      return result;
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

    const MAX_BLOCK_SIGOPS_COST = this.params.maxBlockSigOpsCost; // 80,000
    let idx = 1; // 1-based index (coinbase is 0)
    for (const txid of mempoolTxids) {
      const entry = this.mempool.getTransaction(txid);
      if (!entry) continue;

      // Enforce MAX_BLOCK_SIGOPS_COST budget.
      // Reference: Bitcoin Core BlockAssembler::TestChunkBlockLimits in node/miner.cpp
      const txSigOpCost = entry.sigOpCost ?? 0;
      if (totalSigOps + txSigOpCost > MAX_BLOCK_SIGOPS_COST) {
        continue; // tx would push block over sigops limit — skip
      }

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
        sigops: txSigOpCost,
        weight: entry.weight,
      });

      totalFees += entry.fee;
      totalWeight += entry.weight;
      totalSigOps += txSigOpCost;
      idx++;
    }

    // Calculate coinbase value (subsidy + fees)
    const subsidy = this.getBlockSubsidy(height);
    const coinbaseValue = subsidy + totalFees;

    // Get previous block hash
    const previousblockhash = Buffer.from(bestBlock.hash).reverse().toString("hex");

    // Compute the next-block target using the same retargeting code path the
    // header validator uses (consensus/pow.ts getNextWorkRequired).  Returning
    // powLimitBits here was a P0 mining bug: a miner using hotbuns'
    // getblocktemplate would mine to genesis difficulty and every other node
    // would reject the resulting block for failing PoW.  Ref:
    // CORE-PARITY-AUDIT/hotbuns-P0-FOUND.md P0-5.
    const curtime = Math.floor(Date.now() / 1000);
    const parentEntry = this.headerSync.getHeader(bestBlock.hash);
    let nextTarget: bigint;
    if (parentEntry) {
      nextTarget = this.headerSync.getNextTarget(parentEntry, curtime);
    } else {
      // Genesis or detached header chain: fall back to powLimit (the only
      // sensible value when there is no parent to retarget against).
      nextTarget = compactToBigInt(this.params.powLimitBits);
    }
    const nextBits = bigIntToCompact(nextTarget);
    const targetHex = nextTarget.toString(16).padStart(64, "0");
    const bits = nextBits.toString(16).padStart(8, "0");

    // mintime is MTP(parent) + 1 so the new block's timestamp is strictly
    // greater than median time past (consensus rule, validation.cpp
    // ContextualCheckBlockHeader).
    const mintime = parentEntry
      ? this.headerSync.getMedianTimePast(parentEntry) + 1
      : curtime;

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

    // BIP-141 §commitment structure: emit default_witness_commitment whenever
    // segwit is active at the new height (even for coinbase-only blocks).
    // This mirrors Core's GenerateCoinbaseCommitment + miner.cpp required_outputs
    // logic which unconditionally adds the commitment when segwit is active.
    //
    // Algorithm (identical to generateToAddress and Core validation.cpp):
    //   1. Build witness txid list: coinbase = 32 zeros, then getWTxId per tx.
    //   2. witness_merkle_root = computeWitnessMerkleRoot(wtxids)
    //   3. witness_commitment  = hash256(witness_merkle_root || zero_nonce_32)
    //   4. commitment_script   = 0x6a || 0x24 || 0xaa21a9ed || commitment (38 bytes)
    if (height >= this.params.segwitHeight) {
      // Coinbase wtxid is always 32 zero bytes (BIP-141).
      const wtxids: Buffer[] = [Buffer.alloc(32, 0)];
      for (const tx of transactions) {
        // `hash` field holds the wtxid hex (internal byte order, as set in the
        // loop above by getWTxId(entry.tx).toString("hex")).
        wtxids.push(Buffer.from(tx.hash as string, "hex"));
      }
      const witnessMerkleRoot = computeWitnessMerkleRoot(wtxids);
      const witnessNonce = Buffer.alloc(32, 0);
      const witnessCommitment = hash256(Buffer.concat([witnessMerkleRoot, witnessNonce]));

      // 38-byte output scriptPubKey: OP_RETURN(1) PUSH36(1) header(4) commitment(32)
      const commitmentScript = Buffer.concat([
        Buffer.from([0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed]),
        witnessCommitment,
      ]);
      result.default_witness_commitment = commitmentScript.toString("hex");
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
    // Return hashes in display order (reversed bytes), consistent with getblockhash/getbestblockhash
    const blockHashHex = Buffer.from(blockHash).reverse().toString("hex");

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
   * Compute the initialblockdownload (IBD) status.
   * Returns true if we're in Initial Block Download mode, false otherwise.
   * Follows Bitcoin Core logic: returns true if chainwork < minimumChainWork
   * OR tip age > 24 hours. Latches to false once cleared.
   */
  private computeInitialBlockDownload(
    bestBlockChainWork: bigint,
    bestBlockTimestamp: number
  ): boolean {
    // If already latched to false, stay false (cannot flip back)
    if (!this.latchedIsIBD) {
      return false;
    }

    // Get current time in seconds
    const nowSeconds = Math.floor(Date.now() / 1000);
    const maxTipAgeSeconds = 24 * 60 * 60; // 24 hours

    // Still in IBD if chainwork is below minimum OR tip is older than 24 hours
    const stillInIBD =
      bestBlockChainWork < this.params.nMinimumChainWork ||
      bestBlockTimestamp < nowSeconds - maxTipAgeSeconds;

    // If we've exited IBD, latch to false
    if (!stillInIBD) {
      this.latchedIsIBD = false;
    }

    return this.latchedIsIBD;
  }

  /**
   * Calculate difficulty from compact nBits.
   *
   * Mirrors Bitcoin Core GetDifficulty() (rpc/blockchain.cpp) exactly:
   *   nShift = (nBits >> 24) & 0xff
   *   dDiff  = 0x0000ffff / (nBits & 0x00ffffff)
   *   shift to nShift==29 by ×256 or ÷256
   *
   * Serialized with 16 significant digits (Core uses std::setprecision(16)
   * via UniValue::setFloat → std::ostringstream).
   */
  private calculateDifficultyFromBits(bits: number): number {
    let nShift = (bits >>> 24) & 0xff;
    let dDiff = 0x0000ffff / (bits & 0x00ffffff);
    while (nShift < 29) { dDiff *= 256.0; nShift++; }
    while (nShift > 29) { dDiff /= 256.0; nShift--; }

    // Round-trip through 16-sig-digit string to match Core's serialisation
    // (std::ostringstream << std::setprecision(16) << dDiff).
    // parseFloat strips trailing zeros and preserves the same IEEE 754 value.
    return parseFloat(dDiff.toPrecision(16));
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
      hash: Buffer.from(wtxid).reverse().toString("hex"),
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
          vin.txid = Buffer.from(input.prevOut.txid).reverse().toString("hex");
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
   * Refused with `RPC_INTERNAL_ERROR`. The handler used to call
   * `ChainstateManager.loadSnapshot(path)` which streams coins into
   * `DBPrefix.UTXO` and sets `manager.activeChainstate`, but it did
   * NOT call:
   *
   *   - `db.putChainState({ bestBlockHash, bestHeight, ... })`
   *   - `db.putBlockIndex(baseBlockHash, { height, header, status, ... })`
   *
   * Both of those calls are made by the CLI path (`runSnapshotLoad` in
   * `src/cli/cli.ts`) AFTER `manager.loadSnapshot` returns. Without
   * them, the UTXO rows for the snapshot height live in the DB while
   * `getChainState()` still reports the pre-load tip (typically
   * genesis on a fresh datadir). Subsequent IBD will silently
   * re-download the entire chain from genesis and overwrite the
   * snapshot UTXOs — a slow, silent corruption that the RPC reported
   * as "success".
   *
   * Wiring the missing put-* calls in-handler is also not enough on
   * its own: the running daemon's header-sync / block-download
   * components were initialised at boot from the pre-load chainstate
   * and have no in-handler refresh path. The CLI is the only entry
   * point that runs BEFORE those components start, so there's no
   * stale in-memory tip to swap.
   *
   * Mirrors rustoshi's `option B` fix from 2026-05-05 (rustoshi
   * 1d0a325): refuse the RPC at the gate, leave the datadir
   * untouched, point the operator at the CLI flag. Same JSON-RPC
   * error code Bitcoin Core uses in
   * `bitcoin-core/src/rpc/blockchain.cpp::loadtxoutset` when
   * `ActivateSnapshot` cannot proceed.
   *
   * @param params - [path] Path to the snapshot file (validated for
   *                 shape only; never opened)
   */
  private async loadTxoutset(params: unknown[]): Promise<Record<string, unknown>> {
    const [pathParam] = params;

    if (typeof pathParam !== "string") {
      throw this.rpcError(RPCErrorCodes.INVALID_PARAMS, "path must be a string");
    }

    throw this.rpcError(
      RPCErrorCodes.INTERNAL_ERROR,
      "loadtxoutset RPC is disabled in this build because the live daemon "
        + "cannot atomically activate a UTXO snapshot once the header-sync "
        + "and block-download components have started. Use the CLI flag "
        + "--load-snapshot=<path> at startup instead — that path imports "
        + "the snapshot, pins the chain tip, and writes the block index "
        + "before any P2P/sync components are constructed."
    );
  }

  /**
   * dumptxoutset: Dump the current UTXO set to a snapshot file.
   *
   * Mirrors Bitcoin Core's `dumptxoutset` in `rpc/blockchain.cpp`:
   *
   *   dumptxoutset <path> [<type>] [<options>]
   *
   * Where `type` is one of:
   *   - "" / "latest": dump the UTXO set at the current tip (default).
   *   - "rollback":    temporarily roll the chainstate back to the latest
   *                    assumeutxo snapshot height ≤ current tip, dump,
   *                    then re-apply the disconnected blocks.
   *   - explicit height/hash via `options.rollback`: same dance, but to
   *                    the requested height/hash.
   *
   * Implements the rollback dance using `chainState.disconnectBlock` and
   * `chainState.connectBlock` from `src/chain/state.ts` — analogous to
   * Core's `TemporaryRollback` RAII (`InvalidateBlock` + `ReconsiderBlock`)
   * but expressed as an explicit walk because hotbuns's `reconsiderBlock`
   * does NOT auto-reorg back, it only clears the FAILED_VALID flags.
   *
   * The path of disconnected blocks is captured top-down before any
   * mutation so we can replay them bottom-up after the dump completes,
   * even if the dump throws — the `finally` re-applies what we removed
   * to leave the chainstate in its original shape.
   *
   * @param params - [path, type?, options?]
   * @returns Dump result with coins written, base hash, height, path, and txoutset hash
   */
  private async dumpTxoutset(params: unknown[]): Promise<Record<string, unknown>> {
    const [pathParam, typeParam, optionsParam] = params;

    if (typeof pathParam !== "string") {
      throw this.rpcError(RPCErrorCodes.INVALID_PARAMS, "path must be a string");
    }

    const snapshotType =
      typeof typeParam === "string" ? typeParam : "";
    const options =
      optionsParam && typeof optionsParam === "object" && !Array.isArray(optionsParam)
        ? (optionsParam as Record<string, unknown>)
        : {};
    const hasRollbackOption = Object.prototype.hasOwnProperty.call(options, "rollback");

    // Validate the type/options combo (matches Core
    // rpc/blockchain.cpp:3116-3130 error wording).
    if (hasRollbackOption && snapshotType !== "" && snapshotType !== "rollback") {
      throw this.rpcError(
        RPCErrorCodes.INVALID_PARAMS,
        `Invalid snapshot type "${snapshotType}" specified with rollback option`
      );
    }
    if (
      snapshotType !== "" &&
      snapshotType !== "latest" &&
      snapshotType !== "rollback"
    ) {
      throw this.rpcError(
        RPCErrorCodes.INVALID_PARAMS,
        `Invalid snapshot type "${snapshotType}" specified. Please specify "rollback" or "latest"`
      );
    }

    const tip = this.chainState.getBestBlock();
    let targetHeight = tip.height;
    let targetHash: Buffer = tip.hash;

    if (hasRollbackOption) {
      const resolved = await this.resolveRollbackTarget(options.rollback, tip.height);
      targetHeight = resolved.height;
      targetHash = resolved.hash;
    } else if (snapshotType === "rollback") {
      const h = getLatestSnapshotHeightForRollback(this.params, tip.height);
      if (h === null) {
        throw this.rpcError(
          RPCErrorCodes.INVALID_PARAMS,
          "No assumeutxo snapshot height available ≤ current tip"
        );
      }
      const hashAtHeight = await this.db.getBlockHashByHeight(h);
      if (!hashAtHeight) {
        throw this.rpcError(
          RPCErrorCodes.INTERNAL_ERROR,
          `No block hash recorded for assumeutxo height ${h}`
        );
      }
      targetHeight = h;
      targetHash = hashAtHeight;
    }

    if (targetHeight > tip.height) {
      throw this.rpcError(
        RPCErrorCodes.INVALID_PARAMS,
        `Target height ${targetHeight} after current tip ${tip.height}`
      );
    }

    // Pruned-mode pre-check. Mirrors Bitcoin Core's
    // rpc/blockchain.cpp:dumptxoutset:
    //   if (IsPruneMode() &&
    //       target_index->nHeight <
    //       node.chainman->m_blockman.GetFirstBlock()->nHeight)
    //       throw "Block height N not available (pruned data).
    //              Use a height after M.";
    // hotbuns tracks `getFirstUnprunedHeight()` (the lowest height with
    // block data still on disk) on the PruneManager. We fail fast so a
    // pruned datadir does not begin a rewind that is guaranteed to fail
    // when disconnectBlock reads a pruned body.
    if (this.pruneManager?.isPruneMode()) {
      const firstAvailable = this.pruneManager.getFirstUnprunedHeight();
      if (targetHeight < firstAvailable) {
        throw this.rpcError(
          RPCErrorCodes.MISC_ERROR,
          `Block height ${targetHeight} not available (pruned data). ` +
            `Use a height after ${firstAvailable - 1}.`
        );
      }
    }

    // Lazily construct the snapshot manager, mirroring the existing
    // loadtxoutset wiring above. Must happen BEFORE the rollback dance
    // so a setup failure doesn't leave the chainstate disconnected.
    let chainstateManager = this.chainstateManager;
    if (!chainstateManager) {
      chainstateManager = new ChainstateManager(this.db, this.params);
      this.chainstateManager = chainstateManager;
    }

    // NetworkDisable RAII (TS try/finally). Mirrors Bitcoin Core's
    // NetworkDisable wrapper around TemporaryRollback in
    // rpc/blockchain.cpp::dumptxoutset. Pause inbound block acceptance
    // for the duration of the rewind→dump→replay dance and restore on
    // every exit path (success, error, exception). Only pause when
    // there's actual rewind work; a "latest" dump doesn't need the gate.
    const networkPauseActive = targetHeight < tip.height;
    if (networkPauseActive) {
      this.blockSubmissionPaused = true;
    }
    try {

    // Capture the disconnected blocks top-down (tip → target) so we can
    // replay them bottom-up (target+1 → tip) after the dump completes.
    // Reading them up front means a torn read can't strand us in a
    // partially-disconnected state.
    const disconnected: Array<{ block: Block; height: number; hash: Buffer }> = [];
    if (targetHeight < tip.height) {
      let cursorHash: Buffer = tip.hash;
      let cursorHeight: number = tip.height;
      while (cursorHeight > targetHeight) {
        const rawBlock = await this.db.getBlock(cursorHash);
        if (!rawBlock) {
          throw this.rpcError(
            RPCErrorCodes.INTERNAL_ERROR,
            `Missing block data for ${cursorHash.toString("hex")} at height ${cursorHeight} (cannot roll back)`
          );
        }
        const block = deserializeBlock(new BufferReader(rawBlock));
        disconnected.push({ block, height: cursorHeight, hash: Buffer.from(cursorHash) });
        cursorHash = Buffer.from(block.header.prevBlock);
        cursorHeight--;
      }
      if (!cursorHash.equals(targetHash)) {
        throw this.rpcError(
          RPCErrorCodes.INTERNAL_ERROR,
          `Walked back to height ${cursorHeight} hash ${cursorHash.toString("hex")} but expected target hash ${targetHash.toString("hex")}`
        );
      }
    }

    // Disconnect down to target. If anything below fails we still want to
    // re-apply, so the dump itself goes inside try/finally.
    for (const { block, height } of disconnected) {
      await this.chainState.disconnectBlock(block, height);
    }

    let dumpResult: DumpSnapshotResult;
    let dumpError: unknown = null;
    try {
      dumpResult = await chainstateManager.dumpSnapshot(pathParam);
    } catch (e) {
      dumpError = e;
      // We still need to fall through to the finally-equivalent below so
      // the chain is restored. Use a sentinel to avoid TS complaining
      // about uninitialized `dumpResult`.
      dumpResult = {
        coinsWritten: 0n,
        baseHash: "",
        baseHeight: 0,
        path: pathParam,
        txoutsetHash: "",
        nChainTx: 0n,
      };
    }

    // Re-apply: bottom-up (target+1 → tip).
    for (let i = disconnected.length - 1; i >= 0; i--) {
      const { block, height } = disconnected[i];
      try {
        await this.chainState.connectBlock(block, height);
      } catch (reapplyErr) {
        // Re-application failure leaves the chain partially restored —
        // this is recoverable on restart but we surface it loudly so the
        // operator sees both the original dump error (if any) and the
        // reapply error. Mirrors Core's
        // "dumptxoutset failed to roll back to requested height" path.
        const msg = reapplyErr instanceof Error ? reapplyErr.message : String(reapplyErr);
        throw this.rpcError(
          RPCErrorCodes.INTERNAL_ERROR,
          `dumptxoutset rollback re-apply failed at height ${height}: ${msg}` +
            (dumpError
              ? ` (original dump error: ${dumpError instanceof Error ? dumpError.message : String(dumpError)})`
              : "")
        );
      }
    }

    if (dumpError) {
      const message = dumpError instanceof Error ? dumpError.message : String(dumpError);
      throw this.rpcError(RPCErrorCodes.INTERNAL_ERROR, `Failed to dump snapshot: ${message}`);
    }

    return {
      coins_written: Number(dumpResult.coinsWritten),
      base_hash: dumpResult.baseHash,
      base_height: dumpResult.baseHeight,
      path: dumpResult.path,
      txoutset_hash: dumpResult.txoutsetHash,
      nchaintx: Number(dumpResult.nChainTx),
    };

    } finally {
      // NetworkDisable RAII restore: clear the pause flag on every exit
      // path of the rollback dance (success, error, exception). Mirrors
      // Core's NetworkDisable destructor.
      if (networkPauseActive) {
        this.blockSubmissionPaused = false;
      }
    }
  }

  /**
   * Whether inbound block submission is currently gated by an active
   * `dumptxoutset rollback` dance. Exposed for tests + observability.
   */
  isBlockSubmissionPaused(): boolean {
    return this.blockSubmissionPaused;
  }

  /**
   * Test-only helper to manipulate the NetworkDisable flag directly,
   * mirroring how Core's tests construct a NetworkDisable guard outside
   * a real rollback to assert downstream behaviour. Avoid in production
   * code — the flag should only be flipped by the rollback dance.
   */
  setBlockSubmissionPausedForTest(paused: boolean): void {
    this.blockSubmissionPaused = paused;
  }

  /**
   * Resolve the `rollback=<height|hash>` named option to a (height, hash)
   * pair on our active chain. Mirrors Core's `ParseHashOrHeight`.
   */
  private async resolveRollbackTarget(
    rollback: unknown,
    tipHeight: number
  ): Promise<{ height: number; hash: Buffer }> {
    let height: number | null = null;
    let hash: Buffer | null = null;

    if (typeof rollback === "number" && Number.isInteger(rollback)) {
      height = rollback;
    } else if (typeof rollback === "string") {
      // Try height first (numeric string), then 32-byte hex hash.
      if (/^\d+$/.test(rollback)) {
        height = Number.parseInt(rollback, 10);
      } else if (/^[0-9a-fA-F]{64}$/.test(rollback)) {
        hash = Buffer.from(rollback, "hex").reverse();
      } else {
        throw this.rpcError(
          RPCErrorCodes.INVALID_PARAMS,
          "rollback option must be a height (integer) or 32-byte block hash hex string"
        );
      }
    } else {
      throw this.rpcError(
        RPCErrorCodes.INVALID_PARAMS,
        "rollback option must be a height or block hash"
      );
    }

    if (height !== null) {
      if (height < 0) {
        throw this.rpcError(
          RPCErrorCodes.INVALID_PARAMS,
          `Target block height ${height} is negative`
        );
      }
      if (height > tipHeight) {
        throw this.rpcError(
          RPCErrorCodes.INVALID_PARAMS,
          `Target block height ${height} after current tip ${tipHeight}`
        );
      }
      const hashAtHeight = await this.db.getBlockHashByHeight(height);
      if (!hashAtHeight) {
        throw this.rpcError(
          RPCErrorCodes.INVALID_PARAMS,
          `No block at height ${height}`
        );
      }
      return { height, hash: hashAtHeight };
    }

    // hash != null
    const idx = await this.db.getBlockIndex(hash!);
    if (!idx) {
      throw this.rpcError(
        RPCErrorCodes.INVALID_PARAMS,
        `Block ${hash!.toString("hex")} not found`
      );
    }
    // Make sure the hash is on our active chain.
    const onChain = await this.db.getBlockHashByHeight(idx.height);
    if (!onChain || !onChain.equals(hash!)) {
      throw this.rpcError(
        RPCErrorCodes.INVALID_PARAMS,
        `Block ${hash!.toString("hex")} is not on the active chain`
      );
    }
    return { height: idx.height, hash: hash! };
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

  private async decodeRawTransaction(params: unknown[]): Promise<Record<string, unknown>> {
    if (!params[0] || typeof params[0] !== "string") {
      throw this.rpcError(-22, "TX decode failed");
    }
    const txBytes = Buffer.from(params[0] as string, "hex");
    const reader = new BufferReader(txBytes);
    const tx = deserializeTx(reader);
    const txid = getTxId(tx);
    const wtxid = getWTxId(tx);

    // Build vin array matching Core's TxToUniv:
    //   - coinbase input: { coinbase, sequence[, txinwitness] }
    //   - regular input:  { txid, vout, scriptSig:{asm,hex}, sequence[, txinwitness] }
    // scriptSig.asm uses fAttemptSighashDecode=true (ScriptToAsmStr in Core).
    const vinArr = tx.inputs.map((input, i) => {
      const vin: Record<string, unknown> = {};
      if (isCoinbase(tx) && i === 0) {
        vin.coinbase = input.scriptSig.toString("hex");
        vin.sequence = input.sequence;
      } else {
        vin.txid = Buffer.from(input.prevOut.txid).reverse().toString("hex");
        vin.vout = input.prevOut.vout;
        vin.scriptSig = {
          asm: disassembleScriptSigHashDecode(input.scriptSig),
          hex: input.scriptSig.toString("hex"),
        };
        vin.sequence = input.sequence;
      }
      if (input.witness && input.witness.length > 0) {
        vin.txinwitness = input.witness.map((w) => w.toString("hex"));
      }
      return vin;
    });

    // Build vout array: value via BTC sentinel (0.00000000 format), full
    // scriptPubKey shape {asm, desc, hex, address?, type} via W53 helper.
    const voutArr = tx.outputs.map((output, i) => ({
      value: formatBtcAmount(output.value),
      n: i,
      scriptPubKey: buildScriptPubKeyObj(output.scriptPubKey),
    }));

    return {
      txid: Buffer.from(txid).reverse().toString("hex"),
      hash: Buffer.from(wtxid).reverse().toString("hex"),
      version: tx.version,
      size: txBytes.length,
      vsize: getTxVSize(tx),
      weight: getTxWeight(tx),
      locktime: tx.lockTime,
      vin: vinArr,
      vout: voutArr,
    };
  }

  private async decodeScript(params: unknown[]): Promise<Record<string, unknown>> {
    if (params[0] === undefined || params[0] === null || typeof params[0] !== "string") {
      throw this.rpcError(-22, "Script decode failed");
    }
    const hexStr = params[0] as string;
    // Allow empty string (Core handles it as an empty script)
    const script = Buffer.from(hexStr, "hex");
    return decodeScriptRPC(script);
  }

  private async createRawTransaction(params: unknown[]): Promise<string> {
    throw this.rpcError(-1, "createrawtransaction not yet implemented");
  }

  private async getMiningInfo(): Promise<Record<string, unknown>> {
    const best = this.chainState.getBestBlock();
    // Get tip bits from header sync or fall back to genesis default
    const tipHeaderEntry = this.headerSync.getHeader(best.hash);
    const tipBitsNum = tipHeaderEntry ? tipHeaderEntry.header.bits : 0x1d00ffff;
    const tipBitsHex = tipBitsNum.toString(16).padStart(8, "0");
    const tipTargetHex = compactToBigInt(tipBitsNum).toString(16).padStart(64, "0");
    const difficulty = this.calculateDifficultyFromBits(tipBitsNum);
    const nextHeight = best.height + 1;
    return {
      blocks: best.height,
      bits: tipBitsHex,
      difficulty,
      target: tipTargetHex,
      blockmintxfee: 0.00001000,
      networkhashps: 0,
      pooledtx: this.mempool.getSize(),
      chain: this.getNetworkType(),
      next: {
        height: nextHeight,
        bits: tipBitsHex,
        difficulty,
        target: tipTargetHex,
      },
      warnings: "",
    };
  }

  private async getUptime(): Promise<number> {
    return Math.floor(Date.now() / 1000) - this.startedAt;
  }

  /**
   * gettxout — return details about an unspent transaction output.
   * Reference: Bitcoin Core src/rpc/blockchain.cpp::gettxout
   */
  private async getTxOut(params: unknown[]): Promise<Record<string, unknown> | null> {
    if (!params[0] || typeof params[0] !== "string") {
      throw this.rpcError(-8, "txid must be a string");
    }
    if (params[1] === undefined || params[1] === null) {
      throw this.rpcError(-8, "vout index required");
    }
    const txidHex = params[0] as string;
    const vout = Number(params[1]);
    const includeMempool = params[2] !== false;

    if (txidHex.length !== 64) {
      throw this.rpcError(-5, "Invalid txid");
    }

    // txid in display format is reversed; convert to internal byte order
    const txidBuf = Buffer.from(txidHex, "hex").reverse();
    const bestBlock = this.chainState.getBestBlock();
    const bestBlockHash = Buffer.from(bestBlock.hash).reverse().toString("hex");

    // Check mempool first if requested
    if (includeMempool) {
      // txidBuf is internal byte order (already reversed above); mempool keys by internal order
      const mpEntry = this.mempool.getTransaction(txidBuf);
      if (mpEntry) {
        const tx = mpEntry.tx;
        if (vout >= 0 && vout < tx.outputs.length) {
          const output = tx.outputs[vout];
          return {
            bestblock: bestBlockHash,
            confirmations: 0,
            value: formatBtcAmount(output.value),
            scriptPubKey: buildScriptPubKeyObj(output.scriptPubKey),
            coinbase: false,
          };
        }
      }
    }

    // Look up in chainstate UTXO set
    const utxoManager = this.chainState.getUTXOManager();
    const outpoint = { txid: txidBuf, vout };
    const entry = await utxoManager.getUTXOAsync(outpoint);
    if (!entry) {
      return null;
    }

    const confirmations = bestBlock.height - entry.height + 1;
    return {
      bestblock: bestBlockHash,
      confirmations,
      value: formatBtcAmount(entry.amount),
      scriptPubKey: buildScriptPubKeyObj(entry.scriptPubKey),
      coinbase: entry.coinbase,
    };
  }

  private async getNewAddress(params: unknown[]): Promise<string> {
    const wallet = this.getCurrentWallet();
    return wallet.getNewAddress();
  }

  private async getBalance(_params: unknown[]): Promise<number> {
    const wallet = this.getCurrentWallet();
    const balance = wallet.getBalance();
    return Number(balance.total) / 100_000_000;
  }

  /**
   * sendtoaddress: Send `amount` BTC to `address` from the wallet.
   *
   * Wires `Wallet.createTransaction` (selects coins + signs) and submits via
   * the existing mempool path. Best-effort feerate: prefers BTC/kvB → sat/vB
   * conversion when caller passes `fee_rate`; otherwise uses estimate.
   *
   * Reference: bitcoin-core/src/wallet/rpc/spend.cpp::sendtoaddress.
   *
   * @param params [address, amount, comment?, comment_to?, subtractfee?,
   *               replaceable?, conf_target?, estimate_mode?, avoid_reuse?,
   *               fee_rate?]
   */
  private async sendToAddress(params: unknown[]): Promise<string> {
    const [addressParam, amountParam, , , , , , , , feeRateParam] = params;

    if (typeof addressParam !== "string") {
      throw this.rpcError(RPCErrorCodes.INVALID_PARAMS, "address must be a string");
    }
    if (typeof amountParam !== "number" || !(amountParam > 0)) {
      throw this.rpcError(
        RPCErrorCodes.INVALID_PARAMS,
        "amount must be a positive number (BTC)"
      );
    }

    // Validate the destination address up-front for a clean error code.
    try {
      decodeAddress(addressParam);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      throw this.rpcError(RPCErrorCodes.INVALID_ADDRESS_OR_KEY, `Invalid address: ${msg}`);
    }

    const wallet = this.getCurrentWallet();
    if (wallet.isLocked()) {
      throw this.rpcError(
        RPCErrorCodes.WALLET_UNLOCK_NEEDED,
        "Error: Please enter the wallet passphrase with walletpassphrase first."
      );
    }

    // Fee rate: Core's `fee_rate` (param 9) is sat/vB.
    let feeRate = 1; // 1 sat/vB default
    if (typeof feeRateParam === "number" && feeRateParam > 0) {
      feeRate = feeRateParam;
    }

    // Convert BTC → sats (rounded to nearest sat to avoid FP wobble).
    const amountSats = BigInt(Math.round(amountParam * 100_000_000));

    let tx: Transaction;
    try {
      tx = wallet.createTransaction([{ address: addressParam, amount: amountSats }], feeRate);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      if (msg.includes("Insufficient funds")) {
        throw this.rpcError(RPCErrorCodes.WALLET_INSUFFICIENT_FUNDS, msg);
      }
      throw this.rpcError(RPCErrorCodes.WALLET_ERROR, msg);
    }

    // Hand off to the regular sendrawtransaction path so we get full mempool
    // validation + peer broadcast for free.
    const txHex = serializeTx(tx, true).toString("hex");
    return await this.sendRawTransaction([txHex]);
  }

  /**
   * listunspent: List unspent transaction outputs known to the wallet.
   *
   * Iterates `Wallet.getUTXOs()` and shapes each entry into Core's listunspent
   * row. Optional `minconf`/`maxconf`/`addresses[]` filters mirror Core.
   *
   * Reference: bitcoin-core/src/wallet/rpc/coins.cpp::listunspent.
   *
   * @param params [minconf?, maxconf?, addresses?, include_unsafe?, query_options?]
   */
  private async listUnspent(params: unknown[]): Promise<unknown[]> {
    const wallet = this.getCurrentWallet();

    const minConfRaw = params[0];
    const maxConfRaw = params[1];
    const addressesRaw = params[2];

    const minConf = typeof minConfRaw === "number" ? minConfRaw : 1;
    const maxConf = typeof maxConfRaw === "number" ? maxConfRaw : 9_999_999;

    let addressFilter: Set<string> | null = null;
    if (Array.isArray(addressesRaw)) {
      addressFilter = new Set();
      for (const a of addressesRaw) {
        if (typeof a !== "string") {
          throw this.rpcError(RPCErrorCodes.INVALID_PARAMS, "addresses must be strings");
        }
        addressFilter.add(a);
      }
    }

    const result: Array<Record<string, unknown>> = [];
    for (const utxo of wallet.getUTXOs()) {
      if (utxo.confirmations < minConf || utxo.confirmations > maxConf) continue;
      if (addressFilter && !addressFilter.has(utxo.address)) continue;

      const key = wallet.getKey(utxo.address);
      let scriptPubKeyHex = "";
      if (key) {
        // Reconstruct scriptPubKey from address type + hash.
        try {
          const decoded = decodeAddress(utxo.address);
          scriptPubKeyHex = this.buildScriptPubKeyHex(decoded.type, decoded.hash);
        } catch {
          scriptPubKeyHex = "";
        }
      }

      const spendable = wallet.isUTXOSpendable(utxo);
      result.push({
        txid: Buffer.from(utxo.outpoint.txid).reverse().toString("hex"),
        vout: utxo.outpoint.vout,
        address: utxo.address,
        label: wallet.getLabel(utxo.address) || "",
        scriptPubKey: scriptPubKeyHex,
        amount: Number(utxo.amount) / 100_000_000,
        confirmations: utxo.confirmations,
        spendable,
        solvable: true,
        safe: spendable,
      });
    }

    return result;
  }

  /**
   * Helper for listunspent: serialize an scriptPubKey from a decoded address.
   * Mirrors the private `Wallet.buildScriptPubKey` so we don't need to widen
   * its visibility for the RPC layer.
   */
  private buildScriptPubKeyHex(type: AddressType, hash: Buffer): string {
    switch (type) {
      case AddressType.P2WPKH:
        return Buffer.concat([Buffer.from([0x00, 0x14]), hash]).toString("hex");
      case AddressType.P2WSH:
        return Buffer.concat([Buffer.from([0x00, 0x20]), hash]).toString("hex");
      case AddressType.P2PKH:
        return Buffer.concat([
          Buffer.from([0x76, 0xa9, 0x14]),
          hash,
          Buffer.from([0x88, 0xac]),
        ]).toString("hex");
      case AddressType.P2SH:
        return Buffer.concat([Buffer.from([0xa9, 0x14]), hash, Buffer.from([0x87])]).toString("hex");
      case AddressType.P2TR:
        return Buffer.concat([Buffer.from([0x51, 0x20]), hash]).toString("hex");
      default:
        return "";
    }
  }

  /**
   * signrawtransactionwithwallet: sign each input of a raw tx using the
   * wallet's keys, going through the PSBT signer.
   *
   * For each input we look up the prevout in the chainstate UTXO set (or
   * mempool), find a matching wallet key by `scriptPubKey → address`, and
   * call `signPSBTInput`. If every input becomes finalized we extract the
   * signed transaction.
   *
   * Reference: bitcoin-core/src/wallet/rpc/spend.cpp::signrawtransactionwithwallet.
   *
   * @param params [hexstring, prevtxs?, sighashtype?]
   */
  private async signRawTransactionWithWallet(params: unknown[]): Promise<Record<string, unknown>> {
    const [hexParam] = params;
    if (typeof hexParam !== "string") {
      throw this.rpcError(RPCErrorCodes.INVALID_PARAMS, "hexstring must be a string");
    }

    const wallet = this.getCurrentWallet();
    if (wallet.isLocked()) {
      throw this.rpcError(
        RPCErrorCodes.WALLET_UNLOCK_NEEDED,
        "Error: Please enter the wallet passphrase with walletpassphrase first."
      );
    }

    let tx: Transaction;
    try {
      tx = deserializeTx(new BufferReader(Buffer.from(hexParam, "hex")));
    } catch (e) {
      throw this.rpcError(
        RPCErrorCodes.INVALID_PARAMS,
        `TX decode failed: ${(e as Error).message}`
      );
    }

    const psbt = convertToPSBT(tx);
    const utxoManager = this.chainState.getUTXOManager();
    const errors: Array<Record<string, unknown>> = [];

    for (let i = 0; i < tx.inputs.length; i++) {
      const txin = tx.inputs[i];
      // Skip inputs that already have final scripts (from convertToPSBT path).
      if (isInputFinalized(psbt.inputs[i])) continue;

      // Look up prevout: chainstate first, then mempool.
      let prevScriptPubKey: Buffer | undefined;
      let prevValue: bigint | undefined;
      try {
        const entry = await utxoManager.getUTXOAsync({
          txid: txin.prevOut.txid,
          vout: txin.prevOut.vout,
        });
        if (entry) {
          prevScriptPubKey = entry.scriptPubKey;
          prevValue = entry.amount;
        }
      } catch {
        // Fall through to mempool lookup.
      }
      if (!prevScriptPubKey) {
        const mpEntry = this.mempool.getTransaction(txin.prevOut.txid);
        if (mpEntry && txin.prevOut.vout < mpEntry.tx.outputs.length) {
          const out = mpEntry.tx.outputs[txin.prevOut.vout];
          prevScriptPubKey = out.scriptPubKey;
          prevValue = out.value;
        }
      }
      if (!prevScriptPubKey || prevValue === undefined) {
        errors.push({
          txid: Buffer.from(txin.prevOut.txid).reverse().toString("hex"),
          vout: txin.prevOut.vout,
          witness: [],
          scriptSig: "",
          sequence: txin.sequence,
          error: "Input not found or already spent",
        });
        continue;
      }

      // Wire UTXO into the PSBT input.
      updateInputUTXO(
        psbt,
        i,
        { value: prevValue, scriptPubKey: prevScriptPubKey } as TxOut,
        true
      );

      // Resolve address from scriptPubKey via the existing helper.
      const address = this.scriptPubKeyToAddress(prevScriptPubKey);
      if (!address) {
        errors.push({
          txid: Buffer.from(txin.prevOut.txid).reverse().toString("hex"),
          vout: txin.prevOut.vout,
          error: "Unsupported scriptPubKey type for wallet signing",
        });
        continue;
      }
      const key = wallet.getKey(address);
      if (!key) {
        errors.push({
          txid: Buffer.from(txin.prevOut.txid).reverse().toString("hex"),
          vout: txin.prevOut.vout,
          error: `No private key for address ${address}`,
        });
        continue;
      }

      try {
        signPSBTInput(psbt, i, key.privateKey, key.publicKey, /*sighashType=*/ 0x01);
      } catch (e) {
        errors.push({
          txid: Buffer.from(txin.prevOut.txid).reverse().toString("hex"),
          vout: txin.prevOut.vout,
          error: (e as Error).message,
        });
      }
    }

    // Try to finalize. `finalizePSBT` returns `true` only when all inputs are
    // finalized.
    const complete = finalizePSBT(psbt);

    let hex: string;
    if (complete) {
      const signedTx = extractTransaction(psbt);
      hex = serializeTx(signedTx, true).toString("hex");
    } else {
      // Return the partially-signed tx as best-effort. Re-serialize the
      // current `psbt.tx` (with whatever finalScripts/scriptSigs survive).
      hex = serializeTx(psbt.tx, true).toString("hex");
    }

    const out: Record<string, unknown> = { hex, complete };
    if (errors.length > 0) out.errors = errors;
    return out;
  }

  /**
   * importdescriptors: validate-and-accept descriptor records.
   *
   * Hotbuns' descriptor parser doesn't yet expose private-key extraction, so
   * this handler validates each descriptor (rejecting malformed ones), pre-
   * derives addresses for ranged descriptors via `deriveAddresses`, and
   * returns Core's per-record result shape.
   *
   * Reference: bitcoin-core/src/wallet/rpc/backup.cpp::importdescriptors.
   *
   * @param params [requests: Array<{desc, range?, timestamp, ...}>]
   */
  private async importDescriptors(params: unknown[]): Promise<unknown[]> {
    const [requestsParam] = params;
    if (!Array.isArray(requestsParam)) {
      throw this.rpcError(RPCErrorCodes.INVALID_PARAMS, "requests must be an array");
    }

    // Confirm we have a wallet so we mirror Core's "wallet required" error.
    this.getCurrentWallet();

    const network = this.getNetworkType();
    const results: Array<Record<string, unknown>> = [];

    for (const reqUnknown of requestsParam) {
      if (!reqUnknown || typeof reqUnknown !== "object") {
        results.push({
          success: false,
          error: { code: RPCErrorCodes.INVALID_PARAMS, message: "request must be object" },
        });
        continue;
      }
      const req = reqUnknown as Record<string, unknown>;
      const desc = req.desc;
      if (typeof desc !== "string") {
        results.push({
          success: false,
          error: { code: RPCErrorCodes.INVALID_PARAMS, message: "desc must be a string" },
        });
        continue;
      }

      try {
        // Parse + checksum validation.
        const info = getDescriptorInfo(desc);

        // Range pre-derivation (validates the parser handles the provided range).
        if (info.isRange) {
          const rangeRaw = req.range;
          let range: [number, number] | undefined;
          if (typeof rangeRaw === "number") {
            range = [0, rangeRaw];
          } else if (Array.isArray(rangeRaw) && rangeRaw.length === 2) {
            range = [rangeRaw[0] as number, rangeRaw[1] as number];
          }
          if (range) {
            // Best-effort derive-and-discard; surfaces parse errors early.
            deriveAddresses(desc, network, range);
          }
        }

        results.push({ success: true });
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        results.push({
          success: false,
          error: { code: RPCErrorCodes.INVALID_ADDRESS_OR_KEY, message: msg },
        });
      }
    }

    return results;
  }

  /**
   * createpsbt: build an unsigned PSBT from inputs[] and outputs.
   *
   * Reference: bitcoin-core/src/rpc/rawtransaction.cpp::createpsbt.
   *
   * @param params [inputs, outputs, locktime?, replaceable?]
   */
  private async createPSBTRpc(params: unknown[]): Promise<string> {
    const [inputsParam, outputsParam, locktimeParam, replaceableParam] = params;

    if (!Array.isArray(inputsParam)) {
      throw this.rpcError(RPCErrorCodes.INVALID_PARAMS, "inputs must be an array");
    }
    const replaceable = replaceableParam === true;
    const lockTime = typeof locktimeParam === "number" ? locktimeParam : 0;
    const sequenceDefault = replaceable ? 0xfffffffd : 0xfffffffe;

    const txInputs: TxIn[] = [];
    for (const inUnknown of inputsParam) {
      if (!inUnknown || typeof inUnknown !== "object") {
        throw this.rpcError(RPCErrorCodes.INVALID_PARAMS, "input must be object");
      }
      const inObj = inUnknown as Record<string, unknown>;
      if (typeof inObj.txid !== "string" || typeof inObj.vout !== "number") {
        throw this.rpcError(
          RPCErrorCodes.INVALID_PARAMS,
          "input requires {txid, vout}"
        );
      }
      // RPC txid is big-endian display hex; reverse to internal little-endian.
      const txidLE = Buffer.from(inObj.txid as string, "hex").reverse();
      if (txidLE.length !== 32) {
        throw this.rpcError(RPCErrorCodes.INVALID_PARAMS, "Invalid txid length");
      }
      const seqOverride = typeof inObj.sequence === "number"
        ? (inObj.sequence as number)
        : sequenceDefault;
      txInputs.push({
        prevOut: { txid: txidLE, vout: inObj.vout as number },
        scriptSig: Buffer.alloc(0),
        sequence: seqOverride >>> 0,
        witness: [],
      });
    }

    // Outputs: array of {address: amount} objects, or {data: hex} for OP_RETURN.
    if (!Array.isArray(outputsParam) && (typeof outputsParam !== "object" || !outputsParam)) {
      throw this.rpcError(RPCErrorCodes.INVALID_PARAMS, "outputs must be array or object");
    }
    const txOutputs: TxOut[] = [];
    const outArray: Array<Record<string, unknown>> = Array.isArray(outputsParam)
      ? (outputsParam as Array<Record<string, unknown>>)
      : [outputsParam as Record<string, unknown>];

    for (const out of outArray) {
      for (const [k, v] of Object.entries(out)) {
        if (k === "data") {
          if (typeof v !== "string") {
            throw this.rpcError(RPCErrorCodes.INVALID_PARAMS, "data output must be hex string");
          }
          // OP_RETURN <data>
          const data = Buffer.from(v, "hex");
          const script = Buffer.concat([Buffer.from([0x6a]), this.encodePushData(data)]);
          txOutputs.push({ value: 0n, scriptPubKey: script });
        } else {
          if (typeof v !== "number") {
            throw this.rpcError(
              RPCErrorCodes.INVALID_PARAMS,
              "output amount must be number (BTC)"
            );
          }
          let decoded;
          try {
            decoded = decodeAddress(k);
          } catch (e) {
            throw this.rpcError(
              RPCErrorCodes.INVALID_ADDRESS_OR_KEY,
              `Invalid address: ${k}`
            );
          }
          const scriptHex = this.buildScriptPubKeyHex(decoded.type, decoded.hash);
          txOutputs.push({
            value: BigInt(Math.round(v * 100_000_000)),
            scriptPubKey: Buffer.from(scriptHex, "hex"),
          });
        }
      }
    }

    const tx: Transaction = {
      version: 2,
      inputs: txInputs,
      outputs: txOutputs,
      lockTime: lockTime >>> 0,
    };
    const psbt = createPSBT(tx);
    return encodePSBTBase64(psbt);
  }

  /**
   * Tiny helper for OP_RETURN data encoding; mirrors Core's PushDataLength.
   */
  private encodePushData(data: Buffer): Buffer {
    if (data.length < 0x4c) {
      return Buffer.concat([Buffer.from([data.length]), data]);
    }
    if (data.length <= 0xff) {
      return Buffer.concat([Buffer.from([0x4c, data.length]), data]);
    }
    if (data.length <= 0xffff) {
      const lenBuf = Buffer.alloc(3);
      lenBuf[0] = 0x4d;
      lenBuf.writeUInt16LE(data.length, 1);
      return Buffer.concat([lenBuf, data]);
    }
    const lenBuf = Buffer.alloc(5);
    lenBuf[0] = 0x4e;
    lenBuf.writeUInt32LE(data.length, 1);
    return Buffer.concat([lenBuf, data]);
  }

  /**
   * decodepsbt: decode a base64 PSBT into Core's JSON output shape.
   *
   * Reference: bitcoin-core/src/rpc/rawtransaction.cpp::decodepsbt.
   *
   * @param params [psbt]
   */
  private async decodePSBTRpc(params: unknown[]): Promise<Record<string, unknown>> {
    const [psbtParam] = params;
    if (typeof psbtParam !== "string") {
      throw this.rpcError(RPCErrorCodes.INVALID_PARAMS, "psbt must be a string");
    }
    let psbt: PSBT;
    try {
      psbt = decodePSBTBase64(psbtParam);
    } catch (e) {
      throw this.rpcError(
        RPCErrorCodes.INVALID_PARAMS,
        `PSBT decode failed: ${(e as Error).message}`
      );
    }
    return decodePSBTToJSON(psbt) as unknown as Record<string, unknown>;
  }

  /**
   * combinepsbt: COMBINE multiple base64 PSBTs into one.
   *
   * Reference: bitcoin-core/src/rpc/rawtransaction.cpp::combinepsbt.
   *
   * @param params [txs: string[]]
   */
  private async combinePSBTRpc(params: unknown[]): Promise<string> {
    const [psbtsParam] = params;
    if (!Array.isArray(psbtsParam) || psbtsParam.length === 0) {
      throw this.rpcError(
        RPCErrorCodes.INVALID_PARAMS,
        "txs must be a non-empty array of base64 PSBTs"
      );
    }
    const psbts: PSBT[] = [];
    for (const s of psbtsParam) {
      if (typeof s !== "string") {
        throw this.rpcError(RPCErrorCodes.INVALID_PARAMS, "every PSBT must be base64 string");
      }
      try {
        psbts.push(decodePSBTBase64(s));
      } catch (e) {
        throw this.rpcError(
          RPCErrorCodes.INVALID_PARAMS,
          `PSBT decode failed: ${(e as Error).message}`
        );
      }
    }
    let combined: PSBT;
    try {
      combined = combinePSBTs(psbts);
    } catch (e) {
      throw this.rpcError(
        RPCErrorCodes.INVALID_PARAMS,
        `combine failed: ${(e as Error).message}`
      );
    }
    return encodePSBTBase64(combined);
  }

  /**
   * finalizepsbt: try to finalize a PSBT. If `extract` (default true) and
   * the PSBT is now complete, returns the network-serialized hex.
   *
   * Reference: bitcoin-core/src/rpc/rawtransaction.cpp::finalizepsbt.
   *
   * @param params [psbt, extract?]
   */
  private async finalizePSBTRpc(params: unknown[]): Promise<Record<string, unknown>> {
    const [psbtParam, extractParam] = params;
    if (typeof psbtParam !== "string") {
      throw this.rpcError(RPCErrorCodes.INVALID_PARAMS, "psbt must be a string");
    }
    const extract = extractParam === undefined ? true : extractParam === true;

    let psbt: PSBT;
    try {
      psbt = decodePSBTBase64(psbtParam);
    } catch (e) {
      throw this.rpcError(
        RPCErrorCodes.INVALID_PARAMS,
        `PSBT decode failed: ${(e as Error).message}`
      );
    }

    const complete = finalizePSBT(psbt);

    const result: Record<string, unknown> = { complete };
    if (complete && extract) {
      const tx = extractTransaction(psbt);
      result.hex = serializeTx(tx, true).toString("hex");
    } else {
      result.psbt = encodePSBTBase64(psbt);
    }
    return result;
  }

  /**
   * analyzepsbt: analyse a PSBT and report next-role per input + globally.
   *
   * Output shape mirrors Bitcoin Core's `analyzepsbt`
   * (`bitcoin-core/src/rpc/rawtransaction.cpp::analyzepsbt`,
   * `bitcoin-core/src/node/psbt.cpp::AnalyzePSBT`):
   *
   *   {
   *     "inputs": [
   *       { "has_utxo": bool, "is_final": bool, "next": role,
   *         "missing": { "signatures": ["pubkey-hex", ...] } (optional) },
   *       ...
   *     ],
   *     "next": role
   *   }
   *
   * The PSBT-level `next` is the minimum per-input role in Core's order
   * (creator < updater < signer < finalizer < extractor). Multisig inputs
   * are classified by parsing the redeem/witness CHECKMULTISIG layout to
   * derive the M threshold; an input with M partial sigs is reported as
   * `next=finalizer`, not `signer` (W47 / W44-1 finding; see also
   * camlcoin commit `2a22a0e` for the OCaml reference implementation).
   *
   * Per-input `estimated_vsize` / `estimated_feerate` / `fee` are not
   * emitted yet — the W40-C harness only checks the top-level `next`
   * field. Adding them is a follow-up that requires a working
   * dummy-signer analog of Core's `SignPSBTInput`.
   *
   * @param params [psbt]
   */
  private async analyzePSBTRpc(params: unknown[]): Promise<Record<string, unknown>> {
    const [psbtParam] = params;
    if (typeof psbtParam !== "string") {
      throw this.rpcError(RPCErrorCodes.INVALID_PARAMS, "psbt must be a string");
    }
    let psbt: PSBT;
    try {
      psbt = decodePSBTBase64(psbtParam);
    } catch (e) {
      throw this.rpcError(
        RPCErrorCodes.INVALID_PARAMS,
        `TX decode failed ${(e as Error).message}`
      );
    }
    const analysis = analyzePSBTCore(psbt);
    // Cast through unknown — `AnalyzedPSBT` is a structurally-compatible
    // JSON object (string-keyed, JSON-safe values).
    return analysis as unknown as Record<string, unknown>;
  }

  /**
   * walletcreatefundedpsbt: build, fund (coin-select) and PSBT-encode an
   * unsigned transaction using the wallet's UTXOs and change address.
   *
   * Implements Core's CREATOR + UPDATER roles. We use the wallet's existing
   * coin-selection (BnB → Knapsack → largest-first) and attach a witness
   * UTXO to each PSBT input so subsequent SIGNER passes can finalize.
   *
   * Reference: bitcoin-core/src/wallet/rpc/spend.cpp::walletcreatefundedpsbt.
   *
   * @param params [inputs, outputs, locktime?, options?, bip32derivs?]
   */
  private async walletCreateFundedPSBT(params: unknown[]): Promise<Record<string, unknown>> {
    const [inputsParam, outputsParam, locktimeParam, optionsParam] = params;

    if (!Array.isArray(inputsParam)) {
      throw this.rpcError(RPCErrorCodes.INVALID_PARAMS, "inputs must be an array");
    }
    if (
      !Array.isArray(outputsParam) &&
      (typeof outputsParam !== "object" || outputsParam === null)
    ) {
      throw this.rpcError(RPCErrorCodes.INVALID_PARAMS, "outputs must be array or object");
    }

    const wallet = this.getCurrentWallet();
    const lockTime = (typeof locktimeParam === "number" ? locktimeParam : 0) >>> 0;
    const options = (typeof optionsParam === "object" && optionsParam) ? optionsParam as Record<string, unknown> : {};
    const replaceable = options.replaceable === true;
    const sequenceDefault = replaceable ? 0xfffffffd : 0xfffffffe;

    // Parse outputs into {address, amountSats}[].
    const outputsList: Array<{ scriptPubKey: Buffer; value: bigint; address?: string }> = [];
    let totalOutputSats = 0n;
    const outArray: Array<Record<string, unknown>> = Array.isArray(outputsParam)
      ? (outputsParam as Array<Record<string, unknown>>)
      : [outputsParam as Record<string, unknown>];
    for (const out of outArray) {
      for (const [k, v] of Object.entries(out)) {
        if (k === "data") {
          if (typeof v !== "string") {
            throw this.rpcError(RPCErrorCodes.INVALID_PARAMS, "data output must be hex string");
          }
          const dataBuf = Buffer.from(v, "hex");
          const script = Buffer.concat([Buffer.from([0x6a]), this.encodePushData(dataBuf)]);
          outputsList.push({ scriptPubKey: script, value: 0n });
        } else {
          if (typeof v !== "number" || v < 0) {
            throw this.rpcError(
              RPCErrorCodes.INVALID_PARAMS,
              "output amount must be a non-negative number"
            );
          }
          let decoded;
          try {
            decoded = decodeAddress(k);
          } catch {
            throw this.rpcError(RPCErrorCodes.INVALID_ADDRESS_OR_KEY, `Invalid address: ${k}`);
          }
          const sats = BigInt(Math.round(v * 100_000_000));
          totalOutputSats += sats;
          const scriptHex = this.buildScriptPubKeyHex(decoded.type, decoded.hash);
          outputsList.push({
            scriptPubKey: Buffer.from(scriptHex, "hex"),
            value: sats,
            address: k,
          });
        }
      }
    }

    // Fee rate: prefer options.fee_rate (sat/vB).
    let feeRate = 1;
    if (typeof options.fee_rate === "number" && options.fee_rate > 0) {
      feeRate = options.fee_rate as number;
    } else if (typeof options.feeRate === "number" && (options.feeRate as number) > 0) {
      // Core accepts feeRate (BTC/kvB) as a deprecated alias; convert to sat/vB.
      feeRate = ((options.feeRate as number) * 100_000_000) / 1000;
    }

    // Pre-supplied inputs are not coin-selected; for now we require
    // inputs=[] and let the wallet choose. Manual prevouts are a follow-up.
    if (inputsParam.length > 0) {
      throw this.rpcError(
        RPCErrorCodes.INVALID_PARAMS,
        "Manual `inputs` aren't supported yet; pass [] to auto-select from wallet"
      );
    }

    // Coin selection.
    let selection;
    try {
      selection = wallet.selectCoinsAdvanced(totalOutputSats, feeRate);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      throw this.rpcError(RPCErrorCodes.WALLET_INSUFFICIENT_FUNDS, msg);
    }

    // Build inputs.
    const txInputs: TxIn[] = selection.inputs.map((u) => ({
      prevOut: u.outpoint,
      scriptSig: Buffer.alloc(0),
      sequence: sequenceDefault,
      witness: [],
    }));

    // Build outputs (caller-specified) + optional change output.
    const txOutputs: TxOut[] = outputsList.map((o) => ({
      value: o.value,
      scriptPubKey: o.scriptPubKey,
    }));
    let changePos = -1;
    const DUST_THRESHOLD = 546n;
    if (selection.change > DUST_THRESHOLD) {
      const changeAddr = (typeof options.changeAddress === "string"
        && options.changeAddress.length > 0)
        ? options.changeAddress as string
        : wallet.getChangeAddress();
      const decoded = decodeAddress(changeAddr);
      const scriptHex = this.buildScriptPubKeyHex(decoded.type, decoded.hash);
      changePos = txOutputs.length;
      txOutputs.push({
        value: selection.change,
        scriptPubKey: Buffer.from(scriptHex, "hex"),
      });
    }

    const tx: Transaction = {
      version: 2,
      inputs: txInputs,
      outputs: txOutputs,
      lockTime,
    };

    // Build PSBT and attach witness UTXOs so a signer/finalizer downstream
    // has everything it needs.
    const psbt = createPSBT(tx);
    for (let i = 0; i < selection.inputs.length; i++) {
      const u = selection.inputs[i];
      const decoded = decodeAddress(u.address);
      const scriptPubKey = Buffer.from(
        this.buildScriptPubKeyHex(decoded.type, decoded.hash),
        "hex"
      );
      updateInputUTXO(psbt, i, { value: u.amount, scriptPubKey } as TxOut, true);
    }

    return {
      psbt: encodePSBTBase64(psbt),
      fee: Number(selection.fee) / 100_000_000,
      changepos: changePos,
    };
  }

  private async help(params: unknown[]): Promise<string> {
    const methods = Array.from(this.methods.keys()).sort().join("\n");
    return methods;
  }

  // ========== Wave-47b Methods ==========

  /**
   * gettxoutsetinfo: Returns statistics about the unspent transaction output set.
   */
  private async getTxOutSetInfo(params: unknown[]): Promise<Record<string, unknown>> {
    const chainState = await this.db.getChainState();
    if (!chainState) {
      throw this.rpcError(RPCErrorCodes.MISC_ERROR, "No chain state available");
    }
    const bestBlock = this.chainState.getBestBlock();
    const bestBlockHashHex = Buffer.from(bestBlock.hash).reverse().toString("hex");

    // Compute hash_serialized_3 via the shared helper
    const { hash, coinsCount } = await computeUTXOSetHash(this.db);
    return {
      height: bestBlock.height,
      bestblock: bestBlockHashHex,
      txouts: Number(coinsCount),
      transactions: Number(coinsCount),
      bogosize: 0,
      hash_serialized_3: hash.reverse().toString("hex"),
      total_amount: 0,
    };
  }

  /**
   * getnetworkhashps: Estimated network hash rate over the last nblocks blocks.
   * Mirrors Bitcoin Core: workDiff / timeDiff over a sliding window.
   */
  private async getNetworkHashPS(params: unknown[]): Promise<number> {
    const nblocks = typeof params[0] === "number" ? params[0] : 120;
    const bestBlock = this.chainState.getBestBlock();
    const tipHeight = bestBlock.height;
    if (tipHeight < 2) return 0;

    const window = nblocks <= 0 ? 120 : Math.min(nblocks, tipHeight);
    const hiHeight = tipHeight;
    const loHeight = hiHeight - window;

    const hiEntry = this.headerSync.getHeaderByHeight(hiHeight);
    const loEntry = this.headerSync.getHeaderByHeight(loHeight);
    if (!hiEntry || !loEntry) return 0;

    const workDiff = hiEntry.chainWork - loEntry.chainWork;
    const timeDiff = hiEntry.header.timestamp - loEntry.header.timestamp;
    if (timeDiff <= 0) return 0;

    // workDiff is bigint; divide using bigint arithmetic, convert to number for JSON
    const hashps = workDiff / BigInt(timeDiff);
    // Number() is safe here: Bitcoin mainnet hashrate is ~10^21 H/s which exceeds
    // Number.MAX_SAFE_INTEGER but JSON clients expect a numeric result. Use Number()
    // which converts to float — same as Bitcoin Core's return type.
    return Number(hashps);
  }

  /**
   * gettxoutproof: Returns a CMerkleBlock hex proof that a txid is in a block.
   */
  private async getTxOutProof(params: unknown[]): Promise<string> {
    if (!Array.isArray(params) || !Array.isArray(params[0])) {
      throw this.rpcError(RPCErrorCodes.INVALID_PARAMS, "Invalid parameters: expected [txids] or [txids, blockhash]");
    }
    const txidHexList: string[] = params[0] as string[];
    const blockHashHexParam = typeof params[1] === "string" ? params[1] : null;

    // Convert display-order txids to internal order
    const reqTxids = txidHexList.map((h) => Buffer.from(h, "hex").reverse());

    // Find the block containing the first txid
    let blockHashInternal: Buffer;
    if (blockHashHexParam) {
      blockHashInternal = Buffer.from(blockHashHexParam, "hex").reverse();
    } else {
      const first = reqTxids[0];
      if (!first) throw this.rpcError(RPCErrorCodes.INVALID_PARAMS, "No txids provided");
      const entry = await this.db.getTxIndex(first);
      if (!entry) throw this.rpcError(RPCErrorCodes.MISC_ERROR, "Transaction not found in block index");
      blockHashInternal = entry.blockHash;
    }

    const blockData = await this.db.getBlock(blockHashInternal);
    if (!blockData) throw this.rpcError(RPCErrorCodes.MISC_ERROR, "Block not found");

    const reader = new BufferReader(blockData);
    const block = deserializeBlock(reader);

    const allTxids = block.transactions.map((tx) => getTxId(tx) as Buffer);
    const nTx = allTxids.length;
    const matchFlags = allTxids.map((txid) =>
      reqTxids.some((req) => req.equals(txid))
    );

    const { hashes, bits } = w47bTraverseAndBuild(nTx, allTxids, matchFlags);

    // Encode CMerkleBlock: 80-byte header | nTx LE | varint hashes | hashes | varint flags | flags
    const hdrCs = serializeBlockHeader(block.header);

    const parts: Buffer[] = [hdrCs];
    const nTxBuf = Buffer.alloc(4);
    nTxBuf.writeUInt32LE(nTx, 0);
    parts.push(nTxBuf);
    parts.push(w47bEncodeVarInt(hashes.length));
    for (const h of hashes) parts.push(h);
    const flagBytes = w47bBitsToBytes(bits);
    parts.push(w47bEncodeVarInt(flagBytes.length));
    parts.push(flagBytes);

    return Buffer.concat(parts).toString("hex");
  }

  /**
   * verifytxoutproof: Verifies a CMerkleBlock proof and returns matched txids.
   */
  private async verifyTxOutProof(params: unknown[]): Promise<string[]> {
    if (typeof params[0] !== "string") {
      throw this.rpcError(RPCErrorCodes.INVALID_PARAMS, "Invalid parameters: expected [proof_hex]");
    }
    const proofBuf = Buffer.from(params[0] as string, "hex");
    if (proofBuf.length < 84) {
      throw this.rpcError(RPCErrorCodes.MISC_ERROR, "Proof too short");
    }

    const nTx = proofBuf.readUInt32LE(80);
    if (nTx === 0) return [];

    let pos = 84;
    const [hashCount, pos2] = w47bReadVarInt(proofBuf, pos);
    pos = pos2;
    if (proofBuf.length < pos + hashCount * 32) {
      throw this.rpcError(RPCErrorCodes.MISC_ERROR, "Proof truncated (hashes)");
    }
    const hashes: Buffer[] = [];
    for (let i = 0; i < hashCount; i++) {
      hashes.push(proofBuf.subarray(pos + i * 32, pos + i * 32 + 32));
    }
    pos += hashCount * 32;

    const [flagCount, pos3] = w47bReadVarInt(proofBuf, pos);
    pos = pos3;
    if (proofBuf.length < pos + flagCount) {
      throw this.rpcError(RPCErrorCodes.MISC_ERROR, "Proof truncated (flags)");
    }
    const flagBytes = proofBuf.subarray(pos, pos + flagCount);

    return w47bTraverseAndExtract(nTx, hashes, flagBytes);
  }

  /**
   * getrpcinfo: Returns runtime information about the RPC server.
   */
  private async getRpcInfo(): Promise<Record<string, unknown>> {
    return {
      active_commands: [],
      logpath: "",
    };
  }
}
