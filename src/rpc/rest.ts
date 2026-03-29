/**
 * REST API for read-only blockchain queries.
 *
 * Implements Bitcoin Core-compatible REST endpoints:
 * - /rest/block/<hash>.<format>
 * - /rest/block/notxdetails/<hash>.<format>
 * - /rest/headers/<count>/<hash>.<format>
 * - /rest/blockhashbyheight/<height>.<format>
 * - /rest/tx/<txid>.<format>
 * - /rest/getutxos/<checkmempool>/<txid-vout>/....<format>
 * - /rest/mempool/info.json
 * - /rest/mempool/contents.json
 *
 * Formats: .json, .bin, .hex
 * No authentication required (read-only).
 *
 * Reference: /home/max/hashhog/bitcoin/src/rest.cpp
 */

import type { ChainStateManager } from "../chain/state.js";
import type { ChainDB, UTXOEntry } from "../storage/database.js";
import type { Mempool } from "../mempool/mempool.js";
import type { HeaderSync } from "../sync/headers.js";
import type { ConsensusParams } from "../consensus/params.js";
import type { Block, BlockHeader } from "../validation/block.js";
import {
  deserializeBlock,
  serializeBlock,
  serializeBlockHeader,
  getBlockHash,
} from "../validation/block.js";
import {
  deserializeTx,
  serializeTx,
  getTxId,
  getWTxId,
  getTxWeight,
  getTxVSize,
  hasWitness,
  isCoinbase,
} from "../validation/tx.js";
import { BufferReader, BufferWriter } from "../wire/serialization.js";
import type { TxIndexManager } from "../storage/indexes.js";

/**
 * Supported REST response formats.
 */
export type RESTFormat = "json" | "bin" | "hex";

/**
 * Maximum number of headers to return per request.
 */
const MAX_REST_HEADERS_RESULTS = 2000;

/**
 * Maximum number of outpoints to query in getutxos.
 */
const MAX_GETUTXOS_OUTPOINTS = 15;

/**
 * REST server configuration.
 */
export interface RESTServerConfig {
  /** Port to listen on (default 8332). */
  port: number;
  /** Host to bind to (default '127.0.0.1'). */
  host: string;
  /** Enable tx lookup by txid (requires txindex). */
  txIndexEnabled: boolean;
}

/**
 * Dependencies for the REST server.
 */
export interface RESTServerDeps {
  chainState: ChainStateManager;
  mempool: Mempool;
  headerSync: HeaderSync;
  db: ChainDB;
  params: ConsensusParams;
  txIndex?: TxIndexManager;
}

/**
 * REST API server using Bun.serve.
 *
 * Serves read-only blockchain data in JSON, binary, and hex formats.
 * No authentication required.
 */
export class RESTServer {
  private server: ReturnType<typeof Bun.serve> | null = null;
  private config: RESTServerConfig;
  private chainState: ChainStateManager;
  private mempool: Mempool;
  private headerSync: HeaderSync;
  private db: ChainDB;
  private params: ConsensusParams;
  private txIndex?: TxIndexManager;

  constructor(config: RESTServerConfig, deps: RESTServerDeps) {
    this.config = {
      port: config.port ?? 8332,
      host: config.host ?? "127.0.0.1",
      txIndexEnabled: config.txIndexEnabled ?? false,
    };
    this.chainState = deps.chainState;
    this.mempool = deps.mempool;
    this.headerSync = deps.headerSync;
    this.db = deps.db;
    this.params = deps.params;
    this.txIndex = deps.txIndex;
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
      `REST API listening on http://${this.config.host}:${this.config.port}/rest/`
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
   * Handle an incoming HTTP request.
   */
  private async handleRequest(req: Request): Promise<Response> {
    // Only accept GET requests
    if (req.method !== "GET") {
      return this.errorResponse(405, "Only GET requests are supported");
    }

    const url = new URL(req.url);
    const path = url.pathname;

    // All REST endpoints start with /rest/
    if (!path.startsWith("/rest/")) {
      return this.errorResponse(404, "Not found");
    }

    const restPath = path.slice(6); // Remove "/rest/"

    try {
      // Route to appropriate handler
      if (restPath.startsWith("block/notxdetails/")) {
        return await this.handleBlockNoTxDetails(restPath.slice(18));
      }
      if (restPath.startsWith("block/")) {
        return await this.handleBlock(restPath.slice(6));
      }
      if (restPath.startsWith("headers/")) {
        return await this.handleHeaders(restPath.slice(8));
      }
      if (restPath.startsWith("blockhashbyheight/")) {
        return await this.handleBlockHashByHeight(restPath.slice(18));
      }
      if (restPath.startsWith("tx/")) {
        return await this.handleTx(restPath.slice(3));
      }
      if (restPath.startsWith("getutxos/")) {
        return await this.handleGetUTXOs(restPath.slice(9));
      }
      if (restPath.startsWith("mempool/")) {
        return await this.handleMempool(restPath.slice(8));
      }
      if (restPath.startsWith("chaininfo")) {
        return await this.handleChainInfo(restPath.slice(9));
      }

      return this.errorResponse(404, "Unknown REST endpoint");
    } catch (error) {
      const message = error instanceof Error ? error.message : "Internal error";
      return this.errorResponse(500, message);
    }
  }

  /**
   * Parse format from URI path (e.g., "hash.json" -> ["hash", "json"]).
   */
  private parseFormat(param: string): { path: string; format: RESTFormat } {
    // Remove query string if present
    const queryIndex = param.indexOf("?");
    if (queryIndex !== -1) {
      param = param.slice(0, queryIndex);
    }

    const dotIndex = param.lastIndexOf(".");
    if (dotIndex === -1) {
      return { path: param, format: "json" }; // Default to JSON
    }

    const ext = param.slice(dotIndex + 1);
    const path = param.slice(0, dotIndex);

    if (ext === "json" || ext === "bin" || ext === "hex") {
      return { path, format: ext };
    }

    return { path: param, format: "json" };
  }

  /**
   * Create a response with appropriate content type.
   */
  private formatResponse(
    data: unknown,
    format: RESTFormat,
    binaryData?: Buffer
  ): Response {
    switch (format) {
      case "json":
        return new Response(JSON.stringify(data) + "\n", {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      case "bin":
        return new Response(binaryData ?? Buffer.alloc(0), {
          status: 200,
          headers: { "Content-Type": "application/octet-stream" },
        });
      case "hex":
        const hexStr = (binaryData ?? Buffer.alloc(0)).toString("hex") + "\n";
        return new Response(hexStr, {
          status: 200,
          headers: { "Content-Type": "text/plain" },
        });
    }
  }

  /**
   * Create an error response.
   */
  private errorResponse(status: number, message: string): Response {
    return new Response(message + "\r\n", {
      status,
      headers: { "Content-Type": "text/plain" },
    });
  }

  // ========== Block Endpoints ==========

  /**
   * GET /rest/block/<hash>.<format>
   * Returns full block data with transaction details.
   */
  private async handleBlock(pathParam: string): Promise<Response> {
    const { path: hashStr, format } = this.parseFormat(pathParam);

    // Validate hash
    const hash = this.parseBlockHash(hashStr);
    if (!hash) {
      return this.errorResponse(400, "Invalid hash: " + hashStr);
    }

    // Get block data
    const blockData = await this.db.getBlock(hash);
    if (!blockData) {
      return this.errorResponse(404, hashStr + " not found");
    }

    // For binary/hex, return raw block
    if (format === "bin" || format === "hex") {
      return this.formatResponse(null, format, blockData);
    }

    // For JSON, parse and format
    const reader = new BufferReader(blockData);
    const block = deserializeBlock(reader);
    const blockIndex = await this.db.getBlockIndex(hash);
    const height = blockIndex?.height ?? -1;

    const json = this.formatBlockJson(block, hash, height, true);
    return this.formatResponse(json, format);
  }

  /**
   * GET /rest/block/notxdetails/<hash>.<format>
   * Returns block data without full transaction details (only txids).
   */
  private async handleBlockNoTxDetails(pathParam: string): Promise<Response> {
    const { path: hashStr, format } = this.parseFormat(pathParam);

    const hash = this.parseBlockHash(hashStr);
    if (!hash) {
      return this.errorResponse(400, "Invalid hash: " + hashStr);
    }

    const blockData = await this.db.getBlock(hash);
    if (!blockData) {
      return this.errorResponse(404, hashStr + " not found");
    }

    if (format === "bin" || format === "hex") {
      return this.formatResponse(null, format, blockData);
    }

    const reader = new BufferReader(blockData);
    const block = deserializeBlock(reader);
    const blockIndex = await this.db.getBlockIndex(hash);
    const height = blockIndex?.height ?? -1;

    const json = this.formatBlockJson(block, hash, height, false);
    return this.formatResponse(json, format);
  }

  /**
   * Format block to JSON.
   */
  private formatBlockJson(
    block: Block,
    hash: Buffer,
    height: number,
    includeTxDetails: boolean
  ): Record<string, unknown> {
    const headerEntry = this.headerSync.getHeader(hash);
    const bestBlock = this.chainState.getBestBlock();

    const result: Record<string, unknown> = {
      hash: Buffer.from(hash).reverse().toString("hex"),
      confirmations: height >= 0 ? bestBlock.height - height + 1 : 0,
      height,
      version: block.header.version,
      versionHex: block.header.version.toString(16).padStart(8, "0"),
      merkleroot: Buffer.from(block.header.merkleRoot).reverse().toString("hex"),
      time: block.header.timestamp,
      mediantime: headerEntry
        ? this.headerSync.getMedianTimePast(headerEntry)
        : block.header.timestamp,
      nonce: block.header.nonce,
      bits: block.header.bits.toString(16).padStart(8, "0"),
      difficulty: this.calculateDifficultyFromBits(block.header.bits),
      chainwork: headerEntry?.chainWork.toString(16).padStart(64, "0") ?? "0",
      nTx: block.transactions.length,
      previousblockhash: Buffer.from(block.header.prevBlock).reverse().toString("hex"),
    };

    if (includeTxDetails) {
      result.tx = block.transactions.map((tx, index) =>
        this.formatTxJson(tx, hash, height, index)
      );
    } else {
      result.tx = block.transactions.map((tx) => Buffer.from(getTxId(tx)).reverse().toString("hex"));
    }

    return result;
  }

  // ========== Headers Endpoint ==========

  /**
   * GET /rest/headers/<count>/<hash>.<format>
   * Returns count headers starting from hash.
   */
  private async handleHeaders(pathParam: string): Promise<Response> {
    const { path, format } = this.parseFormat(pathParam);

    // Parse count/hash from path
    const parts = path.split("/");
    let count: number;
    let hashStr: string;

    if (parts.length === 2) {
      // Deprecated path: /rest/headers/<count>/<hash>
      count = parseInt(parts[0], 10);
      hashStr = parts[1];
    } else if (parts.length === 1) {
      // New path: /rest/headers/<hash>?count=<count>
      hashStr = parts[0];
      count = 5; // Default
    } else {
      return this.errorResponse(
        400,
        "Invalid URI format. Expected /rest/headers/<hash>.<ext>?count=<count>"
      );
    }

    if (isNaN(count) || count < 1 || count > MAX_REST_HEADERS_RESULTS) {
      return this.errorResponse(
        400,
        `Header count is invalid or out of acceptable range (1-${MAX_REST_HEADERS_RESULTS})`
      );
    }

    const hash = this.parseBlockHash(hashStr);
    if (!hash) {
      return this.errorResponse(400, "Invalid hash: " + hashStr);
    }

    // Collect headers
    const headers: BlockHeader[] = [];
    let currentHash = hash;

    for (let i = 0; i < count; i++) {
      const blockIndex = await this.db.getBlockIndex(currentHash);
      if (!blockIndex) break;

      const headerBuf = blockIndex.header;
      const header: BlockHeader = {
        version: headerBuf.readInt32LE(0),
        prevBlock: Buffer.from(headerBuf.subarray(4, 36)),
        merkleRoot: Buffer.from(headerBuf.subarray(36, 68)),
        timestamp: headerBuf.readUInt32LE(68),
        bits: headerBuf.readUInt32LE(72),
        nonce: headerBuf.readUInt32LE(76),
      };
      headers.push(header);

      // Get next block hash
      const nextHash = await this.db.getBlockHashByHeight(blockIndex.height + 1);
      if (!nextHash) break;
      currentHash = nextHash;
    }

    if (format === "bin" || format === "hex") {
      // Serialize all headers
      const writer = new BufferWriter();
      for (const header of headers) {
        writer.writeBytes(serializeBlockHeader(header));
      }
      return this.formatResponse(null, format, writer.toBuffer());
    }

    // JSON format
    const jsonHeaders = headers.map((header, index) => {
      const headerHash = getBlockHash(header);
      const headerEntry = this.headerSync.getHeader(headerHash);
      return this.formatHeaderJson(header, headerHash, headerEntry);
    });

    return this.formatResponse(jsonHeaders, format);
  }

  /**
   * Format header to JSON.
   */
  private formatHeaderJson(
    header: BlockHeader,
    hash: Buffer,
    headerEntry?: { height: number; chainWork: bigint }
  ): Record<string, unknown> {
    const bestBlock = this.chainState.getBestBlock();
    const height = headerEntry?.height ?? -1;

    return {
      hash: Buffer.from(hash).reverse().toString("hex"),
      confirmations: height >= 0 ? bestBlock.height - height + 1 : 0,
      height,
      version: header.version,
      versionHex: header.version.toString(16).padStart(8, "0"),
      merkleroot: Buffer.from(header.merkleRoot).reverse().toString("hex"),
      time: header.timestamp,
      nonce: header.nonce,
      bits: header.bits.toString(16).padStart(8, "0"),
      difficulty: this.calculateDifficultyFromBits(header.bits),
      chainwork: headerEntry?.chainWork.toString(16).padStart(64, "0") ?? "0",
      previousblockhash: Buffer.from(header.prevBlock).reverse().toString("hex"),
    };
  }

  // ========== Block Hash by Height ==========

  /**
   * GET /rest/blockhashbyheight/<height>.<format>
   * Returns block hash at the given height.
   */
  private async handleBlockHashByHeight(pathParam: string): Promise<Response> {
    const { path: heightStr, format } = this.parseFormat(pathParam);

    const height = parseInt(heightStr, 10);
    if (isNaN(height) || height < 0) {
      return this.errorResponse(400, "Invalid height: " + heightStr);
    }

    const bestBlock = this.chainState.getBestBlock();
    if (height > bestBlock.height) {
      return this.errorResponse(404, "Block height out of range");
    }

    const hash = await this.db.getBlockHashByHeight(height);
    if (!hash) {
      return this.errorResponse(404, "Block hash not found for height");
    }

    if (format === "bin") {
      return this.formatResponse(null, format, hash);
    }

    if (format === "hex") {
      return new Response(Buffer.from(hash).reverse().toString("hex") + "\n", {
        status: 200,
        headers: { "Content-Type": "text/plain" },
      });
    }

    return this.formatResponse({ blockhash: Buffer.from(hash).reverse().toString("hex") }, format);
  }

  // ========== Transaction Endpoint ==========

  /**
   * GET /rest/tx/<txid>.<format>
   * Returns transaction data (requires txindex or mempool lookup).
   */
  private async handleTx(pathParam: string): Promise<Response> {
    const { path: txidStr, format } = this.parseFormat(pathParam);

    const txid = this.parseTxid(txidStr);
    if (!txid) {
      return this.errorResponse(400, "Invalid hash: " + txidStr);
    }

    // Check mempool first
    const mempoolEntry = this.mempool.getTransaction(txid);
    if (mempoolEntry) {
      const rawTx = serializeTx(mempoolEntry.tx, true);

      if (format === "bin" || format === "hex") {
        return this.formatResponse(null, format, rawTx);
      }

      const json = this.formatTxJson(mempoolEntry.tx, null, -1, 0);
      return this.formatResponse(json, format);
    }

    // Check txindex if enabled
    if (!this.config.txIndexEnabled || !this.txIndex) {
      return this.errorResponse(
        404,
        "No such mempool transaction. Use -txindex to enable transaction index"
      );
    }

    const txIndexEntry = await this.txIndex.getTransaction(txid);
    if (!txIndexEntry) {
      return this.errorResponse(404, txidStr + " not found");
    }

    // Load transaction from block
    const blockData = await this.db.getBlock(txIndexEntry.blockHash);
    if (!blockData) {
      return this.errorResponse(404, "Block data not available");
    }

    // Extract transaction
    const txData = blockData.subarray(
      txIndexEntry.offset,
      txIndexEntry.offset + txIndexEntry.length
    );
    const reader = new BufferReader(txData);
    const tx = deserializeTx(reader);

    if (format === "bin" || format === "hex") {
      return this.formatResponse(null, format, serializeTx(tx, true));
    }

    // Get block height
    const blockIndex = await this.db.getBlockIndex(txIndexEntry.blockHash);
    const height = blockIndex?.height ?? -1;

    const json = this.formatTxJson(tx, txIndexEntry.blockHash, height, 0);
    return this.formatResponse(json, format);
  }

  /**
   * Format transaction to JSON.
   */
  private formatTxJson(
    tx: import("../validation/tx.js").Transaction,
    blockHash: Buffer | null,
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
        if (isCoinbase(tx)) {
          vin.coinbase = input.scriptSig.toString("hex");
        } else {
          vin.txid = Buffer.from(input.prevOut.txid).reverse().toString("hex");
          vin.vout = input.prevOut.vout;
          vin.scriptSig = {
            hex: input.scriptSig.toString("hex"),
          };
        }
        vin.sequence = input.sequence;
        if (input.witness && input.witness.length > 0) {
          vin.txinwitness = input.witness.map((w) => w.toString("hex"));
        }
        return vin;
      }),
      vout: tx.outputs.map((output, i) => ({
        value: Number(output.value) / 100000000,
        n: i,
        scriptPubKey: {
          hex: output.scriptPubKey.toString("hex"),
        },
      })),
    };

    if (blockHash) {
      result.blockhash = Buffer.from(blockHash).reverse().toString("hex");
      result.confirmations = this.chainState.getBestBlock().height - height + 1;
      result.blocktime = 0; // Would need to look up
    }

    return result;
  }

  // ========== UTXO Endpoint ==========

  /**
   * GET /rest/getutxos/<checkmempool>/<txid-vout>/....<format>
   * Check UTXO status for specified outpoints.
   */
  private async handleGetUTXOs(pathParam: string): Promise<Response> {
    const { path, format } = this.parseFormat(pathParam);

    const parts = path.split("/").filter((p) => p.length > 0);
    if (parts.length === 0) {
      return this.errorResponse(400, "Error: empty request");
    }

    // Check for checkmempool flag
    let checkMempool = false;
    let outpointParts = parts;
    if (parts[0] === "checkmempool") {
      checkMempool = true;
      outpointParts = parts.slice(1);
    }

    if (outpointParts.length === 0) {
      return this.errorResponse(400, "Error: empty request");
    }

    if (outpointParts.length > MAX_GETUTXOS_OUTPOINTS) {
      return this.errorResponse(
        400,
        `Error: max outpoints exceeded (max: ${MAX_GETUTXOS_OUTPOINTS}, tried: ${outpointParts.length})`
      );
    }

    // Parse outpoints (format: txid-vout)
    const outpoints: Array<{ txid: Buffer; vout: number }> = [];
    for (const part of outpointParts) {
      const dashIndex = part.lastIndexOf("-");
      if (dashIndex === -1) {
        return this.errorResponse(400, "Parse error");
      }
      const txidHex = part.slice(0, dashIndex);
      const voutStr = part.slice(dashIndex + 1);

      const txid = this.parseTxid(txidHex);
      const vout = parseInt(voutStr, 10);
      if (!txid || isNaN(vout)) {
        return this.errorResponse(400, "Parse error");
      }
      outpoints.push({ txid, vout });
    }

    // Check each outpoint
    const hits: boolean[] = [];
    const utxos: Array<{ height: number; value: bigint; scriptPubKey: Buffer }> = [];
    const bestBlock = this.chainState.getBestBlock();

    for (const { txid, vout } of outpoints) {
      // Check if spent in mempool
      if (checkMempool) {
        const isSpentInMempool = this.mempool.isOutpointSpent(txid, vout);
        if (isSpentInMempool) {
          hits.push(false);
          continue;
        }
      }

      // Check UTXO set
      const utxo = await this.db.getUTXO(txid, vout);
      if (utxo) {
        hits.push(true);
        utxos.push({
          height: utxo.height,
          value: utxo.amount,
          scriptPubKey: utxo.scriptPubKey,
        });
      } else {
        hits.push(false);
      }
    }

    // Build bitmap
    const bitmap = Buffer.alloc(Math.ceil(hits.length / 8), 0);
    for (let i = 0; i < hits.length; i++) {
      if (hits[i]) {
        bitmap[Math.floor(i / 8)] |= 1 << (i % 8);
      }
    }

    if (format === "bin") {
      // Binary format: height (4) + hash (32) + bitmap + utxos
      const writer = new BufferWriter();
      writer.writeInt32LE(bestBlock.height);
      writer.writeHash(bestBlock.hash);
      writer.writeVarBytes(bitmap);

      for (const utxo of utxos) {
        writer.writeUInt32LE(0); // nTxVerDummy
        writer.writeUInt32LE(utxo.height);
        writer.writeUInt64LE(utxo.value);
        writer.writeVarBytes(utxo.scriptPubKey);
      }

      return this.formatResponse(null, format, writer.toBuffer());
    }

    if (format === "hex") {
      const writer = new BufferWriter();
      writer.writeInt32LE(bestBlock.height);
      writer.writeHash(bestBlock.hash);
      writer.writeVarBytes(bitmap);

      for (const utxo of utxos) {
        writer.writeUInt32LE(0);
        writer.writeUInt32LE(utxo.height);
        writer.writeUInt64LE(utxo.value);
        writer.writeVarBytes(utxo.scriptPubKey);
      }

      return this.formatResponse(null, format, writer.toBuffer());
    }

    // JSON format
    const bitmapStr = hits.map((h) => (h ? "1" : "0")).join("");
    const json: Record<string, unknown> = {
      chainHeight: bestBlock.height,
      chaintipHash: Buffer.from(bestBlock.hash).reverse().toString("hex"),
      bitmap: bitmapStr,
      utxos: utxos.map((utxo) => ({
        height: utxo.height,
        value: Number(utxo.value) / 100000000,
        scriptPubKey: {
          hex: utxo.scriptPubKey.toString("hex"),
        },
      })),
    };

    return this.formatResponse(json, format);
  }

  // ========== Mempool Endpoints ==========

  /**
   * GET /rest/mempool/info.json or /rest/mempool/contents.json
   */
  private async handleMempool(pathParam: string): Promise<Response> {
    const { path, format } = this.parseFormat(pathParam);

    if (format !== "json") {
      return this.errorResponse(404, "output format not found (available: json)");
    }

    if (path === "info") {
      const info = this.mempool.getInfo();
      const json = {
        loaded: true,
        size: info.size,
        bytes: info.bytes,
        usage: info.bytes, // Approximate memory usage
        maxmempool: 300000000, // Default 300MB
        mempoolminfee: info.minFeeRate / 100000, // Convert to BTC/kvB
        minrelaytxfee: 0.00001, // 1 sat/vB
      };
      return this.formatResponse(json, format);
    }

    if (path === "contents") {
      const entries = new Map<string, Record<string, unknown>>();
      const txids = this.mempool.getAllTxids();

      for (const txid of txids) {
        const entry = this.mempool.getTransaction(txid);
        if (entry) {
          entries.set(Buffer.from(txid).reverse().toString("hex"), {
            vsize: entry.vsize,
            weight: entry.weight,
            fee: Number(entry.fee) / 100000000,
            modifiedfee: Number(entry.fee) / 100000000,
            time: entry.addedTime,
            height: entry.height,
            descendantcount: entry.descendantCount,
            descendantsize: entry.descendantSize,
            ancestorcount: entry.ancestorCount,
            ancestorsize: entry.ancestorSize,
            wtxid: Buffer.from(getWTxId(entry.tx)).reverse().toString("hex"),
            fees: {
              base: Number(entry.fee) / 100000000,
              modified: Number(entry.fee) / 100000000,
              ancestor: Number(entry.fee) / 100000000,
              descendant: Number(entry.fee) / 100000000,
            },
            depends: Array.from(entry.dependsOn),
            spentby: Array.from(entry.spentBy),
          });
        }
      }

      return this.formatResponse(Object.fromEntries(entries), format);
    }

    return this.errorResponse(
      400,
      "Invalid URI format. Expected /rest/mempool/<info|contents>.json"
    );
  }

  // ========== Chain Info Endpoint ==========

  /**
   * GET /rest/chaininfo.json
   */
  private async handleChainInfo(pathParam: string): Promise<Response> {
    const { format } = this.parseFormat(pathParam);

    if (format !== "json") {
      return this.errorResponse(404, "output format not found (available: json)");
    }

    const bestBlock = this.chainState.getBestBlock();
    const bestHeader = this.headerSync.getBestHeader();

    const json = {
      chain: this.getChainName(),
      blocks: bestBlock.height,
      headers: bestHeader?.height ?? bestBlock.height,
      bestblockhash: Buffer.from(bestBlock.hash).reverse().toString("hex"),
      difficulty: await this.getDifficulty(bestBlock.hash),
      mediantime: 0, // Would need MTP calculation
      verificationprogress:
        bestHeader && bestHeader.height > 0
          ? bestBlock.height / bestHeader.height
          : 1.0,
      chainwork: bestBlock.chainWork.toString(16).padStart(64, "0"),
      pruned: false,
      softforks: {},
      warnings: "",
    };

    return this.formatResponse(json, format);
  }

  // ========== Helper Methods ==========

  /**
   * Parse a block hash from hex string.
   */
  private parseBlockHash(hashStr: string): Buffer | null {
    if (!/^[0-9a-fA-F]{64}$/.test(hashStr)) {
      return null;
    }
    return Buffer.from(hashStr, "hex");
  }

  /**
   * Parse a txid from hex string.
   */
  private parseTxid(txidStr: string): Buffer | null {
    if (!/^[0-9a-fA-F]{64}$/.test(txidStr)) {
      return null;
    }
    return Buffer.from(txidStr, "hex");
  }

  /**
   * Calculate difficulty from compact bits.
   */
  private calculateDifficultyFromBits(bits: number): number {
    const exponent = bits >>> 24;
    const mantissa = bits & 0x7fffff;

    // Genesis difficulty calculation
    const genesisBits = 0x1d00ffff;
    const genesisExp = genesisBits >>> 24;
    const genesisMantissa = genesisBits & 0x7fffff;

    if (mantissa === 0 || exponent > genesisExp) {
      return 1;
    }

    const target = Number(mantissa) * Math.pow(256, exponent - 3);
    const genesisTarget = Number(genesisMantissa) * Math.pow(256, genesisExp - 3);

    return genesisTarget / target;
  }

  /**
   * Get chain name based on network magic.
   */
  private getChainName(): string {
    switch (this.params.networkMagic) {
      case 0xd9b4bef9:
        return "main";
      case 0x0709110b:
        return "test";
      case 0xdab5bffa:
        return "regtest";
      case 0x1c163f28:
        return "testnet4";
      default:
        return "unknown";
    }
  }

  /**
   * Get current difficulty.
   */
  private async getDifficulty(blockHash: Buffer): Promise<number> {
    const blockIndex = await this.db.getBlockIndex(blockHash);
    if (!blockIndex) return 1;

    const bits = blockIndex.header.readUInt32LE(72);
    return this.calculateDifficultyFromBits(bits);
  }
}
