/**
 * FIX-65 — BIP-78 PayJoin receiver tests.
 *
 * Closes the receiver-side gates of W119 (BUG-1 P0-FEATURE):
 *   G1   POST /payjoin endpoint exists
 *   G4   Receiver parses Original PSBT base64 body
 *   G5   Receiver rejects unfinalized Original PSBT  (original-psbt-rejected)
 *   G18  TTL replay window (PendingPayJoinRequestsMap)
 *   G21  v != 1 → version-unsupported
 *   G23  Response Content-Type: text/plain
 *
 * Plus the 4 BIP-78 §G error strings:
 *   - unavailable             (no wallet / no UTXOs)
 *   - not-enough-money        (UTXO probe failed)
 *   - version-unsupported     (v != 1)
 *   - original-psbt-rejected  (any validation failure)
 *
 * Test plan:
 *   1. Build a wallet, fund it with a P2WPKH UTXO.
 *   2. Build an Original PSBT that pays a receiver address from a sender
 *      wallet (we manually craft a finalized P2WPKH tx to avoid sender
 *      infrastructure).
 *   3. POST to the running RPC server.
 *   4. Assert the response is a valid base64-encoded PSBT containing one
 *      MORE input than the Original.
 *
 * Reference: BIP-78 §F, https://github.com/bitcoin/bips/blob/master/bip-0078.mediawiki
 */

import { describe, it, expect, beforeAll, afterAll, beforeEach } from "bun:test";
import { mkdtempSync, rmSync } from "fs";
import * as os from "os";
import * as path from "path";

import { RPCServer, type RPCServerConfig, type RPCServerDeps } from "../rpc/server.js";
import { REGTEST } from "../consensus/params.js";
import { Wallet, type WalletConfig } from "../wallet/wallet.js";
import { AddressType, decodeAddress, encodeAddress } from "../address/encoding.js";
import {
  createPSBT,
  encodePSBTBase64,
  decodePSBTBase64,
  isInputFinalized,
} from "../wallet/psbt.js";
import type { Transaction, TxIn, TxOut } from "../validation/tx.js";
import {
  handlePayJoinRequest,
  parsePayJoinQuery,
  createPendingPayJoinRequestsMap,
  originalPsbtHashHex,
  PayJoinError,
  PAYJOIN_ERROR_UNAVAILABLE,
  PAYJOIN_ERROR_NOT_ENOUGH_MONEY,
  PAYJOIN_ERROR_VERSION_UNSUPPORTED,
  PAYJOIN_ERROR_ORIGINAL_PSBT_REJECTED,
} from "../payjoin/receiver.js";

// ---------------------------------------------------------------------------
// Mock dependencies, same shape as fix64_tls.test.ts so the RPCServer can
// boot. Only wallet + chain shape matter for PayJoin.
// ---------------------------------------------------------------------------

class MockChainStateManager {
  private bestBlock = { hash: Buffer.alloc(32, 0), height: 100, chainWork: 1000n };
  getBestBlock() { return { ...this.bestBlock }; }
}
class MockMempool {
  getInfo() { return { size: 0, bytes: 0, minFeeRate: 1 }; }
  getAllTxids(): Buffer[] { return []; }
  getTransaction(_txid: Buffer) { return null; }
  hasTransaction(_txid: Buffer) { return false; }
  async addTransaction(_tx: any) { return { accepted: true }; }
  removeTransaction(_txid: Buffer, _removeDependents = true): void {}
  async isTransactionConfirmed(_txid: Buffer): Promise<boolean> { return false; }
  isReplaceable(_txid: Buffer): boolean { return true; }
}
class MockPeerManager {
  getConnectedPeers() { return []; }
  broadcast(_msg: any) {}
  usingASMap(): boolean { return false; }
  getMappedAS(_addr: string): number { return 0; }
  getOutboundNetGroups(): Set<string> { return new Set(); }
}
class MockFeeEstimator {
  public buckets: any[] = [];
  estimateSmartFee(targetBlocks: number) { return { feeRate: 10, blocks: targetBlocks }; }
  getBuckets() { return this.buckets; }
  get horizons() {
    return {
      0: { decay: 0.962, scale: 1, periods: 12, buckets: [] },
      1: { decay: 0.9952, scale: 2, periods: 24, buckets: [] },
      2: { decay: 0.99931, scale: 24, periods: 42, buckets: [] },
    };
  }
}
class MockHeaderSync {
  getBestHeader() { return { hash: Buffer.alloc(32, 0), height: 100, chainWork: 1000n }; }
  getHeader(_h: Buffer) { return undefined; }
  getMedianTimePast(_e: any) { return 1234567890; }
  getNextTarget(_p: any) { return 0n; }
}
class MockChainDB {
  async getBlock(_h: Buffer) { return null; }
  async getBlockIndex(_h: Buffer) { return null; }
  async getBlockHashByHeight(_h: number) { return null; }
  async getChainWork(_h: Buffer): Promise<bigint | null> { return null; }
}

function makeDeps(wallet?: Wallet): RPCServerDeps {
  return {
    chainState: new MockChainStateManager() as any,
    mempool: new MockMempool() as any,
    peerManager: new MockPeerManager() as any,
    feeEstimator: new MockFeeEstimator() as any,
    headerSync: new MockHeaderSync() as any,
    db: new MockChainDB() as any,
    params: REGTEST,
    wallet,
  };
}

// Two distinct BIP-39 mnemonics for receiver + sender so neither wallet
// "knows" the other's UTXOs / keys.
const RECEIVER_MNEMONIC =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const SENDER_MNEMONIC =
  "legal winner thank year wave sausage worth useful legal winner thank yellow";

let tmpDir: string;
function makeReceiverWallet(): Wallet {
  const cfg: WalletConfig = { datadir: tmpDir, network: "regtest" };
  return Wallet.create(cfg, RECEIVER_MNEMONIC);
}
function makeSenderWallet(): Wallet {
  const cfg: WalletConfig = { datadir: tmpDir, network: "regtest" };
  return Wallet.create(cfg, SENDER_MNEMONIC);
}

// ---------------------------------------------------------------------------
// Build an Original PSBT (sender-side fixture).
//
// The simplest legal "finalized" PSBT is one where every input has both
// finalScriptSig and finalScriptWitness set (matching the post-FINALIZER
// state of the BIP-174 role sequence). We don't need real signatures to
// drive the receiver pipeline — what the receiver inspects is only:
//   - input.scriptSig + input.witness are non-empty (= finalized),
//   - one of the tx outputs pays the receiver's wallet.
// The receiver then PRESERVES those bytes verbatim and adds its own input.
// ---------------------------------------------------------------------------

function buildOriginalPsbt(opts: {
  senderUtxoTxid: Buffer;
  senderUtxoVout: number;
  receiverAddress: string;
  receiverAmountSat: bigint;
  senderChangeScriptPubKey: Buffer;
  senderChangeAmountSat: bigint;
  fakeSignature?: Buffer;
  fakePubkey?: Buffer;
}): { psbtBase64: string; psbtBytes: Buffer; tx: Transaction } {
  const decoded = decodeAddress(opts.receiverAddress);
  if (decoded.type !== AddressType.P2WPKH) {
    throw new Error("test fixture only supports P2WPKH receiver");
  }
  // OP_0 <20-byte hash> for P2WPKH.
  const receiverSpk = Buffer.concat([
    Buffer.from([0x00, 0x14]),
    decoded.hash,
  ]);

  const txInputs: TxIn[] = [
    {
      prevOut: { txid: opts.senderUtxoTxid, vout: opts.senderUtxoVout },
      scriptSig: Buffer.alloc(0),
      sequence: 0xfffffffd, // BIP-125 RBF
      witness: [],
    },
  ];
  const txOutputs: TxOut[] = [
    { value: opts.receiverAmountSat, scriptPubKey: receiverSpk },
    { value: opts.senderChangeAmountSat, scriptPubKey: opts.senderChangeScriptPubKey },
  ];
  const tx: Transaction = {
    version: 2,
    inputs: txInputs,
    outputs: txOutputs,
    lockTime: 0,
  };

  const psbt = createPSBT(tx);
  // "Finalize" the input with a synthetic witness/scriptSig. The receiver
  // doesn't verify these — it only checks they're present.
  const sig = opts.fakeSignature ?? Buffer.alloc(72, 0x30); // any non-empty buffer
  const pubkey = opts.fakePubkey ?? Buffer.alloc(33, 0x02);
  psbt.inputs[0].finalScriptWitness = [sig, pubkey];
  psbt.inputs[0].finalScriptSig = Buffer.alloc(0);
  // Also stash the witness UTXO so receiver-side validation has the value.
  psbt.inputs[0].witnessUtxo = {
    value: opts.receiverAmountSat + opts.senderChangeAmountSat + 1000n, // input > outputs
    scriptPubKey: Buffer.from([0x00, 0x14, ...Buffer.alloc(20, 0x05)]),
  };

  // The receiver code path operates over the parsed psbt structure with
  // input.finalScriptWitness/finalScriptSig — we expose the base64 form
  // and the in-memory tx for assertions.
  const base64 = encodePSBTBase64(psbt);
  return {
    psbtBase64: base64,
    psbtBytes: Buffer.from(base64, "base64"),
    tx,
  };
}

// Each test gets its own port to avoid collisions when the runner
// parallelizes.
let portCounter = 38443;
function getTestPort(): number { return portCounter++; }

// ---------------------------------------------------------------------------
// Test suites.
// ---------------------------------------------------------------------------

describe("BIP-78 PayJoin receiver (FIX-65)", () => {
  beforeAll(() => {
    tmpDir = mkdtempSync(path.join(os.tmpdir(), "hotbuns-fix65-"));
  });
  afterAll(() => {
    try { rmSync(tmpDir, { recursive: true, force: true }); } catch {}
  });

  // -------------------------------------------------------------------
  // Direct receiver-pipeline tests (no Bun.serve).
  // -------------------------------------------------------------------

  describe("handlePayJoinRequest (pipeline)", () => {
    let receiver: Wallet;
    let recvAddress: string;

    beforeEach(() => {
      receiver = makeReceiverWallet();
      recvAddress = receiver.getNewAddress();

      // Fund the receiver wallet with a confirmed P2WPKH UTXO.
      // The address from getNewAddress() is what we just generated; add a
      // UTXO at that address so coin-selection can pick it.
      const utxoAddr = receiver.getNewAddress(); // second receive addr
      receiver.addUTXO({
        outpoint: { txid: Buffer.alloc(32, 0x07), vout: 0 },
        amount: 50_000n,
        address: utxoAddr,
        keyPath: "m/84'/1'/0'/0/1",
        confirmations: 10,
        addressType: AddressType.P2WPKH,
        isCoinbase: false,
      });
    });

    it("round-trip: receiver adds input, returns valid PSBT", async () => {
      const { psbtBase64 } = buildOriginalPsbt({
        senderUtxoTxid: Buffer.alloc(32, 0x11),
        senderUtxoVout: 0,
        receiverAddress: recvAddress,
        receiverAmountSat: 100_000n,
        senderChangeScriptPubKey: Buffer.from([0x00, 0x14, ...Buffer.alloc(20, 0x99)]),
        senderChangeAmountSat: 99_000n,
      });

      const pending = createPendingPayJoinRequestsMap();
      const result = await handlePayJoinRequest(
        psbtBase64,
        { v: 1 },
        { wallet: receiver, pending }
      );

      // Re-parse the response and assert the receiver added exactly one
      // input + bumped the receiver's output value.
      const reparsed = decodePSBTBase64(result.base64Psbt);
      expect(reparsed.tx.inputs.length).toBe(2);
      // Sender's original input is still finalized.
      expect(isInputFinalized(reparsed.inputs[0])).toBe(true);
      // Receiver-added input is also finalized (we sign in-place).
      expect(isInputFinalized(reparsed.inputs[1])).toBe(true);
      // Receiver's output increased by the UTXO amount.
      const receiverOutput = reparsed.tx.outputs[0];
      expect(receiverOutput.value).toBe(100_000n + 50_000n);

      // Pending map registered the hash.
      expect(pending.has(result.originalPsbtHash)).toBe(true);
    });

    it("G4: receiver rejects garbage body (original-psbt-rejected)", async () => {
      const pending = createPendingPayJoinRequestsMap();
      let caught: unknown;
      try {
        await handlePayJoinRequest("this-is-not-base64-psbt", { v: 1 }, {
          wallet: receiver,
          pending,
        });
      } catch (err) {
        caught = err;
      }
      expect(caught).toBeInstanceOf(PayJoinError);
      expect((caught as PayJoinError).errorCode).toBe(
        PAYJOIN_ERROR_ORIGINAL_PSBT_REJECTED
      );
    });

    it("G5: unfinalized Original PSBT → original-psbt-rejected", async () => {
      // Build a PSBT that is NOT finalized (omit finalScriptWitness).
      const decoded = decodeAddress(recvAddress);
      const recvSpk = Buffer.concat([Buffer.from([0x00, 0x14]), decoded.hash]);

      const tx: Transaction = {
        version: 2,
        inputs: [
          {
            prevOut: { txid: Buffer.alloc(32, 0x12), vout: 0 },
            scriptSig: Buffer.alloc(0),
            sequence: 0xfffffffd,
            witness: [],
          },
        ],
        outputs: [{ value: 100_000n, scriptPubKey: recvSpk }],
        lockTime: 0,
      };
      const psbt = createPSBT(tx);
      // Intentionally NO finalScriptWitness / finalScriptSig assignment.
      const body = encodePSBTBase64(psbt);

      const pending = createPendingPayJoinRequestsMap();
      let caught: unknown;
      try {
        await handlePayJoinRequest(body, { v: 1 }, { wallet: receiver, pending });
      } catch (err) {
        caught = err;
      }
      expect(caught).toBeInstanceOf(PayJoinError);
      expect((caught as PayJoinError).errorCode).toBe(
        PAYJOIN_ERROR_ORIGINAL_PSBT_REJECTED
      );
      expect((caught as PayJoinError).message).toMatch(/not finalized/i);
    });

    it("Original PSBT that doesn't pay receiver → original-psbt-rejected", async () => {
      // Build a PSBT that pays a totally unrelated address.
      const unrelatedSpk = Buffer.from([0x00, 0x14, ...Buffer.alloc(20, 0xaa)]);
      const tx: Transaction = {
        version: 2,
        inputs: [
          {
            prevOut: { txid: Buffer.alloc(32, 0x13), vout: 0 },
            scriptSig: Buffer.alloc(0),
            sequence: 0xfffffffd,
            witness: [],
          },
        ],
        outputs: [{ value: 100_000n, scriptPubKey: unrelatedSpk }],
        lockTime: 0,
      };
      const psbt = createPSBT(tx);
      psbt.inputs[0].finalScriptWitness = [Buffer.alloc(72, 0x30), Buffer.alloc(33, 0x02)];
      psbt.inputs[0].finalScriptSig = Buffer.alloc(0);

      const pending = createPendingPayJoinRequestsMap();
      let caught: unknown;
      try {
        await handlePayJoinRequest(encodePSBTBase64(psbt), { v: 1 }, {
          wallet: receiver,
          pending,
        });
      } catch (err) {
        caught = err;
      }
      expect(caught).toBeInstanceOf(PayJoinError);
      expect((caught as PayJoinError).errorCode).toBe(
        PAYJOIN_ERROR_ORIGINAL_PSBT_REJECTED
      );
      expect((caught as PayJoinError).message).toMatch(/does not pay/i);
    });

    it("not-enough-money: empty wallet → not-enough-money", async () => {
      // Build a fresh wallet WITH the receive address but without any
      // funded UTXOs.
      const emptyReceiver = makeReceiverWallet();
      // Use the SAME receive address as the funded wallet: the receiver-
      // ownership check still passes (BIP-32 mnemonic is identical), but
      // there are no UTXOs to spend.
      const emptyAddr = emptyReceiver.getNewAddress();
      expect(emptyAddr).toBe(recvAddress);

      const { psbtBase64 } = buildOriginalPsbt({
        senderUtxoTxid: Buffer.alloc(32, 0x14),
        senderUtxoVout: 0,
        receiverAddress: emptyAddr,
        receiverAmountSat: 100_000n,
        senderChangeScriptPubKey: Buffer.from([0x00, 0x14, ...Buffer.alloc(20, 0x99)]),
        senderChangeAmountSat: 99_000n,
      });

      const pending = createPendingPayJoinRequestsMap();
      let caught: unknown;
      try {
        await handlePayJoinRequest(psbtBase64, { v: 1 }, {
          wallet: emptyReceiver,
          pending,
        });
      } catch (err) {
        caught = err;
      }
      expect(caught).toBeInstanceOf(PayJoinError);
      expect((caught as PayJoinError).errorCode).toBe(
        PAYJOIN_ERROR_NOT_ENOUGH_MONEY
      );
    });

    // -------------------------------------------------------------------
    // G18 / G30 replay window (PendingPayJoinRequestsMap).
    // -------------------------------------------------------------------

    it("G18 + G30: second POST of same Original PSBT within TTL → original-psbt-rejected", async () => {
      const { psbtBase64 } = buildOriginalPsbt({
        senderUtxoTxid: Buffer.alloc(32, 0x15),
        senderUtxoVout: 0,
        receiverAddress: recvAddress,
        receiverAmountSat: 100_000n,
        senderChangeScriptPubKey: Buffer.from([0x00, 0x14, ...Buffer.alloc(20, 0x99)]),
        senderChangeAmountSat: 99_000n,
      });

      const pending = createPendingPayJoinRequestsMap();
      // First call succeeds.
      const r1 = await handlePayJoinRequest(psbtBase64, { v: 1 }, {
        wallet: receiver,
        pending,
        now: () => 1_000_000,
      });
      expect(r1.base64Psbt.length).toBeGreaterThan(0);

      // Re-fund the wallet so the second attempt's "not-enough-money"
      // doesn't mask the replay rejection. The earlier successful call
      // already consumed the test UTXO logically (we don't simulate that
      // here — selectCoins() returns from the same available pool); we
      // only need to ensure the test signal is "replay" not "no money".
      receiver.addUTXO({
        outpoint: { txid: Buffer.alloc(32, 0xb1), vout: 0 },
        amount: 70_000n,
        address: recvAddress,
        keyPath: "m/84'/1'/0'/0/0",
        confirmations: 10,
        addressType: AddressType.P2WPKH,
        isCoinbase: false,
      });

      // Second call within the TTL window MUST reject.
      let caught: unknown;
      try {
        await handlePayJoinRequest(psbtBase64, { v: 1 }, {
          wallet: receiver,
          pending,
          now: () => 1_000_500, // 500ms later
        });
      } catch (err) {
        caught = err;
      }
      expect(caught).toBeInstanceOf(PayJoinError);
      expect((caught as PayJoinError).errorCode).toBe(
        PAYJOIN_ERROR_ORIGINAL_PSBT_REJECTED
      );
      expect((caught as PayJoinError).message).toMatch(/already submitted/i);
    });

    it("pending map: TTL expiry allows resubmission", async () => {
      const { psbtBase64 } = buildOriginalPsbt({
        senderUtxoTxid: Buffer.alloc(32, 0x16),
        senderUtxoVout: 0,
        receiverAddress: recvAddress,
        receiverAmountSat: 100_000n,
        senderChangeScriptPubKey: Buffer.from([0x00, 0x14, ...Buffer.alloc(20, 0x99)]),
        senderChangeAmountSat: 99_000n,
      });

      const pending = createPendingPayJoinRequestsMap();
      const ttlMs = 1000;
      await handlePayJoinRequest(psbtBase64, { v: 1 }, {
        wallet: receiver,
        pending,
        now: () => 1_000_000,
        ttlMs,
      });
      expect(pending.size).toBe(1);

      // Add fresh UTXO for the post-expiry attempt.
      receiver.addUTXO({
        outpoint: { txid: Buffer.alloc(32, 0xb2), vout: 0 },
        amount: 80_000n,
        address: recvAddress,
        keyPath: "m/84'/1'/0'/0/0",
        confirmations: 10,
        addressType: AddressType.P2WPKH,
        isCoinbase: false,
      });

      // After TTL: the same PSBT should be accepted again. The opportunistic
      // prune runs at the top of handlePayJoinRequest and removes the
      // expired entry.
      const r2 = await handlePayJoinRequest(psbtBase64, { v: 1 }, {
        wallet: receiver,
        pending,
        now: () => 1_000_000 + ttlMs + 1,
        ttlMs,
      });
      expect(r2.base64Psbt.length).toBeGreaterThan(0);
    });

    // -------------------------------------------------------------------
    // originalPsbtHashHex hashing helper.
    // -------------------------------------------------------------------

    it("hashes the Original PSBT canonically (sha256 of bytes)", () => {
      const bytes = Buffer.from([0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04]);
      const h1 = originalPsbtHashHex(bytes);
      const h2 = originalPsbtHashHex(Buffer.from(bytes)); // independent copy
      expect(h1).toBe(h2);
      expect(h1.length).toBe(64); // hex of 32-byte sha256
    });
  });

  // -------------------------------------------------------------------
  // parsePayJoinQuery — BIP-78 §D / §G version handling.
  // -------------------------------------------------------------------

  describe("parsePayJoinQuery", () => {
    it("v=1 parses", () => {
      const q = parsePayJoinQuery(new URLSearchParams("v=1"));
      expect(q.v).toBe(1);
    });

    it("v=2 → version-unsupported", () => {
      let caught: unknown;
      try { parsePayJoinQuery(new URLSearchParams("v=2")); } catch (e) { caught = e; }
      expect(caught).toBeInstanceOf(PayJoinError);
      expect((caught as PayJoinError).errorCode).toBe(
        PAYJOIN_ERROR_VERSION_UNSUPPORTED
      );
    });

    it("v=1.0 (decimal) → version-unsupported (strict integer)", () => {
      let caught: unknown;
      try { parsePayJoinQuery(new URLSearchParams("v=1.0")); } catch (e) { caught = e; }
      expect(caught).toBeInstanceOf(PayJoinError);
      expect((caught as PayJoinError).errorCode).toBe(
        PAYJOIN_ERROR_VERSION_UNSUPPORTED
      );
    });

    it("missing v → original-psbt-rejected", () => {
      let caught: unknown;
      try { parsePayJoinQuery(new URLSearchParams("")); } catch (e) { caught = e; }
      expect(caught).toBeInstanceOf(PayJoinError);
      expect((caught as PayJoinError).errorCode).toBe(
        PAYJOIN_ERROR_ORIGINAL_PSBT_REJECTED
      );
    });

    it("recognized params parse (case-insensitive)", () => {
      const q = parsePayJoinQuery(new URLSearchParams(
        "V=1&additionalfeeoutputindex=2&MaxAdditionalFeeContribution=1234&disableoutputsubstitution=true&minfeerate=2.5"
      ));
      expect(q.v).toBe(1);
      expect(q.additionalFeeOutputIndex).toBe(2);
      expect(q.maxAdditionalFeeContribution).toBe(1234n);
      expect(q.disableOutputSubstitution).toBe(true);
      expect(q.minFeeRate).toBe(2.5);
    });

    it("garbage minfeerate → original-psbt-rejected", () => {
      let caught: unknown;
      try {
        parsePayJoinQuery(new URLSearchParams("v=1&minfeerate=banana"));
      } catch (e) { caught = e; }
      expect(caught).toBeInstanceOf(PayJoinError);
      expect((caught as PayJoinError).errorCode).toBe(
        PAYJOIN_ERROR_ORIGINAL_PSBT_REJECTED
      );
    });
  });

  // -------------------------------------------------------------------
  // HTTP integration — POST /payjoin on the live Bun.serve.
  // -------------------------------------------------------------------

  describe("POST /payjoin (HTTP integration)", () => {
    let receiver: Wallet;
    let recvAddress: string;

    beforeEach(() => {
      receiver = makeReceiverWallet();
      recvAddress = receiver.getNewAddress();
      // Second address gets the UTXO so we don't accidentally pick the
      // payment-receiving address.
      const utxoAddr = receiver.getNewAddress();
      receiver.addUTXO({
        outpoint: { txid: Buffer.alloc(32, 0x21), vout: 0 },
        amount: 50_000n,
        address: utxoAddr,
        keyPath: "m/84'/1'/0'/0/1",
        confirmations: 10,
        addressType: AddressType.P2WPKH,
        isCoinbase: false,
      });
    });

    it("G1 + G23: POST /payjoin?v=1 round-trips with text/plain body", async () => {
      const port = getTestPort();
      const config: RPCServerConfig = {
        port, host: "127.0.0.1", noAuth: true,
      };
      const server = new RPCServer(config, makeDeps(receiver));
      server.start();
      try {
        const { psbtBase64 } = buildOriginalPsbt({
          senderUtxoTxid: Buffer.alloc(32, 0x22),
          senderUtxoVout: 0,
          receiverAddress: recvAddress,
          receiverAmountSat: 100_000n,
          senderChangeScriptPubKey: Buffer.from([0x00, 0x14, ...Buffer.alloc(20, 0x99)]),
          senderChangeAmountSat: 99_000n,
        });
        const response = await fetch(`http://127.0.0.1:${port}/payjoin?v=1`, {
          method: "POST",
          headers: { "Content-Type": "text/plain" },
          body: psbtBase64,
        });
        expect(response.status).toBe(200);
        expect(response.headers.get("Content-Type")).toBe("text/plain");
        const body = await response.text();
        expect(body.length).toBeGreaterThan(0);
        // The body MUST be a parseable base64 PSBT with one more input.
        const reparsed = decodePSBTBase64(body);
        expect(reparsed.tx.inputs.length).toBe(2);
      } finally {
        server.stop();
      }
    });

    it("G21: POST /payjoin?v=2 → 400 with version-unsupported", async () => {
      const port = getTestPort();
      const config: RPCServerConfig = {
        port, host: "127.0.0.1", noAuth: true,
      };
      const server = new RPCServer(config, makeDeps(receiver));
      server.start();
      try {
        const { psbtBase64 } = buildOriginalPsbt({
          senderUtxoTxid: Buffer.alloc(32, 0x23),
          senderUtxoVout: 0,
          receiverAddress: recvAddress,
          receiverAmountSat: 100_000n,
          senderChangeScriptPubKey: Buffer.from([0x00, 0x14, ...Buffer.alloc(20, 0x99)]),
          senderChangeAmountSat: 99_000n,
        });
        const response = await fetch(`http://127.0.0.1:${port}/payjoin?v=2`, {
          method: "POST",
          headers: { "Content-Type": "text/plain" },
          body: psbtBase64,
        });
        expect(response.status).toBe(400);
        const json = await response.json() as { errorCode: string; message: string };
        expect(json.errorCode).toBe(PAYJOIN_ERROR_VERSION_UNSUPPORTED);
      } finally {
        server.stop();
      }
    });

    it("BIP-78 §G: empty body → original-psbt-rejected JSON", async () => {
      const port = getTestPort();
      const config: RPCServerConfig = {
        port, host: "127.0.0.1", noAuth: true,
      };
      const server = new RPCServer(config, makeDeps(receiver));
      server.start();
      try {
        const response = await fetch(`http://127.0.0.1:${port}/payjoin?v=1`, {
          method: "POST",
          headers: { "Content-Type": "text/plain" },
          body: "",
        });
        expect(response.status).toBe(400);
        const json = await response.json() as { errorCode: string };
        expect(json.errorCode).toBe(PAYJOIN_ERROR_ORIGINAL_PSBT_REJECTED);
      } finally {
        server.stop();
      }
    });

    it("BIP-78 §G: no wallet wired → unavailable", async () => {
      const port = getTestPort();
      const config: RPCServerConfig = {
        port, host: "127.0.0.1", noAuth: true,
      };
      // makeDeps() without the wallet arg.
      const server = new RPCServer(config, makeDeps(undefined));
      server.start();
      try {
        const response = await fetch(`http://127.0.0.1:${port}/payjoin?v=1`, {
          method: "POST",
          headers: { "Content-Type": "text/plain" },
          body: "AA==", // any non-empty body
        });
        expect(response.status).toBe(400);
        const json = await response.json() as { errorCode: string };
        expect(json.errorCode).toBe(PAYJOIN_ERROR_UNAVAILABLE);
      } finally {
        server.stop();
      }
    });

    it("non-POST to /payjoin → 405 method-not-allowed", async () => {
      const port = getTestPort();
      const config: RPCServerConfig = {
        port, host: "127.0.0.1", noAuth: true,
      };
      const server = new RPCServer(config, makeDeps(receiver));
      server.start();
      try {
        const response = await fetch(`http://127.0.0.1:${port}/payjoin?v=1`, {
          method: "GET",
        });
        expect(response.status).toBe(405);
      } finally {
        server.stop();
      }
    });
  });

  // -------------------------------------------------------------------
  // W119 audit-flip assertions (BUG-1 / G1, G4, G5, G18, G21, G23).
  // -------------------------------------------------------------------
  //
  // The audit file (src/__tests__/w119_payjoin.test.ts) records these
  // receiver-side gates as test.skip with `expect(true).toBe(false)`. We
  // don't edit that file (audit history stays intact) — instead we re-
  // prove the inverse here so the receiver gates are machine-checkable.
  describe("W119 receiver-side audit flips", () => {
    it("BUG-1 receiver module exists at src/payjoin/receiver.ts", async () => {
      const mod = await import("../payjoin/receiver.js");
      expect(typeof mod.handlePayJoinRequest).toBe("function");
      expect(typeof mod.parsePayJoinQuery).toBe("function");
      expect(typeof mod.createPendingPayJoinRequestsMap).toBe("function");
    });

    it("BUG-1 four BIP-78 §G error codes are exported", async () => {
      const mod = await import("../payjoin/receiver.js");
      expect(mod.PAYJOIN_ERROR_UNAVAILABLE).toBe("unavailable");
      expect(mod.PAYJOIN_ERROR_NOT_ENOUGH_MONEY).toBe("not-enough-money");
      expect(mod.PAYJOIN_ERROR_VERSION_UNSUPPORTED).toBe("version-unsupported");
      expect(mod.PAYJOIN_ERROR_ORIGINAL_PSBT_REJECTED).toBe("original-psbt-rejected");
    });
  });
});
