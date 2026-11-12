/**
 * gettransaction/listtransactions details for a debiting tx (wallet cause D).
 *
 * Core CachedTxGetAmounts: when the wallet is debited, change outputs are
 * skipped, every other output is a "send" entry, and an output that pays the
 * wallet is also a "receive" entry. A send of 1 BTC to a second address of the
 * same wallet is therefore [send -1, receive +1] and the change is not listed.
 */
import { describe, expect, test, beforeEach, afterEach } from "bun:test";
import { rmSync, mkdirSync } from "fs";
import { Wallet } from "./wallet";
import { AddressType, decodeAddress } from "../address/encoding";

const DIR = "/tmp/hotbuns-self-send-details-test";
const MNEMONIC =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

function spk(address: string): Buffer {
  const d: any = decodeAddress(address);
  return Buffer.concat([Buffer.from([0x00, 0x14]), Buffer.from(d.hash ?? d.program ?? d.data)]);
}

function setup(): { wallet: Wallet; prev: Buffer } {
  const wallet = Wallet.create({ datadir: DIR, network: "regtest" }, MNEMONIC);
  const address = wallet.getNewAddress();
  const prev = Buffer.alloc(32, 7);
  wallet.addUTXO({
    outpoint: { txid: prev, vout: 0 },
    amount: 5000000000n,
    address,
    keyPath: "m/84'/0'/0'/0/0",
    confirmations: 6,
    addressType: AddressType.P2WPKH,
    isCoinbase: false,
  });
  return { wallet, prev };
}

function block(txs: any[]) {
  return {
    header: {
      version: 1,
      prevBlock: Buffer.alloc(32, 0),
      merkleRoot: Buffer.alloc(32, 0),
      timestamp: Math.floor(Date.now() / 1000),
      bits: 0x1d00ffff,
      nonce: 0,
    },
    transactions: txs,
  };
}

function mine(wallet: Wallet, prev: Buffer, outputs: { value: bigint; scriptPubKey: Buffer }[]) {
  const tx = {
    version: 2,
    inputs: [
      {
        prevOut: { txid: prev, vout: 0 },
        scriptSig: Buffer.alloc(0),
        sequence: 0xffffffff,
        witness: [Buffer.from([0x30]), Buffer.alloc(33, 0x02)],
      },
    ],
    outputs,
    lockTime: 0,
  };
  wallet.processBlock(block([tx]) as any, 101);
  return wallet.getTxHistory()[0];
}

describe("wallet tx details for a debiting transaction", () => {
  beforeEach(() => mkdirSync(DIR, { recursive: true }));
  afterEach(() => rmSync(DIR, { recursive: true, force: true }));

  test("send to a second own address lists send and receive, not the change", () => {
    const { wallet, prev } = setup();
    const second = wallet.getNewAddress();
    const change = wallet.getChangeAddress();
    const rec = mine(wallet, prev, [
      { value: 100000000n, scriptPubKey: spk(second) },
      { value: 4899999000n, scriptPubKey: spk(change) },
    ]);
    const view = rec.details.map((d) => [d.category, d.vout, d.amount]);
    expect(view).toEqual([
      ["send", 0, 100000000n],
      ["receive", 0, 100000000n],
    ]);
    // Bookkeeping that balances / coin selection use is untouched.
    expect(rec.credit).toBe(100000000n + 4899999000n);
    expect(rec.debit).toBe(5000000000n);
    expect(rec.fee).toBe(1000n);
    expect(wallet.getUTXOs().length).toBe(2);
  });

  test("control: payment to an external address lists only the send, change omitted", () => {
    const { wallet, prev } = setup();
    const change = wallet.getChangeAddress();
    const rec = mine(wallet, prev, [
      { value: 100000000n, scriptPubKey: Buffer.from([0x00, 0x14, ...Buffer.alloc(20, 9)]) },
      { value: 4899999000n, scriptPubKey: spk(change) },
    ]);
    expect(rec.details.map((d) => [d.category, d.vout])).toEqual([["send", 0]]);
    expect(wallet.getUTXOs().length).toBe(1);
  });

  test("control: an incoming payment to a wallet address is still a plain receive", () => {
    const { wallet } = setup();
    const addr = wallet.getNewAddress();
    const tx = {
      version: 2,
      inputs: [
        { prevOut: { txid: Buffer.alloc(32, 8), vout: 0 }, scriptSig: Buffer.alloc(0), sequence: 0xffffffff, witness: [] },
      ],
      outputs: [{ value: 100000000n, scriptPubKey: spk(addr) }],
      lockTime: 0,
    };
    wallet.processBlock(block([tx]) as any, 101);
    const rec = wallet.getTxHistory().find((r) => !r.isFromMe)!;
    expect(rec.details.map((d) => [d.category, d.vout])).toEqual([["receive", 0]]);
  });
});
