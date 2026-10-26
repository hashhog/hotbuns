/**
 * A wallet send that was broadcast (commitUnconfirmedSpend drops its inputs)
 * must still be recorded as a debit when the confirming block connects, or
 * listtransactions has no "send" entry and the change shows up as a receive.
 */
import { describe, expect, test, beforeEach, afterEach } from "bun:test";
import { rmSync, mkdirSync } from "fs";
import { Wallet } from "./wallet";
import { AddressType } from "../address/encoding";

const DIR = "/tmp/hotbuns-pending-spend-history-test";
const MNEMONIC =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

describe("wallet history after commitUnconfirmedSpend", () => {
  beforeEach(() => mkdirSync(DIR, { recursive: true }));
  afterEach(() => rmSync(DIR, { recursive: true, force: true }));

  test("confirming block records a send (isFromMe, fee) for a broadcast spend", () => {
    const wallet = Wallet.create({ datadir: DIR, network: "regtest" }, MNEMONIC);
    const address = wallet.getNewAddress();
    const prev = Buffer.alloc(32, 7);
    wallet.addUTXO({
      outpoint: { txid: prev, vout: 0 },
      amount: 100000000n,
      address,
      keyPath: "m/84'/0'/0'/0/0",
      confirmations: 6,
      addressType: AddressType.P2WPKH,
      isCoinbase: false,
    });

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
      outputs: [
        { value: 99999000n, scriptPubKey: Buffer.from([0x00, 0x14, ...Buffer.alloc(20, 9)]) },
      ],
      lockTime: 0,
    };
    // Broadcast: the RPC layer drops the inputs before any block exists.
    wallet.commitUnconfirmedSpend(tx as any);
    expect(wallet.getUTXOs().length).toBe(0);

    const block = {
      header: {
        version: 1,
        prevBlock: Buffer.alloc(32, 0),
        merkleRoot: Buffer.alloc(32, 0),
        timestamp: Math.floor(Date.now() / 1000),
        bits: 0x1d00ffff,
        nonce: 0,
      },
      transactions: [tx],
    };
    wallet.processBlock(block as any, 101);

    const recs = wallet.getTxHistory();
    expect(recs.length).toBe(1);
    expect(recs[0].isFromMe).toBe(true);
    expect(recs[0].debit).toBe(100000000n);
    expect(recs[0].fee).toBe(1000n);
    expect(recs[0].details.some((d) => d.category === "send")).toBe(true);
  });
});
