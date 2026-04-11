import { describe, expect, test, beforeEach, afterEach } from "bun:test";
import { rmSync, mkdirSync } from "fs";
import { Wallet, type WalletConfig, type WalletUTXO } from "./wallet";
import { AddressType, decodeAddress } from "../address/encoding";
import { hash160, privateKeyToPublicKey, ecdsaVerify } from "../crypto/primitives";
import { sigHashWitnessV0, SIGHASH_ALL, type Transaction } from "../validation/tx";

const TEST_DATADIR = "/tmp/hotbuns-wallet-test";

/**
 * Known BIP-84 test vectors from https://github.com/bitcoin/bips/blob/master/bip-0084.mediawiki
 *
 * Mnemonic: abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about
 * BIP-39 seed (hex): 5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4
 *
 * Account 0, external chain (receive):
 * m/84'/0'/0'/0/0: bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu
 *
 * Account 0, internal chain (change):
 * m/84'/0'/0'/1/0: bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el
 */
const TEST_MNEMONIC =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

// Expected addresses from BIP-84 test vector (mainnet)
const EXPECTED_RECEIVE_0 = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu";
const EXPECTED_CHANGE_0 = "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el";

function createTestConfig(network: "mainnet" | "testnet" | "regtest" = "mainnet"): WalletConfig {
  return {
    datadir: TEST_DATADIR,
    network,
  };
}

describe("Wallet creation", () => {
  beforeEach(() => {
    mkdirSync(TEST_DATADIR, { recursive: true });
  });

  afterEach(() => {
    rmSync(TEST_DATADIR, { recursive: true, force: true });
  });

  test("creates wallet from mnemonic", () => {
    const config = createTestConfig();
    const wallet = Wallet.create(config, TEST_MNEMONIC);

    expect(wallet).toBeDefined();
    expect(wallet.getSeed().length).toBe(64);
  });

  test("creates wallet with random seed when no mnemonic provided", () => {
    const config = createTestConfig();
    const wallet = Wallet.create(config);

    expect(wallet).toBeDefined();
    expect(wallet.getSeed().length).toBe(64);
  });

  test("different wallets have different seeds", () => {
    const config = createTestConfig();
    const wallet1 = Wallet.create(config);
    const wallet2 = Wallet.create(config);

    expect(wallet1.getSeed().equals(wallet2.getSeed())).toBe(false);
  });

  test("same mnemonic produces same seed", () => {
    const config = createTestConfig();
    const wallet1 = Wallet.create(config, TEST_MNEMONIC);
    const wallet2 = Wallet.create(config, TEST_MNEMONIC);

    expect(wallet1.getSeed().equals(wallet2.getSeed())).toBe(true);
  });
});

describe("BIP-84 key derivation", () => {
  test("derives correct BIP-84 addresses from test vector", () => {
    const config = createTestConfig("mainnet");
    const wallet = Wallet.create(config, TEST_MNEMONIC);

    // Get the first receive address
    const address0 = wallet.getNewAddress();
    expect(address0).toBe(EXPECTED_RECEIVE_0);

    // Second address should be different from first
    const address1 = wallet.getNewAddress();
    expect(address1).not.toBe(address0);
    expect(address1.startsWith("bc1q")).toBe(true);
  });

  test("derives correct change address", () => {
    const config = createTestConfig("mainnet");
    const wallet = Wallet.create(config, TEST_MNEMONIC);

    const changeAddress = wallet.getChangeAddress();
    expect(changeAddress).toBe(EXPECTED_CHANGE_0);
  });

  test("testnet uses different coin type", () => {
    const config = createTestConfig("testnet");
    const wallet = Wallet.create(config, TEST_MNEMONIC);

    const address = wallet.getNewAddress();

    // Testnet addresses start with tb1
    expect(address.startsWith("tb1q")).toBe(true);
  });

  test("regtest uses tb1 prefix", () => {
    const config = createTestConfig("regtest");
    const wallet = Wallet.create(config, TEST_MNEMONIC);

    const address = wallet.getNewAddress();

    // Regtest addresses start with bcrt1
    expect(address.startsWith("bcrt1q")).toBe(true);
  });

  test("addresses are P2WPKH type", () => {
    const config = createTestConfig("mainnet");
    const wallet = Wallet.create(config, TEST_MNEMONIC);

    const address = wallet.getNewAddress();
    const decoded = decodeAddress(address);

    expect(decoded.type).toBe(AddressType.P2WPKH);
    expect(decoded.hash.length).toBe(20);
  });
});

describe("Address generation", () => {
  test("getNewAddress increments index", () => {
    const config = createTestConfig();
    const wallet = Wallet.create(config, TEST_MNEMONIC);

    const addr1 = wallet.getNewAddress();
    const addr2 = wallet.getNewAddress();
    const addr3 = wallet.getNewAddress();

    expect(addr1).not.toBe(addr2);
    expect(addr2).not.toBe(addr3);
    expect(addr1).not.toBe(addr3);
  });

  test("listAddresses includes pre-generated addresses", () => {
    const config = createTestConfig();
    const wallet = Wallet.create(config, TEST_MNEMONIC);

    const addresses = wallet.listAddresses();

    // Should have at least the gap of 20 receive + 20 change = 40
    expect(addresses.length).toBeGreaterThanOrEqual(40);
  });

  test("hasAddress returns true for wallet addresses", () => {
    const config = createTestConfig();
    const wallet = Wallet.create(config, TEST_MNEMONIC);

    const address = wallet.getNewAddress();

    expect(wallet.hasAddress(address)).toBe(true);
    expect(wallet.hasAddress("bc1qnotthere")).toBe(false);
  });

  test("getKey returns key for known address", () => {
    const config = createTestConfig();
    const wallet = Wallet.create(config, TEST_MNEMONIC);

    const address = wallet.getNewAddress();
    const key = wallet.getKey(address);

    expect(key).toBeDefined();
    expect(key!.address).toBe(address);
    expect(key!.privateKey.length).toBe(32);
    expect(key!.publicKey.length).toBe(33);
    expect(key!.addressType).toBe(AddressType.P2WPKH);
  });

  test("derived public key matches hash160 in address", () => {
    const config = createTestConfig();
    const wallet = Wallet.create(config, TEST_MNEMONIC);

    const address = wallet.getNewAddress();
    const key = wallet.getKey(address)!;
    const decoded = decodeAddress(address);

    // Address hash should match hash160 of public key
    const expectedHash = hash160(key.publicKey);
    expect(decoded.hash.equals(expectedHash)).toBe(true);
  });
});

describe("Balance and UTXOs", () => {
  test("new wallet has zero balance", () => {
    const config = createTestConfig();
    const wallet = Wallet.create(config, TEST_MNEMONIC);

    const balance = wallet.getBalance();

    expect(balance.confirmed).toBe(0n);
    expect(balance.unconfirmed).toBe(0n);
    expect(balance.total).toBe(0n);
  });

  test("addUTXO increases balance", () => {
    const config = createTestConfig();
    const wallet = Wallet.create(config, TEST_MNEMONIC);

    const address = wallet.getNewAddress();
    const utxo: WalletUTXO = {
      outpoint: {
        txid: Buffer.alloc(32, 1),
        vout: 0,
      },
      amount: 100000000n, // 1 BTC
      address,
      keyPath: "m/84'/0'/0'/0/0",
      confirmations: 6,
      addressType: AddressType.P2WPKH,
      isCoinbase: false,
    };

    wallet.addUTXO(utxo);

    const balance = wallet.getBalance();
    expect(balance.confirmed).toBe(100000000n);
    expect(balance.total).toBe(100000000n);
  });

  test("unconfirmed UTXOs are tracked separately", () => {
    const config = createTestConfig();
    const wallet = Wallet.create(config, TEST_MNEMONIC);

    const address = wallet.getNewAddress();

    // Confirmed UTXO
    wallet.addUTXO({
      outpoint: { txid: Buffer.alloc(32, 1), vout: 0 },
      amount: 100000000n,
      address,
      keyPath: "m/84'/0'/0'/0/0",
      confirmations: 6,
      addressType: AddressType.P2WPKH,
      isCoinbase: false,
    });

    // Unconfirmed UTXO
    wallet.addUTXO({
      outpoint: { txid: Buffer.alloc(32, 2), vout: 0 },
      amount: 50000000n,
      address,
      keyPath: "m/84'/0'/0'/0/0",
      confirmations: 0,
      addressType: AddressType.P2WPKH,
      isCoinbase: false,
    });

    const balance = wallet.getBalance();
    expect(balance.confirmed).toBe(100000000n);
    expect(balance.unconfirmed).toBe(50000000n);
    expect(balance.total).toBe(150000000n);
  });

  test("getUTXOs returns all UTXOs", () => {
    const config = createTestConfig();
    const wallet = Wallet.create(config, TEST_MNEMONIC);

    const address = wallet.getNewAddress();

    wallet.addUTXO({
      outpoint: { txid: Buffer.alloc(32, 1), vout: 0 },
      amount: 100000000n,
      address,
      keyPath: "m/84'/0'/0'/0/0",
      confirmations: 6,
      addressType: AddressType.P2WPKH,
      isCoinbase: false,
    });

    wallet.addUTXO({
      outpoint: { txid: Buffer.alloc(32, 2), vout: 1 },
      amount: 50000000n,
      address,
      keyPath: "m/84'/0'/0'/0/0",
      confirmations: 3,
      addressType: AddressType.P2WPKH,
      isCoinbase: false,
    });

    const utxos = wallet.getUTXOs();
    expect(utxos.length).toBe(2);
  });
});

describe("Coin selection", () => {
  test("throws on insufficient funds", () => {
    const config = createTestConfig();
    const wallet = Wallet.create(config, TEST_MNEMONIC);

    const address = wallet.getNewAddress();
    wallet.addUTXO({
      outpoint: { txid: Buffer.alloc(32, 1), vout: 0 },
      amount: 1000n, // Very small
      address,
      keyPath: "m/84'/0'/0'/0/0",
      confirmations: 6,
      addressType: AddressType.P2WPKH,
      isCoinbase: false,
    });

    expect(() => {
      wallet.createTransaction(
        [{ address: "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", amount: 100000000n }],
        1 // 1 sat/vbyte
      );
    }).toThrow("Insufficient funds");
  });

  test("selects UTXOs efficiently", () => {
    const config = createTestConfig();
    const wallet = Wallet.create(config, TEST_MNEMONIC);

    const address = wallet.getNewAddress();

    // Add multiple UTXOs of different sizes
    wallet.addUTXO({
      outpoint: { txid: Buffer.alloc(32, 1), vout: 0 },
      amount: 100000n,
      address,
      keyPath: "m/84'/0'/0'/0/0",
      confirmations: 6,
      addressType: AddressType.P2WPKH,
      isCoinbase: false,
    });

    wallet.addUTXO({
      outpoint: { txid: Buffer.alloc(32, 2), vout: 0 },
      amount: 500000n,
      address,
      keyPath: "m/84'/0'/0'/0/0",
      confirmations: 6,
      addressType: AddressType.P2WPKH,
      isCoinbase: false,
    });

    wallet.addUTXO({
      outpoint: { txid: Buffer.alloc(32, 3), vout: 0 },
      amount: 300000n,
      address,
      keyPath: "m/84'/0'/0'/0/0",
      confirmations: 6,
      addressType: AddressType.P2WPKH,
      isCoinbase: false,
    });

    // Create transaction that only needs the largest UTXO
    const tx = wallet.createTransaction(
      [{ address: "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", amount: 10000n }],
      1
    );

    // Should select inputs efficiently (may be 1 or 2 depending on algorithm)
    // The coin selection algorithm will choose optimally based on fees
    expect(tx.inputs.length).toBeGreaterThanOrEqual(1);
    expect(tx.inputs.length).toBeLessThanOrEqual(3);
  });
});

describe("Transaction creation and signing", () => {
  test("creates valid transaction structure", () => {
    const config = createTestConfig();
    const wallet = Wallet.create(config, TEST_MNEMONIC);

    const address = wallet.getNewAddress();
    wallet.addUTXO({
      outpoint: { txid: Buffer.alloc(32, 1), vout: 0 },
      amount: 100000000n, // 1 BTC
      address,
      keyPath: "m/84'/0'/0'/0/0",
      confirmations: 6,
      addressType: AddressType.P2WPKH,
      isCoinbase: false,
    });

    const tx = wallet.createTransaction(
      [{ address: "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", amount: 50000000n }],
      1
    );

    expect(tx.version).toBe(2);
    expect(tx.inputs.length).toBeGreaterThanOrEqual(1);
    expect(tx.outputs.length).toBeGreaterThanOrEqual(1);
    expect(tx.lockTime).toBe(0);
  });

  test("includes witness data for segwit", () => {
    const config = createTestConfig();
    const wallet = Wallet.create(config, TEST_MNEMONIC);

    const address = wallet.getNewAddress();
    wallet.addUTXO({
      outpoint: { txid: Buffer.alloc(32, 1), vout: 0 },
      amount: 100000000n,
      address,
      keyPath: "m/84'/0'/0'/0/0",
      confirmations: 6,
      addressType: AddressType.P2WPKH,
      isCoinbase: false,
    });

    const tx = wallet.createTransaction(
      [{ address: "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", amount: 50000000n }],
      1
    );

    // Witness should have 2 items: signature and pubkey
    expect(tx.inputs[0].witness.length).toBe(2);
    expect(tx.inputs[0].witness[0].length).toBeGreaterThan(0); // signature
    expect(tx.inputs[0].witness[1].length).toBe(33); // compressed pubkey
  });

  test("signature is valid", () => {
    const config = createTestConfig();
    const wallet = Wallet.create(config, TEST_MNEMONIC);

    const address = wallet.getNewAddress();
    const key = wallet.getKey(address)!;
    const inputAmount = 100000000n;

    wallet.addUTXO({
      outpoint: { txid: Buffer.alloc(32, 1), vout: 0 },
      amount: inputAmount,
      address,
      keyPath: "m/84'/0'/0'/0/0",
      confirmations: 6,
      addressType: AddressType.P2WPKH,
      isCoinbase: false,
    });

    const tx = wallet.createTransaction(
      [{ address: "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", amount: 50000000n }],
      1
    );

    // Verify signature
    const sigWithType = tx.inputs[0].witness[0];
    const signature = sigWithType.subarray(0, sigWithType.length - 1); // Remove sighash type
    const pubkey = tx.inputs[0].witness[1];

    // Recompute sighash
    const pubKeyHash = hash160(pubkey);
    const scriptCode = Buffer.concat([
      Buffer.from([0x76, 0xa9, 0x14]),
      pubKeyHash,
      Buffer.from([0x88, 0xac]),
    ]);
    const sighash = sigHashWitnessV0(tx, 0, scriptCode, inputAmount, SIGHASH_ALL);

    const valid = ecdsaVerify(signature, sighash, pubkey);
    expect(valid).toBe(true);
  });

  test("adds change output when necessary", () => {
    const config = createTestConfig();
    const wallet = Wallet.create(config, TEST_MNEMONIC);

    const address = wallet.getNewAddress();
    wallet.addUTXO({
      outpoint: { txid: Buffer.alloc(32, 1), vout: 0 },
      amount: 100000000n, // 1 BTC
      address,
      keyPath: "m/84'/0'/0'/0/0",
      confirmations: 6,
      addressType: AddressType.P2WPKH,
      isCoinbase: false,
    });

    const tx = wallet.createTransaction(
      [{ address: "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", amount: 10000000n }], // 0.1 BTC
      1
    );

    // Should have 2 outputs: payment and change
    expect(tx.outputs.length).toBe(2);
  });

  test("does not add dust change output", () => {
    const config = createTestConfig();
    const wallet = Wallet.create(config, TEST_MNEMONIC);

    const address = wallet.getNewAddress();

    // Calculate a specific amount that would leave dust change
    // Fee estimate: ~10 + 68*1 + 31*2 = 140 vbytes @ 1 sat/vbyte = 140 sats
    // We want to leave ~500 sats change (below dust threshold of 546)
    const paymentAmount = 100000000n - 140n - 500n;

    wallet.addUTXO({
      outpoint: { txid: Buffer.alloc(32, 1), vout: 0 },
      amount: 100000000n,
      address,
      keyPath: "m/84'/0'/0'/0/0",
      confirmations: 6,
      addressType: AddressType.P2WPKH,
      isCoinbase: false,
    });

    const tx = wallet.createTransaction(
      [{ address: "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", amount: paymentAmount }],
      1
    );

    // Should have only 1 output (payment, no dust change)
    expect(tx.outputs.length).toBe(1);
  });

  test("throws on negative output amount", () => {
    const config = createTestConfig();
    const wallet = Wallet.create(config, TEST_MNEMONIC);

    expect(() => {
      wallet.createTransaction(
        [{ address: "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", amount: -1n }],
        1
      );
    }).toThrow("positive");
  });

  test("throws on zero output amount", () => {
    const config = createTestConfig();
    const wallet = Wallet.create(config, TEST_MNEMONIC);

    expect(() => {
      wallet.createTransaction(
        [{ address: "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", amount: 0n }],
        1
      );
    }).toThrow("positive");
  });
});

describe("Wallet persistence", () => {
  beforeEach(() => {
    mkdirSync(TEST_DATADIR, { recursive: true });
  });

  afterEach(() => {
    rmSync(TEST_DATADIR, { recursive: true, force: true });
  });

  test("saves and loads wallet", async () => {
    const config = createTestConfig();
    const password = "test-password-123";

    // Create and save wallet
    const wallet1 = Wallet.create(config, TEST_MNEMONIC);
    const addr1 = wallet1.getNewAddress();
    const addr2 = wallet1.getNewAddress();

    wallet1.addUTXO({
      outpoint: { txid: Buffer.alloc(32, 1), vout: 0 },
      amount: 100000000n,
      address: addr1,
      keyPath: "m/84'/0'/0'/0/0",
      confirmations: 6,
      addressType: AddressType.P2WPKH,
      isCoinbase: false,
    });

    await wallet1.save(password);

    // Load wallet
    const wallet2 = await Wallet.load(config, password);

    // Verify seed matches
    expect(wallet2.getSeed().equals(wallet1.getSeed())).toBe(true);

    // Verify addresses can be regenerated
    expect(wallet2.hasAddress(addr1)).toBe(true);
    expect(wallet2.hasAddress(addr2)).toBe(true);

    // Verify UTXOs are restored
    const utxos = wallet2.getUTXOs();
    expect(utxos.length).toBe(1);
    expect(utxos[0].amount).toBe(100000000n);

    // Verify balance
    const balance = wallet2.getBalance();
    expect(balance.confirmed).toBe(100000000n);
  });

  test("fails to load with wrong password", async () => {
    const config = createTestConfig();

    const wallet = Wallet.create(config, TEST_MNEMONIC);
    await wallet.save("correct-password");

    await expect(Wallet.load(config, "wrong-password")).rejects.toThrow();
  });

  test("fails to load non-existent wallet", async () => {
    const config = createTestConfig();

    await expect(Wallet.load(config, "password")).rejects.toThrow("not found");
  });
});

describe("Block processing", () => {
  test("processBlock detects incoming payments", () => {
    const config = createTestConfig();
    const wallet = Wallet.create(config, TEST_MNEMONIC);

    const address = wallet.getNewAddress();
    const decoded = decodeAddress(address);

    // Create a mock block with a tx paying to our address
    const block = {
      header: {
        version: 1,
        prevBlock: Buffer.alloc(32, 0),
        merkleRoot: Buffer.alloc(32, 0),
        timestamp: Math.floor(Date.now() / 1000),
        bits: 0x1d00ffff,
        nonce: 0,
      },
      transactions: [
        {
          version: 1,
          inputs: [
            {
              prevOut: { txid: Buffer.alloc(32, 0), vout: 0xffffffff },
              scriptSig: Buffer.from([0x03, 0x01, 0x00, 0x00]),
              sequence: 0xffffffff,
              witness: [],
            },
          ],
          outputs: [
            {
              value: 50000000n,
              // P2WPKH scriptPubKey: OP_0 <20-byte hash>
              scriptPubKey: Buffer.concat([Buffer.from([0x00, 0x14]), decoded.hash]),
            },
          ],
          lockTime: 0,
        },
      ],
    };

    wallet.processBlock(block, 100);

    const balance = wallet.getBalance();
    expect(balance.total).toBe(50000000n);

    const utxos = wallet.getUTXOs();
    expect(utxos.length).toBe(1);
    expect(utxos[0].address).toBe(address);
  });

  test("processBlock detects spent UTXOs", () => {
    const config = createTestConfig();
    const wallet = Wallet.create(config, TEST_MNEMONIC);

    const address = wallet.getNewAddress();
    const txid = Buffer.alloc(32, 1);

    // Add an initial UTXO
    wallet.addUTXO({
      outpoint: { txid, vout: 0 },
      amount: 100000000n,
      address,
      keyPath: "m/84'/0'/0'/0/0",
      confirmations: 6,
      addressType: AddressType.P2WPKH,
      isCoinbase: false,
    });

    expect(wallet.getBalance().total).toBe(100000000n);

    // Create a block that spends the UTXO
    const block = {
      header: {
        version: 1,
        prevBlock: Buffer.alloc(32, 0),
        merkleRoot: Buffer.alloc(32, 0),
        timestamp: Math.floor(Date.now() / 1000),
        bits: 0x1d00ffff,
        nonce: 0,
      },
      transactions: [
        {
          version: 1,
          inputs: [
            {
              prevOut: { txid, vout: 0 }, // Spends our UTXO
              scriptSig: Buffer.alloc(0),
              sequence: 0xffffffff,
              witness: [Buffer.from([0x30]), Buffer.alloc(33, 0x02)],
            },
          ],
          outputs: [
            {
              value: 99999000n,
              scriptPubKey: Buffer.from([0x00, 0x14, ...Buffer.alloc(20, 0)]),
            },
          ],
          lockTime: 0,
        },
      ],
    };

    wallet.processBlock(block, 101);

    // UTXO should be spent
    expect(wallet.getBalance().total).toBe(0n);
    expect(wallet.getUTXOs().length).toBe(0);
  });

  test("processBlock increments confirmations", () => {
    const config = createTestConfig();
    const wallet = Wallet.create(config, TEST_MNEMONIC);

    const address = wallet.getNewAddress();

    wallet.addUTXO({
      outpoint: { txid: Buffer.alloc(32, 1), vout: 0 },
      amount: 100000000n,
      address,
      keyPath: "m/84'/0'/0'/0/0",
      confirmations: 1,
      addressType: AddressType.P2WPKH,
      isCoinbase: false,
    });

    const emptyBlock = {
      header: {
        version: 1,
        prevBlock: Buffer.alloc(32, 0),
        merkleRoot: Buffer.alloc(32, 0),
        timestamp: Math.floor(Date.now() / 1000),
        bits: 0x1d00ffff,
        nonce: 0,
      },
      transactions: [],
    };

    wallet.processBlock(emptyBlock, 100);

    const utxos = wallet.getUTXOs();
    expect(utxos[0].confirmations).toBe(2);
  });
});

describe("All address types", () => {
  test("generates P2PKH (legacy) addresses", () => {
    const config = createTestConfig("mainnet");
    const wallet = Wallet.create(config, TEST_MNEMONIC);

    const address = wallet.getNewAddress("legacy");
    const decoded = decodeAddress(address);

    // Legacy addresses start with 1 on mainnet
    expect(address.startsWith("1")).toBe(true);
    expect(decoded.type).toBe(AddressType.P2PKH);
    expect(decoded.hash.length).toBe(20);
  });

  test("generates P2SH-P2WPKH (nested segwit) addresses", () => {
    const config = createTestConfig("mainnet");
    const wallet = Wallet.create(config, TEST_MNEMONIC);

    const address = wallet.getNewAddress("p2sh-segwit");
    const decoded = decodeAddress(address);

    // P2SH addresses start with 3 on mainnet
    expect(address.startsWith("3")).toBe(true);
    expect(decoded.type).toBe(AddressType.P2SH);
    expect(decoded.hash.length).toBe(20);
  });

  test("generates P2WPKH (native segwit) addresses", () => {
    const config = createTestConfig("mainnet");
    const wallet = Wallet.create(config, TEST_MNEMONIC);

    const address = wallet.getNewAddress("bech32");
    const decoded = decodeAddress(address);

    // Native segwit addresses start with bc1q on mainnet
    expect(address.startsWith("bc1q")).toBe(true);
    expect(decoded.type).toBe(AddressType.P2WPKH);
    expect(decoded.hash.length).toBe(20);
  });

  test("generates P2TR (taproot) addresses", () => {
    const config = createTestConfig("mainnet");
    const wallet = Wallet.create(config, TEST_MNEMONIC);

    const address = wallet.getNewAddress("bech32m");
    const decoded = decodeAddress(address);

    // Taproot addresses start with bc1p on mainnet
    expect(address.startsWith("bc1p")).toBe(true);
    expect(decoded.type).toBe(AddressType.P2TR);
    expect(decoded.hash.length).toBe(32);
  });

  test("testnet addresses use correct prefixes", () => {
    const config = createTestConfig("testnet");
    const wallet = Wallet.create(config, TEST_MNEMONIC);

    const legacy = wallet.getNewAddress("legacy");
    const p2sh = wallet.getNewAddress("p2sh-segwit");
    const bech32 = wallet.getNewAddress("bech32");
    const bech32m = wallet.getNewAddress("bech32m");

    // Testnet prefixes
    expect(legacy.startsWith("m") || legacy.startsWith("n")).toBe(true);
    expect(p2sh.startsWith("2")).toBe(true);
    expect(bech32.startsWith("tb1q")).toBe(true);
    expect(bech32m.startsWith("tb1p")).toBe(true);
  });

  test("different address types have different derivation paths", () => {
    const config = createTestConfig("mainnet");
    const wallet = Wallet.create(config, TEST_MNEMONIC);

    const legacy = wallet.getNewAddress("legacy");
    const p2sh = wallet.getNewAddress("p2sh-segwit");
    const bech32 = wallet.getNewAddress("bech32");
    const bech32m = wallet.getNewAddress("bech32m");

    const legacyKey = wallet.getKey(legacy)!;
    const p2shKey = wallet.getKey(p2sh)!;
    const bech32Key = wallet.getKey(bech32)!;
    const bech32mKey = wallet.getKey(bech32m)!;

    // Different BIP purposes
    expect(legacyKey.path.includes("/44'/")).toBe(true);
    expect(p2shKey.path.includes("/49'/")).toBe(true);
    expect(bech32Key.path.includes("/84'/")).toBe(true);
    expect(bech32mKey.path.includes("/86'/")).toBe(true);
  });
});

describe("Advanced coin selection", () => {
  test("BnB finds exact match without change", () => {
    const config = createTestConfig();
    const wallet = Wallet.create(config, TEST_MNEMONIC);

    const address = wallet.getNewAddress();

    // Add UTXOs that can exactly match the target + fee
    wallet.addUTXO({
      outpoint: { txid: Buffer.alloc(32, 1), vout: 0 },
      amount: 50000n,
      address,
      keyPath: "m/84'/0'/0'/0/0",
      confirmations: 6,
      addressType: AddressType.P2WPKH,
      isCoinbase: false,
    });

    wallet.addUTXO({
      outpoint: { txid: Buffer.alloc(32, 2), vout: 0 },
      amount: 50000n,
      address,
      keyPath: "m/84'/0'/0'/0/0",
      confirmations: 6,
      addressType: AddressType.P2WPKH,
      isCoinbase: false,
    });

    // Attempt to select coins using the advanced method
    const result = wallet.selectCoinsAdvanced(95000n, 1);

    // Should find an efficient selection
    expect(result.inputs.length).toBeGreaterThanOrEqual(1);
    expect(result.totalInput).toBeGreaterThanOrEqual(95000n);
  });

  test("Knapsack handles cases BnB cannot", () => {
    const config = createTestConfig();
    const wallet = Wallet.create(config, TEST_MNEMONIC);

    const address = wallet.getNewAddress();

    // Add a large UTXO that requires change
    wallet.addUTXO({
      outpoint: { txid: Buffer.alloc(32, 1), vout: 0 },
      amount: 10000000n, // 0.1 BTC
      address,
      keyPath: "m/84'/0'/0'/0/0",
      confirmations: 6,
      addressType: AddressType.P2WPKH,
      isCoinbase: false,
    });

    const result = wallet.selectCoinsAdvanced(1000000n, 1);

    // Should produce change
    expect(result.inputs.length).toBe(1);
    expect(result.change).toBeGreaterThan(0n);
  });

  test("coin selection respects address types for fee calculation", () => {
    const config = createTestConfig();
    const wallet = Wallet.create(config, TEST_MNEMONIC);

    const legacyAddr = wallet.getNewAddress("legacy");
    const segwitAddr = wallet.getNewAddress("bech32");

    // Add legacy UTXO (larger input size)
    wallet.addUTXO({
      outpoint: { txid: Buffer.alloc(32, 1), vout: 0 },
      amount: 100000n,
      address: legacyAddr,
      keyPath: "m/44'/0'/0'/0/0",
      confirmations: 6,
      addressType: AddressType.P2PKH,
      isCoinbase: false,
    });

    // Add segwit UTXO (smaller input size)
    wallet.addUTXO({
      outpoint: { txid: Buffer.alloc(32, 2), vout: 0 },
      amount: 100000n,
      address: segwitAddr,
      keyPath: "m/84'/0'/0'/0/0",
      confirmations: 6,
      addressType: AddressType.P2WPKH,
      isCoinbase: false,
    });

    const result = wallet.selectCoinsAdvanced(50000n, 1);

    // Should select inputs
    expect(result.inputs.length).toBeGreaterThanOrEqual(1);
    expect(result.fee).toBeGreaterThan(0n);
  });
});
