#!/usr/bin/env bun
/**
 * Regtest block differential for the legacy CHECKMULTISIG empty-sig
 * FindAndDelete rule: Bitcoin Core vs a hotbuns tree, same blocks, submitblock.
 *
 * Core's OP_CHECKMULTISIG (SigVersion::BASE) runs
 * FindAndDelete(scriptCode, CScript() << vchSig) for every sig; for an empty
 * sig that is the pattern OP_0, so every opcode-aligned OP_0 leaves scriptCode
 * before any signature is checked. A hotbuns that skips the empty sig hashes a
 * different scriptCode, which splits consensus in both directions:
 *
 *   --case=forward  scriptPubKey 00 75 53 <pk1..pk4> 54 ae 91
 *                   scriptSig    00 00 01 01 <S>, S by pk4 over the OP_0-free
 *                   scriptCode. Core: S verifies, the next sig 01 fails DER,
 *                   block invalid.
 *   --case=reverse  scriptPubKey 00 75 53 <pk1..pk3> 53 ae 91
 *                   scriptSig    00 00 01 01 <S>, S by pk3 over the full
 *                   scriptPubKey. Core: S fails, multisig false, OP_NOT true,
 *                   block valid.
 *
 * Steps: start Core and the hotbuns tree on regtest (fresh datadirs under
 * --workdir, free ports, no peers); Core mines block 1 to the bare script
 * (generatetodescriptor raw(...)) and 100 blocks to raw(51); every block is
 * fed to hotbuns with submitblock and the tips are compared; then one block
 * spending the bare output is built here and submitted to both. Both nodes are
 * stopped with the `stop` RPC.
 *
 *   bun run tools/repro-multisig-findanddelete-empty-sig.ts \
 *     --core=<bitcoind 31.1> --tree=<hotbuns checkout> --case=forward|reverse \
 *     --workdir=<empty dir>
 *
 * Prints one JSON line. Exit 0 when hotbuns' verdict equals Core's, 1 when it
 * differs, 2 on a harness error.
 */
import { spawn } from "node:child_process";
import { mkdirSync, openSync } from "node:fs";
import { createServer } from "node:net";
import { join, resolve } from "node:path";
import { ecdsaSign, privateKeyToPublicKey } from "../src/crypto/primitives.js";
import {
	type Block,
	computeMerkleRoot,
	getBlockHash,
	serializeBlock,
} from "../src/validation/block.js";
import {
	getTxId,
	SIGHASH_ALL,
	serializeTx,
	sigHashLegacy,
	type Transaction,
} from "../src/validation/tx.js";

const args = new Map<string, string>();
for (const a of process.argv.slice(2)) {
	const m = /^--([^=]+)(?:=(.*))?$/.exec(a);
	if (m) args.set(m[1]!, m[2] ?? "1");
}
const CORE = args.get("core");
const TREE = resolve(args.get("tree") ?? ".");
const CASE = args.get("case") ?? "forward";
const WORK = args.get("workdir");
if (!CORE || !WORK || (CASE !== "forward" && CASE !== "reverse")) {
	console.error("usage: --core=<bitcoind> --tree=<hotbuns> --case=forward|reverse --workdir=<dir>");
	process.exit(2);
}
const BUN = process.execPath;

// ----------------------------------------------------------------- scripts
const h = (s: string) => Buffer.from(s, "hex");
const push = (b: Buffer) => Buffer.concat([Buffer.from([b.length]), b]);
const PRIVS = [1, 2, 3, 4].map((b) => Buffer.alloc(32, b));
const PUBS = PRIVS.map((p) => privateKeyToPublicKey(p, true));
const SPK =
	CASE === "forward"
		? Buffer.concat([h("007553"), ...PUBS.map(push), h("54ae91")])
		: Buffer.concat([h("007553"), ...PUBS.slice(0, 3).map(push), h("53ae91")]);
// Core's scriptCode after FindAndDelete(OP_0): the leading OP_0 is the only
// opcode-aligned 0x00 in SPK (the pubkey bytes are push payload).
const CORE_SCRIPTCODE = SPK.subarray(1);
const SIGN_OVER = CASE === "forward" ? CORE_SCRIPTCODE : SPK;
const SIGNER = CASE === "forward" ? PRIVS[3]! : PRIVS[2]!;
const CORE_EXPECT = CASE === "forward" ? "reject" : "accept";

// ----------------------------------------------------------------- procs
function freePort(): Promise<number> {
	return new Promise((ok, bad) => {
		const s = createServer();
		s.once("error", bad);
		s.listen(0, "127.0.0.1", () => {
			const p = (s.address() as { port: number }).port;
			s.close(() => ok(p));
		});
	});
}

async function rpc(port: number, method: string, params: unknown[] = []): Promise<any> {
	const res = await fetch(`http://127.0.0.1:${port}/`, {
		method: "POST",
		headers: {
			"content-type": "application/json",
			authorization: "Basic " + Buffer.from("test:test").toString("base64"),
		},
		body: JSON.stringify({ jsonrpc: "1.0", id: 1, method, params }),
		signal: AbortSignal.timeout(120_000),
	});
	const j = (await res.json()) as { result: unknown; error: { message: string } | null };
	if (j.error) throw new Error(`${method}: ${j.error.message}`);
	return j.result;
}

async function waitRpc(port: number, label: string, ms: number) {
	const t0 = Date.now();
	for (;;) {
		try {
			await rpc(port, "getblockcount");
			return;
		} catch {
			if (Date.now() - t0 > ms) throw new Error(`${label} RPC not up after ${ms} ms`);
			await Bun.sleep(500);
		}
	}
}

type Proc = ReturnType<typeof spawn>;
function start(label: string, cmd: string, argv: string[], cwd: string): Proc {
	const log = openSync(join(WORK!, `${label}.log`), "a");
	return spawn(cmd, argv, { cwd, stdio: ["ignore", log, log] });
}

async function stopNode(label: string, port: number, p: Proc): Promise<string> {
	const exited = new Promise<void>((ok) => p.once("exit", () => ok()));
	if (p.exitCode !== null) return "already-exited";
	try {
		await rpc(port, "stop");
	} catch (e) {
		return `stop-rpc-failed: ${(e as Error).message}`;
	}
	const t = await Promise.race([exited.then(() => "stopped"), Bun.sleep(90_000).then(() => "STILL-RUNNING")]);
	return t === "stopped" ? "stopped" : `${label} pid ${p.pid} did not exit within 90 s`;
}

// ----------------------------------------------------------------- block
function cbHeight(height: number): Buffer {
	// CScript() << height, minimal (BIP34); regtest heights here are < 32768.
	if (height <= 16) throw new Error("height too small for this helper");
	const n: number[] = [];
	let v = height;
	while (v > 0) {
		n.push(v & 0xff);
		v >>= 8;
	}
	if (n[n.length - 1]! & 0x80) n.push(0);
	return Buffer.concat([Buffer.from([n.length]), Buffer.from(n)]);
}

function buildSpend(prevTxid: Buffer, value: bigint): Transaction {
	const tx: Transaction = {
		version: 1,
		inputs: [{ prevOut: { txid: prevTxid, vout: 0 }, scriptSig: Buffer.alloc(0), sequence: 0xffffffff, witness: [] }],
		outputs: [{ value: value - 1000n, scriptPubKey: h("51") }],
		lockTime: 0,
	};
	const sighash = sigHashLegacy(tx, 0, SIGN_OVER, SIGHASH_ALL);
	const S = Buffer.concat([ecdsaSign(sighash, SIGNER), Buffer.from([SIGHASH_ALL])]);
	// Fresh object: getTxId caches on the tx, and the unsigned one must not leak.
	return {
		version: tx.version,
		inputs: [{ ...tx.inputs[0]!, scriptSig: Buffer.concat([h("00" + "00" + "0101"), push(S)]) }],
		outputs: tx.outputs,
		lockTime: tx.lockTime,
	};
}

function buildBlock(prevHashHex: string, height: number, time: number, bits: number, spend: Transaction, subsidy: bigint): Block {
	const coinbase: Transaction = {
		version: 1,
		inputs: [{ prevOut: { txid: Buffer.alloc(32, 0), vout: 0xffffffff }, scriptSig: Buffer.concat([cbHeight(height), h("00")]), sequence: 0xffffffff, witness: [] }],
		outputs: [{ value: subsidy + 1000n, scriptPubKey: h("51") }],
		lockTime: 0,
	};
	const txs = [coinbase, spend];
	const block: Block = {
		header: {
			version: 0x20000000,
			prevBlock: Buffer.from(prevHashHex, "hex").reverse(),
			merkleRoot: computeMerkleRoot(txs.map(getTxId)),
			timestamp: time,
			bits,
			nonce: 0,
		},
		transactions: txs,
	};
	// Regtest target 0x207fffff: about one nonce in two works.
	const exp = bits >>> 24;
	const target = BigInt(bits & 0x7fffff) << BigInt(8 * (exp - 3));
	for (;;) {
		const hash = BigInt("0x" + Buffer.from(getBlockHash(block.header)).reverse().toString("hex"));
		if (hash <= target) return block;
		block.header.nonce++;
	}
}

// ----------------------------------------------------------------- main
async function main() {
	mkdirSync(WORK!, { recursive: true });
	const coreDir = join(WORK!, "core");
	const hbDir = join(WORK!, "hotbuns");
	mkdirSync(coreDir, { recursive: true });
	mkdirSync(hbDir, { recursive: true });
	const [cRpc, cP2p, hRpc, hP2p] = [await freePort(), await freePort(), await freePort(), await freePort()];

	const core = start("core", CORE!, [
		"-regtest", `-datadir=${coreDir}`, `-rpcport=${cRpc}`, `-port=${cP2p}`, "-listen=0",
		"-connect=0", "-dnsseed=0", "-rpcuser=test", "-rpcpassword=test", "-printtoconsole=0",
	], coreDir);
	const hb = start("hotbuns", BUN, [
		"run", join(TREE, "src/index.ts"), "--network=regtest", `--datadir=${hbDir}`,
		`--rpcport=${hRpc}`, `--port=${hP2p}`, "--metrics-port=0", "--rpc-user=test",
		"--rpc-password=test", "--nodnsseed", "--nodiscover", "--connect=127.0.0.1:1", "--listen=0",
	], TREE);

	const out: Record<string, unknown> = { case: CASE, tree: TREE, core_expected: CORE_EXPECT };
	let code = 2;
	try {
		await waitRpc(cRpc, "core", 120_000);
		await waitRpc(hRpc, "hotbuns", 180_000);
		out.core_version = (await rpc(cRpc, "getnetworkinfo")).subversion;

		const desc = async (d: string) => (await rpc(cRpc, "getdescriptorinfo", [d])).descriptor as string;
		const [bareHash] = (await rpc(cRpc, "generatetodescriptor", [1, await desc(`raw(${SPK.toString("hex")})`)])) as string[];
		await rpc(cRpc, "generatetodescriptor", [100, await desc("raw(51)")]);

		const n = (await rpc(cRpc, "getblockcount")) as number;
		for (let i = 1; i <= n; i++) {
			const bh = await rpc(cRpc, "getblockhash", [i]);
			const r = await rpc(hRpc, "submitblock", [await rpc(cRpc, "getblock", [bh, 0])]);
			if (r !== null && r !== "duplicate") throw new Error(`hotbuns refused Core block ${i}: ${r}`);
		}
		const cTip = await rpc(cRpc, "getbestblockhash");
		const hTip = await rpc(hRpc, "getbestblockhash");
		out.base_height = n;
		if (cTip !== hTip) throw new Error(`base chains differ: core ${cTip} hotbuns ${hTip}`);

		const bare = await rpc(cRpc, "getblock", [bareHash, 2]);
		const cb = bare.tx[0];
		if (cb.vout[0].scriptPubKey.hex !== SPK.toString("hex")) throw new Error("block 1 coinbase does not pay the bare script");
		const value = BigInt(Math.round(cb.vout[0].value * 1e8));
		const tip = await rpc(cRpc, "getblockheader", [cTip]);
		const spend = buildSpend(Buffer.from(cb.txid, "hex").reverse(), value);
		const block = buildBlock(cTip, n + 1, Math.max(tip.time + 1, tip.mediantime + 1), parseInt(tip.bits, 16), spend, 50_0000_0000n);
		const hex = serializeBlock(block).toString("hex");
		out.spend_txid = Buffer.from(getTxId(spend)).reverse().toString("hex");
		out.spend_tx = serializeTx(spend, false).toString("hex");
		out.block_hash = Buffer.from(getBlockHash(block.header)).reverse().toString("hex");

		const cRes = await rpc(cRpc, "submitblock", [hex]);
		const hRes = await rpc(hRpc, "submitblock", [hex]);
		const cNew = await rpc(cRpc, "getbestblockhash");
		const hNew = await rpc(hRpc, "getbestblockhash");
		const verdict = (res: unknown, tipNow: string) =>
			res === null && tipNow === out.block_hash ? "accept" : "reject";
		out.core = { submitblock: cRes, tip_is_block: cNew === out.block_hash, verdict: verdict(cRes, cNew) };
		out.hotbuns = { submitblock: hRes, tip_is_block: hNew === out.block_hash, verdict: verdict(hRes, hNew) };
		const cv = (out.core as { verdict: string }).verdict;
		const hv = (out.hotbuns as { verdict: string }).verdict;
		if (cv !== CORE_EXPECT) throw new Error(`Core control failed: expected ${CORE_EXPECT}, got ${cv} (${cRes})`);
		out.match = cv === hv;
		code = cv === hv ? 0 : 1;
	} catch (e) {
		out.error = (e as Error).message;
		code = 2;
	} finally {
		out.stop_core = await stopNode("core", cRpc, core);
		out.stop_hotbuns = await stopNode("hotbuns", hRpc, hb);
	}
	console.log(JSON.stringify(out));
	process.exit(code);
}

main();
