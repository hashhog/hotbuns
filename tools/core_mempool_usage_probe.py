#!/usr/bin/env python3
"""Measure Bitcoin Core's getmempoolinfo "usage" for transactions of known shape.

The expected values in src/mempool/core_mempool_usage.test.ts come from this
probe run against Bitcoin Core 31.1 on regtest; its recorded output is
tools/core_mempool_usage_probe.recorded.jsonl.

Usage:
  core_mempool_usage_probe.py <bitcoind> <scratch-datadir> <rpcport>

The datadir must be a scratch directory (it gets a wallet and a regtest chain).
Two parts, one JSON line per measurement:

  shapes  P2WSH(OP_DROP OP_DROP OP_TRUE) spends whose witness is two 80-byte
          items and the 3-byte script: the shapes of the unit test. Each case
          is funded and confirmed through the wallet, then bitcoind is
          restarted with -persistmempool=0 so the pool (and its
          txns_randomized vector) starts empty, like a new hotbuns Mempool.
          After the measurement one block is mined and the emptied pool's
          usage is recorded too.
  wallet  Wallet-signed P2WPKH / P2PKH / P2TR / P2SH-P2WPKH spends of 1-5
          inputs and 1-3 outputs, two and three singletons, and a parent with
          its child, each sent into the running pool after mining the last.
"""
import base64
import hashlib
import json
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.request

BITCOIND, DATADIR, PORT = sys.argv[1], sys.argv[2], int(sys.argv[3])
AUTH = base64.b64encode(b"u:p").decode()
DROP_SCRIPT = bytes.fromhex("755175")  # OP_DROP OP_DROP OP_TRUE
DROP_P2WSH = b"\x00\x20" + hashlib.sha256(DROP_SCRIPT).digest()
HEAVY_SCRIPT = b"\x00\x14" + b"\x11" * 20
V = 100_000_000


def compact_size(n):
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", n)
    return b"\xfe" + struct.pack("<I", n)


def txid_of_legacy(raw):
    return hashlib.sha256(hashlib.sha256(raw).digest()).digest()[::-1].hex()


def drop_spend(outpoints, outputs):
    """A segwit tx spending DROP_P2WSH outpoints. Returns (hex, txid)."""
    body = compact_size(len(outpoints))
    for txid, vout in outpoints:
        body += bytes.fromhex(txid)[::-1] + struct.pack("<I", vout) + b"\x00" + struct.pack("<I", 0xFFFFFFFD)
    body += compact_size(len(outputs))
    for amount, script in outputs:
        body += struct.pack("<q", amount) + compact_size(len(script)) + script
    version, locktime = struct.pack("<i", 2), struct.pack("<I", 0)
    items = [b"\x11" * 80, b"\x22" * 80, DROP_SCRIPT]
    witness = b"".join(compact_size(len(items)) + b"".join(compact_size(len(i)) + i for i in items)
                       for _ in outpoints)
    raw = version + b"\x00\x01" + body + witness + locktime
    return raw.hex(), txid_of_legacy(version + body + locktime)


def rpc(method, params=None, wallet=None):
    url = f"http://127.0.0.1:{PORT}/" + (f"wallet/{wallet}" if wallet else "")
    body = json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": params or []}).encode()
    req = urllib.request.Request(url, body, {"Authorization": "Basic " + AUTH})
    try:
        out = json.load(urllib.request.urlopen(req, timeout=120))
    except urllib.error.HTTPError as e:
        out = json.load(e)
    if out.get("error"):
        raise RuntimeError(f"{method}: {out['error']}")
    return out["result"]


def w(method, params=None):
    return rpc(method, params, wallet="w")


def start():
    subprocess.run([BITCOIND, "-regtest", f"-datadir={DATADIR}", f"-rpcport={PORT}", f"-port={PORT + 1}",
                    "-listen=0", "-rpcuser=u", "-rpcpassword=p", "-fallbackfee=0.0001",
                    "-persistmempool=0", "-daemonwait"], check=True, capture_output=True)
    for _ in range(100):
        try:
            rpc("getblockcount")
            break
        except Exception:
            time.sleep(0.2)
    if "w" not in rpc("listwallets"):
        try:
            rpc("loadwallet", ["w"])
        except RuntimeError:
            rpc("createwallet", ["w"])


def stop():
    rpc("stop")
    for _ in range(300):
        try:
            rpc("getblockcount")
            time.sleep(0.2)
        except Exception:
            time.sleep(0.5)
            return


def mine(n=1):
    rpc("generatetoaddress", [n, w("getnewaddress")])


def fund(n, sats):
    addr = rpc("decodescript", [DROP_SCRIPT.hex()])["segwit"]["address"]
    outs = []
    for _ in range(n):
        txid = w("sendtoaddress", [addr, sats / 1e8])
        tx = rpc("getrawtransaction", [txid, True])
        outs.append((txid, next(o["n"] for o in tx["vout"] if o["scriptPubKey"]["hex"] == DROP_P2WSH.hex())))
    mine()
    return outs


def shape_case(name, build):
    start()
    try:
        hexes = build()
        stop()
        start()  # funding went through the pool; restart so it starts empty
        before = rpc("getmempoolinfo")["usage"]
        for h in hexes:
            rpc("sendrawtransaction", [h])
        info = rpc("getmempoolinfo")
        rec = {"part": "shapes", "case": name, "empty_before": before, "usage": info["usage"],
               "size": info["size"], "bytes": info["bytes"]}
        mine()
        rec["drained_usage"] = rpc("getmempoolinfo")["usage"]
        rec["hexes"] = hexes
        print(json.dumps(rec), flush=True)
    finally:
        stop()


def shapes():
    def lone():
        (op,) = fund(1, V)
        return [drop_spend([op], [(V - 10_000, HEAVY_SCRIPT)])[0]]

    def two_in_two_out():
        ops = fund(2, V)
        return [drop_spend(ops, [(V - 10_000, HEAVY_SCRIPT), (V, DROP_P2WSH)])[0]]

    def three_singletons():
        ops = fund(3, V)
        return [drop_spend([op], [(V - 10_000 - i * 1000, HEAVY_SCRIPT)])[0] for i, op in enumerate(ops)]

    def pair(parent_fee, child_fee):
        def build():
            (op,) = fund(1, V)
            praw, ptxid = drop_spend([op], [(V - parent_fee, DROP_P2WSH)])
            craw, _ = drop_spend([(ptxid, 0)], [(V - parent_fee - child_fee, HEAVY_SCRIPT)])
            return [praw, craw]
        return build

    def chain3():
        (op,) = fund(1, V)
        r1, t1 = drop_spend([op], [(V - 2_000, DROP_P2WSH)])
        r2, t2 = drop_spend([(t1, 0)], [(V - 4_000, DROP_P2WSH)])
        r3, _ = drop_spend([(t2, 0)], [(V - 6_000, HEAVY_SCRIPT)])
        return [r1, r2, r3]

    def fanout100():
        (op,) = fund(1, V)
        return [drop_spend([op], [(990_000, DROP_P2WSH)] * 100)[0]]

    shape_case("lone-1in-1out", lone)
    shape_case("2in-2out", two_in_two_out)
    shape_case("three-singletons", three_singletons)
    shape_case("pair-cpfp-one-chunk", pair(1_000, 50_000))
    shape_case("pair-two-chunks", pair(50_000, 1_000))
    shape_case("chain3", chain3)
    shape_case("fanout-1in-100out", fanout100)


def wallet():
    start()
    try:
        outs = {}
        for kind in ["bech32", "legacy", "bech32m", "p2sh-segwit"]:
            for _ in range(40):
                outs[w("getnewaddress", ["", kind])] = 1.0
        w("sendmany", ["", outs])
        mine()
        used = set()
        prefix = {"bech32": ("bcrt1q",), "legacy": ("m", "n"), "bech32m": ("bcrt1p",), "p2sh-segwit": ("2",)}

        def make_tx(kind, nin, nout, out_kind="bech32"):
            ins = [u for u in w("listunspent") if u["address"].startswith(prefix[kind])
                   and abs(u["amount"] - 1.0) < 1e-9 and (u["txid"], u["vout"]) not in used][:nin]
            assert len(ins) == nin, (kind, nin)
            used.update((u["txid"], u["vout"]) for u in ins)
            total = nin - 0.001
            outputs = [{w("getnewaddress", ["", out_kind]): round(total / nout, 8)} for _ in range(nout)]
            raw = rpc("createrawtransaction", [[{"txid": u["txid"], "vout": u["vout"]} for u in ins], outputs])
            return w("signrawtransactionwithwallet", [raw])["hex"]

        def measure(label, hexes):
            mine()
            before = rpc("getmempoolinfo")["usage"]
            for h in hexes:
                rpc("sendrawtransaction", [h])
            info = rpc("getmempoolinfo")
            shape = [[len(d["vin"]), len(d["vout"])] for d in (rpc("decoderawtransaction", [h]) for h in hexes)]
            print(json.dumps({"part": "wallet", "case": label, "empty_before": before, "usage": info["usage"],
                              "size": info["size"], "shape": shape, "hexes": hexes}), flush=True)

        for kind in ["bech32", "legacy", "bech32m", "p2sh-segwit"]:
            for nin, nout in [(1, 1), (1, 2), (2, 1), (3, 3), (5, 2)]:
                measure(f"{kind}-{nin}x{nout}", [make_tx(kind, nin, nout)])
        for out_kind in ["legacy", "bech32m", "p2sh-segwit"]:
            measure(f"bech32-1x2-to-{out_kind}", [make_tx("bech32", 1, 2, out_kind)])
        measure("two-singletons", [make_tx("bech32", 1, 1) for _ in range(2)])
        measure("three-singletons", [make_tx("bech32", 1, 1) for _ in range(3)])
        mine()
        parent = make_tx("bech32", 1, 1)
        ptxid = rpc("sendrawtransaction", [parent])
        value = rpc("decoderawtransaction", [parent])["vout"][0]["value"]
        child_raw = rpc("createrawtransaction", [[{"txid": ptxid, "vout": 0}],
                                                 [{w("getnewaddress", ["", "bech32"]): round(value - 0.001, 8)}]])
        child = w("signrawtransactionwithwallet", [child_raw])["hex"]
        rpc("sendrawtransaction", [child])
        info = rpc("getmempoolinfo")
        print(json.dumps({"part": "wallet", "case": "parent-child", "usage": info["usage"], "size": info["size"],
                          "hexes": [parent, child]}), flush=True)
    finally:
        stop()


def main():
    start()
    if rpc("getblockcount") < 300:
        mine(300)
    stop()
    shapes()
    wallet()


if __name__ == "__main__":
    main()
