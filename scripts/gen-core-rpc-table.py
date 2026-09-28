#!/usr/bin/env python3
"""Generate src/rpc/core-arity.json FROM A RUNNING BITCOIN CORE.

For every method Core lists in `help`, record what Core's RPCHelpMan enforces
centrally before any handler runs (bitcoin-core/src/rpc/util.cpp:640-657):

  * arity   -- IsValidNumArgs (util.cpp:733): required = 1-based index of the
               LAST non-optional argument, declared = number of arguments
               (hidden ones included). Violations throw the help text as -1.
  * types   -- RPCArg::MatchesType (util.cpp:899): each positional argument
               whose RPCArg::Type maps to one UniValue type (STR/STR_HEX ->
               string, NUM -> number, BOOL -> bool, OBJ* -> object, ARR ->
               array) must have that type, unless it is optional and null.
               AMOUNT / RANGE / custom type_str accept several types and are
               not checked. Violations are -3 "Wrong type passed:\n{...}".
  * help    -- the full help text, which IS Core's -1 arity message.

Arguments are read from the numbered "Arguments:" section of `help <method>`,
not from the one-line signature (the signature splits `"range": n or [n,n]`
into extra arguments and cannot mark a required argument that follows an
optional one, e.g. prioritisetransaction's fee_delta).

Two things help does not show are patched from Core source:
  * SKIP_TYPE_CHECK -- args declared with RPCArgOptions{.skip_type_check=true}
  * HIDDEN          -- args declared with RPCArgOptions{.hidden=true}

usage: gen-core-rpc-table.py <core-rpc-port> <core-cookie-file> > src/rpc/core-arity.json
"""
import base64, json, re, sys, urllib.request

# grep -rn skip_type_check bitcoin-core/src/{rpc,wallet/rpc} (top-level args only;
# the RPCResult and nested-object uses do not affect positional checks).
SKIP_TYPE_CHECK = {
    ("getblock", "verbosity"),                 # rpc/blockchain.cpp:772
    ("gettxoutsetinfo", "hash_or_height"),     # rpc/blockchain.cpp:1020
    ("getblockstats", "hash_or_height"),       # rpc/blockchain.cpp:1965
    ("createrawtransaction", "outputs"),       # rpc/rawtransaction.cpp:118 (CreateTxDoc)
    ("createpsbt", "outputs"),                 # rpc/rawtransaction.cpp:118 (CreateTxDoc)
    ("getrawtransaction", "verbosity"),        # rpc/rawtransaction.cpp:233
    ("getorphantxs", "verbosity"),             # rpc/mempool.cpp:1241
    ("fundrawtransaction", "options"),         # wallet/rpc/spend.cpp:770
    ("send", "outputs"),                       # wallet/rpc/spend.cpp:1177
    ("walletcreatefundedpsbt", "outputs"),     # wallet/rpc/spend.cpp:1684
} | {("echo", f"arg{i}") for i in range(10)} | {("echojson", f"arg{i}") for i in range(10)}

# rpc/server.cpp:155 -- stop's hidden `wait` (NUM, optional).
HIDDEN = {"stop": [["wait", "number", False]]}

ALIASES = {  # m_names as Core prints them in "Position N (<m_names>)"
    ("getblock", "verbosity"): "verbosity|verbose",
    ("getrawtransaction", "verbosity"): "verbosity|verbose",
}

TYPEMAP = {"string": "string", "numeric": "number", "boolean": "bool",
           "json object": "object", "json array": "array"}

ARG_RE = re.compile(r"^(\d+)\. (\S+)\s+\(([^)]*)\)")


def rpc(port, cookie, method, params):
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}/",
        data=json.dumps({"jsonrpc": "1.0", "id": 1, "method": method,
                         "params": params}).encode(),
        headers={"Authorization": "Basic " + base64.b64encode(cookie.encode()).decode()})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read())["result"]
    except urllib.error.HTTPError as e:
        return json.loads(e.read())["result"]


def parse_args(method, text):
    lines = text.split("\n")
    try:
        start = lines.index("Arguments:") + 1
    except ValueError:
        return []
    args = []
    for ln in lines[start:]:
        if ln.startswith("Result") or ln.startswith("Examples:"):
            break
        m = ARG_RE.match(ln)
        if not m:
            continue
        idx, name, meta = int(m.group(1)), m.group(2), m.group(3)
        assert idx == len(args) + 1, (method, ln)
        parts = [p.strip() for p in meta.split(",")]
        typ = TYPEMAP.get(parts[0])
        if (method, name) in SKIP_TYPE_CHECK:
            typ = None
        required = "required" in parts
        args.append([ALIASES.get((method, name), name), typ, required])
    return args


def main():
    port, cookie = int(sys.argv[1]), open(sys.argv[2]).read().strip()
    methods = sorted({l.split()[0] for l in rpc(port, cookie, "help", []).split("\n")
                      if l and not l.startswith("==")})
    table = {}
    for m in methods:
        text = rpc(port, cookie, "help", [m])
        args = parse_args(m, text) + HIDDEN.get(m, [])
        required = max((i + 1 for i, a in enumerate(args) if a[2]), default=0)
        table[m] = {"required": required, "declared": len(args),
                    "sig": text.split("\n")[0], "help": text, "args": args}
    json.dump(table, sys.stdout, indent=1, sort_keys=True)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
