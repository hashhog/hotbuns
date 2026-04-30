/**
 * Tests for CLI argument parsing and configuration.
 */

import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import { parseArgs, loadConfig, saveConfig, formatRpcRequest } from "./cli.js";

describe("parseArgs", () => {
  test("parses default start command", () => {
    const result = parseArgs(["bun", "script.ts"]);
    expect(result.command).toBe("start");
    expect(result.config.network).toBe("mainnet");
    expect(result.config.rpcPort).toBe(8332);
  });

  test("parses explicit start command", () => {
    const result = parseArgs(["bun", "script.ts", "start"]);
    expect(result.command).toBe("start");
  });

  test("parses stop command", () => {
    const result = parseArgs(["bun", "script.ts", "stop"]);
    expect(result.command).toBe("stop");
  });

  test("parses getinfo command", () => {
    const result = parseArgs(["bun", "script.ts", "getinfo"]);
    expect(result.command).toBe("getinfo");
  });

  test("parses getblock command with args", () => {
    const result = parseArgs([
      "bun",
      "script.ts",
      "getblock",
      "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
    ]);
    expect(result.command).toBe("getblock");
    expect(result.args).toEqual([
      "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
    ]);
  });

  test("parses sendrawtransaction command", () => {
    const result = parseArgs([
      "bun",
      "script.ts",
      "sendrawtransaction",
      "0100000001...",
    ]);
    expect(result.command).toBe("sendrawtransaction");
    expect(result.args).toEqual(["0100000001..."]);
  });

  test("parses wallet command with subcommand", () => {
    const result = parseArgs(["bun", "script.ts", "wallet", "create"]);
    expect(result.command).toBe("wallet");
    expect(result.args).toEqual(["create"]);
  });

  test("parses --datadir flag", () => {
    const result = parseArgs([
      "bun",
      "script.ts",
      "--datadir=/custom/path",
      "start",
    ]);
    expect(result.config.datadir).toBe("/custom/path");
    expect(result.command).toBe("start");
  });

  test("parses --network=testnet flag", () => {
    const result = parseArgs(["bun", "script.ts", "--network=testnet"]);
    expect(result.config.network).toBe("testnet");
    expect(result.config.rpcPort).toBe(18332);
    expect(result.config.port).toBe(18333);
  });

  test("parses --network=regtest flag", () => {
    const result = parseArgs(["bun", "script.ts", "--network=regtest"]);
    expect(result.config.network).toBe("regtest");
    expect(result.config.rpcPort).toBe(18443);
    expect(result.config.port).toBe(18444);
  });

  test("parses explicit --rpc-port flag", () => {
    const result = parseArgs([
      "bun",
      "script.ts",
      "--network=testnet",
      "--rpc-port=9999",
    ]);
    expect(result.config.rpcPort).toBe(9999);
  });

  test("parses --rpc-user and --rpc-password flags", () => {
    const result = parseArgs([
      "bun",
      "script.ts",
      "--rpc-user=alice",
      "--rpc-password=secret123",
    ]);
    expect(result.config.rpcUser).toBe("alice");
    expect(result.config.rpcPassword).toBe("secret123");
  });

  test("parses --max-outbound flag", () => {
    const result = parseArgs(["bun", "script.ts", "--max-outbound=4"]);
    expect(result.config.maxOutbound).toBe(4);
  });

  test("parses --log-level flag", () => {
    const result = parseArgs(["bun", "script.ts", "--log-level=debug"]);
    expect(result.config.logLevel).toBe("debug");
  });

  test("parses --connect flag", () => {
    const result = parseArgs([
      "bun",
      "script.ts",
      "--connect=192.168.1.1:8333",
      "--connect=192.168.1.2:8333",
    ]);
    expect(result.config.connect).toEqual([
      "192.168.1.1:8333",
      "192.168.1.2:8333",
    ]);
  });

  test("parses --listen=0 flag", () => {
    const result = parseArgs(["bun", "script.ts", "--listen=0"]);
    expect(result.config.listen).toBe(false);
  });

  test("parses --help flag", () => {
    const result = parseArgs(["bun", "script.ts", "--help"]);
    expect(result.command).toBe("help");
  });

  test("parses mixed flags and arguments", () => {
    const result = parseArgs([
      "bun",
      "script.ts",
      "--network=testnet",
      "getblock",
      "abc123",
      "--rpc-user=bob",
    ]);
    expect(result.command).toBe("getblock");
    expect(result.config.network).toBe("testnet");
    expect(result.config.rpcUser).toBe("bob");
    expect(result.args).toEqual(["abc123"]);
  });

  test("preserves --password flag for wallet commands", () => {
    const result = parseArgs([
      "bun",
      "script.ts",
      "wallet",
      "create",
      "--password=mysecret",
    ]);
    expect(result.command).toBe("wallet");
    expect(result.args).toContain("create");
    expect(result.args).toContain("--password=mysecret");
  });

  test("preserves --fee-rate flag for wallet send", () => {
    const result = parseArgs([
      "bun",
      "script.ts",
      "wallet",
      "send",
      "bc1q...",
      "0.01",
      "--password=mysecret",
      "--fee-rate=5",
    ]);
    expect(result.command).toBe("wallet");
    expect(result.args).toContain("send");
    expect(result.args).toContain("bc1q...");
    expect(result.args).toContain("0.01");
    expect(result.args).toContain("--password=mysecret");
    expect(result.args).toContain("--fee-rate=5");
  });

  test("returns default config values", () => {
    const result = parseArgs(["bun", "script.ts"]);
    expect(result.config.datadir).toContain(".hotbuns");
    expect(result.config.maxOutbound).toBe(8);
    expect(result.config.listen).toBe(true);
    expect(result.config.logLevel).toBe("info");
    // BIP-35 / BIP-111: NODE_BLOOM advertisement defaults to OFF, matching
    // Bitcoin Core's `DEFAULT_PEERBLOOMFILTERS = false` (net_processing.h).
    expect(result.config.peerBloomFilters).toBe(false);
  });

  test("parses --peerbloomfilters=0 flag (disable BIP-35 gate)", () => {
    const result = parseArgs(["bun", "script.ts", "--peerbloomfilters=0"]);
    expect(result.config.peerBloomFilters).toBe(false);
  });

  test("parses --peerbloomfilters=1 flag (explicit enable)", () => {
    const result = parseArgs(["bun", "script.ts", "--peerbloomfilters=1"]);
    expect(result.config.peerBloomFilters).toBe(true);
  });

  test("parses --peer-bloom-filters=false (kebab-case alias)", () => {
    const result = parseArgs(["bun", "script.ts", "--peer-bloom-filters=false"]);
    expect(result.config.peerBloomFilters).toBe(false);
  });

  test("parses bare --peerbloomfilters as enable", () => {
    const result = parseArgs(["bun", "script.ts", "--peerbloomfilters"]);
    expect(result.config.peerBloomFilters).toBe(true);
  });

  test("defaults --dbcache to 512 MiB", () => {
    const result = parseArgs(["bun", "script.ts"]);
    expect(result.config.dbcacheMB).toBe(512);
  });

  test("parses --dbcache=256 (smaller cache)", () => {
    const result = parseArgs(["bun", "script.ts", "--dbcache=256"]);
    expect(result.config.dbcacheMB).toBe(256);
  });

  test("parses --dbcache=4096 (larger cache)", () => {
    const result = parseArgs(["bun", "script.ts", "--dbcache=4096"]);
    expect(result.config.dbcacheMB).toBe(4096);
  });

  test("rejects --dbcache=0 (falls back to default)", () => {
    const result = parseArgs(["bun", "script.ts", "--dbcache=0"]);
    expect(result.config.dbcacheMB).toBe(512);
  });

  test("rejects --dbcache=abc (falls back to default)", () => {
    const result = parseArgs(["bun", "script.ts", "--dbcache=abc"]);
    expect(result.config.dbcacheMB).toBe(512);
  });

  test("rejects negative --dbcache (falls back to default)", () => {
    const result = parseArgs(["bun", "script.ts", "--dbcache=-100"]);
    expect(result.config.dbcacheMB).toBe(512);
  });
});

describe("loadConfig and saveConfig", () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = path.join(os.tmpdir(), `hotbuns-test-${Date.now()}`);
    await fs.promises.mkdir(tempDir, { recursive: true });
  });

  afterEach(async () => {
    await fs.promises.rm(tempDir, { recursive: true, force: true });
  });

  test("loads config from empty directory", async () => {
    const config = await loadConfig(tempDir);
    expect(config).toEqual({});
  });

  test("saves and loads config", async () => {
    await saveConfig(tempDir, {
      network: "testnet",
      rpcPort: 18332,
      rpcUser: "alice",
      rpcPassword: "secret",
      maxOutbound: 4,
      listen: true,
      logLevel: "debug",
    });

    const loaded = await loadConfig(tempDir);
    expect(loaded.network).toBe("testnet");
    expect(loaded.rpcPort).toBe(18332);
    expect(loaded.rpcUser).toBe("alice");
    expect(loaded.rpcPassword).toBe("secret");
    expect(loaded.maxOutbound).toBe(4);
    expect(loaded.listen).toBe(true);
    expect(loaded.logLevel).toBe("debug");
  });

  test("ignores comments in config file", async () => {
    const configPath = path.join(tempDir, "hotbuns.conf");
    await Bun.write(
      configPath,
      `# This is a comment
network=testnet
# Another comment
rpcuser=bob
`
    );

    const config = await loadConfig(tempDir);
    expect(config.network).toBe("testnet");
    expect(config.rpcUser).toBe("bob");
  });

  test("handles missing values in config file", async () => {
    const configPath = path.join(tempDir, "hotbuns.conf");
    await Bun.write(configPath, `network=regtest\n`);

    const config = await loadConfig(tempDir);
    expect(config.network).toBe("regtest");
    expect(config.rpcPort).toBeUndefined();
  });

  test("creates datadir if it does not exist", async () => {
    const subDir = path.join(tempDir, "subdir", "deep");
    await loadConfig(subDir);

    const stat = await fs.promises.stat(subDir);
    expect(stat.isDirectory()).toBe(true);
  });

  test("parses peerbloomfilters=0 in config file", async () => {
    const configPath = path.join(tempDir, "hotbuns.conf");
    await Bun.write(configPath, `peerbloomfilters=0\n`);

    const config = await loadConfig(tempDir);
    expect(config.peerBloomFilters).toBe(false);
  });

  test("parses peerbloomfilters=1 in config file", async () => {
    const configPath = path.join(tempDir, "hotbuns.conf");
    await Bun.write(configPath, `peerbloomfilters=1\n`);

    const config = await loadConfig(tempDir);
    expect(config.peerBloomFilters).toBe(true);
  });

  test("parses dbcache=2048 in config file", async () => {
    const configPath = path.join(tempDir, "hotbuns.conf");
    await Bun.write(configPath, `dbcache=2048\n`);

    const config = await loadConfig(tempDir);
    expect(config.dbcacheMB).toBe(2048);
  });

  test("ignores dbcache=0 in config file", async () => {
    const configPath = path.join(tempDir, "hotbuns.conf");
    await Bun.write(configPath, `dbcache=0\n`);

    const config = await loadConfig(tempDir);
    expect(config.dbcacheMB).toBeUndefined();
  });
});

describe("formatRpcRequest", () => {
  test("formats RPC request correctly", () => {
    const config = {
      datadir: "/tmp",
      network: "mainnet" as const,
      rpcPort: 8332,
      rpcUser: "alice",
      rpcPassword: "password123",
      maxOutbound: 8,
      listen: true,
      port: 8333,
      logLevel: "info" as const,
      metricsPort: 0,
      peerBloomFilters: true,
      dbcacheMB: 512,
      daemon: false,
      internalDaemonChild: false,
    };

    const request = formatRpcRequest(config, "getblockchaininfo", []);

    expect(request.url).toBe("http://127.0.0.1:8332/");
    expect(request.headers["Content-Type"]).toBe("application/json");
    expect(request.headers["Authorization"]).toStartWith("Basic ");

    const body = JSON.parse(request.body);
    expect(body.jsonrpc).toBe("2.0");
    expect(body.id).toBe(1);
    expect(body.method).toBe("getblockchaininfo");
    expect(body.params).toEqual([]);
  });

  test("formats RPC request with params", () => {
    const config = {
      datadir: "/tmp",
      network: "testnet" as const,
      rpcPort: 18332,
      rpcUser: "user",
      rpcPassword: "pass",
      maxOutbound: 8,
      listen: true,
      port: 18333,
      logLevel: "info" as const,
      metricsPort: 0,
      peerBloomFilters: true,
      dbcacheMB: 512,
      daemon: false,
      internalDaemonChild: false,
    };

    const request = formatRpcRequest(config, "getblock", ["abc123", 1]);

    const body = JSON.parse(request.body);
    expect(body.method).toBe("getblock");
    expect(body.params).toEqual(["abc123", 1]);
  });

  test("encodes authentication correctly", () => {
    const config = {
      datadir: "/tmp",
      network: "mainnet" as const,
      rpcPort: 8332,
      rpcUser: "testuser",
      rpcPassword: "testpass",
      maxOutbound: 8,
      listen: true,
      port: 8333,
      logLevel: "info" as const,
      metricsPort: 0,
      peerBloomFilters: true,
      dbcacheMB: 512,
      daemon: false,
      internalDaemonChild: false,
    };

    const request = formatRpcRequest(config, "test", []);

    const auth = request.headers["Authorization"];
    const base64Part = auth.replace("Basic ", "");
    const decoded = Buffer.from(base64Part, "base64").toString("utf-8");
    expect(decoded).toBe("testuser:testpass");
  });
});

describe("parseArgs network defaults", () => {
  test("mainnet uses port 8333 and rpc 8332", () => {
    const result = parseArgs(["bun", "script.ts", "--network=mainnet"]);
    expect(result.config.port).toBe(8333);
    expect(result.config.rpcPort).toBe(8332);
  });

  test("testnet uses port 18333 and rpc 18332", () => {
    const result = parseArgs(["bun", "script.ts", "--network=testnet"]);
    expect(result.config.port).toBe(18333);
    expect(result.config.rpcPort).toBe(18332);
  });

  test("regtest uses port 18444 and rpc 18443", () => {
    const result = parseArgs(["bun", "script.ts", "--network=regtest"]);
    expect(result.config.port).toBe(18444);
    expect(result.config.rpcPort).toBe(18443);
  });
});

describe("parseArgs edge cases", () => {
  test("handles empty argv gracefully", () => {
    const result = parseArgs([]);
    expect(result.command).toBe("start");
    expect(result.config.network).toBe("mainnet");
  });

  test("handles unknown flags gracefully", () => {
    const result = parseArgs(["bun", "script.ts", "--unknown-flag=value"]);
    expect(result.command).toBe("start");
  });

  test("handles invalid network value", () => {
    const result = parseArgs(["bun", "script.ts", "--network=invalid"]);
    expect(result.config.network).toBe("mainnet"); // Falls back to default
  });

  test("handles invalid log level value", () => {
    const result = parseArgs(["bun", "script.ts", "--log-level=invalid"]);
    expect(result.config.logLevel).toBe("info"); // Falls back to default
  });

  test("handles flags without values", () => {
    const result = parseArgs(["bun", "script.ts", "--help"]);
    expect(result.command).toBe("help");
  });

  test("handles multiple commands (takes first)", () => {
    const result = parseArgs(["bun", "script.ts", "stop", "getinfo"]);
    expect(result.command).toBe("stop");
    expect(result.args).toContain("getinfo");
  });
});

describe("parseArgs operational flags", () => {
  test("--daemon (bare) enables daemon mode", () => {
    const result = parseArgs(["bun", "script.ts", "--daemon"]);
    expect(result.config.daemon).toBe(true);
    expect(result.config.internalDaemonChild).toBe(false);
  });

  test("--daemon=1 enables daemon mode", () => {
    const result = parseArgs(["bun", "script.ts", "--daemon=1"]);
    expect(result.config.daemon).toBe(true);
  });

  test("--daemon=0 explicitly disables daemon mode", () => {
    const result = parseArgs(["bun", "script.ts", "--daemon=0"]);
    expect(result.config.daemon).toBe(false);
  });

  test("--internal-daemon-child sets the internal flag", () => {
    const result = parseArgs([
      "bun",
      "script.ts",
      "--internal-daemon-child",
    ]);
    expect(result.config.internalDaemonChild).toBe(true);
  });

  test("--pid=<path> records pid file path", () => {
    const result = parseArgs([
      "bun",
      "script.ts",
      "--pid=/var/run/hotbuns.pid",
    ]);
    expect(result.config.pid).toBe("/var/run/hotbuns.pid");
  });

  test("--pid= (empty) preserves empty string sentinel for 'disabled'", () => {
    const result = parseArgs(["bun", "script.ts", "--pid="]);
    expect(result.config.pid).toBe("");
  });

  test("--conf=<path> stores override config path", () => {
    const result = parseArgs([
      "bun",
      "script.ts",
      "--conf=/etc/hotbuns/main.conf",
    ]);
    expect(result.config.conf).toBe("/etc/hotbuns/main.conf");
  });

  test("--printtoconsole (bare) enables console logging", () => {
    const result = parseArgs(["bun", "script.ts", "--printtoconsole"]);
    expect(result.config.printToConsole).toBe(true);
  });

  test("--print-to-console=0 disables console logging", () => {
    const result = parseArgs(["bun", "script.ts", "--print-to-console=0"]);
    expect(result.config.printToConsole).toBe(false);
  });

  test("--debug=net adds a single category", () => {
    const result = parseArgs(["bun", "script.ts", "--debug=net"]);
    expect(result.config.debug).toEqual(["net"]);
  });

  test("--debug repeats accumulate categories", () => {
    const result = parseArgs([
      "bun",
      "script.ts",
      "--debug=net",
      "--debug=mempool",
      "--debug=rpc",
    ]);
    expect(result.config.debug).toEqual(["net", "mempool", "rpc"]);
  });

  test("--debug (bare, no value) defaults to 'all'", () => {
    const result = parseArgs(["bun", "script.ts", "--debug"]);
    expect(result.config.debug).toEqual(["all"]);
  });

  test("--debug=all is preserved verbatim for the logger", () => {
    const result = parseArgs(["bun", "script.ts", "--debug=all"]);
    expect(result.config.debug).toEqual(["all"]);
  });

  test("--ready-fd=N parses to readyFd integer", () => {
    const result = parseArgs(["bun", "script.ts", "--ready-fd=3"]);
    expect(result.config.readyFd).toBe(3);
  });

  test("invalid --ready-fd is ignored", () => {
    const result = parseArgs(["bun", "script.ts", "--ready-fd=abc"]);
    expect(result.config.readyFd).toBeUndefined();
  });

  test("default config does not enable daemon or internal child", () => {
    const result = parseArgs(["bun", "script.ts"]);
    expect(result.config.daemon).toBe(false);
    expect(result.config.internalDaemonChild).toBe(false);
    expect(result.config.pid).toBeUndefined();
    expect(result.config.conf).toBeUndefined();
    expect(result.config.debug).toBeUndefined();
    expect(result.config.printToConsole).toBeUndefined();
    expect(result.config.readyFd).toBeUndefined();
  });
});

describe("loadConfig with --conf override", () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = path.join(os.tmpdir(), `hotbuns-conf-test-${Date.now()}`);
    await fs.promises.mkdir(tempDir, { recursive: true });
  });

  afterEach(async () => {
    await fs.promises.rm(tempDir, { recursive: true, force: true });
  });

  test("loads from explicit --conf absolute path", async () => {
    const altPath = path.join(tempDir, "custom.conf");
    await Bun.write(altPath, "network=testnet\nrpcuser=carol\n");

    const config = await loadConfig(tempDir, altPath);
    expect(config.network).toBe("testnet");
    expect(config.rpcUser).toBe("carol");
  });

  test("loads from explicit --conf relative-to-datadir path", async () => {
    const altPath = path.join(tempDir, "alt.conf");
    await Bun.write(altPath, "network=regtest\n");

    const config = await loadConfig(tempDir, "alt.conf");
    expect(config.network).toBe("regtest");
  });

  test("--conf override ignores default hotbuns.conf", async () => {
    // Default config file says testnet, override says regtest.  The override
    // should win and the default should be ignored entirely.
    const defaultPath = path.join(tempDir, "hotbuns.conf");
    await Bun.write(defaultPath, "network=testnet\n");
    const altPath = path.join(tempDir, "override.conf");
    await Bun.write(altPath, "network=regtest\n");

    const config = await loadConfig(tempDir, altPath);
    expect(config.network).toBe("regtest");
  });

  test("parses daemon=1 in config file", async () => {
    const altPath = path.join(tempDir, "hotbuns.conf");
    await Bun.write(altPath, "daemon=1\n");
    const config = await loadConfig(tempDir);
    expect(config.daemon).toBe(true);
  });

  test("parses pid=<path> in config file", async () => {
    const altPath = path.join(tempDir, "hotbuns.conf");
    await Bun.write(altPath, "pid=/var/run/hotbuns.pid\n");
    const config = await loadConfig(tempDir);
    expect(config.pid).toBe("/var/run/hotbuns.pid");
  });

  test("parses debug=<cat> in config file", async () => {
    const altPath = path.join(tempDir, "hotbuns.conf");
    await Bun.write(altPath, "debug=net\ndebug=mempool\n");
    const config = await loadConfig(tempDir);
    expect(config.debug).toEqual(["net", "mempool"]);
  });

  test("parses printtoconsole=1 in config file", async () => {
    const altPath = path.join(tempDir, "hotbuns.conf");
    await Bun.write(altPath, "printtoconsole=1\n");
    const config = await loadConfig(tempDir);
    expect(config.printToConsole).toBe(true);
  });
});
