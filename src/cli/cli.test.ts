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
