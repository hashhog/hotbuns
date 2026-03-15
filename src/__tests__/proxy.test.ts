/**
 * Tests for Tor/I2P Proxy Support
 *
 * Tests SOCKS5 client, Tor control, I2P SAM, and multi-network proxy manager
 * using mock servers.
 */

import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach } from "bun:test";
import type { Server, Socket } from "bun";
import {
  SOCKSVersion,
  SOCKS5Method,
  SOCKS5Command,
  SOCKS5Atyp,
  SOCKS5Reply,
  SOCKS5Client,
  TorControl,
  I2PSAM,
  ProxyManager,
  socks5ErrorString,
  getNetworkTypeFromAddress,
  networkTypeToBIP155,
  type ProxyConfig,
  type ProxyCredentials,
} from "../p2p/proxy.js";
import { BIP155Network } from "../p2p/addrv2.js";

// ============================================================================
// Mock SOCKS5 Server
// ============================================================================

interface MockSOCKS5Options {
  requireAuth?: boolean;
  validCredentials?: ProxyCredentials;
  rejectConnect?: SOCKS5Reply;
  responseDelay?: number;
}

class MockSOCKS5Server {
  private server: Server | null = null;
  private options: MockSOCKS5Options;
  port: number = 0;

  constructor(options: MockSOCKS5Options = {}) {
    this.options = options;
  }

  async start(): Promise<void> {
    this.server = Bun.listen({
      hostname: "127.0.0.1",
      port: 0,
      socket: {
        data: (socket, data) => this.handleData(socket, Buffer.from(data)),
        open: () => {},
        close: () => {},
        error: () => {},
      },
    });
    this.port = this.server.port;
  }

  stop(): void {
    this.server?.stop();
    this.server = null;
  }

  private handleData(socket: Socket, data: Buffer): void {
    // Track state on socket
    const state = (socket as any).__mockState || { phase: "method" };
    (socket as any).__mockState = state;

    if (this.options.responseDelay) {
      setTimeout(() => this.processData(socket, data, state), this.options.responseDelay);
    } else {
      this.processData(socket, data, state);
    }
  }

  private processData(socket: Socket, data: Buffer, state: any): void {
    switch (state.phase) {
      case "method":
        this.handleMethodSelection(socket, data, state);
        break;
      case "auth":
        this.handleAuth(socket, data, state);
        break;
      case "connect":
        this.handleConnect(socket, data, state);
        break;
      case "connected":
        // Forward data (echo for testing)
        socket.write(data);
        break;
    }
  }

  private handleMethodSelection(socket: Socket, data: Buffer, state: any): void {
    if (data[0] !== SOCKSVersion.SOCKS5) {
      socket.end();
      return;
    }

    const nmethods = data[1];
    const methods = Array.from(data.subarray(2, 2 + nmethods));

    let selectedMethod: SOCKS5Method;

    if (this.options.requireAuth) {
      if (methods.includes(SOCKS5Method.USER_PASS)) {
        selectedMethod = SOCKS5Method.USER_PASS;
        state.phase = "auth";
      } else {
        selectedMethod = SOCKS5Method.NO_ACCEPTABLE;
      }
    } else {
      if (methods.includes(SOCKS5Method.NO_AUTH)) {
        selectedMethod = SOCKS5Method.NO_AUTH;
        state.phase = "connect";
      } else {
        selectedMethod = SOCKS5Method.NO_ACCEPTABLE;
      }
    }

    socket.write(Buffer.from([SOCKSVersion.SOCKS5, selectedMethod]));
  }

  private handleAuth(socket: Socket, data: Buffer, state: any): void {
    // RFC 1929 format: version(1) + ulen(1) + uname(ulen) + plen(1) + passwd(plen)
    const version = data[0];
    if (version !== 0x01) {
      socket.write(Buffer.from([0x01, 0x01])); // Failure
      state.phase = "done";
      return;
    }

    const ulen = data[1];
    const username = data.subarray(2, 2 + ulen).toString();
    const plen = data[2 + ulen];
    const password = data.subarray(3 + ulen, 3 + ulen + plen).toString();

    const valid = this.options.validCredentials;
    if (valid && username === valid.username && password === valid.password) {
      socket.write(Buffer.from([0x01, 0x00])); // Success
      state.phase = "connect";
    } else if (!this.options.validCredentials) {
      // Accept any credentials if none specified
      socket.write(Buffer.from([0x01, 0x00]));
      state.phase = "connect";
    } else {
      socket.write(Buffer.from([0x01, 0x01])); // Failure
      state.phase = "done";
    }
  }

  private handleConnect(socket: Socket, data: Buffer, state: any): void {
    // SOCKS5 CONNECT request
    if (data[0] !== SOCKSVersion.SOCKS5 || data[1] !== SOCKS5Command.CONNECT) {
      socket.write(Buffer.from([
        SOCKSVersion.SOCKS5,
        SOCKS5Reply.COMMAND_NOT_SUPPORTED,
        0x00,
        SOCKS5Atyp.IPV4,
        0, 0, 0, 0,
        0, 0,
      ]));
      return;
    }

    // Check for forced rejection
    if (this.options.rejectConnect) {
      socket.write(Buffer.from([
        SOCKSVersion.SOCKS5,
        this.options.rejectConnect,
        0x00,
        SOCKS5Atyp.IPV4,
        0, 0, 0, 0,
        0, 0,
      ]));
      return;
    }

    // Parse destination
    const atyp = data[3];
    let addrEnd: number;

    switch (atyp) {
      case SOCKS5Atyp.IPV4:
        addrEnd = 4 + 4;
        break;
      case SOCKS5Atyp.DOMAINNAME:
        addrEnd = 4 + 1 + data[4];
        break;
      case SOCKS5Atyp.IPV6:
        addrEnd = 4 + 16;
        break;
      default:
        socket.write(Buffer.from([
          SOCKSVersion.SOCKS5,
          SOCKS5Reply.ADDRESS_TYPE_NOT_SUPPORTED,
          0x00,
          SOCKS5Atyp.IPV4,
          0, 0, 0, 0,
          0, 0,
        ]));
        return;
    }

    // Success response
    socket.write(Buffer.from([
      SOCKSVersion.SOCKS5,
      SOCKS5Reply.SUCCEEDED,
      0x00,
      SOCKS5Atyp.IPV4,
      127, 0, 0, 1, // Bound address
      0x1f, 0x90,   // Bound port (8080)
    ]));

    state.phase = "connected";
  }
}

// ============================================================================
// Mock Tor Control Server
// ============================================================================

class MockTorControlServer {
  private server: Server | null = null;
  private password: string;
  private onionAddress: string;
  port: number = 0;

  constructor(password: string = "", onionAddress: string = "testserviceid1234567890123456") {
    this.password = password;
    this.onionAddress = onionAddress;
  }

  async start(): Promise<void> {
    this.server = Bun.listen({
      hostname: "127.0.0.1",
      port: 0,
      socket: {
        data: (socket, data) => this.handleData(socket, Buffer.from(data).toString()),
        open: () => {},
        close: () => {},
        error: () => {},
      },
    });
    this.port = this.server.port;
  }

  stop(): void {
    this.server?.stop();
    this.server = null;
  }

  private handleData(socket: Socket, data: string): void {
    const lines = data.trim().split("\r\n");

    for (const line of lines) {
      const parts = line.split(" ");
      const command = parts[0].toUpperCase();

      switch (command) {
        case "AUTHENTICATE":
          this.handleAuthenticate(socket, line);
          break;
        case "ADD_ONION":
          this.handleAddOnion(socket, line);
          break;
        case "DEL_ONION":
          this.handleDelOnion(socket, line);
          break;
        default:
          socket.write("510 Unrecognized command\r\n");
      }
    }
  }

  private handleAuthenticate(socket: Socket, line: string): void {
    if (this.password) {
      const match = line.match(/AUTHENTICATE "([^"]+)"/);
      if (match && match[1] === this.password) {
        socket.write("250 OK\r\n");
      } else {
        socket.write("515 Bad authentication\r\n");
      }
    } else {
      socket.write("250 OK\r\n");
    }
  }

  private handleAddOnion(socket: Socket, _line: string): void {
    const response = [
      `250-ServiceID=${this.onionAddress}`,
      `250-PrivateKey=ED25519-V3:testkeydata`,
      "250 OK",
    ].join("\r\n") + "\r\n";

    socket.write(response);
  }

  private handleDelOnion(socket: Socket, _line: string): void {
    socket.write("250 OK\r\n");
  }
}

// ============================================================================
// Mock I2P SAM Server
// ============================================================================

class MockI2PSAMServer {
  private server: Server | null = null;
  private sessionCreated: boolean = false;
  private destination: string;
  private fakePrivKey: Buffer;
  port: number = 0;

  constructor(destination: string = "testdestination1234567890") {
    this.destination = destination;
    // Generate a fake private key (500 bytes with cert_len=0)
    this.fakePrivKey = Buffer.alloc(500).fill(0x41);
    this.fakePrivKey.writeUInt16BE(0, 385); // cert_len = 0
  }

  async start(): Promise<void> {
    this.server = Bun.listen({
      hostname: "127.0.0.1",
      port: 0,
      socket: {
        data: (socket, data) => this.handleData(socket, Buffer.from(data).toString()),
        open: () => {},
        close: () => {},
        error: () => {},
      },
    });
    this.port = this.server.port;
  }

  stop(): void {
    this.server?.stop();
    this.server = null;
  }

  private encodeI2PBase64(data: Buffer): string {
    return data.toString("base64").replace(/\+/g, "-").replace(/\//g, "~");
  }

  private handleData(socket: Socket, data: string): void {
    const lines = data.trim().split("\n");
    for (const line of lines) {
      this.handleLine(socket, line.trim());
    }
  }

  private handleLine(socket: Socket, line: string): void {
    const parts = line.split(" ");
    const command = parts[0];

    switch (command) {
      case "HELLO":
        socket.write("HELLO REPLY RESULT=OK VERSION=3.1\n");
        break;
      case "DEST":
        if (parts[1] === "GENERATE") {
          const encoded = this.encodeI2PBase64(this.fakePrivKey);
          socket.write(`DEST REPLY PUB=${this.destination} PRIV=${encoded}\n`);
        }
        break;
      case "SESSION":
        if (parts[1] === "CREATE") {
          this.sessionCreated = true;
          // For transient sessions, return a DESTINATION in the response
          const isTransient = line.includes("DESTINATION=TRANSIENT");
          if (isTransient) {
            const encoded = this.encodeI2PBase64(this.fakePrivKey);
            socket.write(`SESSION STATUS RESULT=OK DESTINATION=${encoded}\n`);
          } else {
            socket.write("SESSION STATUS RESULT=OK\n");
          }
        }
        break;
      case "STREAM":
        if (parts[1] === "CONNECT") {
          socket.write("STREAM STATUS RESULT=OK\n");
        } else if (parts[1] === "ACCEPT") {
          socket.write("STREAM STATUS RESULT=OK\n");
          // Send peer destination after a short delay
          setTimeout(() => {
            socket.write(`${this.destination}\n`);
          }, 10);
        }
        break;
      case "NAMING":
        if (parts[1] === "LOOKUP") {
          const name = parts.find((p) => p.startsWith("NAME="))?.substring(5);
          socket.write(`NAMING REPLY RESULT=OK NAME=${name} VALUE=${this.destination}\n`);
        }
        break;
      default:
        // Ignore empty lines or unknown commands
        if (line.length > 0) {
          socket.write("ERROR unknown command\n");
        }
    }
  }
}

// ============================================================================
// Tests
// ============================================================================

describe("SOCKS5 Error Messages", () => {
  it("should return correct error strings for all reply codes", () => {
    expect(socks5ErrorString(SOCKS5Reply.SUCCEEDED)).toBe("success");
    expect(socks5ErrorString(SOCKS5Reply.GENERAL_FAILURE)).toBe("general failure");
    expect(socks5ErrorString(SOCKS5Reply.NOT_ALLOWED)).toBe("connection not allowed");
    expect(socks5ErrorString(SOCKS5Reply.NETWORK_UNREACHABLE)).toBe("network unreachable");
    expect(socks5ErrorString(SOCKS5Reply.HOST_UNREACHABLE)).toBe("host unreachable");
    expect(socks5ErrorString(SOCKS5Reply.CONNECTION_REFUSED)).toBe("connection refused");
    expect(socks5ErrorString(SOCKS5Reply.TTL_EXPIRED)).toBe("TTL expired");
    expect(socks5ErrorString(SOCKS5Reply.COMMAND_NOT_SUPPORTED)).toBe("protocol error");
    expect(socks5ErrorString(SOCKS5Reply.ADDRESS_TYPE_NOT_SUPPORTED)).toBe("address type not supported");

    // Tor-specific errors
    expect(socks5ErrorString(SOCKS5Reply.TOR_HS_DESC_NOT_FOUND)).toBe("onion service descriptor can not be found");
    expect(socks5ErrorString(SOCKS5Reply.TOR_HS_DESC_INVALID)).toBe("onion service descriptor is invalid");
    expect(socks5ErrorString(SOCKS5Reply.TOR_HS_INTRO_FAILED)).toBe("onion service introduction failed");
    expect(socks5ErrorString(SOCKS5Reply.TOR_HS_REND_FAILED)).toBe("onion service rendezvous failed");
    expect(socks5ErrorString(SOCKS5Reply.TOR_HS_MISSING_CLIENT_AUTH)).toBe("onion service missing client authorization");
    expect(socks5ErrorString(SOCKS5Reply.TOR_HS_WRONG_CLIENT_AUTH)).toBe("onion service wrong client authorization");
    expect(socks5ErrorString(SOCKS5Reply.TOR_HS_BAD_ADDRESS)).toBe("onion service invalid address");
    expect(socks5ErrorString(SOCKS5Reply.TOR_HS_INTRO_TIMEOUT)).toBe("onion service introduction timed out");

    // Unknown code
    expect(socks5ErrorString(0x99 as SOCKS5Reply)).toBe("unknown (0x99)");
  });
});

describe("Network Type Detection", () => {
  it("should detect IPv4 addresses", () => {
    expect(getNetworkTypeFromAddress("192.168.1.1")).toBe("ipv4");
    expect(getNetworkTypeFromAddress("8.8.8.8")).toBe("ipv4");
    expect(getNetworkTypeFromAddress("example.com")).toBe("ipv4");
  });

  it("should detect IPv6 addresses", () => {
    expect(getNetworkTypeFromAddress("::1")).toBe("ipv6");
    expect(getNetworkTypeFromAddress("2001:db8::1")).toBe("ipv6");
    expect(getNetworkTypeFromAddress("[2001:db8::1]")).toBe("ipv6");
  });

  it("should detect CJDNS addresses", () => {
    expect(getNetworkTypeFromAddress("fc00::1")).toBe("cjdns");
    expect(getNetworkTypeFromAddress("[fc00:1234:5678::1]")).toBe("cjdns");
    expect(getNetworkTypeFromAddress("FC00::1")).toBe("cjdns");
  });

  it("should detect Tor .onion addresses", () => {
    expect(getNetworkTypeFromAddress("example1234567890123456.onion")).toBe("onion");
    expect(getNetworkTypeFromAddress("7x3xrq7r5vewqkrcqklabcdefghijklm.onion")).toBe("onion");
  });

  it("should detect I2P addresses", () => {
    expect(getNetworkTypeFromAddress("example.b32.i2p")).toBe("i2p");
    expect(getNetworkTypeFromAddress("abcd1234.i2p")).toBe("i2p");
  });

  it("should map network types to BIP155", () => {
    expect(networkTypeToBIP155("ipv4")).toBe(BIP155Network.IPV4);
    expect(networkTypeToBIP155("ipv6")).toBe(BIP155Network.IPV6);
    expect(networkTypeToBIP155("onion")).toBe(BIP155Network.TORV3);
    expect(networkTypeToBIP155("i2p")).toBe(BIP155Network.I2P);
    expect(networkTypeToBIP155("cjdns")).toBe(BIP155Network.CJDNS);
  });
});

describe("SOCKS5 Client", () => {
  let mockServer: MockSOCKS5Server;

  afterEach(() => {
    mockServer?.stop();
  });

  it("should connect without authentication", async () => {
    mockServer = new MockSOCKS5Server();
    await mockServer.start();

    const client = new SOCKS5Client({
      host: "127.0.0.1",
      port: mockServer.port,
    });

    const socket = await client.connect("example.com", 80);
    expect(socket).toBeDefined();
    socket.end();
  });

  it("should connect with username/password authentication", async () => {
    mockServer = new MockSOCKS5Server({
      requireAuth: true,
      validCredentials: { username: "testuser", password: "testpass" },
    });
    await mockServer.start();

    const client = new SOCKS5Client({
      host: "127.0.0.1",
      port: mockServer.port,
      credentials: { username: "testuser", password: "testpass" },
    });

    const socket = await client.connect("example.com", 443);
    expect(socket).toBeDefined();
    socket.end();
  });

  it("should fail with invalid credentials", async () => {
    mockServer = new MockSOCKS5Server({
      requireAuth: true,
      validCredentials: { username: "correct", password: "password" },
    });
    await mockServer.start();

    const client = new SOCKS5Client({
      host: "127.0.0.1",
      port: mockServer.port,
      credentials: { username: "wrong", password: "creds" },
    });

    await expect(client.connect("example.com", 80)).rejects.toThrow("SOCKS5:");
  });

  it("should fail when no acceptable auth method", async () => {
    mockServer = new MockSOCKS5Server({
      requireAuth: true,
    });
    await mockServer.start();

    const client = new SOCKS5Client({
      host: "127.0.0.1",
      port: mockServer.port,
      // No credentials provided
    });

    await expect(client.connect("example.com", 80)).rejects.toThrow("SOCKS5:");
  });

  it("should handle connection refused", async () => {
    mockServer = new MockSOCKS5Server({
      rejectConnect: SOCKS5Reply.CONNECTION_REFUSED,
    });
    await mockServer.start();

    const client = new SOCKS5Client({
      host: "127.0.0.1",
      port: mockServer.port,
    });

    await expect(client.connect("blocked.com", 80)).rejects.toThrow("SOCKS5:");
  });

  it("should handle host unreachable", async () => {
    mockServer = new MockSOCKS5Server({
      rejectConnect: SOCKS5Reply.HOST_UNREACHABLE,
    });
    await mockServer.start();

    const client = new SOCKS5Client({
      host: "127.0.0.1",
      port: mockServer.port,
    });

    await expect(client.connect("unreachable.com", 80)).rejects.toThrow("SOCKS5:");
  });

  it("should handle network unreachable", async () => {
    mockServer = new MockSOCKS5Server({
      rejectConnect: SOCKS5Reply.NETWORK_UNREACHABLE,
    });
    await mockServer.start();

    const client = new SOCKS5Client({
      host: "127.0.0.1",
      port: mockServer.port,
    });

    await expect(client.connect("unreachable.net", 80)).rejects.toThrow("SOCKS5:");
  });

  it("should handle Tor-specific error codes", async () => {
    mockServer = new MockSOCKS5Server({
      rejectConnect: SOCKS5Reply.TOR_HS_DESC_NOT_FOUND,
    });
    await mockServer.start();

    const client = new SOCKS5Client({
      host: "127.0.0.1",
      port: mockServer.port,
    });

    await expect(client.connect("missing.onion", 80)).rejects.toThrow("SOCKS5:");
  });

  it("should reject hostnames longer than 255 bytes", async () => {
    mockServer = new MockSOCKS5Server();
    await mockServer.start();

    const client = new SOCKS5Client({
      host: "127.0.0.1",
      port: mockServer.port,
    });

    const longHostname = "a".repeat(256);
    await expect(client.connect(longHostname, 80)).rejects.toThrow(
      "SOCKS5: hostname too long"
    );
  });

  it("should use stream isolation with unique credentials", async () => {
    mockServer = new MockSOCKS5Server({
      requireAuth: true,
    });
    await mockServer.start();

    const client = new SOCKS5Client(
      {
        host: "127.0.0.1",
        port: mockServer.port,
      },
      true // Enable stream isolation
    );

    // Both connections should succeed with auto-generated credentials
    const socket1 = await client.connect("example1.com", 80);
    socket1.end();

    const socket2 = await client.connect("example2.com", 80);
    socket2.end();
  });

  it("should connect to .onion addresses via domain name", async () => {
    mockServer = new MockSOCKS5Server();
    await mockServer.start();

    const client = new SOCKS5Client({
      host: "127.0.0.1",
      port: mockServer.port,
    });

    const socket = await client.connect(
      "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion",
      443
    );
    expect(socket).toBeDefined();
    socket.end();
  });
});

describe("Tor Control", () => {
  let mockServer: MockTorControlServer;

  afterEach(() => {
    mockServer?.stop();
  });

  it("should authenticate without password", async () => {
    mockServer = new MockTorControlServer();
    await mockServer.start();

    const control = new TorControl({
      host: "127.0.0.1",
      port: mockServer.port,
    });

    await control.connect();
    await control.authenticate();
    control.disconnect();
  });

  it("should authenticate with password", async () => {
    mockServer = new MockTorControlServer("mypassword");
    await mockServer.start();

    const control = new TorControl({
      host: "127.0.0.1",
      port: mockServer.port,
      password: "mypassword",
    });

    await control.connect();
    await control.authenticate();
    control.disconnect();
  });

  it("should fail authentication with wrong password", async () => {
    mockServer = new MockTorControlServer("correctpassword");
    await mockServer.start();

    const control = new TorControl({
      host: "127.0.0.1",
      port: mockServer.port,
      password: "wrongpassword",
    });

    await control.connect();
    await expect(control.authenticate()).rejects.toThrow(
      "TorControl: authentication failed"
    );
    control.disconnect();
  });

  it("should create hidden service", async () => {
    mockServer = new MockTorControlServer("", "myserviceid12345678901234567890");
    await mockServer.start();

    const control = new TorControl({
      host: "127.0.0.1",
      port: mockServer.port,
    });

    await control.connect();
    await control.authenticate();

    const serviceId = await control.addOnion(8333, "127.0.0.1", 8333);
    expect(serviceId).toBe("myserviceid12345678901234567890");
    expect(control.getOnionAddress()).toBe("myserviceid12345678901234567890.onion");
    expect(control.getPrivateKey()).toContain("ED25519-V3:");

    await control.delOnion();
    control.disconnect();
  });
});

describe("I2P SAM", () => {
  let mockServer: MockI2PSAMServer;

  afterEach(() => {
    mockServer?.stop();
  });

  it("should create transient session", async () => {
    mockServer = new MockI2PSAMServer();
    await mockServer.start();

    const sam = new I2PSAM({
      host: "127.0.0.1",
      port: mockServer.port,
      transient: true,
    });

    await sam.createSession();
    expect(sam.getAddress()).toContain(".b32.i2p");
    sam.close();
  });

  it("should connect to I2P destination", async () => {
    mockServer = new MockI2PSAMServer("testdest123");
    await mockServer.start();

    const sam = new I2PSAM({
      host: "127.0.0.1",
      port: mockServer.port,
      transient: true,
    });

    await sam.createSession();
    const socket = await sam.connect("target.b32.i2p");
    expect(socket).toBeDefined();
    socket.end();
    sam.close();
  });

  it("should accept incoming I2P connections", async () => {
    mockServer = new MockI2PSAMServer("peerdestination456");
    await mockServer.start();

    const sam = new I2PSAM({
      host: "127.0.0.1",
      port: mockServer.port,
      transient: true,
    });

    await sam.createSession();

    // Start accept - mock will send peer destination
    const { socket, peerDestination } = await sam.accept();
    expect(socket).toBeDefined();
    expect(peerDestination).toBe("peerdestination456");
    socket.end();
    sam.close();
  });
});

describe("ProxyManager", () => {
  let socks5Server: MockSOCKS5Server;
  let torServer: MockTorControlServer;
  let samServer: MockI2PSAMServer;

  afterEach(async () => {
    socks5Server?.stop();
    torServer?.stop();
    samServer?.stop();
  });

  it("should connect directly without proxy", async () => {
    const manager = new ProxyManager({});
    await manager.initialize();

    // Create a simple echo server for testing
    const echoServer = Bun.listen({
      hostname: "127.0.0.1",
      port: 0,
      socket: {
        data: (socket, data) => socket.write(data),
        open: () => {},
        close: () => {},
        error: () => {},
      },
    });

    try {
      const socket = await manager.connect("127.0.0.1", echoServer.port);
      expect(socket).toBeDefined();
      socket.end();
    } finally {
      echoServer.stop();
      await manager.close();
    }
  });

  it("should route clearnet through SOCKS5 proxy", async () => {
    socks5Server = new MockSOCKS5Server();
    await socks5Server.start();

    const manager = new ProxyManager({
      proxy: {
        host: "127.0.0.1",
        port: socks5Server.port,
      },
    });

    await manager.initialize();

    const socket = await manager.connect("example.com", 80);
    expect(socket).toBeDefined();
    socket.end();

    await manager.close();
  });

  it("should route .onion through onion proxy", async () => {
    socks5Server = new MockSOCKS5Server();
    await socks5Server.start();

    const onionServer = new MockSOCKS5Server();
    await onionServer.start();

    const manager = new ProxyManager({
      proxy: {
        host: "127.0.0.1",
        port: socks5Server.port,
      },
      onionProxy: {
        host: "127.0.0.1",
        port: onionServer.port,
      },
    });

    await manager.initialize();

    const socket = await manager.connect("test1234567890.onion", 80);
    expect(socket).toBeDefined();
    socket.end();

    await manager.close();
    onionServer.stop();
  });

  it("should create hidden service via Tor control", async () => {
    torServer = new MockTorControlServer("", "hiddenservice123456789012345678");
    await torServer.start();

    const manager = new ProxyManager({
      torControl: {
        host: "127.0.0.1",
        port: torServer.port,
      },
    });

    await manager.initialize();

    const onionAddr = await manager.createHiddenService(8333, "127.0.0.1", 8333);
    expect(onionAddr).toBe("hiddenservice123456789012345678.onion");
    expect(manager.getOnionAddress()).toBe("hiddenservice123456789012345678.onion");

    await manager.close();
  });

  it("should route I2P addresses through SAM", async () => {
    samServer = new MockI2PSAMServer();
    await samServer.start();

    const manager = new ProxyManager({
      i2pSam: {
        host: "127.0.0.1",
        port: samServer.port,
        transient: true,
      },
    });

    await manager.initialize();

    expect(manager.getI2PAddress()).toContain(".b32.i2p");

    const socket = await manager.connect("target.b32.i2p", 0);
    expect(socket).toBeDefined();
    socket.end();

    await manager.close();
  });

  it("should check network reachability", async () => {
    socks5Server = new MockSOCKS5Server();
    await socks5Server.start();

    samServer = new MockI2PSAMServer();
    await samServer.start();

    const manager = new ProxyManager({
      onionProxy: {
        host: "127.0.0.1",
        port: socks5Server.port,
      },
      i2pSam: {
        host: "127.0.0.1",
        port: samServer.port,
        transient: true,
      },
    });

    await manager.initialize();

    expect(manager.isReachable("ipv4")).toBe(true);
    expect(manager.isReachable("ipv6")).toBe(true);
    expect(manager.isReachable("onion")).toBe(true);
    expect(manager.isReachable("i2p")).toBe(true);
    expect(manager.isReachable("cjdns")).toBe(true);

    await manager.close();
  });

  it("should fail I2P connect without SAM configured", async () => {
    const manager = new ProxyManager({});
    await manager.initialize();

    await expect(manager.connect("test.b32.i2p", 0)).rejects.toThrow(
      "ProxyManager: I2P SAM not configured"
    );

    await manager.close();
  });

  it("should fail .onion connect without proxy configured", async () => {
    const manager = new ProxyManager({});
    await manager.initialize();

    await expect(manager.connect("test.onion", 80)).rejects.toThrow(
      "ProxyManager: no proxy configured for .onion addresses"
    );

    await manager.close();
  });
});

describe("SOCKS5 Constants", () => {
  it("should have correct SOCKS5 version value", () => {
    expect(SOCKSVersion.SOCKS5).toBe(0x05);
    expect(SOCKSVersion.SOCKS4).toBe(0x04);
  });

  it("should have correct SOCKS5 method values", () => {
    expect(SOCKS5Method.NO_AUTH).toBe(0x00);
    expect(SOCKS5Method.GSSAPI).toBe(0x01);
    expect(SOCKS5Method.USER_PASS).toBe(0x02);
    expect(SOCKS5Method.NO_ACCEPTABLE).toBe(0xff);
  });

  it("should have correct SOCKS5 command values", () => {
    expect(SOCKS5Command.CONNECT).toBe(0x01);
    expect(SOCKS5Command.BIND).toBe(0x02);
    expect(SOCKS5Command.UDP_ASSOCIATE).toBe(0x03);
  });

  it("should have correct SOCKS5 address type values", () => {
    expect(SOCKS5Atyp.IPV4).toBe(0x01);
    expect(SOCKS5Atyp.DOMAINNAME).toBe(0x03);
    expect(SOCKS5Atyp.IPV6).toBe(0x04);
  });
});
