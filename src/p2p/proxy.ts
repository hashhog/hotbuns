/**
 * Tor/I2P Proxy Support for Bitcoin P2P Connections
 *
 * Implements SOCKS5 proxy, Tor control protocol for hidden services,
 * and I2P SAM protocol for anonymous networking.
 *
 * Reference:
 * - RFC 1928 (SOCKS5 Protocol)
 * - RFC 1929 (SOCKS5 Username/Password Auth)
 * - Tor Control Protocol: https://spec.torproject.org/control-spec
 * - I2P SAM: https://geti2p.net/en/docs/api/samv3
 * - Bitcoin Core: src/netbase.cpp, src/i2p.cpp
 */

import type { Socket, TCPSocketListener } from "bun";
import { BIP155Network } from "./addrv2.js";

// ============================================================================
// Types & Constants
// ============================================================================

/** SOCKS protocol version */
export const enum SOCKSVersion {
  SOCKS4 = 0x04,
  SOCKS5 = 0x05,
}

/** SOCKS5 authentication methods (RFC 1928) */
export const enum SOCKS5Method {
  NO_AUTH = 0x00,
  GSSAPI = 0x01,
  USER_PASS = 0x02,
  NO_ACCEPTABLE = 0xff,
}

/** SOCKS5 command types (RFC 1928) */
export const enum SOCKS5Command {
  CONNECT = 0x01,
  BIND = 0x02,
  UDP_ASSOCIATE = 0x03,
}

/** SOCKS5 address types (RFC 1928) */
export const enum SOCKS5Atyp {
  IPV4 = 0x01,
  DOMAINNAME = 0x03,
  IPV6 = 0x04,
}

/** SOCKS5 reply codes (RFC 1928 + Tor extensions) */
export const enum SOCKS5Reply {
  SUCCEEDED = 0x00,
  GENERAL_FAILURE = 0x01,
  NOT_ALLOWED = 0x02,
  NETWORK_UNREACHABLE = 0x03,
  HOST_UNREACHABLE = 0x04,
  CONNECTION_REFUSED = 0x05,
  TTL_EXPIRED = 0x06,
  COMMAND_NOT_SUPPORTED = 0x07,
  ADDRESS_TYPE_NOT_SUPPORTED = 0x08,
  // Tor-specific error codes
  TOR_HS_DESC_NOT_FOUND = 0xf0,
  TOR_HS_DESC_INVALID = 0xf1,
  TOR_HS_INTRO_FAILED = 0xf2,
  TOR_HS_REND_FAILED = 0xf3,
  TOR_HS_MISSING_CLIENT_AUTH = 0xf4,
  TOR_HS_WRONG_CLIENT_AUTH = 0xf5,
  TOR_HS_BAD_ADDRESS = 0xf6,
  TOR_HS_INTRO_TIMEOUT = 0xf7,
}

/** I2P SAM default port used for Bitcoin */
export const I2P_SAM31_PORT = 0;

/** Proxy credentials for authentication */
export interface ProxyCredentials {
  username: string;
  password: string;
}

/** Proxy configuration */
export interface ProxyConfig {
  host: string;
  port: number;
  credentials?: ProxyCredentials;
}

/** Tor control configuration */
export interface TorControlConfig {
  host: string;
  port: number;
  password?: string;
  cookieFile?: string;
}

/** I2P SAM configuration */
export interface I2PSAMConfig {
  host: string;
  port: number;
  privateKeyFile?: string;
  transient?: boolean;
}

/** Network type for routing decisions */
export type NetworkType = "ipv4" | "ipv6" | "onion" | "i2p" | "cjdns";

/** Multi-proxy configuration */
export interface MultiProxyConfig {
  /** Default SOCKS5 proxy for all outbound connections */
  proxy?: ProxyConfig;
  /** Separate proxy for .onion addresses */
  onionProxy?: ProxyConfig;
  /** Tor control for hidden service */
  torControl?: TorControlConfig;
  /** I2P SAM bridge */
  i2pSam?: I2PSAMConfig;
  /** Enable stream isolation (unique credentials per connection for Tor) */
  streamIsolation?: boolean;
}

/** Result of a proxy connection */
export interface ProxyConnection {
  socket: Socket;
  boundAddress?: string;
  boundPort?: number;
}

// ============================================================================
// SOCKS5 Error Messages
// ============================================================================

/**
 * Convert SOCKS5 reply code to human-readable message.
 * Matches Bitcoin Core's Socks5ErrorString() in netbase.cpp.
 */
export function socks5ErrorString(reply: SOCKS5Reply): string {
  switch (reply) {
    case SOCKS5Reply.SUCCEEDED:
      return "success";
    case SOCKS5Reply.GENERAL_FAILURE:
      return "general failure";
    case SOCKS5Reply.NOT_ALLOWED:
      return "connection not allowed";
    case SOCKS5Reply.NETWORK_UNREACHABLE:
      return "network unreachable";
    case SOCKS5Reply.HOST_UNREACHABLE:
      return "host unreachable";
    case SOCKS5Reply.CONNECTION_REFUSED:
      return "connection refused";
    case SOCKS5Reply.TTL_EXPIRED:
      return "TTL expired";
    case SOCKS5Reply.COMMAND_NOT_SUPPORTED:
      return "protocol error";
    case SOCKS5Reply.ADDRESS_TYPE_NOT_SUPPORTED:
      return "address type not supported";
    case SOCKS5Reply.TOR_HS_DESC_NOT_FOUND:
      return "onion service descriptor can not be found";
    case SOCKS5Reply.TOR_HS_DESC_INVALID:
      return "onion service descriptor is invalid";
    case SOCKS5Reply.TOR_HS_INTRO_FAILED:
      return "onion service introduction failed";
    case SOCKS5Reply.TOR_HS_REND_FAILED:
      return "onion service rendezvous failed";
    case SOCKS5Reply.TOR_HS_MISSING_CLIENT_AUTH:
      return "onion service missing client authorization";
    case SOCKS5Reply.TOR_HS_WRONG_CLIENT_AUTH:
      return "onion service wrong client authorization";
    case SOCKS5Reply.TOR_HS_BAD_ADDRESS:
      return "onion service invalid address";
    case SOCKS5Reply.TOR_HS_INTRO_TIMEOUT:
      return "onion service introduction timed out";
    default:
      return `unknown (0x${reply.toString(16).padStart(2, "0")})`;
  }
}

// ============================================================================
// SOCKS5 Client
// ============================================================================

/** SOCKS5 receive timeout (20 seconds, needs ample time for slow proxies like Tor) */
export const SOCKS5_RECV_TIMEOUT_MS = 20_000;

/**
 * SOCKS5 client for connecting through a proxy.
 *
 * Implements RFC 1928 (SOCKS5 Protocol) and RFC 1929 (Username/Password Auth).
 * Supports:
 * - No authentication (method 0x00)
 * - Username/password authentication (method 0x02)
 * - Domain name resolution through proxy (ATYP 0x03)
 *
 * Reference: Bitcoin Core netbase.cpp Socks5()
 */
export class SOCKS5Client {
  private config: ProxyConfig;
  private streamIsolation: boolean;
  private isolationCounter: number;
  private isolationPrefix: string;

  constructor(config: ProxyConfig, streamIsolation: boolean = false) {
    this.config = config;
    this.streamIsolation = streamIsolation;
    this.isolationCounter = 0;
    // Generate random prefix for stream isolation (like Bitcoin Core)
    this.isolationPrefix = this.generateIsolationPrefix();
  }

  /**
   * Generate a random prefix for stream isolation credentials.
   * This ensures different application launches use different circuits.
   */
  private generateIsolationPrefix(): string {
    const bytes = new Uint8Array(8);
    crypto.getRandomValues(bytes);
    return Array.from(bytes)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  }

  /**
   * Get stream isolation credentials.
   * Each call returns unique credentials to force Tor to use different circuits.
   */
  private getIsolationCredentials(): ProxyCredentials {
    const id = `${this.isolationPrefix}${this.isolationCounter++}`;
    return { username: id, password: id };
  }

  /**
   * Connect to a destination through the SOCKS5 proxy.
   *
   * @param dest - Hostname or IP address to connect to
   * @param port - Port number
   * @returns Connected socket ready for application data
   * @throws Error if connection fails
   */
  async connect(dest: string, port: number): Promise<Socket> {
    // Validate destination length (max 255 bytes for domain names)
    if (dest.length > 255) {
      throw new Error("SOCKS5: hostname too long (max 255 bytes)");
    }

    // Connect to proxy server and perform handshake
    const { socket, recvBuffer } = await this.connectAndHandshake(dest, port);

    // Store any leftover data for application to read
    if (recvBuffer.length > 0) {
      (socket as any).__leftoverData = recvBuffer;
    }

    return socket;
  }

  /**
   * Connect to proxy and perform SOCKS5 handshake.
   * Returns socket and any leftover data in buffer.
   */
  private async connectAndHandshake(
    dest: string,
    port: number
  ): Promise<{ socket: Socket; recvBuffer: Buffer }> {
    // Determine credentials to use
    const credentials = this.streamIsolation
      ? this.getIsolationCredentials()
      : this.config.credentials;

    return new Promise((resolve, reject) => {
      let socket: Socket;
      let recvBuffer = Buffer.alloc(0);
      let phase: "method" | "auth" | "connect" | "response" = "method";
      let responseExpected = 0;
      let timeoutId: ReturnType<typeof setTimeout>;

      const cleanup = () => {
        clearTimeout(timeoutId);
      };

      const fail = (error: Error) => {
        cleanup();
        socket?.end();
        reject(error);
      };

      timeoutId = setTimeout(() => {
        fail(new Error("SOCKS5: timeout reading from proxy"));
      }, SOCKS5_RECV_TIMEOUT_MS);

      Bun.connect({
        hostname: this.config.host,
        port: this.config.port,
        socket: {
          open(sock) {
            socket = sock;
            // Step 1: Send method selection
            const methodSelection = credentials
              ? Buffer.from([
                  SOCKSVersion.SOCKS5,
                  0x02,
                  SOCKS5Method.NO_AUTH,
                  SOCKS5Method.USER_PASS,
                ])
              : Buffer.from([
                  SOCKSVersion.SOCKS5,
                  0x01,
                  SOCKS5Method.NO_AUTH,
                ]);
            socket.write(methodSelection);
          },
          data(_sock, data) {
            recvBuffer = Buffer.concat([recvBuffer, Buffer.from(data)]);

            // Process based on current phase
            while (recvBuffer.length > 0) {
              if (phase === "method") {
                if (recvBuffer.length < 2) return;

                if (recvBuffer[0] !== SOCKSVersion.SOCKS5) {
                  fail(new Error("SOCKS5: proxy failed to initialize"));
                  return;
                }

                const selectedMethod = recvBuffer[1] as SOCKS5Method;
                recvBuffer = recvBuffer.subarray(2);

                if (selectedMethod === SOCKS5Method.USER_PASS && credentials) {
                  // Send auth
                  const authRequest = Buffer.alloc(
                    3 + credentials.username.length + credentials.password.length
                  );
                  let offset = 0;
                  authRequest[offset++] = 0x01;
                  authRequest[offset++] = credentials.username.length;
                  Buffer.from(credentials.username).copy(authRequest, offset);
                  offset += credentials.username.length;
                  authRequest[offset++] = credentials.password.length;
                  Buffer.from(credentials.password).copy(authRequest, offset);
                  socket.write(authRequest);
                  phase = "auth";
                } else if (selectedMethod === SOCKS5Method.NO_AUTH) {
                  // Send CONNECT request
                  const destBytes = Buffer.from(dest);
                  const request = Buffer.alloc(4 + 1 + destBytes.length + 2);
                  let offset = 0;
                  request[offset++] = SOCKSVersion.SOCKS5;
                  request[offset++] = SOCKS5Command.CONNECT;
                  request[offset++] = 0x00;
                  request[offset++] = SOCKS5Atyp.DOMAINNAME;
                  request[offset++] = destBytes.length;
                  destBytes.copy(request, offset);
                  offset += destBytes.length;
                  request.writeUInt16BE(port, offset);
                  socket.write(request);
                  phase = "connect";
                } else if (selectedMethod === SOCKS5Method.NO_ACCEPTABLE) {
                  fail(new Error("SOCKS5: no acceptable authentication method"));
                  return;
                } else {
                  fail(new Error(`SOCKS5: proxy requested unsupported auth method 0x${selectedMethod.toString(16)}`));
                  return;
                }
              } else if (phase === "auth") {
                if (recvBuffer.length < 2) return;

                if (recvBuffer[0] !== 0x01 || recvBuffer[1] !== 0x00) {
                  fail(new Error("SOCKS5: authentication failed"));
                  return;
                }
                recvBuffer = recvBuffer.subarray(2);

                // Send CONNECT request
                const destBytes = Buffer.from(dest);
                const request = Buffer.alloc(4 + 1 + destBytes.length + 2);
                let offset = 0;
                request[offset++] = SOCKSVersion.SOCKS5;
                request[offset++] = SOCKS5Command.CONNECT;
                request[offset++] = 0x00;
                request[offset++] = SOCKS5Atyp.DOMAINNAME;
                request[offset++] = destBytes.length;
                destBytes.copy(request, offset);
                offset += destBytes.length;
                request.writeUInt16BE(port, offset);
                socket.write(request);
                phase = "connect";
              } else if (phase === "connect") {
                if (recvBuffer.length < 4) return;

                if (recvBuffer[0] !== SOCKSVersion.SOCKS5) {
                  fail(new Error("SOCKS5: invalid response version"));
                  return;
                }

                const reply = recvBuffer[1] as SOCKS5Reply;
                if (reply !== SOCKS5Reply.SUCCEEDED) {
                  fail(new Error(`SOCKS5: ${socks5ErrorString(reply)}`));
                  return;
                }

                if (recvBuffer[2] !== 0x00) {
                  fail(new Error("SOCKS5: malformed response (reserved != 0)"));
                  return;
                }

                const atyp = recvBuffer[3] as SOCKS5Atyp;
                let addrLen: number;
                switch (atyp) {
                  case SOCKS5Atyp.IPV4:
                    addrLen = 4;
                    break;
                  case SOCKS5Atyp.IPV6:
                    addrLen = 16;
                    break;
                  case SOCKS5Atyp.DOMAINNAME:
                    if (recvBuffer.length < 5) return;
                    addrLen = 1 + recvBuffer[4];
                    break;
                  default:
                    fail(new Error(`SOCKS5: unsupported address type 0x${atyp.toString(16)}`));
                    return;
                }

                // Total response size: 4 + addrLen + 2 (port)
                const totalLen = 4 + addrLen + 2;
                if (recvBuffer.length < totalLen) return;

                // Success! Consume the response
                recvBuffer = recvBuffer.subarray(totalLen);
                phase = "response";

                cleanup();
                resolve({ socket, recvBuffer });
                return;
              } else {
                // Already resolved, shouldn't happen
                return;
              }
            }
          },
          close() {
            if (phase !== "response") {
              fail(new Error("SOCKS5: connection closed"));
            }
          },
          error(_sock, error) {
            fail(error);
          },
          connectError(_sock, error) {
            fail(error);
          },
        },
      }).catch(reject);
    });
  }
}

// ============================================================================
// Tor Control Protocol
// ============================================================================

/**
 * Tor control protocol client.
 *
 * Implements subset of the Tor control protocol for:
 * - Authentication (AUTHENTICATE)
 * - Hidden service creation (ADD_ONION)
 * - Hidden service removal (DEL_ONION)
 *
 * Reference: https://spec.torproject.org/control-spec
 */
export class TorControl {
  private config: TorControlConfig;
  private socket: Socket | null = null;
  private serviceId: string | null = null;
  private privateKey: string | null = null;
  private recvBuffer: string = "";
  private pendingResolve: ((value: string) => void) | null = null;
  private pendingReject: ((error: Error) => void) | null = null;
  private pendingTimeout: ReturnType<typeof setTimeout> | null = null;

  constructor(config: TorControlConfig) {
    this.config = config;
  }

  /**
   * Connect to the Tor control port.
   */
  async connect(): Promise<void> {
    this.socket = await new Promise<Socket>((resolve, reject) => {
      Bun.connect({
        hostname: this.config.host,
        port: this.config.port,
        socket: {
          open: (socket) => {
            resolve(socket);
          },
          data: (_sock, data) => {
            this.handleData(Buffer.from(data).toString("utf-8"));
          },
          close: () => {},
          error: (_socket, error) => {
            if (this.pendingReject) {
              this.pendingReject(error);
              this.pendingResolve = null;
              this.pendingReject = null;
            } else {
              reject(error);
            }
          },
          connectError: (_socket, error) => {
            reject(error);
          },
        },
      }).catch(reject);
    });
  }

  private handleData(data: string): void {
    this.recvBuffer += data;

    // Check for complete response (line starting with "250 " or error code "5xx ")
    const lines = this.recvBuffer.split("\r\n");
    for (const line of lines) {
      // Final response line: "250 OK" or "5xx ..."
      if (/^\d{3} /.test(line)) {
        const response = this.recvBuffer;
        this.recvBuffer = "";

        if (this.pendingTimeout) {
          clearTimeout(this.pendingTimeout);
          this.pendingTimeout = null;
        }

        if (this.pendingResolve) {
          this.pendingResolve(response);
          this.pendingResolve = null;
          this.pendingReject = null;
        }
        return;
      }
    }
  }

  /**
   * Authenticate with the Tor control port.
   *
   * Supports:
   * - Password authentication
   * - Cookie file authentication
   */
  async authenticate(): Promise<void> {
    if (!this.socket) {
      throw new Error("TorControl: not connected");
    }

    let authData: string;

    if (this.config.cookieFile) {
      // Read cookie from file
      const file = Bun.file(this.config.cookieFile);
      const cookie = await file.arrayBuffer();
      authData = Buffer.from(cookie).toString("hex");
    } else if (this.config.password) {
      // Use password (quote it for the command)
      authData = `"${this.config.password}"`;
    } else {
      // Try null authentication
      authData = "";
    }

    const response = await this.sendCommand(`AUTHENTICATE ${authData}`);
    if (!response.startsWith("250")) {
      throw new Error(`TorControl: authentication failed: ${response}`);
    }
  }

  /**
   * Create a new Tor hidden service.
   *
   * @param virtualPort - Port exposed on the .onion address
   * @param targetHost - Local host to forward to
   * @param targetPort - Local port to forward to
   * @param existingKey - Optional existing private key to reuse
   * @returns The .onion address (without .onion suffix)
   */
  async addOnion(
    virtualPort: number,
    targetHost: string,
    targetPort: number,
    existingKey?: string
  ): Promise<string> {
    if (!this.socket) {
      throw new Error("TorControl: not connected");
    }

    // Build ADD_ONION command
    // Format: ADD_ONION KeyType:KeyBlob [Flags] Port=<virt>[,<target>]
    const keySpec = existingKey || "NEW:ED25519-V3";
    const portSpec = `Port=${virtualPort},${targetHost}:${targetPort}`;
    const command = `ADD_ONION ${keySpec} ${portSpec}`;

    const response = await this.sendCommand(command);

    // Parse response
    // 250-ServiceID=<onion_address>
    // 250-PrivateKey=<key_type>:<key_blob>
    // 250 OK
    const lines = response.split("\r\n");
    for (const line of lines) {
      if (line.startsWith("250-ServiceID=")) {
        this.serviceId = line.substring("250-ServiceID=".length);
      } else if (line.startsWith("250-PrivateKey=")) {
        this.privateKey = line.substring("250-".length);
      }
    }

    if (!this.serviceId) {
      throw new Error(`TorControl: failed to create hidden service: ${response}`);
    }

    return this.serviceId;
  }

  /**
   * Remove the hidden service.
   */
  async delOnion(): Promise<void> {
    if (!this.socket || !this.serviceId) {
      return;
    }

    const response = await this.sendCommand(`DEL_ONION ${this.serviceId}`);
    if (!response.startsWith("250")) {
      throw new Error(`TorControl: failed to remove hidden service: ${response}`);
    }

    this.serviceId = null;
    this.privateKey = null;
  }

  /**
   * Get the current service ID (.onion address without suffix).
   */
  getServiceId(): string | null {
    return this.serviceId;
  }

  /**
   * Get the full .onion address.
   */
  getOnionAddress(): string | null {
    return this.serviceId ? `${this.serviceId}.onion` : null;
  }

  /**
   * Get the private key for the hidden service (for persistence).
   */
  getPrivateKey(): string | null {
    return this.privateKey;
  }

  /**
   * Disconnect from the Tor control port.
   */
  disconnect(): void {
    if (this.socket) {
      this.socket.end();
      this.socket = null;
    }
  }

  /**
   * Send a command and receive the response.
   */
  private sendCommand(command: string): Promise<string> {
    if (!this.socket) {
      return Promise.reject(new Error("TorControl: not connected"));
    }

    return new Promise((resolve, reject) => {
      this.pendingResolve = resolve;
      this.pendingReject = reject;
      this.recvBuffer = "";

      this.pendingTimeout = setTimeout(() => {
        this.pendingResolve = null;
        this.pendingReject = null;
        reject(new Error("TorControl: command timeout"));
      }, 30_000);

      // Send command
      this.socket!.write(command + "\r\n");
    });
  }
}

// ============================================================================
// I2P SAM Protocol
// ============================================================================

/**
 * I2P SAM v3.1 client.
 *
 * Implements the SAM (Simple Anonymous Messaging) protocol for
 * connecting to the I2P network.
 *
 * Reference:
 * - https://geti2p.net/en/docs/api/samv3
 * - Bitcoin Core: src/i2p.cpp
 */
export class I2PSAM {
  private config: I2PSAMConfig;
  private controlSocket: Socket | null = null;
  private sessionId: string | null = null;
  private privateKey: Buffer | null = null;
  private myDestination: string | null = null;
  private myAddress: string | null = null;
  private recvBuffer: string = "";
  private pendingResolve: ((value: string) => void) | null = null;
  private pendingReject: ((error: Error) => void) | null = null;
  private pendingTimeout: ReturnType<typeof setTimeout> | null = null;

  constructor(config: I2PSAMConfig) {
    this.config = config;
  }

  /**
   * Create an I2P session.
   *
   * Steps:
   * 1. Connect to SAM bridge
   * 2. Send HELLO VERSION
   * 3. Generate or load private key
   * 4. Create SESSION
   */
  async createSession(): Promise<void> {
    // Connect to SAM bridge
    await this.connectToControlSocket();

    // Send HELLO
    await this.hello();

    // Load or generate private key
    await this.loadOrGeneratePrivateKey();

    // Create session
    await this.createSessionInternal();
  }

  /**
   * Connect to control socket.
   */
  private async connectToControlSocket(): Promise<void> {
    this.controlSocket = await new Promise<Socket>((resolve, reject) => {
      Bun.connect({
        hostname: this.config.host,
        port: this.config.port,
        socket: {
          open: (socket) => {
            resolve(socket);
          },
          data: (_sock, data) => {
            this.handleControlData(Buffer.from(data).toString("utf-8"));
          },
          close: () => {},
          error: (_socket, error) => {
            if (this.pendingReject) {
              this.pendingReject(error);
              this.pendingResolve = null;
              this.pendingReject = null;
            } else {
              reject(error);
            }
          },
          connectError: (_socket, error) => {
            reject(error);
          },
        },
      }).catch(reject);
    });
  }

  private handleControlData(data: string): void {
    this.recvBuffer += data;

    // SAM responses are newline-terminated
    if (this.recvBuffer.includes("\n")) {
      const response = this.recvBuffer.trim();
      this.recvBuffer = "";

      if (this.pendingTimeout) {
        clearTimeout(this.pendingTimeout);
        this.pendingTimeout = null;
      }

      if (this.pendingResolve) {
        this.pendingResolve(response);
        this.pendingResolve = null;
        this.pendingReject = null;
      }
    }
  }

  /**
   * Send HELLO VERSION to SAM.
   */
  private async hello(): Promise<void> {
    const response = await this.sendCommand("HELLO VERSION MIN=3.1 MAX=3.1");

    if (!response.includes("RESULT=OK")) {
      throw new Error(`I2PSAM: HELLO failed: ${response}`);
    }
  }

  /**
   * Load private key from file or generate new one.
   */
  private async loadOrGeneratePrivateKey(): Promise<void> {
    if (this.config.transient) {
      // Transient session - generate key during SESSION CREATE
      return;
    }

    if (this.config.privateKeyFile) {
      const file = Bun.file(this.config.privateKeyFile);
      if (await file.exists()) {
        const data = await file.arrayBuffer();
        this.privateKey = Buffer.from(data);
        return;
      }
    }

    // Generate new key using DEST GENERATE
    await this.generatePrivateKey();
  }

  /**
   * Generate a new I2P private key.
   */
  private async generatePrivateKey(): Promise<void> {
    // Use EdDSA_SHA512_Ed25519 (signature type 7)
    const response = await this.sendCommand("DEST GENERATE SIGNATURE_TYPE=7");

    // Parse PRIV from response
    const privMatch = response.match(/PRIV=([^\s]+)/);
    if (!privMatch) {
      throw new Error(`I2PSAM: failed to generate key: ${response}`);
    }

    // Decode I2P Base64 to binary
    this.privateKey = this.decodeI2PBase64(privMatch[1]);

    // Save to file if configured
    if (this.config.privateKeyFile) {
      await Bun.write(this.config.privateKeyFile, this.privateKey);
    }
  }

  /**
   * Create the SAM session.
   */
  private async createSessionInternal(): Promise<void> {
    // Generate random session ID (similar to Bitcoin Core)
    const idBytes = new Uint8Array(5);
    crypto.getRandomValues(idBytes);
    this.sessionId = Array.from(idBytes)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");

    let command: string;

    if (this.config.transient) {
      // Transient session - generate destination on the fly
      command =
        `SESSION CREATE STYLE=STREAM ID=${this.sessionId} ` +
        `DESTINATION=TRANSIENT SIGNATURE_TYPE=7 ` +
        `i2cp.leaseSetEncType=4,0 inbound.quantity=1 outbound.quantity=1`;
    } else if (this.privateKey) {
      // Persistent session - use existing key
      const keyB64 = this.encodeI2PBase64(this.privateKey);
      command =
        `SESSION CREATE STYLE=STREAM ID=${this.sessionId} ` +
        `DESTINATION=${keyB64} ` +
        `i2cp.leaseSetEncType=4,0 inbound.quantity=3 outbound.quantity=3`;
    } else {
      throw new Error("I2PSAM: no private key available");
    }

    const response = await this.sendCommand(command);

    if (!response.includes("RESULT=OK")) {
      throw new Error(`I2PSAM: SESSION CREATE failed: ${response}`);
    }

    // For transient sessions, extract the generated destination
    if (this.config.transient) {
      const destMatch = response.match(/DESTINATION=([^\s]+)/);
      if (destMatch) {
        this.privateKey = this.decodeI2PBase64(destMatch[1]);
      }
    }

    // Derive our .b32.i2p address from the destination
    if (this.privateKey) {
      this.myDestination = this.deriveDestination();
      this.myAddress = this.deriveB32Address();
    }
  }

  /**
   * Connect to an I2P destination.
   *
   * @param destination - I2P destination (base64 or .b32.i2p)
   * @returns Connected socket
   */
  async connect(destination: string): Promise<Socket> {
    if (!this.sessionId) {
      throw new Error("I2PSAM: no session");
    }

    // Create new socket for this connection with its own state
    const { socket, sendCommand } = await this.createStreamSocket();

    // Send HELLO on new socket
    const helloResponse = await sendCommand("HELLO VERSION MIN=3.1 MAX=3.1");
    if (!helloResponse.includes("RESULT=OK")) {
      socket.end();
      throw new Error(`I2PSAM: HELLO failed: ${helloResponse}`);
    }

    // Look up the destination if it's a .b32.i2p address
    let destBase64 = destination;
    if (destination.endsWith(".b32.i2p")) {
      const lookupResponse = await sendCommand(`NAMING LOOKUP NAME=${destination}`);
      const parsed = this.parseReply(lookupResponse);
      const value = parsed.get("VALUE");
      if (!value) {
        socket.end();
        throw new Error(`I2PSAM: NAMING LOOKUP failed: ${lookupResponse}`);
      }
      destBase64 = value;
    }

    // Send STREAM CONNECT
    const command = `STREAM CONNECT ID=${this.sessionId} DESTINATION=${destBase64} SILENT=false`;
    const response = await sendCommand(command);

    const result = this.parseReply(response).get("RESULT");
    if (result !== "OK") {
      socket.end();
      throw new Error(`I2PSAM: STREAM CONNECT failed: ${result}`);
    }

    return socket;
  }

  /**
   * Accept incoming I2P connections.
   *
   * @returns Socket and peer's base64 destination
   */
  async accept(): Promise<{ socket: Socket; peerDestination: string }> {
    if (!this.sessionId) {
      throw new Error("I2PSAM: no session");
    }

    // Create new socket for accepting
    const { socket, sendCommand, readLine } = await this.createStreamSocket();

    // Send HELLO on new socket
    const helloResponse = await sendCommand("HELLO VERSION MIN=3.1 MAX=3.1");
    if (!helloResponse.includes("RESULT=OK")) {
      socket.end();
      throw new Error(`I2PSAM: HELLO failed: ${helloResponse}`);
    }

    // Send STREAM ACCEPT
    const command = `STREAM ACCEPT ID=${this.sessionId} SILENT=false`;
    const response = await sendCommand(command);

    const result = this.parseReply(response).get("RESULT");
    if (result !== "OK") {
      socket.end();
      throw new Error(`I2PSAM: STREAM ACCEPT failed: ${result}`);
    }

    // Wait for incoming connection - peer destination is sent as next line
    const peerDest = await readLine();

    return { socket, peerDestination: peerDest };
  }

  /**
   * Create a stream socket with its own command/response state.
   */
  private async createStreamSocket(): Promise<{
    socket: Socket;
    sendCommand: (cmd: string) => Promise<string>;
    readLine: () => Promise<string>;
  }> {
    let recvBuffer = "";
    let pendingResolve: ((value: string) => void) | null = null;
    let pendingReject: ((error: Error) => void) | null = null;
    let pendingTimeout: ReturnType<typeof setTimeout> | null = null;

    const socket = await new Promise<Socket>((resolve, reject) => {
      Bun.connect({
        hostname: this.config.host,
        port: this.config.port,
        socket: {
          open: (sock) => {
            resolve(sock);
          },
          data: (_sock, data) => {
            recvBuffer += Buffer.from(data).toString("utf-8");

            // SAM responses are newline-terminated
            if (recvBuffer.includes("\n")) {
              const response = recvBuffer.trim();
              recvBuffer = "";

              if (pendingTimeout) {
                clearTimeout(pendingTimeout);
                pendingTimeout = null;
              }

              if (pendingResolve) {
                const resolve = pendingResolve;
                pendingResolve = null;
                pendingReject = null;
                resolve(response);
              }
            }
          },
          close: () => {
            if (pendingReject) {
              pendingReject(new Error("I2PSAM: connection closed"));
              pendingResolve = null;
              pendingReject = null;
            }
          },
          error: (_sock, error) => {
            if (pendingReject) {
              pendingReject(error);
              pendingResolve = null;
              pendingReject = null;
            } else {
              reject(error);
            }
          },
          connectError: (_sock, error) => {
            reject(error);
          },
        },
      }).catch(reject);
    });

    const sendCommand = (cmd: string): Promise<string> => {
      return new Promise((resolve, reject) => {
        pendingResolve = resolve;
        pendingReject = reject;
        recvBuffer = "";

        pendingTimeout = setTimeout(() => {
          pendingResolve = null;
          pendingReject = null;
          reject(new Error("I2PSAM: command timeout"));
        }, 180_000);

        socket.write(cmd + "\n");
      });
    };

    const readLine = (): Promise<string> => {
      return new Promise((resolve, reject) => {
        pendingResolve = resolve;
        pendingReject = reject;
        recvBuffer = "";

        pendingTimeout = setTimeout(() => {
          pendingResolve = null;
          pendingReject = null;
          reject(new Error("I2PSAM: read timeout"));
        }, 180_000);
      });
    };

    return { socket, sendCommand, readLine };
  }

  /**
   * Get our I2P address (.b32.i2p).
   */
  getAddress(): string | null {
    return this.myAddress;
  }

  /**
   * Get our full I2P destination (base64).
   */
  getDestination(): string | null {
    return this.myDestination;
  }

  /**
   * Close the SAM session.
   */
  close(): void {
    if (this.controlSocket) {
      this.controlSocket.end();
      this.controlSocket = null;
    }
    this.sessionId = null;
  }

  /**
   * Send command on control socket.
   */
  private sendCommand(command: string): Promise<string> {
    if (!this.controlSocket) {
      return Promise.reject(new Error("I2PSAM: not connected"));
    }

    return new Promise((resolve, reject) => {
      this.pendingResolve = resolve;
      this.pendingReject = reject;
      this.recvBuffer = "";

      this.pendingTimeout = setTimeout(() => {
        this.pendingResolve = null;
        this.pendingReject = null;
        reject(new Error("I2PSAM: command timeout"));
      }, 180_000);

      this.controlSocket!.write(command + "\n");
    });
  }

  /**
   * Parse SAM reply into key-value pairs.
   */
  private parseReply(reply: string): Map<string, string | undefined> {
    const result = new Map<string, string | undefined>();
    const parts = reply.split(" ");

    for (const part of parts) {
      const eqIndex = part.indexOf("=");
      if (eqIndex !== -1) {
        result.set(part.substring(0, eqIndex), part.substring(eqIndex + 1));
      } else {
        result.set(part, undefined);
      }
    }

    return result;
  }

  /**
   * Decode I2P Base64 (uses - and ~ instead of + and /).
   */
  private decodeI2PBase64(encoded: string): Buffer {
    // Convert I2P Base64 to standard Base64
    const standard = encoded.replace(/-/g, "+").replace(/~/g, "/");
    return Buffer.from(standard, "base64");
  }

  /**
   * Encode binary to I2P Base64.
   */
  private encodeI2PBase64(data: Buffer): string {
    // Convert standard Base64 to I2P Base64
    const standard = data.toString("base64");
    return standard.replace(/\+/g, "-").replace(/\//g, "~");
  }

  /**
   * Derive the base64 destination from the private key.
   * The destination is the first 387 + cert_len bytes of the private key.
   */
  private deriveDestination(): string {
    if (!this.privateKey) {
      throw new Error("I2PSAM: no private key");
    }

    const DEST_LEN_BASE = 387;
    const CERT_LEN_POS = 385;

    if (this.privateKey.length < CERT_LEN_POS + 2) {
      throw new Error("I2PSAM: private key too short");
    }

    const certLen = this.privateKey.readUInt16BE(CERT_LEN_POS);
    const destLen = DEST_LEN_BASE + certLen;

    if (destLen > this.privateKey.length) {
      throw new Error("I2PSAM: invalid certificate length");
    }

    const dest = this.privateKey.subarray(0, destLen);
    return this.encodeI2PBase64(dest);
  }

  /**
   * Derive the .b32.i2p address from the destination.
   */
  private deriveB32Address(): string {
    if (!this.privateKey) {
      throw new Error("I2PSAM: no private key");
    }

    // Get the destination portion
    const DEST_LEN_BASE = 387;
    const CERT_LEN_POS = 385;
    const certLen = this.privateKey.readUInt16BE(CERT_LEN_POS);
    const destLen = DEST_LEN_BASE + certLen;
    const dest = this.privateKey.subarray(0, destLen);

    // SHA256 hash of the destination
    const hash = new Bun.CryptoHasher("sha256").update(dest).digest();

    // Base32 encode (lowercase, no padding)
    const base32 = this.encodeBase32(Buffer.from(hash));

    return `${base32}.b32.i2p`;
  }

  /**
   * Encode buffer as lowercase base32 (no padding).
   */
  private encodeBase32(data: Buffer): string {
    const alphabet = "abcdefghijklmnopqrstuvwxyz234567";
    let result = "";
    let bits = 0;
    let value = 0;

    for (let i = 0; i < data.length; i++) {
      value = (value << 8) | data[i];
      bits += 8;

      while (bits >= 5) {
        result += alphabet[(value >>> (bits - 5)) & 31];
        bits -= 5;
      }
    }

    if (bits > 0) {
      result += alphabet[(value << (5 - bits)) & 31];
    }

    return result;
  }
}

// ============================================================================
// Multi-Network Proxy Manager
// ============================================================================

/**
 * Determines the network type from an address string.
 */
export function getNetworkTypeFromAddress(address: string): NetworkType {
  // Check for .onion (Tor v3)
  if (address.endsWith(".onion")) {
    return "onion";
  }

  // Check for .b32.i2p (I2P)
  if (address.endsWith(".b32.i2p") || address.endsWith(".i2p")) {
    return "i2p";
  }

  // Check for IPv6 (contains : or starts with [)
  if (address.includes(":") || address.startsWith("[")) {
    // CJDNS addresses start with fc
    const cleanAddr = address.replace(/^\[/, "").replace(/\].*$/, "");
    if (cleanAddr.toLowerCase().startsWith("fc")) {
      return "cjdns";
    }
    return "ipv6";
  }

  // Default to IPv4
  return "ipv4";
}

/**
 * Map NetworkType to BIP155Network.
 */
export function networkTypeToBIP155(type: NetworkType): BIP155Network {
  switch (type) {
    case "ipv4":
      return BIP155Network.IPV4;
    case "ipv6":
      return BIP155Network.IPV6;
    case "onion":
      return BIP155Network.TORV3;
    case "i2p":
      return BIP155Network.I2P;
    case "cjdns":
      return BIP155Network.CJDNS;
  }
}

/**
 * Multi-network proxy manager.
 *
 * Coordinates proxies for different network types:
 * - Clearnet (IPv4/IPv6) through optional SOCKS5 proxy
 * - Tor (.onion) through Tor SOCKS5 proxy
 * - I2P through SAM bridge
 *
 * Supports running all network types simultaneously.
 */
export class ProxyManager {
  private config: MultiProxyConfig;
  private defaultProxy: SOCKS5Client | null = null;
  private onionProxy: SOCKS5Client | null = null;
  private torControl: TorControl | null = null;
  private i2pSam: I2PSAM | null = null;
  private initialized: boolean = false;

  constructor(config: MultiProxyConfig) {
    this.config = config;
  }

  /**
   * Initialize all configured proxies.
   */
  async initialize(): Promise<void> {
    if (this.initialized) {
      return;
    }

    // Initialize default SOCKS5 proxy
    if (this.config.proxy) {
      this.defaultProxy = new SOCKS5Client(
        this.config.proxy,
        this.config.streamIsolation ?? false
      );
    }

    // Initialize separate onion proxy
    if (this.config.onionProxy) {
      this.onionProxy = new SOCKS5Client(
        this.config.onionProxy,
        this.config.streamIsolation ?? true // Always use stream isolation for Tor
      );
    }

    // Initialize Tor control for hidden service
    if (this.config.torControl) {
      this.torControl = new TorControl(this.config.torControl);
      await this.torControl.connect();
      await this.torControl.authenticate();
    }

    // Initialize I2P SAM
    if (this.config.i2pSam) {
      this.i2pSam = new I2PSAM(this.config.i2pSam);
      await this.i2pSam.createSession();
    }

    this.initialized = true;
  }

  /**
   * Connect to a peer, routing through appropriate proxy based on address type.
   *
   * @param address - Target address (hostname or IP)
   * @param port - Target port
   * @returns Connected socket
   */
  async connect(address: string, port: number): Promise<Socket> {
    const networkType = getNetworkTypeFromAddress(address);

    switch (networkType) {
      case "onion":
        return this.connectOnion(address, port);
      case "i2p":
        return this.connectI2P(address);
      default:
        return this.connectClearnet(address, port);
    }
  }

  /**
   * Connect through clearnet (possibly via SOCKS5 proxy).
   */
  private async connectClearnet(address: string, port: number): Promise<Socket> {
    if (this.defaultProxy) {
      return this.defaultProxy.connect(address, port);
    }

    // Direct connection
    return new Promise((resolve, reject) => {
      Bun.connect({
        hostname: address,
        port,
        socket: {
          open(socket) {
            resolve(socket);
          },
          data() {},
          close() {},
          error(_socket, error) {
            reject(error);
          },
          connectError(_socket, error) {
            reject(error);
          },
        },
      }).catch(reject);
    });
  }

  /**
   * Connect to a Tor hidden service.
   */
  private async connectOnion(address: string, port: number): Promise<Socket> {
    // Use dedicated onion proxy if available, otherwise default proxy
    const proxy = this.onionProxy || this.defaultProxy;
    if (!proxy) {
      throw new Error("ProxyManager: no proxy configured for .onion addresses");
    }

    return proxy.connect(address, port);
  }

  /**
   * Connect to an I2P destination.
   */
  private async connectI2P(address: string): Promise<Socket> {
    if (!this.i2pSam) {
      throw new Error("ProxyManager: I2P SAM not configured");
    }

    return this.i2pSam.connect(address);
  }

  /**
   * Create a Tor hidden service.
   *
   * @param virtualPort - Port exposed on .onion
   * @param targetHost - Local host to forward to
   * @param targetPort - Local port to forward to
   * @returns The .onion address
   */
  async createHiddenService(
    virtualPort: number,
    targetHost: string,
    targetPort: number
  ): Promise<string> {
    if (!this.torControl) {
      throw new Error("ProxyManager: Tor control not configured");
    }

    const serviceId = await this.torControl.addOnion(
      virtualPort,
      targetHost,
      targetPort
    );

    return `${serviceId}.onion`;
  }

  /**
   * Get our I2P address.
   */
  getI2PAddress(): string | null {
    return this.i2pSam?.getAddress() ?? null;
  }

  /**
   * Get our Tor hidden service address.
   */
  getOnionAddress(): string | null {
    return this.torControl?.getOnionAddress() ?? null;
  }

  /**
   * Check if a network type is reachable.
   */
  isReachable(networkType: NetworkType): boolean {
    switch (networkType) {
      case "onion":
        return !!(this.onionProxy || this.defaultProxy);
      case "i2p":
        return !!this.i2pSam;
      case "ipv4":
      case "ipv6":
      case "cjdns":
        return true; // Always reachable (possibly via proxy)
    }
  }

  /**
   * Accept incoming I2P connections.
   */
  async acceptI2P(): Promise<{ socket: Socket; peerAddress: string }> {
    if (!this.i2pSam) {
      throw new Error("ProxyManager: I2P SAM not configured");
    }

    const { socket, peerDestination } = await this.i2pSam.accept();

    // Convert destination to .b32.i2p address
    // For now, return the raw destination
    return { socket, peerAddress: peerDestination };
  }

  /**
   * Close all proxies and release resources.
   */
  async close(): Promise<void> {
    if (this.torControl) {
      await this.torControl.delOnion().catch(() => {});
      this.torControl.disconnect();
      this.torControl = null;
    }

    if (this.i2pSam) {
      this.i2pSam.close();
      this.i2pSam = null;
    }

    this.defaultProxy = null;
    this.onionProxy = null;
    this.initialized = false;
  }
}
