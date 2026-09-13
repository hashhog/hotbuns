/**
 * Bind an RPC server for tests without colliding with Linux ephemeral ports.
 *
 * Test files that pick 32768–60999 (the default ip_local_port_range) flake
 * with EADDRINUSE against Tailscale / outbound TIME_WAIT. Default is port 0
 * (kernel-assigned). A requested port retries on EADDRINUSE.
 */
import { RPCServer, type RPCServerConfig, type RPCServerDeps } from "../rpc/server.js";

export function isAddrInUse(err: unknown): boolean {
  const e = err as { code?: string; message?: string };
  return e.code === "EADDRINUSE" || /in use/i.test(String(e.message ?? err));
}

export function startTestRpc(
  deps: RPCServerDeps,
  extra: Partial<RPCServerConfig> = {},
): { server: RPCServer; port: number } {
  const host = extra.host ?? "127.0.0.1";
  const noAuth = extra.noAuth ?? true;
  const useEphemeral = extra.port === undefined || extra.port === 0;
  let last: unknown;
  for (let i = 0; i < 32; i++) {
    const port = useEphemeral ? 0 : extra.port! + i;
    const server = new RPCServer({ ...extra, host, noAuth, port }, deps);
    try {
      server.start();
      const bound = server.listeningPort();
      if (!Number.isInteger(bound) || bound <= 0) {
        server.stop();
        throw new Error(`RPC test server bound invalid port ${bound}`);
      }
      return { server, port: bound };
    } catch (err) {
      try {
        server.stop();
      } catch {
        /* already not listening */
      }
      if (!isAddrInUse(err)) throw err;
      last = err;
    }
  }
  throw last ?? new Error("no free RPC test port");
}
