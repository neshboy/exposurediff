/**
 * Real, read-only TCP port checks: attempts a plain TCP connect to each
 * (host, port) pair and records whether it succeeded. No payloads are sent,
 * no protocol-level probing beyond the handshake itself — this is
 * intentionally the least invasive thing that can still answer "is this
 * port open right now".
 */
import net from "node:net";
import { PortResult } from "./types.js";
import { mapWithConcurrency } from "./concurrency.js";

/** A small default set of commonly-exposed service ports. */
export const DEFAULT_PORTS: readonly number[] = [
  21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465, 587, 993, 995, 1433, 1521, 2049,
  3306, 3389, 5432, 5900, 5985, 6379, 8000, 8080, 8443, 9000, 9200, 11211, 27017,
];

export const DEFAULT_PORT_CONCURRENCY = 20;
export const DEFAULT_PORT_TIMEOUT_MS = 1500;

/**
 * Absolute ceiling on how many ports a single scan may probe without the
 * caller explicitly opting in via `allowWideRange`. This prevents someone
 * from (accidentally or otherwise) turning this "gentle change monitor"
 * into a full 1-65535 port sweep by default.
 */
export const MAX_PORTS_WITHOUT_OVERRIDE = 200;

export class PortRangeTooWideError extends Error {
  constructor(count: number) {
    super(
      `Refusing to probe ${count} ports without an explicit override: default cap is ${MAX_PORTS_WITHOUT_OVERRIDE}. ` +
        `Pass allowWideRange to acknowledge a wider scan.`
    );
    this.name = "PortRangeTooWideError";
  }
}

/** Throws PortRangeTooWideError if `ports` exceeds the safety cap and no override was given. */
export function assertPortRangeAllowed(ports: readonly number[], allowWideRange = false): void {
  if (!allowWideRange && ports.length > MAX_PORTS_WITHOUT_OVERRIDE) {
    throw new PortRangeTooWideError(ports.length);
  }
  for (const p of ports) {
    if (!Number.isInteger(p) || p < 1 || p > 65535) {
      throw new Error(`Invalid port: ${p}. Ports must be integers in 1-65535.`);
    }
  }
}

export interface PortScanOptions {
  concurrency?: number;
  timeoutMs?: number;
}

function probeOne(host: string, port: number, timeoutMs: number): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let settled = false;
    const finish = (open: boolean) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(open);
    };
    socket.setTimeout(timeoutMs);
    socket.once("connect", () => finish(true));
    socket.once("timeout", () => finish(false));
    socket.once("error", () => finish(false));
    socket.connect(port, host);
  });
}

/**
 * Probes each port in `ports` against `host`, concurrency-capped. Rejects
 * with PortRangeTooWideError if the requested port list is unreasonably
 * large and no override was supplied.
 */
export async function scanPorts(
  host: string,
  ports: readonly number[] = DEFAULT_PORTS,
  options: PortScanOptions & { allowWideRange?: boolean } = {}
): Promise<PortResult[]> {
  assertPortRangeAllowed(ports, options.allowWideRange);
  const concurrency = options.concurrency ?? DEFAULT_PORT_CONCURRENCY;
  const timeoutMs = options.timeoutMs ?? DEFAULT_PORT_TIMEOUT_MS;

  const results = await mapWithConcurrency(ports, concurrency, async (port) => {
    const open = await probeOne(host, port, timeoutMs);
    return { host, port, open } as PortResult;
  });

  return results.sort((a, b) => a.port - b.port);
}
