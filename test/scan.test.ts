import net from "node:net";
import { afterEach, describe, expect, it } from "vitest";
import { useTempHome } from "./helpers/tempHome.js";
import { AuthorizationRefusedError, runScan } from "../src/scan.js";
import { readAuditLog } from "../src/auditlog.js";

/**
 * End-to-end integration test: wires the authorization gate, real port
 * scanning, snapshot persistence, and the diff engine together against a
 * real TCP listener on 127.0.0.1. DNS enumeration is scoped to an empty
 * wordlist (wordlist: []) purely to keep this test fast and focused on one
 * host — it still runs the real dns.lookup for the apex address, it just
 * skips the (irrelevant, for a bare IP target) wordlist fan-out.
 */
function listenOnEphemeralPort(): Promise<{ server: net.Server; port: number }> {
  return new Promise((resolve, reject) => {
    const server = net.createServer((socket) => socket.end());
    server.on("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      if (address && typeof address === "object") resolve({ server, port: address.port });
      else reject(new Error("failed to bind"));
    });
  });
}

describe("runScan (integration)", () => {
  useTempHome();
  let activeServer: net.Server | undefined;

  afterEach(async () => {
    if (activeServer) {
      await new Promise<void>((resolve) => activeServer!.close(() => resolve()));
      activeServer = undefined;
    }
  });

  it("scans a private loopback target with no authorization record needed, and records a baseline", async () => {
    const { server, port } = await listenOnEphemeralPort();
    activeServer = server;

    const result = await runScan("127.0.0.1", {
      wordlist: [],
      ports: [port],
      tlsPort: 65533, // nothing listening there; TLS just reports unreachable
      timeoutMs: 1000,
    });

    expect(result.diff).toBeUndefined(); // first-ever snapshot: no prior data to diff against
    expect(result.snapshot.ports.find((p) => p.port === port)?.open).toBe(true);

    const auditLines = readAuditLog();
    expect(auditLines.some((l) => JSON.parse(l).action === "scan-allowed")).toBe(true);
  });

  it("detects a port closing between two real scans of the same target", async () => {
    const { server, port } = await listenOnEphemeralPort();

    await runScan("127.0.0.1", { wordlist: [], ports: [port], tlsPort: 65533, timeoutMs: 1000 });

    await new Promise<void>((resolve) => server.close(() => resolve()));

    const second = await runScan("127.0.0.1", { wordlist: [], ports: [port], tlsPort: 65533, timeoutMs: 1000 });

    expect(second.diff).toBeDefined();
    const closed = second.diff!.changes.filter((c) => c.kind === "port-closed");
    expect(closed).toHaveLength(1);
    expect(closed[0].detail).toMatchObject({ host: "127.0.0.1", port });
  });

  it("refuses to scan a public target with no authorization record, and never touches the network for probing", async () => {
    // TEST-NET-3 (RFC 5737): reserved, non-routable. The gate must refuse
    // before any DNS/port/TLS probing of this target is attempted.
    await expect(runScan("203.0.113.77", { wordlist: [], ports: [12345] })).rejects.toThrow(
      AuthorizationRefusedError
    );

    const auditLines = readAuditLog().map((l) => JSON.parse(l));
    expect(auditLines.some((l) => l.action === "scan-refused" && l.target === "203.0.113.77")).toBe(true);
  });
});
