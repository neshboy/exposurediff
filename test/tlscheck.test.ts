import fs from "node:fs";
import path from "node:path";
import tls from "node:tls";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import { checkTlsCertificate } from "../src/tlscheck.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const fixturesDir = path.join(__dirname, "fixtures", "tls");

function loadFixture(name: "a" | "b") {
  return {
    key: fs.readFileSync(path.join(fixturesDir, `cert-${name}-key.pem`), "utf8"),
    cert: fs.readFileSync(path.join(fixturesDir, `cert-${name}.pem`), "utf8"),
  };
}

function startTlsServer(name: "a" | "b"): Promise<{ server: tls.Server; port: number }> {
  const { key, cert } = loadFixture(name);
  return new Promise((resolve, reject) => {
    const server = tls.createServer({ key, cert }, (socket) => socket.end());
    server.on("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      if (address && typeof address === "object") {
        resolve({ server, port: address.port });
      } else {
        reject(new Error("failed to bind ephemeral TLS port"));
      }
    });
  });
}

/**
 * These tests perform a real TLS handshake (node:tls) against a real local
 * server on 127.0.0.1 presenting a real, openssl-generated self-signed
 * certificate (test/fixtures/tls). No mocking of the TLS layer and no
 * external hosts touched.
 */
describe("checkTlsCertificate", () => {
  let activeServer: tls.Server | undefined;

  afterEach(async () => {
    if (activeServer) {
      await new Promise<void>((resolve) => activeServer!.close(() => resolve()));
      activeServer = undefined;
    }
  });

  it("reads real issuer/subject/validity from a live TLS server (fixture A)", async () => {
    const { server, port } = await startTlsServer("a");
    activeServer = server;

    const result = await checkTlsCertificate("127.0.0.1", port, { timeoutMs: 2000 });

    expect(result.reachable).toBe(true);
    expect(result.issuer).toContain("ExposureDiff Test Org A");
    expect(result.subject).toContain("exposurediff-test-a.invalid");
    expect(result.validFrom).toBeDefined();
    expect(result.validTo).toBeDefined();
    expect(new Date(result.validTo!).getTime()).toBeGreaterThan(Date.now());
    expect(result.fingerprint256).toMatch(/^[0-9A-F:]+$/);
  });

  it("reads a different real issuer/subject from a live TLS server (fixture B)", async () => {
    const { server, port } = await startTlsServer("b");
    activeServer = server;

    const result = await checkTlsCertificate("127.0.0.1", port, { timeoutMs: 2000 });

    expect(result.reachable).toBe(true);
    expect(result.issuer).toContain("ExposureDiff Test Org B");
    expect(result.subject).toContain("exposurediff-test-b.invalid");
  });

  it("produces different fingerprints for two different real certificates", async () => {
    const serverA = await startTlsServer("a");
    const resultA = await checkTlsCertificate("127.0.0.1", serverA.port, { timeoutMs: 2000 });
    await new Promise<void>((resolve) => serverA.server.close(() => resolve()));

    const serverB = await startTlsServer("b");
    activeServer = serverB.server;
    const resultB = await checkTlsCertificate("127.0.0.1", serverB.port, { timeoutMs: 2000 });

    expect(resultA.fingerprint256).not.toBe(resultB.fingerprint256);
    expect(resultA.issuer).not.toBe(resultB.issuer);
  });

  it("reports reachable:false with an error when nothing is listening", async () => {
    // Grab and immediately release an ephemeral port so we know nothing is bound there.
    const probe = await startTlsServer("a");
    const freePort = probe.port;
    await new Promise<void>((resolve) => probe.server.close(() => resolve()));

    const result = await checkTlsCertificate("127.0.0.1", freePort, { timeoutMs: 1000 });
    expect(result.reachable).toBe(false);
    expect(result.error).toBeTruthy();
    expect(result.issuer).toBeUndefined();
  });

  it("reports reachable:false when the handshake times out (non-TLS listener)", async () => {
    const net = await import("node:net");
    const acceptedSockets: import("node:net").Socket[] = [];
    const rawServer = net.createServer((socket) => {
      // Accept the TCP connection but never speak TLS back. Track it so we
      // can force it closed afterwards — otherwise a graceful
      // server.close() would hang waiting for this half-open connection to
      // end on its own, which it never will.
      acceptedSockets.push(socket);
    });
    await new Promise<void>((resolve) => rawServer.listen(0, "127.0.0.1", () => resolve()));
    const address = rawServer.address();
    const port = typeof address === "object" && address ? address.port : 0;

    const result = await checkTlsCertificate("127.0.0.1", port, { timeoutMs: 500 });
    expect(result.reachable).toBe(false);
    expect(result.error).toBeTruthy();

    for (const socket of acceptedSockets) socket.destroy();
    await new Promise<void>((resolve) => rawServer.close(() => resolve()));
  });
});
