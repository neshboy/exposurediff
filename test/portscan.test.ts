import net from "node:net";
import { afterEach, describe, expect, it } from "vitest";
import { PortRangeTooWideError, assertPortRangeAllowed, scanPorts } from "../src/portscan.js";

/**
 * These tests open real TCP listeners on 127.0.0.1 and run scanPorts()
 * against them for real — no mocked sockets. This is the same loopback-only
 * discipline as the rest of the suite: real network I/O, zero external
 * hosts touched.
 */
function listenOnEphemeralPort(): Promise<{ server: net.Server; port: number }> {
  return new Promise((resolve, reject) => {
    const server = net.createServer((socket) => socket.end());
    server.on("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      if (address && typeof address === "object") {
        resolve({ server, port: address.port });
      } else {
        reject(new Error("failed to bind ephemeral port"));
      }
    });
  });
}

describe("scanPorts", () => {
  let openServer: net.Server | undefined;

  afterEach(async () => {
    if (openServer) {
      await new Promise<void>((resolve) => openServer!.close(() => resolve()));
      openServer = undefined;
    }
  });

  it("reports a real listening port as open and a real closed port as closed", async () => {
    const { server, port: openPort } = await listenOnEphemeralPort();
    openServer = server;

    // Grab a second ephemeral port, then close it immediately so nothing is
    // listening there — a real "closed port" fixture, not a guess.
    const { server: throwaway, port: closedPort } = await listenOnEphemeralPort();
    await new Promise<void>((resolve) => throwaway.close(() => resolve()));

    const results = await scanPorts("127.0.0.1", [openPort, closedPort], {
      concurrency: 4,
      timeoutMs: 1000,
    });

    const byPort = new Map(results.map((r) => [r.port, r]));
    expect(byPort.get(openPort)?.open).toBe(true);
    expect(byPort.get(closedPort)?.open).toBe(false);
  });

  it("returns results sorted by port number", async () => {
    const results = await scanPorts("127.0.0.1", [9999, 111, 5555], { timeoutMs: 500 });
    expect(results.map((r) => r.port)).toEqual([111, 5555, 9999]);
  });

  it("respects a bounded concurrency across many ports without crashing", async () => {
    const ports = Array.from({ length: 30 }, (_, i) => 20000 + i);
    const results = await scanPorts("127.0.0.1", ports, { concurrency: 5, timeoutMs: 500 });
    expect(results).toHaveLength(30);
    expect(results.every((r) => r.open === false)).toBe(true);
  });
});

describe("assertPortRangeAllowed", () => {
  it("allows a small, reasonable port list by default", () => {
    expect(() => assertPortRangeAllowed([22, 80, 443])).not.toThrow();
  });

  it("refuses an absurdly wide port range without an explicit override", () => {
    const wideRange = Array.from({ length: 5000 }, (_, i) => i + 1);
    expect(() => assertPortRangeAllowed(wideRange)).toThrow(PortRangeTooWideError);
  });

  it("allows the wide range when the caller explicitly opts in", () => {
    const wideRange = Array.from({ length: 5000 }, (_, i) => i + 1);
    expect(() => assertPortRangeAllowed(wideRange, true)).not.toThrow();
  });

  it("rejects invalid port numbers", () => {
    expect(() => assertPortRangeAllowed([0])).toThrow(/invalid port/i);
    expect(() => assertPortRangeAllowed([70000])).toThrow(/invalid port/i);
    expect(() => assertPortRangeAllowed([1.5])).toThrow(/invalid port/i);
  });
});
