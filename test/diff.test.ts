import { describe, expect, it } from "vitest";
import { diffSnapshots } from "../src/diff.js";
import { ScanSnapshot } from "../src/types.js";

function baseSnapshot(overrides: Partial<ScanSnapshot> = {}): ScanSnapshot {
  return {
    target: "example.invalid",
    takenAt: "2026-01-01T00:00:00.000Z",
    subdomains: [
      { hostname: "example.invalid", addresses: ["10.0.0.1"] },
      { hostname: "www.example.invalid", addresses: ["10.0.0.2"] },
      { hostname: "api.example.invalid", addresses: ["10.0.0.3"] },
    ],
    ports: [
      { host: "example.invalid", port: 80, open: true },
      { host: "example.invalid", port: 443, open: true },
      { host: "example.invalid", port: 22, open: false },
      { host: "www.example.invalid", port: 443, open: true },
    ],
    tls: [
      {
        host: "example.invalid",
        port: 443,
        reachable: true,
        issuer: "O=Original CA, CN=Original CA",
        subject: "CN=example.invalid",
        validFrom: "2025-01-01T00:00:00.000Z",
        validTo: "2027-01-01T00:00:00.000Z",
        fingerprint256: "AA:BB:CC",
      },
    ],
    ...overrides,
  };
}

describe("diffSnapshots", () => {
  it("reports no changes for two identical snapshots", () => {
    const prev = baseSnapshot();
    const curr = baseSnapshot({ takenAt: "2026-01-02T00:00:00.000Z" });
    const result = diffSnapshots(prev, curr);
    expect(result.changes).toEqual([]);
    expect(result.previousSnapshotAt).toBe(prev.takenAt);
    expect(result.currentSnapshotAt).toBe(curr.takenAt);
  });

  it("detects a newly appeared subdomain", () => {
    const prev = baseSnapshot();
    const curr = baseSnapshot({
      subdomains: [
        ...prev.subdomains,
        { hostname: "staging.example.invalid", addresses: ["10.0.0.9"] },
      ],
    });
    const result = diffSnapshots(prev, curr);
    const added = result.changes.filter((c) => c.kind === "subdomain-added");
    expect(added).toHaveLength(1);
    expect(added[0].detail).toMatchObject({ hostname: "staging.example.invalid" });
  });

  it("detects a subdomain that disappeared", () => {
    const prev = baseSnapshot();
    const curr = baseSnapshot({
      subdomains: prev.subdomains.filter((s) => s.hostname !== "api.example.invalid"),
    });
    const result = diffSnapshots(prev, curr);
    const removed = result.changes.filter((c) => c.kind === "subdomain-removed");
    expect(removed).toHaveLength(1);
    expect(removed[0].detail).toMatchObject({ hostname: "api.example.invalid" });
  });

  it("detects a subdomain whose resolved address changed", () => {
    const prev = baseSnapshot();
    const curr = baseSnapshot({
      subdomains: prev.subdomains.map((s) =>
        s.hostname === "www.example.invalid" ? { ...s, addresses: ["10.0.0.99"] } : s
      ),
    });
    const result = diffSnapshots(prev, curr);
    const changed = result.changes.filter((c) => c.kind === "subdomain-address-changed");
    expect(changed).toHaveLength(1);
    expect(changed[0].detail).toMatchObject({
      hostname: "www.example.invalid",
      previousAddresses: ["10.0.0.2"],
      currentAddresses: ["10.0.0.99"],
    });
  });

  it("detects a port that opened", () => {
    const prev = baseSnapshot();
    const curr = baseSnapshot({
      ports: prev.ports.map((p) =>
        p.host === "example.invalid" && p.port === 22 ? { ...p, open: true } : p
      ),
    });
    const result = diffSnapshots(prev, curr);
    const opened = result.changes.filter((c) => c.kind === "port-opened");
    expect(opened).toHaveLength(1);
    expect(opened[0].detail).toMatchObject({ host: "example.invalid", port: 22 });
  });

  it("detects a port that closed", () => {
    const prev = baseSnapshot();
    const curr = baseSnapshot({
      ports: prev.ports.map((p) =>
        p.host === "example.invalid" && p.port === 443 ? { ...p, open: false } : p
      ),
    });
    const result = diffSnapshots(prev, curr);
    const closed = result.changes.filter((c) => c.kind === "port-closed");
    expect(closed).toHaveLength(1);
    expect(closed[0].detail).toMatchObject({ host: "example.invalid", port: 443 });
  });

  it("detects a port that appears open on a brand-new host entry", () => {
    const prev = baseSnapshot();
    const curr = baseSnapshot({
      ports: [...prev.ports, { host: "api.example.invalid", port: 8080, open: true }],
    });
    const result = diffSnapshots(prev, curr);
    const opened = result.changes.filter((c) => c.kind === "port-opened");
    expect(opened).toHaveLength(1);
    expect(opened[0].detail).toMatchObject({ host: "api.example.invalid", port: 8080 });
  });

  it("detects a TLS issuer change", () => {
    const prev = baseSnapshot();
    const curr = baseSnapshot({
      tls: [{ ...prev.tls[0], issuer: "O=New CA, CN=New CA" }],
    });
    const result = diffSnapshots(prev, curr);
    const issuerChanges = result.changes.filter((c) => c.kind === "tls-issuer-changed");
    expect(issuerChanges).toHaveLength(1);
    expect(issuerChanges[0].detail).toMatchObject({
      previousIssuer: "O=Original CA, CN=Original CA",
      currentIssuer: "O=New CA, CN=New CA",
    });
  });

  it("detects a TLS expiry change (reissuance)", () => {
    const prev = baseSnapshot();
    const curr = baseSnapshot({
      tls: [{ ...prev.tls[0], validTo: "2028-06-01T00:00:00.000Z" }],
    });
    const result = diffSnapshots(prev, curr);
    const expiryChanges = result.changes.filter((c) => c.kind === "tls-expiry-changed");
    expect(expiryChanges).toHaveLength(1);
    expect(expiryChanges[0].detail).toMatchObject({
      previousValidTo: "2027-01-01T00:00:00.000Z",
      currentValidTo: "2028-06-01T00:00:00.000Z",
    });
  });

  it("detects TLS becoming unreachable", () => {
    const prev = baseSnapshot();
    const curr = baseSnapshot({
      tls: [{ host: "example.invalid", port: 443, reachable: false, error: "connect ECONNREFUSED" }],
    });
    const result = diffSnapshots(prev, curr);
    expect(result.changes.filter((c) => c.kind === "tls-became-unreachable")).toHaveLength(1);
    // Should not also fire issuer/expiry changes once unreachable.
    expect(result.changes.filter((c) => c.kind === "tls-issuer-changed")).toHaveLength(0);
  });

  it("detects TLS becoming reachable again", () => {
    const prev = baseSnapshot({
      tls: [{ host: "example.invalid", port: 443, reachable: false, error: "timed out" }],
    });
    const curr = baseSnapshot();
    const result = diffSnapshots(prev, curr);
    expect(result.changes.filter((c) => c.kind === "tls-became-reachable")).toHaveLength(1);
  });

  it("reports no TLS change when both snapshots are unreachable", () => {
    const prev = baseSnapshot({
      tls: [{ host: "example.invalid", port: 443, reachable: false, error: "timed out" }],
    });
    const curr = baseSnapshot({
      tls: [{ host: "example.invalid", port: 443, reachable: false, error: "connection refused" }],
    });
    const result = diffSnapshots(prev, curr);
    expect(result.changes).toEqual([]);
  });

  it("combines multiple simultaneous changes correctly in one diff", () => {
    const prev = baseSnapshot();
    const curr = baseSnapshot({
      subdomains: [
        prev.subdomains[0],
        prev.subdomains[1],
        { hostname: "new.example.invalid", addresses: ["10.0.0.50"] },
      ],
      ports: [
        { host: "example.invalid", port: 80, open: true },
        { host: "example.invalid", port: 443, open: true },
        { host: "example.invalid", port: 22, open: true }, // opened
        { host: "www.example.invalid", port: 443, open: false }, // closed
      ],
      tls: [{ ...prev.tls[0], issuer: "O=New CA, CN=New CA" }],
    });
    const result = diffSnapshots(prev, curr);
    const kinds = result.changes.map((c) => c.kind).sort();
    expect(kinds).toEqual(
      ["port-closed", "port-opened", "subdomain-added", "subdomain-removed", "tls-issuer-changed"].sort()
    );
  });

  it("throws when asked to diff snapshots for two different targets", () => {
    const prev = baseSnapshot({ target: "a.invalid" });
    const curr = baseSnapshot({ target: "b.invalid" });
    expect(() => diffSnapshots(prev, curr)).toThrow(/different targets/i);
  });
});
