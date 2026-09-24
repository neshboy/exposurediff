import fs from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { useTempHome } from "./helpers/tempHome.js";
import {
  addAuthorization,
  ensureAuthorized,
  findCurrentAuthorization,
  listAuthorizations,
  revokeAuthorization,
} from "../src/authz.js";
import { authorizationsFilePath } from "../src/storage.js";

// TEST-NET-3 (RFC 5737): reserved for documentation/testing, never routable.
// Using literal IPs here means these tests never perform a real DNS lookup
// or touch any real external host — they only exercise the private-range
// classification and the authorization-record logic.
const PUBLIC_TEST_IP = "203.0.113.10";
const OTHER_PUBLIC_TEST_IP = "198.51.100.20";

describe("authorization gate", () => {
  useTempHome();

  it("allows loopback addresses with no authorization record", async () => {
    const decision = await ensureAuthorized("127.0.0.1");
    expect(decision.allowed).toBe(true);
    expect(decision.method).toBe("loopback-exempt");
  });

  it("allows private RFC1918 addresses with no authorization record", async () => {
    const decision = await ensureAuthorized("10.1.2.3");
    expect(decision.allowed).toBe(true);
    expect(decision.method).toBe("loopback-exempt");
  });

  it("allows the literal hostname 'localhost'", async () => {
    const decision = await ensureAuthorized("localhost");
    expect(decision.allowed).toBe(true);
  });

  it("refuses a public address with no authorization record", async () => {
    const decision = await ensureAuthorized(PUBLIC_TEST_IP);
    expect(decision.allowed).toBe(false);
    expect(decision.reason).toMatch(/authz add/);
  });

  it("does not leak authorization across different public targets", async () => {
    addAuthorization(PUBLIC_TEST_IP, "authorized for target A only");
    const decisionOther = await ensureAuthorized(OTHER_PUBLIC_TEST_IP);
    expect(decisionOther.allowed).toBe(false);
  });

  it("allows a public address once a current authorization record exists", async () => {
    addAuthorization(PUBLIC_TEST_IP, "pentest engagement #123, written client approval on file");
    const decision = await ensureAuthorized(PUBLIC_TEST_IP);
    expect(decision.allowed).toBe(true);
    expect(decision.method).toBe("authorization-file");
    expect(decision.record?.note).toMatch(/pentest engagement/);
  });

  it("rejects addAuthorization without a note", () => {
    expect(() => addAuthorization(PUBLIC_TEST_IP, "")).toThrow(/note/i);
    expect(() => addAuthorization(PUBLIC_TEST_IP, "   ")).toThrow(/note/i);
  });

  it("lists all recorded authorizations", () => {
    addAuthorization(PUBLIC_TEST_IP, "reason one");
    addAuthorization(OTHER_PUBLIC_TEST_IP, "reason two");
    const records = listAuthorizations();
    expect(records).toHaveLength(2);
    expect(records.map((r) => r.target).sort()).toEqual([OTHER_PUBLIC_TEST_IP, PUBLIC_TEST_IP].sort());
  });

  it("revoking a target's authorization makes it fail the gate again", async () => {
    addAuthorization(PUBLIC_TEST_IP, "temporary engagement");
    expect((await ensureAuthorized(PUBLIC_TEST_IP)).allowed).toBe(true);

    const revokedCount = revokeAuthorization(PUBLIC_TEST_IP);
    expect(revokedCount).toBe(1);

    const decision = await ensureAuthorized(PUBLIC_TEST_IP);
    expect(decision.allowed).toBe(false);
    expect(findCurrentAuthorization(PUBLIC_TEST_IP)).toBeUndefined();
  });

  it("an expired authorization record no longer satisfies the gate", async () => {
    addAuthorization(PUBLIC_TEST_IP, "will be expired manually for this test");
    // Simulate time passing: rewrite the stored record with an expiresAt in the past.
    const file = authorizationsFilePath();
    const records = JSON.parse(fs.readFileSync(file, "utf8"));
    records[0].expiresAt = new Date(Date.now() - 1000).toISOString();
    fs.writeFileSync(file, JSON.stringify(records, null, 2));

    expect(findCurrentAuthorization(PUBLIC_TEST_IP)).toBeUndefined();
    const decision = await ensureAuthorized(PUBLIC_TEST_IP);
    expect(decision.allowed).toBe(false);
  });

  it("treats a corrupt authorization store as empty (fails closed, does not throw)", async () => {
    fs.mkdirSync(path.dirname(authorizationsFilePath()), { recursive: true });
    fs.writeFileSync(authorizationsFilePath(), "{ not valid json ][", "utf8");
    expect(listAuthorizations()).toEqual([]);
    const decision = await ensureAuthorized(PUBLIC_TEST_IP);
    expect(decision.allowed).toBe(false);
  });
});
