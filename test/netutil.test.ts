import { describe, expect, it } from "vitest";
import { classifyTargetPrivacy, hostOf, isPrivateIpv4, isPrivateIpv6, isPrivateLiteralAddress } from "../src/netutil.js";

describe("isPrivateIpv4", () => {
  it("recognizes loopback and RFC1918 ranges", () => {
    expect(isPrivateIpv4("127.0.0.1")).toBe(true);
    expect(isPrivateIpv4("127.255.255.255")).toBe(true);
    expect(isPrivateIpv4("10.0.0.1")).toBe(true);
    expect(isPrivateIpv4("172.16.0.1")).toBe(true);
    expect(isPrivateIpv4("172.31.255.255")).toBe(true);
    expect(isPrivateIpv4("192.168.1.1")).toBe(true);
    expect(isPrivateIpv4("169.254.1.1")).toBe(true);
  });

  it("rejects public addresses and addresses just outside private ranges", () => {
    expect(isPrivateIpv4("8.8.8.8")).toBe(false);
    expect(isPrivateIpv4("172.15.255.255")).toBe(false); // just below 172.16/12
    expect(isPrivateIpv4("172.32.0.0")).toBe(false); // just above 172.31/12
    expect(isPrivateIpv4("203.0.113.5")).toBe(false);
    expect(isPrivateIpv4("not-an-ip")).toBe(false);
  });
});

describe("isPrivateIpv6", () => {
  it("recognizes loopback, unique-local, link-local, and mapped-v4", () => {
    expect(isPrivateIpv6("::1")).toBe(true);
    expect(isPrivateIpv6("fd00::1")).toBe(true);
    expect(isPrivateIpv6("fe80::1")).toBe(true);
    expect(isPrivateIpv6("::ffff:10.0.0.5")).toBe(true);
  });

  it("rejects public IPv6 and public mapped-v4", () => {
    expect(isPrivateIpv6("2001:4860:4860::8888")).toBe(false);
    expect(isPrivateIpv6("::ffff:8.8.8.8")).toBe(false);
  });
});

describe("isPrivateLiteralAddress", () => {
  it("dispatches to the correct family check", () => {
    expect(isPrivateLiteralAddress("10.0.0.1")).toBe(true);
    expect(isPrivateLiteralAddress("::1")).toBe(true);
    expect(isPrivateLiteralAddress("8.8.8.8")).toBe(false);
  });

  it("returns false for non-IP strings", () => {
    expect(isPrivateLiteralAddress("example.invalid")).toBe(false);
  });
});

describe("hostOf", () => {
  it("strips scheme, path, and port", () => {
    expect(hostOf("https://example.invalid:8443/some/path")).toBe("example.invalid");
    expect(hostOf("example.invalid")).toBe("example.invalid");
    expect(hostOf("127.0.0.1:9200")).toBe("127.0.0.1");
  });

  it("handles bracketed IPv6 literals", () => {
    expect(hostOf("https://[::1]:8443/")).toBe("::1");
    expect(hostOf("[fe80::1]")).toBe("fe80::1");
  });
});

describe("classifyTargetPrivacy", () => {
  it("treats 'localhost' as private without any lookup", async () => {
    const result = await classifyTargetPrivacy("localhost", async () => {
      throw new Error("lookup should not be called for 'localhost'");
    });
    expect(result.isPrivate).toBe(true);
  });

  it("classifies literal IPs without performing a lookup", async () => {
    const noLookup = async () => {
      throw new Error("lookup should not be called for literal IPs");
    };
    expect((await classifyTargetPrivacy("10.0.0.1", noLookup)).isPrivate).toBe(true);
    expect((await classifyTargetPrivacy("203.0.113.5", noLookup)).isPrivate).toBe(false);
  });

  it("resolves a hostname and treats it as private only if every address is private", async () => {
    const result = await classifyTargetPrivacy("internal.example.invalid", async () => [
      { address: "10.0.0.5", family: 4 },
      { address: "192.168.1.5", family: 4 },
    ]);
    expect(result.isPrivate).toBe(true);
  });

  it("treats a hostname with any public address as not private", async () => {
    const result = await classifyTargetPrivacy("mixed.example.invalid", async () => [
      { address: "10.0.0.5", family: 4 },
      { address: "203.0.113.9", family: 4 },
    ]);
    expect(result.isPrivate).toBe(false);
  });

  it("fails closed (not private) when the hostname does not resolve", async () => {
    const result = await classifyTargetPrivacy("nowhere.example.invalid", async () => {
      const err = new Error("getaddrinfo ENOTFOUND nowhere.example.invalid");
      throw err;
    });
    expect(result.isPrivate).toBe(false);
  });

  it("fails closed when the resolver returns zero addresses", async () => {
    const result = await classifyTargetPrivacy("empty.example.invalid", async () => []);
    expect(result.isPrivate).toBe(false);
  });
});
