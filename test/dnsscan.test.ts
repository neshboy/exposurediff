import { describe, expect, it } from "vitest";
import { discoverSubdomains } from "../src/dnsscan.js";

/**
 * discoverSubdomains() accepts an injectable lookup function (the same
 * dependency-injection pattern greenlight uses for its own DNS-privacy
 * check) so these tests exercise the REAL discovery algorithm — candidate
 * generation, concurrency, timeout handling, filtering, sorting — against a
 * deterministic, hermetic fixture instead of real external DNS infrastructure.
 */
function fixtureZone(records: Record<string, string[]>) {
  return async (host: string) => {
    const addresses = records[host];
    if (!addresses) {
      const err = new Error(`getaddrinfo ENOTFOUND ${host}`);
      throw err;
    }
    return addresses.map((address) => ({ address, family: 4 }));
  };
}

describe("discoverSubdomains", () => {
  it("returns only hostnames that actually resolve in the fixture zone", async () => {
    const lookupFn = fixtureZone({
      "example.invalid": ["10.0.0.1"],
      "www.example.invalid": ["10.0.0.2"],
      "api.example.invalid": ["10.0.0.3"],
      // "mail.example.invalid" intentionally absent -> should not appear
    });

    const results = await discoverSubdomains("example.invalid", {
      wordlist: ["www", "api", "mail", "doesnotexist"],
      lookupFn,
      concurrency: 4,
    });

    expect(results.map((r) => r.hostname)).toEqual([
      "api.example.invalid",
      "example.invalid",
      "www.example.invalid",
    ]);
  });

  it("deduplicates and sorts resolved addresses per host", async () => {
    const lookupFn = async () => [
      { address: "10.0.0.9", family: 4 },
      { address: "10.0.0.1", family: 4 },
      { address: "10.0.0.9", family: 4 },
    ];
    const results = await discoverSubdomains("example.invalid", {
      wordlist: [],
      lookupFn,
    });
    expect(results).toHaveLength(1);
    expect(results[0].addresses).toEqual(["10.0.0.1", "10.0.0.9"]);
  });

  it("treats a slow lookup that exceeds the timeout as non-resolving", async () => {
    const lookupFn = async (host: string) => {
      if (host === "slow.example.invalid") {
        await new Promise((resolve) => setTimeout(resolve, 200));
        return [{ address: "10.0.0.5", family: 4 }];
      }
      return [{ address: "10.0.0.1", family: 4 }];
    };

    const results = await discoverSubdomains("example.invalid", {
      wordlist: ["slow"],
      lookupFn,
      timeoutMs: 20,
    });

    expect(results.map((r) => r.hostname)).toEqual(["example.invalid"]);
  });

  it("returns an empty array when nothing in the wordlist resolves", async () => {
    const lookupFn = fixtureZone({});
    const results = await discoverSubdomains("nowhere.invalid", {
      wordlist: ["a", "b", "c"],
      lookupFn,
    });
    expect(results).toEqual([]);
  });

  it("respects a bounded concurrency while still checking every candidate", async () => {
    let concurrent = 0;
    let maxConcurrent = 0;
    const wordlist = Array.from({ length: 25 }, (_, i) => `w${i}`);
    const lookupFn = async () => {
      concurrent++;
      maxConcurrent = Math.max(maxConcurrent, concurrent);
      await new Promise((resolve) => setTimeout(resolve, 5));
      concurrent--;
      return [{ address: "10.0.0.1", family: 4 }];
    };

    const results = await discoverSubdomains("example.invalid", {
      wordlist,
      lookupFn,
      concurrency: 3,
    });

    expect(results).toHaveLength(wordlist.length + 1); // + the apex domain
    expect(maxConcurrent).toBeLessThanOrEqual(3);
  });
});
