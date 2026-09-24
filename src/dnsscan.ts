/**
 * Real DNS subdomain discovery: tries the base domain plus every label in
 * the wordlist as "<label>.<domain>", using Node's real resolver
 * (dns.promises). No guessing, no synthetic data — only labels that
 * actually resolve are reported, together with the real addresses they
 * resolved to.
 */
import dns from "node:dns/promises";
import { DiscoveredHost } from "./types.js";
import { mapWithConcurrency } from "./concurrency.js";
import { DEFAULT_SUBDOMAIN_WORDLIST } from "./wordlist.js";

export const DEFAULT_DNS_CONCURRENCY = 8;
export const DEFAULT_DNS_TIMEOUT_MS = 3000;

export interface DnsScanOptions {
  wordlist?: readonly string[];
  concurrency?: number;
  timeoutMs?: number;
  /** Injectable for tests; defaults to dns.promises.lookup. */
  lookupFn?: (host: string) => Promise<{ address: string; family: number }[]>;
}

function withTimeout<T>(promise: Promise<T>, ms: number): Promise<T> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`timed out after ${ms}ms`)), ms);
    promise.then(
      (v) => {
        clearTimeout(timer);
        resolve(v);
      },
      (e) => {
        clearTimeout(timer);
        reject(e);
      }
    );
  });
}

/**
 * Discovers real subdomains of `domain` by resolving the domain itself plus
 * every candidate "<word>.<domain>" from the wordlist. Concurrency-capped
 * and timeout-bounded so this stays a gentle, read-only DNS client, never a
 * flood.
 */
export async function discoverSubdomains(
  domain: string,
  options: DnsScanOptions = {}
): Promise<DiscoveredHost[]> {
  const wordlist = options.wordlist ?? DEFAULT_SUBDOMAIN_WORDLIST;
  const concurrency = options.concurrency ?? DEFAULT_DNS_CONCURRENCY;
  const timeoutMs = options.timeoutMs ?? DEFAULT_DNS_TIMEOUT_MS;
  const lookupFn = options.lookupFn ?? ((host: string) => dns.lookup(host, { all: true, verbatim: true }));

  const candidates = [domain, ...wordlist.map((w) => `${w}.${domain}`)];

  const outcomes = await mapWithConcurrency(candidates, concurrency, async (hostname) => {
    try {
      const records = await withTimeout(lookupFn(hostname), timeoutMs);
      if (records.length === 0) return null;
      const addresses = Array.from(new Set(records.map((r) => r.address))).sort();
      return { hostname, addresses } as DiscoveredHost;
    } catch {
      return null; // NXDOMAIN, timeout, etc: simply not present.
    }
  });

  return outcomes
    .filter((o): o is DiscoveredHost => o !== null)
    .sort((a, b) => a.hostname.localeCompare(b.hostname));
}
