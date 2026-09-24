/**
 * Host/IP parsing and private-range classification helpers.
 *
 * These are deliberately conservative: anything that cannot be confidently
 * classified as private/loopback is treated as public, so the authorization
 * gate in authz.ts fails closed.
 */
import net from "node:net";
import dns from "node:dns/promises";

/** RFC1918 / loopback / link-local IPv4 ranges we treat as "in scope without explicit authorization". */
const PRIVATE_IPV4_RANGES: Array<{ base: number[]; maskBits: number }> = [
  { base: [127, 0, 0, 0], maskBits: 8 }, // loopback
  { base: [10, 0, 0, 0], maskBits: 8 }, // RFC1918
  { base: [172, 16, 0, 0], maskBits: 12 }, // RFC1918
  { base: [192, 168, 0, 0], maskBits: 16 }, // RFC1918
  { base: [169, 254, 0, 0], maskBits: 16 }, // link-local / APIPA
];

function ipv4ToInt(parts: number[]): number {
  return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}

export function isPrivateIpv4(ip: string): boolean {
  const parts = ip.split(".").map((p) => Number.parseInt(p, 10));
  if (parts.length !== 4 || parts.some((p) => Number.isNaN(p) || p < 0 || p > 255)) {
    return false;
  }
  const asInt = ipv4ToInt(parts);
  return PRIVATE_IPV4_RANGES.some(({ base, maskBits }) => {
    const mask = maskBits === 0 ? 0 : (0xffffffff << (32 - maskBits)) >>> 0;
    return (asInt & mask) === (ipv4ToInt(base) & mask);
  });
}

export function isPrivateIpv6(ip: string): boolean {
  const norm = ip.toLowerCase();
  if (norm === "::1") return true; // loopback
  if (/^f[cd][0-9a-f]{2}:/.test(norm)) return true; // unique local fc00::/7
  if (/^fe[89ab][0-9a-f]:/.test(norm)) return true; // link-local fe80::/10
  const mapped = norm.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (mapped) return isPrivateIpv4(mapped[1]);
  return false;
}

/** True for any literal IP address (v4 or v6) inside a private/loopback/link-local range. */
export function isPrivateLiteralAddress(ip: string): boolean {
  if (net.isIPv4(ip)) return isPrivateIpv4(ip);
  if (net.isIPv6(ip)) return isPrivateIpv6(ip);
  return false;
}

/** Strips scheme, path, and trailing port from a user-supplied target, returning the bare host. */
export function hostOf(target: string): string {
  let t = target.trim();
  t = t.replace(/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//, "");
  t = t.split(/[/?#]/)[0];
  if (t.startsWith("[")) {
    const end = t.indexOf("]");
    return end === -1 ? t : t.slice(1, end);
  }
  const lastColon = t.lastIndexOf(":");
  if (lastColon !== -1 && /^\d+$/.test(t.slice(lastColon + 1))) {
    return t.slice(0, lastColon);
  }
  return t;
}

export type LookupFn = (host: string) => Promise<{ address: string; family: number }[]>;

const realLookup: LookupFn = (host) => dns.lookup(host, { all: true, verbatim: true });

export interface PrivacyVerdict {
  isPrivate: boolean;
  reason: string;
}

/**
 * Decides whether a target is exempt from requiring an explicit authorization
 * record because it resolves only to private/loopback addresses. Hostname
 * resolution failures and mixed public/private results are treated as
 * "not private" (fail closed).
 */
export async function classifyTargetPrivacy(
  target: string,
  lookup: LookupFn = realLookup
): Promise<PrivacyVerdict> {
  const host = hostOf(target).toLowerCase();

  if (host === "localhost") {
    return { isPrivate: true, reason: "hostname is 'localhost'" };
  }

  if (net.isIP(host)) {
    return isPrivateLiteralAddress(host)
      ? { isPrivate: true, reason: `literal address ${host} is private/loopback` }
      : { isPrivate: false, reason: `literal address ${host} is public` };
  }

  try {
    const records = await lookup(host);
    if (records.length === 0) {
      return { isPrivate: false, reason: `${host} did not resolve to any address` };
    }
    const allPrivate = records.every((r) => isPrivateLiteralAddress(r.address));
    return allPrivate
      ? { isPrivate: true, reason: `${host} resolves only to private/loopback addresses` }
      : { isPrivate: false, reason: `${host} resolves to at least one public address` };
  } catch (err) {
    return {
      isPrivate: false,
      reason: `${host} could not be resolved (${(err as Error).message}); treated as public`,
    };
  }
}
