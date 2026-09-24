# ExposureDiff

ExposureDiff is a scheduled, self-hosted **external-attack-surface change monitor**. Point it at a domain you're authorized to monitor and run it regularly (cron, a scheduled task, CI) — on every run it re-discovers your real subdomains, re-checks your real open ports, and re-inspects your real TLS certificates, then **diffs the current findings against the last saved snapshot** and tells you exactly what changed: a subdomain that newly appeared, a port that opened, a certificate that got reissued with a different issuer. The diff is the product, not the scan.

## Acceptable Use

**ExposureDiff must only be used against systems you own, or for which you have explicit written permission to monitor.**

- Unauthorized scanning of systems you do not own or control may be **illegal** under computer-crime laws in your jurisdiction (e.g. the U.S. Computer Fraud and Abuse Act, the UK Computer Misuse Act, and equivalents elsewhere), even when every probe is passive/read-only.
- ExposureDiff enforces an authorization gate in code (see below), but that gate is a safety rail, not a legal opinion. Recording an authorization note does not make monitoring lawful if you don't actually have the underlying permission.
- ExposureDiff performs **read-only reconnaissance only**: real DNS lookups, a plain TCP connect to see if a port answers, and a TLS handshake to read the certificate a server presents. It never sends exploit payloads, brute-forces credentials, floods/DoS's a target, or persists anything on the target.
- You are responsible for keeping your own authorization records (contracts, written permission, signed monitoring agreements). ExposureDiff's local `authorizations.json` is an operational log, not a substitute for a real agreement.

If you're not sure whether you're authorized to monitor something, you aren't — get it in writing first.

## ExposureDiff vs. Greenlight

[Greenlight](../greenlight) is a sibling project in this portfolio: an authorized-use **one-shot** reconnaissance and misconfiguration scanner. You point it at a target, it scans right now, and it reports what it found *this instant* — headers, exposed files, TLS config, open ports, all as of one run.

ExposureDiff solves a different problem: **what changed since last time?** It intentionally does less scanning depth per run (no header/misconfiguration checks, no vulnerability scoring) and spends that budget instead on a real snapshot-diff engine: it persists every run's findings to disk and structurally compares each new run against the most recent prior one. A one-shot scanner tells you your attack surface *right now*; ExposureDiff tells you *that a new subdomain appeared last Tuesday, that port 8080 opened yesterday, and that your cert was silently reissued by a different CA* — the kind of drift that a single scan, run once, can never catch. Both tools share the same authorization-gate discipline (enforced in code, fail-closed, audit-logged) because that discipline is the non-negotiable part regardless of what the scan does with its findings.

## What it does

1. **Real DNS subdomain discovery** — Node's `dns.promises`, a built-in ~100-word list (www, api, staging, admin, vpn, ...), concurrency-capped and timeout-bounded. Only labels that actually resolve are reported, together with their real resolved addresses.
2. **Real rate-limited TCP port checks** — a plain TCP connect (no payload) against a small default port list, concurrency-capped and timeout-bounded, for every subdomain found (plus the apex domain). Refuses to probe an absurdly wide port range (>200 ports) unless you explicitly pass `--allow-wide-range`.
3. **Real TLS certificate inspection** — an actual TLS handshake (Node's `tls` module) reading the real issuer, subject, validity window, and fingerprint of whatever certificate the server presents. It reports what's there; it doesn't validate the trust chain (self-signed/internal certs are expected on private targets you monitor).
4. **The diff engine** — every run's findings are saved as a timestamped JSON snapshot. Each subsequent run loads the most recent prior snapshot and computes a structural diff: new/disappeared subdomains, subdomains whose resolved address changed, ports that opened/closed, and TLS certificates that changed issuer, changed expiry, or flipped reachability. This is the part that's actually novel — it's pure, deterministic, and the most heavily tested part of the codebase (see `test/diff.test.ts`).

Everything is implemented with Node's built-in `dns`, `net`, and `tls` modules — no exploit payloads, no brute-forcing, no packet crafting, nothing that mutates the target.

## Install / Quick start

```bash
npm install
npm run build
```

### The authorization workflow

Monitoring a private/loopback address (127.0.0.1, ::1, RFC1918 10.x/172.16-31.x/192.168.x, link-local 169.254.x, or "localhost") never requires authorization — ExposureDiff assumes that's your own machine/lab:

```bash
node dist/cli.js scan 127.0.0.1
```

Scanning anything else without a recorded authorization is refused, in code, before any DNS/port/TLS probing happens:

```
$ node dist/cli.js scan example.com

Refused: Refusing to scan "example.com": it is not a private/loopback address and no
current authorization record exists. Run: exposurediff authz add example.com --note "<justification>"
```

Record authorization first, with a justification note (contract reference, written permission, etc.):

```bash
node dist/cli.js authz add example.com --note "Written permission from IT director, monitoring agreement dated 2026-09-24"
node dist/cli.js authz list
node dist/cli.js scan example.com
```

Revoke authorization when a monitoring agreement ends:

```bash
node dist/cli.js authz revoke example.com
```

Every scan attempt — authorized or refused — plus every `authz add`/`authz revoke`, is appended to `~/.exposurediff/audit.log` with a timestamp, the target, and why it was allowed or refused.

Schedule it (cron example, runs daily at 03:00):

```
0 3 * * * cd /path/to/exposurediff && node dist/cli.js scan example.com >> /var/log/exposurediff.log 2>&1
```

### Example diff output

First run establishes a baseline; there's nothing to diff against yet:

```
$ node dist/cli.js scan example.com
Scan complete for "example.com" at 2026-09-24T09:00:00.000Z
  subdomains found: 4
  open ports:       3
  snapshot saved:   ~/.exposurediff/snapshots/example.com/2026-09-24T09-00-00-000Z.json

No prior snapshot for this target — this is the baseline. Run again later to see a diff.
```

A later run against the same target diffs against that baseline:

```
$ node dist/cli.js scan example.com
Scan complete for "example.com" at 2026-10-01T09:00:00.000Z
  subdomains found: 5
  open ports:       4
  snapshot saved:   ~/.exposurediff/snapshots/example.com/2026-10-01T09-00-00-000Z.json

3 change(s) since previous snapshot (2026-09-24T09:00:00.000Z):
  [subdomain-added] New subdomain discovered: staging.example.com (203.0.113.44)
  [port-opened] Port opened: staging.example.com:8080
  [tls-issuer-changed] TLS issuer changed on example.com:443: "O=Old CA, CN=Old CA" -> "O=New CA, CN=New CA"
```

### History

```bash
node dist/cli.js history example.com
```

```
3 saved snapshot(s) for "example.com":
  2026-09-24T09:00:00.000Z  subdomains=4  openPorts=3
  2026-10-01T09:00:00.000Z  subdomains=5  openPorts=4
  2026-10-08T09:00:00.000Z  subdomains=5  openPorts=4
```

## CLI reference

```
exposurediff authz add <target> --note "<justification>" [--days N]
exposurediff authz list
exposurediff authz revoke <target>

exposurediff scan <target> [--ports 22,80,443] [--allow-wide-range]
                            [--concurrency N] [--timeout-ms N] [--json]

exposurediff history <target> [--json]
```

## How the authorization gate is enforced

The gate lives in `src/authz.ts`, in `ensureAuthorized()`. `src/scan.ts`'s `runScan()` is the **only** entry point that runs any DNS/port/TLS probing, and it calls the gate first:

```ts
export async function runScan(target: string, options: ScanOptions = {}): Promise<ScanRunResult> {
  const host = hostOf(target);
  const decision = await ensureAuthorized(target);

  if (!decision.allowed) {
    appendAuditLog({ action: "scan-refused", target: host, reason: decision.reason });
    throw new AuthorizationRefusedError(decision.reason);
  }
  appendAuditLog({ action: "scan-allowed", target: host, reason: decision.reason, detail: { method: decision.method } });

  const subdomains = await discoverSubdomains(host, /* ... */);
  // ... port + TLS probing only happens after this point
```

`ensureAuthorized()` itself fails closed:

```ts
export async function ensureAuthorized(target: string): Promise<AuthorizationDecision> {
  const host = hostOf(target);
  const privacy = await classifyTargetPrivacy(target);
  if (privacy.isPrivate) {
    return { allowed: true, method: "loopback-exempt", reason: privacy.reason };
  }
  const record = findCurrentAuthorization(target);
  if (record) {
    return { allowed: true, method: "authorization-file", record, reason: "current authorization record found ..." };
  }
  return { allowed: false, reason: `Refusing to scan "${host}": ...` };
}
```

A target is only exempt from requiring a recorded authorization if it's a literal loopback/RFC1918/link-local address, `"localhost"`, or a hostname that *resolves only* to such addresses — resolution failures, mixed results, and corrupt/unreadable authorization stores are all treated as **not exempt / not authorized** (fail closed), never as an implicit allow.

## Testing

The automated test suite (Vitest, 63 tests across 8 files) never touches real external domains. It uses:

- Real local TCP listeners on `127.0.0.1` (ephemeral ports) for the port-scan tests.
- Real local TLS servers on `127.0.0.1` presenting real openssl-generated self-signed certificates (`test/fixtures/tls/`) for the TLS tests — a real handshake, real certificate parsing, two distinct real certs to prove issuer/fingerprint differences are actually detected.
- An injectable DNS lookup function (the same dependency-injection pattern Greenlight uses for its own privacy check) so subdomain-discovery tests exercise the real algorithm — candidate generation, concurrency, timeout handling, filtering, sorting — against deterministic fixtures instead of live DNS infrastructure.
- Literal RFC 5737 documentation-only IPs (`203.0.113.x`, `198.51.100.x`) to test the "public target, refuse without authorization" path without resolving or contacting anything real.
- Pure, constructed `ScanSnapshot` JSON fixtures (no network, no filesystem) for the diff engine — the most heavily tested module, covering every change kind plus "no changes" and cross-target-mismatch error handling.
- A real end-to-end integration test wiring the gate, a real loopback port scan, snapshot persistence, and the diff engine together, including detecting a real port closing between two runs.

Run it with:

```bash
npm test
```

## Limitations

ExposureDiff is a **change-detection tool**, not a full vulnerability scanner or a substitute for professional attack-surface management:

- It does not check HTTP security headers, exposed files/directories, or misconfigurations — that's Greenlight's job. ExposureDiff is deliberately narrower and longer-running.
- The DNS subdomain wordlist is small (~100 entries) and will miss subdomains not in the list; it is not a substitute for certificate-transparency-log or passive-DNS-based enumeration.
- The default port list is small and common-services-only; a "closed" result does not guarantee nothing is listening on an unchecked port.
- TLS findings are limited to what the certificate itself states (issuer, subject, validity, fingerprint) — no chain validation, no cipher/protocol negotiation analysis, no OCSP/CRL checking.
- The diff engine compares only against the single most recent snapshot, not the full history — a change that happens and reverts between two scheduled runs will never be observed.
- Snapshot storage is local, unencrypted JSON on disk; there's no built-in remote storage, alerting/webhook integration, or multi-user access control. This is an MVP meant to be extended, not a finished SaaS product.
- Rate limiting (small default concurrency, small default word/port lists, per-connection timeouts, a hard cap on port-range width) is intentional and non-negotiable — ExposureDiff is deliberately not tunable into a stress-testing/DoS tool.

Always corroborate findings manually before treating a diff as confirmed evidence of a security incident.

## License

MIT — see [LICENSE](./LICENSE).
