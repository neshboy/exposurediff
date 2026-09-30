/**
 * Scan orchestration: wires the authorization gate, the real DNS/port/TLS
 * probes, snapshot persistence, and the diff engine together into a single
 * "run a monitoring pass for this target" operation. This is what the CLI's
 * `scan` command calls.
 */
import { ScanOptions, ScanSnapshot, DiffResult } from "./types.js";
import { ensureAuthorized } from "./authz.js";
import { appendAuditLog } from "./auditlog.js";
import { discoverSubdomains } from "./dnsscan.js";
import { scanPorts, DEFAULT_PORTS } from "./portscan.js";
import { checkTlsCertificate } from "./tlscheck.js";
import { diffSnapshots } from "./diff.js";
import { loadLatestSnapshot, saveSnapshot } from "./snapshot.js";
import { hostOf } from "./netutil.js";
import { mapWithConcurrency } from "./concurrency.js";

export class AuthorizationRefusedError extends Error {
  constructor(public readonly reason: string) {
    super(reason);
    this.name = "AuthorizationRefusedError";
  }
}

export interface ScanRunResult {
  snapshot: ScanSnapshot;
  previousSnapshot?: ScanSnapshot;
  diff?: DiffResult; // undefined when this is the first-ever snapshot for the target
  snapshotFile: string;
}

/**
 * Runs one full monitoring pass for `target`: authorization gate, then real
 * DNS/port/TLS collection, then diff against the last saved snapshot (if
 * any), then persists the new snapshot. Throws AuthorizationRefusedError if
 * the gate refuses the target — callers must not catch-and-continue past
 * that without addressing the authorization requirement.
 */
export async function runScan(target: string, options: ScanOptions = {}): Promise<ScanRunResult> {
  const host = hostOf(target).toLowerCase();
  const decision = await ensureAuthorized(target);

  if (!decision.allowed) {
    appendAuditLog({ action: "scan-refused", target: host, reason: decision.reason });
    throw new AuthorizationRefusedError(decision.reason);
  }
  appendAuditLog({
    action: "scan-allowed",
    target: host,
    reason: decision.reason,
    detail: { method: decision.method },
  });

  const subdomains = await discoverSubdomains(host, {
    wordlist: options.wordlist,
    concurrency: options.concurrency,
    timeoutMs: options.timeoutMs,
  });

  const hostsToProbe = Array.from(new Set([host, ...subdomains.map((s) => s.hostname)]));
  const ports = options.ports ?? DEFAULT_PORTS;

  const portResultsByHost = await mapWithConcurrency(hostsToProbe, 4, (h) =>
    scanPorts(h, ports, {
      concurrency: options.concurrency,
      timeoutMs: options.timeoutMs,
      allowWideRange: options.allowWideRange,
    })
  );
  const portResults = portResultsByHost.flat();

  const tlsPort = options.tlsPort ?? 443;
  const tlsResults = await mapWithConcurrency(hostsToProbe, 4, (h) =>
    checkTlsCertificate(h, tlsPort, { timeoutMs: options.timeoutMs })
  );

  const snapshot: ScanSnapshot = {
    target: host,
    takenAt: new Date().toISOString(),
    subdomains,
    ports: portResults,
    tls: tlsResults,
  };

  const previousSnapshot = loadLatestSnapshot(host);
  const diff = previousSnapshot ? diffSnapshots(previousSnapshot, snapshot) : undefined;

  const snapshotFile = saveSnapshot(snapshot);

  return { snapshot, previousSnapshot, diff, snapshotFile };
}
