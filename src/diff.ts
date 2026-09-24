/**
 * The snapshot-diff engine.
 *
 * This is the actual novel value-add of ExposureDiff over a one-shot
 * scanner: given the previous saved snapshot and the current scan's real
 * findings, compute exactly what changed — new/disappeared subdomains,
 * ports that opened/closed, and TLS certificates that changed issuer,
 * expiry, or reachability. Pure function of its two inputs: no I/O, no
 * network, no clocks — which is what makes it straightforward to test
 * exhaustively against constructed fixtures.
 */
import { Change, DiffResult, PortResult, ScanSnapshot, TlsResult } from "./types.js";

function subdomainMap(snapshot: ScanSnapshot): Map<string, string[]> {
  const map = new Map<string, string[]>();
  for (const host of snapshot.subdomains) {
    map.set(host.hostname, [...host.addresses].sort());
  }
  return map;
}

function portKey(p: Pick<PortResult, "host" | "port">): string {
  return `${p.host}:${p.port}`;
}

function portMap(snapshot: ScanSnapshot): Map<string, PortResult> {
  const map = new Map<string, PortResult>();
  for (const p of snapshot.ports) map.set(portKey(p), p);
  return map;
}

function tlsKey(t: Pick<TlsResult, "host" | "port">): string {
  return `${t.host}:${t.port}`;
}

function tlsMap(snapshot: ScanSnapshot): Map<string, TlsResult> {
  const map = new Map<string, TlsResult>();
  for (const t of snapshot.tls) map.set(tlsKey(t), t);
  return map;
}

function arraysEqual(a: string[], b: string[]): boolean {
  return a.length === b.length && a.every((v, i) => v === b[i]);
}

function diffSubdomains(previous: ScanSnapshot, current: ScanSnapshot): Change[] {
  const changes: Change[] = [];
  const prevMap = subdomainMap(previous);
  const currMap = subdomainMap(current);

  for (const [hostname, addresses] of currMap) {
    if (!prevMap.has(hostname)) {
      changes.push({
        kind: "subdomain-added",
        description: `New subdomain discovered: ${hostname} (${addresses.join(", ") || "no addresses"})`,
        detail: { hostname, addresses },
      });
    }
  }

  for (const [hostname, addresses] of prevMap) {
    if (!currMap.has(hostname)) {
      changes.push({
        kind: "subdomain-removed",
        description: `Subdomain no longer resolves: ${hostname} (was ${addresses.join(", ") || "no addresses"})`,
        detail: { hostname, addresses },
      });
    }
  }

  for (const [hostname, currAddresses] of currMap) {
    const prevAddresses = prevMap.get(hostname);
    if (prevAddresses && !arraysEqual(prevAddresses, currAddresses)) {
      changes.push({
        kind: "subdomain-address-changed",
        description: `Subdomain ${hostname} now resolves to different addresses: ${prevAddresses.join(", ") || "none"} -> ${currAddresses.join(", ") || "none"}`,
        detail: { hostname, previousAddresses: prevAddresses, currentAddresses: currAddresses },
      });
    }
  }

  return changes;
}

function diffPorts(previous: ScanSnapshot, current: ScanSnapshot): Change[] {
  const changes: Change[] = [];
  const prevMap = portMap(previous);
  const currMap = portMap(current);
  const allKeys = new Set<string>([...prevMap.keys(), ...currMap.keys()]);

  for (const key of allKeys) {
    const prev = prevMap.get(key);
    const curr = currMap.get(key);
    const wasOpen = prev?.open ?? false;
    const isOpen = curr?.open ?? false;
    if (!wasOpen && isOpen && curr) {
      changes.push({
        kind: "port-opened",
        description: `Port opened: ${curr.host}:${curr.port}`,
        detail: { host: curr.host, port: curr.port },
      });
    } else if (wasOpen && !isOpen && prev) {
      changes.push({
        kind: "port-closed",
        description: `Port closed: ${prev.host}:${prev.port}`,
        detail: { host: prev.host, port: prev.port },
      });
    }
  }

  return changes.sort((a, b) => a.description.localeCompare(b.description));
}

function diffTls(previous: ScanSnapshot, current: ScanSnapshot): Change[] {
  const changes: Change[] = [];
  const prevMap = tlsMap(previous);
  const currMap = tlsMap(current);
  const allKeys = new Set<string>([...prevMap.keys(), ...currMap.keys()]);

  for (const key of allKeys) {
    const prev = prevMap.get(key);
    const curr = currMap.get(key);

    if (!prev || !curr) continue; // presence handled elsewhere (subdomain/port diffs)

    if (prev.reachable && !curr.reachable) {
      changes.push({
        kind: "tls-became-unreachable",
        description: `TLS on ${curr.host}:${curr.port} became unreachable (${curr.error ?? "unknown error"})`,
        detail: { host: curr.host, port: curr.port, error: curr.error },
      });
      continue;
    }
    if (!prev.reachable && curr.reachable) {
      changes.push({
        kind: "tls-became-reachable",
        description: `TLS on ${curr.host}:${curr.port} became reachable (issuer: ${curr.issuer ?? "unknown"})`,
        detail: { host: curr.host, port: curr.port, issuer: curr.issuer },
      });
      continue;
    }
    if (!prev.reachable && !curr.reachable) continue;

    if (prev.issuer !== curr.issuer) {
      changes.push({
        kind: "tls-issuer-changed",
        description: `TLS issuer changed on ${curr.host}:${curr.port}: "${prev.issuer ?? "unknown"}" -> "${curr.issuer ?? "unknown"}"`,
        detail: { host: curr.host, port: curr.port, previousIssuer: prev.issuer, currentIssuer: curr.issuer },
      });
    }
    if (prev.validTo !== curr.validTo) {
      changes.push({
        kind: "tls-expiry-changed",
        description: `TLS expiry changed on ${curr.host}:${curr.port}: ${prev.validTo ?? "unknown"} -> ${curr.validTo ?? "unknown"}`,
        detail: { host: curr.host, port: curr.port, previousValidTo: prev.validTo, currentValidTo: curr.validTo },
      });
    }
  }

  return changes.sort((a, b) => a.description.localeCompare(b.description));
}

/**
 * Computes the structural diff between two snapshots of the same target.
 * Pure and deterministic: same two inputs always produce the same ordered
 * list of changes.
 */
export function diffSnapshots(previous: ScanSnapshot, current: ScanSnapshot): DiffResult {
  if (previous.target !== current.target) {
    throw new Error(
      `Cannot diff snapshots for different targets ("${previous.target}" vs "${current.target}").`
    );
  }
  const changes: Change[] = [
    ...diffSubdomains(previous, current),
    ...diffPorts(previous, current),
    ...diffTls(previous, current),
  ];
  return {
    target: current.target,
    previousSnapshotAt: previous.takenAt,
    currentSnapshotAt: current.takenAt,
    changes,
  };
}

// Re-exported for callers that want to compare address lists directly.
export { arraysEqual };
