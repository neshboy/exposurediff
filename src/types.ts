/** Shared type definitions for ExposureDiff. */

/** A recorded authorization to monitor a non-private target. */
export interface AuthorizationRecord {
  /** Normalized host (lowercase, no scheme/path/port). */
  target: string;
  createdAt: string; // ISO timestamp
  expiresAt: string; // ISO timestamp
  note: string;
  revoked: boolean;
  revokedAt?: string;
}

export type AuthorizationMethod = "loopback-exempt" | "authorization-file";

/** Outcome of running a target through the authorization gate. */
export interface AuthorizationDecision {
  allowed: boolean;
  method?: AuthorizationMethod;
  record?: AuthorizationRecord;
  reason: string;
}

/** A single subdomain discovered by DNS enumeration, with its resolved addresses. */
export interface DiscoveredHost {
  hostname: string;
  addresses: string[];
}

/** Result of probing one TCP port on one host. */
export interface PortResult {
  host: string;
  port: number;
  open: boolean;
}

/** Result of a TLS handshake against one host:port. */
export interface TlsResult {
  host: string;
  port: number;
  reachable: boolean;
  /** Populated when reachable and a certificate was presented. */
  issuer?: string;
  subject?: string;
  validFrom?: string; // ISO timestamp
  validTo?: string; // ISO timestamp
  fingerprint256?: string;
  /** Set when the handshake failed or no certificate could be read. */
  error?: string;
}

/** The full set of real findings collected during one scan run, for one target. */
export interface ScanSnapshot {
  target: string;
  takenAt: string; // ISO timestamp
  subdomains: DiscoveredHost[];
  ports: PortResult[];
  tls: TlsResult[];
}

/** Options controlling the scope/aggressiveness of a scan. Safety caps live here. */
export interface ScanOptions {
  ports?: number[];
  concurrency?: number;
  timeoutMs?: number;
  wordlist?: string[];
  tlsPort?: number;
  /** Explicit opt-in to scan more than MAX_PORTS_WITHOUT_OVERRIDE ports (see portscan.ts). */
  allowWideRange?: boolean;
}

export type ChangeKind =
  | "subdomain-added"
  | "subdomain-removed"
  | "subdomain-address-changed"
  | "port-opened"
  | "port-closed"
  | "tls-issuer-changed"
  | "tls-expiry-changed"
  | "tls-became-unreachable"
  | "tls-became-reachable";

export interface Change {
  kind: ChangeKind;
  description: string;
  detail?: Record<string, unknown>;
}

export interface DiffResult {
  target: string;
  previousSnapshotAt: string | null;
  currentSnapshotAt: string;
  changes: Change[];
}
