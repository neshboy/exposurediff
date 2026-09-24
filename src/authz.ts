/**
 * THE AUTHORIZATION GATE.
 *
 * Every code path that touches the network (DNS enumeration, port probing,
 * TLS handshakes) MUST go through `ensureAuthorized()` first. It fails
 * closed: a target is only allowed through if it is confidently
 * private/loopback (see netutil.classifyTargetPrivacy), OR there is a
 * current, non-revoked, non-expired authorization record for it.
 *
 * There is deliberately no "just trust me" flag on `scan`. The only way to
 * scan a non-private target is to record an authorization first via
 * `exposurediff authz add <target> --note "..."`.
 */
import fs from "node:fs";
import { AuthorizationDecision, AuthorizationRecord } from "./types.js";
import { authorizationsFilePath, ensureHomeDir } from "./storage.js";
import { classifyTargetPrivacy, hostOf } from "./netutil.js";

const DEFAULT_VALIDITY_DAYS = 90;

function normalizeHost(target: string): string {
  return hostOf(target).toLowerCase();
}

export function loadAuthorizations(): AuthorizationRecord[] {
  const file = authorizationsFilePath();
  if (!fs.existsSync(file)) return [];
  try {
    const raw = fs.readFileSync(file, "utf8");
    if (!raw.trim()) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? (parsed as AuthorizationRecord[]) : [];
  } catch {
    // Corrupt/unreadable authorization store: fail closed, act as if empty.
    return [];
  }
}

function saveAuthorizations(records: AuthorizationRecord[]): void {
  ensureHomeDir();
  fs.writeFileSync(authorizationsFilePath(), JSON.stringify(records, null, 2) + "\n", "utf8");
}

export function addAuthorization(
  target: string,
  note: string,
  validityDays: number = DEFAULT_VALIDITY_DAYS
): AuthorizationRecord {
  if (!note || !note.trim()) {
    throw new Error(
      'A --note is required, explaining the basis for authorization (e.g. "written permission from domain owner, ticket #123").'
    );
  }
  if (!Number.isFinite(validityDays) || validityDays <= 0) {
    throw new Error("validityDays must be a positive number.");
  }
  const now = new Date();
  const record: AuthorizationRecord = {
    target: normalizeHost(target),
    createdAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + validityDays * 24 * 60 * 60 * 1000).toISOString(),
    note: note.trim(),
    revoked: false,
  };
  const records = loadAuthorizations();
  records.push(record);
  saveAuthorizations(records);
  return record;
}

export function listAuthorizations(): AuthorizationRecord[] {
  return loadAuthorizations();
}

export function revokeAuthorization(target: string): number {
  const norm = normalizeHost(target);
  const records = loadAuthorizations();
  let revokedCount = 0;
  const now = new Date().toISOString();
  for (const record of records) {
    if (record.target === norm && !record.revoked) {
      record.revoked = true;
      record.revokedAt = now;
      revokedCount++;
    }
  }
  if (revokedCount > 0) saveAuthorizations(records);
  return revokedCount;
}

/** The current (not revoked, not expired) authorization record for a target, if any. */
export function findCurrentAuthorization(target: string): AuthorizationRecord | undefined {
  const norm = normalizeHost(target);
  const now = Date.now();
  return loadAuthorizations().find(
    (r) => r.target === norm && !r.revoked && new Date(r.expiresAt).getTime() > now
  );
}

/**
 * Runs a target through the authorization gate. Returns an
 * AuthorizationDecision describing whether scanning may proceed and why.
 * Never throws for an unauthorized target — callers are expected to check
 * `.allowed` and refuse to scan when it is false.
 */
export async function ensureAuthorized(target: string): Promise<AuthorizationDecision> {
  const host = hostOf(target);

  const privacy = await classifyTargetPrivacy(target);
  if (privacy.isPrivate) {
    return { allowed: true, method: "loopback-exempt", reason: privacy.reason };
  }

  const record = findCurrentAuthorization(target);
  if (record) {
    return {
      allowed: true,
      method: "authorization-file",
      record,
      reason: `current authorization record found (recorded ${record.createdAt}, expires ${record.expiresAt})`,
    };
  }

  return {
    allowed: false,
    reason:
      `Refusing to scan "${host}": it is not a private/loopback address and no current authorization ` +
      `record exists. Run: exposurediff authz add ${host} --note "<justification>"`,
  };
}
