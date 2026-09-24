/**
 * Append-only audit log. Every run (authorized or refused) gets a line, so
 * there is always a record of what ExposureDiff did and why, independent of
 * the authorization records themselves.
 */
import fs from "node:fs";
import { auditLogFilePath, ensureHomeDir } from "./storage.js";

export interface AuditEvent {
  action: "authz-add" | "authz-revoke" | "scan-allowed" | "scan-refused";
  target: string;
  reason: string;
  detail?: Record<string, unknown>;
}

export function appendAuditLog(event: AuditEvent): void {
  ensureHomeDir();
  const line = {
    ts: new Date().toISOString(),
    ...event,
  };
  fs.appendFileSync(auditLogFilePath(), JSON.stringify(line) + "\n", "utf8");
}

export function readAuditLog(): string[] {
  const file = auditLogFilePath();
  if (!fs.existsSync(file)) return [];
  return fs
    .readFileSync(file, "utf8")
    .split("\n")
    .filter((l) => l.trim().length > 0);
}
