/**
 * Local, on-disk storage for ExposureDiff's own state: authorization
 * records, per-target snapshot history, and the audit log. Everything lives
 * under a single "home" directory so it's easy to inspect, back up, or wipe.
 *
 * The location can be overridden with the EXPOSUREDIFF_HOME environment
 * variable (used heavily by the test suite to keep tests hermetic).
 */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

export function homeDir(): string {
  return process.env.EXPOSUREDIFF_HOME ?? path.join(os.homedir(), ".exposurediff");
}

export function ensureHomeDir(): void {
  fs.mkdirSync(homeDir(), { recursive: true });
  fs.mkdirSync(snapshotsRootDir(), { recursive: true });
}

export function authorizationsFilePath(): string {
  return path.join(homeDir(), "authorizations.json");
}

export function auditLogFilePath(): string {
  return path.join(homeDir(), "audit.log");
}

export function snapshotsRootDir(): string {
  return path.join(homeDir(), "snapshots");
}

/** Turns a target hostname into a filesystem-safe directory name. */
export function slugifyTarget(target: string): string {
  return target.toLowerCase().replace(/[^a-z0-9.-]/g, "_");
}

export function snapshotsDirFor(target: string): string {
  return path.join(snapshotsRootDir(), slugifyTarget(target));
}
