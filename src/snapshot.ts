/**
 * Snapshot persistence: each scan's real findings are saved as a
 * timestamped JSON file under the target's snapshot directory. History is
 * append-only — old snapshots are never rewritten — so `history <target>`
 * can show a full timeline and the diff engine always has a stable prior
 * snapshot to compare against.
 */
import fs from "node:fs";
import path from "node:path";
import { ScanSnapshot } from "./types.js";
import { ensureHomeDir, snapshotsDirFor } from "./storage.js";

/** Filesystem/sort-safe timestamp, e.g. 2026-09-24T18-30-00-123Z.json */
function filenameFor(takenAt: string): string {
  return `${takenAt.replace(/[:.]/g, "-")}.json`;
}

export function saveSnapshot(snapshot: ScanSnapshot): string {
  ensureHomeDir();
  const dir = snapshotsDirFor(snapshot.target);
  fs.mkdirSync(dir, { recursive: true });
  const file = path.join(dir, filenameFor(snapshot.takenAt));
  fs.writeFileSync(file, JSON.stringify(snapshot, null, 2) + "\n", "utf8");
  return file;
}

/** Lists snapshot filenames for a target, oldest first. Empty if none exist. */
export function listSnapshotFiles(target: string): string[] {
  const dir = snapshotsDirFor(target);
  if (!fs.existsSync(dir)) return [];
  return fs
    .readdirSync(dir)
    .filter((f) => f.endsWith(".json"))
    .sort();
}

export function loadSnapshotFile(target: string, filename: string): ScanSnapshot {
  const file = path.join(snapshotsDirFor(target), filename);
  return JSON.parse(fs.readFileSync(file, "utf8")) as ScanSnapshot;
}

/** Loads every saved snapshot for a target, oldest first. */
export function loadAllSnapshots(target: string): ScanSnapshot[] {
  return listSnapshotFiles(target).map((f) => loadSnapshotFile(target, f));
}

/** The most recently saved snapshot for a target, or undefined if none exist yet. */
export function loadLatestSnapshot(target: string): ScanSnapshot | undefined {
  const files = listSnapshotFiles(target);
  if (files.length === 0) return undefined;
  return loadSnapshotFile(target, files[files.length - 1]);
}
