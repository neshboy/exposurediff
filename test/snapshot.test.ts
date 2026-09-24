import { describe, expect, it } from "vitest";
import { useTempHome } from "./helpers/tempHome.js";
import { loadAllSnapshots, loadLatestSnapshot, listSnapshotFiles, saveSnapshot } from "../src/snapshot.js";
import { ScanSnapshot } from "../src/types.js";

function snap(takenAt: string, subdomainCount: number): ScanSnapshot {
  return {
    target: "example.invalid",
    takenAt,
    subdomains: Array.from({ length: subdomainCount }, (_, i) => ({
      hostname: `h${i}.example.invalid`,
      addresses: ["10.0.0.1"],
    })),
    ports: [],
    tls: [],
  };
}

describe("snapshot persistence", () => {
  useTempHome();

  it("returns no snapshots and no latest snapshot before any scan has run", () => {
    expect(listSnapshotFiles("example.invalid")).toEqual([]);
    expect(loadLatestSnapshot("example.invalid")).toBeUndefined();
  });

  it("saves and reloads a snapshot with full fidelity", () => {
    const original = snap("2026-01-01T00:00:00.000Z", 2);
    saveSnapshot(original);
    const latest = loadLatestSnapshot("example.invalid");
    expect(latest).toEqual(original);
  });

  it("keeps snapshot history in chronological order and returns the most recent as latest", () => {
    saveSnapshot(snap("2026-01-01T00:00:00.000Z", 1));
    saveSnapshot(snap("2026-01-02T00:00:00.000Z", 2));
    saveSnapshot(snap("2026-01-03T00:00:00.000Z", 3));

    const all = loadAllSnapshots("example.invalid");
    expect(all.map((s) => s.takenAt)).toEqual([
      "2026-01-01T00:00:00.000Z",
      "2026-01-02T00:00:00.000Z",
      "2026-01-03T00:00:00.000Z",
    ]);

    const latest = loadLatestSnapshot("example.invalid");
    expect(latest?.takenAt).toBe("2026-01-03T00:00:00.000Z");
    expect(latest?.subdomains).toHaveLength(3);
  });

  it("keeps separate targets' snapshot histories isolated from each other", () => {
    const snapA = { ...snap("2026-01-01T00:00:00.000Z", 1), target: "a.invalid" };
    const snapB = { ...snap("2026-01-01T00:00:00.000Z", 5), target: "b.invalid" };
    saveSnapshot(snapA);
    saveSnapshot(snapB);

    expect(loadLatestSnapshot("a.invalid")?.subdomains).toHaveLength(1);
    expect(loadLatestSnapshot("b.invalid")?.subdomains).toHaveLength(5);
  });
});
