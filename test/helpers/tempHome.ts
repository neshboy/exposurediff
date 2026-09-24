/**
 * Test helper: points EXPOSUREDIFF_HOME at a fresh temp directory for the
 * duration of a test, and cleans it up afterwards. Every test that touches
 * authorization records, snapshots, or the audit log uses this so tests
 * never read/write the real user's ~/.exposurediff.
 */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach } from "vitest";

let currentDir: string | undefined;

export function useTempHome(): void {
  beforeEach(() => {
    currentDir = fs.mkdtempSync(path.join(os.tmpdir(), "exposurediff-test-"));
    process.env.EXPOSUREDIFF_HOME = currentDir;
  });

  afterEach(() => {
    delete process.env.EXPOSUREDIFF_HOME;
    if (currentDir && fs.existsSync(currentDir)) {
      fs.rmSync(currentDir, { recursive: true, force: true });
    }
    currentDir = undefined;
  });
}
