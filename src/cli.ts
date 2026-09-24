#!/usr/bin/env node
/**
 * ExposureDiff CLI.
 *
 *   exposurediff authz add <target> --note "..."   record authorization for a non-private target
 *   exposurediff authz list                         list all authorization records
 *   exposurediff authz revoke <target>              revoke authorization for a target
 *   exposurediff scan <target>                      run a monitoring pass + diff against last snapshot
 *   exposurediff history <target>                   list saved snapshots for a target
 *
 * No command bypasses the authorization gate: `scan` always calls
 * ensureAuthorized() before any network probing happens.
 */
import { addAuthorization, listAuthorizations, revokeAuthorization } from "./authz.js";
import { appendAuditLog } from "./auditlog.js";
import { AuthorizationRefusedError, runScan } from "./scan.js";
import { listSnapshotFiles, loadSnapshotFile } from "./snapshot.js";
import { assertPortRangeAllowed } from "./portscan.js";

interface ParsedArgs {
  positionals: string[];
  flags: Map<string, string | boolean>;
}

function parseArgs(argv: string[]): ParsedArgs {
  const positionals: string[] = [];
  const flags = new Map<string, string | boolean>();
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg.startsWith("--")) {
      const key = arg.slice(2);
      const next = argv[i + 1];
      if (next !== undefined && !next.startsWith("--")) {
        flags.set(key, next);
        i++;
      } else {
        flags.set(key, true);
      }
    } else {
      positionals.push(arg);
    }
  }
  return { positionals, flags };
}

function printUsage(): void {
  console.log(`ExposureDiff - continuous external-attack-surface diff monitoring

Usage:
  exposurediff authz add <target> --note "<justification>" [--days N]
  exposurediff authz list
  exposurediff authz revoke <target>
  exposurediff scan <target> [--ports 22,80,443] [--allow-wide-range] [--json]
  exposurediff history <target> [--json]

Targets that are NOT private/loopback addresses require a current
authorization record (see "authz add") before "scan" will run. This is
enforced in code, not just documented.`);
}

function parsePortsFlag(value: string): number[] {
  return value
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s.length > 0)
    .map((s) => {
      const n = Number.parseInt(s, 10);
      if (!Number.isInteger(n)) throw new Error(`Invalid port value: "${s}"`);
      return n;
    });
}

async function main(): Promise<void> {
  const [command, ...rest] = process.argv.slice(2);

  if (!command || command === "--help" || command === "-h") {
    printUsage();
    process.exitCode = command ? 0 : 1;
    return;
  }

  if (command === "authz") {
    const [sub, ...subRest] = rest;
    const { positionals, flags } = parseArgs(subRest);

    if (sub === "add") {
      const target = positionals[0];
      if (!target) {
        console.error("Usage: exposurediff authz add <target> --note \"<justification>\"");
        process.exitCode = 1;
        return;
      }
      const note = typeof flags.get("note") === "string" ? (flags.get("note") as string) : "";
      const days = typeof flags.get("days") === "string" ? Number(flags.get("days")) : undefined;
      try {
        const record = addAuthorization(target, note, days);
        appendAuditLog({ action: "authz-add", target: record.target, reason: note });
        console.log(`Authorization recorded for "${record.target}".`);
        console.log(`  created:  ${record.createdAt}`);
        console.log(`  expires:  ${record.expiresAt}`);
        console.log(`  note:     ${record.note}`);
      } catch (err) {
        console.error(`Error: ${(err as Error).message}`);
        process.exitCode = 1;
      }
      return;
    }

    if (sub === "list") {
      const records = listAuthorizations();
      if (records.length === 0) {
        console.log("No authorization records found.");
        return;
      }
      for (const r of records) {
        const status = r.revoked ? "REVOKED" : new Date(r.expiresAt) < new Date() ? "EXPIRED" : "ACTIVE";
        console.log(`[${status}] ${r.target}  (created ${r.createdAt}, expires ${r.expiresAt})`);
        console.log(`    note: ${r.note}`);
      }
      return;
    }

    if (sub === "revoke") {
      const target = positionals[0];
      if (!target) {
        console.error("Usage: exposurediff authz revoke <target>");
        process.exitCode = 1;
        return;
      }
      const count = revokeAuthorization(target);
      appendAuditLog({ action: "authz-revoke", target, reason: `revoked ${count} record(s)` });
      console.log(`Revoked ${count} authorization record(s) for "${target}".`);
      return;
    }

    console.error(`Unknown authz subcommand: "${sub ?? ""}"`);
    printUsage();
    process.exitCode = 1;
    return;
  }

  if (command === "scan") {
    const { positionals, flags } = parseArgs(rest);
    const target = positionals[0];
    if (!target) {
      console.error("Usage: exposurediff scan <target>");
      process.exitCode = 1;
      return;
    }
    const json = flags.get("json") === true;
    const allowWideRange = flags.get("allow-wide-range") === true;

    try {
      let ports: number[] | undefined;
      const portsFlag = flags.get("ports");
      if (typeof portsFlag === "string") {
        ports = parsePortsFlag(portsFlag);
        assertPortRangeAllowed(ports, allowWideRange);
      }
      const concurrencyFlag = flags.get("concurrency");
      const timeoutFlag = flags.get("timeout-ms");

      const result = await runScan(target, {
        ports,
        concurrency: typeof concurrencyFlag === "string" ? Number(concurrencyFlag) : undefined,
        timeoutMs: typeof timeoutFlag === "string" ? Number(timeoutFlag) : undefined,
      });

      if (json) {
        console.log(JSON.stringify(result, null, 2));
        return;
      }

      console.log(`Scan complete for "${result.snapshot.target}" at ${result.snapshot.takenAt}`);
      console.log(`  subdomains found: ${result.snapshot.subdomains.length}`);
      console.log(`  open ports:       ${result.snapshot.ports.filter((p) => p.open).length}`);
      console.log(`  snapshot saved:   ${result.snapshotFile}`);

      if (!result.diff) {
        console.log("\nNo prior snapshot for this target — this is the baseline. Run again later to see a diff.");
        return;
      }

      if (result.diff.changes.length === 0) {
        console.log(`\nNo changes since previous snapshot (${result.diff.previousSnapshotAt}).`);
        return;
      }

      console.log(`\n${result.diff.changes.length} change(s) since previous snapshot (${result.diff.previousSnapshotAt}):`);
      for (const change of result.diff.changes) {
        console.log(`  [${change.kind}] ${change.description}`);
      }
    } catch (err) {
      if (err instanceof AuthorizationRefusedError) {
        console.error(`Refused: ${err.reason}`);
        process.exitCode = 2;
        return;
      }
      console.error(`Error: ${(err as Error).message}`);
      process.exitCode = 1;
    }
    return;
  }

  if (command === "history") {
    const { positionals, flags } = parseArgs(rest);
    const target = positionals[0];
    if (!target) {
      console.error("Usage: exposurediff history <target>");
      process.exitCode = 1;
      return;
    }
    const files = listSnapshotFiles(target);
    if (files.length === 0) {
      console.log(`No snapshots saved yet for "${target}". Run "exposurediff scan ${target}" first.`);
      return;
    }
    if (flags.get("json") === true) {
      const snapshots = files.map((f) => loadSnapshotFile(target, f));
      console.log(JSON.stringify(snapshots, null, 2));
      return;
    }
    console.log(`${files.length} saved snapshot(s) for "${target}":`);
    for (const f of files) {
      const snap = loadSnapshotFile(target, f);
      const openPorts = snap.ports.filter((p) => p.open).length;
      console.log(`  ${snap.takenAt}  subdomains=${snap.subdomains.length}  openPorts=${openPorts}`);
    }
    return;
  }

  console.error(`Unknown command: "${command}"`);
  printUsage();
  process.exitCode = 1;
}

main().catch((err) => {
  console.error(`Fatal error: ${(err as Error).message}`);
  process.exitCode = 1;
});
