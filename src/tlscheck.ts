/**
 * Real TLS certificate inspection: performs an actual TLS handshake against
 * host:port and reads the certificate the server presents (issuer, subject,
 * validity window, fingerprint). Read-only — we never send anything beyond
 * the TLS ClientHello needed to complete the handshake, and we don't
 * validate the certificate chain (self-signed/internal certs are expected
 * on private targets); we just report what's actually there.
 */
import net from "node:net";
import tls from "node:tls";
import { TlsResult } from "./types.js";

export const DEFAULT_TLS_TIMEOUT_MS = 4000;

export interface TlsCheckOptions {
  timeoutMs?: number;
  /** Passed through to tls.connect; SNI servername. Defaults to `host`. */
  servername?: string;
}

function formatName(name: Record<string, string> | undefined): string | undefined {
  if (!name) return undefined;
  const parts = Object.entries(name).map(([k, v]) => `${k}=${v}`);
  return parts.length > 0 ? parts.join(", ") : undefined;
}

/**
 * Connects to host:port over TLS and reports the presented certificate.
 * Never throws: connection failures and handshake errors are reported as
 * `{ reachable: false, error }` so a scan can proceed and simply record
 * "TLS not reachable" as a finding.
 */
export function checkTlsCertificate(
  host: string,
  port: number,
  options: TlsCheckOptions = {}
): Promise<TlsResult> {
  const timeoutMs = options.timeoutMs ?? DEFAULT_TLS_TIMEOUT_MS;

  return new Promise((resolve) => {
    let settled = false;
    const finish = (result: TlsResult) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(result);
    };

    // SNI (the `servername` option) is only meaningful for hostnames, and
    // Node warns/ignores it for literal IP addresses (RFC 6066) — so only
    // set it when the target isn't a literal IP.
    const servername = options.servername ?? (net.isIP(host) ? undefined : host);

    const socket = tls.connect(
      {
        host,
        port,
        servername,
        rejectUnauthorized: false, // we're reporting, not validating trust
        timeout: timeoutMs,
      },
      () => {
        const cert = socket.getPeerCertificate(false);
        if (!cert || Object.keys(cert).length === 0) {
          finish({ host, port, reachable: true, error: "no certificate presented" });
          return;
        }
        finish({
          host,
          port,
          reachable: true,
          issuer: formatName(cert.issuer as unknown as Record<string, string>),
          subject: formatName(cert.subject as unknown as Record<string, string>),
          validFrom: cert.valid_from ? new Date(cert.valid_from).toISOString() : undefined,
          validTo: cert.valid_to ? new Date(cert.valid_to).toISOString() : undefined,
          fingerprint256: cert.fingerprint256,
        });
      }
    );

    socket.once("timeout", () => finish({ host, port, reachable: false, error: `timed out after ${timeoutMs}ms` }));
    socket.once("error", (err) => finish({ host, port, reachable: false, error: err.message }));
  });
}
