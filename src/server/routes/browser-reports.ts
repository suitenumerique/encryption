/**
 * Receives every report the browser's Reporting API produces for our origins.
 *
 * The Reporting API is generic: one endpoint, and the report's `type` says what it
 * is. CSP violations, COOP and COEP isolation reports, Integrity-Policy violations,
 * crashes, deprecations and interventions all arrive here. The endpoint is declared
 * under the reserved name `default`, which is the only way to receive the types that
 * have no header of their own to name an endpoint with (crash, deprecation,
 * intervention). A CSP-specific endpoint would silently drop those.
 *
 * The security-relevant types are alerted on, the rest are informational:
 *
 * - `csp-violation` on the vault is close to proof of a compromised bundle. That
 *   policy is `default-src 'none'; script-src 'self'; connect-src 'self'`, so the
 *   vault has NO legitimate reason to attempt an external load; a violation there
 *   means something is trying to fetch a payload or beacon out.
 * - `coop` and `coep` mean an isolation guarantee the vault relies on is being
 *   violated, which is either a misconfiguration or an embedding attempt.
 * - `crash` means the renderer died, which for a process holding private keys is
 *   worth knowing even though it is usually an out-of-memory.
 * - `deprecation` and `intervention` are engineering signals, never alerts.
 *
 * One more type, `browser-error`, is posted by our own code in the interface and
 * in the vault, for a JavaScript exception the Reporting API does not cover. It goes
 * through this same endpoint rather than to a collector directly, which is
 * deliberate: the browser never talks to a third-party domain, so the CSP needs no
 * exception, an extension blocking analytics cannot suppress a security report, and
 * every string is redacted server-side before it leaves. The shape is a strict
 * schema (`src/shared/schemas/browser-error-report.ts`): a class name, a stable code
 * and stack positions, plus a message and a page path that only the interface may
 * send. A report from the VAULT host carrying either is dropped here, whatever the
 * vault's own code did: its variables are private keys and plaintext.
 *
 * When a collector is configured, the security-relevant types are forwarded to it
 * from here. Nothing is forwarded when it is not, and the log line is emitted
 * either way.
 *
 * The endpoint is unauthenticated because the browser sends reports without
 * credentials, and it is deliberately kept out of the OpenAPI document: it is
 * infrastructure, not part of the API the interface consumes.
 */
import type { FastifyInstance } from 'fastify';
import { z } from 'zod';

import { env } from '@encryption/src/server/env';
import { captureBrowserError, captureServerMessage } from '@encryption/src/server/monitoring';
import { BROWSER_REPORT_PATH } from '@encryption/src/shared/constants';
import { BrowserErrorReportSchema, type ReportFrame } from '@encryption/src/shared/schemas/browser-error-report';

/** Anyone can POST here, so nothing is stored and the body is size-capped. */
const MAX_REPORT_BYTES = 16 * 1024;

/** Report types that mean something is wrong with the security of the page. */
const ALERTING_TYPES = new Set(['csp-violation', 'coop', 'coep', 'integrity-violation', 'crash', 'browser-error']);

/**
 * Two wire formats reach this endpoint, and both are accepted because browser
 * support is split: the legacy `report-uri` format (a single object under
 * `csp-report`, CSP only) and the Reporting API format used by `report-to` (an
 * array carrying a `type`).
 */
const legacyReportSchema = z.object({
  'csp-report': z
    .object({
      'document-uri': z.string().optional(),
      'violated-directive': z.string().optional(),
      'effective-directive': z.string().optional(),
      'blocked-uri': z.string().optional(),
      'script-sample': z.string().optional(),
    })
    .loose(),
});

const reportingApiSchema = z.array(
  z
    .object({
      type: z.string().optional(),
      url: z.string().optional(),
      body: z.looseObject({}).optional(),
    })
    .loose()
);

export interface NormalizedReport {
  type: string;
  documentUri?: string;
  directive?: string;
  blockedUri?: string;
  sample?: string;
  name?: string;
  code?: string;
  message?: string;
  frames?: ReportFrame[];
}

function fromCspBody(body: Record<string, unknown>): Pick<NormalizedReport, 'directive' | 'blockedUri' | 'sample'> {
  return {
    directive: typeof body.effectiveDirective === 'string' ? body.effectiveDirective : undefined,
    blockedUri: typeof body.blockedURL === 'string' ? body.blockedURL : undefined,
    sample: typeof body.sample === 'string' ? body.sample : undefined,
  };
}

/**
 * Reduces both wire formats to a type plus the fields worth alerting on. Returns an
 * empty list for anything unrecognized rather than throwing: this endpoint is
 * publicly reachable, and a malformed body must not become a 500.
 */
export function normalizeReports(body: unknown): NormalizedReport[] {
  const browserError = BrowserErrorReportSchema.safeParse(body);

  if (browserError.success) {
    const { name, code, frames, message, path } = browserError.data;

    return [{ type: 'browser-error', documentUri: path, name, code, message, frames }];
  }

  const legacy = legacyReportSchema.safeParse(body);

  if (legacy.success) {
    const report = legacy.data['csp-report'];

    return [
      {
        type: 'csp-violation',
        documentUri: report['document-uri'],
        directive: report['effective-directive'] ?? report['violated-directive'],
        blockedUri: report['blocked-uri'],
        sample: report['script-sample'],
      },
    ];
  }

  const modern = reportingApiSchema.safeParse(body);

  if (modern.success) {
    return modern.data.map((entry) => {
      const type = entry.type ?? 'csp-violation';
      const reportBody = (entry.body ?? {}) as Record<string, unknown>;

      return {
        type,
        documentUri: typeof reportBody.documentURL === 'string' ? reportBody.documentURL : entry.url,
        ...(type === 'csp-violation' ? fromCspBody(reportBody) : {}),
      };
    });
  }

  return [];
}

export async function browserReportsRoute(app: FastifyInstance): Promise<void> {
  // Browsers send these under content types Fastify does not parse by default.
  // Encapsulated to this plugin, so no other route starts accepting them.
  for (const contentType of ['application/csp-report', 'application/reports+json']) {
    app.addContentTypeParser(contentType, { parseAs: 'string', bodyLimit: MAX_REPORT_BYTES }, (_request, payload, done) => {
      try {
        done(null, JSON.parse(payload as string));
      } catch {
        // A body we cannot parse is still a signal that something reported; answer
        // 204 rather than 400 so a browser quirk does not turn into error noise.
        done(null, null);
      }
    });
  }

  app.post(BROWSER_REPORT_PATH, { schema: { hide: true }, bodyLimit: MAX_REPORT_BYTES }, async (request, reply) => {
    for (const report of normalizeReports(request.body)) {
      // The log line never carries the interface's free text either: the collector
      // gets it redacted, the log gets the code and the positions.
      const { message: _message, ...loggable } = report;
      const line = { host: request.host, ...loggable };

      if (ALERTING_TYPES.has(report.type)) {
        request.log.warn(line, 'Browser security report');

        if (report.type === 'browser-error') {
          // The vault's guarantee, enforced where the vault's code cannot reach: a
          // report from its host may carry positions and codes, never text.
          if (request.host === env.VAULT_HOST && (report.message !== undefined || report.documentUri !== undefined)) {
            request.log.warn({ host: request.host, name: report.name, code: report.code }, 'Vault report carried text and was dropped');

            continue;
          }

          captureBrowserError(
            { name: report.name ?? 'Error', code: report.code ?? 'UNKNOWN', message: report.message, frames: report.frames ?? [] },
            { tags: { reportType: report.type, host: request.host, code: report.code } }
          );

          continue;
        }

        // Only the tags below leave this process. The report's own strings go into
        // the message, where `redact()` scrubs them; the raw body never does.
        captureServerMessage(`Browser report: ${report.type} ${report.directive ?? report.name ?? ''} ${report.blockedUri ?? report.message ?? ''}`, {
          level: 'warning',
          tags: { reportType: report.type, host: request.host },
        });
      } else {
        request.log.info(line, 'Browser report');
      }
    }

    // Nothing to say back to the browser, and nothing is stored.
    return reply.code(204).send();
  });
}
