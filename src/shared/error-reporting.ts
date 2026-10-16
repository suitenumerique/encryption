/**
 * Reports an uncaught JavaScript failure to our OWN backend, from the interface and
 * from the vault, with one difference between the two: whether free text is allowed.
 *
 * Why our own backend and not a collector: the browser never talks to a third-party
 * domain, so the CSP keeps `connect-src 'self'`, an extension blocking analytics
 * cannot suppress a security report, and redaction happens server-side.
 *
 * What always leaves, for both surfaces, is the shape in
 * `src/shared/schemas/browser-error-report.ts`: the error class NAME (letters only),
 * the stable CODE (a `VaultError` code, or the classifier's answer for any other
 * throw), and stack POSITIONS parsed here from the frame lines only, as a same-origin
 * path with its query dropped, a line, a column and the identifier the engine
 * printed. Frames from any other origin (an extension, a product page) are dropped.
 *
 * `error.stack` itself is never sent: its first line is the message. The interface
 * adds the message and the page path explicitly (`withText: true`); the vault, whose
 * variables are private keys and plaintext, does not, and the server refuses those
 * two fields from the vault host anyway.
 */
import { BROWSER_REPORT_PATH } from '@encryption/src/shared/constants';
import {
  type BrowserErrorReport,
  REPORT_FUNCTION_PATTERN,
  REPORT_MAX_FRAMES,
  REPORT_MAX_MESSAGE_LENGTH,
  REPORT_NAME_PATTERN,
  REPORT_PATH_PATTERN,
  type ReportFrame,
} from '@encryption/src/shared/schemas/browser-error-report';
import { classifyVaultError } from '@encryption/src/shared/vault-error';

/** A broken page can fail on every render; one page load reports a few times. */
const MAX_REPORTS_PER_CONTEXT = 5;

// V8 prints `    at fn (url:line:col)` or `    at url:line:col`; Firefox and Safari
// print `fn@url:line:col`. The message line at the top matches neither.
const FRAME_PATTERN = /^\s*(?:at\s+)?(?:(.*?)\s*[@(])?\s*((?:[a-z][a-z0-9+.-]*):[^\s()]+?):(\d+):(\d+)\)?\s*$/i;

export interface ReporterOptions {
  /** Include the message and the page path. Only the interface may say yes. */
  withText: boolean;
}

function frameFromLine(line: string, origin: string): ReportFrame | null {
  const match = FRAME_PATTERN.exec(line);

  if (!match) return null;

  const [, fn, location, lineno, colno] = match;
  let url: URL;

  try {
    url = new URL(location);
  } catch {
    return null;
  }

  // Only our own scripts: a path is meaningful for symbolication only if we built
  // the file, and a foreign URL could carry anything in its path.
  if (url.origin !== origin || !REPORT_PATH_PATTERN.test(url.pathname)) return null;

  const frame: ReportFrame = { filename: url.pathname, lineno: Number(lineno), colno: Number(colno) };
  const name = fn?.trim();

  if (name && REPORT_FUNCTION_PATTERN.test(name)) frame.function = name;

  return frame;
}

/**
 * Pure: turns any thrown value into the report shape, dropping everything the
 * schema has no field for. `origin` is the page's own origin; frames elsewhere are
 * discarded. `path` is the page path to attach when text is allowed.
 */
export function buildBrowserErrorReport(error: unknown, origin: string, options: ReporterOptions & { path?: string }): BrowserErrorReport {
  const name = error instanceof Error && REPORT_NAME_PATTERN.test(error.name) ? error.name : 'Error';
  const stack = error instanceof Error && typeof error.stack === 'string' ? error.stack : '';
  const frames: ReportFrame[] = [];

  for (const line of stack.split('\n')) {
    const frame = frameFromLine(line, origin);

    if (frame) frames.push(frame);
    if (frames.length === REPORT_MAX_FRAMES) break;
  }

  const report: BrowserErrorReport = { type: 'browser-error', name, code: classifyVaultError(error), frames };

  if (options.withText) {
    report.message = (error instanceof Error ? error.message : String(error)).slice(0, REPORT_MAX_MESSAGE_LENGTH);
    if (options.path !== undefined && REPORT_PATH_PATTERN.test(options.path)) report.path = options.path;
  }

  return report;
}

export interface ErrorReporter {
  report(error: unknown): void;
  /** Uncaught errors and unhandled rejections of a window or a Service Worker. */
  install(target: {
    addEventListener(type: 'error', listener: (event: ErrorEvent) => void): void;
    addEventListener(type: 'unhandledrejection', listener: (event: PromiseRejectionEvent) => void): void;
  }): void;
  /** Test seam. */
  reset(): void;
}

export function createErrorReporter(options: ReporterOptions): ErrorReporter {
  let sent = 0;
  const alreadySent = new Set<string>();

  function report(error: unknown): void {
    const built = buildBrowserErrorReport(error, globalThis.location.origin, { ...options, path: globalThis.location.pathname });
    const first = built.frames[0];
    const key = `${built.name}:${built.code}:${first?.filename ?? ''}:${first?.lineno ?? ''}:${first?.colno ?? ''}`;

    if (sent >= MAX_REPORTS_PER_CONTEXT || alreadySent.has(key)) return;

    alreadySent.add(key);
    sent += 1;

    try {
      void fetch(BROWSER_REPORT_PATH, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        // No cookies, no Authorization: the endpoint is unauthenticated on purpose.
        credentials: 'omit',
        // Survives the navigation or unload that an error often triggers.
        keepalive: true,
        body: JSON.stringify(built),
      }).catch(() => {
        // Reporting a failure must never become a failure of its own.
      });
    } catch {
      // Same: a runtime without fetch, or a fetch that throws synchronously.
    }
  }

  return {
    report,
    install(target) {
      target.addEventListener('error', (event) => report(event.error));
      target.addEventListener('unhandledrejection', (event) => report(event.reason));
    },
    reset() {
      sent = 0;
      alreadySent.clear();
    },
  };
}
