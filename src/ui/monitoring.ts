/**
 * Reports uncaught interface errors to our OWN backend, never to a third party.
 *
 * The Reporting API covers CSP, COOP/COEP, crashes and deprecations, but not a
 * plain JavaScript exception, which is the failure a user actually notices. This
 * fills that gap without an SDK and without a second origin:
 *
 * - no third-party domain, so the CSP keeps `connect-src 'self'` and an extension
 *   blocking analytics cannot suppress a report;
 * - no breadcrumbs, no DOM capture, no session replay, no user identity;
 * - the path only, never `location.search` or `location.hash`: the OIDC callback
 *   carries an authorization code there;
 * - the backend redacts every string before it can reach a collector.
 *
 * The VAULT deliberately has no equivalent. Its variables are private keys and
 * plaintext, so nothing there is safe to serialize, and its failures already reach
 * the interface as stable error codes.
 */
import { BROWSER_REPORT_PATH } from '@encryption/src/shared/constants';

/** A broken render can throw on every frame; a page load reports a few times. */
const MAX_REPORTS_PER_PAGE = 5;

const MAX_MESSAGE_LENGTH = 1000;
const MAX_STACK_LENGTH = 4000;

let sent = 0;
const alreadySent = new Set<string>();

function report(name: string, message: string, stack: string | undefined): void {
  const key = `${name}:${message}`;

  if (sent >= MAX_REPORTS_PER_PAGE || alreadySent.has(key)) return;

  alreadySent.add(key);
  sent += 1;

  void fetch(BROWSER_REPORT_PATH, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    // No cookies, no Authorization: this endpoint is unauthenticated on purpose.
    credentials: 'omit',
    // Lets the report survive the navigation that an error often triggers.
    keepalive: true,
    body: JSON.stringify({
      type: 'app-error',
      name: name.slice(0, 200),
      message: message.slice(0, MAX_MESSAGE_LENGTH),
      stack: stack?.slice(0, MAX_STACK_LENGTH),
      url: window.location.pathname,
    }),
  }).catch(() => {
    // Reporting a failure must never become a failure of its own.
  });
}

export function installErrorReporting(): void {
  window.addEventListener('error', (event) => {
    const error = event.error;

    if (error instanceof Error) {
      report(error.name, error.message, error.stack);

      return;
    }

    report('Error', String(event.message ?? 'unknown'), undefined);
  });

  window.addEventListener('unhandledrejection', (event) => {
    const reason = event.reason;

    if (reason instanceof Error) {
      report(reason.name, reason.message, reason.stack);

      return;
    }

    report('UnhandledRejection', String(reason), undefined);
  });
}
