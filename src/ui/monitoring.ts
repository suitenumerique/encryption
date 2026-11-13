/**
 * The interface's error reporting: the shared reporter (`src/shared/error-reporting.ts`)
 * with text switched on. The interface variables are not key material, so the
 * message and the page path travel too; the backend redacts every string before it
 * can reach a collector, and only `location.pathname` is sent, never the query
 * string, which on `/auth/callback` carries an authorization code.
 */
import { createErrorReporter } from '@encryption/src/shared/error-reporting';

const reporter = createErrorReporter({ withText: true });

export function installErrorReporting(): void {
  reporter.install(window);
}
