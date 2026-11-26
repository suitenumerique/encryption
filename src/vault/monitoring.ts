/**
 * The vault's error reporting: the shared reporter (`src/shared/error-reporting.ts`)
 * with text switched off, plus the policy of WHAT to report.
 *
 * The vault holds private keys and plaintext, so what leaves is a class name, a
 * stable code and stack positions, never a message. The server refuses a message
 * from the vault host as well, so the guarantee does not rest on this file alone.
 *
 * The policy is narrow, to add nothing the operator already sees elsewhere: CSP,
 * Trusted Types, COOP/COEP violations and crashes reach the same endpoint through
 * the browser's Reporting API without any vault code, and expected failures (a wrong
 * passphrase, missing keys) already travel to the product as stable codes. What is
 * left: an uncaught error in the vault window or its Service Worker, an unexpected
 * throw inside an operation, and the integrity failures that mean the server or a
 * directory record was tampered with.
 */
import { createErrorReporter } from '@encryption/src/shared/error-reporting';
import { VaultErrorCode, isVaultError } from '@encryption/src/shared/vault-error';

/**
 * Expected outcomes that are still worth an alert: each one means data the vault
 * pulled from the server or the directory failed a signature or hash check.
 */
const INTEGRITY_CODES: ReadonlySet<VaultErrorCode> = new Set([VaultErrorCode.VAULT_INTEGRITY_FAILED, VaultErrorCode.INVALID_KEY_BINDING]);

const reporter = createErrorReporter({ withText: false });

/**
 * Whether a failure caught inside an operation is worth reporting: anything that is
 * not a `VaultError` is an unexpected throw (a bug or a broken runtime), and a few
 * `VaultError` codes are integrity signals. Every other code is a normal outcome the
 * caller already receives.
 */
export function shouldReportVaultError(error: unknown): boolean {
  return !isVaultError(error) || INTEGRITY_CODES.has(error.code);
}

export const reportVaultError = reporter.report;
export const installVaultErrorReporting = reporter.install;
export const resetVaultErrorReporting = reporter.reset;
