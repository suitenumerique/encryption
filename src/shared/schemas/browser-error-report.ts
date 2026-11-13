/**
 * The ONLY shape a JavaScript failure report from the interface or the vault may
 * take. The browser side builds it (`src/shared/error-reporting.ts`) and the server
 * validates it with this exact schema, which is `strict`: a body carrying any other
 * field is not a report and is dropped whole.
 *
 * What travels is an error class name, a stable error code, and stack POSITIONS (a
 * same-origin path, a line, a column, an identifier), all constrained character by
 * character so they cannot hold key material or plaintext. Two more fields exist for
 * the interface only, a message and the page path; the server refuses them from the
 * vault host, so the vault's guarantee does not depend on the vault's own code.
 */
import { z } from 'zod';

import { VaultErrorCode } from '@encryption/src/shared/vault-error';
import '@encryption/src/shared/zod-jitless';

/** An error class name: letters only, as `Error.prototype.name` values are. */
export const REPORT_NAME_PATTERN = /^[A-Za-z]{1,40}$/;
/** A function name as engines print it: identifiers, dots, `<anonymous>`, `async`. */
export const REPORT_FUNCTION_PATTERN = /^[\w$.<>[\] ]{1,80}$/;
/** A same-origin path, query and hash already stripped, no traversal. */
export const REPORT_PATH_PATTERN = /^\/(?!.*\.\.)[\w./@-]{0,200}$/;

export const REPORT_MAX_FRAMES = 30;
export const REPORT_MAX_MESSAGE_LENGTH = 1000;

export const ReportFrameSchema = z.strictObject({
  filename: z.string().regex(REPORT_PATH_PATTERN),
  lineno: z.number().int().min(0).max(1_000_000_000),
  colno: z.number().int().min(0).max(1_000_000_000),
  function: z.string().regex(REPORT_FUNCTION_PATTERN).optional(),
});

export const BrowserErrorReportSchema = z.strictObject({
  type: z.literal('browser-error'),
  name: z.string().regex(REPORT_NAME_PATTERN),
  code: z.enum(Object.values(VaultErrorCode) as [VaultErrorCode, ...VaultErrorCode[]]),
  frames: z.array(ReportFrameSchema).max(REPORT_MAX_FRAMES),
  /** Interface only. The vault never sets it, and the server refuses it from the vault host. */
  message: z.string().max(REPORT_MAX_MESSAGE_LENGTH).optional(),
  /** Interface only: `location.pathname`, never the query string. */
  path: z.string().regex(REPORT_PATH_PATTERN).optional(),
});

export type ReportFrame = z.infer<typeof ReportFrameSchema>;
export type BrowserErrorReport = z.infer<typeof BrowserErrorReportSchema>;
