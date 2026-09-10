/**
 * @vitest-environment jsdom
 */
import fc from 'fast-check';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { buildBrowserErrorReport, createErrorReporter } from '@encryption/src/shared/error-reporting';
import {
  BrowserErrorReportSchema,
  REPORT_FUNCTION_PATTERN,
  REPORT_NAME_PATTERN,
  REPORT_PATH_PATTERN,
} from '@encryption/src/shared/schemas/browser-error-report';
import { VaultError, VaultErrorCode } from '@encryption/src/shared/vault-error';

const ORIGIN = window.location.origin;
const NO_TEXT = { withText: false } as const;

function withStack(error: Error, lines: string[]): Error {
  error.stack = [`${error.name}: ${error.message}`, ...lines].join('\n');

  return error;
}

describe('buildBrowserErrorReport', () => {
  it('keeps the class name, the code and same-origin positions', () => {
    const error = withStack(new VaultError(VaultErrorCode.VAULT_INTEGRITY_FAILED, 'manifest signature mismatch'), [
      `    at verifyPulledVault (${ORIGIN}/vault.js?v=abc:1:5000)`,
      `    at async Object.<anonymous> (${ORIGIN}/vault.js:1:100)`,
      `    at ${ORIGIN}/vault.js:2:7`,
    ]);

    expect(buildBrowserErrorReport(error, ORIGIN, NO_TEXT)).toEqual({
      type: 'browser-error',
      name: 'VaultError',
      code: 'VAULT_INTEGRITY_FAILED',
      frames: [
        { filename: '/vault.js', lineno: 1, colno: 5000, function: 'verifyPulledVault' },
        { filename: '/vault.js', lineno: 1, colno: 100, function: 'async Object.<anonymous>' },
        { filename: '/vault.js', lineno: 2, colno: 7 },
      ],
    });
  });

  it('adds the message and the page path only when text is allowed', () => {
    const error = new TypeError('x is not a function');

    expect(buildBrowserErrorReport(error, ORIGIN, { withText: true, path: '/settings' })).toMatchObject({
      name: 'TypeError',
      code: 'UNKNOWN',
      message: 'x is not a function',
      path: '/settings',
    });

    const silent = buildBrowserErrorReport(error, ORIGIN, { withText: false, path: '/settings' });
    expect(silent).not.toHaveProperty('message');
    expect(silent).not.toHaveProperty('path');
  });

  it('caps the message and drops a path that is not a plain pathname', () => {
    const report = buildBrowserErrorReport(new Error('m'.repeat(5000)), ORIGIN, { withText: true, path: '/auth/callback?code=secret' });

    expect(report.message).toHaveLength(1000);
    expect(report).not.toHaveProperty('path');
  });

  it('reads Firefox and Safari frames too', () => {
    const error = withStack(new Error('x'), [`decap@${ORIGIN}/vault.js:3:4`, `@${ORIGIN}/vault.js:5:6`]);

    expect(buildBrowserErrorReport(error, ORIGIN, NO_TEXT).frames).toEqual([
      { filename: '/vault.js', lineno: 3, colno: 4, function: 'decap' },
      { filename: '/vault.js', lineno: 5, colno: 6 },
    ]);
  });

  it('drops frames from any other origin or an extension, and keeps only a normalized same-origin path', () => {
    const error = withStack(new Error('x'), [
      `    at inject (chrome-extension://abcdef/content.js:1:1)`,
      `    at leak (https://product.example/app.js?token=abc:1:1)`,
      `    at up (${ORIGIN}/../etc/passwd:1:1)`,
      `    at ok (${ORIGIN}/sw.js:9:9)`,
    ]);

    // URL parsing resolves the traversal before the pattern sees it; what remains is
    // a plain path, which the server maps only if it names a bundle we built.
    expect(buildBrowserErrorReport(error, ORIGIN, NO_TEXT).frames).toEqual([
      { filename: '/etc/passwd', lineno: 1, colno: 1, function: 'up' },
      { filename: '/sw.js', lineno: 9, colno: 9, function: 'ok' },
    ]);
  });

  it('omits a function name that is not a plain identifier, and normalizes an odd class name', () => {
    const error = withStack(new Error('x'), [`    at eval (${ORIGIN}/vault.js:1:1)`, `    at {"k":"v"} (${ORIGIN}/vault.js:1:2)`]);
    error.name = 'Error with secret 123';

    const report = buildBrowserErrorReport(error, ORIGIN, NO_TEXT);

    expect(report.name).toBe('Error');
    expect(report.frames).toEqual([
      { filename: '/vault.js', lineno: 1, colno: 1, function: 'eval' },
      { filename: '/vault.js', lineno: 1, colno: 2 },
    ]);
  });

  it('classifies a throw that is not a VaultError, and copes with a non-Error throw', () => {
    expect(buildBrowserErrorReport(new Error('wrong secret key for the given ciphertext'), ORIGIN, NO_TEXT)).toEqual({
      type: 'browser-error',
      name: 'Error',
      code: 'WRONG_SECRET_KEY',
      frames: [],
    });
    expect(buildBrowserErrorReport('just a string', ORIGIN, NO_TEXT)).toEqual({ type: 'browser-error', name: 'Error', code: 'UNKNOWN', frames: [] });
    expect(buildBrowserErrorReport('just a string', ORIGIN, { withText: true }).message).toBe('just a string');
  });

  // The guarantee the vault relies on. Without text, a message or any stack line
  // that is not a frame never leaves, whatever it contains. The three fields that do
  // leave (class name, function identifier, path) can only carry text shaped like
  // one: anything else put there is normalized or dropped.
  it('without text, lets nothing through except identifier-shaped names and paths (property)', () => {
    const text = fc.string({ unit: 'grapheme', minLength: 12, maxLength: 60 });

    fc.assert(
      fc.property(text, fc.constantFrom('message', 'name', 'stack-line', 'frame-name', 'frame-url'), (s, where) => {
        const error = new Error(where === 'message' ? s : 'x');
        if (where === 'name') error.name = s;
        error.stack = [
          `${error.name}: ${error.message}`,
          where === 'stack-line' ? `    ${s}` : '',
          where === 'frame-name' ? `    at ${s} (${ORIGIN}/vault.js:1:1)` : `    at f (${ORIGIN}/vault.js:1:1)`,
          where === 'frame-url' ? `    at g (${ORIGIN}/${encodeURIComponent(s)}:1:1)` : '',
        ].join('\n');

        const report = buildBrowserErrorReport(error, ORIGIN, NO_TEXT);
        const leaked = JSON.stringify(report).includes(JSON.stringify(s).slice(1, -1));

        expect(BrowserErrorReportSchema.safeParse(report).success).toBe(true);
        expect(report).not.toHaveProperty('message');

        if (where === 'message' || where === 'stack-line') {
          expect(leaked).toBe(false);
        } else if (where === 'name') {
          expect(leaked).toBe(REPORT_NAME_PATTERN.test(s));
        } else if (leaked) {
          expect(where === 'frame-name' ? REPORT_FUNCTION_PATTERN.test(s) : REPORT_PATH_PATTERN.test(`/${s}`)).toBe(true);
        }
      })
    );
  });

  it('always produces a report the server schema accepts, for any stack text and either mode (property)', () => {
    fc.assert(
      fc.property(
        fc.string({ unit: 'grapheme', maxLength: 400 }),
        fc.string({ unit: 'grapheme', maxLength: 1200 }),
        fc.boolean(),
        (stack, message, withText) => {
          const error = new Error(message);
          error.stack = stack;

          expect(BrowserErrorReportSchema.safeParse(buildBrowserErrorReport(error, ORIGIN, { withText, path: '/x' })).success).toBe(true);
        }
      )
    );
  });
});

describe('createErrorReporter', () => {
  const fetchMock = vi.fn().mockResolvedValue(undefined);

  beforeEach(() => {
    fetchMock.mockClear();
    vi.stubGlobal('fetch', fetchMock);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  const bodyOf = (call: number) => JSON.parse((fetchMock.mock.calls[call][1] as RequestInit).body as string);

  it('posts to our own endpoint without credentials, with the page path when text is allowed', () => {
    createErrorReporter({ withText: true }).report(new TypeError('boom'));

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('/api/browser-reports');
    expect(init.credentials).toBe('omit');
    expect(init.keepalive).toBe(true);
    expect(bodyOf(0)).toEqual({
      type: 'browser-error',
      name: 'TypeError',
      code: 'UNKNOWN',
      frames: [],
      message: 'boom',
      path: window.location.pathname,
    });
  });

  it('sends each distinct failure once and at most five per context', () => {
    const reporter = createErrorReporter({ withText: false });

    for (let i = 0; i < 3; i++) reporter.report(new TypeError('same'));
    expect(fetchMock).toHaveBeenCalledTimes(1);

    for (let i = 0; i < 10; i++) {
      const error = new Error('x');
      error.stack = `Error: x\n    at f (${ORIGIN}/vault.js:${i}:1)`;
      reporter.report(error);
    }
    expect(fetchMock).toHaveBeenCalledTimes(5);
  });

  it('wires to uncaught errors and unhandled rejections of the given scope', () => {
    const listeners: Record<string, (event: unknown) => void> = {};
    const target = {
      addEventListener: (type: string, listener: unknown) => {
        listeners[type] = listener as (event: unknown) => void;
      },
    };
    createErrorReporter({ withText: false }).install(target as unknown as Parameters<ReturnType<typeof createErrorReporter>['install']>[0]);

    listeners.error({ error: new RangeError('a') });
    listeners.unhandledrejection({ reason: new VaultError(VaultErrorCode.SYNC_FAILED, 'b') });

    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(bodyOf(0).name).toBe('RangeError');
    expect(bodyOf(1).code).toBe('SYNC_FAILED');
  });
});
