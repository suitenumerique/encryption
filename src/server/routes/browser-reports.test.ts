import Fastify, { type FastifyInstance } from 'fastify';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { captureBrowserError } from '@encryption/src/server/monitoring';
import { browserReportsRoute, normalizeReports } from '@encryption/src/server/routes/browser-reports';

vi.mock('@encryption/src/server/monitoring', () => ({
  captureBrowserError: vi.fn(),
  captureServerMessage: vi.fn(),
}));

vi.mock('@encryption/src/server/env', () => ({
  env: { VAULT_HOST: 'data.encryption.example', UI_HOST: 'encryption.example' },
}));

const VAULT_REPORT = {
  type: 'browser-error',
  name: 'VaultError',
  code: 'VAULT_INTEGRITY_FAILED',
  frames: [{ filename: '/vault.js', lineno: 1, colno: 5000, function: 'verifyPulledVault' }],
};

const INTERFACE_REPORT = {
  type: 'browser-error',
  name: 'TypeError',
  code: 'UNKNOWN',
  message: 'x is not a function',
  path: '/settings',
  frames: [{ filename: '/assets/interface-abc.js', lineno: 1, colno: 1 }],
};

describe('normalizeReports', () => {
  it('reads the legacy report-uri format', () => {
    expect(
      normalizeReports({
        'csp-report': {
          'document-uri': 'https://data.encryption.example/bridge.html',
          'effective-directive': 'connect-src',
          'blocked-uri': 'https://attacker.example/beacon',
        },
      })
    ).toEqual([
      {
        type: 'csp-violation',
        documentUri: 'https://data.encryption.example/bridge.html',
        directive: 'connect-src',
        blockedUri: 'https://attacker.example/beacon',
        sample: undefined,
      },
    ]);
  });

  it('falls back to violated-directive when the browser omits the effective one', () => {
    expect(normalizeReports({ 'csp-report': { 'violated-directive': "script-src 'self'" } })[0].directive).toBe("script-src 'self'");
  });

  it('reads the Reporting API format used by report-to', () => {
    expect(
      normalizeReports([
        {
          type: 'csp-violation',
          url: 'https://data.encryption.example/bridge.html',
          body: { effectiveDirective: 'script-src', blockedURL: 'https://cdn.attacker.example/x.js', sample: 'eval(...)' },
        },
      ])
    ).toEqual([
      {
        type: 'csp-violation',
        documentUri: 'https://data.encryption.example/bridge.html',
        directive: 'script-src',
        blockedUri: 'https://cdn.attacker.example/x.js',
        sample: 'eval(...)',
      },
    ]);
  });

  it('keeps report types other than CSP, without the CSP-only fields', () => {
    expect(normalizeReports([{ type: 'deprecation', url: 'https://encryption.example/settings', body: {} }])).toEqual([
      { type: 'deprecation', documentUri: 'https://encryption.example/settings' },
    ]);
  });

  it("reads the interface's own browser-error report, which the Reporting API does not cover", () => {
    expect(normalizeReports(INTERFACE_REPORT)).toEqual([
      {
        type: 'browser-error',
        documentUri: '/settings',
        name: 'TypeError',
        code: 'UNKNOWN',
        message: 'x is not a function',
        frames: INTERFACE_REPORT.frames,
      },
    ]);
  });

  it('reads a COOP report, which is what tells us the vault isolation is being broken', () => {
    expect(normalizeReports([{ type: 'coop', url: 'https://data.encryption.example/bridge.html', body: {} }])[0].type).toBe('coop');
  });

  it('returns nothing for a body it does not recognize, rather than throwing', () => {
    // The endpoint is publicly reachable, so a malformed body must never become a 500.
    for (const body of [null, 'nonsense', 42, {}, { unrelated: true }]) {
      expect(normalizeReports(body)).toEqual([]);
    }
  });
});

describe('browserReportsRoute', () => {
  let app: FastifyInstance;
  const warn = vi.fn();
  const info = vi.fn();

  beforeEach(async () => {
    warn.mockClear();
    info.mockClear();
    app = Fastify();
    app.addHook('onRequest', async (request) => {
      request.log.warn = warn;
      request.log.info = info;
    });
    await app.register(browserReportsRoute);
    await app.ready();
  });

  afterEach(async () => {
    await app.close();
  });

  async function report(contentType: string, payload: string) {
    return app.inject({ method: 'POST', url: '/api/browser-reports', headers: { 'content-type': contentType }, payload });
  }

  it('accepts the legacy content type and logs the violation', async () => {
    const response = await report('application/csp-report', JSON.stringify({ 'csp-report': { 'blocked-uri': 'https://evil.example' } }));

    expect(response.statusCode).toBe(204);
    expect(warn).toHaveBeenCalledWith(expect.objectContaining({ blockedUri: 'https://evil.example' }), 'Browser security report');
  });

  it('accepts the Reporting API content type', async () => {
    const response = await report(
      'application/reports+json',
      JSON.stringify([{ type: 'csp-violation', body: { blockedURL: 'https://evil.example' } }])
    );

    expect(response.statusCode).toBe(204);
    expect(warn).toHaveBeenCalledTimes(1);
  });

  it('accepts a browser-error posted by the interface as JSON, and keeps its message out of the log', async () => {
    const response = await report('application/json', JSON.stringify(INTERFACE_REPORT));

    expect(response.statusCode).toBe(204);
    expect(warn).toHaveBeenCalledWith(expect.objectContaining({ type: 'browser-error', name: 'TypeError' }), 'Browser security report');
    expect(warn).toHaveBeenCalledWith(expect.not.objectContaining({ message: expect.anything() }), 'Browser security report');
  });

  it('logs a deprecation report at info, so only security reports can raise an alert', async () => {
    const response = await report('application/reports+json', JSON.stringify([{ type: 'deprecation', body: {} }]));

    expect(response.statusCode).toBe(204);
    expect(warn).not.toHaveBeenCalled();
    expect(info).toHaveBeenCalledWith(expect.objectContaining({ type: 'deprecation' }), 'Browser report');
  });

  it('answers 204 without logging when the body cannot be parsed', async () => {
    const response = await report('application/csp-report', '{ not json');

    expect(response.statusCode).toBe(204);
    expect(warn).not.toHaveBeenCalled();
  });

  it('rejects a body large enough to be an abuse vector', async () => {
    const response = await report('application/csp-report', JSON.stringify({ 'csp-report': { 'script-sample': 'x'.repeat(32 * 1024) } }));

    expect(response.statusCode).toBe(413);
  });

  it('requires no authentication, because the browser sends the report without credentials', async () => {
    expect((await report('application/csp-report', JSON.stringify({ 'csp-report': {} }))).statusCode).toBe(204);
  });
});

describe('browser-error reports from the vault', () => {
  it('reads a report with no text', () => {
    expect(normalizeReports(VAULT_REPORT)).toEqual([
      {
        type: 'browser-error',
        documentUri: undefined,
        name: 'VaultError',
        code: 'VAULT_INTEGRITY_FAILED',
        message: undefined,
        frames: VAULT_REPORT.frames,
      },
    ]);
  });

  // The strictness IS the privacy guarantee: inventing a field discards the report.
  it('drops the whole report when it carries any field the schema does not name', () => {
    expect(normalizeReports({ ...VAULT_REPORT, stack: 'Error: the passphrase was correct horse battery' })).toEqual([]);
    expect(normalizeReports({ ...VAULT_REPORT, frames: [{ ...VAULT_REPORT.frames[0], context: 'x' }] })).toEqual([]);
  });

  it('drops a report whose fields could carry text: an unknown code, a foreign path, an odd name', () => {
    expect(normalizeReports({ ...VAULT_REPORT, code: 'NOT_A_CODE' })).toEqual([]);
    expect(normalizeReports({ ...VAULT_REPORT, name: 'Error: secret' })).toEqual([]);
    expect(normalizeReports({ ...VAULT_REPORT, frames: [{ filename: 'https://x.example/a.js', lineno: 1, colno: 1 }] })).toEqual([]);
    expect(normalizeReports({ ...VAULT_REPORT, frames: [{ filename: '/../vault.js', lineno: 1, colno: 1 }] })).toEqual([]);
    expect(normalizeReports({ ...VAULT_REPORT, frames: [{ filename: '/vault.js', lineno: 1, colno: 1, function: 'a b (c)' }] })).toEqual([]);
  });

  async function post(host: string, payload: unknown) {
    const app = Fastify();
    const warn = vi.fn();
    app.addHook('onRequest', async (request) => {
      request.log.warn = warn;
    });
    await app.register(browserReportsRoute);
    await app.ready();

    const response = await app.inject({
      method: 'POST',
      url: '/api/browser-reports',
      headers: { 'content-type': 'application/json', host },
      payload: JSON.stringify(payload),
    });
    await app.close();

    return { response, warn };
  }

  it('is forwarded as an alert with its code as the only text', async () => {
    vi.mocked(captureBrowserError).mockClear();
    const { response, warn } = await post('data.encryption.example', VAULT_REPORT);

    expect(response.statusCode).toBe(204);
    expect(warn).toHaveBeenCalledWith(expect.objectContaining({ type: 'browser-error', code: 'VAULT_INTEGRITY_FAILED' }), 'Browser security report');
    expect(captureBrowserError).toHaveBeenCalledWith(
      { name: 'VaultError', code: 'VAULT_INTEGRITY_FAILED', message: undefined, frames: VAULT_REPORT.frames },
      { tags: { reportType: 'browser-error', host: 'data.encryption.example', code: 'VAULT_INTEGRITY_FAILED' } }
    );
  });

  // Enforced here, where the vault's own code cannot reach: whatever a vault ever
  // sends, text from its host goes nowhere.
  it('drops a report from the vault host that carries a message or a path, and forwards nothing', async () => {
    vi.mocked(captureBrowserError).mockClear();

    for (const payload of [
      { ...VAULT_REPORT, message: 'x' },
      { ...VAULT_REPORT, path: '/bridge.html' },
    ]) {
      const { response, warn } = await post('data.encryption.example', payload);

      expect(response.statusCode).toBe(204);
      expect(warn).toHaveBeenCalledWith(expect.not.objectContaining({ message: expect.anything() }), 'Vault report carried text and was dropped');
    }
    expect(captureBrowserError).not.toHaveBeenCalled();

    // The same body from the interface host is fine.
    await post('encryption.example', { ...VAULT_REPORT, message: 'x' });
    expect(captureBrowserError).toHaveBeenCalledTimes(1);
  });
});
