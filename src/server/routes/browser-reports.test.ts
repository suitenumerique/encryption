import Fastify, { type FastifyInstance } from 'fastify';

import { browserReportsRoute, normalizeReports } from '@encryption/src/server/routes/browser-reports';

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

  it("reads the interface's own app-error report, which the Reporting API does not cover", () => {
    expect(
      normalizeReports({
        type: 'app-error',
        name: 'TypeError',
        message: 'x is not a function',
        stack: 'TypeError: x is not a function\n    at f (/assets/interface.js:1:1)',
        url: '/settings',
      })
    ).toEqual([
      {
        type: 'app-error',
        documentUri: '/settings',
        name: 'TypeError',
        message: 'x is not a function',
        stack: 'TypeError: x is not a function\n    at f (/assets/interface.js:1:1)',
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
  const warn = jest.fn();
  const info = jest.fn();

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

  it('accepts an app-error posted by the interface as JSON', async () => {
    const response = await report('application/json', JSON.stringify({ type: 'app-error', name: 'TypeError', message: 'boom' }));

    expect(response.statusCode).toBe(204);
    expect(warn).toHaveBeenCalledWith(expect.objectContaining({ type: 'app-error', name: 'TypeError' }), 'Browser security report');
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
