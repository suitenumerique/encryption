import {
  buildEnvelope,
  buildEvent,
  captureServerError,
  flushMonitoring,
  initMonitoring,
  isMonitoringEnabled,
  parseBrowserStack,
  parseDsn,
  parseStack,
  redact,
  resetMonitoring,
} from '@encryption/src/server/monitoring';

describe('parseDsn', () => {
  it('builds the envelope endpoint from a standard DSN', () => {
    expect(parseDsn('https://abc123@o1.ingest.sentry.io/456')).toEqual({
      url: 'https://o1.ingest.sentry.io/api/456/envelope/',
      publicKey: 'abc123',
    });
  });

  it('keeps a path prefix, which is how a self-hosted collector is usually mounted', () => {
    expect(parseDsn('https://key@glitchtip.example/reporting/9')?.url).toBe('https://glitchtip.example/reporting/api/9/envelope/');
  });

  it('returns null rather than throwing on anything unusable, so a typo disables reporting', () => {
    for (const dsn of ['', 'not-a-url', 'https://sentry.example/456', 'ftp://key@sentry.example/456', 'https://key@sentry.example']) {
      expect(parseDsn(dsn)).toBeNull();
    }
  });
});

describe('redact', () => {
  it('removes an email address', () => {
    expect(redact('failed for user.name+tag@example.gouv.fr')).toBe('failed for [email]');
  });

  it('removes anything that looks like key material', () => {
    // A base64url blob, which is what a wrapped key or a backup payload looks like.
    const blob = 'dGhpcyBpcyBub3QgYSByZWFsIGtleSBidXQgaXQgaXMgbG9uZyBlbm91Z2g';

    expect(redact(`cannot open item ${blob}`)).toBe('cannot open item [redacted]');
  });

  it('removes every segment of a JWT', () => {
    const jwt = `${'a'.repeat(40)}.${'b'.repeat(40)}.${'c'.repeat(40)}`;

    expect(redact(jwt)).toBe('[redacted].[redacted].[redacted]');
  });

  it('leaves ordinary prose and short identifiers alone', () => {
    expect(redact('Prisma query failed on table identities (code P2002)')).toBe('Prisma query failed on table identities (code P2002)');
  });

  it('truncates rather than sending an unbounded string', () => {
    // Ordinary prose, so the truncation is what is being measured, not the scrubber.
    expect(redact('failed '.repeat(200), 100)).toHaveLength(101);
  });
});

describe('parseStack', () => {
  it('reads frames oldest first, which is the order the event format expects', () => {
    const frames = parseStack(
      ['Error: boom', '    at inner (/app/dist/server/main.mjs:10:5)', '    at outer (/app/node_modules/fastify/lib/x.js:20:7)'].join('\n')
    );

    expect(frames.map((frame) => frame.function)).toEqual(['outer', 'inner']);
    expect(frames.map((frame) => frame.in_app)).toEqual([false, true]);
    expect(frames[1]).toMatchObject({ filename: '/app/dist/server/main.mjs', lineno: 10, colno: 5 });
  });

  it('returns nothing for a missing stack', () => {
    expect(parseStack(undefined)).toEqual([]);
  });
});

describe('parseBrowserStack', () => {
  it('reads the Chrome format, keeping the full asset URL a source map is matched on', () => {
    const frames = parseBrowserStack(
      [
        'TypeError: x is not a function',
        '    at o (https://interface.encryption.example/assets/index-BOeWTOD4.js:12:345)',
        '    at https://interface.encryption.example/assets/vendor-abc.js:1:20',
      ].join('\n')
    );

    expect(frames).toHaveLength(2);
    expect(frames[1]).toMatchObject({
      function: 'o',
      filename: 'https://interface.encryption.example/assets/index-BOeWTOD4.js',
      lineno: 12,
      colno: 345,
      in_app: true,
    });
  });

  it('reads the Firefox and Safari format, which has no "at"', () => {
    const frames = parseBrowserStack('handleClick@https://interface.encryption.example/assets/index.js:5:9');

    expect(frames[0]).toMatchObject({ function: 'handleClick', filename: 'https://interface.encryption.example/assets/index.js', lineno: 5 });
  });

  it('marks an extension frame as not ours, so a user add-on does not look like our bug', () => {
    const frames = parseBrowserStack('    at f (chrome-extension://abcdef/inject.js:1:1)');

    expect(frames[0].in_app).toBe(false);
  });

  it('drops a query string from the file, but never scrubs the path itself', () => {
    // A redacted character in the path would silently break symbolication.
    const frames = parseBrowserStack(
      '    at f (https://interface.encryption.example/assets/index-0123456789abcdef0123456789abcdef.js?token=secret:1:1)'
    );

    expect(frames[0].filename).toBe('https://interface.encryption.example/assets/index-0123456789abcdef0123456789abcdef.js');
  });
});

describe('buildEvent', () => {
  const config = { environment: 'production', release: 'abc123' };

  it('sends the error type, a redacted message and the stack, and nothing else', () => {
    const error = new Error('cannot decrypt for bob@example.gouv.fr');
    const event = buildEvent(config, { error }, { tags: { route: '/api/vault/items', method: 'POST', status: 500 } }, 'fixed-id');

    expect(event.exception?.values[0]).toMatchObject({ type: 'Error', value: 'cannot decrypt for [email]' });
    expect(event.tags).toEqual({ route: '/api/vault/items', method: 'POST', status: '500' });
    expect(event.level).toBe('error');
    expect(event.release).toBe('abc123');
  });

  it('carries no request, user, breadcrumb or context field at all', () => {
    const event = buildEvent(config, { error: new Error('boom') }, { tags: { route: '/api/me' } });

    // The guarantee is structural: these keys are never built, so no configuration
    // and no future SDK integration can start populating them.
    for (const forbidden of ['request', 'user', 'breadcrumbs', 'contexts', 'extra', 'server_name', 'modules']) {
      expect(event).not.toHaveProperty(forbidden);
    }
  });

  it('drops a tag that is not on the allowlist instead of redacting it', () => {
    const event = buildEvent(config, { message: 'hello' }, { tags: { authorization: 'Bearer x' } as never });

    expect(event.tags).toEqual({});
  });

  it('redacts tag values too', () => {
    const event = buildEvent(config, { message: 'hello' }, { tags: { host: 'a'.repeat(40) } });

    expect(event.tags.host).toBe('[redacted]');
  });

  it('handles a thrown non-Error without losing the event', () => {
    const event = buildEvent(config, { error: 'a plain string' });

    expect(event.exception?.values[0]).toEqual({ type: 'UnknownError', value: 'a plain string' });
  });

  it('sends a browser failure as a javascript exception with frames, not as text', () => {
    const event = buildEvent(config, {
      browserError: {
        name: 'TypeError',
        message: 'x is not a function',
        frames: [{ filename: 'https://interface.encryption.example/assets/index.js', lineno: 1, colno: 2, in_app: true }],
      },
    });

    expect(event.platform).toBe('javascript');
    expect(event.exception?.values[0].stacktrace?.frames[0].filename).toBe('https://interface.encryption.example/assets/index.js');
    expect(event).not.toHaveProperty('message');
  });

  it('omits release when the deployment sets none', () => {
    expect(buildEvent({ environment: 'test' }, { message: 'hello' })).not.toHaveProperty('release');
  });
});

describe('buildEnvelope', () => {
  it('emits the three newline-delimited lines the ingest API expects', () => {
    const event = buildEvent({ environment: 'test' }, { message: 'hello' }, {}, 'abcdef');
    const lines = buildEnvelope(event, '2026-01-01T00:00:00.000Z').split('\n');

    expect(JSON.parse(lines[0])).toEqual({ event_id: 'abcdef', sent_at: '2026-01-01T00:00:00.000Z' });
    expect(JSON.parse(lines[1])).toEqual({ type: 'event' });
    expect(JSON.parse(lines[2]).message.formatted).toBe('hello');
  });
});

describe('initMonitoring', () => {
  afterEach(() => {
    resetMonitoring();
    jest.restoreAllMocks();
  });

  it('stays disabled with no DSN, which is the default deployment', () => {
    expect(initMonitoring(undefined)).toBe(false);
    expect(initMonitoring({ dsn: '', environment: 'production' })).toBe(false);
    expect(isMonitoringEnabled()).toBe(false);
  });

  it('stays disabled on an unusable DSN rather than failing the boot', () => {
    expect(initMonitoring({ dsn: 'nonsense', environment: 'production' })).toBe(false);
  });

  it('sends nothing while disabled', async () => {
    const fetchMock = jest.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(null, { status: 200 }));

    captureServerError(new Error('boom'));
    await flushMonitoring();

    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('posts an envelope once enabled, with the auth header and no cookies', async () => {
    const fetchMock = jest.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(null, { status: 200 }));

    expect(initMonitoring({ dsn: 'https://key@sentry.example/7', environment: 'production' })).toBe(true);

    captureServerError(new Error('boom'), { tags: { route: '/api/me' } });
    await flushMonitoring();

    expect(fetchMock).toHaveBeenCalledTimes(1);

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    const headers = init.headers as Record<string, string>;

    expect(url).toBe('https://sentry.example/api/7/envelope/');
    expect(headers['Content-Type']).toBe('application/x-sentry-envelope');
    expect(headers['X-Sentry-Auth']).toContain('sentry_key=key');
    expect(init).not.toHaveProperty('credentials');
    expect(String(init.body)).toContain('"route":"/api/me"');
  });

  it('never lets a failing collector reach the caller', async () => {
    jest.spyOn(globalThis, 'fetch').mockRejectedValue(new Error('network down'));

    initMonitoring({ dsn: 'https://key@sentry.example/7', environment: 'production' });

    expect(() => captureServerError(new Error('boom'))).not.toThrow();
    await expect(flushMonitoring()).resolves.toBeUndefined();
  });

  it('stops sending after the rate limit, so an error loop cannot become a request loop', async () => {
    const fetchMock = jest.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(null, { status: 200 }));

    initMonitoring({ dsn: 'https://key@sentry.example/7', environment: 'production' });

    for (let index = 0; index < 100; index += 1) captureServerError(new Error(`boom ${index}`));
    await flushMonitoring();

    expect(fetchMock).toHaveBeenCalledTimes(30);
  });
});
