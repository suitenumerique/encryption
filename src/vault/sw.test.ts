/**
 * @jest-environment jsdom
 *
 * The service worker keeps its logic internal (no exports, since it is
 * registered as a classic script and exports would break it). We therefore
 * drive it through its real public surface: we capture the event handlers it
 * registers at import time, mock the Cache API + fetch, then fire the
 * `activate` event which schedules the version check and runs it once
 * immediately.
 */

const VERSION_KEY = '/__internal__/known-version';
const PRECACHE_URLS = ['/bridge.html', '/vault.js', '/client.js', '/client.mjs', '/client.d.ts'];

// Minimal Response stand-in: jsdom does not expose a controllable Response.
class MockResponse {
  body: string;
  ok: boolean;
  status: number;

  constructor(body = '', init?: { ok?: boolean; status?: number }) {
    this.body = body;
    this.ok = init?.ok ?? true;
    this.status = init?.status ?? 200;
  }

  async text(): Promise<string> {
    return this.body;
  }

  async json(): Promise<unknown> {
    return JSON.parse(this.body);
  }
}

// Single in-memory cache shared by caches.open() (the SW uses one named cache).
class FakeCache {
  store = new Map<string, MockResponse>();

  async match(key: string): Promise<MockResponse | undefined> {
    return this.store.get(key);
  }

  async put(key: string, value: MockResponse): Promise<void> {
    this.store.set(key, value);
  }
}

const flush = () => new Promise((resolve) => setTimeout(resolve, 0));

describe('sw version check + atomic refresh', () => {
  let handlers: Record<string, (event: unknown) => void>;
  let cache: FakeCache;
  let fetchMock: jest.Mock;
  let originalAddEventListener: typeof window.addEventListener;

  const activate = async () => {
    handlers.activate?.({ waitUntil: () => {} });
    await flush();
    await flush();
  };

  const seedBaseline = async (version: string) => {
    cache.store.set(VERSION_KEY, new MockResponse(version));

    for (const url of PRECACHE_URLS) {
      cache.store.set(url, new MockResponse('old'));
    }
  };

  beforeEach(async () => {
    jest.resetModules();

    handlers = {};
    cache = new FakeCache();

    originalAddEventListener = window.addEventListener;
    // Capture the handlers the SW registers at import time.
    (window as unknown as { addEventListener: unknown }).addEventListener = (type: string, h: (event: unknown) => void) => {
      handlers[type] = h;
    };

    // Neutralize the 5-minute interval; checkForUpdate() still runs once directly.
    jest.spyOn(window, 'setInterval').mockReturnValue(0 as unknown as ReturnType<typeof setInterval>);

    (window as unknown as { clients: unknown }).clients = { claim: () => Promise.resolve() };
    (globalThis as unknown as { caches: unknown }).caches = { open: async () => cache };
    (globalThis as unknown as { Response: unknown }).Response = MockResponse;

    fetchMock = jest.fn();
    (globalThis as unknown as { fetch: unknown }).fetch = fetchMock;

    await jest.isolateModulesAsync(async () => {
      await import('@encryption/src/vault/sw');
    });
  });

  afterEach(() => {
    (window as unknown as { addEventListener: unknown }).addEventListener = originalAddEventListener;
    jest.restoreAllMocks();
  });

  const versionResponse = (version: string) => new MockResponse(JSON.stringify({ version }), { ok: true });

  it('records the version and rewrites every bundle when all fetches succeed', async () => {
    await seedBaseline('v1');

    fetchMock.mockImplementation(async (url: string) => {
      if (url === '/api/version') return versionResponse('v2');

      return new MockResponse(`new:${url}`, { ok: true });
    });

    await activate();

    expect(await (await cache.match(VERSION_KEY))!.text()).toBe('v2');

    for (const url of PRECACHE_URLS) {
      expect((await cache.match(url))!.body).toBe(`new:${url}`);
    }
  });

  it('does NOT advance the version and leaves the cache untouched when one bundle fails mid-refresh', async () => {
    await seedBaseline('v1');

    fetchMock.mockImplementation(async (url: string) => {
      if (url === '/api/version') return versionResponse('v2');
      // The third bundle 404s: the refresh must be all-or-nothing.
      if (url === '/client.js') return new MockResponse('', { ok: false, status: 404 });

      return new MockResponse(`new:${url}`, { ok: true });
    });

    await activate();

    // Version stays at the old baseline so the next tick retries.
    expect(await (await cache.match(VERSION_KEY))!.text()).toBe('v1');

    // No bundle was overwritten (all-or-nothing) — not even the ones fetched
    // before the failing one, which would otherwise pin a mixed old/new set.
    for (const url of PRECACHE_URLS) {
      expect((await cache.match(url))!.body).toBe('old');
    }
  });

  it('does NOT advance the version when the network throws mid-refresh', async () => {
    await seedBaseline('v1');

    fetchMock.mockImplementation(async (url: string) => {
      if (url === '/api/version') return versionResponse('v2');
      if (url === '/vault.js') throw new Error('offline');

      return new MockResponse(`new:${url}`, { ok: true });
    });

    await activate();

    expect(await (await cache.match(VERSION_KEY))!.text()).toBe('v1');

    for (const url of PRECACHE_URLS) {
      expect((await cache.match(url))!.body).toBe('old');
    }
  });

  it('stores the baseline on the first-ever check without refreshing bundles', async () => {
    // No known version yet.
    fetchMock.mockImplementation(async (url: string) => {
      if (url === '/api/version') return versionResponse('v1');

      throw new Error('bundles should not be fetched on the baseline check');
    });

    await activate();

    expect(await (await cache.match(VERSION_KEY))!.text()).toBe('v1');
    // Only /api/version was fetched.
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock).toHaveBeenCalledWith('/api/version', { cache: 'no-store' });
  });
});

export {};
