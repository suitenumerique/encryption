/**
 * @vitest-environment jsdom
 *
 * The service worker keeps its logic internal (no exports, since it is
 * registered as a classic script and exports would break it). We therefore
 * drive it through its real public surface: we capture the event handlers it
 * registers at import time, mock the Cache API, the clients and fetch, then fire
 * `install`, `activate` and `fetch` events.
 */
import { type Mock, afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const VERSION_CACHE = 'vault-version';
const CURRENT_VERSION_KEY = '/__internal__/current-version';
const VAULT_FILES = ['/bridge.html', '/vault.js'];

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

class FakeCache {
  store = new Map<string, MockResponse>();

  async match(key: string): Promise<MockResponse | undefined> {
    return this.store.get(key);
  }

  async put(key: string, value: MockResponse): Promise<void> {
    this.store.set(key, value);
  }
}

class FakeCacheStorage {
  caches = new Map<string, FakeCache>();

  async open(name: string): Promise<FakeCache> {
    if (!this.caches.has(name)) this.caches.set(name, new FakeCache());

    return this.caches.get(name)!;
  }

  async keys(): Promise<string[]> {
    return [...this.caches.keys()];
  }

  async delete(name: string): Promise<boolean> {
    return this.caches.delete(name);
  }
}

describe('sw', () => {
  let handlers: Record<string, (event: unknown) => void>;
  let storage: FakeCacheStorage;
  let fetchMock: Mock;
  let liveClients: string[];
  let originalAddEventListener: typeof window.addEventListener;

  const versionResponse = (version: string) => new MockResponse(JSON.stringify({ version }), { ok: true });

  // A server at `version`, answering every file with its version in the body.
  const serve = (version: string) =>
    fetchMock.mockImplementation(async (url: string) =>
      url === '/api/version' ? versionResponse(version) : new MockResponse(`${version}:${url}`, { ok: true })
    );

  const seed = (version: string) => {
    storage.caches.set(VERSION_CACHE, new FakeCache());
    storage.caches.get(VERSION_CACHE)!.store.set(CURRENT_VERSION_KEY, new MockResponse(version));

    const files = new FakeCache();

    for (const path of VAULT_FILES) files.store.set(path, new MockResponse(`${version}:${path}`));

    storage.caches.set(`vault-files-${version}`, files);
  };

  const currentVersion = async () => (await storage.caches.get(VERSION_CACHE)?.match(CURRENT_VERSION_KEY))?.body;

  const lifecycle = async (type: 'install' | 'activate'): Promise<void> => {
    let done: Promise<unknown> = Promise.resolve();

    handlers[type]?.({ waitUntil: (promise: Promise<unknown>) => (done = promise) });

    await done;
  };

  // `client` is the frame the vault page creates, or the frame asking for vault.js.
  const load = (path: string, client = 'frame-1'): Promise<MockResponse> => {
    let response: Promise<MockResponse> | undefined;
    const isPage = path === '/bridge.html';

    handlers.fetch?.({
      request: { url: `${window.location.origin}${path}` },
      clientId: isPage ? '' : client,
      resultingClientId: isPage ? client : '',
      respondWith: (promise: Promise<MockResponse>) => {
        response = promise;
      },
      waitUntil: () => {},
    });

    if (!response) throw new Error(`the worker did not answer ${path}`);

    return response;
  };

  const versionChecks = () => fetchMock.mock.calls.filter(([url]) => url === '/api/version').length;

  beforeEach(async () => {
    handlers = {};
    storage = new FakeCacheStorage();
    liveClients = [];

    originalAddEventListener = window.addEventListener;
    // Capture the handlers the SW registers at import time.
    (window as unknown as { addEventListener: unknown }).addEventListener = (type: string, h: (event: unknown) => void) => {
      handlers[type] = h;
    };

    (window as unknown as { clients: unknown }).clients = {
      claim: () => Promise.resolve(),
      matchAll: async () => liveClients.map((id) => ({ id })),
    };
    (window as unknown as { skipWaiting: unknown }).skipWaiting = () => Promise.resolve();
    (globalThis as unknown as { caches: unknown }).caches = storage;
    (globalThis as unknown as { Response: unknown }).Response = MockResponse;

    fetchMock = vi.fn();
    (globalThis as unknown as { fetch: unknown }).fetch = fetchMock;

    vi.resetModules();
    await import('@encryption/src/vault/sw');
  });

  afterEach(() => {
    (window as unknown as { addEventListener: unknown }).addEventListener = originalAddEventListener;
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  describe('install', () => {
    it('downloads the files of the server version into their own cache and makes it current', async () => {
      serve('v1');

      await lifecycle('install');

      expect(await currentVersion()).toBe('v1');

      for (const path of VAULT_FILES) {
        expect((await storage.caches.get('vault-files-v1')!.match(path))!.body).toBe(`v1:${path}`);
      }
    });

    it('fails when a file cannot be downloaded, so the browser keeps the previous worker', async () => {
      fetchMock.mockImplementation(async (url: string) =>
        url === '/vault.js' ? new MockResponse('', { ok: false, status: 404 }) : versionResponse('v1')
      );

      await expect(lifecycle('install')).rejects.toThrow();
      expect(await currentVersion()).toBeUndefined();
    });

    it('records nothing when a deployment lands during the download', async () => {
      let versionCalls = 0;

      fetchMock.mockImplementation(async (url: string) => {
        if (url === '/api/version') return versionResponse(versionCalls++ === 0 ? 'v1' : 'v2');

        return new MockResponse(`mixed:${url}`, { ok: true });
      });

      await expect(lifecycle('install')).rejects.toThrow();
      expect(await currentVersion()).toBeUndefined();
    });
  });

  it('activate deletes the caches of an earlier worker', async () => {
    seed('v1');
    storage.caches.set('vault-v1', new FakeCache());

    await lifecycle('activate');

    expect(await storage.keys()).toEqual([VERSION_CACHE, 'vault-files-v1']);
  });

  // The browser stops an idle worker and starts it again for the next request
  // without `activate`: these tests import the worker and only fire `fetch`.
  describe('on a vault load', () => {
    it('serves the new vault on the first load after a deployment', async () => {
      seed('v1');
      serve('v2');

      expect((await load('/bridge.html')).body).toBe('v2:/bridge.html');
      expect((await load('/vault.js')).body).toBe('v2:/vault.js');
      expect(await currentVersion()).toBe('v2');
      expect(fetchMock).toHaveBeenCalledWith('/api/version', { cache: 'no-store' });
    });

    it('serves the cache without downloading anything when the version is unchanged', async () => {
      seed('v1');
      fetchMock.mockImplementation(async (url: string) => {
        if (url === '/api/version') return versionResponse('v1');

        throw new Error('files should not be downloaded when the version is unchanged');
      });

      expect((await load('/bridge.html')).body).toBe('v1:/bridge.html');
      expect(fetchMock).toHaveBeenCalledTimes(1);
    });

    it('serves the cache at once, without asking, when the browser is offline', async () => {
      seed('v1');
      vi.spyOn(window.navigator, 'onLine', 'get').mockReturnValue(false);

      expect((await load('/bridge.html')).body).toBe('v1:/bridge.html');
      expect(fetchMock).not.toHaveBeenCalled();
    });

    it('serves the cache when the server is unreachable', async () => {
      seed('v1');
      fetchMock.mockRejectedValue(new Error('offline'));

      expect((await load('/bridge.html')).body).toBe('v1:/bridge.html');
    });

    it('keeps the current version when a file fails during the download', async () => {
      seed('v1');
      fetchMock.mockImplementation(async (url: string) => {
        if (url === '/api/version') return versionResponse('v2');
        if (url === '/vault.js') return new MockResponse('', { ok: false, status: 404 });

        return new MockResponse(`v2:${url}`, { ok: true });
      });

      expect((await load('/bridge.html')).body).toBe('v1:/bridge.html');
      expect(await currentVersion()).toBe('v1');
    });

    it('keeps the current version when a deployment lands during the download', async () => {
      seed('v1');

      let versionCalls = 0;

      fetchMock.mockImplementation(async (url: string) => {
        if (url === '/api/version') return versionResponse(versionCalls++ === 0 ? 'v2' : 'v3');

        return new MockResponse(`mixed:${url}`, { ok: true });
      });

      expect((await load('/bridge.html')).body).toBe('v1:/bridge.html');
      expect(await currentVersion()).toBe('v1');
    });

    it('serves the cache after the timeout, and the page served keeps its own vault.js once the update lands', async () => {
      vi.useFakeTimers();
      seed('v1');

      let answerVersion: (response: MockResponse) => void = () => {};

      fetchMock.mockImplementation((url: string) => {
        if (url === '/api/version' && versionChecks() === 1) return new Promise((resolve) => (answerVersion = resolve));
        if (url === '/api/version') return Promise.resolve(versionResponse('v2'));

        return Promise.resolve(new MockResponse(`v2:${url}`, { ok: true }));
      });

      const page = load('/bridge.html', 'slow-frame');

      await vi.advanceTimersByTimeAsync(3000);
      expect((await page).body).toBe('v1:/bridge.html');

      answerVersion(versionResponse('v2'));
      await vi.advanceTimersByTimeAsync(0);
      expect(await currentVersion()).toBe('v2');

      // The old page pins the old vault.js by its SRI hash.
      expect((await load('/vault.js', 'slow-frame')).body).toBe('v1:/vault.js');
      expect((await load('/bridge.html', 'next-frame')).body).toBe('v2:/bridge.html');
      expect((await load('/vault.js', 'next-frame')).body).toBe('v2:/vault.js');
    });

    it('checks once for frames loading together', async () => {
      seed('v1');
      serve('v2');

      const pages = await Promise.all([load('/bridge.html', 'frame-1'), load('/bridge.html', 'frame-2')]);

      expect(pages.map((page) => page.body)).toEqual(['v2:/bridge.html', 'v2:/bridge.html']);
      expect(fetchMock.mock.calls.filter(([url]) => url === '/vault.js')).toHaveLength(1);
    });

    it('does not ask again for a load following closely, and asks once the answer is old', async () => {
      vi.useFakeTimers();
      seed('v1');
      serve('v1');

      await load('/bridge.html', 'frame-1');
      await vi.advanceTimersByTimeAsync(5000);
      await load('/bridge.html', 'frame-2');
      expect(versionChecks()).toBe(1);

      await vi.advanceTimersByTimeAsync(5000);
      await load('/bridge.html', 'frame-3');
      expect(versionChecks()).toBe(2);
    });

    it('does not check the version for vault.js', async () => {
      seed('v1');

      expect((await load('/vault.js')).body).toBe('v1:/vault.js');
      expect(fetchMock).not.toHaveBeenCalled();
    });

    it('lets the SDK files through to the network', () => {
      expect(() => load('/client.js')).toThrow('the worker did not answer /client.js');
    });
  });

  describe('old versions', () => {
    it('are kept while a frame still runs them, then deleted', async () => {
      vi.useFakeTimers();
      seed('v1');
      serve('v1');

      await load('/bridge.html', 'old-frame');
      liveClients = ['old-frame'];

      serve('v2');
      await vi.advanceTimersByTimeAsync(10_000);
      await load('/bridge.html', 'new-frame');
      expect(await storage.keys()).toContain('vault-files-v1');

      liveClients = ['new-frame'];
      await vi.advanceTimersByTimeAsync(60_000);
      await load('/bridge.html', 'newer-frame');
      expect(await storage.keys()).toEqual([VERSION_CACHE, 'vault-files-v2']);
    });

    it('survive a cleanup that runs before the frame just served is listed', async () => {
      vi.useFakeTimers();
      seed('v1');
      serve('v1');

      await load('/bridge.html', 'unlisted-frame');

      serve('v2');
      await vi.advanceTimersByTimeAsync(10_000);
      await load('/bridge.html', 'new-frame');

      expect((await load('/vault.js', 'unlisted-frame')).body).toBe('v1:/vault.js');
    });
  });
});

export {};
