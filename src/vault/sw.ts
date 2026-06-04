/// <reference lib="webworker" />

/**
 * Service Worker for data.encryption (vault + client SDK).
 *
 * - Caches vault and client files on install
 * - Serves from cache first (works offline)
 * - Checks /api/version every 5 minutes
 * - If a new version is detected, re-fetches all files into cache
 * - Notifies all clients (vault iframes) of updates
 *
 * The known version is persisted in the Cache API (not in JS memory)
 * so it survives SW restarts by the browser.
 */

const sw = self as unknown as ServiceWorkerGlobalScope;

const CACHE_NAME = 'vault-v1';
const VERSION_KEY = '/__internal__/known-version';
const VERSION_CHECK_INTERVAL_MS = 5 * 60 * 1000;

const PRECACHE_URLS = ['/bridge.html', '/vault.js', '/client.js', '/client.mjs', '/client.d.ts'];

// --- Persisted version storage via Cache API ---

async function getKnownVersion(): Promise<string | null> {
  try {
    const cache = await caches.open(CACHE_NAME);
    const response = await cache.match(VERSION_KEY);

    if (!response) return null;

    return await response.text();
  } catch {
    return null;
  }
}

async function setKnownVersion(version: string): Promise<void> {
  try {
    const cache = await caches.open(CACHE_NAME);

    await cache.put(VERSION_KEY, new Response(version, { headers: { 'Content-Type': 'text/plain' } }));
  } catch {
    // Best-effort
  }
}

// --- Install: precache files ---
sw.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then(async (cache) => {
      for (const url of PRECACHE_URLS) {
        try {
          const response = await fetch(url, { cache: 'reload' });

          if (response.ok) {
            await cache.put(url, response);
          }
        } catch {
          // Fetch may fail in dev
        }
      }
    })
  );

  sw.skipWaiting();
});

// --- Activate: claim all clients ---
sw.addEventListener('activate', (event) => {
  event.waitUntil(sw.clients.claim());
  startVersionCheck();
});

// --- Fetch: cache-first for static files ---
sw.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);

  if (url.origin !== sw.location.origin) {
    return;
  }

  const cachedPaths = ['/bridge.html', '/vault.js', '/client.js', '/client.mjs', '/client.d.ts'];

  if (cachedPaths.includes(url.pathname)) {
    event.respondWith(caches.match(event.request).then((cached) => cached ?? fetch(event.request)));
  }
});

// --- Version check ---
function startVersionCheck(): void {
  setInterval(checkForUpdate, VERSION_CHECK_INTERVAL_MS);
  checkForUpdate();
}

async function checkForUpdate(): Promise<void> {
  try {
    const response = await fetch('/api/version', { cache: 'no-store' });

    if (!response.ok) {
      if (response.status < 500) {
        await refreshCache();
      }

      return;
    }

    let data: unknown;

    try {
      data = await response.json();
    } catch {
      await refreshCache();

      return;
    }

    if (!data || typeof data !== 'object' || typeof (data as { version: unknown }).version !== 'string') {
      await refreshCache();

      return;
    }

    const serverVersion = (data as { version: string }).version;
    const knownVersion = await getKnownVersion();

    if (knownVersion === null) {
      // First check ever — store as baseline
      await setKnownVersion(serverVersion);
    } else if (serverVersion !== knownVersion) {
      await setKnownVersion(serverVersion);
      await refreshCache();

      const clients = await sw.clients.matchAll();

      for (const client of clients) {
        client.postMessage({ type: 'vault:update-available', version: serverVersion });
      }
    }
  } catch {
    // Network error — retry later
  }
}

async function refreshCache(): Promise<void> {
  const cache = await caches.open(CACHE_NAME);

  for (const url of PRECACHE_URLS) {
    try {
      const response = await fetch(url, { cache: 'reload' });

      if (response.ok) {
        await cache.put(url, response);
      }
    } catch {
      // Offline
    }
  }
}
