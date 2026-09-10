/// <reference lib="webworker" />

// This file is a module (see the trailing `export {}`) purely so its top-level
// declarations stay module-scoped rather than leaking into the global namespace.
// It exports no bindings, so the bundled classic service worker stays export-free.

/**
 * Service Worker for data.encryption (vault + client SDK).
 *
 * - Caches vault and client files on install
 * - Serves from cache first (works offline)
 * - Checks /api/version every 5 minutes
 * - If a new version is detected, re-fetches all files into cache atomically
 *
 * Updates are applied silently to the cache and take effect on the next natural
 * page load; no message is emitted to clients.
 *
 * The known version is persisted in the Cache API (not in JS memory)
 * so it survives SW restarts by the browser.
 */

const sw = self as unknown as ServiceWorkerGlobalScope;

// Report the worker's uncaught errors, otherwise it can die silently and leave stale
// bundles in the cache with nobody knowing.
//
// Why this is written out here instead of importing src/shared/error-reporting.ts:
// vault.js and sw.js are two entries of the same Vite build. If both import one
// module, Rollup moves that module into a third file (a shared chunk under assets/)
// and makes both entries import it. The vault host only serves a fixed list of
// files, so that chunk would be a 404 in production, and a Service Worker cannot
// import modules anyway. The build fails on any extra chunk to make this visible.
//
// What is sent: the error class name and a fixed code, nothing else. No message, no
// stack. Same endpoint, same origin, at most five reports per worker lifetime.
const MAX_REPORTS = 5;
let reported = 0;

function reportWorkerError(error: unknown): void {
  if (reported >= MAX_REPORTS) return;
  reported += 1;

  const name = error instanceof Error && /^[A-Za-z]{1,40}$/.test(error.name) ? error.name : 'Error';

  fetch('/api/browser-reports', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'omit',
    keepalive: true,
    body: JSON.stringify({ type: 'browser-error', name, code: 'UNKNOWN', frames: [] }),
  }).catch(() => {
    // Reporting a failure must never become a failure of its own.
  });
}

sw.addEventListener('error', (event) => reportWorkerError(event.error));
sw.addEventListener('unhandledrejection', (event) => reportWorkerError(event.reason));

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
      // First check ever, store as baseline.
      await setKnownVersion(serverVersion);
    } else if (serverVersion !== knownVersion) {
      // Refresh the cache first and only record the new version once every
      // bundle was updated. On failure, leave knownVersion untouched so the
      // next tick retries instead of pinning a mixed old/new bundle set that
      // SRI would reject.
      const refreshed = await refreshCache();

      if (refreshed) {
        await setKnownVersion(serverVersion);
      }
    }
  } catch {
    // Network error — retry later
  }
}

/**
 * Re-fetch all precached files and write them into the cache atomically
 * (all-or-nothing). Every URL is fetched first; only if EVERY response is ok
 * are they written into the cache. On any failure the existing cache and the
 * recorded version are left untouched, so the next check retries cleanly and
 * a mid-refresh network failure can never pin a mixed old/new bundle set
 * (e.g. new HTML with an old vault.js) that SRI would then reject.
 *
 * @returns true if the cache was fully refreshed, false otherwise.
 */
async function refreshCache(): Promise<boolean> {
  try {
    const responses: Response[] = [];

    for (const url of PRECACHE_URLS) {
      const response = await fetch(url, { cache: 'reload' });

      if (!response.ok) {
        return false;
      }

      responses.push(response);
    }

    const cache = await caches.open(CACHE_NAME);

    await Promise.all(PRECACHE_URLS.map((url, index) => cache.put(url, responses[index])));

    return true;
  } catch {
    // Offline or a fetch failed — leave the existing cache untouched.
    return false;
  }
}

// Make this file a module for the type-checker without emitting any runtime export.
export {};
