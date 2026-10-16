/// <reference lib="webworker" />

// This file is a module (see the trailing `export {}`) purely so its top-level
// declarations stay module-scoped rather than leaking into the global namespace.
// It exports no bindings, so the bundled classic service worker stays export-free.

/**
 * Service Worker for data.encryption (the vault).
 *
 * - Downloads the vault files of the server's version on install
 * - Serves them from the cache (works offline)
 * - Before serving the vault page, compares /api/version with the version it
 *   serves and, when they differ, downloads the new files into a cache of their
 *   own and switches to it, so the load that meets a new deployment already runs it
 *
 * The check runs on the vault page's request, not on a timer: the browser stops
 * an idle worker after about thirty seconds and starts it again for the next
 * event without `activate`, so a timer set there would not survive. A vault
 * whose code no longer matches the server fails in ways that name neither
 * (a proof of possession that never verifies, a seal the other side cannot
 * open), which is why the page waits for the check rather than updating for
 * the load after. Offline it does not wait at all; online it waits at most
 * VERSION_CHECK_TIMEOUT_MS and serves the cache.
 *
 * The SDK files (client.js, client.mjs) are not served from here: product pages
 * load them from another origin, and a Service Worker only sees the requests of
 * the pages of its own origin.
 *
 * Each version's files live in their own cache and the current version is
 * persisted in the Cache API (not in JS memory), so it survives SW restarts by
 * the browser.
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

const VERSION_CACHE = 'vault-version';
const CURRENT_VERSION_KEY = '/__internal__/current-version';
const FILES_CACHE_PREFIX = 'vault-files-';
const VAULT_PAGE_PATH = '/bridge.html';
const VAULT_FILES = ['/bridge.html', '/vault.js'];
const VERSION_CHECK_TIMEOUT_MS = 3000;
// Moving between a product's pages loads the vault again each time: one answer
// covers the loads that follow it closely.
const VERSION_CHECK_TTL_MS = 10_000;
// A frame just served is not yet listed by `clients.matchAll()`, and the files
// of its version must outlive a cleanup that runs before it asks for vault.js.
const SERVED_CLIENT_GRACE_MS = 60_000;

const filesCacheName = (version: string) => `${FILES_CACHE_PREFIX}${version}`;

// When the server last confirmed the current version, in this worker's lifetime.
let lastConfirmedAt = 0;

// --- Current version: the pointer to the files cache the next vault load uses ---

async function getCurrentVersion(): Promise<string | null> {
  try {
    const response = await (await caches.open(VERSION_CACHE)).match(CURRENT_VERSION_KEY);

    return response ? await response.text() : null;
  } catch {
    return null;
  }
}

async function setCurrentVersion(version: string): Promise<void> {
  const cache = await caches.open(VERSION_CACHE);

  await cache.put(CURRENT_VERSION_KEY, new Response(version, { headers: { 'Content-Type': 'text/plain' } }));
}

async function fetchServerVersion(): Promise<string | null> {
  const response = await fetch('/api/version', { cache: 'no-store' });

  if (!response.ok) return null;

  const data: unknown = await response.json().catch(() => null);

  return data && typeof data === 'object' && typeof (data as { version: unknown }).version === 'string'
    ? (data as { version: string }).version
    : null;
}

/**
 * Download every vault file into the cache of `version`, then make it current.
 * The files go to a cache nothing reads yet and the switch is a single write, so a
 * load sees either the previous set or the new one, never a mix that SRI would
 * reject. A deployment landing between the version request and the files would put
 * another version's files under this name: the version is asked again afterwards and
 * nothing is switched when it moved.
 */
async function downloadVersion(version: string): Promise<boolean> {
  try {
    const responses: Response[] = [];

    for (const path of VAULT_FILES) {
      const response = await fetch(path, { cache: 'reload' });

      if (!response.ok) return false;

      responses.push(response);
    }

    if ((await fetchServerVersion()) !== version) return false;

    const cache = await caches.open(filesCacheName(version));

    await Promise.all(VAULT_FILES.map((path, index) => cache.put(path, responses[index])));
    await setCurrentVersion(version);

    return true;
  } catch {
    return false;
  }
}

// --- Install: download the server's version ---
sw.addEventListener('install', (event) => {
  // A worker without files would only pass every request to the network: failing the
  // install keeps the previous worker, and the next vault load registers again.
  event.waitUntil(
    (async () => {
      const version = await fetchServerVersion();

      if (version === null || !(await downloadVersion(version))) {
        throw new Error('the vault files could not be downloaded');
      }

      lastConfirmedAt = Date.now();
    })()
  );

  sw.skipWaiting();
});

// --- Activate: claim all clients, drop the caches of an earlier worker ---
sw.addEventListener('activate', (event) => {
  event.waitUntil(Promise.all([sw.clients.claim(), deleteUnusedCaches()]));
});

// --- Fetch: the vault page after a version check, its script from the same version ---

// The version each vault frame was served, so its vault.js comes from the same set
// even when an update lands between the page and the script.
const servedVersions = new Map<string, { version: string; at: number }>();

sw.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);

  if (url.origin !== sw.location.origin || !VAULT_FILES.includes(url.pathname)) {
    return;
  }

  if (url.pathname !== VAULT_PAGE_PATH) {
    event.respondWith(serveFile(event.request, url.pathname, servedVersions.get(event.clientId)?.version));

    return;
  }

  // Offline the answer is known without asking. `onLine` can be true without a
  // working connection (a captive portal, a server that does not answer), which is
  // what the timeout is for.
  let ready = Promise.resolve();

  if (sw.navigator.onLine && Date.now() - lastConfirmedAt >= VERSION_CHECK_TTL_MS) {
    const check = checkForUpdateOnce();

    // A check that outlasts the wait still completes, for the next load.
    event.waitUntil(check);
    ready = waitAtMost(check, VERSION_CHECK_TIMEOUT_MS);
  }

  event.respondWith(
    ready.then(async () => {
      const version = await getCurrentVersion();

      if (version !== null && event.resultingClientId) {
        servedVersions.set(event.resultingClientId, { version, at: Date.now() });
      }

      return serveFile(event.request, VAULT_PAGE_PATH, version ?? undefined);
    })
  );
});

async function serveFile(request: Request, path: string, version: string | undefined): Promise<Response> {
  const name = version ?? (await getCurrentVersion());
  const cached = name === null ? undefined : await (await caches.open(filesCacheName(name))).match(path);

  return cached ?? fetch(request);
}

function waitAtMost(promise: Promise<void>, ms: number): Promise<void> {
  return new Promise((resolve) => {
    const timer = setTimeout(resolve, ms);

    promise.finally(() => {
      clearTimeout(timer);
      resolve();
    });
  });
}

// --- Version check ---

// Frames loading together (a product embeds the vault more than once, several tabs
// open at once) share one check instead of each downloading the files.
let pendingCheck: Promise<void> | null = null;

function checkForUpdateOnce(): Promise<void> {
  pendingCheck ??= checkForUpdate().finally(() => {
    pendingCheck = null;
  });

  return pendingCheck;
}

async function checkForUpdate(): Promise<void> {
  try {
    const serverVersion = await fetchServerVersion();

    if (serverVersion === null) return;

    // On failure the current version stays, and the next load tries again.
    if (serverVersion === (await getCurrentVersion()) || (await downloadVersion(serverVersion))) {
      lastConfirmedAt = Date.now();
      await deleteUnusedCaches();
    }
  } catch {
    // Network error: the next vault load checks again
  }
}

/**
 * Keep the current files and those of the frames still running an earlier version;
 * delete everything else, including the caches of an earlier worker.
 */
async function deleteUnusedCaches(): Promise<void> {
  const current = await getCurrentVersion();
  const liveClients = new Set((await sw.clients.matchAll({ includeUncontrolled: true })).map((client) => client.id));
  const now = Date.now();

  for (const [clientId, served] of servedVersions) {
    if (!liveClients.has(clientId) && now - served.at >= SERVED_CLIENT_GRACE_MS) {
      servedVersions.delete(clientId);
    }
  }

  const kept = new Set([VERSION_CACHE, ...[...servedVersions.values()].map((served) => filesCacheName(served.version))]);

  if (current !== null) kept.add(filesCacheName(current));

  for (const name of await caches.keys()) {
    if (!kept.has(name)) await caches.delete(name);
  }
}

// Make this file a module for the type-checker without emitting any runtime export.
export {};
