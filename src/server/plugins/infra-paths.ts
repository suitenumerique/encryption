// Infrastructure paths Fastify owns on EVERY host, including the vault and UI hosts whose
// remaining traffic belongs to the static files (production) or to Vite (development).
// Both of those intercept requests before routing, so a path missing here is shadowed:
// it 404s under Vite, and the interface answers it with its HTML page in production.
// Must stay in sync with the matching routes in server.ts.
export const FASTIFY_INFRA_PATHS = new Set(['/health', '/robots.txt', '/favicon.ico', '/.well-known/security.txt']);
