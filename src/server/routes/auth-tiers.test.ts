import Fastify from 'fastify';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it, vi } from 'vitest';

import { API_ROUTE_PLUGINS } from '@encryption/src/server/routes/api-routes';

vi.mock('@encryption/src/server/env', () => ({ env: { OIDC_ISSUER: 'https://issuer.example' } }));

// Routes registered by a plugin that installs the transport auth, recorded from inside it.
const transportAuthRoutes = vi.hoisted(() => new Set<string>());

vi.mock('@encryption/src/server/routes/transport-auth', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@encryption/src/server/routes/transport-auth')>();

  return {
    ...actual,
    registerTransportAuth: (app: Parameters<typeof actual.registerTransportAuth>[0]) => {
      actual.registerTransportAuth(app);
      app.addHook('onRoute', (route) => {
        for (const method of [route.method].flat()) transportAuthRoutes.add(`${method} ${route.url}`);
      });
    },
  };
});

/**
 * The complete authentication surface of the API, asserted as data.
 *
 *   PUBLIC              no authentication before the handler (what the handler checks
 *                       itself, if anything, is commented below)
 *   ID_TOKEN            the interface's ID token only: a `verifyIdToken` preHandler, or
 *                       SKIP_SIG for callers that structurally cannot sign yet
 *                       (proof-of-possession flows, the lost-key recovery paths)
 *   SIGNATURE           the identity signature only (SIG_ONLY), for the background data plane
 *   ID_TOKEN+SIGNATURE  the transport auth's default, for any route that does not opt out
 *   +STEP_UP            plus a fresh second-factor authentication (STEP_UP)
 *
 * A new route, or a changed flag, fails this test until the line below is
 * updated deliberately. That is the point: weakening a route's auth should be an
 * explicit edit to this table, reviewed as such, never a silent side effect of a
 * refactor. The per-route MECHANISM (signature validity, path binding, body
 * digest, replay) is covered separately in vault.test.ts.
 */
const EXPECTED_AUTH_SURFACE = [
  'DELETE /api/councils/escrow ID_TOKEN+SIGNATURE+STEP_UP',
  'DELETE /api/emergency-access/:id ID_TOKEN',
  'DELETE /api/public-keys ID_TOKEN',
  // The login itself (authorize, relay, token) rests on the OIDC provider's word,
  // checked inside: the state, the PKCE verifier and the provider's code.
  'GET /api/auth/authorize PUBLIC',
  'GET /api/council-recovery/requests/:id/custodian ID_TOKEN',
  'GET /api/council-recovery/requests/:id/shares ID_TOKEN',
  'GET /api/council-recovery/requests/mine ID_TOKEN',
  'GET /api/councils/:councilId/requests ID_TOKEN',
  'GET /api/councils/:councilId/shares-to-check ID_TOKEN',
  'GET /api/councils/for-me ID_TOKEN',
  'GET /api/councils/mine ID_TOKEN',
  'GET /api/councils/reshare/:sessionId/batch ID_TOKEN',
  'GET /api/emergency-access/granted ID_TOKEN',
  'GET /api/emergency-access/pending SIGNATURE',
  'GET /api/emergency-access/search ID_TOKEN',
  'GET /api/emergency-access/trusted ID_TOKEN',
  // Called by the vault during a product's share, which carries no token.
  'GET /api/maintenance-escrow/assignment PUBLIC',
  // The public-key directory.
  'GET /api/public-keys PUBLIC',
  'GET /api/public-keys/:userId PUBLIC',
  'GET /api/public-keys/:userId/continuity PUBLIC',
  'GET /api/public-keys/next ID_TOKEN',
  'GET /api/vault/approvals/:requestId ID_TOKEN',
  'GET /api/vault/approvals/pending ID_TOKEN+SIGNATURE',
  'GET /api/vault/events SIGNATURE',
  'GET /api/vault/items SIGNATURE',
  'GET /api/vault/meta ID_TOKEN',
  'GET /api/vault/revision SIGNATURE',
  'GET /api/version PUBLIC',
  'POST /api/auth/relay PUBLIC',
  'POST /api/auth/token PUBLIC',
  // Sent by browsers, which attach nothing to a report.
  'POST /api/browser-reports PUBLIC',
  'POST /api/council-recovery/requests ID_TOKEN',
  'POST /api/council-recovery/requests/:id/abort ID_TOKEN+SIGNATURE+STEP_UP',
  'POST /api/council-recovery/requests/:id/contribute ID_TOKEN+SIGNATURE+STEP_UP',
  'POST /api/council-recovery/requests/:id/refuse ID_TOKEN',
  'POST /api/councils/:councilId/reshare ID_TOKEN+SIGNATURE+STEP_UP',
  'POST /api/councils/:councilId/shares-checked ID_TOKEN+SIGNATURE',
  'POST /api/councils/:councilId/versions/:version/sign ID_TOKEN+SIGNATURE+STEP_UP',
  'POST /api/councils/escrow ID_TOKEN+SIGNATURE',
  'POST /api/councils/reshare/:sessionId/cancel ID_TOKEN+SIGNATURE+STEP_UP',
  'POST /api/councils/reshare/:sessionId/keys ID_TOKEN+SIGNATURE+STEP_UP',
  'POST /api/councils/reshare/:sessionId/sub-shares ID_TOKEN+SIGNATURE+STEP_UP',
  'POST /api/emergency-access ID_TOKEN+SIGNATURE',
  'POST /api/emergency-access/:id/accept ID_TOKEN',
  'POST /api/emergency-access/:id/cancel ID_TOKEN',
  'POST /api/emergency-access/:id/initiate ID_TOKEN+SIGNATURE',
  'POST /api/emergency-access/:id/rearm ID_TOKEN+SIGNATURE',
  'POST /api/emergency-access/:id/recover ID_TOKEN+SIGNATURE',
  'POST /api/emergency-access/:id/reject ID_TOKEN',
  'POST /api/public-keys/register/complete ID_TOKEN',
  // Asks the step-up itself, only when the key would replace the user's identity.
  'POST /api/public-keys/register/init ID_TOKEN',
  // Asks the step-up itself, only when the vault would replace the user's identity.
  'POST /api/vault ID_TOKEN',
  'POST /api/vault/approvals/:requestId/approve ID_TOKEN+SIGNATURE',
  'POST /api/vault/approvals/request ID_TOKEN',
  'POST /api/vault/challenge ID_TOKEN',
  'POST /api/vault/fetch ID_TOKEN',
  'POST /api/vault/reactivate ID_TOKEN',
  'POST /api/vault/reactivate-keyring ID_TOKEN',
  'PUT /api/emergency-access/:id ID_TOKEN+SIGNATURE',
  'PUT /api/vault/items/:itemId SIGNATURE',
  'PUT /api/vault/keyring ID_TOKEN+SIGNATURE',
];

interface CollectedRoute {
  row: string;
  hidden: boolean;
}

async function collectAuthSurface(): Promise<CollectedRoute[]> {
  const app = Fastify();
  const routes: { key: string; config: Record<string, unknown>; preHandler: boolean; hidden: boolean }[] = [];

  app.decorate('verifyIdToken', async () => {});

  app.addHook('onRoute', (route) => {
    for (const method of [route.method].flat()) {
      // HEAD is auto-derived from GET by Fastify and always mirrors it.
      if (method === 'HEAD') continue;

      routes.push({
        key: `${method} ${route.url}`,
        config: (route.config ?? {}) as Record<string, unknown>,
        preHandler: Boolean(route.preHandler),
        hidden: Boolean((route.schema as { hide?: boolean } | undefined)?.hide),
      });
    }
  });

  for (const plugin of API_ROUTE_PLUGINS) {
    await app.register(plugin);
  }
  await app.ready();
  await app.close();

  return routes
    .filter(({ key }) => key.split(' ')[1].startsWith('/api/'))
    .map(({ key, config, preHandler, hidden }) => {
      let tier: string;

      if (!transportAuthRoutes.has(key)) tier = preHandler ? 'ID_TOKEN' : 'PUBLIC';
      else if (config.signatureOnly) tier = 'SIGNATURE';
      else if (config.skipRequestSignature) tier = 'ID_TOKEN';
      else tier = config.stepUp ? 'ID_TOKEN+SIGNATURE+STEP_UP' : 'ID_TOKEN+SIGNATURE';

      return { row: `${key} ${tier}`, hidden };
    })
    .sort((a, b) => a.row.localeCompare(b.row));
}

function openApiOperations(): string[] {
  const document = JSON.parse(readFileSync(resolve(process.cwd(), 'openapi.json'), 'utf-8')) as { paths: Record<string, Record<string, unknown>> };

  return Object.entries(document.paths)
    .flatMap(([path, operations]) => Object.keys(operations).map((method) => `${method.toUpperCase()} ${path.replace(/\{(\w+)\}/g, ':$1')}`))
    .sort();
}

describe('API authentication surface', () => {
  it('assigns every route the expected auth tier', async () => {
    expect((await collectAuthSurface()).map(({ row }) => row)).toEqual(EXPECTED_AUTH_SURFACE);
  });

  it('covers every operation of the committed openapi.json, and no other documented one', async () => {
    const documented = (await collectAuthSurface()).filter(({ hidden }) => !hidden).map(({ row }) => row.split(' ').slice(0, 2).join(' '));

    expect(documented.sort()).toEqual(openApiOperations());
  });
});
