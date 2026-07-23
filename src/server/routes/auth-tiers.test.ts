import Fastify from 'fastify';

import { meRoute } from '@encryption/src/server/routes/me';
import { publicKeysRoute } from '@encryption/src/server/routes/public-keys';
import { vaultRoute } from '@encryption/src/server/routes/vault';
import { versionRoute } from '@encryption/src/server/routes/versions';

jest.mock('@encryption/src/server/env', () => ({ env: { OIDC_ISSUER: 'https://issuer.example' } }));

/**
 * The complete authentication surface of the API, asserted as data.
 *
 * Each route's tier comes from its `config` (see the SKIP_SIG / SIG_ONLY flags in
 * vault.ts) and whether it installs the verifyJWT preHandler:
 *
 *   DEFAULT   JWT + per-request identity signature (the strictest tier, applied
 *             to anything under the vault plugin that does not opt out)
 *   SKIP_SIG  JWT only, for callers that structurally CANNOT sign yet
 *             (proof-of-possession flows, the lost-key recovery paths)
 *   SIG_ONLY  identity signature only, no JWT, for the background data plane
 *   jwt       whether the route runs `app.verifyJWT` itself
 *
 * A new route, or a changed flag, fails this test until the line below is
 * updated deliberately. That is the point: weakening a route's auth should be an
 * explicit edit to this table, reviewed as such, never a silent side effect of a
 * refactor. The per-route MECHANISM (signature validity, path binding, body
 * digest, replay) is covered separately in vault.test.ts.
 */
const EXPECTED_AUTH_SURFACE = [
  'DELETE /api/public-keys DEFAULT jwt=yes',
  'GET /api/me DEFAULT jwt=yes',
  'GET /api/public-keys DEFAULT jwt=no',
  'GET /api/public-keys/:userId DEFAULT jwt=no',
  'GET /api/public-keys/:userId/continuity DEFAULT jwt=no',
  'GET /api/public-keys/next DEFAULT jwt=yes',
  'GET /api/vault/approvals/:requestId SKIP_SIG jwt=no',
  'GET /api/vault/approvals/pending DEFAULT jwt=no',
  'GET /api/vault/events SIG_ONLY jwt=no',
  'GET /api/vault/items SIG_ONLY jwt=no',
  'GET /api/vault/meta SKIP_SIG jwt=no',
  'GET /api/vault/revision SIG_ONLY jwt=no',
  'GET /api/version DEFAULT jwt=no',
  'POST /api/public-keys/register/complete DEFAULT jwt=yes',
  'POST /api/public-keys/register/init DEFAULT jwt=yes',
  'POST /api/vault SKIP_SIG jwt=no',
  'POST /api/vault/approvals/:requestId/approve DEFAULT jwt=no',
  'POST /api/vault/approvals/request SKIP_SIG jwt=no',
  'POST /api/vault/challenge SKIP_SIG jwt=no',
  'POST /api/vault/fetch SKIP_SIG jwt=no',
  'POST /api/vault/reactivate SKIP_SIG jwt=no',
  'PUT /api/vault/items/:itemId SIG_ONLY jwt=no',
  'PUT /api/vault/keyring DEFAULT jwt=no',
];

async function collectAuthSurface(): Promise<string[]> {
  const app = Fastify();
  const rows: string[] = [];

  app.decorate('verifyJWT', async () => {});

  app.addHook('onRoute', (route) => {
    // HEAD is auto-derived from GET by Fastify and always mirrors it.
    if (route.method === 'HEAD') {
      return;
    }

    const config = (route.config ?? {}) as { skipRequestSignature?: boolean; signatureOnly?: boolean };
    const tier = config.signatureOnly ? 'SIG_ONLY' : config.skipRequestSignature ? 'SKIP_SIG' : 'DEFAULT';

    rows.push(`${route.method} ${route.url} ${tier} jwt=${route.preHandler ? 'yes' : 'no'}`);
  });

  await app.register(versionRoute);
  await app.register(meRoute);
  await app.register(publicKeysRoute);
  await app.register(vaultRoute);
  await app.ready();
  await app.close();

  return rows.sort();
}

describe('API authentication surface', () => {
  it('assigns every route the expected auth tier', async () => {
    expect(await collectAuthSurface()).toEqual(EXPECTED_AUTH_SURFACE);
  });

  it('leaves no route on a weaker tier than the default without an explicit opt-out', async () => {
    // Restated as an invariant rather than a list: a route may only skip the
    // identity signature if it says so in its own config. Anything registered
    // under the vault plugin without a flag falls under JWT + signature.
    const relaxed = (await collectAuthSurface()).filter((row) => row.includes('SKIP_SIG') || row.includes('SIG_ONLY'));

    expect(relaxed).toEqual(EXPECTED_AUTH_SURFACE.filter((row) => row.includes('SKIP_SIG') || row.includes('SIG_ONLY')));
  });
});
