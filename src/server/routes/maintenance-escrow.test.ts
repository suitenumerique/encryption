import Fastify from 'fastify';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { exportPublicKeyAsBase64, generateUserKeyPair } from '@encryption/src/crypto';
import { computeMaintenanceKeyFingerprint } from '@encryption/src/crypto/maintenance-escrow';
import { testPrisma, useTestDatabase } from '@encryption/src/prisma/testing';
import { maintenanceEscrowRoute } from '@encryption/src/server/routes/maintenance-escrow';

const env = vi.hoisted(() => ({ OIDC_ISSUER: 'https://issuer.example', MAINTENANCE_ESCROW_KEYS: undefined as unknown }));

vi.mock('@encryption/src/server/env', () => ({ env }));
vi.mock('@encryption/src/prisma/client', async () => ({
  prisma: (await vi.importActual<typeof import('@encryption/src/prisma/testing')>('@encryption/src/prisma/testing')).testPrisma,
}));

const ALICE = '11111111-1111-4111-8111-111111111111';
const BOB = '22222222-2222-4222-8222-222222222222';
const CAROL = '33333333-3333-4333-8333-333333333333';

describe('GET /api/maintenance-escrow/assignments', () => {
  useTestDatabase();

  let agriculture: string;
  let fallback: string;

  beforeEach(async () => {
    agriculture = exportPublicKeyAsBase64((await generateUserKeyPair()).publicKey);
    fallback = exportPublicKeyAsBase64((await generateUserKeyPair()).publicKey);
    env.MAINTENANCE_ESCROW_KEYS = [{ domains: ['agriculture.gouv.fr'], publicKey: agriculture }];

    await testPrisma.user.createMany({
      data: [
        { id: ALICE, email: 'alice@monequipe.agriculture.gouv.fr' },
        { id: BOB, email: 'bob@interieur.gouv.fr' },
        { id: CAROL, email: 'carol@agriculture.gouv.fr' },
      ],
    });
    await testPrisma.oidcAccount.createMany({
      data: [
        { userId: ALICE, issuer: 'https://issuer.example', subject: 'kc-alice' },
        { userId: BOB, issuer: 'https://issuer.example', subject: 'kc-bob' },
        // A retired issuer's sub never resolves, as in the directory.
        { userId: CAROL, issuer: 'https://old-issuer.example', subject: 'kc-carol' },
      ],
    });
  });

  const get = async (query: string) => {
    const app = Fastify();

    app.register(maintenanceEscrowRoute);

    const response = await app.inject({ method: 'GET', url: `/api/maintenance-escrow/assignments?${query}` });

    expect(response.statusCode).toBe(200);

    return (JSON.parse(response.body) as { assignments: unknown[] }).assignments;
  };

  it("answers the fingerprint of the key covering each owner's email, null when none does", async () => {
    expect(await get('subs=kc-alice&subs=kc-bob&subs=kc-carol&subs=kc-nobody')).toEqual([
      { user_id: ALICE, sub: 'kc-alice', key_fingerprint: await computeMaintenanceKeyFingerprint(agriculture) },
      { user_id: BOB, sub: 'kc-bob', key_fingerprint: null },
    ]);
  });

  it('resolves internal ids too, and follows the * entry for every other email', async () => {
    env.MAINTENANCE_ESCROW_KEYS = [
      { domains: ['agriculture.gouv.fr'], publicKey: agriculture },
      { domains: ['*'], publicKey: fallback },
    ];

    expect(await get(`user_ids=${BOB}&user_ids=${CAROL}`)).toEqual([
      { user_id: BOB, key_fingerprint: await computeMaintenanceKeyFingerprint(fallback) },
      { user_id: CAROL, key_fingerprint: await computeMaintenanceKeyFingerprint(agriculture) },
    ]);
  });

  it('assigns no key to anyone when the deployment configured none', async () => {
    env.MAINTENANCE_ESCROW_KEYS = undefined;

    expect(await get(`user_ids=${ALICE}`)).toEqual([{ user_id: ALICE, key_fingerprint: null }]);
  });
});
