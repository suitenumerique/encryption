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

describe('GET /api/maintenance-escrow/assignment', () => {
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

    return app.inject({ method: 'GET', url: `/api/maintenance-escrow/assignment?${query}` });
  };

  const fingerprintFor = async (query: string) => {
    const response = await get(query);

    expect(response.statusCode).toBe(200);

    return (JSON.parse(response.body) as { key_fingerprint: string | null }).key_fingerprint;
  };

  it("answers the fingerprint of the key covering the owner's email, null when none does", async () => {
    expect(await fingerprintFor('sub=kc-alice')).toBe(await computeMaintenanceKeyFingerprint(agriculture));
    expect(await fingerprintFor('sub=kc-bob')).toBeNull();
  });

  it('answers null for an owner the service has no account for, a retired-issuer sub included', async () => {
    expect(await fingerprintFor('sub=kc-nobody')).toBeNull();
    expect(await fingerprintFor('sub=kc-carol')).toBeNull();
  });

  it('resolves internal ids too, and follows the * entry for every other email', async () => {
    env.MAINTENANCE_ESCROW_KEYS = [
      { domains: ['agriculture.gouv.fr'], publicKey: agriculture },
      { domains: ['*'], publicKey: fallback },
    ];

    expect(await fingerprintFor(`user_id=${BOB}`)).toBe(await computeMaintenanceKeyFingerprint(fallback));
    expect(await fingerprintFor(`user_id=${CAROL}`)).toBe(await computeMaintenanceKeyFingerprint(agriculture));
  });

  it('assigns no key to anyone when the deployment configured none', async () => {
    env.MAINTENANCE_ESCROW_KEYS = undefined;

    expect(await fingerprintFor(`user_id=${ALICE}`)).toBeNull();
  });

  it('asks about exactly one owner', async () => {
    expect((await get('')).statusCode).toBe(400);
    expect((await get(`sub=kc-alice&user_id=${ALICE}`)).statusCode).toBe(400);
  });
});
