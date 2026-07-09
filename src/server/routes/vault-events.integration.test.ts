/**
 * Integration test for the server-push channel: a device opens the SSE stream
 * authenticated by its IDENTITY SIGNATURE ALONE (no JWT — tier 1), and a
 * `notifyVaultChanged` for that user delivers a `changed` wake to it within a few
 * ms. Uses a real listening server + Node `fetch` streaming (no new deps); Prisma
 * is mocked exactly as the unit tests do.
 */
import Fastify, { type FastifyInstance } from 'fastify';
import type { AddressInfo } from 'node:net';

import { exportPublicKeyAsBase64, base64ToUint8 } from '@encryption/src/crypto/encryption-backup';
import { REQUEST_SIG_HEADER, signRequestProof } from '@encryption/src/crypto/request-proof';
import { generateSignatureKeyPair } from '@encryption/src/crypto/signature';
import { prisma } from '@encryption/src/prisma/client';
import { vaultRoute } from '@encryption/src/server/routes/vault';
import { notifyVaultChanged } from '@encryption/src/server/vault-notify';

jest.mock('@encryption/src/prisma/client', () => ({
  prisma: {
    identity: { findFirst: jest.fn(), findUnique: jest.fn() },
    vaultKeyring: { findFirst: jest.fn() },
    vaultMeta: { findUnique: jest.fn() },
    vaultItem: { findMany: jest.fn() },
    vaultChallenge: { deleteMany: jest.fn() },
  },
}));

const mp = prisma as unknown as Record<string, Record<string, jest.Mock>>;
const USER_ID = 'user-integration';

let app: FastifyInstance;
let signer: Awaited<ReturnType<typeof generateSignatureKeyPair>>;

beforeAll(async () => {
  signer = await generateSignatureKeyPair();

  // The SSE route (tier 1) verifies the request signature against the user's
  // active identity — return the signer's WIRE public key for it.
  mp.identity.findFirst.mockResolvedValue({
    signaturePublicKey: Buffer.from(base64ToUint8(exportPublicKeyAsBase64(signer.publicKey))),
  } as never);

  app = Fastify();
  app.decorate('verifyJWT', async () => {}); // unused on tier-1 routes, present so the decorator exists
  app.register(vaultRoute);
  await app.listen({ port: 0, host: '127.0.0.1' });
});

afterAll(async () => {
  await app.close();
});

it('delivers a "changed" wake to a signature-authenticated (no JWT) SSE connection', async () => {
  const { port } = app.server.address() as AddressInfo;
  const controller = new AbortController();

  const token = await signRequestProof({
    method: 'GET',
    path: '/api/vault/events',
    userId: USER_ID,
    identitySecretKey: signer.secretKey,
    nowSeconds: Math.floor(Date.now() / 1000),
  });

  const res = await fetch(`http://127.0.0.1:${port}/api/vault/events`, {
    headers: { [REQUEST_SIG_HEADER]: token }, // no Authorization / JWT
    signal: controller.signal,
  });

  expect(res.status).toBe(200);

  const reader = res.body!.getReader();
  const decoder = new TextDecoder();
  let received = '';

  const readUntilChanged = (async () => {
    while (!received.includes('event: changed')) {
      const { value, done } = await reader.read();
      if (done) break;
      received += decoder.decode(value, { stream: true });
    }
  })();

  // Let the connection register, then push a wake for this user.
  await new Promise((r) => setTimeout(r, 50));
  notifyVaultChanged(USER_ID, 7);

  await Promise.race([readUntilChanged, new Promise((_, reject) => setTimeout(() => reject(new Error('no wake within 2s')), 2000))]);

  expect(received).toContain('event: changed');
  expect(received).toContain('"revision":7');

  controller.abort();
});

it('rejects an SSE connection with no signature (401)', async () => {
  const { port } = app.server.address() as AddressInfo;
  const res = await fetch(`http://127.0.0.1:${port}/api/vault/events`);

  expect(res.status).toBe(401);
});
