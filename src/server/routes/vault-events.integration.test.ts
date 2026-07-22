/**
 * Integration test for the server-push channel: a device opens the SSE stream
 * authenticated by its IDENTITY SIGNATURE ALONE (no JWT — tier 1), and a
 * `notifyVaultChanged` for that user delivers a `changed` wake to it within a few
 * ms. Uses a real listening server + Node `fetch` streaming (no new deps), and a
 * real in-process Postgres so the identity lookup behind the signature check is
 * the actual query.
 */
import Fastify, { type FastifyInstance } from 'fastify';
import type { AddressInfo } from 'node:net';

import { base64ToUint8, exportPublicKeyAsBase64 } from '@encryption/src/crypto/encryption-backup';
import { REQUEST_SIG_HEADER, signRequestProof } from '@encryption/src/crypto/request-proof';
import { generateSignatureKeyPair } from '@encryption/src/crypto/signature';
import { testPrisma, useTestDatabase } from '@encryption/src/prisma/testing';
import { vaultRoute } from '@encryption/src/server/routes/vault';
import { notifyVaultChanged } from '@encryption/src/server/vault-notify';

jest.mock('@encryption/src/prisma/client', () => ({ prisma: jest.requireActual('@encryption/src/prisma/testing').testPrisma }));

useTestDatabase();

let app: FastifyInstance;
let signer: Awaited<ReturnType<typeof generateSignatureKeyPair>>;
let userId: string;

beforeEach(async () => {
  signer = await generateSignatureKeyPair();

  // The SSE route (tier 1) verifies the request signature against the user's
  // ACTIVE identity, so seed exactly that: a user carrying the signer's wire
  // public key as its current identity.
  const user = await testPrisma.user.create({ data: { email: 'sse@example.org' } });

  userId = user.id;

  await testPrisma.identity.create({
    data: {
      userId,
      generation: 1,
      signaturePublicKey: Buffer.from(base64ToUint8(exportPublicKeyAsBase64(signer.publicKey))),
    },
  });
});

beforeAll(async () => {
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
    userId,
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
  notifyVaultChanged(userId, 7);

  // The deadline timer MUST be cleared once the wake arrives. Left pending it
  // outlives the suite, and jest then force-exits the worker with "a worker
  // process has failed to exit gracefully".
  let deadline: NodeJS.Timeout | undefined;

  try {
    await Promise.race([
      readUntilChanged,
      new Promise((_, reject) => {
        deadline = setTimeout(() => reject(new Error('no wake within 2s')), 2000);
      }),
    ]);
  } finally {
    clearTimeout(deadline);
  }

  expect(received).toContain('event: changed');
  expect(received).toContain('"revision":7');

  controller.abort();
});

it('rejects an SSE connection with no signature (401)', async () => {
  const { port } = app.server.address() as AddressInfo;
  const res = await fetch(`http://127.0.0.1:${port}/api/vault/events`);

  expect(res.status).toBe(401);
});
