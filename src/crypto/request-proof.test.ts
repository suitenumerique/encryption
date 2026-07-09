import { REQUEST_SIG_MAX_AGE_SECONDS, REQUEST_SIG_SKEW_SECONDS, signRequestProof, verifyRequestProof } from '@encryption/src/crypto/request-proof';
import { generateSignatureKeyPair } from '@encryption/src/crypto/signature';
import { CRYPTO_VERSION } from '@encryption/src/shared/constants';

const NOW = 1_700_000_000; // fixed epoch seconds for determinism

// The server stores identity public keys as version-prefixed wire blobs.
function wire(rawPublicKey: Uint8Array): Uint8Array {
  return new Uint8Array([CRYPTO_VERSION, ...rawPublicKey]);
}

async function makeIdentity() {
  const kp = await generateSignatureKeyPair();

  return { secret: kp.secretKey, wirePublic: wire(kp.publicKey) };
}

async function verify(token: string, over: { method: string; path: string; userId: string; keys: Uint8Array[]; nowSeconds?: number }) {
  return verifyRequestProof({
    token,
    method: over.method,
    path: over.path,
    userId: over.userId,
    acceptableIdentityWireKeys: over.keys,
    nowSeconds: over.nowSeconds ?? NOW,
  });
}

describe('request-proof', () => {
  it('verifies a well-formed proof against the matching request and key', async () => {
    const id = await makeIdentity();
    const token = await signRequestProof({
      method: 'GET',
      path: '/api/vault/items',
      userId: 'user-1',
      identitySecretKey: id.secret,
      nowSeconds: NOW,
    });

    await expect(verify(token, { method: 'GET', path: '/api/vault/items', userId: 'user-1', keys: [id.wirePublic] })).resolves.toBe(true);
  });

  it('rejects a proof reused on a different method or path', async () => {
    const id = await makeIdentity();
    const token = await signRequestProof({
      method: 'GET',
      path: '/api/vault/items',
      userId: 'user-1',
      identitySecretKey: id.secret,
      nowSeconds: NOW,
    });

    await expect(verify(token, { method: 'DELETE', path: '/api/vault/items', userId: 'user-1', keys: [id.wirePublic] })).resolves.toBe(false);
    await expect(verify(token, { method: 'GET', path: '/api/vault/keyring', userId: 'user-1', keys: [id.wirePublic] })).resolves.toBe(false);
  });

  it('binds the request body: a swapped payload invalidates the proof (POST/PUT)', async () => {
    // The proof covers a SHA-256 digest of the body (SigV4 / RFC 9421 style), so a
    // captured signature cannot be replayed against the same method+path with a
    // different payload.
    const id = await makeIdentity();
    const body = JSON.stringify({ wrapped_device_bootstrap: 'AAAA' });
    const token = await signRequestProof({
      method: 'POST',
      path: '/api/vault/approvals/r1/approve',
      userId: 'u',
      identitySecretKey: id.secret,
      nowSeconds: NOW,
      body,
    });

    // Same method+path+body → valid.
    await expect(
      verifyRequestProof({
        token,
        method: 'POST',
        path: '/api/vault/approvals/r1/approve',
        userId: 'u',
        body,
        acceptableIdentityWireKeys: [id.wirePublic],
        nowSeconds: NOW,
      })
    ).resolves.toBe(true);

    // Same signature, TAMPERED body → rejected.
    const hacked = JSON.stringify({ wrapped_device_bootstrap: 'EVIL' });
    await expect(
      verifyRequestProof({
        token,
        method: 'POST',
        path: '/api/vault/approvals/r1/approve',
        userId: 'u',
        body: hacked,
        acceptableIdentityWireKeys: [id.wirePublic],
        nowSeconds: NOW,
      })
    ).resolves.toBe(false);

    // A GET proof (bodyless) must not authorize the POST, and vice-versa.
    await expect(verify(token, { method: 'GET', path: '/api/vault/approvals/r1/approve', userId: 'u', keys: [id.wirePublic] })).resolves.toBe(false);
  });

  it('rejects a proof presented for a different user', async () => {
    const id = await makeIdentity();
    const token = await signRequestProof({
      method: 'GET',
      path: '/api/vault/items',
      userId: 'user-1',
      identitySecretKey: id.secret,
      nowSeconds: NOW,
    });

    await expect(verify(token, { method: 'GET', path: '/api/vault/items', userId: 'user-2', keys: [id.wirePublic] })).resolves.toBe(false);
  });

  it('ignores a query string on either side (only the path is covered)', async () => {
    const id = await makeIdentity();
    const token = await signRequestProof({
      method: 'GET',
      path: '/api/vault/items?foo=1',
      userId: 'u',
      identitySecretKey: id.secret,
      nowSeconds: NOW,
    });

    await expect(verify(token, { method: 'GET', path: '/api/vault/items?bar=2', userId: 'u', keys: [id.wirePublic] })).resolves.toBe(true);
  });

  it('rejects an expired proof and one issued too far in the future', async () => {
    const id = await makeIdentity();
    const token = await signRequestProof({ method: 'GET', path: '/api/vault/items', userId: 'u', identitySecretKey: id.secret, nowSeconds: NOW });

    // Past the validity window.
    await expect(
      verify(token, {
        method: 'GET',
        path: '/api/vault/items',
        userId: 'u',
        keys: [id.wirePublic],
        nowSeconds: NOW + REQUEST_SIG_MAX_AGE_SECONDS + 1,
      })
    ).resolves.toBe(false);
    // Clock skew: verifying well before it was issued.
    await expect(
      verify(token, { method: 'GET', path: '/api/vault/items', userId: 'u', keys: [id.wirePublic], nowSeconds: NOW - REQUEST_SIG_SKEW_SECONDS - 5 })
    ).resolves.toBe(false);
  });

  it('rejects a proof signed by a key the server does not accept', async () => {
    const signer = await makeIdentity();
    const other = await makeIdentity();
    const token = await signRequestProof({ method: 'GET', path: '/api/vault/items', userId: 'u', identitySecretKey: signer.secret, nowSeconds: NOW });

    await expect(verify(token, { method: 'GET', path: '/api/vault/items', userId: 'u', keys: [other.wirePublic] })).resolves.toBe(false);
    // ...but accepts it when the signer's key is anywhere in the acceptable set.
    await expect(verify(token, { method: 'GET', path: '/api/vault/items', userId: 'u', keys: [other.wirePublic, signer.wirePublic] })).resolves.toBe(
      true
    );
  });

  it('rejects a tampered token and malformed input', async () => {
    const id = await makeIdentity();
    const token = await signRequestProof({ method: 'GET', path: '/api/vault/items', userId: 'u', identitySecretKey: id.secret, nowSeconds: NOW });
    const [h, p] = token.split('.');
    const tampered = `${h}.${p}.AAAA`;

    await expect(verify(tampered, { method: 'GET', path: '/api/vault/items', userId: 'u', keys: [id.wirePublic] })).resolves.toBe(false);
    await expect(verify('not-a-jws', { method: 'GET', path: '/api/vault/items', userId: 'u', keys: [id.wirePublic] })).resolves.toBe(false);
  });
});
