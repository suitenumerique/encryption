/**
 * @jest-environment jsdom
 */
import { RUNTIME_CONFIG_ELEMENT_ID } from '@encryption/src/shared/runtime-config';
import type { refreshTokenWithLock as RefreshTokenWithLock, TokenSet } from '@encryption/src/ui/auth/oidc-client';

// A JWT whose payload segment base64-decodes to the given claims (signature not verified).
function makeJwt(claims: Record<string, unknown>): string {
  return `header.${btoa(JSON.stringify(claims))}.sig`;
}

describe('refreshTokenWithLock', () => {
  let refreshTokenWithLock: typeof RefreshTokenWithLock;
  let fetchMock: jest.Mock;

  beforeAll(async () => {
    // The module reads the OIDC config off the runtime-config data block at load time,
    // so the document has to carry one before the import.
    const block = document.createElement('script');

    block.type = 'application/json';
    block.id = RUNTIME_CONFIG_ELEMENT_ID;
    // The schema validates a served block in full, so the fixture is a whole config
    // even though this suite only exercises the OIDC fields.
    block.textContent = JSON.stringify({
      oidcIssuer: 'https://keycloak.test/realms/test',
      oidcClientId: 'encryption',
      oidcRedirectUri: 'https://encryption.test/auth/callback',
      vaultUrl: 'https://data.encryption.test',
      apiBaseUrl: '',
      docsEnabled: true,
    });
    document.head.appendChild(block);

    ({ refreshTokenWithLock } = await import('@encryption/src/ui/auth/oidc-client'));
  });

  beforeEach(() => {
    fetchMock = jest.fn();
    (globalThis as unknown as { fetch: unknown }).fetch = fetchMock;

    // Web Locks: run the callback immediately (single-tab test).
    (navigator as unknown as { locks: unknown }).locks = {
      request: (_name: string, cb: () => Promise<unknown>) => cb(),
    };
  });

  const staleToken = (): TokenSet => ({
    accessToken: 'old-access',
    refreshToken: 'old-refresh',
    idToken: null,
    expiresAt: Date.now() - 1_000, // already expired
    sub: 'user-1',
  });

  it('persists the refreshed token INSIDE the lock, before resolving', async () => {
    const rotatedAccess = makeJwt({ sub: 'user-1' });

    fetchMock.mockResolvedValue({
      ok: true,
      json: async () => ({
        access_token: rotatedAccess,
        refresh_token: 'rotated-refresh',
        id_token: null,
        expires_in: 300,
      }),
    });

    const events: string[] = [];
    const persisted: TokenSet[] = [];
    const persistToken = (t: TokenSet) => {
      events.push('persist');
      persisted.push(t);
    };

    const readStoredToken = async () => null;

    const refreshed = await refreshTokenWithLock(staleToken(), readStoredToken, persistToken);
    events.push('resolved');

    // Persist happened, and it happened before the outer promise resolved
    // (i.e. still under the lock).
    expect(events).toEqual(['persist', 'resolved']);
    expect(persisted).toHaveLength(1);
    expect(persisted[0]).toEqual(refreshed);

    expect(refreshed.accessToken).toBe(rotatedAccess);
    expect(refreshed.refreshToken).toBe('rotated-refresh');
    expect(refreshed.sub).toBe('user-1');
  });

  it('returns the already-fresh stored token without refreshing or persisting', async () => {
    const fresh: TokenSet = {
      accessToken: 'fresh-access',
      refreshToken: 'fresh-refresh',
      idToken: null,
      expiresAt: Date.now() + 10 * 60 * 1000, // well within validity
      sub: 'user-1',
    };

    const persistToken = jest.fn();
    const readStoredToken = async () => fresh;

    const result = await refreshTokenWithLock(staleToken(), readStoredToken, persistToken);

    expect(result).toEqual(fresh);
    expect(persistToken).not.toHaveBeenCalled();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('uses the stored refresh token when a concurrent tab already rotated it', async () => {
    const rotatedAccess = makeJwt({ sub: 'user-1' });

    // Stored token is present but still expired, carrying a newer refresh token.
    const storedExpired: TokenSet = {
      accessToken: 'stored-access',
      refreshToken: 'stored-refresh',
      idToken: null,
      expiresAt: Date.now() - 1_000,
      sub: 'user-1',
    };

    fetchMock.mockResolvedValue({
      ok: true,
      json: async () => ({
        access_token: rotatedAccess,
        refresh_token: 'newest-refresh',
        id_token: null,
        expires_in: 300,
      }),
    });

    const persistToken = jest.fn();
    const readStoredToken = async () => storedExpired;

    await refreshTokenWithLock(staleToken(), readStoredToken, persistToken);

    const body = (fetchMock.mock.calls[0][1] as { body: URLSearchParams }).body;
    expect(body.get('refresh_token')).toBe('stored-refresh');
    expect(persistToken).toHaveBeenCalledTimes(1);
  });

  // The caller evicts the stored session on InvalidGrantError only, so the two
  // failure shapes must stay distinguishable: a dead token has to log the user
  // out, an IdP hiccup must not.
  it('reports a definitively rejected refresh token as InvalidGrantError', async () => {
    fetchMock.mockResolvedValue({ ok: false, status: 400, json: async () => ({ error: 'invalid_grant' }) });

    await expect(refreshTokenWithLock(staleToken(), async () => null, jest.fn())).rejects.toMatchObject({ name: 'InvalidGrantError' });
  });

  it('does NOT report a transient failure as InvalidGrantError', async () => {
    fetchMock.mockResolvedValue({ ok: false, status: 503, json: async () => ({}) });

    await expect(refreshTokenWithLock(staleToken(), async () => null, jest.fn())).rejects.not.toMatchObject({ name: 'InvalidGrantError' });

    fetchMock.mockRejectedValue(new TypeError('Failed to fetch'));

    await expect(refreshTokenWithLock(staleToken(), async () => null, jest.fn())).rejects.not.toMatchObject({ name: 'InvalidGrantError' });
  });
});
