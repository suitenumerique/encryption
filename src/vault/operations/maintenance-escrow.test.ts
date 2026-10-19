import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { computeMaintenanceKeyFingerprint, exportPublicKeyAsBase64, generateUserKeyPair } from '@encryption/src/crypto';
import { VaultErrorCode } from '@encryption/src/shared/vault-error';

const config: { maintenanceEscrowPublicKeys?: string[] } = {};

vi.mock('@encryption/src/vault/runtime-config', () => ({ runtimeConfig: config }));

const OWNER_ID = '11111111-1111-4111-8111-111111111111';

function answer(assignments: unknown[]) {
  const fetchMock = vi.fn(async () => new Response(JSON.stringify({ assignments }), { status: 200 }));

  vi.stubGlobal('fetch', fetchMock);

  return fetchMock;
}

describe('resolveMaintenanceKey', () => {
  let agriculture: string;
  let interieur: string;

  beforeEach(async () => {
    vi.resetModules();
    agriculture = exportPublicKeyAsBase64((await generateUserKeyPair()).publicKey);
    interieur = exportPublicKeyAsBase64((await generateUserKeyPair()).publicKey);
    config.maintenanceEscrowPublicKeys = [agriculture, interieur];
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  const load = async () => import('@encryption/src/vault/operations/maintenance-escrow');

  it('asks nothing and escrows nothing when the deployment configured no key', async () => {
    delete config.maintenanceEscrowPublicKeys;
    const fetchMock = answer([]);

    expect(await (await load()).resolveMaintenanceKey({ userId: OWNER_ID })).toBeNull();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("wraps for the configured key whose fingerprint the server assigns to the owner, named by sub or by the vault's own id", async () => {
    const { resolveMaintenanceKey } = await load();
    const fetchMock = answer([{ user_id: OWNER_ID, sub: 'kc-owner', key_fingerprint: await computeMaintenanceKeyFingerprint(interieur) }]);

    const key = await resolveMaintenanceKey({ sub: 'kc-owner' });

    expect(exportPublicKeyAsBase64(key!.publicKey)).toBe(interieur);
    expect(fetchMock).toHaveBeenCalledWith('/api/maintenance-escrow/assignments?subs=kc-owner');

    answer([{ user_id: OWNER_ID, key_fingerprint: await computeMaintenanceKeyFingerprint(agriculture) }]);

    expect(exportPublicKeyAsBase64((await resolveMaintenanceKey({ userId: OWNER_ID }))!.publicKey)).toBe(agriculture);
  });

  it('makes no copy for an owner no configured key covers', async () => {
    answer([{ user_id: OWNER_ID, key_fingerprint: null }]);

    expect(await (await load()).resolveMaintenanceKey({ userId: OWNER_ID })).toBeNull();
  });

  it('refuses a fingerprint outside its runtime config: the server picks among the keys, it never adds one', async () => {
    const stranger = exportPublicKeyAsBase64((await generateUserKeyPair()).publicKey);

    answer([{ user_id: OWNER_ID, key_fingerprint: await computeMaintenanceKeyFingerprint(stranger) }]);

    await expect((await load()).resolveMaintenanceKey({ userId: OWNER_ID })).rejects.toMatchObject({ code: VaultErrorCode.INVALID_MAINTENANCE_KEY });
  });

  it('makes no copy, without failing the share, for an owner the service has no account for', async () => {
    answer([]);

    expect(await (await load()).resolveMaintenanceKey({ sub: 'kc-nobody' })).toBeNull();
  });

  it('fails every wrap rather than silently escrowing nothing when a served key is malformed', async () => {
    config.maintenanceEscrowPublicKeys = ['AAAA'];

    await expect((await load()).getMaintenanceKeys()).rejects.toMatchObject({ code: VaultErrorCode.INVALID_MAINTENANCE_KEY });
  });
});
