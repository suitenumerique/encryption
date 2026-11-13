import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { computeMaintenanceKeyFingerprint, exportPublicKeyAsBase64, generateUserKeyPair } from '@encryption/src/crypto';
import { VaultErrorCode } from '@encryption/src/shared/vault-error';

const config: { maintenanceEscrowPublicKeys?: string[] } = {};

vi.mock('@encryption/src/vault/runtime-config', () => ({ runtimeConfig: config }));

const OWNER_ID = '11111111-1111-4111-8111-111111111111';

function answer(fingerprint: string | null) {
  const fetchMock = vi.fn(async () => new Response(JSON.stringify({ key_fingerprint: fingerprint }), { status: 200 }));

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
    vi.useRealTimers();
  });

  const load = async () => import('@encryption/src/vault/operations/maintenance-escrow');

  it('asks nothing and escrows nothing when the deployment configured no key', async () => {
    delete config.maintenanceEscrowPublicKeys;
    const fetchMock = answer(null);

    expect(await (await load()).resolveMaintenanceKey({ userId: OWNER_ID })).toBeNull();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("wraps for the configured key whose fingerprint the server assigns to the owner, named by sub or by the vault's own id", async () => {
    const { resolveMaintenanceKey } = await load();
    const fetchMock = answer(await computeMaintenanceKeyFingerprint(interieur));

    const key = await resolveMaintenanceKey({ sub: 'kc-owner' });

    expect(exportPublicKeyAsBase64(key!.publicKey)).toBe(interieur);
    expect(fetchMock).toHaveBeenCalledWith('/api/maintenance-escrow/assignment?sub=kc-owner');

    const ownFetch = answer(await computeMaintenanceKeyFingerprint(agriculture));

    expect(exportPublicKeyAsBase64((await resolveMaintenanceKey({ userId: OWNER_ID }))!.publicKey)).toBe(agriculture);
    expect(ownFetch).toHaveBeenCalledWith(`/api/maintenance-escrow/assignment?user_id=${OWNER_ID}`);
  });

  it('makes no copy, without failing the share, for an owner no configured key covers or the service does not know', async () => {
    answer(null);

    expect(await (await load()).resolveMaintenanceKey({ userId: OWNER_ID })).toBeNull();
  });

  it('refuses a fingerprint outside its runtime config: the server picks among the keys, it never adds one', async () => {
    const stranger = exportPublicKeyAsBase64((await generateUserKeyPair()).publicKey);

    answer(await computeMaintenanceKeyFingerprint(stranger));

    await expect((await load()).resolveMaintenanceKey({ userId: OWNER_ID })).rejects.toMatchObject({ code: VaultErrorCode.INVALID_MAINTENANCE_KEY });
  });

  it('asks once per owner for a while, again once the answer is stale, and never keeps a failure', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });

    const { resolveMaintenanceKey } = await load();
    const fetchMock = answer(await computeMaintenanceKeyFingerprint(agriculture));

    await resolveMaintenanceKey({ userId: OWNER_ID });
    await resolveMaintenanceKey({ userId: OWNER_ID });
    await resolveMaintenanceKey({ sub: 'kc-owner' });
    expect(fetchMock).toHaveBeenCalledTimes(2);

    vi.advanceTimersByTime(5 * 60_000 + 1);
    await resolveMaintenanceKey({ userId: OWNER_ID });
    expect(fetchMock).toHaveBeenCalledTimes(3);

    const failing = vi.fn(async () => new Response('', { status: 503 }));

    vi.stubGlobal('fetch', failing);
    await expect(resolveMaintenanceKey({ sub: 'kc-other' })).rejects.toThrow(/503/);
    await expect(resolveMaintenanceKey({ sub: 'kc-other' })).rejects.toThrow(/503/);
    expect(failing).toHaveBeenCalledTimes(2);
  });

  it('fails every wrap rather than silently escrowing nothing when a served key is malformed', async () => {
    config.maintenanceEscrowPublicKeys = ['AAAA'];

    await expect((await load()).getMaintenanceKeys()).rejects.toMatchObject({ code: VaultErrorCode.INVALID_MAINTENANCE_KEY });
  });
});
