import { beforeEach, describe, expect, it, vi } from 'vitest';

import { exportPublicKeyAsBase64, generateUserKeyPair } from '@encryption/src/crypto';
import { VaultErrorCode } from '@encryption/src/shared/vault-error';

const config: { maintenanceEscrowPublicKey?: string } = {};

vi.mock('@encryption/src/vault/runtime-config', () => ({ runtimeConfig: config }));

describe('getMaintenancePublicKey', () => {
  beforeEach(() => {
    vi.resetModules();
    delete config.maintenanceEscrowPublicKey;
  });

  it('is null when the deployment configured no escrow key', async () => {
    const { getMaintenancePublicKey } = await import('@encryption/src/vault/operations/maintenance-escrow');

    expect(getMaintenancePublicKey()).toBeNull();
  });

  it('parses the configured key once and hands back the raw X-Wing key', async () => {
    const pair = await generateUserKeyPair();
    config.maintenanceEscrowPublicKey = exportPublicKeyAsBase64(pair.publicKey);

    const { getMaintenancePublicKey } = await import('@encryption/src/vault/operations/maintenance-escrow');

    expect(getMaintenancePublicKey()).toEqual(pair.publicKey);
    expect(getMaintenancePublicKey()).toBe(getMaintenancePublicKey());
  });

  it('fails every wrap rather than silently escrowing nothing when the served key is malformed', async () => {
    config.maintenanceEscrowPublicKey = 'AAAA';

    const { getMaintenancePublicKey } = await import('@encryption/src/vault/operations/maintenance-escrow');

    expect(() => getMaintenancePublicKey()).toThrow(expect.objectContaining({ code: VaultErrorCode.INVALID_MAINTENANCE_KEY }));
  });
});
