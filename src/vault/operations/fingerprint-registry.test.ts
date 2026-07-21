/**
 * Tests for the sub-boundary wrappers of the TOFU registry: resolution of
 * caller subs to the internal ids the trust store keys on, and the mapping of
 * verdicts back to the caller's id space.
 */
import { type VaultState, emptyVaultState, setTofu } from '@encryption/src/crypto/vault-state';
import { VaultErrorCode } from '@encryption/src/shared/vault-error';
import { handleFetchPublicKeys } from '@encryption/src/vault/operations/fetch-public-keys';
import {
  handleAcceptFingerprintBySub,
  handleCheckFingerprintsBySubs,
  handleRefuseFingerprintBySub,
} from '@encryption/src/vault/operations/fingerprint-registry';
import { handleSync } from '@encryption/src/vault/operations/vault-sync-run';
import { loadVault, mutateVault } from '@encryption/src/vault/vault-keys';

jest.mock('@encryption/src/vault/operations/fetch-public-keys', () => ({
  handleFetchPublicKeys: jest.fn(),
  fetchContinuityChain: jest.fn().mockResolvedValue([]),
}));
jest.mock('@encryption/src/vault/vault-keys', () => ({
  loadVault: jest.fn(),
  mutateVault: jest.fn(),
}));
jest.mock('@encryption/src/vault/operations/vault-sync-run', () => ({
  handleSync: jest.fn(),
}));

const mockFetchKeys = handleFetchPublicKeys as jest.Mock;
const mockLoadVault = loadVault as jest.Mock;
const mockMutateVault = mutateVault as jest.Mock;
const mockSync = handleSync as jest.Mock;

const OWNER = 'internal-alice';

// A directory entry as handleFetchPublicKeys returns it: map keyed by the
// queried sub, internal id carried as a field.
function entry(internalId: string, fingerprint: string) {
  return {
    userId: internalId,
    signaturePublicKey: new ArrayBuffer(0),
    identityFingerprint: fingerprint,
    version: 1,
    verified: true,
    encryptionPublicKey: new ArrayBuffer(0),
  };
}

function stateWithTofu(entries: Record<string, { fingerprint: string; status: 'trusted' | 'refused' | 'unknown' }>): VaultState {
  return Object.entries(entries).reduce((state, [remoteUserId, e]) => setTofu(state, remoteUserId, e.fingerprint, e.status, 1), emptyVaultState());
}

beforeEach(() => {
  jest.clearAllMocks();
  mockLoadVault.mockResolvedValue({ state: emptyVaultState() });
  mockMutateVault.mockResolvedValue(emptyVaultState());
});

describe('handleCheckFingerprintsBySubs', () => {
  it('checks trust under the INTERNAL id and answers under the queried sub', async () => {
    mockFetchKeys.mockResolvedValue({ users: { 'sub-bob': entry('internal-bob', 'fp-bob') } });
    mockLoadVault.mockResolvedValue({ state: stateWithTofu({ 'internal-bob': { fingerprint: 'fp-bob', status: 'trusted' } }) });

    const { results } = await handleCheckFingerprintsBySubs(OWNER, { userFingerprints: { 'sub-bob': 'fp-bob' } });

    expect(results).toEqual([{ userId: 'sub-bob', knownFingerprint: 'fp-bob', providedFingerprint: 'fp-bob', status: 'trusted' }]);
  });

  it('answers EVERY queried sub when two subs resolve to the same internal user (email-linked credentials)', async () => {
    mockFetchKeys.mockResolvedValue({
      users: { 'sub-old': entry('internal-bob', 'fp-bob'), 'sub-new': entry('internal-bob', 'fp-bob') },
    });
    mockLoadVault.mockResolvedValue({ state: stateWithTofu({ 'internal-bob': { fingerprint: 'fp-bob', status: 'trusted' } }) });

    const { results } = await handleCheckFingerprintsBySubs(OWNER, { userFingerprints: { 'sub-old': 'fp-bob', 'sub-new': 'fp-bob' } });

    expect(results).toHaveLength(2);
    expect(results.map((r) => [r.userId, r.status])).toEqual([
      ['sub-old', 'trusted'],
      ['sub-new', 'trusted'],
    ]);
  });

  it("reads an unresolvable sub as 'unknown' with no recorded fingerprint", async () => {
    mockFetchKeys.mockResolvedValue({ users: {} });

    const { results } = await handleCheckFingerprintsBySubs(OWNER, { userFingerprints: { 'sub-ghost': 'fp-ghost' } });

    expect(results).toEqual([{ userId: 'sub-ghost', knownFingerprint: null, providedFingerprint: 'fp-ghost', status: 'unknown' }]);
    // Nothing to check internally, so the vault is never even loaded for it.
    expect(mockMutateVault).not.toHaveBeenCalled();
  });

  it('skips the directory fetch entirely for an empty payload', async () => {
    const { results } = await handleCheckFingerprintsBySubs(OWNER, { userFingerprints: {} });

    expect(results).toEqual([]);
    expect(mockFetchKeys).not.toHaveBeenCalled();
  });
});

describe('handleAcceptFingerprintBySub / handleRefuseFingerprintBySub', () => {
  it('records the decision under the resolved INTERNAL id (write-through sync)', async () => {
    mockFetchKeys.mockResolvedValue({ users: { 'sub-bob': entry('internal-bob', 'fp-bob') } });
    mockSync.mockResolvedValue({ status: 'ok' });

    await handleAcceptFingerprintBySub(OWNER, { sub: 'sub-bob', fingerprint: 'fp-bob' });

    expect(mockSync).toHaveBeenCalledTimes(1);
    const [syncUser, { mutate }] = mockSync.mock.calls[0];
    expect(syncUser).toBe(OWNER);

    // The mutation pins the fingerprint under the internal id, never the sub.
    const mutated = mutate(emptyVaultState());
    expect(mutated.tofu['internal-bob']).toMatchObject({ fingerprint: 'fp-bob', status: 'trusted' });
    expect(mutated.tofu['sub-bob']).toBeUndefined();
  });

  it('refuses under the internal id too', async () => {
    mockFetchKeys.mockResolvedValue({ users: { 'sub-eve': entry('internal-eve', 'fp-eve') } });
    mockSync.mockResolvedValue({ status: 'ok' });

    await handleRefuseFingerprintBySub(OWNER, { sub: 'sub-eve', fingerprint: 'fp-eve' });

    const [, { mutate }] = mockSync.mock.calls[0];
    expect(mutate(emptyVaultState()).tofu['internal-eve']).toMatchObject({ fingerprint: 'fp-eve', status: 'refused' });
  });

  it('throws UNRESOLVED_USER for a sub with no directory record, before any write', async () => {
    mockFetchKeys.mockResolvedValue({ users: {} });

    await expect(handleAcceptFingerprintBySub(OWNER, { sub: 'sub-ghost', fingerprint: 'fp' })).rejects.toMatchObject({
      code: VaultErrorCode.UNRESOLVED_USER,
    });
    expect(mockSync).not.toHaveBeenCalled();
  });
});
