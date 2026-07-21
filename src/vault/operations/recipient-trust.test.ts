import { VaultErrorCode } from '@encryption/src/shared/vault-error';
import { handleFetchPublicKeys } from '@encryption/src/vault/operations/fetch-public-keys';
import { handleCheckFingerprints } from '@encryption/src/vault/operations/fingerprint-registry';
import { resolveTrustedRecipientKeys } from '@encryption/src/vault/operations/recipient-trust';

jest.mock('@encryption/src/vault/operations/fetch-public-keys', () => ({
  handleFetchPublicKeys: jest.fn(),
}));
jest.mock('@encryption/src/vault/operations/fingerprint-registry', () => ({
  handleCheckFingerprints: jest.fn(),
}));

const mockFetch = handleFetchPublicKeys as jest.Mock;
const mockCheck = handleCheckFingerprints as jest.Mock;

const buf = (s: string) => new TextEncoder().encode(s).buffer as ArrayBuffer;

// A directory entry as the vault's binding-verifying fetch would return it:
// keyed by the queried SUB in the map, carrying the INTERNAL id (the TOFU key
// space) as a field. Tests derive internal ids as `internal-<sub>`.
function entry(sub: string, opts: { verified: boolean; key: ArrayBuffer | null; fingerprint: string }) {
  return { userId: `internal-${sub}`, verified: opts.verified, encryptionPublicKey: opts.key, identityFingerprint: opts.fingerprint };
}

// TOFU verdict per user (keyed by INTERNAL id), as handleCheckFingerprints
// returns it. The `map` argument is sub-keyed for test readability.
function checks(map: Record<string, 'trusted' | 'refused' | 'unknown' | 'mismatch'>) {
  return {
    results: Object.entries(map).map(([sub, status]) => ({ userId: `internal-${sub}`, status, knownFingerprint: null, providedFingerprint: '' })),
  };
}

describe('resolveTrustedRecipientKeys (wrap-time trust gate)', () => {
  beforeEach(() => jest.clearAllMocks());

  it('returns the encryption key for a verified, TOFU-trusted recipient', async () => {
    mockFetch.mockResolvedValue({ users: { bob: entry('bob', { verified: true, key: buf('bobkey'), fingerprint: 'fp-bob' }) } });
    mockCheck.mockResolvedValue(checks({ bob: 'trusted' }));

    const res = await resolveTrustedRecipientKeys('alice', ['bob']);

    expect(new Uint8Array(res.bob)).toEqual(new Uint8Array(buf('bobkey')));
  });

  it('refuses a recipient that TOFU refused', async () => {
    mockFetch.mockResolvedValue({ users: { bob: entry('bob', { verified: true, key: buf('bobkey'), fingerprint: 'fp-bob' }) } });
    mockCheck.mockResolvedValue(checks({ bob: 'refused' }));

    await expect(resolveTrustedRecipientKeys('alice', ['bob'])).rejects.toMatchObject({ code: VaultErrorCode.UNTRUSTED_RECIPIENT });
  });

  it("refuses when TOFU says 'mismatch' — a recorded fingerprint that has CHANGED (MITM key swap or unverified rotation)", async () => {
    mockFetch.mockResolvedValue({ users: { bob: entry('bob', { verified: true, key: buf('evilkey'), fingerprint: 'fp-EVIL' }) } });
    mockCheck.mockResolvedValue(checks({ bob: 'mismatch' }));

    await expect(resolveTrustedRecipientKeys('alice', ['bob'])).rejects.toMatchObject({ code: VaultErrorCode.UNTRUSTED_RECIPIENT });
  });

  it("wraps for an 'unknown' recipient (seen, not yet verified): sharing to an unverified contact is allowed", async () => {
    mockFetch.mockResolvedValue({ users: { bob: entry('bob', { verified: true, key: buf('bobkey'), fingerprint: 'fp-bob' }) } });
    mockCheck.mockResolvedValue(checks({ bob: 'unknown' }));

    const res = await resolveTrustedRecipientKeys('alice', ['bob']);

    expect(res.bob).toBeDefined();
  });

  it('refuses when the binding did not verify (encryption key withheld as null)', async () => {
    mockFetch.mockResolvedValue({ users: { bob: entry('bob', { verified: false, key: null, fingerprint: 'fp-bob' }) } });
    // A withheld key is not even offered to TOFU, so no verdict comes back for it.
    mockCheck.mockResolvedValue(checks({}));

    await expect(resolveTrustedRecipientKeys('alice', ['bob'])).rejects.toMatchObject({ code: VaultErrorCode.UNTRUSTED_RECIPIENT });
  });

  it('wraps for an explicitly-trusted recipient, checking TOFU by INTERNAL id', async () => {
    mockFetch.mockResolvedValue({ users: { bob: entry('bob', { verified: true, key: buf('bobkey'), fingerprint: 'fp-bob' }) } });
    // Trust is only ever 'trusted' after an explicit user decision (there is no
    // trust-on-first-use); the gate then wraps.
    mockCheck.mockResolvedValue(checks({ bob: 'trusted' }));

    const res = await resolveTrustedRecipientKeys('alice', ['bob']);

    expect(res.bob).toBeDefined();
    // TOFU is keyed by the record's INTERNAL id (never the sub), so trust
    // survives an OIDC provider migration. record: true because an actual
    // share records first-sight recipients.
    expect(mockCheck).toHaveBeenCalledWith('alice', { userFingerprints: { 'internal-bob': 'fp-bob' } }, { record: true });
  });

  it('rejects the whole set if any single recipient is untrusted (all-or-nothing)', async () => {
    mockFetch.mockResolvedValue({
      users: {
        bob: entry('bob', { verified: true, key: buf('bobkey'), fingerprint: 'fp-bob' }),
        eve: entry('eve', { verified: true, key: buf('evekey'), fingerprint: 'fp-eve' }),
      },
    });
    mockCheck.mockResolvedValue(checks({ bob: 'trusted', eve: 'mismatch' }));

    await expect(resolveTrustedRecipientKeys('alice', ['bob', 'eve'])).rejects.toMatchObject({ code: VaultErrorCode.UNTRUSTED_RECIPIENT });
  });

  it('batches: one directory fetch for many recipients', async () => {
    mockFetch.mockResolvedValue({
      users: {
        bob: entry('bob', { verified: true, key: buf('bobkey'), fingerprint: 'fp-bob' }),
        carol: entry('carol', { verified: true, key: buf('carolkey'), fingerprint: 'fp-carol' }),
      },
    });
    mockCheck.mockResolvedValue(checks({ bob: 'trusted', carol: 'trusted' }));

    await resolveTrustedRecipientKeys('alice', ['bob', 'carol']);

    expect(mockFetch).toHaveBeenCalledTimes(1);
    expect(mockFetch).toHaveBeenCalledWith('alice', { subs: ['bob', 'carol'] });
  });
});
