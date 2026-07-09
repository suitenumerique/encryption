import {
  type SurfacedRecipient,
  allRecipientsTrusted,
  buildUserFingerprints,
  surfaceUntrustedRecipients,
} from '@encryption/src/ui/components/verify-recipients-logic';

describe('buildUserFingerprints', () => {
  it('keeps only binding-verified records', () => {
    const users = {
      alice: { identityFingerprint: 'aaa', verified: true },
      bob: { identityFingerprint: 'bbb', verified: false },
    };

    expect(buildUserFingerprints(['alice', 'bob'], users)).toEqual({ alice: 'aaa' });
  });

  it('ignores userIds absent from the directory', () => {
    expect(buildUserFingerprints(['ghost'], {})).toEqual({});
  });
});

describe('surfaceUntrustedRecipients', () => {
  it('surfaces only the blocking statuses (mismatch and refused)', () => {
    const surfaced = surfaceUntrustedRecipients([
      { userId: 'alice', providedFingerprint: 'aaa', status: 'trusted' },
      { userId: 'bob', providedFingerprint: 'bbb', status: 'unknown' },
      { userId: 'carol', providedFingerprint: 'ccc', status: 'refused' },
      { userId: 'dave', providedFingerprint: 'ddd', status: 'mismatch' },
    ]);

    expect(surfaced).toEqual([
      { userId: 'carol', fingerprint: 'ccc', trusted: false, status: 'refused' },
      { userId: 'dave', fingerprint: 'ddd', trusted: false, status: 'mismatch' },
    ]);
  });

  it('does not surface unknown (first contact) or trusted recipients', () => {
    expect(
      surfaceUntrustedRecipients([
        { userId: 'alice', providedFingerprint: 'aaa', status: 'trusted' },
        { userId: 'bob', providedFingerprint: 'bbb', status: 'unknown' },
      ])
    ).toEqual([]);
  });
});

describe('allRecipientsTrusted (all-or-nothing gate)', () => {
  const bob: SurfacedRecipient = { userId: 'bob', fingerprint: 'bbb', trusted: false, status: 'mismatch' };
  const carol: SurfacedRecipient = { userId: 'carol', fingerprint: 'ccc', trusted: false, status: 'refused' };

  it('is false while any surfaced recipient is untrusted', () => {
    expect(allRecipientsTrusted([bob, carol])).toBe(false);
    expect(allRecipientsTrusted([{ ...bob, trusted: true }, carol])).toBe(false);
  });

  it('is true only once every surfaced recipient is trusted', () => {
    expect(
      allRecipientsTrusted([
        { ...bob, trusted: true },
        { ...carol, trusted: true },
      ])
    ).toBe(true);
  });

  it('is true when there is nothing to verify', () => {
    expect(allRecipientsTrusted([])).toBe(true);
  });
});
