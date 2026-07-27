import type { EmergencyDesignateBody } from '@encryption/src/shared/schemas/emergency-access';
import {
  MAX_WAIT_DAYS,
  MIN_WAIT_DAYS,
  UntrustedRearmError,
  countdownTo,
  emergencyPhase,
  grantedRearmRows,
  parseWaitDays,
  rearmBodyFromDesignation,
} from '@encryption/src/ui/components/emergency-access-logic';

describe('parseWaitDays', () => {
  it('accepts whole numbers within the server bounds', () => {
    expect(parseWaitDays('7')).toBe(7);
    expect(parseWaitDays(' 45 ')).toBe(45);
    expect(parseWaitDays(String(MIN_WAIT_DAYS))).toBe(MIN_WAIT_DAYS);
    expect(parseWaitDays(String(MAX_WAIT_DAYS))).toBe(MAX_WAIT_DAYS);
  });

  it('rejects out-of-range, fractional, and non-numeric input', () => {
    expect(parseWaitDays('0')).toBeNull();
    expect(parseWaitDays('91')).toBeNull();
    expect(parseWaitDays('7.5')).toBeNull();
    expect(parseWaitDays('-3')).toBeNull();
    expect(parseWaitDays('')).toBeNull();
    expect(parseWaitDays('abc')).toBeNull();
  });
});

describe('emergencyPhase', () => {
  const now = 1_000_000;

  it('passes invited and confirmed through', () => {
    expect(emergencyPhase({ status: 'invited', deadline_millis: null }, now)).toBe('invited');
    expect(emergencyPhase({ status: 'confirmed', deadline_millis: null }, now)).toBe('confirmed');
  });

  it('keeps a running request as requested until its deadline', () => {
    expect(emergencyPhase({ status: 'recoveryRequested', deadline_millis: now + 1 }, now)).toBe('requested');
  });

  it('reads an elapsed deadline as approved even if the stored status has not moved', () => {
    expect(emergencyPhase({ status: 'recoveryRequested', deadline_millis: now }, now)).toBe('approved');
    expect(emergencyPhase({ status: 'recoveryRequested', deadline_millis: now - 1 }, now)).toBe('approved');
  });

  it('treats a request with no deadline as still requested', () => {
    expect(emergencyPhase({ status: 'recoveryRequested', deadline_millis: null }, now)).toBe('requested');
  });

  it('reads recoveryApproved as approved regardless of deadline', () => {
    expect(emergencyPhase({ status: 'recoveryApproved', deadline_millis: null }, now)).toBe('approved');
  });
});

describe('grantedRearmRows', () => {
  const now = 1_000_000;
  const base = { grantee_user_id: 'u1', grantee_email: 'contact@example.org', wait_time_days: 15 };

  it('selects approved rows and elapsed requests, mapping to re-arm inputs', () => {
    const rows = grantedRearmRows(
      [
        { ...base, id: 'a', status: 'recoveryApproved', deadline_millis: null },
        { ...base, id: 'b', status: 'recoveryRequested', deadline_millis: now - 1 },
        { ...base, id: 'c', status: 'recoveryRequested', deadline_millis: now + 1 },
        { ...base, id: 'd', status: 'confirmed', deadline_millis: null },
        { ...base, id: 'e', status: 'invited', deadline_millis: null },
      ],
      now
    );

    expect(rows).toEqual([
      { emergencyAccessId: 'a', granteeUserId: 'u1', granteeEmail: 'contact@example.org', waitTimeDays: 15 },
      { emergencyAccessId: 'b', granteeUserId: 'u1', granteeEmail: 'contact@example.org', waitTimeDays: 15 },
    ]);
  });

  it('never includes rows bound to a previous (disabled) vault', () => {
    const rows = grantedRearmRows([{ ...base, id: 'a', status: 'recoveryApproved', deadline_millis: null, vault_active: false }], now);

    expect(rows).toEqual([]);
  });
});

describe('rearmBodyFromDesignation', () => {
  it('strips exactly the two relationship fields and preserves the rest (order included)', () => {
    const designation = {
      grantee_user_id: 'grantee-uuid',
      wait_time_days: 30,
      credential: { wrapped_vrk: 'vrk', auth_public_key: 'apk', auth_pub_sig: 'sig', kdf_ops: 3, kdf_mem: 64, lang: 'french' },
      grantee_identity_public_key: 'identity-b64',
      grantee_key_version: 2,
      wrapped_phrase_for_grantee: 'capsule-b64',
      escrow_signature: 'escrow-sig-b64',
      escrow_created_at_millis: 1234,
    } as unknown as EmergencyDesignateBody;

    const rearm = rearmBodyFromDesignation(designation);

    expect(rearm).not.toHaveProperty('grantee_user_id');
    expect(rearm).not.toHaveProperty('wait_time_days');
    expect(Object.keys(rearm)).toEqual([
      'credential',
      'grantee_identity_public_key',
      'grantee_key_version',
      'wrapped_phrase_for_grantee',
      'escrow_signature',
      'escrow_created_at_millis',
    ]);
    expect(rearm.credential).toBe(designation.credential);
  });
});

describe('countdownTo', () => {
  it('floors the remaining time into days, hours and minutes', () => {
    const now = 0;
    const deadline = (2 * 24 * 60 + 3 * 60 + 4) * 60_000 + 30_000; // 2d 3h 4min 30s

    expect(countdownTo(deadline, now)).toEqual({ expired: false, days: 2, hours: 3, minutes: 4 });
  });

  it('reports an elapsed deadline as expired', () => {
    expect(countdownTo(1_000, 1_000)).toEqual({ expired: true, days: 0, hours: 0, minutes: 0 });
    expect(countdownTo(1_000, 2_000)).toEqual({ expired: true, days: 0, hours: 0, minutes: 0 });
  });
});

describe('UntrustedRearmError', () => {
  it('carries the blocking contacts for the revoke-and-retry offer', () => {
    const err = new UntrustedRearmError([{ id: 'a', email: 'contact@example.org' }]);

    expect(err).toBeInstanceOf(Error);
    expect(err.name).toBe('UntrustedRearmError');
    expect(err.contacts).toEqual([{ id: 'a', email: 'contact@example.org' }]);
  });
});
