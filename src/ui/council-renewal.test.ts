import { describe, expect, it, vi } from 'vitest';

import type { CouncilEscrowBody } from '@encryption/src/shared/schemas/recovery-council';
import {
  COUNCIL_RENEWAL_INTERVAL_MS,
  type CouncilRenewalDeps,
  checkedRecently,
  rememberCheck,
  renewCouncilEscrowIfDue,
  renewsOn,
} from '@encryption/src/ui/council-renewal';
import { forMe } from '@encryption/src/ui/testing/council-stories';

const body = { council_id: 'dinum' } as CouncilEscrowBody;
const enrolled = () => forMe({ escrow: {} });

function deps(
  overrides: Partial<CouncilRenewalDeps> = {}
): CouncilRenewalDeps & { [K in 'checkEscrow' | 'createEscrow' | 'enroll']: ReturnType<typeof vi.fn> } {
  return {
    fetchForMe: async () => enrolled(),
    checkEscrow: vi.fn(async () => ({ status: 'ok' as const, renewalDue: true })),
    createEscrow: vi.fn(async () => body),
    enroll: vi.fn(async () => ({})),
    lang: 'french',
    ...overrides,
  } as never;
}

describe('council escrow renewal', () => {
  it('draws a new secret anchored on the signed version once a custodian left, and enrolls it', async () => {
    const d = deps();
    const { council, escrow } = enrolled();

    expect(await renewCouncilEscrowIfDue(d)).toBe('renewed');
    expect(d.createEscrow).toHaveBeenCalledWith(council!.council_id, council!.chain, 'french', escrow!.record.roster_hash);
    expect(d.enroll).toHaveBeenCalledWith(body);
  });

  it('does nothing while every custodian of the split is still there', async () => {
    const d = deps({ checkEscrow: vi.fn(async () => ({ status: 'ok' as const, renewalDue: false })) });

    expect(await renewCouncilEscrowIfDue(d)).toBe('not-due');
    expect(d.createEscrow).not.toHaveBeenCalled();
  });

  // A record or a chain the vault refused is shown in the settings, never re-armed onto.
  it.each(['tampered', 'chain-broken'] as const)('never renews an escrow that is %s', async (status) => {
    const d = deps({ checkEscrow: vi.fn(async () => ({ status, renewalDue: true })) });

    expect(await renewCouncilEscrowIfDue(d)).toBe('not-due');
    expect(d.createEscrow).not.toHaveBeenCalled();
  });

  it.each([
    ['no council', { ...enrolled(), council: null }],
    ['no escrow', forMe({ escrow: null })],
    ['an escrow of another vault', forMe({ escrow: { vault_active: false } })],
    ['a lost escrow (set up again explicitly)', forMe({ escrow: { health: { status: 'lost' } as never } })],
  ])('leaves %s alone', async (_, answer) => {
    const d = deps({ fetchForMe: async () => answer as never });

    expect(await renewCouncilEscrowIfDue(d)).toBe('not-enrolled');
    expect(d.checkEscrow).not.toHaveBeenCalled();
    expect(d.enroll).not.toHaveBeenCalled();
  });

  it('lets a refused enrollment through to the caller (a request in progress, a head that just changed)', async () => {
    const d = deps({ enroll: vi.fn(async () => Promise.reject(new Error('409'))) });

    await expect(renewCouncilEscrowIfDue(d)).rejects.toThrow('409');
  });

  it('runs only from screens that do not write an escrow of their own', () => {
    expect(renewsOn('settings')).toBe(true);
    expect(renewsOn('council-custodian')).toBe(true);
    for (const route of ['onboarding', 'restore', 'recovery-council', 'backup', 'device-approval', 'login', 'auth-callback'] as const) {
      expect(renewsOn(route)).toBe(false);
    }
    expect(renewsOn(null)).toBe(false);
  });

  describe('once a day', () => {
    const NOW = 1_800_000_000_000;

    function memory(): Pick<Storage, 'getItem' | 'setItem'> {
      const items = new Map<string, string>();

      return { getItem: (key) => items.get(key) ?? null, setItem: (key, value) => void items.set(key, value) };
    }

    it('skips a check made less than a day ago by this browser, for this user only', () => {
      const storage = memory();
      expect(checkedRecently('u1', NOW, storage)).toBe(false);

      rememberCheck('u1', NOW, storage);
      expect(checkedRecently('u1', NOW + COUNCIL_RENEWAL_INTERVAL_MS - 1, storage)).toBe(true);
      expect(checkedRecently('u1', NOW + COUNCIL_RENEWAL_INTERVAL_MS, storage)).toBe(false);
      expect(checkedRecently('u2', NOW, storage)).toBe(false);
    });

    // A clock set back, or garbage in the store, must not silence the check.
    it('checks again when the stored time is in the future or unreadable', () => {
      const storage = memory();
      rememberCheck('u1', NOW + 60_000, storage);
      expect(checkedRecently('u1', NOW, storage)).toBe(false);

      storage.setItem('encryption:council-renewal-checked:u1', 'not a number');
      expect(checkedRecently('u1', NOW, storage)).toBe(false);
    });

    it('never blocks a check when the storage is missing or refuses access', () => {
      const refusing = {
        getItem: () => {
          throw new Error('SecurityError');
        },
        setItem: () => {
          throw new Error('SecurityError');
        },
      };

      expect(checkedRecently('u1', NOW, null)).toBe(false);
      expect(checkedRecently('u1', NOW, refusing)).toBe(false);
      expect(() => rememberCheck('u1', NOW, refusing)).not.toThrow();
    });
  });
});
