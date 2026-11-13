import { describe, expect, it } from 'vitest';

import { exportPublicKeyAsBase64, generateUserKeyPair } from '@encryption/src/crypto';
import { maintenanceEscrowKeyForEmail, maintenanceEscrowKeysSchema } from '@encryption/src/server/maintenance-escrow';

const newKey = async () => exportPublicKeyAsBase64((await generateUserKeyPair()).publicKey);

describe('maintenanceEscrowKeyForEmail', () => {
  it('picks the longest listed domain the email belongs to, on a label boundary, else the * entry', async () => {
    const [ministry, team, fallback] = [await newKey(), await newKey(), await newKey()];
    const entries = maintenanceEscrowKeysSchema.parse([
      { domains: ['agriculture.gouv.fr'], publicKey: ministry },
      { domains: ['forets.agriculture.gouv.fr'], publicKey: team },
      { domains: ['*'], publicKey: fallback },
    ]);

    expect(maintenanceEscrowKeyForEmail(entries, 'alice@agriculture.gouv.fr')).toBe(ministry);
    expect(maintenanceEscrowKeyForEmail(entries, 'bob@monequipe.agriculture.gouv.fr')).toBe(ministry);
    expect(maintenanceEscrowKeyForEmail(entries, 'carol@Sylve.FORETS.agriculture.gouv.fr')).toBe(team);
    expect(maintenanceEscrowKeyForEmail(entries, 'dan@fauxagriculture.gouv.fr')).toBe(fallback);
    expect(maintenanceEscrowKeyForEmail(entries, 'eve@interieur.gouv.fr')).toBe(fallback);
  });

  it('escrows nothing for an email no entry covers when there is no * entry', async () => {
    const entries = maintenanceEscrowKeysSchema.parse([{ domains: ['agriculture.gouv.fr'], publicKey: await newKey() }]);

    expect(maintenanceEscrowKeyForEmail(entries, 'eve@interieur.gouv.fr')).toBeNull();
    expect(maintenanceEscrowKeyForEmail([], 'alice@agriculture.gouv.fr')).toBeNull();
  });
});

describe('maintenanceEscrowKeysSchema', () => {
  it('refuses a domain listed twice or a key split across entries, since either makes the choice ambiguous', async () => {
    const [a, b] = [await newKey(), await newKey()];

    expect(
      maintenanceEscrowKeysSchema.safeParse([
        { domains: ['agriculture.gouv.fr'], publicKey: a },
        { domains: ['AGRICULTURE.gouv.fr'], publicKey: b },
      ]).success
    ).toBe(false);
    expect(
      maintenanceEscrowKeysSchema.safeParse([
        { domains: ['agriculture.gouv.fr'], publicKey: a },
        { domains: ['interieur.gouv.fr'], publicKey: a },
      ]).success
    ).toBe(false);
  });
});
