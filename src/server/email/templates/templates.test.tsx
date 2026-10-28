import { renderToMjml } from '@faire/mjml-react/utils/renderToMjml';
import mjml2html from 'mjml';
import { ReactElement } from 'react';
import { describe, expect, it } from 'vitest';

import { CouncilRecoveryAbortedEmail, subject as councilRecoveryAbortedSubject } from '@encryption/src/server/email/templates/CouncilRecoveryAborted';
import {
  CouncilRecoveryCompletedEmail,
  subject as councilRecoveryCompletedSubject,
} from '@encryption/src/server/email/templates/CouncilRecoveryCompleted';
import {
  CouncilRecoveryCompletedCustodianEmail,
  subject as councilRecoveryCompletedCustodianSubject,
} from '@encryption/src/server/email/templates/CouncilRecoveryCompletedCustodian';
import { CouncilRecoveryMeetingEmail, subject as councilRecoveryMeetingSubject } from '@encryption/src/server/email/templates/CouncilRecoveryMeeting';
import {
  CouncilRecoveryRequestedEmail,
  subject as councilRecoveryRequestedSubject,
} from '@encryption/src/server/email/templates/CouncilRecoveryRequested';
import {
  CouncilRecoveryToApproveEmail,
  subject as councilRecoveryToApproveSubject,
} from '@encryption/src/server/email/templates/CouncilRecoveryToApprove';
import { CouncilRosterToSignEmail, subject as councilRosterToSignSubject } from '@encryption/src/server/email/templates/CouncilRosterToSign';
import { EmergencyAcceptedEmail, subject as acceptedSubject } from '@encryption/src/server/email/templates/EmergencyAccepted';
import { EmergencyDeclinedEmail, subject as declinedSubject } from '@encryption/src/server/email/templates/EmergencyDeclined';
import { EmergencyDesignatedEmail, subject as designatedSubject } from '@encryption/src/server/email/templates/EmergencyDesignated';
import {
  EmergencyRecoveryApprovedContactEmail,
  subject as approvedContactSubject,
} from '@encryption/src/server/email/templates/EmergencyRecoveryApprovedContact';
import {
  EmergencyRecoveryApprovedGrantorEmail,
  subject as approvedGrantorSubject,
} from '@encryption/src/server/email/templates/EmergencyRecoveryApprovedGrantor';
import { EmergencyRecoveryCancelledEmail, subject as cancelledSubject } from '@encryption/src/server/email/templates/EmergencyRecoveryCancelled';
import { EmergencyRecoveryRejectedEmail, subject as rejectedSubject } from '@encryption/src/server/email/templates/EmergencyRecoveryRejected';
import { EmergencyRecoveryReminderEmail, subject as reminderSubject } from '@encryption/src/server/email/templates/EmergencyRecoveryReminder';
import { EmergencyRecoveryRequestedEmail, subject as requestedSubject } from '@encryption/src/server/email/templates/EmergencyRecoveryRequested';
import { EmergencyRevokedEmail, subject as revokedSubject } from '@encryption/src/server/email/templates/EmergencyRevoked';
import { EmergencyVaultRecoveredEmail, subject as vaultRecoveredSubject } from '@encryption/src/server/email/templates/EmergencyVaultRecovered';
import {
  EmergencyVaultRecoveredContactEmail,
  subject as vaultRecoveredContactSubject,
} from '@encryption/src/server/email/templates/EmergencyVaultRecoveredContact';
import { VaultPurgeWarningEmail, subject as purgeWarningSubject } from '@encryption/src/server/email/templates/VaultPurgeWarning';
import { VaultPurgedEmail, subject as purgedSubject } from '@encryption/src/server/email/templates/VaultPurged';

const grantor = 'Alice Martin (alice.martin@numerique.gouv.fr)';
const grantee = 'Jean Dupont';
const productUrl = 'http://localhost:7201';

// Midday UTC so the formatted date is August 15 in every realistic server timezone
const deadlineMillis = Date.UTC(2026, 7, 15, 12);
const disabledAtMillis = Date.UTC(2024, 7, 15, 12);

type Locale = 'fr' | 'en';

interface Case {
  name: string;
  subject: (locale: Locale) => string;
  make: (locale: Locale) => ReactElement;
  // Strings that must land in the rendered HTML, per locale
  expected: Record<Locale, string[]>;
}

const cases: Case[] = [
  {
    name: 'CouncilRecoveryRequested',
    subject: councilRecoveryRequestedSubject,
    make: (locale) => CouncilRecoveryRequestedEmail({ locale, council: 'Équipe sécurité DINUM', productUrl: 'http://localhost:7201' }),
    expected: {
      fr: ['Équipe sécurité DINUM', 'collège de recouvrement'],
      en: ['Équipe sécurité DINUM', 'recovery council'],
    },
  },
  {
    name: 'CouncilRecoveryToApprove',
    subject: (locale: string) => councilRecoveryToApproveSubject(locale, 'approve'),
    make: (locale) =>
      CouncilRecoveryToApproveEmail({
        locale,
        requester: 'Jean Dupont (jean.dupont@numerique.gouv.fr)',
        council: 'Équipe sécurité DINUM',
        step: 'approve',
        productUrl: 'http://localhost:7201',
      }),
    expected: {
      fr: ['Jean Dupont', 'Équipe sécurité DINUM', 'approuver à distance'],
      en: ['Jean Dupont', 'Équipe sécurité DINUM', 'approve it remotely'],
    },
  },
  {
    name: 'CouncilRecoveryToApprove (meet first)',
    subject: (locale: string) => councilRecoveryToApproveSubject(locale, 'meet'),
    make: (locale) =>
      CouncilRecoveryToApproveEmail({
        locale,
        requester: 'Jean Dupont (jean.dupont@numerique.gouv.fr)',
        council: 'Équipe sécurité DINUM',
        step: 'meet',
        productUrl: 'http://localhost:7201',
      }),
    expected: {
      fr: ['Jean Dupont', 'Rien ne peut être approuvé à distance'],
      en: ['Jean Dupont', 'Nothing can be approved remotely'],
    },
  },
  {
    name: 'CouncilRecoveryMeeting',
    subject: councilRecoveryMeetingSubject,
    make: (locale) =>
      CouncilRecoveryMeetingEmail({
        locale,
        council: 'Équipe sécurité DINUM',
        custodians: 'Claire Petit, David Moreau',
        productUrl: 'http://localhost:7201',
      }),
    expected: {
      fr: ['Claire Petit, David Moreau'],
      en: ['Claire Petit, David Moreau'],
    },
  },
  {
    name: 'CouncilRecoveryCompleted',
    subject: councilRecoveryCompletedSubject,
    make: (locale) => CouncilRecoveryCompletedEmail({ locale, council: 'Équipe sécurité DINUM', contributors: 'Alice Martin, Claire Petit' }),
    expected: {
      fr: ['Alice Martin, Claire Petit'],
      en: ['Alice Martin, Claire Petit'],
    },
  },
  {
    name: 'CouncilRecoveryCompletedCustodian',
    subject: councilRecoveryCompletedCustodianSubject,
    make: (locale) => CouncilRecoveryCompletedCustodianEmail({ locale, requester: 'Jean Dupont', council: 'Équipe sécurité DINUM' }),
    expected: {
      fr: ['Jean Dupont'],
      en: ['Jean Dupont'],
    },
  },
  {
    name: 'CouncilRecoveryAborted',
    subject: councilRecoveryAbortedSubject,
    make: (locale) => CouncilRecoveryAbortedEmail({ locale, council: 'Équipe sécurité DINUM' }),
    expected: {
      fr: ['Équipe sécurité DINUM'],
      en: ['Équipe sécurité DINUM'],
    },
  },
  {
    name: 'CouncilRosterToSign',
    subject: councilRosterToSignSubject,
    make: (locale) => CouncilRosterToSignEmail({ locale, council: 'Équipe sécurité DINUM', productUrl: 'http://localhost:7201' }),
    expected: {
      fr: ['Équipe sécurité DINUM'],
      en: ['Équipe sécurité DINUM'],
    },
  },
  {
    name: 'EmergencyDesignated',
    subject: designatedSubject,
    make: (locale) => EmergencyDesignatedEmail({ locale, grantor, waitTimeDays: 15, productUrl }),
    expected: {
      fr: [grantor, '15 jours', 'contact de confiance', productUrl],
      en: [grantor, '15 days', 'trusted contact', productUrl],
    },
  },
  {
    name: 'EmergencyAccepted',
    subject: acceptedSubject,
    make: (locale) => EmergencyAcceptedEmail({ locale, grantee }),
    expected: {
      fr: [grantee, 'accepté'],
      en: [grantee, 'accepted'],
    },
  },
  {
    name: 'EmergencyDeclined',
    subject: declinedSubject,
    make: (locale) => EmergencyDeclinedEmail({ locale, grantee }),
    expected: {
      fr: [grantee, 'décliné'],
      en: [grantee, 'declined'],
    },
  },
  {
    name: 'EmergencyRecoveryRequested',
    subject: requestedSubject,
    make: (locale) => EmergencyRecoveryRequestedEmail({ locale, grantee, waitTimeDays: 15, deadlineMillis, productUrl }),
    expected: {
      fr: [grantee, '15 jours', '<strong>15 août 2026</strong>', 'refusez-la', productUrl],
      en: [grantee, '15-day', '<strong>August 15, 2026</strong>', 'refuse it now', productUrl],
    },
  },
  {
    name: 'EmergencyRecoveryReminder',
    subject: reminderSubject,
    make: (locale) => EmergencyRecoveryReminderEmail({ locale, grantee, daysRemaining: 3, productUrl }),
    expected: {
      fr: [`<strong>${grantee}</strong>`, '3 jours', productUrl],
      en: [`<strong>${grantee}</strong>`, '3 days', productUrl],
    },
  },
  {
    name: 'EmergencyRecoveryApprovedGrantor',
    subject: approvedGrantorSubject,
    make: (locale) => EmergencyRecoveryApprovedGrantorEmail({ locale, grantee, productUrl }),
    expected: {
      fr: [grantee, 'accordé', productUrl],
      en: [grantee, 'granted', productUrl],
    },
  },
  {
    name: 'EmergencyRecoveryApprovedContact',
    subject: approvedContactSubject,
    make: (locale) => EmergencyRecoveryApprovedContactEmail({ locale, grantor, productUrl }),
    expected: {
      fr: [grantor, 'en personne', productUrl],
      en: [grantor, 'in person', productUrl],
    },
  },
  {
    name: 'EmergencyRecoveryRejected',
    subject: rejectedSubject,
    make: (locale) => EmergencyRecoveryRejectedEmail({ locale, grantor }),
    expected: {
      fr: [grantor, 'refusé'],
      en: [grantor, 'refused'],
    },
  },
  {
    name: 'EmergencyRecoveryCancelled',
    subject: cancelledSubject,
    make: (locale) => EmergencyRecoveryCancelledEmail({ locale, grantee }),
    expected: {
      fr: [grantee, 'annulé'],
      en: [grantee, 'cancelled'],
    },
  },
  {
    name: 'EmergencyVaultRecovered',
    subject: vaultRecoveredSubject,
    make: (locale) => EmergencyVaultRecoveredEmail({ locale, grantee }),
    expected: {
      fr: [grantee, 'caduque'],
      en: [grantee, 'void'],
    },
  },
  {
    name: 'EmergencyVaultRecoveredContact',
    subject: vaultRecoveredContactSubject,
    make: (locale) => EmergencyVaultRecoveredContactEmail({ locale, grantor }),
    expected: {
      fr: [grantor, 'caduque'],
      en: [grantor, 'void'],
    },
  },
  {
    name: 'EmergencyRevoked',
    subject: revokedSubject,
    make: (locale) => EmergencyRevokedEmail({ locale, grantor }),
    expected: {
      fr: [grantor, 'contact de confiance'],
      en: [grantor, 'trusted contact'],
    },
  },
  {
    name: 'VaultPurgeWarning',
    subject: purgeWarningSubject,
    make: (locale) => VaultPurgeWarningEmail({ locale, disabledAtMillis, purgeAtMillis: deadlineMillis, productUrl }),
    expected: {
      fr: ['<strong>15 août 2024</strong>', '<strong>15 août 2026</strong>', 'phrase de récupération', productUrl],
      en: ['<strong>August 15, 2024</strong>', '<strong>August 15, 2026</strong>', 'recovery phrase', productUrl],
    },
  },
  {
    name: 'VaultPurged',
    subject: purgedSubject,
    make: (locale) => VaultPurgedEmail({ locale, disabledAtMillis }),
    expected: {
      fr: ['<strong>15 août 2024</strong>', 'supprimé'],
      en: ['<strong>August 15, 2024</strong>', 'deleted'],
    },
  },
];

const locales: Locale[] = ['fr', 'en'];

describe.each(cases)('$name', (c) => {
  describe.each(locales)('%s', (locale) => {
    it('renders without mjml errors and contains the key strings', async () => {
      const transformResult = await mjml2html(renderToMjml(c.make(locale)));

      expect(transformResult.errors).toHaveLength(0);

      for (const expected of c.expected[locale]) {
        expect(transformResult.html).toContain(expected);
      }

      // The subject doubles as the title tag
      expect(transformResult.html).toContain(`<title>${c.subject(locale)}</title>`);

      // Every email carries the header logo (served from /public-assets), with a
      // light and a dark variant swapped by theme.
      expect(transformResult.html).toContain('public-assets/logo.png');
      expect(transformResult.html).toContain('public-assets/logo-dark.png');
    });

    it('exposes a non-empty subject', () => {
      expect(c.subject(locale).length).toBeGreaterThan(0);
    });
  });

  it('translates the subject', () => {
    expect(c.subject('fr')).not.toEqual(c.subject('en'));
  });
});
