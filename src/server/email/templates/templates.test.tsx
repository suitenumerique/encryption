import { renderToMjml } from '@faire/mjml-react/utils/renderToMjml';
import mjml2html from 'mjml';
import { ReactElement } from 'react';

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

const grantorEmail = 'alice.martin@numerique.gouv.fr';
const granteeEmail = 'jean.dupont@numerique.gouv.fr';
const productUrl = 'http://localhost:7201';

// Midday UTC so the formatted date is August 15 in every realistic server timezone
const deadlineMillis = Date.UTC(2026, 7, 15, 12);

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
    name: 'EmergencyDesignated',
    subject: designatedSubject,
    make: (locale) => EmergencyDesignatedEmail({ locale, grantorEmail, waitTimeDays: 15, productUrl }),
    expected: {
      fr: [grantorEmail, '15 jours', 'contact de confiance', productUrl],
      en: [grantorEmail, '15 days', 'trusted contact', productUrl],
    },
  },
  {
    name: 'EmergencyAccepted',
    subject: acceptedSubject,
    make: (locale) => EmergencyAcceptedEmail({ locale, granteeEmail }),
    expected: {
      fr: [granteeEmail, 'accepté'],
      en: [granteeEmail, 'accepted'],
    },
  },
  {
    name: 'EmergencyDeclined',
    subject: declinedSubject,
    make: (locale) => EmergencyDeclinedEmail({ locale, granteeEmail }),
    expected: {
      fr: [granteeEmail, 'décliné'],
      en: [granteeEmail, 'declined'],
    },
  },
  {
    name: 'EmergencyRecoveryRequested',
    subject: requestedSubject,
    make: (locale) => EmergencyRecoveryRequestedEmail({ locale, granteeEmail, waitTimeDays: 15, deadlineMillis, productUrl }),
    expected: {
      fr: [granteeEmail, '15 jours', '<strong>15 août 2026</strong>', 'refusez-la', productUrl],
      en: [granteeEmail, '15-day', '<strong>August 15, 2026</strong>', 'refuse it now', productUrl],
    },
  },
  {
    name: 'EmergencyRecoveryReminder',
    subject: reminderSubject,
    make: (locale) => EmergencyRecoveryReminderEmail({ locale, granteeEmail, daysRemaining: 3, productUrl }),
    expected: {
      fr: [`<strong>${granteeEmail}</strong>`, '3 jours', productUrl],
      en: [`<strong>${granteeEmail}</strong>`, '3 days', productUrl],
    },
  },
  {
    name: 'EmergencyRecoveryApprovedGrantor',
    subject: approvedGrantorSubject,
    make: (locale) => EmergencyRecoveryApprovedGrantorEmail({ locale, granteeEmail, productUrl }),
    expected: {
      fr: [granteeEmail, 'accordé', productUrl],
      en: [granteeEmail, 'granted', productUrl],
    },
  },
  {
    name: 'EmergencyRecoveryApprovedContact',
    subject: approvedContactSubject,
    make: (locale) => EmergencyRecoveryApprovedContactEmail({ locale, grantorEmail, productUrl }),
    expected: {
      fr: [grantorEmail, 'en personne', productUrl],
      en: [grantorEmail, 'in person', productUrl],
    },
  },
  {
    name: 'EmergencyRecoveryRejected',
    subject: rejectedSubject,
    make: (locale) => EmergencyRecoveryRejectedEmail({ locale, grantorEmail }),
    expected: {
      fr: [grantorEmail, 'refusé'],
      en: [grantorEmail, 'refused'],
    },
  },
  {
    name: 'EmergencyRecoveryCancelled',
    subject: cancelledSubject,
    make: (locale) => EmergencyRecoveryCancelledEmail({ locale, granteeEmail }),
    expected: {
      fr: [granteeEmail, 'annulé'],
      en: [granteeEmail, 'cancelled'],
    },
  },
  {
    name: 'EmergencyVaultRecovered',
    subject: vaultRecoveredSubject,
    make: (locale) => EmergencyVaultRecoveredEmail({ locale, granteeEmail }),
    expected: {
      fr: [granteeEmail, 'caduque'],
      en: [granteeEmail, 'void'],
    },
  },
  {
    name: 'EmergencyVaultRecoveredContact',
    subject: vaultRecoveredContactSubject,
    make: (locale) => EmergencyVaultRecoveredContactEmail({ locale, grantorEmail }),
    expected: {
      fr: [grantorEmail, 'caduque'],
      en: [grantorEmail, 'void'],
    },
  },
  {
    name: 'EmergencyRevoked',
    subject: revokedSubject,
    make: (locale) => EmergencyRevokedEmail({ locale, grantorEmail }),
    expected: {
      fr: [grantorEmail, 'contact de confiance'],
      en: [grantorEmail, 'trusted contact'],
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
