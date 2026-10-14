import { mailer } from '@encryption/src/server/email/mailer';
import type { SendOptions } from '@encryption/src/server/email/mailer';
import { VaultPurgeWarningEmail, subject as vaultPurgeWarningSubject } from '@encryption/src/server/email/templates/VaultPurgeWarning';
import { VaultPurgedEmail, subject as vaultPurgedSubject } from '@encryption/src/server/email/templates/VaultPurged';
import { env } from '@encryption/src/server/env';
import { t } from '@encryption/src/server/i18n';

function send(locale: string, recipient: string, subject: string, emailComponent: SendOptions['emailComponent']) {
  return mailer.send({
    recipients: [recipient],
    subject,
    emailComponent,
    sender: { name: t(locale, 'emails.senderName'), address: env.MAILER_SENDER_ADDRESS },
  });
}

export async function sendVaultPurgeWarning(params: {
  recipient: string;
  locale: string;
  disabledAtMillis: number;
  purgeAtMillis: number;
  productUrl: string;
}): Promise<void> {
  await send(params.locale, params.recipient, vaultPurgeWarningSubject(params.locale), VaultPurgeWarningEmail(params));
}

export async function sendVaultPurged(params: { recipient: string; locale: string; disabledAtMillis: number }): Promise<void> {
  await send(params.locale, params.recipient, vaultPurgedSubject(params.locale), VaultPurgedEmail(params));
}
