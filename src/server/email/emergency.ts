import { mailer } from '@encryption/src/server/email/mailer';
import { EmergencyAcceptedEmail, subject as emergencyAcceptedSubject } from '@encryption/src/server/email/templates/EmergencyAccepted';
import { EmergencyDeclinedEmail, subject as emergencyDeclinedSubject } from '@encryption/src/server/email/templates/EmergencyDeclined';
import { EmergencyDesignatedEmail, subject as emergencyDesignatedSubject } from '@encryption/src/server/email/templates/EmergencyDesignated';
import {
  EmergencyRecoveryApprovedContactEmail,
  subject as emergencyRecoveryApprovedContactSubject,
} from '@encryption/src/server/email/templates/EmergencyRecoveryApprovedContact';
import {
  EmergencyRecoveryApprovedGrantorEmail,
  subject as emergencyRecoveryApprovedGrantorSubject,
} from '@encryption/src/server/email/templates/EmergencyRecoveryApprovedGrantor';
import {
  EmergencyRecoveryCancelledEmail,
  subject as emergencyRecoveryCancelledSubject,
} from '@encryption/src/server/email/templates/EmergencyRecoveryCancelled';
import {
  EmergencyRecoveryRejectedEmail,
  subject as emergencyRecoveryRejectedSubject,
} from '@encryption/src/server/email/templates/EmergencyRecoveryRejected';
import {
  EmergencyRecoveryReminderEmail,
  subject as emergencyRecoveryReminderSubject,
} from '@encryption/src/server/email/templates/EmergencyRecoveryReminder';
import {
  EmergencyRecoveryRequestedEmail,
  subject as emergencyRecoveryRequestedSubject,
} from '@encryption/src/server/email/templates/EmergencyRecoveryRequested';
import { EmergencyRevokedEmail, subject as emergencyRevokedSubject } from '@encryption/src/server/email/templates/EmergencyRevoked';
import {
  EmergencyVaultRecoveredEmail,
  subject as emergencyVaultRecoveredSubject,
} from '@encryption/src/server/email/templates/EmergencyVaultRecovered';
import {
  EmergencyVaultRecoveredContactEmail,
  subject as emergencyVaultRecoveredContactSubject,
} from '@encryption/src/server/email/templates/EmergencyVaultRecoveredContact';

export async function sendEmergencyDesignated(params: {
  recipient: string;
  locale: string;
  grantorEmail: string;
  waitTimeDays: number;
  productUrl: string;
}): Promise<void> {
  await mailer.send({
    recipients: [params.recipient],
    subject: emergencyDesignatedSubject(params.locale),
    emailComponent: EmergencyDesignatedEmail(params),
  });
}

export async function sendEmergencyAccepted(params: { recipient: string; locale: string; granteeEmail: string }): Promise<void> {
  await mailer.send({
    recipients: [params.recipient],
    subject: emergencyAcceptedSubject(params.locale),
    emailComponent: EmergencyAcceptedEmail(params),
  });
}

export async function sendEmergencyDeclined(params: { recipient: string; locale: string; granteeEmail: string }): Promise<void> {
  await mailer.send({
    recipients: [params.recipient],
    subject: emergencyDeclinedSubject(params.locale),
    emailComponent: EmergencyDeclinedEmail(params),
  });
}

export async function sendEmergencyRecoveryRequested(params: {
  recipient: string;
  locale: string;
  granteeEmail: string;
  waitTimeDays: number;
  deadlineMillis: number;
  productUrl: string;
}): Promise<void> {
  await mailer.send({
    recipients: [params.recipient],
    subject: emergencyRecoveryRequestedSubject(params.locale),
    emailComponent: EmergencyRecoveryRequestedEmail(params),
  });
}

export async function sendEmergencyRecoveryReminder(params: {
  recipient: string;
  locale: string;
  granteeEmail: string;
  daysRemaining: number;
  productUrl: string;
}): Promise<void> {
  await mailer.send({
    recipients: [params.recipient],
    subject: emergencyRecoveryReminderSubject(params.locale),
    emailComponent: EmergencyRecoveryReminderEmail(params),
  });
}

export async function sendEmergencyRecoveryApprovedGrantor(params: {
  recipient: string;
  locale: string;
  granteeEmail: string;
  productUrl: string;
}): Promise<void> {
  await mailer.send({
    recipients: [params.recipient],
    subject: emergencyRecoveryApprovedGrantorSubject(params.locale),
    emailComponent: EmergencyRecoveryApprovedGrantorEmail(params),
  });
}

export async function sendEmergencyRecoveryApprovedContact(params: {
  recipient: string;
  locale: string;
  grantorEmail: string;
  productUrl: string;
}): Promise<void> {
  await mailer.send({
    recipients: [params.recipient],
    subject: emergencyRecoveryApprovedContactSubject(params.locale),
    emailComponent: EmergencyRecoveryApprovedContactEmail(params),
  });
}

export async function sendEmergencyRecoveryRejected(params: { recipient: string; locale: string; grantorEmail: string }): Promise<void> {
  await mailer.send({
    recipients: [params.recipient],
    subject: emergencyRecoveryRejectedSubject(params.locale),
    emailComponent: EmergencyRecoveryRejectedEmail(params),
  });
}

export async function sendEmergencyRecoveryCancelled(params: { recipient: string; locale: string; granteeEmail: string }): Promise<void> {
  await mailer.send({
    recipients: [params.recipient],
    subject: emergencyRecoveryCancelledSubject(params.locale),
    emailComponent: EmergencyRecoveryCancelledEmail(params),
  });
}

export async function sendEmergencyVaultRecovered(params: { recipient: string; locale: string; granteeEmail: string }): Promise<void> {
  await mailer.send({
    recipients: [params.recipient],
    subject: emergencyVaultRecoveredSubject(params.locale),
    emailComponent: EmergencyVaultRecoveredEmail(params),
  });
}

export async function sendEmergencyVaultRecoveredContact(params: { recipient: string; locale: string; grantorEmail: string }): Promise<void> {
  await mailer.send({
    recipients: [params.recipient],
    subject: emergencyVaultRecoveredContactSubject(params.locale),
    emailComponent: EmergencyVaultRecoveredContactEmail(params),
  });
}

export async function sendEmergencyRevoked(params: { recipient: string; locale: string; grantorEmail: string }): Promise<void> {
  await mailer.send({
    recipients: [params.recipient],
    subject: emergencyRevokedSubject(params.locale),
    emailComponent: EmergencyRevokedEmail(params),
  });
}
