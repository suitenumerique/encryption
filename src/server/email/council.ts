import { senderFor } from '@encryption/src/server/email/emergency';
import { mailer } from '@encryption/src/server/email/mailer';
import type { SendOptions } from '@encryption/src/server/email/mailer';
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
  type CouncilRecoveryStep,
  CouncilRecoveryToApproveEmail,
  subject as councilRecoveryToApproveSubject,
} from '@encryption/src/server/email/templates/CouncilRecoveryToApprove';
import { CouncilRosterToSignEmail, subject as councilRosterToSignSubject } from '@encryption/src/server/email/templates/CouncilRosterToSign';

// The recovery council's notifications (architecture.md F.3, F.2). Same sender and
// layout as every other email of the service.
function send(locale: string, options: Omit<SendOptions, 'sender'>): Promise<void> {
  return mailer.send({ ...options, sender: senderFor(locale) });
}

export async function sendCouncilRecoveryRequested(params: {
  recipient: string;
  locale: string;
  council: string;
  productUrl: string;
}): Promise<void> {
  await send(params.locale, {
    recipients: [params.recipient],
    subject: councilRecoveryRequestedSubject(params.locale),
    emailComponent: CouncilRecoveryRequestedEmail(params),
  });
}

export async function sendCouncilRecoveryToApprove(params: {
  recipient: string;
  locale: string;
  requester: string;
  council: string;
  step: CouncilRecoveryStep;
  productUrl: string;
}): Promise<void> {
  await send(params.locale, {
    recipients: [params.recipient],
    subject: councilRecoveryToApproveSubject(params.locale, params.step),
    emailComponent: CouncilRecoveryToApproveEmail(params),
  });
}

export async function sendCouncilRecoveryMeeting(params: {
  recipient: string;
  locale: string;
  council: string;
  custodians: string;
  productUrl: string;
}): Promise<void> {
  await send(params.locale, {
    recipients: [params.recipient],
    subject: councilRecoveryMeetingSubject(params.locale),
    emailComponent: CouncilRecoveryMeetingEmail(params),
  });
}

export async function sendCouncilRecoveryCompleted(params: {
  recipient: string;
  locale: string;
  council: string;
  contributors: string;
}): Promise<void> {
  await send(params.locale, {
    recipients: [params.recipient],
    subject: councilRecoveryCompletedSubject(params.locale),
    emailComponent: CouncilRecoveryCompletedEmail(params),
  });
}

export async function sendCouncilRecoveryCompletedCustodian(params: {
  recipient: string;
  locale: string;
  requester: string;
  council: string;
}): Promise<void> {
  await send(params.locale, {
    recipients: [params.recipient],
    subject: councilRecoveryCompletedCustodianSubject(params.locale),
    emailComponent: CouncilRecoveryCompletedCustodianEmail(params),
  });
}

export async function sendCouncilRecoveryAborted(params: { recipient: string; locale: string; council: string }): Promise<void> {
  await send(params.locale, {
    recipients: [params.recipient],
    subject: councilRecoveryAbortedSubject(params.locale),
    emailComponent: CouncilRecoveryAbortedEmail(params),
  });
}

export async function sendCouncilRosterToSign(params: { recipient: string; locale: string; council: string; productUrl: string }): Promise<void> {
  await send(params.locale, {
    recipients: [params.recipient],
    subject: councilRosterToSignSubject(params.locale),
    emailComponent: CouncilRosterToSignEmail(params),
  });
}
