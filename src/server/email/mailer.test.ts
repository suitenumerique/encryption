import nodemailer, { Transporter } from 'nodemailer';

import { type EmailServerSettings, Mailer } from '@encryption/src/server/email/mailer';
import { EmergencyAcceptedEmail } from '@encryption/src/server/email/templates/EmergencyAccepted';

// The module singleton reads the server env at import time; tests build their own instances
jest.mock('@encryption/src/server/env', () => ({ env: {} }));

const defaultSender = 'Chiffrement <noreply@example.com>';
const smtpSettings = { host: 'primary.example.com', port: 25, user: '', password: '' };
const fallbackSmtpSettings = { host: 'fallback.example.com', port: 25, user: '', password: '' };

function sendOptions() {
  return {
    recipients: ['grantor@example.com'],
    subject: 'Test subject',
    emailComponent: EmergencyAcceptedEmail({ locale: 'fr', granteeEmail: 'jean.dupont@numerique.gouv.fr' }),
  };
}

describe('Mailer', () => {
  it('sends a rendered email with both html and text bodies', async () => {
    const transport = nodemailer.createTransport({ jsonTransport: true });
    const sendMailSpy = jest.spyOn(transport, 'sendMail');

    const mailer = new Mailer({ defaultSender, smtp: smtpSettings, createTransport: () => transport });

    await mailer.send(sendOptions());

    expect(sendMailSpy).toHaveBeenCalledTimes(1);

    const parameters = sendMailSpy.mock.calls[0][0];
    expect(parameters.from).toBe(defaultSender);
    expect(parameters.to).toBe('grantor@example.com');
    expect(parameters.subject).toBe('Test subject');
    expect(parameters.html).toContain('jean.dupont@numerique.gouv.fr');
    expect(parameters.text).toContain('jean.dupont@numerique.gouv.fr');
    // The plaintext version must not carry markup
    expect(parameters.text).not.toContain('<');
  });

  it('retries on the fallback transport when the primary fails', async () => {
    const failing = { sendMail: jest.fn().mockRejectedValue(new Error('primary is down')) } as unknown as Transporter;
    const recording = nodemailer.createTransport({ jsonTransport: true });
    const recordingSpy = jest.spyOn(recording, 'sendMail');
    jest.spyOn(console, 'error').mockImplementation(() => {});

    const mailer = new Mailer({
      defaultSender,
      smtp: smtpSettings,
      fallbackSmtp: fallbackSmtpSettings,
      createTransport: (settings) => (settings.host === smtpSettings.host ? failing : recording),
    });

    await mailer.send(sendOptions());

    expect(failing.sendMail).toHaveBeenCalledTimes(1);
    expect(recordingSpy).toHaveBeenCalledTimes(1);
  });

  it('retries on the primary transport when no fallback is configured, then rethrows', async () => {
    const failing = { sendMail: jest.fn().mockRejectedValue(new Error('primary is down')) } as unknown as Transporter;
    jest.spyOn(console, 'error').mockImplementation(() => {});

    const mailer = new Mailer({ defaultSender, smtp: smtpSettings, createTransport: () => failing });

    await expect(mailer.send(sendOptions())).rejects.toThrow('primary is down');
    expect(failing.sendMail).toHaveBeenCalledTimes(2);
  });

  it('produces a well-formed MIME message (the bytes an SMTP server would receive)', async () => {
    // jsonTransport shows the FIELDS we hand to nodemailer; streamTransport
    // serialises the actual message, which is the only way to catch a broken
    // multipart assembly or a mis-encoded accented subject. Neither needs a
    // server: nodemailer's own SMTP client is not our code to test.
    const transport = nodemailer.createTransport({ streamTransport: true, buffer: true });
    const sendMailSpy = jest.spyOn(transport, 'sendMail');
    const mailer = new Mailer({ defaultSender, smtp: smtpSettings, createTransport: () => transport });

    await mailer.send({ ...sendOptions(), subject: 'Accès d’urgence accepté' });

    const info = await sendMailSpy.mock.results[0].value;
    const sent = (info.message as Buffer).toString('utf8');

    expect(sent).toContain('Content-Type: multipart/alternative');
    expect(sent).toContain('Content-Type: text/plain');
    expect(sent).toContain('Content-Type: text/html');
    // A non-ASCII subject must cross the wire encoded, never raw.
    expect(sent).toMatch(/Subject: =\?UTF-8\?/);
    expect(sent).toContain('To: grantor@example.com');
    expect(sent).toContain('From: Chiffrement <noreply@example.com>');
  });

  it('throws rather than silently dropping the email when no SMTP host is configured', async () => {
    // A resolved-but-not-sent send would void the emergency-access guarantee that
    // a recovery can never start without notifying the grantor.
    const mailer = new Mailer({ defaultSender });

    await expect(mailer.send(sendOptions())).rejects.toThrow('SMTP is not configured');
  });

  it('builds a STARTTLS-required transport by default, and honours an explicit opt-out', () => {
    // Goes through the REAL transport factory (no createTransport override): the
    // point is that a relay which never advertises STARTTLS must not receive the
    // credentials and the message in clear.
    const optionsOf = (settings: EmailServerSettings) =>
      (new Mailer({ defaultSender, smtp: settings }) as unknown as { transporter: { options: Record<string, unknown> } }).transporter.options;

    const secured = optionsOf(smtpSettings);
    expect(secured.requireTLS).toBe(true);
    expect(secured.secure).toBe(false);

    // A local relay (maildev) speaks no TLS at all and has to opt out explicitly.
    const local = optionsOf({ ...smtpSettings, requireTls: false });
    expect(local.requireTLS).toBe(false);

    // Implicit TLS (port 465) is the other supported shape.
    const implicit = optionsOf({ ...smtpSettings, port: 465, secure: true });
    expect(implicit.secure).toBe(true);
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });
});
