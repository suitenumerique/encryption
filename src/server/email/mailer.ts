import { renderToMjml } from '@faire/mjml-react/utils/renderToMjml';
import mjml2html from 'mjml';
import { readFileSync } from 'node:fs';
import nodemailer, { Transporter } from 'nodemailer';
import type { Options as MailOptions } from 'nodemailer/lib/mailer/index';
import { ReactElement } from 'react';

import { setEmailAssetBaseUrl } from '@encryption/src/server/email/assets';
import { convertHtmlEmailToText } from '@encryption/src/server/email/helpers';
import { applyEmailPaletteOverride } from '@encryption/src/server/email/palette';
import { env } from '@encryption/src/server/env';
import { parseBrandFont, setServerBrandFont } from '@encryption/src/shared/brand-font';

// Emails reference the logo by absolute URL (mail clients cannot resolve a
// relative one); it is served by the interface under /public-assets.
setEmailAssetBaseUrl(env.UI_URL);

// The email colours are bundled+minified into the server, so an instance re-themes
// them by mounting a JSON override file rather than rebuilding. Applied once here,
// at startup, before any email renders. The fs read lives in this server-only
// module so `palette.ts` stays browser-safe for Storybook. A broken file is logged
// and skipped: bad colours must not stop the server from sending mail.
if (env.EMAIL_PALETTE_PATH) {
  try {
    applyEmailPaletteOverride(JSON.parse(readFileSync(env.EMAIL_PALETTE_PATH, 'utf8')));
  } catch (err) {
    console.error(`Failed to load the email palette override from ${env.EMAIL_PALETTE_PATH}, keeping the defaults`, err);
  }
}

// The brand font is shared with the interface (PDF + UI); resolve it once here so
// email rendering can name it in `font-family`. Unset = a generic stack.
setServerBrandFont(parseBrandFont(env.BRAND_FONT));

export interface EmailServerSettings {
  host: string;
  port: number;
  user: string;
  password: string;
  secure?: boolean;
  requireTls?: boolean;
}

export type CreateTransportFactory = (settings: EmailServerSettings) => Transporter;

export interface MailerOptions {
  defaultSender: string;
  smtp?: EmailServerSettings;
  fallbackSmtp?: EmailServerSettings;
  // Injectable so tests can substitute nodemailer's jsonTransport for real SMTP connections
  createTransport?: CreateTransportFactory;
}

export interface SendOptions {
  sender?: string;
  replyTo?: string;
  recipients: string[];
  subject: string;
  emailComponent: ReactElement;
}

function defaultCreateTransport(settings: EmailServerSettings): Transporter {
  return nodemailer.createTransport({
    host: settings.host,
    port: settings.port,
    // Local relays like maildev advertise no AUTH extension, so only authenticate when credentials are provided
    auth: settings.user !== '' ? { user: settings.user, pass: settings.password } : undefined,
    secure: settings.secure ?? false,
    requireTLS: settings.requireTls ?? true,
  });
}

export class Mailer {
  protected transporter: Transporter | null = null;
  protected fallbackTransporter: Transporter | null = null;
  protected defaultSender: string;

  constructor(options: MailerOptions) {
    this.defaultSender = options.defaultSender;

    const createTransport = options.createTransport ?? defaultCreateTransport;

    if (options.smtp) {
      this.transporter = createTransport(options.smtp);
    }

    if (options.fallbackSmtp) {
      this.fallbackTransporter = createTransport(options.fallbackSmtp);
    }
  }

  public close() {
    if (this.transporter) {
      this.transporter.removeAllListeners();
      this.transporter.close();
    }

    if (this.fallbackTransporter) {
      this.fallbackTransporter.removeAllListeners();
      this.fallbackTransporter.close();
    }
  }

  public async send(options: SendOptions): Promise<void> {
    // Always render, even without SMTP configured, so a broken template surfaces in development too
    const mjmlContent = renderToMjml(options.emailComponent);
    const transformResult = await mjml2html(mjmlContent);

    if (transformResult.errors) {
      for (const err of transformResult.errors) {
        throw err;
      }
    }

    const rawHtmlVersion = transformResult.html;
    const plaintextVersion = convertHtmlEmailToText(rawHtmlVersion);

    // Fail-closed. A silent "rendered but not sent" would void the one guarantee
    // the emergency-access wait period rests on (the grantor is told a recovery
    // started), and would do it invisibly. The env schema makes the primary host
    // mandatory, so this only fires for a hand-built Mailer.
    if (!this.transporter) {
      throw new Error(`SMTP is not configured, refusing to silently drop the email "${options.subject}"`);
    }

    const parameters: MailOptions = {
      from: options.sender || this.defaultSender,
      replyTo: options.replyTo ?? undefined,
      to: options.recipients.join(','),
      subject: options.subject,
      html: rawHtmlVersion,
      text: plaintextVersion,
    };

    try {
      await this.transporter.sendMail(parameters);
    } catch (err) {
      console.error('the first attempt to send the email has failed');
      console.error(err);

      const retryTransporter = this.fallbackTransporter || this.transporter;

      try {
        await retryTransporter.sendMail(parameters);
      } catch (retryErr) {
        console.error('the second attempt to send the email has failed');
        console.error(retryErr);

        // Until a proper queue system exists, failing loudly lets the caller know a retry is needed
        throw retryErr;
      }
    }
  }
}

export const mailer = new Mailer({
  defaultSender: `Chiffrement <noreply@${env.MAILER_DEFAULT_DOMAIN}>`,
  smtp: {
    host: env.MAILER_SMTP_HOST,
    port: env.MAILER_SMTP_PORT,
    user: env.MAILER_SMTP_USER ?? '',
    password: env.MAILER_SMTP_PASSWORD ?? '',
    secure: env.MAILER_SMTP_SECURE,
    requireTls: env.MAILER_SMTP_REQUIRE_TLS,
  },
  fallbackSmtp: env.MAILER_FALLBACK_SMTP_HOST
    ? {
        host: env.MAILER_FALLBACK_SMTP_HOST,
        port: env.MAILER_FALLBACK_SMTP_PORT ?? 25,
        user: env.MAILER_FALLBACK_SMTP_USER ?? '',
        password: env.MAILER_FALLBACK_SMTP_PASSWORD ?? '',
        secure: env.MAILER_FALLBACK_SMTP_SECURE,
        requireTls: env.MAILER_FALLBACK_SMTP_REQUIRE_TLS,
      }
    : undefined,
});
