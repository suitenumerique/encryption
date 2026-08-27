import { z } from 'zod';

const envSchema = z.object({
  PORT: z.coerce.number().default(7200),
  HOST: z.string().default('0.0.0.0'),
  DATABASE_URL: z.string(),
  VAULT_URL: z.string().url(),
  UI_URL: z.string().url(),
  ALLOWED_FRAME_ANCESTORS: z.string(),
  OIDC_JWKS_URL: z.string(),
  OIDC_SERVER_CLIENT_ID: z.string(),
  // OIDC configuration for the encryption interface (injected into the HTML at runtime)
  OIDC_ISSUER: z.string(),
  OIDC_CLIENT_ID: z.string(),
  OIDC_REDIRECT_URI: z.string(),
  OIDC_ACCEPT_UNVERIFIED_EMAIL: z.stringbool().default(false),
  OIDC_FALLBACK_TO_EMAIL_FOR_IDENTIFICATION: z.stringbool().default(false),
  DOCS_ENABLED: z.coerce.boolean().default(true),
  // Email delivery. The primary SMTP host is MANDATORY, not a convenience: the
  // emergency-access wait period is only a protection for a grantor who actually
  // learns a recovery started, so the notification is a security control. A
  // deployment without a relay would start recoveries silently, which is why the
  // server refuses to boot rather than degrade to console logging.
  MAILER_SMTP_HOST: z.string().min(1),
  MAILER_SMTP_PORT: z.coerce.number().default(25),
  MAILER_SMTP_USER: z.string().optional(),
  MAILER_SMTP_PASSWORD: z.string().optional(),
  // Implicit TLS (port 465). Leave false for the usual STARTTLS-on-25/587 relay.
  MAILER_SMTP_SECURE: z.stringbool().default(false),
  // Refuse to deliver over a connection the relay never upgraded to TLS. Default
  // on, so credentials and recipient addresses cannot silently cross in clear;
  // local relays (maildev) that speak no TLS need it explicitly disabled.
  MAILER_SMTP_REQUIRE_TLS: z.stringbool().default(true),
  // Optional second relay, tried when the primary send fails.
  MAILER_FALLBACK_SMTP_HOST: z.string().optional(),
  MAILER_FALLBACK_SMTP_PORT: z.coerce.number().optional(),
  MAILER_FALLBACK_SMTP_USER: z.string().optional(),
  MAILER_FALLBACK_SMTP_PASSWORD: z.string().optional(),
  MAILER_FALLBACK_SMTP_SECURE: z.stringbool().default(false),
  MAILER_FALLBACK_SMTP_REQUIRE_TLS: z.stringbool().default(true),
  // Sender domain for "Chiffrement <noreply@domain>"
  MAILER_DEFAULT_DOMAIN: z.string().min(1),
  // The product page email links point to: the encryption interface only exists
  // embedded in products, so every notification needs somewhere to send the user.
  EMAIL_PRODUCT_URL: z.string().url(),
  // Optional path to a JSON file overriding email colours (keys of EmailPalette).
  EMAIL_PALETTE_PATH: z.string().optional(),
  // Optional error reporting to a Sentry-compatible collector (Sentry, GlitchTip).
  // Leaving SENTRY_DSN unset disables reporting entirely and is a fully supported
  // deployment mode: nothing in the service depends on a collector existing.
  SENTRY_DSN: z.string().optional(),
  SENTRY_ENVIRONMENT: z.string().optional(),
  // Identifies the deployed build in the collector. The /api/version hash is a
  // reasonable value when no release tag is available.
  SENTRY_RELEASE: z.string().optional(),
  // Optional JSON for the product brand font (BrandFont: family + woff URLs),
  // shared by the emails, the Recovery Kit PDF and the interface UI. Unset = each
  // surface's generic fallback.
  BRAND_FONT: z.string().optional(),
});

const parsed = envSchema.safeParse(process.env);

if (!parsed.success) {
  console.error('Invalid environment variables:', z.treeifyError(parsed.error));
  process.exit(1);
}

const data = parsed.data;

// Derive the host (hostname:port) from the URLs for Host-based routing.
// new URL("http://data.encryption.localhost:7200").host → "data.encryption.localhost:7200"
// new URL("https://data.encryption.example.com").host → "data.encryption.example.com"
export const env = {
  ...data,
  VAULT_HOST: new URL(data.VAULT_URL).host,
  UI_HOST: new URL(data.UI_URL).host,
};
