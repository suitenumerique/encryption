import { z } from 'zod';

import { jsonEnvironmentValue } from '@encryption/src/server/email-domain-groups';
import { maintenanceEscrowKeysSchema } from '@encryption/src/server/maintenance-escrow';
import { recoveryCouncilsSchema } from '@encryption/src/server/recovery-councils';
import { parseDeviceInactivityDays } from '@encryption/src/shared/device-inactivity';
import { isValidOriginEntry, parseOriginAllowlist } from '@encryption/src/shared/origin-allowlist';

// A comma-separated variable as a list, blanks dropped: an empty value is an empty list.
function commaSeparatedList(defaultValue: string) {
  return z
    .string()
    .default(defaultValue)
    .transform((value) =>
      value
        .split(',')
        .map((item) => item.trim())
        .filter((item) => item.length > 0)
    );
}

const envFields = z.object({
  PORT: z.coerce.number().default(7200),
  HOST: z.string().default('0.0.0.0'),
  DATABASE_URL: z.string(),
  VAULT_URL: z.string().url(),
  UI_URL: z.string().url(),
  // Feeds both the CSP `frame-ancestors` and the vault's origin checks, so an entry
  // the two would read differently (a lone `*`, a bare host) stops the start.
  ALLOWED_FRAME_ANCESTORS: z.string().superRefine((value, ctx) => {
    const entries = parseOriginAllowlist(value);

    if (entries.length === 0) {
      ctx.addIssue({ code: 'custom', message: 'needs at least one product origin' });
    }

    const invalid = entries.filter((entry) => !isValidOriginEntry(entry));

    if (invalid.length > 0) {
      ctx.addIssue({
        code: 'custom',
        message: `expects origins like https://docs.example.org or https://*.example.org, got: ${invalid.join(', ')}`,
      });
    }
  }),
  // The OIDC provider the interface's users sign in with. The SERVER runs the
  // login (code exchange, ID token check, userinfo) as a confidential client,
  // then hands the ID token to the interface as its Bearer credential.
  OIDC_ISSUER: z.string().url(),
  OIDC_CLIENT_ID: z.string(),
  OIDC_CLIENT_SECRET: z.string().min(1),
  // How the secret reaches the token endpoint (OIDC Core 9): in the form body
  // (`client_secret_post`), or as HTTP Basic credentials (`client_secret_basic`).
  OIDC_TOKEN_ENDPOINT_AUTH_METHOD: z.enum(['client_secret_post', 'client_secret_basic']).default('client_secret_post'),
  OIDC_REDIRECT_URI: z.string(),
  // `openid` alone by default: the email and names are then asked for in the
  // userinfo answer only, through the `claims` parameter, so they never ride in
  // the ID token sent with every API call. The fallback for a provider that
  // ignores that parameter is to grant the scopes here (e.g. `openid email
  // profile`, or one scope per claim where the provider works that way).
  OIDC_SCOPES: z.string().default('openid'),
  // Which claims carry the user's names, each an ordered list of candidates.
  // The first name is required, plus a last name or a full name: without a last
  // name, it is the full name minus the first name (see identity-claims.ts).
  OIDC_CLAIMS_FIRST_NAME: commaSeparatedList('given_name'),
  OIDC_CLAIMS_LAST_NAME: commaSeparatedList('usual_name,family_name'),
  OIDC_CLAIMS_FULL_NAME: commaSeparatedList('name'),
  // Step-up (RFC 9470) for the sensitive actions: the ID token must show a
  // second factor, through an `acr` among these values OR an `amr` among those,
  // and an authentication (`auth_time`) younger than the max age. The defaults
  // are the eIDAS second-factor levels and RFC 8176 methods.
  // Both lists empty = only the fresh authentication is required.
  // Off by default for now: LaSuite Accounts, the suite's provider, ignores the
  // `acr` a product asks for, reports no second factor and never renews
  // `auth_time`, so no user could meet the step-up. Turn it on by default once
  // Accounts handles it (suitenumerique/accounts#141).
  OIDC_STEP_UP_ENABLED: z.stringbool().default(false),
  OIDC_STEP_UP_ACR_VALUES: commaSeparatedList('eidas0-mfa,eidas1-mfa,eidas2,eidas3'),
  OIDC_STEP_UP_AMR_VALUES: commaSeparatedList('mfa,otp,totp,hwk,sc,pop'),
  OIDC_STEP_UP_MAX_AGE_SECONDS: z.coerce.number().int().positive().default(300),
  OIDC_ACCEPT_UNVERIFIED_EMAIL: z.stringbool().default(false),
  OIDC_FALLBACK_TO_EMAIL_FOR_IDENTIFICATION: z.stringbool().default(false),
  // `stringbool`, not `coerce.boolean`: the latter turns the string "false" into true.
  DOCS_ENABLED: z.stringbool().default(true),
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
  // The address notifications are sent from, as "Chiffrement <address>". Whole, not just a
  // domain: a relay only accepts senders it was set up for, and an operator may have to
  // use a given mailbox (one per environment, for instance).
  MAILER_SENDER_ADDRESS: z.email(),
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
  // Labels the deployed build in the collector. Defaults to the commit the image
  // was built from (SOURCE_COMMIT, set by CI in the Dockerfile), else to the
  // /api/version hash of the bundles. A label only: stacks are resolved inside the
  // image, so nothing is ever matched against uploaded artifacts.
  SENTRY_RELEASE: z.string().optional(),
  SOURCE_COMMIT: z.string().optional(),
  // Where a security researcher should report a problem with THIS deployment
  // (published as /.well-known/security.txt). It belongs to whoever operates the
  // instance, not to the code, so nothing is served until the operator sets it: an
  // `mailto:` or an `https://` URL.
  SECURITY_CONTACT_URL: z.preprocess(
    (value) => (value === '' ? undefined : value),
    z
      .string()
      .regex(/^(?:https:\/\/|mailto:)\S+$/)
      .optional()
  ),
  // Days a dormant vault (superseded by a start-over, or left by leaving encryption)
  // stays restorable by its own recovery phrase before its content is deleted. The
  // active vault is never concerned. 0 keeps dormant vaults forever. Below six months
  // a user returning from a long leave would find the vault they left already gone.
  // Empty means unset (the default), never 0: coercing '' would silently turn the
  // purge off.
  VAULT_PURGE_AFTER_DAYS: z.preprocess(
    (value) => (value === '' ? undefined : value),
    z.coerce
      .number()
      .int()
      .refine((days) => days === 0 || days >= 180, 'expects 0 (never purge) or at least 180 days')
      .default(730)
  ),
  // Days without any use of encryption after which a browser forgets its copy of the
  // vault (device key, wrapped VRK, sealed items) and has to be enrolled again with
  // another device or the recovery phrase. 0 keeps it until the user leaves
  // encryption or clears the site data.
  VAULT_DEVICE_INACTIVITY_DAYS: z
    .string()
    .optional()
    .transform((raw, ctx) => {
      try {
        return parseDeviceInactivityDays(raw);
      } catch (error) {
        ctx.addIssue({ code: 'custom', message: (error as Error).message });

        return z.NEVER;
      }
    }),
  // Optional maintenance escrow (architecture.md, Appendix E): a JSON list of the
  // operators' X-Wing public keys, each with the email domains whose owners'
  // resources it escrows (src/server/maintenance-escrow.ts). Validated in full at
  // boot: a malformed key would otherwise fail every document creation in the
  // browser, and a domain listed twice would make the choice of key ambiguous.
  MAINTENANCE_ESCROW_KEYS: z.preprocess(
    jsonEnvironmentValue('must be a JSON list of { "domains": [...], "publicKey": "..." }'),
    maintenanceEscrowKeysSchema.optional()
  ),
  // Optional recovery councils (architecture.md Appendix F): a JSON list of councils, each with the
  // email domains of the users it covers, its custodians and its threshold
  // (src/server/recovery-councils.ts). The variable only PROPOSES a membership:
  // what is in force is the roster signed by the custodians themselves, so an
  // empty or removed entry changes nothing already set up.
  RECOVERY_COUNCILS: z.preprocess(
    jsonEnvironmentValue('must be a JSON list of { "id", "label", "domains": [...], "custodians": [{ "userId", "email" }], "threshold" }'),
    recoveryCouncilsSchema.optional()
  ),
  // Optional JSON for the product brand font (BrandFont: family + woff URLs),
  // shared by the emails and the interface UI. Unset = each
  // surface's generic fallback.
  BRAND_FONT: z.string().optional(),
});

export const envSchema = envFields.superRefine((env, ctx) => {
  // A sign-in needs a last name, read from its own claim or derived from the full name.
  if (env.OIDC_CLAIMS_LAST_NAME.length === 0 && env.OIDC_CLAIMS_FULL_NAME.length === 0) {
    ctx.addIssue({
      code: 'custom',
      path: ['OIDC_CLAIMS_LAST_NAME'],
      message: 'OIDC_CLAIMS_LAST_NAME or OIDC_CLAIMS_FULL_NAME must name at least one claim: without either, every sign-in is refused',
    });
  }
});
