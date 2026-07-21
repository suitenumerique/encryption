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
