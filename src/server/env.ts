import { z } from 'zod';

import { envSchema } from '@encryption/src/server/env-schema';

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
