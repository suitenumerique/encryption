import { z } from 'zod';

import type { BrandFont } from '@encryption/src/shared/brand-font';
import '@encryption/src/shared/zod-jitless';

// The configuration the server hands each document at serve time. Every field comes
// from an env var the server already validates at boot (see src/server/env.ts), so a
// block that reaches the browser incomplete means the document was tampered with or
// truncated, not that the deployment is merely unconfigured. Hence: required.

const brandFontSchema = z.object({
  family: z.string().min(1),
  regular: z.string().min(1),
  medium: z.string().optional(),
  bold: z.string().optional(),
});

// Fails to compile if brand-font.ts and this schema ever drift apart.
type _BrandFontMatchesSchema =
  z.infer<typeof brandFontSchema> extends BrandFont ? (BrandFont extends z.infer<typeof brandFontSchema> ? true : never) : never;
const _brandFontMatchesSchema: _BrandFontMatchesSchema = true;
void _brandFontMatchesSchema;

export const uiRuntimeConfigSchema = z.object({
  oidcIssuer: z.string().min(1),
  oidcClientId: z.string().min(1),
  oidcRedirectUri: z.string().min(1),
  vaultUrl: z.string().url(),
  // Empty on purpose in production: the API is same-origin with the interface.
  apiBaseUrl: z.string(),
  docsEnabled: z.boolean(),
  // The only genuinely optional one, BRAND_FONT being the only optional env var.
  brandFont: brandFontSchema.optional(),
});

export const vaultRuntimeConfigSchema = z.object({
  allowedOrigins: z.array(z.string().min(1)),
  interfaceOrigin: z.string().url(),
});

export type UiRuntimeConfig = z.infer<typeof uiRuntimeConfigSchema>;
export type VaultRuntimeConfig = z.infer<typeof vaultRuntimeConfigSchema>;
