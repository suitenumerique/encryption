import 'fastify';

// Per-route config flags read by the vault's request-signature hook
// (src/server/routes/vault.ts: SIG_ONLY / SKIP_SIG). Declared here so
// `{ config: { signatureOnly: true } }` is type-checked, rather than relying on
// route `config` being unconstrained. Relying on that broke once
// fastify-type-provider-zod pulled in @fastify/swagger (a peer), whose own
// FastifyContextConfig augmentation tightened the type.
declare module 'fastify' {
  interface FastifyContextConfig {
    signatureOnly?: boolean;
    skipRequestSignature?: boolean;
  }
}
