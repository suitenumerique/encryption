import type { FastifyInstance } from 'fastify';

import { env } from '@encryption/src/server/env';

export const SECURITY_TXT_PATH = '/.well-known/security.txt';

const POLICY_URL = 'https://github.com/suitenumerique/encryption/blob/main/SECURITY.md';

// RFC 9116 makes `Expires` mandatory and wants it under a year away; a committed file
// would go stale, so the date is computed at request time instead.
const EXPIRES_IN_MS = 30 * 24 * 60 * 60 * 1000;

export function buildSecurityTxt(contactUrl: string, now: Date = new Date()): string {
  const expires = new Date(now.getTime() + EXPIRES_IN_MS).toISOString();

  return [
    `Contact: ${contactUrl}`,
    `Expires: ${expires}`,
    `Preferred-Languages: fr, en`,
    `Canonical: ${env.UI_URL}${SECURITY_TXT_PATH}`,
    `Canonical: ${env.VAULT_URL}${SECURITY_TXT_PATH}`,
    `Policy: ${POLICY_URL}`,
    '',
  ].join('\n');
}

/**
 * Where researchers and scanners look for the disclosure channel (RFC 9116). Served on
 * every host, since both public domains are candidates for a report. The contact is
 * the operator's, so without SECURITY_CONTACT_URL the path does not exist: a contact
 * the operator never chose would route reports about their servers elsewhere.
 */
export async function securityTxtRoute(app: FastifyInstance): Promise<void> {
  const contactUrl = env.SECURITY_CONTACT_URL;

  if (contactUrl === undefined) return;

  app.get(SECURITY_TXT_PATH, { schema: { hide: true } }, async (_, reply) => {
    reply.type('text/plain; charset=utf-8').send(buildSecurityTxt(contactUrl));
  });
}
