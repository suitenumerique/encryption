import type { FastifyInstance } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { createHash } from 'node:crypto';
import { z } from 'zod';

import { base64ToUint8, uint8ToBase64 } from '@encryption/src/crypto/encryption-backup';
import type { EmergencyAccess, Identity, VaultCredential } from '@encryption/src/generated/prisma/client';
import { prisma } from '@encryption/src/prisma/client';
import {
  sendEmergencyAccepted,
  sendEmergencyDeclined,
  sendEmergencyDesignated,
  sendEmergencyRecoveryApprovedContact,
  sendEmergencyRecoveryApprovedGrantor,
  sendEmergencyRecoveryCancelled,
  sendEmergencyRecoveryRejected,
  sendEmergencyRecoveryRequested,
  sendEmergencyRevoked,
} from '@encryption/src/server/email/emergency';
import { env } from '@encryption/src/server/env';
import { errorResponses } from '@encryption/src/server/error-response';
import {
  emergencyApprovalHolds,
  emergencyDeadlineMillis,
  emergencyRecipient,
  verifyEscrowSubmission,
} from '@encryption/src/server/routes/emergency-core';
import { isRetryableRegistrationError } from '@encryption/src/server/routes/registration-core';
import { SIG_ONLY, SKIP_SIG, activeIdentityWireKey, assertUserId, registerTransportAuth } from '@encryption/src/server/routes/transport-auth';
import { configureZodValidation } from '@encryption/src/server/zod-validation';
import {
  API_ERROR_CONCURRENT_REGISTRATION,
  API_ERROR_EMERGENCY_ALREADY_EXISTS,
  API_ERROR_EMERGENCY_BAD_STATUS,
  API_ERROR_EMERGENCY_CONTACT_NOT_ONBOARDED,
  API_ERROR_EMERGENCY_ESCROW_INVALID,
  API_ERROR_EMERGENCY_NOT_FOUND,
  API_ERROR_EMERGENCY_SELF_DESIGNATION,
  API_ERROR_RATE_LIMIT_EMERGENCY,
  API_ERROR_VAULT_NOT_FOUND,
} from '@encryption/src/shared/error-codes';
import {
  EmergencyAccessStatusSchema,
  EmergencyDesignateBodySchema,
  type EmergencyGrantedEntry,
  EmergencyGrantedEntrySchema,
  EmergencyRearmBodySchema,
  EmergencyRecoverResponseSchema,
  EmergencySearchResponseSchema,
  type EmergencyTrustedEntry,
  EmergencyTrustedEntrySchema,
  EmergencyUpdateBodySchema,
} from '@encryption/src/shared/schemas/emergency-access';

// Hand-rolled rate limits, following the repo pattern (bounded counters + 429).
// They live in memory: per-instance and reset on restart, which is cheap and
// adequate while this runs as a single instance. Behind several replicas the
// effective ceiling is multiplied by the replica count, so a shared store (or a
// durable attempt log) is the upgrade path if that ever changes.
const SEARCH_RATE_LIMIT_WINDOW_MS = 60 * 60 * 1000;
const SEARCH_RATE_LIMIT_MAX = 20;
const INITIATE_RATE_LIMIT_WINDOW_MS = 24 * 60 * 60 * 1000;
const INITIATE_RATE_LIMIT_MAX = 5;
const DESIGNATE_RATE_LIMIT_WINDOW_MS = 24 * 60 * 60 * 1000;
const DESIGNATE_RATE_LIMIT_MAX = 10;

function slidingWindowLimiter(windowMs: number, max: number) {
  const hits = new Map<string, number[]>();

  return (key: string, nowMs: number): boolean => {
    const kept = (hits.get(key) ?? []).filter((t) => t > nowMs - windowMs);
    const allowed = kept.length < max;

    if (allowed) kept.push(nowMs);

    if (kept.length === 0) hits.delete(key);
    else hits.set(key, kept);

    return allowed;
  };
}

function authPublicKeyHashB64(authPublicKey: Uint8Array): string {
  return createHash('sha256').update(authPublicKey).digest('base64');
}

type RowWithCredential = EmergencyAccess & { credential: VaultCredential; granteeIdentity: Identity };

function escrowRecordWire(row: RowWithCredential) {
  return {
    grantee_identity_public_key: uint8ToBase64(new Uint8Array(row.granteeIdentity.signaturePublicKey)),
    grantee_key_version: row.granteeKeyVersion,
    wrapped_phrase_for_grantee: row.wrappedPhraseForGrantee,
    escrow_signature: uint8ToBase64(new Uint8Array(row.escrowSignature)),
    escrow_created_at_millis: row.escrowCreatedAt.getTime(),
    credential_auth_public_key_hash: authPublicKeyHashB64(new Uint8Array(row.credential.authPublicKey)),
  };
}

// "Onboarded" = designatable: registered keys AND an active vault (the escrow
// wraps to the encryption key; exercising it requires their vault).
async function onboardedUser(userId: string): Promise<boolean> {
  const [identity, encryptionKey, keyring] = await Promise.all([
    prisma.identity.findFirst({ where: { userId, disabledAt: null } }),
    prisma.encryptionKey.findFirst({ where: { userId, disabledAt: null } }),
    prisma.vaultKeyring.findFirst({ where: { userId, disabledAt: null } }),
  ]);

  return identity !== null && encryptionKey !== null && keyring !== null;
}

export async function emergencyAccessRoute(app: FastifyInstance): Promise<void> {
  configureZodValidation(app);
  registerTransportAuth(app);

  const searchAllowed = slidingWindowLimiter(SEARCH_RATE_LIMIT_WINDOW_MS, SEARCH_RATE_LIMIT_MAX);
  const initiateAllowed = slidingWindowLimiter(INITIATE_RATE_LIMIT_WINDOW_MS, INITIATE_RATE_LIMIT_MAX);
  const designateAllowed = slidingWindowLimiter(DESIGNATE_RATE_LIMIT_WINDOW_MS, DESIGNATE_RATE_LIMIT_MAX);

  const productUrl = env.EMAIL_PRODUCT_URL ?? '';

  function logEmailFailure(context: string) {
    return (err: unknown) => app.log.error({ err }, `emergency-access email failed: ${context}`);
  }

  // Exact-email lookup in the local base: contacts must already be onboarded
  // HERE (their keys are needed to build the escrow), unlike Bitwarden's
  // invite-any-email. Authenticated + rate-limited + exact-match only, since it
  // necessarily reveals whether an address has an onboarded account.
  app.withTypeProvider<ZodTypeProvider>().get(
    '/api/emergency-access/search',
    {
      ...SKIP_SIG,
      schema: { querystring: z.object({ email: z.string().optional() }), response: { 200: EmergencySearchResponseSchema, ...errorResponses(429) } },
    },
    async (request, reply) => {
      assertUserId(request);
      if (!searchAllowed(request.userId, Date.now())) return reply.status(429).send({ code: API_ERROR_RATE_LIMIT_EMERGENCY });

      const email = String(request.query.email ?? '')
        .trim()
        .toLowerCase();
      if (!email) return { user: null, onboarded: false };

      // Never surface the searcher's own account: designating yourself as your
      // own trusted contact is meaningless and is rejected at designation anyway.
      const candidates = (await prisma.user.findMany({ where: { email } })).filter((u) => u.id !== request.userId);

      const onboardedFlags = await Promise.all(candidates.map((u) => onboardedUser(u.id)));
      const onboarded = candidates.filter((_, i) => onboardedFlags[i]);

      // Zero or several onboarded matches both surface as "nobody designatable":
      // an ambiguous address (recycled email) must not guess between two humans.
      if (onboarded.length !== 1) {
        const known = candidates.length > 0;

        return { user: known && candidates.length === 1 ? { user_id: candidates[0].id, email: candidates[0].email } : null, onboarded: false };
      }

      return { user: { user_id: onboarded[0].id, email: onboarded[0].email }, onboarded: true };
    }
  );

  // Actionable pending state, fetched by the VAULT over the identity-signed
  // data plane (SIG_ONLY: the SDK/products never hold a JWT), so a product page
  // can surface "someone requested recovery of your data" / "you were
  // designated as a contact" the moment the user is there. A grantor with no
  // vault left cannot sign this and is covered by the emails instead.
  app.withTypeProvider<ZodTypeProvider>().get(
    '/api/emergency-access/pending',
    {
      ...SIG_ONLY,
      schema: {
        response: {
          // Counts only. The interface renders the actual list from its own
          // JWT-authenticated fetch, so this signal (which reaches the product
          // page) carries nothing an attacker could spoof into a prompt.
          200: z.object({
            invitations: z.number().int().nonnegative(),
            recovery_requests: z.number().int().nonnegative(),
          }),
        },
      },
    },
    async (request) => {
      assertUserId(request);
      const userId = request.userId;

      const [invitations, recoveryRequests] = await Promise.all([
        prisma.emergencyAccess.count({ where: { granteeUserId: userId, status: 'invited' } }),
        prisma.emergencyAccess.count({ where: { grantorUserId: userId, status: { in: ['recoveryRequested', 'recoveryApproved'] } } }),
      ]);

      return { invitations, recovery_requests: recoveryRequests };
    }
  );

  // Contacts I designated, pending designations included; carries the signed
  // escrow record so the interface can audit the list in the vault
  // (MSG_VAULT_VERIFY_ESCROWS) against server tampering.
  //
  // Scope of that audit: the escrow signature binds INTERNAL USER IDS, not
  // addresses. `grantee_email` is a server-supplied display label and is NOT
  // covered, so a hostile server could show the wrong address next to a row the
  // audit legitimately marks `ok`. The trust decision itself is unaffected (it was
  // taken against the identity fingerprint at designation, and the capsule is
  // wrapped to that identity's key), so binding the label would buy little for the
  // complexity of signing and reconciling a mutable, OIDC-refreshed field.
  app
    .withTypeProvider<ZodTypeProvider>()
    .get(
      '/api/emergency-access/trusted',
      { ...SKIP_SIG, schema: { response: { 200: z.object({ contacts: z.array(EmergencyTrustedEntrySchema) }) } } },
      async (request) => {
        assertUserId(request);
        const rows = await prisma.emergencyAccess.findMany({
          where: { grantorUserId: request.userId },
          include: { credential: { include: { vault: true } }, grantee: true, granteeIdentity: true },
          orderBy: { createdAt: 'asc' },
        });

        const contacts: EmergencyTrustedEntry[] = rows.map((row) => ({
          id: row.id,
          grantee_user_id: row.granteeUserId,
          grantee_email: row.grantee.email,
          status: row.status,
          wait_time_days: row.waitTimeDays,
          created_at_millis: row.createdAt.getTime(),
          recovery_requested_at_millis: row.recoveryRequestedAt?.getTime() ?? null,
          deadline_millis: emergencyDeadlineMillis(row),
          vault_active: row.credential.vault.disabledAt === null,
          escrow: escrowRecordWire(row),
        }));

        return { contacts };
      }
    );

  // Vaults entrusted to me, invitations awaiting my acceptance included.
  app
    .withTypeProvider<ZodTypeProvider>()
    .get(
      '/api/emergency-access/granted',
      { ...SKIP_SIG, schema: { response: { 200: z.object({ grantors: z.array(EmergencyGrantedEntrySchema) }) } } },
      async (request) => {
        assertUserId(request);
        const rows = await prisma.emergencyAccess.findMany({
          where: { granteeUserId: request.userId },
          include: { grantor: true },
          orderBy: { createdAt: 'asc' },
        });

        const grantors: EmergencyGrantedEntry[] = rows.map((row) => ({
          id: row.id,
          grantor_user_id: row.grantorUserId,
          grantor_email: row.grantor.email,
          status: row.status,
          wait_time_days: row.waitTimeDays,
          created_at_millis: row.createdAt.getTime(),
          recovery_requested_at_millis: row.recoveryRequestedAt?.getTime() ?? null,
          deadline_millis: emergencyDeadlineMillis(row),
        }));

        return { grantors };
      }
    );

  // One-step designation: the dormant emergency credential, the wrapped phrase
  // and the binding signature all commit together; the contact only has to
  // consent (accept). Grantor-signed (vault open by construction).
  app.withTypeProvider<ZodTypeProvider>().post(
    '/api/emergency-access',
    {
      schema: {
        body: EmergencyDesignateBodySchema,
        response: { 200: z.object({ id: z.string().uuid(), status: EmergencyAccessStatusSchema }), ...errorResponses(400, 404, 409, 429) },
      },
    },
    async (request, reply) => {
      const body = request.body;
      assertUserId(request);
      const userId = request.userId;
      const now = Date.now();

      if (body.grantee_user_id === userId) return reply.status(400).send({ code: API_ERROR_EMERGENCY_SELF_DESIGNATION });

      // Counted in memory, NOT from the stored rows: a designation is deletable
      // (either party can revoke), so a row count resets the moment the caller
      // revokes, and designate -> revoke -> designate would loop forever, mailing
      // the target a designation + a revocation notice on every cycle. The durable
      // count below stays as a restart-surviving backstop, but the attempt counter
      // is what actually caps the loop.
      if (!designateAllowed(userId, now)) return reply.status(429).send({ code: API_ERROR_RATE_LIMIT_EMERGENCY });

      const recent = await prisma.emergencyAccess.count({
        where: { grantorUserId: userId, createdAt: { gte: new Date(now - DESIGNATE_RATE_LIMIT_WINDOW_MS) } },
      });
      if (recent >= DESIGNATE_RATE_LIMIT_MAX) return reply.status(429).send({ code: API_ERROR_RATE_LIMIT_EMERGENCY });

      const keyring = await prisma.vaultKeyring.findFirst({ where: { userId, disabledAt: null } });
      const identityKey = await activeIdentityWireKey(userId);
      if (!keyring || !identityKey) return reply.status(404).send({ code: API_ERROR_VAULT_NOT_FOUND });

      if (!(await onboardedUser(body.grantee_user_id))) return reply.status(400).send({ code: API_ERROR_EMERGENCY_CONTACT_NOT_ONBOARDED });

      // The pinned contact identity and the wrapped key version must be the
      // contact's CURRENT ones: the client just resolved them from the directory,
      // so any divergence means a stale or manipulated designation.
      const granteeIdentity = await prisma.identity.findFirst({ where: { userId: body.grantee_user_id, disabledAt: null } });
      const granteeKey = await prisma.encryptionKey.findFirst({ where: { userId: body.grantee_user_id, disabledAt: null } });
      if (
        !granteeIdentity ||
        !granteeKey ||
        !Buffer.from(base64ToUint8(body.grantee_identity_public_key)).equals(Buffer.from(granteeIdentity.signaturePublicKey)) ||
        granteeKey.version !== body.grantee_key_version
      )
        return reply.status(400).send({ code: API_ERROR_EMERGENCY_ESCROW_INVALID });

      const valid = await verifyEscrowSubmission(
        { grantorUserId: userId, granteeUserId: body.grantee_user_id, waitTimeDays: body.wait_time_days, credential: body.credential, escrow: body },
        identityKey
      );
      if (!valid) return reply.status(400).send({ code: API_ERROR_EMERGENCY_ESCROW_INVALID });

      let created: EmergencyAccess;

      try {
        created = await prisma.$transaction(
          async (tx) => {
            const credential = await tx.vaultCredential.create({
              data: {
                vaultId: keyring.id,
                type: 'emergency',
                wrappedVrk: body.credential.wrapped_vrk,
                authPublicKey: Buffer.from(base64ToUint8(body.credential.auth_public_key)),
                authPubSig: Buffer.from(base64ToUint8(body.credential.auth_pub_sig)),
                kdfOps: body.credential.kdf_ops,
                kdfMem: body.credential.kdf_mem,
                lang: body.credential.lang,
              },
            });

            return tx.emergencyAccess.create({
              data: {
                grantorUserId: userId,
                granteeUserId: body.grantee_user_id,
                status: 'invited',
                waitTimeDays: body.wait_time_days,
                credentialId: credential.id,
                wrappedPhraseForGrantee: body.wrapped_phrase_for_grantee,
                granteeIdentityId: granteeIdentity.id,
                granteeKeyVersion: body.grantee_key_version,
                escrowSignature: Buffer.from(base64ToUint8(body.escrow_signature)),
                escrowCreatedAt: new Date(body.escrow_created_at_millis),
              },
            });
          },
          { isolationLevel: 'Serializable' }
        );
      } catch (err) {
        // The (grantor, grantee) unique also lands here: one relationship per pair.
        if (isRetryableRegistrationError(err)) return reply.status(409).send({ code: API_ERROR_EMERGENCY_ALREADY_EXISTS });
        throw err;
      }

      const [grantor, grantee] = await Promise.all([emergencyRecipient(userId), emergencyRecipient(body.grantee_user_id)]);
      if (grantor && grantee)
        sendEmergencyDesignated({
          recipient: grantee.email,
          locale: grantee.locale,
          grantorEmail: grantor.email,
          waitTimeDays: body.wait_time_days,
          productUrl,
        }).catch(logEmailFailure('designated'));

      return { id: created.id, status: created.status };
    }
  );

  async function loadOwnedRow(id: string, where: { grantorUserId?: string; granteeUserId?: string }): Promise<RowWithCredential | null> {
    const row = await prisma.emergencyAccess.findUnique({ where: { id }, include: { credential: true, granteeIdentity: true } });

    if (!row) return null;
    if (where.grantorUserId && row.grantorUserId !== where.grantorUserId) return null;
    if (where.granteeUserId && row.granteeUserId !== where.granteeUserId) return null;

    return row;
  }

  // Consent, nothing more: the escrow already exists, dormant.
  app.withTypeProvider<ZodTypeProvider>().post(
    '/api/emergency-access/:id/accept',
    {
      ...SKIP_SIG,
      schema: {
        params: z.object({ id: z.string().uuid() }),
        response: { 200: z.object({ status: EmergencyAccessStatusSchema }), ...errorResponses(400, 404) },
      },
    },
    async (request, reply) => {
      assertUserId(request);
      const row = await loadOwnedRow(request.params.id, { granteeUserId: request.userId });
      if (!row) return reply.status(404).send({ code: API_ERROR_EMERGENCY_NOT_FOUND });
      if (row.status !== 'invited') return reply.status(400).send({ code: API_ERROR_EMERGENCY_BAD_STATUS });

      await prisma.emergencyAccess.update({ where: { id: row.id }, data: { status: 'confirmed' } });

      const [grantor, grantee] = await Promise.all([emergencyRecipient(row.grantorUserId), emergencyRecipient(row.granteeUserId)]);
      if (grantor && grantee)
        sendEmergencyAccepted({ recipient: grantor.email, locale: grantor.locale, granteeEmail: grantee.email }).catch(logEmailFailure('accepted'));

      return { status: 'confirmed' as const };
    }
  );

  // Change the wait time. It is inside the binding signature, so the grantor
  // re-signs over the EXISTING credential + capsule; only outside a running
  // recovery (a request must run under the wait it was made under).
  app.withTypeProvider<ZodTypeProvider>().put(
    '/api/emergency-access/:id',
    {
      schema: {
        params: z.object({ id: z.string().uuid() }),
        body: EmergencyUpdateBodySchema,
        response: { 200: z.object({ updated: z.boolean() }), ...errorResponses(400, 404) },
      },
    },
    async (request, reply) => {
      assertUserId(request);
      const body = request.body;
      const row = await loadOwnedRow(request.params.id, { grantorUserId: request.userId });
      if (!row) return reply.status(404).send({ code: API_ERROR_EMERGENCY_NOT_FOUND });
      if (row.status !== 'invited' && row.status !== 'confirmed') return reply.status(400).send({ code: API_ERROR_EMERGENCY_BAD_STATUS });

      const identityKey = await activeIdentityWireKey(request.userId);
      if (!identityKey) return reply.status(404).send({ code: API_ERROR_VAULT_NOT_FOUND });

      const valid = await verifyEscrowSubmission(
        {
          grantorUserId: row.grantorUserId,
          granteeUserId: row.granteeUserId,
          waitTimeDays: body.wait_time_days,
          credential: {
            // Reconstruct the stored credential's signed identifiers; wrapped_vrk
            // and kdf params are not inside the escrow signature.
            wrapped_vrk: row.credential.wrappedVrk,
            auth_public_key: uint8ToBase64(new Uint8Array(row.credential.authPublicKey)),
            auth_pub_sig: uint8ToBase64(new Uint8Array(row.credential.authPubSig)),
            kdf_ops: row.credential.kdfOps,
            kdf_mem: row.credential.kdfMem,
            lang: row.credential.lang,
          },
          escrow: {
            grantee_identity_public_key: uint8ToBase64(new Uint8Array(row.granteeIdentity.signaturePublicKey)),
            grantee_key_version: row.granteeKeyVersion,
            wrapped_phrase_for_grantee: row.wrappedPhraseForGrantee,
            escrow_signature: body.escrow_signature,
            escrow_created_at_millis: body.escrow_created_at_millis,
          },
        },
        identityKey
      );
      if (!valid) return reply.status(400).send({ code: API_ERROR_EMERGENCY_ESCROW_INVALID });

      await prisma.emergencyAccess.update({
        where: { id: row.id },
        data: {
          waitTimeDays: body.wait_time_days,
          escrowSignature: Buffer.from(base64ToUint8(body.escrow_signature)),
          escrowCreatedAt: new Date(body.escrow_created_at_millis),
        },
      });

      return { updated: true };
    }
  );

  // Replace the escrow material in place (fresh phrase + credential + capsule):
  // the one-click answer to "the contact rotated their encryption key". Only
  // outside a running recovery; the burn + re-arm of a granted recovery goes
  // through the keyring rewrite instead (vault.ts).
  app.withTypeProvider<ZodTypeProvider>().post(
    '/api/emergency-access/:id/rearm',
    {
      schema: {
        params: z.object({ id: z.string().uuid() }),
        body: EmergencyRearmBodySchema,
        response: { 200: z.object({ rearmed: z.boolean() }), ...errorResponses(400, 404, 409) },
      },
    },
    async (request, reply) => {
      const body = request.body;
      assertUserId(request);
      const userId = request.userId;
      const row = await loadOwnedRow(request.params.id, { grantorUserId: userId });
      if (!row) return reply.status(404).send({ code: API_ERROR_EMERGENCY_NOT_FOUND });
      if (row.status !== 'invited' && row.status !== 'confirmed') return reply.status(400).send({ code: API_ERROR_EMERGENCY_BAD_STATUS });

      const identityKey = await activeIdentityWireKey(userId);
      if (!identityKey) return reply.status(404).send({ code: API_ERROR_VAULT_NOT_FOUND });

      const granteeIdentity = await prisma.identity.findFirst({ where: { userId: row.granteeUserId, disabledAt: null } });
      const granteeKey = await prisma.encryptionKey.findFirst({ where: { userId: row.granteeUserId, disabledAt: null } });
      if (
        !granteeIdentity ||
        !granteeKey ||
        !Buffer.from(base64ToUint8(body.grantee_identity_public_key)).equals(Buffer.from(granteeIdentity.signaturePublicKey)) ||
        granteeKey.version !== body.grantee_key_version
      )
        return reply.status(400).send({ code: API_ERROR_EMERGENCY_ESCROW_INVALID });

      const valid = await verifyEscrowSubmission(
        { grantorUserId: userId, granteeUserId: row.granteeUserId, waitTimeDays: row.waitTimeDays, credential: body.credential, escrow: body },
        identityKey
      );
      if (!valid) return reply.status(400).send({ code: API_ERROR_EMERGENCY_ESCROW_INVALID });

      try {
        await prisma.$transaction(
          async (tx) => {
            const fresh = await tx.vaultCredential.create({
              data: {
                vaultId: row.credential.vaultId,
                type: 'emergency',
                wrappedVrk: body.credential.wrapped_vrk,
                authPublicKey: Buffer.from(base64ToUint8(body.credential.auth_public_key)),
                authPubSig: Buffer.from(base64ToUint8(body.credential.auth_pub_sig)),
                kdfOps: body.credential.kdf_ops,
                kdfMem: body.credential.kdf_mem,
                lang: body.credential.lang,
              },
            });

            await tx.emergencyAccess.update({
              where: { id: row.id },
              data: {
                credentialId: fresh.id,
                wrappedPhraseForGrantee: body.wrapped_phrase_for_grantee,
                granteeIdentityId: granteeIdentity.id,
                granteeKeyVersion: body.grantee_key_version,
                escrowSignature: Buffer.from(base64ToUint8(body.escrow_signature)),
                escrowCreatedAt: new Date(body.escrow_created_at_millis),
              },
            });

            await tx.vaultCredential.delete({ where: { id: row.credentialId } });
          },
          { isolationLevel: 'Serializable' }
        );
      } catch (err) {
        if (isRetryableRegistrationError(err)) return reply.status(409).send({ code: API_ERROR_CONCURRENT_REGISTRATION });
        throw err;
      }

      return { rearmed: true };
    }
  );

  // Revoke (grantor) or bow out / decline (contact). Deleting the credential
  // is what destroys the escrow; the relationship row cascades with it.
  app.withTypeProvider<ZodTypeProvider>().delete(
    '/api/emergency-access/:id',
    {
      ...SKIP_SIG,
      schema: { params: z.object({ id: z.string().uuid() }), response: { 200: z.object({ deleted: z.boolean() }), ...errorResponses(404) } },
    },
    async (request, reply) => {
      assertUserId(request);
      const userId = request.userId;
      const row = await prisma.emergencyAccess.findUnique({ where: { id: request.params.id }, include: { credential: true } });
      if (!row || (row.grantorUserId !== userId && row.granteeUserId !== userId))
        return reply.status(404).send({ code: API_ERROR_EMERGENCY_NOT_FOUND });

      await prisma.vaultCredential.deleteMany({ where: { id: row.credentialId } });

      const [grantor, grantee] = await Promise.all([emergencyRecipient(row.grantorUserId), emergencyRecipient(row.granteeUserId)]);
      if (userId === row.grantorUserId) {
        if (grantee && grantor)
          sendEmergencyRevoked({ recipient: grantee.email, locale: grantee.locale, grantorEmail: grantor.email }).catch(logEmailFailure('revoked'));
      } else if (grantor && grantee) {
        sendEmergencyDeclined({ recipient: grantor.email, locale: grantor.locale, granteeEmail: grantee.email }).catch(logEmailFailure('declined'));
      }

      return { deleted: true };
    }
  );

  // Start a recovery. Contact-signed (their vault must be open): a stolen
  // contact OIDC session alone cannot even trigger the flow. The notification
  // to the grantor is LOAD-BEARING (the wait only protects a grantor who can
  // learn about the request), so a failed send fails the whole call and leaves
  // the relationship untouched.
  app.withTypeProvider<ZodTypeProvider>().post(
    '/api/emergency-access/:id/initiate',
    {
      schema: {
        params: z.object({ id: z.string().uuid() }),
        response: { 200: z.object({ status: EmergencyAccessStatusSchema, deadline_millis: z.number().int() }), ...errorResponses(400, 404, 429) },
      },
    },
    async (request, reply) => {
      assertUserId(request);
      const userId = request.userId;
      const now = Date.now();

      if (!initiateAllowed(userId, now)) return reply.status(429).send({ code: API_ERROR_RATE_LIMIT_EMERGENCY });

      const row = await loadOwnedRow(request.params.id, { granteeUserId: userId });
      if (!row) return reply.status(404).send({ code: API_ERROR_EMERGENCY_NOT_FOUND });
      if (row.status !== 'confirmed') return reply.status(400).send({ code: API_ERROR_EMERGENCY_BAD_STATUS });

      const [grantor, grantee] = await Promise.all([emergencyRecipient(row.grantorUserId), emergencyRecipient(row.granteeUserId)]);
      if (!grantor || !grantee) return reply.status(404).send({ code: API_ERROR_EMERGENCY_NOT_FOUND });

      // Deliberately BEFORE the DB write, and AWAITED (not the fire-and-forget
      // `.catch(logEmailFailure)` the other handlers use): starting a recovery is
      // the one notification that is load-bearing, not a courtesy. The grantor
      // MUST learn a request began so they can refuse it during the wait window.
      // If the email cannot be delivered we throw here (500) and the request is
      // never recorded, so a recovery can never start silently; the contact just
      // retries. The trade-off is accepted: a working notification matters more
      // than recording the request.
      await sendEmergencyRecoveryRequested({
        recipient: grantor.email,
        locale: grantor.locale,
        granteeEmail: grantee.email,
        waitTimeDays: row.waitTimeDays,
        deadlineMillis: now + row.waitTimeDays * 24 * 60 * 60 * 1000,
        productUrl,
      });

      // Guarded update: a concurrent initiate/reject resolves to exactly one
      // running request (count 0 means the status moved under us).
      const updated = await prisma.emergencyAccess.updateMany({
        where: { id: row.id, status: 'confirmed' },
        data: { status: 'recoveryRequested', recoveryRequestedAt: new Date(now), lastNotifiedAt: new Date(now) },
      });
      if (updated.count === 0) return reply.status(400).send({ code: API_ERROR_EMERGENCY_BAD_STATUS });

      return { status: 'recoveryRequested' as const, deadline_millis: now + row.waitTimeDays * 24 * 60 * 60 * 1000 };
    }
  );

  // The contact withdraws their own request. Fail-safe, so JWT-only.
  app.withTypeProvider<ZodTypeProvider>().post(
    '/api/emergency-access/:id/cancel',
    {
      ...SKIP_SIG,
      schema: {
        params: z.object({ id: z.string().uuid() }),
        response: { 200: z.object({ status: EmergencyAccessStatusSchema }), ...errorResponses(400, 404) },
      },
    },
    async (request, reply) => {
      assertUserId(request);
      const row = await loadOwnedRow(request.params.id, { granteeUserId: request.userId });
      if (!row) return reply.status(404).send({ code: API_ERROR_EMERGENCY_NOT_FOUND });
      if (row.status !== 'recoveryRequested') return reply.status(400).send({ code: API_ERROR_EMERGENCY_BAD_STATUS });

      await prisma.emergencyAccess.update({
        where: { id: row.id },
        data: { status: 'confirmed', recoveryRequestedAt: null, lastNotifiedAt: null },
      });

      const [grantor, grantee] = await Promise.all([emergencyRecipient(row.grantorUserId), emergencyRecipient(row.granteeUserId)]);
      if (grantor && grantee)
        sendEmergencyRecoveryCancelled({ recipient: grantor.email, locale: grantor.locale, granteeEmail: grantee.email }).catch(
          logEmailFailure('cancelled')
        );

      return { status: 'confirmed' as const };
    }
  );

  // The grantor's veto: allowed while a request runs AND after auto-approval
  // (re-dormanting the credential, which kills a revealed-but-unused phrase).
  // Deliberately JWT-only: the grantor by definition may have no vault left,
  // and the worst a stolen session can do here is deny a recovery.
  app.withTypeProvider<ZodTypeProvider>().post(
    '/api/emergency-access/:id/reject',
    {
      ...SKIP_SIG,
      schema: {
        params: z.object({ id: z.string().uuid() }),
        response: { 200: z.object({ status: EmergencyAccessStatusSchema }), ...errorResponses(400, 404) },
      },
    },
    async (request, reply) => {
      assertUserId(request);
      const row = await loadOwnedRow(request.params.id, { grantorUserId: request.userId });
      if (!row) return reply.status(404).send({ code: API_ERROR_EMERGENCY_NOT_FOUND });
      if (row.status !== 'recoveryRequested' && row.status !== 'recoveryApproved')
        return reply.status(400).send({ code: API_ERROR_EMERGENCY_BAD_STATUS });

      await prisma.emergencyAccess.update({
        where: { id: row.id },
        data: { status: 'confirmed', recoveryRequestedAt: null, lastNotifiedAt: null },
      });

      const [grantor, grantee] = await Promise.all([emergencyRecipient(row.grantorUserId), emergencyRecipient(row.granteeUserId)]);
      if (grantee && grantor)
        sendEmergencyRecoveryRejected({ recipient: grantee.email, locale: grantee.locale, grantorEmail: grantor.email }).catch(
          logEmailFailure('rejected')
        );

      return { status: 'confirmed' as const };
    }
  );

  // Release the capsule. Contact-signed. The wait-deadline ARITHMETIC is the
  // authority (the cron only emails and flips the visible status), re-checked
  // here on every call; repeatable while granted (the phrase is only burned by
  // the grantor's forced rotation). Releases nothing but the capsule + the
  // signed escrow record + the wordlist language: never items, never keys.
  app
    .withTypeProvider<ZodTypeProvider>()
    .post(
      '/api/emergency-access/:id/recover',
      { schema: { params: z.object({ id: z.string().uuid() }), response: { 200: EmergencyRecoverResponseSchema, ...errorResponses(400, 404) } } },
      async (request, reply) => {
        assertUserId(request);
        const row = await loadOwnedRow(request.params.id, { granteeUserId: request.userId });
        if (!row) return reply.status(404).send({ code: API_ERROR_EMERGENCY_NOT_FOUND });

        const now = Date.now();
        if (!emergencyApprovalHolds(row, now)) return reply.status(400).send({ code: API_ERROR_EMERGENCY_BAD_STATUS });

        // Lazy flip when the cron has not run yet, with the approval emails it
        // would have sent (best-effort; the release itself never depends on them).
        if (row.status === 'recoveryRequested') {
          await prisma.emergencyAccess.updateMany({ where: { id: row.id, status: 'recoveryRequested' }, data: { status: 'recoveryApproved' } });

          const [grantor, grantee] = await Promise.all([emergencyRecipient(row.grantorUserId), emergencyRecipient(row.granteeUserId)]);
          if (grantor && grantee) {
            sendEmergencyRecoveryApprovedGrantor({ recipient: grantor.email, locale: grantor.locale, granteeEmail: grantee.email, productUrl }).catch(
              logEmailFailure('approved grantor')
            );
            sendEmergencyRecoveryApprovedContact({ recipient: grantee.email, locale: grantee.locale, grantorEmail: grantor.email, productUrl }).catch(
              logEmailFailure('approved contact')
            );
          }
        }

        return {
          id: row.id,
          grantor_user_id: row.grantorUserId,
          wait_time_days: row.waitTimeDays,
          // The emergency phrase was generated in the GRANTOR's wordlist language,
          // recorded on the escrow credential itself.
          lang: row.credential.lang,
          escrow: escrowRecordWire(row),
        };
      }
    );
}
