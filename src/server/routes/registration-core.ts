// Core of the two-phase key registration, factored out of the public-keys
// route so it can run either on its own (POST /register/complete) or folded
// into the vault bootstrap transaction (POST /api/vault). Keeping the write
// logic here means both entry points enforce the exact same invariants:
// single active key/identity, monotonic versioning, immutable records, and
// rejection of keys claimed by another user.
import { PrismaClientKnownRequestError } from '@prisma/client/runtime/client';

import { base64ToUint8, importPublicKeyFromBytes, uint8ToBase64 } from '@encryption/src/crypto/encryption-backup';
import { verifyChallengeResponse } from '@encryption/src/crypto/key-possession-challenge';
import { encodePopChallengeMessage } from '@encryption/src/crypto/key-registration';
import { verifyDetached } from '@encryption/src/crypto/signature';
import type { Prisma } from '@encryption/src/generated/prisma/client';
import { prisma } from '@encryption/src/prisma/client';
import {
  API_ERROR_CHALLENGE_EXPIRED,
  API_ERROR_CHALLENGE_INVALID_RESPONSE,
  API_ERROR_CHALLENGE_NOT_FOUND,
  API_ERROR_ENCRYPTION_KEY_TAKEN,
  API_ERROR_IDENTITY_TAKEN,
  API_ERROR_INVALID_CHALLENGE_SIGNATURE,
  API_ERROR_KEY_VERSION_CONFLICT,
  API_ERROR_NO_SERVER_VAULT,
  API_ERROR_RATE_LIMIT_KEYS,
} from '@encryption/src/shared/error-codes';

export const RATE_LIMIT_WINDOW_DAYS = 30;
export const RATE_LIMIT_MAX_CREATIONS = 10;

// PostgreSQL serialization-failure (40001) surfaces as P2034 in Prisma, and a
// unique-constraint violation as P2002. Either can happen when two completes
// for the same user race for the same next version; both are safe to retry.
const PRISMA_SERIALIZATION_FAILURE = 'P2034';
const PRISMA_UNIQUE_VIOLATION = 'P2002';

export function isRetryableRegistrationError(err: unknown): boolean {
  return err instanceof PrismaClientKnownRequestError && (err.code === PRISMA_SERIALIZATION_FAILURE || err.code === PRISMA_UNIQUE_VIOLATION);
}

// The stored challenge row, typed off the client so we don't depend on the
// generated model's exported name.
export type ChallengeRow = NonNullable<Awaited<ReturnType<typeof prisma.keyPossessionChallenge.findUnique>>>;

// A read-only proof check that ran before any write. `ok` carries the verified
// challenge row to feed the transaction; the failure carries an HTTP mapping.
export type PossessionCheck = { ok: true; challenge: ChallengeRow } | { ok: false; status: number; code: string };

// Discriminated result from the write transaction. Returning a value (rather
// than throwing) lets every business-logic exit commit a clean no-op tx while
// still mapping to a stable HTTP code.
export type CompleteTxResult =
  | {
      kind: 'success';
      userId: string;
      identityId: string;
      encryptionPublicKey: string;
      signaturePublicKey: string;
      keyBindingSignature: string;
      version: number;
      createdAtMillis: number;
    }
  | { kind: 'consumed' }
  | { kind: 'no_vault' }
  | { kind: 'version_conflict' }
  | { kind: 'rate_limit' }
  | { kind: 'identity_taken' }
  | { kind: 'encryption_key_taken' };

// Enforce the invariant "exactly one active EncryptionKey + Identity per
// user": disable every other active row for the user, then (re)enable the
// chosen pair.
export async function activateRegistration(tx: Prisma.TransactionClient, userId: string, encryptionKeyId: string, identityId: string): Promise<void> {
  await tx.encryptionKey.updateMany({
    where: { userId, disabledAt: null, id: { not: encryptionKeyId } },
    data: { disabledAt: new Date() },
  });
  await tx.encryptionKey.update({
    where: { id: encryptionKeyId },
    data: { disabledAt: null },
  });
  await tx.identity.updateMany({
    where: { userId, disabledAt: null, id: { not: identityId } },
    data: { disabledAt: new Date() },
  });
  await tx.identity.update({
    where: { id: identityId },
    data: { disabledAt: null },
  });
}

// Read-only proof-of-possession verification, done before entering the write
// transaction. Loads the challenge, checks ownership + expiry, then verifies
// the encryption-key HMAC PoP and the signature-key Ed25519 PoP. The state it
// reads is re-checked inside the transaction to avoid TOCTOU.
export async function loadAndVerifyPossession(
  userId: string,
  body: { challenge_id: string; response: string; challenge_signature: string }
): Promise<PossessionCheck> {
  const challenge = await prisma.keyPossessionChallenge.findUnique({ where: { id: body.challenge_id } });

  // Treat "not mine" the same as "not found" — never confirm to a caller that
  // someone else has a challenge with this id.
  if (!challenge || challenge.userId !== userId) {
    return { ok: false, status: 404, code: API_ERROR_CHALLENGE_NOT_FOUND };
  }

  if (challenge.expiresAt.getTime() < Date.now()) {
    await prisma.keyPossessionChallenge.deleteMany({ where: { id: challenge.id } });

    return { ok: false, status: 410, code: API_ERROR_CHALLENGE_EXPIRED };
  }

  // Encryption-key PoP: the HMAC the client derived from decapsulating our
  // X-Wing ciphertext must match the tag we stored at init.
  const received = base64ToUint8(body.response);
  const hmacOk = await verifyChallengeResponse(new Uint8Array(challenge.expectedHmac), received);

  if (!hmacOk) {
    // Don't delete on first miss — the HMAC could be a transport glitch. Keep
    // the row until expiry; the caller can retry with the same id.
    return { ok: false, status: 400, code: API_ERROR_CHALLENGE_INVALID_RESPONSE };
  }

  // Signature-key PoP: an Ed25519 signature over the challenge id, made by the
  // candidate identity key. Proves the caller holds the signature private key.
  let signaturePopOk = false;

  try {
    const signatureRawKey = importPublicKeyFromBytes(challenge.signaturePublicKey);
    const challengeMessage = encodePopChallengeMessage(challenge.id);
    signaturePopOk = await verifyDetached(base64ToUint8(body.challenge_signature), challengeMessage, signatureRawKey);
  } catch {
    signaturePopOk = false;
  }

  if (!signaturePopOk) {
    return { ok: false, status: 400, code: API_ERROR_INVALID_CHALLENGE_SIGNATURE };
  }

  return { ok: true, challenge };
}

// The write half of registration. MUST run inside a Serializable transaction
// (so concurrent completes can't both mint a fresh active key) and the caller
// MUST retry on isRetryableRegistrationError. Re-reads and deletes the
// challenge inside the tx so the row doubles as a single-use mutex.
/**
 * Resolve or create the identity for a signature key so a following
 * completeRegistrationInTx can register the encryption key under it. This is the
 * ONLY place an identity is minted, and it is used ONLY by the atomic bootstrap
 * (POST /api/vault), which creates the identity together with its vault keyring in
 * the same transaction. Keeping minting here couples "new identity" with "new
 * vault" by construction, so no identity ever exists on the server without a vault.
 */
export async function mintIdentityInTx(
  tx: Prisma.TransactionClient,
  userId: string,
  signaturePublicKey: ChallengeRow['signaturePublicKey']
): Promise<{ kind: 'ok' } | { kind: 'identity_taken' }> {
  const existingIdentity = await tx.identity.findUnique({ where: { signaturePublicKey } });

  if (existingIdentity) {
    // The identity key is globally unique: a row for someone else is a takeover.
    if (existingIdentity.userId !== userId) {
      return { kind: 'identity_taken' };
    }
    // A re-onboard that reuses the same signature key just re-enables it.
    if (existingIdentity.disabledAt) {
      await tx.identity.update({ where: { id: existingIdentity.id }, data: { disabledAt: null } });
    }

    return { kind: 'ok' };
  }

  const genAggregate = await tx.identity.aggregate({ where: { userId }, _max: { generation: true } });
  const generation = (genAggregate._max.generation ?? 0) + 1;

  // A fresh identity is not cross-signed by any previous one here: re-onboarding
  // is a deliberate new identity. The continuity chain is reserved for a future
  // identity-migration flow.
  await tx.identity.create({ data: { userId, signaturePublicKey, generation } });

  return { kind: 'ok' };
}

export async function completeRegistrationInTx(tx: Prisma.TransactionClient, userId: string, challenge: ChallengeRow): Promise<CompleteTxResult> {
  const fresh = await tx.keyPossessionChallenge.findUnique({ where: { id: challenge.id } });

  if (!fresh) {
    return { kind: 'consumed' };
  }

  // --- Reactivate path -----------------------------------------------------
  // A registration record is IMMUTABLE (its version/createdAt/binding are
  // signed together). Restoring an already-registered key must reactivate its
  // existing row. Keyed on the globally-unique encryption key.
  const existing = await tx.encryptionKey.findUnique({
    where: { encryptionPublicKey: fresh.encryptionPublicKey },
    include: { identity: true },
  });

  if (existing) {
    // The key belongs to someone else — astronomically unlikely for a real
    // X-Wing key, so treat it as an attempted takeover.
    if (existing.userId !== userId) {
      return { kind: 'encryption_key_taken' };
    }

    await activateRegistration(tx, userId, existing.id, existing.identityId);

    // WARM reactivation: re-presenting an already-registered key proves the
    // caller controls this identity (both PoPs passed), so also bring the
    // identity's vault keyring back as the active one, demoting any other. This
    // keeps identity + vault coupled WITHOUT the recovery phrase — the device
    // re-registering already holds the VRK locally, so no wrappedVrk is released
    // here (that only happens on the phrase-gated /fetch). Mirrors the keyring
    // flip in /api/vault/reactivate. Only the reactivate path (existing key) does
    // this; a brand-new key goes through the new-key path + bootstrap instead.
    const keyring = await tx.vaultKeyring.findFirst({
      where: { userId, identityId: existing.identityId },
      orderBy: { createdAt: 'desc' },
    });

    if (keyring) {
      await tx.vaultKeyring.updateMany({ where: { userId, disabledAt: null }, data: { disabledAt: new Date() } });
      await tx.vaultKeyring.update({ where: { id: keyring.id }, data: { disabledAt: null } });
    }

    await tx.keyPossessionChallenge.delete({ where: { id: challenge.id } });

    return {
      kind: 'success',
      userId: existing.userId,
      identityId: existing.identityId,
      encryptionPublicKey: uint8ToBase64(existing.encryptionPublicKey),
      signaturePublicKey: uint8ToBase64(existing.identity.signaturePublicKey),
      keyBindingSignature: uint8ToBase64(existing.keyBindingSignature),
      version: existing.version,
      createdAtMillis: existing.createdAt.getTime(),
    };
  }

  // --- New encryption key path ---------------------------------------------
  // Register a new encryption key under an EXISTING identity: either a rotation,
  // or the key created right after bootstrap minted the identity in this same
  // transaction. This path NEVER mints an identity (that is mintIdentityInTx's
  // job, bootstrap-only). Since an identity is always created together with its
  // vault keyring, an identity existing here means a vault exists behind it.
  const existingIdentity = await tx.identity.findUnique({ where: { signaturePublicKey: fresh.signaturePublicKey } });

  if (existingIdentity && existingIdentity.userId !== userId) {
    return { kind: 'identity_taken' };
  }

  // No identity on the server for this signature key means the keys were never
  // bootstrapped (an orphaned local vault). Registering them would leave a
  // directory entry with no vault: refuse so the client onboards from scratch.
  if (!existingIdentity) {
    return { kind: 'no_vault' };
  }

  // Rate-limit at completion only: an attacker who can't pass PoP can't burn
  // the user's quota, while honest churners are bounded.
  const windowStart = new Date();
  windowStart.setDate(windowStart.getDate() - RATE_LIMIT_WINDOW_DAYS);
  const recentCreations = await tx.encryptionKey.count({ where: { userId, createdAt: { gte: windowStart } } });

  if (recentCreations >= RATE_LIMIT_MAX_CREATIONS) {
    return { kind: 'rate_limit' };
  }

  // Monotonic versioning: the candidate version must be exactly (current max
  // for this user) + 1. The signature covers `version`, so the server can't
  // silently renumber — a mismatch means the client signed a stale view.
  const aggregate = await tx.encryptionKey.aggregate({ where: { userId }, _max: { version: true } });
  const expectedVersion = (aggregate._max.version ?? 0) + 1;

  if (fresh.version !== expectedVersion) {
    return { kind: 'version_conflict' };
  }

  // Register under the existing identity (rotation, or the identity bootstrap
  // just minted). Re-enable it if it was disabled.
  const identityId = existingIdentity.id;

  if (existingIdentity.disabledAt) {
    await tx.identity.update({ where: { id: existingIdentity.id }, data: { disabledAt: null } });
  }

  const created = await tx.encryptionKey.create({
    data: {
      userId,
      identityId,
      encryptionPublicKey: fresh.encryptionPublicKey,
      keyBindingSignature: fresh.keyBindingSignature,
      version: fresh.version,
      // The signed timestamp becomes the row's createdAt, so later
      // verifications (which sign over created_at) keep matching.
      createdAt: fresh.signedCreatedAt,
    },
    include: { identity: true },
  });

  await activateRegistration(tx, userId, created.id, identityId);
  await tx.keyPossessionChallenge.delete({ where: { id: challenge.id } });

  return {
    kind: 'success',
    userId: created.userId,
    identityId,
    encryptionPublicKey: uint8ToBase64(created.encryptionPublicKey),
    signaturePublicKey: uint8ToBase64(created.identity.signaturePublicKey),
    keyBindingSignature: uint8ToBase64(created.keyBindingSignature),
    version: created.version,
    createdAtMillis: created.createdAt.getTime(),
  };
}

// Map a non-success transaction result to its HTTP status/code. Returns null
// for `success` (the caller shapes the success body itself, which differs
// between the standalone route and the vault bootstrap).
export function completeResultToHttpError(result: CompleteTxResult): { status: number; code: string; params?: Record<string, unknown> } | null {
  switch (result.kind) {
    case 'success':
      return null;
    case 'consumed':
      return { status: 404, code: API_ERROR_CHALLENGE_NOT_FOUND };
    case 'no_vault':
      return { status: 409, code: API_ERROR_NO_SERVER_VAULT };
    case 'version_conflict':
      return { status: 409, code: API_ERROR_KEY_VERSION_CONFLICT };
    case 'identity_taken':
      return { status: 409, code: API_ERROR_IDENTITY_TAKEN };
    case 'encryption_key_taken':
      return { status: 409, code: API_ERROR_ENCRYPTION_KEY_TAKEN };
    case 'rate_limit':
      return {
        status: 429,
        code: API_ERROR_RATE_LIMIT_KEYS,
        params: { max: RATE_LIMIT_MAX_CREATIONS, days: RATE_LIMIT_WINDOW_DAYS },
      };
  }
}
