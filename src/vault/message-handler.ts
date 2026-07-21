import {
  MSG_VAULT_ACCEPT_FINGERPRINT,
  MSG_VAULT_APPROVE_DEVICE,
  MSG_VAULT_CHANGE_RECOVERY_PHRASE,
  MSG_VAULT_CHECK_FINGERPRINTS,
  MSG_VAULT_COMMIT_STAGED,
  MSG_VAULT_COMPLETE_DEVICE_APPROVAL,
  MSG_VAULT_DECRYPT_WITH_KEY,
  MSG_VAULT_DESTROY_KEYS,
  MSG_VAULT_ENCRYPT_NESTED_WITHOUT_KEY,
  MSG_VAULT_ENCRYPT_WITHOUT_KEY,
  MSG_VAULT_ENCRYPT_WITH_KEY,
  MSG_VAULT_FETCH_PUBLIC_KEYS,
  MSG_VAULT_GENERATE_KEYS,
  MSG_VAULT_GET_KNOWN_FINGERPRINTS,
  MSG_VAULT_GET_PUBLIC_KEY,
  MSG_VAULT_HAS_KEYS,
  MSG_VAULT_PREPARE_ONBOARDING,
  MSG_VAULT_REACTIVATE,
  MSG_VAULT_REFUSE_FINGERPRINT,
  MSG_VAULT_RESOLVE_USER,
  MSG_VAULT_RESPOND_TO_KEY_CHALLENGE,
  MSG_VAULT_RESTORE_FROM_PHRASE,
  MSG_VAULT_RESULT,
  MSG_VAULT_REWRAP_NESTED_KEY,
  MSG_VAULT_SHARE_KEYS,
  MSG_VAULT_SIGN_KEY_REGISTRATION,
  MSG_VAULT_SIGN_REQUEST,
  MSG_VAULT_START_DEVICE_APPROVAL,
  MSG_VAULT_SYNC,
  MSG_VAULT_UNCOMMIT_STAGED,
  MSG_VAULT_WRAP_NESTED_KEY,
} from '@encryption/src/shared/constants';
import { PRIVILEGED_OPERATIONS, type VaultResponse } from '@encryption/src/shared/schemas/post-message';
import { VaultError, VaultErrorCode, classifyVaultError } from '@encryption/src/shared/vault-error';
import { handleCommitStagedVault, handleUncommitStagedVault } from '@encryption/src/vault/operations/commit-staged';
import { handleDecryptWithKey } from '@encryption/src/vault/operations/decrypt';
import { handleDestroyKeys } from '@encryption/src/vault/operations/destroy-keys';
import { handleApproveDevice, handleCompleteDeviceApproval, handleStartDeviceApproval } from '@encryption/src/vault/operations/device-approval-flow';
import { handleEncryptNestedWithoutKey, handleEncryptWithKey, handleEncryptWithoutKey } from '@encryption/src/vault/operations/encrypt';
import { handleFetchPublicKeys } from '@encryption/src/vault/operations/fetch-public-keys';
import {
  handleAcceptFingerprintBySub,
  handleCheckFingerprintsBySubs,
  handleGetKnownFingerprints,
  handleRefuseFingerprintBySub,
} from '@encryption/src/vault/operations/fingerprint-registry';
import { handleGenerateKeys } from '@encryption/src/vault/operations/generate-keys';
import { handleGetPublicKey, handleHasKeys } from '@encryption/src/vault/operations/key-management';
import { handleChangeRecoveryPhrase, handlePrepareOnboarding } from '@encryption/src/vault/operations/onboarding';
import { resolveTrustedRecipientKeys } from '@encryption/src/vault/operations/recipient-trust';
import { handleRespondToKeyChallenge } from '@encryption/src/vault/operations/respond-to-key-challenge';
import { handleRewrapNestedKey } from '@encryption/src/vault/operations/rewrap-nested-key';
import { handleShareKeys } from '@encryption/src/vault/operations/share-keys';
import { handleSignKeyRegistration } from '@encryption/src/vault/operations/sign-key-registration';
import { handleSignRequest } from '@encryption/src/vault/operations/sign-request';
import { handleReactivateVault, handleRestoreFromPhrase } from '@encryption/src/vault/operations/vault-restore';
import { handleSync } from '@encryption/src/vault/operations/vault-sync-run';
import { handleWrapNestedKey } from '@encryption/src/vault/operations/wrap-nested-key';
import { isInterfaceOrigin, isOriginAllowed } from '@encryption/src/vault/origin-guard';
import { resolveBoundaryUser } from '@encryption/src/vault/user-resolution';
import { ensureVaultSyncDriver } from '@encryption/src/vault/vault-sync-driver';

async function dispatch(data: unknown, userId: string): Promise<unknown> {
  // Extract type and payload from the message. Payload may contain ArrayBuffer
  // which Zod cannot validate, so we validate the message structure only.
  const msg = data as { type: string; payload?: Record<string, unknown> };
  const payload = msg.payload ?? {};

  switch (msg.type) {
    // Product operations (any allowed origin)
    case MSG_VAULT_HAS_KEYS:
      return handleHasKeys(userId);
    case MSG_VAULT_GET_PUBLIC_KEY:
      return handleGetPublicKey(userId);
    case MSG_VAULT_ENCRYPT_WITHOUT_KEY: {
      // Trust gate at the boundary: the product passes recipient SUBS (the only
      // id space it holds); the vault resolves them to encryption keys ONLY for
      // identities whose binding verifies and that are TOFU-trusted (trust is
      // keyed internally). A product can never inject raw keys.
      const p = payload as { data: ArrayBuffer; recipientSubs: string[] };
      const userPublicKeys = await resolveTrustedRecipientKeys(userId, p.recipientSubs ?? []);

      return handleEncryptWithoutKey(userId, { data: p.data, userPublicKeys });
    }
    case MSG_VAULT_ENCRYPT_NESTED_WITHOUT_KEY:
      return handleEncryptNestedWithoutKey(
        userId,
        payload as {
          data: ArrayBuffer;
          encryptedSymmetricKey: ArrayBuffer;
          encryptedKeyChain?: ArrayBuffer[];
        }
      );
    case MSG_VAULT_ENCRYPT_WITH_KEY:
      return handleEncryptWithKey(userId, payload as { data: ArrayBuffer; encryptedSymmetricKey: ArrayBuffer; encryptedKeyChain?: ArrayBuffer[] });
    case MSG_VAULT_DECRYPT_WITH_KEY:
      return handleDecryptWithKey(
        userId,
        payload as { encryptedData: ArrayBuffer; encryptedSymmetricKey: ArrayBuffer; encryptedKeyChain?: ArrayBuffer[] }
      );
    case MSG_VAULT_REWRAP_NESTED_KEY:
      return handleRewrapNestedKey(
        userId,
        payload as {
          encryptedSymmetricKey: ArrayBuffer;
          oldEncryptedKey: ArrayBuffer;
          oldEncryptedKeyChain?: ArrayBuffer[];
          newEncryptedKeyChain?: ArrayBuffer[];
        }
      );
    case MSG_VAULT_WRAP_NESTED_KEY:
      return handleWrapNestedKey(
        userId,
        payload as {
          userEncryptedKey: ArrayBuffer;
          newEntryEncryptedSymmetricKey: ArrayBuffer;
          newEncryptedKeyChain?: ArrayBuffer[];
        }
      );
    case MSG_VAULT_SHARE_KEYS: {
      // Same trust gate as encrypt-without-key: resolve recipient subs to
      // verified, TOFU-trusted encryption keys before the wrap.
      const p = payload as { encryptedSymmetricKey: ArrayBuffer; recipientSubs: string[]; encryptedKeyChain?: ArrayBuffer[] };
      const userPublicKeys = await resolveTrustedRecipientKeys(userId, p.recipientSubs ?? []);

      return handleShareKeys(userId, { encryptedSymmetricKey: p.encryptedSymmetricKey, userPublicKeys, encryptedKeyChain: p.encryptedKeyChain });
    }
    case MSG_VAULT_FETCH_PUBLIC_KEYS:
      // `subs` is the product/interface form: results come back keyed by the
      // queried subs, which is all a product correlates on. `userIds` is for
      // vault-internal callers. Entries carry the internal id as a field
      // (public directory data, and the wrappers here need it for TOFU), but
      // products have no use for it.
      return handleFetchPublicKeys(userId, payload as { userIds?: string[]; subs?: string[] });
    case MSG_VAULT_CHECK_FINGERPRINTS:
      // Callers hold subs; the wrapper resolves them to the internal ids the
      // TOFU store keys on and maps results back.
      return handleCheckFingerprintsBySubs(userId, payload as { userFingerprints: Record<string, string> });
    case MSG_VAULT_ACCEPT_FINGERPRINT:
      return handleAcceptFingerprintBySub(userId, payload as { sub: string; fingerprint: string });
    case MSG_VAULT_REFUSE_FINGERPRINT:
      return handleRefuseFingerprintBySub(userId, payload as { sub: string; fingerprint: string });
    case MSG_VAULT_GET_KNOWN_FINGERPRINTS:
      return handleGetKnownFingerprints(userId);

    // Privileged operations (encryption only)
    case MSG_VAULT_RESOLVE_USER:
      // The boundary above already did the work: it adopted the interface's
      // declared internal id (persisting the sub -> id alias) or resolved the
      // sub through the alias/registry chain. Echoing the outcome lets the
      // interface obtain its id with no OIDC session (expired-token settings);
      // the unresolvable case answers null before dispatch, like has-keys.
      return { internalUserId: userId };
    case MSG_VAULT_GENERATE_KEYS:
      return handleGenerateKeys(userId);
    case MSG_VAULT_COMMIT_STAGED:
      return handleCommitStagedVault(userId);
    case MSG_VAULT_UNCOMMIT_STAGED:
      return handleUncommitStagedVault(userId);
    case MSG_VAULT_SIGN_KEY_REGISTRATION:
      return handleSignKeyRegistration(userId, payload as { version: number; createdAtMillis: number });
    case MSG_VAULT_RESPOND_TO_KEY_CHALLENGE:
      return handleRespondToKeyChallenge(userId, payload as { challengeId: string; ciphertext: string });
    case MSG_VAULT_DESTROY_KEYS:
      return handleDestroyKeys(userId);
    case MSG_VAULT_PREPARE_ONBOARDING:
      return handlePrepareOnboarding(userId, payload as { lang?: 'french' | 'english'; version?: number; generation?: number; reusePhrase?: string });
    case MSG_VAULT_CHANGE_RECOVERY_PHRASE:
      return handleChangeRecoveryPhrase(userId, payload as { lang?: 'french' | 'english' });
    case MSG_VAULT_RESTORE_FROM_PHRASE:
      return handleRestoreFromPhrase(userId, payload as { recoveryPhrase: string; token: string });
    case MSG_VAULT_REACTIVATE:
      return handleReactivateVault(userId, payload as { recoveryPhrase: string; token: string });
    case MSG_VAULT_SYNC:
      return handleSync(userId, payload as { token?: string | null });
    case MSG_VAULT_SIGN_REQUEST:
      return handleSignRequest(userId, payload as { method: string; path: string; body?: string });
    case MSG_VAULT_START_DEVICE_APPROVAL:
      return handleStartDeviceApproval();
    case MSG_VAULT_COMPLETE_DEVICE_APPROVAL:
      return handleCompleteDeviceApproval(userId, payload as { wrappedDeviceBootstrap: string; token?: string | null });
    case MSG_VAULT_APPROVE_DEVICE:
      return handleApproveDevice(userId, payload as { devicePublicKey: string; expectedDecimal: string });
  }
}

export function setupMessageHandler(): void {
  window.addEventListener('message', async (event: MessageEvent) => {
    if (!isOriginAllowed(event.origin) && !isInterfaceOrigin(event.origin)) {
      return;
    }

    if (!event.data || typeof event.data !== 'object' || !('type' in event.data) || !('requestId' in event.data)) {
      return;
    }

    const requestId = event.data.requestId as string;
    const operationType = event.data.type as string;

    // In dev mode, allow any allowed origin to perform privileged operations
    // (e.g., benchmark page on localhost:7201 can generate keys without OIDC)
    const isPrivilegedAllowed = isInterfaceOrigin(event.origin) || (import.meta.env.DEV && isOriginAllowed(event.origin));

    if (PRIVILEGED_OPERATIONS.has(operationType) && !isPrivilegedAllowed) {
      const response: VaultResponse = {
        type: MSG_VAULT_RESULT,
        requestId,
        success: false,
        error: `Operation "${operationType}" is only allowed from encryption.`,
        code: VaultErrorCode.PRIVILEGED_ORIGIN_REQUIRED,
      };

      event.source?.postMessage(response, { targetOrigin: event.origin });

      return;
    }

    let response: VaultResponse;

    try {
      // Products declare the OIDC sub (`suiteUserId`); the interface, which
      // learned the internal id from /api/me, declares `internalUserId` too.
      // The sub stops HERE: everything past this boundary (cache keys, TOFU,
      // signed payloads, request proofs) speaks the internal id only. The
      // adopt-vs-resolve decision lives in resolveBoundaryUser.
      const declaredSub = event.data.suiteUserId as string | undefined;
      const declaredInternalId = event.data.internalUserId as string | undefined;

      const userId = await resolveBoundaryUser(declaredSub, declaredInternalId, isPrivilegedAllowed);

      if (!userId) {
        // A sub with no resolvable internal id means "this user never
        // registered anything" (or the registry is unreachable with nothing
        // cached). `has-keys` has a truthful answer for that, and
        // `resolve-user`'s whole job is to report resolvability, so it answers
        // null rather than failing; everything else fails with a stable,
        // actionable code.
        if (operationType === MSG_VAULT_HAS_KEYS || operationType === MSG_VAULT_RESOLVE_USER) {
          const data = operationType === MSG_VAULT_HAS_KEYS ? { hasKeys: false } : { internalUserId: null };
          const response: VaultResponse = { type: MSG_VAULT_RESULT, requestId, success: true, data };
          event.source?.postMessage(response, { targetOrigin: event.origin });

          return;
        }

        throw new VaultError(VaultErrorCode.UNRESOLVED_USER, 'No encryption account is known for this user yet.');
      }

      // Ensure the background sync driver is running for this user (idempotent):
      // the vault keeps itself synced (identity-signed, no interface/JWT) as long
      // as any product page is open.
      ensureVaultSyncDriver(userId);

      const data = (await dispatch(event.data, userId)) as Record<string, unknown> | undefined;

      response = { type: MSG_VAULT_RESULT, requestId, success: true, data };

      // Honour the `optimizeMemory` flag from the request payload. When
      // the caller opted in, we transfer every top-level ArrayBuffer in
      // the response — zero-copy back, but the vault iframe loses its
      // local reference (acceptable since these results are produced
      // per-request and the vault never reuses them). When the flag is
      // absent or false, postMessage falls back to structured clone for
      // the response, mirroring the safe-by-default contract on input.
      const requestPayload =
        event.data && typeof event.data === 'object' && 'payload' in event.data ? (event.data as { payload?: unknown }).payload : undefined;
      const optimizeMemory =
        requestPayload &&
        typeof requestPayload === 'object' &&
        'optimizeMemory' in (requestPayload as Record<string, unknown>) &&
        (requestPayload as { optimizeMemory?: unknown }).optimizeMemory === true;

      const transferables: Transferable[] = [];

      if (optimizeMemory && data && typeof data === 'object') {
        for (const value of Object.values(data)) {
          if (value instanceof ArrayBuffer) {
            transferables.push(value);
          }
        }
      }

      event.source?.postMessage(response, { targetOrigin: event.origin, transfer: transferables });

      return;
    } catch (error) {
      // Marshal the error code alongside the message so consumers can
      // switch on it without regexing. VaultError instances expose
      // `code` directly; anything else (e.g. a libsodium throw that
      // slipped past `decryptContent`'s wrap) goes through the
      // last-line classifier and ends up at worst as UNKNOWN — never
      // an unmatched message string.
      response = {
        type: MSG_VAULT_RESULT,
        requestId,
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
        code: classifyVaultError(error),
      };
    }

    event.source?.postMessage(response, { targetOrigin: event.origin });
  });
}
