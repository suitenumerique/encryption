import {
  MSG_VAULT_ACCEPT_FINGERPRINT,
  MSG_VAULT_CHECK_FINGERPRINTS,
  MSG_VAULT_CLAIM_TRANSFER_IMPORT,
  MSG_VAULT_DECRYPT_WITH_KEY,
  MSG_VAULT_DESTROY_KEYS,
  MSG_VAULT_ENCRYPT_NESTED_WITHOUT_KEY,
  MSG_VAULT_ENCRYPT_WITHOUT_KEY,
  MSG_VAULT_ENCRYPT_WITH_KEY,
  MSG_VAULT_EXPORT_BACKUP,
  MSG_VAULT_FETCH_PUBLIC_KEYS,
  MSG_VAULT_GENERATE_KEYS,
  MSG_VAULT_GET_KNOWN_FINGERPRINTS,
  MSG_VAULT_GET_PUBLIC_KEY,
  MSG_VAULT_HAS_KEYS,
  MSG_VAULT_IMPORT_BACKUP,
  MSG_VAULT_PREPARE_TRANSFER_EXPORT,
  MSG_VAULT_REFUSE_FINGERPRINT,
  MSG_VAULT_RESPOND_TO_KEY_CHALLENGE,
  MSG_VAULT_RESULT,
  MSG_VAULT_REWRAP_NESTED_KEY,
  MSG_VAULT_SHARE_KEYS,
  MSG_VAULT_WRAP_NESTED_KEY,
} from '@encryption/src/shared/constants';
import { PRIVILEGED_OPERATIONS, type VaultResponse } from '@encryption/src/shared/schemas/post-message';
import { VaultError, VaultErrorCode, classifyVaultError } from '@encryption/src/shared/vault-error';
import { handleDecryptWithKey } from '@encryption/src/vault/operations/decrypt';
import { handleDestroyKeys } from '@encryption/src/vault/operations/destroy-keys';
import { handleClaimTransferImport, handlePrepareTransferExport } from '@encryption/src/vault/operations/device-transfer';
import {
  handleEncryptNestedWithoutKey,
  handleEncryptWithoutKey,
  handleEncryptWithKey,
} from '@encryption/src/vault/operations/encrypt';
import { handleExportBackup, handleImportBackup } from '@encryption/src/vault/operations/export-public-key';
import { handleFetchPublicKeys } from '@encryption/src/vault/operations/fetch-public-keys';
import {
  handleAcceptFingerprint,
  handleCheckFingerprints,
  handleGetKnownFingerprints,
  handleRefuseFingerprint,
} from '@encryption/src/vault/operations/fingerprint-registry';
import { handleGenerateKeys } from '@encryption/src/vault/operations/generate-keys';
import { handleGetPublicKey, handleHasKeys } from '@encryption/src/vault/operations/key-management';
import { handleRespondToKeyChallenge } from '@encryption/src/vault/operations/respond-to-key-challenge';
import { handleRewrapNestedKey } from '@encryption/src/vault/operations/rewrap-nested-key';
import { handleShareKeys } from '@encryption/src/vault/operations/share-keys';
import { handleWrapNestedKey } from '@encryption/src/vault/operations/wrap-nested-key';
import { isInterfaceOrigin, isOriginAllowed } from '@encryption/src/vault/origin-guard';

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
    case MSG_VAULT_ENCRYPT_WITHOUT_KEY:
      return handleEncryptWithoutKey(
        userId,
        payload as { data: ArrayBuffer; userPublicKeys: Record<string, ArrayBuffer> },
      );
    case MSG_VAULT_ENCRYPT_NESTED_WITHOUT_KEY:
      return handleEncryptNestedWithoutKey(
        userId,
        payload as {
          data: ArrayBuffer;
          encryptedSymmetricKey: ArrayBuffer;
          encryptedKeyChain?: ArrayBuffer[];
        },
      );
    case MSG_VAULT_ENCRYPT_WITH_KEY:
      return handleEncryptWithKey(userId, payload as { data: ArrayBuffer; encryptedSymmetricKey: ArrayBuffer; encryptedKeyChain?: ArrayBuffer[] });
    case MSG_VAULT_DECRYPT_WITH_KEY:
      return handleDecryptWithKey(userId, payload as { encryptedData: ArrayBuffer; encryptedSymmetricKey: ArrayBuffer; encryptedKeyChain?: ArrayBuffer[] });
    case MSG_VAULT_REWRAP_NESTED_KEY:
      return handleRewrapNestedKey(
        userId,
        payload as {
          encryptedSymmetricKey: ArrayBuffer;
          oldEncryptedKey: ArrayBuffer;
          oldEncryptedKeyChain?: ArrayBuffer[];
          newEncryptedKeyChain?: ArrayBuffer[];
        },
      );
    case MSG_VAULT_WRAP_NESTED_KEY:
      return handleWrapNestedKey(
        userId,
        payload as {
          userEncryptedKey: ArrayBuffer;
          newEntryEncryptedSymmetricKey: ArrayBuffer;
          newEncryptedKeyChain?: ArrayBuffer[];
        },
      );
    case MSG_VAULT_SHARE_KEYS:
      return handleShareKeys(userId, payload as { encryptedSymmetricKey: ArrayBuffer; userPublicKeys: Record<string, ArrayBuffer>; encryptedKeyChain?: ArrayBuffer[] });
    case MSG_VAULT_FETCH_PUBLIC_KEYS:
      return handleFetchPublicKeys(userId, payload as { userIds: string[] });
    case MSG_VAULT_CHECK_FINGERPRINTS:
      return handleCheckFingerprints(userId, payload as { userFingerprints: Record<string, string>; currentUserId?: string });
    case MSG_VAULT_ACCEPT_FINGERPRINT:
      return handleAcceptFingerprint(userId, payload as { userId: string; fingerprint: string });
    case MSG_VAULT_REFUSE_FINGERPRINT:
      return handleRefuseFingerprint(userId, payload as { userId: string; fingerprint: string });
    case MSG_VAULT_GET_KNOWN_FINGERPRINTS:
      return handleGetKnownFingerprints(userId);

    // Privileged operations (encryption only)
    case MSG_VAULT_GENERATE_KEYS:
      return handleGenerateKeys(userId);
    case MSG_VAULT_RESPOND_TO_KEY_CHALLENGE:
      return handleRespondToKeyChallenge(userId, payload as { challengeId: string; ciphertext: string });
    case MSG_VAULT_EXPORT_BACKUP:
      return handleExportBackup(userId);
    case MSG_VAULT_IMPORT_BACKUP:
      return handleImportBackup(userId, payload as { passphrase: string });
    case MSG_VAULT_DESTROY_KEYS:
      return handleDestroyKeys(userId);
    case MSG_VAULT_PREPARE_TRANSFER_EXPORT:
      return handlePrepareTransferExport(
        userId,
        (Object.keys(payload).length > 0 ? payload : undefined) as { language?: 'french' | 'english' } | undefined
      );
    case MSG_VAULT_CLAIM_TRANSFER_IMPORT:
      return handleClaimTransferImport(userId, payload as { encryptedPayload: string; transferPassphrase: string });
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
      const declaredUserId = event.data.suiteUserId as string | undefined;

      if (!declaredUserId) {
        throw new VaultError(VaultErrorCode.AUTH_REQUIRED, 'suiteUserId is required for all vault operations.');
      }

      const userId = declaredUserId;

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
        event.data && typeof event.data === 'object' && 'payload' in event.data
          ? (event.data as { payload?: unknown }).payload
          : undefined;
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
