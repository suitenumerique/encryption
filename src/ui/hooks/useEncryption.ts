import { useCallback, useEffect, useRef, useState } from 'react';

import {
  MSG_VAULT_CLAIM_TRANSFER_IMPORT,
  MSG_VAULT_EXPORT_BACKUP,
  MSG_VAULT_GENERATE_KEYS,
  MSG_VAULT_GET_PUBLIC_KEY,
  MSG_VAULT_HAS_KEYS,
  MSG_VAULT_IMPORT_BACKUP,
  MSG_VAULT_PREPARE_TRANSFER_EXPORT,
  MSG_VAULT_READY,
  MSG_VAULT_RESPOND_TO_KEY_CHALLENGE,
  MSG_VAULT_RESULT,
  MSG_VAULT_SIGN_KEY_REGISTRATION,
} from '@encryption/src/shared/constants';
import type { VaultResponse } from '@encryption/src/shared/schemas/post-message';

interface UseEncryptionOptions {
  vaultUrl: string;
}

interface UseEncryptionReturn {
  /** True when the vault iframe is loaded AND auth info has been set */
  isReady: boolean;
  /** Set the auth info (suiteUserId) for all subsequent vault requests */
  setAuthInfo: (suiteUserId: string) => void;
  request: (type: string, payload?: unknown) => Promise<unknown>;
  generateKeys: () => Promise<{ publicKey: string; signaturePublicKey: string }>;
  signKeyRegistration: (
    version: number,
    createdAtMillis: number
  ) => Promise<{
    encryptionPublicKey: string;
    signaturePublicKey: string;
    version: number;
    createdAtMillis: number;
    keyBindingSignature: string;
  }>;
  respondToKeyChallenge: (challengeId: string, ciphertext: string) => Promise<{ response: string; challengeSignature: string }>;
  hasKeys: () => Promise<{ hasKeys: boolean }>;
  getPublicKey: () => Promise<{ publicKey: string; signaturePublicKey?: string }>;
  exportBackup: () => Promise<{ passphrase: string }>;
  importBackup: (passphrase: string) => Promise<{ publicKey: string; signaturePublicKey: string }>;
  prepareTransferExport: (language?: 'french' | 'english') => Promise<{ encryptedPayload: string; transferPassphrase: string }>;
  claimTransferImport: (encryptedPayload: string, transferPassphrase: string) => Promise<{ publicKey: string; signaturePublicKey: string }>;
}

export function useEncryption({ vaultUrl }: UseEncryptionOptions): UseEncryptionReturn {
  const [iframeReady, setIframeReady] = useState(false);
  const [hasAuth, setHasAuth] = useState(false);
  const iframeRef = useRef<HTMLIFrameElement | null>(null);
  const userIdRef = useRef<string | null>(null);
  const pendingRef = useRef<Map<string, { resolve: (value: unknown) => void; reject: (reason: unknown) => void }>>(new Map());

  useEffect(() => {
    // Create hidden vault iframe
    const iframe = document.createElement('iframe');
    iframe.src = `${vaultUrl}/bridge.html`;
    iframe.style.display = 'none';
    iframe.setAttribute('sandbox', 'allow-scripts allow-same-origin');
    document.body.appendChild(iframe);
    iframeRef.current = iframe;

    const handleMessage = (event: MessageEvent) => {
      if (new URL(vaultUrl).origin !== event.origin) {
        return;
      }

      const data = event.data as VaultResponse;

      if (data.type === MSG_VAULT_READY) {
        setIframeReady(true);

        return;
      }

      if (data.type === MSG_VAULT_RESULT && 'requestId' in data) {
        const pending = pendingRef.current.get(data.requestId);

        if (pending) {
          pendingRef.current.delete(data.requestId);

          if (data.success) {
            pending.resolve(data.data);
          } else {
            pending.reject(new Error(data.error));
          }
        }
      }
    };

    window.addEventListener('message', handleMessage);

    return () => {
      window.removeEventListener('message', handleMessage);

      // Reject all pending requests on cleanup to avoid dangling promises
      for (const [, pending] of pendingRef.current) {
        pending.reject(new Error('Vault iframe destroyed'));
      }
      pendingRef.current.clear();

      if (iframe.parentNode) {
        iframe.parentNode.removeChild(iframe);
      }
    };
  }, [vaultUrl]);

  const setAuthInfo = useCallback((suiteUserId: string) => {
    userIdRef.current = suiteUserId;
    setHasAuth(true);
  }, []);

  const request = useCallback(
    async (type: string, payload?: unknown): Promise<unknown> => {
      if (!iframeRef.current?.contentWindow) {
        throw new Error('Vault iframe not ready');
      }

      if (!userIdRef.current) {
        throw new Error('Auth info is required. Call setAuthInfo() first.');
      }

      const requestId = crypto.randomUUID();
      const vaultOrigin = new URL(vaultUrl).origin;

      return new Promise((resolve, reject) => {
        // Timeout after 30s (libsodium WASM init + key generation)
        const timeout = setTimeout(() => {
          pendingRef.current.delete(requestId);
          reject(new Error('Vault request timed out'));
        }, 30000);

        pendingRef.current.set(requestId, {
          resolve: (value) => {
            clearTimeout(timeout);
            resolve(value);
          },
          reject: (reason) => {
            clearTimeout(timeout);
            reject(reason);
          },
        });

        iframeRef.current!.contentWindow!.postMessage({ type, requestId, suiteUserId: userIdRef.current, payload }, vaultOrigin);
      });
    },
    [vaultUrl]
  );

  const generateKeys = useCallback(
    () => request(MSG_VAULT_GENERATE_KEYS) as Promise<{ publicKey: string; signaturePublicKey: string }>,
    [request]
  );

  const signKeyRegistration = useCallback(
    (version: number, createdAtMillis: number) =>
      request(MSG_VAULT_SIGN_KEY_REGISTRATION, { version, createdAtMillis }) as Promise<{
        encryptionPublicKey: string;
        signaturePublicKey: string;
        version: number;
        createdAtMillis: number;
        keyBindingSignature: string;
      }>,
    [request]
  );

  const respondToKeyChallenge = useCallback(
    (challengeId: string, ciphertext: string) =>
      request(MSG_VAULT_RESPOND_TO_KEY_CHALLENGE, { challengeId, ciphertext }) as Promise<{ response: string; challengeSignature: string }>,
    [request],
  );

  const hasKeys = useCallback(() => request(MSG_VAULT_HAS_KEYS) as Promise<{ hasKeys: boolean }>, [request]);

  const getPublicKey = useCallback(
    () => request(MSG_VAULT_GET_PUBLIC_KEY) as Promise<{ publicKey: string; signaturePublicKey?: string }>,
    [request]
  );

  const exportBackup = useCallback(() => request(MSG_VAULT_EXPORT_BACKUP) as Promise<{ passphrase: string }>, [request]);

  const importBackup = useCallback(
    (passphrase: string) => request(MSG_VAULT_IMPORT_BACKUP, { passphrase }) as Promise<{ publicKey: string; signaturePublicKey: string }>,
    [request]
  );

  const prepareTransferExport = useCallback(
    (language?: 'french' | 'english') =>
      request(MSG_VAULT_PREPARE_TRANSFER_EXPORT, language ? { language } : undefined) as Promise<{
        encryptedPayload: string;
        transferPassphrase: string;
      }>,
    [request]
  );

  const claimTransferImport = useCallback(
    (encryptedPayload: string, transferPassphrase: string) =>
      request(MSG_VAULT_CLAIM_TRANSFER_IMPORT, { encryptedPayload, transferPassphrase }) as Promise<{
        publicKey: string;
        signaturePublicKey: string;
      }>,
    [request]
  );

  const isReady = iframeReady && hasAuth;

  return {
    isReady,
    setAuthInfo,
    request,
    generateKeys,
    signKeyRegistration,
    respondToKeyChallenge,
    hasKeys,
    getPublicKey,
    exportBackup,
    importBackup,
    prepareTransferExport,
    claimTransferImport,
  };
}
